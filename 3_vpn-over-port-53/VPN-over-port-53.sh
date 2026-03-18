#!/usr/bin/env bash
# VPN-over-port-53.sh -- DNS tunnel + WireGuard VPN server + CrowdSec port security
# Debian 12+, must be run as root.
#
# Usage:
#   chmod +x VPN-over-port-53.sh && sudo ./VPN-over-port-53.sh
#
# ── What this script installs ─────────────────────────────────────────────────
#
#   Always installed:
#     nftables           Firewall; prerouting, NAT, rate limits
#     CoreDNS            DNS server on :53 (Docker); routes tunnel vs decoy traffic
#     iodined            DNS tunnel server on 127.0.0.1:5300 (Docker)
#     Docker             Container runtime for CoreDNS and iodined
#
#   Optional (selected at the component menu before any install work begins):
#     WireGuard          VPN server on :51820 (internal; clients connect via :53)
#                          The nftables UDP:53->:51820 DNAT prerouting rule is
#                          always written regardless of this selection.
#     easy-wg-quick      WireGuard client config generator (Docker, run once)
#     CrowdSec local     IPS with LAPI on this node; bouncer bans via nftables
#     CrowdSec remote    Agent + bouncer here; LAPI lives on another node.
#                          Requires before running: on the remote node,
#                            cscli machines add <this-node-name> --auto
#                            cscli bouncers add <bouncer-name> -o raw
#
# ── Architecture ──────────────────────────────────────────────────────────────
#
#   External UDP/TCP port 53, TCP port 22
#         |
#    nftables prerouting  (kernel, before anything else sees the packet)
#    /                \
# WireGuard packet?   DNS packet?
# [REDIRECT :51820]   [pass through]
#       |                   |
#    nftables input: CrowdSec chain  (priority -1) -- source IP banned? ──> DROP
#    nftables input: filter chain    (priority  0) -- SSH, rate limits, port rules
#       |                   |
#  wg-quick :51820    CoreDNS :53  ──>  iodined :5300  (tunnel traffic)
#                                  ──>  decoy 93.184.216.34  (everything else)
#
#   External TCP port 53  -->  CoreDNS :53 (WireGuard is UDP-only)
#   Port 51820 is NOT open externally -- only reachable via prerouting redirect.
#
# ── CrowdSec remote LAPI mode ─────────────────────────────────────────────────
#
#   The full crowdsec agent runs locally (detects threats from CoreDNS, auth.log,
#   and kern.log). The local LAPI server is disabled (api.server.enable: false).
#   local_api_credentials.yaml is written with the remote LAPI URL and the
#   machine login/password generated on the remote node. The bouncer api_url
#   and api_key fields are patched to point at the remote LAPI.
#
#   This means: detection originates here, decisions are made at the remote LAPI,
#   and the bouncer here enforces those decisions via nftables.
#
# ── CrowdSec log -> ban pipeline ─────────────────────────────────────────────
#
#   CoreDNS stdout    ─┐
#   /var/log/auth.log  ├──>  CrowdSec agent  ──>  LAPI  ──>  bouncer  ──>  crowdsec-blacklists
#   /var/log/kern.log  ┘     (parse + score)       ^          (nftables DROP set)
#                                                  |
#                                            local (this node) or remote
#
# ── How the redirect works ────────────────────────────────────────────────────
#
#   1. Client sends WireGuard type-1 (init) to SERVER_IP:53
#   2. nftables prerouting matches first 4 bytes of UDP payload (WireGuard type
#      field) and redirects to :51820. conntrack records the DNAT.
#   3. wg-quick receives the packet -- real source IP preserved.
#   4. wg-quick sends response from :51820. conntrack reverses the DNAT,
#      rewriting source to :53. Client sees traffic from SERVER_IP:53.
#   5. Subsequent type-4 (data) packets from the same source reuse the conntrack
#      entry and are redirected without re-evaluating the payload match.
#
#   IMPORTANT: conntrack -F must run ONCE before services start to clear any
#   stale entries. Do NOT flush conntrack after services are up.
#
# ── WireGuard payload byte identification ────────────────────────────────────
#   @th,64,32 = 32 bits at offset 64 bits from transport header start
#             = first 4 bytes of UDP payload (past the 8-byte UDP header)
#   nftables reads big-endian, WireGuard types are little-endian uint32:
#   type 1 (handshake init):     01 00 00 00  ->  0x01000000
#   type 2 (handshake response): 02 00 00 00  ->  0x02000000
#   type 3 (cookie reply):       03 00 00 00  ->  0x03000000
#   type 4 (transport data):     04 00 00 00  ->  0x04000000
#
# ── easy-wg-quick seed files ─────────────────────────────────────────────────
#   portno.txt  = 53    -> client Endpoint = SERVER_IP:53
#   extnetip.txt        -> SERVER_IP (WAN IP in client configs)
#   extnetif.txt        -> PUBLIC_IFACE
#   sysctltype.txt=none -> we manage sysctl via sysctl.conf
#   fwtype.txt=none     -> nftables handles all NAT; no PostUp/PostDown in wghub.conf
#   intnetaddress.txt   -> 10.13.1.
#   intnetdns.txt       -> WG_DNS
#
#   After generation, wghub.conf has ListenPort = 53 (from portno.txt).
#   We patch it to 51820 -- that is the actual port wg-quick binds internally.
#   Client configs are not patched -- Endpoint = SERVER_IP:53 is correct.
#
#  ── File locations ───────────────────────────────────────────
#
#    /etc/wireguard/wghub.conf                                WireGuard server config
#    /opt/wg/                                                 WireGuard client configs
#    /opt/iodine/docker-compose.yml                           CoreDNS + iodined  [install sentinel]
#    /opt/iodine/Corefile                                     CoreDNS config
#    /etc/nftables.conf                                       Firewall rules
#    /etc/crowdsec/acquis.d/                                  CrowdSec log sources
#    /etc/crowdsec/parsers/s01-parse/coredns-decoy-logs.yaml  CoreDNS parser
#    /etc/crowdsec/parsers/s02-enrich/vpn-whitelist.yaml      VPN IP whitelist
#    /etc/crowdsec/scenarios/dns-decoy-scanner.yaml           DNS decoy ban scenario
#    /etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml    Bouncer config
#    /etc/crowdsec/local_api_credentials.yaml                 Agent->LAPI credentials
#    /opt/crowdsec-grafana/                                   Dashboard files (if installed)
#

set -euo pipefail

die()     { echo "ERROR: $*" >&2; exit 1; }
section() { echo ""; echo "================================================================"; echo "  $*"; echo "================================================================"; }

# ── load_existing_config ──────────────────────────────────────────────────────
# Reads all variables needed by build_and_show_menu() from deployed files.
# Called when /opt/iodine/docker-compose.yml already exists and the user just
# wants to view the Setup Complete menu without re-running the full install.
# WireGuard may or may not be installed -- all WG reads are gated on file presence.
load_existing_config() {
    local errors=0

    # ── iodine domain from Corefile ───────────────────────────────────────────
    IODINE_DOMAIN="$(grep -v '^[[:space:]]*\.' /opt/iodine/Corefile 2>/dev/null \
        | grep -oE '^[^[:space:]]+' 2>/dev/null | head -1 || true)"
    [ -n "$IODINE_DOMAIN" ] \
        || { echo "  WARNING: could not parse IODINE_DOMAIN from Corefile"; errors=$((errors+1)); }

    # ── iodined password and tunnel IP from docker-compose.yml ───────────────
    # The compose YAML splits the iodined command across two lines:
    #   line 1:  iodined -f -c -4 -p 5300 -l 127.0.0.1 -n auto
    #   line 2:  -P <pass> <tunnel_ip> <domain>
    local p_line
    p_line="$(grep -- '-P ' /opt/iodine/docker-compose.yml 2>/dev/null \
        | grep -v '^[[:space:]]*#' | head -1 || true)"

    IODINED_PASS="$(echo "$p_line" \
        | awk '{for(i=1;i<=NF;i++) if($i=="-P") {print $(i+1); exit}}' || true)"
    [ -n "$IODINED_PASS" ] \
        || { echo "  WARNING: could not parse iodine password from docker-compose.yml"; errors=$((errors+1)); }

    TUNNEL_IP="$(echo "$p_line" \
        | awk '{for(i=1;i<=NF;i++) if($i=="-P") {print $(i+2); exit}}' || true)"
    [[ "$TUNNEL_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] \
        || { echo "  WARNING: could not parse TUNNEL_IP (got: '$TUNNEL_IP')"; TUNNEL_IP="(unknown)"; errors=$((errors+1)); }

    IODINE_NETWORK="${TUNNEL_IP%.*}.0/28"

    # ── SERVER_IP: prefer seed file, fall back to live detection ─────────────
    SERVER_IP=""
    [ -f /opt/wg/extnetip.txt ] \
        && SERVER_IP="$(cat /opt/wg/extnetip.txt 2>/dev/null | tr -d '[:space:]' || true)"
    if [ -z "$SERVER_IP" ]; then
        SERVER_IP="$(curl -fsSL --max-time 5 https://api.ipify.org 2>/dev/null || true)"
    fi
    [ -n "$SERVER_IP" ] \
        || { echo "  WARNING: could not determine SERVER_IP"; SERVER_IP="(unknown)"; errors=$((errors+1)); }

    # ── PUBLIC_IFACE: prefer seed file, fall back to routing table ───────────
    PUBLIC_IFACE=""
    [ -f /opt/wg/extnetif.txt ] \
        && PUBLIC_IFACE="$(cat /opt/wg/extnetif.txt 2>/dev/null | tr -d '[:space:]' || true)"
    if [ -z "$PUBLIC_IFACE" ]; then
        PUBLIC_IFACE="$(ip route get 8.8.8.8 2>/dev/null \
            | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1); exit}' || true)"
    fi
    [ -n "$PUBLIC_IFACE" ] \
        || { echo "  WARNING: could not determine PUBLIC_IFACE"; PUBLIC_IFACE="(unknown)"; errors=$((errors+1)); }

    # ── WireGuard: only if wghub.conf is present ─────────────────────────────
    if [ -f /etc/wireguard/wghub.conf ]; then
        WG_PORT="$(grep '^ListenPort' /etc/wireguard/wghub.conf 2>/dev/null \
            | awk '{print $3}' || true)"
        [ -n "$WG_PORT" ] \
            || { echo "  WARNING: could not read ListenPort from wghub.conf"; errors=$((errors+1)); }

        local wg_addr
        wg_addr="$(grep '^Address' /etc/wireguard/wghub.conf 2>/dev/null \
            | awk '{print $3}' | tr -d '[:space:]' || true)"
        if [ -n "$wg_addr" ]; then
            WG_NETWORK="${wg_addr%.*}.0/24"
        else
            echo "  WARNING: could not read WG_NETWORK from wghub.conf"
            WG_NETWORK="10.13.1.0/24"
            errors=$((errors+1))
        fi

        WG_DNS="$(cat /opt/wg/intnetdns.txt 2>/dev/null | tr -d '[:space:]' || true)"
        [ -n "$WG_DNS" ] || WG_DNS="(unknown)"

        local names=()
        for f in /opt/wg/wgclient_*.conf; do
            [ -f "$f" ] || continue
            local base name
            base="$(basename "$f" .conf)"
            name="${base#wgclient_}"
            # Skip _ntp variants -- they are port-123 copies of primary configs.
            # The menu handles them separately via a second loop over *_ntp.conf.
            [[ "$name" == *_ntp ]] && continue
            names+=("$name")
        done
        if [ "${#names[@]}" -gt 0 ]; then
            WG_CLIENTS_RAW="$(IFS=','; echo "${names[*]}")"
        else
            echo "  WARNING: no wgclient_*.conf files found in /opt/wg/"
            WG_CLIENTS_RAW=""
            errors=$((errors+1))
        fi
    else
        # WireGuard not installed on this node. Use defaults so nftables
        # display text in the menu still renders without blank substitutions.
        WG_PORT="51820"
        WG_NETWORK="10.13.1.0/24"
        WG_DNS="(not installed)"
        WG_CLIENTS_RAW=""
    fi

    # Detect which external ports are active from the deployed nftables.conf.
    # Used by build_and_show_menu and action_add_wireguard_client.
    WG_USE_PORT_53=false
    WG_USE_PORT_123=false
    grep -q 'udp dport 53[[:space:]].*redirect to :51820' /etc/nftables.conf 2>/dev/null \
        && WG_USE_PORT_53=true
    grep -q 'udp dport 123[[:space:]].*redirect to :51820' /etc/nftables.conf 2>/dev/null \
        && WG_USE_PORT_123=true

    if [ "$errors" -gt 0 ]; then
        echo ""
        echo "  $errors value(s) could not be read from deployed files."
        echo "  The menu will show what it can. Missing values shown as (unknown)."
        echo ""
        read -rsp "  Press any key to continue..." -n1 || true; echo ""
    fi
}

# ── patch_dashboard ───────────────────────────────────────────────────────────
# Patches a downloaded Grafana dashboard JSON for local provisioning:
#   - Extracts __inputs datasource variable names via jq
#   - Replaces ${VAR_NAME} placeholders with the literal string "CrowdSec"
#   - Strips __inputs, nulls id, and sets a stable uid
# Called by action_install_dashboard() for each downloaded dashboard file.
# Arguments: <src-tmp-file> <dst-file> <uid-string>
patch_dashboard() {
    local src="$1" dst="$2" uid="$3"
    local sed_script=""

    while IFS= read -r varname; do
        [ -z "$varname" ] && continue
        sed_script="${sed_script}s/\${${varname}}/CrowdSec/g;"
    done < <(jq -r \
        '(.["__inputs"] // []) | .[] | select(.type == "datasource") | .name' \
        "$src" 2>/dev/null)

    if jq --arg uid "$uid" \
        'del(.__inputs) | .id = null | .uid = $uid' "$src" 2>/dev/null \
        | if [ -n "$sed_script" ]; then sed "$sed_script"; else cat; fi \
        > "$dst" && [ -s "$dst" ]; then
        echo "  [OK]   $(basename "$dst")"
    else
        cp "$src" "$dst"
        echo "  WARN:  patch failed, using raw JSON"
    fi
}

# ── build_and_show_menu ───────────────────────────────────────────────────────
# Builds temp files for each menu section from current variable values, then
# runs the interactive select loop. Temp dir is cleaned up on exit/interrupt.
# Can be called after a full install (variables already set) or after
# load_existing_config() (variables read back from deployed files).
#
# WireGuard and CrowdSec sections are conditionally included based on what is
# actually installed at menu-build time -- not on the INSTALL_* flags from the
# current run. This means the menu is always accurate whether this is a fresh
# install, a re-run, or a view-only invocation.
build_and_show_menu() {
    MENUDIR="$(mktemp -d /tmp/dns-tunnel-menu.XXXXXX)"

    # ── Detect what is installed on this node at menu-build time ─────────────
    local MENU_HAS_WG="false"
    local MENU_HAS_CS="false"
    local MENU_HAS_GRAFANA="false"
    local MENU_HAS_WEBUI="false"
    [ -f /etc/wireguard/wghub.conf ]          && MENU_HAS_WG="true"
    command -v cscli >/dev/null 2>&1           && MENU_HAS_CS="true"
    [ "$(docker inspect -f '{{.State.Running}}' crowdsec-grafana  2>/dev/null)" = "true" ] \
        && MENU_HAS_GRAFANA="true"
    [ "$(docker inspect -f '{{.State.Running}}' crowdsec-web-ui   2>/dev/null)" = "true" ] \
        && MENU_HAS_WEBUI="true"

    # ── 1. DNS delegation ─────────────────────────────────────────────────────
    cat > "$MENUDIR/01_dns_delegation.txt" << SECTION
================================================================
  DNS Delegation  (set at your registrar)
================================================================

  You need two records pointing at this server:

    ${IODINE_DOMAIN}    IN NS    address.yourdomain.com
    address.yourdomain.com  IN A  ${SERVER_IP}

  address.yourdomain.com is the glue record pointing to this server.
  Replace 'address' and 'yourdomain.com' with your actual names.

  Propagation can take up to 48 hours.
  Test with:
    dig NS ${IODINE_DOMAIN}
    dig +short @${SERVER_IP} test.${IODINE_DOMAIN}

  Example records:
    tunnel.yourdomain.com  IN NS   address.yourdomain.com
    address.yourdomain.com IN A    ${SERVER_IP}
SECTION

    # ── 2. iodine connect instructions ────────────────────────────────────────
    cat > "$MENUDIR/02_iodine_connect.txt" << SECTION
================================================================
  iodine -- DNS Tunnel
================================================================

  iodine encodes all traffic as DNS queries so it works even
  when a carrier intercepts or blocks non-DNS ports.

  ── Linux / Desktop ─────────────────────────────────────────

    sudo iodine -L0 -f -P '${IODINED_PASS}' ${SERVER_IP} ${IODINE_DOMAIN}

    -L0  = lazy mode (faster, keeps connection open)
    -f   = stay in foreground

    Once connected, tunnel IP is ${TUNNEL_IP}

  ── Linux: DNS configuration (required) ─────────────────────

    iodine does not configure DNS automatically.
    The server's CoreDNS is a decoy -- do NOT use it for DNS.
    Point DNS directly at an external resolver instead.
    The iodine subnet is already NAT'd to the internet, so
    external resolvers are reachable through the tunnel.

    Temporary (lost on reboot):
      echo 'nameserver ${WG_DNS}' | sudo tee /etc/resolv.conf

    Or use any public resolver: 1.1.1.1, 8.8.8.8, etc.

  ── Linux: route all traffic through iodine ─────────────────

    iodine only routes the tunnel subnet by default.
    To route all internet traffic through the tunnel:

      sudo ip route add default via ${TUNNEL_IP} metric 10

    Remove when done:
      sudo ip route del default via ${TUNNEL_IP}

  ── SSH SOCKS proxy (alternative to full routing) ────────────

    ssh -D 1080 -C -N user@${TUNNEL_IP}
    Then set browser proxy: SOCKS5 127.0.0.1:1080

  ── Android: AndIodine app ───────────────────────────────────

    AndIodine routes your phone's data through DNS tunneling,
    bypassing carrier port blocks entirely.

    Get it on F-Droid:
    https://f-droid.org/en/packages/org.xapek.andiodine/

    App settings:

      Tunnel Top Domain   ${IODINE_DOMAIN}
      Password            ${IODINED_PASS}
      Nameserver Mode     SET_CUSTOM
      Nameserver          45.11.45.11
      Lazy Mode           ENABLE
      Raw Mode            DISABLE
      Default Route       ENABLE

    With Default Route ENABLE, all traffic routes through the
    tunnel.  Android routes DNS to 45.11.45.11 directly via
    the tunnel -- no extra DNS config needed on Android.

  ── IMPORTANT ────────────────────────────────────────────────

    iodine provides NO encryption on its own.
    Always layer SSH or WireGuard on top.

  ── WireGuard over iodine (carrier bypass, desktop only) ────

    Android can only run one VPN at a time, so iodine+WireGuard
    is only useful on desktop/Linux.

    1. Connect iodine (above)
    2. Edit your WireGuard client config:
         Endpoint = ${TUNNEL_IP}:${WG_PORT}
    3. wg-quick up <client>
    4. Traffic flows: WireGuard -> iodine tunnel -> server
SECTION

    # ── 3. WireGuard per-client configs + QR codes ────────────────────────────
    # Only populated when WireGuard is installed on this node.
    local CLIENT_IDX=3
    if [ "$MENU_HAS_WG" = "true" ] && [ -n "$WG_CLIENTS_RAW" ]; then
        IFS=',' read -ra WG_CLIENT_NAMES <<< "$WG_CLIENTS_RAW"
        for raw_name in "${WG_CLIENT_NAMES[@]}"; do
            local name
            name="$(echo "$raw_name" | tr -d '[:space:]')"
            [ -z "$name" ] && continue
            local conf="/opt/wg/wgclient_${name}.conf"
            [ -f "$conf" ] || continue

            local PADDED OUTFILE
            PADDED="$(printf '%02d' $CLIENT_IDX)"
            OUTFILE="$MENUDIR/${PADDED}_wg_${name}.txt"

            {
                echo "================================================================"
                echo "  WireGuard Client: ${name}"
                echo "================================================================"
                echo ""
                echo "  Config file: $conf"
                echo "  Endpoint:    $(grep Endpoint "$conf" | awk '{print $3}')"
                echo ""
                echo "  ── Config contents ─────────────────────────────────────────"
                echo ""
                cat "$conf"
                echo ""
                echo "  ── QR Code (scan with WireGuard app) ───────────────────────"
                echo ""
                if command -v qrencode >/dev/null 2>&1; then
                    qrencode -t ansiutf8 < "$conf" 2>/dev/null || echo "  (qrencode failed)"
                else
                    echo "  (qrencode not installed -- sudo apt install qrencode)"
                fi
                echo ""
                echo "  ── How to connect ──────────────────────────────────────────"
                echo ""
                echo "  Android / iOS:"
                echo "    1. Open WireGuard app"
                echo "    2. Tap + -> Scan QR code"
                echo "    3. Point camera at the QR code above"
                echo "    4. Activate the tunnel"
                echo ""
                echo "  Linux:"
                echo "    sudo wg-quick up $conf"
                echo "    # or copy to /etc/wireguard/${name}.conf and:"
                echo "    sudo wg-quick up ${name}"
                echo ""
                echo "  Linux -- if you see 'resolvconf: command not found':"
                echo "    sudo apt install resolvconf"
                echo "    sudo wg-quick up $conf"
                echo ""
                echo "  Windows:"
                echo "    Import tunnel from file: $conf"
                echo ""
                echo "  ┌─────────────────────────────────────────────────────────┐"
                echo "  │  ⚠  CELLULAR WARNING   ⚠   ⚠   ⚠   ⚠   ⚠   ⚠                   │"
                echo "  │                                                              │"
                echo "  │  WireGuard is ontop of UDP port 53. Most cell phone          │"
                echo "  │  carriers (Verizon,etc) run a transparent DNS proxy          │"
                echo "  │  ontop of your communications that intercepts UDP/53         │"
                echo "  │  This corrupts UDP :53 traffic that is not real DNS.         │"
                echo "  │                                                              │"
                echo "  │  Symptom: works on WiFi, fails on cellular.                  │"
                echo "  │  Fix: get off the cell network, or use iodine                │"
                echo "  │                                                              │"
                echo "  │  Android: iodine alone is your tunnel on cellular.           │"
                echo "  │                                                              │"
                echo "  │  See 'cellular warning' in this menu for full details.       │"
                echo "  └─────────────────────────────────────────────────────────┘"
            } > "$OUTFILE"

            CLIENT_IDX=$((CLIENT_IDX + 1))
        done
    fi

    # ── 3b. Port 123 (_ntp) WireGuard client configs ─────────────────────────
    # Only added when both ports are configured. Each _ntp config is a copy of
    # the primary with Endpoint patched to port 123.
    if [ "$MENU_HAS_WG" = "true" ] && $WG_USE_PORT_53 && $WG_USE_PORT_123 \
            && [ -n "$WG_CLIENTS_RAW" ]; then
        IFS=',' read -ra _ntp_names <<< "$WG_CLIENTS_RAW"
        for raw_name in "${_ntp_names[@]}"; do
            local name
            name="$(echo "$raw_name" | tr -d '[:space:]')"
            [ -z "$name" ] && continue
            local conf="/opt/wg/wgclient_${name}_ntp.conf"
            [ -f "$conf" ] || continue

            local PADDED OUTFILE
            PADDED="$(printf '%02d' $CLIENT_IDX)"
            OUTFILE="$MENUDIR/${PADDED}_wg_${name}_ntp.txt"

            {
                echo "================================================================"
                echo "  WireGuard Client: ${name}  [port 123 / NTP bypass]"
                echo "================================================================"
                echo ""
                echo "  Use this config when port 53 is intercepted by your carrier"
                echo "  or network."
                echo ""
                echo "  !! THROUGHPUT WARNING: port 123 is rate-capped by some ISPs !!"
                echo ""
                echo "  Some carriers rate-limit UDP/123 to ~50 Kbps / ~4-5 packets/sec."
                echo "  This is a hard ceiling imposed upstream -- the server cannot raise"
                echo "  it.  50 Kbps is dial-up modem speed.  Expect extremely slow web,"
                echo "  unusable video, and marginally usable SSH."
                echo ""
                echo "  The other ISP threat on this port is DPI (Deep Packet Inspection):"
                echo "  carriers that inspect payloads confirm NTP's fixed 48-byte packet"
                echo "  size and structure.  WireGuard packets do not match.  If port 123"
                echo "  connects but immediately drops, DPI is the likely cause.  There is"
                echo "  no server-side workaround for DPI -- switch to iodine instead."
                echo ""
                echo "  Config file: $conf"
                echo "  Endpoint:    $(grep Endpoint "$conf" | awk '{print $3}')"
                echo ""
                echo "  ── Config contents ─────────────────────────────────────────"
                echo ""
                cat "$conf"
                echo ""
                echo "  ── QR Code (scan with WireGuard app) ───────────────────────"
                echo ""
                if command -v qrencode >/dev/null 2>&1; then
                    qrencode -t ansiutf8 < "$conf" 2>/dev/null || echo "  (qrencode failed)"
                else
                    echo "  (qrencode not installed -- sudo apt install qrencode)"
                fi
                echo ""
                echo "  ── How to connect ──────────────────────────────────────────"
                echo ""
                echo "  Android / iOS:"
                echo "    1. Open WireGuard app"
                echo "    2. Tap + -> Scan QR code (this code, not the port-53 one)"
                echo "    3. Point camera at the QR code above"
                echo "    4. Activate the tunnel"
                echo ""
                echo "  Linux:"
                echo "    sudo wg-quick up $conf"
                echo ""
                echo "  Windows:"
                echo "    Import tunnel from file: $conf"
                echo ""
                echo "  ── When to use port 123 vs port 53 ─────────────────────────"
                echo ""
                echo "  Port 53 works:    hotels, offices, most restrictive WiFi"
                echo "  Port 123 works:   carriers that intercept/redirect UDP :53"
                echo ""
                echo "  Test port 53 first. If it fails on cellular but works on"
                echo "  WiFi, switch to this port-123 config."
            } > "$OUTFILE"

            CLIENT_IDX=$((CLIENT_IDX + 1))
        done
    fi

    # ── 4. Service management ─────────────────────────────────────────────────
    # Content is built with conditional echo statements rather than a heredoc
    # so WireGuard and CrowdSec lines can be included only when installed.
    {
        echo "================================================================"
        echo "  Service Management"
        echo "================================================================"
        echo ""
        echo "  ── Status ──────────────────────────────────────────────────"
        echo ""
        [ "$MENU_HAS_WG" = "true" ] && echo "    sudo wg show"
        [ "$MENU_HAS_WG" = "true" ] && echo "    sudo systemctl status wg-quick@wghub"
        [ "$MENU_HAS_CS" = "true" ] && echo "    sudo systemctl status crowdsec"
        [ "$MENU_HAS_CS" = "true" ] && echo "    sudo systemctl status crowdsec-firewall-bouncer"
        echo "    cd /opt/iodine && docker compose ps"
        echo "    sudo nft list ruleset"
        echo ""
        echo "  ── Restart all ─────────────────────────────────────────────"
        echo ""
        echo "    sudo systemctl restart nftables"
        [ "$MENU_HAS_WG" = "true" ] && echo "    sudo systemctl restart wg-quick@wghub"
        [ "$MENU_HAS_CS" = "true" ] && echo "    sudo systemctl restart crowdsec"
        [ "$MENU_HAS_CS" = "true" ] && echo "    sudo systemctl restart crowdsec-firewall-bouncer"
        echo "    cd /opt/iodine && docker compose restart"
        echo ""
        echo "  ── Logs ────────────────────────────────────────────────────"
        echo ""
        [ "$MENU_HAS_WG" = "true" ] && echo "    sudo journalctl -u wg-quick@wghub -f"
        echo "    sudo journalctl -u nftables --no-pager -n 30"
        [ "$MENU_HAS_CS" = "true" ] && echo "    sudo journalctl -u crowdsec -f"
        [ "$MENU_HAS_CS" = "true" ] && echo "    sudo journalctl -u crowdsec-firewall-bouncer -f"
        echo "    cd /opt/iodine && docker compose logs -f coredns"
        echo "    cd /opt/iodine && docker compose logs -f iodine"
        echo ""
        if [ "$MENU_HAS_CS" = "true" ]; then
            # Show live dashboard access URLs for whichever is currently running.
            local _wg_ip="${WG_NETWORK%.*}.1"
            if [ "$MENU_HAS_GRAFANA" = "true" ] || [ "$MENU_HAS_WEBUI" = "true" ]; then
                echo "  ── Dashboard access (VPN required) ──────────────────────────"
                echo ""
                if [ "$MENU_HAS_GRAFANA" = "true" ]; then
                    echo "  Grafana:  http://${_wg_ip}:3000    (WireGuard)"
                    echo "            http://${TUNNEL_IP}:3000    (iodine)"
                fi
                if [ "$MENU_HAS_WEBUI" = "true" ]; then
                    echo "  Web UI:   http://${_wg_ip}:3000    (WireGuard)"
                    echo "            http://${TUNNEL_IP}:3000    (iodine)"
                fi
                echo ""
            fi
            echo "  ── Dashboard containers ─────────────────────────────────────"
            echo ""
            if [ "$MENU_HAS_GRAFANA" = "true" ]; then
                echo "    docker stop  crowdsec-prometheus crowdsec-grafana"
                echo "    docker start crowdsec-prometheus crowdsec-grafana"
                echo "    docker logs  crowdsec-prometheus"
                echo "    docker logs  crowdsec-grafana"
                echo "    docker rm -f crowdsec-prometheus crowdsec-grafana"
            elif [ "$MENU_HAS_WEBUI" = "true" ]; then
                echo "    docker stop  crowdsec-web-ui"
                echo "    docker start crowdsec-web-ui"
                echo "    docker logs  crowdsec-web-ui"
                echo "    docker rm -f crowdsec-web-ui"
            else
                echo "    No dashboard running. Use '* install dashboard' from this menu."
            fi
            echo ""
        fi
        echo "  ── Conntrack (active tunnels) ──────────────────────────────"
        echo ""
        echo "    sudo conntrack -L | grep 51820"
        echo ""
        echo "  ── Traffic verification ─────────────────────────────────────"
        echo ""
        echo "    # WireGuard packets arriving on port 53 (will look like garbled DNS):"
        echo "    sudo tcpdump -i ${PUBLIC_IFACE} -n udp port 53"
        echo ""
        echo "    # If nothing appears on :53 when phone connects, carrier is blocking it."
        echo "    # Use iodine fallback (see iodine menu entry)."
        echo ""
        echo "  ── File locations ───────────────────────────────────────────"
        echo ""
        [ "$MENU_HAS_WG" = "true" ] && echo "    /etc/wireguard/wghub.conf                                WireGuard server config"
        [ "$MENU_HAS_WG" = "true" ] && echo "    /opt/wg/                                                 WireGuard client configs"
        echo "    /opt/iodine/docker-compose.yml                           CoreDNS + iodined"
        echo "    /opt/iodine/Corefile                                     CoreDNS config"
        echo "    /etc/nftables.conf                                       Firewall rules"
        if [ "$MENU_HAS_CS" = "true" ]; then
            echo "    /etc/crowdsec/acquis.d/                                  CrowdSec log sources"
            echo "    /etc/crowdsec/parsers/s01-parse/coredns-decoy-logs.yaml  CoreDNS parser"
            echo "    /etc/crowdsec/parsers/s02-enrich/vpn-whitelist.yaml      VPN IP whitelist"
            echo "    /etc/crowdsec/scenarios/dns-decoy-scanner.yaml           DNS decoy ban scenario"
            echo "    /etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml    Bouncer config"
            echo "    /etc/crowdsec/local_api_credentials.yaml                 Agent LAPI credentials"
            echo "    /opt/crowdsec-grafana/                                   Dashboard files (if installed)"
        fi
    } > "$MENUDIR/91_services.txt"

    # ── 5. Cellular warning ───────────────────────────────────────────────────
    cat > "$MENUDIR/92_cellular_warning.txt" << 'SECTION'
================================================================
  ⚠  ⚠  HEADS UP: WireGuard on cellular may not work  ⚠  ⚠
================================================================

  THIS SETUP RUNS WIREGUARD OVER UDP PORT 53.
  PORT 53 IS THE DNS PORT. YOUR CARRIER KNOWS THIS.

  ── What happens on WiFi ────────────────────────────────────

    Your router forwards UDP/53 to the internet untouched.
    WireGuard handshake arrives at the server.  Works fine.

  ── What happens on cellular ────────────────────────────────

    Your carrier owns the DNS layer on their network.
    Many carriers run a transparent DNS proxy that intercepts
    ALL UDP port 53 traffic before it leaves their network --
    even if the destination is your server, not their DNS.

    The proxy tries to parse your WireGuard handshake as a
    DNS query. It is not a DNS query. The proxy either:
      - Silently drops the packet
      - Replies with a DNS error
      - Forwards garbled garbage

    Your server never sees the handshake. No tunnel.
    This is not a bug. It is a carrier feature. You cannot
    fix it by changing anything on the server.

  ── How to tell if this is happening ────────────────────────

    WiFi:     WireGuard connects     -> carrier is NOT the problem
    Cellular: WireGuard fails        -> carrier IS intercepting :53

    Confirm on server while phone is on cellular:
      sudo tcpdump -i <iface> -n udp port 53
    If you see NOTHING when you try to connect: carrier blocked it.
    If you see garbled replies going back: carrier is proxying it.

  ── Workaround option 1: switch to port 123 (NTP) ───────────

    If this server was configured with WireGuard on port 123,
    use the port-123 client config instead of the port-53 one.

    Port 123 is used by NTP (Network Time Protocol). Carrier DNS
    proxies do not touch it, which solves the port-53 interception
    problem.  However, port 123 has two other ISP threat models:

    1. Rate limiting: some carriers cap UDP/123 to ~50 Kbps / ~5 PPS.
       This is a hard ceiling imposed upstream -- the server cannot raise
       it.  50 Kbps is dial-up speed.  WireGuard will connect but the
       experience will be extremely slow for anything beyond SSH.

    2. DPI fingerprinting: carriers that do payload inspection check
       that traffic on port 123 matches NTP's fixed 48-byte packet
       size and message structure.  WireGuard packets do not match.
       If port 123 connects briefly then dies, DPI is the likely cause.
       There is no server-side workaround for DPI.

    Look for a "port 123 / NTP bypass" entry in this menu for the
    config and QR code. If it is not listed, port 123 was not
    selected at install time.

  ── Workaround option 2: tunnel WireGuard through iodine ────

    iodine encodes traffic as real DNS queries -- it was built
    to survive exactly this. Once iodine is connected, you have
    a direct IP path to the server that bypasses the carrier proxy.

    Desktop / Linux only (Android = one VPN at a time):
      1. Connect iodine  (see iodine menu entry for credentials)
      2. In your WireGuard client config, temporarily set:
           Endpoint = TUNNEL_IP:WG_PORT
      3. Connect WireGuard as normal
      4. All traffic: phone -> iodine DNS tunnel -> server -> internet

    On Android, use iodine alone as your tunnel while on cellular.
    iodine alone gives you a TCP/IP path to the server; layer SSH
    on top for encryption:
      ssh -D 1080 -C -N user@TUNNEL_IP
    Then set your browser/app SOCKS proxy to 127.0.0.1:1080.

  ── Why port 53 at all? ──────────────────────────────────────

    Most firewalls (hotels, airports, offices, restrictive ISPs)
    block everything except ports 80, 443, and 53.
    Port 53 gets through almost everywhere -- except carriers
    who own the DNS infrastructure themselves.

    Port 123 avoids carrier DNS proxying.  The trade-offs are:
      - Rate cap (~50 Kbps / ~5 PPS) on carriers that police UDP/123.
        This is a hard ISP ceiling.  There is no server-side workaround.
      - DPI fingerprinting on carriers that inspect NTP payload size and
        structure.  Cannot be worked around server-side.

    Port 53 + port 123 together cover the widest range of networks.
SECTION

    # ── 6. CrowdSec about + commands: only if CrowdSec is installed ───────────
    if [ "$MENU_HAS_CS" = "true" ]; then
        cat > "$MENUDIR/93_crowdsec_about.txt" << 'SECTION'
================================================================
  CrowdSec -- Post-Install Guide
================================================================

  ── What CrowdSec does ──────────────────────────────────────

  CrowdSec is a collaborative intrusion prevention system.
  It watches your logs in real-time, detects attack patterns,
  and bans the source IP -- across every machine in your network
  simultaneously.

  On this server, decoy sensors on the open ports are the
  primary detection mechanism. Any IP that probes a port it
  should not be probing is treated as a scanner and banned.

  ── How the pieces fit together ─────────────────────────────

    Sensor (CoreDNS decoy -- port 53)
      Every DNS query that hits the catch-all zone is logged.
      CrowdSec reads those logs in real-time via the Docker
      datasource.

    Parser (custom/coredns-decoy-logs)
      Converts raw CoreDNS log lines into structured events
      with source IP, query name, and response code.

    Scenario (custom/dns-decoy-scanner)
      Leaky-bucket: 3 probes within 60s = ban.
      A small grace period absorbs misconfigured resolvers
      that retry once or twice before giving up.

    LAPI (Local API -- this node or remote)
      The central brain. Stores all ban decisions.
      Every bouncer on every enrolled machine polls LAPI
      and enforces the same ban list.

    Bouncer (crowdsec-firewall-bouncer-nftables)
      Reads ban decisions from LAPI every 10 seconds.
      Creates an nftables chain that bans IPs at the kernel
      level before traffic reaches any service (WireGuard,
      CoreDNS, SSH, or anything else).

  ── Mental model ────────────────────────────────────────────

    Sensor  ->  Parser  ->  Scenario  ->  LAPI  ->  Bouncer
    (logs)      (events)    (decisions)   (brain)   (firewall)

SECTION

        # Insert port 123 sensor description when active.
        if $WG_USE_PORT_123; then
            cat >> "$MENUDIR/93_crowdsec_about.txt" << 'SECTION'
    Sensor (nftables CROWDSEC_DROP -- port 123)
      Non-WireGuard UDP:123 packets are not DNAT'd in prerouting.
      They reach the input chain, are dropped, and the CROWDSEC_DROP
      nftables log rule writes them to kern.log.

    Parser (custom/ntp-probe-enrich -- s02-enrich)
      crowdsecurity/iptables-logs (s01-parse) already processes all
      CROWDSEC_DROP kernel log lines, extracts the source IP from
      SRC=, and promotes the event to s02-enrich via next_stage.
      This enricher runs in s02-enrich and tags events where the
      already-parsed message contains DPT=123 as log_type=ntp_probe.

    Scenario (custom/ntp-probe-scanner)
      Same leaky-bucket as the DNS decoy: 3 probes within 60s = ban.
      Uses evt.Meta.source_ip which iptables-logs already set.

SECTION
        fi

        cat >> "$MENUDIR/93_crowdsec_about.txt" << 'SECTION'
  ── Daily monitoring (three commands cover most needs) ───────

    sudo cscli decisions list     -- who is currently banned
    sudo cscli alerts list        -- what triggered those bans
    sudo cscli metrics            -- system health + performance

  ── Check current bans ──────────────────────────────────────

    sudo cscli decisions list
    sudo cscli decisions list --origin crowdsec --limit 20
    sudo cscli alerts list --scenario custom/dns-decoy-scanner
    sudo cscli alerts list --scenario custom/ntp-probe-scanner

  ── Manually ban or unban an IP ─────────────────────────────

    sudo cscli decisions add --ip 1.2.3.4 --duration 24h --reason "manual"
    sudo cscli decisions delete --ip 1.2.3.4
      (use delete if you accidentally trigger the DNS sensor while testing)

  ── Health checks ───────────────────────────────────────────

    sudo cscli lapi status        -- LAPI reachable? if not, bans not enforced
    sudo cscli bouncers list      -- bouncer heartbeat (stale = not enforcing)
    sudo cscli hub list           -- confirm custom parsers + scenario loaded

  ── Step 1: Test the DNS sensor ─────────────────────────────

    From a machine NOT on your VPN (external IP required):
      for i in $(seq 1 5); do dig @<SERVER_IP> probe$i.test.com; done
    Then back on this server:
      sudo cscli decisions list
    Your external IP should appear as banned within seconds.

  ── Step 2: Add remote nodes to THIS LAPI (local LAPI only) ─

    Point other servers' bouncers at this LAPI instead of
    running isolated instances. One ban anywhere = ban everywhere.

      ON THIS NODE (once per remote machine):
        sudo cscli machines add <node-name> --auto

      ON EACH REMOTE NODE:
        sudo cscli lapi register \
          --url http://<THIS_SERVER_IP>:8080 \
          --token <token-from-above>
        sudo systemctl restart crowdsec
        sudo apt-get install -y crowdsec-firewall-bouncer-nftables

    Common mistake: running a full crowdsec agent on every machine
    with its own local LAPI. Bans never propagate. One central
    LAPI + bouncers everywhere is the correct architecture.

  ── Step 3: Optional Grafana dashboard ──────────────────────

    Select "install grafana dashboard" from the Setup Complete menu.
    Accessible only over WireGuard or iodine -- blocked from internet.

  ── Zero-tolerance mode (ban on first probe) ─────────────────

    For the DNS decoy (port 53):
      Edit /etc/crowdsec/scenarios/dns-decoy-scanner.yaml
      Set: type: trigger  (remove leakspeed and capacity lines)

    For the port 123 probe scanner (if port 123 active):
      Edit /etc/crowdsec/scenarios/ntp-probe-scanner.yaml
      Set: type: trigger  (remove leakspeed and capacity lines)

    sudo systemctl restart crowdsec
SECTION

        cat > "$MENUDIR/94_crowdsec_commands.txt" << 'SECTION'
================================================================
  CrowdSec -- Commands Reference
================================================================

  All commands require sudo unless you are already root.

  ── Daily monitoring workflow ────────────────────────────────

  These three commands cover most of what you need day-to-day:

    sudo cscli decisions list     -- who is currently banned
    sudo cscli alerts list        -- what triggered those bans
    sudo cscli metrics            -- system health + performance

  ── Ban decisions ────────────────────────────────────────────

  sudo cscli decisions list

    Shows every active ban or remediation decision.
    Each row: IP address, ban duration, reason, origin.

    Useful filters:
      --type ban           only show bans (not captchas etc.)
      --scope ip           only IP-level decisions
      --origin crowdsec    bans triggered by local scenarios
      --origin lists       bans from community blocklists
      --limit 50           show only the last 50 decisions
      --machine            include which machine triggered it

    Example -- show the last 20 bans from local detection:
      sudo cscli decisions list --origin crowdsec --limit 20

  ── Security alerts ──────────────────────────────────────────

  sudo cscli alerts list

    Shows the events that triggered a ban decision.
    More context than 'decisions list' -- includes scenario
    name, attack timestamps, and the source machine.

    Useful filters:
      --scenario custom/dns-decoy-scanner   only DNS decoy hits
      --limit 50                            last 50 alerts
      --since 24h                           last 24 hours

    Example -- recent DNS decoy hits:
      sudo cscli alerts list --scenario custom/dns-decoy-scanner

  ── API status ───────────────────────────────────────────────

  sudo cscli lapi status

    Checks connectivity to the LAPI (local or remote).
    Run this first if decisions are not propagating. If this
    fails, bouncer bans are not being applied anywhere.

  ── Performance metrics ──────────────────────────────────────

  sudo cscli metrics

    Displays Prometheus metrics: parser success/failure rates,
    events parsed per second, bucket states, API call counts.

    Key things to look for:
      PARSERS section:  'success' count growing = logs are parsed
      SCENARIOS section: 'bucket_overflows' = bans being triggered
      LAPI section:     'decisions_get_total' = bouncers polling

  ── Installed content ────────────────────────────────────────

  sudo cscli hub list

    Shows all installed parsers, scenarios, and collections.
    Check here to confirm custom/coredns-decoy-logs and
    custom/dns-decoy-scanner are loaded.

  ── Machine & bouncer management ─────────────────────────────

  sudo cscli machines list

    Lists every CrowdSec agent registered with this LAPI.
    A machine that has not checked in recently shows stale status.

  sudo cscli bouncers list

    Lists every bouncer registered with this LAPI.
    If the nftables bouncer shows as disconnected, bans are not
    being enforced -- restart it:
      sudo systemctl restart crowdsec-firewall-bouncer

  ── Manually add or delete a ban ─────────────────────────────

  sudo cscli decisions add --ip 1.2.3.4 --duration 24h --reason "manual"
  sudo cscli decisions delete --ip 1.2.3.4

  ── CrowdSec service management ──────────────────────────────

  sudo systemctl status crowdsec
  sudo systemctl status crowdsec-firewall-bouncer
  sudo systemctl restart crowdsec
  sudo systemctl restart crowdsec-firewall-bouncer

  Logs:
    sudo journalctl -u crowdsec -f
    sudo journalctl -u crowdsec-firewall-bouncer -f
SECTION
    fi  # MENU_HAS_CS

    # ── Action sentinel files ─────────────────────────────────────────────────
    # .sh files in MENUDIR are detected by the menu loop as action items and
    # invoke the corresponding action_*() function instead of paging a file.
    [ "$MENU_HAS_WG" = "true" ] && touch "$MENUDIR/50_add_wireguard_client.sh"
    [ "$MENU_HAS_CS" = "true" ] && touch "$MENUDIR/51_crowdsec_live.sh"
    [ "$MENU_HAS_CS" = "true" ] && touch "$MENUDIR/60_install_dashboard.sh"

    # ── Menu loop ─────────────────────────────────────────────────────────────
    local PAGER="less -R"
    command -v less >/dev/null 2>&1 || PAGER="more"

    show_section() { clear; ${PAGER} "$1"; }

    action_add_wireguard_client() {
        clear
        echo ""
        echo "  ── Add WireGuard Client ────────────────────────────────────"
        echo ""
        echo "  This will generate a new WireGuard client config, add the"
        echo "  peer to the server, and display the QR code to scan."
        echo ""
        read -rp "  Client name (letters/numbers only, e.g. laptop): " newname || true
        newname="$(echo "$newname" | tr -d '[:space:]')"
        if [ -z "$newname" ]; then
            echo "  No name entered. Cancelled."
            return
        fi
        if [ -f "/opt/wg/wgclient_${newname}.conf" ]; then
            echo "  wgclient_${newname}.conf already exists."
            echo "  Use a different name or delete the existing config first."
            return
        fi
        echo ""
        echo "  Generating client: $newname ..."
        docker run --rm \
            -v "/opt/wg:/pwd" \
            ghcr.io/burghardt/easy-wg-quick \
            "$newname" || { echo "  ERROR: easy-wg-quick failed."; return; }
        [ -f "/opt/wg/wgclient_${newname}.conf" ] \
            || { echo "  ERROR: config file not created."; return; }
        chmod 600 "/opt/wg/wgclient_${newname}.conf"

        # easy-wg-quick wrote the new peer into /opt/wg/wghub.conf.
        # /etc/wireguard/wghub.conf is what wg-quick@wghub runs from and what
        # wg syncconf reads below.  Without this copy the new peer is invisible
        # to the live WireGuard instance and lost on every restart.
        install -m 600 /opt/wg/wghub.conf /etc/wireguard/wghub.conf \
            || { echo "  ERROR: could not update /etc/wireguard/wghub.conf"; return; }

        # Reload WireGuard live -- no downtime, no reconnect needed for existing peers
        echo "  Reloading WireGuard..."
        wg syncconf wghub <(wg-quick strip /etc/wireguard/wghub.conf) \
            || { echo "  WARNING: wg syncconf failed -- restart wg-quick manually."; }

        echo ""
        echo "  ── Config: /opt/wg/wgclient_${newname}.conf ──────────────────"
        echo ""
        cat "/opt/wg/wgclient_${newname}.conf"
        echo ""
        echo "  ── QR Code ──────────────────────────────────────────────────"
        echo ""
        if command -v qrencode >/dev/null 2>&1; then
            qrencode -t ansiutf8 < "/opt/wg/wgclient_${newname}.conf" 2>/dev/null \
                || echo "  (qrencode failed)"
        else
            echo "  (qrencode not installed -- sudo apt install qrencode)"
        fi
        echo ""
        echo "  Scan the QR code with the WireGuard app, or copy the config file."
        echo "  New peer is already live on the server -- no restart needed."
        echo ""

        # When both ports are active, create the port-123 variant immediately.
        if $WG_USE_PORT_53 && $WG_USE_PORT_123; then
            local _new_ntp="/opt/wg/wgclient_${newname}_ntp.conf"
            sed "s/Endpoint = ${SERVER_IP}:53/Endpoint = ${SERVER_IP}:123/" \
                "/opt/wg/wgclient_${newname}.conf" > "$_new_ntp"
            chmod 600 "$_new_ntp"
            echo "  Created wgclient_${newname}_ntp.conf (Endpoint: ${SERVER_IP}:123)"
            echo "  Both configs are ready -- see port 123 entry in this menu."
        fi

        # Rebuild the per-client menu page so the new client appears
        local newconf="/opt/wg/wgclient_${newname}.conf"
        local newpadded newfile
        newpadded="$(printf '%02d' "$CLIENT_IDX")"
        newfile="$MENUDIR/${newpadded}_wg_${newname}.txt"
        {
            echo "================================================================"
            echo "  WireGuard Client: ${newname}"
            echo "================================================================"
            echo ""
            echo "  Config file: $newconf"
            echo "  Endpoint:    $(grep Endpoint "$newconf" | awk '{print $3}')"
            echo ""
            echo "  ── Config contents ─────────────────────────────────────────"
            echo ""
            cat "$newconf"
            echo ""
            echo "  ── QR Code (scan with WireGuard app) ───────────────────────"
            echo ""
            if command -v qrencode >/dev/null 2>&1; then
                qrencode -t ansiutf8 < "$newconf" 2>/dev/null || echo "  (qrencode failed)"
            else
                echo "  (qrencode not installed)"
            fi
            echo ""
            echo "  ── How to connect ──────────────────────────────────────────"
            echo ""
            echo "  Android / iOS:"
            echo "    1. Open WireGuard app"
            echo "    2. Tap + -> Scan QR code"
            echo "    3. Point camera at the QR code above"
            echo "    4. Activate the tunnel"
            echo ""
            echo "  Linux:"
            echo "    sudo wg-quick up $newconf"
            echo ""
            echo "  Linux -- if you see 'resolvconf: command not found':"
            echo "    sudo apt install resolvconf"
            echo "    sudo wg-quick up $newconf"
            echo ""
            echo "  Windows:"
            echo "    Import tunnel from file: $newconf"
            echo ""
            echo "  ┌─────────────────────────────────────────────────────────┐"
            echo "  │  ⚠  CELLULAR WARNING   ⚠   ⚠   ⚠   ⚠   ⚠   ⚠                  │"
            echo "  │                                                              │"
            echo "  │  WireGuard is ontop of UDP port 53. Most cell phone          │"
            echo "  │  carriers (Verizon,etc) run a transparent DNS proxy          │"
            echo "  │  ontop of your communications that intercepts UDP/53         │"
            echo "  │  This corrupts UDP :53 traffic that is not real DNS.         │"
            echo "  │                                                              │"
            echo "  │  Symptom: works on WiFi, fails on cellular.                  │"
            echo "  │  Fix: get off the cell network, or use iodine                │"
            echo "  │                                                              │"
            echo "  │  Android: iodine alone is your tunnel on cellular.           │"
            echo "  │                                                              │"
            echo "  │  See 'cellular warning' in this menu for full details.       │"
            echo "  └─────────────────────────────────────────────────────────┘"
        } > "$newfile"
        CLIENT_IDX=$((CLIENT_IDX + 1))

        # Rebuild the port-123 menu page for the new client when both ports active.
        if $WG_USE_PORT_53 && $WG_USE_PORT_123; then
            local newntp_conf="/opt/wg/wgclient_${newname}_ntp.conf"
            if [ -f "$newntp_conf" ]; then
                local newntp_padded newntp_file
                newntp_padded="$(printf '%02d' "$CLIENT_IDX")"
                newntp_file="$MENUDIR/${newntp_padded}_wg_${newname}_ntp.txt"
                {
                    echo "================================================================"
                    echo "  WireGuard Client: ${newname}  [port 123 / NTP bypass]"
                    echo "================================================================"
                    echo ""
                    echo "  Use this config when port 53 is intercepted by your carrier"
                    echo "  or network. Port 123 (NTP) is usually passed through without"
                    echo "  inspection and works where port 53 does not."
                    echo ""
                    echo "  Config file: $newntp_conf"
                    echo "  Endpoint:    $(grep Endpoint "$newntp_conf" | awk '{print $3}')"
                    echo ""
                    echo "  ── Config contents ─────────────────────────────────────────"
                    echo ""
                    cat "$newntp_conf"
                    echo ""
                    echo "  ── QR Code (scan with WireGuard app) ───────────────────────"
                    echo ""
                    if command -v qrencode >/dev/null 2>&1; then
                        qrencode -t ansiutf8 < "$newntp_conf" 2>/dev/null || echo "  (qrencode failed)"
                    else
                        echo "  (qrencode not installed)"
                    fi
                    echo ""
                    echo "  ── When to use port 123 vs port 53 ─────────────────────────"
                    echo ""
                    echo "  Port 53 works:    hotels, offices, most restrictive WiFi"
                    echo "  Port 123 works:   carriers that intercept/redirect UDP :53"
                    echo ""
                    echo "  Test port 53 first. If it fails on cellular but works on"
                    echo "  WiFi, switch to this port-123 config."
                } > "$newntp_file"
                CLIENT_IDX=$((CLIENT_IDX + 1))
            fi
        fi
    }

    action_crowdsec_live() {
        clear
        echo ""
        echo "  ╔══════════════════════════════════════════════════╗"
        echo "  ║   CrowdSec -- Live Decisions & System Status          ║"
        echo "  ╚══════════════════════════════════════════════════╝"
        echo ""

        if ! command -v cscli >/dev/null 2>&1; then
            echo "  ERROR: cscli not found -- CrowdSec may not be installed."
            return
        fi

        # Detect LAPI mode from the credentials file URL.
        # If the URL is not localhost/127.0.0.1, this node uses a remote LAPI.
        # cscli commands that require LAPI admin access (bouncers list) may
        # fail in remote mode -- the remote node has those credentials, not this one.
        local lapi_url
        lapi_url="$(grep '^url:' /etc/crowdsec/local_api_credentials.yaml 2>/dev/null \
            | awk '{print $2}' || true)"
        if [[ -n "$lapi_url" \
              && "$lapi_url" != *"127.0.0.1"* \
              && "$lapi_url" != *"localhost"* ]]; then
            echo "  NOTE: Remote LAPI mode detected."
            echo "        This node's agent sends events to: $lapi_url"
            echo "        Ban decisions and bouncer lists must be checked on the remote node."
            echo "        Commands that require LAPI admin access are skipped below."
            echo ""
        fi

        echo "  ── Service status ────────────────────────────────────"
        echo ""
        local cs_active cs_bouncer_active
        cs_active="$(systemctl is-active crowdsec 2>/dev/null)"
        cs_bouncer_active="$(systemctl is-active crowdsec-firewall-bouncer 2>/dev/null)"
        echo "    crowdsec agent:   $cs_active"
        echo "    nftables bouncer: $cs_bouncer_active"

        if nft list table ip crowdsec >/dev/null 2>&1; then
            local banned_ips
            banned_ips="$(nft list set ip crowdsec crowdsec-blacklists 2>/dev/null \
                | grep -oP '(?<=elements = \{ ).*(?= \})' \
                | tr ',' '\n' | grep -c '\.' 2>/dev/null || echo 0)"
            echo "    nftables crowdsec table: present  ($banned_ips IPs currently blocked)"
        elif [ "$cs_bouncer_active" = "active" ]; then
            echo ""
        else
            echo "    nftables crowdsec table: MISSING  <-- bouncer is not running"
        fi
        echo ""

        echo "  ── LAPI connectivity ─────────────────────────────────"
        echo ""
        cscli lapi status 2>&1 | sed 's/^/    /'
        echo ""

        echo "  ── Active ban decisions ──────────────────────────────"
        echo ""
        local decisions
        decisions="$(cscli decisions list 2>&1)"
        if echo "$decisions" | grep -qE 'No active decisions|No results'; then
            echo "    No active bans right now."
        else
            echo "$decisions" | sed 's/^/    /'
        fi
        echo ""

        echo "  ── Recent alerts (last 10) ───────────────────────────"
        echo ""
        local alerts
        alerts="$(cscli alerts list --limit 10 2>&1)"
        if echo "$alerts" | grep -qE 'No alerts|No results'; then
            echo "    No recent alerts."
        else
            echo "$alerts" | sed 's/^/    /'
        fi
        echo ""

        echo "  ── DNS decoy hits (last 24h) ─────────────────────────"
        echo ""
        local decoy_alerts
        decoy_alerts="$(cscli alerts list \
            --scenario custom/dns-decoy-scanner \
            --since 24h --limit 20 2>&1)"
        if echo "$decoy_alerts" | grep -qE 'No alerts|No results'; then
            echo "    No DNS decoy hits in the last 24 hours."
            echo "    (Either no scanners have probed port 53, or the"
            echo "     scenario has not yet accumulated enough events to ban.)"
        else
            echo "$decoy_alerts" | sed 's/^/    /'
        fi
        echo ""

        echo "  ── Registered bouncers ───────────────────────────────"
        echo ""
        cscli bouncers list 2>&1 | sed 's/^/    /'
        echo ""
    }

    # ── _install_grafana_dashboard ────────────────────────────────────────────
    # Called by action_install_dashboard when the user selects Grafana.
    # Not auto-dispatched by the menu loop (no action_ prefix).
    _install_grafana_dashboard() {
        clear
        local WG_SERVER_IP="${WG_NETWORK%.*}.1"
        local GRAFANA_DIR="/opt/crowdsec-grafana"

        echo ""
        echo "  ╔══════════════════════════════════════════════════╗"
        echo "  ║   CrowdSec Grafana Dashboard -- Local Install         ║"
        echo "  ╚══════════════════════════════════════════════════╝"
        echo ""
        echo "  Stack:"
        echo "    CrowdSec :6060/metrics  (Prometheus exporter, not a server)"
        echo "    Prometheus :9090        (scrapes CrowdSec, provides query API)"
        echo "    Grafana    :3000        (queries Prometheus, renders dashboards)"
        echo ""
        echo "  Both ports 3000 and 9090 are blocked from the internet by nftables."
        echo ""
        echo "  ── How to connect from your device ─────────────────"
        echo ""
        echo "  1. Connect your device to WireGuard or iodine first."
        echo "  2. Open a browser on that device and navigate to:"
        echo ""
        echo "       http://${WG_SERVER_IP}:3000    (via WireGuard)"
        echo "       http://${TUNNEL_IP}:3000         (via iodine)"
        echo ""

        command -v docker >/dev/null 2>&1 || { echo "  ERROR: docker not found."; return; }
        systemctl is-active crowdsec >/dev/null 2>&1 || {
            echo "  ERROR: crowdsec not running -- start it first."; return
        }

        if ! curl -sf http://127.0.0.1:6060/metrics >/dev/null 2>&1; then
            echo "  ERROR: CrowdSec metrics endpoint not responding at http://127.0.0.1:6060/metrics"
            echo "  Check: cscli metrics   and   journalctl -u crowdsec -n 20 --no-pager"
            return
        fi
        echo "  [OK]   CrowdSec metrics endpoint reachable at :6060/metrics"

        local any_exists=false
        for cname in crowdsec-grafana crowdsec-prometheus; do
            docker inspect "$cname" >/dev/null 2>&1 && any_exists=true
        done
        if $any_exists; then
            for cname in crowdsec-prometheus crowdsec-grafana; do
                if docker inspect "$cname" >/dev/null 2>&1; then
                    local st
                    st="$(docker inspect -f '{{.State.Status}}' "$cname" 2>/dev/null)"
                    echo "  Container $cname already exists (state: $st)."
                fi
            done
            echo ""
            echo "    r) Start/restart existing containers"
            echo "    R) Remove and reinstall both (clean slate)"
            echo "    q) Cancel"
            echo ""
            read -rp "  Choice: " ch || true
            case "$ch" in
                r)
                    docker start crowdsec-prometheus 2>/dev/null || true
                    docker start crowdsec-grafana    2>/dev/null || true
                    echo "  Started."
                    return ;;
                R)
                    docker rm -f crowdsec-prometheus crowdsec-grafana 2>/dev/null || true
                    echo "  Removed. Reinstalling..." ;;
                *)
                    echo "  Cancelled."; return ;;
            esac
        fi

        echo "  Creating directory layout under ${GRAFANA_DIR}..."
        mkdir -p "${GRAFANA_DIR}/prometheus"
        mkdir -p "${GRAFANA_DIR}/provisioning/datasources"
        mkdir -p "${GRAFANA_DIR}/provisioning/dashboards"

        cat > "${GRAFANA_DIR}/prometheus/prometheus.yml" << 'ENDYAML'
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'crowdsec'
    static_configs:
      - targets: ['localhost:6060']
        labels:
          instance: 'crowdsec'
ENDYAML
        echo "  [OK]   prometheus/prometheus.yml"

        cat > "${GRAFANA_DIR}/provisioning/datasources/crowdsec.yml" << 'ENDYAML'
apiVersion: 1
datasources:
  - name: CrowdSec
    type: prometheus
    access: proxy
    url: http://127.0.0.1:9090
    isDefault: true
    editable: false
ENDYAML
        echo "  [OK]   provisioning/datasources/crowdsec.yml  (url: 127.0.0.1:9090)"

        cat > "${GRAFANA_DIR}/provisioning/dashboards/provider.yml" << 'ENDYAML'
apiVersion: 1
providers:
  - name: "CrowdSec"
    orgId: 1
    folder: "CrowdSec"
    type: file
    disableDeletion: false
    updateIntervalSeconds: 30
    allowUiUpdates: false
    options:
      path: /etc/grafana/provisioning/dashboards
      foldersFromFilesStructure: false
ENDYAML
        echo "  [OK]   provisioning/dashboards/provider.yml"

        local BASE="https://raw.githubusercontent.com/crowdsecurity/grafana-dashboards/master/dashboards_v5"
        local DASHDIR="${GRAFANA_DIR}/provisioning/dashboards"
        local dl_ok=0

        echo "  Downloading CrowdSec v5 dashboards..."
        for entry in \
            "Crowdsec%20Overview.json|crowdsec-overview.json|crowdsec-overview" \
            "Crowdsec%20Insight.json|crowdsec-insight.json|crowdsec-insight" \
            "Crowdsec%20Details%20per%20Machine.json|crowdsec-details.json|crowdsec-details"; do
            local remote dst uid
            remote="${entry%%|*}"; rest="${entry#*|}"; dst="${rest%%|*}"; uid="${rest#*|}"
            if curl -fsSL "${BASE}/${remote}" -o "${DASHDIR}/${dst}.tmp" 2>/dev/null; then
                patch_dashboard "${DASHDIR}/${dst}.tmp" "${DASHDIR}/${dst}" "$uid"
                rm -f "${DASHDIR}/${dst}.tmp"
                dl_ok=$((dl_ok+1))
            else
                echo "  WARN:  Download failed for ${remote}"
            fi
        done

        if [ "$dl_ok" -gt 0 ]; then
            echo "  [OK]   $dl_ok/3 dashboards ready"
        else
            echo "  WARN:  All downloads failed. Import manually from:"
            echo "    https://github.com/crowdsecurity/grafana-dashboards/tree/master/dashboards_v5"
        fi

        echo "  Pulling images..."
        docker pull prom/prometheus:latest || { echo "  ERROR: prometheus pull failed."; return; }
        docker pull grafana/grafana:latest || { echo "  ERROR: grafana pull failed.";    return; }

        echo "  Starting Prometheus..."
        docker run -d \
            --name crowdsec-prometheus \
            --restart unless-stopped \
            --network host \
            -v "${GRAFANA_DIR}/prometheus/prometheus.yml:/etc/prometheus/prometheus.yml:ro" \
            prom/prometheus:latest \
            --config.file=/etc/prometheus/prometheus.yml \
            --web.listen-address=127.0.0.1:9090 \
            --storage.tsdb.retention.time=7d || {
                echo "  ERROR: Prometheus start failed."
                echo "  Check: docker logs crowdsec-prometheus"
                return
            }

        local p=0
        until curl -sf http://127.0.0.1:9090/-/ready >/dev/null 2>&1; do
            sleep 2; p=$((p+1))
            [ $p -ge 15 ] && { echo "  WARN: Prometheus slow to start -- continuing anyway"; break; }
        done
        echo "  [OK]   Prometheus ready at :9090"

        echo "  Starting Grafana..."
        docker run -d \
            --name crowdsec-grafana \
            --restart unless-stopped \
            --network host \
            -e GF_SERVER_HTTP_PORT=3000 \
            -e GF_AUTH_ANONYMOUS_ENABLED=true \
            -e GF_AUTH_ANONYMOUS_ORG_ROLE=Viewer \
            -e GF_SECURITY_ALLOW_EMBEDDING=true \
            -e "GF_DASHBOARDS_DEFAULT_HOME_DASHBOARD_PATH=/etc/grafana/provisioning/dashboards/crowdsec-overview.json" \
            -v "${GRAFANA_DIR}/provisioning:/etc/grafana/provisioning" \
            grafana/grafana:latest || {
                echo "  ERROR: Grafana start failed."
                echo "  Check: docker logs crowdsec-grafana"
                return
            }

        echo "  Waiting for Grafana (may take up to 90 seconds)..."
        sleep 5
        local i=0
        until curl -sf http://127.0.0.1:3000/api/health >/dev/null 2>&1; do
            sleep 3; printf "."; i=$((i+1))
            [ $i -ge 30 ] && {
                echo ""
                echo "  Grafana health check timed out."
                echo "    docker ps                       # confirm Up"
                echo "    docker logs crowdsec-grafana    # check for errors"
                echo "    curl http://127.0.0.1:3000/api/health"
                return
            }
        done
        echo " ready."

        sleep 5
        local targets_json targets
        targets_json="$(curl -sf 'http://127.0.0.1:9090/api/v1/targets' 2>/dev/null || true)"
        if echo "$targets_json" | grep -q '"crowdsec"' \
            && echo "$targets_json" | grep -q '"health":"up"'; then
            targets="up"
        elif [ -n "$targets_json" ]; then
            targets="not_up"
        else
            targets="unknown"
        fi
        if [ "$targets" = "up" ]; then
            echo "  [OK]   Prometheus scraping CrowdSec (target: up)"
        else
            echo "  NOTE:  Prometheus target status: $targets (may need 15s to first scrape)"
        fi

        echo ""
        echo "  ╔══════════════════════════════════════════════════╗"
        echo "  ║   Stack is ready                                      ║"
        echo "  ╚══════════════════════════════════════════════════╝"
        echo ""
        echo "  Connect VPN then open in your browser:"
        echo "       http://${WG_SERVER_IP}:3000    (WireGuard)"
        echo "       http://${TUNNEL_IP}:3000         (iodine)"
        echo ""
        echo "  The CrowdSec Overview dashboard loads automatically."
        echo "  No login needed to view. Admin: admin / admin (change on first login)."
        echo ""
        echo "  ── Verify Prometheus is scraping ─────────────────────"
        echo ""
        echo "    curl http://127.0.0.1:9090/api/v1/targets | jq ."
        echo "    curl http://127.0.0.1:9090/api/v1/query?query=cs_active_decisions"
        echo ""
        echo "  ── Container management ─────────────────────────────"
        echo ""
        echo "    docker stop  crowdsec-prometheus crowdsec-grafana"
        echo "    docker start crowdsec-prometheus crowdsec-grafana"
        echo "    docker logs  crowdsec-prometheus"
        echo "    docker logs  crowdsec-grafana"
        echo "    docker rm -f crowdsec-prometheus crowdsec-grafana"
        echo ""
    }

    # ── _install_crowdsec_webui ───────────────────────────────────────────────
    # Called by action_install_dashboard when the user selects Web UI.
    # Not auto-dispatched by the menu loop (no action_ prefix).
    _install_crowdsec_webui() {
        clear
        local WEBUI_DATA="/opt/crowdsec-webui/data"
        local WEBUI_CONTAINER="crowdsec-web-ui"

        echo ""
        echo "  ╔══════════════════════════════════════════════════╗"
        echo "  ║   CrowdSec Web UI -- Local Install                    ║"
        echo "  ╚══════════════════════════════════════════════════╝"
        echo ""
        echo "  A modern React/Bun dashboard for CrowdSec."
        echo "  Manages alerts and decisions directly via the LAPI."
        echo "  No Prometheus or Grafana required."
        echo ""
        echo "  Source: https://github.com/TheDuffman85/crowdsec-web-ui"
        echo ""
        echo "  SECURITY: This UI has no built-in authentication."
        echo "  It is accessible only over WireGuard or iodine (VPN-only"
        echo "  port rule in nftables). Do not expose it publicly."
        echo ""

        # ── Prerequisites ─────────────────────────────────────────────────────
        command -v docker >/dev/null 2>&1 \
            || { echo "  ERROR: docker not found."; return; }
        command -v cscli >/dev/null 2>&1 \
            || { echo "  ERROR: cscli not found -- CrowdSec may not be installed."; return; }
        systemctl is-active crowdsec >/dev/null 2>&1 \
            || { echo "  ERROR: crowdsec not running -- start it first."; return; }

        # ── Detect LAPI URL from deployed credentials ──────────────────────────
        # Same detection pattern used by action_crowdsec_live.
        # For local mode this is http://127.0.0.1:8080.
        # For remote mode this is whatever was configured at install time.
        local lapi_url
        lapi_url="$(grep '^url:' /etc/crowdsec/local_api_credentials.yaml 2>/dev/null \
            | awk '{print $2}' | tr -d '[:space:]' || true)"
        if [ -z "$lapi_url" ]; then
            lapi_url="http://127.0.0.1:8080"
            echo "  NOTE: Could not read LAPI URL from local_api_credentials.yaml."
            echo "        Defaulting to http://127.0.0.1:8080"
        fi
        echo "  LAPI URL: $lapi_url"
        echo ""

        # ── Port 3000 conflict check ───────────────────────────────────────────
        # The web UI binds port 3000. The Grafana stack (action_install_dashboard)
        # also uses port 3000. They cannot coexist on the same port.
        # If Grafana containers exist, warn and offer to stop them.
        local grafana_running=false
        docker inspect crowdsec-grafana >/dev/null 2>&1 \
            && [ "$(docker inspect -f '{{.State.Running}}' crowdsec-grafana 2>/dev/null)" = "true" ] \
            && grafana_running=true

        if $grafana_running; then
            echo "  WARNING: crowdsec-grafana is currently running on port 3000."
            echo "           The Web UI also uses port 3000. Both cannot run at once."
            echo ""
            echo "    s) Stop Grafana and continue installing Web UI"
            echo "    q) Cancel"
            echo ""
            read -rp "  Choice: " _gf_ch || true
            case "${_gf_ch:-q}" in
                s)
                    docker stop crowdsec-grafana 2>/dev/null || true
                    echo "  crowdsec-grafana stopped."
                    ;;
                *)
                    echo "  Cancelled."; return ;;
            esac
            echo ""
        fi

        # ── Existing web UI container check ───────────────────────────────────
        if docker inspect "$WEBUI_CONTAINER" >/dev/null 2>&1; then
            local st
            st="$(docker inspect -f '{{.State.Status}}' "$WEBUI_CONTAINER" 2>/dev/null)"
            echo "  Container $WEBUI_CONTAINER already exists (state: $st)."
            echo ""
            echo "    r) Start/restart existing container"
            echo "    R) Remove and reinstall (clean slate -- data volume preserved)"
            echo "    q) Cancel"
            echo ""
            read -rp "  Choice: " _wu_ch || true
            case "${_wu_ch:-q}" in
                r)
                    docker start "$WEBUI_CONTAINER" 2>/dev/null || true
                    echo "  Started."
                    echo "  Connect VPN then open: http://${WG_NETWORK%.*}.1:3000"
                    return ;;
                R)
                    docker rm -f "$WEBUI_CONTAINER" 2>/dev/null || true
                    echo "  Removed. Reinstalling..." ;;
                *)
                    echo "  Cancelled."; return ;;
            esac
            echo ""
        fi

        # ── Machine account registration ──────────────────────────────────────
        # The web UI authenticates against the LAPI as a "machine" (watcher).
        # We register it here with a generated password.
        # -f /dev/null: do NOT write a local_api_credentials.yaml file.
        #   This is critical -- cscli machines add would otherwise overwrite
        #   /etc/crowdsec/local_api_credentials.yaml, breaking the agent's own
        #   LAPI connection.
        # If the machine already exists, cscli exits non-zero but that is safe
        # to ignore -- the existing registration is still valid.
        echo "  ── Machine account setup ──────────────────────────────────"
        echo ""
        local WEBUI_PASS
        WEBUI_PASS="$(openssl rand -hex 32)"
        echo "  Generated web UI machine password."

        if cscli machines list 2>/dev/null | grep -q 'crowdsec-web-ui'; then
            echo "  Machine 'crowdsec-web-ui' already registered."
            echo "  A new password will be set. If this container was previously"
            echo "  running with a different password, it will be replaced."
            # Update password by re-adding -- cscli machines add is idempotent
            # when the machine already exists; it updates the password.
            cscli machines add crowdsec-web-ui --password "$WEBUI_PASS" -f /dev/null 2>/dev/null \
                || { echo "  ERROR: Failed to update machine password."; return; }
            echo "  [OK]   Machine password updated."
        else
            cscli machines add crowdsec-web-ui --password "$WEBUI_PASS" -f /dev/null 2>/dev/null \
                || { echo "  ERROR: Failed to register machine with LAPI."; return; }
            echo "  [OK]   Machine 'crowdsec-web-ui' registered with LAPI."
        fi
        echo ""

        # ── Pull image ────────────────────────────────────────────────────────
        echo "  Pulling image ghcr.io/theduffman85/crowdsec-web-ui:latest ..."
        docker pull ghcr.io/theduffman85/crowdsec-web-ui:latest \
            || { echo "  ERROR: image pull failed."; return; }
        echo "  [OK]   Image ready."

        # ── Data directory ────────────────────────────────────────────────────
        # Pre-create the data directory owned by UID/GID 1000 -- the bun user
        # inside the container. The entrypoint runs a chown on /app/data; if the
        # directory is already owned by 1000:1000 that chown is a no-op and the
        # container starts cleanly. If it is root:root the chown fails (CRITICAL
        # FAILURE) and the container restart-loops.
        mkdir -p "$WEBUI_DATA"
        chown 1000:1000 "$WEBUI_DATA"
        echo "  [OK]   Data directory: $WEBUI_DATA (owned 1000:1000 for bun user)"

        # ── Pull image ────────────────────────────────────────────────────────
        echo "  Pulling image ghcr.io/theduffman85/crowdsec-web-ui:latest ..."
        docker pull ghcr.io/theduffman85/crowdsec-web-ui:latest \
            || { echo "  ERROR: image pull failed."; return; }
        echo "  [OK]   Image ready."

        # ── Start container ───────────────────────────────────────────────────
        # --network host: LAPI is on 127.0.0.1:8080 (local) or a routable address
        #   (remote). Host networking makes both reachable without extra config.
        #   As a side effect, the container's requests appear from 127.0.0.1,
        #   which is in CrowdSec's default trusted_ips -- delete operations work
        #   without any additional config.yaml changes.
        # Port 3000 is already allowed from VPN subnets in nftables.
        echo "  Starting $WEBUI_CONTAINER ..."
        docker run -d \
            --name "$WEBUI_CONTAINER" \
            --restart unless-stopped \
            --network host \
            -e CROWDSEC_URL="$lapi_url" \
            -e CROWDSEC_USER=crowdsec-web-ui \
            -e CROWDSEC_PASSWORD="$WEBUI_PASS" \
            -e CROWDSEC_LOOKBACK_PERIOD=7d \
            -e CROWDSEC_REFRESH_INTERVAL=30s \
            -v "$WEBUI_DATA:/app/data" \
            ghcr.io/theduffman85/crowdsec-web-ui:latest \
            || { echo "  ERROR: container failed to start."; echo "  Check: docker logs $WEBUI_CONTAINER"; return; }

        # ── Health check ──────────────────────────────────────────────────────
        echo "  Waiting for Web UI to become ready..."
        local i=0
        until curl -sf http://127.0.0.1:3000/api/health >/dev/null 2>&1; do
            sleep 2; printf "."; i=$((i+1))
            [ $i -ge 30 ] && {
                echo ""
                echo "  Health check timed out."
                echo "    docker ps                         # confirm Up"
                echo "    docker logs $WEBUI_CONTAINER      # check for errors"
                echo "    curl http://127.0.0.1:3000/api/health"
                return
            }
        done
        echo " ready."
        echo ""

        local WG_SERVER_IP="${WG_NETWORK%.*}.1"
        echo "  ╔══════════════════════════════════════════════════╗"
        echo "  ║   Web UI is ready                                     ║"
        echo "  ╚══════════════════════════════════════════════════╝"
        echo ""
        echo "  Connect VPN then open in your browser:"
        echo "       http://${WG_SERVER_IP}:3000    (via WireGuard)"
        echo "       http://${TUNNEL_IP}:3000         (via iodine)"
        echo ""
        echo "  ── Container management ──────────────────────────────"
        echo ""
        echo "    docker stop  $WEBUI_CONTAINER"
        echo "    docker start $WEBUI_CONTAINER"
        echo "    docker logs  $WEBUI_CONTAINER"
        echo "    docker rm -f $WEBUI_CONTAINER"
        echo ""
        echo "  ── Data persistence ──────────────────────────────────"
        echo ""
        echo "    Host path:  $WEBUI_DATA"
        echo "    Database:   $WEBUI_DATA/crowdsec.db"
        echo "    Alerts retained for 7 days (CROWDSEC_LOOKBACK_PERIOD)."
        echo "    Data survives container restarts and reinstalls."
        echo ""
        echo "  ── Re-running this install replaces the machine password."
        echo "     The container will be restarted with the new credentials."
        echo ""
    }

    # ── action_install_dashboard ─────────────────────────────────────────────
    # Entry point dispatched by the menu loop from 60_install_dashboard.sh.
    # Presents a choice between the Grafana stack and the CrowdSec Web UI,
    # then delegates to the appropriate helper function.
    # Both use port 3000 -- only one can run at a time.
    action_install_dashboard() {
        clear
        echo ""
        echo "  ╔══════════════════════════════════════════════════╗"
        echo "  ║   CrowdSec Dashboard -- Choose Your Stack             ║"
        echo "  ╚══════════════════════════════════════════════════╝"
        echo ""
        echo "  Both options serve a dashboard on port 3000 (VPN-only)."
        echo "  Only one can run at a time on the same port."
        echo ""

        # ── AVX check for Web UI ──────────────────────────────────────────────
        # The crowdsec-web-ui container runs Bun, which requires AVX CPU
        # instructions. Without AVX the Bun binary receives SIGILL (exit 132)
        # on startup regardless of permissions, volumes, or configuration.
        # This is a CPU feature check, not a kernel or Docker version check.
        # VMs that do not expose host CPU flags to guests will fail this test
        # even if the physical host has AVX capable hardware.
        local _avx_ok="false"
        grep -qw 'avx' /proc/cpuinfo 2>/dev/null && _avx_ok="true"

        echo "  ── Option 1: Grafana + Prometheus ─────────────────────────────"
        echo ""
        echo "    Metrics-based. Pulls from CrowdSec's Prometheus endpoint."
        echo "    Shows ban counts, parser rates, alert trends over time."
        echo "    Three pre-built panels: Overview, Insight, Per-Machine."
        echo "    No authentication built-in."
        echo "    Works on all CPUs."
        echo ""
        echo "  ── Option 2: CrowdSec Web UI ───────────────────────────────────"
        echo ""
        echo "    React/Bun dashboard. Connects directly to the LAPI."
        echo "    View and manage individual alerts and decisions."
        echo "    Ban IPs manually. Filter by status. IP geolocation."
        echo "    Lighter-weight -- no Prometheus or separate metrics stack."
        echo "    No authentication built-in."
        echo "    Source: https://github.com/TheDuffman85/crowdsec-web-ui"
        echo ""
        if [ "$_avx_ok" = "true" ]; then
            echo "    CPU: AVX detected -- Web UI is compatible with this host."
        else
            echo "    CPU: AVX NOT detected -- Web UI CANNOT run on this host."
            echo "    The Bun runtime requires AVX CPU instructions (Intel/AMD"
            echo "    circa 2011+). This host either lacks AVX in hardware or"
            echo "    is a VM on a CPU that predates AVX (e.g. AMD Phenom II,"
            echo "    Intel Core 2). There is no software workaround."
            echo "    Option 2 is disabled. Use Grafana instead."
        fi
        echo ""

        if [ "$_avx_ok" = "true" ]; then
            echo "    1)  Install Grafana + Prometheus"
            echo "    2)  Install CrowdSec Web UI"
            echo "    q)  Cancel"
            echo ""
            read -rp "  Choice: " _dash_ch || true
            case "${_dash_ch:-q}" in
                1) _install_grafana_dashboard ;;
                2) _install_crowdsec_webui    ;;
                *) echo "  Cancelled."; return ;;
            esac
        else
            echo "    1)  Install Grafana + Prometheus"
            echo "    q)  Cancel"
            echo ""
            read -rp "  Choice: " _dash_ch || true
            case "${_dash_ch:-q}" in
                1) _install_grafana_dashboard ;;
                *) echo "  Cancelled."; return ;;
            esac
        fi
    }

    clear
    echo ""
    echo "  ╔══════════════════════════════════════════════════╗"
    echo "  ║   DNS Tunnel + WireGuard  --  Setup Complete          ║"
    echo "  ╚══════════════════════════════════════════════════╝"
    echo ""
    echo "  Use the menu below to view connection info, QR codes,"
    echo "  service commands, and CrowdSec monitoring."
    echo ""

    while true; do
        echo "  ── Select a section ──────────────────────────────"
        echo ""

        local MENU_FILES=() MENU_LABELS=() MENU_TYPES=()
        for f in "$MENUDIR"/*.txt "$MENUDIR"/*.sh; do
            [ -f "$f" ] || continue
            local base label ftype
            base="$(basename "$f")"
            label="${base%.*}"
            ftype="${base##*.}"
            label="${label#[0-9][0-9]_}"
            label="${label//_/ }"
            MENU_FILES+=("$f")
            MENU_LABELS+=("$label")
            MENU_TYPES+=("$ftype")
        done

        for i in "${!MENU_LABELS[@]}"; do
            if [[ "${MENU_TYPES[$i]}" == "sh" ]]; then
                printf "    %2d)  * %s\n" "$((i+1))" "${MENU_LABELS[$i]}"
            else
                printf "    %2d)  %s\n" "$((i+1))" "${MENU_LABELS[$i]}"
            fi
        done
        echo ""
        echo "     q)  Exit"
        echo ""
        read -rp "  Choice: " choice || true

        if [[ "$choice" == "q" || "$choice" == "Q" ]]; then
            clear
            echo "  Exiting. Configs are in /opt/wg/"
            echo "  Run this script again at any time to return to this menu."
            echo ""
            break
        fi

        if [[ "$choice" =~ ^[0-9]+$ ]] \
            && [ "$choice" -ge 1 ] \
            && [ "$choice" -le "${#MENU_FILES[@]}" ]; then
            local chosen_type="${MENU_TYPES[$((choice-1))]}"
            local chosen_file="${MENU_FILES[$((choice-1))]}"
            if [[ "$chosen_type" == "sh" ]]; then
                local action_base
                action_base="$(basename "$chosen_file" .sh)"
                action_base="${action_base#[0-9][0-9]_}"
                local action_fn="action_${action_base}"
                if declare -f "$action_fn" >/dev/null 2>&1; then
                    $action_fn
                else
                    echo "  ERROR: action function '$action_fn' not defined."
                fi
            else
                show_section "$chosen_file"
            fi
            echo ""
            read -rsp "  Press any key to return to menu..." -n1 || true
            clear
        else
            echo "  Invalid choice."
        fi
    done
}

# ── show_install_menu ─────────────────────────────────────────────────────────
# Presented once at startup (after root check, before any install work).
# Sets the four component-selection globals used throughout the rest of the script.
# Re-presented on re-runs so the user can change their selection.
show_install_menu() {
    clear
    echo ""
    echo "  ╔══════════════════════════════════════════════════════════╗"
    echo "  ║   Component Selection                                         ║"
    echo "  ╚══════════════════════════════════════════════════════════╝"
    echo ""
    echo "  Always installed:  nftables  iodine  CoreDNS  Docker"
    echo ""
    echo "  ── WireGuard ────────────────────────────────────────────────"
    echo ""
    echo "    1)  Install locally  (this node is the WireGuard server)"
    echo "    2)  Skip             (WireGuard is elsewhere or not needed)"
    echo "                         nftables DNAT rule is still written"
    echo ""
    read -rp "  WireGuard [1/2, default 1]: " _wg_ch
    case "${_wg_ch:-1}" in
        2) INSTALL_WIREGUARD=false ;;
        *) INSTALL_WIREGUARD=true  ;;
    esac

    if $INSTALL_WIREGUARD; then
        echo ""
        echo "  ── WireGuard tunnel port ────────────────────────────────────"
        echo ""
        echo "    1)  53    DNS port  (default)"
        echo "    2)  123   NTP port"
        echo "    3)  BOTH  one client config per port per peer"
        echo ""

        while true; do
            read -rp "  Tunnel port [1/2/3, default 1]: " _wgport_ch
            case "${_wgport_ch:-1}" in
                1)
                    WG_USE_PORT_53=true
                    WG_USE_PORT_123=false
                    break
                    ;;
                2|3)
                    # ── Port 123 warning gate ─────────────────────────────
                    # Inner loop: warning screen is redrawn on every iteration
                    # so that invalid input (including bare Enter) never drops
                    # the user back to the tunnel-port prompt without context.
                    # 'back' breaks inner and falls through to redraw the port
                    # menu before the outer loop re-reads _wgport_ch.
                    # 'I understand' sets vars and breaks the outer loop.
                    _p123_go_back=false
                    while true; do
                        clear
                        echo ""
                        echo "  ╔══════════════════════════════════════════════════════════╗"
                        echo "  ║   !! WARNING: Port 123 (NTP) has severe limitations !!        ║"
                        echo "  ╚══════════════════════════════════════════════════════════╝"
                        echo ""
                        echo "  Before selecting port 123, you must understand the following."
                        echo ""
                        echo "  ── What port 123 solves ─────────────────────────────────────"
                        echo ""
                        echo "    Port 53 is intercepted by carrier DNS proxies on some"
                        echo "    cellular networks.  Port 123 (NTP) bypasses those proxies"
                        echo "    because carriers do not redirect NTP traffic."
                        echo ""
                        echo "  ── What port 123 does NOT solve ─────────────────────────────"
                        echo ""
                        echo "    1. ISP RATE CAP (~50 Kbps / ~5 packets/sec)"
                        echo ""
                        echo "       Some carriers rate-limit ALL UDP/123 traffic to ~50 Kbps."
                        echo "       This is a hard ceiling imposed upstream. Dial-up speed."
                        echo "       WireGuard will connect but the experience will be:"
                        echo "         - Web browsing: extremely slow"
                        echo "         - Video/audio:  unusable"
                        echo "         - SSH / text:   marginally usable"
                        echo ""
                        echo "       There is no server-side fix for this.  It is an ISP"
                        echo "       policy enforced in their network, not yours."
                        echo ""
                        echo "    2. DPI FINGERPRINTING (payload inspection)"
                        echo ""
                        echo "       Carriers that do deep packet inspection check that"
                        echo "       UDP/123 traffic matches NTP's fixed 48-byte payload."
                        echo "       There is no server-side fix for DPI.  If this happens,"
                        echo "       iodine (DNS tunnel) is your only fallback."
                        echo ""
                        echo "  ── Summary ──────────────────────────────────────────────────"
                        echo ""
                        echo "    Don't use NTP. Use iodine."
                        echo ""
                        echo "  ─────────────────────────────────────────────────────────────"
                        echo ""
                        echo "    Type  'I understand'  to proceed with port 123."
                        echo "    Type  'back'          to return to port selection."
                        echo ""
                        read -rp "  > " _p123_confirm
                        case "${_p123_confirm}" in
                            "I understand"|"i understand")
                                if [ "${_wgport_ch}" = "2" ]; then
                                    WG_USE_PORT_53=false
                                    WG_USE_PORT_123=true
                                else
                                    WG_USE_PORT_53=true
                                    WG_USE_PORT_123=true
                                fi
                                clear
                                break 2
                                ;;
                            back|Back|BACK)
                                _p123_go_back=true
                                break
                                ;;
                            *)
                                echo ""
                                echo "  Type 'I understand' to proceed, or 'back' to go back."
                                read -rsp "  Press any key..." -n1
                                echo ""
                                ;;
                        esac
                    done
                    # Redraw the port menu before the outer loop re-reads
                    if $_p123_go_back; then
                        clear
                        echo ""
                        echo "  ── WireGuard tunnel port ────────────────────────────────────"
                        echo ""
                        echo "    1)  53    DNS port  (default)"
                        echo "    2)  123   NTP port"
                        echo "    3)  BOTH  one client config per port per peer"
                        echo ""
                    fi
                    ;;
                *)
                    echo "  Invalid choice."
                    ;;
            esac
        done
    fi

    echo ""
    echo "  ── CrowdSec ─────────────────────────────────────────────────"
    echo ""
    echo "    1)  Local LAPI   (this node runs the CrowdSec brain + bouncer)"
    echo "    2)  Remote LAPI  (agent + bouncer here; LAPI is on another node)"
    echo "                     Before selecting this, on the remote node run:"
    echo "                       cscli machines add <this-node-name> --auto"
    echo "                       cscli bouncers add <bouncer-name> -o raw"
    echo "    3)  Skip         (no CrowdSec)"
    echo ""
    read -rp "  CrowdSec [1/2/3, default 1]: " _cs_ch
    case "${_cs_ch:-1}" in
        2) INSTALL_CS=true;  CS_LAPI_MODE=remote ;;
        3) INSTALL_CS=false; CS_LAPI_MODE=none   ;;
        *) INSTALL_CS=true;  CS_LAPI_MODE=local  ;;
    esac

    echo ""
    echo "  ── Selection summary ────────────────────────────────────────"
    echo ""
    echo "    Always:    nftables  iodine  CoreDNS  Docker"
    if $INSTALL_WIREGUARD; then
        local _port_desc="port 53 only"
        $WG_USE_PORT_123 && ! $WG_USE_PORT_53 && _port_desc="port 123 only"
        $WG_USE_PORT_53  && $WG_USE_PORT_123   && _port_desc="ports 53 + 123 (dual)"
        echo "    WireGuard: install locally ($_port_desc)"
    else
        echo "    WireGuard: skip  (DNAT prerouting rule still written)"
    fi
    if $INSTALL_CS; then
        if [ "$CS_LAPI_MODE" = "remote" ]; then
            echo "    CrowdSec:  agent + bouncer -> remote LAPI"
            echo "               (credentials will be prompted in Configuration)"
        else
            echo "    CrowdSec:  full install with local LAPI"
        fi
    else
        echo "    CrowdSec:  skip"
    fi
    echo ""
    read -rp "  Proceed with this selection? [Y/n]: " _sel_confirm
    _sel_confirm="${_sel_confirm:-Y}"
    [[ "$_sel_confirm" =~ ^[Yy]$ ]] || die "Aborted."
}

# ── Component selection flags ─────────────────────────────────────────────────
# Defaults; overwritten by show_install_menu() before any install work starts.
INSTALL_WIREGUARD=true
WG_USE_PORT_53=true    # expose WireGuard on UDP 53 (DNAT prerouting)
WG_USE_PORT_123=false  # expose WireGuard on UDP 123 (NTP port bypass)
INSTALL_CS=true
CS_LAPI_MODE=local    # local | remote | none

# Remote LAPI credentials -- populated by the Configuration section when
# INSTALL_CS=true and CS_LAPI_MODE=remote.
CS_LAPI_URL=""
CS_MACHINE_LOGIN=""
CS_MACHINE_PASSWORD=""
CS_BOUNCER_KEY=""

# ── Cleanup ───────────────────────────────────────────────────────────────────
GENDIR=""
MENUDIR=""
cleanup() {
    [ -n "$GENDIR"  ] && rm -rf "$GENDIR"
    [ -n "$MENUDIR" ] && rm -rf "$MENUDIR"
}
trap cleanup EXIT INT TERM

# ── Intro ─────────────────────────────────────────────────────────────────────
clear
cat << 'INTRO'
'##::::'##:'########::'##::: ##::::::::::'########::'#######::
 ##:::: ##: ##.... ##: ###:: ##:::::::::: ##.....::'##.... ##:
 ##:::: ##: ##:::: ##: ####: ##:::::::::: ##:::::::..::::: ##:
 ##:::: ##: ########:: ## ## ##:'#######: #######:::'#######::
. ##:: ##:: ##.....::: ##. ####:........:...... ##::...... ##:
:. ## ##::: ##:::::::: ##:. ###::::::::::'##::: ##:'##:::: ##:
::. ###:::: ##:::::::: ##::. ##::::::::::. ######::. #######::
:::...:::::..:::::::::..::::..::::::::::::......::::.......:::
   DNS TUNNEL + WIREGUARD VPN + CROWDSEC IPS  --  ports 53 / 123

  Architecture:
    nftables (kernel)  -- inspects first 4 bytes of every UDP:53 and UDP:123 packet
      WireGuard bytes  -->  wg-quick on :51820  (kernel redirect, no proxy)
      DNS bytes        -->  CoreDNS on :53
    CoreDNS            -- tunnel domain --> iodined; everything else --> decoy
    iodined            -- iodine DNS tunnel on 127.0.0.1:5300
    wg-quick           -- WireGuard hub on :51820 (optional; see component menu)
    CrowdSec           -- IDS/IPS: DNS decoy sensor, SSH + port-scan detection
                          port 123: non-WireGuard traffic is dropped
                          optional; local LAPI or remote LAPI mode

  Always installed:
    nftables firewall, iodine DNS tunnel, CoreDNS, Docker

  Optional (selected at component menu):
    WireGuard VPN -- port 53 only, port 123 only, or both
      Port 53:  gets through most firewalls and captive portals
      Port 123: NTP port, bypasses carrier DNS proxies ONLY
                WARNING: some ISPs rate-cap UDP/123 to ~50 Kbps (dial-up speed)
                probes on :123 detected via CROWDSEC_DROP + s02-enrich
    CrowdSec IPS (local LAPI or remote LAPI)

  What you need before running:
    Two DNS records at your registrar:
      tunnel.yourdomain.com   IN NS   address.yourdomain.com
      address.yourdomain.com  IN A    <this server's public IP>
    DNS propagation takes up to 48 hours -- set these up first.

INTRO

read -rsp "  Press any key to continue, Ctrl-C to abort..." -n1
echo ""; echo ""

# ── Root check ────────────────────────────────────────────────────────────────
[ "$(id -u)" -eq 0 ] || { echo "ERROR: Must be run as root." >&2; exit 1; }

# ── Existing install check ────────────────────────────────────────────────────
# Sentinel: /opt/iodine/docker-compose.yml
# iodine is always installed; this file's presence indicates a prior run.
# The previous sentinel (wghub.conf) was WireGuard-specific and would not
# detect installs where WireGuard was skipped.
if [ -f /opt/iodine/docker-compose.yml ]; then
    clear
    echo ""
    echo "  ╔══════════════════════════════════════════════════╗"
    echo "  ║   Existing installation detected                      ║"
    echo "  ║   /opt/iodine/docker-compose.yml exists               ║"
    echo "  ╚══════════════════════════════════════════════════╝"
    echo ""
    echo "  What would you like to do?"
    echo ""
    echo "    1)  View Setup Complete menu  (QR codes, connect info -- no changes made)"
    echo "    2)  Re-run full install       (reconfigures everything from scratch)"
    echo "    3)  Exit"
    echo ""
    read -rp "  Choice [1/2/3]: " EXISTING_CHOICE
    case "${EXISTING_CHOICE:-1}" in
        1)
            echo ""
            echo "  Reading existing configuration from deployed files..."
            load_existing_config
            build_and_show_menu
            exit 0
            ;;
        2)
            echo ""
            echo "  Continuing with full install."
            echo "  Idempotency guards will skip wghub.conf and existing client configs."
            echo ""
            read -rsp "  Press any key to continue..." -n1; echo ""; echo ""
            ;;
        *)
            echo "  Exiting."
            exit 0
            ;;
    esac
fi

# ── Component selection ───────────────────────────────────────────────────────
# Must run after the existing-install check so a re-run can re-select components.
show_install_menu

# ── Pre-flight ────────────────────────────────────────────────────────────────
section "Pre-flight checks"

[ "$(id -u)" -eq 0 ] || die "Must be run as root."
for cmd in ss ip curl gpg openssl apt-get; do
    command -v "$cmd" >/dev/null 2>&1 || die "'$cmd' not found -- this script requires Debian/Ubuntu."
done
echo "  Pre-flight passed."

# ── Install dependencies ──────────────────────────────────────────────────────
section "Installing dependencies"

apt-get update -qq

# conntrack: required to flush stale conntrack entries after nftables reloads.
# Without conntrack -F, existing entries bypass prerouting and WireGuard packets
# go to CoreDNS instead of being redirected to :51820.
# wireguard-tools and qrencode are only needed when WireGuard is installed locally.
if $INSTALL_WIREGUARD; then
    apt-get install -y nftables dnsutils wireguard-tools qrencode conntrack jq
    echo "  nftables, dnsutils, wireguard-tools, qrencode, conntrack, jq: installed"
else
    apt-get install -y nftables dnsutils conntrack jq
    echo "  nftables, dnsutils, conntrack, jq: installed"
    echo "  wireguard-tools, qrencode: skipped (WireGuard not selected)"
fi

if ! command -v docker >/dev/null 2>&1; then
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/debian/gpg \
        | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    chmod a+r /etc/apt/keyrings/docker.gpg
    echo \
        "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
https://download.docker.com/linux/debian \
$(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
        > /etc/apt/sources.list.d/docker.list
    apt-get update -qq
    apt-get install -y docker-ce docker-ce-cli containerd.io \
        docker-buildx-plugin docker-compose-plugin
    echo "  Docker Engine: installed"
else
    echo "  Docker Engine: already installed"
fi

if ! docker compose version >/dev/null 2>&1; then
    apt-get install -y docker-compose-plugin
    docker compose version >/dev/null 2>&1 || die "docker-compose-plugin install failed"
fi

# Disable Docker's iptables/nftables management.
# Docker wipes firewall rules it does not own on every startup.
# With iptables=false it does not touch the firewall at all.
# Our nftables rules handle all NAT, filtering, and the WireGuard redirect.
mkdir -p /etc/docker
cat > /etc/docker/daemon.json << 'DOCKERJSON'
{
  "iptables": false
}
DOCKERJSON
echo "  Docker iptables management: disabled"

systemctl enable docker
systemctl restart docker
docker info >/dev/null 2>&1 || die "Docker daemon failed to start"
echo "  Docker daemon: running"

# ── Configuration ─────────────────────────────────────────────────────────────
section "Configuration"

IODINE_DOMAIN=""
while [ -z "$IODINE_DOMAIN" ]; do
    read -rp "Tunnel zone (e.g. tunnel.yourdomain.com): " IODINE_DOMAIN
    [ -z "$IODINE_DOMAIN" ] && echo "  Required."
done

DETECTED_IP="$(curl -fsSL --max-time 5 https://api.ipify.org 2>/dev/null || true)"
if [[ "$DETECTED_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    read -rp "Server public IP (detected: $DETECTED_IP, enter to accept): " SERVER_IP
    SERVER_IP="${SERVER_IP:-$DETECTED_IP}"
else
    read -rp "Server public IP (enter manually): " SERVER_IP
fi
[[ "$SERVER_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "Invalid IP: $SERVER_IP"

DETECTED_IFACE="$(ip route get 8.8.8.8 2>/dev/null \
    | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1); exit}' || true)"
if [ -n "$DETECTED_IFACE" ]; then
    read -rp "Public interface (detected: $DETECTED_IFACE, enter to accept): " PUBLIC_IFACE
    PUBLIC_IFACE="${PUBLIC_IFACE:-$DETECTED_IFACE}"
else
    read -rp "Public interface (e.g. eth0): " PUBLIC_IFACE
fi
[ -n "$PUBLIC_IFACE" ] || die "Interface name cannot be empty."
ip link show "$PUBLIC_IFACE" >/dev/null 2>&1 || die "Interface '$PUBLIC_IFACE' not found."

read -rp "iodine tunnel base IP (default: 10.53.53.1): " TUNNEL_IP
TUNNEL_IP="${TUNNEL_IP:-10.53.53.1}"
IODINE_NETWORK="${TUNNEL_IP%.*}.0/28"

DEFAULT_PASS="$(openssl rand -base64 24 | tr -d '=' | cut -c1-32)"
read -rsp "iodine password (max 32 chars, blank to generate): " IODINED_PASS
echo ""
if [ -z "$IODINED_PASS" ]; then
    IODINED_PASS="$DEFAULT_PASS"
    echo "  Generated iodine password: $IODINED_PASS"
    echo "  Save this -- required on every iodine client."
    echo ""
fi
[ "${#IODINED_PASS}" -le 32 ] || die "iodine password exceeds 32 chars."
[[ "$IODINED_PASS" != *' '* ]] || die "iodine password contains a space."

# ── WireGuard-specific prompts ────────────────────────────────────────────────
# WG_PORT and WG_NETWORK are always set (used in nftables regardless of whether
# WireGuard is installed locally) but their values are only prompted when WG is local.
WG_PORT=51820
WG_NETWORK="10.13.1.0/24"

if $INSTALL_WIREGUARD; then
    read -rp "WireGuard client DNS (default: 45.11.45.11): " WG_DNS
    WG_DNS="${WG_DNS:-45.11.45.11}"

    read -rp "WireGuard client names, comma-separated (e.g. phone,laptop): " WG_CLIENTS_RAW
    WG_CLIENTS_RAW="${WG_CLIENTS_RAW:-phone}"
else
    WG_DNS="45.11.45.11"
    WG_CLIENTS_RAW=""
fi

# Management IP: the IP you SSH from. Whitelisted in CrowdSec (never banned)
# and gets an unconditional nftables SSH accept rule so you cannot be locked out.
DETECTED_SSH_IP="$(echo "${SSH_CLIENT:-}" | awk '{print $1}' || true)"
if [[ "$DETECTED_SSH_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "  Detected SSH source IP: $DETECTED_SSH_IP"
fi
read -rp "Your unbannable management IP (default: 127.0.0.1): " MANAGEMENT_IP
MANAGEMENT_IP="${MANAGEMENT_IP:-127.0.0.1}"
[[ "$MANAGEMENT_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "Invalid management IP: $MANAGEMENT_IP"

# ── Remote LAPI credentials ────────────────────────────────────────────────────
# Prompted only when CrowdSec is selected with remote LAPI mode.
# The remote node must have generated these before this script runs:
#   cscli machines add <this-node-name> --auto   -> CS_MACHINE_LOGIN + CS_MACHINE_PASSWORD
#   cscli bouncers add <bouncer-name> -o raw     -> CS_BOUNCER_KEY
if $INSTALL_CS && [ "$CS_LAPI_MODE" = "remote" ]; then
    echo ""
    echo "  ── CrowdSec remote LAPI credentials ───────────────────────"
    echo ""
    echo "  Enter the values from the remote LAPI node."
    echo "  (If you have not generated them yet, Ctrl-C now and run:"
    echo "   cscli machines add <this-node-name> --auto"
    echo "   cscli bouncers add <bouncer-name> -o raw"
    echo "   on the remote node, then re-run this script.)"
    echo ""

    while true; do
        read -rp "  Remote LAPI URL (e.g. http://1.2.3.4:8080): " CS_LAPI_URL
        [[ "$CS_LAPI_URL" =~ ^https?:// ]] && break
        echo "  Must start with http:// or https://"
    done

    read -rp "  Machine login (from cscli machines add --auto): " CS_MACHINE_LOGIN
    [ -n "$CS_MACHINE_LOGIN" ] || die "Machine login cannot be empty."

    read -rsp "  Machine password: " CS_MACHINE_PASSWORD; echo ""
    [ -n "$CS_MACHINE_PASSWORD" ] || die "Machine password cannot be empty."

    read -rsp "  Bouncer API key (from cscli bouncers add -o raw): " CS_BOUNCER_KEY; echo ""
    [ -n "$CS_BOUNCER_KEY" ] || die "Bouncer API key cannot be empty."
fi

echo ""
echo "  Summary:"
echo "    Tunnel zone      : $IODINE_DOMAIN"
echo "    Server IP        : $SERVER_IP"
echo "    Interface        : $PUBLIC_IFACE"
echo "    iodine net       : $IODINE_NETWORK"
echo "    Management IP    : $MANAGEMENT_IP  (whitelisted -- never banned, always has SSH)"
if [ "$IODINED_PASS" = "$DEFAULT_PASS" ]; then
    echo "    iodine password  : $IODINED_PASS  (generated)"
else
    echo "    iodine password  : ${#IODINED_PASS} chars (user supplied)"
fi
echo ""
if $INSTALL_WIREGUARD; then
    _port_summary="port 53 only"
    $WG_USE_PORT_123 && ! $WG_USE_PORT_53 && _port_summary="port 123 only"
    $WG_USE_PORT_53  && $WG_USE_PORT_123   && _port_summary="ports 53 + 123 (dual)"
    echo "    WireGuard        : install locally ($_port_summary)"
    echo "    WireGuard int    : $WG_PORT (internal listen port, not externally open)"
    echo "    WireGuard subnet : $WG_NETWORK"
    echo "    WireGuard DNS    : $WG_DNS"
    echo "    WG clients       : $WG_CLIENTS_RAW"
else
    echo "    WireGuard        : skip  (DNAT rule still written for :$WG_PORT)"
fi
echo ""
if $INSTALL_CS; then
    if [ "$CS_LAPI_MODE" = "remote" ]; then
        echo "    CrowdSec         : agent + bouncer -> remote LAPI"
        echo "    Remote LAPI URL  : $CS_LAPI_URL"
        echo "    Machine login    : $CS_MACHINE_LOGIN"
        echo "    Bouncer key      : ${#CS_BOUNCER_KEY} chars"
    else
        echo "    CrowdSec         : full install with local LAPI"
    fi
else
    echo "    CrowdSec         : skip"
fi
echo ""
read -rp "Continue? [Y/n]: " CONFIRM
CONFIRM="${CONFIRM:-Y}"
[[ "$CONFIRM" =~ ^[Yy]$ ]] || die "Aborted."

# ── Generate config files ─────────────────────────────────────────────────────
section "Generating config files"

GENDIR="$(mktemp -d)"
mkdir -p "$GENDIR/iodine" "$GENDIR/wg"

# ── Corefile ──────────────────────────────────────────────────────────────────
# {{ .Name }} is CoreDNS template syntax, not shell -- passes through heredoc.
#
# Two server blocks:
#
#   1. ${IODINE_DOMAIN}: forwards to iodined on 127.0.0.1:5300.
#      Handles the iodine tunnel handshake protocol -- must never be altered.
#
#   2. . (catch-all): decoy zone, public-facing.  Logs all queries for
#      CrowdSec, blocks type ANY (anti-amplification), and returns
#      93.184.216.34 for everything to look like a broken public resolver.
#
# DNS for iodine clients: do NOT bind a third zone to ${TUNNEL_IP}.
# CoreDNS would try to bind that IP at startup before iodined has created
# the tun interface -- the bind fails, CoreDNS exits, and the iodine handshake
# zone (block 1) never comes up.  Iodine clients instead use an external
# resolver directly (e.g. 45.11.45.11); this works because the nftables
# masquerade rule already NATs iodine subnet traffic to the internet.
cat > "$GENDIR/iodine/Corefile" << COREFILE_EOF
${IODINE_DOMAIN} {
    forward . 127.0.0.1:5300
}

. {
    log
    acl {
        block type ANY
    }
    template IN ANY {
        answer "{{ .Name }} 60 IN A 93.184.216.34"
    }
}
COREFILE_EOF

# ── docker-compose.yml (CoreDNS + iodined) ────────────────────────────────────
cat > "$GENDIR/iodine/docker-compose.yml" << COMPOSE_EOF
# /opt/iodine/docker-compose.yml
# Manage:
#   cd /opt/iodine && docker compose up -d
#   cd /opt/iodine && docker compose logs -f
#   cd /opt/iodine && docker compose pull && docker compose up -d

services:

  coredns:
    image: coredns/coredns:latest
    container_name: coredns
    network_mode: host
    restart: unless-stopped
    volumes:
      - ./Corefile:/Corefile:ro
    depends_on:
      - iodine

  iodine:
    image: spritsail/iodine:latest
    container_name: iodine
    network_mode: host
    privileged: true
    restart: unless-stopped
    devices:
      - /dev/net/tun:/dev/net/tun
    command: >
      iodined -f -c -4 -p 5300 -l 127.0.0.1 -n auto
      -P ${IODINED_PASS} ${TUNNEL_IP} ${IODINE_DOMAIN}
COMPOSE_EOF

# ── nftables.conf ─────────────────────────────────────────────────────────────
#
# The WireGuard DNAT prerouting rule (UDP:53 -> :51820) is always written
# regardless of whether WireGuard is installed locally. This is harmless if WG
# is not local (no listener on :51820, redirected packets are dropped by the
# input chain) and means nftables does not need to be regenerated if WG is added
# later.
#
# The CrowdSec table (ip crowdsec) is always written. If CrowdSec is not
# installed, the set is empty and the chain accepts everything -- no overhead.
# This also means nftables survives if CrowdSec is added later without a reload.

# ── Build WireGuard prerouting rules ─────────────────────────────────────────
# Always written regardless of INSTALL_WIREGUARD (harmless if no listener on
# :51820; avoids regenerating nftables.conf if WireGuard is added later).
# Port 53's rate limit is added post-hoc by CrowdSec step 2c (unchanged).
_NFT_WG_PORT53_RULE=""
if $WG_USE_PORT_53; then
    _NFT_WG_PORT53_RULE="        # Redirect WireGuard packets arriving on port 53 to wg-quick on :51820.
        # Matches all four WireGuard message types by the first 4 bytes of the
        # UDP payload. conntrack records the DNAT so replies are rewritten back
        # to source port 53 transparently.
        udp dport 53 @th,64,32 { 0x01000000, 0x02000000, 0x03000000, 0x04000000 } redirect to :51820"
fi
_NFT_WG_PORT123_RULE=""
if $WG_USE_PORT_123; then
    _NFT_WG_PORT123_RULE="        # Redirect WireGuard packets arriving on port 123 to wg-quick on :51820.
        # Non-WireGuard UDP:123 (NTP probes, scanners) fall through to the input
        # chain where 'log prefix CROWDSEC_DROP' logs them for the ntp-probe-scanner
        # scenario before the final drop.  No rate limit here: a prerouting cap
        # would silently discard probes before CrowdSec can see them, and would
        # introduce a shared token bucket that any non-WG packet could drain.
        udp dport 123 @th,64,32 { 0x01000000, 0x02000000, 0x03000000, 0x04000000 } redirect to :51820"
fi

cat > "$GENDIR/nftables.conf" << NFTABLES_EOF
#!/usr/sbin/nft -f
# /etc/nftables.conf -- generated by VPN-over-port-53.sh

table ip iodine_nat
flush table ip iodine_nat

table ip iodine_nat {

    chain prerouting {
        type nat hook prerouting priority dstnat; policy accept;
${_NFT_WG_PORT53_RULE}
${_NFT_WG_PORT123_RULE}
    }

    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        ip saddr ${IODINE_NETWORK} oif "${PUBLIC_IFACE}" masquerade
        ip saddr ${WG_NETWORK}     oif "${PUBLIC_IFACE}" masquerade
    }
}

table inet filter
flush table inet filter

table inet filter {

    chain input {
        type filter hook input priority 0; policy drop;

        iif "lo" accept
        ct state established,related accept

        # Accept WireGuard packets that were DNAT'd in prerouting.
        # Without this, the input chain sees dport=51820, ct state=new, drops it.
        ct status dnat accept

        # Management IP always gets SSH -- never rate-limited, never hit by bans.
        ip saddr ${MANAGEMENT_IP} tcp dport 22 accept
        ip saddr { ${WG_NETWORK}, ${IODINE_NETWORK} } tcp dport 22 accept

        tcp dport 22 ct state new limit rate 5/minute accept
        tcp dport 22 drop

        tcp flags & (fin|syn|rst|psh|ack|urg) == fin|syn drop
        tcp flags & (fin|syn|rst|psh|ack|urg) == fin|syn|rst drop
        tcp flags & (fin|syn|rst|psh|ack|urg) == fin|rst drop
        tcp flags & (fin|syn|rst|psh|ack|urg) == 0x0 drop
        ip saddr { ${WG_NETWORK}, ${IODINE_NETWORK} } tcp dport { 80, 443 } accept
        tcp dport { 80, 443 } ct state new limit rate over 25/second burst 50 packets drop
        tcp dport { 80, 443 } ct state new ct count over 100 drop
        tcp dport { 80, 443 } accept

        # Port 53: CoreDNS receives DNS; prerouting redirects WireGuard to :51820.
        # Both VPN subnets bypass the rate limit step 2c injects before 'udp dport 53 accept'.
        ip saddr { ${WG_NETWORK}, ${IODINE_NETWORK} } udp dport 53 accept
        udp dport 53 accept
        ip saddr { ${WG_NETWORK}, ${IODINE_NETWORK} } tcp dport 53 accept
        tcp dport 53 ct state new limit rate over 2/minute drop
        tcp dport 53 accept

        # Port 51820 from the iodine subnet only -- iodine fallback path.
        ip saddr ${IODINE_NETWORK} udp dport ${WG_PORT} accept

        # Dashboard port 3000 (Grafana) and 9090 (Prometheus): VPN only.
        ip saddr { ${WG_NETWORK}, ${IODINE_NETWORK} } tcp dport { 3000, 9090 } accept

        ip saddr { ${WG_NETWORK}, ${IODINE_NETWORK} } icmp type echo-request accept
        icmp type echo-request limit rate 5/second accept
        icmp type echo-request drop

        log prefix "CROWDSEC_DROP: "
        drop
    }

    chain forward {
        type filter hook forward priority 0; policy drop;

        ip saddr ${IODINE_NETWORK} accept
        ip daddr ${IODINE_NETWORK} ct state established,related accept

        ip saddr ${WG_NETWORK} accept
        ip daddr ${WG_NETWORK} ct state established,related accept

        drop
    }

    chain output {
        type filter hook output priority 0; policy accept;
    }
}

# ── CrowdSec bouncer table ─────────────────────────────────────────────────────
# Defined here so the set and hooked chain survive 'systemctl restart nftables'.
# Without this block, every nftables reload wipes the dynamic CrowdSec table and
# bans stop being enforced until the bouncer recreates it (up to 10s gap, or
# permanently if the bouncer stalls). The bouncer detects the pre-existing set
# and chain, reuses them, and only manages set membership.
# Priority -1 ensures this chain runs BEFORE the inet filter input chain (priority 0).
# If CrowdSec is not installed, the set is empty and the chain accepts everything.
table ip crowdsec
flush table ip crowdsec

table ip crowdsec {
    set crowdsec_blacklists {
        type ipv4_addr
        flags timeout
    }

    chain crowdsec_chain {
        type filter hook input priority -1; policy accept;
        ip saddr @crowdsec_blacklists drop
        ip daddr @crowdsec_blacklists drop
    }
}
NFTABLES_EOF

# ── WireGuard seed files (only written when WireGuard is installed locally) ───
if $INSTALL_WIREGUARD; then
    # _WG_PORTNO is the external port written into client Endpoint fields via
    # portno.txt. When both ports are active, 53 is primary; _ntp copies (port
    # 123) are generated afterward by patching the Endpoint field.
    _WG_PORTNO=53
    $WG_USE_PORT_123 && ! $WG_USE_PORT_53 && _WG_PORTNO=123

    echo "${SERVER_IP}"    > "$GENDIR/wg/extnetip.txt"
    echo "${_WG_PORTNO}"   > "$GENDIR/wg/portno.txt"
    echo "${PUBLIC_IFACE}" > "$GENDIR/wg/extnetif.txt"
    echo "none"            > "$GENDIR/wg/sysctltype.txt"
    echo "none"            > "$GENDIR/wg/fwtype.txt"
    echo "10.13.1."        > "$GENDIR/wg/intnetaddress.txt"
    echo "${WG_DNS}"       > "$GENDIR/wg/intnetdns.txt"
fi

echo "  Config files generated."

# ── Run easy-wg-quick ─────────────────────────────────────────────────────────
if $INSTALL_WIREGUARD; then
    section "Generating WireGuard configs (easy-wg-quick)"

    WG_WORKDIR="/opt/wg"
    mkdir -p "$WG_WORKDIR"

    # Always write seed files -- they are cheap and ensure settings are current
    # even on re-runs. easy-wg-quick reads them before generating any config.
    cp "$GENDIR/wg/"*.txt "$WG_WORKDIR/"

    IFS=',' read -ra WG_CLIENT_NAMES <<< "$WG_CLIENTS_RAW"
    FIRST_CLIENT="$(echo "${WG_CLIENT_NAMES[0]}" | tr -d '[:space:]')"
    [ -z "$FIRST_CLIENT" ] && FIRST_CLIENT="client1"

    # ── Idempotency: wghub.conf ───────────────────────────────────────────────
    if [ -f "$WG_WORKDIR/wghub.conf" ] && grep -q "ListenPort = ${WG_PORT}" "$WG_WORKDIR/wghub.conf"; then
        echo "  wghub.conf exists with ListenPort = ${WG_PORT} -- skipping hub generation"
    else
        echo "  Generating wghub.conf + client: $FIRST_CLIENT..."
        docker run --rm \
            -v "${WG_WORKDIR}:/pwd" \
            ghcr.io/burghardt/easy-wg-quick \
            "$FIRST_CLIENT" \
            || die "easy-wg-quick failed (first client: $FIRST_CLIENT)"

        [ -f "$WG_WORKDIR/wghub.conf" ]                    || die "wghub.conf not found after generation"
        [ -f "$WG_WORKDIR/wgclient_${FIRST_CLIENT}.conf" ] || die "wgclient_${FIRST_CLIENT}.conf not found"

        # Patch wghub.conf ListenPort: _WG_PORTNO (written by portno.txt) -> 51820.
        grep -q "ListenPort = ${_WG_PORTNO}" "$WG_WORKDIR/wghub.conf" \
            || die "wghub.conf does not have 'ListenPort = ${_WG_PORTNO}' -- portno.txt seed may have failed"
        sed -i "s/^ListenPort = ${_WG_PORTNO}$/ListenPort = 51820/" "$WG_WORKDIR/wghub.conf"
        grep -q "ListenPort = ${WG_PORT}" "$WG_WORKDIR/wghub.conf" \
            || die "wghub.conf ListenPort patch failed"
        echo "  wghub.conf ListenPort patched: ${_WG_PORTNO} -> ${WG_PORT}"
    fi

    # ── Idempotency: client configs ───────────────────────────────────────────
    for raw_name in "${WG_CLIENT_NAMES[@]}"; do
        name="$(echo "$raw_name" | tr -d '[:space:]')"
        [ -z "$name" ] && continue
        if [ -f "$WG_WORKDIR/wgclient_${name}.conf" ]; then
            echo "  wgclient_${name}.conf exists -- skipping (re-run won't rotate keys)"
        else
            echo "  Generating client: $name..."
            docker run --rm \
                -v "${WG_WORKDIR}:/pwd" \
                ghcr.io/burghardt/easy-wg-quick \
                "$name" \
                || die "easy-wg-quick failed for client: $name"
            [ -f "$WG_WORKDIR/wgclient_${name}.conf" ] \
                || die "wgclient_${name}.conf not found after generation"
        fi
    done

    chmod 600 "$WG_WORKDIR"/*.conf
    echo "  All WireGuard configs ready."

    # ── Port 123 (_ntp) client configs ───────────────────────────────────────
    # When both ports are active, create a wgclient_<name>_ntp.conf for each
    # client by patching the Endpoint port from the primary port to 123.
    # These are never generated by easy-wg-quick -- always derived from primaries.
    # Naming convention _ntp is intentional: descriptive, and the load_existing_config
    # and build_and_show_menu functions explicitly skip/handle files with this suffix.
    if $WG_USE_PORT_53 && $WG_USE_PORT_123; then
        for raw_name in "${WG_CLIENT_NAMES[@]}"; do
            name="$(echo "$raw_name" | tr -d '[:space:]')"
            [ -z "$name" ] && continue
            _ntp_dst="$WG_WORKDIR/wgclient_${name}_ntp.conf"
            if [ -f "$_ntp_dst" ]; then
                echo "  wgclient_${name}_ntp.conf exists -- skipping"
            else
                sed "s/Endpoint = ${SERVER_IP}:${_WG_PORTNO}/Endpoint = ${SERVER_IP}:123/" \
                    "$WG_WORKDIR/wgclient_${name}.conf" > "$_ntp_dst"
                chmod 600 "$_ntp_dst"
                echo "  wgclient_${name}_ntp.conf created (Endpoint: ${SERVER_IP}:123)"
            fi
        done
    fi

    SAMPLE_CONF="$WG_WORKDIR/wgclient_${FIRST_CLIENT}.conf"
    if grep -q "Endpoint = ${SERVER_IP}:${_WG_PORTNO}" "$SAMPLE_CONF"; then
        echo "  Client Endpoint = ${SERVER_IP}:${_WG_PORTNO}  [correct]"
    else
        ENDPOINT_FOUND="$(grep "Endpoint" "$SAMPLE_CONF" || echo "(not found)")"
        echo "  WARNING: unexpected client Endpoint: $ENDPOINT_FOUND"
    fi
fi  # INSTALL_WIREGUARD

# ── Deploy ────────────────────────────────────────────────────────────────────
section "Deploying files"

mkdir -p /opt/iodine
install -m 644 "$GENDIR/iodine/Corefile"           /opt/iodine/Corefile
echo "  -> /opt/iodine/Corefile"
install -m 600 "$GENDIR/iodine/docker-compose.yml" /opt/iodine/docker-compose.yml
chown root:root /opt/iodine/docker-compose.yml
echo "  -> /opt/iodine/docker-compose.yml  (mode 600)"

install -m 644 "$GENDIR/nftables.conf" /etc/nftables.conf
echo "  -> /etc/nftables.conf"

if $INSTALL_WIREGUARD; then
    mkdir -p /etc/wireguard
    install -m 600 "$WG_WORKDIR/wghub.conf" /etc/wireguard/wghub.conf
    echo "  -> /etc/wireguard/wghub.conf  (mode 600)"
fi

# ── Kernel configuration ──────────────────────────────────────────────────────
section "Kernel configuration"

apply_sysctl() {
    local key="$1" val="$2"
    grep -q "^${key}" /etc/sysctl.conf 2>/dev/null \
        && sed -i "s|^${key}.*|${key}=${val}|" /etc/sysctl.conf \
        || echo "${key}=${val}" >> /etc/sysctl.conf
    sysctl -w "${key}=${val}" >/dev/null
}

apply_sysctl net.ipv4.ip_forward 1
apply_sysctl net.ipv4.conf.all.src_valid_mark 1
apply_sysctl net.ipv6.conf.all.disable_ipv6 1
apply_sysctl net.ipv6.conf.default.disable_ipv6 1
echo "  ip_forward=1, src_valid_mark=1, IPv6 disabled."

# ── Start services ────────────────────────────────────────────────────────────
section "Starting services"
# Order matters:
#   1. nftables  -- prerouting redirect must exist before anything binds port 53
#   2. conntrack -F  -- flush stale entries that would bypass prerouting
#   3. wg-quick  -- binds :51820  (only if WireGuard selected)
#   4. CoreDNS + iodined (Docker)  -- CoreDNS binds :53
#   5. nftables reload only -- conntrack NOT flushed after this point

systemctl daemon-reload

# 1. nftables
systemctl enable nftables
systemctl restart nftables
echo "  nftables: started"

# 2. flush conntrack -- no stale entries before anything binds
conntrack -F 2>/dev/null || true
echo "  conntrack: flushed"

# 3. wg-quick (only when WireGuard is installed locally)
if $INSTALL_WIREGUARD; then
    systemctl enable wg-quick@wghub
    systemctl restart wg-quick@wghub \
        || { echo ""; echo "  ERROR: wg-quick@wghub failed. Logs:"; \
             journalctl -u wg-quick@wghub --no-pager -n 30; \
             die "WireGuard failed -- see logs above"; }
    ip link show wghub >/dev/null 2>&1 || die "wghub interface not found after wg-quick start"
    echo "  WireGuard (wghub): started"
    wg show wghub
fi

# 4. CoreDNS + iodined
echo "  Pulling images..."
docker compose -f /opt/iodine/docker-compose.yml pull
docker compose -f /opt/iodine/docker-compose.yml up -d
echo "  iodined + CoreDNS: started"

# 5. nftables reload -- Docker no longer wipes our rules (iptables=false).
#    Do NOT flush conntrack here. The WireGuard handshake DNAT entry must
#    survive so conntrack can rewrite response src port 51820 -> 53 on the
#    way back to the client.
sleep 3
systemctl restart nftables
echo "  nftables: reloaded (conntrack NOT flushed -- intentional)"

sleep 3

# ── Verify ────────────────────────────────────────────────────────────────────
section "Verification"

PASS=0; FAIL=0
check_pass() { echo "  [OK]   $1"; PASS=$((PASS+1)); }
check_fail() { echo "  [FAIL] $1"; FAIL=$((FAIL+1)); }

[ "$(docker inspect -f '{{.State.Running}}' iodine  2>/dev/null)" = "true" ] \
    && check_pass "iodine container running"   || check_fail "iodine container NOT running"
[ "$(docker inspect -f '{{.State.Running}}' coredns 2>/dev/null)" = "true" ] \
    && check_pass "coredns container running"  || check_fail "coredns container NOT running"

ss -ulnp | grep -q '127.0.0.1:5300' \
    && check_pass "iodined on 127.0.0.1:5300"  || check_fail "iodined not on 127.0.0.1:5300"

ss -ulnp | grep -qE '\*:53|0\.0\.0\.0:53' \
    && check_pass "CoreDNS on port 53 (UDP)"   || check_fail "CoreDNS not on port 53 (UDP)"
ss -tlnp | grep -qE '\*:53|0\.0\.0\.0:53' \
    && check_pass "CoreDNS on port 53 (TCP)"   || check_fail "CoreDNS not on port 53 (TCP)"

if $INSTALL_WIREGUARD; then
    ss -ulnp | grep -qE "0\.0\.0\.0:${WG_PORT}|\*:${WG_PORT}" \
        && check_pass "WireGuard on :${WG_PORT}"   || check_fail "WireGuard not on :${WG_PORT}"
    ip link show wghub >/dev/null 2>&1 \
        && check_pass "wghub interface up"         || check_fail "wghub interface not found"
fi

nft list table ip iodine_nat >/dev/null 2>&1 \
    && check_pass "nftables iodine_nat table" \
    || check_fail "nftables iodine_nat table missing"
nft list chain ip iodine_nat prerouting >/dev/null 2>&1 \
    && check_pass "nftables prerouting chain loaded" \
    || check_fail "nftables prerouting chain MISSING"
nft list chain ip iodine_nat prerouting 2>/dev/null | grep -qE ':?51820' \
    && check_pass "nftables WireGuard redirect rule present" \
    || check_fail "nftables WireGuard redirect rule MISSING"
if $WG_USE_PORT_123; then
    nft list chain ip iodine_nat prerouting 2>/dev/null \
        | grep -q 'udp dport 123' \
        && check_pass "nftables port 123 (NTP) redirect rule present" \
        || check_fail "nftables port 123 redirect rule MISSING"
fi
nft list table inet filter >/dev/null 2>&1 \
    && check_pass "nftables inet filter table" \
    || check_fail "nftables inet filter table missing"

DIG_DECOY="$(dig +short @127.0.0.1 google.com A 2>/dev/null || true)"
echo "$DIG_DECOY" | grep -q '93.184.216.34' \
    && check_pass "decoy DNS: google.com -> 93.184.216.34" \
    || check_fail "decoy DNS: unexpected (got: $DIG_DECOY)"

sysctl net.ipv4.ip_forward           2>/dev/null | grep -q '= 1' \
    && check_pass "IP forwarding enabled"      || check_fail "IP forwarding not enabled"
sysctl net.ipv4.conf.all.src_valid_mark 2>/dev/null | grep -q '= 1' \
    && check_pass "src_valid_mark enabled"     || check_fail "src_valid_mark not enabled"
sysctl net.ipv6.conf.all.disable_ipv6 2>/dev/null | grep -q '= 1' \
    && check_pass "IPv6 disabled"              || check_fail "IPv6 not disabled"

echo ""
echo "  ----------------------------------------------------------------"
echo "    Passed: $PASS   Failed: $FAIL"
echo "  ----------------------------------------------------------------"
if [ "$FAIL" -gt 0 ]; then
    echo ""
    echo "  WARNING: $FAIL check(s) failed. Review logs:"
    if $INSTALL_WIREGUARD; then
        echo "    journalctl -u wg-quick@wghub --no-pager -n 30"
    fi
    echo "    journalctl -u nftables       --no-pager -n 20"
    echo "    docker logs coredns"
    echo "    docker logs iodine"
    echo "    nft list ruleset"
fi

# ── CrowdSec integration ──────────────────────────────────────────────────────
# Wires the port-53 CoreDNS decoy into CrowdSec.
# Skipped entirely when INSTALL_CS=false.
# Branches on CS_LAPI_MODE (local | remote) at the points where behavior differs:
#   - local: LAPI runs here; cscli registers bouncer locally
#   - remote: local LAPI disabled; agent and bouncer credentials point at remote
#
# Shared between both modes (steps marked identically):
#   step 1:   install crowdsec binary
#   step 2a:  drop iodine container privilege
#   step 2b:  enable CoreDNS query logging
#   step 2c:  nftables UDP/53 rate limit
#   step 2d:  acquisition config (docker datasource)
#   step 2e:  custom CoreDNS parser
#   step 2f:  VPN subnet whitelist
#   step 2g:  DNS decoy scenario
#   step 3:   start CrowdSec
#   step 4:   install bouncer package
#   step 5:   patch bouncer config (mode, set-only, IPv6)
#   step 6:   start bouncer
#   step 7:   recreate containers + reload nftables
if $INSTALL_CS; then

section "CrowdSec -- DNS decoy sensor"

# ── Step 1: Install CrowdSec binary ──────────────────────────────────────────
if ! command -v crowdsec >/dev/null 2>&1; then
    echo "  Adding CrowdSec repository..."
    curl -fsSL https://install.crowdsec.net | bash
    echo "  Installing crowdsec package..."
    echo "  (post-install hook may print a hub hash-mismatch warning -- tolerated)"
    # || true: binary always lands even when post-install hook fails.
    # Never retry with dpkg --configure or apt-get install -f -- they re-run
    # the exact same failing hook.
    apt-get install -y crowdsec 2>&1 || true
    command -v cscli >/dev/null 2>&1 \
        || die "crowdsec binary missing after apt-get -- cannot continue."
    echo "  [OK]   crowdsec binary installed"
else
    echo "  [OK]   crowdsec already installed"
    cscli hub update 2>/dev/null || true
fi

# ── Docker group access for crowdsec ─────────────────────────────────────────
# CrowdSec reads CoreDNS logs via the Docker socket (docker:coredns source in
# coredns-decoy.yaml). If crowdsec cannot access /var/run/docker.sock the
# docker acquisition source silently reads zero lines -- no alerts fire.
# CrowdSec runs as root on Debian but the socket is group:docker mode 660.
# Adding crowdsec to the docker group ensures access survives future installs
# that may drop root privileges.
if getent group docker >/dev/null 2>&1; then
    if ! id crowdsec >/dev/null 2>&1; then
        # No dedicated crowdsec system user -- process runs as root, socket
        # is accessible. Nothing to do.
        echo "  [OK]   CrowdSec runs as root -- docker socket accessible"
    elif id -nG crowdsec 2>/dev/null | grep -qw docker; then
        echo "  [OK]   crowdsec already in docker group"
    else
        usermod -aG docker crowdsec
        echo "  [OK]   crowdsec added to docker group (socket: /var/run/docker.sock)"
    fi
else
    echo "  [WARN] docker group not found -- coredns acquisition may fail"
fi

# ── Step 2a: Security fix: drop iodine container privilege ───────────────────
if grep -q 'privileged: true' /opt/iodine/docker-compose.yml; then
    sed -i '/^\s*privileged: true\s*$/d' /opt/iodine/docker-compose.yml
    sed -i '0,/^    devices:/{s/^    devices:/    cap_add:\n      - NET_ADMIN\n    devices:/}' \
        /opt/iodine/docker-compose.yml
    echo "  [OK]   privileged:true removed; cap_add:[NET_ADMIN] added"
else
    echo "  [OK]   iodine: already without privileged:true"
fi

# ── Step 2b: Enable CoreDNS query logging ────────────────────────────────────
if grep -qE '^\s+log\s*$' /opt/iodine/Corefile; then
    echo "  [OK]   CoreDNS log plugin already present"
else
    sed -i '/^\. {$/a\    log' /opt/iodine/Corefile
    echo "  [OK]   'log' added to CoreDNS catch-all zone"
fi

# ── Step 2c: nftables UDP/53 rate limit + relax TCP/53 ───────────────────────
# Port 53: the rate limit is added here (post-generation) because it needs to
# land before 'udp dport 53 accept' in the input chain.
# Port 123: the rate limit is baked into _NFT_WG_PORT123_RULE at generation
# time (in prerouting, before DNAT fires) because port 123 has no accept rule
# in the input chain -- it enters only via ct status dnat accept.
if grep -q 'udp dport 53 limit rate' /etc/nftables.conf; then
    echo "  [OK]   nftables UDP/53 rate limit already present"
else
    awk '
/^        udp dport 53 accept$/ && !_done {
    print "        # UDP/53 rate limit: kernel DoS cap, evaluated before CrowdSec."
    print "        # WireGuard packets matched by ct status dnat above -- not affected."
    print "        udp dport 53 limit rate over 200/second burst 400 packets drop"
    _done=1
}
{ print }
' /etc/nftables.conf > /etc/nftables.conf.tmp \
        && mv /etc/nftables.conf.tmp /etc/nftables.conf
    sed -i 's/tcp dport 53 ct state new limit rate over 2\/minute drop/tcp dport 53 ct state new limit rate over 30\/minute drop/' \
        /etc/nftables.conf
    echo "  [OK]   UDP/53 rate limit added; TCP/53 limit relaxed 2/min -> 30/min"
fi

# ── Step 2d: Write acquisition config ────────────────────────────────────────
mkdir -p /etc/crowdsec/acquis.d
cat > /etc/crowdsec/acquis.d/coredns-decoy.yaml << 'ACQUIS'
source: docker
container_name:
  - coredns
labels:
  type: coredns
ACQUIS
echo "  [OK]   Acquisition: /etc/crowdsec/acquis.d/coredns-decoy.yaml (docker source)"

# sshd: Debian 12 uses journald-only -- /var/log/auth.log does not exist.
# The crowdsec package auto-generates setup.sshd.yaml using journalctl.
# Our custom sshd.yaml would override that with a broken file path.
# Write a journalctl source instead to be explicit and survive re-installs.
cat > /etc/crowdsec/acquis.d/sshd.yaml << 'ACQUIS'
source: journalctl
journalctl_filter:
  - "_SYSTEMD_UNIT=ssh.service"
labels:
  type: syslog
ACQUIS
echo "  [OK]   Acquisition: /etc/crowdsec/acquis.d/sshd.yaml (journalctl ssh)"

# kernel: Debian 12 uses journald-only -- /var/log/kern.log does not exist.
# _TRANSPORT=kernel captures all kernel messages including nftables LOG output
# (CROWDSEC_DROP: prefix lines) needed for port-scan detection.
cat > /etc/crowdsec/acquis.d/kernel.yaml << 'ACQUIS'
source: journalctl
journalctl_filter:
  - "_TRANSPORT=kernel"
labels:
  type: syslog
ACQUIS
echo "  [OK]   Acquisition: /etc/crowdsec/acquis.d/kernel.yaml (journalctl kernel)"

# ── Step 2e: Write custom CoreDNS parser ─────────────────────────────────────
mkdir -p /etc/crowdsec/parsers/s01-parse
cat > /etc/crowdsec/parsers/s01-parse/coredns-decoy-logs.yaml << 'PARSER'
name: custom/coredns-decoy-logs
description: Parse CoreDNS query log lines from the decoy catch-all zone.
filter: "evt.Line.Labels.type == 'coredns'"
onsuccess: next_stage
nodes:
  - grok:
      # Pure grok %{MACRO:name} syntax -- CrowdSec's grokky does not support
      # raw (?P<n>...) regex named groups; they silently fail to capture.
      # apply_on: message = evt.Parsed.message, set by non-syslog in s00-raw.
      pattern: '\[%{WORD:log_level}\] %{IP:src_ip}:%{INT:src_port} - %{INT:query_id} "%{WORD:dns_type} IN %{NOTSPACE:dns_qname} %{WORD:dns_proto} %{INT:req_size} %{WORD:do_bit} %{INT:bufsize}" %{WORD:dns_rcode}'
      apply_on: message
    statics:
      - meta: log_type
        value: coredns_decoy_query
      - meta: source_ip
        expression: evt.Parsed.src_ip
      - meta: dns_qname
        expression: evt.Parsed.dns_qname
      - meta: dns_rcode
        expression: evt.Parsed.dns_rcode
PARSER
echo "  [OK]   Parser: coredns-decoy-logs.yaml"

# ── Step 2f: Write VPN subnet whitelist ──────────────────────────────────────
mkdir -p /etc/crowdsec/parsers/s02-enrich
cat > /etc/crowdsec/parsers/s02-enrich/vpn-whitelist.yaml << WHITELIST
name: custom/vpn-whitelist
description: Whitelist WireGuard and iodine VPN clients from all scenarios.
filter: "true"
whitelist:
  reason: "WireGuard or iodine VPN client -- internal trusted range"
  ip:
    - "${MANAGEMENT_IP}"
  cidr:
    - "127.0.0.0/8"
    - "${WG_NETWORK}"
    - "${IODINE_NETWORK}"
WHITELIST
echo "  [OK]   Whitelist: vpn-whitelist.yaml"

# ── Step 2g: Write detection scenario ────────────────────────────────────────
mkdir -p /etc/crowdsec/scenarios
cat > /etc/crowdsec/scenarios/dns-decoy-scanner.yaml << SCENARIO
name: custom/dns-decoy-scanner
description: >
  External IP probing the DNS decoy zone.
  This server is not a public resolver; any external query is reconnaissance.
type: leaky
filter: "evt.Meta.log_type == 'coredns_decoy_query' && !(evt.Meta.dns_qname contains '${IODINE_DOMAIN}')"
leakspeed: "20s"
capacity: 3
groupby: evt.Meta.source_ip
blackhole: 2m
labels:
  service: dns
  type: decoy_probe
  remediation: true
SCENARIO
echo "  [OK]   Scenario: dns-decoy-scanner.yaml"

# ── Step 2h: Port 123 probe detection via s02-enrich (port 123 only) ─────────
# When WireGuard uses port 123, non-WireGuard UDP:123 packets are NOT DNAT'd.
# They reach the input chain, are dropped, and the 'log prefix "CROWDSEC_DROP: "'
# rule writes them to kern.log. kern.log is already acquired as type:syslog.
#
# Pipeline:
#   kern.log → crowdsecurity/syslog-logs (s00-raw, sets evt.Parsed.message)
#           → crowdsecurity/iptables-logs (s01-parse, extracts SRC/DPT,
#               sets evt.Meta.source_ip, onsuccess:next_stage → promotes to s02-enrich)
#           → custom/ntp-probe-enrich (s02-enrich, filters on DPT=123 in
#               the CROWDSEC_DROP line, sets log_type=ntp_probe)
#           → ntp-probe-scanner scenario → ban decision → bouncer → DROP
#
# The parser lives in s02-enrich (NOT s01-parse) because iptables-logs in
# s01-parse already consumed and promoted these events. evt.Meta.source_ip is
# already set by iptables-logs so this parser only needs to tag the event.
# No dedicated LOG rule needed -- CROWDSEC_DROP already logs everything.
# No NTP server needed -- it couldn't bind port 123 anyway since WireGuard
# DNAT redirects from it at the prerouting level.
if $WG_USE_PORT_123; then
    mkdir -p /etc/crowdsec/parsers/s02-enrich
    cat > /etc/crowdsec/parsers/s02-enrich/ntp-probe-enrich.yaml << 'PARSER'
name: custom/ntp-probe-enrich
description: >
  Tag nftables CROWDSEC_DROP events on DPT=123 as NTP probes.
  Runs in s02-enrich because iptables-logs in s01-parse already consumed
  these kernel log lines and promoted them here via onsuccess:next_stage.
  evt.Meta.source_ip is already populated by iptables-logs.
  Uses evt.Line.Raw which is always available; evt.Parsed.message is not
  reliably set in s02-enrich context and causes a nil dereference crash.
filter: "evt.Line.Raw contains 'CROWDSEC_DROP:' && evt.Line.Raw contains 'DPT=123'"
nodes:
  - statics:
      - meta: log_type
        value: ntp_probe
PARSER
    echo "  [OK]   Parser: s02-enrich/ntp-probe-enrich.yaml"

    cat > /etc/crowdsec/scenarios/ntp-probe-scanner.yaml << 'SCENARIO'
name: custom/ntp-probe-scanner
description: >
  External IP probing UDP port 123. This server does not run an NTP
  service -- any non-WireGuard packet on port 123 is a probe or scan.
type: leaky
filter: "evt.Meta.log_type == 'ntp_probe'"
leakspeed: "20s"
capacity: 3
groupby: evt.Meta.source_ip
blackhole: 2m
labels:
  service: ntp
  type: decoy_probe
  remediation: true
SCENARIO
    echo "  [OK]   Scenario: ntp-probe-scanner.yaml"
fi  # WG_USE_PORT_123

# ── Remote LAPI: configure agent to use remote LAPI before first start ────────
# These steps only apply when CS_LAPI_MODE=remote. For local mode, the default
# config.yaml (local LAPI enabled) is used unchanged.
if [ "$CS_LAPI_MODE" = "remote" ]; then
    echo ""
    echo "  ── Configuring agent for remote LAPI ────────────────────────"

    # ── Pre-flight: verify machine credentials against remote LAPI ───────────
    # The agent will FATAL on startup if the machine is not registered on the
    # remote LAPI. Catch this now with a clear error rather than a systemd crash.
    # POST /v1/watchers/login is the same endpoint the agent uses at startup.
    # Ref: https://crowdsecurity.github.io/api_doc/index.html?urls.primaryName=LAPI#/watchers/post_v1_watchers_login
    echo "  Verifying machine credentials against $CS_LAPI_URL ..."
    _cs_auth_result="$(curl -sf --max-time 10 \
        -X POST \
        -H 'Content-Type: application/json' \
        -d "{\"machine_id\":\"${CS_MACHINE_LOGIN}\",\"password\":\"${CS_MACHINE_PASSWORD}\",\"scenarios\":[]}" \
        "${CS_LAPI_URL}/v1/watchers/login" 2>/dev/null || true)"

    if echo "$_cs_auth_result" | grep -q '"token"'; then
        echo "  [OK]   Machine credentials verified (remote LAPI accepted login)"
    else
        # Surface the LAPI error if present, otherwise show raw response
        _cs_err="$(echo "$_cs_auth_result" | grep -o '"message":"[^"]*"' | head -1 || true)"
        echo ""
        echo "  ERROR: Remote LAPI rejected the machine credentials."
        [ -n "$_cs_err" ] && echo "         LAPI says: $_cs_err"
        echo ""
        echo "  The machine '${CS_MACHINE_LOGIN}' must be registered on the remote"
        echo "  LAPI node BEFORE running this script. On the remote node run:"
        echo ""
        echo "    sudo cscli machines add ${CS_MACHINE_LOGIN} --auto"
        echo ""
        echo "  That command prints the login and password to use here."
        echo "  Re-run this script once the machine is registered."
        die "Remote LAPI credential verification failed -- cannot continue."
    fi

    # Write remote LAPI credentials. The crowdsec agent reads this file on
    # startup to connect to the LAPI.
    # Ref: https://doc.crowdsec.net/docs/configuration/crowdsec_configuration/#local_api_credentials
    cat > /etc/crowdsec/local_api_credentials.yaml << CREDS
url: ${CS_LAPI_URL}
login: ${CS_MACHINE_LOGIN}
password: ${CS_MACHINE_PASSWORD}
CREDS
    chmod 600 /etc/crowdsec/local_api_credentials.yaml
    echo "  [OK]   local_api_credentials.yaml written (url: $CS_LAPI_URL)"

    # Disable the local LAPI server. The crowdsec binary runs both agent and
    # LAPI by default. Setting api.server.enable: false makes it agent-only.
    #
    # In config.yaml, the structure is:
    #   api:           <- 0-space
    #     client:      <- 2-space
    #     server:      <- 2-space
    #       enable:    <- 4-space (may be absent in default install)
    #
    # Two cases:
    #   A) 'enable:' already exists under server: -- replace its value.
    #   B) 'enable:' is absent (default) -- insert it as first line under server:.
    #
    # We detect case A by checking the 20 lines after '  server:' for an enable:
    # field. This is safer than a global grep since enable: appears in other
    # sections (e.g. prometheus).
    _CONFIG=/etc/crowdsec/config.yaml
    if grep -A 20 '^  server:' "$_CONFIG" 2>/dev/null | grep -q '^\s*enable:'; then
        # Case A: replace existing enable: under server:
        # awk sets a flag on '  server:' and replaces the first enable: it finds.
        awk '
            /^  server:/  { in_server=1 }
            in_server && /^\s*enable:/ {
                sub(/enable:.*/, "enable: false")
                in_server=0
            }
            { print }
        ' "$_CONFIG" > "$_CONFIG.tmp" && mv "$_CONFIG.tmp" "$_CONFIG"
        echo "  [OK]   api.server.enable replaced with false"
    elif grep -q '^  server:' "$_CONFIG" 2>/dev/null; then
        # Case B: insert enable: false as the first subkey under server:
        # sed 'a\' appends the line immediately after the matched line.
        sed -i '/^  server:$/a\    enable: false' "$_CONFIG"
        echo "  [OK]   api.server.enable: false inserted under server:"
    else
        echo "  [WARN] Could not locate 'server:' block in config.yaml"
        echo "         The local LAPI will start on :8080 alongside the agent."
        echo "         This is benign -- the bouncer uses the remote LAPI."
        echo "         To suppress: add '    enable: false' under 'server:'"
        echo "         in /etc/crowdsec/config.yaml and restart crowdsec."
    fi
fi

# ── Step 3: Start CrowdSec ────────────────────────────────────────────────────
echo "  Starting CrowdSec..."
systemctl enable crowdsec
systemctl restart crowdsec
sleep 8
systemctl is-active crowdsec >/dev/null 2>&1 \
    || die "CrowdSec failed to start. Check: journalctl -u crowdsec -n 40 --no-pager"
echo "  [OK]   CrowdSec running"

cscli hub update 2>/dev/null \
    && echo "  [OK]   Hub index updated" \
    || echo "  NOTE:  Hub update failed -- continuing with collections install"

# crowdsecurity/coredns-logs is intentionally NOT installed.
# If present it runs alphabetically before custom/coredns-decoy-logs in s01-parse
# and its onsuccess:next_stage moves events before log_type is set, breaking bans.
echo "  Installing CrowdSec collections..."
cscli collections install \
    crowdsecurity/linux \
    crowdsecurity/iptables \
    crowdsecurity/linux-lpe 2>/dev/null \
    && echo "  [OK]   Collections installed" \
    || echo "  NOTE:  Collection install had warnings -- check cscli collections list"

systemctl restart crowdsec
sleep 5
systemctl is-active crowdsec >/dev/null 2>&1 \
    || die "CrowdSec failed to restart after collections install. Check: journalctl -u crowdsec -n 40 --no-pager"

# ── Step 4: Install bouncer AFTER CrowdSec agent confirmed running ────────────
# For local LAPI: bouncer post-install auto-generates API key AND starts service.
#   "stream halted" crash loop guaranteed if LAPI is down at install time.
# For remote LAPI: bouncer post-install will attempt to register with LAPI;
#   we override its api_url and api_key in step 5 before starting it.
systemctl is-active crowdsec >/dev/null 2>&1 \
    || die "CrowdSec agent not running -- cannot install bouncer safely."

if ! dpkg -l crowdsec-firewall-bouncer-nftables 2>/dev/null | grep -q '^ii'; then
    apt-get install -y crowdsec-firewall-bouncer-nftables
    echo "  [OK]   crowdsec-firewall-bouncer-nftables installed"
else
    echo "  [OK]   crowdsec-firewall-bouncer-nftables already installed"
fi

# ── Step 5: Patch bouncer config ─────────────────────────────────────────────
BOUNCER_CONF=/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml
[ -f "$BOUNCER_CONF" ] || die "Bouncer config not found at $BOUNCER_CONF"

# Force nftables mode. Package default can be ipset, which creates iptables
# rules not evaluated by the nftables kernel path.
sed -i 's/^mode:.*/mode: nftables/' "$BOUNCER_CONF"

# set-only: false -- bouncer owns a hooked chain, not just the IP set.
sed -i '/set-only:/ s/set-only:.*/set-only: false/' "$BOUNCER_CONF"
sed -i '/^nftables:/,/^[^ ]/{/enabled: true/a\    set-only: false
}' "$BOUNCER_CONF" 2>/dev/null || true

# Disable IPv6 (off system-wide via sysctl).
sed -i '/^[[:space:]]*ipv6:/,/enabled:/{s/enabled: true/enabled: false/}' "$BOUNCER_CONF"

if grep -q 'mode: nftables' "$BOUNCER_CONF" && grep -q 'set-only: false' "$BOUNCER_CONF"; then
    echo "  [OK]   Bouncer patched: mode=nftables, set-only=false, IPv6 off"
else
    echo "  [WARN] Bouncer patch incomplete -- check manually"
fi

# ── Bouncer API key / LAPI URL: local vs remote ───────────────────────────────
if [ "$CS_LAPI_MODE" = "remote" ]; then
    # Remote mode: write the pre-issued bouncer key and remote URL directly.
    # The post-install hook may have written a local key that will not work --
    # overwrite both fields unconditionally.
    # VERIFY: these field names are top-level keys in the default bouncer config.
    # Check: grep -E '^api_url:|^api_key:' /etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml
    sed -i "s|^api_url:.*|api_url: ${CS_LAPI_URL}|" "$BOUNCER_CONF"
    sed -i "s|^api_key:.*|api_key: ${CS_BOUNCER_KEY}|" "$BOUNCER_CONF"
    echo "  [OK]   Bouncer api_url set to remote LAPI: $CS_LAPI_URL"
    echo "  [OK]   Bouncer api_key set from provided key"
else
    # Local mode: bouncer post-install registers its key automatically when LAPI is up.
    # Only register manually if that step somehow did not run.
    if ! cscli bouncers list 2>/dev/null | grep -qE 'crowdsec-firewall-bouncer|nftables-bouncer'; then
        echo "  Registering bouncer API key with LAPI..."
        BOUNCER_KEY="$(cscli bouncers add nftables-bouncer -o raw 2>/dev/null)" \
            || die "Failed to register bouncer with LAPI."
        [ -n "$BOUNCER_KEY" ] || die "Got empty bouncer key."
        sed -i "s|^api_key:.*|api_key: ${BOUNCER_KEY}|" "$BOUNCER_CONF"
        echo "  [OK]   nftables-bouncer API key registered"
    else
        echo "  [OK]   Bouncer API key already registered (post-install did it)"
    fi
fi

# ── Step 6: Start bouncer ─────────────────────────────────────────────────────
echo "  Starting nftables bouncer..."
systemctl enable crowdsec-firewall-bouncer
systemctl restart crowdsec-firewall-bouncer
sleep 3
systemctl is-active crowdsec-firewall-bouncer >/dev/null 2>&1 \
    && echo "  [OK]   nftables bouncer running" \
    || die "Bouncer failed. Check: journalctl -u crowdsec-firewall-bouncer -n 20"

# ── Step 7: Recreate containers + reload nftables ────────────────────────────
echo "  Recreating CoreDNS + iodine containers..."
docker compose -f /opt/iodine/docker-compose.yml up -d --force-recreate coredns iodine
echo "  [OK]   CoreDNS + iodine recreated"

echo "  Reloading nftables (conntrack NOT flushed -- intentional)..."
systemctl restart nftables
echo "  [OK]   nftables reloaded"

# CrowdSec adds a hook at priority -1 (crowdsec_chain) that did not exist when
# wg-quick started.  Stale conntrack DNAT entries created before that hook was
# registered no longer match the reverse-DNAT path correctly, so wg-quick's
# response rewrite (src :51820 -> :53) silently fails.  Flush conntrack and
# restart wg-quick so all entries are created against the final hook ordering.
# This flush is safe here: it is a fresh install path with no live clients yet.
if $INSTALL_WIREGUARD; then
    conntrack -F 2>/dev/null || true
    systemctl restart wg-quick@wghub \
        || die "wg-quick restart after CrowdSec hook install failed"
    echo "  [OK]   conntrack flushed + wg-quick restarted (post CrowdSec hook)"
fi

# Restart bouncer immediately after nftables reload to re-apply all current bans.
echo "  Restarting bouncer after nftables reload (re-applies all active bans)..."
systemctl restart crowdsec-firewall-bouncer
sleep 3
systemctl is-active crowdsec-firewall-bouncer >/dev/null 2>&1 \
    && echo "  [OK]   bouncer restarted and active" \
    || echo "  [WARN] bouncer may not have restarted cleanly -- check: journalctl -u crowdsec-firewall-bouncer -n 20"

echo "  Restarting CrowdSec to load parser + scenario + acquisition..."
systemctl restart crowdsec
sleep 5
systemctl is-active crowdsec >/dev/null 2>&1 \
    || die "CrowdSec failed after final restart. Check: journalctl -u crowdsec -n 40"
echo "  [OK]   CrowdSec restarted with full config"

# ── CrowdSec verification ─────────────────────────────────────────────────────
echo ""
CS_PASS=0; CS_FAIL=0
cs_ok()   { echo "  [OK]   $1"; CS_PASS=$((CS_PASS+1)); }
cs_fail() { echo "  [FAIL] $1"; CS_FAIL=$((CS_FAIL+1)); }

systemctl is-active crowdsec >/dev/null 2>&1 \
    && cs_ok  "CrowdSec agent running"           || cs_fail "CrowdSec agent NOT running"
systemctl is-active crowdsec-firewall-bouncer >/dev/null 2>&1 \
    && cs_ok  "nftables bouncer running"          || cs_fail "nftables bouncer NOT running"

if [ "$CS_LAPI_MODE" = "local" ]; then
    # Local LAPI: verify bouncer is registered and chain has its hook
    cscli bouncers list 2>/dev/null | grep -qE 'crowdsec-firewall-bouncer|nftables-bouncer' \
        && cs_ok  "bouncer registered with local LAPI"      || cs_fail "bouncer NOT registered"
else
    # Remote LAPI: verify agent can reach remote LAPI
    cscli lapi status 2>/dev/null | grep -q 'You can successfully interact' \
        && cs_ok  "CrowdSec agent connected to remote LAPI ($CS_LAPI_URL)" \
        || cs_fail "CrowdSec agent cannot reach remote LAPI -- check credentials and network"
    grep -q "api_url: ${CS_LAPI_URL}" "$BOUNCER_CONF" \
        && cs_ok  "Bouncer api_url points at remote LAPI" \
        || cs_fail "Bouncer api_url does not match expected remote LAPI URL"
fi

nft list table ip crowdsec >/dev/null 2>&1 \
    && cs_ok  "nftables crowdsec table present (ip)" \
    || cs_fail "nftables crowdsec table missing"
nft list chain ip crowdsec crowdsec_chain 2>/dev/null | grep -q 'hook input' \
    && cs_ok  "CrowdSec chain has input hook (priority -1) -- bans enforced" \
    || cs_fail "CrowdSec chain is MISSING its input hook -- bans will NOT block traffic"
grep -qE '^\s+log\s*$' /opt/iodine/Corefile \
    && cs_ok  "CoreDNS log plugin active"         || cs_fail "CoreDNS log plugin MISSING"
! grep -q 'privileged: true' /opt/iodine/docker-compose.yml \
    && cs_ok  "iodine privilege dropped"          || cs_fail "iodine: still has privileged:true"
grep -q 'udp dport 53 limit rate' /etc/nftables.conf \
    && cs_ok  "nftables UDP/53 rate limit"        || cs_fail "nftables UDP/53 rate limit MISSING"
cscli scenarios list 2>/dev/null | grep -q 'dns-decoy-scanner' \
    && cs_ok  "DNS decoy scenario loaded"         || cs_fail "DNS decoy scenario NOT loaded"
[ -f /etc/crowdsec/acquis.d/coredns-decoy.yaml ] \
    && cs_ok  "CrowdSec acquisition config"       || cs_fail "Acquisition config MISSING"
grep -q 'source: docker' /etc/crowdsec/acquis.d/coredns-decoy.yaml \
    && cs_ok  "Acquisition uses docker source"    || cs_fail "Acquisition source wrong"
cscli parsers list 2>/dev/null | grep -q 'coredns-decoy-logs' \
    && cs_ok  "CoreDNS parser loaded"             || cs_fail "CoreDNS parser NOT loaded"
grep -q 'apply_on: message' /etc/crowdsec/parsers/s01-parse/coredns-decoy-logs.yaml \
    && cs_ok  "Parser apply_on correct"           || cs_fail "Parser apply_on wrong -- must be message"

if $WG_USE_PORT_123; then
    cscli parsers list 2>/dev/null | grep -q 'ntp-probe-enrich' \
        && cs_ok  "Port 123 probe enricher loaded (s02-enrich)" \
        || cs_fail "Port 123 probe enricher NOT loaded -- probes on :123 won't trigger scenario"
    cscli scenarios list 2>/dev/null | grep -q 'ntp-probe-scanner' \
        && cs_ok  "Port 123 probe scenario loaded" \
        || cs_fail "Port 123 probe scenario NOT loaded"
fi

echo ""
echo "  ── CrowdSec: Passed: $CS_PASS   Failed: $CS_FAIL ──"
if [ "$CS_FAIL" -gt 0 ]; then
    echo ""
    echo "  CrowdSec diagnostics:"
    echo "    journalctl -u crowdsec                   -n 40 --no-pager"
    echo "    journalctl -u crowdsec-firewall-bouncer  -n 20 --no-pager"
    echo "    cscli lapi status"
    echo "    cscli bouncers list"
fi

echo ""
echo "  ── CrowdSec next steps ──────────────────────────────────────────────────"
echo ""
echo "  Test the DNS sensor from an external IP (not on your VPN):"
echo "    for i in \$(seq 1 5); do dig @${SERVER_IP} probe\$i.test.com; done"
echo "    sudo cscli decisions list   # your external IP should appear banned"
echo ""
if [ "$CS_LAPI_MODE" = "local" ]; then
    echo "  Add a remote node (jumpbox, reverse proxy) to THIS LAPI:"
    echo "    ON THIS NODE:   sudo cscli machines add <node-name> --auto"
    echo "    ON REMOTE NODE: sudo cscli lapi register --url http://${SERVER_IP}:8080 --token <token>"
    echo "                    sudo systemctl restart crowdsec"
    echo "                    sudo apt-get install -y crowdsec-firewall-bouncer-nftables"
    echo "    Remote bouncers MUST point at THIS LAPI, not their own local one."
    echo ""
fi
if [ "$CS_LAPI_MODE" = "remote" ]; then
    echo "  This node ships events to remote LAPI: $CS_LAPI_URL"
    echo "  Check decisions on the remote node: sudo cscli decisions list"
    echo ""
fi
echo "  Zero-tolerance mode (ban on first probe, no grace period):"
echo "    Edit /etc/crowdsec/scenarios/dns-decoy-scanner.yaml"
echo "    Set: type: trigger  (remove leakspeed and capacity lines)"
echo "    sudo systemctl restart crowdsec"
echo ""
echo "  Optional local Grafana dashboard:"
echo "    Select 'install dashboard' from the Setup Complete menu."
echo "    Connect WireGuard first, then open in your browser:"
echo "      http://\${WG_NETWORK%.*}.1:3000    <-- server WireGuard IP"
echo "    Do NOT use 127.0.0.1 -- that would be your own device."
echo ""

fi  # INSTALL_CS

# ── Post-install interactive menu ────────────────────────────────────────────
# build_and_show_menu() is defined at the top of the script alongside
# load_existing_config(). It detects what is installed at call time and
# conditionally includes WireGuard and CrowdSec sections.
build_and_show_menu
