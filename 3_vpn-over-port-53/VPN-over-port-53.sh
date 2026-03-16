#!/usr/bin/env bash
# VPN-over-port-53.sh -- DNS tunnel + WireGuard VPN server + Crowdsec port secuirty
# Debian 12+, must be run as root.
#
# Usage:
#   chmod +x VPN-over-port-53.sh && sudo ./VPN-over-port-53.sh
#
# ── What this script installs ─────────────────────────────────────────────────
#
#   WireGuard          VPN server on :51820 (internal; clients connect via :53)
#   CoreDNS            DNS server on :53 (Docker); routes tunnel vs decoy traffic
#   iodined            DNS tunnel server on 127.0.0.1:5300 (Docker)
#   nftables           Firewall; WireGuard/DNS prerouting, NAT, rate limits
#   CrowdSec           IPS: DNS decoy sensor, SSH + port-scan detection,
#                        nftables bouncer bans attackers at the kernel level
#   easy-wg-quick      WireGuard client config generator (Docker, run once)
#
# ── Dependencies (installed by this script) ───────────────────────────────────
#
#   nftables           Firewall and WireGuard prerouting redirect
#   wireguard-tools    wg, wg-quick
#   conntrack          Required to flush stale DNAT entries before services start
#   dnsutils           dig -- used for post-install verification
#   qrencode           Renders WireGuard client configs as QR codes in the menu
#   jq                 JSON processing for Grafana dashboard patching
#   docker-ce          Runs CoreDNS, iodined, and easy-wg-quick containers
#   docker-compose-plugin  Manages the CoreDNS + iodined stack
#   crowdsec           IPS agent and LAPI
#   crowdsec-firewall-bouncer-nftables  Enforces CrowdSec bans via nftables
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
# ── CrowdSec log -> ban pipeline ─────────────────────────────────────────────
#
#   CoreDNS stdout    ─┐
#   /var/log/auth.log  ├──>  CrowdSec agent  ──>  LAPI  ──>  bouncer  ──>  crowdsec-blacklists
#   /var/log/kern.log  ┘     (parse + score)                             (nftables DROP set)
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
#   stale entries. Do NOT flush conntrack after services are up -- flushing
#   removes active DNAT entries and breaks the WireGuard return path.
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
#    /opt/iodine/docker-compose.yml                           CoreDNS + iodined
#    /opt/iodine/Corefile                                     CoreDNS config
#    /etc/nftables.conf                                       Firewall rules
#    /etc/crowdsec/acquis.d/                                  CrowdSec log sources
#    /etc/crowdsec/parsers/s01-parse/coredns-decoy-logs.yaml  CoreDNS parser
#    /etc/crowdsec/parsers/s02-enrich/vpn-whitelist.yaml      VPN IP whitelist
#    /etc/crowdsec/scenarios/dns-decoy-scanner.yaml           DNS decoy ban scenario
#    /etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml    Bouncer config
#    /opt/crowdsec-grafana/                                   Dashboard files (if installed)
#

set -euo pipefail

die()     { echo "ERROR: $*" >&2; exit 1; }
section() { echo ""; echo "================================================================"; echo "  $*"; echo "================================================================"; }

# ── load_existing_config ──────────────────────────────────────────────────────
# Reads all variables needed by build_and_show_menu() from deployed files.
# Called when /etc/wireguard/wghub.conf already exists and the user just wants
# to view the Setup Complete menu without re-running the full install.
load_existing_config() {
    # set -e is active for the whole script. Every subshell that might fail
    # must use || true so a missing file or parse failure does not kill the
    # script silently before the menu ever appears.
    local errors=0

    # WG_PORT from wghub.conf ListenPort
    WG_PORT="$(grep '^ListenPort' /etc/wireguard/wghub.conf 2>/dev/null \
        | awk '{print $3}' || true)"
    [ -n "$WG_PORT" ] || { echo "  WARNING: could not read ListenPort from wghub.conf"; errors=$((errors+1)); }

    # SERVER_IP, PUBLIC_IFACE, WG_DNS from easy-wg-quick seed files
    SERVER_IP="$(cat /opt/wg/extnetip.txt 2>/dev/null | tr -d '[:space:]' || true)"
    [ -n "$SERVER_IP" ] || { echo "  WARNING: /opt/wg/extnetip.txt not found"; errors=$((errors+1)); }

    PUBLIC_IFACE="$(cat /opt/wg/extnetif.txt 2>/dev/null | tr -d '[:space:]' || true)"
    [ -n "$PUBLIC_IFACE" ] || { echo "  WARNING: /opt/wg/extnetif.txt not found"; errors=$((errors+1)); }

    WG_DNS="$(cat /opt/wg/intnetdns.txt 2>/dev/null | tr -d '[:space:]' || true)"
    [ -n "$WG_DNS" ] || WG_DNS="(unknown)"

    # IODINE_DOMAIN from Corefile -- first non-dot zone block
    IODINE_DOMAIN="$(grep -v '^[[:space:]]*\.' /opt/iodine/Corefile 2>/dev/null \
        | grep -oE '^[^[:space:]]+' 2>/dev/null | head -1 || true)"
    [ -n "$IODINE_DOMAIN" ] || { echo "  WARNING: could not parse IODINE_DOMAIN from Corefile"; errors=$((errors+1)); }

    # IODINED_PASS and TUNNEL_IP from docker-compose.yml.
    # The compose YAML splits the iodined command across two lines:
    #   line 1:  iodined -f -c -4 -p 5300 -l 127.0.0.1 -n auto
    #   line 2:  -P <pass> <tunnel_ip> <domain>
    # Grepping for 'iodined' finds line 1 which has no -P, so we grep for '-P '
    # specifically to find line 2. Fields on that line: -P pass tunnel_ip domain.
    local p_line
    p_line="$(grep -- '-P ' /opt/iodine/docker-compose.yml 2>/dev/null \
        | grep -v '^[[:space:]]*#' | head -1 || true)"

    IODINED_PASS="$(echo "$p_line" \
        | awk '{for(i=1;i<=NF;i++) if($i=="-P") {print $(i+1); exit}}' || true)"
    [ -n "$IODINED_PASS" ] || { echo "  WARNING: could not parse iodine password from docker-compose.yml"; errors=$((errors+1)); }

    # TUNNEL_IP is two fields after -P (pass=i+1, tunnel_ip=i+2)
    TUNNEL_IP="$(echo "$p_line" \
        | awk '{for(i=1;i<=NF;i++) if($i=="-P") {print $(i+2); exit}}' || true)"
    [[ "$TUNNEL_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] \
        || { echo "  WARNING: could not parse TUNNEL_IP (got: '$TUNNEL_IP')"; TUNNEL_IP="(unknown)"; errors=$((errors+1)); }

    # IODINE_NETWORK derived from TUNNEL_IP
    IODINE_NETWORK="${TUNNEL_IP%.*}.0/28"

    # WG_NETWORK from wghub.conf Address line (e.g. "Address = 10.13.1.1/24")
    # Strip the host IP and keep the network prefix with /24.
    local wg_addr
    wg_addr="$(grep '^Address' /etc/wireguard/wghub.conf 2>/dev/null \
        | awk '{print $3}' | tr -d '[:space:]' || true)"
    if [ -n "$wg_addr" ]; then
        # Convert host address (e.g. 10.13.1.1/24) to network (10.13.1.0/24).
        # The WireGuard subnet is always /24 (set by the intnetaddress.txt seed),
        # so stripping the last octet and appending .0/24 is exact.
        WG_NETWORK="${wg_addr%.*}.0/24"
    else
        echo "  WARNING: could not read WG_NETWORK from wghub.conf"
        WG_NETWORK="(unknown)"
        errors=$((errors+1))
    fi

    # WG_CLIENTS_RAW from wgclient_*.conf filenames in /opt/wg/
    local names=()
    for f in /opt/wg/wgclient_*.conf; do
        [ -f "$f" ] || continue
        local base name
        base="$(basename "$f" .conf)"
        name="${base#wgclient_}"
        names+=("$name")
    done
    if [ "${#names[@]}" -gt 0 ]; then
        WG_CLIENTS_RAW="$(IFS=','; echo "${names[*]}")"
    else
        echo "  WARNING: no wgclient_*.conf files found in /opt/wg/"
        WG_CLIENTS_RAW=""
        errors=$((errors+1))
    fi

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

    # Build a sed substitution script: for every datasource input variable
    # declared in __inputs, replace ${VAR_NAME} with CrowdSec throughout.
    # jq extracts the names; sed does the text-level replacement on the
    # jq-processed output so the two tools handle distinct concerns.
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
build_and_show_menu() {
    MENUDIR="$(mktemp -d /tmp/dns-tunnel-menu.XXXXXX)"
    # Temp dir removed by the global cleanup() trap registered at script start.

    # 1. DNS delegation
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

    # 2. iodine connect instructions
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
    SSH SOCKS proxy: ssh -D 1080 -C -N user@${TUNNEL_IP}

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

    Once connected, all phone traffic routes through the tunnel.

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

    # 3. WireGuard per-client configs + QR codes
    IFS=',' read -ra WG_CLIENT_NAMES <<< "$WG_CLIENTS_RAW"
    local CLIENT_IDX=3
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
            echo "  Windows:"
            echo "    Import tunnel from file: $conf"
            echo ""
            echo "  ┌─────────────────────────────────────────────────────────┐"
            echo "  │  ⚠  CELLULAR WARNING   ⚠   ⚠   ⚠   ⚠   ⚠   ⚠            │"
            echo "  │                                                         │"
            echo "  │  WireGuard is ontop of UDP port 53. Most cell phone     │"
            echo "  │  carriers (Verizon,etc) run a transparent DNS proxy     │"
            echo "  │  ontop of your communications that intercepts UDP/53    │"
            echo "  │  This corrupts UDP :53 traffic that is not real DNS.    │"
            echo "  │                                                         │"
            echo "  │  Symptom: works on WiFi, fails on cellular.             │"
            echo "  │  Fix: get off the cell network, or use iodine           │"
            echo "  │                                                         │"
            echo "  │  Android: iodine alone is your tunnel on cellular.      │"
            echo "  │                                                         │"
            echo "  │  See 'cellular warning' in this menu for full details.  │"
            echo "  └─────────────────────────────────────────────────────────┘"
        } > "$OUTFILE"

        CLIENT_IDX=$((CLIENT_IDX + 1))
    done

    # 4. Service management
    cat > "$MENUDIR/91_services.txt" << SECTION
================================================================
  Service Management
================================================================

  ── Status ──────────────────────────────────────────────────

    sudo wg show
    sudo systemctl status wg-quick@wghub
    sudo systemctl status crowdsec
    sudo systemctl status crowdsec-firewall-bouncer
    cd /opt/iodine && docker compose ps
    sudo nft list ruleset

  ── Restart all ─────────────────────────────────────────────

    sudo systemctl restart nftables
    sudo systemctl restart wg-quick@wghub
    sudo systemctl restart crowdsec
    sudo systemctl restart crowdsec-firewall-bouncer
    cd /opt/iodine && docker compose restart

  ── Logs ────────────────────────────────────────────────────

    sudo journalctl -u wg-quick@wghub -f
    sudo journalctl -u nftables --no-pager -n 30
    sudo journalctl -u crowdsec -f
    sudo journalctl -u crowdsec-firewall-bouncer -f
    cd /opt/iodine && docker compose logs -f coredns
    cd /opt/iodine && docker compose logs -f iodine

  ── Grafana / Prometheus (if dashboard installed) ────────────

    docker ps | grep -E 'crowdsec-prometheus|crowdsec-grafana'
    docker start crowdsec-prometheus crowdsec-grafana
    docker stop  crowdsec-prometheus crowdsec-grafana
    docker logs  crowdsec-prometheus
    docker logs  crowdsec-grafana

  ── Conntrack (active tunnels) ──────────────────────────────

    sudo conntrack -L | grep 51820

  ── Traffic verification ─────────────────────────────────────

    # WireGuard packets arriving on port 53 (will look like garbled DNS):
    sudo tcpdump -i ${PUBLIC_IFACE} -n udp port 53

    # If nothing appears on :53 when phone connects, carrier is blocking it.
    # Use iodine fallback (see iodine menu entry).

  ── File locations ───────────────────────────────────────────

    /etc/wireguard/wghub.conf                                WireGuard server config
    /opt/wg/                                                 WireGuard client configs
    /opt/iodine/docker-compose.yml                           CoreDNS + iodined
    /opt/iodine/Corefile                                     CoreDNS config
    /etc/nftables.conf                                       Firewall rules
    /etc/crowdsec/acquis.d/                                  CrowdSec log sources
    /etc/crowdsec/parsers/s01-parse/coredns-decoy-logs.yaml  CoreDNS parser
    /etc/crowdsec/parsers/s02-enrich/vpn-whitelist.yaml      VPN IP whitelist
    /etc/crowdsec/scenarios/dns-decoy-scanner.yaml           DNS decoy ban scenario
    /etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml    Bouncer config
    /opt/crowdsec-grafana/                                   Dashboard files (if installed)
SECTION

    # 6. Cellular warning
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

  ── Workaround: tunnel WireGuard through iodine ─────────────

    iodine encodes traffic as real DNS queries -- it was built
    to survive exactly this. Once iodine is connected, you have
    a direct IP path to the server that bypasses the carrier proxy.

    Desktop / Linux only (Android = one VPN at a time):
      1. Connect iodine  (see iodine menu entry for credentials)
      2. In your WireGuard client config, temporarily set:
           Endpoint = ${TUNNEL_IP}:${WG_PORT}
      3. Connect WireGuard as normal
      4. All traffic: phone -> iodine DNS tunnel -> server -> internet

    On Android, use iodine alone as your tunnel while on cellular.
    iodine alone gives you a TCP/IP path to the server; layer SSH
    on top for encryption:
      ssh -D 1080 -C -N user@${TUNNEL_IP}
    Then set your browser/app SOCKS proxy to 127.0.0.1:1080.

  ── Why port 53 at all? ──────────────────────────────────────

    Most firewalls (hotels, airports, offices, restrictive ISPs)
    block everything except ports 80, 443, and 53.
    Port 53 gets through almost everywhere -- except carriers
    who own the DNS infrastructure themselves.
    It is a trade-off: maximum firewall bypass, some carrier risk.
SECTION

    # ── CrowdSec: what it is and next steps (wiki) ──────────────────────────────
    cat > "$MENUDIR/93_crowdsec_about.txt" << 'SECTION'
================================================================
  CrowdSec -- Post-Install Guide
================================================================

  ── What CrowdSec does ──────────────────────────────────────

  CrowdSec is a collaborative intrusion prevention system.
  It watches your logs in real-time, detects attack patterns,
  and bans the source IP -- across every machine in your network
  simultaneously.

  On this server, the DNS decoy on port 53 is the primary sensor.
  Any IP that probes your DNS (this server is not a public resolver)
  is treated as a scanner and banned automatically.

  ── How the pieces fit together ─────────────────────────────

    Sensor (CoreDNS decoy)
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

    LAPI (Local API on this machine, port 8080)
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

  ── Daily monitoring (three commands cover most needs) ───────

    sudo cscli decisions list     -- who is currently banned
    sudo cscli alerts list        -- what triggered those bans
    sudo cscli metrics            -- system health + performance

  ── Check current bans ──────────────────────────────────────

    sudo cscli decisions list
    sudo cscli decisions list --origin crowdsec --limit 20
    sudo cscli alerts list --scenario custom/dns-decoy-scanner

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

  ── Step 2: Add remote nodes to THIS LAPI (optional) ────────

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

    Edit /etc/crowdsec/scenarios/dns-decoy-scanner.yaml
    Set: type: trigger  (remove leakspeed and capacity lines)
    sudo systemctl restart crowdsec
SECTION

    # ── CrowdSec: commands reference ─────────────────────────────────────────────
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

    Checks connectivity to the Local API (LAPI) on this machine.
    Run this first if decisions are not propagating. If this
    fails, bouncer bans are not being applied anywhere.

  sudo cscli console status

    Shows the status of CrowdSec console options.
    This setup runs fully offline -- no cloud enrollment needed.

  ── Performance metrics ──────────────────────────────────────

  sudo cscli metrics

    Displays Prometheus metrics: parser success/failure rates,
    events parsed per second, bucket states, API call counts.
    Use this if CrowdSec seems slow or not triggering scenarios.

    Key things to look for:
      PARSERS section:  'success' count growing = logs are parsed
      SCENARIOS section: 'bucket_overflows' = bans being triggered
      LAPI section:     'decisions_get_total' = bouncers polling

  sudo cscli metrics list

    Shows the available metric categories if you want to filter
    the output of 'cscli metrics'.

  ── Installed content ────────────────────────────────────────

  sudo cscli hub list

    Shows all installed parsers, scenarios, and collections.
    Check here to confirm custom/coredns-decoy-logs and
    custom/dns-decoy-scanner are loaded.

  sudo cscli hub update

    Fetches the latest hub index from CrowdSec's CDN.
    Run this before upgrading any hub content.

  ── Machine & bouncer management ─────────────────────────────

  sudo cscli machines list

    Lists every CrowdSec agent registered with this LAPI.
    If you add remote nodes (see About section), they appear here.
    A machine that has not checked in recently shows stale status.

  sudo cscli bouncers list

    Lists every bouncer registered with this LAPI.
    Each bouncer shows its last heartbeat time.
    If the nftables bouncer shows as disconnected, bans are not
    being enforced -- restart it:
      sudo systemctl restart crowdsec-firewall-bouncer

  ── Manually add or delete a ban ─────────────────────────────

  sudo cscli decisions add --ip 1.2.3.4 --duration 24h --reason "manual"

    Manually ban an IP for 24 hours. The bouncer picks it up
    within 10 seconds and drops all traffic from that IP.

  sudo cscli decisions delete --ip 1.2.3.4

    Remove a ban for a specific IP. Use this to unban yourself
    if you accidentally trigger the DNS decoy sensor while testing.

  ── CrowdSec service management ──────────────────────────────

  sudo systemctl status crowdsec
  sudo systemctl status crowdsec-firewall-bouncer
  sudo systemctl restart crowdsec
  sudo systemctl restart crowdsec-firewall-bouncer

  Logs:
    sudo journalctl -u crowdsec -f
    sudo journalctl -u crowdsec-firewall-bouncer -f
SECTION

    touch "$MENUDIR/51_crowdsec_live.sh"

    # ── Add new WireGuard client action ──────────────────────────────────────
    # Stored as a .sh sentinel file. The menu loop detects .sh and runs the
    # function instead of paging a file. This lets the menu support live
    # actions alongside static info pages.
    touch "$MENUDIR/50_add_wireguard_client.sh"
    touch "$MENUDIR/60_install_dashboard.sh"

    # ── Menu loop ─────────────────────────────────────────────────────────────
    # IMPORTANT: read calls use || true so set -e does not kill the script on
    # empty input or EOF. Without this, pressing Enter on an empty line or any
    # terminal quirk causes a silent exit back to the shell.
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

        # Rebuild the per-client menu pages so the new client appears
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
            echo "  Windows:"
            echo "    Import tunnel from file: $newconf"
            echo ""
            echo "  ┌─────────────────────────────────────────────────────────┐"
            echo "  │  ⚠  CELLULAR WARNING   ⚠   ⚠   ⚠   ⚠   ⚠   ⚠            │"
            echo "  │                                                         │"
            echo "  │  WireGuard is ontop of UDP port 53. Most cell phone     │"
            echo "  │  carriers (Verizon,etc) run a transparent DNS proxy     │"
            echo "  │  ontop of your communications that intercepts UDP/53    │"
            echo "  │  This corrupts UDP :53 traffic that is not real DNS.    │"
            echo "  │                                                         │"
            echo "  │  Symptom: works on WiFi, fails on cellular.             │"
            echo "  │  Fix: get off the cell network, or use iodine           │"
            echo "  │                                                         │"
            echo "  │  Android: iodine alone is your tunnel on cellular.      │"
            echo "  │                                                         │"
            echo "  │  See 'cellular warning' in this menu for full details.  │"
            echo "  └─────────────────────────────────────────────────────────┘"
        } > "$newfile"
        CLIENT_IDX=$((CLIENT_IDX + 1))
    }
    action_crowdsec_live() {
        clear
        echo ""
        echo "  ╔══════════════════════════════════════════════════╗"
        echo "  ║   CrowdSec -- Live Decisions & System Status     ║"
        echo "  ╚══════════════════════════════════════════════════╝"
        echo ""
        echo "  This view shows what CrowdSec is actively doing:"
        echo "  current bans, recent alerts, and system health."
        echo ""

        if ! command -v cscli >/dev/null 2>&1; then
            echo "  ERROR: cscli not found -- CrowdSec may not be installed."
            return
        fi

        echo "  ── Service status ────────────────────────────────────"
        echo ""
        local cs_active cs_bouncer_active
        cs_active="$(systemctl is-active crowdsec 2>/dev/null)"
        cs_bouncer_active="$(systemctl is-active crowdsec-firewall-bouncer 2>/dev/null)"
        echo "    crowdsec agent:   $cs_active"
        echo "    nftables bouncer: $cs_bouncer_active"

        # The bouncer creates 'table ip crowdsec' on its first poll cycle
        # (up to 10s after start). Check for the exact table -- not a grep
        # on 'nft list tables' which could match unrelated table names.
        # If bouncer is active but table absent, it just hasn't polled yet.
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
        echo "  Alerts specifically from the port-53 DNS decoy sensor."
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

    action_install_dashboard() {
        clear
        local WG_SERVER_IP="${WG_NETWORK%.*}.1"
        local GRAFANA_DIR="/opt/crowdsec-grafana"

        echo ""
        echo "  ╔══════════════════════════════════════════════════╗"
        echo "  ║   CrowdSec Grafana Dashboard -- Local Install    ║"
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

        # Verify CrowdSec Prometheus endpoint is actually up
        if ! curl -sf http://127.0.0.1:6060/metrics >/dev/null 2>&1; then
            echo "  ERROR: CrowdSec metrics endpoint not responding at http://127.0.0.1:6060/metrics"
            echo "  Check: cscli metrics   and   journalctl -u crowdsec -n 20 --no-pager"
            return
        fi
        echo "  [OK]   CrowdSec metrics endpoint reachable at :6060/metrics"

        # Handle existing containers
        local reinstall=false
        for cname in crowdsec-prometheus crowdsec-grafana; do
            if docker inspect "$cname" >/dev/null 2>&1; then
                local st
                st="$(docker inspect -f '{{.State.Status}}' "$cname" 2>/dev/null)"
                echo "  Container $cname already exists (state: $st)."
            fi
        done
        local any_exists=false
        for cname in crowdsec-grafana crowdsec-prometheus; do
            docker inspect "$cname" >/dev/null 2>&1 && any_exists=true
        done
        if $any_exists; then
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

        # ── Directory layout ──────────────────────────────────────────────────
        echo "  Creating directory layout under ${GRAFANA_DIR}..."
        mkdir -p "${GRAFANA_DIR}/prometheus"
        mkdir -p "${GRAFANA_DIR}/provisioning/datasources"
        mkdir -p "${GRAFANA_DIR}/provisioning/dashboards"

        # ── Prometheus config ─────────────────────────────────────────────────
        # Scrapes CrowdSec's built-in Prometheus exporter on localhost:6060.
        # Both containers run --network host so localhost is the same for both.
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

        # ── Grafana datasource: Prometheus server at :9090 ────────────────────
        # Grafana queries Prometheus via the full query API (/api/v1/query etc.)
        # on port 9090 -- NOT CrowdSec's raw metrics exporter on port 6060.
        # CrowdSec's :6060 only serves /metrics in exposition format; Grafana
        # cannot use it directly as a datasource.
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

        # ── Dashboard provider ────────────────────────────────────────────────
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

        # ── Download CrowdSec dashboards (v5) ────────────────────────────────
        # Official dashboards from crowdsecurity/grafana-dashboards (dashboards_v5).
        # These target a Prometheus datasource with CrowdSec metrics -- exactly
        # what we have. We patch __inputs datasource placeholders to "CrowdSec".
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

        # ── Pull images ───────────────────────────────────────────────────────
        echo "  Pulling images..."
        docker pull prom/prometheus:latest || { echo "  ERROR: prometheus pull failed."; return; }
        docker pull grafana/grafana:latest || { echo "  ERROR: grafana pull failed.";    return; }

        # ── Start Prometheus ──────────────────────────────────────────────────
        # --network host: localhost:6060 resolves to the host's CrowdSec.
        # Port 9090 is blocked from internet by nftables (VPN-only).
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

        # Brief wait for Prometheus to be ready before starting Grafana
        local p=0
        until curl -sf http://127.0.0.1:9090/-/ready >/dev/null 2>&1; do
            sleep 2; p=$((p+1))
            [ $p -ge 15 ] && { echo "  WARN: Prometheus slow to start -- continuing anyway"; break; }
        done
        echo "  [OK]   Prometheus ready at :9090"

        # ── Start Grafana ─────────────────────────────────────────────────────
        # --network host: localhost:9090 resolves to the Prometheus container above.
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

        # Wait for Grafana health
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

        # Verify Prometheus is actually scraping CrowdSec
        sleep 5
        local targets_json targets
        targets_json="$(curl -sf 'http://127.0.0.1:9090/api/v1/targets' 2>/dev/null || true)"
        # Advisory check only -- target may need up to 15s after first scrape.
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
        echo "  ║   Stack is ready                                  ║"
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
        echo "  ── Files ───────────────────────────────────────────"
        echo ""
        echo "    ${GRAFANA_DIR}/prometheus/prometheus.yml"
        echo "    ${GRAFANA_DIR}/provisioning/datasources/crowdsec.yml"
        echo "    ${GRAFANA_DIR}/provisioning/dashboards/provider.yml"
        echo "    ${GRAFANA_DIR}/provisioning/dashboards/crowdsec-overview.json"
        echo "    ${GRAFANA_DIR}/provisioning/dashboards/crowdsec-insight.json"
        echo "    ${GRAFANA_DIR}/provisioning/dashboards/crowdsec-details.json"
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




    clear
    echo ""
    echo "  ╔══════════════════════════════════════════════════╗"
    echo "  ║   DNS Tunnel + WireGuard  --  Setup Complete     ║"
    echo "  ╚══════════════════════════════════════════════════╝"
    echo ""
    echo "  Use the menu below to view connection info, QR codes,"
    echo "  service commands, and CrowdSec monitoring."
    echo ""

    while true; do
        echo "  ── Select a section ──────────────────────────────"
        echo ""

        # Build lists from both .txt (page) and .sh (action) files in MENUDIR
        local MENU_FILES=() MENU_LABELS=() MENU_TYPES=()
        for f in "$MENUDIR"/*.txt "$MENUDIR"/*.sh; do
            [ -f "$f" ] || continue
            local base label ftype
            base="$(basename "$f")"
            # strip extension
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
                printf "    %2d)  ★ %s\n" "$((i+1))" "${MENU_LABELS[$i]}"
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
                # Action item -- derive function name from filename and call it
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

# ── Cleanup ───────────────────────────────────────────────────────────────────
# A single trap owns both temp directories so neither code path can
# accidentally overwrite the other's registration.
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
   DNS TUNNEL + WIREGUARD VPN + CROWDSEC IPS  --  port 53

  Architecture:
    nftables (kernel)  -- inspects first 4 bytes of every UDP:53 packet
      WireGuard bytes  -->  wg-quick on :51820  (kernel redirect, no proxy)
      DNS bytes        -->  CoreDNS on :53
    CoreDNS            -- tunnel domain --> iodined; everything else --> decoy
    iodined            -- iodine DNS tunnel on 127.0.0.1:5300
    wg-quick           -- WireGuard hub on :51820 (internal; not externally open)
    CrowdSec           -- IDS/IPS: DNS decoy sensor, SSH + port-scan detection,
                          nftables bouncer bans attackers at the kernel level

  What this script installs:
    WireGuard VPN, iodine DNS tunnel, CoreDNS, nftables firewall, CrowdSec IPS

  What you need before running:
    Two DNS records at your registrar:
      tunnel.yourdomain.com   IN NS   address.yourdomain.com
      address.yourdomain.com  IN A    <this server's public IP>
    DNS propagation takes up to 48 hours -- set these up first.

INTRO

read -rsp "  Press any key to continue, Ctrl-C to abort..." -n1
echo ""; echo ""

# ── Root check (needed before existing-install check) ────────────────────────
[ "$(id -u)" -eq 0 ] || { echo "ERROR: Must be run as root." >&2; exit 1; }

# ── Existing install check ────────────────────────────────────────────────────
# If /etc/wireguard/wghub.conf already exists the user may just want to view
# their QR codes or connection info without re-running the full install.
# This check runs before any apt/install/config work so it is instant.
if [ -f /etc/wireguard/wghub.conf ]; then
    clear
    echo ""
    echo "  ╔══════════════════════════════════════════════════╗"
    echo "  ║   Existing installation detected                 ║"
    echo "  ║   /etc/wireguard/wghub.conf already exists       ║"
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
            # Read config values from deployed files and jump to the interactive menu.
            # No packages are installed, no files are modified.
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
apt-get install -y nftables dnsutils wireguard-tools qrencode conntrack jq
echo "  nftables, dnsutils, wireguard-tools, qrencode, conntrack, jq: installed"

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

read -rp "WireGuard client DNS (default: 45.11.45.11): " WG_DNS
WG_DNS="${WG_DNS:-45.11.45.11}"

read -rp "WireGuard client names, comma-separated (e.g. phone,laptop): " WG_CLIENTS_RAW
WG_CLIENTS_RAW="${WG_CLIENTS_RAW:-phone}"

# Management IP: the IP you SSH from. Whitelisted in CrowdSec (never banned)
# and gets an unconditional nftables SSH accept rule so you cannot be locked out.
DETECTED_SSH_IP="$(echo "${SSH_CLIENT:-}" | awk '{print $1}' || true)"
if [[ "$DETECTED_SSH_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "  Detected SSH source IP: $DETECTED_SSH_IP"
fi
read -rp "Your unbannable management IP (default: 127.0.0.1): " MANAGEMENT_IP
MANAGEMENT_IP="${MANAGEMENT_IP:-127.0.0.1}"
[[ "$MANAGEMENT_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "Invalid management IP: $MANAGEMENT_IP"

WG_PORT=51820
WG_NETWORK="10.13.1.0/24"

echo ""
echo "  Summary:"
echo "    Tunnel zone      : $IODINE_DOMAIN"
echo "    Server IP        : $SERVER_IP"
echo "    Interface        : $PUBLIC_IFACE"
echo "    iodine net       : $IODINE_NETWORK"
echo "    WireGuard port   : $WG_PORT (internal; clients connect to port 53)"
echo "    WireGuard subnet : $WG_NETWORK"
echo "    WireGuard DNS    : $WG_DNS"
echo "    WG clients       : $WG_CLIENTS_RAW"
echo "    Management IP    : $MANAGEMENT_IP  (whitelisted -- never banned, always has SSH)"
if [ "$IODINED_PASS" = "$DEFAULT_PASS" ]; then
    echo "    iodine password  : $IODINED_PASS  (generated)"
else
    echo "    iodine password  : ${#IODINED_PASS} chars (user supplied)"
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
# Both network_mode: host -- they share the host network namespace directly.
# CoreDNS depends_on iodined so iodined binds :5300 before CoreDNS forwards to it.
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
# table ip iodine_nat:
#
#   chain prerouting (dstnat priority):
#     Matches WireGuard UDP packets on port 53 by payload type field.
#     @th,64,32 = 32 bits at offset 64 bits from transport header = first 4
#     bytes of UDP payload. nftables reads big-endian; WireGuard type bytes
#     are little-endian, so type 1 (0x01 0x00 0x00 0x00) = 0x01000000.
#     Redirect changes dport to 51820. conntrack records the DNAT and rewrites
#     the source port on replies, so clients see traffic from SERVER_IP:53.
#
#   chain postrouting (srcnat priority):
#     Masquerade for iodine and WireGuard subnets leaving via public interface.
#
# table inet filter:
#   Port 53 open externally (CoreDNS + prerouting redirect for WireGuard).
#   Port 51820 NOT open externally -- ct status dnat accept handles
#   the redirected WireGuard packets after they pass through prerouting.
#
# Docker table collision avoidance:
#   Docker creates: table ip filter, table ip nat
#   We create:      table ip iodine_nat, table inet filter (different names/family)
cat > "$GENDIR/nftables.conf" << NFTABLES_EOF
#!/usr/sbin/nft -f
# /etc/nftables.conf -- generated by VPN-over-port-53.sh

table ip iodine_nat
flush table ip iodine_nat

table ip iodine_nat {

    chain prerouting {
        type nat hook prerouting priority dstnat; policy accept;
        # Redirect WireGuard packets arriving on port 53 to wg-quick on :51820.
        # Matches all four WireGuard message types by the first 4 bytes of the
        # UDP payload. conntrack records the DNAT so replies are rewritten back
        # to source port 53 transparently.
        udp dport 53 @th,64,32 { 0x01000000, 0x02000000, 0x03000000, 0x04000000 } redirect to :51820
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
        # This rule is at priority 0 (main filter). The CrowdSec chain is at
        # priority -1 so it fires first. But management IP is in the CrowdSec
        # whitelist so it will never be added to the ban set in the first place.
        ip saddr ${MANAGEMENT_IP} tcp dport 22 accept

        tcp dport 22 ct state new limit rate 5/minute accept
        tcp dport 22 drop

        tcp flags & (fin|syn|rst|psh|ack|urg) == fin|syn drop
        tcp flags & (fin|syn|rst|psh|ack|urg) == fin|syn|rst drop
        tcp flags & (fin|syn|rst|psh|ack|urg) == fin|rst drop
        tcp flags & (fin|syn|rst|psh|ack|urg) == 0x0 drop
        tcp dport { 80, 443 } ct state new limit rate over 25/second burst 50 packets drop
        tcp dport { 80, 443 } ct state new ct count over 100 drop
        tcp dport { 80, 443 } accept

        # Port 53: CoreDNS receives DNS; prerouting redirects WireGuard to :51820.
        # Port 51820 is NOT open externally -- ct status dnat accept above handles
        # packets that arrive via the port-53 prerouting DNAT redirect.
        udp dport 53 accept
        tcp dport 53 ct state new limit rate over 2/minute drop
        tcp dport 53 accept

        # Port 51820 from the iodine subnet only -- iodine fallback path.
        # When a carrier intercepts UDP port 53, clients connect iodine first
        # (which survives because it looks like valid DNS), then send WireGuard
        # traffic directly to ${TUNNEL_IP}:51820 from inside the iodine tunnel.
        # These packets arrive on the iodine tun interface (not via DNAT), so
        # ct status dnat does not match them. We allow them explicitly by source
        # subnet rather than by interface name -- the iodine tun device name
        # (dns0) is created at runtime and may vary.
        # The internet cannot reach this rule: ${IODINE_NETWORK} is a private
        # RFC1918 range only reachable after a successful iodine handshake.
        ip saddr ${IODINE_NETWORK} udp dport ${WG_PORT} accept

        # Dashboard port 3000 (Grafana) and 9090 (Prometheus): VPN only.
        # Port 9090 must be blocked from internet -- Prometheus has no auth.
        ip saddr { ${WG_NETWORK}, ${IODINE_NETWORK} } tcp dport { 3000, 9090 } accept

        icmp type echo-request limit rate 5/second accept
        icmp type echo-request drop

        # Log unmatched packets to kern.log before dropping.
        # crowdsecurity/iptables reads these to detect port scans.
        # Only external probes reach here -- VPN/SSH/DNS are accepted above.
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
# permanently if the bouncer stalls).  The bouncer detects the pre-existing set
# and chain, reuses them, and only manages set membership.
# Priority -1 ensures this chain runs BEFORE the inet filter input chain (priority 0).
# That means banned IPs are dropped here, before 'ct state established,related accept'
# in the filter chain ever fires -- so even active SSH sessions from banned IPs are cut.
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

# ── easy-wg-quick seed files ──────────────────────────────────────────────────
# portno.txt = 53  -> client Endpoint = SERVER_IP:53
# After generation, wghub.conf has ListenPort = 53. We patch it to 51820.
# Client configs are not patched -- Endpoint = SERVER_IP:53 is correct.
echo "${SERVER_IP}"    > "$GENDIR/wg/extnetip.txt"
echo "53"              > "$GENDIR/wg/portno.txt"
echo "${PUBLIC_IFACE}" > "$GENDIR/wg/extnetif.txt"
echo "none"            > "$GENDIR/wg/sysctltype.txt"
echo "none"            > "$GENDIR/wg/fwtype.txt"
echo "10.13.1."        > "$GENDIR/wg/intnetaddress.txt"
echo "${WG_DNS}"       > "$GENDIR/wg/intnetdns.txt"

echo "  Config files generated."

# ── Run easy-wg-quick ─────────────────────────────────────────────────────────
section "Generating WireGuard configs (easy-wg-quick)"

WG_WORKDIR="/opt/wg"
mkdir -p "$WG_WORKDIR"

# Always write seed files -- they are cheap and ensure settings are current
# even on re-runs. easy-wg-quick reads them before generating any config.
cp "$GENDIR/wg/"*.txt "$WG_WORKDIR/"

IFS=',' read -ra WG_CLIENT_NAMES <<< "$WG_CLIENTS_RAW"
FIRST_CLIENT="$(echo "${WG_CLIENT_NAMES[0]}" | tr -d '[:space:]')"
[ -z "$FIRST_CLIENT" ] && FIRST_CLIENT="client1"

# ── Idempotency: wghub.conf ───────────────────────────────────────────────────
# wghub.conf only needs to be generated once. On re-runs it already exists and
# already has ListenPort = 51820 (patched on first run). Regenerating it would
# rotate the server private key, invalidating all existing client configs.
# Skip generation if wghub.conf exists AND already has the correct ListenPort.
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

    # Patch wghub.conf ListenPort: 53 (written by portno.txt) -> 51820 (wg-quick internal port).
    #
    # Why these are different:
    #   portno.txt = 53  so easy-wg-quick writes Endpoint = SERVER_IP:53 into every
    #   client config. That is the correct external port -- the only port open to the
    #   internet. nftables prerouting redirects WireGuard packets arriving on :53 to
    #   :51820 where wg-quick actually listens. wghub.conf therefore needs 51820.
    #
    # This patch must happen exactly once, immediately after generation, before
    # wghub.conf is copied to /etc/wireguard/. On re-runs the file already has 51820
    # and the block above skips here entirely.
    grep -q "ListenPort = 53" "$WG_WORKDIR/wghub.conf" \
        || die "wghub.conf does not have 'ListenPort = 53' -- portno.txt seed may have failed"
    sed -i 's/^ListenPort = 53$/ListenPort = 51820/' "$WG_WORKDIR/wghub.conf"
    grep -q "ListenPort = ${WG_PORT}" "$WG_WORKDIR/wghub.conf" \
        || die "wghub.conf ListenPort patch failed"
    echo "  wghub.conf ListenPort patched: 53 -> ${WG_PORT}"
fi

# ── Idempotency: client configs ───────────────────────────────────────────────
# Generate only clients that do not already have a config file.
# Existing client configs are skipped -- regenerating rotates their keys and
# requires redistributing the config to the device.
# The first client was handled above (with wghub.conf). Process all clients here
# uniformly -- the skip logic handles the first client too if it already existed.
#
# Note: no _iodine variant is generated here. Android can only run one VPN at a
# time, so a separate iodine+WireGuard combined profile is not useful on mobile.
# On desktop/Linux, connecting WireGuard over iodine is done manually by setting
# Endpoint = TUNNEL_IP:51820 in the existing client config while iodine is up.
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

SAMPLE_CONF="$WG_WORKDIR/wgclient_${FIRST_CLIENT}.conf"
if grep -q "Endpoint = ${SERVER_IP}:53" "$SAMPLE_CONF"; then
    echo "  Client Endpoint = ${SERVER_IP}:53  [correct]"
else
    ENDPOINT_FOUND="$(grep "Endpoint" "$SAMPLE_CONF" || echo "(not found)")"
    echo "  WARNING: unexpected client Endpoint: $ENDPOINT_FOUND"
fi

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

mkdir -p /etc/wireguard
install -m 600 "$WG_WORKDIR/wghub.conf" /etc/wireguard/wghub.conf
echo "  -> /etc/wireguard/wghub.conf  (mode 600)"

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
# Order:
#   1. nftables  -- prerouting redirect must exist before anything binds port 53
#   2. conntrack -F  -- flush stale entries that would bypass prerouting
#   3. wg-quick  -- binds :51820
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

# 3. wg-quick
systemctl enable wg-quick@wghub
systemctl restart wg-quick@wghub \
    || { echo ""; echo "  ERROR: wg-quick@wghub failed. Logs:"; \
         journalctl -u wg-quick@wghub --no-pager -n 30; \
         die "WireGuard failed -- see logs above"; }
ip link show wghub >/dev/null 2>&1 || die "wghub interface not found after wg-quick start"
echo "  WireGuard (wghub): started"
wg show wghub

# 4. CoreDNS + iodined
echo "  Pulling images..."
docker compose -f /opt/iodine/docker-compose.yml pull
docker compose -f /opt/iodine/docker-compose.yml up -d
echo "  iodined + CoreDNS: started"

# 5. nftables reload -- Docker no longer wipes our rules (iptables=false).
#    Do NOT flush conntrack here. The WireGuard handshake DNAT entry must
#    survive so conntrack can rewrite response src port 51820 -> 53 on the
#    way back to the client. Flushing mid-handshake breaks the return path.
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

ss -ulnp | grep -qE "0\.0\.0\.0:${WG_PORT}|\*:${WG_PORT}" \
    && check_pass "WireGuard on :${WG_PORT}"   || check_fail "WireGuard not on :${WG_PORT}"
ip link show wghub >/dev/null 2>&1 \
    && check_pass "wghub interface up"         || check_fail "wghub interface not found"

nft list table ip iodine_nat >/dev/null 2>&1 \
    && check_pass "nftables iodine_nat table" \
    || check_fail "nftables iodine_nat table missing"
nft list chain ip iodine_nat prerouting >/dev/null 2>&1 \
    && check_pass "nftables prerouting chain loaded" \
    || check_fail "nftables prerouting chain MISSING"
nft list chain ip iodine_nat prerouting 2>/dev/null | grep -qE ':?51820' \
    && check_pass "nftables WireGuard redirect rule present" \
    || check_fail "nftables WireGuard redirect rule MISSING"
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
    echo "    journalctl -u wg-quick@wghub --no-pager -n 30"
    echo "    journalctl -u nftables       --no-pager -n 20"
    echo "    docker logs coredns"
    echo "    docker logs iodine"
    echo "    nft list ruleset"
fi

# ── CrowdSec integration ──────────────────────────────────────────────────────
# Wires the port-53 CoreDNS decoy into CrowdSec LAPI.
# Every external DNS probe triggers an alert and propagates a ban network-wide.
#
# Variables already in scope: SERVER_IP  WG_NETWORK  IODINE_NETWORK  IODINE_DOMAIN
#
# ── Log pipeline ──────────────────────────────────────────────────────────────
# Uses CrowdSec's built-in 'docker' datasource. Reads CoreDNS stdout directly
# from the Docker socket. No extra plugins required.
# journald datasource avoided -- requires a separate plugin not shipped by
# default; causes "unknown data source journald" fatal startup error.
#
# ── Startup order ─────────────────────────────────────────────────────────────
#   1. Install binary  (apt-get; post-install hook failure tolerated)
#   2. Write ALL config BEFORE first start
#        acquisition  -- "no datasource enabled" = fatal if missing
#        scenarios    -- unknown YAML fields = fatal; 'enabled' is NOT valid
#   3. Start CrowdSec / LAPI
#   4. Install bouncer AFTER LAPI confirmed running
#        bouncer post-install starts service immediately; LAPI must be up
#   5. Patch bouncer config (disable IPv6 -- sysctl has IPv6 off system-wide)
#   6. Start bouncer
#   7. Recreate containers + reload nftables

section "CrowdSec -- DNS decoy sensor + LAPI"

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

# ── Step 2a: Security fix: drop iodine container privilege ───────────────────
# privileged:true grants full host capabilities. iodined only needs NET_ADMIN.
if grep -q 'privileged: true' /opt/iodine/docker-compose.yml; then
    # Remove the privileged:true line
    sed -i '/^\s*privileged: true\s*$/d' /opt/iodine/docker-compose.yml
    # Insert cap_add block before the first 'devices:' key.
    # 0,/pattern/ is GNU sed syntax: applies the substitution only to the
    # first matching line so subsequent 'devices:' entries are not affected.
    sed -i '0,/^    devices:/{s/^    devices:/    cap_add:\n      - NET_ADMIN\n    devices:/}' \
        /opt/iodine/docker-compose.yml
    echo "  [OK]   privileged:true removed; cap_add:[NET_ADMIN] added"
else
    echo "  [OK]   iodine: already without privileged:true"
fi

# ── Step 2b: Enable CoreDNS query logging ────────────────────────────────────
# CoreDNS 'log' plugin writes query lines to stdout.
# Docker captures stdout; CrowdSec reads it via the docker datasource.
if grep -qE '^\s+log\s*$' /opt/iodine/Corefile; then
    echo "  [OK]   CoreDNS log plugin already present"
else
    # Append '    log' on the line after the catch-all zone opener '. {'
    sed -i '/^\. {$/a\    log' /opt/iodine/Corefile
    echo "  [OK]   'log' added to CoreDNS catch-all zone"
fi

# ── Step 2c: nftables UDP/53 rate limit + relax TCP/53 ───────────────────────
if grep -q 'udp dport 53 limit rate' /etc/nftables.conf; then
    echo "  [OK]   nftables UDP/53 rate limit already present"
else
    # Insert the UDP/53 rate-limit comment+rule before the first
    # 'udp dport 53 accept' line. awk fires only once (_done guard) so
    # subsequent matching lines (there are none, but safety) are untouched.
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
    # Relax the TCP/53 new-connection rate: 2/min is too tight for legitimate
    # resolvers that open a fresh TCP session per query.
    sed -i 's/tcp dport 53 ct state new limit rate over 2\/minute drop/tcp dport 53 ct state new limit rate over 30\/minute drop/' \
        /etc/nftables.conf
    echo "  [OK]   UDP/53 rate limit added; TCP/53 limit relaxed 2/min -> 30/min"
fi

# ── Step 2d: Write acquisition config ────────────────────────────────────────
# 'docker' datasource is built into CrowdSec -- no plugin required.
# MUST exist before first 'systemctl start crowdsec'.
mkdir -p /etc/crowdsec/acquis.d
cat > /etc/crowdsec/acquis.d/coredns-decoy.yaml << 'ACQUIS'
source: docker
container_name:
  - coredns
labels:
  type: coredns
ACQUIS
echo "  [OK]   Acquisition: /etc/crowdsec/acquis.d/coredns-decoy.yaml (docker source)"

# Auth.log: feeds crowdsecurity/sshd-logs (SSH brute-force detection).
# The linux + sshd collections parse this file to detect failed logins.
cat > /etc/crowdsec/acquis.d/sshd.yaml << 'ACQUIS'
filenames:
  - /var/log/auth.log
labels:
  type: syslog
ACQUIS
echo "  [OK]   Acquisition: /etc/crowdsec/acquis.d/sshd.yaml (auth.log)"

# kern.log: feeds crowdsecurity/iptables-logs (port-scan detection) and
# crowdsecurity/linux-lpe (privilege escalation / segfault detection).
# Requires the nftables log rule added to the input chain above.
cat > /etc/crowdsec/acquis.d/kernel.yaml << 'ACQUIS'
filenames:
  - /var/log/kern.log
labels:
  type: syslog
ACQUIS
echo "  [OK]   Acquisition: /etc/crowdsec/acquis.d/kernel.yaml (kern.log)"

# ── Step 2e: Write custom CoreDNS parser ─────────────────────────────────────
mkdir -p /etc/crowdsec/parsers/s01-parse
# Parser uses raw RE2 named groups instead of grok %{PATTERN:field} syntax.
# Reason: grok's HOSTNAME pattern ends with \.? which RE2 (no backtracking)
# greedily consumes the trailing dot, leaving nothing for the literal \. that
# follows -- causing every log line to fail silently. The multi-line grok
# >- YAML scalar also introduced double-spaces at line-fold boundaries.
# This single-line pattern is unambiguous and tested against actual CoreDNS output.
cat > /etc/crowdsec/parsers/s01-parse/coredns-decoy-logs.yaml << 'PARSER'
name: custom/coredns-decoy-logs
description: Parse CoreDNS query log lines from the decoy catch-all zone.
filter: "evt.Line.Labels.type == 'coredns'"
onsuccess: next_stage
nodes:
  - grok:
      # Pure grok %{MACRO:name} syntax -- CrowdSec's grokky does not support
      # raw (?P<name>...) regex named groups; they silently fail to capture.
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
# Valid BucketFactory fields only. 'enabled' is NOT a valid field and causes
# "field enabled not found in type leakybucket.BucketFactory" fatal error.
# To disable this scenario: rm the file and restart crowdsec.
mkdir -p /etc/crowdsec/scenarios
cat > /etc/crowdsec/scenarios/dns-decoy-scanner.yaml << SCENARIO
name: custom/dns-decoy-scanner
description: >
  External IP probing the DNS decoy zone.
  This server is not a public resolver; any external query is reconnaissance.
type: leaky
# Exclude queries for IODINE_DOMAIN -- those are legitimate tunnel users.
# IODINE_DOMAIN is a secret path; scanners will be banned long before
# they could discover it. Existing clients must never be caught by this.
# Single-line filter -- avoids YAML >- folding ambiguity.
# ! is the canonical negation operator in CrowdSec's expr-lang.
# CoreDNS routing already sends IODINE_DOMAIN queries to the forward zone
# (never reaching the catch-all log plugin), so this is a safety net.
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

# ── Install collections ───────────────────────────────────────────────────
# crowdsecurity/linux:     syslog + geoip + SSH brute-force (reads auth.log)
# crowdsecurity/iptables:  port-scan detection (reads kern.log CROWDSEC_DROP logs)
# crowdsecurity/linux-lpe: LPE detection -- pkexec CVE, segfault patterns (kern.log)
#
# Note: despite the name, crowdsecurity/iptables also works with nftables.
# The parser reads standard netfilter log format which both iptables and
# nftables produce. Our input chain logs dropped packets with prefix
# "CROWDSEC_DROP: " which writes to kern.log in the standard format.
echo "  Installing CrowdSec collections..."
cscli collections install \
    crowdsecurity/linux \
    crowdsecurity/iptables \
    crowdsecurity/linux-lpe 2>/dev/null \
    && echo "  [OK]   Collections installed" \
    || echo "  NOTE:  Collection install had warnings -- check cscli collections list"

# Restart so newly installed parsers and scenarios are loaded.
# This restart is safe -- LAPI was confirmed active above, the bouncer
# install gate (Step 4) re-checks is-active immediately after.
systemctl restart crowdsec
sleep 5
systemctl is-active crowdsec >/dev/null 2>&1 \
    || die "CrowdSec failed to restart after collections install. Check: journalctl -u crowdsec -n 40 --no-pager"

# ── Step 4: Install bouncer AFTER LAPI confirmed running ─────────────────────
# Bouncer post-install auto-generates API key AND immediately starts service.
# "stream halted" crash loop guaranteed if LAPI is down at install time.
systemctl is-active crowdsec >/dev/null 2>&1 \
    || die "CrowdSec LAPI not running -- cannot install bouncer safely."

if ! dpkg -l crowdsec-firewall-bouncer-nftables 2>/dev/null | grep -q '^ii'; then
    apt-get install -y crowdsec-firewall-bouncer-nftables
    echo "  [OK]   crowdsec-firewall-bouncer-nftables installed"
else
    echo "  [OK]   crowdsec-firewall-bouncer-nftables already installed"
fi

# ── Step 5: Patch bouncer config ─────────────────────────────────────────────
BOUNCER_CONF=/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml
[ -f "$BOUNCER_CONF" ] || die "Bouncer config not found at $BOUNCER_CONF"

# Patch only the fields we need. Leave everything else as the package installed
# it -- rewriting the entire config has caused routing regressions.

# Force nftables mode. Package default can be ipset, which creates iptables
# rules not evaluated by the nftables kernel path -- bans appear in LAPI
# but nothing is ever blocked.
sed -i 's/^mode:.*/mode: nftables/' "$BOUNCER_CONF"

# Ensure set-only: false under nftables.ipv4 (and ipv6 if present).
# 'set-only: true' makes the bouncer manage only the IP set and skip creating
# a hooked chain -- bans land in the set but no nftables rule ever drops the
# traffic.  'nftables_hooks' is NOT a valid config key and is silently ignored;
# the correct mechanism is set-only: false, which instructs the bouncer to own
# a chain with 'type filter hook input priority -1'.
# Since we now define that chain statically in nftables.conf, the bouncer
# detects the pre-existing structure and reuses it.
sed -i '/set-only:/ s/set-only:.*/set-only: false/' "$BOUNCER_CONF"
# If set-only is absent entirely, insert it after each 'enabled: true' under nftables:
# (idempotent -- sed does nothing if set-only already exists after above pass)
sed -i '/^nftables:/,/^[^ ]/{/enabled: true/a\    set-only: false
}' "$BOUNCER_CONF" 2>/dev/null || true

# Disable IPv6 (off system-wide via sysctl).
# The range /ipv6:/,/enabled:/ selects from the ipv6: key to the first
# 'enabled:' line beneath it -- replacing 'enabled: true' only in that range.
# This is resilient to indentation changes between CrowdSec package releases.
sed -i '/^[[:space:]]*ipv6:/,/enabled:/{s/enabled: true/enabled: false/}' "$BOUNCER_CONF"

if grep -q 'mode: nftables' "$BOUNCER_CONF" && grep -q 'set-only: false' "$BOUNCER_CONF"; then
    echo "  [OK]   Bouncer patched: mode=nftables, set-only=false, IPv6 off"
else
    echo "  [WARN] Bouncer patch incomplete -- check manually"
fi

# Bouncer post-install registers its key automatically when LAPI is up.
# Only add manually if that step somehow did not run.
if ! cscli bouncers list 2>/dev/null | grep -qE 'crowdsec-firewall-bouncer|nftables-bouncer'; then
    echo "  Registering bouncer API key with LAPI..."
    BOUNCER_KEY="$(cscli bouncers add nftables-bouncer -o raw 2>/dev/null)"         || die "Failed to register bouncer with LAPI."
    [ -n "$BOUNCER_KEY" ] || die "Got empty bouncer key."
    sed -i "s|^api_key:.*|api_key: ${BOUNCER_KEY}|" "$BOUNCER_CONF"
    echo "  [OK]   nftables-bouncer API key registered"
else
    echo "  [OK]   Bouncer API key already registered (post-install did it)"
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
# Apply: CoreDNS log plugin, iodine privilege drop, nftables UDP/53 rate limit.
# Do NOT flush conntrack -- active WireGuard DNAT entries must survive.
echo "  Recreating CoreDNS + iodine containers..."
docker compose -f /opt/iodine/docker-compose.yml up -d --force-recreate coredns iodine
echo "  [OK]   CoreDNS + iodine recreated"

echo "  Reloading nftables (conntrack NOT flushed -- intentional)..."
systemctl restart nftables
echo "  [OK]   nftables reloaded"

# Restart bouncer immediately after nftables reload.
# 'systemctl restart nftables' reloads /etc/nftables.conf.  The CrowdSec table
# structure (chain + set) is now defined there, so the infrastructure survives.
# However the bouncer holds in-memory state about which IPs are in the set; a
# restart forces it to re-poll LAPI and re-apply all current ban decisions into
# the (freshly loaded) set.  Without this, the set exists but is empty until
# the bouncer's next automatic poll cycle (default 10 s) -- during which ALL
# bans are silently unenforced.
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
cscli bouncers list 2>/dev/null | grep -qE 'crowdsec-firewall-bouncer|nftables-bouncer' \
    && cs_ok  "bouncer registered with LAPI"      || cs_fail "bouncer NOT registered"
# Use exact table lookup -- nft list tables grep can false-negative if
# the bouncer hasn't completed its first poll cycle yet after install.
nft list table ip crowdsec >/dev/null 2>&1 \
    && cs_ok  "nftables crowdsec table present (ip)" \
    || cs_fail "nftables crowdsec table missing -- check bouncer: journalctl -u crowdsec-firewall-bouncer -n 20"
# Verify the chain actually has a netfilter hook.  A hookless chain means the
# set exists but no rule ever DROP-tests against it -- bans are invisible to traffic.
nft list chain ip crowdsec crowdsec_chain 2>/dev/null | grep -q 'hook input' \
    && cs_ok  "CrowdSec chain has input hook (priority -1) -- bans enforced" \
    || cs_fail "CrowdSec chain is MISSING its input hook -- bans will NOT block traffic; check bouncer set-only setting"
grep -qE '^\s+log\s*$' /opt/iodine/Corefile \
    && cs_ok  "CoreDNS log plugin active"         || cs_fail "CoreDNS log plugin MISSING"
! grep -q 'privileged: true' /opt/iodine/docker-compose.yml \
    && cs_ok  "iodine privilege dropped"          || cs_fail "iodine: still has privileged:true"
grep -q 'udp dport 53 limit rate' /etc/nftables.conf \
    && cs_ok  "nftables UDP/53 rate limit"        || cs_fail "nftables UDP/53 rate limit MISSING"
cscli scenarios list 2>/dev/null | grep -q 'dns-decoy-scanner' \
    && cs_ok  "DNS decoy scenario loaded"         || cs_fail "DNS decoy scenario NOT loaded -- check: journalctl -u crowdsec -n 20"
[ -f /etc/crowdsec/acquis.d/coredns-decoy.yaml ] \
    && cs_ok  "CrowdSec acquisition config"       || cs_fail "Acquisition config MISSING"
grep -q 'source: docker' /etc/crowdsec/acquis.d/coredns-decoy.yaml \
    && cs_ok  "Acquisition uses docker source"    || cs_fail "Acquisition source wrong"
cscli parsers list 2>/dev/null | grep -q 'coredns-decoy-logs' \
    && cs_ok  "CoreDNS parser loaded"             || cs_fail "CoreDNS parser NOT loaded -- check: journalctl -u crowdsec -n 20"
grep -q 'apply_on: message' /etc/crowdsec/parsers/s01-parse/coredns-decoy-logs.yaml \
    && cs_ok  "Parser apply_on correct"           || cs_fail "Parser apply_on wrong -- must be message"

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
echo "  Add a remote node (jumpbox, reverse proxy) to THIS LAPI:"
echo "    ON THIS NODE:   sudo cscli machines add <node-name> --auto"
echo "    ON REMOTE NODE: sudo cscli lapi register --url http://${SERVER_IP}:8080 --token <token>"
echo "                    sudo systemctl restart crowdsec"
echo "                    sudo apt-get install -y crowdsec-firewall-bouncer-nftables"
echo "    Remote bouncers MUST point at THIS LAPI, not their own local one."
echo ""
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

# ── Post-install interactive menu ───────────────────────────────────────────
# build_and_show_menu() is defined at the top of the script alongside
# load_existing_config(). It creates temp files for each section, runs the
# interactive select loop, and cleans up on exit. Called here after a full
# install, and also called directly (via option 1 in the existing-install
# check) when the user just wants to re-view their QR codes without reinstalling.
build_and_show_menu
