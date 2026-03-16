# VPN over port 53

WireGuard VPN disguised as DNS traffic, iodine DNS tunnel fallback, and CrowdSec DNS decoy as a fail2ban.

Three folders, each building on the last — from a plain WireGuard setup to a fully disguised VPN that survives networks that block everything except DNS.


* * *

## Part 1 — WireGuard

[`1_easy-wg-quick`](./../../1_easy-wg-quick)

A basic WireGuard server using easy-wg-quick. No UI, no daemon — just flat config files you can read and commit.

- Generates client and server configs

- Works on any Linux host with `wireguard-tools`

- Start here if WireGuard is new to you


* * *

## Part 2 — DNS Tunnel

[`2_iodine-on-docker`](./../../2_iodine-on-docker)

CoreDNS + iodined running in Docker. Encodes arbitrary traffic as DNS queries so it passes through networks that block everything else.

- Edit the `Corefile` with your domain, edit `docker-compose.yml` with your password and domain

- Connect from a client with `sudo iodine -L0 -f -P <password> <server_ip> t.<your_domain.whatever>`

- iodine provides no encryption — this is plain text


* * *

## Part 3 — The Full Stack

[`3_wireguard-iodine-crowdsec/`](./../../3_wireguard-iodine-crowdsec)

One script that installs and puts everything together.

- Continues the CoreDNS + iodined in Docker — keeping iodine as a fallback for carriers that modify DNS traffic

- WireGuard on `:51820` — redirected from `:53` by nftables payload matching

- CrowdSec watching CoreDNS logs — 3 DNS probes in 60 seconds triggers a kernel-level ban

- nftables NAT masquerade — all outbound traffic exits as the server's IP, so any website you visit sees the server address, not yours

```bash
sudo bash VPN-over-port-53.sh
```


* * *

## Step 4 — VPN Inside a Website

[`4_hidden-vpn-that-looks-like-a-website`](./../../../hidden-vpn-that-looks-like-a-website)

If your carrier intercepts port 53 and iodine is not enough, this is the final escalation. 

**A VLESS tunnel hidden inside a real HTTPS website on port 443** — the only thing DPI can see is a domain name.

- nginx serves a convincing tech-company decoy site

- XRAY handles the WebSocket tunnel at a hidden path — only reachable with the right client config

- Let's Encrypt certificate via certbot — looks identical to any other HTTPS site

- Runs standalone on Debian/Ubuntu or fully dockerized with a browser terminal (no SSH needed)

```bash
# Docker
cp .env.example .env  # set TTYD_CREDENTIAL=user:password
docker compose up -d  # open http://<server-ip>:7681
```


* * *

## Why VPN over port 53

Port 53 is DNS — most networks must leave it open or software using the internet tends to stops working. Most firewalls that block VPNs do not block port 53. This uses that gap.

The catch: some firewalls do DPI and can see those DNS packets are not correct and drop them. Some mobile carriers run a transparent DNS proxy that intercepts all UDP/53 traffic. iodine is the fallback — it sends real DNS queries that pass straight through.
