# WireGuard VPN Setup

We're going to first deploy Wireguard.

![easy-wg-quick a secure vpn tunneling smoothie drink](https://raw.githubusercontent.com/MarcusHoltz/marcusholtz.github.io/refs/heads/main/assets/img/posts/easy-wg-quick-smoothie.png)

This is the best example of a VPN/tunnel connection.


* * * 

## wg-easy

The best all-in-one WireGuard solution is probably [wg-easy](https://wg-easy.github.io/wg-easy/latest/examples/tutorials/basic-installation/). 

- Has a built-in web UI

- Everything managed from docker and web UI

> [!TIP]
> But we're not going to use that ...


* * *

## easy-wg-quick

The best choice when you just want a quick plain-text config — [easy-wg-quick](https://github.com/burghardt/easy-wg-quick). 

- No daemon, no UI, no database - just some text files.

- Works on any Linux host with `wireguard-tools`


* * *

### --> Start here <--

**Open** the [Holtzweb easy-wg-quick interactive guide](./easy-wg-quick-guide.html) in any browser:

- [easy-wg-quick-guide.html](./easy-wg-quick-guide.html)

Or online: [https://blog.holtzweb.com/.../easy-wg-quick-guide.html](https://blog.holtzweb.com/assets/html/easy-wg-quick-guide.html)


* * *

## Setup complete

Make sure you have your wireguard port open, and pointed to the right machine - you should now have a working Wireguard connection!


* * *
* * *

# Part 2: CoreDNS carrying IodineD in Docker

With the tunnel example down, we can move on to [2_docker-iodine](../2_docker-iodine) example.

