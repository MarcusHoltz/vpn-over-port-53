# WireGuard VPN Setup

We're going to first deploy Wireguard. This is the best example of a tunnel connection.

![easy-wg-quick a secure vpn tunneling smoothie drink](https://raw.githubusercontent.com/MarcusHoltz/marcusholtz.github.io/refs/heads/main/assets/img/posts/easy-wg-quick-smoothie.png)


* * * 

## wg-easy

The best all-in-one WireGuard solution is probably [wg-easy](https://wg-easy.github.io/wg-easy/latest/examples/tutorials/basic-installation/). It is a single Docker container, has a built-in web UI, and zero extra dependencies.

> [!TIP]
> But we're not going to use that ...


* * *

## easy-wg-quick

The best choice when you just want a quick plain-text config — [easy-wg-quick](https://github.com/burghardt/easy-wg-quick). It has no daemon, no UI, no database - just some text files.

- Config is flat files you can read, diff, and commit

- Adding a new user takes seconds

- Works on any Linux host with `wireguard-tools`


* * *

### Start here

Open the Holtzweb easy-wg-quick interactive guide in any browser:

[easy-wg-quick-guide.html](./easy-wg-quick-guide.html)

Or online: [https://blog.holtzweb.com/.../easy-wg-quick-guide.html](https://blog.holtzweb.com/assets/html/easy-wg-quick-guide.html)


## Setup complete

Make sure you have all your ports open, and pointed to the right machine - you should now have a working Wireguard connection!


* * *
* * *

# Part 2: CoreDNS carrying IodineD in Docker

With the tunnel example down, we can move on to [2_docker-iodine](../2_docker-iodine) example.

