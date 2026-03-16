# CoreDNS carrying IodineD in Docker

CoreDNS alongside IodineD within a Dockerized enclave.

> [!IMPORTANT]
> Dual-purpose DNS façade—one that ostensibly resolves benign queries while surreptitiously encapsulating traffic through a GRE-like tunneling mechanism over DNS.


* * *

![DNS Requests using IodineD to escape](https://raw.githubusercontent.com/MarcusHoltz/marcusholtz.github.io/refs/heads/main/assets/img/header/header--network--iodine-dns-tunnel-requests-escape.jpg "DNS Requests using IodineD to escape")

* * *

## Step 1. Edit Corefile

Edit the [Corefile](./Corefile) for CoreDNS and put the nameserver you're using for Iodine in there.

```ini
t.<your_domain_here>.com {
```

> You can find more information on [Iodine's Github](https://github.com/yarrick/iodine?tab=readme-ov-file#how-to-use).


* * *

## Step 2. Edit docker-compose.yml

Edit your [docker-compose.yml](./docker-compose.yml) file to change:

- your password 

- your domain


```yaml
Your32CharPassword12345678901234 10.53.53.1 t.<your_domain.whatever>
```


* * *

## Step 3. Run docker

With everything set, you can now bring up our docker stack.

```
docker compose down && docker ps && docker compose up -d --force-recreate && docker compose logs -f
```


* * *

## Step 4. Client Connect

To test Iodine, get to another computer. Try and use lazy connect to allow for longer connections, aka laggy connections.

```
sudo iodine -L0 -f -P Your32CharPassword123456789012345 <the_server_IP_to_connect_to> t.<your_domain.whatever> || dig NS t.<your_domain.whatever> @8.8.8.8
```


* * *

## Step 5. Transfer 

### Netcat (nc)

#### What it is:

netcat is a networking tool that reads and writes data across network connections, allowing data transfer between different computers.

#### How it works:

##### On Receiver:

```bash
nc -l -p 1234
```

###### On Sender:

```bash
echo "hello" | nc <your_10.55.55.2_iodine_address> 1234
```

> netcat establishes a network connection between two machines.

#### Send a file from Computer A to Computer B:

##### On Computer B (receiver)

```bash
nc -l -p 1234 > received_file.txt
```

###### On Computer A (sender)
```bash
nc  <your_10.55.55.1_iodine_address> 1234 < file.txt
```

* * *
* * *


## After Setup

With the tunnel example down, we can move on to [3_wireguard-iodine-crowdsec](./../../../3_wireguard-iodine-crowdsec) example.

