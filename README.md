# ISEC-603-Padding-Oracle
 

Padding Oracle Demo

Needed Libraries
pip install cryptography

This demo showcases how the cryptography of the Padding Oracle attack works.
To Run
python oracle.py
enter your message
then run
python attack.py

POODLE demo

This demo is for the network part of the poodle attack you need to run it on a linux machine with docker you can download docker with the provided commands.
This demo will show how a rogue router can filter and block higher versions of TLS forcing the connection to downgrade otherwise suffer from a DoS attack.
This demo only shows the downgrade part to see the padding oracle attack see that demo, the code shows you were you'd implement the full attack.

Install Docker

sudo apt-get update
sudo apt-get install ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc

# Add the repository to Apt sources:
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update

sudo apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin



Once docker is installed run the run-fw-ex-2.sh file in the docker folder
run docker file
run-fw-ex-2.sh

Once docker is running create three terminals and go into theses three docker containers and run theses commands for each containers
This is to properly set up routing and setting so the python files run correctly
Router

Login to router with
sudo docker exec -it router-10.29.107.11-fw bash

iptables -A FORWARD -p tcp --dport 65434 -j NFQUEUE --queue-num 0
iptables -A FORWARD -p tcp --sport 65434 -j NFQUEUE --queue-num 0

apt-get update

apt-get install build-essential python3-dev libnetfilter-queue-dev
python3 -m pip install netfilterqueue
python3 -m pip install pyshark

apt install wireshark
apt install tshark


pico mitm.py
Paste mitm.py into file

run with 
python3 mitm.py

Host1

Login to host1 with
sudo docker exec -it host1-192.168.90.5-fw bash

pico /etc/ssl/openssl.cnf

Add this line at the top:

openssl_conf = openssl_init


And add these lines at the end:

[openssl_init]
ssl_conf = ssl_sect

[ssl_sect]
system_default = system_default_sect

[system_default_sect]
CipherString = DEFAULT@SECLEVEL=0


pico client.py
Paste client.py into file

run with 
python3 client.py

Other-User

Login to other user with
sudo docker exec -it other-user-10.29.107.24-fw bash

pico /etc/ssl/openssl.cnf

Add this line at the top:

openssl_conf = openssl_init


And add these lines at the end:

[openssl_init]
ssl_conf = ssl_sect

[ssl_sect]
system_default = system_default_sect

[system_default_sect]
CipherString = DEFAULT@SECLEVEL=0


ip route add 192.168.90.0/24 via 10.29.107.11


# Generate the private key
openssl genpkey -algorithm RSA -out server.key -pkeyopt rsa_keygen_bits:2048

# Generate the self-signed certificate (valid for 365 days)
openssl req -new -key server.key -out server.csr
openssl x509 -req -in server.csr -signkey server.key -out server.crt -days 365


pico server.py
Paste server.py into file

run with 
python3 server.py