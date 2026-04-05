# Breaking Access Control in Home Wireless Mesh Networks
Do you know your home mesh network can be hacked? Check out!

# Introduction
We discovered novel attacks for home wireless mesh networks. Simply speaking, the control protocols over backhaul wireless links can be tampered with. As a result, an attacker who has a (fronthaul) Wi-Fi passphrase can obtain root shells on access points, and/or steal fronthaul/backhaul Wi-Fi passphrases. Obtaining a root shell allows an attacker to capture/inject wireless packets, to change Wi-Fi passphrases to attacker-controlled values, among others. Stealing fronthaul/backhaul Wi-Fi passphrases allows an attacker to evade network access revocations. 

# Publication
Untangling the Knot: Breaking Access Control in Home Wireless Mesh Networks [[PDF]](https://www.cs.ucr.edu/%7Ezhiyunq/pub/ccs24_wireless_mesh.pdf) \
Xin’an Zhou, Qing Deng, Juefei Pu, Keyu Man, Zhiyun Qian, Srikanth V. Krishnamurthy \
Proceedings of the 2024 ACM SIGSAC Conference on Computer and Communications Security. 

Fallen Tower of Babel: Rooting Wireless Mesh Networks by Abusing Heterogeneous Control Protocols [[Link]](https://www.blackhat.com/us-24/briefings/schedule/index.html#fallen-tower-of-babel-rooting-wireless-mesh-networks-by-abusing-heterogeneous-control-protocols-39898) \
Xin’an Zhou, Zhiyun Qian, Juefei Pu, Qing Deng, Srikanth V. Krishnamurthy, Keyu Man \
Black Hat USA 2024

# Affected Vendors/Products
[Netgear Orbi](https://www.netgear.com/home/wifi/mesh/orbi/) \
[ASUS AiMesh](https://www.asus.com/microsite/aimesh/en/index.html) 

| Vendor  | Model  | Version  | Vulnerable?  | Patched?  |
|---|---|---|---|---|
| ASUS  | RT-BE96U  | <= 3.0.0.6.102_32882  | Yes  |  Yes (3.0.0.6.102_34488) |
| ASUS  | RT-AC68P  | <= 3.0.0.4.386_51668  | Yes  |  Yes (3.0.0.4.386_51685) |
| ASUS  | RT-AX57  | <= 3.0.0.4.386_52294  | Yes  | Yes (3.0.0.4.386_52303)  |
| ASUS  | RT-AX88U  | <= 3.0.0.4.388_24198  | Yes  | Yes (3.0.0.4.388_24209)  |
| ASUS  | RT-AX86 Series(RT-AX86U/RT-AX86S)  | <= 3.0.0.4.388_24231  | Yes  | Yes (3.0.0.4.388_24243)  |
| ASUS  | RT-AC86U  | <= 3.0.0.4.386_51915  | Yes  | Yes (3.0.0.4.386_51925)  |
| ASUS  | RT-AX55  | <= 3.0.0.4.386_52294  | Yes  | Yes (3.0.0.4.386_52303)  |
| ASUS  | RT-AX88U  | <= 3.0.0.4.388_24198  | Yes  | Yes (3.0.0.4.388_24209)  |
| ASUS  | XT8  | <= 3.0.0.4.388_24609  | Yes  | Yes (3.0.0.4.388_24621) |
| ASUS  | RT-AC66U B1  | <= 3.0.0.4.386_51668 | Yes  | Yes (3.0.0.4.386_51685) |
| ASUS  | AiMesh AC1900 WiFi System (RT-AC67U 2 Pack)  | <= 3.0.0.4.386_51668 | Yes  | Yes (3.0.0.4.386_51685) |
| ASUS  | RT-AC68U  | <= 3.0.0.4.386_51668 | Yes  | Yes (3.0.0.4.386_51685) |
| ASUS  | RP-AC1900  | <= 3.0.0.4.386_51668 | Yes  | Yes (3.0.0.4.386_51685) |
| ASUS  | ROG Rapture GT-BE98 Pro  | <= 3.0.0.6.102_32882 | Yes  | Yes (3.0.0.6.102_34491) |
| ASUS  | RT-AC68R  | <= 3.0.0.4.386_51668 | Yes  | Yes (3.0.0.4.386_51685) |
| ASUS  | RT-AC2900  | <= 3.0.0.4.386_51915 | Yes  | Yes (3.0.0.4.386_51925)|
| ASUS  | RT-AC1900P  | <= 3.0.0.4.386_51668 | Yes  | Yes (3.0.0.4.386_51685)|
| ASUS  | RT-AC1750 B1  | <= 3.0.0.4.386_51668 | Yes  | Yes (3.0.0.4.386_51685) |
| ASUS  | RT-AC1900U  | <= 3.0.0.4.386_51668 | Yes  | Yes (3.0.0.4.386_51685)|
| ASUS  | RT-AC1900  | <= 3.0.0.4.386_51668 | Yes  | Yes (3.0.0.4.386_51685) |
| ASUS  | ASUS ExpertWiFi EBR63  | <= 3.0.0.6.102_32645 | Yes  | Yes (3.0.0.6.102_44544) |
| ASUS  | RT-AC68UF  | <= 3.0.0.4.386_51668 | Yes  | Yes (3.0.0.4.386_51685) |

[TP-Link Deco](https://www.tp-link.com/us/deco-mesh-wifi/product-family/) \
[Linksys](https://store.linksys.com/shop/shop-home/whole-home-mesh-wifi/) \
[Wyze](https://www.wyze.com/products/wyze-mesh-router-pro)

| Vendor  | Model  | Version  | Vulnerable?  | Patched?  |
|---|---|---|---|---|
| Wyze Wi-Fi 6E Mesh Router Pro  | AXE5400  | <= 1.0.1.109  | Yes  |  Yes (1.0.1.121 (May 7, 2024)) |

[AmpliFi](https://amplifi.com/) \
[Wi-Fi EasyMesh Standard](https://www.wi-fi.org/discover-wi-fi/wi-fi-easymesh)

Note that the two types of security flaws we found are general, impacting the whole Wi-Fi mesh industry. If you don't find your brand of choice above, it is still possible that your mesh network is vulnerable. 

# Write-ups
[ASUS AiMesh Attack](./ASUS/)

[Linksys Mesh Network Attack](./Linksys/)

[Wyze Mesh Network Attack](./Wyze/)

[EasyMesh Attack](./EasyMesh/)

[TP-Link Attack](./TP-Link/)

# Open-source Timeline
The full exploitation code will be available before the ACM CCS 2024 publication date (10/2024). ~~At this stage (08/2024), we still want to give vendors and users more time to deploy patches.~~

(11/28/2024) TP-Link Mesh Network Attack is fully available! See here: [TP-Link Attack](./TP-Link/)

(10/9/2024) EasyMesh Attack is fully available! See here: [EasyMesh Attack](./EasyMesh/)

(10/6/2024) Wyze Mesh Network Attack is fully available! See here: [Wyze Mesh Network Attack](./Wyze/)

(10/5/2024) Linksys Mesh Network Attack is fully available! See here: [Linksys Mesh Network Attack](./Linksys/)

(10/1/2024) ASUS AiMesh Attack is fully available! See here: [ASUS AiMesh Attack](./ASUS/)
