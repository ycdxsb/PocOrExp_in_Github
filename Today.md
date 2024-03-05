# Update 2024-03-05
## CVE-2024-24760
 mailcow is a dockerized email package, with multiple containers linked in one bridged network. A security vulnerability has been identified in mailcow affecting versions &lt; 2024-01c. This vulnerability potentially allows attackers on the same subnet to connect to exposed ports of a Docker container, even when the port is bound to 127.0.0.1. The vulnerability has been addressed by implementing additional iptables/nftables rules. These rules drop packets for Docker containers on ports 3306, 6379, 8983, and 12345, where the input interface is not `br-mailcow` and the output interface is `br-mailcow`.

- [https://github.com/killerbees19/CVE-2024-24760](https://github.com/killerbees19/CVE-2024-24760) :  ![starts](https://img.shields.io/github/stars/killerbees19/CVE-2024-24760.svg) ![forks](https://img.shields.io/github/forks/killerbees19/CVE-2024-24760.svg)


## CVE-2024-21762
 A out-of-bounds write in Fortinet FortiOS versions 7.4.0 through 7.4.2, 7.2.0 through 7.2.6, 7.0.0 through 7.0.13, 6.4.0 through 6.4.14, 6.2.0 through 6.2.15, 6.0.0 through 6.0.17, FortiProxy versions 7.4.0 through 7.4.2, 7.2.0 through 7.2.8, 7.0.0 through 7.0.14, 2.0.0 through 2.0.13, 1.2.0 through 1.2.13, 1.1.0 through 1.1.6, 1.0.0 through 1.0.7 allows attacker to execute unauthorized code or commands via specifically crafted requests

- [https://github.com/tr1pl3ight/CVE-2024-21762-POC](https://github.com/tr1pl3ight/CVE-2024-21762-POC) :  ![starts](https://img.shields.io/github/stars/tr1pl3ight/CVE-2024-21762-POC.svg) ![forks](https://img.shields.io/github/forks/tr1pl3ight/CVE-2024-21762-POC.svg)


## CVE-2023-34845
 ** DISPUTED ** Bludit v3.14.1 was discovered to contain an arbitrary file upload vulnerability in the component /admin/new-content. This vulnerability allows attackers to execute arbitrary web scripts or HTML via uploading a crafted SVG file. NOTE: the product's security model is that users are trusted by the administrator to insert arbitrary content (users cannot create their own accounts through self-registration).

- [https://github.com/r4vanan/CVE-2023-34845](https://github.com/r4vanan/CVE-2023-34845) :  ![starts](https://img.shields.io/github/stars/r4vanan/CVE-2023-34845.svg) ![forks](https://img.shields.io/github/forks/r4vanan/CVE-2023-34845.svg)


## CVE-2010-4669
 The Neighbor Discovery (ND) protocol implementation in the IPv6 stack in Microsoft Windows XP, Windows Server 2003, Windows Vista, Windows Server 2008, and Windows 7 allows remote attackers to cause a denial of service (CPU consumption and system hang) by sending many Router Advertisement (RA) messages with different source addresses, as demonstrated by the flood_router6 program in the thc-ipv6 package.

- [https://github.com/wrong-commit/CVE-2010-4669](https://github.com/wrong-commit/CVE-2010-4669) :  ![starts](https://img.shields.io/github/stars/wrong-commit/CVE-2010-4669.svg) ![forks](https://img.shields.io/github/forks/wrong-commit/CVE-2010-4669.svg)

