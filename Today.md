# Update 2024-10-22
## CVE-2024-23334
 aiohttp is an asynchronous HTTP client/server framework for asyncio and Python. When using aiohttp as a web server and configuring static routes, it is necessary to specify the root path for static files. Additionally, the option 'follow_symlinks' can be used to determine whether to follow symbolic links outside the static root directory. When 'follow_symlinks' is set to True, there is no validation to check if reading a file is within the root directory. This can lead to directory traversal vulnerabilities, resulting in unauthorized access to arbitrary files on the system, even when symlinks are not present. Disabling follow_symlinks and using a reverse proxy are encouraged mitigations. Version 3.9.2 fixes this issue.

- [https://github.com/wizarddos/CVE-2024-23334](https://github.com/wizarddos/CVE-2024-23334) :  ![starts](https://img.shields.io/github/stars/wizarddos/CVE-2024-23334.svg) ![forks](https://img.shields.io/github/forks/wizarddos/CVE-2024-23334.svg)


## CVE-2024-1014
 Uncontrolled resource consumption vulnerability in SE-elektronic GmbH E-DDC3.3 affecting versions 03.07.03 and higher. An attacker could interrupt the availability of the administration panel by sending multiple ICMP packets.

- [https://github.com/holypryx/CVE-2024-10140](https://github.com/holypryx/CVE-2024-10140) :  ![starts](https://img.shields.io/github/stars/holypryx/CVE-2024-10140.svg) ![forks](https://img.shields.io/github/forks/holypryx/CVE-2024-10140.svg)


## CVE-2019-15107
 An issue was discovered in Webmin &lt;=1.920. The parameter old in password_change.cgi contains a command injection vulnerability.

- [https://github.com/CyberTuz/CVE-2019-15107_detection](https://github.com/CyberTuz/CVE-2019-15107_detection) :  ![starts](https://img.shields.io/github/stars/CyberTuz/CVE-2019-15107_detection.svg) ![forks](https://img.shields.io/github/forks/CyberTuz/CVE-2019-15107_detection.svg)


## CVE-2018-0101
 A vulnerability in the Secure Sockets Layer (SSL) VPN functionality of the Cisco Adaptive Security Appliance (ASA) Software could allow an unauthenticated, remote attacker to cause a reload of the affected system or to remotely execute code. The vulnerability is due to an attempt to double free a region of memory when the webvpn feature is enabled on the Cisco ASA device. An attacker could exploit this vulnerability by sending multiple, crafted XML packets to a webvpn-configured interface on the affected system. An exploit could allow the attacker to execute arbitrary code and obtain full control of the system, or cause a reload of the affected device. This vulnerability affects Cisco ASA Software that is running on the following Cisco products: 3000 Series Industrial Security Appliance (ISA), ASA 5500 Series Adaptive Security Appliances, ASA 5500-X Series Next-Generation Firewalls, ASA Services Module for Cisco Catalyst 6500 Series Switches and Cisco 7600 Series Routers, ASA 1000V Cloud Firewall, Adaptive Security Virtual Appliance (ASAv), Firepower 2100 Series Security Appliance, Firepower 4110 Security Appliance, Firepower 9300 ASA Security Module, Firepower Threat Defense Software (FTD). Cisco Bug IDs: CSCvg35618.

- [https://github.com/MikeHorn-git/CVE-2018-0101](https://github.com/MikeHorn-git/CVE-2018-0101) :  ![starts](https://img.shields.io/github/stars/MikeHorn-git/CVE-2018-0101.svg) ![forks](https://img.shields.io/github/forks/MikeHorn-git/CVE-2018-0101.svg)

