# Update 2024-09-10
## CVE-2024-37713
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/fullbbadda1208/CVE-2024-37713](https://github.com/fullbbadda1208/CVE-2024-37713) :  ![starts](https://img.shields.io/github/stars/fullbbadda1208/CVE-2024-37713.svg) ![forks](https://img.shields.io/github/forks/fullbbadda1208/CVE-2024-37713.svg)


## CVE-2024-34831
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/enzored/CVE-2024-34831](https://github.com/enzored/CVE-2024-34831) :  ![starts](https://img.shields.io/github/stars/enzored/CVE-2024-34831.svg) ![forks](https://img.shields.io/github/forks/enzored/CVE-2024-34831.svg)


## CVE-2024-29269
 An issue discovered in Telesquare TLR-2005Ksh 1.0.0 and 1.1.4 allows attackers to run arbitrary system commands via the Cmd parameter.

- [https://github.com/hack-with-rohit/CVE-2024-29269-RCE](https://github.com/hack-with-rohit/CVE-2024-29269-RCE) :  ![starts](https://img.shields.io/github/stars/hack-with-rohit/CVE-2024-29269-RCE.svg) ![forks](https://img.shields.io/github/forks/hack-with-rohit/CVE-2024-29269-RCE.svg)


## CVE-2024-23334
 aiohttp is an asynchronous HTTP client/server framework for asyncio and Python. When using aiohttp as a web server and configuring static routes, it is necessary to specify the root path for static files. Additionally, the option 'follow_symlinks' can be used to determine whether to follow symbolic links outside the static root directory. When 'follow_symlinks' is set to True, there is no validation to check if reading a file is within the root directory. This can lead to directory traversal vulnerabilities, resulting in unauthorized access to arbitrary files on the system, even when symlinks are not present. Disabling follow_symlinks and using a reverse proxy are encouraged mitigations. Version 3.9.2 fixes this issue.

- [https://github.com/s4botai/CVE-2024-23334-PoC](https://github.com/s4botai/CVE-2024-23334-PoC) :  ![starts](https://img.shields.io/github/stars/s4botai/CVE-2024-23334-PoC.svg) ![forks](https://img.shields.io/github/forks/s4botai/CVE-2024-23334-PoC.svg)


## CVE-2024-4505
 A vulnerability, which was classified as critical, was found in Ruijie RG-UAC up to 20240428. This affects an unknown part of the file /view/IPV6/ipv6Addr/ip_addr_add_commit.php. The manipulation of the argument prelen/ethname leads to os command injection. It is possible to initiate the attack remotely. The exploit has been disclosed to the public and may be used. The identifier VDB-263109 was assigned to this vulnerability. NOTE: The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/0xbhsu/CVE-2024-45058](https://github.com/0xbhsu/CVE-2024-45058) :  ![starts](https://img.shields.io/github/stars/0xbhsu/CVE-2024-45058.svg) ![forks](https://img.shields.io/github/forks/0xbhsu/CVE-2024-45058.svg)


## CVE-2023-38408
 The PKCS#11 feature in ssh-agent in OpenSSH before 9.3p2 has an insufficiently trustworthy search path, leading to remote code execution if an agent is forwarded to an attacker-controlled system. (Code in /usr/lib is not necessarily safe for loading into ssh-agent.) NOTE: this issue exists because of an incomplete fix for CVE-2016-10009.

- [https://github.com/0xxnum/CVE-2023-38408](https://github.com/0xxnum/CVE-2023-38408) :  ![starts](https://img.shields.io/github/stars/0xxnum/CVE-2023-38408.svg) ![forks](https://img.shields.io/github/forks/0xxnum/CVE-2023-38408.svg)


## CVE-2022-0944
 Template injection in connection test endpoint leads to RCE in GitHub repository sqlpad/sqlpad prior to 6.10.1.

- [https://github.com/shhrew/CVE-2022-0944](https://github.com/shhrew/CVE-2022-0944) :  ![starts](https://img.shields.io/github/stars/shhrew/CVE-2022-0944.svg) ![forks](https://img.shields.io/github/forks/shhrew/CVE-2022-0944.svg)


## CVE-2020-1938
 When using the Apache JServ Protocol (AJP), care must be taken when trusting incoming connections to Apache Tomcat. Tomcat treats AJP connections as having higher trust than, for example, a similar HTTP connection. If such connections are available to an attacker, they can be exploited in ways that may be surprising. In Apache Tomcat 9.0.0.M1 to 9.0.0.30, 8.5.0 to 8.5.50 and 7.0.0 to 7.0.99, Tomcat shipped with an AJP Connector enabled by default that listened on all configured IP addresses. It was expected (and recommended in the security guide) that this Connector would be disabled if not required. This vulnerability report identified a mechanism that allowed: - returning arbitrary files from anywhere in the web application - processing any file in the web application as a JSP Further, if the web application allowed file upload and stored those files within the web application (or the attacker was able to control the content of the web application by some other means) then this, along with the ability to process a file as a JSP, made remote code execution possible. It is important to note that mitigation is only required if an AJP port is accessible to untrusted users. Users wishing to take a defence-in-depth approach and block the vector that permits returning arbitrary files and execution as JSP may upgrade to Apache Tomcat 9.0.31, 8.5.51 or 7.0.100 or later. A number of changes were made to the default AJP Connector configuration in 9.0.31 to harden the default configuration. It is likely that users upgrading to 9.0.31, 8.5.51 or 7.0.100 or later will need to make small changes to their configurations.

- [https://github.com/lizhianyuguangming/TomcatScanPro](https://github.com/lizhianyuguangming/TomcatScanPro) :  ![starts](https://img.shields.io/github/stars/lizhianyuguangming/TomcatScanPro.svg) ![forks](https://img.shields.io/github/forks/lizhianyuguangming/TomcatScanPro.svg)


## CVE-2018-14714
 System command injection in appGet.cgi on ASUS RT-AC3200 version 3.0.0.4.382.50010 allows attackers to execute system commands via the &quot;load_script&quot; URL parameter.

- [https://github.com/BTtea/CVE-2018-14714-RCE-exploit](https://github.com/BTtea/CVE-2018-14714-RCE-exploit) :  ![starts](https://img.shields.io/github/stars/BTtea/CVE-2018-14714-RCE-exploit.svg) ![forks](https://img.shields.io/github/forks/BTtea/CVE-2018-14714-RCE-exploit.svg)


## CVE-2018-6574
 Go before 1.8.7, Go 1.9.x before 1.9.4, and Go 1.10 pre-releases before Go 1.10rc2 allow &quot;go get&quot; remote command execution during source code build, by leveraging the gcc or clang plugin feature, because -fplugin= and -plugin= arguments were not blocked.

- [https://github.com/lisu60/cve-2018-6574](https://github.com/lisu60/cve-2018-6574) :  ![starts](https://img.shields.io/github/stars/lisu60/cve-2018-6574.svg) ![forks](https://img.shields.io/github/forks/lisu60/cve-2018-6574.svg)


## CVE-2018-0114
 A vulnerability in the Cisco node-jose open source library before 0.11.0 could allow an unauthenticated, remote attacker to re-sign tokens using a key that is embedded within the token. The vulnerability is due to node-jose following the JSON Web Signature (JWS) standard for JSON Web Tokens (JWTs). This standard specifies that a JSON Web Key (JWK) representing a public key can be embedded within the header of a JWS. This public key is then trusted for verification. An attacker could exploit this by forging valid JWS objects by removing the original signature, adding a new public key to the header, and then signing the object using the (attacker-owned) private key associated with the public key embedded in that JWS header.

- [https://github.com/Pandora-research/CVE-2018-0114-Exploit](https://github.com/Pandora-research/CVE-2018-0114-Exploit) :  ![starts](https://img.shields.io/github/stars/Pandora-research/CVE-2018-0114-Exploit.svg) ![forks](https://img.shields.io/github/forks/Pandora-research/CVE-2018-0114-Exploit.svg)


## CVE-2017-12615
 When running Apache Tomcat 7.0.0 to 7.0.79 on Windows with HTTP PUTs enabled (e.g. via setting the readonly initialisation parameter of the Default to false) it was possible to upload a JSP file to the server via a specially crafted request. This JSP could then be requested and any code it contained would be executed by the server.

- [https://github.com/lizhianyuguangming/TomcatScanPro](https://github.com/lizhianyuguangming/TomcatScanPro) :  ![starts](https://img.shields.io/github/stars/lizhianyuguangming/TomcatScanPro.svg) ![forks](https://img.shields.io/github/forks/lizhianyuguangming/TomcatScanPro.svg)

