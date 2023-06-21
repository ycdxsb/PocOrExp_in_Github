# Update 2023-06-21
## CVE-2023-33476
 ReadyMedia (MiniDLNA) versions from 1.1.15 up to 1.3.2 is vulnerable to Buffer Overflow. The vulnerability is caused by incorrect validation logic when handling HTTP requests using chunked transport encoding. This results in other code later using attacker-controlled chunk values that exceed the length of the allocated buffer, resulting in out-of-bounds read/write.

- [https://github.com/mellow-hype/cve-2023-33476](https://github.com/mellow-hype/cve-2023-33476) :  ![starts](https://img.shields.io/github/stars/mellow-hype/cve-2023-33476.svg) ![forks](https://img.shields.io/github/forks/mellow-hype/cve-2023-33476.svg)


## CVE-2023-30212
 OURPHP &lt;= 7.2.0 is vulnerale to Cross Site Scripting (XSS) via /client/manage/ourphp_out.php.

- [https://github.com/arunsnap/CVE-2023-30212-POC](https://github.com/arunsnap/CVE-2023-30212-POC) :  ![starts](https://img.shields.io/github/stars/arunsnap/CVE-2023-30212-POC.svg) ![forks](https://img.shields.io/github/forks/arunsnap/CVE-2023-30212-POC.svg)


## CVE-2023-29325
 Windows OLE Remote Code Execution Vulnerability

- [https://github.com/a-bazi/test2-CVE-2023-29325](https://github.com/a-bazi/test2-CVE-2023-29325) :  ![starts](https://img.shields.io/github/stars/a-bazi/test2-CVE-2023-29325.svg) ![forks](https://img.shields.io/github/forks/a-bazi/test2-CVE-2023-29325.svg)


## CVE-2023-27997
 A heap-based buffer overflow vulnerability [CWE-122] in FortiOS version 7.2.4 and below, version 7.0.11 and below, version 6.4.12 and below, version 6.0.16 and below and FortiProxy version 7.2.3 and below, version 7.0.9 and below, version 2.0.12 and below, version 1.2 all versions, version 1.1 all versions SSL-VPN may allow a remote attacker to execute arbitrary code or commands via specifically crafted requests.

- [https://github.com/BishopFox/CVE-2023-27997-check](https://github.com/BishopFox/CVE-2023-27997-check) :  ![starts](https://img.shields.io/github/stars/BishopFox/CVE-2023-27997-check.svg) ![forks](https://img.shields.io/github/forks/BishopFox/CVE-2023-27997-check.svg)


## CVE-2023-27372
 SPIP before 4.2.1 allows Remote Code Execution via form values in the public area because serialization is mishandled. The fixed versions are 3.2.18, 4.0.10, 4.1.8, and 4.2.1.

- [https://github.com/nuts7/CVE-2023-27372](https://github.com/nuts7/CVE-2023-27372) :  ![starts](https://img.shields.io/github/stars/nuts7/CVE-2023-27372.svg) ![forks](https://img.shields.io/github/forks/nuts7/CVE-2023-27372.svg)


## CVE-2023-22809
 In Sudo before 1.9.12p2, the sudoedit (aka -e) feature mishandles extra arguments passed in the user-provided environment variables (SUDO_EDITOR, VISUAL, and EDITOR), allowing a local attacker to append arbitrary entries to the list of files to process. This can lead to privilege escalation. Affected versions are 1.8.0 through 1.9.12.p1. The problem exists because a user-specified editor may contain a &quot;--&quot; argument that defeats a protection mechanism, e.g., an EDITOR='vim -- /path/to/extra/file' value.

- [https://github.com/Chan9Yan9/CVE-2023-22809](https://github.com/Chan9Yan9/CVE-2023-22809) :  ![starts](https://img.shields.io/github/stars/Chan9Yan9/CVE-2023-22809.svg) ![forks](https://img.shields.io/github/forks/Chan9Yan9/CVE-2023-22809.svg)


## CVE-2023-2833
 The ReviewX plugin for WordPress is vulnerable to privilege escalation in versions up to, and including, 1.6.13 due to insufficient restriction on the 'rx_set_screen_options' function. This makes it possible for authenticated attackers, with minimal permissions such as a subscriber, to modify their user role by supplying the 'wp_screen_options[option]' and 'wp_screen_options[value]' parameters during a screen option update.

- [https://github.com/Alucard0x1/CVE-2023-2833](https://github.com/Alucard0x1/CVE-2023-2833) :  ![starts](https://img.shields.io/github/stars/Alucard0x1/CVE-2023-2833.svg) ![forks](https://img.shields.io/github/forks/Alucard0x1/CVE-2023-2833.svg)


## CVE-2023-2825
 An issue has been discovered in GitLab CE/EE affecting only version 16.0.0. An unauthenticated malicious user can use a path traversal vulnerability to read arbitrary files on the server when an attachment exists in a public project nested within at least five groups.

- [https://github.com/EmmanuelCruzL/CVE-2023-2825](https://github.com/EmmanuelCruzL/CVE-2023-2825) :  ![starts](https://img.shields.io/github/stars/EmmanuelCruzL/CVE-2023-2825.svg) ![forks](https://img.shields.io/github/forks/EmmanuelCruzL/CVE-2023-2825.svg)


## CVE-2022-22963
 In Spring Cloud Function versions 3.1.6, 3.2.2 and older unsupported versions, when using routing functionality it is possible for a user to provide a specially crafted SpEL as a routing-expression that may result in remote code execution and access to local resources.

- [https://github.com/gunzf0x/CVE-2022-22963](https://github.com/gunzf0x/CVE-2022-22963) :  ![starts](https://img.shields.io/github/stars/gunzf0x/CVE-2022-22963.svg) ![forks](https://img.shields.io/github/forks/gunzf0x/CVE-2022-22963.svg)


## CVE-2021-22911
 A improper input sanitization vulnerability exists in Rocket.Chat server 3.11, 3.12 &amp; 3.13 that could lead to unauthenticated NoSQL injection, resulting potentially in RCE.

- [https://github.com/overgrowncarrot1/CVE-2021-22911](https://github.com/overgrowncarrot1/CVE-2021-22911) :  ![starts](https://img.shields.io/github/stars/overgrowncarrot1/CVE-2021-22911.svg) ![forks](https://img.shields.io/github/forks/overgrowncarrot1/CVE-2021-22911.svg)


## CVE-2021-4045
 TP-Link Tapo C200 IP camera, on its 1.1.15 firmware version and below, is affected by an unauthenticated RCE vulnerability, present in the uhttpd binary running by default as root. The exploitation of this vulnerability allows an attacker to take full control of the camera.

- [https://github.com/onebytex/CVE-2021-4045](https://github.com/onebytex/CVE-2021-4045) :  ![starts](https://img.shields.io/github/stars/onebytex/CVE-2021-4045.svg) ![forks](https://img.shields.io/github/forks/onebytex/CVE-2021-4045.svg)


## CVE-2019-1476
 An elevation of privilege vulnerability exists when Windows AppX Deployment Service (AppXSVC) improperly handles hard links, aka 'Windows Elevation of Privilege Vulnerability'. This CVE ID is unique from CVE-2019-1483.

- [https://github.com/sgabe/CVE-2019-1476](https://github.com/sgabe/CVE-2019-1476) :  ![starts](https://img.shields.io/github/stars/sgabe/CVE-2019-1476.svg) ![forks](https://img.shields.io/github/forks/sgabe/CVE-2019-1476.svg)


## CVE-2019-1040
 A tampering vulnerability exists in Microsoft Windows when a man-in-the-middle attacker is able to successfully bypass the NTLM MIC (Message Integrity Check) protection, aka 'Windows NTLM Tampering Vulnerability'.

- [https://github.com/fox-it/cve-2019-1040-scanner](https://github.com/fox-it/cve-2019-1040-scanner) :  ![starts](https://img.shields.io/github/stars/fox-it/cve-2019-1040-scanner.svg) ![forks](https://img.shields.io/github/forks/fox-it/cve-2019-1040-scanner.svg)


## CVE-2018-6574
 Go before 1.8.7, Go 1.9.x before 1.9.4, and Go 1.10 pre-releases before Go 1.10rc2 allow &quot;go get&quot; remote command execution during source code build, by leveraging the gcc or clang plugin feature, because -fplugin= and -plugin= arguments were not blocked.

- [https://github.com/Zeeshan12340/CVE-2018-6574](https://github.com/Zeeshan12340/CVE-2018-6574) :  ![starts](https://img.shields.io/github/stars/Zeeshan12340/CVE-2018-6574.svg) ![forks](https://img.shields.io/github/forks/Zeeshan12340/CVE-2018-6574.svg)


## CVE-2016-1287
 Buffer overflow in the IKEv1 and IKEv2 implementations in Cisco ASA Software before 8.4(7.30), 8.7 before 8.7(1.18), 9.0 before 9.0(4.38), 9.1 before 9.1(7), 9.2 before 9.2(4.5), 9.3 before 9.3(3.7), 9.4 before 9.4(2.4), and 9.5 before 9.5(2.2) on ASA 5500 devices, ASA 5500-X devices, ASA Services Module for Cisco Catalyst 6500 and Cisco 7600 devices, ASA 1000V devices, Adaptive Security Virtual Appliance (aka ASAv), Firepower 9300 ASA Security Module, and ISA 3000 devices allows remote attackers to execute arbitrary code or cause a denial of service (device reload) via crafted UDP packets, aka Bug IDs CSCux29978 and CSCux42019.

- [https://github.com/jgajek/killasa](https://github.com/jgajek/killasa) :  ![starts](https://img.shields.io/github/stars/jgajek/killasa.svg) ![forks](https://img.shields.io/github/forks/jgajek/killasa.svg)

