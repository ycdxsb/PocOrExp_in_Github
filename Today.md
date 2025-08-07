# Update 2025-08-07
## CVE-2025-54135
 Cursor is a code editor built for programming with AI. Cursor allows writing in-workspace files with no user approval in versions below 1.3.9, If the file is a dotfile, editing it requires approval but creating a new one doesn't. Hence, if sensitive MCP files, such as the .cursor/mcp.json file don't already exist in the workspace, an attacker can chain a indirect prompt injection vulnerability to hijack the context to write to the settings file and trigger RCE on the victim without user approval. This is fixed in version 1.3.9.

- [https://github.com/allinsthon/CVE-2025-54135](https://github.com/allinsthon/CVE-2025-54135) :  ![starts](https://img.shields.io/github/stars/allinsthon/CVE-2025-54135.svg) ![forks](https://img.shields.io/github/forks/allinsthon/CVE-2025-54135.svg)


## CVE-2025-53770
Microsoft is preparing and fully testing a comprehensive update to address this vulnerability.  In the meantime, please make sure that the mitigation provided in this CVE documentation is in place so that you are protected from exploitation.

- [https://github.com/SDX442/CVE-2025-53770](https://github.com/SDX442/CVE-2025-53770) :  ![starts](https://img.shields.io/github/stars/SDX442/CVE-2025-53770.svg) ![forks](https://img.shields.io/github/forks/SDX442/CVE-2025-53770.svg)


## CVE-2025-52078
 File upload vulnerability in Writebot AI Content Generator SaaS React Template thru 4.0.0, allowing remote attackers to gain escalated privileges via a crafted POST request to the /file-upload endpoint.

- [https://github.com/Yucaerin/CVE-2025-52078](https://github.com/Yucaerin/CVE-2025-52078) :  ![starts](https://img.shields.io/github/stars/Yucaerin/CVE-2025-52078.svg) ![forks](https://img.shields.io/github/forks/Yucaerin/CVE-2025-52078.svg)


## CVE-2025-50592
 Cross site scripting vulnerability in seacms before 13.2 via the vid parameter to Upload/js/player/dmplayer/player.

- [https://github.com/1515601525/CVE-2025-50592](https://github.com/1515601525/CVE-2025-50592) :  ![starts](https://img.shields.io/github/stars/1515601525/CVE-2025-50592.svg) ![forks](https://img.shields.io/github/forks/1515601525/CVE-2025-50592.svg)


## CVE-2025-48799
 Improper link resolution before file access ('link following') in Windows Update Service allows an authorized attacker to elevate privileges locally.

- [https://github.com/painoob/CVE-2025-48799](https://github.com/painoob/CVE-2025-48799) :  ![starts](https://img.shields.io/github/stars/painoob/CVE-2025-48799.svg) ![forks](https://img.shields.io/github/forks/painoob/CVE-2025-48799.svg)


## CVE-2025-45512
 A lack of signature verification in the bootloader of DENX Software Engineering Das U-Boot (U-Boot) v1.1.3 allows attackers to install crafted firmware files, leading to arbitrary code execution.

- [https://github.com/AzhariRamadhan/CVE-2025-45512](https://github.com/AzhariRamadhan/CVE-2025-45512) :  ![starts](https://img.shields.io/github/stars/AzhariRamadhan/CVE-2025-45512.svg) ![forks](https://img.shields.io/github/forks/AzhariRamadhan/CVE-2025-45512.svg)


## CVE-2025-32463
 Sudo before 1.9.17p1 allows local users to obtain root access because /etc/nsswitch.conf from a user-controlled directory is used with the --chroot option.

- [https://github.com/aldoClau98/CVE-2025-32463](https://github.com/aldoClau98/CVE-2025-32463) :  ![starts](https://img.shields.io/github/stars/aldoClau98/CVE-2025-32463.svg) ![forks](https://img.shields.io/github/forks/aldoClau98/CVE-2025-32463.svg)
- [https://github.com/painoob/CVE-2025-32463](https://github.com/painoob/CVE-2025-32463) :  ![starts](https://img.shields.io/github/stars/painoob/CVE-2025-32463.svg) ![forks](https://img.shields.io/github/forks/painoob/CVE-2025-32463.svg)


## CVE-2025-24893
 XWiki Platform is a generic wiki platform offering runtime services for applications built on top of it. Any guest can perform arbitrary remote code execution through a request to `SolrSearch`. This impacts the confidentiality, integrity and availability of the whole XWiki installation. To reproduce on an instance, without being logged in, go to `host/xwiki/bin/get/Main/SolrSearch?media=rss&text=%7D%7D%7D%7B%7Basync%20async%3Dfalse%7D%7D%7B%7Bgroovy%7D%7Dprintln%28"Hello%20from"%20%2B%20"%20search%20text%3A"%20%2B%20%2823%20%2B%2019%29%29%7B%7B%2Fgroovy%7D%7D%7B%7B%2Fasync%7D%7D%20`. If there is an output, and the title of the RSS feed contains `Hello from search text:42`, then the instance is vulnerable. This vulnerability has been patched in XWiki 15.10.11, 16.4.1 and 16.5.0RC1. Users are advised to upgrade. Users unable to upgrade may edit `Main.SolrSearchMacros` in `SolrSearchMacros.xml` on line 955 to match the `rawResponse` macro in `macros.vm#L2824` with a content type of `application/xml`, instead of simply outputting the content of the feed.

- [https://github.com/investigato/cve-2025-24893-poc](https://github.com/investigato/cve-2025-24893-poc) :  ![starts](https://img.shields.io/github/stars/investigato/cve-2025-24893-poc.svg) ![forks](https://img.shields.io/github/forks/investigato/cve-2025-24893-poc.svg)
- [https://github.com/zs1n/CVE-2025-24893](https://github.com/zs1n/CVE-2025-24893) :  ![starts](https://img.shields.io/github/stars/zs1n/CVE-2025-24893.svg) ![forks](https://img.shields.io/github/forks/zs1n/CVE-2025-24893.svg)


## CVE-2025-8550
 A vulnerability was found in atjiu pybbs up to 6.0.0. It has been declared as problematic. Affected by this vulnerability is an unknown functionality of the file /admin/topic/list. The manipulation of the argument Username leads to cross site scripting. The attack can be launched remotely. The exploit has been disclosed to the public and may be used. The patch is named 2fe4a51afbce0068c291bc1818bbc8f7f3b01a22. It is recommended to apply a patch to fix this issue.

- [https://github.com/byteReaper77/CVE-2025-8550](https://github.com/byteReaper77/CVE-2025-8550) :  ![starts](https://img.shields.io/github/stars/byteReaper77/CVE-2025-8550.svg) ![forks](https://img.shields.io/github/forks/byteReaper77/CVE-2025-8550.svg)


## CVE-2025-5067
 Inappropriate implementation in Tab Strip in Google Chrome prior to 137.0.7151.55 allowed a remote attacker to perform UI spoofing via a crafted HTML page. (Chromium security severity: Low)

- [https://github.com/LukeSec/CVE-2025-50675-GPMAW-Permissions](https://github.com/LukeSec/CVE-2025-50675-GPMAW-Permissions) :  ![starts](https://img.shields.io/github/stars/LukeSec/CVE-2025-50675-GPMAW-Permissions.svg) ![forks](https://img.shields.io/github/forks/LukeSec/CVE-2025-50675-GPMAW-Permissions.svg)


## CVE-2025-5028
allow an attacker to misuse to delete an arbitrary file without having the permissions to do so.

- [https://github.com/binneko/CVE-2025-50286](https://github.com/binneko/CVE-2025-50286) :  ![starts](https://img.shields.io/github/stars/binneko/CVE-2025-50286.svg) ![forks](https://img.shields.io/github/forks/binneko/CVE-2025-50286.svg)


## CVE-2024-45200
 In Nintendo Mario Kart 8 Deluxe before 3.0.3, the LAN/LDN local multiplayer implementation allows a remote attacker to exploit a stack-based buffer overflow upon deserialization of session information via a malformed browse-reply packet, aka KartLANPwn. The victim is not required to join a game session with an attacker. The victim must open the "Wireless Play" (or "LAN Play") menu from the game's title screen, and an attacker nearby (LDN) or on the same LAN network as the victim can send a crafted reply packet to the victim's console. This enables a remote attacker to obtain complete denial-of-service on the game's process, or potentially, remote code execution on the victim's console. The issue is caused by incorrect use of the Nintendo Pia library,

- [https://github.com/chadhyatt/kartlanpwn](https://github.com/chadhyatt/kartlanpwn) :  ![starts](https://img.shields.io/github/stars/chadhyatt/kartlanpwn.svg) ![forks](https://img.shields.io/github/forks/chadhyatt/kartlanpwn.svg)


## CVE-2024-32019
 Netdata is an open source observability tool. In affected versions the `ndsudo` tool shipped with affected versions of the Netdata Agent allows an attacker to run arbitrary programs with root permissions. The `ndsudo` tool is packaged as a `root`-owned executable with the SUID bit set. It only runs a restricted set of external commands, but its search paths are supplied by the `PATH` environment variable. This allows an attacker to control where `ndsudo` looks for these commands, which may be a path the attacker has write access to. This may lead to local privilege escalation. This vulnerability has been addressed in versions 1.45.3 and 1.45.2-169. Users are advised to upgrade. There are no known workarounds for this vulnerability.

- [https://github.com/juanbelin/CVE-2024-32019-POC](https://github.com/juanbelin/CVE-2024-32019-POC) :  ![starts](https://img.shields.io/github/stars/juanbelin/CVE-2024-32019-POC.svg) ![forks](https://img.shields.io/github/forks/juanbelin/CVE-2024-32019-POC.svg)
- [https://github.com/dollarboysushil/CVE-2024-32019-Netdata-ndsudo-PATH-Vulnerability-Privilege-Escalation](https://github.com/dollarboysushil/CVE-2024-32019-Netdata-ndsudo-PATH-Vulnerability-Privilege-Escalation) :  ![starts](https://img.shields.io/github/stars/dollarboysushil/CVE-2024-32019-Netdata-ndsudo-PATH-Vulnerability-Privilege-Escalation.svg) ![forks](https://img.shields.io/github/forks/dollarboysushil/CVE-2024-32019-Netdata-ndsudo-PATH-Vulnerability-Privilege-Escalation.svg)


## CVE-2023-7028
 An issue has been discovered in GitLab CE/EE affecting all versions from 16.1 prior to 16.1.6, 16.2 prior to 16.2.9, 16.3 prior to 16.3.7, 16.4 prior to 16.4.5, 16.5 prior to 16.5.6, 16.6 prior to 16.6.4, and 16.7 prior to 16.7.2 in which user account password reset emails could be delivered to an unverified email address.

- [https://github.com/KameliaZaman/Exploiting-GitLab-CVE-2023-7028](https://github.com/KameliaZaman/Exploiting-GitLab-CVE-2023-7028) :  ![starts](https://img.shields.io/github/stars/KameliaZaman/Exploiting-GitLab-CVE-2023-7028.svg) ![forks](https://img.shields.io/github/forks/KameliaZaman/Exploiting-GitLab-CVE-2023-7028.svg)


## CVE-2022-22965
 A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the application to run on Tomcat as a WAR deployment. If the application is deployed as a Spring Boot executable jar, i.e. the default, it is not vulnerable to the exploit. However, the nature of the vulnerability is more general, and there may be other ways to exploit it.

- [https://github.com/salo-404/firewall.](https://github.com/salo-404/firewall.) :  ![starts](https://img.shields.io/github/stars/salo-404/firewall..svg) ![forks](https://img.shields.io/github/forks/salo-404/firewall..svg)


## CVE-2021-34527
pNote that the security updates released on and after July 6, 2021 contain protections for CVE-2021-1675 and the additional remote code execution exploit in the Windows Print Spooler service known as “PrintNightmare”, documented in CVE-2021-34527./p

- [https://github.com/GlacierGossip/PrintNightmare](https://github.com/GlacierGossip/PrintNightmare) :  ![starts](https://img.shields.io/github/stars/GlacierGossip/PrintNightmare.svg) ![forks](https://img.shields.io/github/forks/GlacierGossip/PrintNightmare.svg)


## CVE-2021-1675
 Windows Print Spooler Remote Code Execution Vulnerability

- [https://github.com/GlacierGossip/PrintNightmare](https://github.com/GlacierGossip/PrintNightmare) :  ![starts](https://img.shields.io/github/stars/GlacierGossip/PrintNightmare.svg) ![forks](https://img.shields.io/github/forks/GlacierGossip/PrintNightmare.svg)


## CVE-2020-0796
 A remote code execution vulnerability exists in the way that the Microsoft Server Message Block 3.1.1 (SMBv3) protocol handles certain requests, aka 'Windows SMBv3 Client/Server Remote Code Execution Vulnerability'.

- [https://github.com/esmwaSpyware/DoS-PoC-for-CVE-2020-0796-SMBGhost-](https://github.com/esmwaSpyware/DoS-PoC-for-CVE-2020-0796-SMBGhost-) :  ![starts](https://img.shields.io/github/stars/esmwaSpyware/DoS-PoC-for-CVE-2020-0796-SMBGhost-.svg) ![forks](https://img.shields.io/github/forks/esmwaSpyware/DoS-PoC-for-CVE-2020-0796-SMBGhost-.svg)


## CVE-2017-13156
 An elevation of privilege vulnerability in the Android system (art). Product: Android. Versions: 5.1.1, 6.0, 6.0.1, 7.0, 7.1.1, 7.1.2, 8.0. Android ID A-64211847.

- [https://github.com/nictjh/threatDemos](https://github.com/nictjh/threatDemos) :  ![starts](https://img.shields.io/github/stars/nictjh/threatDemos.svg) ![forks](https://img.shields.io/github/forks/nictjh/threatDemos.svg)


## CVE-2014-0160
 The (1) TLS and (2) DTLS implementations in OpenSSL 1.0.1 before 1.0.1g do not properly handle Heartbeat Extension packets, which allows remote attackers to obtain sensitive information from process memory via crafted packets that trigger a buffer over-read, as demonstrated by reading private keys, related to d1_both.c and t1_lib.c, aka the Heartbleed bug.

- [https://github.com/0x00-V/heartbleed-poc](https://github.com/0x00-V/heartbleed-poc) :  ![starts](https://img.shields.io/github/stars/0x00-V/heartbleed-poc.svg) ![forks](https://img.shields.io/github/forks/0x00-V/heartbleed-poc.svg)

