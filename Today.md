# Update 2025-09-23
## CVE-2025-49144
 Notepad++ is a free and open-source source code editor. In versions 8.8.1 and prior, a privilege escalation vulnerability exists in the Notepad++ v8.8.1 installer that allows unprivileged users to gain SYSTEM-level privileges through insecure executable search paths. An attacker could use social engineering or clickjacking to trick users into downloading both the legitimate installer and a malicious executable to the same directory (typically Downloads folder - which is known as Vulnerable directory). Upon running the installer, the attack executes automatically with SYSTEM privileges. This issue has been fixed and will be released in version 8.8.2.

- [https://github.com/TheTorjanCaptain/CVE-2025-49144_PoC](https://github.com/TheTorjanCaptain/CVE-2025-49144_PoC) :  ![starts](https://img.shields.io/github/stars/TheTorjanCaptain/CVE-2025-49144_PoC.svg) ![forks](https://img.shields.io/github/forks/TheTorjanCaptain/CVE-2025-49144_PoC.svg)


## CVE-2025-34152
 An unauthenticated OS command injection vulnerability exists in the Shenzhen Aitemi M300 Wi-Fi Repeater (hardware model MT02) via the 'time' parameter of the '/protocol.csp?' endpoint. The input is processed by the internal date '-s' command without rebooting or disrupting HTTP service. Unlike other injection points, this vector allows remote compromise without triggering visible configuration changes.

- [https://github.com/kh4sh3i/CVE-2025-34152](https://github.com/kh4sh3i/CVE-2025-34152) :  ![starts](https://img.shields.io/github/stars/kh4sh3i/CVE-2025-34152.svg) ![forks](https://img.shields.io/github/forks/kh4sh3i/CVE-2025-34152.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/JOOJIII/CVE-2025-29927](https://github.com/JOOJIII/CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/JOOJIII/CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/JOOJIII/CVE-2025-29927.svg)
- [https://github.com/iteride/CVE-2025-29927](https://github.com/iteride/CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/iteride/CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/iteride/CVE-2025-29927.svg)


## CVE-2025-25257
 An improper neutralization of special elements used in an SQL command ('SQL Injection') vulnerability [CWE-89] in Fortinet FortiWeb version 7.6.0 through 7.6.3, 7.4.0 through 7.4.7, 7.2.0 through 7.2.10 and below 7.0.10 allows an unauthenticated attacker to execute unauthorized SQL code or commands via crafted HTTP or HTTPs requests.

- [https://github.com/segfault-it/CVE-2025-25257](https://github.com/segfault-it/CVE-2025-25257) :  ![starts](https://img.shields.io/github/stars/segfault-it/CVE-2025-25257.svg) ![forks](https://img.shields.io/github/forks/segfault-it/CVE-2025-25257.svg)


## CVE-2025-10035
 A deserialization vulnerability in the License Servlet of Fortra's GoAnywhere MFT allows an actor with a validly forged license response signature to deserialize an arbitrary actor-controlled object, possibly leading to command injection.

- [https://github.com/ThemeHackers/CVE-2025-10035](https://github.com/ThemeHackers/CVE-2025-10035) :  ![starts](https://img.shields.io/github/stars/ThemeHackers/CVE-2025-10035.svg) ![forks](https://img.shields.io/github/forks/ThemeHackers/CVE-2025-10035.svg)


## CVE-2025-8088
     from ESET.

- [https://github.com/m4nbun/CVE-2025-8088](https://github.com/m4nbun/CVE-2025-8088) :  ![starts](https://img.shields.io/github/stars/m4nbun/CVE-2025-8088.svg) ![forks](https://img.shields.io/github/forks/m4nbun/CVE-2025-8088.svg)
- [https://github.com/Osinskitito499/CVE-2025-8088](https://github.com/Osinskitito499/CVE-2025-8088) :  ![starts](https://img.shields.io/github/stars/Osinskitito499/CVE-2025-8088.svg) ![forks](https://img.shields.io/github/forks/Osinskitito499/CVE-2025-8088.svg)


## CVE-2024-46982
 Next.js is a React framework for building full-stack web applications. By sending a crafted HTTP request, it is possible to poison the cache of a non-dynamic server-side rendered route in the pages router (this does not affect the app router). When this crafted request is sent it could coerce Next.js to cache a route that is meant to not be cached and send a `Cache-Control: s-maxage=1, stale-while-revalidate` header which some upstream CDNs may cache as well. To be potentially affected all of the following must apply: 1. Next.js between 13.5.1 and 14.2.9, 2. Using pages router, & 3. Using non-dynamic server-side rendered routes e.g. `pages/dashboard.tsx` not `pages/blog/[slug].tsx`. This vulnerability was resolved in Next.js v13.5.7, v14.2.10, and later. We recommend upgrading regardless of whether you can reproduce the issue or not. There are no official or recommended workarounds for this issue, we recommend that users patch to a safe version.

- [https://github.com/melmathari/CVE-2024-46982-NUCLEI](https://github.com/melmathari/CVE-2024-46982-NUCLEI) :  ![starts](https://img.shields.io/github/stars/melmathari/CVE-2024-46982-NUCLEI.svg) ![forks](https://img.shields.io/github/forks/melmathari/CVE-2024-46982-NUCLEI.svg)


## CVE-2023-1545
 SQL Injection in GitHub repository nilsteampassnet/teampass prior to 3.0.0.23.

- [https://github.com/lineeralgebra/CVE-2023-1545-POC](https://github.com/lineeralgebra/CVE-2023-1545-POC) :  ![starts](https://img.shields.io/github/stars/lineeralgebra/CVE-2023-1545-POC.svg) ![forks](https://img.shields.io/github/forks/lineeralgebra/CVE-2023-1545-POC.svg)


## CVE-2022-26134
 In affected versions of Confluence Server and Data Center, an OGNL injection vulnerability exists that would allow an unauthenticated attacker to execute arbitrary code on a Confluence Server or Data Center instance. The affected versions are from 1.3.0 before 7.4.17, from 7.13.0 before 7.13.7, from 7.14.0 before 7.14.3, from 7.15.0 before 7.15.2, from 7.16.0 before 7.16.4, from 7.17.0 before 7.17.4, and from 7.18.0 before 7.18.1.

- [https://github.com/Yuri08loveElaina/CVE-2022-26134](https://github.com/Yuri08loveElaina/CVE-2022-26134) :  ![starts](https://img.shields.io/github/stars/Yuri08loveElaina/CVE-2022-26134.svg) ![forks](https://img.shields.io/github/forks/Yuri08loveElaina/CVE-2022-26134.svg)
- [https://github.com/Yuri08loveElaina/CVE_2022_26134_exploit](https://github.com/Yuri08loveElaina/CVE_2022_26134_exploit) :  ![starts](https://img.shields.io/github/stars/Yuri08loveElaina/CVE_2022_26134_exploit.svg) ![forks](https://img.shields.io/github/forks/Yuri08loveElaina/CVE_2022_26134_exploit.svg)
- [https://github.com/Yuri08loveElaina/CVE_2022_26134](https://github.com/Yuri08loveElaina/CVE_2022_26134) :  ![starts](https://img.shields.io/github/stars/Yuri08loveElaina/CVE_2022_26134.svg) ![forks](https://img.shields.io/github/forks/Yuri08loveElaina/CVE_2022_26134.svg)
- [https://github.com/thetowsif/CVE-2022-26134](https://github.com/thetowsif/CVE-2022-26134) :  ![starts](https://img.shields.io/github/stars/thetowsif/CVE-2022-26134.svg) ![forks](https://img.shields.io/github/forks/thetowsif/CVE-2022-26134.svg)
- [https://github.com/MAHABUB122003/Atlassian-CVE-2022-26134](https://github.com/MAHABUB122003/Atlassian-CVE-2022-26134) :  ![starts](https://img.shields.io/github/stars/MAHABUB122003/Atlassian-CVE-2022-26134.svg) ![forks](https://img.shields.io/github/forks/MAHABUB122003/Atlassian-CVE-2022-26134.svg)


## CVE-2022-22965
 A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the application to run on Tomcat as a WAR deployment. If the application is deployed as a Spring Boot executable jar, i.e. the default, it is not vulnerable to the exploit. However, the nature of the vulnerability is more general, and there may be other ways to exploit it.

- [https://github.com/brunoh6/web-threat-mitigation](https://github.com/brunoh6/web-threat-mitigation) :  ![starts](https://img.shields.io/github/stars/brunoh6/web-threat-mitigation.svg) ![forks](https://img.shields.io/github/forks/brunoh6/web-threat-mitigation.svg)
- [https://github.com/e21-AS/telstra-cybersecurity-experience](https://github.com/e21-AS/telstra-cybersecurity-experience) :  ![starts](https://img.shields.io/github/stars/e21-AS/telstra-cybersecurity-experience.svg) ![forks](https://img.shields.io/github/forks/e21-AS/telstra-cybersecurity-experience.svg)


## CVE-2021-44228
 Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled. From log4j 2.15.0, this behavior has been disabled by default. From version 2.16.0 (along with 2.12.2, 2.12.3, and 2.3.1), this functionality has been completely removed. Note that this vulnerability is specific to log4j-core and does not affect log4net, log4cxx, or other Apache Logging Services projects.

- [https://github.com/thecyberneh/Log4j-RCE-Exploiter](https://github.com/thecyberneh/Log4j-RCE-Exploiter) :  ![starts](https://img.shields.io/github/stars/thecyberneh/Log4j-RCE-Exploiter.svg) ![forks](https://img.shields.io/github/forks/thecyberneh/Log4j-RCE-Exploiter.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/CyberQuestor-infosec/CVE-2021-41773-Apache_2.4.49-Path-traversal-to-RCE](https://github.com/CyberQuestor-infosec/CVE-2021-41773-Apache_2.4.49-Path-traversal-to-RCE) :  ![starts](https://img.shields.io/github/stars/CyberQuestor-infosec/CVE-2021-41773-Apache_2.4.49-Path-traversal-to-RCE.svg) ![forks](https://img.shields.io/github/forks/CyberQuestor-infosec/CVE-2021-41773-Apache_2.4.49-Path-traversal-to-RCE.svg)
- [https://github.com/puckiestyle/CVE-2021-41773](https://github.com/puckiestyle/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/puckiestyle/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/puckiestyle/CVE-2021-41773.svg)
- [https://github.com/JIYUN02/cve-2021-41773](https://github.com/JIYUN02/cve-2021-41773) :  ![starts](https://img.shields.io/github/stars/JIYUN02/cve-2021-41773.svg) ![forks](https://img.shields.io/github/forks/JIYUN02/cve-2021-41773.svg)
- [https://github.com/AzK-os-dev/CVE-2021-41773](https://github.com/AzK-os-dev/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/AzK-os-dev/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/AzK-os-dev/CVE-2021-41773.svg)


## CVE-2021-40964
 A Path Traversal vulnerability exists in TinyFileManager all version up to and including 2.4.6 that allows attackers to upload a file (with Admin credentials or with the CSRF vulnerability) with the "fullpath" parameter containing path traversal strings (../ and ..\) in order to escape the server's intended working directory and write malicious files onto any directory on the computer.

- [https://github.com/Z3R0-0x30/CVE-2021-40964](https://github.com/Z3R0-0x30/CVE-2021-40964) :  ![starts](https://img.shields.io/github/stars/Z3R0-0x30/CVE-2021-40964.svg) ![forks](https://img.shields.io/github/forks/Z3R0-0x30/CVE-2021-40964.svg)


## CVE-2021-40724
 Acrobat Reader for Android versions 21.8.0 (and earlier) are affected by a Path traversal vulnerability. An unauthenticated attacker could leverage this vulnerability to achieve arbitrary code execution in the context of the current user. Exploitation of this issue requires user interaction in that a victim must open a malicious file.

- [https://github.com/tinopreter/DocViewerExploitApp](https://github.com/tinopreter/DocViewerExploitApp) :  ![starts](https://img.shields.io/github/stars/tinopreter/DocViewerExploitApp.svg) ![forks](https://img.shields.io/github/forks/tinopreter/DocViewerExploitApp.svg)


## CVE-2021-36934
pAfter installing this security update, you emmust/em manually delete all shadow copies of system files, including the SAM database, to fully mitigate this vulnerabilty. strongSimply installing this security update will not fully mitigate this vulnerability./strong See a href="https://support.microsoft.com/topic/1ceaa637-aaa3-4b58-a48b-baf72a2fa9e7"KB5005357- Delete Volume Shadow Copies/a./p

- [https://github.com/P1rat3R00t/Why-so-Serious-SAM](https://github.com/P1rat3R00t/Why-so-Serious-SAM) :  ![starts](https://img.shields.io/github/stars/P1rat3R00t/Why-so-Serious-SAM.svg) ![forks](https://img.shields.io/github/forks/P1rat3R00t/Why-so-Serious-SAM.svg)


## CVE-2021-31956
 Windows NTFS Elevation of Privilege Vulnerability

- [https://github.com/deletehead/Pool-Overflow-CVE-2021-31956](https://github.com/deletehead/Pool-Overflow-CVE-2021-31956) :  ![starts](https://img.shields.io/github/stars/deletehead/Pool-Overflow-CVE-2021-31956.svg) ![forks](https://img.shields.io/github/forks/deletehead/Pool-Overflow-CVE-2021-31956.svg)


## CVE-2021-31630
 Command Injection in Open PLC Webserver v3 allows remote attackers to execute arbitrary code via the "Hardware Layer Code Box" component on the "/hardware" page of the application.

- [https://github.com/UserB1ank/CVE-2021-31630](https://github.com/UserB1ank/CVE-2021-31630) :  ![starts](https://img.shields.io/github/stars/UserB1ank/CVE-2021-31630.svg) ![forks](https://img.shields.io/github/forks/UserB1ank/CVE-2021-31630.svg)


## CVE-2021-29447
 Wordpress is an open source CMS. A user with the ability to upload files (like an Author) can exploit an XML parsing issue in the Media Library leading to XXE attacks. This requires WordPress installation to be using PHP 8. Access to internal files is possible in a successful XXE attack. This has been patched in WordPress version 5.7.1, along with the older affected versions via a minor release. We strongly recommend you keep auto-updates enabled.

- [https://github.com/magicrc/CVE-2021-29447](https://github.com/magicrc/CVE-2021-29447) :  ![starts](https://img.shields.io/github/stars/magicrc/CVE-2021-29447.svg) ![forks](https://img.shields.io/github/forks/magicrc/CVE-2021-29447.svg)


## CVE-2021-26828
 OpenPLC ScadaBR through 0.9.1 on Linux and through 1.12.4 on Windows allows remote authenticated users to upload and execute arbitrary JSP files via view_edit.shtm.

- [https://github.com/Yuri08loveElaina/CVE-2021-26828](https://github.com/Yuri08loveElaina/CVE-2021-26828) :  ![starts](https://img.shields.io/github/stars/Yuri08loveElaina/CVE-2021-26828.svg) ![forks](https://img.shields.io/github/forks/Yuri08loveElaina/CVE-2021-26828.svg)


## CVE-2021-22600
 A double free bug in packet_set_ring() in net/packet/af_packet.c can be exploited by a local user through crafted syscalls to escalate privileges or deny service. We recommend upgrading kernel past the effected versions or rebuilding past ec6af094ea28f0f2dda1a6a33b14cd57e36a9755

- [https://github.com/sendINUX/CVE-2021-22600__DirtyPagetable](https://github.com/sendINUX/CVE-2021-22600__DirtyPagetable) :  ![starts](https://img.shields.io/github/stars/sendINUX/CVE-2021-22600__DirtyPagetable.svg) ![forks](https://img.shields.io/github/forks/sendINUX/CVE-2021-22600__DirtyPagetable.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/teelrabbit/Polkit-pkexec-exploit-for-Linux](https://github.com/teelrabbit/Polkit-pkexec-exploit-for-Linux) :  ![starts](https://img.shields.io/github/stars/teelrabbit/Polkit-pkexec-exploit-for-Linux.svg) ![forks](https://img.shields.io/github/forks/teelrabbit/Polkit-pkexec-exploit-for-Linux.svg)


## CVE-2021-3156
 Sudo before 1.9.5p2 contains an off-by-one error that can result in a heap-based buffer overflow, which allows privilege escalation to root via "sudoedit -s" and a command-line argument that ends with a single backslash character.

- [https://github.com/TopskiyPavelQwertyGang/Review.CVE-2021-3156](https://github.com/TopskiyPavelQwertyGang/Review.CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/TopskiyPavelQwertyGang/Review.CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/TopskiyPavelQwertyGang/Review.CVE-2021-3156.svg)


## CVE-2020-21365
 Directory traversal vulnerability in wkhtmltopdf through 0.12.5 allows remote attackers to read local files and disclose sensitive information via a crafted html file running with the default configurations.

- [https://github.com/samaellovecraft/CVE-2020-21365](https://github.com/samaellovecraft/CVE-2020-21365) :  ![starts](https://img.shields.io/github/stars/samaellovecraft/CVE-2020-21365.svg) ![forks](https://img.shields.io/github/forks/samaellovecraft/CVE-2020-21365.svg)
- [https://github.com/andrei2308/CVE-2020-21365](https://github.com/andrei2308/CVE-2020-21365) :  ![starts](https://img.shields.io/github/stars/andrei2308/CVE-2020-21365.svg) ![forks](https://img.shields.io/github/forks/andrei2308/CVE-2020-21365.svg)


## CVE-2020-14871
 Vulnerability in the Oracle Solaris product of Oracle Systems (component: Pluggable authentication module). Supported versions that are affected are 10 and 11. Easily exploitable vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise Oracle Solaris. While the vulnerability is in Oracle Solaris, attacks may significantly impact additional products. Successful attacks of this vulnerability can result in takeover of Oracle Solaris. Note: This CVE is not exploitable for Solaris 11.1 and later releases, and ZFSSA 8.7 and later releases, thus the CVSS Base Score is 0.0. CVSS 3.1 Base Score 10.0 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H).

- [https://github.com/FromPartsUnknown/EvilSunCheck](https://github.com/FromPartsUnknown/EvilSunCheck) :  ![starts](https://img.shields.io/github/stars/FromPartsUnknown/EvilSunCheck.svg) ![forks](https://img.shields.io/github/forks/FromPartsUnknown/EvilSunCheck.svg)
- [https://github.com/FromPartsUnknown/CoreTrawler](https://github.com/FromPartsUnknown/CoreTrawler) :  ![starts](https://img.shields.io/github/stars/FromPartsUnknown/CoreTrawler.svg) ![forks](https://img.shields.io/github/forks/FromPartsUnknown/CoreTrawler.svg)


## CVE-2020-9483
 **Resolved** When use H2/MySQL/TiDB as Apache SkyWalking storage, the metadata query through GraphQL protocol, there is a SQL injection vulnerability, which allows to access unpexcted data. Apache SkyWalking 6.0.0 to 6.6.0, 7.0.0 H2/MySQL/TiDB storage implementations don't use the appropriate way to set SQL parameters.

- [https://github.com/tuaandatt/CVE-2020-9483---Apache-Skywalking-8.3.0](https://github.com/tuaandatt/CVE-2020-9483---Apache-Skywalking-8.3.0) :  ![starts](https://img.shields.io/github/stars/tuaandatt/CVE-2020-9483---Apache-Skywalking-8.3.0.svg) ![forks](https://img.shields.io/github/forks/tuaandatt/CVE-2020-9483---Apache-Skywalking-8.3.0.svg)


## CVE-2020-7378
 CRIXP OpenCRX version 4.30 and 5.0-20200717 and prior suffers from an unverified password change vulnerability. An attacker who is able to connect to the affected OpenCRX instance can change the password of any user, including admin-Standard, to any chosen value. This issue was resolved in version 5.0-20200904, released September 4, 2020.

- [https://github.com/loganpkinfosec/CVE-2020-7378](https://github.com/loganpkinfosec/CVE-2020-7378) :  ![starts](https://img.shields.io/github/stars/loganpkinfosec/CVE-2020-7378.svg) ![forks](https://img.shields.io/github/forks/loganpkinfosec/CVE-2020-7378.svg)


## CVE-2020-5902
 In BIG-IP versions 15.0.0-15.1.0.3, 14.1.0-14.1.2.5, 13.1.0-13.1.3.3, 12.1.0-12.1.5.1, and 11.6.1-11.6.5.1, the Traffic Management User Interface (TMUI), also referred to as the Configuration utility, has a Remote Code Execution (RCE) vulnerability in undisclosed pages.

- [https://github.com/Josekutty-K/f5-Big-IP-Unauth-RCE-Checker](https://github.com/Josekutty-K/f5-Big-IP-Unauth-RCE-Checker) :  ![starts](https://img.shields.io/github/stars/Josekutty-K/f5-Big-IP-Unauth-RCE-Checker.svg) ![forks](https://img.shields.io/github/forks/Josekutty-K/f5-Big-IP-Unauth-RCE-Checker.svg)


## CVE-2020-5142
 A stored cross-site scripting (XSS) vulnerability exists in the SonicOS SSLVPN web interface. A remote unauthenticated attacker is able to store and potentially execute arbitrary JavaScript code in the firewall SSLVPN portal. This vulnerability affected SonicOS Gen 5 version 5.9.1.7, 5.9.1.13, Gen 6 version 6.5.4.7, 6.5.1.12, 6.0.5.3, SonicOSv 6.5.4.v and Gen 7 version SonicOS 7.0.0.0.

- [https://github.com/hackerlawyer/CVE-2020-5142-POC-MB](https://github.com/hackerlawyer/CVE-2020-5142-POC-MB) :  ![starts](https://img.shields.io/github/stars/hackerlawyer/CVE-2020-5142-POC-MB.svg) ![forks](https://img.shields.io/github/forks/hackerlawyer/CVE-2020-5142-POC-MB.svg)


## CVE-2020-1048
 An elevation of privilege vulnerability exists when the Windows Print Spooler service improperly allows arbitrary writing to the file system, aka 'Windows Print Spooler Elevation of Privilege Vulnerability'. This CVE ID is unique from CVE-2020-1070.

- [https://github.com/talsim/printDemon2system](https://github.com/talsim/printDemon2system) :  ![starts](https://img.shields.io/github/stars/talsim/printDemon2system.svg) ![forks](https://img.shields.io/github/forks/talsim/printDemon2system.svg)


## CVE-2020-0796
 A remote code execution vulnerability exists in the way that the Microsoft Server Message Block 3.1.1 (SMBv3) protocol handles certain requests, aka 'Windows SMBv3 Client/Server Remote Code Execution Vulnerability'.

- [https://github.com/maqeel-git/CVE-2020-0796](https://github.com/maqeel-git/CVE-2020-0796) :  ![starts](https://img.shields.io/github/stars/maqeel-git/CVE-2020-0796.svg) ![forks](https://img.shields.io/github/forks/maqeel-git/CVE-2020-0796.svg)
- [https://github.com/Jagadeesh7532/-CVE-2020-0796-SMBGhost-Windows-10-SMBv3-Remote-Code-Execution-Vulnerability](https://github.com/Jagadeesh7532/-CVE-2020-0796-SMBGhost-Windows-10-SMBv3-Remote-Code-Execution-Vulnerability) :  ![starts](https://img.shields.io/github/stars/Jagadeesh7532/-CVE-2020-0796-SMBGhost-Windows-10-SMBv3-Remote-Code-Execution-Vulnerability.svg) ![forks](https://img.shields.io/github/forks/Jagadeesh7532/-CVE-2020-0796-SMBGhost-Windows-10-SMBv3-Remote-Code-Execution-Vulnerability.svg)


## CVE-2019-15107
 An issue was discovered in Webmin =1.920. The parameter old in password_change.cgi contains a command injection vulnerability.

- [https://github.com/bayazid-bit/CVE-2019-15107](https://github.com/bayazid-bit/CVE-2019-15107) :  ![starts](https://img.shields.io/github/stars/bayazid-bit/CVE-2019-15107.svg) ![forks](https://img.shields.io/github/forks/bayazid-bit/CVE-2019-15107.svg)
- [https://github.com/m4lk3rnel/CVE-2019-15107](https://github.com/m4lk3rnel/CVE-2019-15107) :  ![starts](https://img.shields.io/github/stars/m4lk3rnel/CVE-2019-15107.svg) ![forks](https://img.shields.io/github/forks/m4lk3rnel/CVE-2019-15107.svg)
- [https://github.com/EdouardosStav/CVE-2019-15107-RCE-WebMin](https://github.com/EdouardosStav/CVE-2019-15107-RCE-WebMin) :  ![starts](https://img.shields.io/github/stars/EdouardosStav/CVE-2019-15107-RCE-WebMin.svg) ![forks](https://img.shields.io/github/forks/EdouardosStav/CVE-2019-15107-RCE-WebMin.svg)


## CVE-2019-14811
 A flaw was found in, ghostscript versions prior to 9.50, in the .pdf_hook_DSC_Creator procedure where it did not properly secure its privileged calls, enabling scripts to bypass `-dSAFER` restrictions. A specially crafted PostScript file could disable security protection and then have access to the file system, or execute arbitrary commands.

- [https://github.com/matejsmycka/CVE-2019-14811-in-pdf-exploit](https://github.com/matejsmycka/CVE-2019-14811-in-pdf-exploit) :  ![starts](https://img.shields.io/github/stars/matejsmycka/CVE-2019-14811-in-pdf-exploit.svg) ![forks](https://img.shields.io/github/forks/matejsmycka/CVE-2019-14811-in-pdf-exploit.svg)


## CVE-2019-11043
 In PHP versions 7.1.x below 7.1.33, 7.2.x below 7.2.24 and 7.3.x below 7.3.11 in certain configurations of FPM setup it is possible to cause FPM module to write past allocated buffers into the space reserved for FCGI protocol data, thus opening the possibility of remote code execution.

- [https://github.com/bayazid-bit/CVE-2019-11043-](https://github.com/bayazid-bit/CVE-2019-11043-) :  ![starts](https://img.shields.io/github/stars/bayazid-bit/CVE-2019-11043-.svg) ![forks](https://img.shields.io/github/forks/bayazid-bit/CVE-2019-11043-.svg)


## CVE-2019-7304
 Canonical snapd before version 2.37.1 incorrectly performed socket owner validation, allowing an attacker to run arbitrary commands as root. This issue affects: Canonical snapd versions prior to 2.37.1.

- [https://github.com/coby-nguyen/Document-Linux-Privilege-Escalation](https://github.com/coby-nguyen/Document-Linux-Privilege-Escalation) :  ![starts](https://img.shields.io/github/stars/coby-nguyen/Document-Linux-Privilege-Escalation.svg) ![forks](https://img.shields.io/github/forks/coby-nguyen/Document-Linux-Privilege-Escalation.svg)


## CVE-2019-5736
 runc through 1.0-rc6, as used in Docker before 18.09.2 and other products, allows attackers to overwrite the host runc binary (and consequently obtain host root access) by leveraging the ability to execute a command as root within one of these types of containers: (1) a new container with an attacker-controlled image, or (2) an existing container, to which the attacker previously had write access, that can be attached with docker exec. This occurs because of file-descriptor mishandling, related to /proc/self/exe.

- [https://github.com/Perimora/cve_2019-5736-PoC](https://github.com/Perimora/cve_2019-5736-PoC) :  ![starts](https://img.shields.io/github/stars/Perimora/cve_2019-5736-PoC.svg) ![forks](https://img.shields.io/github/forks/Perimora/cve_2019-5736-PoC.svg)


## CVE-2019-3980
 The Solarwinds Dameware Mini Remote Client agent v12.1.0.89 supports smart card authentication which can allow a user to upload an executable to be executed on the DWRCS.exe host. An unauthenticated, remote attacker can request smart card login and upload and execute an arbitrary executable run under the Local System account.

- [https://github.com/CyberQuestor-infosec/CVE-2019-3980-Open_Net_Admin_v18.1.1_RCE](https://github.com/CyberQuestor-infosec/CVE-2019-3980-Open_Net_Admin_v18.1.1_RCE) :  ![starts](https://img.shields.io/github/stars/CyberQuestor-infosec/CVE-2019-3980-Open_Net_Admin_v18.1.1_RCE.svg) ![forks](https://img.shields.io/github/forks/CyberQuestor-infosec/CVE-2019-3980-Open_Net_Admin_v18.1.1_RCE.svg)


## CVE-2018-25031
 Swagger UI 4.1.2 and earlier could allow a remote attacker to conduct spoofing attacks. By persuading a victim to open a crafted URL, an attacker could exploit this vulnerability to display remote OpenAPI definitions. Note: This was originally claimed to be resolved in 4.1.3. However, third parties have indicated this is not resolved in 4.1.3 and even occurs in that version and possibly others.

- [https://github.com/rasinfosec/CVE-2018-25031](https://github.com/rasinfosec/CVE-2018-25031) :  ![starts](https://img.shields.io/github/stars/rasinfosec/CVE-2018-25031.svg) ![forks](https://img.shields.io/github/forks/rasinfosec/CVE-2018-25031.svg)
- [https://github.com/h4ckt0m/CVE-2018-25031-test](https://github.com/h4ckt0m/CVE-2018-25031-test) :  ![starts](https://img.shields.io/github/stars/h4ckt0m/CVE-2018-25031-test.svg) ![forks](https://img.shields.io/github/forks/h4ckt0m/CVE-2018-25031-test.svg)


## CVE-2018-17179
 An issue was discovered in OpenEMR before 5.0.1 Patch 7. There is SQL Injection in the make_task function in /interface/forms/eye_mag/php/taskman_functions.php via /interface/forms/eye_mag/taskman.php.

- [https://github.com/CyberQuestor-infosec/CVE-2018-17179-OpenEMR](https://github.com/CyberQuestor-infosec/CVE-2018-17179-OpenEMR) :  ![starts](https://img.shields.io/github/stars/CyberQuestor-infosec/CVE-2018-17179-OpenEMR.svg) ![forks](https://img.shields.io/github/forks/CyberQuestor-infosec/CVE-2018-17179-OpenEMR.svg)


## CVE-2018-9035
 CSV Injection vulnerability in ExportToCsvUtf8.php of the Contact Form 7 to Database Extension plugin 2.10.32 for WordPress allows remote attackers to inject spreadsheet formulas into CSV files via the contact form.

- [https://github.com/HaiNhat-HUST/CVE-2018-9035](https://github.com/HaiNhat-HUST/CVE-2018-9035) :  ![starts](https://img.shields.io/github/stars/HaiNhat-HUST/CVE-2018-9035.svg) ![forks](https://img.shields.io/github/forks/HaiNhat-HUST/CVE-2018-9035.svg)


## CVE-2018-7600
 Drupal before 7.58, 8.x before 8.3.9, 8.4.x before 8.4.6, and 8.5.x before 8.5.1 allows remote attackers to execute arbitrary code because of an issue affecting multiple subsystems with default or common module configurations.

- [https://github.com/nika0x38/CVE-2018-7600](https://github.com/nika0x38/CVE-2018-7600) :  ![starts](https://img.shields.io/github/stars/nika0x38/CVE-2018-7600.svg) ![forks](https://img.shields.io/github/forks/nika0x38/CVE-2018-7600.svg)


## CVE-2018-1273
 Spring Data Commons, versions prior to 1.13 to 1.13.10, 2.0 to 2.0.5, and older unsupported versions, contain a property binder vulnerability caused by improper neutralization of special elements. An unauthenticated remote malicious user (or attacker) can supply specially crafted request parameters against Spring Data REST backed HTTP resources or using Spring Data's projection-based request payload binding hat can lead to a remote code execution attack.

- [https://github.com/hdgokani/CVE-2018-1273](https://github.com/hdgokani/CVE-2018-1273) :  ![starts](https://img.shields.io/github/stars/hdgokani/CVE-2018-1273.svg) ![forks](https://img.shields.io/github/forks/hdgokani/CVE-2018-1273.svg)


## CVE-2017-12615
 When running Apache Tomcat 7.0.0 to 7.0.79 on Windows with HTTP PUTs enabled (e.g. via setting the readonly initialisation parameter of the Default to false) it was possible to upload a JSP file to the server via a specially crafted request. This JSP could then be requested and any code it contained would be executed by the server.

- [https://github.com/edyekomu/CVE-2017-12615-PoC](https://github.com/edyekomu/CVE-2017-12615-PoC) :  ![starts](https://img.shields.io/github/stars/edyekomu/CVE-2017-12615-PoC.svg) ![forks](https://img.shields.io/github/forks/edyekomu/CVE-2017-12615-PoC.svg)


## CVE-2017-9841
 Util/PHP/eval-stdin.php in PHPUnit before 4.8.28 and 5.x before 5.6.3 allows remote attackers to execute arbitrary PHP code via HTTP POST data beginning with a "?php " substring, as demonstrated by an attack on a site with an exposed /vendor folder, i.e., external access to the /vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php URI.

- [https://github.com/K3ysTr0K3R/CVE-2017-9841-EXPLOIT](https://github.com/K3ysTr0K3R/CVE-2017-9841-EXPLOIT) :  ![starts](https://img.shields.io/github/stars/K3ysTr0K3R/CVE-2017-9841-EXPLOIT.svg) ![forks](https://img.shields.io/github/forks/K3ysTr0K3R/CVE-2017-9841-EXPLOIT.svg)


## CVE-2017-8291
 Artifex Ghostscript through 2017-04-26 allows -dSAFER bypass and remote command execution via .rsdparams type confusion with a "/OutputFile (%pipe%" substring in a crafted .eps document that is an input to the gs program, as exploited in the wild in April 2017.

- [https://github.com/hkcfs/PIL-CVE-2017-8291](https://github.com/hkcfs/PIL-CVE-2017-8291) :  ![starts](https://img.shields.io/github/stars/hkcfs/PIL-CVE-2017-8291.svg) ![forks](https://img.shields.io/github/forks/hkcfs/PIL-CVE-2017-8291.svg)


## CVE-2017-5638
 The Jakarta Multipart parser in Apache Struts 2 2.3.x before 2.3.32 and 2.5.x before 2.5.10.1 has incorrect exception handling and error-message generation during file-upload attempts, which allows remote attackers to execute arbitrary commands via a crafted Content-Type, Content-Disposition, or Content-Length HTTP header, as exploited in the wild in March 2017 with a Content-Type header containing a #cmd= string.

- [https://github.com/haxerr9/CVE-2017-5638](https://github.com/haxerr9/CVE-2017-5638) :  ![starts](https://img.shields.io/github/stars/haxerr9/CVE-2017-5638.svg) ![forks](https://img.shields.io/github/forks/haxerr9/CVE-2017-5638.svg)


## CVE-2017-0144
 The SMBv1 server in Microsoft Windows Vista SP2; Windows Server 2008 SP2 and R2 SP1; Windows 7 SP1; Windows 8.1; Windows Server 2012 Gold and R2; Windows RT 8.1; and Windows 10 Gold, 1511, and 1607; and Windows Server 2016 allows remote attackers to execute arbitrary code via crafted packets, aka "Windows SMB Remote Code Execution Vulnerability." This vulnerability is different from those described in CVE-2017-0143, CVE-2017-0145, CVE-2017-0146, and CVE-2017-0148.

- [https://github.com/luckyman2907/SMB-Protocol-Vulnerability_CVE-2017-0144](https://github.com/luckyman2907/SMB-Protocol-Vulnerability_CVE-2017-0144) :  ![starts](https://img.shields.io/github/stars/luckyman2907/SMB-Protocol-Vulnerability_CVE-2017-0144.svg) ![forks](https://img.shields.io/github/forks/luckyman2907/SMB-Protocol-Vulnerability_CVE-2017-0144.svg)


## CVE-2017-0143
 The SMBv1 server in Microsoft Windows Vista SP2; Windows Server 2008 SP2 and R2 SP1; Windows 7 SP1; Windows 8.1; Windows Server 2012 Gold and R2; Windows RT 8.1; and Windows 10 Gold, 1511, and 1607; and Windows Server 2016 allows remote attackers to execute arbitrary code via crafted packets, aka "Windows SMB Remote Code Execution Vulnerability." This vulnerability is different from those described in CVE-2017-0144, CVE-2017-0145, CVE-2017-0146, and CVE-2017-0148.

- [https://github.com/Mafiosohack/offensive-security-lab-1](https://github.com/Mafiosohack/offensive-security-lab-1) :  ![starts](https://img.shields.io/github/stars/Mafiosohack/offensive-security-lab-1.svg) ![forks](https://img.shields.io/github/forks/Mafiosohack/offensive-security-lab-1.svg)


## CVE-2016-1000002
 gdm3 3.14.2 and possibly later has an information leak before screen lock

- [https://github.com/hdgokani/CVE2016-10000027](https://github.com/hdgokani/CVE2016-10000027) :  ![starts](https://img.shields.io/github/stars/hdgokani/CVE2016-10000027.svg) ![forks](https://img.shields.io/github/forks/hdgokani/CVE2016-10000027.svg)


## CVE-2016-5195
 Race condition in mm/gup.c in the Linux kernel 2.x through 4.x before 4.8.3 allows local users to gain privileges by leveraging incorrect handling of a copy-on-write (COW) feature to write to a read-only memory mapping, as exploited in the wild in October 2016, aka "Dirty COW."

- [https://github.com/Samuel-G3/Escalamiento-de-Privilegios-usando-el-Kernel-Exploit-Dirty-Cow](https://github.com/Samuel-G3/Escalamiento-de-Privilegios-usando-el-Kernel-Exploit-Dirty-Cow) :  ![starts](https://img.shields.io/github/stars/Samuel-G3/Escalamiento-de-Privilegios-usando-el-Kernel-Exploit-Dirty-Cow.svg) ![forks](https://img.shields.io/github/forks/Samuel-G3/Escalamiento-de-Privilegios-usando-el-Kernel-Exploit-Dirty-Cow.svg)


## CVE-2016-3088
 The Fileserver web application in Apache ActiveMQ 5.x before 5.14.0 allows remote attackers to upload and execute arbitrary files via an HTTP PUT followed by an HTTP MOVE request.

- [https://github.com/HeArtE4t3r/CVE-2016-3088](https://github.com/HeArtE4t3r/CVE-2016-3088) :  ![starts](https://img.shields.io/github/stars/HeArtE4t3r/CVE-2016-3088.svg) ![forks](https://img.shields.io/github/forks/HeArtE4t3r/CVE-2016-3088.svg)


## CVE-2015-9251
 jQuery before 3.0.0 is vulnerable to Cross-site Scripting (XSS) attacks when a cross-domain Ajax request is performed without the dataType option, causing text/javascript responses to be executed.

- [https://github.com/rox-11/xss](https://github.com/rox-11/xss) :  ![starts](https://img.shields.io/github/stars/rox-11/xss.svg) ![forks](https://img.shields.io/github/forks/rox-11/xss.svg)


## CVE-2015-6967
 Unrestricted file upload vulnerability in the My Image plugin in Nibbleblog before 4.0.5 allows remote administrators to execute arbitrary code by uploading a file with an executable extension, then accessing it via a direct request to the file in content/private/plugins/my_image/image.php.

- [https://github.com/cuerv0x/CVE-2015-6967](https://github.com/cuerv0x/CVE-2015-6967) :  ![starts](https://img.shields.io/github/stars/cuerv0x/CVE-2015-6967.svg) ![forks](https://img.shields.io/github/forks/cuerv0x/CVE-2015-6967.svg)


## CVE-2015-1578
 Multiple open redirect vulnerabilities in u5CMS before 3.9.4 allow remote attackers to redirect users to arbitrary web sites and conduct phishing attacks via a URL in the (1) pidvesa cookie to u5admin/pidvesa.php or (2) uri parameter to u5admin/meta2.php.

- [https://github.com/yaldobaoth/CVE-2015-1578-PoC](https://github.com/yaldobaoth/CVE-2015-1578-PoC) :  ![starts](https://img.shields.io/github/stars/yaldobaoth/CVE-2015-1578-PoC.svg) ![forks](https://img.shields.io/github/forks/yaldobaoth/CVE-2015-1578-PoC.svg)
- [https://github.com/yaldobaoth/CVE-2015-1578-PoC-Metasploit](https://github.com/yaldobaoth/CVE-2015-1578-PoC-Metasploit) :  ![starts](https://img.shields.io/github/stars/yaldobaoth/CVE-2015-1578-PoC-Metasploit.svg) ![forks](https://img.shields.io/github/forks/yaldobaoth/CVE-2015-1578-PoC-Metasploit.svg)


## CVE-2014-6287
 The findMacroMarker function in parserLib.pas in Rejetto HTTP File Server (aks HFS or HttpFileServer) 2.3x before 2.3c allows remote attackers to execute arbitrary programs via a %00 sequence in a search action.

- [https://github.com/Z3R0-0x30/CVE-2014-6287](https://github.com/Z3R0-0x30/CVE-2014-6287) :  ![starts](https://img.shields.io/github/stars/Z3R0-0x30/CVE-2014-6287.svg) ![forks](https://img.shields.io/github/forks/Z3R0-0x30/CVE-2014-6287.svg)


## CVE-2014-6271
 GNU Bash through 4.3 processes trailing strings after function definitions in the values of environment variables, which allows remote attackers to execute arbitrary code via a crafted environment, as demonstrated by vectors involving the ForceCommand feature in OpenSSH sshd, the mod_cgi and mod_cgid modules in the Apache HTTP Server, scripts executed by unspecified DHCP clients, and other situations in which setting the environment occurs across a privilege boundary from Bash execution, aka "ShellShock."  NOTE: the original fix for this issue was incorrect; CVE-2014-7169 has been assigned to cover the vulnerability that is still present after the incorrect fix.

- [https://github.com/knightc0de/Shellshock_vuln_Exploit](https://github.com/knightc0de/Shellshock_vuln_Exploit) :  ![starts](https://img.shields.io/github/stars/knightc0de/Shellshock_vuln_Exploit.svg) ![forks](https://img.shields.io/github/forks/knightc0de/Shellshock_vuln_Exploit.svg)


## CVE-2014-0346
 DO NOT USE THIS CANDIDATE NUMBER.  ConsultIDs: CVE-2014-0160.  Reason: This candidate is a reservation duplicate of CVE-2014-0160.  Notes: All CVE users should reference CVE-2014-0160 instead of this candidate.  All references and descriptions in this candidate have been removed to prevent accidental usage

- [https://github.com/Songul-Kizilay/CVE-2014-0346](https://github.com/Songul-Kizilay/CVE-2014-0346) :  ![starts](https://img.shields.io/github/stars/Songul-Kizilay/CVE-2014-0346.svg) ![forks](https://img.shields.io/github/forks/Songul-Kizilay/CVE-2014-0346.svg)


## CVE-2011-2523
 vsftpd 2.3.4 downloaded between 20110630 and 20110703 contains a backdoor which opens a shell on port 6200/tcp.

- [https://github.com/lghost256/vsftpd234-exploit](https://github.com/lghost256/vsftpd234-exploit) :  ![starts](https://img.shields.io/github/stars/lghost256/vsftpd234-exploit.svg) ![forks](https://img.shields.io/github/forks/lghost256/vsftpd234-exploit.svg)


## CVE-2010-5195
 Untrusted search path vulnerability in Roxio MyDVD 9 allows local users to gain privileges via a Trojan horse HomeUtils9.dll file in the current working directory, as demonstrated by a directory that contains a .dmsd or .dmsm file.  NOTE: some of these details are obtained from third party information.

- [https://github.com/CristinaPravata/dirtycaw-projet](https://github.com/CristinaPravata/dirtycaw-projet) :  ![starts](https://img.shields.io/github/stars/CristinaPravata/dirtycaw-projet.svg) ![forks](https://img.shields.io/github/forks/CristinaPravata/dirtycaw-projet.svg)


## CVE-2010-2883
 Stack-based buffer overflow in CoolType.dll in Adobe Reader and Acrobat 9.x before 9.4, and 8.x before 8.2.5 on Windows and Mac OS X, allows remote attackers to execute arbitrary code or cause a denial of service (application crash) via a PDF document with a long field in a Smart INdependent Glyphlets (SING) table in a TTF font, as exploited in the wild in September 2010. NOTE: some of these details are obtained from third party information.

- [https://github.com/avielzecharia/CVE-2010-2883](https://github.com/avielzecharia/CVE-2010-2883) :  ![starts](https://img.shields.io/github/stars/avielzecharia/CVE-2010-2883.svg) ![forks](https://img.shields.io/github/forks/avielzecharia/CVE-2010-2883.svg)


## CVE-2010-1872
 Cross-site scripting (XSS) vulnerability in cPlayer.php in FlashCard 2.6.5 and 3.0.1 allows remote attackers to inject arbitrary web script or HTML via the id parameter.  NOTE: some of these details are obtained from third party information.

- [https://github.com/LipeOzyy/CVE-2010-1872-BlazeDVD-SEH-Exploit](https://github.com/LipeOzyy/CVE-2010-1872-BlazeDVD-SEH-Exploit) :  ![starts](https://img.shields.io/github/stars/LipeOzyy/CVE-2010-1872-BlazeDVD-SEH-Exploit.svg) ![forks](https://img.shields.io/github/forks/LipeOzyy/CVE-2010-1872-BlazeDVD-SEH-Exploit.svg)


## CVE-2007-2447
 The MS-RPC functionality in smbd in Samba 3.0.0 through 3.0.25rc3 allows remote attackers to execute arbitrary commands via shell metacharacters involving the (1) SamrChangePassword function, when the "username map script" smb.conf option is enabled, and allows remote authenticated users to execute commands via shell metacharacters involving other MS-RPC functions in the (2) remote printer and (3) file share management.

- [https://github.com/DevinLiggins14/SMB-PenTest-Exploiting-CVE-2007-2447-on-Metasploitable-2](https://github.com/DevinLiggins14/SMB-PenTest-Exploiting-CVE-2007-2447-on-Metasploitable-2) :  ![starts](https://img.shields.io/github/stars/DevinLiggins14/SMB-PenTest-Exploiting-CVE-2007-2447-on-Metasploitable-2.svg) ![forks](https://img.shields.io/github/forks/DevinLiggins14/SMB-PenTest-Exploiting-CVE-2007-2447-on-Metasploitable-2.svg)
- [https://github.com/SeifEldienAhmad/Penetration-Testing-on-Metasploitable2](https://github.com/SeifEldienAhmad/Penetration-Testing-on-Metasploitable2) :  ![starts](https://img.shields.io/github/stars/SeifEldienAhmad/Penetration-Testing-on-Metasploitable2.svg) ![forks](https://img.shields.io/github/forks/SeifEldienAhmad/Penetration-Testing-on-Metasploitable2.svg)

