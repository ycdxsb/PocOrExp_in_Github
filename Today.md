# Update 2024-03-22
## CVE-2024-1086
 A use-after-free vulnerability in the Linux kernel's netfilter: nf_tables component can be exploited to achieve local privilege escalation. The nft_verdict_init() function allows positive values as drop error within the hook verdict, and hence the nf_hook_slow() function can cause a double free vulnerability when NF_DROP is issued with a drop error which resembles NF_ACCEPT. We recommend upgrading past commit f342de4e2f33e0e39165d8639387aa6c19dff660.

- [https://github.com/Notselwyn/CVE-2024-1086](https://github.com/Notselwyn/CVE-2024-1086) :  ![starts](https://img.shields.io/github/stars/Notselwyn/CVE-2024-1086.svg) ![forks](https://img.shields.io/github/forks/Notselwyn/CVE-2024-1086.svg)


## CVE-2023-26049
 Jetty is a java based web server and servlet engine. Nonstandard cookie parsing in Jetty may allow an attacker to smuggle cookies within other cookies, or otherwise perform unintended behavior by tampering with the cookie parsing mechanism. If Jetty sees a cookie VALUE that starts with `&quot;` (double quote), it will continue to read the cookie string until it sees a closing quote -- even if a semicolon is encountered. So, a cookie header such as: `DISPLAY_LANGUAGE=&quot;b; JSESSIONID=1337; c=d&quot;` will be parsed as one cookie, with the name DISPLAY_LANGUAGE and a value of b; JSESSIONID=1337; c=d instead of 3 separate cookies. This has security implications because if, say, JSESSIONID is an HttpOnly cookie, and the DISPLAY_LANGUAGE cookie value is rendered on the page, an attacker can smuggle the JSESSIONID cookie into the DISPLAY_LANGUAGE cookie and thereby exfiltrate it. This is significant when an intermediary is enacting some policy based on cookies, so a smuggled cookie can bypass that policy yet still be seen by the Jetty server or its logging system. This issue has been addressed in versions 9.4.51, 10.0.14, 11.0.14, and 12.0.0.beta0 and users are advised to upgrade. There are no known workarounds for this issue.

- [https://github.com/hshivhare67/Jetty_v9.4.31_CVE-2023-26049](https://github.com/hshivhare67/Jetty_v9.4.31_CVE-2023-26049) :  ![starts](https://img.shields.io/github/stars/hshivhare67/Jetty_v9.4.31_CVE-2023-26049.svg) ![forks](https://img.shields.io/github/forks/hshivhare67/Jetty_v9.4.31_CVE-2023-26049.svg)


## CVE-2023-23397
 Microsoft Outlook Elevation of Privilege Vulnerability

- [https://github.com/TheUnknownSoul/CVE-2023-23397-PoW](https://github.com/TheUnknownSoul/CVE-2023-23397-PoW) :  ![starts](https://img.shields.io/github/stars/TheUnknownSoul/CVE-2023-23397-PoW.svg) ![forks](https://img.shields.io/github/forks/TheUnknownSoul/CVE-2023-23397-PoW.svg)


## CVE-2023-21282
 In TRANSPOSER_SETTINGS of lpp_tran.h, there is a possible out of bounds write due to an incorrect bounds check. This could lead to remote code execution with no additional execution privileges needed. User interaction is needed for exploitation.

- [https://github.com/Trinadh465/external_aac_android-4.2.2_r1_CVE-2023-21282](https://github.com/Trinadh465/external_aac_android-4.2.2_r1_CVE-2023-21282) :  ![starts](https://img.shields.io/github/stars/Trinadh465/external_aac_android-4.2.2_r1_CVE-2023-21282.svg) ![forks](https://img.shields.io/github/forks/Trinadh465/external_aac_android-4.2.2_r1_CVE-2023-21282.svg)


## CVE-2021-43217
 Windows Encrypting File System (EFS) Remote Code Execution Vulnerability

- [https://github.com/JolynNgSC/EFS_CVE-2021-43217](https://github.com/JolynNgSC/EFS_CVE-2021-43217) :  ![starts](https://img.shields.io/github/stars/JolynNgSC/EFS_CVE-2021-43217.svg) ![forks](https://img.shields.io/github/forks/JolynNgSC/EFS_CVE-2021-43217.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/vuongnv3389-sec/cve-2021-41773](https://github.com/vuongnv3389-sec/cve-2021-41773) :  ![starts](https://img.shields.io/github/stars/vuongnv3389-sec/cve-2021-41773.svg) ![forks](https://img.shields.io/github/forks/vuongnv3389-sec/cve-2021-41773.svg)
- [https://github.com/skentagon/CVE-2021-41773](https://github.com/skentagon/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/skentagon/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/skentagon/CVE-2021-41773.svg)


## CVE-2021-31630
 Command Injection in Open PLC Webserver v3 allows remote attackers to execute arbitrary code via the &quot;Hardware Layer Code Box&quot; component on the &quot;/hardware&quot; page of the application.

- [https://github.com/Hunt3r0x/CVE-2021-31630-HTB](https://github.com/Hunt3r0x/CVE-2021-31630-HTB) :  ![starts](https://img.shields.io/github/stars/Hunt3r0x/CVE-2021-31630-HTB.svg) ![forks](https://img.shields.io/github/forks/Hunt3r0x/CVE-2021-31630-HTB.svg)


## CVE-2021-3492
 Shiftfs, an out-of-tree stacking file system included in Ubuntu Linux kernels, did not properly handle faults occurring during copy_from_user() correctly. These could lead to either a double-free situation or memory not being freed at all. An attacker could use this to cause a denial of service (kernel memory exhaustion) or gain privileges via executing arbitrary code. AKA ZDI-CAN-13562.

- [https://github.com/synacktiv/CVE-2021-3492](https://github.com/synacktiv/CVE-2021-3492) :  ![starts](https://img.shields.io/github/stars/synacktiv/CVE-2021-3492.svg) ![forks](https://img.shields.io/github/forks/synacktiv/CVE-2021-3492.svg)


## CVE-2020-11652
 An issue was discovered in SaltStack Salt before 2019.2.4 and 3000 before 3000.2. The salt-master process ClearFuncs class allows access to some methods that improperly sanitize paths. These methods allow arbitrary directory access to authenticated users.

- [https://github.com/limon768/CVE-2020-11652-POC](https://github.com/limon768/CVE-2020-11652-POC) :  ![starts](https://img.shields.io/github/stars/limon768/CVE-2020-11652-POC.svg) ![forks](https://img.shields.io/github/forks/limon768/CVE-2020-11652-POC.svg)


## CVE-2020-11651
 An issue was discovered in SaltStack Salt before 2019.2.4 and 3000 before 3000.2. The salt-master process ClearFuncs class does not properly validate method calls. This allows a remote user to access some methods without authentication. These methods can be used to retrieve user tokens from the salt master and/or run arbitrary commands on salt minions.

- [https://github.com/limon768/CVE-2020-11652-POC](https://github.com/limon768/CVE-2020-11652-POC) :  ![starts](https://img.shields.io/github/stars/limon768/CVE-2020-11652-POC.svg) ![forks](https://img.shields.io/github/forks/limon768/CVE-2020-11652-POC.svg)


## CVE-2020-1472
 An elevation of privilege vulnerability exists when an attacker establishes a vulnerable Netlogon secure channel connection to a domain controller, using the Netlogon Remote Protocol (MS-NRPC). An attacker who successfully exploited the vulnerability could run a specially crafted application on a device on the network. To exploit the vulnerability, an unauthenticated attacker would be required to use MS-NRPC to connect to a domain controller to obtain domain administrator access. Microsoft is addressing the vulnerability in a phased two-part rollout. These updates address the vulnerability by modifying how Netlogon handles the usage of Netlogon secure channels. For guidelines on how to manage the changes required for this vulnerability and more information on the phased rollout, see How to manage the changes in Netlogon secure channel connections associated with CVE-2020-1472 (updated September 28, 2020). When the second phase of Windows updates become available in Q1 2021, customers will be notified via a revision to this security vulnerability. If you wish to be notified when these updates are released, we recommend that you register for the security notifications mailer to be alerted of content changes to this advisory. See Microsoft Technical Security Notifications.

- [https://github.com/JolynNgSC/Zerologon_CVE-2020-1472](https://github.com/JolynNgSC/Zerologon_CVE-2020-1472) :  ![starts](https://img.shields.io/github/stars/JolynNgSC/Zerologon_CVE-2020-1472.svg) ![forks](https://img.shields.io/github/forks/JolynNgSC/Zerologon_CVE-2020-1472.svg)


## CVE-2019-16253
 The Text-to-speech Engine (aka SamsungTTS) application before 3.0.02.7 and 3.0.00.101 for Android allows a local attacker to escalate privileges, e.g., to system privileges. The Samsung case ID is 101755.

- [https://github.com/k0mraid3/K0mraid3s-System-Shell-PREBUILT](https://github.com/k0mraid3/K0mraid3s-System-Shell-PREBUILT) :  ![starts](https://img.shields.io/github/stars/k0mraid3/K0mraid3s-System-Shell-PREBUILT.svg) ![forks](https://img.shields.io/github/forks/k0mraid3/K0mraid3s-System-Shell-PREBUILT.svg)


## CVE-2012-2982
 file/show.cgi in Webmin 1.590 and earlier allows remote authenticated users to execute arbitrary commands via an invalid character in a pathname, as demonstrated by a | (pipe) character.

- [https://github.com/CpyRe/CVE-2012-2982](https://github.com/CpyRe/CVE-2012-2982) :  ![starts](https://img.shields.io/github/stars/CpyRe/CVE-2012-2982.svg) ![forks](https://img.shields.io/github/forks/CpyRe/CVE-2012-2982.svg)

