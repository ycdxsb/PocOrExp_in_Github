# Update 2024-07-12
## CVE-2024-37032
 Ollama before 0.1.34 does not validate the format of the digest (sha256 with 64 hex digits) when getting the model path, and thus mishandles the TestGetBlobsPath test cases such as fewer than 64 hex digits, more than 64 hex digits, or an initial ../ substring.

- [https://github.com/ahboon/CVE-2024-37032-scanner](https://github.com/ahboon/CVE-2024-37032-scanner) :  ![starts](https://img.shields.io/github/stars/ahboon/CVE-2024-37032-scanner.svg) ![forks](https://img.shields.io/github/forks/ahboon/CVE-2024-37032-scanner.svg)


## CVE-2024-36991
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/Cappricio-Securities/CVE-2024-36991](https://github.com/Cappricio-Securities/CVE-2024-36991) :  ![starts](https://img.shields.io/github/stars/Cappricio-Securities/CVE-2024-36991.svg) ![forks](https://img.shields.io/github/forks/Cappricio-Securities/CVE-2024-36991.svg)


## CVE-2024-34102
 Adobe Commerce versions 2.4.7, 2.4.6-p5, 2.4.5-p7, 2.4.4-p8 and earlier are affected by an Improper Restriction of XML External Entity Reference ('XXE') vulnerability that could result in arbitrary code execution. An attacker could exploit this vulnerability by sending a crafted XML document that references external entities. Exploitation of this issue does not require user interaction.

- [https://github.com/Ex-Arn/CVE-2024-34102-RCE](https://github.com/Ex-Arn/CVE-2024-34102-RCE) :  ![starts](https://img.shields.io/github/stars/Ex-Arn/CVE-2024-34102-RCE.svg) ![forks](https://img.shields.io/github/forks/Ex-Arn/CVE-2024-34102-RCE.svg)


## CVE-2024-29510
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/swsmith2391/CVE-2024-29510](https://github.com/swsmith2391/CVE-2024-29510) :  ![starts](https://img.shields.io/github/stars/swsmith2391/CVE-2024-29510.svg) ![forks](https://img.shields.io/github/forks/swsmith2391/CVE-2024-29510.svg)


## CVE-2024-23692
 Rejetto HTTP File Server, up to and including version 2.3m, is vulnerable to a template injection vulnerability. This vulnerability allows a remote, unauthenticated attacker to execute arbitrary commands on the affected system by sending a specially crafted HTTP request. As of the CVE assignment date, Rejetto HFS 2.3m is no longer supported.

- [https://github.com/pradeepboo/Rejetto-HFS-2.x-RCE-CVE-2024-23692-](https://github.com/pradeepboo/Rejetto-HFS-2.x-RCE-CVE-2024-23692-) :  ![starts](https://img.shields.io/github/stars/pradeepboo/Rejetto-HFS-2.x-RCE-CVE-2024-23692-.svg) ![forks](https://img.shields.io/github/forks/pradeepboo/Rejetto-HFS-2.x-RCE-CVE-2024-23692-.svg)


## CVE-2024-22274
 The vCenter Server contains an authenticated remote code execution vulnerability. A malicious actor with administrative privileges on the vCenter appliance shell may exploit this issue to run arbitrary commands on the underlying operating system.

- [https://github.com/ninhpn1337/CVE-2024-22274](https://github.com/ninhpn1337/CVE-2024-22274) :  ![starts](https://img.shields.io/github/stars/ninhpn1337/CVE-2024-22274.svg) ![forks](https://img.shields.io/github/forks/ninhpn1337/CVE-2024-22274.svg)


## CVE-2024-4577
 In PHP versions 8.1.* before 8.1.29, 8.2.* before 8.2.20, 8.3.* before 8.3.8, when using Apache and PHP-CGI on Windows, if the system is set up to use certain code pages, Windows may use &quot;Best-Fit&quot; behavior to replace characters in command line given to Win32 API functions. PHP CGI module may misinterpret those characters as PHP options, which may allow a malicious user to pass options to PHP binary being run, and thus reveal the source code of scripts, run arbitrary PHP code on the server, etc.

- [https://github.com/bibo318/CVE-2024-4577-RCE-ATTACK](https://github.com/bibo318/CVE-2024-4577-RCE-ATTACK) :  ![starts](https://img.shields.io/github/stars/bibo318/CVE-2024-4577-RCE-ATTACK.svg) ![forks](https://img.shields.io/github/forks/bibo318/CVE-2024-4577-RCE-ATTACK.svg)


## CVE-2023-32784
 In KeePass 2.x before 2.54, it is possible to recover the cleartext master password from a memory dump, even when a workspace is locked or no longer running. The memory dump can be a KeePass process dump, swap file (pagefile.sys), hibernation file (hiberfil.sys), or RAM dump of the entire system. The first character cannot be recovered. In 2.54, there is different API usage and/or random string insertion for mitigation.

- [https://github.com/Cmadhushanka/CVE-2023-32784-Exploitation](https://github.com/Cmadhushanka/CVE-2023-32784-Exploitation) :  ![starts](https://img.shields.io/github/stars/Cmadhushanka/CVE-2023-32784-Exploitation.svg) ![forks](https://img.shields.io/github/forks/Cmadhushanka/CVE-2023-32784-Exploitation.svg)


## CVE-2022-27646
 This vulnerability allows network-adjacent attackers to execute arbitrary code on affected installations of NETGEAR R6700v3 1.0.4.120_10.0.91 routers. Although authentication is required to exploit this vulnerability, the existing authentication mechanism can be bypassed. The specific flaw exists within the circled daemon. A crafted circleinfo.txt file can trigger an overflow of a fixed-length stack-based buffer. An attacker can leverage this vulnerability to execute code in the context of root. Was ZDI-CAN-15879.

- [https://github.com/cyber-defence-campus/netgear_r6700v3_circled](https://github.com/cyber-defence-campus/netgear_r6700v3_circled) :  ![starts](https://img.shields.io/github/stars/cyber-defence-campus/netgear_r6700v3_circled.svg) ![forks](https://img.shields.io/github/forks/cyber-defence-campus/netgear_r6700v3_circled.svg)


## CVE-2020-25540
 ThinkAdmin v6 is affected by a directory traversal vulnerability. An unauthorized attacker can read arbitrarily file on a remote server via GET request encode parameter.

- [https://github.com/simonlee-hello/CVE-2020-25540](https://github.com/simonlee-hello/CVE-2020-25540) :  ![starts](https://img.shields.io/github/stars/simonlee-hello/CVE-2020-25540.svg) ![forks](https://img.shields.io/github/forks/simonlee-hello/CVE-2020-25540.svg)


## CVE-2017-11882
 Microsoft Office 2007 Service Pack 3, Microsoft Office 2010 Service Pack 2, Microsoft Office 2013 Service Pack 1, and Microsoft Office 2016 allow an attacker to run arbitrary code in the context of the current user by failing to properly handle objects in memory, aka &quot;Microsoft Office Memory Corruption Vulnerability&quot;. This CVE ID is unique from CVE-2017-11884.

- [https://github.com/jadeapar/Dragonfish-s-Malware-Cyber-Analysis](https://github.com/jadeapar/Dragonfish-s-Malware-Cyber-Analysis) :  ![starts](https://img.shields.io/github/stars/jadeapar/Dragonfish-s-Malware-Cyber-Analysis.svg) ![forks](https://img.shields.io/github/forks/jadeapar/Dragonfish-s-Malware-Cyber-Analysis.svg)


## CVE-2017-5638
 The Jakarta Multipart parser in Apache Struts 2 2.3.x before 2.3.32 and 2.5.x before 2.5.10.1 has incorrect exception handling and error-message generation during file-upload attempts, which allows remote attackers to execute arbitrary commands via a crafted Content-Type, Content-Disposition, or Content-Length HTTP header, as exploited in the wild in March 2017 with a Content-Type header containing a #cmd= string.

- [https://github.com/Nithylesh/web-application-firewall-](https://github.com/Nithylesh/web-application-firewall-) :  ![starts](https://img.shields.io/github/stars/Nithylesh/web-application-firewall-.svg) ![forks](https://img.shields.io/github/forks/Nithylesh/web-application-firewall-.svg)


## CVE-2006-5051
 Signal handler race condition in OpenSSH before 4.4 allows remote attackers to cause a denial of service (crash), and possibly execute arbitrary code if GSSAPI authentication is enabled, via unspecified vectors that lead to a double-free.

- [https://github.com/ThemeHackers/CVE-2024-6387](https://github.com/ThemeHackers/CVE-2024-6387) :  ![starts](https://img.shields.io/github/stars/ThemeHackers/CVE-2024-6387.svg) ![forks](https://img.shields.io/github/forks/ThemeHackers/CVE-2024-6387.svg)

