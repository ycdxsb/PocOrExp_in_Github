# Update 2022-09-25
## CVE-2022-39197
 An XSS (Cross Site Scripting) vulnerability was found in HelpSystems Cobalt Strike through 4.7 that allowed a remote attacker to execute HTML on the Cobalt Strike teamserver. To exploit the vulnerability, one must first inspect a Cobalt Strike payload, and then modify the username field in the payload (or create a new payload with the extracted information and then modify that username field to be malformed).

- [https://github.com/xzajyjs/CVE-2022-39197-POC](https://github.com/xzajyjs/CVE-2022-39197-POC) :  ![starts](https://img.shields.io/github/stars/xzajyjs/CVE-2022-39197-POC.svg) ![forks](https://img.shields.io/github/forks/xzajyjs/CVE-2022-39197-POC.svg)


## CVE-2022-36804
 Multiple API endpoints in Atlassian Bitbucket Server and Data Center 7.0.0 before version 7.6.17, from version 7.7.0 before version 7.17.10, from version 7.18.0 before version 7.21.4, from version 8.0.0 before version 8.0.3, from version 8.1.0 before version 8.1.3, and from version 8.2.0 before version 8.2.2, and from version 8.3.0 before 8.3.1 allows remote attackers with read permissions to a public or private Bitbucket repository to execute arbitrary code by sending a malicious HTTP request. This vulnerability was reported via our Bug Bounty Program by TheGrandPew.

- [https://github.com/Chocapikk/CVE-2022-36804-ReverseShell](https://github.com/Chocapikk/CVE-2022-36804-ReverseShell) :  ![starts](https://img.shields.io/github/stars/Chocapikk/CVE-2022-36804-ReverseShell.svg) ![forks](https://img.shields.io/github/forks/Chocapikk/CVE-2022-36804-ReverseShell.svg)
- [https://github.com/JRandomSage/CVE-2022-36804-MASS-RCE](https://github.com/JRandomSage/CVE-2022-36804-MASS-RCE) :  ![starts](https://img.shields.io/github/stars/JRandomSage/CVE-2022-36804-MASS-RCE.svg) ![forks](https://img.shields.io/github/forks/JRandomSage/CVE-2022-36804-MASS-RCE.svg)


## CVE-2022-32548
 An issue was discovered on certain DrayTek Vigor routers before July 2022 such as the Vigor3910 before 4.3.1.1. /cgi-bin/wlogin.cgi has a buffer overflow via the username or password to the aa or ab field.

- [https://github.com/expl0despl0it/CVE-2022-32548](https://github.com/expl0despl0it/CVE-2022-32548) :  ![starts](https://img.shields.io/github/stars/expl0despl0it/CVE-2022-32548.svg) ![forks](https://img.shields.io/github/forks/expl0despl0it/CVE-2022-32548.svg)


## CVE-2022-31798
 Nortek Linear eMerge E3-Series 0.32-07p devices are vulnerable to /card_scan.php?CardFormatNo= XSS with session fixation (via PHPSESSID) when they are chained together. This would allow an attacker to take over an admin account or a user account.

- [https://github.com/omarhashem123/CVE-2022-31798](https://github.com/omarhashem123/CVE-2022-31798) :  ![starts](https://img.shields.io/github/stars/omarhashem123/CVE-2022-31798.svg) ![forks](https://img.shields.io/github/forks/omarhashem123/CVE-2022-31798.svg)


## CVE-2022-31499
 Nortek Linear eMerge E3-Series devices before 0.32-08f allow an unauthenticated attacker to inject OS commands via ReaderNo. NOTE: this issue exists because of an incomplete fix for CVE-2019-7256.

- [https://github.com/omarhashem123/CVE-2022-31499](https://github.com/omarhashem123/CVE-2022-31499) :  ![starts](https://img.shields.io/github/stars/omarhashem123/CVE-2022-31499.svg) ![forks](https://img.shields.io/github/forks/omarhashem123/CVE-2022-31499.svg)


## CVE-2022-31269
 Nortek Linear eMerge E3-Series devices through 0.32-09c place admin credentials in /test.txt that allow an attacker to open a building's doors. (This occurs in situations where the CVE-2019-7271 default credentials have been changed.)

- [https://github.com/omarhashem123/CVE-2022-31269](https://github.com/omarhashem123/CVE-2022-31269) :  ![starts](https://img.shields.io/github/stars/omarhashem123/CVE-2022-31269.svg) ![forks](https://img.shields.io/github/forks/omarhashem123/CVE-2022-31269.svg)


## CVE-2022-26809
 Remote Procedure Call Runtime Remote Code Execution Vulnerability. This CVE ID is unique from CVE-2022-24492, CVE-2022-24528.

- [https://github.com/Ziggy78/CVE-2022-26809-FULL-RCE](https://github.com/Ziggy78/CVE-2022-26809-FULL-RCE) :  ![starts](https://img.shields.io/github/stars/Ziggy78/CVE-2022-26809-FULL-RCE.svg) ![forks](https://img.shields.io/github/forks/Ziggy78/CVE-2022-26809-FULL-RCE.svg)


## CVE-2022-26138
 The Atlassian Questions For Confluence app for Confluence Server and Data Center creates a Confluence user account in the confluence-users group with the username disabledsystemuser and a hardcoded password. A remote, unauthenticated attacker with knowledge of the hardcoded password could exploit this to log into Confluence and access all content accessible to users in the confluence-users group. This user account is created when installing versions 2.7.34, 2.7.35, and 3.0.2 of the app.

- [https://github.com/shavchen/CVE-2022-26138](https://github.com/shavchen/CVE-2022-26138) :  ![starts](https://img.shields.io/github/stars/shavchen/CVE-2022-26138.svg) ![forks](https://img.shields.io/github/forks/shavchen/CVE-2022-26138.svg)


## CVE-2022-25845
 The package com.alibaba:fastjson before 1.2.83 are vulnerable to Deserialization of Untrusted Data by bypassing the default autoType shutdown restrictions, which is possible under certain conditions. Exploiting this vulnerability allows attacking remote servers. Workaround: If upgrading is not possible, you can enable [safeMode](https://github.com/alibaba/fastjson/wiki/fastjson_safemode).

- [https://github.com/expl0despl0it/CVE-2022-25845](https://github.com/expl0despl0it/CVE-2022-25845) :  ![starts](https://img.shields.io/github/stars/expl0despl0it/CVE-2022-25845.svg) ![forks](https://img.shields.io/github/forks/expl0despl0it/CVE-2022-25845.svg)


## CVE-2022-20841
 Multiple vulnerabilities in Cisco Small Business RV160, RV260, RV340, and RV345 Series Routers could allow an unauthenticated, remote attacker to execute arbitrary code or cause a denial of service (DoS) condition on an affected device. For more information about these vulnerabilities, see the Details section of this advisory.

- [https://github.com/expl0despl0it/CVE-2022-20841](https://github.com/expl0despl0it/CVE-2022-20841) :  ![starts](https://img.shields.io/github/stars/expl0despl0it/CVE-2022-20841.svg) ![forks](https://img.shields.io/github/forks/expl0despl0it/CVE-2022-20841.svg)


## CVE-2021-44158
 ASUS RT-AX56U Wi-Fi Router is vulnerable to stack-based buffer overflow due to improper validation for httpd parameter length. An authenticated local area network attacker can launch arbitrary code execution to control the system or disrupt service.

- [https://github.com/expl0despl0it/CVE-2021-44158](https://github.com/expl0despl0it/CVE-2021-44158) :  ![starts](https://img.shields.io/github/stars/expl0despl0it/CVE-2021-44158.svg) ![forks](https://img.shields.io/github/forks/expl0despl0it/CVE-2021-44158.svg)


## CVE-2020-7247
 smtp_mailaddr in smtp_session.c in OpenSMTPD 6.6, as used in OpenBSD 6.6 and other products, allows remote attackers to execute arbitrary commands as root via a crafted SMTP session, as demonstrated by shell metacharacters in a MAIL FROM field. This affects the &quot;uncommented&quot; default configuration. The issue exists because of an incorrect return value upon failure of input validation.

- [https://github.com/bytescrappers/CVE-2020-7247](https://github.com/bytescrappers/CVE-2020-7247) :  ![starts](https://img.shields.io/github/stars/bytescrappers/CVE-2020-7247.svg) ![forks](https://img.shields.io/github/forks/bytescrappers/CVE-2020-7247.svg)


## CVE-2020-1938
 When using the Apache JServ Protocol (AJP), care must be taken when trusting incoming connections to Apache Tomcat. Tomcat treats AJP connections as having higher trust than, for example, a similar HTTP connection. If such connections are available to an attacker, they can be exploited in ways that may be surprising. In Apache Tomcat 9.0.0.M1 to 9.0.0.30, 8.5.0 to 8.5.50 and 7.0.0 to 7.0.99, Tomcat shipped with an AJP Connector enabled by default that listened on all configured IP addresses. It was expected (and recommended in the security guide) that this Connector would be disabled if not required. This vulnerability report identified a mechanism that allowed: - returning arbitrary files from anywhere in the web application - processing any file in the web application as a JSP Further, if the web application allowed file upload and stored those files within the web application (or the attacker was able to control the content of the web application by some other means) then this, along with the ability to process a file as a JSP, made remote code execution possible. It is important to note that mitigation is only required if an AJP port is accessible to untrusted users. Users wishing to take a defence-in-depth approach and block the vector that permits returning arbitrary files and execution as JSP may upgrade to Apache Tomcat 9.0.31, 8.5.51 or 7.0.100 or later. A number of changes were made to the default AJP Connector configuration in 9.0.31 to harden the default configuration. It is likely that users upgrading to 9.0.31, 8.5.51 or 7.0.100 or later will need to make small changes to their configurations.

- [https://github.com/h7hac9/CVE-2020-1938](https://github.com/h7hac9/CVE-2020-1938) :  ![starts](https://img.shields.io/github/stars/h7hac9/CVE-2020-1938.svg) ![forks](https://img.shields.io/github/forks/h7hac9/CVE-2020-1938.svg)


## CVE-2018-6242
 Some NVIDIA Tegra mobile processors released prior to 2016 contain a buffer overflow vulnerability in BootROM Recovery Mode (RCM). An attacker with physical access to the device's USB and the ability to force the device to reboot into RCM could exploit the vulnerability to execute unverified code.

- [https://github.com/Haruster/Haruster-Nintendo-CVE-2018-6242](https://github.com/Haruster/Haruster-Nintendo-CVE-2018-6242) :  ![starts](https://img.shields.io/github/stars/Haruster/Haruster-Nintendo-CVE-2018-6242.svg) ![forks](https://img.shields.io/github/forks/Haruster/Haruster-Nintendo-CVE-2018-6242.svg)

