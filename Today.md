# Update 2021-04-28
## CVE-2021-31221
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/fireaye/ioc-scanner-CVE-2021-31221](https://github.com/fireaye/ioc-scanner-CVE-2021-31221) :  ![starts](https://img.shields.io/github/stars/fireaye/ioc-scanner-CVE-2021-31221.svg) ![forks](https://img.shields.io/github/forks/fireaye/ioc-scanner-CVE-2021-31221.svg)


## CVE-2021-26868
 Windows Graphics Component Elevation of Privilege Vulnerability

- [https://github.com/mavillon/CVE-2021-26868](https://github.com/mavillon/CVE-2021-26868) :  ![starts](https://img.shields.io/github/stars/mavillon/CVE-2021-26868.svg) ![forks](https://img.shields.io/github/forks/mavillon/CVE-2021-26868.svg)


## CVE-2021-1112
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/chenanu123/cve-2021-11123](https://github.com/chenanu123/cve-2021-11123) :  ![starts](https://img.shields.io/github/stars/chenanu123/cve-2021-11123.svg) ![forks](https://img.shields.io/github/forks/chenanu123/cve-2021-11123.svg)


## CVE-2020-8958
 Guangzhou 1GE ONU V2801RW 1.9.1-181203 through 2.9.0-181024 and V2804RGW 1.9.1-181203 through 2.9.0-181024 devices allow remote attackers to execute arbitrary OS commands via shell metacharacters in the boaform/admin/formPing Dest IP Address field.

- [https://github.com/Asjidkalam/CVE-2020-8958](https://github.com/Asjidkalam/CVE-2020-8958) :  ![starts](https://img.shields.io/github/stars/Asjidkalam/CVE-2020-8958.svg) ![forks](https://img.shields.io/github/forks/Asjidkalam/CVE-2020-8958.svg)


## CVE-2020-1938
 When using the Apache JServ Protocol (AJP), care must be taken when trusting incoming connections to Apache Tomcat. Tomcat treats AJP connections as having higher trust than, for example, a similar HTTP connection. If such connections are available to an attacker, they can be exploited in ways that may be surprising. In Apache Tomcat 9.0.0.M1 to 9.0.0.30, 8.5.0 to 8.5.50 and 7.0.0 to 7.0.99, Tomcat shipped with an AJP Connector enabled by default that listened on all configured IP addresses. It was expected (and recommended in the security guide) that this Connector would be disabled if not required. This vulnerability report identified a mechanism that allowed: - returning arbitrary files from anywhere in the web application - processing any file in the web application as a JSP Further, if the web application allowed file upload and stored those files within the web application (or the attacker was able to control the content of the web application by some other means) then this, along with the ability to process a file as a JSP, made remote code execution possible. It is important to note that mitigation is only required if an AJP port is accessible to untrusted users. Users wishing to take a defence-in-depth approach and block the vector that permits returning arbitrary files and execution as JSP may upgrade to Apache Tomcat 9.0.31, 8.5.51 or 7.0.100 or later. A number of changes were made to the default AJP Connector configuration in 9.0.31 to harden the default configuration. It is likely that users upgrading to 9.0.31, 8.5.51 or 7.0.100 or later will need to make small changes to their configurations.

- [https://github.com/streghstreek/CVE-2020-1938](https://github.com/streghstreek/CVE-2020-1938) :  ![starts](https://img.shields.io/github/stars/streghstreek/CVE-2020-1938.svg) ![forks](https://img.shields.io/github/forks/streghstreek/CVE-2020-1938.svg)


## CVE-2019-18634
 In Sudo before 1.8.26, if pwfeedback is enabled in /etc/sudoers, users can trigger a stack-based buffer overflow in the privileged sudo process. (pwfeedback is a default setting in Linux Mint and elementary OS; however, it is NOT the default for upstream and many other packages, and would exist only if enabled by an administrator.) The attacker needs to deliver a long string to the stdin of getln() in tgetpass.c.

- [https://github.com/Y3A/CVE-2019-18634](https://github.com/Y3A/CVE-2019-18634) :  ![starts](https://img.shields.io/github/stars/Y3A/CVE-2019-18634.svg) ![forks](https://img.shields.io/github/forks/Y3A/CVE-2019-18634.svg)


## CVE-2019-12725
 Zeroshell 3.9.0 is prone to a remote command execution vulnerability. Specifically, this issue occurs because the web application mishandles a few HTTP parameters. An unauthenticated attacker can exploit this issue by injecting OS commands inside the vulnerable parameters.

- [https://github.com/givemefivw/CVE-2019-12725](https://github.com/givemefivw/CVE-2019-12725) :  ![starts](https://img.shields.io/github/stars/givemefivw/CVE-2019-12725.svg) ![forks](https://img.shields.io/github/forks/givemefivw/CVE-2019-12725.svg)


## CVE-2018-8611
 An elevation of privilege vulnerability exists when the Windows kernel fails to properly handle objects in memory, aka &quot;Windows Kernel Elevation of Privilege Vulnerability.&quot; This affects Windows 7, Windows Server 2012 R2, Windows RT 8.1, Windows Server 2008, Windows Server 2019, Windows Server 2012, Windows 8.1, Windows Server 2016, Windows Server 2008 R2, Windows 10, Windows 10 Servers.

- [https://github.com/lsw29475/CVE-2018-8611](https://github.com/lsw29475/CVE-2018-8611) :  ![starts](https://img.shields.io/github/stars/lsw29475/CVE-2018-8611.svg) ![forks](https://img.shields.io/github/forks/lsw29475/CVE-2018-8611.svg)


## CVE-2018-1273
 Spring Data Commons, versions prior to 1.13 to 1.13.10, 2.0 to 2.0.5, and older unsupported versions, contain a property binder vulnerability caused by improper neutralization of special elements. An unauthenticated remote malicious user (or attacker) can supply specially crafted request parameters against Spring Data REST backed HTTP resources or using Spring Data's projection-based request payload binding hat can lead to a remote code execution attack.

- [https://github.com/jas502n/cve-2018-1273](https://github.com/jas502n/cve-2018-1273) :  ![starts](https://img.shields.io/github/stars/jas502n/cve-2018-1273.svg) ![forks](https://img.shields.io/github/forks/jas502n/cve-2018-1273.svg)

