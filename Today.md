# Update 2021-08-16
## CVE-2021-38699
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/Justin-1993/CVE-2021-38699](https://github.com/Justin-1993/CVE-2021-38699) :  ![starts](https://img.shields.io/github/stars/Justin-1993/CVE-2021-38699.svg) ![forks](https://img.shields.io/github/forks/Justin-1993/CVE-2021-38699.svg)


## CVE-2021-36949
 Microsoft Azure Active Directory Connect Authentication Bypass Vulnerability

- [https://github.com/Maxwitat/Check-AAD-Connect-for-CVE-2021-36949-vulnerability](https://github.com/Maxwitat/Check-AAD-Connect-for-CVE-2021-36949-vulnerability) :  ![starts](https://img.shields.io/github/stars/Maxwitat/Check-AAD-Connect-for-CVE-2021-36949-vulnerability.svg) ![forks](https://img.shields.io/github/forks/Maxwitat/Check-AAD-Connect-for-CVE-2021-36949-vulnerability.svg)


## CVE-2021-2394
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Core). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0, 12.2.1.4.0 and 14.1.1.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3, IIOP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/lz2y/CVE-2021-2394](https://github.com/lz2y/CVE-2021-2394) :  ![starts](https://img.shields.io/github/stars/lz2y/CVE-2021-2394.svg) ![forks](https://img.shields.io/github/forks/lz2y/CVE-2021-2394.svg)


## CVE-2020-1938
 When using the Apache JServ Protocol (AJP), care must be taken when trusting incoming connections to Apache Tomcat. Tomcat treats AJP connections as having higher trust than, for example, a similar HTTP connection. If such connections are available to an attacker, they can be exploited in ways that may be surprising. In Apache Tomcat 9.0.0.M1 to 9.0.0.30, 8.5.0 to 8.5.50 and 7.0.0 to 7.0.99, Tomcat shipped with an AJP Connector enabled by default that listened on all configured IP addresses. It was expected (and recommended in the security guide) that this Connector would be disabled if not required. This vulnerability report identified a mechanism that allowed: - returning arbitrary files from anywhere in the web application - processing any file in the web application as a JSP Further, if the web application allowed file upload and stored those files within the web application (or the attacker was able to control the content of the web application by some other means) then this, along with the ability to process a file as a JSP, made remote code execution possible. It is important to note that mitigation is only required if an AJP port is accessible to untrusted users. Users wishing to take a defence-in-depth approach and block the vector that permits returning arbitrary files and execution as JSP may upgrade to Apache Tomcat 9.0.31, 8.5.51 or 7.0.100 or later. A number of changes were made to the default AJP Connector configuration in 9.0.31 to harden the default configuration. It is likely that users upgrading to 9.0.31, 8.5.51 or 7.0.100 or later will need to make small changes to their configurations.

- [https://github.com/jptr218/ghostcat](https://github.com/jptr218/ghostcat) :  ![starts](https://img.shields.io/github/stars/jptr218/ghostcat.svg) ![forks](https://img.shields.io/github/forks/jptr218/ghostcat.svg)


## CVE-2019-15107
 An issue was discovered in Webmin &lt;=1.920. The parameter old in password_change.cgi contains a command injection vulnerability.

- [https://github.com/whokilleddb/CVE-2019-15107](https://github.com/whokilleddb/CVE-2019-15107) :  ![starts](https://img.shields.io/github/stars/whokilleddb/CVE-2019-15107.svg) ![forks](https://img.shields.io/github/forks/whokilleddb/CVE-2019-15107.svg)


## CVE-2014-0160
 The (1) TLS and (2) DTLS implementations in OpenSSL 1.0.1 before 1.0.1g do not properly handle Heartbeat Extension packets, which allows remote attackers to obtain sensitive information from process memory via crafted packets that trigger a buffer over-read, as demonstrated by reading private keys, related to d1_both.c and t1_lib.c, aka the Heartbleed bug.

- [https://github.com/pierceoneill/bleeding-heart](https://github.com/pierceoneill/bleeding-heart) :  ![starts](https://img.shields.io/github/stars/pierceoneill/bleeding-heart.svg) ![forks](https://img.shields.io/github/forks/pierceoneill/bleeding-heart.svg)


## CVE-2011-1249
 The Ancillary Function Driver (AFD) in afd.sys in Microsoft Windows XP SP2 and SP3, Windows Server 2003 SP2, Windows Vista SP1 and SP2, Windows Server 2008 Gold, SP2, R2, and R2 SP1, and Windows 7 Gold and SP1 does not properly validate user-mode input, which allows local users to gain privileges via a crafted application, aka &quot;Ancillary Function Driver Elevation of Privilege Vulnerability.&quot;

- [https://github.com/3hydraking/CVE-2011-1249](https://github.com/3hydraking/CVE-2011-1249) :  ![starts](https://img.shields.io/github/stars/3hydraking/CVE-2011-1249.svg) ![forks](https://img.shields.io/github/forks/3hydraking/CVE-2011-1249.svg)

