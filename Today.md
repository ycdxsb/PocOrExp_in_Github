# Update 2021-06-10
## CVE-2021-26714
 The Enterprise License Manager portal in Mitel MiContact Center Enterprise before 9.4 could allow a user to access restricted files and folders due to insufficient access control. A successful exploit could allow an attacker to view and modify application data via Directory Traversal.

- [https://github.com/PwCNO-CTO/CVE-2021-26714](https://github.com/PwCNO-CTO/CVE-2021-26714) :  ![starts](https://img.shields.io/github/stars/PwCNO-CTO/CVE-2021-26714.svg) ![forks](https://img.shields.io/github/forks/PwCNO-CTO/CVE-2021-26714.svg)


## CVE-2021-21234
 spring-boot-actuator-logview in a library that adds a simple logfile viewer as spring boot actuator endpoint. It is maven package &quot;eu.hinsch:spring-boot-actuator-logview&quot;. In spring-boot-actuator-logview before version 0.2.13 there is a directory traversal vulnerability. The nature of this library is to expose a log file directory via admin (spring boot actuator) HTTP endpoints. Both the filename to view and a base folder (relative to the logging folder root) can be specified via request parameters. While the filename parameter was checked to prevent directory traversal exploits (so that `filename=../somefile` would not work), the base folder parameter was not sufficiently checked, so that `filename=somefile&amp;base=../` could access a file outside the logging base directory). The vulnerability has been patched in release 0.2.13. Any users of 0.2.12 should be able to update without any issues as there are no other changes in that release. There is no workaround to fix the vulnerability other than updating or removing the dependency. However, removing read access of the user the application is run with to any directory not required for running the application can limit the impact. Additionally, access to the logview endpoint can be limited by deploying the application behind a reverse proxy.

- [https://github.com/PwCNO-CTO/CVE-2021-21234](https://github.com/PwCNO-CTO/CVE-2021-21234) :  ![starts](https://img.shields.io/github/stars/PwCNO-CTO/CVE-2021-21234.svg) ![forks](https://img.shields.io/github/forks/PwCNO-CTO/CVE-2021-21234.svg)


## CVE-2020-8835
 In the Linux kernel 5.5.0 and newer, the bpf verifier (kernel/bpf/verifier.c) did not properly restrict the register bounds for 32-bit operations, leading to out-of-bounds reads and writes in kernel memory. The vulnerability also affects the Linux 5.4 stable series, starting with v5.4.7, as the introducing commit was backported to that branch. This vulnerability was fixed in 5.6.1, 5.5.14, and 5.4.29. (issue is aka ZDI-CAN-10780)

- [https://github.com/digamma-ai/CVE-2020-8835-verification](https://github.com/digamma-ai/CVE-2020-8835-verification) :  ![starts](https://img.shields.io/github/stars/digamma-ai/CVE-2020-8835-verification.svg) ![forks](https://img.shields.io/github/forks/digamma-ai/CVE-2020-8835-verification.svg)


## CVE-2020-1938
 When using the Apache JServ Protocol (AJP), care must be taken when trusting incoming connections to Apache Tomcat. Tomcat treats AJP connections as having higher trust than, for example, a similar HTTP connection. If such connections are available to an attacker, they can be exploited in ways that may be surprising. In Apache Tomcat 9.0.0.M1 to 9.0.0.30, 8.5.0 to 8.5.50 and 7.0.0 to 7.0.99, Tomcat shipped with an AJP Connector enabled by default that listened on all configured IP addresses. It was expected (and recommended in the security guide) that this Connector would be disabled if not required. This vulnerability report identified a mechanism that allowed: - returning arbitrary files from anywhere in the web application - processing any file in the web application as a JSP Further, if the web application allowed file upload and stored those files within the web application (or the attacker was able to control the content of the web application by some other means) then this, along with the ability to process a file as a JSP, made remote code execution possible. It is important to note that mitigation is only required if an AJP port is accessible to untrusted users. Users wishing to take a defence-in-depth approach and block the vector that permits returning arbitrary files and execution as JSP may upgrade to Apache Tomcat 9.0.31, 8.5.51 or 7.0.100 or later. A number of changes were made to the default AJP Connector configuration in 9.0.31 to harden the default configuration. It is likely that users upgrading to 9.0.31, 8.5.51 or 7.0.100 or later will need to make small changes to their configurations.

- [https://github.com/b1cat/CVE_2020_1938_ajp_poc](https://github.com/b1cat/CVE_2020_1938_ajp_poc) :  ![starts](https://img.shields.io/github/stars/b1cat/CVE_2020_1938_ajp_poc.svg) ![forks](https://img.shields.io/github/forks/b1cat/CVE_2020_1938_ajp_poc.svg)


## CVE-2020-1206
 An information disclosure vulnerability exists in the way that the Microsoft Server Message Block 3.1.1 (SMBv3) protocol handles certain requests, aka 'Windows SMBv3 Client/Server Information Disclosure Vulnerability'.

- [https://github.com/ZecOps/SMBGhost-SMBleed-scanner](https://github.com/ZecOps/SMBGhost-SMBleed-scanner) :  ![starts](https://img.shields.io/github/stars/ZecOps/SMBGhost-SMBleed-scanner.svg) ![forks](https://img.shields.io/github/forks/ZecOps/SMBGhost-SMBleed-scanner.svg)


## CVE-2018-16509
 An issue was discovered in Artifex Ghostscript before 9.24. Incorrect &quot;restoration of privilege&quot; checking during handling of /invalidaccess exceptions could be used by attackers able to supply crafted PostScript to execute code using the &quot;pipe&quot; instruction.

- [https://github.com/AssassinUKG/CVE_2018_16509](https://github.com/AssassinUKG/CVE_2018_16509) :  ![starts](https://img.shields.io/github/stars/AssassinUKG/CVE_2018_16509.svg) ![forks](https://img.shields.io/github/forks/AssassinUKG/CVE_2018_16509.svg)


## CVE-2017-9554
 An information exposure vulnerability in forget_passwd.cgi in Synology DiskStation Manager (DSM) before 6.1.3-15152 allows remote attackers to enumerate valid usernames via unspecified vectors.

- [https://github.com/Ez0-yf/CVE-2017-9554-Exploit-Tool](https://github.com/Ez0-yf/CVE-2017-9554-Exploit-Tool) :  ![starts](https://img.shields.io/github/stars/Ez0-yf/CVE-2017-9554-Exploit-Tool.svg) ![forks](https://img.shields.io/github/forks/Ez0-yf/CVE-2017-9554-Exploit-Tool.svg)


## CVE-2017-0213
 Windows COM Aggregate Marshaler in Microsoft Windows Server 2008 SP2 and R2 SP1, Windows 7 SP1, Windows 8.1, Windows Server 2012 Gold and R2, Windows RT 8.1, Windows 10 Gold, 1511, 1607, and 1703, and Windows Server 2016 allows an elevation privilege vulnerability when an attacker runs a specially crafted application, aka &quot;Windows COM Elevation of Privilege Vulnerability&quot;. This CVE ID is unique from CVE-2017-0214.

- [https://github.com/jbooz1/CVE-2017-0213](https://github.com/jbooz1/CVE-2017-0213) :  ![starts](https://img.shields.io/github/stars/jbooz1/CVE-2017-0213.svg) ![forks](https://img.shields.io/github/forks/jbooz1/CVE-2017-0213.svg)

