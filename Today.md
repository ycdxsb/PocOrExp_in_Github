# Update 2021-09-02
## CVE-2021-40353
 A SQL injection vulnerability exists in version 8.0 of openSIS when MySQL or MariaDB is used as the application database. An attacker can then issue the SQL command through the index.php USERNAME parameter. NOTE: this issue may exist because of an incomplete fix for CVE-2020-6637.

- [https://github.com/5qu1n7/CVE-2021-40353](https://github.com/5qu1n7/CVE-2021-40353) :  ![starts](https://img.shields.io/github/stars/5qu1n7/CVE-2021-40353.svg) ![forks](https://img.shields.io/github/forks/5qu1n7/CVE-2021-40353.svg)


## CVE-2021-33766
 Microsoft Exchange Information Disclosure Vulnerability

- [https://github.com/bhdresh/CVE-2021-33766-ProxyToken](https://github.com/bhdresh/CVE-2021-33766-ProxyToken) :  ![starts](https://img.shields.io/github/stars/bhdresh/CVE-2021-33766-ProxyToken.svg) ![forks](https://img.shields.io/github/forks/bhdresh/CVE-2021-33766-ProxyToken.svg)


## CVE-2021-32804
 The npm package &quot;tar&quot; (aka node-tar) before versions 6.1.1, 5.0.6, 4.4.14, and 3.3.2 has a arbitrary File Creation/Overwrite vulnerability due to insufficient absolute path sanitization. node-tar aims to prevent extraction of absolute file paths by turning absolute paths into relative paths when the `preservePaths` flag is not set to `true`. This is achieved by stripping the absolute path root from any absolute file paths contained in a tar file. For example `/home/user/.bashrc` would turn into `home/user/.bashrc`. This logic was insufficient when file paths contained repeated path roots such as `////home/user/.bashrc`. `node-tar` would only strip a single path root from such paths. When given an absolute file path with repeating path roots, the resulting path (e.g. `///home/user/.bashrc`) would still resolve to an absolute path, thus allowing arbitrary file creation and overwrite. This issue was addressed in releases 3.2.2, 4.4.14, 5.0.6 and 6.1.1. Users may work around this vulnerability without upgrading by creating a custom `onentry` method which sanitizes the `entry.path` or a `filter` method which removes entries with absolute paths. See referenced GitHub Advisory for details. Be aware of CVE-2021-32803 which fixes a similar bug in later versions of tar.

- [https://github.com/yamory/CVE-2021-32804](https://github.com/yamory/CVE-2021-32804) :  ![starts](https://img.shields.io/github/stars/yamory/CVE-2021-32804.svg) ![forks](https://img.shields.io/github/forks/yamory/CVE-2021-32804.svg)


## CVE-2021-28378
 Gitea 1.12.x and 1.13.x before 1.13.4 allows XSS via certain issue data in some situations.

- [https://github.com/PandatiX/CVE-2021-28378](https://github.com/PandatiX/CVE-2021-28378) :  ![starts](https://img.shields.io/github/stars/PandatiX/CVE-2021-28378.svg) ![forks](https://img.shields.io/github/forks/PandatiX/CVE-2021-28378.svg)


## CVE-2021-26084
 In affected versions of Confluence Server and Data Center, an OGNL injection vulnerability exists that would allow an authenticated user, and in some instances an unauthenticated user, to execute arbitrary code on a Confluence Server or Data Center instance. The vulnerable endpoints can be accessed by a non-administrator user or unauthenticated user if &#8216;Allow people to sign up to create their account&#8217; is enabled. To check whether this is enabled go to COG &gt; User Management &gt; User Signup Options. The affected versions are before version 6.13.23, from version 6.14.0 before 7.4.11, from version 7.5.0 before 7.11.6, and from version 7.12.0 before 7.12.5.

- [https://github.com/dinhbaouit/CVE-2021-26084](https://github.com/dinhbaouit/CVE-2021-26084) :  ![starts](https://img.shields.io/github/stars/dinhbaouit/CVE-2021-26084.svg) ![forks](https://img.shields.io/github/forks/dinhbaouit/CVE-2021-26084.svg)
- [https://github.com/alt3kx/CVE-2021-26084_PoC](https://github.com/alt3kx/CVE-2021-26084_PoC) :  ![starts](https://img.shields.io/github/stars/alt3kx/CVE-2021-26084_PoC.svg) ![forks](https://img.shields.io/github/forks/alt3kx/CVE-2021-26084_PoC.svg)
- [https://github.com/carlosevieira/CVE-2021-26084](https://github.com/carlosevieira/CVE-2021-26084) :  ![starts](https://img.shields.io/github/stars/carlosevieira/CVE-2021-26084.svg) ![forks](https://img.shields.io/github/forks/carlosevieira/CVE-2021-26084.svg)
- [https://github.com/JKme/CVE-2021-26084](https://github.com/JKme/CVE-2021-26084) :  ![starts](https://img.shields.io/github/stars/JKme/CVE-2021-26084.svg) ![forks](https://img.shields.io/github/forks/JKme/CVE-2021-26084.svg)


## CVE-2021-22192
 An issue has been discovered in GitLab CE/EE affecting all versions starting from 13.2 allowing unauthorized authenticated users to execute arbitrary code on the server.

- [https://github.com/lyy289065406/CVE-2021-22192](https://github.com/lyy289065406/CVE-2021-22192) :  ![starts](https://img.shields.io/github/stars/lyy289065406/CVE-2021-22192.svg) ![forks](https://img.shields.io/github/forks/lyy289065406/CVE-2021-22192.svg)


## CVE-2021-1748
 A validation issue was addressed with improved input sanitization. This issue is fixed in tvOS 14.4, watchOS 7.3, iOS 14.4 and iPadOS 14.4. Processing a maliciously crafted URL may lead to arbitrary javascript code execution.

- [https://github.com/tihmstar/itmsBlock](https://github.com/tihmstar/itmsBlock) :  ![starts](https://img.shields.io/github/stars/tihmstar/itmsBlock.svg) ![forks](https://img.shields.io/github/forks/tihmstar/itmsBlock.svg)


## CVE-2020-2556
 Vulnerability in the Primavera P6 Enterprise Project Portfolio Management product of Oracle Construction and Engineering (component: Core). Supported versions that are affected are 16.2.0.0-16.2.19.0, 17.12.0.0-17.12.16.0, 18.8.0.0-18.8.16.0, 19.12.0.0 and 20.1.0.0. Easily exploitable vulnerability allows low privileged attacker with logon to the infrastructure where Primavera P6 Enterprise Project Portfolio Management executes to compromise Primavera P6 Enterprise Project Portfolio Management. Successful attacks require human interaction from a person other than the attacker and while the vulnerability is in Primavera P6 Enterprise Project Portfolio Management, attacks may significantly impact additional products. Successful attacks of this vulnerability can result in unauthorized creation, deletion or modification access to critical data or all Primavera P6 Enterprise Project Portfolio Management accessible data as well as unauthorized read access to a subset of Primavera P6 Enterprise Project Portfolio Management accessible data and unauthorized ability to cause a partial denial of service (partial DOS) of Primavera P6 Enterprise Project Portfolio Management. CVSS 3.0 Base Score 7.3 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:C/C:L/I:H/A:L).

- [https://github.com/5l1v3r1/CVE-2020-2556](https://github.com/5l1v3r1/CVE-2020-2556) :  ![starts](https://img.shields.io/github/stars/5l1v3r1/CVE-2020-2556.svg) ![forks](https://img.shields.io/github/forks/5l1v3r1/CVE-2020-2556.svg)


## CVE-2020-2555
 Vulnerability in the Oracle Coherence product of Oracle Fusion Middleware (component: Caching,CacheStore,Invocation). Supported versions that are affected are 3.7.1.0, 12.1.3.0.0, 12.2.1.3.0 and 12.2.1.4.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3 to compromise Oracle Coherence. Successful attacks of this vulnerability can result in takeover of Oracle Coherence. CVSS 3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/5l1v3r1/CVE-2020-2556](https://github.com/5l1v3r1/CVE-2020-2556) :  ![starts](https://img.shields.io/github/stars/5l1v3r1/CVE-2020-2556.svg) ![forks](https://img.shields.io/github/forks/5l1v3r1/CVE-2020-2556.svg)


## CVE-2020-2553
 Vulnerability in the Oracle Knowledge product of Oracle Knowledge (component: Information Manager Console). Supported versions that are affected are 8.6.0-8.6.3. Difficult to exploit vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Knowledge. Successful attacks of this vulnerability can result in unauthorized update, insert or delete access to some of Oracle Knowledge accessible data as well as unauthorized read access to a subset of Oracle Knowledge accessible data. CVSS 3.0 Base Score 4.8 (Confidentiality and Integrity impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N).

- [https://github.com/5l1v3r1/CVE-2020-2553](https://github.com/5l1v3r1/CVE-2020-2553) :  ![starts](https://img.shields.io/github/stars/5l1v3r1/CVE-2020-2553.svg) ![forks](https://img.shields.io/github/forks/5l1v3r1/CVE-2020-2553.svg)


## CVE-2020-2551
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: WLS Core Components). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0 and 12.2.1.4.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via IIOP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/5l1v3r1/CVE-2020-2553](https://github.com/5l1v3r1/CVE-2020-2553) :  ![starts](https://img.shields.io/github/stars/5l1v3r1/CVE-2020-2553.svg) ![forks](https://img.shields.io/github/forks/5l1v3r1/CVE-2020-2553.svg)


## CVE-2020-1948
 This vulnerability can affect all Dubbo users stay on version 2.7.6 or lower. An attacker can send RPC requests with unrecognized service name or method name along with some malicious parameter payloads. When the malicious parameter is deserialized, it will execute some malicious code. More details can be found below.

- [https://github.com/txrw/Dubbo-CVE-2020-1948](https://github.com/txrw/Dubbo-CVE-2020-1948) :  ![starts](https://img.shields.io/github/stars/txrw/Dubbo-CVE-2020-1948.svg) ![forks](https://img.shields.io/github/forks/txrw/Dubbo-CVE-2020-1948.svg)


## CVE-2020-1938
 When using the Apache JServ Protocol (AJP), care must be taken when trusting incoming connections to Apache Tomcat. Tomcat treats AJP connections as having higher trust than, for example, a similar HTTP connection. If such connections are available to an attacker, they can be exploited in ways that may be surprising. In Apache Tomcat 9.0.0.M1 to 9.0.0.30, 8.5.0 to 8.5.50 and 7.0.0 to 7.0.99, Tomcat shipped with an AJP Connector enabled by default that listened on all configured IP addresses. It was expected (and recommended in the security guide) that this Connector would be disabled if not required. This vulnerability report identified a mechanism that allowed: - returning arbitrary files from anywhere in the web application - processing any file in the web application as a JSP Further, if the web application allowed file upload and stored those files within the web application (or the attacker was able to control the content of the web application by some other means) then this, along with the ability to process a file as a JSP, made remote code execution possible. It is important to note that mitigation is only required if an AJP port is accessible to untrusted users. Users wishing to take a defence-in-depth approach and block the vector that permits returning arbitrary files and execution as JSP may upgrade to Apache Tomcat 9.0.31, 8.5.51 or 7.0.100 or later. A number of changes were made to the default AJP Connector configuration in 9.0.31 to harden the default configuration. It is likely that users upgrading to 9.0.31, 8.5.51 or 7.0.100 or later will need to make small changes to their configurations.

- [https://github.com/FirstKaiXin/CVE-2020-1938](https://github.com/FirstKaiXin/CVE-2020-1938) :  ![starts](https://img.shields.io/github/stars/FirstKaiXin/CVE-2020-1938.svg) ![forks](https://img.shields.io/github/forks/FirstKaiXin/CVE-2020-1938.svg)


## CVE-2019-17662
 ThinVNC 1.0b1 is vulnerable to arbitrary file read, which leads to a compromise of the VNC server. The vulnerability exists even when authentication is turned on during the deployment of the VNC server. The password for authentication is stored in cleartext in a file that can be read via a ../../ThinVnc.ini directory traversal attack vector.

- [https://github.com/MuirlandOracle/CVE-2019-17662](https://github.com/MuirlandOracle/CVE-2019-17662) :  ![starts](https://img.shields.io/github/stars/MuirlandOracle/CVE-2019-17662.svg) ![forks](https://img.shields.io/github/forks/MuirlandOracle/CVE-2019-17662.svg)


## CVE-2015-7547
 Multiple stack-based buffer overflows in the (1) send_dg and (2) send_vc functions in the libresolv library in the GNU C Library (aka glibc or libc6) before 2.23 allow remote attackers to cause a denial of service (crash) or possibly execute arbitrary code via a crafted DNS response that triggers a call to the getaddrinfo function with the AF_UNSPEC or AF_INET6 address family, related to performing &quot;dual A/AAAA DNS queries&quot; and the libnss_dns.so.2 NSS module.

- [https://github.com/AlAIAL90/CVE-2015-7547](https://github.com/AlAIAL90/CVE-2015-7547) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2015-7547.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2015-7547.svg)


## CVE-2013-7423
 The send_dg function in resolv/res_send.c in GNU C Library (aka glibc or libc6) before 2.20 does not properly reuse file descriptors, which allows remote attackers to send DNS queries to unintended locations via a large number of requests that trigger a call to the getaddrinfo function.

- [https://github.com/AlAIAL90/CVE-2013-7423](https://github.com/AlAIAL90/CVE-2013-7423) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2013-7423.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2013-7423.svg)


## CVE-2013-1914
 Stack-based buffer overflow in the getaddrinfo function in sysdeps/posix/getaddrinfo.c in GNU C Library (aka glibc or libc6) 2.17 and earlier allows remote attackers to cause a denial of service (crash) via a (1) hostname or (2) IP address that triggers a large number of domain conversion results.

- [https://github.com/AlAIAL90/CVE-2013-1914](https://github.com/AlAIAL90/CVE-2013-1914) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2013-1914.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2013-1914.svg)


## CVE-2012-4869
 The callme_startcall function in recordings/misc/callme_page.php in FreePBX 2.9, 2.10, and earlier allows remote attackers to execute arbitrary commands via the callmenum parameter in a c action.

- [https://github.com/bitc0de/Elastix-Remote-Code-Execution](https://github.com/bitc0de/Elastix-Remote-Code-Execution) :  ![starts](https://img.shields.io/github/stars/bitc0de/Elastix-Remote-Code-Execution.svg) ![forks](https://img.shields.io/github/forks/bitc0de/Elastix-Remote-Code-Execution.svg)


## CVE-2010-4756
 The glob implementation in the GNU C Library (aka glibc or libc6) allows remote authenticated users to cause a denial of service (CPU and memory consumption) via crafted glob expressions that do not match any pathnames, as demonstrated by glob expressions in STAT commands to an FTP daemon, a different vulnerability than CVE-2010-2632.

- [https://github.com/AlAIAL90/CVE-2010-4756](https://github.com/AlAIAL90/CVE-2010-4756) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2010-4756.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2010-4756.svg)


## CVE-2010-2632
 Unspecified vulnerability in the FTP Server in Oracle Solaris 8, 9, 10, and 11 Express allows remote attackers to affect availability. NOTE: the previous information was obtained from the January 2011 CPU. Oracle has not commented on claims from a reliable researcher that this is an issue in the glob implementation in libc that allows remote authenticated users to cause a denial of service (CPU and memory consumption) via crafted glob expressions that do not match any pathnames.

- [https://github.com/AlAIAL90/CVE-2010-4756](https://github.com/AlAIAL90/CVE-2010-4756) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2010-4756.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2010-4756.svg)

