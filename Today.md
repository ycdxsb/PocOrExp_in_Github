# Update 2021-07-21
## CVE-2021-36799
 KNX ETS5 uses the hard-coded password ETS5Password, with a salt value of Ivan Medvedev.

- [https://github.com/robertguetzkow/ets5-password-recovery](https://github.com/robertguetzkow/ets5-password-recovery) :  ![starts](https://img.shields.io/github/stars/robertguetzkow/ets5-password-recovery.svg) ![forks](https://img.shields.io/github/forks/robertguetzkow/ets5-password-recovery.svg)


## CVE-2021-21551
 Dell dbutil_2_3.sys driver contains an insufficient access control vulnerability which may lead to escalation of privileges, denial of service, or information disclosure. Local authenticated user access is required.

- [https://github.com/mzakocs/CVE-2021-21551-POC](https://github.com/mzakocs/CVE-2021-21551-POC) :  ![starts](https://img.shields.io/github/stars/mzakocs/CVE-2021-21551-POC.svg) ![forks](https://img.shields.io/github/forks/mzakocs/CVE-2021-21551-POC.svg)


## CVE-2020-25213
 The File Manager (wp-file-manager) plugin before 6.9 for WordPress allows remote attackers to upload and execute arbitrary PHP code because it renames an unsafe example elFinder connector file to have the .php extension. This, for example, allows attackers to run the elFinder upload (or mkfile and put) command to write PHP code into the wp-content/plugins/wp-file-manager/lib/files/ directory. This was exploited in the wild in August and September 2020.

- [https://github.com/ARON-TN/0day-elFinder-2020](https://github.com/ARON-TN/0day-elFinder-2020) :  ![starts](https://img.shields.io/github/stars/ARON-TN/0day-elFinder-2020.svg) ![forks](https://img.shields.io/github/forks/ARON-TN/0day-elFinder-2020.svg)


## CVE-2020-15778
 ** DISPUTED ** scp in OpenSSH through 8.3p1 allows command injection in the scp.c toremote function, as demonstrated by backtick characters in the destination argument. NOTE: the vendor reportedly has stated that they intentionally omit validation of &quot;anomalous argument transfers&quot; because that could &quot;stand a great chance of breaking existing workflows.&quot;

- [https://github.com/Neko2sh1ro/CVE-2020-15778-Exploit](https://github.com/Neko2sh1ro/CVE-2020-15778-Exploit) :  ![starts](https://img.shields.io/github/stars/Neko2sh1ro/CVE-2020-15778-Exploit.svg) ![forks](https://img.shields.io/github/forks/Neko2sh1ro/CVE-2020-15778-Exploit.svg)


## CVE-2020-1938
 When using the Apache JServ Protocol (AJP), care must be taken when trusting incoming connections to Apache Tomcat. Tomcat treats AJP connections as having higher trust than, for example, a similar HTTP connection. If such connections are available to an attacker, they can be exploited in ways that may be surprising. In Apache Tomcat 9.0.0.M1 to 9.0.0.30, 8.5.0 to 8.5.50 and 7.0.0 to 7.0.99, Tomcat shipped with an AJP Connector enabled by default that listened on all configured IP addresses. It was expected (and recommended in the security guide) that this Connector would be disabled if not required. This vulnerability report identified a mechanism that allowed: - returning arbitrary files from anywhere in the web application - processing any file in the web application as a JSP Further, if the web application allowed file upload and stored those files within the web application (or the attacker was able to control the content of the web application by some other means) then this, along with the ability to process a file as a JSP, made remote code execution possible. It is important to note that mitigation is only required if an AJP port is accessible to untrusted users. Users wishing to take a defence-in-depth approach and block the vector that permits returning arbitrary files and execution as JSP may upgrade to Apache Tomcat 9.0.31, 8.5.51 or 7.0.100 or later. A number of changes were made to the default AJP Connector configuration in 9.0.31 to harden the default configuration. It is likely that users upgrading to 9.0.31, 8.5.51 or 7.0.100 or later will need to make small changes to their configurations.

- [https://github.com/Neko2sh1ro/CVE-2020-1938](https://github.com/Neko2sh1ro/CVE-2020-1938) :  ![starts](https://img.shields.io/github/stars/Neko2sh1ro/CVE-2020-1938.svg) ![forks](https://img.shields.io/github/forks/Neko2sh1ro/CVE-2020-1938.svg)


## CVE-2020-0674
 A remote code execution vulnerability exists in the way that the scripting engine handles objects in memory in Internet Explorer, aka 'Scripting Engine Memory Corruption Vulnerability'. This CVE ID is unique from CVE-2020-0673, CVE-2020-0710, CVE-2020-0711, CVE-2020-0712, CVE-2020-0713, CVE-2020-0767.

- [https://github.com/Neko2sh1ro/CVE-2020-0674-PoC](https://github.com/Neko2sh1ro/CVE-2020-0674-PoC) :  ![starts](https://img.shields.io/github/stars/Neko2sh1ro/CVE-2020-0674-PoC.svg) ![forks](https://img.shields.io/github/forks/Neko2sh1ro/CVE-2020-0674-PoC.svg)


## CVE-2019-15165
 sf-pcapng.c in libpcap before 1.9.1 does not properly validate the PHB header length before allocating memory.

- [https://github.com/madhans23/libpcap-with-Fix-CVE-2019-15165](https://github.com/madhans23/libpcap-with-Fix-CVE-2019-15165) :  ![starts](https://img.shields.io/github/stars/madhans23/libpcap-with-Fix-CVE-2019-15165.svg) ![forks](https://img.shields.io/github/forks/madhans23/libpcap-with-Fix-CVE-2019-15165.svg)
- [https://github.com/madhans23/libpcap-without-Fix-CVE-2019-15165](https://github.com/madhans23/libpcap-without-Fix-CVE-2019-15165) :  ![starts](https://img.shields.io/github/stars/madhans23/libpcap-without-Fix-CVE-2019-15165.svg) ![forks](https://img.shields.io/github/forks/madhans23/libpcap-without-Fix-CVE-2019-15165.svg)


## CVE-2019-2729
 Vulnerability in the Oracle WebLogic Server component of Oracle Fusion Middleware (subcomponent: Web Services). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0 and 12.2.1.3.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/black-mirror/Weblogic](https://github.com/black-mirror/Weblogic) :  ![starts](https://img.shields.io/github/stars/black-mirror/Weblogic.svg) ![forks](https://img.shields.io/github/forks/black-mirror/Weblogic.svg)

