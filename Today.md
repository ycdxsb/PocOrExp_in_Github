# Update 2021-07-16
## CVE-2021-34527
 Windows Print Spooler Remote Code Execution Vulnerability

- [https://github.com/BeetleChunks/SpoolSploit](https://github.com/BeetleChunks/SpoolSploit) :  ![starts](https://img.shields.io/github/stars/BeetleChunks/SpoolSploit.svg) ![forks](https://img.shields.io/github/forks/BeetleChunks/SpoolSploit.svg)


## CVE-2021-34496
 Windows GDI Information Disclosure Vulnerability

- [https://github.com/fkm75P8YjLkb/CVE-2021-34496](https://github.com/fkm75P8YjLkb/CVE-2021-34496) :  ![starts](https://img.shields.io/github/stars/fkm75P8YjLkb/CVE-2021-34496.svg) ![forks](https://img.shields.io/github/forks/fkm75P8YjLkb/CVE-2021-34496.svg)


## CVE-2021-30641
 Apache HTTP Server versions 2.4.39 to 2.4.46 Unexpected matching behavior with 'MergeSlashes OFF'

- [https://github.com/fkm75P8YjLkb/CVE-2021-30641](https://github.com/fkm75P8YjLkb/CVE-2021-30641) :  ![starts](https://img.shields.io/github/stars/fkm75P8YjLkb/CVE-2021-30641.svg) ![forks](https://img.shields.io/github/forks/fkm75P8YjLkb/CVE-2021-30641.svg)


## CVE-2021-30461
 A remote code execution issue was discovered in the web UI of VoIPmonitor before 24.61. When the recheck option is used, the user-supplied SPOOLDIR value (which might contain PHP code) is injected into config/configuration.php.

- [https://github.com/puckiestyle/CVE-2021-30461](https://github.com/puckiestyle/CVE-2021-30461) :  ![starts](https://img.shields.io/github/stars/puckiestyle/CVE-2021-30461.svg) ![forks](https://img.shields.io/github/forks/puckiestyle/CVE-2021-30461.svg)


## CVE-2021-26691
 In Apache HTTP Server versions 2.4.0 to 2.4.46 a specially crafted SessionHeader sent by an origin server could cause a heap overflow

- [https://github.com/fkm75P8YjLkb/CVE-2021-26691](https://github.com/fkm75P8YjLkb/CVE-2021-26691) :  ![starts](https://img.shields.io/github/stars/fkm75P8YjLkb/CVE-2021-26691.svg) ![forks](https://img.shields.io/github/forks/fkm75P8YjLkb/CVE-2021-26691.svg)


## CVE-2021-26690
 Apache HTTP Server versions 2.4.0 to 2.4.46 A specially crafted Cookie header handled by mod_session can cause a NULL pointer dereference and crash, leading to a possible Denial Of Service

- [https://github.com/fkm75P8YjLkb/CVE-2021-26690](https://github.com/fkm75P8YjLkb/CVE-2021-26690) :  ![starts](https://img.shields.io/github/stars/fkm75P8YjLkb/CVE-2021-26690.svg) ![forks](https://img.shields.io/github/forks/fkm75P8YjLkb/CVE-2021-26690.svg)


## CVE-2021-3516
 There's a flaw in libxml2's xmllint in versions before 2.9.11. An attacker who is able to submit a crafted file to be processed by xmllint could trigger a use-after-free. The greatest impact of this flaw is to confidentiality, integrity, and availability.

- [https://github.com/fkm75P8YjLkb/CVE-2021-3516](https://github.com/fkm75P8YjLkb/CVE-2021-3516) :  ![starts](https://img.shields.io/github/stars/fkm75P8YjLkb/CVE-2021-3516.svg) ![forks](https://img.shields.io/github/forks/fkm75P8YjLkb/CVE-2021-3516.svg)


## CVE-2020-15778
 ** DISPUTED ** scp in OpenSSH through 8.3p1 allows command injection in the scp.c toremote function, as demonstrated by backtick characters in the destination argument. NOTE: the vendor reportedly has stated that they intentionally omit validation of &quot;anomalous argument transfers&quot; because that could &quot;stand a great chance of breaking existing workflows.&quot;

- [https://github.com/yukiNeko114514/CVE-2020-15778-Exploit](https://github.com/yukiNeko114514/CVE-2020-15778-Exploit) :  ![starts](https://img.shields.io/github/stars/yukiNeko114514/CVE-2020-15778-Exploit.svg) ![forks](https://img.shields.io/github/forks/yukiNeko114514/CVE-2020-15778-Exploit.svg)


## CVE-2020-1938
 When using the Apache JServ Protocol (AJP), care must be taken when trusting incoming connections to Apache Tomcat. Tomcat treats AJP connections as having higher trust than, for example, a similar HTTP connection. If such connections are available to an attacker, they can be exploited in ways that may be surprising. In Apache Tomcat 9.0.0.M1 to 9.0.0.30, 8.5.0 to 8.5.50 and 7.0.0 to 7.0.99, Tomcat shipped with an AJP Connector enabled by default that listened on all configured IP addresses. It was expected (and recommended in the security guide) that this Connector would be disabled if not required. This vulnerability report identified a mechanism that allowed: - returning arbitrary files from anywhere in the web application - processing any file in the web application as a JSP Further, if the web application allowed file upload and stored those files within the web application (or the attacker was able to control the content of the web application by some other means) then this, along with the ability to process a file as a JSP, made remote code execution possible. It is important to note that mitigation is only required if an AJP port is accessible to untrusted users. Users wishing to take a defence-in-depth approach and block the vector that permits returning arbitrary files and execution as JSP may upgrade to Apache Tomcat 9.0.31, 8.5.51 or 7.0.100 or later. A number of changes were made to the default AJP Connector configuration in 9.0.31 to harden the default configuration. It is likely that users upgrading to 9.0.31, 8.5.51 or 7.0.100 or later will need to make small changes to their configurations.

- [https://github.com/0nise/CVE-2020-1938](https://github.com/0nise/CVE-2020-1938) :  ![starts](https://img.shields.io/github/stars/0nise/CVE-2020-1938.svg) ![forks](https://img.shields.io/github/forks/0nise/CVE-2020-1938.svg)
- [https://github.com/delsadan/CNVD-2020-10487-Bulk-verification](https://github.com/delsadan/CNVD-2020-10487-Bulk-verification) :  ![starts](https://img.shields.io/github/stars/delsadan/CNVD-2020-10487-Bulk-verification.svg) ![forks](https://img.shields.io/github/forks/delsadan/CNVD-2020-10487-Bulk-verification.svg)
- [https://github.com/yukiNeko114514/CVE-2020-1938](https://github.com/yukiNeko114514/CVE-2020-1938) :  ![starts](https://img.shields.io/github/stars/yukiNeko114514/CVE-2020-1938.svg) ![forks](https://img.shields.io/github/forks/yukiNeko114514/CVE-2020-1938.svg)
- [https://github.com/kukudechen-chen/cve-2020-1938](https://github.com/kukudechen-chen/cve-2020-1938) :  ![starts](https://img.shields.io/github/stars/kukudechen-chen/cve-2020-1938.svg) ![forks](https://img.shields.io/github/forks/kukudechen-chen/cve-2020-1938.svg)


## CVE-2020-0796
 A remote code execution vulnerability exists in the way that the Microsoft Server Message Block 3.1.1 (SMBv3) protocol handles certain requests, aka 'Windows SMBv3 Client/Server Remote Code Execution Vulnerability'.

- [https://github.com/1stPeak/CVE-2020-0796-Scanner](https://github.com/1stPeak/CVE-2020-0796-Scanner) :  ![starts](https://img.shields.io/github/stars/1stPeak/CVE-2020-0796-Scanner.svg) ![forks](https://img.shields.io/github/forks/1stPeak/CVE-2020-0796-Scanner.svg)


## CVE-2012-1870
 The CBC mode in the TLS protocol, as used in Microsoft Windows XP SP2 and SP3, Windows Server 2003 SP2, Windows Vista SP2, Windows Server 2008 SP2, R2, and R2 SP1, Windows 7 Gold and SP1, and other products, allows remote web servers to obtain plaintext data by triggering multiple requests to a third-party HTTPS server and sniffing the network during the resulting HTTPS session, aka &quot;TLS Protocol Vulnerability.&quot;

- [https://github.com/fkm75P8YjLkb/CVE-2012-1870](https://github.com/fkm75P8YjLkb/CVE-2012-1870) :  ![starts](https://img.shields.io/github/stars/fkm75P8YjLkb/CVE-2012-1870.svg) ![forks](https://img.shields.io/github/forks/fkm75P8YjLkb/CVE-2012-1870.svg)

