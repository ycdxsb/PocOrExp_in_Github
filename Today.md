# Update 2023-06-22
## CVE-2023-34584
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/fu2x2000/-CVE-2023-34584](https://github.com/fu2x2000/-CVE-2023-34584) :  ![starts](https://img.shields.io/github/stars/fu2x2000/-CVE-2023-34584.svg) ![forks](https://img.shields.io/github/forks/fu2x2000/-CVE-2023-34584.svg)


## CVE-2023-33405
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/hacip/CVE-2023-33405](https://github.com/hacip/CVE-2023-33405) :  ![starts](https://img.shields.io/github/stars/hacip/CVE-2023-33405.svg) ![forks](https://img.shields.io/github/forks/hacip/CVE-2023-33405.svg)


## CVE-2023-33404
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/hacip/CVE-2023-33404](https://github.com/hacip/CVE-2023-33404) :  ![starts](https://img.shields.io/github/stars/hacip/CVE-2023-33404.svg) ![forks](https://img.shields.io/github/forks/hacip/CVE-2023-33404.svg)


## CVE-2023-30212
 OURPHP &lt;= 7.2.0 is vulnerale to Cross Site Scripting (XSS) via /client/manage/ourphp_out.php.

- [https://github.com/AAsh035/CVE-2023-30212](https://github.com/AAsh035/CVE-2023-30212) :  ![starts](https://img.shields.io/github/stars/AAsh035/CVE-2023-30212.svg) ![forks](https://img.shields.io/github/forks/AAsh035/CVE-2023-30212.svg)
- [https://github.com/VisDev23/Vulnerable-Docker-CVE-2023-30212](https://github.com/VisDev23/Vulnerable-Docker-CVE-2023-30212) :  ![starts](https://img.shields.io/github/stars/VisDev23/Vulnerable-Docker-CVE-2023-30212.svg) ![forks](https://img.shields.io/github/forks/VisDev23/Vulnerable-Docker-CVE-2023-30212.svg)
- [https://github.com/VisDev23/Vulnerable-Docker--CVE-2023-30212-](https://github.com/VisDev23/Vulnerable-Docker--CVE-2023-30212-) :  ![starts](https://img.shields.io/github/stars/VisDev23/Vulnerable-Docker--CVE-2023-30212-.svg) ![forks](https://img.shields.io/github/forks/VisDev23/Vulnerable-Docker--CVE-2023-30212-.svg)
- [https://github.com/hheeyywweellccoommee/CVE-2023-30212-Vulnerable-Lab-xjghb](https://github.com/hheeyywweellccoommee/CVE-2023-30212-Vulnerable-Lab-xjghb) :  ![starts](https://img.shields.io/github/stars/hheeyywweellccoommee/CVE-2023-30212-Vulnerable-Lab-xjghb.svg) ![forks](https://img.shields.io/github/forks/hheeyywweellccoommee/CVE-2023-30212-Vulnerable-Lab-xjghb.svg)
- [https://github.com/JasaluRah/Creating-a-Vulnerable-Docker-Environment-CVE-2023-30212-](https://github.com/JasaluRah/Creating-a-Vulnerable-Docker-Environment-CVE-2023-30212-) :  ![starts](https://img.shields.io/github/stars/JasaluRah/Creating-a-Vulnerable-Docker-Environment-CVE-2023-30212-.svg) ![forks](https://img.shields.io/github/forks/JasaluRah/Creating-a-Vulnerable-Docker-Environment-CVE-2023-30212-.svg)


## CVE-2023-1454
 A vulnerability classified as critical has been found in jeecg-boot 3.5.0. This affects an unknown part of the file jmreport/qurestSql. The manipulation of the argument apiSelectId leads to sql injection. It is possible to initiate the attack remotely. The exploit has been disclosed to the public and may be used. The associated identifier of this vulnerability is VDB-223299.

- [https://github.com/Sweelg/CVE-2023-1454-Jeecg-Boot-qurestSql-SQLvuln](https://github.com/Sweelg/CVE-2023-1454-Jeecg-Boot-qurestSql-SQLvuln) :  ![starts](https://img.shields.io/github/stars/Sweelg/CVE-2023-1454-Jeecg-Boot-qurestSql-SQLvuln.svg) ![forks](https://img.shields.io/github/forks/Sweelg/CVE-2023-1454-Jeecg-Boot-qurestSql-SQLvuln.svg)


## CVE-2022-22965
 A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the application to run on Tomcat as a WAR deployment. If the application is deployed as a Spring Boot executable jar, i.e. the default, it is not vulnerable to the exploit. However, the nature of the vulnerability is more general, and there may be other ways to exploit it.

- [https://github.com/jakabakos/spring4shell](https://github.com/jakabakos/spring4shell) :  ![starts](https://img.shields.io/github/stars/jakabakos/spring4shell.svg) ![forks](https://img.shields.io/github/forks/jakabakos/spring4shell.svg)


## CVE-2022-4450
 The function PEM_read_bio_ex() reads a PEM file from a BIO and parses and decodes the &quot;name&quot; (e.g. &quot;CERTIFICATE&quot;), any header data and the payload data. If the function succeeds then the &quot;name_out&quot;, &quot;header&quot; and &quot;data&quot; arguments are populated with pointers to buffers containing the relevant decoded data. The caller is responsible for freeing those buffers. It is possible to construct a PEM file that results in 0 bytes of payload data. In this case PEM_read_bio_ex() will return a failure code but will populate the header argument with a pointer to a buffer that has already been freed. If the caller also frees this buffer then a double free will occur. This will most likely lead to a crash. This could be exploited by an attacker who has the ability to supply malicious PEM files for parsing to achieve a denial of service attack. The functions PEM_read_bio() and PEM_read() are simple wrappers around PEM_read_bio_ex() and therefore these functions are also directly affected. These functions are also called indirectly by a number of other OpenSSL functions including PEM_X509_INFO_read_bio_ex() and SSL_CTX_use_serverinfo_file() which are also vulnerable. Some OpenSSL internal uses of these functions are not vulnerable because the caller does not free the header argument if PEM_read_bio_ex() returns a failure code. These locations include the PEM_read_bio_TYPE() functions as well as the decoders introduced in OpenSSL 3.0. The OpenSSL asn1parse command line application is also impacted by this issue.

- [https://github.com/nidhi7598/OPENSSL_1.1.1g_G3_CVE-2022-4450](https://github.com/nidhi7598/OPENSSL_1.1.1g_G3_CVE-2022-4450) :  ![starts](https://img.shields.io/github/stars/nidhi7598/OPENSSL_1.1.1g_G3_CVE-2022-4450.svg) ![forks](https://img.shields.io/github/forks/nidhi7598/OPENSSL_1.1.1g_G3_CVE-2022-4450.svg)


## CVE-2022-0847
 A flaw was found in the way the &quot;flags&quot; member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/0xeremus/dirty-pipe-poc](https://github.com/0xeremus/dirty-pipe-poc) :  ![starts](https://img.shields.io/github/stars/0xeremus/dirty-pipe-poc.svg) ![forks](https://img.shields.io/github/forks/0xeremus/dirty-pipe-poc.svg)


## CVE-2020-17382
 The MSI AmbientLink MsIo64 driver 1.0.0.8 has a Buffer Overflow (0x80102040, 0x80102044, 0x80102050,and 0x80102054).

- [https://github.com/Exploitables/CVE-2020-17382](https://github.com/Exploitables/CVE-2020-17382) :  ![starts](https://img.shields.io/github/stars/Exploitables/CVE-2020-17382.svg) ![forks](https://img.shields.io/github/forks/Exploitables/CVE-2020-17382.svg)


## CVE-2020-12702
 Weak encryption in the Quick Pairing mode in the eWeLink mobile application (Android application V4.9.2 and earlier, iOS application V4.9.1 and earlier) allows physically proximate attackers to eavesdrop on Wi-Fi credentials and other sensitive information by monitoring the Wi-Fi spectrum during the pairing process.

- [https://github.com/salgio/eWeLink-QR-Code](https://github.com/salgio/eWeLink-QR-Code) :  ![starts](https://img.shields.io/github/stars/salgio/eWeLink-QR-Code.svg) ![forks](https://img.shields.io/github/forks/salgio/eWeLink-QR-Code.svg)


## CVE-2020-1938
 When using the Apache JServ Protocol (AJP), care must be taken when trusting incoming connections to Apache Tomcat. Tomcat treats AJP connections as having higher trust than, for example, a similar HTTP connection. If such connections are available to an attacker, they can be exploited in ways that may be surprising. In Apache Tomcat 9.0.0.M1 to 9.0.0.30, 8.5.0 to 8.5.50 and 7.0.0 to 7.0.99, Tomcat shipped with an AJP Connector enabled by default that listened on all configured IP addresses. It was expected (and recommended in the security guide) that this Connector would be disabled if not required. This vulnerability report identified a mechanism that allowed: - returning arbitrary files from anywhere in the web application - processing any file in the web application as a JSP Further, if the web application allowed file upload and stored those files within the web application (or the attacker was able to control the content of the web application by some other means) then this, along with the ability to process a file as a JSP, made remote code execution possible. It is important to note that mitigation is only required if an AJP port is accessible to untrusted users. Users wishing to take a defence-in-depth approach and block the vector that permits returning arbitrary files and execution as JSP may upgrade to Apache Tomcat 9.0.31, 8.5.51 or 7.0.100 or later. A number of changes were made to the default AJP Connector configuration in 9.0.31 to harden the default configuration. It is likely that users upgrading to 9.0.31, 8.5.51 or 7.0.100 or later will need to make small changes to their configurations.

- [https://github.com/zhzyker/exphub](https://github.com/zhzyker/exphub) :  ![starts](https://img.shields.io/github/stars/zhzyker/exphub.svg) ![forks](https://img.shields.io/github/forks/zhzyker/exphub.svg)
- [https://github.com/hypn0s/AJPy](https://github.com/hypn0s/AJPy) :  ![starts](https://img.shields.io/github/stars/hypn0s/AJPy.svg) ![forks](https://img.shields.io/github/forks/hypn0s/AJPy.svg)
- [https://github.com/00theway/Ghostcat-CNVD-2020-10487](https://github.com/00theway/Ghostcat-CNVD-2020-10487) :  ![starts](https://img.shields.io/github/stars/00theway/Ghostcat-CNVD-2020-10487.svg) ![forks](https://img.shields.io/github/forks/00theway/Ghostcat-CNVD-2020-10487.svg)
- [https://github.com/nibiwodong/CNVD-2020-10487-Tomcat-ajp-POC](https://github.com/nibiwodong/CNVD-2020-10487-Tomcat-ajp-POC) :  ![starts](https://img.shields.io/github/stars/nibiwodong/CNVD-2020-10487-Tomcat-ajp-POC.svg) ![forks](https://img.shields.io/github/forks/nibiwodong/CNVD-2020-10487-Tomcat-ajp-POC.svg)
- [https://github.com/sgdream/CVE-2020-1938](https://github.com/sgdream/CVE-2020-1938) :  ![starts](https://img.shields.io/github/stars/sgdream/CVE-2020-1938.svg) ![forks](https://img.shields.io/github/forks/sgdream/CVE-2020-1938.svg)
- [https://github.com/Zaziki1337/Ghostcat-CVE-2020-1938](https://github.com/Zaziki1337/Ghostcat-CVE-2020-1938) :  ![starts](https://img.shields.io/github/stars/Zaziki1337/Ghostcat-CVE-2020-1938.svg) ![forks](https://img.shields.io/github/forks/Zaziki1337/Ghostcat-CVE-2020-1938.svg)
- [https://github.com/acodervic/CVE-2020-1938-MSF-MODULE](https://github.com/acodervic/CVE-2020-1938-MSF-MODULE) :  ![starts](https://img.shields.io/github/stars/acodervic/CVE-2020-1938-MSF-MODULE.svg) ![forks](https://img.shields.io/github/forks/acodervic/CVE-2020-1938-MSF-MODULE.svg)
- [https://github.com/MateoSec/ghostcatch](https://github.com/MateoSec/ghostcatch) :  ![starts](https://img.shields.io/github/stars/MateoSec/ghostcatch.svg) ![forks](https://img.shields.io/github/forks/MateoSec/ghostcatch.svg)


## CVE-2020-0917
 An elevation of privilege vulnerability exists when Windows Hyper-V on a host server fails to properly handle objects in memory, aka 'Windows Hyper-V Elevation of Privilege Vulnerability'. This CVE ID is unique from CVE-2020-0918.

- [https://github.com/L0ch/CVE-2020-0917_Exploit](https://github.com/L0ch/CVE-2020-0917_Exploit) :  ![starts](https://img.shields.io/github/stars/L0ch/CVE-2020-0917_Exploit.svg) ![forks](https://img.shields.io/github/forks/L0ch/CVE-2020-0917_Exploit.svg)


## CVE-2018-3252
 Vulnerability in the Oracle WebLogic Server component of Oracle Fusion Middleware (subcomponent: WLS Core Components). Supported versions that are affected are 10.3.6.0, 12.1.3.0 and 12.2.1.3. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3 to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/go-spider/CVE-2018-3252](https://github.com/go-spider/CVE-2018-3252) :  ![starts](https://img.shields.io/github/stars/go-spider/CVE-2018-3252.svg) ![forks](https://img.shields.io/github/forks/go-spider/CVE-2018-3252.svg)


## CVE-2014-6271
 GNU Bash through 4.3 processes trailing strings after function definitions in the values of environment variables, which allows remote attackers to execute arbitrary code via a crafted environment, as demonstrated by vectors involving the ForceCommand feature in OpenSSH sshd, the mod_cgi and mod_cgid modules in the Apache HTTP Server, scripts executed by unspecified DHCP clients, and other situations in which setting the environment occurs across a privilege boundary from Bash execution, aka &quot;ShellShock.&quot;  NOTE: the original fix for this issue was incorrect; CVE-2014-7169 has been assigned to cover the vulnerability that is still present after the incorrect fix.

- [https://github.com/Darkrai-404/CVE-2014-6271-Shellshock-Vulnerability](https://github.com/Darkrai-404/CVE-2014-6271-Shellshock-Vulnerability) :  ![starts](https://img.shields.io/github/stars/Darkrai-404/CVE-2014-6271-Shellshock-Vulnerability.svg) ![forks](https://img.shields.io/github/forks/Darkrai-404/CVE-2014-6271-Shellshock-Vulnerability.svg)

