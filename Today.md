# Update 2023-03-12
## CVE-2023-27898
 Jenkins 2.270 through 2.393 (both inclusive), LTS 2.277.1 through 2.375.3 (both inclusive) does not escape the Jenkins version a plugin depends on when rendering the error message stating its incompatibility with the current version of Jenkins, resulting in a stored cross-site scripting (XSS) vulnerability exploitable by attackers able to provide plugins to the configured update sites and have this message shown by Jenkins instances.

- [https://github.com/Inplex-sys/CVE-2022-23093](https://github.com/Inplex-sys/CVE-2022-23093) :  ![starts](https://img.shields.io/github/stars/Inplex-sys/CVE-2022-23093.svg) ![forks](https://img.shields.io/github/forks/Inplex-sys/CVE-2022-23093.svg)


## CVE-2023-24749
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/mahaloz/netgear-pwnagent](https://github.com/mahaloz/netgear-pwnagent) :  ![starts](https://img.shields.io/github/stars/mahaloz/netgear-pwnagent.svg) ![forks](https://img.shields.io/github/forks/mahaloz/netgear-pwnagent.svg)


## CVE-2023-24055
 ** DISPUTED ** KeePass through 2.53 (in a default installation) allows an attacker, who has write access to the XML configuration file, to obtain the cleartext passwords by adding an export trigger. NOTE: the vendor's position is that the password database is not intended to be secure against an attacker who has that level of access to the local PC.

- [https://github.com/poppylarrry/Zero-Days](https://github.com/poppylarrry/Zero-Days) :  ![starts](https://img.shields.io/github/stars/poppylarrry/Zero-Days.svg) ![forks](https://img.shields.io/github/forks/poppylarrry/Zero-Days.svg)


## CVE-2023-23752
 An issue was discovered in Joomla! 4.0.0 through 4.2.7. An improper access check allows unauthorized access to webservice endpoints.

- [https://github.com/H454NSec/CVE-2023-23752](https://github.com/H454NSec/CVE-2023-23752) :  ![starts](https://img.shields.io/github/stars/H454NSec/CVE-2023-23752.svg) ![forks](https://img.shields.io/github/forks/H454NSec/CVE-2023-23752.svg)


## CVE-2023-22960
 Lexmark products through 2023-01-10 have Improper Control of Interaction Frequency.

- [https://github.com/poppylarrry/Zero-Days](https://github.com/poppylarrry/Zero-Days) :  ![starts](https://img.shields.io/github/stars/poppylarrry/Zero-Days.svg) ![forks](https://img.shields.io/github/forks/poppylarrry/Zero-Days.svg)


## CVE-2023-22809
 In Sudo before 1.9.12p2, the sudoedit (aka -e) feature mishandles extra arguments passed in the user-provided environment variables (SUDO_EDITOR, VISUAL, and EDITOR), allowing a local attacker to append arbitrary entries to the list of files to process. This can lead to privilege escalation. Affected versions are 1.8.0 through 1.9.12.p1. The problem exists because a user-specified editor may contain a &quot;--&quot; argument that defeats a protection mechanism, e.g., an EDITOR='vim -- /path/to/extra/file' value.

- [https://github.com/poppylarrry/Zero-Days](https://github.com/poppylarrry/Zero-Days) :  ![starts](https://img.shields.io/github/stars/poppylarrry/Zero-Days.svg) ![forks](https://img.shields.io/github/forks/poppylarrry/Zero-Days.svg)


## CVE-2023-21839
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Core). Supported versions that are affected are 12.2.1.3.0, 12.2.1.4.0 and 14.1.1.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3, IIOP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in unauthorized access to critical data or complete access to all Oracle WebLogic Server accessible data. CVSS 3.1 Base Score 7.5 (Confidentiality impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N).

- [https://github.com/poppylarrry/Zero-Days](https://github.com/poppylarrry/Zero-Days) :  ![starts](https://img.shields.io/github/stars/poppylarrry/Zero-Days.svg) ![forks](https://img.shields.io/github/forks/poppylarrry/Zero-Days.svg)


## CVE-2023-21768
 Windows Ancillary Function Driver for WinSock Elevation of Privilege Vulnerability.

- [https://github.com/SamuelTulach/nullmap](https://github.com/SamuelTulach/nullmap) :  ![starts](https://img.shields.io/github/stars/SamuelTulach/nullmap.svg) ![forks](https://img.shields.io/github/forks/SamuelTulach/nullmap.svg)


## CVE-2023-21608
 Adobe Acrobat Reader versions 22.003.20282 (and earlier), 22.003.20281 (and earlier) and 20.005.30418 (and earlier) are affected by a Use After Free vulnerability that could result in arbitrary code execution in the context of the current user. Exploitation of this issue requires user interaction in that a victim must open a malicious file.

- [https://github.com/poppylarrry/Zero-Days](https://github.com/poppylarrry/Zero-Days) :  ![starts](https://img.shields.io/github/stars/poppylarrry/Zero-Days.svg) ![forks](https://img.shields.io/github/forks/poppylarrry/Zero-Days.svg)


## CVE-2022-26809
 Remote Procedure Call Runtime Remote Code Execution Vulnerability. This CVE ID is unique from CVE-2022-24492, CVE-2022-24528.

- [https://github.com/poppylarrry/Zero-Days](https://github.com/poppylarrry/Zero-Days) :  ![starts](https://img.shields.io/github/stars/poppylarrry/Zero-Days.svg) ![forks](https://img.shields.io/github/forks/poppylarrry/Zero-Days.svg)


## CVE-2022-3602
 A buffer overrun can be triggered in X.509 certificate verification, specifically in name constraint checking. Note that this occurs after certificate chain signature verification and requires either a CA to have signed the malicious certificate or for the application to continue certificate verification despite failure to construct a path to a trusted issuer. An attacker can craft a malicious email address to overflow four attacker-controlled bytes on the stack. This buffer overflow could result in a crash (causing a denial of service) or potentially remote code execution. Many platforms implement stack overflow protections which would mitigate against the risk of remote code execution. The risk may be further mitigated based on stack layout for any given platform/compiler. Pre-announcements of CVE-2022-3602 described this issue as CRITICAL. Further analysis based on some of the mitigating factors described above have led this to be downgraded to HIGH. Users are still encouraged to upgrade to a new version as soon as possible. In a TLS client, this can be triggered by connecting to a malicious server. In a TLS server, this can be triggered if the server requests client authentication and a malicious client connects. Fixed in OpenSSL 3.0.7 (Affected 3.0.0,3.0.1,3.0.2,3.0.3,3.0.4,3.0.5,3.0.6).

- [https://github.com/rbowes-r7/cve-2022-3602-and-cve-2022-3786-openssl-poc](https://github.com/rbowes-r7/cve-2022-3602-and-cve-2022-3786-openssl-poc) :  ![starts](https://img.shields.io/github/stars/rbowes-r7/cve-2022-3602-and-cve-2022-3786-openssl-poc.svg) ![forks](https://img.shields.io/github/forks/rbowes-r7/cve-2022-3602-and-cve-2022-3786-openssl-poc.svg)


## CVE-2022-0995
 An out-of-bounds (OOB) memory write flaw was found in the Linux kernel&#8217;s watch_queue event notification subsystem. This flaw can overwrite parts of the kernel state, potentially allowing a local user to gain privileged access or cause a denial of service on the system.

- [https://github.com/AndreevSemen/CVE-2022-0995](https://github.com/AndreevSemen/CVE-2022-0995) :  ![starts](https://img.shields.io/github/stars/AndreevSemen/CVE-2022-0995.svg) ![forks](https://img.shields.io/github/forks/AndreevSemen/CVE-2022-0995.svg)


## CVE-2022-0847
 A flaw was found in the way the &quot;flags&quot; member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/poppylarrry/Zero-Days](https://github.com/poppylarrry/Zero-Days) :  ![starts](https://img.shields.io/github/stars/poppylarrry/Zero-Days.svg) ![forks](https://img.shields.io/github/forks/poppylarrry/Zero-Days.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/sixpacksecurity/CVE-2021-41773](https://github.com/sixpacksecurity/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/sixpacksecurity/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/sixpacksecurity/CVE-2021-41773.svg)


## CVE-2021-27065
 Microsoft Exchange Server Remote Code Execution Vulnerability This CVE ID is unique from CVE-2021-26412, CVE-2021-26854, CVE-2021-26855, CVE-2021-26857, CVE-2021-26858, CVE-2021-27078.

- [https://github.com/byinarie/Zirconium](https://github.com/byinarie/Zirconium) :  ![starts](https://img.shields.io/github/stars/byinarie/Zirconium.svg) ![forks](https://img.shields.io/github/forks/byinarie/Zirconium.svg)


## CVE-2021-26858
 Microsoft Exchange Server Remote Code Execution Vulnerability This CVE ID is unique from CVE-2021-26412, CVE-2021-26854, CVE-2021-26855, CVE-2021-26857, CVE-2021-27065, CVE-2021-27078.

- [https://github.com/byinarie/Zirconium](https://github.com/byinarie/Zirconium) :  ![starts](https://img.shields.io/github/stars/byinarie/Zirconium.svg) ![forks](https://img.shields.io/github/forks/byinarie/Zirconium.svg)


## CVE-2021-26857
 Microsoft Exchange Server Remote Code Execution Vulnerability This CVE ID is unique from CVE-2021-26412, CVE-2021-26854, CVE-2021-26855, CVE-2021-26858, CVE-2021-27065, CVE-2021-27078.

- [https://github.com/byinarie/Zirconium](https://github.com/byinarie/Zirconium) :  ![starts](https://img.shields.io/github/stars/byinarie/Zirconium.svg) ![forks](https://img.shields.io/github/forks/byinarie/Zirconium.svg)


## CVE-2021-26855
 Microsoft Exchange Server Remote Code Execution Vulnerability This CVE ID is unique from CVE-2021-26412, CVE-2021-26854, CVE-2021-26857, CVE-2021-26858, CVE-2021-27065, CVE-2021-27078.

- [https://github.com/byinarie/Zirconium](https://github.com/byinarie/Zirconium) :  ![starts](https://img.shields.io/github/stars/byinarie/Zirconium.svg) ![forks](https://img.shields.io/github/forks/byinarie/Zirconium.svg)


## CVE-2021-4104
 JMSAppender in Log4j 1.2 is vulnerable to deserialization of untrusted data when the attacker has write access to the Log4j configuration. The attacker can provide TopicBindingName and TopicConnectionFactoryBindingName configurations causing JMSAppender to perform JNDI requests that result in remote code execution in a similar fashion to CVE-2021-44228. Note this issue only affects Log4j 1.2 when specifically configured to use JMSAppender, which is not the default. Apache Log4j 1.2 reached end of life in August 2015. Users should upgrade to Log4j 2 as it addresses numerous other issues from the previous versions.

- [https://github.com/thl-cmk/CVE-log4j-check_mk-plugin](https://github.com/thl-cmk/CVE-log4j-check_mk-plugin) :  ![starts](https://img.shields.io/github/stars/thl-cmk/CVE-log4j-check_mk-plugin.svg) ![forks](https://img.shields.io/github/forks/thl-cmk/CVE-log4j-check_mk-plugin.svg)


## CVE-2021-3019
 ffay lanproxy 0.1 allows Directory Traversal to read /../conf/config.properties to obtain credentials for a connection to the intranet.

- [https://github.com/Maksim-venus/CVE-2021-3019](https://github.com/Maksim-venus/CVE-2021-3019) :  ![starts](https://img.shields.io/github/stars/Maksim-venus/CVE-2021-3019.svg) ![forks](https://img.shields.io/github/forks/Maksim-venus/CVE-2021-3019.svg)


## CVE-2020-1472
 An elevation of privilege vulnerability exists when an attacker establishes a vulnerable Netlogon secure channel connection to a domain controller, using the Netlogon Remote Protocol (MS-NRPC), aka 'Netlogon Elevation of Privilege Vulnerability'.

- [https://github.com/mos165/CVE-20200-1472](https://github.com/mos165/CVE-20200-1472) :  ![starts](https://img.shields.io/github/stars/mos165/CVE-20200-1472.svg) ![forks](https://img.shields.io/github/forks/mos165/CVE-20200-1472.svg)
- [https://github.com/SaharAttackit/CVE-2020-1472](https://github.com/SaharAttackit/CVE-2020-1472) :  ![starts](https://img.shields.io/github/stars/SaharAttackit/CVE-2020-1472.svg) ![forks](https://img.shields.io/github/forks/SaharAttackit/CVE-2020-1472.svg)


## CVE-2019-6111
 An issue was discovered in OpenSSH 7.9. Due to the scp implementation being derived from 1983 rcp, the server chooses which files/directories are sent to the client. However, the scp client only performs cursory validation of the object name returned (only directory traversal attacks are prevented). A malicious scp server (or Man-in-The-Middle attacker) can overwrite arbitrary files in the scp client target directory. If recursive operation (-r) is performed, the server can manipulate subdirectories as well (for example, to overwrite the .ssh/authorized_keys file).

- [https://github.com/Sigmw/CVE-2019-6111-poc](https://github.com/Sigmw/CVE-2019-6111-poc) :  ![starts](https://img.shields.io/github/stars/Sigmw/CVE-2019-6111-poc.svg) ![forks](https://img.shields.io/github/forks/Sigmw/CVE-2019-6111-poc.svg)


## CVE-2018-1324
 A specially crafted ZIP archive can be used to cause an infinite loop inside of Apache Commons Compress' extra field parser used by the ZipFile and ZipArchiveInputStream classes in versions 1.11 to 1.15. This can be used to mount a denial of service attack against services that use Compress' zip package.

- [https://github.com/tafamace/CVE-2018-1324](https://github.com/tafamace/CVE-2018-1324) :  ![starts](https://img.shields.io/github/stars/tafamace/CVE-2018-1324.svg) ![forks](https://img.shields.io/github/forks/tafamace/CVE-2018-1324.svg)


## CVE-2017-12615
 When running Apache Tomcat 7.0.0 to 7.0.79 on Windows with HTTP PUTs enabled (e.g. via setting the readonly initialisation parameter of the Default to false) it was possible to upload a JSP file to the server via a specially crafted request. This JSP could then be requested and any code it contained would be executed by the server.

- [https://github.com/xiaokp7/Tomcat_PUT_EXP](https://github.com/xiaokp7/Tomcat_PUT_EXP) :  ![starts](https://img.shields.io/github/stars/xiaokp7/Tomcat_PUT_EXP.svg) ![forks](https://img.shields.io/github/forks/xiaokp7/Tomcat_PUT_EXP.svg)

