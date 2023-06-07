# Update 2023-06-07
## CVE-2023-33477
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/Skr11lex/CVE-2023-33477](https://github.com/Skr11lex/CVE-2023-33477) :  ![starts](https://img.shields.io/github/stars/Skr11lex/CVE-2023-33477.svg) ![forks](https://img.shields.io/github/forks/Skr11lex/CVE-2023-33477.svg)


## CVE-2023-33243
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/RedTeamPentesting/CVE-2023-33243](https://github.com/RedTeamPentesting/CVE-2023-33243) :  ![starts](https://img.shields.io/github/stars/RedTeamPentesting/CVE-2023-33243.svg) ![forks](https://img.shields.io/github/forks/RedTeamPentesting/CVE-2023-33243.svg)


## CVE-2023-2825
 An issue has been discovered in GitLab CE/EE affecting only version 16.0.0. An unauthenticated malicious user can use a path traversal vulnerability to read arbitrary files on the server when an attachment exists in a public project nested within at least five groups.

- [https://github.com/EmmanuelCruzL/CVE-2023-2825](https://github.com/EmmanuelCruzL/CVE-2023-2825) :  ![starts](https://img.shields.io/github/stars/EmmanuelCruzL/CVE-2023-2825.svg) ![forks](https://img.shields.io/github/forks/EmmanuelCruzL/CVE-2023-2825.svg)


## CVE-2023-2732
 The MStore API plugin for WordPress is vulnerable to authentication bypass in versions up to, and including, 3.9.2. This is due to insufficient verification on the user being supplied during the add listing REST API request through the plugin. This makes it possible for unauthenticated attackers to log in as any existing user on the site, such as an administrator, if they have access to the user id.

- [https://github.com/Jenderal92/WP-CVE-2023-2732](https://github.com/Jenderal92/WP-CVE-2023-2732) :  ![starts](https://img.shields.io/github/stars/Jenderal92/WP-CVE-2023-2732.svg) ![forks](https://img.shields.io/github/forks/Jenderal92/WP-CVE-2023-2732.svg)


## CVE-2023-2650
 Issue summary: Processing some specially crafted ASN.1 object identifiers or data containing them may be very slow. Impact summary: Applications that use OBJ_obj2txt() directly, or use any of the OpenSSL subsystems OCSP, PKCS7/SMIME, CMS, CMP/CRMF or TS with no message size limit may experience notable to very long delays when processing those messages, which may lead to a Denial of Service. An OBJECT IDENTIFIER is composed of a series of numbers - sub-identifiers - most of which have no size limit. OBJ_obj2txt() may be used to translate an ASN.1 OBJECT IDENTIFIER given in DER encoding form (using the OpenSSL type ASN1_OBJECT) to its canonical numeric text form, which are the sub-identifiers of the OBJECT IDENTIFIER in decimal form, separated by periods. When one of the sub-identifiers in the OBJECT IDENTIFIER is very large (these are sizes that are seen as absurdly large, taking up tens or hundreds of KiBs), the translation to a decimal number in text may take a very long time. The time complexity is O(n^2) with 'n' being the size of the sub-identifiers in bytes (*). With OpenSSL 3.0, support to fetch cryptographic algorithms using names / identifiers in string form was introduced. This includes using OBJECT IDENTIFIERs in canonical numeric text form as identifiers for fetching algorithms. Such OBJECT IDENTIFIERs may be received through the ASN.1 structure AlgorithmIdentifier, which is commonly used in multiple protocols to specify what cryptographic algorithm should be used to sign or verify, encrypt or decrypt, or digest passed data. Applications that call OBJ_obj2txt() directly with untrusted data are affected, with any version of OpenSSL. If the use is for the mere purpose of display, the severity is considered low. In OpenSSL 3.0 and newer, this affects the subsystems OCSP, PKCS7/SMIME, CMS, CMP/CRMF or TS. It also impacts anything that processes X.509 certificates, including simple things like verifying its signature. The impact on TLS is relatively low, because all versions of OpenSSL have a 100KiB limit on the peer's certificate chain. Additionally, this only impacts clients, or servers that have explicitly enabled client authentication. In OpenSSL 1.1.1 and 1.0.2, this only affects displaying diverse objects, such as X.509 certificates. This is assumed to not happen in such a way that it would cause a Denial of Service, so these versions are considered not affected by this issue in such a way that it would be cause for concern, and the severity is therefore considered low.

- [https://github.com/hshivhare67/OpenSSL_1.1.1g_CVE-2023-2650](https://github.com/hshivhare67/OpenSSL_1.1.1g_CVE-2023-2650) :  ![starts](https://img.shields.io/github/stars/hshivhare67/OpenSSL_1.1.1g_CVE-2023-2650.svg) ![forks](https://img.shields.io/github/forks/hshivhare67/OpenSSL_1.1.1g_CVE-2023-2650.svg)


## CVE-2021-42013
 It was found that the fix for CVE-2021-41773 in Apache HTTP Server 2.4.50 was insufficient. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue only affects Apache 2.4.49 and Apache 2.4.50 and not earlier versions.

- [https://github.com/sergiovks/LFI-RCE-Unauthenticated-Apache-2.4.49-2.4.50](https://github.com/sergiovks/LFI-RCE-Unauthenticated-Apache-2.4.49-2.4.50) :  ![starts](https://img.shields.io/github/stars/sergiovks/LFI-RCE-Unauthenticated-Apache-2.4.49-2.4.50.svg) ![forks](https://img.shields.io/github/forks/sergiovks/LFI-RCE-Unauthenticated-Apache-2.4.49-2.4.50.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/mightysai1997/cve-2021-41773](https://github.com/mightysai1997/cve-2021-41773) :  ![starts](https://img.shields.io/github/stars/mightysai1997/cve-2021-41773.svg) ![forks](https://img.shields.io/github/forks/mightysai1997/cve-2021-41773.svg)


## CVE-2021-22911
 A improper input sanitization vulnerability exists in Rocket.Chat server 3.11, 3.12 &amp; 3.13 that could lead to unauthenticated NoSQL injection, resulting potentially in RCE.

- [https://github.com/MrDottt/CVE-2021-22911](https://github.com/MrDottt/CVE-2021-22911) :  ![starts](https://img.shields.io/github/stars/MrDottt/CVE-2021-22911.svg) ![forks](https://img.shields.io/github/forks/MrDottt/CVE-2021-22911.svg)


## CVE-2021-21234
 spring-boot-actuator-logview in a library that adds a simple logfile viewer as spring boot actuator endpoint. It is maven package &quot;eu.hinsch:spring-boot-actuator-logview&quot;. In spring-boot-actuator-logview before version 0.2.13 there is a directory traversal vulnerability. The nature of this library is to expose a log file directory via admin (spring boot actuator) HTTP endpoints. Both the filename to view and a base folder (relative to the logging folder root) can be specified via request parameters. While the filename parameter was checked to prevent directory traversal exploits (so that `filename=../somefile` would not work), the base folder parameter was not sufficiently checked, so that `filename=somefile&amp;base=../` could access a file outside the logging base directory). The vulnerability has been patched in release 0.2.13. Any users of 0.2.12 should be able to update without any issues as there are no other changes in that release. There is no workaround to fix the vulnerability other than updating or removing the dependency. However, removing read access of the user the application is run with to any directory not required for running the application can limit the impact. Additionally, access to the logview endpoint can be limited by deploying the application behind a reverse proxy.

- [https://github.com/CLincat/vulcat](https://github.com/CLincat/vulcat) :  ![starts](https://img.shields.io/github/stars/CLincat/vulcat.svg) ![forks](https://img.shields.io/github/forks/CLincat/vulcat.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/zhzyker/CVE-2021-4034](https://github.com/zhzyker/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/zhzyker/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/zhzyker/CVE-2021-4034.svg)
- [https://github.com/c3l3si4n/pwnkit](https://github.com/c3l3si4n/pwnkit) :  ![starts](https://img.shields.io/github/stars/c3l3si4n/pwnkit.svg) ![forks](https://img.shields.io/github/forks/c3l3si4n/pwnkit.svg)
- [https://github.com/dadvlingd/CVE-2021-4034](https://github.com/dadvlingd/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/dadvlingd/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/dadvlingd/CVE-2021-4034.svg)
- [https://github.com/chenaotian/CVE-2021-4034](https://github.com/chenaotian/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/chenaotian/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/chenaotian/CVE-2021-4034.svg)
- [https://github.com/Kirill89/CVE-2021-4034](https://github.com/Kirill89/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/Kirill89/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/Kirill89/CVE-2021-4034.svg)
- [https://github.com/FDlucifer/Pwnkit-go](https://github.com/FDlucifer/Pwnkit-go) :  ![starts](https://img.shields.io/github/stars/FDlucifer/Pwnkit-go.svg) ![forks](https://img.shields.io/github/forks/FDlucifer/Pwnkit-go.svg)
- [https://github.com/x04000/CVE-2021-4034](https://github.com/x04000/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/x04000/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/x04000/CVE-2021-4034.svg)


## CVE-2021-3129
 Ignition before 2.5.2, as used in Laravel and other products, allows unauthenticated remote attackers to execute arbitrary code because of insecure usage of file_get_contents() and file_put_contents(). This is exploitable on sites using debug mode with Laravel before 8.4.2.

- [https://github.com/knqyf263/CVE-2021-3129](https://github.com/knqyf263/CVE-2021-3129) :  ![starts](https://img.shields.io/github/stars/knqyf263/CVE-2021-3129.svg) ![forks](https://img.shields.io/github/forks/knqyf263/CVE-2021-3129.svg)
- [https://github.com/aurelien-vilminot/ENSIMAG_EXPLOIT_CVE2_3A](https://github.com/aurelien-vilminot/ENSIMAG_EXPLOIT_CVE2_3A) :  ![starts](https://img.shields.io/github/stars/aurelien-vilminot/ENSIMAG_EXPLOIT_CVE2_3A.svg) ![forks](https://img.shields.io/github/forks/aurelien-vilminot/ENSIMAG_EXPLOIT_CVE2_3A.svg)
- [https://github.com/qaisarafridi/cve-2021-3129](https://github.com/qaisarafridi/cve-2021-3129) :  ![starts](https://img.shields.io/github/stars/qaisarafridi/cve-2021-3129.svg) ![forks](https://img.shields.io/github/forks/qaisarafridi/cve-2021-3129.svg)
- [https://github.com/Zoo1sondv/CVE-2021-3129](https://github.com/Zoo1sondv/CVE-2021-3129) :  ![starts](https://img.shields.io/github/stars/Zoo1sondv/CVE-2021-3129.svg) ![forks](https://img.shields.io/github/forks/Zoo1sondv/CVE-2021-3129.svg)


## CVE-2020-1938
 When using the Apache JServ Protocol (AJP), care must be taken when trusting incoming connections to Apache Tomcat. Tomcat treats AJP connections as having higher trust than, for example, a similar HTTP connection. If such connections are available to an attacker, they can be exploited in ways that may be surprising. In Apache Tomcat 9.0.0.M1 to 9.0.0.30, 8.5.0 to 8.5.50 and 7.0.0 to 7.0.99, Tomcat shipped with an AJP Connector enabled by default that listened on all configured IP addresses. It was expected (and recommended in the security guide) that this Connector would be disabled if not required. This vulnerability report identified a mechanism that allowed: - returning arbitrary files from anywhere in the web application - processing any file in the web application as a JSP Further, if the web application allowed file upload and stored those files within the web application (or the attacker was able to control the content of the web application by some other means) then this, along with the ability to process a file as a JSP, made remote code execution possible. It is important to note that mitigation is only required if an AJP port is accessible to untrusted users. Users wishing to take a defence-in-depth approach and block the vector that permits returning arbitrary files and execution as JSP may upgrade to Apache Tomcat 9.0.31, 8.5.51 or 7.0.100 or later. A number of changes were made to the default AJP Connector configuration in 9.0.31 to harden the default configuration. It is likely that users upgrading to 9.0.31, 8.5.51 or 7.0.100 or later will need to make small changes to their configurations.

- [https://github.com/xindongzhuaizhuai/CVE-2020-1938](https://github.com/xindongzhuaizhuai/CVE-2020-1938) :  ![starts](https://img.shields.io/github/stars/xindongzhuaizhuai/CVE-2020-1938.svg) ![forks](https://img.shields.io/github/forks/xindongzhuaizhuai/CVE-2020-1938.svg)
- [https://github.com/woaiqiukui/CVE-2020-1938TomcatAjpScanner](https://github.com/woaiqiukui/CVE-2020-1938TomcatAjpScanner) :  ![starts](https://img.shields.io/github/stars/woaiqiukui/CVE-2020-1938TomcatAjpScanner.svg) ![forks](https://img.shields.io/github/forks/woaiqiukui/CVE-2020-1938TomcatAjpScanner.svg)
- [https://github.com/fairyming/CVE-2020-1938](https://github.com/fairyming/CVE-2020-1938) :  ![starts](https://img.shields.io/github/stars/fairyming/CVE-2020-1938.svg) ![forks](https://img.shields.io/github/forks/fairyming/CVE-2020-1938.svg)
- [https://github.com/dacade/CVE-2020-1938](https://github.com/dacade/CVE-2020-1938) :  ![starts](https://img.shields.io/github/stars/dacade/CVE-2020-1938.svg) ![forks](https://img.shields.io/github/forks/dacade/CVE-2020-1938.svg)
- [https://github.com/Just1ceP4rtn3r/CVE-2020-1938-Tool](https://github.com/Just1ceP4rtn3r/CVE-2020-1938-Tool) :  ![starts](https://img.shields.io/github/stars/Just1ceP4rtn3r/CVE-2020-1938-Tool.svg) ![forks](https://img.shields.io/github/forks/Just1ceP4rtn3r/CVE-2020-1938-Tool.svg)
- [https://github.com/Umesh2807/Ghostcat](https://github.com/Umesh2807/Ghostcat) :  ![starts](https://img.shields.io/github/stars/Umesh2807/Ghostcat.svg) ![forks](https://img.shields.io/github/forks/Umesh2807/Ghostcat.svg)


## CVE-2019-2025
 In binder_thread_read of binder.c, there is a possible use-after-free due to improper locking. This could lead to local escalation of privilege in the kernel with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-116855682References: Upstream kernel

- [https://github.com/jltxgcy/CVE_2019_2025_EXP](https://github.com/jltxgcy/CVE_2019_2025_EXP) :  ![starts](https://img.shields.io/github/stars/jltxgcy/CVE_2019_2025_EXP.svg) ![forks](https://img.shields.io/github/forks/jltxgcy/CVE_2019_2025_EXP.svg)


## CVE-2018-1111
 DHCP packages in Red Hat Enterprise Linux 6 and 7, Fedora 28, and earlier are vulnerable to a command injection flaw in the NetworkManager integration script included in the DHCP client. A malicious DHCP server, or an attacker on the local network able to spoof DHCP responses, could use this flaw to execute arbitrary commands with root privileges on systems using NetworkManager and configured to obtain network configuration using the DHCP protocol.

- [https://github.com/kkirsche/CVE-2018-1111](https://github.com/kkirsche/CVE-2018-1111) :  ![starts](https://img.shields.io/github/stars/kkirsche/CVE-2018-1111.svg) ![forks](https://img.shields.io/github/forks/kkirsche/CVE-2018-1111.svg)


## CVE-2015-1805
 The (1) pipe_read and (2) pipe_write implementations in fs/pipe.c in the Linux kernel before 3.16 do not properly consider the side effects of failed __copy_to_user_inatomic and __copy_from_user_inatomic calls, which allows local users to cause a denial of service (system crash) or possibly gain privileges via a crafted application, aka an &quot;I/O vector array overrun.&quot;

- [https://github.com/dosomder/iovyroot](https://github.com/dosomder/iovyroot) :  ![starts](https://img.shields.io/github/stars/dosomder/iovyroot.svg) ![forks](https://img.shields.io/github/forks/dosomder/iovyroot.svg)

