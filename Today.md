# Update 2023-12-28
## CVE-2023-51764
 Postfix through 3.8.4 allows SMTP smuggling unless configured with smtpd_data_restrictions=reject_unauth_pipelining and smtpd_discard_ehlo_keywords=chunking (or certain other options that exist in recent versions). Remote attackers can use a published exploitation technique to inject e-mail messages with a spoofed MAIL FROM address, allowing bypass of an SPF protection mechanism. This occurs because Postfix supports &lt;LF&gt;.&lt;CR&gt;&lt;LF&gt; but some other popular e-mail servers do not. To prevent attack variants (by always disallowing &lt;LF&gt; without &lt;CR&gt;), a different solution is required: the smtpd_forbid_bare_newline=yes option with a Postfix minimum version of 3.5.23, 3.6.13, 3.7.9, 3.8.4, or 3.9.

- [https://github.com/duy-31/CVE-2023-51764](https://github.com/duy-31/CVE-2023-51764) :  ![starts](https://img.shields.io/github/stars/duy-31/CVE-2023-51764.svg) ![forks](https://img.shields.io/github/forks/duy-31/CVE-2023-51764.svg)


## CVE-2023-51385
 In ssh in OpenSSH before 9.6, OS command injection might occur if a user name or host name has shell metacharacters, and this name is referenced by an expansion token in certain situations. For example, an untrusted Git repository can have a submodule with shell metacharacters in a user name or host name.

- [https://github.com/WLaoDuo/CVE-2023-51385_poc-test](https://github.com/WLaoDuo/CVE-2023-51385_poc-test) :  ![starts](https://img.shields.io/github/stars/WLaoDuo/CVE-2023-51385_poc-test.svg) ![forks](https://img.shields.io/github/forks/WLaoDuo/CVE-2023-51385_poc-test.svg)


## CVE-2023-43177
 CrushFTP prior to 10.5.1 is vulnerable to Improperly Controlled Modification of Dynamically-Determined Object Attributes.

- [https://github.com/the-emmons/CVE-2023-43177](https://github.com/the-emmons/CVE-2023-43177) :  ![starts](https://img.shields.io/github/stars/the-emmons/CVE-2023-43177.svg) ![forks](https://img.shields.io/github/forks/the-emmons/CVE-2023-43177.svg)


## CVE-2023-41892
 Craft CMS is a platform for creating digital experiences. This is a high-impact, low-complexity attack vector. Users running Craft installations before 4.4.15 are encouraged to update to at least that version to mitigate the issue. This issue has been fixed in Craft CMS 4.4.15.

- [https://github.com/Faelian/CraftCMS_CVE-2023-41892](https://github.com/Faelian/CraftCMS_CVE-2023-41892) :  ![starts](https://img.shields.io/github/stars/Faelian/CraftCMS_CVE-2023-41892.svg) ![forks](https://img.shields.io/github/forks/Faelian/CraftCMS_CVE-2023-41892.svg)


## CVE-2023-40037
 Apache NiFi 1.21.0 through 1.23.0 support JDBC and JNDI JMS access in several Processors and Controller Services with connection URL validation that does not provide sufficient protection against crafted inputs. An authenticated and authorized user can bypass connection URL validation using custom input formatting. The resolution enhances connection URL validation and introduces validation for additional related properties. Upgrading to Apache NiFi 1.23.1 is the recommended mitigation.

- [https://github.com/mbadanoiu/CVE-2023-40037](https://github.com/mbadanoiu/CVE-2023-40037) :  ![starts](https://img.shields.io/github/stars/mbadanoiu/CVE-2023-40037.svg) ![forks](https://img.shields.io/github/forks/mbadanoiu/CVE-2023-40037.svg)


## CVE-2023-33246
 For RocketMQ versions 5.1.0 and below, under certain conditions, there is a risk of remote command execution. Several components of RocketMQ, including NameServer, Broker, and Controller, are leaked on the extranet and lack permission verification, an attacker can exploit this vulnerability by using the update configuration function to execute commands as the system users that RocketMQ is running as. Additionally, an attacker can achieve the same effect by forging the RocketMQ protocol content. To prevent these attacks, users are recommended to upgrade to version 5.1.1 or above for using RocketMQ 5.x or 4.9.6 or above for using RocketMQ 4.x .

- [https://github.com/MkJos/CVE-2023-33246_RocketMQ_RCE_EXP](https://github.com/MkJos/CVE-2023-33246_RocketMQ_RCE_EXP) :  ![starts](https://img.shields.io/github/stars/MkJos/CVE-2023-33246_RocketMQ_RCE_EXP.svg) ![forks](https://img.shields.io/github/forks/MkJos/CVE-2023-33246_RocketMQ_RCE_EXP.svg)


## CVE-2023-21266
 In killBackgroundProcesses of ActivityManagerService.java, there is a possible way to escape Google Play protection due to a permissions bypass. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/nidhi7598/frameworks_base_AOSP10_r33_CVE-2023-21266](https://github.com/nidhi7598/frameworks_base_AOSP10_r33_CVE-2023-21266) :  ![starts](https://img.shields.io/github/stars/nidhi7598/frameworks_base_AOSP10_r33_CVE-2023-21266.svg) ![forks](https://img.shields.io/github/forks/nidhi7598/frameworks_base_AOSP10_r33_CVE-2023-21266.svg)


## CVE-2023-2868
 A remote command injection vulnerability exists in the Barracuda Email Security Gateway (appliance form factor only) product effecting versions 5.1.3.001-9.2.0.006. The vulnerability arises out of a failure to comprehensively sanitize the processing of .tar file (tape archives). The vulnerability stems from incomplete input validation of a user-supplied .tar file as it pertains to the names of the files contained within the archive. As a consequence, a remote attacker can specifically format these file names in a particular manner that will result in remotely executing a system command through Perl's qx operator with the privileges of the Email Security Gateway product. This issue was fixed as part of BNSF-36456 patch. This patch was automatically applied to all customer appliances.

- [https://github.com/cfielding-r7/poc-cve-2023-2868](https://github.com/cfielding-r7/poc-cve-2023-2868) :  ![starts](https://img.shields.io/github/stars/cfielding-r7/poc-cve-2023-2868.svg) ![forks](https://img.shields.io/github/forks/cfielding-r7/poc-cve-2023-2868.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/m96dg/CVE-2021-41773-exercise](https://github.com/m96dg/CVE-2021-41773-exercise) :  ![starts](https://img.shields.io/github/stars/m96dg/CVE-2021-41773-exercise.svg) ![forks](https://img.shields.io/github/forks/m96dg/CVE-2021-41773-exercise.svg)


## CVE-2021-32305
 WebSVN before 2.6.1 allows remote attackers to execute arbitrary commands via shell metacharacters in the search parameter.

- [https://github.com/FredBrave/CVE-2021-32305-websvn-2.6.0](https://github.com/FredBrave/CVE-2021-32305-websvn-2.6.0) :  ![starts](https://img.shields.io/github/stars/FredBrave/CVE-2021-32305-websvn-2.6.0.svg) ![forks](https://img.shields.io/github/forks/FredBrave/CVE-2021-32305-websvn-2.6.0.svg)


## CVE-2021-27065
 Microsoft Exchange Server Remote Code Execution Vulnerability This CVE ID is unique from CVE-2021-26412, CVE-2021-26854, CVE-2021-26855, CVE-2021-26857, CVE-2021-26858, CVE-2021-27078.

- [https://github.com/gobysec/Goby](https://github.com/gobysec/Goby) :  ![starts](https://img.shields.io/github/stars/gobysec/Goby.svg) ![forks](https://img.shields.io/github/forks/gobysec/Goby.svg)
- [https://github.com/dwisiswant0/proxylogscan](https://github.com/dwisiswant0/proxylogscan) :  ![starts](https://img.shields.io/github/stars/dwisiswant0/proxylogscan.svg) ![forks](https://img.shields.io/github/forks/dwisiswant0/proxylogscan.svg)
- [https://github.com/ssrsec/Microsoft-Exchange-RCE](https://github.com/ssrsec/Microsoft-Exchange-RCE) :  ![starts](https://img.shields.io/github/stars/ssrsec/Microsoft-Exchange-RCE.svg) ![forks](https://img.shields.io/github/forks/ssrsec/Microsoft-Exchange-RCE.svg)


## CVE-2021-3156
 Sudo before 1.9.5p2 contains an off-by-one error that can result in a heap-based buffer overflow, which allows privilege escalation to root via &quot;sudoedit -s&quot; and a command-line argument that ends with a single backslash character.

- [https://github.com/DDayLuong/CVE-2021-3156](https://github.com/DDayLuong/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/DDayLuong/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/DDayLuong/CVE-2021-3156.svg)


## CVE-2020-14064
 IceWarp Email Server 12.3.0.1 has Incorrect Access Control for user accounts.

- [https://github.com/networksecure/CVE-2020-14064](https://github.com/networksecure/CVE-2020-14064) :  ![starts](https://img.shields.io/github/stars/networksecure/CVE-2020-14064.svg) ![forks](https://img.shields.io/github/forks/networksecure/CVE-2020-14064.svg)


## CVE-2019-18634
 In Sudo before 1.8.26, if pwfeedback is enabled in /etc/sudoers, users can trigger a stack-based buffer overflow in the privileged sudo process. (pwfeedback is a default setting in Linux Mint and elementary OS; however, it is NOT the default for upstream and many other packages, and would exist only if enabled by an administrator.) The attacker needs to deliver a long string to the stdin of getln() in tgetpass.c.

- [https://github.com/DDayLuong/CVE-2019-18634](https://github.com/DDayLuong/CVE-2019-18634) :  ![starts](https://img.shields.io/github/stars/DDayLuong/CVE-2019-18634.svg) ![forks](https://img.shields.io/github/forks/DDayLuong/CVE-2019-18634.svg)


## CVE-2019-16098
 The driver in Micro-Star MSI Afterburner 4.6.2.15658 (aka RTCore64.sys and RTCore32.sys) allows any authenticated user to read and write to arbitrary memory, I/O ports, and MSRs. This can be exploited for privilege escalation, code execution under high privileges, and information disclosure. These signed drivers can also be used to bypass the Microsoft driver-signing policy to deploy malicious code.

- [https://github.com/houseofxyz/CVE-2019-16098](https://github.com/houseofxyz/CVE-2019-16098) :  ![starts](https://img.shields.io/github/stars/houseofxyz/CVE-2019-16098.svg) ![forks](https://img.shields.io/github/forks/houseofxyz/CVE-2019-16098.svg)


## CVE-2019-12840
 In Webmin through 1.910, any user authorized to the &quot;Package Updates&quot; module can execute arbitrary commands with root privileges via the data parameter to update.cgi.

- [https://github.com/zAbuQasem/CVE-2019-12840](https://github.com/zAbuQasem/CVE-2019-12840) :  ![starts](https://img.shields.io/github/stars/zAbuQasem/CVE-2019-12840.svg) ![forks](https://img.shields.io/github/forks/zAbuQasem/CVE-2019-12840.svg)
- [https://github.com/WizzzStark/CVE-2019-12840.py](https://github.com/WizzzStark/CVE-2019-12840.py) :  ![starts](https://img.shields.io/github/stars/WizzzStark/CVE-2019-12840.py.svg) ![forks](https://img.shields.io/github/forks/WizzzStark/CVE-2019-12840.py.svg)


## CVE-2016-8858
 ** DISPUTED ** The kex_input_kexinit function in kex.c in OpenSSH 6.x and 7.x through 7.3 allows remote attackers to cause a denial of service (memory consumption) by sending many duplicate KEXINIT requests.  NOTE: a third party reports that &quot;OpenSSH upstream does not consider this as a security issue.&quot;

- [https://github.com/dag-erling/kexkill](https://github.com/dag-erling/kexkill) :  ![starts](https://img.shields.io/github/stars/dag-erling/kexkill.svg) ![forks](https://img.shields.io/github/forks/dag-erling/kexkill.svg)

