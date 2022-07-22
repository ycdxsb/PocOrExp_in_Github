# Update 2022-07-22
## CVE-2022-34918
 An issue was discovered in the Linux kernel through 5.18.9. A type confusion bug in nft_set_elem_init (leading to a buffer overflow) could be used by a local attacker to escalate privileges, a different vulnerability than CVE-2022-32250. (The attacker can obtain root access, but must start with an unprivileged user namespace to obtain CAP_NET_ADMIN access.) This can be fixed in nft_setelem_parse_data in net/netfilter/nf_tables_api.c.

- [https://github.com/randorisec/CVE-2022-34918-LPE-PoC](https://github.com/randorisec/CVE-2022-34918-LPE-PoC) :  ![starts](https://img.shields.io/github/stars/randorisec/CVE-2022-34918-LPE-PoC.svg) ![forks](https://img.shields.io/github/forks/randorisec/CVE-2022-34918-LPE-PoC.svg)


## CVE-2022-33891
 The Apache Spark UI offers the possibility to enable ACLs via the configuration option spark.acls.enable. With an authentication filter, this checks whether a user has access permissions to view or modify the application. If ACLs are enabled, a code path in HttpSecurityFilter can allow someone to perform impersonation by providing an arbitrary user name. A malicious user might then be able to reach a permission check function that will ultimately build a Unix shell command based on their input, and execute it. This will result in arbitrary shell command execution as the user Spark is currently running as. This affects Apache Spark versions 3.0.3 and earlier, versions 3.1.1 to 3.1.2, and versions 3.2.0 to 3.2.1.

- [https://github.com/AkbarTrilaksana/cve-2022-33891](https://github.com/AkbarTrilaksana/cve-2022-33891) :  ![starts](https://img.shields.io/github/stars/AkbarTrilaksana/cve-2022-33891.svg) ![forks](https://img.shields.io/github/forks/AkbarTrilaksana/cve-2022-33891.svg)


## CVE-2022-29078
 The ejs (aka Embedded JavaScript templates) package 3.1.6 for Node.js allows server-side template injection in settings[view options][outputFunctionName]. This is parsed as an internal option, and overwrites the outputFunctionName option with an arbitrary OS command (which is executed upon template compilation).

- [https://github.com/miko550/CVE-2022-29078](https://github.com/miko550/CVE-2022-29078) :  ![starts](https://img.shields.io/github/stars/miko550/CVE-2022-29078.svg) ![forks](https://img.shields.io/github/forks/miko550/CVE-2022-29078.svg)


## CVE-2021-22205
 An issue has been discovered in GitLab CE/EE affecting all versions starting from 11.9. GitLab was not properly validating image files that were passed to a file parser which resulted in a remote command execution.

- [https://github.com/keven1z/CVE-2021-22205](https://github.com/keven1z/CVE-2021-22205) :  ![starts](https://img.shields.io/github/stars/keven1z/CVE-2021-22205.svg) ![forks](https://img.shields.io/github/forks/keven1z/CVE-2021-22205.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/PentesterSoham/CVE-2021-4034-exploit](https://github.com/PentesterSoham/CVE-2021-4034-exploit) :  ![starts](https://img.shields.io/github/stars/PentesterSoham/CVE-2021-4034-exploit.svg) ![forks](https://img.shields.io/github/forks/PentesterSoham/CVE-2021-4034-exploit.svg)


## CVE-2021-3129
 Ignition before 2.5.2, as used in Laravel and other products, allows unauthenticated remote attackers to execute arbitrary code because of insecure usage of file_get_contents() and file_put_contents(). This is exploitable on sites using debug mode with Laravel before 8.4.2.

- [https://github.com/nth347/CVE-2021-3129_exploit](https://github.com/nth347/CVE-2021-3129_exploit) :  ![starts](https://img.shields.io/github/stars/nth347/CVE-2021-3129_exploit.svg) ![forks](https://img.shields.io/github/forks/nth347/CVE-2021-3129_exploit.svg)
- [https://github.com/cuongtop4598/CVE-2021-3129-Script](https://github.com/cuongtop4598/CVE-2021-3129-Script) :  ![starts](https://img.shields.io/github/stars/cuongtop4598/CVE-2021-3129-Script.svg) ![forks](https://img.shields.io/github/forks/cuongtop4598/CVE-2021-3129-Script.svg)


## CVE-2021-2119
 Vulnerability in the Oracle VM VirtualBox product of Oracle Virtualization (component: Core). The supported version that is affected is Prior to 6.1.18. Easily exploitable vulnerability allows high privileged attacker with logon to the infrastructure where Oracle VM VirtualBox executes to compromise Oracle VM VirtualBox. While the vulnerability is in Oracle VM VirtualBox, attacks may significantly impact additional products. Successful attacks of this vulnerability can result in unauthorized access to critical data or complete access to all Oracle VM VirtualBox accessible data. CVSS 3.1 Base Score 6.0 (Confidentiality impacts). CVSS Vector: (CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:N/A:N).

- [https://github.com/chatbottesisgmailh/Sauercloude](https://github.com/chatbottesisgmailh/Sauercloude) :  ![starts](https://img.shields.io/github/stars/chatbottesisgmailh/Sauercloude.svg) ![forks](https://img.shields.io/github/forks/chatbottesisgmailh/Sauercloude.svg)


## CVE-2018-19246
 PHP-Proxy 5.1.0 allows remote attackers to read local files if the default &quot;pre-installed version&quot; (intended for users who lack shell access to their web server) is used. This occurs because the aeb067ca0aa9a3193dce3a7264c90187 app_key value from the default config.php is in place, and this value can be easily used to calculate the authorization data needed for local file inclusion.

- [https://github.com/NeoWans/CVE-2018-19246](https://github.com/NeoWans/CVE-2018-19246) :  ![starts](https://img.shields.io/github/stars/NeoWans/CVE-2018-19246.svg) ![forks](https://img.shields.io/github/forks/NeoWans/CVE-2018-19246.svg)


## CVE-2017-9248
 Telerik.Web.UI.dll in Progress Telerik UI for ASP.NET AJAX before R2 2017 SP1 and Sitefinity before 10.0.6412.0 does not properly protect Telerik.Web.UI.DialogParametersEncryptionKey or the MachineKey, which makes it easier for remote attackers to defeat cryptographic protection mechanisms, leading to a MachineKey leak, arbitrary file uploads or downloads, XSS, or ASP.NET ViewState compromise.

- [https://github.com/oldboy-snt/dp](https://github.com/oldboy-snt/dp) :  ![starts](https://img.shields.io/github/stars/oldboy-snt/dp.svg) ![forks](https://img.shields.io/github/forks/oldboy-snt/dp.svg)


## CVE-2017-5638
 The Jakarta Multipart parser in Apache Struts 2 2.3.x before 2.3.32 and 2.5.x before 2.5.10.1 has incorrect exception handling and error-message generation during file-upload attempts, which allows remote attackers to execute arbitrary commands via a crafted Content-Type, Content-Disposition, or Content-Length HTTP header, as exploited in the wild in March 2017 with a Content-Type header containing a #cmd= string.

- [https://github.com/immunio/apache-struts2-CVE-2017-5638](https://github.com/immunio/apache-struts2-CVE-2017-5638) :  ![starts](https://img.shields.io/github/stars/immunio/apache-struts2-CVE-2017-5638.svg) ![forks](https://img.shields.io/github/forks/immunio/apache-struts2-CVE-2017-5638.svg)


## CVE-2015-2523
 Microsoft Excel 2007 SP3, Excel 2010 SP2, Excel 2013 SP1, Excel 2013 RT SP1, Excel for Mac 2011 and 2016, Office Compatibility Pack SP3, and Excel Viewer allow remote attackers to execute arbitrary code via a crafted Office document, aka &quot;Microsoft Office Memory Corruption Vulnerability.&quot;

- [https://github.com/krdsploit/MSFu-Extentions-](https://github.com/krdsploit/MSFu-Extentions-) :  ![starts](https://img.shields.io/github/stars/krdsploit/MSFu-Extentions-.svg) ![forks](https://img.shields.io/github/forks/krdsploit/MSFu-Extentions-.svg)


## CVE-2014-6271
 GNU Bash through 4.3 processes trailing strings after function definitions in the values of environment variables, which allows remote attackers to execute arbitrary code via a crafted environment, as demonstrated by vectors involving the ForceCommand feature in OpenSSH sshd, the mod_cgi and mod_cgid modules in the Apache HTTP Server, scripts executed by unspecified DHCP clients, and other situations in which setting the environment occurs across a privilege boundary from Bash execution, aka &quot;ShellShock.&quot;  NOTE: the original fix for this issue was incorrect; CVE-2014-7169 has been assigned to cover the vulnerability that is still present after the incorrect fix.

- [https://github.com/heikipikker/shellshock-shell](https://github.com/heikipikker/shellshock-shell) :  ![starts](https://img.shields.io/github/stars/heikipikker/shellshock-shell.svg) ![forks](https://img.shields.io/github/forks/heikipikker/shellshock-shell.svg)

