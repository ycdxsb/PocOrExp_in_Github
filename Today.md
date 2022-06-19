# Update 2022-06-19
## CVE-2022-26809
 Remote Procedure Call Runtime Remote Code Execution Vulnerability. This CVE ID is unique from CVE-2022-24492, CVE-2022-24528.

- [https://github.com/Ziggy78/CVE-2022-26809-POC](https://github.com/Ziggy78/CVE-2022-26809-POC) :  ![starts](https://img.shields.io/github/stars/Ziggy78/CVE-2022-26809-POC.svg) ![forks](https://img.shields.io/github/forks/Ziggy78/CVE-2022-26809-POC.svg)


## CVE-2022-23342
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/InitRoot/CVE-2022-23342](https://github.com/InitRoot/CVE-2022-23342) :  ![starts](https://img.shields.io/github/stars/InitRoot/CVE-2022-23342.svg) ![forks](https://img.shields.io/github/forks/InitRoot/CVE-2022-23342.svg)


## CVE-2021-43229
 Windows NTFS Elevation of Privilege Vulnerability This CVE ID is unique from CVE-2021-43230, CVE-2021-43231.

- [https://github.com/Citizen13X/CVE-2021-43229](https://github.com/Citizen13X/CVE-2021-43229) :  ![starts](https://img.shields.io/github/stars/Citizen13X/CVE-2021-43229.svg) ![forks](https://img.shields.io/github/forks/Citizen13X/CVE-2021-43229.svg)


## CVE-2021-42013
 It was found that the fix for CVE-2021-41773 in Apache HTTP Server 2.4.50 was insufficient. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue only affects Apache 2.4.49 and Apache 2.4.50 and not earlier versions.

- [https://github.com/pwn3z/CVE-2021-41773-Apache-RCE](https://github.com/pwn3z/CVE-2021-41773-Apache-RCE) :  ![starts](https://img.shields.io/github/stars/pwn3z/CVE-2021-41773-Apache-RCE.svg) ![forks](https://img.shields.io/github/forks/pwn3z/CVE-2021-41773-Apache-RCE.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/pwn3z/CVE-2021-41773-Apache-RCE](https://github.com/pwn3z/CVE-2021-41773-Apache-RCE) :  ![starts](https://img.shields.io/github/stars/pwn3z/CVE-2021-41773-Apache-RCE.svg) ![forks](https://img.shields.io/github/forks/pwn3z/CVE-2021-41773-Apache-RCE.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/PentesterSoham/CVE-2021-4034-exploit](https://github.com/PentesterSoham/CVE-2021-4034-exploit) :  ![starts](https://img.shields.io/github/stars/PentesterSoham/CVE-2021-4034-exploit.svg) ![forks](https://img.shields.io/github/forks/PentesterSoham/CVE-2021-4034-exploit.svg)


## CVE-2020-8950
 The AUEPLauncher service in Radeon AMD User Experience Program Launcher through 1.0.0.1 on Windows allows elevation of privilege by placing a crafted file in %PROGRAMDATA%\AMD\PPC\upload and then creating a symbolic link in %PROGRAMDATA%\AMD\PPC\temp that points to an arbitrary folder with an arbitrary file name.

- [https://github.com/sailay1996/amd_eop_poc](https://github.com/sailay1996/amd_eop_poc) :  ![starts](https://img.shields.io/github/stars/sailay1996/amd_eop_poc.svg) ![forks](https://img.shields.io/github/forks/sailay1996/amd_eop_poc.svg)


## CVE-2019-15107
 An issue was discovered in Webmin &lt;=1.920. The parameter old in password_change.cgi contains a command injection vulnerability.

- [https://github.com/psw01/CVE-2019-15107_webminRCE](https://github.com/psw01/CVE-2019-15107_webminRCE) :  ![starts](https://img.shields.io/github/stars/psw01/CVE-2019-15107_webminRCE.svg) ![forks](https://img.shields.io/github/forks/psw01/CVE-2019-15107_webminRCE.svg)


## CVE-2019-1759
 A vulnerability in access control list (ACL) functionality of the Gigabit Ethernet Management interface of Cisco IOS XE Software could allow an unauthenticated, remote attacker to reach the configured IP addresses on the Gigabit Ethernet Management interface. The vulnerability is due to a logic error that was introduced in the Cisco IOS XE Software 16.1.1 Release, which prevents the ACL from working when applied against the management interface. An attacker could exploit this issue by attempting to access the device via the management interface.

- [https://github.com/r3m0t3nu11/CVE-2019-1759-csrf-js-rce](https://github.com/r3m0t3nu11/CVE-2019-1759-csrf-js-rce) :  ![starts](https://img.shields.io/github/stars/r3m0t3nu11/CVE-2019-1759-csrf-js-rce.svg) ![forks](https://img.shields.io/github/forks/r3m0t3nu11/CVE-2019-1759-csrf-js-rce.svg)


## CVE-2017-1635
 IBM Tivoli Monitoring V6 6.2.2.x could allow a remote attacker to execute arbitrary code on the system, caused by a use-after-free error. A remote attacker could exploit this vulnerability to execute arbitrary code on the system or cause the application to crash. IBM X-Force ID: 133243.

- [https://github.com/bcdannyboy/cve-2017-1635-PoC](https://github.com/bcdannyboy/cve-2017-1635-PoC) :  ![starts](https://img.shields.io/github/stars/bcdannyboy/cve-2017-1635-PoC.svg) ![forks](https://img.shields.io/github/forks/bcdannyboy/cve-2017-1635-PoC.svg)


## CVE-2014-6271
 GNU Bash through 4.3 processes trailing strings after function definitions in the values of environment variables, which allows remote attackers to execute arbitrary code via a crafted environment, as demonstrated by vectors involving the ForceCommand feature in OpenSSH sshd, the mod_cgi and mod_cgid modules in the Apache HTTP Server, scripts executed by unspecified DHCP clients, and other situations in which setting the environment occurs across a privilege boundary from Bash execution, aka &quot;ShellShock.&quot;  NOTE: the original fix for this issue was incorrect; CVE-2014-7169 has been assigned to cover the vulnerability that is still present after the incorrect fix.

- [https://github.com/abandonedship/ShellShock](https://github.com/abandonedship/ShellShock) :  ![starts](https://img.shields.io/github/stars/abandonedship/ShellShock.svg) ![forks](https://img.shields.io/github/forks/abandonedship/ShellShock.svg)


## CVE-2010-2078
 DataTrack System 3.5 allows remote attackers to list the root directory via a (1) /%u0085/ or (2) /%u00A0/ URI.

- [https://github.com/abandonedship/UnrealIrcd-3.2.8.1-cve-2010-2075-exploit](https://github.com/abandonedship/UnrealIrcd-3.2.8.1-cve-2010-2075-exploit) :  ![starts](https://img.shields.io/github/stars/abandonedship/UnrealIrcd-3.2.8.1-cve-2010-2075-exploit.svg) ![forks](https://img.shields.io/github/forks/abandonedship/UnrealIrcd-3.2.8.1-cve-2010-2075-exploit.svg)


## CVE-2010-2075
 UnrealIRCd 3.2.8.1, as distributed on certain mirror sites from November 2009 through June 2010, contains an externally introduced modification (Trojan Horse) in the DEBUG3_DOLOG_SYSTEM macro, which allows remote attackers to execute arbitrary commands.

- [https://github.com/abandonedship/UnrealIrcd-3.2.8.1-cve-2010-2075-exploit](https://github.com/abandonedship/UnrealIrcd-3.2.8.1-cve-2010-2075-exploit) :  ![starts](https://img.shields.io/github/stars/abandonedship/UnrealIrcd-3.2.8.1-cve-2010-2075-exploit.svg) ![forks](https://img.shields.io/github/forks/abandonedship/UnrealIrcd-3.2.8.1-cve-2010-2075-exploit.svg)


## CVE-2002-1614
 Buffer overflow in HP Tru64 UNIX allows local users to execute arbitrary code via a long argument to /usr/bin/at.

- [https://github.com/wlensinas/CVE-2002-1614](https://github.com/wlensinas/CVE-2002-1614) :  ![starts](https://img.shields.io/github/stars/wlensinas/CVE-2002-1614.svg) ![forks](https://img.shields.io/github/forks/wlensinas/CVE-2002-1614.svg)

