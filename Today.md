# Update 2025-11-21
## CVE-2025-64708
 authentik is an open-source Identity Provider. Prior to versions 2025.8.5 and 2025.10.2, in previous authentik versions, invitations were considered valid regardless if they are expired or not, thus relying on background tasks to clean up expired ones. In a normal scenario this can take up to 5 minutes because the cleanup of expired objects is scheduled to run every 5 minutes. However, with a large amount of tasks in the backlog, this might take longer. authentik versions 2025.8.5 and 2025.10.2 fix this issue. A workaround involves creating a policy that explicitly checks whether the invitation is still valid, and then bind it to the invitation stage on the invitation flow, and denying access if the invitation is not valid.

- [https://github.com/DylanDavis1/CVE-2025-64708](https://github.com/DylanDavis1/CVE-2025-64708) :  ![starts](https://img.shields.io/github/stars/DylanDavis1/CVE-2025-64708.svg) ![forks](https://img.shields.io/github/forks/DylanDavis1/CVE-2025-64708.svg)


## CVE-2025-64446
 A relative path traversal vulnerability in Fortinet FortiWeb 8.0.0 through 8.0.1, FortiWeb 7.6.0 through 7.6.4, FortiWeb 7.4.0 through 7.4.9, FortiWeb 7.2.0 through 7.2.11, FortiWeb 7.0.0 through 7.0.11 may allow an attacker to execute administrative commands on the system via crafted HTTP or HTTPS requests.

- [https://github.com/Death112233/CVE-2025-64446-](https://github.com/Death112233/CVE-2025-64446-) :  ![starts](https://img.shields.io/github/stars/Death112233/CVE-2025-64446-.svg) ![forks](https://img.shields.io/github/forks/Death112233/CVE-2025-64446-.svg)


## CVE-2025-58034
 An Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') vulnerability [CWE-78] in Fortinet FortiWeb 8.0.0 through 8.0.1, FortiWeb 7.6.0 through 7.6.5, FortiWeb 7.4.0 through 7.4.10, FortiWeb 7.2.0 through 7.2.11, FortiWeb 7.0.0 through 7.0.11 may allow an authenticated attacker to execute unauthorized code on the underlying system via crafted HTTP requests or CLI commands.

- [https://github.com/B1ack4sh/Blackash-CVE-2025-58034](https://github.com/B1ack4sh/Blackash-CVE-2025-58034) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-58034.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-58034.svg)


## CVE-2025-54110
 Integer overflow or wraparound in Windows Kernel allows an authorized attacker to elevate privileges locally.

- [https://github.com/canomer/CVE-2025-54110-Kernel-EoP-PoC](https://github.com/canomer/CVE-2025-54110-Kernel-EoP-PoC) :  ![starts](https://img.shields.io/github/stars/canomer/CVE-2025-54110-Kernel-EoP-PoC.svg) ![forks](https://img.shields.io/github/forks/canomer/CVE-2025-54110-Kernel-EoP-PoC.svg)


## CVE-2025-53779
 Relative path traversal in Windows Kerberos allows an authorized attacker to elevate privileges over a network.

- [https://github.com/b5null/Invoke-BadSuccessor.ps1](https://github.com/b5null/Invoke-BadSuccessor.ps1) :  ![starts](https://img.shields.io/github/stars/b5null/Invoke-BadSuccessor.ps1.svg) ![forks](https://img.shields.io/github/forks/b5null/Invoke-BadSuccessor.ps1.svg)


## CVE-2025-40629
 PNETLab 4.2.10 does not properly sanitize user inputs in its file access mechanisms. This allows attackers to perform directory traversal by manipulating file paths in HTTP requests. Specifically, the application is vulnerable to requests that access sensitive files outside the intended directory.

- [https://github.com/omr00t/CVE-2025-40629](https://github.com/omr00t/CVE-2025-40629) :  ![starts](https://img.shields.io/github/stars/omr00t/CVE-2025-40629.svg) ![forks](https://img.shields.io/github/forks/omr00t/CVE-2025-40629.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/jmbowes/NextSecureScan](https://github.com/jmbowes/NextSecureScan) :  ![starts](https://img.shields.io/github/stars/jmbowes/NextSecureScan.svg) ![forks](https://img.shields.io/github/forks/jmbowes/NextSecureScan.svg)


## CVE-2025-27591
 A privilege escalation vulnerability existed in the Below service prior to v0.9.0 due to the creation of a world-writable directory at /var/log/below. This could have allowed local unprivileged users to escalate to root privileges through symlink attacks that manipulate files such as /etc/shadow.

- [https://github.com/0x00Jeff/CVE-2025-27591](https://github.com/0x00Jeff/CVE-2025-27591) :  ![starts](https://img.shields.io/github/stars/0x00Jeff/CVE-2025-27591.svg) ![forks](https://img.shields.io/github/forks/0x00Jeff/CVE-2025-27591.svg)


## CVE-2025-25255
 An Improperly Implemented Security Check for Standard vulnerability [CWE-358] in FortiProxy 7.6.0 through 7.6.3, 7.4 all versions, 7.2 all versions, 7.0.1 through 7.0.21, and FortiOS 7.6.0 through 7.6.3 explicit web proxy may allow an authenticated proxy user to bypass the domain fronting protection feature via crafted HTTP requests.

- [https://github.com/chjkfbvmvff/CVE-2025-25255](https://github.com/chjkfbvmvff/CVE-2025-25255) :  ![starts](https://img.shields.io/github/stars/chjkfbvmvff/CVE-2025-25255.svg) ![forks](https://img.shields.io/github/forks/chjkfbvmvff/CVE-2025-25255.svg)


## CVE-2025-24801
 GLPI is a free asset and IT management software package. An authenticated user can upload and force the execution of *.php files located on the GLPI server. This vulnerability is fixed in 10.0.18.

- [https://github.com/r1beirin/Exploit-CVE-2025-24801](https://github.com/r1beirin/Exploit-CVE-2025-24801) :  ![starts](https://img.shields.io/github/stars/r1beirin/Exploit-CVE-2025-24801.svg) ![forks](https://img.shields.io/github/forks/r1beirin/Exploit-CVE-2025-24801.svg)


## CVE-2025-11001
The specific flaw exists within the handling of symbolic links in ZIP files. Crafted data in a ZIP file can cause the process to traverse to unintended directories. An attacker can leverage this vulnerability to execute code in the context of a service account. Was ZDI-CAN-26753.

- [https://github.com/pacbypass/CVE-2025-11001](https://github.com/pacbypass/CVE-2025-11001) :  ![starts](https://img.shields.io/github/stars/pacbypass/CVE-2025-11001.svg) ![forks](https://img.shields.io/github/forks/pacbypass/CVE-2025-11001.svg)
- [https://github.com/shalevo13/Se7enSlip](https://github.com/shalevo13/Se7enSlip) :  ![starts](https://img.shields.io/github/stars/shalevo13/Se7enSlip.svg) ![forks](https://img.shields.io/github/forks/shalevo13/Se7enSlip.svg)


## CVE-2025-10492
 A Java deserialisation vulnerability has been discovered in Jaspersoft Library. Improper handling of externally supplied data may allow attackers to execute arbitrary code remotely on systems that use the affected library

- [https://github.com/dovezp/CVE-2025-10492-POC](https://github.com/dovezp/CVE-2025-10492-POC) :  ![starts](https://img.shields.io/github/stars/dovezp/CVE-2025-10492-POC.svg) ![forks](https://img.shields.io/github/forks/dovezp/CVE-2025-10492-POC.svg)


## CVE-2025-10230
 A flaw was found in Samba, in the front-end WINS hook handling: NetBIOS names from registration packets are passed to a shell without proper validation or escaping. Unsanitized NetBIOS name data from WINS registration packets are inserted into a shell command and executed by the Samba Active Directory Domain Controller’s wins hook, allowing an unauthenticated network attacker to achieve remote command execution as the Samba process.

- [https://github.com/B1ack4sh/Blackash-CVE-2025-10230](https://github.com/B1ack4sh/Blackash-CVE-2025-10230) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-10230.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-10230.svg)


## CVE-2025-3248
code.

- [https://github.com/drackyjr/-CVE-2025-3248](https://github.com/drackyjr/-CVE-2025-3248) :  ![starts](https://img.shields.io/github/stars/drackyjr/-CVE-2025-3248.svg) ![forks](https://img.shields.io/github/forks/drackyjr/-CVE-2025-3248.svg)


## CVE-2024-21413
 Microsoft Outlook Remote Code Execution Vulnerability

- [https://github.com/hau2212/Moniker-Link-CVE-2024-21413-](https://github.com/hau2212/Moniker-Link-CVE-2024-21413-) :  ![starts](https://img.shields.io/github/stars/hau2212/Moniker-Link-CVE-2024-21413-.svg) ![forks](https://img.shields.io/github/forks/hau2212/Moniker-Link-CVE-2024-21413-.svg)


## CVE-2022-40684
 An authentication bypass using an alternate path or channel [CWE-288] in Fortinet FortiOS version 7.2.0 through 7.2.1 and 7.0.0 through 7.0.6, FortiProxy version 7.2.0 and version 7.0.0 through 7.0.6 and FortiSwitchManager version 7.2.0 and 7.0.0 allows an unauthenticated atttacker to perform operations on the administrative interface via specially crafted HTTP or HTTPS requests.

- [https://github.com/ccordeiro/CVE-2022-40684](https://github.com/ccordeiro/CVE-2022-40684) :  ![starts](https://img.shields.io/github/stars/ccordeiro/CVE-2022-40684.svg) ![forks](https://img.shields.io/github/forks/ccordeiro/CVE-2022-40684.svg)


## CVE-2022-0847
 A flaw was found in the way the "flags" member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/muhammad1596/CVE-2022-0847-DirtyPipe-Exploits](https://github.com/muhammad1596/CVE-2022-0847-DirtyPipe-Exploits) :  ![starts](https://img.shields.io/github/stars/muhammad1596/CVE-2022-0847-DirtyPipe-Exploits.svg) ![forks](https://img.shields.io/github/forks/muhammad1596/CVE-2022-0847-DirtyPipe-Exploits.svg)


## CVE-2021-43008
 Improper Access Control in Adminer versions 1.12.0 to 4.6.2 (fixed in version 4.6.3) allows an attacker to achieve Arbitrary File Read on the remote server by requesting the Adminer to connect to a remote MySQL database.

- [https://github.com/DaturaSaturated/Adminer-CVE-2021-43008](https://github.com/DaturaSaturated/Adminer-CVE-2021-43008) :  ![starts](https://img.shields.io/github/stars/DaturaSaturated/Adminer-CVE-2021-43008.svg) ![forks](https://img.shields.io/github/forks/DaturaSaturated/Adminer-CVE-2021-43008.svg)


## CVE-2021-42013
 It was found that the fix for CVE-2021-41773 in Apache HTTP Server 2.4.50 was insufficient. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue only affects Apache 2.4.49 and Apache 2.4.50 and not earlier versions.

- [https://github.com/drackyjr/CVE-2021-42013](https://github.com/drackyjr/CVE-2021-42013) :  ![starts](https://img.shields.io/github/stars/drackyjr/CVE-2021-42013.svg) ![forks](https://img.shields.io/github/forks/drackyjr/CVE-2021-42013.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/RizqiSec/CVE-2021-41773](https://github.com/RizqiSec/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/RizqiSec/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/RizqiSec/CVE-2021-41773.svg)


## CVE-2018-15133
 In Laravel Framework through 5.5.40 and 5.6.x through 5.6.29, remote code execution might occur as a result of an unserialize call on a potentially untrusted X-XSRF-TOKEN value. This involves the decrypt method in Illuminate/Encryption/Encrypter.php and PendingBroadcast in gadgetchains/Laravel/RCE/3/chain.php in phpggc. The attacker must know the application key, which normally would never occur, but could happen if the attacker previously had privileged access or successfully accomplished a previous attack.

- [https://github.com/Loaxert/CVE-2018-15133-PoC](https://github.com/Loaxert/CVE-2018-15133-PoC) :  ![starts](https://img.shields.io/github/stars/Loaxert/CVE-2018-15133-PoC.svg) ![forks](https://img.shields.io/github/forks/Loaxert/CVE-2018-15133-PoC.svg)


## CVE-2006-3392
 Webmin before 1.290 and Usermin before 1.220 calls the simplify_path function before decoding HTML, which allows remote attackers to read arbitrary files, as demonstrated using "..%01" sequences, which bypass the removal of "../" sequences before bytes such as "%01" are removed from the filename.  NOTE: This is a different issue than CVE-2006-3274.

- [https://github.com/oxagast/oxasploits](https://github.com/oxagast/oxasploits) :  ![starts](https://img.shields.io/github/stars/oxagast/oxasploits.svg) ![forks](https://img.shields.io/github/forks/oxagast/oxasploits.svg)

