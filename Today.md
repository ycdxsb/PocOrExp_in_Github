# Update 2023-08-24
## CVE-2023-37191
 A stored cross-site scripting (XSS) vulnerability in Issabel issabel-pbx v.4.0.0-6 allows attackers to execute arbitrary web scripts or HTML via a crafted payload injected into the Group and Description parameters.

- [https://github.com/sahiloj/CVE-2023-37191](https://github.com/sahiloj/CVE-2023-37191) :  ![starts](https://img.shields.io/github/stars/sahiloj/CVE-2023-37191.svg) ![forks](https://img.shields.io/github/forks/sahiloj/CVE-2023-37191.svg)


## CVE-2022-24637
 Open Web Analytics (OWA) before 1.7.4 allows an unauthenticated remote attacker to obtain sensitive user information, which can be used to gain admin privileges by leveraging cache hashes. This occurs because files generated with '&lt;?php (instead of the intended &quot;&lt;?php sequence) aren't handled by the PHP interpreter.

- [https://github.com/0xRyuk/CVE-2022-24637](https://github.com/0xRyuk/CVE-2022-24637) :  ![starts](https://img.shields.io/github/stars/0xRyuk/CVE-2022-24637.svg) ![forks](https://img.shields.io/github/forks/0xRyuk/CVE-2022-24637.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/mightysai1997/CVE-2021-41773-i-](https://github.com/mightysai1997/CVE-2021-41773-i-) :  ![starts](https://img.shields.io/github/stars/mightysai1997/CVE-2021-41773-i-.svg) ![forks](https://img.shields.io/github/forks/mightysai1997/CVE-2021-41773-i-.svg)


## CVE-2021-21985
 The vSphere Client (HTML5) contains a remote code execution vulnerability due to lack of input validation in the Virtual SAN Health Check plug-in which is enabled by default in vCenter Server. A malicious actor with network access to port 443 may exploit this issue to execute commands with unrestricted privileges on the underlying operating system that hosts vCenter Server.

- [https://github.com/onSec-fr/CVE-2021-21985-Checker](https://github.com/onSec-fr/CVE-2021-21985-Checker) :  ![starts](https://img.shields.io/github/stars/onSec-fr/CVE-2021-21985-Checker.svg) ![forks](https://img.shields.io/github/forks/onSec-fr/CVE-2021-21985-Checker.svg)
- [https://github.com/mauricelambert/CVE-2021-21985](https://github.com/mauricelambert/CVE-2021-21985) :  ![starts](https://img.shields.io/github/stars/mauricelambert/CVE-2021-21985.svg) ![forks](https://img.shields.io/github/forks/mauricelambert/CVE-2021-21985.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/wudicainiao/cve-2021-4034](https://github.com/wudicainiao/cve-2021-4034) :  ![starts](https://img.shields.io/github/stars/wudicainiao/cve-2021-4034.svg) ![forks](https://img.shields.io/github/forks/wudicainiao/cve-2021-4034.svg)
- [https://github.com/drapl0n/pwnKit](https://github.com/drapl0n/pwnKit) :  ![starts](https://img.shields.io/github/stars/drapl0n/pwnKit.svg) ![forks](https://img.shields.io/github/forks/drapl0n/pwnKit.svg)
- [https://github.com/OXDBXKXO/ez-pwnkit](https://github.com/OXDBXKXO/ez-pwnkit) :  ![starts](https://img.shields.io/github/stars/OXDBXKXO/ez-pwnkit.svg) ![forks](https://img.shields.io/github/forks/OXDBXKXO/ez-pwnkit.svg)
- [https://github.com/moldabekov/CVE-2021-4034](https://github.com/moldabekov/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/moldabekov/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/moldabekov/CVE-2021-4034.svg)


## CVE-2020-5260
 Affected versions of Git have a vulnerability whereby Git can be tricked into sending private credentials to a host controlled by an attacker. Git uses external &quot;credential helper&quot; programs to store and retrieve passwords or other credentials from secure storage provided by the operating system. Specially-crafted URLs that contain an encoded newline can inject unintended values into the credential helper protocol stream, causing the credential helper to retrieve the password for one server (e.g., good.example.com) for an HTTP request being made to another server (e.g., evil.example.com), resulting in credentials for the former being sent to the latter. There are no restrictions on the relationship between the two, meaning that an attacker can craft a URL that will present stored credentials for any host to a host of their choosing. The vulnerability can be triggered by feeding a malicious URL to git clone. However, the affected URLs look rather suspicious; the likely vector would be through systems which automatically clone URLs not visible to the user, such as Git submodules, or package systems built around Git. The problem has been patched in the versions published on April 14th, 2020, going back to v2.17.x. Anyone wishing to backport the change further can do so by applying commit 9a6bbee (the full release includes extra checks for git fsck, but that commit is sufficient to protect clients against the vulnerability). The patched versions are: 2.17.4, 2.18.3, 2.19.4, 2.20.3, 2.21.2, 2.22.3, 2.23.2, 2.24.2, 2.25.3, 2.26.1.

- [https://github.com/sv3nbeast/CVE-2020-5260](https://github.com/sv3nbeast/CVE-2020-5260) :  ![starts](https://img.shields.io/github/stars/sv3nbeast/CVE-2020-5260.svg) ![forks](https://img.shields.io/github/forks/sv3nbeast/CVE-2020-5260.svg)


## CVE-2019-15896
 An issue was discovered in the LifterLMS plugin through 3.34.5 for WordPress. The upload_import function in the class.llms.admin.import.php script is prone to an unauthenticated options import vulnerability that could lead to privilege escalation (administrator account creation), website redirection, and stored XSS.

- [https://github.com/RandomRobbieBF/CVE-2019-15896](https://github.com/RandomRobbieBF/CVE-2019-15896) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2019-15896.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2019-15896.svg)


## CVE-2018-1273
 Spring Data Commons, versions prior to 1.13 to 1.13.10, 2.0 to 2.0.5, and older unsupported versions, contain a property binder vulnerability caused by improper neutralization of special elements. An unauthenticated remote malicious user (or attacker) can supply specially crafted request parameters against Spring Data REST backed HTTP resources or using Spring Data's projection-based request payload binding hat can lead to a remote code execution attack.

- [https://github.com/wearearima/poc-cve-2018-1273](https://github.com/wearearima/poc-cve-2018-1273) :  ![starts](https://img.shields.io/github/stars/wearearima/poc-cve-2018-1273.svg) ![forks](https://img.shields.io/github/forks/wearearima/poc-cve-2018-1273.svg)

