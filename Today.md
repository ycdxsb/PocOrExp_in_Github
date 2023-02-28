# Update 2023-02-28
## CVE-2023-0669
 Fortra (formerly, HelpSystems) GoAnywhere MFT suffers from a pre-authentication command injection vulnerability in the License Response Servlet due to deserializing an arbitrary attacker-controlled object. This issue was patched in version 7.1.2.

- [https://github.com/yosef0x01/CVE-2023-0669-Analysis](https://github.com/yosef0x01/CVE-2023-0669-Analysis) :  ![starts](https://img.shields.io/github/stars/yosef0x01/CVE-2023-0669-Analysis.svg) ![forks](https://img.shields.io/github/forks/yosef0x01/CVE-2023-0669-Analysis.svg)
- [https://github.com/trhacknon/CVE-2023-0669-bis](https://github.com/trhacknon/CVE-2023-0669-bis) :  ![starts](https://img.shields.io/github/stars/trhacknon/CVE-2023-0669-bis.svg) ![forks](https://img.shields.io/github/forks/trhacknon/CVE-2023-0669-bis.svg)


## CVE-2022-45482
 Lazy Mouse server enforces weak password requirements and doesn't implement rate limiting, allowing remote unauthenticated users to easily and quickly brute force the PIN and execute arbitrary commands. CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

- [https://github.com/M507/nmap-vulnerability-scan-scripts](https://github.com/M507/nmap-vulnerability-scan-scripts) :  ![starts](https://img.shields.io/github/stars/M507/nmap-vulnerability-scan-scripts.svg) ![forks](https://img.shields.io/github/forks/M507/nmap-vulnerability-scan-scripts.svg)


## CVE-2022-45481
 The default configuration of Lazy Mouse does not require a password, allowing remote unauthenticated users to execute arbitrary code with no prior authorization or authentication. CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

- [https://github.com/M507/nmap-vulnerability-scan-scripts](https://github.com/M507/nmap-vulnerability-scan-scripts) :  ![starts](https://img.shields.io/github/stars/M507/nmap-vulnerability-scan-scripts.svg) ![forks](https://img.shields.io/github/forks/M507/nmap-vulnerability-scan-scripts.svg)


## CVE-2022-45479
 PC Keyboard allows remote unauthenticated users to send instructions to the server to execute arbitrary code without any previous authorization or authentication. CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

- [https://github.com/M507/nmap-vulnerability-scan-scripts](https://github.com/M507/nmap-vulnerability-scan-scripts) :  ![starts](https://img.shields.io/github/stars/M507/nmap-vulnerability-scan-scripts.svg) ![forks](https://img.shields.io/github/forks/M507/nmap-vulnerability-scan-scripts.svg)


## CVE-2022-45477
 Telepad allows remote unauthenticated users to send instructions to the server to execute arbitrary code without any previous authorization or authentication. CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

- [https://github.com/M507/nmap-vulnerability-scan-scripts](https://github.com/M507/nmap-vulnerability-scan-scripts) :  ![starts](https://img.shields.io/github/stars/M507/nmap-vulnerability-scan-scripts.svg) ![forks](https://img.shields.io/github/forks/M507/nmap-vulnerability-scan-scripts.svg)


## CVE-2022-39952
 A external control of file name or path in Fortinet FortiNAC versions 9.4.0, 9.2.0 through 9.2.5, 9.1.0 through 9.1.7, 8.8.0 through 8.8.11, 8.7.0 through 8.7.6, 8.6.0 through 8.6.5, 8.5.0 through 8.5.4, 8.3.7 may allow an unauthenticated attacker to execute unauthorized code or commands via specifically crafted HTTP request.

- [https://github.com/Chocapikk/CVE-2022-39952](https://github.com/Chocapikk/CVE-2022-39952) :  ![starts](https://img.shields.io/github/stars/Chocapikk/CVE-2022-39952.svg) ![forks](https://img.shields.io/github/forks/Chocapikk/CVE-2022-39952.svg)


## CVE-2022-22966
 An authenticated, high privileged malicious actor with network access to the VMware Cloud Director tenant or provider may be able to exploit a remote code execution vulnerability to gain access to the server.

- [https://github.com/avboy1337/CVE-2022-22966](https://github.com/avboy1337/CVE-2022-22966) :  ![starts](https://img.shields.io/github/stars/avboy1337/CVE-2022-22966.svg) ![forks](https://img.shields.io/github/forks/avboy1337/CVE-2022-22966.svg)


## CVE-2022-0847
 A flaw was found in the way the &quot;flags&quot; member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/orsuprasad/CVE-2022-0847-DirtyPipe-Exploits](https://github.com/orsuprasad/CVE-2022-0847-DirtyPipe-Exploits) :  ![starts](https://img.shields.io/github/stars/orsuprasad/CVE-2022-0847-DirtyPipe-Exploits.svg) ![forks](https://img.shields.io/github/forks/orsuprasad/CVE-2022-0847-DirtyPipe-Exploits.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/shiomiyan/CVE-2021-41773](https://github.com/shiomiyan/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/shiomiyan/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/shiomiyan/CVE-2021-41773.svg)
- [https://github.com/puckiestyle/CVE-2021-41773](https://github.com/puckiestyle/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/puckiestyle/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/puckiestyle/CVE-2021-41773.svg)
- [https://github.com/Plunder283/CVE-2021-41773](https://github.com/Plunder283/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/Plunder283/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/Plunder283/CVE-2021-41773.svg)
- [https://github.com/m96dg/CVE-2021-41773-exercise](https://github.com/m96dg/CVE-2021-41773-exercise) :  ![starts](https://img.shields.io/github/stars/m96dg/CVE-2021-41773-exercise.svg) ![forks](https://img.shields.io/github/forks/m96dg/CVE-2021-41773-exercise.svg)


## CVE-2021-32305
 WebSVN before 2.6.1 allows remote attackers to execute arbitrary commands via shell metacharacters in the search parameter.

- [https://github.com/sz-guanx/CVE-2021-32305](https://github.com/sz-guanx/CVE-2021-32305) :  ![starts](https://img.shields.io/github/stars/sz-guanx/CVE-2021-32305.svg) ![forks](https://img.shields.io/github/forks/sz-guanx/CVE-2021-32305.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/teelrabbit/Polkit-pkexec-exploit-for-Linux](https://github.com/teelrabbit/Polkit-pkexec-exploit-for-Linux) :  ![starts](https://img.shields.io/github/stars/teelrabbit/Polkit-pkexec-exploit-for-Linux.svg) ![forks](https://img.shields.io/github/forks/teelrabbit/Polkit-pkexec-exploit-for-Linux.svg)


## CVE-2021-1732
 Windows Win32k Elevation of Privilege Vulnerability This CVE ID is unique from CVE-2021-1698.

- [https://github.com/Pai-Po/CVE-2021-1732](https://github.com/Pai-Po/CVE-2021-1732) :  ![starts](https://img.shields.io/github/stars/Pai-Po/CVE-2021-1732.svg) ![forks](https://img.shields.io/github/forks/Pai-Po/CVE-2021-1732.svg)


## CVE-2020-1764
 A hard-coded cryptographic key vulnerability in the default configuration file was found in Kiali, all versions prior to 1.15.1. A remote attacker could abuse this flaw by creating their own JWT signed tokens and bypass Kiali authentication mechanisms, possibly gaining privileges to view and alter the Istio configuration.

- [https://github.com/jpts/cve-2020-1764-poc](https://github.com/jpts/cve-2020-1764-poc) :  ![starts](https://img.shields.io/github/stars/jpts/cve-2020-1764-poc.svg) ![forks](https://img.shields.io/github/forks/jpts/cve-2020-1764-poc.svg)


## CVE-2020-1472
 An elevation of privilege vulnerability exists when an attacker establishes a vulnerable Netlogon secure channel connection to a domain controller, using the Netlogon Remote Protocol (MS-NRPC), aka 'Netlogon Elevation of Privilege Vulnerability'.

- [https://github.com/n3rada/zero-effort](https://github.com/n3rada/zero-effort) :  ![starts](https://img.shields.io/github/stars/n3rada/zero-effort.svg) ![forks](https://img.shields.io/github/forks/n3rada/zero-effort.svg)

