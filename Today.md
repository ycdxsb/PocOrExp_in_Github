# Update 2022-11-17
## CVE-2022-36067
 vm2 is a sandbox that can run untrusted code with whitelisted Node's built-in modules. In versions prior to version 3.9.11, a threat actor can bypass the sandbox protections to gain remote code execution rights on the host running the sandbox. This vulnerability was patched in the release of version 3.9.11 of vm2. There are no known workarounds.

- [https://github.com/0x1nsomnia/CVE-2022-36067-vm2-POC-webapp](https://github.com/0x1nsomnia/CVE-2022-36067-vm2-POC-webapp) :  ![starts](https://img.shields.io/github/stars/0x1nsomnia/CVE-2022-36067-vm2-POC-webapp.svg) ![forks](https://img.shields.io/github/forks/0x1nsomnia/CVE-2022-36067-vm2-POC-webapp.svg)


## CVE-2022-24637
 Open Web Analytics (OWA) before 1.7.4 allows an unauthenticated remote attacker to obtain sensitive user information, which can be used to gain admin privileges by leveraging cache hashes. This occurs because files generated with '&lt;?php (instead of the intended &quot;&lt;?php sequence) aren't handled by the PHP interpreter.

- [https://github.com/icebreack/CVE-2022-24637](https://github.com/icebreack/CVE-2022-24637) :  ![starts](https://img.shields.io/github/stars/icebreack/CVE-2022-24637.svg) ![forks](https://img.shields.io/github/forks/icebreack/CVE-2022-24637.svg)


## CVE-2022-22947
 In spring cloud gateway versions prior to 3.1.1+ and 3.0.7+ , applications are vulnerable to a code injection attack when the Gateway Actuator endpoint is enabled, exposed and unsecured. A remote attacker could make a maliciously crafted request that could allow arbitrary remote execution on the remote host.

- [https://github.com/qq87234770/CVE-2022-22947](https://github.com/qq87234770/CVE-2022-22947) :  ![starts](https://img.shields.io/github/stars/qq87234770/CVE-2022-22947.svg) ![forks](https://img.shields.io/github/forks/qq87234770/CVE-2022-22947.svg)


## CVE-2022-0847
 A flaw was found in the way the &quot;flags&quot; member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/Z3R0W4R3/CVE-2022-0847-DirtyPipe-Exploits](https://github.com/Z3R0W4R3/CVE-2022-0847-DirtyPipe-Exploits) :  ![starts](https://img.shields.io/github/stars/Z3R0W4R3/CVE-2022-0847-DirtyPipe-Exploits.svg) ![forks](https://img.shields.io/github/forks/Z3R0W4R3/CVE-2022-0847-DirtyPipe-Exploits.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/WebApache/CVE-2021-41773-Apache-RCE](https://github.com/WebApache/CVE-2021-41773-Apache-RCE) :  ![starts](https://img.shields.io/github/stars/WebApache/CVE-2021-41773-Apache-RCE.svg) ![forks](https://img.shields.io/github/forks/WebApache/CVE-2021-41773-Apache-RCE.svg)


## CVE-2021-3560
 It was found that polkit could be tricked into bypassing the credential checks for D-Bus requests, elevating the privileges of the requestor to the root user. This flaw could be used by an unprivileged local attacker to, for example, create a new local administrator. The highest threat from this vulnerability is to data confidentiality and integrity as well as system availability.

- [https://github.com/cpu0x00/CVE-2021-3560](https://github.com/cpu0x00/CVE-2021-3560) :  ![starts](https://img.shields.io/github/stars/cpu0x00/CVE-2021-3560.svg) ![forks](https://img.shields.io/github/forks/cpu0x00/CVE-2021-3560.svg)

