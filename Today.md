# Update 2024-01-04
## CVE-2024-0190
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/codeb0ss/CVE-2024-0190-PoC](https://github.com/codeb0ss/CVE-2024-0190-PoC) :  ![starts](https://img.shields.io/github/stars/codeb0ss/CVE-2024-0190-PoC.svg) ![forks](https://img.shields.io/github/forks/codeb0ss/CVE-2024-0190-PoC.svg)


## CVE-2023-51385
 In ssh in OpenSSH before 9.6, OS command injection might occur if a user name or host name has shell metacharacters, and this name is referenced by an expansion token in certain situations. For example, an untrusted Git repository can have a submodule with shell metacharacters in a user name or host name.

- [https://github.com/uccu99/CVE-2023-51385](https://github.com/uccu99/CVE-2023-51385) :  ![starts](https://img.shields.io/github/stars/uccu99/CVE-2023-51385.svg) ![forks](https://img.shields.io/github/forks/uccu99/CVE-2023-51385.svg)


## CVE-2023-22515
 Atlassian has been made aware of an issue reported by a handful of customers where external attackers may have exploited a previously unknown vulnerability in publicly accessible Confluence Data Center and Server instances to create unauthorized Confluence administrator accounts and access Confluence instances. Atlassian Cloud sites are not affected by this vulnerability. If your Confluence site is accessed via an atlassian.net domain, it is hosted by Atlassian and is not vulnerable to this issue.

- [https://github.com/CalegariMindSec/Exploit-CVE-2023-22515](https://github.com/CalegariMindSec/Exploit-CVE-2023-22515) :  ![starts](https://img.shields.io/github/stars/CalegariMindSec/Exploit-CVE-2023-22515.svg) ![forks](https://img.shields.io/github/forks/CalegariMindSec/Exploit-CVE-2023-22515.svg)


## CVE-2023-4911
 A buffer overflow was discovered in the GNU C Library's dynamic loader ld.so while processing the GLIBC_TUNABLES environment variable. This issue could allow a local attacker to use maliciously crafted GLIBC_TUNABLES environment variables when launching binaries with SUID permission to execute code with elevated privileges.

- [https://github.com/guffre/CVE-2023-4911](https://github.com/guffre/CVE-2023-4911) :  ![starts](https://img.shields.io/github/stars/guffre/CVE-2023-4911.svg) ![forks](https://img.shields.io/github/forks/guffre/CVE-2023-4911.svg)


## CVE-2023-2636
 The AN_GradeBook WordPress plugin through 5.0.1 does not properly sanitise and escape a parameter before using it in a SQL statement, leading to a SQL injection exploitable by users with a role as low as subscriber

- [https://github.com/lukinneberg/CVE-2023-2636](https://github.com/lukinneberg/CVE-2023-2636) :  ![starts](https://img.shields.io/github/stars/lukinneberg/CVE-2023-2636.svg) ![forks](https://img.shields.io/github/forks/lukinneberg/CVE-2023-2636.svg)


## CVE-2023-2002
 A vulnerability was found in the HCI sockets implementation due to a missing capability check in net/bluetooth/hci_sock.c in the Linux Kernel. This flaw allows an attacker to unauthorized execution of management commands, compromising the confidentiality, integrity, and availability of Bluetooth communication.

- [https://github.com/lrh2000/CVE-2023-2002](https://github.com/lrh2000/CVE-2023-2002) :  ![starts](https://img.shields.io/github/stars/lrh2000/CVE-2023-2002.svg) ![forks](https://img.shields.io/github/forks/lrh2000/CVE-2023-2002.svg)


## CVE-2022-1386
 The Fusion Builder WordPress plugin before 3.6.2, used in the Avada theme, does not validate a parameter in its forms which could be used to initiate arbitrary HTTP requests. The data returned is then reflected back in the application's response. This could be used to interact with hosts on the server's local network bypassing firewalls and access control measures.

- [https://github.com/ardzz/CVE-2022-1386](https://github.com/ardzz/CVE-2022-1386) :  ![starts](https://img.shields.io/github/stars/ardzz/CVE-2022-1386.svg) ![forks](https://img.shields.io/github/forks/ardzz/CVE-2022-1386.svg)


## CVE-2021-45046
 It was found that the fix to address CVE-2021-44228 in Apache Log4j 2.15.0 was incomplete in certain non-default configurations. This could allows attackers with control over Thread Context Map (MDC) input data when the logging configuration uses a non-default Pattern Layout with either a Context Lookup (for example, $${ctx:loginId}) or a Thread Context Map pattern (%X, %mdc, or %MDC) to craft malicious input data using a JNDI Lookup pattern resulting in an information leak and remote code execution in some environments and local code execution in all environments. Log4j 2.16.0 (Java 8) and 2.12.2 (Java 7) fix this issue by removing support for message lookup patterns and disabling JNDI functionality by default.

- [https://github.com/xsultan/log4jshield](https://github.com/xsultan/log4jshield) :  ![starts](https://img.shields.io/github/stars/xsultan/log4jshield.svg) ![forks](https://img.shields.io/github/forks/xsultan/log4jshield.svg)
- [https://github.com/demonrvm/Log4ShellRemediation](https://github.com/demonrvm/Log4ShellRemediation) :  ![starts](https://img.shields.io/github/stars/demonrvm/Log4ShellRemediation.svg) ![forks](https://img.shields.io/github/forks/demonrvm/Log4ShellRemediation.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/scarmandef/CVE-2021-41773](https://github.com/scarmandef/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/scarmandef/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/scarmandef/CVE-2021-41773.svg)


## CVE-2021-23132
 An issue was discovered in Joomla! 3.0.0 through 3.9.24. com_media allowed paths that are not intended for image uploads

- [https://github.com/HoangKien1020/CVE-2021-23132](https://github.com/HoangKien1020/CVE-2021-23132) :  ![starts](https://img.shields.io/github/stars/HoangKien1020/CVE-2021-23132.svg) ![forks](https://img.shields.io/github/forks/HoangKien1020/CVE-2021-23132.svg)


## CVE-2021-4154
 A use-after-free flaw was found in cgroup1_parse_param in kernel/cgroup/cgroup-v1.c in the Linux kernel's cgroup v1 parser. A local attacker with a user privilege could cause a privilege escalation by exploiting the fsconfig syscall parameter leading to a container breakout and a denial of service on the system.

- [https://github.com/Markakd/CVE-2021-4154](https://github.com/Markakd/CVE-2021-4154) :  ![starts](https://img.shields.io/github/stars/Markakd/CVE-2021-4154.svg) ![forks](https://img.shields.io/github/forks/Markakd/CVE-2021-4154.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/jm33-m0/emp3r0r](https://github.com/jm33-m0/emp3r0r) :  ![starts](https://img.shields.io/github/stars/jm33-m0/emp3r0r.svg) ![forks](https://img.shields.io/github/forks/jm33-m0/emp3r0r.svg)
- [https://github.com/c3c/CVE-2021-4034](https://github.com/c3c/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/c3c/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/c3c/CVE-2021-4034.svg)
- [https://github.com/rvizx/CVE-2021-4034](https://github.com/rvizx/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/rvizx/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/rvizx/CVE-2021-4034.svg)


## CVE-2020-11023
 In jQuery versions greater than or equal to 1.0.3 and before 3.5.0, passing HTML containing &lt;option&gt; elements from untrusted sources - even after sanitizing it - to one of jQuery's DOM manipulation methods (i.e. .html(), .append(), and others) may execute untrusted code. This problem is patched in jQuery 3.5.0.

- [https://github.com/Cybernegro/CVE-2020-11023](https://github.com/Cybernegro/CVE-2020-11023) :  ![starts](https://img.shields.io/github/stars/Cybernegro/CVE-2020-11023.svg) ![forks](https://img.shields.io/github/forks/Cybernegro/CVE-2020-11023.svg)


## CVE-2020-1764
 A hard-coded cryptographic key vulnerability in the default configuration file was found in Kiali, all versions prior to 1.15.1. A remote attacker could abuse this flaw by creating their own JWT signed tokens and bypass Kiali authentication mechanisms, possibly gaining privileges to view and alter the Istio configuration.

- [https://github.com/jpts/cve-2020-1764-poc](https://github.com/jpts/cve-2020-1764-poc) :  ![starts](https://img.shields.io/github/stars/jpts/cve-2020-1764-poc.svg) ![forks](https://img.shields.io/github/forks/jpts/cve-2020-1764-poc.svg)


## CVE-2019-11708
 Insufficient vetting of parameters passed with the Prompt:Open IPC message between child and parent processes can result in the non-sandboxed parent process opening web content chosen by a compromised child process. When combined with additional vulnerabilities this could result in executing arbitrary code on the user's computer. This vulnerability affects Firefox ESR &lt; 60.7.2, Firefox &lt; 67.0.4, and Thunderbird &lt; 60.7.2.

- [https://github.com/0vercl0k/CVE-2019-11708](https://github.com/0vercl0k/CVE-2019-11708) :  ![starts](https://img.shields.io/github/stars/0vercl0k/CVE-2019-11708.svg) ![forks](https://img.shields.io/github/forks/0vercl0k/CVE-2019-11708.svg)


## CVE-2018-19320
 The GDrv low-level driver in GIGABYTE APP Center v1.05.21 and earlier, AORUS GRAPHICS ENGINE before 1.57, XTREME GAMING ENGINE before 1.26, and OC GURU II v2.08 exposes ring0 memcpy-like functionality that could allow a local attacker to take complete control of the affected system.

- [https://github.com/ss256100/CVE-2018-19320](https://github.com/ss256100/CVE-2018-19320) :  ![starts](https://img.shields.io/github/stars/ss256100/CVE-2018-19320.svg) ![forks](https://img.shields.io/github/forks/ss256100/CVE-2018-19320.svg)


## CVE-2018-1335
 From Apache Tika versions 1.7 to 1.17, clients could send carefully crafted headers to tika-server that could be used to inject commands into the command line of the server running tika-server. This vulnerability only affects those running tika-server on a server that is open to untrusted clients. The mitigation is to upgrade to Tika 1.18.

- [https://github.com/N0b1e6/CVE-2018-1335-Python3](https://github.com/N0b1e6/CVE-2018-1335-Python3) :  ![starts](https://img.shields.io/github/stars/N0b1e6/CVE-2018-1335-Python3.svg) ![forks](https://img.shields.io/github/forks/N0b1e6/CVE-2018-1335-Python3.svg)


## CVE-2017-13156
 An elevation of privilege vulnerability in the Android system (art). Product: Android. Versions: 5.1.1, 6.0, 6.0.1, 7.0, 7.1.1, 7.1.2, 8.0. Android ID A-64211847.

- [https://github.com/entediado97/rosa_dex_injetor](https://github.com/entediado97/rosa_dex_injetor) :  ![starts](https://img.shields.io/github/stars/entediado97/rosa_dex_injetor.svg) ![forks](https://img.shields.io/github/forks/entediado97/rosa_dex_injetor.svg)

