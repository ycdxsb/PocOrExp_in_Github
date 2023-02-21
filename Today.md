# Update 2023-02-21
## CVE-2022-44311
 html2xhtml v1.3 was discovered to contain an Out-Of-Bounds read in the function static void elm_close(tree_node_t *nodo) at procesador.c. This vulnerability allows attackers to access sensitive files or cause a Denial of Service (DoS) via a crafted html file.

- [https://github.com/DesmondSanctity/Out-Of-Bounds-read-in-html2xhtml-v1.3-CVE-2022-44311](https://github.com/DesmondSanctity/Out-Of-Bounds-read-in-html2xhtml-v1.3-CVE-2022-44311) :  ![starts](https://img.shields.io/github/stars/DesmondSanctity/Out-Of-Bounds-read-in-html2xhtml-v1.3-CVE-2022-44311.svg) ![forks](https://img.shields.io/github/forks/DesmondSanctity/Out-Of-Bounds-read-in-html2xhtml-v1.3-CVE-2022-44311.svg)


## CVE-2022-42889
 Apache Commons Text performs variable interpolation, allowing properties to be dynamically evaluated and expanded. The standard format for interpolation is &quot;${prefix:name}&quot;, where &quot;prefix&quot; is used to locate an instance of org.apache.commons.text.lookup.StringLookup that performs the interpolation. Starting with version 1.5 and continuing through 1.9, the set of default Lookup instances included interpolators that could result in arbitrary code execution or contact with remote servers. These lookups are: - &quot;script&quot; - execute expressions using the JVM script execution engine (javax.script) - &quot;dns&quot; - resolve dns records - &quot;url&quot; - load values from urls, including from remote servers Applications using the interpolation defaults in the affected versions may be vulnerable to remote code execution or unintentional contact with remote servers if untrusted configuration values are used. Users are recommended to upgrade to Apache Commons Text 1.10.0, which disables the problematic interpolators by default.

- [https://github.com/WFS-Mend/vtrade-common](https://github.com/WFS-Mend/vtrade-common) :  ![starts](https://img.shields.io/github/stars/WFS-Mend/vtrade-common.svg) ![forks](https://img.shields.io/github/forks/WFS-Mend/vtrade-common.svg)


## CVE-2022-39952
 A external control of file name or path in Fortinet FortiNAC versions 9.4.0, 9.2.0 through 9.2.5, 9.1.0 through 9.1.7, 8.8.0 through 8.8.11, 8.7.0 through 8.7.6, 8.6.0 through 8.6.5, 8.5.0 through 8.5.4, 8.3.7 may allow an unauthenticated attacker to execute unauthorized code or commands via specifically crafted HTTP request.

- [https://github.com/Florian-R0th/CVE-2022-39952](https://github.com/Florian-R0th/CVE-2022-39952) :  ![starts](https://img.shields.io/github/stars/Florian-R0th/CVE-2022-39952.svg) ![forks](https://img.shields.io/github/forks/Florian-R0th/CVE-2022-39952.svg)


## CVE-2022-25365
 Docker Desktop before 4.5.1 on Windows allows attackers to move arbitrary files. NOTE: this issue exists because of an incomplete fix for CVE-2022-23774.

- [https://github.com/followboy1999/CVE-2022-25365](https://github.com/followboy1999/CVE-2022-25365) :  ![starts](https://img.shields.io/github/stars/followboy1999/CVE-2022-25365.svg) ![forks](https://img.shields.io/github/forks/followboy1999/CVE-2022-25365.svg)


## CVE-2022-4025
 Inappropriate implementation in Paint in Google Chrome prior to 98.0.4758.80 allowed a remote attacker to leak cross-origin data outside an iframe via a crafted HTML page. (Chrome security severity: Low)

- [https://github.com/Live-Hack-CVE/CVE-2022-4025](https://github.com/Live-Hack-CVE/CVE-2022-4025) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4025.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4025.svg)


## CVE-2022-2985
 In music service, there is a missing permission check. This could lead to elevation of privilege in contacts service with no additional execution privileges needed.

- [https://github.com/Live-Hack-CVE/CVE-2022-2985](https://github.com/Live-Hack-CVE/CVE-2022-2985) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2985.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2985.svg)


## CVE-2022-2900
 Server-Side Request Forgery (SSRF) in GitHub repository ionicabizau/parse-url prior to 8.1.0.

- [https://github.com/Live-Hack-CVE/CVE-2022-2900](https://github.com/Live-Hack-CVE/CVE-2022-2900) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2900.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2900.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/m96dg/CVE-2021-41773-exercise](https://github.com/m96dg/CVE-2021-41773-exercise) :  ![starts](https://img.shields.io/github/stars/m96dg/CVE-2021-41773-exercise.svg) ![forks](https://img.shields.io/github/forks/m96dg/CVE-2021-41773-exercise.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/dadvlingd/CVE-2021-4034](https://github.com/dadvlingd/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/dadvlingd/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/dadvlingd/CVE-2021-4034.svg)


## CVE-2021-3864
 A flaw was found in the way the dumpable flag setting was handled when certain SUID binaries executed its descendants. The prerequisite is a SUID binary that sets real UID equal to effective UID, and real GID equal to effective GID. The descendant will then have a dumpable value set to 1. As a result, if the descendant process crashes and core_pattern is set to a relative value, its core dump is stored in the current directory with uid:gid permissions. An unprivileged local user with eligible root SUID binary could use this flaw to place core dumps into root-owned directories, potentially resulting in escalation of privileges.

- [https://github.com/Live-Hack-CVE/CVE-2021-3864](https://github.com/Live-Hack-CVE/CVE-2021-3864) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-3864.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-3864.svg)


## CVE-2021-3655
 A vulnerability was found in the Linux kernel in versions prior to v5.14-rc1. Missing size validations on inbound SCTP packets may allow the kernel to read uninitialized memory.

- [https://github.com/Live-Hack-CVE/CVE-2021-3655](https://github.com/Live-Hack-CVE/CVE-2021-3655) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-3655.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-3655.svg)


## CVE-2020-1472
 An elevation of privilege vulnerability exists when an attacker establishes a vulnerable Netlogon secure channel connection to a domain controller, using the Netlogon Remote Protocol (MS-NRPC), aka 'Netlogon Elevation of Privilege Vulnerability'.

- [https://github.com/mstxq17/cve-2020-1472](https://github.com/mstxq17/cve-2020-1472) :  ![starts](https://img.shields.io/github/stars/mstxq17/cve-2020-1472.svg) ![forks](https://img.shields.io/github/forks/mstxq17/cve-2020-1472.svg)
- [https://github.com/k8gege/CVE-2020-1472-EXP](https://github.com/k8gege/CVE-2020-1472-EXP) :  ![starts](https://img.shields.io/github/stars/k8gege/CVE-2020-1472-EXP.svg) ![forks](https://img.shields.io/github/forks/k8gege/CVE-2020-1472-EXP.svg)
- [https://github.com/guglia001/MassZeroLogon](https://github.com/guglia001/MassZeroLogon) :  ![starts](https://img.shields.io/github/stars/guglia001/MassZeroLogon.svg) ![forks](https://img.shields.io/github/forks/guglia001/MassZeroLogon.svg)
- [https://github.com/422926799/CVE-2020-1472](https://github.com/422926799/CVE-2020-1472) :  ![starts](https://img.shields.io/github/stars/422926799/CVE-2020-1472.svg) ![forks](https://img.shields.io/github/forks/422926799/CVE-2020-1472.svg)
- [https://github.com/victim10wq3/CVE-2020-1472](https://github.com/victim10wq3/CVE-2020-1472) :  ![starts](https://img.shields.io/github/stars/victim10wq3/CVE-2020-1472.svg) ![forks](https://img.shields.io/github/forks/victim10wq3/CVE-2020-1472.svg)


## CVE-2018-1111
 DHCP packages in Red Hat Enterprise Linux 6 and 7, Fedora 28, and earlier are vulnerable to a command injection flaw in the NetworkManager integration script included in the DHCP client. A malicious DHCP server, or an attacker on the local network able to spoof DHCP responses, could use this flaw to execute arbitrary commands with root privileges on systems using NetworkManager and configured to obtain network configuration using the DHCP protocol.

- [https://github.com/Live-Hack-CVE/CVE-2018-1111](https://github.com/Live-Hack-CVE/CVE-2018-1111) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2018-1111.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2018-1111.svg)


## CVE-2006-20001
 A carefully crafted If: request header can cause a memory read, or write of a single zero byte, in a pool (heap) memory location beyond the header value sent. This could cause the process to crash. This issue affects Apache HTTP Server 2.4.54 and earlier.

- [https://github.com/Saksham2002/CVE-2006-20001](https://github.com/Saksham2002/CVE-2006-20001) :  ![starts](https://img.shields.io/github/stars/Saksham2002/CVE-2006-20001.svg) ![forks](https://img.shields.io/github/forks/Saksham2002/CVE-2006-20001.svg)

