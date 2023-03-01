# Update 2023-03-01
## CVE-2022-42889
 Apache Commons Text performs variable interpolation, allowing properties to be dynamically evaluated and expanded. The standard format for interpolation is &quot;${prefix:name}&quot;, where &quot;prefix&quot; is used to locate an instance of org.apache.commons.text.lookup.StringLookup that performs the interpolation. Starting with version 1.5 and continuing through 1.9, the set of default Lookup instances included interpolators that could result in arbitrary code execution or contact with remote servers. These lookups are: - &quot;script&quot; - execute expressions using the JVM script execution engine (javax.script) - &quot;dns&quot; - resolve dns records - &quot;url&quot; - load values from urls, including from remote servers Applications using the interpolation defaults in the affected versions may be vulnerable to remote code execution or unintentional contact with remote servers if untrusted configuration values are used. Users are recommended to upgrade to Apache Commons Text 1.10.0, which disables the problematic interpolators by default.

- [https://github.com/devenes/text4shell-cve-2022-42889](https://github.com/devenes/text4shell-cve-2022-42889) :  ![starts](https://img.shields.io/github/stars/devenes/text4shell-cve-2022-42889.svg) ![forks](https://img.shields.io/github/forks/devenes/text4shell-cve-2022-42889.svg)


## CVE-2022-40684
 An authentication bypass using an alternate path or channel [CWE-288] in Fortinet FortiOS version 7.2.0 through 7.2.1 and 7.0.0 through 7.0.6, FortiProxy version 7.2.0 and version 7.0.0 through 7.0.6 and FortiSwitchManager version 7.2.0 and 7.0.0 allows an unauthenticated atttacker to perform operations on the administrative interface via specially crafted HTTP or HTTPS requests.

- [https://github.com/z-bool/CVE-2022-40684](https://github.com/z-bool/CVE-2022-40684) :  ![starts](https://img.shields.io/github/stars/z-bool/CVE-2022-40684.svg) ![forks](https://img.shields.io/github/forks/z-bool/CVE-2022-40684.svg)


## CVE-2022-30190
 Microsoft Windows Support Diagnostic Tool (MSDT) Remote Code Execution Vulnerability.

- [https://github.com/Gra3s/CVE-2022-30190_PowerPoint](https://github.com/Gra3s/CVE-2022-30190_PowerPoint) :  ![starts](https://img.shields.io/github/stars/Gra3s/CVE-2022-30190_PowerPoint.svg) ![forks](https://img.shields.io/github/forks/Gra3s/CVE-2022-30190_PowerPoint.svg)


## CVE-2022-1386
 The Fusion Builder WordPress plugin before 3.6.2, used in the Avada theme, does not validate a parameter in its forms which could be used to initiate arbitrary HTTP requests. The data returned is then reflected back in the application's response. This could be used to interact with hosts on the server's local network bypassing firewalls and access control measures.

- [https://github.com/ardzz/CVE-2022-1386](https://github.com/ardzz/CVE-2022-1386) :  ![starts](https://img.shields.io/github/stars/ardzz/CVE-2022-1386.svg) ![forks](https://img.shields.io/github/forks/ardzz/CVE-2022-1386.svg)


## CVE-2021-44228
 Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled. From log4j 2.15.0, this behavior has been disabled by default. From version 2.16.0 (along with 2.12.2, 2.12.3, and 2.3.1), this functionality has been completely removed. Note that this vulnerability is specific to log4j-core and does not affect log4net, log4cxx, or other Apache Logging Services projects.

- [https://github.com/rakutentech/jndi-ldap-test-server](https://github.com/rakutentech/jndi-ldap-test-server) :  ![starts](https://img.shields.io/github/stars/rakutentech/jndi-ldap-test-server.svg) ![forks](https://img.shields.io/github/forks/rakutentech/jndi-ldap-test-server.svg)


## CVE-2021-40870
 An issue was discovered in Aviatrix Controller 6.x before 6.5-1804.1922. Unrestricted upload of a file with a dangerous type is possible, which allows an unauthenticated user to execute arbitrary code via directory traversal.

- [https://github.com/0xAgun/CVE-2021-40870](https://github.com/0xAgun/CVE-2021-40870) :  ![starts](https://img.shields.io/github/stars/0xAgun/CVE-2021-40870.svg) ![forks](https://img.shields.io/github/forks/0xAgun/CVE-2021-40870.svg)


## CVE-2021-22205
 An issue has been discovered in GitLab CE/EE affecting all versions starting from 11.9. GitLab was not properly validating image files that were passed to a file parser which resulted in a remote command execution.

- [https://github.com/hhhotdrink/CVE-2021-22205](https://github.com/hhhotdrink/CVE-2021-22205) :  ![starts](https://img.shields.io/github/stars/hhhotdrink/CVE-2021-22205.svg) ![forks](https://img.shields.io/github/forks/hhhotdrink/CVE-2021-22205.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/azazelm3dj3d/CVE-2021-4034](https://github.com/azazelm3dj3d/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/azazelm3dj3d/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/azazelm3dj3d/CVE-2021-4034.svg)


## CVE-2020-0796
 A remote code execution vulnerability exists in the way that the Microsoft Server Message Block 3.1.1 (SMBv3) protocol handles certain requests, aka 'Windows SMBv3 Client/Server Remote Code Execution Vulnerability'.

- [https://github.com/OldDream666/cve-2020-0796](https://github.com/OldDream666/cve-2020-0796) :  ![starts](https://img.shields.io/github/stars/OldDream666/cve-2020-0796.svg) ![forks](https://img.shields.io/github/forks/OldDream666/cve-2020-0796.svg)


## CVE-2019-13623
 In NSA Ghidra before 9.1, path traversal can occur in RestoreTask.java (from the package ghidra.app.plugin.core.archive) via an archive with an executable file that has an initial ../ in its filename. This allows attackers to overwrite arbitrary files in scenarios where an intermediate analysis result is archived for sharing with other persons. To achieve arbitrary code execution, one approach is to overwrite some critical Ghidra modules, e.g., the decompile module.

- [https://github.com/s9rA16Bf4/exploits](https://github.com/s9rA16Bf4/exploits) :  ![starts](https://img.shields.io/github/stars/s9rA16Bf4/exploits.svg) ![forks](https://img.shields.io/github/forks/s9rA16Bf4/exploits.svg)


## CVE-2019-1064
 An elevation of privilege vulnerability exists when Windows AppX Deployment Service (AppXSVC) improperly handles hard links, aka 'Windows Elevation of Privilege Vulnerability'.

- [https://github.com/0x00-0x00/CVE-2019-1064](https://github.com/0x00-0x00/CVE-2019-1064) :  ![starts](https://img.shields.io/github/stars/0x00-0x00/CVE-2019-1064.svg) ![forks](https://img.shields.io/github/forks/0x00-0x00/CVE-2019-1064.svg)


## CVE-2017-9077
 The tcp_v6_syn_recv_sock function in net/ipv6/tcp_ipv6.c in the Linux kernel through 4.11.1 mishandles inheritance, which allows local users to cause a denial of service or possibly have unspecified other impact via crafted system calls, a related issue to CVE-2017-8890.

- [https://github.com/idhyt/androotzf](https://github.com/idhyt/androotzf) :  ![starts](https://img.shields.io/github/stars/idhyt/androotzf.svg) ![forks](https://img.shields.io/github/forks/idhyt/androotzf.svg)


## CVE-2017-8890
 The inet_csk_clone_lock function in net/ipv4/inet_connection_sock.c in the Linux kernel through 4.10.15 allows attackers to cause a denial of service (double free) or possibly have unspecified other impact by leveraging use of the accept system call.

- [https://github.com/idhyt/androotzf](https://github.com/idhyt/androotzf) :  ![starts](https://img.shields.io/github/stars/idhyt/androotzf.svg) ![forks](https://img.shields.io/github/forks/idhyt/androotzf.svg)


## CVE-2016-5195
 Race condition in mm/gup.c in the Linux kernel 2.x through 4.x before 4.8.3 allows local users to gain privileges by leveraging incorrect handling of a copy-on-write (COW) feature to write to a read-only memory mapping, as exploited in the wild in October 2016, aka &quot;Dirty COW.&quot;

- [https://github.com/TotallyNotAHaxxer/CVE-2016-5195](https://github.com/TotallyNotAHaxxer/CVE-2016-5195) :  ![starts](https://img.shields.io/github/stars/TotallyNotAHaxxer/CVE-2016-5195.svg) ![forks](https://img.shields.io/github/forks/TotallyNotAHaxxer/CVE-2016-5195.svg)


## CVE-2016-5159
 Multiple integer overflows in OpenJPEG, as used in PDFium in Google Chrome before 53.0.2785.89 on Windows and OS X and before 53.0.2785.92 on Linux, allow remote attackers to cause a denial of service (heap-based buffer overflow) or possibly have unspecified other impact via crafted JPEG 2000 data that is mishandled during opj_aligned_malloc calls in dwt.c and t1.c.

- [https://github.com/idhyt/androotzf](https://github.com/idhyt/androotzf) :  ![starts](https://img.shields.io/github/stars/idhyt/androotzf.svg) ![forks](https://img.shields.io/github/forks/idhyt/androotzf.svg)


## CVE-2015-3636
 The ping_unhash function in net/ipv4/ping.c in the Linux kernel before 4.0.3 does not initialize a certain list data structure during an unhash operation, which allows local users to gain privileges or cause a denial of service (use-after-free and system crash) by leveraging the ability to make a SOCK_DGRAM socket system call for the IPPROTO_ICMP or IPPROTO_ICMPV6 protocol, and then making a connect system call after a disconnect.

- [https://github.com/idhyt/androotzf](https://github.com/idhyt/androotzf) :  ![starts](https://img.shields.io/github/stars/idhyt/androotzf.svg) ![forks](https://img.shields.io/github/forks/idhyt/androotzf.svg)


## CVE-2015-1805
 The (1) pipe_read and (2) pipe_write implementations in fs/pipe.c in the Linux kernel before 3.16 do not properly consider the side effects of failed __copy_to_user_inatomic and __copy_from_user_inatomic calls, which allows local users to cause a denial of service (system crash) or possibly gain privileges via a crafted application, aka an &quot;I/O vector array overrun.&quot;

- [https://github.com/idhyt/androotzf](https://github.com/idhyt/androotzf) :  ![starts](https://img.shields.io/github/stars/idhyt/androotzf.svg) ![forks](https://img.shields.io/github/forks/idhyt/androotzf.svg)

