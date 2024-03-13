# Update 2024-03-13
## CVE-2024-27665
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/Thirukrishnan/CVE-2024-27665](https://github.com/Thirukrishnan/CVE-2024-27665) :  ![starts](https://img.shields.io/github/stars/Thirukrishnan/CVE-2024-27665.svg) ![forks](https://img.shields.io/github/forks/Thirukrishnan/CVE-2024-27665.svg)


## CVE-2024-21762
 A out-of-bounds write in Fortinet FortiOS versions 7.4.0 through 7.4.2, 7.2.0 through 7.2.6, 7.0.0 through 7.0.13, 6.4.0 through 6.4.14, 6.2.0 through 6.2.15, 6.0.0 through 6.0.17, FortiProxy versions 7.4.0 through 7.4.2, 7.2.0 through 7.2.8, 7.0.0 through 7.0.14, 2.0.0 through 2.0.13, 1.2.0 through 1.2.13, 1.1.0 through 1.1.6, 1.0.0 through 1.0.7 allows attacker to execute unauthorized code or commands via specifically crafted requests

- [https://github.com/c0d3b3af/CVE-2024-21762-RCE-exploit](https://github.com/c0d3b3af/CVE-2024-21762-RCE-exploit) :  ![starts](https://img.shields.io/github/stars/c0d3b3af/CVE-2024-21762-RCE-exploit.svg) ![forks](https://img.shields.io/github/forks/c0d3b3af/CVE-2024-21762-RCE-exploit.svg)
- [https://github.com/cleverg0d/CVE-2024-21762-Checker](https://github.com/cleverg0d/CVE-2024-21762-Checker) :  ![starts](https://img.shields.io/github/stars/cleverg0d/CVE-2024-21762-Checker.svg) ![forks](https://img.shields.io/github/forks/cleverg0d/CVE-2024-21762-Checker.svg)


## CVE-2022-20114
 In placeCall of TelecomManager.java, there is a possible way for an application to keep itself running with foreground service importance due to a permissions bypass. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-10 Android-11 Android-12 Android-12LAndroid ID: A-211114016

- [https://github.com/hienkiet/CVE-2022-201145-12.2.1.3.0-Weblogic](https://github.com/hienkiet/CVE-2022-201145-12.2.1.3.0-Weblogic) :  ![starts](https://img.shields.io/github/stars/hienkiet/CVE-2022-201145-12.2.1.3.0-Weblogic.svg) ![forks](https://img.shields.io/github/forks/hienkiet/CVE-2022-201145-12.2.1.3.0-Weblogic.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/Plunder283/CVE-2021-41773](https://github.com/Plunder283/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/Plunder283/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/Plunder283/CVE-2021-41773.svg)


## CVE-2020-25579
 In FreeBSD 12.2-STABLE before r368969, 11.4-STABLE before r369047, 12.2-RELEASE before p3, 12.1-RELEASE before p13 and 11.4-RELEASE before p7 msdosfs(5) was failing to zero-fill a pair of padding fields in the dirent structure, resulting in a leak of three uninitialized bytes.

- [https://github.com/farazsth98/freebsd-dirent-info-leak-bugs](https://github.com/farazsth98/freebsd-dirent-info-leak-bugs) :  ![starts](https://img.shields.io/github/stars/farazsth98/freebsd-dirent-info-leak-bugs.svg) ![forks](https://img.shields.io/github/forks/farazsth98/freebsd-dirent-info-leak-bugs.svg)


## CVE-2020-25578
 In FreeBSD 12.2-STABLE before r368969, 11.4-STABLE before r369047, 12.2-RELEASE before p3, 12.1-RELEASE before p13 and 11.4-RELEASE before p7 several file systems were not properly initializing the d_off field of the dirent structures returned by VOP_READDIR. In particular, tmpfs(5), smbfs(5), autofs(5) and mqueuefs(5) were failing to do so. As a result, eight uninitialized kernel stack bytes may be leaked to userspace by these file systems.

- [https://github.com/farazsth98/freebsd-dirent-info-leak-bugs](https://github.com/farazsth98/freebsd-dirent-info-leak-bugs) :  ![starts](https://img.shields.io/github/stars/farazsth98/freebsd-dirent-info-leak-bugs.svg) ![forks](https://img.shields.io/github/forks/farazsth98/freebsd-dirent-info-leak-bugs.svg)

