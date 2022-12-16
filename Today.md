# Update 2022-12-16
## CVE-2022-46381
 Certain Linear eMerge E3-Series devices are vulnerable to XSS via the type parameter (e.g., to the badging/badge_template_v0.php component). This affects 0.32-08f, 0.32-07p, 0.32-07e, 0.32-09c, 0.32-09b, 0.32-09a, and 0.32-08e.

- [https://github.com/amitlttwo/CVE-2022-46381](https://github.com/amitlttwo/CVE-2022-46381) :  ![starts](https://img.shields.io/github/stars/amitlttwo/CVE-2022-46381.svg) ![forks](https://img.shields.io/github/forks/amitlttwo/CVE-2022-46381.svg)


## CVE-2022-41974
 multipath-tools 0.7.0 through 0.9.x before 0.9.2 allows local users to obtain root access, as exploited alone or in conjunction with CVE-2022-41973. Local users able to write to UNIX domain sockets can bypass access controls and manipulate the multipath setup. This can lead to local privilege escalation to root. This occurs because an attacker can repeat a keyword, which is mishandled because arithmetic ADD is used instead of bitwise OR.

- [https://github.com/Mr-xn/CVE-2022-3328](https://github.com/Mr-xn/CVE-2022-3328) :  ![starts](https://img.shields.io/github/stars/Mr-xn/CVE-2022-3328.svg) ![forks](https://img.shields.io/github/forks/Mr-xn/CVE-2022-3328.svg)


## CVE-2022-41973
 multipath-tools 0.7.7 through 0.9.x before 0.9.2 allows local users to obtain root access, as exploited in conjunction with CVE-2022-41974. Local users able to access /dev/shm can change symlinks in multipathd due to incorrect symlink handling, which could lead to controlled file writes outside of the /dev/shm directory. This could be used indirectly for local privilege escalation to root.

- [https://github.com/Mr-xn/CVE-2022-3328](https://github.com/Mr-xn/CVE-2022-3328) :  ![starts](https://img.shields.io/github/stars/Mr-xn/CVE-2022-3328.svg) ![forks](https://img.shields.io/github/forks/Mr-xn/CVE-2022-3328.svg)


## CVE-2022-3328
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/Mr-xn/CVE-2022-3328](https://github.com/Mr-xn/CVE-2022-3328) :  ![starts](https://img.shields.io/github/stars/Mr-xn/CVE-2022-3328.svg) ![forks](https://img.shields.io/github/forks/Mr-xn/CVE-2022-3328.svg)


## CVE-2021-42013
 It was found that the fix for CVE-2021-41773 in Apache HTTP Server 2.4.50 was insufficient. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue only affects Apache 2.4.49 and Apache 2.4.50 and not earlier versions.

- [https://github.com/hifumi1337/apache-traversal](https://github.com/hifumi1337/apache-traversal) :  ![starts](https://img.shields.io/github/stars/hifumi1337/apache-traversal.svg) ![forks](https://img.shields.io/github/forks/hifumi1337/apache-traversal.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/hifumi1337/apache-traversal](https://github.com/hifumi1337/apache-traversal) :  ![starts](https://img.shields.io/github/stars/hifumi1337/apache-traversal.svg) ![forks](https://img.shields.io/github/forks/hifumi1337/apache-traversal.svg)
- [https://github.com/Plunder283/CVE-2021-41773](https://github.com/Plunder283/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/Plunder283/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/Plunder283/CVE-2021-41773.svg)
- [https://github.com/Evil-d0Zz/CVE-2021-41773-](https://github.com/Evil-d0Zz/CVE-2021-41773-) :  ![starts](https://img.shields.io/github/stars/Evil-d0Zz/CVE-2021-41773-.svg) ![forks](https://img.shields.io/github/forks/Evil-d0Zz/CVE-2021-41773-.svg)


## CVE-2021-36782
 A Cleartext Storage of Sensitive Information vulnerability in SUSE Rancher allows authenticated Cluster Owners, Cluster Members, Project Owners, Project Members and User Base to use the Kubernetes API to retrieve plaintext version of sensitive data. This issue affects: SUSE Rancher Rancher versions prior to 2.5.16; Rancher versions prior to 2.6.7.

- [https://github.com/fe-ax/tf-cve-2021-36782](https://github.com/fe-ax/tf-cve-2021-36782) :  ![starts](https://img.shields.io/github/stars/fe-ax/tf-cve-2021-36782.svg) ![forks](https://img.shields.io/github/forks/fe-ax/tf-cve-2021-36782.svg)


## CVE-2021-27928
 A remote code execution issue was discovered in MariaDB 10.2 before 10.2.37, 10.3 before 10.3.28, 10.4 before 10.4.18, and 10.5 before 10.5.9; Percona Server through 2021-03-03; and the wsrep patch through 2021-03-03 for MySQL. An untrusted search path leads to eval injection, in which a database SUPER user can execute OS commands after modifying wsrep_provider and wsrep_notify_cmd. NOTE: this does not affect an Oracle product.

- [https://github.com/LalieA/CVE-2021-27928](https://github.com/LalieA/CVE-2021-27928) :  ![starts](https://img.shields.io/github/stars/LalieA/CVE-2021-27928.svg) ![forks](https://img.shields.io/github/forks/LalieA/CVE-2021-27928.svg)


## CVE-2020-1020
 A remote code execution vulnerability exists in Microsoft Windows when the Windows Adobe Type Manager Library improperly handles a specially-crafted multi-master font - Adobe Type 1 PostScript format.For all systems except Windows 10, an attacker who successfully exploited the vulnerability could execute code remotely, aka 'Adobe Font Manager Library Remote Code Execution Vulnerability'. This CVE ID is unique from CVE-2020-0938.

- [https://github.com/KaLendsi/CVE-2020-1020](https://github.com/KaLendsi/CVE-2020-1020) :  ![starts](https://img.shields.io/github/stars/KaLendsi/CVE-2020-1020.svg) ![forks](https://img.shields.io/github/forks/KaLendsi/CVE-2020-1020.svg)


## CVE-2020-0796
 A remote code execution vulnerability exists in the way that the Microsoft Server Message Block 3.1.1 (SMBv3) protocol handles certain requests, aka 'Windows SMBv3 Client/Server Remote Code Execution Vulnerability'.

- [https://github.com/TweatherQ/CVE-2020-0796](https://github.com/TweatherQ/CVE-2020-0796) :  ![starts](https://img.shields.io/github/stars/TweatherQ/CVE-2020-0796.svg) ![forks](https://img.shields.io/github/forks/TweatherQ/CVE-2020-0796.svg)


## CVE-2019-10220
 Linux kernel CIFS implementation, version 4.9.0 is vulnerable to a relative paths injection in directory entry lists.

- [https://github.com/Trinadh465/linux-3.0.35_CVE-2019-10220](https://github.com/Trinadh465/linux-3.0.35_CVE-2019-10220) :  ![starts](https://img.shields.io/github/stars/Trinadh465/linux-3.0.35_CVE-2019-10220.svg) ![forks](https://img.shields.io/github/forks/Trinadh465/linux-3.0.35_CVE-2019-10220.svg)


## CVE-2019-9053
 An issue was discovered in CMS Made Simple 2.2.8. It is possible with the News module, through a crafted URL, to achieve unauthenticated blind time-based SQL injection via the m1_idlist parameter.

- [https://github.com/pedrojosenavasperez/CVE-2019-9053-Python3](https://github.com/pedrojosenavasperez/CVE-2019-9053-Python3) :  ![starts](https://img.shields.io/github/stars/pedrojosenavasperez/CVE-2019-9053-Python3.svg) ![forks](https://img.shields.io/github/forks/pedrojosenavasperez/CVE-2019-9053-Python3.svg)


## CVE-2012-2982
 file/show.cgi in Webmin 1.590 and earlier allows remote authenticated users to execute arbitrary commands via an invalid character in a pathname, as demonstrated by a | (pipe) character.

- [https://github.com/0xTas/CVE-2012-2982](https://github.com/0xTas/CVE-2012-2982) :  ![starts](https://img.shields.io/github/stars/0xTas/CVE-2012-2982.svg) ![forks](https://img.shields.io/github/forks/0xTas/CVE-2012-2982.svg)

