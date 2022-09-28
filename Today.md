# Update 2022-09-28
## CVE-2022-39197
 An XSS (Cross Site Scripting) vulnerability was found in HelpSystems Cobalt Strike through 4.7 that allowed a remote attacker to execute HTML on the Cobalt Strike teamserver. To exploit the vulnerability, one must first inspect a Cobalt Strike payload, and then modify the username field in the payload (or create a new payload with the extracted information and then modify that username field to be malformed).

- [https://github.com/burpheart/CVE-2022-39197-patch](https://github.com/burpheart/CVE-2022-39197-patch) :  ![starts](https://img.shields.io/github/stars/burpheart/CVE-2022-39197-patch.svg) ![forks](https://img.shields.io/github/forks/burpheart/CVE-2022-39197-patch.svg)
- [https://github.com/lovechoudoufu/about_cobaltstrike4.5_cdf](https://github.com/lovechoudoufu/about_cobaltstrike4.5_cdf) :  ![starts](https://img.shields.io/github/stars/lovechoudoufu/about_cobaltstrike4.5_cdf.svg) ![forks](https://img.shields.io/github/forks/lovechoudoufu/about_cobaltstrike4.5_cdf.svg)


## CVE-2022-36804
 Multiple API endpoints in Atlassian Bitbucket Server and Data Center 7.0.0 before version 7.6.17, from version 7.7.0 before version 7.17.10, from version 7.18.0 before version 7.21.4, from version 8.0.0 before version 8.0.3, from version 8.1.0 before version 8.1.3, and from version 8.2.0 before version 8.2.2, and from version 8.3.0 before 8.3.1 allows remote attackers with read permissions to a public or private Bitbucket repository to execute arbitrary code by sending a malicious HTTP request. This vulnerability was reported via our Bug Bounty Program by TheGrandPew.

- [https://github.com/Inplex-sys/CVE-2022-36804](https://github.com/Inplex-sys/CVE-2022-36804) :  ![starts](https://img.shields.io/github/stars/Inplex-sys/CVE-2022-36804.svg) ![forks](https://img.shields.io/github/forks/Inplex-sys/CVE-2022-36804.svg)


## CVE-2022-32548
 An issue was discovered on certain DrayTek Vigor routers before July 2022 such as the Vigor3910 before 4.3.1.1. /cgi-bin/wlogin.cgi has a buffer overflow via the username or password to the aa or ab field.

- [https://github.com/MaX0dexpoit/CVE-2022-32548](https://github.com/MaX0dexpoit/CVE-2022-32548) :  ![starts](https://img.shields.io/github/stars/MaX0dexpoit/CVE-2022-32548.svg) ![forks](https://img.shields.io/github/forks/MaX0dexpoit/CVE-2022-32548.svg)
- [https://github.com/Xu0Tex1/CVE-2022-32548-Mass-Rce](https://github.com/Xu0Tex1/CVE-2022-32548-Mass-Rce) :  ![starts](https://img.shields.io/github/stars/Xu0Tex1/CVE-2022-32548-Mass-Rce.svg) ![forks](https://img.shields.io/github/forks/Xu0Tex1/CVE-2022-32548-Mass-Rce.svg)


## CVE-2022-30206
 Windows Print Spooler Elevation of Privilege Vulnerability. This CVE ID is unique from CVE-2022-22022, CVE-2022-22041, CVE-2022-30226.

- [https://github.com/Malwareman007/CVE-2022-30206](https://github.com/Malwareman007/CVE-2022-30206) :  ![starts](https://img.shields.io/github/stars/Malwareman007/CVE-2022-30206.svg) ![forks](https://img.shields.io/github/forks/Malwareman007/CVE-2022-30206.svg)


## CVE-2021-42013
 It was found that the fix for CVE-2021-41773 in Apache HTTP Server 2.4.50 was insufficient. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue only affects Apache 2.4.49 and Apache 2.4.50 and not earlier versions.

- [https://github.com/sne4ker/apache-CVE-2021-41773-CVE-2021-42013](https://github.com/sne4ker/apache-CVE-2021-41773-CVE-2021-42013) :  ![starts](https://img.shields.io/github/stars/sne4ker/apache-CVE-2021-41773-CVE-2021-42013.svg) ![forks](https://img.shields.io/github/forks/sne4ker/apache-CVE-2021-41773-CVE-2021-42013.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/hab1b0x/CVE-2021-41773](https://github.com/hab1b0x/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/hab1b0x/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/hab1b0x/CVE-2021-41773.svg)


## CVE-2021-20038
 A Stack-based buffer overflow vulnerability in SMA100 Apache httpd server's mod_cgi module environment variables allows a remote unauthenticated attacker to potentially execute code as a 'nobody' user in the appliance. This vulnerability affected SMA 200, 210, 400, 410 and 500v appliances firmware 10.2.0.8-37sv, 10.2.1.1-19sv, 10.2.1.2-24sv and earlier versions.

- [https://github.com/MaX0dexpoit/CVE-2021-20038](https://github.com/MaX0dexpoit/CVE-2021-20038) :  ![starts](https://img.shields.io/github/stars/MaX0dexpoit/CVE-2021-20038.svg) ![forks](https://img.shields.io/github/forks/MaX0dexpoit/CVE-2021-20038.svg)


## CVE-2021-3493
 The overlayfs implementation in the linux kernel did not properly validate with respect to user namespaces the setting of file capabilities on files in an underlying file system. Due to the combination of unprivileged user namespaces along with a patch carried in the Ubuntu kernel to allow unprivileged overlay mounts, an attacker could use this to gain elevated privileges.

- [https://github.com/Ishan3011/CVE-2021-3493](https://github.com/Ishan3011/CVE-2021-3493) :  ![starts](https://img.shields.io/github/stars/Ishan3011/CVE-2021-3493.svg) ![forks](https://img.shields.io/github/forks/Ishan3011/CVE-2021-3493.svg)

