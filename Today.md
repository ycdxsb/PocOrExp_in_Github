# Update 2022-09-19
## CVE-2022-32548
 An issue was discovered on certain DrayTek Vigor routers before July 2022 such as the Vigor3910 before 4.3.1.1. /cgi-bin/wlogin.cgi has a buffer overflow via the username or password to the aa or ab field.

- [https://github.com/n0zxRY0/CVE-2022-32548-RCE](https://github.com/n0zxRY0/CVE-2022-32548-RCE) :  ![starts](https://img.shields.io/github/stars/n0zxRY0/CVE-2022-32548-RCE.svg) ![forks](https://img.shields.io/github/forks/n0zxRY0/CVE-2022-32548-RCE.svg)


## CVE-2022-29856
 A hardcoded cryptographic key in Automation360 22 allows an attacker to decrypt exported RPA packages.

- [https://github.com/Flo451/CVE-2022-29856-PoC](https://github.com/Flo451/CVE-2022-29856-PoC) :  ![starts](https://img.shields.io/github/stars/Flo451/CVE-2022-29856-PoC.svg) ![forks](https://img.shields.io/github/forks/Flo451/CVE-2022-29856-PoC.svg)


## CVE-2022-27925
 Zimbra Collaboration (aka ZCS) 8.8.15 and 9.0 has mboximport functionality that receives a ZIP archive and extracts files from it. An authenticated user with administrator rights has the ability to upload arbitrary files to the system, leading to directory traversal.

- [https://github.com/touchmycrazyredhat/CVE-2022-27925-Revshell](https://github.com/touchmycrazyredhat/CVE-2022-27925-Revshell) :  ![starts](https://img.shields.io/github/stars/touchmycrazyredhat/CVE-2022-27925-Revshell.svg) ![forks](https://img.shields.io/github/forks/touchmycrazyredhat/CVE-2022-27925-Revshell.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/hab1b0x/CVE-2021-41773](https://github.com/hab1b0x/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/hab1b0x/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/hab1b0x/CVE-2021-41773.svg)


## CVE-2021-39172
 Cachet is an open source status page system. Prior to version 2.5.1, authenticated users, regardless of their privileges (User or Admin), can exploit a new line injection in the configuration edition feature (e.g. mail settings) and gain arbitrary code execution on the server. This issue was addressed in version 2.5.1 by improving `UpdateConfigCommandHandler` and preventing the use of new lines characters in new configuration values. As a workaround, only allow trusted source IP addresses to access to the administration dashboard.

- [https://github.com/W1ngLess/CVE-2021-39172-RCE](https://github.com/W1ngLess/CVE-2021-39172-RCE) :  ![starts](https://img.shields.io/github/stars/W1ngLess/CVE-2021-39172-RCE.svg) ![forks](https://img.shields.io/github/forks/W1ngLess/CVE-2021-39172-RCE.svg)

