# Update 2021-10-17
## CVE-2021-42071
 In Visual Tools DVR VX16 4.2.28.0, an unauthenticated attacker can achieve remote command execution via shell metacharacters in the cgi-bin/slogin/login.py User-Agent HTTP header.

- [https://github.com/adubaldo/CVE-2021-42071](https://github.com/adubaldo/CVE-2021-42071) :  ![starts](https://img.shields.io/github/stars/adubaldo/CVE-2021-42071.svg) ![forks](https://img.shields.io/github/forks/adubaldo/CVE-2021-42071.svg)


## CVE-2021-42013
 It was found that the fix for CVE-2021-41773 in Apache HTTP Server 2.4.50 was insufficient. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue only affects Apache 2.4.49 and Apache 2.4.50 and not earlier versions.

- [https://github.com/theLSA/apache-httpd-path-traversal-checker](https://github.com/theLSA/apache-httpd-path-traversal-checker) :  ![starts](https://img.shields.io/github/stars/theLSA/apache-httpd-path-traversal-checker.svg) ![forks](https://img.shields.io/github/forks/theLSA/apache-httpd-path-traversal-checker.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/theLSA/apache-httpd-path-traversal-checker](https://github.com/theLSA/apache-httpd-path-traversal-checker) :  ![starts](https://img.shields.io/github/stars/theLSA/apache-httpd-path-traversal-checker.svg) ![forks](https://img.shields.io/github/forks/theLSA/apache-httpd-path-traversal-checker.svg)
- [https://github.com/anonsecteaminc/CVE-2021-41773-PoC](https://github.com/anonsecteaminc/CVE-2021-41773-PoC) :  ![starts](https://img.shields.io/github/stars/anonsecteaminc/CVE-2021-41773-PoC.svg) ![forks](https://img.shields.io/github/forks/anonsecteaminc/CVE-2021-41773-PoC.svg)
- [https://github.com/shiomiyan/CVE-2021-41773](https://github.com/shiomiyan/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/shiomiyan/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/shiomiyan/CVE-2021-41773.svg)
- [https://github.com/LudovicPatho/CVE-2021-41773](https://github.com/LudovicPatho/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/LudovicPatho/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/LudovicPatho/CVE-2021-41773.svg)


## CVE-2021-22555
 A heap out-of-bounds write affecting Linux since v2.6.19-rc1 was discovered in net/netfilter/x_tables.c. This allows an attacker to gain privileges or cause a DoS (via heap memory corruption) through user name space

- [https://github.com/xyjl-ly/CVE-2021-22555-Exploit](https://github.com/xyjl-ly/CVE-2021-22555-Exploit) :  ![starts](https://img.shields.io/github/stars/xyjl-ly/CVE-2021-22555-Exploit.svg) ![forks](https://img.shields.io/github/forks/xyjl-ly/CVE-2021-22555-Exploit.svg)


## CVE-2020-25078
 An issue was discovered on D-Link DCS-2530L before 1.06.01 Hotfix and DCS-2670L through 2.02 devices. The unauthenticated /config/getuser endpoint allows for remote administrator password disclosure.

- [https://github.com/chinaYozz/CVE-2020-25078](https://github.com/chinaYozz/CVE-2020-25078) :  ![starts](https://img.shields.io/github/stars/chinaYozz/CVE-2020-25078.svg) ![forks](https://img.shields.io/github/forks/chinaYozz/CVE-2020-25078.svg)


## CVE-2020-11023
 In jQuery versions greater than or equal to 1.0.3 and before 3.5.0, passing HTML containing &lt;option&gt; elements from untrusted sources - even after sanitizing it - to one of jQuery's DOM manipulation methods (i.e. .html(), .append(), and others) may execute untrusted code. This problem is patched in jQuery 3.5.0.

- [https://github.com/0xAJ2K/CVE-2020-11022-CVE-2020-11023](https://github.com/0xAJ2K/CVE-2020-11022-CVE-2020-11023) :  ![starts](https://img.shields.io/github/stars/0xAJ2K/CVE-2020-11022-CVE-2020-11023.svg) ![forks](https://img.shields.io/github/forks/0xAJ2K/CVE-2020-11022-CVE-2020-11023.svg)


## CVE-2020-11022
 In jQuery versions greater than or equal to 1.2 and before 3.5.0, passing HTML from untrusted sources - even after sanitizing it - to one of jQuery's DOM manipulation methods (i.e. .html(), .append(), and others) may execute untrusted code. This problem is patched in jQuery 3.5.0.

- [https://github.com/0xAJ2K/CVE-2020-11022-CVE-2020-11023](https://github.com/0xAJ2K/CVE-2020-11022-CVE-2020-11023) :  ![starts](https://img.shields.io/github/stars/0xAJ2K/CVE-2020-11022-CVE-2020-11023.svg) ![forks](https://img.shields.io/github/forks/0xAJ2K/CVE-2020-11022-CVE-2020-11023.svg)


## CVE-2020-5902
 In BIG-IP versions 15.0.0-15.1.0.3, 14.1.0-14.1.2.5, 13.1.0-13.1.3.3, 12.1.0-12.1.5.1, and 11.6.1-11.6.5.1, the Traffic Management User Interface (TMUI), also referred to as the Configuration utility, has a Remote Code Execution (RCE) vulnerability in undisclosed pages.

- [https://github.com/anonsecteaminc/CVE-2020-5902-Scanner](https://github.com/anonsecteaminc/CVE-2020-5902-Scanner) :  ![starts](https://img.shields.io/github/stars/anonsecteaminc/CVE-2020-5902-Scanner.svg) ![forks](https://img.shields.io/github/forks/anonsecteaminc/CVE-2020-5902-Scanner.svg)


## CVE-2020-3153
 A vulnerability in the installer component of Cisco AnyConnect Secure Mobility Client for Windows could allow an authenticated local attacker to copy user-supplied files to system level directories with system level privileges. The vulnerability is due to the incorrect handling of directory paths. An attacker could exploit this vulnerability by creating a malicious file and copying the file to a system directory. An exploit could allow the attacker to copy malicious files to arbitrary locations with system level privileges. This could include DLL pre-loading, DLL hijacking, and other related attacks. To exploit this vulnerability, the attacker needs valid credentials on the Windows system.

- [https://github.com/goichot/CVE-2020-3153](https://github.com/goichot/CVE-2020-3153) :  ![starts](https://img.shields.io/github/stars/goichot/CVE-2020-3153.svg) ![forks](https://img.shields.io/github/forks/goichot/CVE-2020-3153.svg)


## CVE-2020-0609
 A remote code execution vulnerability exists in Windows Remote Desktop Gateway (RD Gateway) when an unauthenticated attacker connects to the target system using RDP and sends specially crafted requests, aka 'Windows Remote Desktop Gateway (RD Gateway) Remote Code Execution Vulnerability'. This CVE ID is unique from CVE-2020-0610.

- [https://github.com/ruppde/rdg_scanner_cve-2020-0609](https://github.com/ruppde/rdg_scanner_cve-2020-0609) :  ![starts](https://img.shields.io/github/stars/ruppde/rdg_scanner_cve-2020-0609.svg) ![forks](https://img.shields.io/github/forks/ruppde/rdg_scanner_cve-2020-0609.svg)


## CVE-2020-0041
 In binder_transaction of binder.c, there is a possible out of bounds write due to an incorrect bounds check. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-145988638References: Upstream kernel

- [https://github.com/koharin/CVE-2020-0041](https://github.com/koharin/CVE-2020-0041) :  ![starts](https://img.shields.io/github/stars/koharin/CVE-2020-0041.svg) ![forks](https://img.shields.io/github/forks/koharin/CVE-2020-0041.svg)


## CVE-2019-11447
 An issue was discovered in CutePHP CuteNews 2.1.2. An attacker can infiltrate the server through the avatar upload process in the profile area via the avatar_file field to index.php?mod=main&amp;opt=personal. There is no effective control of $imgsize in /core/modules/dashboard.php. The header content of a file can be changed and the control can be bypassed for code execution. (An attacker can use the GIF header for this.)

- [https://github.com/iainr/CuteNewsRCE](https://github.com/iainr/CuteNewsRCE) :  ![starts](https://img.shields.io/github/stars/iainr/CuteNewsRCE.svg) ![forks](https://img.shields.io/github/forks/iainr/CuteNewsRCE.svg)


## CVE-2017-15950
 Flexense SyncBreeze Enterprise version 10.1.16 is vulnerable to a buffer overflow that can be exploited for arbitrary code execution. The flaw is triggered by providing a long input into the &quot;Destination directory&quot; field, either within an XML document or through use of passive mode.

- [https://github.com/rnnsz/CVE-2017-15950](https://github.com/rnnsz/CVE-2017-15950) :  ![starts](https://img.shields.io/github/stars/rnnsz/CVE-2017-15950.svg) ![forks](https://img.shields.io/github/forks/rnnsz/CVE-2017-15950.svg)

