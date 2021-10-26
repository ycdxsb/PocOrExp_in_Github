# Update 2021-10-26
## CVE-2021-42013
 It was found that the fix for CVE-2021-41773 in Apache HTTP Server 2.4.50 was insufficient. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue only affects Apache 2.4.49 and Apache 2.4.50 and not earlier versions.

- [https://github.com/TheLastVvV/CVE-2021-42013_Reverse-Shell](https://github.com/TheLastVvV/CVE-2021-42013_Reverse-Shell) :  ![starts](https://img.shields.io/github/stars/TheLastVvV/CVE-2021-42013_Reverse-Shell.svg) ![forks](https://img.shields.io/github/forks/TheLastVvV/CVE-2021-42013_Reverse-Shell.svg)
- [https://github.com/corelight/CVE-2021-41773](https://github.com/corelight/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/corelight/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/corelight/CVE-2021-41773.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/walnutsecurity/cve-2021-41773](https://github.com/walnutsecurity/cve-2021-41773) :  ![starts](https://img.shields.io/github/stars/walnutsecurity/cve-2021-41773.svg) ![forks](https://img.shields.io/github/forks/walnutsecurity/cve-2021-41773.svg)
- [https://github.com/corelight/CVE-2021-41773](https://github.com/corelight/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/corelight/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/corelight/CVE-2021-41773.svg)


## CVE-2021-40444
 Microsoft MSHTML Remote Code Execution Vulnerability

- [https://github.com/TiagoSergio/CVE-2021-40444](https://github.com/TiagoSergio/CVE-2021-40444) :  ![starts](https://img.shields.io/github/stars/TiagoSergio/CVE-2021-40444.svg) ![forks](https://img.shields.io/github/forks/TiagoSergio/CVE-2021-40444.svg)


## CVE-2021-40438
 A crafted request uri-path can cause mod_proxy to forward the request to an origin server choosen by the remote user. This issue affects Apache HTTP Server 2.4.48 and earlier.

- [https://github.com/sixpacksecurity/CVE-2021-40438](https://github.com/sixpacksecurity/CVE-2021-40438) :  ![starts](https://img.shields.io/github/stars/sixpacksecurity/CVE-2021-40438.svg) ![forks](https://img.shields.io/github/forks/sixpacksecurity/CVE-2021-40438.svg)


## CVE-2021-26084
 In affected versions of Confluence Server and Data Center, an OGNL injection vulnerability exists that would allow an unauthenticated attacker to execute arbitrary code on a Confluence Server or Data Center instance. The affected versions are before version 6.13.23, from version 6.14.0 before 7.4.11, from version 7.5.0 before 7.11.6, and from version 7.12.0 before 7.12.5.

- [https://github.com/Jun-5heng/CVE-2021-26084](https://github.com/Jun-5heng/CVE-2021-26084) :  ![starts](https://img.shields.io/github/stars/Jun-5heng/CVE-2021-26084.svg) ![forks](https://img.shields.io/github/forks/Jun-5heng/CVE-2021-26084.svg)


## CVE-2021-22005
 The vCenter Server contains an arbitrary file upload vulnerability in the Analytics service. A malicious actor with network access to port 443 on vCenter Server may exploit this issue to execute code on vCenter Server by uploading a specially crafted file.

- [https://github.com/TiagoSergio/CVE-2021-22005](https://github.com/TiagoSergio/CVE-2021-22005) :  ![starts](https://img.shields.io/github/stars/TiagoSergio/CVE-2021-22005.svg) ![forks](https://img.shields.io/github/forks/TiagoSergio/CVE-2021-22005.svg)


## CVE-2019-11447
 An issue was discovered in CutePHP CuteNews 2.1.2. An attacker can infiltrate the server through the avatar upload process in the profile area via the avatar_file field to index.php?mod=main&amp;opt=personal. There is no effective control of $imgsize in /core/modules/dashboard.php. The header content of a file can be changed and the control can be bypassed for code execution. (An attacker can use the GIF header for this.)

- [https://github.com/iainr/CuteNewsRCE](https://github.com/iainr/CuteNewsRCE) :  ![starts](https://img.shields.io/github/stars/iainr/CuteNewsRCE.svg) ![forks](https://img.shields.io/github/forks/iainr/CuteNewsRCE.svg)


## CVE-2019-5736
 runc through 1.0-rc6, as used in Docker before 18.09.2 and other products, allows attackers to overwrite the host runc binary (and consequently obtain host root access) by leveraging the ability to execute a command as root within one of these types of containers: (1) a new container with an attacker-controlled image, or (2) an existing container, to which the attacker previously had write access, that can be attached with docker exec. This occurs because of file-descriptor mishandling, related to /proc/self/exe.

- [https://github.com/fahmifj/Docker-breakout-runc](https://github.com/fahmifj/Docker-breakout-runc) :  ![starts](https://img.shields.io/github/stars/fahmifj/Docker-breakout-runc.svg) ![forks](https://img.shields.io/github/forks/fahmifj/Docker-breakout-runc.svg)


## CVE-2014-9390
 Git before 1.8.5.6, 1.9.x before 1.9.5, 2.0.x before 2.0.5, 2.1.x before 2.1.4, and 2.2.x before 2.2.1 on Windows and OS X; Mercurial before 3.2.3 on Windows and OS X; Apple Xcode before 6.2 beta 3; mine all versions before 08-12-2014; libgit2 all versions up to 0.21.2; Egit all versions before 08-12-2014; and JGit all versions before 08-12-2014 allow remote Git servers to execute arbitrary commands via a tree containing a crafted .git/config file with (1) an ignorable Unicode codepoint, (2) a git~1/config representation, or (3) mixed case that is improperly handled on a case-insensitive filesystem.

- [https://github.com/mdisec/CVE-2014-9390](https://github.com/mdisec/CVE-2014-9390) :  ![starts](https://img.shields.io/github/stars/mdisec/CVE-2014-9390.svg) ![forks](https://img.shields.io/github/forks/mdisec/CVE-2014-9390.svg)


## CVE-2014-6271
 GNU Bash through 4.3 processes trailing strings after function definitions in the values of environment variables, which allows remote attackers to execute arbitrary code via a crafted environment, as demonstrated by vectors involving the ForceCommand feature in OpenSSH sshd, the mod_cgi and mod_cgid modules in the Apache HTTP Server, scripts executed by unspecified DHCP clients, and other situations in which setting the environment occurs across a privilege boundary from Bash execution, aka &quot;ShellShock.&quot;  NOTE: the original fix for this issue was incorrect; CVE-2014-7169 has been assigned to cover the vulnerability that is still present after the incorrect fix.

- [https://github.com/alexphiliotis/ShellShock](https://github.com/alexphiliotis/ShellShock) :  ![starts](https://img.shields.io/github/stars/alexphiliotis/ShellShock.svg) ![forks](https://img.shields.io/github/forks/alexphiliotis/ShellShock.svg)


## CVE-2000-0649
 IIS 4.0 allows remote attackers to obtain the internal IP address of the server via an HTTP 1.0 request for a web page which is protected by basic authentication and has no realm defined.

- [https://github.com/stevenvegar/cve-2000-0649](https://github.com/stevenvegar/cve-2000-0649) :  ![starts](https://img.shields.io/github/stars/stevenvegar/cve-2000-0649.svg) ![forks](https://img.shields.io/github/forks/stevenvegar/cve-2000-0649.svg)

