# Update 2021-10-23
## CVE-2021-42013
 It was found that the fix for CVE-2021-41773 in Apache HTTP Server 2.4.50 was insufficient. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue only affects Apache 2.4.49 and Apache 2.4.50 and not earlier versions.

- [https://github.com/LayarKacaSiber/CVE-2021-42013](https://github.com/LayarKacaSiber/CVE-2021-42013) :  ![starts](https://img.shields.io/github/stars/LayarKacaSiber/CVE-2021-42013.svg) ![forks](https://img.shields.io/github/forks/LayarKacaSiber/CVE-2021-42013.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/LayarKacaSiber/CVE-2021-41773](https://github.com/LayarKacaSiber/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/LayarKacaSiber/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/LayarKacaSiber/CVE-2021-41773.svg)


## CVE-2021-30858
 A use after free issue was addressed with improved memory management. This issue is fixed in iOS 14.8 and iPadOS 14.8, macOS Big Sur 11.6. Processing maliciously crafted web content may lead to arbitrary code execution. Apple is aware of a report that this issue may have been actively exploited.

- [https://github.com/Jeromeyoung/ps4_8.00_vuln_poc](https://github.com/Jeromeyoung/ps4_8.00_vuln_poc) :  ![starts](https://img.shields.io/github/stars/Jeromeyoung/ps4_8.00_vuln_poc.svg) ![forks](https://img.shields.io/github/forks/Jeromeyoung/ps4_8.00_vuln_poc.svg)


## CVE-2021-30632
 Out of bounds write in V8 in Google Chrome prior to 93.0.4577.82 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

- [https://github.com/CrackerCat/CVE-2021-30632](https://github.com/CrackerCat/CVE-2021-30632) :  ![starts](https://img.shields.io/github/stars/CrackerCat/CVE-2021-30632.svg) ![forks](https://img.shields.io/github/forks/CrackerCat/CVE-2021-30632.svg)


## CVE-2021-3156
 Sudo before 1.9.5p2 contains an off-by-one error that can result in a heap-based buffer overflow, which allows privilege escalation to root via &quot;sudoedit -s&quot; and a command-line argument that ends with a single backslash character.

- [https://github.com/Exodusro/CVE-2021-3156](https://github.com/Exodusro/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/Exodusro/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/Exodusro/CVE-2021-3156.svg)


## CVE-2021-3129
 Ignition before 2.5.2, as used in Laravel and other products, allows unauthenticated remote attackers to execute arbitrary code because of insecure usage of file_get_contents() and file_put_contents(). This is exploitable on sites using debug mode with Laravel before 8.4.2.

- [https://github.com/nth347/CVE-2021-3129_exploit](https://github.com/nth347/CVE-2021-3129_exploit) :  ![starts](https://img.shields.io/github/stars/nth347/CVE-2021-3129_exploit.svg) ![forks](https://img.shields.io/github/forks/nth347/CVE-2021-3129_exploit.svg)


## CVE-2020-35488
 The fileop module of the NXLog service in NXLog Community Edition 2.10.2150 allows remote attackers to cause a denial of service (daemon crash) via a crafted Syslog payload to the Syslog service. This attack requires a specific configuration. Also, the name of the directory created must use a Syslog field. (For example, on Linux it is not possible to create a .. directory. On Windows, it is not possible to create a CON directory.)

- [https://github.com/githubfoam/nxlog-ubuntu-githubactions](https://github.com/githubfoam/nxlog-ubuntu-githubactions) :  ![starts](https://img.shields.io/github/stars/githubfoam/nxlog-ubuntu-githubactions.svg) ![forks](https://img.shields.io/github/forks/githubfoam/nxlog-ubuntu-githubactions.svg)


## CVE-2020-2555
 Vulnerability in the Oracle Coherence product of Oracle Fusion Middleware (component: Caching,CacheStore,Invocation). Supported versions that are affected are 3.7.1.0, 12.1.3.0.0, 12.2.1.3.0 and 12.2.1.4.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3 to compromise Oracle Coherence. Successful attacks of this vulnerability can result in takeover of Oracle Coherence. CVSS 3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/gobysec/GobyVuls](https://github.com/gobysec/GobyVuls) :  ![starts](https://img.shields.io/github/stars/gobysec/GobyVuls.svg) ![forks](https://img.shields.io/github/forks/gobysec/GobyVuls.svg)


## CVE-2019-5736
 runc through 1.0-rc6, as used in Docker before 18.09.2 and other products, allows attackers to overwrite the host runc binary (and consequently obtain host root access) by leveraging the ability to execute a command as root within one of these types of containers: (1) a new container with an attacker-controlled image, or (2) an existing container, to which the attacker previously had write access, that can be attached with docker exec. This occurs because of file-descriptor mishandling, related to /proc/self/exe.

- [https://github.com/geropl/CVE-2019-5736](https://github.com/geropl/CVE-2019-5736) :  ![starts](https://img.shields.io/github/stars/geropl/CVE-2019-5736.svg) ![forks](https://img.shields.io/github/forks/geropl/CVE-2019-5736.svg)


## CVE-2017-3241
 Vulnerability in the Java SE, Java SE Embedded, JRockit component of Oracle Java SE (subcomponent: RMI). Supported versions that are affected are Java SE: 6u131, 7u121 and 8u112; Java SE Embedded: 8u111; JRockit: R28.3.12. Difficult to exploit vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise Java SE, Java SE Embedded, JRockit. While the vulnerability is in Java SE, Java SE Embedded, JRockit, attacks may significantly impact additional products. Successful attacks of this vulnerability can result in takeover of Java SE, Java SE Embedded, JRockit. Note: This vulnerability can only be exploited by supplying data to APIs in the specified Component without using Untrusted Java Web Start applications or Untrusted Java applets, such as through a web service. CVSS v3.0 Base Score 9.0 (Confidentiality, Integrity and Availability impacts).

- [https://github.com/scopion/CVE-2017-3241](https://github.com/scopion/CVE-2017-3241) :  ![starts](https://img.shields.io/github/stars/scopion/CVE-2017-3241.svg) ![forks](https://img.shields.io/github/forks/scopion/CVE-2017-3241.svg)

