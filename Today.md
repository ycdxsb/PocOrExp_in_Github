# Update 2023-05-18
## CVE-2023-32233
 In the Linux kernel through 6.3.1, a use-after-free in Netfilter nf_tables when processing batch requests can be abused to perform arbitrary read and write operations on kernel memory. Unprivileged local users can obtain root privileges. This occurs because anonymous sets are mishandled.

- [https://github.com/oferchen/POC-CVE-2023-32233](https://github.com/oferchen/POC-CVE-2023-32233) :  ![starts](https://img.shields.io/github/stars/oferchen/POC-CVE-2023-32233.svg) ![forks](https://img.shields.io/github/forks/oferchen/POC-CVE-2023-32233.svg)


## CVE-2023-31070
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/bugprove/cve-2023-31070](https://github.com/bugprove/cve-2023-31070) :  ![starts](https://img.shields.io/github/stars/bugprove/cve-2023-31070.svg) ![forks](https://img.shields.io/github/forks/bugprove/cve-2023-31070.svg)


## CVE-2023-0386
 A flaw was found in the Linux kernel, where unauthorized access to the execution of the setuid file with capabilities was found in the Linux kernel&#8217;s OverlayFS subsystem in how a user copies a capable file from a nosuid mount into another mount. This uid mapping bug allows a local user to escalate their privileges on the system.

- [https://github.com/sxlmnwb/CVE-2023-0386](https://github.com/sxlmnwb/CVE-2023-0386) :  ![starts](https://img.shields.io/github/stars/sxlmnwb/CVE-2023-0386.svg) ![forks](https://img.shields.io/github/forks/sxlmnwb/CVE-2023-0386.svg)


## CVE-2022-36944
 Scala 2.13.x before 2.13.9 has a Java deserialization chain in its JAR file. On its own, it cannot be exploited. There is only a risk in conjunction with Java object deserialization within an application. In such situations, it allows attackers to erase contents of arbitrary files, make network connections, or possibly run arbitrary code (specifically, Function0 functions) via a gadget chain.

- [https://github.com/yarocher/lazylist-cve-poc](https://github.com/yarocher/lazylist-cve-poc) :  ![starts](https://img.shields.io/github/stars/yarocher/lazylist-cve-poc.svg) ![forks](https://img.shields.io/github/forks/yarocher/lazylist-cve-poc.svg)


## CVE-2022-3368
 A vulnerability within the Software Updater functionality of Avira Security for Windows allowed an attacker with write access to the filesystem, to escalate his privileges in certain scenarios. The issue was fixed with Avira Security version 1.1.72.30556.

- [https://github.com/Wh04m1001/CVE-2022-3368](https://github.com/Wh04m1001/CVE-2022-3368) :  ![starts](https://img.shields.io/github/stars/Wh04m1001/CVE-2022-3368.svg) ![forks](https://img.shields.io/github/forks/Wh04m1001/CVE-2022-3368.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/K3ysTr0K3R/CVE-2021-41773-EXPLOIT](https://github.com/K3ysTr0K3R/CVE-2021-41773-EXPLOIT) :  ![starts](https://img.shields.io/github/stars/K3ysTr0K3R/CVE-2021-41773-EXPLOIT.svg) ![forks](https://img.shields.io/github/forks/K3ysTr0K3R/CVE-2021-41773-EXPLOIT.svg)
- [https://github.com/shiomiyan/CVE-2021-41773](https://github.com/shiomiyan/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/shiomiyan/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/shiomiyan/CVE-2021-41773.svg)
- [https://github.com/Plunder283/CVE-2021-41773](https://github.com/Plunder283/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/Plunder283/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/Plunder283/CVE-2021-41773.svg)
- [https://github.com/puckiestyle/CVE-2021-41773](https://github.com/puckiestyle/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/puckiestyle/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/puckiestyle/CVE-2021-41773.svg)
- [https://github.com/wolf1892/CVE-2021-41773](https://github.com/wolf1892/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/wolf1892/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/wolf1892/CVE-2021-41773.svg)
- [https://github.com/honypot/CVE-2021-41773](https://github.com/honypot/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/honypot/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/honypot/CVE-2021-41773.svg)
- [https://github.com/mightysai1997/cve-2021-41773](https://github.com/mightysai1997/cve-2021-41773) :  ![starts](https://img.shields.io/github/stars/mightysai1997/cve-2021-41773.svg) ![forks](https://img.shields.io/github/forks/mightysai1997/cve-2021-41773.svg)


## CVE-2018-8120
 An elevation of privilege vulnerability exists in Windows when the Win32k component fails to properly handle objects in memory, aka &quot;Win32k Elevation of Privilege Vulnerability.&quot; This affects Windows Server 2008, Windows 7, Windows Server 2008 R2. This CVE ID is unique from CVE-2018-8124, CVE-2018-8164, CVE-2018-8166.

- [https://github.com/ozkanbilge/CVE-2018-8120](https://github.com/ozkanbilge/CVE-2018-8120) :  ![starts](https://img.shields.io/github/stars/ozkanbilge/CVE-2018-8120.svg) ![forks](https://img.shields.io/github/forks/ozkanbilge/CVE-2018-8120.svg)


## CVE-2017-9248
 Telerik.Web.UI.dll in Progress Telerik UI for ASP.NET AJAX before R2 2017 SP1 and Sitefinity before 10.0.6412.0 does not properly protect Telerik.Web.UI.DialogParametersEncryptionKey or the MachineKey, which makes it easier for remote attackers to defeat cryptographic protection mechanisms, leading to a MachineKey leak, arbitrary file uploads or downloads, XSS, or ASP.NET ViewState compromise.

- [https://github.com/ZhenwarX/Telerik-CVE-2017-9248-PoC](https://github.com/ZhenwarX/Telerik-CVE-2017-9248-PoC) :  ![starts](https://img.shields.io/github/stars/ZhenwarX/Telerik-CVE-2017-9248-PoC.svg) ![forks](https://img.shields.io/github/forks/ZhenwarX/Telerik-CVE-2017-9248-PoC.svg)


## CVE-1999-0001
 ip_input.c in BSD-derived TCP/IP implementations allows remote attackers to cause a denial of service (crash or hang) via crafted packets.

- [https://github.com/MarcusGutierrez/complex-vulnerabilities](https://github.com/MarcusGutierrez/complex-vulnerabilities) :  ![starts](https://img.shields.io/github/stars/MarcusGutierrez/complex-vulnerabilities.svg) ![forks](https://img.shields.io/github/forks/MarcusGutierrez/complex-vulnerabilities.svg)

