# Update 2023-04-19
## CVE-2023-21554
 Microsoft Message Queuing Remote Code Execution Vulnerability

- [https://github.com/C00k3rbkr/CVE-2023-21554-RCE](https://github.com/C00k3rbkr/CVE-2023-21554-RCE) :  ![starts](https://img.shields.io/github/stars/C00k3rbkr/CVE-2023-21554-RCE.svg) ![forks](https://img.shields.io/github/forks/C00k3rbkr/CVE-2023-21554-RCE.svg)


## CVE-2022-46689
 A race condition was addressed with additional validation. This issue is fixed in tvOS 16.2, macOS Monterey 12.6.2, macOS Ventura 13.1, macOS Big Sur 11.7.2, iOS 15.7.2 and iPadOS 15.7.2, iOS 16.2 and iPadOS 16.2, watchOS 9.2. An app may be able to execute arbitrary code with kernel privileges.

- [https://github.com/BomberFish/AbsoluteSolver-iOS](https://github.com/BomberFish/AbsoluteSolver-iOS) :  ![starts](https://img.shields.io/github/stars/BomberFish/AbsoluteSolver-iOS.svg) ![forks](https://img.shields.io/github/forks/BomberFish/AbsoluteSolver-iOS.svg)


## CVE-2022-34527
 D-Link DSL-3782 v1.03 and below was discovered to contain a command injection vulnerability via the function byte_4C0160.

- [https://github.com/FzBacon/CVE-2022-34527_D-Link_DSL-3782_Router_command_injection](https://github.com/FzBacon/CVE-2022-34527_D-Link_DSL-3782_Router_command_injection) :  ![starts](https://img.shields.io/github/stars/FzBacon/CVE-2022-34527_D-Link_DSL-3782_Router_command_injection.svg) ![forks](https://img.shields.io/github/forks/FzBacon/CVE-2022-34527_D-Link_DSL-3782_Router_command_injection.svg)


## CVE-2022-26627
 Online Project Time Management System v1.0 was discovered to contain an arbitrary file write vulnerability which allows attackers to execute arbitrary code via a crafted HTML file.

- [https://github.com/qerogram/BUG_WEB](https://github.com/qerogram/BUG_WEB) :  ![starts](https://img.shields.io/github/stars/qerogram/BUG_WEB.svg) ![forks](https://img.shields.io/github/forks/qerogram/BUG_WEB.svg)


## CVE-2022-22963
 In Spring Cloud Function versions 3.1.6, 3.2.2 and older unsupported versions, when using routing functionality it is possible for a user to provide a specially crafted SpEL as a routing-expression that may result in remote code execution and access to local resources.

- [https://github.com/randallbanner/Spring-Cloud-Function-Vulnerability-CVE-2022-22963-RCE](https://github.com/randallbanner/Spring-Cloud-Function-Vulnerability-CVE-2022-22963-RCE) :  ![starts](https://img.shields.io/github/stars/randallbanner/Spring-Cloud-Function-Vulnerability-CVE-2022-22963-RCE.svg) ![forks](https://img.shields.io/github/forks/randallbanner/Spring-Cloud-Function-Vulnerability-CVE-2022-22963-RCE.svg)


## CVE-2022-0687
 The Amelia WordPress plugin before 1.0.47 stores image blobs into actual files whose extension is controlled by the user, which may lead to PHP backdoors being uploaded onto the site. This vulnerability can be exploited by logged-in users with the custom &quot;Amelia Manager&quot; role.

- [https://github.com/qerogram/BUG_WEB](https://github.com/qerogram/BUG_WEB) :  ![starts](https://img.shields.io/github/stars/qerogram/BUG_WEB.svg) ![forks](https://img.shields.io/github/forks/qerogram/BUG_WEB.svg)


## CVE-2022-0537
 The MapPress Maps for WordPress plugin before 2.73.13 allows a high privileged user to bypass the DISALLOW_FILE_EDIT and DISALLOW_FILE_MODS settings and upload arbitrary files to the site through the &quot;ajax_save&quot; function. The file is written relative to the current 's stylesheet directory, and a .php file extension is added. No validation is performed on the content of the file, triggering an RCE vulnerability by uploading a web shell. Further the name parameter is not sanitized, allowing the payload to be uploaded to any directory to which the server has write access.

- [https://github.com/qerogram/BUG_WEB](https://github.com/qerogram/BUG_WEB) :  ![starts](https://img.shields.io/github/stars/qerogram/BUG_WEB.svg) ![forks](https://img.shields.io/github/forks/qerogram/BUG_WEB.svg)


## CVE-2022-0493
 The String locator WordPress plugin before 2.5.0 does not properly validate the path of the files to be searched, allowing high privilege users such as admin to query arbitrary files on the web server via a path traversal vector. Furthermore, due to a flaw in the search, allowing a pattern to be provided, which will be used to output the relevant matches from the matching file, all content of the file can be disclosed.

- [https://github.com/qerogram/BUG_WEB](https://github.com/qerogram/BUG_WEB) :  ![starts](https://img.shields.io/github/stars/qerogram/BUG_WEB.svg) ![forks](https://img.shields.io/github/forks/qerogram/BUG_WEB.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/shiomiyan/CVE-2021-41773](https://github.com/shiomiyan/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/shiomiyan/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/shiomiyan/CVE-2021-41773.svg)
- [https://github.com/Plunder283/CVE-2021-41773](https://github.com/Plunder283/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/Plunder283/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/Plunder283/CVE-2021-41773.svg)
- [https://github.com/puckiestyle/CVE-2021-41773](https://github.com/puckiestyle/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/puckiestyle/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/puckiestyle/CVE-2021-41773.svg)


## CVE-2021-3560
 It was found that polkit could be tricked into bypassing the credential checks for D-Bus requests, elevating the privileges of the requestor to the root user. This flaw could be used by an unprivileged local attacker to, for example, create a new local administrator. The highest threat from this vulnerability is to data confidentiality and integrity as well as system availability.

- [https://github.com/UNICORDev/exploit-CVE-2021-3560](https://github.com/UNICORDev/exploit-CVE-2021-3560) :  ![starts](https://img.shields.io/github/stars/UNICORDev/exploit-CVE-2021-3560.svg) ![forks](https://img.shields.io/github/forks/UNICORDev/exploit-CVE-2021-3560.svg)


## CVE-2020-2546
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Application Container - JavaEE). Supported versions that are affected are 10.3.6.0.0 and 12.1.3.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3 to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/hktalent/CVE_2020_2546](https://github.com/hktalent/CVE_2020_2546) :  ![starts](https://img.shields.io/github/stars/hktalent/CVE_2020_2546.svg) ![forks](https://img.shields.io/github/forks/hktalent/CVE_2020_2546.svg)


## CVE-2017-1000251
 The native Bluetooth stack in the Linux Kernel (BlueZ), starting at the Linux kernel version 2.6.32 and up to and including 4.13.1, are vulnerable to a stack overflow vulnerability in the processing of L2CAP configuration responses resulting in Remote code execution in kernel space.

- [https://github.com/CrackSoft900/Blue-Borne](https://github.com/CrackSoft900/Blue-Borne) :  ![starts](https://img.shields.io/github/stars/CrackSoft900/Blue-Borne.svg) ![forks](https://img.shields.io/github/forks/CrackSoft900/Blue-Borne.svg)


## CVE-2017-7529
 Nginx versions since 0.5.6 up to and including 1.13.2 are vulnerable to integer overflow vulnerability in nginx range filter module resulting into leak of potentially sensitive information triggered by specially crafted request.

- [https://github.com/ninjabuster/exploit-nginx-1.10.3](https://github.com/ninjabuster/exploit-nginx-1.10.3) :  ![starts](https://img.shields.io/github/stars/ninjabuster/exploit-nginx-1.10.3.svg) ![forks](https://img.shields.io/github/forks/ninjabuster/exploit-nginx-1.10.3.svg)
- [https://github.com/fardeen-ahmed/Remote-Integer-Overflow-Vulnerability](https://github.com/fardeen-ahmed/Remote-Integer-Overflow-Vulnerability) :  ![starts](https://img.shields.io/github/stars/fardeen-ahmed/Remote-Integer-Overflow-Vulnerability.svg) ![forks](https://img.shields.io/github/forks/fardeen-ahmed/Remote-Integer-Overflow-Vulnerability.svg)

