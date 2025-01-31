# Update 2025-01-31
## CVE-2025-24085
 A use after free issue was addressed with improved memory management. This issue is fixed in visionOS 2.3, iOS 18.3 and iPadOS 18.3, macOS Sequoia 15.3, watchOS 11.3, tvOS 18.3. A malicious application may be able to elevate privileges. Apple is aware of a report that this issue may have been actively exploited against versions of iOS before iOS 17.2.

- [https://github.com/clidancc1/CVE-2025-24085](https://github.com/clidancc1/CVE-2025-24085) :  ![starts](https://img.shields.io/github/stars/clidancc1/CVE-2025-24085.svg) ![forks](https://img.shields.io/github/forks/clidancc1/CVE-2025-24085.svg)


## CVE-2024-55591
 An Authentication Bypass Using an Alternate Path or Channel vulnerability [CWE-288] affecting FortiOS version 7.0.0 through 7.0.16 and FortiProxy version 7.0.0 through 7.0.19 and 7.2.0 through 7.2.12 allows a remote attacker to gain super-admin privileges via crafted requests to Node.js websocket module.

- [https://github.com/rawtips/CVE-2024-55591](https://github.com/rawtips/CVE-2024-55591) :  ![starts](https://img.shields.io/github/stars/rawtips/CVE-2024-55591.svg) ![forks](https://img.shields.io/github/forks/rawtips/CVE-2024-55591.svg)
- [https://github.com/exfil0/CVE-2024-55591-POC](https://github.com/exfil0/CVE-2024-55591-POC) :  ![starts](https://img.shields.io/github/stars/exfil0/CVE-2024-55591-POC.svg) ![forks](https://img.shields.io/github/forks/exfil0/CVE-2024-55591-POC.svg)


## CVE-2024-23733
 The /WmAdmin/,/invoke/vm.server/login login page in the Integration Server in Software AG webMethods 10.15.0 before Core_Fix7 allows remote attackers to reach the administration panel and discover hostname and version information by sending an arbitrary username and a blank password to the /WmAdmin/#/login/ URI.

- [https://github.com/ekcrsm/CVE-2024-23733](https://github.com/ekcrsm/CVE-2024-23733) :  ![starts](https://img.shields.io/github/stars/ekcrsm/CVE-2024-23733.svg) ![forks](https://img.shields.io/github/forks/ekcrsm/CVE-2024-23733.svg)


## CVE-2024-12084
 A heap-based buffer overflow flaw was found in the rsync daemon. This issue is due to improper handling of attacker-controlled checksum lengths (s2length) in the code. When MAX_DIGEST_LEN exceeds the fixed SUM_LENGTH (16 bytes), an attacker can write out of bounds in the sum2 buffer.

- [https://github.com/rxerium/CVE-2024-12084](https://github.com/rxerium/CVE-2024-12084) :  ![starts](https://img.shields.io/github/stars/rxerium/CVE-2024-12084.svg) ![forks](https://img.shields.io/github/forks/rxerium/CVE-2024-12084.svg)


## CVE-2024-11972
 The Hunk Companion WordPress plugin before 1.9.0 does not correctly authorize some REST API endpoints, allowing unauthenticated requests to install and activate arbitrary Hunk Companion WordPress plugin before 1.9.0 from the WordPress.org repo, including vulnerable Hunk Companion WordPress plugin before 1.9.0 that have been closed.

- [https://github.com/Nxploited/CVE-2024-11972-PoC](https://github.com/Nxploited/CVE-2024-11972-PoC) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2024-11972-PoC.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2024-11972-PoC.svg)


## CVE-2024-5361
 A vulnerability was found in PHPGurukul Zoo Management System 2.1. It has been rated as critical. This issue affects some unknown processing of the file /admin/normal-bwdates-reports-details.php. The manipulation of the argument fromdate leads to sql injection. The attack may be initiated remotely. The exploit has been disclosed to the public and may be used. The identifier VDB-266273 was assigned to this vulnerability.

- [https://github.com/beune/CVE-2024-53615](https://github.com/beune/CVE-2024-53615) :  ![starts](https://img.shields.io/github/stars/beune/CVE-2024-53615.svg) ![forks](https://img.shields.io/github/forks/beune/CVE-2024-53615.svg)


## CVE-2024-2961
 The iconv() function in the GNU C Library versions 2.39 and older may overflow the output buffer passed to it by up to 4 bytes when converting strings to the ISO-2022-CN-EXT character set, which may be used to crash an application or overwrite a neighbouring variable.

- [https://github.com/4wayhandshake/CVE-2024-2961](https://github.com/4wayhandshake/CVE-2024-2961) :  ![starts](https://img.shields.io/github/stars/4wayhandshake/CVE-2024-2961.svg) ![forks](https://img.shields.io/github/forks/4wayhandshake/CVE-2024-2961.svg)


## CVE-2021-42013
 It was found that the fix for CVE-2021-41773 in Apache HTTP Server 2.4.50 was insufficient. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue only affects Apache 2.4.49 and Apache 2.4.50 and not earlier versions.

- [https://github.com/asepsaepdin/cve-2021-42013](https://github.com/asepsaepdin/cve-2021-42013) :  ![starts](https://img.shields.io/github/stars/asepsaepdin/cve-2021-42013.svg) ![forks](https://img.shields.io/github/forks/asepsaepdin/cve-2021-42013.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/Plunder283/CVE-2021-41773](https://github.com/Plunder283/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/Plunder283/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/Plunder283/CVE-2021-41773.svg)


## CVE-2020-0796
 A remote code execution vulnerability exists in the way that the Microsoft Server Message Block 3.1.1 (SMBv3) protocol handles certain requests, aka 'Windows SMBv3 Client/Server Remote Code Execution Vulnerability'.

- [https://github.com/Kaizzzo1/CVE-2020-0796](https://github.com/Kaizzzo1/CVE-2020-0796) :  ![starts](https://img.shields.io/github/stars/Kaizzzo1/CVE-2020-0796.svg) ![forks](https://img.shields.io/github/forks/Kaizzzo1/CVE-2020-0796.svg)


## CVE-2020-0079
 In decrypt_1_2 of CryptoPlugin.cpp, there is a possible out of bounds write due to stale pointer. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-9 Android-10Android ID: A-144506242

- [https://github.com/Kaizzzo1/cve-2020-00796](https://github.com/Kaizzzo1/cve-2020-00796) :  ![starts](https://img.shields.io/github/stars/Kaizzzo1/cve-2020-00796.svg) ![forks](https://img.shields.io/github/forks/Kaizzzo1/cve-2020-00796.svg)

