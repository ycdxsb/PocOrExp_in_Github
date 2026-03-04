# Update 2026-03-04
## CVE-2026-27179
 MajorDoMo (aka Major Domestic Module) contains an unauthenticated SQL injection vulnerability in the commands module. The commands_search.inc.php file directly interpolates the $_GET['parent'] parameter into multiple SQL queries without sanitization or parameterized queries. The commands module is loadable without authentication via the /objects/?module=commands endpoint, which includes arbitrary modules by name and calls their usual() method. Time-based blind SQL injection is exploitable using UNION SELECT SLEEP() syntax. Because MajorDoMo stores admin passwords as unsalted MD5 hashes in the users table, successful exploitation enables extraction of credentials and subsequent admin panel access.

- [https://github.com/p3Nt3st3r-sTAr/MajorDoMo-CVE-2026-27179](https://github.com/p3Nt3st3r-sTAr/MajorDoMo-CVE-2026-27179) :  ![starts](https://img.shields.io/github/stars/p3Nt3st3r-sTAr/MajorDoMo-CVE-2026-27179.svg) ![forks](https://img.shields.io/github/forks/p3Nt3st3r-sTAr/MajorDoMo-CVE-2026-27179.svg)


## CVE-2026-26720
 An issue in Twenty CRM v1.15.0 and before allows a remote attacker to execute arbitrary code via the local.driver.ts module.

- [https://github.com/dillonkirsch/CVE-2026-26720-Twenty-RCE](https://github.com/dillonkirsch/CVE-2026-26720-Twenty-RCE) :  ![starts](https://img.shields.io/github/stars/dillonkirsch/CVE-2026-26720-Twenty-RCE.svg) ![forks](https://img.shields.io/github/forks/dillonkirsch/CVE-2026-26720-Twenty-RCE.svg)


## CVE-2026-25940
 jsPDF is a library to generate PDFs in JavaScript. Prior to 4.2.0, user control of properties and methods of the Acroform module allows users to inject arbitrary PDF objects, such as JavaScript actions. If given the possibility to pass unsanitized input to one of the following property, a user can inject arbitrary PDF objects, such as JavaScript actions, which are executed when the victim hovers over the radio option. The vulnerability has been fixed in jsPDF@4.2.0. As a workaround, sanitize user input before passing it to the vulnerable API members.

- [https://github.com/dajneem23/CVE-2026-25940](https://github.com/dajneem23/CVE-2026-25940) :  ![starts](https://img.shields.io/github/stars/dajneem23/CVE-2026-25940.svg) ![forks](https://img.shields.io/github/forks/dajneem23/CVE-2026-25940.svg)


## CVE-2026-3395
 A flaw has been found in MaxSite CMS up to 109.1. This impacts the function eval of the file application/maxsite/admin/plugins/editor_markitup/preview-ajax.php of the component MarkItUp Preview AJAX Endpoint. Executing a manipulation can lead to code injection. It is possible to launch the attack remotely. The exploit has been published and may be used. Upgrading to version 109.2 will fix this issue. This patch is called 08937a3c5d672a242d68f53e9fccf8a748820ef3. You should upgrade the affected component. The code maintainer was informed beforehand about the issues. He reacted very fast and highly professional.

- [https://github.com/rootdirective-sec/CVE-2026-3395-Lab](https://github.com/rootdirective-sec/CVE-2026-3395-Lab) :  ![starts](https://img.shields.io/github/stars/rootdirective-sec/CVE-2026-3395-Lab.svg) ![forks](https://img.shields.io/github/forks/rootdirective-sec/CVE-2026-3395-Lab.svg)


## CVE-2026-2751
 Blind SQL Injection via unsanitized array keys in Service Dependencies deletion. Vulnerability in Centreon Centreon Web on Central Server on Linux (Service Dependencies modules) allows Blind SQL Injection.This issue affects Centreon Web on Central Server before 25.10.8, 24.10.20, 24.04.24.

- [https://github.com/hakaioffsec/Centreon-Exploits-2026](https://github.com/hakaioffsec/Centreon-Exploits-2026) :  ![starts](https://img.shields.io/github/stars/hakaioffsec/Centreon-Exploits-2026.svg) ![forks](https://img.shields.io/github/forks/hakaioffsec/Centreon-Exploits-2026.svg)


## CVE-2026-2750
 Improper Input Validation vulnerability in Centreon Centreon Open Tickets on Central Server on Linux (Centreon Open Tickets modules).This issue affects Centreon Open Tickets on Central Server: from all before 25.10; 24.10;24.04.

- [https://github.com/hakaioffsec/Centreon-Exploits-2026](https://github.com/hakaioffsec/Centreon-Exploits-2026) :  ![starts](https://img.shields.io/github/stars/hakaioffsec/Centreon-Exploits-2026.svg) ![forks](https://img.shields.io/github/forks/hakaioffsec/Centreon-Exploits-2026.svg)


## CVE-2026-2749
 Vulnerability in Centreon Centreon Open Tickets on Central Server on Linux (Centroen Open Ticket modules).This issue affects Centreon Open Tickets on Central Server: from all before 25.10.3, 24.10.8, 24.04.7.

- [https://github.com/hakaioffsec/Centreon-Exploits-2026](https://github.com/hakaioffsec/Centreon-Exploits-2026) :  ![starts](https://img.shields.io/github/stars/hakaioffsec/Centreon-Exploits-2026.svg) ![forks](https://img.shields.io/github/forks/hakaioffsec/Centreon-Exploits-2026.svg)


## CVE-2026-2256
 A command injection vulnerability in ModelScope's ms-agent versions v1.6.0rc1 and earlier exists, allowing an attacker to execute arbitrary operating system commands through crafted prompt-derived input.

- [https://github.com/Itamar-Yochpaz/CVE-2026-2256-PoC](https://github.com/Itamar-Yochpaz/CVE-2026-2256-PoC) :  ![starts](https://img.shields.io/github/stars/Itamar-Yochpaz/CVE-2026-2256-PoC.svg) ![forks](https://img.shields.io/github/forks/Itamar-Yochpaz/CVE-2026-2256-PoC.svg)


## CVE-2026-0006
 In multiple locations, there is a possible out of bounds read and write due to a heap buffer overflow. This could lead to remote code execution with no additional execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/aydin5245/cve-2026-0006](https://github.com/aydin5245/cve-2026-0006) :  ![starts](https://img.shields.io/github/stars/aydin5245/cve-2026-0006.svg) ![forks](https://img.shields.io/github/forks/aydin5245/cve-2026-0006.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-alias](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-alias) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-alias.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-alias.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-tilde](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-tilde) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-tilde.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-tilde.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-zero-installs](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-zero-installs) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-zero-installs.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-zero-installs.svg)


## CVE-2025-64446
 A relative path traversal vulnerability in Fortinet FortiWeb 8.0.0 through 8.0.1, FortiWeb 7.6.0 through 7.6.4, FortiWeb 7.4.0 through 7.4.9, FortiWeb 7.2.0 through 7.2.11, FortiWeb 7.0.0 through 7.0.11 may allow an attacker to execute administrative commands on the system via crafted HTTP or HTTPS requests.

- [https://github.com/BaoSec/CVE-2025-64446-CVE-2025-58034-Research-and-Analysis](https://github.com/BaoSec/CVE-2025-64446-CVE-2025-58034-Research-and-Analysis) :  ![starts](https://img.shields.io/github/stars/BaoSec/CVE-2025-64446-CVE-2025-58034-Research-and-Analysis.svg) ![forks](https://img.shields.io/github/forks/BaoSec/CVE-2025-64446-CVE-2025-58034-Research-and-Analysis.svg)


## CVE-2025-62215
 Concurrent execution using shared resource with improper synchronization ('race condition') in Windows Kernel allows an authorized attacker to elevate privileges locally.

- [https://github.com/gowonisgood/CVE-2025-62215-POC](https://github.com/gowonisgood/CVE-2025-62215-POC) :  ![starts](https://img.shields.io/github/stars/gowonisgood/CVE-2025-62215-POC.svg) ![forks](https://img.shields.io/github/forks/gowonisgood/CVE-2025-62215-POC.svg)


## CVE-2025-58107
 In Microsoft Exchange through 2019, Exchange ActiveSync (EAS) configurations on on-premises servers may transmit sensitive data from Samsung mobile devices in cleartext, including the user's name, e-mail address, device ID, bearer token, and base64-encoded password.

- [https://github.com/geo-chen/microsoft](https://github.com/geo-chen/microsoft) :  ![starts](https://img.shields.io/github/stars/geo-chen/microsoft.svg) ![forks](https://img.shields.io/github/forks/geo-chen/microsoft.svg)


## CVE-2025-58034
 An Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') vulnerability [CWE-78] vulnerability in Fortinet FortiWeb 8.0.0 through 8.0.1, FortiWeb 7.6.0 through 7.6.5, FortiWeb 7.4.0 through 7.4.10, FortiWeb 7.2.0 through 7.2.11, FortiWeb 7.0.0 through 7.0.11 may allow an authenticated attacker to execute unauthorized code on the underlying system via crafted HTTP requests or CLI commands.

- [https://github.com/BaoSec/CVE-2025-64446-CVE-2025-58034-Research-and-Analysis](https://github.com/BaoSec/CVE-2025-64446-CVE-2025-58034-Research-and-Analysis) :  ![starts](https://img.shields.io/github/stars/BaoSec/CVE-2025-64446-CVE-2025-58034-Research-and-Analysis.svg) ![forks](https://img.shields.io/github/forks/BaoSec/CVE-2025-64446-CVE-2025-58034-Research-and-Analysis.svg)


## CVE-2025-52999
 jackson-core contains core low-level incremental ("streaming") parser and generator abstractions used by Jackson Data Processor. In versions prior to 2.15.0, if a user parses an input file and it has deeply nested data, Jackson could end up throwing a StackoverflowError if the depth is particularly large. jackson-core 2.15.0 contains a configurable limit for how deep Jackson will traverse in an input document, defaulting to an allowable depth of 1000. jackson-core will throw a StreamConstraintsException if the limit is reached. jackson-databind also benefits from this change because it uses jackson-core to parse JSON inputs. As a workaround, users should avoid parsing input files from untrusted sources.

- [https://github.com/sassoftware/jackson](https://github.com/sassoftware/jackson) :  ![starts](https://img.shields.io/github/stars/sassoftware/jackson.svg) ![forks](https://img.shields.io/github/forks/sassoftware/jackson.svg)


## CVE-2025-43529
 A use-after-free issue was addressed with improved memory management. This issue is fixed in watchOS 26.2, Safari 26.2, iOS 18.7.3 and iPadOS 18.7.3, iOS 26.2 and iPadOS 26.2, macOS Tahoe 26.2, visionOS 26.2, tvOS 26.2. Processing maliciously crafted web content may lead to arbitrary code execution. Apple is aware of a report that this issue may have been exploited in an extremely sophisticated attack against specific targeted individuals on versions of iOS before iOS 26. CVE-2025-14174 was also issued in response to this report.

- [https://github.com/kmeps4/bugtest](https://github.com/kmeps4/bugtest) :  ![starts](https://img.shields.io/github/stars/kmeps4/bugtest.svg) ![forks](https://img.shields.io/github/forks/kmeps4/bugtest.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/dbwlsdnr95/CVE-2025-29927](https://github.com/dbwlsdnr95/CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/dbwlsdnr95/CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/dbwlsdnr95/CVE-2025-29927.svg)


## CVE-2025-24132
 The issue was addressed with improved memory handling. This issue is fixed in AirPlay audio SDK 2.7.1, AirPlay video SDK 3.6.0.126, CarPlay Communication Plug-in R18.1. An attacker on the local network may cause an unexpected app termination.

- [https://github.com/TheGamingGallifreyan/LiberationPlay-CVE-2025-24132-AirBourne-POC](https://github.com/TheGamingGallifreyan/LiberationPlay-CVE-2025-24132-AirBourne-POC) :  ![starts](https://img.shields.io/github/stars/TheGamingGallifreyan/LiberationPlay-CVE-2025-24132-AirBourne-POC.svg) ![forks](https://img.shields.io/github/forks/TheGamingGallifreyan/LiberationPlay-CVE-2025-24132-AirBourne-POC.svg)


## CVE-2025-11700
 N-central versions  2025.4 are vulnerable to multiple XML External Entities injection leading to information disclosure

- [https://github.com/zyyyys123/CVE-2025-9316_CVE-2025-11700](https://github.com/zyyyys123/CVE-2025-9316_CVE-2025-11700) :  ![starts](https://img.shields.io/github/stars/zyyyys123/CVE-2025-9316_CVE-2025-11700.svg) ![forks](https://img.shields.io/github/forks/zyyyys123/CVE-2025-9316_CVE-2025-11700.svg)


## CVE-2025-9316
This issue affects N-central: before 2025.4.

- [https://github.com/zyyyys123/CVE-2025-9316_CVE-2025-11700](https://github.com/zyyyys123/CVE-2025-9316_CVE-2025-11700) :  ![starts](https://img.shields.io/github/stars/zyyyys123/CVE-2025-9316_CVE-2025-11700.svg) ![forks](https://img.shields.io/github/forks/zyyyys123/CVE-2025-9316_CVE-2025-11700.svg)


## CVE-2025-6018
 A Local Privilege Escalation (LPE) vulnerability has been discovered in pam-config within Linux Pluggable Authentication Modules (PAM). This flaw allows an unprivileged local attacker (for example, a user logged in via SSH) to obtain the elevated privileges normally reserved for a physically present, "allow_active" user. The highest risk is that the attacker can then perform all allow_active yes Polkit actions, which are typically restricted to console users, potentially gaining unauthorized control over system configurations, services, or other sensitive operations.

- [https://github.com/e1arth/CVE-2025-6018](https://github.com/e1arth/CVE-2025-6018) :  ![starts](https://img.shields.io/github/stars/e1arth/CVE-2025-6018.svg) ![forks](https://img.shields.io/github/forks/e1arth/CVE-2025-6018.svg)


## CVE-2025-5777
 Insufficient input validation leading to memory overread when the NetScaler is configured as a Gateway (VPN virtual server, ICA Proxy, CVPN, RDP Proxy) OR AAA virtual server

- [https://github.com/zaryouhashraf/CVE-2025-5777](https://github.com/zaryouhashraf/CVE-2025-5777) :  ![starts](https://img.shields.io/github/stars/zaryouhashraf/CVE-2025-5777.svg) ![forks](https://img.shields.io/github/forks/zaryouhashraf/CVE-2025-5777.svg)


## CVE-2025-4517
Note that none of these vulnerabilities significantly affect the installation of source distributions which are tar archives as source distributions already allow arbitrary code execution during the build process. However when evaluating source distributions it's important to avoid installing source distributions with suspicious links.

- [https://github.com/Gh0s7Ops/CVE-2025-4517-POC](https://github.com/Gh0s7Ops/CVE-2025-4517-POC) :  ![starts](https://img.shields.io/github/stars/Gh0s7Ops/CVE-2025-4517-POC.svg) ![forks](https://img.shields.io/github/forks/Gh0s7Ops/CVE-2025-4517-POC.svg)


## CVE-2025-3047
Users should upgrade to v1.133.0 or newer and ensure any forked or derivative code is patched to incorporate the new fixes.

- [https://github.com/murataydemir/AWS-SAM-CLI-Vulnerabilities](https://github.com/murataydemir/AWS-SAM-CLI-Vulnerabilities) :  ![starts](https://img.shields.io/github/stars/murataydemir/AWS-SAM-CLI-Vulnerabilities.svg) ![forks](https://img.shields.io/github/forks/murataydemir/AWS-SAM-CLI-Vulnerabilities.svg)


## CVE-2024-2997
 A vulnerability was found in Bdtask Multi-Store Inventory Management System up to 20240320. It has been declared as problematic. Affected by this vulnerability is an unknown functionality. The manipulation of the argument Category Name/Model Name/Brand Name/Unit Name leads to cross site scripting. The attack can be launched remotely. The exploit has been disclosed to the public and may be used. The associated identifier of this vulnerability is VDB-258199. NOTE: The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/lfilharv/CVE-2024-2997](https://github.com/lfilharv/CVE-2024-2997) :  ![starts](https://img.shields.io/github/stars/lfilharv/CVE-2024-2997.svg) ![forks](https://img.shields.io/github/forks/lfilharv/CVE-2024-2997.svg)


## CVE-2023-24932
 Secure Boot Security Feature Bypass Vulnerability

- [https://github.com/v1ckxy/Orchestrated-Powershell-for-CVE-2023-24932-en](https://github.com/v1ckxy/Orchestrated-Powershell-for-CVE-2023-24932-en) :  ![starts](https://img.shields.io/github/stars/v1ckxy/Orchestrated-Powershell-for-CVE-2023-24932-en.svg) ![forks](https://img.shields.io/github/forks/v1ckxy/Orchestrated-Powershell-for-CVE-2023-24932-en.svg)


## CVE-2015-1855
 verify_certificate_identity in the OpenSSL extension in Ruby before 2.0.0 patchlevel 645, 2.1.x before 2.1.6, and 2.2.x before 2.2.2 does not properly validate hostnames, which allows remote attackers to spoof servers via vectors related to (1) multiple wildcards, (1) wildcards in IDNA names, (3) case sensitivity, and (4) non-ASCII characters.

- [https://github.com/vpereira/CVE-2015-1855](https://github.com/vpereira/CVE-2015-1855) :  ![starts](https://img.shields.io/github/stars/vpereira/CVE-2015-1855.svg) ![forks](https://img.shields.io/github/forks/vpereira/CVE-2015-1855.svg)


## CVE-2015-1560
 SQL injection vulnerability in the isUserAdmin function in include/common/common-Func.php in Centreon (formerly Merethis Centreon) 2.5.4 and earlier (fixed in Centreon web 2.7.0) allows remote attackers to execute arbitrary SQL commands via the sid parameter to include/common/XmlTree/GetXmlTree.php.

- [https://github.com/Iansus/Centreon-CVE-2015-1560_1561](https://github.com/Iansus/Centreon-CVE-2015-1560_1561) :  ![starts](https://img.shields.io/github/stars/Iansus/Centreon-CVE-2015-1560_1561.svg) ![forks](https://img.shields.io/github/forks/Iansus/Centreon-CVE-2015-1560_1561.svg)


## CVE-2009-2585
 SQL injection vulnerability in index.php in Mlffat 2.2 allows remote attackers to execute arbitrary SQL commands via a member cookie in an account editprofile action, a different vector than CVE-2009-1731.

- [https://github.com/securityforge/CVE2009-2585_HP_Power_Manager_BoF](https://github.com/securityforge/CVE2009-2585_HP_Power_Manager_BoF) :  ![starts](https://img.shields.io/github/stars/securityforge/CVE2009-2585_HP_Power_Manager_BoF.svg) ![forks](https://img.shields.io/github/forks/securityforge/CVE2009-2585_HP_Power_Manager_BoF.svg)

