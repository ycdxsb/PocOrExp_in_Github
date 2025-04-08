# Update 2025-04-08
## CVE-2025-30567
 Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') vulnerability in wp01ru WP01 allows Path Traversal. This issue affects WP01: from n/a through 2.6.2.

- [https://github.com/KaxuFF/CVE-2025-30567-PoC](https://github.com/KaxuFF/CVE-2025-30567-PoC) :  ![starts](https://img.shields.io/github/stars/KaxuFF/CVE-2025-30567-PoC.svg) ![forks](https://img.shields.io/github/forks/KaxuFF/CVE-2025-30567-PoC.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Prior to 14.2.25 and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 14.2.25 and 15.2.3.

- [https://github.com/gotr00t0day/CVE-2025-29927](https://github.com/gotr00t0day/CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/gotr00t0day/CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/gotr00t0day/CVE-2025-29927.svg)
- [https://github.com/YEONDG/nextjs-cve-2025-29927](https://github.com/YEONDG/nextjs-cve-2025-29927) :  ![starts](https://img.shields.io/github/stars/YEONDG/nextjs-cve-2025-29927.svg) ![forks](https://img.shields.io/github/forks/YEONDG/nextjs-cve-2025-29927.svg)


## CVE-2025-24813
Users are recommended to upgrade to version 11.0.3, 10.1.35 or 9.0.99, which fixes the issue.

- [https://github.com/La3B0z/CVE-2025-24813-POC](https://github.com/La3B0z/CVE-2025-24813-POC) :  ![starts](https://img.shields.io/github/stars/La3B0z/CVE-2025-24813-POC.svg) ![forks](https://img.shields.io/github/forks/La3B0z/CVE-2025-24813-POC.svg)


## CVE-2025-2783
 Incorrect handle provided in unspecified circumstances in Mojo in Google Chrome on Windows prior to 134.0.6998.177 allowed a remote attacker to perform a sandbox escape via a malicious file. (Chromium security severity: High)

- [https://github.com/Alchemist3dot14/CVE-2025-2783](https://github.com/Alchemist3dot14/CVE-2025-2783) :  ![starts](https://img.shields.io/github/stars/Alchemist3dot14/CVE-2025-2783.svg) ![forks](https://img.shields.io/github/forks/Alchemist3dot14/CVE-2025-2783.svg)


## CVE-2025-2005
 The Front End Users plugin for WordPress is vulnerable to arbitrary file uploads due to missing file type validation in the file uploads field of the registration form in all versions up to, and including, 3.2.32. This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible.

- [https://github.com/mrmtwoj/CVE-2025-2005](https://github.com/mrmtwoj/CVE-2025-2005) :  ![starts](https://img.shields.io/github/stars/mrmtwoj/CVE-2025-2005.svg) ![forks](https://img.shields.io/github/forks/mrmtwoj/CVE-2025-2005.svg)


## CVE-2024-56145
 Craft is a flexible, user-friendly CMS for creating custom digital experiences on the web and beyond. Users of affected versions are affected by this vulnerability if their php.ini configuration has `register_argc_argv` enabled. For these users an unspecified remote code execution vector is present. Users are advised to update to version 3.9.14, 4.13.2, or 5.5.2. Users unable to upgrade should disable `register_argc_argv` to mitigate the issue.

- [https://github.com/hmhlol/craft-cms-RCE-CVE-2024-56145](https://github.com/hmhlol/craft-cms-RCE-CVE-2024-56145) :  ![starts](https://img.shields.io/github/stars/hmhlol/craft-cms-RCE-CVE-2024-56145.svg) ![forks](https://img.shields.io/github/forks/hmhlol/craft-cms-RCE-CVE-2024-56145.svg)


## CVE-2024-42007
 SPX (aka php-spx) through 0.4.15 allows SPX_UI_URI Directory Traversal to read arbitrary files.

- [https://github.com/BubblyCola/CVE_2024_42007](https://github.com/BubblyCola/CVE_2024_42007) :  ![starts](https://img.shields.io/github/stars/BubblyCola/CVE_2024_42007.svg) ![forks](https://img.shields.io/github/forks/BubblyCola/CVE_2024_42007.svg)


## CVE-2024-34102
 Adobe Commerce versions 2.4.7, 2.4.6-p5, 2.4.5-p7, 2.4.4-p8 and earlier are affected by an Improper Restriction of XML External Entity Reference ('XXE') vulnerability that could result in arbitrary code execution. An attacker could exploit this vulnerability by sending a crafted XML document that references external entities. Exploitation of this issue does not require user interaction.

- [https://github.com/Koray123-debug/CVE-2024-34102](https://github.com/Koray123-debug/CVE-2024-34102) :  ![starts](https://img.shields.io/github/stars/Koray123-debug/CVE-2024-34102.svg) ![forks](https://img.shields.io/github/forks/Koray123-debug/CVE-2024-34102.svg)


## CVE-2024-10924
 The Really Simple Security (Free, Pro, and Pro Multisite) plugins for WordPress are vulnerable to authentication bypass in versions 9.0.0 to 9.1.1.1. This is due to improper user check error handling in the two-factor REST API actions with the 'check_login_and_get_user' function. This makes it possible for unauthenticated attackers to log in as any existing user on the site, such as an administrator, when the "Two-Factor Authentication" setting is enabled (disabled by default).

- [https://github.com/OliveiraaX/-CVE-2024-10924](https://github.com/OliveiraaX/-CVE-2024-10924) :  ![starts](https://img.shields.io/github/stars/OliveiraaX/-CVE-2024-10924.svg) ![forks](https://img.shields.io/github/forks/OliveiraaX/-CVE-2024-10924.svg)


## CVE-2024-4367
 A type check was missing when handling fonts in PDF.js, which would allow arbitrary JavaScript execution in the PDF.js context. This vulnerability affects Firefox  126, Firefox ESR  115.11, and Thunderbird  115.11.

- [https://github.com/VVeakee/CVE-2024-4367](https://github.com/VVeakee/CVE-2024-4367) :  ![starts](https://img.shields.io/github/stars/VVeakee/CVE-2024-4367.svg) ![forks](https://img.shields.io/github/forks/VVeakee/CVE-2024-4367.svg)


## CVE-2023-41425
 Cross Site Scripting vulnerability in Wonder CMS v.3.2.0 thru v.3.4.2 allows a remote attacker to execute arbitrary code via a crafted script uploaded to the installModule component.

- [https://github.com/insomnia-jacob/CVE-2023-41425](https://github.com/insomnia-jacob/CVE-2023-41425) :  ![starts](https://img.shields.io/github/stars/insomnia-jacob/CVE-2023-41425.svg) ![forks](https://img.shields.io/github/forks/insomnia-jacob/CVE-2023-41425.svg)


## CVE-2023-23397
 Microsoft Outlook Elevation of Privilege Vulnerability

- [https://github.com/Agentgilspy/CVE-2023-23397](https://github.com/Agentgilspy/CVE-2023-23397) :  ![starts](https://img.shields.io/github/stars/Agentgilspy/CVE-2023-23397.svg) ![forks](https://img.shields.io/github/forks/Agentgilspy/CVE-2023-23397.svg)


## CVE-2023-4220
 Unrestricted file upload in big file upload functionality in `/main/inc/lib/javascript/bigupload/inc/bigUpload.php` in Chamilo LMS = v1.11.24 allows unauthenticated attackers to perform stored cross-site scripting attacks and obtain remote code execution via uploading of web shell.

- [https://github.com/insomnia-jacob/CVE-2023-4220](https://github.com/insomnia-jacob/CVE-2023-4220) :  ![starts](https://img.shields.io/github/stars/insomnia-jacob/CVE-2023-4220.svg) ![forks](https://img.shields.io/github/forks/insomnia-jacob/CVE-2023-4220.svg)


## CVE-2022-42889
 Apache Commons Text performs variable interpolation, allowing properties to be dynamically evaluated and expanded. The standard format for interpolation is "${prefix:name}", where "prefix" is used to locate an instance of org.apache.commons.text.lookup.StringLookup that performs the interpolation. Starting with version 1.5 and continuing through 1.9, the set of default Lookup instances included interpolators that could result in arbitrary code execution or contact with remote servers. These lookups are: - "script" - execute expressions using the JVM script execution engine (javax.script) - "dns" - resolve dns records - "url" - load values from urls, including from remote servers Applications using the interpolation defaults in the affected versions may be vulnerable to remote code execution or unintentional contact with remote servers if untrusted configuration values are used. Users are recommended to upgrade to Apache Commons Text 1.10.0, which disables the problematic interpolators by default.

- [https://github.com/Gotcha1G/CVE-2022-42889](https://github.com/Gotcha1G/CVE-2022-42889) :  ![starts](https://img.shields.io/github/stars/Gotcha1G/CVE-2022-42889.svg) ![forks](https://img.shields.io/github/forks/Gotcha1G/CVE-2022-42889.svg)


## CVE-2022-22978
 In spring security versions prior to 5.4.11+, 5.5.7+ , 5.6.4+ and older unsupported versions, RegexRequestMatcher can easily be misconfigured to be bypassed on some servlet containers. Applications using RegexRequestMatcher with `.` in the regular expression are possibly vulnerable to an authorization bypass.

- [https://github.com/he-ewo/CVE-2022-22978](https://github.com/he-ewo/CVE-2022-22978) :  ![starts](https://img.shields.io/github/stars/he-ewo/CVE-2022-22978.svg) ![forks](https://img.shields.io/github/forks/he-ewo/CVE-2022-22978.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/McSl0vv/CVE-2021-41773](https://github.com/McSl0vv/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/McSl0vv/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/McSl0vv/CVE-2021-41773.svg)
- [https://github.com/12345qwert123456/CVE-2021-41773](https://github.com/12345qwert123456/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/12345qwert123456/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/12345qwert123456/CVE-2021-41773.svg)
- [https://github.com/ch4os443/CVE-2021-41773](https://github.com/ch4os443/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/ch4os443/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/ch4os443/CVE-2021-41773.svg)


## CVE-2021-24006
 An improper access control vulnerability in FortiManager versions 6.4.0 to 6.4.3 may allow an authenticated attacker with a restricted user profile to access the SD-WAN Orchestrator panel via directly visiting its URL.

- [https://github.com/cnetsec/CVE-2021-24006](https://github.com/cnetsec/CVE-2021-24006) :  ![starts](https://img.shields.io/github/stars/cnetsec/CVE-2021-24006.svg) ![forks](https://img.shields.io/github/forks/cnetsec/CVE-2021-24006.svg)

