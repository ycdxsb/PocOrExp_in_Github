# Update 2026-02-23
## CVE-2026-27574
 OneUptime is a solution for monitoring and managing online services. In versions 9.5.13 and below, custom JavaScript monitor feature uses Node.js's node:vm module (explicitly documented as not a security mechanism) to execute user-supplied code, allowing trivial sandbox escape via a well-known one-liner that grants full access to the underlying process. Because the probe runs with host networking and holds all cluster credentials (ONEUPTIME_SECRET, DATABASE_PASSWORD, REDIS_PASSWORD, CLICKHOUSE_PASSWORD) in its environment variables, and monitor creation is available to the lowest role (ProjectMember) with open registration enabled by default, any anonymous user can achieve full cluster compromise in about 30 seconds. This issue has been fixed in version 10.0.5.

- [https://github.com/mbanyamer/CVE-2026-27574-OneUptime-RCE](https://github.com/mbanyamer/CVE-2026-27574-OneUptime-RCE) :  ![starts](https://img.shields.io/github/stars/mbanyamer/CVE-2026-27574-OneUptime-RCE.svg) ![forks](https://img.shields.io/github/forks/mbanyamer/CVE-2026-27574-OneUptime-RCE.svg)


## CVE-2026-27470
 ZoneMinder is a free, open source closed-circuit television software application. In versions 1.36.37 and below and 1.37.61 through 1.38.0, there is a second-order SQL Injection vulnerability in the web/ajax/status.php file within the getNearEvents() function. Event field values (specifically Name and Cause) are stored safely via parameterized queries but are later retrieved and concatenated directly into SQL WHERE clauses without escaping. An authenticated user with Events edit and view permissions can exploit this to execute arbitrary SQL queries.

- [https://github.com/kocaemre/CVE-2026-27470](https://github.com/kocaemre/CVE-2026-27470) :  ![starts](https://img.shields.io/github/stars/kocaemre/CVE-2026-27470.svg) ![forks](https://img.shields.io/github/forks/kocaemre/CVE-2026-27470.svg)


## CVE-2026-27199
 Werkzeug is a comprehensive WSGI web application library. Versions 3.1.5 and below, the safe_join function allows Windows device names as filenames if preceded by other path segments. This was previously reported as GHSA-hgf8-39gv-g3f2, but the added filtering failed to account for the fact that safe_join accepts paths with multiple segments, such as example/NUL. The function send_from_directory uses safe_join to safely serve files at user-specified paths under a directory. If the application is running on Windows, and the requested path ends with a special device name, the file will be opened successfully, but reading will hang indefinitely. This issue has been fixed in version 3.1.6.

- [https://github.com/alimezar/CVE-2026-27199-werkzeug-safe-join-bypass-PoC](https://github.com/alimezar/CVE-2026-27199-werkzeug-safe-join-bypass-PoC) :  ![starts](https://img.shields.io/github/stars/alimezar/CVE-2026-27199-werkzeug-safe-join-bypass-PoC.svg) ![forks](https://img.shields.io/github/forks/alimezar/CVE-2026-27199-werkzeug-safe-join-bypass-PoC.svg)


## CVE-2026-2848
 A flaw has been found in SourceCodester Simple Responsive Tourism Website 1.0. Affected by this vulnerability is an unknown functionality of the file /classes/Master.php?f=register of the component Registration. This manipulation of the argument Username causes sql injection. The attack may be initiated remotely. The exploit has been published and may be used.

- [https://github.com/richardpaimu34/CVE-2026-2848](https://github.com/richardpaimu34/CVE-2026-2848) :  ![starts](https://img.shields.io/github/stars/richardpaimu34/CVE-2026-2848.svg) ![forks](https://img.shields.io/github/forks/richardpaimu34/CVE-2026-2848.svg)


## CVE-2025-68645
 A Local File Inclusion (LFI) vulnerability exists in the Webmail Classic UI of Zimbra Collaboration (ZCS) 10.0 and 10.1 because of improper handling of user-supplied request parameters in the RestFilter servlet. An unauthenticated remote attacker can craft requests to the /h/rest endpoint to influence internal request dispatching, allowing inclusion of arbitrary files from the WebRoot directory.

- [https://github.com/CMEGh0stX47/CVE-2025-68645](https://github.com/CMEGh0stX47/CVE-2025-68645) :  ![starts](https://img.shields.io/github/stars/CMEGh0stX47/CVE-2025-68645.svg) ![forks](https://img.shields.io/github/forks/CMEGh0stX47/CVE-2025-68645.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo.svg)


## CVE-2025-49132
 Pterodactyl is a free, open-source game server management panel. Prior to version 1.11.11, using the /locales/locale.json with the locale and namespace query parameters, a malicious actor is able to execute arbitrary code without being authenticated. With the ability to execute arbitrary code it could be used to gain access to the Panel's server, read credentials from the Panel's config, extract sensitive information from the database, access files of servers managed by the panel, etc. This issue has been patched in version 1.11.11. There are no software workarounds for this vulnerability, but use of an external Web Application Firewall (WAF) could help mitigate this attack.

- [https://github.com/4nuxd/CVE-2025-49132](https://github.com/4nuxd/CVE-2025-49132) :  ![starts](https://img.shields.io/github/stars/4nuxd/CVE-2025-49132.svg) ![forks](https://img.shields.io/github/forks/4nuxd/CVE-2025-49132.svg)


## CVE-2025-32463
 Sudo before 1.9.17p1 allows local users to obtain root access because /etc/nsswitch.conf from a user-controlled directory is used with the --chroot option.

- [https://github.com/danilo1992-sys/CVE-2025-32463](https://github.com/danilo1992-sys/CVE-2025-32463) :  ![starts](https://img.shields.io/github/stars/danilo1992-sys/CVE-2025-32463.svg) ![forks](https://img.shields.io/github/forks/danilo1992-sys/CVE-2025-32463.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/lstudlo/nextjs-cve-demo](https://github.com/lstudlo/nextjs-cve-demo) :  ![starts](https://img.shields.io/github/stars/lstudlo/nextjs-cve-demo.svg) ![forks](https://img.shields.io/github/forks/lstudlo/nextjs-cve-demo.svg)


## CVE-2023-43208
 NextGen Healthcare Mirth Connect before version 4.4.1 is vulnerable to unauthenticated remote code execution. Note that this vulnerability is caused by the incomplete patch of CVE-2023-37679.

- [https://github.com/kyakei/CVE-2023-43208](https://github.com/kyakei/CVE-2023-43208) :  ![starts](https://img.shields.io/github/stars/kyakei/CVE-2023-43208.svg) ![forks](https://img.shields.io/github/forks/kyakei/CVE-2023-43208.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/ch4os443/CVE-2021-41773](https://github.com/ch4os443/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/ch4os443/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/ch4os443/CVE-2021-41773.svg)
- [https://github.com/Taldrid1/cve-2021-41773](https://github.com/Taldrid1/cve-2021-41773) :  ![starts](https://img.shields.io/github/stars/Taldrid1/cve-2021-41773.svg) ![forks](https://img.shields.io/github/forks/Taldrid1/cve-2021-41773.svg)


## CVE-2021-36934
pAfter installing this security update, you emmust/em manually delete all shadow copies of system files, including the SAM database, to fully mitigate this vulnerabilty. strongSimply installing this security update will not fully mitigate this vulnerability./strong See a href="https://support.microsoft.com/topic/1ceaa637-aaa3-4b58-a48b-baf72a2fa9e7"KB5005357- Delete Volume Shadow Copies/a./p

- [https://github.com/d4yon/CVE-2021-36934-HiveNightmare-Lab](https://github.com/d4yon/CVE-2021-36934-HiveNightmare-Lab) :  ![starts](https://img.shields.io/github/stars/d4yon/CVE-2021-36934-HiveNightmare-Lab.svg) ![forks](https://img.shields.io/github/forks/d4yon/CVE-2021-36934-HiveNightmare-Lab.svg)


## CVE-2019-1619
 A vulnerability in the web-based management interface of Cisco Data Center Network Manager (DCNM) could allow an unauthenticated, remote attacker to bypass authentication and execute arbitrary actions with administrative privileges on an affected device. The vulnerability is due to improper session management on affected DCNM software. An attacker could exploit this vulnerability by sending a crafted HTTP request to the affected device. A successful exploit could allow the attacker to gain administrative access on the affected device.

- [https://github.com/Cipolone95/CVE-2019-1619](https://github.com/Cipolone95/CVE-2019-1619) :  ![starts](https://img.shields.io/github/stars/Cipolone95/CVE-2019-1619.svg) ![forks](https://img.shields.io/github/forks/Cipolone95/CVE-2019-1619.svg)

