# Update 2025-02-04
## CVE-2024-10924
 The Really Simple Security (Free, Pro, and Pro Multisite) plugins for WordPress are vulnerable to authentication bypass in versions 9.0.0 to 9.1.1.1. This is due to improper user check error handling in the two-factor REST API actions with the 'check_login_and_get_user' function. This makes it possible for unauthenticated attackers to log in as any existing user on the site, such as an administrator, when the "Two-Factor Authentication" setting is enabled (disabled by default).

- [https://github.com/Nxploited/CVE-2024-10924-Exploit](https://github.com/Nxploited/CVE-2024-10924-Exploit) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2024-10924-Exploit.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2024-10924-Exploit.svg)


## CVE-2024-6366
 The User Profile Builder  WordPress plugin before 3.11.8 does not have proper authorisation, allowing unauthenticated users to upload media files via the async upload functionality of WP.

- [https://github.com/Nxploited/CVE-2024-6366-PoC](https://github.com/Nxploited/CVE-2024-6366-PoC) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2024-6366-PoC.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2024-6366-PoC.svg)


## CVE-2024-5690
 By monitoring the time certain operations take, an attacker could have guessed which external protocol handlers were functional on a user's system. This vulnerability affects Firefox  127, Firefox ESR  115.12, and Thunderbird  115.12.

- [https://github.com/DRAGOWN/CVE-2024-56902](https://github.com/DRAGOWN/CVE-2024-56902) :  ![starts](https://img.shields.io/github/stars/DRAGOWN/CVE-2024-56902.svg) ![forks](https://img.shields.io/github/forks/DRAGOWN/CVE-2024-56902.svg)
- [https://github.com/DRAGOWN/CVE-2024-56901](https://github.com/DRAGOWN/CVE-2024-56901) :  ![starts](https://img.shields.io/github/stars/DRAGOWN/CVE-2024-56901.svg) ![forks](https://img.shields.io/github/forks/DRAGOWN/CVE-2024-56901.svg)
- [https://github.com/DRAGOWN/CVE-2024-56903](https://github.com/DRAGOWN/CVE-2024-56903) :  ![starts](https://img.shields.io/github/stars/DRAGOWN/CVE-2024-56903.svg) ![forks](https://img.shields.io/github/forks/DRAGOWN/CVE-2024-56903.svg)


## CVE-2024-5689
 In addition to detecting when a user was taking a screenshot (XXX), a website was able to overlay the 'My Shots' button that appeared, and direct the user to a replica Firefox Screenshots page that could be used for phishing. This vulnerability affects Firefox  127.

- [https://github.com/DRAGOWN/CVE-2024-56898](https://github.com/DRAGOWN/CVE-2024-56898) :  ![starts](https://img.shields.io/github/stars/DRAGOWN/CVE-2024-56898.svg) ![forks](https://img.shields.io/github/forks/DRAGOWN/CVE-2024-56898.svg)


## CVE-2024-5339
 A vulnerability was found in Ruijie RG-UAC up to 20240516. It has been declared as critical. Affected by this vulnerability is an unknown functionality of the file /view/vpn/autovpn/online_check.php. The manipulation of the argument peernode leads to os command injection. The attack can be launched remotely. The exploit has been disclosed to the public and may be used. The identifier VDB-266245 was assigned to this vulnerability. NOTE: The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/alirezac0/CVE-2024-53393](https://github.com/alirezac0/CVE-2024-53393) :  ![starts](https://img.shields.io/github/stars/alirezac0/CVE-2024-53393.svg) ![forks](https://img.shields.io/github/forks/alirezac0/CVE-2024-53393.svg)


## CVE-2024-3400
Cloud NGFW, Panorama appliances, and Prisma Access are not impacted by this vulnerability.

- [https://github.com/drake044/SOC274-Palo-Alto-Networks-PAN-OS-Command-Injection-Vulnerability-Exploitation-CVE-2024-3400](https://github.com/drake044/SOC274-Palo-Alto-Networks-PAN-OS-Command-Injection-Vulnerability-Exploitation-CVE-2024-3400) :  ![starts](https://img.shields.io/github/stars/drake044/SOC274-Palo-Alto-Networks-PAN-OS-Command-Injection-Vulnerability-Exploitation-CVE-2024-3400.svg) ![forks](https://img.shields.io/github/forks/drake044/SOC274-Palo-Alto-Networks-PAN-OS-Command-Injection-Vulnerability-Exploitation-CVE-2024-3400.svg)


## CVE-2024-2961
 The iconv() function in the GNU C Library versions 2.39 and older may overflow the output buffer passed to it by up to 4 bytes when converting strings to the ISO-2022-CN-EXT character set, which may be used to crash an application or overwrite a neighbouring variable.

- [https://github.com/omarelshopky/exploit_cve-2023-26326_using_cve-2024-2961](https://github.com/omarelshopky/exploit_cve-2023-26326_using_cve-2024-2961) :  ![starts](https://img.shields.io/github/stars/omarelshopky/exploit_cve-2023-26326_using_cve-2024-2961.svg) ![forks](https://img.shields.io/github/forks/omarelshopky/exploit_cve-2023-26326_using_cve-2024-2961.svg)


## CVE-2023-40028
 Ghost is an open source content management system. Versions prior to 5.59.1 are subject to a vulnerability which allows authenticated users to upload files that are symlinks. This can be exploited to perform an arbitrary file read of any file on the host operating system. Site administrators can check for exploitation of this issue by looking for unknown symlinks within Ghost's `content/` folder. Version 5.59.1 contains a fix for this issue. All users are advised to upgrade. There are no known workarounds for this vulnerability.

- [https://github.com/rehan6658/CVE-2023-40028](https://github.com/rehan6658/CVE-2023-40028) :  ![starts](https://img.shields.io/github/stars/rehan6658/CVE-2023-40028.svg) ![forks](https://img.shields.io/github/forks/rehan6658/CVE-2023-40028.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/zer0qs/CVE-2021-41773](https://github.com/zer0qs/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/zer0qs/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/zer0qs/CVE-2021-41773.svg)


## CVE-2018-18820
 A buffer overflow was discovered in the URL-authentication backend of the Icecast before 2.4.4. If the backend is enabled, then any malicious HTTP client can send a request for that specific resource including a crafted header, leading to denial of service and potentially remote code execution.

- [https://github.com/impulsiveness/CVE-2018-18820](https://github.com/impulsiveness/CVE-2018-18820) :  ![starts](https://img.shields.io/github/stars/impulsiveness/CVE-2018-18820.svg) ![forks](https://img.shields.io/github/forks/impulsiveness/CVE-2018-18820.svg)


## CVE-2017-8869
 Buffer overflow in MediaCoder 0.8.48.5888 allows remote attackers to execute arbitrary code via a crafted .m3u file.

- [https://github.com/tankist0x01/CVE-2017-8869](https://github.com/tankist0x01/CVE-2017-8869) :  ![starts](https://img.shields.io/github/stars/tankist0x01/CVE-2017-8869.svg) ![forks](https://img.shields.io/github/forks/tankist0x01/CVE-2017-8869.svg)


## CVE-2014-3704
 The expandArguments function in the database abstraction API in Drupal core 7.x before 7.32 does not properly construct prepared statements, which allows remote attackers to conduct SQL injection attacks via an array containing crafted keys.

- [https://github.com/joaomorenorf/CVE-2014-3704](https://github.com/joaomorenorf/CVE-2014-3704) :  ![starts](https://img.shields.io/github/stars/joaomorenorf/CVE-2014-3704.svg) ![forks](https://img.shields.io/github/forks/joaomorenorf/CVE-2014-3704.svg)

