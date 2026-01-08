# Update 2026-01-08
## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-overrides](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-overrides) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-overrides.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-overrides.svg)


## CVE-2025-55182
 A pre-authentication remote code execution vulnerability exists in React Server Components versions 19.0.0, 19.1.0, 19.1.1, and 19.2.0 including the following packages: react-server-dom-parcel, react-server-dom-turbopack, and react-server-dom-webpack. The vulnerable code unsafely deserializes payloads from HTTP requests to Server Function endpoints.

- [https://github.com/Updatelap/CVE-2025-55182](https://github.com/Updatelap/CVE-2025-55182) :  ![starts](https://img.shields.io/github/stars/Updatelap/CVE-2025-55182.svg) ![forks](https://img.shields.io/github/forks/Updatelap/CVE-2025-55182.svg)
- [https://github.com/theman001/CVE-2025-55182](https://github.com/theman001/CVE-2025-55182) :  ![starts](https://img.shields.io/github/stars/theman001/CVE-2025-55182.svg) ![forks](https://img.shields.io/github/forks/theman001/CVE-2025-55182.svg)


## CVE-2025-37164
 A remote code execution issue exists in HPE OneView.

- [https://github.com/LACHHAB-Anas/Exploit_CVE-2025-37164](https://github.com/LACHHAB-Anas/Exploit_CVE-2025-37164) :  ![starts](https://img.shields.io/github/stars/LACHHAB-Anas/Exploit_CVE-2025-37164.svg) ![forks](https://img.shields.io/github/forks/LACHHAB-Anas/Exploit_CVE-2025-37164.svg)


## CVE-2025-31161
 CrushFTP 10 before 10.8.4 and 11 before 11.3.1 allows authentication bypass and takeover of the crushadmin account (unless a DMZ proxy instance is used), as exploited in the wild in March and April 2025, aka "Unauthenticated HTTP(S) port access." A race condition exists in the AWS4-HMAC (compatible with S3) authorization method of the HTTP component of the FTP server. The server first verifies the existence of the user by performing a call to login_user_pass() with no password requirement. This will authenticate the session through the HMAC verification process and up until the server checks for user verification once more. The vulnerability can be further stabilized, eliminating the need for successfully triggering a race condition, by sending a mangled AWS4-HMAC header. By providing only the username and a following slash (/), the server will successfully find a username, which triggers the successful anypass authentication process, but the server will fail to find the expected SignedHeaders entry, resulting in an index-out-of-bounds error that stops the code from reaching the session cleanup. Together, these issues make it trivial to authenticate as any known or guessable user (e.g., crushadmin), and can lead to a full compromise of the system by obtaining an administrative account.

- [https://github.com/ch3m1cl/CVE-2025-31161](https://github.com/ch3m1cl/CVE-2025-31161) :  ![starts](https://img.shields.io/github/stars/ch3m1cl/CVE-2025-31161.svg) ![forks](https://img.shields.io/github/forks/ch3m1cl/CVE-2025-31161.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/lucaschanzx/CVE-2025-29927-PoC](https://github.com/lucaschanzx/CVE-2025-29927-PoC) :  ![starts](https://img.shields.io/github/stars/lucaschanzx/CVE-2025-29927-PoC.svg) ![forks](https://img.shields.io/github/forks/lucaschanzx/CVE-2025-29927-PoC.svg)
- [https://github.com/sn1p3rt3s7/NextJS_CVE-2025-29927](https://github.com/sn1p3rt3s7/NextJS_CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/sn1p3rt3s7/NextJS_CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/sn1p3rt3s7/NextJS_CVE-2025-29927.svg)
- [https://github.com/enochgitgamefied/NextJS-CVE-2025-29927](https://github.com/enochgitgamefied/NextJS-CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/enochgitgamefied/NextJS-CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/enochgitgamefied/NextJS-CVE-2025-29927.svg)


## CVE-2025-24813
Users are recommended to upgrade to version 11.0.3, 10.1.35 or 9.0.99, which fixes the issue.

- [https://github.com/cchopin/CVE-Arsenal-Lab](https://github.com/cchopin/CVE-Arsenal-Lab) :  ![starts](https://img.shields.io/github/stars/cchopin/CVE-Arsenal-Lab.svg) ![forks](https://img.shields.io/github/forks/cchopin/CVE-Arsenal-Lab.svg)


## CVE-2025-20393
 Cisco is aware of a potential vulnerability.&nbsp; Cisco is currently investigating and&nbsp;will update these details as appropriate&nbsp;as more information becomes available.

- [https://github.com/MRH701/mrh701.github.io](https://github.com/MRH701/mrh701.github.io) :  ![starts](https://img.shields.io/github/stars/MRH701/mrh701.github.io.svg) ![forks](https://img.shields.io/github/forks/MRH701/mrh701.github.io.svg)
- [https://github.com/MRH701/cisco-sa-sma-attack-N9bf4](https://github.com/MRH701/cisco-sa-sma-attack-N9bf4) :  ![starts](https://img.shields.io/github/stars/MRH701/cisco-sa-sma-attack-N9bf4.svg) ![forks](https://img.shields.io/github/forks/MRH701/cisco-sa-sma-attack-N9bf4.svg)


## CVE-2025-14847
 Mismatched length fields in Zlib compressed protocol headers may allow a read of uninitialized heap memory by an unauthenticated client. This issue affects all MongoDB Server v7.0 prior to 7.0.28 versions, MongoDB Server v8.0 versions prior to 8.0.17, MongoDB Server v8.2 versions prior to 8.2.3, MongoDB Server v6.0 versions prior to 6.0.27, MongoDB Server v5.0 versions prior to 5.0.32, MongoDB Server v4.4 versions prior to 4.4.30, MongoDB Server v4.2 versions greater than or equal to 4.2.0, MongoDB Server v4.0 versions greater than or equal to 4.0.0, and MongoDB Server v3.6 versions greater than or equal to 3.6.0.

- [https://github.com/waheeb71/CVE-2025-14847](https://github.com/waheeb71/CVE-2025-14847) :  ![starts](https://img.shields.io/github/stars/waheeb71/CVE-2025-14847.svg) ![forks](https://img.shields.io/github/forks/waheeb71/CVE-2025-14847.svg)


## CVE-2025-1203
 The Slider, Gallery, and Carousel by MetaSlider  WordPress plugin before 3.95.0 does not sanitise and escape some of its settings, which could allow high privilege users such as editor to perform Stored Cross-Site Scripting attacks even when the unfiltered_html capability is disallowed (for example in multisite setup).

- [https://github.com/SnailSploit/CVE-2025-12030](https://github.com/SnailSploit/CVE-2025-12030) :  ![starts](https://img.shields.io/github/stars/SnailSploit/CVE-2025-12030.svg) ![forks](https://img.shields.io/github/forks/SnailSploit/CVE-2025-12030.svg)


## CVE-2024-5932
 The GiveWP – Donation Plugin and Fundraising Platform plugin for WordPress is vulnerable to PHP Object Injection in all versions up to, and including, 3.14.1 via deserialization of untrusted input from the 'give_title' parameter. This makes it possible for unauthenticated attackers to inject a PHP Object. The additional presence of a POP chain allows attackers to execute code remotely, and to delete arbitrary files.

- [https://github.com/nishant-kumar-5173/CVE-2024-5932](https://github.com/nishant-kumar-5173/CVE-2024-5932) :  ![starts](https://img.shields.io/github/stars/nishant-kumar-5173/CVE-2024-5932.svg) ![forks](https://img.shields.io/github/forks/nishant-kumar-5173/CVE-2024-5932.svg)


## CVE-2023-4220
 Unrestricted file upload in big file upload functionality in `/main/inc/lib/javascript/bigupload/inc/bigUpload.php` in Chamilo LMS = v1.11.24 allows unauthenticated attackers to perform stored cross-site scripting attacks and obtain remote code execution via uploading of web shell.

- [https://github.com/B1TC0R3/CVE-2023-4220](https://github.com/B1TC0R3/CVE-2023-4220) :  ![starts](https://img.shields.io/github/stars/B1TC0R3/CVE-2023-4220.svg) ![forks](https://img.shields.io/github/forks/B1TC0R3/CVE-2023-4220.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/Fa1c0n35/CVE-2021-41773](https://github.com/Fa1c0n35/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/Fa1c0n35/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/Fa1c0n35/CVE-2021-41773.svg)
- [https://github.com/vuongnv3389-sec/cve-2021-41773](https://github.com/vuongnv3389-sec/cve-2021-41773) :  ![starts](https://img.shields.io/github/stars/vuongnv3389-sec/cve-2021-41773.svg) ![forks](https://img.shields.io/github/forks/vuongnv3389-sec/cve-2021-41773.svg)
- [https://github.com/skentagon/CVE-2021-41773](https://github.com/skentagon/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/skentagon/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/skentagon/CVE-2021-41773.svg)


## CVE-2018-2628
 Vulnerability in the Oracle WebLogic Server component of Oracle Fusion Middleware (subcomponent: WLS Core Components). Supported versions that are affected are 10.3.6.0, 12.1.3.0, 12.2.1.2 and 12.2.1.3. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3 to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/herantong/CVE-2018-2628](https://github.com/herantong/CVE-2018-2628) :  ![starts](https://img.shields.io/github/stars/herantong/CVE-2018-2628.svg) ![forks](https://img.shields.io/github/forks/herantong/CVE-2018-2628.svg)


## CVE-2016-1611
 Novell Filr 1.2 before Hot Patch 6 and 2.0 before Hot Patch 2 uses world-writable permissions for /etc/profile.d/vainit.sh, which allows local users to gain privileges by replacing this file's content with arbitrary shell commands.

- [https://github.com/d3vn0mi/cve-2016-16113](https://github.com/d3vn0mi/cve-2016-16113) :  ![starts](https://img.shields.io/github/stars/d3vn0mi/cve-2016-16113.svg) ![forks](https://img.shields.io/github/forks/d3vn0mi/cve-2016-16113.svg)

