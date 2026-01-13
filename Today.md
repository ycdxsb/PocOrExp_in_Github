# Update 2026-01-13
## CVE-2026-21440
 AdonisJS is a TypeScript-first web framework. A Path Traversal vulnerability in AdonisJS multipart file handling may allow a remote attacker to write arbitrary files to arbitrary locations on the server filesystem. This impacts @adonisjs/bodyparser through version 10.1.1 and 11.x prerelease versions prior to 11.0.0-next.6. This issue has been patched in @adonisjs/bodyparser versions 10.1.2 and 11.0.0-next.6.

- [https://github.com/k0nnect/cve-2026-21440-writeup-poc](https://github.com/k0nnect/cve-2026-21440-writeup-poc) :  ![starts](https://img.shields.io/github/stars/k0nnect/cve-2026-21440-writeup-poc.svg) ![forks](https://img.shields.io/github/forks/k0nnect/cve-2026-21440-writeup-poc.svg)


## CVE-2026-0842
 A flaw has been found in Flycatcher Toys smART Sketcher up to 2.0. This affects an unknown part of the component Bluetooth Low Energy Interface. This manipulation causes missing authentication. The attack can only be done within the local network. The exploit has been published and may be used. The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/davidrxchester/smart-sketcher-upload](https://github.com/davidrxchester/smart-sketcher-upload) :  ![starts](https://img.shields.io/github/stars/davidrxchester/smart-sketcher-upload.svg) ![forks](https://img.shields.io/github/forks/davidrxchester/smart-sketcher-upload.svg)


## CVE-2025-68120
 To prevent unexpected untrusted code execution, the Visual Studio Code Go extension is now disabled in Restricted Mode.

- [https://github.com/choewonwoo1817/CVE-2025-68120](https://github.com/choewonwoo1817/CVE-2025-68120) :  ![starts](https://img.shields.io/github/stars/choewonwoo1817/CVE-2025-68120.svg) ![forks](https://img.shields.io/github/forks/choewonwoo1817/CVE-2025-68120.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-14x](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-14x) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-14x.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-14x.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp.svg)


## CVE-2025-55182
 A pre-authentication remote code execution vulnerability exists in React Server Components versions 19.0.0, 19.1.0, 19.1.1, and 19.2.0 including the following packages: react-server-dom-parcel, react-server-dom-turbopack, and react-server-dom-webpack. The vulnerable code unsafely deserializes payloads from HTTP requests to Server Function endpoints.

- [https://github.com/Faithtiannn/CVE-2025-55182](https://github.com/Faithtiannn/CVE-2025-55182) :  ![starts](https://img.shields.io/github/stars/Faithtiannn/CVE-2025-55182.svg) ![forks](https://img.shields.io/github/forks/Faithtiannn/CVE-2025-55182.svg)


## CVE-2025-31161
 CrushFTP 10 before 10.8.4 and 11 before 11.3.1 allows authentication bypass and takeover of the crushadmin account (unless a DMZ proxy instance is used), as exploited in the wild in March and April 2025, aka "Unauthenticated HTTP(S) port access." A race condition exists in the AWS4-HMAC (compatible with S3) authorization method of the HTTP component of the FTP server. The server first verifies the existence of the user by performing a call to login_user_pass() with no password requirement. This will authenticate the session through the HMAC verification process and up until the server checks for user verification once more. The vulnerability can be further stabilized, eliminating the need for successfully triggering a race condition, by sending a mangled AWS4-HMAC header. By providing only the username and a following slash (/), the server will successfully find a username, which triggers the successful anypass authentication process, but the server will fail to find the expected SignedHeaders entry, resulting in an index-out-of-bounds error that stops the code from reaching the session cleanup. Together, these issues make it trivial to authenticate as any known or guessable user (e.g., crushadmin), and can lead to a full compromise of the system by obtaining an administrative account.

- [https://github.com/Dairrow/CVE-2025-31161](https://github.com/Dairrow/CVE-2025-31161) :  ![starts](https://img.shields.io/github/stars/Dairrow/CVE-2025-31161.svg) ![forks](https://img.shields.io/github/forks/Dairrow/CVE-2025-31161.svg)


## CVE-2025-26198
 CloudClassroom-PHP-Project v1.0 contains a critical SQL Injection vulnerability in the loginlinkadmin.php component. The application fails to sanitize user-supplied input in the admin login form before directly including it in SQL queries. This allows unauthenticated attackers to inject arbitrary SQL payloads and bypass authentication, gaining unauthorized administrative access. The vulnerability is triggered when an attacker supplies specially crafted input in the username field, such as ' OR '1'='1, leading to complete compromise of the login mechanism and potential exposure of sensitive backend data.

- [https://github.com/WailYacoubi9/CVE-2025-26198](https://github.com/WailYacoubi9/CVE-2025-26198) :  ![starts](https://img.shields.io/github/stars/WailYacoubi9/CVE-2025-26198.svg) ![forks](https://img.shields.io/github/forks/WailYacoubi9/CVE-2025-26198.svg)


## CVE-2025-14847
 Mismatched length fields in Zlib compressed protocol headers may allow a read of uninitialized heap memory by an unauthenticated client. This issue affects all MongoDB Server v7.0 prior to 7.0.28 versions, MongoDB Server v8.0 versions prior to 8.0.17, MongoDB Server v8.2 versions prior to 8.2.3, MongoDB Server v6.0 versions prior to 6.0.27, MongoDB Server v5.0 versions prior to 5.0.32, MongoDB Server v4.4 versions prior to 4.4.30, MongoDB Server v4.2 versions greater than or equal to 4.2.0, MongoDB Server v4.0 versions greater than or equal to 4.0.0, and MongoDB Server v3.6 versions greater than or equal to 3.6.0.

- [https://github.com/sahar042/CVE-2025-14847](https://github.com/sahar042/CVE-2025-14847) :  ![starts](https://img.shields.io/github/stars/sahar042/CVE-2025-14847.svg) ![forks](https://img.shields.io/github/forks/sahar042/CVE-2025-14847.svg)


## CVE-2025-8088
     from ESET.

- [https://github.com/ilhamrzr/RAR-Anomaly-Inspector](https://github.com/ilhamrzr/RAR-Anomaly-Inspector) :  ![starts](https://img.shields.io/github/stars/ilhamrzr/RAR-Anomaly-Inspector.svg) ![forks](https://img.shields.io/github/forks/ilhamrzr/RAR-Anomaly-Inspector.svg)


## CVE-2025-6668
 A vulnerability was found in code-projects Inventory Management System 1.0. It has been classified as critical. This affects an unknown part of the file /php_action/fetchSelectedBrand.php. The manipulation of the argument brandId leads to sql injection. It is possible to initiate the attack remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/scap3sh4rk/CVE-2025-66683](https://github.com/scap3sh4rk/CVE-2025-66683) :  ![starts](https://img.shields.io/github/stars/scap3sh4rk/CVE-2025-66683.svg) ![forks](https://img.shields.io/github/forks/scap3sh4rk/CVE-2025-66683.svg)


## CVE-2024-28397
 An issue in the component js2py.disable_pyimport() of js2py up to v0.74 allows attackers to execute arbitrary code via a crafted API call.

- [https://github.com/3z-p0wn/CVE-2024-28397-exploit](https://github.com/3z-p0wn/CVE-2024-28397-exploit) :  ![starts](https://img.shields.io/github/stars/3z-p0wn/CVE-2024-28397-exploit.svg) ![forks](https://img.shields.io/github/forks/3z-p0wn/CVE-2024-28397-exploit.svg)


## CVE-2022-4782
 The ClickFunnels WordPress plugin through 3.1.1 does not validate and escape one of its shortcode attributes, which could allow users with a role as low as contributor to perform Stored Cross-Site Scripting attack.

- [https://github.com/Sudo-WP/sudowp-clickfunnels-zurich](https://github.com/Sudo-WP/sudowp-clickfunnels-zurich) :  ![starts](https://img.shields.io/github/stars/Sudo-WP/sudowp-clickfunnels-zurich.svg) ![forks](https://img.shields.io/github/forks/Sudo-WP/sudowp-clickfunnels-zurich.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/Fa1c0n35/CVE-2021-41773](https://github.com/Fa1c0n35/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/Fa1c0n35/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/Fa1c0n35/CVE-2021-41773.svg)
- [https://github.com/vuongnv3389-sec/cve-2021-41773](https://github.com/vuongnv3389-sec/cve-2021-41773) :  ![starts](https://img.shields.io/github/stars/vuongnv3389-sec/cve-2021-41773.svg) ![forks](https://img.shields.io/github/forks/vuongnv3389-sec/cve-2021-41773.svg)
- [https://github.com/skentagon/CVE-2021-41773](https://github.com/skentagon/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/skentagon/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/skentagon/CVE-2021-41773.svg)


## CVE-2018-16763
 FUEL CMS 1.4.1 allows PHP Code Evaluation via the pages/select/ filter parameter or the preview/ data parameter. This can lead to Pre-Auth Remote Code Execution.

- [https://github.com/kaxm23/exploit_cms_fuel](https://github.com/kaxm23/exploit_cms_fuel) :  ![starts](https://img.shields.io/github/stars/kaxm23/exploit_cms_fuel.svg) ![forks](https://img.shields.io/github/forks/kaxm23/exploit_cms_fuel.svg)


## CVE-2015-1538
 Integer overflow in the SampleTable::setSampleToChunkParams function in SampleTable.cpp in libstagefright in Android before 5.1.1 LMY48I allows remote attackers to execute arbitrary code via crafted atoms in MP4 data that trigger an unchecked multiplication, aka internal bug 20139950, a related issue to CVE-2015-4496.

- [https://github.com/xsleaksiki/cve](https://github.com/xsleaksiki/cve) :  ![starts](https://img.shields.io/github/stars/xsleaksiki/cve.svg) ![forks](https://img.shields.io/github/forks/xsleaksiki/cve.svg)

