# Update 2025-10-09
## CVE-2025-61984
 ssh in OpenSSH before 10.1 allows control characters in usernames that originate from certain possibly untrusted sources, potentially leading to code execution when a ProxyCommand is used. The untrusted sources are the command line and %-sequence expansion of a configuration file. (A configuration file that provides a complete literal username is not categorized as an untrusted source.)

- [https://github.com/dgl/cve-2025-61984-poc](https://github.com/dgl/cve-2025-61984-poc) :  ![starts](https://img.shields.io/github/stars/dgl/cve-2025-61984-poc.svg) ![forks](https://img.shields.io/github/forks/dgl/cve-2025-61984-poc.svg)


## CVE-2025-61882
 Vulnerability in the Oracle Concurrent Processing product of Oracle E-Business Suite (component: BI Publisher Integration).  Supported versions that are affected are 12.2.3-12.2.14. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Concurrent Processing.  Successful attacks of this vulnerability can result in takeover of Oracle Concurrent Processing. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/B1ack4sh/Blackash-CVE-2025-61882](https://github.com/B1ack4sh/Blackash-CVE-2025-61882) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-61882.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-61882.svg)


## CVE-2025-59934
 Formbricks is an open source qualtrics alternative. Prior to version 4.0.1, Formbricks is missing JWT signature verification. This vulnerability stems from a token validation routine that only decodes JWTs (jwt.decode) without verifying their signatures. Both the email verification token login path and the password reset server action use the same validator, which does not check the token’s signature, expiration, issuer, or audience. If an attacker learns the victim’s actual user.id, they can craft an arbitrary JWT with an alg: "none" header and use it to authenticate and reset the victim’s password. This issue has been patched in version 4.0.1.

- [https://github.com/suriryuk/cve-2025-59934](https://github.com/suriryuk/cve-2025-59934) :  ![starts](https://img.shields.io/github/stars/suriryuk/cve-2025-59934.svg) ![forks](https://img.shields.io/github/forks/suriryuk/cve-2025-59934.svg)


## CVE-2025-56243
 A Cross-Site Scripting (XSS) vulnerability was found in the register.php page of PuneethReddyHC Event Management System 1.0, where the event_id GET parameter is improperly handled. An attacker can craft a malicious URL to execute arbitrary JavaScript in the victim s browser by injecting code into this parameter.

- [https://github.com/hafizgemilang/CVE-2025-56243](https://github.com/hafizgemilang/CVE-2025-56243) :  ![starts](https://img.shields.io/github/stars/hafizgemilang/CVE-2025-56243.svg) ![forks](https://img.shields.io/github/forks/hafizgemilang/CVE-2025-56243.svg)


## CVE-2025-53786
 On April 18th 2025, Microsoft announced Exchange Server Security Changes for Hybrid Deployments and accompanying non-security Hot Fix. Microsoft made these changes in the general interest of improving the security of hybrid Exchange deployments. Following further investigation, Microsoft identified specific security implications tied to the guidance and configuration steps outlined in the April announcement. Microsoft is issuing CVE-2025-53786 to document a vulnerability that is addressed by taking the steps documented with the April 18th announcement. Microsoft strongly recommends reading the information, installing the April 2025 (or later) Hot Fix and implementing the changes in your Exchange Server and hybrid environment.

- [https://github.com/vincentdthe/CVE-2025-53786](https://github.com/vincentdthe/CVE-2025-53786) :  ![starts](https://img.shields.io/github/stars/vincentdthe/CVE-2025-53786.svg) ![forks](https://img.shields.io/github/forks/vincentdthe/CVE-2025-53786.svg)


## CVE-2025-52021
 A SQL Injection vulnerability exists in the edit_product.php file of PuneethReddyHC Online Shopping System Advanced 1.0. The product_id GET parameter is unsafely passed to a SQL query without proper validation or parameterization.

- [https://github.com/hafizgemilang/CVE-2025-52021](https://github.com/hafizgemilang/CVE-2025-52021) :  ![starts](https://img.shields.io/github/stars/hafizgemilang/CVE-2025-52021.svg) ![forks](https://img.shields.io/github/forks/hafizgemilang/CVE-2025-52021.svg)


## CVE-2025-50505
 Clash Verge Rev thru 2.2.3 forces the installation of system services(clash-verge-service) by default and exposes key functions through the unauthorized HTTP API `/start_clash`, allowing local users to submit arbitrary bin_path parameters and pass them directly to the service process for execution, resulting in local privilege escalation.

- [https://github.com/bron1e/CVE-2025-50505](https://github.com/bron1e/CVE-2025-50505) :  ![starts](https://img.shields.io/github/stars/bron1e/CVE-2025-50505.svg) ![forks](https://img.shields.io/github/forks/bron1e/CVE-2025-50505.svg)


## CVE-2025-49844
 Redis is an open source, in-memory database that persists on disk. Versions 8.2.1 and below allow an authenticated user to use a specially crafted Lua script to manipulate the garbage collector, trigger a use-after-free and potentially lead to remote code execution. The problem exists in all versions of Redis with Lua scripting. This issue is fixed in version 8.2.2. To workaround this issue without patching the redis-server executable is to prevent users from executing Lua scripts. This can be done using ACL to restrict EVAL and EVALSHA commands.

- [https://github.com/dwisiswant0/CVE-2025-49844](https://github.com/dwisiswant0/CVE-2025-49844) :  ![starts](https://img.shields.io/github/stars/dwisiswant0/CVE-2025-49844.svg) ![forks](https://img.shields.io/github/forks/dwisiswant0/CVE-2025-49844.svg)
- [https://github.com/lastvocher/redis-CVE-2025-49844](https://github.com/lastvocher/redis-CVE-2025-49844) :  ![starts](https://img.shields.io/github/stars/lastvocher/redis-CVE-2025-49844.svg) ![forks](https://img.shields.io/github/forks/lastvocher/redis-CVE-2025-49844.svg)
- [https://github.com/gopinaath/CVE-2025-49844-discovery](https://github.com/gopinaath/CVE-2025-49844-discovery) :  ![starts](https://img.shields.io/github/stars/gopinaath/CVE-2025-49844-discovery.svg) ![forks](https://img.shields.io/github/forks/gopinaath/CVE-2025-49844-discovery.svg)


## CVE-2025-48827
 vBulletin 5.0.0 through 5.7.5 and 6.0.0 through 6.0.3 allows unauthenticated users to invoke protected API controllers' methods when running on PHP 8.1 or later, as demonstrated by the /api.php?method=protectedMethod pattern, as exploited in the wild in May 2025.

- [https://github.com/zr1p3r/CVE-2025-48827](https://github.com/zr1p3r/CVE-2025-48827) :  ![starts](https://img.shields.io/github/stars/zr1p3r/CVE-2025-48827.svg) ![forks](https://img.shields.io/github/forks/zr1p3r/CVE-2025-48827.svg)


## CVE-2025-47812
 In Wing FTP Server before 7.4.4. the user and admin web interfaces mishandle '\0' bytes, ultimately allowing injection of arbitrary Lua code into user session files. This can be used to execute arbitrary system commands with the privileges of the FTP service (root or SYSTEM by default). This is thus a remote code execution vulnerability that guarantees a total server compromise. This is also exploitable via anonymous FTP accounts.

- [https://github.com/zr1p3r/CVE-2025-47812](https://github.com/zr1p3r/CVE-2025-47812) :  ![starts](https://img.shields.io/github/stars/zr1p3r/CVE-2025-47812.svg) ![forks](https://img.shields.io/github/forks/zr1p3r/CVE-2025-47812.svg)


## CVE-2025-46819
 Redis is an open source, in-memory database that persists on disk. Versions 8.2.1 and below allow an authenticated user to use a specially crafted LUA script to read out-of-bound data or crash the server and subsequent denial of service. The problem exists in all versions of Redis with Lua scripting. This issue is fixed in version 8.2.2. To workaround this issue without patching the redis-server executable is to prevent users from executing Lua scripts. This can be done using ACL to block a script by restricting both the EVAL and FUNCTION command families.

- [https://github.com/dwisiswant0/CVE-2025-46819](https://github.com/dwisiswant0/CVE-2025-46819) :  ![starts](https://img.shields.io/github/stars/dwisiswant0/CVE-2025-46819.svg) ![forks](https://img.shields.io/github/forks/dwisiswant0/CVE-2025-46819.svg)


## CVE-2025-46818
 Redis is an open source, in-memory database that persists on disk. Versions 8.2.1 and below allow an authenticated user to use a specially crafted Lua script to manipulate different LUA objects and potentially run their own code in the context of another user. The problem exists in all versions of Redis with LUA scripting. This issue is fixed in version 8.2.2. A workaround to mitigate the problem without patching the redis-server executable is to prevent users from executing LUA scripts. This can be done using ACL to block a script by restricting both the EVAL and FUNCTION command families.

- [https://github.com/dwisiswant0/CVE-2025-46818](https://github.com/dwisiswant0/CVE-2025-46818) :  ![starts](https://img.shields.io/github/stars/dwisiswant0/CVE-2025-46818.svg) ![forks](https://img.shields.io/github/forks/dwisiswant0/CVE-2025-46818.svg)


## CVE-2025-46817
 Redis is an open source, in-memory database that persists on disk. Versions 8.2.1 and below allow an authenticated user to use a specially crafted Lua script to cause an integer overflow and potentially lead to remote code execution The problem exists in all versions of Redis with Lua scripting. This issue is fixed in version 8.2.2.

- [https://github.com/dwisiswant0/CVE-2025-46817](https://github.com/dwisiswant0/CVE-2025-46817) :  ![starts](https://img.shields.io/github/stars/dwisiswant0/CVE-2025-46817.svg) ![forks](https://img.shields.io/github/forks/dwisiswant0/CVE-2025-46817.svg)


## CVE-2025-44823
 Nagios Log Server before 2024R1.3.2 allows authenticated users to retrieve cleartext administrative API keys via a /nagioslogserver/index.php/api/system/get_users call. This is GL:NLS#475.

- [https://github.com/skraft9/CVE-2025-44823](https://github.com/skraft9/CVE-2025-44823) :  ![starts](https://img.shields.io/github/stars/skraft9/CVE-2025-44823.svg) ![forks](https://img.shields.io/github/forks/skraft9/CVE-2025-44823.svg)


## CVE-2025-34085
 This CVE ID has been rejected or withdrawn by its CVE Numbering Authority as it is a duplicate of CVE-2020-36847.

- [https://github.com/zr1p3r/CVE-2025-34085](https://github.com/zr1p3r/CVE-2025-34085) :  ![starts](https://img.shields.io/github/stars/zr1p3r/CVE-2025-34085.svg) ![forks](https://img.shields.io/github/forks/zr1p3r/CVE-2025-34085.svg)


## CVE-2025-34077
 An authentication bypass vulnerability exists in the WordPress Pie Register plugin ≤ 3.7.1.4 that allows unauthenticated attackers to impersonate arbitrary users by submitting a crafted POST request to the login endpoint. By setting social_site=true and manipulating the user_id_social_site parameter, an attacker can generate a valid WordPress session cookie for any user ID, including administrators. Once authenticated, the attacker may exploit plugin upload functionality to install a malicious plugin containing arbitrary PHP code, resulting in remote code execution on the underlying server.

- [https://github.com/zr1p3r/CVE-2025-34077](https://github.com/zr1p3r/CVE-2025-34077) :  ![starts](https://img.shields.io/github/stars/zr1p3r/CVE-2025-34077.svg) ![forks](https://img.shields.io/github/forks/zr1p3r/CVE-2025-34077.svg)


## CVE-2025-32463
 Sudo before 1.9.17p1 allows local users to obtain root access because /etc/nsswitch.conf from a user-controlled directory is used with the --chroot option.

- [https://github.com/harsh1verma/CVE-Analysis](https://github.com/harsh1verma/CVE-Analysis) :  ![starts](https://img.shields.io/github/stars/harsh1verma/CVE-Analysis.svg) ![forks](https://img.shields.io/github/forks/harsh1verma/CVE-Analysis.svg)


## CVE-2025-32462
 Sudo before 1.9.17p1, when used with a sudoers file that specifies a host that is neither the current host nor ALL, allows listed users to execute commands on unintended machines.

- [https://github.com/harsh1verma/CVE-Analysis](https://github.com/harsh1verma/CVE-Analysis) :  ![starts](https://img.shields.io/github/stars/harsh1verma/CVE-Analysis.svg) ![forks](https://img.shields.io/github/forks/harsh1verma/CVE-Analysis.svg)


## CVE-2025-31161
 CrushFTP 10 before 10.8.4 and 11 before 11.3.1 allows authentication bypass and takeover of the crushadmin account (unless a DMZ proxy instance is used), as exploited in the wild in March and April 2025, aka "Unauthenticated HTTP(S) port access." A race condition exists in the AWS4-HMAC (compatible with S3) authorization method of the HTTP component of the FTP server. The server first verifies the existence of the user by performing a call to login_user_pass() with no password requirement. This will authenticate the session through the HMAC verification process and up until the server checks for user verification once more. The vulnerability can be further stabilized, eliminating the need for successfully triggering a race condition, by sending a mangled AWS4-HMAC header. By providing only the username and a following slash (/), the server will successfully find a username, which triggers the successful anypass authentication process, but the server will fail to find the expected SignedHeaders entry, resulting in an index-out-of-bounds error that stops the code from reaching the session cleanup. Together, these issues make it trivial to authenticate as any known or guessable user (e.g., crushadmin), and can lead to a full compromise of the system by obtaining an administrative account.

- [https://github.com/zr1p3r/CVE-2025-31161](https://github.com/zr1p3r/CVE-2025-31161) :  ![starts](https://img.shields.io/github/stars/zr1p3r/CVE-2025-31161.svg) ![forks](https://img.shields.io/github/forks/zr1p3r/CVE-2025-31161.svg)


## CVE-2025-31125
 Vite is a frontend tooling framework for javascript. Vite exposes content of non-allowed files using ?inline&import or ?raw?import. Only apps explicitly exposing the Vite dev server to the network (using --host or server.host config option) are affected. This vulnerability is fixed in 6.2.4, 6.1.3, 6.0.13, 5.4.16, and 4.5.11.

- [https://github.com/zr1p3r/CVE-2025-31125](https://github.com/zr1p3r/CVE-2025-31125) :  ![starts](https://img.shields.io/github/stars/zr1p3r/CVE-2025-31125.svg) ![forks](https://img.shields.io/github/forks/zr1p3r/CVE-2025-31125.svg)


## CVE-2025-25257
 An improper neutralization of special elements used in an SQL command ('SQL Injection') vulnerability [CWE-89] in Fortinet FortiWeb version 7.6.0 through 7.6.3, 7.4.0 through 7.4.7, 7.2.0 through 7.2.10 and below 7.0.10 allows an unauthenticated attacker to execute unauthorized SQL code or commands via crafted HTTP or HTTPs requests.

- [https://github.com/zr1p3r/CVE-2025-25257](https://github.com/zr1p3r/CVE-2025-25257) :  ![starts](https://img.shields.io/github/stars/zr1p3r/CVE-2025-25257.svg) ![forks](https://img.shields.io/github/forks/zr1p3r/CVE-2025-25257.svg)


## CVE-2025-7441
 The StoryChief plugin for WordPress is vulnerable to arbitrary file uploads in all versions up to, and including, 1.0.42. This vulnerability occurs through the /wp-json/storychief/webhook REST-API endpoint that does not have sufficient filetype validation. This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible.

- [https://github.com/Nxploited/CVE-2025-7441](https://github.com/Nxploited/CVE-2025-7441) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-7441.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-7441.svg)


## CVE-2025-7401
 The Premium Age Verification / Restriction for WordPress plugin for WordPress is vulnerable to arbitrary file read and write due to the existence of an insufficiently protected remote support functionality in remote_tunnel.php in all versions up to, and including, 3.0.2. This makes it possible for unauthenticated attackers to read from or write to arbitrary files on the affected site's server which may make the exposure of sensitive information or remote code execution possible.

- [https://github.com/Nxploited/CVE-2025-7401](https://github.com/Nxploited/CVE-2025-7401) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-7401.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-7401.svg)


## CVE-2025-6934
 The Opal Estate Pro – Property Management and Submission plugin for WordPress, used by the FullHouse - Real Estate Responsive WordPress Theme, is vulnerable to privilege escalation via in all versions up to, and including, 1.7.5. This is due to a lack of role restriction during registration in the 'on_regiser_user' function. This makes it possible for unauthenticated attackers to arbitrarily choose the role, including the Administrator role, assigned when registering.

- [https://github.com/zr1p3r/CVE-2025-6934](https://github.com/zr1p3r/CVE-2025-6934) :  ![starts](https://img.shields.io/github/stars/zr1p3r/CVE-2025-6934.svg) ![forks](https://img.shields.io/github/forks/zr1p3r/CVE-2025-6934.svg)


## CVE-2025-6384
This issue affects CrafterCMS: from 4.0.0 through 4.2.2.

- [https://github.com/maestro-ant/CrafterCMS-CVE-2025-6384](https://github.com/maestro-ant/CrafterCMS-CVE-2025-6384) :  ![starts](https://img.shields.io/github/stars/maestro-ant/CrafterCMS-CVE-2025-6384.svg) ![forks](https://img.shields.io/github/forks/maestro-ant/CrafterCMS-CVE-2025-6384.svg)


## CVE-2025-6058
 The WPBookit plugin for WordPress is vulnerable to arbitrary file uploads due to missing file type validation in the image_upload_handle() function hooked via the 'add_booking_type' route in all versions up to, and including, 1.0.4. This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible.

- [https://github.com/zr1p3r/CVE-2025-6058](https://github.com/zr1p3r/CVE-2025-6058) :  ![starts](https://img.shields.io/github/stars/zr1p3r/CVE-2025-6058.svg) ![forks](https://img.shields.io/github/forks/zr1p3r/CVE-2025-6058.svg)


## CVE-2025-5777
 Insufficient input validation leading to memory overread when the NetScaler is configured as a Gateway (VPN virtual server, ICA Proxy, CVPN, RDP Proxy) OR AAA virtual server

- [https://github.com/zr1p3r/CVE-2025-5777](https://github.com/zr1p3r/CVE-2025-5777) :  ![starts](https://img.shields.io/github/stars/zr1p3r/CVE-2025-5777.svg) ![forks](https://img.shields.io/github/forks/zr1p3r/CVE-2025-5777.svg)


## CVE-2025-4334
 The Simple User Registration plugin for WordPress is vulnerable to Privilege Escalation in all versions up to, and including, 6.3. This is due to insufficient restrictions on user meta values that can be supplied during registration. This makes it possible for unauthenticated attackers to register as an administrator.

- [https://github.com/zr1p3r/CVE-2025-4334](https://github.com/zr1p3r/CVE-2025-4334) :  ![starts](https://img.shields.io/github/stars/zr1p3r/CVE-2025-4334.svg) ![forks](https://img.shields.io/github/forks/zr1p3r/CVE-2025-4334.svg)


## CVE-2025-3248
code.

- [https://github.com/zr1p3r/CVE-2025-3248](https://github.com/zr1p3r/CVE-2025-3248) :  ![starts](https://img.shields.io/github/stars/zr1p3r/CVE-2025-3248.svg) ![forks](https://img.shields.io/github/forks/zr1p3r/CVE-2025-3248.svg)


## CVE-2025-3102
 The SureTriggers: All-in-One Automation Platform plugin for WordPress is vulnerable to an authentication bypass leading to administrative account creation due to a missing empty value check on the 'secret_key' value in the 'autheticate_user' function in all versions up to, and including, 1.0.78. This makes it possible for unauthenticated attackers to create administrator accounts on the target website when the plugin is installed and activated but not configured with an API key.

- [https://github.com/zr1p3r/CVE-2025-3102](https://github.com/zr1p3r/CVE-2025-3102) :  ![starts](https://img.shields.io/github/stars/zr1p3r/CVE-2025-3102.svg) ![forks](https://img.shields.io/github/forks/zr1p3r/CVE-2025-3102.svg)


## CVE-2024-39309
 Parse Server is an open source backend that can be deployed to any infrastructure that can run Node.js. A vulnerability in versions prior to 6.5.7 and 7.1.0 allows SQL injection when Parse Server is configured to use the PostgreSQL database. The algorithm to detect SQL injection has been improved in versions 6.5.7 and 7.1.0. No known workarounds are available.

- [https://github.com/HeavyGhost-le/POC_SQL_injection_in_Parse_Server_prior_6.5.7_-_7.1.0](https://github.com/HeavyGhost-le/POC_SQL_injection_in_Parse_Server_prior_6.5.7_-_7.1.0) :  ![starts](https://img.shields.io/github/stars/HeavyGhost-le/POC_SQL_injection_in_Parse_Server_prior_6.5.7_-_7.1.0.svg) ![forks](https://img.shields.io/github/forks/HeavyGhost-le/POC_SQL_injection_in_Parse_Server_prior_6.5.7_-_7.1.0.svg)


## CVE-2024-38819
 Applications serving static resources through the functional web frameworks WebMvc.fn or WebFlux.fn are vulnerable to path traversal attacks. An attacker can craft malicious HTTP requests and obtain any file on the file system that is also accessible to the process in which the Spring application is running.

- [https://github.com/Nandavardhan8/spring-poc-CVE-2024-38819](https://github.com/Nandavardhan8/spring-poc-CVE-2024-38819) :  ![starts](https://img.shields.io/github/stars/Nandavardhan8/spring-poc-CVE-2024-38819.svg) ![forks](https://img.shields.io/github/forks/Nandavardhan8/spring-poc-CVE-2024-38819.svg)


## CVE-2024-37742
 Insecure Access Control in Safe Exam Browser (SEB) = 3.5.0 on Windows. The vulnerability allows an attacker to share clipboard data between the SEB kiosk mode and the underlying system, compromising exam integrity. By exploiting this flaw, an attacker can bypass exam controls and gain an unfair advantage during exams.

- [https://github.com/Aar0nD0m1n1c/CVE-2024-37742](https://github.com/Aar0nD0m1n1c/CVE-2024-37742) :  ![starts](https://img.shields.io/github/stars/Aar0nD0m1n1c/CVE-2024-37742.svg) ![forks](https://img.shields.io/github/forks/Aar0nD0m1n1c/CVE-2024-37742.svg)


## CVE-2022-0739
 The BookingPress WordPress plugin before 1.0.11 fails to properly sanitize user supplied POST data before it is used in a dynamically constructed SQL query via the bookingpress_front_get_category_services AJAX action (available to unauthenticated users), leading to an unauthenticated SQL Injection

- [https://github.com/Manjen1218/CVE-2022-0739-Exploitation](https://github.com/Manjen1218/CVE-2022-0739-Exploitation) :  ![starts](https://img.shields.io/github/stars/Manjen1218/CVE-2022-0739-Exploitation.svg) ![forks](https://img.shields.io/github/forks/Manjen1218/CVE-2022-0739-Exploitation.svg)


## CVE-2017-7921
 An Improper Authentication issue was discovered in Hikvision DS-2CD2xx2F-I Series V5.2.0 build 140721 to V5.4.0 build 160530, DS-2CD2xx0F-I Series V5.2.0 build 140721 to V5.4.0 Build 160401, DS-2CD2xx2FWD Series V5.3.1 build 150410 to V5.4.4 Build 161125, DS-2CD4x2xFWD Series V5.2.0 build 140721 to V5.4.0 Build 160414, DS-2CD4xx5 Series V5.2.0 build 140721 to V5.4.0 Build 160421, DS-2DFx Series V5.2.0 build 140805 to V5.4.5 Build 160928, and DS-2CD63xx Series V5.0.9 build 140305 to V5.3.5 Build 160106 devices. The improper authentication vulnerability occurs when an application does not adequately or correctly authenticate users. This may allow a malicious user to escalate his or her privileges on the system and gain access to sensitive information.

- [https://github.com/lastvocher/Hikvision-CVE-2017-7921-decryptor](https://github.com/lastvocher/Hikvision-CVE-2017-7921-decryptor) :  ![starts](https://img.shields.io/github/stars/lastvocher/Hikvision-CVE-2017-7921-decryptor.svg) ![forks](https://img.shields.io/github/forks/lastvocher/Hikvision-CVE-2017-7921-decryptor.svg)


## CVE-2008-5161
 Error handling in the SSH protocol in (1) SSH Tectia Client and Server and Connector 4.0 through 4.4.11, 5.0 through 5.2.4, and 5.3 through 5.3.8; Client and Server and ConnectSecure 6.0 through 6.0.4; Server for Linux on IBM System z 6.0.4; Server for IBM z/OS 5.5.1 and earlier, 6.0.0, and 6.0.1; and Client 4.0-J through 4.3.3-J and 4.0-K through 4.3.10-K; and (2) OpenSSH 4.7p1 and possibly other versions, when using a block cipher algorithm in Cipher Block Chaining (CBC) mode, makes it easier for remote attackers to recover certain plaintext data from an arbitrary block of ciphertext in an SSH session via unknown vectors.

- [https://github.com/talha3117/OpenSSH-4.7p1-CVE-2008-5161-Exploit](https://github.com/talha3117/OpenSSH-4.7p1-CVE-2008-5161-Exploit) :  ![starts](https://img.shields.io/github/stars/talha3117/OpenSSH-4.7p1-CVE-2008-5161-Exploit.svg) ![forks](https://img.shields.io/github/forks/talha3117/OpenSSH-4.7p1-CVE-2008-5161-Exploit.svg)

