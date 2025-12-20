# Update 2025-12-20
## CVE-2025-68434
 Open Source Point of Sale (opensourcepos) is a web based point of sale application written in PHP using CodeIgniter framework. Starting in version 3.4.0 and prior to version 3.4.2, a Cross-Site Request Forgery (CSRF) vulnerability exists in the application's filter configuration. The CSRF protection mechanism was **explicitly disabled**, allowing the application to process state-changing requests (POST) without verifying a valid CSRF token. An unauthenticated remote attacker can exploit this by hosting a malicious web page. If a logged-in administrator visits this page, their browser is forced to send unauthorized requests to the application. A successful exploit allows the attacker to silently create a new Administrator account with full privileges, leading to a complete takeover of the system and loss of confidentiality, integrity, and availability. The vulnerability has been patched in version 3.4.2. The fix re-enables the CSRF filter in `app/Config/Filters.php` and resolves associated AJAX race conditions by adjusting token regeneration settings. As a workaround, administrators can manually re-enable the CSRF filter in `app/Config/Filters.php` by uncommenting the protection line. However, this is not recommended without applying the full patch, as it may cause functionality breakage in the Sales module due to token synchronization issues.

- [https://github.com/Nixon-H/CVE-2025-68434-OSPOS-CSRF](https://github.com/Nixon-H/CVE-2025-68434-OSPOS-CSRF) :  ![starts](https://img.shields.io/github/stars/Nixon-H/CVE-2025-68434-OSPOS-CSRF.svg) ![forks](https://img.shields.io/github/forks/Nixon-H/CVE-2025-68434-OSPOS-CSRF.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/aleksandrova834/react2shell-bypasswaf](https://github.com/aleksandrova834/react2shell-bypasswaf) :  ![starts](https://img.shields.io/github/stars/aleksandrova834/react2shell-bypasswaf.svg) ![forks](https://img.shields.io/github/forks/aleksandrova834/react2shell-bypasswaf.svg)


## CVE-2025-63353
 A vulnerability in FiberHome GPON ONU HG6145F1 RP4423 allows the device's factory default Wi-Fi password (WPA/WPA2 pre-shared key) to be predicted from the SSID. The device generates default passwords using a deterministic algorithm that derives the router passphrase from the SSID, enabling an attacker who can observe the SSID to predict the default password without authentication or user interaction.

- [https://github.com/0xA1M/CVE-2025-63353](https://github.com/0xA1M/CVE-2025-63353) :  ![starts](https://img.shields.io/github/stars/0xA1M/CVE-2025-63353.svg) ![forks](https://img.shields.io/github/forks/0xA1M/CVE-2025-63353.svg)


## CVE-2025-62470
 Heap-based buffer overflow in Windows Common Log File System Driver allows an authorized attacker to elevate privileges locally.

- [https://github.com/96613686/CVE-2025-62470](https://github.com/96613686/CVE-2025-62470) :  ![starts](https://img.shields.io/github/stars/96613686/CVE-2025-62470.svg) ![forks](https://img.shields.io/github/forks/96613686/CVE-2025-62470.svg)


## CVE-2025-62454
 Heap-based buffer overflow in Windows Cloud Files Mini Filter Driver allows an authorized attacker to elevate privileges locally.

- [https://github.com/96613686/CVE-2025-62454](https://github.com/96613686/CVE-2025-62454) :  ![starts](https://img.shields.io/github/stars/96613686/CVE-2025-62454.svg) ![forks](https://img.shields.io/github/forks/96613686/CVE-2025-62454.svg)


## CVE-2025-55184
 A pre-authentication denial of service vulnerability exists in React Server Components versions 19.0.0, 19.0.1 19.1.0, 19.1.1, 19.1.2, 19.2.0 and 19.2.1, including the following packages: react-server-dom-parcel, react-server-dom-turbopack, and react-server-dom-webpack. The vulnerable code unsafely deserializes payloads from HTTP requests to Server Function endpoints, which can cause an infinite loop that hangs the server process and may prevent future HTTP requests from being served.

- [https://github.com/KkHackingLearning/CVE-2025-55184_Testing](https://github.com/KkHackingLearning/CVE-2025-55184_Testing) :  ![starts](https://img.shields.io/github/stars/KkHackingLearning/CVE-2025-55184_Testing.svg) ![forks](https://img.shields.io/github/forks/KkHackingLearning/CVE-2025-55184_Testing.svg)


## CVE-2025-55182
 A pre-authentication remote code execution vulnerability exists in React Server Components versions 19.0.0, 19.1.0, 19.1.1, and 19.2.0 including the following packages: react-server-dom-parcel, react-server-dom-turbopack, and react-server-dom-webpack. The vulnerable code unsafely deserializes payloads from HTTP requests to Server Function endpoints.

- [https://github.com/zr0n/react2shell](https://github.com/zr0n/react2shell) :  ![starts](https://img.shields.io/github/stars/zr0n/react2shell.svg) ![forks](https://img.shields.io/github/forks/zr0n/react2shell.svg)


## CVE-2025-40602
 A local privilege escalation vulnerability due to insufficient authorization in the SonicWall SMA1000 appliance management console (AMC).

- [https://github.com/rxerium/CVE-2025-40602](https://github.com/rxerium/CVE-2025-40602) :  ![starts](https://img.shields.io/github/stars/rxerium/CVE-2025-40602.svg) ![forks](https://img.shields.io/github/forks/rxerium/CVE-2025-40602.svg)


## CVE-2025-37164
 A remote code execution issue exists in HPE OneView.

- [https://github.com/rxerium/CVE-2025-37164](https://github.com/rxerium/CVE-2025-37164) :  ![starts](https://img.shields.io/github/stars/rxerium/CVE-2025-37164.svg) ![forks](https://img.shields.io/github/forks/rxerium/CVE-2025-37164.svg)


## CVE-2025-33053
 External control of file name or path in Internet Shortcut Files allows an unauthorized attacker to execute code over a network.

- [https://github.com/Cyberw1ng/CVE-2025-33053-POC](https://github.com/Cyberw1ng/CVE-2025-33053-POC) :  ![starts](https://img.shields.io/github/stars/Cyberw1ng/CVE-2025-33053-POC.svg) ![forks](https://img.shields.io/github/forks/Cyberw1ng/CVE-2025-33053-POC.svg)


## CVE-2025-20393
 Cisco is aware of a potential vulnerability.&nbsp; Cisco is currently investigating and&nbsp;will update these details as appropriate&nbsp;as more information becomes available.

- [https://github.com/StasonJatham/cisco-sa-sma-attack-N9bf4](https://github.com/StasonJatham/cisco-sa-sma-attack-N9bf4) :  ![starts](https://img.shields.io/github/stars/StasonJatham/cisco-sa-sma-attack-N9bf4.svg) ![forks](https://img.shields.io/github/forks/StasonJatham/cisco-sa-sma-attack-N9bf4.svg)
- [https://github.com/thesystemowner/CVE-2025-20393-POC](https://github.com/thesystemowner/CVE-2025-20393-POC) :  ![starts](https://img.shields.io/github/stars/thesystemowner/CVE-2025-20393-POC.svg) ![forks](https://img.shields.io/github/forks/thesystemowner/CVE-2025-20393-POC.svg)
- [https://github.com/b1gchoi/CVE-2025-20393](https://github.com/b1gchoi/CVE-2025-20393) :  ![starts](https://img.shields.io/github/stars/b1gchoi/CVE-2025-20393.svg) ![forks](https://img.shields.io/github/forks/b1gchoi/CVE-2025-20393.svg)
- [https://github.com/KingHacker353/CVE-2025-20393](https://github.com/KingHacker353/CVE-2025-20393) :  ![starts](https://img.shields.io/github/stars/KingHacker353/CVE-2025-20393.svg) ![forks](https://img.shields.io/github/forks/KingHacker353/CVE-2025-20393.svg)
- [https://github.com/cyberleelawat/CVE-2025-20393](https://github.com/cyberleelawat/CVE-2025-20393) :  ![starts](https://img.shields.io/github/stars/cyberleelawat/CVE-2025-20393.svg) ![forks](https://img.shields.io/github/forks/cyberleelawat/CVE-2025-20393.svg)


## CVE-2025-14700
 An input neutralization vulnerability in the Webhook Template component of Crafty Controller allows a remote, authenticated attacker to perform remote code execution via Server Side Template Injection.

- [https://github.com/secdongle/POC_CVE-2025-14700](https://github.com/secdongle/POC_CVE-2025-14700) :  ![starts](https://img.shields.io/github/stars/secdongle/POC_CVE-2025-14700.svg) ![forks](https://img.shields.io/github/forks/secdongle/POC_CVE-2025-14700.svg)


## CVE-2025-14440
 The JAY Login & Register plugin for WordPress is vulnerable to authentication bypass in versions up to, and including, 2.4.01. This is due to incorrect authentication checking in the 'jay_login_register_process_switch_back' function with the 'jay_login_register_process_switch_back' cookie value. This makes it possible for unauthenticated attackers to log in as any existing user on the site, such as an administrator, if they have access to the user id.

- [https://github.com/Nxploited/CVE-2025-14440](https://github.com/Nxploited/CVE-2025-14440) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-14440.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-14440.svg)


## CVE-2025-14174
 Out of bounds memory access in ANGLE in Google Chrome on Mac prior to 143.0.7499.110 allowed a remote attacker to perform out of bounds memory access via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/Satirush/CVE-2025-14174-Poc](https://github.com/Satirush/CVE-2025-14174-Poc) :  ![starts](https://img.shields.io/github/stars/Satirush/CVE-2025-14174-Poc.svg) ![forks](https://img.shields.io/github/forks/Satirush/CVE-2025-14174-Poc.svg)


## CVE-2025-14156
 The Fox LMS – WordPress LMS Plugin plugin for WordPress is vulnerable to privilege escalation in all versions up to, and including, 1.0.5.1. This is due to the plugin not properly validating the 'role' parameter when creating new users via the `/fox-lms/v1/payments/create-order` REST API endpoint. This makes it possible for unauthenticated attackers to create new user accounts with arbitrary roles, including administrator, leading to complete site compromise.

- [https://github.com/Nxploited/CVE-2025-14156](https://github.com/Nxploited/CVE-2025-14156) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-14156.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-14156.svg)


## CVE-2025-6788
diagrams.

- [https://github.com/reewardius/CVE-2025-67888](https://github.com/reewardius/CVE-2025-67888) :  ![starts](https://img.shields.io/github/stars/reewardius/CVE-2025-67888.svg) ![forks](https://img.shields.io/github/forks/reewardius/CVE-2025-67888.svg)
- [https://github.com/reewardius/CVE-2025-67887](https://github.com/reewardius/CVE-2025-67887) :  ![starts](https://img.shields.io/github/stars/reewardius/CVE-2025-67887.svg) ![forks](https://img.shields.io/github/forks/reewardius/CVE-2025-67887.svg)
- [https://github.com/reewardius/CVE-2025-67886](https://github.com/reewardius/CVE-2025-67886) :  ![starts](https://img.shields.io/github/stars/reewardius/CVE-2025-67886.svg) ![forks](https://img.shields.io/github/forks/reewardius/CVE-2025-67886.svg)
- [https://github.com/cyberok-org/CVE-2025-67887](https://github.com/cyberok-org/CVE-2025-67887) :  ![starts](https://img.shields.io/github/stars/cyberok-org/CVE-2025-67887.svg) ![forks](https://img.shields.io/github/forks/cyberok-org/CVE-2025-67887.svg)


## CVE-2025-6729
 The PayMaster for WooCommerce plugin for WordPress is vulnerable to Server-Side Request Forgery in all versions up to, and including, 0.4.31 via the 'wp_ajax_paym_status' AJAX action This makes it possible for authenticated attackers, with Subscriber-level access and above, to make web requests to arbitrary locations originating from the web application and can be used to query and modify information from internal services.

- [https://github.com/0xthem7/CVE-2025-67294](https://github.com/0xthem7/CVE-2025-67294) :  ![starts](https://img.shields.io/github/stars/0xthem7/CVE-2025-67294.svg) ![forks](https://img.shields.io/github/forks/0xthem7/CVE-2025-67294.svg)


## CVE-2025-6554
 Type confusion in V8 in Google Chrome prior to 138.0.7204.96 allowed a remote attacker to perform arbitrary read/write via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/juccoblak/CVE-2025-6554](https://github.com/juccoblak/CVE-2025-6554) :  ![starts](https://img.shields.io/github/stars/juccoblak/CVE-2025-6554.svg) ![forks](https://img.shields.io/github/forks/juccoblak/CVE-2025-6554.svg)


## CVE-2024-1900
The user will stay authenticated until the Devolutions Server token expiration.

- [https://github.com/anonymous-echo/cve-2024-19002](https://github.com/anonymous-echo/cve-2024-19002) :  ![starts](https://img.shields.io/github/stars/anonymous-echo/cve-2024-19002.svg) ![forks](https://img.shields.io/github/forks/anonymous-echo/cve-2024-19002.svg)


## CVE-2024-0204
 Authentication bypass in Fortra's GoAnywhere MFT prior to 7.4.1 allows an unauthorized user to create an admin user via the administration portal.

- [https://github.com/anonymous-echo/CVE-2024-0204](https://github.com/anonymous-echo/CVE-2024-0204) :  ![starts](https://img.shields.io/github/stars/anonymous-echo/CVE-2024-0204.svg) ![forks](https://img.shields.io/github/forks/anonymous-echo/CVE-2024-0204.svg)


## CVE-2023-27350
 This vulnerability allows remote attackers to bypass authentication on affected installations of PaperCut NG 22.0.5 (Build 63914). Authentication is not required to exploit this vulnerability. The specific flaw exists within the SetupCompleted class. The issue results from improper access control. An attacker can leverage this vulnerability to bypass authentication and execute arbitrary code in the context of SYSTEM. Was ZDI-CAN-18987.

- [https://github.com/dezso-dfield/CVE-2023-27350](https://github.com/dezso-dfield/CVE-2023-27350) :  ![starts](https://img.shields.io/github/stars/dezso-dfield/CVE-2023-27350.svg) ![forks](https://img.shields.io/github/forks/dezso-dfield/CVE-2023-27350.svg)


## CVE-2023-5204
 The ChatBot plugin for WordPress is vulnerable to SQL Injection via the $strid parameter in versions up to, and including, 4.8.9 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query.  This makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database.

- [https://github.com/RandomRobbieBF/CVE-2023-5204](https://github.com/RandomRobbieBF/CVE-2023-5204) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2023-5204.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2023-5204.svg)


## CVE-2023-0704
 Insufficient policy enforcement in DevTools in Google Chrome prior to 110.0.5481.77 allowed a remote attacker to bypass same origin policy and proxy settings via a crafted HTML page. (Chromium security severity: Low)

- [https://github.com/hex01e/exploit-CVE-2023-0704](https://github.com/hex01e/exploit-CVE-2023-0704) :  ![starts](https://img.shields.io/github/stars/hex01e/exploit-CVE-2023-0704.svg) ![forks](https://img.shields.io/github/forks/hex01e/exploit-CVE-2023-0704.svg)


## CVE-2022-27254
 The remote keyless system on Honda Civic 2018 vehicles sends the same RF signal for each door-open request, which allows for a replay attack, a related issue to CVE-2019-20626.

- [https://github.com/fbettag/car_breaker_19](https://github.com/fbettag/car_breaker_19) :  ![starts](https://img.shields.io/github/stars/fbettag/car_breaker_19.svg) ![forks](https://img.shields.io/github/forks/fbettag/car_breaker_19.svg)


## CVE-2021-46145
 The keyfob subsystem in Honda Civic 2012 vehicles allows a replay attack for unlocking. This is related to a non-expiring rolling code and counter resynchronization.

- [https://github.com/fbettag/car_breaker_19](https://github.com/fbettag/car_breaker_19) :  ![starts](https://img.shields.io/github/stars/fbettag/car_breaker_19.svg) ![forks](https://img.shields.io/github/forks/fbettag/car_breaker_19.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/ch4os443/CVE-2021-41773](https://github.com/ch4os443/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/ch4os443/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/ch4os443/CVE-2021-41773.svg)

