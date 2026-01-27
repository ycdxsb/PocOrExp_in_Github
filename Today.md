# Update 2026-01-27
## CVE-2026-24422
 phpMyFAQ is an open source FAQ web application. In versions 4.0.16 and below, multiple public API endpoints improperly expose sensitive user information due to insufficient access controls. The OpenQuestionController::list() endpoint calls Question::getAll() with showAll=true by default, returning records marked as non-public (isVisible=false) along with user email addresses, with similar exposures present in comment, news, and FAQ APIs. This information disclosure vulnerability could enable attackers to harvest email addresses for phishing campaigns or access content that was explicitly marked as private. This issue has been fixed in version 4.0.17.

- [https://github.com/boroeurnprach/CVE-2026-24422_PoC](https://github.com/boroeurnprach/CVE-2026-24422_PoC) :  ![starts](https://img.shields.io/github/stars/boroeurnprach/CVE-2026-24422_PoC.svg) ![forks](https://img.shields.io/github/forks/boroeurnprach/CVE-2026-24422_PoC.svg)


## CVE-2026-24061
 telnetd in GNU Inetutils through 2.7 allows remote authentication bypass via a "-f root" value for the USER environment variable.

- [https://github.com/infat0x/CVE-2026-24061](https://github.com/infat0x/CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/infat0x/CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/infat0x/CVE-2026-24061.svg)
- [https://github.com/typeconfused/CVE-2026-24061](https://github.com/typeconfused/CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/typeconfused/CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/typeconfused/CVE-2026-24061.svg)
- [https://github.com/ms0x08-dev/CVE-2026-24061-POC](https://github.com/ms0x08-dev/CVE-2026-24061-POC) :  ![starts](https://img.shields.io/github/stars/ms0x08-dev/CVE-2026-24061-POC.svg) ![forks](https://img.shields.io/github/forks/ms0x08-dev/CVE-2026-24061-POC.svg)
- [https://github.com/Alter-N0X/CVE-2026-24061-POC](https://github.com/Alter-N0X/CVE-2026-24061-POC) :  ![starts](https://img.shields.io/github/stars/Alter-N0X/CVE-2026-24061-POC.svg) ![forks](https://img.shields.io/github/forks/Alter-N0X/CVE-2026-24061-POC.svg)


## CVE-2026-0920
 The LA-Studio Element Kit for Elementor plugin for WordPress is vulnerable to Administrative User Creation in all versions up to, and including, 1.5.6.3. This is due to the 'ajax_register_handle' function not restricting what user roles a user can register with. This makes it possible for unauthenticated attackers to supply the 'lakit_bkrole' parameter during registration and gain administrator access to the site.

- [https://github.com/O99099O/By-Poloss..-..CVE-2026-0920](https://github.com/O99099O/By-Poloss..-..CVE-2026-0920) :  ![starts](https://img.shields.io/github/stars/O99099O/By-Poloss..-..CVE-2026-0920.svg) ![forks](https://img.shields.io/github/forks/O99099O/By-Poloss..-..CVE-2026-0920.svg)


## CVE-2025-68921
 SteelSeries Nahimic 3 1.10.7 allows Directory traversal.

- [https://github.com/kikiuuw/CVE-2025-68921](https://github.com/kikiuuw/CVE-2025-68921) :  ![starts](https://img.shields.io/github/stars/kikiuuw/CVE-2025-68921.svg) ![forks](https://img.shields.io/github/forks/kikiuuw/CVE-2025-68921.svg)
- [https://github.com/kikiuuw/kikiuuw.github.io](https://github.com/kikiuuw/kikiuuw.github.io) :  ![starts](https://img.shields.io/github/stars/kikiuuw/kikiuuw.github.io.svg) ![forks](https://img.shields.io/github/forks/kikiuuw/kikiuuw.github.io.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-15x](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-15x) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-15x.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-15x.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-berry](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-berry) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-berry.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-berry.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-git-dep](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-git-dep) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-git-dep.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-git-dep.svg)


## CVE-2025-55182
 A pre-authentication remote code execution vulnerability exists in React Server Components versions 19.0.0, 19.1.0, 19.1.1, and 19.2.0 including the following packages: react-server-dom-parcel, react-server-dom-turbopack, and react-server-dom-webpack. The vulnerable code unsafely deserializes payloads from HTTP requests to Server Function endpoints.

- [https://github.com/MemerGamer/CVE-2025-55182](https://github.com/MemerGamer/CVE-2025-55182) :  ![starts](https://img.shields.io/github/stars/MemerGamer/CVE-2025-55182.svg) ![forks](https://img.shields.io/github/forks/MemerGamer/CVE-2025-55182.svg)


## CVE-2025-43529
 A use-after-free issue was addressed with improved memory management. This issue is fixed in watchOS 26.2, Safari 26.2, iOS 18.7.3 and iPadOS 18.7.3, iOS 26.2 and iPadOS 26.2, macOS Tahoe 26.2, visionOS 26.2, tvOS 26.2. Processing maliciously crafted web content may lead to arbitrary code execution. Apple is aware of a report that this issue may have been exploited in an extremely sophisticated attack against specific targeted individuals on versions of iOS before iOS 26. CVE-2025-14174 was also issued in response to this report.

- [https://github.com/sakyu7/sakyu7.github.io](https://github.com/sakyu7/sakyu7.github.io) :  ![starts](https://img.shields.io/github/stars/sakyu7/sakyu7.github.io.svg) ![forks](https://img.shields.io/github/forks/sakyu7/sakyu7.github.io.svg)


## CVE-2025-43300
 An out-of-bounds write issue was addressed with improved bounds checking. This issue is fixed in iOS 15.8.5 and iPadOS 15.8.5, iOS 16.7.12 and iPadOS 16.7.12. Processing a malicious image file may result in memory corruption. Apple is aware of a report that this issue may have been exploited in an extremely sophisticated attack against specific targeted individuals.

- [https://github.com/AR-DEV-1/CVE-2025-43300-exp](https://github.com/AR-DEV-1/CVE-2025-43300-exp) :  ![starts](https://img.shields.io/github/stars/AR-DEV-1/CVE-2025-43300-exp.svg) ![forks](https://img.shields.io/github/forks/AR-DEV-1/CVE-2025-43300-exp.svg)


## CVE-2025-36911
 In key-based pairing, there is a possible ID due to a logic error in the code. This could lead to remote (proximal/adjacent) information disclosure of user's conversations and location with no additional execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/aalex954/whisperpair-poc-tool](https://github.com/aalex954/whisperpair-poc-tool) :  ![starts](https://img.shields.io/github/stars/aalex954/whisperpair-poc-tool.svg) ![forks](https://img.shields.io/github/forks/aalex954/whisperpair-poc-tool.svg)


## CVE-2025-14174
 Out of bounds memory access in ANGLE in Google Chrome on Mac prior to 143.0.7499.110 allowed a remote attacker to perform out of bounds memory access via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/sakyu7/sakyu7.github.io](https://github.com/sakyu7/sakyu7.github.io) :  ![starts](https://img.shields.io/github/stars/sakyu7/sakyu7.github.io.svg) ![forks](https://img.shields.io/github/forks/sakyu7/sakyu7.github.io.svg)


## CVE-2025-10042
 The Quiz Maker plugin for WordPress is vulnerable to SQL Injection via spoofed IP headers in all versions up to, and including, 6.7.0.56 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query.  This makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database. This is only exploitable in configurations where the server is set up to retrieve the IP from a user-supplied field like `X-Forwarded-For` and limit users by IP is enabled.

- [https://github.com/fumioryoto/Quiz-Maker-SQL-Injection-CVE-2025-10042](https://github.com/fumioryoto/Quiz-Maker-SQL-Injection-CVE-2025-10042) :  ![starts](https://img.shields.io/github/stars/fumioryoto/Quiz-Maker-SQL-Injection-CVE-2025-10042.svg) ![forks](https://img.shields.io/github/forks/fumioryoto/Quiz-Maker-SQL-Injection-CVE-2025-10042.svg)


## CVE-2025-6526
 A vulnerability, which was classified as problematic, has been found in 70mai M300 up to 20250611. This issue affects some unknown processing of the component HTTP Server. The manipulation leads to insufficiently protected credentials. The attack can only be done within the local network. The complexity of an attack is rather high. The exploitation is known to be difficult. The exploit has been disclosed to the public and may be used. The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/cwjchoi01/CVE-2025-65264](https://github.com/cwjchoi01/CVE-2025-65264) :  ![starts](https://img.shields.io/github/stars/cwjchoi01/CVE-2025-65264.svg) ![forks](https://img.shields.io/github/forks/cwjchoi01/CVE-2025-65264.svg)


## CVE-2025-1094
 Improper neutralization of quoting syntax in PostgreSQL libpq functions PQescapeLiteral(), PQescapeIdentifier(), PQescapeString(), and PQescapeStringConn() allows a database input provider to achieve SQL injection in certain usage patterns.  Specifically, SQL injection requires the application to use the function result to construct input to psql, the PostgreSQL interactive terminal.  Similarly, improper neutralization of quoting syntax in PostgreSQL command line utility programs allows a source of command line arguments to achieve SQL injection when client_encoding is BIG5 and server_encoding is one of EUC_TW or MULE_INTERNAL.  Versions before PostgreSQL 17.3, 16.7, 15.11, 14.16, and 13.19 are affected.

- [https://github.com/Nguyen-Van-Gia-Binh/Fcode-Security-Demo](https://github.com/Nguyen-Van-Gia-Binh/Fcode-Security-Demo) :  ![starts](https://img.shields.io/github/stars/Nguyen-Van-Gia-Binh/Fcode-Security-Demo.svg) ![forks](https://img.shields.io/github/forks/Nguyen-Van-Gia-Binh/Fcode-Security-Demo.svg)


## CVE-2024-21413
 Microsoft Outlook Remote Code Execution Vulnerability

- [https://github.com/dionissh/CVE-2024-21413](https://github.com/dionissh/CVE-2024-21413) :  ![starts](https://img.shields.io/github/stars/dionissh/CVE-2024-21413.svg) ![forks](https://img.shields.io/github/forks/dionissh/CVE-2024-21413.svg)


## CVE-2024-9796
 The WP-Advanced-Search WordPress plugin before 3.3.9.2 does not sanitize and escape the t parameter before using it in a SQL statement, allowing unauthenticated users to perform SQL injection attacks

- [https://github.com/yup-Ivan/CVE-2024-9796](https://github.com/yup-Ivan/CVE-2024-9796) :  ![starts](https://img.shields.io/github/stars/yup-Ivan/CVE-2024-9796.svg) ![forks](https://img.shields.io/github/forks/yup-Ivan/CVE-2024-9796.svg)


## CVE-2024-3094
Through a series of complex obfuscations, the liblzma build process extracts a prebuilt object file from a disguised test file existing in the source code, which is then used to modify specific functions in the liblzma code. This results in a modified liblzma library that can be used by any software linked against this library, intercepting and modifying the data interaction with this library.

- [https://github.com/hackura/xz-cve-2024-3094](https://github.com/hackura/xz-cve-2024-3094) :  ![starts](https://img.shields.io/github/stars/hackura/xz-cve-2024-3094.svg) ![forks](https://img.shields.io/github/forks/hackura/xz-cve-2024-3094.svg)
- [https://github.com/spidygal/CVE-2024-3094-Nmap-NSE-script](https://github.com/spidygal/CVE-2024-3094-Nmap-NSE-script) :  ![starts](https://img.shields.io/github/stars/spidygal/CVE-2024-3094-Nmap-NSE-script.svg) ![forks](https://img.shields.io/github/forks/spidygal/CVE-2024-3094-Nmap-NSE-script.svg)


## CVE-2023-38817
 An issue in Inspect Element Ltd Echo.ac v.5.2.1.0 allows a local attacker to gain privileges via a crafted command to the echo_driver.sys component. NOTE: the vendor's position is that the reported ability for user-mode applications to execute code as NT AUTHORITY\SYSTEM was "deactivated by Microsoft itself."

- [https://github.com/SecSecBurger/CVE-2023-38817](https://github.com/SecSecBurger/CVE-2023-38817) :  ![starts](https://img.shields.io/github/stars/SecSecBurger/CVE-2023-38817.svg) ![forks](https://img.shields.io/github/forks/SecSecBurger/CVE-2023-38817.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/zer0qs/CVE-2021-41773](https://github.com/zer0qs/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/zer0qs/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/zer0qs/CVE-2021-41773.svg)


## CVE-2018-1270
 Spring Framework, versions 5.0 prior to 5.0.5 and versions 4.3 prior to 4.3.15 and older unsupported versions, allow applications to expose STOMP over WebSocket endpoints with a simple, in-memory STOMP broker through the spring-messaging module. A malicious user (or attacker) can craft a message to the broker that can lead to a remote code execution attack.

- [https://github.com/Tom4t0/CVE-2018-1270_EXP](https://github.com/Tom4t0/CVE-2018-1270_EXP) :  ![starts](https://img.shields.io/github/stars/Tom4t0/CVE-2018-1270_EXP.svg) ![forks](https://img.shields.io/github/forks/Tom4t0/CVE-2018-1270_EXP.svg)


## CVE-2017-13156
 An elevation of privilege vulnerability in the Android system (art). Product: Android. Versions: 5.1.1, 6.0, 6.0.1, 7.0, 7.1.1, 7.1.2, 8.0. Android ID A-64211847.

- [https://github.com/l1ackerronin/Janus-Vulnerability-CVE-2017-13156-Exploit](https://github.com/l1ackerronin/Janus-Vulnerability-CVE-2017-13156-Exploit) :  ![starts](https://img.shields.io/github/stars/l1ackerronin/Janus-Vulnerability-CVE-2017-13156-Exploit.svg) ![forks](https://img.shields.io/github/forks/l1ackerronin/Janus-Vulnerability-CVE-2017-13156-Exploit.svg)


## CVE-2015-2291
 (1) IQVW32.sys before 1.3.1.0 and (2) IQVW64.sys before 1.3.1.0 in the Intel Ethernet diagnostics driver for Windows allows local users to cause a denial of service or possibly execute arbitrary code with kernel privileges via a crafted (a) 0x80862013, (b) 0x8086200B, (c) 0x8086200F, or (d) 0x80862007 IOCTL call.

- [https://github.com/ethanedits/iqvw64e-privilege-escalation](https://github.com/ethanedits/iqvw64e-privilege-escalation) :  ![starts](https://img.shields.io/github/stars/ethanedits/iqvw64e-privilege-escalation.svg) ![forks](https://img.shields.io/github/forks/ethanedits/iqvw64e-privilege-escalation.svg)


## CVE-2014-6287
 The findMacroMarker function in parserLib.pas in Rejetto HTTP File Server (aks HFS or HttpFileServer) 2.3x before 2.3c allows remote attackers to execute arbitrary programs via a %00 sequence in a search action.

- [https://github.com/jagg3rsec/CVE-2014-6287](https://github.com/jagg3rsec/CVE-2014-6287) :  ![starts](https://img.shields.io/github/stars/jagg3rsec/CVE-2014-6287.svg) ![forks](https://img.shields.io/github/forks/jagg3rsec/CVE-2014-6287.svg)

