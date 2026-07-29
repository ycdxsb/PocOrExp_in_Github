# Update 2026-07-29
## CVE-2026-66731
 facil.io 0.7.5 through 0.7.6 contains a denial-of-service vulnerability in the HTTP/1.1 chunked transfer encoding parser that allows unauthenticated remote attackers to crash the server by sending a negative chunk size value. Attackers can send a single POST request with a Transfer-Encoding: chunked header containing a leading minus sign in the chunk size field, causing the parser in http1_parser.h to compute a large positive integer from the negated value, corrupting internal state and moving the read pointer into unmapped memory resulting in a fault.

- [https://github.com/theopaid/CVE-2026-66731-Negative-Chunk-Size-Parsing-Causes-Memory-Corruption-leading-to-Server-Crash](https://github.com/theopaid/CVE-2026-66731-Negative-Chunk-Size-Parsing-Causes-Memory-Corruption-leading-to-Server-Crash) :  ![starts](https://img.shields.io/github/stars/theopaid/CVE-2026-66731-Negative-Chunk-Size-Parsing-Causes-Memory-Corruption-leading-to-Server-Crash.svg) ![forks](https://img.shields.io/github/forks/theopaid/CVE-2026-66731-Negative-Chunk-Size-Parsing-Causes-Memory-Corruption-leading-to-Server-Crash.svg)


## CVE-2026-66730
 facil.io 0.6.0 through 0.7.6 contains a denial-of-service vulnerability in the multipart body parser that allows an unauthenticated remote attacker to permanently freeze worker processes at 100% CPU by sending a multipart/form-data request with a partial closing boundary. The missing progress guard in the parser loop causes http_mime_parse to return 0 bytes consumed without setting done or error flags, causing the calling loop to re-invoke the parser on the same buffer indefinitely, exhausting all workers and permanently disabling the server until manually restarted.

- [https://github.com/theopaid/CVE-2026-66730-Infinite-Loop-DoS-in-facil.io-MIME-Parser](https://github.com/theopaid/CVE-2026-66730-Infinite-Loop-DoS-in-facil.io-MIME-Parser) :  ![starts](https://img.shields.io/github/stars/theopaid/CVE-2026-66730-Infinite-Loop-DoS-in-facil.io-MIME-Parser.svg) ![forks](https://img.shields.io/github/forks/theopaid/CVE-2026-66730-Infinite-Loop-DoS-in-facil.io-MIME-Parser.svg)


## CVE-2026-66729
 facil.io 0.6.0 through 0.7.6 contains an integer underflow vulnerability in the multipart MIME body parser that allows unauthenticated remote attackers to crash the server process by sending a crafted Content-Disposition header with an empty field name. Attackers can trigger a uint32_t wraparound in http_mime_parser.h causing an out-of-bounds memory read past the name pointer, resulting in a bus fault that crashes the handling worker with a single POST request.

- [https://github.com/theopaid/CVE-2026-66729-Out-of-Bounds-Read-in-facil.io-MIME-Parser-leads-to-Server-Crash](https://github.com/theopaid/CVE-2026-66729-Out-of-Bounds-Read-in-facil.io-MIME-Parser-leads-to-Server-Crash) :  ![starts](https://img.shields.io/github/stars/theopaid/CVE-2026-66729-Out-of-Bounds-Read-in-facil.io-MIME-Parser-leads-to-Server-Crash.svg) ![forks](https://img.shields.io/github/forks/theopaid/CVE-2026-66729-Out-of-Bounds-Read-in-facil.io-MIME-Parser-leads-to-Server-Crash.svg)


## CVE-2026-66412
 Leantime 3.6.2 and prior contains a broken access control vulnerability that allows authenticated users to read milestone data from projects they are not assigned to by supplying arbitrary integer milestone IDs to the tickets.getMilestone JSON-RPC endpoint. Attackers can enumerate integer milestone IDs through the JSON-RPC API to access project planning information, milestone titles, descriptions, and timelines across all projects on the instance regardless of project membership.

- [https://github.com/javokhir-sec/CVE-PoC-Hub](https://github.com/javokhir-sec/CVE-PoC-Hub) :  ![starts](https://img.shields.io/github/stars/javokhir-sec/CVE-PoC-Hub.svg) ![forks](https://img.shields.io/github/forks/javokhir-sec/CVE-PoC-Hub.svg)


## CVE-2026-65008
 Grav 2.0.4 (fixed in 2.0.7) contains a remote code execution vulnerability in Blueprint::dynamicData() (system/src/Grav/Common/Data/Blueprint.php), which passes a Class::method callable string and its arguments directly to call_user_func_array() without any allowlist. Because the form plugin routes page frontmatter through this path, an authenticated account with the admin.pages (or api.pages.write) permission can plant a malicious callable directive in a page. The command then executes as the web-server user whenever anyone — including an unauthenticated visitor — accesses the page.

- [https://github.com/zer0dayf/CVE-2026-65008](https://github.com/zer0dayf/CVE-2026-65008) :  ![starts](https://img.shields.io/github/stars/zer0dayf/CVE-2026-65008.svg) ![forks](https://img.shields.io/github/forks/zer0dayf/CVE-2026-65008.svg)


## CVE-2026-63030
 WordPress 6.9.x before 6.9.5 and 7.0.x before 7.0.2 is affected by a REST API batch endpoint route confusion issue which, combined with the author__not_in WP_Query SQL Injection (CVE-2026-60137), could allow an attacker to perform SQL Injection and achieve Remote Code Execution.

- [https://github.com/yuag/wp2shell](https://github.com/yuag/wp2shell) :  ![starts](https://img.shields.io/github/stars/yuag/wp2shell.svg) ![forks](https://img.shields.io/github/forks/yuag/wp2shell.svg)
- [https://github.com/BytesPulse-OE/wp2shell-Hestia-Scanner](https://github.com/BytesPulse-OE/wp2shell-Hestia-Scanner) :  ![starts](https://img.shields.io/github/stars/BytesPulse-OE/wp2shell-Hestia-Scanner.svg) ![forks](https://img.shields.io/github/forks/BytesPulse-OE/wp2shell-Hestia-Scanner.svg)


## CVE-2026-61511
 vBulletin 5.x through 5.7.5 and 6.x through 6.2.1 contains an eval injection vulnerability in the vB5_Template_Runtime::runMaths() method within the template runtime that allows unauthenticated remote attackers to execute arbitrary PHP code by supplying crafted input through the pagenav[pagenumber] parameter. Attackers can exploit the insufficiently restrictive regex filter by using phpfuck-style encoding with permitted characters to inject and execute arbitrary PHP code via the unauthenticated ajax/render template route without any authentication.

- [https://github.com/HORKimhab/CVE-2026-61511](https://github.com/HORKimhab/CVE-2026-61511) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-61511.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-61511.svg)


## CVE-2026-60137
 WordPress 6.8.x before 6.8.6, 6.9.x before 6.9.5, and 7.0.x before 7.0.2 does not properly sanitise the author__not_in parameter of WP_Query, which could allow SQL Injection when a plugin or theme passes untrusted input to the parameter.

- [https://github.com/Dungsocool/CVE-2026-60137_CVE-2026-63030](https://github.com/Dungsocool/CVE-2026-60137_CVE-2026-63030) :  ![starts](https://img.shields.io/github/stars/Dungsocool/CVE-2026-60137_CVE-2026-63030.svg) ![forks](https://img.shields.io/github/forks/Dungsocool/CVE-2026-60137_CVE-2026-63030.svg)
- [https://github.com/yuag/wp2shell](https://github.com/yuag/wp2shell) :  ![starts](https://img.shields.io/github/stars/yuag/wp2shell.svg) ![forks](https://img.shields.io/github/forks/yuag/wp2shell.svg)
- [https://github.com/BytesPulse-OE/wp2shell-Hestia-Scanner](https://github.com/BytesPulse-OE/wp2shell-Hestia-Scanner) :  ![starts](https://img.shields.io/github/stars/BytesPulse-OE/wp2shell-Hestia-Scanner.svg) ![forks](https://img.shields.io/github/forks/BytesPulse-OE/wp2shell-Hestia-Scanner.svg)


## CVE-2026-57973
 Time-of-check time-of-use (toctou) race condition in Windows Subsystem for Linux allows an authorized attacker to perform tampering locally.

- [https://github.com/riddhimaan-sth404/CVE-2026-57973](https://github.com/riddhimaan-sth404/CVE-2026-57973) :  ![starts](https://img.shields.io/github/stars/riddhimaan-sth404/CVE-2026-57973.svg) ![forks](https://img.shields.io/github/forks/riddhimaan-sth404/CVE-2026-57973.svg)


## CVE-2026-55579
 Pheditor is a single-file editor and file manager written in PHP. From version 2.0.1 to before version 2.0.6, Pheditor ships with a hardcoded default password admin (SHA-512 hash stored at pheditor.php:11). There is no mechanism to force a password change on first login. Any deployment using the default credentials grants an attacker full access to the file editor, file upload, and terminal features, enabling arbitrary file read/write and remote code execution. This issue has been patched in version 2.0.6.

- [https://github.com/Ch4120N/CVE-2026-55579](https://github.com/Ch4120N/CVE-2026-55579) :  ![starts](https://img.shields.io/github/stars/Ch4120N/CVE-2026-55579.svg) ![forks](https://img.shields.io/github/forks/Ch4120N/CVE-2026-55579.svg)


## CVE-2026-54121
 Improper authorization in Active Directory Certificate Services (AD CS) allows an authorized attacker to elevate privileges over a network.

- [https://github.com/marcgoam/CVE-2026-54121-CertiGhost](https://github.com/marcgoam/CVE-2026-54121-CertiGhost) :  ![starts](https://img.shields.io/github/stars/marcgoam/CVE-2026-54121-CertiGhost.svg) ![forks](https://img.shields.io/github/forks/marcgoam/CVE-2026-54121-CertiGhost.svg)
- [https://github.com/ChPratik/CVE-2026-54121](https://github.com/ChPratik/CVE-2026-54121) :  ![starts](https://img.shields.io/github/stars/ChPratik/CVE-2026-54121.svg) ![forks](https://img.shields.io/github/forks/ChPratik/CVE-2026-54121.svg)


## CVE-2026-51565
 Cross-site scripting (XSS) vulnerability in Modules/Docs/DocsController.php in Milk admin =0.9.8 allows remote attackers to inject arbitrary web script or HTML via the action parameter in a crafted request

- [https://github.com/1337Skid/CVE-2026-51565](https://github.com/1337Skid/CVE-2026-51565) :  ![starts](https://img.shields.io/github/stars/1337Skid/CVE-2026-51565.svg) ![forks](https://img.shields.io/github/forks/1337Skid/CVE-2026-51565.svg)


## CVE-2026-51564
 An issue in the redirect parameter in Milk admin =0.9.8 allows remote attackers to redirect users to arbitrary external URLs via a crafted request.

- [https://github.com/1337Skid/CVE-2026-51564](https://github.com/1337Skid/CVE-2026-51564) :  ![starts](https://img.shields.io/github/stars/1337Skid/CVE-2026-51564.svg) ![forks](https://img.shields.io/github/forks/1337Skid/CVE-2026-51564.svg)


## CVE-2026-50522
 Deserialization of untrusted data in Microsoft Office SharePoint allows an unauthorized attacker to execute code over a network.

- [https://github.com/ChPratik/CVE-2026-50522](https://github.com/ChPratik/CVE-2026-50522) :  ![starts](https://img.shields.io/github/stars/ChPratik/CVE-2026-50522.svg) ![forks](https://img.shields.io/github/forks/ChPratik/CVE-2026-50522.svg)


## CVE-2026-48030
 Pheditor is a single-file editor and file manager written in PHP. From version 2.0.1 to before version 2.0.4, an OS Command Injection vulnerability in the terminal action handler allows any authenticated user to execute arbitrary OS commands by injecting shell metacharacters into the 'dir' POST parameter, completely bypassing the TERMINAL_COMMANDS whitelist and achieving full Remote Code Execution with web server privileges. This issue has been patched in version 2.0.4.

- [https://github.com/muslimbek-0x/CVE-2026-48030](https://github.com/muslimbek-0x/CVE-2026-48030) :  ![starts](https://img.shields.io/github/stars/muslimbek-0x/CVE-2026-48030.svg) ![forks](https://img.shields.io/github/forks/muslimbek-0x/CVE-2026-48030.svg)


## CVE-2026-43499
  	changelog ]

- [https://github.com/dnlid/CVE-2026-43499](https://github.com/dnlid/CVE-2026-43499) :  ![starts](https://img.shields.io/github/stars/dnlid/CVE-2026-43499.svg) ![forks](https://img.shields.io/github/forks/dnlid/CVE-2026-43499.svg)
- [https://github.com/soralis0912/CVE-2026-43499-warhol-root](https://github.com/soralis0912/CVE-2026-43499-warhol-root) :  ![starts](https://img.shields.io/github/stars/soralis0912/CVE-2026-43499-warhol-root.svg) ![forks](https://img.shields.io/github/forks/soralis0912/CVE-2026-43499-warhol-root.svg)
- [https://github.com/KawaiiHachimi/CVE-2026-43499-pkb110](https://github.com/KawaiiHachimi/CVE-2026-43499-pkb110) :  ![starts](https://img.shields.io/github/stars/KawaiiHachimi/CVE-2026-43499-pkb110.svg) ![forks](https://img.shields.io/github/forks/KawaiiHachimi/CVE-2026-43499-pkb110.svg)
- [https://github.com/soralis0912/CVE-2026-43499-pmg110-root](https://github.com/soralis0912/CVE-2026-43499-pmg110-root) :  ![starts](https://img.shields.io/github/stars/soralis0912/CVE-2026-43499-pmg110-root.svg) ![forks](https://img.shields.io/github/forks/soralis0912/CVE-2026-43499-pmg110-root.svg)


## CVE-2026-42533
 Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/imbas007/CVE-2026-42533](https://github.com/imbas007/CVE-2026-42533) :  ![starts](https://img.shields.io/github/stars/imbas007/CVE-2026-42533.svg) ![forks](https://img.shields.io/github/forks/imbas007/CVE-2026-42533.svg)


## CVE-2026-40000
 The Activity zte.com.cn.filer/zte.com.cn.filer.FilePreViewActivity within ZTE File Manager is designed to preview compressed files. Third-party applications can launch this Activity and supply arbitrary file paths (e.g., content://zte.com.cn.filer.fileprovider/root_path), enabling file access with the privilege level of ZTE File Manager. This allows unrooted devices to read files under certain system directories such as /data/data and /data/local/tmp. If access restrictions do not block untrusted applications, additional directories may also be accessible.

- [https://github.com/Skorpion96/CVE-2026-40000](https://github.com/Skorpion96/CVE-2026-40000) :  ![starts](https://img.shields.io/github/stars/Skorpion96/CVE-2026-40000.svg) ![forks](https://img.shields.io/github/forks/Skorpion96/CVE-2026-40000.svg)


## CVE-2026-39875
 A permissions issue was addressed with additional restrictions. This issue is fixed in macOS Sequoia 15.7.8, macOS Sonoma 14.8.8, macOS Tahoe 26.6. A malicious app may be able to gain root privileges.

- [https://github.com/mac-123456789-lab/CVE-2026-39875-macOS-CUPS-LPE](https://github.com/mac-123456789-lab/CVE-2026-39875-macOS-CUPS-LPE) :  ![starts](https://img.shields.io/github/stars/mac-123456789-lab/CVE-2026-39875-macOS-CUPS-LPE.svg) ![forks](https://img.shields.io/github/forks/mac-123456789-lab/CVE-2026-39875-macOS-CUPS-LPE.svg)


## CVE-2026-28992
 A memory corruption vulnerability was addressed with improved locking. This issue is fixed in iOS 18.7.9 and iPadOS 18.7.9, iOS 26.5 and iPadOS 26.5, macOS Sequoia 15.7.7, macOS Sonoma 14.8.7, macOS Tahoe 26.5, tvOS 26.5, visionOS 26.5, watchOS 26.5. An attacker may be able to cause unexpected app termination.

- [https://github.com/0xjohnnydev/CVE-2026-28992-IOHIDFamily-FastPathUserClient-Race-Conditions](https://github.com/0xjohnnydev/CVE-2026-28992-IOHIDFamily-FastPathUserClient-Race-Conditions) :  ![starts](https://img.shields.io/github/stars/0xjohnnydev/CVE-2026-28992-IOHIDFamily-FastPathUserClient-Race-Conditions.svg) ![forks](https://img.shields.io/github/forks/0xjohnnydev/CVE-2026-28992-IOHIDFamily-FastPathUserClient-Race-Conditions.svg)


## CVE-2026-27577
 n8n is an open source workflow automation platform. Prior to versions 2.10.1, 2.9.3, and 1.123.22, additional exploits in the expression evaluation of n8n have been identified and patched following CVE-2025-68613. An authenticated user with permission to create or modify workflows could abuse crafted expressions in workflow parameters to trigger unintended system command execution on the host running n8n. The issues have been fixed in n8n versions 2.10.1, 2.9.3, and 1.123.22. Users should upgrade to one of these versions or later to remediate all known vulnerabilities. If upgrading is not immediately possible, administrators should consider the following temporary mitigations. Limit workflow creation and editing permissions to fully trusted users only, and/or deploy n8n in a hardened environment with restricted operating system privileges and network access to reduce the impact of potential exploitation. These workarounds do not fully remediate the risk and should only be used as short-term mitigation measures.

- [https://github.com/HORKimhab/CVE-2026-27577](https://github.com/HORKimhab/CVE-2026-27577) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-27577.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-27577.svg)


## CVE-2026-20687
 A use after free issue was addressed with improved memory management. This issue is fixed in iOS 18.7.7 and iPadOS 18.7.7, iOS 26.4 and iPadOS 26.4, macOS Sequoia 15.7.5, macOS Tahoe 26.4, tvOS 26.4, watchOS 26.4. An app may be able to cause unexpected system termination or write kernel memory.

- [https://github.com/0xjohnnydev/CVE-2026-20687-AppleJPEGDriver-UAF](https://github.com/0xjohnnydev/CVE-2026-20687-AppleJPEGDriver-UAF) :  ![starts](https://img.shields.io/github/stars/0xjohnnydev/CVE-2026-20687-AppleJPEGDriver-UAF.svg) ![forks](https://img.shields.io/github/forks/0xjohnnydev/CVE-2026-20687-AppleJPEGDriver-UAF.svg)


## CVE-2026-20643
 A cross-origin issue in the Navigation API was addressed with improved input validation. This issue is fixed in Background Security Improvements for iOS, iPadOS, and macOS, Safari 26.4, iOS 18.7.7 and iPadOS 18.7.7, iOS 26.4 and iPadOS 26.4, macOS Tahoe 26.4, visionOS 26.4. Processing maliciously crafted web content may bypass Same Origin Policy.

- [https://github.com/0xjohnnydev/WebKit-NavigationAPI-SOP-Bypass](https://github.com/0xjohnnydev/WebKit-NavigationAPI-SOP-Bypass) :  ![starts](https://img.shields.io/github/stars/0xjohnnydev/WebKit-NavigationAPI-SOP-Bypass.svg) ![forks](https://img.shields.io/github/forks/0xjohnnydev/WebKit-NavigationAPI-SOP-Bypass.svg)


## CVE-2026-20637
 A use after free issue was addressed with improved memory management. This issue is fixed in iOS 18.7.7 and iPadOS 18.7.7, iOS 26.3 and iPadOS 26.3, macOS Sequoia 15.7.5, macOS Sonoma 14.8.5, macOS Tahoe 26.3, tvOS 26.3, visionOS 26.3, watchOS 26.3. An app may be able to cause unexpected system termination.

- [https://github.com/0xjohnnydev/CVE-2026-20637-AppleSEPKeyStore-UAF](https://github.com/0xjohnnydev/CVE-2026-20637-AppleSEPKeyStore-UAF) :  ![starts](https://img.shields.io/github/stars/0xjohnnydev/CVE-2026-20637-AppleSEPKeyStore-UAF.svg) ![forks](https://img.shields.io/github/forks/0xjohnnydev/CVE-2026-20637-AppleSEPKeyStore-UAF.svg)


## CVE-2026-16723
 A remote code execution (RCE) vulnerability exists in fastjson 1.2.68 through 1.2.83. This vulnerability is exploitable under fastjson's stock default configuration — no AutoType enablement required, no classpath gadget required.

- [https://github.com/dinosn/fastjson-jsontype-rce-lab](https://github.com/dinosn/fastjson-jsontype-rce-lab) :  ![starts](https://img.shields.io/github/stars/dinosn/fastjson-jsontype-rce-lab.svg) ![forks](https://img.shields.io/github/forks/dinosn/fastjson-jsontype-rce-lab.svg)
- [https://github.com/why-success/fastjson-rce-lab](https://github.com/why-success/fastjson-rce-lab) :  ![starts](https://img.shields.io/github/stars/why-success/fastjson-rce-lab.svg) ![forks](https://img.shields.io/github/forks/why-success/fastjson-rce-lab.svg)


## CVE-2026-15013
 The SAML Single Sign On – SSO Login plugin for WordPress is vulnerable to Authentication Bypass via SAML Signature Algorithm Confusion in all versions up to, and including, 5.4.3. The vulnerability exists because `Mo_SAML_Utilities::mo_saml_cast_key()` reads the `SignatureMethod` Algorithm attribute directly from the attacker-controlled `SAMLResponse` parameter rather than enforcing the locally configured algorithm, causing the plugin to recast the IdP's RSA public key as an HMAC-SHA1 shared secret and validate the forged signature against it. This makes it possible for unauthenticated attackers to forge a SAML assertion targeting any WordPress account — including administrators — obtain valid WordPress authentication cookies, and achieve full administrator-level account takeover.

- [https://github.com/zer0dayf/CVE-2026-15013](https://github.com/zer0dayf/CVE-2026-15013) :  ![starts](https://img.shields.io/github/stars/zer0dayf/CVE-2026-15013.svg) ![forks](https://img.shields.io/github/forks/zer0dayf/CVE-2026-15013.svg)


## CVE-2026-9830
 The bookingpress-appointment-booking-pro WordPress plugin before 5.7.3 does not correctly invoke its REST permission callback, leaving every route in one of its API namespaces reachable without authentication and allowing unauthenticated attackers to read customer booking data and modify other users' bookings.

- [https://github.com/ChPratik/CVE-2026-9830](https://github.com/ChPratik/CVE-2026-9830) :  ![starts](https://img.shields.io/github/stars/ChPratik/CVE-2026-9830.svg) ![forks](https://img.shields.io/github/forks/ChPratik/CVE-2026-9830.svg)


## CVE-2026-0010
 In onTransact of IDrmManagerService.cpp, there is a possible out of bounds write due to a missing bounds check. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/cduram/NotCVE-2026-0010](https://github.com/cduram/NotCVE-2026-0010) :  ![starts](https://img.shields.io/github/stars/cduram/NotCVE-2026-0010.svg) ![forks](https://img.shields.io/github/forks/cduram/NotCVE-2026-0010.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-14x](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-14x) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-14x.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-14x.svg)


## CVE-2025-64512
 Pdfminer.six is a community maintained fork of the original PDFMiner, a tool for extracting information from PDF documents. Prior to version 20251107, pdfminer.six will execute arbitrary code from a malicious pickle file if provided with a malicious PDF file. The `CMapDB._load_data()` function in pdfminer.six uses `pickle.loads()` to deserialize pickle files. These pickle files are supposed to be part of the pdfminer.six distribution stored in the `cmap/` directory, but a malicious PDF can specify an alternative directory and filename as long as the filename ends in `.pickle.gz`. A malicious, zipped pickle file can then contain code which will automatically execute when the PDF is processed. Version 20251107 fixes the issue.

- [https://github.com/saadhassan77/CVE-2025-64512---pdfminer.six-Remote-Code-Execution-RCE-](https://github.com/saadhassan77/CVE-2025-64512---pdfminer.six-Remote-Code-Execution-RCE-) :  ![starts](https://img.shields.io/github/stars/saadhassan77/CVE-2025-64512---pdfminer.six-Remote-Code-Execution-RCE-.svg) ![forks](https://img.shields.io/github/forks/saadhassan77/CVE-2025-64512---pdfminer.six-Remote-Code-Execution-RCE-.svg)


## CVE-2025-59287
 Deserialization of untrusted data in Windows Server Update Service allows an unauthorized attacker to execute code over a network.

- [https://github.com/MaxymGorn/cve-2025-59287-exploit-poc](https://github.com/MaxymGorn/cve-2025-59287-exploit-poc) :  ![starts](https://img.shields.io/github/stars/MaxymGorn/cve-2025-59287-exploit-poc.svg) ![forks](https://img.shields.io/github/forks/MaxymGorn/cve-2025-59287-exploit-poc.svg)


## CVE-2025-43529
 A use-after-free issue was addressed with improved memory management. This issue is fixed in Safari 26.2, iOS 18.7.3 and iPadOS 18.7.3, iOS 26.2 and iPadOS 26.2, macOS Tahoe 26.2, tvOS 26.2, visionOS 26.2, watchOS 26.2. Processing maliciously crafted web content may lead to arbitrary code execution. Apple is aware of a report that this issue may have been exploited in an extremely sophisticated attack against specific targeted individuals on versions of iOS before iOS 26. CVE-2025-14174 was also issued in response to this report.

- [https://github.com/0xjohnnydev/WebKit-UAF-ANGLE-OOB-Analysis](https://github.com/0xjohnnydev/WebKit-UAF-ANGLE-OOB-Analysis) :  ![starts](https://img.shields.io/github/stars/0xjohnnydev/WebKit-UAF-ANGLE-OOB-Analysis.svg) ![forks](https://img.shields.io/github/forks/0xjohnnydev/WebKit-UAF-ANGLE-OOB-Analysis.svg)


## CVE-2025-24990
Microsoft recommends removing any existing dependencies on this hardware.

- [https://github.com/sentinel-aidefense/CVE-2025-24990](https://github.com/sentinel-aidefense/CVE-2025-24990) :  ![starts](https://img.shields.io/github/stars/sentinel-aidefense/CVE-2025-24990.svg) ![forks](https://img.shields.io/github/forks/sentinel-aidefense/CVE-2025-24990.svg)


## CVE-2025-21479
 Memory corruption due to unauthorized command execution in GPU micronode while executing specific sequence of commands.

- [https://github.com/CamsShaft/SELinux-Permissive-Only-CVE-2025-21479](https://github.com/CamsShaft/SELinux-Permissive-Only-CVE-2025-21479) :  ![starts](https://img.shields.io/github/stars/CamsShaft/SELinux-Permissive-Only-CVE-2025-21479.svg) ![forks](https://img.shields.io/github/forks/CamsShaft/SELinux-Permissive-Only-CVE-2025-21479.svg)


## CVE-2025-14174
 Out of bounds memory access in ANGLE in Google Chrome on Mac prior to 143.0.7499.110 allowed a remote attacker to perform out of bounds memory access via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/0xjohnnydev/WebKit-UAF-ANGLE-OOB-Analysis](https://github.com/0xjohnnydev/WebKit-UAF-ANGLE-OOB-Analysis) :  ![starts](https://img.shields.io/github/stars/0xjohnnydev/WebKit-UAF-ANGLE-OOB-Analysis.svg) ![forks](https://img.shields.io/github/forks/0xjohnnydev/WebKit-UAF-ANGLE-OOB-Analysis.svg)


## CVE-2024-28987
 The SolarWinds Web Help Desk (WHD) software is affected by a hardcoded credential vulnerability, allowing remote unauthenticated user to access internal functionality and modify data.

- [https://github.com/Darabium/CVE-2024-28987](https://github.com/Darabium/CVE-2024-28987) :  ![starts](https://img.shields.io/github/stars/Darabium/CVE-2024-28987.svg) ![forks](https://img.shields.io/github/forks/Darabium/CVE-2024-28987.svg)


## CVE-2024-23659
 SPIP before 4.1.14 and 4.2.x before 4.2.8 allows XSS via the name of an uploaded file. This is related to javascript/bigup.js and javascript/bigup.utils.js.

- [https://github.com/amis13/SPIP-CVE-2024-23659-](https://github.com/amis13/SPIP-CVE-2024-23659-) :  ![starts](https://img.shields.io/github/stars/amis13/SPIP-CVE-2024-23659-.svg) ![forks](https://img.shields.io/github/forks/amis13/SPIP-CVE-2024-23659-.svg)

