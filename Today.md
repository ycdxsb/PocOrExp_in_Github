# Update 2026-08-04
## CVE-2026-67206
 Wolf CMS through 0.8.3.1 contains a remote code execution vulnerability in FileManagerController that allows authenticated attackers to create arbitrary PHP files by exploiting missing file extension validation in the create_file() and save() functions. Attackers with the file_manager_mkfile capability can write malicious PHP content into the web-accessible FILES_DIR directory and trigger execution by requesting the file over HTTP.

- [https://github.com/anirbala98/CVE-2026-67206](https://github.com/anirbala98/CVE-2026-67206) :  ![starts](https://img.shields.io/github/stars/anirbala98/CVE-2026-67206.svg) ![forks](https://img.shields.io/github/forks/anirbala98/CVE-2026-67206.svg)


## CVE-2026-66421
 OpenClaw Dashboard contains a stored cross-site scripting vulnerability that allows unauthenticated remote attackers to execute arbitrary JavaScript in the administrator's browser session by injecting HTML markup into agent transcript messages processed through the sessions API. Attackers can craft a message containing inline event handler payloads such as an img tag with an onerror attribute within the 60-character rendering budget, which is stored in the session transcript and interpolated unsanitized into innerHTML on the default landing page, allowing theft of session tokens and unauthorized calls to authenticated administrative endpoints including agent instruction file modification.

- [https://github.com/theopaid/CVE-2026-66421-OpenClaw-Dashboard-Stored-XSS-via-lastMessage-Session-Field](https://github.com/theopaid/CVE-2026-66421-OpenClaw-Dashboard-Stored-XSS-via-lastMessage-Session-Field) :  ![starts](https://img.shields.io/github/stars/theopaid/CVE-2026-66421-OpenClaw-Dashboard-Stored-XSS-via-lastMessage-Session-Field.svg) ![forks](https://img.shields.io/github/forks/theopaid/CVE-2026-66421-OpenClaw-Dashboard-Stored-XSS-via-lastMessage-Session-Field.svg)


## CVE-2026-66418
 OpenClaw Dashboard v3.0.0 contains a stored cross-site scripting vulnerability that allows unauthenticated remote attackers to inject arbitrary HTML and script payloads by submitting a crafted username in a failed login POST request, which is recorded verbatim in the audit log. When an administrator opens the notification panel, the unescaped log entry is rendered via innerHTML with a permissive Content-Security-Policy allowing inline event handlers, enabling the attacker-supplied payload to execute in the administrator's session and interact with authenticated endpoints including agent instruction file editing and configuration changes.

- [https://github.com/theopaid/CVE-2026-66418-OpenClaw-Dashboard-v3.0.0-Stored-XSS-via-Failed-Login-Username-Field](https://github.com/theopaid/CVE-2026-66418-OpenClaw-Dashboard-v3.0.0-Stored-XSS-via-Failed-Login-Username-Field) :  ![starts](https://img.shields.io/github/stars/theopaid/CVE-2026-66418-OpenClaw-Dashboard-v3.0.0-Stored-XSS-via-Failed-Login-Username-Field.svg) ![forks](https://img.shields.io/github/forks/theopaid/CVE-2026-66418-OpenClaw-Dashboard-v3.0.0-Stored-XSS-via-Failed-Login-Username-Field.svg)


## CVE-2026-63223
 CodeIgniter is a PHP full-stack web framework. Prior to 4.7.4, the is_image and mime_in upload validation rules do not independently enforce a safe client filename extension, allowing a remote attacker to upload executable content when an application preserves the client filename and stores uploads in a web-accessible script-enabled directory. Applications are impacted when they validate uploads using is_image or mime_in without an independent safe extension check (such as ext_in on patched versions), save uploaded files using the client-supplied filename, and place uploads in a web-accessible directory where PHP files can execute. This issue is fixed in version 4.7.4.

- [https://github.com/imbas007/CVE-2026-63223-POC](https://github.com/imbas007/CVE-2026-63223-POC) :  ![starts](https://img.shields.io/github/stars/imbas007/CVE-2026-63223-POC.svg) ![forks](https://img.shields.io/github/forks/imbas007/CVE-2026-63223-POC.svg)


## CVE-2026-59941
 Dompdf is an HTML to PDF converter for PHP. Versions 3.15 and prior accept a BMP image and generates a PDF-compatible PNG based only on its declared header dimensions and never bounds width × height before the image is converted through GD. A 58-byte BMP whose header declares e.g. 6000×6000 is accepted and later drives imagecreatetruecolor($width, $height) (and PHP's native BMP decoder) to allocate the full pixel canvas. A payload can fit in a single HTTP request: the BMP can be inlined as a data:image/bmp;base64,… URI inside attacker-controlled HTML, so no upload, no remote fetch, and no chroot-reachable file is required. I measured a 169-byte request driving a dompdf render to ~412 MB peak RSS and ~4.8 s of CPU/wall time, versus ~34 MB for an identically-sized benign request — roughly a 12× memory amplification per request, repeatable and unauthenticated. This issue has been fixed in version 3.16.

- [https://github.com/far00t01/CVE-2026-59941](https://github.com/far00t01/CVE-2026-59941) :  ![starts](https://img.shields.io/github/stars/far00t01/CVE-2026-59941.svg) ![forks](https://img.shields.io/github/forks/far00t01/CVE-2026-59941.svg)


## CVE-2026-58424
 Permanent Fork PR Workflow Approval Gate Bypass

- [https://github.com/BridgerAlderson/CVE-2026-58424](https://github.com/BridgerAlderson/CVE-2026-58424) :  ![starts](https://img.shields.io/github/stars/BridgerAlderson/CVE-2026-58424.svg) ![forks](https://img.shields.io/github/forks/BridgerAlderson/CVE-2026-58424.svg)


## CVE-2026-57827
 Joomla Extension - rsjoomla.com - Unauthenticated file upload in RSFiles component  1.17.12 - The Joomla extension RSFiles is vulnerable to an unauthenticated arbitrary file upload that allows uploading executable files and leads to full RCE.

- [https://github.com/Mohammad-008/rsfiles-CVE-2026-57827](https://github.com/Mohammad-008/rsfiles-CVE-2026-57827) :  ![starts](https://img.shields.io/github/stars/Mohammad-008/rsfiles-CVE-2026-57827.svg) ![forks](https://img.shields.io/github/forks/Mohammad-008/rsfiles-CVE-2026-57827.svg)


## CVE-2026-49049
 The Helix3 plugin for Joomla exposes an ajax handler task, that allows unauthenticated attackers to delete arbitrary files, write arbitrary JSON files and update template parameters.

- [https://github.com/Jenderal92/CVE-2026-49049](https://github.com/Jenderal92/CVE-2026-49049) :  ![starts](https://img.shields.io/github/stars/Jenderal92/CVE-2026-49049.svg) ![forks](https://img.shields.io/github/forks/Jenderal92/CVE-2026-49049.svg)


## CVE-2026-43724
 The issue was addressed with improved input sanitization. This issue is fixed in iOS 26.5.2 and iPadOS 26.5.2, macOS Sequoia 15.7.8, macOS Sonoma 14.8.8, macOS Tahoe 26.5.2, tvOS 26.6, visionOS 26.6, watchOS 26.6. An app may be able to cause unexpected system termination or write kernel memory.

- [https://github.com/gracecondition/DirtySlide](https://github.com/gracecondition/DirtySlide) :  ![starts](https://img.shields.io/github/stars/gracecondition/DirtySlide.svg) ![forks](https://img.shields.io/github/forks/gracecondition/DirtySlide.svg)


## CVE-2026-43499
  	changelog ]

- [https://github.com/boxiaolanya2008/CVE-2026-43499-Neo11Plus](https://github.com/boxiaolanya2008/CVE-2026-43499-Neo11Plus) :  ![starts](https://img.shields.io/github/stars/boxiaolanya2008/CVE-2026-43499-Neo11Plus.svg) ![forks](https://img.shields.io/github/forks/boxiaolanya2008/CVE-2026-43499-Neo11Plus.svg)
- [https://github.com/alex193a/Root-My-Pixel](https://github.com/alex193a/Root-My-Pixel) :  ![starts](https://img.shields.io/github/stars/alex193a/Root-My-Pixel.svg) ![forks](https://img.shields.io/github/forks/alex193a/Root-My-Pixel.svg)


## CVE-2026-43284
destination-frag path or fall back to skb_cow_data().

- [https://github.com/RevyHub/CVE-2026-43284---DirtyFrag-Analysis-THM-](https://github.com/RevyHub/CVE-2026-43284---DirtyFrag-Analysis-THM-) :  ![starts](https://img.shields.io/github/stars/RevyHub/CVE-2026-43284---DirtyFrag-Analysis-THM-.svg) ![forks](https://img.shields.io/github/forks/RevyHub/CVE-2026-43284---DirtyFrag-Analysis-THM-.svg)


## CVE-2026-41651
3. Late flag read at execution time (lines 2273–2277): The scheduler's idle callback reads cached_transaction_flags at dispatch time, not at authorization time. If flags were overwritten between authorization and execution, the backend sees the attacker's flags.

- [https://github.com/gbuyssens/CVE-2026-41651](https://github.com/gbuyssens/CVE-2026-41651) :  ![starts](https://img.shields.io/github/stars/gbuyssens/CVE-2026-41651.svg) ![forks](https://img.shields.io/github/forks/gbuyssens/CVE-2026-41651.svg)


## CVE-2026-39987
 marimo is a reactive Python notebook. Prior to 0.23.0, Marimo has a Pre-Auth RCE vulnerability. The terminal WebSocket endpoint /terminal/ws lacks authentication validation, allowing an unauthenticated attacker to obtain a full PTY shell and execute arbitrary system commands. Unlike other WebSocket endpoints (e.g., /ws) that correctly call validate_auth() for authentication, the /terminal/ws endpoint only checks the running mode and platform support before accepting connections, completely skipping authentication verification. This vulnerability is fixed in 0.23.0.

- [https://github.com/vanhari/CVE-2026-39987](https://github.com/vanhari/CVE-2026-39987) :  ![starts](https://img.shields.io/github/stars/vanhari/CVE-2026-39987.svg) ![forks](https://img.shields.io/github/forks/vanhari/CVE-2026-39987.svg)
- [https://github.com/jasonbernier/CVE-2026-39987](https://github.com/jasonbernier/CVE-2026-39987) :  ![starts](https://img.shields.io/github/stars/jasonbernier/CVE-2026-39987.svg) ![forks](https://img.shields.io/github/forks/jasonbernier/CVE-2026-39987.svg)
- [https://github.com/gbuyssens/CVE-2026-39987](https://github.com/gbuyssens/CVE-2026-39987) :  ![starts](https://img.shields.io/github/stars/gbuyssens/CVE-2026-39987.svg) ![forks](https://img.shields.io/github/forks/gbuyssens/CVE-2026-39987.svg)
- [https://github.com/Wind010/CVE-2026-39987_PoC](https://github.com/Wind010/CVE-2026-39987_PoC) :  ![starts](https://img.shields.io/github/stars/Wind010/CVE-2026-39987_PoC.svg) ![forks](https://img.shields.io/github/forks/Wind010/CVE-2026-39987_PoC.svg)


## CVE-2026-32746
 telnetd in GNU inetutils through 2.7 allows an out-of-bounds write in the LINEMODE SLC (Set Local Characters) suboption handler because add_slc does not check whether the buffer is full.

- [https://github.com/MonkeySeC-sys/Kangaroo](https://github.com/MonkeySeC-sys/Kangaroo) :  ![starts](https://img.shields.io/github/stars/MonkeySeC-sys/Kangaroo.svg) ![forks](https://img.shields.io/github/forks/MonkeySeC-sys/Kangaroo.svg)


## CVE-2026-24072
Users are recommended to upgrade to version 2.4.67, which fixes this issue.

- [https://github.com/meh098/CVE-2026-24072-Analysis](https://github.com/meh098/CVE-2026-24072-Analysis) :  ![starts](https://img.shields.io/github/stars/meh098/CVE-2026-24072-Analysis.svg) ![forks](https://img.shields.io/github/forks/meh098/CVE-2026-24072-Analysis.svg)


## CVE-2026-16540
 The Simply Schedule Appointments WordPress plugin before 1.6.12.6 does not correctly restrict a bulk appointment operation to the requester's own records, allowing unauthenticated users to retrieve the personal data of all appointments across the site and, on premium editions, to permanently delete them.

- [https://github.com/huseyn0vs/CVE-2026-16540-SimplyScheduleAppointments](https://github.com/huseyn0vs/CVE-2026-16540-SimplyScheduleAppointments) :  ![starts](https://img.shields.io/github/stars/huseyn0vs/CVE-2026-16540-SimplyScheduleAppointments.svg) ![forks](https://img.shields.io/github/forks/huseyn0vs/CVE-2026-16540-SimplyScheduleAppointments.svg)


## CVE-2026-13714
 The Realtyna Organic IDX plugin + WPL Real Estate WordPress plugin before 5.3.0 does not validate the type of uploaded files, and its file upload functionality is gated only by an API that is enabled by default and authenticated with hardcoded credentials shipped identically across all installations. This makes it possible for unauthenticated attackers to upload arbitrary PHP files and achieve remote code execution.

- [https://github.com/Nxploited/CVE-2026-13714](https://github.com/Nxploited/CVE-2026-13714) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2026-13714.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2026-13714.svg)


## CVE-2026-9999
 Inappropriate implementation in ANGLE in Google Chrome on Mac prior to 148.0.7778.216 allowed a remote attacker to execute arbitrary code inside a sandbox via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/George0Papasotiriou/CVE-2026-9999-Serverless-Event-Injection-to-Code-Overwrite](https://github.com/George0Papasotiriou/CVE-2026-9999-Serverless-Event-Injection-to-Code-Overwrite) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2026-9999-Serverless-Event-Injection-to-Code-Overwrite.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2026-9999-Serverless-Event-Injection-to-Code-Overwrite.svg)


## CVE-2026-9998
 Integer overflow in Skia in Google Chrome prior to 148.0.7778.216 allowed a remote attacker who had compromised the renderer process to potentially perform a sandbox escape via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/George0Papasotiriou/CVE-2026-9998-Insecure-Deserialization-in-Blockchain-Oracle](https://github.com/George0Papasotiriou/CVE-2026-9998-Insecure-Deserialization-in-Blockchain-Oracle) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2026-9998-Insecure-Deserialization-in-Blockchain-Oracle.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2026-9998-Insecure-Deserialization-in-Blockchain-Oracle.svg)


## CVE-2026-9997
 Use after free in Input in Google Chrome prior to 148.0.7778.216 allowed a remote attacker who had compromised the renderer process to potentially perform a sandbox escape via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/George0Papasotiriou/CVE-2026-9997-VPN-Split-Tunneling-Bypass-via-DHCP-Option-Injection](https://github.com/George0Papasotiriou/CVE-2026-9997-VPN-Split-Tunneling-Bypass-via-DHCP-Option-Injection) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2026-9997-VPN-Split-Tunneling-Bypass-via-DHCP-Option-Injection.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2026-9997-VPN-Split-Tunneling-Bypass-via-DHCP-Option-Injection.svg)


## CVE-2026-9811
 A stored Cross-Site Scripting (XSS) vulnerability exists in the project selector component of Mautic 7. When rendering selection menus for associating projects with system entities, the application fails to sanitize project names returned via AJAX before injecting them into the DOM as option fields. An authenticated user with permissions to create projects can exploit this to store a malicious script payload in the project's name. When another administrative user subsequently opens an entity editor containing the project selector, the injected script executes within the context of their active browser session. This could allow an attacker to hijack the session, perform unauthorized state coordination, or access organizational data within the dashboard.

- [https://github.com/aj2108/CVE-2026-9811](https://github.com/aj2108/CVE-2026-9811) :  ![starts](https://img.shields.io/github/stars/aj2108/CVE-2026-9811.svg) ![forks](https://img.shields.io/github/forks/aj2108/CVE-2026-9811.svg)


## CVE-2026-9809
 A stored Cross-Site Scripting (XSS) vulnerability exists in the Projects component of Mautic 7. When displaying project tags and popovers on administrative detail views (such as campaigns, emails, or forms), user-supplied project names are rendered without proper sanitization. An authenticated user with permissions to create or edit projects can exploit this to inject malicious script payloads. When an administrative user views an entity associated with a compromised project and hovers over its tag, the injected script executes within the context of their active browser session. This could allow an attacker to perform administrative actions on behalf of the victim, alter system configurations, or exfiltrate sensitive data.

- [https://github.com/aj2108/CVE-2026-9809](https://github.com/aj2108/CVE-2026-9809) :  ![starts](https://img.shields.io/github/stars/aj2108/CVE-2026-9809.svg) ![forks](https://img.shields.io/github/forks/aj2108/CVE-2026-9809.svg)


## CVE-2026-9806
 A stored cross-site scripting (XSS) vulnerability exists in the notification panel of CTI Transmute in versions prior to the patched release. Notification messages containing user-controlled convert names were rendered in the notification bell dropdown using innerHTML without adequate sanitization. An attacker able to create or influence a convert name that is included in a notification could inject arbitrary JavaScript, which would execute in the browser of an authenticated user when they opened the notification panel. Successful exploitation could allow the attacker to perform actions in the victim's session or access information available to the application in the browser context. The issue was remediated by constructing notification elements through DOM methods and assigning notification message content via textContent instead of innerHTML. This vulnerability was only present on a development branch.

- [https://github.com/aj2108/CVE-2026-9806](https://github.com/aj2108/CVE-2026-9806) :  ![starts](https://img.shields.io/github/stars/aj2108/CVE-2026-9806.svg) ![forks](https://img.shields.io/github/forks/aj2108/CVE-2026-9806.svg)


## CVE-2026-9090
 Casdoor versions 2.362.0 and earlier contain a vulnerability that allows an attacker to bypass authentication by supplying an arbitrary signing certificate. The buildSpCertificateStore function extracts the X.509 certificate directly from the incoming SAMLResponse instead of using the trusted pre-configured Identity Provider certificate, allowing an attacker to forge assertions signed with an attacker-controlled key.

- [https://github.com/George0Papasotiriou/CVE-2026-9090-Modbus-TCP-Write-to-Read-Only-Coils-via-Function-Code-Spoofing](https://github.com/George0Papasotiriou/CVE-2026-9090-Modbus-TCP-Write-to-Read-Only-Coils-via-Function-Code-Spoofing) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2026-9090-Modbus-TCP-Write-to-Read-Only-Coils-via-Function-Code-Spoofing.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2026-9090-Modbus-TCP-Write-to-Read-Only-Coils-via-Function-Code-Spoofing.svg)


## CVE-2026-8888
 Version 3.0.7 of the Securly Chrome Extension downloads config.json over HTTP and compiles server-provided patterns as JavaScript regular expressions via new RegExp() without complexity validation. An on-path attacker can inject specific patterns to cause catastrophic backtracking, resulting in denial of service on all browsing.

- [https://github.com/George0Papasotiriou/CVE-2026-8888-Printer-Firmware-Unsigned-Update-via-HTTP](https://github.com/George0Papasotiriou/CVE-2026-8888-Printer-Firmware-Unsigned-Update-via-HTTP) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2026-8888-Printer-Firmware-Unsigned-Update-via-HTTP.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2026-8888-Printer-Firmware-Unsigned-Update-via-HTTP.svg)


## CVE-2026-8080
This affects the old templating (not more accessible in 2.5.37) engine from MISP which will be removed in 2.5.38

- [https://github.com/George0Papasotiriou/CVE-2026-8080-DKIM-Signature-Verification-Bypass-Header-Canonicalization-Flaw-](https://github.com/George0Papasotiriou/CVE-2026-8080-DKIM-Signature-Verification-Bypass-Header-Canonicalization-Flaw-) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2026-8080-DKIM-Signature-Verification-Bypass-Header-Canonicalization-Flaw-.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2026-8080-DKIM-Signature-Verification-Bypass-Header-Canonicalization-Flaw-.svg)


## CVE-2026-7070
 A weakness has been identified in code-projects Inventory Management System 1.0. Affected is an unknown function of the component Login. Executing a manipulation of the argument Username can lead to sql injection. The attack may be launched remotely. The exploit has been made available to the public and could be used for attacks.

- [https://github.com/George0Papasotiriou/CVE-2026-7070-RDP-Clipboard-Hijacking-via-Virtual-Channel-Injection](https://github.com/George0Papasotiriou/CVE-2026-7070-RDP-Clipboard-Hijacking-via-Virtual-Channel-Injection) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2026-7070-RDP-Clipboard-Hijacking-via-Virtual-Channel-Injection.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2026-7070-RDP-Clipboard-Hijacking-via-Virtual-Channel-Injection.svg)


## CVE-2026-6666
 A possible null pointer reference in PgBouncer before 1.25.2 could lead to a crash, if a server sends an error response without SQLSTATE field.

- [https://github.com/George0Papasotiriou/CVE-2026-6666-XPC-Service-NSKeyedUnarchiver-Deserialization-Attack-macOS-iOS-simulation-](https://github.com/George0Papasotiriou/CVE-2026-6666-XPC-Service-NSKeyedUnarchiver-Deserialization-Attack-macOS-iOS-simulation-) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2026-6666-XPC-Service-NSKeyedUnarchiver-Deserialization-Attack-macOS-iOS-simulation-.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2026-6666-XPC-Service-NSKeyedUnarchiver-Deserialization-Attack-macOS-iOS-simulation-.svg)


## CVE-2026-6060
  *  2026.X before 2026.3.X

- [https://github.com/George0Papasotiriou/CVE-2026-6060-QUIC-Handshake-Amplification-via-Address-Validation-Bypass](https://github.com/George0Papasotiriou/CVE-2026-6060-QUIC-Handshake-Amplification-via-Address-Validation-Bypass) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2026-6060-QUIC-Handshake-Amplification-via-Address-Validation-Bypass.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2026-6060-QUIC-Handshake-Amplification-via-Address-Validation-Bypass.svg)


## CVE-2026-5556
 A security vulnerability has been detected in badlogic pi-mono up to 0.58.4. This vulnerability affects the function discoverAndLoadExtensions of the file packages/coding-agent/src/core/extensions/loader.ts. The manipulation leads to code injection. Remote exploitation of the attack is possible. The exploit has been disclosed publicly and may be used. The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/George0Papasotiriou/CVE-2026-5556-Kubernetes-Admission-Controller-Bypass-via-Case-Sensitivity](https://github.com/George0Papasotiriou/CVE-2026-5556-Kubernetes-Admission-Controller-Bypass-via-Case-Sensitivity) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2026-5556-Kubernetes-Admission-Controller-Bypass-via-Case-Sensitivity.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2026-5556-Kubernetes-Admission-Controller-Bypass-via-Case-Sensitivity.svg)


## CVE-2026-5555
 A weakness has been identified in code-projects Concert Ticket Reservation System 1.0. This affects an unknown part of the file /ConcertTicketReservationSystem-master/login.php of the component Parameter Handler. Executing a manipulation of the argument Email can lead to sql injection. The attack may be launched remotely. The exploit has been made available to the public and could be used for attacks.

- [https://github.com/George0Papasotiriou/CVE-2026-5555-Container-Escape-via-proc-self-fd-Symlink-in-Shared-Volume](https://github.com/George0Papasotiriou/CVE-2026-5555-Container-Escape-via-proc-self-fd-Symlink-in-Shared-Volume) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2026-5555-Container-Escape-via-proc-self-fd-Symlink-in-Shared-Volume.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2026-5555-Container-Escape-via-proc-self-fd-Symlink-in-Shared-Volume.svg)


## CVE-2026-5050
 The Payment Gateway for Redsys & WooCommerce Lite plugin for WordPress is vulnerable to Improper Verification of Cryptographic Signature in versions up to, and including, 7.0.0 due to successful_request() handlers calculating a local signature but not validating Ds_Signature from the request before accepting payment status across the Redsys, Bizum, and Google Pay gateway flows. This makes it possible for unauthenticated attackers to forge payment callback data and mark pending orders as paid when they know a valid order key and order amount, potentially allowing checkout completion and product or service fulfillment without a successful payment.

- [https://github.com/George0Papasotiriou/CVE-2026-5050-Blind-LDAP-Injection-via-Unescaped-Filter](https://github.com/George0Papasotiriou/CVE-2026-5050-Blind-LDAP-Injection-via-Unescaped-Filter) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2026-5050-Blind-LDAP-Injection-via-Unescaped-Filter.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2026-5050-Blind-LDAP-Injection-via-Unescaped-Filter.svg)


## CVE-2026-4567
 A vulnerability has been found in Tenda A15 15.13.07.13. The impacted element is the function UploadCfg of the file /cgi-bin/UploadCfg. The manipulation of the argument File leads to stack-based buffer overflow. The attack may be initiated remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/George0Papasotiriou/CVE-2026-4567-Post-Quantum-KEM-Timing-Side-Channel-Kyber-Decapsulation-](https://github.com/George0Papasotiriou/CVE-2026-4567-Post-Quantum-KEM-Timing-Side-Channel-Kyber-Decapsulation-) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2026-4567-Post-Quantum-KEM-Timing-Side-Channel-Kyber-Decapsulation-.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2026-4567-Post-Quantum-KEM-Timing-Side-Channel-Kyber-Decapsulation-.svg)


## CVE-2026-4444
 Stack buffer overflow in WebRTC in Google Chrome prior to 146.0.7680.153 allowed a remote attacker to potentially exploit stack corruption via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/George0Papasotiriou/CVE-2026-4444-JWT-Algorithm-Confusion-via-kid-Injection](https://github.com/George0Papasotiriou/CVE-2026-4444-JWT-Algorithm-Confusion-via-kid-Injection) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2026-4444-JWT-Algorithm-Confusion-via-kid-Injection.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2026-4444-JWT-Algorithm-Confusion-via-kid-Injection.svg)


## CVE-2026-4443
 Heap buffer overflow in WebAudio in Google Chrome prior to 146.0.7680.153 allowed a remote attacker to execute arbitrary code inside a sandbox via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/llaytynher/CVE-2026-44438](https://github.com/llaytynher/CVE-2026-44438) :  ![starts](https://img.shields.io/github/stars/llaytynher/CVE-2026-44438.svg) ![forks](https://img.shields.io/github/forks/llaytynher/CVE-2026-44438.svg)


## CVE-2026-4040
 A vulnerability was identified in OpenClaw up to 2026.2.17. This issue affects the function tools.exec.safeBins of the component File Existence Handler. The manipulation leads to information exposure through discrepancy. The attack needs to be performed locally. Upgrading to version 2026.2.19-beta.1 is capable of addressing this issue. The identifier of the patch is bafdbb6f112409a65decd3d4e7350fbd637c7754. Upgrading the affected component is advised.

- [https://github.com/George0Papasotiriou/CVE-2026-4040-Race-Condition-in-File-Upload-Leading-to-RCE](https://github.com/George0Papasotiriou/CVE-2026-4040-Race-Condition-in-File-Upload-Leading-to-RCE) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2026-4040-Race-Condition-in-File-Upload-Leading-to-RCE.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2026-4040-Race-Condition-in-File-Upload-Leading-to-RCE.svg)


## CVE-2026-3854
 An improper neutralization of special elements vulnerability was identified in GitHub Enterprise Server that allowed an attacker with push access to a repository to achieve remote code execution on the instance. During a git push operation, user-supplied push option values were not properly sanitized before being included in internal service headers. Because the internal header format used a delimiter character that could also appear in user input, an attacker could inject additional metadata fields through crafted push option values. This vulnerability was reported via the GitHub Bug Bounty program and has been fixed in GitHub Enterprise Server versions 3.14.25, 3.15.20, 3.16.16, 3.17.13, 3.18.7 and 3.19.4.

- [https://github.com/royaleybovich/CVE-2026-3854-lab](https://github.com/royaleybovich/CVE-2026-3854-lab) :  ![starts](https://img.shields.io/github/stars/royaleybovich/CVE-2026-3854-lab.svg) ![forks](https://img.shields.io/github/forks/royaleybovich/CVE-2026-3854-lab.svg)


## CVE-2026-3456
 The GeekyBot — Generate AI Content Without Prompt, Chatbot and Lead Generation plugin for WordPress is vulnerable to SQL Injection via the 'attributekey' parameter in versions up to, and including, 1.2.0 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query. This makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database.

- [https://github.com/George0Papasotiriou/CVE-2026-3456-OAuth2-PKCE-Race-Condition-Account-Takeover-](https://github.com/George0Papasotiriou/CVE-2026-3456-OAuth2-PKCE-Race-Condition-Account-Takeover-) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2026-3456-OAuth2-PKCE-Race-Condition-Account-Takeover-.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2026-3456-OAuth2-PKCE-Race-Condition-Account-Takeover-.svg)


## CVE-2026-3333
 The MinhNhut Link Gateway plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the plugin's 'linkgate' shortcode in all versions up to, and including, 3.6.1 due to insufficient input sanitization and output escaping on user supplied attributes. This makes it possible for authenticated attackers, with Contributor-level access and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.

- [https://github.com/George0Papasotiriou/CVE-2026-3333-DNS-Rebinding-to-Steal-Cloud-Metadata](https://github.com/George0Papasotiriou/CVE-2026-3333-DNS-Rebinding-to-Steal-Cloud-Metadata) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2026-3333-DNS-Rebinding-to-Steal-Cloud-Metadata.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2026-3333-DNS-Rebinding-to-Steal-Cloud-Metadata.svg)


## CVE-2026-2828
 ** REJECT ** DO NOT USE THIS CANDIDATE NUMBER. Reason: This candidate was issued in error. Notes: All references and descriptions in this candidate have been removed to prevent accidental usage.

- [https://github.com/George0Papasotiriou/CVE-2026-2828-WebGPU-Cross-Origin-Pixel-Stealing-via-Timing](https://github.com/George0Papasotiriou/CVE-2026-2828-WebGPU-Cross-Origin-Pixel-Stealing-via-Timing) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2026-2828-WebGPU-Cross-Origin-Pixel-Stealing-via-Timing.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2026-2828-WebGPU-Cross-Origin-Pixel-Stealing-via-Timing.svg)


## CVE-2026-1337
Proof of concept exploit:  https://github.com/JoakimBulow/CVE-2026-1337

- [https://github.com/George0Papasotiriou/CVE-2026-1337-AI-Coding-Assistant-Prompt-Injection-to-Sandbox-Escape](https://github.com/George0Papasotiriou/CVE-2026-1337-AI-Coding-Assistant-Prompt-Injection-to-Sandbox-Escape) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2026-1337-AI-Coding-Assistant-Prompt-Injection-to-Sandbox-Escape.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2026-1337-AI-Coding-Assistant-Prompt-Injection-to-Sandbox-Escape.svg)


## CVE-2026-1122
 A vulnerability was determined in Yonyou KSOA 9.0. This impacts an unknown function of the file /worksheet/work_info.jsp of the component HTTP GET Parameter Handler. This manipulation of the argument ID causes sql injection. The attack may be initiated remotely. The exploit has been publicly disclosed and may be utilized. The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/George0Papasotiriou/CVE-2026-1122-IoT-Firmware-Update-Signature-Bypass-via-Low-Order-Point-Injection](https://github.com/George0Papasotiriou/CVE-2026-1122-IoT-Firmware-Update-Signature-Bypass-via-Low-Order-Point-Injection) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2026-1122-IoT-Firmware-Update-Signature-Bypass-via-Low-Order-Point-Injection.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2026-1122-IoT-Firmware-Update-Signature-Bypass-via-Low-Order-Point-Injection.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo.svg)


## CVE-2025-55192
 HomeAssistant-Tapo-Control offers Control for Tapo cameras as a Home Assistant component. Prior to commit 2a3b80f, there is a code injection vulnerability in the GitHub Actions workflow .github/workflows/issues.yml. It does not affect users of the Home Assistant integration itself — it only impacts the GitHub Actions environment for this repository. The vulnerable workflow directly inserted user-controlled content from the issue body (github.event.issue.body) into a Bash conditional without proper sanitization. A malicious GitHub user could craft an issue body that executes arbitrary commands on the GitHub Actions runner in a privileged context whenever an issue is opened. The potential impact is limited to the repository’s CI/CD environment, which could allow access to repository contents or GitHub Actions secrets. This issue has been patched via commit 2a3b80f. Workarounds involve disabling the affected workflow (issues.yml), replacing the unsafe Bash comparison with a safe quoted grep (or a pure GitHub Actions expression check), or ensuring minimal permissions in workflows (permissions: block) to reduce possible impact.

- [https://github.com/ghapvharmo/gha-lab-7ccf56a2a4](https://github.com/ghapvharmo/gha-lab-7ccf56a2a4) :  ![starts](https://img.shields.io/github/stars/ghapvharmo/gha-lab-7ccf56a2a4.svg) ![forks](https://img.shields.io/github/forks/ghapvharmo/gha-lab-7ccf56a2a4.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/0xPb1/Next.js-CVE-2025-29927](https://github.com/0xPb1/Next.js-CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/0xPb1/Next.js-CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/0xPb1/Next.js-CVE-2025-29927.svg)


## CVE-2025-4893
 A vulnerability classified as critical has been found in jammy928 CoinExchange_CryptoExchange_Java up to 8adf508b996020d3efbeeb2473d7235bd01436fa. This affects the function uploadLocalImage of the file /CoinExchange_CryptoExchange_Java-master/00_framework/core/src/main/java/com/bizzan/bitrade/util/UploadFileUtil.java of the component File Upload Endpoint. The manipulation of the argument filename leads to path traversal. It is possible to initiate the attack remotely. The exploit has been disclosed to the public and may be used. This product does not use versioning. This is why information about affected and unaffected releases are unavailable.

- [https://github.com/CerberusMrXi/CVE-2025-48932-Invision-Community-SQLi-Exploit](https://github.com/CerberusMrXi/CVE-2025-48932-Invision-Community-SQLi-Exploit) :  ![starts](https://img.shields.io/github/stars/CerberusMrXi/CVE-2025-48932-Invision-Community-SQLi-Exploit.svg) ![forks](https://img.shields.io/github/forks/CerberusMrXi/CVE-2025-48932-Invision-Community-SQLi-Exploit.svg)


## CVE-2024-21762
 A out-of-bounds write in Fortinet FortiOS versions 7.4.0 through 7.4.2, 7.2.0 through 7.2.6, 7.0.0 through 7.0.13, 6.4.0 through 6.4.14, 6.2.0 through 6.2.15, 6.0.0 through 6.0.17, FortiProxy versions 7.4.0 through 7.4.2, 7.2.0 through 7.2.8, 7.0.0 through 7.0.14, 2.0.0 through 2.0.13, 1.2.0 through 1.2.13, 1.1.0 through 1.1.6, 1.0.0 through 1.0.7 allows attacker to execute unauthorized code or commands via specifically crafted requests

- [https://github.com/Vampsecure-Labs/vamp-forticheck](https://github.com/Vampsecure-Labs/vamp-forticheck) :  ![starts](https://img.shields.io/github/stars/Vampsecure-Labs/vamp-forticheck.svg) ![forks](https://img.shields.io/github/forks/Vampsecure-Labs/vamp-forticheck.svg)


## CVE-2024-4367
 A type check was missing when handling fonts in PDF.js, which would allow arbitrary JavaScript execution in the PDF.js context. This vulnerability affects Firefox  126, Firefox ESR  115.11, and Thunderbird  115.11.

- [https://github.com/DharmarajPS/pdfjs-cve-2024-4367-poc](https://github.com/DharmarajPS/pdfjs-cve-2024-4367-poc) :  ![starts](https://img.shields.io/github/stars/DharmarajPS/pdfjs-cve-2024-4367-poc.svg) ![forks](https://img.shields.io/github/forks/DharmarajPS/pdfjs-cve-2024-4367-poc.svg)

