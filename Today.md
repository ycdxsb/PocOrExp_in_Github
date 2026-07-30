# Update 2026-07-30
## CVE-2026-67185
 TinyWeb through 0.0.8 contains a path traversal vulnerability that allows unauthenticated attackers to read arbitrary files by submitting ../ sequences in the URL path, which are concatenated directly to the configured web root in HttpBuilder::buildResponse() without normalization, dot-segment removal, or boundary checks. Attackers can craft a single request with ../ sequences that pass through the URL parser unchanged and reach the filesystem call via HttpFile::setFile(), exposing sensitive files such as credential stores and private keys when the server process runs as root.

- [https://github.com/theopaid/CVE-2026-67185-Unauthenticated-Path-Traversal-Allows-Arbitrary-File-Read-TinyWeb-](https://github.com/theopaid/CVE-2026-67185-Unauthenticated-Path-Traversal-Allows-Arbitrary-File-Read-TinyWeb-) :  ![starts](https://img.shields.io/github/stars/theopaid/CVE-2026-67185-Unauthenticated-Path-Traversal-Allows-Arbitrary-File-Read-TinyWeb-.svg) ![forks](https://img.shields.io/github/forks/theopaid/CVE-2026-67185-Unauthenticated-Path-Traversal-Allows-Arbitrary-File-Read-TinyWeb-.svg)


## CVE-2026-67184
 TinyWeb through 0.0.8 contains a null pointer dereference vulnerability that allows unauthenticated remote attackers to crash worker processes by sending a malformed HTTP request line with an invalid version string. The HttpParser::execute() function fails to allocate the Url object when version parsing fails, leaving the url pointer NULL, and buildResponse() subsequently dereferences this NULL pointer without checking the valid_requ flag, producing a SIGSEGV that terminates the worker process and, when repeated across all workers, takes the server permanently offline until manually restarted.

- [https://github.com/theopaid/CVE-2026-67184-Unauthenticated-NULL-Pointer-Dereference-Crashes-the-Server-TinyWeb-](https://github.com/theopaid/CVE-2026-67184-Unauthenticated-NULL-Pointer-Dereference-Crashes-the-Server-TinyWeb-) :  ![starts](https://img.shields.io/github/stars/theopaid/CVE-2026-67184-Unauthenticated-NULL-Pointer-Dereference-Crashes-the-Server-TinyWeb-.svg) ![forks](https://img.shields.io/github/forks/theopaid/CVE-2026-67184-Unauthenticated-NULL-Pointer-Dereference-Crashes-the-Server-TinyWeb-.svg)


## CVE-2026-67183
 TinyWeb through 0.0.8 contains a memory leak vulnerability that allows unauthenticated attackers to exhaust available memory by sending ordinary well-formed HTTP requests. Each request causes HttpParser::execute() to allocate Url objects, HttpHeaders objects, and HttpHeader instances via raw new expressions that are never freed due to missing destructors and unreachable delete calls, causing worker resident memory to grow monotonically by approximately 20 to 28 kB per request until the worker process is killed.

- [https://github.com/theopaid/CVE-2026-67183-Unauthenticated-Memory-Leak-Leads-To-Memory-Exhaustion-TinyWeb-](https://github.com/theopaid/CVE-2026-67183-Unauthenticated-Memory-Leak-Leads-To-Memory-Exhaustion-TinyWeb-) :  ![starts](https://img.shields.io/github/stars/theopaid/CVE-2026-67183-Unauthenticated-Memory-Leak-Leads-To-Memory-Exhaustion-TinyWeb-.svg) ![forks](https://img.shields.io/github/forks/theopaid/CVE-2026-67183-Unauthenticated-Memory-Leak-Leads-To-Memory-Exhaustion-TinyWeb-.svg)


## CVE-2026-67182
 Rouille 0.3.3 through 3.6.2 contains an HTTP request smuggling vulnerability that allows remote attackers to bypass access controls by injecting bare line feed characters (0x0A) into client-supplied request header values that are copied verbatim to upstream connections without validation. Attackers can craft a header value containing a complete additional HTTP request that is interpreted as a separate request by backends such as Go net/http and Python http.server, causing the backend to process a smuggled request with attacker-chosen method, path, and headers that bypasses the rouille handler's access control logic.

- [https://github.com/theopaid/CVE-2026-67182-HTTP-Request-Smuggling-Enables-Front-End-Access-Control-Bypass-rouille-](https://github.com/theopaid/CVE-2026-67182-HTTP-Request-Smuggling-Enables-Front-End-Access-Control-Bypass-rouille-) :  ![starts](https://img.shields.io/github/stars/theopaid/CVE-2026-67182-HTTP-Request-Smuggling-Enables-Front-End-Access-Control-Bypass-rouille-.svg) ![forks](https://img.shields.io/github/forks/theopaid/CVE-2026-67182-HTTP-Request-Smuggling-Enables-Front-End-Access-Control-Bypass-rouille-.svg)


## CVE-2026-67181
 Rouille 0.3.3 through 3.6.2 contains an HTTP request smuggling vulnerability that allows remote attackers to desynchronize HTTP message boundaries by exploiting improper header forwarding in the proxy implementation. The proxy in src/proxy.rs forwards the client's Transfer-Encoding header to upstream backends unchanged while transmitting a body already de-chunked by tiny_http, enabling CL.TE desynchronization attacks where attackers control where the backend believes the request body ends.

- [https://github.com/theopaid/CVE-2026-67181-HTTP-Request-Smuggling-via-Transfer-Encoding-Desynchronization-rouille-](https://github.com/theopaid/CVE-2026-67181-HTTP-Request-Smuggling-via-Transfer-Encoding-Desynchronization-rouille-) :  ![starts](https://img.shields.io/github/stars/theopaid/CVE-2026-67181-HTTP-Request-Smuggling-via-Transfer-Encoding-Desynchronization-rouille-.svg) ![forks](https://img.shields.io/github/forks/theopaid/CVE-2026-67181-HTTP-Request-Smuggling-via-Transfer-Encoding-Desynchronization-rouille-.svg)


## CVE-2026-66754
 Rouille 0.1.6 through 3.6.2 contains a reachable assertion vulnerability in the Request::remove_prefix function that allows remote unauthenticated attackers to crash the server by sending a crafted percent-encoded URL. Attackers can send a request whose decoded path matches a configured prefix while the raw percent-encoded path does not, causing the assert! to fail and triggering either a 500 error or full process termination depending on the panic configuration.

- [https://github.com/theopaid/CVE-2026-66754-Remote-Denial-of-Service-via-Reachable-Assertion-in-URL-Prefix-Handling-rouille-](https://github.com/theopaid/CVE-2026-66754-Remote-Denial-of-Service-via-Reachable-Assertion-in-URL-Prefix-Handling-rouille-) :  ![starts](https://img.shields.io/github/stars/theopaid/CVE-2026-66754-Remote-Denial-of-Service-via-Reachable-Assertion-in-URL-Prefix-Handling-rouille-.svg) ![forks](https://img.shields.io/github/forks/theopaid/CVE-2026-66754-Remote-Denial-of-Service-via-Reachable-Assertion-in-URL-Prefix-Handling-rouille-.svg)


## CVE-2026-66753
 tiny-http through 0.12.0 contains an HTTP header injection vulnerability that allows attackers to inject carriage return (0x0D) and line feed (0x0A) bytes into HTTP header values on both request and response sides due to insufficient validation in header parsing and serialization. Attackers can exploit this injection primitive to perform response splitting, cache poisoning, session fixation via Set-Cookie injection, security header override, and request smuggling against line-feed-tolerant backends.

- [https://github.com/theopaid/CVE-2026-66753-HTTP-Header-Injection-via-Unvalidated-CR-and-LF-in-Header-Values-tiny_http-](https://github.com/theopaid/CVE-2026-66753-HTTP-Header-Injection-via-Unvalidated-CR-and-LF-in-Header-Values-tiny_http-) :  ![starts](https://img.shields.io/github/stars/theopaid/CVE-2026-66753-HTTP-Header-Injection-via-Unvalidated-CR-and-LF-in-Header-Values-tiny_http-.svg) ![forks](https://img.shields.io/github/forks/theopaid/CVE-2026-66753-HTTP-Header-Injection-via-Unvalidated-CR-and-LF-in-Header-Values-tiny_http-.svg)


## CVE-2026-66752
 tiny-http through 0.12.0 contains an HTTP request smuggling vulnerability that allows remote attackers to desynchronize request framing by sending a Transfer-Encoding header with any value, including non-chunked codings, which causes the library to unconditionally apply chunk-decoding and discard Content-Length. Attackers can exploit the discrepancy between tiny_http's improper Transfer-Encoding parsing and a correctly-implemented front-end proxy to produce two distinct interpretations of a single byte stream, enabling request smuggling, and can additionally send non-chunked bodies with non-chunked Transfer-Encoding values to cause failed body reads that tie up connections and consume worker threads without signaling errors to clients.

- [https://github.com/theopaid/CVE-2026-66752-HTTP-Request-Smuggling-via-Unparsed-Transfer-Encoding-Values-tiny_http-](https://github.com/theopaid/CVE-2026-66752-HTTP-Request-Smuggling-via-Unparsed-Transfer-Encoding-Values-tiny_http-) :  ![starts](https://img.shields.io/github/stars/theopaid/CVE-2026-66752-HTTP-Request-Smuggling-via-Unparsed-Transfer-Encoding-Values-tiny_http-.svg) ![forks](https://img.shields.io/github/forks/theopaid/CVE-2026-66752-HTTP-Request-Smuggling-via-Unparsed-Transfer-Encoding-Values-tiny_http-.svg)


## CVE-2026-66751
 Let's Chat 0.3.0 through 0.4.8 contains an improper authorization vulnerability that allows any authenticated user to archive any room on the server by sending a DELETE request to the rooms handler without ownership verification. Attackers can enumerate room IDs via the rooms listing endpoint and permanently archive private or password-protected rooms they cannot access, with no application-level recovery path requiring direct database intervention to restore.

- [https://github.com/theopaid/CVE-2026-66751-Insufficient-Access-Controls-Allow-for-Unauthorized-Room-Deletion-Let-s-Chat-](https://github.com/theopaid/CVE-2026-66751-Insufficient-Access-Controls-Allow-for-Unauthorized-Room-Deletion-Let-s-Chat-) :  ![starts](https://img.shields.io/github/stars/theopaid/CVE-2026-66751-Insufficient-Access-Controls-Allow-for-Unauthorized-Room-Deletion-Let-s-Chat-.svg) ![forks](https://img.shields.io/github/forks/theopaid/CVE-2026-66751-Insufficient-Access-Controls-Allow-for-Unauthorized-Room-Deletion-Let-s-Chat-.svg)


## CVE-2026-66750
 Let's Chat 0.3.0 through 0.4.8 contains a broken access control vulnerability that allows authenticated attackers to download file attachments from private and password-protected rooms they are not a member of by exploiting missing room membership checks in the file retrieval route. Attackers can enumerate adjacent MongoDB ObjectIds derived from a known file ID to recover files uploaded by other users, as the GET /files/:id/:name route in app/controllers/files.js only enforces login authentication without consulting room membership or the Room.canJoin check.

- [https://github.com/theopaid/CVE-2026-66750-Insufficient-Access-Controls-Allow-for-Unauthorized-File-Downloads-Let-s-Chat-](https://github.com/theopaid/CVE-2026-66750-Insufficient-Access-Controls-Allow-for-Unauthorized-File-Downloads-Let-s-Chat-) :  ![starts](https://img.shields.io/github/stars/theopaid/CVE-2026-66750-Insufficient-Access-Controls-Allow-for-Unauthorized-File-Downloads-Let-s-Chat-.svg) ![forks](https://img.shields.io/github/forks/theopaid/CVE-2026-66750-Insufficient-Access-Controls-Allow-for-Unauthorized-File-Downloads-Let-s-Chat-.svg)


## CVE-2026-66749
 Let's Chat 0.4.0 through 0.4.8 contains a null dereference vulnerability that allows authenticated attackers to crash the server by supplying a valid 24-character hex string room parameter that matches no document in the database. Attackers can send a crafted GET /messages request causing an uncaught TypeError in an asynchronous Mongoose callback that terminates the Node.js server process, with the same defect reachable through multiple code paths including the socket.io interface.

- [https://github.com/theopaid/CVE-2026-66749-Unchecked-Room-Lookup-Leads-to-Server-Crash-Let-s-Chat-](https://github.com/theopaid/CVE-2026-66749-Unchecked-Room-Lookup-Leads-to-Server-Crash-Let-s-Chat-) :  ![starts](https://img.shields.io/github/stars/theopaid/CVE-2026-66749-Unchecked-Room-Lookup-Leads-to-Server-Crash-Let-s-Chat-.svg) ![forks](https://img.shields.io/github/forks/theopaid/CVE-2026-66749-Unchecked-Room-Lookup-Leads-to-Server-Crash-Let-s-Chat-.svg)


## CVE-2026-66748
 Camaleon CMS versions 2.1.1 through 2.9.1 contains an authenticated remote code execution vulnerability that allows users with custom_fields manage permission to execute arbitrary Ruby code by supplying a malicious expression through the select_eval custom field type. Attackers can store an attacker-controlled Ruby expression in the field options command parameter, which is evaluated via instance_eval within an ERB view whenever a post edit page is rendered, achieving server-side code execution with web server process privileges.

- [https://github.com/theopaid/CVE-2026-66748-Camaleon-CMS---Authenticated-RCE-via-select_eval-Custom-Field](https://github.com/theopaid/CVE-2026-66748-Camaleon-CMS---Authenticated-RCE-via-select_eval-Custom-Field) :  ![starts](https://img.shields.io/github/stars/theopaid/CVE-2026-66748-Camaleon-CMS---Authenticated-RCE-via-select_eval-Custom-Field.svg) ![forks](https://img.shields.io/github/forks/theopaid/CVE-2026-66748-Camaleon-CMS---Authenticated-RCE-via-select_eval-Custom-Field.svg)


## CVE-2026-66746
 Rouille 0.4.0 through 3.6.2 contains an HTTP response splitting vulnerability that allows remote attackers to inject arbitrary response headers by embedding carriage return (0x0D) or line feed (0x0A) bytes into attacker-controlled input. Attackers can exploit percent-decoded query parameters reflected into response headers or inject bare LF characters into Cookie header values that are interpolated directly into Set-Cookie response headers, enabling cache poisoning, session fixation, and security header override attacks such as bypassing CSP or CORS policies.

- [https://github.com/theopaid/CVE-2026-66746-HTTP-Response-Splitting-via-Unvalidated-Response-Header-Values-rouille-](https://github.com/theopaid/CVE-2026-66746-HTTP-Response-Splitting-via-Unvalidated-Response-Header-Values-rouille-) :  ![starts](https://img.shields.io/github/stars/theopaid/CVE-2026-66746-HTTP-Response-Splitting-via-Unvalidated-Response-Header-Values-rouille-.svg) ![forks](https://img.shields.io/github/forks/theopaid/CVE-2026-66746-HTTP-Response-Splitting-via-Unvalidated-Response-Header-Values-rouille-.svg)


## CVE-2026-65894
Successful exploitation of this vulnerability could allow an attacker to gain unauthorized access to live video snapshots from the targeted device.

- [https://github.com/ivmks74/IIITA-IoT-Security-Research](https://github.com/ivmks74/IIITA-IoT-Security-Research) :  ![starts](https://img.shields.io/github/stars/ivmks74/IIITA-IoT-Security-Research.svg) ![forks](https://img.shields.io/github/forks/ivmks74/IIITA-IoT-Security-Research.svg)


## CVE-2026-65893
Successful exploitation of this vulnerability could allow an attacker to execute arbitrary code with elevated privileges on the targeted device.

- [https://github.com/CyberVinner/CP-PLUS-EZ-P21-CVE-2026-65893-65894](https://github.com/CyberVinner/CP-PLUS-EZ-P21-CVE-2026-65893-65894) :  ![starts](https://img.shields.io/github/stars/CyberVinner/CP-PLUS-EZ-P21-CVE-2026-65893-65894.svg) ![forks](https://img.shields.io/github/forks/CyberVinner/CP-PLUS-EZ-P21-CVE-2026-65893-65894.svg)
- [https://github.com/ivmks74/IIITA-IoT-Security-Research](https://github.com/ivmks74/IIITA-IoT-Security-Research) :  ![starts](https://img.shields.io/github/stars/ivmks74/IIITA-IoT-Security-Research.svg) ![forks](https://img.shields.io/github/forks/ivmks74/IIITA-IoT-Security-Research.svg)


## CVE-2026-65761
 Joomla Extension - joomshaper.com - Unauthenticated SQL injection in Easy Store extension 1.0.0-2.0.1 - Improper validation of order parameters lead to an unauthenticated SQL injection in easystore, allowing full DB read access including credentials and sessions.

- [https://github.com/ywh-jfellus/CVE-2026-65761](https://github.com/ywh-jfellus/CVE-2026-65761) :  ![starts](https://img.shields.io/github/stars/ywh-jfellus/CVE-2026-65761.svg) ![forks](https://img.shields.io/github/forks/ywh-jfellus/CVE-2026-65761.svg)


## CVE-2026-64725
 An out-of-bounds write issue was addressed with improved bounds checking. This issue is fixed in iOS 26.6 and iPadOS 26.6, macOS Sequoia 15.7.8, macOS Sonoma 14.8.8, macOS Tahoe 26.6, tvOS 26.6, visionOS 26.6, watchOS 26.6. An app may be able to cause a denial-of-service.

- [https://github.com/altvist/cve-2026-64725-poc](https://github.com/altvist/cve-2026-64725-poc) :  ![starts](https://img.shields.io/github/stars/altvist/cve-2026-64725-poc.svg) ![forks](https://img.shields.io/github/forks/altvist/cve-2026-64725-poc.svg)


## CVE-2026-64600
sequence counter changes across the ILOCK cycle.

- [https://github.com/bha-vin/CVE-2026-64600-Exploit](https://github.com/bha-vin/CVE-2026-64600-Exploit) :  ![starts](https://img.shields.io/github/stars/bha-vin/CVE-2026-64600-Exploit.svg) ![forks](https://img.shields.io/github/forks/bha-vin/CVE-2026-64600-Exploit.svg)
- [https://github.com/letsr00t/RefluxFS_CVE-2026-64600](https://github.com/letsr00t/RefluxFS_CVE-2026-64600) :  ![starts](https://img.shields.io/github/stars/letsr00t/RefluxFS_CVE-2026-64600.svg) ![forks](https://img.shields.io/github/forks/letsr00t/RefluxFS_CVE-2026-64600.svg)


## CVE-2026-61511
 vBulletin 5.x through 5.7.5 and 6.x through 6.2.1 contains an eval injection vulnerability in the vB5_Template_Runtime::runMaths() method within the template runtime that allows unauthenticated remote attackers to execute arbitrary PHP code by supplying crafted input through the pagenav[pagenumber] parameter. Attackers can exploit the insufficiently restrictive regex filter by using phpfuck-style encoding with permitted characters to inject and execute arbitrary PHP code via the unauthenticated ajax/render template route without any authentication.

- [https://github.com/puj790201-lab/cve-2026-61511](https://github.com/puj790201-lab/cve-2026-61511) :  ![starts](https://img.shields.io/github/stars/puj790201-lab/cve-2026-61511.svg) ![forks](https://img.shields.io/github/forks/puj790201-lab/cve-2026-61511.svg)
- [https://github.com/codeb0ssx/Ultimate-CVE-2026-61511](https://github.com/codeb0ssx/Ultimate-CVE-2026-61511) :  ![starts](https://img.shields.io/github/stars/codeb0ssx/Ultimate-CVE-2026-61511.svg) ![forks](https://img.shields.io/github/forks/codeb0ssx/Ultimate-CVE-2026-61511.svg)


## CVE-2026-59891
 sigstore-js provides JavaScript libraries for interacting with Sigstore services. Prior to 0.7.1, getRegistryCredentials() reads credentials from the Docker config file and selects an entry by checking whether any configured auth key contains the target registry string. Because this is a substring match rather than an exact host match, credentials configured for one registry can be selected for and transmitted to a different registry whose hostname has a substring relationship with a configured auth key. This issue is fixed in version 0.7.1.

- [https://github.com/gyubin02/cve-2026-59891-control-lab](https://github.com/gyubin02/cve-2026-59891-control-lab) :  ![starts](https://img.shields.io/github/stars/gyubin02/cve-2026-59891-control-lab.svg) ![forks](https://img.shields.io/github/forks/gyubin02/cve-2026-59891-control-lab.svg)


## CVE-2026-58586
Any caller that decodes an untrusted WebP image reaches the bundled decoder. Because the library is compiled into the module, upgrading the system libwebp does not remediate this.

- [https://github.com/extratao/Image-WebP](https://github.com/extratao/Image-WebP) :  ![starts](https://img.shields.io/github/stars/extratao/Image-WebP.svg) ![forks](https://img.shields.io/github/forks/extratao/Image-WebP.svg)


## CVE-2026-54121
 Improper authorization in Active Directory Certificate Services (AD CS) allows an authorized attacker to elevate privileges over a network.

- [https://github.com/mwnickerson/certighost-bof](https://github.com/mwnickerson/certighost-bof) :  ![starts](https://img.shields.io/github/stars/mwnickerson/certighost-bof.svg) ![forks](https://img.shields.io/github/forks/mwnickerson/certighost-bof.svg)
- [https://github.com/neebuchesno1/CVE-2026-54121](https://github.com/neebuchesno1/CVE-2026-54121) :  ![starts](https://img.shields.io/github/stars/neebuchesno1/CVE-2026-54121.svg) ![forks](https://img.shields.io/github/forks/neebuchesno1/CVE-2026-54121.svg)


## CVE-2026-53264
period, so no UAF can occur.

- [https://github.com/HORKimhab/CVE-2026-53264](https://github.com/HORKimhab/CVE-2026-53264) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-53264.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-53264.svg)


## CVE-2026-51302
 SQLite 3.41 has a use-after-free vulnerability exists in the expression evaluation logic. The sqlite3ReleaseTempReg function improperly releases temporary register resources, and the subsequent exprComputeOperands function continues to access the already freed register memory. By supplying a malicious SQL statement, a remote attacker can exploit this flaw to cause denial of service, leak sensitive information, or potentially execute arbitrary code on the affected system.

- [https://github.com/extratao/CVE-2026-51302-PoC](https://github.com/extratao/CVE-2026-51302-PoC) :  ![starts](https://img.shields.io/github/stars/extratao/CVE-2026-51302-PoC.svg) ![forks](https://img.shields.io/github/forks/extratao/CVE-2026-51302-PoC.svg)


## CVE-2026-50522
 Deserialization of untrusted data in Microsoft Office SharePoint allows an unauthorized attacker to execute code over a network.

- [https://github.com/darses/CVE-2026-50522](https://github.com/darses/CVE-2026-50522) :  ![starts](https://img.shields.io/github/stars/darses/CVE-2026-50522.svg) ![forks](https://img.shields.io/github/forks/darses/CVE-2026-50522.svg)


## CVE-2026-43499
  	changelog ]

- [https://github.com/Witaqua-tools/Root-My-Device](https://github.com/Witaqua-tools/Root-My-Device) :  ![starts](https://img.shields.io/github/stars/Witaqua-tools/Root-My-Device.svg) ![forks](https://img.shields.io/github/forks/Witaqua-tools/Root-My-Device.svg)


## CVE-2026-42926
 When NGINX Open Source is configured to proxy HTTP/2 traffic by setting proxy_http_version to 2, and also uses proxy_set_body, an attacker may be able to inject frame headers and payload bytes to the upstream peer.  Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/ChPratik/NGINX_2026_CVE_Bundle_CTI_Report](https://github.com/ChPratik/NGINX_2026_CVE_Bundle_CTI_Report) :  ![starts](https://img.shields.io/github/stars/ChPratik/NGINX_2026_CVE_Bundle_CTI_Report.svg) ![forks](https://img.shields.io/github/forks/ChPratik/NGINX_2026_CVE_Bundle_CTI_Report.svg)


## CVE-2026-42533
 Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/ChPratik/NGINX_2026_CVE_Bundle_CTI_Report](https://github.com/ChPratik/NGINX_2026_CVE_Bundle_CTI_Report) :  ![starts](https://img.shields.io/github/stars/ChPratik/NGINX_2026_CVE_Bundle_CTI_Report.svg) ![forks](https://img.shields.io/github/forks/ChPratik/NGINX_2026_CVE_Bundle_CTI_Report.svg)


## CVE-2026-42055
Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/ChPratik/NGINX_2026_CVE_Bundle_CTI_Report](https://github.com/ChPratik/NGINX_2026_CVE_Bundle_CTI_Report) :  ![starts](https://img.shields.io/github/stars/ChPratik/NGINX_2026_CVE_Bundle_CTI_Report.svg) ![forks](https://img.shields.io/github/forks/ChPratik/NGINX_2026_CVE_Bundle_CTI_Report.svg)


## CVE-2026-28755
Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/ChPratik/NGINX_2026_CVE_Bundle_CTI_Report](https://github.com/ChPratik/NGINX_2026_CVE_Bundle_CTI_Report) :  ![starts](https://img.shields.io/github/stars/ChPratik/NGINX_2026_CVE_Bundle_CTI_Report.svg) ![forks](https://img.shields.io/github/forks/ChPratik/NGINX_2026_CVE_Bundle_CTI_Report.svg)


## CVE-2026-16232
 An authentication bypass vulnerability in the Check Point SmartConsole login process allows an unauthenticated remote attacker to obtain an application login token and use it to authenticate with full administrative privileges. Successful exploitation allows the attacker to modify security policies and security configurations. Remote exploitation requires internet access to the Management Server IP address and a configuration that does not restrict Trusted Clients. Check Point is aware that this vulnerability is being exploited and has affected a very small number of customers.

- [https://github.com/sfewer-r7/CVE-2026-16232](https://github.com/sfewer-r7/CVE-2026-16232) :  ![starts](https://img.shields.io/github/stars/sfewer-r7/CVE-2026-16232.svg) ![forks](https://img.shields.io/github/forks/sfewer-r7/CVE-2026-16232.svg)


## CVE-2026-14856
 A stored Cross-Site Scripting (XSS) vulnerability in the file upload functionality of the Media Manager in TastyIgniter v4.3.0, caused by insufficient validation and sanitization of SVG files. An authenticated user with low privileges can upload a malicious SVG file containing JavaScript code. When an administrator views that file, the code executes in the context of their browser. By chaining this vulnerability with a Cross-Site Request Forgery (CSRF) attack, an attacker can extract the administrator’s CSRF token and perform unauthorized actions—such as modifying credentials—thereby gaining full control of the administrative account.

- [https://github.com/jonas-fernandez-as/CVE-2026-14856-TastyIgniter](https://github.com/jonas-fernandez-as/CVE-2026-14856-TastyIgniter) :  ![starts](https://img.shields.io/github/stars/jonas-fernandez-as/CVE-2026-14856-TastyIgniter.svg) ![forks](https://img.shields.io/github/forks/jonas-fernandez-as/CVE-2026-14856-TastyIgniter.svg)


## CVE-2026-9256
Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/ChPratik/NGINX_2026_CVE_Bundle_CTI_Report](https://github.com/ChPratik/NGINX_2026_CVE_Bundle_CTI_Report) :  ![starts](https://img.shields.io/github/stars/ChPratik/NGINX_2026_CVE_Bundle_CTI_Report.svg) ![forks](https://img.shields.io/github/forks/ChPratik/NGINX_2026_CVE_Bundle_CTI_Report.svg)


## CVE-2026-9198
 IBM Langflow OSS 1.0.0 through 1.10.0 allows unauthenticated attackers to chain /api/v1/auto_login (mints SUPERUSER tokens to any network caller) with /api/v1/validate/code (executes user code via exec()) to achieve full RCE on default Langflow deployments

- [https://github.com/samael0x4/CVE-2026-9198](https://github.com/samael0x4/CVE-2026-9198) :  ![starts](https://img.shields.io/github/stars/samael0x4/CVE-2026-9198.svg) ![forks](https://img.shields.io/github/forks/samael0x4/CVE-2026-9198.svg)


## CVE-2026-8206
 The Kirki – Freeform Page Builder, Website Builder & Customizer plugin for WordPress is vulnerable to privilege escalation via account takeover in all versions 6.0.0 to 6.0.6. This is due to the plugin accepting an arbitrary email address when a username is used in the password reset request. This makes it possible for unauthenticated attackers to send a password reset link for any user registered on the site to their own email address.

- [https://github.com/Dungsocool/CVE-2026-8206](https://github.com/Dungsocool/CVE-2026-8206) :  ![starts](https://img.shields.io/github/stars/Dungsocool/CVE-2026-8206.svg) ![forks](https://img.shields.io/github/forks/Dungsocool/CVE-2026-8206.svg)


## CVE-2026-5392
 Heap out-of-bounds read in PKCS7 parsing. A crafted PKCS7 message can trigger an OOB read on the heap. The missing bounds check is in the indefinite-length end-of-content verification loop in PKCS7_VerifySignedData().

- [https://github.com/0xBlackash/CVE-2026-53921](https://github.com/0xBlackash/CVE-2026-53921) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-53921.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-53921.svg)
- [https://github.com/tc4dy/CVE-2026-53921-PoC-Exploit](https://github.com/tc4dy/CVE-2026-53921-PoC-Exploit) :  ![starts](https://img.shields.io/github/stars/tc4dy/CVE-2026-53921-PoC-Exploit.svg) ![forks](https://img.shields.io/github/forks/tc4dy/CVE-2026-53921-PoC-Exploit.svg)


## CVE-2026-5199
This vulnerability also impacted Temporal Cloud when the attacker and victim namespaces were on the same cell, with the same preconditions as self-hosted clusters.

- [https://github.com/TheLiimbo/CVE-2026-51992](https://github.com/TheLiimbo/CVE-2026-51992) :  ![starts](https://img.shields.io/github/stars/TheLiimbo/CVE-2026-51992.svg) ![forks](https://img.shields.io/github/forks/TheLiimbo/CVE-2026-51992.svg)


## CVE-2025-71389
 Cal.com (calcom/cal.diy) before 5.9.9 is vulnerable to unauthenticated remote code execution because it bundles a version of Next.js whose React Server Components (RSC) request handling deserializes attacker-controlled input. A remote attacker can send a crafted RSC request to the server and cause arbitrary code to be executed during server-side processing, without authentication or user interaction. The flaw derives from the upstream Next.js vulnerability CVE-2025-55182 and is resolved in 5.9.9 by updating the affected dependency.

- [https://github.com/0xdak/CVE-2025-71389_exploit](https://github.com/0xdak/CVE-2025-71389_exploit) :  ![starts](https://img.shields.io/github/stars/0xdak/CVE-2025-71389_exploit.svg) ![forks](https://img.shields.io/github/forks/0xdak/CVE-2025-71389_exploit.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/Jibaru/CVE-2025-66478-github-patcher](https://github.com/Jibaru/CVE-2025-66478-github-patcher) :  ![starts](https://img.shields.io/github/stars/Jibaru/CVE-2025-66478-github-patcher.svg) ![forks](https://img.shields.io/github/forks/Jibaru/CVE-2025-66478-github-patcher.svg)


## CVE-2025-6563
 A cross-site scripting vulnerability is present in the hotspot of MikroTik's RouterOS on versions below 7.19.2. An attacker can inject the `javascript` protocol in the `dst` parameter. When the victim browses to the malicious URL and logs in, the XSS executes. The POST request used to login, can also be converted to a GET request, allowing an attacker to send a specifically crafted URL that automatically logs in the victim (into the attacker's account) and triggers the payload.

- [https://github.com/praksokchea/CVE-2025-6563](https://github.com/praksokchea/CVE-2025-6563) :  ![starts](https://img.shields.io/github/stars/praksokchea/CVE-2025-6563.svg) ![forks](https://img.shields.io/github/forks/praksokchea/CVE-2025-6563.svg)


## CVE-2025-5777
 Insufficient input validation leading to memory overread when the NetScaler is configured as a Gateway (VPN virtual server, ICA Proxy, CVPN, RDP Proxy) OR AAA virtual server

- [https://github.com/Sheep-Hunter/CVE-2025-5777-POC](https://github.com/Sheep-Hunter/CVE-2025-5777-POC) :  ![starts](https://img.shields.io/github/stars/Sheep-Hunter/CVE-2025-5777-POC.svg) ![forks](https://img.shields.io/github/forks/Sheep-Hunter/CVE-2025-5777-POC.svg)


## CVE-2024-4577
 In PHP versions 8.1.* before 8.1.29, 8.2.* before 8.2.20, 8.3.* before 8.3.8, when using Apache and PHP-CGI on Windows, if the system is set up to use certain code pages, Windows may use "Best-Fit" behavior to replace characters in command line given to Win32 API functions. PHP CGI module may misinterpret those characters as PHP options, which may allow a malicious user to pass options to PHP binary being run, and thus reveal the source code of scripts, run arbitrary PHP code on the server, etc.

- [https://github.com/NKTriS/HTSOC](https://github.com/NKTriS/HTSOC) :  ![starts](https://img.shields.io/github/stars/NKTriS/HTSOC.svg) ![forks](https://img.shields.io/github/forks/NKTriS/HTSOC.svg)


## CVE-2024-1813
 The Simple Job Board plugin for WordPress is vulnerable to PHP Object Injection in all versions up to, and including, 2.11.0 via deserialization of untrusted input in the job_board_applicant_list_columns_value function. This makes it possible for unauthenticated attackers to inject a PHP Object. If a POP chain is present via an additional plugin or theme installed on the target system, it could allow the attacker to delete arbitrary files, retrieve sensitive data, or execute code when a submitted job application is viewed.

- [https://github.com/webshellseo8/CVE-2024-1813-Proof-of-Concept](https://github.com/webshellseo8/CVE-2024-1813-Proof-of-Concept) :  ![starts](https://img.shields.io/github/stars/webshellseo8/CVE-2024-1813-Proof-of-Concept.svg) ![forks](https://img.shields.io/github/forks/webshellseo8/CVE-2024-1813-Proof-of-Concept.svg)


## CVE-2023-0264
 A flaw was found in Keycloaks OpenID Connect user authentication, which may incorrectly authenticate requests. An authenticated attacker who could obtain information from a user request within the same realm could use that data to impersonate the victim and generate new session tokens. This issue could impact confidentiality, integrity, and availability.

- [https://github.com/ElianGonzi00/pocKeycloakCVE-2023-0264](https://github.com/ElianGonzi00/pocKeycloakCVE-2023-0264) :  ![starts](https://img.shields.io/github/stars/ElianGonzi00/pocKeycloakCVE-2023-0264.svg) ![forks](https://img.shields.io/github/forks/ElianGonzi00/pocKeycloakCVE-2023-0264.svg)

