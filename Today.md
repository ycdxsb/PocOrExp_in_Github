# Update 2026-01-05
## CVE-2026-21450
 Bagisto is an open source laravel eCommerce platform. Versions prior to 2.3.10 are vulnerable to server-side template injection via type parameter, which can lead to remote code execution or another exploitation. Version 2.3.10 fixes the issue.

- [https://github.com/Ashwesker/Ashwesker-CVE-2026-21450](https://github.com/Ashwesker/Ashwesker-CVE-2026-21450) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2026-21450.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2026-21450.svg)


## CVE-2025-68613
 n8n is an open source workflow automation platform. Versions starting with 0.211.0 and prior to 1.120.4, 1.121.1, and 1.122.0 contain a critical Remote Code Execution (RCE) vulnerability in their workflow expression evaluation system. Under certain conditions, expressions supplied by authenticated users during workflow configuration may be evaluated in an execution context that is not sufficiently isolated from the underlying runtime. An authenticated attacker could abuse this behavior to execute arbitrary code with the privileges of the n8n process. Successful exploitation may lead to full compromise of the affected instance, including unauthorized access to sensitive data, modification of workflows, and execution of system-level operations. This issue has been fixed in versions 1.120.4, 1.121.1, and 1.122.0. Users are strongly advised to upgrade to a patched version, which introduces additional safeguards to restrict expression evaluation. If upgrading is not immediately possible, administrators should consider the following temporary mitigations: Limit workflow creation and editing permissions to fully trusted users only; and/or deploy n8n in a hardened environment with restricted operating system privileges and network access to reduce the impact of potential exploitation. These workarounds do not fully eliminate the risk and should only be used as short-term measures.

- [https://github.com/TheInterception/n8n_CVE-2025-68613_exploit_payloads](https://github.com/TheInterception/n8n_CVE-2025-68613_exploit_payloads) :  ![starts](https://img.shields.io/github/stars/TheInterception/n8n_CVE-2025-68613_exploit_payloads.svg) ![forks](https://img.shields.io/github/forks/TheInterception/n8n_CVE-2025-68613_exploit_payloads.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-transitive](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-transitive) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-transitive.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-transitive.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-overrides](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-overrides) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-overrides.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-overrides.svg)


## CVE-2025-66039
 FreePBX Endpoint Manager is a module for managing telephony endpoints in FreePBX systems. Versions are vulnerable to authentication bypass when the authentication type is set to "webserver." When providing an Authorization header with an arbitrary value, a session is associated with the target user regardless of valid credentials. This issue is fixed in versions 16.0.44 and 17.0.23.

- [https://github.com/jhow019/jhow019.github.io](https://github.com/jhow019/jhow019.github.io) :  ![starts](https://img.shields.io/github/stars/jhow019/jhow019.github.io.svg) ![forks](https://img.shields.io/github/forks/jhow019/jhow019.github.io.svg)
- [https://github.com/jhow019/FreePBX-Vulns-December-25](https://github.com/jhow019/FreePBX-Vulns-December-25) :  ![starts](https://img.shields.io/github/stars/jhow019/FreePBX-Vulns-December-25.svg) ![forks](https://img.shields.io/github/forks/jhow019/FreePBX-Vulns-December-25.svg)


## CVE-2025-61678
 FreePBX Endpoint Manager is a module for managing telephony endpoints in FreePBX systems. In versions prior to 16.0.92 for FreePBX 16 and versions prior to 17.0.6 for FreePBX 17, the Endpoint Manager module contains an authenticated arbitrary file upload vulnerability affecting the fwbrand parameter. The fwbrand parameter allows an attacker to change the file path. Combined, these issues can result in a webshell being uploaded. Authentication with a known username is required to exploit this vulnerability. Successful exploitation allows authenticated users to upload arbitrary files to attacker-controlled paths on the server, potentially leading to remote code execution. This issue has been patched in version 16.0.92 for FreePBX 16 and version 17.0.6 for FreePBX 17.

- [https://github.com/jhow019/jhow019.github.io](https://github.com/jhow019/jhow019.github.io) :  ![starts](https://img.shields.io/github/stars/jhow019/jhow019.github.io.svg) ![forks](https://img.shields.io/github/forks/jhow019/jhow019.github.io.svg)
- [https://github.com/jhow019/FreePBX-Vulns-December-25](https://github.com/jhow019/FreePBX-Vulns-December-25) :  ![starts](https://img.shields.io/github/stars/jhow019/FreePBX-Vulns-December-25.svg) ![forks](https://img.shields.io/github/forks/jhow019/FreePBX-Vulns-December-25.svg)


## CVE-2025-61675
 FreePBX Endpoint Manager is a module for managing telephony endpoints in FreePBX systems. In versions prior to 16.0.92 for FreePBX 16 and versions prior to 17.0.6 for FreePBX 17, the Endpoint Manager module contains authenticated SQL injection vulnerabilities affecting multiple parameters in the basestation, model, firmware, and custom extension configuration functionality areas. Authentication with a known username is required to exploit these vulnerabilities. Successful exploitation allows authenticated users to execute arbitrary SQL queries against the database, potentially enabling access to sensitive data or modification of database contents. This issue has been patched in version 16.0.92 for FreePBX 16 and version 17.0.6 for FreePBX 17.

- [https://github.com/jhow019/FreePBX-Vulns-December-25](https://github.com/jhow019/FreePBX-Vulns-December-25) :  ![starts](https://img.shields.io/github/stars/jhow019/FreePBX-Vulns-December-25.svg) ![forks](https://img.shields.io/github/forks/jhow019/FreePBX-Vulns-December-25.svg)
- [https://github.com/jhow019/jhow019.github.io](https://github.com/jhow019/jhow019.github.io) :  ![starts](https://img.shields.io/github/stars/jhow019/jhow019.github.io.svg) ![forks](https://img.shields.io/github/forks/jhow019/jhow019.github.io.svg)


## CVE-2025-55182
 A pre-authentication remote code execution vulnerability exists in React Server Components versions 19.0.0, 19.1.0, 19.1.1, and 19.2.0 including the following packages: react-server-dom-parcel, react-server-dom-turbopack, and react-server-dom-webpack. The vulnerable code unsafely deserializes payloads from HTTP requests to Server Function endpoints.

- [https://github.com/xkillbit/cve-2025-55182-scanner](https://github.com/xkillbit/cve-2025-55182-scanner) :  ![starts](https://img.shields.io/github/stars/xkillbit/cve-2025-55182-scanner.svg) ![forks](https://img.shields.io/github/forks/xkillbit/cve-2025-55182-scanner.svg)


## CVE-2025-54795
 Claude Code is an agentic coding tool. In versions below 1.0.20, an error in command parsing makes it possible to bypass the Claude Code confirmation prompt to trigger execution of an untrusted command. Reliably exploiting this requires the ability to add untrusted content into a Claude Code context window. This is fixed in version 1.0.20.

- [https://github.com/dial481/ralph](https://github.com/dial481/ralph) :  ![starts](https://img.shields.io/github/stars/dial481/ralph.svg) ![forks](https://img.shields.io/github/forks/dial481/ralph.svg)


## CVE-2025-38352
anyway in this case.

- [https://github.com/farazsth98/chronomaly](https://github.com/farazsth98/chronomaly) :  ![starts](https://img.shields.io/github/stars/farazsth98/chronomaly.svg) ![forks](https://img.shields.io/github/forks/farazsth98/chronomaly.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/sn1p3rt3s7/NextJS_CVE-2025-29927](https://github.com/sn1p3rt3s7/NextJS_CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/sn1p3rt3s7/NextJS_CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/sn1p3rt3s7/NextJS_CVE-2025-29927.svg)
- [https://github.com/enochgitgamefied/NextJS-CVE-2025-29927](https://github.com/enochgitgamefied/NextJS-CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/enochgitgamefied/NextJS-CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/enochgitgamefied/NextJS-CVE-2025-29927.svg)


## CVE-2025-9074
This can lead to execution of a wide range of privileged commands to the engine API, including controlling other containers, creating new ones, managing images etc. In some circumstances (e.g. Docker Desktop for Windows with WSL backend) it also allows mounting the host drive with the same privileges as the user running Docker Desktop.

- [https://github.com/KvzinNcpx7/CVE-2025-9074_DAEMON_KILLER](https://github.com/KvzinNcpx7/CVE-2025-9074_DAEMON_KILLER) :  ![starts](https://img.shields.io/github/stars/KvzinNcpx7/CVE-2025-9074_DAEMON_KILLER.svg) ![forks](https://img.shields.io/github/forks/KvzinNcpx7/CVE-2025-9074_DAEMON_KILLER.svg)
- [https://github.com/KvzinNcpx7/kvzinncpx7.github.io](https://github.com/KvzinNcpx7/kvzinncpx7.github.io) :  ![starts](https://img.shields.io/github/stars/KvzinNcpx7/kvzinncpx7.github.io.svg) ![forks](https://img.shields.io/github/forks/KvzinNcpx7/kvzinncpx7.github.io.svg)


## CVE-2025-6440
 The WooCommerce Designer Pro plugin for WordPress, used by the Pricom - Printing Company & Design Services WordPress theme, is vulnerable to arbitrary file uploads due to missing file type validation in the 'wcdp_save_canvas_design_ajax' function in all versions up to, and including, 1.9.26. This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible.

- [https://github.com/rimbadirgantara/CVE-2025-6440](https://github.com/rimbadirgantara/CVE-2025-6440) :  ![starts](https://img.shields.io/github/stars/rimbadirgantara/CVE-2025-6440.svg) ![forks](https://img.shields.io/github/forks/rimbadirgantara/CVE-2025-6440.svg)


## CVE-2025-1868
 Vulnerability of unauthorized exposure of confidential information affecting Advanced IP Scanner and Advanced Port Scanner. It occurs when these applications initiate a network scan, inadvertently sending the NTLM hash of the user performing the scan. This vulnerability can be exploited by intercepting network traffic to a legitimate server or by setting up a fake server, in both local and remote scenarios. This exposure is relevant for both HTTP/HTTPS and SMB protocols.

- [https://github.com/itres-labs/CVE-2025-1868](https://github.com/itres-labs/CVE-2025-1868) :  ![starts](https://img.shields.io/github/stars/itres-labs/CVE-2025-1868.svg) ![forks](https://img.shields.io/github/forks/itres-labs/CVE-2025-1868.svg)


## CVE-2025-0184
 A Server-Side Request Forgery (SSRF) vulnerability was identified in langgenius/dify version 0.10.2. The vulnerability occurs in the 'Create Knowledge' section when uploading DOCX files. If an external relationship exists in the DOCX file, the reltype value is requested as a URL using the 'requests' module instead of the 'ssrf_proxy', leading to an SSRF vulnerability. This issue was fixed in version 0.11.0.

- [https://github.com/m0d0ri205/wargame_Re-LS](https://github.com/m0d0ri205/wargame_Re-LS) :  ![starts](https://img.shields.io/github/stars/m0d0ri205/wargame_Re-LS.svg) ![forks](https://img.shields.io/github/forks/m0d0ri205/wargame_Re-LS.svg)


## CVE-2024-40110
 Sourcecodester Poultry Farm Management System v1.0 contains an Unauthenticated Remote Code Execution (RCE) vulnerability via the productimage parameter at /farm/product.php.

- [https://github.com/AnGrY-Althaf/CVE-2024-40110](https://github.com/AnGrY-Althaf/CVE-2024-40110) :  ![starts](https://img.shields.io/github/stars/AnGrY-Althaf/CVE-2024-40110.svg) ![forks](https://img.shields.io/github/forks/AnGrY-Althaf/CVE-2024-40110.svg)


## CVE-2021-30809
 A use after free issue was addressed with improved memory management. This issue is fixed in Safari 15, tvOS 15, watchOS 8, iOS 15 and iPadOS 15. Processing maliciously crafted web content may lead to arbitrary code execution.

- [https://github.com/seregonwar/CVE-2021-30809-OOM](https://github.com/seregonwar/CVE-2021-30809-OOM) :  ![starts](https://img.shields.io/github/stars/seregonwar/CVE-2021-30809-OOM.svg) ![forks](https://img.shields.io/github/forks/seregonwar/CVE-2021-30809-OOM.svg)


## CVE-2019-9168
 WooCommerce before 3.5.5 allows XSS via a Photoswipe caption.

- [https://github.com/floudeciel/WooCommerce-CVEs](https://github.com/floudeciel/WooCommerce-CVEs) :  ![starts](https://img.shields.io/github/stars/floudeciel/WooCommerce-CVEs.svg) ![forks](https://img.shields.io/github/forks/floudeciel/WooCommerce-CVEs.svg)


## CVE-2018-20148
 In WordPress before 4.9.9 and 5.x before 5.0.1, contributors could conduct PHP object injection attacks via crafted metadata in a wp.getMediaItem XMLRPC call. This is caused by mishandling of serialized data at phar:// URLs in the wp_get_attachment_thumb_file function in wp-includes/post.php.

- [https://github.com/floudeciel/WooCommerce-CVEs](https://github.com/floudeciel/WooCommerce-CVEs) :  ![starts](https://img.shields.io/github/stars/floudeciel/WooCommerce-CVEs.svg) ![forks](https://img.shields.io/github/forks/floudeciel/WooCommerce-CVEs.svg)


## CVE-2017-5638
 The Jakarta Multipart parser in Apache Struts 2 2.3.x before 2.3.32 and 2.5.x before 2.5.10.1 has incorrect exception handling and error-message generation during file-upload attempts, which allows remote attackers to execute arbitrary commands via a crafted Content-Type, Content-Disposition, or Content-Length HTTP header, as exploited in the wild in March 2017 with a Content-Type header containing a #cmd= string.

- [https://github.com/louislafosse/CVE-2017-5638-assignement](https://github.com/louislafosse/CVE-2017-5638-assignement) :  ![starts](https://img.shields.io/github/stars/louislafosse/CVE-2017-5638-assignement.svg) ![forks](https://img.shields.io/github/forks/louislafosse/CVE-2017-5638-assignement.svg)


## CVE-2007-2447
 The MS-RPC functionality in smbd in Samba 3.0.0 through 3.0.25rc3 allows remote attackers to execute arbitrary commands via shell metacharacters involving the (1) SamrChangePassword function, when the "username map script" smb.conf option is enabled, and allows remote authenticated users to execute commands via shell metacharacters involving other MS-RPC functions in the (2) remote printer and (3) file share management.

- [https://github.com/abdulsaabir/CVE-2007-2447](https://github.com/abdulsaabir/CVE-2007-2447) :  ![starts](https://img.shields.io/github/stars/abdulsaabir/CVE-2007-2447.svg) ![forks](https://img.shields.io/github/forks/abdulsaabir/CVE-2007-2447.svg)

