# Update 2026-02-06
## CVE-2026-25546
 Godot MCP is a Model Context Protocol (MCP) server for interacting with the Godot game engine. Prior to version 0.1.1, a command injection vulnerability in godot-mcp allows remote code execution. The executeOperation function passed user-controlled input (e.g., projectPath) directly to exec(), which spawns a shell. An attacker could inject shell metacharacters like $(command) or &calc to execute arbitrary commands with the privileges of the MCP server process. This affects any tool that accepts projectPath, including create_scene, add_node, load_sprite, and others. This issue has been patched in version 0.1.1.

- [https://github.com/mbanyamer/CVE-2026-25546-godot-mcp-0.1.1-OS-Command-Injection](https://github.com/mbanyamer/CVE-2026-25546-godot-mcp-0.1.1-OS-Command-Injection) :  ![starts](https://img.shields.io/github/stars/mbanyamer/CVE-2026-25546-godot-mcp-0.1.1-OS-Command-Injection.svg) ![forks](https://img.shields.io/github/forks/mbanyamer/CVE-2026-25546-godot-mcp-0.1.1-OS-Command-Injection.svg)


## CVE-2026-25512
 Group-Office is an enterprise customer relationship management and groupware tool. Prior to versions 6.8.150, 25.0.82, and 26.0.5, there is a remote code execution (RCE) vulnerability in Group-Office. The endpoint email/message/tnefAttachmentFromTempFile directly concatenates the user-controlled parameter tmp_file into an exec() call. By injecting shell metacharacters into tmp_file, an authenticated attacker can execute arbitrary system commands on the server. This issue has been patched in versions 6.8.150, 25.0.82, and 26.0.5.

- [https://github.com/NumberOreo1/CVE-2026-25512](https://github.com/NumberOreo1/CVE-2026-25512) :  ![starts](https://img.shields.io/github/stars/NumberOreo1/CVE-2026-25512.svg) ![forks](https://img.shields.io/github/forks/NumberOreo1/CVE-2026-25512.svg)
- [https://github.com/mbanyamer/CVE-2026-25512-PoC-Group-Office-Authenticated-RCE](https://github.com/mbanyamer/CVE-2026-25512-PoC-Group-Office-Authenticated-RCE) :  ![starts](https://img.shields.io/github/stars/mbanyamer/CVE-2026-25512-PoC-Group-Office-Authenticated-RCE.svg) ![forks](https://img.shields.io/github/forks/mbanyamer/CVE-2026-25512-PoC-Group-Office-Authenticated-RCE.svg)


## CVE-2026-24061
 telnetd in GNU Inetutils through 2.7 allows remote authentication bypass via a "-f root" value for the USER environment variable.

- [https://github.com/lavabyte/telnet-CVE-2026-24061](https://github.com/lavabyte/telnet-CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/lavabyte/telnet-CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/lavabyte/telnet-CVE-2026-24061.svg)
- [https://github.com/canpilayda/inetutils-telnetd-cve-2026-24061](https://github.com/canpilayda/inetutils-telnetd-cve-2026-24061) :  ![starts](https://img.shields.io/github/stars/canpilayda/inetutils-telnetd-cve-2026-24061.svg) ![forks](https://img.shields.io/github/forks/canpilayda/inetutils-telnetd-cve-2026-24061.svg)


## CVE-2026-21509
 Reliance on untrusted inputs in a security decision in Microsoft Office allows an unauthorized attacker to bypass a security feature locally.

- [https://github.com/decalage2/detect_CVE-2026-21509](https://github.com/decalage2/detect_CVE-2026-21509) :  ![starts](https://img.shields.io/github/stars/decalage2/detect_CVE-2026-21509.svg) ![forks](https://img.shields.io/github/forks/decalage2/detect_CVE-2026-21509.svg)


## CVE-2025-70545
 A stored cross-site scripting (XSS) vulnerability exists in the web management interface of the PPC (Belden) ONT 2K05X router running firmware v1.1.9_206L. The Common Gateway Interface (CGI) component improperly handles user-supplied input, allowing a remote, unauthenticated attacker to inject arbitrary JavaScript that is persistently stored and executed when the affected interface is accessed.

- [https://github.com/jeyabalaji711/CVE-2025-70545](https://github.com/jeyabalaji711/CVE-2025-70545) :  ![starts](https://img.shields.io/github/stars/jeyabalaji711/CVE-2025-70545.svg) ![forks](https://img.shields.io/github/forks/jeyabalaji711/CVE-2025-70545.svg)


## CVE-2025-68493
Users are recommended to upgrade to version 6.1.1, which fixes the issue.

- [https://github.com/hsltz/CVE-2025-68493](https://github.com/hsltz/CVE-2025-68493) :  ![starts](https://img.shields.io/github/stars/hsltz/CVE-2025-68493.svg) ![forks](https://img.shields.io/github/forks/hsltz/CVE-2025-68493.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-berry](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-berry) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-berry.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-berry.svg)


## CVE-2025-60690
 A stack-based buffer overflow exists in the get_merge_ipaddr function of the httpd binary on Linksys E1200 v2 routers (Firmware E1200_v2.0.11.001_us.tar.gz). The function concatenates up to four user-supplied CGI parameters matching parameter_0~3 into a fixed-size buffer (a2) without bounds checking. Remote attackers can exploit this vulnerability via specially crafted HTTP requests to execute arbitrary code or cause denial of service without authentication.

- [https://github.com/Jarrettgohxz/CVE-research](https://github.com/Jarrettgohxz/CVE-research) :  ![starts](https://img.shields.io/github/stars/Jarrettgohxz/CVE-research.svg) ![forks](https://img.shields.io/github/forks/Jarrettgohxz/CVE-research.svg)


## CVE-2025-55182
 A pre-authentication remote code execution vulnerability exists in React Server Components versions 19.0.0, 19.1.0, 19.1.1, and 19.2.0 including the following packages: react-server-dom-parcel, react-server-dom-turbopack, and react-server-dom-webpack. The vulnerable code unsafely deserializes payloads from HTTP requests to Server Function endpoints.

- [https://github.com/Syrins/CVE-2025-55182-React2Shell-RCE](https://github.com/Syrins/CVE-2025-55182-React2Shell-RCE) :  ![starts](https://img.shields.io/github/stars/Syrins/CVE-2025-55182-React2Shell-RCE.svg) ![forks](https://img.shields.io/github/forks/Syrins/CVE-2025-55182-React2Shell-RCE.svg)


## CVE-2025-49113
 Roundcube Webmail before 1.5.10 and 1.6.x before 1.6.11 allows remote code execution by authenticated users because the _from parameter in a URL is not validated in program/actions/settings/upload.php, leading to PHP Object Deserialization.

- [https://github.com/Evillm/CVE-2025-49113-PoC](https://github.com/Evillm/CVE-2025-49113-PoC) :  ![starts](https://img.shields.io/github/stars/Evillm/CVE-2025-49113-PoC.svg) ![forks](https://img.shields.io/github/forks/Evillm/CVE-2025-49113-PoC.svg)


## CVE-2025-47445
 Relative Path Traversal vulnerability in Themewinter Eventin allows Path Traversal.This issue affects Eventin: from n/a through 4.0.26.

- [https://github.com/inverterad/CVE-2025-47445-PoC](https://github.com/inverterad/CVE-2025-47445-PoC) :  ![starts](https://img.shields.io/github/stars/inverterad/CVE-2025-47445-PoC.svg) ![forks](https://img.shields.io/github/forks/inverterad/CVE-2025-47445-PoC.svg)


## CVE-2025-40778
This issue affects BIND 9 versions 9.11.0 through 9.16.50, 9.18.0 through 9.18.39, 9.20.0 through 9.20.13, 9.21.0 through 9.21.12, 9.11.3-S1 through 9.16.50-S1, 9.18.11-S1 through 9.18.39-S1, and 9.20.9-S1 through 9.20.13-S1.

- [https://github.com/nicholasC03/DNS-Poisoning-Triage-Lab](https://github.com/nicholasC03/DNS-Poisoning-Triage-Lab) :  ![starts](https://img.shields.io/github/stars/nicholasC03/DNS-Poisoning-Triage-Lab.svg) ![forks](https://img.shields.io/github/forks/nicholasC03/DNS-Poisoning-Triage-Lab.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/Si-Ni/CVE-2025-29927-Proof-of-Concept](https://github.com/Si-Ni/CVE-2025-29927-Proof-of-Concept) :  ![starts](https://img.shields.io/github/stars/Si-Ni/CVE-2025-29927-Proof-of-Concept.svg) ![forks](https://img.shields.io/github/forks/Si-Ni/CVE-2025-29927-Proof-of-Concept.svg)


## CVE-2025-27520
 BentoML is a Python library for building online serving systems optimized for AI apps and model inference. A Remote Code Execution (RCE) vulnerability caused by insecure deserialization has been identified in the latest version (v1.4.2) of BentoML. It allows any unauthenticated user to execute arbitrary code on the server. It exists an unsafe code segment in serde.py. This vulnerability is fixed in 1.4.3.

- [https://github.com/Evillm/CVE-2025-27520-PoC](https://github.com/Evillm/CVE-2025-27520-PoC) :  ![starts](https://img.shields.io/github/stars/Evillm/CVE-2025-27520-PoC.svg) ![forks](https://img.shields.io/github/forks/Evillm/CVE-2025-27520-PoC.svg)


## CVE-2025-8088
     from ESET.

- [https://github.com/Syrins/CVE-2025-8088-Winrar-Tool-Gui](https://github.com/Syrins/CVE-2025-8088-Winrar-Tool-Gui) :  ![starts](https://img.shields.io/github/stars/Syrins/CVE-2025-8088-Winrar-Tool-Gui.svg) ![forks](https://img.shields.io/github/forks/Syrins/CVE-2025-8088-Winrar-Tool-Gui.svg)


## CVE-2025-6990
 The kallyas theme for WordPress is vulnerable to Remote Code Execution in all versions up to, and including, 4.24.0 via the  `TH_PhpCode` pagebuilder widget. This is due to the theme not restricting access to the code editor widget for non-administrators. This makes it possible for authenticated attackers, with Contributor-level access and above, to execute code on the server.

- [https://github.com/cypherdavy/CVE-2025-69906-Monstra-CMS-3.0.4-Arbitrary-File-Upload-to-RCE](https://github.com/cypherdavy/CVE-2025-69906-Monstra-CMS-3.0.4-Arbitrary-File-Upload-to-RCE) :  ![starts](https://img.shields.io/github/stars/cypherdavy/CVE-2025-69906-Monstra-CMS-3.0.4-Arbitrary-File-Upload-to-RCE.svg) ![forks](https://img.shields.io/github/forks/cypherdavy/CVE-2025-69906-Monstra-CMS-3.0.4-Arbitrary-File-Upload-to-RCE.svg)


## CVE-2025-5329
NOTE: The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/sahici/CVE-2025-5329](https://github.com/sahici/CVE-2025-5329) :  ![starts](https://img.shields.io/github/stars/sahici/CVE-2025-5329.svg) ![forks](https://img.shields.io/github/forks/sahici/CVE-2025-5329.svg)


## CVE-2025-2304
When a user wishes to change his password, the 'updated_ajax' method of the UsersController is called. The vulnerability stems from the use of the dangerous permit! method, which allows all parameters to pass through without any filtering.

- [https://github.com/Alien0ne/CVE-2025-2304](https://github.com/Alien0ne/CVE-2025-2304) :  ![starts](https://img.shields.io/github/stars/Alien0ne/CVE-2025-2304.svg) ![forks](https://img.shields.io/github/forks/Alien0ne/CVE-2025-2304.svg)
- [https://github.com/PwnManjaro/CVE-2025-2304](https://github.com/PwnManjaro/CVE-2025-2304) :  ![starts](https://img.shields.io/github/stars/PwnManjaro/CVE-2025-2304.svg) ![forks](https://img.shields.io/github/forks/PwnManjaro/CVE-2025-2304.svg)


## CVE-2024-46987
 Camaleon CMS is a dynamic and advanced content management system based on Ruby on Rails. A path traversal vulnerability accessible via MediaController's download_private_file method allows authenticated users to download any file on the web server Camaleon CMS is running on (depending on the file permissions). This issue may lead to Information Disclosure. This issue has been addressed in release version 2.8.2. Users are advised to upgrade. There are no known workarounds for this vulnerability.

- [https://github.com/sparrowhawk1113/Exploit-for-CVE-2024-46987](https://github.com/sparrowhawk1113/Exploit-for-CVE-2024-46987) :  ![starts](https://img.shields.io/github/stars/sparrowhawk1113/Exploit-for-CVE-2024-46987.svg) ![forks](https://img.shields.io/github/forks/sparrowhawk1113/Exploit-for-CVE-2024-46987.svg)


## CVE-2024-45590
 body-parser is Node.js body parsing middleware. body-parser 1.20.3 is vulnerable to denial of service when url encoding is enabled. A malicious actor using a specially crafted payload could flood the server with a large number of requests, resulting in denial of service. This issue is patched in 1.20.3.

- [https://github.com/Evillm/CVE-2024-45590-PoC](https://github.com/Evillm/CVE-2024-45590-PoC) :  ![starts](https://img.shields.io/github/stars/Evillm/CVE-2024-45590-PoC.svg) ![forks](https://img.shields.io/github/forks/Evillm/CVE-2024-45590-PoC.svg)


## CVE-2024-8856
 The Backup and Staging by WP Time Capsule plugin for WordPress is vulnerable to arbitrary file uploads due to missing file type validation in the the UploadHandler.php file and no direct file access prevention in all versions up to, and including, 1.22.21. This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible.

- [https://github.com/Evillm/CVE-2024-8856-PoC](https://github.com/Evillm/CVE-2024-8856-PoC) :  ![starts](https://img.shields.io/github/stars/Evillm/CVE-2024-8856-PoC.svg) ![forks](https://img.shields.io/github/forks/Evillm/CVE-2024-8856-PoC.svg)


## CVE-2023-33107
 Memory corruption in Graphics Linux while assigning shared virtual memory region during IOCTL call.

- [https://github.com/keto0422/CVE-2023-33107](https://github.com/keto0422/CVE-2023-33107) :  ![starts](https://img.shields.io/github/stars/keto0422/CVE-2023-33107.svg) ![forks](https://img.shields.io/github/forks/keto0422/CVE-2023-33107.svg)


## CVE-2023-4634
 The Media Library Assistant plugin for WordPress is vulnerable to Local File Inclusion and Remote Code Execution in versions up to, and including, 3.09. This is due to insufficient controls on file paths being supplied to the 'mla_stream_file' parameter from the ~/includes/mla-stream-image.php file, where images are processed via Imagick(). This makes it possible for unauthenticated attackers to supply files via FTP that will make directory lists, local file inclusion, and remote code execution possible.

- [https://github.com/Evillm/CVE-2023-4634-PoC](https://github.com/Evillm/CVE-2023-4634-PoC) :  ![starts](https://img.shields.io/github/stars/Evillm/CVE-2023-4634-PoC.svg) ![forks](https://img.shields.io/github/forks/Evillm/CVE-2023-4634-PoC.svg)


## CVE-2022-25584
 Seyeon Tech Co., Ltd FlexWATCH FW3170-PS-E Network Video System 4.23-3000_GY allows attackers to access sensitive information.

- [https://github.com/yichenC1c/CVE-2022-25584](https://github.com/yichenC1c/CVE-2022-25584) :  ![starts](https://img.shields.io/github/stars/yichenC1c/CVE-2022-25584.svg) ![forks](https://img.shields.io/github/forks/yichenC1c/CVE-2022-25584.svg)

