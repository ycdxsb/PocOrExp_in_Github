# Update 2026-08-11
## CVE-2026-69084
 SiYuan versions = v3.7.2 expose the /api/search/searchEmbedBlock endpoint, which passes a client-supplied SQL statement verbatim to the main read-write siyuan.db handle with no single-statement, read-only, or admin restrictions. The endpoint is gated only by CheckAuth, making it reachable by the publish RoleReader token and by anonymous users when publish authentication is disabled. Because the underlying driver executes stacked statements, an attacker can read and modify content across all opened cleartext notebooks (encrypted per-box notebooks are excluded). Fixed in v3.7.3.

- [https://github.com/Boreas37/CVE-2026-69084-PoC](https://github.com/Boreas37/CVE-2026-69084-PoC) :  ![starts](https://img.shields.io/github/stars/Boreas37/CVE-2026-69084-PoC.svg) ![forks](https://img.shields.io/github/forks/Boreas37/CVE-2026-69084-PoC.svg)


## CVE-2026-64638
Discovered and responsibly disclosed by [the team at pwn.ai](https://pwn.ai/).

- [https://github.com/Boreas37/CVE-2026-64638-PoC-XSS2Shell-](https://github.com/Boreas37/CVE-2026-64638-PoC-XSS2Shell-) :  ![starts](https://img.shields.io/github/stars/Boreas37/CVE-2026-64638-PoC-XSS2Shell-.svg) ![forks](https://img.shields.io/github/forks/Boreas37/CVE-2026-64638-PoC-XSS2Shell-.svg)
- [https://github.com/0xlipon/xss2shell](https://github.com/0xlipon/xss2shell) :  ![starts](https://img.shields.io/github/stars/0xlipon/xss2shell.svg) ![forks](https://img.shields.io/github/forks/0xlipon/xss2shell.svg)
- [https://github.com/eh-amish/CVE-2026-64638-XSS-to-Shell-PoC](https://github.com/eh-amish/CVE-2026-64638-XSS-to-Shell-PoC) :  ![starts](https://img.shields.io/github/stars/eh-amish/CVE-2026-64638-XSS-to-Shell-PoC.svg) ![forks](https://img.shields.io/github/forks/eh-amish/CVE-2026-64638-XSS-to-Shell-PoC.svg)


## CVE-2026-57827
 Joomla Extension - rsjoomla.com - Unauthenticated file upload in RSFiles component  1.17.12 - The Joomla extension RSFiles is vulnerable to an unauthenticated arbitrary file upload that allows uploading executable files and leads to full RCE.

- [https://github.com/Ahmall-sec/CVE_2026_57827](https://github.com/Ahmall-sec/CVE_2026_57827) :  ![starts](https://img.shields.io/github/stars/Ahmall-sec/CVE_2026_57827.svg) ![forks](https://img.shields.io/github/forks/Ahmall-sec/CVE_2026_57827.svg)


## CVE-2026-53787
 Amasty Order Attributes for Magento 2 before version 4.0.0 contains an unauthenticated arbitrary file upload vulnerability that allows unauthenticated attackers to write arbitrary files to the store's media directory by submitting files of any type or name to the upload endpoint without authentication, session validation, or cart context. Attackers can upload PHP files to achieve remote code execution on servers where the media directory permits PHP execution, or alternatively enable malware hosting, stored cross-site scripting via HTML or SVG uploads, and path traversal to write files outside the intended upload directory.

- [https://github.com/ChrisSEC2014/amasty-chekout-POC-rce](https://github.com/ChrisSEC2014/amasty-chekout-POC-rce) :  ![starts](https://img.shields.io/github/stars/ChrisSEC2014/amasty-chekout-POC-rce.svg) ![forks](https://img.shields.io/github/forks/ChrisSEC2014/amasty-chekout-POC-rce.svg)


## CVE-2026-43499
  	changelog ]

- [https://github.com/ruik-tech/Root-My-Galaxy](https://github.com/ruik-tech/Root-My-Galaxy) :  ![starts](https://img.shields.io/github/stars/ruik-tech/Root-My-Galaxy.svg) ![forks](https://img.shields.io/github/forks/ruik-tech/Root-My-Galaxy.svg)
- [https://github.com/OhLookItsTheIRS/Root-My-Galaxy-tests](https://github.com/OhLookItsTheIRS/Root-My-Galaxy-tests) :  ![starts](https://img.shields.io/github/stars/OhLookItsTheIRS/Root-My-Galaxy-tests.svg) ![forks](https://img.shields.io/github/forks/OhLookItsTheIRS/Root-My-Galaxy-tests.svg)


## CVE-2026-41091
 Improper link resolution before file access ('link following') in Microsoft Defender allows an authorized attacker to elevate privileges locally.

- [https://github.com/s4m98/RedSun-](https://github.com/s4m98/RedSun-) :  ![starts](https://img.shields.io/github/stars/s4m98/RedSun-.svg) ![forks](https://img.shields.io/github/forks/s4m98/RedSun-.svg)


## CVE-2026-39987
 marimo is a reactive Python notebook. Prior to 0.23.0, Marimo has a Pre-Auth RCE vulnerability. The terminal WebSocket endpoint /terminal/ws lacks authentication validation, allowing an unauthenticated attacker to obtain a full PTY shell and execute arbitrary system commands. Unlike other WebSocket endpoints (e.g., /ws) that correctly call validate_auth() for authentication, the /terminal/ws endpoint only checks the running mode and platform support before accepting connections, completely skipping authentication verification. This vulnerability is fixed in 0.23.0.

- [https://github.com/MADA0L/CVE-2026-39987-Poc](https://github.com/MADA0L/CVE-2026-39987-Poc) :  ![starts](https://img.shields.io/github/stars/MADA0L/CVE-2026-39987-Poc.svg) ![forks](https://img.shields.io/github/forks/MADA0L/CVE-2026-39987-Poc.svg)


## CVE-2026-34910
 A malicious actor with access to the network could exploit an Improper Input Validation vulnerability found in UniFi OS devices to execute a Command Injection.

- [https://github.com/Boreas37/CVE-2026-34910-PoC](https://github.com/Boreas37/CVE-2026-34910-PoC) :  ![starts](https://img.shields.io/github/stars/Boreas37/CVE-2026-34910-PoC.svg) ![forks](https://img.shields.io/github/forks/Boreas37/CVE-2026-34910-PoC.svg)


## CVE-2026-26119
 Improper authentication in Windows Admin Center allows an authorized attacker to elevate privileges over a network.

- [https://github.com/Cyb3rWitch3r/CVE-2026-26119](https://github.com/Cyb3rWitch3r/CVE-2026-26119) :  ![starts](https://img.shields.io/github/stars/Cyb3rWitch3r/CVE-2026-26119.svg) ![forks](https://img.shields.io/github/forks/Cyb3rWitch3r/CVE-2026-26119.svg)
- [https://github.com/r3vpwnx/CVE-2026-26119](https://github.com/r3vpwnx/CVE-2026-26119) :  ![starts](https://img.shields.io/github/stars/r3vpwnx/CVE-2026-26119.svg) ![forks](https://img.shields.io/github/forks/r3vpwnx/CVE-2026-26119.svg)


## CVE-2026-25857
 Tenda G300-F router firmware version 16.01.14.2 and prior contain an OS command injection vulnerability in the WAN diagnostic functionality (formSetWanDiag). The implementation constructs a shell command that invokes curl and incorporates attacker-controlled input into the command line without adequate neutralization. As a result, a remote attacker with access to the affected management interface can inject additional shell syntax and execute arbitrary commands on the device with the privileges of the management process.

- [https://github.com/eeeeeeeeeevan/CVE-2026-25857](https://github.com/eeeeeeeeeevan/CVE-2026-25857) :  ![starts](https://img.shields.io/github/stars/eeeeeeeeeevan/CVE-2026-25857.svg) ![forks](https://img.shields.io/github/forks/eeeeeeeeeevan/CVE-2026-25857.svg)


## CVE-2026-22747
This issue affects Spring Security: from 7.0.0 through 7.0.4.

- [https://github.com/gsadagopan/cve-2026-22747-sandbox](https://github.com/gsadagopan/cve-2026-22747-sandbox) :  ![starts](https://img.shields.io/github/stars/gsadagopan/cve-2026-22747-sandbox.svg) ![forks](https://img.shields.io/github/forks/gsadagopan/cve-2026-22747-sandbox.svg)


## CVE-2026-15038
 The InfiniteWP Client WordPress plugin before 1.13.6 does not properly verify the site-connection state and the authenticity of requests to its remote-management endpoint on WordPress Multisite installations, allowing unauthenticated attackers to bind their own key, hijack an administrator session, and take over the entire network, leading to remote code execution.

- [https://github.com/Polosss/By-Poloss..-..CVE-2026-15038-POC](https://github.com/Polosss/By-Poloss..-..CVE-2026-15038-POC) :  ![starts](https://img.shields.io/github/stars/Polosss/By-Poloss..-..CVE-2026-15038-POC.svg) ![forks](https://img.shields.io/github/forks/Polosss/By-Poloss..-..CVE-2026-15038-POC.svg)


## CVE-2026-9645
 Exposed methods allow authenticated users to create and execute arbitrary JavaScript code on the server. The scripts execute with full access, enabling complete system compromise as commands are executed as root.

- [https://github.com/0xmhany/CVE-2026-9645-ScadaBR-Analysis](https://github.com/0xmhany/CVE-2026-9645-ScadaBR-Analysis) :  ![starts](https://img.shields.io/github/stars/0xmhany/CVE-2026-9645-ScadaBR-Analysis.svg) ![forks](https://img.shields.io/github/forks/0xmhany/CVE-2026-9645-ScadaBR-Analysis.svg)


## CVE-2026-4282
 A flaw was found in Keycloak. The SingleUseObjectProvider, a global key-value store, lacks proper type and namespace isolation. This vulnerability allows an unauthenticated attacker to forge authorization codes. Successful exploitation can lead to the creation of admin-capable access tokens, resulting in privilege escalation.

- [https://github.com/hexissam/CVE-2026-4282-Scanner](https://github.com/hexissam/CVE-2026-4282-Scanner) :  ![starts](https://img.shields.io/github/stars/hexissam/CVE-2026-4282-Scanner.svg) ![forks](https://img.shields.io/github/forks/hexissam/CVE-2026-4282-Scanner.svg)


## CVE-2026-3494
 In MariaDB server version through 11.8.5, when server audit plugin is enabled with server_audit_events variable configured with QUERY_DCL, QUERY_DDL, or QUERY_DML filtering, if an authenticated database user invokes a SQL statement prefixed with double-hyphen (—) or hash (#) style comments, the statement is not logged.

- [https://github.com/Kelnor/CVE-2026-3494_Verfication](https://github.com/Kelnor/CVE-2026-3494_Verfication) :  ![starts](https://img.shields.io/github/stars/Kelnor/CVE-2026-3494_Verfication.svg) ![forks](https://img.shields.io/github/forks/Kelnor/CVE-2026-3494_Verfication.svg)


## CVE-2025-59528
 Flowise is a drag & drop user interface to build a customized large language model flow. In version 3.0.5, Flowise is vulnerable to remote code execution. The CustomMCP node allows users to input configuration settings for connecting to an external MCP server. This node parses the user-provided mcpServerConfig string to build the MCP server configuration. However, during this process, it executes JavaScript code without any security validation. Specifically, inside the convertToValidJSONString function, user input is directly passed to the Function() constructor, which evaluates and executes the input as JavaScript code. Since this runs with full Node.js runtime privileges, it can access dangerous modules such as child_process and fs. This issue has been patched in version 3.0.6.

- [https://github.com/sonnelon/CVE-2025-59528-PoC](https://github.com/sonnelon/CVE-2025-59528-PoC) :  ![starts](https://img.shields.io/github/stars/sonnelon/CVE-2025-59528-PoC.svg) ![forks](https://img.shields.io/github/forks/sonnelon/CVE-2025-59528-PoC.svg)
- [https://github.com/Loaxert/CVE-2025-59528-PoC](https://github.com/Loaxert/CVE-2025-59528-PoC) :  ![starts](https://img.shields.io/github/stars/Loaxert/CVE-2025-59528-PoC.svg) ![forks](https://img.shields.io/github/forks/Loaxert/CVE-2025-59528-PoC.svg)


## CVE-2025-55182
 A pre-authentication remote code execution vulnerability exists in React Server Components versions 19.0.0, 19.1.0, 19.1.1, and 19.2.0 including the following packages: react-server-dom-parcel, react-server-dom-turbopack, and react-server-dom-webpack. The vulnerable code unsafely deserializes payloads from HTTP requests to Server Function endpoints.

- [https://github.com/Chocapikk/CVE-2025-55182](https://github.com/Chocapikk/CVE-2025-55182) :  ![starts](https://img.shields.io/github/stars/Chocapikk/CVE-2025-55182.svg) ![forks](https://img.shields.io/github/forks/Chocapikk/CVE-2025-55182.svg)
- [https://github.com/Chocapikk/malware_analysis_react2shell](https://github.com/Chocapikk/malware_analysis_react2shell) :  ![starts](https://img.shields.io/github/stars/Chocapikk/malware_analysis_react2shell.svg) ![forks](https://img.shields.io/github/forks/Chocapikk/malware_analysis_react2shell.svg)


## CVE-2025-34152
 An unauthenticated OS command injection vulnerability exists in the Shenzhen Aitemi M300 Wi-Fi Repeater (hardware model MT02) via the 'time' parameter of the '/protocol.csp?' endpoint. The input is processed by the internal date '-s' command without rebooting or disrupting HTTP service. Unlike other injection points, this vector allows remote compromise without triggering visible configuration changes.

- [https://github.com/Chocapikk/CVE-2025-34152](https://github.com/Chocapikk/CVE-2025-34152) :  ![starts](https://img.shields.io/github/stars/Chocapikk/CVE-2025-34152.svg) ![forks](https://img.shields.io/github/forks/Chocapikk/CVE-2025-34152.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/Heimd411/CVE-2025-29927-PoC](https://github.com/Heimd411/CVE-2025-29927-PoC) :  ![starts](https://img.shields.io/github/stars/Heimd411/CVE-2025-29927-PoC.svg) ![forks](https://img.shields.io/github/forks/Heimd411/CVE-2025-29927-PoC.svg)


## CVE-2025-7029
 A vulnerability in the Software SMI handler (SwSmiInputValue 0xB2) allows a local attacker to control the RBX register, which is used to derive pointers (OcHeader, OcData) passed into power and thermal configuration logic. These buffers are not validated before performing multiple structured memory writes based on OcSetup NVRAM values, enabling arbitrary SMRAM corruption and potential SMM privilege escalation.

- [https://github.com/Tobss8/GIGABYTE-H510M-K-V2-BIOS-SMM-Reverse-Engineering-CVE-2025-7026-7027-7028-7029-Research](https://github.com/Tobss8/GIGABYTE-H510M-K-V2-BIOS-SMM-Reverse-Engineering-CVE-2025-7026-7027-7028-7029-Research) :  ![starts](https://img.shields.io/github/stars/Tobss8/GIGABYTE-H510M-K-V2-BIOS-SMM-Reverse-Engineering-CVE-2025-7026-7027-7028-7029-Research.svg) ![forks](https://img.shields.io/github/forks/Tobss8/GIGABYTE-H510M-K-V2-BIOS-SMM-Reverse-Engineering-CVE-2025-7026-7027-7028-7029-Research.svg)


## CVE-2025-7028
 A vulnerability in the Software SMI handler (SwSmiInputValue 0x20) allows a local attacker to supply a crafted pointer (FuncBlock) through RBX and RCX register values. This pointer is passed unchecked into multiple flash management functions (ReadFlash, WriteFlash, EraseFlash, and GetFlashInfo) that dereference both the structure and its nested members, such as BufAddr. This enables arbitrary read/write access to System Management RAM (SMRAM), allowing an attacker to corrupt firmware memory, exfiltrate SMRAM content via flash, or install persistent implants.

- [https://github.com/Tobss8/GIGABYTE-H510M-K-V2-BIOS-SMM-Reverse-Engineering-CVE-2025-7026-7027-7028-7029-Research](https://github.com/Tobss8/GIGABYTE-H510M-K-V2-BIOS-SMM-Reverse-Engineering-CVE-2025-7026-7027-7028-7029-Research) :  ![starts](https://img.shields.io/github/stars/Tobss8/GIGABYTE-H510M-K-V2-BIOS-SMM-Reverse-Engineering-CVE-2025-7026-7027-7028-7029-Research.svg) ![forks](https://img.shields.io/github/forks/Tobss8/GIGABYTE-H510M-K-V2-BIOS-SMM-Reverse-Engineering-CVE-2025-7026-7027-7028-7029-Research.svg)


## CVE-2025-7027
 A vulnerability in the Software SMI handler (SwSmiInputValue 0xB2) allows a local attacker to control both the read and write addresses used by the CommandRcx1 function. The write target is derived from an unvalidated UEFI NVRAM variable (SetupXtuBufferAddress), while the write content is read from an attacker-controlled pointer based on the RBX register. This dual-pointer dereference enables arbitrary memory writes within System Management RAM (SMRAM), leading to potential SMM privilege escalation and firmware compromise.

- [https://github.com/Tobss8/GIGABYTE-H510M-K-V2-BIOS-SMM-Reverse-Engineering-CVE-2025-7026-7027-7028-7029-Research](https://github.com/Tobss8/GIGABYTE-H510M-K-V2-BIOS-SMM-Reverse-Engineering-CVE-2025-7026-7027-7028-7029-Research) :  ![starts](https://img.shields.io/github/stars/Tobss8/GIGABYTE-H510M-K-V2-BIOS-SMM-Reverse-Engineering-CVE-2025-7026-7027-7028-7029-Research.svg) ![forks](https://img.shields.io/github/forks/Tobss8/GIGABYTE-H510M-K-V2-BIOS-SMM-Reverse-Engineering-CVE-2025-7026-7027-7028-7029-Research.svg)


## CVE-2025-7026
 A vulnerability in the Software SMI handler (SwSmiInputValue 0xB2) allows a local attacker to control the RBX register, which is used as an unchecked pointer in the CommandRcx0 function. If the contents at RBX match certain expected values (e.g., '$DB$' or '2DB$'), the function performs arbitrary writes to System Management RAM (SMRAM), leading to potential privilege escalation to System Management Mode (SMM) and persistent firmware compromise.

- [https://github.com/Tobss8/GIGABYTE-H510M-K-V2-BIOS-SMM-Reverse-Engineering-CVE-2025-7026-7027-7028-7029-Research](https://github.com/Tobss8/GIGABYTE-H510M-K-V2-BIOS-SMM-Reverse-Engineering-CVE-2025-7026-7027-7028-7029-Research) :  ![starts](https://img.shields.io/github/stars/Tobss8/GIGABYTE-H510M-K-V2-BIOS-SMM-Reverse-Engineering-CVE-2025-7026-7027-7028-7029-Research.svg) ![forks](https://img.shields.io/github/forks/Tobss8/GIGABYTE-H510M-K-V2-BIOS-SMM-Reverse-Engineering-CVE-2025-7026-7027-7028-7029-Research.svg)


## CVE-2025-3248
code.

- [https://github.com/preemware/langflow-exploit](https://github.com/preemware/langflow-exploit) :  ![starts](https://img.shields.io/github/stars/preemware/langflow-exploit.svg) ![forks](https://img.shields.io/github/forks/preemware/langflow-exploit.svg)


## CVE-2024-56145
 Craft is a flexible, user-friendly CMS for creating custom digital experiences on the web and beyond. Users of affected versions are affected by this vulnerability if their php.ini configuration has `register_argc_argv` enabled. For these users an unspecified remote code execution vector is present. Users are advised to update to version 3.9.14, 4.13.2, or 5.5.2. Users unable to upgrade should disable `register_argc_argv` to mitigate the issue.

- [https://github.com/Chocapikk/CVE-2024-56145](https://github.com/Chocapikk/CVE-2024-56145) :  ![starts](https://img.shields.io/github/stars/Chocapikk/CVE-2024-56145.svg) ![forks](https://img.shields.io/github/forks/Chocapikk/CVE-2024-56145.svg)


## CVE-2024-45519
 The postjournal service in Zimbra Collaboration (ZCS) before 8.8.15 Patch 46, 9 before 9.0.0 Patch 41, 10 before 10.0.9, and 10.1 before 10.1.1 sometimes allows unauthenticated users to execute commands.

- [https://github.com/Chocapikk/CVE-2024-45519](https://github.com/Chocapikk/CVE-2024-45519) :  ![starts](https://img.shields.io/github/stars/Chocapikk/CVE-2024-45519.svg) ![forks](https://img.shields.io/github/forks/Chocapikk/CVE-2024-45519.svg)


## CVE-2024-36401
Versions 2.22.6, 2.23.6, 2.24.4, and 2.25.2 contain a patch for the issue. A workaround exists by removing the `gt-complex-x.y.jar` file from the GeoServer where `x.y` is the GeoTools version (e.g., `gt-complex-31.1.jar` if running GeoServer 2.25.1). This will remove the vulnerable code from GeoServer but may break some GeoServer functionality or prevent GeoServer from deploying if the gt-complex module is needed.

- [https://github.com/Chocapikk/CVE-2024-36401](https://github.com/Chocapikk/CVE-2024-36401) :  ![starts](https://img.shields.io/github/stars/Chocapikk/CVE-2024-36401.svg) ![forks](https://img.shields.io/github/forks/Chocapikk/CVE-2024-36401.svg)


## CVE-2024-34102
 Adobe Commerce versions 2.4.7, 2.4.6-p5, 2.4.5-p7, 2.4.4-p8 and earlier are affected by an Improper Restriction of XML External Entity Reference ('XXE') vulnerability that could result in arbitrary code execution. An attacker could exploit this vulnerability by sending a crafted XML document that references external entities. Exploitation of this issue does not require user interaction.

- [https://github.com/Chocapikk/CVE-2024-34102](https://github.com/Chocapikk/CVE-2024-34102) :  ![starts](https://img.shields.io/github/stars/Chocapikk/CVE-2024-34102.svg) ![forks](https://img.shields.io/github/forks/Chocapikk/CVE-2024-34102.svg)


## CVE-2024-31819
 An issue in WWBN AVideo v.12.4 through v.14.2 allows a remote attacker to execute arbitrary code via the systemRootPath parameter of the submitIndex.php component.

- [https://github.com/Chocapikk/CVE-2024-31819](https://github.com/Chocapikk/CVE-2024-31819) :  ![starts](https://img.shields.io/github/stars/Chocapikk/CVE-2024-31819.svg) ![forks](https://img.shields.io/github/forks/Chocapikk/CVE-2024-31819.svg)


## CVE-2024-30088
 Windows Kernel Elevation of Privilege Vulnerability

- [https://github.com/th3g3ntl3m4n84/CVE-2024-30088__Windows-TOCTOU-exploit](https://github.com/th3g3ntl3m4n84/CVE-2024-30088__Windows-TOCTOU-exploit) :  ![starts](https://img.shields.io/github/stars/th3g3ntl3m4n84/CVE-2024-30088__Windows-TOCTOU-exploit.svg) ![forks](https://img.shields.io/github/forks/th3g3ntl3m4n84/CVE-2024-30088__Windows-TOCTOU-exploit.svg)


## CVE-2024-29943
 An attacker was able to perform an out-of-bounds read or write on a JavaScript object by fooling range-based bounds check elimination. This vulnerability affects Firefox  124.0.1.

- [https://github.com/SneakyNachos/CVE-2024-29943-but-with-wasm](https://github.com/SneakyNachos/CVE-2024-29943-but-with-wasm) :  ![starts](https://img.shields.io/github/stars/SneakyNachos/CVE-2024-29943-but-with-wasm.svg) ![forks](https://img.shields.io/github/forks/SneakyNachos/CVE-2024-29943-but-with-wasm.svg)


## CVE-2024-29269
 An issue discovered in Telesquare TLR-2005Ksh 1.0.0 and 1.1.4 allows attackers to run arbitrary system commands via the Cmd parameter.

- [https://github.com/Chocapikk/CVE-2024-29269](https://github.com/Chocapikk/CVE-2024-29269) :  ![starts](https://img.shields.io/github/stars/Chocapikk/CVE-2024-29269.svg) ![forks](https://img.shields.io/github/forks/Chocapikk/CVE-2024-29269.svg)


## CVE-2024-27198
 In JetBrains TeamCity before 2023.11.4 authentication bypass allowing to perform admin actions was possible

- [https://github.com/Chocapikk/CVE-2024-27198](https://github.com/Chocapikk/CVE-2024-27198) :  ![starts](https://img.shields.io/github/stars/Chocapikk/CVE-2024-27198.svg) ![forks](https://img.shields.io/github/forks/Chocapikk/CVE-2024-27198.svg)


## CVE-2024-25600
 Improper Control of Generation of Code ('Code Injection') vulnerability in Codeer Limited Bricks Builder allows Code Injection.This issue affects Bricks Builder: from n/a through 1.9.6.

- [https://github.com/Chocapikk/CVE-2024-25600](https://github.com/Chocapikk/CVE-2024-25600) :  ![starts](https://img.shields.io/github/stars/Chocapikk/CVE-2024-25600.svg) ![forks](https://img.shields.io/github/forks/Chocapikk/CVE-2024-25600.svg)


## CVE-2024-22903
 Vinchin Backup & Recovery v7.2 was discovered to contain an authenticated remote code execution (RCE) vulnerability via the deleteUpdateAPK function.

- [https://github.com/Chocapikk/CVE-2024-22899-to-22903-ExploitChain](https://github.com/Chocapikk/CVE-2024-22899-to-22903-ExploitChain) :  ![starts](https://img.shields.io/github/stars/Chocapikk/CVE-2024-22899-to-22903-ExploitChain.svg) ![forks](https://img.shields.io/github/forks/Chocapikk/CVE-2024-22899-to-22903-ExploitChain.svg)


## CVE-2024-22902
 Vinchin Backup & Recovery v7.2 was discovered to be configured with default root credentials.

- [https://github.com/Chocapikk/CVE-2024-22899-to-22903-ExploitChain](https://github.com/Chocapikk/CVE-2024-22899-to-22903-ExploitChain) :  ![starts](https://img.shields.io/github/stars/Chocapikk/CVE-2024-22899-to-22903-ExploitChain.svg) ![forks](https://img.shields.io/github/forks/Chocapikk/CVE-2024-22899-to-22903-ExploitChain.svg)


## CVE-2024-22901
 Vinchin Backup & Recovery v7.2 was discovered to use default MYSQL credentials.

- [https://github.com/Chocapikk/CVE-2024-22899-to-22903-ExploitChain](https://github.com/Chocapikk/CVE-2024-22899-to-22903-ExploitChain) :  ![starts](https://img.shields.io/github/stars/Chocapikk/CVE-2024-22899-to-22903-ExploitChain.svg) ![forks](https://img.shields.io/github/forks/Chocapikk/CVE-2024-22899-to-22903-ExploitChain.svg)


## CVE-2024-22900
 Vinchin Backup & Recovery v7.2 was discovered to contain an authenticated remote code execution (RCE) vulnerability via the setNetworkCardInfo function.

- [https://github.com/Chocapikk/CVE-2024-22899-to-22903-ExploitChain](https://github.com/Chocapikk/CVE-2024-22899-to-22903-ExploitChain) :  ![starts](https://img.shields.io/github/stars/Chocapikk/CVE-2024-22899-to-22903-ExploitChain.svg) ![forks](https://img.shields.io/github/forks/Chocapikk/CVE-2024-22899-to-22903-ExploitChain.svg)


## CVE-2024-22899
 Vinchin Backup & Recovery v7.2 was discovered to contain an authenticated remote code execution (RCE) vulnerability via the syncNtpTime function.

- [https://github.com/Chocapikk/CVE-2024-22899-to-22903-ExploitChain](https://github.com/Chocapikk/CVE-2024-22899-to-22903-ExploitChain) :  ![starts](https://img.shields.io/github/stars/Chocapikk/CVE-2024-22899-to-22903-ExploitChain.svg) ![forks](https://img.shields.io/github/forks/Chocapikk/CVE-2024-22899-to-22903-ExploitChain.svg)


## CVE-2024-21893
 A server-side request forgery vulnerability in the SAML component of Ivanti Connect Secure (9.x, 22.x) and Ivanti Policy Secure (9.x, 22.x) and Ivanti Neurons for ZTA allows an attacker to access certain restricted resources without authentication.

- [https://github.com/Chocapikk/CVE-2024-21893-to-CVE-2024-21887](https://github.com/Chocapikk/CVE-2024-21893-to-CVE-2024-21887) :  ![starts](https://img.shields.io/github/stars/Chocapikk/CVE-2024-21893-to-CVE-2024-21887.svg) ![forks](https://img.shields.io/github/forks/Chocapikk/CVE-2024-21893-to-CVE-2024-21887.svg)


## CVE-2024-21887
 A command injection vulnerability in web components of Ivanti Connect Secure (9.x, 22.x) and Ivanti Policy Secure (9.x, 22.x)  allows an authenticated administrator to send specially crafted requests and execute arbitrary commands on the appliance.

- [https://github.com/Chocapikk/CVE-2024-21887](https://github.com/Chocapikk/CVE-2024-21887) :  ![starts](https://img.shields.io/github/stars/Chocapikk/CVE-2024-21887.svg) ![forks](https://img.shields.io/github/forks/Chocapikk/CVE-2024-21887.svg)
- [https://github.com/Chocapikk/CVE-2024-21893-to-CVE-2024-21887](https://github.com/Chocapikk/CVE-2024-21893-to-CVE-2024-21887) :  ![starts](https://img.shields.io/github/stars/Chocapikk/CVE-2024-21893-to-CVE-2024-21887.svg) ![forks](https://img.shields.io/github/forks/Chocapikk/CVE-2024-21893-to-CVE-2024-21887.svg)


## CVE-2024-20767
 ColdFusion versions 2023.6, 2021.12 and earlier are affected by an Improper Access Control vulnerability that could result in arbitrary file system read. An attacker could leverage this vulnerability to access or modify restricted files. Exploitation of this issue does not require user interaction. Exploitation of this issue requires the admin panel be exposed to the internet.

- [https://github.com/Chocapikk/CVE-2024-20767](https://github.com/Chocapikk/CVE-2024-20767) :  ![starts](https://img.shields.io/github/stars/Chocapikk/CVE-2024-20767.svg) ![forks](https://img.shields.io/github/forks/Chocapikk/CVE-2024-20767.svg)


## CVE-2024-9474
Cloud NGFW and Prisma Access are not impacted by this vulnerability.

- [https://github.com/Chocapikk/CVE-2024-9474](https://github.com/Chocapikk/CVE-2024-9474) :  ![starts](https://img.shields.io/github/stars/Chocapikk/CVE-2024-9474.svg) ![forks](https://img.shields.io/github/forks/Chocapikk/CVE-2024-9474.svg)


## CVE-2024-8672
 The Widget Options – The #1 WordPress Widget & Block Control Plugin plugin for WordPress is vulnerable to Remote Code Execution in all versions up to, and including, 4.0.7 via the display logic functionality that extends several page builders. This is due to the plugin allowing users to supply input that will be passed through eval() without any filtering or capability checks. This makes it possible for authenticated attackers, with contributor-level access and above, to execute code on the server. Special note: We suggested the vendor implement an allowlist of functions and limit the ability to execute commands to just administrators, however, they did not take our advice. We are considering this patched, however, we believe it could still be further hardened and there may be residual risk with how the issue is currently patched.

- [https://github.com/Chocapikk/CVE-2024-8672](https://github.com/Chocapikk/CVE-2024-8672) :  ![starts](https://img.shields.io/github/stars/Chocapikk/CVE-2024-8672.svg) ![forks](https://img.shields.io/github/forks/Chocapikk/CVE-2024-8672.svg)


## CVE-2024-8517
remote and unauthenticated attacker can execute arbitrary operating system commands by sending a crafted multipart file upload HTTP request.

- [https://github.com/Chocapikk/CVE-2024-8517](https://github.com/Chocapikk/CVE-2024-8517) :  ![starts](https://img.shields.io/github/stars/Chocapikk/CVE-2024-8517.svg) ![forks](https://img.shields.io/github/forks/Chocapikk/CVE-2024-8517.svg)


## CVE-2024-8504
 An attacker with authenticated access to VICIdial as an "agent" can execute arbitrary shell commands as the "root" user. This attack can be chained with CVE-2024-8503 to execute arbitrary shell commands starting from an unauthenticated perspective.

- [https://github.com/Chocapikk/CVE-2024-8504](https://github.com/Chocapikk/CVE-2024-8504) :  ![starts](https://img.shields.io/github/stars/Chocapikk/CVE-2024-8504.svg) ![forks](https://img.shields.io/github/forks/Chocapikk/CVE-2024-8504.svg)


## CVE-2024-8503
 An unauthenticated attacker can leverage a time-based SQL injection vulnerability in VICIdial to enumerate database records. By default, VICIdial stores plaintext credentials within the database.

- [https://github.com/Chocapikk/CVE-2024-8504](https://github.com/Chocapikk/CVE-2024-8504) :  ![starts](https://img.shields.io/github/stars/Chocapikk/CVE-2024-8504.svg) ![forks](https://img.shields.io/github/forks/Chocapikk/CVE-2024-8504.svg)


## CVE-2024-7954
 The porte_plume plugin used by SPIP before 4.30-alpha2, 4.2.13, and 4.1.16 is vulnerable to an arbitrary code execution vulnerability. A remote and unauthenticated attacker can execute arbitrary PHP as the SPIP user by sending a crafted HTTP request.

- [https://github.com/Chocapikk/CVE-2024-7954](https://github.com/Chocapikk/CVE-2024-7954) :  ![starts](https://img.shields.io/github/stars/Chocapikk/CVE-2024-7954.svg) ![forks](https://img.shields.io/github/forks/Chocapikk/CVE-2024-7954.svg)


## CVE-2024-5084
 The Hash Form – Drag & Drop Form Builder plugin for WordPress is vulnerable to arbitrary file uploads due to missing file type validation in the 'file_upload_action' function in all versions up to, and including, 1.1.0. This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible.

- [https://github.com/Chocapikk/CVE-2024-5084](https://github.com/Chocapikk/CVE-2024-5084) :  ![starts](https://img.shields.io/github/stars/Chocapikk/CVE-2024-5084.svg) ![forks](https://img.shields.io/github/forks/Chocapikk/CVE-2024-5084.svg)


## CVE-2024-4577
 In PHP versions 8.1.* before 8.1.29, 8.2.* before 8.2.20, 8.3.* before 8.3.8, when using Apache and PHP-CGI on Windows, if the system is set up to use certain code pages, Windows may use "Best-Fit" behavior to replace characters in command line given to Win32 API functions. PHP CGI module may misinterpret those characters as PHP options, which may allow a malicious user to pass options to PHP binary being run, and thus reveal the source code of scripts, run arbitrary PHP code on the server, etc.

- [https://github.com/Chocapikk/CVE-2024-4577](https://github.com/Chocapikk/CVE-2024-4577) :  ![starts](https://img.shields.io/github/stars/Chocapikk/CVE-2024-4577.svg) ![forks](https://img.shields.io/github/forks/Chocapikk/CVE-2024-4577.svg)
- [https://github.com/DuyDuongDuyDuong/CVE-2024-4577-Exploitation-AsyncRAT-Deployment-DFIR-Investigatio](https://github.com/DuyDuongDuyDuong/CVE-2024-4577-Exploitation-AsyncRAT-Deployment-DFIR-Investigatio) :  ![starts](https://img.shields.io/github/stars/DuyDuongDuyDuong/CVE-2024-4577-Exploitation-AsyncRAT-Deployment-DFIR-Investigatio.svg) ![forks](https://img.shields.io/github/forks/DuyDuongDuyDuong/CVE-2024-4577-Exploitation-AsyncRAT-Deployment-DFIR-Investigatio.svg)


## CVE-2024-3400
Cloud NGFW, Panorama appliances, and Prisma Access are not impacted by this vulnerability.

- [https://github.com/Chocapikk/CVE-2024-3400](https://github.com/Chocapikk/CVE-2024-3400) :  ![starts](https://img.shields.io/github/stars/Chocapikk/CVE-2024-3400.svg) ![forks](https://img.shields.io/github/forks/Chocapikk/CVE-2024-3400.svg)


## CVE-2024-3273
 ** UNSUPPORTED WHEN ASSIGNED ** A vulnerability, which was classified as critical, was found in D-Link DNS-320L, DNS-325, DNS-327L and DNS-340L up to 20240403. Affected is an unknown function of the file /cgi-bin/nas_sharing.cgi of the component HTTP GET Request Handler. The manipulation of the argument system leads to command injection. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used. The identifier of this vulnerability is VDB-259284. NOTE: This vulnerability only affects products that are no longer supported by the maintainer. NOTE: Vendor was contacted early and confirmed immediately that the product is end-of-life. It should be retired and replaced.

- [https://github.com/Chocapikk/CVE-2024-3273](https://github.com/Chocapikk/CVE-2024-3273) :  ![starts](https://img.shields.io/github/stars/Chocapikk/CVE-2024-3273.svg) ![forks](https://img.shields.io/github/forks/Chocapikk/CVE-2024-3273.svg)


## CVE-2024-3094
Through a series of complex obfuscations, the liblzma build process extracts a prebuilt object file from a disguised test file existing in the source code, which is then used to modify specific functions in the liblzma code. This results in a modified liblzma library that can be used by any software linked against this library, intercepting and modifying the data interaction with this library.

- [https://github.com/namegabevictoire01-sys/cs50-cybersecurity-final-project](https://github.com/namegabevictoire01-sys/cs50-cybersecurity-final-project) :  ![starts](https://img.shields.io/github/stars/namegabevictoire01-sys/cs50-cybersecurity-final-project.svg) ![forks](https://img.shields.io/github/forks/namegabevictoire01-sys/cs50-cybersecurity-final-project.svg)


## CVE-2024-1212
 Unauthenticated remote attackers can access the system through the LoadMaster management interface, enabling arbitrary system command execution.

- [https://github.com/Chocapikk/CVE-2024-1212](https://github.com/Chocapikk/CVE-2024-1212) :  ![starts](https://img.shields.io/github/stars/Chocapikk/CVE-2024-1212.svg) ![forks](https://img.shields.io/github/forks/Chocapikk/CVE-2024-1212.svg)

