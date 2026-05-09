# Update 2026-05-09
## CVE-2026-44109
 OpenClaw before 2026.4.15 contains an authentication bypass vulnerability in Feishu webhook and card-action validation that allows unauthenticated requests to reach command dispatch. Missing encryptKey configuration and blank callback tokens fail open instead of rejecting requests, enabling attackers to bypass signature verification and replay protection to execute arbitrary commands.

- [https://github.com/CryptReaper12/CVE-2026-44109](https://github.com/CryptReaper12/CVE-2026-44109) :  ![starts](https://img.shields.io/github/stars/CryptReaper12/CVE-2026-44109.svg) ![forks](https://img.shields.io/github/forks/CryptReaper12/CVE-2026-44109.svg)


## CVE-2026-43585
 OpenClaw before 2026.4.15 captures resolved bearer-auth configuration at startup, allowing revoked tokens to remain valid after SecretRef rotation. Gateway HTTP and WebSocket handlers fail to re-resolve authentication per-request, enabling attackers to use rotated-out bearer tokens for unauthorized gateway access.

- [https://github.com/ByteWraith1/CVE-2026-43585](https://github.com/ByteWraith1/CVE-2026-43585) :  ![starts](https://img.shields.io/github/stars/ByteWraith1/CVE-2026-43585.svg) ![forks](https://img.shields.io/github/forks/ByteWraith1/CVE-2026-43585.svg)


## CVE-2026-42231
 n8n is an open source workflow automation platform. Prior to versions 1.123.32, 2.17.4, and 2.18.1, a flaw in the xml2js library used to parse XML request bodies in n8n's webhook handler allowed prototype pollution via a crafted XML payload. An authenticated user with permission to create or modify workflows could exploit this to pollute the JavaScript object prototype and, by chaining the pollution with the Git node's SSH operations, achieve remote code execution on the n8n host. This issue has been patched in versions 1.123.32, 2.17.4, and 2.18.1.

- [https://github.com/rudSarkar/CVE-2026-42231](https://github.com/rudSarkar/CVE-2026-42231) :  ![starts](https://img.shields.io/github/stars/rudSarkar/CVE-2026-42231.svg) ![forks](https://img.shields.io/github/forks/rudSarkar/CVE-2026-42231.svg)


## CVE-2026-42228
 n8n is an open source workflow automation platform. Prior to versions 1.123.32, 2.17.4, and 2.18.1, the /chat WebSocket endpoint used by the Chat Trigger node's Hosted Chat feature did not verify that an incoming connection was authorized to interact with the target execution. An unauthenticated remote attacker who could identify a valid execution ID for a workflow in a waiting state could attach to that execution, receive the pending prompt intended for the legitimate user, and submit arbitrary input to resume or influence downstream workflow behavior. This issue has been patched in versions 1.123.32, 2.17.4, and 2.18.1.

- [https://github.com/rudSarkar/CVE-2026-42228](https://github.com/rudSarkar/CVE-2026-42228) :  ![starts](https://img.shields.io/github/stars/rudSarkar/CVE-2026-42228.svg) ![forks](https://img.shields.io/github/forks/rudSarkar/CVE-2026-42228.svg)


## CVE-2026-41940
 cPanel and WHM versions after 11.40 contain an authentication bypass vulnerability in the login flow that allows unauthenticated remote attackers to gain unauthorized access to the control panel.

- [https://github.com/thekawix/CVE-2026-41940](https://github.com/thekawix/CVE-2026-41940) :  ![starts](https://img.shields.io/github/stars/thekawix/CVE-2026-41940.svg) ![forks](https://img.shields.io/github/forks/thekawix/CVE-2026-41940.svg)


## CVE-2026-41653
 BentoPDF is a client-side PDF toolkit that is self hostable. Prior to version 2.8.3, a cross-site scripting vulnerability was identified in BentoPD. An attacker may be able to execute arbitrary JavaScript in certain circumstances in Markdown to PDF Tool. This issue has been patched in version 2.8.3.

- [https://github.com/Astaruf/CVE-2026-41653](https://github.com/Astaruf/CVE-2026-41653) :  ![starts](https://img.shields.io/github/stars/Astaruf/CVE-2026-41653.svg) ![forks](https://img.shields.io/github/forks/Astaruf/CVE-2026-41653.svg)


## CVE-2026-41651
3. Late flag read at execution time (lines 2273–2277): The scheduler's idle callback reads cached_transaction_flags at dispatch time, not at authorization time. If flags were overwritten between authorization and execution, the backend sees the attacker's flags.

- [https://github.com/mawussid/CVE-2026-41651-Python](https://github.com/mawussid/CVE-2026-41651-Python) :  ![starts](https://img.shields.io/github/stars/mawussid/CVE-2026-41651-Python.svg) ![forks](https://img.shields.io/github/forks/mawussid/CVE-2026-41651-Python.svg)


## CVE-2026-40897
 Math.js is an extensive math library for JavaScript and Node.js. From 13.1.1 to before 15.2.0, a vulnerability allowed executing arbitrary JavaScript via the expression parser of mathjs. You can be affected when you have an application where users can evaluate arbitrary expressions using the mathjs expression parser. This vulnerability is fixed in 15.2.0.

- [https://github.com/EQSTLab/CVE-2026-40897](https://github.com/EQSTLab/CVE-2026-40897) :  ![starts](https://img.shields.io/github/stars/EQSTLab/CVE-2026-40897.svg) ![forks](https://img.shields.io/github/forks/EQSTLab/CVE-2026-40897.svg)


## CVE-2026-40281
 Gotenberg is a Docker-powered stateless API for PDF files. In versions 8.30.1 and earlier, the metadata write endpoint validates metadata keys for control characters but leaves metadata values unsanitized. A newline character in a metadata value splits the ExifTool stdin line into two separate arguments, allowing injection of arbitrary ExifTool pseudo-tags such as -FileName, -Directory, -SymLink, and -HardLink. This is a bypass of the incomplete key-sanitization fix introduced in v8.30.1. An unauthenticated attacker can rename or move any PDF being processed to an arbitrary path in the container filesystem, overwrite arbitrary files, or create symlinks and hard links at arbitrary paths.

- [https://github.com/ByteWraith1/CVE-2026-40281](https://github.com/ByteWraith1/CVE-2026-40281) :  ![starts](https://img.shields.io/github/stars/ByteWraith1/CVE-2026-40281.svg) ![forks](https://img.shields.io/github/forks/ByteWraith1/CVE-2026-40281.svg)


## CVE-2026-40003
 ZTE ZX297520V3 BootROM contains a vulnerability that allows arbitrary memory writes via USB. Attackers can exploit the lack of target address validation in the USB download mode to write data to any location in BootROM runtime memory, thereby overwriting the stack, hijacking the execution flow, bypassing the Secure Boot signature verification mechanism, and achieving unauthorized code execution.

- [https://github.com/rva3/CVE-2026-40003](https://github.com/rva3/CVE-2026-40003) :  ![starts](https://img.shields.io/github/stars/rva3/CVE-2026-40003.svg) ![forks](https://img.shields.io/github/forks/rva3/CVE-2026-40003.svg)


## CVE-2026-36341
 Cross-Site Scripting (XSS) vulnerability exists in Webkul Krayin CRM v2.1.5. The application fails to sanitize user-supplied input in the comment field during Activity creation on the /admin/activities/create endpoint

- [https://github.com/cybercrewinc/CVE-2026-36341](https://github.com/cybercrewinc/CVE-2026-36341) :  ![starts](https://img.shields.io/github/stars/cybercrewinc/CVE-2026-36341.svg) ![forks](https://img.shields.io/github/forks/cybercrewinc/CVE-2026-36341.svg)


## CVE-2026-35250
 Vulnerability in the Oracle VM VirtualBox product of Oracle Virtualization (component: Core).   The supported version that is affected is 7.2.6. Easily exploitable vulnerability allows high privileged attacker with logon to the infrastructure where Oracle VM VirtualBox executes to compromise Oracle VM VirtualBox.  Successful attacks of this vulnerability can result in unauthorized ability to cause a partial denial of service (partial DOS) of Oracle VM VirtualBox. CVSS 3.1 Base Score 2.3 (Availability impacts).  CVSS Vector: (CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:L).

- [https://github.com/xooxo/CVE-2026-35250](https://github.com/xooxo/CVE-2026-35250) :  ![starts](https://img.shields.io/github/stars/xooxo/CVE-2026-35250.svg) ![forks](https://img.shields.io/github/forks/xooxo/CVE-2026-35250.svg)


## CVE-2026-31431
AD directly.

- [https://github.com/sgkdev/page_inject](https://github.com/sgkdev/page_inject) :  ![starts](https://img.shields.io/github/stars/sgkdev/page_inject.svg) ![forks](https://img.shields.io/github/forks/sgkdev/page_inject.svg)
- [https://github.com/codesource/copyfail-check](https://github.com/codesource/copyfail-check) :  ![starts](https://img.shields.io/github/stars/codesource/copyfail-check.svg) ![forks](https://img.shields.io/github/forks/codesource/copyfail-check.svg)
- [https://github.com/pedromizz/copy-fail](https://github.com/pedromizz/copy-fail) :  ![starts](https://img.shields.io/github/stars/pedromizz/copy-fail.svg) ![forks](https://img.shields.io/github/forks/pedromizz/copy-fail.svg)
- [https://github.com/gagaltotal/cve-2026-31431-copy-fail](https://github.com/gagaltotal/cve-2026-31431-copy-fail) :  ![starts](https://img.shields.io/github/stars/gagaltotal/cve-2026-31431-copy-fail.svg) ![forks](https://img.shields.io/github/forks/gagaltotal/cve-2026-31431-copy-fail.svg)
- [https://github.com/philfry/cve-2026-31431-ftrace](https://github.com/philfry/cve-2026-31431-ftrace) :  ![starts](https://img.shields.io/github/stars/philfry/cve-2026-31431-ftrace.svg) ![forks](https://img.shields.io/github/forks/philfry/cve-2026-31431-ftrace.svg)
- [https://github.com/Vatson112/deny-af-alg-bpf](https://github.com/Vatson112/deny-af-alg-bpf) :  ![starts](https://img.shields.io/github/stars/Vatson112/deny-af-alg-bpf.svg) ![forks](https://img.shields.io/github/forks/Vatson112/deny-af-alg-bpf.svg)


## CVE-2026-27944
 Nginx UI is a web user interface for the Nginx web server. Prior to version 2.3.3, the /api/backup endpoint is accessible without authentication and discloses the encryption keys required to decrypt the backup in the X-Backup-Security response header. This allows an unauthenticated attacker to download a full system backup containing sensitive data (user credentials, session tokens, SSL private keys, Nginx configurations) and decrypt it immediately. This issue has been patched in version 2.3.3.

- [https://github.com/karimelsheikh1/HTB-Snapped-Writeup](https://github.com/karimelsheikh1/HTB-Snapped-Writeup) :  ![starts](https://img.shields.io/github/stars/karimelsheikh1/HTB-Snapped-Writeup.svg) ![forks](https://img.shields.io/github/forks/karimelsheikh1/HTB-Snapped-Writeup.svg)


## CVE-2026-27906
 Improper input validation in Windows Hello allows an authorized attacker to bypass a security feature locally.

- [https://github.com/ByteWraith1/CVE-2026-27906](https://github.com/ByteWraith1/CVE-2026-27906) :  ![starts](https://img.shields.io/github/stars/ByteWraith1/CVE-2026-27906.svg) ![forks](https://img.shields.io/github/forks/ByteWraith1/CVE-2026-27906.svg)


## CVE-2026-24118
 vm2 is an open source vm/sandbox for Node.js. Prior to version 3.11.0, VM2 suffers from a sandbox breakout vulnerability. This allows attackers to write code which can escape from the VM2 sandbox and execute arbitrary commands on the host system. This issue has been patched in version 3.11.0.

- [https://github.com/HORKimhab/CVE-2026-24118](https://github.com/HORKimhab/CVE-2026-24118) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-24118.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-24118.svg)


## CVE-2026-23918
Users are recommended to upgrade to version 2.4.67, which fixes the issue.

- [https://github.com/alt3kx/CVE-2026-23918](https://github.com/alt3kx/CVE-2026-23918) :  ![starts](https://img.shields.io/github/stars/alt3kx/CVE-2026-23918.svg) ![forks](https://img.shields.io/github/forks/alt3kx/CVE-2026-23918.svg)


## CVE-2026-23870
 A denial of service vulnerability could be triggered by sending specially crafted HTTP requests to server function endpoints, this could lead to server crashes, out-of-memory exceptions or excessive CPU usage; affecting the following packages: react-server-dom-webpack, react-server-dom-parcel, react-server-dom-turbopack (versions 19.0.0 through 19.0.5, 19.1.0 through 19.1.6, and 19.2.0 through 19.2.5).

- [https://github.com/dwisiswant0/next-16.2.4-pocs](https://github.com/dwisiswant0/next-16.2.4-pocs) :  ![starts](https://img.shields.io/github/stars/dwisiswant0/next-16.2.4-pocs.svg) ![forks](https://img.shields.io/github/forks/dwisiswant0/next-16.2.4-pocs.svg)


## CVE-2026-7482
 Ollama before 0.17.1 contains a heap out-of-bounds read vulnerability in the GGUF model loader. The /api/create endpoint accepts an attacker-supplied GGUF file in which the declared tensor offset and size exceed the file's actual length; during quantization in fs/ggml/gguf.go and server/quantization.go (WriteTo()), the server reads past the allocated heap buffer. The leaked memory contents may include environment variables, API keys, system prompts, and concurrent users' conversation data, and can be exfiltrated by uploading the resulting model artifact through the /api/push endpoint to an attacker-controlled registry. The /api/create and /api/push endpoints have no authentication in the upstream distribution. Default deployments bind to 127.0.0.1, but the documented OLLAMA_HOST=0.0.0.0 configuration is widely used in practice (large public-internet exposure observed).

- [https://github.com/szybnev/CVE-2026-7482](https://github.com/szybnev/CVE-2026-7482) :  ![starts](https://img.shields.io/github/stars/szybnev/CVE-2026-7482.svg) ![forks](https://img.shields.io/github/forks/szybnev/CVE-2026-7482.svg)


## CVE-2026-6508
This issue affects Liderahenk: from 2.0.1 before 2.0.2.

- [https://github.com/jackalkarlos/EvilAhenk](https://github.com/jackalkarlos/EvilAhenk) :  ![starts](https://img.shields.io/github/stars/jackalkarlos/EvilAhenk.svg) ![forks](https://img.shields.io/github/forks/jackalkarlos/EvilAhenk.svg)


## CVE-2026-5615
 A weakness has been identified in givanz Vvvebjs up to 2.0.5. The affected element is an unknown function of the file upload.php of the component File Upload Endpoint. This manipulation of the argument uploadAllowExtensions causes cross site scripting. Remote exploitation of the attack is possible. The exploit has been made available to the public and could be used for attacks. Patch name: 8cac22cff99b8bc701c408aa8e887fa702755336. Applying a patch is the recommended action to fix this issue. The vendor was contacted early, responded in a very professional manner and quickly released a fixed version of the affected product.

- [https://github.com/sahmsec/CVE-2026-5615](https://github.com/sahmsec/CVE-2026-5615) :  ![starts](https://img.shields.io/github/stars/sahmsec/CVE-2026-5615.svg) ![forks](https://img.shields.io/github/forks/sahmsec/CVE-2026-5615.svg)


## CVE-2026-4459
 Out of bounds read and write in WebAudio in Google Chrome prior to 146.0.7680.153 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/Astaruf/CVE-2026-44590](https://github.com/Astaruf/CVE-2026-44590) :  ![starts](https://img.shields.io/github/stars/Astaruf/CVE-2026-44590.svg) ![forks](https://img.shields.io/github/forks/Astaruf/CVE-2026-44590.svg)


## CVE-2026-4426
 A flaw was found in libarchive. An Undefined Behavior vulnerability exists in the zisofs decompression logic, caused by improper validation of a field (`pz_log2_bs`) read from ISO9660 Rock Ridge extensions. A remote attacker can exploit this by supplying a specially crafted ISO file. This can lead to incorrect memory allocation and potential application crashes, resulting in a denial-of-service (DoS) condition.

- [https://github.com/joshuavanderpoll/CVE-2026-44262](https://github.com/joshuavanderpoll/CVE-2026-44262) :  ![starts](https://img.shields.io/github/stars/joshuavanderpoll/CVE-2026-44262.svg) ![forks](https://img.shields.io/github/forks/joshuavanderpoll/CVE-2026-44262.svg)


## CVE-2026-3888
 Local privilege escalation in snapd on Linux allows local attackers to get root privilege by re-creating snap's private /tmp directory when systemd-tmpfiles is configured to automatically clean up this directory. This issue affects Ubuntu 16.04 LTS, 18.04 LTS, 20.04 LTS, 22.04 LTS, and 24.04 LTS.

- [https://github.com/karimelsheikh1/HTB-Snapped-Writeup](https://github.com/karimelsheikh1/HTB-Snapped-Writeup) :  ![starts](https://img.shields.io/github/stars/karimelsheikh1/HTB-Snapped-Writeup.svg) ![forks](https://img.shields.io/github/forks/karimelsheikh1/HTB-Snapped-Writeup.svg)


## CVE-2026-3844
 The Breeze Cache plugin for WordPress is vulnerable to arbitrary file uploads due to missing file type validation in the 'fetch_gravatar_from_remote' function in all versions up to, and including, 2.4.4. This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible. The vulnerability can only be exploited if "Host Files Locally - Gravatars" is enabled, which is disabled by default.

- [https://github.com/sahmsec/CVE-2026-3844](https://github.com/sahmsec/CVE-2026-3844) :  ![starts](https://img.shields.io/github/stars/sahmsec/CVE-2026-3844.svg) ![forks](https://img.shields.io/github/forks/sahmsec/CVE-2026-3844.svg)


## CVE-2026-3727
 A vulnerability was found in Tenda F453 1.0.0.3. This vulnerability affects the function sub_3C6C0 of the file /goform/QuickIndex. The manipulation of the argument mit_linktype/PPPOEPassword results in stack-based buffer overflow. The attack may be launched remotely. The exploit has been made public and could be used.

- [https://github.com/vytlanikhil/CVE-2026-37272](https://github.com/vytlanikhil/CVE-2026-37272) :  ![starts](https://img.shields.io/github/stars/vytlanikhil/CVE-2026-37272.svg) ![forks](https://img.shields.io/github/forks/vytlanikhil/CVE-2026-37272.svg)


## CVE-2026-0073
 In adbd_tls_verify_cert of auth.cpp, there is a possible bypass of wireless ADB mutual authentication due to a logic error in the code. This could lead to remote (proximal/adjacent) code execution as the shell user with no additional execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/0xBlackash/CVE-2026-0073](https://github.com/0xBlackash/CVE-2026-0073) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-0073.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-0073.svg)
- [https://github.com/unnaim/adbHijacker](https://github.com/unnaim/adbHijacker) :  ![starts](https://img.shields.io/github/stars/unnaim/adbHijacker.svg) ![forks](https://img.shields.io/github/forks/unnaim/adbHijacker.svg)


## CVE-2025-69256
 The Serverless Framework is a framework for using AWS Lambda and other managed cloud services to build applications. Starting in version 4.29.0 and prior to version 4.29.3, a command injection vulnerability exists in the Serverless Framework's built-in MCP server package (@serverless/mcp). This vulnerability only affects users of the experimental MCP server feature (serverless mcp), which represents less than 0.1% of Serverless Framework users. The core Serverless Framework CLI and deployment functionality are not affected. The vulnerability is caused by the unsanitized use of input parameters within a call to `child_process.exec`, enabling an attacker to inject arbitrary system commands. Successful exploitation can lead to remote code execution under the server process's privileges. The server constructs and executes shell commands using unvalidated user input directly within command-line strings. This introduces the possibility of shell metacharacter injection (`|`, ``, `&&`, etc.). Version 4.29.3 fixes the issue.

- [https://github.com/studiomeyer-io/mcp-stdio-shellguard](https://github.com/studiomeyer-io/mcp-stdio-shellguard) :  ![starts](https://img.shields.io/github/stars/studiomeyer-io/mcp-stdio-shellguard.svg) ![forks](https://img.shields.io/github/forks/studiomeyer-io/mcp-stdio-shellguard.svg)


## CVE-2025-44964
 A lack of SSL certificate validation in BlueStacks v5.20 allows attackers to execute a man-it-the-middle attack and obtain sensitive information.

- [https://github.com/ddanielx86/CVE-2025-44964](https://github.com/ddanielx86/CVE-2025-44964) :  ![starts](https://img.shields.io/github/stars/ddanielx86/CVE-2025-44964.svg) ![forks](https://img.shields.io/github/forks/ddanielx86/CVE-2025-44964.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/sn1p3rt3s7/NextJS_CVE-2025-29927](https://github.com/sn1p3rt3s7/NextJS_CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/sn1p3rt3s7/NextJS_CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/sn1p3rt3s7/NextJS_CVE-2025-29927.svg)


## CVE-2025-6440
 The WooCommerce Designer Pro plugin for WordPress, used by the Pricom - Printing Company & Design Services WordPress theme, is vulnerable to arbitrary file uploads due to missing file type validation in the 'wcdp_save_canvas_design_ajax' function in all versions up to, and including, 1.9.26. This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible.

- [https://github.com/sahmsec/CVE-2025-6440](https://github.com/sahmsec/CVE-2025-6440) :  ![starts](https://img.shields.io/github/stars/sahmsec/CVE-2025-6440.svg) ![forks](https://img.shields.io/github/forks/sahmsec/CVE-2025-6440.svg)


## CVE-2025-4321
 In a Bluetooth device, using RS9116-WiseConnect SDK experiences a Denial of Service, if it receives malformed L2CAP packets, only hard reset will bring the device to normal operation

- [https://github.com/Salman-Sec/Patch-management-](https://github.com/Salman-Sec/Patch-management-) :  ![starts](https://img.shields.io/github/stars/Salman-Sec/Patch-management-.svg) ![forks](https://img.shields.io/github/forks/Salman-Sec/Patch-management-.svg)


## CVE-2024-32002
 Git is a revision control system. Prior to versions 2.45.1, 2.44.1, 2.43.4, 2.42.2, 2.41.1, 2.40.2, and 2.39.4, repositories with submodules can be crafted in a way that exploits a bug in Git whereby it can be fooled into writing files not into the submodule's worktree but into a `.git/` directory. This allows writing a hook that will be executed while the clone operation is still running, giving the user no opportunity to inspect the code that is being executed. The problem has been patched in versions 2.45.1, 2.44.1, 2.43.4, 2.42.2, 2.41.1, 2.40.2, and 2.39.4. If symbolic link support is disabled in Git (e.g. via `git config --global core.symlinks false`), the described attack won't work. As always, it is best to avoid cloning repositories from untrusted sources.

- [https://github.com/jakob-pennington/cve-2024-32002-poc-rce](https://github.com/jakob-pennington/cve-2024-32002-poc-rce) :  ![starts](https://img.shields.io/github/stars/jakob-pennington/cve-2024-32002-poc-rce.svg) ![forks](https://img.shields.io/github/forks/jakob-pennington/cve-2024-32002-poc-rce.svg)
- [https://github.com/jakob-pennington/cve-2024-32002-submodule-aw](https://github.com/jakob-pennington/cve-2024-32002-submodule-aw) :  ![starts](https://img.shields.io/github/stars/jakob-pennington/cve-2024-32002-submodule-aw.svg) ![forks](https://img.shields.io/github/forks/jakob-pennington/cve-2024-32002-submodule-aw.svg)
- [https://github.com/jakob-pennington/cve-2024-32002-poc-aw](https://github.com/jakob-pennington/cve-2024-32002-poc-aw) :  ![starts](https://img.shields.io/github/stars/jakob-pennington/cve-2024-32002-poc-aw.svg) ![forks](https://img.shields.io/github/forks/jakob-pennington/cve-2024-32002-poc-aw.svg)
- [https://github.com/jakob-pennington/cve-2024-32002-submodule-rce](https://github.com/jakob-pennington/cve-2024-32002-submodule-rce) :  ![starts](https://img.shields.io/github/stars/jakob-pennington/cve-2024-32002-submodule-rce.svg) ![forks](https://img.shields.io/github/forks/jakob-pennington/cve-2024-32002-submodule-rce.svg)


## CVE-2024-27956
 Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vulnerability in ValvePress Automatic allows SQL Injection.This issue affects Automatic: from n/a through 3.92.0.

- [https://github.com/AiGptCode/AiGPT-WordPress-Exploitation-Framework](https://github.com/AiGptCode/AiGPT-WordPress-Exploitation-Framework) :  ![starts](https://img.shields.io/github/stars/AiGptCode/AiGPT-WordPress-Exploitation-Framework.svg) ![forks](https://img.shields.io/github/forks/AiGptCode/AiGPT-WordPress-Exploitation-Framework.svg)


## CVE-2024-27102
 Wings is the server control plane for Pterodactyl Panel. This vulnerability impacts anyone running the affected versions of Wings. The vulnerability can potentially be used to access files and directories on the host system. The full scope of impact is exactly unknown, but reading files outside of a server's base directory (sandbox root) is possible. In order to use this exploit, an attacker must have an existing "server" allocated and controlled by Wings. Details on the exploitation of this vulnerability are embargoed until March 27th, 2024 at 18:00 UTC. In order to mitigate this vulnerability, a full rewrite of the entire server filesystem was necessary. Because of this, the size of the patch is massive, however effort was made to reduce the amount of breaking changes. Users are advised to update to version 1.11.9. There are no known workarounds for this vulnerability.

- [https://github.com/wyllowDev/Magnohost-Vulnerabilities-pentest](https://github.com/wyllowDev/Magnohost-Vulnerabilities-pentest) :  ![starts](https://img.shields.io/github/stars/wyllowDev/Magnohost-Vulnerabilities-pentest.svg) ![forks](https://img.shields.io/github/forks/wyllowDev/Magnohost-Vulnerabilities-pentest.svg)


## CVE-2023-21716
 Microsoft Word Remote Code Execution Vulnerability

- [https://github.com/Caliburn9/CVE-2023-21716-Analysis-ICT287](https://github.com/Caliburn9/CVE-2023-21716-Analysis-ICT287) :  ![starts](https://img.shields.io/github/stars/Caliburn9/CVE-2023-21716-Analysis-ICT287.svg) ![forks](https://img.shields.io/github/forks/Caliburn9/CVE-2023-21716-Analysis-ICT287.svg)


## CVE-2022-30190
Please see the MSRC Blog Entry for important information about steps you can take to protect your system from this vulnerability.

- [https://github.com/Dhananjayasj/CVE-2022-30190-Follina-](https://github.com/Dhananjayasj/CVE-2022-30190-Follina-) :  ![starts](https://img.shields.io/github/stars/Dhananjayasj/CVE-2022-30190-Follina-.svg) ![forks](https://img.shields.io/github/forks/Dhananjayasj/CVE-2022-30190-Follina-.svg)


## CVE-2022-1026
 Kyocera multifunction printers running vulnerable versions of Net View unintentionally expose sensitive user information, including usernames and passwords, through an insufficiently protected address book export function.

- [https://github.com/sh94ya/kyocera_cve_2022_1026](https://github.com/sh94ya/kyocera_cve_2022_1026) :  ![starts](https://img.shields.io/github/stars/sh94ya/kyocera_cve_2022_1026.svg) ![forks](https://img.shields.io/github/forks/sh94ya/kyocera_cve_2022_1026.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/wolf1892/CVE-2021-41773](https://github.com/wolf1892/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/wolf1892/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/wolf1892/CVE-2021-41773.svg)


## CVE-2021-21220
 Insufficient validation of untrusted input in V8 in Google Chrome prior to 89.0.4389.128 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

- [https://github.com/JacobTaylor3/Docker-Lab-Milestone-3](https://github.com/JacobTaylor3/Docker-Lab-Milestone-3) :  ![starts](https://img.shields.io/github/stars/JacobTaylor3/Docker-Lab-Milestone-3.svg) ![forks](https://img.shields.io/github/forks/JacobTaylor3/Docker-Lab-Milestone-3.svg)
- [https://github.com/borahll/CVE-2021-21220](https://github.com/borahll/CVE-2021-21220) :  ![starts](https://img.shields.io/github/stars/borahll/CVE-2021-21220.svg) ![forks](https://img.shields.io/github/forks/borahll/CVE-2021-21220.svg)


## CVE-2020-1938
 When using the Apache JServ Protocol (AJP), care must be taken when trusting incoming connections to Apache Tomcat. Tomcat treats AJP connections as having higher trust than, for example, a similar HTTP connection. If such connections are available to an attacker, they can be exploited in ways that may be surprising. In Apache Tomcat 9.0.0.M1 to 9.0.0.30, 8.5.0 to 8.5.50 and 7.0.0 to 7.0.99, Tomcat shipped with an AJP Connector enabled by default that listened on all configured IP addresses. It was expected (and recommended in the security guide) that this Connector would be disabled if not required. This vulnerability report identified a mechanism that allowed: - returning arbitrary files from anywhere in the web application - processing any file in the web application as a JSP Further, if the web application allowed file upload and stored those files within the web application (or the attacker was able to control the content of the web application by some other means) then this, along with the ability to process a file as a JSP, made remote code execution possible. It is important to note that mitigation is only required if an AJP port is accessible to untrusted users. Users wishing to take a defence-in-depth approach and block the vector that permits returning arbitrary files and execution as JSP may upgrade to Apache Tomcat 9.0.31, 8.5.51 or 7.0.100 or later. A number of changes were made to the default AJP Connector configuration in 9.0.31 to harden the default configuration. It is likely that users upgrading to 9.0.31, 8.5.51 or 7.0.100 or later will need to make small changes to their configurations.

- [https://github.com/si1ence90/Ghostcat-Tomcat-AJP-Exploit-Py3](https://github.com/si1ence90/Ghostcat-Tomcat-AJP-Exploit-Py3) :  ![starts](https://img.shields.io/github/stars/si1ence90/Ghostcat-Tomcat-AJP-Exploit-Py3.svg) ![forks](https://img.shields.io/github/forks/si1ence90/Ghostcat-Tomcat-AJP-Exploit-Py3.svg)


## CVE-2019-10149
 A flaw was found in Exim versions 4.87 to 4.91 (inclusive). Improper validation of recipient address in deliver_message() function in /src/deliver.c may lead to remote command execution.

- [https://github.com/Ambrella-Security/CVE-2019-10149](https://github.com/Ambrella-Security/CVE-2019-10149) :  ![starts](https://img.shields.io/github/stars/Ambrella-Security/CVE-2019-10149.svg) ![forks](https://img.shields.io/github/forks/Ambrella-Security/CVE-2019-10149.svg)


## CVE-2015-1328
 The overlayfs implementation in the linux (aka Linux kernel) package before 3.19.0-21.21 in Ubuntu through 15.04 does not properly check permissions for file creation in the upper filesystem directory, which allows local users to obtain root access by leveraging a configuration in which overlayfs is permitted in an arbitrary mount namespace.

- [https://github.com/saqib-butt2/blackbox-pentesting-infsecos](https://github.com/saqib-butt2/blackbox-pentesting-infsecos) :  ![starts](https://img.shields.io/github/stars/saqib-butt2/blackbox-pentesting-infsecos.svg) ![forks](https://img.shields.io/github/forks/saqib-butt2/blackbox-pentesting-infsecos.svg)


## CVE-2009-3999
 Stack-based buffer overflow in goform/formExportDataLogs in HP Power Manager before 4.2.10 allows remote attackers to execute arbitrary code via a long fileName parameter.

- [https://github.com/AC8999/CVE-2009-3999-HP-Power-Manager-4.2-Build-7-Buffer-Overflow](https://github.com/AC8999/CVE-2009-3999-HP-Power-Manager-4.2-Build-7-Buffer-Overflow) :  ![starts](https://img.shields.io/github/stars/AC8999/CVE-2009-3999-HP-Power-Manager-4.2-Build-7-Buffer-Overflow.svg) ![forks](https://img.shields.io/github/forks/AC8999/CVE-2009-3999-HP-Power-Manager-4.2-Build-7-Buffer-Overflow.svg)

