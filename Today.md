# Update 2026-03-12
## CVE-2026-29786
 node-tar is a full-featured Tar for Node.js. Prior to version 7.5.10, tar can be tricked into creating a hardlink that points outside the extraction directory by using a drive-relative link target such as C:../target.txt, which enables file overwrite outside cwd during normal tar.x() extraction. This issue has been patched in version 7.5.10.

- [https://github.com/Rohitberiwala/NodeJS-Tar-Symlink-Exploit-CVE-2026-29786](https://github.com/Rohitberiwala/NodeJS-Tar-Symlink-Exploit-CVE-2026-29786) :  ![starts](https://img.shields.io/github/stars/Rohitberiwala/NodeJS-Tar-Symlink-Exploit-CVE-2026-29786.svg) ![forks](https://img.shields.io/github/forks/Rohitberiwala/NodeJS-Tar-Symlink-Exploit-CVE-2026-29786.svg)


## CVE-2026-29780
 eml_parser serves as a python module for parsing eml files and returning various information found in the e-mail as well as computed information. Prior to version 2.0.1, the official example script examples/recursively_extract_attachments.py contains a path traversal vulnerability that allows arbitrary file write outside the intended output directory. Attachment filenames extracted from parsed emails are directly used to construct output file paths without any sanitization, allowing an attacker-controlled filename to escape the target directory. This issue has been patched in version 2.0.1.

- [https://github.com/redyank/CVE-2026-29780](https://github.com/redyank/CVE-2026-29780) :  ![starts](https://img.shields.io/github/stars/redyank/CVE-2026-29780.svg) ![forks](https://img.shields.io/github/forks/redyank/CVE-2026-29780.svg)


## CVE-2026-28372
 telnetd in GNU inetutils through 2.7 allows privilege escalation that can be exploited by abusing systemd service credentials support added to the login(1) implementation of util-linux in release 2.40. This is related to client control over the CREDENTIALS_DIRECTORY environment variable, and requires an unprivileged local user to create a login.noauth file.

- [https://github.com/Rohitberiwala/CVE-2026-28372-telnetd-Privilege-Escalation](https://github.com/Rohitberiwala/CVE-2026-28372-telnetd-Privilege-Escalation) :  ![starts](https://img.shields.io/github/stars/Rohitberiwala/CVE-2026-28372-telnetd-Privilege-Escalation.svg) ![forks](https://img.shields.io/github/forks/Rohitberiwala/CVE-2026-28372-telnetd-Privilege-Escalation.svg)


## CVE-2026-27944
 Nginx UI is a web user interface for the Nginx web server. Prior to version 2.3.3, the /api/backup endpoint is accessible without authentication and discloses the encryption keys required to decrypt the backup in the X-Backup-Security response header. This allows an unauthenticated attacker to download a full system backup containing sensitive data (user credentials, session tokens, SSL private keys, Nginx configurations) and decrypt it immediately. This issue has been patched in version 2.3.3.

- [https://github.com/NULL200OK/CVE-2026-27944](https://github.com/NULL200OK/CVE-2026-27944) :  ![starts](https://img.shields.io/github/stars/NULL200OK/CVE-2026-27944.svg) ![forks](https://img.shields.io/github/forks/NULL200OK/CVE-2026-27944.svg)
- [https://github.com/weefunker/CVE-2026-27944-Lab](https://github.com/weefunker/CVE-2026-27944-Lab) :  ![starts](https://img.shields.io/github/stars/weefunker/CVE-2026-27944-Lab.svg) ![forks](https://img.shields.io/github/forks/weefunker/CVE-2026-27944-Lab.svg)
- [https://github.com/NULL200OK/-nginxui_discover](https://github.com/NULL200OK/-nginxui_discover) :  ![starts](https://img.shields.io/github/stars/NULL200OK/-nginxui_discover.svg) ![forks](https://img.shields.io/github/forks/NULL200OK/-nginxui_discover.svg)


## CVE-2026-27826
 MCP Atlassian is a Model Context Protocol (MCP) server for Atlassian products (Confluence and Jira). Prior to version 0.17.0, an unauthenticated attacker who can reach the mcp-atlassian HTTP endpoint can force the server process to make outbound HTTP requests to an arbitrary attacker-controlled URL by supplying two custom HTTP headers without an `Authorization` header. No authentication is required. The vulnerability exists in the HTTP middleware and dependency injection layer — not in any MCP tool handler - making it invisible to tool-level code analysis. In cloud deployments, this could enable theft of IAM role credentials via the instance metadata endpoint (`169[.]254[.]169[.]254`). In any HTTP deployment it enables internal network reconnaissance and injection of attacker-controlled content into LLM tool results. Version 0.17.0 fixes the issue.

- [https://github.com/plutosecurity/MCPwnfluence](https://github.com/plutosecurity/MCPwnfluence) :  ![starts](https://img.shields.io/github/stars/plutosecurity/MCPwnfluence.svg) ![forks](https://img.shields.io/github/forks/plutosecurity/MCPwnfluence.svg)


## CVE-2026-27825
 MCP Atlassian is a Model Context Protocol (MCP) server for Atlassian products (Confluence and Jira). Prior to version 0.17.0, the `confluence_download_attachment` MCP tool accepts a `download_path` parameter that is written to without any directory boundary enforcement. An attacker who can call this tool and supply or access a Confluence attachment with malicious content can write arbitrary content to any path the server process has write access to. Because the attacker controls both the write destination and the written content (via an uploaded Confluence attachment), this constitutes for arbitrary code execution (for example, writing a valid cron entry to `/etc/cron.d/` achieves code execution within one scheduler cycle with no server restart required). Version 0.17.0 fixes the issue.

- [https://github.com/plutosecurity/MCPwnfluence](https://github.com/plutosecurity/MCPwnfluence) :  ![starts](https://img.shields.io/github/stars/plutosecurity/MCPwnfluence.svg) ![forks](https://img.shields.io/github/forks/plutosecurity/MCPwnfluence.svg)


## CVE-2026-24423
 SmarterTools SmarterMail versions prior to build 9511 contain an unauthenticated remote code execution vulnerability in the ConnectToHub API method. The attacker could point the SmarterMail to the malicious HTTP server, which serves the malicious OS command. This command will be executed by the vulnerable application.

- [https://github.com/aaddmin1122345/CVE-2026-24423](https://github.com/aaddmin1122345/CVE-2026-24423) :  ![starts](https://img.shields.io/github/stars/aaddmin1122345/CVE-2026-24423.svg) ![forks](https://img.shields.io/github/forks/aaddmin1122345/CVE-2026-24423.svg)


## CVE-2026-23907
been adjusted.

- [https://github.com/JoakimBulow/CVE-2026-23907](https://github.com/JoakimBulow/CVE-2026-23907) :  ![starts](https://img.shields.io/github/stars/JoakimBulow/CVE-2026-23907.svg) ![forks](https://img.shields.io/github/forks/JoakimBulow/CVE-2026-23907.svg)


## CVE-2026-21536
 Microsoft Devices Pricing Program Remote Code Execution Vulnerability

- [https://github.com/b1gchoi/CVE-2026-21536-RCE](https://github.com/b1gchoi/CVE-2026-21536-RCE) :  ![starts](https://img.shields.io/github/stars/b1gchoi/CVE-2026-21536-RCE.svg) ![forks](https://img.shields.io/github/forks/b1gchoi/CVE-2026-21536-RCE.svg)


## CVE-2026-3847
 Memory safety bugs present in Firefox 148.0.2. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some of these could have been exploited to run arbitrary code. This vulnerability affects Firefox  148.0.2.

- [https://github.com/HiZisec/CVE-2026-3847-Poc](https://github.com/HiZisec/CVE-2026-3847-Poc) :  ![starts](https://img.shields.io/github/stars/HiZisec/CVE-2026-3847-Poc.svg) ![forks](https://img.shields.io/github/forks/HiZisec/CVE-2026-3847-Poc.svg)


## CVE-2026-3288
 A security issue was discovered in ingress-nginx where the `nginx.ingress.kubernetes.io/rewrite-target` Ingress annotation can be used to inject configuration into nginx. This can lead to arbitrary code execution in the context of the ingress-nginx controller, and disclosure of Secrets accessible to the controller. (Note that in the default installation, the controller can access all Secrets cluster-wide.)

- [https://github.com/SnailSploit/CVE-2026-3288](https://github.com/SnailSploit/CVE-2026-3288) :  ![starts](https://img.shields.io/github/stars/SnailSploit/CVE-2026-3288.svg) ![forks](https://img.shields.io/github/forks/SnailSploit/CVE-2026-3288.svg)


## CVE-2026-2472
 Stored Cross-Site Scripting (XSS) in the _genai/_evals_visualization component of Google Cloud Vertex AI SDK (google-cloud-aiplatform) versions from 1.98.0 up to (but not including) 1.131.0 allows an unauthenticated remote attacker to execute arbitrary JavaScript in a victim's Jupyter or Colab environment via injecting script escape sequences into model evaluation results or dataset JSON data.

- [https://github.com/megafart1/CVE-2026-2472-Vertex-AI-SDK-Google-Cloud](https://github.com/megafart1/CVE-2026-2472-Vertex-AI-SDK-Google-Cloud) :  ![starts](https://img.shields.io/github/stars/megafart1/CVE-2026-2472-Vertex-AI-SDK-Google-Cloud.svg) ![forks](https://img.shields.io/github/forks/megafart1/CVE-2026-2472-Vertex-AI-SDK-Google-Cloud.svg)


## CVE-2026-1550
 A security flaw has been discovered in PHPGurukul Hospital Management System 1.0. Affected by this issue is some unknown functionality of the file /hms/hospital/docappsystem/adminviews.py of the component Admin Dashboard Page. Performing a manipulation results in improper authorization. Remote exploitation of the attack is possible. The exploit has been released to the public and may be used for attacks.

- [https://github.com/rsecroot/CVE-2026-1550](https://github.com/rsecroot/CVE-2026-1550) :  ![starts](https://img.shields.io/github/stars/rsecroot/CVE-2026-1550.svg) ![forks](https://img.shields.io/github/forks/rsecroot/CVE-2026-1550.svg)


## CVE-2026-1492
 The User Registration & Membership – Custom Registration Form Builder, Custom Login Form, User Profile, Content Restriction & Membership Plugin plugin for WordPress is vulnerable to improper privilege management in all versions up to, and including, 5.1.2. This is due to the plugin accepting a user-supplied role during membership registration without properly enforcing a server-side allowlist. This makes it possible for unauthenticated attackers to create administrator accounts by supplying a role value during membership registration.

- [https://github.com/DeadExpl0it/CVE-2026-1492](https://github.com/DeadExpl0it/CVE-2026-1492) :  ![starts](https://img.shields.io/github/stars/DeadExpl0it/CVE-2026-1492.svg) ![forks](https://img.shields.io/github/forks/DeadExpl0it/CVE-2026-1492.svg)


## CVE-2026-1424
 A vulnerability was identified in PHPGurukul News Portal 1.0. This affects an unknown part of the component Profile Pic Handler. The manipulation leads to unrestricted upload. It is possible to initiate the attack remotely. The exploit is publicly available and might be used.

- [https://github.com/rsecroot/CVE-2026-1424](https://github.com/rsecroot/CVE-2026-1424) :  ![starts](https://img.shields.io/github/stars/rsecroot/CVE-2026-1424.svg) ![forks](https://img.shields.io/github/forks/rsecroot/CVE-2026-1424.svg)


## CVE-2026-1357
 The Migration, Backup, Staging – WPvivid Backup & Migration plugin for WordPress is vulnerable to Unauthenticated Arbitrary File Upload in versions up to and including 0.9.123. This is due to improper error handling in the RSA decryption process combined with a lack of path sanitization when writing uploaded files. When the plugin fails to decrypt a session key using openssl_private_decrypt(), it does not terminate execution and instead passes the boolean false value to the phpseclib library's AES cipher initialization. The library treats this false value as a string of null bytes, allowing an attacker to encrypt a malicious payload using a predictable null-byte key. Additionally, the plugin accepts filenames from the decrypted payload without sanitization, enabling directory traversal to escape the protected backup directory. This makes it possible for unauthenticated attackers to upload arbitrary PHP files to publicly accessible directories and achieve Remote Code Execution via the wpvivid_action=send_to_site parameter.

- [https://github.com/Nxploited/CVE-2026-1357](https://github.com/Nxploited/CVE-2026-1357) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2026-1357.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2026-1357.svg)


## CVE-2026-0730
 A flaw has been found in PHPGurukul Staff Leave Management System 1.0. The affected element is the function ADD_STAFF/UPDATE_STAFF of the file /staffleave/slms/slms/adminviews.py of the component SVG File Handler. Executing a manipulation of the argument profile_pic can lead to cross site scripting. The attack can be executed remotely. The exploit has been published and may be used.

- [https://github.com/rsecroot/CVE-2026-0730](https://github.com/rsecroot/CVE-2026-0730) :  ![starts](https://img.shields.io/github/stars/rsecroot/CVE-2026-0730.svg) ![forks](https://img.shields.io/github/forks/rsecroot/CVE-2026-0730.svg)


## CVE-2026-0709
 Some Hikvision Wireless Access Points are vulnerable to authenticated command execution due to insufficient input validation. Attackers with valid credentials can exploit this flaw by sending crafted packets containing malicious commands to affected devices, leading to arbitrary command execution.

- [https://github.com/SnipersMaster/CVE-2026-0709](https://github.com/SnipersMaster/CVE-2026-0709) :  ![starts](https://img.shields.io/github/stars/SnipersMaster/CVE-2026-0709.svg) ![forks](https://img.shields.io/github/forks/SnipersMaster/CVE-2026-0709.svg)


## CVE-2025-69219
You should upgrade to version 6.0.0 of the provider to avoid even that risk.

- [https://github.com/sak110/CVE-2025-69219](https://github.com/sak110/CVE-2025-69219) :  ![starts](https://img.shields.io/github/stars/sak110/CVE-2025-69219.svg) ![forks](https://img.shields.io/github/forks/sak110/CVE-2025-69219.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions.svg)


## CVE-2025-66398
 Signal K Server is a server application that runs on a central hub in a boat. Prior to version 2.19.0, an unauthenticated attacker can pollute the internal state (`restoreFilePath`) of the server via the `/skServer/validateBackup` endpoint. This allows the attacker to hijack the administrator's "Restore" functionality to overwrite critical server configuration files (e.g., `security.json`, `package.json`), leading to account takeover and Remote Code Execution (RCE). Version 2.19.0 patches this vulnerability.

- [https://github.com/joshuavanderpoll/cve-2025-66398](https://github.com/joshuavanderpoll/cve-2025-66398) :  ![starts](https://img.shields.io/github/stars/joshuavanderpoll/cve-2025-66398.svg) ![forks](https://img.shields.io/github/forks/joshuavanderpoll/cve-2025-66398.svg)


## CVE-2025-60739
 Cross Site Request Forgery (CSRF) vulnerability in Ilevia EVE X1 Server Firmware Version v4.7.18.0.eden and before, Logic Version v6.00 - 2025_07_21 allows a remote attacker to execute arbitrary code via the /bh_web_backend component

- [https://github.com/GadaLuBau1337/CVE-2025-60739](https://github.com/GadaLuBau1337/CVE-2025-60739) :  ![starts](https://img.shields.io/github/stars/GadaLuBau1337/CVE-2025-60739.svg) ![forks](https://img.shields.io/github/forks/GadaLuBau1337/CVE-2025-60739.svg)


## CVE-2025-59536
 Claude Code is an agentic coding tool. Versions before 1.0.111 were vulnerable to Code Injection due to a bug in the startup trust dialog implementation. Claude Code could be tricked to execute code contained in a project before the user accepted the startup trust dialog. Exploiting this requires a user to start Claude Code in an untrusted directory. Users on standard Claude Code auto-update will have received this fix automatically. Users performing manual updates are advised to update to the latest version. This issue is fixed in version 1.0.111.

- [https://github.com/Rohitberiwala/Claude-Code-MCP-Injection-PoC](https://github.com/Rohitberiwala/Claude-Code-MCP-Injection-PoC) :  ![starts](https://img.shields.io/github/stars/Rohitberiwala/Claude-Code-MCP-Injection-PoC.svg) ![forks](https://img.shields.io/github/forks/Rohitberiwala/Claude-Code-MCP-Injection-PoC.svg)


## CVE-2025-36911
 In key-based pairing, there is a possible ID due to a logic error in the code. This could lead to remote (proximal/adjacent) information disclosure of user's conversations and location with no additional execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/Athexblackhat/BLUE-SPY](https://github.com/Athexblackhat/BLUE-SPY) :  ![starts](https://img.shields.io/github/stars/Athexblackhat/BLUE-SPY.svg) ![forks](https://img.shields.io/github/forks/Athexblackhat/BLUE-SPY.svg)


## CVE-2025-27136
 LocalS3 is an Amazon S3 mock service for testing and local development. Prior to version 1.21, the LocalS3 service's bucket creation endpoint is vulnerable to XML External Entity (XXE) injection. When processing the CreateBucketConfiguration XML document during bucket creation, the service's XML parser is configured to resolve external entities. This allows an attacker to declare an external entity that references an internal URL, which the server will then attempt to fetch when parsing the XML. The vulnerability specifically occurs in the location constraint processing, where the XML parser resolves external entities without proper validation or restrictions. When the external entity is resolved, the server makes an HTTP request to the specified URL and includes the response content in the parsed XML document. This vulnerability can be exploited to perform server-side request forgery (SSRF) attacks, allowing an attacker to make requests to internal services or resources that should not be accessible from external networks. The server will include the responses from these internal requests in the resulting bucket configuration, effectively leaking sensitive information. The attacker only needs to be able to send HTTP requests to the LocalS3 service to exploit this vulnerability.

- [https://github.com/IssaBoudin/CVE-2025-27136](https://github.com/IssaBoudin/CVE-2025-27136) :  ![starts](https://img.shields.io/github/stars/IssaBoudin/CVE-2025-27136.svg) ![forks](https://img.shields.io/github/forks/IssaBoudin/CVE-2025-27136.svg)


## CVE-2025-13465
This issue is patched on 4.17.23

- [https://github.com/jaytarr-geo/nextjs-lodash-cve-2025-13465-repro](https://github.com/jaytarr-geo/nextjs-lodash-cve-2025-13465-repro) :  ![starts](https://img.shields.io/github/stars/jaytarr-geo/nextjs-lodash-cve-2025-13465-repro.svg) ![forks](https://img.shields.io/github/forks/jaytarr-geo/nextjs-lodash-cve-2025-13465-repro.svg)


## CVE-2024-51482
 ZoneMinder is a free, open source closed-circuit television software application. ZoneMinder v1.37.* = 1.37.64 is vulnerable to boolean-based SQL Injection in function of web/ajax/event.php. This is fixed in 1.37.65.

- [https://github.com/lnn0v4/sqli-hunter-CVE-2024-51482-PoC](https://github.com/lnn0v4/sqli-hunter-CVE-2024-51482-PoC) :  ![starts](https://img.shields.io/github/stars/lnn0v4/sqli-hunter-CVE-2024-51482-PoC.svg) ![forks](https://img.shields.io/github/forks/lnn0v4/sqli-hunter-CVE-2024-51482-PoC.svg)


## CVE-2024-27198
 In JetBrains TeamCity before 2023.11.4 authentication bypass allowing to perform admin actions was possible

- [https://github.com/dbwlsdnr95/CVE-2024-27198](https://github.com/dbwlsdnr95/CVE-2024-27198) :  ![starts](https://img.shields.io/github/stars/dbwlsdnr95/CVE-2024-27198.svg) ![forks](https://img.shields.io/github/forks/dbwlsdnr95/CVE-2024-27198.svg)


## CVE-2024-4577
 In PHP versions 8.1.* before 8.1.29, 8.2.* before 8.2.20, 8.3.* before 8.3.8, when using Apache and PHP-CGI on Windows, if the system is set up to use certain code pages, Windows may use "Best-Fit" behavior to replace characters in command line given to Win32 API functions. PHP CGI module may misinterpret those characters as PHP options, which may allow a malicious user to pass options to PHP binary being run, and thus reveal the source code of scripts, run arbitrary PHP code on the server, etc.

- [https://github.com/aaddmin1122345/cve-2024-4577](https://github.com/aaddmin1122345/cve-2024-4577) :  ![starts](https://img.shields.io/github/stars/aaddmin1122345/cve-2024-4577.svg) ![forks](https://img.shields.io/github/forks/aaddmin1122345/cve-2024-4577.svg)


## CVE-2024-0044
 In createSessionInternal of PackageInstallerService.java, there is a possible run-as any app due to improper input validation. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/Athexblackhat/EXPLOITER](https://github.com/Athexblackhat/EXPLOITER) :  ![starts](https://img.shields.io/github/stars/Athexblackhat/EXPLOITER.svg) ![forks](https://img.shields.io/github/forks/Athexblackhat/EXPLOITER.svg)


## CVE-2022-31898
 gl-inet GL-MT300N-V2 Mango v3.212 and GL-AX1800 Flint v3.214 were discovered to contain multiple command injection vulnerabilities via the ping_addr and trace_addr function parameters.

- [https://github.com/CryptoGhost1/MangoPunch-CVE-2022-31898](https://github.com/CryptoGhost1/MangoPunch-CVE-2022-31898) :  ![starts](https://img.shields.io/github/stars/CryptoGhost1/MangoPunch-CVE-2022-31898.svg) ![forks](https://img.shields.io/github/forks/CryptoGhost1/MangoPunch-CVE-2022-31898.svg)


## CVE-2019-10068
 An issue was discovered in Kentico 12.0.x before 12.0.15, 11.0.x before 11.0.48, 10.0.x before 10.0.52, and 9.x versions. Due to a failure to validate security headers, it was possible for a specially crafted request to the staging service to bypass the initial authentication and proceed to deserialize user-controlled .NET object input. This deserialization then led to unauthenticated remote code execution on the server where the Kentico instance was hosted.

- [https://github.com/cianananan/CVE-2019-10068-PoC](https://github.com/cianananan/CVE-2019-10068-PoC) :  ![starts](https://img.shields.io/github/stars/cianananan/CVE-2019-10068-PoC.svg) ![forks](https://img.shields.io/github/forks/cianananan/CVE-2019-10068-PoC.svg)


## CVE-2017-15220
 Flexense VX Search Enterprise 10.1.12 is vulnerable to a buffer overflow via an empty POST request to a long URI beginning with a /../ substring. This allows remote attackers to execute arbitrary code.

- [https://github.com/vasilerevnic/CVE-2017-15220-vxsearch-rce](https://github.com/vasilerevnic/CVE-2017-15220-vxsearch-rce) :  ![starts](https://img.shields.io/github/stars/vasilerevnic/CVE-2017-15220-vxsearch-rce.svg) ![forks](https://img.shields.io/github/forks/vasilerevnic/CVE-2017-15220-vxsearch-rce.svg)


## CVE-2017-12615
 When running Apache Tomcat 7.0.0 to 7.0.79 on Windows with HTTP PUTs enabled (e.g. via setting the readonly initialisation parameter of the Default to false) it was possible to upload a JSP file to the server via a specially crafted request. This JSP could then be requested and any code it contained would be executed by the server.

- [https://github.com/lizhianyuguangming/TomcatScanPro](https://github.com/lizhianyuguangming/TomcatScanPro) :  ![starts](https://img.shields.io/github/stars/lizhianyuguangming/TomcatScanPro.svg) ![forks](https://img.shields.io/github/forks/lizhianyuguangming/TomcatScanPro.svg)
- [https://github.com/tpt11fb/AttackTomcat](https://github.com/tpt11fb/AttackTomcat) :  ![starts](https://img.shields.io/github/stars/tpt11fb/AttackTomcat.svg) ![forks](https://img.shields.io/github/forks/tpt11fb/AttackTomcat.svg)
- [https://github.com/breaktoprotect/CVE-2017-12615](https://github.com/breaktoprotect/CVE-2017-12615) :  ![starts](https://img.shields.io/github/stars/breaktoprotect/CVE-2017-12615.svg) ![forks](https://img.shields.io/github/forks/breaktoprotect/CVE-2017-12615.svg)
- [https://github.com/mefulton/cve-2017-12615](https://github.com/mefulton/cve-2017-12615) :  ![starts](https://img.shields.io/github/stars/mefulton/cve-2017-12615.svg) ![forks](https://img.shields.io/github/forks/mefulton/cve-2017-12615.svg)
- [https://github.com/xiaokp7/Tomcat_PUT_GUI_EXP](https://github.com/xiaokp7/Tomcat_PUT_GUI_EXP) :  ![starts](https://img.shields.io/github/stars/xiaokp7/Tomcat_PUT_GUI_EXP.svg) ![forks](https://img.shields.io/github/forks/xiaokp7/Tomcat_PUT_GUI_EXP.svg)
- [https://github.com/zi0Black/POC-CVE-2017-12615-or-CVE-2017-12717](https://github.com/zi0Black/POC-CVE-2017-12615-or-CVE-2017-12717) :  ![starts](https://img.shields.io/github/stars/zi0Black/POC-CVE-2017-12615-or-CVE-2017-12717.svg) ![forks](https://img.shields.io/github/forks/zi0Black/POC-CVE-2017-12615-or-CVE-2017-12717.svg)
- [https://github.com/1337g/CVE-2017-12615](https://github.com/1337g/CVE-2017-12615) :  ![starts](https://img.shields.io/github/stars/1337g/CVE-2017-12615.svg) ![forks](https://img.shields.io/github/forks/1337g/CVE-2017-12615.svg)
- [https://github.com/wsg00d/cve-2017-12615](https://github.com/wsg00d/cve-2017-12615) :  ![starts](https://img.shields.io/github/stars/wsg00d/cve-2017-12615.svg) ![forks](https://img.shields.io/github/forks/wsg00d/cve-2017-12615.svg)
- [https://github.com/BeyondCy/CVE-2017-12615](https://github.com/BeyondCy/CVE-2017-12615) :  ![starts](https://img.shields.io/github/stars/BeyondCy/CVE-2017-12615.svg) ![forks](https://img.shields.io/github/forks/BeyondCy/CVE-2017-12615.svg)
- [https://github.com/ianxtianxt/CVE-2017-12615](https://github.com/ianxtianxt/CVE-2017-12615) :  ![starts](https://img.shields.io/github/stars/ianxtianxt/CVE-2017-12615.svg) ![forks](https://img.shields.io/github/forks/ianxtianxt/CVE-2017-12615.svg)
- [https://github.com/w0x68y/CVE-2017-12615-EXP](https://github.com/w0x68y/CVE-2017-12615-EXP) :  ![starts](https://img.shields.io/github/stars/w0x68y/CVE-2017-12615-EXP.svg) ![forks](https://img.shields.io/github/forks/w0x68y/CVE-2017-12615-EXP.svg)
- [https://github.com/cved-sources/cve-2017-12615](https://github.com/cved-sources/cve-2017-12615) :  ![starts](https://img.shields.io/github/stars/cved-sources/cve-2017-12615.svg) ![forks](https://img.shields.io/github/forks/cved-sources/cve-2017-12615.svg)
- [https://github.com/Fa1c0n35/CVE-2017-12615](https://github.com/Fa1c0n35/CVE-2017-12615) :  ![starts](https://img.shields.io/github/stars/Fa1c0n35/CVE-2017-12615.svg) ![forks](https://img.shields.io/github/forks/Fa1c0n35/CVE-2017-12615.svg)
- [https://github.com/Shellkeys/CVE-2017-12615](https://github.com/Shellkeys/CVE-2017-12615) :  ![starts](https://img.shields.io/github/stars/Shellkeys/CVE-2017-12615.svg) ![forks](https://img.shields.io/github/forks/Shellkeys/CVE-2017-12615.svg)
- [https://github.com/cyberharsh/Tomcat-CVE-2017-12615](https://github.com/cyberharsh/Tomcat-CVE-2017-12615) :  ![starts](https://img.shields.io/github/stars/cyberharsh/Tomcat-CVE-2017-12615.svg) ![forks](https://img.shields.io/github/forks/cyberharsh/Tomcat-CVE-2017-12615.svg)
- [https://github.com/wudidwo/CVE-2017-12615-poc](https://github.com/wudidwo/CVE-2017-12615-poc) :  ![starts](https://img.shields.io/github/stars/wudidwo/CVE-2017-12615-poc.svg) ![forks](https://img.shields.io/github/forks/wudidwo/CVE-2017-12615-poc.svg)
- [https://github.com/netw0rk7/CVE-2017-12615-Home-Lab](https://github.com/netw0rk7/CVE-2017-12615-Home-Lab) :  ![starts](https://img.shields.io/github/stars/netw0rk7/CVE-2017-12615-Home-Lab.svg) ![forks](https://img.shields.io/github/forks/netw0rk7/CVE-2017-12615-Home-Lab.svg)
- [https://github.com/edyekomu/CVE-2017-12615-PoC](https://github.com/edyekomu/CVE-2017-12615-PoC) :  ![starts](https://img.shields.io/github/stars/edyekomu/CVE-2017-12615-PoC.svg) ![forks](https://img.shields.io/github/forks/edyekomu/CVE-2017-12615-PoC.svg)


## CVE-2015-9235
 In jsonwebtoken node module before 4.2.2 it is possible for an attacker to bypass verification when a token digitally signed with an asymmetric key (RS/ES family) of algorithms but instead the attacker send a token digitally signed with a symmetric algorithm (HS* family).

- [https://github.com/tierChampion/POC_CVE-2015-9235](https://github.com/tierChampion/POC_CVE-2015-9235) :  ![starts](https://img.shields.io/github/stars/tierChampion/POC_CVE-2015-9235.svg) ![forks](https://img.shields.io/github/forks/tierChampion/POC_CVE-2015-9235.svg)


## CVE-2014-6287
 The findMacroMarker function in parserLib.pas in Rejetto HTTP File Server (aks HFS or HttpFileServer) 2.3x before 2.3c allows remote attackers to execute arbitrary programs via a %00 sequence in a search action.

- [https://github.com/R3fr4kt/Optimum](https://github.com/R3fr4kt/Optimum) :  ![starts](https://img.shields.io/github/stars/R3fr4kt/Optimum.svg) ![forks](https://img.shields.io/github/forks/R3fr4kt/Optimum.svg)


## CVE-2007-2447
 The MS-RPC functionality in smbd in Samba 3.0.0 through 3.0.25rc3 allows remote attackers to execute arbitrary commands via shell metacharacters involving the (1) SamrChangePassword function, when the "username map script" smb.conf option is enabled, and allows remote authenticated users to execute commands via shell metacharacters involving other MS-RPC functions in the (2) remote printer and (3) file share management.

- [https://github.com/vig9610/Exploiting-Samba-on-Metasploitable-2](https://github.com/vig9610/Exploiting-Samba-on-Metasploitable-2) :  ![starts](https://img.shields.io/github/stars/vig9610/Exploiting-Samba-on-Metasploitable-2.svg) ![forks](https://img.shields.io/github/forks/vig9610/Exploiting-Samba-on-Metasploitable-2.svg)

