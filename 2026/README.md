## CVE-2026-27180
 MajorDoMo (aka Major Domestic Module) is vulnerable to unauthenticated remote code execution through supply chain compromise via update URL poisoning. The saverestore module exposes its admin() method through the /objects/?module=saverestore endpoint without authentication because it uses gr('mode') (which reads directly from $_REQUEST) instead of the framework's $this-mode. An attacker can poison the system update URL via the auto_update_settings mode handler, then trigger the force_update handler to initiate the update chain. The autoUpdateSystem() method fetches an Atom feed from the attacker-controlled URL with trivial validation, downloads a tarball via curl with TLS verification disabled (CURLOPT_SSL_VERIFYPEER set to FALSE), extracts it using exec('tar xzvf ...'), and copies all extracted files to the document root using copyTree(). This allows an attacker to deploy arbitrary PHP files, including webshells, to the webroot with two GET requests.



- [https://github.com/mbanyamer/CVE-2026-27180-MajorDoMo-unauthenticated-RCE](https://github.com/mbanyamer/CVE-2026-27180-MajorDoMo-unauthenticated-RCE) :  ![starts](https://img.shields.io/github/stars/mbanyamer/CVE-2026-27180-MajorDoMo-unauthenticated-RCE.svg) ![forks](https://img.shields.io/github/forks/mbanyamer/CVE-2026-27180-MajorDoMo-unauthenticated-RCE.svg)

## CVE-2026-26988
 LibreNMS is an auto-discovering PHP/MySQL/SNMP based network monitoring tool. Versions 25.12.0 and below contain an SQL Injection vulnerability in the ajax_table.php endpoint. The application fails to properly sanitize or parameterize user input when processing IPv6 address searches. Specifically, the address parameter is split into an address and a prefix, and the prefix portion is directly concatenated into the SQL query string without validation. This allows an attacker to inject arbitrary SQL commands, potentially leading to unauthorized data access or database manipulation. This issue has been fixed in version 26.2.0.



- [https://github.com/mbanyamer/CVE-2026-26988-LibreNMS-SQLi](https://github.com/mbanyamer/CVE-2026-26988-LibreNMS-SQLi) :  ![starts](https://img.shields.io/github/stars/mbanyamer/CVE-2026-26988-LibreNMS-SQLi.svg) ![forks](https://img.shields.io/github/forks/mbanyamer/CVE-2026-26988-LibreNMS-SQLi.svg)

## CVE-2026-26746
 OpenSourcePOS 3.4.1 contains a Local File Inclusion (LFI) vulnerability in the Sales.php::getInvoice() function. An attacker can read arbitrary files on the web server by manipulating the Invoice Type configuration. This issue can be chained with the file upload functionality to achieve Remote Code Execution (RCE).



- [https://github.com/hungnqdz/CVE-2026-26746](https://github.com/hungnqdz/CVE-2026-26746) :  ![starts](https://img.shields.io/github/stars/hungnqdz/CVE-2026-26746.svg) ![forks](https://img.shields.io/github/forks/hungnqdz/CVE-2026-26746.svg)

## CVE-2026-26744
 A user enumeration vulnerability exists in FormaLMS 4.1.18 and below in the password recovery functionality accessible via the /lostpwd endpoint. The application returns different error messages for valid and invalid usernames allowing an unauthenticated attacker to determine which usernames are registered in the system through observable response discrepancy.



- [https://github.com/lorenzobruno7/CVE-2026-26744](https://github.com/lorenzobruno7/CVE-2026-26744) :  ![starts](https://img.shields.io/github/stars/lorenzobruno7/CVE-2026-26744.svg) ![forks](https://img.shields.io/github/forks/lorenzobruno7/CVE-2026-26744.svg)

## CVE-2026-26335
 Calero VeraSMART versions prior to 2022 R1 use static ASP.NET/IIS machineKey values configured for the VeraSMART web application and stored in C:\\Program Files (x86)\\Veramark\\VeraSMART\\WebRoot\\web.config. An attacker who obtains these keys can craft a valid ASP.NET ViewState payload that passes integrity validation and is accepted by the application, resulting in server-side deserialization and remote code execution in the context of the IIS application.



- [https://github.com/mbanyamer/CVE-2026-26335-Calero-VeraSMART-RCE](https://github.com/mbanyamer/CVE-2026-26335-Calero-VeraSMART-RCE) :  ![starts](https://img.shields.io/github/stars/mbanyamer/CVE-2026-26335-Calero-VeraSMART-RCE.svg) ![forks](https://img.shields.io/github/forks/mbanyamer/CVE-2026-26335-Calero-VeraSMART-RCE.svg)

## CVE-2026-26235
 JUNG Smart Visu Server 1.1.1050 contains a denial of service vulnerability that allows unauthenticated attackers to remotely shutdown or reboot the server. Attackers can send a single POST request to trigger the server reboot without requiring any authentication.



- [https://github.com/mbanyamer/CVE-2026-26235-JUNG-Smart-Visu-Server-Unauthenticated-Reboot-Shutdown](https://github.com/mbanyamer/CVE-2026-26235-JUNG-Smart-Visu-Server-Unauthenticated-Reboot-Shutdown) :  ![starts](https://img.shields.io/github/stars/mbanyamer/CVE-2026-26235-JUNG-Smart-Visu-Server-Unauthenticated-Reboot-Shutdown.svg) ![forks](https://img.shields.io/github/forks/mbanyamer/CVE-2026-26235-JUNG-Smart-Visu-Server-Unauthenticated-Reboot-Shutdown.svg)

## CVE-2026-26221
 Hyland OnBase contains an unauthenticated .NET Remoting exposure in the OnBase Workflow Timer Service (Hyland.Core.Workflow.NTService.exe). An attacker who can reach the service can send crafted .NET Remoting requests to default HTTP channel endpoints on TCP/8900 (e.g., TimerServiceAPI.rem and TimerServiceEvents.rem for Workflow) to trigger unsafe object unmarshalling, enabling arbitrary file read/write. By writing attacker-controlled content into web-accessible locations or chaining with other OnBase features, this can lead to remote code execution. The same primitive can be abused by supplying a UNC path to coerce outbound NTLM authentication (SMB coercion) to an attacker-controlled host.



- [https://github.com/mbanyamer/CVE-2026-26221-Hyland-OnBase-Timer-Service-Unauthenticated-RCE](https://github.com/mbanyamer/CVE-2026-26221-Hyland-OnBase-Timer-Service-Unauthenticated-RCE) :  ![starts](https://img.shields.io/github/stars/mbanyamer/CVE-2026-26221-Hyland-OnBase-Timer-Service-Unauthenticated-RCE.svg) ![forks](https://img.shields.io/github/forks/mbanyamer/CVE-2026-26221-Hyland-OnBase-Timer-Service-Unauthenticated-RCE.svg)

## CVE-2026-26215
 manga-image-translator version beta-0.3 and prior in shared API mode contains an unsafe deserialization vulnerability that can lead to unauthenticated remote code execution. The FastAPI endpoints /simple_execute/{method} and /execute/{method} deserialize attacker-controlled request bodies using pickle.loads() without validation. Although a nonce-based authorization check is intended to restrict access, the nonce defaults to an empty string and the check is skipped, allowing remote attackers to execute arbitrary code in the server context by sending a crafted pickle payload.



- [https://github.com/mbanyamer/-CVE-2026-26215-manga-image-translator-RCE](https://github.com/mbanyamer/-CVE-2026-26215-manga-image-translator-RCE) :  ![starts](https://img.shields.io/github/stars/mbanyamer/-CVE-2026-26215-manga-image-translator-RCE.svg) ![forks](https://img.shields.io/github/forks/mbanyamer/-CVE-2026-26215-manga-image-translator-RCE.svg)

## CVE-2026-26012
 vaultwarden is an unofficial Bitwarden compatible server written in Rust, formerly known as bitwarden_rs. Prior to 1.35.3, a regular organization member can retrieve all ciphers within an organization, regardless of collection permissions. The endpoint /ciphers/organization-details is accessible to any organization member and internally uses Cipher::find_by_org to retrieve all ciphers. These ciphers are returned with CipherSyncType::Organization without enforcing collection-level access control. This vulnerability is fixed in 1.35.3.



- [https://github.com/Dulieno/CVE-2026-26012](https://github.com/Dulieno/CVE-2026-26012) :  ![starts](https://img.shields.io/github/stars/Dulieno/CVE-2026-26012.svg) ![forks](https://img.shields.io/github/forks/Dulieno/CVE-2026-26012.svg)

- [https://github.com/diegobaelen/CVE-2026-26012](https://github.com/diegobaelen/CVE-2026-26012) :  ![starts](https://img.shields.io/github/stars/diegobaelen/CVE-2026-26012.svg) ![forks](https://img.shields.io/github/forks/diegobaelen/CVE-2026-26012.svg)

## CVE-2026-25991
 Tandoor Recipes is an application for managing recipes, planning meals, and building shopping lists. Prior to 2.5.1, there is a Blind Server-Side Request Forgery (SSRF) vulnerability in the Cookmate recipe import feature of Tandoor Recipes. The application fails to validate the destination URL after following HTTP redirects, allowing any authenticated user (including standard users without administrative privileges) to force the server to connect to arbitrary internal or external resources. The vulnerability lies in cookbook/integration/cookmate.py, within the Cookmate integration class. This vulnerability can be leveraged to scan internal network ports, access cloud instance metadata (e.g., AWS/GCP Metadata Service), or disclose the server's real IP address. This vulnerability is fixed in 2.5.1.



- [https://github.com/drkim-dev/CVE-2026-25991](https://github.com/drkim-dev/CVE-2026-25991) :  ![starts](https://img.shields.io/github/stars/drkim-dev/CVE-2026-25991.svg) ![forks](https://img.shields.io/github/forks/drkim-dev/CVE-2026-25991.svg)

## CVE-2026-25964
 Tandoor Recipes is an application for managing recipes, planning meals, and building shopping lists. Prior to 2.5.1, a Path Traversal vulnerability in the RecipeImport workflow of Tandoor Recipes allows authenticated users with import permissions to read arbitrary files on the server. This vulnerability stems from a lack of input validation in the file_path parameter and insufficient checks in the Local storage backend, enabling an attacker to bypass storage directory restrictions and access sensitive system files (e.g., /etc/passwd) or application configuration files (e.g., settings.py), potentially leading to full system compromise. This vulnerability is fixed in 2.5.1.



- [https://github.com/drkim-dev/CVE-2026-25964](https://github.com/drkim-dev/CVE-2026-25964) :  ![starts](https://img.shields.io/github/stars/drkim-dev/CVE-2026-25964.svg) ![forks](https://img.shields.io/github/forks/drkim-dev/CVE-2026-25964.svg)

## CVE-2026-25961
 SumatraPDF is a multi-format reader for Windows. In 3.5.0 through 3.5.2, SumatraPDF's update mechanism disables TLS hostname verification (INTERNET_FLAG_IGNORE_CERT_CN_INVALID) and executes installers without signature checks. A network attacker with any valid TLS certificate (e.g., Let's Encrypt) can intercept the update check request, inject a malicious installer URL, and achieve arbitrary code execution.



- [https://github.com/mbanyamer/CVE-2026-25961-SumatraPDF-3.5.0---3.5.2-RCE](https://github.com/mbanyamer/CVE-2026-25961-SumatraPDF-3.5.0---3.5.2-RCE) :  ![starts](https://img.shields.io/github/stars/mbanyamer/CVE-2026-25961-SumatraPDF-3.5.0---3.5.2-RCE.svg) ![forks](https://img.shields.io/github/forks/mbanyamer/CVE-2026-25961-SumatraPDF-3.5.0---3.5.2-RCE.svg)

## CVE-2026-25939
 FUXA is a web-based Process Visualization (SCADA/HMI/Dashboard) software. From 1.2.8 through version 1.2.10, 
an authorization bypass vulnerability in the FUXA allows an unauthenticated, remote attacker to create and modify arbitrary schedulers, exposing connected ICS/SCADA environments to follow-on actions. This has been patched in FUXA version 1.2.11.



- [https://github.com/mbanyamer/CVE-2026-25939-SCADA-FUXA-Unauthenticated-Remote-Arbitrary](https://github.com/mbanyamer/CVE-2026-25939-SCADA-FUXA-Unauthenticated-Remote-Arbitrary) :  ![starts](https://img.shields.io/github/stars/mbanyamer/CVE-2026-25939-SCADA-FUXA-Unauthenticated-Remote-Arbitrary.svg) ![forks](https://img.shields.io/github/forks/mbanyamer/CVE-2026-25939-SCADA-FUXA-Unauthenticated-Remote-Arbitrary.svg)

## CVE-2026-25924
 Kanboard is project management software focused on Kanban methodology. Prior to 1.2.50, a security control bypass vulnerability in Kanboard allows an authenticated administrator to achieve full Remote Code Execution (RCE). Although the application correctly hides the plugin installation interface when the PLUGIN_INSTALLER configuration is set to false, the underlying backend endpoint fails to verify this security setting. An attacker can exploit this oversight to force the server to download and install a malicious plugin, leading to arbitrary code execution. This vulnerability is fixed in 1.2.50.



- [https://github.com/drkim-dev/CVE-2026-25924](https://github.com/drkim-dev/CVE-2026-25924) :  ![starts](https://img.shields.io/github/stars/drkim-dev/CVE-2026-25924.svg) ![forks](https://img.shields.io/github/forks/drkim-dev/CVE-2026-25924.svg)

## CVE-2026-25916
 Roundcube Webmail before 1.5.13 and 1.6 before 1.6.13, when "Block remote images" is used, does not block SVG feImage.



- [https://github.com/mbanyamer/CVE-2026-25916-Roundcube-Webmail-DOM-based-XSS-Exploit-via-SVG-href-Attribute](https://github.com/mbanyamer/CVE-2026-25916-Roundcube-Webmail-DOM-based-XSS-Exploit-via-SVG-href-Attribute) :  ![starts](https://img.shields.io/github/stars/mbanyamer/CVE-2026-25916-Roundcube-Webmail-DOM-based-XSS-Exploit-via-SVG-href-Attribute.svg) ![forks](https://img.shields.io/github/forks/mbanyamer/CVE-2026-25916-Roundcube-Webmail-DOM-based-XSS-Exploit-via-SVG-href-Attribute.svg)

## CVE-2026-25890
 File Browser provides a file managing interface within a specified directory and it can be used to upload, delete, preview, rename and edit files. Prior to 2.57.1, an authenticated user can bypass the application's "Disallow" file path rules by modifying the request URL. By adding multiple slashes (e.g., //private/) to the path, the authorization check fails to match the rule, while the underlying filesystem resolves the path correctly, granting unauthorized access to restricted files. This vulnerability is fixed in 2.57.1.



- [https://github.com/mbanyamer/CVE-2026-25890-FileBrowser-Access-Control-Bypass](https://github.com/mbanyamer/CVE-2026-25890-FileBrowser-Access-Control-Bypass) :  ![starts](https://img.shields.io/github/stars/mbanyamer/CVE-2026-25890-FileBrowser-Access-Control-Bypass.svg) ![forks](https://img.shields.io/github/forks/mbanyamer/CVE-2026-25890-FileBrowser-Access-Control-Bypass.svg)

## CVE-2026-25857
 Tenda G300-F router firmware version 16.01.14.2 and prior contain an OS command injection vulnerability in the WAN diagnostic functionality (formSetWanDiag). The implementation constructs a shell command that invokes curl and incorporates attacker-controlled input into the command line without adequate neutralization. As a result, a remote attacker with access to the affected management interface can inject additional shell syntax and execute arbitrary commands on the device with the privileges of the management process.



- [https://github.com/eeeeeeeeeevan/CVE-2026-25857](https://github.com/eeeeeeeeeevan/CVE-2026-25857) :  ![starts](https://img.shields.io/github/stars/eeeeeeeeeevan/CVE-2026-25857.svg) ![forks](https://img.shields.io/github/forks/eeeeeeeeeevan/CVE-2026-25857.svg)

## CVE-2026-25828
 grub-btrfs through 2026-01-31 (on Arch Linux and derivative distributions) allows initramfs OS command injection because it does not sanitize the $root parameter to resolve_device().



- [https://github.com/cardosource/CVE-2026-25828](https://github.com/cardosource/CVE-2026-25828) :  ![starts](https://img.shields.io/github/stars/cardosource/CVE-2026-25828.svg) ![forks](https://img.shields.io/github/forks/cardosource/CVE-2026-25828.svg)

## CVE-2026-25807
 ZAI Shell is an autonomous SysOps agent designed to navigate, repair, and secure complex environments. Prior to 9.0.3, the P2P terminal sharing feature (share start) opens a TCP socket on port 5757 without any authentication mechanism. Any remote attacker can connect to this port using a simple socket script. An attacker who connects to a ZAI-Shell P2P session running in --no-ai mode can send arbitrary system commands. If the host user approves the command without reviewing its contents, the command executes directly with the user's privileges, bypassing all Sentinel safety checks. This vulnerability is fixed in 9.0.3.



- [https://github.com/ibrahmsql/CVE-2026-25807-Exploit](https://github.com/ibrahmsql/CVE-2026-25807-Exploit) :  ![starts](https://img.shields.io/github/stars/ibrahmsql/CVE-2026-25807-Exploit.svg) ![forks](https://img.shields.io/github/forks/ibrahmsql/CVE-2026-25807-Exploit.svg)

## CVE-2026-25732
 NiceGUI is a Python-based UI framework. Prior to 3.7.0, NiceGUI's FileUpload.name property exposes client-supplied filename metadata without sanitization, enabling path traversal when developers use the pattern UPLOAD_DIR / file.name. Malicious filenames containing ../ sequences allow attackers to write files outside intended directories, with potential for remote code execution through application file overwrites in vulnerable deployment patterns. This design creates a prevalent security footgun affecting applications following common community patterns. Note: Exploitation requires application code incorporating file.name into filesystem paths without sanitization. Applications using fixed paths, generated filenames, or explicit sanitization are not affected. This vulnerability is fixed in 3.7.0.



- [https://github.com/mbanyamer/CVE-2026-25732-NiceGUI-3.6.1](https://github.com/mbanyamer/CVE-2026-25732-NiceGUI-3.6.1) :  ![starts](https://img.shields.io/github/stars/mbanyamer/CVE-2026-25732-NiceGUI-3.6.1.svg) ![forks](https://img.shields.io/github/forks/mbanyamer/CVE-2026-25732-NiceGUI-3.6.1.svg)

## CVE-2026-25731
 calibre is an e-book manager. Prior to 9.2.0, a Server-Side Template Injection (SSTI) vulnerability in Calibre's Templite templating engine allows arbitrary code execution when a user converts an ebook using a malicious custom template file via the --template-html or --template-html-index command-line options. This vulnerability is fixed in 9.2.0.



- [https://github.com/dxlerYT/CVE-2026-25731](https://github.com/dxlerYT/CVE-2026-25731) :  ![starts](https://img.shields.io/github/stars/dxlerYT/CVE-2026-25731.svg) ![forks](https://img.shields.io/github/forks/dxlerYT/CVE-2026-25731.svg)

## CVE-2026-25676
 The installer of M-Track Duo HD version 1.0.0 contains an issue with the DLL search path, which may lead to insecurely loading Dynamic Link Libraries. As a result, arbitrary code may be executed with administrator privileges.



- [https://github.com/Nexxus67/cve-2026-25676](https://github.com/Nexxus67/cve-2026-25676) :  ![starts](https://img.shields.io/github/stars/Nexxus67/cve-2026-25676.svg) ![forks](https://img.shields.io/github/forks/Nexxus67/cve-2026-25676.svg)

## CVE-2026-25643
 Frigate is a network video recorder (NVR) with realtime local object detection for IP cameras. Prior to 0.16.4, a critical Remote Command Execution (RCE) vulnerability has been identified in the Frigate integration with go2rtc. The application does not sanitize user input in the video stream configuration (config.yaml), allowing direct injection of system commands via the exec: directive. The go2rtc service executes these commands without restrictions. This vulnerability is only exploitable by an administrator or users who have exposed their Frigate install to the open internet with no authentication which allows anyone full administrative control. This vulnerability is fixed in 0.16.4.



- [https://github.com/jduardo2704/CVE-2026-25643-Frigate-RCE](https://github.com/jduardo2704/CVE-2026-25643-Frigate-RCE) :  ![starts](https://img.shields.io/github/stars/jduardo2704/CVE-2026-25643-Frigate-RCE.svg) ![forks](https://img.shields.io/github/forks/jduardo2704/CVE-2026-25643-Frigate-RCE.svg)

## CVE-2026-25546
 Godot MCP is a Model Context Protocol (MCP) server for interacting with the Godot game engine. Prior to version 0.1.1, a command injection vulnerability in godot-mcp allows remote code execution. The executeOperation function passed user-controlled input (e.g., projectPath) directly to exec(), which spawns a shell. An attacker could inject shell metacharacters like $(command) or &calc to execute arbitrary commands with the privileges of the MCP server process. This affects any tool that accepts projectPath, including create_scene, add_node, load_sprite, and others. This issue has been patched in version 0.1.1.



- [https://github.com/mbanyamer/CVE-2026-25546-godot-mcp-0.1.1-OS-Command-Injection](https://github.com/mbanyamer/CVE-2026-25546-godot-mcp-0.1.1-OS-Command-Injection) :  ![starts](https://img.shields.io/github/stars/mbanyamer/CVE-2026-25546-godot-mcp-0.1.1-OS-Command-Injection.svg) ![forks](https://img.shields.io/github/forks/mbanyamer/CVE-2026-25546-godot-mcp-0.1.1-OS-Command-Injection.svg)

## CVE-2026-25526
 JinJava is a Java-based template engine based on django template syntax, adapted to render jinja templates. Prior to versions 2.7.6 and 2.8.3, JinJava is vulnerable to arbitrary Java execution via bypass through ForTag. This allows arbitrary Java class instantiation and file access bypassing built-in sandbox restrictions. This issue has been patched in versions 2.7.6 and 2.8.3.



- [https://github.com/av4nth1ka/jinjava-cve-2026-25526-poc](https://github.com/av4nth1ka/jinjava-cve-2026-25526-poc) :  ![starts](https://img.shields.io/github/stars/av4nth1ka/jinjava-cve-2026-25526-poc.svg) ![forks](https://img.shields.io/github/forks/av4nth1ka/jinjava-cve-2026-25526-poc.svg)

## CVE-2026-25512
 Group-Office is an enterprise customer relationship management and groupware tool. Prior to versions 6.8.150, 25.0.82, and 26.0.5, there is a remote code execution (RCE) vulnerability in Group-Office. The endpoint email/message/tnefAttachmentFromTempFile directly concatenates the user-controlled parameter tmp_file into an exec() call. By injecting shell metacharacters into tmp_file, an authenticated attacker can execute arbitrary system commands on the server. This issue has been patched in versions 6.8.150, 25.0.82, and 26.0.5.



- [https://github.com/NumberOreo1/CVE-2026-25512](https://github.com/NumberOreo1/CVE-2026-25512) :  ![starts](https://img.shields.io/github/stars/NumberOreo1/CVE-2026-25512.svg) ![forks](https://img.shields.io/github/forks/NumberOreo1/CVE-2026-25512.svg)

- [https://github.com/mbanyamer/CVE-2026-25512-PoC-Group-Office-Authenticated-RCE](https://github.com/mbanyamer/CVE-2026-25512-PoC-Group-Office-Authenticated-RCE) :  ![starts](https://img.shields.io/github/stars/mbanyamer/CVE-2026-25512-PoC-Group-Office-Authenticated-RCE.svg) ![forks](https://img.shields.io/github/forks/mbanyamer/CVE-2026-25512-PoC-Group-Office-Authenticated-RCE.svg)

## CVE-2026-25253
 OpenClaw (aka clawdbot or Moltbot) before 2026.1.29 obtains a gatewayUrl value from a query string and automatically makes a WebSocket connection without prompting, sending a token value.



- [https://github.com/ethiack/moltbot-1click-rce](https://github.com/ethiack/moltbot-1click-rce) :  ![starts](https://img.shields.io/github/stars/ethiack/moltbot-1click-rce.svg) ![forks](https://img.shields.io/github/forks/ethiack/moltbot-1click-rce.svg)

- [https://github.com/adibirzu/openclaw-security-monitor](https://github.com/adibirzu/openclaw-security-monitor) :  ![starts](https://img.shields.io/github/stars/adibirzu/openclaw-security-monitor.svg) ![forks](https://img.shields.io/github/forks/adibirzu/openclaw-security-monitor.svg)

- [https://github.com/al4n4n/CVE-2026-25253-research](https://github.com/al4n4n/CVE-2026-25253-research) :  ![starts](https://img.shields.io/github/stars/al4n4n/CVE-2026-25253-research.svg) ![forks](https://img.shields.io/github/forks/al4n4n/CVE-2026-25253-research.svg)

- [https://github.com/Joseph19820124/openclaw-vuln-report](https://github.com/Joseph19820124/openclaw-vuln-report) :  ![starts](https://img.shields.io/github/stars/Joseph19820124/openclaw-vuln-report.svg) ![forks](https://img.shields.io/github/forks/Joseph19820124/openclaw-vuln-report.svg)

- [https://github.com/Ckokoski/moatbot-security](https://github.com/Ckokoski/moatbot-security) :  ![starts](https://img.shields.io/github/stars/Ckokoski/moatbot-security.svg) ![forks](https://img.shields.io/github/forks/Ckokoski/moatbot-security.svg)

## CVE-2026-25251
 This has been moved to the REJECTED state because the information source is under review. If circumstances change, it is possible that this will be moved to the PUBLISHED state at a later date.



- [https://github.com/0verdu/Senate_Surprise](https://github.com/0verdu/Senate_Surprise) :  ![starts](https://img.shields.io/github/stars/0verdu/Senate_Surprise.svg) ![forks](https://img.shields.io/github/forks/0verdu/Senate_Surprise.svg)

## CVE-2026-25242
 Gogs is an open source self-hosted Git service. Versions 0.13.4 and below expose unauthenticated file upload endpoints by default. When the global RequireSigninView setting is disabled (default), any remote user can upload arbitrary files to the server via /releases/attachments and /issues/attachments. This enables the instance to be abused as a public file host, potentially leading to disk exhaustion, content hosting, or delivery of malware. CSRF tokens do not mitigate this attack due to same-origin cookie issuance. This issue has been fixed in version 0.14.1.



- [https://github.com/mindkernel/CVE-2026-25242](https://github.com/mindkernel/CVE-2026-25242) :  ![starts](https://img.shields.io/github/stars/mindkernel/CVE-2026-25242.svg) ![forks](https://img.shields.io/github/forks/mindkernel/CVE-2026-25242.svg)

## CVE-2026-25211
 Llama Stack (aka llama-stack) before 0.4.0rc3 does not censor the pgvector password in the initialization log.



- [https://github.com/mbanyamer/Llama-Stack-0.4.0rc3-local-CVE-2026-25211](https://github.com/mbanyamer/Llama-Stack-0.4.0rc3-local-CVE-2026-25211) :  ![starts](https://img.shields.io/github/stars/mbanyamer/Llama-Stack-0.4.0rc3-local-CVE-2026-25211.svg) ![forks](https://img.shields.io/github/forks/mbanyamer/Llama-Stack-0.4.0rc3-local-CVE-2026-25211.svg)

## CVE-2026-25130
 Cybersecurity AI (CAI) is a framework for AI Security. In versions up to and including 0.5.10, the CAI (Cybersecurity AI) framework contains multiple argument injection vulnerabilities in its function tools. User-controlled input is passed directly to shell commands via `subprocess.Popen()` with `shell=True`, allowing attackers to execute arbitrary commands on the host system. The `find_file()` tool executes without requiring user approval because find is considered a "safe" pre-approved command. This means an attacker can achieve Remote Code Execution (RCE) by injecting malicious arguments (like -exec) into the args parameter, completely bypassing any human-in-the-loop safety mechanisms. Commit e22a1220f764e2d7cf9da6d6144926f53ca01cde contains a fix.



- [https://github.com/mbanyamer/CVE-2026-25130-Cybersecurity-AI-CAI-Framework-0.5.10](https://github.com/mbanyamer/CVE-2026-25130-Cybersecurity-AI-CAI-Framework-0.5.10) :  ![starts](https://img.shields.io/github/stars/mbanyamer/CVE-2026-25130-Cybersecurity-AI-CAI-Framework-0.5.10.svg) ![forks](https://img.shields.io/github/forks/mbanyamer/CVE-2026-25130-Cybersecurity-AI-CAI-Framework-0.5.10.svg)

## CVE-2026-25126
 PolarLearn is a free and open-source learning program. Prior to version 0-PRERELEASE-15, the vote API route (`POST /api/v1/forum/vote`) trusts the JSON body’s `direction` value without runtime validation. TypeScript types are not enforced at runtime, so an attacker can send arbitrary strings (e.g., `"x"`) as `direction`. Downstream (`VoteServer`) treats any non-`"up"` and non-`null` value as a downvote and persists the invalid value in `votes_data`. This can be exploited to bypass intended business logic. Version 0-PRERELEASE-15 fixes the vulnerability.



- [https://github.com/Jvr2022/CVE-2026-25126](https://github.com/Jvr2022/CVE-2026-25126) :  ![starts](https://img.shields.io/github/stars/Jvr2022/CVE-2026-25126.svg) ![forks](https://img.shields.io/github/forks/Jvr2022/CVE-2026-25126.svg)

## CVE-2026-25053
 n8n is an open source workflow automation platform. Prior to versions 1.123.10 and 2.5.0, vulnerabilities in the Git node allowed authenticated users with permission to create or modify workflows to execute arbitrary system commands or read arbitrary files on the n8n host. This issue has been patched in versions 1.123.10 and 2.5.0.



- [https://github.com/yadhukrishnam/CVE-2026-25053](https://github.com/yadhukrishnam/CVE-2026-25053) :  ![starts](https://img.shields.io/github/stars/yadhukrishnam/CVE-2026-25053.svg) ![forks](https://img.shields.io/github/forks/yadhukrishnam/CVE-2026-25053.svg)

## CVE-2026-25050
 Vendure is an open-source headless commerce platform. Prior to version 3.5.3, the `NativeAuthenticationStrategy.authenticate()` method is vulnerable to a timing attack that allows attackers to enumerate valid usernames (email addresses). In `packages/core/src/config/auth/native-authentication-strategy.ts`, the authenticate method returns immediately if a user is not found. The significant timing difference (~200-400ms for bcrypt vs ~1-5ms for DB miss) allows attackers to reliably distinguish between existing and non-existing accounts. Version 3.5.3 fixes the issue.



- [https://github.com/Christbowel/CVE-2026-25050](https://github.com/Christbowel/CVE-2026-25050) :  ![starts](https://img.shields.io/github/stars/Christbowel/CVE-2026-25050.svg) ![forks](https://img.shields.io/github/forks/Christbowel/CVE-2026-25050.svg)

## CVE-2026-25049
 n8n is an open source workflow automation platform. Prior to versions 1.123.17 and 2.5.2, an authenticated user with permission to create or modify workflows could abuse crafted expressions in workflow parameters to trigger unintended system command execution on the host running n8n. This issue has been patched in versions 1.123.17 and 2.5.2.



- [https://github.com/otakuliu/Expression-Sandbox-Escape-Simulation-Lab](https://github.com/otakuliu/Expression-Sandbox-Escape-Simulation-Lab) :  ![starts](https://img.shields.io/github/stars/otakuliu/Expression-Sandbox-Escape-Simulation-Lab.svg) ![forks](https://img.shields.io/github/forks/otakuliu/Expression-Sandbox-Escape-Simulation-Lab.svg)

## CVE-2026-25047
 deepHas provides a test for the existence of a nested object key and optionally returns that key. A prototype pollution vulnerability exists in version 1.0.7 of the deephas npm package that allows an attacker to modify global object behavior. This issue was fixed in version 1.0.8.



- [https://github.com/mbanyamer/deephas-1.0.7-Prototype-Pollution-PoC-CVE-2026-25047-](https://github.com/mbanyamer/deephas-1.0.7-Prototype-Pollution-PoC-CVE-2026-25047-) :  ![starts](https://img.shields.io/github/stars/mbanyamer/deephas-1.0.7-Prototype-Pollution-PoC-CVE-2026-25047-.svg) ![forks](https://img.shields.io/github/forks/mbanyamer/deephas-1.0.7-Prototype-Pollution-PoC-CVE-2026-25047-.svg)

## CVE-2026-24858
 An Authentication Bypass Using an Alternate Path or Channel vulnerability [CWE-288] vulnerability in Fortinet FortiAnalyzer 7.6.0 through 7.6.5, FortiAnalyzer 7.4.0 through 7.4.9, FortiAnalyzer 7.2.0 through 7.2.11, FortiAnalyzer 7.0.0 through 7.0.15, FortiManager 7.6.0 through 7.6.5, FortiManager 7.4.0 through 7.4.9, FortiManager 7.2.0 through 7.2.11, FortiManager 7.0.0 through 7.0.15, FortiOS 7.6.0 through 7.6.5, FortiOS 7.4.0 through 7.4.10, FortiOS 7.2.0 through 7.2.12, FortiOS 7.0.0 through 7.0.18, FortiProxy 7.6.0 through 7.6.4, FortiProxy 7.4.0 through 7.4.12, FortiProxy 7.2.0 through 7.2.15, FortiProxy 7.0.0 through 7.0.22, FortiWeb 8.0.0 through 8.0.3, FortiWeb 7.6.0 through 7.6.6, FortiWeb 7.4.0 through 7.4.11 may allow an attacker with a FortiCloud account and a registered device to log into other devices registered to other accounts, if FortiCloud SSO authentication is enabled on those devices.



- [https://github.com/absholi7ly/CVE-2026-24858-FortiCloud-SSO-Authentication-Bypass](https://github.com/absholi7ly/CVE-2026-24858-FortiCloud-SSO-Authentication-Bypass) :  ![starts](https://img.shields.io/github/stars/absholi7ly/CVE-2026-24858-FortiCloud-SSO-Authentication-Bypass.svg) ![forks](https://img.shields.io/github/forks/absholi7ly/CVE-2026-24858-FortiCloud-SSO-Authentication-Bypass.svg)

- [https://github.com/m0d0ri205/CVE-2026-24858](https://github.com/m0d0ri205/CVE-2026-24858) :  ![starts](https://img.shields.io/github/stars/m0d0ri205/CVE-2026-24858.svg) ![forks](https://img.shields.io/github/forks/m0d0ri205/CVE-2026-24858.svg)

- [https://github.com/gagaltotal/cve-2026-24858](https://github.com/gagaltotal/cve-2026-24858) :  ![starts](https://img.shields.io/github/stars/gagaltotal/cve-2026-24858.svg) ![forks](https://img.shields.io/github/forks/gagaltotal/cve-2026-24858.svg)

- [https://github.com/SimoesCTT/-CTT-NSP-Convergent-Time-Theory---Network-Stack-Projection-CVE-2026-24858-](https://github.com/SimoesCTT/-CTT-NSP-Convergent-Time-Theory---Network-Stack-Projection-CVE-2026-24858-) :  ![starts](https://img.shields.io/github/stars/SimoesCTT/-CTT-NSP-Convergent-Time-Theory---Network-Stack-Projection-CVE-2026-24858-.svg) ![forks](https://img.shields.io/github/forks/SimoesCTT/-CTT-NSP-Convergent-Time-Theory---Network-Stack-Projection-CVE-2026-24858-.svg)

- [https://github.com/SimoesCTT/SCTT-2026-33-0004-FortiCloud-SSO-Identity-Singularity](https://github.com/SimoesCTT/SCTT-2026-33-0004-FortiCloud-SSO-Identity-Singularity) :  ![starts](https://img.shields.io/github/stars/SimoesCTT/SCTT-2026-33-0004-FortiCloud-SSO-Identity-Singularity.svg) ![forks](https://img.shields.io/github/forks/SimoesCTT/SCTT-2026-33-0004-FortiCloud-SSO-Identity-Singularity.svg)

## CVE-2026-24854
 ChurchCRM is an open-source church management system. A SQL Injection vulnerability exists in endpoint `/PaddleNumEditor.php` in ChurchCRM prior to version 6.7.2. Any authenticated user, including one with zero assigned permissions, can exploit SQL injection through the `PerID` parameter. Version 6.7.2 contains a patch for the issue.



- [https://github.com/mbanyamer/CVE-2026-24854-ChurchCRM-6.7.2-Authenticated-Numeric-SQL-Injection](https://github.com/mbanyamer/CVE-2026-24854-ChurchCRM-6.7.2-Authenticated-Numeric-SQL-Injection) :  ![starts](https://img.shields.io/github/stars/mbanyamer/CVE-2026-24854-ChurchCRM-6.7.2-Authenticated-Numeric-SQL-Injection.svg) ![forks](https://img.shields.io/github/forks/mbanyamer/CVE-2026-24854-ChurchCRM-6.7.2-Authenticated-Numeric-SQL-Injection.svg)

## CVE-2026-24841
 Dokploy is a free, self-hostable Platform as a Service (PaaS). In versions prior to 0.26.6, a critical command injection vulnerability exists in Dokploy's WebSocket endpoint `/docker-container-terminal`. The `containerId` and `activeWay` parameters are directly interpolated into shell commands without sanitization, allowing authenticated attackers to execute arbitrary commands on the host server. Version 0.26.6 fixes the issue.



- [https://github.com/otakuliu/CVE-2026-24841_Range](https://github.com/otakuliu/CVE-2026-24841_Range) :  ![starts](https://img.shields.io/github/stars/otakuliu/CVE-2026-24841_Range.svg) ![forks](https://img.shields.io/github/forks/otakuliu/CVE-2026-24841_Range.svg)

## CVE-2026-24688
 pypdf is a free and open-source pure-python PDF library. An attacker who uses an infinite loop vulnerability that is present in versions prior to 6.6.2 can craft a PDF which leads to an infinite loop. This requires accessing the outlines/bookmarks. This has been fixed in pypdf 6.6.2. If projects cannot upgrade yet, consider applying the changes from PR #3610 manually.



- [https://github.com/JoakimBulow/CVE-2026-24688](https://github.com/JoakimBulow/CVE-2026-24688) :  ![starts](https://img.shields.io/github/stars/JoakimBulow/CVE-2026-24688.svg) ![forks](https://img.shields.io/github/forks/JoakimBulow/CVE-2026-24688.svg)

## CVE-2026-24514
 A security issue was discovered in ingress-nginx where the validating admission controller feature is subject to a denial of service condition. By sending large requests to the validating admission controller, an attacker can cause memory consumption, which may result in the ingress-nginx controller pod being killed or the node running out of memory.



- [https://github.com/mbanyamer/cve-2026-24514-Kubernetes-Dos](https://github.com/mbanyamer/cve-2026-24514-Kubernetes-Dos) :  ![starts](https://img.shields.io/github/stars/mbanyamer/cve-2026-24514-Kubernetes-Dos.svg) ![forks](https://img.shields.io/github/forks/mbanyamer/cve-2026-24514-Kubernetes-Dos.svg)

## CVE-2026-24423
 SmarterTools SmarterMail versions prior to build 9511 contain an unauthenticated remote code execution vulnerability in the ConnectToHub API method. The attacker could point the SmarterMail to the malicious HTTP server, which serves the malicious OS command. This command will be executed by the vulnerable application.



- [https://github.com/aavamin/CVE-2026-24423](https://github.com/aavamin/CVE-2026-24423) :  ![starts](https://img.shields.io/github/stars/aavamin/CVE-2026-24423.svg) ![forks](https://img.shields.io/github/forks/aavamin/CVE-2026-24423.svg)

## CVE-2026-24306
 Improper access control in Azure Front Door (AFD) allows an unauthorized attacker to elevate privileges over a network.



- [https://github.com/ExploreUnknowed/CVE-2026-24306](https://github.com/ExploreUnknowed/CVE-2026-24306) :  ![starts](https://img.shields.io/github/stars/ExploreUnknowed/CVE-2026-24306.svg) ![forks](https://img.shields.io/github/forks/ExploreUnknowed/CVE-2026-24306.svg)

## CVE-2026-24135
 Gogs is an open source self-hosted Git service. In version 0.13.3 and prior, a path traversal vulnerability exists in the updateWikiPage function of Gogs. The vulnerability allows an authenticated user with write access to a repository's wiki to delete arbitrary files on the server by manipulating the old_title parameter in the wiki editing form. This issue has been patched in versions 0.13.4 and 0.14.0+dev.



- [https://github.com/reschjonas/CVE-2026-24135](https://github.com/reschjonas/CVE-2026-24135) :  ![starts](https://img.shields.io/github/stars/reschjonas/CVE-2026-24135.svg) ![forks](https://img.shields.io/github/forks/reschjonas/CVE-2026-24135.svg)

## CVE-2026-24134
 StudioCMS is a server-side-rendered, Astro native, headless content management system. Versions prior to 0.2.0 contain a Broken Object Level Authorization (BOLA) vulnerability in the Content Management feature that allows users with the "Visitor" role to access draft content created by Editor/Admin/Owner users. Version 0.2.0 patches the issue.



- [https://github.com/FilipeGaudard/CVE-2026-24134-PoC](https://github.com/FilipeGaudard/CVE-2026-24134-PoC) :  ![starts](https://img.shields.io/github/stars/FilipeGaudard/CVE-2026-24134-PoC.svg) ![forks](https://img.shields.io/github/forks/FilipeGaudard/CVE-2026-24134-PoC.svg)

## CVE-2026-24061
 telnetd in GNU Inetutils through 2.7 allows remote authentication bypass via a "-f root" value for the USER environment variable.



- [https://github.com/SafeBreach-Labs/CVE-2026-24061](https://github.com/SafeBreach-Labs/CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/SafeBreach-Labs/CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/SafeBreach-Labs/CVE-2026-24061.svg)

- [https://github.com/JayGLXR/CVE-2026-24061-POC](https://github.com/JayGLXR/CVE-2026-24061-POC) :  ![starts](https://img.shields.io/github/stars/JayGLXR/CVE-2026-24061-POC.svg) ![forks](https://img.shields.io/github/forks/JayGLXR/CVE-2026-24061-POC.svg)

- [https://github.com/parameciumzhang/Tell-Me-Root](https://github.com/parameciumzhang/Tell-Me-Root) :  ![starts](https://img.shields.io/github/stars/parameciumzhang/Tell-Me-Root.svg) ![forks](https://img.shields.io/github/forks/parameciumzhang/Tell-Me-Root.svg)

- [https://github.com/Lingzesec/CVE-2026-24061-GUI](https://github.com/Lingzesec/CVE-2026-24061-GUI) :  ![starts](https://img.shields.io/github/stars/Lingzesec/CVE-2026-24061-GUI.svg) ![forks](https://img.shields.io/github/forks/Lingzesec/CVE-2026-24061-GUI.svg)

- [https://github.com/h3athen/CVE-2026-24061](https://github.com/h3athen/CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/h3athen/CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/h3athen/CVE-2026-24061.svg)

- [https://github.com/leonjza/inetutils-telnetd-auth-bypass](https://github.com/leonjza/inetutils-telnetd-auth-bypass) :  ![starts](https://img.shields.io/github/stars/leonjza/inetutils-telnetd-auth-bypass.svg) ![forks](https://img.shields.io/github/forks/leonjza/inetutils-telnetd-auth-bypass.svg)

- [https://github.com/TryA9ain/CVE-2026-24061](https://github.com/TryA9ain/CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/TryA9ain/CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/TryA9ain/CVE-2026-24061.svg)

- [https://github.com/SystemVll/CVE-2026-24061](https://github.com/SystemVll/CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/SystemVll/CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/SystemVll/CVE-2026-24061.svg)

- [https://github.com/Chocapikk/CVE-2026-24061](https://github.com/Chocapikk/CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/Chocapikk/CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/Chocapikk/CVE-2026-24061.svg)

- [https://github.com/ilostmypassword/Melissae](https://github.com/ilostmypassword/Melissae) :  ![starts](https://img.shields.io/github/stars/ilostmypassword/Melissae.svg) ![forks](https://img.shields.io/github/forks/ilostmypassword/Melissae.svg)

- [https://github.com/ibrahmsql/CVE-2026-24061-PoC](https://github.com/ibrahmsql/CVE-2026-24061-PoC) :  ![starts](https://img.shields.io/github/stars/ibrahmsql/CVE-2026-24061-PoC.svg) ![forks](https://img.shields.io/github/forks/ibrahmsql/CVE-2026-24061-PoC.svg)

- [https://github.com/shivam-bathla/CVE-2026-24061-setup](https://github.com/shivam-bathla/CVE-2026-24061-setup) :  ![starts](https://img.shields.io/github/stars/shivam-bathla/CVE-2026-24061-setup.svg) ![forks](https://img.shields.io/github/forks/shivam-bathla/CVE-2026-24061-setup.svg)

- [https://github.com/yanxinwu946/CVE-2026-24061--telnetd](https://github.com/yanxinwu946/CVE-2026-24061--telnetd) :  ![starts](https://img.shields.io/github/stars/yanxinwu946/CVE-2026-24061--telnetd.svg) ![forks](https://img.shields.io/github/forks/yanxinwu946/CVE-2026-24061--telnetd.svg)

- [https://github.com/0p5cur/CVE-2026-24061-POC](https://github.com/0p5cur/CVE-2026-24061-POC) :  ![starts](https://img.shields.io/github/stars/0p5cur/CVE-2026-24061-POC.svg) ![forks](https://img.shields.io/github/forks/0p5cur/CVE-2026-24061-POC.svg)

- [https://github.com/duy-31/CVE-2026-24061---telnetd](https://github.com/duy-31/CVE-2026-24061---telnetd) :  ![starts](https://img.shields.io/github/stars/duy-31/CVE-2026-24061---telnetd.svg) ![forks](https://img.shields.io/github/forks/duy-31/CVE-2026-24061---telnetd.svg)

- [https://github.com/infat0x/CVE-2026-24061](https://github.com/infat0x/CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/infat0x/CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/infat0x/CVE-2026-24061.svg)

- [https://github.com/xuemian168/CVE-2026-24061](https://github.com/xuemian168/CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/xuemian168/CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/xuemian168/CVE-2026-24061.svg)

- [https://github.com/dotelpenguin/telnetd_CVE-2026-24061_tester](https://github.com/dotelpenguin/telnetd_CVE-2026-24061_tester) :  ![starts](https://img.shields.io/github/stars/dotelpenguin/telnetd_CVE-2026-24061_tester.svg) ![forks](https://img.shields.io/github/forks/dotelpenguin/telnetd_CVE-2026-24061_tester.svg)

- [https://github.com/balgan/CVE-2026-24061](https://github.com/balgan/CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/balgan/CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/balgan/CVE-2026-24061.svg)

- [https://github.com/X-croot/CVE-2026-24061_POC](https://github.com/X-croot/CVE-2026-24061_POC) :  ![starts](https://img.shields.io/github/stars/X-croot/CVE-2026-24061_POC.svg) ![forks](https://img.shields.io/github/forks/X-croot/CVE-2026-24061_POC.svg)

- [https://github.com/franckferman/CVE_2026_24061_PoC](https://github.com/franckferman/CVE_2026_24061_PoC) :  ![starts](https://img.shields.io/github/stars/franckferman/CVE_2026_24061_PoC.svg) ![forks](https://img.shields.io/github/forks/franckferman/CVE_2026_24061_PoC.svg)

- [https://github.com/madfxr/Twenty-Three-Scanner](https://github.com/madfxr/Twenty-Three-Scanner) :  ![starts](https://img.shields.io/github/stars/madfxr/Twenty-Three-Scanner.svg) ![forks](https://img.shields.io/github/forks/madfxr/Twenty-Three-Scanner.svg)

- [https://github.com/FurkanKAYAPINAR/CVE-2026-24061-telnet2root](https://github.com/FurkanKAYAPINAR/CVE-2026-24061-telnet2root) :  ![starts](https://img.shields.io/github/stars/FurkanKAYAPINAR/CVE-2026-24061-telnet2root.svg) ![forks](https://img.shields.io/github/forks/FurkanKAYAPINAR/CVE-2026-24061-telnet2root.svg)

- [https://github.com/ridpath/Terrminus-CVE-2026-2406](https://github.com/ridpath/Terrminus-CVE-2026-2406) :  ![starts](https://img.shields.io/github/stars/ridpath/Terrminus-CVE-2026-2406.svg) ![forks](https://img.shields.io/github/forks/ridpath/Terrminus-CVE-2026-2406.svg)

- [https://github.com/Ali-brarou/telnest](https://github.com/Ali-brarou/telnest) :  ![starts](https://img.shields.io/github/stars/Ali-brarou/telnest.svg) ![forks](https://img.shields.io/github/forks/Ali-brarou/telnest.svg)

- [https://github.com/Mefhika120/Ashwesker-CVE-2026-24061](https://github.com/Mefhika120/Ashwesker-CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/Mefhika120/Ashwesker-CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/Mefhika120/Ashwesker-CVE-2026-24061.svg)

- [https://github.com/novitahk/Exploit-CVE-2026-24061](https://github.com/novitahk/Exploit-CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/novitahk/Exploit-CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/novitahk/Exploit-CVE-2026-24061.svg)

- [https://github.com/r00tuser111/CVE-2026-24061](https://github.com/r00tuser111/CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/r00tuser111/CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/r00tuser111/CVE-2026-24061.svg)

- [https://github.com/scumfrog/cve-2026-24061](https://github.com/scumfrog/cve-2026-24061) :  ![starts](https://img.shields.io/github/stars/scumfrog/cve-2026-24061.svg) ![forks](https://img.shields.io/github/forks/scumfrog/cve-2026-24061.svg)

- [https://github.com/buzz075/CVE-2026-24061](https://github.com/buzz075/CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/buzz075/CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/buzz075/CVE-2026-24061.svg)

- [https://github.com/XsanFlip/CVE-2026-24061-Scanner](https://github.com/XsanFlip/CVE-2026-24061-Scanner) :  ![starts](https://img.shields.io/github/stars/XsanFlip/CVE-2026-24061-Scanner.svg) ![forks](https://img.shields.io/github/forks/XsanFlip/CVE-2026-24061-Scanner.svg)

- [https://github.com/Mr-Zapi/CVE-2026-24061](https://github.com/Mr-Zapi/CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/Mr-Zapi/CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/Mr-Zapi/CVE-2026-24061.svg)

- [https://github.com/LucasPDiniz/CVE-2026-24061](https://github.com/LucasPDiniz/CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/LucasPDiniz/CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/LucasPDiniz/CVE-2026-24061.svg)

- [https://github.com/SeptembersEND/CVE--2026-24061](https://github.com/SeptembersEND/CVE--2026-24061) :  ![starts](https://img.shields.io/github/stars/SeptembersEND/CVE--2026-24061.svg) ![forks](https://img.shields.io/github/forks/SeptembersEND/CVE--2026-24061.svg)

- [https://github.com/BrainBob/CVE-2026-24061](https://github.com/BrainBob/CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/BrainBob/CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/BrainBob/CVE-2026-24061.svg)

- [https://github.com/monstertsl/CVE-2026-24061](https://github.com/monstertsl/CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/monstertsl/CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/monstertsl/CVE-2026-24061.svg)

- [https://github.com/z3n70/CVE-2026-24061](https://github.com/z3n70/CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/z3n70/CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/z3n70/CVE-2026-24061.svg)

- [https://github.com/Parad0x7e/CVE-2026-24061](https://github.com/Parad0x7e/CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/Parad0x7e/CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/Parad0x7e/CVE-2026-24061.svg)

- [https://github.com/typeconfused/CVE-2026-24061](https://github.com/typeconfused/CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/typeconfused/CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/typeconfused/CVE-2026-24061.svg)

- [https://github.com/obrunolima1910/CVE-2026-24061](https://github.com/obrunolima1910/CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/obrunolima1910/CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/obrunolima1910/CVE-2026-24061.svg)

- [https://github.com/hilwa24/CVE-2026-24061](https://github.com/hilwa24/CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/hilwa24/CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/hilwa24/CVE-2026-24061.svg)

- [https://github.com/Gabs-hub/CVE-2026-24061_Lab](https://github.com/Gabs-hub/CVE-2026-24061_Lab) :  ![starts](https://img.shields.io/github/stars/Gabs-hub/CVE-2026-24061_Lab.svg) ![forks](https://img.shields.io/github/forks/Gabs-hub/CVE-2026-24061_Lab.svg)

- [https://github.com/tiborscholtz/CVE-2026-24061](https://github.com/tiborscholtz/CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/tiborscholtz/CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/tiborscholtz/CVE-2026-24061.svg)

- [https://github.com/midox008/CVE-2026-24061](https://github.com/midox008/CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/midox008/CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/midox008/CVE-2026-24061.svg)

- [https://github.com/0x7556/CVE-2026-24061](https://github.com/0x7556/CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/0x7556/CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/0x7556/CVE-2026-24061.svg)

- [https://github.com/killsystema/scan-cve-2026-24061](https://github.com/killsystema/scan-cve-2026-24061) :  ![starts](https://img.shields.io/github/stars/killsystema/scan-cve-2026-24061.svg) ![forks](https://img.shields.io/github/forks/killsystema/scan-cve-2026-24061.svg)

- [https://github.com/m3ngx1ng/cve_2026_24061_cli](https://github.com/m3ngx1ng/cve_2026_24061_cli) :  ![starts](https://img.shields.io/github/stars/m3ngx1ng/cve_2026_24061_cli.svg) ![forks](https://img.shields.io/github/forks/m3ngx1ng/cve_2026_24061_cli.svg)

- [https://github.com/ms0x08-dev/CVE-2026-24061-POC](https://github.com/ms0x08-dev/CVE-2026-24061-POC) :  ![starts](https://img.shields.io/github/stars/ms0x08-dev/CVE-2026-24061-POC.svg) ![forks](https://img.shields.io/github/forks/ms0x08-dev/CVE-2026-24061-POC.svg)

- [https://github.com/lavabyte/telnet-CVE-2026-24061](https://github.com/lavabyte/telnet-CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/lavabyte/telnet-CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/lavabyte/telnet-CVE-2026-24061.svg)

- [https://github.com/punitdarji/telnetd-cve-2026-24061](https://github.com/punitdarji/telnetd-cve-2026-24061) :  ![starts](https://img.shields.io/github/stars/punitdarji/telnetd-cve-2026-24061.svg) ![forks](https://img.shields.io/github/forks/punitdarji/telnetd-cve-2026-24061.svg)

- [https://github.com/Alter-N0X/CVE-2026-24061-POC](https://github.com/Alter-N0X/CVE-2026-24061-POC) :  ![starts](https://img.shields.io/github/stars/Alter-N0X/CVE-2026-24061-POC.svg) ![forks](https://img.shields.io/github/forks/Alter-N0X/CVE-2026-24061-POC.svg)

- [https://github.com/canpilayda/inetutils-telnetd-cve-2026-24061](https://github.com/canpilayda/inetutils-telnetd-cve-2026-24061) :  ![starts](https://img.shields.io/github/stars/canpilayda/inetutils-telnetd-cve-2026-24061.svg) ![forks](https://img.shields.io/github/forks/canpilayda/inetutils-telnetd-cve-2026-24061.svg)

- [https://github.com/MY0723/GNU-Inetutils-telnet-CVE-2026-24061-](https://github.com/MY0723/GNU-Inetutils-telnet-CVE-2026-24061-) :  ![starts](https://img.shields.io/github/stars/MY0723/GNU-Inetutils-telnet-CVE-2026-24061-.svg) ![forks](https://img.shields.io/github/forks/MY0723/GNU-Inetutils-telnet-CVE-2026-24061-.svg)

- [https://github.com/BrainBob/Telnet-TestVuln-CVE-2026-24061](https://github.com/BrainBob/Telnet-TestVuln-CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/BrainBob/Telnet-TestVuln-CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/BrainBob/Telnet-TestVuln-CVE-2026-24061.svg)

- [https://github.com/androidteacher/CVE-2026-24061-PoC-Telnetd](https://github.com/androidteacher/CVE-2026-24061-PoC-Telnetd) :  ![starts](https://img.shields.io/github/stars/androidteacher/CVE-2026-24061-PoC-Telnetd.svg) ![forks](https://img.shields.io/github/forks/androidteacher/CVE-2026-24061-PoC-Telnetd.svg)

- [https://github.com/0xXyc/telnet-inetutils-auth-bypass-CVE-2026-24061](https://github.com/0xXyc/telnet-inetutils-auth-bypass-CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/0xXyc/telnet-inetutils-auth-bypass-CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/0xXyc/telnet-inetutils-auth-bypass-CVE-2026-24061.svg)

- [https://github.com/nrnw/CVE-2026-24061-GNU-inetutils-Telnet-Detector](https://github.com/nrnw/CVE-2026-24061-GNU-inetutils-Telnet-Detector) :  ![starts](https://img.shields.io/github/stars/nrnw/CVE-2026-24061-GNU-inetutils-Telnet-Detector.svg) ![forks](https://img.shields.io/github/forks/nrnw/CVE-2026-24061-GNU-inetutils-Telnet-Detector.svg)

- [https://github.com/mbanyamer/CVE-2026-24061-GNU-Inetutils-telnetd-Remote-Authentication-Bypass-Root-Shell-](https://github.com/mbanyamer/CVE-2026-24061-GNU-Inetutils-telnetd-Remote-Authentication-Bypass-Root-Shell-) :  ![starts](https://img.shields.io/github/stars/mbanyamer/CVE-2026-24061-GNU-Inetutils-telnetd-Remote-Authentication-Bypass-Root-Shell-.svg) ![forks](https://img.shields.io/github/forks/mbanyamer/CVE-2026-24061-GNU-Inetutils-telnetd-Remote-Authentication-Bypass-Root-Shell-.svg)

- [https://github.com/cumakurt/tscan](https://github.com/cumakurt/tscan) :  ![starts](https://img.shields.io/github/stars/cumakurt/tscan.svg) ![forks](https://img.shields.io/github/forks/cumakurt/tscan.svg)

- [https://github.com/hyu164/Terrminus-CVE-2026-2406](https://github.com/hyu164/Terrminus-CVE-2026-2406) :  ![starts](https://img.shields.io/github/stars/hyu164/Terrminus-CVE-2026-2406.svg) ![forks](https://img.shields.io/github/forks/hyu164/Terrminus-CVE-2026-2406.svg)

- [https://github.com/hackingyseguridad/root](https://github.com/hackingyseguridad/root) :  ![starts](https://img.shields.io/github/stars/hackingyseguridad/root.svg) ![forks](https://img.shields.io/github/forks/hackingyseguridad/root.svg)

## CVE-2026-24049
 wheel is a command line tool for manipulating Python wheel files, as defined in PEP 427. In versions 0.40.0 through 0.46.1, the unpack function is vulnerable to file permission modification through mishandling of file permissions after extraction. The logic blindly trusts the filename from the archive header for the chmod operation, even though the extraction process itself might have sanitized the path. Attackers can craft a malicious wheel file that, when unpacked, changes the permissions of critical system files (e.g., /etc/passwd, SSH keys, config files), allowing for Privilege Escalation or arbitrary code execution by modifying now-writable scripts. This issue has been fixed in version 0.46.2.



- [https://github.com/kriskimmerle/wheelaudit](https://github.com/kriskimmerle/wheelaudit) :  ![starts](https://img.shields.io/github/stars/kriskimmerle/wheelaudit.svg) ![forks](https://img.shields.io/github/forks/kriskimmerle/wheelaudit.svg)

## CVE-2026-23947
 Orval generates type-safe JS clients (TypeScript) from any valid OpenAPI v3 or Swagger v2 specification. Versions prior to 7.19.0 until 8.0.2 are vulnerable to arbitrary code execution in environments consuming generated clients. This issue is similar in nature to CVE-2026-22785, but affects a different code path in @orval/core that was not addressed by CVE-2026-22785's fix. The vulnerability allows untrusted OpenAPI specifications to inject arbitrary TypeScript/JavaScript code into generated clients via the x-enumDescriptions field, which is embedded without proper escaping in getEnumImplementation(). I have confirmed that the injection occurs during const enum generation and results in executable code within the generated schema files. Orval 7.19.0 and 8.0.2 contain a fix for the issue.



- [https://github.com/boroeurnprach/CVE-2026-23947-PoC](https://github.com/boroeurnprach/CVE-2026-23947-PoC) :  ![starts](https://img.shields.io/github/stars/boroeurnprach/CVE-2026-23947-PoC.svg) ![forks](https://img.shields.io/github/forks/boroeurnprach/CVE-2026-23947-PoC.svg)

## CVE-2026-23885
 Alchemy is an open source content management system engine written in Ruby on Rails. Prior to versions 7.4.12 and 8.0.3, the application uses the Ruby `eval()` function to dynamically execute a string provided by the `resource_handler.engine_name` attribute in `Alchemy::ResourcesHelper#resource_url_proxy`. The vulnerability exists in `app/helpers/alchemy/resources_helper.rb` at line 28. The code explicitly bypasses security linting with `# rubocop:disable Security/Eval`, indicating that the use of a dangerous function was known but not properly mitigated. Since `engine_name` is sourced from module definitions that can be influenced by administrative configurations, it allows an authenticated attacker to escape the Ruby sandbox and execute arbitrary system commands on the host OS. Versions 7.4.12 and 8.0.3 fix the issue by replacing `eval()` with `send()`.



- [https://github.com/TheDeepOpc/CVE-2026-23885](https://github.com/TheDeepOpc/CVE-2026-23885) :  ![starts](https://img.shields.io/github/stars/TheDeepOpc/CVE-2026-23885.svg) ![forks](https://img.shields.io/github/forks/TheDeepOpc/CVE-2026-23885.svg)

## CVE-2026-23830
 SandboxJS is a JavaScript sandboxing library. Versions prior to 0.8.26 have a sandbox escape vulnerability due to `AsyncFunction` not being isolated in `SandboxFunction`. The library attempts to sandbox code execution by replacing the global `Function` constructor with a safe, sandboxed version (`SandboxFunction`). This is handled in `utils.ts` by mapping `Function` to `sandboxFunction` within a map used for lookups. However, before version 0.8.26, the library did not include mappings for `AsyncFunction`, `GeneratorFunction`, and `AsyncGeneratorFunction`. These constructors are not global properties but can be accessed via the `.constructor` property of an instance (e.g., `(async () = {}).constructor`). In `executor.ts`, property access is handled. When code running inside the sandbox accesses `.constructor` on an async function (which the sandbox allows creating), the `executor` retrieves the property value. Since `AsyncFunction` was not in the safe-replacement map, the `executor` returns the actual native host `AsyncFunction` constructor. Constructors for functions in JavaScript (like `Function`, `AsyncFunction`) create functions that execute in the global scope. By obtaining the host `AsyncFunction` constructor, an attacker can create a new async function that executes entirely outside the sandbox context, bypassing all restrictions and gaining full access to the host environment (Remote Code Execution). Version 0.8.26 patches this vulnerability.



- [https://github.com/Galaxy-sc/CVE-2026-23830-SandBreak](https://github.com/Galaxy-sc/CVE-2026-23830-SandBreak) :  ![starts](https://img.shields.io/github/stars/Galaxy-sc/CVE-2026-23830-SandBreak.svg) ![forks](https://img.shields.io/github/forks/Galaxy-sc/CVE-2026-23830-SandBreak.svg)

## CVE-2026-23829
 Mailpit is an email testing tool and API for developers. Prior to version 1.28.3, Mailpit's SMTP server is vulnerable to Header Injection due to an insufficient Regular Expression used to validate `RCPT TO` and `MAIL FROM` addresses. An attacker can inject arbitrary SMTP headers (or corrupt existing ones) by including carriage return characters (`\r`) in the email address. This header injection occurs because the regex intended to filter control characters fails to exclude `\r` and `\n` when used inside a character class. Version 1.28.3 fixes this issue.



- [https://github.com/SimoesCTT/-CVE-2026-23829-CTT-Mailpit-phase-reconstruction-](https://github.com/SimoesCTT/-CVE-2026-23829-CTT-Mailpit-phase-reconstruction-) :  ![starts](https://img.shields.io/github/stars/SimoesCTT/-CVE-2026-23829-CTT-Mailpit-phase-reconstruction-.svg) ![forks](https://img.shields.io/github/forks/SimoesCTT/-CVE-2026-23829-CTT-Mailpit-phase-reconstruction-.svg)

- [https://github.com/SimoesCTT/CTT-Mailpit-RCE-v1.0---Temporal-Resonance-Mail-Server-Takeover](https://github.com/SimoesCTT/CTT-Mailpit-RCE-v1.0---Temporal-Resonance-Mail-Server-Takeover) :  ![starts](https://img.shields.io/github/stars/SimoesCTT/CTT-Mailpit-RCE-v1.0---Temporal-Resonance-Mail-Server-Takeover.svg) ![forks](https://img.shields.io/github/forks/SimoesCTT/CTT-Mailpit-RCE-v1.0---Temporal-Resonance-Mail-Server-Takeover.svg)

## CVE-2026-23760
 SmarterTools SmarterMail versions prior to build 9511 contain an authentication bypass vulnerability in the password reset API. The force-reset-password endpoint permits anonymous requests and fails to verify the existing password or a reset token when resetting system administrator accounts. An unauthenticated attacker can supply a target administrator username and a new password to reset the account, resulting in full administrative compromise of the SmarterMail instance. NOTE: SmarterMail system administrator privileges grant the ability to execute operating system commands via built-in management functionality, effectively providing administrative (SYSTEM or root) access on the underlying host.



- [https://github.com/hilwa24/CVE-2026-23760_SmarterMail-Auth-Bypass-and-RCE](https://github.com/hilwa24/CVE-2026-23760_SmarterMail-Auth-Bypass-and-RCE) :  ![starts](https://img.shields.io/github/stars/hilwa24/CVE-2026-23760_SmarterMail-Auth-Bypass-and-RCE.svg) ![forks](https://img.shields.io/github/forks/hilwa24/CVE-2026-23760_SmarterMail-Auth-Bypass-and-RCE.svg)

- [https://github.com/MaxMnMl/smartermail-CVE-2026-23760-poc](https://github.com/MaxMnMl/smartermail-CVE-2026-23760-poc) :  ![starts](https://img.shields.io/github/stars/MaxMnMl/smartermail-CVE-2026-23760-poc.svg) ![forks](https://img.shields.io/github/forks/MaxMnMl/smartermail-CVE-2026-23760-poc.svg)

## CVE-2026-23745
 node-tar is a Tar for Node.js. The node-tar library (= 7.5.2) fails to sanitize the linkpath of Link (hardlink) and SymbolicLink entries when preservePaths is false (the default secure behavior). This allows malicious archives to bypass the extraction root restriction, leading to Arbitrary File Overwrite via hardlinks and Symlink Poisoning via absolute symlink targets. This vulnerability is fixed in 7.5.3.



- [https://github.com/Jvr2022/CVE-2026-23745](https://github.com/Jvr2022/CVE-2026-23745) :  ![starts](https://img.shields.io/github/stars/Jvr2022/CVE-2026-23745.svg) ![forks](https://img.shields.io/github/forks/Jvr2022/CVE-2026-23745.svg)

## CVE-2026-23744
 MCPJam inspector is the local-first development platform for MCP servers. Versions 1.4.2 and earlier are vulnerable to remote code execution (RCE) vulnerability, which allows an attacker to send a crafted HTTP request that triggers the installation of an MCP server, leading to RCE. Since MCPJam inspector by default listens on 0.0.0.0 instead of 127.0.0.1, an attacker can trigger the RCE remotely via a simple HTTP request. Version 1.4.3 contains a patch.



- [https://github.com/boroeurnprach/CVE-2026-23744-PoC](https://github.com/boroeurnprach/CVE-2026-23744-PoC) :  ![starts](https://img.shields.io/github/stars/boroeurnprach/CVE-2026-23744-PoC.svg) ![forks](https://img.shields.io/github/forks/boroeurnprach/CVE-2026-23744-PoC.svg)

- [https://github.com/rootdirective-sec/CVE-2026-23744-Lab](https://github.com/rootdirective-sec/CVE-2026-23744-Lab) :  ![starts](https://img.shields.io/github/stars/rootdirective-sec/CVE-2026-23744-Lab.svg) ![forks](https://img.shields.io/github/forks/rootdirective-sec/CVE-2026-23744-Lab.svg)

## CVE-2026-23723
 WeGIA is a web manager for charitable institutions. Prior to 3.6.2, an authenticated SQL Injection vulnerability was identified in the Atendido_ocorrenciaControle endpoint via the id_memorando parameter. This flaw allows for full database exfiltration, exposure of sensitive PII, and potential arbitrary file reads in misconfigured environments. This vulnerability is fixed in 3.6.2.



- [https://github.com/Ch35h1r3c47/CVE-2026-23723-POC](https://github.com/Ch35h1r3c47/CVE-2026-23723-POC) :  ![starts](https://img.shields.io/github/stars/Ch35h1r3c47/CVE-2026-23723-POC.svg) ![forks](https://img.shields.io/github/forks/Ch35h1r3c47/CVE-2026-23723-POC.svg)

## CVE-2026-23550
 Incorrect Privilege Assignment vulnerability in Modular DS allows Privilege Escalation.This issue affects Modular DS: from n/a through 2.5.1.



- [https://github.com/O99099O/By-Poloss..-..CVE-2026-23550](https://github.com/O99099O/By-Poloss..-..CVE-2026-23550) :  ![starts](https://img.shields.io/github/stars/O99099O/By-Poloss..-..CVE-2026-23550.svg) ![forks](https://img.shields.io/github/forks/O99099O/By-Poloss..-..CVE-2026-23550.svg)

- [https://github.com/dzmind2312/Mass-CVE-2026-23550-Exploit](https://github.com/dzmind2312/Mass-CVE-2026-23550-Exploit) :  ![starts](https://img.shields.io/github/stars/dzmind2312/Mass-CVE-2026-23550-Exploit.svg) ![forks](https://img.shields.io/github/forks/dzmind2312/Mass-CVE-2026-23550-Exploit.svg)

- [https://github.com/TheTorjanCaptain/CVE-2026-23550-PoC](https://github.com/TheTorjanCaptain/CVE-2026-23550-PoC) :  ![starts](https://img.shields.io/github/stars/TheTorjanCaptain/CVE-2026-23550-PoC.svg) ![forks](https://img.shields.io/github/forks/TheTorjanCaptain/CVE-2026-23550-PoC.svg)

- [https://github.com/cyberdudebivash/CYBERDUDEBIVASH-Modular-DS-CVE-2026-23550-Detector](https://github.com/cyberdudebivash/CYBERDUDEBIVASH-Modular-DS-CVE-2026-23550-Detector) :  ![starts](https://img.shields.io/github/stars/cyberdudebivash/CYBERDUDEBIVASH-Modular-DS-CVE-2026-23550-Detector.svg) ![forks](https://img.shields.io/github/forks/cyberdudebivash/CYBERDUDEBIVASH-Modular-DS-CVE-2026-23550-Detector.svg)

- [https://github.com/epsilonpoint88-glitch/EpSiLoNPoInT-](https://github.com/epsilonpoint88-glitch/EpSiLoNPoInT-) :  ![starts](https://img.shields.io/github/stars/epsilonpoint88-glitch/EpSiLoNPoInT-.svg) ![forks](https://img.shields.io/github/forks/epsilonpoint88-glitch/EpSiLoNPoInT-.svg)

## CVE-2026-22862
 go-ethereum (geth) is a golang execution layer implementation of the Ethereum protocol. A vulnerable node can be forced to shutdown/crash using a specially crafted message. This vulnerability is fixed in 1.16.8.



- [https://github.com/qzhodl/CVE-2026-22862](https://github.com/qzhodl/CVE-2026-22862) :  ![starts](https://img.shields.io/github/stars/qzhodl/CVE-2026-22862.svg) ![forks](https://img.shields.io/github/forks/qzhodl/CVE-2026-22862.svg)

## CVE-2026-22812
 OpenCode is an open source AI coding agent. Prior to 1.0.216, OpenCode automatically starts an unauthenticated HTTP server that allows any local process (or any website via permissive CORS) to execute arbitrary shell commands with the user's privileges. This vulnerability is fixed in 1.0.216.



- [https://github.com/rohmatariow/CVE-2026-22812-exploit](https://github.com/rohmatariow/CVE-2026-22812-exploit) :  ![starts](https://img.shields.io/github/stars/rohmatariow/CVE-2026-22812-exploit.svg) ![forks](https://img.shields.io/github/forks/rohmatariow/CVE-2026-22812-exploit.svg)

- [https://github.com/barrersoftware/opencode-secure](https://github.com/barrersoftware/opencode-secure) :  ![starts](https://img.shields.io/github/stars/barrersoftware/opencode-secure.svg) ![forks](https://img.shields.io/github/forks/barrersoftware/opencode-secure.svg)

- [https://github.com/Udyz/CVE-2026-22812-Exp](https://github.com/Udyz/CVE-2026-22812-Exp) :  ![starts](https://img.shields.io/github/stars/Udyz/CVE-2026-22812-Exp.svg) ![forks](https://img.shields.io/github/forks/Udyz/CVE-2026-22812-Exp.svg)

- [https://github.com/0xgh057r3c0n/CVE-2026-22812](https://github.com/0xgh057r3c0n/CVE-2026-22812) :  ![starts](https://img.shields.io/github/stars/0xgh057r3c0n/CVE-2026-22812.svg) ![forks](https://img.shields.io/github/forks/0xgh057r3c0n/CVE-2026-22812.svg)

- [https://github.com/mad12wader/CVE-2026-22812](https://github.com/mad12wader/CVE-2026-22812) :  ![starts](https://img.shields.io/github/stars/mad12wader/CVE-2026-22812.svg) ![forks](https://img.shields.io/github/forks/mad12wader/CVE-2026-22812.svg)

- [https://github.com/CayberMods/CVE-2026-22812-POC](https://github.com/CayberMods/CVE-2026-22812-POC) :  ![starts](https://img.shields.io/github/stars/CayberMods/CVE-2026-22812-POC.svg) ![forks](https://img.shields.io/github/forks/CayberMods/CVE-2026-22812-POC.svg)

## CVE-2026-22807
 vLLM is an inference and serving engine for large language models (LLMs). Starting in version 0.10.1 and prior to version 0.14.0, vLLM loads Hugging Face `auto_map` dynamic modules during model resolution without gating on `trust_remote_code`, allowing attacker-controlled Python code in a model repo/path to execute at server startup. An attacker who can influence the model repo/path (local directory or remote Hugging Face repo) can achieve arbitrary code execution on the vLLM host during model load. This happens before any request handling and does not require API access. Version 0.14.0 fixes the issue.



- [https://github.com/otakuliu/CVE-2026-22807_Range](https://github.com/otakuliu/CVE-2026-22807_Range) :  ![starts](https://img.shields.io/github/stars/otakuliu/CVE-2026-22807_Range.svg) ![forks](https://img.shields.io/github/forks/otakuliu/CVE-2026-22807_Range.svg)

## CVE-2026-22804
 Termix is a web-based server management platform with SSH terminal, tunneling, and file editing capabilities. From 1.7.0 to 1.9.0, Stored Cross-Site Scripting (XSS) vulnerability exists in the Termix File Manager component. The application fails to sanitize SVG file content before rendering it. This allows an attacker who has compromised a managed SSH server to plant a malicious file, which, when previewed by the Termix user, executes arbitrary JavaScript in the context of the application. The vulnerability is located in src/ui/desktop/apps/file-manager/components/FileViewer.tsx. This vulnerability is fixed in 1.10.0.



- [https://github.com/ThemeHackers/CVE-2026-22804](https://github.com/ThemeHackers/CVE-2026-22804) :  ![starts](https://img.shields.io/github/stars/ThemeHackers/CVE-2026-22804.svg) ![forks](https://img.shields.io/github/forks/ThemeHackers/CVE-2026-22804.svg)

## CVE-2026-22794
 Appsmith is a platform to build admin panels, internal tools, and dashboards. Prior to 1.93, the server uses the Origin value from the request headers as the email link baseUrl without validation. If an attacker controls the Origin, password reset / email verification links in emails can be generated pointing to the attacker’s domain, causing authentication tokens to be exposed and potentially leading to account takeover. This vulnerability is fixed in 1.93.



- [https://github.com/MalikHamza7/CVE-2026-22794-POC](https://github.com/MalikHamza7/CVE-2026-22794-POC) :  ![starts](https://img.shields.io/github/stars/MalikHamza7/CVE-2026-22794-POC.svg) ![forks](https://img.shields.io/github/forks/MalikHamza7/CVE-2026-22794-POC.svg)

## CVE-2026-22785
 orval generates type-safe JS clients (TypeScript) from any valid OpenAPI v3 or Swagger v2 specification. Prior to 7.18.0, the MCP server generation logic relies on string manipulation that incorporates the summary field from the OpenAPI specification without proper validation or escaping. This allows an attacker to "break out" of the string literal and inject arbitrary code. This vulnerability is fixed in 7.18.0.



- [https://github.com/langbyyi/CVE-2026-22785](https://github.com/langbyyi/CVE-2026-22785) :  ![starts](https://img.shields.io/github/stars/langbyyi/CVE-2026-22785.svg) ![forks](https://img.shields.io/github/forks/langbyyi/CVE-2026-22785.svg)

## CVE-2026-22686
 Enclave is a secure JavaScript sandbox designed for safe AI agent code execution. Prior to 2.7.0, there is a critical sandbox escape vulnerability in enclave-vm that allows untrusted, sandboxed JavaScript code to execute arbitrary code in the host Node.js runtime. When a tool invocation fails, enclave-vm exposes a host-side Error object to sandboxed code. This Error object retains its host realm prototype chain, which can be traversed to reach the host Function constructor. An attacker can intentionally trigger a host error, then climb the prototype chain. Using the host Function constructor, arbitrary JavaScript can be compiled and executed in the host context, fully bypassing the sandbox and granting access to sensitive resources such as process.env, filesystem, and network. This breaks enclave-vm’s core security guarantee of isolating untrusted code. This vulnerability is fixed in 2.7.0.



- [https://github.com/amusedx/CVE-2026-22686](https://github.com/amusedx/CVE-2026-22686) :  ![starts](https://img.shields.io/github/stars/amusedx/CVE-2026-22686.svg) ![forks](https://img.shields.io/github/forks/amusedx/CVE-2026-22686.svg)

## CVE-2026-22610
 Angular is a development platform for building mobile and desktop web applications using TypeScript/JavaScript and other languages. Prior to versions 19.2.18, 20.3.16, 21.0.7, and 21.1.0-rc.0, a cross-site scripting (XSS) vulnerability has been identified in the Angular Template Compiler. The vulnerability exists because Angular’s internal sanitization schema fails to recognize the href and xlink:href attributes of SVG script elements as a Resource URL context. This issue has been patched in versions 19.2.18, 20.3.16, 21.0.7, and 21.1.0-rc.0.



- [https://github.com/ashizZz/CVE-2026-22610](https://github.com/ashizZz/CVE-2026-22610) :  ![starts](https://img.shields.io/github/stars/ashizZz/CVE-2026-22610.svg) ![forks](https://img.shields.io/github/forks/ashizZz/CVE-2026-22610.svg)

## CVE-2026-22444
 The "create core" API of Apache Solr 8.6 through 9.10.0 lacks sufficient input validation on some API parameters, which can cause Solr to check the existence of and attempt to read file-system paths that should be disallowed by Solr's  "allowPaths" security setting https://https://solr.apache.org/guide/solr/latest/configuration-guide/configuring-solr-xml.html#the-solr-element .  These read-only accesses can allow users to create cores using unexpected configsets if any are accessible via the filesystem.  On Windows systems configured to allow UNC paths this can additionally cause disclosure of NTLM "user" hashes. 

Solr deployments are subject to this vulnerability if they meet the following criteria:
  *  Solr is running in its "standalone" mode.
  *  Solr's "allowPath" setting is being used to restrict file access to certain directories.
  *  Solr's "create core" API is exposed and accessible to untrusted users.  This can happen if Solr's  RuleBasedAuthorizationPlugin https://solr.apache.org/guide/solr/latest/deployment-guide/rule-based-authorization-plugin.html  is disabled, or if it is enabled but the "core-admin-edit" predefined permission (or an equivalent custom permission) is given to low-trust (i.e. non-admin) user roles.

Users can mitigate this by enabling Solr's RuleBasedAuthorizationPlugin (if disabled) and configuring a permission-list that prevents untrusted users from creating new Solr cores.  Users should also upgrade to Apache Solr 9.10.1 or greater, which contain fixes for this issue.



- [https://github.com/dptsec/CVE-2026-22444](https://github.com/dptsec/CVE-2026-22444) :  ![starts](https://img.shields.io/github/stars/dptsec/CVE-2026-22444.svg) ![forks](https://img.shields.io/github/forks/dptsec/CVE-2026-22444.svg)

- [https://github.com/bfdfhdsfdd-crypto/CVE-2026-22444](https://github.com/bfdfhdsfdd-crypto/CVE-2026-22444) :  ![starts](https://img.shields.io/github/stars/bfdfhdsfdd-crypto/CVE-2026-22444.svg) ![forks](https://img.shields.io/github/forks/bfdfhdsfdd-crypto/CVE-2026-22444.svg)

## CVE-2026-22241
 The Open eClass platform (formerly known as GUnet eClass) is a complete course management system. Prior to version 4.2, an arbitrary file upload vulnerability in the theme import functionality enables an attacker with administrative privileges to upload arbitrary files on the server's file system. The main cause of the issue is that no validation or sanitization of the file's present inside the zip archive. This leads to remote code execution on the web server. Version 4.2 patches the issue.



- [https://github.com/Ashifcoder/CVE-2026-22241](https://github.com/Ashifcoder/CVE-2026-22241) :  ![starts](https://img.shields.io/github/stars/Ashifcoder/CVE-2026-22241.svg) ![forks](https://img.shields.io/github/forks/Ashifcoder/CVE-2026-22241.svg)

## CVE-2026-22200
 Enhancesoft osTicket versions 1.18.x prior to 1.18.3 and 1.17.x prior to 1.17.7 contain an arbitrary file read vulnerability in the ticket PDF export functionality. A remote attacker can submit a ticket containing crafted rich-text HTML that includes PHP filter expressions which are insufficiently sanitized before being processed by the mPDF PDF generator during export. When the attacker exports the ticket to PDF, the generated PDF can embed the contents of attacker-selected files from the server filesystem as bitmap images, allowing disclosure of sensitive local files in the context of the osTicket application user. This issue is exploitable in default configurations where guests may create tickets and access ticket status, or where self-registration is enabled.



- [https://github.com/horizon3ai/CVE-2026-22200](https://github.com/horizon3ai/CVE-2026-22200) :  ![starts](https://img.shields.io/github/stars/horizon3ai/CVE-2026-22200.svg) ![forks](https://img.shields.io/github/forks/horizon3ai/CVE-2026-22200.svg)

## CVE-2026-22187
 Bio-Formats versions up to and including 8.3.0 perform unsafe Java deserialization of attacker-controlled memoization cache files (.bfmemo) during image processing. The loci.formats.Memoizer class automatically loads and deserializes memo files associated with images without validation, integrity checks, or trust enforcement. An attacker who can supply a crafted .bfmemo file alongside an image can trigger deserialization of untrusted data, which may result in denial of service, logic manipulation, or potentially remote code execution in environments where suitable gadget chains are present on the classpath.



- [https://github.com/George0Papasotiriou/CVE-2026-22187-Bio-Formats-unsafe-Java-deserialization-via-.bfmemo](https://github.com/George0Papasotiriou/CVE-2026-22187-Bio-Formats-unsafe-Java-deserialization-via-.bfmemo) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2026-22187-Bio-Formats-unsafe-Java-deserialization-via-.bfmemo.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2026-22187-Bio-Formats-unsafe-Java-deserialization-via-.bfmemo.svg)

## CVE-2026-22153
 An Authentication Bypass by Primary Weakness vulnerability [CWE-305] vulnerability in Fortinet FortiOS 7.6.0 through 7.6.4 may allow an unauthenticated attacker to bypass LDAP authentication of Agentless VPN or FSSO policy, when the remote LDAP server is configured in a specific way.



- [https://github.com/glitchhawks/CVE-2026-22153](https://github.com/glitchhawks/CVE-2026-22153) :  ![starts](https://img.shields.io/github/stars/glitchhawks/CVE-2026-22153.svg) ![forks](https://img.shields.io/github/forks/glitchhawks/CVE-2026-22153.svg)

- [https://github.com/washingtonmaister/CVE-2026-22153-exp](https://github.com/washingtonmaister/CVE-2026-22153-exp) :  ![starts](https://img.shields.io/github/stars/washingtonmaister/CVE-2026-22153-exp.svg) ![forks](https://img.shields.io/github/forks/washingtonmaister/CVE-2026-22153-exp.svg)

## CVE-2026-21962
 Vulnerability in the Oracle HTTP Server, Oracle Weblogic Server Proxy Plug-in product of Oracle Fusion Middleware (component: Weblogic Server Proxy Plug-in for Apache HTTP Server, Weblogic Server Proxy Plug-in for IIS).  Supported versions that are affected are 12.2.1.4.0, 14.1.1.0.0 and  14.1.2.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle HTTP Server, Oracle Weblogic Server Proxy Plug-in.  While the vulnerability is in Oracle HTTP Server, Oracle Weblogic Server Proxy Plug-in, attacks may significantly impact additional products (scope change).  Successful attacks of this vulnerability can result in  unauthorized creation, deletion or modification access to critical data or all Oracle HTTP Server, Oracle Weblogic Server Proxy Plug-in accessible data as well as  unauthorized access to critical data or complete access to all Oracle HTTP Server, Oracle Weblogic Server Proxy Plug-in accessible data. Note: Affected version for Weblogic Server Proxy Plug-in for IIS is 12.2.1.4.0 only. CVSS 3.1 Base Score 10.0 (Confidentiality and Integrity impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N).



- [https://github.com/samael0x4/CVE-2026-21962](https://github.com/samael0x4/CVE-2026-21962) :  ![starts](https://img.shields.io/github/stars/samael0x4/CVE-2026-21962.svg) ![forks](https://img.shields.io/github/forks/samael0x4/CVE-2026-21962.svg)

- [https://github.com/boroeurnprach/Ashwesker-CVE-2026-21962](https://github.com/boroeurnprach/Ashwesker-CVE-2026-21962) :  ![starts](https://img.shields.io/github/stars/boroeurnprach/Ashwesker-CVE-2026-21962.svg) ![forks](https://img.shields.io/github/forks/boroeurnprach/Ashwesker-CVE-2026-21962.svg)

- [https://github.com/George0Papasotiriou/CVE-2026-21962-Oracle-HTTP-Server-WebLogic-Proxy-Plug-in-Critical-](https://github.com/George0Papasotiriou/CVE-2026-21962-Oracle-HTTP-Server-WebLogic-Proxy-Plug-in-Critical-) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2026-21962-Oracle-HTTP-Server-WebLogic-Proxy-Plug-in-Critical-.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2026-21962-Oracle-HTTP-Server-WebLogic-Proxy-Plug-in-Critical-.svg)

- [https://github.com/ThumpBo/CVE-2026-21962](https://github.com/ThumpBo/CVE-2026-21962) :  ![starts](https://img.shields.io/github/stars/ThumpBo/CVE-2026-21962.svg) ![forks](https://img.shields.io/github/forks/ThumpBo/CVE-2026-21962.svg)

- [https://github.com/gregk4sec/CVE-2026-21962](https://github.com/gregk4sec/CVE-2026-21962) :  ![starts](https://img.shields.io/github/stars/gregk4sec/CVE-2026-21962.svg) ![forks](https://img.shields.io/github/forks/gregk4sec/CVE-2026-21962.svg)

- [https://github.com/gglessner/cve_2026_21962_scanner](https://github.com/gglessner/cve_2026_21962_scanner) :  ![starts](https://img.shields.io/github/stars/gglessner/cve_2026_21962_scanner.svg) ![forks](https://img.shields.io/github/forks/gglessner/cve_2026_21962_scanner.svg)

## CVE-2026-21876
 The OWASP core rule set (CRS) is a set of generic attack detection rules for use with compatible web application firewalls. Prior to versions 4.22.0 and 3.3.8, the current rule 922110 has a bug when processing multipart requests with multiple parts. When the first rule in a chain iterates over a collection (like `MULTIPART_PART_HEADERS`), the capture variables (`TX:0`, `TX:1`) get overwritten with each iteration. Only the last captured value is available to the chained rule, which means malicious charsets in earlier parts can be missed if a later part has a legitimate charset. Versions 4.22.0 and 3.3.8 patch the issue.



- [https://github.com/daytriftnewgen/CVE-2026-21876](https://github.com/daytriftnewgen/CVE-2026-21876) :  ![starts](https://img.shields.io/github/stars/daytriftnewgen/CVE-2026-21876.svg) ![forks](https://img.shields.io/github/forks/daytriftnewgen/CVE-2026-21876.svg)

## CVE-2026-21858
 n8n is an open source workflow automation platform. Versions starting with 1.65.0 and below 1.121.0 enable an attacker to access files on the underlying server through execution of certain form-based workflows. A vulnerable workflow could grant access to an unauthenticated remote attacker, resulting in exposure of sensitive information stored on the system and may enable further compromise depending on deployment configuration and workflow usage. This issue is fixed in version 1.121.0.



- [https://github.com/Chocapikk/CVE-2026-21858](https://github.com/Chocapikk/CVE-2026-21858) :  ![starts](https://img.shields.io/github/stars/Chocapikk/CVE-2026-21858.svg) ![forks](https://img.shields.io/github/forks/Chocapikk/CVE-2026-21858.svg)

- [https://github.com/SystemVll/CVE-2026-21858](https://github.com/SystemVll/CVE-2026-21858) :  ![starts](https://img.shields.io/github/stars/SystemVll/CVE-2026-21858.svg) ![forks](https://img.shields.io/github/forks/SystemVll/CVE-2026-21858.svg)

- [https://github.com/EQSTLab/CVE-2026-21858](https://github.com/EQSTLab/CVE-2026-21858) :  ![starts](https://img.shields.io/github/stars/EQSTLab/CVE-2026-21858.svg) ![forks](https://img.shields.io/github/forks/EQSTLab/CVE-2026-21858.svg)

- [https://github.com/bgarz929/Ashwesker-CVE-2026-21858](https://github.com/bgarz929/Ashwesker-CVE-2026-21858) :  ![starts](https://img.shields.io/github/stars/bgarz929/Ashwesker-CVE-2026-21858.svg) ![forks](https://img.shields.io/github/forks/bgarz929/Ashwesker-CVE-2026-21858.svg)

- [https://github.com/Alhakim88/CVE-2026-21858](https://github.com/Alhakim88/CVE-2026-21858) :  ![starts](https://img.shields.io/github/stars/Alhakim88/CVE-2026-21858.svg) ![forks](https://img.shields.io/github/forks/Alhakim88/CVE-2026-21858.svg)

- [https://github.com/sec-dojo-com/CVE-2026-21858](https://github.com/sec-dojo-com/CVE-2026-21858) :  ![starts](https://img.shields.io/github/stars/sec-dojo-com/CVE-2026-21858.svg) ![forks](https://img.shields.io/github/forks/sec-dojo-com/CVE-2026-21858.svg)

- [https://github.com/sastraadiwiguna-purpleeliteteaming/SASTRA-ADI-WIGUNA-CVE-2026-21858-Holistic-Audit](https://github.com/sastraadiwiguna-purpleeliteteaming/SASTRA-ADI-WIGUNA-CVE-2026-21858-Holistic-Audit) :  ![starts](https://img.shields.io/github/stars/sastraadiwiguna-purpleeliteteaming/SASTRA-ADI-WIGUNA-CVE-2026-21858-Holistic-Audit.svg) ![forks](https://img.shields.io/github/forks/sastraadiwiguna-purpleeliteteaming/SASTRA-ADI-WIGUNA-CVE-2026-21858-Holistic-Audit.svg)

- [https://github.com/cropnet/Ni8mare](https://github.com/cropnet/Ni8mare) :  ![starts](https://img.shields.io/github/stars/cropnet/Ni8mare.svg) ![forks](https://img.shields.io/github/forks/cropnet/Ni8mare.svg)

## CVE-2026-21721
 The dashboard permissions API does not verify the target dashboard scope and only checks the dashboards.permissions:* action. As a result, a user who has permission management rights on one dashboard can read and modify permissions on other dashboards. This is an organization‑internal privilege escalation.



- [https://github.com/Leonideath/Exploit-LPE-CVE-2026-21721](https://github.com/Leonideath/Exploit-LPE-CVE-2026-21721) :  ![starts](https://img.shields.io/github/stars/Leonideath/Exploit-LPE-CVE-2026-21721.svg) ![forks](https://img.shields.io/github/forks/Leonideath/Exploit-LPE-CVE-2026-21721.svg)

## CVE-2026-21533
 Improper privilege management in Windows Remote Desktop allows an authorized attacker to elevate privileges locally.



- [https://github.com/elvin31thai/CVE-2026-21533](https://github.com/elvin31thai/CVE-2026-21533) :  ![starts](https://img.shields.io/github/stars/elvin31thai/CVE-2026-21533.svg) ![forks](https://img.shields.io/github/forks/elvin31thai/CVE-2026-21533.svg)

- [https://github.com/jenniferreire26/CVE-2026-21533](https://github.com/jenniferreire26/CVE-2026-21533) :  ![starts](https://img.shields.io/github/stars/jenniferreire26/CVE-2026-21533.svg) ![forks](https://img.shields.io/github/forks/jenniferreire26/CVE-2026-21533.svg)

- [https://github.com/Pairs34/RDPVulnarableCheck](https://github.com/Pairs34/RDPVulnarableCheck) :  ![starts](https://img.shields.io/github/stars/Pairs34/RDPVulnarableCheck.svg) ![forks](https://img.shields.io/github/forks/Pairs34/RDPVulnarableCheck.svg)

- [https://github.com/washingtonmaister/CVE-2026-21533](https://github.com/washingtonmaister/CVE-2026-21533) :  ![starts](https://img.shields.io/github/stars/washingtonmaister/CVE-2026-21533.svg) ![forks](https://img.shields.io/github/forks/washingtonmaister/CVE-2026-21533.svg)

- [https://github.com/richardpaimu34/CVE-2026-21533](https://github.com/richardpaimu34/CVE-2026-21533) :  ![starts](https://img.shields.io/github/stars/richardpaimu34/CVE-2026-21533.svg) ![forks](https://img.shields.io/github/forks/richardpaimu34/CVE-2026-21533.svg)

## CVE-2026-21531
 Deserialization of untrusted data in Azure SDK allows an unauthorized attacker to execute code over a network.



- [https://github.com/NetVanguard-cmd/CVE-2026-21531](https://github.com/NetVanguard-cmd/CVE-2026-21531) :  ![starts](https://img.shields.io/github/stars/NetVanguard-cmd/CVE-2026-21531.svg) ![forks](https://img.shields.io/github/forks/NetVanguard-cmd/CVE-2026-21531.svg)

## CVE-2026-21510
 Protection mechanism failure in Windows Shell allows an unauthorized attacker to bypass a security feature over a network.



- [https://github.com/andreassudo/CVE-2026-21510-CVSS-8.8-Important-Windows-Shell-security-feature-bypass](https://github.com/andreassudo/CVE-2026-21510-CVSS-8.8-Important-Windows-Shell-security-feature-bypass) :  ![starts](https://img.shields.io/github/stars/andreassudo/CVE-2026-21510-CVSS-8.8-Important-Windows-Shell-security-feature-bypass.svg) ![forks](https://img.shields.io/github/forks/andreassudo/CVE-2026-21510-CVSS-8.8-Important-Windows-Shell-security-feature-bypass.svg)

## CVE-2026-21509
 Reliance on untrusted inputs in a security decision in Microsoft Office allows an unauthorized attacker to bypass a security feature locally.



- [https://github.com/gavz/CVE-2026-21509-PoC](https://github.com/gavz/CVE-2026-21509-PoC) :  ![starts](https://img.shields.io/github/stars/gavz/CVE-2026-21509-PoC.svg) ![forks](https://img.shields.io/github/forks/gavz/CVE-2026-21509-PoC.svg)

- [https://github.com/kimstars/Ashwesker-CVE-2026-21509](https://github.com/kimstars/Ashwesker-CVE-2026-21509) :  ![starts](https://img.shields.io/github/stars/kimstars/Ashwesker-CVE-2026-21509.svg) ![forks](https://img.shields.io/github/forks/kimstars/Ashwesker-CVE-2026-21509.svg)

- [https://github.com/SimoesCTT/CTT-MICROSOFT-OFFICE-OLE-MANIFOLD-BYPASS-CVE-2026-21509](https://github.com/SimoesCTT/CTT-MICROSOFT-OFFICE-OLE-MANIFOLD-BYPASS-CVE-2026-21509) :  ![starts](https://img.shields.io/github/stars/SimoesCTT/CTT-MICROSOFT-OFFICE-OLE-MANIFOLD-BYPASS-CVE-2026-21509.svg) ![forks](https://img.shields.io/github/forks/SimoesCTT/CTT-MICROSOFT-OFFICE-OLE-MANIFOLD-BYPASS-CVE-2026-21509.svg)

- [https://github.com/SimoesCTT/CTT-NFS-Vortex-RCE](https://github.com/SimoesCTT/CTT-NFS-Vortex-RCE) :  ![starts](https://img.shields.io/github/stars/SimoesCTT/CTT-NFS-Vortex-RCE.svg) ![forks](https://img.shields.io/github/forks/SimoesCTT/CTT-NFS-Vortex-RCE.svg)

- [https://github.com/decalage2/detect_CVE-2026-21509](https://github.com/decalage2/detect_CVE-2026-21509) :  ![starts](https://img.shields.io/github/stars/decalage2/detect_CVE-2026-21509.svg) ![forks](https://img.shields.io/github/forks/decalage2/detect_CVE-2026-21509.svg)

- [https://github.com/ksk-itdk/KSK-ITDK-CVE-2026-21509-Mitigation](https://github.com/ksk-itdk/KSK-ITDK-CVE-2026-21509-Mitigation) :  ![starts](https://img.shields.io/github/stars/ksk-itdk/KSK-ITDK-CVE-2026-21509-Mitigation.svg) ![forks](https://img.shields.io/github/forks/ksk-itdk/KSK-ITDK-CVE-2026-21509-Mitigation.svg)

- [https://github.com/SimoesCTT/SCTT-2026-33-0007-The-OLE-Vortex-Laminar-Bypass-](https://github.com/SimoesCTT/SCTT-2026-33-0007-The-OLE-Vortex-Laminar-Bypass-) :  ![starts](https://img.shields.io/github/stars/SimoesCTT/SCTT-2026-33-0007-The-OLE-Vortex-Laminar-Bypass-.svg) ![forks](https://img.shields.io/github/forks/SimoesCTT/SCTT-2026-33-0007-The-OLE-Vortex-Laminar-Bypass-.svg)

- [https://github.com/planetoid/cve-2026-21509-mitigation](https://github.com/planetoid/cve-2026-21509-mitigation) :  ![starts](https://img.shields.io/github/stars/planetoid/cve-2026-21509-mitigation.svg) ![forks](https://img.shields.io/github/forks/planetoid/cve-2026-21509-mitigation.svg)

- [https://github.com/kaizensecurity/CVE-2026-21509](https://github.com/kaizensecurity/CVE-2026-21509) :  ![starts](https://img.shields.io/github/stars/kaizensecurity/CVE-2026-21509.svg) ![forks](https://img.shields.io/github/forks/kaizensecurity/CVE-2026-21509.svg)

## CVE-2026-21508
 Improper authentication in Windows Storage allows an authorized attacker to elevate privileges locally.



- [https://github.com/0xc4r/CVE-2026-21508_POC](https://github.com/0xc4r/CVE-2026-21508_POC) :  ![starts](https://img.shields.io/github/stars/0xc4r/CVE-2026-21508_POC.svg) ![forks](https://img.shields.io/github/forks/0xc4r/CVE-2026-21508_POC.svg)

## CVE-2026-21445
 Langflow is a tool for building and deploying AI-powered agents and workflows. Prior to version 1.7.0.dev45, multiple critical API endpoints in Langflow are missing authentication controls. The issue allows any unauthenticated user to access sensitive user conversation data, transaction histories, and perform destructive operations including message deletion. This affects endpoints handling personal data and system operations that should require proper authorization. Version 1.7.0.dev45 contains a patch.



- [https://github.com/chinaxploiter/CVE-2026-21445-PoC](https://github.com/chinaxploiter/CVE-2026-21445-PoC) :  ![starts](https://img.shields.io/github/stars/chinaxploiter/CVE-2026-21445-PoC.svg) ![forks](https://img.shields.io/github/forks/chinaxploiter/CVE-2026-21445-PoC.svg)

## CVE-2026-21440
 AdonisJS is a TypeScript-first web framework. A Path Traversal vulnerability in AdonisJS multipart file handling may allow a remote attacker to write arbitrary files to arbitrary locations on the server filesystem. This impacts @adonisjs/bodyparser through version 10.1.1 and 11.x prerelease versions prior to 11.0.0-next.6. This issue has been patched in @adonisjs/bodyparser versions 10.1.2 and 11.0.0-next.6.



- [https://github.com/k0nnect/cve-2026-21440-writeup-poc](https://github.com/k0nnect/cve-2026-21440-writeup-poc) :  ![starts](https://img.shields.io/github/stars/k0nnect/cve-2026-21440-writeup-poc.svg) ![forks](https://img.shields.io/github/forks/k0nnect/cve-2026-21440-writeup-poc.svg)

- [https://github.com/you-ssef9/CVE-2026-21440](https://github.com/you-ssef9/CVE-2026-21440) :  ![starts](https://img.shields.io/github/stars/you-ssef9/CVE-2026-21440.svg) ![forks](https://img.shields.io/github/forks/you-ssef9/CVE-2026-21440.svg)

- [https://github.com/redpack-kr/Ashwesker-CVE-2026-21440](https://github.com/redpack-kr/Ashwesker-CVE-2026-21440) :  ![starts](https://img.shields.io/github/stars/redpack-kr/Ashwesker-CVE-2026-21440.svg) ![forks](https://img.shields.io/github/forks/redpack-kr/Ashwesker-CVE-2026-21440.svg)

- [https://github.com/TibbersV6/CVE-2026-21440-POC-EXP](https://github.com/TibbersV6/CVE-2026-21440-POC-EXP) :  ![starts](https://img.shields.io/github/stars/TibbersV6/CVE-2026-21440-POC-EXP.svg) ![forks](https://img.shields.io/github/forks/TibbersV6/CVE-2026-21440-POC-EXP.svg)

## CVE-2026-21437
 eopkg is a Solus package manager implemented in python3. In versions prior to 4.4.0, a malicious package could include files that are not tracked by `eopkg`. This requires the installation of a package from a malicious or compromised source. Files in such packages would not be shown by `lseopkg` and related tools. The issue has been fixed in v4.4.0. Users only installing packages from the Solus repositories are not affected.



- [https://github.com/osmancanvural/CVE-2026-21437](https://github.com/osmancanvural/CVE-2026-21437) :  ![starts](https://img.shields.io/github/stars/osmancanvural/CVE-2026-21437.svg) ![forks](https://img.shields.io/github/forks/osmancanvural/CVE-2026-21437.svg)

## CVE-2026-21436
 eopkg is a Solus package manager implemented in python3. In versions prior to 4.4.0, a malicious package could escape the directory set by `--destdir`. This requires the installation of a package from a malicious or compromised source. Files in such packages would not be installed in the path given by `--destdir`, but on a different location on the host. The issue has been fixed in v4.4.0. Users only installing packages from the Solus repositories are not affected.



- [https://github.com/osmancanvural/CVE-2026-21436](https://github.com/osmancanvural/CVE-2026-21436) :  ![starts](https://img.shields.io/github/stars/osmancanvural/CVE-2026-21436.svg) ![forks](https://img.shields.io/github/forks/osmancanvural/CVE-2026-21436.svg)

## CVE-2026-20871
 Use after free in Desktop Windows Manager allows an authorized attacker to elevate privileges locally.



- [https://github.com/SimoesCTT/-SCTT-2026-33-0002-DWM-Visual-Field-Singularity](https://github.com/SimoesCTT/-SCTT-2026-33-0002-DWM-Visual-Field-Singularity) :  ![starts](https://img.shields.io/github/stars/SimoesCTT/-SCTT-2026-33-0002-DWM-Visual-Field-Singularity.svg) ![forks](https://img.shields.io/github/forks/SimoesCTT/-SCTT-2026-33-0002-DWM-Visual-Field-Singularity.svg)

- [https://github.com/SimoesCTT/SCTT-2026-33-0002-DWM-Visual-Field-Singularity](https://github.com/SimoesCTT/SCTT-2026-33-0002-DWM-Visual-Field-Singularity) :  ![starts](https://img.shields.io/github/stars/SimoesCTT/SCTT-2026-33-0002-DWM-Visual-Field-Singularity.svg) ![forks](https://img.shields.io/github/forks/SimoesCTT/SCTT-2026-33-0002-DWM-Visual-Field-Singularity.svg)

## CVE-2026-20841
 Improper neutralization of special elements used in a command ('command injection') in Windows Notepad App allows an unauthorized attacker to execute code locally.



- [https://github.com/BTtea/CVE-2026-20841-PoC](https://github.com/BTtea/CVE-2026-20841-PoC) :  ![starts](https://img.shields.io/github/stars/BTtea/CVE-2026-20841-PoC.svg) ![forks](https://img.shields.io/github/forks/BTtea/CVE-2026-20841-PoC.svg)

- [https://github.com/patchpoint/CVE-2026-20841](https://github.com/patchpoint/CVE-2026-20841) :  ![starts](https://img.shields.io/github/stars/patchpoint/CVE-2026-20841.svg) ![forks](https://img.shields.io/github/forks/patchpoint/CVE-2026-20841.svg)

- [https://github.com/atiilla/CVE-2026-20841](https://github.com/atiilla/CVE-2026-20841) :  ![starts](https://img.shields.io/github/stars/atiilla/CVE-2026-20841.svg) ![forks](https://img.shields.io/github/forks/atiilla/CVE-2026-20841.svg)

- [https://github.com/dogukankurnaz/CVE-2026-20841-PoC](https://github.com/dogukankurnaz/CVE-2026-20841-PoC) :  ![starts](https://img.shields.io/github/stars/dogukankurnaz/CVE-2026-20841-PoC.svg) ![forks](https://img.shields.io/github/forks/dogukankurnaz/CVE-2026-20841-PoC.svg)

- [https://github.com/uky007/CVE-2026-20841_notepad_analysis](https://github.com/uky007/CVE-2026-20841_notepad_analysis) :  ![starts](https://img.shields.io/github/stars/uky007/CVE-2026-20841_notepad_analysis.svg) ![forks](https://img.shields.io/github/forks/uky007/CVE-2026-20841_notepad_analysis.svg)

- [https://github.com/SecureWithUmer/CVE-2026-20841](https://github.com/SecureWithUmer/CVE-2026-20841) :  ![starts](https://img.shields.io/github/stars/SecureWithUmer/CVE-2026-20841.svg) ![forks](https://img.shields.io/github/forks/SecureWithUmer/CVE-2026-20841.svg)

- [https://github.com/tangent65536/CVE-2026-20841](https://github.com/tangent65536/CVE-2026-20841) :  ![starts](https://img.shields.io/github/stars/tangent65536/CVE-2026-20841.svg) ![forks](https://img.shields.io/github/forks/tangent65536/CVE-2026-20841.svg)

- [https://github.com/hackfaiz/CVE-2026-20841-PoC](https://github.com/hackfaiz/CVE-2026-20841-PoC) :  ![starts](https://img.shields.io/github/stars/hackfaiz/CVE-2026-20841-PoC.svg) ![forks](https://img.shields.io/github/forks/hackfaiz/CVE-2026-20841-PoC.svg)

- [https://github.com/RajaUzairAbdullah/CVE-2026-20841](https://github.com/RajaUzairAbdullah/CVE-2026-20841) :  ![starts](https://img.shields.io/github/stars/RajaUzairAbdullah/CVE-2026-20841.svg) ![forks](https://img.shields.io/github/forks/RajaUzairAbdullah/CVE-2026-20841.svg)

- [https://github.com/EleniChristopoulou/PoC-CVE-2026-20841](https://github.com/EleniChristopoulou/PoC-CVE-2026-20841) :  ![starts](https://img.shields.io/github/stars/EleniChristopoulou/PoC-CVE-2026-20841.svg) ![forks](https://img.shields.io/github/forks/EleniChristopoulou/PoC-CVE-2026-20841.svg)

## CVE-2026-20817
 Improper handling of insufficient permissions or privileges in Windows Error Reporting allows an authorized attacker to elevate privileges locally.



- [https://github.com/oxfemale/CVE-2026-20817](https://github.com/oxfemale/CVE-2026-20817) :  ![starts](https://img.shields.io/github/stars/oxfemale/CVE-2026-20817.svg) ![forks](https://img.shields.io/github/forks/oxfemale/CVE-2026-20817.svg)

## CVE-2026-20805
 Exposure of sensitive information to an unauthorized actor in Desktop Windows Manager allows an authorized attacker to disclose information locally.



- [https://github.com/fevar54/CVE-2026-20805-POC](https://github.com/fevar54/CVE-2026-20805-POC) :  ![starts](https://img.shields.io/github/stars/fevar54/CVE-2026-20805-POC.svg) ![forks](https://img.shields.io/github/forks/fevar54/CVE-2026-20805-POC.svg)

- [https://github.com/Uzair-Baig0900/CVE-2026-20805-PoC](https://github.com/Uzair-Baig0900/CVE-2026-20805-PoC) :  ![starts](https://img.shields.io/github/stars/Uzair-Baig0900/CVE-2026-20805-PoC.svg) ![forks](https://img.shields.io/github/forks/Uzair-Baig0900/CVE-2026-20805-PoC.svg)

- [https://github.com/mrk336/Inside-CVE-2026-20805-How-a-Windows-DWM-Flaw-Exposed-Sensitive-Data](https://github.com/mrk336/Inside-CVE-2026-20805-How-a-Windows-DWM-Flaw-Exposed-Sensitive-Data) :  ![starts](https://img.shields.io/github/stars/mrk336/Inside-CVE-2026-20805-How-a-Windows-DWM-Flaw-Exposed-Sensitive-Data.svg) ![forks](https://img.shields.io/github/forks/mrk336/Inside-CVE-2026-20805-How-a-Windows-DWM-Flaw-Exposed-Sensitive-Data.svg)

- [https://github.com/SimoesCTT/-SCTT-2026-33-0002-DWM-Visual-Field-Singularity](https://github.com/SimoesCTT/-SCTT-2026-33-0002-DWM-Visual-Field-Singularity) :  ![starts](https://img.shields.io/github/stars/SimoesCTT/-SCTT-2026-33-0002-DWM-Visual-Field-Singularity.svg) ![forks](https://img.shields.io/github/forks/SimoesCTT/-SCTT-2026-33-0002-DWM-Visual-Field-Singularity.svg)

- [https://github.com/SimoesCTT/SCTT-2026-33-0002-DWM-Visual-Field-Singularity](https://github.com/SimoesCTT/SCTT-2026-33-0002-DWM-Visual-Field-Singularity) :  ![starts](https://img.shields.io/github/stars/SimoesCTT/SCTT-2026-33-0002-DWM-Visual-Field-Singularity.svg) ![forks](https://img.shields.io/github/forks/SimoesCTT/SCTT-2026-33-0002-DWM-Visual-Field-Singularity.svg)

## CVE-2026-20700
 A memory corruption issue was addressed with improved state management. This issue is fixed in watchOS 26.3, tvOS 26.3, macOS Tahoe 26.3, visionOS 26.3, iOS 26.3 and iPadOS 26.3. An attacker with memory write capability may be able to execute arbitrary code. Apple is aware of a report that this issue may have been exploited in an extremely sophisticated attack against specific targeted individuals on versions of iOS before iOS 26. CVE-2025-14174 and CVE-2025-43529 were also issued in response to this report.



- [https://github.com/sundenovak/CVE-2026-20700-An-analysis-WIP](https://github.com/sundenovak/CVE-2026-20700-An-analysis-WIP) :  ![starts](https://img.shields.io/github/stars/sundenovak/CVE-2026-20700-An-analysis-WIP.svg) ![forks](https://img.shields.io/github/forks/sundenovak/CVE-2026-20700-An-analysis-WIP.svg)

## CVE-2026-20404
 In Modem, there is a possible system crash due to improper input validation. This could lead to remote denial of service, if a UE has connected to a rogue base station controlled by the attacker, with no additional execution privileges needed. User interaction is not needed for exploitation. Patch ID: MOLY01689248; Issue ID: MSV-4837.



- [https://github.com/George0Papasotiriou/CVE-2026-20404-MediaTek-modem-remote-DoS-rogue-base-station-scenario-](https://github.com/George0Papasotiriou/CVE-2026-20404-MediaTek-modem-remote-DoS-rogue-base-station-scenario-) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2026-20404-MediaTek-modem-remote-DoS-rogue-base-station-scenario-.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2026-20404-MediaTek-modem-remote-DoS-rogue-base-station-scenario-.svg)

## CVE-2026-20045
 A vulnerability in Cisco Unified Communications Manager (Unified CM), Cisco Unified Communications Manager Session Management Edition (Unified CM SME), Cisco Unified Communications Manager IM &amp; Presence Service (Unified CM IM&amp;P), Cisco Unity Connection, and Cisco Webex Calling Dedicated Instance could allow an unauthenticated, remote attacker to execute arbitrary commands on the underlying operating system of an affected device.&nbsp;

This vulnerability is due to improper validation of user-supplied input in HTTP requests. An attacker could exploit this vulnerability by sending a sequence of crafted HTTP requests to the web-based management interface of an affected device. A successful exploit could allow the attacker to obtain user-level access to the underlying operating system and then elevate privileges to root.&nbsp;
Note: Cisco has assigned this security advisory a Security Impact Rating (SIR) of Critical rather than High as the score indicates. The reason is that exploitation of this vulnerability could result in an attacker elevating privileges to root.



- [https://github.com/dkstar11q/Ashwesker-CVE-2026-20045](https://github.com/dkstar11q/Ashwesker-CVE-2026-20045) :  ![starts](https://img.shields.io/github/stars/dkstar11q/Ashwesker-CVE-2026-20045.svg) ![forks](https://img.shields.io/github/forks/dkstar11q/Ashwesker-CVE-2026-20045.svg)

## CVE-2026-2670
 A vulnerability was identified in Advantech WISE-6610 1.2.1_20251110. Affected is an unknown function of the file /cgi-bin/luci/admin/openvpn_apply of the component Background Management. Such manipulation of the argument delete_file leads to os command injection. The attack can be executed remotely. The exploit is publicly available and might be used. The vendor was contacted early about this disclosure but did not respond in any way.



- [https://github.com/ali-py3/exploit-CVE-2026-2670](https://github.com/ali-py3/exploit-CVE-2026-2670) :  ![starts](https://img.shields.io/github/stars/ali-py3/exploit-CVE-2026-2670.svg) ![forks](https://img.shields.io/github/forks/ali-py3/exploit-CVE-2026-2670.svg)

## CVE-2026-2441
 Use after free in CSS in Google Chrome prior to 145.0.7632.75 allowed a remote attacker to execute arbitrary code inside a sandbox via a crafted HTML page. (Chromium security severity: High)



- [https://github.com/huseyinstif/CVE-2026-2441-PoC](https://github.com/huseyinstif/CVE-2026-2441-PoC) :  ![starts](https://img.shields.io/github/stars/huseyinstif/CVE-2026-2441-PoC.svg) ![forks](https://img.shields.io/github/forks/huseyinstif/CVE-2026-2441-PoC.svg)

- [https://github.com/b1gchoi/CVE-2026-2441_POC](https://github.com/b1gchoi/CVE-2026-2441_POC) :  ![starts](https://img.shields.io/github/stars/b1gchoi/CVE-2026-2441_POC.svg) ![forks](https://img.shields.io/github/forks/b1gchoi/CVE-2026-2441_POC.svg)

- [https://github.com/washingtonmaister/CVE-2026-2441](https://github.com/washingtonmaister/CVE-2026-2441) :  ![starts](https://img.shields.io/github/stars/washingtonmaister/CVE-2026-2441.svg) ![forks](https://img.shields.io/github/forks/washingtonmaister/CVE-2026-2441.svg)

- [https://github.com/theemperorspath/CVE-2026-2441-PoC](https://github.com/theemperorspath/CVE-2026-2441-PoC) :  ![starts](https://img.shields.io/github/stars/theemperorspath/CVE-2026-2441-PoC.svg) ![forks](https://img.shields.io/github/forks/theemperorspath/CVE-2026-2441-PoC.svg)

## CVE-2026-2113
 A security vulnerability has been detected in yuan1994 tpadmin up to 1.3.12. This affects an unknown part in the library /public/static/admin/lib/webuploader/0.1.5/server/preview.php of the component WebUploader. The manipulation leads to deserialization. The attack is possible to be carried out remotely. The exploit has been disclosed publicly and may be used. This vulnerability only affects products that are no longer supported by the maintainer.



- [https://github.com/MaxMnMl/tpadmin-CVE-2026-2113-poc](https://github.com/MaxMnMl/tpadmin-CVE-2026-2113-poc) :  ![starts](https://img.shields.io/github/stars/MaxMnMl/tpadmin-CVE-2026-2113-poc.svg) ![forks](https://img.shields.io/github/forks/MaxMnMl/tpadmin-CVE-2026-2113-poc.svg)

## CVE-2026-1953
 Nukegraphic CMS v3.1.2 contains a stored cross-site scripting (XSS) vulnerability in the user profile edit functionality at /ngc-cms/user-edit-profile.php. The application fails to properly sanitize user input in the name field before storing it in the database and rendering it across multiple CMS pages. An authenticated attacker with low privileges can inject malicious JavaScript payloads through the profile edit request, which are then executed site-wide whenever the affected user's name is displayed. This allows the attacker to execute arbitrary JavaScript in the context of other users' sessions, potentially leading to session hijacking, credential theft, or unauthorized actions performed on behalf of victims.



- [https://github.com/carlosbudiman/CVE-2026-1953-Disclosure](https://github.com/carlosbudiman/CVE-2026-1953-Disclosure) :  ![starts](https://img.shields.io/github/stars/carlosbudiman/CVE-2026-1953-Disclosure.svg) ![forks](https://img.shields.io/github/forks/carlosbudiman/CVE-2026-1953-Disclosure.svg)

## CVE-2026-1862
 Type Confusion in V8 in Google Chrome prior to 144.0.7559.132 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)



- [https://github.com/b1gchoi/CVE-2026-1862-exp](https://github.com/b1gchoi/CVE-2026-1862-exp) :  ![starts](https://img.shields.io/github/stars/b1gchoi/CVE-2026-1862-exp.svg) ![forks](https://img.shields.io/github/forks/b1gchoi/CVE-2026-1862-exp.svg)

## CVE-2026-1844
 The PixelYourSite PRO plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the 'pysTrafficSource' parameter and the 'pys_landing_page' parameter in all versions up to, and including, 12.4.0.2 due to insufficient input sanitization and output escaping. This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.



- [https://github.com/adamshaikhma/CVE-2026-1844](https://github.com/adamshaikhma/CVE-2026-1844) :  ![starts](https://img.shields.io/github/stars/adamshaikhma/CVE-2026-1844.svg) ![forks](https://img.shields.io/github/forks/adamshaikhma/CVE-2026-1844.svg)

## CVE-2026-1731
 BeyondTrust Remote Support (RS) and certain older versions of Privileged Remote Access (PRA) contain a critical pre-authentication remote code execution vulnerability. By sending specially crafted requests, an unauthenticated remote attacker may be able to execute operating system commands in the context of the site user.



- [https://github.com/win3zz/CVE-2026-1731](https://github.com/win3zz/CVE-2026-1731) :  ![starts](https://img.shields.io/github/stars/win3zz/CVE-2026-1731.svg) ![forks](https://img.shields.io/github/forks/win3zz/CVE-2026-1731.svg)

- [https://github.com/cybrdude/cve-2026-1731-scanner](https://github.com/cybrdude/cve-2026-1731-scanner) :  ![starts](https://img.shields.io/github/stars/cybrdude/cve-2026-1731-scanner.svg) ![forks](https://img.shields.io/github/forks/cybrdude/cve-2026-1731-scanner.svg)

- [https://github.com/jakubie07/CVE-2026-1731](https://github.com/jakubie07/CVE-2026-1731) :  ![starts](https://img.shields.io/github/stars/jakubie07/CVE-2026-1731.svg) ![forks](https://img.shields.io/github/forks/jakubie07/CVE-2026-1731.svg)

- [https://github.com/richardpaimu34/CVE-2026-1731](https://github.com/richardpaimu34/CVE-2026-1731) :  ![starts](https://img.shields.io/github/stars/richardpaimu34/CVE-2026-1731.svg) ![forks](https://img.shields.io/github/forks/richardpaimu34/CVE-2026-1731.svg)

## CVE-2026-1729
 The AdForest theme for WordPress is vulnerable to authentication bypass in all versions up to, and including, 6.0.12. This is due to the plugin not properly verifying a user's identity prior to authenticating them through the 'sb_login_user_with_otp_fun' function. This makes it possible for unauthenticated attackers to log in as arbitrary users, including administrators.



- [https://github.com/ninjazan420/CVE-2026-1729-PoC-AdForest-WordPress-Authentication-Bypass](https://github.com/ninjazan420/CVE-2026-1729-PoC-AdForest-WordPress-Authentication-Bypass) :  ![starts](https://img.shields.io/github/stars/ninjazan420/CVE-2026-1729-PoC-AdForest-WordPress-Authentication-Bypass.svg) ![forks](https://img.shields.io/github/forks/ninjazan420/CVE-2026-1729-PoC-AdForest-WordPress-Authentication-Bypass.svg)

## CVE-2026-1560
 The Custom Block Builder – Lazy Blocks plugin for WordPress is vulnerable to Remote Code Execution in all versions up to, and including, 4.2.0 via multiple functions in the 'LazyBlocks_Blocks' class. This makes it possible for authenticated attackers, with Contributor-level access and above, to execute code on the server.



- [https://github.com/Z3YR0xX/CVE-2026-1560-Authenticated-Remote-Code-Execution-in-Lazy-Blocks-4.2.0](https://github.com/Z3YR0xX/CVE-2026-1560-Authenticated-Remote-Code-Execution-in-Lazy-Blocks-4.2.0) :  ![starts](https://img.shields.io/github/stars/Z3YR0xX/CVE-2026-1560-Authenticated-Remote-Code-Execution-in-Lazy-Blocks-4.2.0.svg) ![forks](https://img.shields.io/github/forks/Z3YR0xX/CVE-2026-1560-Authenticated-Remote-Code-Execution-in-Lazy-Blocks-4.2.0.svg)

## CVE-2026-1529
 A flaw was found in Keycloak. An attacker can exploit this vulnerability by modifying the organization ID and target email within a legitimate invitation token's JSON Web Token (JWT) payload. This lack of cryptographic signature verification allows the attacker to successfully self-register into an unauthorized organization, leading to unauthorized access.



- [https://github.com/ninjazan420/CVE-2026-1529-PoC-keycloak-unauthorized-registration-via-improper-invitation-token-validation](https://github.com/ninjazan420/CVE-2026-1529-PoC-keycloak-unauthorized-registration-via-improper-invitation-token-validation) :  ![starts](https://img.shields.io/github/stars/ninjazan420/CVE-2026-1529-PoC-keycloak-unauthorized-registration-via-improper-invitation-token-validation.svg) ![forks](https://img.shields.io/github/forks/ninjazan420/CVE-2026-1529-PoC-keycloak-unauthorized-registration-via-improper-invitation-token-validation.svg)

- [https://github.com/0x240x23elu/CVE-2026-1529](https://github.com/0x240x23elu/CVE-2026-1529) :  ![starts](https://img.shields.io/github/stars/0x240x23elu/CVE-2026-1529.svg) ![forks](https://img.shields.io/github/forks/0x240x23elu/CVE-2026-1529.svg)

## CVE-2026-1490
 The Spam protection, Anti-Spam, FireWall by CleanTalk plugin for WordPress is vulnerable to unauthorized Arbitrary Plugin Installation due to an authorization bypass via reverse DNS (PTR record) spoofing on the 'checkWithoutToken' function in all versions up to, and including, 6.71. This makes it possible for unauthenticated attackers to install and activate arbitrary plugins which can be leveraged to achieve remote code execution if another vulnerable plugin is installed and activated. Note: This is only exploitable on sites with an invalid API key.



- [https://github.com/comthompson30/CVE-2026-1490](https://github.com/comthompson30/CVE-2026-1490) :  ![starts](https://img.shields.io/github/stars/comthompson30/CVE-2026-1490.svg) ![forks](https://img.shields.io/github/forks/comthompson30/CVE-2026-1490.svg)

## CVE-2026-1457
 An authenticated buffer handling flaw in TP-Link VIGI C385 V1 Web API lacking input sanitization, may allow memory corruption leading to remote code execution. Authenticated attackers may trigger buffer overflow and potentially execute arbitrary code with elevated privileges.



- [https://github.com/ii4gsp/CVE-2026-1457](https://github.com/ii4gsp/CVE-2026-1457) :  ![starts](https://img.shields.io/github/stars/ii4gsp/CVE-2026-1457.svg) ![forks](https://img.shields.io/github/forks/ii4gsp/CVE-2026-1457.svg)

## CVE-2026-1405
 The Slider Future plugin for WordPress is vulnerable to arbitrary file uploads due to missing file type validation in the 'slider_future_handle_image_upload' function in all versions up to, and including, 1.0.5. This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible.



- [https://github.com/Nxploited/CVE-2026-1405](https://github.com/Nxploited/CVE-2026-1405) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2026-1405.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2026-1405.svg)

## CVE-2026-1357
 The Migration, Backup, Staging – WPvivid Backup & Migration plugin for WordPress is vulnerable to Unauthenticated Arbitrary File Upload in versions up to and including 0.9.123. This is due to improper error handling in the RSA decryption process combined with a lack of path sanitization when writing uploaded files. When the plugin fails to decrypt a session key using openssl_private_decrypt(), it does not terminate execution and instead passes the boolean false value to the phpseclib library's AES cipher initialization. The library treats this false value as a string of null bytes, allowing an attacker to encrypt a malicious payload using a predictable null-byte key. Additionally, the plugin accepts filenames from the decrypted payload without sanitization, enabling directory traversal to escape the protected backup directory. This makes it possible for unauthenticated attackers to upload arbitrary PHP files to publicly accessible directories and achieve Remote Code Execution via the wpvivid_action=send_to_site parameter.



- [https://github.com/halilkirazkaya/CVE-2026-1357](https://github.com/halilkirazkaya/CVE-2026-1357) :  ![starts](https://img.shields.io/github/stars/halilkirazkaya/CVE-2026-1357.svg) ![forks](https://img.shields.io/github/forks/halilkirazkaya/CVE-2026-1357.svg)

- [https://github.com/cybertechajju/CVE-2026-1357-POC](https://github.com/cybertechajju/CVE-2026-1357-POC) :  ![starts](https://img.shields.io/github/stars/cybertechajju/CVE-2026-1357-POC.svg) ![forks](https://img.shields.io/github/forks/cybertechajju/CVE-2026-1357-POC.svg)

- [https://github.com/LucasM0ntes/POC-CVE-2026-1357](https://github.com/LucasM0ntes/POC-CVE-2026-1357) :  ![starts](https://img.shields.io/github/stars/LucasM0ntes/POC-CVE-2026-1357.svg) ![forks](https://img.shields.io/github/forks/LucasM0ntes/POC-CVE-2026-1357.svg)

- [https://github.com/itsismarcos/Exploit-CVE-2026-1357](https://github.com/itsismarcos/Exploit-CVE-2026-1357) :  ![starts](https://img.shields.io/github/stars/itsismarcos/Exploit-CVE-2026-1357.svg) ![forks](https://img.shields.io/github/forks/itsismarcos/Exploit-CVE-2026-1357.svg)

## CVE-2026-1340
 A code injection in Ivanti Endpoint Manager Mobile allowing attackers to achieve unauthenticated remote code execution.



- [https://github.com/MehdiLeDeaut/CVE-2026-1281-Ivanti-EPMM-RCE](https://github.com/MehdiLeDeaut/CVE-2026-1281-Ivanti-EPMM-RCE) :  ![starts](https://img.shields.io/github/stars/MehdiLeDeaut/CVE-2026-1281-Ivanti-EPMM-RCE.svg) ![forks](https://img.shields.io/github/forks/MehdiLeDeaut/CVE-2026-1281-Ivanti-EPMM-RCE.svg)

- [https://github.com/YunfeiGE18/CVE-2026-1281-CVE-2026-1340-Ivanti-EPMM-RCE](https://github.com/YunfeiGE18/CVE-2026-1281-CVE-2026-1340-Ivanti-EPMM-RCE) :  ![starts](https://img.shields.io/github/stars/YunfeiGE18/CVE-2026-1281-CVE-2026-1340-Ivanti-EPMM-RCE.svg) ![forks](https://img.shields.io/github/forks/YunfeiGE18/CVE-2026-1281-CVE-2026-1340-Ivanti-EPMM-RCE.svg)

## CVE-2026-1337
 Insufficient escaping of unicode characters in query log in Neo4j Enterprise and Community editions prior to 2026.01 can lead to XSS if the user opens the logs in a tool that treats them as HTML. There is no security impact on Neo4j products, but this advisory is released as a precaution to treat the logs as plain text if using versions prior to 2026.01.

Proof of concept exploit:  https://github.com/JoakimBulow/CVE-2026-1337



- [https://github.com/JoakimBulow/CVE-2026-1337](https://github.com/JoakimBulow/CVE-2026-1337) :  ![starts](https://img.shields.io/github/stars/JoakimBulow/CVE-2026-1337.svg) ![forks](https://img.shields.io/github/forks/JoakimBulow/CVE-2026-1337.svg)

## CVE-2026-1306
 The midi-Synth plugin for WordPress is vulnerable to arbitrary file uploads due to missing file type and file extension validation in the 'export' AJAX action in all versions up to, and including, 1.1.0. This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible granted the attacker can obtain a valid nonce. The nonce is exposed in frontend JavaScript making it trivially accessible to unauthenticated attackers.



- [https://github.com/richardpaimu34/CVE-2026-1306](https://github.com/richardpaimu34/CVE-2026-1306) :  ![starts](https://img.shields.io/github/stars/richardpaimu34/CVE-2026-1306.svg) ![forks](https://img.shields.io/github/forks/richardpaimu34/CVE-2026-1306.svg)

## CVE-2026-1281
 A code injection in Ivanti Endpoint Manager Mobile allowing attackers to achieve unauthenticated remote code execution.



- [https://github.com/MehdiLeDeaut/CVE-2026-1281-Ivanti-EPMM-RCE](https://github.com/MehdiLeDeaut/CVE-2026-1281-Ivanti-EPMM-RCE) :  ![starts](https://img.shields.io/github/stars/MehdiLeDeaut/CVE-2026-1281-Ivanti-EPMM-RCE.svg) ![forks](https://img.shields.io/github/forks/MehdiLeDeaut/CVE-2026-1281-Ivanti-EPMM-RCE.svg)

- [https://github.com/YunfeiGE18/CVE-2026-1281-CVE-2026-1340-Ivanti-EPMM-RCE](https://github.com/YunfeiGE18/CVE-2026-1281-CVE-2026-1340-Ivanti-EPMM-RCE) :  ![starts](https://img.shields.io/github/stars/YunfeiGE18/CVE-2026-1281-CVE-2026-1340-Ivanti-EPMM-RCE.svg) ![forks](https://img.shields.io/github/forks/YunfeiGE18/CVE-2026-1281-CVE-2026-1340-Ivanti-EPMM-RCE.svg)

## CVE-2026-1208
 The Friendly Functions for Welcart plugin for WordPress is vulnerable to Cross-Site Request Forgery in all versions up to, and including, 1.2.5. This is due to missing or incorrect nonce validation on the settings page. This makes it possible for unauthenticated attackers to update plugin settings via a forged request granted they can trick a site administrator into performing an action such as clicking on a link.



- [https://github.com/SnailSploit/CVE-2026-1208](https://github.com/SnailSploit/CVE-2026-1208) :  ![starts](https://img.shields.io/github/stars/SnailSploit/CVE-2026-1208.svg) ![forks](https://img.shields.io/github/forks/SnailSploit/CVE-2026-1208.svg)

## CVE-2026-1107
 A weakness has been identified in EyouCMS up to 1.7.1/5.0. Impacted is the function check_userinfo of the file Diyajax.php of the component Member Avatar Handler. Executing a manipulation of the argument viewfile can lead to unrestricted upload. The attack may be performed from remote. The exploit has been made available to the public and could be used for attacks. The vendor was contacted early about this disclosure but did not respond in any way.



- [https://github.com/Iniivan13/CVE-2026-1107](https://github.com/Iniivan13/CVE-2026-1107) :  ![starts](https://img.shields.io/github/stars/Iniivan13/CVE-2026-1107.svg) ![forks](https://img.shields.io/github/forks/Iniivan13/CVE-2026-1107.svg)

## CVE-2026-1056
 The Snow Monkey Forms plugin for WordPress is vulnerable to arbitrary file deletion due to insufficient file path validation in the 'generate_user_dirpath' function in all versions up to, and including, 12.0.3. This makes it possible for unauthenticated attackers to delete arbitrary files on the server, which can easily lead to remote code execution when the right file is deleted (such as wp-config.php).



- [https://github.com/ch4r0nn/CVE-2026-1056-POC](https://github.com/ch4r0nn/CVE-2026-1056-POC) :  ![starts](https://img.shields.io/github/stars/ch4r0nn/CVE-2026-1056-POC.svg) ![forks](https://img.shields.io/github/forks/ch4r0nn/CVE-2026-1056-POC.svg)

## CVE-2026-0920
 The LA-Studio Element Kit for Elementor plugin for WordPress is vulnerable to Administrative User Creation in all versions up to, and including, 1.5.6.3. This is due to the 'ajax_register_handle' function not restricting what user roles a user can register with. This makes it possible for unauthenticated attackers to supply the 'lakit_bkrole' parameter during registration and gain administrator access to the site.



- [https://github.com/John-doe-code-a11/CVE-2026-0920](https://github.com/John-doe-code-a11/CVE-2026-0920) :  ![starts](https://img.shields.io/github/stars/John-doe-code-a11/CVE-2026-0920.svg) ![forks](https://img.shields.io/github/forks/John-doe-code-a11/CVE-2026-0920.svg)

- [https://github.com/O99099O/By-Poloss..-..CVE-2026-0920](https://github.com/O99099O/By-Poloss..-..CVE-2026-0920) :  ![starts](https://img.shields.io/github/stars/O99099O/By-Poloss..-..CVE-2026-0920.svg) ![forks](https://img.shields.io/github/forks/O99099O/By-Poloss..-..CVE-2026-0920.svg)

- [https://github.com/Galaxy-sc/CVE-2026-0920-WordPress-LA-Studio-Exploit](https://github.com/Galaxy-sc/CVE-2026-0920-WordPress-LA-Studio-Exploit) :  ![starts](https://img.shields.io/github/stars/Galaxy-sc/CVE-2026-0920-WordPress-LA-Studio-Exploit.svg) ![forks](https://img.shields.io/github/forks/Galaxy-sc/CVE-2026-0920-WordPress-LA-Studio-Exploit.svg)

## CVE-2026-0915
 Calling getnetbyaddr or getnetbyaddr_r with a configured nsswitch.conf that specifies the library's DNS backend for networks and queries for a zero-valued network in the GNU C Library version 2.0 to version 2.42 can leak stack contents to the configured DNS resolver.



- [https://github.com/cyberwulfy200-dev/CVE-2026-0915-json-Patch.-V2.0](https://github.com/cyberwulfy200-dev/CVE-2026-0915-json-Patch.-V2.0) :  ![starts](https://img.shields.io/github/stars/cyberwulfy200-dev/CVE-2026-0915-json-Patch.-V2.0.svg) ![forks](https://img.shields.io/github/forks/cyberwulfy200-dev/CVE-2026-0915-json-Patch.-V2.0.svg)

## CVE-2026-0842
 A flaw has been found in Flycatcher Toys smART Sketcher up to 2.0. This affects an unknown part of the component Bluetooth Low Energy Interface. This manipulation causes missing authentication. The attack can only be done within the local network. The exploit has been published and may be used. The vendor was contacted early about this disclosure but did not respond in any way.



- [https://github.com/davidrxchester/smart-sketcher-upload](https://github.com/davidrxchester/smart-sketcher-upload) :  ![starts](https://img.shields.io/github/stars/davidrxchester/smart-sketcher-upload.svg) ![forks](https://img.shields.io/github/forks/davidrxchester/smart-sketcher-upload.svg)

## CVE-2026-0834
 Logic vulnerability in TP-Link Archer C20 v6.0 and Archer AX53 v1.0 (TDDP module) allows unauthenticated adjacent attackers to execute administrative commands including factory reset and device reboot without credentials. Attackers on the adjacent network can remotely trigger factory resets and reboots without credentials, causing configuration loss and interruption of device availability.This issue affects Archer C20 v6.0  V6_251031.


Archer AX53 v1.0  

V1_251215



- [https://github.com/mattgsys/CVE-2026-0834](https://github.com/mattgsys/CVE-2026-0834) :  ![starts](https://img.shields.io/github/stars/mattgsys/CVE-2026-0834.svg) ![forks](https://img.shields.io/github/forks/mattgsys/CVE-2026-0834.svg)

## CVE-2026-0770
 Langflow exec_globals Inclusion of Functionality from Untrusted Control Sphere Remote Code Execution Vulnerability. This vulnerability allows remote attackers to execute arbitrary code on affected installations of Langflow. Authentication is not required to exploit this vulnerability.

The specific flaw exists within the handling of the exec_globals parameter provided to the validate endpoint. The issue results from the inclusion of a resource from an untrusted control sphere. An attacker can leverage this vulnerability to execute code in the context of root. Was ZDI-CAN-27325.



- [https://github.com/affix/CVE-2026-0770-PoC](https://github.com/affix/CVE-2026-0770-PoC) :  ![starts](https://img.shields.io/github/stars/affix/CVE-2026-0770-PoC.svg) ![forks](https://img.shields.io/github/forks/affix/CVE-2026-0770-PoC.svg)

## CVE-2026-0745
 The User Language Switch plugin for WordPress is vulnerable to Server-Side Request Forgery in all versions up to, and including, 1.6.10 due to missing URL validation on the 'download_language()' function. This makes it possible for authenticated attackers, with Administrator-level access and above, to make web requests to arbitrary locations originating from the web application and can be used to query and modify information from internal services.



- [https://github.com/blackhatlegend/CVE-2026-0745](https://github.com/blackhatlegend/CVE-2026-0745) :  ![starts](https://img.shields.io/github/stars/blackhatlegend/CVE-2026-0745.svg) ![forks](https://img.shields.io/github/forks/blackhatlegend/CVE-2026-0745.svg)

## CVE-2026-0628
 Insufficient policy enforcement in WebView tag in Google Chrome prior to 143.0.7499.192 allowed an attacker who convinced a user to install a malicious extension to inject scripts or HTML into a privileged page via a crafted Chrome Extension. (Chromium security severity: High)



- [https://github.com/sastraadiwiguna-purpleeliteteaming/Dissecting-CVE-2026-0628-Chromium-Extension-Privilege-Escalation](https://github.com/sastraadiwiguna-purpleeliteteaming/Dissecting-CVE-2026-0628-Chromium-Extension-Privilege-Escalation) :  ![starts](https://img.shields.io/github/stars/sastraadiwiguna-purpleeliteteaming/Dissecting-CVE-2026-0628-Chromium-Extension-Privilege-Escalation.svg) ![forks](https://img.shields.io/github/forks/sastraadiwiguna-purpleeliteteaming/Dissecting-CVE-2026-0628-Chromium-Extension-Privilege-Escalation.svg)

- [https://github.com/fevar54/CVE-2026-0628-POC](https://github.com/fevar54/CVE-2026-0628-POC) :  ![starts](https://img.shields.io/github/stars/fevar54/CVE-2026-0628-POC.svg) ![forks](https://img.shields.io/github/forks/fevar54/CVE-2026-0628-POC.svg)

## CVE-2026-0622
 Open 5GS WebUI uses a hard-coded JWT signing key (change-me) whenever the environment variable JWT_SECRET_KEY is unset



- [https://github.com/cyberdudebivash/CYBERDUDEBIVASH-5G-Core-Key-Rotation-Ghost-Admin-Auditor](https://github.com/cyberdudebivash/CYBERDUDEBIVASH-5G-Core-Key-Rotation-Ghost-Admin-Auditor) :  ![starts](https://img.shields.io/github/stars/cyberdudebivash/CYBERDUDEBIVASH-5G-Core-Key-Rotation-Ghost-Admin-Auditor.svg) ![forks](https://img.shields.io/github/forks/cyberdudebivash/CYBERDUDEBIVASH-5G-Core-Key-Rotation-Ghost-Admin-Auditor.svg)

## CVE-2026-0594
 The List Site Contributors plugin for WordPress is vulnerable to Reflected Cross-Site Scripting via the 'alpha' parameter in versions up to, and including, 1.1.8 due to insufficient input sanitization and output escaping. This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that execute if they can successfully trick a user into performing an action such as clicking on a link.



- [https://github.com/m4sh-wacker/CVE-2026-0594-ListSiteContributors-Plugin-Exploit](https://github.com/m4sh-wacker/CVE-2026-0594-ListSiteContributors-Plugin-Exploit) :  ![starts](https://img.shields.io/github/stars/m4sh-wacker/CVE-2026-0594-ListSiteContributors-Plugin-Exploit.svg) ![forks](https://img.shields.io/github/forks/m4sh-wacker/CVE-2026-0594-ListSiteContributors-Plugin-Exploit.svg)

## CVE-2026-0547
 A vulnerability was found in PHPGurukul Online Course Registration up to 3.1. This issue affects some unknown processing of the file /admin/edit-student-profile.php of the component Student Registration Page. The manipulation of the argument photo results in unrestricted upload. The attack may be launched remotely. The exploit has been made public and could be used.



- [https://github.com/rsecroot/CVE-2026-0547](https://github.com/rsecroot/CVE-2026-0547) :  ![starts](https://img.shields.io/github/stars/rsecroot/CVE-2026-0547.svg) ![forks](https://img.shields.io/github/forks/rsecroot/CVE-2026-0547.svg)

## CVE-2026-0227
 A vulnerability in Palo Alto Networks PAN-OS software enables an unauthenticated attacker to cause a denial of service (DoS) to the firewall. Repeated attempts to trigger this issue results in the firewall entering into maintenance mode.



- [https://github.com/CkAbhijit/CVE-2026-0227-Advanced-Scanner](https://github.com/CkAbhijit/CVE-2026-0227-Advanced-Scanner) :  ![starts](https://img.shields.io/github/stars/CkAbhijit/CVE-2026-0227-Advanced-Scanner.svg) ![forks](https://img.shields.io/github/forks/CkAbhijit/CVE-2026-0227-Advanced-Scanner.svg)

- [https://github.com/TeeyaR/CVE-2026-0227-Palo-Alto](https://github.com/TeeyaR/CVE-2026-0227-Palo-Alto) :  ![starts](https://img.shields.io/github/stars/TeeyaR/CVE-2026-0227-Palo-Alto.svg) ![forks](https://img.shields.io/github/forks/TeeyaR/CVE-2026-0227-Palo-Alto.svg)
