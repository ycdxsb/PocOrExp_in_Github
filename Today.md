# Update 2026-11-01
## CVE-2026-119025
 open 7.2.0 before 11.0.0 contains an OS command injection vulnerability that allows attackers to execute PowerShell code by supplying crafted URLs on Windows and WSL. Attackers can embed $(...) subexpressions in URLs, such as OAuth authorization_endpoint values from malicious MCP servers, which execute when index.js passes them unescaped to powershell -EncodedCommand.

- [https://github.com/shouvikkkk/oauth-sink-check](https://github.com/shouvikkkk/oauth-sink-check) :  ![starts](https://img.shields.io/github/stars/shouvikkkk/oauth-sink-check.svg) ![forks](https://img.shields.io/github/forks/shouvikkkk/oauth-sink-check.svg)


## CVE-2026-118776
 Forge (also called node-forge) is a native implementation of Transport Layer Security in JavaScript. Prior to 1.4.1, the affected implementation used decipher.finish(), CBC and ECB modes, PKCS#7 padding to process the relevant input or security decision. node-forge validated only the final byte of PKCS#7 padding during CBC and ECB decryption and accepted zero, oversized, or mismatched padding bytes. Malformed ciphertext could consequently be accepted and up to four plaintext blocks could be silently removed, causing an integrity failure in applications that treated successful decryption as proof of valid padding. This issue is fixed in version 1.4.1.

- [https://github.com/zebbernCVE/CVE-2026-118776](https://github.com/zebbernCVE/CVE-2026-118776) :  ![starts](https://img.shields.io/github/stars/zebbernCVE/CVE-2026-118776.svg) ![forks](https://img.shields.io/github/forks/zebbernCVE/CVE-2026-118776.svg)


## CVE-2026-118238
 The Tenda W18E web management server is vulnerable to OS command injection via the "diagnose" packet-capture feature due to improper validation of JSON fields. An authenticated user can inject shell metacharacters into the protocol or targetDevice fields, which are later concatenated into a tcpdump command and executed with root privileges. This vulnerability can be exploited without authentication if the device is in a factory-reset state.

- [https://github.com/Cushz/CVE-2026-118238](https://github.com/Cushz/CVE-2026-118238) :  ![starts](https://img.shields.io/github/stars/Cushz/CVE-2026-118238.svg) ![forks](https://img.shields.io/github/forks/Cushz/CVE-2026-118238.svg)


## CVE-2026-117184
 An issue in the GraphQL endpoint of traggo server v0.8.3 allows attackers to cause a Denial of Service (DoS) via a crafted POST request to the GraphQL endpoint

- [https://github.com/Primandito/CVE-2026-117184](https://github.com/Primandito/CVE-2026-117184) :  ![starts](https://img.shields.io/github/stars/Primandito/CVE-2026-117184.svg) ![forks](https://img.shields.io/github/forks/Primandito/CVE-2026-117184.svg)


## CVE-2026-117183
 A path traversal vulnerability in the FeaturedImage component of astro-notion-blog 0.13.0 allows attackers to escape the intended directory, as well as read and overwrite files on the server via a crafted URL.

- [https://github.com/Primandito/CVE-2026-117183](https://github.com/Primandito/CVE-2026-117183) :  ![starts](https://img.shields.io/github/stars/Primandito/CVE-2026-117183.svg) ![forks](https://img.shields.io/github/forks/Primandito/CVE-2026-117183.svg)


## CVE-2026-117182
 An authenticated cross-site scripting (XSS) vulnerability in the /spina/embeddable.rb component of Spina CMS v2.21.0 allows attackers to execute arbitrary web scripts or HTML via injecting a crafted URL.

- [https://github.com/Primandito/CVE-2026-117182](https://github.com/Primandito/CVE-2026-117182) :  ![starts](https://img.shields.io/github/stars/Primandito/CVE-2026-117182.svg) ![forks](https://img.shields.io/github/forks/Primandito/CVE-2026-117182.svg)


## CVE-2026-116191
 Rclone before 1.75.2 contains a path traversal vulnerability in serve webdav that allows unauthenticated attackers to write above the served root by sending an unvalidated '..' path component. Attackers can send MKCOL /.. to plant a VFS node, then PUT, MOVE, COPY, or MKCOL to create, overwrite, or delete files belonging to other tenants.

- [https://github.com/mehmet-emir-eroglu/CVE-2026-116191](https://github.com/mehmet-emir-eroglu/CVE-2026-116191) :  ![starts](https://img.shields.io/github/stars/mehmet-emir-eroglu/CVE-2026-116191.svg) ![forks](https://img.shields.io/github/forks/mehmet-emir-eroglu/CVE-2026-116191.svg)


## CVE-2026-116165
 Parse Server before 8.6.101 and 9.0.0 before 9.10.4-alpha.4 contains a missing authorization vulnerability on MongoDB deployments that lets clients without the master key delete the stored schema of any class. Unauthenticated attackers can send REST API delete requests targeting the internal _SCHEMA collection to remove field definitions, class-level permissions, and protected fields, exposing data to unauthorized reads and modifications.

- [https://github.com/mehmet-emir-eroglu/CVE-2026-116165](https://github.com/mehmet-emir-eroglu/CVE-2026-116165) :  ![starts](https://img.shields.io/github/stars/mehmet-emir-eroglu/CVE-2026-116165.svg) ![forks](https://img.shields.io/github/forks/mehmet-emir-eroglu/CVE-2026-116165.svg)


## CVE-2026-114820
 Vulnerability in the Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component: JSSE).  Supported versions that are affected are Oracle Java SE: 8u511-b32, 8u511-perf-b32, 11.0.33.0.2, 17.0.21.0.2, 21.0.13.0.2, 25.0.5.0.2, 27.0.1.0.2; Oracle GraalVM for JDK: 17.0.21.0.2 and  21.0.13.0.2; Oracle GraalVM Enterprise Edition: 21.3.20.0.2. Easily exploitable vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition.  Successful attacks of this vulnerability can result in  unauthorized creation, deletion or modification access to critical data or all Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition accessible data as well as  unauthorized access to critical data or complete access to all Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition accessible data. Note: This vulnerability can be exploited by using APIs in the specified Component, e.g., through a web service which supplies data to the APIs. This vulnerability also applies to Java deployments, typically in clients running sandboxed Java Web Start applications or sandboxed Java applets, that load and run untrusted code (e.g., code that comes from the internet) and rely on the Java sandbox for security. CVSS 3.1 Base Score 9.1 (Confidentiality and Integrity impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N).

- [https://github.com/mehmet-emir-eroglu/CVE-2026-114820](https://github.com/mehmet-emir-eroglu/CVE-2026-114820) :  ![starts](https://img.shields.io/github/stars/mehmet-emir-eroglu/CVE-2026-114820.svg) ![forks](https://img.shields.io/github/forks/mehmet-emir-eroglu/CVE-2026-114820.svg)


## CVE-2026-114625
Hosted, including Dedicated, versions of VCO were impacted and have already been patched.

- [https://github.com/definitiveref/CVE-2026-114625-Proof-Of-Concept](https://github.com/definitiveref/CVE-2026-114625-Proof-Of-Concept) :  ![starts](https://img.shields.io/github/stars/definitiveref/CVE-2026-114625-Proof-Of-Concept.svg) ![forks](https://img.shields.io/github/forks/definitiveref/CVE-2026-114625-Proof-Of-Concept.svg)


## CVE-2026-114509
 Laravel is a web application framework. Prior to 12.68.0 and 13.29.0, TokenGuard configured as a standard token-based API guard does not reject a crafted non-string credential. Under affected MySQL or MariaDB configurations, the authentication lookup can match an unintended existing user, allowing an unauthenticated attacker to bypass authentication and take over an account on routes protected by TokenGuard. This issue is fixed in versions 12.68.0 and 13.29.0.

- [https://github.com/Nguemoue/project2026_20261030_tokengate](https://github.com/Nguemoue/project2026_20261030_tokengate) :  ![starts](https://img.shields.io/github/stars/Nguemoue/project2026_20261030_tokengate.svg) ![forks](https://img.shields.io/github/forks/Nguemoue/project2026_20261030_tokengate.svg)


## CVE-2026-112705
 An out-of-bounds write issue was addressed with improved bounds checking. This issue is fixed in iOS 26.7.2 and iPadOS 26.7.2, iOS 27.2 and iPadOS 27.2, macOS Golden Gate 27.2, macOS Sequoia 15.8.2, macOS Tahoe 26.7.2, tvOS 27.2. An app may be able to cause unexpected system termination.

- [https://github.com/MchinaMd57764/AVETemporalPoC-CVE-2026-112705](https://github.com/MchinaMd57764/AVETemporalPoC-CVE-2026-112705) :  ![starts](https://img.shields.io/github/stars/MchinaMd57764/AVETemporalPoC-CVE-2026-112705.svg) ![forks](https://img.shields.io/github/forks/MchinaMd57764/AVETemporalPoC-CVE-2026-112705.svg)
- [https://github.com/Lak453/CVE-2026-112705-poc](https://github.com/Lak453/CVE-2026-112705-poc) :  ![starts](https://img.shields.io/github/stars/Lak453/CVE-2026-112705-poc.svg) ![forks](https://img.shields.io/github/forks/Lak453/CVE-2026-112705-poc.svg)


## CVE-2026-112621
 An out-of-bounds write issue was addressed with improved bounds checking. This issue is fixed in Safari 27.2, iOS 26.7.2 and iPadOS 26.7.2, iOS 27.2 and iPadOS 27.2, macOS Golden Gate 27.2, visionOS 27.2. Processing a maliciously crafted image may result in memory corruption.

- [https://github.com/PickAstley11/CVE-2026-112621-oob-write-poc](https://github.com/PickAstley11/CVE-2026-112621-oob-write-poc) :  ![starts](https://img.shields.io/github/stars/PickAstley11/CVE-2026-112621-oob-write-poc.svg) ![forks](https://img.shields.io/github/forks/PickAstley11/CVE-2026-112621-oob-write-poc.svg)


## CVE-2026-111497
Users need to update any Brotli libraries or binaries between 1.0.3 through 1.2.0 to the latest available version: 1.0.10 or 1.1.1 or 1.2.1.

- [https://github.com/atiilla/CVE-2026-111497-Node2Shell](https://github.com/atiilla/CVE-2026-111497-Node2Shell) :  ![starts](https://img.shields.io/github/stars/atiilla/CVE-2026-111497-Node2Shell.svg) ![forks](https://img.shields.io/github/forks/atiilla/CVE-2026-111497-Node2Shell.svg)
- [https://github.com/Nucklear/CVE-2026-111497-working](https://github.com/Nucklear/CVE-2026-111497-working) :  ![starts](https://img.shields.io/github/stars/Nucklear/CVE-2026-111497-working.svg) ![forks](https://img.shields.io/github/forks/Nucklear/CVE-2026-111497-working.svg)
- [https://github.com/miracle438/node2shell-two-stage](https://github.com/miracle438/node2shell-two-stage) :  ![starts](https://img.shields.io/github/stars/miracle438/node2shell-two-stage.svg) ![forks](https://img.shields.io/github/forks/miracle438/node2shell-two-stage.svg)
- [https://github.com/dansaurabh/brotli2shell_Hunter](https://github.com/dansaurabh/brotli2shell_Hunter) :  ![starts](https://img.shields.io/github/stars/dansaurabh/brotli2shell_Hunter.svg) ![forks](https://img.shields.io/github/forks/dansaurabh/brotli2shell_Hunter.svg)
- [https://github.com/upeul/vulnpocalypse-2026-10-response](https://github.com/upeul/vulnpocalypse-2026-10-response) :  ![starts](https://img.shields.io/github/stars/upeul/vulnpocalypse-2026-10-response.svg) ![forks](https://img.shields.io/github/forks/upeul/vulnpocalypse-2026-10-response.svg)


## CVE-2026-110447
 Collabora Online Built-in CODE Server before 26.4.303 (richdocumentscode), a Nextcloud app, allows remote code execution, as exploited in the wild in September and October 2026, a different vulnerability than CVE-2025-66208. This is an OS command injection in proxy.php when the CODE server isn't running (e.g., the product was recently restarted). The vulnerability is not present in standalone Collabora Online servers; only this deployment with CODE Server is affected.

- [https://github.com/Iceman2050/cve-2026-110447-checker](https://github.com/Iceman2050/cve-2026-110447-checker) :  ![starts](https://img.shields.io/github/stars/Iceman2050/cve-2026-110447-checker.svg) ![forks](https://img.shields.io/github/forks/Iceman2050/cve-2026-110447-checker.svg)


## CVE-2026-110264
 An issue has been discovered in GitLab CE/EE affecting all versions from 7.0 before 18.11.13, 19.0 before 19.0.10, 19.1 before 19.1.9, 19.2 before 19.2.9, 19.3 before 19.3.6, 19.4 before 19.4.3, and 19.5 before 19.5.1 that, under certain conditions, could have allowed an unauthenticated user to execute arbitrary code on the GitLab server due to integer overflow when compiling a specially crafted regular expression.

- [https://github.com/foxcornlab/gitlab-onigmo-scanner](https://github.com/foxcornlab/gitlab-onigmo-scanner) :  ![starts](https://img.shields.io/github/stars/foxcornlab/gitlab-onigmo-scanner.svg) ![forks](https://img.shields.io/github/forks/foxcornlab/gitlab-onigmo-scanner.svg)


## CVE-2026-109619
 PHP has various global state that temporarily points into request memory. In some scenarios, global state may not be correctly reset, or may be repopulated after being reset. The global state may then refer to request memory even after it has been freed. Subsequent requests may read or branch on this stale state before it is fully initialized. Multiple strategies can trigger this condition and produce remote code execution (RCE).

- [https://github.com/xaviware/go-php2shell-scanner-CVE-2026-109618-CVE-2026-109619](https://github.com/xaviware/go-php2shell-scanner-CVE-2026-109618-CVE-2026-109619) :  ![starts](https://img.shields.io/github/stars/xaviware/go-php2shell-scanner-CVE-2026-109618-CVE-2026-109619.svg) ![forks](https://img.shields.io/github/forks/xaviware/go-php2shell-scanner-CVE-2026-109618-CVE-2026-109619.svg)
- [https://github.com/erdemkayar/php2shell-scan](https://github.com/erdemkayar/php2shell-scan) :  ![starts](https://img.shields.io/github/stars/erdemkayar/php2shell-scan.svg) ![forks](https://img.shields.io/github/forks/erdemkayar/php2shell-scan.svg)


## CVE-2026-109618
 PHP uses longjmp() for out-of-memory (OOM) errors to exit the current context and abort handling of the request. Some contexts may not properly account for this scenario and leave request memory in an uninitialized state before performing an allocation. The subsequent request cleanup procedure may read or branch on this memory. Multiple OOM strategies can consistently trigger this condition and lead to remote code execution (RCE).

- [https://github.com/mym0us3r/PHP2Shell-Detection-with-Wazuh](https://github.com/mym0us3r/PHP2Shell-Detection-with-Wazuh) :  ![starts](https://img.shields.io/github/stars/mym0us3r/PHP2Shell-Detection-with-Wazuh.svg) ![forks](https://img.shields.io/github/forks/mym0us3r/PHP2Shell-Detection-with-Wazuh.svg)
- [https://github.com/umair-aziz025/PHP2Shell](https://github.com/umair-aziz025/PHP2Shell) :  ![starts](https://img.shields.io/github/stars/umair-aziz025/PHP2Shell.svg) ![forks](https://img.shields.io/github/forks/umair-aziz025/PHP2Shell.svg)
- [https://github.com/GarciaG1/charla-php2shell](https://github.com/GarciaG1/charla-php2shell) :  ![starts](https://img.shields.io/github/stars/GarciaG1/charla-php2shell.svg) ![forks](https://img.shields.io/github/forks/GarciaG1/charla-php2shell.svg)


## CVE-2026-109566
 Rapyd Admin from 9.0.0 before 9.20.0 contains a hard-coded credentials vulnerability that allows remote unauthenticated attackers to gain super-admin access through an AuthSeeder-created admin@laravel account with password admin. The account is seeded by the setup installer and silently re-created on every rpd:make run, letting attackers log in as a global super admin bypassing per-record authorization and tenant scoping.

- [https://github.com/hyderpwn/CVE-rapyd-admin](https://github.com/hyderpwn/CVE-rapyd-admin) :  ![starts](https://img.shields.io/github/stars/hyderpwn/CVE-rapyd-admin.svg) ![forks](https://img.shields.io/github/forks/hyderpwn/CVE-rapyd-admin.svg)


## CVE-2026-109384
 The The Innovative Form Builder – IvyForms plugin for WordPress is vulnerable to Arbitrary File Upload in all versions up to, and including, 1.5.1 via the filterFiletypeAndExt function. This is due to insufficient file type validation due to the absence of a dangerous-extension denylist in the allowed-extensions sanitizer and deliberate override of WordPress's native MIME and extension defences via a registered wp_check_filetype_and_ext filter. This makes it possible for authenticated attackers, with custom-level access and above, to upload files that may be executable, which makes remote code execution possible. An authenticated attacker with the custom add_edit_forms capability must first configure a File Upload field with a dangerous extension (e.g., php) in the allowed-extensions list; once that form is published, any unauthenticated visitor can trigger the actual file upload via the publicly accessible /wp-json/ivyforms/v1/form/submission/ REST route.

- [https://github.com/noxcrypt-x/CVE-2026-109384](https://github.com/noxcrypt-x/CVE-2026-109384) :  ![starts](https://img.shields.io/github/stars/noxcrypt-x/CVE-2026-109384.svg) ![forks](https://img.shields.io/github/forks/noxcrypt-x/CVE-2026-109384.svg)


## CVE-2026-108097
 Use of Externally-Controlled Input to Select Classes or Code ('Unsafe Reflection') vulnerability in Drupal Drupal core allows Reflection Injection. This issue affects Drupal core versions: from 8.9.0 to 10.6.19, from 11.0.0 to 11.3.19, from 11.4.0 to 11.4.10, from 12.0.0-alpha1 to 12.0.0-beta2.

- [https://github.com/ExDev994/CVE-2026-108097](https://github.com/ExDev994/CVE-2026-108097) :  ![starts](https://img.shields.io/github/stars/ExDev994/CVE-2026-108097.svg) ![forks](https://img.shields.io/github/forks/ExDev994/CVE-2026-108097.svg)
- [https://github.com/FurkanKAYAPINAR/CVE-2026-108097](https://github.com/FurkanKAYAPINAR/CVE-2026-108097) :  ![starts](https://img.shields.io/github/stars/FurkanKAYAPINAR/CVE-2026-108097.svg) ![forks](https://img.shields.io/github/forks/FurkanKAYAPINAR/CVE-2026-108097.svg)
- [https://github.com/fortbridge/cve-2026-108097-research](https://github.com/fortbridge/cve-2026-108097-research) :  ![starts](https://img.shields.io/github/stars/fortbridge/cve-2026-108097-research.svg) ![forks](https://img.shields.io/github/forks/fortbridge/cve-2026-108097-research.svg)


## CVE-2026-107824
 x64dbg-MCP Server is a native Model Context Protocol (MCP) plugin for x64dbg that exposes the debugger's full functionality over HTTP. Prior to 1.1, x64dbg-MCP Server exposes all MCP debugger tools over HTTP and SSE without authentication while listening on 0.0.0.0 by default. Any unauthenticated network client that can reach the default port, 9094 for x64 or 9095 for x32, can execute arbitrary x64dbg commands, attach to processes by PID, read and write debuggee memory, and write files to arbitrary paths. This issue is fixed in version 1.1.

- [https://github.com/Iceman2050/mcp-patch-gap-scanner](https://github.com/Iceman2050/mcp-patch-gap-scanner) :  ![starts](https://img.shields.io/github/stars/Iceman2050/mcp-patch-gap-scanner.svg) ![forks](https://img.shields.io/github/forks/Iceman2050/mcp-patch-gap-scanner.svg)


## CVE-2026-107326
 IBM Langflow OSS 1.0.0 through 1.12.4 could allow a remote authenticated attacker to execute arbitrary code due to improper neutralization of special elements used in an OS command.

- [https://github.com/rmhowe425/POC-CVE-2026-107326](https://github.com/rmhowe425/POC-CVE-2026-107326) :  ![starts](https://img.shields.io/github/stars/rmhowe425/POC-CVE-2026-107326.svg) ![forks](https://img.shields.io/github/forks/rmhowe425/POC-CVE-2026-107326.svg)


## CVE-2026-107268
 Insertion of Sensitive Information Into Sent Data vulnerability in Drupal Two Factor Authentication - TFA / Passwordless Login allows Forceful Browsing. This issue affects Two Factor Authentication - TFA / Passwordless Login versions: from 0.0.0 to 5.4.1, from 5.5.0 to 5.5.2.

- [https://github.com/yuwkaaa/CVE-2026-107268](https://github.com/yuwkaaa/CVE-2026-107268) :  ![starts](https://img.shields.io/github/stars/yuwkaaa/CVE-2026-107268.svg) ![forks](https://img.shields.io/github/forks/yuwkaaa/CVE-2026-107268.svg)


## CVE-2026-106378
 Privilege elevation in Sandbox in Google Chrome on on Mac prior to 155.0.8059.39 allowed a remote attacker who had compromised the renderer process to execute arbitrary code outside the sandbox via a crafted HTML page. (Chromium security severity: Medium)

- [https://github.com/leisureprog/CVE-2026-106378](https://github.com/leisureprog/CVE-2026-106378) :  ![starts](https://img.shields.io/github/stars/leisureprog/CVE-2026-106378.svg) ![forks](https://img.shields.io/github/forks/leisureprog/CVE-2026-106378.svg)


## CVE-2026-105697
 Langflow is a tool for building and deploying AI-powered agents and workflows. Before Langflow 1.10.3, the MCP stdio transport launched whatever command / args a user put in an MCP server configuration, with no allowlist and (before 1.10.3) wrapped in bash -c "exec {command} ...". Any user able to reach the MCP server settings ("Settings → MCP Servers → Add MCP Server", POST/PATCH /api/v2/mcp/servers/{server_name}) or to build a flow with the MCP Tools component could add a "server" whose command is an arbitrary OS command (touch, rm -rf, a reverse shell, ...). The command runs on the Langflow host as the Langflow process user as soon as Langflow tries to connect to the server (listing servers, loading tools, running the flow) — even when the UI then reports that the stdio server failed to start. With the default LANGFLOW_AUTO_LOGIN=true, GET /api/v1/auto_login hands out a token without credentials, so on an exposed instance running the default configuration this is reachable without an account. AUTO_LOGIN is documented as a development-only setting; with it disabled, any authenticated (non-admin) user can exploit it. This issue is fixed in Langflow 1.10.3, langflow-base 0.10.3, and lfx 1.10.3.

- [https://github.com/Iceman2050/mcp-patch-gap-scanner](https://github.com/Iceman2050/mcp-patch-gap-scanner) :  ![starts](https://img.shields.io/github/stars/Iceman2050/mcp-patch-gap-scanner.svg) ![forks](https://img.shields.io/github/forks/Iceman2050/mcp-patch-gap-scanner.svg)


## CVE-2026-104850
 MCP TypeScript SDK is the official TypeScript SDK for Model Context Protocol servers and clients. Starting in version 1.12.0 and prior to versions 1.31.0 and 2.2.0, the SDK's OAuth client support let the MCP server a client connected to decide which authorization server received the client's OAuth credentials. Stored and pre-provisioned credentials were not bound to the authorization server they belong to. A malicious or compromised MCP server could name its own authorization server in its protected resource metadata. Without any user interaction, the client would send that server the `refresh_token` and `client_secret` stored from an earlier sign-in (1.x), or the configured `client_secret` or signed assertion of a bundled non-interactive provider (1.x and 2.x). Only those applications that use the SDK as an MCP client over HTTP with an `authProvider`: your own `OAuthClientProvider`, or the bundled `ClientCredentialsProvider`, `PrivateKeyJwtProvider`, `StaticPrivateKeyJwtProvider` or (2.x) `CrossAppAccessProvider` and that may connect to an MCP server the owners does not fully trust while holding credentials for a legitimate authorization server are affected. `@modelcontextprotocol/sdk` 1.31.0 (1.x) and `@modelcontextprotocol/client` 2.2.0 (2.x) patch the issue. A workaround for those who cannot upgrade is available. 2.0.0 and 2.1.0 already accept `expectedIssuer`. On 1.x, the only workaround is to connect OAuth-enabled clients only to MCP servers you trust.

- [https://github.com/Iceman2050/mcp-oauth-discovery-prober](https://github.com/Iceman2050/mcp-oauth-discovery-prober) :  ![starts](https://img.shields.io/github/stars/Iceman2050/mcp-oauth-discovery-prober.svg) ![forks](https://img.shields.io/github/forks/Iceman2050/mcp-oauth-discovery-prober.svg)


## CVE-2026-104623
 A security vulnerability exists in the authorization handling for the local (management) cluster shell feature of SUSE Rancher Manager 2.15.0 up to 2.15.3, 2.14.0 up to 2.14.7, 2.13.0 up to 2.13.11, 2.12.0 up to 2.12.15, 2.11.0 up to 2.11.19 and possible older versions. The authorization check that was introduced to protect this feature was not applied to every API route that can reach it, so an alternative request form reached the shell handler without the access check being evaluated. This could allow any authenticated users to run a pod on the management cluster.

- [https://github.com/googlesky/CVE-2026-104623](https://github.com/googlesky/CVE-2026-104623) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-104623.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-104623.svg)


## CVE-2026-104120
 A security vulnerability has been detected in modelcontextprotocol mcp-server-fetch and mcp-server-everything up to 2026.6.4. Affected is the function fetch_url of the file mcp_server_fetch/server.py of the component Fetch Tool. The manipulation of the argument url/path leads to server-side request forgery. The attack may be initiated remotely. The exploit has been disclosed publicly and may be used. The pull request to fix this issue awaits acceptance.

- [https://github.com/Iceman2050/mcp-patch-gap-scanner](https://github.com/Iceman2050/mcp-patch-gap-scanner) :  ![starts](https://img.shields.io/github/stars/Iceman2050/mcp-patch-gap-scanner.svg) ![forks](https://img.shields.io/github/forks/Iceman2050/mcp-patch-gap-scanner.svg)


## CVE-2026-103688
 The Checkout Files Upload for WooCommerce WordPress plugin before 2.4.0 does not validate uploaded file types when its accepted file types setting is left empty, which it documents as the way to accept all files, allowing unauthenticated users to upload arbitrary files, including PHP files that lead to remote code execution on servers that execute PHP from the uploads directory.

- [https://github.com/noxcrypt-x/CVE-2026-103688](https://github.com/noxcrypt-x/CVE-2026-103688) :  ![starts](https://img.shields.io/github/stars/noxcrypt-x/CVE-2026-103688.svg) ![forks](https://img.shields.io/github/forks/noxcrypt-x/CVE-2026-103688.svg)


## CVE-2026-103409
Note that this vulnerability can only be exploited prior to the device being onboarded to Mist/Conductor. The issue can no longer be exploited once a device is onboarded to Mist/Conductor.

- [https://github.com/Hunt-Benito/the-unguarded-first-day-cve-2026-103409-juniper-session-smart-router](https://github.com/Hunt-Benito/the-unguarded-first-day-cve-2026-103409-juniper-session-smart-router) :  ![starts](https://img.shields.io/github/stars/Hunt-Benito/the-unguarded-first-day-cve-2026-103409-juniper-session-smart-router.svg) ![forks](https://img.shields.io/github/forks/Hunt-Benito/the-unguarded-first-day-cve-2026-103409-juniper-session-smart-router.svg)


## CVE-2026-103056
 AiSOC versions 7.2.0 before 12.0.0 contain a command injection vulnerability in the actions service that builds CrowdStrike Real Time Response command strings by interpolating unescaped action parameters in crowdstrike_rtr.py and endpoint.py. Authenticated users can inject single quotes into file_path, path, script_name, or script_args parameters to break out of quoted arguments and execute arbitrary commands on managed endpoints with SYSTEM or root privileges.

- [https://github.com/hyderpwn/CVE-aisoc](https://github.com/hyderpwn/CVE-aisoc) :  ![starts](https://img.shields.io/github/stars/hyderpwn/CVE-aisoc.svg) ![forks](https://img.shields.io/github/forks/hyderpwn/CVE-aisoc.svg)


## CVE-2026-101767
 Vulnerability in the Oracle Application Object Library product of Oracle E-Business Suite (component: Core).  Supported versions that are affected are 12.2.3-12.2.15. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Application Object Library.  Successful attacks of this vulnerability can result in takeover of Oracle Application Object Library. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/shivrajem/ebs-cve-2026-101767-check](https://github.com/shivrajem/ebs-cve-2026-101767-check) :  ![starts](https://img.shields.io/github/stars/shivrajem/ebs-cve-2026-101767-check.svg) ![forks](https://img.shields.io/github/forks/shivrajem/ebs-cve-2026-101767-check.svg)


## CVE-2026-98432
will be addressed in a separate patch.

- [https://github.com/tc4dy/CVE-2026-98432-PoC-Exploit](https://github.com/tc4dy/CVE-2026-98432-PoC-Exploit) :  ![starts](https://img.shields.io/github/stars/tc4dy/CVE-2026-98432-PoC-Exploit.svg) ![forks](https://img.shields.io/github/forks/tc4dy/CVE-2026-98432-PoC-Exploit.svg)
- [https://github.com/Alucard0x1/cve-2026-98432](https://github.com/Alucard0x1/cve-2026-98432) :  ![starts](https://img.shields.io/github/stars/Alucard0x1/cve-2026-98432.svg) ![forks](https://img.shields.io/github/forks/Alucard0x1/cve-2026-98432.svg)
- [https://github.com/bitwire-it/Probe-CVE-2026-98432](https://github.com/bitwire-it/Probe-CVE-2026-98432) :  ![starts](https://img.shields.io/github/stars/bitwire-it/Probe-CVE-2026-98432.svg) ![forks](https://img.shields.io/github/forks/bitwire-it/Probe-CVE-2026-98432.svg)
- [https://github.com/MikkoAbudo/CVE-2026-98432-POC](https://github.com/MikkoAbudo/CVE-2026-98432-POC) :  ![starts](https://img.shields.io/github/stars/MikkoAbudo/CVE-2026-98432-POC.svg) ![forks](https://img.shields.io/github/forks/MikkoAbudo/CVE-2026-98432-POC.svg)
- [https://github.com/davetha/cve-2026-98432](https://github.com/davetha/cve-2026-98432) :  ![starts](https://img.shields.io/github/stars/davetha/cve-2026-98432.svg) ![forks](https://img.shields.io/github/forks/davetha/cve-2026-98432.svg)
- [https://github.com/xen0bit/netprobe-cve-2026-98432](https://github.com/xen0bit/netprobe-cve-2026-98432) :  ![starts](https://img.shields.io/github/stars/xen0bit/netprobe-cve-2026-98432.svg) ![forks](https://img.shields.io/github/forks/xen0bit/netprobe-cve-2026-98432.svg)
- [https://github.com/ZombiePm/cve-2026-98432-mitigation](https://github.com/ZombiePm/cve-2026-98432-mitigation) :  ![starts](https://img.shields.io/github/stars/ZombiePm/cve-2026-98432-mitigation.svg) ![forks](https://img.shields.io/github/forks/ZombiePm/cve-2026-98432-mitigation.svg)
- [https://github.com/fbuff-tools/cve-2026-98432-checker](https://github.com/fbuff-tools/cve-2026-98432-checker) :  ![starts](https://img.shields.io/github/stars/fbuff-tools/cve-2026-98432-checker.svg) ![forks](https://img.shields.io/github/forks/fbuff-tools/cve-2026-98432-checker.svg)
- [https://github.com/scriptzteam/Paranoid-CVE-2026-98432](https://github.com/scriptzteam/Paranoid-CVE-2026-98432) :  ![starts](https://img.shields.io/github/stars/scriptzteam/Paranoid-CVE-2026-98432.svg) ![forks](https://img.shields.io/github/forks/scriptzteam/Paranoid-CVE-2026-98432.svg)
- [https://github.com/brett6320/fix_CVE-2026-98432](https://github.com/brett6320/fix_CVE-2026-98432) :  ![starts](https://img.shields.io/github/stars/brett6320/fix_CVE-2026-98432.svg) ![forks](https://img.shields.io/github/forks/brett6320/fix_CVE-2026-98432.svg)
- [https://github.com/akamai/cve-2026-98432-validation-mitigation](https://github.com/akamai/cve-2026-98432-validation-mitigation) :  ![starts](https://img.shields.io/github/stars/akamai/cve-2026-98432-validation-mitigation.svg) ![forks](https://img.shields.io/github/forks/akamai/cve-2026-98432-validation-mitigation.svg)
- [https://github.com/medandevsec/cve-2026-98432-ubuntu-analisis](https://github.com/medandevsec/cve-2026-98432-ubuntu-analisis) :  ![starts](https://img.shields.io/github/stars/medandevsec/cve-2026-98432-ubuntu-analisis.svg) ![forks](https://img.shields.io/github/forks/medandevsec/cve-2026-98432-ubuntu-analisis.svg)
- [https://github.com/polikhronidi/cve-2026-98432-ubuntu-backport](https://github.com/polikhronidi/cve-2026-98432-ubuntu-backport) :  ![starts](https://img.shields.io/github/stars/polikhronidi/cve-2026-98432-ubuntu-backport.svg) ![forks](https://img.shields.io/github/forks/polikhronidi/cve-2026-98432-ubuntu-backport.svg)
- [https://github.com/pob220/ubuntu-noble-tcp-rcu-backport](https://github.com/pob220/ubuntu-noble-tcp-rcu-backport) :  ![starts](https://img.shields.io/github/stars/pob220/ubuntu-noble-tcp-rcu-backport.svg) ![forks](https://img.shields.io/github/forks/pob220/ubuntu-noble-tcp-rcu-backport.svg)
- [https://github.com/offline-ant/tcp2kaslr](https://github.com/offline-ant/tcp2kaslr) :  ![starts](https://img.shields.io/github/stars/offline-ant/tcp2kaslr.svg) ![forks](https://img.shields.io/github/forks/offline-ant/tcp2kaslr.svg)
- [https://github.com/adeptum-labs/cve-emergency-monitor](https://github.com/adeptum-labs/cve-emergency-monitor) :  ![starts](https://img.shields.io/github/stars/adeptum-labs/cve-emergency-monitor.svg) ![forks](https://img.shields.io/github/forks/adeptum-labs/cve-emergency-monitor.svg)


## CVE-2026-98260
[ tglx: Move the cleanup right after de_thread() ]

- [https://github.com/AmarnathCJD/CVE-2026-98260-IQOO-13](https://github.com/AmarnathCJD/CVE-2026-98260-IQOO-13) :  ![starts](https://img.shields.io/github/stars/AmarnathCJD/CVE-2026-98260-IQOO-13.svg) ![forks](https://img.shields.io/github/forks/AmarnathCJD/CVE-2026-98260-IQOO-13.svg)
- [https://github.com/molanp/CVE-2026-98260-vivo-s60-poc](https://github.com/molanp/CVE-2026-98260-vivo-s60-poc) :  ![starts](https://img.shields.io/github/stars/molanp/CVE-2026-98260-vivo-s60-poc.svg) ![forks](https://img.shields.io/github/forks/molanp/CVE-2026-98260-vivo-s60-poc.svg)


## CVE-2026-97229
 GitLab has remediated an issue in GitLab CE/EE affecting all versions from 19.2 before 19.2.8, 19.3 before 19.3.5, and 19.4 before 19.4.2 that, under certain conditions, could have allowed an unauthenticated user to execute arbitrary code on the GitLab server via a specially crafted regular expression in a CI/CD configuration, due to insufficient regular expression validation.

- [https://github.com/foxcornlab/gitlab-onigmo-scanner](https://github.com/foxcornlab/gitlab-onigmo-scanner) :  ![starts](https://img.shields.io/github/stars/foxcornlab/gitlab-onigmo-scanner.svg) ![forks](https://img.shields.io/github/forks/foxcornlab/gitlab-onigmo-scanner.svg)


## CVE-2026-93489
Refer to the ' Security Update for ASUS Router Firmware ' section on the ASUS Security Advisory for more information.

- [https://github.com/cybersecurity/CVE-2026-93489](https://github.com/cybersecurity/CVE-2026-93489) :  ![starts](https://img.shields.io/github/stars/cybersecurity/CVE-2026-93489.svg) ![forks](https://img.shields.io/github/forks/cybersecurity/CVE-2026-93489.svg)


## CVE-2026-92744
arbitrary code as LocalSystem.

- [https://github.com/isukasanuj/CVE-2026-92744](https://github.com/isukasanuj/CVE-2026-92744) :  ![starts](https://img.shields.io/github/stars/isukasanuj/CVE-2026-92744.svg) ![forks](https://img.shields.io/github/forks/isukasanuj/CVE-2026-92744.svg)


## CVE-2026-89020
 MikroTik RouterOS before 7.23.4 (long-term) and 7.24.2 (stable) contains a stack-based buffer overflow vulnerability in the mtget binary's TFTP RRQ builder function that allows authenticated users to crash the mtget worker process by supplying a URL path of 507 bytes or more to the /tool fetch command; the first write outside the 528-byte buffer occurs at 505 bytes. Attackers can trigger the overflow by issuing a fetch command with a crafted tftp:// URL path, which causes an unbounded rep movsb instruction to overwrite saved registers at a deterministic offset, crashing the process without requiring a reachable TFTP server or elevated privileges beyond read-only group membership.

- [https://github.com/davtur19/PoC-CVE-2026-89020-PrivEsc](https://github.com/davtur19/PoC-CVE-2026-89020-PrivEsc) :  ![starts](https://img.shields.io/github/stars/davtur19/PoC-CVE-2026-89020-PrivEsc.svg) ![forks](https://img.shields.io/github/forks/davtur19/PoC-CVE-2026-89020-PrivEsc.svg)


## CVE-2026-82384
 Deserialization of Untrusted Data in Apache Roller 6.1.5 allows an unauthenticated remote attacker to cause deserialization of attacker-controlled bytes, because the XML-RPC endpoint accepts vendor extension types that are deserialized during request parsing, before authentication. The servlet is mapped unconditionally, so parsing occurs even when the global XML-RPC feature is set to disabled; no non-default configuration is required for this path. This can lead to remote code execution. Users are recommended to upgrade to Apache Roller 6.1.6 or later, which disables the extension types and rejects requests when the XML-RPC feature is disabled.

- [https://github.com/krevetkqqq/CVE-2026-82384](https://github.com/krevetkqqq/CVE-2026-82384) :  ![starts](https://img.shields.io/github/stars/krevetkqqq/CVE-2026-82384.svg) ![forks](https://img.shields.io/github/forks/krevetkqqq/CVE-2026-82384.svg)


## CVE-2026-64560
---truncated---

- [https://github.com/aucai/Redmi-K90-CVE-2026-64560](https://github.com/aucai/Redmi-K90-CVE-2026-64560) :  ![starts](https://img.shields.io/github/stars/aucai/Redmi-K90-CVE-2026-64560.svg) ![forks](https://img.shields.io/github/forks/aucai/Redmi-K90-CVE-2026-64560.svg)
- [https://github.com/youssefnoser/opd2415-6.6.118-cve-2026-64560-ksu](https://github.com/youssefnoser/opd2415-6.6.118-cve-2026-64560-ksu) :  ![starts](https://img.shields.io/github/stars/youssefnoser/opd2415-6.6.118-cve-2026-64560-ksu.svg) ![forks](https://img.shields.io/github/forks/youssefnoser/opd2415-6.6.118-cve-2026-64560-ksu.svg)


## CVE-2026-62958
 libriscv is a RISC-V sandbox and emulator. Prior to 1.18, a crafted ELF binary can cause out-of-bounds reads in the host emulator. `MemoryW::binary_loader` checks `PT_LOAD` program-header bounds, but `MemoryW::serialize_execute_segment` trusts section-header `sh_offset` and `sh_size` when locating `.text` without verifying the file range against `m_binary.size()`; `MemoryW::lookup()` has a similar section-table problem. Malformed `.text` or `.symtab` offsets can therefore bypass the program-header checks and point outside the binary buffer, crashing rvlinux. With suitable memory layout or integer overflow, out-of-buffer host heap memory may instead be mapped into the guest by `create_execute_segment()`, potentially exposing host memory. The reported reproducer demonstrates a host SIGSEGV, while memory disclosure through grooming is described as possible rather than demonstrated. This issue is fixed in version 1.18.

- [https://github.com/0Linear/CVE-2026-62958](https://github.com/0Linear/CVE-2026-62958) :  ![starts](https://img.shields.io/github/stars/0Linear/CVE-2026-62958.svg) ![forks](https://img.shields.io/github/forks/0Linear/CVE-2026-62958.svg)


## CVE-2026-61732
 Decepticon is an autonomous hacking agent for red teams. Versions prior to 1.1.17 wrap web crawl results — the output of agent reconnaissance against target services — into LLM messages without neutralizing ChatML special-token literals. Under the BYOK (Bring Your Own Key) deployment model, users configure their own LLM credentials to any OpenAI-compatible endpoint. Most open-source and self-deployed model providers (vLLM, SGLang, Ollama, LM Studio, text-generation-webui, etc.) do not filter special-token literals from user content in their default configurations. Those literals are parsed into structural role-boundary token IDs, meaning an attacker string planted in a target web page forges a new operator turn the model treats as authoritative, bypassing Decepticon's agent guardrails and resulting in arbitrary command execution inside the Kali Linux sandbox. Version 1.1.17 patches the issue.

- [https://github.com/Iceman2050/chatml-role-token-probe](https://github.com/Iceman2050/chatml-role-token-probe) :  ![starts](https://img.shields.io/github/stars/Iceman2050/chatml-role-token-probe.svg) ![forks](https://img.shields.io/github/forks/Iceman2050/chatml-role-token-probe.svg)


## CVE-2026-61515
 Puwell IP Camera firmware versions 2.x through 4.x contains an unauthenticated command injection vulnerability that allows remote attackers to execute arbitrary operating system commands by sending a crafted JSON payload to the DebugShell interface exposed on TCP port 34567. Attackers can exploit the lack of authentication and input sanitization in the binary protocol service to pass arbitrary commands directly to the underlying operating system, achieving root-level code execution and complete device compromise.

- [https://github.com/krevetkqqq/CVE-2026-61515](https://github.com/krevetkqqq/CVE-2026-61515) :  ![starts](https://img.shields.io/github/stars/krevetkqqq/CVE-2026-61515.svg) ![forks](https://img.shields.io/github/forks/krevetkqqq/CVE-2026-61515.svg)


## CVE-2026-49468
 LiteLLM is a proxy server (AI Gateway) to call LLM APIs in OpenAI (or native) format. Prior to 1.84.0, a Host-header parsing flaw in the LiteLLM proxy could, under specific conditions, allow unauthenticated access to protected management routes. The auth layer derived the effective route from request.url.path in litellm/proxy/auth/auth_utils.py::get_request_route(), which Starlette reconstructs from the Host header. A crafted Host could therefore make the auth gate evaluate a different route from the one FastAPI dispatched. This vulnerability is fixed in 1.84.0.

- [https://github.com/krevetkqqq/CVE-2026-49468](https://github.com/krevetkqqq/CVE-2026-49468) :  ![starts](https://img.shields.io/github/stars/krevetkqqq/CVE-2026-49468.svg) ![forks](https://img.shields.io/github/forks/krevetkqqq/CVE-2026-49468.svg)


## CVE-2026-48500
 Filament is a collection of full-stack components for accelerated Laravel development. From 3.0.0 until 3.3.52, 4.11.5, and 5.6.5, any schema can contain a file upload form field, so Filament applies Livewire's WithFileUploads trait to the Livewire component the schema is embedded in. However, some schemas, such as the panel login form, do not require file uploads, and exposing unauthenticated temporary file uploads on these components is not an acceptable risk. On these components, an unauthenticated attacker could upload arbitrary files to the application's temporary storage, which could be abused to exhaust disk space or inflate storage costs. This vulnerability is fixed in 3.3.52, 4.11.5, and 5.6.5.

- [https://github.com/inj3ct00r/CVE-2026-48500](https://github.com/inj3ct00r/CVE-2026-48500) :  ![starts](https://img.shields.io/github/stars/inj3ct00r/CVE-2026-48500.svg) ![forks](https://img.shields.io/github/forks/inj3ct00r/CVE-2026-48500.svg)


## CVE-2026-46300
bytes into @to's linear data rather than transferring frag descriptors.

- [https://github.com/clearhandreview/panos-php2shell-defense](https://github.com/clearhandreview/panos-php2shell-defense) :  ![starts](https://img.shields.io/github/stars/clearhandreview/panos-php2shell-defense.svg) ![forks](https://img.shields.io/github/forks/clearhandreview/panos-php2shell-defense.svg)


## CVE-2026-41940
 cPanel and WHM versions after 11.40 contain an authentication bypass vulnerability in the login flow that allows unauthenticated remote attackers to gain unauthorized access to the control panel.

- [https://github.com/willygailo/CVE-2026-41940-Linux](https://github.com/willygailo/CVE-2026-41940-Linux) :  ![starts](https://img.shields.io/github/stars/willygailo/CVE-2026-41940-Linux.svg) ![forks](https://img.shields.io/github/forks/willygailo/CVE-2026-41940-Linux.svg)


## CVE-2026-40489
 editorconfig-core-c  is an EditorConfig core library for use by plugins supporting EditorConfig parsing. Versions up to and including 0.12.10 have a stack-based buffer overflow in ec_glob() that allows an attacker to crash any application using libeditorconfig by providing a specially crafted directory structure and .editorconfig file. This is an incomplete fix for CVE-2023-0341. The pcre_str buffer was protected in 0.12.6 but the adjacent l_pattern[8194] stack buffer received no equivalent protection. On Ubuntu 24.04, FORTIFY_SOURCE converts the overflow to SIGABRT (DoS). Version 0.12.11 contains an updated fix.

- [https://github.com/saretawa/CVE-2026-40489](https://github.com/saretawa/CVE-2026-40489) :  ![starts](https://img.shields.io/github/stars/saretawa/CVE-2026-40489.svg) ![forks](https://img.shields.io/github/forks/saretawa/CVE-2026-40489.svg)


## CVE-2026-38751
 OpenSTAManager version 2.10 and earlier contains an arbitrary file upload vulnerability in the module update functionality (modules/aggiornamenti/upload_modules.php)

- [https://github.com/UnDefinedCS/CVE-2026-38751-exploit](https://github.com/UnDefinedCS/CVE-2026-38751-exploit) :  ![starts](https://img.shields.io/github/stars/UnDefinedCS/CVE-2026-38751-exploit.svg) ![forks](https://img.shields.io/github/forks/UnDefinedCS/CVE-2026-38751-exploit.svg)


## CVE-2026-29000
 pac4j-jwt versions prior to 4.5.9, 5.7.9, and 6.3.3 contain an authentication bypass vulnerability in JwtAuthenticator when processing encrypted JWTs that allows remote attackers to forge authentication tokens. Attackers who possess the server's RSA public key can create a JWE-wrapped PlainJWT with arbitrary subject and role claims, bypassing signature verification to authenticate as any user including administrators.

- [https://github.com/tscherwinski/CVE-2026-29000-jweforge](https://github.com/tscherwinski/CVE-2026-29000-jweforge) :  ![starts](https://img.shields.io/github/stars/tscherwinski/CVE-2026-29000-jweforge.svg) ![forks](https://img.shields.io/github/forks/tscherwinski/CVE-2026-29000-jweforge.svg)


## CVE-2026-27626
 OliveTin gives access to predefined shell commands from a web interface. In versions up to and including 3000.10.0, OliveTin's shell mode safety check (`checkShellArgumentSafety`) blocks several dangerous argument types but not `password`. A user supplying a `password`-typed argument can inject shell metacharacters that execute arbitrary OS commands. A second independent vector allows unauthenticated RCE via webhook-extracted JSON values that skip type safety checks entirely before reaching `sh -c`. When exploiting vector 1, any authenticated user (registration enabled by default, `authType: none` by default) can execute arbitrary OS commands on the OliveTin host with the permissions of the OliveTin process. When exploiting vector 2, an unauthenticated attacker can achieve the same if the instance receives webhooks from external sources, which is a primary OliveTin use case. When an attacker exploits both vectors, this results in unauthenticated RCE on any OliveTin instance using Shell mode with webhook-triggered actions. As of time of publication, a patched version is not available.

- [https://github.com/Cobrastrike62/CVE-2026-27626-POC](https://github.com/Cobrastrike62/CVE-2026-27626-POC) :  ![starts](https://img.shields.io/github/stars/Cobrastrike62/CVE-2026-27626-POC.svg) ![forks](https://img.shields.io/github/forks/Cobrastrike62/CVE-2026-27626-POC.svg)
- [https://github.com/Shisones/CVE-2026-27626](https://github.com/Shisones/CVE-2026-27626) :  ![starts](https://img.shields.io/github/stars/Shisones/CVE-2026-27626.svg) ![forks](https://img.shields.io/github/forks/Shisones/CVE-2026-27626.svg)


## CVE-2026-20687
 A use after free issue was addressed with improved memory management. This issue is fixed in iOS 18.7.7 and iPadOS 18.7.7, iOS 26.4 and iPadOS 26.4, macOS Sequoia 15.7.5, macOS Tahoe 26.4, tvOS 26.4, watchOS 26.4. An app may be able to cause unexpected system termination or write kernel memory.

- [https://github.com/nenasevartem70-cmyk/hidra](https://github.com/nenasevartem70-cmyk/hidra) :  ![starts](https://img.shields.io/github/stars/nenasevartem70-cmyk/hidra.svg) ![forks](https://img.shields.io/github/forks/nenasevartem70-cmyk/hidra.svg)


## CVE-2026-13684
 An improper encoding or escaping of output vulnerability in SCGI in Synology DiskStation Manager (DSM) before 7.2.1-69057-12, 7.2.2-72806-9, 7.3.2-86009-4 and 7.4-90075 allows remote attackers to read or write arbitrary files and conduct denial-of-service attacks.

- [https://github.com/SHIFox8/synology-dsm-vuln-scanner](https://github.com/SHIFox8/synology-dsm-vuln-scanner) :  ![starts](https://img.shields.io/github/stars/SHIFox8/synology-dsm-vuln-scanner.svg) ![forks](https://img.shields.io/github/forks/SHIFox8/synology-dsm-vuln-scanner.svg)


## CVE-2026-10961
 Use after free in Chrome for iOS in Google Chrome on iOS prior to 149.0.7827.53 allowed a remote attacker who had compromised the renderer process to potentially perform a sandbox escape via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/alvaroguzmancode/CVE-2026-109618](https://github.com/alvaroguzmancode/CVE-2026-109618) :  ![starts](https://img.shields.io/github/stars/alvaroguzmancode/CVE-2026-109618.svg) ![forks](https://img.shields.io/github/forks/alvaroguzmancode/CVE-2026-109618.svg)


## CVE-2026-6516
 Zohocorp ManageEngine ADAudit Plus versions before 8606 are affected by Unauthenticated Remote code execution due to the vulnerable agent API.

- [https://github.com/t3chn0t3s-org/cve-2026-6516-scanner](https://github.com/t3chn0t3s-org/cve-2026-6516-scanner) :  ![starts](https://img.shields.io/github/stars/t3chn0t3s-org/cve-2026-6516-scanner.svg) ![forks](https://img.shields.io/github/forks/t3chn0t3s-org/cve-2026-6516-scanner.svg)


## CVE-2026-3891
 The Pix for WooCommerce plugin for WordPress is vulnerable to arbitrary file uploads due to missing capability check and missing file type validation in the 'lkn_pix_for_woocommerce_c6_save_settings' function in all versions up to, and including, 1.5.0. This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible.

- [https://github.com/willygailo/CVE-2026-3891-Linux](https://github.com/willygailo/CVE-2026-3891-Linux) :  ![starts](https://img.shields.io/github/stars/willygailo/CVE-2026-3891-Linux.svg) ![forks](https://img.shields.io/github/forks/willygailo/CVE-2026-3891-Linux.svg)


## CVE-2026-2005
 Heap buffer overflow in PostgreSQL pgcrypto allows a ciphertext provider to execute arbitrary code as the operating system user running the database.  Versions before PostgreSQL 18.2, 17.8, 16.12, 15.16, and 14.21 are affected.

- [https://github.com/M3str3/CVE-2026-2005](https://github.com/M3str3/CVE-2026-2005) :  ![starts](https://img.shields.io/github/stars/M3str3/CVE-2026-2005.svg) ![forks](https://img.shields.io/github/forks/M3str3/CVE-2026-2005.svg)


## CVE-2026-1555
 The WebStack theme for WordPress is vulnerable to arbitrary file uploads due to missing file type validation in the io_img_upload() function in all versions up to, and including, 1.2024. This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible.

- [https://github.com/willygailo/WG-CVE-2026-1555-Linux](https://github.com/willygailo/WG-CVE-2026-1555-Linux) :  ![starts](https://img.shields.io/github/stars/willygailo/WG-CVE-2026-1555-Linux.svg) ![forks](https://img.shields.io/github/forks/willygailo/WG-CVE-2026-1555-Linux.svg)


## CVE-2026-1337
Proof of concept exploit:  https://github.com/JoakimBulow/CVE-2026-1337

- [https://github.com/primatelab/bash2shell](https://github.com/primatelab/bash2shell) :  ![starts](https://img.shields.io/github/stars/primatelab/bash2shell.svg) ![forks](https://img.shields.io/github/forks/primatelab/bash2shell.svg)


## CVE-2026-1096
 The Best-wp-google-map plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the 'latitude' and 'longitudinal' parameters of the 'google_map_view' shortcode in all versions up to, and including, 2.1 due to insufficient input sanitization and output escaping. This makes it possible for authenticated attackers, with Contributor-level access and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.

- [https://github.com/1Nightlovel/CVE-2026-109618](https://github.com/1Nightlovel/CVE-2026-109618) :  ![starts](https://img.shields.io/github/stars/1Nightlovel/CVE-2026-109618.svg) ![forks](https://img.shields.io/github/forks/1Nightlovel/CVE-2026-109618.svg)
- [https://github.com/MorphingYU/CVE-2026-109618](https://github.com/MorphingYU/CVE-2026-109618) :  ![starts](https://img.shields.io/github/stars/MorphingYU/CVE-2026-109618.svg) ![forks](https://img.shields.io/github/forks/MorphingYU/CVE-2026-109618.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict.svg)


## CVE-2025-51482
 Remote Code Execution in letta.server.rest_api.routers.v1.tools.run_tool_from_source in letta-ai Letta 0.7.12 allows remote attackers to execute arbitrary Python code and system commands via crafted payloads to the /v1/tools/run endpoint, bypassing intended sandbox restrictions.

- [https://github.com/diamorphine666/CVE-2024-51482](https://github.com/diamorphine666/CVE-2024-51482) :  ![starts](https://img.shields.io/github/stars/diamorphine666/CVE-2024-51482.svg) ![forks](https://img.shields.io/github/forks/diamorphine666/CVE-2024-51482.svg)


## CVE-2025-43520
 A memory corruption issue was addressed with improved memory handling. This issue is fixed in iOS 18.7.2 and iPadOS 18.7.2, iOS 26.1 and iPadOS 26.1, macOS Sequoia 15.7.2, macOS Sonoma 14.8.2, macOS Tahoe 26.1, tvOS 26.1, visionOS 26.1, watchOS 26.1. A malicious application may be able to cause unexpected system termination or write kernel memory.

- [https://github.com/df2029/cs-build](https://github.com/df2029/cs-build) :  ![starts](https://img.shields.io/github/stars/df2029/cs-build.svg) ![forks](https://img.shields.io/github/forks/df2029/cs-build.svg)


## CVE-2025-31277
 The issue was addressed with improved memory handling. This issue is fixed in Safari 18.6, iOS 18.6 and iPadOS 18.6, macOS Sequoia 15.6, tvOS 18.6, visionOS 2.6, watchOS 11.6. Processing maliciously crafted web content may lead to memory corruption.

- [https://github.com/hoarseprairie/CVE-2025-31277-WebKit-Memory-Corruption-Patch-Bypass](https://github.com/hoarseprairie/CVE-2025-31277-WebKit-Memory-Corruption-Patch-Bypass) :  ![starts](https://img.shields.io/github/stars/hoarseprairie/CVE-2025-31277-WebKit-Memory-Corruption-Patch-Bypass.svg) ![forks](https://img.shields.io/github/forks/hoarseprairie/CVE-2025-31277-WebKit-Memory-Corruption-Patch-Bypass.svg)


## CVE-2025-31161
 CrushFTP 10 before 10.8.4 and 11 before 11.3.1 allows authentication bypass and takeover of the crushadmin account (unless a DMZ proxy instance is used), as exploited in the wild in March and April 2025, aka "Unauthenticated HTTP(S) port access." A race condition exists in the AWS4-HMAC (compatible with S3) authorization method of the HTTP component of the FTP server. The server first verifies the existence of the user by performing a call to login_user_pass() with no password requirement. This will authenticate the session through the HMAC verification process and up until the server checks for user verification once more. The vulnerability can be further stabilized, eliminating the need for successfully triggering a race condition, by sending a mangled AWS4-HMAC header. By providing only the username and a following slash (/), the server will successfully find a username, which triggers the successful anypass authentication process, but the server will fail to find the expected SignedHeaders entry, resulting in an index-out-of-bounds error that stops the code from reaching the session cleanup. Together, these issues make it trivial to authenticate as any known or guessable user (e.g., crushadmin), and can lead to a full compromise of the system by obtaining an administrative account.

- [https://github.com/Shisones/CVE-2025-31161](https://github.com/Shisones/CVE-2025-31161) :  ![starts](https://img.shields.io/github/stars/Shisones/CVE-2025-31161.svg) ![forks](https://img.shields.io/github/forks/Shisones/CVE-2025-31161.svg)


## CVE-2025-28137
 The TOTOLINK A810R V4.1.2cu.5182_B20201026 were found to contain a pre-auth remote command execution vulnerability in the setNoticeCfg function through the NoticeUrl parameter.

- [https://github.com/krevetkqqq/CVE-2025-28137](https://github.com/krevetkqqq/CVE-2025-28137) :  ![starts](https://img.shields.io/github/stars/krevetkqqq/CVE-2025-28137.svg) ![forks](https://img.shields.io/github/forks/krevetkqqq/CVE-2025-28137.svg)


## CVE-2025-20393
This vulnerability is due to insufficient validation of HTTP requests by the Spam Quarantine feature. An attacker could exploit this vulnerability by sending a crafted HTTP request to the affected device. A successful exploit could allow the attacker to execute arbitrary commands on the underlying operating system with&nbsp;root privileges.

- [https://github.com/StasonJatham/cisco-sa-sma-attack-N9bf4](https://github.com/StasonJatham/cisco-sa-sma-attack-N9bf4) :  ![starts](https://img.shields.io/github/stars/StasonJatham/cisco-sa-sma-attack-N9bf4.svg) ![forks](https://img.shields.io/github/forks/StasonJatham/cisco-sa-sma-attack-N9bf4.svg)


## CVE-2025-14847
 Mismatched length fields in Zlib compressed protocol headers may allow a read of uninitialized heap memory by an unauthenticated client. This issue affects all MongoDB Server v7.0 prior to 7.0.28 versions, MongoDB Server v8.0 versions prior to 8.0.17, MongoDB Server v8.2 versions prior to 8.2.3, MongoDB Server v6.0 versions prior to 6.0.27, MongoDB Server v5.0 versions prior to 5.0.32, MongoDB Server v4.4 versions prior to 4.4.30, MongoDB Server v4.2 versions greater than or equal to 4.2.0, MongoDB Server v4.0 versions greater than or equal to 4.0.0, and MongoDB Server v3.6 versions greater than or equal to 3.6.0.

- [https://github.com/t3chn0t3s-org/cve-2025-14847-scanner](https://github.com/t3chn0t3s-org/cve-2025-14847-scanner) :  ![starts](https://img.shields.io/github/stars/t3chn0t3s-org/cve-2025-14847-scanner.svg) ![forks](https://img.shields.io/github/forks/t3chn0t3s-org/cve-2025-14847-scanner.svg)


## CVE-2025-6647
The specific flaw exists within the parsing of U3D files. The issue results from the lack of proper validation of user-supplied data, which can result in a write past the end of an allocated object. An attacker can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-26644.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm.svg)


## CVE-2025-3248
code.

- [https://github.com/LeotheGGman/Langflow-RCE-CVE-2025-3248](https://github.com/LeotheGGman/Langflow-RCE-CVE-2025-3248) :  ![starts](https://img.shields.io/github/stars/LeotheGGman/Langflow-RCE-CVE-2025-3248.svg) ![forks](https://img.shields.io/github/forks/LeotheGGman/Langflow-RCE-CVE-2025-3248.svg)


## CVE-2025-0890
Insecure default credentials for the Telnet function in the legacy DSL CPE Zyxel VMG4325-B10A firmware version 1.00(AAFR.4)C0_20170615 could allow an attacker to log in to the management interface if the administrators have the option to change the default credentials but fail to do so.

- [https://github.com/krevetkqqq/CVE-2025-0890](https://github.com/krevetkqqq/CVE-2025-0890) :  ![starts](https://img.shields.io/github/stars/krevetkqqq/CVE-2025-0890.svg) ![forks](https://img.shields.io/github/forks/krevetkqqq/CVE-2025-0890.svg)


## CVE-2024-47066
 Lobe Chat is an open-source artificial intelligence chat framework. Prior to version 1.19.13, server-side request forgery protection implemented in `src/app/api/proxy/route.ts` does not consider redirect and could be bypassed when attacker provides an external malicious URL which redirects to internal resources like a private network or loopback address. Version 1.19.13 contains an improved fix for the issue.

- [https://github.com/EQSTLab/CVE-2024-47066](https://github.com/EQSTLab/CVE-2024-47066) :  ![starts](https://img.shields.io/github/stars/EQSTLab/CVE-2024-47066.svg) ![forks](https://img.shields.io/github/forks/EQSTLab/CVE-2024-47066.svg)


## CVE-2024-40891
A post-authentication command injection vulnerability in the management commands of the legacy DSL CPE Zyxel VMG4325-B10A firmware version 1.00(AAFR.4)C0_20170615 could allow an authenticated attacker to execute operating system (OS) commands on an affected device via Telnet.

- [https://github.com/krevetkqqq/CVE-2024-40891](https://github.com/krevetkqqq/CVE-2024-40891) :  ![starts](https://img.shields.io/github/stars/krevetkqqq/CVE-2024-40891.svg) ![forks](https://img.shields.io/github/forks/krevetkqqq/CVE-2024-40891.svg)


## CVE-2024-30090
 Microsoft Streaming Service Elevation of Privilege Vulnerability

- [https://github.com/m01000xd/CVE-2024-30090](https://github.com/m01000xd/CVE-2024-30090) :  ![starts](https://img.shields.io/github/stars/m01000xd/CVE-2024-30090.svg) ![forks](https://img.shields.io/github/forks/m01000xd/CVE-2024-30090.svg)


## CVE-2024-10441
 Improper encoding or escaping of output vulnerability in the system plugin daemon in Synology BeeStation OS (BSM) before 1.1-65374 and Synology DiskStation Manager (DSM) before 7.2-64570-4, 7.2.1-69057-6 and 7.2.2-72806-1 allows remote attackers to execute arbitrary code via unspecified vectors.

- [https://github.com/SHIFox8/synology-dsm-vuln-scanner](https://github.com/SHIFox8/synology-dsm-vuln-scanner) :  ![starts](https://img.shields.io/github/stars/SHIFox8/synology-dsm-vuln-scanner.svg) ![forks](https://img.shields.io/github/forks/SHIFox8/synology-dsm-vuln-scanner.svg)


## CVE-2024-9644
authentication bypass vulnerability in the administrative web server. Authentication is not enforced on some administrative functionality when using the "bapply.cgi" endpoint instead of the normal "apply.cgi" endpoint. A remote and unauthenticated can use this vulnerability to modify settings or chain with existing authenticated vulnerabilities.

- [https://github.com/krevetkqqq/CVE-2024-9644](https://github.com/krevetkqqq/CVE-2024-9644) :  ![starts](https://img.shields.io/github/stars/krevetkqqq/CVE-2024-9644.svg) ![forks](https://img.shields.io/github/forks/krevetkqqq/CVE-2024-9644.svg)


## CVE-2024-9441
 The Linear eMerge e3-Series through version 1.00-07 is vulnerable to an OS command injection vulnerability. A remote and unauthenticated attacker can execute arbitrary OS commands via the login_id parameter when invoking the forgot_password functionality over HTTP.

- [https://github.com/krevetkqqq/CVE-2024-9441](https://github.com/krevetkqqq/CVE-2024-9441) :  ![starts](https://img.shields.io/github/stars/krevetkqqq/CVE-2024-9441.svg) ![forks](https://img.shields.io/github/forks/krevetkqqq/CVE-2024-9441.svg)


## CVE-2023-48022
 Anyscale Ray 2.6.3 and 2.8.0 allows a remote attacker to execute arbitrary code via the job submission API. NOTE: the vendor's position is that this report is irrelevant because Ray, as stated in its documentation, is not intended for use outside of a strictly controlled network environment. (Also, within that environment, customers at version 2.52.0 and later can choose to use token authentication.)

- [https://github.com/krevetkqqq/CVE-2023-48022](https://github.com/krevetkqqq/CVE-2023-48022) :  ![starts](https://img.shields.io/github/stars/krevetkqqq/CVE-2023-48022.svg) ![forks](https://img.shields.io/github/forks/krevetkqqq/CVE-2023-48022.svg)


## CVE-2023-46604
which fixes this issue.

- [https://github.com/krevetkqqq/cve-2023-46604-activemq-lab](https://github.com/krevetkqqq/cve-2023-46604-activemq-lab) :  ![starts](https://img.shields.io/github/stars/krevetkqqq/cve-2023-46604-activemq-lab.svg) ![forks](https://img.shields.io/github/forks/krevetkqqq/cve-2023-46604-activemq-lab.svg)


## CVE-2023-43364
 main.py in Searchor before 2.4.2 uses eval on CLI input, which may cause unexpected code execution.

- [https://github.com/diamorphine666/CVE-2023-43364](https://github.com/diamorphine666/CVE-2023-43364) :  ![starts](https://img.shields.io/github/stars/diamorphine666/CVE-2023-43364.svg) ![forks](https://img.shields.io/github/forks/diamorphine666/CVE-2023-43364.svg)


## CVE-2023-42495
Dasan Networks - W-Web versions 1.22-1.27 - CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')

- [https://github.com/krevetkqqq/CVE-2023-42495](https://github.com/krevetkqqq/CVE-2023-42495) :  ![starts](https://img.shields.io/github/stars/krevetkqqq/CVE-2023-42495.svg) ![forks](https://img.shields.io/github/forks/krevetkqqq/CVE-2023-42495.svg)


## CVE-2023-41348
 ASUS RT-AX55’s authentication-related function has a vulnerability of insufficient filtering of special characters within its code-authentication module. An authenticated remote attacker can exploit this vulnerability to perform a Command Injection attack to execute arbitrary commands, disrupt the system or terminate services.

- [https://github.com/krevetkqqq/CVE-2023-41348](https://github.com/krevetkqqq/CVE-2023-41348) :  ![starts](https://img.shields.io/github/stars/krevetkqqq/CVE-2023-41348.svg) ![forks](https://img.shields.io/github/forks/krevetkqqq/CVE-2023-41348.svg)


## CVE-2023-41346
 ASUS RT-AX55’s authentication-related function has a vulnerability of insufficient filtering of special characters within its token-refresh module. An authenticated remote attacker can exploit this vulnerability to perform a Command Injection attack to execute arbitrary commands, disrupt the system or terminate services.

- [https://github.com/krevetkqqq/CVE-2023-41346](https://github.com/krevetkqqq/CVE-2023-41346) :  ![starts](https://img.shields.io/github/stars/krevetkqqq/CVE-2023-41346.svg) ![forks](https://img.shields.io/github/forks/krevetkqqq/CVE-2023-41346.svg)


## CVE-2023-41011
 Command Execution vulnerability in China Mobile Communications China Mobile Intelligent Home Gateway v.HG6543C4 allows a remote attacker to execute arbitrary code via the shortcut_telnet.cg component.

- [https://github.com/krevetkqqq/CVE-2023-41011](https://github.com/krevetkqqq/CVE-2023-41011) :  ![starts](https://img.shields.io/github/stars/krevetkqqq/CVE-2023-41011.svg) ![forks](https://img.shields.io/github/forks/krevetkqqq/CVE-2023-41011.svg)


## CVE-2023-39780
 On ASUS RT-AX55 3.0.0.4.386.51598 devices, authenticated attackers can perform OS command injection via the /start_apply.htm qos_bw_rulelist parameter. NOTE: for the similar "token-generated module" issue, see CVE-2023-41345; for the similar "token-refresh module" issue, see CVE-2023-41346; for the similar "check token module" issue, see CVE-2023-41347; and for the similar "code-authentication module" issue, see CVE-2023-41348.

- [https://github.com/krevetkqqq/CVE-2023-39780](https://github.com/krevetkqqq/CVE-2023-39780) :  ![starts](https://img.shields.io/github/stars/krevetkqqq/CVE-2023-39780.svg) ![forks](https://img.shields.io/github/forks/krevetkqqq/CVE-2023-39780.svg)


## CVE-2023-38646
 Metabase open source before 0.46.6.1 and Metabase Enterprise before 1.46.6.1 allow attackers to execute arbitrary commands on the server, at the server's privilege level. Authentication is not required for exploitation. The other fixed versions are 0.45.4.1, 1.45.4.1, 0.44.7.1, 1.44.7.1, 0.43.7.2, and 1.43.7.2.

- [https://github.com/Shisones/MetabaseRCE_CVE-2023-38646](https://github.com/Shisones/MetabaseRCE_CVE-2023-38646) :  ![starts](https://img.shields.io/github/stars/Shisones/MetabaseRCE_CVE-2023-38646.svg) ![forks](https://img.shields.io/github/forks/Shisones/MetabaseRCE_CVE-2023-38646.svg)


## CVE-2023-37679
 A remote command execution (RCE) vulnerability in NextGen Mirth Connect v4.3.0 allows attackers to execute arbitrary commands on the hosting server.

- [https://github.com/krevetkqqq/CVE-2023-37679](https://github.com/krevetkqqq/CVE-2023-37679) :  ![starts](https://img.shields.io/github/stars/krevetkqqq/CVE-2023-37679.svg) ![forks](https://img.shields.io/github/forks/krevetkqqq/CVE-2023-37679.svg)


## CVE-2023-32315
 Openfire is an XMPP server licensed under the Open Source Apache License. Openfire's administrative console, a web-based application, was found to be vulnerable to a path traversal attack via the setup environment. This permitted an unauthenticated user to use the unauthenticated Openfire Setup Environment in an already configured Openfire environment to access restricted pages in the Openfire Admin Console reserved for administrative users. This vulnerability affects all versions of Openfire that have been released since April 2015, starting with version 3.10.0. The problem has been patched in Openfire release 4.7.5 and 4.6.8, and further improvements will be included in the yet-to-be released first version on the 4.8 branch (which is expected to be version 4.8.0). Users are advised to upgrade. If an Openfire upgrade isn’t available for a specific release, or isn’t quickly actionable, users may see the linked github advisory (GHSA-gw42-f939-fhvm) for mitigation advice.

- [https://github.com/krevetkqqq/cve-2023-32315-openfire-lab](https://github.com/krevetkqqq/cve-2023-32315-openfire-lab) :  ![starts](https://img.shields.io/github/stars/krevetkqqq/cve-2023-32315-openfire-lab.svg) ![forks](https://img.shields.io/github/forks/krevetkqqq/cve-2023-32315-openfire-lab.svg)


## CVE-2023-32311
 CloudExplorer Lite is an open source cloud management platform. In CloudExplorer Lite prior to version 1.1.0 users organization/workspace permissions are not properly checked. This allows users to add themselves to any organization. This vulnerability has been fixed in v1.1.0. Users are advised to upgrade. There are no known workarounds for this issue.

- [https://github.com/krevetkqqq/CVE-2023-32311](https://github.com/krevetkqqq/CVE-2023-32311) :  ![starts](https://img.shields.io/github/stars/krevetkqqq/CVE-2023-32311.svg) ![forks](https://img.shields.io/github/forks/krevetkqqq/CVE-2023-32311.svg)


## CVE-2022-44384
 An arbitrary file upload vulnerability in rconfig v3.9.6 allows attackers to execute arbitrary code via a crafted PHP file.

- [https://github.com/d4ytox/CVE-2022-44384](https://github.com/d4ytox/CVE-2022-44384) :  ![starts](https://img.shields.io/github/stars/d4ytox/CVE-2022-44384.svg) ![forks](https://img.shields.io/github/forks/d4ytox/CVE-2022-44384.svg)


## CVE-2022-40624
 pfSense pfBlockerNG through 2.1.4_27 allows remote attackers to execute arbitrary OS commands as root via the HTTP Host header, a different vulnerability than CVE-2022-31814.

- [https://github.com/krevetkqqq/CVE-2022-40624](https://github.com/krevetkqqq/CVE-2022-40624) :  ![starts](https://img.shields.io/github/stars/krevetkqqq/CVE-2022-40624.svg) ![forks](https://img.shields.io/github/forks/krevetkqqq/CVE-2022-40624.svg)


## CVE-2022-1388
 On F5 BIG-IP 16.1.x versions prior to 16.1.2.2, 15.1.x versions prior to 15.1.5.1, 14.1.x versions prior to 14.1.4.6, 13.1.x versions prior to 13.1.5, and all 12.1.x and 11.6.x versions, undisclosed requests may bypass iControl REST authentication. Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated

- [https://github.com/revanmalang/CVE-2022-1388](https://github.com/revanmalang/CVE-2022-1388) :  ![starts](https://img.shields.io/github/stars/revanmalang/CVE-2022-1388.svg) ![forks](https://img.shields.io/github/forks/revanmalang/CVE-2022-1388.svg)


## CVE-2022-0847
 A flaw was found in the way the "flags" member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/Greetdawn/CVE-2022-0847-DirtyPipe-](https://github.com/Greetdawn/CVE-2022-0847-DirtyPipe-) :  ![starts](https://img.shields.io/github/stars/Greetdawn/CVE-2022-0847-DirtyPipe-.svg) ![forks](https://img.shields.io/github/forks/Greetdawn/CVE-2022-0847-DirtyPipe-.svg)
- [https://github.com/pmihsan/Dirty-Pipe-CVE-2022-0847](https://github.com/pmihsan/Dirty-Pipe-CVE-2022-0847) :  ![starts](https://img.shields.io/github/stars/pmihsan/Dirty-Pipe-CVE-2022-0847.svg) ![forks](https://img.shields.io/github/forks/pmihsan/Dirty-Pipe-CVE-2022-0847.svg)
- [https://github.com/morgenm/dirtypipe](https://github.com/morgenm/dirtypipe) :  ![starts](https://img.shields.io/github/stars/morgenm/dirtypipe.svg) ![forks](https://img.shields.io/github/forks/morgenm/dirtypipe.svg)


## CVE-2021-27177
 An issue was discovered on FiberHome HG6245D devices through RP2613. It is possible to bypass authentication by sending the decoded value of the GgpoZWxwCmxpc3QKd2hvCg== string to the telnet server.

- [https://github.com/krevetkqqq/CVE-2021-27177](https://github.com/krevetkqqq/CVE-2021-27177) :  ![starts](https://img.shields.io/github/stars/krevetkqqq/CVE-2021-27177.svg) ![forks](https://img.shields.io/github/forks/krevetkqqq/CVE-2021-27177.svg)


## CVE-2021-22204
 Improper neutralization of user data in the DjVu file format in ExifTool versions 7.44 and up allows arbitrary code execution when parsing the malicious image

- [https://github.com/d4ytox/CVE-2021-22204](https://github.com/d4ytox/CVE-2021-22204) :  ![starts](https://img.shields.io/github/stars/d4ytox/CVE-2021-22204.svg) ![forks](https://img.shields.io/github/forks/d4ytox/CVE-2021-22204.svg)


## CVE-2021-21425
 Grav Admin Plugin is an HTML user interface that provides a way to configure Grav and create and modify pages. In versions 1.10.7 and earlier, an unauthenticated user can execute some methods of administrator controller without needing any credentials. Particular method execution will result in arbitrary YAML file creation or content change of existing YAML files on the system. Successfully exploitation of that vulnerability results in configuration changes, such as general site information change, custom scheduler job definition, etc. Due to the nature of the vulnerability, an adversary can change some part of the webpage, or hijack an administrator account, or execute operating system command under the context of the web-server user. This vulnerability is fixed in version 1.10.8. Blocking access to the `/admin` path from untrusted sources can be applied as a workaround.

- [https://github.com/d4ytox/CVE-2021-21425](https://github.com/d4ytox/CVE-2021-21425) :  ![starts](https://img.shields.io/github/stars/d4ytox/CVE-2021-21425.svg) ![forks](https://img.shields.io/github/forks/d4ytox/CVE-2021-21425.svg)


## CVE-2021-3493
 The overlayfs implementation in the linux kernel did not properly validate with respect to user namespaces the setting of file capabilities on files in an underlying file system. Due to the combination of unprivileged user namespaces along with a patch carried in the Ubuntu kernel to allow unprivileged overlay mounts, an attacker could use this to gain elevated privileges.

- [https://github.com/devloperhalaand-ship-it/TryHackMe-OverlayFS---CVE-2021-3493](https://github.com/devloperhalaand-ship-it/TryHackMe-OverlayFS---CVE-2021-3493) :  ![starts](https://img.shields.io/github/stars/devloperhalaand-ship-it/TryHackMe-OverlayFS---CVE-2021-3493.svg) ![forks](https://img.shields.io/github/forks/devloperhalaand-ship-it/TryHackMe-OverlayFS---CVE-2021-3493.svg)


## CVE-2020-8958
 Guangzhou 1GE ONU V2801RW 1.9.1-181203 through 2.9.0-181024 and V2804RGW 1.9.1-181203 through 2.9.0-181024 devices allow remote attackers to execute arbitrary OS commands via shell metacharacters in the boaform/admin/formPing Dest IP Address field.

- [https://github.com/krevetkqqq/CVE-2020-8958](https://github.com/krevetkqqq/CVE-2020-8958) :  ![starts](https://img.shields.io/github/stars/krevetkqqq/CVE-2020-8958.svg) ![forks](https://img.shields.io/github/forks/krevetkqqq/CVE-2020-8958.svg)


## CVE-2019-15107
 An issue was discovered in Webmin =1.920. The parameter old in password_change.cgi contains a command injection vulnerability.

- [https://github.com/r3vpwnx/Webmin-1.910-Exploit-Script](https://github.com/r3vpwnx/Webmin-1.910-Exploit-Script) :  ![starts](https://img.shields.io/github/stars/r3vpwnx/Webmin-1.910-Exploit-Script.svg) ![forks](https://img.shields.io/github/forks/r3vpwnx/Webmin-1.910-Exploit-Script.svg)


## CVE-2019-7256
 Linear eMerge E3-Series devices allow Command Injections.

- [https://github.com/krevetkqqq/CVE-2019-7256](https://github.com/krevetkqqq/CVE-2019-7256) :  ![starts](https://img.shields.io/github/stars/krevetkqqq/CVE-2019-7256.svg) ![forks](https://img.shields.io/github/forks/krevetkqqq/CVE-2019-7256.svg)


## CVE-2018-8120
 An elevation of privilege vulnerability exists in Windows when the Win32k component fails to properly handle objects in memory, aka "Win32k Elevation of Privilege Vulnerability." This affects Windows Server 2008, Windows 7, Windows Server 2008 R2. This CVE ID is unique from CVE-2018-8124, CVE-2018-8164, CVE-2018-8166.

- [https://github.com/leeqwind/HolicPOC](https://github.com/leeqwind/HolicPOC) :  ![starts](https://img.shields.io/github/stars/leeqwind/HolicPOC.svg) ![forks](https://img.shields.io/github/forks/leeqwind/HolicPOC.svg)


## CVE-2018-0817
 The Windows Graphics Device Interface (GDI) in Microsoft Windows Server 2008 SP2 and R2 SP1, Windows 7 SP1, Windows 8.1 and RT 8.1, Windows Server 2012 and R2, Windows 10 Gold, 1511, 1607, 1703, and 1709, Windows Server 2016 and Windows Server, version 1709 allows an elevation of privilege vulnerability due to the way objects are handled in memory, aka "Windows GDI Elevation of Privilege Vulnerability". This CVE is unique from CVE-2018-0815 and CVE-2018-0816.

- [https://github.com/leeqwind/HolicPOC](https://github.com/leeqwind/HolicPOC) :  ![starts](https://img.shields.io/github/stars/leeqwind/HolicPOC.svg) ![forks](https://img.shields.io/github/forks/leeqwind/HolicPOC.svg)


## CVE-2017-0263
 The kernel-mode drivers in Microsoft Windows Server 2008 SP2 and R2 SP1, Windows 7 SP1, Windows 8.1, Windows Server 2012 Gold and R2, Windows RT 8.1, Windows 10 Gold, 1511, 1607, 1703, and Windows Server 2016 allow local users to gain privileges via a crafted application, aka "Win32k Elevation of Privilege Vulnerability."

- [https://github.com/leeqwind/HolicPOC](https://github.com/leeqwind/HolicPOC) :  ![starts](https://img.shields.io/github/stars/leeqwind/HolicPOC.svg) ![forks](https://img.shields.io/github/forks/leeqwind/HolicPOC.svg)


## CVE-2017-0144
 The SMBv1 server in Microsoft Windows Vista SP2; Windows Server 2008 SP2 and R2 SP1; Windows 7 SP1; Windows 8.1; Windows Server 2012 Gold and R2; Windows RT 8.1; and Windows 10 Gold, 1511, and 1607; and Windows Server 2016 allows remote attackers to execute arbitrary code via crafted packets, aka "Windows SMB Remote Code Execution Vulnerability." This vulnerability is different from those described in CVE-2017-0143, CVE-2017-0145, CVE-2017-0146, and CVE-2017-0148.

- [https://github.com/0xBlackash/CVE-2017-0144](https://github.com/0xBlackash/CVE-2017-0144) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2017-0144.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2017-0144.svg)


## CVE-2017-0101
 The kernel-mode drivers in Transaction Manager in Microsoft Windows Vista SP2; Windows Server 2008 SP2 and R2; Windows 7 SP1; Windows 8.1, Windows Server 2012 Gold and R2, Windows RT 8.1; Windows 10 Gold, 1511, and 1607; and Windows Server 2016 allow local users to gain privileges via a crafted application, aka "Windows Elevation of Privilege Vulnerability."

- [https://github.com/leeqwind/HolicPOC](https://github.com/leeqwind/HolicPOC) :  ![starts](https://img.shields.io/github/stars/leeqwind/HolicPOC.svg) ![forks](https://img.shields.io/github/forks/leeqwind/HolicPOC.svg)


## CVE-2016-0167
 The kernel-mode driver in Microsoft Windows Vista SP2, Windows Server 2008 SP2 and R2 SP1, Windows 7 SP1, Windows 8.1, Windows Server 2012 Gold and R2, Windows RT 8.1, and Windows 10 Gold and 1511 allows local users to gain privileges via a crafted application, aka "Win32k Elevation of Privilege Vulnerability," a different vulnerability than CVE-2016-0143 and CVE-2016-0165.

- [https://github.com/leeqwind/HolicPOC](https://github.com/leeqwind/HolicPOC) :  ![starts](https://img.shields.io/github/stars/leeqwind/HolicPOC.svg) ![forks](https://img.shields.io/github/forks/leeqwind/HolicPOC.svg)


## CVE-2016-0165
 The kernel-mode driver in Microsoft Windows Vista SP2, Windows Server 2008 SP2 and R2 SP1, Windows 7 SP1, Windows 8.1, Windows Server 2012 Gold and R2, Windows RT 8.1, and Windows 10 Gold and 1511 allows local users to gain privileges via a crafted application, aka "Win32k Elevation of Privilege Vulnerability," a different vulnerability than CVE-2016-0143 and CVE-2016-0167.

- [https://github.com/leeqwind/HolicPOC](https://github.com/leeqwind/HolicPOC) :  ![starts](https://img.shields.io/github/stars/leeqwind/HolicPOC.svg) ![forks](https://img.shields.io/github/forks/leeqwind/HolicPOC.svg)


## CVE-2015-2546
 The kernel-mode driver in Microsoft Windows Vista SP2, Windows Server 2008 SP2 and R2 SP1, Windows 7 SP1, Windows 8, Windows 8.1, Windows Server 2012 Gold and R2, Windows RT Gold and 8.1, and Windows 10 allows local users to gain privileges via a crafted application, aka "Win32k Memory Corruption Elevation of Privilege Vulnerability," a different vulnerability than CVE-2015-2511, CVE-2015-2517, and CVE-2015-2518.

- [https://github.com/leeqwind/HolicPOC](https://github.com/leeqwind/HolicPOC) :  ![starts](https://img.shields.io/github/stars/leeqwind/HolicPOC.svg) ![forks](https://img.shields.io/github/forks/leeqwind/HolicPOC.svg)


## CVE-2014-9583
 common.c in infosvr in ASUS WRT firmware 3.0.0.4.376_1071, 3.0.0.376.2524-g0013f52, and other versions, as used in RT-AC66U, RT-N66U, and other routers, does not properly check the MAC address for a request, which allows remote attackers to bypass authentication and execute arbitrary commands via a NET_CMD_ID_MANU_CMD packet to UDP port 9999.  NOTE: this issue was incorrectly mapped to CVE-2014-10000, but that ID is invalid due to its use as an example of the 2014 CVE ID syntax change.

- [https://github.com/krevetkqqq/CVE-2014-9583](https://github.com/krevetkqqq/CVE-2014-9583) :  ![starts](https://img.shields.io/github/stars/krevetkqqq/CVE-2014-9583.svg) ![forks](https://img.shields.io/github/forks/krevetkqqq/CVE-2014-9583.svg)


## CVE-2014-8361
 The miniigd SOAP service in Realtek SDK allows remote attackers to execute arbitrary code via a crafted NewInternalClient request, as exploited in the wild through 2023.

- [https://github.com/krevetkqqq/CVE-2014-8361](https://github.com/krevetkqqq/CVE-2014-8361) :  ![starts](https://img.shields.io/github/stars/krevetkqqq/CVE-2014-8361.svg) ![forks](https://img.shields.io/github/forks/krevetkqqq/CVE-2014-8361.svg)


## CVE-2014-6271
 GNU Bash through 4.3 processes trailing strings after function definitions in the values of environment variables, which allows remote attackers to execute arbitrary code via a crafted environment, as demonstrated by vectors involving the ForceCommand feature in OpenSSH sshd, the mod_cgi and mod_cgid modules in the Apache HTTP Server, scripts executed by unspecified DHCP clients, and other situations in which setting the environment occurs across a privilege boundary from Bash execution, aka "ShellShock."  NOTE: the original fix for this issue was incorrect; CVE-2014-7169 has been assigned to cover the vulnerability that is still present after the incorrect fix.

- [https://github.com/0xBlackash/CVE-2014-6271](https://github.com/0xBlackash/CVE-2014-6271) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2014-6271.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2014-6271.svg)


## CVE-2014-0160
 The (1) TLS and (2) DTLS implementations in OpenSSL 1.0.1 before 1.0.1g do not properly handle Heartbeat Extension packets, which allows remote attackers to obtain sensitive information from process memory via crafted packets that trigger a buffer over-read, as demonstrated by reading private keys, related to d1_both.c and t1_lib.c, aka the Heartbleed bug.

- [https://github.com/0xBlackash/CVE-2014-0160](https://github.com/0xBlackash/CVE-2014-0160) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2014-0160.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2014-0160.svg)


## CVE-2012-0002
 The Remote Desktop Protocol (RDP) implementation in Microsoft Windows XP SP2 and SP3, Windows Server 2003 SP2, Windows Vista SP2, Windows Server 2008 SP2, R2, and R2 SP1, and Windows 7 Gold and SP1 does not properly process packets in memory, which allows remote attackers to execute arbitrary code by sending crafted RDP packets triggering access to an object that (1) was not properly initialized or (2) is deleted, aka "Remote Desktop Protocol Vulnerability."

- [https://github.com/engineer-lucasmcmelo/CVE-2012-0002](https://github.com/engineer-lucasmcmelo/CVE-2012-0002) :  ![starts](https://img.shields.io/github/stars/engineer-lucasmcmelo/CVE-2012-0002.svg) ![forks](https://img.shields.io/github/forks/engineer-lucasmcmelo/CVE-2012-0002.svg)

