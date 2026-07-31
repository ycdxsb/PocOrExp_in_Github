# Update 2026-07-31
## CVE-2026-61511
 vBulletin 5.x through 5.7.5 and 6.x through 6.2.1 contains an eval injection vulnerability in the vB5_Template_Runtime::runMaths() method within the template runtime that allows unauthenticated remote attackers to execute arbitrary PHP code by supplying crafted input through the pagenav[pagenumber] parameter. Attackers can exploit the insufficiently restrictive regex filter by using phpfuck-style encoding with permitted characters to inject and execute arbitrary PHP code via the unauthenticated ajax/render template route without any authentication.

- [https://github.com/tc4dy/CVE-2026-61511-PoC-Exploit](https://github.com/tc4dy/CVE-2026-61511-PoC-Exploit) :  ![starts](https://img.shields.io/github/stars/tc4dy/CVE-2026-61511-PoC-Exploit.svg) ![forks](https://img.shields.io/github/forks/tc4dy/CVE-2026-61511-PoC-Exploit.svg)
- [https://github.com/webshellseo8/CVE-2026-61511-POC](https://github.com/webshellseo8/CVE-2026-61511-POC) :  ![starts](https://img.shields.io/github/stars/webshellseo8/CVE-2026-61511-POC.svg) ![forks](https://img.shields.io/github/forks/webshellseo8/CVE-2026-61511-POC.svg)


## CVE-2026-59726
 Ruflo is an agent meta-harness for Claude Code and Codex. Prior to 3.16.3, ruflo's default docker-compose deployment exposed the MCP bridge POST /mcp and POST /mcp/:group endpoints without authentication, allowing an unauthenticated network attacker to invoke tools/call to terminal_execute, obtain a shell in the bridge container, read provider API keys, and poison AgentDB learning-store patterns. This issue is fixed in version 3.16.3.

- [https://github.com/HORKimhab/CVE-2026-59726](https://github.com/HORKimhab/CVE-2026-59726) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-59726.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-59726.svg)


## CVE-2026-59243
 The FAB auth manager's Azure AD OAuth login defaulted `verify_signature=False` when decoding the ID token, so an attacker able to present a forged or unsigned (`alg:none`) ID token to the OAuth callback could bypass authentication and log in as an arbitrary user, including one holding the Admin role (CWE-347). Deployments running the FAB auth manager with the Azure AD OAuth login path under its default configuration are affected; the Authentik path already defaulted to `True`. This issue affects `apache-airflow-providers-fab` before 3.7.3. Users are advised to upgrade to `apache-airflow-providers-fab` 3.7.3, which defaults `verify_signature=True`.

- [https://github.com/MalHyuk/CVE-2026-59243](https://github.com/MalHyuk/CVE-2026-59243) :  ![starts](https://img.shields.io/github/stars/MalHyuk/CVE-2026-59243.svg) ![forks](https://img.shields.io/github/forks/MalHyuk/CVE-2026-59243.svg)


## CVE-2026-58025
This issue affects MediaWiki: from * before 1.46.0, 1.45.4, 1.44.6, 1.43.9.

- [https://github.com/shinthink/CVE-2026-58025](https://github.com/shinthink/CVE-2026-58025) :  ![starts](https://img.shields.io/github/stars/shinthink/CVE-2026-58025.svg) ![forks](https://img.shields.io/github/forks/shinthink/CVE-2026-58025.svg)


## CVE-2026-57827
 Joomla Extension - rsjoomla.com - Unauthenticated file upload in RSFiles component  1.17.12 - The Joomla extension RSFiles is vulnerable to an unauthenticated arbitrary file upload that allows uploading executable files and leads to full RCE.

- [https://github.com/shinthink/CVE-2026-57827](https://github.com/shinthink/CVE-2026-57827) :  ![starts](https://img.shields.io/github/stars/shinthink/CVE-2026-57827.svg) ![forks](https://img.shields.io/github/forks/shinthink/CVE-2026-57827.svg)


## CVE-2026-57811
 Improper Control of Generation of Code ('Code Injection') vulnerability in Realtyna Realtyna Organic IDX plugin real-estate-listing-realtyna-wpl allows Remote Code Inclusion.This issue affects Realtyna Organic IDX plugin: from n/a through = 5.2.0.

- [https://github.com/webshellseo8/CVE-2026-57811-Proof-of-Concept](https://github.com/webshellseo8/CVE-2026-57811-Proof-of-Concept) :  ![starts](https://img.shields.io/github/stars/webshellseo8/CVE-2026-57811-Proof-of-Concept.svg) ![forks](https://img.shields.io/github/forks/webshellseo8/CVE-2026-57811-Proof-of-Concept.svg)


## CVE-2026-54107
 Concurrent execution using shared resource with improper synchronization ('race condition') in Windows Win32K allows an authorized attacker to elevate privileges locally.

- [https://github.com/Pravin761/CVE-2026-54107](https://github.com/Pravin761/CVE-2026-54107) :  ![starts](https://img.shields.io/github/stars/Pravin761/CVE-2026-54107.svg) ![forks](https://img.shields.io/github/forks/Pravin761/CVE-2026-54107.svg)


## CVE-2026-51992
 SQL Injection vulnerability in ClickHouse Server Versions = 26.3.9.8 allows a remote attacker to execute arbitrary code via the create dictionaries function.

- [https://github.com/TheLiimbo/CVE-2026-51992](https://github.com/TheLiimbo/CVE-2026-51992) :  ![starts](https://img.shields.io/github/stars/TheLiimbo/CVE-2026-51992.svg) ![forks](https://img.shields.io/github/forks/TheLiimbo/CVE-2026-51992.svg)


## CVE-2026-50522
 Deserialization of untrusted data in Microsoft Office SharePoint allows an unauthorized attacker to execute code over a network.

- [https://github.com/webshellseo8/CVE-2026-50522-Proof-of-Concept](https://github.com/webshellseo8/CVE-2026-50522-Proof-of-Concept) :  ![starts](https://img.shields.io/github/stars/webshellseo8/CVE-2026-50522-Proof-of-Concept.svg) ![forks](https://img.shields.io/github/forks/webshellseo8/CVE-2026-50522-Proof-of-Concept.svg)


## CVE-2026-49176
 Improper privilege management in Windows WalletService allows an authorized attacker to elevate privileges locally.

- [https://github.com/777erp/CVE-2026-49176_BOF](https://github.com/777erp/CVE-2026-49176_BOF) :  ![starts](https://img.shields.io/github/stars/777erp/CVE-2026-49176_BOF.svg) ![forks](https://img.shields.io/github/forks/777erp/CVE-2026-49176_BOF.svg)


## CVE-2026-45750
 Termix is a web-based server management platform with SSH terminal, tunneling, and file editing capabilities. Prior to version 2.3.2, the GET /ssh/file_manager/ssh/resolvePath endpoint in the Termix File Manager component unsafely processes the path parameter and embeds it into a shell command executed over the active SSH session. Because the user-controlled value is placed inside double quotes and only double quotes are escaped, shell command substitution syntax such as $(...) is still interpreted by the remote shell. Version 2.3.2 fixes the issue.

- [https://github.com/GabrielHA12/Termix-research](https://github.com/GabrielHA12/Termix-research) :  ![starts](https://img.shields.io/github/stars/GabrielHA12/Termix-research.svg) ![forks](https://img.shields.io/github/forks/GabrielHA12/Termix-research.svg)


## CVE-2026-45746
 Termix is a web-based server management platform with SSH terminal, tunneling, and file editing capabilities. Prior to version 2.3.2, the File Manager functionality in Termix contains a critical Broken Access Control vulnerability due to improper validation of the sessionId parameter. The backend trusts a client-controlled identifier without verifying that it belongs to the authenticated user. This allows an attacker to manipulate the value and access active File Manager sessions belonging to other users. Since these sessions are tied to SSH connections to remote VPS instances, exploitation allows unauthorized interaction with another user's remote filesystem. Because the File Manager exposes functionality such as file reading, writing, uploading, and execution, this vulnerability enables direct command execution on another user's VPS (RCE). Version 2.3.2 patches the issue.

- [https://github.com/GabrielHA12/Termix-research](https://github.com/GabrielHA12/Termix-research) :  ![starts](https://img.shields.io/github/stars/GabrielHA12/Termix-research.svg) ![forks](https://img.shields.io/github/forks/GabrielHA12/Termix-research.svg)


## CVE-2026-43813
 A validation issue was addressed with improved input sanitization. This issue is fixed in iOS 26.6 and iPadOS 26.6, macOS Tahoe 26.6, tvOS 26.6, visionOS 26.6, watchOS 26.6. A maliciously crafted app may be able to bypass code signing enforcement.

- [https://github.com/EastArctica/CVE-2026-43813](https://github.com/EastArctica/CVE-2026-43813) :  ![starts](https://img.shields.io/github/stars/EastArctica/CVE-2026-43813.svg) ![forks](https://img.shields.io/github/forks/EastArctica/CVE-2026-43813.svg)


## CVE-2026-43499
  	changelog ]

- [https://github.com/Linuxoid-cn/CVE-2026-43499-Poc-Analysis](https://github.com/Linuxoid-cn/CVE-2026-43499-Poc-Analysis) :  ![starts](https://img.shields.io/github/stars/Linuxoid-cn/CVE-2026-43499-Poc-Analysis.svg) ![forks](https://img.shields.io/github/forks/Linuxoid-cn/CVE-2026-43499-Poc-Analysis.svg)
- [https://github.com/233laoliu/mt6985-CVE-2026-43499](https://github.com/233laoliu/mt6985-CVE-2026-43499) :  ![starts](https://img.shields.io/github/stars/233laoliu/mt6985-CVE-2026-43499.svg) ![forks](https://img.shields.io/github/forks/233laoliu/mt6985-CVE-2026-43499.svg)


## CVE-2026-42533
 Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/jelasin/CVE-2026-42533](https://github.com/jelasin/CVE-2026-42533) :  ![starts](https://img.shields.io/github/stars/jelasin/CVE-2026-42533.svg) ![forks](https://img.shields.io/github/forks/jelasin/CVE-2026-42533.svg)


## CVE-2026-38526
 An authenticated arbitrary file upload vulnerability in the /admin/tinymce/upload endpoint of Webkul Krayin CRM v2.2.x allows attackers to execute arbitrary code via uploading a crafted PHP file.

- [https://github.com/b0nyo/PoC-CVE-2026-38526](https://github.com/b0nyo/PoC-CVE-2026-38526) :  ![starts](https://img.shields.io/github/stars/b0nyo/PoC-CVE-2026-38526.svg) ![forks](https://img.shields.io/github/forks/b0nyo/PoC-CVE-2026-38526.svg)


## CVE-2026-33718
 OpenHands is software for AI-driven development. Starting in version 1.5.0, a Command Injection vulnerability exists in the `get_git_diff()` method at `openhands/runtime/utils/git_handler.py:134`. The `path` parameter from the `/api/conversations/{conversation_id}/git/diff` API endpoint is passed unsanitized to a shell command, allowing authenticated attackers to execute arbitrary commands in the agent sandbox. The user is already allowed to instruct the agent to execute commands, but this bypasses the normal channels. Version 1.5.0 fixes the issue.

- [https://github.com/HORKimhab/CVE-2026-33718](https://github.com/HORKimhab/CVE-2026-33718) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-33718.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-33718.svg)


## CVE-2026-31694
the readdir cache.

- [https://github.com/zenzue/CVE_2026_31694](https://github.com/zenzue/CVE_2026_31694) :  ![starts](https://img.shields.io/github/stars/zenzue/CVE_2026_31694.svg) ![forks](https://img.shields.io/github/forks/zenzue/CVE_2026_31694.svg)


## CVE-2026-20896
 Gitea Docker image versions up to and including 1.26.2 use REVERSE_PROXY_TRUSTED_PROXIES=* by default, allowing any source IP to impersonate a user when reverse-proxy authentication headers such as X-WEBAUTH-USER are enabled.

- [https://github.com/EQSTLab/CVE-2026-20896](https://github.com/EQSTLab/CVE-2026-20896) :  ![starts](https://img.shields.io/github/stars/EQSTLab/CVE-2026-20896.svg) ![forks](https://img.shields.io/github/forks/EQSTLab/CVE-2026-20896.svg)


## CVE-2026-18220
Note: This vulnerability is only exploitable when binutils is built with the DLX backend enabled (typically via --enable-targets=all).

- [https://github.com/4D4J/objdump-Out-Of-Bounds-write](https://github.com/4D4J/objdump-Out-Of-Bounds-write) :  ![starts](https://img.shields.io/github/stars/4D4J/objdump-Out-Of-Bounds-write.svg) ![forks](https://img.shields.io/github/forks/4D4J/objdump-Out-Of-Bounds-write.svg)


## CVE-2026-14266
The specific flaw exists within the processing of XZ chunked data. Crafted XZ-compressed data can trigger an overflow of a heap-based buffer. An attacker can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-30169.

- [https://github.com/4minx/CVE-2026-14266](https://github.com/4minx/CVE-2026-14266) :  ![starts](https://img.shields.io/github/stars/4minx/CVE-2026-14266.svg) ![forks](https://img.shields.io/github/forks/4minx/CVE-2026-14266.svg)
- [https://github.com/liyuxuan504-byte/CVE-2026-14266](https://github.com/liyuxuan504-byte/CVE-2026-14266) :  ![starts](https://img.shields.io/github/stars/liyuxuan504-byte/CVE-2026-14266.svg) ![forks](https://img.shields.io/github/forks/liyuxuan504-byte/CVE-2026-14266.svg)
- [https://github.com/hg0434hongzh0/CVE-2026-14266](https://github.com/hg0434hongzh0/CVE-2026-14266) :  ![starts](https://img.shields.io/github/stars/hg0434hongzh0/CVE-2026-14266.svg) ![forks](https://img.shields.io/github/forks/hg0434hongzh0/CVE-2026-14266.svg)


## CVE-2026-10702
 JIT miscompilation in the JavaScript Engine: JIT component. This vulnerability was fixed in Firefox 151.0.3.

- [https://github.com/HORKimhab/CVE-2026-10702](https://github.com/HORKimhab/CVE-2026-10702) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-10702.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-10702.svg)


## CVE-2026-6606
 A weakness has been identified in modelscope agentscope up to 1.0.18. This vulnerability affects the function _process_audio_block of the file src/agentscope/agent/_agent_base.py. Executing a manipulation of the argument url can lead to server-side request forgery. It is possible to launch the attack remotely. The exploit has been made available to the public and could be used for attacks. The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/0xBlackash/CVE-2026-66066](https://github.com/0xBlackash/CVE-2026-66066) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-66066.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-66066.svg)
- [https://github.com/Zer0SumGam3/CVE-2026-66066-POC](https://github.com/Zer0SumGam3/CVE-2026-66066-POC) :  ![starts](https://img.shields.io/github/stars/Zer0SumGam3/CVE-2026-66066-POC.svg) ![forks](https://img.shields.io/github/forks/Zer0SumGam3/CVE-2026-66066-POC.svg)


## CVE-2026-6000
 A vulnerability was found in code-projects Online Library Management System 1.0. Affected is an unknown function of the file /sql/library.sql of the component SQL Database Backup File Handler. Performing a manipulation results in information disclosure. The attack may be initiated remotely. The exploit has been made public and could be used.

- [https://github.com/HORKimhab/CVE-2026-60004](https://github.com/HORKimhab/CVE-2026-60004) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-60004.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-60004.svg)


## CVE-2026-5283
 Inappropriate implementation in ANGLE in Google Chrome prior to 146.0.7680.178 allowed a remote attacker to leak cross-origin data via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/mdvpat/CVE-2026-52832-PoC-exploit-nuclio-dashboard](https://github.com/mdvpat/CVE-2026-52832-PoC-exploit-nuclio-dashboard) :  ![starts](https://img.shields.io/github/stars/mdvpat/CVE-2026-52832-PoC-exploit-nuclio-dashboard.svg) ![forks](https://img.shields.io/github/forks/mdvpat/CVE-2026-52832-PoC-exploit-nuclio-dashboard.svg)


## CVE-2026-5213
 A vulnerability was determined in D-Link DNS-120, DNR-202L, DNS-315L, DNS-320, DNS-320L, DNS-320LW, DNS-321, DNR-322L, DNS-323, DNS-325, DNS-326, DNS-327L, DNR-326, DNS-340L, DNS-343, DNS-345, DNS-726-4, DNS-1100-4, DNS-1200-05 and DNS-1550-04 up to 20260205. The affected element is the function cgi_adduser_to_session of the file /cgi-bin/account_mgr.cgi. This manipulation of the argument read_list causes stack-based buffer overflow. It is possible to initiate the attack remotely. The exploit has been publicly disclosed and may be utilized.

- [https://github.com/if-forget/CVE-2026-52134-libiec61850](https://github.com/if-forget/CVE-2026-52134-libiec61850) :  ![starts](https://img.shields.io/github/stars/if-forget/CVE-2026-52134-libiec61850.svg) ![forks](https://img.shields.io/github/forks/if-forget/CVE-2026-52134-libiec61850.svg)


## CVE-2026-4986
 The WPForms  WordPress plugin before 1.10.0.5 does not verify the authenticity of incoming PayPal webhook events before processing them, allowing unauthenticated attackers to forge webhook payloads and manipulate the payment state of arbitrary transactions.

- [https://github.com/cyeezy08/Kimai-CVE-2026-49865-POC](https://github.com/cyeezy08/Kimai-CVE-2026-49865-POC) :  ![starts](https://img.shields.io/github/stars/cyeezy08/Kimai-CVE-2026-49865-POC.svg) ![forks](https://img.shields.io/github/forks/cyeezy08/Kimai-CVE-2026-49865-POC.svg)


## CVE-2026-2586
 An authenticated Remote Code Execution (RCE) vulnerability was identified in GlassFish's Administration Console. A user with access to the panel can send crafted requests that allow the execution of arbitrary operating system commands with the privileges of the application service user. This issue affects Eclipse GlassFish: from 8.0.0 to 8.0.1, fixed in 8.0.2; 7.1.0, fixed in 7.1.1; from 7.0.0 to 7.0.25, fixed in 7.0.26. Impact on versions from 5.1.0 to 6.2.5 is unknown.

- [https://github.com/GabrielHA12/Glassfish-research](https://github.com/GabrielHA12/Glassfish-research) :  ![starts](https://img.shields.io/github/stars/GabrielHA12/Glassfish-research.svg) ![forks](https://img.shields.io/github/forks/GabrielHA12/Glassfish-research.svg)


## CVE-2026-1647
 The Comment Genius plugin for WordPress is vulnerable to Reflected Cross-Site Scripting via the `$_SERVER['PHP_SELF']` parameter in all versions up to, and including, 1.2.5 due to insufficient input sanitization and output escaping. This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that execute if they can successfully trick a user into performing an action such as clicking on a link.

- [https://github.com/afertar/CVE-2026-16475-PoC](https://github.com/afertar/CVE-2026-16475-PoC) :  ![starts](https://img.shields.io/github/stars/afertar/CVE-2026-16475-PoC.svg) ![forks](https://img.shields.io/github/forks/afertar/CVE-2026-16475-PoC.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-git-dep](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-git-dep) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-git-dep.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-git-dep.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-berry](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-berry) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-berry.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-berry.svg)


## CVE-2025-26466
 A flaw was found in the OpenSSH package. For each ping packet the SSH server receives, a pong packet is allocated in a memory buffer and stored in a queue of packages. It is only freed when the server/client key exchange has finished. A malicious client may keep sending such packages, leading to an uncontrolled increase in memory consumption on the server side. Consequently, the server may become unavailable, resulting in a denial of service attack.

- [https://github.com/acidboonrs/cve-2025-26466-openssh-poc](https://github.com/acidboonrs/cve-2025-26466-openssh-poc) :  ![starts](https://img.shields.io/github/stars/acidboonrs/cve-2025-26466-openssh-poc.svg) ![forks](https://img.shields.io/github/forks/acidboonrs/cve-2025-26466-openssh-poc.svg)


## CVE-2025-6440
 The WooCommerce Designer Pro plugin for WordPress, used by the Pricom - Printing Company & Design Services WordPress theme, is vulnerable to arbitrary file uploads due to missing file type validation in the 'wcdp_save_canvas_design_ajax' function in all versions up to, and including, 1.9.26. This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible.

- [https://github.com/m2hcz/CVE-2025-6440-Poc-Exploit](https://github.com/m2hcz/CVE-2025-6440-Poc-Exploit) :  ![starts](https://img.shields.io/github/stars/m2hcz/CVE-2025-6440-Poc-Exploit.svg) ![forks](https://img.shields.io/github/forks/m2hcz/CVE-2025-6440-Poc-Exploit.svg)
- [https://github.com/sahmsec/CVE-2025-6440](https://github.com/sahmsec/CVE-2025-6440) :  ![starts](https://img.shields.io/github/stars/sahmsec/CVE-2025-6440.svg) ![forks](https://img.shields.io/github/forks/sahmsec/CVE-2025-6440.svg)
- [https://github.com/AnotherSec/CVE-2025-6440](https://github.com/AnotherSec/CVE-2025-6440) :  ![starts](https://img.shields.io/github/stars/AnotherSec/CVE-2025-6440.svg) ![forks](https://img.shields.io/github/forks/AnotherSec/CVE-2025-6440.svg)
- [https://github.com/Nxploited/CVE-2025-6440](https://github.com/Nxploited/CVE-2025-6440) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-6440.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-6440.svg)
- [https://github.com/rimbadirgantara/CVE-2025-6440](https://github.com/rimbadirgantara/CVE-2025-6440) :  ![starts](https://img.shields.io/github/stars/rimbadirgantara/CVE-2025-6440.svg) ![forks](https://img.shields.io/github/forks/rimbadirgantara/CVE-2025-6440.svg)
- [https://github.com/0axz-tools/CVE-2025-6440](https://github.com/0axz-tools/CVE-2025-6440) :  ![starts](https://img.shields.io/github/stars/0axz-tools/CVE-2025-6440.svg) ![forks](https://img.shields.io/github/forks/0axz-tools/CVE-2025-6440.svg)
- [https://github.com/Cyber-DarkNay/CVE-2025-6440](https://github.com/Cyber-DarkNay/CVE-2025-6440) :  ![starts](https://img.shields.io/github/stars/Cyber-DarkNay/CVE-2025-6440.svg) ![forks](https://img.shields.io/github/forks/Cyber-DarkNay/CVE-2025-6440.svg)


## CVE-2025-5915
 A vulnerability has been identified in the libarchive library. This flaw can lead to a heap buffer over-read due to the size of a filter block potentially exceeding the Lempel-Ziv-Storer-Schieber (LZSS) window. This means the library may attempt to read beyond the allocated memory buffer, which can result in unpredictable program behavior, crashes (denial of service), or the disclosure of sensitive information from adjacent memory regions.

- [https://github.com/R3n3r0/cve-2025-5915](https://github.com/R3n3r0/cve-2025-5915) :  ![starts](https://img.shields.io/github/stars/R3n3r0/cve-2025-5915.svg) ![forks](https://img.shields.io/github/forks/R3n3r0/cve-2025-5915.svg)


## CVE-2024-54152
 Angular Expressions provides expressions for the Angular.JS web framework as a standalone module. Prior to version 1.4.3, an attacker can write a malicious expression that escapes the sandbox to execute arbitrary code on the system. With a more complex (undisclosed) payload, one can get full access to Arbitrary code execution on the system. The problem has been patched in version 1.4.3 of Angular Expressions. Two possible workarounds are available. One may either disable access to `__proto__` globally or make sure that one uses the function with just one argument.

- [https://github.com/math-x-io/CVE-2024-54152](https://github.com/math-x-io/CVE-2024-54152) :  ![starts](https://img.shields.io/github/stars/math-x-io/CVE-2024-54152.svg) ![forks](https://img.shields.io/github/forks/math-x-io/CVE-2024-54152.svg)


## CVE-2024-36104
Users are recommended to upgrade to version 18.12.14, which fixes the issue.

- [https://github.com/Groppoxx/CVE-2024-36104-PoC](https://github.com/Groppoxx/CVE-2024-36104-PoC) :  ![starts](https://img.shields.io/github/stars/Groppoxx/CVE-2024-36104-PoC.svg) ![forks](https://img.shields.io/github/forks/Groppoxx/CVE-2024-36104-PoC.svg)


## CVE-2024-28000
 Incorrect Privilege Assignment vulnerability in LiteSpeed Technologies LiteSpeed Cache litespeed-cache.This issue affects LiteSpeed Cache: from n/a through = 6.3.0.1.

- [https://github.com/AliHzSec/CVE-2024-28000](https://github.com/AliHzSec/CVE-2024-28000) :  ![starts](https://img.shields.io/github/stars/AliHzSec/CVE-2024-28000.svg) ![forks](https://img.shields.io/github/forks/AliHzSec/CVE-2024-28000.svg)

