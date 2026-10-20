# Update 2026-10-20
## CVE-2026-107824
 x64dbg-MCP Server is a native Model Context Protocol (MCP) plugin for x64dbg that exposes the debugger's full functionality over HTTP. Prior to 1.1, x64dbg-MCP Server exposes all MCP debugger tools over HTTP and SSE without authentication while listening on 0.0.0.0 by default. Any unauthenticated network client that can reach the default port, 9094 for x64 or 9095 for x32, can execute arbitrary x64dbg commands, attach to processes by PID, read and write debuggee memory, and write files to arbitrary paths. This issue is fixed in version 1.1.

- [https://github.com/Iceman2050/mcp-patch-gap-scanner](https://github.com/Iceman2050/mcp-patch-gap-scanner) :  ![starts](https://img.shields.io/github/stars/Iceman2050/mcp-patch-gap-scanner.svg) ![forks](https://img.shields.io/github/forks/Iceman2050/mcp-patch-gap-scanner.svg)


## CVE-2026-105697
 Langflow is a tool for building and deploying AI-powered agents and workflows. Before Langflow 1.10.3, the MCP stdio transport launched whatever command / args a user put in an MCP server configuration, with no allowlist and (before 1.10.3) wrapped in bash -c "exec {command} ...". Any user able to reach the MCP server settings ("Settings → MCP Servers → Add MCP Server", POST/PATCH /api/v2/mcp/servers/{server_name}) or to build a flow with the MCP Tools component could add a "server" whose command is an arbitrary OS command (touch, rm -rf, a reverse shell, ...). The command runs on the Langflow host as the Langflow process user as soon as Langflow tries to connect to the server (listing servers, loading tools, running the flow) — even when the UI then reports that the stdio server failed to start. With the default LANGFLOW_AUTO_LOGIN=true, GET /api/v1/auto_login hands out a token without credentials, so on an exposed instance running the default configuration this is reachable without an account. AUTO_LOGIN is documented as a development-only setting; with it disabled, any authenticated (non-admin) user can exploit it. This issue is fixed in Langflow 1.10.3, langflow-base 0.10.3, and lfx 1.10.3.

- [https://github.com/Iceman2050/mcp-patch-gap-scanner](https://github.com/Iceman2050/mcp-patch-gap-scanner) :  ![starts](https://img.shields.io/github/stars/Iceman2050/mcp-patch-gap-scanner.svg) ![forks](https://img.shields.io/github/forks/Iceman2050/mcp-patch-gap-scanner.svg)


## CVE-2026-104736
 The LearnPress plugin for WordPress is vulnerable to PHP Object Injection in versions up to, and including, 4.4.10 via deserialization of untrusted input from the 'checkout-email' request parameter during the checkout AJAX action. The value is passed through sanitize_text_field(), which does not strip serialized object syntax, then stored in the LearnPress session table and later fed to LP_Helper::maybe_unserialize() → unserialize() (without an allowed_classes restriction) by LP_Session_Handler::get() on subsequent requests. This makes it possible for unauthenticated attackers to inject a PHP Object.

- [https://github.com/murrez/CVE-2026-104736](https://github.com/murrez/CVE-2026-104736) :  ![starts](https://img.shields.io/github/stars/murrez/CVE-2026-104736.svg) ![forks](https://img.shields.io/github/forks/murrez/CVE-2026-104736.svg)


## CVE-2026-104120
 A security vulnerability has been detected in modelcontextprotocol mcp-server-fetch and mcp-server-everything up to 2026.6.4. Affected is the function fetch_url of the file mcp_server_fetch/server.py of the component Fetch Tool. The manipulation of the argument url/path leads to server-side request forgery. The attack may be initiated remotely. The exploit has been disclosed publicly and may be used. The pull request to fix this issue awaits acceptance.

- [https://github.com/Iceman2050/mcp-patch-gap-scanner](https://github.com/Iceman2050/mcp-patch-gap-scanner) :  ![starts](https://img.shields.io/github/stars/Iceman2050/mcp-patch-gap-scanner.svg) ![forks](https://img.shields.io/github/forks/Iceman2050/mcp-patch-gap-scanner.svg)


## CVE-2026-103849
 Adobe Commerce is affected by an Improper Neutralization of Special Elements Used in a Template Engine vulnerability that could result in arbitrary code execution in the context of the current user, potentially gaining elevated access or control over the victim's account or session. Exploitation of this issue does not require user interaction. Scope is changed.

- [https://github.com/dinosn/cve-2026-103849-blockstrap-lab](https://github.com/dinosn/cve-2026-103849-blockstrap-lab) :  ![starts](https://img.shields.io/github/stars/dinosn/cve-2026-103849-blockstrap-lab.svg) ![forks](https://img.shields.io/github/forks/dinosn/cve-2026-103849-blockstrap-lab.svg)


## CVE-2026-99999
A more complete validation at input is forthcoming, but needs more work.

- [https://github.com/01luyicheng/CVE-2026-99999](https://github.com/01luyicheng/CVE-2026-99999) :  ![starts](https://img.shields.io/github/stars/01luyicheng/CVE-2026-99999.svg) ![forks](https://img.shields.io/github/forks/01luyicheng/CVE-2026-99999.svg)
- [https://github.com/zakinko/kpatch-alma-cve-2026-99999](https://github.com/zakinko/kpatch-alma-cve-2026-99999) :  ![starts](https://img.shields.io/github/stars/zakinko/kpatch-alma-cve-2026-99999.svg) ![forks](https://img.shields.io/github/forks/zakinko/kpatch-alma-cve-2026-99999.svg)
- [https://github.com/kingahmadr/CVE-2026-99999-kernel-check](https://github.com/kingahmadr/CVE-2026-99999-kernel-check) :  ![starts](https://img.shields.io/github/stars/kingahmadr/CVE-2026-99999-kernel-check.svg) ![forks](https://img.shields.io/github/forks/kingahmadr/CVE-2026-99999-kernel-check.svg)


## CVE-2026-98385
(sched_cache_grp) to this object instead of embedding it.

- [https://github.com/ylh440104/InfinityCore-Android-CVE-2026-98385](https://github.com/ylh440104/InfinityCore-Android-CVE-2026-98385) :  ![starts](https://img.shields.io/github/stars/ylh440104/InfinityCore-Android-CVE-2026-98385.svg) ![forks](https://img.shields.io/github/forks/ylh440104/InfinityCore-Android-CVE-2026-98385.svg)


## CVE-2026-98260
[ tglx: Move the cleanup right after de_thread() ]

- [https://github.com/ylh440104/InfinityCore-Android-CVE-2026-98260](https://github.com/ylh440104/InfinityCore-Android-CVE-2026-98260) :  ![starts](https://img.shields.io/github/stars/ylh440104/InfinityCore-Android-CVE-2026-98260.svg) ![forks](https://img.shields.io/github/forks/ylh440104/InfinityCore-Android-CVE-2026-98260.svg)
- [https://github.com/jadedFella/lpe-study-notes](https://github.com/jadedFella/lpe-study-notes) :  ![starts](https://img.shields.io/github/stars/jadedFella/lpe-study-notes.svg) ![forks](https://img.shields.io/github/forks/jadedFella/lpe-study-notes.svg)


## CVE-2026-98256
---truncated---

- [https://github.com/villager1314/CVE-2026-98256-Analysis](https://github.com/villager1314/CVE-2026-98256-Analysis) :  ![starts](https://img.shields.io/github/stars/villager1314/CVE-2026-98256-Analysis.svg) ![forks](https://img.shields.io/github/forks/villager1314/CVE-2026-98256-Analysis.svg)
- [https://github.com/ylh440104/InfinityCore-Android-CVE-2026-98256](https://github.com/ylh440104/InfinityCore-Android-CVE-2026-98256) :  ![starts](https://img.shields.io/github/stars/ylh440104/InfinityCore-Android-CVE-2026-98256.svg) ![forks](https://img.shields.io/github/forks/ylh440104/InfinityCore-Android-CVE-2026-98256.svg)


## CVE-2026-98180
Patchwork: https://patchwork.freedesktop.org/patch/750234/

- [https://github.com/MalHyuk/CVE-2026-98180](https://github.com/MalHyuk/CVE-2026-98180) :  ![starts](https://img.shields.io/github/stars/MalHyuk/CVE-2026-98180.svg) ![forks](https://img.shields.io/github/forks/MalHyuk/CVE-2026-98180.svg)


## CVE-2026-97941
bring back unlikely() hint now that the condition is unlikely.

- [https://github.com/ylh440104/InfinityCore-Android-CVE-2026-97941](https://github.com/ylh440104/InfinityCore-Android-CVE-2026-97941) :  ![starts](https://img.shields.io/github/stars/ylh440104/InfinityCore-Android-CVE-2026-97941.svg) ![forks](https://img.shields.io/github/forks/ylh440104/InfinityCore-Android-CVE-2026-97941.svg)


## CVE-2026-96656
 Plex Media Server before 1.43.3.10861 allows an admin user to write arbitrary files that may be executed on load. The preference TranscoderH264Options is appended verbatim to x264's option string on every transcode. At startup, all .so files are run without signature, execute bit, or symbol checks.

- [https://github.com/gmh5225/plex2shell](https://github.com/gmh5225/plex2shell) :  ![starts](https://img.shields.io/github/stars/gmh5225/plex2shell.svg) ![forks](https://img.shields.io/github/forks/gmh5225/plex2shell.svg)
- [https://github.com/a3igner/plex-codec-cache-implant](https://github.com/a3igner/plex-codec-cache-implant) :  ![starts](https://img.shields.io/github/stars/a3igner/plex-codec-cache-implant.svg) ![forks](https://img.shields.io/github/forks/a3igner/plex-codec-cache-implant.svg)


## CVE-2026-96655
 Plex Media Server before 1.43.3.10861 allows an authenticated user to request arbitrary internal or external addresses via the '/video/:/transcode/universal' path parameter.

- [https://github.com/gmh5225/plex2shell](https://github.com/gmh5225/plex2shell) :  ![starts](https://img.shields.io/github/stars/gmh5225/plex2shell.svg) ![forks](https://img.shields.io/github/forks/gmh5225/plex2shell.svg)


## CVE-2026-96654
 Plex Media Server before 1.43.3.10861 does not correctly neutralize URL values included in 'searchOne,' allowing an attacker to call other plugins' functions and supply their own parameters.

- [https://github.com/gmh5225/plex2shell](https://github.com/gmh5225/plex2shell) :  ![starts](https://img.shields.io/github/stars/gmh5225/plex2shell.svg) ![forks](https://img.shields.io/github/forks/gmh5225/plex2shell.svg)


## CVE-2026-96652
 Plex Media Server before 1.43.3.10861 allows SSRF via '/player/timeline'. An attacker using any X-Plex-Token value can include a full URL in the 'protocol' parameter and force the Plex server to POST to the attacker's chosen destination.

- [https://github.com/gmh5225/plex2shell](https://github.com/gmh5225/plex2shell) :  ![starts](https://img.shields.io/github/stars/gmh5225/plex2shell.svg) ![forks](https://img.shields.io/github/forks/gmh5225/plex2shell.svg)


## CVE-2026-92262
 MariaDB server is a community developed fork of MySQL server. From 10.6.1 until 10.6.28, 10.11.19, 11.4.13, 11.8.9, 12.3.3, and 13.0.2, the #mysql50# bypass prefix is affected because it allows the #mysql50# prefix to bypass normal table-name filesystem encoding. An attacker can trigger the issue with a table name using the #mysql50# prefix, then use a #mysql50# table name to access files under their legacy unencoded name and cause crashes, data corruption, data exfiltration, or remote code execution. This issue is fixed in versions 10.6.28, 10.11.19, 11.4.13, 11.8.9, 12.3.3, and 13.0.2.

- [https://github.com/SeanDishman/mariadb-cve-2026-92262](https://github.com/SeanDishman/mariadb-cve-2026-92262) :  ![starts](https://img.shields.io/github/stars/SeanDishman/mariadb-cve-2026-92262.svg) ![forks](https://img.shields.io/github/forks/SeanDishman/mariadb-cve-2026-92262.svg)


## CVE-2026-89754
---truncated---

- [https://github.com/ylh440104/InfinityCore-Android-CVE-2026-89754](https://github.com/ylh440104/InfinityCore-Android-CVE-2026-89754) :  ![starts](https://img.shields.io/github/stars/ylh440104/InfinityCore-Android-CVE-2026-89754.svg) ![forks](https://img.shields.io/github/forks/ylh440104/InfinityCore-Android-CVE-2026-89754.svg)


## CVE-2026-85748
 MariaDB server is a community developed fork of MySQL server. From 12.3.1 until 12.3.3 and 13.0.2, SYS_REFCURSOR handling is affected because cursor-array reallocation can leave stale references in routine contexts. A low-privileged attacker can open a large number of SYS_REFCURSORs and then fetch one to trigger a use-after-free that can enable remote code execution when combined with another vulnerability. This issue is fixed in versions 12.3.3 and 13.0.2.

- [https://github.com/SeanDishman/mariadb-cve-2026-92262](https://github.com/SeanDishman/mariadb-cve-2026-92262) :  ![starts](https://img.shields.io/github/stars/SeanDishman/mariadb-cve-2026-92262.svg) ![forks](https://img.shields.io/github/forks/SeanDishman/mariadb-cve-2026-92262.svg)


## CVE-2026-85746
 MariaDB server is a community developed fork of MySQL server. From 10.6.1 until 10.6.28, 10.11.19, 11.4.13, 11.8.9, 12.3.3, and 13.0.2, ST_AsText can write beyond an allocated output buffer when converting deeply nested GeometryCollections because recursive WKT serialization does not account for bytes consumed or reserve sufficient space. A low-privileged remote attacker can submit a specially crafted GIS object to corrupt memory and potentially achieve code execution when combined with another vulnerability. This issue is fixed in versions 10.6.28, 10.11.19, 11.4.13, 11.8.9, 12.3.3, and 13.0.2.

- [https://github.com/SeanDishman/mariadb-cve-2026-92262](https://github.com/SeanDishman/mariadb-cve-2026-92262) :  ![starts](https://img.shields.io/github/stars/SeanDishman/mariadb-cve-2026-92262.svg) ![forks](https://img.shields.io/github/forks/SeanDishman/mariadb-cve-2026-92262.svg)


## CVE-2026-80775
another task can install a private hash while the counter is still 0.

- [https://github.com/ylh440104/InfinityCore-Android-CVE-2026-80775](https://github.com/ylh440104/InfinityCore-Android-CVE-2026-80775) :  ![starts](https://img.shields.io/github/stars/ylh440104/InfinityCore-Android-CVE-2026-80775.svg) ![forks](https://img.shields.io/github/forks/ylh440104/InfinityCore-Android-CVE-2026-80775.svg)


## CVE-2026-71557
 go-git is an extensible git implementation library written in pure Go. Prior to 5.19.2 and 6.0.0-alpha.5, reference names are not sanitized before being used to construct on-disk paths under the reference storage directory, so a maliciously crafted reference name (for example containing directory-traversal sequences) can cause go-git to write files outside the intended reference storage directory. Versions 5.19.2 and 6.0.0-alpha.5 fix the issue.

- [https://github.com/Saku0512/reprokit-go-git-cve-2026-71557-lab](https://github.com/Saku0512/reprokit-go-git-cve-2026-71557-lab) :  ![starts](https://img.shields.io/github/stars/Saku0512/reprokit-go-git-cve-2026-71557-lab.svg) ![forks](https://img.shields.io/github/forks/Saku0512/reprokit-go-git-cve-2026-71557-lab.svg)


## CVE-2026-64560
---truncated---

- [https://github.com/itsmichiya/exploit-CVE-2026-64560](https://github.com/itsmichiya/exploit-CVE-2026-64560) :  ![starts](https://img.shields.io/github/stars/itsmichiya/exploit-CVE-2026-64560.svg) ![forks](https://img.shields.io/github/forks/itsmichiya/exploit-CVE-2026-64560.svg)


## CVE-2026-61732
 Decepticon is an autonomous hacking agent for red teams. Versions prior to 1.1.17 wrap web crawl results — the output of agent reconnaissance against target services — into LLM messages without neutralizing ChatML special-token literals. Under the BYOK (Bring Your Own Key) deployment model, users configure their own LLM credentials to any OpenAI-compatible endpoint. Most open-source and self-deployed model providers (vLLM, SGLang, Ollama, LM Studio, text-generation-webui, etc.) do not filter special-token literals from user content in their default configurations. Those literals are parsed into structural role-boundary token IDs, meaning an attacker string planted in a target web page forges a new operator turn the model treats as authoritative, bypassing Decepticon's agent guardrails and resulting in arbitrary command execution inside the Kali Linux sandbox. Version 1.1.17 patches the issue.

- [https://github.com/Iceman2050/chatml-role-token-probe](https://github.com/Iceman2050/chatml-role-token-probe) :  ![starts](https://img.shields.io/github/stars/Iceman2050/chatml-role-token-probe.svg) ![forks](https://img.shields.io/github/forks/Iceman2050/chatml-role-token-probe.svg)


## CVE-2026-53787
 Amasty Order Attributes for Magento 2 before version 4.0.0 contains an unauthenticated arbitrary file upload vulnerability that allows unauthenticated attackers to write arbitrary files to the store's media directory by submitting files of any type or name to the upload endpoint without authentication, session validation, or cart context. Attackers can upload PHP files to achieve remote code execution on servers where the media directory permits PHP execution, or alternatively enable malware hosting, stored cross-site scripting via HTML or SVG uploads, and path traversal to write files outside the intended upload directory.

- [https://github.com/MRdark-ops/CVE-2026-53787-poc](https://github.com/MRdark-ops/CVE-2026-53787-poc) :  ![starts](https://img.shields.io/github/stars/MRdark-ops/CVE-2026-53787-poc.svg) ![forks](https://img.shields.io/github/forks/MRdark-ops/CVE-2026-53787-poc.svg)
- [https://github.com/elitexspam/Def4cer](https://github.com/elitexspam/Def4cer) :  ![starts](https://img.shields.io/github/stars/elitexspam/Def4cer.svg) ![forks](https://img.shields.io/github/forks/elitexspam/Def4cer.svg)


## CVE-2026-50229
Users are recommended to upgrade to version 11.0.23, 10.1.56 or 9.0.119, which fix the issue.

- [https://github.com/qsuv/CVE-2026-50229](https://github.com/qsuv/CVE-2026-50229) :  ![starts](https://img.shields.io/github/stars/qsuv/CVE-2026-50229.svg) ![forks](https://img.shields.io/github/forks/qsuv/CVE-2026-50229.svg)


## CVE-2026-43499
  	changelog ]

- [https://github.com/MSEDGE-CORE/GhostLock-HonorFne](https://github.com/MSEDGE-CORE/GhostLock-HonorFne) :  ![starts](https://img.shields.io/github/stars/MSEDGE-CORE/GhostLock-HonorFne.svg) ![forks](https://img.shields.io/github/forks/MSEDGE-CORE/GhostLock-HonorFne.svg)
- [https://github.com/newazbenalam/Root-My-Galaxy-Payloads](https://github.com/newazbenalam/Root-My-Galaxy-Payloads) :  ![starts](https://img.shields.io/github/stars/newazbenalam/Root-My-Galaxy-Payloads.svg) ![forks](https://img.shields.io/github/forks/newazbenalam/Root-My-Galaxy-Payloads.svg)


## CVE-2026-43284
destination-frag path or fall back to skb_cow_data().

- [https://github.com/tangdino222/DirtyFrag](https://github.com/tangdino222/DirtyFrag) :  ![starts](https://img.shields.io/github/stars/tangdino222/DirtyFrag.svg) ![forks](https://img.shields.io/github/forks/tangdino222/DirtyFrag.svg)


## CVE-2026-33017
 Langflow is a tool for building and deploying AI-powered agents and workflows. In versions prior to 1.9.0, the POST /api/v1/build_public_tmp/{flow_id}/flow endpoint allows building public flows without requiring authentication. When the optional data parameter is supplied, the endpoint uses attacker-controlled flow data (containing arbitrary Python code in node definitions) instead of the stored flow data from the database. This code is passed to exec() with zero sandboxing, resulting in unauthenticated remote code execution. This is distinct from CVE-2025-3248, which fixed /api/v1/validate/code by adding authentication. The build_public_tmp endpoint is designed to be unauthenticated (for public flows) but incorrectly accepts attacker-supplied flow data containing arbitrary executable code. This issue has been fixed in version 1.9.0.

- [https://github.com/HackfutSecRoot/LangFlow-Rce](https://github.com/HackfutSecRoot/LangFlow-Rce) :  ![starts](https://img.shields.io/github/stars/HackfutSecRoot/LangFlow-Rce.svg) ![forks](https://img.shields.io/github/forks/HackfutSecRoot/LangFlow-Rce.svg)


## CVE-2026-20349
This vulnerability is due to insufficient error checking when processing HTTP requests. An attacker could exploit this vulnerability by sending a crafted HTTP request to the Remote Access SSL VPN service on an affected device. A successful exploit could allow the attacker to cause the affected device to reload, resulting in a DoS condition.

- [https://github.com/ekacs/predicted-cve-2026-20349](https://github.com/ekacs/predicted-cve-2026-20349) :  ![starts](https://img.shields.io/github/stars/ekacs/predicted-cve-2026-20349.svg) ![forks](https://img.shields.io/github/forks/ekacs/predicted-cve-2026-20349.svg)


## CVE-2026-10809
 A security flaw has been discovered in itsourcecode Fees Management System 1.0. This impacts an unknown function of the file /manage_user.php. The manipulation of the argument ID results in sql injection. The attack can be executed remotely. The exploit has been released to the public and may be used for attacks.

- [https://github.com/fortbridge/cve-2026-108097-research](https://github.com/fortbridge/cve-2026-108097-research) :  ![starts](https://img.shields.io/github/stars/fortbridge/cve-2026-108097-research.svg) ![forks](https://img.shields.io/github/forks/fortbridge/cve-2026-108097-research.svg)


## CVE-2026-8034
 A server-side request forgery (SSRF) vulnerability was identified in the GitHub Enterprise Server notebook viewer that allowed an attacker to access internal services by exploiting URL parser confusion between the validation layer and the HTTP request library. The hostname validation used a different URL parser than the request library, enabling a crafted URL to pass validation while directing the request to an unintended host. Exploitation required network access to the GitHub Enterprise Server instance. This vulnerability affected all versions of GitHub Enterprise Server prior to 3.21 and was fixed in versions 3.16.18, 3.17.15, 3.18.9, 3.19.6, and 3.20.2. This vulnerability was reported via the GitHub Bug Bounty program.

- [https://github.com/oscerd/CVE-2026-80343](https://github.com/oscerd/CVE-2026-80343) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-80343.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-80343.svg)


## CVE-2026-8031
 A vulnerability was detected in PicoTronica e-Clinic Healthcare System ECHS 5.7. The affected element is an unknown function of the file /cdemos/echs/api/v2/patient-records of the component API Endpoint. The manipulation results in missing authentication. The attack can be executed remotely. The exploit is now public and may be used. Upgrading to version 5.7.1 is sufficient to fix this issue. You should upgrade the affected component. The vendor was contacted early, responded in a very professional manner and quickly released a fixed version of the affected product.

- [https://github.com/oscerd/CVE-2026-80312](https://github.com/oscerd/CVE-2026-80312) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-80312.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-80312.svg)


## CVE-2026-5822
 This CVE ID has been rejected or withdrawn by its CVE Numbering Authority.

- [https://github.com/DevAli00/CVE-2026-58221](https://github.com/DevAli00/CVE-2026-58221) :  ![starts](https://img.shields.io/github/stars/DevAli00/CVE-2026-58221.svg) ![forks](https://img.shields.io/github/forks/DevAli00/CVE-2026-58221.svg)


## CVE-2026-4349
 A vulnerability was determined in Duende IdentityServer4 up to 4.1.2. The affected element is an unknown function of the file /connect/authorize of the component Token Renewal Endpoint. This manipulation of the argument id_token_hint causes improper authentication. It is possible to initiate the attack remotely. The attack is considered to have high complexity. The exploitability is described as difficult. This vulnerability only affects products that are no longer supported by the maintainer.

- [https://github.com/HORKimhab/CVE-2026-43499](https://github.com/HORKimhab/CVE-2026-43499) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-43499.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-43499.svg)


## CVE-2026-3415
Successful exploitation may allow a highly privileged actor to read files accessible within the server hosting the affected product. Additionally, it may be possible to trigger outbound requests to unintended internal or external locations, depending on the server environment and network configuration. Specially crafted XML payloads can also lead to excessive resource consumption during parsing, impacting the availability of the product.

- [https://github.com/Saku0512/CVE-2026-34157-poc](https://github.com/Saku0512/CVE-2026-34157-poc) :  ![starts](https://img.shields.io/github/stars/Saku0512/CVE-2026-34157-poc.svg) ![forks](https://img.shields.io/github/forks/Saku0512/CVE-2026-34157-poc.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-15x](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-15x) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-15x.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-15x.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo.svg)


## CVE-2025-53051
 Vulnerability in the RDBMS Functional Index component of Oracle Database Server.  Supported versions that are affected are 23.4-23.9. Easily exploitable vulnerability allows high privileged attacker having SYSDBA privilege with network access via Oracle Net to compromise RDBMS Functional Index.  Successful attacks of this vulnerability can result in  unauthorized read access to a subset of RDBMS Functional Index accessible data. CVSS 3.1 Base Score 2.7 (Confidentiality impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:N/A:N).

- [https://github.com/emad-almousa/CVE-2025-53051](https://github.com/emad-almousa/CVE-2025-53051) :  ![starts](https://img.shields.io/github/stars/emad-almousa/CVE-2025-53051.svg) ![forks](https://img.shields.io/github/forks/emad-almousa/CVE-2025-53051.svg)


## CVE-2025-49812
Only configurations using "SSLEngine optional" to enable TLS upgrades are affected. Users are recommended to upgrade to version 2.4.64, which removes support for TLS upgrade.

- [https://github.com/kimdongjun22/cve-2025-49812-ctf](https://github.com/kimdongjun22/cve-2025-49812-ctf) :  ![starts](https://img.shields.io/github/stars/kimdongjun22/cve-2025-49812-ctf.svg) ![forks](https://img.shields.io/github/forks/kimdongjun22/cve-2025-49812-ctf.svg)


## CVE-2025-32711
 Ai command injection in M365 Copilot allows an unauthorized attacker to disclose information over a network.

- [https://github.com/Danielle-Respes/Threat-Hunt-EchoLeak-Copilot-Prompt-Injection-Sentinel-KQL-Oct-2026](https://github.com/Danielle-Respes/Threat-Hunt-EchoLeak-Copilot-Prompt-Injection-Sentinel-KQL-Oct-2026) :  ![starts](https://img.shields.io/github/stars/Danielle-Respes/Threat-Hunt-EchoLeak-Copilot-Prompt-Injection-Sentinel-KQL-Oct-2026.svg) ![forks](https://img.shields.io/github/forks/Danielle-Respes/Threat-Hunt-EchoLeak-Copilot-Prompt-Injection-Sentinel-KQL-Oct-2026.svg)


## CVE-2025-31125
 Vite is a frontend tooling framework for javascript. Vite exposes content of non-allowed files using ?inline&import or ?raw?import. Only apps explicitly exposing the Vite dev server to the network (using --host or server.host config option) are affected. This vulnerability is fixed in 6.2.4, 6.1.3, 6.0.13, 5.4.16, and 4.5.11.

- [https://github.com/L15B04/Exploit-VITE-CVE-2025-30208-CVE-2025-31125](https://github.com/L15B04/Exploit-VITE-CVE-2025-30208-CVE-2025-31125) :  ![starts](https://img.shields.io/github/stars/L15B04/Exploit-VITE-CVE-2025-30208-CVE-2025-31125.svg) ![forks](https://img.shields.io/github/forks/L15B04/Exploit-VITE-CVE-2025-30208-CVE-2025-31125.svg)


## CVE-2025-30208
 Vite, a provider of frontend development tooling, has a vulnerability in versions prior to 6.2.3, 6.1.2, 6.0.12, 5.4.15, and 4.5.10. `@fs` denies access to files outside of Vite serving allow list. Adding `?raw??` or `?import&raw??` to the URL bypasses this limitation and returns the file content if it exists. This bypass exists because trailing separators such as `?` are removed in several places, but are not accounted for in query string regexes. The contents of arbitrary files can be returned to the browser. Only apps explicitly exposing the Vite dev server to the network (using `--host` or `server.host` config option) are affected. Versions 6.2.3, 6.1.2, 6.0.12, 5.4.15, and 4.5.10 fix the issue.

- [https://github.com/L15B04/Exploit-VITE-CVE-2025-30208-CVE-2025-31125](https://github.com/L15B04/Exploit-VITE-CVE-2025-30208-CVE-2025-31125) :  ![starts](https://img.shields.io/github/stars/L15B04/Exploit-VITE-CVE-2025-30208-CVE-2025-31125.svg) ![forks](https://img.shields.io/github/forks/L15B04/Exploit-VITE-CVE-2025-30208-CVE-2025-31125.svg)


## CVE-2025-6647
The specific flaw exists within the parsing of U3D files. The issue results from the lack of proper validation of user-supplied data, which can result in a write past the end of an allocated object. An attacker can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-26644.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict.svg)


## CVE-2025-6440
 The WooCommerce Designer Pro plugin for WordPress, used by the Pricom - Printing Company & Design Services WordPress theme, is vulnerable to arbitrary file uploads due to missing file type validation in the 'wcdp_save_canvas_design_ajax' function in all versions up to, and including, 1.9.26. This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible.

- [https://github.com/0xCyp1337/CVE-2025-6440-BypassExt](https://github.com/0xCyp1337/CVE-2025-6440-BypassExt) :  ![starts](https://img.shields.io/github/stars/0xCyp1337/CVE-2025-6440-BypassExt.svg) ![forks](https://img.shields.io/github/forks/0xCyp1337/CVE-2025-6440-BypassExt.svg)


## CVE-2025-3248
code.

- [https://github.com/cpwjdgh/CVE-2025-3248-CTF-Lab](https://github.com/cpwjdgh/CVE-2025-3248-CTF-Lab) :  ![starts](https://img.shields.io/github/stars/cpwjdgh/CVE-2025-3248-CTF-Lab.svg) ![forks](https://img.shields.io/github/forks/cpwjdgh/CVE-2025-3248-CTF-Lab.svg)


## CVE-2024-27198
 In JetBrains TeamCity before 2023.11.4 authentication bypass allowing to perform admin actions was possible

- [https://github.com/wonnnggge/CVE-2024-27198_CTF](https://github.com/wonnnggge/CVE-2024-27198_CTF) :  ![starts](https://img.shields.io/github/stars/wonnnggge/CVE-2024-27198_CTF.svg) ![forks](https://img.shields.io/github/forks/wonnnggge/CVE-2024-27198_CTF.svg)


## CVE-2024-25600
 Improper Control of Generation of Code ('Code Injection') vulnerability in Codeer Limited Bricks Builder allows Code Injection.This issue affects Bricks Builder: from n/a through 1.9.6.

- [https://github.com/K52-ai/CVE-2024-25600](https://github.com/K52-ai/CVE-2024-25600) :  ![starts](https://img.shields.io/github/stars/K52-ai/CVE-2024-25600.svg) ![forks](https://img.shields.io/github/forks/K52-ai/CVE-2024-25600.svg)


## CVE-2024-23897
 Jenkins 2.441 and earlier, LTS 2.426.2 and earlier does not disable a feature of its CLI command parser that replaces an '@' character followed by a file path in an argument with the file's contents, allowing unauthenticated attackers to read arbitrary files on the Jenkins controller file system.

- [https://github.com/ydkdk12345-bot/CVE-2024-23897-CTF](https://github.com/ydkdk12345-bot/CVE-2024-23897-CTF) :  ![starts](https://img.shields.io/github/stars/ydkdk12345-bot/CVE-2024-23897-CTF.svg) ![forks](https://img.shields.io/github/forks/ydkdk12345-bot/CVE-2024-23897-CTF.svg)


## CVE-2023-4622
We recommend upgrading past commit 790c2f9d15b594350ae9bca7b236f2b1859de02c (or backported equivalents).

- [https://github.com/uz56764/CVE-CVE-2023-4622](https://github.com/uz56764/CVE-CVE-2023-4622) :  ![starts](https://img.shields.io/github/stars/uz56764/CVE-CVE-2023-4622.svg) ![forks](https://img.shields.io/github/forks/uz56764/CVE-CVE-2023-4622.svg)


## CVE-2022-30190
Please see the MSRC Blog Entry for important information about steps you can take to protect your system from this vulnerability.

- [https://github.com/dayobamiii/OMOTOSO-AYOBAMI](https://github.com/dayobamiii/OMOTOSO-AYOBAMI) :  ![starts](https://img.shields.io/github/stars/dayobamiii/OMOTOSO-AYOBAMI.svg) ![forks](https://img.shields.io/github/forks/dayobamiii/OMOTOSO-AYOBAMI.svg)


## CVE-2022-22706
 Arm Mali GPU Kernel Driver allows a non-privileged user to achieve write access to read-only memory pages. This affects Midgard r26p0 through r31p0, Bifrost r0p0 through r35p0, and Valhall r19p0 through r35p0.

- [https://github.com/BennyWaitWhat/Sony-XBR-65X850D](https://github.com/BennyWaitWhat/Sony-XBR-65X850D) :  ![starts](https://img.shields.io/github/stars/BennyWaitWhat/Sony-XBR-65X850D.svg) ![forks](https://img.shields.io/github/forks/BennyWaitWhat/Sony-XBR-65X850D.svg)


## CVE-2022-1015
 A flaw was found in the Linux kernel in linux/net/netfilter/nf_tables_api.c of the netfilter subsystem. This flaw allows a local user to cause an out-of-bounds write issue.

- [https://github.com/uz56764/CVE-2022-1015](https://github.com/uz56764/CVE-2022-1015) :  ![starts](https://img.shields.io/github/stars/uz56764/CVE-2022-1015.svg) ![forks](https://img.shields.io/github/forks/uz56764/CVE-2022-1015.svg)


## CVE-2022-0847
 A flaw was found in the way the "flags" member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/Greetdawn/CVE-2022-0847-DirtyPipe](https://github.com/Greetdawn/CVE-2022-0847-DirtyPipe) :  ![starts](https://img.shields.io/github/stars/Greetdawn/CVE-2022-0847-DirtyPipe.svg) ![forks](https://img.shields.io/github/forks/Greetdawn/CVE-2022-0847-DirtyPipe.svg)
- [https://github.com/MingqiZhang7710/cve-2022-0847-poc-dockerimage](https://github.com/MingqiZhang7710/cve-2022-0847-poc-dockerimage) :  ![starts](https://img.shields.io/github/stars/MingqiZhang7710/cve-2022-0847-poc-dockerimage.svg) ![forks](https://img.shields.io/github/forks/MingqiZhang7710/cve-2022-0847-poc-dockerimage.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/mah4nzfr/CVE-2021-41773](https://github.com/mah4nzfr/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/mah4nzfr/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/mah4nzfr/CVE-2021-41773.svg)


## CVE-2021-4177
 livehelperchat is vulnerable to Generation of Error Message Containing Sensitive Information

- [https://github.com/LayarKacaSiber/CVE-2021-41773](https://github.com/LayarKacaSiber/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/LayarKacaSiber/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/LayarKacaSiber/CVE-2021-41773.svg)


## CVE-2020-36847
 The Simple-File-List Plugin for WordPress is vulnerable to Remote Code Execution in versions up to, and including, 4.2.2 via the rename function which can be used to rename uploaded PHP code with a png extension to use a php extension. This allows unauthenticated attackers to execute code on the server.

- [https://github.com/K52-ai/CVE-2020-36847](https://github.com/K52-ai/CVE-2020-36847) :  ![starts](https://img.shields.io/github/stars/K52-ai/CVE-2020-36847.svg) ![forks](https://img.shields.io/github/forks/K52-ai/CVE-2020-36847.svg)


## CVE-2018-5391
 The Linux kernel, versions 3.9+, is vulnerable to a denial of service attack with low rates of specially modified packets targeting IP fragment re-assembly. An attacker may cause a denial of service condition by sending specially crafted IP fragments. Various vulnerabilities in IP fragmentation have been discovered and fixed over the years. The current vulnerability (CVE-2018-5391) became exploitable in the Linux kernel with the increase of the IP fragment reassembly queue size.

- [https://github.com/zeinabmazraani/OverlapCraft](https://github.com/zeinabmazraani/OverlapCraft) :  ![starts](https://img.shields.io/github/stars/zeinabmazraani/OverlapCraft.svg) ![forks](https://img.shields.io/github/forks/zeinabmazraani/OverlapCraft.svg)


## CVE-2017-11882
 Microsoft Office 2007 Service Pack 3, Microsoft Office 2010 Service Pack 2, Microsoft Office 2013 Service Pack 1, and Microsoft Office 2016 allow an attacker to run arbitrary code in the context of the current user by failing to properly handle objects in memory, aka "Microsoft Office Memory Corruption Vulnerability". This CVE ID is unique from CVE-2017-11884.

- [https://github.com/danielakin417/CVE-2017-11882-analysis](https://github.com/danielakin417/CVE-2017-11882-analysis) :  ![starts](https://img.shields.io/github/stars/danielakin417/CVE-2017-11882-analysis.svg) ![forks](https://img.shields.io/github/forks/danielakin417/CVE-2017-11882-analysis.svg)


## CVE-2011-2523
 vsftpd 2.3.4 downloaded between 20110630 and 20110703 contains a backdoor which opens a shell on port 6200/tcp.

- [https://github.com/secwitness/CVE-2011-2523-vsftpd-backdoor-analysis](https://github.com/secwitness/CVE-2011-2523-vsftpd-backdoor-analysis) :  ![starts](https://img.shields.io/github/stars/secwitness/CVE-2011-2523-vsftpd-backdoor-analysis.svg) ![forks](https://img.shields.io/github/forks/secwitness/CVE-2011-2523-vsftpd-backdoor-analysis.svg)

