# Update 2026-11-07
## CVE-2026-123158
 sshd in OpenSSH before 10.6p2 on Linux, when musl libc is used without PAM, lacks a workaround for a password authentication bypass (related to misinterpretation of whether a string is intended to be a password hash). For some configurations of accounts, any password between 256 and 1024 characters succeeds. An example of a platform using musl libc without PAM is Alpine Linux.

- [https://github.com/rothoma2/cve-2026-123158-sshole](https://github.com/rothoma2/cve-2026-123158-sshole) :  ![starts](https://img.shields.io/github/stars/rothoma2/cve-2026-123158-sshole.svg) ![forks](https://img.shields.io/github/forks/rothoma2/cve-2026-123158-sshole.svg)
- [https://github.com/0xBlackash/CVE-2026-123158](https://github.com/0xBlackash/CVE-2026-123158) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-123158.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-123158.svg)
- [https://github.com/gabrielunknown/CVE-2026-123158_SSHole](https://github.com/gabrielunknown/CVE-2026-123158_SSHole) :  ![starts](https://img.shields.io/github/stars/gabrielunknown/CVE-2026-123158_SSHole.svg) ![forks](https://img.shields.io/github/forks/gabrielunknown/CVE-2026-123158_SSHole.svg)
- [https://github.com/coboliqcom/cve-2026-123158-sshole-safe-rust](https://github.com/coboliqcom/cve-2026-123158-sshole-safe-rust) :  ![starts](https://img.shields.io/github/stars/coboliqcom/cve-2026-123158-sshole-safe-rust.svg) ![forks](https://img.shields.io/github/forks/coboliqcom/cve-2026-123158-sshole-safe-rust.svg)
- [https://github.com/ersinkoc/sshole-check](https://github.com/ersinkoc/sshole-check) :  ![starts](https://img.shields.io/github/stars/ersinkoc/sshole-check.svg) ![forks](https://img.shields.io/github/forks/ersinkoc/sshole-check.svg)
- [https://github.com/The-DevOps-Daily/alpine-sshd-check](https://github.com/The-DevOps-Daily/alpine-sshd-check) :  ![starts](https://img.shields.io/github/stars/The-DevOps-Daily/alpine-sshd-check.svg) ![forks](https://img.shields.io/github/forks/The-DevOps-Daily/alpine-sshd-check.svg)


## CVE-2026-122158
 A security flaw has been discovered in InvoiceShelf up to 2.4.3/3.0.0-alpha.3. Affected by this issue is the function MemberService::create of the file app/Domains/Accounts/Application/MemberService.php. Performing a manipulation of the argument companies[].id/companies[].role results in improper access controls. The attack is possible to be carried out remotely. The exploit has been released to the public and may be used for attacks. Upgrading to version 2.4.4 and 3.0.0-alpha.4 can resolve this issue. The patch is named c798b513c3ab6e672a1678774720fbb282f4d0c6. It is recommended to upgrade the affected component.

- [https://github.com/capivara-research/CVE-2026-122158](https://github.com/capivara-research/CVE-2026-122158) :  ![starts](https://img.shields.io/github/stars/capivara-research/CVE-2026-122158.svg) ![forks](https://img.shields.io/github/forks/capivara-research/CVE-2026-122158.svg)


## CVE-2026-122051
 A flaw has been found in Edimax BR-6208AC 1.32. Affected by this vulnerability is an unknown functionality of the file /goform/mp. Executing a manipulation can lead to command injection. The attack may be launched remotely. The exploit has been published and may be used. The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/carterlasalle/CVE-2026-122051](https://github.com/carterlasalle/CVE-2026-122051) :  ![starts](https://img.shields.io/github/stars/carterlasalle/CVE-2026-122051.svg) ![forks](https://img.shields.io/github/forks/carterlasalle/CVE-2026-122051.svg)


## CVE-2026-122006
 The activestorage gem before 8.1.4.1 for Ruby on Rails, when ImageMagick attachment processing occurs, can allow server read and write operations (e.g., reading secret_key_base) because the ImageMagick analyzer runs when a file is attached, and there is not an ImageMagick security policy to block unintended functionality.

- [https://github.com/charlie-goldenowl/cve-2026-122006-check](https://github.com/charlie-goldenowl/cve-2026-122006-check) :  ![starts](https://img.shields.io/github/stars/charlie-goldenowl/cve-2026-122006-check.svg) ![forks](https://img.shields.io/github/forks/charlie-goldenowl/cve-2026-122006-check.svg)


## CVE-2026-120232
 A vulnerability was identified in Horizon DataSys Reboot Restore Standard up to 13.2. The impacted element is the function sub_23908 in the library shield.sys of the component Kernel Driver. Such manipulation leads to memory corruption. The attack can only be performed from a local environment. The exploit is publicly available and might be used. A fix is planned for the upcoming release.

- [https://github.com/Element2023H/CVE-2026-120232-RUST-POC](https://github.com/Element2023H/CVE-2026-120232-RUST-POC) :  ![starts](https://img.shields.io/github/stars/Element2023H/CVE-2026-120232-RUST-POC.svg) ![forks](https://img.shields.io/github/forks/Element2023H/CVE-2026-120232-RUST-POC.svg)


## CVE-2026-119977
 WordPress Core is vulnerable to Remote Code Execution in versions 4.7 through 7.1.3. This is due to predictable, web-accessible staging paths used during full-package core upgrades. This makes it possible for unauthenticated attackers to execute code on the server during the upgrade window.

- [https://github.com/tc4dy/CVE-2026-119977-Toolkit](https://github.com/tc4dy/CVE-2026-119977-Toolkit) :  ![starts](https://img.shields.io/github/stars/tc4dy/CVE-2026-119977-Toolkit.svg) ![forks](https://img.shields.io/github/forks/tc4dy/CVE-2026-119977-Toolkit.svg)


## CVE-2026-116779
 FreeSWITCH is a Software Defined Telecom Stack enabling the digital transformation from proprietary telecom switches to a software implementation that runs on any commodity hardware. Prior to 1.11.3, sofia_presence_handle_sip_i_message() split the To user of an inbound SIP MESSAGE on a plus sign and treated the left side as a chat protocol selector. Selecting the api chat proto reached switch_api_execute(), allowing a peer whose MESSAGE was accepted to run FreeSWITCH API commands, including operating-system command sinks, with the daemon's privileges. Inbound chat is enabled on the stock internal and external profiles, and any authenticated profile account is sufficient; stock directory users without password material can also remove that barrier in affected configurations. The flaw permits configuration and credential disclosure, arbitrary call control, and command execution, and exploitation has been observed in the wild. This issue is fixed in version 1.11.3.

- [https://github.com/majidrahimi5020-lgtm/Poc-exploit-for-CVE-2026-116779-FreeSWITCH-](https://github.com/majidrahimi5020-lgtm/Poc-exploit-for-CVE-2026-116779-FreeSWITCH-) :  ![starts](https://img.shields.io/github/stars/majidrahimi5020-lgtm/Poc-exploit-for-CVE-2026-116779-FreeSWITCH-.svg) ![forks](https://img.shields.io/github/forks/majidrahimi5020-lgtm/Poc-exploit-for-CVE-2026-116779-FreeSWITCH-.svg)


## CVE-2026-116606
 An authentication bypass in Barracuda Email Security Gateway versions earlier than 9.4.0.030 allows an unauthenticated remote attacker to invoke a configuration-import function and restore a crafted, compatible backup archive, resulting in unauthorized modification of the appliance’s global configuration.

- [https://github.com/watchtowrlabs/watchTowr-vs-Barracuda-RCE-CVE-2026-116606-CVE-2026-111560](https://github.com/watchtowrlabs/watchTowr-vs-Barracuda-RCE-CVE-2026-116606-CVE-2026-111560) :  ![starts](https://img.shields.io/github/stars/watchtowrlabs/watchTowr-vs-Barracuda-RCE-CVE-2026-116606-CVE-2026-111560.svg) ![forks](https://img.shields.io/github/forks/watchtowrlabs/watchTowr-vs-Barracuda-RCE-CVE-2026-116606-CVE-2026-111560.svg)


## CVE-2026-116512
 The Project Manager – AI Powered Project Management, Task Management, Kanban Board & Time Tracker plugin for WordPress is vulnerable to Remote Code Execution in all versions up to, and including, 4.1.1 via the 'id' parameter parameter. This is due to unsanitized 'id' parameter value concatenated directly into the pipe-delimited validation rule string, which is then split and each token invoked as a dynamic PHP function with no allowlist check. This makes it possible for unauthenticated attackers to execute code on the server. This is exploitable by unauthenticated attackers because WordPress core executes the route argument's validate_callback inside WP_REST_Server::dispatch() before the route's permission_callback is invoked, meaning the Project_Manage_Capability authorization gate is never reached on the vulnerable code path.

- [https://github.com/Mushr00w/CVE-2026-116512](https://github.com/Mushr00w/CVE-2026-116512) :  ![starts](https://img.shields.io/github/stars/Mushr00w/CVE-2026-116512.svg) ![forks](https://img.shields.io/github/forks/Mushr00w/CVE-2026-116512.svg)


## CVE-2026-115290
 Uncontrolled Recursion (CWE-674) in Elasticsearch can lead to denial of service via Serialized Data with Nested Payloads (CAPEC-230). An unauthenticated attacker with network access to the remote cluster server interface of a node can send a specially crafted request that causes the node to terminate. No credentials are required. The attacker can repeat the request against each reachable node.

- [https://github.com/googlesky/CVE-2026-115290](https://github.com/googlesky/CVE-2026-115290) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-115290.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-115290.svg)


## CVE-2026-114550
The specific flaw exists within the handling of PUBACK packets. The issue results from the lack of proper validation of user-supplied data, which can result in a write past the end of an allocated buffer. An attacker can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-31039.

- [https://github.com/googlesky/CVE-2026-114550](https://github.com/googlesky/CVE-2026-114550) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-114550.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-114550.svg)


## CVE-2026-112688
 A memory corruption issue was addressed with improved memory handling. This issue is fixed in iOS 26.7 and iPadOS 26.7, iOS 27.2 and iPadOS 27.2, macOS Golden Gate 27.2, macOS Sequoia 15.8.2, macOS Tahoe 26.7.2. Parsing a file may lead to an unexpected app termination or arbitrary code execution.

- [https://github.com/xcbjkymz/cve-2026-112688-oobw](https://github.com/xcbjkymz/cve-2026-112688-oobw) :  ![starts](https://img.shields.io/github/stars/xcbjkymz/cve-2026-112688-oobw.svg) ![forks](https://img.shields.io/github/forks/xcbjkymz/cve-2026-112688-oobw.svg)


## CVE-2026-111943
 On most platforms, Go uses the given system root certificates. However, in some narrower cases, the system trust stores may not be updated without further action. To defend against the narrower set of cases that may remain affected, a denylist was added in crypto/x509 to return an error when calling Verify with any of the known intermediate certificates that are no longer considered to be trustworthy.

- [https://github.com/sam00/CVE-2026-111943-Emudhra-Ca-Compromise-POC](https://github.com/sam00/CVE-2026-111943-Emudhra-Ca-Compromise-POC) :  ![starts](https://img.shields.io/github/stars/sam00/CVE-2026-111943-Emudhra-Ca-Compromise-POC.svg) ![forks](https://img.shields.io/github/forks/sam00/CVE-2026-111943-Emudhra-Ca-Compromise-POC.svg)


## CVE-2026-111770
 The Model Context Protocol TypeScript SDK provides TypeScript client and server implementations of the Model Context Protocol. From 2.0.0 until 2.3.0 in @modelcontextprotocol/server, applications that shared one stateless HTTP transport or one McpServer or Server instance among multiple clients could deliver responses and notifications to the wrong client. The affected surface is an MCP server reached over HTTP by multiple clients. The trigger is reuse of one stateless transport or server instance. Messages were associated with a connection using only the JSON-RPC request identifier. SDK clients start request identifiers at zero, so collisions occur in normal operation. Cross-client delivery exposes one client's responses and notifications to another client. The issue requires an HTTP endpoint reachable by more than one client and an application that constructs the server or transport once at startup instead of once per request or session. stdio servers and factory-created per-call servers are not affected. Upgrading causes reused instances to fail and therefore requires an application code change. This issue is fixed in @modelcontextprotocol/server 2.3.0.

- [https://github.com/hahahahahahahahah6/mcp-idprobe](https://github.com/hahahahahahahahah6/mcp-idprobe) :  ![starts](https://img.shields.io/github/stars/hahahahahahahahah6/mcp-idprobe.svg) ![forks](https://img.shields.io/github/forks/hahahahahahahahah6/mcp-idprobe.svg)


## CVE-2026-111560
 Improper neutralization of shell metacharacters in the timezone configuration field in certain Barracuda appliance products using common Barracuda code allows an authenticated administrator to inject OS commands that execute with root privileges when the crafted timezone value is subsequently processed.

- [https://github.com/watchtowrlabs/watchTowr-vs-Barracuda-RCE-CVE-2026-116606-CVE-2026-111560](https://github.com/watchtowrlabs/watchTowr-vs-Barracuda-RCE-CVE-2026-116606-CVE-2026-111560) :  ![starts](https://img.shields.io/github/stars/watchtowrlabs/watchTowr-vs-Barracuda-RCE-CVE-2026-116606-CVE-2026-111560.svg) ![forks](https://img.shields.io/github/forks/watchtowrlabs/watchTowr-vs-Barracuda-RCE-CVE-2026-116606-CVE-2026-111560.svg)


## CVE-2026-109619
 PHP has various global state that temporarily points into request memory. In some scenarios, global state may not be correctly reset, or may be repopulated after being reset. The global state may then refer to request memory even after it has been freed. Subsequent requests may read or branch on this stale state before it is fully initialized. Multiple strategies can trigger this condition and produce remote code execution (RCE).

- [https://github.com/naravid19/php2shell-ioc](https://github.com/naravid19/php2shell-ioc) :  ![starts](https://img.shields.io/github/stars/naravid19/php2shell-ioc.svg) ![forks](https://img.shields.io/github/forks/naravid19/php2shell-ioc.svg)
- [https://github.com/leonewt0n/php2shell-poc](https://github.com/leonewt0n/php2shell-poc) :  ![starts](https://img.shields.io/github/stars/leonewt0n/php2shell-poc.svg) ![forks](https://img.shields.io/github/forks/leonewt0n/php2shell-poc.svg)
- [https://github.com/Liam-G/php2shell-audit](https://github.com/Liam-G/php2shell-audit) :  ![starts](https://img.shields.io/github/stars/Liam-G/php2shell-audit.svg) ![forks](https://img.shields.io/github/forks/Liam-G/php2shell-audit.svg)


## CVE-2026-109618
 PHP uses longjmp() for out-of-memory (OOM) errors to exit the current context and abort handling of the request. Some contexts may not properly account for this scenario and leave request memory in an uninitialized state before performing an allocation. The subsequent request cleanup procedure may read or branch on this memory. Multiple OOM strategies can consistently trigger this condition and lead to remote code execution (RCE).

- [https://github.com/open0x01/php2shell](https://github.com/open0x01/php2shell) :  ![starts](https://img.shields.io/github/stars/open0x01/php2shell.svg) ![forks](https://img.shields.io/github/forks/open0x01/php2shell.svg)


## CVE-2026-109518
The vulnerability is caused by the reuse of hard links and requires the client to follow redirects and retry the download of package files. It requires the client to have a non-zero Acquire::Retries configuration setting; the value 3 is the default starting with Debian 12 (bookworm) and Ubuntu 22.04 LTS (Jammy Jellyfish), so older releases are unaffected in a default configuration

- [https://github.com/jordanhardee/cve-2026-109518-apt-patch-proxmox-and-generic](https://github.com/jordanhardee/cve-2026-109518-apt-patch-proxmox-and-generic) :  ![starts](https://img.shields.io/github/stars/jordanhardee/cve-2026-109518-apt-patch-proxmox-and-generic.svg) ![forks](https://img.shields.io/github/forks/jordanhardee/cve-2026-109518-apt-patch-proxmox-and-generic.svg)


## CVE-2026-107441
 An out-of-bounds write vulnerability in the CGI program of Zyxel GS1900-24E firmware versions through 2.90(AAHK.2)C0 could allow an unauthenticated adjacent attacker  to exploit the flaw and potentially execute OS commands via a crafted HTTP request.

- [https://github.com/foxcornlab/zyxel-gs1900-scanner](https://github.com/foxcornlab/zyxel-gs1900-scanner) :  ![starts](https://img.shields.io/github/stars/foxcornlab/zyxel-gs1900-scanner.svg) ![forks](https://img.shields.io/github/forks/foxcornlab/zyxel-gs1900-scanner.svg)


## CVE-2026-102334
 Nginx Proxy Manager through 2.16.0 lacks rate-limiting on authentication endpoints, allowing unauthenticated attackers to make unlimited password guesses against any account. Attackers can brute-force login credentials via POST /api/tokens and subsequently guess TOTP codes via POST /api/tokens/2fa to gain full session access and administrative control.

- [https://github.com/davidoberst/CVE-2026-102334-exploit](https://github.com/davidoberst/CVE-2026-102334-exploit) :  ![starts](https://img.shields.io/github/stars/davidoberst/CVE-2026-102334-exploit.svg) ![forks](https://img.shields.io/github/forks/davidoberst/CVE-2026-102334-exploit.svg)


## CVE-2026-98432
will be addressed in a separate patch.

- [https://github.com/mafudge/cve-2026-98432](https://github.com/mafudge/cve-2026-98432) :  ![starts](https://img.shields.io/github/stars/mafudge/cve-2026-98432.svg) ![forks](https://img.shields.io/github/forks/mafudge/cve-2026-98432.svg)
- [https://github.com/INFOKOM-KI/CVE-2026-98432-Wazuh-](https://github.com/INFOKOM-KI/CVE-2026-98432-Wazuh-) :  ![starts](https://img.shields.io/github/stars/INFOKOM-KI/CVE-2026-98432-Wazuh-.svg) ![forks](https://img.shields.io/github/forks/INFOKOM-KI/CVE-2026-98432-Wazuh-.svg)
- [https://github.com/dolistblesson/CVE-2026-98432-update](https://github.com/dolistblesson/CVE-2026-98432-update) :  ![starts](https://img.shields.io/github/stars/dolistblesson/CVE-2026-98432-update.svg) ![forks](https://img.shields.io/github/forks/dolistblesson/CVE-2026-98432-update.svg)
- [https://github.com/datacenter-metrotel/Mitigating-CVE-2026-98432](https://github.com/datacenter-metrotel/Mitigating-CVE-2026-98432) :  ![starts](https://img.shields.io/github/stars/datacenter-metrotel/Mitigating-CVE-2026-98432.svg) ![forks](https://img.shields.io/github/forks/datacenter-metrotel/Mitigating-CVE-2026-98432.svg)
- [https://github.com/carlosbustillordguez/cve-2026-98432-mitigation](https://github.com/carlosbustillordguez/cve-2026-98432-mitigation) :  ![starts](https://img.shields.io/github/stars/carlosbustillordguez/cve-2026-98432-mitigation.svg) ![forks](https://img.shields.io/github/forks/carlosbustillordguez/cve-2026-98432-mitigation.svg)
- [https://github.com/sv3t0sl4v/CVE-2026-98432-Ubuntu-Temporary-Mitigation](https://github.com/sv3t0sl4v/CVE-2026-98432-Ubuntu-Temporary-Mitigation) :  ![starts](https://img.shields.io/github/stars/sv3t0sl4v/CVE-2026-98432-Ubuntu-Temporary-Mitigation.svg) ![forks](https://img.shields.io/github/forks/sv3t0sl4v/CVE-2026-98432-Ubuntu-Temporary-Mitigation.svg)
- [https://github.com/keithel/ubuntu-26.04-kernel-cve-2026-98432-patch-build-docker](https://github.com/keithel/ubuntu-26.04-kernel-cve-2026-98432-patch-build-docker) :  ![starts](https://img.shields.io/github/stars/keithel/ubuntu-26.04-kernel-cve-2026-98432-patch-build-docker.svg) ![forks](https://img.shields.io/github/forks/keithel/ubuntu-26.04-kernel-cve-2026-98432-patch-build-docker.svg)


## CVE-2026-98260
[ tglx: Move the cleanup right after de_thread() ]

- [https://github.com/starriv/CVE-2026-98260-Xiaomi-17-Pro-Max](https://github.com/starriv/CVE-2026-98260-Xiaomi-17-Pro-Max) :  ![starts](https://img.shields.io/github/stars/starriv/CVE-2026-98260-Xiaomi-17-Pro-Max.svg) ![forks](https://img.shields.io/github/forks/starriv/CVE-2026-98260-Xiaomi-17-Pro-Max.svg)
- [https://github.com/Yukaneko520/RootMyZ9Turbo](https://github.com/Yukaneko520/RootMyZ9Turbo) :  ![starts](https://img.shields.io/github/stars/Yukaneko520/RootMyZ9Turbo.svg) ![forks](https://img.shields.io/github/forks/Yukaneko520/RootMyZ9Turbo.svg)
- [https://github.com/al123xiaaaa/CVE-2026-98260-GT7Pro-RMX5010](https://github.com/al123xiaaaa/CVE-2026-98260-GT7Pro-RMX5010) :  ![starts](https://img.shields.io/github/stars/al123xiaaaa/CVE-2026-98260-GT7Pro-RMX5010.svg) ![forks](https://img.shields.io/github/forks/al123xiaaaa/CVE-2026-98260-GT7Pro-RMX5010.svg)
- [https://github.com/whooslizi/infinitycore-x200pro](https://github.com/whooslizi/infinitycore-x200pro) :  ![starts](https://img.shields.io/github/stars/whooslizi/infinitycore-x200pro.svg) ![forks](https://img.shields.io/github/forks/whooslizi/infinitycore-x200pro.svg)


## CVE-2026-91403
 Vulnerability in the Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component: JSSE).  Supported versions that are affected are Oracle Java SE: 8u511, 8u511-perf, 11.0.33, 17.0.21, 21.0.13, 25.0.5, 27.0.1; Oracle GraalVM for JDK: 17.0.21 and  21.0.13; Oracle GraalVM Enterprise Edition: 21.3.20. Easily exploitable vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition.  Successful attacks of this vulnerability can result in  unauthorized creation, deletion or modification access to critical data or all Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition accessible data as well as  unauthorized access to critical data or complete access to all Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition accessible data. Note: This vulnerability can be exploited by using APIs in the specified Component, e.g., through a web service which supplies data to the APIs. This vulnerability also applies to Java deployments, typically in clients running sandboxed Java Web Start applications or sandboxed Java applets, that load and run untrusted code (e.g., code that comes from the internet) and rely on the Java sandbox for security. CVSS 3.1 Base Score 9.1 (Confidentiality and Integrity impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N).

- [https://github.com/bryanHsiao/domino-emudhra-cert-mitigation](https://github.com/bryanHsiao/domino-emudhra-cert-mitigation) :  ![starts](https://img.shields.io/github/stars/bryanHsiao/domino-emudhra-cert-mitigation.svg) ![forks](https://img.shields.io/github/forks/bryanHsiao/domino-emudhra-cert-mitigation.svg)


## CVE-2026-88771
This issue affects ADC: before 14.1-73.37, before 13.1-64.23, before 14.1-73.37 FIPS, and before 13.1.37.279 FIPS and NDcPP; Gateway: before 14.1-73.37 and before 13.1-64.23 leading to an unauthenticated attacker to execute arbitrary commands.

- [https://github.com/irfanr-source/Get-NetScalerTimeline](https://github.com/irfanr-source/Get-NetScalerTimeline) :  ![starts](https://img.shields.io/github/stars/irfanr-source/Get-NetScalerTimeline.svg) ![forks](https://img.shields.io/github/forks/irfanr-source/Get-NetScalerTimeline.svg)


## CVE-2026-87008
 Code Graph RAG is an AI-powered knowledge graph and retrieval system for querying, understanding, and editing multi-language codebases. Prior to 0.0.589, AstGrepService in codebase_rag/tools/ast_grep_service.py enumerates files beneath project_root and relies on should_skip_path in codebase_rag/utils/path_utils.py to classify them, but the containment check operates on unresolved lexical paths. A symbolic link planted inside an analyzed repository can therefore reference a file outside the configured root while still appearing in scope. The structural_search tool follows the link and discloses readable content without an approval gate, while structural_replace with dry_run=False follows it and overwrites writable content; the MCP path invokes structural replacement without the agent-loop approval control. An attacker who causes a victim to analyze a repository containing such a link can read credentials, keys, environment files, or sibling source and can modify files accessible to the code-graph-rag process. This issue is fixed in version 0.0.589.

- [https://github.com/squeeze440/code-graph-rag-PoC](https://github.com/squeeze440/code-graph-rag-PoC) :  ![starts](https://img.shields.io/github/stars/squeeze440/code-graph-rag-PoC.svg) ![forks](https://img.shields.io/github/forks/squeeze440/code-graph-rag-PoC.svg)


## CVE-2026-77622
 Sliver is a command and control framework. Prior to 1.7.6, an HTTP(S) listener using the PNG encoder accepts attacker-controlled PNG dimensions without an effective decoded-size or pixel limit in util/encoders/images.go, while the listener nonce space implemented in server/encoders/encoders.go is small enough to search remotely. An unauthenticated attacker who identifies a valid nonce can submit a highly compressed image to PNGEncoder.Decode, where it expands during png.Decode, exhausting server memory and causing a complete loss of availability. This vulnerability is fixed in 1.7.6.

- [https://github.com/Squ1shification/PNGboomer-CVE-2026-77622](https://github.com/Squ1shification/PNGboomer-CVE-2026-77622) :  ![starts](https://img.shields.io/github/stars/Squ1shification/PNGboomer-CVE-2026-77622.svg) ![forks](https://img.shields.io/github/forks/Squ1shification/PNGboomer-CVE-2026-77622.svg)


## CVE-2026-76142
 Insufficient authentication and access control on the internal-only IPC SOAP endpoint of the Genian NAC/ZTNA policy server allows an unauthenticated attacker to invoke internal functions

- [https://github.com/MalHyuk/CVE-2026-76142](https://github.com/MalHyuk/CVE-2026-76142) :  ![starts](https://img.shields.io/github/stars/MalHyuk/CVE-2026-76142.svg) ![forks](https://img.shields.io/github/forks/MalHyuk/CVE-2026-76142.svg)


## CVE-2026-69137
 SuiteCRM is an open-source, enterprise-ready Customer Relationship Management (CRM) software application. Prior to 7.15.2 and 8.10.2, the CalendarAccount testConnection action passes an authenticated caller's server_url directly to curl without host, address, or scheme validation. The affected flow begins at CalendarAccount::action_testConnection and uses server_url, CalDAVProvider::makeCalDAVRequest(), and PROPFIND to carry attacker-controlled data or authorization state into the security-sensitive operation. The server sends a PROPFIND request from its network context and returns non-success response bodies, enabling internal-service access, partial response disclosure, service enumeration, and possible cloud metadata access. This issue is fixed in versions 7.15.2 and 8.10.2.

- [https://github.com/EntroVyx/CVE-2026-69137](https://github.com/EntroVyx/CVE-2026-69137) :  ![starts](https://img.shields.io/github/stars/EntroVyx/CVE-2026-69137.svg) ![forks](https://img.shields.io/github/forks/EntroVyx/CVE-2026-69137.svg)


## CVE-2026-63030
 WordPress 6.9.x before 6.9.5 and 7.0.x before 7.0.2 is affected by a REST API batch endpoint route confusion issue which, combined with the author__not_in WP_Query SQL Injection (CVE-2026-60137), could allow an attacker to perform SQL Injection and achieve Remote Code Execution.

- [https://github.com/CptNope/JAT-Shell-Scanner](https://github.com/CptNope/JAT-Shell-Scanner) :  ![starts](https://img.shields.io/github/stars/CptNope/JAT-Shell-Scanner.svg) ![forks](https://img.shields.io/github/forks/CptNope/JAT-Shell-Scanner.svg)


## CVE-2026-58868
 In onOutputReceived of FrameDecoder.cpp, there is a possible out-of-bounds write due to a heap buffer overflow. This could lead to remote code execution with no additional execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/probear0001/CVE-2026-58868](https://github.com/probear0001/CVE-2026-58868) :  ![starts](https://img.shields.io/github/stars/probear0001/CVE-2026-58868.svg) ![forks](https://img.shields.io/github/forks/probear0001/CVE-2026-58868.svg)
- [https://github.com/redfishrouge/CVE-2026-58868-PoC](https://github.com/redfishrouge/CVE-2026-58868-PoC) :  ![starts](https://img.shields.io/github/stars/redfishrouge/CVE-2026-58868-PoC.svg) ![forks](https://img.shields.io/github/forks/redfishrouge/CVE-2026-58868-PoC.svg)


## CVE-2026-43499
  	changelog ]

- [https://github.com/deancyl/s9180-rootmygalaxy](https://github.com/deancyl/s9180-rootmygalaxy) :  ![starts](https://img.shields.io/github/stars/deancyl/s9180-rootmygalaxy.svg) ![forks](https://img.shields.io/github/forks/deancyl/s9180-rootmygalaxy.svg)


## CVE-2026-39338
 ChurchCRM is an open-source church management system. Prior to 7.1.0, a Blind Reflected Cross-Site Scripting vulnerability exists in the search parameter accepted by the ChurchCRM dashboard. The application fails to sanitize or encode user-supplied input prior to rendering it within the browser's DOM. Although the application ultimately returns an HTTP 500 error due to the malformed API request caused by the payload, the browser's JavaScript engine parses and executes the injected script tags before the error response is returned — resulting in successful code execution regardless of the server-side error. This vulnerability is fixed in 7.1.0.

- [https://github.com/HackinKraken/Security-Research-and-CVE](https://github.com/HackinKraken/Security-Research-and-CVE) :  ![starts](https://img.shields.io/github/stars/HackinKraken/Security-Research-and-CVE.svg) ![forks](https://img.shields.io/github/forks/HackinKraken/Security-Research-and-CVE.svg)


## CVE-2026-34157
 Wails is a framework for building desktop applications using Go and web technologies. From 2.0.0 until 2.13.0, BindingsAllowedOrigins in v2/internal/frontend/originvalidator/originValidator.go passes wildcard patterns to wildcardPatternToRegex, which expands every asterisk to an unrestricted regular-expression match. When an application configures a trailing or partial-label wildcard immediately after an allowed domain, an attacker-controlled lookalike origin can match the allowed suffix and invoke bound Go methods through IPC. A complete-component subdomain wildcard is an unaffected configuration. The resulting confidentiality, integrity, and availability impact depends on the file, database, command, credential, or other operations exposed by the application's bound methods. This issue is fixed in version 2.13.0.

- [https://github.com/Saku0512/CVE-2026-34157-poc](https://github.com/Saku0512/CVE-2026-34157-poc) :  ![starts](https://img.shields.io/github/stars/Saku0512/CVE-2026-34157-poc.svg) ![forks](https://img.shields.io/github/forks/Saku0512/CVE-2026-34157-poc.svg)


## CVE-2026-18470
 The Login & Register Forms  WordPress plugin before 4.0.2 does not verify that a password reset request comes from the account's owner, and does not adequately redact the address returned in its response, allowing unauthenticated users to obtain registered users' email addresses, including administrators'.

- [https://github.com/0xg33k/CVE-2026-18470](https://github.com/0xg33k/CVE-2026-18470) :  ![starts](https://img.shields.io/github/stars/0xg33k/CVE-2026-18470.svg) ![forks](https://img.shields.io/github/forks/0xg33k/CVE-2026-18470.svg)


## CVE-2026-10961
 Use after free in Chrome for iOS in Google Chrome on iOS prior to 149.0.7827.53 allowed a remote attacker who had compromised the renderer process to potentially perform a sandbox escape via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/definitiveref/php2shell-CVE-2026-109618-109619-Research](https://github.com/definitiveref/php2shell-CVE-2026-109618-109619-Research) :  ![starts](https://img.shields.io/github/stars/definitiveref/php2shell-CVE-2026-109618-109619-Research.svg) ![forks](https://img.shields.io/github/forks/definitiveref/php2shell-CVE-2026-109618-109619-Research.svg)
- [https://github.com/sam00/CVE-2026-109618-CVE-2026-109619-POC](https://github.com/sam00/CVE-2026-109618-CVE-2026-109619-POC) :  ![starts](https://img.shields.io/github/stars/sam00/CVE-2026-109618-CVE-2026-109619-POC.svg) ![forks](https://img.shields.io/github/forks/sam00/CVE-2026-109618-CVE-2026-109619-POC.svg)


## CVE-2026-1096
 The Best-wp-google-map plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the 'latitude' and 'longitudinal' parameters of the 'google_map_view' shortcode in all versions up to, and including, 2.1 due to insufficient input sanitization and output escaping. This makes it possible for authenticated attackers, with Contributor-level access and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.

- [https://github.com/WKL-Sec/CVE-2026-109618](https://github.com/WKL-Sec/CVE-2026-109618) :  ![starts](https://img.shields.io/github/stars/WKL-Sec/CVE-2026-109618.svg) ![forks](https://img.shields.io/github/forks/WKL-Sec/CVE-2026-109618.svg)
- [https://github.com/1Nightlovel/CVE-2026-109618](https://github.com/1Nightlovel/CVE-2026-109618) :  ![starts](https://img.shields.io/github/stars/1Nightlovel/CVE-2026-109618.svg) ![forks](https://img.shields.io/github/forks/1Nightlovel/CVE-2026-109618.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm.svg)


## CVE-2025-50579
 A CORS misconfiguration in Nginx Proxy Manager v2.12.3 allows unauthorized domains to access sensitive data, particularly JWT tokens, due to improper validation of the Origin header. This misconfiguration enables attackers to intercept tokens using a simple browser script and exfiltrate them to a remote attacker-controlled server, potentially leading to unauthorized actions within the application.

- [https://github.com/davidoberst/CVE-2025-50579-CORS-Misconfiguration-Exploit](https://github.com/davidoberst/CVE-2025-50579-CORS-Misconfiguration-Exploit) :  ![starts](https://img.shields.io/github/stars/davidoberst/CVE-2025-50579-CORS-Misconfiguration-Exploit.svg) ![forks](https://img.shields.io/github/forks/davidoberst/CVE-2025-50579-CORS-Misconfiguration-Exploit.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/ticofookfook/poc-nextjs-CVE-2025-29927](https://github.com/ticofookfook/poc-nextjs-CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/ticofookfook/poc-nextjs-CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/ticofookfook/poc-nextjs-CVE-2025-29927.svg)


## CVE-2025-6647
The specific flaw exists within the parsing of U3D files. The issue results from the lack of proper validation of user-supplied data, which can result in a write past the end of an allocated object. An attacker can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-26644.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo.svg)


## CVE-2025-2992
 A vulnerability classified as critical was found in Tenda FH1202 1.2.0.14(408). Affected by this vulnerability is an unknown functionality of the file /goform/AdvSetWrlsafeset of the component Web Management Interface. The manipulation leads to improper access controls. The attack can be launched remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/amitlttwo/Next.JS-CVE-2025-29927](https://github.com/amitlttwo/Next.JS-CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/amitlttwo/Next.JS-CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/amitlttwo/Next.JS-CVE-2025-29927.svg)


## CVE-2024-26229
 Windows CSC Service Elevation of Privilege Vulnerability

- [https://github.com/stillbigjosh/cve-2024-26229-bof](https://github.com/stillbigjosh/cve-2024-26229-bof) :  ![starts](https://img.shields.io/github/stars/stillbigjosh/cve-2024-26229-bof.svg) ![forks](https://img.shields.io/github/forks/stillbigjosh/cve-2024-26229-bof.svg)


## CVE-2023-46071
 Unauth. Reflected Cross-Site Scripting (XSS) vulnerability in ClickDatos Protección de Datos RGPD plugin = 3.1.0 versions.

- [https://github.com/raycoarana/rgpd-cookie-legal](https://github.com/raycoarana/rgpd-cookie-legal) :  ![starts](https://img.shields.io/github/stars/raycoarana/rgpd-cookie-legal.svg) ![forks](https://img.shields.io/github/forks/raycoarana/rgpd-cookie-legal.svg)


## CVE-2022-46364
 A SSRF vulnerability in parsing the href attribute of XOP:Include in MTOM requests in versions of Apache CXF before 3.5.5 and 3.4.10 allows an attacker to perform SSRF style attacks on webservices that take at least one parameter of any type. 

- [https://github.com/0xmid00/CVE-2022-46364-poc](https://github.com/0xmid00/CVE-2022-46364-poc) :  ![starts](https://img.shields.io/github/stars/0xmid00/CVE-2022-46364-poc.svg) ![forks](https://img.shields.io/github/forks/0xmid00/CVE-2022-46364-poc.svg)


## CVE-2022-38181
 The Arm Mali GPU kernel driver allows unprivileged users to access freed memory because GPU memory operations are mishandled. This affects Bifrost r0p0 through r38p1, and r39p0; Valhall r19p0 through r38p1, and r39p0; and Midgard r4p0 through r32p0.

- [https://github.com/lRENyaaa/AGM3-W09HN-TempRoot](https://github.com/lRENyaaa/AGM3-W09HN-TempRoot) :  ![starts](https://img.shields.io/github/stars/lRENyaaa/AGM3-W09HN-TempRoot.svg) ![forks](https://img.shields.io/github/forks/lRENyaaa/AGM3-W09HN-TempRoot.svg)


## CVE-2022-2650
 Improper Restriction of Excessive Authentication Attempts in GitHub repository wger-project/wger prior to 2.2.

- [https://github.com/HackinKraken/Security-Research-and-CVE](https://github.com/HackinKraken/Security-Research-and-CVE) :  ![starts](https://img.shields.io/github/stars/HackinKraken/Security-Research-and-CVE.svg) ![forks](https://img.shields.io/github/forks/HackinKraken/Security-Research-and-CVE.svg)


## CVE-2022-0847
 A flaw was found in the way the "flags" member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/Greetdawn/CVE-2022-0847-DirtyPipe](https://github.com/Greetdawn/CVE-2022-0847-DirtyPipe) :  ![starts](https://img.shields.io/github/stars/Greetdawn/CVE-2022-0847-DirtyPipe.svg) ![forks](https://img.shields.io/github/forks/Greetdawn/CVE-2022-0847-DirtyPipe.svg)
- [https://github.com/MingqiZhang7710/cve-2022-0847-poc-dockerimage](https://github.com/MingqiZhang7710/cve-2022-0847-poc-dockerimage) :  ![starts](https://img.shields.io/github/stars/MingqiZhang7710/cve-2022-0847-poc-dockerimage.svg) ![forks](https://img.shields.io/github/forks/MingqiZhang7710/cve-2022-0847-poc-dockerimage.svg)


## CVE-2021-36260
 A command injection vulnerability in the web server of some Hikvision product. Due to the insufficient input validation, attacker can exploit the vulnerability to launch a command injection attack by sending some messages with malicious commands.

- [https://github.com/foxnaim/Ingram](https://github.com/foxnaim/Ingram) :  ![starts](https://img.shields.io/github/stars/foxnaim/Ingram.svg) ![forks](https://img.shields.io/github/forks/foxnaim/Ingram.svg)


## CVE-2021-33044
 The identity authentication bypass vulnerability found in some Dahua products during the login process. Attackers can bypass device identity authentication by constructing malicious data packets.

- [https://github.com/foxnaim/Ingram](https://github.com/foxnaim/Ingram) :  ![starts](https://img.shields.io/github/stars/foxnaim/Ingram.svg) ![forks](https://img.shields.io/github/forks/foxnaim/Ingram.svg)


## CVE-2021-4422
 The POST SMTP Mailer plugin for WordPress is vulnerable to Cross-Site Request Forgery in versions up to, and including, 2.0.20. This is due to missing or incorrect nonce validation on the handleCsvExport() function. This makes it possible for unauthenticated attackers to trigger a CSV export via a forged request granted they can trick a site administrator into performing an action such as clicking on a link.

- [https://github.com/asd58584388/CVE-2021-44228](https://github.com/asd58584388/CVE-2021-44228) :  ![starts](https://img.shields.io/github/stars/asd58584388/CVE-2021-44228.svg) ![forks](https://img.shields.io/github/forks/asd58584388/CVE-2021-44228.svg)


## CVE-2020-25078
 An issue was discovered on D-Link DCS-2530L before 1.06.01 Hotfix and DCS-2670L through 2.02 devices. The unauthenticated /config/getuser endpoint allows for remote administrator password disclosure.

- [https://github.com/foxnaim/Ingram](https://github.com/foxnaim/Ingram) :  ![starts](https://img.shields.io/github/stars/foxnaim/Ingram.svg) ![forks](https://img.shields.io/github/forks/foxnaim/Ingram.svg)


## CVE-2020-1350
 A remote code execution vulnerability exists in Windows Domain Name System servers when they fail to properly handle requests, aka 'Windows DNS Server Remote Code Execution Vulnerability'.

- [https://github.com/Sheisback/CVE-2020-1350-Exploit](https://github.com/Sheisback/CVE-2020-1350-Exploit) :  ![starts](https://img.shields.io/github/stars/Sheisback/CVE-2020-1350-Exploit.svg) ![forks](https://img.shields.io/github/forks/Sheisback/CVE-2020-1350-Exploit.svg)


## CVE-2017-7921
 An Improper Authentication issue was discovered in Hikvision DS-2CD2xx2F-I Series V5.2.0 build 140721 to V5.4.0 build 160530, DS-2CD2xx0F-I Series V5.2.0 build 140721 to V5.4.0 Build 160401, DS-2CD2xx2FWD Series V5.3.1 build 150410 to V5.4.4 Build 161125, DS-2CD4x2xFWD Series V5.2.0 build 140721 to V5.4.0 Build 160414, DS-2CD4xx5 Series V5.2.0 build 140721 to V5.4.0 Build 160421, DS-2DFx Series V5.2.0 build 140805 to V5.4.5 Build 160928, and DS-2CD63xx Series V5.0.9 build 140305 to V5.3.5 Build 160106 devices. The improper authentication vulnerability occurs when an application does not adequately or correctly authenticate users. This may allow a malicious user to escalate his or her privileges on the system and gain access to sensitive information.

- [https://github.com/foxnaim/Ingram](https://github.com/foxnaim/Ingram) :  ![starts](https://img.shields.io/github/stars/foxnaim/Ingram.svg) ![forks](https://img.shields.io/github/forks/foxnaim/Ingram.svg)

