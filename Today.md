# Update 2026-08-06
## CVE-2026-70481
 Open WebUI is an extensible, feature-rich, and user-friendly self-hosted AI platform. From 0.5.0 until 0.11.0, the standard channel message update and delete handlers accepted any caller holding write access on the channel without checking that the caller wrote the message. Because write access is the same grant a member needs to post, any ordinary participant in a shared standard channel could rewrite or permanently delete another participant message, while group and direct message handlers enforced authorship. This issue is fixed in 0.11.0.

- [https://github.com/Foxer131/CVE-2026-70481](https://github.com/Foxer131/CVE-2026-70481) :  ![starts](https://img.shields.io/github/stars/Foxer131/CVE-2026-70481.svg) ![forks](https://img.shields.io/github/forks/Foxer131/CVE-2026-70481.svg)


## CVE-2026-69243
 AIOHTTP is an asynchronous HTTP client/server framework for asyncio and Python. Prior to 3.14.2, the HTTP parsers were vulnerable to a request smuggling attack relating to WebSocket upgrades. If using the server-side component, an attacker may be able to execute a request smuggling vulnerability using an edge case in the WebSocket upgrade procedure. A WebSocket upgrade request with a body could cause the parser to switch protocols before the complete request body was received, leaving trailing bytes to be handled as upgraded-protocol or pipelined data rather than normal HTTP body data. This issue is fixed in version 3.14.2.

- [https://github.com/JVBotelho/cve-2026-69243-poc-aiohttp-smuggling](https://github.com/JVBotelho/cve-2026-69243-poc-aiohttp-smuggling) :  ![starts](https://img.shields.io/github/stars/JVBotelho/cve-2026-69243-poc-aiohttp-smuggling.svg) ![forks](https://img.shields.io/github/forks/JVBotelho/cve-2026-69243-poc-aiohttp-smuggling.svg)


## CVE-2026-67340
 ArcadeDB before 26.7.2 (arcadedb-engine) allows trigger scripts to look up host classes in java.lang.* (via Java.type) because ScriptTriggerExecutor adds java.lang.* to the allowed packages. An authenticated user with UPDATE_SCHEMA permission can create a JavaScript trigger that invokes java.lang.Runtime.getRuntime().exec() (or ProcessBuilder), achieving OS command execution when the trigger fires.

- [https://github.com/0xdak/CVE-2026-67340_exploit](https://github.com/0xdak/CVE-2026-67340_exploit) :  ![starts](https://img.shields.io/github/stars/0xdak/CVE-2026-67340_exploit.svg) ![forks](https://img.shields.io/github/forks/0xdak/CVE-2026-67340_exploit.svg)


## CVE-2026-66066
 Action Pack is a framework for handling and responding to web requests. In versions prior to 7.2.3.2, 8.0.5.1 and 8.1.3.1, Active Storage does not disable libvips operations marked unsafe for untrusted content, allowing a crafted upload to invoke such an operation. Consuming applications are affected when configured to use libvips and accept image uploads from untrusted users. An unauthenticated attacker may exploit this behavior to read arbitrary files accessible to the Rails process, including environment variables and application secrets. Exposure of credentials such as secret_key_base or external-service tokens may enable remote code execution or lateral movement. This issue has been fixed in versions 7.2.3.2, 8.0.5.1 and 8.1.3.1.

- [https://github.com/HackSpeak/CVE-2026-66066](https://github.com/HackSpeak/CVE-2026-66066) :  ![starts](https://img.shields.io/github/stars/HackSpeak/CVE-2026-66066.svg) ![forks](https://img.shields.io/github/forks/HackSpeak/CVE-2026-66066.svg)
- [https://github.com/shinthink/CVE-2026-66066](https://github.com/shinthink/CVE-2026-66066) :  ![starts](https://img.shields.io/github/stars/shinthink/CVE-2026-66066.svg) ![forks](https://img.shields.io/github/forks/shinthink/CVE-2026-66066.svg)


## CVE-2026-64531
ownership and truncates on close failure.

- [https://github.com/HackSpeak/CVE-2026-64531](https://github.com/HackSpeak/CVE-2026-64531) :  ![starts](https://img.shields.io/github/stars/HackSpeak/CVE-2026-64531.svg) ![forks](https://img.shields.io/github/forks/HackSpeak/CVE-2026-64531.svg)


## CVE-2026-63223
 CodeIgniter is a PHP full-stack web framework. Prior to 4.7.4, the is_image and mime_in upload validation rules do not independently enforce a safe client filename extension, allowing a remote attacker to upload executable content when an application preserves the client filename and stores uploads in a web-accessible script-enabled directory. Applications are impacted when they validate uploads using is_image or mime_in without an independent safe extension check (such as ext_in on patched versions), save uploaded files using the client-supplied filename, and place uploads in a web-accessible directory where PHP files can execute. This issue is fixed in version 4.7.4.

- [https://github.com/shinthink/CVE-2026-63223](https://github.com/shinthink/CVE-2026-63223) :  ![starts](https://img.shields.io/github/stars/shinthink/CVE-2026-63223.svg) ![forks](https://img.shields.io/github/forks/shinthink/CVE-2026-63223.svg)


## CVE-2026-63030
 WordPress 6.9.x before 6.9.5 and 7.0.x before 7.0.2 is affected by a REST API batch endpoint route confusion issue which, combined with the author__not_in WP_Query SQL Injection (CVE-2026-60137), could allow an attacker to perform SQL Injection and achieve Remote Code Execution.

- [https://github.com/johnlodan/wp2shell-rce](https://github.com/johnlodan/wp2shell-rce) :  ![starts](https://img.shields.io/github/stars/johnlodan/wp2shell-rce.svg) ![forks](https://img.shields.io/github/forks/johnlodan/wp2shell-rce.svg)
- [https://github.com/rechandra/wp2exp-2026](https://github.com/rechandra/wp2exp-2026) :  ![starts](https://img.shields.io/github/stars/rechandra/wp2exp-2026.svg) ![forks](https://img.shields.io/github/forks/rechandra/wp2exp-2026.svg)
- [https://github.com/x-znn/CVE-2026-63030](https://github.com/x-znn/CVE-2026-63030) :  ![starts](https://img.shields.io/github/stars/x-znn/CVE-2026-63030.svg) ![forks](https://img.shields.io/github/forks/x-znn/CVE-2026-63030.svg)


## CVE-2026-60137
 WordPress 6.8.x before 6.8.6, 6.9.x before 6.9.5, and 7.0.x before 7.0.2 does not properly sanitise the author__not_in parameter of WP_Query, which could allow SQL Injection when a plugin or theme passes untrusted input to the parameter.

- [https://github.com/johnlodan/wp2shell-rce](https://github.com/johnlodan/wp2shell-rce) :  ![starts](https://img.shields.io/github/stars/johnlodan/wp2shell-rce.svg) ![forks](https://img.shields.io/github/forks/johnlodan/wp2shell-rce.svg)
- [https://github.com/AbdullahMaqbool22/CVE-2026-60137-WordPress-Core-SQL-Injection-PoC](https://github.com/AbdullahMaqbool22/CVE-2026-60137-WordPress-Core-SQL-Injection-PoC) :  ![starts](https://img.shields.io/github/stars/AbdullahMaqbool22/CVE-2026-60137-WordPress-Core-SQL-Injection-PoC.svg) ![forks](https://img.shields.io/github/forks/AbdullahMaqbool22/CVE-2026-60137-WordPress-Core-SQL-Injection-PoC.svg)


## CVE-2026-59243
 The FAB auth manager's Azure AD OAuth login defaulted `verify_signature=False` when decoding the ID token, so an attacker able to present a forged or unsigned (`alg:none`) ID token to the OAuth callback could bypass authentication and log in as an arbitrary user, including one holding the Admin role (CWE-347). Deployments running the FAB auth manager with the Azure AD OAuth login path under its default configuration are affected; the Authentik path already defaulted to `True`. This issue affects `apache-airflow-providers-fab` before 3.7.3. Users are advised to upgrade to `apache-airflow-providers-fab` 3.7.3, which defaults `verify_signature=True`.

- [https://github.com/0xdak/CVE-2026-59243_exploit](https://github.com/0xdak/CVE-2026-59243_exploit) :  ![starts](https://img.shields.io/github/stars/0xdak/CVE-2026-59243_exploit.svg) ![forks](https://img.shields.io/github/forks/0xdak/CVE-2026-59243_exploit.svg)


## CVE-2026-54917
 SeaweedFS is a distributed storage system for object storage (S3), file systems, and Iceberg tables. Prior to 4.30, the S3 API gateway and the Iceberg REST catalog gateway construct their routers with mux.NewRouter().SkipClean(true). With path cleaning disabled, a .. segment inside the URL survives routing, so a request such as `GET /bucket-A/../evil-bucket/key`, is matched as bucket=bucket-A, object=../evil-bucket/key. The captured object key is then joined into a filer path with util.JoinPath (S3) / path.Join (Iceberg), which collapse the .. server-side, so the actual read or write lands in evil-bucket. This vulnerability is fixed in 4.30.

- [https://github.com/BiiTts/CVE-2026-54917-SeaweedFS-Cross-Bucket-Traversal](https://github.com/BiiTts/CVE-2026-54917-SeaweedFS-Cross-Bucket-Traversal) :  ![starts](https://img.shields.io/github/stars/BiiTts/CVE-2026-54917-SeaweedFS-Cross-Bucket-Traversal.svg) ![forks](https://img.shields.io/github/forks/BiiTts/CVE-2026-54917-SeaweedFS-Cross-Bucket-Traversal.svg)


## CVE-2026-52680
Users are recommended to upgrade to version 1.12.0, which fixes the issue.

- [https://github.com/0xdak/CVE-2026-52680_exploit](https://github.com/0xdak/CVE-2026-52680_exploit) :  ![starts](https://img.shields.io/github/stars/0xdak/CVE-2026-52680_exploit.svg) ![forks](https://img.shields.io/github/forks/0xdak/CVE-2026-52680_exploit.svg)


## CVE-2026-52370
 A reflected cross-site scripting (XSS) vulnerability in the Forum posting function of O2OA v10 allows attackers to execute arbitrary Javascript in the context of the victim's browser via a crafted URL.

- [https://github.com/RichardKabuto/CVE-2026-52370](https://github.com/RichardKabuto/CVE-2026-52370) :  ![starts](https://img.shields.io/github/stars/RichardKabuto/CVE-2026-52370.svg) ![forks](https://img.shields.io/github/forks/RichardKabuto/CVE-2026-52370.svg)


## CVE-2026-52102
 An OS command injection vulnerability in the openmediavault-md plugin of OpenMediaVault v8.0.4-1 allows attackers to execute arbitrary commands as root via injecting shell metacharacters.

- [https://github.com/showmeyourhands/CVE-2026-52102-PoC](https://github.com/showmeyourhands/CVE-2026-52102-PoC) :  ![starts](https://img.shields.io/github/stars/showmeyourhands/CVE-2026-52102-PoC.svg) ![forks](https://img.shields.io/github/forks/showmeyourhands/CVE-2026-52102-PoC.svg)


## CVE-2026-45033
 GitHub Copilot CLI brings AI-powered coding assistance directly to your command line. Prior to 1.0.43, a  security vulnerability has been identified in GitHub Copilot CLI where a malicious bare git repository nested inside a project directory can achieve arbitrary code execution when the agent performs git operations. By exploiting git's automatic bare repository discovery during directory traversal, an attacker can set core.fsmonitor or other executable config keys to run arbitrary commands without user awareness or approval. The vulnerability arises because git's core.fsmonitor config key (and 15+ similar keys such as core.hookspath, diff.external, merge.tool, etc.) can specify arbitrary shell commands that git will execute as part of normal operations like status, diff, or rev-parse. This vulnerability is fixed in 1.0.43.

- [https://github.com/grassplatypus/cve-2026-45033-class](https://github.com/grassplatypus/cve-2026-45033-class) :  ![starts](https://img.shields.io/github/stars/grassplatypus/cve-2026-45033-class.svg) ![forks](https://img.shields.io/github/forks/grassplatypus/cve-2026-45033-class.svg)


## CVE-2026-43499
  	changelog ]

- [https://github.com/taoubi1/ghostlock-sm-a155f](https://github.com/taoubi1/ghostlock-sm-a155f) :  ![starts](https://img.shields.io/github/stars/taoubi1/ghostlock-sm-a155f.svg) ![forks](https://img.shields.io/github/forks/taoubi1/ghostlock-sm-a155f.svg)
- [https://github.com/oopnv70-lab/ghostlock-honor-aak](https://github.com/oopnv70-lab/ghostlock-honor-aak) :  ![starts](https://img.shields.io/github/stars/oopnv70-lab/ghostlock-honor-aak.svg) ![forks](https://img.shields.io/github/forks/oopnv70-lab/ghostlock-honor-aak.svg)
- [https://github.com/eroorvbsyes-hotmail/CVE-2026-43499_x86_Exploit](https://github.com/eroorvbsyes-hotmail/CVE-2026-43499_x86_Exploit) :  ![starts](https://img.shields.io/github/stars/eroorvbsyes-hotmail/CVE-2026-43499_x86_Exploit.svg) ![forks](https://img.shields.io/github/forks/eroorvbsyes-hotmail/CVE-2026-43499_x86_Exploit.svg)


## CVE-2026-39363
 Vite is a frontend tooling framework for JavaScript. From 6.0.0 to before 6.4.2, 7.3.2, and 8.0.5, if it is possible to connect to the Vite dev server’s WebSocket without an Origin header, an attacker can invoke fetchModule via the custom WebSocket event vite:invoke and combine file://... with ?raw (or ?inline) to retrieve the contents of arbitrary files on the server as a JavaScript string (e.g., export default "..."). The access control enforced in the HTTP request path (such as server.fs.allow) is not applied to this WebSocket-based execution path. This vulnerability is fixed in 6.4.2, 7.3.2, and 8.0.5.

- [https://github.com/sunynov/CVE-2026-39363](https://github.com/sunynov/CVE-2026-39363) :  ![starts](https://img.shields.io/github/stars/sunynov/CVE-2026-39363.svg) ![forks](https://img.shields.io/github/forks/sunynov/CVE-2026-39363.svg)


## CVE-2026-26190
 Milvus is an open-source vector database built for generative AI applications. Prior to 2.5.27 and 2.6.10, Milvus exposes TCP port 9091 by default, which enables authentication bypasses. The /expr debug endpoint uses a weak, predictable default authentication token derived from etcd.rootPath (default: by-dev), enabling arbitrary expression evaluation. The full REST API (/api/v1/*) is registered on the metrics/management port without any authentication, allowing unauthenticated access to all business operations including data manipulation and credential management. This vulnerability is fixed in 2.5.27 and 2.6.10.

- [https://github.com/qianlijaingshan/milvus-auth-audit](https://github.com/qianlijaingshan/milvus-auth-audit) :  ![starts](https://img.shields.io/github/stars/qianlijaingshan/milvus-auth-audit.svg) ![forks](https://img.shields.io/github/forks/qianlijaingshan/milvus-auth-audit.svg)


## CVE-2026-24060
updates from the PLC can also be sniffed and reverse engineered.

- [https://github.com/spinfosecurity/BAS-Guardian](https://github.com/spinfosecurity/BAS-Guardian) :  ![starts](https://img.shields.io/github/stars/spinfosecurity/BAS-Guardian.svg) ![forks](https://img.shields.io/github/forks/spinfosecurity/BAS-Guardian.svg)


## CVE-2026-23479
 Redis is an in-memory data structure store. In redis-server from 7.2.0 until 8.6.3, the unblock client flow does not handle an error return from `processCommandAndResetClient` when re-executing a blocked command. If a blocked client is evicted during this flow, an authenticated attacker can trigger a use-after-free that may lead to remote code execution. This has been patched in version 8.6.3.

- [https://github.com/rizlmaulanaa/CVE-2026-23479-Redis-UAF-Proof-of-Concept](https://github.com/rizlmaulanaa/CVE-2026-23479-Redis-UAF-Proof-of-Concept) :  ![starts](https://img.shields.io/github/stars/rizlmaulanaa/CVE-2026-23479-Redis-UAF-Proof-of-Concept.svg) ![forks](https://img.shields.io/github/forks/rizlmaulanaa/CVE-2026-23479-Redis-UAF-Proof-of-Concept.svg)


## CVE-2026-22019
 Vulnerability in the PeopleSoft Enterprise HCM Shared Components product of Oracle PeopleSoft (component: Person Search).   The supported version that is affected is 9.2. Easily exploitable vulnerability allows low privileged attacker with network access via HTTP to compromise PeopleSoft Enterprise HCM Shared Components.  Successful attacks require human interaction from a person other than the attacker and while the vulnerability is in PeopleSoft Enterprise HCM Shared Components, attacks may significantly impact additional products (scope change). Successful attacks of this vulnerability can result in  unauthorized update, insert or delete access to some of PeopleSoft Enterprise HCM Shared Components accessible data as well as  unauthorized read access to a subset of PeopleSoft Enterprise HCM Shared Components accessible data. CVSS 3.1 Base Score 5.4 (Confidentiality and Integrity impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N).

- [https://github.com/George0Papasotiriou/CVE-2026-22019-libcurl-HTTP-2-CONNECT-Tunnel-Mixup](https://github.com/George0Papasotiriou/CVE-2026-22019-libcurl-HTTP-2-CONNECT-Tunnel-Mixup) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2026-22019-libcurl-HTTP-2-CONNECT-Tunnel-Mixup.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2026-22019-libcurl-HTTP-2-CONNECT-Tunnel-Mixup.svg)


## CVE-2026-22018
 Vulnerability in the Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component: Libraries).  Supported versions that are affected are Oracle Java SE: 8u481, 8u481-b50, 8u481-perf, 11.0.30, 17.0.18, 21.0.10, 25.0.2, 26; Oracle GraalVM for JDK: 17.0.18 and  21.0.10; Oracle GraalVM Enterprise Edition: 21.3.17. Difficult to exploit vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition.  Successful attacks of this vulnerability can result in unauthorized ability to cause a partial denial of service (partial DOS) of Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition. Note: This vulnerability can be exploited by using APIs in the specified Component, e.g., through a web service which supplies data to the APIs. This vulnerability also applies to Java deployments, typically in clients running sandboxed Java Web Start applications or sandboxed Java applets, that load and run untrusted code (e.g., code that comes from the internet) and rely on the Java sandbox for security. CVSS 3.1 Base Score 3.7 (Availability impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L).

- [https://github.com/George0Papasotiriou/CVE-2026-22018-Jenkins-Pipeline-Shared-Library-Code-Execution-via-Grab-](https://github.com/George0Papasotiriou/CVE-2026-22018-Jenkins-Pipeline-Shared-Library-Code-Execution-via-Grab-) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2026-22018-Jenkins-Pipeline-Shared-Library-Code-Execution-via-Grab-.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2026-22018-Jenkins-Pipeline-Shared-Library-Code-Execution-via-Grab-.svg)


## CVE-2026-22017
 Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Optimizer).  Supported versions that are affected are 8.0.0-8.0.45, 8.4.0-8.4.8 and  9.0.0-9.6.0. Easily exploitable vulnerability allows low privileged attacker with network access via multiple protocols to compromise MySQL Server.  Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of MySQL Server. CVSS 3.1 Base Score 6.5 (Availability impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H).

- [https://github.com/George0Papasotiriou/CVE-2026-22017-Firmware-Update-via-BLE-Without-Authentication](https://github.com/George0Papasotiriou/CVE-2026-22017-Firmware-Update-via-BLE-Without-Authentication) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2026-22017-Firmware-Update-via-BLE-Without-Authentication.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2026-22017-Firmware-Update-via-BLE-Without-Authentication.svg)


## CVE-2026-22016
 Vulnerability in the Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component: JAXP).  Supported versions that are affected are Oracle Java SE: 8u481, 8u481-b50, 8u481-perf, 11.0.30, 17.0.18, 21.0.10, 25.0.2, 26; Oracle GraalVM for JDK: 17.0.18 and  21.0.10; Oracle GraalVM Enterprise Edition: 21.3.17. Easily exploitable vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition.  Successful attacks of this vulnerability can result in  unauthorized access to critical data or complete access to all Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition accessible data. Note: This vulnerability can be exploited by using APIs in the specified Component, e.g., through a web service which supplies data to the APIs. This vulnerability also applies to Java deployments, typically in clients running sandboxed Java Web Start applications or sandboxed Java applets, that load and run untrusted code (e.g., code that comes from the internet) and rely on the Java sandbox for security. CVSS 3.1 Base Score 7.5 (Confidentiality impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N).

- [https://github.com/George0Papasotiriou/CVE-2026-22016-IPFS-CID-Spoofing-via-Multihash-Length-Extension](https://github.com/George0Papasotiriou/CVE-2026-22016-IPFS-CID-Spoofing-via-Multihash-Length-Extension) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2026-22016-IPFS-CID-Spoofing-via-Multihash-Length-Extension.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2026-22016-IPFS-CID-Spoofing-via-Multihash-Length-Extension.svg)


## CVE-2026-22015
 Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Information Schema).  Supported versions that are affected are 8.0.0-8.0.45, 8.4.0-8.4.8 and  9.0.0-9.6.0. Easily exploitable vulnerability allows low privileged attacker with network access via multiple protocols to compromise MySQL Server.  Successful attacks of this vulnerability can result in  unauthorized read access to a subset of MySQL Server accessible data. CVSS 3.1 Base Score 4.3 (Confidentiality impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N).

- [https://github.com/George0Papasotiriou/CVE-2026-22015-Serverless-Function-Environment-Variable-Injection-via-Event](https://github.com/George0Papasotiriou/CVE-2026-22015-Serverless-Function-Environment-Variable-Injection-via-Event) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2026-22015-Serverless-Function-Environment-Variable-Injection-via-Event.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2026-22015-Serverless-Function-Environment-Variable-Injection-via-Event.svg)


## CVE-2026-22014
 Vulnerability in the Oracle User Management product of Oracle E-Business Suite (component: Workflow and Business Events).  Supported versions that are affected are 12.2.7-12.2.15. Easily exploitable vulnerability allows high privileged attacker with network access via HTTP to compromise Oracle User Management.  Successful attacks of this vulnerability can result in  unauthorized update, insert or delete access to some of Oracle User Management accessible data as well as  unauthorized read access to a subset of Oracle User Management accessible data. CVSS 3.1 Base Score 3.8 (Confidentiality and Integrity impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:N).

- [https://github.com/George0Papasotiriou/CVE-2026-22014-GraphQL-Persisted-Queries-Injection-via-ID-Manipulation](https://github.com/George0Papasotiriou/CVE-2026-22014-GraphQL-Persisted-Queries-Injection-via-ID-Manipulation) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2026-22014-GraphQL-Persisted-Queries-Injection-via-ID-Manipulation.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2026-22014-GraphQL-Persisted-Queries-Injection-via-ID-Manipulation.svg)


## CVE-2026-22013
 Vulnerability in the Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component: JGSS).  Supported versions that are affected are Oracle Java SE: 8u481, 8u481-b50, 8u481-perf, 11.0.30, 17.0.18, 21.0.10, 25.0.2, 26; Oracle GraalVM for JDK: 17.0.18 and  21.0.10; Oracle GraalVM Enterprise Edition: 21.3.17. Difficult to exploit vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition.  Successful attacks require human interaction from a person other than the attacker. Successful attacks of this vulnerability can result in  unauthorized access to critical data or complete access to all Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition accessible data. Note: This vulnerability applies to Java deployments, typically in clients running sandboxed Java Web Start applications or sandboxed Java applets, that load and run untrusted code (e.g., code that comes from the internet) and rely on the Java sandbox for security. This vulnerability does not apply to Java deployments, typically in servers, that load and run only trusted code (e.g., code installed by an administrator). CVSS 3.1 Base Score 5.3 (Confidentiality impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N).

- [https://github.com/George0Papasotiriou/CVE-2026-22013-Hardware-Wallet-USB-Descriptor-Buffer-Overflow](https://github.com/George0Papasotiriou/CVE-2026-22013-Hardware-Wallet-USB-Descriptor-Buffer-Overflow) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2026-22013-Hardware-Wallet-USB-Descriptor-Buffer-Overflow.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2026-22013-Hardware-Wallet-USB-Descriptor-Buffer-Overflow.svg)


## CVE-2026-22011
 Vulnerability in the Oracle Applications DBA product of Oracle E-Business Suite (component: ADPatch).  Supported versions that are affected are 12.2.3-12.2.15. Difficult to exploit vulnerability allows high privileged attacker with network access via HTTP to compromise Oracle Applications DBA.  Successful attacks require human interaction from a person other than the attacker and while the vulnerability is in Oracle Applications DBA, attacks may significantly impact additional products (scope change). Successful attacks of this vulnerability can result in takeover of Oracle Applications DBA. CVSS 3.1 Base Score 7.6 (Confidentiality, Integrity and Availability impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:C/C:H/I:H/A:H).

- [https://github.com/George0Papasotiriou/CVE-2026-22011-iOS-MDM-Profile-Delivery-over-HTTP](https://github.com/George0Papasotiriou/CVE-2026-22011-iOS-MDM-Profile-Delivery-over-HTTP) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2026-22011-iOS-MDM-Profile-Delivery-over-HTTP.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2026-22011-iOS-MDM-Profile-Delivery-over-HTTP.svg)


## CVE-2026-22010
 Vulnerability in the Oracle Financial Services Analytical Applications Infrastructure product of Oracle Financial Services Applications (component: Platform).  Supported versions that are affected are 8.0.7.9, 8.0.8.7 and  8.1.2.5. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Financial Services Analytical Applications Infrastructure.  Successful attacks of this vulnerability can result in  unauthorized access to critical data or complete access to all Oracle Financial Services Analytical Applications Infrastructure accessible data. CVSS 3.1 Base Score 7.5 (Confidentiality impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N).

- [https://github.com/George0Papasotiriou/CVE-2026-22010-Android-Intent-Redirection-to-Exported-Component](https://github.com/George0Papasotiriou/CVE-2026-22010-Android-Intent-Redirection-to-Exported-Component) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2026-22010-Android-Intent-Redirection-to-Exported-Component.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2026-22010-Android-Intent-Redirection-to-Exported-Component.svg)


## CVE-2026-22009
 Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Optimizer).  Supported versions that are affected are 8.0.0-8.0.45, 8.4.0-8.4.8 and  9.0.0-9.6.0. Easily exploitable vulnerability allows low privileged attacker with network access via multiple protocols to compromise MySQL Server.  Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of MySQL Server. CVSS 3.1 Base Score 6.5 (Availability impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H).

- [https://github.com/George0Papasotiriou/CVE-2026-22009-Linux-eBPF-Map-Locking-Race-Use-After-Free](https://github.com/George0Papasotiriou/CVE-2026-22009-Linux-eBPF-Map-Locking-Race-Use-After-Free) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2026-22009-Linux-eBPF-Map-Locking-Race-Use-After-Free.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2026-22009-Linux-eBPF-Map-Locking-Race-Use-After-Free.svg)


## CVE-2026-22008
 Vulnerability in Oracle Java SE (component: Libraries).   The supported version that is affected is Oracle Java SE: 25.0.1. Difficult to exploit vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise Oracle Java SE.  Successful attacks of this vulnerability can result in  unauthorized update, insert or delete access to some of Oracle Java SE accessible data. Note: This vulnerability applies to Java deployments, typically in clients running sandboxed Java Web Start applications or sandboxed Java applets, that load and run untrusted code (e.g., code that comes from the internet) and rely on the Java sandbox for security. This vulnerability does not apply to Java deployments, typically in servers, that load and run only trusted code (e.g., code installed by an administrator). CVSS 3.1 Base Score 3.7 (Integrity impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N).

- [https://github.com/George0Papasotiriou/CVE-2026-22008-AWS-Lambda-Layer-Injection-via-Shared-Layer-ARN](https://github.com/George0Papasotiriou/CVE-2026-22008-AWS-Lambda-Layer-Injection-via-Shared-Layer-ARN) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2026-22008-AWS-Lambda-Layer-Injection-via-Shared-Layer-ARN.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2026-22008-AWS-Lambda-Layer-Injection-via-Shared-Layer-ARN.svg)


## CVE-2026-22007
 Vulnerability in the Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component: Security).  Supported versions that are affected are Oracle Java SE: 8u481, 8u481-b50, 8u481-perf, 11.0.30, 17.0.18, 21.0.10, 25.0.2, 26; Oracle GraalVM for JDK: 17.0.18 and  21.0.10; Oracle GraalVM Enterprise Edition: 21.3.17. Difficult to exploit vulnerability allows unauthenticated attacker with logon to the infrastructure where Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition executes to compromise Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition.  Successful attacks of this vulnerability can result in  unauthorized read access to a subset of Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition accessible data. Note: This vulnerability can be exploited by using APIs in the specified Component, e.g., through a web service which supplies data to the APIs. This vulnerability also applies to Java deployments, typically in clients running sandboxed Java Web Start applications or sandboxed Java applets, that load and run untrusted code (e.g., code that comes from the internet) and rely on the Java sandbox for security. CVSS 3.1 Base Score 2.9 (Confidentiality impacts).  CVSS Vector: (CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N).

- [https://github.com/George0Papasotiriou/CVE-2026-22007-NTP-monlist-Amplification-over-IPv6](https://github.com/George0Papasotiriou/CVE-2026-22007-NTP-monlist-Amplification-over-IPv6) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2026-22007-NTP-monlist-Amplification-over-IPv6.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2026-22007-NTP-monlist-Amplification-over-IPv6.svg)


## CVE-2026-22006
 Vulnerability in the PeopleSoft Enterprise HCM Human Resources product of Oracle PeopleSoft (component: Employee Snapshot).   The supported version that is affected is 9.2. Easily exploitable vulnerability allows low privileged attacker with network access via HTTP to compromise PeopleSoft Enterprise HCM Human Resources.  Successful attacks require human interaction from a person other than the attacker and while the vulnerability is in PeopleSoft Enterprise HCM Human Resources, attacks may significantly impact additional products (scope change). Successful attacks of this vulnerability can result in  unauthorized update, insert or delete access to some of PeopleSoft Enterprise HCM Human Resources accessible data as well as  unauthorized read access to a subset of PeopleSoft Enterprise HCM Human Resources accessible data. CVSS 3.1 Base Score 5.4 (Confidentiality and Integrity impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N).

- [https://github.com/George0Papasotiriou/CVE-2026-22006-XSLT-Server-Side-Injection-via-xsl-script-](https://github.com/George0Papasotiriou/CVE-2026-22006-XSLT-Server-Side-Injection-via-xsl-script-) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2026-22006-XSLT-Server-Side-Injection-via-xsl-script-.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2026-22006-XSLT-Server-Side-Injection-via-xsl-script-.svg)


## CVE-2026-22005
 Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Optimizer).  Supported versions that are affected are 8.0.0-8.0.45, 8.4.0-8.4.8 and  9.0.0-9.6.0. Easily exploitable vulnerability allows high privileged attacker with network access via multiple protocols to compromise MySQL Server.  Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of MySQL Server. CVSS 3.1 Base Score 4.9 (Availability impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H).

- [https://github.com/George0Papasotiriou/CVE-2026-22005-OAuth-2.0-Device-Code-Phishing-Short-Interval-](https://github.com/George0Papasotiriou/CVE-2026-22005-OAuth-2.0-Device-Code-Phishing-Short-Interval-) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2026-22005-OAuth-2.0-Device-Code-Phishing-Short-Interval-.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2026-22005-OAuth-2.0-Device-Code-Phishing-Short-Interval-.svg)


## CVE-2026-22004
 Vulnerability in the MySQL Server product of Oracle MySQL (component: InnoDB).  Supported versions that are affected are 8.0.0-8.0.45, 8.4.0-8.4.8 and  9.0.0-9.6.0. Easily exploitable vulnerability allows high privileged attacker with network access via multiple protocols to compromise MySQL Server.  Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of MySQL Server. CVSS 3.1 Base Score 4.9 (Availability impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H).

- [https://github.com/George0Papasotiriou/CVE-2026-22004-Git-LFS-Pointer-Poisoning-Supply-Chain-](https://github.com/George0Papasotiriou/CVE-2026-22004-Git-LFS-Pointer-Poisoning-Supply-Chain-) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2026-22004-Git-LFS-Pointer-Poisoning-Supply-Chain-.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2026-22004-Git-LFS-Pointer-Poisoning-Supply-Chain-.svg)


## CVE-2026-22003
 Vulnerability in the Oracle Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component: Hotspot).  Supported versions that are affected are Oracle Java SE: 8u481 and  8u481-b50; Oracle GraalVM Enterprise Edition: 21.3.17. Difficult to exploit vulnerability allows low privileged attacker with logon to the infrastructure where Oracle Java SE, Oracle GraalVM Enterprise Edition executes to compromise Oracle Java SE, Oracle GraalVM Enterprise Edition.  Successful attacks require human interaction from a person other than the attacker. Successful attacks of this vulnerability can result in  unauthorized creation, deletion or modification access to critical data or all Oracle Java SE, Oracle GraalVM Enterprise Edition accessible data and unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of Oracle Java SE, Oracle GraalVM Enterprise Edition. Note: This vulnerability applies to Java deployments, typically in clients running sandboxed Java Web Start applications or sandboxed Java applets, that load and run untrusted code (e.g., code that comes from the internet) and rely on the Java sandbox for security. This vulnerability does not apply to Java deployments, typically in servers, that load and run only trusted code (e.g., code installed by an administrator). CVSS 3.1 Base Score 6.0 (Integrity and Availability impacts).  CVSS Vector: (CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:N/I:H/A:H).

- [https://github.com/George0Papasotiriou/CVE-2026-22003-Redis-Lua-Sandbox-Escape-via-debug.sethook-](https://github.com/George0Papasotiriou/CVE-2026-22003-Redis-Lua-Sandbox-Escape-via-debug.sethook-) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2026-22003-Redis-Lua-Sandbox-Escape-via-debug.sethook-.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2026-22003-Redis-Lua-Sandbox-Escape-via-debug.sethook-.svg)


## CVE-2026-22002
 Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Optimizer).  Supported versions that are affected are 8.0.0-8.0.45, 8.4.0-8.4.8 and  9.0.0-9.6.0. Easily exploitable vulnerability allows high privileged attacker with network access via multiple protocols to compromise MySQL Server.  Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of MySQL Server. CVSS 3.1 Base Score 4.9 (Availability impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H).

- [https://github.com/George0Papasotiriou/CVE-2026-22002-VNC-Authentication-Bypass-via-Protocol-Version-Confusion](https://github.com/George0Papasotiriou/CVE-2026-22002-VNC-Authentication-Bypass-via-Protocol-Version-Confusion) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2026-22002-VNC-Authentication-Bypass-via-Protocol-Version-Confusion.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2026-22002-VNC-Authentication-Bypass-via-Protocol-Version-Confusion.svg)


## CVE-2026-22001
 Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Information Schema).  Supported versions that are affected are 8.0.0-8.0.45, 8.4.0-8.4.8 and  9.0.0-9.6.0. Easily exploitable vulnerability allows high privileged attacker with network access via multiple protocols to compromise MySQL Server.  Successful attacks of this vulnerability can result in  unauthorized read access to a subset of MySQL Server accessible data. CVSS 3.1 Base Score 2.7 (Confidentiality impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:N/A:N).

- [https://github.com/George0Papasotiriou/CVE-2026-22001-SPHINCS-WOTS-Weak-Randomness-Forgeable-Signature](https://github.com/George0Papasotiriou/CVE-2026-22001-SPHINCS-WOTS-Weak-Randomness-Forgeable-Signature) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2026-22001-SPHINCS-WOTS-Weak-Randomness-Forgeable-Signature.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2026-22001-SPHINCS-WOTS-Weak-Randomness-Forgeable-Signature.svg)


## CVE-2026-18577
 An incomplete patch for CVE-2026-18556 allows for authentication bypass and account takeover in N-central Versions through 2026.3.1

- [https://github.com/HORKimhab/CVE-2026-18577](https://github.com/HORKimhab/CVE-2026-18577) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-18577.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-18577.svg)


## CVE-2026-17566
This issue affects pgAdmin 4: from the introduction of _is_query_parens_balanced() before 9.18.

- [https://github.com/HackSpeak/CVE-2026-17566](https://github.com/HackSpeak/CVE-2026-17566) :  ![starts](https://img.shields.io/github/stars/HackSpeak/CVE-2026-17566.svg) ![forks](https://img.shields.io/github/forks/HackSpeak/CVE-2026-17566.svg)


## CVE-2026-17543
 Improper escaping of backslashes in attacker-provided parameters would allow for trivial SQL injection in PHP versions from 8.2.* before 8.2.33, from 8.3.* before 8.3.33, from 8.4.* before 8.4.24, and from 8.5.* before 8.5.9.

- [https://github.com/pratham220/CVE-2026-17543-PHP-Exposure-Validator](https://github.com/pratham220/CVE-2026-17543-PHP-Exposure-Validator) :  ![starts](https://img.shields.io/github/stars/pratham220/CVE-2026-17543-PHP-Exposure-Validator.svg) ![forks](https://img.shields.io/github/forks/pratham220/CVE-2026-17543-PHP-Exposure-Validator.svg)


## CVE-2026-16232
 An authentication bypass vulnerability in the Check Point SmartConsole login process allows an unauthenticated remote attacker to obtain an application login token and use it to authenticate with full administrative privileges. Successful exploitation allows the attacker to modify security policies and security configurations. Remote exploitation requires internet access to the Management Server IP address and a configuration that does not restrict Trusted Clients. Check Point is aware that this vulnerability is being exploited and has affected a very small number of customers.

- [https://github.com/HackSpeak/CVE-2026-16232](https://github.com/HackSpeak/CVE-2026-16232) :  ![starts](https://img.shields.io/github/stars/HackSpeak/CVE-2026-16232.svg) ![forks](https://img.shields.io/github/forks/HackSpeak/CVE-2026-16232.svg)


## CVE-2026-14483
 The Realtyna Organic IDX plugin + WPL Real Estate plugin for WordPress is vulnerable to Arbitrary File Upload in all versions up to, and including, 5.2.0 via the upload function. This is due to missing file type validation in the upload function, combined with a publicly accessible I/O endpoint authenticated solely by static, plugin-seeded API credentials that are identical across all installations. This makes it possible for unauthenticated attackers to upload files that may be executable, which makes remote code execution possible. The WPL I/O service endpoint is registered on the public WordPress init hook with no WordPress capability check, and the required api_key and api_secret values are static defaults seeded by the plugin's own SQL migration files, meaning any unauthenticated attacker who knows these publicly documented defaults can reach and exploit the vulnerable upload path.

- [https://github.com/0xdak/CVE-2026-14483_exploit](https://github.com/0xdak/CVE-2026-14483_exploit) :  ![starts](https://img.shields.io/github/stars/0xdak/CVE-2026-14483_exploit.svg) ![forks](https://img.shields.io/github/forks/0xdak/CVE-2026-14483_exploit.svg)


## CVE-2026-12720
 The Kirki  WordPress plugin before 6.0.13 does not restrict which classes may be instantiated when it deserialises data that unauthenticated users can store, leading to PHP Object Injection that is triggered when an administrator later reviews the stored data. With a suitable gadget chain present on the site (via another installed Kirki  WordPress plugin before 6.0.13, , or an outdated WordPress version), this could be leveraged to perform a variety of attacks, such as remote code execution.

- [https://github.com/webshellseo8/CVE-2026-12720-Proof-of-Concept](https://github.com/webshellseo8/CVE-2026-12720-Proof-of-Concept) :  ![starts](https://img.shields.io/github/stars/webshellseo8/CVE-2026-12720-Proof-of-Concept.svg) ![forks](https://img.shields.io/github/forks/webshellseo8/CVE-2026-12720-Proof-of-Concept.svg)


## CVE-2026-6768
 Mitigation bypass in the Networking: Cookies component. This vulnerability was fixed in Firefox 150 and Thunderbird 150.

- [https://github.com/qflksheep/CVE-2026-67689-FineAdmin.Mvc-vulnerability](https://github.com/qflksheep/CVE-2026-67689-FineAdmin.Mvc-vulnerability) :  ![starts](https://img.shields.io/github/stars/qflksheep/CVE-2026-67689-FineAdmin.Mvc-vulnerability.svg) ![forks](https://img.shields.io/github/forks/qflksheep/CVE-2026-67689-FineAdmin.Mvc-vulnerability.svg)
- [https://github.com/qflksheep/CVE-2026-67687-ICS-Park-Smart-Park-Management-System-v2.0](https://github.com/qflksheep/CVE-2026-67687-ICS-Park-Smart-Park-Management-System-v2.0) :  ![starts](https://img.shields.io/github/stars/qflksheep/CVE-2026-67687-ICS-Park-Smart-Park-Management-System-v2.0.svg) ![forks](https://img.shields.io/github/forks/qflksheep/CVE-2026-67687-ICS-Park-Smart-Park-Management-System-v2.0.svg)


## CVE-2026-6762
 Spoofing issue in the DOM: Core & HTML component. This vulnerability was fixed in Firefox 150, Firefox ESR 115.35, Firefox ESR 140.10, Thunderbird 150, and Thunderbird 140.10.

- [https://github.com/abdugafforov-bobur/CVE-2026-67620-poc](https://github.com/abdugafforov-bobur/CVE-2026-67620-poc) :  ![starts](https://img.shields.io/github/stars/abdugafforov-bobur/CVE-2026-67620-poc.svg) ![forks](https://img.shields.io/github/forks/abdugafforov-bobur/CVE-2026-67620-poc.svg)


## CVE-2026-6000
 A vulnerability was found in code-projects Online Library Management System 1.0. Affected is an unknown function of the file /sql/library.sql of the component SQL Database Backup File Handler. Performing a manipulation results in information disclosure. The attack may be initiated remotely. The exploit has been made public and could be used.

- [https://github.com/HackSpeak/CVE-2026-60004](https://github.com/HackSpeak/CVE-2026-60004) :  ![starts](https://img.shields.io/github/stars/HackSpeak/CVE-2026-60004.svg) ![forks](https://img.shields.io/github/forks/HackSpeak/CVE-2026-60004.svg)
- [https://github.com/Sachinart/CVE-2026-60004-gitea-0day](https://github.com/Sachinart/CVE-2026-60004-gitea-0day) :  ![starts](https://img.shields.io/github/stars/Sachinart/CVE-2026-60004-gitea-0day.svg) ![forks](https://img.shields.io/github/forks/Sachinart/CVE-2026-60004-gitea-0day.svg)


## CVE-2026-2525
 A vulnerability has been found in Free5GC up to 4.1.0. This affects an unknown function of the component PFCP UDP Endpoint. Such manipulation leads to denial of service. The attack can be launched remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/TheMalwareGuardian/CVE-2026-25250](https://github.com/TheMalwareGuardian/CVE-2026-25250) :  ![starts](https://img.shields.io/github/stars/TheMalwareGuardian/CVE-2026-25250.svg) ![forks](https://img.shields.io/github/forks/TheMalwareGuardian/CVE-2026-25250.svg)


## CVE-2026-2202
 A vulnerability was detected in Tenda AC8 16.03.33.05. Affected is the function fromSetWifiGusetBasic of the file /goform/WifiGuestSet of the component httpd. The manipulation of the argument shareSpeed results in buffer overflow. The attack may be launched remotely. The exploit is now public and may be used.

- [https://github.com/George0Papasotiriou/CVE-2026-22020-Weak-Seed-in-Quantum-Key-Distribution-Error-Correction](https://github.com/George0Papasotiriou/CVE-2026-22020-Weak-Seed-in-Quantum-Key-Distribution-Error-Correction) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2026-22020-Weak-Seed-in-Quantum-Key-Distribution-Error-Correction.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2026-22020-Weak-Seed-in-Quantum-Key-Distribution-Error-Correction.svg)


## CVE-2026-2201
 A security vulnerability has been detected in ZeroWdd studentmanager up to 2151560fc0a50ec00426785ec1e01a3763b380d9. This impacts the function addLeave of the file src/main/java/com/wdd/studentmanager/controller/LeaveController.java. The manipulation of the argument Reason for Leave leads to cross site scripting. The attack may be initiated remotely. The exploit has been disclosed publicly and may be used. This product uses a rolling release model to deliver continuous updates. As a result, specific version information for affected or updated releases is not available. The code repository of the project has not been active for many years.

- [https://github.com/George0Papasotiriou/CVE-2026-22012-Diameter-Protocol-Credit-Control-Bypass-in-5G](https://github.com/George0Papasotiriou/CVE-2026-22012-Diameter-Protocol-Credit-Control-Bypass-in-5G) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2026-22012-Diameter-Protocol-Credit-Control-Bypass-in-5G.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2026-22012-Diameter-Protocol-Credit-Control-Bypass-in-5G.svg)


## CVE-2025-64513
 Milvus is an open-source vector database built for generative AI applications. An unauthenticated attacker can exploit a vulnerability in versions prior to 2.4.24, 2.5.21, and 2.6.5 to bypass all authentication mechanisms in the Milvus Proxy component, gaining full administrative access to the Milvus cluster. This grants the attacker the ability to read, modify, or delete data, and to perform privileged administrative operations such as database or collection management. This issue has been fixed in Milvus 2.4.24, 2.5.21, and 2.6.5. If immediate upgrade is not possible, a temporary mitigation can be applied by removing the sourceID header from all incoming requests at the gateway, API gateway, or load balancer level before they reach the Milvus Proxy. This prevents attackers from exploiting the authentication bypass behavior.

- [https://github.com/qianlijaingshan/milvus-auth-audit](https://github.com/qianlijaingshan/milvus-auth-audit) :  ![starts](https://img.shields.io/github/stars/qianlijaingshan/milvus-auth-audit.svg) ![forks](https://img.shields.io/github/forks/qianlijaingshan/milvus-auth-audit.svg)


## CVE-2025-59528
 Flowise is a drag & drop user interface to build a customized large language model flow. In version 3.0.5, Flowise is vulnerable to remote code execution. The CustomMCP node allows users to input configuration settings for connecting to an external MCP server. This node parses the user-provided mcpServerConfig string to build the MCP server configuration. However, during this process, it executes JavaScript code without any security validation. Specifically, inside the convertToValidJSONString function, user input is directly passed to the Function() constructor, which evaluates and executes the input as JavaScript code. Since this runs with full Node.js runtime privileges, it can access dangerous modules such as child_process and fs. This issue has been patched in version 3.0.6.

- [https://github.com/Twappz/HTB-Silentium-Writeup](https://github.com/Twappz/HTB-Silentium-Writeup) :  ![starts](https://img.shields.io/github/stars/Twappz/HTB-Silentium-Writeup.svg) ![forks](https://img.shields.io/github/forks/Twappz/HTB-Silentium-Writeup.svg)


## CVE-2025-58434
 Flowise is a drag & drop user interface to build a customized large language model flow. In version 3.0.5 and earlier, the `forgot-password` endpoint in Flowise returns sensitive information including a valid password reset `tempToken` without authentication or verification. This enables any attacker to generate a reset token for arbitrary users and directly reset their password, leading to a complete account takeover (ATO). This vulnerability applies to both the cloud service (`cloud.flowiseai.com`) and self-hosted/local Flowise deployments that expose the same API. Commit 9e178d68873eb876073846433a596590d3d9c863 in version 3.0.6 secures password reset endpoints. Several recommended remediation steps are available. Do not return reset tokens or sensitive account details in API responses. Tokens must only be delivered securely via the registered email channel. Ensure `forgot-password` responds with a generic success message regardless of input, to avoid user enumeration. Require strong validation of the `tempToken` (e.g., single-use, short expiry, tied to request origin, validated against email delivery). Apply the same fixes to both cloud and self-hosted/local deployments. Log and monitor password reset requests for suspicious activity. Consider multi-factor verification for sensitive accounts.

- [https://github.com/Twappz/HTB-Silentium-Writeup](https://github.com/Twappz/HTB-Silentium-Writeup) :  ![starts](https://img.shields.io/github/stars/Twappz/HTB-Silentium-Writeup.svg) ![forks](https://img.shields.io/github/forks/Twappz/HTB-Silentium-Writeup.svg)


## CVE-2025-53770
Microsoft is preparing and fully testing a comprehensive update to address this vulnerability.  In the meantime, please make sure that the mitigation provided in this CVE documentation is in place so that you are protected from exploitation.

- [https://github.com/0xKr1x/CVE-2025-53770-Scanner](https://github.com/0xKr1x/CVE-2025-53770-Scanner) :  ![starts](https://img.shields.io/github/stars/0xKr1x/CVE-2025-53770-Scanner.svg) ![forks](https://img.shields.io/github/forks/0xKr1x/CVE-2025-53770-Scanner.svg)
- [https://github.com/mfarshad-abdullah-khan/cve-2025-53770-research](https://github.com/mfarshad-abdullah-khan/cve-2025-53770-research) :  ![starts](https://img.shields.io/github/stars/mfarshad-abdullah-khan/cve-2025-53770-research.svg) ![forks](https://img.shields.io/github/forks/mfarshad-abdullah-khan/cve-2025-53770-research.svg)


## CVE-2025-32463
 Sudo before 1.9.17p1 allows local users to obtain root access because /etc/nsswitch.conf from a user-controlled directory is used with the --chroot option.

- [https://github.com/0xdak/CVE-2025-32463_exploit](https://github.com/0xdak/CVE-2025-32463_exploit) :  ![starts](https://img.shields.io/github/stars/0xdak/CVE-2025-32463_exploit.svg) ![forks](https://img.shields.io/github/forks/0xdak/CVE-2025-32463_exploit.svg)


## CVE-2025-27840
 Espressif ESP32 chips allow 29 hidden HCI commands, such as 0xFC02 (Write memory).

- [https://github.com/JasonW88/esp32-cve-2025-27840-power-trace-experiment](https://github.com/JasonW88/esp32-cve-2025-27840-power-trace-experiment) :  ![starts](https://img.shields.io/github/stars/JasonW88/esp32-cve-2025-27840-power-trace-experiment.svg) ![forks](https://img.shields.io/github/forks/JasonW88/esp32-cve-2025-27840-power-trace-experiment.svg)


## CVE-2025-8110
 Improper Symbolic link handling in the PutContents API in Gogs allows Local Execution of Code.

- [https://github.com/Twappz/HTB-Silentium-Writeup](https://github.com/Twappz/HTB-Silentium-Writeup) :  ![starts](https://img.shields.io/github/stars/Twappz/HTB-Silentium-Writeup.svg) ![forks](https://img.shields.io/github/forks/Twappz/HTB-Silentium-Writeup.svg)


## CVE-2025-4275
 A vulnerability in the digital signature verification process does not properly validate variable attributes which allows an attacker to bypass signature verification by creating a non-authenticated NVRAM variable. An attacker may to execute arbitrary signed UEFI code and bypass Secure Boot.

- [https://github.com/TheMalwareGuardian/CVE-2025-4275](https://github.com/TheMalwareGuardian/CVE-2025-4275) :  ![starts](https://img.shields.io/github/stars/TheMalwareGuardian/CVE-2025-4275.svg) ![forks](https://img.shields.io/github/forks/TheMalwareGuardian/CVE-2025-4275.svg)


## CVE-2025-3052
 An arbitrary write vulnerability in Microsoft signed UEFI firmware allows for code execution of untrusted software. This allows an attacker to control its value, leading to arbitrary memory writes, including modification of critical firmware settings stored in NVRAM. Exploiting this vulnerability could enable security bypasses, persistence mechanisms, or full system compromise.

- [https://github.com/TheMalwareGuardian/CVE-2025-3052](https://github.com/TheMalwareGuardian/CVE-2025-3052) :  ![starts](https://img.shields.io/github/stars/TheMalwareGuardian/CVE-2025-3052.svg) ![forks](https://img.shields.io/github/forks/TheMalwareGuardian/CVE-2025-3052.svg)


## CVE-2024-21413
 Microsoft Outlook Remote Code Execution Vulnerability

- [https://github.com/h4cknain/CVE-2024-21413-Microsoft-Outlook-Moniker-Link-Vulnerability](https://github.com/h4cknain/CVE-2024-21413-Microsoft-Outlook-Moniker-Link-Vulnerability) :  ![starts](https://img.shields.io/github/stars/h4cknain/CVE-2024-21413-Microsoft-Outlook-Moniker-Link-Vulnerability.svg) ![forks](https://img.shields.io/github/forks/h4cknain/CVE-2024-21413-Microsoft-Outlook-Moniker-Link-Vulnerability.svg)
- [https://github.com/OmarMahmoud1024/tryhackme-monikerlink-writeup](https://github.com/OmarMahmoud1024/tryhackme-monikerlink-writeup) :  ![starts](https://img.shields.io/github/stars/OmarMahmoud1024/tryhackme-monikerlink-writeup.svg) ![forks](https://img.shields.io/github/forks/OmarMahmoud1024/tryhackme-monikerlink-writeup.svg)


## CVE-2023-31902
 RPA Technology Mobile Mouse 3.6.0.4 is vulnerable to Remote Code Execution (RCE).

- [https://github.com/lypd0/mouseserver-exploit](https://github.com/lypd0/mouseserver-exploit) :  ![starts](https://img.shields.io/github/stars/lypd0/mouseserver-exploit.svg) ![forks](https://img.shields.io/github/forks/lypd0/mouseserver-exploit.svg)

