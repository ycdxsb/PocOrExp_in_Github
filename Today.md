# Update 2026-07-25
## CVE-2026-64600
sequence counter changes across the ILOCK cycle.

- [https://github.com/0xBlackash/CVE-2026-64600](https://github.com/0xBlackash/CVE-2026-64600) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-64600.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-64600.svg)
- [https://github.com/HORKimhab/CVE-2026-64600](https://github.com/HORKimhab/CVE-2026-64600) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-64600.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-64600.svg)


## CVE-2026-63766
 GPT-SoVITS through 20250606v2pro contains an OS command injection vulnerability in webui.py where ASR, slice, denoise, and uvr5 functions interpolate unsanitized Gradio textbox values directly into shell commands executed with shell=True. Attackers can inject shell metacharacters through path parameters to execute arbitrary OS commands as the server process user without authentication.

- [https://github.com/0xdak/CVE-2026-63766_exploit](https://github.com/0xdak/CVE-2026-63766_exploit) :  ![starts](https://img.shields.io/github/stars/0xdak/CVE-2026-63766_exploit.svg) ![forks](https://img.shields.io/github/forks/0xdak/CVE-2026-63766_exploit.svg)


## CVE-2026-63030
 WordPress 6.9.x before 6.9.5 and 7.0.x before 7.0.2 is affected by a REST API batch endpoint route confusion issue which, combined with the author__not_in WP_Query SQL Injection (CVE-2026-60137), could allow an attacker to perform SQL Injection and achieve Remote Code Execution.

- [https://github.com/razureink/cve-2026-63030_60137-wordpress_rce_reproduction](https://github.com/razureink/cve-2026-63030_60137-wordpress_rce_reproduction) :  ![starts](https://img.shields.io/github/stars/razureink/cve-2026-63030_60137-wordpress_rce_reproduction.svg) ![forks](https://img.shields.io/github/forks/razureink/cve-2026-63030_60137-wordpress_rce_reproduction.svg)


## CVE-2026-60206
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Core).  Supported versions that are affected are 12.2.1.4.0, 14.1.1.0.0, 14.1.2.0.0 and  15.1.1.0.0. Easily exploitable vulnerability allows low privileged attacker with network access via SAML to compromise Oracle WebLogic Server.  While the vulnerability is in Oracle WebLogic Server, attacks may significantly impact additional products (scope change).  Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.1 Base Score 9.9 (Confidentiality, Integrity and Availability impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H).

- [https://github.com/0xBlackash/CVE-2026-60206](https://github.com/0xBlackash/CVE-2026-60206) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-60206.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-60206.svg)


## CVE-2026-59880
 Immutable.js provides many Persistent Immutable data structures. Prior to 4.3.9 and 5.1.8, Immutable.Map and Immutable.Set keep keys that share the same 32-bit hash in a HashCollisionNode collision bucket that is scanned linearly, allowing an attacker who controls keys inserted into a Map, such as through Immutable.Map(obj), Immutable.fromJS(obj), state.merge(userObject), or mergeDeep, to craft many colliding keys and degrade insertion and lookup to consume disproportionate CPU. This issue is fixed in versions 4.3.9 and 5.1.8.

- [https://github.com/nvth/cve-2026-59880](https://github.com/nvth/cve-2026-59880) :  ![starts](https://img.shields.io/github/stars/nvth/cve-2026-59880.svg) ![forks](https://img.shields.io/github/forks/nvth/cve-2026-59880.svg)


## CVE-2026-59827
 Metabase is an open-source business intelligence and embedded analytics tool. Prior to 1.58.15, 1.59.12, 1.60.6.3, and 1.61.1.4, Metabase instances with an H2 database connection, including the default sample database, deserialize arbitrary Java objects returned in H2 native query result columns of type OTHER without validation, allowing an authenticated user who can run native H2 queries to execute code on the Metabase server. This issue is fixed in versions 1.58.15, 1.59.12, 1.60.6.3, and 1.61.1.4.

- [https://github.com/pickl31/CVE-2026-59827](https://github.com/pickl31/CVE-2026-59827) :  ![starts](https://img.shields.io/github/stars/pickl31/CVE-2026-59827.svg) ![forks](https://img.shields.io/github/forks/pickl31/CVE-2026-59827.svg)


## CVE-2026-58057
 Flowise before 3.1.3 validates Custom MCP stdio environment variables against a denylist using a case-sensitive comparison, so on Windows, where environment names are case-insensitive, supplying 'node_options' bypasses the NODE_OPTIONS denylist entry. An authenticated user who can configure a Custom MCP node can thereby inject NODE_OPTIONS --require and execute arbitrary code in the Flowise server context.

- [https://github.com/CerberusMrXi/Flowise-CVE-2026-58057-exploit](https://github.com/CerberusMrXi/Flowise-CVE-2026-58057-exploit) :  ![starts](https://img.shields.io/github/stars/CerberusMrXi/Flowise-CVE-2026-58057-exploit.svg) ![forks](https://img.shields.io/github/forks/CerberusMrXi/Flowise-CVE-2026-58057-exploit.svg)


## CVE-2026-56121
 Feast before 0.63.0 contains an unsafe deserialization vulnerability that allows unauthenticated or unauthorized attackers to achieve remote code execution by sending a crafted gRPC request to the registry server. The user_defined_function.body field of an OnDemandFeatureView spec is decoded from base64 and passed to dill.loads() before any authorization check is performed, enabling attackers to embed a malicious serialized Python object with an arbitrary __reduce__ method to execute OS commands as the feast service account.

- [https://github.com/0xdak/CVE-2026-56121_exploit](https://github.com/0xdak/CVE-2026-56121_exploit) :  ![starts](https://img.shields.io/github/stars/0xdak/CVE-2026-56121_exploit.svg) ![forks](https://img.shields.io/github/forks/0xdak/CVE-2026-56121_exploit.svg)


## CVE-2026-54121
 Improper authorization in Active Directory Certificate Services (AD CS) allows an authorized attacker to elevate privileges over a network.

- [https://github.com/aniqfakhrul/CVE-2026-54121](https://github.com/aniqfakhrul/CVE-2026-54121) :  ![starts](https://img.shields.io/github/stars/aniqfakhrul/CVE-2026-54121.svg) ![forks](https://img.shields.io/github/forks/aniqfakhrul/CVE-2026-54121.svg)


## CVE-2026-48546
 KanaDojo before 0.1.18 contains a sandbox escape vulnerability that allows an attacker to execute arbitrary code by exploiting the explicit passing of the global require function into a Node.js vm.runInNewContext() sandbox context in the issue-auto-respond.yml workflow. Attackers can submit a pull request modifying messages.cjs to import arbitrary Node.js modules, bypassing sandbox restrictions and achieving remote code execution with full GitHub Actions runner privileges including access to AUTOMATION_PR_TOKEN.

- [https://github.com/ghapvharmo/gha-lab-a5c1876997-1](https://github.com/ghapvharmo/gha-lab-a5c1876997-1) :  ![starts](https://img.shields.io/github/stars/ghapvharmo/gha-lab-a5c1876997-1.svg) ![forks](https://img.shields.io/github/forks/ghapvharmo/gha-lab-a5c1876997-1.svg)


## CVE-2026-47670
 DbGate is cross-platform database manager. Versions 7.1.8 and prior are vulnerable to authenticated Remote Code Execution (RCE). Any user with valid DbGate credentials can execute arbitrary OS commands as root by exploiting an unsanitized `functionName` parameter in the `/runners/load-reader` endpoint. The `require = null` mitigation is trivially bypassed via dynamic `import()`. Version 7.1.9 contains a patch.

- [https://github.com/error-inside/CVE-2026-47670](https://github.com/error-inside/CVE-2026-47670) :  ![starts](https://img.shields.io/github/stars/error-inside/CVE-2026-47670.svg) ![forks](https://img.shields.io/github/forks/error-inside/CVE-2026-47670.svg)


## CVE-2026-47668
 DbGate is cross-platform database manager. In versions 7.1.8 and prior, DbGate's JSON script runner (`POST /runners/start`) allows remote code execution via code injection in the `functionName` parameter of JSON script `assign` commands. The `functionName` value is interpolated directly into dynamically generated JavaScript source code via string concatenation. The generated code is then executed in a forked Node.js child process. Version 7.1.9 contains a patch.

- [https://github.com/Nxploited/CVE-2026-47668](https://github.com/Nxploited/CVE-2026-47668) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2026-47668.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2026-47668.svg)


## CVE-2026-45585
No, if you are using TPM+PIN the vulnerability is not exploitable.

- [https://github.com/yellowkey-exploit/YellowKey-Bitlocker](https://github.com/yellowkey-exploit/YellowKey-Bitlocker) :  ![starts](https://img.shields.io/github/stars/yellowkey-exploit/YellowKey-Bitlocker.svg) ![forks](https://img.shields.io/github/forks/yellowkey-exploit/YellowKey-Bitlocker.svg)


## CVE-2026-45132
 CloudPirates Open Source Helm Charts is a collection of Helm charts. Prior to commit fcf9302, a GitHub Actions workflow (generate-schema.yaml) exposes sensitive credentials (Personal Access Token and SSH signing key) to fork-controlled code due to unsafe checkout and credential handling practices. This issue has been patched via commit fcf9302.

- [https://github.com/ghapvharmo/gha-lab-a815a82f03-1](https://github.com/ghapvharmo/gha-lab-a815a82f03-1) :  ![starts](https://img.shields.io/github/stars/ghapvharmo/gha-lab-a815a82f03-1.svg) ![forks](https://img.shields.io/github/forks/ghapvharmo/gha-lab-a815a82f03-1.svg)


## CVE-2026-43499
  	changelog ]

- [https://github.com/Bailan766/rmx3888-cve-2026-43499-config](https://github.com/Bailan766/rmx3888-cve-2026-43499-config) :  ![starts](https://img.shields.io/github/stars/Bailan766/rmx3888-cve-2026-43499-config.svg) ![forks](https://img.shields.io/github/forks/Bailan766/rmx3888-cve-2026-43499-config.svg)
- [https://github.com/soralis0912/CVE-2026-43499-aristotle](https://github.com/soralis0912/CVE-2026-43499-aristotle) :  ![starts](https://img.shields.io/github/stars/soralis0912/CVE-2026-43499-aristotle.svg) ![forks](https://img.shields.io/github/forks/soralis0912/CVE-2026-43499-aristotle.svg)
- [https://github.com/soralis0912/CVE-2026-43499-aristotle-apk](https://github.com/soralis0912/CVE-2026-43499-aristotle-apk) :  ![starts](https://img.shields.io/github/stars/soralis0912/CVE-2026-43499-aristotle-apk.svg) ![forks](https://img.shields.io/github/forks/soralis0912/CVE-2026-43499-aristotle-apk.svg)


## CVE-2026-42533
 Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/gagaltotal/CVE-2026-42533-nginx](https://github.com/gagaltotal/CVE-2026-42533-nginx) :  ![starts](https://img.shields.io/github/stars/gagaltotal/CVE-2026-42533-nginx.svg) ![forks](https://img.shields.io/github/forks/gagaltotal/CVE-2026-42533-nginx.svg)


## CVE-2026-41948
 Dify version 1.14.1 and prior contain a path traversal vulnerability that allows authenticated users to manipulate requests forwarded to the Plugin Daemon's internal REST API by exploiting insufficient URL path sanitization. Attackers can traverse out of their authorized tenant path using unencoded dot sequences in task identifiers or manipulated filename parameters to access internal endpoints such as debug interfaces, requiring only knowledge of the victim tenant's UUID. NOTE: Dify Cloud allows unauthenticated free self-registration, making account creation trivially accessible to any attacker.

- [https://github.com/dann3xplo1t/Cpanel](https://github.com/dann3xplo1t/Cpanel) :  ![starts](https://img.shields.io/github/stars/dann3xplo1t/Cpanel.svg) ![forks](https://img.shields.io/github/forks/dann3xplo1t/Cpanel.svg)


## CVE-2026-41940
 cPanel and WHM versions after 11.40 contain an authentication bypass vulnerability in the login flow that allows unauthenticated remote attackers to gain unauthorized access to the control panel.

- [https://github.com/dann3xplo1t/Cpanel](https://github.com/dann3xplo1t/Cpanel) :  ![starts](https://img.shields.io/github/stars/dann3xplo1t/Cpanel.svg) ![forks](https://img.shields.io/github/forks/dann3xplo1t/Cpanel.svg)


## CVE-2026-41472
 CyberPanel versions prior to 2.4.4 contain a stored cross-site scripting vulnerability in the AI Scanner dashboard where the POST /api/ai-scanner/callback endpoint lacks authentication and allows unauthenticated attackers to inject malicious JavaScript by overwriting the findings_json field of ScanHistory records. Attackers can inject JavaScript that executes in an administrator's authenticated session when they visit the AI Scanner dashboard, allowing them to issue same-origin requests to plant cron jobs and achieve remote code execution on the server.

- [https://github.com/whiteov3rflow/CyberPanel-Poc](https://github.com/whiteov3rflow/CyberPanel-Poc) :  ![starts](https://img.shields.io/github/stars/whiteov3rflow/CyberPanel-Poc.svg) ![forks](https://img.shields.io/github/forks/whiteov3rflow/CyberPanel-Poc.svg)


## CVE-2026-38764
 An issue in Unistal Systems Pvt. Ltd.Protegent 360 v2.0.0.4 allows a local attacker to escalate privileges via the kernel driver pgsecdl.sys

- [https://github.com/D7EAD/CVE-2026-38764](https://github.com/D7EAD/CVE-2026-38764) :  ![starts](https://img.shields.io/github/stars/D7EAD/CVE-2026-38764.svg) ![forks](https://img.shields.io/github/forks/D7EAD/CVE-2026-38764.svg)


## CVE-2026-33017
 Langflow is a tool for building and deploying AI-powered agents and workflows. In versions prior to 1.9.0, the POST /api/v1/build_public_tmp/{flow_id}/flow endpoint allows building public flows without requiring authentication. When the optional data parameter is supplied, the endpoint uses attacker-controlled flow data (containing arbitrary Python code in node definitions) instead of the stored flow data from the database. This code is passed to exec() with zero sandboxing, resulting in unauthenticated remote code execution. This is distinct from CVE-2025-3248, which fixed /api/v1/validate/code by adding authentication. The build_public_tmp endpoint is designed to be unauthenticated (for public flows) but incorrectly accepts attacker-supplied flow data containing arbitrary executable code. This issue has been fixed in version 1.9.0.

- [https://github.com/Dynamo2k1/CVE-2026-33017](https://github.com/Dynamo2k1/CVE-2026-33017) :  ![starts](https://img.shields.io/github/stars/Dynamo2k1/CVE-2026-33017.svg) ![forks](https://img.shields.io/github/forks/Dynamo2k1/CVE-2026-33017.svg)


## CVE-2026-31431
AD directly.

- [https://github.com/cs8425/copy-fail-go](https://github.com/cs8425/copy-fail-go) :  ![starts](https://img.shields.io/github/stars/cs8425/copy-fail-go.svg) ![forks](https://img.shields.io/github/forks/cs8425/copy-fail-go.svg)


## CVE-2026-27641
 Flask-Reuploaded provides file uploads for Flask. A critical path traversal and extension bypass vulnerability in versions prior to 1.5.0 allows remote attackers to achieve arbitrary file write and remote code execution through Server-Side Template Injection (SSTI). Flask-Reuploaded has been patched in version 1.5.0. Some workarounds are available. Do not pass user input to the `name` parameter, use auto-generated filenames only, and implement strict input validation if `name` must be used.

- [https://github.com/Max78000/CVE-2026-27641-Flask-Reuploaded](https://github.com/Max78000/CVE-2026-27641-Flask-Reuploaded) :  ![starts](https://img.shields.io/github/stars/Max78000/CVE-2026-27641-Flask-Reuploaded.svg) ![forks](https://img.shields.io/github/forks/Max78000/CVE-2026-27641-Flask-Reuploaded.svg)


## CVE-2026-25243
 Redis is an in-memory data structure store. In versions of redis-server up to 8.6.3, the RESTORE command does not properly validate serialized values. An authenticated attacker with permission to execute RESTORE can supply a crafted serialized payload that triggers invalid memory access and may lead to remote code execution. A workaround is to restrict access to the RESTORE command with ACL rules. This is patched in version 8.6.3.

- [https://github.com/dinosn/CVE-2026-25243](https://github.com/dinosn/CVE-2026-25243) :  ![starts](https://img.shields.io/github/stars/dinosn/CVE-2026-25243.svg) ![forks](https://img.shields.io/github/forks/dinosn/CVE-2026-25243.svg)
- [https://github.com/dinosn/CVE-2026-25243-debugfree](https://github.com/dinosn/CVE-2026-25243-debugfree) :  ![starts](https://img.shields.io/github/stars/dinosn/CVE-2026-25243-debugfree.svg) ![forks](https://img.shields.io/github/forks/dinosn/CVE-2026-25243-debugfree.svg)


## CVE-2026-23744
 MCPJam inspector is the local-first development platform for MCP servers. Versions 1.4.2 and earlier are vulnerable to remote code execution (RCE) vulnerability, which allows an attacker to send a crafted HTTP request that triggers the installation of an MCP server, leading to RCE. Since MCPJam inspector by default listens on 0.0.0.0 instead of 127.0.0.1, an attacker can trigger the RCE remotely via a simple HTTP request. Version 1.4.3 contains a patch.

- [https://github.com/nullRoot-Red/CVE-2026-23744](https://github.com/nullRoot-Red/CVE-2026-23744) :  ![starts](https://img.shields.io/github/stars/nullRoot-Red/CVE-2026-23744.svg) ![forks](https://img.shields.io/github/forks/nullRoot-Red/CVE-2026-23744.svg)


## CVE-2026-21509
 Reliance on untrusted inputs in a security decision in Microsoft Office allows an unauthorized attacker to bypass a security feature locally.

- [https://github.com/razureink/cve-2026-21509-office_security_bypass_reproduction](https://github.com/razureink/cve-2026-21509-office_security_bypass_reproduction) :  ![starts](https://img.shields.io/github/stars/razureink/cve-2026-21509-office_security_bypass_reproduction.svg) ![forks](https://img.shields.io/github/forks/razureink/cve-2026-21509-office_security_bypass_reproduction.svg)


## CVE-2026-13001
 The Podlove Podcast Publisher plugin for WordPress is vulnerable to arbitrary file uploads due to missing file type validation in the 'podlove_handle_cache_files' function in all versions up to, and including, 4.5.1. This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible.

- [https://github.com/ghostpels/CVE-2026-13001](https://github.com/ghostpels/CVE-2026-13001) :  ![starts](https://img.shields.io/github/stars/ghostpels/CVE-2026-13001.svg) ![forks](https://img.shields.io/github/forks/ghostpels/CVE-2026-13001.svg)


## CVE-2026-10097
 wolfSSL's AVX2-optimized ML-KEM implementation (mlkem_cmp_avx2) compares only 1536 of the 1568 ciphertext bytes during the Fujisaki-Okamoto re-encryption check in ML-KEM-1024 decapsulation. Ciphertexts that differ from the expected re-encryption solely in bytes 1536-1567 bypass implicit rejection and are accepted as valid, breaking IND-CCA2 security. An attacker able to submit chosen ciphertexts to a decapsulation oracle that uses a static ML-KEM-1024 key, and to observe whether the genuine shared secret or the implicit-rejection secret was produced, can use this as a plaintext-checking oracle to recover the private key. A proof of concept recovered a full ML-KEM-1024 private key with approximately 98% success using roughly 350 chosen ciphertexts. The flaw is a deterministic logic error and does not rely on timing measurements.

- [https://github.com/007bsd/ml-kem-key-recovery](https://github.com/007bsd/ml-kem-key-recovery) :  ![starts](https://img.shields.io/github/stars/007bsd/ml-kem-key-recovery.svg) ![forks](https://img.shields.io/github/forks/007bsd/ml-kem-key-recovery.svg)


## CVE-2026-6597
 A weakness has been identified in langflow-ai langflow up to 1.8.3. Impacted is the function remove_api_keys/has_api_terms of the file src/backend/base/langflow/api/utils/core.py of the component Flow Using API. This manipulation causes unprotected storage of credentials. The attack can be initiated remotely. The exploit has been made available to the public and could be used for attacks. The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/BiiTts/POC-CVE-2026-65971](https://github.com/BiiTts/POC-CVE-2026-65971) :  ![starts](https://img.shields.io/github/stars/BiiTts/POC-CVE-2026-65971.svg) ![forks](https://img.shields.io/github/forks/BiiTts/POC-CVE-2026-65971.svg)


## CVE-2026-6330
 The ML-KEM ARM64 NEON ciphertext comparison only compares half of the input, breaking the Fujisaki-Okamoto transform's implicit rejection and weakening IND-CCA2 security on that code path. The constant-time comparison effectively ignored part of the re-encrypted ciphertext, so a decapsulating party could fail to detect a manipulated ciphertext and proceed without the standard's required implicit rejection.

- [https://github.com/007bsd/ml-kem-key-recovery](https://github.com/007bsd/ml-kem-key-recovery) :  ![starts](https://img.shields.io/github/stars/007bsd/ml-kem-key-recovery.svg) ![forks](https://img.shields.io/github/forks/007bsd/ml-kem-key-recovery.svg)


## CVE-2026-2005
 Heap buffer overflow in PostgreSQL pgcrypto allows a ciphertext provider to execute arbitrary code as the operating system user running the database.  Versions before PostgreSQL 18.2, 17.8, 16.12, 15.16, and 14.21 are affected.

- [https://github.com/dinosn/cve-2026-2005](https://github.com/dinosn/cve-2026-2005) :  ![starts](https://img.shields.io/github/stars/dinosn/cve-2026-2005.svg) ![forks](https://img.shields.io/github/forks/dinosn/cve-2026-2005.svg)


## CVE-2026-0770
The specific flaw exists within the handling of the exec_globals parameter provided to the validate endpoint. The issue results from the inclusion of a resource from an untrusted control sphere. An attacker can leverage this vulnerability to execute code in the context of root. Was ZDI-CAN-27325.

- [https://github.com/razureink/cve-2026-0770-langflow_rce_reproduction](https://github.com/razureink/cve-2026-0770-langflow_rce_reproduction) :  ![starts](https://img.shields.io/github/stars/razureink/cve-2026-0770-langflow_rce_reproduction.svg) ![forks](https://img.shields.io/github/forks/razureink/cve-2026-0770-langflow_rce_reproduction.svg)


## CVE-2026-0560
 A Server-Side Request Forgery (SSRF) vulnerability exists in parisneo/lollms versions prior to 2.2.0, specifically in the `/api/files/export-content` endpoint. The `_download_image_to_temp()` function in `backend/routers/files.py` fails to validate user-controlled URLs, allowing attackers to make arbitrary HTTP requests to internal services and cloud metadata endpoints. This vulnerability can lead to internal network access, cloud metadata access, information disclosure, port scanning, and potentially remote code execution.

- [https://github.com/Max78000/CVE-2026-0560-lollms](https://github.com/Max78000/CVE-2026-0560-lollms) :  ![starts](https://img.shields.io/github/stars/Max78000/CVE-2026-0560-lollms.svg) ![forks](https://img.shields.io/github/forks/Max78000/CVE-2026-0560-lollms.svg)


## CVE-2026-0009
 In multiple locations, there is a possible tapjacking due to a logic error in the code. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/cduram/NotCVE-2026-0009](https://github.com/cduram/NotCVE-2026-0009) :  ![starts](https://img.shields.io/github/stars/cduram/NotCVE-2026-0009.svg) ![forks](https://img.shields.io/github/forks/cduram/NotCVE-2026-0009.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-git-dep](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-git-dep) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-git-dep.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-git-dep.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-berry](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-berry) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-berry.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-berry.svg)


## CVE-2025-53779
 Relative path traversal in Windows Kerberos allows an authorized attacker to elevate privileges over a network.

- [https://github.com/razureink/cve-2025-53779-kerberos_bypass_reproduction](https://github.com/razureink/cve-2025-53779-kerberos_bypass_reproduction) :  ![starts](https://img.shields.io/github/stars/razureink/cve-2025-53779-kerberos_bypass_reproduction.svg) ![forks](https://img.shields.io/github/forks/razureink/cve-2025-53779-kerberos_bypass_reproduction.svg)


## CVE-2025-43564
 ColdFusion versions 2025.1, 2023.13, 2021.19 and earlier are affected by an Improper Access Control vulnerability that could result in arbitrary file system read. A high-privileged attacker could leverage this vulnerability to access or modify sensitive data without proper authorization. Exploitation of this issue does not require user interaction, and scope is changed

- [https://github.com/razureink/cve-2025-43564-tomcat_put_rce_reproduction](https://github.com/razureink/cve-2025-43564-tomcat_put_rce_reproduction) :  ![starts](https://img.shields.io/github/stars/razureink/cve-2025-43564-tomcat_put_rce_reproduction.svg) ![forks](https://img.shields.io/github/forks/razureink/cve-2025-43564-tomcat_put_rce_reproduction.svg)


## CVE-2025-38001
[5] https://lore.kernel.org/netdev/8DuRWwfqjoRDLDmBMlIfbrsZg9Gx50DHJc1ilxsEBNe2D6NMoigR_eIRIG0LOjMc3r10nUUZtArXx4oZBIdUfZQrwjcQhdinnMis_0G7VEk=@willsroot.io/T/#u

- [https://github.com/Jevil36239/CVE-2025-38001](https://github.com/Jevil36239/CVE-2025-38001) :  ![starts](https://img.shields.io/github/stars/Jevil36239/CVE-2025-38001.svg) ![forks](https://img.shields.io/github/forks/Jevil36239/CVE-2025-38001.svg)


## CVE-2025-32433
 Erlang/OTP is a set of libraries for the Erlang programming language. Prior to versions OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20, a SSH server may allow an attacker to perform unauthenticated remote code execution (RCE). By exploiting a flaw in SSH protocol message handling, a malicious actor could gain unauthorized access to affected systems and execute arbitrary commands without valid credentials. This issue is patched in versions OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20. A temporary workaround involves disabling the SSH server or to prevent access via firewall rules.

- [https://github.com/razureink/cve-2025-32433-erlang_ssh_rce_reproduction](https://github.com/razureink/cve-2025-32433-erlang_ssh_rce_reproduction) :  ![starts](https://img.shields.io/github/stars/razureink/cve-2025-32433-erlang_ssh_rce_reproduction.svg) ![forks](https://img.shields.io/github/forks/razureink/cve-2025-32433-erlang_ssh_rce_reproduction.svg)


## CVE-2025-32432
 Craft is a flexible, user-friendly CMS for creating custom digital experiences on the web and beyond. Starting from version 3.0.0-RC1 to before 3.9.15, 4.0.0-RC1 to before 4.14.15, and 5.0.0-RC1 to before 5.6.17, Craft is vulnerable to remote code execution. This is a high-impact, low-complexity attack vector. This issue has been patched in versions 3.9.15, 4.14.15, and 5.6.17, and is an additional fix for CVE-2023-41892.

- [https://github.com/theeomega/CVE-2025-32432-POC](https://github.com/theeomega/CVE-2025-32432-POC) :  ![starts](https://img.shields.io/github/stars/theeomega/CVE-2025-32432-POC.svg) ![forks](https://img.shields.io/github/forks/theeomega/CVE-2025-32432-POC.svg)


## CVE-2025-27520
 BentoML is a Python library for building online serving systems optimized for AI apps and model inference. A Remote Code Execution (RCE) vulnerability caused by insecure deserialization has been identified in the latest version (v1.4.2) of BentoML. It allows any unauthenticated user to execute arbitrary code on the server. It exists an unsafe code segment in serde.py. This vulnerability is fixed in 1.4.3.

- [https://github.com/electricsheep08/CVE-2025-27520](https://github.com/electricsheep08/CVE-2025-27520) :  ![starts](https://img.shields.io/github/stars/electricsheep08/CVE-2025-27520.svg) ![forks](https://img.shields.io/github/forks/electricsheep08/CVE-2025-27520.svg)


## CVE-2025-20701
 In the Airoha Bluetooth audio SDK, there is a possible way to pair Bluetooth audio device without user consent. This could lead to remote escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/x0jac0b0x/skullcandy-dime3-cve-2025-20701](https://github.com/x0jac0b0x/skullcandy-dime3-cve-2025-20701) :  ![starts](https://img.shields.io/github/stars/x0jac0b0x/skullcandy-dime3-cve-2025-20701.svg) ![forks](https://img.shields.io/github/forks/x0jac0b0x/skullcandy-dime3-cve-2025-20701.svg)


## CVE-2025-9242
 An Out-of-bounds Write vulnerability in WatchGuard Fireware OS may allow a remote unauthenticated attacker to execute arbitrary code. This vulnerability affects both the Mobile User VPN with IKEv2 and the Branch Office VPN using IKEv2 when configured with a dynamic gateway peer.This vulnerability affects Fireware OS 11.10.2 up to and including 11.12.4_Update1, 12.0 up to and including 12.11.3 and 2025.1.

- [https://github.com/UnusualGiraffe/Mass-Scanner-CVE-2025-9242](https://github.com/UnusualGiraffe/Mass-Scanner-CVE-2025-9242) :  ![starts](https://img.shields.io/github/stars/UnusualGiraffe/Mass-Scanner-CVE-2025-9242.svg) ![forks](https://img.shields.io/github/forks/UnusualGiraffe/Mass-Scanner-CVE-2025-9242.svg)


## CVE-2025-0282
 A stack-based buffer overflow in Ivanti Connect Secure before version 22.7R2.5, Ivanti Policy Secure before version 22.7R1.2, and Ivanti Neurons for ZTA gateways before version 22.7R2.3 allows a remote unauthenticated attacker to achieve remote code execution.

- [https://github.com/razureink/cve-2025-0282-ivanti_rce_reproduction](https://github.com/razureink/cve-2025-0282-ivanti_rce_reproduction) :  ![starts](https://img.shields.io/github/stars/razureink/cve-2025-0282-ivanti_rce_reproduction.svg) ![forks](https://img.shields.io/github/forks/razureink/cve-2025-0282-ivanti_rce_reproduction.svg)


## CVE-2024-49113
 Windows Lightweight Directory Access Protocol (LDAP) Denial of Service Vulnerability

- [https://github.com/razureink/cve-2024-49113-ldap_nightmare_reproduction](https://github.com/razureink/cve-2024-49113-ldap_nightmare_reproduction) :  ![starts](https://img.shields.io/github/stars/razureink/cve-2024-49113-ldap_nightmare_reproduction.svg) ![forks](https://img.shields.io/github/forks/razureink/cve-2024-49113-ldap_nightmare_reproduction.svg)


## CVE-2024-29973
The command injection vulnerability in the “setCookie” parameter in Zyxel NAS326 firmware versions before V5.21(AAZF.17)C0 and NAS542 firmware versions before V5.21(ABAG.14)C0 could allow an unauthenticated attacker to execute some operating system (OS) commands by sending a crafted HTTP POST request.

- [https://github.com/kernel364/CVE-2024-29973](https://github.com/kernel364/CVE-2024-29973) :  ![starts](https://img.shields.io/github/stars/kernel364/CVE-2024-29973.svg) ![forks](https://img.shields.io/github/forks/kernel364/CVE-2024-29973.svg)


## CVE-2024-27198
 In JetBrains TeamCity before 2023.11.4 authentication bypass allowing to perform admin actions was possible

- [https://github.com/kxom9ks/CVE-2024-27198](https://github.com/kxom9ks/CVE-2024-27198) :  ![starts](https://img.shields.io/github/stars/kxom9ks/CVE-2024-27198.svg) ![forks](https://img.shields.io/github/forks/kxom9ks/CVE-2024-27198.svg)


## CVE-2024-24919
 Potentially allowing an attacker to read certain information on Check Point Security Gateways once connected to the internet and enabled with remote Access VPN or Mobile Access Software Blades. A Security fix that mitigates this vulnerability is available.

- [https://github.com/kernel364/CVE-2024-24919](https://github.com/kernel364/CVE-2024-24919) :  ![starts](https://img.shields.io/github/stars/kernel364/CVE-2024-24919.svg) ![forks](https://img.shields.io/github/forks/kernel364/CVE-2024-24919.svg)


## CVE-2024-23897
 Jenkins 2.441 and earlier, LTS 2.426.2 and earlier does not disable a feature of its CLI command parser that replaces an '@' character followed by a file path in an argument with the file's contents, allowing unauthenticated attackers to read arbitrary files on the Jenkins controller file system.

- [https://github.com/razureink/cve-2024-23897-jenkins_lfi_reproduction](https://github.com/razureink/cve-2024-23897-jenkins_lfi_reproduction) :  ![starts](https://img.shields.io/github/stars/razureink/cve-2024-23897-jenkins_lfi_reproduction.svg) ![forks](https://img.shields.io/github/forks/razureink/cve-2024-23897-jenkins_lfi_reproduction.svg)


## CVE-2024-22019
 A vulnerability in Node.js HTTP servers allows an attacker to send a specially crafted HTTP request with chunked encoding, leading to resource exhaustion and denial of service (DoS). The server reads an unbounded number of bytes from a single connection, exploiting the lack of limitations on chunk extension bytes. The issue can cause CPU and network bandwidth exhaustion, bypassing standard safeguards like timeouts and body size limits.

- [https://github.com/kos2001/code-shield](https://github.com/kos2001/code-shield) :  ![starts](https://img.shields.io/github/stars/kos2001/code-shield.svg) ![forks](https://img.shields.io/github/forks/kos2001/code-shield.svg)


## CVE-2024-7593
 Incorrect implementation of an authentication algorithm in Ivanti vTM other than versions 22.2R1 or 22.7R2 allows a remote unauthenticated attacker to bypass authentication of the admin panel.

- [https://github.com/kernel364/CVE-2024-7593](https://github.com/kernel364/CVE-2024-7593) :  ![starts](https://img.shields.io/github/stars/kernel364/CVE-2024-7593.svg) ![forks](https://img.shields.io/github/forks/kernel364/CVE-2024-7593.svg)


## CVE-2024-6387
 A security regression (CVE-2006-5051) was discovered in OpenSSH's server (sshd). There is a race condition which can lead sshd to handle some signals in an unsafe manner. An unauthenticated, remote attacker may be able to trigger it by failing to authenticate within a set time period.

- [https://github.com/al7araziruby-jpg/CVE-2024-6387-OpenSSH-Analysis](https://github.com/al7araziruby-jpg/CVE-2024-6387-OpenSSH-Analysis) :  ![starts](https://img.shields.io/github/stars/al7araziruby-jpg/CVE-2024-6387-OpenSSH-Analysis.svg) ![forks](https://img.shields.io/github/forks/al7araziruby-jpg/CVE-2024-6387-OpenSSH-Analysis.svg)


## CVE-2024-3400
Cloud NGFW, Panorama appliances, and Prisma Access are not impacted by this vulnerability.

- [https://github.com/razureink/cve-2024-3400-panos_rce_reproduction](https://github.com/razureink/cve-2024-3400-panos_rce_reproduction) :  ![starts](https://img.shields.io/github/stars/razureink/cve-2024-3400-panos_rce_reproduction.svg) ![forks](https://img.shields.io/github/forks/razureink/cve-2024-3400-panos_rce_reproduction.svg)


## CVE-2024-2876
 The Email Subscribers by Icegram Express – Email Marketing, Newsletters, Automation for WordPress & WooCommerce plugin for WordPress is vulnerable to SQL Injection via the 'run' function of the 'IG_ES_Subscribers_Query' class in all versions up to, and including, 5.7.14 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query.  This makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database.

- [https://github.com/kernel364/CVE-2024-2876](https://github.com/kernel364/CVE-2024-2876) :  ![starts](https://img.shields.io/github/stars/kernel364/CVE-2024-2876.svg) ![forks](https://img.shields.io/github/forks/kernel364/CVE-2024-2876.svg)


## CVE-2024-1708
the ability to execute remote code or directly impact confidential data or critical systems.

- [https://github.com/razureink/cve-2024-1708-connectwise_rce_reproduction](https://github.com/razureink/cve-2024-1708-connectwise_rce_reproduction) :  ![starts](https://img.shields.io/github/stars/razureink/cve-2024-1708-connectwise_rce_reproduction.svg) ![forks](https://img.shields.io/github/forks/razureink/cve-2024-1708-connectwise_rce_reproduction.svg)

