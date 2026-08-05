# Update 2026-08-05
## CVE-2026-69083
 SiYuan versions before v3.7.3 contain SQL injection vulnerabilities in the fullTextSearchAssetContent endpoint reachable by unauthenticated users and publish RoleReader tokens. Attackers can execute arbitrary SQL on the read-write asset-content database via unescaped method parameters and REGEXP clauses to read, modify, or delete cross-notebook data.

- [https://github.com/0xdak/CVE-2026-69083_exploit](https://github.com/0xdak/CVE-2026-69083_exploit) :  ![starts](https://img.shields.io/github/stars/0xdak/CVE-2026-69083_exploit.svg) ![forks](https://img.shields.io/github/forks/0xdak/CVE-2026-69083_exploit.svg)


## CVE-2026-68771
 ComfyUI v0.23.0 contains an unsafe deserialization vulnerability in the LoadTrainingDataset node that allows unauthenticated remote attackers to execute arbitrary Python code by uploading a crafted pickle file and triggering its deserialization. Attackers can upload a malicious shard_*.pkl file via the unauthenticated POST /upload/image endpoint and then queue a workflow graph via POST /prompt referencing the uploaded file, causing torch.load to deserialize the attacker-controlled pickle payload using __reduce__ and execute arbitrary commands as the ComfyUI process user.

- [https://github.com/0xdak/CVE-2026-68771_exploit](https://github.com/0xdak/CVE-2026-68771_exploit) :  ![starts](https://img.shields.io/github/stars/0xdak/CVE-2026-68771_exploit.svg) ![forks](https://img.shields.io/github/forks/0xdak/CVE-2026-68771_exploit.svg)


## CVE-2026-67599
 ClearOS 7.9 contains an OS command injection vulnerability in the Log Viewer component that allows authenticated attackers to execute arbitrary commands by submitting unsanitized input through the filter parameter, which is interpolated directly into a shell command in File.php. Attackers can inject command substitution payloads into the filter parameter to execute arbitrary commands as the webconfig user, and due to extensive NOPASSWD sudo privileges granted to that user by default, immediately escalate to root.

- [https://github.com/LazyTitan33/CVE-2026-67599_ClearOS_RCE](https://github.com/LazyTitan33/CVE-2026-67599_ClearOS_RCE) :  ![starts](https://img.shields.io/github/stars/LazyTitan33/CVE-2026-67599_ClearOS_RCE.svg) ![forks](https://img.shields.io/github/forks/LazyTitan33/CVE-2026-67599_ClearOS_RCE.svg)


## CVE-2026-66066
 Action Pack is a framework for handling and responding to web requests. In versions prior to 7.2.3.2, 8.0.5.1 and 8.1.3.1, Active Storage does not disable libvips operations marked unsafe for untrusted content, allowing a crafted upload to invoke such an operation. Consuming applications are affected when configured to use libvips and accept image uploads from untrusted users. An unauthenticated attacker may exploit this behavior to read arbitrary files accessible to the Rails process, including environment variables and application secrets. Exposure of credentials such as secret_key_base or external-service tokens may enable remote code execution or lateral movement. This issue has been fixed in versions 7.2.3.2, 8.0.5.1 and 8.1.3.1.

- [https://github.com/HackSpeak/kindarails2shell-poc](https://github.com/HackSpeak/kindarails2shell-poc) :  ![starts](https://img.shields.io/github/stars/HackSpeak/kindarails2shell-poc.svg) ![forks](https://img.shields.io/github/forks/HackSpeak/kindarails2shell-poc.svg)


## CVE-2026-65321
 PyAthena prior to 3.35.4 contains a sql injection vulnerability that allows unauthenticated attackers to inject arbitrary SQL by exploiting improper quote-escaping in DefaultParameterFormatter.format(), which routes DELETE and CTAS statements to the _escape_hive function that backslash-escapes single quotes rather than doubling them. Because Athena and Trino do not treat backslashes as escape characters inside string literals, attacker-supplied input such as a single quote followed by SQL syntax causes the parser to terminate the string literal prematurely, enabling data exfiltration via UNION SELECT, execution of destructive statements, and attacker-controlled CTAS destination and content.

- [https://github.com/rahulreddykarne/CVE-2026-65321-pyathena](https://github.com/rahulreddykarne/CVE-2026-65321-pyathena) :  ![starts](https://img.shields.io/github/stars/rahulreddykarne/CVE-2026-65321-pyathena.svg) ![forks](https://img.shields.io/github/forks/rahulreddykarne/CVE-2026-65321-pyathena.svg)


## CVE-2026-64560
---truncated---

- [https://github.com/villager1314/CVE-2026-64560-Analysis](https://github.com/villager1314/CVE-2026-64560-Analysis) :  ![starts](https://img.shields.io/github/stars/villager1314/CVE-2026-64560-Analysis.svg) ![forks](https://img.shields.io/github/forks/villager1314/CVE-2026-64560-Analysis.svg)


## CVE-2026-64531
ownership and truncates on close failure.

- [https://github.com/HackSpeak/ovswrap-poc](https://github.com/HackSpeak/ovswrap-poc) :  ![starts](https://img.shields.io/github/stars/HackSpeak/ovswrap-poc.svg) ![forks](https://img.shields.io/github/forks/HackSpeak/ovswrap-poc.svg)


## CVE-2026-63720
 datamodel-code-generator prior to version 0.70.0 contains a code injection vulnerability that allows attackers who control input schemas to achieve remote code execution by supplying a malicious customBasePath value containing embedded newlines and a dot-free Python expression. The crafted value is emitted verbatim into a generated 'from ... import ...' statement without identifier validation, causing arbitrary Python code to execute when the generated module is imported.

- [https://github.com/rahulreddykarne/CVE-2026-63720-datamodel-code-generator](https://github.com/rahulreddykarne/CVE-2026-63720-datamodel-code-generator) :  ![starts](https://img.shields.io/github/stars/rahulreddykarne/CVE-2026-63720-datamodel-code-generator.svg) ![forks](https://img.shields.io/github/forks/rahulreddykarne/CVE-2026-63720-datamodel-code-generator.svg)


## CVE-2026-63563
Products intended for the Japanese market are not affected.

- [https://github.com/redr0nin/CVE-2026-63563](https://github.com/redr0nin/CVE-2026-63563) :  ![starts](https://img.shields.io/github/stars/redr0nin/CVE-2026-63563.svg) ![forks](https://img.shields.io/github/forks/redr0nin/CVE-2026-63563.svg)


## CVE-2026-63030
 WordPress 6.9.x before 6.9.5 and 7.0.x before 7.0.2 is affected by a REST API batch endpoint route confusion issue which, combined with the author__not_in WP_Query SQL Injection (CVE-2026-60137), could allow an attacker to perform SQL Injection and achieve Remote Code Execution.

- [https://github.com/Procjevt/CVE-2026-63030](https://github.com/Procjevt/CVE-2026-63030) :  ![starts](https://img.shields.io/github/stars/Procjevt/CVE-2026-63030.svg) ![forks](https://img.shields.io/github/forks/Procjevt/CVE-2026-63030.svg)


## CVE-2026-60137
 WordPress 6.8.x before 6.8.6, 6.9.x before 6.9.5, and 7.0.x before 7.0.2 does not properly sanitise the author__not_in parameter of WP_Query, which could allow SQL Injection when a plugin or theme passes untrusted input to the parameter.

- [https://github.com/AdarshThakur14777-cyber/CVE-2026-60137](https://github.com/AdarshThakur14777-cyber/CVE-2026-60137) :  ![starts](https://img.shields.io/github/stars/AdarshThakur14777-cyber/CVE-2026-60137.svg) ![forks](https://img.shields.io/github/forks/AdarshThakur14777-cyber/CVE-2026-60137.svg)


## CVE-2026-58048
 Improper preservation of SQL mode when renaming databases in  cPanel allows execution of SQL in root context.

- [https://github.com/imbas007/POC-CVE-2026-58048](https://github.com/imbas007/POC-CVE-2026-58048) :  ![starts](https://img.shields.io/github/stars/imbas007/POC-CVE-2026-58048.svg) ![forks](https://img.shields.io/github/forks/imbas007/POC-CVE-2026-58048.svg)


## CVE-2026-54121
 Improper authorization in Active Directory Certificate Services (AD CS) allows an authorized attacker to elevate privileges over a network.

- [https://github.com/AtlasVector/Certighost-CVE-2026-54121](https://github.com/AtlasVector/Certighost-CVE-2026-54121) :  ![starts](https://img.shields.io/github/stars/AtlasVector/Certighost-CVE-2026-54121.svg) ![forks](https://img.shields.io/github/forks/AtlasVector/Certighost-CVE-2026-54121.svg)
- [https://github.com/sam00/POC-CVE-2026-54121-Certighost](https://github.com/sam00/POC-CVE-2026-54121-Certighost) :  ![starts](https://img.shields.io/github/stars/sam00/POC-CVE-2026-54121-Certighost.svg) ![forks](https://img.shields.io/github/forks/sam00/POC-CVE-2026-54121-Certighost.svg)


## CVE-2026-52887
 NocoBase is an AI-powered no-code/low-code platform for building business applications and enterprise solutions. Prior to 2.0.61, NocoBase @nocobase/plugin-notification-in-app-message exposed GET /api/myInAppChannels:list, where the filter[latestMsgReceiveTimestamp][$lt] value was inserted into a Sequelize.literal() template string without escaping or parameter binding, allowing a signed-up authenticated user to run stacked PostgreSQL statements and potentially execute commands with COPY ... TO PROGRAM. This vulnerability is fixed in 2.0.61.

- [https://github.com/BiiTts/CVE-2026-52887-NocoBase-SQLi-RCE](https://github.com/BiiTts/CVE-2026-52887-NocoBase-SQLi-RCE) :  ![starts](https://img.shields.io/github/stars/BiiTts/CVE-2026-52887-NocoBase-SQLi-RCE.svg) ![forks](https://img.shields.io/github/forks/BiiTts/CVE-2026-52887-NocoBase-SQLi-RCE.svg)


## CVE-2026-48710
 Starlette is a lightweight ASGI framework/toolkit. Prior to version 1.0.1, the HTTP `Host` request header was not validated before being used to reconstruct `request.url`. Because the routing algorithm relies on the raw HTTP path while `request.url` is rebuilt from the `Host` header, a malformed header could make `request.url.path` differ from the path that was actually requested. Middleware and endpoints that apply security restrictions based on `request.url` (rather than the raw `scope` path) could therefore be bypassed. Users should upgrade to a version greater than or equal to version 1.0.1, which validates the `Host` header against the grammar of RFC 9112 §3.2 / RFC 3986 §3.2.2 when constructing `request.url` and falls back to `scope["server"]` for malformed values.

- [https://github.com/sb-ox/repro-OXDEV-77637-uv-workspace](https://github.com/sb-ox/repro-OXDEV-77637-uv-workspace) :  ![starts](https://img.shields.io/github/stars/sb-ox/repro-OXDEV-77637-uv-workspace.svg) ![forks](https://img.shields.io/github/forks/sb-ox/repro-OXDEV-77637-uv-workspace.svg)


## CVE-2026-46243
spnego_cred to request the key.

- [https://github.com/0xBlackash/CVE-2026-46243](https://github.com/0xBlackash/CVE-2026-46243) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-46243.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-46243.svg)


## CVE-2026-45585
No, if you are using TPM+PIN the vulnerability is not exploitable.

- [https://github.com/Donalhighnecked528/YellowKey-Bitlocker-CVE-2026-45585](https://github.com/Donalhighnecked528/YellowKey-Bitlocker-CVE-2026-45585) :  ![starts](https://img.shields.io/github/stars/Donalhighnecked528/YellowKey-Bitlocker-CVE-2026-45585.svg) ![forks](https://img.shields.io/github/forks/Donalhighnecked528/YellowKey-Bitlocker-CVE-2026-45585.svg)


## CVE-2026-43637
 Cornac before 2.6.0 contains a path traversal (Tar Slip) vulnerability that allows attackers to write arbitrary files outside the intended cache directory by supplying a crafted TAR archive containing ../ sequences, absolute paths, or symlink/hardlink entries to the _extract_archive() function in cornac/utils/download.py. Attackers can trigger this vulnerability through the built-in dataset loaders, which automatically download and extract archives, causing archive.extractall() to write files to arbitrary locations on the filesystem accessible to the running process.

- [https://github.com/rahulreddykarne/CVE-2026-43637-cornac](https://github.com/rahulreddykarne/CVE-2026-43637-cornac) :  ![starts](https://img.shields.io/github/stars/rahulreddykarne/CVE-2026-43637-cornac.svg) ![forks](https://img.shields.io/github/forks/rahulreddykarne/CVE-2026-43637-cornac.svg)


## CVE-2026-43499
  	changelog ]

- [https://github.com/jason5545/ghostlock-myron-tw](https://github.com/jason5545/ghostlock-myron-tw) :  ![starts](https://img.shields.io/github/stars/jason5545/ghostlock-myron-tw.svg) ![forks](https://img.shields.io/github/forks/jason5545/ghostlock-myron-tw.svg)


## CVE-2026-42945
 NGINX Plus and NGINX Open Source have a vulnerability in the ngx_http_rewrite_module module. This vulnerability exists when the rewrite directive is followed by a rewrite, if, or set directive and an unnamed Perl-Compatible Regular Expression (PCRE) capture (for example, $1, $2) with a replacement string that includes a question mark (?). An unauthenticated attacker along with conditions beyond its control can exploit this vulnerability by sending crafted HTTP requests. This may cause a heap buffer overflow in the NGINX worker process leading to a restart. Additionally, attackers can execute code on systems with Address Space Layout Randomization (ASLR) disabled or when the attacker can bypass ASLR.  Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/tal7aouy/nginx-cve-2026-42945](https://github.com/tal7aouy/nginx-cve-2026-42945) :  ![starts](https://img.shields.io/github/stars/tal7aouy/nginx-cve-2026-42945.svg) ![forks](https://img.shields.io/github/forks/tal7aouy/nginx-cve-2026-42945.svg)


## CVE-2026-42826
 Exposure of sensitive information to an unauthorized actor in Azure DevOps allows an unauthorized attacker to disclose information over a network.

- [https://github.com/sam00/POC-CVE-2026-42826-2026-42826-Microsoft-Azure-DevOps-Information-Disclosure-Vulnerability](https://github.com/sam00/POC-CVE-2026-42826-2026-42826-Microsoft-Azure-DevOps-Information-Disclosure-Vulnerability) :  ![starts](https://img.shields.io/github/stars/sam00/POC-CVE-2026-42826-2026-42826-Microsoft-Azure-DevOps-Information-Disclosure-Vulnerability.svg) ![forks](https://img.shields.io/github/forks/sam00/POC-CVE-2026-42826-2026-42826-Microsoft-Azure-DevOps-Information-Disclosure-Vulnerability.svg)


## CVE-2026-38444
 osTicket v1.18.3 is vulnerable to Stored Cross-Site Scripting (XSS) via the email From-header display name. The value is extracted without sanitization in include/class.mailparse.php and stored raw in the poster field of ost_thread_entry. When an unauthenticated attacker sends a reply email to an existing ticket from an unregistered address with an XSS payload in the From display name.

- [https://github.com/fr3akhacks/cve-disclosures](https://github.com/fr3akhacks/cve-disclosures) :  ![starts](https://img.shields.io/github/stars/fr3akhacks/cve-disclosures.svg) ![forks](https://img.shields.io/github/forks/fr3akhacks/cve-disclosures.svg)


## CVE-2026-33937
 Handlebars provides the power necessary to let users build semantic templates. In versions 4.0.0 through 4.7.8, `Handlebars.compile()` accepts a pre-parsed AST object in addition to a template string. The `value` field of a `NumberLiteral` AST node is emitted directly into the generated JavaScript without quoting or sanitization. An attacker who can supply a crafted AST to `compile()` can therefore inject and execute arbitrary JavaScript, leading to Remote Code Execution on the server. Version 4.7.9 fixes the issue. Some workarounds are available. Validate input type before calling `Handlebars.compile()`; ensure the argument is always a  `string`, never a plain object or JSON-deserialized value. Use the Handlebars runtime-only build (`handlebars/runtime`) on the server if templates are pre-compiled at build time; `compile()` will be unavailable.

- [https://github.com/c0gnit00/CVE-2026-33937](https://github.com/c0gnit00/CVE-2026-33937) :  ![starts](https://img.shields.io/github/stars/c0gnit00/CVE-2026-33937.svg) ![forks](https://img.shields.io/github/forks/c0gnit00/CVE-2026-33937.svg)


## CVE-2026-32621
 Apollo Federation is an architecture for declaratively composing APIs into a unified graph. Prior to 2.9.6, 2.10.5, 2.11.6, 2.12.3, and 2.13.2, a vulnerability exists in query plan execution within the gateway that may allow pollution of Object.prototype in certain scenarios. A malicious client may be able to pollute Object.prototype in gateway directly by crafting operations with field aliases and/or variable names that target prototype-inheritable properties. Alternatively, if a subgraph were to be compromised by a malicious actor, they may be able to pollute Object.prototype in gateway by crafting JSON response payloads that target prototype-inheritable properties. This vulnerability is fixed in 2.9.6, 2.10.5, 2.11.6, 2.12.3, and 2.13.2.

- [https://github.com/sam00/POC-CVE-2026-32621-Apollo-Federation-XSS-Vulnerability](https://github.com/sam00/POC-CVE-2026-32621-Apollo-Federation-XSS-Vulnerability) :  ![starts](https://img.shields.io/github/stars/sam00/POC-CVE-2026-32621-Apollo-Federation-XSS-Vulnerability.svg) ![forks](https://img.shields.io/github/forks/sam00/POC-CVE-2026-32621-Apollo-Federation-XSS-Vulnerability.svg)


## CVE-2026-29000
 pac4j-jwt versions prior to 4.5.9, 5.7.9, and 6.3.3 contain an authentication bypass vulnerability in JwtAuthenticator when processing encrypted JWTs that allows remote attackers to forge authentication tokens. Attackers who possess the server's RSA public key can create a JWE-wrapped PlainJWT with arbitrary subject and role claims, bypassing signature verification to authenticate as any user including administrators.

- [https://github.com/xiaoqiMikko/pac4j-check](https://github.com/xiaoqiMikko/pac4j-check) :  ![starts](https://img.shields.io/github/stars/xiaoqiMikko/pac4j-check.svg) ![forks](https://img.shields.io/github/forks/xiaoqiMikko/pac4j-check.svg)


## CVE-2026-26114
 Deserialization of untrusted data in Microsoft Office SharePoint allows an authorized attacker to execute code over a network.

- [https://github.com/fazilbaig1/CVE-2026-26114-Patch](https://github.com/fazilbaig1/CVE-2026-26114-Patch) :  ![starts](https://img.shields.io/github/stars/fazilbaig1/CVE-2026-26114-Patch.svg) ![forks](https://img.shields.io/github/forks/fazilbaig1/CVE-2026-26114-Patch.svg)


## CVE-2026-21020
 Improper export of android application components in OmaCP prior to SMR May-2026 Release 1 allows local attackers to trigger privileged functions.

- [https://github.com/George0Papasotiriou/CVE-2026-21020-Protobuf-Message-Parsing-Polymorphic-Deserialization-Vulnerability](https://github.com/George0Papasotiriou/CVE-2026-21020-Protobuf-Message-Parsing-Polymorphic-Deserialization-Vulnerability) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2026-21020-Protobuf-Message-Parsing-Polymorphic-Deserialization-Vulnerability.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2026-21020-Protobuf-Message-Parsing-Polymorphic-Deserialization-Vulnerability.svg)


## CVE-2026-21019
 Improper input validation in FacAtFunction in Galaxy Watch prior to SMR May-2026 Release 1 allows local attacker to execute arbitrary code with system privilege.

- [https://github.com/George0Papasotiriou/CVE-2026-21019-Kubernetes-CronJob-Suspended-Execution-via-Time-Manipulation](https://github.com/George0Papasotiriou/CVE-2026-21019-Kubernetes-CronJob-Suspended-Execution-via-Time-Manipulation) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2026-21019-Kubernetes-CronJob-Suspended-Execution-via-Time-Manipulation.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2026-21019-Kubernetes-CronJob-Suspended-Execution-via-Time-Manipulation.svg)


## CVE-2026-21018
 Out-of-bounds write in SveService prior to SMR May-2026 Release 1 allows local privileged attackers to execute arbitrary code.

- [https://github.com/George0Papasotiriou/CVE-2026-21018-OPC-UA-Authentication-Bypass-via-None-Security-Policy](https://github.com/George0Papasotiriou/CVE-2026-21018-OPC-UA-Authentication-Bypass-via-None-Security-Policy) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2026-21018-OPC-UA-Authentication-Bypass-via-None-Security-Policy.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2026-21018-OPC-UA-Authentication-Bypass-via-None-Security-Policy.svg)


## CVE-2026-21017
 Improper handling of insufficient privileges in SecTelephonyProvider prior to SMR Jun-2026 Release 1 allows local attackers to access privileged files.

- [https://github.com/George0Papasotiriou/CVE-2026-21017-LDAP-Anonymous-Bind-Privilege-Escalation](https://github.com/George0Papasotiriou/CVE-2026-21017-LDAP-Anonymous-Bind-Privilege-Escalation) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2026-21017-LDAP-Anonymous-Bind-Privilege-Escalation.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2026-21017-LDAP-Anonymous-Bind-Privilege-Escalation.svg)


## CVE-2026-21016
 Incorrect privilege assignment in LocationManager prior to SMR May-2026 Release 1 allows local attackers to access sensitive information.

- [https://github.com/George0Papasotiriou/CVE-2026-21016-Malicious-PyPI-Package-Install-Hook-setup.py-Execution-](https://github.com/George0Papasotiriou/CVE-2026-21016-Malicious-PyPI-Package-Install-Hook-setup.py-Execution-) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2026-21016-Malicious-PyPI-Package-Install-Hook-setup.py-Execution-.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2026-21016-Malicious-PyPI-Package-Install-Hook-setup.py-Execution-.svg)


## CVE-2026-21015
 Incorrect default permissions in FactoryCamera prior to SMR May-2026 Release 1 allows local attacker to access unique identifier.

- [https://github.com/George0Papasotiriou/CVE-2026-21015-PHP-Filter-Chain-Arbitrary-File-Read](https://github.com/George0Papasotiriou/CVE-2026-21015-PHP-Filter-Chain-Arbitrary-File-Read) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2026-21015-PHP-Filter-Chain-Arbitrary-File-Read.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2026-21015-PHP-Filter-Chain-Arbitrary-File-Read.svg)


## CVE-2026-21014
 Improper access control in Samsung Camera prior to version 16.5.00.28 allows local attacker to access location data. User interaction is required for triggering this vulnerability.

- [https://github.com/George0Papasotiriou/CVE-2026-21014-CAN-Bus-Frame-Replay-Attack-on-Automotive-ECU](https://github.com/George0Papasotiriou/CVE-2026-21014-CAN-Bus-Frame-Replay-Attack-on-Automotive-ECU) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2026-21014-CAN-Bus-Frame-Replay-Attack-on-Automotive-ECU.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2026-21014-CAN-Bus-Frame-Replay-Attack-on-Automotive-ECU.svg)


## CVE-2026-21013
 Incorrect default permission in Galaxy Wearable prior to version 2.2.68.26 allows local attackers to access sensitive information.

- [https://github.com/George0Papasotiriou/CVE-2026-21013-PDF-JavaScript-Injection-via-Embedded-Script](https://github.com/George0Papasotiriou/CVE-2026-21013-PDF-JavaScript-Injection-via-Embedded-Script) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2026-21013-PDF-JavaScript-Injection-via-Embedded-Script.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2026-21013-PDF-JavaScript-Injection-via-Embedded-Script.svg)


## CVE-2026-21012
 External control of file name in AODManager prior to SMR Apr-2026 Release 1 allows privileged local attacker to create file with system privilege.

- [https://github.com/George0Papasotiriou/CVE-2026-21012-Rust-serde-Deserialization-of-Untrusted-Enum-Variant-Injection-](https://github.com/George0Papasotiriou/CVE-2026-21012-Rust-serde-Deserialization-of-Untrusted-Enum-Variant-Injection-) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2026-21012-Rust-serde-Deserialization-of-Untrusted-Enum-Variant-Injection-.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2026-21012-Rust-serde-Deserialization-of-Untrusted-Enum-Variant-Injection-.svg)


## CVE-2026-21011
 Incorrect privilege assignment in Bluetooth in Maintenance mode prior to SMR Apr-2026 Release 1 allows physical attackers to bypass Extend Unlock.

- [https://github.com/George0Papasotiriou/CVE-2026-21011-Log4j-style-JNDI-Injection-in-Custom-Logger-Simulated-](https://github.com/George0Papasotiriou/CVE-2026-21011-Log4j-style-JNDI-Injection-in-Custom-Logger-Simulated-) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2026-21011-Log4j-style-JNDI-Injection-in-Custom-Logger-Simulated-.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2026-21011-Log4j-style-JNDI-Injection-in-Custom-Logger-Simulated-.svg)


## CVE-2026-21010
 Improper input validation in Retail Mode prior to SMR Apr-2026 Release 1 allows local attackers to trigger privileged functions.

- [https://github.com/George0Papasotiriou/CVE-2026-21010-VoIP-SIP-Digest-Authentication-Replay](https://github.com/George0Papasotiriou/CVE-2026-21010-VoIP-SIP-Digest-Authentication-Replay) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2026-21010-VoIP-SIP-Digest-Authentication-Replay.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2026-21010-VoIP-SIP-Digest-Authentication-Replay.svg)


## CVE-2026-21009
 Improper check for exceptional conditions in Recents prior to SMR Apr-2026 Release 1 allows physical attacker to bypass App Pinning.

- [https://github.com/George0Papasotiriou/CVE-2026-21009-ECDSA-Nonce-Reuse-in-IoT-Firmware-Signing](https://github.com/George0Papasotiriou/CVE-2026-21009-ECDSA-Nonce-Reuse-in-IoT-Firmware-Signing) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2026-21009-ECDSA-Nonce-Reuse-in-IoT-Firmware-Signing.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2026-21009-ECDSA-Nonce-Reuse-in-IoT-Firmware-Signing.svg)


## CVE-2026-21008
 Exposure of sensitive information in S Share prior to SMR Apr-2026 Release 1 allows adjacent attacker to access sensitive information.

- [https://github.com/George0Papasotiriou/CVE-2026-21008-Kubernetes-Service-Account-Token-Mounted-in-HostPath](https://github.com/George0Papasotiriou/CVE-2026-21008-Kubernetes-Service-Account-Token-Mounted-in-HostPath) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2026-21008-Kubernetes-Service-Account-Token-Mounted-in-HostPath.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2026-21008-Kubernetes-Service-Account-Token-Mounted-in-HostPath.svg)


## CVE-2026-21007
 Improper check for exceptional conditions in Device Care prior to SMR Apr-2026 Release 1 allows physical attackers to bypass Knox Guard.

- [https://github.com/George0Papasotiriou/CVE-2026-21007-GPU-Driver-ioctl-Race-Condition-Kernel-Memory-Mapping-](https://github.com/George0Papasotiriou/CVE-2026-21007-GPU-Driver-ioctl-Race-Condition-Kernel-Memory-Mapping-) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2026-21007-GPU-Driver-ioctl-Race-Condition-Kernel-Memory-Mapping-.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2026-21007-GPU-Driver-ioctl-Race-Condition-Kernel-Memory-Mapping-.svg)


## CVE-2026-21006
 Improper access control in Samsung DeX prior to SMR Apr-2026 Release 1 allows physical attackers to access to hidden notification contents.

- [https://github.com/George0Papasotiriou/CVE-2026-21006-Zigbee-Light-Link-Factory-Reset-Exploit](https://github.com/George0Papasotiriou/CVE-2026-21006-Zigbee-Light-Link-Factory-Reset-Exploit) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2026-21006-Zigbee-Light-Link-Factory-Reset-Exploit.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2026-21006-Zigbee-Light-Link-Factory-Reset-Exploit.svg)


## CVE-2026-21005
 Path traversal in Smart Switch prior to version 3.7.69.15 allows adjacent attackers to overwrite arbitrary files with Smart Switch privilege.

- [https://github.com/George0Papasotiriou/CVE-2026-21005-Docker-Registry-V2-Schema-1-Image-Poisoning](https://github.com/George0Papasotiriou/CVE-2026-21005-Docker-Registry-V2-Schema-1-Image-Poisoning) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2026-21005-Docker-Registry-V2-Schema-1-Image-Poisoning.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2026-21005-Docker-Registry-V2-Schema-1-Image-Poisoning.svg)


## CVE-2026-21004
 Improper authentication in Smart Switch prior to version 3.7.69.15 allows adjacent attackers to trigger a denial of service.

- [https://github.com/George0Papasotiriou/CVE-2026-21004-SQLite-FTS3-Match-Infoleak-via-Query-Crafting](https://github.com/George0Papasotiriou/CVE-2026-21004-SQLite-FTS3-Match-Infoleak-via-Query-Crafting) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2026-21004-SQLite-FTS3-Match-Infoleak-via-Query-Crafting.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2026-21004-SQLite-FTS3-Match-Infoleak-via-Query-Crafting.svg)


## CVE-2026-21003
 Improper input validation in data related to network restrictions prior to SMR Apr-2026 Release 1 allows physical attackers to bypass the restrictions.

- [https://github.com/George0Papasotiriou/CVE-2026-21003-JWT-none-Algorithm-Bypass-via-kid-Header-Omission](https://github.com/George0Papasotiriou/CVE-2026-21003-JWT-none-Algorithm-Bypass-via-kid-Header-Omission) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2026-21003-JWT-none-Algorithm-Bypass-via-kid-Header-Omission.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2026-21003-JWT-none-Algorithm-Bypass-via-kid-Header-Omission.svg)


## CVE-2026-21002
 Improper verification of cryptographic signature in Galaxy Store prior to version 4.6.03.8 allows local attacker to install arbitrary application.

- [https://github.com/George0Papasotiriou/CVE-2026-21002-Serverless-Cold-Start-Credential-Leakage-via-Reused-tmp](https://github.com/George0Papasotiriou/CVE-2026-21002-Serverless-Cold-Start-Credential-Leakage-via-Reused-tmp) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2026-21002-Serverless-Cold-Start-Credential-Leakage-via-Reused-tmp.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2026-21002-Serverless-Cold-Start-Credential-Leakage-via-Reused-tmp.svg)


## CVE-2026-21001
 Path traversal in Galaxy Store prior to version 4.6.03.8 allows local attacker to create file with Galaxy Store privilege.

- [https://github.com/George0Papasotiriou/CVE-2026-21001-WebAssembly-Linear-Memory-OOB-via-Table-Index-Confusion](https://github.com/George0Papasotiriou/CVE-2026-21001-WebAssembly-Linear-Memory-OOB-via-Table-Index-Confusion) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2026-21001-WebAssembly-Linear-Memory-OOB-via-Table-Index-Confusion.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2026-21001-WebAssembly-Linear-Memory-OOB-via-Table-Index-Confusion.svg)


## CVE-2026-18718
 Ghidra contains an arbitrary code execution vulnerability in the Swift demangler analyzer that allows an attacker to execute arbitrary binaries by supplying a malicious Ghidra project with a crafted Swift tool directory path. When a victim opens the attacker-supplied project, SwiftDemanglerAnalyzer restores the persisted Swift binary directory from project state and SwiftNativeDemangler executes the resolved binary without integrity or signature verification, causing attacker-controlled executables to run under the Ghidra process user with no prompt or confirmation.

- [https://github.com/sn0x-sharma/CVE-2026-18718](https://github.com/sn0x-sharma/CVE-2026-18718) :  ![starts](https://img.shields.io/github/stars/sn0x-sharma/CVE-2026-18718.svg) ![forks](https://img.shields.io/github/forks/sn0x-sharma/CVE-2026-18718.svg)


## CVE-2026-16723
 A remote code execution (RCE) vulnerability exists in fastjson 1.2.68 through 1.2.83. This vulnerability is exploitable under fastjson's stock default configuration — no AutoType enablement required, no classpath gadget required.

- [https://github.com/xiaoqiMikko/fastjson-check](https://github.com/xiaoqiMikko/fastjson-check) :  ![starts](https://img.shields.io/github/stars/xiaoqiMikko/fastjson-check.svg) ![forks](https://img.shields.io/github/forks/xiaoqiMikko/fastjson-check.svg)


## CVE-2026-16232
 An authentication bypass vulnerability in the Check Point SmartConsole login process allows an unauthenticated remote attacker to obtain an application login token and use it to authenticate with full administrative privileges. Successful exploitation allows the attacker to modify security policies and security configurations. Remote exploitation requires internet access to the Management Server IP address and a configuration that does not restrict Trusted Clients. Check Point is aware that this vulnerability is being exploited and has affected a very small number of customers.

- [https://github.com/HackSpeak/checkpoint-smartconsole-poc](https://github.com/HackSpeak/checkpoint-smartconsole-poc) :  ![starts](https://img.shields.io/github/stars/HackSpeak/checkpoint-smartconsole-poc.svg) ![forks](https://img.shields.io/github/forks/HackSpeak/checkpoint-smartconsole-poc.svg)


## CVE-2026-15409
 A Server-side request forgery (SSRF) vulnerability has been identified in the SMA1000 Appliance Work Place interface. A remote unauthenticated attacker could potentially cause the appliance to make requests to unintended location.

- [https://github.com/Ch4120N/CVE-2026-15409](https://github.com/Ch4120N/CVE-2026-15409) :  ![starts](https://img.shields.io/github/stars/Ch4120N/CVE-2026-15409.svg) ![forks](https://img.shields.io/github/forks/Ch4120N/CVE-2026-15409.svg)


## CVE-2026-12940
 IBM Langflow OSS 1.0.0 through 1.10.1  are vulnerable to unauthenticated remote code execution via environment variable injection in the MCP (Model Context Protocol) stdio launcher. The vulnerability exists in src/lfx/src/lfx/base/mcp/util.py where the DANGEROUS_ENV_VARS blocklist fails to include SHELLOPTS , BASHOPTS , and PS4 environment variables.

- [https://github.com/BiiTts/CVE-2026-12940-Langflow-Unauth-RCE](https://github.com/BiiTts/CVE-2026-12940-Langflow-Unauth-RCE) :  ![starts](https://img.shields.io/github/stars/BiiTts/CVE-2026-12940-Langflow-Unauth-RCE.svg) ![forks](https://img.shields.io/github/forks/BiiTts/CVE-2026-12940-Langflow-Unauth-RCE.svg)


## CVE-2026-11120
 Insufficient validation of untrusted input in Enterprise Reporting in Google Chrome prior to 149.0.7827.53 allowed a remote attacker who had compromised the renderer process to potentially perform a sandbox escape via a crafted HTML page. (Chromium security severity: Medium)

- [https://github.com/George0Papasotiriou/CVE-2026-11120-Command-Injection-via-Git-URL-in-CI-CD-Pipeline](https://github.com/George0Papasotiriou/CVE-2026-11120-Command-Injection-via-Git-URL-in-CI-CD-Pipeline) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2026-11120-Command-Injection-via-Git-URL-in-CI-CD-Pipeline.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2026-11120-Command-Injection-via-Git-URL-in-CI-CD-Pipeline.svg)


## CVE-2026-11119
 Inappropriate implementation in GPU in Google Chrome on Android prior to 149.0.7827.53 allowed a remote attacker who had compromised the renderer process to potentially perform a sandbox escape via a crafted HTML page. (Chromium security severity: Medium)

- [https://github.com/George0Papasotiriou/CVE-2026-11119-Padding-Oracle-Attack-on-CBC-Mode-Encryption](https://github.com/George0Papasotiriou/CVE-2026-11119-Padding-Oracle-Attack-on-CBC-Mode-Encryption) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2026-11119-Padding-Oracle-Attack-on-CBC-Mode-Encryption.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2026-11119-Padding-Oracle-Attack-on-CBC-Mode-Encryption.svg)


## CVE-2026-11118
 Use after free in WebRTC in Google Chrome prior to 149.0.7827.53 allowed a remote attacker to execute arbitrary code inside a sandbox via a crafted HTML page. (Chromium security severity: Medium)

- [https://github.com/George0Papasotiriou/CVE-2026-11118-HTTP-2-Rapid-Reset-DDoS](https://github.com/George0Papasotiriou/CVE-2026-11118-HTTP-2-Rapid-Reset-DDoS) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2026-11118-HTTP-2-Rapid-Reset-DDoS.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2026-11118-HTTP-2-Rapid-Reset-DDoS.svg)


## CVE-2026-11117
 Use after free in Views in Google Chrome on Windows prior to 149.0.7827.53 allowed a remote attacker to execute arbitrary code via a crafted HTML page. (Chromium security severity: Medium)

- [https://github.com/George0Papasotiriou/CVE-2026-11117-WPA2-4-Way-Handshake-Reinstallation-KRACK-Sim-](https://github.com/George0Papasotiriou/CVE-2026-11117-WPA2-4-Way-Handshake-Reinstallation-KRACK-Sim-) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2026-11117-WPA2-4-Way-Handshake-Reinstallation-KRACK-Sim-.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2026-11117-WPA2-4-Way-Handshake-Reinstallation-KRACK-Sim-.svg)


## CVE-2026-11116
 Use after free in Chromoting in Google Chrome prior to 149.0.7827.53 allowed a remote attacker to execute arbitrary code via malicious network traffic. (Chromium security severity: Medium)

- [https://github.com/George0Papasotiriou/CVE-2026-11116-SNMPv3-Authentication-Bypass-via-Default-EngineID](https://github.com/George0Papasotiriou/CVE-2026-11116-SNMPv3-Authentication-Bypass-via-Default-EngineID) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2026-11116-SNMPv3-Authentication-Bypass-via-Default-EngineID.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2026-11116-SNMPv3-Authentication-Bypass-via-Default-EngineID.svg)


## CVE-2026-11115
 Use after free in Updater in Google Chrome on Windows prior to 149.0.7827.53 allowed a local attacker to perform OS-level privilege escalation via a malicious file. (Chromium security severity: Medium)

- [https://github.com/George0Papasotiriou/CVE-2026-11115-Database-Connection-String-Injection-via-Env-Variable](https://github.com/George0Papasotiriou/CVE-2026-11115-Database-Connection-String-Injection-via-Env-Variable) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2026-11115-Database-Connection-String-Injection-via-Env-Variable.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2026-11115-Database-Connection-String-Injection-via-Env-Variable.svg)


## CVE-2026-11114
 Use after free in Device Trust in Google Chrome on Mac prior to 149.0.7827.53 allowed a remote attacker who had compromised the renderer process to potentially perform a sandbox escape via a crafted HTML page. (Chromium security severity: Medium)

- [https://github.com/George0Papasotiriou/CVE-2026-11114-Node.js-vm-Sandbox-Escape-via-Proxy](https://github.com/George0Papasotiriou/CVE-2026-11114-Node.js-vm-Sandbox-Escape-via-Proxy) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2026-11114-Node.js-vm-Sandbox-Escape-via-Proxy.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2026-11114-Node.js-vm-Sandbox-Escape-via-Proxy.svg)


## CVE-2026-11113
 Insufficient validation of untrusted input in ANGLE in Google Chrome prior to 149.0.7827.53 allowed a remote attacker who had compromised the renderer process to potentially perform a sandbox escape via a crafted HTML page. (Chromium security severity: Medium)

- [https://github.com/George0Papasotiriou/CVE-2026-11113-SMTP-Header-Injection-in-Contact-Form](https://github.com/George0Papasotiriou/CVE-2026-11113-SMTP-Header-Injection-in-Contact-Form) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2026-11113-SMTP-Header-Injection-in-Contact-Form.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2026-11113-SMTP-Header-Injection-in-Contact-Form.svg)


## CVE-2026-11112
 Insufficient validation of untrusted input in Chromoting in Google Chrome on Linux prior to 149.0.7827.53 allowed a remote attacker who had compromised the renderer process to potentially perform a sandbox escape via a crafted Chrome Extension. (Chromium security severity: Medium)

- [https://github.com/George0Papasotiriou/CVE-2026-11112-XXE-via-SVG-Image-Upload](https://github.com/George0Papasotiriou/CVE-2026-11112-XXE-via-SVG-Image-Upload) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2026-11112-XXE-via-SVG-Image-Upload.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2026-11112-XXE-via-SVG-Image-Upload.svg)


## CVE-2026-11111
 Out of bounds read in ANGLE in Google Chrome prior to 149.0.7827.53 allowed a remote attacker to perform an out of bounds memory read via a crafted HTML page. (Chromium security severity: Medium)

- [https://github.com/George0Papasotiriou/CVE-2026-11111-TOCTOU-in-File-Permission-Check-Before-Open](https://github.com/George0Papasotiriou/CVE-2026-11111-TOCTOU-in-File-Permission-Check-Before-Open) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2026-11111-TOCTOU-in-File-Permission-Check-Before-Open.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2026-11111-TOCTOU-in-File-Permission-Check-Before-Open.svg)


## CVE-2026-11110
 Uninitialized Use in ANGLE in Google Chrome prior to 149.0.7827.53 allowed a remote attacker to leak cross-origin data via a crafted HTML page. (Chromium security severity: Medium)

- [https://github.com/George0Papasotiriou/CVE-2026-11110-AES-GCM-Nonce-Reuse-Leading-to-Key-Recovery](https://github.com/George0Papasotiriou/CVE-2026-11110-AES-GCM-Nonce-Reuse-Leading-to-Key-Recovery) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2026-11110-AES-GCM-Nonce-Reuse-Leading-to-Key-Recovery.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2026-11110-AES-GCM-Nonce-Reuse-Leading-to-Key-Recovery.svg)


## CVE-2026-11109
 Uninitialized Use in ANGLE in Google Chrome prior to 149.0.7827.53 allowed a remote attacker to leak cross-origin data via a crafted HTML page. (Chromium security severity: Medium)

- [https://github.com/George0Papasotiriou/CVE-2026-11109-Bluetooth-Classic-KNOB-Attack-Key-Negotiation-of-Bluetooth-](https://github.com/George0Papasotiriou/CVE-2026-11109-Bluetooth-Classic-KNOB-Attack-Key-Negotiation-of-Bluetooth-) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2026-11109-Bluetooth-Classic-KNOB-Attack-Key-Negotiation-of-Bluetooth-.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2026-11109-Bluetooth-Classic-KNOB-Attack-Key-Negotiation-of-Bluetooth-.svg)


## CVE-2026-11108
 Inappropriate implementation in NFC in Google Chrome on Android prior to 149.0.7827.53 allowed a remote attacker to perform privilege escalation via a crafted HTML page. (Chromium security severity: Medium)

- [https://github.com/George0Papasotiriou/CVE-2026-11108-Integer-Overflow-in-Memory-Allocator-kmalloc-Sim-](https://github.com/George0Papasotiriou/CVE-2026-11108-Integer-Overflow-in-Memory-Allocator-kmalloc-Sim-) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2026-11108-Integer-Overflow-in-Memory-Allocator-kmalloc-Sim-.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2026-11108-Integer-Overflow-in-Memory-Allocator-kmalloc-Sim-.svg)


## CVE-2026-11107
 Inappropriate implementation in Downloads in Google Chrome prior to 149.0.7827.53 allowed a remote attacker to perform UI spoofing via a crafted HTML page. (Chromium security severity: Medium)

- [https://github.com/George0Papasotiriou/CVE-2026-11107-Insecure-Direct-Object-Reference-with-Predictable-UUIDv1](https://github.com/George0Papasotiriou/CVE-2026-11107-Insecure-Direct-Object-Reference-with-Predictable-UUIDv1) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2026-11107-Insecure-Direct-Object-Reference-with-Predictable-UUIDv1.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2026-11107-Insecure-Direct-Object-Reference-with-Predictable-UUIDv1.svg)


## CVE-2026-11106
 Inappropriate implementation in Media in Google Chrome prior to 149.0.7827.53 allowed a remote attacker to leak cross-origin data via a crafted HTML page. (Chromium security severity: Medium)

- [https://github.com/George0Papasotiriou/CVE-2026-11106-DNS-Zone-Transfer-AXFR-Information-Disclosure](https://github.com/George0Papasotiriou/CVE-2026-11106-DNS-Zone-Transfer-AXFR-Information-Disclosure) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2026-11106-DNS-Zone-Transfer-AXFR-Information-Disclosure.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2026-11106-DNS-Zone-Transfer-AXFR-Information-Disclosure.svg)


## CVE-2026-11105
 Insufficient validation of untrusted input in WebUI in Google Chrome prior to 149.0.7827.53 allowed a remote attacker who had compromised the renderer process to leak cross-origin data via a crafted HTML page. (Chromium security severity: Medium)

- [https://github.com/George0Papasotiriou/CVE-2026-11105-Stack-Buffer-Overflow-in-Custom-Base64-Decoder](https://github.com/George0Papasotiriou/CVE-2026-11105-Stack-Buffer-Overflow-in-Custom-Base64-Decoder) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2026-11105-Stack-Buffer-Overflow-in-Custom-Base64-Decoder.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2026-11105-Stack-Buffer-Overflow-in-Custom-Base64-Decoder.svg)


## CVE-2026-11104
 Uninitialized Use in ANGLE in Google Chrome prior to 149.0.7827.53 allowed a remote attacker who had compromised the renderer process to obtain potentially sensitive information from process memory via a crafted HTML page. (Chromium security severity: Medium)

- [https://github.com/George0Papasotiriou/CVE-2026-11104-Python-SSTI-via-Jinja2-attr-Filter-Bypass](https://github.com/George0Papasotiriou/CVE-2026-11104-Python-SSTI-via-Jinja2-attr-Filter-Bypass) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2026-11104-Python-SSTI-via-Jinja2-attr-Filter-Bypass.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2026-11104-Python-SSTI-via-Jinja2-attr-Filter-Bypass.svg)


## CVE-2026-11103
 Inappropriate implementation in Installer in Google Chrome on Windows prior to 149.0.7827.53 allowed a local attacker to perform OS-level privilege escalation via a malicious file. (Chromium security severity: Medium)

- [https://github.com/George0Papasotiriou/CVE-2026-11103-GraphQL-Batching-Alias-Rate-Limit-Bypass](https://github.com/George0Papasotiriou/CVE-2026-11103-GraphQL-Batching-Alias-Rate-Limit-Bypass) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2026-11103-GraphQL-Batching-Alias-Rate-Limit-Bypass.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2026-11103-GraphQL-Batching-Alias-Rate-Limit-Bypass.svg)


## CVE-2026-11102
 Inappropriate implementation in Isolated Web Apps in Google Chrome prior to 149.0.7827.53 allowed a remote attacker to execute arbitrary code inside a sandbox via a malicious file. (Chromium security severity: Medium)

- [https://github.com/George0Papasotiriou/CVE-2026-11102-OAuth2-Implicit-Grant-Fragment-Hijacking](https://github.com/George0Papasotiriou/CVE-2026-11102-OAuth2-Implicit-Grant-Fragment-Hijacking) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2026-11102-OAuth2-Implicit-Grant-Fragment-Hijacking.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2026-11102-OAuth2-Implicit-Grant-Fragment-Hijacking.svg)


## CVE-2026-11101
 Uninitialized Use in Dawn in Google Chrome on Windows prior to 149.0.7827.53 allowed a remote attacker to leak cross-origin data via a crafted HTML page. (Chromium security severity: Medium)

- [https://github.com/George0Papasotiriou/CVE-2026-11101-HTTP-Cache-Poisoning-via-Unkeyed-Query-Parameter](https://github.com/George0Papasotiriou/CVE-2026-11101-HTTP-Cache-Poisoning-via-Unkeyed-Query-Parameter) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2026-11101-HTTP-Cache-Poisoning-via-Unkeyed-Query-Parameter.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2026-11101-HTTP-Cache-Poisoning-via-Unkeyed-Query-Parameter.svg)


## CVE-2026-9848
 The WP Ticket plugin for WordPress is vulnerable to SQL Injection via the WordPress search query parameter (`s`) in versions up to, and including, 6.0.4 The plugin hooks WordPress's `posts_request` filter with `wp_ticket_com_posts_request()`, which calls `emd_author_search_results()` when the current request is an unauthenticated front-end search. That function reads `$query-query_vars['s']` — already wp_unslash()'d by `WP_Query::parse_query()`, so wp_magic_quotes protection has been stripped — and concatenates the raw value into a SQL `LIKE` clause inside a UNION sub-SELECT appended to the main query, with no `$wpdb-prepare()` or escaping. This makes it possible for unauthenticated attackers to append additional SQL queries into already-existing queries that can be used to extract sensitive information from the database.

- [https://github.com/aj2108/CVE-2026-9848](https://github.com/aj2108/CVE-2026-9848) :  ![starts](https://img.shields.io/github/stars/aj2108/CVE-2026-9848.svg) ![forks](https://img.shields.io/github/forks/aj2108/CVE-2026-9848.svg)


## CVE-2026-6000
 A vulnerability was found in code-projects Online Library Management System 1.0. Affected is an unknown function of the file /sql/library.sql of the component SQL Database Backup File Handler. Performing a manipulation results in information disclosure. The attack may be initiated remotely. The exploit has been made public and could be used.

- [https://github.com/imbas007/CVE-2026-60004-POC](https://github.com/imbas007/CVE-2026-60004-POC) :  ![starts](https://img.shields.io/github/stars/imbas007/CVE-2026-60004-POC.svg) ![forks](https://img.shields.io/github/forks/imbas007/CVE-2026-60004-POC.svg)
- [https://github.com/shinthink/CVE-2026-60004](https://github.com/shinthink/CVE-2026-60004) :  ![starts](https://img.shields.io/github/stars/shinthink/CVE-2026-60004.svg) ![forks](https://img.shields.io/github/forks/shinthink/CVE-2026-60004.svg)


## CVE-2026-5615
 A weakness has been identified in givanz Vvvebjs up to 2.0.5. The affected element is an unknown function of the file upload.php of the component File Upload Endpoint. This manipulation of the argument uploadAllowExtensions causes cross site scripting. Remote exploitation of the attack is possible. The exploit has been made available to the public and could be used for attacks. Patch name: 8cac22cff99b8bc701c408aa8e887fa702755336. Applying a patch is the recommended action to fix this issue. The vendor was contacted early, responded in a very professional manner and quickly released a fixed version of the affected product.

- [https://github.com/sam00/CVE-2026-56158-.NET-Framework-RCE-PoC-Exploit](https://github.com/sam00/CVE-2026-56158-.NET-Framework-RCE-PoC-Exploit) :  ![starts](https://img.shields.io/github/stars/sam00/CVE-2026-56158-.NET-Framework-RCE-PoC-Exploit.svg) ![forks](https://img.shields.io/github/forks/sam00/CVE-2026-56158-.NET-Framework-RCE-PoC-Exploit.svg)


## CVE-2026-5282
 Out of bounds read in WebCodecs in Google Chrome prior to 146.0.7680.178 allowed a remote attacker to perform an out of bounds memory read via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/AzureADTrent/CVE-2026-52824](https://github.com/AzureADTrent/CVE-2026-52824) :  ![starts](https://img.shields.io/github/stars/AzureADTrent/CVE-2026-52824.svg) ![forks](https://img.shields.io/github/forks/AzureADTrent/CVE-2026-52824.svg)


## CVE-2026-3891
 The Pix for WooCommerce plugin for WordPress is vulnerable to arbitrary file uploads due to missing capability check and missing file type validation in the 'lkn_pix_for_woocommerce_c6_save_settings' function in all versions up to, and including, 1.5.0. This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible.

- [https://github.com/Ch4120N/CVE-2026-3891](https://github.com/Ch4120N/CVE-2026-3891) :  ![starts](https://img.shields.io/github/stars/Ch4120N/CVE-2026-3891.svg) ![forks](https://img.shields.io/github/forks/Ch4120N/CVE-2026-3891.svg)


## CVE-2026-3611
 The Honeywell IQ4x building management controller, exposes its full web-based HMI without authentication in its factory-default configuration. With no user module configured, security is disabled by design and the system operates under a System Guest (level 100) context, granting read/write privileges to any party able to reach the HTTP interface. Authentication controls are only enforced after a web user is created via U.htm, which dynamically enables the user module. Because this function is accessible prior to authentication, a remote user can create a new account with administrative read/write permissions enabling the user module and imposing authentication under attacker-controlled credentials. This action can effectively lock legitimate operators out of local and web-based configuration and administration.

- [https://github.com/spinfosecurity/BAS-Guardian](https://github.com/spinfosecurity/BAS-Guardian) :  ![starts](https://img.shields.io/github/stars/spinfosecurity/BAS-Guardian.svg) ![forks](https://img.shields.io/github/forks/spinfosecurity/BAS-Guardian.svg)


## CVE-2026-2222
 A weakness has been identified in code-projects Online Reviewer System 1.0. Affected by this vulnerability is an unknown functionality of the file /system/system/admins/manage/users/btn_functions.php. Executing a manipulation of the argument firstname can lead to cross site scripting. The attack may be performed from remote. The exploit has been made available to the public and could be used for attacks.

- [https://github.com/George0Papasotiriou/CVE-2026-2222-MQTT-Broker-CONNECT-Packet-Heap-Overflow](https://github.com/George0Papasotiriou/CVE-2026-2222-MQTT-Broker-CONNECT-Packet-Heap-Overflow) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2026-2222-MQTT-Broker-CONNECT-Packet-Heap-Overflow.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2026-2222-MQTT-Broker-CONNECT-Packet-Heap-Overflow.svg)


## CVE-2026-2020
 The JS Archive List plugin for WordPress is vulnerable to PHP Object Injection in all versions up to, and including, 6.1.7 via the 'included' shortcode attribute. This is due to the deserialization of untrusted input supplied via the 'included' parameter of the plugin's shortcode. This makes it possible for authenticated attackers, with Contributor-level access and above, to inject a PHP Object. No known POP chain is present in the vulnerable software. If a POP chain is present via an additional plugin or theme installed on the target system, it could allow the attacker to delete arbitrary files, retrieve sensitive data, or execute code.

- [https://github.com/George0Papasotiriou/CVE-2026-2020-SSRF-via-URL-Parser-Differential](https://github.com/George0Papasotiriou/CVE-2026-2020-SSRF-via-URL-Parser-Differential) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2026-2020-SSRF-via-URL-Parser-Differential.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2026-2020-SSRF-via-URL-Parser-Differential.svg)


## CVE-2026-1700
 A weakness has been identified in projectworlds House Rental and Property Listing 1.0. This vulnerability affects unknown code of the file /app/sms.php. This manipulation of the argument Message causes cross site scripting. It is possible to initiate the attack remotely. The exploit has been made available to the public and could be used for attacks.

- [https://github.com/llaytynher/CVE-2026-17001](https://github.com/llaytynher/CVE-2026-17001) :  ![starts](https://img.shields.io/github/stars/llaytynher/CVE-2026-17001.svg) ![forks](https://img.shields.io/github/forks/llaytynher/CVE-2026-17001.svg)


## CVE-2026-1111
 A vulnerability has been found in Sanluan PublicCMS up to 5.202506.d. This impacts the function Save of the file com/publiccms/controller/admin/sys/TaskTemplateAdminController.java of the component Task Template Management Handler. Such manipulation of the argument path leads to path traversal. The attack can be launched remotely. The exploit has been disclosed to the public and may be used. The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/George0Papasotiriou/CVE-2026-1111-Smart-Contract-Cross-Function-Reentrancy](https://github.com/George0Papasotiriou/CVE-2026-1111-Smart-Contract-Cross-Function-Reentrancy) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2026-1111-Smart-Contract-Cross-Function-Reentrancy.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2026-1111-Smart-Contract-Cross-Function-Reentrancy.svg)


## CVE-2026-1010
When an administrator views the affected workflow, the injected payload executes in the administrator’s browser context, allowing privilege escalation, including creation of new administrator accounts, session token theft, and execution of administrative actions.

- [https://github.com/George0Papasotiriou/CVE-2026-1010-WebSocket-Connection-Smuggling-via-Malformed-Upgrade-Header](https://github.com/George0Papasotiriou/CVE-2026-1010-WebSocket-Connection-Smuggling-via-Malformed-Upgrade-Header) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2026-1010-WebSocket-Connection-Smuggling-via-Malformed-Upgrade-Header.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2026-1010-WebSocket-Connection-Smuggling-via-Malformed-Upgrade-Header.svg)


## CVE-2025-71338
 Flowise contains a path traversal vulnerability in the /api/v1/document-store/loader/process endpoint that allows unauthenticated attackers to write arbitrary files to the filesystem. Attackers can exploit unsanitized fileName parameters with ../ sequences to overwrite critical files like package.json and achieve remote code execution when the application restarts.

- [https://github.com/majpuV/flowise-arbitrary-file-read-getFileFromStorage](https://github.com/majpuV/flowise-arbitrary-file-read-getFileFromStorage) :  ![starts](https://img.shields.io/github/stars/majpuV/flowise-arbitrary-file-read-getFileFromStorage.svg) ![forks](https://img.shields.io/github/forks/majpuV/flowise-arbitrary-file-read-getFileFromStorage.svg)


## CVE-2025-57052
 cJSON 1.5.0 through 1.7.18 allows out-of-bounds access via the decode_array_index_from_pointer function in cJSON_Utils.c, allowing remote attackers to bypass array bounds checking and access restricted data via malformed JSON pointer strings containing alphanumeric characters.

- [https://github.com/DhruvP2205/cjson-rust-port](https://github.com/DhruvP2205/cjson-rust-port) :  ![starts](https://img.shields.io/github/stars/DhruvP2205/cjson-rust-port.svg) ![forks](https://img.shields.io/github/forks/DhruvP2205/cjson-rust-port.svg)


## CVE-2025-55182
 A pre-authentication remote code execution vulnerability exists in React Server Components versions 19.0.0, 19.1.0, 19.1.1, and 19.2.0 including the following packages: react-server-dom-parcel, react-server-dom-turbopack, and react-server-dom-webpack. The vulnerable code unsafely deserializes payloads from HTTP requests to Server Function endpoints.

- [https://github.com/xiaopeng-ye/react2shell-detector](https://github.com/xiaopeng-ye/react2shell-detector) :  ![starts](https://img.shields.io/github/stars/xiaopeng-ye/react2shell-detector.svg) ![forks](https://img.shields.io/github/forks/xiaopeng-ye/react2shell-detector.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/berraesen/nextjs-middleware-auth-bypass-lab](https://github.com/berraesen/nextjs-middleware-auth-bypass-lab) :  ![starts](https://img.shields.io/github/stars/berraesen/nextjs-middleware-auth-bypass-lab.svg) ![forks](https://img.shields.io/github/forks/berraesen/nextjs-middleware-auth-bypass-lab.svg)


## CVE-2025-1727
systems.

- [https://github.com/spinfosecurity/Rail-OT-Protector](https://github.com/spinfosecurity/Rail-OT-Protector) :  ![starts](https://img.shields.io/github/stars/spinfosecurity/Rail-OT-Protector.svg) ![forks](https://img.shields.io/github/forks/spinfosecurity/Rail-OT-Protector.svg)


## CVE-2024-7344
 Howyar UEFI Application "Reloader"  (32-bit and 64-bit)  is vulnerable to execution of unsigned software in a hardcoded path.

- [https://github.com/TheMalwareGuardian/CVE-2024-7344](https://github.com/TheMalwareGuardian/CVE-2024-7344) :  ![starts](https://img.shields.io/github/stars/TheMalwareGuardian/CVE-2024-7344.svg) ![forks](https://img.shields.io/github/forks/TheMalwareGuardian/CVE-2024-7344.svg)


## CVE-2023-30547
 vm2 is a sandbox that can run untrusted code with whitelisted Node's built-in modules. There exists a vulnerability in exception sanitization of vm2 for versions up to 3.9.16, allowing attackers to raise an unsanitized host exception inside `handleException()` which can be used to escape the sandbox and run arbitrary code in host context. This vulnerability was patched in the release of version `3.9.17` of `vm2`. There are no known workarounds for this vulnerability. Users are advised to upgrade.

- [https://github.com/R3fr4kt/Codify-TJNULL-OSCP-](https://github.com/R3fr4kt/Codify-TJNULL-OSCP-) :  ![starts](https://img.shields.io/github/stars/R3fr4kt/Codify-TJNULL-OSCP-.svg) ![forks](https://img.shields.io/github/forks/R3fr4kt/Codify-TJNULL-OSCP-.svg)

