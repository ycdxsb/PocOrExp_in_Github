# Update 2026-08-30
## CVE-2026-76060
 An authenticated OS command injection vulnerability exists in ZoneMinder's event export functionality. The exportFile HTTP request parameter is passed unsanitized into a shell command executed via PHP's exec(), allowing any authenticated user with View Events permission to execute arbitrary operating system commands on the server.

- [https://github.com/investigato/CVE-2026-76060_ZoneMinder_CommandInjection-PoC](https://github.com/investigato/CVE-2026-76060_ZoneMinder_CommandInjection-PoC) :  ![starts](https://img.shields.io/github/stars/investigato/CVE-2026-76060_ZoneMinder_CommandInjection-PoC.svg) ![forks](https://img.shields.io/github/forks/investigato/CVE-2026-76060_ZoneMinder_CommandInjection-PoC.svg)


## CVE-2026-73570
 A remote code execution vulnerability exists in Zimbra Collaboration (ZCS) before 10.1.20 when the optional zimbra-snmp package is installed and SNMP notifications are enabled. Due to improper sanitization of untrusted input during SNMP notification processing, an unauthenticated attacker can send specially crafted SMTP requests that may result in execution of arbitrary operating system commands as the Zimbra user.

- [https://github.com/INFOKOM-KI/Zimbra-CVE-2026-73570-Rules](https://github.com/INFOKOM-KI/Zimbra-CVE-2026-73570-Rules) :  ![starts](https://img.shields.io/github/stars/INFOKOM-KI/Zimbra-CVE-2026-73570-Rules.svg) ![forks](https://img.shields.io/github/forks/INFOKOM-KI/Zimbra-CVE-2026-73570-Rules.svg)
- [https://github.com/alsyundawy/eradicate-zimbra-malware](https://github.com/alsyundawy/eradicate-zimbra-malware) :  ![starts](https://img.shields.io/github/stars/alsyundawy/eradicate-zimbra-malware.svg) ![forks](https://img.shields.io/github/forks/alsyundawy/eradicate-zimbra-malware.svg)


## CVE-2026-70463
 rsync 3.1.0 before 3.5.0 contains an authorization bypass in auth users directive parsing. The auth users parser uses comma-only tokenization when splitting the user list, which fails to correctly handle entries of the form @Group Name where the group name contains a space. The space within the group name causes the parser to split the entry at the space boundary, discarding the deny rule associated with the group. An authenticated user whose username or group membership would be denied by an @Group Name auth users entry can connect to a restricted module because the deny rule is silently discarded during parsing.

- [https://github.com/Fyyre/CVE-2026-70463](https://github.com/Fyyre/CVE-2026-70463) :  ![starts](https://img.shields.io/github/stars/Fyyre/CVE-2026-70463.svg) ![forks](https://img.shields.io/github/forks/Fyyre/CVE-2026-70463.svg)


## CVE-2026-66384
 An authenticated user may write data outside the intended Docker cache path under specific remote-repository conditions.

- [https://github.com/HORKimhab/CVE-2026-66384](https://github.com/HORKimhab/CVE-2026-66384) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-66384.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-66384.svg)


## CVE-2026-55584
 phpSysInfo is a customizable PHP script that displays system information. Prior to 3.4.6, the PSI_ALLOWED access-control check in read_config.php trusts attacker-controlled X-Forwarded-For and Client-IP HTTP headers before REMOTE_ADDR. A remote unauthenticated attacker can supply an allowed address in one of these headers to impersonate a trusted client and access exposed hostname, kernel, CPU, memory, filesystem, and network-interface information. This issue is fixed in version 3.4.6.

- [https://github.com/mirackayikci/CVE-2026-55584](https://github.com/mirackayikci/CVE-2026-55584) :  ![starts](https://img.shields.io/github/stars/mirackayikci/CVE-2026-55584.svg) ![forks](https://img.shields.io/github/forks/mirackayikci/CVE-2026-55584.svg)


## CVE-2026-55511
 Yamcs is a mission control framework. Prior to 5.12.8 and 5.13.2, Yamcs allows a user with SystemPrivilege.ControlArchiving to create a double-quoted StreamSQL column name that is interpolated into generated Java source by Expression.fillCode_InputDefVars and Expression.sanitizeName. A sum aggregate reaches yamcs-core/src/main/java/org/yamcs/yarch/streamsql/CompilableAggregateExpression.java and yamcs-core/src/main/java/org/yamcs/yarch/streamsql/funct/SumExpression.java through SelectExpression.compile, where Janino SimpleCompiler.cook compiles the injected source. POST /api/archive/{instance}:executeSql can therefore execute arbitrary Java in the Yamcs server process, exposing mission data and credentials and permitting telemetry tampering or denial of service. This issue is fixed in versions 5.12.8 and 5.13.2.

- [https://github.com/junfuture1103/CVE-2026-55511](https://github.com/junfuture1103/CVE-2026-55511) :  ![starts](https://img.shields.io/github/stars/junfuture1103/CVE-2026-55511.svg) ![forks](https://img.shields.io/github/forks/junfuture1103/CVE-2026-55511.svg)


## CVE-2026-52923
checkpoint/restore path fails once the valid range is exhausted.

- [https://github.com/Hari-v542/CVE-2026-52923](https://github.com/Hari-v542/CVE-2026-52923) :  ![starts](https://img.shields.io/github/stars/Hari-v542/CVE-2026-52923.svg) ![forks](https://img.shields.io/github/forks/Hari-v542/CVE-2026-52923.svg)


## CVE-2026-50980
 Cross-Site Scripting (XSS) vulnerability in the DNS lookup/management component of oPanel before v1.20.25 allows remote attackers to execute arbitrary JavaScript and perform session hijacking via a crafted DNS TXT record

- [https://github.com/bugresearch/CVE-2026-50980](https://github.com/bugresearch/CVE-2026-50980) :  ![starts](https://img.shields.io/github/stars/bugresearch/CVE-2026-50980.svg) ![forks](https://img.shields.io/github/forks/bugresearch/CVE-2026-50980.svg)


## CVE-2026-50979
 A command injection vulnerability in the 'advanced/curl' component of Osbil Technology oPanel v1.19.50 and earlier allows authenticated attackers to execute arbitrary shell commands via the 'url' parameter

- [https://github.com/bugresearch/CVE-2026-50979](https://github.com/bugresearch/CVE-2026-50979) :  ![starts](https://img.shields.io/github/stars/bugresearch/CVE-2026-50979.svg) ![forks](https://img.shields.io/github/forks/bugresearch/CVE-2026-50979.svg)


## CVE-2026-50751
 A logic flow weakness in Remote Access and Mobile Access certificate validation in deprecated IKEv1 key exchange allows an unauthenticated remote attacker to bypass user authentication and establish a remote access VPN connection without a valid user password.

- [https://github.com/e4zyy/Project-CVE-2026-50751](https://github.com/e4zyy/Project-CVE-2026-50751) :  ![starts](https://img.shields.io/github/stars/e4zyy/Project-CVE-2026-50751.svg) ![forks](https://img.shields.io/github/forks/e4zyy/Project-CVE-2026-50751.svg)


## CVE-2026-46339
 9Router is an AI router & token saver. From 0.4.30 until 0.4.37, 9Router's src/proxy.js middleware did not protect /api/cli-tools/* and /api/mcp/*, allowing unauthenticated registration of customPlugins through src/app/api/cli-tools/cowork-settings/route.js and command execution through the MCP bridge. This vulnerability is fixed in 0.4.37.

- [https://github.com/SimoesCTT/CTT-Enhanced-CVE-2026-46339-Exploit-Engine](https://github.com/SimoesCTT/CTT-Enhanced-CVE-2026-46339-Exploit-Engine) :  ![starts](https://img.shields.io/github/stars/SimoesCTT/CTT-Enhanced-CVE-2026-46339-Exploit-Engine.svg) ![forks](https://img.shields.io/github/forks/SimoesCTT/CTT-Enhanced-CVE-2026-46339-Exploit-Engine.svg)


## CVE-2026-33057
 Mesop is a Python-based UI framework that allows users to build web applications. In versions 1.2.2 and below, an explicit web endpoint inside the ai/ testing module infrastructure directly ingests untrusted Python code strings unconditionally without authentication measures, yielding standard Unrestricted Remote Code Execution. Any individual capable of routing HTTP logic to this server block will gain explicit host-machine command rights. The AI codebase package includes a lightweight debugging Flask server inside ai/sandbox/wsgi_app.py. The /exec-py route accepts base_64 encoded raw string payloads inside the code parameter natively evaluated by a basic POST web request. It saves it rapidly to the operating system logic path and injects it recursively using execute_module(module_path...). This issue has been fixed in version 1.2.3.

- [https://github.com/hackpatato/CVE-2026-33057---Mesop-Unauthenticated-RCE-PoC-and-yara-rules](https://github.com/hackpatato/CVE-2026-33057---Mesop-Unauthenticated-RCE-PoC-and-yara-rules) :  ![starts](https://img.shields.io/github/stars/hackpatato/CVE-2026-33057---Mesop-Unauthenticated-RCE-PoC-and-yara-rules.svg) ![forks](https://img.shields.io/github/forks/hackpatato/CVE-2026-33057---Mesop-Unauthenticated-RCE-PoC-and-yara-rules.svg)


## CVE-2026-33017
 Langflow is a tool for building and deploying AI-powered agents and workflows. In versions prior to 1.9.0, the POST /api/v1/build_public_tmp/{flow_id}/flow endpoint allows building public flows without requiring authentication. When the optional data parameter is supplied, the endpoint uses attacker-controlled flow data (containing arbitrary Python code in node definitions) instead of the stored flow data from the database. This code is passed to exec() with zero sandboxing, resulting in unauthenticated remote code execution. This is distinct from CVE-2025-3248, which fixed /api/v1/validate/code by adding authentication. The build_public_tmp endpoint is designed to be unauthenticated (for public flows) but incorrectly accepts attacker-supplied flow data containing arbitrary executable code. This issue has been fixed in version 1.9.0.

- [https://github.com/e4zyy/Project-CVE-2026-33017](https://github.com/e4zyy/Project-CVE-2026-33017) :  ![starts](https://img.shields.io/github/stars/e4zyy/Project-CVE-2026-33017.svg) ![forks](https://img.shields.io/github/forks/e4zyy/Project-CVE-2026-33017.svg)
- [https://github.com/ahseven/CVE-2026-33017-PoC-Reverse-Shell](https://github.com/ahseven/CVE-2026-33017-PoC-Reverse-Shell) :  ![starts](https://img.shields.io/github/stars/ahseven/CVE-2026-33017-PoC-Reverse-Shell.svg) ![forks](https://img.shields.io/github/forks/ahseven/CVE-2026-33017-PoC-Reverse-Shell.svg)


## CVE-2026-24061
 telnetd in GNU Inetutils through 2.7 allows remote authentication bypass via a "-f root" value for the USER environment variable.

- [https://github.com/iLokaas/CVE-2026-24061-payload](https://github.com/iLokaas/CVE-2026-24061-payload) :  ![starts](https://img.shields.io/github/stars/iLokaas/CVE-2026-24061-payload.svg) ![forks](https://img.shields.io/github/forks/iLokaas/CVE-2026-24061-payload.svg)


## CVE-2026-23751
 Kofax Capture, now referred to as Tungsten Capture, version 6.0.0.0 (other versions may be affected) exposes a deprecated .NET Remoting HTTP channel on port 2424 via the Ascent Capture Service that is accessible without authentication and uses a default, publicly known endpoint identifier. An unauthenticated remote attacker can exploit .NET Remoting object unmarshalling techniques to instantiate a remote System.Net.WebClient object and read arbitrary files from the server filesystem, write attacker-controlled files to the server, or coerce NTLMv2 authentication to an attacker-controlled host, enabling sensitive credential disclosure, denial of service, remote code execution, or lateral movement depending on service account privileges and network environment.

- [https://github.com/SieBRUM/CVE-2026-23751-poc](https://github.com/SieBRUM/CVE-2026-23751-poc) :  ![starts](https://img.shields.io/github/stars/SieBRUM/CVE-2026-23751-poc.svg) ![forks](https://img.shields.io/github/forks/SieBRUM/CVE-2026-23751-poc.svg)


## CVE-2026-22732
: from 5.7.0 through 5.7.21, from 5.8.0 through 5.8.23, from 6.3.0 through 6.3.14, from 6.4.0 through 6.4.14, from 6.5.0 through 6.5.8, from 7.0.0 through 7.0.3.

- [https://github.com/moderneinc/rewrite-cve-2026-22732](https://github.com/moderneinc/rewrite-cve-2026-22732) :  ![starts](https://img.shields.io/github/stars/moderneinc/rewrite-cve-2026-22732.svg) ![forks](https://img.shields.io/github/forks/moderneinc/rewrite-cve-2026-22732.svg)


## CVE-2026-20131
Note: If the FMC management interface does not have public internet access, the attack surface that is associated with this vulnerability is reduced.

- [https://github.com/Jwa7470/CVE-2026-20131-Post-Incident-Written-Report](https://github.com/Jwa7470/CVE-2026-20131-Post-Incident-Written-Report) :  ![starts](https://img.shields.io/github/stars/Jwa7470/CVE-2026-20131-Post-Incident-Written-Report.svg) ![forks](https://img.shields.io/github/forks/Jwa7470/CVE-2026-20131-Post-Incident-Written-Report.svg)


## CVE-2026-19295
 IBM Langflow OSS 1.0.0 through 1.11.1 allows an authenticated attacker to execute arbitrary operating system commands in the server process by saving a flow with a crafted type field value and triggering a build of a wrapper flow that references it. This allowed privilege escalation from "authenticated flow user" to arbitrary OS-level command execution under the server process identity, bypassing the LANGFLOW_ALLOW_CUSTOM_COMPONENTS=false policy control.

- [https://github.com/rmhowe425/POC-CVE-2026-19295](https://github.com/rmhowe425/POC-CVE-2026-19295) :  ![starts](https://img.shields.io/github/stars/rmhowe425/POC-CVE-2026-19295.svg) ![forks](https://img.shields.io/github/forks/rmhowe425/POC-CVE-2026-19295.svg)


## CVE-2026-19286
 IBM Langflow OSS 1.0.0 through 1.11.1 could allow a remote attacker to execute arbitrary code due to improper enforcement of security restrictions on the A2A public endpoint.

- [https://github.com/rmhowe425/POC-CVE-2026-19286](https://github.com/rmhowe425/POC-CVE-2026-19286) :  ![starts](https://img.shields.io/github/stars/rmhowe425/POC-CVE-2026-19286.svg) ![forks](https://img.shields.io/github/forks/rmhowe425/POC-CVE-2026-19286.svg)


## CVE-2026-16723
 A remote code execution (RCE) vulnerability exists in fastjson 1.2.68 through 1.2.83. This vulnerability is exploitable under fastjson's stock default configuration — no AutoType enablement required, no classpath gadget required.

- [https://github.com/ipisav/fastjson-cve](https://github.com/ipisav/fastjson-cve) :  ![starts](https://img.shields.io/github/stars/ipisav/fastjson-cve.svg) ![forks](https://img.shields.io/github/forks/ipisav/fastjson-cve.svg)


## CVE-2026-10036
 SpeechBrain before 1.1.1 contains an arbitrary code execution vulnerability that allows attackers to execute arbitrary code by supplying a crafted CKPT.yaml checkpoint metadata file parsed with PyYAML's unsafe loader during candidate enumeration in Checkpointer.recover_if_possible(). Attackers can embed malicious Python object construction tags such as !!python/object/apply in any CKPT.yaml file within the configured checkpoint path to trigger code execution during candidate discovery, even if the malicious checkpoint is never selected for recovery.

- [https://github.com/SaiTeja-Erukude/CVE-2026-10036-speechbrain-rce](https://github.com/SaiTeja-Erukude/CVE-2026-10036-speechbrain-rce) :  ![starts](https://img.shields.io/github/stars/SaiTeja-Erukude/CVE-2026-10036-speechbrain-rce.svg) ![forks](https://img.shields.io/github/forks/SaiTeja-Erukude/CVE-2026-10036-speechbrain-rce.svg)


## CVE-2026-9973
 Out of bounds write in V8 in Google Chrome prior to 148.0.7778.216 allowed a remote attacker to execute arbitrary code inside a sandbox via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/Mofarthim/CVE-2026-9973-exploit](https://github.com/Mofarthim/CVE-2026-9973-exploit) :  ![starts](https://img.shields.io/github/stars/Mofarthim/CVE-2026-9973-exploit.svg) ![forks](https://img.shields.io/github/forks/Mofarthim/CVE-2026-9973-exploit.svg)


## CVE-2026-6564
 A vulnerability was found in EMQ EMQX Enterprise up to 6.1.0. The impacted element is an unknown function of the component Session Handling. The manipulation results in improper authorization. It is possible to launch the attack remotely. The exploit has been made public and could be used. The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/HORKimhab/CVE-2026-65643](https://github.com/HORKimhab/CVE-2026-65643) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-65643.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-65643.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun.svg)


## CVE-2025-59528
 Flowise is a drag & drop user interface to build a customized large language model flow. In version 3.0.5, Flowise is vulnerable to remote code execution. The CustomMCP node allows users to input configuration settings for connecting to an external MCP server. This node parses the user-provided mcpServerConfig string to build the MCP server configuration. However, during this process, it executes JavaScript code without any security validation. Specifically, inside the convertToValidJSONString function, user input is directly passed to the Function() constructor, which evaluates and executes the input as JavaScript code. Since this runs with full Node.js runtime privileges, it can access dangerous modules such as child_process and fs. This issue has been patched in version 3.0.6.

- [https://github.com/hackpatato/PoC-and-yara-rules-of-CVE-2025-59528-Flowise-has-Remote-Code-Execution-vulnerability](https://github.com/hackpatato/PoC-and-yara-rules-of-CVE-2025-59528-Flowise-has-Remote-Code-Execution-vulnerability) :  ![starts](https://img.shields.io/github/stars/hackpatato/PoC-and-yara-rules-of-CVE-2025-59528-Flowise-has-Remote-Code-Execution-vulnerability.svg) ![forks](https://img.shields.io/github/forks/hackpatato/PoC-and-yara-rules-of-CVE-2025-59528-Flowise-has-Remote-Code-Execution-vulnerability.svg)


## CVE-2025-54068
 Livewire is a full-stack framework for Laravel. In Livewire v3 up to and including v3.6.3, a vulnerability allows unauthenticated attackers to achieve remote command execution in specific scenarios. The issue stems from how certain component property updates are hydrated. This vulnerability is unique to Livewire v3 and does not affect prior major versions. Exploitation requires a component to be mounted and configured in a particular way, but does not require authentication or user interaction. This issue has been patched in Livewire v3.6.4. All users are strongly encouraged to upgrade to this version or later as soon as possible. No known workarounds are available.

- [https://github.com/e4zyy/Project-CVE-2025-54068](https://github.com/e4zyy/Project-CVE-2025-54068) :  ![starts](https://img.shields.io/github/stars/e4zyy/Project-CVE-2025-54068.svg) ![forks](https://img.shields.io/github/forks/e4zyy/Project-CVE-2025-54068.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/all3njk/NextJS_CVE-2025-29927](https://github.com/all3njk/NextJS_CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/all3njk/NextJS_CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/all3njk/NextJS_CVE-2025-29927.svg)


## CVE-2025-10952
 A security flaw has been discovered in geyang ml-logger up to acf255bade5be6ad88d90735c8367b28cbe3a743. Affected by this issue is the function stream_handler of the file ml_logger/server.py of the component File Handler. Performing manipulation of the argument key results in information disclosure. The attack can be initiated remotely. The exploit has been released to the public and may be exploited. Continious delivery with rolling releases is used by this product. Therefore, no version details of affected nor updated releases are available.

- [https://github.com/Khashayarnzk/CVE-2025-10952-ml-logger-AFR](https://github.com/Khashayarnzk/CVE-2025-10952-ml-logger-AFR) :  ![starts](https://img.shields.io/github/stars/Khashayarnzk/CVE-2025-10952-ml-logger-AFR.svg) ![forks](https://img.shields.io/github/forks/Khashayarnzk/CVE-2025-10952-ml-logger-AFR.svg)


## CVE-2025-6647
The specific flaw exists within the parsing of U3D files. The issue results from the lack of proper validation of user-supplied data, which can result in a write past the end of an allocated object. An attacker can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-26644.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo.svg)


## CVE-2025-5352
 A critical stored Cross-Site Scripting (XSS) vulnerability exists in the Analytics component of lunary-ai/lunary versions up to 1.9.23, where the NEXT_PUBLIC_CUSTOM_SCRIPT environment variable is directly injected into the DOM using dangerouslySetInnerHTML without any sanitization or validation. This allows arbitrary JavaScript execution in all users' browsers if an attacker can control the environment variable during deployment or through server compromise. The vulnerability can lead to complete account takeover, data exfiltration, malware distribution, and persistent attacks affecting all users until the environment variable is cleaned. The issue is fixed in version 1.9.25.

- [https://github.com/sahiloj/CVE-2025-5352](https://github.com/sahiloj/CVE-2025-5352) :  ![starts](https://img.shields.io/github/stars/sahiloj/CVE-2025-5352.svg) ![forks](https://img.shields.io/github/forks/sahiloj/CVE-2025-5352.svg)


## CVE-2025-2992
 A vulnerability classified as critical was found in Tenda FH1202 1.2.0.14(408). Affected by this vulnerability is an unknown functionality of the file /goform/AdvSetWrlsafeset of the component Web Management Interface. The manipulation leads to improper access controls. The attack can be launched remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/rgvillanueva28/vulnbox-easy-CVE-2025-29927](https://github.com/rgvillanueva28/vulnbox-easy-CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/rgvillanueva28/vulnbox-easy-CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/rgvillanueva28/vulnbox-easy-CVE-2025-29927.svg)


## CVE-2024-23897
 Jenkins 2.441 and earlier, LTS 2.426.2 and earlier does not disable a feature of its CLI command parser that replaces an '@' character followed by a file path in an argument with the file's contents, allowing unauthenticated attackers to read arbitrary files on the Jenkins controller file system.

- [https://github.com/MachiavelliII/CVE-2024-23897](https://github.com/MachiavelliII/CVE-2024-23897) :  ![starts](https://img.shields.io/github/stars/MachiavelliII/CVE-2024-23897.svg) ![forks](https://img.shields.io/github/forks/MachiavelliII/CVE-2024-23897.svg)


## CVE-2023-27351
 This vulnerability allows remote attackers to bypass authentication on affected installations of PaperCut NG 22.0.5 (Build 63914). Authentication is not required to exploit this vulnerability. The specific flaw exists within the SecurityRequestFilter class. The issue results from improper implementation of the authentication algorithm. An attacker can leverage this vulnerability to bypass authentication on the system. Was ZDI-CAN-19226.

- [https://github.com/HORKimhab/CVE-2023-27350-CVE-2023-27351](https://github.com/HORKimhab/CVE-2023-27350-CVE-2023-27351) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2023-27350-CVE-2023-27351.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2023-27350-CVE-2023-27351.svg)


## CVE-2023-27350
 This vulnerability allows remote attackers to bypass authentication on affected installations of PaperCut NG 22.0.5 (Build 63914). Authentication is not required to exploit this vulnerability. The specific flaw exists within the SetupCompleted class. The issue results from improper access control. An attacker can leverage this vulnerability to bypass authentication and execute arbitrary code in the context of SYSTEM. Was ZDI-CAN-18987.

- [https://github.com/HORKimhab/CVE-2023-27350-CVE-2023-27351](https://github.com/HORKimhab/CVE-2023-27350-CVE-2023-27351) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2023-27350-CVE-2023-27351.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2023-27350-CVE-2023-27351.svg)


## CVE-2023-23397
 Microsoft Outlook Elevation of Privilege Vulnerability

- [https://github.com/ZHOUCC-CPU/cve-2023-23397-detection-lab](https://github.com/ZHOUCC-CPU/cve-2023-23397-detection-lab) :  ![starts](https://img.shields.io/github/stars/ZHOUCC-CPU/cve-2023-23397-detection-lab.svg) ![forks](https://img.shields.io/github/forks/ZHOUCC-CPU/cve-2023-23397-detection-lab.svg)


## CVE-2022-46169
This command injection vulnerability allows an unauthenticated user to execute arbitrary commands if a `poller_item` with the `action` type `POLLER_ACTION_SCRIPT_PHP` (`2`) is configured. The authorization bypass should be prevented by not allowing an attacker to make `get_client_addr` (file `lib/functions.php`) return an arbitrary IP address. This could be done by not honoring the `HTTP_...` `$_SERVER` variables. If these should be kept for compatibility reasons it should at least be prevented to fake the IP address of the server running Cacti. This vulnerability has been addressed in both the 1.2.x and 1.3.x release branches with `1.2.23` being the first release containing the patch.

- [https://github.com/K4PXD/CVE-2022-46169](https://github.com/K4PXD/CVE-2022-46169) :  ![starts](https://img.shields.io/github/stars/K4PXD/CVE-2022-46169.svg) ![forks](https://img.shields.io/github/forks/K4PXD/CVE-2022-46169.svg)


## CVE-2022-0847
 A flaw was found in the way the "flags" member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/Greetdawn/CVE-2022-0847-DirtyPipe-](https://github.com/Greetdawn/CVE-2022-0847-DirtyPipe-) :  ![starts](https://img.shields.io/github/stars/Greetdawn/CVE-2022-0847-DirtyPipe-.svg) ![forks](https://img.shields.io/github/forks/Greetdawn/CVE-2022-0847-DirtyPipe-.svg)


## CVE-2021-4422
 The POST SMTP Mailer plugin for WordPress is vulnerable to Cross-Site Request Forgery in versions up to, and including, 2.0.20. This is due to missing or incorrect nonce validation on the handleCsvExport() function. This makes it possible for unauthenticated attackers to trigger a CSV export via a forged request granted they can trick a site administrator into performing an action such as clicking on a link.

- [https://github.com/Super-Binary/cve-2021-44228](https://github.com/Super-Binary/cve-2021-44228) :  ![starts](https://img.shields.io/github/stars/Super-Binary/cve-2021-44228.svg) ![forks](https://img.shields.io/github/forks/Super-Binary/cve-2021-44228.svg)


## CVE-2020-12712
 A vulnerability based on insecure user/password encryption in the JOE (job editor) component of SOS JobScheduler 1.12 and 1.13 allows attackers to decrypt the user/password that is optionally stored with a user's profile.

- [https://github.com/0xVEDETTE/CVE-2020-12712](https://github.com/0xVEDETTE/CVE-2020-12712) :  ![starts](https://img.shields.io/github/stars/0xVEDETTE/CVE-2020-12712.svg) ![forks](https://img.shields.io/github/forks/0xVEDETTE/CVE-2020-12712.svg)

