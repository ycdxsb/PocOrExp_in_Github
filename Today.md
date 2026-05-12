# Update 2026-05-12
## CVE-2026-43284
destination-frag path or fall back to skb_cow_data().

- [https://github.com/ryan2929/CVE-2026-43284-](https://github.com/ryan2929/CVE-2026-43284-) :  ![starts](https://img.shields.io/github/stars/ryan2929/CVE-2026-43284-.svg) ![forks](https://img.shields.io/github/forks/ryan2929/CVE-2026-43284-.svg)
- [https://github.com/attaattaatta/CVE-2026-43500](https://github.com/attaattaatta/CVE-2026-43500) :  ![starts](https://img.shields.io/github/stars/attaattaatta/CVE-2026-43500.svg) ![forks](https://img.shields.io/github/forks/attaattaatta/CVE-2026-43500.svg)


## CVE-2026-42208
 LiteLLM is a proxy server (AI Gateway) to call LLM APIs in OpenAI (or native) format. From version 1.81.16 to before version 1.83.7, a database query used during proxy API key checks mixed the caller-supplied key value into the query text instead of passing it as a separate parameter. An unauthenticated attacker could send a specially crafted Authorization header to any LLM API route (for example POST /chat/completions) and reach this query through the proxy's error-handling path. An attacker could read data from the proxy's database and may be able to modify it, leading to unauthorised access to the proxy and the credentials it manages. This issue has been patched in version 1.83.7.

- [https://github.com/rootdirective-sec/cve-2026-42208-Lab](https://github.com/rootdirective-sec/cve-2026-42208-Lab) :  ![starts](https://img.shields.io/github/stars/rootdirective-sec/cve-2026-42208-Lab.svg) ![forks](https://img.shields.io/github/forks/rootdirective-sec/cve-2026-42208-Lab.svg)
- [https://github.com/Zeltoc/threat-intel-brief-cve-2026-42208-litellm](https://github.com/Zeltoc/threat-intel-brief-cve-2026-42208-litellm) :  ![starts](https://img.shields.io/github/stars/Zeltoc/threat-intel-brief-cve-2026-42208-litellm.svg) ![forks](https://img.shields.io/github/forks/Zeltoc/threat-intel-brief-cve-2026-42208-litellm.svg)


## CVE-2026-41940
 cPanel and WHM versions after 11.40 contain an authentication bypass vulnerability in the login flow that allows unauthenticated remote attackers to gain unauthorized access to the control panel.

- [https://github.com/44pie/cpsniper](https://github.com/44pie/cpsniper) :  ![starts](https://img.shields.io/github/stars/44pie/cpsniper.svg) ![forks](https://img.shields.io/github/forks/44pie/cpsniper.svg)
- [https://github.com/ngksiva/cpanel-forensics](https://github.com/ngksiva/cpanel-forensics) :  ![starts](https://img.shields.io/github/stars/ngksiva/cpanel-forensics.svg) ![forks](https://img.shields.io/github/forks/ngksiva/cpanel-forensics.svg)


## CVE-2026-31431
AD directly.

- [https://github.com/Gr-1m/CVE-2026-31431](https://github.com/Gr-1m/CVE-2026-31431) :  ![starts](https://img.shields.io/github/stars/Gr-1m/CVE-2026-31431.svg) ![forks](https://img.shields.io/github/forks/Gr-1m/CVE-2026-31431.svg)


## CVE-2026-25253
 OpenClaw (aka clawdbot or Moltbot) before 2026.1.29 obtains a gatewayUrl value from a query string and automatically makes a WebSocket connection without prompting, sending a token value.

- [https://github.com/siyad01/agentbox](https://github.com/siyad01/agentbox) :  ![starts](https://img.shields.io/github/stars/siyad01/agentbox.svg) ![forks](https://img.shields.io/github/forks/siyad01/agentbox.svg)


## CVE-2026-23744
 MCPJam inspector is the local-first development platform for MCP servers. Versions 1.4.2 and earlier are vulnerable to remote code execution (RCE) vulnerability, which allows an attacker to send a crafted HTTP request that triggers the installation of an MCP server, leading to RCE. Since MCPJam inspector by default listens on 0.0.0.0 instead of 127.0.0.1, an attacker can trigger the RCE remotely via a simple HTTP request. Version 1.4.3 contains a patch.

- [https://github.com/ledksv/kobold](https://github.com/ledksv/kobold) :  ![starts](https://img.shields.io/github/stars/ledksv/kobold.svg) ![forks](https://img.shields.io/github/forks/ledksv/kobold.svg)


## CVE-2026-20131
Note: If the FMC management interface does not have public internet access, the attack surface that is associated with this vulnerability is reduced.

- [https://github.com/0xBlackash/CVE-2026-20131](https://github.com/0xBlackash/CVE-2026-20131) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-20131.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-20131.svg)


## CVE-2026-7482
 Ollama before 0.17.1 contains a heap out-of-bounds read vulnerability in the GGUF model loader. The /api/create endpoint accepts an attacker-supplied GGUF file in which the declared tensor offset and size exceed the file's actual length; during quantization in fs/ggml/gguf.go and server/quantization.go (WriteTo()), the server reads past the allocated heap buffer. The leaked memory contents may include environment variables, API keys, system prompts, and concurrent users' conversation data, and can be exfiltrated by uploading the resulting model artifact through the /api/push endpoint to an attacker-controlled registry. The /api/create and /api/push endpoints have no authentication in the upstream distribution. Default deployments bind to 127.0.0.1, but the documented OLLAMA_HOST=0.0.0.0 configuration is widely used in practice (large public-internet exposure observed).

- [https://github.com/msuiche/gguf_cve2026_7482](https://github.com/msuiche/gguf_cve2026_7482) :  ![starts](https://img.shields.io/github/stars/msuiche/gguf_cve2026_7482.svg) ![forks](https://img.shields.io/github/forks/msuiche/gguf_cve2026_7482.svg)
- [https://github.com/kaleth4/CVE-2026-7482](https://github.com/kaleth4/CVE-2026-7482) :  ![starts](https://img.shields.io/github/stars/kaleth4/CVE-2026-7482.svg) ![forks](https://img.shields.io/github/forks/kaleth4/CVE-2026-7482.svg)


## CVE-2026-7458
 The User Verification by PickPlugins plugin for WordPress is vulnerable to authentication bypass in all versions up to, and including, 2.0.46. This is due to the use of a loose PHP comparison operator to validate OTP codes in the "user_verification_form_wrap_process_otpLogin" function. This makes it possible for unauthenticated attackers to log in as any user with a verified email address, such as an administrator, by submitting a "true" OTP value.

- [https://github.com/zycoder0day/CVE-2026-7458](https://github.com/zycoder0day/CVE-2026-7458) :  ![starts](https://img.shields.io/github/stars/zycoder0day/CVE-2026-7458.svg) ![forks](https://img.shields.io/github/forks/zycoder0day/CVE-2026-7458.svg)


## CVE-2026-5865
 Type Confusion in V8 in Google Chrome prior to 147.0.7727.55 allowed a remote attacker to execute arbitrary code inside a sandbox via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/Crihexe/v8-poc-CVE-2026-5865](https://github.com/Crihexe/v8-poc-CVE-2026-5865) :  ![starts](https://img.shields.io/github/stars/Crihexe/v8-poc-CVE-2026-5865.svg) ![forks](https://img.shields.io/github/forks/Crihexe/v8-poc-CVE-2026-5865.svg)


## CVE-2026-4350
 The Perfmatters plugin for WordPress is vulnerable to arbitrary file deletion via path traversal in all versions up to, and including, 2.5.9.1. This is due to the `PMCS::action_handler()` method processing the `$_GET['delete']` parameter without any sanitization, authorization check, or nonce verification. The unsanitized filename is concatenated with the storage directory path and passed to `unlink()`. This makes it possible for authenticated attackers, with Subscriber-level access and above, to delete arbitrary files on the server by using `../` path traversal sequences, including `wp-config.php` which would force WordPress into the installation wizard and allow full site takeover.

- [https://github.com/attaattaatta/CVE-2026-43500](https://github.com/attaattaatta/CVE-2026-43500) :  ![starts](https://img.shields.io/github/stars/attaattaatta/CVE-2026-43500.svg) ![forks](https://img.shields.io/github/forks/attaattaatta/CVE-2026-43500.svg)


## CVE-2026-3844
 The Breeze Cache plugin for WordPress is vulnerable to arbitrary file uploads due to missing file type validation in the 'fetch_gravatar_from_remote' function in all versions up to, and including, 2.4.4. This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible. The vulnerability can only be exploited if "Host Files Locally - Gravatars" is enabled, which is disabled by default.

- [https://github.com/zycoder0day/CVE-2026-3844](https://github.com/zycoder0day/CVE-2026-3844) :  ![starts](https://img.shields.io/github/stars/zycoder0day/CVE-2026-3844.svg) ![forks](https://img.shields.io/github/forks/zycoder0day/CVE-2026-3844.svg)


## CVE-2026-3698
 A vulnerability was identified in UTT HiPER 810G up to 1.7.7-171114. This affects the function strcpy of the file /goform/NTP. The manipulation leads to buffer overflow. The attack may be initiated remotely. The exploit is publicly available and might be used.

- [https://github.com/canomer/CVE-2026-36981-Kernel-EoP-PoC](https://github.com/canomer/CVE-2026-36981-Kernel-EoP-PoC) :  ![starts](https://img.shields.io/github/stars/canomer/CVE-2026-36981-Kernel-EoP-PoC.svg) ![forks](https://img.shields.io/github/forks/canomer/CVE-2026-36981-Kernel-EoP-PoC.svg)
- [https://github.com/canomer/CVE-2026-36980-Kernel-BSOD-DoS-PoC](https://github.com/canomer/CVE-2026-36980-Kernel-BSOD-DoS-PoC) :  ![starts](https://img.shields.io/github/stars/canomer/CVE-2026-36980-Kernel-BSOD-DoS-PoC.svg) ![forks](https://img.shields.io/github/forks/canomer/CVE-2026-36980-Kernel-BSOD-DoS-PoC.svg)


## CVE-2025-68664
 LangChain is a framework for building agents and LLM-powered applications. Prior to versions 0.3.81 and 1.2.5, a serialization injection vulnerability exists in LangChain's dumps() and dumpd() functions. The functions do not escape dictionaries with 'lc' keys when serializing free-form dictionaries. The 'lc' key is used internally by LangChain to mark serialized objects. When user-controlled data contains this key structure, it is treated as a legitimate LangChain object during deserialization rather than plain user data. This issue has been patched in versions 0.3.81 and 1.2.5.

- [https://github.com/Johnnyzhou666/langgrinch-cve-2025-68664-analysis](https://github.com/Johnnyzhou666/langgrinch-cve-2025-68664-analysis) :  ![starts](https://img.shields.io/github/stars/Johnnyzhou666/langgrinch-cve-2025-68664-analysis.svg) ![forks](https://img.shields.io/github/forks/Johnnyzhou666/langgrinch-cve-2025-68664-analysis.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-transitive](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-transitive) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-transitive.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-transitive.svg)


## CVE-2025-58434
 Flowise is a drag & drop user interface to build a customized large language model flow. In version 3.0.5 and earlier, the `forgot-password` endpoint in Flowise returns sensitive information including a valid password reset `tempToken` without authentication or verification. This enables any attacker to generate a reset token for arbitrary users and directly reset their password, leading to a complete account takeover (ATO). This vulnerability applies to both the cloud service (`cloud.flowiseai.com`) and self-hosted/local Flowise deployments that expose the same API. Commit 9e178d68873eb876073846433a596590d3d9c863 in version 3.0.6 secures password reset endpoints. Several recommended remediation steps are available. Do not return reset tokens or sensitive account details in API responses. Tokens must only be delivered securely via the registered email channel. Ensure `forgot-password` responds with a generic success message regardless of input, to avoid user enumeration. Require strong validation of the `tempToken` (e.g., single-use, short expiry, tied to request origin, validated against email delivery). Apply the same fixes to both cloud and self-hosted/local deployments. Log and monitor password reset requests for suspicious activity. Consider multi-factor verification for sensitive accounts.

- [https://github.com/v3rycl0p3r/CVE-PoC-CVE-2025-58434](https://github.com/v3rycl0p3r/CVE-PoC-CVE-2025-58434) :  ![starts](https://img.shields.io/github/stars/v3rycl0p3r/CVE-PoC-CVE-2025-58434.svg) ![forks](https://img.shields.io/github/forks/v3rycl0p3r/CVE-PoC-CVE-2025-58434.svg)


## CVE-2025-41242
We have verified that applications deployed on Apache Tomcat or Eclipse Jetty are not vulnerable, as long as default security features are not disabled in the configuration. Because we cannot check exploits against all Servlet containers and configuration variants, we strongly recommend upgrading your application.

- [https://github.com/HORKimhab/CVE-2025-41242](https://github.com/HORKimhab/CVE-2025-41242) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2025-41242.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2025-41242.svg)


## CVE-2025-32463
 Sudo before 1.9.17p1 allows local users to obtain root access because /etc/nsswitch.conf from a user-controlled directory is used with the --chroot option.

- [https://github.com/v3rycl0p3r/CVE-2025-32463](https://github.com/v3rycl0p3r/CVE-2025-32463) :  ![starts](https://img.shields.io/github/stars/v3rycl0p3r/CVE-2025-32463.svg) ![forks](https://img.shields.io/github/forks/v3rycl0p3r/CVE-2025-32463.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/sn1p3rt3s7/NextJS_CVE-2025-29927](https://github.com/sn1p3rt3s7/NextJS_CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/sn1p3rt3s7/NextJS_CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/sn1p3rt3s7/NextJS_CVE-2025-29927.svg)


## CVE-2025-20700
 In the Airoha Bluetooth audio SDK, there is a possible permission bypass that allows access critical data of RACE protocol through Bluetooth LE GATT service. This could lead to remote escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/Yedidia-Bakuradze/mem-forensics-analysis](https://github.com/Yedidia-Bakuradze/mem-forensics-analysis) :  ![starts](https://img.shields.io/github/stars/Yedidia-Bakuradze/mem-forensics-analysis.svg) ![forks](https://img.shields.io/github/forks/Yedidia-Bakuradze/mem-forensics-analysis.svg)


## CVE-2025-6019
 A Local Privilege Escalation (LPE) vulnerability was found in libblockdev. Generally, the "allow_active" setting in Polkit permits a physically present user to take certain actions based on the session type. Due to the way libblockdev interacts with the udisks daemon, an "allow_active" user on a system may be able escalate to full root privileges on the target host. Normally, udisks mounts user-provided filesystem images with security flags like nosuid and nodev to prevent privilege escalation.  However, a local attacker can create a specially crafted XFS image containing a SUID-root shell, then trick udisks into resizing it. This mounts their malicious filesystem with root privileges, allowing them to execute their SUID-root shell and gain complete control of the system.

- [https://github.com/tr3m0x/CVE-2025-6019](https://github.com/tr3m0x/CVE-2025-6019) :  ![starts](https://img.shields.io/github/stars/tr3m0x/CVE-2025-6019.svg) ![forks](https://img.shields.io/github/forks/tr3m0x/CVE-2025-6019.svg)


## CVE-2025-4396
 The Relevanssi – A Better Search plugin for WordPress is vulnerable to time-based SQL Injection via the cats and tags query parameters in all versions up to, and including, 4.24.4 (Free) and = 2.27.5 (Premium) due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query.  This makes it possible for unauthenticated attackers to append additional SQL queries to already existing queries that can be used to extract sensitive information from the database.

- [https://github.com/sup3rDav3/CVE-2025-4396](https://github.com/sup3rDav3/CVE-2025-4396) :  ![starts](https://img.shields.io/github/stars/sup3rDav3/CVE-2025-4396.svg) ![forks](https://img.shields.io/github/forks/sup3rDav3/CVE-2025-4396.svg)


## CVE-2025-1094
 Improper neutralization of quoting syntax in PostgreSQL libpq functions PQescapeLiteral(), PQescapeIdentifier(), PQescapeString(), and PQescapeStringConn() allows a database input provider to achieve SQL injection in certain usage patterns.  Specifically, SQL injection requires the application to use the function result to construct input to psql, the PostgreSQL interactive terminal.  Similarly, improper neutralization of quoting syntax in PostgreSQL command line utility programs allows a source of command line arguments to achieve SQL injection when client_encoding is BIG5 and server_encoding is one of EUC_TW or MULE_INTERNAL.  Versions before PostgreSQL 17.3, 16.7, 15.11, 14.16, and 13.19 are affected.

- [https://github.com/TranDongA3/POC-CVE-2025-1094](https://github.com/TranDongA3/POC-CVE-2025-1094) :  ![starts](https://img.shields.io/github/stars/TranDongA3/POC-CVE-2025-1094.svg) ![forks](https://img.shields.io/github/forks/TranDongA3/POC-CVE-2025-1094.svg)


## CVE-2024-47176
 CUPS is a standards-based, open-source printing system, and `cups-browsed` contains network printing functionality including, but not limited to, auto-discovering print services and shared printers. `cups-browsed` binds to `INADDR_ANY:631`, causing it to trust any packet from any source, and can cause the `Get-Printer-Attributes` IPP request to an attacker controlled URL. When combined with other vulnerabilities, such as CVE-2024-47076, CVE-2024-47175, and CVE-2024-47177, an attacker can execute arbitrary commands remotely on the target machine without authentication when a malicious printer is printed to.

- [https://github.com/jimi2x/dirtycups](https://github.com/jimi2x/dirtycups) :  ![starts](https://img.shields.io/github/stars/jimi2x/dirtycups.svg) ![forks](https://img.shields.io/github/forks/jimi2x/dirtycups.svg)


## CVE-2024-31680
 File Upload vulnerability in Shibang Communications Co., Ltd. IP network intercom broadcasting system v.1.0 allows a local attacker to execute arbitrary code via the my_parser.php component.

- [https://github.com/h3rkk/CVE-2024-31680](https://github.com/h3rkk/CVE-2024-31680) :  ![starts](https://img.shields.io/github/stars/h3rkk/CVE-2024-31680.svg) ![forks](https://img.shields.io/github/forks/h3rkk/CVE-2024-31680.svg)


## CVE-2024-22120
 Zabbix server can perform command execution for configured scripts. After command is executed, audit entry is added to "Audit Log". Due to "clientip" field is not sanitized, it is possible to injection SQL into "clientip" and exploit time based blind SQL injection.

- [https://github.com/darkbytehunter/CVE-2024-22120-RCE-with-gopher](https://github.com/darkbytehunter/CVE-2024-22120-RCE-with-gopher) :  ![starts](https://img.shields.io/github/stars/darkbytehunter/CVE-2024-22120-RCE-with-gopher.svg) ![forks](https://img.shields.io/github/forks/darkbytehunter/CVE-2024-22120-RCE-with-gopher.svg)


## CVE-2024-12381
 Type Confusion in V8 in Google Chrome prior to 131.0.6778.139 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/FatfishIO/CVE-2024-12381-PoC](https://github.com/FatfishIO/CVE-2024-12381-PoC) :  ![starts](https://img.shields.io/github/stars/FatfishIO/CVE-2024-12381-PoC.svg) ![forks](https://img.shields.io/github/forks/FatfishIO/CVE-2024-12381-PoC.svg)


## CVE-2024-4367
 A type check was missing when handling fonts in PDF.js, which would allow arbitrary JavaScript execution in the PDF.js context. This vulnerability affects Firefox  126, Firefox ESR  115.11, and Thunderbird  115.11.

- [https://github.com/John-Popovici/CVE-2026-31431-CopyFail-Linux-PrivEsc](https://github.com/John-Popovici/CVE-2026-31431-CopyFail-Linux-PrivEsc) :  ![starts](https://img.shields.io/github/stars/John-Popovici/CVE-2026-31431-CopyFail-Linux-PrivEsc.svg) ![forks](https://img.shields.io/github/forks/John-Popovici/CVE-2026-31431-CopyFail-Linux-PrivEsc.svg)


## CVE-2024-4322
 A path traversal vulnerability exists in the parisneo/lollms-webui application, specifically within the `/list_personalities` endpoint. By manipulating the `category` parameter, an attacker can traverse the directory structure and list any directory on the system. This issue affects the latest version of the application. The vulnerability is due to improper handling of user-supplied input in the `list_personalities` function, where the `category` parameter can be controlled to specify arbitrary directories for listing. Successful exploitation of this vulnerability could allow an attacker to list all folders in the drive on the system, potentially leading to information disclosure.

- [https://github.com/MJ-bin/POC_CVE-2024-4322](https://github.com/MJ-bin/POC_CVE-2024-4322) :  ![starts](https://img.shields.io/github/stars/MJ-bin/POC_CVE-2024-4322.svg) ![forks](https://img.shields.io/github/forks/MJ-bin/POC_CVE-2024-4322.svg)


## CVE-2024-3829
 qdrant/qdrant version 1.9.0-dev is vulnerable to arbitrary file read and write during the snapshot recovery process. Attackers can exploit this vulnerability by manipulating snapshot files to include symlinks, leading to arbitrary file read by adding a symlink that points to a desired file on the filesystem and arbitrary file write by including a symlink and a payload file in the snapshot's directory structure. This vulnerability allows for the reading and writing of arbitrary files on the server, which could potentially lead to a full takeover of the system. The issue is fixed in version v1.9.0.

- [https://github.com/fabse-hack/CVE-2024-3829](https://github.com/fabse-hack/CVE-2024-3829) :  ![starts](https://img.shields.io/github/stars/fabse-hack/CVE-2024-3829.svg) ![forks](https://img.shields.io/github/forks/fabse-hack/CVE-2024-3829.svg)


## CVE-2023-34468
You are recommended to upgrade to version 1.22.0 or later which fixes this issue.

- [https://github.com/Jeanpt/CVE-2023-34468](https://github.com/Jeanpt/CVE-2023-34468) :  ![starts](https://img.shields.io/github/stars/Jeanpt/CVE-2023-34468.svg) ![forks](https://img.shields.io/github/forks/Jeanpt/CVE-2023-34468.svg)
- [https://github.com/Al3xx-sec/CVE-2023-34468-POC](https://github.com/Al3xx-sec/CVE-2023-34468-POC) :  ![starts](https://img.shields.io/github/stars/Al3xx-sec/CVE-2023-34468-POC.svg) ![forks](https://img.shields.io/github/forks/Al3xx-sec/CVE-2023-34468-POC.svg)


## CVE-2022-36804
 Multiple API endpoints in Atlassian Bitbucket Server and Data Center 7.0.0 before version 7.6.17, from version 7.7.0 before version 7.17.10, from version 7.18.0 before version 7.21.4, from version 8.0.0 before version 8.0.3, from version 8.1.0 before version 8.1.3, and from version 8.2.0 before version 8.2.2, and from version 8.3.0 before 8.3.1 allows remote attackers with read permissions to a public or private Bitbucket repository to execute arbitrary code by sending a malicious HTTP request. This vulnerability was reported via our Bug Bounty Program by TheGrandPew.

- [https://github.com/DanielHallbro/CVE-2022-36804-Bitbucket-RCE-Analysis](https://github.com/DanielHallbro/CVE-2022-36804-Bitbucket-RCE-Analysis) :  ![starts](https://img.shields.io/github/stars/DanielHallbro/CVE-2022-36804-Bitbucket-RCE-Analysis.svg) ![forks](https://img.shields.io/github/forks/DanielHallbro/CVE-2022-36804-Bitbucket-RCE-Analysis.svg)


## CVE-2022-0847
 A flaw was found in the way the "flags" member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/0xlane/pagecache-guard](https://github.com/0xlane/pagecache-guard) :  ![starts](https://img.shields.io/github/stars/0xlane/pagecache-guard.svg) ![forks](https://img.shields.io/github/forks/0xlane/pagecache-guard.svg)
- [https://github.com/AyoubNajim/cve-2022-0847dirtypipe-exploit](https://github.com/AyoubNajim/cve-2022-0847dirtypipe-exploit) :  ![starts](https://img.shields.io/github/stars/AyoubNajim/cve-2022-0847dirtypipe-exploit.svg) ![forks](https://img.shields.io/github/forks/AyoubNajim/cve-2022-0847dirtypipe-exploit.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/12345qwert123456/CVE-2021-41773](https://github.com/12345qwert123456/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/12345qwert123456/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/12345qwert123456/CVE-2021-41773.svg)
- [https://github.com/Taldrid1/cve-2021-41773](https://github.com/Taldrid1/cve-2021-41773) :  ![starts](https://img.shields.io/github/stars/Taldrid1/cve-2021-41773.svg) ![forks](https://img.shields.io/github/forks/Taldrid1/cve-2021-41773.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/Fato07/Pwnkit-exploit](https://github.com/Fato07/Pwnkit-exploit) :  ![starts](https://img.shields.io/github/stars/Fato07/Pwnkit-exploit.svg) ![forks](https://img.shields.io/github/forks/Fato07/Pwnkit-exploit.svg)


## CVE-2021-1675
 Windows Print Spooler Remote Code Execution Vulnerability

- [https://github.com/thalpius/microsoft-cve-2021-1675](https://github.com/thalpius/microsoft-cve-2021-1675) :  ![starts](https://img.shields.io/github/stars/thalpius/microsoft-cve-2021-1675.svg) ![forks](https://img.shields.io/github/forks/thalpius/microsoft-cve-2021-1675.svg)


## CVE-2020-26160
 jwt-go before 4.0.0-preview1 allows attackers to bypass intended access restrictions in situations with []string{} for m["aud"] (which is allowed by the specification). Because the type assertion fails, "" is the value of aud. This is a security problem if the JWT token is presented to a service that lacks its own audience check.

- [https://github.com/mlbrilliance/aurora-demo-lockfile](https://github.com/mlbrilliance/aurora-demo-lockfile) :  ![starts](https://img.shields.io/github/stars/mlbrilliance/aurora-demo-lockfile.svg) ![forks](https://img.shields.io/github/forks/mlbrilliance/aurora-demo-lockfile.svg)


## CVE-2020-0423
 In binder_release_work of binder.c, there is a possible use-after-free due to improper locking. This could lead to local escalation of privilege in the kernel with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-161151868References: N/A

- [https://github.com/wired0ut/CVE-2020-0423](https://github.com/wired0ut/CVE-2020-0423) :  ![starts](https://img.shields.io/github/stars/wired0ut/CVE-2020-0423.svg) ![forks](https://img.shields.io/github/forks/wired0ut/CVE-2020-0423.svg)


## CVE-2019-10744
 Versions of lodash lower than 4.17.12 are vulnerable to Prototype Pollution. The function defaultsDeep could be tricked into adding or modifying properties of Object.prototype using a constructor payload.

- [https://github.com/mlbrilliance/aurora-demo-lockfile](https://github.com/mlbrilliance/aurora-demo-lockfile) :  ![starts](https://img.shields.io/github/stars/mlbrilliance/aurora-demo-lockfile.svg) ![forks](https://img.shields.io/github/forks/mlbrilliance/aurora-demo-lockfile.svg)


## CVE-2018-19323
 The GDrv low-level driver in GIGABYTE APP Center v1.05.21 and earlier, AORUS GRAPHICS ENGINE before 1.57, XTREME GAMING ENGINE before 1.26, and OC GURU II v2.08 exposes functionality to read and write Machine Specific Registers (MSRs).

- [https://github.com/blueisbeautiful/CVE-2018-19323](https://github.com/blueisbeautiful/CVE-2018-19323) :  ![starts](https://img.shields.io/github/stars/blueisbeautiful/CVE-2018-19323.svg) ![forks](https://img.shields.io/github/forks/blueisbeautiful/CVE-2018-19323.svg)


## CVE-2018-18074
 The Requests package before 2.20.0 for Python sends an HTTP Authorization header to an http URI upon receiving a same-hostname https-to-http redirect, which makes it easier for remote attackers to discover credentials by sniffing the network.

- [https://github.com/mlbrilliance/aurora-demo-lockfile](https://github.com/mlbrilliance/aurora-demo-lockfile) :  ![starts](https://img.shields.io/github/stars/mlbrilliance/aurora-demo-lockfile.svg) ![forks](https://img.shields.io/github/forks/mlbrilliance/aurora-demo-lockfile.svg)

