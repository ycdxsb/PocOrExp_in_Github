# Update 2026-05-17
## CVE-2026-44578
 Next.js is a React framework for building full-stack web applications. From 13.4.13 to before 15.5.16 and 16.2.5, self-hosted applications using the built-in Node.js server can be vulnerable to server-side request forgery through crafted WebSocket upgrade requests. An attacker can cause the server to proxy requests to arbitrary internal or external destinations, which may expose internal services or cloud metadata endpoints. Vercel-hosted deployments are not affected. This vulnerability is fixed in 15.5.16 and 16.2.5.

- [https://github.com/ynsmroztas/nextssrf](https://github.com/ynsmroztas/nextssrf) :  ![starts](https://img.shields.io/github/stars/ynsmroztas/nextssrf.svg) ![forks](https://img.shields.io/github/forks/ynsmroztas/nextssrf.svg)
- [https://github.com/love07oj/nextjs-cve-2026-44578](https://github.com/love07oj/nextjs-cve-2026-44578) :  ![starts](https://img.shields.io/github/stars/love07oj/nextjs-cve-2026-44578.svg) ![forks](https://img.shields.io/github/forks/love07oj/nextjs-cve-2026-44578.svg)
- [https://github.com/tocong282/CVE-2026-44578-PoC](https://github.com/tocong282/CVE-2026-44578-PoC) :  ![starts](https://img.shields.io/github/stars/tocong282/CVE-2026-44578-PoC.svg) ![forks](https://img.shields.io/github/forks/tocong282/CVE-2026-44578-PoC.svg)


## CVE-2026-44338
 PraisonAI is a multi-agent teams system. From version 2.5.6 to before version 4.6.34, PraisonAI ships a legacy Flask API server with authentication disabled by default. When that server is used, any caller that can reach it can access /agents and trigger the configured agents.yaml workflow through /chat without providing a token. This issue has been patched in version 4.6.34.

- [https://github.com/HORKimhab/CVE-2026-44338](https://github.com/HORKimhab/CVE-2026-44338) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-44338.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-44338.svg)
- [https://github.com/rootdirective-sec/CVE-2026-44338-Lab](https://github.com/rootdirective-sec/CVE-2026-44338-Lab) :  ![starts](https://img.shields.io/github/stars/rootdirective-sec/CVE-2026-44338-Lab.svg) ![forks](https://img.shields.io/github/forks/rootdirective-sec/CVE-2026-44338-Lab.svg)


## CVE-2026-43284
destination-frag path or fall back to skb_cow_data().

- [https://github.com/grabesec/XCP_ng_CVE-2026-43284_tester](https://github.com/grabesec/XCP_ng_CVE-2026-43284_tester) :  ![starts](https://img.shields.io/github/stars/grabesec/XCP_ng_CVE-2026-43284_tester.svg) ![forks](https://img.shields.io/github/forks/grabesec/XCP_ng_CVE-2026-43284_tester.svg)
- [https://github.com/xd20111/CVE-2026-43284](https://github.com/xd20111/CVE-2026-43284) :  ![starts](https://img.shields.io/github/stars/xd20111/CVE-2026-43284.svg) ![forks](https://img.shields.io/github/forks/xd20111/CVE-2026-43284.svg)


## CVE-2026-42945
 NGINX Plus and NGINX Open Source have a vulnerability in the ngx_http_rewrite_module module. This vulnerability exists when the rewrite directive is followed by a rewrite, if, or set directive and an unnamed Perl-Compatible Regular Expression (PCRE) capture (for example, $1, $2) with a replacement string that includes a question mark (?). An unauthenticated attacker along with conditions beyond its control can exploit this vulnerability by sending crafted HTTP requests. This may cause a heap buffer overflow in the NGINX worker process leading to a restart. Additionally, for systems with Address Space Layout Randomization (ASLR ) disabled, code execution is possible.  Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/oseasfr/Scanner_CVE_2026-42945](https://github.com/oseasfr/Scanner_CVE_2026-42945) :  ![starts](https://img.shields.io/github/stars/oseasfr/Scanner_CVE_2026-42945.svg) ![forks](https://img.shields.io/github/forks/oseasfr/Scanner_CVE_2026-42945.svg)
- [https://github.com/iammerrida-source/nginx-rift-detect](https://github.com/iammerrida-source/nginx-rift-detect) :  ![starts](https://img.shields.io/github/stars/iammerrida-source/nginx-rift-detect.svg) ![forks](https://img.shields.io/github/forks/iammerrida-source/nginx-rift-detect.svg)
- [https://github.com/chenqin231/CVE-2026-42945](https://github.com/chenqin231/CVE-2026-42945) :  ![starts](https://img.shields.io/github/stars/chenqin231/CVE-2026-42945.svg) ![forks](https://img.shields.io/github/forks/chenqin231/CVE-2026-42945.svg)
- [https://github.com/jelasin/CVE-2026-42945](https://github.com/jelasin/CVE-2026-42945) :  ![starts](https://img.shields.io/github/stars/jelasin/CVE-2026-42945.svg) ![forks](https://img.shields.io/github/forks/jelasin/CVE-2026-42945.svg)
- [https://github.com/forxiucn/nginx-cve-2026-42945-poc](https://github.com/forxiucn/nginx-cve-2026-42945-poc) :  ![starts](https://img.shields.io/github/stars/forxiucn/nginx-cve-2026-42945-poc.svg) ![forks](https://img.shields.io/github/forks/forxiucn/nginx-cve-2026-42945-poc.svg)
- [https://github.com/byezero/nginx-cve-2026-42945-check](https://github.com/byezero/nginx-cve-2026-42945-check) :  ![starts](https://img.shields.io/github/stars/byezero/nginx-cve-2026-42945-check.svg) ![forks](https://img.shields.io/github/forks/byezero/nginx-cve-2026-42945-check.svg)
- [https://github.com/soksofos/wazuh-nginx-cve-2026-42945-sca-lab](https://github.com/soksofos/wazuh-nginx-cve-2026-42945-sca-lab) :  ![starts](https://img.shields.io/github/stars/soksofos/wazuh-nginx-cve-2026-42945-sca-lab.svg) ![forks](https://img.shields.io/github/forks/soksofos/wazuh-nginx-cve-2026-42945-sca-lab.svg)


## CVE-2026-42897
 Improper neutralization of input during web page generation ('cross-site scripting') in Microsoft Exchange Server allows an unauthorized attacker to perform spoofing over a network.

- [https://github.com/atiilla/CVE-2026-42897](https://github.com/atiilla/CVE-2026-42897) :  ![starts](https://img.shields.io/github/stars/atiilla/CVE-2026-42897.svg) ![forks](https://img.shields.io/github/forks/atiilla/CVE-2026-42897.svg)


## CVE-2026-42203
 LiteLLM is a proxy server (AI Gateway) to call LLM APIs in OpenAI (or native) format. From version 1.80.5 to before version 1.83.7, the POST /prompts/test endpoint accepted user-supplied prompt templates and rendered them without sandboxing. A crafted template could run arbitrary code inside the LiteLLM Proxy process. The endpoint only checks that the caller presents a valid proxy API key, so any authenticated user could reach it. Depending on how the proxy is deployed, this could expose secrets in the process environment (such as provider API keys or database credentials) and allow commands to be run on the host. This issue has been patched in version 1.83.7.

- [https://github.com/Astianjy/CVE-2026-42203](https://github.com/Astianjy/CVE-2026-42203) :  ![starts](https://img.shields.io/github/stars/Astianjy/CVE-2026-42203.svg) ![forks](https://img.shields.io/github/forks/Astianjy/CVE-2026-42203.svg)


## CVE-2026-42154
 Prometheus is an open-source monitoring system and time series database. Prior to versions 3.5.3 and 3.11.3, the remote read endpoint (/api/v1/read) does not validate the declared decoded length in a snappy-compressed request body before allocating memory. An unauthenticated attacker can send a small payload that causes a huge heap allocation per request. Under concurrent load this can exhaust available memory and crash the Prometheus process. This issue has been patched in versions 3.5.3 and 3.11.3.

- [https://github.com/ShadowByte1/CVE-2026-42154](https://github.com/ShadowByte1/CVE-2026-42154) :  ![starts](https://img.shields.io/github/stars/ShadowByte1/CVE-2026-42154.svg) ![forks](https://img.shields.io/github/forks/ShadowByte1/CVE-2026-42154.svg)


## CVE-2026-41096
 Heap-based buffer overflow in Microsoft Windows DNS allows an unauthorized attacker to execute code over a network.

- [https://github.com/mrk336/DNS-Mayhem-CVE-2026-41096-Deep-Dive](https://github.com/mrk336/DNS-Mayhem-CVE-2026-41096-Deep-Dive) :  ![starts](https://img.shields.io/github/stars/mrk336/DNS-Mayhem-CVE-2026-41096-Deep-Dive.svg) ![forks](https://img.shields.io/github/forks/mrk336/DNS-Mayhem-CVE-2026-41096-Deep-Dive.svg)


## CVE-2026-41044
Users are recommended to upgrade to version 6.2.5 or 5.19.6, which fixes the issue.

- [https://github.com/mrillicit/CVE-2026-41044](https://github.com/mrillicit/CVE-2026-41044) :  ![starts](https://img.shields.io/github/stars/mrillicit/CVE-2026-41044.svg) ![forks](https://img.shields.io/github/forks/mrillicit/CVE-2026-41044.svg)


## CVE-2026-39987
 marimo is a reactive Python notebook. Prior to 0.23.0, Marimo has a Pre-Auth RCE vulnerability. The terminal WebSocket endpoint /terminal/ws lacks authentication validation, allowing an unauthenticated attacker to obtain a full PTY shell and execute arbitrary system commands. Unlike other WebSocket endpoints (e.g., /ws) that correctly call validate_auth() for authentication, the /terminal/ws endpoint only checks the running mode and platform support before accepting connections, completely skipping authentication verification. This vulnerability is fixed in 0.23.0.

- [https://github.com/0xdeadroot/CVE-2026-39987-marimo-rce](https://github.com/0xdeadroot/CVE-2026-39987-marimo-rce) :  ![starts](https://img.shields.io/github/stars/0xdeadroot/CVE-2026-39987-marimo-rce.svg) ![forks](https://img.shields.io/github/forks/0xdeadroot/CVE-2026-39987-marimo-rce.svg)


## CVE-2026-31431
AD directly.

- [https://github.com/Koshmare-Blossom/Copyfail-sh](https://github.com/Koshmare-Blossom/Copyfail-sh) :  ![starts](https://img.shields.io/github/stars/Koshmare-Blossom/Copyfail-sh.svg) ![forks](https://img.shields.io/github/forks/Koshmare-Blossom/Copyfail-sh.svg)
- [https://github.com/ctzisme/copyfail-guard](https://github.com/ctzisme/copyfail-guard) :  ![starts](https://img.shields.io/github/stars/ctzisme/copyfail-guard.svg) ![forks](https://img.shields.io/github/forks/ctzisme/copyfail-guard.svg)
- [https://github.com/luotian2/CVE-2026-31431](https://github.com/luotian2/CVE-2026-31431) :  ![starts](https://img.shields.io/github/stars/luotian2/CVE-2026-31431.svg) ![forks](https://img.shields.io/github/forks/luotian2/CVE-2026-31431.svg)


## CVE-2026-29145
Users are recommended to upgrade to version Tomcat Native 1.3.7 or 2.0.14 and Tomcat 11.0.20, 10.1.53 and 9.0.116, which fix the issue.

- [https://github.com/Chenjp/CVE-2026-29145-Tester](https://github.com/Chenjp/CVE-2026-29145-Tester) :  ![starts](https://img.shields.io/github/stars/Chenjp/CVE-2026-29145-Tester.svg) ![forks](https://img.shields.io/github/forks/Chenjp/CVE-2026-29145-Tester.svg)


## CVE-2026-24332
 Discord through 2026-01-16 allows gathering information about whether a user's client state is Invisible (and not actually offline) because the response to a WebSocket API request includes the user in the presences array (with "status": "offline"), whereas offline users are omitted from the presences array. This is arguably inconsistent with the UI description of Invisible as "You will appear offline."

- [https://github.com/WhiteTPoison100/Discord-CVE-2026-24332-demo](https://github.com/WhiteTPoison100/Discord-CVE-2026-24332-demo) :  ![starts](https://img.shields.io/github/stars/WhiteTPoison100/Discord-CVE-2026-24332-demo.svg) ![forks](https://img.shields.io/github/forks/WhiteTPoison100/Discord-CVE-2026-24332-demo.svg)


## CVE-2026-24009
 Docling Core (or docling-core) is a library that defines core data types and transformations in the document processing application Docling. A PyYAML-related Remote Code Execution (RCE) vulnerability, namely CVE-2020-14343, is exposed in docling-core starting in version 2.21.0 and prior to version 2.48.4, specifically only if the application uses pyyaml prior to version 5.4 and invokes `docling_core.types.doc.DoclingDocument.load_from_yaml()` passing it untrusted YAML data. The vulnerability has been patched in docling-core version 2.48.4. The fix mitigates the issue by switching `PyYAML` deserialization from `yaml.FullLoader` to `yaml.SafeLoader`, ensuring that untrusted data cannot trigger code execution. Users who cannot immediately upgrade docling-core can alternatively ensure that the installed version of PyYAML is 5.4 or greater.

- [https://github.com/BiranPeretz/docling-core-CVE-2026-24009](https://github.com/BiranPeretz/docling-core-CVE-2026-24009) :  ![starts](https://img.shields.io/github/stars/BiranPeretz/docling-core-CVE-2026-24009.svg) ![forks](https://img.shields.io/github/forks/BiranPeretz/docling-core-CVE-2026-24009.svg)


## CVE-2026-20224
This vulnerability is due to improper handling of XML External Entity (XXE) entries when parsing an XML file. An attacker could exploit this vulnerability by sending a crafted request to an affected system. A successful exploit could allow the attacker to read arbitrary files that are stored in the affected system.

- [https://github.com/fevar54/CVE-2026-20224---XXE-Injection-en-Cisco-Catalyst-SD-WAN-Manager](https://github.com/fevar54/CVE-2026-20224---XXE-Injection-en-Cisco-Catalyst-SD-WAN-Manager) :  ![starts](https://img.shields.io/github/stars/fevar54/CVE-2026-20224---XXE-Injection-en-Cisco-Catalyst-SD-WAN-Manager.svg) ![forks](https://img.shields.io/github/forks/fevar54/CVE-2026-20224---XXE-Injection-en-Cisco-Catalyst-SD-WAN-Manager.svg)


## CVE-2026-20182
This vulnerability exists because the peering authentication mechanism in an affected system is not working properly. An attacker could exploit this vulnerability by sending crafted requests to the affected system. A successful exploit could allow the attacker to log in to an affected Cisco Catalyst SD-WAN Controller as an internal, high-privileged, non-root user account. Using this account, the attacker could access NETCONF, which would then allow the attacker to manipulate network configuration for the SD-WAN fabric.

- [https://github.com/fangbarristerbar/CVE-2026-20182-POC](https://github.com/fangbarristerbar/CVE-2026-20182-POC) :  ![starts](https://img.shields.io/github/stars/fangbarristerbar/CVE-2026-20182-POC.svg) ![forks](https://img.shields.io/github/forks/fangbarristerbar/CVE-2026-20182-POC.svg)


## CVE-2026-8181
 The Burst Statistics – Privacy-Friendly WordPress Analytics (Google Analytics Alternative) plugin for WordPress is vulnerable to Authentication Bypass in versions 3.4.0 to 3.4.1.1. This is due to incorrect return-value handling in the `is_mainwp_authenticated()` function when validating application passwords from the Authorization header. This makes it possible for unauthenticated attackers, with knowledge of an administrator username, to impersonate that administrator for the duration of the request by supplying any random Basic Authentication password achieving privilege escalation.

- [https://github.com/murrez/CVE-2026-8181](https://github.com/murrez/CVE-2026-8181) :  ![starts](https://img.shields.io/github/stars/murrez/CVE-2026-8181.svg) ![forks](https://img.shields.io/github/forks/murrez/CVE-2026-8181.svg)


## CVE-2026-0770
The specific flaw exists within the handling of the exec_globals parameter provided to the validate endpoint. The issue results from the inclusion of a resource from an untrusted control sphere. An attacker can leverage this vulnerability to execute code in the context of root. Was ZDI-CAN-27325.

- [https://github.com/Ez4rd1x1/CVE-2026-0770](https://github.com/Ez4rd1x1/CVE-2026-0770) :  ![starts](https://img.shields.io/github/stars/Ez4rd1x1/CVE-2026-0770.svg) ![forks](https://img.shields.io/github/forks/Ez4rd1x1/CVE-2026-0770.svg)


## CVE-2026-0745
 The User Language Switch plugin for WordPress is vulnerable to Server-Side Request Forgery in all versions up to, and including, 1.6.10 due to missing URL validation on the 'download_language()' function. This makes it possible for authenticated attackers, with Administrator-level access and above, to make web requests to arbitrary locations originating from the web application and can be used to query and modify information from internal services.

- [https://github.com/HORKimhab/CVE-2026-0745](https://github.com/HORKimhab/CVE-2026-0745) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-0745.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-0745.svg)


## CVE-2025-70849
 Arbitrary File Upload in podinfo thru 6.9.0 allows unauthenticated attackers to upload arbitrary files via crafted POST request to the /store endpoint. The application renders uploaded content without a restrictive Content-Security-Policy (CSP) or adequate Content-Type validation, leading to Stored Cross-Site Scripting (XSS).

- [https://github.com/deaprojects/CVE-2025-70849](https://github.com/deaprojects/CVE-2025-70849) :  ![starts](https://img.shields.io/github/stars/deaprojects/CVE-2025-70849.svg) ![forks](https://img.shields.io/github/forks/deaprojects/CVE-2025-70849.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-15x](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-15x) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-15x.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-15x.svg)


## CVE-2025-53392
 In Netgate pfSense CE 2.8.0, the "WebCfg - Diagnostics: Command" privilege allows reading arbitrary files via diag_command.php dlPath directory traversal. NOTE: the Supplier's perspective is that this is intended behavior for this privilege level, and that system administrators are informed through both the product documentation and UI.

- [https://github.com/skraft9/pfsense-security-research](https://github.com/skraft9/pfsense-security-research) :  ![starts](https://img.shields.io/github/stars/skraft9/pfsense-security-research.svg) ![forks](https://img.shields.io/github/forks/skraft9/pfsense-security-research.svg)


## CVE-2025-32432
 Craft is a flexible, user-friendly CMS for creating custom digital experiences on the web and beyond. Starting from version 3.0.0-RC1 to before 3.9.15, 4.0.0-RC1 to before 4.14.15, and 5.0.0-RC1 to before 5.6.17, Craft is vulnerable to remote code execution. This is a high-impact, low-complexity attack vector. This issue has been patched in versions 3.9.15, 4.14.15, and 5.6.17, and is an additional fix for CVE-2023-41892.

- [https://github.com/cd-ratel/CVE-2025-32432](https://github.com/cd-ratel/CVE-2025-32432) :  ![starts](https://img.shields.io/github/stars/cd-ratel/CVE-2025-32432.svg) ![forks](https://img.shields.io/github/forks/cd-ratel/CVE-2025-32432.svg)
- [https://github.com/ZzHotte/cve-2025-32432-replication-lab](https://github.com/ZzHotte/cve-2025-32432-replication-lab) :  ![starts](https://img.shields.io/github/stars/ZzHotte/cve-2025-32432-replication-lab.svg) ![forks](https://img.shields.io/github/forks/ZzHotte/cve-2025-32432-replication-lab.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/DanielHallbro/CVE-2025-29927-Nextjs-Bypass-PoC](https://github.com/DanielHallbro/CVE-2025-29927-Nextjs-Bypass-PoC) :  ![starts](https://img.shields.io/github/stars/DanielHallbro/CVE-2025-29927-Nextjs-Bypass-PoC.svg) ![forks](https://img.shields.io/github/forks/DanielHallbro/CVE-2025-29927-Nextjs-Bypass-PoC.svg)


## CVE-2025-25763
 crmeb CRMEB-KY v5.4.0 and before has a SQL Injection vulnerability at getRead() in /system/SystemDatabackupServices.php

- [https://github.com/Oyst3r1ng/CVE-2025-25763](https://github.com/Oyst3r1ng/CVE-2025-25763) :  ![starts](https://img.shields.io/github/stars/Oyst3r1ng/CVE-2025-25763.svg) ![forks](https://img.shields.io/github/forks/Oyst3r1ng/CVE-2025-25763.svg)


## CVE-2025-25620
 Unifiedtransform 2.0 is vulnerable to Cross Site Scripting (XSS) in the Create assignment function.

- [https://github.com/armaansidana2003/CVE-2025-25620](https://github.com/armaansidana2003/CVE-2025-25620) :  ![starts](https://img.shields.io/github/stars/armaansidana2003/CVE-2025-25620.svg) ![forks](https://img.shields.io/github/forks/armaansidana2003/CVE-2025-25620.svg)


## CVE-2025-25617
 Incorrect Access Control in Unifiedtransform 2.X leads to Privilege Escalation allowing teachers to create syllabus.

- [https://github.com/armaansidana2003/CVE-2025-25617](https://github.com/armaansidana2003/CVE-2025-25617) :  ![starts](https://img.shields.io/github/stars/armaansidana2003/CVE-2025-25617.svg) ![forks](https://img.shields.io/github/forks/armaansidana2003/CVE-2025-25617.svg)


## CVE-2025-9074
This can lead to execution of a wide range of privileged commands to the engine API, including controlling other containers, creating new ones, managing images etc. In some circumstances (e.g. Docker Desktop for Windows with WSL backend) it also allows mounting the host drive with the same privileges as the user running Docker Desktop.

- [https://github.com/Medaz-Sploit/CVE-2025-9074-Docker-Desktop-API-Escape-PoC](https://github.com/Medaz-Sploit/CVE-2025-9074-Docker-Desktop-API-Escape-PoC) :  ![starts](https://img.shields.io/github/stars/Medaz-Sploit/CVE-2025-9074-Docker-Desktop-API-Escape-PoC.svg) ![forks](https://img.shields.io/github/forks/Medaz-Sploit/CVE-2025-9074-Docker-Desktop-API-Escape-PoC.svg)


## CVE-2024-36042
 Silverpeas before 6.3.5 allows authentication bypass by omitting the Password field to AuthenticationServlet, often providing an unauthenticated user with superadmin access.

- [https://github.com/HA5ANT/Silverpeas-AuthBypass-CVE-2024-36042](https://github.com/HA5ANT/Silverpeas-AuthBypass-CVE-2024-36042) :  ![starts](https://img.shields.io/github/stars/HA5ANT/Silverpeas-AuthBypass-CVE-2024-36042.svg) ![forks](https://img.shields.io/github/forks/HA5ANT/Silverpeas-AuthBypass-CVE-2024-36042.svg)


## CVE-2024-21907
 Newtonsoft.Json before version 13.0.1 is affected by a mishandling of exceptional conditions vulnerability. Crafted data that is passed to the JsonConvert.DeserializeObject method may trigger a StackOverflow exception resulting in denial of service. Depending on the usage of the library, an unauthenticated and remote attacker may be able to cause the denial of service condition.

- [https://github.com/seal-sec-demo-2/seal-security-nuget-demo-net7](https://github.com/seal-sec-demo-2/seal-security-nuget-demo-net7) :  ![starts](https://img.shields.io/github/stars/seal-sec-demo-2/seal-security-nuget-demo-net7.svg) ![forks](https://img.shields.io/github/forks/seal-sec-demo-2/seal-security-nuget-demo-net7.svg)


## CVE-2023-44487
 The HTTP/2 protocol allows a denial of service (server resource consumption) because request cancellation can reset many streams quickly, as exploited in the wild in August through October 2023.

- [https://github.com/Hirokiii/CVE-2023-44487](https://github.com/Hirokiii/CVE-2023-44487) :  ![starts](https://img.shields.io/github/stars/Hirokiii/CVE-2023-44487.svg) ![forks](https://img.shields.io/github/forks/Hirokiii/CVE-2023-44487.svg)


## CVE-2023-20963
 In WorkSource, there is a possible parcel mismatch. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-11 Android-12 Android-12L Android-13Android ID: A-220302519

- [https://github.com/pwnipc/BadParcel](https://github.com/pwnipc/BadParcel) :  ![starts](https://img.shields.io/github/stars/pwnipc/BadParcel.svg) ![forks](https://img.shields.io/github/forks/pwnipc/BadParcel.svg)
- [https://github.com/Trinadh465/frameworks_base_AOSP10_r33_CVE-2023-20963](https://github.com/Trinadh465/frameworks_base_AOSP10_r33_CVE-2023-20963) :  ![starts](https://img.shields.io/github/stars/Trinadh465/frameworks_base_AOSP10_r33_CVE-2023-20963.svg) ![forks](https://img.shields.io/github/forks/Trinadh465/frameworks_base_AOSP10_r33_CVE-2023-20963.svg)


## CVE-2023-20904
 In getTrampolineIntent of SettingsActivity.java, there is a possible launch of arbitrary activity due to an Intent mismatch in the code. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-12L Android-13Android ID: A-246300272

- [https://github.com/FishMan132/CVE-2023-20904](https://github.com/FishMan132/CVE-2023-20904) :  ![starts](https://img.shields.io/github/stars/FishMan132/CVE-2023-20904.svg) ![forks](https://img.shields.io/github/forks/FishMan132/CVE-2023-20904.svg)


## CVE-2023-20178
 This vulnerability exists because improper permissions are assigned to a temporary directory that is created during the update process. An attacker could exploit this vulnerability by abusing a specific function of the Windows installer process. A successful exploit could allow the attacker to execute code with SYSTEM privileges.

- [https://github.com/Wh04m1001/CVE-2023-20178](https://github.com/Wh04m1001/CVE-2023-20178) :  ![starts](https://img.shields.io/github/stars/Wh04m1001/CVE-2023-20178.svg) ![forks](https://img.shields.io/github/forks/Wh04m1001/CVE-2023-20178.svg)


## CVE-2022-37969
 Windows Common Log File System Driver Elevation of Privilege Vulnerability

- [https://github.com/nhh9905/CVE-2022-37969](https://github.com/nhh9905/CVE-2022-37969) :  ![starts](https://img.shields.io/github/stars/nhh9905/CVE-2022-37969.svg) ![forks](https://img.shields.io/github/forks/nhh9905/CVE-2022-37969.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/wolf1892/CVE-2021-41773](https://github.com/wolf1892/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/wolf1892/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/wolf1892/CVE-2021-41773.svg)
- [https://github.com/honypot/CVE-2021-41773](https://github.com/honypot/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/honypot/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/honypot/CVE-2021-41773.svg)
- [https://github.com/Taldrid1/cve-2021-41773](https://github.com/Taldrid1/cve-2021-41773) :  ![starts](https://img.shields.io/github/stars/Taldrid1/cve-2021-41773.svg) ![forks](https://img.shields.io/github/forks/Taldrid1/cve-2021-41773.svg)


## CVE-2021-21425
 Grav Admin Plugin is an HTML user interface that provides a way to configure Grav and create and modify pages. In versions 1.10.7 and earlier, an unauthenticated user can execute some methods of administrator controller without needing any credentials. Particular method execution will result in arbitrary YAML file creation or content change of existing YAML files on the system. Successfully exploitation of that vulnerability results in configuration changes, such as general site information change, custom scheduler job definition, etc. Due to the nature of the vulnerability, an adversary can change some part of the webpage, or hijack an administrator account, or execute operating system command under the context of the web-server user. This vulnerability is fixed in version 1.10.8. Blocking access to the `/admin` path from untrusted sources can be applied as a workaround.

- [https://github.com/TeddyEngel/CVE-2021-21425](https://github.com/TeddyEngel/CVE-2021-21425) :  ![starts](https://img.shields.io/github/stars/TeddyEngel/CVE-2021-21425.svg) ![forks](https://img.shields.io/github/forks/TeddyEngel/CVE-2021-21425.svg)


## CVE-2019-0227
 A Server Side Request Forgery (SSRF) vulnerability affected the Apache Axis 1.4 distribution that was last released in 2006. Security and bug commits commits continue in the projects Axis 1.x Subversion repository, legacy users are encouraged to build from source. The successor to Axis 1.x is Axis2, the latest version is 1.7.9 and is not vulnerable to this issue.

- [https://github.com/1475210817/Axis1.4-CVE-2019-0227](https://github.com/1475210817/Axis1.4-CVE-2019-0227) :  ![starts](https://img.shields.io/github/stars/1475210817/Axis1.4-CVE-2019-0227.svg) ![forks](https://img.shields.io/github/forks/1475210817/Axis1.4-CVE-2019-0227.svg)


## CVE-2017-11499
 Node.js v4.0 through v4.8.3, all versions of v5.x, v6.0 through v6.11.0, v7.0 through v7.10.0, and v8.0 through v8.1.3 was susceptible to hash flooding remote DoS attacks as the HashTable seed was constant across a given released version of Node.js. This was a result of building with V8 snapshots enabled by default which caused the initially randomized seed to be overwritten on startup.

- [https://github.com/open-flaw/CVE-2017-11499](https://github.com/open-flaw/CVE-2017-11499) :  ![starts](https://img.shields.io/github/stars/open-flaw/CVE-2017-11499.svg) ![forks](https://img.shields.io/github/forks/open-flaw/CVE-2017-11499.svg)


## CVE-2015-3256
 PolicyKit (aka polkit) before 0.113 allows local users to cause a denial of service (memory corruption and polkitd daemon crash) and possibly gain privileges via unspecified vectors, related to "javascript rule evaluation."

- [https://github.com/puglia-ryan/S-V-Project-Implementation-of-CVE-2015-3256](https://github.com/puglia-ryan/S-V-Project-Implementation-of-CVE-2015-3256) :  ![starts](https://img.shields.io/github/stars/puglia-ryan/S-V-Project-Implementation-of-CVE-2015-3256.svg) ![forks](https://img.shields.io/github/forks/puglia-ryan/S-V-Project-Implementation-of-CVE-2015-3256.svg)


## CVE-2012-3153
 Unspecified vulnerability in the Oracle Reports Developer component in Oracle Fusion Middleware 11.1.1.4, 11.1.1.6, and 11.1.2.0 allows remote attackers to affect confidentiality and integrity via unknown vectors related to Servlet.  NOTE: the previous information is from the October 2012 CPU. Oracle has not commented on claims from the original researcher that the PARSEQUERY function allows remote attackers to obtain database credentials via reports/rwservlet/parsequery, and that this issue occurs in earlier versions.  NOTE: this can be leveraged with CVE-2012-3152 to execute arbitrary code by uploading a .jsp file.

- [https://github.com/abq0/rwsploit](https://github.com/abq0/rwsploit) :  ![starts](https://img.shields.io/github/stars/abq0/rwsploit.svg) ![forks](https://img.shields.io/github/forks/abq0/rwsploit.svg)


## CVE-2012-3152
 Unspecified vulnerability in the Oracle Reports Developer component in Oracle Fusion Middleware 11.1.1.4, 11.1.1.6, and 11.1.2.0 allows remote attackers to affect confidentiality and integrity via unknown vectors related to Report Server Component.  NOTE: the previous information is from the October 2012 CPU. Oracle has not commented on claims from the original researcher that the URLPARAMETER functionality allows remote attackers to read and upload arbitrary files to reports/rwservlet, and that this issue occurs in earlier versions.  NOTE: this can be leveraged with CVE-2012-3153 to execute arbitrary code by uploading a .jsp file.

- [https://github.com/abq0/rwsploit](https://github.com/abq0/rwsploit) :  ![starts](https://img.shields.io/github/stars/abq0/rwsploit.svg) ![forks](https://img.shields.io/github/forks/abq0/rwsploit.svg)


## CVE-2007-2447
 The MS-RPC functionality in smbd in Samba 3.0.0 through 3.0.25rc3 allows remote attackers to execute arbitrary commands via shell metacharacters involving the (1) SamrChangePassword function, when the "username map script" smb.conf option is enabled, and allows remote authenticated users to execute commands via shell metacharacters involving other MS-RPC functions in the (2) remote printer and (3) file share management.

- [https://github.com/r3vpwnx/CVE-2007-2447](https://github.com/r3vpwnx/CVE-2007-2447) :  ![starts](https://img.shields.io/github/stars/r3vpwnx/CVE-2007-2447.svg) ![forks](https://img.shields.io/github/forks/r3vpwnx/CVE-2007-2447.svg)

