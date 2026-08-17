# Update 2026-08-17
## CVE-2026-73847
 Emlog is an open source website building system. In 2.6.26 and earlier, missing CSRF protection on the AI Assistant execute_tool action in admin/ai.php lets a remote unauthenticated attacker submit a forged cross-site request from an attacker-controlled page to a recently logged-in administrator. The authentication cookie set in include/lib/loginauth.php has no explicit SameSite attribute, enabling Chrome's temporary Lax+POST grace window. The query_database case passes attacker-controlled sql and confirm_code values to Ai::queryDatabase in include/service/ai.php; read queries need no confirmation, write queries accept the public confirm string, only the blog table is write-protected, and aliasing password as pwd_hash bypasses output redaction. A successful request can read every database table and write every table except blog, including changing the user table to take over an administrator account. No fixed version is available as of this review.

- [https://github.com/squeeze440/CVE-2026-73847-emlog-PoC](https://github.com/squeeze440/CVE-2026-73847-emlog-PoC) :  ![starts](https://img.shields.io/github/stars/squeeze440/CVE-2026-73847-emlog-PoC.svg) ![forks](https://img.shields.io/github/forks/squeeze440/CVE-2026-73847-emlog-PoC.svg)


## CVE-2026-73678
 MindsDB Minds Platform version 26.1.0 and earlier contains an unauthenticated remote code execution vulnerability that allows unauthenticated attackers to execute arbitrary OS commands by submitting crafted prompts to the unprotected POST /api/v1/responses/ endpoint, which reaches the Anton agent's scratchpad tool that calls exec() on attacker-influenced Python source without sandboxing. Attackers can first configure their own LLM API key through the unauthenticated PUT /api/v1/settings/ endpoint, then POST a prompt directing the agent to invoke the scratchpad tool with arbitrary Python code, achieving full OS command execution as the user running the desktop application and enabling access to SSH keys, stored credentials, and environment secrets.

- [https://github.com/Hunt-Benito/bring-your-own-key-cve-2026-73678-unauthenticated-rce-in-mindsdb-cowork](https://github.com/Hunt-Benito/bring-your-own-key-cve-2026-73678-unauthenticated-rce-in-mindsdb-cowork) :  ![starts](https://img.shields.io/github/stars/Hunt-Benito/bring-your-own-key-cve-2026-73678-unauthenticated-rce-in-mindsdb-cowork.svg) ![forks](https://img.shields.io/github/forks/Hunt-Benito/bring-your-own-key-cve-2026-73678-unauthenticated-rce-in-mindsdb-cowork.svg)


## CVE-2026-73633
Users are recommended to upgrade to version 6.11.0 or 7.3.0, which fixes the issue.

- [https://github.com/CuteeCat/S2-072](https://github.com/CuteeCat/S2-072) :  ![starts](https://img.shields.io/github/stars/CuteeCat/S2-072.svg) ![forks](https://img.shields.io/github/forks/CuteeCat/S2-072.svg)


## CVE-2026-73519
 WolfStack before 25.9.2 contains a hard-coded cluster-authentication secret compiled into every build and published as a constant in src/auth/mod.rs, allowing remote unauthenticated attackers to bypass authentication by supplying this value in the X-WolfStack-Secret header to the require_auth() gate without any session, API key, or user account. Attackers can reach an affected node's management port to enumerate all Docker and LXC containers on the host and execute arbitrary commands as root inside any container via the POST /api/containers/{runtime}/{id}/exec endpoint.

- [https://github.com/squeeze440/CVE-2026-73519-WolfStack-PoC](https://github.com/squeeze440/CVE-2026-73519-WolfStack-PoC) :  ![starts](https://img.shields.io/github/stars/squeeze440/CVE-2026-73519-WolfStack-PoC.svg) ![forks](https://img.shields.io/github/forks/squeeze440/CVE-2026-73519-WolfStack-PoC.svg)


## CVE-2026-72898
 Metabase allows a remote, unauthenticated attacker to inject arbitrary SQL via the '/reset_password' database endpoint and gain administrator access to the connected Metabase instance.

- [https://github.com/VuxNx/CVE-2026-72898](https://github.com/VuxNx/CVE-2026-72898) :  ![starts](https://img.shields.io/github/stars/VuxNx/CVE-2026-72898.svg) ![forks](https://img.shields.io/github/forks/VuxNx/CVE-2026-72898.svg)
- [https://github.com/ubitquity/Metabase-Setup-Endpoint-SQLi-Fix](https://github.com/ubitquity/Metabase-Setup-Endpoint-SQLi-Fix) :  ![starts](https://img.shields.io/github/stars/ubitquity/Metabase-Setup-Endpoint-SQLi-Fix.svg) ![forks](https://img.shields.io/github/forks/ubitquity/Metabase-Setup-Endpoint-SQLi-Fix.svg)
- [https://github.com/4minx/CVE-2026-72898](https://github.com/4minx/CVE-2026-72898) :  ![starts](https://img.shields.io/github/stars/4minx/CVE-2026-72898.svg) ![forks](https://img.shields.io/github/forks/4minx/CVE-2026-72898.svg)


## CVE-2026-71362
 Adobe Commerce is affected by an Incorrect Authorization vulnerability that could result in privilege escalation. An attacker could leverage this vulnerability to gain elevated access to sensitive resources. Exploitation of this issue does not require user interaction.

- [https://github.com/dinosn/cve-2026-71362-magento-lab](https://github.com/dinosn/cve-2026-71362-magento-lab) :  ![starts](https://img.shields.io/github/stars/dinosn/cve-2026-71362-magento-lab.svg) ![forks](https://img.shields.io/github/forks/dinosn/cve-2026-71362-magento-lab.svg)


## CVE-2026-68820
 Use after free in Windows Ancillary Function Driver for WinSock allows an authorized attacker to elevate privileges locally.

- [https://github.com/ubitquity/Windows-WinSock-UAF-Mitigation](https://github.com/ubitquity/Windows-WinSock-UAF-Mitigation) :  ![starts](https://img.shields.io/github/stars/ubitquity/Windows-WinSock-UAF-Mitigation.svg) ![forks](https://img.shields.io/github/forks/ubitquity/Windows-WinSock-UAF-Mitigation.svg)


## CVE-2026-64638
Discovered and responsibly disclosed by [the team at pwn.ai](https://pwn.ai/).

- [https://github.com/Alixploit22/CVEX2SHEL](https://github.com/Alixploit22/CVEX2SHEL) :  ![starts](https://img.shields.io/github/stars/Alixploit22/CVEX2SHEL.svg) ![forks](https://img.shields.io/github/forks/Alixploit22/CVEX2SHEL.svg)


## CVE-2026-58231
availability of the application.

- [https://github.com/HORKimhab/CVE-2026-58231](https://github.com/HORKimhab/CVE-2026-58231) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-58231.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-58231.svg)


## CVE-2026-56197
 Improper neutralization of special elements used in a command ('command injection') in Windows Admin Center allows an authorized attacker to execute code over a network.

- [https://github.com/victorbonato/PoCs](https://github.com/victorbonato/PoCs) :  ![starts](https://img.shields.io/github/stars/victorbonato/PoCs.svg) ![forks](https://img.shields.io/github/forks/victorbonato/PoCs.svg)


## CVE-2026-51031
 FlareSolverr before version 3.4.7 contains a server-side request forgery (SSRF) vulnerability in the /v1 API endpoint. This allows a remote attacker to obtain sensitive information

- [https://github.com/daemoncibsec/flar3ad](https://github.com/daemoncibsec/flar3ad) :  ![starts](https://img.shields.io/github/stars/daemoncibsec/flar3ad.svg) ![forks](https://img.shields.io/github/forks/daemoncibsec/flar3ad.svg)


## CVE-2026-47117
 OpenMed before 1.5.2 contains a remote code execution vulnerability in the PII privacy-filter model loading path. The privacy-filter dispatcher used broad substring matching on the user-supplied model_name parameter, allowing a value such as attacker/foo-privacy-filter-bar to route through a path that loads Hugging Face models with trust_remote_code=True. An unauthenticated attacker can supply a malicious model repository containing custom Transformers code via auto_map in config.json or tokenizer_config.json, which is imported and executed with the privileges of the OpenMed service process.

- [https://github.com/SaiTeja-Erukude/CVE-2026-47117-openmed-rce](https://github.com/SaiTeja-Erukude/CVE-2026-47117-openmed-rce) :  ![starts](https://img.shields.io/github/stars/SaiTeja-Erukude/CVE-2026-47117-openmed-rce.svg) ![forks](https://img.shields.io/github/forks/SaiTeja-Erukude/CVE-2026-47117-openmed-rce.svg)


## CVE-2026-47103
 Python StateMachine versions 3.0.0 before 3.2.0 contains a remote code execution vulnerability that allows attackers to execute arbitrary code by supplying malicious SCXML documents containing crafted `data expr="..."` attributes evaluated unsafely. The SCXMLProcessor passes attacker-controlled expression strings through a call chain ending in Python's built-in eval() without sandboxing, enabling arbitrary code execution in the context of the hosting process.

- [https://github.com/SaiTeja-Erukude/CVE-2026-47103-python-statemachine-rce](https://github.com/SaiTeja-Erukude/CVE-2026-47103-python-statemachine-rce) :  ![starts](https://img.shields.io/github/stars/SaiTeja-Erukude/CVE-2026-47103-python-statemachine-rce.svg) ![forks](https://img.shields.io/github/forks/SaiTeja-Erukude/CVE-2026-47103-python-statemachine-rce.svg)


## CVE-2026-43499
  	changelog ]

- [https://github.com/knowlily/cve-2026-43499-honor](https://github.com/knowlily/cve-2026-43499-honor) :  ![starts](https://img.shields.io/github/stars/knowlily/cve-2026-43499-honor.svg) ![forks](https://img.shields.io/github/forks/knowlily/cve-2026-43499-honor.svg)
- [https://github.com/CamsShaft/IonStack-S22-cve-2026-43499](https://github.com/CamsShaft/IonStack-S22-cve-2026-43499) :  ![starts](https://img.shields.io/github/stars/CamsShaft/IonStack-S22-cve-2026-43499.svg) ![forks](https://img.shields.io/github/forks/CamsShaft/IonStack-S22-cve-2026-43499.svg)


## CVE-2026-20896
 Gitea Docker image versions up to and including 1.26.2 use REVERSE_PROXY_TRUSTED_PROXIES=* by default, allowing any source IP to impersonate a user when reverse-proxy authentication headers such as X-WEBAUTH-USER are enabled.

- [https://github.com/judgedbykira/CVE-2026-20896-Gitea-Authentication-Bypass](https://github.com/judgedbykira/CVE-2026-20896-Gitea-Authentication-Bypass) :  ![starts](https://img.shields.io/github/stars/judgedbykira/CVE-2026-20896-Gitea-Authentication-Bypass.svg) ![forks](https://img.shields.io/github/forks/judgedbykira/CVE-2026-20896-Gitea-Authentication-Bypass.svg)


## CVE-2026-17544
 Attacker-provided inputs to bccomp() could lead to an out-of-bounds write with stack and heap corruption in PHP versions from 8.4.* before 8.4.24 and from 8.5.* before 8.5.9.

- [https://github.com/r2qa/CVE-2026-17544](https://github.com/r2qa/CVE-2026-17544) :  ![starts](https://img.shields.io/github/stars/r2qa/CVE-2026-17544.svg) ![forks](https://img.shields.io/github/forks/r2qa/CVE-2026-17544.svg)


## CVE-2026-9830
 The bookingpress-appointment-booking-pro WordPress plugin before 5.7.3 does not correctly invoke its REST permission callback, leaving every route in one of its API namespaces reachable without authentication and allowing unauthenticated attackers to read customer booking data and modify other users' bookings.

- [https://github.com/opaxial/CVE-2026-9830](https://github.com/opaxial/CVE-2026-9830) :  ![starts](https://img.shields.io/github/stars/opaxial/CVE-2026-9830.svg) ![forks](https://img.shields.io/github/forks/opaxial/CVE-2026-9830.svg)


## CVE-2026-9147
 uproot dynamically generates Python class source code from ROOT TStreamerInfo records in a file and compiles it at runtime. Some file-controlled streamer metadata fields (for example, streamer element names) are interpolated into the generated Python source without safe quoting via repr() or the !r format specifier. An attacker who can supply a crafted ROOT file can place Python expression-breaking content into a streamer metadata field. When uproot generates and invokes the corresponding reader method, the injected Python expression is evaluated in the context of the process opening the file, resulting in arbitrary Python code execution in applications that open or process attacker-controlled ROOT files with affected uproot code paths.

- [https://github.com/SaiTeja-Erukude/CVE-2026-9147-uproot-rce](https://github.com/SaiTeja-Erukude/CVE-2026-9147-uproot-rce) :  ![starts](https://img.shields.io/github/stars/SaiTeja-Erukude/CVE-2026-9147-uproot-rce.svg) ![forks](https://img.shields.io/github/forks/SaiTeja-Erukude/CVE-2026-9147-uproot-rce.svg)


## CVE-2026-9090
 Casdoor versions 2.362.0 and earlier contain a vulnerability that allows an attacker to bypass authentication by supplying an arbitrary signing certificate. The buildSpCertificateStore function extracts the X.509 certificate directly from the incoming SAMLResponse instead of using the trusted pre-configured Identity Provider certificate, allowing an attacker to forge assertions signed with an attacker-controlled key.

- [https://github.com/Kimdir01/CVE-2026-9090-poc](https://github.com/Kimdir01/CVE-2026-9090-poc) :  ![starts](https://img.shields.io/github/stars/Kimdir01/CVE-2026-9090-poc.svg) ![forks](https://img.shields.io/github/forks/Kimdir01/CVE-2026-9090-poc.svg)


## CVE-2026-8794
 PaperCut NG/MF contains an observable timing discrepancy in its authentication component. An unauthenticated remote attacker can exploit this vulnerability to perform username enumeration by measuring response times during login attempts. The system executes a password hash comparison only when a valid account is supplied, creating a measurable timing oracle that reveals account existence.

- [https://github.com/H4zaz/CVE-2026-8794](https://github.com/H4zaz/CVE-2026-8794) :  ![starts](https://img.shields.io/github/stars/H4zaz/CVE-2026-8794.svg) ![forks](https://img.shields.io/github/forks/H4zaz/CVE-2026-8794.svg)


## CVE-2026-8793
 PaperCut NG/MF does not properly restrict excessive authentication attempts within its login component. An unauthenticated remote attacker can exploit this vulnerability to perform unrestricted brute-force or credential-stuffing attacks without triggering account lockout or rate-limiting mechanisms in some configurations.

- [https://github.com/H4zaz/CVE-2026-8793](https://github.com/H4zaz/CVE-2026-8793) :  ![starts](https://img.shields.io/github/stars/H4zaz/CVE-2026-8793.svg) ![forks](https://img.shields.io/github/forks/H4zaz/CVE-2026-8793.svg)


## CVE-2026-6440
 The GoodMeet – Google Meet Integration for Webinar, Meeting & Video Conference plugin for WordPress is vulnerable to Cross-Site Request Forgery in versions up to and including 1.1.8. This is due to a missing nonce verification in the reset_credential() function, which handles the wp_ajax_goodmeet_reset_google_meet_credential AJAX action. While the function does verify the user's capability (manage_options), it does not validate a nonce, making it susceptible to CSRF attacks. This makes it possible for unauthenticated attackers to trick a site administrator into clicking a malicious link that will reset (delete) the plugin's stored Google Meet API credentials (goodmeet_google_credentials) and OAuth tokens (goodmeet_google_token), effectively disabling the Google Meet integration on the site.

- [https://github.com/Alixploit22/CVE-2026-6440](https://github.com/Alixploit22/CVE-2026-6440) :  ![starts](https://img.shields.io/github/stars/Alixploit22/CVE-2026-6440.svg) ![forks](https://img.shields.io/github/forks/Alixploit22/CVE-2026-6440.svg)


## CVE-2026-5358
 REJECTED: CVE-2026-5358 is rejected for two reasons. Firstly it has been discovered that no NIS+ client or server was ever released for any Linux-based OS distributions and as such this makes the API provisional and unused.  Secondly it has been discovered that the NIS+ cold start cache (/var/nis/NIS_COLD_START) cannot be bypassed and as such the API can only be called with a trusted server from the pre-populated cache. The use of a trusted server means no trust boundary is crossed and this is therefore considered a normal bug.

- [https://github.com/Alixploit22/CVE-2026-53587](https://github.com/Alixploit22/CVE-2026-53587) :  ![starts](https://img.shields.io/github/stars/Alixploit22/CVE-2026-53587.svg) ![forks](https://img.shields.io/github/forks/Alixploit22/CVE-2026-53587.svg)


## CVE-2026-3143
 The Total Upkeep – WordPress Backup Plugin plus Restore & Migrate by BoldGrid plugin for WordPress is vulnerable to unauthorized modification of data due to a missing capability check on the 'wp_ajax_cli_cancel' function in all versions up to, and including, 1.17.1. This makes it possible for unauthenticated attackers to cancel a pending rollback, potentially preventing a WordPress installation from automatically reverting a failed update.

- [https://github.com/xn0kkx/CVE-2026-31431_CopyFail_LinuxKernel_LPE](https://github.com/xn0kkx/CVE-2026-31431_CopyFail_LinuxKernel_LPE) :  ![starts](https://img.shields.io/github/stars/xn0kkx/CVE-2026-31431_CopyFail_LinuxKernel_LPE.svg) ![forks](https://img.shields.io/github/forks/xn0kkx/CVE-2026-31431_CopyFail_LinuxKernel_LPE.svg)
- [https://github.com/abdullaabdullazade/CVE-2026-31431](https://github.com/abdullaabdullazade/CVE-2026-31431) :  ![starts](https://img.shields.io/github/stars/abdullaabdullazade/CVE-2026-31431.svg) ![forks](https://img.shields.io/github/forks/abdullaabdullazade/CVE-2026-31431.svg)
- [https://github.com/mishl-dev/CVE_2026_31431](https://github.com/mishl-dev/CVE_2026_31431) :  ![starts](https://img.shields.io/github/stars/mishl-dev/CVE_2026_31431.svg) ![forks](https://img.shields.io/github/forks/mishl-dev/CVE_2026_31431.svg)
- [https://github.com/slauger/CVE-2026-31431](https://github.com/slauger/CVE-2026-31431) :  ![starts](https://img.shields.io/github/stars/slauger/CVE-2026-31431.svg) ![forks](https://img.shields.io/github/forks/slauger/CVE-2026-31431.svg)
- [https://github.com/yiyihuohuo/CVE-2026-31431](https://github.com/yiyihuohuo/CVE-2026-31431) :  ![starts](https://img.shields.io/github/stars/yiyihuohuo/CVE-2026-31431.svg) ![forks](https://img.shields.io/github/forks/yiyihuohuo/CVE-2026-31431.svg)
- [https://github.com/mfloresdacunha/CVE-2026-31431](https://github.com/mfloresdacunha/CVE-2026-31431) :  ![starts](https://img.shields.io/github/stars/mfloresdacunha/CVE-2026-31431.svg) ![forks](https://img.shields.io/github/forks/mfloresdacunha/CVE-2026-31431.svg)
- [https://github.com/Naimadx123/cve_2026_31431](https://github.com/Naimadx123/cve_2026_31431) :  ![starts](https://img.shields.io/github/stars/Naimadx123/cve_2026_31431.svg) ![forks](https://img.shields.io/github/forks/Naimadx123/cve_2026_31431.svg)
- [https://github.com/Lutfifakee-Project/CVE-2026-31431](https://github.com/Lutfifakee-Project/CVE-2026-31431) :  ![starts](https://img.shields.io/github/stars/Lutfifakee-Project/CVE-2026-31431.svg) ![forks](https://img.shields.io/github/forks/Lutfifakee-Project/CVE-2026-31431.svg)
- [https://github.com/gbonacini/CVE-2026-31431](https://github.com/gbonacini/CVE-2026-31431) :  ![starts](https://img.shields.io/github/stars/gbonacini/CVE-2026-31431.svg) ![forks](https://img.shields.io/github/forks/gbonacini/CVE-2026-31431.svg)
- [https://github.com/studiogangster/CVE-2026-31431](https://github.com/studiogangster/CVE-2026-31431) :  ![starts](https://img.shields.io/github/stars/studiogangster/CVE-2026-31431.svg) ![forks](https://img.shields.io/github/forks/studiogangster/CVE-2026-31431.svg)
- [https://github.com/yxdm02/CVE-2026-31431](https://github.com/yxdm02/CVE-2026-31431) :  ![starts](https://img.shields.io/github/stars/yxdm02/CVE-2026-31431.svg) ![forks](https://img.shields.io/github/forks/yxdm02/CVE-2026-31431.svg)
- [https://github.com/Gr-1m/CVE-2026-31431](https://github.com/Gr-1m/CVE-2026-31431) :  ![starts](https://img.shields.io/github/stars/Gr-1m/CVE-2026-31431.svg) ![forks](https://img.shields.io/github/forks/Gr-1m/CVE-2026-31431.svg)
- [https://github.com/Sebastian294/cve-2026-31431](https://github.com/Sebastian294/cve-2026-31431) :  ![starts](https://img.shields.io/github/stars/Sebastian294/cve-2026-31431.svg) ![forks](https://img.shields.io/github/forks/Sebastian294/cve-2026-31431.svg)
- [https://github.com/amdisrar/cve-2026-31431-mitigation](https://github.com/amdisrar/cve-2026-31431-mitigation) :  ![starts](https://img.shields.io/github/stars/amdisrar/cve-2026-31431-mitigation.svg) ![forks](https://img.shields.io/github/forks/amdisrar/cve-2026-31431-mitigation.svg)
- [https://github.com/galoryber/CVE-2026-31431-cleaned](https://github.com/galoryber/CVE-2026-31431-cleaned) :  ![starts](https://img.shields.io/github/stars/galoryber/CVE-2026-31431-cleaned.svg) ![forks](https://img.shields.io/github/forks/galoryber/CVE-2026-31431-cleaned.svg)
- [https://github.com/darioomatos/cve-2026-31431-copyfail](https://github.com/darioomatos/cve-2026-31431-copyfail) :  ![starts](https://img.shields.io/github/stars/darioomatos/cve-2026-31431-copyfail.svg) ![forks](https://img.shields.io/github/forks/darioomatos/cve-2026-31431-copyfail.svg)
- [https://github.com/alvaroguzmancode/CVE-2026-31431-mitigacion](https://github.com/alvaroguzmancode/CVE-2026-31431-mitigacion) :  ![starts](https://img.shields.io/github/stars/alvaroguzmancode/CVE-2026-31431-mitigacion.svg) ![forks](https://img.shields.io/github/forks/alvaroguzmancode/CVE-2026-31431-mitigacion.svg)
- [https://github.com/Trex1e/copyfail-CVE-2026-31431](https://github.com/Trex1e/copyfail-CVE-2026-31431) :  ![starts](https://img.shields.io/github/stars/Trex1e/copyfail-CVE-2026-31431.svg) ![forks](https://img.shields.io/github/forks/Trex1e/copyfail-CVE-2026-31431.svg)
- [https://github.com/thrandomv/cve-2026-31431-detection](https://github.com/thrandomv/cve-2026-31431-detection) :  ![starts](https://img.shields.io/github/stars/thrandomv/cve-2026-31431-detection.svg) ![forks](https://img.shields.io/github/forks/thrandomv/cve-2026-31431-detection.svg)
- [https://github.com/DENNISDGR/CVE-2026-31431-poc](https://github.com/DENNISDGR/CVE-2026-31431-poc) :  ![starts](https://img.shields.io/github/stars/DENNISDGR/CVE-2026-31431-poc.svg) ![forks](https://img.shields.io/github/forks/DENNISDGR/CVE-2026-31431-poc.svg)
- [https://github.com/poyea/CVE-2026-31431.c](https://github.com/poyea/CVE-2026-31431.c) :  ![starts](https://img.shields.io/github/stars/poyea/CVE-2026-31431.c.svg) ![forks](https://img.shields.io/github/forks/poyea/CVE-2026-31431.c.svg)
- [https://github.com/rippsec/CVE-2026-31431-Copy-Fail](https://github.com/rippsec/CVE-2026-31431-Copy-Fail) :  ![starts](https://img.shields.io/github/stars/rippsec/CVE-2026-31431-Copy-Fail.svg) ![forks](https://img.shields.io/github/forks/rippsec/CVE-2026-31431-Copy-Fail.svg)
- [https://github.com/dgrobinson0/CopyFile_CVE-2026-31431](https://github.com/dgrobinson0/CopyFile_CVE-2026-31431) :  ![starts](https://img.shields.io/github/stars/dgrobinson0/CopyFile_CVE-2026-31431.svg) ![forks](https://img.shields.io/github/forks/dgrobinson0/CopyFile_CVE-2026-31431.svg)
- [https://github.com/pyroceper/copy-fail-CVE-2026-31431](https://github.com/pyroceper/copy-fail-CVE-2026-31431) :  ![starts](https://img.shields.io/github/stars/pyroceper/copy-fail-CVE-2026-31431.svg) ![forks](https://img.shields.io/github/forks/pyroceper/copy-fail-CVE-2026-31431.svg)
- [https://github.com/1amBa7Man/Linux-copy-fail-CVE-2026-31431](https://github.com/1amBa7Man/Linux-copy-fail-CVE-2026-31431) :  ![starts](https://img.shields.io/github/stars/1amBa7Man/Linux-copy-fail-CVE-2026-31431.svg) ![forks](https://img.shields.io/github/forks/1amBa7Man/Linux-copy-fail-CVE-2026-31431.svg)
- [https://github.com/euriconicacio/copy-fail-CVE-2026-31431-poc](https://github.com/euriconicacio/copy-fail-CVE-2026-31431-poc) :  ![starts](https://img.shields.io/github/stars/euriconicacio/copy-fail-CVE-2026-31431-poc.svg) ![forks](https://img.shields.io/github/forks/euriconicacio/copy-fail-CVE-2026-31431-poc.svg)
- [https://github.com/SunL0w/PATCH-CVE-2026-31431-Ubuntu_Debian](https://github.com/SunL0w/PATCH-CVE-2026-31431-Ubuntu_Debian) :  ![starts](https://img.shields.io/github/stars/SunL0w/PATCH-CVE-2026-31431-Ubuntu_Debian.svg) ![forks](https://img.shields.io/github/forks/SunL0w/PATCH-CVE-2026-31431-Ubuntu_Debian.svg)
- [https://github.com/Y5neKO/copy-fail-CVE-2026-31431-universal](https://github.com/Y5neKO/copy-fail-CVE-2026-31431-universal) :  ![starts](https://img.shields.io/github/stars/Y5neKO/copy-fail-CVE-2026-31431-universal.svg) ![forks](https://img.shields.io/github/forks/Y5neKO/copy-fail-CVE-2026-31431-universal.svg)
- [https://github.com/AvPrince26/copy-fail-CVE-2026-31431-Python-Golfing](https://github.com/AvPrince26/copy-fail-CVE-2026-31431-Python-Golfing) :  ![starts](https://img.shields.io/github/stars/AvPrince26/copy-fail-CVE-2026-31431-Python-Golfing.svg) ![forks](https://img.shields.io/github/forks/AvPrince26/copy-fail-CVE-2026-31431-Python-Golfing.svg)
- [https://github.com/krish-foren6/CVE-2026-31431-Report-Copy-fail-Vulnerability-](https://github.com/krish-foren6/CVE-2026-31431-Report-Copy-fail-Vulnerability-) :  ![starts](https://img.shields.io/github/stars/krish-foren6/CVE-2026-31431-Report-Copy-fail-Vulnerability-.svg) ![forks](https://img.shields.io/github/forks/krish-foren6/CVE-2026-31431-Report-Copy-fail-Vulnerability-.svg)
- [https://github.com/maniakh/CVE-2026-31431---Copy-Fail-PoC](https://github.com/maniakh/CVE-2026-31431---Copy-Fail-PoC) :  ![starts](https://img.shields.io/github/stars/maniakh/CVE-2026-31431---Copy-Fail-PoC.svg) ![forks](https://img.shields.io/github/forks/maniakh/CVE-2026-31431---Copy-Fail-PoC.svg)
- [https://github.com/sbeteta42/CVE-2026-31431_je_sappelle_RoOt](https://github.com/sbeteta42/CVE-2026-31431_je_sappelle_RoOt) :  ![starts](https://img.shields.io/github/stars/sbeteta42/CVE-2026-31431_je_sappelle_RoOt.svg) ![forks](https://img.shields.io/github/forks/sbeteta42/CVE-2026-31431_je_sappelle_RoOt.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions.svg)


## CVE-2025-64512
 Pdfminer.six is a community maintained fork of the original PDFMiner, a tool for extracting information from PDF documents. Prior to version 20251107, pdfminer.six will execute arbitrary code from a malicious pickle file if provided with a malicious PDF file. The `CMapDB._load_data()` function in pdfminer.six uses `pickle.loads()` to deserialize pickle files. These pickle files are supposed to be part of the pdfminer.six distribution stored in the `cmap/` directory, but a malicious PDF can specify an alternative directory and filename as long as the filename ends in `.pickle.gz`. A malicious, zipped pickle file can then contain code which will automatically execute when the PDF is processed. Version 20251107 fixes the issue.

- [https://github.com/oguzylmzx/CVE-2025-64512-pdfminer-PoC](https://github.com/oguzylmzx/CVE-2025-64512-pdfminer-PoC) :  ![starts](https://img.shields.io/github/stars/oguzylmzx/CVE-2025-64512-pdfminer-PoC.svg) ![forks](https://img.shields.io/github/forks/oguzylmzx/CVE-2025-64512-pdfminer-PoC.svg)


## CVE-2025-57819
 FreePBX is an open-source web-based graphical user interface. FreePBX 15, 16, and 17 endpoints are vulnerable due to insufficiently sanitized user-supplied data allowing unauthenticated access to FreePBX Administrator leading to arbitrary database manipulation and remote code execution. This issue has been patched in endpoint versions 15.0.66, 16.0.89, and 17.0.3.

- [https://github.com/iamrajkumar1995/cve-2025-5781_FreePBX](https://github.com/iamrajkumar1995/cve-2025-5781_FreePBX) :  ![starts](https://img.shields.io/github/stars/iamrajkumar1995/cve-2025-5781_FreePBX.svg) ![forks](https://img.shields.io/github/forks/iamrajkumar1995/cve-2025-5781_FreePBX.svg)


## CVE-2025-6647
The specific flaw exists within the parsing of U3D files. The issue results from the lack of proper validation of user-supplied data, which can result in a write past the end of an allocated object. An attacker can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-26644.

- [https://github.com/lincemorado97/CVE-2025-55182_CVE-2025-66478](https://github.com/lincemorado97/CVE-2025-55182_CVE-2025-66478) :  ![starts](https://img.shields.io/github/stars/lincemorado97/CVE-2025-55182_CVE-2025-66478.svg) ![forks](https://img.shields.io/github/forks/lincemorado97/CVE-2025-55182_CVE-2025-66478.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo.svg)
- [https://github.com/nilfredb/CVE-2025-66478-Research-Proof-of-Concept](https://github.com/nilfredb/CVE-2025-66478-Research-Proof-of-Concept) :  ![starts](https://img.shields.io/github/stars/nilfredb/CVE-2025-66478-Research-Proof-of-Concept.svg) ![forks](https://img.shields.io/github/forks/nilfredb/CVE-2025-66478-Research-Proof-of-Concept.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-pnpm-overrides](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-pnpm-overrides) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-pnpm-overrides.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-pnpm-overrides.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-range](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-range) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-range.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-range.svg)
- [https://github.com/thedarckpassenger/Next.js-RSC-RCE-Scanner-CVE-2025-66478](https://github.com/thedarckpassenger/Next.js-RSC-RCE-Scanner-CVE-2025-66478) :  ![starts](https://img.shields.io/github/stars/thedarckpassenger/Next.js-RSC-RCE-Scanner-CVE-2025-66478.svg) ![forks](https://img.shields.io/github/forks/thedarckpassenger/Next.js-RSC-RCE-Scanner-CVE-2025-66478.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-packagemanager-field](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-packagemanager-field) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-packagemanager-field.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-packagemanager-field.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-no-lockfile](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-no-lockfile) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-no-lockfile.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-no-lockfile.svg)
- [https://github.com/DavionGowie/-vercel-application-is-vulnerable-to-CVE-2025-66478.](https://github.com/DavionGowie/-vercel-application-is-vulnerable-to-CVE-2025-66478.) :  ![starts](https://img.shields.io/github/stars/DavionGowie/-vercel-application-is-vulnerable-to-CVE-2025-66478..svg) ![forks](https://img.shields.io/github/forks/DavionGowie/-vercel-application-is-vulnerable-to-CVE-2025-66478..svg)
- [https://github.com/changgun-lee/Next.js-RSC-RCE-Scanner-CVE-2025-66478](https://github.com/changgun-lee/Next.js-RSC-RCE-Scanner-CVE-2025-66478) :  ![starts](https://img.shields.io/github/stars/changgun-lee/Next.js-RSC-RCE-Scanner-CVE-2025-66478.svg) ![forks](https://img.shields.io/github/forks/changgun-lee/Next.js-RSC-RCE-Scanner-CVE-2025-66478.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-optional-deps](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-optional-deps) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-optional-deps.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-optional-deps.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-15x](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-15x) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-15x.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-15x.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-14x](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-14x) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-14x.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-14x.svg)
- [https://github.com/Mustafa1p/Next.js-RCE-Scanner---CVE-2025-55182-CVE-2025-66478](https://github.com/Mustafa1p/Next.js-RCE-Scanner---CVE-2025-55182-CVE-2025-66478) :  ![starts](https://img.shields.io/github/stars/Mustafa1p/Next.js-RCE-Scanner---CVE-2025-55182-CVE-2025-66478.svg) ![forks](https://img.shields.io/github/forks/Mustafa1p/Next.js-RCE-Scanner---CVE-2025-55182-CVE-2025-66478.svg)
- [https://github.com/DavionGowie/-vercel-prod.yml-application-is-vulnerable-to-CVE-2025-66478.](https://github.com/DavionGowie/-vercel-prod.yml-application-is-vulnerable-to-CVE-2025-66478.) :  ![starts](https://img.shields.io/github/stars/DavionGowie/-vercel-prod.yml-application-is-vulnerable-to-CVE-2025-66478..svg) ![forks](https://img.shields.io/github/forks/DavionGowie/-vercel-prod.yml-application-is-vulnerable-to-CVE-2025-66478..svg)


## CVE-2025-5518
This issue affects BILGER: before 2.4.6.

- [https://github.com/timsonner/React2Shell-CVE-2025-55182](https://github.com/timsonner/React2Shell-CVE-2025-55182) :  ![starts](https://img.shields.io/github/stars/timsonner/React2Shell-CVE-2025-55182.svg) ![forks](https://img.shields.io/github/forks/timsonner/React2Shell-CVE-2025-55182.svg)
- [https://github.com/MuhammadWaseem29/React2Shell_Rce-cve-2025-55182](https://github.com/MuhammadWaseem29/React2Shell_Rce-cve-2025-55182) :  ![starts](https://img.shields.io/github/stars/MuhammadWaseem29/React2Shell_Rce-cve-2025-55182.svg) ![forks](https://img.shields.io/github/forks/MuhammadWaseem29/React2Shell_Rce-cve-2025-55182.svg)
- [https://github.com/Cillian-Collins/CVE-2025-55182](https://github.com/Cillian-Collins/CVE-2025-55182) :  ![starts](https://img.shields.io/github/stars/Cillian-Collins/CVE-2025-55182.svg) ![forks](https://img.shields.io/github/forks/Cillian-Collins/CVE-2025-55182.svg)
- [https://github.com/hoosin/CVE-2025-55182](https://github.com/hoosin/CVE-2025-55182) :  ![starts](https://img.shields.io/github/stars/hoosin/CVE-2025-55182.svg) ![forks](https://img.shields.io/github/forks/hoosin/CVE-2025-55182.svg)
- [https://github.com/jf0x3a/CVE-2025-55182-exploit](https://github.com/jf0x3a/CVE-2025-55182-exploit) :  ![starts](https://img.shields.io/github/stars/jf0x3a/CVE-2025-55182-exploit.svg) ![forks](https://img.shields.io/github/forks/jf0x3a/CVE-2025-55182-exploit.svg)
- [https://github.com/techgaun/cve-2025-55182-scanner](https://github.com/techgaun/cve-2025-55182-scanner) :  ![starts](https://img.shields.io/github/stars/techgaun/cve-2025-55182-scanner.svg) ![forks](https://img.shields.io/github/forks/techgaun/cve-2025-55182-scanner.svg)
- [https://github.com/TrixSec/CVE-2025-55182-Scanner](https://github.com/TrixSec/CVE-2025-55182-Scanner) :  ![starts](https://img.shields.io/github/stars/TrixSec/CVE-2025-55182-Scanner.svg) ![forks](https://img.shields.io/github/forks/TrixSec/CVE-2025-55182-Scanner.svg)
- [https://github.com/anuththara2007-W/CVE-2025-55182-Exploit-extension](https://github.com/anuththara2007-W/CVE-2025-55182-Exploit-extension) :  ![starts](https://img.shields.io/github/stars/anuththara2007-W/CVE-2025-55182-Exploit-extension.svg) ![forks](https://img.shields.io/github/forks/anuththara2007-W/CVE-2025-55182-Exploit-extension.svg)
- [https://github.com/VeilVulp/RscScan-cve-2025-55182](https://github.com/VeilVulp/RscScan-cve-2025-55182) :  ![starts](https://img.shields.io/github/stars/VeilVulp/RscScan-cve-2025-55182.svg) ![forks](https://img.shields.io/github/forks/VeilVulp/RscScan-cve-2025-55182.svg)
- [https://github.com/Dh4v4l8/CVE-2025-55182-poc-tool](https://github.com/Dh4v4l8/CVE-2025-55182-poc-tool) :  ![starts](https://img.shields.io/github/stars/Dh4v4l8/CVE-2025-55182-poc-tool.svg) ![forks](https://img.shields.io/github/forks/Dh4v4l8/CVE-2025-55182-poc-tool.svg)
- [https://github.com/Syrins/CVE-2025-55182-React2Shell-RCE](https://github.com/Syrins/CVE-2025-55182-React2Shell-RCE) :  ![starts](https://img.shields.io/github/stars/Syrins/CVE-2025-55182-React2Shell-RCE.svg) ![forks](https://img.shields.io/github/forks/Syrins/CVE-2025-55182-React2Shell-RCE.svg)
- [https://github.com/joelvaiju/react2shell-CVE-2025-55182-poc](https://github.com/joelvaiju/react2shell-CVE-2025-55182-poc) :  ![starts](https://img.shields.io/github/stars/joelvaiju/react2shell-CVE-2025-55182-poc.svg) ![forks](https://img.shields.io/github/forks/joelvaiju/react2shell-CVE-2025-55182-poc.svg)
- [https://github.com/Rat5ak/CVE-2025-55182-React2Shell-RCE-POC](https://github.com/Rat5ak/CVE-2025-55182-React2Shell-RCE-POC) :  ![starts](https://img.shields.io/github/stars/Rat5ak/CVE-2025-55182-React2Shell-RCE-POC.svg) ![forks](https://img.shields.io/github/forks/Rat5ak/CVE-2025-55182-React2Shell-RCE-POC.svg)
- [https://github.com/InferiorAK/CVE-2025-55182-React2Shell-Async-Scanner](https://github.com/InferiorAK/CVE-2025-55182-React2Shell-Async-Scanner) :  ![starts](https://img.shields.io/github/stars/InferiorAK/CVE-2025-55182-React2Shell-Async-Scanner.svg) ![forks](https://img.shields.io/github/forks/InferiorAK/CVE-2025-55182-React2Shell-Async-Scanner.svg)
- [https://github.com/ihhgimhana/React2Shell-CVE-2025-55182-PoC-Reverse-Shell](https://github.com/ihhgimhana/React2Shell-CVE-2025-55182-PoC-Reverse-Shell) :  ![starts](https://img.shields.io/github/stars/ihhgimhana/React2Shell-CVE-2025-55182-PoC-Reverse-Shell.svg) ![forks](https://img.shields.io/github/forks/ihhgimhana/React2Shell-CVE-2025-55182-PoC-Reverse-Shell.svg)
- [https://github.com/hzhsec/cve_2025_55182_test](https://github.com/hzhsec/cve_2025_55182_test) :  ![starts](https://img.shields.io/github/stars/hzhsec/cve_2025_55182_test.svg) ![forks](https://img.shields.io/github/forks/hzhsec/cve_2025_55182_test.svg)
- [https://github.com/vulncheck-oss/cve-2025-55182](https://github.com/vulncheck-oss/cve-2025-55182) :  ![starts](https://img.shields.io/github/stars/vulncheck-oss/cve-2025-55182.svg) ![forks](https://img.shields.io/github/forks/vulncheck-oss/cve-2025-55182.svg)
- [https://github.com/theman001/CVE-2025-55182](https://github.com/theman001/CVE-2025-55182) :  ![starts](https://img.shields.io/github/stars/theman001/CVE-2025-55182.svg) ![forks](https://img.shields.io/github/forks/theman001/CVE-2025-55182.svg)
- [https://github.com/logesh-GIT001/CVE-2025-55182](https://github.com/logesh-GIT001/CVE-2025-55182) :  ![starts](https://img.shields.io/github/stars/logesh-GIT001/CVE-2025-55182.svg) ![forks](https://img.shields.io/github/forks/logesh-GIT001/CVE-2025-55182.svg)
- [https://github.com/subhdotsol/CVE-2025-55182](https://github.com/subhdotsol/CVE-2025-55182) :  ![starts](https://img.shields.io/github/stars/subhdotsol/CVE-2025-55182.svg) ![forks](https://img.shields.io/github/forks/subhdotsol/CVE-2025-55182.svg)
- [https://github.com/ceh-aditya-raj/CVE-2025-55182](https://github.com/ceh-aditya-raj/CVE-2025-55182) :  ![starts](https://img.shields.io/github/stars/ceh-aditya-raj/CVE-2025-55182.svg) ![forks](https://img.shields.io/github/forks/ceh-aditya-raj/CVE-2025-55182.svg)
- [https://github.com/MemerGamer/CVE-2025-55182](https://github.com/MemerGamer/CVE-2025-55182) :  ![starts](https://img.shields.io/github/stars/MemerGamer/CVE-2025-55182.svg) ![forks](https://img.shields.io/github/forks/MemerGamer/CVE-2025-55182.svg)
- [https://github.com/LucasPDiniz/CVE-2025-55182](https://github.com/LucasPDiniz/CVE-2025-55182) :  ![starts](https://img.shields.io/github/stars/LucasPDiniz/CVE-2025-55182.svg) ![forks](https://img.shields.io/github/forks/LucasPDiniz/CVE-2025-55182.svg)
- [https://github.com/kindone09/CVE-2025-55182](https://github.com/kindone09/CVE-2025-55182) :  ![starts](https://img.shields.io/github/stars/kindone09/CVE-2025-55182.svg) ![forks](https://img.shields.io/github/forks/kindone09/CVE-2025-55182.svg)
- [https://github.com/Faithtiannn/CVE-2025-55182](https://github.com/Faithtiannn/CVE-2025-55182) :  ![starts](https://img.shields.io/github/stars/Faithtiannn/CVE-2025-55182.svg) ![forks](https://img.shields.io/github/forks/Faithtiannn/CVE-2025-55182.svg)
- [https://github.com/l0n3m4n/CVE-2025-55182-Waf](https://github.com/l0n3m4n/CVE-2025-55182-Waf) :  ![starts](https://img.shields.io/github/stars/l0n3m4n/CVE-2025-55182-Waf.svg) ![forks](https://img.shields.io/github/forks/l0n3m4n/CVE-2025-55182-Waf.svg)
- [https://github.com/Sairbo/Unihackers---CVE-2025-55182-](https://github.com/Sairbo/Unihackers---CVE-2025-55182-) :  ![starts](https://img.shields.io/github/stars/Sairbo/Unihackers---CVE-2025-55182-.svg) ![forks](https://img.shields.io/github/forks/Sairbo/Unihackers---CVE-2025-55182-.svg)
- [https://github.com/LC-pro/CVE-2025-55182-EXP](https://github.com/LC-pro/CVE-2025-55182-EXP) :  ![starts](https://img.shields.io/github/stars/LC-pro/CVE-2025-55182-EXP.svg) ![forks](https://img.shields.io/github/forks/LC-pro/CVE-2025-55182-EXP.svg)
- [https://github.com/SainiONHacks/CVE-2025-55182-Scanner](https://github.com/SainiONHacks/CVE-2025-55182-Scanner) :  ![starts](https://img.shields.io/github/stars/SainiONHacks/CVE-2025-55182-Scanner.svg) ![forks](https://img.shields.io/github/forks/SainiONHacks/CVE-2025-55182-Scanner.svg)
- [https://github.com/InfoSecAntara/CTF_CVE_2025_55182](https://github.com/InfoSecAntara/CTF_CVE_2025_55182) :  ![starts](https://img.shields.io/github/stars/InfoSecAntara/CTF_CVE_2025_55182.svg) ![forks](https://img.shields.io/github/forks/InfoSecAntara/CTF_CVE_2025_55182.svg)
- [https://github.com/mingyisecurity-lab/CVE-2025-55182-TOOLS](https://github.com/mingyisecurity-lab/CVE-2025-55182-TOOLS) :  ![starts](https://img.shields.io/github/stars/mingyisecurity-lab/CVE-2025-55182-TOOLS.svg) ![forks](https://img.shields.io/github/forks/mingyisecurity-lab/CVE-2025-55182-TOOLS.svg)
- [https://github.com/sudo-Yangziran/CVE-2025-55182POC](https://github.com/sudo-Yangziran/CVE-2025-55182POC) :  ![starts](https://img.shields.io/github/stars/sudo-Yangziran/CVE-2025-55182POC.svg) ![forks](https://img.shields.io/github/forks/sudo-Yangziran/CVE-2025-55182POC.svg)
- [https://github.com/sangleshubham/React-Security-CVE-2025-55182-Exploit](https://github.com/sangleshubham/React-Security-CVE-2025-55182-Exploit) :  ![starts](https://img.shields.io/github/stars/sangleshubham/React-Security-CVE-2025-55182-Exploit.svg) ![forks](https://img.shields.io/github/forks/sangleshubham/React-Security-CVE-2025-55182-Exploit.svg)


## CVE-2025-3194
 Versions of the package bigint-buffer from 0.0.0 are vulnerable to Buffer Overflow in the toBigIntLE() function. Attackers can exploit this to crash the application.

- [https://github.com/LoserLab/bigint-buffer-safe](https://github.com/LoserLab/bigint-buffer-safe) :  ![starts](https://img.shields.io/github/stars/LoserLab/bigint-buffer-safe.svg) ![forks](https://img.shields.io/github/forks/LoserLab/bigint-buffer-safe.svg)


## CVE-2025-2992
 A vulnerability classified as critical was found in Tenda FH1202 1.2.0.14(408). Affected by this vulnerability is an unknown functionality of the file /goform/AdvSetWrlsafeset of the component Web Management Interface. The manipulation leads to improper access controls. The attack can be launched remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/Heimd411/CVE-2025-29927-PoC](https://github.com/Heimd411/CVE-2025-29927-PoC) :  ![starts](https://img.shields.io/github/stars/Heimd411/CVE-2025-29927-PoC.svg) ![forks](https://img.shields.io/github/forks/Heimd411/CVE-2025-29927-PoC.svg)
- [https://github.com/all3njk/NextJS_CVE-2025-29927](https://github.com/all3njk/NextJS_CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/all3njk/NextJS_CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/all3njk/NextJS_CVE-2025-29927.svg)
- [https://github.com/enochgitgamefied/NextJS-CVE-2025-29927](https://github.com/enochgitgamefied/NextJS-CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/enochgitgamefied/NextJS-CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/enochgitgamefied/NextJS-CVE-2025-29927.svg)
- [https://github.com/lucaschanzx/CVE-2025-29927-PoC](https://github.com/lucaschanzx/CVE-2025-29927-PoC) :  ![starts](https://img.shields.io/github/stars/lucaschanzx/CVE-2025-29927-PoC.svg) ![forks](https://img.shields.io/github/forks/lucaschanzx/CVE-2025-29927-PoC.svg)
- [https://github.com/rgvillanueva28/vulnbox-easy-CVE-2025-29927](https://github.com/rgvillanueva28/vulnbox-easy-CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/rgvillanueva28/vulnbox-easy-CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/rgvillanueva28/vulnbox-easy-CVE-2025-29927.svg)
- [https://github.com/0xPThree/next.js_cve-2025-29927](https://github.com/0xPThree/next.js_cve-2025-29927) :  ![starts](https://img.shields.io/github/stars/0xPThree/next.js_cve-2025-29927.svg) ![forks](https://img.shields.io/github/forks/0xPThree/next.js_cve-2025-29927.svg)
- [https://github.com/maronnjapan/claude-create-CVE-2025-29927](https://github.com/maronnjapan/claude-create-CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/maronnjapan/claude-create-CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/maronnjapan/claude-create-CVE-2025-29927.svg)
- [https://github.com/adjscent/vulnerable-nextjs-14-CVE-2025-29927](https://github.com/adjscent/vulnerable-nextjs-14-CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/adjscent/vulnerable-nextjs-14-CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/adjscent/vulnerable-nextjs-14-CVE-2025-29927.svg)
- [https://github.com/Grand-Moomin/Vuln-Next.js-CVE-2025-29927](https://github.com/Grand-Moomin/Vuln-Next.js-CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/Grand-Moomin/Vuln-Next.js-CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/Grand-Moomin/Vuln-Next.js-CVE-2025-29927.svg)
- [https://github.com/Si-Ni/CVE-2025-29927-Proof-of-Concept](https://github.com/Si-Ni/CVE-2025-29927-Proof-of-Concept) :  ![starts](https://img.shields.io/github/stars/Si-Ni/CVE-2025-29927-Proof-of-Concept.svg) ![forks](https://img.shields.io/github/forks/Si-Ni/CVE-2025-29927-Proof-of-Concept.svg)
- [https://github.com/pickovven/vulnerable-nextjs-14-CVE-2025-29927](https://github.com/pickovven/vulnerable-nextjs-14-CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/pickovven/vulnerable-nextjs-14-CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/pickovven/vulnerable-nextjs-14-CVE-2025-29927.svg)
- [https://github.com/Knotsecurity/CVE-2025-29927-NextJs-Middleware-Simulation](https://github.com/Knotsecurity/CVE-2025-29927-NextJs-Middleware-Simulation) :  ![starts](https://img.shields.io/github/stars/Knotsecurity/CVE-2025-29927-NextJs-Middleware-Simulation.svg) ![forks](https://img.shields.io/github/forks/Knotsecurity/CVE-2025-29927-NextJs-Middleware-Simulation.svg)
- [https://github.com/enochgitgamefied/NextJS-CVE-2025-29927-Docker-Lab](https://github.com/enochgitgamefied/NextJS-CVE-2025-29927-Docker-Lab) :  ![starts](https://img.shields.io/github/stars/enochgitgamefied/NextJS-CVE-2025-29927-Docker-Lab.svg) ![forks](https://img.shields.io/github/forks/enochgitgamefied/NextJS-CVE-2025-29927-Docker-Lab.svg)
- [https://github.com/R3verseIN/Nextjs-middleware-vulnerable-appdemo-CVE-2025-29927](https://github.com/R3verseIN/Nextjs-middleware-vulnerable-appdemo-CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/R3verseIN/Nextjs-middleware-vulnerable-appdemo-CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/R3verseIN/Nextjs-middleware-vulnerable-appdemo-CVE-2025-29927.svg)
- [https://github.com/Naveen-005/Next.Js-middleware-bypass-vulnerability-CVE-2025-29927](https://github.com/Naveen-005/Next.Js-middleware-bypass-vulnerability-CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/Naveen-005/Next.Js-middleware-bypass-vulnerability-CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/Naveen-005/Next.Js-middleware-bypass-vulnerability-CVE-2025-29927.svg)


## CVE-2024-56426
 An issue was discovered in Samsung Mobile Processor and Wearable Processor Exynos 980, 990, 850, 1080, 2100, 1280, 2200, 1330, 1380, 1480, 2400, W920, W930, W1000. The lack of a length check leads to out-of-bounds writes via malformed USB packets to the target.

- [https://github.com/xcracker000/CVE-2024-56426](https://github.com/xcracker000/CVE-2024-56426) :  ![starts](https://img.shields.io/github/stars/xcracker000/CVE-2024-56426.svg) ![forks](https://img.shields.io/github/forks/xcracker000/CVE-2024-56426.svg)


## CVE-2024-45519
 The postjournal service in Zimbra Collaboration (ZCS) before 8.8.15 Patch 46, 9 before 9.0.0 Patch 41, 10 before 10.0.9, and 10.1 before 10.1.1 sometimes allows unauthenticated users to execute commands.

- [https://github.com/lionels-cyber/CVE-2024-45519-Zimbra-Real-Fix](https://github.com/lionels-cyber/CVE-2024-45519-Zimbra-Real-Fix) :  ![starts](https://img.shields.io/github/stars/lionels-cyber/CVE-2024-45519-Zimbra-Real-Fix.svg) ![forks](https://img.shields.io/github/forks/lionels-cyber/CVE-2024-45519-Zimbra-Real-Fix.svg)


## CVE-2024-7344
 Howyar UEFI Application "Reloader"  (32-bit and 64-bit)  is vulnerable to execution of unsigned software in a hardcoded path.

- [https://github.com/Serious-senpai/remote-access-trojan](https://github.com/Serious-senpai/remote-access-trojan) :  ![starts](https://img.shields.io/github/stars/Serious-senpai/remote-access-trojan.svg) ![forks](https://img.shields.io/github/forks/Serious-senpai/remote-access-trojan.svg)


## CVE-2024-4577
 In PHP versions 8.1.* before 8.1.29, 8.2.* before 8.2.20, 8.3.* before 8.3.8, when using Apache and PHP-CGI on Windows, if the system is set up to use certain code pages, Windows may use "Best-Fit" behavior to replace characters in command line given to Win32 API functions. PHP CGI module may misinterpret those characters as PHP options, which may allow a malicious user to pass options to PHP binary being run, and thus reveal the source code of scripts, run arbitrary PHP code on the server, etc.

- [https://github.com/DuyDuongDuyDuong/CVE-2024-4577-Exploitation-AsyncRAT-Deployment-DFIR-Investigation](https://github.com/DuyDuongDuyDuong/CVE-2024-4577-Exploitation-AsyncRAT-Deployment-DFIR-Investigation) :  ![starts](https://img.shields.io/github/stars/DuyDuongDuyDuong/CVE-2024-4577-Exploitation-AsyncRAT-Deployment-DFIR-Investigation.svg) ![forks](https://img.shields.io/github/forks/DuyDuongDuyDuong/CVE-2024-4577-Exploitation-AsyncRAT-Deployment-DFIR-Investigation.svg)


## CVE-2024-0044
 In createSessionInternal of PackageInstallerService.java, there is a possible run-as any app due to improper input validation. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/hackerronin/CVE-2024-0044](https://github.com/hackerronin/CVE-2024-0044) :  ![starts](https://img.shields.io/github/stars/hackerronin/CVE-2024-0044.svg) ![forks](https://img.shields.io/github/forks/hackerronin/CVE-2024-0044.svg)


## CVE-2023-52076
 Atril Document Viewer is the default document reader of the MATE desktop environment for Linux. A path traversal and arbitrary file write vulnerability exists in versions of Atril prior to 1.26.2. This vulnerability is capable of writing arbitrary files anywhere on the filesystem to which the user opening a crafted document has access. The only limitation is that this vulnerability cannot be exploited to overwrite existing files, but that doesn't stop an attacker from achieving Remote Command Execution on the target system. Version 1.26.2 of Atril contains a patch for this vulnerability.

- [https://github.com/Groppoxx/CVE-2023-52076-PoC](https://github.com/Groppoxx/CVE-2023-52076-PoC) :  ![starts](https://img.shields.io/github/stars/Groppoxx/CVE-2023-52076-PoC.svg) ![forks](https://img.shields.io/github/forks/Groppoxx/CVE-2023-52076-PoC.svg)


## CVE-2023-50685
 An issue in Hipcam Cameras RealServer v.1.0 allows a remote attacker to cause a denial of service via a crafted script to the client_port parameter.

- [https://github.com/MaximilianLJungblut/Hipcam-RTSP-Format-Validation-Vulnerability](https://github.com/MaximilianLJungblut/Hipcam-RTSP-Format-Validation-Vulnerability) :  ![starts](https://img.shields.io/github/stars/MaximilianLJungblut/Hipcam-RTSP-Format-Validation-Vulnerability.svg) ![forks](https://img.shields.io/github/forks/MaximilianLJungblut/Hipcam-RTSP-Format-Validation-Vulnerability.svg)


## CVE-2023-48795
 The SSH transport protocol with certain OpenSSH extensions, found in OpenSSH before 9.6 and other products, allows remote attackers to bypass integrity checks such that some packets are omitted (from the extension negotiation message), and a client and server may consequently end up with a connection for which some security features have been downgraded or disabled, aka a Terrapin attack. This occurs because the SSH Binary Packet Protocol (BPP), implemented by these extensions, mishandles the handshake phase and mishandles use of sequence numbers. For example, there is an effective attack against SSH's use of ChaCha20-Poly1305 (and CBC with Encrypt-then-MAC). The bypass occurs in chacha20-poly1305@openssh.com and (if CBC is used) the -etm@openssh.com MAC algorithms. This also affects Maverick Synergy Java SSH API before 3.1.0-SNAPSHOT, Dropbear through 2022.83, Ssh before 5.1.1 in Erlang/OTP, PuTTY before 0.80, AsyncSSH before 2.14.2, golang.org/x/crypto before 0.17.0, libssh before 0.10.6, libssh2 through 1.11.0, Thorn Tech SFTP Gateway before 3.4.6, Tera Term before 5.1, Paramiko before 3.4.0, jsch before 0.2.15, SFTPGo before 2.5.6, Netgate pfSense Plus through 23.09.1, Netgate pfSense CE through 2.7.2, HPN-SSH through 18.2.0, ProFTPD before 1.3.8b (and before 1.3.9rc2), ORYX CycloneSSH before 2.3.4, NetSarang XShell 7 before Build 0144, CrushFTP before 10.6.0, ConnectBot SSH library before 2.2.22, Apache MINA sshd through 2.11.0, sshj through 0.37.0, TinySSH through 20230101, trilead-ssh2 6401, LANCOM LCOS and LANconfig, FileZilla before 3.66.4, Nova before 11.8, PKIX-SSH before 14.4, SecureCRT before 9.4.3, Transmit5 before 5.10.4, Win32-OpenSSH before 9.5.0.0p1-Beta, WinSCP before 6.2.2, Bitvise SSH Server before 9.32, Bitvise SSH Client before 9.33, KiTTY through 0.76.1.13, the net-ssh gem 7.2.0 for Ruby, the mscdex ssh2 module before 1.15.0 for Node.js, the thrussh library before 0.35.1 for Rust, and the Russh crate before 0.40.2 for Rust.

- [https://github.com/hav0cx0/CVE-2023-48795](https://github.com/hav0cx0/CVE-2023-48795) :  ![starts](https://img.shields.io/github/stars/hav0cx0/CVE-2023-48795.svg) ![forks](https://img.shields.io/github/forks/hav0cx0/CVE-2023-48795.svg)


## CVE-2023-48084
 Nagios XI before version 5.11.3 was discovered to contain a SQL injection vulnerability via the bulk modification tool.

- [https://github.com/MettHK/CVE-2023-48084-Revised](https://github.com/MettHK/CVE-2023-48084-Revised) :  ![starts](https://img.shields.io/github/stars/MettHK/CVE-2023-48084-Revised.svg) ![forks](https://img.shields.io/github/forks/MettHK/CVE-2023-48084-Revised.svg)


## CVE-2023-44487
 The HTTP/2 protocol allows a denial of service (server resource consumption) because request cancellation can reset many streams quickly, as exploited in the wild in August through October 2023.

- [https://github.com/tahaXafous/CVE-2023-44487-dos](https://github.com/tahaXafous/CVE-2023-44487-dos) :  ![starts](https://img.shields.io/github/stars/tahaXafous/CVE-2023-44487-dos.svg) ![forks](https://img.shields.io/github/forks/tahaXafous/CVE-2023-44487-dos.svg)
- [https://github.com/CerberusMrXi/CVE-2023-44487-HTTP2-DoS-Rapid-Reset-Exploit](https://github.com/CerberusMrXi/CVE-2023-44487-HTTP2-DoS-Rapid-Reset-Exploit) :  ![starts](https://img.shields.io/github/stars/CerberusMrXi/CVE-2023-44487-HTTP2-DoS-Rapid-Reset-Exploit.svg) ![forks](https://img.shields.io/github/forks/CerberusMrXi/CVE-2023-44487-HTTP2-DoS-Rapid-Reset-Exploit.svg)


## CVE-2023-41898
 Home assistant is an open source home automation. The Home Assistant Companion for Android app up to version 2023.8.2 is vulnerable to arbitrary URL loading in a WebView. This enables all sorts of attacks, including arbitrary JavaScript execution, limited native code execution, and credential theft. This issue has been patched in version 2023.9.2 and all users are advised to upgrade. There are no known workarounds for this vulnerability. This issue is also tracked as GitHub Security Lab (GHSL) Vulnerability Report: `GHSL-2023-142`.

- [https://github.com/LazyBear8372/CVE-2023-41898_Lab](https://github.com/LazyBear8372/CVE-2023-41898_Lab) :  ![starts](https://img.shields.io/github/stars/LazyBear8372/CVE-2023-41898_Lab.svg) ![forks](https://img.shields.io/github/forks/LazyBear8372/CVE-2023-41898_Lab.svg)


## CVE-2023-39910
 The cryptocurrency wallet entropy seeding mechanism used in Libbitcoin Explorer 3.0.0 through 3.6.0 is weak, aka the Milk Sad issue. The use of an mt19937 Mersenne Twister PRNG restricts the internal entropy to 32 bits regardless of settings. This allows remote attackers to recover any wallet private keys generated from "bx seed" entropy output and steal funds. (Affected users need to move funds to a secure new cryptocurrency wallet.) NOTE: the vendor's position is that there was sufficient documentation advising against "bx seed" but others disagree. NOTE: this was exploited in the wild in June and July 2023.

- [https://github.com/Xaxis/bitcoin-security](https://github.com/Xaxis/bitcoin-security) :  ![starts](https://img.shields.io/github/stars/Xaxis/bitcoin-security.svg) ![forks](https://img.shields.io/github/forks/Xaxis/bitcoin-security.svg)


## CVE-2023-38831
 RARLAB WinRAR before 6.23 allows attackers to execute arbitrary code when a user attempts to view a benign file within a ZIP archive. The issue occurs because a ZIP archive may include a benign file (such as an ordinary .JPG file) and also a folder that has the same name as the benign file, and the contents of the folder (which may include executable content) are processed during an attempt to access only the benign file. This was exploited in the wild in April through October 2023.

- [https://github.com/cristhiansm0/TXDXCristhian_2023-CVE-38831](https://github.com/cristhiansm0/TXDXCristhian_2023-CVE-38831) :  ![starts](https://img.shields.io/github/stars/cristhiansm0/TXDXCristhian_2023-CVE-38831.svg) ![forks](https://img.shields.io/github/forks/cristhiansm0/TXDXCristhian_2023-CVE-38831.svg)


## CVE-2023-36874
 Windows Error Reporting Service Elevation of Privilege Vulnerability

- [https://github.com/johnnygreeme/CVE-2023-36874](https://github.com/johnnygreeme/CVE-2023-36874) :  ![starts](https://img.shields.io/github/stars/johnnygreeme/CVE-2023-36874.svg) ![forks](https://img.shields.io/github/forks/johnnygreeme/CVE-2023-36874.svg)


## CVE-2023-36802
 Microsoft Streaming Service Proxy Elevation of Privilege Vulnerability

- [https://github.com/nhh9905/CVE-2023-36802](https://github.com/nhh9905/CVE-2023-36802) :  ![starts](https://img.shields.io/github/stars/nhh9905/CVE-2023-36802.svg) ![forks](https://img.shields.io/github/forks/nhh9905/CVE-2023-36802.svg)


## CVE-2023-36003
 XAML Diagnostics Elevation of Privilege Vulnerability

- [https://github.com/johnnygreeme/CVE-2023-36003](https://github.com/johnnygreeme/CVE-2023-36003) :  ![starts](https://img.shields.io/github/stars/johnnygreeme/CVE-2023-36003.svg) ![forks](https://img.shields.io/github/forks/johnnygreeme/CVE-2023-36003.svg)


## CVE-2023-34478
Mitigation: Update to Apache Shiro 1.12.0+ or 2.0.0-alpha-3+

- [https://github.com/xiaoqiMikko/shiro-check](https://github.com/xiaoqiMikko/shiro-check) :  ![starts](https://img.shields.io/github/stars/xiaoqiMikko/shiro-check.svg) ![forks](https://img.shields.io/github/forks/xiaoqiMikko/shiro-check.svg)


## CVE-2023-33107
 Memory corruption in Graphics Linux while assigning shared virtual memory region during IOCTL call.

- [https://github.com/264312431/picohaxx](https://github.com/264312431/picohaxx) :  ![starts](https://img.shields.io/github/stars/264312431/picohaxx.svg) ![forks](https://img.shields.io/github/forks/264312431/picohaxx.svg)


## CVE-2023-32784
 In KeePass 2.x before 2.54, it is possible to recover the cleartext master password from a memory dump, even when a workspace is locked or no longer running. The memory dump can be a KeePass process dump, swap file (pagefile.sys), hibernation file (hiberfil.sys), or RAM dump of the entire system. The first character cannot be recovered. In 2.54, there is different API usage and/or random string insertion for mitigation.

- [https://github.com/Pugazhendii22/keepass-exfil-forensics](https://github.com/Pugazhendii22/keepass-exfil-forensics) :  ![starts](https://img.shields.io/github/stars/Pugazhendii22/keepass-exfil-forensics.svg) ![forks](https://img.shields.io/github/forks/Pugazhendii22/keepass-exfil-forensics.svg)


## CVE-2023-32233
 In the Linux kernel through 6.3.1, a use-after-free in Netfilter nf_tables when processing batch requests can be abused to perform arbitrary read and write operations on kernel memory. Unprivileged local users can obtain root privileges. This occurs because anonymous sets are mishandled.

- [https://github.com/BurnSkyup/CVE-2023-32233-reproduction](https://github.com/BurnSkyup/CVE-2023-32233-reproduction) :  ![starts](https://img.shields.io/github/stars/BurnSkyup/CVE-2023-32233-reproduction.svg) ![forks](https://img.shields.io/github/forks/BurnSkyup/CVE-2023-32233-reproduction.svg)


## CVE-2023-30943
 The vulnerability was found Moodle which exists because the application allows a user to control path of the older to create in TinyMCE loaders. A remote user can send a specially crafted HTTP request and create arbitrary folders on the system.

- [https://github.com/Chocapikk/CVE-2023-30943](https://github.com/Chocapikk/CVE-2023-30943) :  ![starts](https://img.shields.io/github/stars/Chocapikk/CVE-2023-30943.svg) ![forks](https://img.shields.io/github/forks/Chocapikk/CVE-2023-30943.svg)


## CVE-2023-30258
 Command Injection vulnerability in MagnusSolution magnusbilling 6.x and 7.x allows remote attackers to run arbitrary commands via unauthenticated HTTP request.

- [https://github.com/Chocapikk/CVE-2023-30258](https://github.com/Chocapikk/CVE-2023-30258) :  ![starts](https://img.shields.io/github/stars/Chocapikk/CVE-2023-30258.svg) ![forks](https://img.shields.io/github/forks/Chocapikk/CVE-2023-30258.svg)


## CVE-2023-29375
 An issue was discovered in Progress Sitefinity 13.3 before 13.3.7647, 14.0 before 14.0.7736, 14.1 before 14.1.7826, 14.2 before 14.2.7930, and 14.3 before 14.3.8025. There is potentially dangerous file upload through the SharePoint connector.

- [https://github.com/Zedocun/Sharepoint-cve-2023-29375-incident-response](https://github.com/Zedocun/Sharepoint-cve-2023-29375-incident-response) :  ![starts](https://img.shields.io/github/stars/Zedocun/Sharepoint-cve-2023-29375-incident-response.svg) ![forks](https://img.shields.io/github/forks/Zedocun/Sharepoint-cve-2023-29375-incident-response.svg)


## CVE-2023-27997
 A heap-based buffer overflow vulnerability [CWE-122] in FortiOS version 7.2.4 and below, version 7.0.11 and below, version 6.4.12 and below, version 6.0.16 and below and FortiProxy version 7.2.3 and below, version 7.0.9 and below, version 2.0.12 and below, version 1.2 all versions, version 1.1 all versions SSL-VPN may allow a remote attacker to execute arbitrary code or commands via specifically crafted requests.

- [https://github.com/Vampsecure-Labs/vamp-forticheck](https://github.com/Vampsecure-Labs/vamp-forticheck) :  ![starts](https://img.shields.io/github/stars/Vampsecure-Labs/vamp-forticheck.svg) ![forks](https://img.shields.io/github/forks/Vampsecure-Labs/vamp-forticheck.svg)


## CVE-2023-27524
Alternatively you can set it with `SUPERSET_SECRET_KEY` environment variable.

- [https://github.com/h1n4mx0z/Research-CVE-2023-27524](https://github.com/h1n4mx0z/Research-CVE-2023-27524) :  ![starts](https://img.shields.io/github/stars/h1n4mx0z/Research-CVE-2023-27524.svg) ![forks](https://img.shields.io/github/forks/h1n4mx0z/Research-CVE-2023-27524.svg)


## CVE-2023-27350
 This vulnerability allows remote attackers to bypass authentication on affected installations of PaperCut NG 22.0.5 (Build 63914). Authentication is not required to exploit this vulnerability. The specific flaw exists within the SetupCompleted class. The issue results from improper access control. An attacker can leverage this vulnerability to bypass authentication and execute arbitrary code in the context of SYSTEM. Was ZDI-CAN-18987.

- [https://github.com/danielissaq/-PaperCut-CVE-2023-27350-](https://github.com/danielissaq/-PaperCut-CVE-2023-27350-) :  ![starts](https://img.shields.io/github/stars/danielissaq/-PaperCut-CVE-2023-27350-.svg) ![forks](https://img.shields.io/github/forks/danielissaq/-PaperCut-CVE-2023-27350-.svg)


## CVE-2023-26083
 Memory leak vulnerability in Mali GPU Kernel Driver in Midgard GPU Kernel Driver all versions from r6p0 - r32p0, Bifrost GPU Kernel Driver all versions from r0p0 - r42p0, Valhall GPU Kernel Driver all versions from r19p0 - r42p0, and Avalon GPU Kernel Driver all versions from r41p0 - r42p0 allows a non-privileged user to make valid GPU processing operations that expose sensitive kernel metadata.

- [https://github.com/noverisp3/CVE-2023-26083](https://github.com/noverisp3/CVE-2023-26083) :  ![starts](https://img.shields.io/github/stars/noverisp3/CVE-2023-26083.svg) ![forks](https://img.shields.io/github/forks/noverisp3/CVE-2023-26083.svg)


## CVE-2023-24932
 Secure Boot Security Feature Bypass Vulnerability

- [https://github.com/ETS-MSE/secure-boot-cert-servicing](https://github.com/ETS-MSE/secure-boot-cert-servicing) :  ![starts](https://img.shields.io/github/stars/ETS-MSE/secure-boot-cert-servicing.svg) ![forks](https://img.shields.io/github/forks/ETS-MSE/secure-boot-cert-servicing.svg)


## CVE-2023-24709
 An issue found in Paradox Security Systems IPR512 allows attackers to cause a denial of service via the login.html and login.xml parameters.

- [https://github.com/darknesschieftain/Injection-vulnerability-in-Paradox-Security-Systems-IPR512-CVE-2023-24709-PoC](https://github.com/darknesschieftain/Injection-vulnerability-in-Paradox-Security-Systems-IPR512-CVE-2023-24709-PoC) :  ![starts](https://img.shields.io/github/stars/darknesschieftain/Injection-vulnerability-in-Paradox-Security-Systems-IPR512-CVE-2023-24709-PoC.svg) ![forks](https://img.shields.io/github/forks/darknesschieftain/Injection-vulnerability-in-Paradox-Security-Systems-IPR512-CVE-2023-24709-PoC.svg)


## CVE-2023-22602
Mitigation: Update to Apache Shiro 1.11.0, or set the following Spring Boot configuration value:  `spring.mvc.pathmatch.matching-strategy = ant_path_matcher`

- [https://github.com/xiaoqiMikko/shiro-check](https://github.com/xiaoqiMikko/shiro-check) :  ![starts](https://img.shields.io/github/stars/xiaoqiMikko/shiro-check.svg) ![forks](https://img.shields.io/github/forks/xiaoqiMikko/shiro-check.svg)


## CVE-2023-22518
Atlassian Cloud sites are not affected by this vulnerability. If your Confluence site is accessed via an atlassian.net domain, it is hosted by Atlassian and is not vulnerable to this issue.

- [https://github.com/d3ckkNo0b/analyze-Exploit-CVE-2023-22518-Confluence](https://github.com/d3ckkNo0b/analyze-Exploit-CVE-2023-22518-Confluence) :  ![starts](https://img.shields.io/github/stars/d3ckkNo0b/analyze-Exploit-CVE-2023-22518-Confluence.svg) ![forks](https://img.shields.io/github/forks/d3ckkNo0b/analyze-Exploit-CVE-2023-22518-Confluence.svg)


## CVE-2023-22047
 Vulnerability in the PeopleSoft Enterprise PeopleTools product of Oracle PeopleSoft (component: Portal).  Supported versions that are affected are 8.59 and  8.60. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise PeopleSoft Enterprise PeopleTools.  Successful attacks of this vulnerability can result in  unauthorized access to critical data or complete access to all PeopleSoft Enterprise PeopleTools accessible data. CVSS 3.1 Base Score 7.5 (Confidentiality impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N).

- [https://github.com/0xTerror/CVE-2023-22047---Oracle-PeopleSoft-LFI](https://github.com/0xTerror/CVE-2023-22047---Oracle-PeopleSoft-LFI) :  ![starts](https://img.shields.io/github/stars/0xTerror/CVE-2023-22047---Oracle-PeopleSoft-LFI.svg) ![forks](https://img.shields.io/github/forks/0xTerror/CVE-2023-22047---Oracle-PeopleSoft-LFI.svg)
- [https://github.com/0xTerror/CVE-2023-22047-Oracle-PeopleSoft-LFI](https://github.com/0xTerror/CVE-2023-22047-Oracle-PeopleSoft-LFI) :  ![starts](https://img.shields.io/github/stars/0xTerror/CVE-2023-22047-Oracle-PeopleSoft-LFI.svg) ![forks](https://img.shields.io/github/forks/0xTerror/CVE-2023-22047-Oracle-PeopleSoft-LFI.svg)


## CVE-2023-21817
 Windows Kerberos Elevation of Privilege Vulnerability

- [https://github.com/johnnygreeme/CVE-2023-21817](https://github.com/johnnygreeme/CVE-2023-21817) :  ![starts](https://img.shields.io/github/stars/johnnygreeme/CVE-2023-21817.svg) ![forks](https://img.shields.io/github/forks/johnnygreeme/CVE-2023-21817.svg)


## CVE-2023-21768
 Windows Ancillary Function Driver for WinSock Elevation of Privilege Vulnerability

- [https://github.com/leandrofleury/CVE-2023-21768](https://github.com/leandrofleury/CVE-2023-21768) :  ![starts](https://img.shields.io/github/stars/leandrofleury/CVE-2023-21768.svg) ![forks](https://img.shields.io/github/forks/leandrofleury/CVE-2023-21768.svg)


## CVE-2023-20768
 In ion, there is a possible out of bounds read due to type confusion. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS07560720; Issue ID: ALPS07559800.

- [https://github.com/murf-xd/cve-2023-20768](https://github.com/murf-xd/cve-2023-20768) :  ![starts](https://img.shields.io/github/stars/murf-xd/cve-2023-20768.svg) ![forks](https://img.shields.io/github/forks/murf-xd/cve-2023-20768.svg)


## CVE-2023-6553
 The Backup Migration plugin for WordPress is vulnerable to Remote Code Execution in all versions up to, and including, 1.3.7 via the /includes/backup-heart.php file. This is due to an attacker being able to control the values passed to an include, and subsequently leverage that to achieve remote code execution. This makes it possible for unauthenticated attackers to easily execute code on the server.

- [https://github.com/Dungsocool/CVE-2023-6553](https://github.com/Dungsocool/CVE-2023-6553) :  ![starts](https://img.shields.io/github/stars/Dungsocool/CVE-2023-6553.svg) ![forks](https://img.shields.io/github/forks/Dungsocool/CVE-2023-6553.svg)


## CVE-2023-6241
 Use After Free vulnerability in Arm Ltd Midgard GPU Kernel Driver, Arm Ltd Bifrost GPU Kernel Driver, Arm Ltd Valhall GPU Kernel Driver, Arm Ltd Arm 5th Gen GPU Architecture Kernel Driver allows a local non-privileged user to exploit a software race condition to perform improper memory processing operations. If the system’s memory is carefully prepared by the user, then this in turn cause a use-after-free.This issue affects Midgard GPU Kernel Driver: from r13p0 through r32p0; Bifrost GPU Kernel Driver: from r11p0 through r25p0; Valhall GPU Kernel Driver: from r19p0 through r25p0, from r29p0 through r46p0; Arm 5th Gen GPU Architecture Kernel Driver: from r41p0 through r46p0.

- [https://github.com/s1204IT/CVE-2023-6241](https://github.com/s1204IT/CVE-2023-6241) :  ![starts](https://img.shields.io/github/stars/s1204IT/CVE-2023-6241.svg) ![forks](https://img.shields.io/github/forks/s1204IT/CVE-2023-6241.svg)


## CVE-2023-3350
 A Cryptographic Issue vulnerability has been found on IBERMATICA RPS, affecting version 2019. By firstly downloading the log file, an attacker could retrieve the SQL query sent to the application in plaint text. This log file contains the password hashes coded with AES-CBC-128 bits algorithm, which can be decrypted with a .NET function, obtaining the username's password in plain text.

- [https://github.com/itres-labs/CVE-2023-3350](https://github.com/itres-labs/CVE-2023-3350) :  ![starts](https://img.shields.io/github/stars/itres-labs/CVE-2023-3350.svg) ![forks](https://img.shields.io/github/forks/itres-labs/CVE-2023-3350.svg)


## CVE-2023-0386
 A flaw was found in the Linux kernel, where unauthorized access to the execution of the setuid file with capabilities was found in the Linux kernel’s OverlayFS subsystem in how a user copies a capable file from a nosuid mount into another mount. This uid mapping bug allows a local user to escalate their privileges on the system.

- [https://github.com/abedallarawashdeh/HTB-TwoMillion-machine](https://github.com/abedallarawashdeh/HTB-TwoMillion-machine) :  ![starts](https://img.shields.io/github/stars/abedallarawashdeh/HTB-TwoMillion-machine.svg) ![forks](https://img.shields.io/github/forks/abedallarawashdeh/HTB-TwoMillion-machine.svg)


## CVE-2022-44268
 ImageMagick 7.1.0-49 is vulnerable to Information Disclosure. When it parses a PNG image (e.g., for resize), the resulting image could have embedded the content of an arbitrary. file (if the magick binary has permissions to read it).

- [https://github.com/atici/ImageMagick-CVE-2022-44268-PoC](https://github.com/atici/ImageMagick-CVE-2022-44268-PoC) :  ![starts](https://img.shields.io/github/stars/atici/ImageMagick-CVE-2022-44268-PoC.svg) ![forks](https://img.shields.io/github/forks/atici/ImageMagick-CVE-2022-44268-PoC.svg)


## CVE-2022-40684
 An authentication bypass using an alternate path or channel [CWE-288] in Fortinet FortiOS version 7.2.0 through 7.2.1 and 7.0.0 through 7.0.6, FortiProxy version 7.2.0 and version 7.0.0 through 7.0.6 and FortiSwitchManager version 7.2.0 and 7.0.0 allows an unauthenticated atttacker to perform operations on the administrative interface via specially crafted HTTP or HTTPS requests.

- [https://github.com/Vampsecure-Labs/vamp-forticheck](https://github.com/Vampsecure-Labs/vamp-forticheck) :  ![starts](https://img.shields.io/github/stars/Vampsecure-Labs/vamp-forticheck.svg) ![forks](https://img.shields.io/github/forks/Vampsecure-Labs/vamp-forticheck.svg)


## CVE-2022-40664
 Apache Shiro before 1.10.0, Authentication Bypass Vulnerability in Shiro when forwarding or including via RequestDispatcher.

- [https://github.com/xiaoqiMikko/shiro-check](https://github.com/xiaoqiMikko/shiro-check) :  ![starts](https://img.shields.io/github/stars/xiaoqiMikko/shiro-check.svg) ![forks](https://img.shields.io/github/forks/xiaoqiMikko/shiro-check.svg)


## CVE-2022-38694
 In BootRom, there is a possible unchecked write address. This could lead to local escalation of privilege with no additional execution privileges needed.

- [https://github.com/LeoChen-CoreMind/spd_flasher](https://github.com/LeoChen-CoreMind/spd_flasher) :  ![starts](https://img.shields.io/github/stars/LeoChen-CoreMind/spd_flasher.svg) ![forks](https://img.shields.io/github/forks/LeoChen-CoreMind/spd_flasher.svg)
- [https://github.com/mutur4/UnisocBootROMs](https://github.com/mutur4/UnisocBootROMs) :  ![starts](https://img.shields.io/github/stars/mutur4/UnisocBootROMs.svg) ![forks](https://img.shields.io/github/forks/mutur4/UnisocBootROMs.svg)


## CVE-2022-38599
 Teleport v3.2.2, Teleport v3.5.6-rc6, and Teleport v3.6.3-b2 was discovered to contain an information leak via the /user/get-role-list web interface.

- [https://github.com/arleyna/CVE-2022-38599](https://github.com/arleyna/CVE-2022-38599) :  ![starts](https://img.shields.io/github/stars/arleyna/CVE-2022-38599.svg) ![forks](https://img.shields.io/github/forks/arleyna/CVE-2022-38599.svg)


## CVE-2022-38181
 The Arm Mali GPU kernel driver allows unprivileged users to access freed memory because GPU memory operations are mishandled. This affects Bifrost r0p0 through r38p1, and r39p0; Valhall r19p0 through r38p1, and r39p0; and Midgard r4p0 through r32p0.

- [https://github.com/hackintoanetwork/SCRoot](https://github.com/hackintoanetwork/SCRoot) :  ![starts](https://img.shields.io/github/stars/hackintoanetwork/SCRoot.svg) ![forks](https://img.shields.io/github/forks/hackintoanetwork/SCRoot.svg)
- [https://github.com/soralis0912/CVE-2022-38181-aristotle](https://github.com/soralis0912/CVE-2022-38181-aristotle) :  ![starts](https://img.shields.io/github/stars/soralis0912/CVE-2022-38181-aristotle.svg) ![forks](https://img.shields.io/github/forks/soralis0912/CVE-2022-38181-aristotle.svg)


## CVE-2022-35914
 /vendor/htmlawed/htmlawed/htmLawedTest.php in the htmlawed module for GLPI through 10.0.2 allows PHP code injection.

- [https://github.com/cyb3rk0ala/CVE-2022-35914-RCE](https://github.com/cyb3rk0ala/CVE-2022-35914-RCE) :  ![starts](https://img.shields.io/github/stars/cyb3rk0ala/CVE-2022-35914-RCE.svg) ![forks](https://img.shields.io/github/forks/cyb3rk0ala/CVE-2022-35914-RCE.svg)


## CVE-2022-31626
 In PHP versions 7.4.x below 7.4.30, 8.0.x below 8.0.20, and 8.1.x below 8.1.7, when pdo_mysql extension with mysqlnd driver, if the third party is allowed to supply host to connect to and the password for the connection, password of excessive length can trigger a buffer overflow in PHP, which can lead to a remote code execution vulnerability.

- [https://github.com/HORKimhab/CVE-2022-31626-CVE-2024-2961-CVE-2019-6977](https://github.com/HORKimhab/CVE-2022-31626-CVE-2024-2961-CVE-2019-6977) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2022-31626-CVE-2024-2961-CVE-2019-6977.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2022-31626-CVE-2024-2961-CVE-2019-6977.svg)


## CVE-2022-30190
Please see the MSRC Blog Entry for important information about steps you can take to protect your system from this vulnerability.

- [https://github.com/zavikhttak/follina-msdt-threat-investigation](https://github.com/zavikhttak/follina-msdt-threat-investigation) :  ![starts](https://img.shields.io/github/stars/zavikhttak/follina-msdt-threat-investigation.svg) ![forks](https://img.shields.io/github/forks/zavikhttak/follina-msdt-threat-investigation.svg)
- [https://github.com/KaritaMW/follina-vulnerability-analysis-lab](https://github.com/KaritaMW/follina-vulnerability-analysis-lab) :  ![starts](https://img.shields.io/github/stars/KaritaMW/follina-vulnerability-analysis-lab.svg) ![forks](https://img.shields.io/github/forks/KaritaMW/follina-vulnerability-analysis-lab.svg)


## CVE-2022-30024
 A buffer overflow in the httpd daemon on TP-Link TL-WR841N V12 (firmware version 3.16.9) devices allows an authenticated remote attacker to execute arbitrary code via a GET request to the page for the System Tools of the Wi-Fi network. This affects TL-WR841 V12 TL-WR841N(EU)_V12_160624 and TL-WR841 V11 TL-WR841N(EU)_V11_160325 , TL-WR841N_V11_150616 and TL-WR841 V10 TL-WR841N_V10_150310 are also affected.

- [https://github.com/ilizavr/CVE-2022-30024](https://github.com/ilizavr/CVE-2022-30024) :  ![starts](https://img.shields.io/github/stars/ilizavr/CVE-2022-30024.svg) ![forks](https://img.shields.io/github/forks/ilizavr/CVE-2022-30024.svg)


## CVE-2022-25012
 Argus Surveillance DVR v4.0 employs weak password encryption.

- [https://github.com/m1kb0k/CVE-2022-25012-dvr4-weak-password-encryption](https://github.com/m1kb0k/CVE-2022-25012-dvr4-weak-password-encryption) :  ![starts](https://img.shields.io/github/stars/m1kb0k/CVE-2022-25012-dvr4-weak-password-encryption.svg) ![forks](https://img.shields.io/github/forks/m1kb0k/CVE-2022-25012-dvr4-weak-password-encryption.svg)


## CVE-2022-24903
 Rsyslog is a rocket-fast system for log processing. Modules for TCP syslog reception have a potential heap buffer overflow when octet-counted framing is used. This can result in a segfault or some other malfunction. As of our understanding, this vulnerability can not be used for remote code execution. But there may still be a slight chance for experts to do that. The bug occurs when the octet count is read. While there is a check for the maximum number of octets, digits are written to a heap buffer even when the octet count is over the maximum, This can be used to overrun the memory buffer. However, once the sequence of digits stop, no additional characters can be added to the buffer. In our opinion, this makes remote exploits impossible or at least highly complex. Octet-counted framing is one of two potential framing modes. It is relatively uncommon, but enabled by default on receivers. Modules `imtcp`, `imptcp`, `imgssapi`, and `imhttp` are used for regular syslog message reception. It is best practice not to directly expose them to the public. When this practice is followed, the risk is considerably lower. Module `imdiag` is a diagnostics module primarily intended for testbench runs. We do not expect it to be present on any production installation. Octet-counted framing is not very common. Usually, it needs to be specifically enabled at senders. If users do not need it, they can turn it off for the most important modules. This will mitigate the vulnerability.

- [https://github.com/andree554/CVE-2022-24903-Heap-based-buffer-overflow-Hand-On-Lab](https://github.com/andree554/CVE-2022-24903-Heap-based-buffer-overflow-Hand-On-Lab) :  ![starts](https://img.shields.io/github/stars/andree554/CVE-2022-24903-Heap-based-buffer-overflow-Hand-On-Lab.svg) ![forks](https://img.shields.io/github/forks/andree554/CVE-2022-24903-Heap-based-buffer-overflow-Hand-On-Lab.svg)


## CVE-2022-24834
 Redis is an in-memory database that persists on disk. A specially crafted Lua script executing in Redis can trigger a heap overflow in the cjson library, and result with heap corruption and potentially remote code execution. The problem exists in all versions of Redis with Lua scripting support, starting from 2.6, and affects only authenticated and authorized users. The problem is fixed in versions 7.0.12, 6.2.13, and 6.0.20.

- [https://github.com/Nullx97/CVE-2022-24834-](https://github.com/Nullx97/CVE-2022-24834-) :  ![starts](https://img.shields.io/github/stars/Nullx97/CVE-2022-24834-.svg) ![forks](https://img.shields.io/github/forks/Nullx97/CVE-2022-24834-.svg)


## CVE-2022-24785
 Moment.js is a JavaScript date library for parsing, validating, manipulating, and formatting dates. A path traversal vulnerability impacts npm (server) users of Moment.js between versions 1.0.1 and 2.29.1, especially if a user-provided locale string is directly used to switch moment locale. This problem is patched in 2.29.2, and the patch can be applied to all affected versions. As a workaround, sanitize the user-provided locale name before passing it to Moment.js.

- [https://github.com/AnomalousVectors/cve-2022-24785-poc-lab](https://github.com/AnomalousVectors/cve-2022-24785-poc-lab) :  ![starts](https://img.shields.io/github/stars/AnomalousVectors/cve-2022-24785-poc-lab.svg) ![forks](https://img.shields.io/github/forks/AnomalousVectors/cve-2022-24785-poc-lab.svg)


## CVE-2022-24481
 Windows Common Log File System Driver Elevation of Privilege Vulnerability

- [https://github.com/uname1able/CVE-2022-24481-analysis](https://github.com/uname1able/CVE-2022-24481-analysis) :  ![starts](https://img.shields.io/github/stars/uname1able/CVE-2022-24481-analysis.svg) ![forks](https://img.shields.io/github/forks/uname1able/CVE-2022-24481-analysis.svg)


## CVE-2022-24355
 This vulnerability allows network-adjacent attackers to execute arbitrary code on affected installations of TP-Link TL-WR940N 3.20.1 Build 200316 Rel.34392n (5553) routers. Authentication is not required to exploit this vulnerability. The specific flaw exists within the parsing of file name extensions. The issue results from the lack of proper validation of the length of user-supplied data prior to copying it to a fixed-length stack-based buffer. An attacker can leverage this vulnerability to execute code in the context of root. Was ZDI-CAN-13910.

- [https://github.com/ilizavr/CVE-2022-24355](https://github.com/ilizavr/CVE-2022-24355) :  ![starts](https://img.shields.io/github/stars/ilizavr/CVE-2022-24355.svg) ![forks](https://img.shields.io/github/forks/ilizavr/CVE-2022-24355.svg)


## CVE-2022-22965
 A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the application to run on Tomcat as a WAR deployment. If the application is deployed as a Spring Boot executable jar, i.e. the default, it is not vulnerable to the exploit. However, the nature of the vulnerability is more general, and there may be other ways to exploit it.

- [https://github.com/aditidutta696-dev/Spring4Shell-CVE-2022-22965-Exploitation-Attempt](https://github.com/aditidutta696-dev/Spring4Shell-CVE-2022-22965-Exploitation-Attempt) :  ![starts](https://img.shields.io/github/stars/aditidutta696-dev/Spring4Shell-CVE-2022-22965-Exploitation-Attempt.svg) ![forks](https://img.shields.io/github/forks/aditidutta696-dev/Spring4Shell-CVE-2022-22965-Exploitation-Attempt.svg)


## CVE-2022-22706
 Arm Mali GPU Kernel Driver allows a non-privileged user to achieve write access to read-only memory pages. This affects Midgard r26p0 through r31p0, Bifrost r0p0 through r35p0, and Valhall r19p0 through r35p0.

- [https://github.com/byt3quester/CVE-2022-22706-poc](https://github.com/byt3quester/CVE-2022-22706-poc) :  ![starts](https://img.shields.io/github/stars/byt3quester/CVE-2022-22706-poc.svg) ![forks](https://img.shields.io/github/forks/byt3quester/CVE-2022-22706-poc.svg)


## CVE-2022-21907
 HTTP Protocol Stack Remote Code Execution Vulnerability

- [https://github.com/siboy17/CVE-2022-21907-http.sys](https://github.com/siboy17/CVE-2022-21907-http.sys) :  ![starts](https://img.shields.io/github/stars/siboy17/CVE-2022-21907-http.sys.svg) ![forks](https://img.shields.io/github/forks/siboy17/CVE-2022-21907-http.sys.svg)


## CVE-2022-3590
 WordPress is affected by an unauthenticated blind SSRF in the pingback feature. Because of a TOCTOU race condition between the validation checks and the HTTP request, attackers can reach internal hosts that are explicitly forbidden.

- [https://github.com/4chech/CVE-2022-3590](https://github.com/4chech/CVE-2022-3590) :  ![starts](https://img.shields.io/github/stars/4chech/CVE-2022-3590.svg) ![forks](https://img.shields.io/github/forks/4chech/CVE-2022-3590.svg)


## CVE-2022-3549
 A vulnerability was found in SourceCodester Simple Cold Storage Management System 1.0. It has been rated as problematic. This issue affects some unknown processing of the file /csms/admin/?page=user/manage_user of the component Avatar Handler. The manipulation leads to unrestricted upload. The attack may be initiated remotely. The exploit has been disclosed to the public and may be used. The identifier VDB-211049 was assigned to this vulnerability.

- [https://github.com/PN-Tester/CVE-2022-35499](https://github.com/PN-Tester/CVE-2022-35499) :  ![starts](https://img.shields.io/github/stars/PN-Tester/CVE-2022-35499.svg) ![forks](https://img.shields.io/github/forks/PN-Tester/CVE-2022-35499.svg)
- [https://github.com/PN-Tester/CVE-2022-35497](https://github.com/PN-Tester/CVE-2022-35497) :  ![starts](https://img.shields.io/github/stars/PN-Tester/CVE-2022-35497.svg) ![forks](https://img.shields.io/github/forks/PN-Tester/CVE-2022-35497.svg)


## CVE-2022-3218
 Due to a reliance on client-side authentication, the WiFi Mouse (Mouse Server) from Necta LLC's authentication mechanism is trivially bypassed, which can result in remote code execution.

- [https://github.com/mermehr/MouseServer-1.7.8.5-RCE](https://github.com/mermehr/MouseServer-1.7.8.5-RCE) :  ![starts](https://img.shields.io/github/stars/mermehr/MouseServer-1.7.8.5-RCE.svg) ![forks](https://img.shields.io/github/forks/mermehr/MouseServer-1.7.8.5-RCE.svg)


## CVE-2022-2296
 Use after free in Chrome OS Shell in Google Chrome on Chrome OS prior to 103.0.5060.114 allowed a remote attacker who convinced a user to engage in specific user interactions to potentially exploit heap corruption via direct UI interactions.

- [https://github.com/Shakur1314/CVE-2022-22965-Spring4Shell-Security-Operations-Analysis](https://github.com/Shakur1314/CVE-2022-22965-Spring4Shell-Security-Operations-Analysis) :  ![starts](https://img.shields.io/github/stars/Shakur1314/CVE-2022-22965-Spring4Shell-Security-Operations-Analysis.svg) ![forks](https://img.shields.io/github/forks/Shakur1314/CVE-2022-22965-Spring4Shell-Security-Operations-Analysis.svg)
- [https://github.com/shoucheng3/spring-projects__spring-framework_CVE-2022-22965_5-2-19-RELEASE](https://github.com/shoucheng3/spring-projects__spring-framework_CVE-2022-22965_5-2-19-RELEASE) :  ![starts](https://img.shields.io/github/stars/shoucheng3/spring-projects__spring-framework_CVE-2022-22965_5-2-19-RELEASE.svg) ![forks](https://img.shields.io/github/forks/shoucheng3/spring-projects__spring-framework_CVE-2022-22965_5-2-19-RELEASE.svg)


## CVE-2022-1471
 SnakeYaml's Constructor() class does not restrict types which can be instantiated during deserialization. Deserializing yaml content provided by an attacker can lead to remote code execution. We recommend using SnakeYaml's SafeConsturctor when parsing untrusted content to restrict deserialization. We recommend upgrading to version 2.0 and beyond.

- [https://github.com/aykhan019/cve-2022-1471-jira-lab](https://github.com/aykhan019/cve-2022-1471-jira-lab) :  ![starts](https://img.shields.io/github/stars/aykhan019/cve-2022-1471-jira-lab.svg) ![forks](https://img.shields.io/github/forks/aykhan019/cve-2022-1471-jira-lab.svg)
- [https://github.com/seal-sean-org/yaml-payload](https://github.com/seal-sean-org/yaml-payload) :  ![starts](https://img.shields.io/github/stars/seal-sean-org/yaml-payload.svg) ![forks](https://img.shields.io/github/forks/seal-sean-org/yaml-payload.svg)
- [https://github.com/seal-sean-org/seans-surf-and-skate](https://github.com/seal-sean-org/seans-surf-and-skate) :  ![starts](https://img.shields.io/github/stars/seal-sean-org/seans-surf-and-skate.svg) ![forks](https://img.shields.io/github/forks/seal-sean-org/seans-surf-and-skate.svg)


## CVE-2022-0847
 A flaw was found in the way the "flags" member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/rabomen/Dirty-Pipe](https://github.com/rabomen/Dirty-Pipe) :  ![starts](https://img.shields.io/github/stars/rabomen/Dirty-Pipe.svg) ![forks](https://img.shields.io/github/forks/rabomen/Dirty-Pipe.svg)
- [https://github.com/jxpsx/CVE-2022-0847-DirtyPipe-Exploits](https://github.com/jxpsx/CVE-2022-0847-DirtyPipe-Exploits) :  ![starts](https://img.shields.io/github/stars/jxpsx/CVE-2022-0847-DirtyPipe-Exploits.svg) ![forks](https://img.shields.io/github/forks/jxpsx/CVE-2022-0847-DirtyPipe-Exploits.svg)
- [https://github.com/solomon12354/LockingGirl-----CVE-2022-0847-Dirty_Pipe_virus](https://github.com/solomon12354/LockingGirl-----CVE-2022-0847-Dirty_Pipe_virus) :  ![starts](https://img.shields.io/github/stars/solomon12354/LockingGirl-----CVE-2022-0847-Dirty_Pipe_virus.svg) ![forks](https://img.shields.io/github/forks/solomon12354/LockingGirl-----CVE-2022-0847-Dirty_Pipe_virus.svg)


## CVE-2022-0441
 The MasterStudy LMS WordPress plugin before 2.7.6 does to validate some parameters given when registering a new account, allowing unauthenticated users to register as an admin

- [https://github.com/DappaNISM/CVE-2022-0441](https://github.com/DappaNISM/CVE-2022-0441) :  ![starts](https://img.shields.io/github/stars/DappaNISM/CVE-2022-0441.svg) ![forks](https://img.shields.io/github/forks/DappaNISM/CVE-2022-0441.svg)


## CVE-2021-47881
 dataSIMS Avionics ARINC 664-1 version 4.5.3 contains a local buffer overflow vulnerability that allows attackers to overwrite memory by manipulating the milstd1553result.txt file. Attackers can craft a malicious file with carefully constructed payload and alignment sections to potentially execute arbitrary code on the Windows system.

- [https://github.com/kagancapar/CVE-2021-47881](https://github.com/kagancapar/CVE-2021-47881) :  ![starts](https://img.shields.io/github/stars/kagancapar/CVE-2021-47881.svg) ![forks](https://img.shields.io/github/forks/kagancapar/CVE-2021-47881.svg)


## CVE-2021-44790
 A carefully crafted request body can cause a buffer overflow in the mod_lua multipart parser (r:parsebody() called from Lua scripts). The Apache httpd team is not aware of an exploit for the vulnerabilty though it might be possible to craft one. This issue affects Apache HTTP Server 2.4.51 and earlier.

- [https://github.com/CerberusMrXi/Apache-Lua-Buffer-Overflow-Exploit-CVE-2021-44790](https://github.com/CerberusMrXi/Apache-Lua-Buffer-Overflow-Exploit-CVE-2021-44790) :  ![starts](https://img.shields.io/github/stars/CerberusMrXi/Apache-Lua-Buffer-Overflow-Exploit-CVE-2021-44790.svg) ![forks](https://img.shields.io/github/forks/CerberusMrXi/Apache-Lua-Buffer-Overflow-Exploit-CVE-2021-44790.svg)


## CVE-2021-42574
 An issue was discovered in the Bidirectional Algorithm in the Unicode Specification through 14.0. It permits the visual reordering of characters via control sequences, which can be used to craft source code that renders different logic than the logical ordering of tokens ingested by compilers and interpreters. Adversaries can leverage this to encode source code for compilers accepting Unicode such that targeted vulnerabilities are introduced invisibly to human reviewers. NOTE: the Unicode Consortium offers the following alternative approach to presenting this concern. An issue is noted in the nature of international text that can affect applications that implement support for The Unicode Standard and the Unicode Bidirectional Algorithm (all versions). Due to text display behavior when text includes left-to-right and right-to-left characters, the visual order of tokens may be different from their logical order. Additionally, control characters needed to fully support the requirements of bidirectional text can further obfuscate the logical order of tokens. Unless mitigated, an adversary could craft source code such that the ordering of tokens perceived by human reviewers does not match what will be processed by a compiler/interpreter/etc. The Unicode Consortium has documented this class of vulnerability in its document, Unicode Technical Report #36, Unicode Security Considerations. The Unicode Consortium also provides guidance on mitigations for this class of issues in Unicode Technical Standard #39, Unicode Security Mechanisms, and in Unicode Standard Annex #31, Unicode Identifier and Pattern Syntax. Also, the BIDI specification allows applications to tailor the implementation in ways that can mitigate misleading visual reordering in program text; see HL4 in Unicode Standard Annex #9, Unicode Bidirectional Algorithm.

- [https://github.com/000wq123/boundaryguard](https://github.com/000wq123/boundaryguard) :  ![starts](https://img.shields.io/github/stars/000wq123/boundaryguard.svg) ![forks](https://img.shields.io/github/forks/000wq123/boundaryguard.svg)
- [https://github.com/rakib-nyc/nullorigin](https://github.com/rakib-nyc/nullorigin) :  ![starts](https://img.shields.io/github/stars/rakib-nyc/nullorigin.svg) ![forks](https://img.shields.io/github/forks/rakib-nyc/nullorigin.svg)
- [https://github.com/LuisCastellanos-dev/cobol-shield](https://github.com/LuisCastellanos-dev/cobol-shield) :  ![starts](https://img.shields.io/github/stars/LuisCastellanos-dev/cobol-shield.svg) ![forks](https://img.shields.io/github/forks/LuisCastellanos-dev/cobol-shield.svg)
- [https://github.com/nolindnaidoo/unicode-le](https://github.com/nolindnaidoo/unicode-le) :  ![starts](https://img.shields.io/github/stars/nolindnaidoo/unicode-le.svg) ![forks](https://img.shields.io/github/forks/nolindnaidoo/unicode-le.svg)


## CVE-2021-42013
 It was found that the fix for CVE-2021-41773 in Apache HTTP Server 2.4.50 was insufficient. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue only affects Apache 2.4.49 and Apache 2.4.50 and not earlier versions.

- [https://github.com/berraesen/apache-cve-2021-42013-lab](https://github.com/berraesen/apache-cve-2021-42013-lab) :  ![starts](https://img.shields.io/github/stars/berraesen/apache-cve-2021-42013-lab.svg) ![forks](https://img.shields.io/github/forks/berraesen/apache-cve-2021-42013-lab.svg)


## CVE-2021-42008
 The decode_data function in drivers/net/hamradio/6pack.c in the Linux kernel before 5.13.13 has a slab out-of-bounds write. Input from a process that has the CAP_NET_ADMIN capability can lead to root access.

- [https://github.com/WhatsWrongAndWhy/CVE-2021-42008](https://github.com/WhatsWrongAndWhy/CVE-2021-42008) :  ![starts](https://img.shields.io/github/stars/WhatsWrongAndWhy/CVE-2021-42008.svg) ![forks](https://img.shields.io/github/forks/WhatsWrongAndWhy/CVE-2021-42008.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/gagaltotal/CVE-2021-41773-apache](https://github.com/gagaltotal/CVE-2021-41773-apache) :  ![starts](https://img.shields.io/github/stars/gagaltotal/CVE-2021-41773-apache.svg) ![forks](https://img.shields.io/github/forks/gagaltotal/CVE-2021-41773-apache.svg)
- [https://github.com/Emaar1x/CVE-2021-41773](https://github.com/Emaar1x/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/Emaar1x/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/Emaar1x/CVE-2021-41773.svg)
- [https://github.com/DappaNISM/mass_cve-2021-41773](https://github.com/DappaNISM/mass_cve-2021-41773) :  ![starts](https://img.shields.io/github/stars/DappaNISM/mass_cve-2021-41773.svg) ![forks](https://img.shields.io/github/forks/DappaNISM/mass_cve-2021-41773.svg)
- [https://github.com/SANR01/CVE-2021-41773-Exploit-Lab](https://github.com/SANR01/CVE-2021-41773-Exploit-Lab) :  ![starts](https://img.shields.io/github/stars/SANR01/CVE-2021-41773-Exploit-Lab.svg) ![forks](https://img.shields.io/github/forks/SANR01/CVE-2021-41773-Exploit-Lab.svg)


## CVE-2021-41073
 loop_rw_iter in fs/io_uring.c in the Linux kernel 5.10 through 5.14.6 allows local users to gain privileges by using IORING_OP_PROVIDE_BUFFERS to trigger a free of a kernel buffer, as demonstrated by using /proc/pid/maps for exploitation.

- [https://github.com/WhatsWrongAndWhy/CVE-2021-41073](https://github.com/WhatsWrongAndWhy/CVE-2021-41073) :  ![starts](https://img.shields.io/github/stars/WhatsWrongAndWhy/CVE-2021-41073.svg) ![forks](https://img.shields.io/github/forks/WhatsWrongAndWhy/CVE-2021-41073.svg)


## CVE-2021-39156
 Istio is an open source platform for providing a uniform way to integrate microservices, manage traffic flow across microservices, enforce policies and aggregate telemetry data. Istio 1.11.0, 1.10.3 and below, and 1.9.7 and below contain a remotely exploitable vulnerability where an HTTP request with `#fragment` in the path may bypass Istio’s URI path based authorization policies. Patches are available in Istio 1.11.1, Istio 1.10.4 and Istio 1.9.8. As a work around a Lua filter may be written to normalize the path.

- [https://github.com/mostafaanouarghorab/MicroserviceCVE-2021-39156](https://github.com/mostafaanouarghorab/MicroserviceCVE-2021-39156) :  ![starts](https://img.shields.io/github/stars/mostafaanouarghorab/MicroserviceCVE-2021-39156.svg) ![forks](https://img.shields.io/github/forks/mostafaanouarghorab/MicroserviceCVE-2021-39156.svg)


## CVE-2021-36934
After installing this security update, you must manually delete all shadow copies of system files, including the SAM database, to fully mitigate this vulnerabilty. Simply installing this security update will not fully mitigate this vulnerability. See KB5005357- Delete Volume Shadow Copies.

- [https://github.com/DuyDuongDuyDuong/CVE-2021-36934-DLL-Hijacking-DFIR-Investigation](https://github.com/DuyDuongDuyDuong/CVE-2021-36934-DLL-Hijacking-DFIR-Investigation) :  ![starts](https://img.shields.io/github/stars/DuyDuongDuyDuong/CVE-2021-36934-DLL-Hijacking-DFIR-Investigation.svg) ![forks](https://img.shields.io/github/forks/DuyDuongDuyDuong/CVE-2021-36934-DLL-Hijacking-DFIR-Investigation.svg)


## CVE-2021-36260
 A command injection vulnerability in the web server of some Hikvision product. Due to the insufficient input validation, attacker can exploit the vulnerability to launch a command injection attack by sending some messages with malicious commands.

- [https://github.com/sylhetyhackvenger/HIKRAVEN](https://github.com/sylhetyhackvenger/HIKRAVEN) :  ![starts](https://img.shields.io/github/stars/sylhetyhackvenger/HIKRAVEN.svg) ![forks](https://img.shields.io/github/forks/sylhetyhackvenger/HIKRAVEN.svg)


## CVE-2021-34527
Note that the security updates released on and after July 6, 2021 contain protections for CVE-2021-1675 and the additional remote code execution exploit in the Windows Print Spooler service known as “PrintNightmare”, documented in CVE-2021-34527.

- [https://github.com/KaritaMW/printnightmare-detection-mitigation-lab](https://github.com/KaritaMW/printnightmare-detection-mitigation-lab) :  ![starts](https://img.shields.io/github/stars/KaritaMW/printnightmare-detection-mitigation-lab.svg) ![forks](https://img.shields.io/github/forks/KaritaMW/printnightmare-detection-mitigation-lab.svg)
- [https://github.com/joertx07/printnightmare-detection-lab](https://github.com/joertx07/printnightmare-detection-lab) :  ![starts](https://img.shields.io/github/stars/joertx07/printnightmare-detection-lab.svg) ![forks](https://img.shields.io/github/forks/joertx07/printnightmare-detection-lab.svg)


## CVE-2021-31602
 An issue was discovered in Hitachi Vantara Pentaho through 9.1 and Pentaho Business Intelligence Server through 7.x. The Security Model has different layers of Access Control. One of these layers is the applicationContext security, which is defined in the applicationContext-spring-security.xml file. The default configuration allows an unauthenticated user with no previous knowledge of the platform settings to extract pieces of information without possessing valid credentials.

- [https://github.com/0cool-design/PWNtaho](https://github.com/0cool-design/PWNtaho) :  ![starts](https://img.shields.io/github/stars/0cool-design/PWNtaho.svg) ![forks](https://img.shields.io/github/forks/0cool-design/PWNtaho.svg)


## CVE-2021-31440
 This vulnerability allows local attackers to escalate privileges on affected installations of Linux Kernel 5.11.15. An attacker must first obtain the ability to execute low-privileged code on the target system in order to exploit this vulnerability. The specific flaw exists within the handling of eBPF programs. The issue results from the lack of proper validation of user-supplied eBPF programs prior to executing them. An attacker can leverage this vulnerability to escalate privileges and execute arbitrary code in the context of the kernel. Was ZDI-CAN-13661.

- [https://github.com/WhatsWrongAndWhy/CVE-2021-31440](https://github.com/WhatsWrongAndWhy/CVE-2021-31440) :  ![starts](https://img.shields.io/github/stars/WhatsWrongAndWhy/CVE-2021-31440.svg) ![forks](https://img.shields.io/github/forks/WhatsWrongAndWhy/CVE-2021-31440.svg)


## CVE-2021-27365
 An issue was discovered in the Linux kernel through 5.11.3. Certain iSCSI data structures do not have appropriate length constraints or checks, and can exceed the PAGE_SIZE value. An unprivileged user can send a Netlink message that is associated with iSCSI, and has a length up to the maximum length of a Netlink message.

- [https://github.com/WhatsWrongAndWhy/CVE-2021-27365](https://github.com/WhatsWrongAndWhy/CVE-2021-27365) :  ![starts](https://img.shields.io/github/stars/WhatsWrongAndWhy/CVE-2021-27365.svg) ![forks](https://img.shields.io/github/forks/WhatsWrongAndWhy/CVE-2021-27365.svg)


## CVE-2021-26855
 Microsoft Exchange Server Remote Code Execution Vulnerability

- [https://github.com/probablysecure/Triage-CVE-2021-26855-ProxyLogon---Microsoft-Exchange-](https://github.com/probablysecure/Triage-CVE-2021-26855-ProxyLogon---Microsoft-Exchange-) :  ![starts](https://img.shields.io/github/stars/probablysecure/Triage-CVE-2021-26855-ProxyLogon---Microsoft-Exchange-.svg) ![forks](https://img.shields.io/github/forks/probablysecure/Triage-CVE-2021-26855-ProxyLogon---Microsoft-Exchange-.svg)


## CVE-2021-26837
 SQL Injection vulnerability in SearchTextBox parameter in Fortra (Formerly HelpSystems) DeliverNow before version 1.2.18, allows attackers to execute arbitrary code, escalate privileges, and gain sensitive information.

- [https://github.com/l0lsec/CVE-2021-26837](https://github.com/l0lsec/CVE-2021-26837) :  ![starts](https://img.shields.io/github/stars/l0lsec/CVE-2021-26837.svg) ![forks](https://img.shields.io/github/forks/l0lsec/CVE-2021-26837.svg)


## CVE-2021-26708
 A local privilege escalation was discovered in the Linux kernel before 5.10.13. Multiple race conditions in the AF_VSOCK implementation are caused by wrong locking in net/vmw_vsock/af_vsock.c. The race conditions were implicitly introduced in the commits that added VSOCK multi-transport support.

- [https://github.com/kungaocode/vulnerability-analysis-](https://github.com/kungaocode/vulnerability-analysis-) :  ![starts](https://img.shields.io/github/stars/kungaocode/vulnerability-analysis-.svg) ![forks](https://img.shields.io/github/forks/kungaocode/vulnerability-analysis-.svg)


## CVE-2021-22681
 Rockwell Automation Studio 5000 Logix Designer Versions 21 and later, and RSLogix 5000 Versions 16 through 20 use a key to verify Logix controllers are communicating with Rockwell Automation CompactLogix 1768, 1769, 5370, 5380, 5480: ControlLogix 5550, 5560, 5570, 5580; DriveLogix 5560, 5730, 1794-L34; Compact GuardLogix 5370, 5380; GuardLogix 5570, 5580; SoftLogix 5800. Rockwell Automation Studio 5000 Logix Designer Versions 21 and later and RSLogix 5000: Versions 16 through 20 are vulnerable because an unauthenticated attacker could bypass this verification mechanism and authenticate with Rockwell Automation CompactLogix 1768, 1769, 5370, 5380, 5480: ControlLogix 5550, 5560, 5570, 5580; DriveLogix 5560, 5730, 1794-L34; Compact GuardLogix 5370, 5380; GuardLogix 5570, 5580; SoftLogix 5800.

- [https://github.com/pcrosby-1990/cip-security-poc](https://github.com/pcrosby-1990/cip-security-poc) :  ![starts](https://img.shields.io/github/stars/pcrosby-1990/cip-security-poc.svg) ![forks](https://img.shields.io/github/forks/pcrosby-1990/cip-security-poc.svg)


## CVE-2021-22555
 A heap out-of-bounds write affecting Linux since v2.6.19-rc1 was discovered in net/netfilter/x_tables.c. This allows an attacker to gain privileges or cause a DoS (via heap memory corruption) through user name space

- [https://github.com/WhatsWrongAndWhy/CVE-2021-22555](https://github.com/WhatsWrongAndWhy/CVE-2021-22555) :  ![starts](https://img.shields.io/github/stars/WhatsWrongAndWhy/CVE-2021-22555.svg) ![forks](https://img.shields.io/github/forks/WhatsWrongAndWhy/CVE-2021-22555.svg)


## CVE-2021-21994
 SFCB (Small Footprint CIM Broker) as used in ESXi has an authentication bypass vulnerability. A malicious actor with network access to port 5989 on ESXi may exploit this issue to bypass SFCB authentication by sending a specially crafted request.

- [https://github.com/mreza-en/cve-2021-21994_POC](https://github.com/mreza-en/cve-2021-21994_POC) :  ![starts](https://img.shields.io/github/stars/mreza-en/cve-2021-21994_POC.svg) ![forks](https://img.shields.io/github/forks/mreza-en/cve-2021-21994_POC.svg)


## CVE-2021-21972
 The vSphere Client (HTML5) contains a remote code execution vulnerability in a vCenter Server plugin. A malicious actor with network access to port 443 may exploit this issue to execute commands with unrestricted privileges on the underlying operating system that hosts vCenter Server. This affects VMware vCenter Server (7.x before 7.0 U1c, 6.7 before 6.7 U3l and 6.5 before 6.5 U3n) and VMware Cloud Foundation (4.x before 4.2 and 3.x before 3.10.1.2).

- [https://github.com/Hurrrraaaa/CVE-2021-21972](https://github.com/Hurrrraaaa/CVE-2021-21972) :  ![starts](https://img.shields.io/github/stars/Hurrrraaaa/CVE-2021-21972.svg) ![forks](https://img.shields.io/github/forks/Hurrrraaaa/CVE-2021-21972.svg)


## CVE-2021-4422
 The POST SMTP Mailer plugin for WordPress is vulnerable to Cross-Site Request Forgery in versions up to, and including, 2.0.20. This is due to missing or incorrect nonce validation on the handleCsvExport() function. This makes it possible for unauthenticated attackers to trigger a CSV export via a forged request granted they can trick a site administrator into performing an action such as clicking on a link.

- [https://github.com/roxas-tan/CVE-2021-44228](https://github.com/roxas-tan/CVE-2021-44228) :  ![starts](https://img.shields.io/github/stars/roxas-tan/CVE-2021-44228.svg) ![forks](https://img.shields.io/github/forks/roxas-tan/CVE-2021-44228.svg)
- [https://github.com/kubearmor/log4j-CVE-2021-44228](https://github.com/kubearmor/log4j-CVE-2021-44228) :  ![starts](https://img.shields.io/github/stars/kubearmor/log4j-CVE-2021-44228.svg) ![forks](https://img.shields.io/github/forks/kubearmor/log4j-CVE-2021-44228.svg)
- [https://github.com/qingtengyun/cve-2021-44228-qingteng-patch](https://github.com/qingtengyun/cve-2021-44228-qingteng-patch) :  ![starts](https://img.shields.io/github/stars/qingtengyun/cve-2021-44228-qingteng-patch.svg) ![forks](https://img.shields.io/github/forks/qingtengyun/cve-2021-44228-qingteng-patch.svg)
- [https://github.com/Tai-e/CVE-2021-44228](https://github.com/Tai-e/CVE-2021-44228) :  ![starts](https://img.shields.io/github/stars/Tai-e/CVE-2021-44228.svg) ![forks](https://img.shields.io/github/forks/Tai-e/CVE-2021-44228.svg)
- [https://github.com/Sh0ckFR/log4j-CVE-2021-44228-Public-IoCs](https://github.com/Sh0ckFR/log4j-CVE-2021-44228-Public-IoCs) :  ![starts](https://img.shields.io/github/stars/Sh0ckFR/log4j-CVE-2021-44228-Public-IoCs.svg) ![forks](https://img.shields.io/github/forks/Sh0ckFR/log4j-CVE-2021-44228-Public-IoCs.svg)
- [https://github.com/sunnyvale-it/CVE-2021-44228-PoC](https://github.com/sunnyvale-it/CVE-2021-44228-PoC) :  ![starts](https://img.shields.io/github/stars/sunnyvale-it/CVE-2021-44228-PoC.svg) ![forks](https://img.shields.io/github/forks/sunnyvale-it/CVE-2021-44228-PoC.svg)
- [https://github.com/marcourbano/CVE-2021-44228](https://github.com/marcourbano/CVE-2021-44228) :  ![starts](https://img.shields.io/github/stars/marcourbano/CVE-2021-44228.svg) ![forks](https://img.shields.io/github/forks/marcourbano/CVE-2021-44228.svg)
- [https://github.com/KosmX/CVE-2021-44228-example](https://github.com/KosmX/CVE-2021-44228-example) :  ![starts](https://img.shields.io/github/stars/KosmX/CVE-2021-44228-example.svg) ![forks](https://img.shields.io/github/forks/KosmX/CVE-2021-44228-example.svg)
- [https://github.com/TaroballzChen/CVE-2021-44228-log4jVulnScanner-metasploit](https://github.com/TaroballzChen/CVE-2021-44228-log4jVulnScanner-metasploit) :  ![starts](https://img.shields.io/github/stars/TaroballzChen/CVE-2021-44228-log4jVulnScanner-metasploit.svg) ![forks](https://img.shields.io/github/forks/TaroballzChen/CVE-2021-44228-log4jVulnScanner-metasploit.svg)
- [https://github.com/Azeemering/CVE-2021-44228-DFIR-Notes](https://github.com/Azeemering/CVE-2021-44228-DFIR-Notes) :  ![starts](https://img.shields.io/github/stars/Azeemering/CVE-2021-44228-DFIR-Notes.svg) ![forks](https://img.shields.io/github/forks/Azeemering/CVE-2021-44228-DFIR-Notes.svg)
- [https://github.com/AlexandreHeroux/Fix-CVE-2021-44228](https://github.com/AlexandreHeroux/Fix-CVE-2021-44228) :  ![starts](https://img.shields.io/github/stars/AlexandreHeroux/Fix-CVE-2021-44228.svg) ![forks](https://img.shields.io/github/forks/AlexandreHeroux/Fix-CVE-2021-44228.svg)
- [https://github.com/irgoncalves/f5-waf-enforce-sig-CVE-2021-44228](https://github.com/irgoncalves/f5-waf-enforce-sig-CVE-2021-44228) :  ![starts](https://img.shields.io/github/stars/irgoncalves/f5-waf-enforce-sig-CVE-2021-44228.svg) ![forks](https://img.shields.io/github/forks/irgoncalves/f5-waf-enforce-sig-CVE-2021-44228.svg)
- [https://github.com/justakazh/Log4j-CVE-2021-44228](https://github.com/justakazh/Log4j-CVE-2021-44228) :  ![starts](https://img.shields.io/github/stars/justakazh/Log4j-CVE-2021-44228.svg) ![forks](https://img.shields.io/github/forks/justakazh/Log4j-CVE-2021-44228.svg)
- [https://github.com/maximofernandezriera/CVE-2021-44228](https://github.com/maximofernandezriera/CVE-2021-44228) :  ![starts](https://img.shields.io/github/stars/maximofernandezriera/CVE-2021-44228.svg) ![forks](https://img.shields.io/github/forks/maximofernandezriera/CVE-2021-44228.svg)
- [https://github.com/mrlnstk/cve-2021-44228-minecraft-poc](https://github.com/mrlnstk/cve-2021-44228-minecraft-poc) :  ![starts](https://img.shields.io/github/stars/mrlnstk/cve-2021-44228-minecraft-poc.svg) ![forks](https://img.shields.io/github/forks/mrlnstk/cve-2021-44228-minecraft-poc.svg)
- [https://github.com/manuel-alvarez-alvarez/log4j-cve-2021-44228](https://github.com/manuel-alvarez-alvarez/log4j-cve-2021-44228) :  ![starts](https://img.shields.io/github/stars/manuel-alvarez-alvarez/log4j-cve-2021-44228.svg) ![forks](https://img.shields.io/github/forks/manuel-alvarez-alvarez/log4j-cve-2021-44228.svg)
- [https://github.com/sud0x00/log4j-CVE-2021-44228](https://github.com/sud0x00/log4j-CVE-2021-44228) :  ![starts](https://img.shields.io/github/stars/sud0x00/log4j-CVE-2021-44228.svg) ![forks](https://img.shields.io/github/forks/sud0x00/log4j-CVE-2021-44228.svg)
- [https://github.com/toramanemre/apache-solr-log4j-CVE-2021-44228](https://github.com/toramanemre/apache-solr-log4j-CVE-2021-44228) :  ![starts](https://img.shields.io/github/stars/toramanemre/apache-solr-log4j-CVE-2021-44228.svg) ![forks](https://img.shields.io/github/forks/toramanemre/apache-solr-log4j-CVE-2021-44228.svg)
- [https://github.com/corneacristian/Log4J-CVE-2021-44228-RCE](https://github.com/corneacristian/Log4J-CVE-2021-44228-RCE) :  ![starts](https://img.shields.io/github/stars/corneacristian/Log4J-CVE-2021-44228-RCE.svg) ![forks](https://img.shields.io/github/forks/corneacristian/Log4J-CVE-2021-44228-RCE.svg)
- [https://github.com/Kr0ff/CVE-2021-44228](https://github.com/Kr0ff/CVE-2021-44228) :  ![starts](https://img.shields.io/github/stars/Kr0ff/CVE-2021-44228.svg) ![forks](https://img.shields.io/github/forks/Kr0ff/CVE-2021-44228.svg)
- [https://github.com/shamo0/CVE-2021-44228](https://github.com/shamo0/CVE-2021-44228) :  ![starts](https://img.shields.io/github/stars/shamo0/CVE-2021-44228.svg) ![forks](https://img.shields.io/github/forks/shamo0/CVE-2021-44228.svg)
- [https://github.com/ycdxsb/Log4Shell-CVE-2021-44228-ENV](https://github.com/ycdxsb/Log4Shell-CVE-2021-44228-ENV) :  ![starts](https://img.shields.io/github/stars/ycdxsb/Log4Shell-CVE-2021-44228-ENV.svg) ![forks](https://img.shields.io/github/forks/ycdxsb/Log4Shell-CVE-2021-44228-ENV.svg)
- [https://github.com/M1ngGod/CVE-2021-44228-Log4j-lookup-Rce](https://github.com/M1ngGod/CVE-2021-44228-Log4j-lookup-Rce) :  ![starts](https://img.shields.io/github/stars/M1ngGod/CVE-2021-44228-Log4j-lookup-Rce.svg) ![forks](https://img.shields.io/github/forks/M1ngGod/CVE-2021-44228-Log4j-lookup-Rce.svg)
- [https://github.com/CrackerCat/CVE-2021-44228-Log4j-Payloads](https://github.com/CrackerCat/CVE-2021-44228-Log4j-Payloads) :  ![starts](https://img.shields.io/github/stars/CrackerCat/CVE-2021-44228-Log4j-Payloads.svg) ![forks](https://img.shields.io/github/forks/CrackerCat/CVE-2021-44228-Log4j-Payloads.svg)
- [https://github.com/irgoncalves/f5-waf-quick-patch-cve-2021-44228](https://github.com/irgoncalves/f5-waf-quick-patch-cve-2021-44228) :  ![starts](https://img.shields.io/github/stars/irgoncalves/f5-waf-quick-patch-cve-2021-44228.svg) ![forks](https://img.shields.io/github/forks/irgoncalves/f5-waf-quick-patch-cve-2021-44228.svg)
- [https://github.com/ubitech/cve-2021-44228-rce-poc](https://github.com/ubitech/cve-2021-44228-rce-poc) :  ![starts](https://img.shields.io/github/stars/ubitech/cve-2021-44228-rce-poc.svg) ![forks](https://img.shields.io/github/forks/ubitech/cve-2021-44228-rce-poc.svg)
- [https://github.com/hotpotcookie/CVE-2021-44228-white-box](https://github.com/hotpotcookie/CVE-2021-44228-white-box) :  ![starts](https://img.shields.io/github/stars/hotpotcookie/CVE-2021-44228-white-box.svg) ![forks](https://img.shields.io/github/forks/hotpotcookie/CVE-2021-44228-white-box.svg)
- [https://github.com/zlepper/CVE-2021-44228-Test-Server](https://github.com/zlepper/CVE-2021-44228-Test-Server) :  ![starts](https://img.shields.io/github/stars/zlepper/CVE-2021-44228-Test-Server.svg) ![forks](https://img.shields.io/github/forks/zlepper/CVE-2021-44228-Test-Server.svg)
- [https://github.com/alexandreroman/cve-2021-44228-workaround-buildpack](https://github.com/alexandreroman/cve-2021-44228-workaround-buildpack) :  ![starts](https://img.shields.io/github/stars/alexandreroman/cve-2021-44228-workaround-buildpack.svg) ![forks](https://img.shields.io/github/forks/alexandreroman/cve-2021-44228-workaround-buildpack.svg)
- [https://github.com/pmontesd/log4j-cve-2021-44228](https://github.com/pmontesd/log4j-cve-2021-44228) :  ![starts](https://img.shields.io/github/stars/pmontesd/log4j-cve-2021-44228.svg) ![forks](https://img.shields.io/github/forks/pmontesd/log4j-cve-2021-44228.svg)
- [https://github.com/vorburger/Log4j_CVE-2021-44228](https://github.com/vorburger/Log4j_CVE-2021-44228) :  ![starts](https://img.shields.io/github/stars/vorburger/Log4j_CVE-2021-44228.svg) ![forks](https://img.shields.io/github/forks/vorburger/Log4j_CVE-2021-44228.svg)
- [https://github.com/tadash10/Exploiting-CVE-2021-44228-Log4Shell-in-a-Banking-Environment](https://github.com/tadash10/Exploiting-CVE-2021-44228-Log4Shell-in-a-Banking-Environment) :  ![starts](https://img.shields.io/github/stars/tadash10/Exploiting-CVE-2021-44228-Log4Shell-in-a-Banking-Environment.svg) ![forks](https://img.shields.io/github/forks/tadash10/Exploiting-CVE-2021-44228-Log4Shell-in-a-Banking-Environment.svg)
- [https://github.com/aws-samples/kubernetes-log4j-cve-2021-44228-node-agent](https://github.com/aws-samples/kubernetes-log4j-cve-2021-44228-node-agent) :  ![starts](https://img.shields.io/github/stars/aws-samples/kubernetes-log4j-cve-2021-44228-node-agent.svg) ![forks](https://img.shields.io/github/forks/aws-samples/kubernetes-log4j-cve-2021-44228-node-agent.svg)
- [https://github.com/mzlogin/CVE-2021-44228-Demo](https://github.com/mzlogin/CVE-2021-44228-Demo) :  ![starts](https://img.shields.io/github/stars/mzlogin/CVE-2021-44228-Demo.svg) ![forks](https://img.shields.io/github/forks/mzlogin/CVE-2021-44228-Demo.svg)
- [https://github.com/b-abderrahmane/CVE-2021-44228-playground](https://github.com/b-abderrahmane/CVE-2021-44228-playground) :  ![starts](https://img.shields.io/github/stars/b-abderrahmane/CVE-2021-44228-playground.svg) ![forks](https://img.shields.io/github/forks/b-abderrahmane/CVE-2021-44228-playground.svg)
- [https://github.com/thedevappsecguy/Log4J-Mitigation-CVE-2021-44228--CVE-2021-45046--CVE-2021-45105--CVE-2021-44832](https://github.com/thedevappsecguy/Log4J-Mitigation-CVE-2021-44228--CVE-2021-45046--CVE-2021-45105--CVE-2021-44832) :  ![starts](https://img.shields.io/github/stars/thedevappsecguy/Log4J-Mitigation-CVE-2021-44228--CVE-2021-45046--CVE-2021-45105--CVE-2021-44832.svg) ![forks](https://img.shields.io/github/forks/thedevappsecguy/Log4J-Mitigation-CVE-2021-44228--CVE-2021-45046--CVE-2021-45105--CVE-2021-44832.svg)
- [https://github.com/taurusxin/CVE-2021-44228](https://github.com/taurusxin/CVE-2021-44228) :  ![starts](https://img.shields.io/github/stars/taurusxin/CVE-2021-44228.svg) ![forks](https://img.shields.io/github/forks/taurusxin/CVE-2021-44228.svg)
- [https://github.com/motikan2010/RASP-CVE-2021-44228](https://github.com/motikan2010/RASP-CVE-2021-44228) :  ![starts](https://img.shields.io/github/stars/motikan2010/RASP-CVE-2021-44228.svg) ![forks](https://img.shields.io/github/forks/motikan2010/RASP-CVE-2021-44228.svg)
- [https://github.com/Vulnmachines/log4jshell_CVE-2021-44228](https://github.com/Vulnmachines/log4jshell_CVE-2021-44228) :  ![starts](https://img.shields.io/github/stars/Vulnmachines/log4jshell_CVE-2021-44228.svg) ![forks](https://img.shields.io/github/forks/Vulnmachines/log4jshell_CVE-2021-44228.svg)
- [https://github.com/ColdFusionX/CVE-2021-44228-Log4Shell-POC](https://github.com/ColdFusionX/CVE-2021-44228-Log4Shell-POC) :  ![starts](https://img.shields.io/github/stars/ColdFusionX/CVE-2021-44228-Log4Shell-POC.svg) ![forks](https://img.shields.io/github/forks/ColdFusionX/CVE-2021-44228-Log4Shell-POC.svg)
- [https://github.com/chandru-gunasekaran/log4j-fix-CVE-2021-44228](https://github.com/chandru-gunasekaran/log4j-fix-CVE-2021-44228) :  ![starts](https://img.shields.io/github/stars/chandru-gunasekaran/log4j-fix-CVE-2021-44228.svg) ![forks](https://img.shields.io/github/forks/chandru-gunasekaran/log4j-fix-CVE-2021-44228.svg)
- [https://github.com/BabooPan/Log4Shell-CVE-2021-44228-Demo](https://github.com/BabooPan/Log4Shell-CVE-2021-44228-Demo) :  ![starts](https://img.shields.io/github/stars/BabooPan/Log4Shell-CVE-2021-44228-Demo.svg) ![forks](https://img.shields.io/github/forks/BabooPan/Log4Shell-CVE-2021-44228-Demo.svg)
- [https://github.com/alpacamybags118/log4j-cve-2021-44228-sample](https://github.com/alpacamybags118/log4j-cve-2021-44228-sample) :  ![starts](https://img.shields.io/github/stars/alpacamybags118/log4j-cve-2021-44228-sample.svg) ![forks](https://img.shields.io/github/forks/alpacamybags118/log4j-cve-2021-44228-sample.svg)
- [https://github.com/george-petrakis/log4j-scanner-CVE-2021-44228](https://github.com/george-petrakis/log4j-scanner-CVE-2021-44228) :  ![starts](https://img.shields.io/github/stars/george-petrakis/log4j-scanner-CVE-2021-44228.svg) ![forks](https://img.shields.io/github/forks/george-petrakis/log4j-scanner-CVE-2021-44228.svg)
- [https://github.com/byteboycn/CVE-2021-44228-Apache-Log4j-Rce](https://github.com/byteboycn/CVE-2021-44228-Apache-Log4j-Rce) :  ![starts](https://img.shields.io/github/stars/byteboycn/CVE-2021-44228-Apache-Log4j-Rce.svg) ![forks](https://img.shields.io/github/forks/byteboycn/CVE-2021-44228-Apache-Log4j-Rce.svg)
- [https://github.com/Fazmin/vCenter-Server-Workaround-Script-CVE-2021-44228](https://github.com/Fazmin/vCenter-Server-Workaround-Script-CVE-2021-44228) :  ![starts](https://img.shields.io/github/stars/Fazmin/vCenter-Server-Workaround-Script-CVE-2021-44228.svg) ![forks](https://img.shields.io/github/forks/Fazmin/vCenter-Server-Workaround-Script-CVE-2021-44228.svg)
- [https://github.com/mkhazamipour/log4j-vulnerable-app-cve-2021-44228-terraform](https://github.com/mkhazamipour/log4j-vulnerable-app-cve-2021-44228-terraform) :  ![starts](https://img.shields.io/github/stars/mkhazamipour/log4j-vulnerable-app-cve-2021-44228-terraform.svg) ![forks](https://img.shields.io/github/forks/mkhazamipour/log4j-vulnerable-app-cve-2021-44228-terraform.svg)
- [https://github.com/anuvindhs/how-to-check-patch-secure-log4j-CVE-2021-44228](https://github.com/anuvindhs/how-to-check-patch-secure-log4j-CVE-2021-44228) :  ![starts](https://img.shields.io/github/stars/anuvindhs/how-to-check-patch-secure-log4j-CVE-2021-44228.svg) ![forks](https://img.shields.io/github/forks/anuvindhs/how-to-check-patch-secure-log4j-CVE-2021-44228.svg)
- [https://github.com/sec13b/CVE-2021-44228-POC](https://github.com/sec13b/CVE-2021-44228-POC) :  ![starts](https://img.shields.io/github/stars/sec13b/CVE-2021-44228-POC.svg) ![forks](https://img.shields.io/github/forks/sec13b/CVE-2021-44228-POC.svg)
- [https://github.com/nu11secur1ty/CVE-2021-44228-VULN-APP](https://github.com/nu11secur1ty/CVE-2021-44228-VULN-APP) :  ![starts](https://img.shields.io/github/stars/nu11secur1ty/CVE-2021-44228-VULN-APP.svg) ![forks](https://img.shields.io/github/forks/nu11secur1ty/CVE-2021-44228-VULN-APP.svg)
- [https://github.com/VerveIndustrialProtection/CVE-2021-44228-Log4j](https://github.com/VerveIndustrialProtection/CVE-2021-44228-Log4j) :  ![starts](https://img.shields.io/github/stars/VerveIndustrialProtection/CVE-2021-44228-Log4j.svg) ![forks](https://img.shields.io/github/forks/VerveIndustrialProtection/CVE-2021-44228-Log4j.svg)
- [https://github.com/kimobu/cve-2021-44228](https://github.com/kimobu/cve-2021-44228) :  ![starts](https://img.shields.io/github/stars/kimobu/cve-2021-44228.svg) ![forks](https://img.shields.io/github/forks/kimobu/cve-2021-44228.svg)
- [https://github.com/helsecert/CVE-2021-44228](https://github.com/helsecert/CVE-2021-44228) :  ![starts](https://img.shields.io/github/stars/helsecert/CVE-2021-44228.svg) ![forks](https://img.shields.io/github/forks/helsecert/CVE-2021-44228.svg)
- [https://github.com/srcporter/CVE-2021-44228](https://github.com/srcporter/CVE-2021-44228) :  ![starts](https://img.shields.io/github/stars/srcporter/CVE-2021-44228.svg) ![forks](https://img.shields.io/github/forks/srcporter/CVE-2021-44228.svg)
- [https://github.com/gyaansastra/CVE-2021-44228](https://github.com/gyaansastra/CVE-2021-44228) :  ![starts](https://img.shields.io/github/stars/gyaansastra/CVE-2021-44228.svg) ![forks](https://img.shields.io/github/forks/gyaansastra/CVE-2021-44228.svg)
- [https://github.com/jaehnri/CVE-2021-44228](https://github.com/jaehnri/CVE-2021-44228) :  ![starts](https://img.shields.io/github/stars/jaehnri/CVE-2021-44228.svg) ![forks](https://img.shields.io/github/forks/jaehnri/CVE-2021-44228.svg)
- [https://github.com/bcdunbar/CVE-2021-44228-poc](https://github.com/bcdunbar/CVE-2021-44228-poc) :  ![starts](https://img.shields.io/github/stars/bcdunbar/CVE-2021-44228-poc.svg) ![forks](https://img.shields.io/github/forks/bcdunbar/CVE-2021-44228-poc.svg)
- [https://github.com/Hoanle396/CVE-2021-44228-demo](https://github.com/Hoanle396/CVE-2021-44228-demo) :  ![starts](https://img.shields.io/github/stars/Hoanle396/CVE-2021-44228-demo.svg) ![forks](https://img.shields.io/github/forks/Hoanle396/CVE-2021-44228-demo.svg)
- [https://github.com/qw3rtyou/CVE-2021-44228_dockernize](https://github.com/qw3rtyou/CVE-2021-44228_dockernize) :  ![starts](https://img.shields.io/github/stars/qw3rtyou/CVE-2021-44228_dockernize.svg) ![forks](https://img.shields.io/github/forks/qw3rtyou/CVE-2021-44228_dockernize.svg)
- [https://github.com/RrUZi/Awesome-CVE-2021-44228](https://github.com/RrUZi/Awesome-CVE-2021-44228) :  ![starts](https://img.shields.io/github/stars/RrUZi/Awesome-CVE-2021-44228.svg) ![forks](https://img.shields.io/github/forks/RrUZi/Awesome-CVE-2021-44228.svg)
- [https://github.com/Panyaprach/Prove-CVE-2021-44228](https://github.com/Panyaprach/Prove-CVE-2021-44228) :  ![starts](https://img.shields.io/github/stars/Panyaprach/Prove-CVE-2021-44228.svg) ![forks](https://img.shields.io/github/forks/Panyaprach/Prove-CVE-2021-44228.svg)
- [https://github.com/chilliwebs/CVE-2021-44228_Example](https://github.com/chilliwebs/CVE-2021-44228_Example) :  ![starts](https://img.shields.io/github/stars/chilliwebs/CVE-2021-44228_Example.svg) ![forks](https://img.shields.io/github/forks/chilliwebs/CVE-2021-44228_Example.svg)
- [https://github.com/DiCanio/CVE-2021-44228-docker-example](https://github.com/DiCanio/CVE-2021-44228-docker-example) :  ![starts](https://img.shields.io/github/stars/DiCanio/CVE-2021-44228-docker-example.svg) ![forks](https://img.shields.io/github/forks/DiCanio/CVE-2021-44228-docker-example.svg)
- [https://github.com/uint0/cve-2021-44228--spring-hibernate](https://github.com/uint0/cve-2021-44228--spring-hibernate) :  ![starts](https://img.shields.io/github/stars/uint0/cve-2021-44228--spring-hibernate.svg) ![forks](https://img.shields.io/github/forks/uint0/cve-2021-44228--spring-hibernate.svg)
- [https://github.com/JiuBanSec/Log4j-CVE-2021-44228](https://github.com/JiuBanSec/Log4j-CVE-2021-44228) :  ![starts](https://img.shields.io/github/stars/JiuBanSec/Log4j-CVE-2021-44228.svg) ![forks](https://img.shields.io/github/forks/JiuBanSec/Log4j-CVE-2021-44228.svg)
- [https://github.com/kali-dass/CVE-2021-44228-log4Shell](https://github.com/kali-dass/CVE-2021-44228-log4Shell) :  ![starts](https://img.shields.io/github/stars/kali-dass/CVE-2021-44228-log4Shell.svg) ![forks](https://img.shields.io/github/forks/kali-dass/CVE-2021-44228-log4Shell.svg)
- [https://github.com/horrister/log4shell-cve-2021-44228](https://github.com/horrister/log4shell-cve-2021-44228) :  ![starts](https://img.shields.io/github/stars/horrister/log4shell-cve-2021-44228.svg) ![forks](https://img.shields.io/github/forks/horrister/log4shell-cve-2021-44228.svg)
- [https://github.com/pravin-pp/log4j2-CVE-2021-44228](https://github.com/pravin-pp/log4j2-CVE-2021-44228) :  ![starts](https://img.shields.io/github/stars/pravin-pp/log4j2-CVE-2021-44228.svg) ![forks](https://img.shields.io/github/forks/pravin-pp/log4j2-CVE-2021-44228.svg)
- [https://github.com/lhotari/pulsar-docker-images-patch-CVE-2021-44228](https://github.com/lhotari/pulsar-docker-images-patch-CVE-2021-44228) :  ![starts](https://img.shields.io/github/stars/lhotari/pulsar-docker-images-patch-CVE-2021-44228.svg) ![forks](https://img.shields.io/github/forks/lhotari/pulsar-docker-images-patch-CVE-2021-44228.svg)
- [https://github.com/pierpaolosestito-dev/Log4Shell-CVE-2021-44228-PoC](https://github.com/pierpaolosestito-dev/Log4Shell-CVE-2021-44228-PoC) :  ![starts](https://img.shields.io/github/stars/pierpaolosestito-dev/Log4Shell-CVE-2021-44228-PoC.svg) ![forks](https://img.shields.io/github/forks/pierpaolosestito-dev/Log4Shell-CVE-2021-44228-PoC.svg)
- [https://github.com/Kadantte/CVE-2021-44228-poc](https://github.com/Kadantte/CVE-2021-44228-poc) :  ![starts](https://img.shields.io/github/stars/Kadantte/CVE-2021-44228-poc.svg) ![forks](https://img.shields.io/github/forks/Kadantte/CVE-2021-44228-poc.svg)
- [https://github.com/guardicode/CVE-2021-44228_IoCs](https://github.com/guardicode/CVE-2021-44228_IoCs) :  ![starts](https://img.shields.io/github/stars/guardicode/CVE-2021-44228_IoCs.svg) ![forks](https://img.shields.io/github/forks/guardicode/CVE-2021-44228_IoCs.svg)
- [https://github.com/kannthu/CVE-2021-44228-Apache-Log4j-Rce](https://github.com/kannthu/CVE-2021-44228-Apache-Log4j-Rce) :  ![starts](https://img.shields.io/github/stars/kannthu/CVE-2021-44228-Apache-Log4j-Rce.svg) ![forks](https://img.shields.io/github/forks/kannthu/CVE-2021-44228-Apache-Log4j-Rce.svg)
- [https://github.com/Contrast-Security-OSS/CVE-2021-44228](https://github.com/Contrast-Security-OSS/CVE-2021-44228) :  ![starts](https://img.shields.io/github/stars/Contrast-Security-OSS/CVE-2021-44228.svg) ![forks](https://img.shields.io/github/forks/Contrast-Security-OSS/CVE-2021-44228.svg)
- [https://github.com/dark-ninja10/Log4j-CVE-2021-44228](https://github.com/dark-ninja10/Log4j-CVE-2021-44228) :  ![starts](https://img.shields.io/github/stars/dark-ninja10/Log4j-CVE-2021-44228.svg) ![forks](https://img.shields.io/github/forks/dark-ninja10/Log4j-CVE-2021-44228.svg)
- [https://github.com/kossatzd/log4j-CVE-2021-44228-test](https://github.com/kossatzd/log4j-CVE-2021-44228-test) :  ![starts](https://img.shields.io/github/stars/kossatzd/log4j-CVE-2021-44228-test.svg) ![forks](https://img.shields.io/github/forks/kossatzd/log4j-CVE-2021-44228-test.svg)
- [https://github.com/asd58584388/CVE-2021-44228](https://github.com/asd58584388/CVE-2021-44228) :  ![starts](https://img.shields.io/github/stars/asd58584388/CVE-2021-44228.svg) ![forks](https://img.shields.io/github/forks/asd58584388/CVE-2021-44228.svg)
- [https://github.com/Super-Binary/cve-2021-44228](https://github.com/Super-Binary/cve-2021-44228) :  ![starts](https://img.shields.io/github/stars/Super-Binary/cve-2021-44228.svg) ![forks](https://img.shields.io/github/forks/Super-Binary/cve-2021-44228.svg)


## CVE-2021-4376
 The WooCommerce Multi Currency plugin for WordPress is vulnerable to Missing Authorization  in versions up to, and including, 2.1.17. This makes it possible for authenticated attackers to change the price of a product to an arbitrary value.

- [https://github.com/DanielKevinn/CVE-2021-4376](https://github.com/DanielKevinn/CVE-2021-4376) :  ![starts](https://img.shields.io/github/stars/DanielKevinn/CVE-2021-4376.svg) ![forks](https://img.shields.io/github/forks/DanielKevinn/CVE-2021-4376.svg)


## CVE-2021-4177
 livehelperchat is vulnerable to Generation of Error Message Containing Sensitive Information

- [https://github.com/mohwahyudi/cve-2021-41773](https://github.com/mohwahyudi/cve-2021-41773) :  ![starts](https://img.shields.io/github/stars/mohwahyudi/cve-2021-41773.svg) ![forks](https://img.shields.io/github/forks/mohwahyudi/cve-2021-41773.svg)
- [https://github.com/puckiestyle/CVE-2021-41773](https://github.com/puckiestyle/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/puckiestyle/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/puckiestyle/CVE-2021-41773.svg)
- [https://github.com/AzkOsDev/CVE-2021-41773](https://github.com/AzkOsDev/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/AzkOsDev/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/AzkOsDev/CVE-2021-41773.svg)
- [https://github.com/JIYUN02/cve-2021-41773](https://github.com/JIYUN02/cve-2021-41773) :  ![starts](https://img.shields.io/github/stars/JIYUN02/cve-2021-41773.svg) ![forks](https://img.shields.io/github/forks/JIYUN02/cve-2021-41773.svg)
- [https://github.com/BabyTeam1024/CVE-2021-41773](https://github.com/BabyTeam1024/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/BabyTeam1024/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/BabyTeam1024/CVE-2021-41773.svg)
- [https://github.com/b1tsec/CVE-2021-41773](https://github.com/b1tsec/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/b1tsec/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/b1tsec/CVE-2021-41773.svg)
- [https://github.com/wolf1892/CVE-2021-41773](https://github.com/wolf1892/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/wolf1892/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/wolf1892/CVE-2021-41773.svg)
- [https://github.com/mightysai1997/cve-2021-41773](https://github.com/mightysai1997/cve-2021-41773) :  ![starts](https://img.shields.io/github/stars/mightysai1997/cve-2021-41773.svg) ![forks](https://img.shields.io/github/forks/mightysai1997/cve-2021-41773.svg)
- [https://github.com/r0otk3r/CVE-2021-41773](https://github.com/r0otk3r/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/r0otk3r/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/r0otk3r/CVE-2021-41773.svg)
- [https://github.com/Mahfujurjust/CVE-2021-41773](https://github.com/Mahfujurjust/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/Mahfujurjust/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/Mahfujurjust/CVE-2021-41773.svg)
- [https://github.com/0xc4t/CVE-2021-41773](https://github.com/0xc4t/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/0xc4t/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/0xc4t/CVE-2021-41773.svg)
- [https://github.com/lucastran05/CVE-2021-41773](https://github.com/lucastran05/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/lucastran05/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/lucastran05/CVE-2021-41773.svg)
- [https://github.com/12345qwert123456/CVE-2021-41773](https://github.com/12345qwert123456/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/12345qwert123456/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/12345qwert123456/CVE-2021-41773.svg)
- [https://github.com/Joapath/CVE-2021-41773](https://github.com/Joapath/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/Joapath/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/Joapath/CVE-2021-41773.svg)
- [https://github.com/Taldrid1/cve-2021-41773](https://github.com/Taldrid1/cve-2021-41773) :  ![starts](https://img.shields.io/github/stars/Taldrid1/cve-2021-41773.svg) ![forks](https://img.shields.io/github/forks/Taldrid1/cve-2021-41773.svg)
- [https://github.com/zer0qs/CVE-2021-41773](https://github.com/zer0qs/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/zer0qs/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/zer0qs/CVE-2021-41773.svg)
- [https://github.com/tr3m0x/CVE-2021-41773](https://github.com/tr3m0x/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/tr3m0x/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/tr3m0x/CVE-2021-41773.svg)
- [https://github.com/xMohamed0/CVE-2021-41773](https://github.com/xMohamed0/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/xMohamed0/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/xMohamed0/CVE-2021-41773.svg)
- [https://github.com/sixpacksecurity/CVE-2021-41773](https://github.com/sixpacksecurity/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/sixpacksecurity/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/sixpacksecurity/CVE-2021-41773.svg)
- [https://github.com/ch4os443/CVE-2021-41773](https://github.com/ch4os443/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/ch4os443/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/ch4os443/CVE-2021-41773.svg)
- [https://github.com/TheLastVvV/CVE-2021-41773](https://github.com/TheLastVvV/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/TheLastVvV/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/TheLastVvV/CVE-2021-41773.svg)
- [https://github.com/skentagon/CVE-2021-41773](https://github.com/skentagon/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/skentagon/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/skentagon/CVE-2021-41773.svg)
- [https://github.com/vuongnv3389-sec/cve-2021-41773](https://github.com/vuongnv3389-sec/cve-2021-41773) :  ![starts](https://img.shields.io/github/stars/vuongnv3389-sec/cve-2021-41773.svg) ![forks](https://img.shields.io/github/forks/vuongnv3389-sec/cve-2021-41773.svg)
- [https://github.com/Fa1c0n35/CVE-2021-41773](https://github.com/Fa1c0n35/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/Fa1c0n35/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/Fa1c0n35/CVE-2021-41773.svg)
- [https://github.com/faizdotid/CVE-2021-41773](https://github.com/faizdotid/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/faizdotid/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/faizdotid/CVE-2021-41773.svg)
- [https://github.com/shiomiyan/CVE-2021-41773](https://github.com/shiomiyan/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/shiomiyan/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/shiomiyan/CVE-2021-41773.svg)


## CVE-2021-3560
 It was found that polkit could be tricked into bypassing the credential checks for D-Bus requests, elevating the privileges of the requestor to the root user. This flaw could be used by an unprivileged local attacker to, for example, create a new local administrator. The highest threat from this vulnerability is to data confidentiality and integrity as well as system availability.

- [https://github.com/WithinOneStem/POC-Bash-CVE-2021-3560](https://github.com/WithinOneStem/POC-Bash-CVE-2021-3560) :  ![starts](https://img.shields.io/github/stars/WithinOneStem/POC-Bash-CVE-2021-3560.svg) ![forks](https://img.shields.io/github/forks/WithinOneStem/POC-Bash-CVE-2021-3560.svg)


## CVE-2021-3493
 The overlayfs implementation in the linux kernel did not properly validate with respect to user namespaces the setting of file capabilities on files in an underlying file system. Due to the combination of unprivileged user namespaces along with a patch carried in the Ubuntu kernel to allow unprivileged overlay mounts, an attacker could use this to gain elevated privileges.

- [https://github.com/WhatsWrongAndWhy/CVE-2021-3493](https://github.com/WhatsWrongAndWhy/CVE-2021-3493) :  ![starts](https://img.shields.io/github/stars/WhatsWrongAndWhy/CVE-2021-3493.svg) ![forks](https://img.shields.io/github/forks/WhatsWrongAndWhy/CVE-2021-3493.svg)
- [https://github.com/0xlane/CVE-2021-3493](https://github.com/0xlane/CVE-2021-3493) :  ![starts](https://img.shields.io/github/stars/0xlane/CVE-2021-3493.svg) ![forks](https://img.shields.io/github/forks/0xlane/CVE-2021-3493.svg)


## CVE-2021-3490
 The eBPF ALU32 bounds tracking for bitwise ops (AND, OR and XOR) in the Linux kernel did not properly update 32-bit bounds, which could be turned into out of bounds reads and writes in the Linux kernel and therefore, arbitrary code execution. This issue was fixed via commit 049c4e13714e ("bpf: Fix alu32 const subreg bound tracking on bitwise operations") (v5.13-rc4) and backported to the stable kernels in v5.12.4, v5.11.21, and v5.10.37. The AND/OR issues were introduced by commit 3f50f132d840 ("bpf: Verifier, do explicit ALU32 bounds tracking") (5.7-rc1) and the XOR variant was introduced by 2921c90d4718 ("bpf:Fix a verifier failure with xor") ( 5.10-rc1).

- [https://github.com/WhatsWrongAndWhy/CVE-2021-3490](https://github.com/WhatsWrongAndWhy/CVE-2021-3490) :  ![starts](https://img.shields.io/github/stars/WhatsWrongAndWhy/CVE-2021-3490.svg) ![forks](https://img.shields.io/github/forks/WhatsWrongAndWhy/CVE-2021-3490.svg)


## CVE-2021-3262
 TripSpark VEO Transportation-2.2.x-XP_BB-20201123-184084 NovusEDU-2.2.x-XP_BB-20201123-184084 allows unsafe data inputs in POST body parameters from end users without sanitizing using server-side logic. It was possible to inject custom SQL commands into the "Student Busing Information" search queries.

- [https://github.com/l0lsec/CVE-2021-3262](https://github.com/l0lsec/CVE-2021-3262) :  ![starts](https://img.shields.io/github/stars/l0lsec/CVE-2021-3262.svg) ![forks](https://img.shields.io/github/forks/l0lsec/CVE-2021-3262.svg)


## CVE-2021-3156
 Sudo before 1.9.5p2 contains an off-by-one error that can result in a heap-based buffer overflow, which allows privilege escalation to root via "sudoedit -s" and a command-line argument that ends with a single backslash character.

- [https://github.com/gmh5225/cve-2021-3156-](https://github.com/gmh5225/cve-2021-3156-) :  ![starts](https://img.shields.io/github/stars/gmh5225/cve-2021-3156-.svg) ![forks](https://img.shields.io/github/forks/gmh5225/cve-2021-3156-.svg)
- [https://github.com/WhatsWrongAndWhy/CVE-2021-3156](https://github.com/WhatsWrongAndWhy/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/WhatsWrongAndWhy/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/WhatsWrongAndWhy/CVE-2021-3156.svg)
- [https://github.com/Shams-Ul-Mehmood/CVE-2021-3156-Project](https://github.com/Shams-Ul-Mehmood/CVE-2021-3156-Project) :  ![starts](https://img.shields.io/github/stars/Shams-Ul-Mehmood/CVE-2021-3156-Project.svg) ![forks](https://img.shields.io/github/forks/Shams-Ul-Mehmood/CVE-2021-3156-Project.svg)


## CVE-2021-3129
 Ignition before 2.5.2, as used in Laravel and other products, allows unauthenticated remote attackers to execute arbitrary code because of insecure usage of file_get_contents() and file_put_contents(). This is exploitable on sites using debug mode with Laravel before 8.4.2.

- [https://github.com/Giangdurian/CVE-2021-3129](https://github.com/Giangdurian/CVE-2021-3129) :  ![starts](https://img.shields.io/github/stars/Giangdurian/CVE-2021-3129.svg) ![forks](https://img.shields.io/github/forks/Giangdurian/CVE-2021-3129.svg)
- [https://github.com/theNareshofficial/CVE-2021-3129-Lab](https://github.com/theNareshofficial/CVE-2021-3129-Lab) :  ![starts](https://img.shields.io/github/stars/theNareshofficial/CVE-2021-3129-Lab.svg) ![forks](https://img.shields.io/github/forks/theNareshofficial/CVE-2021-3129-Lab.svg)


## CVE-2021-1931
 Possible buffer overflow due to improper validation of buffer length while processing fast boot commands in Snapdragon Auto, Snapdragon Compute, Snapdragon Connectivity, Snapdragon Consumer IOT, Snapdragon Industrial IOT, Snapdragon Mobile, Snapdragon Voice & Music

- [https://github.com/starseed12345/QuestStack](https://github.com/starseed12345/QuestStack) :  ![starts](https://img.shields.io/github/stars/starseed12345/QuestStack.svg) ![forks](https://img.shields.io/github/forks/starseed12345/QuestStack.svg)


## CVE-2021-1732
 Windows Win32k Elevation of Privilege Vulnerability

- [https://github.com/po4sec/CVE-2021-1732](https://github.com/po4sec/CVE-2021-1732) :  ![starts](https://img.shields.io/github/stars/po4sec/CVE-2021-1732.svg) ![forks](https://img.shields.io/github/forks/po4sec/CVE-2021-1732.svg)


## CVE-2021-1675
 Windows Print Spooler Remote Code Execution Vulnerability

- [https://github.com/thalpius/microsoft-cve-2021-1675](https://github.com/thalpius/microsoft-cve-2021-1675) :  ![starts](https://img.shields.io/github/stars/thalpius/microsoft-cve-2021-1675.svg) ![forks](https://img.shields.io/github/forks/thalpius/microsoft-cve-2021-1675.svg)


## CVE-2020-27194
 An issue was discovered in the Linux kernel before 5.8.15. scalar32_min_max_or in kernel/bpf/verifier.c mishandles bounds tracking during use of 64-bit values, aka CID-5b9fbeb75b6a.

- [https://github.com/WhatsWrongAndWhy/CVE-2020-27194](https://github.com/WhatsWrongAndWhy/CVE-2020-27194) :  ![starts](https://img.shields.io/github/stars/WhatsWrongAndWhy/CVE-2020-27194.svg) ![forks](https://img.shields.io/github/forks/WhatsWrongAndWhy/CVE-2020-27194.svg)


## CVE-2020-25279
 An issue was discovered on Samsung mobile devices with O(8.x), P(9.0), and Q(10.0) (Exynos chipsets) software. The baseband component has a buffer overflow via an abnormal SETUP message, leading to execution of arbitrary code. The Samsung ID is SVE-2020-18098 (September 2020).

- [https://github.com/Gimminse/Firmware-analysis](https://github.com/Gimminse/Firmware-analysis) :  ![starts](https://img.shields.io/github/stars/Gimminse/Firmware-analysis.svg) ![forks](https://img.shields.io/github/forks/Gimminse/Firmware-analysis.svg)


## CVE-2020-25273
 In SourceCodester Online Bus Booking System 1.0, there is Authentication bypass on the Admin Login screen in admin.php via username or password SQL injection.

- [https://github.com/jonathanrey87/CVE-2020-25273](https://github.com/jonathanrey87/CVE-2020-25273) :  ![starts](https://img.shields.io/github/stars/jonathanrey87/CVE-2020-25273.svg) ![forks](https://img.shields.io/github/forks/jonathanrey87/CVE-2020-25273.svg)


## CVE-2020-25270
 PHPGurukul hostel-management-system 2.1 allows XSS via Guardian Name, Guardian Relation, Guardian Contact no, Address, or City.

- [https://github.com/pushpam002/CVE-2020-25270](https://github.com/pushpam002/CVE-2020-25270) :  ![starts](https://img.shields.io/github/stars/pushpam002/CVE-2020-25270.svg) ![forks](https://img.shields.io/github/forks/pushpam002/CVE-2020-25270.svg)


## CVE-2020-24030
 ForLogic Qualiex v1 and v3 has weak token expiration. This allows remote unauthenticated privilege escalation and access to sensitive data via token reuse. NOTE: as of 2025-10-14, the Supplier's perspective is that this is "not exploitable in the current implementation. Tokens are properly expired, invalidated, and bound to session context. Attempts to alter the token payload to extend its validity do not affect server-side validation."

- [https://github.com/RedTeamBrasil/CVE-2020-24030](https://github.com/RedTeamBrasil/CVE-2020-24030) :  ![starts](https://img.shields.io/github/stars/RedTeamBrasil/CVE-2020-24030.svg) ![forks](https://img.shields.io/github/forks/RedTeamBrasil/CVE-2020-24030.svg)


## CVE-2020-24029
 Because of unauthenticated password changes in ForLogic Qualiex v1 and v3, customer and admin permissions and data can be accessed via a simple request. NOTE: as of 2025-10-14, the Supplier's perspective is that this is "corrected in all maintained versions. Password reset requests are validated against registered user emails and require a valid, short-lived token."

- [https://github.com/RedTeamBrasil/CVE-2020-24029](https://github.com/RedTeamBrasil/CVE-2020-24029) :  ![starts](https://img.shields.io/github/stars/RedTeamBrasil/CVE-2020-24029.svg) ![forks](https://img.shields.io/github/forks/RedTeamBrasil/CVE-2020-24029.svg)


## CVE-2020-24028
 ForLogic Qualiex v1 and v3 allows any authenticated customer to achieve privilege escalation via user creations, password changes, or user permission updates. NOTE: as of 2025-10-14, the Supplier's perspective is that this "does not allow administrative privilege gain. Authorization is enforced server-side, restricting actions to the user’s own permission scope."

- [https://github.com/RedTeamBrasil/CVE-2020-24028](https://github.com/RedTeamBrasil/CVE-2020-24028) :  ![starts](https://img.shields.io/github/stars/RedTeamBrasil/CVE-2020-24028.svg) ![forks](https://img.shields.io/github/forks/RedTeamBrasil/CVE-2020-24028.svg)


## CVE-2020-23349
 An intent redirection issue was doscovered in Sina Weibo Android SDK 4.2.7 (com.sina.weibo.sdk.share.WbShareTransActivity), any unexported Activities could be started by the com.sina.weibo.sdk.share.WbShareTransActivity.

- [https://github.com/LazyBear8372/CVE-2020-23349_Lab](https://github.com/LazyBear8372/CVE-2020-23349_Lab) :  ![starts](https://img.shields.io/github/stars/LazyBear8372/CVE-2020-23349_Lab.svg) ![forks](https://img.shields.io/github/forks/LazyBear8372/CVE-2020-23349_Lab.svg)


## CVE-2020-17523
 Apache Shiro before 1.7.1, when using Apache Shiro with Spring, a specially crafted HTTP request may cause an authentication bypass.

- [https://github.com/xiaoqiMikko/shiro-check](https://github.com/xiaoqiMikko/shiro-check) :  ![starts](https://img.shields.io/github/stars/xiaoqiMikko/shiro-check.svg) ![forks](https://img.shields.io/github/forks/xiaoqiMikko/shiro-check.svg)


## CVE-2020-17510
 Apache Shiro before 1.7.0, when using Apache Shiro with Spring, a specially crafted HTTP request may cause an authentication bypass.

- [https://github.com/xiaoqiMikko/shiro-check](https://github.com/xiaoqiMikko/shiro-check) :  ![starts](https://img.shields.io/github/stars/xiaoqiMikko/shiro-check.svg) ![forks](https://img.shields.io/github/forks/xiaoqiMikko/shiro-check.svg)


## CVE-2020-10199
 Sonatype Nexus Repository before 3.21.2 allows JavaEL Injection (issue 1 of 2).

- [https://github.com/finn79426/CVE-2020-10199](https://github.com/finn79426/CVE-2020-10199) :  ![starts](https://img.shields.io/github/stars/finn79426/CVE-2020-10199.svg) ![forks](https://img.shields.io/github/forks/finn79426/CVE-2020-10199.svg)


## CVE-2020-8835
 In the Linux kernel 5.5.0 and newer, the bpf verifier (kernel/bpf/verifier.c) did not properly restrict the register bounds for 32-bit operations, leading to out-of-bounds reads and writes in kernel memory. The vulnerability also affects the Linux 5.4 stable series, starting with v5.4.7, as the introducing commit was backported to that branch. This vulnerability was fixed in 5.6.1, 5.5.14, and 5.4.29. (issue is aka ZDI-CAN-10780)

- [https://github.com/WhatsWrongAndWhy/CVE-2020-8835](https://github.com/WhatsWrongAndWhy/CVE-2020-8835) :  ![starts](https://img.shields.io/github/stars/WhatsWrongAndWhy/CVE-2020-8835.svg) ![forks](https://img.shields.io/github/forks/WhatsWrongAndWhy/CVE-2020-8835.svg)


## CVE-2020-8597
 eap.c in pppd in ppp 2.4.2 through 2.4.8 has an rhostname buffer overflow in the eap_request and eap_response functions.

- [https://github.com/anna-kravets/codeql-buffer-overflow-variant](https://github.com/anna-kravets/codeql-buffer-overflow-variant) :  ![starts](https://img.shields.io/github/stars/anna-kravets/codeql-buffer-overflow-variant.svg) ![forks](https://img.shields.io/github/forks/anna-kravets/codeql-buffer-overflow-variant.svg)


## CVE-2020-7961
 Deserialization of Untrusted Data in Liferay Portal prior to 7.2.1 CE GA2 allows remote attackers to execute arbitrary code via JSON web services (JSONWS).

- [https://github.com/dinosn/liferay-ga4-rce-research](https://github.com/dinosn/liferay-ga4-rce-research) :  ![starts](https://img.shields.io/github/stars/dinosn/liferay-ga4-rce-research.svg) ![forks](https://img.shields.io/github/forks/dinosn/liferay-ga4-rce-research.svg)


## CVE-2020-7882
 Using the parameter of getPFXFolderList function, attackers can see the information of authorization certification and delete the files. It occurs because the parameter contains path traversal characters(ie. '../../../')

- [https://github.com/HORKimhab/CVE-2020-7882](https://github.com/HORKimhab/CVE-2020-7882) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2020-7882.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2020-7882.svg)


## CVE-2020-5148
 SonicWall SSO-agent default configuration uses NetAPI to probe the associated IP's in the network, this client probing method allows a potential attacker to capture the password hash of the privileged user and potentially forces the SSO Agent to authenticate allowing an attacker to bypass firewall access controls.

- [https://github.com/l0lsec/CVE-2020-5148](https://github.com/l0lsec/CVE-2020-5148) :  ![starts](https://img.shields.io/github/stars/l0lsec/CVE-2020-5148.svg) ![forks](https://img.shields.io/github/forks/l0lsec/CVE-2020-5148.svg)


## CVE-2020-3952
 Under certain conditions, vmdir that ships with VMware vCenter Server, as part of an embedded or external Platform Services Controller (PSC), does not correctly implement access controls.

- [https://github.com/virtualcvcell/Exploit](https://github.com/virtualcvcell/Exploit) :  ![starts](https://img.shields.io/github/stars/virtualcvcell/Exploit.svg) ![forks](https://img.shields.io/github/forks/virtualcvcell/Exploit.svg)


## CVE-2020-1957
 Apache Shiro before 1.5.2, when using Apache Shiro with Spring dynamic controllers, a specially crafted request may cause an authentication bypass.

- [https://github.com/xiaoqiMikko/shiro-check](https://github.com/xiaoqiMikko/shiro-check) :  ![starts](https://img.shields.io/github/stars/xiaoqiMikko/shiro-check.svg) ![forks](https://img.shields.io/github/forks/xiaoqiMikko/shiro-check.svg)


## CVE-2020-1472
When the second phase of Windows updates become available in Q1 2021, customers will be notified via a revision to this security vulnerability. If you wish to be notified when these updates are released, we recommend that you register for the security notifications mailer to be alerted of content changes to this advisory. See Microsoft Technical Security Notifications.

- [https://github.com/abdullah50i/internal-penetration-testing-project-using-Metasploit](https://github.com/abdullah50i/internal-penetration-testing-project-using-Metasploit) :  ![starts](https://img.shields.io/github/stars/abdullah50i/internal-penetration-testing-project-using-Metasploit.svg) ![forks](https://img.shields.io/github/forks/abdullah50i/internal-penetration-testing-project-using-Metasploit.svg)


## CVE-2020-0796
 A remote code execution vulnerability exists in the way that the Microsoft Server Message Block 3.1.1 (SMBv3) protocol handles certain requests, aka 'Windows SMBv3 Client/Server Remote Code Execution Vulnerability'.

- [https://github.com/nyambiblaise/Microsoft-Windows-SMBGhost-Vulnerability-Checker---CVE-2020-0796---SMBv3-RCE](https://github.com/nyambiblaise/Microsoft-Windows-SMBGhost-Vulnerability-Checker---CVE-2020-0796---SMBv3-RCE) :  ![starts](https://img.shields.io/github/stars/nyambiblaise/Microsoft-Windows-SMBGhost-Vulnerability-Checker---CVE-2020-0796---SMBv3-RCE.svg) ![forks](https://img.shields.io/github/forks/nyambiblaise/Microsoft-Windows-SMBGhost-Vulnerability-Checker---CVE-2020-0796---SMBv3-RCE.svg)


## CVE-2020-0096
 In startActivities of ActivityStartController.java, there is a possible escalation of privilege due to a confused deputy. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-8.0 Android-8.1 Android-9Android ID: A-145669109

- [https://github.com/hackerronin/CVE-2020-0096-strandhogg-exploit-p0c](https://github.com/hackerronin/CVE-2020-0096-strandhogg-exploit-p0c) :  ![starts](https://img.shields.io/github/stars/hackerronin/CVE-2020-0096-strandhogg-exploit-p0c.svg) ![forks](https://img.shields.io/github/forks/hackerronin/CVE-2020-0096-strandhogg-exploit-p0c.svg)


## CVE-2019-19550
 Remote Authentication Bypass in Senior Rubiweb 6.2.34.28 and 6.2.34.37 allows admin access to sensitive information of affected users using vulnerable versions. The attacker only needs to provide the correct URL.

- [https://github.com/RedTeamBrasil/CVE-2019-19550](https://github.com/RedTeamBrasil/CVE-2019-19550) :  ![starts](https://img.shields.io/github/stars/RedTeamBrasil/CVE-2019-19550.svg) ![forks](https://img.shields.io/github/forks/RedTeamBrasil/CVE-2019-19550.svg)


## CVE-2019-17558
 Apache Solr 5.0.0 to Apache Solr 8.3.1 are vulnerable to a Remote Code Execution through the VelocityResponseWriter. A Velocity template can be provided through Velocity templates in a configset `velocity/` directory or as a parameter. A user defined configset could contain renderable, potentially malicious, templates. Parameter provided templates are disabled by default, but can be enabled by setting `params.resource.loader.enabled` by defining a response writer with that setting set to `true`. Defining a response writer requires configuration API access. Solr 8.4 removed the params resource loader entirely, and only enables the configset-provided template rendering when the configset is `trusted` (has been uploaded by an authenticated user).

- [https://github.com/rogerzeferino/cve-2019-17558-apache-solr-rce](https://github.com/rogerzeferino/cve-2019-17558-apache-solr-rce) :  ![starts](https://img.shields.io/github/stars/rogerzeferino/cve-2019-17558-apache-solr-rce.svg) ![forks](https://img.shields.io/github/forks/rogerzeferino/cve-2019-17558-apache-solr-rce.svg)


## CVE-2019-14287
 In Sudo before 1.8.28, an attacker with access to a Runas ALL sudoer account can bypass certain policy blacklists and session PAM modules, and can cause incorrect logging, by invoking sudo with a crafted user ID. For example, this allows bypass of !root configuration, and USER= logging, for a "sudo -u \#$((0xffffffff))" command.

- [https://github.com/NyxRecon/Sudo-Agent-CTF-](https://github.com/NyxRecon/Sudo-Agent-CTF-) :  ![starts](https://img.shields.io/github/stars/NyxRecon/Sudo-Agent-CTF-.svg) ![forks](https://img.shields.io/github/forks/NyxRecon/Sudo-Agent-CTF-.svg)


## CVE-2019-12840
 In Webmin through 1.910, any user authorized to the "Package Updates" module can execute arbitrary commands with root privileges via the data parameter to update.cgi.

- [https://github.com/note0577/CVE-2019-12840-NodeJs-Exploit](https://github.com/note0577/CVE-2019-12840-NodeJs-Exploit) :  ![starts](https://img.shields.io/github/stars/note0577/CVE-2019-12840-NodeJs-Exploit.svg) ![forks](https://img.shields.io/github/forks/note0577/CVE-2019-12840-NodeJs-Exploit.svg)


## CVE-2019-11043
 In PHP versions 7.1.x below 7.1.33, 7.2.x below 7.2.24 and 7.3.x below 7.3.11 in certain configurations of FPM setup it is possible to cause FPM module to write past allocated buffers into the space reserved for FCGI protocol data, thus opening the possibility of remote code execution.

- [https://github.com/MagentaBear/CVE-2019-11043-Vulnerability](https://github.com/MagentaBear/CVE-2019-11043-Vulnerability) :  ![starts](https://img.shields.io/github/stars/MagentaBear/CVE-2019-11043-Vulnerability.svg) ![forks](https://img.shields.io/github/forks/MagentaBear/CVE-2019-11043-Vulnerability.svg)


## CVE-2019-10392
 Jenkins Git Client Plugin 2.8.4 and earlier and 3.0.0-rc did not properly restrict values passed as URL argument to an invocation of 'git ls-remote', resulting in OS command injection.

- [https://github.com/FortheKahZModan/CVE-2019-10392_EXP](https://github.com/FortheKahZModan/CVE-2019-10392_EXP) :  ![starts](https://img.shields.io/github/stars/FortheKahZModan/CVE-2019-10392_EXP.svg) ![forks](https://img.shields.io/github/forks/FortheKahZModan/CVE-2019-10392_EXP.svg)


## CVE-2019-10070
 Apache Atlas versions 0.8.3 and 1.1.0 were found vulnerable to Stored Cross-Site Scripting in the search functionality

- [https://github.com/PerfectPoH/cve-2019-10070-apache-atlas-xss](https://github.com/PerfectPoH/cve-2019-10070-apache-atlas-xss) :  ![starts](https://img.shields.io/github/stars/PerfectPoH/cve-2019-10070-apache-atlas-xss.svg) ![forks](https://img.shields.io/github/forks/PerfectPoH/cve-2019-10070-apache-atlas-xss.svg)


## CVE-2019-10068
 An issue was discovered in Kentico 12.0.x before 12.0.15, 11.0.x before 11.0.48, 10.0.x before 10.0.52, and 9.x versions. Due to a failure to validate security headers, it was possible for a specially crafted request to the staging service to bypass the initial authentication and proceed to deserialize user-controlled .NET object input. This deserialization then led to unauthenticated remote code execution on the server where the Kentico instance was hosted.

- [https://github.com/cianananan/CVE-2019-10068-PoC](https://github.com/cianananan/CVE-2019-10068-PoC) :  ![starts](https://img.shields.io/github/stars/cianananan/CVE-2019-10068-PoC.svg) ![forks](https://img.shields.io/github/forks/cianananan/CVE-2019-10068-PoC.svg)


## CVE-2019-6977
 gdImageColorMatch in gd_color_match.c in the GD Graphics Library (aka LibGD) 2.2.5, as used in the imagecolormatch function in PHP before 5.6.40, 7.x before 7.1.26, 7.2.x before 7.2.14, and 7.3.x before 7.3.1, has a heap-based buffer overflow. This can be exploited by an attacker who is able to trigger imagecolormatch calls with crafted image data.

- [https://github.com/HORKimhab/CVE-2022-31626-CVE-2024-2961-CVE-2019-6977](https://github.com/HORKimhab/CVE-2022-31626-CVE-2024-2961-CVE-2019-6977) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2022-31626-CVE-2024-2961-CVE-2019-6977.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2022-31626-CVE-2024-2961-CVE-2019-6977.svg)


## CVE-2019-5392
 A disclosure of information vulnerability was identified in HPE Intelligent Management Center (IMC) PLAT earlier than version 7.3 E0506P09.

- [https://github.com/jozliner/CVE-2019-5392-for-Python3](https://github.com/jozliner/CVE-2019-5392-for-Python3) :  ![starts](https://img.shields.io/github/stars/jozliner/CVE-2019-5392-for-Python3.svg) ![forks](https://img.shields.io/github/forks/jozliner/CVE-2019-5392-for-Python3.svg)


## CVE-2019-2215
 A use-after-free in binder.c allows an elevation of privilege from an application to the Linux Kernel. No user interaction is required to exploit this vulnerability, however exploitation does require either the installation of a malicious local application or a separate vulnerability in a network facing application.Product: AndroidAndroid ID: A-141720095

- [https://github.com/NESTle19/CVE-2019-2215](https://github.com/NESTle19/CVE-2019-2215) :  ![starts](https://img.shields.io/github/stars/NESTle19/CVE-2019-2215.svg) ![forks](https://img.shields.io/github/forks/NESTle19/CVE-2019-2215.svg)


## CVE-2019-1749
 A vulnerability in the ingress traffic validation of Cisco IOS XE Software for Cisco Aggregation Services Router (ASR) 900 Route Switch Processor 3 (RSP3) could allow an unauthenticated, adjacent attacker to trigger a reload of an affected device, resulting in a denial of service (DoS) condition. The vulnerability exists because the software insufficiently validates ingress traffic on the ASIC used on the RSP3 platform. An attacker could exploit this vulnerability by sending a malformed OSPF version 2 (OSPFv2) message to an affected device. A successful exploit could allow the attacker to cause a reload of the iosd process, triggering a reload of the affected device and resulting in a DoS condition.

- [https://github.com/delbertgiovanni/test-xss-swagger-CVE-2019-1749](https://github.com/delbertgiovanni/test-xss-swagger-CVE-2019-1749) :  ![starts](https://img.shields.io/github/stars/delbertgiovanni/test-xss-swagger-CVE-2019-1749.svg) ![forks](https://img.shields.io/github/forks/delbertgiovanni/test-xss-swagger-CVE-2019-1749.svg)


## CVE-2019-1388
 An elevation of privilege vulnerability exists in the Windows Certificate Dialog when it does not properly enforce user privileges, aka 'Windows Certificate Dialog Elevation of Privilege Vulnerability'.

- [https://github.com/Tafloh/CVE-2019-1388-Privilege-Escalation--2021-](https://github.com/Tafloh/CVE-2019-1388-Privilege-Escalation--2021-) :  ![starts](https://img.shields.io/github/stars/Tafloh/CVE-2019-1388-Privilege-Escalation--2021-.svg) ![forks](https://img.shields.io/github/forks/Tafloh/CVE-2019-1388-Privilege-Escalation--2021-.svg)


## CVE-2018-19207
 The Van Ons WP GDPR Compliance (aka wp-gdpr-compliance) plugin before 1.4.3 for WordPress allows remote attackers to execute arbitrary code because $wpdb-prepare() input is mishandled, as exploited in the wild in November 2018.

- [https://github.com/AnotherSec/CVE-2018-19207](https://github.com/AnotherSec/CVE-2018-19207) :  ![starts](https://img.shields.io/github/stars/AnotherSec/CVE-2018-19207.svg) ![forks](https://img.shields.io/github/forks/AnotherSec/CVE-2018-19207.svg)


## CVE-2018-18955
 In the Linux kernel 4.15.x through 4.19.x before 4.19.2, map_write() in kernel/user_namespace.c allows privilege escalation because it mishandles nested user namespaces with more than 5 UID or GID ranges. A user who has CAP_SYS_ADMIN in an affected user namespace can bypass access controls on resources outside the namespace, as demonstrated by reading /etc/shadow. This occurs because an ID transformation takes place properly for the namespaced-to-kernel direction but not for the kernel-to-namespaced direction.

- [https://github.com/WhatsWrongAndWhy/CVE-2018-18955](https://github.com/WhatsWrongAndWhy/CVE-2018-18955) :  ![starts](https://img.shields.io/github/stars/WhatsWrongAndWhy/CVE-2018-18955.svg) ![forks](https://img.shields.io/github/forks/WhatsWrongAndWhy/CVE-2018-18955.svg)


## CVE-2018-16763
 FUEL CMS 1.4.1 allows PHP Code Evaluation via the pages/select/ filter parameter or the preview/ data parameter. This can lead to Pre-Auth Remote Code Execution.

- [https://github.com/ShadowR-Root/fuel-cms-cve-2018-16763-python3-port](https://github.com/ShadowR-Root/fuel-cms-cve-2018-16763-python3-port) :  ![starts](https://img.shields.io/github/stars/ShadowR-Root/fuel-cms-cve-2018-16763-python3-port.svg) ![forks](https://img.shields.io/github/forks/ShadowR-Root/fuel-cms-cve-2018-16763-python3-port.svg)


## CVE-2018-15473
 OpenSSH through 7.7 is prone to a user enumeration vulnerability due to not delaying bailout for an invalid authenticating user until after the packet containing the request has been fully parsed, related to auth2-gss.c, auth2-hostbased.c, and auth2-pubkey.c.

- [https://github.com/bdalrhmnhamdalalm-jpg/CVE-2018-15473-User-Enumeration-](https://github.com/bdalrhmnhamdalalm-jpg/CVE-2018-15473-User-Enumeration-) :  ![starts](https://img.shields.io/github/stars/bdalrhmnhamdalalm-jpg/CVE-2018-15473-User-Enumeration-.svg) ![forks](https://img.shields.io/github/forks/bdalrhmnhamdalalm-jpg/CVE-2018-15473-User-Enumeration-.svg)


## CVE-2018-13379
 An Improper Limitation of a Pathname to a Restricted Directory ("Path Traversal") in Fortinet FortiOS 6.0.0 to 6.0.4, 5.6.3 to 5.6.7 and 5.4.6 to 5.4.12 and FortiProxy 2.0.0, 1.2.0 to 1.2.8, 1.1.0 to 1.1.6, 1.0.0 to 1.0.7 under SSL VPN web portal allows an unauthenticated attacker to download system files via special crafted HTTP resource requests.

- [https://github.com/Vampsecure-Labs/vamp-forticheck](https://github.com/Vampsecure-Labs/vamp-forticheck) :  ![starts](https://img.shields.io/github/stars/Vampsecure-Labs/vamp-forticheck.svg) ![forks](https://img.shields.io/github/forks/Vampsecure-Labs/vamp-forticheck.svg)


## CVE-2018-10057
 The remote management interface of cgminer 4.10.0 and bfgminer 5.5.0 allows an authenticated remote attacker to write the miner configuration file to arbitrary locations on the server due to missing basedir restrictions (absolute directory traversal).

- [https://github.com/tintinweb/pub](https://github.com/tintinweb/pub) :  ![starts](https://img.shields.io/github/stars/tintinweb/pub.svg) ![forks](https://img.shields.io/github/forks/tintinweb/pub.svg)


## CVE-2018-9995
 TBK DVR4104 and DVR4216 devices, as well as Novo, CeNova, QSee, Pulnix, XVR 5 in 1, Securus, Night OWL, DVR Login, HVR Login, and MDVR Login, which run re-branded versions of the original TBK DVR4104 and DVR4216 series, allow remote attackers to bypass authentication via a "Cookie: uid=admin" header, as demonstrated by a device.rsp?opt=user&cmd=list request that provides credentials within JSON data in a response.

- [https://github.com/F7P-H4NN1B4L/CVE-2018-9995-DVR-Credentials-Extractor](https://github.com/F7P-H4NN1B4L/CVE-2018-9995-DVR-Credentials-Extractor) :  ![starts](https://img.shields.io/github/stars/F7P-H4NN1B4L/CVE-2018-9995-DVR-Credentials-Extractor.svg) ![forks](https://img.shields.io/github/forks/F7P-H4NN1B4L/CVE-2018-9995-DVR-Credentials-Extractor.svg)


## CVE-2018-9276
 An issue was discovered in PRTG Network Monitor before 18.2.39. An attacker who has access to the PRTG System Administrator web console with administrative privileges can exploit an OS command injection vulnerability (both on the server and on devices) by sending malformed parameters in sensor or notification management scenarios.

- [https://github.com/BardLaudian/CVE-2018-9276](https://github.com/BardLaudian/CVE-2018-9276) :  ![starts](https://img.shields.io/github/stars/BardLaudian/CVE-2018-9276.svg) ![forks](https://img.shields.io/github/forks/BardLaudian/CVE-2018-9276.svg)


## CVE-2018-7600
 Drupal before 7.58, 8.x before 8.3.9, 8.4.x before 8.4.6, and 8.5.x before 8.5.1 allows remote attackers to execute arbitrary code because of an issue affecting multiple subsystems with default or common module configurations.

- [https://github.com/Prapul1/VulnHub-DC1-Writeup](https://github.com/Prapul1/VulnHub-DC1-Writeup) :  ![starts](https://img.shields.io/github/stars/Prapul1/VulnHub-DC1-Writeup.svg) ![forks](https://img.shields.io/github/forks/Prapul1/VulnHub-DC1-Writeup.svg)
- [https://github.com/Shams-Ul-Mehmood/CVE-2018-7600-Drupalgeddon2-RCE](https://github.com/Shams-Ul-Mehmood/CVE-2018-7600-Drupalgeddon2-RCE) :  ![starts](https://img.shields.io/github/stars/Shams-Ul-Mehmood/CVE-2018-7600-Drupalgeddon2-RCE.svg) ![forks](https://img.shields.io/github/forks/Shams-Ul-Mehmood/CVE-2018-7600-Drupalgeddon2-RCE.svg)


## CVE-2018-6574
 Go before 1.8.7, Go 1.9.x before 1.9.4, and Go 1.10 pre-releases before Go 1.10rc2 allow "go get" remote command execution during source code build, by leveraging the gcc or clang plugin feature, because -fplugin= and -plugin= arguments were not blocked.

- [https://github.com/s-p4rk/CVE-2018-6574](https://github.com/s-p4rk/CVE-2018-6574) :  ![starts](https://img.shields.io/github/stars/s-p4rk/CVE-2018-6574.svg) ![forks](https://img.shields.io/github/forks/s-p4rk/CVE-2018-6574.svg)


## CVE-2018-5333
 In the Linux kernel through 4.14.13, the rds_cmsg_atomic function in net/rds/rdma.c mishandles cases where page pinning fails or an invalid address is supplied, leading to an rds_atomic_free_op NULL pointer dereference.

- [https://github.com/WhatsWrongAndWhy/CVE-2018-5333](https://github.com/WhatsWrongAndWhy/CVE-2018-5333) :  ![starts](https://img.shields.io/github/stars/WhatsWrongAndWhy/CVE-2018-5333.svg) ![forks](https://img.shields.io/github/forks/WhatsWrongAndWhy/CVE-2018-5333.svg)


## CVE-2017-1000112
 Linux kernel: Exploitable memory corruption due to UFO to non-UFO path switch. When building a UFO packet with MSG_MORE __ip_append_data() calls ip_ufo_append_data() to append. However in between two send() calls, the append path can be switched from UFO to non-UFO one, which leads to a memory corruption. In case UFO packet lengths exceeds MTU, copy = maxfraglen - skb-len becomes negative on the non-UFO path and the branch to allocate new skb is taken. This triggers fragmentation and computation of fraggap = skb_prev-len - maxfraglen. Fraggap can exceed MTU, causing copy = datalen - transhdrlen - fraggap to become negative. Subsequently skb_copy_and_csum_bits() writes out-of-bounds. A similar issue is present in IPv6 code. The bug was introduced in e89e9cf539a2 ("[IPv4/IPv6]: UFO Scatter-gather approach") on Oct 18 2005.

- [https://github.com/WhatsWrongAndWhy/CVE-2017-1000112](https://github.com/WhatsWrongAndWhy/CVE-2017-1000112) :  ![starts](https://img.shields.io/github/stars/WhatsWrongAndWhy/CVE-2017-1000112.svg) ![forks](https://img.shields.io/github/forks/WhatsWrongAndWhy/CVE-2017-1000112.svg)


## CVE-2017-16995
 The check_alu_op function in kernel/bpf/verifier.c in the Linux kernel through 4.4 allows local users to cause a denial of service (memory corruption) or possibly have unspecified other impact by leveraging incorrect sign extension.

- [https://github.com/WhatsWrongAndWhy/CVE-2017-16995](https://github.com/WhatsWrongAndWhy/CVE-2017-16995) :  ![starts](https://img.shields.io/github/stars/WhatsWrongAndWhy/CVE-2017-16995.svg) ![forks](https://img.shields.io/github/forks/WhatsWrongAndWhy/CVE-2017-16995.svg)


## CVE-2017-14980
 Buffer overflow in Sync Breeze Enterprise 10.0.28 allows remote attackers to have unspecified impact via a long username parameter to /login.

- [https://github.com/godoy-sec/CVE-2017-14980](https://github.com/godoy-sec/CVE-2017-14980) :  ![starts](https://img.shields.io/github/stars/godoy-sec/CVE-2017-14980.svg) ![forks](https://img.shields.io/github/forks/godoy-sec/CVE-2017-14980.svg)


## CVE-2017-13156
 An elevation of privilege vulnerability in the Android system (art). Product: Android. Versions: 5.1.1, 6.0, 6.0.1, 7.0, 7.1.1, 7.1.2, 8.0. Android ID A-64211847.

- [https://github.com/hackerronin/Janus-Vulnerability-CVE-2017-13156-Exploit](https://github.com/hackerronin/Janus-Vulnerability-CVE-2017-13156-Exploit) :  ![starts](https://img.shields.io/github/stars/hackerronin/Janus-Vulnerability-CVE-2017-13156-Exploit.svg) ![forks](https://img.shields.io/github/forks/hackerronin/Janus-Vulnerability-CVE-2017-13156-Exploit.svg)


## CVE-2017-12636
 CouchDB administrative users can configure the database server via HTTP(S). Some of the configuration options include paths for operating system-level binaries that are subsequently launched by CouchDB. This allows an admin user in Apache CouchDB before 1.7.0 and 2.x before 2.1.1 to execute arbitrary shell commands as the CouchDB user, including downloading and executing scripts from the public internet.

- [https://github.com/Darabium/couchdb-exploit](https://github.com/Darabium/couchdb-exploit) :  ![starts](https://img.shields.io/github/stars/Darabium/couchdb-exploit.svg) ![forks](https://img.shields.io/github/forks/Darabium/couchdb-exploit.svg)


## CVE-2017-12635
 Due to differences in the Erlang-based JSON parser and JavaScript-based JSON parser, it is possible in Apache CouchDB before 1.7.0 and 2.x before 2.1.1 to submit _users documents with duplicate keys for 'roles' used for access control within the database, including the special case '_admin' role, that denotes administrative users. In combination with CVE-2017-12636 (Remote Code Execution), this can be used to give non-admin users access to arbitrary shell commands on the server as the database system user. The JSON parser differences result in behaviour that if two 'roles' keys are available in the JSON, the second one will be used for authorising the document write, but the first 'roles' key is used for subsequent authorization for the newly created user. By design, users can not assign themselves roles. The vulnerability allows non-admin users to give themselves admin privileges.

- [https://github.com/Darabium/couchdb-exploit](https://github.com/Darabium/couchdb-exploit) :  ![starts](https://img.shields.io/github/stars/Darabium/couchdb-exploit.svg) ![forks](https://img.shields.io/github/forks/Darabium/couchdb-exploit.svg)


## CVE-2017-9805
 The REST Plugin in Apache Struts 2.1.1 through 2.3.x before 2.3.34 and 2.5.x before 2.5.13 uses an XStreamHandler with an instance of XStream for deserialization without any type filtering, which can lead to Remote Code Execution when deserializing XML payloads.

- [https://github.com/agent3137/CVE-2017-9805-Exploit](https://github.com/agent3137/CVE-2017-9805-Exploit) :  ![starts](https://img.shields.io/github/stars/agent3137/CVE-2017-9805-Exploit.svg) ![forks](https://img.shields.io/github/forks/agent3137/CVE-2017-9805-Exploit.svg)


## CVE-2017-9757
 IPFire 2.19 has a Remote Command Injection vulnerability in ids.cgi via the OINKCODE parameter, which is mishandled by a shell. This can be exploited directly by authenticated users, or through CSRF.

- [https://github.com/joaoaugustom/IPFire_2.19_RCE_Authenticated](https://github.com/joaoaugustom/IPFire_2.19_RCE_Authenticated) :  ![starts](https://img.shields.io/github/stars/joaoaugustom/IPFire_2.19_RCE_Authenticated.svg) ![forks](https://img.shields.io/github/forks/joaoaugustom/IPFire_2.19_RCE_Authenticated.svg)


## CVE-2017-8890
 The inet_csk_clone_lock function in net/ipv4/inet_connection_sock.c in the Linux kernel through 4.10.15 allows attackers to cause a denial of service (double free) or possibly have unspecified other impact by leveraging use of the accept system call.

- [https://github.com/sweatyrocket/huawei-p10-cve-2017-8890-unlock](https://github.com/sweatyrocket/huawei-p10-cve-2017-8890-unlock) :  ![starts](https://img.shields.io/github/stars/sweatyrocket/huawei-p10-cve-2017-8890-unlock.svg) ![forks](https://img.shields.io/github/forks/sweatyrocket/huawei-p10-cve-2017-8890-unlock.svg)


## CVE-2017-8464
 Windows Shell in Microsoft Windows Server 2008 SP2 and R2 SP1, Windows 7 SP1, Windows 8, Windows 8.1, Windows Server 2012 Gold and R2, Windows RT 8.1, Windows 10 Gold, 1511, 1607, 1703, and Windows Server 2016 allows local users or remote attackers to execute arbitrary code via a crafted .LNK file, which is not properly handled during icon display in Windows Explorer or any other application that parses the icon of the shortcut. aka "LNK Remote Code Execution Vulnerability."

- [https://github.com/PlayBoiSK8/POC-CVE-2017-8464-OpenCalculator](https://github.com/PlayBoiSK8/POC-CVE-2017-8464-OpenCalculator) :  ![starts](https://img.shields.io/github/stars/PlayBoiSK8/POC-CVE-2017-8464-OpenCalculator.svg) ![forks](https://img.shields.io/github/forks/PlayBoiSK8/POC-CVE-2017-8464-OpenCalculator.svg)


## CVE-2017-8046
 Malicious PATCH requests submitted to servers using Spring Data REST versions prior to 2.6.9 (Ingalls SR9), versions prior to 3.0.1 (Kay SR1) and Spring Boot versions prior to 1.5.9, 2.0 M6 can use specially crafted JSON data to run arbitrary Java code.

- [https://github.com/lgtm-migrator/CVE-2017-8046-DEMO](https://github.com/lgtm-migrator/CVE-2017-8046-DEMO) :  ![starts](https://img.shields.io/github/stars/lgtm-migrator/CVE-2017-8046-DEMO.svg) ![forks](https://img.shields.io/github/forks/lgtm-migrator/CVE-2017-8046-DEMO.svg)


## CVE-2017-7921
 An Improper Authentication issue was discovered in Hikvision DS-2CD2xx2F-I Series V5.2.0 build 140721 to V5.4.0 build 160530, DS-2CD2xx0F-I Series V5.2.0 build 140721 to V5.4.0 Build 160401, DS-2CD2xx2FWD Series V5.3.1 build 150410 to V5.4.4 Build 161125, DS-2CD4x2xFWD Series V5.2.0 build 140721 to V5.4.0 Build 160414, DS-2CD4xx5 Series V5.2.0 build 140721 to V5.4.0 Build 160421, DS-2DFx Series V5.2.0 build 140805 to V5.4.5 Build 160928, and DS-2CD63xx Series V5.0.9 build 140305 to V5.3.5 Build 160106 devices. The improper authentication vulnerability occurs when an application does not adequately or correctly authenticate users. This may allow a malicious user to escalate his or her privileges on the system and gain access to sensitive information.

- [https://github.com/xjghnxhlh/hikihack](https://github.com/xjghnxhlh/hikihack) :  ![starts](https://img.shields.io/github/stars/xjghnxhlh/hikihack.svg) ![forks](https://img.shields.io/github/forks/xjghnxhlh/hikihack.svg)
- [https://github.com/blacksheepstudio/CVE-2017-7921-EXP](https://github.com/blacksheepstudio/CVE-2017-7921-EXP) :  ![starts](https://img.shields.io/github/stars/blacksheepstudio/CVE-2017-7921-EXP.svg) ![forks](https://img.shields.io/github/forks/blacksheepstudio/CVE-2017-7921-EXP.svg)


## CVE-2017-7529
 Nginx versions since 0.5.6 up to and including 1.13.2 are vulnerable to integer overflow vulnerability in nginx range filter module resulting into leak of potentially sensitive information triggered by specially crafted request.

- [https://github.com/SirEagIe/CVE-2017-7529](https://github.com/SirEagIe/CVE-2017-7529) :  ![starts](https://img.shields.io/github/stars/SirEagIe/CVE-2017-7529.svg) ![forks](https://img.shields.io/github/forks/SirEagIe/CVE-2017-7529.svg)


## CVE-2017-7494
 Samba since version 3.5.0 and before 4.6.4, 4.5.10 and 4.4.14 is vulnerable to remote code execution vulnerability, allowing a malicious client to upload a shared library to a writable share, and then cause the server to load and execute it.

- [https://github.com/YonLiud/CVE-2017-7494](https://github.com/YonLiud/CVE-2017-7494) :  ![starts](https://img.shields.io/github/stars/YonLiud/CVE-2017-7494.svg) ![forks](https://img.shields.io/github/forks/YonLiud/CVE-2017-7494.svg)


## CVE-2017-7308
 The packet_set_ring function in net/packet/af_packet.c in the Linux kernel through 4.10.6 does not properly validate certain block-size data, which allows local users to cause a denial of service (integer signedness error and out-of-bounds write), or gain privileges (if the CAP_NET_RAW capability is held), via crafted system calls.

- [https://github.com/WhatsWrongAndWhy/CVE-2017-7308](https://github.com/WhatsWrongAndWhy/CVE-2017-7308) :  ![starts](https://img.shields.io/github/stars/WhatsWrongAndWhy/CVE-2017-7308.svg) ![forks](https://img.shields.io/github/forks/WhatsWrongAndWhy/CVE-2017-7308.svg)


## CVE-2017-0781
 A remote code execution vulnerability in the Android system (bluetooth). Product: Android. Versions: 4.4.4, 5.0.2, 5.1.1, 6.0, 6.0.1, 7.0, 7.1.1, 7.1.2, 8.0. Android ID: A-63146105.

- [https://github.com/x3ero0/android712-blueborne](https://github.com/x3ero0/android712-blueborne) :  ![starts](https://img.shields.io/github/stars/x3ero0/android712-blueborne.svg) ![forks](https://img.shields.io/github/forks/x3ero0/android712-blueborne.svg)


## CVE-2017-0144
 The SMBv1 server in Microsoft Windows Vista SP2; Windows Server 2008 SP2 and R2 SP1; Windows 7 SP1; Windows 8.1; Windows Server 2012 Gold and R2; Windows RT 8.1; and Windows 10 Gold, 1511, and 1607; and Windows Server 2016 allows remote attackers to execute arbitrary code via crafted packets, aka "Windows SMB Remote Code Execution Vulnerability." This vulnerability is different from those described in CVE-2017-0143, CVE-2017-0145, CVE-2017-0146, and CVE-2017-0148.

- [https://github.com/probablysecure/Triage-CVE-2017-0144](https://github.com/probablysecure/Triage-CVE-2017-0144) :  ![starts](https://img.shields.io/github/stars/probablysecure/Triage-CVE-2017-0144.svg) ![forks](https://img.shields.io/github/forks/probablysecure/Triage-CVE-2017-0144.svg)
- [https://github.com/KitSkater/legacyshield-CVE-2017-0144](https://github.com/KitSkater/legacyshield-CVE-2017-0144) :  ![starts](https://img.shields.io/github/stars/KitSkater/legacyshield-CVE-2017-0144.svg) ![forks](https://img.shields.io/github/forks/KitSkater/legacyshield-CVE-2017-0144.svg)


## CVE-2016-10033
 The mailSend function in the isMail transport in PHPMailer before 5.2.18 might allow remote attackers to pass extra parameters to the mail command and consequently execute arbitrary code via a \" (backslash double quote) in a crafted Sender property.

- [https://github.com/blue-chocolates/CVE-2016-10033](https://github.com/blue-chocolates/CVE-2016-10033) :  ![starts](https://img.shields.io/github/stars/blue-chocolates/CVE-2016-10033.svg) ![forks](https://img.shields.io/github/forks/blue-chocolates/CVE-2016-10033.svg)


## CVE-2016-5195
 Race condition in mm/gup.c in the Linux kernel 2.x through 4.x before 4.8.3 allows local users to gain privileges by leveraging incorrect handling of a copy-on-write (COW) feature to write to a read-only memory mapping, as exploited in the wild in October 2016, aka "Dirty COW."

- [https://github.com/gogooma125732/CVE-2016-5195](https://github.com/gogooma125732/CVE-2016-5195) :  ![starts](https://img.shields.io/github/stars/gogooma125732/CVE-2016-5195.svg) ![forks](https://img.shields.io/github/forks/gogooma125732/CVE-2016-5195.svg)
- [https://github.com/h1n4mx0z/Research-CVE-2016-5195](https://github.com/h1n4mx0z/Research-CVE-2016-5195) :  ![starts](https://img.shields.io/github/stars/h1n4mx0z/Research-CVE-2016-5195.svg) ![forks](https://img.shields.io/github/forks/h1n4mx0z/Research-CVE-2016-5195.svg)
- [https://github.com/voidgguy/lenovo-a1000g-mt8317-A412_01_09_130907-kernel-3.4.0-root-cve-2016-5195](https://github.com/voidgguy/lenovo-a1000g-mt8317-A412_01_09_130907-kernel-3.4.0-root-cve-2016-5195) :  ![starts](https://img.shields.io/github/stars/voidgguy/lenovo-a1000g-mt8317-A412_01_09_130907-kernel-3.4.0-root-cve-2016-5195.svg) ![forks](https://img.shields.io/github/forks/voidgguy/lenovo-a1000g-mt8317-A412_01_09_130907-kernel-3.4.0-root-cve-2016-5195.svg)


## CVE-2016-4437
 Apache Shiro before 1.2.5, when a cipher key has not been configured for the "remember me" feature, allows remote attackers to execute arbitrary code or bypass intended access restrictions via an unspecified request parameter.

- [https://github.com/xiaoqiMikko/shiro-check](https://github.com/xiaoqiMikko/shiro-check) :  ![starts](https://img.shields.io/github/stars/xiaoqiMikko/shiro-check.svg) ![forks](https://img.shields.io/github/forks/xiaoqiMikko/shiro-check.svg)


## CVE-2015-1328
 The overlayfs implementation in the linux (aka Linux kernel) package before 3.19.0-21.21 in Ubuntu through 15.04 does not properly check permissions for file creation in the upper filesystem directory, which allows local users to obtain root access by leveraging a configuration in which overlayfs is permitted in an arbitrary mount namespace.

- [https://github.com/FernandoCassioDev/CVE-2015-1328](https://github.com/FernandoCassioDev/CVE-2015-1328) :  ![starts](https://img.shields.io/github/stars/FernandoCassioDev/CVE-2015-1328.svg) ![forks](https://img.shields.io/github/forks/FernandoCassioDev/CVE-2015-1328.svg)
- [https://github.com/bansalkrish007-arch/cve-2015-1328](https://github.com/bansalkrish007-arch/cve-2015-1328) :  ![starts](https://img.shields.io/github/stars/bansalkrish007-arch/cve-2015-1328.svg) ![forks](https://img.shields.io/github/forks/bansalkrish007-arch/cve-2015-1328.svg)


## CVE-2014-6271
 GNU Bash through 4.3 processes trailing strings after function definitions in the values of environment variables, which allows remote attackers to execute arbitrary code via a crafted environment, as demonstrated by vectors involving the ForceCommand feature in OpenSSH sshd, the mod_cgi and mod_cgid modules in the Apache HTTP Server, scripts executed by unspecified DHCP clients, and other situations in which setting the environment occurs across a privilege boundary from Bash execution, aka "ShellShock."  NOTE: the original fix for this issue was incorrect; CVE-2014-7169 has been assigned to cover the vulnerability that is still present after the incorrect fix.

- [https://github.com/FREEGUY-6/dmz-security-monitoring-hardening](https://github.com/FREEGUY-6/dmz-security-monitoring-hardening) :  ![starts](https://img.shields.io/github/stars/FREEGUY-6/dmz-security-monitoring-hardening.svg) ![forks](https://img.shields.io/github/forks/FREEGUY-6/dmz-security-monitoring-hardening.svg)


## CVE-2014-4688
 pfSense before 2.1.4 allows remote authenticated users to execute arbitrary commands via (1) the hostname value to diag_dns.php in a Create Alias action, (2) the smartmonemail value to diag_smart.php, or (3) the database value to status_rrd_graph_img.php.

- [https://github.com/note0577/CVE-2014-4688-NodeJs-Exploit](https://github.com/note0577/CVE-2014-4688-NodeJs-Exploit) :  ![starts](https://img.shields.io/github/stars/note0577/CVE-2014-4688-NodeJs-Exploit.svg) ![forks](https://img.shields.io/github/forks/note0577/CVE-2014-4688-NodeJs-Exploit.svg)


## CVE-2014-0160
 The (1) TLS and (2) DTLS implementations in OpenSSL 1.0.1 before 1.0.1g do not properly handle Heartbeat Extension packets, which allows remote attackers to obtain sensitive information from process memory via crafted packets that trigger a buffer over-read, as demonstrated by reading private keys, related to d1_both.c and t1_lib.c, aka the Heartbleed bug.

- [https://github.com/tungduongNT/CVE-2014-0160.](https://github.com/tungduongNT/CVE-2014-0160.) :  ![starts](https://img.shields.io/github/stars/tungduongNT/CVE-2014-0160..svg) ![forks](https://img.shields.io/github/forks/tungduongNT/CVE-2014-0160..svg)


## CVE-2013-3900
Exploitation of this vulnerability requires that a user or application run or install a specially crafted, signed PE file. An attacker could modify an... See more at https://msrc.microsoft.com/update-guide/vulnerability/CVE-2013-3900

- [https://github.com/kingsrule50/nessus-vulnerability-scanning-lab](https://github.com/kingsrule50/nessus-vulnerability-scanning-lab) :  ![starts](https://img.shields.io/github/stars/kingsrule50/nessus-vulnerability-scanning-lab.svg) ![forks](https://img.shields.io/github/forks/kingsrule50/nessus-vulnerability-scanning-lab.svg)


## CVE-2012-1823
 sapi/cgi/cgi_main.c in PHP before 5.3.12 and 5.4.x before 5.4.2, when configured as a CGI script (aka php-cgi), does not properly handle query strings that lack an = (equals sign) character, which allows remote attackers to execute arbitrary code by placing command-line options in the query string, related to lack of skipping a certain php_getopt for the 'd' case.

- [https://github.com/tanasescualexandrugabriel/Vulnerability-Assessment-and-OSINT-CVE-2012-1823](https://github.com/tanasescualexandrugabriel/Vulnerability-Assessment-and-OSINT-CVE-2012-1823) :  ![starts](https://img.shields.io/github/stars/tanasescualexandrugabriel/Vulnerability-Assessment-and-OSINT-CVE-2012-1823.svg) ![forks](https://img.shields.io/github/forks/tanasescualexandrugabriel/Vulnerability-Assessment-and-OSINT-CVE-2012-1823.svg)


## CVE-2011-2523
 vsftpd 2.3.4 downloaded between 20110630 and 20110703 contains a backdoor which opens a shell on port 6200/tcp.

- [https://github.com/alexojocyber/cve-2011-2523-vsftpd-validation-lab](https://github.com/alexojocyber/cve-2011-2523-vsftpd-validation-lab) :  ![starts](https://img.shields.io/github/stars/alexojocyber/cve-2011-2523-vsftpd-validation-lab.svg) ![forks](https://img.shields.io/github/forks/alexojocyber/cve-2011-2523-vsftpd-validation-lab.svg)
- [https://github.com/sonalisarkar-2003/FTP-vsFTPD-CVE-2011-2523-VAPT-Report](https://github.com/sonalisarkar-2003/FTP-vsFTPD-CVE-2011-2523-VAPT-Report) :  ![starts](https://img.shields.io/github/stars/sonalisarkar-2003/FTP-vsFTPD-CVE-2011-2523-VAPT-Report.svg) ![forks](https://img.shields.io/github/forks/sonalisarkar-2003/FTP-vsFTPD-CVE-2011-2523-VAPT-Report.svg)
- [https://github.com/IrsaAttiqueCyber/SystemVulnerabilityChecklist_Project4_Decodelabs](https://github.com/IrsaAttiqueCyber/SystemVulnerabilityChecklist_Project4_Decodelabs) :  ![starts](https://img.shields.io/github/stars/IrsaAttiqueCyber/SystemVulnerabilityChecklist_Project4_Decodelabs.svg) ![forks](https://img.shields.io/github/forks/IrsaAttiqueCyber/SystemVulnerabilityChecklist_Project4_Decodelabs.svg)
- [https://github.com/khalilu020/offensive-security-adversary-emulation](https://github.com/khalilu020/offensive-security-adversary-emulation) :  ![starts](https://img.shields.io/github/stars/khalilu020/offensive-security-adversary-emulation.svg) ![forks](https://img.shields.io/github/forks/khalilu020/offensive-security-adversary-emulation.svg)


## CVE-2011-1571
 Unspecified vulnerability in the XSL Content portlet in Liferay Portal Community Edition (CE) 5.x and 6.x before 6.0.6 GA, when Apache Tomcat is used, allows remote attackers to execute arbitrary commands via unknown vectors.

- [https://github.com/yazgx97/CVE-2011-1571](https://github.com/yazgx97/CVE-2011-1571) :  ![starts](https://img.shields.io/github/stars/yazgx97/CVE-2011-1571.svg) ![forks](https://img.shields.io/github/forks/yazgx97/CVE-2011-1571.svg)


## CVE-2009-4496
 Boa 0.94.14rc21 writes data to a log file without sanitizing non-printable characters, which might allow remote attackers to modify a window's title, or possibly execute arbitrary commands or overwrite files, via an HTTP request containing an escape sequence for a terminal emulator.

- [https://github.com/enriquenegri-cyberlaw/boa-cve-2009-4496-analysis](https://github.com/enriquenegri-cyberlaw/boa-cve-2009-4496-analysis) :  ![starts](https://img.shields.io/github/stars/enriquenegri-cyberlaw/boa-cve-2009-4496-analysis.svg) ![forks](https://img.shields.io/github/forks/enriquenegri-cyberlaw/boa-cve-2009-4496-analysis.svg)


## CVE-2007-2447
 The MS-RPC functionality in smbd in Samba 3.0.0 through 3.0.25rc3 allows remote attackers to execute arbitrary commands via shell metacharacters involving the (1) SamrChangePassword function, when the "username map script" smb.conf option is enabled, and allows remote authenticated users to execute commands via shell metacharacters involving other MS-RPC functions in the (2) remote printer and (3) file share management.

- [https://github.com/harshiys/CVE-2007-2447-Exploitation-SIEM-Detection-Lab](https://github.com/harshiys/CVE-2007-2447-Exploitation-SIEM-Detection-Lab) :  ![starts](https://img.shields.io/github/stars/harshiys/CVE-2007-2447-Exploitation-SIEM-Detection-Lab.svg) ![forks](https://img.shields.io/github/forks/harshiys/CVE-2007-2447-Exploitation-SIEM-Detection-Lab.svg)
- [https://github.com/Mboatella25/metasploitable-pentest-lab](https://github.com/Mboatella25/metasploitable-pentest-lab) :  ![starts](https://img.shields.io/github/stars/Mboatella25/metasploitable-pentest-lab.svg) ![forks](https://img.shields.io/github/forks/Mboatella25/metasploitable-pentest-lab.svg)


## CVE-2006-3392
 Webmin before 1.290 and Usermin before 1.220 calls the simplify_path function before decoding HTML, which allows remote attackers to read arbitrary files, as demonstrated using "..%01" sequences, which bypass the removal of "../" sequences before bytes such as "%01" are removed from the filename.  NOTE: This is a different issue than CVE-2006-3274.

- [https://github.com/Adel-hx0d/CVE-2006-3392](https://github.com/Adel-hx0d/CVE-2006-3392) :  ![starts](https://img.shields.io/github/stars/Adel-hx0d/CVE-2006-3392.svg) ![forks](https://img.shields.io/github/forks/Adel-hx0d/CVE-2006-3392.svg)


## CVE-2003-0201
 Buffer overflow in the call_trans2open function in trans2.c for Samba 2.2.x before 2.2.8a, 2.0.10 and earlier 2.0.x versions, and Samba-TNG before 0.3.2, allows remote attackers to execute arbitrary code.

- [https://github.com/americooo/pentest-writeups](https://github.com/americooo/pentest-writeups) :  ![starts](https://img.shields.io/github/stars/americooo/pentest-writeups.svg) ![forks](https://img.shields.io/github/forks/americooo/pentest-writeups.svg)


## CVE-1999-0524
 ICMP information such as (1) netmask and (2) timestamp is allowed from arbitrary hosts.

- [https://github.com/biontdv/CVE-1999-0524-POC](https://github.com/biontdv/CVE-1999-0524-POC) :  ![starts](https://img.shields.io/github/stars/biontdv/CVE-1999-0524-POC.svg) ![forks](https://img.shields.io/github/forks/biontdv/CVE-1999-0524-POC.svg)

