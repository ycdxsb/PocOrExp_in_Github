# Update 2026-05-10
## CVE-2026-43284
destination-frag path or fall back to skb_cow_data().

- [https://github.com/Percivalll/Dirty-Frag-Kubernetes-PoC](https://github.com/Percivalll/Dirty-Frag-Kubernetes-PoC) :  ![starts](https://img.shields.io/github/stars/Percivalll/Dirty-Frag-Kubernetes-PoC.svg) ![forks](https://img.shields.io/github/forks/Percivalll/Dirty-Frag-Kubernetes-PoC.svg)
- [https://github.com/infiniroot/ansible-mitigate-copyfail-dirtyfrag](https://github.com/infiniroot/ansible-mitigate-copyfail-dirtyfrag) :  ![starts](https://img.shields.io/github/stars/infiniroot/ansible-mitigate-copyfail-dirtyfrag.svg) ![forks](https://img.shields.io/github/forks/infiniroot/ansible-mitigate-copyfail-dirtyfrag.svg)
- [https://github.com/0xBlackash/CVE-2026-43284](https://github.com/0xBlackash/CVE-2026-43284) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-43284.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-43284.svg)
- [https://github.com/suominen/CVE-2026-43284](https://github.com/suominen/CVE-2026-43284) :  ![starts](https://img.shields.io/github/stars/suominen/CVE-2026-43284.svg) ![forks](https://img.shields.io/github/forks/suominen/CVE-2026-43284.svg)
- [https://github.com/attaattaatta/CVE-2026-43284](https://github.com/attaattaatta/CVE-2026-43284) :  ![starts](https://img.shields.io/github/stars/attaattaatta/CVE-2026-43284.svg) ![forks](https://img.shields.io/github/forks/attaattaatta/CVE-2026-43284.svg)
- [https://github.com/scriptzteam/Paranoid-Dirty-Frag-CVE-2026-43284](https://github.com/scriptzteam/Paranoid-Dirty-Frag-CVE-2026-43284) :  ![starts](https://img.shields.io/github/stars/scriptzteam/Paranoid-Dirty-Frag-CVE-2026-43284.svg) ![forks](https://img.shields.io/github/forks/scriptzteam/Paranoid-Dirty-Frag-CVE-2026-43284.svg)
- [https://github.com/6abc/Copy-Fail-CVE-2026-31431-dirty-frag-CVE-2026-43284](https://github.com/6abc/Copy-Fail-CVE-2026-31431-dirty-frag-CVE-2026-43284) :  ![starts](https://img.shields.io/github/stars/6abc/Copy-Fail-CVE-2026-31431-dirty-frag-CVE-2026-43284.svg) ![forks](https://img.shields.io/github/forks/6abc/Copy-Fail-CVE-2026-31431-dirty-frag-CVE-2026-43284.svg)
- [https://github.com/lr1458644438/Dirty-Frag-Analysis](https://github.com/lr1458644438/Dirty-Frag-Analysis) :  ![starts](https://img.shields.io/github/stars/lr1458644438/Dirty-Frag-Analysis.svg) ![forks](https://img.shields.io/github/forks/lr1458644438/Dirty-Frag-Analysis.svg)
- [https://github.com/mym0us3r/DIRTY-FRAG-Detection-with-Wazuh-4.14.4](https://github.com/mym0us3r/DIRTY-FRAG-Detection-with-Wazuh-4.14.4) :  ![starts](https://img.shields.io/github/stars/mym0us3r/DIRTY-FRAG-Detection-with-Wazuh-4.14.4.svg) ![forks](https://img.shields.io/github/forks/mym0us3r/DIRTY-FRAG-Detection-with-Wazuh-4.14.4.svg)
- [https://github.com/KaraZajac/DIRTYFAIL](https://github.com/KaraZajac/DIRTYFAIL) :  ![starts](https://img.shields.io/github/stars/KaraZajac/DIRTYFAIL.svg) ![forks](https://img.shields.io/github/forks/KaraZajac/DIRTYFAIL.svg)
- [https://github.com/dixyes/dirtypatch](https://github.com/dixyes/dirtypatch) :  ![starts](https://img.shields.io/github/stars/dixyes/dirtypatch.svg) ![forks](https://img.shields.io/github/forks/dixyes/dirtypatch.svg)


## CVE-2026-42796
 Arelle before 2.39.10 contains an unauthenticated remote code execution vulnerability in the /rest/configure REST endpoint that accepts a plugins query parameter and forwards it to the plugin manager without authentication or authorization. Attackers can supply a URL to a malicious Python file through the plugins parameter, causing the Arelle webserver to download and execute the attacker-controlled code within the Arelle process with its privileges.

- [https://github.com/ameerhamza-malik/CVE-2026-42796](https://github.com/ameerhamza-malik/CVE-2026-42796) :  ![starts](https://img.shields.io/github/stars/ameerhamza-malik/CVE-2026-42796.svg) ![forks](https://img.shields.io/github/forks/ameerhamza-malik/CVE-2026-42796.svg)


## CVE-2026-42208
 LiteLLM is a proxy server (AI Gateway) to call LLM APIs in OpenAI (or native) format. From version 1.81.16 to before version 1.83.7, a database query used during proxy API key checks mixed the caller-supplied key value into the query text instead of passing it as a separate parameter. An unauthenticated attacker could send a specially crafted Authorization header to any LLM API route (for example POST /chat/completions) and reach this query through the proxy's error-handling path. An attacker could read data from the proxy's database and may be able to modify it, leading to unauthorised access to the proxy and the credentials it manages. This issue has been patched in version 1.83.7.

- [https://github.com/imjdl/CVE-2026-42208_lab](https://github.com/imjdl/CVE-2026-42208_lab) :  ![starts](https://img.shields.io/github/stars/imjdl/CVE-2026-42208_lab.svg) ![forks](https://img.shields.io/github/forks/imjdl/CVE-2026-42208_lab.svg)
- [https://github.com/0xBlackash/CVE-2026-42208](https://github.com/0xBlackash/CVE-2026-42208) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-42208.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-42208.svg)


## CVE-2026-41940
 cPanel and WHM versions after 11.40 contain an authentication bypass vulnerability in the login flow that allows unauthenticated remote attackers to gain unauthorized access to the control panel.

- [https://github.com/branixsolutions/Security-CVE-2026-41940-cPanel-WHM-WP2](https://github.com/branixsolutions/Security-CVE-2026-41940-cPanel-WHM-WP2) :  ![starts](https://img.shields.io/github/stars/branixsolutions/Security-CVE-2026-41940-cPanel-WHM-WP2.svg) ![forks](https://img.shields.io/github/forks/branixsolutions/Security-CVE-2026-41940-cPanel-WHM-WP2.svg)
- [https://github.com/acuciureanu/cpanel2shell-honeypot](https://github.com/acuciureanu/cpanel2shell-honeypot) :  ![starts](https://img.shields.io/github/stars/acuciureanu/cpanel2shell-honeypot.svg) ![forks](https://img.shields.io/github/forks/acuciureanu/cpanel2shell-honeypot.svg)


## CVE-2026-41900
 OpenLearnX is an open-source, decentralized learning and assessment platform. Prior to version 2.0.3, a remote code execution (RCE) vulnerability was identified in the OpenLearnX code execution environment, allowing sandbox escape and arbitrary command execution. This issue has been patched in version 2.0.3.

- [https://github.com/Christbowel/CVE-2026-41900-POC](https://github.com/Christbowel/CVE-2026-41900-POC) :  ![starts](https://img.shields.io/github/stars/Christbowel/CVE-2026-41900-POC.svg) ![forks](https://img.shields.io/github/forks/Christbowel/CVE-2026-41900-POC.svg)


## CVE-2026-41575
 In th30d4y/IP from version 1.0.1 to before version 2.0.1, a DOM-Based Cross-Site Scripting (XSS) vulnerability was identified in an IP Reputation Checker application. Unsanitized user input was directly rendered in the browser, allowing attackers to execute arbitrary JavaScript. This issue has been patched in version 2.0.1.

- [https://github.com/krrazee/CVE-2026-41575](https://github.com/krrazee/CVE-2026-41575) :  ![starts](https://img.shields.io/github/stars/krrazee/CVE-2026-41575.svg) ![forks](https://img.shields.io/github/forks/krrazee/CVE-2026-41575.svg)


## CVE-2026-39816
 The optional extension component TinkerpopClientService is missing the Restricted annotation with the Execute Code Required Permission in Apache NiFi 2.0.0-M1 through 2.8.0. The TinkerpopClientService supports configuration of ByteCode Submission for the Script Submission Type, enabling Groovy Script execution in the service prior to submitting the query. The missing Restricted annotation allows users without the Execute Code Permission to configure the Service in installations that use fine-grained authorization and have the optional TinkerpopClientService installed. Apache NiFi installations that do not have the nifi-other-graph-services-nar installed are not subject to this vulnerability. Upgrading to Apache NiFi 2.9.0 is the recommended mitigation.

- [https://github.com/ZeroPathAI/nifi-CVE-2026-39816-poc](https://github.com/ZeroPathAI/nifi-CVE-2026-39816-poc) :  ![starts](https://img.shields.io/github/stars/ZeroPathAI/nifi-CVE-2026-39816-poc.svg) ![forks](https://img.shields.io/github/forks/ZeroPathAI/nifi-CVE-2026-39816-poc.svg)


## CVE-2026-38361
 An issue in fohrloop dash-uploader v.0.1.0 through v.0.7.0a2 allows a remote attacker to execute arbitrary code via the dash_uploader/httprequesthandler.py, dash_uploader/upload.py in the Upload function and max_file_size parameter, dash_uploader/configure_upload.py components

- [https://github.com/a1ohadance/CVE-2026-38361](https://github.com/a1ohadance/CVE-2026-38361) :  ![starts](https://img.shields.io/github/stars/a1ohadance/CVE-2026-38361.svg) ![forks](https://img.shields.io/github/forks/a1ohadance/CVE-2026-38361.svg)


## CVE-2026-38360
 Directory Traversal vulnerability in fohrloop dash-uploader v.0.1.0 through v.0.7.0a2 allows a remote attacker to execute arbitrary code via the dash_uploader/httprequesthandler.py, aseHttpRequestHandler.get_temp_root(), BaseHttpRequestHandler._post() components

- [https://github.com/a1ohadance/CVE-2026-38360](https://github.com/a1ohadance/CVE-2026-38360) :  ![starts](https://img.shields.io/github/stars/a1ohadance/CVE-2026-38360.svg) ![forks](https://img.shields.io/github/forks/a1ohadance/CVE-2026-38360.svg)


## CVE-2026-35397
Version 2.18.0 contains a fix. As a workaround, ensure folder names do not share a common prefix with any sibling directory.

- [https://github.com/HiteshGorana/susvibes-jupyter-server-cve-2026-35397](https://github.com/HiteshGorana/susvibes-jupyter-server-cve-2026-35397) :  ![starts](https://img.shields.io/github/stars/HiteshGorana/susvibes-jupyter-server-cve-2026-35397.svg) ![forks](https://img.shields.io/github/forks/HiteshGorana/susvibes-jupyter-server-cve-2026-35397.svg)


## CVE-2026-34197
Users are recommended to upgrade to version 5.19.4 or 6.2.3, which fixes the issue

- [https://github.com/rootdirective-sec/CVE-2026-34197-Lab](https://github.com/rootdirective-sec/CVE-2026-34197-Lab) :  ![starts](https://img.shields.io/github/stars/rootdirective-sec/CVE-2026-34197-Lab.svg) ![forks](https://img.shields.io/github/forks/rootdirective-sec/CVE-2026-34197-Lab.svg)


## CVE-2026-33534
 EspoCRM is an open source customer relationship management application. Versions 9.3.3 and below have an authenticated Server-Side Request Forgery (SSRF) vulnerability that allows bypassing the internal-host validation logic by using alternative IPv4 representations such as octal notation (e.g., 0177.0.0.1 instead of 127.0.0.1). This is caused by HostCheck::isNotInternalHost() function relying on PHP's filter_var(..., FILTER_VALIDATE_IP), which does not recognize alternative IP formats, causing the validation to fall through to a DNS lookup that returns no records and incorrectly treats the host as safe, however the cURL subsequently normalizes the address and connects to the loopback destination. Through the confirmed /api/v1/Attachment/fromImageUrl endpoint, an authenticated user can force the server to make requests to loopback-only services and store the fetched response as an attachment. This vulnerability is distinct from CVE-2023-46736 (which involved redirect-based SSRF) and may allow access to internal resources reachable from the application runtime. This issue has been fixed in version 9.3.4.

- [https://github.com/EntroVyx/CVE-2026-33534](https://github.com/EntroVyx/CVE-2026-33534) :  ![starts](https://img.shields.io/github/stars/EntroVyx/CVE-2026-33534.svg) ![forks](https://img.shields.io/github/forks/EntroVyx/CVE-2026-33534.svg)


## CVE-2026-33006
Users are recommended to upgrade to version 2.4.67, which fixes this issue.

- [https://github.com/SimoesCTT/CTT-enhanced-Apache-mod_auth_digest-timing-attack-exploit](https://github.com/SimoesCTT/CTT-enhanced-Apache-mod_auth_digest-timing-attack-exploit) :  ![starts](https://img.shields.io/github/stars/SimoesCTT/CTT-enhanced-Apache-mod_auth_digest-timing-attack-exploit.svg) ![forks](https://img.shields.io/github/forks/SimoesCTT/CTT-enhanced-Apache-mod_auth_digest-timing-attack-exploit.svg)


## CVE-2026-32743
 PX4 is an open-source autopilot stack for drones and unmanned vehicles. Versions 1.17.0-rc2 and below are vulnerable to Stack-based Buffer Overflow through the MavlinkLogHandler, and are triggered via MAVLink log request. The LogEntry.filepath buffer is 60 bytes, but the sscanf function parses paths from the log list file with no width specifier, allowing a path longer than 60 characters to overflow the buffer. An attacker with MAVLink link access can trigger this by first creating deeply nested directories via MAVLink FTP, then requesting the log list. The flight controller MAVLink task crashes, losing telemetry and command capability and causing DoS. This issue has been fixed in this commit: https://github.com/PX4/PX4-Autopilot/commit/616b25a280e229c24d5cf12a03dbf248df89c474.

- [https://github.com/SimoesCTT/CTT-Enhanced-PX4-Autopilot-Exploit-CVE-2026-32743](https://github.com/SimoesCTT/CTT-Enhanced-PX4-Autopilot-Exploit-CVE-2026-32743) :  ![starts](https://img.shields.io/github/stars/SimoesCTT/CTT-Enhanced-PX4-Autopilot-Exploit-CVE-2026-32743.svg) ![forks](https://img.shields.io/github/forks/SimoesCTT/CTT-Enhanced-PX4-Autopilot-Exploit-CVE-2026-32743.svg)
- [https://github.com/mbanyamer/CVE-2026-32743-PX4-Autopilot-MavlinkLogHandler-Stack-Buffer-Overflow-DoS-](https://github.com/mbanyamer/CVE-2026-32743-PX4-Autopilot-MavlinkLogHandler-Stack-Buffer-Overflow-DoS-) :  ![starts](https://img.shields.io/github/stars/mbanyamer/CVE-2026-32743-PX4-Autopilot-MavlinkLogHandler-Stack-Buffer-Overflow-DoS-.svg) ![forks](https://img.shields.io/github/forks/mbanyamer/CVE-2026-32743-PX4-Autopilot-MavlinkLogHandler-Stack-Buffer-Overflow-DoS-.svg)


## CVE-2026-32707
 PX4 autopilot is a flight control solution for drones. Prior to 1.17.0-rc2, tattu_can contains an unbounded memcpy in its multi-frame assembly loop, allowing stack memory overwrite when crafted CAN frames are processed. In deployments where tattu_can is enabled and running, a CAN-injection-capable attacker can trigger a crash (DoS) and memory corruption. This vulnerability is fixed in 1.17.0-rc2.

- [https://github.com/mbanyamer/CVE-2026-32707-PX4-Autopilot-tattu_can-Stack-Buffer-Overflow-DoS-](https://github.com/mbanyamer/CVE-2026-32707-PX4-Autopilot-tattu_can-Stack-Buffer-Overflow-DoS-) :  ![starts](https://img.shields.io/github/stars/mbanyamer/CVE-2026-32707-PX4-Autopilot-tattu_can-Stack-Buffer-Overflow-DoS-.svg) ![forks](https://img.shields.io/github/forks/mbanyamer/CVE-2026-32707-PX4-Autopilot-tattu_can-Stack-Buffer-Overflow-DoS-.svg)


## CVE-2026-31431
AD directly.

- [https://github.com/infiniroot/ansible-mitigate-copyfail-dirtyfrag](https://github.com/infiniroot/ansible-mitigate-copyfail-dirtyfrag) :  ![starts](https://img.shields.io/github/stars/infiniroot/ansible-mitigate-copyfail-dirtyfrag.svg) ![forks](https://img.shields.io/github/forks/infiniroot/ansible-mitigate-copyfail-dirtyfrag.svg)
- [https://github.com/Phalanx-CCS/Copy-Fail](https://github.com/Phalanx-CCS/Copy-Fail) :  ![starts](https://img.shields.io/github/stars/Phalanx-CCS/Copy-Fail.svg) ![forks](https://img.shields.io/github/forks/Phalanx-CCS/Copy-Fail.svg)


## CVE-2026-25589
 RedisBloom is a probabilistic data structures module for Redis. In all versions of RedisBloom before 2.8.20, the module does not properly validate serialized values processed through the Redis RESTORE command. An authenticated attacker with permission to execute RESTORE on a server with the RedisBloom module loaded can supply a crafted serialized payload that triggers invalid memory access and may lead to remote code execution. A workaround is to restrict access to the RESTORE command with ACL rules. This issue is fixed in version 2.8.20.

- [https://github.com/mgiay/CVE-2026-25589-25588-25243-23631-23479-REDIS](https://github.com/mgiay/CVE-2026-25589-25588-25243-23631-23479-REDIS) :  ![starts](https://img.shields.io/github/stars/mgiay/CVE-2026-25589-25588-25243-23631-23479-REDIS.svg) ![forks](https://img.shields.io/github/forks/mgiay/CVE-2026-25589-25588-25243-23631-23479-REDIS.svg)


## CVE-2026-23918
Users are recommended to upgrade to version 2.4.67, which fixes the issue.

- [https://github.com/insomnisec/Detections-CVE-2026-23918](https://github.com/insomnisec/Detections-CVE-2026-23918) :  ![starts](https://img.shields.io/github/stars/insomnisec/Detections-CVE-2026-23918.svg) ![forks](https://img.shields.io/github/forks/insomnisec/Detections-CVE-2026-23918.svg)


## CVE-2026-21858
 n8n is an open source workflow automation platform. Versions starting with 1.65.0 and below 1.121.0 enable an attacker to access files on the underlying server through execution of certain form-based workflows. A vulnerable workflow could grant access to an unauthenticated remote attacker, resulting in exposure of sensitive information stored on the system and may enable further compromise depending on deployment configuration and workflow usage. This issue is fixed in version 1.121.0.

- [https://github.com/Bannt08/Research-CVE-2026-21858](https://github.com/Bannt08/Research-CVE-2026-21858) :  ![starts](https://img.shields.io/github/stars/Bannt08/Research-CVE-2026-21858.svg) ![forks](https://img.shields.io/github/forks/Bannt08/Research-CVE-2026-21858.svg)


## CVE-2026-5718
 The Drag and Drop Multiple File Upload for Contact Form 7 plugin for WordPress is vulnerable to arbitrary file upload in versions up to, and including, 1.3.9.6. This is due to insufficient file type validation that occurs when custom blacklist types are configured, which replaces the default dangerous extension denylist instead of merging with it, and the wpcf7_antiscript_file_name() sanitization function being bypassed for filenames containing non-ASCII characters. This makes it possible for unauthenticated attackers to upload arbitrary files, such as PHP files, to the server, which can be leveraged to achieve remote code execution.

- [https://github.com/kyukazamiqq/cve-2026-5718](https://github.com/kyukazamiqq/cve-2026-5718) :  ![starts](https://img.shields.io/github/stars/kyukazamiqq/cve-2026-5718.svg) ![forks](https://img.shields.io/github/forks/kyukazamiqq/cve-2026-5718.svg)


## CVE-2026-4464
 Integer overflow in ANGLE in Google Chrome prior to 146.0.7680.153 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: Medium)

- [https://github.com/zzzm0919/CVE-2026-44648](https://github.com/zzzm0919/CVE-2026-44648) :  ![starts](https://img.shields.io/github/stars/zzzm0919/CVE-2026-44648.svg) ![forks](https://img.shields.io/github/forks/zzzm0919/CVE-2026-44648.svg)


## CVE-2026-3844
 The Breeze Cache plugin for WordPress is vulnerable to arbitrary file uploads due to missing file type validation in the 'fetch_gravatar_from_remote' function in all versions up to, and including, 2.4.4. This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible. The vulnerability can only be exploited if "Host Files Locally - Gravatars" is enabled, which is disabled by default.

- [https://github.com/rootdirective-sec/CVE-2026-3844-Lab](https://github.com/rootdirective-sec/CVE-2026-3844-Lab) :  ![starts](https://img.shields.io/github/stars/rootdirective-sec/CVE-2026-3844-Lab.svg) ![forks](https://img.shields.io/github/forks/rootdirective-sec/CVE-2026-3844-Lab.svg)


## CVE-2026-3763
 A vulnerability was found in code-projects Simple Flight Ticket Booking System 1.0. The affected element is an unknown function of the file showhistory.php. The manipulation results in cross site scripting. It is possible to launch the attack remotely. The exploit has been made public and could be used.

- [https://github.com/SLO-CYBER-SEC/CVE-2026-37637](https://github.com/SLO-CYBER-SEC/CVE-2026-37637) :  ![starts](https://img.shields.io/github/stars/SLO-CYBER-SEC/CVE-2026-37637.svg) ![forks](https://img.shields.io/github/forks/SLO-CYBER-SEC/CVE-2026-37637.svg)


## CVE-2025-69691
 Netgate pfSense CE 2.8.0 allows code execution in the XMLRPC API via pfsense.exec_php. NOTE: the Supplier disputes this because the API call is only available to admins and they are intentionally allowed to execute PHP code.

- [https://github.com/privlabs/CVE-2025-69690-CVE-2025-69691](https://github.com/privlabs/CVE-2025-69690-CVE-2025-69691) :  ![starts](https://img.shields.io/github/stars/privlabs/CVE-2025-69690-CVE-2025-69691.svg) ![forks](https://img.shields.io/github/forks/privlabs/CVE-2025-69690-CVE-2025-69691.svg)


## CVE-2025-69690
 Netgate pfSense CE 2.7.2 allows code execution by using the module installer with a backup file with a serialized PHP object containing the post_reboot_commands property. NOTE: the Supplier disputes this because this installer is only available to admins and they are intentionally allowed to execute PHP code.

- [https://github.com/privlabs/CVE-2025-69690-CVE-2025-69691](https://github.com/privlabs/CVE-2025-69690-CVE-2025-69691) :  ![starts](https://img.shields.io/github/stars/privlabs/CVE-2025-69690-CVE-2025-69691.svg) ![forks](https://img.shields.io/github/forks/privlabs/CVE-2025-69690-CVE-2025-69691.svg)


## CVE-2025-69599
 RayVentory Scan Engine through 12.6 Update 8 allows attackers to gain privileges if they control the value of the PATH environment variable. NOTE: this is disputed because ability of an attacker to control the environment is a site-specific misconfiguration.

- [https://github.com/Wise-Security/CVE-2025-69599](https://github.com/Wise-Security/CVE-2025-69599) :  ![starts](https://img.shields.io/github/stars/Wise-Security/CVE-2025-69599.svg) ![forks](https://img.shields.io/github/forks/Wise-Security/CVE-2025-69599.svg)


## CVE-2025-67888
 An issue was discovered in Control Web Panel (CWP) before 0.9.8.1209. User input passed via the "key" GET parameter to /admin/index.php (when the "api" parameter is set) is not properly sanitized before being used to execute OS commands. This can be exploited by unauthenticated attackers to inject and execute arbitrary OS commands with the privileges of root on the web server. Softaculous or SitePad must be present.

- [https://github.com/reewardius/CVE-2025-67888](https://github.com/reewardius/CVE-2025-67888) :  ![starts](https://img.shields.io/github/stars/reewardius/CVE-2025-67888.svg) ![forks](https://img.shields.io/github/forks/reewardius/CVE-2025-67888.svg)


## CVE-2025-67887
 1C-Bitrix through 25.100.500 allows Remote Code Execution because an actor with SOURCE/WRITE permissions for the Translate Module can upload and execute code by sending a PHP file and a .htaccess file. NOTE: this is disputed by the Supplier because this is intended behavior for the high-privileged users who can upload new translated pages to the website.

- [https://github.com/cyberok-org/CVE-2025-67887](https://github.com/cyberok-org/CVE-2025-67887) :  ![starts](https://img.shields.io/github/stars/cyberok-org/CVE-2025-67887.svg) ![forks](https://img.shields.io/github/forks/cyberok-org/CVE-2025-67887.svg)
- [https://github.com/reewardius/CVE-2025-67887](https://github.com/reewardius/CVE-2025-67887) :  ![starts](https://img.shields.io/github/stars/reewardius/CVE-2025-67887.svg) ![forks](https://img.shields.io/github/forks/reewardius/CVE-2025-67887.svg)


## CVE-2025-67886
 Bitrix24 through 25.100.300 allows Remote Code Execution because an actor with SOURCE/WRITE permissions for the Translate Module can upload and execute code by sending a PHP file and a .htaccess file. NOTE: this is disputed by the Supplier because this is intended behavior for the high-privileged users who can upload new translated pages to the website.

- [https://github.com/reewardius/CVE-2025-67886](https://github.com/reewardius/CVE-2025-67886) :  ![starts](https://img.shields.io/github/stars/reewardius/CVE-2025-67886.svg) ![forks](https://img.shields.io/github/forks/reewardius/CVE-2025-67886.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/jensnesten/React2Shell-PoC](https://github.com/jensnesten/React2Shell-PoC) :  ![starts](https://img.shields.io/github/stars/jensnesten/React2Shell-PoC.svg) ![forks](https://img.shields.io/github/forks/jensnesten/React2Shell-PoC.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-15x](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-15x) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-15x.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-15x.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions.svg)


## CVE-2025-64714
 PrivateBin is an online pastebin where the server has zero knowledge of pasted data. Starting in version 1.7.7 and prior to version 2.0.3, an unauthenticated Local File Inclusion exists in the template-switching feature. If `templateselection` is enabled in the configuration, the server trusts the `template` cookie and includes the referenced PHP file. An attacker can read sensitive data or, if they manage to drop a PHP file elsewhere, gain remote code execution. The constructed path of the template file is checked for existence, then included. For PrivateBin project files this does not leak any secrets due to data files being created with PHP code that prevents execution, but if a configuration file without that line got created or the visitor figures out the relative path to a PHP script that directly performs an action without appropriate privilege checking, those might execute or leak information. The issue has been patched in version 2.0.3. As a workaround, set `templateselection = false` (which is the default) in `cfg/conf.php` or remove it entirely

- [https://github.com/Medaz-Sploit/CVE-2025-64714-privatebin-2.0.2-PoC](https://github.com/Medaz-Sploit/CVE-2025-64714-privatebin-2.0.2-PoC) :  ![starts](https://img.shields.io/github/stars/Medaz-Sploit/CVE-2025-64714-privatebin-2.0.2-PoC.svg) ![forks](https://img.shields.io/github/forks/Medaz-Sploit/CVE-2025-64714-privatebin-2.0.2-PoC.svg)


## CVE-2025-60751
 GeographicLib 2.5 is vulnerable to Buffer Overflow in GeoConvert DMS::InternalDecode.

- [https://github.com/zer0matt/CVE-2025-60751](https://github.com/zer0matt/CVE-2025-60751) :  ![starts](https://img.shields.io/github/stars/zer0matt/CVE-2025-60751.svg) ![forks](https://img.shields.io/github/forks/zer0matt/CVE-2025-60751.svg)
- [https://github.com/kaleth4/CVE-2025-60751](https://github.com/kaleth4/CVE-2025-60751) :  ![starts](https://img.shields.io/github/stars/kaleth4/CVE-2025-60751.svg) ![forks](https://img.shields.io/github/forks/kaleth4/CVE-2025-60751.svg)


## CVE-2025-60595
 SPH Engineering UgCS 5.13.0 is vulnerable to Arbitary code execution.

- [https://github.com/Clicksafeae/CVE-2025-60595](https://github.com/Clicksafeae/CVE-2025-60595) :  ![starts](https://img.shields.io/github/stars/Clicksafeae/CVE-2025-60595.svg) ![forks](https://img.shields.io/github/forks/Clicksafeae/CVE-2025-60595.svg)


## CVE-2025-60021
2. Apply this patch ( https://github.com/apache/brpc/pull/3101 ) manually.

- [https://github.com/Mefhika120/Ashwesker-CVE-2025-60021](https://github.com/Mefhika120/Ashwesker-CVE-2025-60021) :  ![starts](https://img.shields.io/github/stars/Mefhika120/Ashwesker-CVE-2025-60021.svg) ![forks](https://img.shields.io/github/forks/Mefhika120/Ashwesker-CVE-2025-60021.svg)


## CVE-2025-59528
 Flowise is a drag & drop user interface to build a customized large language model flow. In version 3.0.5, Flowise is vulnerable to remote code execution. The CustomMCP node allows users to input configuration settings for connecting to an external MCP server. This node parses the user-provided mcpServerConfig string to build the MCP server configuration. However, during this process, it executes JavaScript code without any security validation. Specifically, inside the convertToValidJSONString function, user input is directly passed to the Function() constructor, which evaluates and executes the input as JavaScript code. Since this runs with full Node.js runtime privileges, it can access dangerous modules such as child_process and fs. This issue has been patched in version 3.0.6.

- [https://github.com/0xDaeras/FlowiseAI-CVE-Chain-PoC](https://github.com/0xDaeras/FlowiseAI-CVE-Chain-PoC) :  ![starts](https://img.shields.io/github/stars/0xDaeras/FlowiseAI-CVE-Chain-PoC.svg) ![forks](https://img.shields.io/github/forks/0xDaeras/FlowiseAI-CVE-Chain-PoC.svg)


## CVE-2025-58434
 Flowise is a drag & drop user interface to build a customized large language model flow. In version 3.0.5 and earlier, the `forgot-password` endpoint in Flowise returns sensitive information including a valid password reset `tempToken` without authentication or verification. This enables any attacker to generate a reset token for arbitrary users and directly reset their password, leading to a complete account takeover (ATO). This vulnerability applies to both the cloud service (`cloud.flowiseai.com`) and self-hosted/local Flowise deployments that expose the same API. Commit 9e178d68873eb876073846433a596590d3d9c863 in version 3.0.6 secures password reset endpoints. Several recommended remediation steps are available. Do not return reset tokens or sensitive account details in API responses. Tokens must only be delivered securely via the registered email channel. Ensure `forgot-password` responds with a generic success message regardless of input, to avoid user enumeration. Require strong validation of the `tempToken` (e.g., single-use, short expiry, tied to request origin, validated against email delivery). Apply the same fixes to both cloud and self-hosted/local deployments. Log and monitor password reset requests for suspicious activity. Consider multi-factor verification for sensitive accounts.

- [https://github.com/0xDaeras/FlowiseAI-CVE-Chain-PoC](https://github.com/0xDaeras/FlowiseAI-CVE-Chain-PoC) :  ![starts](https://img.shields.io/github/stars/0xDaeras/FlowiseAI-CVE-Chain-PoC.svg) ![forks](https://img.shields.io/github/forks/0xDaeras/FlowiseAI-CVE-Chain-PoC.svg)


## CVE-2025-55449
 AstrBotDevs AstrBot 3.5.15 has Advanced_System_for_Text_Response_and_Bot_Operations_Tool as the hardcoded private key used to sign a JWT.

- [https://github.com/xhh1h/CVE-2025-55449](https://github.com/xhh1h/CVE-2025-55449) :  ![starts](https://img.shields.io/github/stars/xhh1h/CVE-2025-55449.svg) ![forks](https://img.shields.io/github/forks/xhh1h/CVE-2025-55449.svg)
- [https://github.com/Marven11/CVE-2025-55449-AstrBot-RCE](https://github.com/Marven11/CVE-2025-55449-AstrBot-RCE) :  ![starts](https://img.shields.io/github/stars/Marven11/CVE-2025-55449-AstrBot-RCE.svg) ![forks](https://img.shields.io/github/forks/Marven11/CVE-2025-55449-AstrBot-RCE.svg)


## CVE-2025-12904
 The SNORDIAN's H5PxAPIkatchu plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the 'insert_data' AJAX endpoint in all versions up to, and including, 0.4.17 due to insufficient input sanitization and output escaping. This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.

- [https://github.com/MooseLoveti/SNORDIAN-s-H5PxAPIkatchu-CVE-Report](https://github.com/MooseLoveti/SNORDIAN-s-H5PxAPIkatchu-CVE-Report) :  ![starts](https://img.shields.io/github/stars/MooseLoveti/SNORDIAN-s-H5PxAPIkatchu-CVE-Report.svg) ![forks](https://img.shields.io/github/forks/MooseLoveti/SNORDIAN-s-H5PxAPIkatchu-CVE-Report.svg)


## CVE-2025-12135
 The WPBookit plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the 'css_code' parameter in all versions up to, and including, 1.0.6 due to a missing capability check on the save_custome_code() function. This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.

- [https://github.com/d0n601/CVE-2025-12135](https://github.com/d0n601/CVE-2025-12135) :  ![starts](https://img.shields.io/github/stars/d0n601/CVE-2025-12135.svg) ![forks](https://img.shields.io/github/forks/d0n601/CVE-2025-12135.svg)


## CVE-2024-46508
 yeti-platform yeti before 2.1.12 allows attackers to generate valid JWT tokens is the secret is not changed (by setting YETI_AUTH_SECRET_KEY to a value other than SECRET).

- [https://github.com/Somchandra17/CVE-2024-46507](https://github.com/Somchandra17/CVE-2024-46507) :  ![starts](https://img.shields.io/github/stars/Somchandra17/CVE-2024-46507.svg) ![forks](https://img.shields.io/github/forks/Somchandra17/CVE-2024-46507.svg)


## CVE-2024-46507
 A SSTI (server side template injection) vulnerability in the custom template export function in yeti-platform yeti before 2.1.12 allows attackers to execute code on the application server.

- [https://github.com/Somchandra17/CVE-2024-46507](https://github.com/Somchandra17/CVE-2024-46507) :  ![starts](https://img.shields.io/github/stars/Somchandra17/CVE-2024-46507.svg) ![forks](https://img.shields.io/github/forks/Somchandra17/CVE-2024-46507.svg)


## CVE-2024-30167
 /cgi-bin/time.cgi in Atlona AT-OME-MS42 Matrix Switcher 1.1.2 allow remote authenticated users to execute arbitrary commands as root via a POST request that carries a serverName parameter.

- [https://github.com/RIZZZIOM/CVE-2024-30167](https://github.com/RIZZZIOM/CVE-2024-30167) :  ![starts](https://img.shields.io/github/stars/RIZZZIOM/CVE-2024-30167.svg) ![forks](https://img.shields.io/github/forks/RIZZZIOM/CVE-2024-30167.svg)


## CVE-2024-27686
 Mikrotik RouterOS (x86) 6.40.5 through 6.49.10 (fixed in 7) allows a remote attacker to cause a denial of service (device crash) via crafted packet data to the SMB service on TCP port 445.

- [https://github.com/ThemeHackers/CVE-2024-27686](https://github.com/ThemeHackers/CVE-2024-27686) :  ![starts](https://img.shields.io/github/stars/ThemeHackers/CVE-2024-27686.svg) ![forks](https://img.shields.io/github/forks/ThemeHackers/CVE-2024-27686.svg)


## CVE-2024-4040
 A server side template injection vulnerability in CrushFTP in all versions before 10.7.1 and 11.1.0 on all platforms allows unauthenticated remote attackers to read files from the filesystem outside of the VFS Sandbox, bypass authentication to gain administrative access, and perform remote code execution on the server.

- [https://github.com/Sidjaz/CrushFTP-CVE-2024-4040-Proof-of-Concept](https://github.com/Sidjaz/CrushFTP-CVE-2024-4040-Proof-of-Concept) :  ![starts](https://img.shields.io/github/stars/Sidjaz/CrushFTP-CVE-2024-4040-Proof-of-Concept.svg) ![forks](https://img.shields.io/github/forks/Sidjaz/CrushFTP-CVE-2024-4040-Proof-of-Concept.svg)


## CVE-2023-47268
 In libslic3r/GCode/PostProcessor.cpp in Prusa PrusaSlicer through 2.6.1, a crafted 3mf project file can execute arbitrary code on a host where the project is sliced and G-code exported.

- [https://github.com/suce0155/CVE-2023-47268](https://github.com/suce0155/CVE-2023-47268) :  ![starts](https://img.shields.io/github/stars/suce0155/CVE-2023-47268.svg) ![forks](https://img.shields.io/github/forks/suce0155/CVE-2023-47268.svg)
- [https://github.com/Pallangyo98/Trickster-HTB](https://github.com/Pallangyo98/Trickster-HTB) :  ![starts](https://img.shields.io/github/stars/Pallangyo98/Trickster-HTB.svg) ![forks](https://img.shields.io/github/forks/Pallangyo98/Trickster-HTB.svg)


## CVE-2023-4863
 Heap buffer overflow in libwebp in Google Chrome prior to 116.0.5845.187 and libwebp 1.3.2 allowed a remote attacker to perform an out of bounds memory write via a crafted HTML page. (Chromium security severity: Critical)

- [https://github.com/577Industries/aegisgraph](https://github.com/577Industries/aegisgraph) :  ![starts](https://img.shields.io/github/stars/577Industries/aegisgraph.svg) ![forks](https://img.shields.io/github/forks/577Industries/aegisgraph.svg)


## CVE-2021-1732
 Windows Win32k Elevation of Privilege Vulnerability

- [https://github.com/SabNa309/Win32k-Callback-Corruption-LPE](https://github.com/SabNa309/Win32k-Callback-Corruption-LPE) :  ![starts](https://img.shields.io/github/stars/SabNa309/Win32k-Callback-Corruption-LPE.svg) ![forks](https://img.shields.io/github/forks/SabNa309/Win32k-Callback-Corruption-LPE.svg)


## CVE-2019-7711
 An issue was discovered in the Interpeak IPCOMShell TELNET server on Green Hills INTEGRITY RTOS 5.0.4. The undocumented shell command "prompt" sets the (user controlled) shell's prompt value, which is used as a format string input to printf, resulting in an information leak of memory addresses.

- [https://github.com/kaleth4/CVE-2019-7711](https://github.com/kaleth4/CVE-2019-7711) :  ![starts](https://img.shields.io/github/stars/kaleth4/CVE-2019-7711.svg) ![forks](https://img.shields.io/github/forks/kaleth4/CVE-2019-7711.svg)


## CVE-2014-6271
 GNU Bash through 4.3 processes trailing strings after function definitions in the values of environment variables, which allows remote attackers to execute arbitrary code via a crafted environment, as demonstrated by vectors involving the ForceCommand feature in OpenSSH sshd, the mod_cgi and mod_cgid modules in the Apache HTTP Server, scripts executed by unspecified DHCP clients, and other situations in which setting the environment occurs across a privilege boundary from Bash execution, aka "ShellShock."  NOTE: the original fix for this issue was incorrect; CVE-2014-7169 has been assigned to cover the vulnerability that is still present after the incorrect fix.

- [https://github.com/alexgar207/Shellshock-Attack-CVE--2014-6271-](https://github.com/alexgar207/Shellshock-Attack-CVE--2014-6271-) :  ![starts](https://img.shields.io/github/stars/alexgar207/Shellshock-Attack-CVE--2014-6271-.svg) ![forks](https://img.shields.io/github/forks/alexgar207/Shellshock-Attack-CVE--2014-6271-.svg)


## CVE-2011-2523
 vsftpd 2.3.4 downloaded between 20110630 and 20110703 contains a backdoor which opens a shell on port 6200/tcp.

- [https://github.com/Prafullya-Shandilya/metasploitable-pentest-report](https://github.com/Prafullya-Shandilya/metasploitable-pentest-report) :  ![starts](https://img.shields.io/github/stars/Prafullya-Shandilya/metasploitable-pentest-report.svg) ![forks](https://img.shields.io/github/forks/Prafullya-Shandilya/metasploitable-pentest-report.svg)

