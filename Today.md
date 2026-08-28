# Update 2026-08-28
## CVE-2026-79266
 Use after free in DevTools in Google Chrome prior to 152.0.7977.65 allowed a remote attacker leveraging social engineering to execute arbitrary code inside the sandbox via a crafted Chrome extension. (Chromium security severity: Medium)

- [https://github.com/virologi-info/chrome-vuln-scanner](https://github.com/virologi-info/chrome-vuln-scanner) :  ![starts](https://img.shields.io/github/stars/virologi-info/chrome-vuln-scanner.svg) ![forks](https://img.shields.io/github/forks/virologi-info/chrome-vuln-scanner.svg)


## CVE-2026-76904
 GeoTools is an open source Java library that provides tools for geospatial data. Starting in version 30.5 and prior to versions 33.6, 34.5, and 33.6, an SQL Injection Vulnerability is present when executing OGC Filters with PostGIS DataStore implementation: `jsonArrayContains` function; Requires PostGIS 12 or greater with a String or JSON field. For PostGIS 12 and greater `jsonArrayContains(column, pointer, value)` function writes `value` into generated SQL without escaping. Patches are available in versions 33.6, 34.5, and 33.6. No known workaround is available. To limit scope of SQL Injection the PostGIS connection pool should be configured with limited rights.

- [https://github.com/bickZero93/CVE-2026-76904](https://github.com/bickZero93/CVE-2026-76904) :  ![starts](https://img.shields.io/github/stars/bickZero93/CVE-2026-76904.svg) ![forks](https://img.shields.io/github/forks/bickZero93/CVE-2026-76904.svg)


## CVE-2026-75898
 RAGFlow before 0.26.3 contains a server-side request forgery vulnerability in the agent workflow "Invoke" component (agent/component/invoke.py). The component builds an outbound request URL from canvas configuration and runtime template variables and passes it to requests.get, requests.post, or requests.put without calling the shared assert_url_is_safe validator or pinning the resolved address, unlike the crawler, SearXNG, file-upload, and RSS fetch paths. A user who can create or trigger an agent can direct the server to fetch loopback, link-local, and RFC 1918 destinations, including cloud instance metadata endpoints and services co-located on the deployment network, and the response body is returned as the component output. Where an agent is configured to interpolate the chat query into the Invoke URL, the destination is chosen by whoever can send that query.

- [https://github.com/t3bik/CVE-2026-75898](https://github.com/t3bik/CVE-2026-75898) :  ![starts](https://img.shields.io/github/stars/t3bik/CVE-2026-75898.svg) ![forks](https://img.shields.io/github/forks/t3bik/CVE-2026-75898.svg)


## CVE-2026-73570
 A remote code execution vulnerability exists in Zimbra Collaboration (ZCS) before 10.1.20 when the optional zimbra-snmp package is installed and SNMP notifications are enabled. Due to improper sanitization of untrusted input during SNMP notification processing, an unauthenticated attacker can send specially crafted SMTP requests that may result in execution of arbitrary operating system commands as the Zimbra user.

- [https://github.com/gabrielunknown/CVE-2026-73570](https://github.com/gabrielunknown/CVE-2026-73570) :  ![starts](https://img.shields.io/github/stars/gabrielunknown/CVE-2026-73570.svg) ![forks](https://img.shields.io/github/forks/gabrielunknown/CVE-2026-73570.svg)


## CVE-2026-72898
 Metabase allows a remote, unauthenticated attacker to inject arbitrary SQL via the '/reset_password' database endpoint and gain administrator access to the connected Metabase instance.

- [https://github.com/d-maggipinto/CVE-2026-72898-metabase-sqli](https://github.com/d-maggipinto/CVE-2026-72898-metabase-sqli) :  ![starts](https://img.shields.io/github/stars/d-maggipinto/CVE-2026-72898-metabase-sqli.svg) ![forks](https://img.shields.io/github/forks/d-maggipinto/CVE-2026-72898-metabase-sqli.svg)


## CVE-2026-67921
 Cross-Site Request Forgery (CSRF) vulnerability exists in Halo CMS versions up to 2.25.4 via the CorsConfigurer.java and the CsrfConfigurer.java components. This allows a remote attacker to execute arbitrary code.

- [https://github.com/unpredictable21/halo-cors-csrf-CVE-2026-67921](https://github.com/unpredictable21/halo-cors-csrf-CVE-2026-67921) :  ![starts](https://img.shields.io/github/stars/unpredictable21/halo-cors-csrf-CVE-2026-67921.svg) ![forks](https://img.shields.io/github/forks/unpredictable21/halo-cors-csrf-CVE-2026-67921.svg)


## CVE-2026-67920
 An issue in Halo 2.25.4 allows a remote attacker to execute arbitrary code via the run.halo.app.migration.impl.MigrationServiceImpl.restoreWorkdir(), and org.springframework.util.FileSystemUtils.copyRecursively() components

- [https://github.com/unpredictable21/halo-2.25.4-backup-write-CVE-2026-67920](https://github.com/unpredictable21/halo-2.25.4-backup-write-CVE-2026-67920) :  ![starts](https://img.shields.io/github/stars/unpredictable21/halo-2.25.4-backup-write-CVE-2026-67920.svg) ![forks](https://img.shields.io/github/forks/unpredictable21/halo-2.25.4-backup-write-CVE-2026-67920.svg)


## CVE-2026-63520
 Improper input validation in Microsoft Office SharePoint allows an unauthorized attacker to execute code over a network.

- [https://github.com/hypnguyen1209/CVE-2026-63520](https://github.com/hypnguyen1209/CVE-2026-63520) :  ![starts](https://img.shields.io/github/stars/hypnguyen1209/CVE-2026-63520.svg) ![forks](https://img.shields.io/github/forks/hypnguyen1209/CVE-2026-63520.svg)


## CVE-2026-63072
modules are affected by this CVE.

- [https://github.com/0xBlackash/CVE-2026-63072](https://github.com/0xBlackash/CVE-2026-63072) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-63072.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-63072.svg)


## CVE-2026-60004
 Gitea before 1.27.1 allows remote code execution via the diffpatch API through Git hook installation.

- [https://github.com/imbas007/CVE-2026-60004-POC](https://github.com/imbas007/CVE-2026-60004-POC) :  ![starts](https://img.shields.io/github/stars/imbas007/CVE-2026-60004-POC.svg) ![forks](https://img.shields.io/github/forks/imbas007/CVE-2026-60004-POC.svg)
- [https://github.com/HORKimhab/CVE-2026-60004](https://github.com/HORKimhab/CVE-2026-60004) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-60004.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-60004.svg)
- [https://github.com/gagaltotal/CVE-2026-60004-poc-gitea](https://github.com/gagaltotal/CVE-2026-60004-poc-gitea) :  ![starts](https://img.shields.io/github/stars/gagaltotal/CVE-2026-60004-poc-gitea.svg) ![forks](https://img.shields.io/github/forks/gagaltotal/CVE-2026-60004-poc-gitea.svg)
- [https://github.com/0xBlackash/CVE-2026-60004](https://github.com/0xBlackash/CVE-2026-60004) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-60004.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-60004.svg)
- [https://github.com/HackSpeak/CVE-2026-60004](https://github.com/HackSpeak/CVE-2026-60004) :  ![starts](https://img.shields.io/github/stars/HackSpeak/CVE-2026-60004.svg) ![forks](https://img.shields.io/github/forks/HackSpeak/CVE-2026-60004.svg)
- [https://github.com/EQSTLab/CVE-2026-60004](https://github.com/EQSTLab/CVE-2026-60004) :  ![starts](https://img.shields.io/github/stars/EQSTLab/CVE-2026-60004.svg) ![forks](https://img.shields.io/github/forks/EQSTLab/CVE-2026-60004.svg)
- [https://github.com/shinthink/CVE-2026-60004](https://github.com/shinthink/CVE-2026-60004) :  ![starts](https://img.shields.io/github/stars/shinthink/CVE-2026-60004.svg) ![forks](https://img.shields.io/github/forks/shinthink/CVE-2026-60004.svg)
- [https://github.com/fevar54/cve-2026-60004](https://github.com/fevar54/cve-2026-60004) :  ![starts](https://img.shields.io/github/stars/fevar54/cve-2026-60004.svg) ![forks](https://img.shields.io/github/forks/fevar54/cve-2026-60004.svg)
- [https://github.com/Sachinart/CVE-2026-60004-gitea-0day](https://github.com/Sachinart/CVE-2026-60004-gitea-0day) :  ![starts](https://img.shields.io/github/stars/Sachinart/CVE-2026-60004-gitea-0day.svg) ![forks](https://img.shields.io/github/forks/Sachinart/CVE-2026-60004-gitea-0day.svg)


## CVE-2026-56705
 Adminer before 5.4.3 fails to sanitize the server field before constructing a PDO DSN string, allowing unauthenticated attackers to inject ODBC parameters via semicolons. Attackers can inject TraceFile and TraceOn parameters to write PHP code to the web root, achieving remote code execution when the trace file is accessed.

- [https://github.com/ChiefYoru/Exploit-CVE-2026-56705](https://github.com/ChiefYoru/Exploit-CVE-2026-56705) :  ![starts](https://img.shields.io/github/stars/ChiefYoru/Exploit-CVE-2026-56705.svg) ![forks](https://img.shields.io/github/forks/ChiefYoru/Exploit-CVE-2026-56705.svg)


## CVE-2026-55040
 Weak authentication in Microsoft Office SharePoint allows an unauthorized attacker to bypass a security feature over a network.

- [https://github.com/zenzue/CVE-2026-55040](https://github.com/zenzue/CVE-2026-55040) :  ![starts](https://img.shields.io/github/stars/zenzue/CVE-2026-55040.svg) ![forks](https://img.shields.io/github/forks/zenzue/CVE-2026-55040.svg)


## CVE-2026-48907
 A vulnerability in the JCE editor extension for Joomla allows the creation of new editor profiles for unauthenticated users, ultimately resulting in PHP code upload and execution.

- [https://github.com/ksotaria1337/-CVE-2026-48907-](https://github.com/ksotaria1337/-CVE-2026-48907-) :  ![starts](https://img.shields.io/github/stars/ksotaria1337/-CVE-2026-48907-.svg) ![forks](https://img.shields.io/github/forks/ksotaria1337/-CVE-2026-48907-.svg)


## CVE-2026-46858
 Vulnerability in the APM - Application Performance Management product of Oracle Enterprise Manager (component: JADM, JVM Diagnostics).  Supported versions that are affected are 13.5 and  24.1. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise APM - Application Performance Management.  Successful attacks of this vulnerability can result in  unauthorized creation, deletion or modification access to critical data or all APM - Application Performance Management accessible data and unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of APM - Application Performance Management. CVSS 3.1 Base Score 9.1 (Integrity and Availability impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H).

- [https://github.com/sergiofigueras/cve-2026-46858](https://github.com/sergiofigueras/cve-2026-46858) :  ![starts](https://img.shields.io/github/stars/sergiofigueras/cve-2026-46858.svg) ![forks](https://img.shields.io/github/forks/sergiofigueras/cve-2026-46858.svg)


## CVE-2026-45585
No, if you are using TPM+PIN the vulnerability is not exploitable.

- [https://github.com/yellowkeycve2026/YellowKey-BitLocker-CVE-2026-45585](https://github.com/yellowkeycve2026/YellowKey-BitLocker-CVE-2026-45585) :  ![starts](https://img.shields.io/github/stars/yellowkeycve2026/YellowKey-BitLocker-CVE-2026-45585.svg) ![forks](https://img.shields.io/github/forks/yellowkeycve2026/YellowKey-BitLocker-CVE-2026-45585.svg)


## CVE-2026-43499
  	changelog ]

- [https://github.com/XingChenRS/CyberMeowfiaNS](https://github.com/XingChenRS/CyberMeowfiaNS) :  ![starts](https://img.shields.io/github/stars/XingChenRS/CyberMeowfiaNS.svg) ![forks](https://img.shields.io/github/forks/XingChenRS/CyberMeowfiaNS.svg)


## CVE-2026-39275
 Cross Site Scripting vulnerability in Cockpit CMS v.2.13.5 and before allows a remote attacker to execute arbitrary code via the item.php, field-select.js and tags.js components.

- [https://github.com/Securify-AI/CVE-2026-39275](https://github.com/Securify-AI/CVE-2026-39275) :  ![starts](https://img.shields.io/github/stars/Securify-AI/CVE-2026-39275.svg) ![forks](https://img.shields.io/github/forks/Securify-AI/CVE-2026-39275.svg)


## CVE-2026-36851
 Path traversal vulnerability in UnPoller 2.33.0 password field allows arbitrary file read and network exfiltration.

- [https://github.com/SyntaxSaiyan/CVE-2026-36851](https://github.com/SyntaxSaiyan/CVE-2026-36851) :  ![starts](https://img.shields.io/github/stars/SyntaxSaiyan/CVE-2026-36851.svg) ![forks](https://img.shields.io/github/forks/SyntaxSaiyan/CVE-2026-36851.svg)


## CVE-2026-31721
bind function, which I moved as well.

- [https://github.com/JakeStone594/f_hid-4.14-backports](https://github.com/JakeStone594/f_hid-4.14-backports) :  ![starts](https://img.shields.io/github/stars/JakeStone594/f_hid-4.14-backports.svg) ![forks](https://img.shields.io/github/forks/JakeStone594/f_hid-4.14-backports.svg)


## CVE-2026-31606
way, we can simply allocate a new one in hidg_bind.

- [https://github.com/JakeStone594/f_hid-4.14-backports](https://github.com/JakeStone594/f_hid-4.14-backports) :  ![starts](https://img.shields.io/github/stars/JakeStone594/f_hid-4.14-backports.svg) ![forks](https://img.shields.io/github/forks/JakeStone594/f_hid-4.14-backports.svg)


## CVE-2026-19913
 The Kaltura HTML5 player (mwEmbed / html5lib) contains a local file disclosure vulnerability due to improper validation of the ServiceUrl parameter in mwEmbedLoader.php. This parameter is used as the base URL for a backend request and accepts non‑HTTP schemes such as file://. When an exception or error occurs, the response is subsequently deserialized and its raw contents are reflected to the client in an error message; this enables an unauthenticated, remote attacker to read any arbitrary internal file reachable by the server. Affected versions include html5lib v2.45, v2.103 and earlier, and other v2.x releases exposing the vulnerable endpoint.

- [https://github.com/HORKimhab/CVE-2026-19912-CVE-2026-19913-CVE-2026-19914](https://github.com/HORKimhab/CVE-2026-19912-CVE-2026-19913-CVE-2026-19914) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-19912-CVE-2026-19913-CVE-2026-19914.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-19912-CVE-2026-19913-CVE-2026-19914.svg)


## CVE-2026-19912
 The Kaltura HTML5 player (mwEmbed / html5lib) contains an unauthenticated remote code execution vulnerability caused by unsafe data deserialization and unsanitized filesystem path construction. mwEmbedLoader.php accepts a user‑controlled ServiceUrl, whose response is passed to unserialize(), and the resulting object’s fields are written to a cache path derived from attacker‑supplied uiconf_id without proper path validation. An attacker can write arbitrary files into web‑accessible locations and achieve code execution as the webserver user. Affected versions include html5lib v2.45, v2.103 and earlier, and other v2.x releases exposing the vulnerable endpoint.

- [https://github.com/HORKimhab/CVE-2026-19912-CVE-2026-19913-CVE-2026-19914](https://github.com/HORKimhab/CVE-2026-19912-CVE-2026-19913-CVE-2026-19914) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-19912-CVE-2026-19913-CVE-2026-19914.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-19912-CVE-2026-19913-CVE-2026-19914.svg)


## CVE-2026-19632
 The TranslatePress – Translate Multilingual sites with AI Translation plugin for WordPress is vulnerable to Sensitive Information Exposure in all versions up to, and including, 3.3.1 via the 'trp_get_translations_regular' AJAX action. This makes it possible for unauthenticated attackers to extract the raw administrator password-reset URL — including the plaintext reset key and login parameters stored in the translation dictionary table — enabling full administrator account takeover. This vulnerability is only exploitable when automatic string saving is enabled (the default setting) and the target administrator's profile locale is set to a published secondary language, as these conditions cause the password-reset URL to be persisted as a translatable string in the secondary-language dictionary table.

- [https://github.com/YonLiud/CVE-2026-19632](https://github.com/YonLiud/CVE-2026-19632) :  ![starts](https://img.shields.io/github/stars/YonLiud/CVE-2026-19632.svg) ![forks](https://img.shields.io/github/forks/YonLiud/CVE-2026-19632.svg)
- [https://github.com/DeadExpl0it/CVE-2026-19632-POC](https://github.com/DeadExpl0it/CVE-2026-19632-POC) :  ![starts](https://img.shields.io/github/stars/DeadExpl0it/CVE-2026-19632-POC.svg) ![forks](https://img.shields.io/github/forks/DeadExpl0it/CVE-2026-19632-POC.svg)


## CVE-2026-19598
 The Pods – Custom Content Types and Fields plugin for WordPress is vulnerable to Privilege Escalation via Authorization Bypass in all versions up to, and including, 3.3.9. The vulnerability exists because the pods_admin AJAX router funnels every access check — including the method allowlist, nonce verification, login enforcement, and capability gate — through pods_error(), which under the JSON meta-box-loader compatibility path only writes failures to the PHP error log and returns false instead of terminating the request, rendering all guards ineffective.  This makes it possible for unauthenticated attackers to escalate their privileges to Administrator or overwrite the password of any user account, including the site owner's, enabling complete site takeover, or perform another administrator action.

- [https://github.com/HackfutSecRoot/multi_exploit_wp](https://github.com/HackfutSecRoot/multi_exploit_wp) :  ![starts](https://img.shields.io/github/stars/HackfutSecRoot/multi_exploit_wp.svg) ![forks](https://img.shields.io/github/forks/HackfutSecRoot/multi_exploit_wp.svg)


## CVE-2026-18080
 The ERP: Complete HR, Accounting & CRM Suite Built for WooCommerce plugin for WordPress is vulnerable to Unrestricted File Type Upload in all versions up to, and including, 1.17.8 via the save_attachments() function. This is due to missing file extension validation and missing path normalization when CRM Email Connect processes inbound IMAP email attachments. This makes it possible for unauthenticated attackers to send a crafted email to the site's configured inbound mailbox with a forged References header matching the plugin's expected pattern and an attachment filename such as `../helper.php`, causing the cron-based IMAP sync job to write attacker-controlled PHP outside of the .htaccess-protected `crm-attachments` directory and into `wp-content/uploads/`. On configurations where PHP executes in uploads, this can lead to remote code execution. Exploitation requires the CRM module and IMAP Email Connect feature to be enabled and configured.

- [https://github.com/Polosss/By-Poloss..-..CVE-2026-18080](https://github.com/Polosss/By-Poloss..-..CVE-2026-18080) :  ![starts](https://img.shields.io/github/stars/Polosss/By-Poloss..-..CVE-2026-18080.svg) ![forks](https://img.shields.io/github/forks/Polosss/By-Poloss..-..CVE-2026-18080.svg)


## CVE-2026-12948
 A stored cross-site scripting (XSS) vulnerability in the web management interface of the Digi PortServer TS, Digi One SP, Digi One SP IA, and Digi One IA allows a remote, authenticated administrator to inject script into certain system configuration fields. The script subsequently executes in the browser of a user who views the affected pages (CWE-79).

- [https://github.com/nvicloud/CVE-2026-12948](https://github.com/nvicloud/CVE-2026-12948) :  ![starts](https://img.shields.io/github/stars/nvicloud/CVE-2026-12948.svg) ![forks](https://img.shields.io/github/forks/nvicloud/CVE-2026-12948.svg)


## CVE-2026-12684
 The Customer Reviews for WooCommerce WordPress plugin before 5.113.0 does not perform authentication, capability, or nonce checks on one of its media upload AJAX actions when the review media attachment feature is enabled, allowing unauthenticated users to upload media files (bounded to an image and video allowlist) to the Media Library and create attachment posts, leading to media library pollution and disk space exhaustion.

- [https://github.com/htrxuan/hdwebmobile-photo-video-reviews](https://github.com/htrxuan/hdwebmobile-photo-video-reviews) :  ![starts](https://img.shields.io/github/stars/htrxuan/hdwebmobile-photo-video-reviews.svg) ![forks](https://img.shields.io/github/forks/htrxuan/hdwebmobile-photo-video-reviews.svg)


## CVE-2026-12352
 This vulnerability allows an unauthenticated actor to bypass authentication and gain access to restricted resources on the device.

- [https://github.com/nvicloud/CVE-2026-12352](https://github.com/nvicloud/CVE-2026-12352) :  ![starts](https://img.shields.io/github/stars/nvicloud/CVE-2026-12352.svg) ![forks](https://img.shields.io/github/forks/nvicloud/CVE-2026-12352.svg)


## CVE-2026-7762
 A heap-based buffer overflow vulnerability in the dot11ah.ko HaLow Wi-Fi kernel driver in Morse Micro HaLowLink 2 software versions prior to 2.11.13 allows an unauthenticated attacker within radio range to cause a Denial of Service (kernel panic) or potentially achieve Remote Code Execution via a crafted 802.11ah beacon or probe response frame containing a malformed S1G Capabilities Information Element (IE element ID 0xD9). The function morse_dot11ah_find_s1g_caps_for_bssid() uses the IE length field directly as the size argument to memcpy without validating it against the 15-byte destination buffer. An attacker can supply up to 255 bytes, causing an overflow of up to 240 bytes of attacker-controlled data into adjacent kernel heap memory. The vulnerability is triggerable during normal scanning without authentication, association, or user interaction.

- [https://github.com/Squ1shification/PNGboomer-CVE-2026-77622](https://github.com/Squ1shification/PNGboomer-CVE-2026-77622) :  ![starts](https://img.shields.io/github/stars/Squ1shification/PNGboomer-CVE-2026-77622.svg) ![forks](https://img.shields.io/github/forks/Squ1shification/PNGboomer-CVE-2026-77622.svg)


## CVE-2026-5361
 The Envira Gallery Lite plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the REST API in versions up to and including 1.12.4. This is due to insufficient input sanitization in the update_gallery_data() function and improper output escaping in the gallery_init() function. The sanitize_config_values() function only sanitizes the justified_gallery_theme and justified_row_height parameters, but does not sanitize the arrows parameter. When the arrows value is output in the inline JavaScript configuration, it uses esc_attr() which is designed for HTML attribute contexts, not JavaScript contexts, allowing JavaScript expression injection. This makes it possible for authenticated attackers, with Author-level access and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.

- [https://github.com/mohamedjawady/CVE-2026-53613-poc](https://github.com/mohamedjawady/CVE-2026-53613-poc) :  ![starts](https://img.shields.io/github/stars/mohamedjawady/CVE-2026-53613-poc.svg) ![forks](https://img.shields.io/github/forks/mohamedjawady/CVE-2026-53613-poc.svg)


## CVE-2026-3990
 A security flaw has been discovered in CesiumGS CesiumJS up to 1.137.0. Affected by this issue is some unknown functionality of the file Apps/Sandcastle/standalone.html. The manipulation of the argument c results in cross site scripting. The attack can be launched remotely. The exploit has been released to the public and may be used for attacks. The presence of this vulnerability remains uncertain at this time. The vendor was contacted early about this disclosure but did not respond in any way. According to CVE-2023-48094, "the vendor's position is that Apps/Sandcastle/standalone.html is part of the CesiumGS/cesium GitHub repository, but is demo code that is not part of the CesiumJS JavaScript library product."

- [https://github.com/kx00007/CVE-2026-39902](https://github.com/kx00007/CVE-2026-39902) :  ![starts](https://img.shields.io/github/stars/kx00007/CVE-2026-39902.svg) ![forks](https://img.shields.io/github/forks/kx00007/CVE-2026-39902.svg)


## CVE-2026-3888
 Local privilege escalation in snapd on Linux allows local attackers to get root privilege by re-creating snap's private /tmp directory when systemd-tmpfiles is configured to automatically clean up this directory. This issue affects Ubuntu 16.04 LTS, 18.04 LTS, 20.04 LTS, 22.04 LTS, and 24.04 LTS.

- [https://github.com/noambouillet/CVE-2026-3888](https://github.com/noambouillet/CVE-2026-3888) :  ![starts](https://img.shields.io/github/stars/noambouillet/CVE-2026-3888.svg) ![forks](https://img.shields.io/github/forks/noambouillet/CVE-2026-3888.svg)


## CVE-2026-3844
 The Breeze Cache plugin for WordPress is vulnerable to arbitrary file uploads due to missing file type validation in the 'fetch_gravatar_from_remote' function in all versions up to, and including, 2.4.4. This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible. The vulnerability can only be exploited if "Host Files Locally - Gravatars" is enabled, which is disabled by default.

- [https://github.com/Alevtinka19/CVE-2026-3844](https://github.com/Alevtinka19/CVE-2026-3844) :  ![starts](https://img.shields.io/github/stars/Alevtinka19/CVE-2026-3844.svg) ![forks](https://img.shields.io/github/forks/Alevtinka19/CVE-2026-3844.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-zero-installs](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-zero-installs) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-zero-installs.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-zero-installs.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-alias](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-alias) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-alias.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-alias.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-tilde](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-tilde) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-tilde.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-tilde.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/Heimd411/CVE-2025-29927-PoC](https://github.com/Heimd411/CVE-2025-29927-PoC) :  ![starts](https://img.shields.io/github/stars/Heimd411/CVE-2025-29927-PoC.svg) ![forks](https://img.shields.io/github/forks/Heimd411/CVE-2025-29927-PoC.svg)


## CVE-2025-6647
The specific flaw exists within the parsing of U3D files. The issue results from the lack of proper validation of user-supplied data, which can result in a write past the end of an allocated object. An attacker can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-26644.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-15x](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-15x) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-15x.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-15x.svg)


## CVE-2025-2992
 A vulnerability classified as critical was found in Tenda FH1202 1.2.0.14(408). Affected by this vulnerability is an unknown functionality of the file /goform/AdvSetWrlsafeset of the component Web Management Interface. The manipulation leads to improper access controls. The attack can be launched remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/lucaschanzx/CVE-2025-29927-PoC](https://github.com/lucaschanzx/CVE-2025-29927-PoC) :  ![starts](https://img.shields.io/github/stars/lucaschanzx/CVE-2025-29927-PoC.svg) ![forks](https://img.shields.io/github/forks/lucaschanzx/CVE-2025-29927-PoC.svg)


## CVE-2025-2945
This issue affects pgAdmin 4: before 9.2.

- [https://github.com/Khashayarnzk/CVE-2025-2945-pgAdmin-RCE](https://github.com/Khashayarnzk/CVE-2025-2945-pgAdmin-RCE) :  ![starts](https://img.shields.io/github/stars/Khashayarnzk/CVE-2025-2945-pgAdmin-RCE.svg) ![forks](https://img.shields.io/github/forks/Khashayarnzk/CVE-2025-2945-pgAdmin-RCE.svg)


## CVE-2023-39910
 The cryptocurrency wallet entropy seeding mechanism used in Libbitcoin Explorer 3.0.0 through 3.6.0 is weak, aka the Milk Sad issue. The use of an mt19937 Mersenne Twister PRNG restricts the internal entropy to 32 bits regardless of settings. This allows remote attackers to recover any wallet private keys generated from "bx seed" entropy output and steal funds. (Affected users need to move funds to a secure new cryptocurrency wallet.) NOTE: the vendor's position is that there was sufficient documentation advising against "bx seed" but others disagree. NOTE: this was exploited in the wild in June and July 2023.

- [https://github.com/easyHackCash/easyWallet](https://github.com/easyHackCash/easyWallet) :  ![starts](https://img.shields.io/github/stars/easyHackCash/easyWallet.svg) ![forks](https://img.shields.io/github/forks/easyHackCash/easyWallet.svg)


## CVE-2023-23397
 Microsoft Outlook Elevation of Privilege Vulnerability

- [https://github.com/praneethnaidu1910-cmd/cve-2023-23397-purple-team](https://github.com/praneethnaidu1910-cmd/cve-2023-23397-purple-team) :  ![starts](https://img.shields.io/github/stars/praneethnaidu1910-cmd/cve-2023-23397-purple-team.svg) ![forks](https://img.shields.io/github/forks/praneethnaidu1910-cmd/cve-2023-23397-purple-team.svg)


## CVE-2023-4861
 The File Manager Pro WordPress plugin before 1.8.1 allows admin users to upload arbitrary files, even in environments where such a user should not be able to gain full control of the server, such as a multisite installation. This leads to remote code execution.

- [https://github.com/noambouillet/CVE-2023-4861-PoC](https://github.com/noambouillet/CVE-2023-4861-PoC) :  ![starts](https://img.shields.io/github/stars/noambouillet/CVE-2023-4861-PoC.svg) ![forks](https://img.shields.io/github/forks/noambouillet/CVE-2023-4861-PoC.svg)


## CVE-2022-29303
 SolarView Compact ver.6.00 was discovered to contain a command injection vulnerability via conf_mail.php.

- [https://github.com/camgoering/solarview-ics-vulnerability-analysis](https://github.com/camgoering/solarview-ics-vulnerability-analysis) :  ![starts](https://img.shields.io/github/stars/camgoering/solarview-ics-vulnerability-analysis.svg) ![forks](https://img.shields.io/github/forks/camgoering/solarview-ics-vulnerability-analysis.svg)


## CVE-2021-4422
 The POST SMTP Mailer plugin for WordPress is vulnerable to Cross-Site Request Forgery in versions up to, and including, 2.0.20. This is due to missing or incorrect nonce validation on the handleCsvExport() function. This makes it possible for unauthenticated attackers to trigger a CSV export via a forged request granted they can trick a site administrator into performing an action such as clicking on a link.

- [https://github.com/dbgee/CVE-2021-44228](https://github.com/dbgee/CVE-2021-44228) :  ![starts](https://img.shields.io/github/stars/dbgee/CVE-2021-44228.svg) ![forks](https://img.shields.io/github/forks/dbgee/CVE-2021-44228.svg)


## CVE-2019-18634
 In Sudo before 1.8.26, if pwfeedback is enabled in /etc/sudoers, users can trigger a stack-based buffer overflow in the privileged sudo process. (pwfeedback is a default setting in Linux Mint and elementary OS; however, it is NOT the default for upstream and many other packages, and would exist only if enabled by an administrator.) The attacker needs to deliver a long string to the stdin of getln() in tgetpass.c.

- [https://github.com/DevTeam6Rabbit/CVE-2019-18634-writeup](https://github.com/DevTeam6Rabbit/CVE-2019-18634-writeup) :  ![starts](https://img.shields.io/github/stars/DevTeam6Rabbit/CVE-2019-18634-writeup.svg) ![forks](https://img.shields.io/github/forks/DevTeam6Rabbit/CVE-2019-18634-writeup.svg)


## CVE-2016-5195
 Race condition in mm/gup.c in the Linux kernel 2.x through 4.x before 4.8.3 allows local users to gain privileges by leveraging incorrect handling of a copy-on-write (COW) feature to write to a read-only memory mapping, as exploited in the wild in October 2016, aka "Dirty COW."

- [https://github.com/KongQBin/CVE-2016-5195](https://github.com/KongQBin/CVE-2016-5195) :  ![starts](https://img.shields.io/github/stars/KongQBin/CVE-2016-5195.svg) ![forks](https://img.shields.io/github/forks/KongQBin/CVE-2016-5195.svg)


## CVE-2011-2523
 vsftpd 2.3.4 downloaded between 20110630 and 20110703 contains a backdoor which opens a shell on port 6200/tcp.

- [https://github.com/Gvln-S/CVE-2011-2523](https://github.com/Gvln-S/CVE-2011-2523) :  ![starts](https://img.shields.io/github/stars/Gvln-S/CVE-2011-2523.svg) ![forks](https://img.shields.io/github/forks/Gvln-S/CVE-2011-2523.svg)

