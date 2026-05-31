# Update 2026-05-31
## CVE-2026-46840
 Vulnerability in Oracle REST Data Services (component: Backend-as-a-Service).  Supported versions that are affected are 24.2.0-26.1.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTPS to compromise Oracle REST Data Services.  While the vulnerability is in Oracle REST Data Services, attacks may significantly impact additional products (scope change).  Successful attacks of this vulnerability can result in takeover of Oracle REST Data Services. CVSS 3.1 Base Score 10.0 (Confidentiality, Integrity and Availability impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H).

- [https://github.com/fangbarristerbar/CVE-2026-46840-ORDS-RCE](https://github.com/fangbarristerbar/CVE-2026-46840-ORDS-RCE) :  ![starts](https://img.shields.io/github/stars/fangbarristerbar/CVE-2026-46840-ORDS-RCE.svg) ![forks](https://img.shields.io/github/forks/fangbarristerbar/CVE-2026-46840-ORDS-RCE.svg)


## CVE-2026-46376
 FreePBX is an open source IP PBX. From 15.0.42 to before 16.0.45 and 17.0.7, unauthenticated users may be able to access the User Control Panel (UCP) using hard-coded initial template credentials if these were not immediately changed by the Administrator who enabled UCP. Authenticated access to ACP is required for the initial setup of UCP generic templates, but after that, without further steps by the admin, unauthenticated users may be able to gain access. This vulnerability is fixed in 16.0.45 and 17.0.7.

- [https://github.com/portbuster1337/CVE-2026-46376](https://github.com/portbuster1337/CVE-2026-46376) :  ![starts](https://img.shields.io/github/stars/portbuster1337/CVE-2026-46376.svg) ![forks](https://img.shields.io/github/forks/portbuster1337/CVE-2026-46376.svg)


## CVE-2026-44648
 SillyTavern is a locally installed user interface that allows users to interact with text generation large language models, image generation engines, and text-to-speech voice models. Prior to 1.18.0, SillyTavern relies on cookie-session for authentication, storing all session data (user handle, permissions) in a signed cookie. The endpoints POST /api/users/change-password and POST /api/users/recover-step2 only update the password hash in the database but do not expire current sessions. Because the session is stateless and stored entirely in the client cookie, there is no server-side mechanism to revoke a token once issued. This vulnerability is fixed in 1.18.0.

- [https://github.com/zzzm0919/CVE-2026-44648](https://github.com/zzzm0919/CVE-2026-44648) :  ![starts](https://img.shields.io/github/stars/zzzm0919/CVE-2026-44648.svg) ![forks](https://img.shields.io/github/forks/zzzm0919/CVE-2026-44648.svg)


## CVE-2026-40564
Users are recommended to upgrade to version 1.15.0, which fixes the issue.

- [https://github.com/oscerd/CVE-2026-40564](https://github.com/oscerd/CVE-2026-40564) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-40564.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-40564.svg)


## CVE-2026-39292
 Falco Solutions PHPPageBuilder v0.31.0 contains an unrestricted file upload vulnerability in the pagemanager/pagebuilder module that allows remote attackers to upload arbitrary files and achieve remote code execution. The vulnerability exists due to insufficient validation of uploaded file types and executable content.

- [https://github.com/krishnadevpmelevila/CVE-2026-39292](https://github.com/krishnadevpmelevila/CVE-2026-39292) :  ![starts](https://img.shields.io/github/stars/krishnadevpmelevila/CVE-2026-39292.svg) ![forks](https://img.shields.io/github/forks/krishnadevpmelevila/CVE-2026-39292.svg)


## CVE-2026-26980
 Ghost is a Node.js content management system. Versions 3.24.0 through 6.19.0 allow unauthenticated attackers to perform arbitrary reads from the database. This issue has been fixed in version 6.19.1.

- [https://github.com/ByteWraith1/CVE-2026-26980](https://github.com/ByteWraith1/CVE-2026-26980) :  ![starts](https://img.shields.io/github/stars/ByteWraith1/CVE-2026-26980.svg) ![forks](https://img.shields.io/github/forks/ByteWraith1/CVE-2026-26980.svg)


## CVE-2026-22557
 A malicious actor with access to the network could exploit a Path Traversal vulnerability found in the UniFi Network Application to access files on the underlying system that could be manipulated to access an underlying account.

- [https://github.com/BishopFox/CVE-2026-22557-check](https://github.com/BishopFox/CVE-2026-22557-check) :  ![starts](https://img.shields.io/github/stars/BishopFox/CVE-2026-22557-check.svg) ![forks](https://img.shields.io/github/forks/BishopFox/CVE-2026-22557-check.svg)


## CVE-2026-8697
Successful exploitation could allow an attacker with adjacent network access to obtain administrative credentials through unrestricted authentication attempts and subsequently gain full administrative access to the device, impacting system confidentiality, integrity, and availability.

- [https://github.com/itzmetanjim/cve-2026-8697](https://github.com/itzmetanjim/cve-2026-8697) :  ![starts](https://img.shields.io/github/stars/itzmetanjim/cve-2026-8697.svg) ![forks](https://img.shields.io/github/forks/itzmetanjim/cve-2026-8697.svg)


## CVE-2026-4655
 The Element Pack Addons for Elementor plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the SVG Image Widget in versions up to and including 8.4.2. This is due to insufficient input sanitization and output escaping on SVG content fetched from remote URLs in the render_svg() function. The function fetches SVG content using wp_safe_remote_get() and then directly echoes it to the page without any sanitization, only applying a preg_replace() to add attributes to the SVG tag which does not remove malicious event handlers. This makes it possible for authenticated attackers, with Contributor-level access and above, to inject arbitrary JavaScript in SVG files that will execute whenever a user accesses a page containing the malicious widget.

- [https://github.com/0xmrma/CVE-2026-46552](https://github.com/0xmrma/CVE-2026-46552) :  ![starts](https://img.shields.io/github/stars/0xmrma/CVE-2026-46552.svg) ![forks](https://img.shields.io/github/forks/0xmrma/CVE-2026-46552.svg)


## CVE-2026-4459
 Out of bounds read and write in WebAudio in Google Chrome prior to 146.0.7680.153 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/ex-cal1bur/CVE-2026-44595](https://github.com/ex-cal1bur/CVE-2026-44595) :  ![starts](https://img.shields.io/github/stars/ex-cal1bur/CVE-2026-44595.svg) ![forks](https://img.shields.io/github/forks/ex-cal1bur/CVE-2026-44595.svg)
- [https://github.com/ex-cal1bur/CVE-2026-44596](https://github.com/ex-cal1bur/CVE-2026-44596) :  ![starts](https://img.shields.io/github/stars/ex-cal1bur/CVE-2026-44596.svg) ![forks](https://img.shields.io/github/forks/ex-cal1bur/CVE-2026-44596.svg)


## CVE-2026-1011
The injected content is rendered verbatim when support cases are viewed by other users, including support staff with elevated privileges, allowing execution of arbitrary JavaScript in the victim’s browser context.

- [https://github.com/Xmyronn/CVE-2026-10110-SQLi](https://github.com/Xmyronn/CVE-2026-10110-SQLi) :  ![starts](https://img.shields.io/github/stars/Xmyronn/CVE-2026-10110-SQLi.svg) ![forks](https://img.shields.io/github/forks/Xmyronn/CVE-2026-10110-SQLi.svg)


## CVE-2026-0257
Panorama and Cloud NGFW are not impacted by these issues.

- [https://github.com/sfewer-r7/CVE-2026-0257](https://github.com/sfewer-r7/CVE-2026-0257) :  ![starts](https://img.shields.io/github/stars/sfewer-r7/CVE-2026-0257.svg) ![forks](https://img.shields.io/github/forks/sfewer-r7/CVE-2026-0257.svg)
- [https://github.com/akashsingh0454/CVE-2026-0257-PoC](https://github.com/akashsingh0454/CVE-2026-0257-PoC) :  ![starts](https://img.shields.io/github/stars/akashsingh0454/CVE-2026-0257-PoC.svg) ![forks](https://img.shields.io/github/forks/akashsingh0454/CVE-2026-0257-PoC.svg)


## CVE-2025-68645
 A Local File Inclusion (LFI) vulnerability exists in the Webmail Classic UI of Zimbra Collaboration (ZCS) 10.0 and 10.1 because of improper handling of user-supplied request parameters in the RestFilter servlet. An unauthenticated remote attacker can craft requests to the /h/rest endpoint to influence internal request dispatching, allowing inclusion of arbitrary files from the WebRoot directory.

- [https://github.com/its970/CVE-2025-68645](https://github.com/its970/CVE-2025-68645) :  ![starts](https://img.shields.io/github/stars/its970/CVE-2025-68645.svg) ![forks](https://img.shields.io/github/forks/its970/CVE-2025-68645.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/wiixx44/CVE-2025-55182](https://github.com/wiixx44/CVE-2025-55182) :  ![starts](https://img.shields.io/github/stars/wiixx44/CVE-2025-55182.svg) ![forks](https://img.shields.io/github/forks/wiixx44/CVE-2025-55182.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces.svg)


## CVE-2025-53770
Microsoft is preparing and fully testing a comprehensive update to address this vulnerability.  In the meantime, please make sure that the mitigation provided in this CVE documentation is in place so that you are protected from exploitation.

- [https://github.com/doerrdan/it-sec-toolshell](https://github.com/doerrdan/it-sec-toolshell) :  ![starts](https://img.shields.io/github/stars/doerrdan/it-sec-toolshell.svg) ![forks](https://img.shields.io/github/forks/doerrdan/it-sec-toolshell.svg)


## CVE-2025-47227
 In the Production Environment extension in Netmake ScriptCase through 9.12.006 (23), the Administrator password reset mechanism is mishandled. Making both a GET and a POST request to login.php.is sufficient. An unauthenticated attacker can then bypass authentication via administrator account takeover.

- [https://github.com/Outs1d3r-Net/CVE-2025-47227](https://github.com/Outs1d3r-Net/CVE-2025-47227) :  ![starts](https://img.shields.io/github/stars/Outs1d3r-Net/CVE-2025-47227.svg) ![forks](https://img.shields.io/github/forks/Outs1d3r-Net/CVE-2025-47227.svg)


## CVE-2025-38352
anyway in this case.

- [https://github.com/AnalyticETH/chronomaly-webos](https://github.com/AnalyticETH/chronomaly-webos) :  ![starts](https://img.shields.io/github/stars/AnalyticETH/chronomaly-webos.svg) ![forks](https://img.shields.io/github/forks/AnalyticETH/chronomaly-webos.svg)


## CVE-2025-34327
 This CVE ID was rejected because it was reserved but not used for a vulnerability disclosure.

- [https://github.com/siddolo/gosign-desktop-exploit-poc](https://github.com/siddolo/gosign-desktop-exploit-poc) :  ![starts](https://img.shields.io/github/stars/siddolo/gosign-desktop-exploit-poc.svg) ![forks](https://img.shields.io/github/forks/siddolo/gosign-desktop-exploit-poc.svg)


## CVE-2025-34324
 GoSign Desktop versions 2.4.0 and earlier use an unsigned update manifest for distributing application updates. The manifest contains package URLs and SHA-256 hashes but is not digitally signed, so its authenticity relies solely on the underlying TLS channel. In affected versions, TLS certificate validation can be disabled when a proxy is configured, allowing an attacker who can intercept network traffic to supply a malicious update manifest and corresponding package with a matching hash. This can cause the client to download and install a tampered update, resulting in arbitrary code execution with the privileges of the GoSign Desktop user on Windows and macOS, or with elevated privileges on some Linux deployments. A local attacker who can modify proxy settings may also abuse this behavior to escalate privileges by forcing installation of a crafted update.

- [https://github.com/siddolo/gosign-desktop-exploit-poc](https://github.com/siddolo/gosign-desktop-exploit-poc) :  ![starts](https://img.shields.io/github/stars/siddolo/gosign-desktop-exploit-poc.svg) ![forks](https://img.shields.io/github/forks/siddolo/gosign-desktop-exploit-poc.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/hujiaozhuzhu/CVE-2025-29927__Next.js](https://github.com/hujiaozhuzhu/CVE-2025-29927__Next.js) :  ![starts](https://img.shields.io/github/stars/hujiaozhuzhu/CVE-2025-29927__Next.js.svg) ![forks](https://img.shields.io/github/forks/hujiaozhuzhu/CVE-2025-29927__Next.js.svg)


## CVE-2025-11844
 Hugging Face Smolagents version 1.20.0 contains an XPath injection vulnerability in the search_item_ctrl_f function located in src/smolagents/vision_web_browser.py. The function constructs an XPath query by directly concatenating user-supplied input into the XPath expression without proper sanitization or escaping. This allows an attacker to inject malicious XPath syntax that can alter the intended query logic. The vulnerability enables attackers to bypass search filters, access unintended DOM elements, and disrupt web automation workflows. This can lead to information disclosure, manipulation of AI agent interactions, and compromise the reliability of automated web tasks. The issue is fixed in version 1.22.0.

- [https://github.com/SparshBiswas-AI/CVE-2025-11844-smolagents](https://github.com/SparshBiswas-AI/CVE-2025-11844-smolagents) :  ![starts](https://img.shields.io/github/stars/SparshBiswas-AI/CVE-2025-11844-smolagents.svg) ![forks](https://img.shields.io/github/forks/SparshBiswas-AI/CVE-2025-11844-smolagents.svg)


## CVE-2025-11391
 The PPOM – Product Addons & Custom Fields for WooCommerce plugin for WordPress is vulnerable to arbitrary file uploads due to missing file type validation in the image cropper functionality in all versions up to, and including, 33.0.15. This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible. While the vulnerable code is in the free version, this only affected users with the paid version of the software installed and activated.

- [https://github.com/ayanamifu/CVE-2025-11391](https://github.com/ayanamifu/CVE-2025-11391) :  ![starts](https://img.shields.io/github/stars/ayanamifu/CVE-2025-11391.svg) ![forks](https://img.shields.io/github/forks/ayanamifu/CVE-2025-11391.svg)


## CVE-2025-6389
 The Sneeit Framework plugin for WordPress is vulnerable to Remote Code Execution in all versions up to, and including, 8.3 via the sneeit_articles_pagination_callback() function. This is due to the function accepting user input and then passing that through call_user_func(). This makes it possible for unauthenticated attackers to execute code on the server which can be leveraged to inject backdoors or, for example, create new administrative user accounts.

- [https://github.com/ayanamifu/Blackash-CVE-2025-6389](https://github.com/ayanamifu/Blackash-CVE-2025-6389) :  ![starts](https://img.shields.io/github/stars/ayanamifu/Blackash-CVE-2025-6389.svg) ![forks](https://img.shields.io/github/forks/ayanamifu/Blackash-CVE-2025-6389.svg)


## CVE-2024-31317
 In multiple functions of ZygoteProcess.java, there is a possible way to achieve code execution as any app via WRITE_SECURE_SETTINGS due to unsafe deserialization. This could lead to local escalation of privilege with User execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/vnescape/zygote-CVE-2024-31317](https://github.com/vnescape/zygote-CVE-2024-31317) :  ![starts](https://img.shields.io/github/stars/vnescape/zygote-CVE-2024-31317.svg) ![forks](https://img.shields.io/github/forks/vnescape/zygote-CVE-2024-31317.svg)


## CVE-2024-21413
 Microsoft Outlook Remote Code Execution Vulnerability

- [https://github.com/Dhananjayasj/CVE-2024-21413-Microsoft-Outlook-Remote-Code-Execution-Vulnerability](https://github.com/Dhananjayasj/CVE-2024-21413-Microsoft-Outlook-Remote-Code-Execution-Vulnerability) :  ![starts](https://img.shields.io/github/stars/Dhananjayasj/CVE-2024-21413-Microsoft-Outlook-Remote-Code-Execution-Vulnerability.svg) ![forks](https://img.shields.io/github/forks/Dhananjayasj/CVE-2024-21413-Microsoft-Outlook-Remote-Code-Execution-Vulnerability.svg)


## CVE-2023-35078
 An authentication bypass vulnerability in Ivanti EPMM allows unauthorized users to access restricted functionality or resources of the application without proper authentication.

- [https://github.com/vaishnochaitanya/CVE-2023-35078-Exploit-POC](https://github.com/vaishnochaitanya/CVE-2023-35078-Exploit-POC) :  ![starts](https://img.shields.io/github/stars/vaishnochaitanya/CVE-2023-35078-Exploit-POC.svg) ![forks](https://img.shields.io/github/forks/vaishnochaitanya/CVE-2023-35078-Exploit-POC.svg)


## CVE-2023-30253
 Dolibarr before 17.0.1 allows remote code execution by an authenticated user via an uppercase manipulation: ?PHP instead of ?php in injected data.

- [https://github.com/Jeanback1/CVE-2023-30253-exploit](https://github.com/Jeanback1/CVE-2023-30253-exploit) :  ![starts](https://img.shields.io/github/stars/Jeanback1/CVE-2023-30253-exploit.svg) ![forks](https://img.shields.io/github/forks/Jeanback1/CVE-2023-30253-exploit.svg)


## CVE-2022-22947
 In spring cloud gateway versions prior to 3.1.1+ and 3.0.7+ , applications are vulnerable to a code injection attack when the Gateway Actuator endpoint is enabled, exposed and unsecured. A remote attacker could make a maliciously crafted request that could allow arbitrary remote execution on the remote host.

- [https://github.com/ciri3/spring-cloud-gateway-cve-2022-22947-report](https://github.com/ciri3/spring-cloud-gateway-cve-2022-22947-report) :  ![starts](https://img.shields.io/github/stars/ciri3/spring-cloud-gateway-cve-2022-22947-report.svg) ![forks](https://img.shields.io/github/forks/ciri3/spring-cloud-gateway-cve-2022-22947-report.svg)


## CVE-2022-21241
 Cross-site scripting vulnerability in CSV+ prior to 0.8.1 allows a remote unauthenticated attacker to inject an arbitrary script or an arbitrary OS command via a specially crafted CSV file that contains HTML a tag.

- [https://github.com/nanaao/csv-plus_vulnerability](https://github.com/nanaao/csv-plus_vulnerability) :  ![starts](https://img.shields.io/github/stars/nanaao/csv-plus_vulnerability.svg) ![forks](https://img.shields.io/github/forks/nanaao/csv-plus_vulnerability.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/puckiestyle/CVE-2021-41773](https://github.com/puckiestyle/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/puckiestyle/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/puckiestyle/CVE-2021-41773.svg)


## CVE-2020-9273
 In ProFTPD 1.3.7, it is possible to corrupt the memory pool by interrupting the data transfer channel. This triggers a use-after-free in alloc_pool in pool.c, and possible remote code execution.

- [https://github.com/dukptkey/CVE-2020-9273](https://github.com/dukptkey/CVE-2020-9273) :  ![starts](https://img.shields.io/github/stars/dukptkey/CVE-2020-9273.svg) ![forks](https://img.shields.io/github/forks/dukptkey/CVE-2020-9273.svg)


## CVE-2019-18634
 In Sudo before 1.8.26, if pwfeedback is enabled in /etc/sudoers, users can trigger a stack-based buffer overflow in the privileged sudo process. (pwfeedback is a default setting in Linux Mint and elementary OS; however, it is NOT the default for upstream and many other packages, and would exist only if enabled by an administrator.) The attacker needs to deliver a long string to the stdin of getln() in tgetpass.c.

- [https://github.com/dukptkey/CVE-2019-18634](https://github.com/dukptkey/CVE-2019-18634) :  ![starts](https://img.shields.io/github/stars/dukptkey/CVE-2019-18634.svg) ![forks](https://img.shields.io/github/forks/dukptkey/CVE-2019-18634.svg)


## CVE-2019-9053
 An issue was discovered in CMS Made Simple 2.2.8. It is possible with the News module, through a crafted URL, to achieve unauthenticated blind time-based SQL injection via the m1_idlist parameter.

- [https://github.com/ImperialX1104/Simple-CTF-Writeup](https://github.com/ImperialX1104/Simple-CTF-Writeup) :  ![starts](https://img.shields.io/github/stars/ImperialX1104/Simple-CTF-Writeup.svg) ![forks](https://img.shields.io/github/forks/ImperialX1104/Simple-CTF-Writeup.svg)


## CVE-2018-7600
 Drupal before 7.58, 8.x before 8.3.9, 8.4.x before 8.4.6, and 8.5.x before 8.5.1 allows remote attackers to execute arbitrary code because of an issue affecting multiple subsystems with default or common module configurations.

- [https://github.com/Dungsocool/CVE-2018-7600](https://github.com/Dungsocool/CVE-2018-7600) :  ![starts](https://img.shields.io/github/stars/Dungsocool/CVE-2018-7600.svg) ![forks](https://img.shields.io/github/forks/Dungsocool/CVE-2018-7600.svg)


## CVE-2017-12635
 Due to differences in the Erlang-based JSON parser and JavaScript-based JSON parser, it is possible in Apache CouchDB before 1.7.0 and 2.x before 2.1.1 to submit _users documents with duplicate keys for 'roles' used for access control within the database, including the special case '_admin' role, that denotes administrative users. In combination with CVE-2017-12636 (Remote Code Execution), this can be used to give non-admin users access to arbitrary shell commands on the server as the database system user. The JSON parser differences result in behaviour that if two 'roles' keys are available in the JSON, the second one will be used for authorising the document write, but the first 'roles' key is used for subsequent authorization for the newly created user. By design, users can not assign themselves roles. The vulnerability allows non-admin users to give themselves admin privileges.

- [https://github.com/Dungsocool/CVE-2017-12635_36](https://github.com/Dungsocool/CVE-2017-12635_36) :  ![starts](https://img.shields.io/github/stars/Dungsocool/CVE-2017-12635_36.svg) ![forks](https://img.shields.io/github/forks/Dungsocool/CVE-2017-12635_36.svg)


## CVE-2014-3566
 The SSL protocol 3.0, as used in OpenSSL through 1.0.1i and other products, uses nondeterministic CBC padding, which makes it easier for man-in-the-middle attackers to obtain cleartext data via a padding-oracle attack, aka the "POODLE" issue.

- [https://github.com/jmonge12/Home-Network-Vulnerability-Assessment](https://github.com/jmonge12/Home-Network-Vulnerability-Assessment) :  ![starts](https://img.shields.io/github/stars/jmonge12/Home-Network-Vulnerability-Assessment.svg) ![forks](https://img.shields.io/github/forks/jmonge12/Home-Network-Vulnerability-Assessment.svg)


## CVE-2010-2333
 LiteSpeed Technologies LiteSpeed Web Server 4.0.x before 4.0.15 allows remote attackers to read the source code of scripts via an HTTP request with a null byte followed by a .txt file extension.

- [https://github.com/jmonge12/Home-Network-Vulnerability-Assessment](https://github.com/jmonge12/Home-Network-Vulnerability-Assessment) :  ![starts](https://img.shields.io/github/stars/jmonge12/Home-Network-Vulnerability-Assessment.svg) ![forks](https://img.shields.io/github/forks/jmonge12/Home-Network-Vulnerability-Assessment.svg)

