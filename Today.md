# Update 2025-11-14
## CVE-2025-64403
Users are recommended to upgrade to version 4.1.16, which fixes the issue.

- [https://github.com/makaroonbourne/CVE-2025-64403-Exploit](https://github.com/makaroonbourne/CVE-2025-64403-Exploit) :  ![starts](https://img.shields.io/github/stars/makaroonbourne/CVE-2025-64403-Exploit.svg) ![forks](https://img.shields.io/github/forks/makaroonbourne/CVE-2025-64403-Exploit.svg)


## CVE-2025-63667
 Incorrect access control in SIMICAM v1.16.41-20250725, KEVIEW v1.14.92-20241120, ASECAM v1.14.10-20240725 allows attackers to access sensitive API endpoints without authentication.

- [https://github.com/Remenis/CVE-2025-63667](https://github.com/Remenis/CVE-2025-63667) :  ![starts](https://img.shields.io/github/stars/Remenis/CVE-2025-63667.svg) ![forks](https://img.shields.io/github/forks/Remenis/CVE-2025-63667.svg)


## CVE-2025-63666
 Tenda AC15 v15.03.05.18_multi) issues an authentication cookie that exposes the account password hash to the client and uses a short, low-entropy suffix as the session identifier. An attacker with network access or the ability to run JS in a victim browser can steal the cookie and replay it to access protected resources.

- [https://github.com/Remenis/CVE-2025-63666](https://github.com/Remenis/CVE-2025-63666) :  ![starts](https://img.shields.io/github/stars/Remenis/CVE-2025-63666.svg) ![forks](https://img.shields.io/github/forks/Remenis/CVE-2025-63666.svg)


## CVE-2025-63419
 Cross Site Scripting (XSS) vulnerability in CrushFTP 11.3.6_48. The Web-Based Server has a feature where users can share files, the feature reflects the filename to an emailbody field with no sanitations leading to HTML Injection.

- [https://github.com/MMAKINGDOM/CVE-2025-63419](https://github.com/MMAKINGDOM/CVE-2025-63419) :  ![starts](https://img.shields.io/github/stars/MMAKINGDOM/CVE-2025-63419.svg) ![forks](https://img.shields.io/github/forks/MMAKINGDOM/CVE-2025-63419.svg)


## CVE-2025-63353
 A vulnerability in FiberHome GPON ONU HG6145F1 RP4423 allows the device's factory default Wi-Fi password (WPA/WPA2 pre-shared key) to be predicted from the SSID. The device generates default passwords using a deterministic algorithm that derives the router passphrase from the SSID, enabling an attacker who can observe the SSID to predict the default password without authentication or user interaction.

- [https://github.com/hanianis/CVE-2025-63353](https://github.com/hanianis/CVE-2025-63353) :  ![starts](https://img.shields.io/github/stars/hanianis/CVE-2025-63353.svg) ![forks](https://img.shields.io/github/forks/hanianis/CVE-2025-63353.svg)


## CVE-2025-62215
 Concurrent execution using shared resource with improper synchronization ('race condition') in Windows Kernel allows an authorized attacker to elevate privileges locally.

- [https://github.com/fordeant/CVE-2025-62215](https://github.com/fordeant/CVE-2025-62215) :  ![starts](https://img.shields.io/github/stars/fordeant/CVE-2025-62215.svg) ![forks](https://img.shields.io/github/forks/fordeant/CVE-2025-62215.svg)


## CVE-2025-60724
 Heap-based buffer overflow in Microsoft Graphics Component allows an unauthorized attacker to execute code over a network.

- [https://github.com/Iomarlto/CVE-2025-60724](https://github.com/Iomarlto/CVE-2025-60724) :  ![starts](https://img.shields.io/github/stars/Iomarlto/CVE-2025-60724.svg) ![forks](https://img.shields.io/github/forks/Iomarlto/CVE-2025-60724.svg)


## CVE-2025-60710
 Improper link resolution before file access ('link following') in Host Process for Windows Tasks allows an authorized attacker to elevate privileges locally.

- [https://github.com/Wh04m1001/CVE-2025-60710](https://github.com/Wh04m1001/CVE-2025-60710) :  ![starts](https://img.shields.io/github/stars/Wh04m1001/CVE-2025-60710.svg) ![forks](https://img.shields.io/github/forks/Wh04m1001/CVE-2025-60710.svg)


## CVE-2025-59253
 Improper access control in Microsoft Windows Search Component allows an authorized attacker to deny service locally.

- [https://github.com/zigzagymym1986/CVE-2025-59253](https://github.com/zigzagymym1986/CVE-2025-59253) :  ![starts](https://img.shields.io/github/stars/zigzagymym1986/CVE-2025-59253.svg) ![forks](https://img.shields.io/github/forks/zigzagymym1986/CVE-2025-59253.svg)


## CVE-2025-57310
 A Cross-Site Request Forgery (CSRF) vulnerability in Salmen2/Simple-Faucet-Script v1.07 via crafted POST request to admin.php?p=ads&c=1 allowing attackers to execute arbitrary code.

- [https://github.com/MMAKINGDOM/CVE-2025-57310](https://github.com/MMAKINGDOM/CVE-2025-57310) :  ![starts](https://img.shields.io/github/stars/MMAKINGDOM/CVE-2025-57310.svg) ![forks](https://img.shields.io/github/forks/MMAKINGDOM/CVE-2025-57310.svg)


## CVE-2025-31133
 runc is a CLI tool for spawning and running containers according to the OCI specification. In versions 1.2.7 and below, 1.3.0-rc.1 through 1.3.1, 1.4.0-rc.1 and 1.4.0-rc.2 files, runc would not perform sufficient verification that the source of the bind-mount (i.e., the container's /dev/null) was actually a real /dev/null inode when using the container's /dev/null to mask. This exposes two methods of attack:  an arbitrary mount gadget, leading to host information disclosure, host denial of service, container escape, or a bypassing of maskedPaths. This issue is fixed in versions 1.2.8, 1.3.3 and 1.4.0-rc.3.

- [https://github.com/skynet-f-nvidia/CVE-2025-31133](https://github.com/skynet-f-nvidia/CVE-2025-31133) :  ![starts](https://img.shields.io/github/stars/skynet-f-nvidia/CVE-2025-31133.svg) ![forks](https://img.shields.io/github/forks/skynet-f-nvidia/CVE-2025-31133.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/rgvillanueva28/vulnbox-easy-CVE-2025-29927](https://github.com/rgvillanueva28/vulnbox-easy-CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/rgvillanueva28/vulnbox-easy-CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/rgvillanueva28/vulnbox-easy-CVE-2025-29927.svg)


## CVE-2025-20260
This vulnerability exists because memory buffers are allocated incorrectly when PDF files are processed. An attacker could exploit this vulnerability by submitting a crafted PDF file to be scanned by ClamAV on an affected device. A successful exploit could allow the attacker to trigger a buffer overflow, likely resulting in the termination of the ClamAV scanning process and a DoS condition on the affected software. Although unproven, there is also a possibility that an attacker could leverage the buffer overflow to execute arbitrary code with the privileges of the ClamAV process.

- [https://github.com/keyuraghao/CVE-2025-20260](https://github.com/keyuraghao/CVE-2025-20260) :  ![starts](https://img.shields.io/github/stars/keyuraghao/CVE-2025-20260.svg) ![forks](https://img.shields.io/github/forks/keyuraghao/CVE-2025-20260.svg)


## CVE-2025-13027
 Memory safety bugs present in Firefox 144 and Thunderbird 144. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some of these could have been exploited to run arbitrary code. This vulnerability affects Firefox  145.

- [https://github.com/yourluckyday3-art/CVE-2025-13027-Exploit](https://github.com/yourluckyday3-art/CVE-2025-13027-Exploit) :  ![starts](https://img.shields.io/github/stars/yourluckyday3-art/CVE-2025-13027-Exploit.svg) ![forks](https://img.shields.io/github/forks/yourluckyday3-art/CVE-2025-13027-Exploit.svg)


## CVE-2025-12748
 A flaw was discovered in libvirt in the XML file processing. More specifically, the parsing of user provided XML files was performed before the ACL checks. A malicious user with limited permissions could exploit this flaw by submitting a specially crafted XML file, causing libvirt to allocate too much memory on the host. The excessive memory consumption could lead to a libvirt process crash on the host, resulting in a denial-of-service condition.

- [https://github.com/TERESH1/CVE-2025-12748](https://github.com/TERESH1/CVE-2025-12748) :  ![starts](https://img.shields.io/github/stars/TERESH1/CVE-2025-12748.svg) ![forks](https://img.shields.io/github/forks/TERESH1/CVE-2025-12748.svg)


## CVE-2025-12101
 Cross-Site Scripting (XSS) in NetScaler ADC and NetScaler Gateway when the appliance is configured as a Gateway (VPN virtual server, ICA Proxy, CVPN, RDP Proxy) OR AAA virtual server

- [https://github.com/6h4ack/CVE-2025-12101-checker](https://github.com/6h4ack/CVE-2025-12101-checker) :  ![starts](https://img.shields.io/github/stars/6h4ack/CVE-2025-12101-checker.svg) ![forks](https://img.shields.io/github/forks/6h4ack/CVE-2025-12101-checker.svg)


## CVE-2025-6383
 The WP-PhotoNav plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the plugin's photonav shortcode in all versions up to, and including, 1.2.2 due to insufficient input sanitization and output escaping on user supplied attributes. This makes it possible for authenticated attackers, with contributor-level access and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.

- [https://github.com/Shubham03007/CVE-2025-63830](https://github.com/Shubham03007/CVE-2025-63830) :  ![starts](https://img.shields.io/github/stars/Shubham03007/CVE-2025-63830.svg) ![forks](https://img.shields.io/github/forks/Shubham03007/CVE-2025-63830.svg)


## CVE-2025-5649
 A vulnerability classified as critical has been found in SourceCodester Student Result Management System 1.0. This affects an unknown part of the file /admin/core/new_user of the component Register Interface. The manipulation leads to improper access controls. It is possible to initiate the attack remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/Cherrling/CVE-2025-56499](https://github.com/Cherrling/CVE-2025-56499) :  ![starts](https://img.shields.io/github/stars/Cherrling/CVE-2025-56499.svg) ![forks](https://img.shields.io/github/forks/Cherrling/CVE-2025-56499.svg)


## CVE-2025-4796
 The Eventin plugin for WordPress is vulnerable to privilege escalation via account takeover in all versions up to, and including, 4.0.34. This is due to the plugin not properly validating a user's identity or capability prior to updating their details like email in the 'Eventin\Speaker\Api\SpeakerController::update_item' function. This makes it possible for unauthenticated attackers with contributor-level and above permissions to change arbitrary user's email addresses, including administrators, and leverage that to reset the user's password and gain access to their account.

- [https://github.com/Pwdnx1337/CVE-2025-4796](https://github.com/Pwdnx1337/CVE-2025-4796) :  ![starts](https://img.shields.io/github/stars/Pwdnx1337/CVE-2025-4796.svg) ![forks](https://img.shields.io/github/forks/Pwdnx1337/CVE-2025-4796.svg)


## CVE-2024-48910
 DOMPurify is a DOM-only, super-fast, uber-tolerant XSS sanitizer for HTML, MathML and SVG. DOMPurify was vulnerable to prototype pollution. This vulnerability is fixed in 2.4.2.

- [https://github.com/Alex-Acero-Security/CVE-2024-48910-POC](https://github.com/Alex-Acero-Security/CVE-2024-48910-POC) :  ![starts](https://img.shields.io/github/stars/Alex-Acero-Security/CVE-2024-48910-POC.svg) ![forks](https://img.shields.io/github/forks/Alex-Acero-Security/CVE-2024-48910-POC.svg)


## CVE-2024-47167
 Gradio is an open-source Python package designed for quick prototyping. This vulnerability relates to **Server-Side Request Forgery (SSRF)** in the `/queue/join` endpoint. Gradio’s `async_save_url_to_cache` function allows attackers to force the Gradio server to send HTTP requests to user-controlled URLs. This could enable attackers to target internal servers or services within a local network and possibly exfiltrate data or cause unwanted internal requests. Additionally, the content from these URLs is stored locally, making it easier for attackers to upload potentially malicious files to the server. This impacts users deploying Gradio servers that use components like the Video component which involve URL fetching. Users are advised to upgrade to `gradio=5` to address this issue.  As a workaround, users can disable or heavily restrict URL-based inputs in their Gradio applications to trusted domains only. Additionally, implementing stricter URL validation (such as allowinglist-based validation) and ensuring that local or internal network addresses cannot be requested via the `/queue/join` endpoint can help mitigate the risk of SSRF attacks.

- [https://github.com/alexan011/CVE-2024-47167-Environment-Setup](https://github.com/alexan011/CVE-2024-47167-Environment-Setup) :  ![starts](https://img.shields.io/github/stars/alexan011/CVE-2024-47167-Environment-Setup.svg) ![forks](https://img.shields.io/github/forks/alexan011/CVE-2024-47167-Environment-Setup.svg)


## CVE-2024-43425
 A flaw was found in Moodle. Additional restrictions are required to avoid a remote code execution risk in calculated question types. Note: This requires the capability to add/update questions.

- [https://github.com/kazuya256/Moodle-authenticated-RCE](https://github.com/kazuya256/Moodle-authenticated-RCE) :  ![starts](https://img.shields.io/github/stars/kazuya256/Moodle-authenticated-RCE.svg) ![forks](https://img.shields.io/github/forks/kazuya256/Moodle-authenticated-RCE.svg)


## CVE-2024-23620
 An improper privilege management vulnerability exists in IBM Merge Healthcare eFilm Workstation. A local, authenticated attacker can exploit this vulnerability to escalate privileges to SYSTEM.

- [https://github.com/daniteaxh853/cve_2024_23620](https://github.com/daniteaxh853/cve_2024_23620) :  ![starts](https://img.shields.io/github/stars/daniteaxh853/cve_2024_23620.svg) ![forks](https://img.shields.io/github/forks/daniteaxh853/cve_2024_23620.svg)


## CVE-2024-4890
 A blind SQL injection vulnerability exists in the berriai/litellm application, specifically within the '/team/update' process. The vulnerability arises due to the improper handling of the 'user_id' parameter in the raw SQL query used for deleting users. An attacker can exploit this vulnerability by injecting malicious SQL commands through the 'user_id' parameter, leading to potential unauthorized access to sensitive information such as API keys, user information, and tokens stored in the database. The affected version is 1.27.14.

- [https://github.com/nekr0ff/needrestart-sudo-escalate-cve-2024-4890](https://github.com/nekr0ff/needrestart-sudo-escalate-cve-2024-4890) :  ![starts](https://img.shields.io/github/stars/nekr0ff/needrestart-sudo-escalate-cve-2024-4890.svg) ![forks](https://img.shields.io/github/forks/nekr0ff/needrestart-sudo-escalate-cve-2024-4890.svg)


## CVE-2020-9802
 A logic issue was addressed with improved restrictions. This issue is fixed in iOS 13.5 and iPadOS 13.5, tvOS 13.4.5, watchOS 6.2.5, Safari 13.1.1, iTunes 12.10.7 for Windows, iCloud for Windows 11.2, iCloud for Windows 7.19. Processing maliciously crafted web content may lead to arbitrary code execution.

- [https://github.com/Billy-Ellis/jitsploitation](https://github.com/Billy-Ellis/jitsploitation) :  ![starts](https://img.shields.io/github/stars/Billy-Ellis/jitsploitation.svg) ![forks](https://img.shields.io/github/forks/Billy-Ellis/jitsploitation.svg)


## CVE-2018-6389
 In WordPress through 4.9.2, unauthenticated attackers can cause a denial of service (resource consumption) by using the large list of registered .js files (from wp-includes/script-loader.php) to construct a series of requests to load every file many times.

- [https://github.com/omidsec/CVE-2018-6389](https://github.com/omidsec/CVE-2018-6389) :  ![starts](https://img.shields.io/github/stars/omidsec/CVE-2018-6389.svg) ![forks](https://img.shields.io/github/forks/omidsec/CVE-2018-6389.svg)

