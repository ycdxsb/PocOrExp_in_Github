# Update 2026-02-07
## CVE-2026-25253
 OpenClaw (aka clawdbot or Moltbot) before 2026.1.29 obtains a gatewayUrl value from a query string and automatically makes a WebSocket connection without prompting, sending a token value.

- [https://github.com/adibirzu/openclaw-security-monitor](https://github.com/adibirzu/openclaw-security-monitor) :  ![starts](https://img.shields.io/github/stars/adibirzu/openclaw-security-monitor.svg) ![forks](https://img.shields.io/github/forks/adibirzu/openclaw-security-monitor.svg)


## CVE-2026-24061
 telnetd in GNU Inetutils through 2.7 allows remote authentication bypass via a "-f root" value for the USER environment variable.

- [https://github.com/killsystema/scan-cve-2026-24061](https://github.com/killsystema/scan-cve-2026-24061) :  ![starts](https://img.shields.io/github/stars/killsystema/scan-cve-2026-24061.svg) ![forks](https://img.shields.io/github/forks/killsystema/scan-cve-2026-24061.svg)


## CVE-2026-24049
 wheel is a command line tool for manipulating Python wheel files, as defined in PEP 427. In versions 0.40.0 through 0.46.1, the unpack function is vulnerable to file permission modification through mishandling of file permissions after extraction. The logic blindly trusts the filename from the archive header for the chmod operation, even though the extraction process itself might have sanitized the path. Attackers can craft a malicious wheel file that, when unpacked, changes the permissions of critical system files (e.g., /etc/passwd, SSH keys, config files), allowing for Privilege Escalation or arbitrary code execution by modifying now-writable scripts. This issue has been fixed in version 0.46.2.

- [https://github.com/kriskimmerle/wheelaudit](https://github.com/kriskimmerle/wheelaudit) :  ![starts](https://img.shields.io/github/stars/kriskimmerle/wheelaudit.svg) ![forks](https://img.shields.io/github/forks/kriskimmerle/wheelaudit.svg)


## CVE-2026-21509
 Reliance on untrusted inputs in a security decision in Microsoft Office allows an unauthorized attacker to bypass a security feature locally.

- [https://github.com/kaizensecurity/CVE-2026-21509](https://github.com/kaizensecurity/CVE-2026-21509) :  ![starts](https://img.shields.io/github/stars/kaizensecurity/CVE-2026-21509.svg) ![forks](https://img.shields.io/github/forks/kaizensecurity/CVE-2026-21509.svg)


## CVE-2026-1953
 Nukegraphic CMS v3.1.2 contains a stored cross-site scripting (XSS) vulnerability in the user profile edit functionality at /ngc-cms/user-edit-profile.php. The application fails to properly sanitize user input in the name field before storing it in the database and rendering it across multiple CMS pages. An authenticated attacker with low privileges can inject malicious JavaScript payloads through the profile edit request, which are then executed site-wide whenever the affected user's name is displayed. This allows the attacker to execute arbitrary JavaScript in the context of other users' sessions, potentially leading to session hijacking, credential theft, or unauthorized actions performed on behalf of victims.

- [https://github.com/carlosbudiman/CVE-2026-1953-Disclosure](https://github.com/carlosbudiman/CVE-2026-1953-Disclosure) :  ![starts](https://img.shields.io/github/stars/carlosbudiman/CVE-2026-1953-Disclosure.svg) ![forks](https://img.shields.io/github/forks/carlosbudiman/CVE-2026-1953-Disclosure.svg)


## CVE-2025-69906
 Monstra CMS v3.0.4 contains an arbitrary file upload vulnerability in the Files Manager plugin. The application relies on blacklist-based file extension validation and stores uploaded files directly in a web-accessible directory. Under typical server configurations, this can allow an attacker to upload files that are interpreted as executable code, resulting in remote code execution.

- [https://github.com/cypherdavy/CVE-2025-69906-Monstra-CMS-3.0.4-Arbitrary-File-Upload-to-RCE](https://github.com/cypherdavy/CVE-2025-69906-Monstra-CMS-3.0.4-Arbitrary-File-Upload-to-RCE) :  ![starts](https://img.shields.io/github/stars/cypherdavy/CVE-2025-69906-Monstra-CMS-3.0.4-Arbitrary-File-Upload-to-RCE.svg) ![forks](https://img.shields.io/github/forks/cypherdavy/CVE-2025-69906-Monstra-CMS-3.0.4-Arbitrary-File-Upload-to-RCE.svg)


## CVE-2025-68723
 Axigen Mail Server before 10.5.57 contains multiple stored Cross-Site Scripting (XSS) vulnerabilities in the WebAdmin interface. Three instances exist: (1) the log file name parameter in the Local Services Log page, (2) certificate file content in the SSL Certificates View Usage feature, and (3) the Certificate File name parameter in the WebMail Listeners SSL settings. Attackers can inject malicious JavaScript payloads that execute in administrators' browsers when they access affected pages or features, enabling privilege escalation attacks where low-privileged admins can force high-privileged admins to perform unauthorized actions.

- [https://github.com/osmancanvural/CVE-2025-68723](https://github.com/osmancanvural/CVE-2025-68723) :  ![starts](https://img.shields.io/github/stars/osmancanvural/CVE-2025-68723.svg) ![forks](https://img.shields.io/github/forks/osmancanvural/CVE-2025-68723.svg)


## CVE-2025-68722
 Axigen Mail Server before 10.5.57 and 10.6.x before 10.6.26 contains a Cross-Site Request Forgery (CSRF) vulnerability in the WebAdmin interface through improper handling of the _s (breadcrumb) parameter. The application accepts state-changing requests via the GET method and automatically processes base64-encoded commands queued in the _s parameter immediately after administrator authentication. Attackers can craft malicious URLs that, when clicked by administrators, execute arbitrary administrative actions upon login without further user interaction, including creating rogue administrator accounts or modifying critical server configurations.

- [https://github.com/osmancanvural/CVE-2025-68722](https://github.com/osmancanvural/CVE-2025-68722) :  ![starts](https://img.shields.io/github/stars/osmancanvural/CVE-2025-68722.svg) ![forks](https://img.shields.io/github/forks/osmancanvural/CVE-2025-68722.svg)


## CVE-2025-68721
 Axigen Mail Server before 10.5.57 contains an improper access control vulnerability in the WebAdmin interface. A delegated admin account with zero permissions can bypass access control checks and gain unauthorized access to the SSL Certificates management endpoint (page=sslcerts). This allows the attacker to view, download, upload, and delete SSL certificate files, despite lacking the necessary privileges to access the Security & Filtering section.

- [https://github.com/osmancanvural/CVE-2025-68721](https://github.com/osmancanvural/CVE-2025-68721) :  ![starts](https://img.shields.io/github/stars/osmancanvural/CVE-2025-68721.svg) ![forks](https://img.shields.io/github/forks/osmancanvural/CVE-2025-68721.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-14x](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-14x) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-14x.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-14x.svg)


## CVE-2025-32463
 Sudo before 1.9.17p1 allows local users to obtain root access because /etc/nsswitch.conf from a user-controlled directory is used with the --chroot option.

- [https://github.com/SpycioKon/CVE-2025-32463](https://github.com/SpycioKon/CVE-2025-32463) :  ![starts](https://img.shields.io/github/stars/SpycioKon/CVE-2025-32463.svg) ![forks](https://img.shields.io/github/forks/SpycioKon/CVE-2025-32463.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/rgvillanueva28/vulnbox-easy-CVE-2025-29927](https://github.com/rgvillanueva28/vulnbox-easy-CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/rgvillanueva28/vulnbox-easy-CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/rgvillanueva28/vulnbox-easy-CVE-2025-29927.svg)


## CVE-2025-24054
 External control of file name or path in Windows NTLM allows an unauthorized attacker to perform spoofing over a network.

- [https://github.com/DukeSec97/CVE-2025-24054](https://github.com/DukeSec97/CVE-2025-24054) :  ![starts](https://img.shields.io/github/stars/DukeSec97/CVE-2025-24054.svg) ![forks](https://img.shields.io/github/forks/DukeSec97/CVE-2025-24054.svg)


## CVE-2025-10042
 The Quiz Maker plugin for WordPress is vulnerable to SQL Injection via spoofed IP headers in all versions up to, and including, 6.7.0.56 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query.  This makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database. This is only exploitable in configurations where the server is set up to retrieve the IP from a user-supplied field like `X-Forwarded-For` and limit users by IP is enabled.

- [https://github.com/Tifa-dev/WordPress-Quiz-Maker-SQLi-Exploit-CVE-2025-10042-](https://github.com/Tifa-dev/WordPress-Quiz-Maker-SQLi-Exploit-CVE-2025-10042-) :  ![starts](https://img.shields.io/github/stars/Tifa-dev/WordPress-Quiz-Maker-SQLi-Exploit-CVE-2025-10042-.svg) ![forks](https://img.shields.io/github/forks/Tifa-dev/WordPress-Quiz-Maker-SQLi-Exploit-CVE-2025-10042-.svg)


## CVE-2025-7088
 A vulnerability, which was classified as critical, was found in Belkin F9K1122 1.00.33. This affects the function formPPPoESetup of the file /goform/formPPPoESetup of the component webs. The manipulation of the argument pppUserName leads to stack-based buffer overflow. It is possible to initiate the attack remotely. The exploit has been disclosed to the public and may be used. The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/HowieHz/CVE-2025-70886](https://github.com/HowieHz/CVE-2025-70886) :  ![starts](https://img.shields.io/github/stars/HowieHz/CVE-2025-70886.svg) ![forks](https://img.shields.io/github/forks/HowieHz/CVE-2025-70886.svg)


## CVE-2025-5585
 The SiteOrigin Widgets Bundle plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the `data-url` DOM Element Attribute in all versions up to, and including, 1.68.4 due to insufficient input sanitization and output escaping. This makes it possible for authenticated attackers, with Contributor-level access and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.

- [https://github.com/Vivz13/CVE-2025-55853](https://github.com/Vivz13/CVE-2025-55853) :  ![starts](https://img.shields.io/github/stars/Vivz13/CVE-2025-55853.svg) ![forks](https://img.shields.io/github/forks/Vivz13/CVE-2025-55853.svg)


## CVE-2025-2304
When a user wishes to change his password, the 'updated_ajax' method of the UsersController is called. The vulnerability stems from the use of the dangerous permit! method, which allows all parameters to pass through without any filtering.

- [https://github.com/sparrowhawk1113/Exploit-for-CVE-2025-2304](https://github.com/sparrowhawk1113/Exploit-for-CVE-2025-2304) :  ![starts](https://img.shields.io/github/stars/sparrowhawk1113/Exploit-for-CVE-2025-2304.svg) ![forks](https://img.shields.io/github/forks/sparrowhawk1113/Exploit-for-CVE-2025-2304.svg)


## CVE-2024-46987
 Camaleon CMS is a dynamic and advanced content management system based on Ruby on Rails. A path traversal vulnerability accessible via MediaController's download_private_file method allows authenticated users to download any file on the web server Camaleon CMS is running on (depending on the file permissions). This issue may lead to Information Disclosure. This issue has been addressed in release version 2.8.2. Users are advised to upgrade. There are no known workarounds for this vulnerability.

- [https://github.com/Rival420/CVE-2024-46987](https://github.com/Rival420/CVE-2024-46987) :  ![starts](https://img.shields.io/github/stars/Rival420/CVE-2024-46987.svg) ![forks](https://img.shields.io/github/forks/Rival420/CVE-2024-46987.svg)
- [https://github.com/advaitpathak21/CVE-2024-46987](https://github.com/advaitpathak21/CVE-2024-46987) :  ![starts](https://img.shields.io/github/stars/advaitpathak21/CVE-2024-46987.svg) ![forks](https://img.shields.io/github/forks/advaitpathak21/CVE-2024-46987.svg)


## CVE-2024-32964
 Lobe Chat is a chatbot framework that supports speech synthesis, multimodal, and extensible Function Call plugin system. Prior to 0.150.6, lobe-chat had an unauthorized Server-Side Request Forgery vulnerability in the /api/proxy endpoint. An attacker can construct malicious requests to cause Server-Side Request Forgery without logging in, attack intranet services, and leak sensitive information.

- [https://github.com/StephenQSstarThomas/aaa-agentxploit-example](https://github.com/StephenQSstarThomas/aaa-agentxploit-example) :  ![starts](https://img.shields.io/github/stars/StephenQSstarThomas/aaa-agentxploit-example.svg) ![forks](https://img.shields.io/github/forks/StephenQSstarThomas/aaa-agentxploit-example.svg)


## CVE-2024-5084
 The Hash Form – Drag & Drop Form Builder plugin for WordPress is vulnerable to arbitrary file uploads due to missing file type validation in the 'file_upload_action' function in all versions up to, and including, 1.1.0. This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible.

- [https://github.com/RedTeamBlueTeam/CVE-2024-5084-Red-Team](https://github.com/RedTeamBlueTeam/CVE-2024-5084-Red-Team) :  ![starts](https://img.shields.io/github/stars/RedTeamBlueTeam/CVE-2024-5084-Red-Team.svg) ![forks](https://img.shields.io/github/forks/RedTeamBlueTeam/CVE-2024-5084-Red-Team.svg)


## CVE-2022-1471
 SnakeYaml's Constructor() class does not restrict types which can be instantiated during deserialization. Deserializing yaml content provided by an attacker can lead to remote code execution. We recommend using SnakeYaml's SafeConsturctor when parsing untrusted content to restrict deserialization. We recommend upgrading to version 2.0 and beyond.

- [https://github.com/seal-sec-demo-2/yaml-payload](https://github.com/seal-sec-demo-2/yaml-payload) :  ![starts](https://img.shields.io/github/stars/seal-sec-demo-2/yaml-payload.svg) ![forks](https://img.shields.io/github/forks/seal-sec-demo-2/yaml-payload.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/ch4os443/CVE-2021-41773](https://github.com/ch4os443/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/ch4os443/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/ch4os443/CVE-2021-41773.svg)

