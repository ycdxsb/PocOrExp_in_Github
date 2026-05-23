# Update 2026-05-23
## CVE-2026-45829
 A pre-authentication, code injection vulnerability in version 1.0.0 or later of the ChromaDB Python project allows an unauthenticated attacker to run arbitrary code on the server by sending a malicious model repository and trust_remote_code set to true in the /api/v2/tenants/{tenant}/databases/{db}/collections endpoint.

- [https://github.com/0xBlackash/CVE-2026-45829](https://github.com/0xBlackash/CVE-2026-45829) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-45829.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-45829.svg)


## CVE-2026-45585
We are issuing this CVE to provide mitigation guidance that can be implemented to protect against this vulnerability until the security update is made available.

- [https://github.com/everest90909/YellowKey-WinRE-Remediation](https://github.com/everest90909/YellowKey-WinRE-Remediation) :  ![starts](https://img.shields.io/github/stars/everest90909/YellowKey-WinRE-Remediation.svg) ![forks](https://img.shields.io/github/forks/everest90909/YellowKey-WinRE-Remediation.svg)


## CVE-2026-45250
Because the bounds check on the supplementary groups list occurs after the kernel stack buffer has already been written, an unprivileged local user may trigger the overflow without holding any special privilege.  Successful exploitation may allow an attacker to execute arbitrary code in the context of the kernel, allowing an unprivileged local user to gain elevated privileges on the affected system.

- [https://github.com/venglin/setcred](https://github.com/venglin/setcred) :  ![starts](https://img.shields.io/github/stars/venglin/setcred.svg) ![forks](https://img.shields.io/github/forks/venglin/setcred.svg)


## CVE-2026-43500
page_pool RX, GRO).  The OOM/trace handling already in place is reused.

- [https://github.com/First-John/cve_2026_frag_family_fix](https://github.com/First-John/cve_2026_frag_family_fix) :  ![starts](https://img.shields.io/github/stars/First-John/cve_2026_frag_family_fix.svg) ![forks](https://img.shields.io/github/forks/First-John/cve_2026_frag_family_fix.svg)


## CVE-2026-43284
destination-frag path or fall back to skb_cow_data().

- [https://github.com/Aiyakami/rust_dirtyfrag](https://github.com/Aiyakami/rust_dirtyfrag) :  ![starts](https://img.shields.io/github/stars/Aiyakami/rust_dirtyfrag.svg) ![forks](https://img.shields.io/github/forks/Aiyakami/rust_dirtyfrag.svg)
- [https://github.com/First-John/cve_2026_frag_family_fix](https://github.com/First-John/cve_2026_frag_family_fix) :  ![starts](https://img.shields.io/github/stars/First-John/cve_2026_frag_family_fix.svg) ![forks](https://img.shields.io/github/forks/First-John/cve_2026_frag_family_fix.svg)


## CVE-2026-42048
 Langflow is a tool for building and deploying AI-powered agents and workflows. Prior to 1.9.0, Langflow is vulnerable to Path Traversal in the Knowledge Bases API (DELETE /api/v1/knowledge_bases). This occurs because user-supplied knowledge base names are concatenated directly into file paths without proper sanitization or boundary validation. An authenticated attacker can exploit this flaw to delete arbitrary directories anywhere on the server's filesystem, leading to data loss and potential service disruption. This vulnerability is fixed in 1.9.0.

- [https://github.com/EQSTLab/CVE-2026-42048](https://github.com/EQSTLab/CVE-2026-42048) :  ![starts](https://img.shields.io/github/stars/EQSTLab/CVE-2026-42048.svg) ![forks](https://img.shields.io/github/forks/EQSTLab/CVE-2026-42048.svg)


## CVE-2026-41940
 cPanel and WHM versions after 11.40 contain an authentication bypass vulnerability in the login flow that allows unauthenticated remote attackers to gain unauthorized access to the control panel.

- [https://github.com/Unleasheddotc/cve-2026-41940-exploit](https://github.com/Unleasheddotc/cve-2026-41940-exploit) :  ![starts](https://img.shields.io/github/stars/Unleasheddotc/cve-2026-41940-exploit.svg) ![forks](https://img.shields.io/github/forks/Unleasheddotc/cve-2026-41940-exploit.svg)


## CVE-2026-41091
 Improper link resolution before file access ('link following') in Microsoft Defender allows an authorized attacker to elevate privileges locally.

- [https://github.com/0xBlackash/CVE-2026-41091](https://github.com/0xBlackash/CVE-2026-41091) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-41091.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-41091.svg)


## CVE-2026-40369
 Untrusted pointer dereference in Windows Kernel allows an authorized attacker to elevate privileges locally.

- [https://github.com/ercihan/CVE-2026-40369](https://github.com/ercihan/CVE-2026-40369) :  ![starts](https://img.shields.io/github/stars/ercihan/CVE-2026-40369.svg) ![forks](https://img.shields.io/github/forks/ercihan/CVE-2026-40369.svg)


## CVE-2026-33829
 Exposure of sensitive information to an unauthorized actor in Windows Snipping Tool allows an unauthorized attacker to perform spoofing over a network.

- [https://github.com/rahultb-sec/CVE-2026-33829-Writeup](https://github.com/rahultb-sec/CVE-2026-33829-Writeup) :  ![starts](https://img.shields.io/github/stars/rahultb-sec/CVE-2026-33829-Writeup.svg) ![forks](https://img.shields.io/github/forks/rahultb-sec/CVE-2026-33829-Writeup.svg)


## CVE-2026-31635
Reject authenticator lengths that exceed the remaining packet payload.

- [https://github.com/0xFuffM3/CVE-2026-31635-DirtyDecrypt](https://github.com/0xFuffM3/CVE-2026-31635-DirtyDecrypt) :  ![starts](https://img.shields.io/github/stars/0xFuffM3/CVE-2026-31635-DirtyDecrypt.svg) ![forks](https://img.shields.io/github/forks/0xFuffM3/CVE-2026-31635-DirtyDecrypt.svg)


## CVE-2026-24061
 telnetd in GNU Inetutils through 2.7 allows remote authentication bypass via a "-f root" value for the USER environment variable.

- [https://github.com/Risma2025/Forensic-Investigation-on-CVE-2026-24061-GNU-InetUtils-telnetd-Authentication-Bypass-Vulnerability](https://github.com/Risma2025/Forensic-Investigation-on-CVE-2026-24061-GNU-InetUtils-telnetd-Authentication-Bypass-Vulnerability) :  ![starts](https://img.shields.io/github/stars/Risma2025/Forensic-Investigation-on-CVE-2026-24061-GNU-InetUtils-telnetd-Authentication-Bypass-Vulnerability.svg) ![forks](https://img.shields.io/github/forks/Risma2025/Forensic-Investigation-on-CVE-2026-24061-GNU-InetUtils-telnetd-Authentication-Bypass-Vulnerability.svg)


## CVE-2026-9082
This issue affects Drupal core: from 8.9.0 before 10.4.10, from 10.5.0 before 10.5.10, from 10.6.0 before 10.6.9, from 11.0.0 before 11.1.10, from 11.2.0 before 11.2.12, from 11.3.0 before 11.3.10.

- [https://github.com/7h30th3r0n3/CVE-2026-9082-Drupal-PoC](https://github.com/7h30th3r0n3/CVE-2026-9082-Drupal-PoC) :  ![starts](https://img.shields.io/github/stars/7h30th3r0n3/CVE-2026-9082-Drupal-PoC.svg) ![forks](https://img.shields.io/github/forks/7h30th3r0n3/CVE-2026-9082-Drupal-PoC.svg)
- [https://github.com/0xBlackash/CVE-2026-9082](https://github.com/0xBlackash/CVE-2026-9082) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-9082.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-9082.svg)
- [https://github.com/HORKimhab/CVE-2026-9082](https://github.com/HORKimhab/CVE-2026-9082) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-9082.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-9082.svg)
- [https://github.com/lysophavin18/cve-2026-9082](https://github.com/lysophavin18/cve-2026-9082) :  ![starts](https://img.shields.io/github/stars/lysophavin18/cve-2026-9082.svg) ![forks](https://img.shields.io/github/forks/lysophavin18/cve-2026-9082.svg)
- [https://github.com/ywh-jfellus/CVE-2026-9082](https://github.com/ywh-jfellus/CVE-2026-9082) :  ![starts](https://img.shields.io/github/stars/ywh-jfellus/CVE-2026-9082.svg) ![forks](https://img.shields.io/github/forks/ywh-jfellus/CVE-2026-9082.svg)


## CVE-2026-5118
 The Divi Form Builder plugin for WordPress is vulnerable to privilege escalation in versions up to, and including, 5.1.2. This is due to the plugin accepting a user-controlled 'role' parameter from POST data during user registration without validating it against the form's configured default_user_role setting. This makes it possible for unauthenticated attackers to create administrator accounts by tampering with the role parameter during registration.

- [https://github.com/zycoder0day/CVE-2026-5118](https://github.com/zycoder0day/CVE-2026-5118) :  ![starts](https://img.shields.io/github/stars/zycoder0day/CVE-2026-5118.svg) ![forks](https://img.shields.io/github/forks/zycoder0day/CVE-2026-5118.svg)
- [https://github.com/Jenderal92/CVE-2026-5118](https://github.com/Jenderal92/CVE-2026-5118) :  ![starts](https://img.shields.io/github/stars/Jenderal92/CVE-2026-5118.svg) ![forks](https://img.shields.io/github/forks/Jenderal92/CVE-2026-5118.svg)
- [https://github.com/puj790201-lab/CVE-2026-5118](https://github.com/puj790201-lab/CVE-2026-5118) :  ![starts](https://img.shields.io/github/stars/puj790201-lab/CVE-2026-5118.svg) ![forks](https://img.shields.io/github/forks/puj790201-lab/CVE-2026-5118.svg)


## CVE-2026-4885
 The Piotnet Addons for Elementor Pro plugin for WordPress is vulnerable to arbitrary file upload due to missing file type validation in the 'pafe_ajax_form_builder' function in all versions up to, and including, 7.1.70. The plugin uses an incomplete extension blacklist that only blocks php, phpt, php5, php7, and exe extensions, while allowing dangerous extensions such as .phar or .phtml to be uploaded. This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible. Note: The exploit can only be exploited if a file field is added to the form.

- [https://github.com/xShadow-Here/CVE-2026-4885](https://github.com/xShadow-Here/CVE-2026-4885) :  ![starts](https://img.shields.io/github/stars/xShadow-Here/CVE-2026-4885.svg) ![forks](https://img.shields.io/github/forks/xShadow-Here/CVE-2026-4885.svg)


## CVE-2026-4668
 The Booking for Appointments and Events Calendar - Amelia plugin for WordPress is vulnerable to SQL Injection via the `sort` parameter in the payments listing endpoint in all versions up to, and including, 2.1.2. This is due to insufficient escaping on the user-supplied `sort` parameter and lack of sufficient preparation on the existing SQL query in `PaymentRepository.php`, where the sort field is interpolated directly into an ORDER BY clause without sanitization or whitelist validation. PDO prepared statements do not protect ORDER BY column names. GET requests also skip Amelia's nonce validation entirely. This makes it possible for authenticated attackers, with Manager-level (`wpamelia-manager`) access and above, to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database via time-based blind SQL injection.

- [https://github.com/r0binak/CVE-2026-46680](https://github.com/r0binak/CVE-2026-46680) :  ![starts](https://img.shields.io/github/stars/r0binak/CVE-2026-46680.svg) ![forks](https://img.shields.io/github/forks/r0binak/CVE-2026-46680.svg)


## CVE-2026-4652
An attacker with network access to the NVMe/TCP target can trigger an unauthenticated Denial of Service condition on the affected machine.

- [https://github.com/N1et/CVE-2026-46529](https://github.com/N1et/CVE-2026-46529) :  ![starts](https://img.shields.io/github/stars/N1et/CVE-2026-46529.svg) ![forks](https://img.shields.io/github/forks/N1et/CVE-2026-46529.svg)


## CVE-2026-3876
 The Prismatic plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the 'prismatic_encoded' pseudo-shortcode in all versions up to, and including, 3.7.3. This is due to insufficient input sanitization and output escaping on user-supplied attributes within the 'prismatic_decode' function. This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page by submitting a comment containing a crafted 'prismatic_encoded' pseudo-shortcode.

- [https://github.com/D7EAD/CVE-2026-38765](https://github.com/D7EAD/CVE-2026-38765) :  ![starts](https://img.shields.io/github/stars/D7EAD/CVE-2026-38765.svg) ![forks](https://img.shields.io/github/forks/D7EAD/CVE-2026-38765.svg)
- [https://github.com/D7EAD/CVE-2026-38764](https://github.com/D7EAD/CVE-2026-38764) :  ![starts](https://img.shields.io/github/stars/D7EAD/CVE-2026-38764.svg) ![forks](https://img.shields.io/github/forks/D7EAD/CVE-2026-38764.svg)
- [https://github.com/D7EAD/CVE-2026-38763](https://github.com/D7EAD/CVE-2026-38763) :  ![starts](https://img.shields.io/github/stars/D7EAD/CVE-2026-38763.svg) ![forks](https://img.shields.io/github/forks/D7EAD/CVE-2026-38763.svg)
- [https://github.com/D7EAD/CVE-2026-38766](https://github.com/D7EAD/CVE-2026-38766) :  ![starts](https://img.shields.io/github/stars/D7EAD/CVE-2026-38766.svg) ![forks](https://img.shields.io/github/forks/D7EAD/CVE-2026-38766.svg)


## CVE-2026-3622
This vulnerability affects TL-WR841N v14  EN_0.9.1 4.19 Build 260303 Rel.42399n (V14_260303) and  US_0.9.1.4.19 Build 260312 Rel. 49108n (V14_0304).

- [https://github.com/NullByte8080/CVE-2026-36229](https://github.com/NullByte8080/CVE-2026-36229) :  ![starts](https://img.shields.io/github/stars/NullByte8080/CVE-2026-36229.svg) ![forks](https://img.shields.io/github/forks/NullByte8080/CVE-2026-36229.svg)


## CVE-2026-0908
 Use after free in ANGLE in Google Chrome prior to 144.0.7559.59 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: Low)

- [https://github.com/lylzjnqe/CVE-2026-0908-Chrome-0-day-RCE](https://github.com/lylzjnqe/CVE-2026-0908-Chrome-0-day-RCE) :  ![starts](https://img.shields.io/github/stars/lylzjnqe/CVE-2026-0908-Chrome-0-day-RCE.svg) ![forks](https://img.shields.io/github/forks/lylzjnqe/CVE-2026-0908-Chrome-0-day-RCE.svg)


## CVE-2026-0300
Prisma Access, Cloud NGFW and Panorama appliances are not impacted by this vulnerability.

- [https://github.com/lu4m575/CVE-2026-0300](https://github.com/lu4m575/CVE-2026-0300) :  ![starts](https://img.shields.io/github/stars/lu4m575/CVE-2026-0300.svg) ![forks](https://img.shields.io/github/forks/lu4m575/CVE-2026-0300.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces.svg)


## CVE-2025-66177
 There is a Stack overflow Vulnerability in the device Search and Discovery feature of Hikvision NVR/DVR/CVR/IPC models. If exploited, an attacker on the same local area network (LAN) could cause the device to malfunction by sending specially crafted packets to an unpatched device.

- [https://github.com/ang3lL/CVE-2025-66177](https://github.com/ang3lL/CVE-2025-66177) :  ![starts](https://img.shields.io/github/stars/ang3lL/CVE-2025-66177.svg) ![forks](https://img.shields.io/github/forks/ang3lL/CVE-2025-66177.svg)


## CVE-2025-39247
 There is an Access Control Vulnerability in some HikCentral Professional versions. This could allow an unauthenticated user to obtain the admin permission.

- [https://github.com/Sita-Technologies/CVE-2025-39247](https://github.com/Sita-Technologies/CVE-2025-39247) :  ![starts](https://img.shields.io/github/stars/Sita-Technologies/CVE-2025-39247.svg) ![forks](https://img.shields.io/github/forks/Sita-Technologies/CVE-2025-39247.svg)


## CVE-2025-27591
 A privilege escalation vulnerability existed in the Below service prior to v0.9.0 due to the creation of a world-writable directory at /var/log/below. This could have allowed local unprivileged users to escalate to root privileges through symlink attacks that manipulate files such as /etc/shadow.

- [https://github.com/umutcamliyurt/CVE-2025-27591](https://github.com/umutcamliyurt/CVE-2025-27591) :  ![starts](https://img.shields.io/github/stars/umutcamliyurt/CVE-2025-27591.svg) ![forks](https://img.shields.io/github/forks/umutcamliyurt/CVE-2025-27591.svg)


## CVE-2025-9999
 Some payload elements of the messages sent between two stations in a networking architecture are not properly checked on the receiving station allowing an attacker to execute unauthorized commands in the application.

- [https://github.com/24520597-blip/CVE-2025-99999](https://github.com/24520597-blip/CVE-2025-99999) :  ![starts](https://img.shields.io/github/stars/24520597-blip/CVE-2025-99999.svg) ![forks](https://img.shields.io/github/forks/24520597-blip/CVE-2025-99999.svg)


## CVE-2024-6678
 An issue was discovered in GitLab CE/EE affecting all versions starting from 8.14 prior to 17.1.7, starting from 17.2 prior to 17.2.5, and starting from 17.3 prior to 17.3.2, which allows an attacker to trigger a pipeline as an arbitrary user under certain circumstances.

- [https://github.com/FaLLenSKiLL1/CVE-2024-6678](https://github.com/FaLLenSKiLL1/CVE-2024-6678) :  ![starts](https://img.shields.io/github/stars/FaLLenSKiLL1/CVE-2024-6678.svg) ![forks](https://img.shields.io/github/forks/FaLLenSKiLL1/CVE-2024-6678.svg)


## CVE-2023-32233
 In the Linux kernel through 6.3.1, a use-after-free in Netfilter nf_tables when processing batch requests can be abused to perform arbitrary read and write operations on kernel memory. Unprivileged local users can obtain root privileges. This occurs because anonymous sets are mishandled.

- [https://github.com/Destawell/gemini-2.5-pro-nf-tables-red-teamin](https://github.com/Destawell/gemini-2.5-pro-nf-tables-red-teamin) :  ![starts](https://img.shields.io/github/stars/Destawell/gemini-2.5-pro-nf-tables-red-teamin.svg) ![forks](https://img.shields.io/github/forks/Destawell/gemini-2.5-pro-nf-tables-red-teamin.svg)


## CVE-2023-25813
 Sequelize is a Node.js ORM tool. In versions prior to 6.19.1 a SQL injection exploit exists related to replacements. Parameters which are passed through replacements are not properly escaped which can lead to arbitrary SQL injection depending on the specific queries in use. The issue has been fixed in Sequelize 6.19.1. Users are advised to upgrade. Users unable to upgrade should not use the `replacements` and the `where` option in the same query.

- [https://github.com/h-gunp/CVE-2023-25813-TEST](https://github.com/h-gunp/CVE-2023-25813-TEST) :  ![starts](https://img.shields.io/github/stars/h-gunp/CVE-2023-25813-TEST.svg) ![forks](https://img.shields.io/github/forks/h-gunp/CVE-2023-25813-TEST.svg)


## CVE-2022-26927
 Windows Graphics Component Remote Code Execution Vulnerability

- [https://github.com/CrackerCat/CVE-2022-26927](https://github.com/CrackerCat/CVE-2022-26927) :  ![starts](https://img.shields.io/github/stars/CrackerCat/CVE-2022-26927.svg) ![forks](https://img.shields.io/github/forks/CrackerCat/CVE-2022-26927.svg)


## CVE-2022-26627
 Online Project Time Management System v1.0 was discovered to contain an arbitrary file write vulnerability which allows attackers to execute arbitrary code via a crafted HTML file.

- [https://github.com/qerogram/BUG_WEB](https://github.com/qerogram/BUG_WEB) :  ![starts](https://img.shields.io/github/stars/qerogram/BUG_WEB.svg) ![forks](https://img.shields.io/github/forks/qerogram/BUG_WEB.svg)


## CVE-2022-22965
 A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the application to run on Tomcat as a WAR deployment. If the application is deployed as a Spring Boot executable jar, i.e. the default, it is not vulnerable to the exploit. However, the nature of the vulnerability is more general, and there may be other ways to exploit it.

- [https://github.com/felisha-elmer/Sandbox-Challenge-Spring4Shell-CVE-2022-22965-](https://github.com/felisha-elmer/Sandbox-Challenge-Spring4Shell-CVE-2022-22965-) :  ![starts](https://img.shields.io/github/stars/felisha-elmer/Sandbox-Challenge-Spring4Shell-CVE-2022-22965-.svg) ![forks](https://img.shields.io/github/forks/felisha-elmer/Sandbox-Challenge-Spring4Shell-CVE-2022-22965-.svg)


## CVE-2022-0847
 A flaw was found in the way the "flags" member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/Scouserr/cve-2022-0847-poc-dockerimage](https://github.com/Scouserr/cve-2022-0847-poc-dockerimage) :  ![starts](https://img.shields.io/github/stars/Scouserr/cve-2022-0847-poc-dockerimage.svg) ![forks](https://img.shields.io/github/forks/Scouserr/cve-2022-0847-poc-dockerimage.svg)


## CVE-2021-34527
pNote that the security updates released on and after July 6, 2021 contain protections for CVE-2021-1675 and the additional remote code execution exploit in the Windows Print Spooler service known as “PrintNightmare”, documented in CVE-2021-34527./p

- [https://github.com/fengjixuchui/CVE-2021-34527-1675](https://github.com/fengjixuchui/CVE-2021-34527-1675) :  ![starts](https://img.shields.io/github/stars/fengjixuchui/CVE-2021-34527-1675.svg) ![forks](https://img.shields.io/github/forks/fengjixuchui/CVE-2021-34527-1675.svg)


## CVE-2021-1675
 Windows Print Spooler Remote Code Execution Vulnerability

- [https://github.com/fengjixuchui/CVE-2021-34527-1675](https://github.com/fengjixuchui/CVE-2021-34527-1675) :  ![starts](https://img.shields.io/github/stars/fengjixuchui/CVE-2021-34527-1675.svg) ![forks](https://img.shields.io/github/forks/fengjixuchui/CVE-2021-34527-1675.svg)


## CVE-2020-28458
 All versions of package datatables.net are vulnerable to Prototype Pollution due to an incomplete fix for https://snyk.io/vuln/SNYK-JS-DATATABLESNET-598806.

- [https://github.com/fazilbaig1/CVE-2020-28458](https://github.com/fazilbaig1/CVE-2020-28458) :  ![starts](https://img.shields.io/github/stars/fazilbaig1/CVE-2020-28458.svg) ![forks](https://img.shields.io/github/forks/fazilbaig1/CVE-2020-28458.svg)
- [https://github.com/Raka200juta/28458](https://github.com/Raka200juta/28458) :  ![starts](https://img.shields.io/github/stars/Raka200juta/28458.svg) ![forks](https://img.shields.io/github/forks/Raka200juta/28458.svg)


## CVE-2020-28413
 In MantisBT 2.24.3, SQL Injection can occur in the parameter "access" of the mc_project_get_users function through the API SOAP.

- [https://github.com/EthicalHCOP/CVE-2020-28413_Mantis2.24.3-SQLi-SOAP](https://github.com/EthicalHCOP/CVE-2020-28413_Mantis2.24.3-SQLi-SOAP) :  ![starts](https://img.shields.io/github/stars/EthicalHCOP/CVE-2020-28413_Mantis2.24.3-SQLi-SOAP.svg) ![forks](https://img.shields.io/github/forks/EthicalHCOP/CVE-2020-28413_Mantis2.24.3-SQLi-SOAP.svg)


## CVE-2020-28243
 An issue was discovered in SaltStack Salt before 3002.5. The minion's restartcheck is vulnerable to command injection via a crafted process name. This allows for a local privilege escalation by any user able to create a files on the minion in a non-blacklisted directory.

- [https://github.com/stealthcopter/CVE-2020-28243](https://github.com/stealthcopter/CVE-2020-28243) :  ![starts](https://img.shields.io/github/stars/stealthcopter/CVE-2020-28243.svg) ![forks](https://img.shields.io/github/forks/stealthcopter/CVE-2020-28243.svg)


## CVE-2020-28052
 An issue was discovered in Legion of the Bouncy Castle BC Java 1.65 and 1.66. The OpenBSDBCrypt.checkPassword utility method compared incorrect data when checking the password, allowing incorrect passwords to indicate they were matching with previously hashed ones that were different.

- [https://github.com/kurenaif/CVE-2020-28052_PoC](https://github.com/kurenaif/CVE-2020-28052_PoC) :  ![starts](https://img.shields.io/github/stars/kurenaif/CVE-2020-28052_PoC.svg) ![forks](https://img.shields.io/github/forks/kurenaif/CVE-2020-28052_PoC.svg)
- [https://github.com/madstap/bouncy-castle-generative-test-poc](https://github.com/madstap/bouncy-castle-generative-test-poc) :  ![starts](https://img.shields.io/github/stars/madstap/bouncy-castle-generative-test-poc.svg) ![forks](https://img.shields.io/github/forks/madstap/bouncy-castle-generative-test-poc.svg)


## CVE-2020-28018
 Exim 4 before 4.94.2 allows Use After Free in smtp_reset in certain situations that may be common for builds with OpenSSL.

- [https://github.com/dorkerdevil/CVE-2020-28018](https://github.com/dorkerdevil/CVE-2020-28018) :  ![starts](https://img.shields.io/github/stars/dorkerdevil/CVE-2020-28018.svg) ![forks](https://img.shields.io/github/forks/dorkerdevil/CVE-2020-28018.svg)
- [https://github.com/zr0tt/CVE-2020-28018](https://github.com/zr0tt/CVE-2020-28018) :  ![starts](https://img.shields.io/github/stars/zr0tt/CVE-2020-28018.svg) ![forks](https://img.shields.io/github/forks/zr0tt/CVE-2020-28018.svg)


## CVE-2020-1967
 Server or client applications that call the SSL_check_chain() function during or after a TLS 1.3 handshake may crash due to a NULL pointer dereference as a result of incorrect handling of the "signature_algorithms_cert" TLS extension. The crash occurs if an invalid or unrecognised signature algorithm is received from the peer. This could be exploited by a malicious peer in a Denial of Service attack. OpenSSL version 1.1.1d, 1.1.1e, and 1.1.1f are affected by this issue. This issue did not affect OpenSSL versions prior to 1.1.1d. Fixed in OpenSSL 1.1.1g (Affected 1.1.1d-1.1.1f).

- [https://github.com/irsl/CVE-2020-1967](https://github.com/irsl/CVE-2020-1967) :  ![starts](https://img.shields.io/github/stars/irsl/CVE-2020-1967.svg) ![forks](https://img.shields.io/github/forks/irsl/CVE-2020-1967.svg)


## CVE-2019-10068
 An issue was discovered in Kentico 12.0.x before 12.0.15, 11.0.x before 11.0.48, 10.0.x before 10.0.52, and 9.x versions. Due to a failure to validate security headers, it was possible for a specially crafted request to the staging service to bypass the initial authentication and proceed to deserialize user-controlled .NET object input. This deserialization then led to unauthenticated remote code execution on the server where the Kentico instance was hosted.

- [https://github.com/0x7a-zip/CVE-2019-10068-PoC](https://github.com/0x7a-zip/CVE-2019-10068-PoC) :  ![starts](https://img.shields.io/github/stars/0x7a-zip/CVE-2019-10068-PoC.svg) ![forks](https://img.shields.io/github/forks/0x7a-zip/CVE-2019-10068-PoC.svg)


## CVE-2019-8943
 WordPress through 5.0.3 allows Path Traversal in wp_crop_image(). An attacker (who has privileges to crop an image) can write the output image to an arbitrary directory via a filename containing two image extensions and ../ sequences, such as a filename ending with the .jpg?/../../file.jpg substring.

- [https://github.com/SpeatX/Wordpress-Crop-RCE](https://github.com/SpeatX/Wordpress-Crop-RCE) :  ![starts](https://img.shields.io/github/stars/SpeatX/Wordpress-Crop-RCE.svg) ![forks](https://img.shields.io/github/forks/SpeatX/Wordpress-Crop-RCE.svg)


## CVE-2019-8942
 WordPress before 4.9.9 and 5.x before 5.0.1 allows remote code execution because an _wp_attached_file Post Meta entry can be changed to an arbitrary string, such as one ending with a .jpg?file.php substring. An attacker with author privileges can execute arbitrary code by uploading a crafted image containing PHP code in the Exif metadata. Exploitation can leverage CVE-2019-8943.

- [https://github.com/SpeatX/Wordpress-Crop-RCE](https://github.com/SpeatX/Wordpress-Crop-RCE) :  ![starts](https://img.shields.io/github/stars/SpeatX/Wordpress-Crop-RCE.svg) ![forks](https://img.shields.io/github/forks/SpeatX/Wordpress-Crop-RCE.svg)

