# Update 2025-09-19
## CVE-2025-57055
 WonderCMS 3.5.0 is vulnerable to Server-Side Request Forgery (SSRF) in the custom module installation functionality. An authenticated administrator can supply a malicious URL via the pluginThemeUrl POST parameter. The server fetches the provided URL using curl_exec() without sufficient validation, allowing the attacker to force internal or external HTTP requests.

- [https://github.com/thawphone/CVE-2025-57055](https://github.com/thawphone/CVE-2025-57055) :  ![starts](https://img.shields.io/github/stars/thawphone/CVE-2025-57055.svg) ![forks](https://img.shields.io/github/forks/thawphone/CVE-2025-57055.svg)


## CVE-2025-54918
 Improper authentication in Windows NTLM allows an authorized attacker to elevate privileges over a network.

- [https://github.com/mrk336/From-Foothold-to-Domain-Admin-Weaponizing-CVE-2025-54918-in-Real-World-DevOps](https://github.com/mrk336/From-Foothold-to-Domain-Admin-Weaponizing-CVE-2025-54918-in-Real-World-DevOps) :  ![starts](https://img.shields.io/github/stars/mrk336/From-Foothold-to-Domain-Admin-Weaponizing-CVE-2025-54918-in-Real-World-DevOps.svg) ![forks](https://img.shields.io/github/forks/mrk336/From-Foothold-to-Domain-Admin-Weaponizing-CVE-2025-54918-in-Real-World-DevOps.svg)


## CVE-2025-49144
 Notepad++ is a free and open-source source code editor. In versions 8.8.1 and prior, a privilege escalation vulnerability exists in the Notepad++ v8.8.1 installer that allows unprivileged users to gain SYSTEM-level privileges through insecure executable search paths. An attacker could use social engineering or clickjacking to trick users into downloading both the legitimate installer and a malicious executable to the same directory (typically Downloads folder - which is known as Vulnerable directory). Upon running the installer, the attack executes automatically with SYSTEM privileges. This issue has been fixed and will be released in version 8.8.2.

- [https://github.com/onniio/CVE-2025-49144](https://github.com/onniio/CVE-2025-49144) :  ![starts](https://img.shields.io/github/stars/onniio/CVE-2025-49144.svg) ![forks](https://img.shields.io/github/forks/onniio/CVE-2025-49144.svg)


## CVE-2025-33073
 Improper access control in Windows SMB allows an authorized attacker to elevate privileges over a network.

- [https://github.com/mverschu/CVE-2025-33073](https://github.com/mverschu/CVE-2025-33073) :  ![starts](https://img.shields.io/github/stars/mverschu/CVE-2025-33073.svg) ![forks](https://img.shields.io/github/forks/mverschu/CVE-2025-33073.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/AventurineJ/CVE-2025-29927-Research](https://github.com/AventurineJ/CVE-2025-29927-Research) :  ![starts](https://img.shields.io/github/stars/AventurineJ/CVE-2025-29927-Research.svg) ![forks](https://img.shields.io/github/forks/AventurineJ/CVE-2025-29927-Research.svg)
- [https://github.com/adjscent/vulnerable-nextjs-14-CVE-2025-29927](https://github.com/adjscent/vulnerable-nextjs-14-CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/adjscent/vulnerable-nextjs-14-CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/adjscent/vulnerable-nextjs-14-CVE-2025-29927.svg)


## CVE-2025-9216
 The StoreEngine – Powerful WordPress eCommerce Plugin for Payments, Memberships, Affiliates, Sales & More plugin for WordPress is vulnerable to arbitrary file uploads due to missing file type validation in the import() function in all versions up to, and including, 1.5.0. This makes it possible for authenticated attackers, with Subscriber-level access and above, to upload arbitrary files on the affected site's server which may make remote code execution possible.

- [https://github.com/d0n601/CVE-2025-9216](https://github.com/d0n601/CVE-2025-9216) :  ![starts](https://img.shields.io/github/stars/d0n601/CVE-2025-9216.svg) ![forks](https://img.shields.io/github/forks/d0n601/CVE-2025-9216.svg)


## CVE-2025-9215
 The StoreEngine – Powerful WordPress eCommerce Plugin for Payments, Memberships, Affiliates, Sales & More plugin for WordPress is vulnerable to Path Traversal in all versions up to, and including, 1.5.0 via the file_download() function. This makes it possible for authenticated attackers, with Subscriber-level access and above, to read the contents of arbitrary files on the server, which can contain sensitive information.

- [https://github.com/d0n601/CVE-2025-9215](https://github.com/d0n601/CVE-2025-9215) :  ![starts](https://img.shields.io/github/stars/d0n601/CVE-2025-9215.svg) ![forks](https://img.shields.io/github/forks/d0n601/CVE-2025-9215.svg)


## CVE-2025-8088
     from ESET.

- [https://github.com/Shinkirou789/Cve-2025-8088-WinRar-vulnerability](https://github.com/Shinkirou789/Cve-2025-8088-WinRar-vulnerability) :  ![starts](https://img.shields.io/github/stars/Shinkirou789/Cve-2025-8088-WinRar-vulnerability.svg) ![forks](https://img.shields.io/github/forks/Shinkirou789/Cve-2025-8088-WinRar-vulnerability.svg)


## CVE-2025-6085
 The Make Connector plugin for WordPress is vulnerable to arbitrary file uploads due to misconfigured file type validation in the 'upload_media' function in all versions up to, and including, 1.5.10. This makes it possible for authenticated attackers, with Administrator-level access and above, to upload arbitrary files on the affected site's server which may make remote code execution possible.

- [https://github.com/d0n601/CVE-2025-6085](https://github.com/d0n601/CVE-2025-6085) :  ![starts](https://img.shields.io/github/stars/d0n601/CVE-2025-6085.svg) ![forks](https://img.shields.io/github/forks/d0n601/CVE-2025-6085.svg)


## CVE-2025-5677
 A vulnerability was found in Campcodes Online Recruitment Management System 1.0. It has been rated as critical. This issue affects some unknown processing of the file /admin/ajax.php?action=save_application. The manipulation of the argument position_id leads to sql injection. The attack may be initiated remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/RRespxwnss/CVE-2025-56771](https://github.com/RRespxwnss/CVE-2025-56771) :  ![starts](https://img.shields.io/github/stars/RRespxwnss/CVE-2025-56771.svg) ![forks](https://img.shields.io/github/forks/RRespxwnss/CVE-2025-56771.svg)
- [https://github.com/RRespxwnss/CVE-2025-56772](https://github.com/RRespxwnss/CVE-2025-56772) :  ![starts](https://img.shields.io/github/stars/RRespxwnss/CVE-2025-56772.svg) ![forks](https://img.shields.io/github/forks/RRespxwnss/CVE-2025-56772.svg)


## CVE-2025-3248
code.

- [https://github.com/wand3rlust/CVE-2025-3248](https://github.com/wand3rlust/CVE-2025-3248) :  ![starts](https://img.shields.io/github/stars/wand3rlust/CVE-2025-3248.svg) ![forks](https://img.shields.io/github/forks/wand3rlust/CVE-2025-3248.svg)


## CVE-2024-43630
 Windows Kernel Elevation of Privilege Vulnerability

- [https://github.com/QuasarBinary/CVE-2024-43630-POC](https://github.com/QuasarBinary/CVE-2024-43630-POC) :  ![starts](https://img.shields.io/github/stars/QuasarBinary/CVE-2024-43630-POC.svg) ![forks](https://img.shields.io/github/forks/QuasarBinary/CVE-2024-43630-POC.svg)


## CVE-2024-28397
 An issue in the component js2py.disable_pyimport() of js2py up to v0.74 allows attackers to execute arbitrary code via a crafted API call.

- [https://github.com/vitaciminIPI/CVE-2024-28397-RCE](https://github.com/vitaciminIPI/CVE-2024-28397-RCE) :  ![starts](https://img.shields.io/github/stars/vitaciminIPI/CVE-2024-28397-RCE.svg) ![forks](https://img.shields.io/github/forks/vitaciminIPI/CVE-2024-28397-RCE.svg)
- [https://github.com/nelissandro/CVE-2024-28397-Js2Py-RCE](https://github.com/nelissandro/CVE-2024-28397-Js2Py-RCE) :  ![starts](https://img.shields.io/github/stars/nelissandro/CVE-2024-28397-Js2Py-RCE.svg) ![forks](https://img.shields.io/github/forks/nelissandro/CVE-2024-28397-Js2Py-RCE.svg)


## CVE-2024-9264
 The SQL Expressions experimental feature of Grafana allows for the evaluation of `duckdb` queries containing user input. These queries are insufficiently sanitized before being passed to `duckdb`, leading to a command injection and local file inclusion vulnerability. Any user with the VIEWER or higher permission is capable of executing this attack.  The `duckdb` binary must be present in Grafana's $PATH for this attack to function; by default, this binary is not installed in Grafana distributions.

- [https://github.com/amalpvatayam67/day05-grafana-sqlexpr-lab](https://github.com/amalpvatayam67/day05-grafana-sqlexpr-lab) :  ![starts](https://img.shields.io/github/stars/amalpvatayam67/day05-grafana-sqlexpr-lab.svg) ![forks](https://img.shields.io/github/forks/amalpvatayam67/day05-grafana-sqlexpr-lab.svg)


## CVE-2024-4157
 The Contact Form Plugin by Fluent Forms for Quiz, Survey, and Drag & Drop WP Form Builder plugin for WordPress is vulnerable to PHP Object Injection in all versions up to, and including, 5.1.15 via deserialization of untrusted input in the extractDynamicValues function. This makes it possible for authenticated attackers, with contributor-level access and above, to inject a PHP Object. If a POP chain is present via an additional plugin or theme installed on the target system, it could allow the attacker to delete arbitrary files, retrieve sensitive data, or execute code. Successful exploitation requires the attacker to have "View Form" and "Manage Form" permissions, which must be explicitly set by an administrator. However, this requirement can be bypassed when this vulnerability is chained with CVE-2024-2771.

- [https://github.com/Ch4os1/CVE-2024-4157-SSRF-RCE-Reverse-Shell](https://github.com/Ch4os1/CVE-2024-4157-SSRF-RCE-Reverse-Shell) :  ![starts](https://img.shields.io/github/stars/Ch4os1/CVE-2024-4157-SSRF-RCE-Reverse-Shell.svg) ![forks](https://img.shields.io/github/forks/Ch4os1/CVE-2024-4157-SSRF-RCE-Reverse-Shell.svg)


## CVE-2023-22515
Atlassian Cloud sites are not affected by this vulnerability. If your Confluence site is accessed via an atlassian.net domain, it is hosted by Atlassian and is not vulnerable to this issue. 

- [https://github.com/K4ptor/CVE-2023-22515](https://github.com/K4ptor/CVE-2023-22515) :  ![starts](https://img.shields.io/github/stars/K4ptor/CVE-2023-22515.svg) ![forks](https://img.shields.io/github/forks/K4ptor/CVE-2023-22515.svg)


## CVE-2022-39299
 Passport-SAML is a SAML 2.0 authentication provider for Passport, the Node.js authentication library. A remote attacker may be able to bypass SAML authentication on a website using passport-saml. A successful attack requires that the attacker is in possession of an arbitrary IDP signed XML element. Depending on the IDP used, fully unauthenticated attacks (e.g without access to a valid user) might also be feasible if generation of a signed message can be triggered. Users should upgrade to passport-saml version 3.2.2 or newer. The issue was also present in the beta releases of `node-saml` before version 4.0.0-beta.5. If you cannot upgrade, disabling SAML authentication may be done as a workaround.

- [https://github.com/AventurineJ/CVE-2022-39299-Research](https://github.com/AventurineJ/CVE-2022-39299-Research) :  ![starts](https://img.shields.io/github/stars/AventurineJ/CVE-2022-39299-Research.svg) ![forks](https://img.shields.io/github/forks/AventurineJ/CVE-2022-39299-Research.svg)


## CVE-2022-0847
 A flaw was found in the way the "flags" member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/cypherlobo/DirtyPipe-BSI](https://github.com/cypherlobo/DirtyPipe-BSI) :  ![starts](https://img.shields.io/github/stars/cypherlobo/DirtyPipe-BSI.svg) ![forks](https://img.shields.io/github/forks/cypherlobo/DirtyPipe-BSI.svg)


## CVE-2020-1938
 When using the Apache JServ Protocol (AJP), care must be taken when trusting incoming connections to Apache Tomcat. Tomcat treats AJP connections as having higher trust than, for example, a similar HTTP connection. If such connections are available to an attacker, they can be exploited in ways that may be surprising. In Apache Tomcat 9.0.0.M1 to 9.0.0.30, 8.5.0 to 8.5.50 and 7.0.0 to 7.0.99, Tomcat shipped with an AJP Connector enabled by default that listened on all configured IP addresses. It was expected (and recommended in the security guide) that this Connector would be disabled if not required. This vulnerability report identified a mechanism that allowed: - returning arbitrary files from anywhere in the web application - processing any file in the web application as a JSP Further, if the web application allowed file upload and stored those files within the web application (or the attacker was able to control the content of the web application by some other means) then this, along with the ability to process a file as a JSP, made remote code execution possible. It is important to note that mitigation is only required if an AJP port is accessible to untrusted users. Users wishing to take a defence-in-depth approach and block the vector that permits returning arbitrary files and execution as JSP may upgrade to Apache Tomcat 9.0.31, 8.5.51 or 7.0.100 or later. A number of changes were made to the default AJP Connector configuration in 9.0.31 to harden the default configuration. It is likely that users upgrading to 9.0.31, 8.5.51 or 7.0.100 or later will need to make small changes to their configurations.

- [https://github.com/Joshua8821/CNVD](https://github.com/Joshua8821/CNVD) :  ![starts](https://img.shields.io/github/stars/Joshua8821/CNVD.svg) ![forks](https://img.shields.io/github/forks/Joshua8821/CNVD.svg)


## CVE-2019-3396
 The Widget Connector macro in Atlassian Confluence Server before version 6.6.12 (the fixed version for 6.6.x), from version 6.7.0 before 6.12.3 (the fixed version for 6.12.x), from version 6.13.0 before 6.13.3 (the fixed version for 6.13.x), and from version 6.14.0 before 6.14.2 (the fixed version for 6.14.x), allows remote attackers to achieve path traversal and remote code execution on a Confluence Server or Data Center instance via server-side template injection.

- [https://github.com/HK4zCzi/CVE-2019-3396-Velocity-Server-Side-Template-Injection](https://github.com/HK4zCzi/CVE-2019-3396-Velocity-Server-Side-Template-Injection) :  ![starts](https://img.shields.io/github/stars/HK4zCzi/CVE-2019-3396-Velocity-Server-Side-Template-Injection.svg) ![forks](https://img.shields.io/github/forks/HK4zCzi/CVE-2019-3396-Velocity-Server-Side-Template-Injection.svg)

