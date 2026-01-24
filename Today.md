# Update 2026-01-24
## CVE-2026-24061
 telnetd in GNU Inetutils through 2.7 allows remote authentication bypass via a "-f root" value for the USER environment variable.

- [https://github.com/leonjza/inetutils-telnetd-auth-bypass](https://github.com/leonjza/inetutils-telnetd-auth-bypass) :  ![starts](https://img.shields.io/github/stars/leonjza/inetutils-telnetd-auth-bypass.svg) ![forks](https://img.shields.io/github/forks/leonjza/inetutils-telnetd-auth-bypass.svg)
- [https://github.com/JayGLXR/CVE-2026-24061-POC](https://github.com/JayGLXR/CVE-2026-24061-POC) :  ![starts](https://img.shields.io/github/stars/JayGLXR/CVE-2026-24061-POC.svg) ![forks](https://img.shields.io/github/forks/JayGLXR/CVE-2026-24061-POC.svg)
- [https://github.com/parameciumzhang/Tell-Me-Root](https://github.com/parameciumzhang/Tell-Me-Root) :  ![starts](https://img.shields.io/github/stars/parameciumzhang/Tell-Me-Root.svg) ![forks](https://img.shields.io/github/forks/parameciumzhang/Tell-Me-Root.svg)
- [https://github.com/TryA9ain/CVE-2026-24061](https://github.com/TryA9ain/CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/TryA9ain/CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/TryA9ain/CVE-2026-24061.svg)
- [https://github.com/duy-31/CVE-2026-24061---telnetd](https://github.com/duy-31/CVE-2026-24061---telnetd) :  ![starts](https://img.shields.io/github/stars/duy-31/CVE-2026-24061---telnetd.svg) ![forks](https://img.shields.io/github/forks/duy-31/CVE-2026-24061---telnetd.svg)
- [https://github.com/yanxinwu946/CVE-2026-24061--telnetd](https://github.com/yanxinwu946/CVE-2026-24061--telnetd) :  ![starts](https://img.shields.io/github/stars/yanxinwu946/CVE-2026-24061--telnetd.svg) ![forks](https://img.shields.io/github/forks/yanxinwu946/CVE-2026-24061--telnetd.svg)
- [https://github.com/h3athen/CVE-2026-24061](https://github.com/h3athen/CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/h3athen/CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/h3athen/CVE-2026-24061.svg)
- [https://github.com/SafeBreach-Labs/CVE-2026-24061](https://github.com/SafeBreach-Labs/CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/SafeBreach-Labs/CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/SafeBreach-Labs/CVE-2026-24061.svg)
- [https://github.com/Chocapikk/CVE-2026-24061](https://github.com/Chocapikk/CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/Chocapikk/CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/Chocapikk/CVE-2026-24061.svg)


## CVE-2026-22444
Users can mitigate this by enabling Solr's RuleBasedAuthorizationPlugin (if disabled) and configuring a permission-list that prevents untrusted users from creating new Solr cores.  Users should also upgrade to Apache Solr 9.10.1 or greater, which contain fixes for this issue.

- [https://github.com/dptsec/CVE-2026-22444](https://github.com/dptsec/CVE-2026-22444) :  ![starts](https://img.shields.io/github/stars/dptsec/CVE-2026-22444.svg) ![forks](https://img.shields.io/github/forks/dptsec/CVE-2026-22444.svg)


## CVE-2026-22200
 Enhancesoft osTicket versions 1.18.x prior to 1.18.3 and 1.17.x prior to 1.17.7 contain an arbitrary file read vulnerability in the ticket PDF export functionality. A remote attacker can submit a ticket containing crafted rich-text HTML that includes PHP filter expressions which are insufficiently sanitized before being processed by the mPDF PDF generator during export. When the attacker exports the ticket to PDF, the generated PDF can embed the contents of attacker-selected files from the server filesystem as bitmap images, allowing disclosure of sensitive local files in the context of the osTicket application user. This issue is exploitable in default configurations where guests may create tickets and access ticket status, or where self-registration is enabled.

- [https://github.com/horizon3ai/CVE-2026-22200](https://github.com/horizon3ai/CVE-2026-22200) :  ![starts](https://img.shields.io/github/stars/horizon3ai/CVE-2026-22200.svg) ![forks](https://img.shields.io/github/forks/horizon3ai/CVE-2026-22200.svg)


## CVE-2026-21962
 Vulnerability in the Oracle HTTP Server, Oracle Weblogic Server Proxy Plug-in product of Oracle Fusion Middleware (component: Weblogic Server Proxy Plug-in for Apache HTTP Server, Weblogic Server Proxy Plug-in for IIS).  Supported versions that are affected are 12.2.1.4.0, 14.1.1.0.0 and  14.1.2.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle HTTP Server, Oracle Weblogic Server Proxy Plug-in.  While the vulnerability is in Oracle HTTP Server, Oracle Weblogic Server Proxy Plug-in, attacks may significantly impact additional products (scope change).  Successful attacks of this vulnerability can result in  unauthorized creation, deletion or modification access to critical data or all Oracle HTTP Server, Oracle Weblogic Server Proxy Plug-in accessible data as well as  unauthorized access to critical data or complete access to all Oracle HTTP Server, Oracle Weblogic Server Proxy Plug-in accessible data. Note: Affected version for Weblogic Server Proxy Plug-in for IIS is 12.2.1.4.0 only. CVSS 3.1 Base Score 10.0 (Confidentiality and Integrity impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N).

- [https://github.com/samael0x4/CVE-2026-21962](https://github.com/samael0x4/CVE-2026-21962) :  ![starts](https://img.shields.io/github/stars/samael0x4/CVE-2026-21962.svg) ![forks](https://img.shields.io/github/forks/samael0x4/CVE-2026-21962.svg)
- [https://github.com/gglessner/cve_2026_21962_scanner](https://github.com/gglessner/cve_2026_21962_scanner) :  ![starts](https://img.shields.io/github/stars/gglessner/cve_2026_21962_scanner.svg) ![forks](https://img.shields.io/github/forks/gglessner/cve_2026_21962_scanner.svg)


## CVE-2026-20045
Note: Cisco has assigned this security advisory a Security Impact Rating (SIR) of Critical rather than High as the score indicates. The reason is that exploitation of this vulnerability could result in an attacker elevating privileges to root.

- [https://github.com/Ashwesker/Ashwesker-CVE-2026-20045](https://github.com/Ashwesker/Ashwesker-CVE-2026-20045) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2026-20045.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2026-20045.svg)


## CVE-2026-0920
 The LA-Studio Element Kit for Elementor plugin for WordPress is vulnerable to Administrative User Creation in all versions up to, and including, 1.5.6.3. This is due to the 'ajax_register_handle' function not restricting what user roles a user can register with. This makes it possible for unauthenticated attackers to supply the 'lakit_bkrole' parameter during registration and gain administrator access to the site.

- [https://github.com/Galaxy-sc/CVE-2026-0920-WordPress-LA-Studio-Exploit](https://github.com/Galaxy-sc/CVE-2026-0920-WordPress-LA-Studio-Exploit) :  ![starts](https://img.shields.io/github/stars/Galaxy-sc/CVE-2026-0920-WordPress-LA-Studio-Exploit.svg) ![forks](https://img.shields.io/github/forks/Galaxy-sc/CVE-2026-0920-WordPress-LA-Studio-Exploit.svg)


## CVE-2026-0622
 Open 5GS WebUI uses a hard-coded JWT signing key (change-me) whenever the environment variable JWT_SECRET_KEY is unset

- [https://github.com/cyberdudebivash/CYBERDUDEBIVASH-5G-Core-Key-Rotation-Ghost-Admin-Auditor](https://github.com/cyberdudebivash/CYBERDUDEBIVASH-5G-Core-Key-Rotation-Ghost-Admin-Auditor) :  ![starts](https://img.shields.io/github/stars/cyberdudebivash/CYBERDUDEBIVASH-5G-Core-Key-Rotation-Ghost-Admin-Auditor.svg) ![forks](https://img.shields.io/github/forks/cyberdudebivash/CYBERDUDEBIVASH-5G-Core-Key-Rotation-Ghost-Admin-Auditor.svg)


## CVE-2026-0594
 The List Site Contributors plugin for WordPress is vulnerable to Reflected Cross-Site Scripting via the 'alpha' parameter in versions up to, and including, 1.1.8 due to insufficient input sanitization and output escaping. This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that execute if they can successfully trick a user into performing an action such as clicking on a link.

- [https://github.com/m4sh-wacker/CVE-2026-0594-ListSiteContributors-Plugin-Exploit](https://github.com/m4sh-wacker/CVE-2026-0594-ListSiteContributors-Plugin-Exploit) :  ![starts](https://img.shields.io/github/stars/m4sh-wacker/CVE-2026-0594-ListSiteContributors-Plugin-Exploit.svg) ![forks](https://img.shields.io/github/forks/m4sh-wacker/CVE-2026-0594-ListSiteContributors-Plugin-Exploit.svg)


## CVE-2025-70899
 PHPgurukul Online Course Registration v3.1 lacks Cross-Site Request Forgery (CSRF) protection on all administrative forms. An attacker can perform unauthorized actions on behalf of authenticated administrators by tricking them into visiting a malicious webpage.

- [https://github.com/mathavamoorthi/CVE-2025-70899](https://github.com/mathavamoorthi/CVE-2025-70899) :  ![starts](https://img.shields.io/github/stars/mathavamoorthi/CVE-2025-70899.svg) ![forks](https://img.shields.io/github/forks/mathavamoorthi/CVE-2025-70899.svg)


## CVE-2025-69822
 An issue in Atomberg Atomberg Erica Smart Fan Firmware Version: V1.0.36 allows an attacker to obtain sensitive information and escalate privileges via a crafted deauth frame

- [https://github.com/CipherX1802/CVE-2025-69822-Atomberg_Erica_SmatFan_Security_Assessment](https://github.com/CipherX1802/CVE-2025-69822-Atomberg_Erica_SmatFan_Security_Assessment) :  ![starts](https://img.shields.io/github/stars/CipherX1802/CVE-2025-69822-Atomberg_Erica_SmatFan_Security_Assessment.svg) ![forks](https://img.shields.io/github/forks/CipherX1802/CVE-2025-69822-Atomberg_Erica_SmatFan_Security_Assessment.svg)


## CVE-2025-69821
 An issue in Beat XP VEGA Smartwatch (Firmware Version - RB303ATV006229) allows an attacker to cause a denial of service via the BLE connection

- [https://github.com/CipherX1802/CVE-2025-69821-Beat-XP-Vega-Smartwatch-Security-Assessment](https://github.com/CipherX1802/CVE-2025-69821-Beat-XP-Vega-Smartwatch-Security-Assessment) :  ![starts](https://img.shields.io/github/stars/CipherX1802/CVE-2025-69821-Beat-XP-Vega-Smartwatch-Security-Assessment.svg) ![forks](https://img.shields.io/github/forks/CipherX1802/CVE-2025-69821-Beat-XP-Vega-Smartwatch-Security-Assessment.svg)


## CVE-2025-69612
 A path traversal vulnerability exists in TMS Management Console (version 6.3.7.27386.20250818) from TMS Global Software. The "Download Template" function in the profile dashboard does not neutralize directory traversal sequences (../) in the filePath parameter, allowing authenticated users to read arbitrary files, such as the server's Web.config.

- [https://github.com/Cr0wld3r/CVE-2025-69612](https://github.com/Cr0wld3r/CVE-2025-69612) :  ![starts](https://img.shields.io/github/stars/Cr0wld3r/CVE-2025-69612.svg) ![forks](https://img.shields.io/github/forks/Cr0wld3r/CVE-2025-69612.svg)


## CVE-2025-68613
 n8n is an open source workflow automation platform. Versions starting with 0.211.0 and prior to 1.120.4, 1.121.1, and 1.122.0 contain a critical Remote Code Execution (RCE) vulnerability in their workflow expression evaluation system. Under certain conditions, expressions supplied by authenticated users during workflow configuration may be evaluated in an execution context that is not sufficiently isolated from the underlying runtime. An authenticated attacker could abuse this behavior to execute arbitrary code with the privileges of the n8n process. Successful exploitation may lead to full compromise of the affected instance, including unauthorized access to sensitive data, modification of workflows, and execution of system-level operations. This issue has been fixed in versions 1.120.4, 1.121.1, and 1.122.0. Users are strongly advised to upgrade to a patched version, which introduces additional safeguards to restrict expression evaluation. If upgrading is not immediately possible, administrators should consider the following temporary mitigations: Limit workflow creation and editing permissions to fully trusted users only; and/or deploy n8n in a hardened environment with restricted operating system privileges and network access to reduce the impact of potential exploitation. These workarounds do not fully eliminate the risk and should only be used as short-term measures.

- [https://github.com/Victorhugofariasvieir66/relatorio-n8n.md](https://github.com/Victorhugofariasvieir66/relatorio-n8n.md) :  ![starts](https://img.shields.io/github/stars/Victorhugofariasvieir66/relatorio-n8n.md.svg) ![forks](https://img.shields.io/github/forks/Victorhugofariasvieir66/relatorio-n8n.md.svg)


## CVE-2025-67303
 An issue in ComfyUI-Manager prior to version 3.38 allowed remote attackers to potentially manipulate its configuration and critical data. This was due to the application storing its files in an insufficiently protected location that was accessible via the web interface

- [https://github.com/ExploreUnknowed/CVE-2025-67303](https://github.com/ExploreUnknowed/CVE-2025-67303) :  ![starts](https://img.shields.io/github/stars/ExploreUnknowed/CVE-2025-67303.svg) ![forks](https://img.shields.io/github/forks/ExploreUnknowed/CVE-2025-67303.svg)


## CVE-2025-67221
 The orjson.dumps function in orjson thru 3.11.4 does not limit recursion for deeply nested JSON documents.

- [https://github.com/kpatsakis/CVE-2025-67221](https://github.com/kpatsakis/CVE-2025-67221) :  ![starts](https://img.shields.io/github/stars/kpatsakis/CVE-2025-67221.svg) ![forks](https://img.shields.io/github/forks/kpatsakis/CVE-2025-67221.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces.svg)


## CVE-2025-65742
 An unauthenticated Broken Function Level Authorization (BFLA) vulnerability in Newgen OmniDocs v11.0 allows attackers to obtain sensitive information and execute a full account takeover via a crafted API request.

- [https://github.com/CBx216/CVE-Newgen-Software-Advisories](https://github.com/CBx216/CVE-Newgen-Software-Advisories) :  ![starts](https://img.shields.io/github/stars/CBx216/CVE-Newgen-Software-Advisories.svg) ![forks](https://img.shields.io/github/forks/CBx216/CVE-Newgen-Software-Advisories.svg)


## CVE-2025-64516
 GLPI is a free asset and IT management software package. Prior to 10.0.21 and 11.0.3, an unauthorized user can access GLPI documents attached to any item (ticket, asset, ...). If the public FAQ is enabled, this unauthorized access can be performed by an anonymous user. This vulnerability is fixed in 10.0.21 and 11.0.3.

- [https://github.com/ArdNoir/CVE-2025-64516](https://github.com/ArdNoir/CVE-2025-64516) :  ![starts](https://img.shields.io/github/stars/ArdNoir/CVE-2025-64516.svg) ![forks](https://img.shields.io/github/forks/ArdNoir/CVE-2025-64516.svg)


## CVE-2025-55182
 A pre-authentication remote code execution vulnerability exists in React Server Components versions 19.0.0, 19.1.0, 19.1.1, and 19.2.0 including the following packages: react-server-dom-parcel, react-server-dom-turbopack, and react-server-dom-webpack. The vulnerable code unsafely deserializes payloads from HTTP requests to Server Function endpoints.

- [https://github.com/grp-ops/react2shell](https://github.com/grp-ops/react2shell) :  ![starts](https://img.shields.io/github/stars/grp-ops/react2shell.svg) ![forks](https://img.shields.io/github/forks/grp-ops/react2shell.svg)


## CVE-2025-38248
---truncated---

- [https://github.com/guard-wait/CVE-2025-38248_EXP](https://github.com/guard-wait/CVE-2025-38248_EXP) :  ![starts](https://img.shields.io/github/stars/guard-wait/CVE-2025-38248_EXP.svg) ![forks](https://img.shields.io/github/forks/guard-wait/CVE-2025-38248_EXP.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/Grand-Moomin/Vuln-Next.js-CVE-2025-29927](https://github.com/Grand-Moomin/Vuln-Next.js-CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/Grand-Moomin/Vuln-Next.js-CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/Grand-Moomin/Vuln-Next.js-CVE-2025-29927.svg)


## CVE-2025-29774
 xml-crypto is an XML digital signature and encryption library for Node.js. An attacker may be able to exploit a vulnerability in versions prior to 6.0.1, 3.2.1, and 2.1.6 to bypass authentication or authorization mechanisms in systems that rely on xml-crypto for verifying signed XML documents. The vulnerability allows an attacker to modify a valid signed XML message in a way that still passes signature verification checks. For example, it could be used to alter critical identity or access control attributes, enabling an attacker with a valid account to escalate privileges or impersonate another user. Users of versions 6.0.0 and prior should upgrade to version 6.0.1 to receive a fix. Those who are still using v2.x or v3.x should upgrade to patched versions 2.1.6 or 3.2.1, respectively.

- [https://github.com/Elinam03/Signature-Forge](https://github.com/Elinam03/Signature-Forge) :  ![starts](https://img.shields.io/github/stars/Elinam03/Signature-Forge.svg) ![forks](https://img.shields.io/github/forks/Elinam03/Signature-Forge.svg)


## CVE-2025-5729
 A vulnerability, which was classified as critical, was found in code-projects Health Center Patient Record Management System 1.0. Affected is an unknown function of the file /birthing_record.php. The manipulation of the argument itr_no leads to sql injection. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/minnggyuu/CVE-2025-57298](https://github.com/minnggyuu/CVE-2025-57298) :  ![starts](https://img.shields.io/github/stars/minnggyuu/CVE-2025-57298.svg) ![forks](https://img.shields.io/github/forks/minnggyuu/CVE-2025-57298.svg)


## CVE-2024-51793
 Unrestricted Upload of File with Dangerous Type vulnerability in Webful Creations Computer Repair Shop allows Upload a Web Shell to a Web Server.This issue affects Computer Repair Shop: from n/a through 3.8115.

- [https://github.com/JoshuaProvoste/0-click-RCE-Exploit-for-CVE-2024-51793](https://github.com/JoshuaProvoste/0-click-RCE-Exploit-for-CVE-2024-51793) :  ![starts](https://img.shields.io/github/stars/JoshuaProvoste/0-click-RCE-Exploit-for-CVE-2024-51793.svg) ![forks](https://img.shields.io/github/forks/JoshuaProvoste/0-click-RCE-Exploit-for-CVE-2024-51793.svg)


## CVE-2024-51791
 Unrestricted Upload of File with Dangerous Type vulnerability in Made I.T. Forms allows Upload a Web Shell to a Web Server.This issue affects Forms: from n/a through 2.8.0.

- [https://github.com/JoshuaProvoste/0-click-RCE-Exploit-for-CVE-2024-51791](https://github.com/JoshuaProvoste/0-click-RCE-Exploit-for-CVE-2024-51791) :  ![starts](https://img.shields.io/github/stars/JoshuaProvoste/0-click-RCE-Exploit-for-CVE-2024-51791.svg) ![forks](https://img.shields.io/github/forks/JoshuaProvoste/0-click-RCE-Exploit-for-CVE-2024-51791.svg)


## CVE-2024-50526
 Unrestricted Upload of File with Dangerous Type vulnerability in mahlamusa Multi Purpose Mail Form allows Upload a Web Shell to a Web Server.This issue affects Multi Purpose Mail Form: from n/a through 1.0.2.

- [https://github.com/JoshuaProvoste/0-click-RCE-Exploit-for-CVE-2024-50526](https://github.com/JoshuaProvoste/0-click-RCE-Exploit-for-CVE-2024-50526) :  ![starts](https://img.shields.io/github/stars/JoshuaProvoste/0-click-RCE-Exploit-for-CVE-2024-50526.svg) ![forks](https://img.shields.io/github/forks/JoshuaProvoste/0-click-RCE-Exploit-for-CVE-2024-50526.svg)


## CVE-2024-50498
 Improper Control of Generation of Code ('Code Injection') vulnerability in LUBUS WP Query Console allows Code Injection.This issue affects WP Query Console: from n/a through 1.0.

- [https://github.com/JoshuaProvoste/0-click-RCE-Exploit-for-CVE-2024-50498](https://github.com/JoshuaProvoste/0-click-RCE-Exploit-for-CVE-2024-50498) :  ![starts](https://img.shields.io/github/stars/JoshuaProvoste/0-click-RCE-Exploit-for-CVE-2024-50498.svg) ![forks](https://img.shields.io/github/forks/JoshuaProvoste/0-click-RCE-Exploit-for-CVE-2024-50498.svg)


## CVE-2024-28000
 Incorrect Privilege Assignment vulnerability in LiteSpeed Technologies LiteSpeed Cache litespeed-cache allows Privilege Escalation.This issue affects LiteSpeed Cache: from 1.9 through 6.3.0.1.

- [https://github.com/arch1m3d/CVE-2024-28000](https://github.com/arch1m3d/CVE-2024-28000) :  ![starts](https://img.shields.io/github/stars/arch1m3d/CVE-2024-28000.svg) ![forks](https://img.shields.io/github/forks/arch1m3d/CVE-2024-28000.svg)


## CVE-2024-10924
 The Really Simple Security (Free, Pro, and Pro Multisite) plugins for WordPress are vulnerable to authentication bypass in versions 9.0.0 to 9.1.1.1. This is due to improper user check error handling in the two-factor REST API actions with the 'check_login_and_get_user' function. This makes it possible for unauthenticated attackers to log in as any existing user on the site, such as an administrator, when the "Two-Factor Authentication" setting is enabled (disabled by default).

- [https://github.com/JoshuaProvoste/0-click-RCE-Exploit-for-CVE-2024-10924](https://github.com/JoshuaProvoste/0-click-RCE-Exploit-for-CVE-2024-10924) :  ![starts](https://img.shields.io/github/stars/JoshuaProvoste/0-click-RCE-Exploit-for-CVE-2024-10924.svg) ![forks](https://img.shields.io/github/forks/JoshuaProvoste/0-click-RCE-Exploit-for-CVE-2024-10924.svg)


## CVE-2024-9932
 The Wux Blog Editor plugin for WordPress is vulnerable to arbitrary file uploads due to insufficient file type validation in the 'wuxbt_insertImageNew' function in versions up to, and including, 3.0.0. This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible.

- [https://github.com/JoshuaProvoste/0-click-RCE-Exploit-for-CVE-2024-9932](https://github.com/JoshuaProvoste/0-click-RCE-Exploit-for-CVE-2024-9932) :  ![starts](https://img.shields.io/github/stars/JoshuaProvoste/0-click-RCE-Exploit-for-CVE-2024-9932.svg) ![forks](https://img.shields.io/github/forks/JoshuaProvoste/0-click-RCE-Exploit-for-CVE-2024-9932.svg)


## CVE-2023-51409
 Unrestricted Upload of File with Dangerous Type vulnerability in Jordy Meow AI Engine: ChatGPT Chatbot.This issue affects AI Engine: ChatGPT Chatbot: from n/a through 1.9.98.

- [https://github.com/JoshuaProvoste/0-click-RCE-Exploit-for-CVE-2023-51409](https://github.com/JoshuaProvoste/0-click-RCE-Exploit-for-CVE-2023-51409) :  ![starts](https://img.shields.io/github/stars/JoshuaProvoste/0-click-RCE-Exploit-for-CVE-2023-51409.svg) ![forks](https://img.shields.io/github/forks/JoshuaProvoste/0-click-RCE-Exploit-for-CVE-2023-51409.svg)


## CVE-2022-39299
 Passport-SAML is a SAML 2.0 authentication provider for Passport, the Node.js authentication library. A remote attacker may be able to bypass SAML authentication on a website using passport-saml. A successful attack requires that the attacker is in possession of an arbitrary IDP signed XML element. Depending on the IDP used, fully unauthenticated attacks (e.g without access to a valid user) might also be feasible if generation of a signed message can be triggered. Users should upgrade to passport-saml version 3.2.2 or newer. The issue was also present in the beta releases of `node-saml` before version 4.0.0-beta.5. If you cannot upgrade, disabling SAML authentication may be done as a workaround.

- [https://github.com/KaztoRay/CVE-2022-39299-Research](https://github.com/KaztoRay/CVE-2022-39299-Research) :  ![starts](https://img.shields.io/github/stars/KaztoRay/CVE-2022-39299-Research.svg) ![forks](https://img.shields.io/github/forks/KaztoRay/CVE-2022-39299-Research.svg)


## CVE-2021-3560
 It was found that polkit could be tricked into bypassing the credential checks for D-Bus requests, elevating the privileges of the requestor to the root user. This flaw could be used by an unprivileged local attacker to, for example, create a new local administrator. The highest threat from this vulnerability is to data confidentiality and integrity as well as system availability.

- [https://github.com/winmin/CVE-2021-3560](https://github.com/winmin/CVE-2021-3560) :  ![starts](https://img.shields.io/github/stars/winmin/CVE-2021-3560.svg) ![forks](https://img.shields.io/github/forks/winmin/CVE-2021-3560.svg)


## CVE-2020-8597
 eap.c in pppd in ppp 2.4.2 through 2.4.8 has an rhostname buffer overflow in the eap_request and eap_response functions.

- [https://github.com/winmin/CVE-2020-8597](https://github.com/winmin/CVE-2020-8597) :  ![starts](https://img.shields.io/github/stars/winmin/CVE-2020-8597.svg) ![forks](https://img.shields.io/github/forks/winmin/CVE-2020-8597.svg)


## CVE-2012-1823
 sapi/cgi/cgi_main.c in PHP before 5.3.12 and 5.4.x before 5.4.2, when configured as a CGI script (aka php-cgi), does not properly handle query strings that lack an = (equals sign) character, which allows remote attackers to execute arbitrary code by placing command-line options in the query string, related to lack of skipping a certain php_getopt for the 'd' case.

- [https://github.com/hackherMind-Pixel/Vulnerable-Lab-Exploitation](https://github.com/hackherMind-Pixel/Vulnerable-Lab-Exploitation) :  ![starts](https://img.shields.io/github/stars/hackherMind-Pixel/Vulnerable-Lab-Exploitation.svg) ![forks](https://img.shields.io/github/forks/hackherMind-Pixel/Vulnerable-Lab-Exploitation.svg)

