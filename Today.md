# Update 2026-10-03
## CVE-2026-104286
 An improper limitation of a pathname to a restricted directory ('path traversal') vulnerability in Fortinet FortiMail 8.0.0 through 8.0.1, FortiMail 7.6.0 through 7.6.6, FortiMail 7.4.0 through 7.4.8, FortiMail 7.2.0 through 7.2.9 may allow an unauthenticated attacker to write arbitrary files on the underlying system via crafted HTTP or HTTPS requests.

- [https://github.com/ShadowForge-Cyber/CVE-2026-104286-POC](https://github.com/ShadowForge-Cyber/CVE-2026-104286-POC) :  ![starts](https://img.shields.io/github/stars/ShadowForge-Cyber/CVE-2026-104286-POC.svg) ![forks](https://img.shields.io/github/forks/ShadowForge-Cyber/CVE-2026-104286-POC.svg)


## CVE-2026-103585
This issue affects MediaWiki MediaSearch extension: 1.46, 1.45, and 1.43.

- [https://github.com/BomboBombone/CVE-2026-103585](https://github.com/BomboBombone/CVE-2026-103585) :  ![starts](https://img.shields.io/github/stars/BomboBombone/CVE-2026-103585.svg) ![forks](https://img.shields.io/github/forks/BomboBombone/CVE-2026-103585.svg)


## CVE-2026-103584
This issue affects MediaWiki CommonsMetadata extension: 1.46, 1.45, and 1.43.

- [https://github.com/BomboBombone/CVE-2026-103584](https://github.com/BomboBombone/CVE-2026-103584) :  ![starts](https://img.shields.io/github/stars/BomboBombone/CVE-2026-103584.svg) ![forks](https://img.shields.io/github/forks/BomboBombone/CVE-2026-103584.svg)


## CVE-2026-102425
 Joomla Extension - balbooa.com - Unauthenticated RCE via field shortcode injection in Balbooa Forms  2.4.3.4 - Balbooa Forms supports administrator-defined PHP code which runs after a public form submission. The feature also supports form-field shortcodes inside that PHP. Before calling `eval()`, the component replaces each shortcode with the raw value submitted by the visitor, leading to an RCE vector. A public form must use the product's optional PHP-after-submission action and interpolate an attacker-controlled field shortcode inside a double-quoted PHP string to be vulnerable.

- [https://github.com/tonydelouvre/CVE-2026-102425](https://github.com/tonydelouvre/CVE-2026-102425) :  ![starts](https://img.shields.io/github/stars/tonydelouvre/CVE-2026-102425.svg) ![forks](https://img.shields.io/github/forks/tonydelouvre/CVE-2026-102425.svg)


## CVE-2026-100671
 Grav is a flat-file CMS. In versions 2.0.19 through 2.0.24 — and in 2.0.0 through 2.0.18 and 1.7.x only where content Twig has been explicitly enabled — page content authored by a user holding only page-write permission is rendered through a Twig sandbox that allowlists get_cookie(), which returns any cookie sent with the current request, including the visitor's session cookie. Because the read occurs server-side via filter_input(INPUT_COOKIE, ...), the HttpOnly, Secure and SameSite attributes offer no protection. Grav then stores the finished post-Twig output in a page-content cache keyed only on page identity and the configuration checksum, with no session, user or request dimension and no bypass for authenticated visitors. A page published by a page-write user can therefore capture the session identifier of the next administrator who views it, after which the cached output serves that identifier to unauthenticated visitors, who can replay the cookie to authenticate as that administrator. Since 2.0.19, security.twig_content.process_enabled defaults to true and Security::applyTwigContentDefault() derives each page's process.twig flag from that gate, so content Twig runs on every page with no frontmatter or operator action. Fixed in 2.0.25; 1.7.x is outside the backport scope.

- [https://github.com/canhieu/cve-2026-100671-poc](https://github.com/canhieu/cve-2026-100671-poc) :  ![starts](https://img.shields.io/github/stars/canhieu/cve-2026-100671-poc.svg) ![forks](https://img.shields.io/github/forks/canhieu/cve-2026-100671-poc.svg)


## CVE-2026-97163
 Joomla Extension - lomart.fr - Unauthenticated remote code installation in UP plugin extension 5.0.0-5.2.0, 6.0.0-6.0.29

- [https://github.com/kize7/cve-2026-97163-payload](https://github.com/kize7/cve-2026-97163-payload) :  ![starts](https://img.shields.io/github/stars/kize7/cve-2026-97163-payload.svg) ![forks](https://img.shields.io/github/forks/kize7/cve-2026-97163-payload.svg)


## CVE-2026-96349
 Unauthenticated Remote Code Execution (RCE) in SiteSkite = 2.1.8 versions.

- [https://github.com/murrez/CVE-2026-96349](https://github.com/murrez/CVE-2026-96349) :  ![starts](https://img.shields.io/github/stars/murrez/CVE-2026-96349.svg) ![forks](https://img.shields.io/github/forks/murrez/CVE-2026-96349.svg)


## CVE-2026-93616
 A directory traversal and file upload vulnerability allows an unauthenticated attacker to upload and execute arbitrary scripts on Check Point Management Server.

- [https://github.com/BishopFox/CVE-2026-93616-check](https://github.com/BishopFox/CVE-2026-93616-check) :  ![starts](https://img.shields.io/github/stars/BishopFox/CVE-2026-93616-check.svg) ![forks](https://img.shields.io/github/forks/BishopFox/CVE-2026-93616-check.svg)


## CVE-2026-92966
 The The Appointment Booking Plugin – LatePoint | Calendar & Scheduling for WordPress plugin for WordPress is vulnerable to arbitrary shortcode execution in all versions up to, and including, 5.7.0. This is due to the software allowing users to execute an action that does not properly validate a value before running do_shortcode. This makes it possible for unauthenticated attackers to execute arbitrary shortcodes. The payload is planted during the unauthenticated booking flow and triggered when the Customer Cabinet block rendered by render_customer_dashboard() outputs the stored name into the content stream, where WordPress core's do_shortcode filter at priority 11 re-parses and executes it.

- [https://github.com/murrez/CVE-2026-92966](https://github.com/murrez/CVE-2026-92966) :  ![starts](https://img.shields.io/github/stars/murrez/CVE-2026-92966.svg) ![forks](https://img.shields.io/github/forks/murrez/CVE-2026-92966.svg)


## CVE-2026-92099
 The WPGraphQL Smart Cache WordPress plugin before 2.3.2 does not require authorisation or validate a caller-supplied query identifier before storing a persisted query from a request, allowing unauthenticated users to publish arbitrary query documents and claim query aliases before a site's own frontend registers them.

- [https://github.com/MS-0x404/CVE-2026-92099](https://github.com/MS-0x404/CVE-2026-92099) :  ![starts](https://img.shields.io/github/stars/MS-0x404/CVE-2026-92099.svg) ![forks](https://img.shields.io/github/forks/MS-0x404/CVE-2026-92099.svg)


## CVE-2026-90907
 Joomla! Core - [20260902] - Core - Unauthorized user account creation via profile.save controller in Joomla 1.5.0-5.4.8, 6.0.0-6.1.3 - The profile.save controller did not check the login state of a user, allowing the creation of guest-level users on sites without active user registration.

- [https://github.com/aorozco-sys/CVE-2026-90907](https://github.com/aorozco-sys/CVE-2026-90907) :  ![starts](https://img.shields.io/github/stars/aorozco-sys/CVE-2026-90907.svg) ![forks](https://img.shields.io/github/forks/aorozco-sys/CVE-2026-90907.svg)


## CVE-2026-90817
 An unauthenticated Remote Code Execution vulnerability was found in the survey passthrough routing and Data Import processing logic, in which a malicious user could potentially exploit it by manipulating HTTP requests to access an unintended controller route from a public survey context and by supplying a crafted file-path/stream parameter during import handling. If successfully exploited, this could allow the attacker to remotely execute arbitrary code on the REDCap server. The attacker does not have to be authenticated in order to exploit this, but exploitation requires knowledge of a valid public survey hash. This vulnerability exists in REDCap 13.3.0 and higher.

- [https://github.com/securifera/CVE-2026-90817](https://github.com/securifera/CVE-2026-90817) :  ![starts](https://img.shields.io/github/stars/securifera/CVE-2026-90817.svg) ![forks](https://img.shields.io/github/forks/securifera/CVE-2026-90817.svg)


## CVE-2026-88996
 The WPForms – AI Form Builder for WordPress – Contact Forms, Payment Forms, Survey Form, Quiz & More plugin for WordPress is vulnerable to Reflected Cross-Site Scripting via 'page_title' POST Parameter via {page_title} Smart Tag in all versions up to, and including, 2.0.2 due to insufficient input sanitization and output escaping. This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that execute if they can successfully trick a user into performing an action such as clicking on a link. This is only exploitable on forms whose admin-authored confirmation message places the {page_title} Smart Tag inside an HTML attribute context.

- [https://github.com/dorkerdevil/wpforms-xss-fix-bypass](https://github.com/dorkerdevil/wpforms-xss-fix-bypass) :  ![starts](https://img.shields.io/github/stars/dorkerdevil/wpforms-xss-fix-bypass.svg) ![forks](https://img.shields.io/github/forks/dorkerdevil/wpforms-xss-fix-bypass.svg)


## CVE-2026-88789
Users are recommended to upgrade to version 3.33.3 or 3.40.0, which fixes this issue.

- [https://github.com/oscerd/CVE-2026-88789](https://github.com/oscerd/CVE-2026-88789) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-88789.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-88789.svg)


## CVE-2026-88778
This issue affects ADC: before 14.1-73.37, before 13.1-64.23, before 14.1-73.37 FIPS, and before 13.1.37.279 FIPS and NDcPP; Gateway: before 14.1-73.37 and before 13.1-64.23.

- [https://github.com/bkchaudhari/NetScaler-CTX697096-Assessment-Script](https://github.com/bkchaudhari/NetScaler-CTX697096-Assessment-Script) :  ![starts](https://img.shields.io/github/stars/bkchaudhari/NetScaler-CTX697096-Assessment-Script.svg) ![forks](https://img.shields.io/github/forks/bkchaudhari/NetScaler-CTX697096-Assessment-Script.svg)


## CVE-2026-88772
This issue affects ADC: before 14.1-73.37, before 13.1-64.23, before 14.1-73.37 FIPS, and before 13.1.37.279 FIPS and NDcPP; Gateway: before 14.1-73.37 and before 13.1-64.23 leading to Remote Code Execution or Denial of Service

- [https://github.com/emilstahl/pitscaler](https://github.com/emilstahl/pitscaler) :  ![starts](https://img.shields.io/github/stars/emilstahl/pitscaler.svg) ![forks](https://img.shields.io/github/forks/emilstahl/pitscaler.svg)


## CVE-2026-88771
This issue affects ADC: before 14.1-73.37, before 13.1-64.23, before 14.1-73.37 FIPS, and before 13.1.37.279 FIPS and NDcPP; Gateway: before 14.1-73.37 and before 13.1-64.23 leading to an unauthenticated attacker to execute arbitrary commands.

- [https://github.com/emilstahl/pitscaler](https://github.com/emilstahl/pitscaler) :  ![starts](https://img.shields.io/github/stars/emilstahl/pitscaler.svg) ![forks](https://img.shields.io/github/forks/emilstahl/pitscaler.svg)
- [https://github.com/bkchaudhari/NetScaler-CTX697096-Assessment-Script](https://github.com/bkchaudhari/NetScaler-CTX697096-Assessment-Script) :  ![starts](https://img.shields.io/github/stars/bkchaudhari/NetScaler-CTX697096-Assessment-Script.svg) ![forks](https://img.shields.io/github/forks/bkchaudhari/NetScaler-CTX697096-Assessment-Script.svg)


## CVE-2026-86950
 An out-of-bounds write issue was addressed with improved bounds checking. This issue is fixed in iOS 26.7.1 and iPadOS 26.7.1, macOS Sequoia 15.8.1, macOS Tahoe 26.7.1. Processing a maliciously crafted file may lead to arbitrary code execution. Apple is aware of a report that this issue may have been exploited in an extremely sophisticated attack against specific targeted individuals on versions of iOS before iOS 27.

- [https://github.com/msuiche/hotcell](https://github.com/msuiche/hotcell) :  ![starts](https://img.shields.io/github/stars/msuiche/hotcell.svg) ![forks](https://img.shields.io/github/forks/msuiche/hotcell.svg)


## CVE-2026-62146
 A trust-boundary flaw in CRI-O's sandbox state persistence allows attacker-influenced pod metadata to overwrite CRI-O's own reserved sandbox bookkeeping; once reloaded as trusted after a restart, a later container recreate in that sandbox can expose a host-side runtime-management resource inside the container, enabling container escape.

- [https://github.com/TeamN4C/SG-2026-0026](https://github.com/TeamN4C/SG-2026-0026) :  ![starts](https://img.shields.io/github/stars/TeamN4C/SG-2026-0026.svg) ![forks](https://img.shields.io/github/forks/TeamN4C/SG-2026-0026.svg)


## CVE-2026-62059
 Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vulnerability in Ultimate Member Ultimate Member ultimate-member allows Blind SQL Injection.This issue affects Ultimate Member: from n/a through 2.13.1.

- [https://github.com/Hassham1/CVE-2026-62059-ultimate-member-sqli-poc](https://github.com/Hassham1/CVE-2026-62059-ultimate-member-sqli-poc) :  ![starts](https://img.shields.io/github/stars/Hassham1/CVE-2026-62059-ultimate-member-sqli-poc.svg) ![forks](https://img.shields.io/github/forks/Hassham1/CVE-2026-62059-ultimate-member-sqli-poc.svg)


## CVE-2026-59310
 VMware vCenter contains a directory traversal vulnerability in the Syslog server. A malicious actor with network access to vCenter may exploit this issue to execute arbitrary code.

- [https://github.com/chu0119/vc-strike](https://github.com/chu0119/vc-strike) :  ![starts](https://img.shields.io/github/stars/chu0119/vc-strike.svg) ![forks](https://img.shields.io/github/forks/chu0119/vc-strike.svg)


## CVE-2026-59309
 VMware vCenter contains an authentication bypass vulnerability in the VMware Directory Service. A malicious actor with network access to vCenter may exploit this issue to bypass authentication and gain unauthorized access to the system.

- [https://github.com/chu0119/vc-strike](https://github.com/chu0119/vc-strike) :  ![starts](https://img.shields.io/github/stars/chu0119/vc-strike.svg) ![forks](https://img.shields.io/github/forks/chu0119/vc-strike.svg)


## CVE-2026-58138
 Orkes Conductor 3.21.21 before 3.30.2 contains an unauthenticated remote code execution vulnerability that allows remote attackers to execute arbitrary OS commands by submitting inline workflow definitions containing malicious JavaScript or Python expressions to the workflow API endpoint prior to authentication. Attackers can exploit unsandboxed GraalVM evaluators configured with HostAccess.ALL or allowAllAccess(true) through INLINE, LAMBDA, DO_WHILE, and SWITCH task types to invoke arbitrary system commands via Java reflection or direct subprocess calls.

- [https://github.com/Ez4rd1x1/CVE-2026-58138-Research](https://github.com/Ez4rd1x1/CVE-2026-58138-Research) :  ![starts](https://img.shields.io/github/stars/Ez4rd1x1/CVE-2026-58138-Research.svg) ![forks](https://img.shields.io/github/forks/Ez4rd1x1/CVE-2026-58138-Research.svg)


## CVE-2026-52824
 Kimai is an open-source time tracking application. Prior to 2.58.0, the official Docker image sets APP_SECRET to the public value change_this_to_something_unique in Dockerfile, and .docker/entrypoint.sh neither replaces nor rejects that value before Symfony uses it as kernel.secret. An unauthenticated attacker who reaches a deployment that did not override APP_SECRET, knows a username, correctly guesses the account ID associated with that username, and targets an account without active two-factor authentication can forge HMAC-protected authentication artifacts, including KIMAI_REMEMBER cookies and login links, to access the account without its password. The updated entrypoint generates and persists a random secret when no safe operator-provided value exists. This issue is fixed in version 2.58.0.

- [https://github.com/cyeezy08/Kimai-CVE-2026-52824-POC](https://github.com/cyeezy08/Kimai-CVE-2026-52824-POC) :  ![starts](https://img.shields.io/github/stars/cyeezy08/Kimai-CVE-2026-52824-POC.svg) ![forks](https://img.shields.io/github/forks/cyeezy08/Kimai-CVE-2026-52824-POC.svg)


## CVE-2026-48500
 Filament is a collection of full-stack components for accelerated Laravel development. From 3.0.0 until 3.3.52, 4.11.5, and 5.6.5, any schema can contain a file upload form field, so Filament applies Livewire's WithFileUploads trait to the Livewire component the schema is embedded in. However, some schemas, such as the panel login form, do not require file uploads, and exposing unauthenticated temporary file uploads on these components is not an acceptable risk. On these components, an unauthenticated attacker could upload arbitrary files to the application's temporary storage, which could be abused to exhaust disk space or inflate storage costs. This vulnerability is fixed in 3.3.52, 4.11.5, and 5.6.5.

- [https://github.com/rimbadirgantara/CVE-2026-48500](https://github.com/rimbadirgantara/CVE-2026-48500) :  ![starts](https://img.shields.io/github/stars/rimbadirgantara/CVE-2026-48500.svg) ![forks](https://img.shields.io/github/forks/rimbadirgantara/CVE-2026-48500.svg)


## CVE-2026-43500
page_pool RX, GRO).  The OOM/trace handling already in place is reused.

- [https://github.com/Quaerendir/dirtyfrag-audit](https://github.com/Quaerendir/dirtyfrag-audit) :  ![starts](https://img.shields.io/github/stars/Quaerendir/dirtyfrag-audit.svg) ![forks](https://img.shields.io/github/forks/Quaerendir/dirtyfrag-audit.svg)


## CVE-2026-43284
destination-frag path or fall back to skb_cow_data().

- [https://github.com/Quaerendir/dirtyfrag-audit](https://github.com/Quaerendir/dirtyfrag-audit) :  ![starts](https://img.shields.io/github/stars/Quaerendir/dirtyfrag-audit.svg) ![forks](https://img.shields.io/github/forks/Quaerendir/dirtyfrag-audit.svg)


## CVE-2026-40281
 Gotenberg is a Docker-powered stateless API for PDF files. In versions 8.30.1 and earlier, the metadata write endpoint validates metadata keys for control characters but leaves metadata values unsanitized. A newline character in a metadata value splits the ExifTool stdin line into two separate arguments, allowing injection of arbitrary ExifTool pseudo-tags such as -FileName, -Directory, -SymLink, and -HardLink. This is a bypass of the incomplete key-sanitization fix introduced in v8.30.1. An unauthenticated attacker can rename or move any PDF being processed to an arbitrary path in the container filesystem, overwrite arbitrary files, or create symlinks and hard links at arbitrary paths.

- [https://github.com/0xgh057r3c0n/CVE-2026-40281](https://github.com/0xgh057r3c0n/CVE-2026-40281) :  ![starts](https://img.shields.io/github/stars/0xgh057r3c0n/CVE-2026-40281.svg) ![forks](https://img.shields.io/github/forks/0xgh057r3c0n/CVE-2026-40281.svg)


## CVE-2026-33825
 Insufficient granularity of access control in Microsoft Defender allows an authorized attacker to elevate privileges locally.

- [https://github.com/anasabugaddara-ux/defender-bluehammer-audit](https://github.com/anasabugaddara-ux/defender-bluehammer-audit) :  ![starts](https://img.shields.io/github/stars/anasabugaddara-ux/defender-bluehammer-audit.svg) ![forks](https://img.shields.io/github/forks/anasabugaddara-ux/defender-bluehammer-audit.svg)


## CVE-2026-32475
This issue affects Elementor Pro: from n/a through 4.2.1.

- [https://github.com/cyeezy08/WordPress_Exploit_Directory](https://github.com/cyeezy08/WordPress_Exploit_Directory) :  ![starts](https://img.shields.io/github/stars/cyeezy08/WordPress_Exploit_Directory.svg) ![forks](https://img.shields.io/github/forks/cyeezy08/WordPress_Exploit_Directory.svg)


## CVE-2026-26026
 GLPI is a free asset and IT management software package. From 11.0.0 to before 11.0.6, template injection by an administrator lead to RCE. This vulnerability is fixed in 11.0.6.

- [https://github.com/petriQore/CVE-2026-26026_PoC](https://github.com/petriQore/CVE-2026-26026_PoC) :  ![starts](https://img.shields.io/github/stars/petriQore/CVE-2026-26026_PoC.svg) ![forks](https://img.shields.io/github/forks/petriQore/CVE-2026-26026_PoC.svg)


## CVE-2026-22777
 ComfyUI-Manager is an extension designed to enhance the usability of ComfyUI. Prior to versions 3.39.2 and 4.0.5, an attacker can inject special characters into HTTP query parameters to add arbitrary configuration values to the config.ini file. This can lead to security setting tampering or modification of application behavior. This issue has been patched in versions 3.39.2 and 4.0.5.

- [https://github.com/Si13NTTT/CVE-2026-22777](https://github.com/Si13NTTT/CVE-2026-22777) :  ![starts](https://img.shields.io/github/stars/Si13NTTT/CVE-2026-22777.svg) ![forks](https://img.shields.io/github/forks/Si13NTTT/CVE-2026-22777.svg)


## CVE-2026-1131
 A vulnerability has been found in Yonyou KSOA 9.0. Impacted is an unknown function of the file /kmc/save_catalog.jsp of the component HTTP GET Parameter Handler. Such manipulation of the argument catalogid leads to sql injection. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used. The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/Cr0wld3r/CVE-2026-11318](https://github.com/Cr0wld3r/CVE-2026-11318) :  ![starts](https://img.shields.io/github/stars/Cr0wld3r/CVE-2026-11318.svg) ![forks](https://img.shields.io/github/forks/Cr0wld3r/CVE-2026-11318.svg)


## CVE-2025-67303
 An issue in ComfyUI-Manager prior to version 3.38 allowed remote attackers to potentially manipulate its configuration and critical data. This was due to the application storing its files in an insufficiently protected location that was accessible via the web interface

- [https://github.com/Si13NTTT/CVE-2026-22777](https://github.com/Si13NTTT/CVE-2026-22777) :  ![starts](https://img.shields.io/github/stars/Si13NTTT/CVE-2026-22777.svg) ![forks](https://img.shields.io/github/forks/Si13NTTT/CVE-2026-22777.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun.svg)


## CVE-2025-57819
 FreePBX is an open-source web-based graphical user interface. FreePBX 15, 16, and 17 endpoints are vulnerable due to insufficiently sanitized user-supplied data allowing unauthenticated access to FreePBX Administrator leading to arbitrary database manipulation and remote code execution. This issue has been patched in endpoint versions 15.0.66, 16.0.89, and 17.0.3.

- [https://github.com/TheScriptKiddoz/FreePBX-SQLi-RCE](https://github.com/TheScriptKiddoz/FreePBX-SQLi-RCE) :  ![starts](https://img.shields.io/github/stars/TheScriptKiddoz/FreePBX-SQLi-RCE.svg) ![forks](https://img.shields.io/github/forks/TheScriptKiddoz/FreePBX-SQLi-RCE.svg)


## CVE-2025-47947
 ModSecurity is an open source, cross platform web application firewall (WAF) engine for Apache, IIS and Nginx. Versions up to and including 2.9.8 are vulnerable to denial of service in one special case (in stable released versions): when the payload's content type is `application/json`, and there is at least one rule which does a `sanitiseMatchedBytes` action. A patch is available at pull request 3389 and expected to be part of version 2.9.9. No known workarounds are available.

- [https://github.com/yel1337/CVE-2025-47947](https://github.com/yel1337/CVE-2025-47947) :  ![starts](https://img.shields.io/github/stars/yel1337/CVE-2025-47947.svg) ![forks](https://img.shields.io/github/forks/yel1337/CVE-2025-47947.svg)


## CVE-2025-32432
 Craft is a flexible, user-friendly CMS for creating custom digital experiences on the web and beyond. Starting from version 3.0.0-RC1 to before 3.9.15, 4.0.0-RC1 to before 4.14.15, and 5.0.0-RC1 to before 5.6.17, Craft is vulnerable to remote code execution. This is a high-impact, low-complexity attack vector. This issue has been patched in versions 3.9.15, 4.14.15, and 5.6.17, and is an additional fix for CVE-2023-41892.

- [https://github.com/Si13NTTT/CVE-2025-32432](https://github.com/Si13NTTT/CVE-2025-32432) :  ![starts](https://img.shields.io/github/stars/Si13NTTT/CVE-2025-32432.svg) ![forks](https://img.shields.io/github/forks/Si13NTTT/CVE-2025-32432.svg)


## CVE-2025-24813
Users are recommended to upgrade to version 11.0.3, 10.1.35 or 9.0.99, which fixes the issue.

- [https://github.com/Si13NTTT/CVE-2025-24813](https://github.com/Si13NTTT/CVE-2025-24813) :  ![starts](https://img.shields.io/github/stars/Si13NTTT/CVE-2025-24813.svg) ![forks](https://img.shields.io/github/forks/Si13NTTT/CVE-2025-24813.svg)
- [https://github.com/HwangEojin/CVE-2025-24813-Tomcat11-Lab](https://github.com/HwangEojin/CVE-2025-24813-Tomcat11-Lab) :  ![starts](https://img.shields.io/github/stars/HwangEojin/CVE-2025-24813-Tomcat11-Lab.svg) ![forks](https://img.shields.io/github/forks/HwangEojin/CVE-2025-24813-Tomcat11-Lab.svg)


## CVE-2025-21479
 Memory corruption due to unauthorized command execution in GPU micronode while executing specific sequence of commands.

- [https://github.com/diyiqiuye/CVE-2025-21479-FX3](https://github.com/diyiqiuye/CVE-2025-21479-FX3) :  ![starts](https://img.shields.io/github/stars/diyiqiuye/CVE-2025-21479-FX3.svg) ![forks](https://img.shields.io/github/forks/diyiqiuye/CVE-2025-21479-FX3.svg)


## CVE-2025-8110
 Improper Symbolic link handling in the PutContents API in Gogs allows Local Execution of Code.

- [https://github.com/Makis6/CVE-2025-8110](https://github.com/Makis6/CVE-2025-8110) :  ![starts](https://img.shields.io/github/stars/Makis6/CVE-2025-8110.svg) ![forks](https://img.shields.io/github/forks/Makis6/CVE-2025-8110.svg)
- [https://github.com/Waynehck8/CVE-2025-8110-POC](https://github.com/Waynehck8/CVE-2025-8110-POC) :  ![starts](https://img.shields.io/github/stars/Waynehck8/CVE-2025-8110-POC.svg) ![forks](https://img.shields.io/github/forks/Waynehck8/CVE-2025-8110-POC.svg)


## CVE-2025-6647
The specific flaw exists within the parsing of U3D files. The issue results from the lack of proper validation of user-supplied data, which can result in a write past the end of an allocated object. An attacker can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-26644.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-packagemanager-field](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-packagemanager-field) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-packagemanager-field.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-packagemanager-field.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package.svg)


## CVE-2024-55591
 An Authentication Bypass Using an Alternate Path or Channel vulnerability [CWE-288] affecting FortiOS version 7.0.0 through 7.0.16 and FortiProxy version 7.0.0 through 7.0.19 and 7.2.0 through 7.2.12 allows a remote attacker to gain super-admin privileges via crafted requests to Node.js websocket module.

- [https://github.com/gotr00t0day/CVE-2024-55591](https://github.com/gotr00t0day/CVE-2024-55591) :  ![starts](https://img.shields.io/github/stars/gotr00t0day/CVE-2024-55591.svg) ![forks](https://img.shields.io/github/forks/gotr00t0day/CVE-2024-55591.svg)


## CVE-2024-23334
 aiohttp is an asynchronous HTTP client/server framework for asyncio and Python. When using aiohttp as a web server and configuring static routes, it is necessary to specify the root path for static files. Additionally, the option 'follow_symlinks' can be used to determine whether to follow symbolic links outside the static root directory. When 'follow_symlinks' is set to True, there is no validation to check if reading a file is within the root directory. This can lead to directory traversal vulnerabilities, resulting in unauthorized access to arbitrary files on the system, even when symlinks are not present.  Disabling follow_symlinks and using a reverse proxy are encouraged mitigations.  Version 3.9.2 fixes this issue.

- [https://github.com/dhtfish-98/PathHarbor](https://github.com/dhtfish-98/PathHarbor) :  ![starts](https://img.shields.io/github/stars/dhtfish-98/PathHarbor.svg) ![forks](https://img.shields.io/github/forks/dhtfish-98/PathHarbor.svg)


## CVE-2024-21626
 runc is a CLI tool for spawning and running containers on Linux according to the OCI specification. In runc 1.1.11 and earlier, due to an internal file descriptor leak, an attacker could cause a newly-spawned container process (from runc exec) to have a working directory in the host filesystem namespace, allowing for a container escape by giving access to the host filesystem ("attack 2"). The same attack could be used by a malicious image to allow a container process to gain access to the host filesystem through runc run ("attack 1"). Variants of attacks 1 and 2 could be also be used to overwrite semi-arbitrary host binaries, allowing for complete container escapes ("attack 3a" and "attack 3b"). runc 1.1.12 includes patches for this issue.

- [https://github.com/MutagomaRaissa/container-security-lab-cve-2024-21626](https://github.com/MutagomaRaissa/container-security-lab-cve-2024-21626) :  ![starts](https://img.shields.io/github/stars/MutagomaRaissa/container-security-lab-cve-2024-21626.svg) ![forks](https://img.shields.io/github/forks/MutagomaRaissa/container-security-lab-cve-2024-21626.svg)


## CVE-2023-28432
and `MINIO_ROOT_PASSWORD`, resulting in information disclosure. All users of distributed deployment are impacted. All users are advised to upgrade to RELEASE.2023-03-20T20-16-18Z.

- [https://github.com/cgi-italy-insula-processing/minio](https://github.com/cgi-italy-insula-processing/minio) :  ![starts](https://img.shields.io/github/stars/cgi-italy-insula-processing/minio.svg) ![forks](https://img.shields.io/github/forks/cgi-italy-insula-processing/minio.svg)


## CVE-2022-22965
 A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the application to run on Tomcat as a WAR deployment. If the application is deployed as a Spring Boot executable jar, i.e. the default, it is not vulnerable to the exploit. However, the nature of the vulnerability is more general, and there may be other ways to exploit it.

- [https://github.com/shoucheng3/spring-projects__spring-framework_CVE-2022-22965_5-2-19-RELEASE](https://github.com/shoucheng3/spring-projects__spring-framework_CVE-2022-22965_5-2-19-RELEASE) :  ![starts](https://img.shields.io/github/stars/shoucheng3/spring-projects__spring-framework_CVE-2022-22965_5-2-19-RELEASE.svg) ![forks](https://img.shields.io/github/forks/shoucheng3/spring-projects__spring-framework_CVE-2022-22965_5-2-19-RELEASE.svg)


## CVE-2022-0847
 A flaw was found in the way the "flags" member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/pmihsan/Dirty-Pipe-CVE-2022-0847](https://github.com/pmihsan/Dirty-Pipe-CVE-2022-0847) :  ![starts](https://img.shields.io/github/stars/pmihsan/Dirty-Pipe-CVE-2022-0847.svg) ![forks](https://img.shields.io/github/forks/pmihsan/Dirty-Pipe-CVE-2022-0847.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/r0otk3r/CVE-2021-41773](https://github.com/r0otk3r/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/r0otk3r/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/r0otk3r/CVE-2021-41773.svg)


## CVE-2021-4177
 livehelperchat is vulnerable to Generation of Error Message Containing Sensitive Information

- [https://github.com/mah4nzfr/CVE-2021-41773](https://github.com/mah4nzfr/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/mah4nzfr/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/mah4nzfr/CVE-2021-41773.svg)
- [https://github.com/Park123r/CVE-2021-41773](https://github.com/Park123r/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/Park123r/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/Park123r/CVE-2021-41773.svg)


## CVE-2020-1472
When the second phase of Windows updates become available in Q1 2021, customers will be notified via a revision to this security vulnerability. If you wish to be notified when these updates are released, we recommend that you register for the security notifications mailer to be alerted of content changes to this advisory. See Microsoft Technical Security Notifications.

- [https://github.com/erk3/zeroscan](https://github.com/erk3/zeroscan) :  ![starts](https://img.shields.io/github/stars/erk3/zeroscan.svg) ![forks](https://img.shields.io/github/forks/erk3/zeroscan.svg)


## CVE-2018-12533
 JBoss RichFaces 3.1.0 through 3.3.4 allows unauthenticated remote attackers to inject expression language (EL) expressions and execute arbitrary Java code via a /DATA/ substring in a path with an org.richfaces.renderkit.html.Paint2DResource$ImageData object, aka RF-14310.

- [https://github.com/arslanben/richfaces-paint2d-lab](https://github.com/arslanben/richfaces-paint2d-lab) :  ![starts](https://img.shields.io/github/stars/arslanben/richfaces-paint2d-lab.svg) ![forks](https://img.shields.io/github/forks/arslanben/richfaces-paint2d-lab.svg)


## CVE-2017-9841
 Util/PHP/eval-stdin.php in PHPUnit before 4.8.28 and 5.x before 5.6.3 allows remote attackers to execute arbitrary PHP code via HTTP POST data beginning with a "?php " substring, as demonstrated by an attack on a site with an exposed /vendor folder, i.e., external access to the /vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php URI.

- [https://github.com/CheLover86/CVE-2017-9841](https://github.com/CheLover86/CVE-2017-9841) :  ![starts](https://img.shields.io/github/stars/CheLover86/CVE-2017-9841.svg) ![forks](https://img.shields.io/github/forks/CheLover86/CVE-2017-9841.svg)


## CVE-2014-6271
 GNU Bash through 4.3 processes trailing strings after function definitions in the values of environment variables, which allows remote attackers to execute arbitrary code via a crafted environment, as demonstrated by vectors involving the ForceCommand feature in OpenSSH sshd, the mod_cgi and mod_cgid modules in the Apache HTTP Server, scripts executed by unspecified DHCP clients, and other situations in which setting the environment occurs across a privilege boundary from Bash execution, aka "ShellShock."  NOTE: the original fix for this issue was incorrect; CVE-2014-7169 has been assigned to cover the vulnerability that is still present after the incorrect fix.

- [https://github.com/JohnRyk/ICMPShock3](https://github.com/JohnRyk/ICMPShock3) :  ![starts](https://img.shields.io/github/stars/JohnRyk/ICMPShock3.svg) ![forks](https://img.shields.io/github/forks/JohnRyk/ICMPShock3.svg)

