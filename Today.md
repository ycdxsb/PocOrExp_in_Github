# Update 2026-11-23
## CVE-2026-133968
 monailabel (aka MONAI Label) through 0.8.5 allows directory traversal, with resultant remote code execution, via the image parameter to the PUT /datastore/image endpoint, as exploited in the wild starting in September 2026.

- [https://github.com/LLCForge/CVE-2026-133968](https://github.com/LLCForge/CVE-2026-133968) :  ![starts](https://img.shields.io/github/stars/LLCForge/CVE-2026-133968.svg) ![forks](https://img.shields.io/github/forks/LLCForge/CVE-2026-133968.svg)


## CVE-2026-133493
 A vulnerability was identified in D-Link DIR-600L 2.17b02. Affected is the function genacgi_main of the file gena.cgi of the component GENA Handler. Such manipulation leads to os command injection. The attack can be launched remotely. The exploit is publicly available and might be used.

- [https://github.com/LLCForge/CVE-2026-133493](https://github.com/LLCForge/CVE-2026-133493) :  ![starts](https://img.shields.io/github/stars/LLCForge/CVE-2026-133493.svg) ![forks](https://img.shields.io/github/forks/LLCForge/CVE-2026-133493.svg)


## CVE-2026-133325
Users are recommended to switch to TLS 1.2 and TLS-PSK or upgrade to version 11.0.30, 10.1.63 or 9.0.125 (when released), which fix the issue.

- [https://github.com/LLCForge/CVE-2026-133325](https://github.com/LLCForge/CVE-2026-133325) :  ![starts](https://img.shields.io/github/stars/LLCForge/CVE-2026-133325.svg) ![forks](https://img.shields.io/github/forks/LLCForge/CVE-2026-133325.svg)


## CVE-2026-132277
 Inscriptis is a Python library for converting HTML to text. From 2.0.0 until 2.7.6, when the parent is block-level, table_end_handler() in model/tag/table_tag.py writes each sibling table through HtmlElement.write_verbatim_text() in model/html_element.py; Canvas.open_block() leaves the parent padding_inline prefix on the stack, Canvas.close_block() does not remove it, and only Canvas.close_tag() calls prefix.remove_last_prefix(). Each following sibling table therefore carries forward accumulated indentation, making get_text() output grow quadratically and allowing small attacker-controlled HTML to exhaust memory in applications converting it without authentication or user interaction. This issue is fixed in 2.7.6.

- [https://github.com/googlesky/CVE-2026-132277](https://github.com/googlesky/CVE-2026-132277) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-132277.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-132277.svg)


## CVE-2026-132276
 wcmatch is a Python library for wildcard file-name matching. Prior to 11.2, under the default flags, matching a non-matching attacker-controlled name against an application-supplied pattern containing several star wildcards separated by literals makes the lazy .? and [^/]? segments, including _STAR and _PATH_STAR emitted by _handle_star() in wcmatch/_wcparse.py, backtrack across possible splits, so a single comparison can consume prolonged CPU time. The pattern remains a developer-controlled constant and only the name is attacker-controlled; affected paths include fnmatch.fnmatch(), glob.globmatch(), and filesystem glob scans where another user can create names, without enabling extglob or any non-default flag. This issue is fixed in 11.2.

- [https://github.com/googlesky/CVE-2026-132276](https://github.com/googlesky/CVE-2026-132276) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-132276.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-132276.svg)


## CVE-2026-132275
 svglib reads SVG files and converts them to other formats. Prior to 2.3.1, the svg2rlg() renderer recursively expands nested SVG use references by deep-copying each referenced subtree; SvgRenderer.renderUse() in src/svglib/svglib.py calls xlink_href_target(), which rejects direct cycles but permits acyclic reference graphs with repeated fan-out. A small attacker-controlled SVG can therefore trigger exponentially increasing node expansion, consuming excessive CPU and memory in any application that renders it without a non-default option; HTML-to-PDF workflows using xhtml2pdf can reach the same renderer when an embedded data:image/svg+xml image in an HTML img element is passed to pisa.CreatePDF(). This issue is fixed in 2.3.1.

- [https://github.com/googlesky/CVE-2026-132275](https://github.com/googlesky/CVE-2026-132275) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-132275.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-132275.svg)


## CVE-2026-130848
 Dolibarr ERP CRM through 24.0.3 contains a code injection vulnerability in Website::importWebSite() that allows website editors without PHP permission to execute code by importing templates. Attackers can import a template zip whose javascript.js.php contains PHP code, which the public javascript.js.php endpoint includes, executing code as the web server user.

- [https://github.com/Zer0Breach/CVE-2026-130848](https://github.com/Zer0Breach/CVE-2026-130848) :  ![starts](https://img.shields.io/github/stars/Zer0Breach/CVE-2026-130848.svg) ![forks](https://img.shields.io/github/forks/Zer0Breach/CVE-2026-130848.svg)


## CVE-2026-130847
 Dolibarr ERP CRM before 24.0.2 contains an improper authorization vulnerability in the Users REST API put() method that allows non-admin API users to set administrator passwords. Authenticated users with user modification and password rights can send a PUT request to the users endpoint with a chosen pass value for a SuperAdmin account and then log in as that administrator.

- [https://github.com/Zer0Breach/CVE-2026-130847](https://github.com/Zer0Breach/CVE-2026-130847) :  ![starts](https://img.shields.io/github/stars/Zer0Breach/CVE-2026-130847.svg) ![forks](https://img.shields.io/github/forks/Zer0Breach/CVE-2026-130847.svg)


## CVE-2026-129448
Users who cannot upgrade right away should set "enabledForExtensions" to "false" in WEB-INF/web.xml, or remove the "/roller-services/xmlrpc" servlet mapping, and restart Roller. Disabling XML-RPC in the administration UI is not enough, because older versions deserialize the request before checking that setting.

- [https://github.com/evenomn/CVE-2026-129448](https://github.com/evenomn/CVE-2026-129448) :  ![starts](https://img.shields.io/github/stars/evenomn/CVE-2026-129448.svg) ![forks](https://img.shields.io/github/forks/evenomn/CVE-2026-129448.svg)


## CVE-2026-129289
This issue affects PHP versions before 8.2.36, 8.3.* before 8.3.37, 8.4.* before 8.4.28 and 8.5.* before 8.5.13.

- [https://github.com/tc4dy/CVE-2026-129289-PoC-Exploit](https://github.com/tc4dy/CVE-2026-129289-PoC-Exploit) :  ![starts](https://img.shields.io/github/stars/tc4dy/CVE-2026-129289-PoC-Exploit.svg) ![forks](https://img.shields.io/github/forks/tc4dy/CVE-2026-129289-PoC-Exploit.svg)


## CVE-2026-129175
 U.S Department of the Interior Unstable Slope Management Program allows an unauthenticated user to inject unauthorized SQL commands that allow the attacker to gain root access and complete control over the database. Fixed on or around 2026-10-19.

- [https://github.com/LLCForge/CVE-2026-129175](https://github.com/LLCForge/CVE-2026-129175) :  ![starts](https://img.shields.io/github/stars/LLCForge/CVE-2026-129175.svg) ![forks](https://img.shields.io/github/forks/LLCForge/CVE-2026-129175.svg)


## CVE-2026-129073
 Authentication Bypass Using an Alternate Path or Channel vulnerability in miniOrange miniorange otp verification miniorange-otp-verification allows Authentication Abuse.This issue affects miniorange otp verification: from n/a through 5.6.1.

- [https://github.com/LLCForge/CVE-2026-129073](https://github.com/LLCForge/CVE-2026-129073) :  ![starts](https://img.shields.io/github/stars/LLCForge/CVE-2026-129073.svg) ![forks](https://img.shields.io/github/forks/LLCForge/CVE-2026-129073.svg)


## CVE-2026-129056
 Incorrect Privilege Assignment vulnerability in Paul Ryan Authorizer authorizer allows Privilege Escalation.This issue affects Authorizer: from n/a before 3.17.2.

- [https://github.com/LLCForge/CVE-2026-129056](https://github.com/LLCForge/CVE-2026-129056) :  ![starts](https://img.shields.io/github/stars/LLCForge/CVE-2026-129056.svg) ![forks](https://img.shields.io/github/forks/LLCForge/CVE-2026-129056.svg)


## CVE-2026-129043
 Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vulnerability in Tribulant Software Newsletters newsletters-lite allows SQL Injection.This issue affects Newsletters: from n/a through 4.18.2.

- [https://github.com/LLCForge/CVE-2026-129043](https://github.com/LLCForge/CVE-2026-129043) :  ![starts](https://img.shields.io/github/stars/LLCForge/CVE-2026-129043.svg) ![forks](https://img.shields.io/github/forks/LLCForge/CVE-2026-129043.svg)


## CVE-2026-129039
 Deserialization of Untrusted Data vulnerability in Tribulant Software Newsletters newsletters-lite allows Object Injection.This issue affects Newsletters: from n/a through 4.18.2.

- [https://github.com/LLCForge/CVE-2026-129039](https://github.com/LLCForge/CVE-2026-129039) :  ![starts](https://img.shields.io/github/stars/LLCForge/CVE-2026-129039.svg) ![forks](https://img.shields.io/github/forks/LLCForge/CVE-2026-129039.svg)


## CVE-2026-126714
This issue affects PHP versions before 8.2.36, 8.3.* before 8.3.37, 8.4.* before 8.4.28 and 8.5.* before 8.5.13.

- [https://github.com/mc493/php2shell-enterprise-hardening-cve-2026-109618-109619](https://github.com/mc493/php2shell-enterprise-hardening-cve-2026-109618-109619) :  ![starts](https://img.shields.io/github/stars/mc493/php2shell-enterprise-hardening-cve-2026-109618-109619.svg) ![forks](https://img.shields.io/github/forks/mc493/php2shell-enterprise-hardening-cve-2026-109618-109619.svg)


## CVE-2026-123890
Telco Cloud Platform 3.0, 4.x, 5.0.x, 5.1.x, 5.2 and Telco Cloud Infrastructure 3.0 are also affected (see KB463116).

- [https://github.com/Sable-Research/CVE-2026-123890-Research](https://github.com/Sable-Research/CVE-2026-123890-Research) :  ![starts](https://img.shields.io/github/stars/Sable-Research/CVE-2026-123890-Research.svg) ![forks](https://img.shields.io/github/forks/Sable-Research/CVE-2026-123890-Research.svg)
- [https://github.com/foxcornlab/vmware-vcenter-scanner](https://github.com/foxcornlab/vmware-vcenter-scanner) :  ![starts](https://img.shields.io/github/stars/foxcornlab/vmware-vcenter-scanner.svg) ![forks](https://img.shields.io/github/forks/foxcornlab/vmware-vcenter-scanner.svg)


## CVE-2026-123633
Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/grupooruss/Division81-cve-2026-123633](https://github.com/grupooruss/Division81-cve-2026-123633) :  ![starts](https://img.shields.io/github/stars/grupooruss/Division81-cve-2026-123633.svg) ![forks](https://img.shields.io/github/forks/grupooruss/Division81-cve-2026-123633.svg)
- [https://github.com/Nexxus67/CVE-2026-123633-PoC](https://github.com/Nexxus67/CVE-2026-123633-PoC) :  ![starts](https://img.shields.io/github/stars/Nexxus67/CVE-2026-123633-PoC.svg) ![forks](https://img.shields.io/github/forks/Nexxus67/CVE-2026-123633-PoC.svg)
- [https://github.com/cyberdesserts/nmap-detections](https://github.com/cyberdesserts/nmap-detections) :  ![starts](https://img.shields.io/github/stars/cyberdesserts/nmap-detections.svg) ![forks](https://img.shields.io/github/forks/cyberdesserts/nmap-detections.svg)


## CVE-2026-123007
Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/T0tooro/cve-2026-123007-lab](https://github.com/T0tooro/cve-2026-123007-lab) :  ![starts](https://img.shields.io/github/stars/T0tooro/cve-2026-123007-lab.svg) ![forks](https://img.shields.io/github/forks/T0tooro/cve-2026-123007-lab.svg)
- [https://github.com/grupooruss/Division81-cve-2026-123633](https://github.com/grupooruss/Division81-cve-2026-123633) :  ![starts](https://img.shields.io/github/stars/grupooruss/Division81-cve-2026-123633.svg) ![forks](https://img.shields.io/github/forks/grupooruss/Division81-cve-2026-123633.svg)


## CVE-2026-122244
 Budibase is an open-source low-code platform. Prior to 3.50.0, a BASIC application user, or an unauthenticated visitor to a public write form, can store markup in a shared external datasource that a builder or administrator later evaluates in any Handlebars binding Preview that surfaces the value, including the Data-section Formula column editor or any binding drawer. jsonFormatter.format() in packages/frontend-core/src/utils/jsonFormatter.ts leaves raw strings and object keys unescaped, while packages/builder/src/components/common/bindings/EvaluationSidePanel.svelte inserts the formatted result as raw HTML. The Handlebars SafeString path preserves the attacker-controlled value, and the Builder origin lacks a Content-Security-Policy that would block the resulting script. This permits stored script execution in the higher-privileged builder or administrator session rather than the writer's own role, allowing privileged Builder API actions and workspace data access. This issue is fixed in versions 3.50.0 and 4.0.0.

- [https://github.com/googlesky/CVE-2026-122244](https://github.com/googlesky/CVE-2026-122244) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-122244.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-122244.svg)


## CVE-2026-121481
The affected code is outside the FIPS module boundary.

- [https://github.com/Mahgal/openssl-evp-check](https://github.com/Mahgal/openssl-evp-check) :  ![starts](https://img.shields.io/github/stars/Mahgal/openssl-evp-check.svg) ![forks](https://img.shields.io/github/forks/Mahgal/openssl-evp-check.svg)


## CVE-2026-121385
 The User Registration Aide WordPress plugin through 1.5.3.8 does not verify the current password or a reset token before changing a user's password, allowing unauthenticated attackers who know a user's username and email address to change the password of any account, including administrators, and take it over.

- [https://github.com/LLCForge/CVE-2026-121385](https://github.com/LLCForge/CVE-2026-121385) :  ![starts](https://img.shields.io/github/stars/LLCForge/CVE-2026-121385.svg) ![forks](https://img.shields.io/github/forks/LLCForge/CVE-2026-121385.svg)


## CVE-2026-120681
 The Mang Board plugin for WordPress is vulnerable to authorization bypass in all versions up to, and including, 2.4.7. This is due to the plugin not properly verifying that a user is authorized to perform an action. This makes it possible for unauthenticated attackers to delete any board post — including administrator-owned content — along with its associated comments and file links. A nonce sufficient to pass the initial nonce check is publicly exposed on any board listing page, meaning no prior authentication or privileged access is required to initiate the exploit.

- [https://github.com/LLCForge/CVE-2026-120681](https://github.com/LLCForge/CVE-2026-120681) :  ![starts](https://img.shields.io/github/stars/LLCForge/CVE-2026-120681.svg) ![forks](https://img.shields.io/github/forks/LLCForge/CVE-2026-120681.svg)


## CVE-2026-120539
 The Restrictions for BuddyPress plugin for WordPress is vulnerable to Remote Code Execution in all versions up to, and including, 1.5.4 This is due to the plugin splicing the attacker-controlled request URI into a PHP expression inside a double-quoted string and evaluating it with eval(). Because PHP interpolates double-quoted strings, a payload of the form {${...}} in the URL path is executed during interpolation, so no quote breakout is required and WordPress' slashing does not mitigate it. This makes it possible for unauthenticated attackers to execute arbitrary code on the server with a single GET request. The affected conditions ship enabled by default and are evaluated before any logged-in check, so no plugin configuration is needed; the site must have BuddyPress and Paid Memberships Pro active alongside this plugin.

- [https://github.com/LLCForge/CVE-2026-120539](https://github.com/LLCForge/CVE-2026-120539) :  ![starts](https://img.shields.io/github/stars/LLCForge/CVE-2026-120539.svg) ![forks](https://img.shields.io/github/forks/LLCForge/CVE-2026-120539.svg)


## CVE-2026-118028
Note: Tomcat 11.0.28 was not released

- [https://github.com/LLCForge/CVE-2026-118028](https://github.com/LLCForge/CVE-2026-118028) :  ![starts](https://img.shields.io/github/stars/LLCForge/CVE-2026-118028.svg) ![forks](https://img.shields.io/github/forks/LLCForge/CVE-2026-118028.svg)


## CVE-2026-116561
Note: Tomcat 11.0.28 was not released

- [https://github.com/LLCForge/CVE-2026-116561](https://github.com/LLCForge/CVE-2026-116561) :  ![starts](https://img.shields.io/github/stars/LLCForge/CVE-2026-116561.svg) ![forks](https://img.shields.io/github/forks/LLCForge/CVE-2026-116561.svg)


## CVE-2026-114938
 Vulnerability in the Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component: Compiler).  Supported versions that are affected are Oracle Java SE: 8u511b33-perf, 17.0.21.0.3, 21.0.13.0.3, 25.0.5.0.3, 27.0.1.0.3; Oracle GraalVM for JDK: 17.0.21.0.3 and  21.0.13.0.3; Oracle GraalVM Enterprise Edition: 21.3.20.0.3. Difficult to exploit vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition.  Successful attacks of this vulnerability can result in takeover of Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition. Note: This vulnerability can only be exploited by supplying data to APIs in the specified Component without using Untrusted Java Web Start applications or Untrusted Java applets, such as through a web service. CVSS 3.1 Base Score 8.1 (Confidentiality, Integrity and Availability impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/m19o/j4s-runner-check](https://github.com/m19o/j4s-runner-check) :  ![starts](https://img.shields.io/github/stars/m19o/j4s-runner-check.svg) ![forks](https://img.shields.io/github/forks/m19o/j4s-runner-check.svg)
- [https://github.com/akshutgoyal/Java4Shell](https://github.com/akshutgoyal/Java4Shell) :  ![starts](https://img.shields.io/github/stars/akshutgoyal/Java4Shell.svg) ![forks](https://img.shields.io/github/forks/akshutgoyal/Java4Shell.svg)
- [https://github.com/BanroxArt/jvm-sweep](https://github.com/BanroxArt/jvm-sweep) :  ![starts](https://img.shields.io/github/stars/BanroxArt/jvm-sweep.svg) ![forks](https://img.shields.io/github/forks/BanroxArt/jvm-sweep.svg)


## CVE-2026-114516
 Etherpad is a real-time collaborative editor. From 1.8.14 until 3.3.3, the pre-authentication /static/* plugin asset handler in src/node/utils/Minify.ts performs a backslash-to-forward-slash conversion after src/node/utils/sanitizePathname.ts has completed its POSIX path checks. On POSIX systems the sanitizer correctly treats backslashes as ordinary filename bytes, but the later conversion turns encoded backslash-separated parent-directory segments into traversal components without revalidation or containment. The expressPreSession registration and the always-present ep_etherpad-lite core pseudo-plugin make this path reachable without credentials, allowing a remote attacker to read any file available to the Etherpad process. Disclosed configuration or environment secrets can expose administrator credentials, after which the administrator plugin installer can provide in-process code execution and full server compromise. This issue is fixed in version 3.3.3.

- [https://github.com/LLCForge/CVE-2026-114516](https://github.com/LLCForge/CVE-2026-114516) :  ![starts](https://img.shields.io/github/stars/LLCForge/CVE-2026-114516.svg) ![forks](https://img.shields.io/github/forks/LLCForge/CVE-2026-114516.svg)
- [https://github.com/evenomn/CVE-2026-114516](https://github.com/evenomn/CVE-2026-114516) :  ![starts](https://img.shields.io/github/stars/evenomn/CVE-2026-114516.svg) ![forks](https://img.shields.io/github/forks/evenomn/CVE-2026-114516.svg)


## CVE-2026-111943
 On most platforms, Go uses the given system root certificates. However, in some narrower cases, the system trust stores may not be updated without further action. To defend against the narrower set of cases that may remain affected, a denylist was added in crypto/x509 to return an error when calling Verify with any of the known intermediate certificates that are no longer considered to be trustworthy.

- [https://github.com/shaofeihuang/emuddler](https://github.com/shaofeihuang/emuddler) :  ![starts](https://img.shields.io/github/stars/shaofeihuang/emuddler.svg) ![forks](https://img.shields.io/github/forks/shaofeihuang/emuddler.svg)


## CVE-2026-109619
 PHP has various global state that temporarily points into request memory. In some scenarios, global state may not be correctly reset, or may be repopulated after being reset. The global state may then refer to request memory even after it has been freed. Subsequent requests may read or branch on this stale state before it is fully initialized. Multiple strategies can trigger this condition and produce remote code execution (RCE).

- [https://github.com/GetPageSpeed/php2shell-check](https://github.com/GetPageSpeed/php2shell-check) :  ![starts](https://img.shields.io/github/stars/GetPageSpeed/php2shell-check.svg) ![forks](https://img.shields.io/github/forks/GetPageSpeed/php2shell-check.svg)


## CVE-2026-105307
 A vulnerability was detected in Casdoor up to 3.161.1. Affected is the function ApiFilter of the file routers/authz_filter.go of the component API Endpoint. Performing a manipulation results in missing authentication. The attack can be initiated remotely. The exploit is now public and may be used. The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/hanlin2002/CVE-2026-105307](https://github.com/hanlin2002/CVE-2026-105307) :  ![starts](https://img.shields.io/github/stars/hanlin2002/CVE-2026-105307.svg) ![forks](https://img.shields.io/github/forks/hanlin2002/CVE-2026-105307.svg)


## CVE-2026-104885
 OpenRemote is an open-source internet-of-things platform. Prior to 1.31.0, an authenticated user who obtains another user's MQTT session ID can disconnect that session across realm boundaries through the GET route GET {realm}/disconnect/{sessionID}. In manager/src/main/java/org/openremote/manager/security/UserResourceImpl.java, disconnectUserSession ignores the requested realm and calls mqttBrokerService.disconnectSession(sessionID) without checking session ownership; model/src/main/java/org/openremote/model/security/UserResource.java exposes the route without an @RolesAllowed restriction. The earlier cross-realm read-method guards did not cover this disconnect method, and same-realm users can also disconnect sessions they do not own. Session IDs are not trivially brute-forceable but may be exposed through monitoring, logs, or correlated API calls, and the unauthorized disconnect can disrupt MQTT connectivity across tenant boundaries without directly disclosing session data. This issue is fixed in 1.31.0.

- [https://github.com/googlesky/CVE-2026-104885](https://github.com/googlesky/CVE-2026-104885) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-104885.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-104885.svg)


## CVE-2026-104773
 CKAN is an open-source data management system for data hubs and data portals. Prior to 2.10.11 and 2.11.6, the web user registration flow authenticates a newly registered account without first regenerating the session identifier when server-side session storage is configured. An attacker who can set a session cookie in a victim's browser or obtain the victim's current valid session identifier can reuse that identifier after the victim registers, gaining access to the new account. CKAN uses cookie-based sessions by default, and web registration is disabled by default through ckan.auth.create_user_via_web. This issue is fixed in CKAN 2.10.11, 2.11.6, and 2.12.0.

- [https://github.com/googlesky/CVE-2026-104773](https://github.com/googlesky/CVE-2026-104773) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-104773.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-104773.svg)


## CVE-2026-104099
 Fabio is an HTTP(S) and TCP router for deploying applications managed by consul. Prior to 1.7.3, route/table.go selects targets using raw req.URL.Path, while proxy/http_proxy.go applies per-route ACL and basic-auth checks to the selected target and forwards the raw path to the origin. Dot-segment, encoded-dot, or repeated-slash variants can fall through to a less restrictive route that reaches the same backend; the backend then normalizes the path and serves the protected resource without the configured access controls. A less restrictive fallback route must reach the same backend; without one, the request returns 404. This issue is fixed in version 1.7.3.

- [https://github.com/LLCForge/CVE-2026-104099](https://github.com/LLCForge/CVE-2026-104099) :  ![starts](https://img.shields.io/github/stars/LLCForge/CVE-2026-104099.svg) ![forks](https://img.shields.io/github/forks/LLCForge/CVE-2026-104099.svg)


## CVE-2026-99320
the related RCU callback queued from vrf_l3_out().

- [https://github.com/ZZ2266/CVE-2026-99320](https://github.com/ZZ2266/CVE-2026-99320) :  ![starts](https://img.shields.io/github/stars/ZZ2266/CVE-2026-99320.svg) ![forks](https://img.shields.io/github/forks/ZZ2266/CVE-2026-99320.svg)


## CVE-2026-99312
CR0.PG must be '0').

- [https://github.com/suominen/CVE-2026-99312](https://github.com/suominen/CVE-2026-99312) :  ![starts](https://img.shields.io/github/stars/suominen/CVE-2026-99312.svg) ![forks](https://img.shields.io/github/forks/suominen/CVE-2026-99312.svg)


## CVE-2026-98260
[ tglx: Move the cleanup right after de_thread() ]

- [https://github.com/tiamo1990/shancha-kernel-workshop](https://github.com/tiamo1990/shancha-kernel-workshop) :  ![starts](https://img.shields.io/github/stars/tiamo1990/shancha-kernel-workshop.svg) ![forks](https://img.shields.io/github/forks/tiamo1990/shancha-kernel-workshop.svg)


## CVE-2026-95517
Note: Tomcat 11.0.28 was not released

- [https://github.com/LLCForge/CVE-2026-95517](https://github.com/LLCForge/CVE-2026-95517) :  ![starts](https://img.shields.io/github/stars/LLCForge/CVE-2026-95517.svg) ![forks](https://img.shields.io/github/forks/LLCForge/CVE-2026-95517.svg)


## CVE-2026-80188
 The BuddyBoss Addons plugin for WordPress is vulnerable to Authentication Bypass leading to Account Takeover in versions up to, and including, 1.2.1. This is due to the Social Login REST endpoint trusting unverified Apple and Facebook identity-token claims and linking an attacker-controlled provider identifier to an existing WordPress user selected by the token’s email claim. This makes it possible for unauthenticated attackers who know a user’s email address to associate their provider identity with that account, including administrator accounts, and subsequently authenticate as the victim. Successful exploitation requires the BuddyBoss Platform plugin to be installed and active, with the Social Login module and selected provider enabled and configured. On sites with the separate BuddyBoss App JWT component, the vulnerable REST request can return an application token immediately.

- [https://github.com/LLCForge/CVE-2026-80188](https://github.com/LLCForge/CVE-2026-80188) :  ![starts](https://img.shields.io/github/stars/LLCForge/CVE-2026-80188.svg) ![forks](https://img.shields.io/github/forks/LLCForge/CVE-2026-80188.svg)


## CVE-2026-77369
 Daptin is a GraphQL/JSON-API headless CMS. From 0.11.4 until 0.12.30, the generic GET /yjs/:documentName WebSocket route in InitializeYjsResources requires a session but does not authorize the database resource selected by a typename.referenceId.columnName room name. The YJS initial-content provider then reads the selected file.* column without CanRead or CanUpdate checks, and bidirectional synchronization allows a low-privileged authenticated user to read or modify restricted row content. Unauthenticated requests are rejected, and standalone non-canonical room names remain shared-by-name rooms. This issue is fixed in version 0.12.30.

- [https://github.com/LLCForge/CVE-2026-77369](https://github.com/LLCForge/CVE-2026-77369) :  ![starts](https://img.shields.io/github/stars/LLCForge/CVE-2026-77369.svg) ![forks](https://img.shields.io/github/forks/LLCForge/CVE-2026-77369.svg)


## CVE-2026-77367
 Daptin is a GraphQL/JSON-API headless CMS. Prior to 0.12.30, the generic GET /api/{entity} list endpoint accepts attacker-controlled sort values in PaginatedFindAllWithoutFilters in server/resource/resource_findallpaginated.go without validating the requested column against the table schema. The code uses those values for SELECT and ORDER BY identifier construction, so an embedded identifier quote can terminate the quoted identifier and make the remainder parse as SQL, allowing an unauthenticated attacker to extract unauthorized table data through blind or error-based behavior or repeatedly trigger query failures. This issue is fixed in version 0.12.30.

- [https://github.com/LLCForge/CVE-2026-77367](https://github.com/LLCForge/CVE-2026-77367) :  ![starts](https://img.shields.io/github/stars/LLCForge/CVE-2026-77367.svg) ![forks](https://img.shields.io/github/forks/LLCForge/CVE-2026-77367.svg)


## CVE-2026-77359
 Jupyter MCP Server is a Model Context Protocol server for Jupyter. Prior to 1.0.3, standalone streamable-http mode validates Host and Origin values for /mcp but does not apply the same browser-origin controls to the state-changing /api/connect and /api/stop management routes. A malicious website can use DNS rebinding so that its hostname resolves to a loopback, LAN, VPN, or published-container MCP listener, then send a browser-shaped request that /api/connect accepts to replace runtime_url and document_url values and start a kernel client against attacker-controlled infrastructure. The attacker can thereby cause Jupyter API and WebSocket traffic to reach that infrastructure and can use /api/stop to stop the current notebook kernel. The default broad bind can increase exposure, but the vulnerability is the missing management-route origin boundary, not a lack of Host validation on /mcp. This issue is fixed in version 1.0.3.

- [https://github.com/googlesky/CVE-2026-77359](https://github.com/googlesky/CVE-2026-77359) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-77359.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-77359.svg)


## CVE-2026-77332
 memtomem-stm is a short-term memory proxy gateway with proactive memory surfacing for AI agents. From 0.1.0 until 0.1.34, untrusted long-term and working-memory fields can introduce Markdown or HTML-compatible structure into the surfaced-memory envelope because those fields are not serialized as inert data. A crafted memory can create misleading structural boundaries or visually conceal surfaced content, affecting how a consuming agent interprets the memory context. Ordinary natural-language persuasion remains a residual model-level risk and is outside the structural serialization flaw. This issue is fixed in version 0.1.34.

- [https://github.com/googlesky/CVE-2026-77332](https://github.com/googlesky/CVE-2026-77332) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-77332.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-77332.svg)


## CVE-2026-77316
 Flyto2 Core is an execution kernel for automation and AI-agent workflows. Prior to 2.26.8, validate_url_ssrf() in src/core/utils.py validates one DNS answer and then returns the hostname, while guarded_aiohttp_request(), enforce_outbound_url(), and validate_url_with_env_config() allow the outbound connection to perform an independent second lookup. A caller with control of the hostname's DNS can make validation see a public address and make the connection see an internal address, bypassing the guard across its outbound consumers and exposing readable internal or metadata-service responses. The attack requires low or zero DNS TTL behavior and a successful timing-dependent answer change; static multiple-address answers are checked and do not provide the same bypass. This issue is fixed in version 2.26.8.

- [https://github.com/googlesky/CVE-2026-77316](https://github.com/googlesky/CVE-2026-77316) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-77316.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-77316.svg)


## CVE-2026-77315
 Flyto2 Core is an execution kernel for automation and AI-agent workflows. Prior to 2.26.8, http.paginate in src/core/modules/atomic/http/paginate.py validates only the initial base_url, and _paginate_link_header then follows a server-supplied Link: rel="next" URL without calling the SSRF guard again. A low-privileged caller can make an allowed first page point the next request at an internal or metadata service, causing a readable second-order SSRF whose response body is aggregated into all_items and returned. This issue is fixed in version 2.26.8.

- [https://github.com/googlesky/CVE-2026-77315](https://github.com/googlesky/CVE-2026-77315) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-77315.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-77315.svg)


## CVE-2026-77313
 Flyto2 Core is an execution kernel for automation and AI-agent workflows. Prior to 2.26.8, validate_url_ssrf in src/core/utils.py resolves and checks a hostname but returns the hostname URL rather than the validated address, and session.get in http.get performs an independent DNS lookup when connecting. A low-privileged caller with control of the hostname's DNS can make the first lookup return a public address and the connection-time lookup return an internal address, bypassing the SSRF guard for all modules that call it and exposing readable internal or metadata-service responses. Successful exploitation requires attacker-controlled DNS and a successful timing-dependent answer change between the two lookups. This issue is fixed in version 2.26.8.

- [https://github.com/googlesky/CVE-2026-77313](https://github.com/googlesky/CVE-2026-77313) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-77313.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-77313.svg)


## CVE-2026-77312
 Flyto2 Core is an execution kernel for automation and AI-agent workflows. Prior to 2.26.8, the earlier CVE-2026-67429 remediation applied validate_path_with_env_config() to only a hand-picked set of file-writing modules, leaving data.csv.write in src/core/modules/atomic/data/csv_write.py, data.json_to_csv in src/core/modules/atomic/data/json_to_csv.py, file.copy in src/core/modules/atomic/file/copy.py, and file.move in src/core/modules/atomic/file/move.py outside the FLYTO_SANDBOX_DIR confinement boundary. The advisory also identifies unguarded modules across the broader data.*, file.*, and report-writer families. data.csv.write relies on a .. substring denylist that does not reject absolute paths, while the other named modules accept caller-controlled output or destination paths without the canonical guard. A caller able to execute modules or recipes can therefore write attacker-controlled content outside the configured sandbox, potentially overwriting application code, recipes, startup files, scheduled-task files, or authorization files and gaining code execution on the host. This issue is fixed in version 2.26.8.

- [https://github.com/LLCForge/CVE-2026-77312](https://github.com/LLCForge/CVE-2026-77312) :  ![starts](https://img.shields.io/github/stars/LLCForge/CVE-2026-77312.svg) ![forks](https://img.shields.io/github/forks/LLCForge/CVE-2026-77312.svg)


## CVE-2026-76466
Note: Cisco Expressway Series refers to Cisco Expressway Core (Expressway-C) devices and Cisco Expressway Edge (Expressway-E) devices.

- [https://github.com/wa6n3r/cve-2026-76466](https://github.com/wa6n3r/cve-2026-76466) :  ![starts](https://img.shields.io/github/stars/wa6n3r/cve-2026-76466.svg) ![forks](https://img.shields.io/github/forks/wa6n3r/cve-2026-76466.svg)


## CVE-2026-69133
 netty-incubator-codec-ohttp implements Oblivious HTTP (OHTTP) gateway and client functionality using Netty. From 0.0.20.Final until 0.0.27.Final, OHttpClientCodec in codec-ohttp/src/main/java/io/netty/incubator/codec/ohttp/OHttpClientCodec.java and OHttpServerCodec in codec-ohttp/src/main/java/io/netty/incubator/codec/ohttp/OHttpServerCodec.java retain the consumed outer cumulationBuffer after a valid OHTTP exchange completes, even though OHttpRequestResponseContext.destroy in codec-ohttp/src/main/java/io/netty/incubator/codec/ohttp/OHttpRequestResponseContext.java releases the inner Binary HTTP cumulation and the channel remains active. A peer can complete a large request or response and leave the keep-alive connection idle, causing the client and server handlers to retain the current high-water pooled or direct buffer capacity until later inbound content replaces it or the handler is removed. Many long-lived idle connections can pin substantial memory and create availability pressure. The issue does not cause unbounded growth for repeated exchanges on a single channel. This issue is fixed in version 0.0.27.Final.

- [https://github.com/googlesky/CVE-2026-69133](https://github.com/googlesky/CVE-2026-69133) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-69133.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-69133.svg)


## CVE-2026-65094
 NVIDIA VIRTIO-Net for Bluefield contains a vulnerability in Virtio-Net where a VM user may cause a Write-What-Where condition by crafted message. A successful exploit of this vulnerability may lead to Code Execution in Virtio-Net scope.

- [https://github.com/LLCForge/CVE-2026-65094](https://github.com/LLCForge/CVE-2026-65094) :  ![starts](https://img.shields.io/github/stars/LLCForge/CVE-2026-65094.svg) ![forks](https://img.shields.io/github/forks/LLCForge/CVE-2026-65094.svg)


## CVE-2026-63415
 Jane is a set of PHP libraries that generates models and API clients from JSON Schema and OpenAPI specifications. Prior to 7.12.0, Jane's Reference.php::doResolve passes an attacker-controlled OpenAPI $ref target to file_get_contents without restricting its scheme or resolved local path. When a victim generates code from an attacker-influenced document, an HTTP or HTTPS reference can cause requests to attacker-chosen or internal services, while an absolute or parent-relative path can read local JSON or YAML files and inline the retrieved content into generated output. Exploitation occurs during generation or CI processing and can disclose local files and internal-service responses. This issue is fixed in version 7.12.0.

- [https://github.com/googlesky/CVE-2026-63415](https://github.com/googlesky/CVE-2026-63415) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-63415.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-63415.svg)


## CVE-2026-63346
 Refitter is a tool for generating a C# REST API client using the Refit library. Prior to 2.1.2, the header parameter name in `parameters[].name` with `in: header` is emitted verbatim into a Refit `[Header("name")]` attribute string without escaping quotation marks. An attacker-influenced OpenAPI description can pass default validation without `--skip-validation` and break out from the parameter-list position by closing the parameter and method syntax, attribute, interface, and namespace. The generated file can remain valid C# while containing a top-level file class with a `[ModuleInitializer]` method, which executes attacker code when the compiled assembly is loaded at application startup, even if the client is never called. Query `AliasAs` and enum/default value sinks are escaped; this flaw is in header-name attribute-string emission. The behavior was verified with Refitter 2.0.0 and .NET 8. This issue is fixed in version 2.1.2.

- [https://github.com/googlesky/CVE-2026-63346](https://github.com/googlesky/CVE-2026-63346) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-63346.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-63346.svg)


## CVE-2026-63345
 Refitter is a tool for generating a C# REST API client using the Refit library. Prior to 2.1.2, OpenAPI `paths`-object keys are emitted verbatim into Refit route attributes such as `[Get("path")]` without escaping quotation marks or restricting characters. An attacker-influenced single-line, slash-prefixed path survives default validation without `--skip-validation` and can close the attribute string, interface, and namespace while introducing a top-level file class and reopening the generated structure to keep valid C#. A `[ModuleInitializer]` method executes attacker code when an application compiles and loads the generated assembly at startup, even without calling the generated client. The enum and default value sinks are escaped and are not the vulnerable path-emission sink. The behavior was verified on Refitter 2.0.0 with .NET 8. This issue is fixed in version 2.1.2.

- [https://github.com/googlesky/CVE-2026-63345](https://github.com/googlesky/CVE-2026-63345) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-63345.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-63345.svg)


## CVE-2026-63344
 Refitter is a tool for generating a C# REST API client using the Refit library. Prior to 2.1.2, content-type keys in the content maps of `requestBody/responses` are emitted verbatim into a Refit `[Headers("Accept: ct", "Content-Type: ct")]` attribute string without escaping quotation marks. A crafted content-type key in an attacker-influenced OpenAPI description survives default validation without `--skip-validation`, breaks out of the attribute string and enclosing interface and namespace, and can introduce a top-level file class while leaving valid generated C#. A `[ModuleInitializer]` method in that class executes attacker code when the generated assembly is loaded at application startup, without requiring a call to the client. The behavior was verified with Refitter 2.0.0 and .NET 8. This issue is fixed in version 2.1.2.

- [https://github.com/googlesky/CVE-2026-63344](https://github.com/googlesky/CVE-2026-63344) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-63344.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-63344.svg)


## CVE-2026-63184
 Refitter is a tool for generating a C# REST API client using the Refit library. Prior to 2.1.1, the `refitter` dotnet tool invokes `NJsonSchema` with unsafe defaults for `$ref` resolution when generating Refit interfaces and contracts from attacker-controlled or attacker-influenced OpenAPI descriptions. Remote `http(s)` references cause requests from the developer or CI host and inline untrusted remote schema content into generated output. Absolute local file paths and relative `../` traversal outside the input directory also resolve and inline local content, permitting arbitrary local-file disclosure. The demonstrated chain stops at server-side request forgery, remote file inclusion, and local file inclusion, not code execution: Refit sets the base URL at runtime, enum values use verbatim-string doubling, and string defaults are escaped. This issue is fixed in version 2.1.1.

- [https://github.com/googlesky/CVE-2026-63184](https://github.com/googlesky/CVE-2026-63184) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-63184.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-63184.svg)


## CVE-2026-58254
 NATS Server is a high-performance server for NATS.io, the cloud and edge native messaging system. Prior to 2.14.3 and 2.12.8, message trace destination checks were applied to ordinary client connections but not consistently to messages arriving through leafnode connections, allowing a leafnode operator to send trace events to subjects that would not otherwise be permitted and to use trace-only behavior to prevent normal delivery or storage of affected messages. This issue is fixed in versions 2.14.3 and 2.12.8.

- [https://github.com/googlesky/CVE-2026-58254](https://github.com/googlesky/CVE-2026-58254) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-58254.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-58254.svg)


## CVE-2026-46333
set), and require a proper CAP_SYS_PTRACE capability to override.

- [https://github.com/Luscious8/Poc-CVE-2026-46333](https://github.com/Luscious8/Poc-CVE-2026-46333) :  ![starts](https://img.shields.io/github/stars/Luscious8/Poc-CVE-2026-46333.svg) ![forks](https://img.shields.io/github/forks/Luscious8/Poc-CVE-2026-46333.svg)
- [https://github.com/Luscious8/CVE-2026-46333-PoC](https://github.com/Luscious8/CVE-2026-46333-PoC) :  ![starts](https://img.shields.io/github/stars/Luscious8/CVE-2026-46333-PoC.svg) ![forks](https://img.shields.io/github/forks/Luscious8/CVE-2026-46333-PoC.svg)


## CVE-2026-43499
  	changelog ]

- [https://github.com/accessmodifier364/cve-2026-43499-firetv-sheldonp-writeup](https://github.com/accessmodifier364/cve-2026-43499-firetv-sheldonp-writeup) :  ![starts](https://img.shields.io/github/stars/accessmodifier364/cve-2026-43499-firetv-sheldonp-writeup.svg) ![forks](https://img.shields.io/github/forks/accessmodifier364/cve-2026-43499-firetv-sheldonp-writeup.svg)


## CVE-2026-43284
destination-frag path or fall back to skb_cow_data().

- [https://github.com/fakehec/plex2shell-to-root](https://github.com/fakehec/plex2shell-to-root) :  ![starts](https://img.shields.io/github/stars/fakehec/plex2shell-to-root.svg) ![forks](https://img.shields.io/github/forks/fakehec/plex2shell-to-root.svg)


## CVE-2026-39987
 marimo is a reactive Python notebook. Prior to 0.23.0, Marimo has a Pre-Auth RCE vulnerability. The terminal WebSocket endpoint /terminal/ws lacks authentication validation, allowing an unauthenticated attacker to obtain a full PTY shell and execute arbitrary system commands. Unlike other WebSocket endpoints (e.g., /ws) that correctly call validate_auth() for authentication, the /terminal/ws endpoint only checks the running mode and platform support before accepting connections, completely skipping authentication verification. This vulnerability is fixed in 0.23.0.

- [https://github.com/RockKingdom/Marimo-CVE-2026-39987](https://github.com/RockKingdom/Marimo-CVE-2026-39987) :  ![starts](https://img.shields.io/github/stars/RockKingdom/Marimo-CVE-2026-39987.svg) ![forks](https://img.shields.io/github/forks/RockKingdom/Marimo-CVE-2026-39987.svg)


## CVE-2026-35377
 A logic error in the env utility of uutils coreutils causes a failure to correctly parse command-line arguments when utilizing the -S (split-string) option. In GNU env, backslashes within single quotes are treated literally (with the exceptions of \\ and \'). However, the uutils implementation incorrectly attempts to validate these sequences, resulting in an "invalid sequence" error and an immediate process termination with an exit status of 125 when encountering valid but unrecognized sequences like \a or \x. This divergence from GNU behavior breaks compatibility for automated scripts and administrative workflows that rely on standard split-string semantics, leading to a local denial of service for those operations.

- [https://github.com/googlesky/CVE-2026-35377](https://github.com/googlesky/CVE-2026-35377) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-35377.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-35377.svg)


## CVE-2026-35374
 A Time-of-Check to Time-of-Use (TOCTOU) vulnerability exists in the split utility of uutils coreutils. The program attempts to prevent data loss by checking for identity between input and output files using their file paths before initiating the split operation. However, the utility subsequently opens the output file with truncation after this path-based validation is complete. A local attacker with write access to the directory can exploit this race window by manipulating mutable path components (e.g., swapping a path with a symbolic link). This can cause split to truncate and write to an unintended target file, potentially including the input file itself or other sensitive files accessible to the process, leading to permanent data loss.

- [https://github.com/googlesky/CVE-2026-35374](https://github.com/googlesky/CVE-2026-35374) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-35374.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-35374.svg)


## CVE-2026-34472
 Unauthenticated credential disclosure in the wizard interface in ZTE ZXHN H188A V6.0.10P2_TE and V6.0.10P3N3_TE allows unauthenticated attackers on the local network to retrieve sensitive credentials from the router's web management interface, including the default administrator password, WLAN PSK, and PPPoE credentials. In some observed cases, configuration changes may also be performed without authentication.

- [https://github.com/muhammadaliattai-source/router-security-audit](https://github.com/muhammadaliattai-source/router-security-audit) :  ![starts](https://img.shields.io/github/stars/muhammadaliattai-source/router-security-audit.svg) ![forks](https://img.shields.io/github/forks/muhammadaliattai-source/router-security-audit.svg)


## CVE-2026-33252
 The Go MCP SDK used Go's standard encoding/json. Prior to version 1.4.1, the Go SDK's Streamable HTTP transport accepted browser-generated cross-site `POST` requests without validating the `Origin` header and without requiring `Content-Type: application/json`. In deployments without Authorization, especially stateless or sessionless configurations, this allows an arbitrary website to send MCP requests to a local server and potentially trigger tool execution. Version 1.4.1 contains a patch for the issue.

- [https://github.com/garag0l/nuclei-templates-mcp](https://github.com/garag0l/nuclei-templates-mcp) :  ![starts](https://img.shields.io/github/stars/garag0l/nuclei-templates-mcp.svg) ![forks](https://img.shields.io/github/forks/garag0l/nuclei-templates-mcp.svg)


## CVE-2026-14914
This issue affects Tegsoft Contact Center: before latest-202611161510.

- [https://github.com/LLCForge/CVE-2026-14914](https://github.com/LLCForge/CVE-2026-14914) :  ![starts](https://img.shields.io/github/stars/LLCForge/CVE-2026-14914.svg) ![forks](https://img.shields.io/github/forks/LLCForge/CVE-2026-14914.svg)


## CVE-2026-12118
 IBM webMethods Integration (on prem) 10.15, 10.11 could allow an unauthenticated remote attacker to execute arbitrary code on the system due to the deserialization of untrusted data.

- [https://github.com/overflowed7/CVE-2026-12118-PoC](https://github.com/overflowed7/CVE-2026-12118-PoC) :  ![starts](https://img.shields.io/github/stars/overflowed7/CVE-2026-12118-PoC.svg) ![forks](https://img.shields.io/github/forks/overflowed7/CVE-2026-12118-PoC.svg)


## CVE-2026-10961
 Use after free in Chrome for iOS in Google Chrome on iOS prior to 149.0.7827.53 allowed a remote attacker who had compromised the renderer process to potentially perform a sandbox escape via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/xaviware/go-php2shell-scanner-CVE-2026-109618-CVE-2026-109619](https://github.com/xaviware/go-php2shell-scanner-CVE-2026-109618-CVE-2026-109619) :  ![starts](https://img.shields.io/github/stars/xaviware/go-php2shell-scanner-CVE-2026-109618-CVE-2026-109619.svg) ![forks](https://img.shields.io/github/forks/xaviware/go-php2shell-scanner-CVE-2026-109618-CVE-2026-109619.svg)
- [https://github.com/anldori/CVE-2026-109618](https://github.com/anldori/CVE-2026-109618) :  ![starts](https://img.shields.io/github/stars/anldori/CVE-2026-109618.svg) ![forks](https://img.shields.io/github/forks/anldori/CVE-2026-109618.svg)


## CVE-2026-1096
 The Best-wp-google-map plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the 'latitude' and 'longitudinal' parameters of the 'google_map_view' shortcode in all versions up to, and including, 2.1 due to insufficient input sanitization and output escaping. This makes it possible for authenticated attackers, with Contributor-level access and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.

- [https://github.com/debugactiveprocess/CVE-2026-109618](https://github.com/debugactiveprocess/CVE-2026-109618) :  ![starts](https://img.shields.io/github/stars/debugactiveprocess/CVE-2026-109618.svg) ![forks](https://img.shields.io/github/forks/debugactiveprocess/CVE-2026-109618.svg)
- [https://github.com/skydwn/CVE-2026-109618](https://github.com/skydwn/CVE-2026-109618) :  ![starts](https://img.shields.io/github/stars/skydwn/CVE-2026-109618.svg) ![forks](https://img.shields.io/github/forks/skydwn/CVE-2026-109618.svg)


## CVE-2026-1048
 A weakness has been identified in LigeroSmart up to 6.1.26. Impacted is an unknown function of the file /otrs/index.pl?Action=AgentTicketZoom. This manipulation of the argument TicketID causes cross site scripting. It is possible to initiate the attack remotely. The exploit has been made available to the public and could be used for attacks. The project was informed of the problem early through an issue report but has not responded yet.

- [https://github.com/googlesky/CVE-2026-104882](https://github.com/googlesky/CVE-2026-104882) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-104882.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-104882.svg)
- [https://github.com/googlesky/CVE-2026-104884](https://github.com/googlesky/CVE-2026-104884) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-104884.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-104884.svg)
- [https://github.com/googlesky/CVE-2026-104881](https://github.com/googlesky/CVE-2026-104881) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-104881.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-104881.svg)
- [https://github.com/googlesky/CVE-2026-104883](https://github.com/googlesky/CVE-2026-104883) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-104883.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-104883.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-tilde](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-tilde) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-tilde.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-tilde.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-zero-installs](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-zero-installs) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-zero-installs.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-zero-installs.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-alias](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-alias) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-alias.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-alias.svg)


## CVE-2025-49596
 The MCP inspector is a developer tool for testing and debugging MCP servers. Versions of MCP Inspector below 0.14.1 are vulnerable to remote code execution due to lack of authentication between the Inspector client and proxy, allowing unauthenticated requests to launch MCP commands over stdio. Users should immediately upgrade to version 0.14.1 or later to address these vulnerabilities.

- [https://github.com/Vitao18/mac0696-ep2-cves](https://github.com/Vitao18/mac0696-ep2-cves) :  ![starts](https://img.shields.io/github/stars/Vitao18/mac0696-ep2-cves.svg) ![forks](https://img.shields.io/github/forks/Vitao18/mac0696-ep2-cves.svg)


## CVE-2025-48617
 In overrideConfig of CarrierConfigLoader.java, there is a possible way to bypass UID check due to a permissions bypass. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/Chiiz0/Stateside](https://github.com/Chiiz0/Stateside) :  ![starts](https://img.shields.io/github/stars/Chiiz0/Stateside.svg) ![forks](https://img.shields.io/github/forks/Chiiz0/Stateside.svg)


## CVE-2025-10890
 Side-channel information leakage in V8 in Google Chrome prior to 140.0.7339.207 allowed a remote attacker to leak cross-origin data via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/SpiralBL0CK/CVE-2025-10890-lab](https://github.com/SpiralBL0CK/CVE-2025-10890-lab) :  ![starts](https://img.shields.io/github/stars/SpiralBL0CK/CVE-2025-10890-lab.svg) ![forks](https://img.shields.io/github/forks/SpiralBL0CK/CVE-2025-10890-lab.svg)


## CVE-2025-6647
The specific flaw exists within the parsing of U3D files. The issue results from the lack of proper validation of user-supplied data, which can result in a write past the end of an allocated object. An attacker can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-26644.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions.svg)


## CVE-2025-5518
This issue affects BILGER: before 2.4.6.

- [https://github.com/Nkwenti-Severian-Ndongtsop/POC_react2shell_CVE-2025-55182](https://github.com/Nkwenti-Severian-Ndongtsop/POC_react2shell_CVE-2025-55182) :  ![starts](https://img.shields.io/github/stars/Nkwenti-Severian-Ndongtsop/POC_react2shell_CVE-2025-55182.svg) ![forks](https://img.shields.io/github/forks/Nkwenti-Severian-Ndongtsop/POC_react2shell_CVE-2025-55182.svg)


## CVE-2024-0265
 A vulnerability was found in SourceCodester Clinic Queuing System 1.0. It has been rated as critical. This issue affects some unknown processing of the file /index.php of the component GET Parameter Handler. The manipulation of the argument page leads to file inclusion. The attack may be initiated remotely. The exploit has been disclosed to the public and may be used. The identifier VDB-249821 was assigned to this vulnerability.

- [https://github.com/wh1t3w1s4/CVE-2024-0264-PoC](https://github.com/wh1t3w1s4/CVE-2024-0264-PoC) :  ![starts](https://img.shields.io/github/stars/wh1t3w1s4/CVE-2024-0264-PoC.svg) ![forks](https://img.shields.io/github/forks/wh1t3w1s4/CVE-2024-0264-PoC.svg)


## CVE-2024-0264
 A vulnerability was found in SourceCodester Clinic Queuing System 1.0. It has been declared as critical. This vulnerability affects unknown code of the file /LoginRegistration.php. The manipulation of the argument formToken leads to authorization bypass. The attack can be initiated remotely. The exploit has been disclosed to the public and may be used. The identifier of this vulnerability is VDB-249820.

- [https://github.com/wh1t3w1s4/CVE-2024-0264-PoC](https://github.com/wh1t3w1s4/CVE-2024-0264-PoC) :  ![starts](https://img.shields.io/github/stars/wh1t3w1s4/CVE-2024-0264-PoC.svg) ![forks](https://img.shields.io/github/forks/wh1t3w1s4/CVE-2024-0264-PoC.svg)


## CVE-2023-47504
 Improper Authentication vulnerability in Elementor Elementor Website Builder allows Accessing Functionality Not Properly Constrained by ACLs.This issue affects Elementor Website Builder: from n/a through 3.16.4.

- [https://github.com/davidxbors/CVE-2023-47504-POC](https://github.com/davidxbors/CVE-2023-47504-POC) :  ![starts](https://img.shields.io/github/stars/davidxbors/CVE-2023-47504-POC.svg) ![forks](https://img.shields.io/github/forks/davidxbors/CVE-2023-47504-POC.svg)


## CVE-2023-34362
 In Progress MOVEit Transfer before 2021.0.6 (13.0.6), 2021.1.4 (13.1.4), 2022.0.4 (14.0.4), 2022.1.5 (14.1.5), and 2023.0.1 (15.0.1), a SQL injection vulnerability has been found in the MOVEit Transfer web application that could allow an unauthenticated attacker to gain access to MOVEit Transfer's database. Depending on the database engine being used (MySQL, Microsoft SQL Server, or Azure SQL), an attacker may be able to infer information about the structure and contents of the database, and execute SQL statements that alter or delete database elements. NOTE: this is exploited in the wild in May and June 2023; exploitation of unpatched systems can occur via HTTP or HTTPS. All versions (e.g., 2020.0 and 2019x) before the five explicitly mentioned versions are affected, including older unsupported versions.

- [https://github.com/khaled970r/moveit-breach-analysis-sqli](https://github.com/khaled970r/moveit-breach-analysis-sqli) :  ![starts](https://img.shields.io/github/stars/khaled970r/moveit-breach-analysis-sqli.svg) ![forks](https://img.shields.io/github/forks/khaled970r/moveit-breach-analysis-sqli.svg)


## CVE-2022-0847
 A flaw was found in the way the "flags" member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/pmihsan/Dirty-Pipe-CVE-2022-0847](https://github.com/pmihsan/Dirty-Pipe-CVE-2022-0847) :  ![starts](https://img.shields.io/github/stars/pmihsan/Dirty-Pipe-CVE-2022-0847.svg) ![forks](https://img.shields.io/github/forks/pmihsan/Dirty-Pipe-CVE-2022-0847.svg)


## CVE-2021-42013
 It was found that the fix for CVE-2021-41773 in Apache HTTP Server 2.4.50 was insufficient. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue only affects Apache 2.4.49 and Apache 2.4.50 and not earlier versions.

- [https://github.com/wvverez/CVE-2021-42013](https://github.com/wvverez/CVE-2021-42013) :  ![starts](https://img.shields.io/github/stars/wvverez/CVE-2021-42013.svg) ![forks](https://img.shields.io/github/forks/wvverez/CVE-2021-42013.svg)


## CVE-2021-4422
 The POST SMTP Mailer plugin for WordPress is vulnerable to Cross-Site Request Forgery in versions up to, and including, 2.0.20. This is due to missing or incorrect nonce validation on the handleCsvExport() function. This makes it possible for unauthenticated attackers to trigger a CSV export via a forged request granted they can trick a site administrator into performing an action such as clicking on a link.

- [https://github.com/Morgenlicht1210/log4j2-cve-2021-44228-poc](https://github.com/Morgenlicht1210/log4j2-cve-2021-44228-poc) :  ![starts](https://img.shields.io/github/stars/Morgenlicht1210/log4j2-cve-2021-44228-poc.svg) ![forks](https://img.shields.io/github/forks/Morgenlicht1210/log4j2-cve-2021-44228-poc.svg)


## CVE-2021-4177
 livehelperchat is vulnerable to Generation of Error Message Containing Sensitive Information

- [https://github.com/sotiak/CVE-2021-41773](https://github.com/sotiak/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/sotiak/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/sotiak/CVE-2021-41773.svg)
- [https://github.com/R3leant/CVE-2021-41773](https://github.com/R3leant/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/R3leant/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/R3leant/CVE-2021-41773.svg)


## CVE-2021-1905
 Possible use after free due to improper handling of memory mapping of multiple processes simultaneously. in Snapdragon Auto, Snapdragon Compute, Snapdragon Connectivity, Snapdragon Consumer IOT, Snapdragon Industrial IOT, Snapdragon Mobile, Snapdragon Voice & Music, Snapdragon Wearables

- [https://github.com/Gonvar/movistar-home-root](https://github.com/Gonvar/movistar-home-root) :  ![starts](https://img.shields.io/github/stars/Gonvar/movistar-home-root.svg) ![forks](https://img.shields.io/github/forks/Gonvar/movistar-home-root.svg)

