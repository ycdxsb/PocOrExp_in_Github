# Update 2026-09-22
## CVE-2026-94036
 A security flaw has been discovered in D-Link DIR-X1860 and DIR-X1860Z up to 1.0.2.220120.165402. The impacted element is an unknown function of the file /ubus of the component routerd. The manipulation of the argument passwd_set results in improper access controls. The attack must originate from the local network. The exploit has been released to the public and may be used for attacks.

- [https://github.com/djzzlim/CVE-2026-94036](https://github.com/djzzlim/CVE-2026-94036) :  ![starts](https://img.shields.io/github/stars/djzzlim/CVE-2026-94036.svg) ![forks](https://img.shields.io/github/forks/djzzlim/CVE-2026-94036.svg)


## CVE-2026-93958
 A vulnerability was found in D-Link R95 BE9500_1.00.16. This vulnerability affects the function system of the file /bin/ssi of the component DHMAPI. The manipulation of the argument NTPServer results in os command injection. The attack can be executed remotely. The exploit has been made public and could be used.

- [https://github.com/HackSpeak/CVE-2026-93958](https://github.com/HackSpeak/CVE-2026-93958) :  ![starts](https://img.shields.io/github/stars/HackSpeak/CVE-2026-93958.svg) ![forks](https://img.shields.io/github/forks/HackSpeak/CVE-2026-93958.svg)


## CVE-2026-89274
 The WP Recipe Maker plugin for WordPress is vulnerable to Arbitrary Shortcode Execution in all versions up to, and including, 10.8.1. The vulnerability exists because `WPRM_Metadata::sanitize_metadata()` recursively calls `do_shortcode()` on every scalar field of the recipe's structured metadata array — including the `reviewBody` field, which is populated verbatim from the `comment_content` of approved `wprm-comment-rating` comments — without sanitizing or stripping shortcode tokens before execution; the subsequent `wp_strip_all_tags()` and `strip_shortcodes()` calls operate only on the output string after execution has already fully occurred, providing no protection against server-side shortcode invocation. This makes it possible for unauthenticated attackers to execute arbitrary registered WordPress shortcodes server-side on every recipe page render, causing shortcode output — such as attachment captions, private post fields, or other data exposed by installed shortcodes — to be embedded in the page's JSON-LD `reviewBody` metadata and disclosed to all visitors who load the recipe page. Successful exploitation requires the attacker's rated comment to pass the site's comment approval threshold, either via auto-approval or moderator action, before the injected shortcode begins executing on page loads.

- [https://github.com/Polosss/By-Poloss..-.CVE-2026-89274](https://github.com/Polosss/By-Poloss..-.CVE-2026-89274) :  ![starts](https://img.shields.io/github/stars/Polosss/By-Poloss..-.CVE-2026-89274.svg) ![forks](https://img.shields.io/github/forks/Polosss/By-Poloss..-.CVE-2026-89274.svg)


## CVE-2026-88854
 Joomla Extension - OrdaSoft.com - Unauthenticated SQL Injection in OrdaSoft Joomla Gallery extension for Joomla  6.2.7 - The extensions showSearchResult() and showSearchResultAjax() read the textsearch/searchText request parameter with $input-getVar(), which is not a real Joomla filter method and falls through to a filter that strips HTML tags but does not touch quotes or SQL syntax. The value is concatenated directly into a LIKE clause with no escaping. The endpoint requires no login of any kind: mod_osgallery_search is a public, commonly-published search box. Any anonymous site visitor can inject a UNION SELECT and read arbitrary database content.

- [https://github.com/murrez/CVE-2026-88854](https://github.com/murrez/CVE-2026-88854) :  ![starts](https://img.shields.io/github/stars/murrez/CVE-2026-88854.svg) ![forks](https://img.shields.io/github/forks/murrez/CVE-2026-88854.svg)


## CVE-2026-86555
 The ZTE SmartLife application has a hardcoded key. The key used to decrypt account server information is stored in plaintext in the code. Once the key is obtained, the server information can be decrypted, thus exposing it.

- [https://github.com/minanagehsalalma/zte-smartlife-app-pwned](https://github.com/minanagehsalalma/zte-smartlife-app-pwned) :  ![starts](https://img.shields.io/github/stars/minanagehsalalma/zte-smartlife-app-pwned.svg) ![forks](https://img.shields.io/github/forks/minanagehsalalma/zte-smartlife-app-pwned.svg)


## CVE-2026-86554
 SmartLife app dynamically generates brand‑new SmartLife application authentication parameters within its runtime process. With the obtained SmartLife application authentication parameters, attackers can directly invoke the backend interface /account/verify.serv to determine whether a target email address is registered for a SmartLife account. If the account exists, the real backend account ID can also be retrieved.

- [https://github.com/minanagehsalalma/zte-smartlife-app-pwned](https://github.com/minanagehsalalma/zte-smartlife-app-pwned) :  ![starts](https://img.shields.io/github/stars/minanagehsalalma/zte-smartlife-app-pwned.svg) ![forks](https://img.shields.io/github/forks/minanagehsalalma/zte-smartlife-app-pwned.svg)


## CVE-2026-86553
 SmartLife app dynamically generates fresh SmartLife application authentication parameters inside its runtime process. Using the acquired SmartLife application authentication parameters, an attacker can directly call the backend interface /account/verify.serv to obtain the real account ID corresponding to a registered email address. By spoofing the application authentication information together with the target account ID, the attacker can reset the password of the target account.

- [https://github.com/minanagehsalalma/zte-smartlife-app-pwned](https://github.com/minanagehsalalma/zte-smartlife-app-pwned) :  ![starts](https://img.shields.io/github/stars/minanagehsalalma/zte-smartlife-app-pwned.svg) ![forks](https://img.shields.io/github/forks/minanagehsalalma/zte-smartlife-app-pwned.svg)


## CVE-2026-86552
 SmartLife app dynamically generates brand‑new SmartLife application authentication parameters at runtime. With the acquired SmartLife application authentication credentials, an attacker can directly complete registration using any arbitrary email address via the backend interface /account/person/signup.serv. Email ownership is not verified prior to registration.

- [https://github.com/minanagehsalalma/zte-smartlife-app-pwned](https://github.com/minanagehsalalma/zte-smartlife-app-pwned) :  ![starts](https://img.shields.io/github/stars/minanagehsalalma/zte-smartlife-app-pwned.svg) ![forks](https://img.shields.io/github/forks/minanagehsalalma/zte-smartlife-app-pwned.svg)


## CVE-2026-78306
Remediation requires a firmware update from the vendor.

- [https://github.com/Wh02m1/CVE-2026-78306](https://github.com/Wh02m1/CVE-2026-78306) :  ![starts](https://img.shields.io/github/stars/Wh02m1/CVE-2026-78306.svg) ![forks](https://img.shields.io/github/forks/Wh02m1/CVE-2026-78306.svg)


## CVE-2026-77812
Remediation requires a firmware update from the vendor. There is no user-side mitigation that fully addresses the vulnerability without upgrading.

- [https://github.com/Wh02m1/CVE-2026-77812](https://github.com/Wh02m1/CVE-2026-77812) :  ![starts](https://img.shields.io/github/stars/Wh02m1/CVE-2026-77812.svg) ![forks](https://img.shields.io/github/forks/Wh02m1/CVE-2026-77812.svg)


## CVE-2026-71217
 A flaw was found in iperf3. A remote attacker can exploit this vulnerability by sending crafted control-channel JSON with oversized numeric parameters, such as `parallel` and `len`, which are not properly validated by the server. This improper input validation can lead to excessive stream and thread creation, as well as large buffer allocations, causing resource exhaustion. Consequently, this can result in a Denial of Service (DoS) on the affected iperf3 server.

- [https://github.com/Reelix/CVE-2026-71217-PoC](https://github.com/Reelix/CVE-2026-71217-PoC) :  ![starts](https://img.shields.io/github/stars/Reelix/CVE-2026-71217-PoC.svg) ![forks](https://img.shields.io/github/forks/Reelix/CVE-2026-71217-PoC.svg)


## CVE-2026-53266
before calling skb_store_bits().

- [https://github.com/suominen/CVE-2026-53266](https://github.com/suominen/CVE-2026-53266) :  ![starts](https://img.shields.io/github/stars/suominen/CVE-2026-53266.svg) ![forks](https://img.shields.io/github/forks/suominen/CVE-2026-53266.svg)


## CVE-2026-43499
  	changelog ]

- [https://github.com/TheAndersMadsen/humane-aipin-ghostlock](https://github.com/TheAndersMadsen/humane-aipin-ghostlock) :  ![starts](https://img.shields.io/github/stars/TheAndersMadsen/humane-aipin-ghostlock.svg) ![forks](https://img.shields.io/github/forks/TheAndersMadsen/humane-aipin-ghostlock.svg)


## CVE-2026-41452
 Krayin CRM 2.2.4 contains a missing authentication vulnerability in the installer middleware that allows unauthenticated remote attackers to overwrite the primary administrator account by sending a crafted HTTP POST request with the X-Requested-With: XMLHttpRequest header to bypass the CanInstall middleware redirect check. Attackers can supply arbitrary name, email, and password values to the admin-config-setup endpoint, which performs an unauthenticated updateOrInsert targeting the hardcoded administrator user ID, enabling full administrative access to all CRM data.

- [https://github.com/o-sec/CVE-2026-41452-poc](https://github.com/o-sec/CVE-2026-41452-poc) :  ![starts](https://img.shields.io/github/stars/o-sec/CVE-2026-41452-poc.svg) ![forks](https://img.shields.io/github/forks/o-sec/CVE-2026-41452-poc.svg)


## CVE-2026-39987
 marimo is a reactive Python notebook. Prior to 0.23.0, Marimo has a Pre-Auth RCE vulnerability. The terminal WebSocket endpoint /terminal/ws lacks authentication validation, allowing an unauthenticated attacker to obtain a full PTY shell and execute arbitrary system commands. Unlike other WebSocket endpoints (e.g., /ws) that correctly call validate_auth() for authentication, the /terminal/ws endpoint only checks the running mode and platform support before accepting connections, completely skipping authentication verification. This vulnerability is fixed in 0.23.0.

- [https://github.com/mfahdk/CVE-2026-39987_RCE_PoC](https://github.com/mfahdk/CVE-2026-39987_RCE_PoC) :  ![starts](https://img.shields.io/github/stars/mfahdk/CVE-2026-39987_RCE_PoC.svg) ![forks](https://img.shields.io/github/forks/mfahdk/CVE-2026-39987_RCE_PoC.svg)


## CVE-2026-36213
 An issue in Microvirt MEmu Android Emulator 9.2.7.0 allows a local attacker to escalate privileges via the MemuService.exe component.

- [https://github.com/g17hubH4ck/CVE-2026-36213-poc](https://github.com/g17hubH4ck/CVE-2026-36213-poc) :  ![starts](https://img.shields.io/github/stars/g17hubH4ck/CVE-2026-36213-poc.svg) ![forks](https://img.shields.io/github/forks/g17hubH4ck/CVE-2026-36213-poc.svg)


## CVE-2026-33439
 Open Access Management (OpenAM) is an access management solution. Prior to 16.0.6, OpenIdentityPlatform OpenAM is vulnerable to pre-authentication Remote Code Execution (RCE) via unsafe Java deserialization of the jato.clientSession HTTP parameter. This bypasses the WhitelistObjectInputStream mitigation that was applied to the jato.pageSession parameter after CVE-2021-35464. An unauthenticated attacker can achieve arbitrary command execution on the server by sending a crafted serialized Java object as the jato.clientSession GET/POST parameter to any JATO ViewBean endpoint whose JSP contains jato:form tags (e.g., the Password Reset pages). This vulnerability is fixed in 16.0.6.

- [https://github.com/rh33t/CVE-2026-33439-Poc](https://github.com/rh33t/CVE-2026-33439-Poc) :  ![starts](https://img.shields.io/github/stars/rh33t/CVE-2026-33439-Poc.svg) ![forks](https://img.shields.io/github/forks/rh33t/CVE-2026-33439-Poc.svg)


## CVE-2026-28609
 In read of MatroskaExtractor.cpp, there is a possible out-of-bounds write due to improper casting. This could lead to remote code execution with no additional execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/devrodT2/CVE-2026-28609-matroska-pcm-oob](https://github.com/devrodT2/CVE-2026-28609-matroska-pcm-oob) :  ![starts](https://img.shields.io/github/stars/devrodT2/CVE-2026-28609-matroska-pcm-oob.svg) ![forks](https://img.shields.io/github/forks/devrodT2/CVE-2026-28609-matroska-pcm-oob.svg)


## CVE-2026-23744
 MCPJam inspector is the local-first development platform for MCP servers. Versions 1.4.2 and earlier are vulnerable to remote code execution (RCE) vulnerability, which allows an attacker to send a crafted HTTP request that triggers the installation of an MCP server, leading to RCE. Since MCPJam inspector by default listens on 0.0.0.0 instead of 127.0.0.1, an attacker can trigger the RCE remotely via a simple HTTP request. Version 1.4.3 contains a patch.

- [https://github.com/0xSoulaimane/CVE-2026-23744-POC](https://github.com/0xSoulaimane/CVE-2026-23744-POC) :  ![starts](https://img.shields.io/github/stars/0xSoulaimane/CVE-2026-23744-POC.svg) ![forks](https://img.shields.io/github/forks/0xSoulaimane/CVE-2026-23744-POC.svg)


## CVE-2026-23111
skip active elements, process inactive ones.

- [https://github.com/vvsy46/CVE-2026-23111-PoC](https://github.com/vvsy46/CVE-2026-23111-PoC) :  ![starts](https://img.shields.io/github/stars/vvsy46/CVE-2026-23111-PoC.svg) ![forks](https://img.shields.io/github/forks/vvsy46/CVE-2026-23111-PoC.svg)


## CVE-2026-7884
 IBM Cognos Analytics 12.1.0 through 12.1.3 FP1, and 12.0.4 through 12.0.4 FP2 allows a non-privileged user to edit their given name and surname to include malicious JavaScript code. When an administrator later accesses the user account management panel and views that user's permissions, the malicious JavaScript code is executed. This could result in the cookies from the administrator being compromised.

- [https://github.com/0Linear/CVE-2026-78844](https://github.com/0Linear/CVE-2026-78844) :  ![starts](https://img.shields.io/github/stars/0Linear/CVE-2026-78844.svg) ![forks](https://img.shields.io/github/forks/0Linear/CVE-2026-78844.svg)


## CVE-2026-5524
 The Divi Form Builder plugin for WordPress is vulnerable to Arbitrary File Upload leading to Remote Code Execution in all versions up to and including 5.1.8. This is due to insufficient file extension validation in the do_image_upload() function where user-supplied input from the acceptFileTypes POST parameter is directly interpolated into a regular expression used to validate uploaded files. Attackers can specify PHP-executable extensions such as .phtml, .phar, .php5, or .php7 to bypass the plugin's .htaccess protection which only blocks .php files specifically. Additionally, on Nginx-based servers, the .htaccess protection is completely ineffective as Nginx does not process .htaccess files. This makes it possible for unauthenticated attackers (who can obtain a nonce from any public page containing a form) to upload executable PHP files to the publicly accessible /wp-content/uploads/de_fb_uploads/ directory and achieve Remote Code Execution by accessing the uploaded file via HTTP. The vulnerability was partially patched in version 5.1.3.

- [https://github.com/iicaicai/CVE-2026-5524-PoC](https://github.com/iicaicai/CVE-2026-5524-PoC) :  ![starts](https://img.shields.io/github/stars/iicaicai/CVE-2026-5524-PoC.svg) ![forks](https://img.shields.io/github/forks/iicaicai/CVE-2026-5524-PoC.svg)


## CVE-2026-5059
The specific flaw exists within the handling of the allowed commands list. The issue results from the lack of proper validation of a user-supplied string before using it to execute a system call. An attacker can leverage this vulnerability to execute code in the context of the MCP server. Was ZDI-CAN-27969.

- [https://github.com/pwn0x000/CVE-2026-5059-poc](https://github.com/pwn0x000/CVE-2026-5059-poc) :  ![starts](https://img.shields.io/github/stars/pwn0x000/CVE-2026-5059-poc.svg) ![forks](https://img.shields.io/github/forks/pwn0x000/CVE-2026-5059-poc.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun.svg)


## CVE-2025-39964
exclusive ownership for writing.

- [https://github.com/suominen/CVE-2025-39964](https://github.com/suominen/CVE-2025-39964) :  ![starts](https://img.shields.io/github/stars/suominen/CVE-2025-39964.svg) ![forks](https://img.shields.io/github/forks/suominen/CVE-2025-39964.svg)


## CVE-2025-39682
zero length.

- [https://github.com/suominen/CVE-2025-39682](https://github.com/suominen/CVE-2025-39682) :  ![starts](https://img.shields.io/github/stars/suominen/CVE-2025-39682.svg) ![forks](https://img.shields.io/github/forks/suominen/CVE-2025-39682.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/0xPb1/Next.js-CVE-2025-29927](https://github.com/0xPb1/Next.js-CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/0xPb1/Next.js-CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/0xPb1/Next.js-CVE-2025-29927.svg)


## CVE-2025-23134
of the register mutex lock again.

- [https://github.com/thrilokh-q123/CVE-2025-23134_fixes_code](https://github.com/thrilokh-q123/CVE-2025-23134_fixes_code) :  ![starts](https://img.shields.io/github/stars/thrilokh-q123/CVE-2025-23134_fixes_code.svg) ![forks](https://img.shields.io/github/forks/thrilokh-q123/CVE-2025-23134_fixes_code.svg)


## CVE-2025-6647
The specific flaw exists within the parsing of U3D files. The issue results from the lack of proper validation of user-supplied data, which can result in a write past the end of an allocated object. An attacker can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-26644.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-alias](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-alias) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-alias.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-alias.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-tilde](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-tilde) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-tilde.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-tilde.svg)


## CVE-2025-2992
 A vulnerability classified as critical was found in Tenda FH1202 1.2.0.14(408). Affected by this vulnerability is an unknown functionality of the file /goform/AdvSetWrlsafeset of the component Web Management Interface. The manipulation leads to improper access controls. The attack can be launched remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/Heimd411/CVE-2025-29927-PoC](https://github.com/Heimd411/CVE-2025-29927-PoC) :  ![starts](https://img.shields.io/github/stars/Heimd411/CVE-2025-29927-PoC.svg) ![forks](https://img.shields.io/github/forks/Heimd411/CVE-2025-29927-PoC.svg)


## CVE-2024-31218
 Webhood is a self-hosted URL scanner used analyzing phishing and malicious sites. Webhood's backend container images in versions 0.9.0 and earlier are subject to Missing Authentication for Critical Function vulnerability. This vulnerability allows an unauthenticated attacker to send a HTTP request to the database (Pocketbase) admin API to create an admin account. The Pocketbase admin API does not check for authentication/authorization when creating an admin account when no admin accounts have been added. In its default deployment, Webhood does not create a database admin account. Therefore, unless users have manually created an admin account in the database, an admin account will not exist in the deployment and the deployment is vulnerable. Versions starting from 0.9.1 are patched. The patch creates a randomly generated admin account if admin accounts have not already been created i.e. the vulnerability is exploitable in the deployment. As a workaround, users can disable access to URL path starting with `/api/admins` entirely. With this workaround, the vulnerability is not exploitable via network.

- [https://github.com/chandrimanath04-hue/CVE-2024-31218-WEBHOOD-LAB](https://github.com/chandrimanath04-hue/CVE-2024-31218-WEBHOOD-LAB) :  ![starts](https://img.shields.io/github/stars/chandrimanath04-hue/CVE-2024-31218-WEBHOOD-LAB.svg) ![forks](https://img.shields.io/github/forks/chandrimanath04-hue/CVE-2024-31218-WEBHOOD-LAB.svg)


## CVE-2024-27954
 Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') vulnerability in WP Automatic Automatic allows Path Traversal, Server Side Request Forgery.This issue affects Automatic: from n/a through 3.92.0.

- [https://github.com/babydessy/CVE-2024-27954](https://github.com/babydessy/CVE-2024-27954) :  ![starts](https://img.shields.io/github/stars/babydessy/CVE-2024-27954.svg) ![forks](https://img.shields.io/github/forks/babydessy/CVE-2024-27954.svg)


## CVE-2024-21413
 Microsoft Outlook Remote Code Execution Vulnerability

- [https://github.com/PCzBuilds/monikerlink-cve-2024-21413-writeup](https://github.com/PCzBuilds/monikerlink-cve-2024-21413-writeup) :  ![starts](https://img.shields.io/github/stars/PCzBuilds/monikerlink-cve-2024-21413-writeup.svg) ![forks](https://img.shields.io/github/forks/PCzBuilds/monikerlink-cve-2024-21413-writeup.svg)


## CVE-2023-43804
 urllib3 is a user-friendly HTTP client library for Python. urllib3 doesn't treat the `Cookie` HTTP header special or provide any helpers for managing cookies over HTTP, that is the responsibility of the user. However, it is possible for a user to specify a `Cookie` header and unknowingly leak information via HTTP redirects to a different origin if that user doesn't disable redirects explicitly. This issue has been patched in urllib3 version 1.26.17 or 2.0.5.

- [https://github.com/deepanshu-khurana/CVE-2023-43804](https://github.com/deepanshu-khurana/CVE-2023-43804) :  ![starts](https://img.shields.io/github/stars/deepanshu-khurana/CVE-2023-43804.svg) ![forks](https://img.shields.io/github/forks/deepanshu-khurana/CVE-2023-43804.svg)


## CVE-2023-42793
 In JetBrains TeamCity before 2023.05.4 authentication bypass leading to RCE on TeamCity Server was possible

- [https://github.com/hhesenjan/CVE-2023-42793](https://github.com/hhesenjan/CVE-2023-42793) :  ![starts](https://img.shields.io/github/stars/hhesenjan/CVE-2023-42793.svg) ![forks](https://img.shields.io/github/forks/hhesenjan/CVE-2023-42793.svg)


## CVE-2023-34468
You are recommended to upgrade to version 1.22.0 or later which fixes this issue.

- [https://github.com/0xSoulaimane/CVE-2023-34468-POC](https://github.com/0xSoulaimane/CVE-2023-34468-POC) :  ![starts](https://img.shields.io/github/stars/0xSoulaimane/CVE-2023-34468-POC.svg) ![forks](https://img.shields.io/github/forks/0xSoulaimane/CVE-2023-34468-POC.svg)


## CVE-2023-27163
 request-baskets up to v1.2.1 was discovered to contain a Server-Side Request Forgery (SSRF) via the component /api/baskets/{name}. This vulnerability allows attackers to access network resources and sensitive information via a crafted API request.

- [https://github.com/hhesenjan/CVE-2023-27163-AND-Mailtrail-v0.53](https://github.com/hhesenjan/CVE-2023-27163-AND-Mailtrail-v0.53) :  ![starts](https://img.shields.io/github/stars/hhesenjan/CVE-2023-27163-AND-Mailtrail-v0.53.svg) ![forks](https://img.shields.io/github/forks/hhesenjan/CVE-2023-27163-AND-Mailtrail-v0.53.svg)
- [https://github.com/AmulyaKaushik/CVE-2023-27163-lab](https://github.com/AmulyaKaushik/CVE-2023-27163-lab) :  ![starts](https://img.shields.io/github/stars/AmulyaKaushik/CVE-2023-27163-lab.svg) ![forks](https://img.shields.io/github/forks/AmulyaKaushik/CVE-2023-27163-lab.svg)


## CVE-2023-21554
 Microsoft Message Queuing (MSMQ) Remote Code Execution Vulnerability

- [https://github.com/TheArtist54/CVE-2023-21554-PoC](https://github.com/TheArtist54/CVE-2023-21554-PoC) :  ![starts](https://img.shields.io/github/stars/TheArtist54/CVE-2023-21554-PoC.svg) ![forks](https://img.shields.io/github/forks/TheArtist54/CVE-2023-21554-PoC.svg)


## CVE-2021-43798
 Grafana is an open-source platform for monitoring and observability. Grafana versions 8.0.0-beta1 through 8.3.0 (except for patched versions) iss vulnerable to directory traversal, allowing access to local files. The vulnerable URL path is: `grafana_host_url/public/plugins//`, where is the plugin ID for any installed plugin. At no time has Grafana Cloud been vulnerable. Users are advised to upgrade to patched versions 8.0.7, 8.1.8, 8.2.7, or 8.3.1. The GitHub Security Advisory contains more information about vulnerable URL paths, mitigation, and the disclosure timeline.

- [https://github.com/shivamg2004/-INE_Shivam_Gupta_23104003](https://github.com/shivamg2004/-INE_Shivam_Gupta_23104003) :  ![starts](https://img.shields.io/github/stars/shivamg2004/-INE_Shivam_Gupta_23104003.svg) ![forks](https://img.shields.io/github/forks/shivamg2004/-INE_Shivam_Gupta_23104003.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/0xrogg/CVE-2021-41773](https://github.com/0xrogg/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/0xrogg/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/0xrogg/CVE-2021-41773.svg)


## CVE-2021-4422
 The POST SMTP Mailer plugin for WordPress is vulnerable to Cross-Site Request Forgery in versions up to, and including, 2.0.20. This is due to missing or incorrect nonce validation on the handleCsvExport() function. This makes it possible for unauthenticated attackers to trigger a CSV export via a forged request granted they can trick a site administrator into performing an action such as clicking on a link.

- [https://github.com/Super-Binary/cve-2021-44228](https://github.com/Super-Binary/cve-2021-44228) :  ![starts](https://img.shields.io/github/stars/Super-Binary/cve-2021-44228.svg) ![forks](https://img.shields.io/github/forks/Super-Binary/cve-2021-44228.svg)


## CVE-2021-4177
 livehelperchat is vulnerable to Generation of Error Message Containing Sensitive Information

- [https://github.com/Mahfujurjust/CVE-2021-41773](https://github.com/Mahfujurjust/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/Mahfujurjust/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/Mahfujurjust/CVE-2021-41773.svg)
- [https://github.com/shiomiyan/CVE-2021-41773](https://github.com/shiomiyan/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/shiomiyan/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/shiomiyan/CVE-2021-41773.svg)
- [https://github.com/gunzf0x/CVE-2021-41773](https://github.com/gunzf0x/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/gunzf0x/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/gunzf0x/CVE-2021-41773.svg)


## CVE-2020-6418
 Type confusion in V8 in Google Chrome prior to 80.0.3987.122 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

- [https://github.com/a-mansilla/CVE-2020-6418](https://github.com/a-mansilla/CVE-2020-6418) :  ![starts](https://img.shields.io/github/stars/a-mansilla/CVE-2020-6418.svg) ![forks](https://img.shields.io/github/forks/a-mansilla/CVE-2020-6418.svg)


## CVE-2019-15107
 An issue was discovered in Webmin =1.920. The parameter old in password_change.cgi contains a command injection vulnerability.

- [https://github.com/shambhaviM18/cve-2019-15107-lab](https://github.com/shambhaviM18/cve-2019-15107-lab) :  ![starts](https://img.shields.io/github/stars/shambhaviM18/cve-2019-15107-lab.svg) ![forks](https://img.shields.io/github/forks/shambhaviM18/cve-2019-15107-lab.svg)


## CVE-2016-10204
 SQL injection vulnerability in Zoneminder 1.30 and earlier allows remote attackers to execute arbitrary SQL commands via the limit parameter in a log query request to index.php.

- [https://github.com/akash0x00/zoneminder-1.29-1.30-rce-exploit](https://github.com/akash0x00/zoneminder-1.29-1.30-rce-exploit) :  ![starts](https://img.shields.io/github/stars/akash0x00/zoneminder-1.29-1.30-rce-exploit.svg) ![forks](https://img.shields.io/github/forks/akash0x00/zoneminder-1.29-1.30-rce-exploit.svg)

