# Update 2026-11-06
## CVE-2026-120019
 The W3 Total Cache plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the 'comment' parameter in all versions up to, and including, 2.10.7 due to insufficient input sanitization and output escaping. This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page. This requires HTML Minify to be enabled with the default 'mfunc' entry present in the ignored-comment stems list, and exploitation depends on the attacker predicting the md5(time()) placeholder namespace by reading the server clock via the HTTP Date response header within the applicable time window.

- [https://github.com/Hassham1/CVE-2026-120019-w3tc-mfunc-comment-xss-poc](https://github.com/Hassham1/CVE-2026-120019-w3tc-mfunc-comment-xss-poc) :  ![starts](https://img.shields.io/github/stars/Hassham1/CVE-2026-120019-w3tc-mfunc-comment-xss-poc.svg) ![forks](https://img.shields.io/github/forks/Hassham1/CVE-2026-120019-w3tc-mfunc-comment-xss-poc.svg)


## CVE-2026-119977
 WordPress Core is vulnerable to Remote Code Execution in versions 4.7 through 7.1.3. This is due to predictable, web-accessible staging paths used during full-package core upgrades. This makes it possible for unauthenticated attackers to execute code on the server during the upgrade window.

- [https://github.com/lysophavin18/CVE-2026-119977](https://github.com/lysophavin18/CVE-2026-119977) :  ![starts](https://img.shields.io/github/stars/lysophavin18/CVE-2026-119977.svg) ![forks](https://img.shields.io/github/forks/lysophavin18/CVE-2026-119977.svg)
- [https://github.com/Worthes/CVE-2026-119977-WordPress-Upgrade-RCE-Bypasses-7.1.4](https://github.com/Worthes/CVE-2026-119977-WordPress-Upgrade-RCE-Bypasses-7.1.4) :  ![starts](https://img.shields.io/github/stars/Worthes/CVE-2026-119977-WordPress-Upgrade-RCE-Bypasses-7.1.4.svg) ![forks](https://img.shields.io/github/forks/Worthes/CVE-2026-119977-WordPress-Upgrade-RCE-Bypasses-7.1.4.svg)
- [https://github.com/foxcornlab/wordpress-core-scanner](https://github.com/foxcornlab/wordpress-core-scanner) :  ![starts](https://img.shields.io/github/stars/foxcornlab/wordpress-core-scanner.svg) ![forks](https://img.shields.io/github/forks/foxcornlab/wordpress-core-scanner.svg)


## CVE-2026-118306
 Use after free in FileSystem in Google Chrome prior to 156.0.8078.73 allowed a remote attacker to execute arbitrary code outside the sandbox via a crafted HTML page. (Chromium security severity: Critical)

- [https://github.com/al4n4n/CVE-2026-118306](https://github.com/al4n4n/CVE-2026-118306) :  ![starts](https://img.shields.io/github/stars/al4n4n/CVE-2026-118306.svg) ![forks](https://img.shields.io/github/forks/al4n4n/CVE-2026-118306.svg)
- [https://github.com/Toddoward/chromium-audit](https://github.com/Toddoward/chromium-audit) :  ![starts](https://img.shields.io/github/stars/Toddoward/chromium-audit.svg) ![forks](https://img.shields.io/github/forks/Toddoward/chromium-audit.svg)


## CVE-2026-111497
Users need to update any Brotli libraries or binaries between 1.0.3 through 1.2.0 to the latest available version: 1.0.10 or 1.1.1 or 1.2.1.

- [https://github.com/aymenkmar/node2shell-check](https://github.com/aymenkmar/node2shell-check) :  ![starts](https://img.shields.io/github/stars/aymenkmar/node2shell-check.svg) ![forks](https://img.shields.io/github/forks/aymenkmar/node2shell-check.svg)
- [https://github.com/sam00/Node2Shell-CVE-2026-111497-POC](https://github.com/sam00/Node2Shell-CVE-2026-111497-POC) :  ![starts](https://img.shields.io/github/stars/sam00/Node2Shell-CVE-2026-111497-POC.svg) ![forks](https://img.shields.io/github/forks/sam00/Node2Shell-CVE-2026-111497-POC.svg)
- [https://github.com/MelissaSkywalkz/broccoli2shell-gis](https://github.com/MelissaSkywalkz/broccoli2shell-gis) :  ![starts](https://img.shields.io/github/stars/MelissaSkywalkz/broccoli2shell-gis.svg) ![forks](https://img.shields.io/github/forks/MelissaSkywalkz/broccoli2shell-gis.svg)


## CVE-2026-110186
 IBM Langflow OSS 1.0.0 through 1.12.8 could allow a remote attacker to execute arbitrary code due to improper control of code generation.

- [https://github.com/al4n4n/CVE-2026-110186](https://github.com/al4n4n/CVE-2026-110186) :  ![starts](https://img.shields.io/github/stars/al4n4n/CVE-2026-110186.svg) ![forks](https://img.shields.io/github/forks/al4n4n/CVE-2026-110186.svg)


## CVE-2026-109619
 PHP has various global state that temporarily points into request memory. In some scenarios, global state may not be correctly reset, or may be repopulated after being reset. The global state may then refer to request memory even after it has been freed. Subsequent requests may read or branch on this stale state before it is fully initialized. Multiple strategies can trigger this condition and produce remote code execution (RCE).

- [https://github.com/sonuoffsec/php2shell-detector](https://github.com/sonuoffsec/php2shell-detector) :  ![starts](https://img.shields.io/github/stars/sonuoffsec/php2shell-detector.svg) ![forks](https://img.shields.io/github/forks/sonuoffsec/php2shell-detector.svg)


## CVE-2026-109618
 PHP uses longjmp() for out-of-memory (OOM) errors to exit the current context and abort handling of the request. Some contexts may not properly account for this scenario and leave request memory in an uninitialized state before performing an allocation. The subsequent request cleanup procedure may read or branch on this memory. Multiple OOM strategies can consistently trigger this condition and lead to remote code execution (RCE).

- [https://github.com/akaihigurashi/php2scan](https://github.com/akaihigurashi/php2scan) :  ![starts](https://img.shields.io/github/stars/akaihigurashi/php2scan.svg) ![forks](https://img.shields.io/github/forks/akaihigurashi/php2scan.svg)


## CVE-2026-109518
The vulnerability is caused by the reuse of hard links and requires the client to follow redirects and retry the download of package files. It requires the client to have a non-zero Acquire::Retries configuration setting; the value 3 is the default starting with Debian 12 (bookworm) and Ubuntu 22.04 LTS (Jammy Jellyfish), so older releases are unaffected in a default configuration

- [https://github.com/Quaerendir/cve-2026-109518-audit](https://github.com/Quaerendir/cve-2026-109518-audit) :  ![starts](https://img.shields.io/github/stars/Quaerendir/cve-2026-109518-audit.svg) ![forks](https://img.shields.io/github/forks/Quaerendir/cve-2026-109518-audit.svg)
- [https://github.com/NeoArtemis37/PHP2shell](https://github.com/NeoArtemis37/PHP2shell) :  ![starts](https://img.shields.io/github/stars/NeoArtemis37/PHP2shell.svg) ![forks](https://img.shields.io/github/forks/NeoArtemis37/PHP2shell.svg)


## CVE-2026-102578
 A flaw was found in Moodle. An authenticated attacker with access to the question bank web service can submit unsanitized input directly into database queries, resulting in a SQL (Structured Query Language) injection vulnerability. This issue could allow an attacker to view, alter, or delete sensitive data stored in the underlying database.

- [https://github.com/caveeroo/CVE-2026-102578](https://github.com/caveeroo/CVE-2026-102578) :  ![starts](https://img.shields.io/github/stars/caveeroo/CVE-2026-102578.svg) ![forks](https://img.shields.io/github/forks/caveeroo/CVE-2026-102578.svg)


## CVE-2026-98432
will be addressed in a separate patch.

- [https://github.com/downitch/CVE-2026-98432_poc](https://github.com/downitch/CVE-2026-98432_poc) :  ![starts](https://img.shields.io/github/stars/downitch/CVE-2026-98432_poc.svg) ![forks](https://img.shields.io/github/forks/downitch/CVE-2026-98432_poc.svg)
- [https://github.com/cybervenom01/Mitigation_CVE-2026-98432](https://github.com/cybervenom01/Mitigation_CVE-2026-98432) :  ![starts](https://img.shields.io/github/stars/cybervenom01/Mitigation_CVE-2026-98432.svg) ![forks](https://img.shields.io/github/forks/cybervenom01/Mitigation_CVE-2026-98432.svg)
- [https://github.com/t0ge-kun/CVE-2026-98432-check](https://github.com/t0ge-kun/CVE-2026-98432-check) :  ![starts](https://img.shields.io/github/stars/t0ge-kun/CVE-2026-98432-check.svg) ![forks](https://img.shields.io/github/forks/t0ge-kun/CVE-2026-98432-check.svg)
- [https://github.com/ScudraServicos/cve-2026-98432-mitigation](https://github.com/ScudraServicos/cve-2026-98432-mitigation) :  ![starts](https://img.shields.io/github/stars/ScudraServicos/cve-2026-98432-mitigation.svg) ![forks](https://img.shields.io/github/forks/ScudraServicos/cve-2026-98432-mitigation.svg)
- [https://github.com/moatome/CVE-2026-98432-pen-test-main](https://github.com/moatome/CVE-2026-98432-pen-test-main) :  ![starts](https://img.shields.io/github/stars/moatome/CVE-2026-98432-pen-test-main.svg) ![forks](https://img.shields.io/github/forks/moatome/CVE-2026-98432-pen-test-main.svg)
- [https://github.com/Certbn/CVE-2026-98432-Linux-IPv4-TCP-IP-Use-After-Free](https://github.com/Certbn/CVE-2026-98432-Linux-IPv4-TCP-IP-Use-After-Free) :  ![starts](https://img.shields.io/github/stars/Certbn/CVE-2026-98432-Linux-IPv4-TCP-IP-Use-After-Free.svg) ![forks](https://img.shields.io/github/forks/Certbn/CVE-2026-98432-Linux-IPv4-TCP-IP-Use-After-Free.svg)


## CVE-2026-98260
[ tglx: Move the cleanup right after de_thread() ]

- [https://github.com/Haor/CVE-2026-98260-OPD2513](https://github.com/Haor/CVE-2026-98260-OPD2513) :  ![starts](https://img.shields.io/github/stars/Haor/CVE-2026-98260-OPD2513.svg) ![forks](https://img.shields.io/github/forks/Haor/CVE-2026-98260-OPD2513.svg)
- [https://github.com/WantenMN/cve-2026-98260-adb](https://github.com/WantenMN/cve-2026-98260-adb) :  ![starts](https://img.shields.io/github/stars/WantenMN/cve-2026-98260-adb.svg) ![forks](https://img.shields.io/github/forks/WantenMN/cve-2026-98260-adb.svg)


## CVE-2026-98258
code to make progress and remove it from the list.

- [https://github.com/imkidz0/Trilemma](https://github.com/imkidz0/Trilemma) :  ![starts](https://img.shields.io/github/stars/imkidz0/Trilemma.svg) ![forks](https://img.shields.io/github/forks/imkidz0/Trilemma.svg)


## CVE-2026-97798
 Improper neutralization of argument delimiters in a command ('argument injection') in Windows Error Reporting allows an authorized attacker to elevate privileges locally.

- [https://github.com/0xBlackash/CVE-2026-97798](https://github.com/0xBlackash/CVE-2026-97798) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-97798.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-97798.svg)


## CVE-2026-97229
 GitLab has remediated an issue in GitLab CE/EE affecting all versions from 19.2 before 19.2.8, 19.3 before 19.3.5, and 19.4 before 19.4.2 that, under certain conditions, could have allowed an unauthenticated user to execute arbitrary code on the GitLab server via a specially crafted regular expression in a CI/CD configuration, due to insufficient regular expression validation.

- [https://github.com/Certbn/CVE-2026-97229-GitLab-CI-CD](https://github.com/Certbn/CVE-2026-97229-GitLab-CI-CD) :  ![starts](https://img.shields.io/github/stars/Certbn/CVE-2026-97229-GitLab-CI-CD.svg) ![forks](https://img.shields.io/github/forks/Certbn/CVE-2026-97229-GitLab-CI-CD.svg)


## CVE-2026-86596
 The s2Member plugin for WordPress is vulnerable to Remote Code Execution in all versions up to, and including, = 260927 via the 'item_name' parameter parameter. This is due to insufficient sanitization in strip_php_tags_deep(), which only strips literal '?' sequences, combined with a post-interpolation placeholder cleanup that reassembles a valid '?php' opener after the attacker-controlled value has already been embedded in the email template. This makes it possible for authenticated attackers, with custom-level access and above, to execute code on the server.

- [https://github.com/Aureels/CVE-2026-86596](https://github.com/Aureels/CVE-2026-86596) :  ![starts](https://img.shields.io/github/stars/Aureels/CVE-2026-86596.svg) ![forks](https://img.shields.io/github/forks/Aureels/CVE-2026-86596.svg)


## CVE-2026-86583
 The Import and export users and customers plugin for WordPress is vulnerable to Privilege Escalation in all versions up to, and including, 2.4.17 via the plugin's own export and re-import workflow. The vulnerability exists because the exporter writes CSV cells using fputcsv() with a NUL byte (\0) as the escape character, while the importer parses the same file using SplFileObject::fgetcsv() with only a single delimiter argument, causing PHP's default backslash escape character to be applied instead; because the export column layout places display_name immediately before the role column and nickname immediately after, an attacker can store crafted values in those two profile fields — saved by WordPress core via the standard profile page — such that the escape mismatch causes the parser to merge the display_name cell into the role field and rebalance the column count via nickname, yielding administrator as the parsed role for their own row when it reaches the import_user function's add_role function. This makes it possible for authenticated attackers with Subscriber-level access or above to escalate their privileges to Administrator. Exploitation requires a site administrator to trigger the plugin's documented export re-import migration with both "Update existing users" and "Update roles for existing users" set to "yes".

- [https://github.com/saretawa/CVE-2026-86583](https://github.com/saretawa/CVE-2026-86583) :  ![starts](https://img.shields.io/github/stars/saretawa/CVE-2026-86583.svg) ![forks](https://img.shields.io/github/forks/saretawa/CVE-2026-86583.svg)


## CVE-2026-85612
 OpenPanel before 2.3.0 contains an unauthenticated server-side request forgery vulnerability in the /misc/favicon and /misc/og endpoints that accept an attacker-supplied url parameter with insufficient validation. Attackers can force the API to fetch arbitrary internal hosts and cloud metadata endpoints, with small responses returned verbatim enabling credential theft and internal service enumeration.

- [https://github.com/hotplugin0x01/CVE-2026-85612](https://github.com/hotplugin0x01/CVE-2026-85612) :  ![starts](https://img.shields.io/github/stars/hotplugin0x01/CVE-2026-85612.svg) ![forks](https://img.shields.io/github/forks/hotplugin0x01/CVE-2026-85612.svg)


## CVE-2026-62911
 Authentication bypass by capture-replay in Microsoft Exchange Server allows an authorized attacker to elevate privileges over a network.

- [https://github.com/che3axujnya/cve-2026-62911](https://github.com/che3axujnya/cve-2026-62911) :  ![starts](https://img.shields.io/github/stars/che3axujnya/cve-2026-62911.svg) ![forks](https://img.shields.io/github/forks/che3axujnya/cve-2026-62911.svg)


## CVE-2026-58115
This could allow an unauthenticated remote attacker to create malicious flows through the HTTP interface in order to execute arbitrary code on the underlying server with maximum privileges.

- [https://github.com/al4n4n/CVE-2026-58115](https://github.com/al4n4n/CVE-2026-58115) :  ![starts](https://img.shields.io/github/stars/al4n4n/CVE-2026-58115.svg) ![forks](https://img.shields.io/github/forks/al4n4n/CVE-2026-58115.svg)


## CVE-2026-56190
 Use of uninitialized resource in Windows RDP allows an unauthorized attacker to execute code over a network.

- [https://github.com/danarhirany300-ctrl/CVE-2026-56190-Full-RCE-Chain](https://github.com/danarhirany300-ctrl/CVE-2026-56190-Full-RCE-Chain) :  ![starts](https://img.shields.io/github/stars/danarhirany300-ctrl/CVE-2026-56190-Full-RCE-Chain.svg) ![forks](https://img.shields.io/github/forks/danarhirany300-ctrl/CVE-2026-56190-Full-RCE-Chain.svg)
- [https://github.com/danarhirany300-ctrl/CVE-2026-56190-Full-RCE-Chainn](https://github.com/danarhirany300-ctrl/CVE-2026-56190-Full-RCE-Chainn) :  ![starts](https://img.shields.io/github/stars/danarhirany300-ctrl/CVE-2026-56190-Full-RCE-Chainn.svg) ![forks](https://img.shields.io/github/forks/danarhirany300-ctrl/CVE-2026-56190-Full-RCE-Chainn.svg)


## CVE-2026-44267
 Elo is a purely functional expression language for no-code tools. Prior to 1.0.1, plain Elo strings supplied to defaultFormats.elo.parse(), bin/elo, or elo-lang.org/try can use .constructor.constructor to reach JavaScript Function because the member_access handler in src/transform.ts does not reject meta-properties, src/compilers/javascript.ts emits the surviving property directly, and src/parser.ts accepts constructor as an ordinary identifier. The resulting generated JavaScript executes attacker-selected code in the host runtime. This permits browser script execution and session compromise on the auto-running playground and arbitrary Node.js code execution on library, CI, or DevOps hosts. This plain-string path is distinct from the programmatic AST-object injection issue. This issue is fixed in version 1.0.1.

- [https://github.com/umair-aziz025/CVE-2026-44267](https://github.com/umair-aziz025/CVE-2026-44267) :  ![starts](https://img.shields.io/github/stars/umair-aziz025/CVE-2026-44267.svg) ![forks](https://img.shields.io/github/forks/umair-aziz025/CVE-2026-44267.svg)


## CVE-2026-43499
  	changelog ]

- [https://github.com/Delta-Water/CVE-2026-43499-phq110-root](https://github.com/Delta-Water/CVE-2026-43499-phq110-root) :  ![starts](https://img.shields.io/github/stars/Delta-Water/CVE-2026-43499-phq110-root.svg) ![forks](https://img.shields.io/github/forks/Delta-Water/CVE-2026-43499-phq110-root.svg)
- [https://github.com/Cxyofficial/K50G-POCOF4GT-CVE-2026-43499-PoC](https://github.com/Cxyofficial/K50G-POCOF4GT-CVE-2026-43499-PoC) :  ![starts](https://img.shields.io/github/stars/Cxyofficial/K50G-POCOF4GT-CVE-2026-43499-PoC.svg) ![forks](https://img.shields.io/github/forks/Cxyofficial/K50G-POCOF4GT-CVE-2026-43499-PoC.svg)
- [https://github.com/RetributionByRevenue/xperia1vi-root](https://github.com/RetributionByRevenue/xperia1vi-root) :  ![starts](https://img.shields.io/github/stars/RetributionByRevenue/xperia1vi-root.svg) ![forks](https://img.shields.io/github/forks/RetributionByRevenue/xperia1vi-root.svg)


## CVE-2026-43284
destination-frag path or fall back to skb_cow_data().

- [https://github.com/mcxiaochenn/iqooNeo8-V2301A-DirtyFrag](https://github.com/mcxiaochenn/iqooNeo8-V2301A-DirtyFrag) :  ![starts](https://img.shields.io/github/stars/mcxiaochenn/iqooNeo8-V2301A-DirtyFrag.svg) ![forks](https://img.shields.io/github/forks/mcxiaochenn/iqooNeo8-V2301A-DirtyFrag.svg)


## CVE-2026-42908
 Out-of-bounds read in Windows RDP allows an unauthorized attacker to disclose information over a network.

- [https://github.com/danarhirany300-ctrl/CVE-2026-56190-Full-RCE-Chainn](https://github.com/danarhirany300-ctrl/CVE-2026-56190-Full-RCE-Chainn) :  ![starts](https://img.shields.io/github/stars/danarhirany300-ctrl/CVE-2026-56190-Full-RCE-Chainn.svg) ![forks](https://img.shields.io/github/forks/danarhirany300-ctrl/CVE-2026-56190-Full-RCE-Chainn.svg)
- [https://github.com/danarhirany300-ctrl/CVE-2026-56190-Full-RCE-Chain](https://github.com/danarhirany300-ctrl/CVE-2026-56190-Full-RCE-Chain) :  ![starts](https://img.shields.io/github/stars/danarhirany300-ctrl/CVE-2026-56190-Full-RCE-Chain.svg) ![forks](https://img.shields.io/github/forks/danarhirany300-ctrl/CVE-2026-56190-Full-RCE-Chain.svg)


## CVE-2026-41651
3. Late flag read at execution time (lines 2273–2277): The scheduler's idle callback reads cached_transaction_flags at dispatch time, not at authorization time. If flags were overwritten between authorization and execution, the backend sees the attacker's flags.

- [https://github.com/1nt1m4cy/HTB-Cohort](https://github.com/1nt1m4cy/HTB-Cohort) :  ![starts](https://img.shields.io/github/stars/1nt1m4cy/HTB-Cohort.svg) ![forks](https://img.shields.io/github/forks/1nt1m4cy/HTB-Cohort.svg)


## CVE-2026-39987
 marimo is a reactive Python notebook. Prior to 0.23.0, Marimo has a Pre-Auth RCE vulnerability. The terminal WebSocket endpoint /terminal/ws lacks authentication validation, allowing an unauthenticated attacker to obtain a full PTY shell and execute arbitrary system commands. Unlike other WebSocket endpoints (e.g., /ws) that correctly call validate_auth() for authentication, the /terminal/ws endpoint only checks the running mode and platform support before accepting connections, completely skipping authentication verification. This vulnerability is fixed in 0.23.0.

- [https://github.com/1nt1m4cy/HTB-Cohort](https://github.com/1nt1m4cy/HTB-Cohort) :  ![starts](https://img.shields.io/github/stars/1nt1m4cy/HTB-Cohort.svg) ![forks](https://img.shields.io/github/forks/1nt1m4cy/HTB-Cohort.svg)


## CVE-2026-31431
AD directly.

- [https://github.com/sec17br/CVE-2026-31431-Copy-Fail](https://github.com/sec17br/CVE-2026-31431-Copy-Fail) :  ![starts](https://img.shields.io/github/stars/sec17br/CVE-2026-31431-Copy-Fail.svg) ![forks](https://img.shields.io/github/forks/sec17br/CVE-2026-31431-Copy-Fail.svg)


## CVE-2026-21440
 AdonisJS is a TypeScript-first web framework. A Path Traversal vulnerability in AdonisJS multipart file handling may allow a remote attacker to write arbitrary files to arbitrary locations on the server filesystem. This impacts @adonisjs/bodyparser through version 10.1.1 and 11.x prerelease versions prior to 11.0.0-next.6. This issue has been patched in @adonisjs/bodyparser versions 10.1.2 and 11.0.0-next.6.

- [https://github.com/Rui0828/CVE-2026-21440-adonisjs-bodyparser](https://github.com/Rui0828/CVE-2026-21440-adonisjs-bodyparser) :  ![starts](https://img.shields.io/github/stars/Rui0828/CVE-2026-21440-adonisjs-bodyparser.svg) ![forks](https://img.shields.io/github/forks/Rui0828/CVE-2026-21440-adonisjs-bodyparser.svg)


## CVE-2026-10961
 Use after free in Chrome for iOS in Google Chrome on iOS prior to 149.0.7827.53 allowed a remote attacker who had compromised the renderer process to potentially perform a sandbox escape via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/che3axujnya/cve-2026-109618-cve-2026-109619-poc](https://github.com/che3axujnya/cve-2026-109618-cve-2026-109619-poc) :  ![starts](https://img.shields.io/github/stars/che3axujnya/cve-2026-109618-cve-2026-109619-poc.svg) ![forks](https://img.shields.io/github/forks/che3axujnya/cve-2026-109618-cve-2026-109619-poc.svg)
- [https://github.com/santihabib/CVE-2026-109619](https://github.com/santihabib/CVE-2026-109619) :  ![starts](https://img.shields.io/github/stars/santihabib/CVE-2026-109619.svg) ![forks](https://img.shields.io/github/forks/santihabib/CVE-2026-109619.svg)
- [https://github.com/WKL-Sec/CVE-2026-109618](https://github.com/WKL-Sec/CVE-2026-109618) :  ![starts](https://img.shields.io/github/stars/WKL-Sec/CVE-2026-109618.svg) ![forks](https://img.shields.io/github/forks/WKL-Sec/CVE-2026-109618.svg)
- [https://github.com/alvaroguzmancode/CVE-2026-109618](https://github.com/alvaroguzmancode/CVE-2026-109618) :  ![starts](https://img.shields.io/github/stars/alvaroguzmancode/CVE-2026-109618.svg) ![forks](https://img.shields.io/github/forks/alvaroguzmancode/CVE-2026-109618.svg)


## CVE-2026-10795
 The UpdraftPlus: WP Backup & Migration Plugin plugin for WordPress is vulnerable to Authentication Bypass in all versions up to, and including, 1.26.4 via the UpdraftPlus_Remote_Communications_V2::wp_loaded function. This is due to insufficient validation of the remote communications message format, where signature verification can be bypassed and unchecked decryption return values collapse to a predictable all-zero encryption key. This makes it possible for unauthenticated attackers to forge arbitrary RPC commands and run them as the connected administrator, such as uploading and activating a malicious plugin, which ultimately leads to remote code execution.

- [https://github.com/T54R/CVE-2026-10795_POC](https://github.com/T54R/CVE-2026-10795_POC) :  ![starts](https://img.shields.io/github/stars/T54R/CVE-2026-10795_POC.svg) ![forks](https://img.shields.io/github/forks/T54R/CVE-2026-10795_POC.svg)


## CVE-2026-7881
 Concrete CMS 9.5.0 and below is subject to Insecure Direct Object Reference (IDOR) in the Express Entry Detail block via the exEntryID parameter. This IDOR leads to unauthorized access to all Express form submissions. The Concrete CMS security team gave this vulnerability a CVSS v.4.0 score of 6.3 with vector CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N. Thanks Tristan Madani for reporting.

- [https://github.com/ammarkrblt/CVE-2026-78818-cyberpanel-phpselection-rce](https://github.com/ammarkrblt/CVE-2026-78818-cyberpanel-phpselection-rce) :  ![starts](https://img.shields.io/github/stars/ammarkrblt/CVE-2026-78818-cyberpanel-phpselection-rce.svg) ![forks](https://img.shields.io/github/forks/ammarkrblt/CVE-2026-78818-cyberpanel-phpselection-rce.svg)


## CVE-2026-3143
 The Total Upkeep – WordPress Backup Plugin plus Restore & Migrate by BoldGrid plugin for WordPress is vulnerable to unauthorized modification of data due to a missing capability check on the 'wp_ajax_cli_cancel' function in all versions up to, and including, 1.17.1. This makes it possible for unauthenticated attackers to cancel a pending rollback, potentially preventing a WordPress installation from automatically reverting a failed update.

- [https://github.com/euriconicacio/copy-fail-CVE-2026-31431-poc](https://github.com/euriconicacio/copy-fail-CVE-2026-31431-poc) :  ![starts](https://img.shields.io/github/stars/euriconicacio/copy-fail-CVE-2026-31431-poc.svg) ![forks](https://img.shields.io/github/forks/euriconicacio/copy-fail-CVE-2026-31431-poc.svg)


## CVE-2026-1096
 The Best-wp-google-map plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the 'latitude' and 'longitudinal' parameters of the 'google_map_view' shortcode in all versions up to, and including, 2.1 due to insufficient input sanitization and output escaping. This makes it possible for authenticated attackers, with Contributor-level access and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.

- [https://github.com/MorphingYU/CVE-2026-109618](https://github.com/MorphingYU/CVE-2026-109618) :  ![starts](https://img.shields.io/github/stars/MorphingYU/CVE-2026-109618.svg) ![forks](https://img.shields.io/github/forks/MorphingYU/CVE-2026-109618.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo.svg)


## CVE-2025-32463
 Sudo before 1.9.17p1 allows local users to obtain root access because /etc/nsswitch.conf from a user-controlled directory is used with the --chroot option.

- [https://github.com/roock3t/CVE-2025-32463](https://github.com/roock3t/CVE-2025-32463) :  ![starts](https://img.shields.io/github/stars/roock3t/CVE-2025-32463.svg) ![forks](https://img.shields.io/github/forks/roock3t/CVE-2025-32463.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/amitlttwo/Next.JS-CVE-2025-29927](https://github.com/amitlttwo/Next.JS-CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/amitlttwo/Next.JS-CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/amitlttwo/Next.JS-CVE-2025-29927.svg)


## CVE-2025-6647
The specific flaw exists within the parsing of U3D files. The issue results from the lack of proper validation of user-supplied data, which can result in a write past the end of an allocated object. An attacker can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-26644.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict.svg)


## CVE-2025-2992
 A vulnerability classified as critical was found in Tenda FH1202 1.2.0.14(408). Affected by this vulnerability is an unknown functionality of the file /goform/AdvSetWrlsafeset of the component Web Management Interface. The manipulation leads to improper access controls. The attack can be launched remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/ticofookfook/poc-nextjs-CVE-2025-29927](https://github.com/ticofookfook/poc-nextjs-CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/ticofookfook/poc-nextjs-CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/ticofookfook/poc-nextjs-CVE-2025-29927.svg)


## CVE-2024-21626
 runc is a CLI tool for spawning and running containers on Linux according to the OCI specification. In runc 1.1.11 and earlier, due to an internal file descriptor leak, an attacker could cause a newly-spawned container process (from runc exec) to have a working directory in the host filesystem namespace, allowing for a container escape by giving access to the host filesystem ("attack 2"). The same attack could be used by a malicious image to allow a container process to gain access to the host filesystem through runc run ("attack 1"). Variants of attacks 1 and 2 could be also be used to overwrite semi-arbitrary host binaries, allowing for complete container escapes ("attack 3a" and "attack 3b"). runc 1.1.12 includes patches for this issue.

- [https://github.com/GjerdanKashmiri/leakyvessels_reproduction_mitigation](https://github.com/GjerdanKashmiri/leakyvessels_reproduction_mitigation) :  ![starts](https://img.shields.io/github/stars/GjerdanKashmiri/leakyvessels_reproduction_mitigation.svg) ![forks](https://img.shields.io/github/forks/GjerdanKashmiri/leakyvessels_reproduction_mitigation.svg)


## CVE-2024-3094
Through a series of complex obfuscations, the liblzma build process extracts a prebuilt object file from a disguised test file existing in the source code, which is then used to modify specific functions in the liblzma code. This results in a modified liblzma library that can be used by any software linked against this library, intercepting and modifying the data interaction with this library.

- [https://github.com/Skytheguy7/xz-utils-case-study](https://github.com/Skytheguy7/xz-utils-case-study) :  ![starts](https://img.shields.io/github/stars/Skytheguy7/xz-utils-case-study.svg) ![forks](https://img.shields.io/github/forks/Skytheguy7/xz-utils-case-study.svg)


## CVE-2023-36308
 disintegration Imaging 1.6.2 allows attackers to cause a panic (because of an integer index out of range during a Grayscale call) via a crafted TIFF file to the scan function of scanner.go. NOTE: it is unclear whether there are common use cases in which this panic could have any security consequence

- [https://github.com/klphp/imaging](https://github.com/klphp/imaging) :  ![starts](https://img.shields.io/github/stars/klphp/imaging.svg) ![forks](https://img.shields.io/github/forks/klphp/imaging.svg)


## CVE-2023-26360
 Adobe ColdFusion versions 2018 Update 15 (and earlier) and 2021 Update 5 (and earlier) are affected by an Improper Access Control vulnerability that could result in arbitrary code execution in the context of the current user. Exploitation of this issue does not require user interaction.

- [https://github.com/DefaultCh40s/CVE-2023-26360](https://github.com/DefaultCh40s/CVE-2023-26360) :  ![starts](https://img.shields.io/github/stars/DefaultCh40s/CVE-2023-26360.svg) ![forks](https://img.shields.io/github/forks/DefaultCh40s/CVE-2023-26360.svg)


## CVE-2022-21675
 Bytecode Viewer (BCV) is a Java/Android reverse engineering suite. Versions of the package prior to 2.11.0 are vulnerable to Arbitrary File Write via Archive Extraction (AKA "Zip Slip"). The vulnerability is exploited using a specially crafted archive that holds directory traversal filenames (e.g. ../../evil.exe). The Zip Slip vulnerability can affect numerous archive formats, including zip, jar, tar, war, cpio, apk, rar and 7z. The attacker can then overwrite executable files and either invoke them remotely or wait for the system or user to call them, thus achieving remote command execution on the victim’s machine. The impact of a Zip Slip vulnerability would allow an attacker to create or overwrite existing files on the filesystem. In the context of a web application, a web shell could be placed within the application directory to achieve code execution. All users should upgrade to BCV v2.11.0 when possible to receive a patch. There are no recommended workarounds aside from upgrading.

- [https://github.com/themd-me/CVE-2022-21675](https://github.com/themd-me/CVE-2022-21675) :  ![starts](https://img.shields.io/github/stars/themd-me/CVE-2022-21675.svg) ![forks](https://img.shields.io/github/forks/themd-me/CVE-2022-21675.svg)


## CVE-2021-42013
 It was found that the fix for CVE-2021-41773 in Apache HTTP Server 2.4.50 was insufficient. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue only affects Apache 2.4.49 and Apache 2.4.50 and not earlier versions.

- [https://github.com/mhd964/CVE-2021-42013](https://github.com/mhd964/CVE-2021-42013) :  ![starts](https://img.shields.io/github/stars/mhd964/CVE-2021-42013.svg) ![forks](https://img.shields.io/github/forks/mhd964/CVE-2021-42013.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/0xrogg/CVE-2021-41773](https://github.com/0xrogg/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/0xrogg/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/0xrogg/CVE-2021-41773.svg)


## CVE-2021-33644
 An attacker who submits a crafted tar file with size in header struct being 0 may be able to trigger an calling of malloc(0) for a variable gnu_longname, causing an out-of-bounds read.

- [https://github.com/nilondal/libtar-CVE-2021-33644-followup](https://github.com/nilondal/libtar-CVE-2021-33644-followup) :  ![starts](https://img.shields.io/github/stars/nilondal/libtar-CVE-2021-33644-followup.svg) ![forks](https://img.shields.io/github/forks/nilondal/libtar-CVE-2021-33644-followup.svg)


## CVE-2021-33643
 An attacker who submits a crafted tar file with size in header struct being 0 may be able to trigger an calling of malloc(0) for a variable gnu_longlink, causing an out-of-bounds read.

- [https://github.com/nilondal/libtar-CVE-2021-33644-followup](https://github.com/nilondal/libtar-CVE-2021-33644-followup) :  ![starts](https://img.shields.io/github/stars/nilondal/libtar-CVE-2021-33644-followup.svg) ![forks](https://img.shields.io/github/forks/nilondal/libtar-CVE-2021-33644-followup.svg)


## CVE-2021-22911
 A improper input sanitization vulnerability exists in Rocket.Chat server 3.11, 3.12 & 3.13 that could lead to unauthenticated NoSQL injection, resulting potentially in RCE.

- [https://github.com/s1lentf00thold/CVE-2021-22911](https://github.com/s1lentf00thold/CVE-2021-22911) :  ![starts](https://img.shields.io/github/stars/s1lentf00thold/CVE-2021-22911.svg) ![forks](https://img.shields.io/github/forks/s1lentf00thold/CVE-2021-22911.svg)


## CVE-2021-4177
 livehelperchat is vulnerable to Generation of Error Message Containing Sensitive Information

- [https://github.com/LayarKacaSiber/CVE-2021-41773](https://github.com/LayarKacaSiber/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/LayarKacaSiber/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/LayarKacaSiber/CVE-2021-41773.svg)
- [https://github.com/zer0qs/CVE-2021-41773](https://github.com/zer0qs/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/zer0qs/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/zer0qs/CVE-2021-41773.svg)
- [https://github.com/gunzf0x/CVE-2021-41773](https://github.com/gunzf0x/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/gunzf0x/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/gunzf0x/CVE-2021-41773.svg)
- [https://github.com/sotiak/CVE-2021-41773](https://github.com/sotiak/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/sotiak/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/sotiak/CVE-2021-41773.svg)


## CVE-2021-2026
 Vulnerability in the Oracle Marketing product of Oracle E-Business Suite (component: Marketing Administration). Supported versions that are affected are 12.1.1-12.1.3 and 12.2.3-12.2.10. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Marketing. Successful attacks require human interaction from a person other than the attacker and while the vulnerability is in Oracle Marketing, attacks may significantly impact additional products. Successful attacks of this vulnerability can result in unauthorized access to critical data or complete access to all Oracle Marketing accessible data as well as unauthorized update, insert or delete access to some of Oracle Marketing accessible data. CVSS 3.1 Base Score 8.2 (Confidentiality and Integrity impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N).

- [https://github.com/ProjectZeroDays/Most_Critical_CVEs_2021-2026](https://github.com/ProjectZeroDays/Most_Critical_CVEs_2021-2026) :  ![starts](https://img.shields.io/github/stars/ProjectZeroDays/Most_Critical_CVEs_2021-2026.svg) ![forks](https://img.shields.io/github/forks/ProjectZeroDays/Most_Critical_CVEs_2021-2026.svg)


## CVE-2017-18349
 parseObject in Fastjson before 1.2.25, as used in FastjsonEngine in Pippo 1.11.0 and other products, allows remote attackers to execute arbitrary code via a crafted JSON request, as demonstrated by a crafted rmi:// URI in the dataSourceName field of HTTP POST data to the Pippo /json URI, which is mishandled in AjaxApplication.java.

- [https://github.com/dichen-L/CVE-2017-18349-fastjson1.2.24-vul](https://github.com/dichen-L/CVE-2017-18349-fastjson1.2.24-vul) :  ![starts](https://img.shields.io/github/stars/dichen-L/CVE-2017-18349-fastjson1.2.24-vul.svg) ![forks](https://img.shields.io/github/forks/dichen-L/CVE-2017-18349-fastjson1.2.24-vul.svg)


## CVE-2017-7921
 An Improper Authentication issue was discovered in Hikvision DS-2CD2xx2F-I Series V5.2.0 build 140721 to V5.4.0 build 160530, DS-2CD2xx0F-I Series V5.2.0 build 140721 to V5.4.0 Build 160401, DS-2CD2xx2FWD Series V5.3.1 build 150410 to V5.4.4 Build 161125, DS-2CD4x2xFWD Series V5.2.0 build 140721 to V5.4.0 Build 160414, DS-2CD4xx5 Series V5.2.0 build 140721 to V5.4.0 Build 160421, DS-2DFx Series V5.2.0 build 140805 to V5.4.5 Build 160928, and DS-2CD63xx Series V5.0.9 build 140305 to V5.3.5 Build 160106 devices. The improper authentication vulnerability occurs when an application does not adequately or correctly authenticate users. This may allow a malicious user to escalate his or her privileges on the system and gain access to sensitive information.

- [https://github.com/Mr-Ochobot/Hikvision-CCTV-POC](https://github.com/Mr-Ochobot/Hikvision-CCTV-POC) :  ![starts](https://img.shields.io/github/stars/Mr-Ochobot/Hikvision-CCTV-POC.svg) ![forks](https://img.shields.io/github/forks/Mr-Ochobot/Hikvision-CCTV-POC.svg)
- [https://github.com/intcost/cve-2017-7921-hikvision-poc](https://github.com/intcost/cve-2017-7921-hikvision-poc) :  ![starts](https://img.shields.io/github/stars/intcost/cve-2017-7921-hikvision-poc.svg) ![forks](https://img.shields.io/github/forks/intcost/cve-2017-7921-hikvision-poc.svg)

