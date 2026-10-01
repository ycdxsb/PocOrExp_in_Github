# Update 2026-10-01
## CVE-2026-102261
 A flaw has been found in owen2345 Camaleon CMS up to 2.9.2. Impacted is the function crop of the file app/controllers/camaleon_cms/admin/media_controller.rb of the component Media Crop Handler. This manipulation of the argument saved_avatar causes authorization bypass. The attack may be initiated remotely. The exploit has been published and may be used. Upgrading to version 2.9.3 is recommended to address this issue. Patch name: c143e145caa600947e70a240e87f2fed889149d3. It is suggested to upgrade the affected component.

- [https://github.com/7acini/CVE-2026-102261](https://github.com/7acini/CVE-2026-102261) :  ![starts](https://img.shields.io/github/stars/7acini/CVE-2026-102261.svg) ![forks](https://img.shields.io/github/forks/7acini/CVE-2026-102261.svg)


## CVE-2026-101894
 The decompress package for Node.js extracts archives. Prior to 10.2.2 and 11.1.4, the default decompress(input, output) API relies on lexical containment checks that do not account for the kernel following a planted symlink chain. An attacker can supply a crafted archive containing chained symlink entries so that a later entry resolves outside the output directory. This allows files outside output to be read or written, and overwriting startup scripts or configuration can lead to remote code execution. The maintained @xhmikosr/decompress package is fixed in 10.2.2 and 11.1.4, but the separately affected unmaintained decompress package remains unpatched through 4.2.1. This vulnerability results from a bypass of the incomplete hardening for CVE-2026-53486. @xhmikosr/decompress is fixed in versions 10.2.2 and 11.1.4.

- [https://github.com/murrez/CVE-2026-101894](https://github.com/murrez/CVE-2026-101894) :  ![starts](https://img.shields.io/github/stars/murrez/CVE-2026-101894.svg) ![forks](https://img.shields.io/github/forks/murrez/CVE-2026-101894.svg)


## CVE-2026-101110
 Joomla Extension - ordasoft.com - Unauthenticated SQL Injection in Book Library (Free)  6.4.6 - site/booklibrary.php’s books() function reads the field and direction request parameters and passes each through a function called protectInjectionWithoutQuote(), whose only real protection is a keyword blacklist that, on detecting the literal substring select, wraps the value in $db-quote() instead of rejecting it. The value is then concatenated directly into an unquoted ORDER BY clause, a position where quoting provides no protection at all. Reaching the vulnerable code path requires two conditions: a first request to prime session-stored sort defaults, and a trailing decoy comment (-- xselect) that satisfies the blacklist’s substring check without altering the payload’s effect.

- [https://github.com/murrez/CVE-2026-101110](https://github.com/murrez/CVE-2026-101110) :  ![starts](https://img.shields.io/github/stars/murrez/CVE-2026-101110.svg) ![forks](https://img.shields.io/github/forks/murrez/CVE-2026-101110.svg)


## CVE-2026-101108
 Joomla Extension - ordasoft.com - Unauthenticated SQL Injection in Vehicle Manager (Free)  6.5.8 - site/vehiclemanager.php reads the order_field and order_direction sort parameters at three separate anonymous-reachable frontend entry points (category listing, search, and the all-vehicles listing) through a sanitizing function that applies real escaping, but the value is then placed into an unquoted ORDER BY clause, where escaping has no protective effect.

- [https://github.com/murrez/CVE-2026-101108](https://github.com/murrez/CVE-2026-101108) :  ![starts](https://img.shields.io/github/stars/murrez/CVE-2026-101108.svg) ![forks](https://img.shields.io/github/forks/murrez/CVE-2026-101108.svg)


## CVE-2026-100752
 Joomla Extension - ordasoft.com - Unauthenticated SQL Injection in Real Estate Manager (Free)  6.7.9 - site/realestatemanager.php builds the ORDER BY clause of three separate frontend property-listing queries (category browsing, search results, and the full property listing) from a request-controlled order_field parameter, concatenated directly into an unquoted SQL clause with no allow-list of real column names and no cast.

- [https://github.com/murrez/CVE-2026-100752](https://github.com/murrez/CVE-2026-100752) :  ![starts](https://img.shields.io/github/stars/murrez/CVE-2026-100752.svg) ![forks](https://img.shields.io/github/forks/murrez/CVE-2026-100752.svg)


## CVE-2026-100633
 SiYuan is a self-hosted personal knowledge management system. In versions 3.8.0 through 3.8.3, the MCP file tool's sensitive-path guard (util.IsForbiddenAbsPath(), invoked from resolvePath()) is applied only to the allowed root of recursive operations and not to each resolved descendant path — an incomplete fix for GHSA-c8r8-95hg-mp34. An authenticated administrator using the in-app Agent or the external MCP server can therefore bypass the protected-workspace-file denylist: file.grep can return matching lines from non-hidden protected descendants (for example conf/conf.json, TLS keys, data/snippets/conf.json, data/templates/, data/.siyuan/publishAccess.json, notebook .siyuan internals, or the kernel log), file.copy can copy protected descendants to an ordinary path where file.read can then retrieve them, and unzip can overwrite protected descendants using ordinary, lexically contained ZIP member names. Because file.grep is globally classified as a safe action, it receives no per-call confirmation, and the confirmation cards for file.copy and unzip show only the allowed root arguments. This issue is fixed in version 3.8.4. Suggested title: SiYuan 3.8.0 through 3.8.3 Sensitive-Path Guard Bypass in Recursive MCP File Operations.

- [https://github.com/dpfkdlemtp/CVE-2026-100633](https://github.com/dpfkdlemtp/CVE-2026-100633) :  ![starts](https://img.shields.io/github/stars/dpfkdlemtp/CVE-2026-100633.svg) ![forks](https://img.shields.io/github/forks/dpfkdlemtp/CVE-2026-100633.svg)


## CVE-2026-100381
This issue affects Mediawiki - UploadWizard Extension: from * before 1.46.1, 1.45.5, 1.43.10.

- [https://github.com/BomboBombone/CVE-2026-100381](https://github.com/BomboBombone/CVE-2026-100381) :  ![starts](https://img.shields.io/github/stars/BomboBombone/CVE-2026-100381.svg) ![forks](https://img.shields.io/github/forks/BomboBombone/CVE-2026-100381.svg)


## CVE-2026-100380
This issue affects Mediawiki - Wikibase Extension: from * before 1.46.1, 1.45.5, 1.43.10.

- [https://github.com/BomboBombone/CVE-2026-100380](https://github.com/BomboBombone/CVE-2026-100380) :  ![starts](https://img.shields.io/github/stars/BomboBombone/CVE-2026-100380.svg) ![forks](https://img.shields.io/github/forks/BomboBombone/CVE-2026-100380.svg)


## CVE-2026-96878
This issue affects Mediawiki - Cargo extension: through 3.9.4.

- [https://github.com/BomboBombone/CVE-2026-96878](https://github.com/BomboBombone/CVE-2026-96878) :  ![starts](https://img.shields.io/github/stars/BomboBombone/CVE-2026-96878.svg) ![forks](https://img.shields.io/github/forks/BomboBombone/CVE-2026-96878.svg)


## CVE-2026-96877
This issue affects Mediawiki - Cargo extension: through 3.9.4.

- [https://github.com/BomboBombone/CVE-2026-96877](https://github.com/BomboBombone/CVE-2026-96877) :  ![starts](https://img.shields.io/github/stars/BomboBombone/CVE-2026-96877.svg) ![forks](https://img.shields.io/github/forks/BomboBombone/CVE-2026-96877.svg)


## CVE-2026-96876
This issue affects Mediawiki - Cargo extension: through 3.9.4.

- [https://github.com/BomboBombone/CVE-2026-96876](https://github.com/BomboBombone/CVE-2026-96876) :  ![starts](https://img.shields.io/github/stars/BomboBombone/CVE-2026-96876.svg) ![forks](https://img.shields.io/github/forks/BomboBombone/CVE-2026-96876.svg)


## CVE-2026-96875
This issue affects Mediawiki - Cargo extension: through 3.9.4.

- [https://github.com/BomboBombone/CVE-2026-96875](https://github.com/BomboBombone/CVE-2026-96875) :  ![starts](https://img.shields.io/github/stars/BomboBombone/CVE-2026-96875.svg) ![forks](https://img.shields.io/github/forks/BomboBombone/CVE-2026-96875.svg)


## CVE-2026-96874
This issue affects Mediawiki - Cargo extension: through 3.9.4.

- [https://github.com/BomboBombone/CVE-2026-96874](https://github.com/BomboBombone/CVE-2026-96874) :  ![starts](https://img.shields.io/github/stars/BomboBombone/CVE-2026-96874.svg) ![forks](https://img.shields.io/github/forks/BomboBombone/CVE-2026-96874.svg)


## CVE-2026-96873
This issue affects Mediawiki - CirrusSearch extension through 1.46.0.

- [https://github.com/BomboBombone/CVE-2026-96873](https://github.com/BomboBombone/CVE-2026-96873) :  ![starts](https://img.shields.io/github/stars/BomboBombone/CVE-2026-96873.svg) ![forks](https://img.shields.io/github/forks/BomboBombone/CVE-2026-96873.svg)


## CVE-2026-96872
This issue affects Mediawiki - WikiLambda Extension: before 1.47.0.

- [https://github.com/BomboBombone/CVE-2026-96872](https://github.com/BomboBombone/CVE-2026-96872) :  ![starts](https://img.shields.io/github/stars/BomboBombone/CVE-2026-96872.svg) ![forks](https://img.shields.io/github/forks/BomboBombone/CVE-2026-96872.svg)


## CVE-2026-93687
 braces through 3.0.3 contains a stack overflow vulnerability in the recursive AST walkers that lack depth guards. Attackers can supply deeply nested brace patterns under the character limit to exhaust the call stack and terminate the Node.js process with an uncaught RangeError.

- [https://github.com/scastillo-jp/braces-fork](https://github.com/scastillo-jp/braces-fork) :  ![starts](https://img.shields.io/github/stars/scastillo-jp/braces-fork.svg) ![forks](https://img.shields.io/github/forks/scastillo-jp/braces-fork.svg)


## CVE-2026-88772
This issue affects ADC: before 14.1-73.37, before 13.1-64.23, before 14.1-73.37 FIPS, and before 13.1.37.279 FIPS and NDcPP; Gateway: before 14.1-73.37 and before 13.1-64.23 leading to Remote Code Execution or Denial of Service

- [https://github.com/watchtowrlabs/watchTowr-vs-Citrix-Netscaler-CVE-2026-88772](https://github.com/watchtowrlabs/watchTowr-vs-Citrix-Netscaler-CVE-2026-88772) :  ![starts](https://img.shields.io/github/stars/watchtowrlabs/watchTowr-vs-Citrix-Netscaler-CVE-2026-88772.svg) ![forks](https://img.shields.io/github/forks/watchtowrlabs/watchTowr-vs-Citrix-Netscaler-CVE-2026-88772.svg)


## CVE-2026-88771
This issue affects ADC: before 14.1-73.37, before 13.1-64.23, before 14.1-73.37 FIPS, and before 13.1.37.279 FIPS and NDcPP; Gateway: before 14.1-73.37 and before 13.1-64.23 leading to an unauthenticated attacker to execute arbitrary commands.

- [https://github.com/SwiftSecur/CVE-2026-88771-HuntScript](https://github.com/SwiftSecur/CVE-2026-88771-HuntScript) :  ![starts](https://img.shields.io/github/stars/SwiftSecur/CVE-2026-88771-HuntScript.svg) ![forks](https://img.shields.io/github/forks/SwiftSecur/CVE-2026-88771-HuntScript.svg)


## CVE-2026-87902
 An unauthenticated attacker can make `get_page_template()` page-template resolution include a chosen readable local `.php` file outside the active theme directories. If relevant pre-conditions for both the server and the active theme are met, this can lead to RCE.

- [https://github.com/tonydelouvre/CVE-2026-87902](https://github.com/tonydelouvre/CVE-2026-87902) :  ![starts](https://img.shields.io/github/stars/tonydelouvre/CVE-2026-87902.svg) ![forks](https://img.shields.io/github/forks/tonydelouvre/CVE-2026-87902.svg)


## CVE-2026-85520
This issue was fixed in version 2.3.9.

- [https://github.com/murrez/CVE-2026-85520](https://github.com/murrez/CVE-2026-85520) :  ![starts](https://img.shields.io/github/stars/murrez/CVE-2026-85520.svg) ![forks](https://img.shields.io/github/forks/murrez/CVE-2026-85520.svg)


## CVE-2026-84383
 libheif is a HEIF and AVIF file format decoder and encoder. From 1.22.0 until 1.23.2, a crafted HEIF, HEIC, or AVIF item graph using nested iden and auxl references can make HeifPixelImage::transfer_channel_from_image_as() append duplicate Alpha planes with different bit depths to m_storage. HeifPixelImage::scale_nearest_neighbor() in libheif/image/pixelimage.cc allocates the destination Alpha plane using the first plane's 8-bit depth, then iterates a later 10-bit or 12-bit Alpha component and writes uint16_t samples into the same 8-bit allocation. The output geometry controls the overflow extent and the encoded sample values control the data written, allowing a remote file processed by heif_decode_image() to cause a heap out-of-bounds write. This issue is fixed in version 1.23.2.

- [https://github.com/dinosn/libheif-cve-2026-84383-lab](https://github.com/dinosn/libheif-cve-2026-84383-lab) :  ![starts](https://img.shields.io/github/stars/dinosn/libheif-cve-2026-84383-lab.svg) ![forks](https://img.shields.io/github/forks/dinosn/libheif-cve-2026-84383-lab.svg)


## CVE-2026-82901
 The Ultra Addons for Contact Form 7 plugin for WordPress is vulnerable to Arbitrary File Upload due to insufficient file type validation in the 'uacf7_wpcf7_mail_components' function in all versions up to, and including, 3.5.50. This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible. Note: This is only exploitable when the plugin's PDF Generator module is enabled, which is disabled by default.

- [https://github.com/tonydelouvre/CVE-2026-82901](https://github.com/tonydelouvre/CVE-2026-82901) :  ![starts](https://img.shields.io/github/stars/tonydelouvre/CVE-2026-82901.svg) ![forks](https://img.shields.io/github/forks/tonydelouvre/CVE-2026-82901.svg)


## CVE-2026-80521
Let's unlink scc_entry before freeing the vertex in unix_del_edge().

- [https://github.com/rifkyards/Container_escape-CVE-2026-80521-CVE-2026-52910](https://github.com/rifkyards/Container_escape-CVE-2026-80521-CVE-2026-52910) :  ![starts](https://img.shields.io/github/stars/rifkyards/Container_escape-CVE-2026-80521-CVE-2026-52910.svg) ![forks](https://img.shields.io/github/forks/rifkyards/Container_escape-CVE-2026-80521-CVE-2026-52910.svg)


## CVE-2026-79417
 Improper Access Control in ArgusMonitor.sys in Argotronic eGbR ArgusMonitor 7.4.02 and earlier allows local, low-privileged users to bypass device handle access restrictions via a TOCTOU condition in IRP_MJ_CREATE and send a crafted IOCTL 0x9C4024A8 request, causing denial-of-service.

- [https://github.com/connorjaydunn/CVE-2026-79417](https://github.com/connorjaydunn/CVE-2026-79417) :  ![starts](https://img.shields.io/github/stars/connorjaydunn/CVE-2026-79417.svg) ![forks](https://img.shields.io/github/forks/connorjaydunn/CVE-2026-79417.svg)


## CVE-2026-63030
 WordPress 6.9.x before 6.9.5 and 7.0.x before 7.0.2 is affected by a REST API batch endpoint route confusion issue which, combined with the author__not_in WP_Query SQL Injection (CVE-2026-60137), could allow an attacker to perform SQL Injection and achieve Remote Code Execution.

- [https://github.com/MRdark-ops/WP2Shell--CVE-2026-63030-CVE-2026-60137-](https://github.com/MRdark-ops/WP2Shell--CVE-2026-63030-CVE-2026-60137-) :  ![starts](https://img.shields.io/github/stars/MRdark-ops/WP2Shell--CVE-2026-63030-CVE-2026-60137-.svg) ![forks](https://img.shields.io/github/forks/MRdark-ops/WP2Shell--CVE-2026-63030-CVE-2026-60137-.svg)


## CVE-2026-60137
 WordPress 6.8.x before 6.8.6, 6.9.x before 6.9.5, and 7.0.x before 7.0.2 does not properly sanitise the author__not_in parameter of WP_Query, which could allow SQL Injection when a plugin or theme passes untrusted input to the parameter.

- [https://github.com/MRdark-ops/WP2Shell--CVE-2026-63030-CVE-2026-60137-](https://github.com/MRdark-ops/WP2Shell--CVE-2026-63030-CVE-2026-60137-) :  ![starts](https://img.shields.io/github/stars/MRdark-ops/WP2Shell--CVE-2026-63030-CVE-2026-60137-.svg) ![forks](https://img.shields.io/github/forks/MRdark-ops/WP2Shell--CVE-2026-63030-CVE-2026-60137-.svg)


## CVE-2026-59310
 VMware vCenter contains a directory traversal vulnerability in the Syslog server. A malicious actor with network access to vCenter may exploit this issue to execute arbitrary code.

- [https://github.com/vpxuser/CVE-2026-59310](https://github.com/vpxuser/CVE-2026-59310) :  ![starts](https://img.shields.io/github/stars/vpxuser/CVE-2026-59310.svg) ![forks](https://img.shields.io/github/forks/vpxuser/CVE-2026-59310.svg)


## CVE-2026-53486
 The decompress package for Node.js extracts archives. Prior to 10.2.1 and 11.1.3, archive extraction can create files and links outside the target directory. When extracting an archive to a directory, a crafted archive can read or write files outside that directory because hardlink and symlink entries are created without checking where targets point, path containment used a string prefix comparison, and file modes failed to remove setuid, setgid, or sticky bits. This issue is fixed in @xhmikosr/decompress versions 10.2.1 and 11.1.3.

- [https://github.com/murrez/CVE-2026-101894](https://github.com/murrez/CVE-2026-101894) :  ![starts](https://img.shields.io/github/stars/murrez/CVE-2026-101894.svg) ![forks](https://img.shields.io/github/forks/murrez/CVE-2026-101894.svg)


## CVE-2026-52910
---truncated---

- [https://github.com/rifkyards/Container_escape-CVE-2026-80521-CVE-2026-52910](https://github.com/rifkyards/Container_escape-CVE-2026-80521-CVE-2026-52910) :  ![starts](https://img.shields.io/github/stars/rifkyards/Container_escape-CVE-2026-80521-CVE-2026-52910.svg) ![forks](https://img.shields.io/github/forks/rifkyards/Container_escape-CVE-2026-80521-CVE-2026-52910.svg)


## CVE-2026-49869
 Kestra is an open-source, event-driven orchestration platform. Prior to 1.0.45 and 1.3.21, AuthenticationFilter in Kestra OSS uses request.getPath().endsWith("/configs") to whitelist the public configuration endpoint from Basic Auth. Because the check is a suffix match rather than an exact path match, any API path whose last segment is configs bypasses authentication entirely. An unauthenticated remote attacker can exploit this to create and execute arbitrary workflows without credentials. Because Kestra ships with script execution plugins (plugin-script-shell, plugin-script-python, etc.) enabled by default, this directly results in unauthenticated Remote Code Execution as root inside the Kestra worker container.  This vulnerability is fixed in 1.0.45 and 1.3.21.

- [https://github.com/EQSTLab/CVE-2026-49869](https://github.com/EQSTLab/CVE-2026-49869) :  ![starts](https://img.shields.io/github/stars/EQSTLab/CVE-2026-49869.svg) ![forks](https://img.shields.io/github/forks/EQSTLab/CVE-2026-49869.svg)


## CVE-2026-43499
  	changelog ]

- [https://github.com/CKwasd/zenfone9-ghostlock](https://github.com/CKwasd/zenfone9-ghostlock) :  ![starts](https://img.shields.io/github/stars/CKwasd/zenfone9-ghostlock.svg) ![forks](https://img.shields.io/github/forks/CKwasd/zenfone9-ghostlock.svg)
- [https://github.com/aniketlab/POCO-M7-Plus-Jailbreak](https://github.com/aniketlab/POCO-M7-Plus-Jailbreak) :  ![starts](https://img.shields.io/github/stars/aniketlab/POCO-M7-Plus-Jailbreak.svg) ![forks](https://img.shields.io/github/forks/aniketlab/POCO-M7-Plus-Jailbreak.svg)
- [https://github.com/HORKimhab/CVE-2026-43499](https://github.com/HORKimhab/CVE-2026-43499) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-43499.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-43499.svg)


## CVE-2026-41089
 Stack-based buffer overflow in Windows Netlogon allows an unauthorized attacker to execute code over a network.

- [https://github.com/1posix/CVE-2026-41089-PoC](https://github.com/1posix/CVE-2026-41089-PoC) :  ![starts](https://img.shields.io/github/stars/1posix/CVE-2026-41089-PoC.svg) ![forks](https://img.shields.io/github/forks/1posix/CVE-2026-41089-PoC.svg)


## CVE-2026-34990
 OpenPrinting CUPS is an open source printing system for Linux and other Unix-like operating systems. In versions 2.4.16 and prior, a local unprivileged user can coerce cupsd into authenticating to an attacker-controlled localhost IPP service with a reusable Authorization: Local ... token. That token is enough to drive /admin/ requests on localhost, and the attacker can combine CUPS-Create-Local-Printer with printer-is-shared=true to persist a file:///... queue even though the normal FileDevice policy rejects such URIs. Printing to that queue gives an arbitrary root file overwrite; the PoC below uses that primitive to drop a sudoers fragment and demonstrate root command execution. At time of publication, there are no publicly available patches.

- [https://github.com/mrdebora/cups-2.4.16-lpe](https://github.com/mrdebora/cups-2.4.16-lpe) :  ![starts](https://img.shields.io/github/stars/mrdebora/cups-2.4.16-lpe.svg) ![forks](https://img.shields.io/github/forks/mrdebora/cups-2.4.16-lpe.svg)


## CVE-2026-31857
 Craft is a content management system (CMS). Prior to 5.9.9 and 4.17.4, a Remote Code Execution vulnerability exists in the Craft CMS 5 conditions system. The BaseElementSelectConditionRule::getElementIds() method passes user-controlled string input through renderObjectTemplate() -- an unsandboxed Twig rendering function with escaping disabled. Any authenticated Control Panel user (including non-admin roles such as Author or Editor) can achieve full RCE by sending a crafted condition rule via standard element listing endpoints. This vulnerability requires no admin privileges, no special permissions beyond basic control panel access, and bypasses all production hardening settings (allowAdminChanges: false, devMode: false, enableTwigSandbox: true). Users should update to the patched 5.9.9 or 4.17.4 release to mitigate the issue.

- [https://github.com/0xTatsuki/CVE-2026-31857](https://github.com/0xTatsuki/CVE-2026-31857) :  ![starts](https://img.shields.io/github/stars/0xTatsuki/CVE-2026-31857.svg) ![forks](https://img.shields.io/github/forks/0xTatsuki/CVE-2026-31857.svg)


## CVE-2026-31431
AD directly.

- [https://github.com/st4rburn/RootRemover](https://github.com/st4rburn/RootRemover) :  ![starts](https://img.shields.io/github/stars/st4rburn/RootRemover.svg) ![forks](https://img.shields.io/github/forks/st4rburn/RootRemover.svg)
- [https://github.com/st4rburn/public-passwd](https://github.com/st4rburn/public-passwd) :  ![starts](https://img.shields.io/github/stars/st4rburn/public-passwd.svg) ![forks](https://img.shields.io/github/forks/st4rburn/public-passwd.svg)
- [https://github.com/ZeroDayEvil/CVE-2026-31431](https://github.com/ZeroDayEvil/CVE-2026-31431) :  ![starts](https://img.shields.io/github/stars/ZeroDayEvil/CVE-2026-31431.svg) ![forks](https://img.shields.io/github/forks/ZeroDayEvil/CVE-2026-31431.svg)


## CVE-2026-24088
 Cryptographic Issue while processing a specific partition which allows unauthorized write access to load a customized bootloader.

- [https://github.com/aniketlab/POCO-M7-Plus-Jailbreak](https://github.com/aniketlab/POCO-M7-Plus-Jailbreak) :  ![starts](https://img.shields.io/github/stars/aniketlab/POCO-M7-Plus-Jailbreak.svg) ![forks](https://img.shields.io/github/forks/aniketlab/POCO-M7-Plus-Jailbreak.svg)


## CVE-2026-10817
 Insufficient input validation leading to memory overread in NetScaler ADC and NetScaler Gateway if the TCP TimeStamp is enabled in TCP Profile and is associated with the virtual server (of type LB, CS, VPN) or the service configured on NetScaler

- [https://github.com/HORKimhab/CVE-2026-10817](https://github.com/HORKimhab/CVE-2026-10817) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-10817.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-10817.svg)


## CVE-2026-9454
 A flaw has been found in Totolink A8000RU 7.1cu.643_b20200521. This vulnerability affects the function setOpenVpnCertGenerationCfg of the file /cgi-bin/cstecgi.cgi of the component Web Management Interface. Executing a manipulation of the argument servername can lead to os command injection. The attack may be launched remotely. The exploit has been published and may be used.

- [https://github.com/EQSTLab/CVE-2026-94545](https://github.com/EQSTLab/CVE-2026-94545) :  ![starts](https://img.shields.io/github/stars/EQSTLab/CVE-2026-94545.svg) ![forks](https://img.shields.io/github/forks/EQSTLab/CVE-2026-94545.svg)


## CVE-2026-8862
 IBM Netezza Software 11.3.0.3 through Interim Fix 002 has credentials that are hardcoded in the application source code, allowing unauthorized access to the container registry. The exposed secret enables attackers to pull private container images, potentially revealing proprietary code, configuration details, and other sensitive information.

- [https://github.com/ExploreIO/CVE-2026-88629-fastgpt-mcp-client-ssrf](https://github.com/ExploreIO/CVE-2026-88629-fastgpt-mcp-client-ssrf) :  ![starts](https://img.shields.io/github/stars/ExploreIO/CVE-2026-88629-fastgpt-mcp-client-ssrf.svg) ![forks](https://img.shields.io/github/forks/ExploreIO/CVE-2026-88629-fastgpt-mcp-client-ssrf.svg)


## CVE-2026-8065
 An authentication bypass vulnerability in the firmware update endpoint of Hitachi Energy RTU500 end-of-life versions allows an unauthenticated attacker to upload arbitrary firmware through a crafted POST request. Successful exploitation could allow the attacker to modify device functionality or compromise the integrity or availability of the device.

- [https://github.com/MRdark-ops/CVE-2026-8065](https://github.com/MRdark-ops/CVE-2026-8065) :  ![starts](https://img.shields.io/github/stars/MRdark-ops/CVE-2026-8065.svg) ![forks](https://img.shields.io/github/forks/MRdark-ops/CVE-2026-8065.svg)
- [https://github.com/murrez/CVE-2026-8065](https://github.com/murrez/CVE-2026-8065) :  ![starts](https://img.shields.io/github/stars/murrez/CVE-2026-8065.svg) ![forks](https://img.shields.io/github/forks/murrez/CVE-2026-8065.svg)


## CVE-2026-4349
 A vulnerability was determined in Duende IdentityServer4 up to 4.1.2. The affected element is an unknown function of the file /connect/authorize of the component Token Renewal Endpoint. This manipulation of the argument id_token_hint causes improper authentication. It is possible to initiate the attack remotely. The attack is considered to have high complexity. The exploitability is described as difficult. This vulnerability only affects products that are no longer supported by the maintainer.

- [https://github.com/Kananosa/CVE-2026-43499-For-Xiaomi-17T-chagall](https://github.com/Kananosa/CVE-2026-43499-For-Xiaomi-17T-chagall) :  ![starts](https://img.shields.io/github/stars/Kananosa/CVE-2026-43499-For-Xiaomi-17T-chagall.svg) ![forks](https://img.shields.io/github/forks/Kananosa/CVE-2026-43499-For-Xiaomi-17T-chagall.svg)
- [https://github.com/shubhampathak65/CVE-2026-43499](https://github.com/shubhampathak65/CVE-2026-43499) :  ![starts](https://img.shields.io/github/stars/shubhampathak65/CVE-2026-43499.svg) ![forks](https://img.shields.io/github/forks/shubhampathak65/CVE-2026-43499.svg)


## CVE-2026-3143
 The Total Upkeep – WordPress Backup Plugin plus Restore & Migrate by BoldGrid plugin for WordPress is vulnerable to unauthorized modification of data due to a missing capability check on the 'wp_ajax_cli_cancel' function in all versions up to, and including, 1.17.1. This makes it possible for unauthenticated attackers to cancel a pending rollback, potentially preventing a WordPress installation from automatically reverting a failed update.

- [https://github.com/sec17br/CVE-2026-31431-Copy-Fail](https://github.com/sec17br/CVE-2026-31431-Copy-Fail) :  ![starts](https://img.shields.io/github/stars/sec17br/CVE-2026-31431-Copy-Fail.svg) ![forks](https://img.shields.io/github/forks/sec17br/CVE-2026-31431-Copy-Fail.svg)
- [https://github.com/pyroceper/copy-fail-CVE-2026-31431](https://github.com/pyroceper/copy-fail-CVE-2026-31431) :  ![starts](https://img.shields.io/github/stars/pyroceper/copy-fail-CVE-2026-31431.svg) ![forks](https://img.shields.io/github/forks/pyroceper/copy-fail-CVE-2026-31431.svg)
- [https://github.com/abdelkabirouadoukou/CVE-2026-31431-Analysis-and-Fix](https://github.com/abdelkabirouadoukou/CVE-2026-31431-Analysis-and-Fix) :  ![starts](https://img.shields.io/github/stars/abdelkabirouadoukou/CVE-2026-31431-Analysis-and-Fix.svg) ![forks](https://img.shields.io/github/forks/abdelkabirouadoukou/CVE-2026-31431-Analysis-and-Fix.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-packagemanager-field](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-packagemanager-field) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-packagemanager-field.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-packagemanager-field.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-15x](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-15x) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-15x.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-15x.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo.svg)


## CVE-2025-62023
 Improper Control of Generation of Code ('Code Injection') vulnerability in Cristián Lávaque s2Member s2member.This issue affects s2Member: from n/a through 250905.

- [https://github.com/josemour8/CVE-2025-62023](https://github.com/josemour8/CVE-2025-62023) :  ![starts](https://img.shields.io/github/stars/josemour8/CVE-2025-62023.svg) ![forks](https://img.shields.io/github/forks/josemour8/CVE-2025-62023.svg)


## CVE-2025-57819
 FreePBX is an open-source web-based graphical user interface. FreePBX 15, 16, and 17 endpoints are vulnerable due to insufficiently sanitized user-supplied data allowing unauthenticated access to FreePBX Administrator leading to arbitrary database manipulation and remote code execution. This issue has been patched in endpoint versions 15.0.66, 16.0.89, and 17.0.3.

- [https://github.com/donggle0802-code/cve-2025-57819](https://github.com/donggle0802-code/cve-2025-57819) :  ![starts](https://img.shields.io/github/stars/donggle0802-code/cve-2025-57819.svg) ![forks](https://img.shields.io/github/forks/donggle0802-code/cve-2025-57819.svg)


## CVE-2025-32463
 Sudo before 1.9.17p1 allows local users to obtain root access because /etc/nsswitch.conf from a user-controlled directory is used with the --chroot option.

- [https://github.com/klvlo/CVE-2025-32463](https://github.com/klvlo/CVE-2025-32463) :  ![starts](https://img.shields.io/github/stars/klvlo/CVE-2025-32463.svg) ![forks](https://img.shields.io/github/forks/klvlo/CVE-2025-32463.svg)


## CVE-2025-14783
 The Easy Digital Downloads plugin for WordPress is vulnerable to Unvalidated Redirect in all versions up to, and including, 3.6.2. This is due to insufficient validation on the redirect url supplied via the 'edd_redirect' parameter. This makes it possible for unauthenticated attackers to redirect users with the password reset email to potentially malicious sites if they can successfully trick them into performing an action.

- [https://github.com/Ngagne-Demba-Dia/CVE-2025-14783-POC](https://github.com/Ngagne-Demba-Dia/CVE-2025-14783-POC) :  ![starts](https://img.shields.io/github/stars/Ngagne-Demba-Dia/CVE-2025-14783-POC.svg) ![forks](https://img.shields.io/github/forks/Ngagne-Demba-Dia/CVE-2025-14783-POC.svg)


## CVE-2025-8088
     from ESET.

- [https://github.com/roof1948576qwd/CVE-2025-8088-WinRAR-PoC-1](https://github.com/roof1948576qwd/CVE-2025-8088-WinRAR-PoC-1) :  ![starts](https://img.shields.io/github/stars/roof1948576qwd/CVE-2025-8088-WinRAR-PoC-1.svg) ![forks](https://img.shields.io/github/forks/roof1948576qwd/CVE-2025-8088-WinRAR-PoC-1.svg)
- [https://github.com/roof1948576qwd/CVE-2025-8088-WinRAR-PoC-3](https://github.com/roof1948576qwd/CVE-2025-8088-WinRAR-PoC-3) :  ![starts](https://img.shields.io/github/stars/roof1948576qwd/CVE-2025-8088-WinRAR-PoC-3.svg) ![forks](https://img.shields.io/github/forks/roof1948576qwd/CVE-2025-8088-WinRAR-PoC-3.svg)
- [https://github.com/roof1948576qwd/CVE-2025-8088-WinRAR-PoC-2](https://github.com/roof1948576qwd/CVE-2025-8088-WinRAR-PoC-2) :  ![starts](https://img.shields.io/github/stars/roof1948576qwd/CVE-2025-8088-WinRAR-PoC-2.svg) ![forks](https://img.shields.io/github/forks/roof1948576qwd/CVE-2025-8088-WinRAR-PoC-2.svg)


## CVE-2025-6647
The specific flaw exists within the parsing of U3D files. The issue results from the lack of proper validation of user-supplied data, which can result in a write past the end of an allocated object. An attacker can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-26644.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-14x](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-14x) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-14x.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-14x.svg)


## CVE-2025-4123
The default Content-Security-Policy (CSP) in Grafana will block the XSS though the `connect-src` directive.

- [https://github.com/primesec-dev/grafana_mythos_cve-2025-4123](https://github.com/primesec-dev/grafana_mythos_cve-2025-4123) :  ![starts](https://img.shields.io/github/stars/primesec-dev/grafana_mythos_cve-2025-4123.svg) ![forks](https://img.shields.io/github/forks/primesec-dev/grafana_mythos_cve-2025-4123.svg)


## CVE-2024-54767
 An access control issue in the component /juis_boxinfo.xml of AVM FRITZ!Box 7530 AX v7.59 allows attackers to obtain sensitive information without authentication. NOTE: this is disputed by the Supplier because it cannot be reproduced, and the issue report focuses on an unintended configuration with direct Internet exposure.

- [https://github.com/lowlevelsec/AVM-FRITZ-Box-CVE-2024-54767-Exploit](https://github.com/lowlevelsec/AVM-FRITZ-Box-CVE-2024-54767-Exploit) :  ![starts](https://img.shields.io/github/stars/lowlevelsec/AVM-FRITZ-Box-CVE-2024-54767-Exploit.svg) ![forks](https://img.shields.io/github/forks/lowlevelsec/AVM-FRITZ-Box-CVE-2024-54767-Exploit.svg)


## CVE-2024-38063
 Windows TCP/IP Remote Code Execution Vulnerability

- [https://github.com/izaan-sh/CVE-2024-38063-Exploitation-Detection-Mitigation-Lab](https://github.com/izaan-sh/CVE-2024-38063-Exploitation-Detection-Mitigation-Lab) :  ![starts](https://img.shields.io/github/stars/izaan-sh/CVE-2024-38063-Exploitation-Detection-Mitigation-Lab.svg) ![forks](https://img.shields.io/github/forks/izaan-sh/CVE-2024-38063-Exploitation-Detection-Mitigation-Lab.svg)


## CVE-2024-21626
 runc is a CLI tool for spawning and running containers on Linux according to the OCI specification. In runc 1.1.11 and earlier, due to an internal file descriptor leak, an attacker could cause a newly-spawned container process (from runc exec) to have a working directory in the host filesystem namespace, allowing for a container escape by giving access to the host filesystem ("attack 2"). The same attack could be used by a malicious image to allow a container process to gain access to the host filesystem through runc run ("attack 1"). Variants of attacks 1 and 2 could be also be used to overwrite semi-arbitrary host binaries, allowing for complete container escapes ("attack 3a" and "attack 3b"). runc 1.1.12 includes patches for this issue.

- [https://github.com/RnW29/cve-2024-21626-runc-lab](https://github.com/RnW29/cve-2024-21626-runc-lab) :  ![starts](https://img.shields.io/github/stars/RnW29/cve-2024-21626-runc-lab.svg) ![forks](https://img.shields.io/github/forks/RnW29/cve-2024-21626-runc-lab.svg)


## CVE-2023-43364
 main.py in Searchor before 2.4.2 uses eval on CLI input, which may cause unexpected code execution.

- [https://github.com/IamSaishi/CVE-2023-43364_Exploit](https://github.com/IamSaishi/CVE-2023-43364_Exploit) :  ![starts](https://img.shields.io/github/stars/IamSaishi/CVE-2023-43364_Exploit.svg) ![forks](https://img.shields.io/github/forks/IamSaishi/CVE-2023-43364_Exploit.svg)


## CVE-2023-40931
 A SQL injection vulnerability in Nagios XI from version 5.11.0 up to and including 5.11.1 allows authenticated attackers to execute arbitrary SQL commands via the ID parameter in the POST request to /nagiosxi/admin/banner_message-ajaxhelper.php

- [https://github.com/NCF0126/Nagios-XI-s-CVE-2023-40931-Exploit](https://github.com/NCF0126/Nagios-XI-s-CVE-2023-40931-Exploit) :  ![starts](https://img.shields.io/github/stars/NCF0126/Nagios-XI-s-CVE-2023-40931-Exploit.svg) ![forks](https://img.shields.io/github/forks/NCF0126/Nagios-XI-s-CVE-2023-40931-Exploit.svg)


## CVE-2023-38831
 RARLAB WinRAR before 6.23 allows attackers to execute arbitrary code when a user attempts to view a benign file within a ZIP archive. The issue occurs because a ZIP archive may include a benign file (such as an ordinary .JPG file) and also a folder that has the same name as the benign file, and the contents of the folder (which may include executable content) are processed during an attempt to access only the benign file. This was exploited in the wild in April through October 2023.

- [https://github.com/KrioSocial/defender-bypass-winrar-cve-2023-38831](https://github.com/KrioSocial/defender-bypass-winrar-cve-2023-38831) :  ![starts](https://img.shields.io/github/stars/KrioSocial/defender-bypass-winrar-cve-2023-38831.svg) ![forks](https://img.shields.io/github/forks/KrioSocial/defender-bypass-winrar-cve-2023-38831.svg)
- [https://github.com/Dnyaneshwari-123/DFIR-Capstone-Investigations](https://github.com/Dnyaneshwari-123/DFIR-Capstone-Investigations) :  ![starts](https://img.shields.io/github/stars/Dnyaneshwari-123/DFIR-Capstone-Investigations.svg) ![forks](https://img.shields.io/github/forks/Dnyaneshwari-123/DFIR-Capstone-Investigations.svg)


## CVE-2022-0847
 A flaw was found in the way the "flags" member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/pmihsan/Dirty-Pipe-CVE-2022-0847](https://github.com/pmihsan/Dirty-Pipe-CVE-2022-0847) :  ![starts](https://img.shields.io/github/stars/pmihsan/Dirty-Pipe-CVE-2022-0847.svg) ![forks](https://img.shields.io/github/forks/pmihsan/Dirty-Pipe-CVE-2022-0847.svg)


## CVE-2021-4177
 livehelperchat is vulnerable to Generation of Error Message Containing Sensitive Information

- [https://github.com/Park123r/CVE-2021-41773](https://github.com/Park123r/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/Park123r/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/Park123r/CVE-2021-41773.svg)


## CVE-2020-24186
 A Remote Code Execution vulnerability exists in the gVectors wpDiscuz plugin 7.0 through 7.0.4 for WordPress, which allows unauthenticated users to upload any type of file, including PHP files via the wmuUploadFiles AJAX action.

- [https://github.com/kiyingiericmark-wq/CVE-2020-24186](https://github.com/kiyingiericmark-wq/CVE-2020-24186) :  ![starts](https://img.shields.io/github/stars/kiyingiericmark-wq/CVE-2020-24186.svg) ![forks](https://img.shields.io/github/forks/kiyingiericmark-wq/CVE-2020-24186.svg)

