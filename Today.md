# Update 2026-11-04
## CVE-2026-120318
 Product Gallery Slider & Additional Variation Images for WooCommerce 2.3.23 before 2.3.26 contains a missing authorization vulnerability in Codestar backup AJAX actions csf-export, csf-import and csf-reset. Shop Managers can read the csf_backup_nonce from the settings page and supply arbitrary option names via the 'unique' parameter to read, overwrite or delete WordPress options, including modifying wp_user_roles to escalate to administrator.

- [https://github.com/7xd10/CVE-2026-120318](https://github.com/7xd10/CVE-2026-120318) :  ![starts](https://img.shields.io/github/stars/7xd10/CVE-2026-120318.svg) ![forks](https://img.shields.io/github/forks/7xd10/CVE-2026-120318.svg)


## CVE-2026-117561
 Codefriar sf-mcp through 1.3.2 contains an OS command injection vulnerability that allows attackers to execute shell commands by supplying crafted Salesforce CLI tool flag values. Because escapeValue() in src/utils.ts fails to neutralize backticks, $() substitution, and other shell metacharacters, these values reach execSync in executeSfCommand and run as the MCP server user.

- [https://github.com/AlexBiller/salesforce-cve-remediation-demo](https://github.com/AlexBiller/salesforce-cve-remediation-demo) :  ![starts](https://img.shields.io/github/stars/AlexBiller/salesforce-cve-remediation-demo.svg) ![forks](https://img.shields.io/github/forks/AlexBiller/salesforce-cve-remediation-demo.svg)


## CVE-2026-115904
 Topluyo is a social networking platform. A vulnerability exists in Topluyo Desktop for Linux prior to version 2026.9.2410 where user-controlled URLs are unsafely processed, leading to OS Command Injection via the `openExternalLinks()` routine in `utils.js`. An attacker who controls a target URL can execute arbitrary operating system commands with the privileges of the user running the application upon opening the link. Version 2026.9.2410 patches the issue.

- [https://github.com/VulnSVNC/CVE-2026-115904](https://github.com/VulnSVNC/CVE-2026-115904) :  ![starts](https://img.shields.io/github/stars/VulnSVNC/CVE-2026-115904.svg) ![forks](https://img.shields.io/github/forks/VulnSVNC/CVE-2026-115904.svg)


## CVE-2026-112816
 Improper certificate validation in the HTTPS listener in Canonical LXD 4.0.14, 5.0.10, 5.21.8, 6.9 before 4.0.15, 5.0.11, 5.21.9, 6.10.1 allows an unauthenticated attacker to authenticate as any trusted client and gain full access to the cluster and managed virtual machines via a crafted certificate chain.

- [https://github.com/foxcornlab/lxd-scanner](https://github.com/foxcornlab/lxd-scanner) :  ![starts](https://img.shields.io/github/stars/foxcornlab/lxd-scanner.svg) ![forks](https://img.shields.io/github/forks/foxcornlab/lxd-scanner.svg)


## CVE-2026-112688
 A memory corruption issue was addressed with improved memory handling. This issue is fixed in iOS 26.7 and iPadOS 26.7, iOS 27.2 and iPadOS 27.2, macOS Golden Gate 27.2, macOS Sequoia 15.8.2, macOS Tahoe 26.7.2. Parsing a file may lead to an unexpected app termination or arbitrary code execution.

- [https://github.com/0xjohnnydev/CVE-2026-112688-backboardd](https://github.com/0xjohnnydev/CVE-2026-112688-backboardd) :  ![starts](https://img.shields.io/github/stars/0xjohnnydev/CVE-2026-112688-backboardd.svg) ![forks](https://img.shields.io/github/forks/0xjohnnydev/CVE-2026-112688-backboardd.svg)


## CVE-2026-111497
Users need to update any Brotli libraries or binaries between 1.0.3 through 1.2.0 to the latest available version: 1.0.10 or 1.1.1 or 1.2.1.

- [https://github.com/fortbridge/cve-2026-111497-wordpress-pingback-brotli](https://github.com/fortbridge/cve-2026-111497-wordpress-pingback-brotli) :  ![starts](https://img.shields.io/github/stars/fortbridge/cve-2026-111497-wordpress-pingback-brotli.svg) ![forks](https://img.shields.io/github/forks/fortbridge/cve-2026-111497-wordpress-pingback-brotli.svg)
- [https://github.com/EQSTLab/CVE-2026-111497](https://github.com/EQSTLab/CVE-2026-111497) :  ![starts](https://img.shields.io/github/stars/EQSTLab/CVE-2026-111497.svg) ![forks](https://img.shields.io/github/forks/EQSTLab/CVE-2026-111497.svg)
- [https://github.com/fieldse/http2shell-checker](https://github.com/fieldse/http2shell-checker) :  ![starts](https://img.shields.io/github/stars/fieldse/http2shell-checker.svg) ![forks](https://img.shields.io/github/forks/fieldse/http2shell-checker.svg)
- [https://github.com/ChriSec7/CVE-2026-111497-POC](https://github.com/ChriSec7/CVE-2026-111497-POC) :  ![starts](https://img.shields.io/github/stars/ChriSec7/CVE-2026-111497-POC.svg) ![forks](https://img.shields.io/github/forks/ChriSec7/CVE-2026-111497-POC.svg)


## CVE-2026-110447
 Collabora Online Built-in CODE Server before 26.4.303 (richdocumentscode), a Nextcloud app, allows remote code execution, as exploited in the wild in September and October 2026, a different vulnerability than CVE-2025-66208. This is an OS command injection in proxy.php when the CODE server isn't running (e.g., the product was recently restarted). The vulnerability is not present in standalone Collabora Online servers; only this deployment with CODE Server is affected.

- [https://github.com/maxprog-svg/CVE-2026-110447](https://github.com/maxprog-svg/CVE-2026-110447) :  ![starts](https://img.shields.io/github/stars/maxprog-svg/CVE-2026-110447.svg) ![forks](https://img.shields.io/github/forks/maxprog-svg/CVE-2026-110447.svg)


## CVE-2026-109619
 PHP has various global state that temporarily points into request memory. In some scenarios, global state may not be correctly reset, or may be repopulated after being reset. The global state may then refer to request memory even after it has been freed. Subsequent requests may read or branch on this stale state before it is fully initialized. Multiple strategies can trigger this condition and produce remote code execution (RCE).

- [https://github.com/godylockz/CVE-2026-109618-109619](https://github.com/godylockz/CVE-2026-109618-109619) :  ![starts](https://img.shields.io/github/stars/godylockz/CVE-2026-109618-109619.svg) ![forks](https://img.shields.io/github/forks/godylockz/CVE-2026-109618-109619.svg)
- [https://github.com/gorgeoushos/CVE-2026-109618-research](https://github.com/gorgeoushos/CVE-2026-109618-research) :  ![starts](https://img.shields.io/github/stars/gorgeoushos/CVE-2026-109618-research.svg) ![forks](https://img.shields.io/github/forks/gorgeoushos/CVE-2026-109618-research.svg)


## CVE-2026-109618
 PHP uses longjmp() for out-of-memory (OOM) errors to exit the current context and abort handling of the request. Some contexts may not properly account for this scenario and leave request memory in an uninitialized state before performing an allocation. The subsequent request cleanup procedure may read or branch on this memory. Multiple OOM strategies can consistently trigger this condition and lead to remote code execution (RCE).

- [https://github.com/godylockz/CVE-2026-109618-109619](https://github.com/godylockz/CVE-2026-109618-109619) :  ![starts](https://img.shields.io/github/stars/godylockz/CVE-2026-109618-109619.svg) ![forks](https://img.shields.io/github/forks/godylockz/CVE-2026-109618-109619.svg)
- [https://github.com/gorgeoushos/CVE-2026-109618-research](https://github.com/gorgeoushos/CVE-2026-109618-research) :  ![starts](https://img.shields.io/github/stars/gorgeoushos/CVE-2026-109618-research.svg) ![forks](https://img.shields.io/github/forks/gorgeoushos/CVE-2026-109618-research.svg)


## CVE-2026-105863
 Payload is a free and open source headless content management system. In versions after 3.0.0 and before 3.90.0, a custom field option that maps a field to a reserved authentication claim name can place unintended values in the authentication token issued at login. This issue is fixed in version 3.90.0.

- [https://github.com/lelaboratoiredegenie/CVE-2026-105863](https://github.com/lelaboratoiredegenie/CVE-2026-105863) :  ![starts](https://img.shields.io/github/stars/lelaboratoiredegenie/CVE-2026-105863.svg) ![forks](https://img.shields.io/github/forks/lelaboratoiredegenie/CVE-2026-105863.svg)


## CVE-2026-98432
will be addressed in a separate patch.

- [https://github.com/Omniversetr/omnicheck_CVE-2026-98432](https://github.com/Omniversetr/omnicheck_CVE-2026-98432) :  ![starts](https://img.shields.io/github/stars/Omniversetr/omnicheck_CVE-2026-98432.svg) ![forks](https://img.shields.io/github/forks/Omniversetr/omnicheck_CVE-2026-98432.svg)
- [https://github.com/0xBlackash/CVE-2026-98432](https://github.com/0xBlackash/CVE-2026-98432) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-98432.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-98432.svg)
- [https://github.com/IgrekLg/cve-2026-98432-mitigation](https://github.com/IgrekLg/cve-2026-98432-mitigation) :  ![starts](https://img.shields.io/github/stars/IgrekLg/cve-2026-98432-mitigation.svg) ![forks](https://img.shields.io/github/forks/IgrekLg/cve-2026-98432-mitigation.svg)
- [https://github.com/illuscapital/CVE-2026-98432](https://github.com/illuscapital/CVE-2026-98432) :  ![starts](https://img.shields.io/github/stars/illuscapital/CVE-2026-98432.svg) ![forks](https://img.shields.io/github/forks/illuscapital/CVE-2026-98432.svg)
- [https://github.com/braginvalentin/cve_2026_98432](https://github.com/braginvalentin/cve_2026_98432) :  ![starts](https://img.shields.io/github/stars/braginvalentin/cve_2026_98432.svg) ![forks](https://img.shields.io/github/forks/braginvalentin/cve_2026_98432.svg)
- [https://github.com/xxhjkl/cve-2026-98432-check](https://github.com/xxhjkl/cve-2026-98432-check) :  ![starts](https://img.shields.io/github/stars/xxhjkl/cve-2026-98432-check.svg) ![forks](https://img.shields.io/github/forks/xxhjkl/cve-2026-98432-check.svg)
- [https://github.com/maxottovon/CVE-2026-98432-scan](https://github.com/maxottovon/CVE-2026-98432-scan) :  ![starts](https://img.shields.io/github/stars/maxottovon/CVE-2026-98432-scan.svg) ![forks](https://img.shields.io/github/forks/maxottovon/CVE-2026-98432-scan.svg)
- [https://github.com/upeul/cve-2026-98432-linux](https://github.com/upeul/cve-2026-98432-linux) :  ![starts](https://img.shields.io/github/stars/upeul/cve-2026-98432-linux.svg) ![forks](https://img.shields.io/github/forks/upeul/cve-2026-98432-linux.svg)
- [https://github.com/knneth/cve-2026-98432-dkms](https://github.com/knneth/cve-2026-98432-dkms) :  ![starts](https://img.shields.io/github/stars/knneth/cve-2026-98432-dkms.svg) ![forks](https://img.shields.io/github/forks/knneth/cve-2026-98432-dkms.svg)
- [https://github.com/marcelofmatos/cve-2026-98432-check](https://github.com/marcelofmatos/cve-2026-98432-check) :  ![starts](https://img.shields.io/github/stars/marcelofmatos/cve-2026-98432-check.svg) ![forks](https://img.shields.io/github/forks/marcelofmatos/cve-2026-98432-check.svg)
- [https://github.com/0xSpuddy/cve-2026-98432-check](https://github.com/0xSpuddy/cve-2026-98432-check) :  ![starts](https://img.shields.io/github/stars/0xSpuddy/cve-2026-98432-check.svg) ![forks](https://img.shields.io/github/forks/0xSpuddy/cve-2026-98432-check.svg)
- [https://github.com/matthew-hollick/mitigate-cve-2026-98432](https://github.com/matthew-hollick/mitigate-cve-2026-98432) :  ![starts](https://img.shields.io/github/stars/matthew-hollick/mitigate-cve-2026-98432.svg) ![forks](https://img.shields.io/github/forks/matthew-hollick/mitigate-cve-2026-98432.svg)
- [https://github.com/valkenindustries/cve-2026-98432-mitigation](https://github.com/valkenindustries/cve-2026-98432-mitigation) :  ![starts](https://img.shields.io/github/stars/valkenindustries/cve-2026-98432-mitigation.svg) ![forks](https://img.shields.io/github/forks/valkenindustries/cve-2026-98432-mitigation.svg)
- [https://github.com/BigBIueWhale/cve-2026-98432-kernel-upgrade](https://github.com/BigBIueWhale/cve-2026-98432-kernel-upgrade) :  ![starts](https://img.shields.io/github/stars/BigBIueWhale/cve-2026-98432-kernel-upgrade.svg) ![forks](https://img.shields.io/github/forks/BigBIueWhale/cve-2026-98432-kernel-upgrade.svg)
- [https://github.com/GarphenGate/cve-2026-98432-defender-toolkit](https://github.com/GarphenGate/cve-2026-98432-defender-toolkit) :  ![starts](https://img.shields.io/github/stars/GarphenGate/cve-2026-98432-defender-toolkit.svg) ![forks](https://img.shields.io/github/forks/GarphenGate/cve-2026-98432-defender-toolkit.svg)
- [https://github.com/thiscitze/cve-2026-98432-root-shell](https://github.com/thiscitze/cve-2026-98432-root-shell) :  ![starts](https://img.shields.io/github/stars/thiscitze/cve-2026-98432-root-shell.svg) ![forks](https://img.shields.io/github/forks/thiscitze/cve-2026-98432-root-shell.svg)
- [https://github.com/johnhsb/linux-tcp-uaf-cve-2026-98432](https://github.com/johnhsb/linux-tcp-uaf-cve-2026-98432) :  ![starts](https://img.shields.io/github/stars/johnhsb/linux-tcp-uaf-cve-2026-98432.svg) ![forks](https://img.shields.io/github/forks/johnhsb/linux-tcp-uaf-cve-2026-98432.svg)
- [https://github.com/Pr0fEs0r-X/CVE-2026-98432-Checker-v-1.0-](https://github.com/Pr0fEs0r-X/CVE-2026-98432-Checker-v-1.0-) :  ![starts](https://img.shields.io/github/stars/Pr0fEs0r-X/CVE-2026-98432-Checker-v-1.0-.svg) ![forks](https://img.shields.io/github/forks/Pr0fEs0r-X/CVE-2026-98432-Checker-v-1.0-.svg)
- [https://github.com/akaihigurashi/kernel98scan](https://github.com/akaihigurashi/kernel98scan) :  ![starts](https://img.shields.io/github/stars/akaihigurashi/kernel98scan.svg) ![forks](https://img.shields.io/github/forks/akaihigurashi/kernel98scan.svg)
- [https://github.com/mc493/kshield](https://github.com/mc493/kshield) :  ![starts](https://img.shields.io/github/stars/mc493/kshield.svg) ![forks](https://img.shields.io/github/forks/mc493/kshield.svg)


## CVE-2026-98260
[ tglx: Move the cleanup right after de_thread() ]

- [https://github.com/LinXing0926/GhostCred](https://github.com/LinXing0926/GhostCred) :  ![starts](https://img.shields.io/github/stars/LinXing0926/GhostCred.svg) ![forks](https://img.shields.io/github/forks/LinXing0926/GhostCred.svg)
- [https://github.com/super2tt/CVE-2026-98260-vivo-x-fold6-poc](https://github.com/super2tt/CVE-2026-98260-vivo-x-fold6-poc) :  ![starts](https://img.shields.io/github/stars/super2tt/CVE-2026-98260-vivo-x-fold6-poc.svg) ![forks](https://img.shields.io/github/forks/super2tt/CVE-2026-98260-vivo-x-fold6-poc.svg)
- [https://github.com/YodonTan/cve-2026-98260-harmonyos-applicability](https://github.com/YodonTan/cve-2026-98260-harmonyos-applicability) :  ![starts](https://img.shields.io/github/stars/YodonTan/cve-2026-98260-harmonyos-applicability.svg) ![forks](https://img.shields.io/github/forks/YodonTan/cve-2026-98260-harmonyos-applicability.svg)
- [https://github.com/kailashrs/infinitylock-app](https://github.com/kailashrs/infinitylock-app) :  ![starts](https://img.shields.io/github/stars/kailashrs/infinitylock-app.svg) ![forks](https://img.shields.io/github/forks/kailashrs/infinitylock-app.svg)


## CVE-2026-86596
 The s2Member plugin for WordPress is vulnerable to Remote Code Execution in all versions up to, and including, = 260927 via the 'item_name' parameter parameter. This is due to insufficient sanitization in strip_php_tags_deep(), which only strips literal '?' sequences, combined with a post-interpolation placeholder cleanup that reassembles a valid '?php' opener after the attacker-controlled value has already been embedded in the email template. This makes it possible for authenticated attackers, with custom-level access and above, to execute code on the server.

- [https://github.com/thiscitze/cve-2026-86596-poc](https://github.com/thiscitze/cve-2026-86596-poc) :  ![starts](https://img.shields.io/github/stars/thiscitze/cve-2026-86596-poc.svg) ![forks](https://img.shields.io/github/forks/thiscitze/cve-2026-86596-poc.svg)


## CVE-2026-82474
 Sudo through 1.9.17p2 fails to apply intercept policy checks to the execveat system call in ptrace-based intercept mode. Users permitted to run specific commands can execute denied programs by calling execveat directly or through fexecve, bypassing policy enforcement and logging.

- [https://github.com/paktiko1986/CVE-2026-82474](https://github.com/paktiko1986/CVE-2026-82474) :  ![starts](https://img.shields.io/github/stars/paktiko1986/CVE-2026-82474.svg) ![forks](https://img.shields.io/github/forks/paktiko1986/CVE-2026-82474.svg)


## CVE-2026-74583
republishing by in-flight readers.

- [https://github.com/santoshkalluri/CVE-2026-74583](https://github.com/santoshkalluri/CVE-2026-74583) :  ![starts](https://img.shields.io/github/stars/santoshkalluri/CVE-2026-74583.svg) ![forks](https://img.shields.io/github/forks/santoshkalluri/CVE-2026-74583.svg)


## CVE-2026-63030
 WordPress 6.9.x before 6.9.5 and 7.0.x before 7.0.2 is affected by a REST API batch endpoint route confusion issue which, combined with the author__not_in WP_Query SQL Injection (CVE-2026-60137), could allow an attacker to perform SQL Injection and achieve Remote Code Execution.

- [https://github.com/l-i-uqing/CVE-2026-63030-wp2shell-repro](https://github.com/l-i-uqing/CVE-2026-63030-wp2shell-repro) :  ![starts](https://img.shields.io/github/stars/l-i-uqing/CVE-2026-63030-wp2shell-repro.svg) ![forks](https://img.shields.io/github/forks/l-i-uqing/CVE-2026-63030-wp2shell-repro.svg)


## CVE-2026-62911
 Authentication bypass by capture-replay in Microsoft Exchange Server allows an authorized attacker to elevate privileges over a network.

- [https://github.com/c5z54/cve-2026-62911-poc](https://github.com/c5z54/cve-2026-62911-poc) :  ![starts](https://img.shields.io/github/stars/c5z54/cve-2026-62911-poc.svg) ![forks](https://img.shields.io/github/forks/c5z54/cve-2026-62911-poc.svg)


## CVE-2026-60137
 WordPress 6.8.x before 6.8.6, 6.9.x before 6.9.5, and 7.0.x before 7.0.2 does not properly sanitise the author__not_in parameter of WP_Query, which could allow SQL Injection when a plugin or theme passes untrusted input to the parameter.

- [https://github.com/l-i-uqing/CVE-2026-63030-wp2shell-repro](https://github.com/l-i-uqing/CVE-2026-63030-wp2shell-repro) :  ![starts](https://img.shields.io/github/stars/l-i-uqing/CVE-2026-63030-wp2shell-repro.svg) ![forks](https://img.shields.io/github/forks/l-i-uqing/CVE-2026-63030-wp2shell-repro.svg)


## CVE-2026-58882
 In decodeWapPdu of WapPushOverSms.java, there is a possible out of bounds read due to an integer overflow. This could lead to a remote denial of service with no additional execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/Ignema/WapGuard](https://github.com/Ignema/WapGuard) :  ![starts](https://img.shields.io/github/stars/Ignema/WapGuard.svg) ![forks](https://img.shields.io/github/forks/Ignema/WapGuard.svg)


## CVE-2026-56190
 Use of uninitialized resource in Windows RDP allows an unauthorized attacker to execute code over a network.

- [https://github.com/danarhirany300-ctrl/CVE-2026-56190-RCE](https://github.com/danarhirany300-ctrl/CVE-2026-56190-RCE) :  ![starts](https://img.shields.io/github/stars/danarhirany300-ctrl/CVE-2026-56190-RCE.svg) ![forks](https://img.shields.io/github/forks/danarhirany300-ctrl/CVE-2026-56190-RCE.svg)


## CVE-2026-53266
before calling skb_store_bits().

- [https://github.com/mc493/kshield](https://github.com/mc493/kshield) :  ![starts](https://img.shields.io/github/stars/mc493/kshield.svg) ![forks](https://img.shields.io/github/forks/mc493/kshield.svg)


## CVE-2026-53157
phonet_address_del() for the same object type.

- [https://github.com/santoshkalluri/CVE-2026-53157](https://github.com/santoshkalluri/CVE-2026-53157) :  ![starts](https://img.shields.io/github/stars/santoshkalluri/CVE-2026-53157.svg) ![forks](https://img.shields.io/github/forks/santoshkalluri/CVE-2026-53157.svg)


## CVE-2026-48907
 A vulnerability in the JCE editor extension for Joomla allows the creation of new editor profiles for unauthenticated users, ultimately resulting in PHP code upload and execution.

- [https://github.com/BastianHxr/CVE-2026-48907](https://github.com/BastianHxr/CVE-2026-48907) :  ![starts](https://img.shields.io/github/stars/BastianHxr/CVE-2026-48907.svg) ![forks](https://img.shields.io/github/forks/BastianHxr/CVE-2026-48907.svg)


## CVE-2026-43499
  	changelog ]

- [https://github.com/tokenbleed/ghostlock-tv](https://github.com/tokenbleed/ghostlock-tv) :  ![starts](https://img.shields.io/github/stars/tokenbleed/ghostlock-tv.svg) ![forks](https://img.shields.io/github/forks/tokenbleed/ghostlock-tv.svg)


## CVE-2026-42945
 NGINX Plus and NGINX Open Source have a vulnerability in the ngx_http_rewrite_module module. This vulnerability exists when the rewrite directive is followed by a rewrite, if, or set directive and an unnamed Perl-Compatible Regular Expression (PCRE) capture (for example, $1, $2) with a replacement string that includes a question mark (?). An unauthenticated attacker along with conditions beyond its control can exploit this vulnerability by sending crafted HTTP requests. This may cause a heap buffer overflow in the NGINX worker process leading to a restart. Additionally, attackers can execute code on systems with Address Space Layout Randomization (ASLR) disabled or when the attacker can bypass ASLR.  Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/basesixtythree/B63-POC-CVE-2026-42945](https://github.com/basesixtythree/B63-POC-CVE-2026-42945) :  ![starts](https://img.shields.io/github/stars/basesixtythree/B63-POC-CVE-2026-42945.svg) ![forks](https://img.shields.io/github/forks/basesixtythree/B63-POC-CVE-2026-42945.svg)


## CVE-2026-40976
Affected: Spring Boot 4.0.0–4.0.5; upgrade to 4.0.6 or later per vendor advisory.

- [https://github.com/madebyrokit/cve_2026_40976](https://github.com/madebyrokit/cve_2026_40976) :  ![starts](https://img.shields.io/github/stars/madebyrokit/cve_2026_40976.svg) ![forks](https://img.shields.io/github/forks/madebyrokit/cve_2026_40976.svg)


## CVE-2026-33439
 Open Access Management (OpenAM) is an access management solution. Prior to 16.0.6, OpenIdentityPlatform OpenAM is vulnerable to pre-authentication Remote Code Execution (RCE) via unsafe Java deserialization of the jato.clientSession HTTP parameter. This bypasses the WhitelistObjectInputStream mitigation that was applied to the jato.pageSession parameter after CVE-2021-35464. An unauthenticated attacker can achieve arbitrary command execution on the server by sending a crafted serialized Java object as the jato.clientSession GET/POST parameter to any JATO ViewBean endpoint whose JSP contains jato:form tags (e.g., the Password Reset pages). This vulnerability is fixed in 16.0.6.

- [https://github.com/stapat1245/CVE-2026-33439_poc](https://github.com/stapat1245/CVE-2026-33439_poc) :  ![starts](https://img.shields.io/github/stars/stapat1245/CVE-2026-33439_poc.svg) ![forks](https://img.shields.io/github/forks/stapat1245/CVE-2026-33439_poc.svg)


## CVE-2026-33186
 gRPC-Go is the Go language implementation of gRPC. Versions prior to 1.79.3 have an authorization bypass resulting from improper input validation of the HTTP/2 `:path` pseudo-header. The gRPC-Go server was too lenient in its routing logic, accepting requests where the `:path` omitted the mandatory leading slash (e.g., `Service/Method` instead of `/Service/Method`). While the server successfully routed these requests to the correct handler, authorization interceptors (including the official `grpc/authz` package) evaluated the raw, non-canonical path string. Consequently, "deny" rules defined using canonical paths (starting with `/`) failed to match the incoming request, allowing it to bypass the policy if a fallback "allow" rule was present. This affects gRPC-Go servers that use path-based authorization interceptors, such as the official RBAC implementation in `google.golang.org/grpc/authz` or custom interceptors relying on `info.FullMethod` or `grpc.Method(ctx)`; AND that have a security policy contains specific "deny" rules for canonical paths but allows other requests by default (a fallback "allow" rule). The vulnerability is exploitable by an attacker who can send raw HTTP/2 frames with malformed `:path` headers directly to the gRPC server. The fix in version 1.79.3 ensures that any request with a `:path` that does not start with a leading slash is immediately rejected with a `codes.Unimplemented` error, preventing it from reaching authorization interceptors or handlers with a non-canonical path string. While upgrading is the most secure and recommended path, users can mitigate the vulnerability using one of the following methods: Use a validating interceptor (recommended mitigation); infrastructure-level normalization; and/or policy hardening.

- [https://github.com/basesixtythree/B63-POC-CVE-2026-33186](https://github.com/basesixtythree/B63-POC-CVE-2026-33186) :  ![starts](https://img.shields.io/github/stars/basesixtythree/B63-POC-CVE-2026-33186.svg) ![forks](https://img.shields.io/github/forks/basesixtythree/B63-POC-CVE-2026-33186.svg)


## CVE-2026-14900
 The Cost Calculator Builder PRO plugin for WordPress is vulnerable to Remote Code Execution in all versions up to, and including, 4.0.3 via the js_to_php function. This is due to insufficient sanitization of the orderDetails[*].originalValue field, which is injected verbatim into a calculator formula string passed to PHP eval() inside js_to_php(), with the regex allow-list in evaluateFormula() only filtering alphanumeric tokens and leaving non-word punctuation characters intact. This makes it possible for unauthenticated attackers to execute code on the server. The only authentication barrier is a nonce check, but the required nonce is publicly emitted on every front-end page via the wp_head hook, making it freely obtainable by unauthenticated visitors. Payloads must be non-word XOR gadgets to bypass sanitization.

- [https://github.com/tenderacer-lgtm/CVE-2026-14900-PoC](https://github.com/tenderacer-lgtm/CVE-2026-14900-PoC) :  ![starts](https://img.shields.io/github/stars/tenderacer-lgtm/CVE-2026-14900-PoC.svg) ![forks](https://img.shields.io/github/forks/tenderacer-lgtm/CVE-2026-14900-PoC.svg)


## CVE-2026-14431
 Type Confusion in V8 in Google Chrome prior to 150.0.7871.46 allowed a remote attacker to execute arbitrary code inside a sandbox via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/djayaGit/CVE-2026-14431](https://github.com/djayaGit/CVE-2026-14431) :  ![starts](https://img.shields.io/github/stars/djayaGit/CVE-2026-14431.svg) ![forks](https://img.shields.io/github/forks/djayaGit/CVE-2026-14431.svg)


## CVE-2026-7882
 Concrete CMS  9.5.0 and below is vulnerable to unauthorized file deletion due to an Inverted CSRF token check in the DeleteFile controller. The code throws an error when the token IS valid and proceeds with file deletion when the token is invalid or missing. This effectively disables CSRF protection for the file deletion endpoint, allowing cross-site request forgery attacks against users who have permission to edit conversation messages. The Concrete CMS security team gave this vulnerability a CVSS v.4.0 score of 2.3 with a vector of CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N. Thanks Tristan Mandani for reporting.

- [https://github.com/saykino/CVE-2026-78823](https://github.com/saykino/CVE-2026-78823) :  ![starts](https://img.shields.io/github/stars/saykino/CVE-2026-78823.svg) ![forks](https://img.shields.io/github/forks/saykino/CVE-2026-78823.svg)


## CVE-2026-4349
 A vulnerability was determined in Duende IdentityServer4 up to 4.1.2. The affected element is an unknown function of the file /connect/authorize of the component Token Renewal Endpoint. This manipulation of the argument id_token_hint causes improper authentication. It is possible to initiate the attack remotely. The attack is considered to have high complexity. The exploitability is described as difficult. This vulnerability only affects products that are no longer supported by the maintainer.

- [https://github.com/shubhampathak65/CVE-2026-43499](https://github.com/shubhampathak65/CVE-2026-43499) :  ![starts](https://img.shields.io/github/stars/shubhampathak65/CVE-2026-43499.svg) ![forks](https://img.shields.io/github/forks/shubhampathak65/CVE-2026-43499.svg)


## CVE-2026-1096
 The Best-wp-google-map plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the 'latitude' and 'longitudinal' parameters of the 'google_map_view' shortcode in all versions up to, and including, 2.1 due to insufficient input sanitization and output escaping. This makes it possible for authenticated attackers, with Contributor-level access and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.

- [https://github.com/1Nightlovel/CVE-2026-109618](https://github.com/1Nightlovel/CVE-2026-109618) :  ![starts](https://img.shields.io/github/stars/1Nightlovel/CVE-2026-109618.svg) ![forks](https://img.shields.io/github/forks/1Nightlovel/CVE-2026-109618.svg)
- [https://github.com/zhaoboy9692/CVE-2026-109618_](https://github.com/zhaoboy9692/CVE-2026-109618_) :  ![starts](https://img.shields.io/github/stars/zhaoboy9692/CVE-2026-109618_.svg) ![forks](https://img.shields.io/github/forks/zhaoboy9692/CVE-2026-109618_.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package.svg)


## CVE-2025-46673
 NASA CryptoLib before 1.3.2 does not check whether the SA is in an operational state before use, possibly leading to a bypass of the Space Data Link Security protocol (SDLS).

- [https://github.com/spookier/NASA-CryptoLib-SDLS-Bypass](https://github.com/spookier/NASA-CryptoLib-SDLS-Bypass) :  ![starts](https://img.shields.io/github/stars/spookier/NASA-CryptoLib-SDLS-Bypass.svg) ![forks](https://img.shields.io/github/forks/spookier/NASA-CryptoLib-SDLS-Bypass.svg)


## CVE-2025-41450
 Improper Authentication vulnerability in Danfoss AKSM8xxA Series.This issue affects Danfoss AK-SM 8xxA Series prior to version 4.2

- [https://github.com/GabrieleDattile/CVE-2025-41450-Fromagegate](https://github.com/GabrieleDattile/CVE-2025-41450-Fromagegate) :  ![starts](https://img.shields.io/github/stars/GabrieleDattile/CVE-2025-41450-Fromagegate.svg) ![forks](https://img.shields.io/github/forks/GabrieleDattile/CVE-2025-41450-Fromagegate.svg)


## CVE-2025-32433
 Erlang/OTP is a set of libraries for the Erlang programming language. Prior to versions OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20, a SSH server may allow an attacker to perform unauthenticated remote code execution (RCE). By exploiting a flaw in SSH protocol message handling, a malicious actor could gain unauthorized access to affected systems and execute arbitrary commands without valid credentials. This issue is patched in versions OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20. A temporary workaround involves disabling the SSH server or to prevent access via firewall rules.

- [https://github.com/Avinash37402/CVE-2025-32433](https://github.com/Avinash37402/CVE-2025-32433) :  ![starts](https://img.shields.io/github/stars/Avinash37402/CVE-2025-32433.svg) ![forks](https://img.shields.io/github/forks/Avinash37402/CVE-2025-32433.svg)
- [https://github.com/Avinash37402/CVE-2025-32433-Erlang-OTP-SSH](https://github.com/Avinash37402/CVE-2025-32433-Erlang-OTP-SSH) :  ![starts](https://img.shields.io/github/stars/Avinash37402/CVE-2025-32433-Erlang-OTP-SSH.svg) ![forks](https://img.shields.io/github/forks/Avinash37402/CVE-2025-32433-Erlang-OTP-SSH.svg)


## CVE-2025-24054
 External control of file name or path in Windows NTLM allows an unauthorized attacker to perform spoofing over a network.

- [https://github.com/nexus956/CVE-2025-24054-PoC](https://github.com/nexus956/CVE-2025-24054-PoC) :  ![starts](https://img.shields.io/github/stars/nexus956/CVE-2025-24054-PoC.svg) ![forks](https://img.shields.io/github/forks/nexus956/CVE-2025-24054-PoC.svg)


## CVE-2025-8110
 Improper Symbolic link handling in the PutContents API in Gogs allows Local Execution of Code.

- [https://github.com/godylockz/CVE-2025-8110](https://github.com/godylockz/CVE-2025-8110) :  ![starts](https://img.shields.io/github/stars/godylockz/CVE-2025-8110.svg) ![forks](https://img.shields.io/github/forks/godylockz/CVE-2025-8110.svg)


## CVE-2025-6647
The specific flaw exists within the parsing of U3D files. The issue results from the lack of proper validation of user-supplied data, which can result in a write past the end of an allocated object. An attacker can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-26644.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions.svg)


## CVE-2024-10441
 Improper encoding or escaping of output vulnerability in the system plugin daemon in Synology BeeStation OS (BSM) before 1.1-65374 and Synology DiskStation Manager (DSM) before 7.2-64570-4, 7.2.1-69057-6 and 7.2.2-72806-1 allows remote attackers to execute arbitrary code via unspecified vectors.

- [https://github.com/MRdark-ops/scanner-syno](https://github.com/MRdark-ops/scanner-syno) :  ![starts](https://img.shields.io/github/stars/MRdark-ops/scanner-syno.svg) ![forks](https://img.shields.io/github/forks/MRdark-ops/scanner-syno.svg)


## CVE-2024-4367
 A type check was missing when handling fonts in PDF.js, which would allow arbitrary JavaScript execution in the PDF.js context. This vulnerability affects Firefox  126, Firefox ESR  115.11, and Thunderbird  115.11.

- [https://github.com/minhi1/CVE-2024-4367](https://github.com/minhi1/CVE-2024-4367) :  ![starts](https://img.shields.io/github/stars/minhi1/CVE-2024-4367.svg) ![forks](https://img.shields.io/github/forks/minhi1/CVE-2024-4367.svg)


## CVE-2024-3094
Through a series of complex obfuscations, the liblzma build process extracts a prebuilt object file from a disguised test file existing in the source code, which is then used to modify specific functions in the liblzma code. This results in a modified liblzma library that can be used by any software linked against this library, intercepting and modifying the data interaction with this library.

- [https://github.com/mcpmark-eval-liuhezi/log4j-xz-lessons](https://github.com/mcpmark-eval-liuhezi/log4j-xz-lessons) :  ![starts](https://img.shields.io/github/stars/mcpmark-eval-liuhezi/log4j-xz-lessons.svg) ![forks](https://img.shields.io/github/forks/mcpmark-eval-liuhezi/log4j-xz-lessons.svg)


## CVE-2024-1086
We recommend upgrading past commit f342de4e2f33e0e39165d8639387aa6c19dff660.

- [https://github.com/mc493/kshield](https://github.com/mc493/kshield) :  ![starts](https://img.shields.io/github/stars/mc493/kshield.svg) ![forks](https://img.shields.io/github/forks/mc493/kshield.svg)


## CVE-2023-34634
 Greenshot 1.2.10 and below allows arbitrary code execution because .NET content is insecurely deserialized when a .greenshot file is opened.

- [https://github.com/LBVDSEC/GreenshotShell-CVE-2023-34634](https://github.com/LBVDSEC/GreenshotShell-CVE-2023-34634) :  ![starts](https://img.shields.io/github/stars/LBVDSEC/GreenshotShell-CVE-2023-34634.svg) ![forks](https://img.shields.io/github/forks/LBVDSEC/GreenshotShell-CVE-2023-34634.svg)


## CVE-2023-29017
 vm2 is a sandbox that can run untrusted code with whitelisted Node's built-in modules. Prior to version 3.9.15, vm2 was not properly handling host objects passed to `Error.prepareStackTrace` in case of unhandled async errors. A threat actor could bypass the sandbox protections to gain remote code execution rights on the host running the sandbox. This vulnerability was patched in the release of version 3.9.15 of vm2. There are no known workarounds.

- [https://github.com/wooung105/Node_CVE-2023-29017](https://github.com/wooung105/Node_CVE-2023-29017) :  ![starts](https://img.shields.io/github/stars/wooung105/Node_CVE-2023-29017.svg) ![forks](https://img.shields.io/github/forks/wooung105/Node_CVE-2023-29017.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/0xrogg/CVE-2021-41773](https://github.com/0xrogg/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/0xrogg/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/0xrogg/CVE-2021-41773.svg)


## CVE-2021-4422
 The POST SMTP Mailer plugin for WordPress is vulnerable to Cross-Site Request Forgery in versions up to, and including, 2.0.20. This is due to missing or incorrect nonce validation on the handleCsvExport() function. This makes it possible for unauthenticated attackers to trigger a CSV export via a forged request granted they can trick a site administrator into performing an action such as clicking on a link.

- [https://github.com/Super-Binary/cve-2021-44228](https://github.com/Super-Binary/cve-2021-44228) :  ![starts](https://img.shields.io/github/stars/Super-Binary/cve-2021-44228.svg) ![forks](https://img.shields.io/github/forks/Super-Binary/cve-2021-44228.svg)


## CVE-2021-4177
 livehelperchat is vulnerable to Generation of Error Message Containing Sensitive Information

- [https://github.com/LayarKacaSiber/CVE-2021-41773](https://github.com/LayarKacaSiber/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/LayarKacaSiber/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/LayarKacaSiber/CVE-2021-41773.svg)
- [https://github.com/gunzf0x/CVE-2021-41773](https://github.com/gunzf0x/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/gunzf0x/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/gunzf0x/CVE-2021-41773.svg)
- [https://github.com/sotiak/CVE-2021-41773](https://github.com/sotiak/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/sotiak/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/sotiak/CVE-2021-41773.svg)


## CVE-2021-3156
 Sudo before 1.9.5p2 contains an off-by-one error that can result in a heap-based buffer overflow, which allows privilege escalation to root via "sudoedit -s" and a command-line argument that ends with a single backslash character.

- [https://github.com/AmroYasserH/DFIR-CVE-2021-3156-Incident-Response](https://github.com/AmroYasserH/DFIR-CVE-2021-3156-Incident-Response) :  ![starts](https://img.shields.io/github/stars/AmroYasserH/DFIR-CVE-2021-3156-Incident-Response.svg) ![forks](https://img.shields.io/github/forks/AmroYasserH/DFIR-CVE-2021-3156-Incident-Response.svg)


## CVE-2017-5689
 An unprivileged network attacker could gain system privileges to provisioned Intel manageability SKUs: Intel Active Management Technology (AMT) and Intel Standard Manageability (ISM). An unprivileged local attacker could provision manageability features gaining unprivileged network or local system privileges on Intel manageability SKUs: Intel Active Management Technology (AMT), Intel Standard Manageability (ISM), and Intel Small Business Technology (SBT).

- [https://github.com/unitnikolai/intel-me-remote-exploit](https://github.com/unitnikolai/intel-me-remote-exploit) :  ![starts](https://img.shields.io/github/stars/unitnikolai/intel-me-remote-exploit.svg) ![forks](https://img.shields.io/github/forks/unitnikolai/intel-me-remote-exploit.svg)

