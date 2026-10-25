# Update 2026-10-25
## CVE-2026-114509
 Laravel is a web application framework. Prior to 12.68.0 and 13.29.0, TokenGuard configured as a standard token-based API guard does not reject a crafted non-string credential. Under affected MySQL or MariaDB configurations, the authentication lookup can match an unintended existing user, allowing an unauthenticated attacker to bypass authentication and take over an account on routes protected by TokenGuard. This issue is fixed in versions 12.68.0 and 13.29.0.

- [https://github.com/hakaioffsec/CVE-2026-114509-PoC](https://github.com/hakaioffsec/CVE-2026-114509-PoC) :  ![starts](https://img.shields.io/github/stars/hakaioffsec/CVE-2026-114509-PoC.svg) ![forks](https://img.shields.io/github/forks/hakaioffsec/CVE-2026-114509-PoC.svg)


## CVE-2026-113872
 multer is a middleware for Node.js that handles multipart/form-data file uploads. In versions from 2.0.0 before 2.5.0, when multer is configured with an asynchronous fileFilter, a single request can crash the Node.js process. If the request is aborted while one file's asynchronous fileFilter is still pending, the pending callback later resumes a parsing stream that multer has already torn down, and the underlying parser emits an error on a stream that no longer has an error listener, which Node raises as an unhandled error event so the process exits. Any application using multer with an asynchronous fileFilter is affected regardless of storage engine, while uploads using a synchronous fileFilter are not affected. The issue is fixed in multer 2.5.0, and users should upgrade to 2.5.0 or later. As a workaround, use a synchronous fileFilter.

- [https://github.com/santihabib/multer-CVE-2026-113872](https://github.com/santihabib/multer-CVE-2026-113872) :  ![starts](https://img.shields.io/github/stars/santihabib/multer-CVE-2026-113872.svg) ![forks](https://img.shields.io/github/forks/santihabib/multer-CVE-2026-113872.svg)


## CVE-2026-112900
 Pillow is a Python imaging library. From 2.6.0 until 13.0.0, Pillow is vulnerable to argument injection when invoking Ghostscript for EPS input. EpsImagePlugin.Ghostscript passes a caller-controlled input filename after -f without converting it to a safe absolute path, so a name beginning with a hyphen can be interpreted as a Ghostscript option. An attacker who controls the filename can inject Ghostscript arguments. Arbitrary command execution specifically requires a leading @ argument-file filename and control of the referenced text file containing additional Ghostscript arguments; the reported chain reproduces with the default -dSAFER invocation. This issue is fixed in version 13.0.0.

- [https://github.com/techupdate24/python-pillow-rce-cve-2026-112900](https://github.com/techupdate24/python-pillow-rce-cve-2026-112900) :  ![starts](https://img.shields.io/github/stars/techupdate24/python-pillow-rce-cve-2026-112900.svg) ![forks](https://img.shields.io/github/forks/techupdate24/python-pillow-rce-cve-2026-112900.svg)


## CVE-2026-112403
 Pillow is a Python imaging library. Prior to 13.0.0, Pillow's JPEG decoder can write a full-width scanline into a buffer sized for a requested draft scale. ImagingJpegDecode does not verify libjpeg's actual output width and component count after scaling is requested, and an 8-bit lossless SOF3 JPEG decoded by a build linked to libjpeg-turbo 3.x can ignore the requested downscaling geometry. An attacker can supply such a JPEG to an application that uses draft() or thumbnail() to request downscaling. This can corrupt heap memory, crash the process, or potentially allow code execution. Older libjpeg-turbo 2.x and IJG builds reject the SOF3 input. This issue is fixed in version 13.0.0.

- [https://github.com/al4n4n/CVE-2026-112403](https://github.com/al4n4n/CVE-2026-112403) :  ![starts](https://img.shields.io/github/stars/al4n4n/CVE-2026-112403.svg) ![forks](https://img.shields.io/github/forks/al4n4n/CVE-2026-112403.svg)


## CVE-2026-112398
 Pillow is a Python imaging library. Prior to 13.0.0, Pillow's FlashPix JPEG-tile decoder can write decoded scanlines beyond the allocated tile buffer. FlashPix (FPX) JPEG decoding selects raw mode LA with two bytes per pixel, while an unrecognized JPEG mode can be decoded as JCS_UNKNOWN with four components, causing ImagingJpegDecode to write four-component scanlines into the two-byte tile buffer. An attacker can supply a crafted OLE2 FlashPix file to an application with the optional olefile dependency installed that opens or thumbnails untrusted input. This can corrupt heap memory and may allow arbitrary code execution. This issue is fixed in version 13.0.0.

- [https://github.com/mcpmark-eval-liuhezi/security-advisory-research](https://github.com/mcpmark-eval-liuhezi/security-advisory-research) :  ![starts](https://img.shields.io/github/stars/mcpmark-eval-liuhezi/security-advisory-research.svg) ![forks](https://img.shields.io/github/forks/mcpmark-eval-liuhezi/security-advisory-research.svg)


## CVE-2026-111943
 On most platforms, Go uses the given system root certificates. However, in some narrower cases, the system trust stores may not be updated without further action. To defend against the narrower set of cases that may remain affected, a denylist was added in crypto/x509 to return an error when calling Verify with any of the known intermediate certificates that are no longer considered to be trustworthy.

- [https://github.com/Xowap/i-can-count-to-four](https://github.com/Xowap/i-can-count-to-four) :  ![starts](https://img.shields.io/github/stars/Xowap/i-can-count-to-four.svg) ![forks](https://img.shields.io/github/forks/Xowap/i-can-count-to-four.svg)


## CVE-2026-111497
Users need to update any Brotli libraries or binaries between 1.0.3 through 1.2.0 to the latest available version: 1.0.10 or 1.1.1 or 1.2.1.

- [https://github.com/ZeroHackOrg/node2shell-poc](https://github.com/ZeroHackOrg/node2shell-poc) :  ![starts](https://img.shields.io/github/stars/ZeroHackOrg/node2shell-poc.svg) ![forks](https://img.shields.io/github/forks/ZeroHackOrg/node2shell-poc.svg)
- [https://github.com/shivrajem/node2shell-detect](https://github.com/shivrajem/node2shell-detect) :  ![starts](https://img.shields.io/github/stars/shivrajem/node2shell-detect.svg) ![forks](https://img.shields.io/github/forks/shivrajem/node2shell-detect.svg)
- [https://github.com/w116tjb/CVE-2026-111497_nodejs_hash_lookup](https://github.com/w116tjb/CVE-2026-111497_nodejs_hash_lookup) :  ![starts](https://img.shields.io/github/stars/w116tjb/CVE-2026-111497_nodejs_hash_lookup.svg) ![forks](https://img.shields.io/github/forks/w116tjb/CVE-2026-111497_nodejs_hash_lookup.svg)
- [https://github.com/trailofbits/brotli-checker](https://github.com/trailofbits/brotli-checker) :  ![starts](https://img.shields.io/github/stars/trailofbits/brotli-checker.svg) ![forks](https://img.shields.io/github/forks/trailofbits/brotli-checker.svg)
- [https://github.com/Arkango/CVE-2026-111497](https://github.com/Arkango/CVE-2026-111497) :  ![starts](https://img.shields.io/github/stars/Arkango/CVE-2026-111497.svg) ![forks](https://img.shields.io/github/forks/Arkango/CVE-2026-111497.svg)
- [https://github.com/Saturate/CVE-2026-111497](https://github.com/Saturate/CVE-2026-111497) :  ![starts](https://img.shields.io/github/stars/Saturate/CVE-2026-111497.svg) ![forks](https://img.shields.io/github/forks/Saturate/CVE-2026-111497.svg)
- [https://github.com/duytien241/nodejs-CVE-2026-111497](https://github.com/duytien241/nodejs-CVE-2026-111497) :  ![starts](https://img.shields.io/github/stars/duytien241/nodejs-CVE-2026-111497.svg) ![forks](https://img.shields.io/github/forks/duytien241/nodejs-CVE-2026-111497.svg)
- [https://github.com/Ghost-Bx1/Node2Shell-CVE-2026-111497](https://github.com/Ghost-Bx1/Node2Shell-CVE-2026-111497) :  ![starts](https://img.shields.io/github/stars/Ghost-Bx1/Node2Shell-CVE-2026-111497.svg) ![forks](https://img.shields.io/github/forks/Ghost-Bx1/Node2Shell-CVE-2026-111497.svg)
- [https://github.com/fuzheado/n2s-buildpack-probe](https://github.com/fuzheado/n2s-buildpack-probe) :  ![starts](https://img.shields.io/github/stars/fuzheado/n2s-buildpack-probe.svg) ![forks](https://img.shields.io/github/forks/fuzheado/n2s-buildpack-probe.svg)
- [https://github.com/AmanSin001/node-brotli-check](https://github.com/AmanSin001/node-brotli-check) :  ![starts](https://img.shields.io/github/stars/AmanSin001/node-brotli-check.svg) ![forks](https://img.shields.io/github/forks/AmanSin001/node-brotli-check.svg)
- [https://github.com/CompleteTech-LLC/node2shell-check](https://github.com/CompleteTech-LLC/node2shell-check) :  ![starts](https://img.shields.io/github/stars/CompleteTech-LLC/node2shell-check.svg) ![forks](https://img.shields.io/github/forks/CompleteTech-LLC/node2shell-check.svg)
- [https://github.com/TahuCryptsi/brotli-distro-check](https://github.com/TahuCryptsi/brotli-distro-check) :  ![starts](https://img.shields.io/github/stars/TahuCryptsi/brotli-distro-check.svg) ![forks](https://img.shields.io/github/forks/TahuCryptsi/brotli-distro-check.svg)
- [https://github.com/Charlie-Netdevops/node-hostcheck](https://github.com/Charlie-Netdevops/node-hostcheck) :  ![starts](https://img.shields.io/github/stars/Charlie-Netdevops/node-hostcheck.svg) ![forks](https://img.shields.io/github/forks/Charlie-Netdevops/node-hostcheck.svg)
- [https://github.com/CodeDotJS/pwn.pied](https://github.com/CodeDotJS/pwn.pied) :  ![starts](https://img.shields.io/github/stars/CodeDotJS/pwn.pied.svg) ![forks](https://img.shields.io/github/forks/CodeDotJS/pwn.pied.svg)
- [https://github.com/malikad778/php2shell-guard](https://github.com/malikad778/php2shell-guard) :  ![starts](https://img.shields.io/github/stars/malikad778/php2shell-guard.svg) ![forks](https://img.shields.io/github/forks/malikad778/php2shell-guard.svg)


## CVE-2026-110447
 Collabora Online Built-in CODE Server before 26.4.303 (richdocumentscode), a Nextcloud app, allows remote code execution, as exploited in the wild in September and October 2026, a different vulnerability than CVE-2025-66208. This is an OS command injection in proxy.php when the CODE server isn't running (e.g., the product was recently restarted). The vulnerability is not present in standalone Collabora Online servers; only this deployment with CODE Server is affected.

- [https://github.com/sstrobl-osm/php2shell-tools](https://github.com/sstrobl-osm/php2shell-tools) :  ![starts](https://img.shields.io/github/stars/sstrobl-osm/php2shell-tools.svg) ![forks](https://img.shields.io/github/forks/sstrobl-osm/php2shell-tools.svg)


## CVE-2026-110264
 An issue has been discovered in GitLab CE/EE affecting all versions from 7.0 before 18.11.13, 19.0 before 19.0.10, 19.1 before 19.1.9, 19.2 before 19.2.9, 19.3 before 19.3.6, 19.4 before 19.4.3, and 19.5 before 19.5.1 that, under certain conditions, could have allowed an unauthenticated user to execute arbitrary code on the GitLab server due to integer overflow when compiling a specially crafted regular expression.

- [https://github.com/al4n4n/CVE-2026-110264](https://github.com/al4n4n/CVE-2026-110264) :  ![starts](https://img.shields.io/github/stars/al4n4n/CVE-2026-110264.svg) ![forks](https://img.shields.io/github/forks/al4n4n/CVE-2026-110264.svg)
- [https://github.com/lesterlam/onigmo-cve-2026-110264](https://github.com/lesterlam/onigmo-cve-2026-110264) :  ![starts](https://img.shields.io/github/stars/lesterlam/onigmo-cve-2026-110264.svg) ![forks](https://img.shields.io/github/forks/lesterlam/onigmo-cve-2026-110264.svg)
- [https://github.com/bastet-ai/gitlab-firing-range](https://github.com/bastet-ai/gitlab-firing-range) :  ![starts](https://img.shields.io/github/stars/bastet-ai/gitlab-firing-range.svg) ![forks](https://img.shields.io/github/forks/bastet-ai/gitlab-firing-range.svg)
- [https://github.com/TheGlitchFixer/gitlab-patch-check](https://github.com/TheGlitchFixer/gitlab-patch-check) :  ![starts](https://img.shields.io/github/stars/TheGlitchFixer/gitlab-patch-check.svg) ![forks](https://img.shields.io/github/forks/TheGlitchFixer/gitlab-patch-check.svg)
- [https://github.com/farimazhar/GitLab2Safe-Defensive-Checker](https://github.com/farimazhar/GitLab2Safe-Defensive-Checker) :  ![starts](https://img.shields.io/github/stars/farimazhar/GitLab2Safe-Defensive-Checker.svg) ![forks](https://img.shields.io/github/forks/farimazhar/GitLab2Safe-Defensive-Checker.svg)


## CVE-2026-109715
 Incorrect boundary conditions in the JavaScript Engine component. This vulnerability was fixed in Firefox 158, Firefox ESR 115.43, Firefox ESR 153.5, Thunderbird 158, and Thunderbird 153.5.

- [https://github.com/Scyrix-LLC/CVE-2026-109715](https://github.com/Scyrix-LLC/CVE-2026-109715) :  ![starts](https://img.shields.io/github/stars/Scyrix-LLC/CVE-2026-109715.svg) ![forks](https://img.shields.io/github/forks/Scyrix-LLC/CVE-2026-109715.svg)


## CVE-2026-109619
 PHP has various global state that temporarily points into request memory. In some scenarios, global state may not be correctly reset, or may be repopulated after being reset. The global state may then refer to request memory even after it has been freed. Subsequent requests may read or branch on this stale state before it is fully initialized. Multiple strategies can trigger this condition and produce remote code execution (RCE).

- [https://github.com/aarsaputra/php2shell](https://github.com/aarsaputra/php2shell) :  ![starts](https://img.shields.io/github/stars/aarsaputra/php2shell.svg) ![forks](https://img.shields.io/github/forks/aarsaputra/php2shell.svg)
- [https://github.com/bahartanir/php2shell](https://github.com/bahartanir/php2shell) :  ![starts](https://img.shields.io/github/stars/bahartanir/php2shell.svg) ![forks](https://img.shields.io/github/forks/bahartanir/php2shell.svg)
- [https://github.com/MRdark-ops/php2shell](https://github.com/MRdark-ops/php2shell) :  ![starts](https://img.shields.io/github/stars/MRdark-ops/php2shell.svg) ![forks](https://img.shields.io/github/forks/MRdark-ops/php2shell.svg)
- [https://github.com/umair-aziz025/PHP2Shell](https://github.com/umair-aziz025/PHP2Shell) :  ![starts](https://img.shields.io/github/stars/umair-aziz025/PHP2Shell.svg) ![forks](https://img.shields.io/github/forks/umair-aziz025/PHP2Shell.svg)
- [https://github.com/brentmartinmiller/php2shell-check](https://github.com/brentmartinmiller/php2shell-check) :  ![starts](https://img.shields.io/github/stars/brentmartinmiller/php2shell-check.svg) ![forks](https://img.shields.io/github/forks/brentmartinmiller/php2shell-check.svg)
- [https://github.com/wemio/php2shell-scan](https://github.com/wemio/php2shell-scan) :  ![starts](https://img.shields.io/github/stars/wemio/php2shell-scan.svg) ![forks](https://img.shields.io/github/forks/wemio/php2shell-scan.svg)
- [https://github.com/SPOTWHALE/php2shell-check](https://github.com/SPOTWHALE/php2shell-check) :  ![starts](https://img.shields.io/github/stars/SPOTWHALE/php2shell-check.svg) ![forks](https://img.shields.io/github/forks/SPOTWHALE/php2shell-check.svg)
- [https://github.com/cereZ23/php-up-2026](https://github.com/cereZ23/php-up-2026) :  ![starts](https://img.shields.io/github/stars/cereZ23/php-up-2026.svg) ![forks](https://img.shields.io/github/forks/cereZ23/php-up-2026.svg)
- [https://github.com/TheFool-TAROT/php2shell-lab](https://github.com/TheFool-TAROT/php2shell-lab) :  ![starts](https://img.shields.io/github/stars/TheFool-TAROT/php2shell-lab.svg) ![forks](https://img.shields.io/github/forks/TheFool-TAROT/php2shell-lab.svg)
- [https://github.com/the-berlin/bitrixvm-php-hotfix](https://github.com/the-berlin/bitrixvm-php-hotfix) :  ![starts](https://img.shields.io/github/stars/the-berlin/bitrixvm-php-hotfix.svg) ![forks](https://img.shields.io/github/forks/the-berlin/bitrixvm-php-hotfix.svg)
- [https://github.com/gkwelding/php2shell-ioc-check](https://github.com/gkwelding/php2shell-ioc-check) :  ![starts](https://img.shields.io/github/stars/gkwelding/php2shell-ioc-check.svg) ![forks](https://img.shields.io/github/forks/gkwelding/php2shell-ioc-check.svg)
- [https://github.com/PHPatch/phpscan](https://github.com/PHPatch/phpscan) :  ![starts](https://img.shields.io/github/stars/PHPatch/phpscan.svg) ![forks](https://img.shields.io/github/forks/PHPatch/phpscan.svg)
- [https://github.com/CompleteTech-LLC/php2shell-check](https://github.com/CompleteTech-LLC/php2shell-check) :  ![starts](https://img.shields.io/github/stars/CompleteTech-LLC/php2shell-check.svg) ![forks](https://img.shields.io/github/forks/CompleteTech-LLC/php2shell-check.svg)
- [https://github.com/kunshdeep2812/php2shell-scanner](https://github.com/kunshdeep2812/php2shell-scanner) :  ![starts](https://img.shields.io/github/stars/kunshdeep2812/php2shell-scanner.svg) ![forks](https://img.shields.io/github/forks/kunshdeep2812/php2shell-scanner.svg)
- [https://github.com/EXT-IT/php2shell-check](https://github.com/EXT-IT/php2shell-check) :  ![starts](https://img.shields.io/github/stars/EXT-IT/php2shell-check.svg) ![forks](https://img.shields.io/github/forks/EXT-IT/php2shell-check.svg)
- [https://github.com/taniungou/php2shell-lab](https://github.com/taniungou/php2shell-lab) :  ![starts](https://img.shields.io/github/stars/taniungou/php2shell-lab.svg) ![forks](https://img.shields.io/github/forks/taniungou/php2shell-lab.svg)
- [https://github.com/KyleClouthier/php2shell-action](https://github.com/KyleClouthier/php2shell-action) :  ![starts](https://img.shields.io/github/stars/KyleClouthier/php2shell-action.svg) ![forks](https://img.shields.io/github/forks/KyleClouthier/php2shell-action.svg)


## CVE-2026-109618
 PHP uses longjmp() for out-of-memory (OOM) errors to exit the current context and abort handling of the request. Some contexts may not properly account for this scenario and leave request memory in an uninitialized state before performing an allocation. The subsequent request cleanup procedure may read or branch on this memory. Multiple OOM strategies can consistently trigger this condition and lead to remote code execution (RCE).

- [https://github.com/bahartanir/php2shell](https://github.com/bahartanir/php2shell) :  ![starts](https://img.shields.io/github/stars/bahartanir/php2shell.svg) ![forks](https://img.shields.io/github/forks/bahartanir/php2shell.svg)
- [https://github.com/Continuum-AI-Corp/orcacyber-php2shell-research](https://github.com/Continuum-AI-Corp/orcacyber-php2shell-research) :  ![starts](https://img.shields.io/github/stars/Continuum-AI-Corp/orcacyber-php2shell-research.svg) ![forks](https://img.shields.io/github/forks/Continuum-AI-Corp/orcacyber-php2shell-research.svg)
- [https://github.com/MRdark-ops/php2shell](https://github.com/MRdark-ops/php2shell) :  ![starts](https://img.shields.io/github/stars/MRdark-ops/php2shell.svg) ![forks](https://img.shields.io/github/forks/MRdark-ops/php2shell.svg)
- [https://github.com/cseelhoff-ms/php2shell-hunting-pack](https://github.com/cseelhoff-ms/php2shell-hunting-pack) :  ![starts](https://img.shields.io/github/stars/cseelhoff-ms/php2shell-hunting-pack.svg) ![forks](https://img.shields.io/github/forks/cseelhoff-ms/php2shell-hunting-pack.svg)
- [https://github.com/umair-aziz025/PHP2Shell](https://github.com/umair-aziz025/PHP2Shell) :  ![starts](https://img.shields.io/github/stars/umair-aziz025/PHP2Shell.svg) ![forks](https://img.shields.io/github/forks/umair-aziz025/PHP2Shell.svg)
- [https://github.com/brentmartinmiller/php2shell-check](https://github.com/brentmartinmiller/php2shell-check) :  ![starts](https://img.shields.io/github/stars/brentmartinmiller/php2shell-check.svg) ![forks](https://img.shields.io/github/forks/brentmartinmiller/php2shell-check.svg)
- [https://github.com/Taz1920/php-sentinel](https://github.com/Taz1920/php-sentinel) :  ![starts](https://img.shields.io/github/stars/Taz1920/php-sentinel.svg) ![forks](https://img.shields.io/github/forks/Taz1920/php-sentinel.svg)
- [https://github.com/pax-k/Php2Shell-POC](https://github.com/pax-k/Php2Shell-POC) :  ![starts](https://img.shields.io/github/stars/pax-k/Php2Shell-POC.svg) ![forks](https://img.shields.io/github/forks/pax-k/Php2Shell-POC.svg)
- [https://github.com/deconstruction/EOLphp-php2shell-patches](https://github.com/deconstruction/EOLphp-php2shell-patches) :  ![starts](https://img.shields.io/github/stars/deconstruction/EOLphp-php2shell-patches.svg) ![forks](https://img.shields.io/github/forks/deconstruction/EOLphp-php2shell-patches.svg)
- [https://github.com/wemio/php2shell-scan](https://github.com/wemio/php2shell-scan) :  ![starts](https://img.shields.io/github/stars/wemio/php2shell-scan.svg) ![forks](https://img.shields.io/github/forks/wemio/php2shell-scan.svg)
- [https://github.com/SPOTWHALE/php2shell-check](https://github.com/SPOTWHALE/php2shell-check) :  ![starts](https://img.shields.io/github/stars/SPOTWHALE/php2shell-check.svg) ![forks](https://img.shields.io/github/forks/SPOTWHALE/php2shell-check.svg)


## CVE-2026-109613
 Frappe ERPNext before 15.121.0 and 16.x before 16.34.0 contains a missing authorization vulnerability in which certain endpoints fail to enforce proper authorization checks on document status modification. Authenticated low-privileged users can call these endpoints to modify data beyond their permitted role, bypassing intended role-based access restrictions.

- [https://github.com/NeoArtemis37/PHP2shell](https://github.com/NeoArtemis37/PHP2shell) :  ![starts](https://img.shields.io/github/stars/NeoArtemis37/PHP2shell.svg) ![forks](https://img.shields.io/github/forks/NeoArtemis37/PHP2shell.svg)


## CVE-2026-108983
 A vulnerability is in Web Server default connection ports under the process name GeoWebServer.exe .

- [https://github.com/Zombie-Kaiser/CVE-2026-108983](https://github.com/Zombie-Kaiser/CVE-2026-108983) :  ![starts](https://img.shields.io/github/stars/Zombie-Kaiser/CVE-2026-108983.svg) ![forks](https://img.shields.io/github/forks/Zombie-Kaiser/CVE-2026-108983.svg)


## CVE-2026-108551
 openapi-typescript-codegen through 0.31.0 contains a code injection vulnerability that allows attackers controlling an OpenAPI document to inject JavaScript by supplying unescaped values interpolated into single-quoted string literals. Attackers can embed a single quote in path keys, parameter names, servers[0].url, or info.version to execute arbitrary JavaScript when generated clients are imported or service methods called.

- [https://github.com/Zombie-Kaiser/CVE-2026-108551-POC](https://github.com/Zombie-Kaiser/CVE-2026-108551-POC) :  ![starts](https://img.shields.io/github/stars/Zombie-Kaiser/CVE-2026-108551-POC.svg) ![forks](https://img.shields.io/github/forks/Zombie-Kaiser/CVE-2026-108551-POC.svg)


## CVE-2026-106173
 A improper limitation of a pathname to a restricted directory ('path traversal') vulnerability in Fortinet FortiSIEM 7.5.0 may allow attacker to execute unauthorized code or commands via specially crafted packets.

- [https://github.com/MRdark-ops/rce-FortiSIEM](https://github.com/MRdark-ops/rce-FortiSIEM) :  ![starts](https://img.shields.io/github/stars/MRdark-ops/rce-FortiSIEM.svg) ![forks](https://img.shields.io/github/forks/MRdark-ops/rce-FortiSIEM.svg)


## CVE-2026-106074
This vulnerability affects Node.js **26.x**, **24.x**, and **22.x**.

- [https://github.com/CompleteTech-LLC/node-cve-2026-106074-check](https://github.com/CompleteTech-LLC/node-cve-2026-106074-check) :  ![starts](https://img.shields.io/github/stars/CompleteTech-LLC/node-cve-2026-106074-check.svg) ![forks](https://img.shields.io/github/forks/CompleteTech-LLC/node-cve-2026-106074-check.svg)


## CVE-2026-106073
This vulnerability affects Node.js **26.x**, **24.x**, and **22.x**.

- [https://github.com/CompleteTech-LLC/node-cve-2026-106073-check](https://github.com/CompleteTech-LLC/node-cve-2026-106073-check) :  ![starts](https://img.shields.io/github/stars/CompleteTech-LLC/node-cve-2026-106073-check.svg) ![forks](https://img.shields.io/github/forks/CompleteTech-LLC/node-cve-2026-106073-check.svg)


## CVE-2026-106072
This vulnerability affects Node.js **26.x**, **24.x**, and **22.x**.

- [https://github.com/CompleteTech-LLC/node-cve-2026-106072-check](https://github.com/CompleteTech-LLC/node-cve-2026-106072-check) :  ![starts](https://img.shields.io/github/stars/CompleteTech-LLC/node-cve-2026-106072-check.svg) ![forks](https://img.shields.io/github/forks/CompleteTech-LLC/node-cve-2026-106072-check.svg)


## CVE-2026-106071
This vulnerability affects Node.js **26.x**.

- [https://github.com/CompleteTech-LLC/node-cve-2026-106071-check](https://github.com/CompleteTech-LLC/node-cve-2026-106071-check) :  ![starts](https://img.shields.io/github/stars/CompleteTech-LLC/node-cve-2026-106071-check.svg) ![forks](https://img.shields.io/github/forks/CompleteTech-LLC/node-cve-2026-106071-check.svg)


## CVE-2026-106070
This vulnerability affects Node.js **26.x**.

- [https://github.com/CompleteTech-LLC/node-cve-2026-106070-check](https://github.com/CompleteTech-LLC/node-cve-2026-106070-check) :  ![starts](https://img.shields.io/github/stars/CompleteTech-LLC/node-cve-2026-106070-check.svg) ![forks](https://img.shields.io/github/forks/CompleteTech-LLC/node-cve-2026-106070-check.svg)


## CVE-2026-106069
This vulnerability affects Node.js **26.x**, **24.x**, and **22.x**.

- [https://github.com/CompleteTech-LLC/node-cve-2026-106069-check](https://github.com/CompleteTech-LLC/node-cve-2026-106069-check) :  ![starts](https://img.shields.io/github/stars/CompleteTech-LLC/node-cve-2026-106069-check.svg) ![forks](https://img.shields.io/github/forks/CompleteTech-LLC/node-cve-2026-106069-check.svg)


## CVE-2026-105483
This vulnerability affects Node.js **26.x** and **24.x**.

- [https://github.com/CompleteTech-LLC/node-cve-2026-105483-check](https://github.com/CompleteTech-LLC/node-cve-2026-105483-check) :  ![starts](https://img.shields.io/github/stars/CompleteTech-LLC/node-cve-2026-105483-check.svg) ![forks](https://img.shields.io/github/forks/CompleteTech-LLC/node-cve-2026-105483-check.svg)
- [https://github.com/WASD258-jpg/dsh-hardening](https://github.com/WASD258-jpg/dsh-hardening) :  ![starts](https://img.shields.io/github/stars/WASD258-jpg/dsh-hardening.svg) ![forks](https://img.shields.io/github/forks/WASD258-jpg/dsh-hardening.svg)


## CVE-2026-105482
This vulnerability affects Node.js 26.x, 24.x, and 22.x.

- [https://github.com/CaterMaoZi/CVE-2026-105482-POC](https://github.com/CaterMaoZi/CVE-2026-105482-POC) :  ![starts](https://img.shields.io/github/stars/CaterMaoZi/CVE-2026-105482-POC.svg) ![forks](https://img.shields.io/github/forks/CaterMaoZi/CVE-2026-105482-POC.svg)
- [https://github.com/CompleteTech-LLC/node-cve-2026-105482-check](https://github.com/CompleteTech-LLC/node-cve-2026-105482-check) :  ![starts](https://img.shields.io/github/stars/CompleteTech-LLC/node-cve-2026-105482-check.svg) ![forks](https://img.shields.io/github/forks/CompleteTech-LLC/node-cve-2026-105482-check.svg)


## CVE-2026-105481
This vulnerability affects Node.js **26.x**, **24.x**, and **22.x**.

- [https://github.com/CompleteTech-LLC/node-cve-2026-105481-check](https://github.com/CompleteTech-LLC/node-cve-2026-105481-check) :  ![starts](https://img.shields.io/github/stars/CompleteTech-LLC/node-cve-2026-105481-check.svg) ![forks](https://img.shields.io/github/forks/CompleteTech-LLC/node-cve-2026-105481-check.svg)


## CVE-2026-105445
 An Incorrect Privilege Assignment vulnerability in Docker Hub's account-to-organization conversion feature allowed an authenticated attacker to reassign a personal access token (PAT) they controlled to another Docker Hub user without rotating or revoking the token secret. The unchanged PAT then authenticated to the registry as the recipient and could pull, push, or delete images, within its scopes, in repositories accessible to that user, including organization repositories.

- [https://github.com/CompleteTech-LLC/docker-hub-pat-check](https://github.com/CompleteTech-LLC/docker-hub-pat-check) :  ![starts](https://img.shields.io/github/stars/CompleteTech-LLC/docker-hub-pat-check.svg) ![forks](https://img.shields.io/github/forks/CompleteTech-LLC/docker-hub-pat-check.svg)


## CVE-2026-104935
 Authentication bypass by spoofing in ICS before version 25.1.3.0 allows a remote unauthenticated attacker to execute arbitrary commands. This does not impact ICS version 22.7R2.14 or prior.

- [https://github.com/CompleteTech-LLC/ivanti-connect-secure-cve-2026-104935-check](https://github.com/CompleteTech-LLC/ivanti-connect-secure-cve-2026-104935-check) :  ![starts](https://img.shields.io/github/stars/CompleteTech-LLC/ivanti-connect-secure-cve-2026-104935-check.svg) ![forks](https://img.shields.io/github/forks/CompleteTech-LLC/ivanti-connect-secure-cve-2026-104935-check.svg)


## CVE-2026-104849
 Tinypool is a minimal Node.js worker thread pool implementation. Prior to 2.1.2, Tinypool reads filename from a caller-supplied options object in pool.run(task, options) without requiring an own property, so a polluted Object.prototype.filename can replace the intended worker module. Applications are affected only when they pass their own second-argument options object to pool.run(); calls without that argument use the trusted default options object. An attacker who can first pollute the prototype can cause the worker pool to load attacker-selected JavaScript and can read or modify task data with the host process's privileges. This issue is fixed in version 2.1.2.

- [https://github.com/CompleteTech-LLC/tinypool-options-rce-check](https://github.com/CompleteTech-LLC/tinypool-options-rce-check) :  ![starts](https://img.shields.io/github/stars/CompleteTech-LLC/tinypool-options-rce-check.svg) ![forks](https://img.shields.io/github/forks/CompleteTech-LLC/tinypool-options-rce-check.svg)


## CVE-2026-104286
 An improper limitation of a pathname to a restricted directory ('path traversal') vulnerability in Fortinet FortiMail 8.0.0 through 8.0.1, FortiMail 7.6.0 through 7.6.6, FortiMail 7.4.0 through 7.4.8, FortiMail 7.2.0 through 7.2.9 may allow an unauthenticated attacker to write arbitrary files on the underlying system via crafted HTTP or HTTPS requests.

- [https://github.com/CompleteTech-LLC/fortimail-cve-2026-104286-check](https://github.com/CompleteTech-LLC/fortimail-cve-2026-104286-check) :  ![starts](https://img.shields.io/github/stars/CompleteTech-LLC/fortimail-cve-2026-104286-check.svg) ![forks](https://img.shields.io/github/forks/CompleteTech-LLC/fortimail-cve-2026-104286-check.svg)


## CVE-2026-102826
 simple-git, an interface for running git commands in any node.js application, enables applications to execute Git operations from JavaScript. Prior to 4.0.0, the default blockUnsafeOperationsPlugin does not completely reject configuration includes supplied through customArgs to git.clone(). The missing include.path classification permits Git to load an attacker-controlled configuration file, and the initial remediation does not cover includeIf.condition.path, allowing the same file-loading primitive through a conditional include. A loaded configuration can set an executable Git option such as core.sshCommand, which Git invokes during the clone operation with the privileges of the Node.js process. Exploitation requires the application to pass attacker-influenced custom arguments and requires an attacker-controlled file that the process can read. This issue is fixed in 4.0.0.

- [https://github.com/CompleteTech-LLC/simplegit-rce-check](https://github.com/CompleteTech-LLC/simplegit-rce-check) :  ![starts](https://img.shields.io/github/stars/CompleteTech-LLC/simplegit-rce-check.svg) ![forks](https://img.shields.io/github/forks/CompleteTech-LLC/simplegit-rce-check.svg)


## CVE-2026-102764
 The vulnerability exists within internal components of BeyondTrust’s Remote Support product. The components did not adequately validate the origin of the messages it received. Under the right conditions, this could allow an attacker to perform file operations on the appliance.

- [https://github.com/CompleteTech-LLC/beyondtrust-remote-support-cve-2026-102764-check](https://github.com/CompleteTech-LLC/beyondtrust-remote-support-cve-2026-102764-check) :  ![starts](https://img.shields.io/github/stars/CompleteTech-LLC/beyondtrust-remote-support-cve-2026-102764-check.svg) ![forks](https://img.shields.io/github/forks/CompleteTech-LLC/beyondtrust-remote-support-cve-2026-102764-check.svg)


## CVE-2026-102258
 Post-authentication Stored Cross-Site Scripting (XSS) vulnerability has been identified in the SMA1000 Appliance Management Console (AMC) which in specific conditions could potentially enable a remote authenticated attacker as administrator to store and potentially execute arbitrary JavaScript code in the Appliance Management Console (AMC).

- [https://github.com/CompleteTech-LLC/sonicwall-sma1000-cve-2026-102258-check](https://github.com/CompleteTech-LLC/sonicwall-sma1000-cve-2026-102258-check) :  ![starts](https://img.shields.io/github/stars/CompleteTech-LLC/sonicwall-sma1000-cve-2026-102258-check.svg) ![forks](https://img.shields.io/github/forks/CompleteTech-LLC/sonicwall-sma1000-cve-2026-102258-check.svg)


## CVE-2026-102257
 A Zip Slip vulnerability in the in the SMA1000 Appliance Management Console (AMC) interface allows an attacker to extract files outside the intended destination directory using a specially crafted archive, resulting in remote code execution.

- [https://github.com/CompleteTech-LLC/sonicwall-sma1000-cve-2026-102257-check](https://github.com/CompleteTech-LLC/sonicwall-sma1000-cve-2026-102257-check) :  ![starts](https://img.shields.io/github/stars/CompleteTech-LLC/sonicwall-sma1000-cve-2026-102257-check.svg) ![forks](https://img.shields.io/github/forks/CompleteTech-LLC/sonicwall-sma1000-cve-2026-102257-check.svg)


## CVE-2026-102256
 Post-authentication Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') vulnerability has been identified in the SMA1000 appliance which in specific conditions could potentially enable a remote authenticated attacker as administrator to execute arbitrary OS commands, resulting in remote code execution.

- [https://github.com/CompleteTech-LLC/sonicwall-sma1000-cve-2026-102256-check](https://github.com/CompleteTech-LLC/sonicwall-sma1000-cve-2026-102256-check) :  ![starts](https://img.shields.io/github/stars/CompleteTech-LLC/sonicwall-sma1000-cve-2026-102256-check.svg) ![forks](https://img.shields.io/github/forks/CompleteTech-LLC/sonicwall-sma1000-cve-2026-102256-check.svg)


## CVE-2026-102255
 A Pre-authentication SSRF vulnerability exists in the SMA1000 Appliance Work Place interface due to an unintended alternate access path. By abusing this path, a remote unauthenticated attacker could potentially exploit this vulnerability to direct the appliance to issue requests on their behalf and reach internal functionality and perform unauthorized operations.

- [https://github.com/CompleteTech-LLC/sonicwall-sma1000-cve-2026-102255-check](https://github.com/CompleteTech-LLC/sonicwall-sma1000-cve-2026-102255-check) :  ![starts](https://img.shields.io/github/stars/CompleteTech-LLC/sonicwall-sma1000-cve-2026-102255-check.svg) ![forks](https://img.shields.io/github/forks/CompleteTech-LLC/sonicwall-sma1000-cve-2026-102255-check.svg)


## CVE-2026-98260
[ tglx: Move the cleanup right after de_thread() ]

- [https://github.com/quyicheng03-boop/CVE-2026-98260-popsicle-android](https://github.com/quyicheng03-boop/CVE-2026-98260-popsicle-android) :  ![starts](https://img.shields.io/github/stars/quyicheng03-boop/CVE-2026-98260-popsicle-android.svg) ![forks](https://img.shields.io/github/forks/quyicheng03-boop/CVE-2026-98260-popsicle-android.svg)
- [https://github.com/quyicheng03-boop/CVE-2026-98260-nezha-android](https://github.com/quyicheng03-boop/CVE-2026-98260-nezha-android) :  ![starts](https://img.shields.io/github/stars/quyicheng03-boop/CVE-2026-98260-nezha-android.svg) ![forks](https://img.shields.io/github/forks/quyicheng03-boop/CVE-2026-98260-nezha-android.svg)


## CVE-2026-96889
 A flaw was found in librsvg. When processing an SVG document containing nested XML inclusions (Xincludes) with duplicate entity declarations, a use-after-free error can occur. This vulnerability arises because the library incorrectly frees an XML entity that is still in use by the parser. An attacker could potentially exploit this to cause a denial of service or execute arbitrary code.

- [https://github.com/CompleteTech-LLC/sharp-rsvg-rce-check](https://github.com/CompleteTech-LLC/sharp-rsvg-rce-check) :  ![starts](https://img.shields.io/github/stars/CompleteTech-LLC/sharp-rsvg-rce-check.svg) ![forks](https://img.shields.io/github/forks/CompleteTech-LLC/sharp-rsvg-rce-check.svg)
- [https://github.com/AmanSin001/next-security-check](https://github.com/AmanSin001/next-security-check) :  ![starts](https://img.shields.io/github/stars/AmanSin001/next-security-check.svg) ![forks](https://img.shields.io/github/forks/AmanSin001/next-security-check.svg)


## CVE-2026-94300
This issue affects BIND 9 versions 9.11.0 through 9.18.50, 9.20.0 through 9.20.29, 9.21.0 through 9.21.26, 9.11.3-S1 through 9.18.50-S1, and 9.20.9-S1 through 9.20.29-S1.

- [https://github.com/Ibonok/CVE-2026-94300](https://github.com/Ibonok/CVE-2026-94300) :  ![starts](https://img.shields.io/github/stars/Ibonok/CVE-2026-94300.svg) ![forks](https://img.shields.io/github/forks/Ibonok/CVE-2026-94300.svg)


## CVE-2026-94293
 An unauthenticated remote attacker can modify Asset Administration Shell submodel data via PATCH requests and can read all data exposed by the GET endpoints.

- [https://github.com/KernelEditor/CVE-2026-94293](https://github.com/KernelEditor/CVE-2026-94293) :  ![starts](https://img.shields.io/github/stars/KernelEditor/CVE-2026-94293.svg) ![forks](https://img.shields.io/github/forks/KernelEditor/CVE-2026-94293.svg)


## CVE-2026-92935
 vm2 is a sandbox for running untrusted Node.js code. In versions = 3.11.4 and = 3.11.6, the NodeVM constructor computes `hasRealRequireConfig` with `typeof requireOpts === 'object' && requireOpts !== null`, so an array-shaped `require` value (for example `require: []`) satisfies the guard that is meant to reject nesting without an explicit require configuration. `makeResolverFromLegacyOptions()` then destructures the array into undefined option fields and returns a resolver containing only `NESTING_OVERRIDE.vm2`. As a result, an attacker who can supply JavaScript executed by a NodeVM configured with truthy `nesting` and an array-shaped `require` (e.g. `new NodeVM({nesting: true, require: []})`) can require the host `vm2` module, create an inner NodeVM with an attacker-chosen builtin allowlist (such as `child_process`), and execute arbitrary commands with the privileges of the host Node.js process, escaping the sandbox. Outer builtin restrictions do not constrain the attacker-created inner NodeVM. This issue is fixed in vm2 3.11.7.

- [https://github.com/CompleteTech-LLC/vm2-nesting-check](https://github.com/CompleteTech-LLC/vm2-nesting-check) :  ![starts](https://img.shields.io/github/stars/CompleteTech-LLC/vm2-nesting-check.svg) ![forks](https://img.shields.io/github/forks/CompleteTech-LLC/vm2-nesting-check.svg)


## CVE-2026-91403
 Vulnerability in the Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component: JSSE).  Supported versions that are affected are Oracle Java SE: 8u511, 8u511-perf, 11.0.33, 17.0.21, 21.0.13, 25.0.5, 27.0.1; Oracle GraalVM for JDK: 17.0.21 and  21.0.13; Oracle GraalVM Enterprise Edition: 21.3.20. Easily exploitable vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition.  Successful attacks of this vulnerability can result in  unauthorized creation, deletion or modification access to critical data or all Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition accessible data as well as  unauthorized access to critical data or complete access to all Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition accessible data. Note: This vulnerability can be exploited by using APIs in the specified Component, e.g., through a web service which supplies data to the APIs. This vulnerability also applies to Java deployments, typically in clients running sandboxed Java Web Start applications or sandboxed Java applets, that load and run untrusted code (e.g., code that comes from the internet) and rely on the Java sandbox for security. CVSS 3.1 Base Score 9.1 (Confidentiality and Integrity impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N).

- [https://github.com/siladu/fix-cve-2026-91403](https://github.com/siladu/fix-cve-2026-91403) :  ![starts](https://img.shields.io/github/stars/siladu/fix-cve-2026-91403.svg) ![forks](https://img.shields.io/github/forks/siladu/fix-cve-2026-91403.svg)
- [https://github.com/FahrihFatahilah/CVE-2026-91403-eMudhra-Java-Scanner](https://github.com/FahrihFatahilah/CVE-2026-91403-eMudhra-Java-Scanner) :  ![starts](https://img.shields.io/github/stars/FahrihFatahilah/CVE-2026-91403-eMudhra-Java-Scanner.svg) ![forks](https://img.shields.io/github/forks/FahrihFatahilah/CVE-2026-91403-eMudhra-Java-Scanner.svg)
- [https://github.com/hubly12/javafix](https://github.com/hubly12/javafix) :  ![starts](https://img.shields.io/github/stars/hubly12/javafix.svg) ![forks](https://img.shields.io/github/forks/hubly12/javafix.svg)


## CVE-2026-88778
This issue affects ADC: before 14.1-73.37, before 13.1-64.23, before 14.1-73.37 FIPS, and before 13.1.37.279 FIPS and NDcPP; Gateway: before 14.1-73.37 and before 13.1-64.23.

- [https://github.com/CompleteTech-LLC/netscaler-cve-2026-88778-check](https://github.com/CompleteTech-LLC/netscaler-cve-2026-88778-check) :  ![starts](https://img.shields.io/github/stars/CompleteTech-LLC/netscaler-cve-2026-88778-check.svg) ![forks](https://img.shields.io/github/forks/CompleteTech-LLC/netscaler-cve-2026-88778-check.svg)


## CVE-2026-88777
This issue affects ADC: before 14.1-73.37, before 13.1-64.23, before 14.1-73.37 FIPS, and before 13.1.37.279 FIPS and NDcPP; Gateway: before 14.1-73.37 and before 13.1-64.23  leading to unpredictable or erroneous behavior or Denial of Service

- [https://github.com/CompleteTech-LLC/netscaler-cve-2026-88777-check](https://github.com/CompleteTech-LLC/netscaler-cve-2026-88777-check) :  ![starts](https://img.shields.io/github/stars/CompleteTech-LLC/netscaler-cve-2026-88777-check.svg) ![forks](https://img.shields.io/github/forks/CompleteTech-LLC/netscaler-cve-2026-88777-check.svg)


## CVE-2026-88776
This issue affects ADC: before 14.1-73.37, before 13.1-64.23, before 14.1-73.37 FIPS, and before 13.1.37.279 FIPS and NDcPP; Gateway: before 14.1-73.37 and before 13.1-64.23  leading to unpredictable or erroneous behavior or Denial of Service

- [https://github.com/CompleteTech-LLC/netscaler-cve-2026-88776-check](https://github.com/CompleteTech-LLC/netscaler-cve-2026-88776-check) :  ![starts](https://img.shields.io/github/stars/CompleteTech-LLC/netscaler-cve-2026-88776-check.svg) ![forks](https://img.shields.io/github/forks/CompleteTech-LLC/netscaler-cve-2026-88776-check.svg)


## CVE-2026-88775
This issue affects ADC: before 14.1-73.37, before 13.1-64.23, before 14.1-73.37 FIPS, and before 13.1.37.279 FIPS and NDcPP; Gateway: before 14.1-73.37 and before 13.1-64.23 leading Memory overflow vulnerability leading to unpredictable or erroneous behavior or Denial of Service

- [https://github.com/CompleteTech-LLC/netscaler-cve-2026-88775-check](https://github.com/CompleteTech-LLC/netscaler-cve-2026-88775-check) :  ![starts](https://img.shields.io/github/stars/CompleteTech-LLC/netscaler-cve-2026-88775-check.svg) ![forks](https://img.shields.io/github/forks/CompleteTech-LLC/netscaler-cve-2026-88775-check.svg)


## CVE-2026-88774
This issue affects ADC: before 14.1-73.37, before 13.1-64.23, before 14.1-73.37 FIPS, and before 13.1.37.279 FIPS and NDcPP; Gateway: before 14.1-73.37 and before 13.1-64.23 leading to a feature policy bypass due to improper HTTP URL based expression usage.

- [https://github.com/CompleteTech-LLC/netscaler-cve-2026-88774-check](https://github.com/CompleteTech-LLC/netscaler-cve-2026-88774-check) :  ![starts](https://img.shields.io/github/stars/CompleteTech-LLC/netscaler-cve-2026-88774-check.svg) ![forks](https://img.shields.io/github/forks/CompleteTech-LLC/netscaler-cve-2026-88774-check.svg)


## CVE-2026-88773
This issue affects ADC: before 14.1-73.37, before 13.1-64.23, before 14.1-73.37 FIPS, and before 13.1-37.279 and NDcPP; Gateway: before 14.1-73.37 FIPS and before 13.1-64.23.

- [https://github.com/CompleteTech-LLC/netscaler-cve-2026-88773-check](https://github.com/CompleteTech-LLC/netscaler-cve-2026-88773-check) :  ![starts](https://img.shields.io/github/stars/CompleteTech-LLC/netscaler-cve-2026-88773-check.svg) ![forks](https://img.shields.io/github/forks/CompleteTech-LLC/netscaler-cve-2026-88773-check.svg)


## CVE-2026-88772
This issue affects ADC: before 14.1-73.37, before 13.1-64.23, before 14.1-73.37 FIPS, and before 13.1.37.279 FIPS and NDcPP; Gateway: before 14.1-73.37 and before 13.1-64.23 leading to Remote Code Execution or Denial of Service

- [https://github.com/CompleteTech-LLC/netscaler-cve-2026-88772-check](https://github.com/CompleteTech-LLC/netscaler-cve-2026-88772-check) :  ![starts](https://img.shields.io/github/stars/CompleteTech-LLC/netscaler-cve-2026-88772-check.svg) ![forks](https://img.shields.io/github/forks/CompleteTech-LLC/netscaler-cve-2026-88772-check.svg)


## CVE-2026-88771
This issue affects ADC: before 14.1-73.37, before 13.1-64.23, before 14.1-73.37 FIPS, and before 13.1.37.279 FIPS and NDcPP; Gateway: before 14.1-73.37 and before 13.1-64.23 leading to an unauthenticated attacker to execute arbitrary commands.

- [https://github.com/CompleteTech-LLC/netscaler-cve-2026-88771-check](https://github.com/CompleteTech-LLC/netscaler-cve-2026-88771-check) :  ![starts](https://img.shields.io/github/stars/CompleteTech-LLC/netscaler-cve-2026-88771-check.svg) ![forks](https://img.shields.io/github/forks/CompleteTech-LLC/netscaler-cve-2026-88771-check.svg)


## CVE-2026-86476
 A flaw was found in gst-plugins-base. A heap buffer overflow can be triggered when processing video buffers whose attached GstVideoMeta metadata declares plane strides and offsets that exceed the actual backing memory allocation. The metadata is not range-checked during deserialization, and the video frame mapping code does not verify that the declared plane geometry fits within the buffer before allowing consumers to read or write video data. A local attacker who controls the sending side of a GStreamer inter-process IPC pipeline can deliver a crafted buffer carrying fabricated strides, causing the receiving process to read or write beyond heap boundaries. Successful exploitation can cause a denial of service or potentially allow code execution within the affected process.

- [https://github.com/0xSemizzz/CVE-2026-86476](https://github.com/0xSemizzz/CVE-2026-86476) :  ![starts](https://img.shields.io/github/stars/0xSemizzz/CVE-2026-86476.svg) ![forks](https://img.shields.io/github/forks/0xSemizzz/CVE-2026-86476.svg)


## CVE-2026-76504
This vulnerability is due to improper handling of URI encoding in an HTTP request, which allows the request to bypass an authentication rule that is intended to restrict access to a specific API endpoint. An attacker could exploit this vulnerability by sending a crafted HTTP request to the API of the affected system. A successful exploit could allow the attacker to bypass authentication and gain access to the API as the admin user.

- [https://github.com/pastelghost3/cve-2026-76504-nuclei](https://github.com/pastelghost3/cve-2026-76504-nuclei) :  ![starts](https://img.shields.io/github/stars/pastelghost3/cve-2026-76504-nuclei.svg) ![forks](https://img.shields.io/github/forks/pastelghost3/cve-2026-76504-nuclei.svg)
- [https://github.com/maxprog-svg/CVE-2026-76504-Cisco](https://github.com/maxprog-svg/CVE-2026-76504-Cisco) :  ![starts](https://img.shields.io/github/stars/maxprog-svg/CVE-2026-76504-Cisco.svg) ![forks](https://img.shields.io/github/forks/maxprog-svg/CVE-2026-76504-Cisco.svg)


## CVE-2026-76268
Splunk Enterprise versions 10.0.x and 9.4.x are not affected.

- [https://github.com/Zombie-Kaiser/CVE-2026-76268](https://github.com/Zombie-Kaiser/CVE-2026-76268) :  ![starts](https://img.shields.io/github/stars/Zombie-Kaiser/CVE-2026-76268.svg) ![forks](https://img.shields.io/github/forks/Zombie-Kaiser/CVE-2026-76268.svg)


## CVE-2026-76183
Users are recommended to upgrade to version 11.0.26, 10.1.60 or 9.0.122, which fix the issue.

- [https://github.com/Ethen1212/tomcat-CVE-2026-76183](https://github.com/Ethen1212/tomcat-CVE-2026-76183) :  ![starts](https://img.shields.io/github/stars/Ethen1212/tomcat-CVE-2026-76183.svg) ![forks](https://img.shields.io/github/forks/Ethen1212/tomcat-CVE-2026-76183.svg)


## CVE-2026-71362
 Adobe Commerce is affected by an Incorrect Authorization vulnerability that could result in privilege escalation. An attacker could leverage this vulnerability to gain elevated access to sensitive resources. Exploitation of this issue does not require user interaction.

- [https://github.com/mahumadad/cve-2026-71362-magento-ato](https://github.com/mahumadad/cve-2026-71362-magento-ato) :  ![starts](https://img.shields.io/github/stars/mahumadad/cve-2026-71362-magento-ato.svg) ![forks](https://img.shields.io/github/forks/mahumadad/cve-2026-71362-magento-ato.svg)


## CVE-2026-69254
 Flowise is a drag & drop user interface to build a customized large language model flow. Prior to 3.1.3, executeJavaScriptCode() accepted caller-provided nodeVMOptions and merged them over the default NodeVM security settings in packages/components/src/utils.ts. An authenticated attacker reaching packages/server/src/routes/node-custom-functions/index.ts could run a custom function that imported flowise-components/dist/src/utils.js, called executeJavaScriptCode() again with nodeVMOptions.require.builtin set to allow all built-in modules, and then required child_process to execute arbitrary system commands as root on the Flowise server. This issue is fixed in version 3.1.3.

- [https://github.com/CompleteTech-LLC/flowise-cve-2026-69254-check](https://github.com/CompleteTech-LLC/flowise-cve-2026-69254-check) :  ![starts](https://img.shields.io/github/stars/CompleteTech-LLC/flowise-cve-2026-69254-check.svg) ![forks](https://img.shields.io/github/forks/CompleteTech-LLC/flowise-cve-2026-69254-check.svg)


## CVE-2026-68136
skb_gro_receive().

- [https://github.com/KernelEditor/CVE-2026-68136](https://github.com/KernelEditor/CVE-2026-68136) :  ![starts](https://img.shields.io/github/stars/KernelEditor/CVE-2026-68136.svg) ![forks](https://img.shields.io/github/forks/KernelEditor/CVE-2026-68136.svg)


## CVE-2026-58045
This vulnerability affects Node.js **22.x**, **24.x**, and **26.x**.

- [https://github.com/CompleteTech-LLC/node-cve-2026-58045-check](https://github.com/CompleteTech-LLC/node-cve-2026-58045-check) :  ![starts](https://img.shields.io/github/stars/CompleteTech-LLC/node-cve-2026-58045-check.svg) ![forks](https://img.shields.io/github/forks/CompleteTech-LLC/node-cve-2026-58045-check.svg)


## CVE-2026-58044
This vulnerability affects all supported release lines: **Node.js 22**, **Node.js 24**, and **Node.js 26**.

- [https://github.com/CompleteTech-LLC/node-cve-2026-58044-check](https://github.com/CompleteTech-LLC/node-cve-2026-58044-check) :  ![starts](https://img.shields.io/github/stars/CompleteTech-LLC/node-cve-2026-58044-check.svg) ![forks](https://img.shields.io/github/forks/CompleteTech-LLC/node-cve-2026-58044-check.svg)


## CVE-2026-58043
This vulnerability affects Node.js **main**, **22.x**, **24.x**, and **26.x**.

- [https://github.com/CompleteTech-LLC/node-cve-2026-58043-check](https://github.com/CompleteTech-LLC/node-cve-2026-58043-check) :  ![starts](https://img.shields.io/github/stars/CompleteTech-LLC/node-cve-2026-58043-check.svg) ![forks](https://img.shields.io/github/forks/CompleteTech-LLC/node-cve-2026-58043-check.svg)


## CVE-2026-58042
This vulnerability affects Node.js **26.x**, **24.x**, and **22.x**.

- [https://github.com/CompleteTech-LLC/node-cve-2026-58042-check](https://github.com/CompleteTech-LLC/node-cve-2026-58042-check) :  ![starts](https://img.shields.io/github/stars/CompleteTech-LLC/node-cve-2026-58042-check.svg) ![forks](https://img.shields.io/github/forks/CompleteTech-LLC/node-cve-2026-58042-check.svg)


## CVE-2026-58041
This vulnerability affects Node.js **22.x**, **24.x**, and **26.x**.

- [https://github.com/CompleteTech-LLC/node-cve-2026-58041-check](https://github.com/CompleteTech-LLC/node-cve-2026-58041-check) :  ![starts](https://img.shields.io/github/stars/CompleteTech-LLC/node-cve-2026-58041-check.svg) ![forks](https://img.shields.io/github/forks/CompleteTech-LLC/node-cve-2026-58041-check.svg)


## CVE-2026-58040
This vulnerability affects Node.js **22.x**, **24.x**, and **26.x**.

- [https://github.com/CompleteTech-LLC/node-cve-2026-58040-check](https://github.com/CompleteTech-LLC/node-cve-2026-58040-check) :  ![starts](https://img.shields.io/github/stars/CompleteTech-LLC/node-cve-2026-58040-check.svg) ![forks](https://img.shields.io/github/forks/CompleteTech-LLC/node-cve-2026-58040-check.svg)


## CVE-2026-58039
This vulnerability affects Node.js **22.x**, **24.x**, and **26.x**.

- [https://github.com/CompleteTech-LLC/node-cve-2026-58039-check](https://github.com/CompleteTech-LLC/node-cve-2026-58039-check) :  ![starts](https://img.shields.io/github/stars/CompleteTech-LLC/node-cve-2026-58039-check.svg) ![forks](https://img.shields.io/github/forks/CompleteTech-LLC/node-cve-2026-58039-check.svg)


## CVE-2026-57845
 Hugging Face Datasets through 5.1.0 contains an insecure deserialization vulnerability that allows attackers to execute arbitrary Python code by crafting a malicious pickle file loaded through the deprecated pandas packaged builder. Attackers can supply a pickle-backed dataset that is processed by Pandas._generate_tables via pandas.read_pickle() without validation, so when a victim calls datasets.load_dataset("pandas", data_files=...), the embedded __reduce__ payload executes code with the victim process's privileges.

- [https://github.com/SaiTeja-Erukude/CVE-2026-57845-hf-datasets-rce](https://github.com/SaiTeja-Erukude/CVE-2026-57845-hf-datasets-rce) :  ![starts](https://img.shields.io/github/stars/SaiTeja-Erukude/CVE-2026-57845-hf-datasets-rce.svg) ![forks](https://img.shields.io/github/forks/SaiTeja-Erukude/CVE-2026-57845-hf-datasets-rce.svg)


## CVE-2026-56850
This vulnerability affects Node.js **26.x**, **24.x**, and **22.x**.

- [https://github.com/CompleteTech-LLC/node-cve-2026-56850-check](https://github.com/CompleteTech-LLC/node-cve-2026-56850-check) :  ![starts](https://img.shields.io/github/stars/CompleteTech-LLC/node-cve-2026-56850-check.svg) ![forks](https://img.shields.io/github/forks/CompleteTech-LLC/node-cve-2026-56850-check.svg)


## CVE-2026-56848
This vulnerability affects Node.js **26.x**, **24.x**, and **22.x**.

- [https://github.com/CompleteTech-LLC/node-cve-2026-56848-check](https://github.com/CompleteTech-LLC/node-cve-2026-56848-check) :  ![starts](https://img.shields.io/github/stars/CompleteTech-LLC/node-cve-2026-56848-check.svg) ![forks](https://img.shields.io/github/forks/CompleteTech-LLC/node-cve-2026-56848-check.svg)


## CVE-2026-56847
This vulnerability affects Node.js **22.x**, **24.x**, and **26.x**.

- [https://github.com/CompleteTech-LLC/node-cve-2026-56847-check](https://github.com/CompleteTech-LLC/node-cve-2026-56847-check) :  ![starts](https://img.shields.io/github/stars/CompleteTech-LLC/node-cve-2026-56847-check.svg) ![forks](https://img.shields.io/github/forks/CompleteTech-LLC/node-cve-2026-56847-check.svg)


## CVE-2026-56846
This vulnerability affects Node.js **24.x** and **22.x**.

- [https://github.com/CompleteTech-LLC/node-cve-2026-56846-check](https://github.com/CompleteTech-LLC/node-cve-2026-56846-check) :  ![starts](https://img.shields.io/github/stars/CompleteTech-LLC/node-cve-2026-56846-check.svg) ![forks](https://img.shields.io/github/forks/CompleteTech-LLC/node-cve-2026-56846-check.svg)


## CVE-2026-54668
 Kitodo.Production is a workflow management tool for mass digitization and is part of the Kitodo Digital Library Suite. Prior to version 3.9.2, org.kitodo.production.helper.XMLUtils exposes several XML parsing helpers that construct a JAXP parser with the default, non-secure configuration. The methods parseXMLString(String), getNumberOfEADElements(String, String) and checkIfXmlIsWellFormed(String) build a DocumentBuilderFactory / XMLInputFactory / SAXParserFactory via newInstance() and parse the attacker-supplied string without disabling DOCTYPE declarations or external entity resolution. These helpers sit directly on the EAD-import path: an authenticated user who uploads an EAD/XML file through the "Create process" file-upload dialog has the uploaded bytes parsed by these methods. A crafted document with an external entity therefore yields XML External Entity (XXE) injection: local file disclosure and outbound SSRF requests from the server. This issue has been patched in version 3.9.2.

- [https://github.com/KernelEditor/CVE-2026-54668](https://github.com/KernelEditor/CVE-2026-54668) :  ![starts](https://img.shields.io/github/stars/KernelEditor/CVE-2026-54668.svg) ![forks](https://img.shields.io/github/forks/KernelEditor/CVE-2026-54668.svg)


## CVE-2026-53921
 odhcpd is the DHCPv6, DHCPv4, and router-advertisement server used by OpenWrt. Prior to version 25.12, odhcpd's DHCPv6 IA response handler writes past the end of a fixed 512-byte stack buffer (pdbuf) when a single DHCPv6 REQUEST carries enough IA options to nearly exhaust the reply space. Two independent overflow sites exist in the same call chain, both reachable from the network via a single unauthenticated UDP packet. odhcpd runs as root on OpenWrt; embedded targets often lack stack canaries and ASLR, making code execution realistic. This issue has been patched in version 25.12.

- [https://github.com/tc4dy/CVE-2026-53921-PoC-Exploit](https://github.com/tc4dy/CVE-2026-53921-PoC-Exploit) :  ![starts](https://img.shields.io/github/stars/tc4dy/CVE-2026-53921-PoC-Exploit.svg) ![forks](https://img.shields.io/github/forks/tc4dy/CVE-2026-53921-PoC-Exploit.svg)
- [https://github.com/0xBlackash/CVE-2026-53921](https://github.com/0xBlackash/CVE-2026-53921) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-53921.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-53921.svg)


## CVE-2026-50787
 e-SIC Livre (esiclivre) v0.2.2 and earlier contains an uncontrolled resource consumption vulnerability in restrito/inc/captcha.php. The application uses user-supplied parameters (l, a, tf, ql) without validation to generate CAPTCHA images, allowing remote attackers to cause denial of service via excessive memory and CPU consumption.

- [https://github.com/brynax/CVE-2026-50787](https://github.com/brynax/CVE-2026-50787) :  ![starts](https://img.shields.io/github/stars/brynax/CVE-2026-50787.svg) ![forks](https://img.shields.io/github/forks/brynax/CVE-2026-50787.svg)


## CVE-2026-43499
  	changelog ]

- [https://github.com/Romk-a/CVE-2026-43499-ghostlock-vivo-x100-ultra-root](https://github.com/Romk-a/CVE-2026-43499-ghostlock-vivo-x100-ultra-root) :  ![starts](https://img.shields.io/github/stars/Romk-a/CVE-2026-43499-ghostlock-vivo-x100-ultra-root.svg) ![forks](https://img.shields.io/github/forks/Romk-a/CVE-2026-43499-ghostlock-vivo-x100-ultra-root.svg)


## CVE-2026-39902
 Cacti is an open source performance and fault management framework. Prior to version 1.2.31, the prior blocklist ([;&| `$\\n\r]) omitted single-quote, double-quote, redirect operators, subshell parens and braces. An authenticated admin could save an input_string` containing single-quote, redirect operator, or subshell parens, and pass the check. This issue has been patched in version 1.2.31.

- [https://github.com/kx00007/CVE-2026-39902](https://github.com/kx00007/CVE-2026-39902) :  ![starts](https://img.shields.io/github/stars/kx00007/CVE-2026-39902.svg) ![forks](https://img.shields.io/github/forks/kx00007/CVE-2026-39902.svg)


## CVE-2026-38751
 OpenSTAManager version 2.10 and earlier contains an arbitrary file upload vulnerability in the module update functionality (modules/aggiornamenti/upload_modules.php)

- [https://github.com/Wingleszy/HTB-Enigma-walkthrough](https://github.com/Wingleszy/HTB-Enigma-walkthrough) :  ![starts](https://img.shields.io/github/stars/Wingleszy/HTB-Enigma-walkthrough.svg) ![forks](https://img.shields.io/github/forks/Wingleszy/HTB-Enigma-walkthrough.svg)


## CVE-2026-38526
 An authenticated arbitrary file upload vulnerability in the /admin/tinymce/upload endpoint of Webkul Krayin CRM v2.2.x allows attackers to execute arbitrary code via uploading a crafted PHP file.

- [https://github.com/Wingleszy/HTB-Nexus-walkthrough](https://github.com/Wingleszy/HTB-Nexus-walkthrough) :  ![starts](https://img.shields.io/github/stars/Wingleszy/HTB-Nexus-walkthrough.svg) ![forks](https://img.shields.io/github/forks/Wingleszy/HTB-Nexus-walkthrough.svg)


## CVE-2026-34717
 OpenProject is an open-source, web-based project management software. Prior to version 17.2.3, the =n operator in modules/reporting/lib/report/operator.rb:177 embeds user input directly into SQL WHERE clauses without parameterization. This issue has been patched in version 17.2.3.

- [https://github.com/quanlevan1207/cve-2026-34717-exploit](https://github.com/quanlevan1207/cve-2026-34717-exploit) :  ![starts](https://img.shields.io/github/stars/quanlevan1207/cve-2026-34717-exploit.svg) ![forks](https://img.shields.io/github/forks/quanlevan1207/cve-2026-34717-exploit.svg)


## CVE-2026-21589
 This is a vulnerability in Bitbucket Data Center, Confluence Data Center, Jira Service Management Data Center, Jira Software Data Center, Bamboo Data Center. Crowd Data Center, Crucible and Fisheye. This Arbitrary File Access vulnerability allows an unauthenticated attacker to access specific files within the web application root directory in affected versions. Exploitation requires prior knowledge of the target file's exact name and path; this vulnerability does not allow attackers to enumerate or list directory contents. In some configurations, there may be some sensitive files that make this highly severe. This vulnerability allows an unauthenticated remote attacker to access specific files within the web application root directory in affected versions. The vulnerability must be addressed for affected versions of: -- Bitbucket Data Center, introduced in version = 4.6.0, fix versions: 9.4.26, 10.2.8, 10.5.1 -- Confluence Data Center, introduced in version = 5.10.0, fix versions 9.2.26, 10.2.19 -- Crowd Data Center, introduced in version = 2.11.0, fix versions 6.3.7, 7.0.3, 7.1.7, 7.2.4 -- Jira Software Data Center, introduced in version = 7.1.0, fix versions 9.12.40, 10.3.26, 11.3.12 -- Jira Service Management Data Center, introduced in version = 3.1.0, fix versions 5.12.40, 10.3.26, 11.3.12 -- Bamboo Data Center = 7.0.1, fix versions 10.2.24, 12.1.12 -- Crucible, fix versions 4.9.15 -- Fisheye, fix version 4.9.15 -- Exploitation requires prior knowledge of the target file's exact name and path. The vulnerability does not include the capability to enumerate or list directory contents.

- [https://github.com/CompleteTech-LLC/atlassian-cve-2026-21589-check](https://github.com/CompleteTech-LLC/atlassian-cve-2026-21589-check) :  ![starts](https://img.shields.io/github/stars/CompleteTech-LLC/atlassian-cve-2026-21589-check.svg) ![forks](https://img.shields.io/github/forks/CompleteTech-LLC/atlassian-cve-2026-21589-check.svg)


## CVE-2026-19490
This issue affects ADC: from 14.1 through 73.32 and from 13.1 through 63.21; Gateway: from 14.1 through 73.32 and from 13.1 through 63.21.

- [https://github.com/CompleteTech-LLC/netscaler-cve-2026-19490-check](https://github.com/CompleteTech-LLC/netscaler-cve-2026-19490-check) :  ![starts](https://img.shields.io/github/stars/CompleteTech-LLC/netscaler-cve-2026-19490-check.svg) ![forks](https://img.shields.io/github/forks/CompleteTech-LLC/netscaler-cve-2026-19490-check.svg)


## CVE-2026-19489
This issue affects ADC: from 14.1 through 73.32 and from 13.1 through 63.21; Gateway: from 14.1 through 73.32 and from 13.1 through 63.21.

- [https://github.com/CompleteTech-LLC/netscaler-cve-2026-19489-check](https://github.com/CompleteTech-LLC/netscaler-cve-2026-19489-check) :  ![starts](https://img.shields.io/github/stars/CompleteTech-LLC/netscaler-cve-2026-19489-check.svg) ![forks](https://img.shields.io/github/forks/CompleteTech-LLC/netscaler-cve-2026-19489-check.svg)


## CVE-2026-17106
 The tar extraction routines in moby/go-archive (Unpack, UnpackLayer, Untar/UntarUncompressed, and the ApplyLayer helpers) do not confine filesystem operations to the destination directory. The extractor decides where each archive entry lands using lexical string checks and then performs the filesystem operation on a path that is resolved by the OS, so links introduced by the archive can be followed out of the destination directory. An attacker who controls the contents of an archive can create or overwrite files at arbitrary paths writable by the extracting process.

- [https://github.com/CompleteTech-LLC/copyescape-check](https://github.com/CompleteTech-LLC/copyescape-check) :  ![starts](https://img.shields.io/github/stars/CompleteTech-LLC/copyescape-check.svg) ![forks](https://img.shields.io/github/forks/CompleteTech-LLC/copyescape-check.svg)


## CVE-2026-16723
 A remote code execution (RCE) vulnerability exists in fastjson 1.2.68 through 1.2.83. This vulnerability is exploitable under fastjson's stock default configuration — no AutoType enablement required, no classpath gadget required.

- [https://github.com/Ethen1212/fastjson-CVE-2026-16723](https://github.com/Ethen1212/fastjson-CVE-2026-16723) :  ![starts](https://img.shields.io/github/stars/Ethen1212/fastjson-CVE-2026-16723.svg) ![forks](https://img.shields.io/github/forks/Ethen1212/fastjson-CVE-2026-16723.svg)


## CVE-2026-11556
 A security flaw has been discovered in Tenda F451 1.0.0.7/1.0.0.9. Impacted is the function formWriteFacMac of the file /goform/WriteFacMac of the component Web Management Interface. Performing a manipulation of the argument mac results in os command injection. Remote exploitation of the attack is possible. The exploit has been released to the public and may be used for attacks.

- [https://github.com/sykeops/CVE-2026-115560](https://github.com/sykeops/CVE-2026-115560) :  ![starts](https://img.shields.io/github/stars/sykeops/CVE-2026-115560.svg) ![forks](https://img.shields.io/github/forks/sykeops/CVE-2026-115560.svg)
- [https://github.com/prnjlksingh/php-cve-2026-115560-demo](https://github.com/prnjlksingh/php-cve-2026-115560-demo) :  ![starts](https://img.shields.io/github/stars/prnjlksingh/php-cve-2026-115560-demo.svg) ![forks](https://img.shields.io/github/forks/prnjlksingh/php-cve-2026-115560-demo.svg)
- [https://github.com/ivst/CVE-2026-115560](https://github.com/ivst/CVE-2026-115560) :  ![starts](https://img.shields.io/github/stars/ivst/CVE-2026-115560.svg) ![forks](https://img.shields.io/github/forks/ivst/CVE-2026-115560.svg)
- [https://github.com/basesixtythree/B63-POC-CVE-2026-115560](https://github.com/basesixtythree/B63-POC-CVE-2026-115560) :  ![starts](https://img.shields.io/github/stars/basesixtythree/B63-POC-CVE-2026-115560.svg) ![forks](https://img.shields.io/github/forks/basesixtythree/B63-POC-CVE-2026-115560.svg)


## CVE-2026-10961
 Use after free in Chrome for iOS in Google Chrome on iOS prior to 149.0.7827.53 allowed a remote attacker who had compromised the renderer process to potentially perform a sandbox escape via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/aduli198/CVE-2026-109618_CVE-2026-109619](https://github.com/aduli198/CVE-2026-109618_CVE-2026-109619) :  ![starts](https://img.shields.io/github/stars/aduli198/CVE-2026-109618_CVE-2026-109619.svg) ![forks](https://img.shields.io/github/forks/aduli198/CVE-2026-109618_CVE-2026-109619.svg)
- [https://github.com/Stensel8/check-for-CVE-2026-109618-CVE-2026-109619](https://github.com/Stensel8/check-for-CVE-2026-109618-CVE-2026-109619) :  ![starts](https://img.shields.io/github/stars/Stensel8/check-for-CVE-2026-109618-CVE-2026-109619.svg) ![forks](https://img.shields.io/github/forks/Stensel8/check-for-CVE-2026-109618-CVE-2026-109619.svg)
- [https://github.com/goodcoddeo/pterodactyl_PHP-CVE-2026-109618-CVE-2026-109619](https://github.com/goodcoddeo/pterodactyl_PHP-CVE-2026-109618-CVE-2026-109619) :  ![starts](https://img.shields.io/github/stars/goodcoddeo/pterodactyl_PHP-CVE-2026-109618-CVE-2026-109619.svg) ![forks](https://img.shields.io/github/forks/goodcoddeo/pterodactyl_PHP-CVE-2026-109618-CVE-2026-109619.svg)
- [https://github.com/kishwordulal2005/CVE-2026-109618-and-CVE-2026-109619-Exploit](https://github.com/kishwordulal2005/CVE-2026-109618-and-CVE-2026-109619-Exploit) :  ![starts](https://img.shields.io/github/stars/kishwordulal2005/CVE-2026-109618-and-CVE-2026-109619-Exploit.svg) ![forks](https://img.shields.io/github/forks/kishwordulal2005/CVE-2026-109618-and-CVE-2026-109619-Exploit.svg)
- [https://github.com/zerbaliy3v/php2shell-CVE-2026-109618-CVE-2026-109619-Dorks](https://github.com/zerbaliy3v/php2shell-CVE-2026-109618-CVE-2026-109619-Dorks) :  ![starts](https://img.shields.io/github/stars/zerbaliy3v/php2shell-CVE-2026-109618-CVE-2026-109619-Dorks.svg) ![forks](https://img.shields.io/github/forks/zerbaliy3v/php2shell-CVE-2026-109618-CVE-2026-109619-Dorks.svg)
- [https://github.com/php2-shell/php2shell-POC-CVE-2026-109618-CVE-2026-109619](https://github.com/php2-shell/php2shell-POC-CVE-2026-109618-CVE-2026-109619) :  ![starts](https://img.shields.io/github/stars/php2-shell/php2shell-POC-CVE-2026-109618-CVE-2026-109619.svg) ![forks](https://img.shields.io/github/forks/php2-shell/php2shell-POC-CVE-2026-109618-CVE-2026-109619.svg)
- [https://github.com/EngOREOO/php2shell-CVE-2026-109618-CVE-2026-109619-PoC](https://github.com/EngOREOO/php2shell-CVE-2026-109618-CVE-2026-109619-PoC) :  ![starts](https://img.shields.io/github/stars/EngOREOO/php2shell-CVE-2026-109618-CVE-2026-109619-PoC.svg) ![forks](https://img.shields.io/github/forks/EngOREOO/php2shell-CVE-2026-109618-CVE-2026-109619-PoC.svg)
- [https://github.com/absholi7ly/Deep-Technical-Report-CVE-2026-109618-CVE-2026-109619-PHP2Shell](https://github.com/absholi7ly/Deep-Technical-Report-CVE-2026-109618-CVE-2026-109619-PHP2Shell) :  ![starts](https://img.shields.io/github/stars/absholi7ly/Deep-Technical-Report-CVE-2026-109618-CVE-2026-109619-PHP2Shell.svg) ![forks](https://img.shields.io/github/forks/absholi7ly/Deep-Technical-Report-CVE-2026-109618-CVE-2026-109619-PHP2Shell.svg)
- [https://github.com/nirzadokox/php2shell-vulnerability-check-for-CVE-2026-109618-CVE-2026-109619](https://github.com/nirzadokox/php2shell-vulnerability-check-for-CVE-2026-109618-CVE-2026-109619) :  ![starts](https://img.shields.io/github/stars/nirzadokox/php2shell-vulnerability-check-for-CVE-2026-109618-CVE-2026-109619.svg) ![forks](https://img.shields.io/github/forks/nirzadokox/php2shell-vulnerability-check-for-CVE-2026-109618-CVE-2026-109619.svg)
- [https://github.com/LeminEly/CVE-2026-109618-109619](https://github.com/LeminEly/CVE-2026-109618-109619) :  ![starts](https://img.shields.io/github/stars/LeminEly/CVE-2026-109618-109619.svg) ![forks](https://img.shields.io/github/forks/LeminEly/CVE-2026-109618-109619.svg)
- [https://github.com/Fazmin/PHP2Shell-CVE-2026-109618-CVE-2026-109619-Mitigation-Info-PoC](https://github.com/Fazmin/PHP2Shell-CVE-2026-109618-CVE-2026-109619-Mitigation-Info-PoC) :  ![starts](https://img.shields.io/github/stars/Fazmin/PHP2Shell-CVE-2026-109618-CVE-2026-109619-Mitigation-Info-PoC.svg) ![forks](https://img.shields.io/github/forks/Fazmin/PHP2Shell-CVE-2026-109618-CVE-2026-109619-Mitigation-Info-PoC.svg)
- [https://github.com/mefulton/CVE-2026-109618-analysis](https://github.com/mefulton/CVE-2026-109618-analysis) :  ![starts](https://img.shields.io/github/stars/mefulton/CVE-2026-109618-analysis.svg) ![forks](https://img.shields.io/github/forks/mefulton/CVE-2026-109618-analysis.svg)
- [https://github.com/Chr1s-T/php2shell-cve-2026-109618](https://github.com/Chr1s-T/php2shell-cve-2026-109618) :  ![starts](https://img.shields.io/github/stars/Chr1s-T/php2shell-cve-2026-109618.svg) ![forks](https://img.shields.io/github/forks/Chr1s-T/php2shell-cve-2026-109618.svg)
- [https://github.com/Ethen1212/php2shell-CVE-2026-109618](https://github.com/Ethen1212/php2shell-CVE-2026-109618) :  ![starts](https://img.shields.io/github/stars/Ethen1212/php2shell-CVE-2026-109618.svg) ![forks](https://img.shields.io/github/forks/Ethen1212/php2shell-CVE-2026-109618.svg)
- [https://github.com/jsrobinson3/php74-focal-cve-2026-109618](https://github.com/jsrobinson3/php74-focal-cve-2026-109618) :  ![starts](https://img.shields.io/github/stars/jsrobinson3/php74-focal-cve-2026-109618.svg) ![forks](https://img.shields.io/github/forks/jsrobinson3/php74-focal-cve-2026-109618.svg)
- [https://github.com/debjit604/PHP2Shell-CVE-2026-109618-CVE-2026-109619](https://github.com/debjit604/PHP2Shell-CVE-2026-109618-CVE-2026-109619) :  ![starts](https://img.shields.io/github/stars/debjit604/PHP2Shell-CVE-2026-109618-CVE-2026-109619.svg) ![forks](https://img.shields.io/github/forks/debjit604/PHP2Shell-CVE-2026-109618-CVE-2026-109619.svg)
- [https://github.com/MorphingYU/CVE-2026-109619](https://github.com/MorphingYU/CVE-2026-109619) :  ![starts](https://img.shields.io/github/stars/MorphingYU/CVE-2026-109619.svg) ![forks](https://img.shields.io/github/forks/MorphingYU/CVE-2026-109619.svg)
- [https://github.com/Ghost-Bx1/php-exploits-CVE-2026-109618-CVE-2026-109619-CVE-2024-4577](https://github.com/Ghost-Bx1/php-exploits-CVE-2026-109618-CVE-2026-109619-CVE-2024-4577) :  ![starts](https://img.shields.io/github/stars/Ghost-Bx1/php-exploits-CVE-2026-109618-CVE-2026-109619-CVE-2024-4577.svg) ![forks](https://img.shields.io/github/forks/Ghost-Bx1/php-exploits-CVE-2026-109618-CVE-2026-109619-CVE-2024-4577.svg)
- [https://github.com/EQSTLab/CVE-2026-109619](https://github.com/EQSTLab/CVE-2026-109619) :  ![starts](https://img.shields.io/github/stars/EQSTLab/CVE-2026-109619.svg) ![forks](https://img.shields.io/github/forks/EQSTLab/CVE-2026-109619.svg)
- [https://github.com/nurlanchip/PHP2SHELL-POC-Lab-CVE-2026-109618-CVE-2026-109619](https://github.com/nurlanchip/PHP2SHELL-POC-Lab-CVE-2026-109618-CVE-2026-109619) :  ![starts](https://img.shields.io/github/stars/nurlanchip/PHP2SHELL-POC-Lab-CVE-2026-109618-CVE-2026-109619.svg) ![forks](https://img.shields.io/github/forks/nurlanchip/PHP2SHELL-POC-Lab-CVE-2026-109618-CVE-2026-109619.svg)
- [https://github.com/skydwn/CVE-2026-109618](https://github.com/skydwn/CVE-2026-109618) :  ![starts](https://img.shields.io/github/stars/skydwn/CVE-2026-109618.svg) ![forks](https://img.shields.io/github/forks/skydwn/CVE-2026-109618.svg)
- [https://github.com/MorphingYU/CVE-2026-109618](https://github.com/MorphingYU/CVE-2026-109618) :  ![starts](https://img.shields.io/github/stars/MorphingYU/CVE-2026-109618.svg) ![forks](https://img.shields.io/github/forks/MorphingYU/CVE-2026-109618.svg)
- [https://github.com/tuwiliyt/cve-2026-109618](https://github.com/tuwiliyt/cve-2026-109618) :  ![starts](https://img.shields.io/github/stars/tuwiliyt/cve-2026-109618.svg) ![forks](https://img.shields.io/github/forks/tuwiliyt/cve-2026-109618.svg)
- [https://github.com/tuanhoma/CVE-2026-109618](https://github.com/tuanhoma/CVE-2026-109618) :  ![starts](https://img.shields.io/github/stars/tuanhoma/CVE-2026-109618.svg) ![forks](https://img.shields.io/github/forks/tuanhoma/CVE-2026-109618.svg)


## CVE-2026-8933
Due to a flaw in how privilege boundaries or security sandboxes are initialized when the binary runs under limited ambient capabilities, a local, unprivileged attacker can exploit this behavior to bypass intended restrictions and execute arbitrary code. Successful exploitation allows the local user to elevate their privileges to full root authority.

- [https://github.com/yifengchen-cc/CVE-2026-8933](https://github.com/yifengchen-cc/CVE-2026-8933) :  ![starts](https://img.shields.io/github/stars/yifengchen-cc/CVE-2026-8933.svg) ![forks](https://img.shields.io/github/forks/yifengchen-cc/CVE-2026-8933.svg)


## CVE-2026-4349
 A vulnerability was determined in Duende IdentityServer4 up to 4.1.2. The affected element is an unknown function of the file /connect/authorize of the component Token Renewal Endpoint. This manipulation of the argument id_token_hint causes improper authentication. It is possible to initiate the attack remotely. The attack is considered to have high complexity. The exploitability is described as difficult. This vulnerability only affects products that are no longer supported by the maintainer.

- [https://github.com/WJNKAC/CVE-2026-43499-OPPO-A5-PBBT30](https://github.com/WJNKAC/CVE-2026-43499-OPPO-A5-PBBT30) :  ![starts](https://img.shields.io/github/stars/WJNKAC/CVE-2026-43499-OPPO-A5-PBBT30.svg) ![forks](https://img.shields.io/github/forks/WJNKAC/CVE-2026-43499-OPPO-A5-PBBT30.svg)


## CVE-2026-3115
 Mattermost versions 11.2.x = 11.2.2, 10.11.x = 10.11.10, 11.4.x = 11.4.0, 11.3.x = 11.3.1 fail to apply view restrictions when retrieving group member IDs, which allows authenticated guest users to enumerate user IDs outside their allowed visibility scope via the group retrieval endpoint.. Mattermost Advisory ID: MMSA-2026-00594

- [https://github.com/Hardik007007/CVE-2026-31158-Boolean-Based-SQL-Injection-in-CRM-Login](https://github.com/Hardik007007/CVE-2026-31158-Boolean-Based-SQL-Injection-in-CRM-Login) :  ![starts](https://img.shields.io/github/stars/Hardik007007/CVE-2026-31158-Boolean-Based-SQL-Injection-in-CRM-Login.svg) ![forks](https://img.shields.io/github/forks/Hardik007007/CVE-2026-31158-Boolean-Based-SQL-Injection-in-CRM-Login.svg)


## CVE-2026-1096
 The Best-wp-google-map plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the 'latitude' and 'longitudinal' parameters of the 'google_map_view' shortcode in all versions up to, and including, 2.1 due to insufficient input sanitization and output escaping. This makes it possible for authenticated attackers, with Contributor-level access and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.

- [https://github.com/nukIeer/CVE-2026-109618-109619-checker](https://github.com/nukIeer/CVE-2026-109618-109619-checker) :  ![starts](https://img.shields.io/github/stars/nukIeer/CVE-2026-109618-109619-checker.svg) ![forks](https://img.shields.io/github/forks/nukIeer/CVE-2026-109618-109619-checker.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun.svg)


## CVE-2025-36911
 In key-based pairing, there is a possible ID due to a logic error in the code. This could lead to remote (proximal/adjacent) information disclosure of user's conversations and location with no additional execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/markmysler/wpair-cli](https://github.com/markmysler/wpair-cli) :  ![starts](https://img.shields.io/github/stars/markmysler/wpair-cli.svg) ![forks](https://img.shields.io/github/forks/markmysler/wpair-cli.svg)


## CVE-2025-32440
 NetAlertX is a network, presence scanner and alert framework. Prior to version 25.4.14, it is possible to bypass the authentication mechanism of NetAlertX to update settings without authentication. An attacker can trigger sensitive functions within util.php by sending crafted requests to /index.php. This issue has been patched in version 25.4.14.

- [https://github.com/jstjep00/CVE-2025-32440-netalertx-auth-bypass](https://github.com/jstjep00/CVE-2025-32440-netalertx-auth-bypass) :  ![starts](https://img.shields.io/github/stars/jstjep00/CVE-2025-32440-netalertx-auth-bypass.svg) ![forks](https://img.shields.io/github/forks/jstjep00/CVE-2025-32440-netalertx-auth-bypass.svg)


## CVE-2025-31161
 CrushFTP 10 before 10.8.4 and 11 before 11.3.1 allows authentication bypass and takeover of the crushadmin account (unless a DMZ proxy instance is used), as exploited in the wild in March and April 2025, aka "Unauthenticated HTTP(S) port access." A race condition exists in the AWS4-HMAC (compatible with S3) authorization method of the HTTP component of the FTP server. The server first verifies the existence of the user by performing a call to login_user_pass() with no password requirement. This will authenticate the session through the HMAC verification process and up until the server checks for user verification once more. The vulnerability can be further stabilized, eliminating the need for successfully triggering a race condition, by sending a mangled AWS4-HMAC header. By providing only the username and a following slash (/), the server will successfully find a username, which triggers the successful anypass authentication process, but the server will fail to find the expected SignedHeaders entry, resulting in an index-out-of-bounds error that stops the code from reaching the session cleanup. Together, these issues make it trivial to authenticate as any known or guessable user (e.g., crushadmin), and can lead to a full compromise of the system by obtaining an administrative account.

- [https://github.com/c4bsec/CVE-2025-31161](https://github.com/c4bsec/CVE-2025-31161) :  ![starts](https://img.shields.io/github/stars/c4bsec/CVE-2025-31161.svg) ![forks](https://img.shields.io/github/forks/c4bsec/CVE-2025-31161.svg)


## CVE-2025-24071
 Exposure of sensitive information to an unauthorized actor in Windows File Explorer allows an unauthorized attacker to perform spoofing over a network.

- [https://github.com/c4bsec/Windows-Explorer-CVE-2025-24071](https://github.com/c4bsec/Windows-Explorer-CVE-2025-24071) :  ![starts](https://img.shields.io/github/stars/c4bsec/Windows-Explorer-CVE-2025-24071.svg) ![forks](https://img.shields.io/github/forks/c4bsec/Windows-Explorer-CVE-2025-24071.svg)


## CVE-2025-10263
 Arm C1-Ultra, C1-Premium, Neoverse V3 & V3AE, Neoverse V2, Neoverse V1, Neoverse-N2, Neoverse-N1, Cortex-X925, Cortex-X4, Cortex-X3, Cortex-X2, Cortex-X1 & X1C, Cortex-A710, Cortex-A78, A78AE & A78C, Cortex-A77, Cortex-A76 & A76A may allow writes to resources owned by a higher exception level.

- [https://github.com/mikedejesushuembesrodriguez-max/erratumcheck](https://github.com/mikedejesushuembesrodriguez-max/erratumcheck) :  ![starts](https://img.shields.io/github/stars/mikedejesushuembesrodriguez-max/erratumcheck.svg) ![forks](https://img.shields.io/github/forks/mikedejesushuembesrodriguez-max/erratumcheck.svg)


## CVE-2025-7771
 ThrottleStop.sys, a legitimate driver, exposes two IOCTL interfaces that allow arbitrary read and write access to physical memory via the MmMapIoSpace function. This insecure implementation can be exploited by a malicious user-mode application to patch the running Windows kernel and invoke arbitrary kernel functions with ring-0 privileges. The vulnerability enables local attackers to execute arbitrary code in kernel context, resulting in privilege escalation and potential follow-on attacks, such as disabling security software or bypassing kernel-level protections. ThrottleStop.sys version 3.0.0.0 and possibly others are affected. Apply updates per vendor instructions.

- [https://github.com/datcathuh/driver-mapper](https://github.com/datcathuh/driver-mapper) :  ![starts](https://img.shields.io/github/stars/datcathuh/driver-mapper.svg) ![forks](https://img.shields.io/github/forks/datcathuh/driver-mapper.svg)


## CVE-2025-6647
The specific flaw exists within the parsing of U3D files. The issue results from the lack of proper validation of user-supplied data, which can result in a write past the end of an allocated object. An attacker can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-26644.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-alias](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-alias) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-alias.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-alias.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-tilde](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-tilde) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-tilde.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-tilde.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-zero-installs](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-zero-installs) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-zero-installs.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-zero-installs.svg)


## CVE-2025-0411
The specific flaw exists within the handling of archived files. When extracting files from a crafted archive that bears the Mark-of-the-Web, 7-Zip does not propagate the Mark-of-the-Web to the extracted files. An attacker can leverage this vulnerability to execute arbitrary code in the context of the current user. Was ZDI-CAN-25456.

- [https://github.com/c4bsec/7-Zip-CVE-2025-0411-POC](https://github.com/c4bsec/7-Zip-CVE-2025-0411-POC) :  ![starts](https://img.shields.io/github/stars/c4bsec/7-Zip-CVE-2025-0411-POC.svg) ![forks](https://img.shields.io/github/forks/c4bsec/7-Zip-CVE-2025-0411-POC.svg)


## CVE-2024-38998
 DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: none. Reason: This candidate was withdrawn by its CNA. Further investigation showed that it was not a security issue. Notes: none.

- [https://github.com/c4bsec/PP_CVE-2024-38998](https://github.com/c4bsec/PP_CVE-2024-38998) :  ![starts](https://img.shields.io/github/stars/c4bsec/PP_CVE-2024-38998.svg) ![forks](https://img.shields.io/github/forks/c4bsec/PP_CVE-2024-38998.svg)


## CVE-2024-25600
 Improper Control of Generation of Code ('Code Injection') vulnerability in Codeer Limited Bricks Builder allows Code Injection.This issue affects Bricks Builder: from n/a through 1.9.6.

- [https://github.com/zxc2009/TryHack3M-Bricks-Heist](https://github.com/zxc2009/TryHack3M-Bricks-Heist) :  ![starts](https://img.shields.io/github/stars/zxc2009/TryHack3M-Bricks-Heist.svg) ![forks](https://img.shields.io/github/forks/zxc2009/TryHack3M-Bricks-Heist.svg)


## CVE-2024-4577
 In PHP versions 8.1.* before 8.1.29, 8.2.* before 8.2.20, 8.3.* before 8.3.8, when using Apache and PHP-CGI on Windows, if the system is set up to use certain code pages, Windows may use "Best-Fit" behavior to replace characters in command line given to Win32 API functions. PHP CGI module may misinterpret those characters as PHP options, which may allow a malicious user to pass options to PHP binary being run, and thus reveal the source code of scripts, run arbitrary PHP code on the server, etc.

- [https://github.com/Ghost-Bx1/php-exploits-CVE-2026-109618-CVE-2026-109619-CVE-2024-4577](https://github.com/Ghost-Bx1/php-exploits-CVE-2026-109618-CVE-2026-109619-CVE-2024-4577) :  ![starts](https://img.shields.io/github/stars/Ghost-Bx1/php-exploits-CVE-2026-109618-CVE-2026-109619-CVE-2024-4577.svg) ![forks](https://img.shields.io/github/forks/Ghost-Bx1/php-exploits-CVE-2026-109618-CVE-2026-109619-CVE-2024-4577.svg)
- [https://github.com/Suleman-Elahi/php2shell-sentinel](https://github.com/Suleman-Elahi/php2shell-sentinel) :  ![starts](https://img.shields.io/github/stars/Suleman-Elahi/php2shell-sentinel.svg) ![forks](https://img.shields.io/github/forks/Suleman-Elahi/php2shell-sentinel.svg)


## CVE-2022-24707
 Anuko Time Tracker is an open source, web-based time tracking application written in PHP. UNION SQL injection and time-based blind injection vulnerabilities existed in Time Tracker Puncher plugin in versions of anuko timetracker prior to 1.20.0.5642. This was happening because the Puncher plugin was reusing code from other places and was relying on an unsanitized date parameter in POST requests. Because the parameter was not checked, it was possible to craft POST requests with malicious SQL for Time Tracker database. This issue has been resolved in in version 1.20.0.5642. Users unable to upgrade are advised to add their own checks to input.

- [https://github.com/c0gnit00/CVE-2022-24707](https://github.com/c0gnit00/CVE-2022-24707) :  ![starts](https://img.shields.io/github/stars/c0gnit00/CVE-2022-24707.svg) ![forks](https://img.shields.io/github/forks/c0gnit00/CVE-2022-24707.svg)


## CVE-2021-4422
 The POST SMTP Mailer plugin for WordPress is vulnerable to Cross-Site Request Forgery in versions up to, and including, 2.0.20. This is due to missing or incorrect nonce validation on the handleCsvExport() function. This makes it possible for unauthenticated attackers to trigger a CSV export via a forged request granted they can trick a site administrator into performing an action such as clicking on a link.

- [https://github.com/Super-Binary/cve-2021-44228](https://github.com/Super-Binary/cve-2021-44228) :  ![starts](https://img.shields.io/github/stars/Super-Binary/cve-2021-44228.svg) ![forks](https://img.shields.io/github/forks/Super-Binary/cve-2021-44228.svg)


## CVE-2021-4177
 livehelperchat is vulnerable to Generation of Error Message Containing Sensitive Information

- [https://github.com/Park123r/CVE-2021-41773](https://github.com/Park123r/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/Park123r/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/Park123r/CVE-2021-41773.svg)


## CVE-2019-7304
 Canonical snapd before version 2.37.1 incorrectly performed socket owner validation, allowing an attacker to run arbitrary commands as root. This issue affects: Canonical snapd versions prior to 2.37.1.

- [https://github.com/Kaine105/Document-Linux-Privilege-Escalation](https://github.com/Kaine105/Document-Linux-Privilege-Escalation) :  ![starts](https://img.shields.io/github/stars/Kaine105/Document-Linux-Privilege-Escalation.svg) ![forks](https://img.shields.io/github/forks/Kaine105/Document-Linux-Privilege-Escalation.svg)


## CVE-2019-2215
 A use-after-free in binder.c allows an elevation of privilege from an application to the Linux Kernel. No user interaction is required to exploit this vulnerability, however exploitation does require either the installation of a malicious local application or a separate vulnerability in a network facing application.Product: AndroidAndroid ID: A-141720095

- [https://github.com/xushihushuo-art/cve-2019-2215-skyworth](https://github.com/xushihushuo-art/cve-2019-2215-skyworth) :  ![starts](https://img.shields.io/github/stars/xushihushuo-art/cve-2019-2215-skyworth.svg) ![forks](https://img.shields.io/github/forks/xushihushuo-art/cve-2019-2215-skyworth.svg)


## CVE-2018-4878
 A use-after-free vulnerability was discovered in Adobe Flash Player before 28.0.0.161. This vulnerability occurs due to a dangling pointer in the Primetime SDK related to media player handling of listener objects. A successful attack can lead to arbitrary code execution. This was exploited in the wild in January and February 2018.

- [https://github.com/tsondt/CVE-2018-4878](https://github.com/tsondt/CVE-2018-4878) :  ![starts](https://img.shields.io/github/stars/tsondt/CVE-2018-4878.svg) ![forks](https://img.shields.io/github/forks/tsondt/CVE-2018-4878.svg)


## CVE-2016-10961
 The colorway theme before 3.4.2 for WordPress has XSS via the contactName parameter.

- [https://github.com/tuanhoma/CVE-2016-109618--TryHackMe-](https://github.com/tuanhoma/CVE-2016-109618--TryHackMe-) :  ![starts](https://img.shields.io/github/stars/tuanhoma/CVE-2016-109618--TryHackMe-.svg) ![forks](https://img.shields.io/github/forks/tuanhoma/CVE-2016-109618--TryHackMe-.svg)

