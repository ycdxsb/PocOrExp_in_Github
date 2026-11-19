# Update 2026-11-19
## CVE-2026-130354
 phpMyFAQ 4.1.0 before 4.1.12 and 4.2.0-alpha before 4.2.0-RC.2 contains an authentication bypass vulnerability in POST /api/webauthn/prepare that creates accounts as active, bypassing manual activation and domain whitelisting. Anonymous attackers can obtain the freely issued CSRF token and register an activated account with an unverified email to access registered-user-only content and functions.

- [https://github.com/googlesky/CVE-2026-130354](https://github.com/googlesky/CVE-2026-130354) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-130354.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-130354.svg)


## CVE-2026-130347
 phpMyFAQ before 4.1.12 and 4.2.0-alpha before 4.2.0-RC.2 contains an authentication bypass in password reset, letting external-identity accounts receive local passwords. Attackers with mailbox access can request reset tokens for OIDC, Keycloak, Entra ID, LDAP, SSO, or WebAuthn accounts and log in locally, skipping IdP MFA and deprovisioning.

- [https://github.com/googlesky/CVE-2026-130347](https://github.com/googlesky/CVE-2026-130347) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-130347.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-130347.svg)


## CVE-2026-130335
 Info-ZIP Zip 3.0 (and 3.1 beta through 3.1c) allows OS command injection by an attacker who controls the command line. The victim must use the -T option followed by a filename containing shell metacharacters, on a platform (such as Linux) where a suitable shell is run. This occurs because the system C library function is used. NOTE: there is no known common scenario in which an untrusted filename reaches a zip -T call.

- [https://github.com/googlesky/CVE-2026-130335](https://github.com/googlesky/CVE-2026-130335) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-130335.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-130335.svg)


## CVE-2026-123158
 sshd in OpenSSH before 10.6p2 on Linux, when musl libc is used without PAM, lacks a workaround for a password authentication bypass (related to misinterpretation of whether a string is intended to be a password hash). For some configurations of accounts, any password between 256 and 1024 characters succeeds. An example of a platform using musl libc without PAM is Alpine Linux.

- [https://github.com/Quaerendir/cve-2026-123158-audit](https://github.com/Quaerendir/cve-2026-123158-audit) :  ![starts](https://img.shields.io/github/stars/Quaerendir/cve-2026-123158-audit.svg) ![forks](https://img.shields.io/github/forks/Quaerendir/cve-2026-123158-audit.svg)


## CVE-2026-121684
 The Soledad theme for WordPress is vulnerable to unauthenticated Remote Code Execution in versions up to, and including, 8.7.7 The public penci_more_post_ajax AJAX action feeds infeedads[ads_code] (base64+urldecoded) to penci_safe_shortcode(), whose allowlist regex inspects only the hyphen-truncated outer shortcode name (e.g. 'adinserter') and never the nested [elementor-element k=.. data=..] tag, so do_shortcode() renders an attacker-chosen Elementor element. The rendered penci-featured-sliders widget passes its unsanitized 'style' setting to include dirname(__FILE__)."/{$style}.php", a path-traversal local file inclusion.

- [https://github.com/im0xfay/CVE-2026-121684](https://github.com/im0xfay/CVE-2026-121684) :  ![starts](https://img.shields.io/github/stars/im0xfay/CVE-2026-121684.svg) ![forks](https://img.shields.io/github/forks/im0xfay/CVE-2026-121684.svg)


## CVE-2026-114938
 Vulnerability in the Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component: Compiler).  Supported versions that are affected are Oracle Java SE: 8u511b33-perf, 17.0.21.0.3, 21.0.13.0.3, 25.0.5.0.3, 27.0.1.0.3; Oracle GraalVM for JDK: 17.0.21.0.3 and  21.0.13.0.3; Oracle GraalVM Enterprise Edition: 21.3.20.0.3. Difficult to exploit vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition.  Successful attacks of this vulnerability can result in takeover of Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition. Note: This vulnerability can only be exploited by supplying data to APIs in the specified Component without using Untrusted Java Web Start applications or Untrusted Java applets, such as through a web service. CVSS 3.1 Base Score 8.1 (Confidentiality, Integrity and Availability impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/ashrafzaryouh/CVE-2026-114938](https://github.com/ashrafzaryouh/CVE-2026-114938) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-114938.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-114938.svg)
- [https://github.com/ikow/java4shell-poc](https://github.com/ikow/java4shell-poc) :  ![starts](https://img.shields.io/github/stars/ikow/java4shell-poc.svg) ![forks](https://img.shields.io/github/forks/ikow/java4shell-poc.svg)
- [https://github.com/theori-io/java4shell-runtime-patch-CVE-2026-114938](https://github.com/theori-io/java4shell-runtime-patch-CVE-2026-114938) :  ![starts](https://img.shields.io/github/stars/theori-io/java4shell-runtime-patch-CVE-2026-114938.svg) ![forks](https://img.shields.io/github/forks/theori-io/java4shell-runtime-patch-CVE-2026-114938.svg)
- [https://github.com/r3dvei1/java4shell](https://github.com/r3dvei1/java4shell) :  ![starts](https://img.shields.io/github/stars/r3dvei1/java4shell.svg) ![forks](https://img.shields.io/github/forks/r3dvei1/java4shell.svg)
- [https://github.com/arturo-b-cmu/CVE-2026-114938](https://github.com/arturo-b-cmu/CVE-2026-114938) :  ![starts](https://img.shields.io/github/stars/arturo-b-cmu/CVE-2026-114938.svg) ![forks](https://img.shields.io/github/forks/arturo-b-cmu/CVE-2026-114938.svg)
- [https://github.com/Pwned-test/cve-2026-114938-java17-PoC](https://github.com/Pwned-test/cve-2026-114938-java17-PoC) :  ![starts](https://img.shields.io/github/stars/Pwned-test/cve-2026-114938-java17-PoC.svg) ![forks](https://img.shields.io/github/forks/Pwned-test/cve-2026-114938-java17-PoC.svg)
- [https://github.com/jeffschafer/BigFix-Java4Shell-CVE-2026-114938-Scanner](https://github.com/jeffschafer/BigFix-Java4Shell-CVE-2026-114938-Scanner) :  ![starts](https://img.shields.io/github/stars/jeffschafer/BigFix-Java4Shell-CVE-2026-114938-Scanner.svg) ![forks](https://img.shields.io/github/forks/jeffschafer/BigFix-Java4Shell-CVE-2026-114938-Scanner.svg)
- [https://github.com/jeffschafer/MANUAL-Scanner-Java4Shell-CVE-2026-114938](https://github.com/jeffschafer/MANUAL-Scanner-Java4Shell-CVE-2026-114938) :  ![starts](https://img.shields.io/github/stars/jeffschafer/MANUAL-Scanner-Java4Shell-CVE-2026-114938.svg) ![forks](https://img.shields.io/github/forks/jeffschafer/MANUAL-Scanner-Java4Shell-CVE-2026-114938.svg)


## CVE-2026-111497
Users need to update any Brotli libraries or binaries between 1.0.3 through 1.2.0 to the latest available version: 1.0.10 or 1.1.1 or 1.2.1.

- [https://github.com/proxy0x/CVE-2026-111497](https://github.com/proxy0x/CVE-2026-111497) :  ![starts](https://img.shields.io/github/stars/proxy0x/CVE-2026-111497.svg) ![forks](https://img.shields.io/github/forks/proxy0x/CVE-2026-111497.svg)


## CVE-2026-109619
 PHP has various global state that temporarily points into request memory. In some scenarios, global state may not be correctly reset, or may be repopulated after being reset. The global state may then refer to request memory even after it has been freed. Subsequent requests may read or branch on this stale state before it is fully initialized. Multiple strategies can trigger this condition and produce remote code execution (RCE).

- [https://github.com/cloudducoeur/ansible-playbook-CVE-2026-109618](https://github.com/cloudducoeur/ansible-playbook-CVE-2026-109618) :  ![starts](https://img.shields.io/github/stars/cloudducoeur/ansible-playbook-CVE-2026-109618.svg) ![forks](https://img.shields.io/github/forks/cloudducoeur/ansible-playbook-CVE-2026-109618.svg)


## CVE-2026-109618
 PHP uses longjmp() for out-of-memory (OOM) errors to exit the current context and abort handling of the request. Some contexts may not properly account for this scenario and leave request memory in an uninitialized state before performing an allocation. The subsequent request cleanup procedure may read or branch on this memory. Multiple OOM strategies can consistently trigger this condition and lead to remote code execution (RCE).

- [https://github.com/toxy4ny/php2shell-checker](https://github.com/toxy4ny/php2shell-checker) :  ![starts](https://img.shields.io/github/stars/toxy4ny/php2shell-checker.svg) ![forks](https://img.shields.io/github/forks/toxy4ny/php2shell-checker.svg)


## CVE-2026-104100
 Teable is an AI spreadsheet for business. Prior to release.2026-07-21T11-27-40Z.2320, a registered user can supply path traversal sequences in the hash field accepted by POST /api/attachments/signature when the default local storage provider is in use. In apps/nestjs-backend/src/features/attachments/plugins/local.ts, LocalStorage.presigned uses the client-controlled hash as the storage filename, and LocalStorage.save resolves that path and copies the uploaded request body without calling assertPathWithinStorage on the write path. The read path uses the jail, but the write path does not, allowing the resolved destination to escape the configured storage directory. Because the backend container runs as uid 0, the attacker can write or overwrite arbitrary root-owned files, which can corrupt the instance or lead to root code execution. Object-storage deployments that do not use LocalStorage.save are not affected by this sink. This issue is fixed in release.2026-07-21T11-27-40Z.2320.

- [https://github.com/Saku0512/CVE-2026-104100-poc](https://github.com/Saku0512/CVE-2026-104100-poc) :  ![starts](https://img.shields.io/github/stars/Saku0512/CVE-2026-104100-poc.svg) ![forks](https://img.shields.io/github/forks/Saku0512/CVE-2026-104100-poc.svg)


## CVE-2026-103931
 Instatic is an open source visual content management system for building static websites. Prior to 0.0.14, isSafeUrl() and safeUrl() in src/core/html-sanitize/index.ts remove tabs, newlines, carriage returns, and characters handled by String.prototype.trim(), but leave other leading C0 control characters that browsers discard before parsing a URL scheme. A low-privileged editor can place a dangerous URL behind one of those controls in a URL property or custom HTML attribute, allowing src/core/publisher/escapeProps.ts and the shared URL sanitizer to emit it into rendered content. When an Owner or Admin activates the element in the same-origin admin editor canvas, script executes with the victim's application authority and can drive admin APIs to read protected data, create an owner account, or install a plugin. This issue is fixed in version 0.0.14.

- [https://github.com/overgrowncarrot1/Instatic-Stored-XSS-CVE-2026-103931](https://github.com/overgrowncarrot1/Instatic-Stored-XSS-CVE-2026-103931) :  ![starts](https://img.shields.io/github/stars/overgrowncarrot1/Instatic-Stored-XSS-CVE-2026-103931.svg) ![forks](https://img.shields.io/github/forks/overgrowncarrot1/Instatic-Stored-XSS-CVE-2026-103931.svg)


## CVE-2026-99288
with reqsk_put() instead of freeing the request directly.

- [https://github.com/re4/noisytcp-poc](https://github.com/re4/noisytcp-poc) :  ![starts](https://img.shields.io/github/stars/re4/noisytcp-poc.svg) ![forks](https://img.shields.io/github/forks/re4/noisytcp-poc.svg)
- [https://github.com/mustafasaydam/CVE-2026-99288---NoisyTCP-Exploit](https://github.com/mustafasaydam/CVE-2026-99288---NoisyTCP-Exploit) :  ![starts](https://img.shields.io/github/stars/mustafasaydam/CVE-2026-99288---NoisyTCP-Exploit.svg) ![forks](https://img.shields.io/github/forks/mustafasaydam/CVE-2026-99288---NoisyTCP-Exploit.svg)
- [https://github.com/donxud/NoisyTCP-Blue-Team-Playbook](https://github.com/donxud/NoisyTCP-Blue-Team-Playbook) :  ![starts](https://img.shields.io/github/stars/donxud/NoisyTCP-Blue-Team-Playbook.svg) ![forks](https://img.shields.io/github/forks/donxud/NoisyTCP-Blue-Team-Playbook.svg)


## CVE-2026-98260
[ tglx: Move the cleanup right after de_thread() ]

- [https://github.com/CYB3R0ID694/Shark-Moto](https://github.com/CYB3R0ID694/Shark-Moto) :  ![starts](https://img.shields.io/github/stars/CYB3R0ID694/Shark-Moto.svg) ![forks](https://img.shields.io/github/forks/CYB3R0ID694/Shark-Moto.svg)
- [https://github.com/yxc0915/cve-2026-98260-ppg-an00](https://github.com/yxc0915/cve-2026-98260-ppg-an00) :  ![starts](https://img.shields.io/github/stars/yxc0915/cve-2026-98260-ppg-an00.svg) ![forks](https://img.shields.io/github/forks/yxc0915/cve-2026-98260-ppg-an00.svg)


## CVE-2026-90436
As Axis 1 has been EOL we recommend you migrate to a different SOAP engine, such as Apache Axis 2/Java. Alternatively you could use a build of Axis with the patch from https://github.com/apache/axis-axis1-java/commit/41f3b4e8d04e310ca81f86b92630ab2c11d608bd applied. The Apache Axis project does not expect to create an Axis 1.x release fixing this problem.

- [https://github.com/dinosn/axis-cve-2026-90436-lab-poc](https://github.com/dinosn/axis-cve-2026-90436-lab-poc) :  ![starts](https://img.shields.io/github/stars/dinosn/axis-cve-2026-90436-lab-poc.svg) ![forks](https://img.shields.io/github/forks/dinosn/axis-cve-2026-90436-lab-poc.svg)
- [https://github.com/foxcornlab/confluence-axis-scanner](https://github.com/foxcornlab/confluence-axis-scanner) :  ![starts](https://img.shields.io/github/stars/foxcornlab/confluence-axis-scanner.svg) ![forks](https://img.shields.io/github/forks/foxcornlab/confluence-axis-scanner.svg)


## CVE-2026-82025
 WP File Manager before 8.0.7 contains a file upload restriction bypass vulnerability that allows authenticated administrators to upload arbitrary PHP files by exploiting a misconfigured elFinder connector in file_folder_manager.php where an empty uploadDeny list causes allowPutMime() to unconditionally return true, bypassing the uploadAllow restriction. Attackers can upload a .php file directly or upload it under an allowed filename and then rename it via the rename connector command, achieving remote code execution as the web server user.

- [https://github.com/rxsklife/CVE-2026-82025](https://github.com/rxsklife/CVE-2026-82025) :  ![starts](https://img.shields.io/github/stars/rxsklife/CVE-2026-82025.svg) ![forks](https://img.shields.io/github/forks/rxsklife/CVE-2026-82025.svg)


## CVE-2026-63219
 GeoNetwork is a catalog application to manage spatially referenced resources. Prior to versions 4.4.12 and 4.2.17, the API endpoint for creating a new formatter via file upload is unprotected and allows the upload of external uncontrolled files. An unauthenticated attacker can upload arbitrary `.xsl` or `.zip` formatter files to the server.  An unauthenticated attacker can write arbitrary files into the GeoNetwork formatter directory. On its own this constitutes unauthorized write access to server storage. The issue is patched in GeoNetwork versions 4.4.12 and 4.2.17.

- [https://github.com/Cyberuser-hash/CVE-2026-63219](https://github.com/Cyberuser-hash/CVE-2026-63219) :  ![starts](https://img.shields.io/github/stars/Cyberuser-hash/CVE-2026-63219.svg) ![forks](https://img.shields.io/github/forks/Cyberuser-hash/CVE-2026-63219.svg)
- [https://github.com/c0gnit00/GNSShell](https://github.com/c0gnit00/GNSShell) :  ![starts](https://img.shields.io/github/stars/c0gnit00/GNSShell.svg) ![forks](https://img.shields.io/github/forks/c0gnit00/GNSShell.svg)


## CVE-2026-59309
 VMware vCenter contains an authentication bypass vulnerability in the VMware Directory Service. A malicious actor with network access to vCenter may exploit this issue to bypass authentication and gain unauthorized access to the system.

- [https://github.com/JHenryArcaneCipher/CVE-2026-59309-PoC](https://github.com/JHenryArcaneCipher/CVE-2026-59309-PoC) :  ![starts](https://img.shields.io/github/stars/JHenryArcaneCipher/CVE-2026-59309-PoC.svg) ![forks](https://img.shields.io/github/forks/JHenryArcaneCipher/CVE-2026-59309-PoC.svg)


## CVE-2026-58400
`java.lang.Runtime.exec()` or `java.lang.ProcessBuilder` directly, achieving arbitrary command execution as the GeoNetwork process user. A user with sufficient privileges to upload a formatter can deliver a `.xsl` file containing Java extension call that execute arbitrary OS commands with the privileges of the GeoNetwork process. The issue is patched in GeoNetwork versions 4.4.12 and 4.2.17.

- [https://github.com/Cyberuser-hash/CVE-2026-63219](https://github.com/Cyberuser-hash/CVE-2026-63219) :  ![starts](https://img.shields.io/github/stars/Cyberuser-hash/CVE-2026-63219.svg) ![forks](https://img.shields.io/github/forks/Cyberuser-hash/CVE-2026-63219.svg)
- [https://github.com/c0gnit00/GNSShell](https://github.com/c0gnit00/GNSShell) :  ![starts](https://img.shields.io/github/stars/c0gnit00/GNSShell.svg) ![forks](https://img.shields.io/github/forks/c0gnit00/GNSShell.svg)


## CVE-2026-43499
  	changelog ]

- [https://github.com/WitAqua-tools/Root-My-Device](https://github.com/WitAqua-tools/Root-My-Device) :  ![starts](https://img.shields.io/github/stars/WitAqua-tools/Root-My-Device.svg) ![forks](https://img.shields.io/github/forks/WitAqua-tools/Root-My-Device.svg)


## CVE-2026-34990
 OpenPrinting CUPS is an open source printing system for Linux and other Unix-like operating systems. In versions 2.4.16 and prior, a local unprivileged user can coerce cupsd into authenticating to an attacker-controlled localhost IPP service with a reusable Authorization: Local ... token. That token is enough to drive /admin/ requests on localhost, and the attacker can combine CUPS-Create-Local-Printer with printer-is-shared=true to persist a file:///... queue even though the normal FileDevice policy rejects such URIs. Printing to that queue gives an arbitrary root file overwrite; the PoC below uses that primitive to drop a sudoers fragment and demonstrate root command execution. At time of publication, there are no publicly available patches.

- [https://github.com/deboravazx/cups-2.4.16-lpe](https://github.com/deboravazx/cups-2.4.16-lpe) :  ![starts](https://img.shields.io/github/stars/deboravazx/cups-2.4.16-lpe.svg) ![forks](https://img.shields.io/github/forks/deboravazx/cups-2.4.16-lpe.svg)


## CVE-2026-31431
AD directly.

- [https://github.com/pulentoski/CVE-2026-31431](https://github.com/pulentoski/CVE-2026-31431) :  ![starts](https://img.shields.io/github/stars/pulentoski/CVE-2026-31431.svg) ![forks](https://img.shields.io/github/forks/pulentoski/CVE-2026-31431.svg)


## CVE-2026-29013
 libcoap contains out-of-bounds read vulnerabilities in OSCORE Appendix B.2 CBOR unwrap handling where get_byte_inc() in src/oscore/oscore_cbor.c relies solely on assert() for bounds checking, which is removed in release builds compiled with NDEBUG. Attackers can send crafted CoAP requests with malformed OSCORE options or responses during OSCORE negotiation to trigger out-of-bounds reads during CBOR parsing and potentially cause out-of-bounds reads through integer wraparound in allocation size computation.

- [https://github.com/DoraYeh1519/cve-2026-29013-libcoap-oscore-repro](https://github.com/DoraYeh1519/cve-2026-29013-libcoap-oscore-repro) :  ![starts](https://img.shields.io/github/stars/DoraYeh1519/cve-2026-29013-libcoap-oscore-repro.svg) ![forks](https://img.shields.io/github/forks/DoraYeh1519/cve-2026-29013-libcoap-oscore-repro.svg)


## CVE-2026-12722
This issue affects FTC E-Commerce Management Panel: before 1.0.2.

- [https://github.com/rahulreddykarne/CVE-2026-127222-sglang](https://github.com/rahulreddykarne/CVE-2026-127222-sglang) :  ![starts](https://img.shields.io/github/stars/rahulreddykarne/CVE-2026-127222-sglang.svg) ![forks](https://img.shields.io/github/forks/rahulreddykarne/CVE-2026-127222-sglang.svg)


## CVE-2026-10961
 Use after free in Chrome for iOS in Google Chrome on iOS prior to 149.0.7827.53 allowed a remote attacker who had compromised the renderer process to potentially perform a sandbox escape via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/DandanLLab/PHP-5.6.40-CVE-2026-109618-109619](https://github.com/DandanLLab/PHP-5.6.40-CVE-2026-109618-109619) :  ![starts](https://img.shields.io/github/stars/DandanLLab/PHP-5.6.40-CVE-2026-109618-109619.svg) ![forks](https://img.shields.io/github/forks/DandanLLab/PHP-5.6.40-CVE-2026-109618-109619.svg)


## CVE-2026-4349
 A vulnerability was determined in Duende IdentityServer4 up to 4.1.2. The affected element is an unknown function of the file /connect/authorize of the component Token Renewal Endpoint. This manipulation of the argument id_token_hint causes improper authentication. It is possible to initiate the attack remotely. The attack is considered to have high complexity. The exploitability is described as difficult. This vulnerability only affects products that are no longer supported by the maintainer.

- [https://github.com/dnlid/CVE-2026-43499](https://github.com/dnlid/CVE-2026-43499) :  ![starts](https://img.shields.io/github/stars/dnlid/CVE-2026-43499.svg) ![forks](https://img.shields.io/github/forks/dnlid/CVE-2026-43499.svg)


## CVE-2026-3143
 The Total Upkeep – WordPress Backup Plugin plus Restore & Migrate by BoldGrid plugin for WordPress is vulnerable to unauthorized modification of data due to a missing capability check on the 'wp_ajax_cli_cancel' function in all versions up to, and including, 1.17.1. This makes it possible for unauthenticated attackers to cancel a pending rollback, potentially preventing a WordPress installation from automatically reverting a failed update.

- [https://github.com/sec17br/CVE-2026-31431-Copy-Fail](https://github.com/sec17br/CVE-2026-31431-Copy-Fail) :  ![starts](https://img.shields.io/github/stars/sec17br/CVE-2026-31431-Copy-Fail.svg) ![forks](https://img.shields.io/github/forks/sec17br/CVE-2026-31431-Copy-Fail.svg)


## CVE-2026-1096
 The Best-wp-google-map plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the 'latitude' and 'longitudinal' parameters of the 'google_map_view' shortcode in all versions up to, and including, 2.1 due to insufficient input sanitization and output escaping. This makes it possible for authenticated attackers, with Contributor-level access and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.

- [https://github.com/WallcroftUK/CVE-2026-109619](https://github.com/WallcroftUK/CVE-2026-109619) :  ![starts](https://img.shields.io/github/stars/WallcroftUK/CVE-2026-109619.svg) ![forks](https://img.shields.io/github/forks/WallcroftUK/CVE-2026-109619.svg)


## CVE-2025-5518
This issue affects BILGER: before 2.4.6.

- [https://github.com/Nkwenti-Severian-Ndongtsop/POC_react2shell_CVE-2025-55182](https://github.com/Nkwenti-Severian-Ndongtsop/POC_react2shell_CVE-2025-55182) :  ![starts](https://img.shields.io/github/stars/Nkwenti-Severian-Ndongtsop/POC_react2shell_CVE-2025-55182.svg) ![forks](https://img.shields.io/github/forks/Nkwenti-Severian-Ndongtsop/POC_react2shell_CVE-2025-55182.svg)


## CVE-2025-0578
 A vulnerability was found in Facile Sistemas Cloud Apps up to 20250107. It has been classified as problematic. Affected is an unknown function of the file /account/forgotpassword of the component Password Reset Handler. The manipulation of the argument reterros leads to cross site scripting. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used. The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/Amoru-Bek/FreePBX-CVE-2025-057819-Remote-Code-Execution](https://github.com/Amoru-Bek/FreePBX-CVE-2025-057819-Remote-Code-Execution) :  ![starts](https://img.shields.io/github/stars/Amoru-Bek/FreePBX-CVE-2025-057819-Remote-Code-Execution.svg) ![forks](https://img.shields.io/github/forks/Amoru-Bek/FreePBX-CVE-2025-057819-Remote-Code-Execution.svg)


## CVE-2024-41570
 An Unauthenticated Server-Side Request Forgery (SSRF) in demon callback handling in Havoc 2 0.7 allows attackers to send arbitrary network traffic originating from the team server.

- [https://github.com/0k1dok1/havoc-CVE-2024-41570](https://github.com/0k1dok1/havoc-CVE-2024-41570) :  ![starts](https://img.shields.io/github/stars/0k1dok1/havoc-CVE-2024-41570.svg) ![forks](https://img.shields.io/github/forks/0k1dok1/havoc-CVE-2024-41570.svg)


## CVE-2024-23692
 Rejetto HTTP File Server, up to and including version 2.3m, is vulnerable to a template injection vulnerability. This vulnerability allows a remote, unauthenticated attacker to execute arbitrary commands on the affected system by sending a specially crafted HTTP request. As of the CVE assignment date, Rejetto HFS 2.3m is no longer supported.

- [https://github.com/Lolicks/hfs-check](https://github.com/Lolicks/hfs-check) :  ![starts](https://img.shields.io/github/stars/Lolicks/hfs-check.svg) ![forks](https://img.shields.io/github/forks/Lolicks/hfs-check.svg)
- [https://github.com/Lolicks/hfs2xray](https://github.com/Lolicks/hfs2xray) :  ![starts](https://img.shields.io/github/stars/Lolicks/hfs2xray.svg) ![forks](https://img.shields.io/github/forks/Lolicks/hfs2xray.svg)


## CVE-2024-21626
 runc is a CLI tool for spawning and running containers on Linux according to the OCI specification. In runc 1.1.11 and earlier, due to an internal file descriptor leak, an attacker could cause a newly-spawned container process (from runc exec) to have a working directory in the host filesystem namespace, allowing for a container escape by giving access to the host filesystem ("attack 2"). The same attack could be used by a malicious image to allow a container process to gain access to the host filesystem through runc run ("attack 1"). Variants of attacks 1 and 2 could be also be used to overwrite semi-arbitrary host binaries, allowing for complete container escapes ("attack 3a" and "attack 3b"). runc 1.1.12 includes patches for this issue.

- [https://github.com/ghs053020-stack/cve-2024-21626-ctf](https://github.com/ghs053020-stack/cve-2024-21626-ctf) :  ![starts](https://img.shields.io/github/stars/ghs053020-stack/cve-2024-21626-ctf.svg) ![forks](https://img.shields.io/github/forks/ghs053020-stack/cve-2024-21626-ctf.svg)


## CVE-2023-33107
 Memory corruption in Graphics Linux while assigning shared virtual memory region during IOCTL call.

- [https://github.com/justwezzz/CVE-2023-33107-908SH](https://github.com/justwezzz/CVE-2023-33107-908SH) :  ![starts](https://img.shields.io/github/stars/justwezzz/CVE-2023-33107-908SH.svg) ![forks](https://img.shields.io/github/forks/justwezzz/CVE-2023-33107-908SH.svg)


## CVE-2023-4863
 Heap buffer overflow in libwebp in Google Chrome prior to 116.0.5845.187 and libwebp 1.3.2 allowed a remote attacker to perform an out of bounds memory write via a crafted HTML page. (Chromium security severity: Critical)

- [https://github.com/joekrump/expo-image-libwebp-repro](https://github.com/joekrump/expo-image-libwebp-repro) :  ![starts](https://img.shields.io/github/stars/joekrump/expo-image-libwebp-repro.svg) ![forks](https://img.shields.io/github/forks/joekrump/expo-image-libwebp-repro.svg)


## CVE-2022-22706
 Arm Mali GPU Kernel Driver allows a non-privileged user to achieve write access to read-only memory pages. This affects Midgard r26p0 through r31p0, Bifrost r0p0 through r35p0, and Valhall r19p0 through r35p0.

- [https://github.com/hrx114514x/vivo-y70s-temp-root](https://github.com/hrx114514x/vivo-y70s-temp-root) :  ![starts](https://img.shields.io/github/stars/hrx114514x/vivo-y70s-temp-root.svg) ![forks](https://img.shields.io/github/forks/hrx114514x/vivo-y70s-temp-root.svg)


## CVE-2021-4177
 livehelperchat is vulnerable to Generation of Error Message Containing Sensitive Information

- [https://github.com/xMohamed0/CVE-2021-41773](https://github.com/xMohamed0/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/xMohamed0/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/xMohamed0/CVE-2021-41773.svg)
- [https://github.com/sixpacksecurity/CVE-2021-41773](https://github.com/sixpacksecurity/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/sixpacksecurity/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/sixpacksecurity/CVE-2021-41773.svg)
- [https://github.com/xlondra/CVE-2021-41773](https://github.com/xlondra/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/xlondra/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/xlondra/CVE-2021-41773.svg)


## CVE-2019-9193
 In PostgreSQL 9.3 through 11.2, the "COPY TO/FROM PROGRAM" function allows superusers and users in the 'pg_execute_server_program' group to execute arbitrary code in the context of the database's operating system user. This functionality is enabled by default and can be abused to run arbitrary operating system commands on Windows, Linux, and macOS. NOTE: Third parties claim/state this is not an issue because PostgreSQL functionality for ‘COPY TO/FROM PROGRAM’ is acting as intended. References state that in PostgreSQL, a superuser can execute commands as the server user without using the ‘COPY FROM PROGRAM’.

- [https://github.com/Exript/CVE-2019-9193-exploit](https://github.com/Exript/CVE-2019-9193-exploit) :  ![starts](https://img.shields.io/github/stars/Exript/CVE-2019-9193-exploit.svg) ![forks](https://img.shields.io/github/forks/Exript/CVE-2019-9193-exploit.svg)


## CVE-2018-18955
 In the Linux kernel 4.15.x through 4.19.x before 4.19.2, map_write() in kernel/user_namespace.c allows privilege escalation because it mishandles nested user namespaces with more than 5 UID or GID ranges. A user who has CAP_SYS_ADMIN in an affected user namespace can bypass access controls on resources outside the namespace, as demonstrated by reading /etc/shadow. This occurs because an ID transformation takes place properly for the namespaced-to-kernel direction but not for the kernel-to-namespaced direction.

- [https://github.com/Moonw4re/Linux-Privilege-Escalation](https://github.com/Moonw4re/Linux-Privilege-Escalation) :  ![starts](https://img.shields.io/github/stars/Moonw4re/Linux-Privilege-Escalation.svg) ![forks](https://img.shields.io/github/forks/Moonw4re/Linux-Privilege-Escalation.svg)

