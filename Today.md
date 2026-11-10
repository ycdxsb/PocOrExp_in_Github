# Update 2026-11-10
## CVE-2026-124040
 CivetWeb through 1.16, when built with USE_HTTP2 and enable_http2 on, contains a use-after-free vulnerability in handle_http2() that retains freed :method and :path pointers. Unauthenticated remote attackers can send a later HEADERS frame omitting these pseudo-headers to influence request method or path seen by access rules, or crash the server.

- [https://github.com/zeetee1235/CVE-2026-124040](https://github.com/zeetee1235/CVE-2026-124040) :  ![starts](https://img.shields.io/github/stars/zeetee1235/CVE-2026-124040.svg) ![forks](https://img.shields.io/github/forks/zeetee1235/CVE-2026-124040.svg)


## CVE-2026-123488
 Craft CMS 4.0.0 before 4.18.9 and 5.0.0 before 5.11.2 contains an unauthenticated SQL injection vulnerability in the element search endpoint because the attribute parameter is concatenated into the query unsanitized and emulated PDO prepares allow stacked statements. Remote attackers can read and write the database, setting the admin flag or overwriting password hashes in the users table to gain administrator access.

- [https://github.com/dinosn/CVE-2026-123488-CraftCMS-Lab](https://github.com/dinosn/CVE-2026-123488-CraftCMS-Lab) :  ![starts](https://img.shields.io/github/stars/dinosn/CVE-2026-123488-CraftCMS-Lab.svg) ![forks](https://img.shields.io/github/forks/dinosn/CVE-2026-123488-CraftCMS-Lab.svg)


## CVE-2026-123158
 sshd in OpenSSH before 10.6p2 on Linux, when musl libc is used without PAM, lacks a workaround for a password authentication bypass (related to misinterpretation of whether a string is intended to be a password hash). For some configurations of accounts, any password between 256 and 1024 characters succeeds. An example of a platform using musl libc without PAM is Alpine Linux.

- [https://github.com/leonjza/sshhole-lab](https://github.com/leonjza/sshhole-lab) :  ![starts](https://img.shields.io/github/stars/leonjza/sshhole-lab.svg) ![forks](https://img.shields.io/github/forks/leonjza/sshhole-lab.svg)
- [https://github.com/Galaxy-sc/CVE-2026-123158](https://github.com/Galaxy-sc/CVE-2026-123158) :  ![starts](https://img.shields.io/github/stars/Galaxy-sc/CVE-2026-123158.svg) ![forks](https://img.shields.io/github/forks/Galaxy-sc/CVE-2026-123158.svg)
- [https://github.com/GarphenGate/cve-2026-123158-defender-toolkit](https://github.com/GarphenGate/cve-2026-123158-defender-toolkit) :  ![starts](https://img.shields.io/github/stars/GarphenGate/cve-2026-123158-defender-toolkit.svg) ![forks](https://img.shields.io/github/forks/GarphenGate/cve-2026-123158-defender-toolkit.svg)


## CVE-2026-121265
Releases before 2.000003 also treat an arrayref in generate() as literal SQL, including through AUTOLOAD when allow_autoload is on, whatever array_datatypes is set to.

- [https://github.com/googlesky/CVE-2026-121265](https://github.com/googlesky/CVE-2026-121265) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-121265.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-121265.svg)


## CVE-2026-119977
 WordPress Core is vulnerable to Remote Code Execution in versions 4.7 through 7.1.3. This is due to predictable, web-accessible staging paths used during full-package core upgrades. This makes it possible for unauthenticated attackers to execute code on the server during the upgrade window.

- [https://github.com/BugStealers/CVE-2026-119977](https://github.com/BugStealers/CVE-2026-119977) :  ![starts](https://img.shields.io/github/stars/BugStealers/CVE-2026-119977.svg) ![forks](https://img.shields.io/github/forks/BugStealers/CVE-2026-119977.svg)
- [https://github.com/mehmet-emir-eroglu/CVE-2026-119977](https://github.com/mehmet-emir-eroglu/CVE-2026-119977) :  ![starts](https://img.shields.io/github/stars/mehmet-emir-eroglu/CVE-2026-119977.svg) ![forks](https://img.shields.io/github/forks/mehmet-emir-eroglu/CVE-2026-119977.svg)


## CVE-2026-113386
 Roundcube Webmail before 1.6.20 and 1.7.x before 1.7.5 are affected by IMAP command injection. A remote authenticated attacker can exploit this via CRLF sequences injected into the _uid parameter of the mail/headers and mail/viewsource actions to execute arbitrary IMAP commands.

- [https://github.com/Neo-XeD/CVE-2026-113386](https://github.com/Neo-XeD/CVE-2026-113386) :  ![starts](https://img.shields.io/github/stars/Neo-XeD/CVE-2026-113386.svg) ![forks](https://img.shields.io/github/forks/Neo-XeD/CVE-2026-113386.svg)


## CVE-2026-112611
 An out-of-bounds write issue was addressed with improved bounds checking. This issue is fixed in iOS 26.7.2 and iPadOS 26.7.2, iOS 27.2 and iPadOS 27.2, macOS Sequoia 15.8.2, macOS Tahoe 26.7.2. Processing a maliciously crafted PDF file may lead to memory corruption.

- [https://github.com/Rust505/CVE-2026-112611](https://github.com/Rust505/CVE-2026-112611) :  ![starts](https://img.shields.io/github/stars/Rust505/CVE-2026-112611.svg) ![forks](https://img.shields.io/github/forks/Rust505/CVE-2026-112611.svg)


## CVE-2026-111967
 The MP3 Audio Player  WordPress plugin before 5.16 does not escape one of its audio player shortcode attributes before outputting it into an HTML attribute, allowing users with Contributor-level access and above to inject arbitrary JavaScript that executes when another user, such as an administrator previewing a pending post, views the content.

- [https://github.com/HexxedBitHeadz/cve-2026-111967](https://github.com/HexxedBitHeadz/cve-2026-111967) :  ![starts](https://img.shields.io/github/stars/HexxedBitHeadz/cve-2026-111967.svg) ![forks](https://img.shields.io/github/forks/HexxedBitHeadz/cve-2026-111967.svg)


## CVE-2026-109619
 PHP has various global state that temporarily points into request memory. In some scenarios, global state may not be correctly reset, or may be repopulated after being reset. The global state may then refer to request memory even after it has been freed. Subsequent requests may read or branch on this stale state before it is fully initialized. Multiple strategies can trigger this condition and produce remote code execution (RCE).

- [https://github.com/djad04/php2shell-deep-dive](https://github.com/djad04/php2shell-deep-dive) :  ![starts](https://img.shields.io/github/stars/djad04/php2shell-deep-dive.svg) ![forks](https://img.shields.io/github/forks/djad04/php2shell-deep-dive.svg)
- [https://github.com/testerxma/php2shell](https://github.com/testerxma/php2shell) :  ![starts](https://img.shields.io/github/stars/testerxma/php2shell.svg) ![forks](https://img.shields.io/github/forks/testerxma/php2shell.svg)


## CVE-2026-109618
 PHP uses longjmp() for out-of-memory (OOM) errors to exit the current context and abort handling of the request. Some contexts may not properly account for this scenario and leave request memory in an uninitialized state before performing an allocation. The subsequent request cleanup procedure may read or branch on this memory. Multiple OOM strategies can consistently trigger this condition and lead to remote code execution (RCE).

- [https://github.com/djad04/php2shell-deep-dive](https://github.com/djad04/php2shell-deep-dive) :  ![starts](https://img.shields.io/github/stars/djad04/php2shell-deep-dive.svg) ![forks](https://img.shields.io/github/forks/djad04/php2shell-deep-dive.svg)


## CVE-2026-99273
not part of the wire format, so the reported lengths are unchanged.

- [https://github.com/googlesky/CVE-2026-99273](https://github.com/googlesky/CVE-2026-99273) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-99273.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-99273.svg)


## CVE-2026-98260
[ tglx: Move the cleanup right after de_thread() ]

- [https://github.com/NanoTurtle1145/root-my-s24](https://github.com/NanoTurtle1145/root-my-s24) :  ![starts](https://img.shields.io/github/stars/NanoTurtle1145/root-my-s24.svg) ![forks](https://img.shields.io/github/forks/NanoTurtle1145/root-my-s24.svg)
- [https://github.com/Yunnijian/Shark](https://github.com/Yunnijian/Shark) :  ![starts](https://img.shields.io/github/stars/Yunnijian/Shark.svg) ![forks](https://img.shields.io/github/forks/Yunnijian/Shark.svg)
- [https://github.com/knowlily/m6-shell](https://github.com/knowlily/m6-shell) :  ![starts](https://img.shields.io/github/stars/knowlily/m6-shell.svg) ![forks](https://img.shields.io/github/forks/knowlily/m6-shell.svg)
- [https://github.com/MocLG/Time-My-Galaxy](https://github.com/MocLG/Time-My-Galaxy) :  ![starts](https://img.shields.io/github/stars/MocLG/Time-My-Galaxy.svg) ![forks](https://img.shields.io/github/forks/MocLG/Time-My-Galaxy.svg)
- [https://github.com/knowlily/cve-2026-98260-bvl-an16](https://github.com/knowlily/cve-2026-98260-bvl-an16) :  ![starts](https://img.shields.io/github/stars/knowlily/cve-2026-98260-bvl-an16.svg) ![forks](https://img.shields.io/github/forks/knowlily/cve-2026-98260-bvl-an16.svg)


## CVE-2026-83844
 Out-of-bounds read in Windows Paint allows an unauthorized attacker to execute code locally.

- [https://github.com/blkph0x/CVE-2026-83844_POC](https://github.com/blkph0x/CVE-2026-83844_POC) :  ![starts](https://img.shields.io/github/stars/blkph0x/CVE-2026-83844_POC.svg) ![forks](https://img.shields.io/github/forks/blkph0x/CVE-2026-83844_POC.svg)


## CVE-2026-63030
 WordPress 6.9.x before 6.9.5 and 7.0.x before 7.0.2 is affected by a REST API batch endpoint route confusion issue which, combined with the author__not_in WP_Query SQL Injection (CVE-2026-60137), could allow an attacker to perform SQL Injection and achieve Remote Code Execution.

- [https://github.com/noxcrypt-x/CVE-2026-63030](https://github.com/noxcrypt-x/CVE-2026-63030) :  ![starts](https://img.shields.io/github/stars/noxcrypt-x/CVE-2026-63030.svg) ![forks](https://img.shields.io/github/forks/noxcrypt-x/CVE-2026-63030.svg)


## CVE-2026-43499
  	changelog ]

- [https://github.com/Anezium/ghostlock-firetv-tank](https://github.com/Anezium/ghostlock-firetv-tank) :  ![starts](https://img.shields.io/github/stars/Anezium/ghostlock-firetv-tank.svg) ![forks](https://img.shields.io/github/forks/Anezium/ghostlock-firetv-tank.svg)


## CVE-2026-43284
destination-frag path or fall back to skb_cow_data().

- [https://github.com/h5hg6vy8nt-hue/meizu20pro-temp-root](https://github.com/h5hg6vy8nt-hue/meizu20pro-temp-root) :  ![starts](https://img.shields.io/github/stars/h5hg6vy8nt-hue/meizu20pro-temp-root.svg) ![forks](https://img.shields.io/github/forks/h5hg6vy8nt-hue/meizu20pro-temp-root.svg)
- [https://github.com/nemoiwkryang/pd2301-dirtyfrag-root](https://github.com/nemoiwkryang/pd2301-dirtyfrag-root) :  ![starts](https://img.shields.io/github/stars/nemoiwkryang/pd2301-dirtyfrag-root.svg) ![forks](https://img.shields.io/github/forks/nemoiwkryang/pd2301-dirtyfrag-root.svg)
- [https://github.com/Jean7z/DFRoot-DirtyFrag](https://github.com/Jean7z/DFRoot-DirtyFrag) :  ![starts](https://img.shields.io/github/stars/Jean7z/DFRoot-DirtyFrag.svg) ![forks](https://img.shields.io/github/forks/Jean7z/DFRoot-DirtyFrag.svg)


## CVE-2026-19868
 An authentication enforcement vulnerability in SonicOS SSLVPN service may allow a user with valid credentials for an alternate authentication method to bypass SAML authentication controls. Successful exploitation may also bypass SAML-enforced multi-factor authentication (MFA).

- [https://github.com/foxcornlab/sonicwall-sonicos-scanner](https://github.com/foxcornlab/sonicwall-sonicos-scanner) :  ![starts](https://img.shields.io/github/stars/foxcornlab/sonicwall-sonicos-scanner.svg) ![forks](https://img.shields.io/github/forks/foxcornlab/sonicwall-sonicos-scanner.svg)


## CVE-2026-19553
isn't supplied.

- [https://github.com/monkeyyey/acw3-tls-lab](https://github.com/monkeyyey/acw3-tls-lab) :  ![starts](https://img.shields.io/github/stars/monkeyyey/acw3-tls-lab.svg) ![forks](https://img.shields.io/github/forks/monkeyyey/acw3-tls-lab.svg)


## CVE-2026-13684
 An improper encoding or escaping of output vulnerability in SCGI in Synology DiskStation Manager (DSM) before 7.2.1-69057-12, 7.2.2-72806-9, 7.3.2-86009-4 and 7.4-90075 allows remote attackers to read or write arbitrary files and conduct denial-of-service attacks.

- [https://github.com/maxprog-svg/CVE-2026-13684](https://github.com/maxprog-svg/CVE-2026-13684) :  ![starts](https://img.shields.io/github/stars/maxprog-svg/CVE-2026-13684.svg) ![forks](https://img.shields.io/github/forks/maxprog-svg/CVE-2026-13684.svg)


## CVE-2026-12375
 The uncanny-automator-pro WordPress plugin before 7.3.0.6 was distributed with malicious code after the vendor's uncanny-automator-pro WordPress plugin before 7.3.0.6 update/distribution infrastructure was compromised; the injected backdoor grants unauthenticated attackers an administrator session on affected sites and beacons the site's secret keys and administrator details to attacker-controlled servers.

- [https://github.com/googlesky/CVE-2026-123753](https://github.com/googlesky/CVE-2026-123753) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-123753.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-123753.svg)


## CVE-2026-10961
 Use after free in Chrome for iOS in Google Chrome on iOS prior to 149.0.7827.53 allowed a remote attacker who had compromised the renderer process to potentially perform a sandbox escape via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/WKL-Sec/CVE-2026-109618](https://github.com/WKL-Sec/CVE-2026-109618) :  ![starts](https://img.shields.io/github/stars/WKL-Sec/CVE-2026-109618.svg) ![forks](https://img.shields.io/github/forks/WKL-Sec/CVE-2026-109618.svg)
- [https://github.com/MorphingYU/CVE-2026-109618](https://github.com/MorphingYU/CVE-2026-109618) :  ![starts](https://img.shields.io/github/stars/MorphingYU/CVE-2026-109618.svg) ![forks](https://img.shields.io/github/forks/MorphingYU/CVE-2026-109618.svg)


## CVE-2026-6952
 A post-authentication command injection vulnerability in the "LogServer" field of the syslog component in Zyxel AX7501-B1 firmware versions through 5.17(ABPC.7.2)C0 could allow an authenticated attacker with administrator privileges to execute OS commands on an affected device.

- [https://github.com/stevejiang0509/zyxel-cve-2026-6952-model-scope](https://github.com/stevejiang0509/zyxel-cve-2026-6952-model-scope) :  ![starts](https://img.shields.io/github/stars/stevejiang0509/zyxel-cve-2026-6952-model-scope.svg) ![forks](https://img.shields.io/github/forks/stevejiang0509/zyxel-cve-2026-6952-model-scope.svg)


## CVE-2026-4349
 A vulnerability was determined in Duende IdentityServer4 up to 4.1.2. The affected element is an unknown function of the file /connect/authorize of the component Token Renewal Endpoint. This manipulation of the argument id_token_hint causes improper authentication. It is possible to initiate the attack remotely. The attack is considered to have high complexity. The exploitability is described as difficult. This vulnerability only affects products that are no longer supported by the maintainer.

- [https://github.com/eroorvbsyes-hotmail/CVE-2026-43499_x86_Exploit](https://github.com/eroorvbsyes-hotmail/CVE-2026-43499_x86_Exploit) :  ![starts](https://img.shields.io/github/stars/eroorvbsyes-hotmail/CVE-2026-43499_x86_Exploit.svg) ![forks](https://img.shields.io/github/forks/eroorvbsyes-hotmail/CVE-2026-43499_x86_Exploit.svg)


## CVE-2026-1096
 The Best-wp-google-map plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the 'latitude' and 'longitudinal' parameters of the 'google_map_view' shortcode in all versions up to, and including, 2.1 due to insufficient input sanitization and output escaping. This makes it possible for authenticated attackers, with Contributor-level access and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.

- [https://github.com/TheMursalin/CVE-2026-109618](https://github.com/TheMursalin/CVE-2026-109618) :  ![starts](https://img.shields.io/github/stars/TheMursalin/CVE-2026-109618.svg) ![forks](https://img.shields.io/github/forks/TheMursalin/CVE-2026-109618.svg)
- [https://github.com/alvaroguzmancode/CVE-2026-109618](https://github.com/alvaroguzmancode/CVE-2026-109618) :  ![starts](https://img.shields.io/github/stars/alvaroguzmancode/CVE-2026-109618.svg) ![forks](https://img.shields.io/github/forks/alvaroguzmancode/CVE-2026-109618.svg)


## CVE-2025-59845
 Apollo Studio Embeddable Explorer & Embeddable Sandbox are website embeddable software solutions from Apollo GraphQL. Prior to Apollo Sandbox version 2.7.2 and Apollo Explorer version 3.7.3, a cross-site request forgery (CSRF) vulnerability was identified. The vulnerability arises from missing origin validation in the client-side code that handles window.postMessage events. A malicious website can send forged messages to the embedding page, causing the victim’s browser to execute arbitrary GraphQL queries or mutations against their GraphQL server while authenticated with the victim’s cookies. This issue has been patched in Apollo Sandbox version 2.7.2 and Apollo Explorer version 3.7.3.

- [https://github.com/C3viche/cve-2025-59845](https://github.com/C3viche/cve-2025-59845) :  ![starts](https://img.shields.io/github/stars/C3viche/cve-2025-59845.svg) ![forks](https://img.shields.io/github/forks/C3viche/cve-2025-59845.svg)


## CVE-2025-48583
 In multiple functions of BaseBundle.java, there is a possible way to execute arbitrary code due to a logic error in the code. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/helloguy1234/CVE-2025-48583-PoC](https://github.com/helloguy1234/CVE-2025-48583-PoC) :  ![starts](https://img.shields.io/github/stars/helloguy1234/CVE-2025-48583-PoC.svg) ![forks](https://img.shields.io/github/forks/helloguy1234/CVE-2025-48583-PoC.svg)


## CVE-2024-23222
 A type confusion issue was addressed with improved checks. This issue is fixed in Safari 17.3, iOS 15.8.7 and iPadOS 15.8.7, iOS 16.7.5 and iPadOS 16.7.5, iOS 17.3 and iPadOS 17.3, macOS Monterey 12.7.3, macOS Sonoma 14.3, macOS Ventura 13.6.4, tvOS 17.3, visionOS 1.0.2. Processing maliciously crafted web content may lead to arbitrary code execution. This fix associated with the Coruna exploit was shipped in iOS 17.3 on January 22, 2024. This update brings that fix to devices that cannot update to the latest iOS version.

- [https://github.com/xxsioo/coruna-lab](https://github.com/xxsioo/coruna-lab) :  ![starts](https://img.shields.io/github/stars/xxsioo/coruna-lab.svg) ![forks](https://img.shields.io/github/forks/xxsioo/coruna-lab.svg)


## CVE-2023-36664
 Artifex Ghostscript before 10.01.2 mishandles permission validation for pipe devices (with the %pipe% prefix or the | pipe character prefix).

- [https://github.com/minsmiths/cve-2023-36664](https://github.com/minsmiths/cve-2023-36664) :  ![starts](https://img.shields.io/github/stars/minsmiths/cve-2023-36664.svg) ![forks](https://img.shields.io/github/forks/minsmiths/cve-2023-36664.svg)


## CVE-2022-0847
 A flaw was found in the way the "flags" member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/pmihsan/Dirty-Pipe-CVE-2022-0847](https://github.com/pmihsan/Dirty-Pipe-CVE-2022-0847) :  ![starts](https://img.shields.io/github/stars/pmihsan/Dirty-Pipe-CVE-2022-0847.svg) ![forks](https://img.shields.io/github/forks/pmihsan/Dirty-Pipe-CVE-2022-0847.svg)


## CVE-2021-4177
 livehelperchat is vulnerable to Generation of Error Message Containing Sensitive Information

- [https://github.com/zer0qs/CVE-2021-41773](https://github.com/zer0qs/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/zer0qs/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/zer0qs/CVE-2021-41773.svg)


## CVE-2020-13405
 userfiles/modules/users/controller/controller.php in Microweber before 1.1.20 allows an unauthenticated user to disclose the users database via a /modules/ POST request.

- [https://github.com/nobleordu/CVE-2020-13405-MicroWeber-PoC](https://github.com/nobleordu/CVE-2020-13405-MicroWeber-PoC) :  ![starts](https://img.shields.io/github/stars/nobleordu/CVE-2020-13405-MicroWeber-PoC.svg) ![forks](https://img.shields.io/github/forks/nobleordu/CVE-2020-13405-MicroWeber-PoC.svg)


## CVE-2019-2215
 A use-after-free in binder.c allows an elevation of privilege from an application to the Linux Kernel. No user interaction is required to exploit this vulnerability, however exploitation does require either the installation of a malicious local application or a separate vulnerability in a network facing application.Product: AndroidAndroid ID: A-141720095

- [https://github.com/RxinnotRstar/CVE-2019-2215-ForMIpad4](https://github.com/RxinnotRstar/CVE-2019-2215-ForMIpad4) :  ![starts](https://img.shields.io/github/stars/RxinnotRstar/CVE-2019-2215-ForMIpad4.svg) ![forks](https://img.shields.io/github/forks/RxinnotRstar/CVE-2019-2215-ForMIpad4.svg)


## CVE-2017-5638
 The Jakarta Multipart parser in Apache Struts 2 2.3.x before 2.3.32 and 2.5.x before 2.5.10.1 has incorrect exception handling and error-message generation during file-upload attempts, which allows remote attackers to execute arbitrary commands via a crafted Content-Type, Content-Disposition, or Content-Length HTTP header, as exploited in the wild in March 2017 with a Content-Type header containing a #cmd= string.

- [https://github.com/AndreiaFelix1/trabalho_cve_2017_5638](https://github.com/AndreiaFelix1/trabalho_cve_2017_5638) :  ![starts](https://img.shields.io/github/stars/AndreiaFelix1/trabalho_cve_2017_5638.svg) ![forks](https://img.shields.io/github/forks/AndreiaFelix1/trabalho_cve_2017_5638.svg)

