# Update 2025-07-22
## CVE-2025-53770
Microsoft is preparing and fully testing a comprehensive update to address this vulnerability.  In the meantime, please make sure that the mitigation provided in this CVE documentation is in place so that you are protected from exploitation.

- [https://github.com/B1ack4sh/Blackash-CVE-2025-53770](https://github.com/B1ack4sh/Blackash-CVE-2025-53770) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-53770.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-53770.svg)


## CVE-2025-49706
 Improper authentication in Microsoft Office SharePoint allows an authorized attacker to perform spoofing over a network.

- [https://github.com/AdityaBhatt3010/CVE-2025-49706-SharePoint-Spoofing-Vulnerability-Under-Active-Exploitation](https://github.com/AdityaBhatt3010/CVE-2025-49706-SharePoint-Spoofing-Vulnerability-Under-Active-Exploitation) :  ![starts](https://img.shields.io/github/stars/AdityaBhatt3010/CVE-2025-49706-SharePoint-Spoofing-Vulnerability-Under-Active-Exploitation.svg) ![forks](https://img.shields.io/github/forks/AdityaBhatt3010/CVE-2025-49706-SharePoint-Spoofing-Vulnerability-Under-Active-Exploitation.svg)


## CVE-2025-48384
 Git is a fast, scalable, distributed revision control system with an unusually rich command set that provides both high-level operations and full access to internals. When reading a config value, Git strips any trailing carriage return and line feed (CRLF). When writing a config entry, values with a trailing CR are not quoted, causing the CR to be lost when the config is later read. When initializing a submodule, if the submodule path contains a trailing CR, the altered path is read resulting in the submodule being checked out to an incorrect location. If a symlink exists that points the altered path to the submodule hooks directory, and the submodule contains an executable post-checkout hook, the script may be unintentionally executed after checkout. This vulnerability is fixed in v2.43.7, v2.44.4, v2.45.4, v2.46.4, v2.47.3, v2.48.2, v2.49.1, and v2.50.1.

- [https://github.com/IK-20211125/CVE-2025-48384](https://github.com/IK-20211125/CVE-2025-48384) :  ![starts](https://img.shields.io/github/stars/IK-20211125/CVE-2025-48384.svg) ![forks](https://img.shields.io/github/forks/IK-20211125/CVE-2025-48384.svg)


## CVE-2025-34085
 This CVE ID has been rejected or withdrawn by its CVE Numbering Authority as it is a duplicate of CVE-2020-36847.

- [https://github.com/0xgh057r3c0n/CVE-2025-34085](https://github.com/0xgh057r3c0n/CVE-2025-34085) :  ![starts](https://img.shields.io/github/stars/0xgh057r3c0n/CVE-2025-34085.svg) ![forks](https://img.shields.io/github/forks/0xgh057r3c0n/CVE-2025-34085.svg)


## CVE-2025-32463
 Sudo before 1.9.17p1 allows local users to obtain root access because /etc/nsswitch.conf from a user-controlled directory is used with the --chroot option.

- [https://github.com/IC3-512/linux-root-kit](https://github.com/IC3-512/linux-root-kit) :  ![starts](https://img.shields.io/github/stars/IC3-512/linux-root-kit.svg) ![forks](https://img.shields.io/github/forks/IC3-512/linux-root-kit.svg)
- [https://github.com/daryllundy/CVE-2025-32463](https://github.com/daryllundy/CVE-2025-32463) :  ![starts](https://img.shields.io/github/stars/daryllundy/CVE-2025-32463.svg) ![forks](https://img.shields.io/github/forks/daryllundy/CVE-2025-32463.svg)


## CVE-2025-32023
 Redis is an open source, in-memory database that persists on disk. From 2.8 to before 8.0.3, 7.4.5, 7.2.10, and 6.2.19, an authenticated user may use a specially crafted string to trigger a stack/heap out of bounds write on hyperloglog operations, potentially leading to remote code execution. The bug likely affects all Redis versions with hyperloglog operations implemented. This vulnerability is fixed in 8.0.3, 7.4.5, 7.2.10, and 6.2.19. An additional workaround to mitigate the problem without patching the redis-server executable is to prevent users from executing hyperloglog operations. This can be done using ACL to restrict HLL commands.

- [https://github.com/shayantrix/POC-CVE-2025-32023](https://github.com/shayantrix/POC-CVE-2025-32023) :  ![starts](https://img.shields.io/github/stars/shayantrix/POC-CVE-2025-32023.svg) ![forks](https://img.shields.io/github/forks/shayantrix/POC-CVE-2025-32023.svg)


## CVE-2025-27591
 A privilege escalation vulnerability existed in the Below service prior to v0.9.0 due to the creation of a world-writable directory at /var/log/below. This could have allowed local unprivileged users to escalate to root privileges through symlink attacks that manipulate files such as /etc/shadow.

- [https://github.com/Thekin-ctrl/CVE-2025-27591-Below](https://github.com/Thekin-ctrl/CVE-2025-27591-Below) :  ![starts](https://img.shields.io/github/stars/Thekin-ctrl/CVE-2025-27591-Below.svg) ![forks](https://img.shields.io/github/forks/Thekin-ctrl/CVE-2025-27591-Below.svg)


## CVE-2025-7840
 A vulnerability was found in Campcodes Online Movie Theater Seat Reservation System 1.0. It has been classified as problematic. This affects an unknown part of the file /index.php?page=reserve of the component Reserve Your Seat Page. The manipulation of the argument Firstname/Lastname leads to cross site scripting. It is possible to initiate the attack remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/byteReaper77/CVE-2025-7840](https://github.com/byteReaper77/CVE-2025-7840) :  ![starts](https://img.shields.io/github/stars/byteReaper77/CVE-2025-7840.svg) ![forks](https://img.shields.io/github/forks/byteReaper77/CVE-2025-7840.svg)


## CVE-2025-5140
 A vulnerability classified as critical has been found in Seeyon Zhiyuan OA Web Application System up to 8.1 SP2. This affects the function this.oursNetService.getData of the file com\ours\www\ehr\openPlatform1\open4ClientType\controller\ThirdMenuController.class. The manipulation of the argument url leads to server-side request forgery. It is possible to initiate the attack remotely. The exploit has been disclosed to the public and may be used. The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/Thewhiteevil/CVE-2025-51403](https://github.com/Thewhiteevil/CVE-2025-51403) :  ![starts](https://img.shields.io/github/stars/Thewhiteevil/CVE-2025-51403.svg) ![forks](https://img.shields.io/github/forks/Thewhiteevil/CVE-2025-51403.svg)
- [https://github.com/Thewhiteevil/CVE-2025-51401](https://github.com/Thewhiteevil/CVE-2025-51401) :  ![starts](https://img.shields.io/github/stars/Thewhiteevil/CVE-2025-51401.svg) ![forks](https://img.shields.io/github/forks/Thewhiteevil/CVE-2025-51401.svg)
- [https://github.com/Thewhiteevil/CVE-2025-51400](https://github.com/Thewhiteevil/CVE-2025-51400) :  ![starts](https://img.shields.io/github/stars/Thewhiteevil/CVE-2025-51400.svg) ![forks](https://img.shields.io/github/forks/Thewhiteevil/CVE-2025-51400.svg)


## CVE-2025-5139
 A vulnerability was found in Qualitor 8.20/8.24. It has been rated as critical. Affected by this issue is some unknown functionality of the file /html/ad/adconexaooffice365/request/testaConexaoOffice365.php of the component Office 365-type Connection Handler. The manipulation of the argument nmconexao leads to command injection. The attack may be launched remotely. The complexity of an attack is rather high. The exploitation is known to be difficult. The exploit has been disclosed to the public and may be used. Upgrading to version 8.20.56 and 8.24.31 is able to address this issue. It is recommended to upgrade the affected component.

- [https://github.com/Thewhiteevil/CVE-2025-51397](https://github.com/Thewhiteevil/CVE-2025-51397) :  ![starts](https://img.shields.io/github/stars/Thewhiteevil/CVE-2025-51397.svg) ![forks](https://img.shields.io/github/forks/Thewhiteevil/CVE-2025-51397.svg)
- [https://github.com/Thewhiteevil/CVE-2025-51396](https://github.com/Thewhiteevil/CVE-2025-51396) :  ![starts](https://img.shields.io/github/stars/Thewhiteevil/CVE-2025-51396.svg) ![forks](https://img.shields.io/github/forks/Thewhiteevil/CVE-2025-51396.svg)
- [https://github.com/Thewhiteevil/CVE-2025-51398](https://github.com/Thewhiteevil/CVE-2025-51398) :  ![starts](https://img.shields.io/github/stars/Thewhiteevil/CVE-2025-51398.svg) ![forks](https://img.shields.io/github/forks/Thewhiteevil/CVE-2025-51398.svg)


## CVE-2025-4380
 The Ads Pro Plugin - Multi-Purpose WordPress Advertising Manager plugin for WordPress is vulnerable to Local File Inclusion in all versions up to, and including, 4.89 via the 'bsa_template' parameter of the `bsa_preview_callback` function. This makes it possible for unauthenticated attackers to include and execute arbitrary files on the server, allowing the execution of any PHP code in those files. This can be used to bypass access controls, obtain sensitive data, or achieve code execution in cases .php files can can be uploaded and included, or already exist on the site.

- [https://github.com/r0otk3r/CVE-2025-4380](https://github.com/r0otk3r/CVE-2025-4380) :  ![starts](https://img.shields.io/github/stars/r0otk3r/CVE-2025-4380.svg) ![forks](https://img.shields.io/github/forks/r0otk3r/CVE-2025-4380.svg)


## CVE-2023-42961
 A path handling issue was addressed with improved validation. This issue is fixed in iOS 17 and iPadOS 17, iOS 16.7 and iPadOS 16.7, macOS Sonoma 14, macOS Ventura 13.6, macOS Monterey 12.7. A sandboxed process may be able to circumvent sandbox restrictions.

- [https://github.com/windz3r0day/CVE-2023-42961](https://github.com/windz3r0day/CVE-2023-42961) :  ![starts](https://img.shields.io/github/stars/windz3r0day/CVE-2023-42961.svg) ![forks](https://img.shields.io/github/forks/windz3r0day/CVE-2023-42961.svg)


## CVE-2023-4911
 A buffer overflow was discovered in the GNU C Library's dynamic loader ld.so while processing the GLIBC_TUNABLES environment variable. This issue could allow a local attacker to use maliciously crafted GLIBC_TUNABLES environment variables when launching binaries with SUID permission to execute code with elevated privileges.

- [https://github.com/RRespxwnss/Looney-Tunables-CVE-2023-4911](https://github.com/RRespxwnss/Looney-Tunables-CVE-2023-4911) :  ![starts](https://img.shields.io/github/stars/RRespxwnss/Looney-Tunables-CVE-2023-4911.svg) ![forks](https://img.shields.io/github/forks/RRespxwnss/Looney-Tunables-CVE-2023-4911.svg)


## CVE-2022-24439
 All versions of package gitpython are vulnerable to Remote Code Execution (RCE) due to improper user input validation, which makes it possible to inject a maliciously crafted remote URL into the clone command. Exploiting this vulnerability is possible because the library makes external calls to git without sufficient sanitization of input arguments.

- [https://github.com/Makkkiiii/GitPython-Exploit-CVE-2022-24439](https://github.com/Makkkiiii/GitPython-Exploit-CVE-2022-24439) :  ![starts](https://img.shields.io/github/stars/Makkkiiii/GitPython-Exploit-CVE-2022-24439.svg) ![forks](https://img.shields.io/github/forks/Makkkiiii/GitPython-Exploit-CVE-2022-24439.svg)


## CVE-2022-0492
 A vulnerability was found in the Linux kernel’s cgroup_release_agent_write in the kernel/cgroup/cgroup-v1.c function. This flaw, under certain circumstances, allows the use of the cgroups v1 release_agent feature to escalate privileges and bypass the namespace isolation unexpectedly.

- [https://github.com/Perimora/cve_2022_0492](https://github.com/Perimora/cve_2022_0492) :  ![starts](https://img.shields.io/github/stars/Perimora/cve_2022_0492.svg) ![forks](https://img.shields.io/github/forks/Perimora/cve_2022_0492.svg)


## CVE-2019-8331
 In Bootstrap before 3.4.1 and 4.3.x before 4.3.1, XSS is possible in the tooltip or popover data-template attribute.

- [https://github.com/Yumeae/Bootstrap-with-XSS](https://github.com/Yumeae/Bootstrap-with-XSS) :  ![starts](https://img.shields.io/github/stars/Yumeae/Bootstrap-with-XSS.svg) ![forks](https://img.shields.io/github/forks/Yumeae/Bootstrap-with-XSS.svg)


## CVE-2018-14040
 In Bootstrap before 4.1.2, XSS is possible in the collapse data-parent attribute.

- [https://github.com/Yumeae/Bootstrap-with-XSS](https://github.com/Yumeae/Bootstrap-with-XSS) :  ![starts](https://img.shields.io/github/stars/Yumeae/Bootstrap-with-XSS.svg) ![forks](https://img.shields.io/github/forks/Yumeae/Bootstrap-with-XSS.svg)


## CVE-2016-10735
 In Bootstrap 3.x before 3.4.0 and 4.x-beta before 4.0.0-beta.2, XSS is possible in the data-target attribute, a different vulnerability than CVE-2018-14041.

- [https://github.com/Yumeae/Bootstrap-with-XSS](https://github.com/Yumeae/Bootstrap-with-XSS) :  ![starts](https://img.shields.io/github/stars/Yumeae/Bootstrap-with-XSS.svg) ![forks](https://img.shields.io/github/forks/Yumeae/Bootstrap-with-XSS.svg)

