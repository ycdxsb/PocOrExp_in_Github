# Update 2026-01-01
## CVE-2025-68645
 A Local File Inclusion (LFI) vulnerability exists in the Webmail Classic UI of Zimbra Collaboration (ZCS) 10.0 and 10.1 because of improper handling of user-supplied request parameters in the RestFilter servlet. An unauthenticated remote attacker can craft requests to the /h/rest endpoint to influence internal request dispatching, allowing inclusion of arbitrary files from the WebRoot directory.

- [https://github.com/chinaxploiter/CVE-2025-68645-PoC](https://github.com/chinaxploiter/CVE-2025-68645-PoC) :  ![starts](https://img.shields.io/github/stars/chinaxploiter/CVE-2025-68645-PoC.svg) ![forks](https://img.shields.io/github/forks/chinaxploiter/CVE-2025-68645-PoC.svg)


## CVE-2025-66723
 inMusic Brands Engine DJ 4.3.0 suffers from Insecure Permissions due to exposed HTTP service in the Remote Library, which allows attackers to access all files and network paths.

- [https://github.com/audiopump/cve-2025-66723](https://github.com/audiopump/cve-2025-66723) :  ![starts](https://img.shields.io/github/stars/audiopump/cve-2025-66723.svg) ![forks](https://img.shields.io/github/forks/audiopump/cve-2025-66723.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-packagemanager-field](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-packagemanager-field) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-packagemanager-field.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-packagemanager-field.svg)


## CVE-2025-65925
 An issue was discovered in Zeroheight (SaaS) prior to 2025-06-13. A legacy user creation API pathway allowed accounts to be created without completing the intended email verification step. While unverified accounts could not access product functionality, the behavior bypassed intended verification controls and allowed unintended account creation. This could have enabled spam/fake account creation or resource usage impact. No data exposure or unauthorized access to existing accounts was reported.

- [https://github.com/Sneden/zeroheight-account-verification-bypass-CVE-2025-65925](https://github.com/Sneden/zeroheight-account-verification-bypass-CVE-2025-65925) :  ![starts](https://img.shields.io/github/stars/Sneden/zeroheight-account-verification-bypass-CVE-2025-65925.svg) ![forks](https://img.shields.io/github/forks/Sneden/zeroheight-account-verification-bypass-CVE-2025-65925.svg)


## CVE-2025-65037
 Improper control of generation of code ('code injection') in Azure Container Apps allows an unauthorized attacker to execute code over a network.

- [https://github.com/b1gchoi/CVE-2025-65037](https://github.com/b1gchoi/CVE-2025-65037) :  ![starts](https://img.shields.io/github/stars/b1gchoi/CVE-2025-65037.svg) ![forks](https://img.shields.io/github/forks/b1gchoi/CVE-2025-65037.svg)


## CVE-2025-54236
 Adobe Commerce versions 2.4.9-alpha2, 2.4.8-p2, 2.4.7-p7, 2.4.6-p12, 2.4.5-p14, 2.4.4-p15 and earlier are affected by an Improper Input Validation vulnerability. A successful attacker can abuse this to achieve session takeover, increasing the confidentiality, and integrity impact to high. Exploitation of this issue does not require user interaction.

- [https://github.com/Baba01hacker666/cve-2025-54236](https://github.com/Baba01hacker666/cve-2025-54236) :  ![starts](https://img.shields.io/github/stars/Baba01hacker666/cve-2025-54236.svg) ![forks](https://img.shields.io/github/forks/Baba01hacker666/cve-2025-54236.svg)


## CVE-2025-52691
 Successful exploitation of the vulnerability could allow an unauthenticated attacker to upload arbitrary files to any location on the mail server, potentially enabling remote code execution.

- [https://github.com/rxerium/CVE-2025-52691](https://github.com/rxerium/CVE-2025-52691) :  ![starts](https://img.shields.io/github/stars/rxerium/CVE-2025-52691.svg) ![forks](https://img.shields.io/github/forks/rxerium/CVE-2025-52691.svg)
- [https://github.com/DeathShotXD/CVE-2025-52691-APT-PoC](https://github.com/DeathShotXD/CVE-2025-52691-APT-PoC) :  ![starts](https://img.shields.io/github/stars/DeathShotXD/CVE-2025-52691-APT-PoC.svg) ![forks](https://img.shields.io/github/forks/DeathShotXD/CVE-2025-52691-APT-PoC.svg)
- [https://github.com/Ashwesker/Ashwesker-CVE-2025-52691](https://github.com/Ashwesker/Ashwesker-CVE-2025-52691) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-52691.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-52691.svg)
- [https://github.com/you-ssef9/CVE-2025-52691](https://github.com/you-ssef9/CVE-2025-52691) :  ![starts](https://img.shields.io/github/stars/you-ssef9/CVE-2025-52691.svg) ![forks](https://img.shields.io/github/forks/you-ssef9/CVE-2025-52691.svg)
- [https://github.com/sajjadsiam/CVE-2025-52691-poc](https://github.com/sajjadsiam/CVE-2025-52691-poc) :  ![starts](https://img.shields.io/github/stars/sajjadsiam/CVE-2025-52691-poc.svg) ![forks](https://img.shields.io/github/forks/sajjadsiam/CVE-2025-52691-poc.svg)


## CVE-2025-49131
 FastGPT is an open-source project that provides a platform for building, deploying, and operating AI-driven workflows and conversational agents. The Sandbox container (fastgpt-sandbox) is a specialized, isolated environment used by FastGPT to safely execute user-submitted or dynamically generated code in isolation. The sandbox before version 4.9.11 has insufficient isolation and inadequate restrictions on code execution by allowing overly permissive syscalls, which allows attackers to escape the intended sandbox boundaries. Attackers could exploit this to read and overwrite arbitrary files and bypass Python module import restrictions. This is patched in version 4.9.11 by restricting the allowed system calls to a safer subset and additional descriptive error messaging.

- [https://github.com/Wenura17125/cve-2025-49131-poc](https://github.com/Wenura17125/cve-2025-49131-poc) :  ![starts](https://img.shields.io/github/stars/Wenura17125/cve-2025-49131-poc.svg) ![forks](https://img.shields.io/github/forks/Wenura17125/cve-2025-49131-poc.svg)


## CVE-2025-47962
 Improper access control in Windows SDK allows an authorized attacker to elevate privileges locally.

- [https://github.com/q1uf3ng/CVE-2025-47962-POC](https://github.com/q1uf3ng/CVE-2025-47962-POC) :  ![starts](https://img.shields.io/github/stars/q1uf3ng/CVE-2025-47962-POC.svg) ![forks](https://img.shields.io/github/forks/q1uf3ng/CVE-2025-47962-POC.svg)


## CVE-2025-40019
it's also checked for decryption and in-place encryption.

- [https://github.com/xooxo/CVE-2025-40019-Essiv](https://github.com/xooxo/CVE-2025-40019-Essiv) :  ![starts](https://img.shields.io/github/stars/xooxo/CVE-2025-40019-Essiv.svg) ![forks](https://img.shields.io/github/forks/xooxo/CVE-2025-40019-Essiv.svg)


## CVE-2025-27515
 Laravel is a web application framework. When using wildcard validation to validate a given file or image field (`files.*`), a user-crafted malicious request could potentially bypass the validation rules. This vulnerability is fixed in 11.44.1 and 12.1.1.

- [https://github.com/joaovicdev/POC-CVE-2025-27515](https://github.com/joaovicdev/POC-CVE-2025-27515) :  ![starts](https://img.shields.io/github/stars/joaovicdev/POC-CVE-2025-27515.svg) ![forks](https://img.shields.io/github/forks/joaovicdev/POC-CVE-2025-27515.svg)


## CVE-2025-14847
 Mismatched length fields in Zlib compressed protocol headers may allow a read of uninitialized heap memory by an unauthenticated client. This issue affects all MongoDB Server v7.0 prior to 7.0.28 versions, MongoDB Server v8.0 versions prior to 8.0.17, MongoDB Server v8.2 versions prior to 8.2.3, MongoDB Server v6.0 versions prior to 6.0.27, MongoDB Server v5.0 versions prior to 5.0.32, MongoDB Server v4.4 versions prior to 4.4.30, MongoDB Server v4.2 versions greater than or equal to 4.2.0, MongoDB Server v4.0 versions greater than or equal to 4.0.0, and MongoDB Server v3.6 versions greater than or equal to 3.6.0.

- [https://github.com/FurkanKAYAPINAR/CVE-2025-14847-MongoBleed-Exploit](https://github.com/FurkanKAYAPINAR/CVE-2025-14847-MongoBleed-Exploit) :  ![starts](https://img.shields.io/github/stars/FurkanKAYAPINAR/CVE-2025-14847-MongoBleed-Exploit.svg) ![forks](https://img.shields.io/github/forks/FurkanKAYAPINAR/CVE-2025-14847-MongoBleed-Exploit.svg)
- [https://github.com/vfa-tuannt/CVE-2025-14847](https://github.com/vfa-tuannt/CVE-2025-14847) :  ![starts](https://img.shields.io/github/stars/vfa-tuannt/CVE-2025-14847.svg) ![forks](https://img.shields.io/github/forks/vfa-tuannt/CVE-2025-14847.svg)
- [https://github.com/NoNameError/MongoBLEED---CVE-2025-14847-POC-](https://github.com/NoNameError/MongoBLEED---CVE-2025-14847-POC-) :  ![starts](https://img.shields.io/github/stars/NoNameError/MongoBLEED---CVE-2025-14847-POC-.svg) ![forks](https://img.shields.io/github/forks/NoNameError/MongoBLEED---CVE-2025-14847-POC-.svg)
- [https://github.com/j0lt-github/mongobleedburp](https://github.com/j0lt-github/mongobleedburp) :  ![starts](https://img.shields.io/github/stars/j0lt-github/mongobleedburp.svg) ![forks](https://img.shields.io/github/forks/j0lt-github/mongobleedburp.svg)


## CVE-2025-8191
 A vulnerability, which was classified as problematic, was found in macrozheng mall up to 1.0.3. Affected is an unknown function of the file /swagger-ui/index.html of the component Swagger UI. The manipulation of the argument configUrl leads to cross site scripting. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used. The vendor deleted the GitHub issue for this vulnerability without any explanation. Afterwards the vendor was contacted early about this disclosure via email but did not respond in any way.

- [https://github.com/YanC1e/CVE-2025-8191](https://github.com/YanC1e/CVE-2025-8191) :  ![starts](https://img.shields.io/github/stars/YanC1e/CVE-2025-8191.svg) ![forks](https://img.shields.io/github/forks/YanC1e/CVE-2025-8191.svg)


## CVE-2024-4577
 In PHP versions 8.1.* before 8.1.29, 8.2.* before 8.2.20, 8.3.* before 8.3.8, when using Apache and PHP-CGI on Windows, if the system is set up to use certain code pages, Windows may use "Best-Fit" behavior to replace characters in command line given to Win32 API functions. PHP CGI module may misinterpret those characters as PHP options, which may allow a malicious user to pass options to PHP binary being run, and thus reveal the source code of scripts, run arbitrary PHP code on the server, etc.

- [https://github.com/rayngnpc/CVE-2024-4577-rayng](https://github.com/rayngnpc/CVE-2024-4577-rayng) :  ![starts](https://img.shields.io/github/stars/rayngnpc/CVE-2024-4577-rayng.svg) ![forks](https://img.shields.io/github/forks/rayngnpc/CVE-2024-4577-rayng.svg)


## CVE-2024-0044
 In createSessionInternal of PackageInstallerService.java, there is a possible run-as any app due to improper input validation. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/Dit-Developers/CVE-2024-0044](https://github.com/Dit-Developers/CVE-2024-0044) :  ![starts](https://img.shields.io/github/stars/Dit-Developers/CVE-2024-0044.svg) ![forks](https://img.shields.io/github/forks/Dit-Developers/CVE-2024-0044.svg)


## CVE-2023-30212
 OURPHP = 7.2.0 is vulnerale to Cross Site Scripting (XSS) via /client/manage/ourphp_out.php.

- [https://github.com/imathewvincent/CVE-2023-30212-OURPHP-Vulnerability](https://github.com/imathewvincent/CVE-2023-30212-OURPHP-Vulnerability) :  ![starts](https://img.shields.io/github/stars/imathewvincent/CVE-2023-30212-OURPHP-Vulnerability.svg) ![forks](https://img.shields.io/github/forks/imathewvincent/CVE-2023-30212-OURPHP-Vulnerability.svg)


## CVE-2022-40471
 Remote Code Execution in Clinic's Patient Management System v 1.0 allows Attacker to Upload arbitrary php webshell via profile picture upload functionality in users.php

- [https://github.com/Dharan10/CVE-2022-40471](https://github.com/Dharan10/CVE-2022-40471) :  ![starts](https://img.shields.io/github/stars/Dharan10/CVE-2022-40471.svg) ![forks](https://img.shields.io/github/forks/Dharan10/CVE-2022-40471.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/ch4os443/CVE-2021-41773](https://github.com/ch4os443/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/ch4os443/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/ch4os443/CVE-2021-41773.svg)


## CVE-2018-12633
 An issue was discovered in the Linux kernel through 4.17.2. vbg_misc_device_ioctl() in drivers/virt/vboxguest/vboxguest_linux.c reads the same user data twice with copy_from_user. The header part of the user data is double-fetched, and a malicious user thread can tamper with the critical variables (hdr.size_in and hdr.size_out) in the header between the two fetches because of a race condition, leading to severe kernel errors, such as buffer over-accesses. This bug can cause a local denial of service and information leakage.

- [https://github.com/wiliam227user/CVE-2018-12633-TPLink-Auth-Bypass](https://github.com/wiliam227user/CVE-2018-12633-TPLink-Auth-Bypass) :  ![starts](https://img.shields.io/github/stars/wiliam227user/CVE-2018-12633-TPLink-Auth-Bypass.svg) ![forks](https://img.shields.io/github/forks/wiliam227user/CVE-2018-12633-TPLink-Auth-Bypass.svg)

