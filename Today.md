# Update 2026-08-24
## CVE-2026-76904
 GeoTools is an open source Java library that provides tools for geospatial data. Starting in version 30.5 and prior to versions 33.6, 34.5, and 33.6, an SQL Injection Vulnerability is present when executing OGC Filters with PostGIS DataStore implementation: `jsonArrayContains` function; Requires PostGIS 12 or greater with a String or JSON field. For PostGIS 12 and greater `jsonArrayContains(column, pointer, value)` function writes `value` into generated SQL without escaping. Patches are available in versions 33.6, 34.5, and 33.6. No known workaround is available. To limit scope of SQL Injection the PostGIS connection pool should be configured with limited rights.

- [https://github.com/YonLiud/CVE-2026-76904](https://github.com/YonLiud/CVE-2026-76904) :  ![starts](https://img.shields.io/github/stars/YonLiud/CVE-2026-76904.svg) ![forks](https://img.shields.io/github/forks/YonLiud/CVE-2026-76904.svg)


## CVE-2026-75616
Successful exploitation may allow arbitrary command execution with elevated privileges, compromising the confidentiality, integrity, and availability of the affected device and network traffic passing through it.

- [https://github.com/totekuh/CVE-2026-75616](https://github.com/totekuh/CVE-2026-75616) :  ![starts](https://img.shields.io/github/stars/totekuh/CVE-2026-75616.svg) ![forks](https://img.shields.io/github/forks/totekuh/CVE-2026-75616.svg)


## CVE-2026-74252
 Joomla Extension - j2commerce.com - Stored XSS in Guest checkout in J2Store 1.0.0-3.3.20, 4.0.0-4.0.20, 4.1.0-4.1.5 - J2Commerce 4.1.5 is vulnerable to Stored Cross-Site Scripting (XSS) through the guest checkout billing address fields. An unauthenticated attacker exploits a filter bypass in Joomla's Input::getArray() combined with PHP's variables_order=EGPCS (Cookie overrides POST in $_REQUEST ) to store unsanitized HTML in fields such as billing_first_name.

- [https://github.com/toanln-cov/CVE-2026-74252](https://github.com/toanln-cov/CVE-2026-74252) :  ![starts](https://img.shields.io/github/stars/toanln-cov/CVE-2026-74252.svg) ![forks](https://img.shields.io/github/forks/toanln-cov/CVE-2026-74252.svg)


## CVE-2026-72844
 The Lean 4 kernel does not verify that the structure named in a projection expression matches the type of the value being projected, and environment::add_inductive in src/kernel/inductive.cpp did not type check the nested inductive applications that are replaced by auxiliary types, so their parametric arguments escaped checking. A metaprogram running in the Lean process can register an ill-typed nested inductive whose constructor applies a .proj C 0 projection to a value of the unrelated type W, and the kernel admits the declaration through the ordinary checked addDecl path at maximum kernel checking, without sorry, unsafeCast, debug.skipKernelTC, addDeclWithoutChecking, FFI, or a modified .olean file. The result is a type confusion yielding a proof of False that carries no axioms, from which any proposition can be derived. The published proof of concept additionally pads two expressions until their hashes and approximate depths collide, which defeats kernel caching; that is the technique used to reach the flaw, not its cause. Exploitation requires running a metaprogram in-process, for example by building a project or importing a malicious Lake dependency.

- [https://github.com/endrazine/lean-cve-poc](https://github.com/endrazine/lean-cve-poc) :  ![starts](https://img.shields.io/github/stars/endrazine/lean-cve-poc.svg) ![forks](https://img.shields.io/github/forks/endrazine/lean-cve-poc.svg)


## CVE-2026-66747
 Zbtlink router firmware ships an embedded remote-control implant, ENDLESSDOORS, present in every published build across the product line. It is the open-source ycsunjane/rctl tool built in as an OpenWrt package (librctl.so), started at boot and run as root under the process name kworker to blend in with the kernel's [kworker/*] threads. It opens no listening port; it phones home over cleartext TCP to a hardcoded command-and-control server (command channel 7000, interactive-shell callback 7001) with no authentication and no transport encryption, re-attempting contact roughly every 35 seconds. Its command handler passes any received string to popen() as uid=0, and a reserved rctlbash command returns an interactive root shell. Because the channel is unauthenticated and cleartext, control is not limited to whoever planted it: any party that answers at the C2 address, occupies the network path (DNS or route hijack), or acquires the hardcoded fallback domain obtains unauthenticated remote code execution as root.

- [https://github.com/oiehnow/oieh-router-checker](https://github.com/oiehnow/oieh-router-checker) :  ![starts](https://img.shields.io/github/stars/oiehnow/oieh-router-checker.svg) ![forks](https://img.shields.io/github/forks/oiehnow/oieh-router-checker.svg)


## CVE-2026-65400
 An authentication issue was addressed with improved state management. This issue is fixed in macOS Sequoia 15.7.9, macOS Sonoma 14.8.9, macOS Tahoe 26.6.1. An attacker on the network may be able to authenticate to Screen Sharing without valid credentials.

- [https://github.com/acheong08/CVE-2026-65400](https://github.com/acheong08/CVE-2026-65400) :  ![starts](https://img.shields.io/github/stars/acheong08/CVE-2026-65400.svg) ![forks](https://img.shields.io/github/forks/acheong08/CVE-2026-65400.svg)


## CVE-2026-62911
 Authentication bypass by capture-replay in Microsoft Exchange Server allows an authorized attacker to elevate privileges over a network.

- [https://github.com/hypnguyen1209/CVE-2026-62911](https://github.com/hypnguyen1209/CVE-2026-62911) :  ![starts](https://img.shields.io/github/stars/hypnguyen1209/CVE-2026-62911.svg) ![forks](https://img.shields.io/github/forks/hypnguyen1209/CVE-2026-62911.svg)


## CVE-2026-58231
availability of the application.

- [https://github.com/WildanDeveloper/CVE-2026-58231](https://github.com/WildanDeveloper/CVE-2026-58231) :  ![starts](https://img.shields.io/github/stars/WildanDeveloper/CVE-2026-58231.svg) ![forks](https://img.shields.io/github/forks/WildanDeveloper/CVE-2026-58231.svg)


## CVE-2026-47630
 NVIDIA Triton Inference Server for Linux contains a vulnerability where an attacker could cause an absolute path traversal. A successful exploit might lead to code execution.

- [https://github.com/s1ko/CVE-2026-47630](https://github.com/s1ko/CVE-2026-47630) :  ![starts](https://img.shields.io/github/stars/s1ko/CVE-2026-47630.svg) ![forks](https://img.shields.io/github/forks/s1ko/CVE-2026-47630.svg)


## CVE-2026-43499
  	changelog ]

- [https://github.com/snothin/ghostlock-s26](https://github.com/snothin/ghostlock-s26) :  ![starts](https://img.shields.io/github/stars/snothin/ghostlock-s26.svg) ![forks](https://img.shields.io/github/forks/snothin/ghostlock-s26.svg)


## CVE-2026-41940
 cPanel and WHM versions after 11.40 contain an authentication bypass vulnerability in the login flow that allows unauthenticated remote attackers to gain unauthorized access to the control panel.

- [https://github.com/t4xo/CVE-2026-41940](https://github.com/t4xo/CVE-2026-41940) :  ![starts](https://img.shields.io/github/stars/t4xo/CVE-2026-41940.svg) ![forks](https://img.shields.io/github/forks/t4xo/CVE-2026-41940.svg)


## CVE-2026-34910
 A malicious actor with access to the network could exploit an Improper Input Validation vulnerability found in UniFi OS devices to execute a Command Injection.

- [https://github.com/gagaltotal/CVE-2026-34910-unifi-poc](https://github.com/gagaltotal/CVE-2026-34910-unifi-poc) :  ![starts](https://img.shields.io/github/stars/gagaltotal/CVE-2026-34910-unifi-poc.svg) ![forks](https://img.shields.io/github/forks/gagaltotal/CVE-2026-34910-unifi-poc.svg)


## CVE-2026-34909
 A malicious actor with access to the network could exploit a Path Traversal vulnerability found in UniFi OS devices to access files on the underlying system that could be manipulated to access an underlying account.

- [https://github.com/gagaltotal/CVE-2026-34910-unifi-poc](https://github.com/gagaltotal/CVE-2026-34910-unifi-poc) :  ![starts](https://img.shields.io/github/stars/gagaltotal/CVE-2026-34910-unifi-poc.svg) ![forks](https://img.shields.io/github/forks/gagaltotal/CVE-2026-34910-unifi-poc.svg)


## CVE-2026-32475
This issue affects Elementor Pro: from n/a through 4.2.1.

- [https://github.com/0xBlackash/CVE-2026-32475](https://github.com/0xBlackash/CVE-2026-32475) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-32475.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-32475.svg)


## CVE-2026-19478
 GitLab has remediated an issue in GitLab CE/EE affecting all versions from 18.2 before 18.11.11, 19.0 before 19.0.8, 19.1 before 19.1.6, and 19.2 before 19.2.4 that under certain conditions could allow an unauthenticated user to remotely modify or delete public projects and user data via a GraphQL directive.

- [https://github.com/punitdarji/Gitlab-CVE-2026-19478](https://github.com/punitdarji/Gitlab-CVE-2026-19478) :  ![starts](https://img.shields.io/github/stars/punitdarji/Gitlab-CVE-2026-19478.svg) ![forks](https://img.shields.io/github/forks/punitdarji/Gitlab-CVE-2026-19478.svg)


## CVE-2026-13736
 The NewPath WildApricotPress Add-on  WordPress plugin through 1.0.0 does not enforce its members-only field privacy on an unauthenticated REST route, allowing anonymous visitors to read member email addresses and phone numbers that are configured to be visible to members only.

- [https://github.com/MinhHK68/CVE-2026-13736](https://github.com/MinhHK68/CVE-2026-13736) :  ![starts](https://img.shields.io/github/stars/MinhHK68/CVE-2026-13736.svg) ![forks](https://img.shields.io/github/forks/MinhHK68/CVE-2026-13736.svg)


## CVE-2026-9198
 IBM Langflow OSS 1.0.0 through 1.10.0 allows unauthenticated attackers to chain /api/v1/auto_login (mints SUPERUSER tokens to any network caller) with /api/v1/validate/code (executes user code via exec()) to achieve full RCE on default Langflow deployments

- [https://github.com/K3ysTr0K3R/CVE-2026-9198](https://github.com/K3ysTr0K3R/CVE-2026-9198) :  ![starts](https://img.shields.io/github/stars/K3ysTr0K3R/CVE-2026-9198.svg) ![forks](https://img.shields.io/github/forks/K3ysTr0K3R/CVE-2026-9198.svg)


## CVE-2026-5865
 Type Confusion in V8 in Google Chrome prior to 147.0.7727.55 allowed a remote attacker to execute arbitrary code inside a sandbox via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/5o1z/CVE-2026-5865](https://github.com/5o1z/CVE-2026-5865) :  ![starts](https://img.shields.io/github/stars/5o1z/CVE-2026-5865.svg) ![forks](https://img.shields.io/github/forks/5o1z/CVE-2026-5865.svg)


## CVE-2026-5261
 A vulnerability was identified in Shandong Hoteam InforCenter PLM up to 8.3.8. The impacted element is the function uploadFileToIIS of the file /Base/BaseHandler.ashx. The manipulation of the argument File leads to unrestricted upload. It is possible to initiate the attack remotely. The exploit is publicly available and might be used. The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/s1ko/CVE-2026-52617](https://github.com/s1ko/CVE-2026-52617) :  ![starts](https://img.shields.io/github/stars/s1ko/CVE-2026-52617.svg) ![forks](https://img.shields.io/github/forks/s1ko/CVE-2026-52617.svg)
- [https://github.com/s1ko/CVE-2026-52616](https://github.com/s1ko/CVE-2026-52616) :  ![starts](https://img.shields.io/github/stars/s1ko/CVE-2026-52616.svg) ![forks](https://img.shields.io/github/forks/s1ko/CVE-2026-52616.svg)
- [https://github.com/s1ko/CVE-2026-52618](https://github.com/s1ko/CVE-2026-52618) :  ![starts](https://img.shields.io/github/stars/s1ko/CVE-2026-52618.svg) ![forks](https://img.shields.io/github/forks/s1ko/CVE-2026-52618.svg)


## CVE-2026-4788
 IBM Tivoli Netcool Impact 7.1.0.0 through 7.1.0.37 stores sensitive information in log files that could be read by a local user.

- [https://github.com/daehyuh/CVE-2026-47883](https://github.com/daehyuh/CVE-2026-47883) :  ![starts](https://img.shields.io/github/stars/daehyuh/CVE-2026-47883.svg) ![forks](https://img.shields.io/github/forks/daehyuh/CVE-2026-47883.svg)


## CVE-2026-3910
 Inappropriate implementation in V8 in Google Chrome prior to 146.0.7680.75 allowed a remote attacker to execute arbitrary code inside a sandbox via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/5o1z/CVE-2026-3910](https://github.com/5o1z/CVE-2026-3910) :  ![starts](https://img.shields.io/github/stars/5o1z/CVE-2026-3910.svg) ![forks](https://img.shields.io/github/forks/5o1z/CVE-2026-3910.svg)


## CVE-2026-3484
 A vulnerability was detected in PhialsBasement nmap-mcp-server up to bee6d23547d57ae02460022f7c78ac0893092e38. Affected by this issue is the function child_process.exec of the file src/index.ts of the component Nmap CLI Command Handler. The manipulation results in command injection. The attack may be performed from remote. This product utilizes a rolling release system for continuous delivery, and as such, version information for affected or updated releases is not disclosed. The patch is identified as 30a6b9e1c7fa6146f51e28d6ab83a2568d9a3488. It is best practice to apply a patch to resolve this issue.

- [https://github.com/s1ko/CVE-2026-52616](https://github.com/s1ko/CVE-2026-52616) :  ![starts](https://img.shields.io/github/stars/s1ko/CVE-2026-52616.svg) ![forks](https://img.shields.io/github/forks/s1ko/CVE-2026-52616.svg)


## CVE-2026-0740
 The Ninja Forms - File Uploads plugin for WordPress is vulnerable to arbitrary file uploads due to missing file type validation in the 'NF_FU_AJAX_Controllers_Uploads::handle_upload' function in all versions up to, and including, 3.3.26. This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible. Note: The vulnerability was partially patched in version 3.3.25 and fully patched in version 3.3.27.

- [https://github.com/llaytynher/CVE-2026-0740-upload-template](https://github.com/llaytynher/CVE-2026-0740-upload-template) :  ![starts](https://img.shields.io/github/stars/llaytynher/CVE-2026-0740-upload-template.svg) ![forks](https://img.shields.io/github/forks/llaytynher/CVE-2026-0740-upload-template.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces.svg)


## CVE-2025-20362
 This vulnerability is due to improper validation of user-supplied input in HTTP(S) requests. An attacker could exploit this vulnerability by sending crafted HTTP requests to a targeted web server on a device. A successful exploit could allow the attacker to access a restricted URL without authentication.

- [https://github.com/cobbbex/Cisco-ASA-vulnerability-research](https://github.com/cobbbex/Cisco-ASA-vulnerability-research) :  ![starts](https://img.shields.io/github/stars/cobbbex/Cisco-ASA-vulnerability-research.svg) ![forks](https://img.shields.io/github/forks/cobbbex/Cisco-ASA-vulnerability-research.svg)


## CVE-2025-20333
 This vulnerability is due to improper validation of user-supplied input in HTTP(S) requests. An attacker with valid VPN user credentials could exploit this vulnerability by sending crafted HTTP requests to an affected device. A successful exploit could allow the attacker to execute arbitrary code as root, possibly resulting in the complete compromise of the affected device.

- [https://github.com/cobbbex/Cisco-ASA-vulnerability-research](https://github.com/cobbbex/Cisco-ASA-vulnerability-research) :  ![starts](https://img.shields.io/github/stars/cobbbex/Cisco-ASA-vulnerability-research.svg) ![forks](https://img.shields.io/github/forks/cobbbex/Cisco-ASA-vulnerability-research.svg)


## CVE-2025-6647
The specific flaw exists within the parsing of U3D files. The issue results from the lack of proper validation of user-supplied data, which can result in a write past the end of an allocated object. An attacker can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-26644.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-alias](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-alias) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-alias.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-alias.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-tilde](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-tilde) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-tilde.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-tilde.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-zero-installs](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-zero-installs) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-zero-installs.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-zero-installs.svg)


## CVE-2024-49138
 Windows Common Log File System Driver Elevation of Privilege Vulnerability

- [https://github.com/basitsajidapply-stack/SOC-Investigation-CVE-2024-49138](https://github.com/basitsajidapply-stack/SOC-Investigation-CVE-2024-49138) :  ![starts](https://img.shields.io/github/stars/basitsajidapply-stack/SOC-Investigation-CVE-2024-49138.svg) ![forks](https://img.shields.io/github/forks/basitsajidapply-stack/SOC-Investigation-CVE-2024-49138.svg)


## CVE-2024-28000
 Incorrect Privilege Assignment vulnerability in LiteSpeed Technologies LiteSpeed Cache litespeed-cache.This issue affects LiteSpeed Cache: from n/a through = 6.3.0.1.

- [https://github.com/shawnng078-ops/CVE-2024-28000-Exploit-Lab](https://github.com/shawnng078-ops/CVE-2024-28000-Exploit-Lab) :  ![starts](https://img.shields.io/github/stars/shawnng078-ops/CVE-2024-28000-Exploit-Lab.svg) ![forks](https://img.shields.io/github/forks/shawnng078-ops/CVE-2024-28000-Exploit-Lab.svg)


## CVE-2022-22963
 In Spring Cloud Function versions 3.1.6, 3.2.2 and older unsupported versions, when using routing functionality it is possible for a user to provide a specially crafted SpEL as a routing-expression that may result in remote code execution and access to local resources.

- [https://github.com/r4y-br/CVE-2022-22963](https://github.com/r4y-br/CVE-2022-22963) :  ![starts](https://img.shields.io/github/stars/r4y-br/CVE-2022-22963.svg) ![forks](https://img.shields.io/github/forks/r4y-br/CVE-2022-22963.svg)


## CVE-2021-24092
 Microsoft Defender Elevation of Privilege Vulnerability

- [https://github.com/HORKimhab/CVE-2021-24092](https://github.com/HORKimhab/CVE-2021-24092) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2021-24092.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2021-24092.svg)


## CVE-2021-4422
 The POST SMTP Mailer plugin for WordPress is vulnerable to Cross-Site Request Forgery in versions up to, and including, 2.0.20. This is due to missing or incorrect nonce validation on the handleCsvExport() function. This makes it possible for unauthenticated attackers to trigger a CSV export via a forged request granted they can trick a site administrator into performing an action such as clicking on a link.

- [https://github.com/Super-Binary/cve-2021-44228](https://github.com/Super-Binary/cve-2021-44228) :  ![starts](https://img.shields.io/github/stars/Super-Binary/cve-2021-44228.svg) ![forks](https://img.shields.io/github/forks/Super-Binary/cve-2021-44228.svg)
- [https://github.com/asd58584388/CVE-2021-44228](https://github.com/asd58584388/CVE-2021-44228) :  ![starts](https://img.shields.io/github/stars/asd58584388/CVE-2021-44228.svg) ![forks](https://img.shields.io/github/forks/asd58584388/CVE-2021-44228.svg)


## CVE-2020-13671
 Drupal core does not properly sanitize certain filenames on uploaded files, which can lead to files being interpreted as the incorrect extension and served as the wrong MIME type or executed as PHP for certain hosting configurations. This issue affects: Drupal Drupal Core 9.0 versions prior to 9.0.8, 8.9 versions prior to 8.9.9, 8.8 versions prior to 8.8.11, and 7 versions prior to 7.74.

- [https://github.com/Dungsocool/CVE-2020-13671](https://github.com/Dungsocool/CVE-2020-13671) :  ![starts](https://img.shields.io/github/stars/Dungsocool/CVE-2020-13671.svg) ![forks](https://img.shields.io/github/forks/Dungsocool/CVE-2020-13671.svg)
- [https://github.com/Dungsocool/CVE-2020-13671-old](https://github.com/Dungsocool/CVE-2020-13671-old) :  ![starts](https://img.shields.io/github/stars/Dungsocool/CVE-2020-13671-old.svg) ![forks](https://img.shields.io/github/forks/Dungsocool/CVE-2020-13671-old.svg)


## CVE-2019-11447
 An issue was discovered in CutePHP CuteNews 2.1.2. An attacker can infiltrate the server through the avatar upload process in the profile area via the avatar_file field to index.php?mod=main&opt=personal. There is no effective control of $imgsize in /core/modules/dashboard.php. The header content of a file can be changed and the control can be bypassed for code execution. (An attacker can use the GIF header for this.)

- [https://github.com/capivara-research/WordPress-Path-Traversal-CVE-2019-11447](https://github.com/capivara-research/WordPress-Path-Traversal-CVE-2019-11447) :  ![starts](https://img.shields.io/github/stars/capivara-research/WordPress-Path-Traversal-CVE-2019-11447.svg) ![forks](https://img.shields.io/github/forks/capivara-research/WordPress-Path-Traversal-CVE-2019-11447.svg)


## CVE-2019-9053
 An issue was discovered in CMS Made Simple 2.2.8. It is possible with the News module, through a crafted URL, to achieve unauthenticated blind time-based SQL injection via the m1_idlist parameter.

- [https://github.com/quliyevresul7777/CVE-2019-9053](https://github.com/quliyevresul7777/CVE-2019-9053) :  ![starts](https://img.shields.io/github/stars/quliyevresul7777/CVE-2019-9053.svg) ![forks](https://img.shields.io/github/forks/quliyevresul7777/CVE-2019-9053.svg)


## CVE-2016-5195
 Race condition in mm/gup.c in the Linux kernel 2.x through 4.x before 4.8.3 allows local users to gain privileges by leveraging incorrect handling of a copy-on-write (COW) feature to write to a read-only memory mapping, as exploited in the wild in October 2016, aka "Dirty COW."

- [https://github.com/Minime794/CVE-2016-5195](https://github.com/Minime794/CVE-2016-5195) :  ![starts](https://img.shields.io/github/stars/Minime794/CVE-2016-5195.svg) ![forks](https://img.shields.io/github/forks/Minime794/CVE-2016-5195.svg)


## CVE-2011-2523
 vsftpd 2.3.4 downloaded between 20110630 and 20110703 contains a backdoor which opens a shell on port 6200/tcp.

- [https://github.com/rsakthikumar-cmd/metasploitable2-vsftpd-writeup](https://github.com/rsakthikumar-cmd/metasploitable2-vsftpd-writeup) :  ![starts](https://img.shields.io/github/stars/rsakthikumar-cmd/metasploitable2-vsftpd-writeup.svg) ![forks](https://img.shields.io/github/forks/rsakthikumar-cmd/metasploitable2-vsftpd-writeup.svg)
- [https://github.com/aish19siddiqua-commits/mtechweek_04](https://github.com/aish19siddiqua-commits/mtechweek_04) :  ![starts](https://img.shields.io/github/stars/aish19siddiqua-commits/mtechweek_04.svg) ![forks](https://img.shields.io/github/forks/aish19siddiqua-commits/mtechweek_04.svg)


## CVE-2009-1185
 udev before 1.4.1 does not verify whether a NETLINK message originates from kernel space, which allows local users to gain privileges by sending a NETLINK message from user space.

- [https://github.com/aish19siddiqua-commits/mtechweek_04](https://github.com/aish19siddiqua-commits/mtechweek_04) :  ![starts](https://img.shields.io/github/stars/aish19siddiqua-commits/mtechweek_04.svg) ![forks](https://img.shields.io/github/forks/aish19siddiqua-commits/mtechweek_04.svg)


## CVE-2004-2687
 distcc 2.x, as used in XCode 1.5 and others, when not configured to restrict access to the server port, allows remote attackers to execute arbitrary commands via compilation jobs, which are executed by the server without authorization checks.

- [https://github.com/aish19siddiqua-commits/mtechweek_04](https://github.com/aish19siddiqua-commits/mtechweek_04) :  ![starts](https://img.shields.io/github/stars/aish19siddiqua-commits/mtechweek_04.svg) ![forks](https://img.shields.io/github/forks/aish19siddiqua-commits/mtechweek_04.svg)

