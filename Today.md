# Update 2026-03-08
## CVE-2026-29041
 Chamilo is a learning management system. Prior to version 1.11.34, Chamilo LMS is affected by an authenticated remote code execution vulnerability caused by improper validation of uploaded files. The application relies solely on MIME-type verification when handling file uploads and does not adequately validate file extensions or enforce safe server-side storage restrictions. As a result, an authenticated low-privileged user can upload a crafted file containing executable code and subsequently execute arbitrary commands on the server. This issue has been patched in version 1.11.34.

- [https://github.com/celeboy711-hue/CVE-2026-29041](https://github.com/celeboy711-hue/CVE-2026-29041) :  ![starts](https://img.shields.io/github/stars/celeboy711-hue/CVE-2026-29041.svg) ![forks](https://img.shields.io/github/forks/celeboy711-hue/CVE-2026-29041.svg)


## CVE-2026-27966
 Langflow is a tool for building and deploying AI-powered agents and workflows. Prior to version 1.8.0, the CSV Agent node in Langflow hardcodes `allow_dangerous_code=True`, which automatically exposes LangChain’s Python REPL tool (`python_repl_ast`). As a result, an attacker can execute arbitrary Python and OS commands on the server via prompt injection, leading to full Remote Code Execution (RCE). Version 1.8.0 fixes the issue.

- [https://github.com/Anon-Cyber-Team/CVE-2026-27966--RCE-in-Langflow](https://github.com/Anon-Cyber-Team/CVE-2026-27966--RCE-in-Langflow) :  ![starts](https://img.shields.io/github/stars/Anon-Cyber-Team/CVE-2026-27966--RCE-in-Langflow.svg) ![forks](https://img.shields.io/github/forks/Anon-Cyber-Team/CVE-2026-27966--RCE-in-Langflow.svg)


## CVE-2026-27483
 MindsDB is a platform for building artificial intelligence from enterprise data. Prior to version 25.9.1.1, there is a path traversal vulnerability in Mindsdb's /api/files interface, which an authenticated attacker can exploit to achieve remote command execution. The vulnerability exists in the "Upload File" module, which corresponds to the API endpoint /api/files. Since the multipart file upload does not perform security checks on the uploaded file path, an attacker can perform path traversal by using `../` sequences in the filename field. The file write operation occurs before calling clear_filename and save_file, meaning there is no filtering of filenames or file types, allowing arbitrary content to be written to any path on the server. Version 25.9.1.1 patches the issue.

- [https://github.com/thewhiteh4t/cve-2026-27483](https://github.com/thewhiteh4t/cve-2026-27483) :  ![starts](https://img.shields.io/github/stars/thewhiteh4t/cve-2026-27483.svg) ![forks](https://img.shields.io/github/forks/thewhiteh4t/cve-2026-27483.svg)


## CVE-2026-24061
 telnetd in GNU Inetutils through 2.7 allows remote authentication bypass via a "-f root" value for the USER environment variable.

- [https://github.com/ilostmypassword/Melissae-Honeypot-Framework](https://github.com/ilostmypassword/Melissae-Honeypot-Framework) :  ![starts](https://img.shields.io/github/stars/ilostmypassword/Melissae-Honeypot-Framework.svg) ![forks](https://img.shields.io/github/forks/ilostmypassword/Melissae-Honeypot-Framework.svg)


## CVE-2026-22722
 A malicious actor with authenticated user privileges on a Windows based Workstation host may be able to cause a null pointer dereference error. To Remediate CVE-2026-22722, apply the patches listed in the "Fixed version" column of the 'Response Matrix'

- [https://github.com/D7EAD/CVE-2026-22722](https://github.com/D7EAD/CVE-2026-22722) :  ![starts](https://img.shields.io/github/stars/D7EAD/CVE-2026-22722.svg) ![forks](https://img.shields.io/github/forks/D7EAD/CVE-2026-22722.svg)


## CVE-2026-20131
 Note: If the FMC management interface does not have public internet access, the attack surface that is associated with this vulnerability is reduced.

- [https://github.com/Sushilsin/CVE-2026-20131](https://github.com/Sushilsin/CVE-2026-20131) :  ![starts](https://img.shields.io/github/stars/Sushilsin/CVE-2026-20131.svg) ![forks](https://img.shields.io/github/forks/Sushilsin/CVE-2026-20131.svg)
- [https://github.com/p3Nt3st3r-sTAr/CVE-2026-20131-POC](https://github.com/p3Nt3st3r-sTAr/CVE-2026-20131-POC) :  ![starts](https://img.shields.io/github/stars/p3Nt3st3r-sTAr/CVE-2026-20131-POC.svg) ![forks](https://img.shields.io/github/forks/p3Nt3st3r-sTAr/CVE-2026-20131-POC.svg)


## CVE-2026-20079
 This vulnerability is due to an improper system process that is created at boot time. An attacker could exploit this vulnerability by sending crafted HTTP requests to an affected device. A successful exploit could allow the attacker to execute a variety of scripts and commands that allow root access to the device.

- [https://github.com/Sushilsin/CVE-2026-20079](https://github.com/Sushilsin/CVE-2026-20079) :  ![starts](https://img.shields.io/github/stars/Sushilsin/CVE-2026-20079.svg) ![forks](https://img.shields.io/github/forks/Sushilsin/CVE-2026-20079.svg)


## CVE-2026-3304
 Multer is a node.js middleware for handling `multipart/form-data`. A vulnerability in Multer prior to version 2.1.0 allows an attacker to trigger a Denial of Service (DoS) by sending malformed requests, potentially causing resource exhaustion. Users should upgrade to version 2.1.0 to receive a patch. No known workarounds are available.

- [https://github.com/Mkway/CVE-2026-3304](https://github.com/Mkway/CVE-2026-3304) :  ![starts](https://img.shields.io/github/stars/Mkway/CVE-2026-3304.svg) ![forks](https://img.shields.io/github/forks/Mkway/CVE-2026-3304.svg)


## CVE-2026-2763
 Use-after-free in the JavaScript Engine component. This vulnerability affects Firefox  148, Firefox ESR  115.33, Firefox ESR  140.8, Thunderbird  148, and Thunderbird  140.8.

- [https://github.com/ppwwiinn/CVE-2026-2763-POC](https://github.com/ppwwiinn/CVE-2026-2763-POC) :  ![starts](https://img.shields.io/github/stars/ppwwiinn/CVE-2026-2763-POC.svg) ![forks](https://img.shields.io/github/forks/ppwwiinn/CVE-2026-2763-POC.svg)


## CVE-2026-0651
 On TP-Link Tapo C260 v1, path traversal is possible due to improper handling of specific GET request paths via https, allowing local unauthenticated probing of filesystem paths. An attacker on the local network can determine whether certain files exists on the device, with no read, write or code execution possibilities.

- [https://github.com/l0lsec/tapo-c260-rce](https://github.com/l0lsec/tapo-c260-rce) :  ![starts](https://img.shields.io/github/stars/l0lsec/tapo-c260-rce.svg) ![forks](https://img.shields.io/github/forks/l0lsec/tapo-c260-rce.svg)


## CVE-2025-63406
 An issue in Intermesh BV GroupOffice vulnerable before v.25.0.47 and 6.8.136 allows a remote attacker to execute arbitrary code via the dbToApi() and eval() in the FunctionField.php

- [https://github.com/Nxvh1337/CVE-2025-63406-PoC](https://github.com/Nxvh1337/CVE-2025-63406-PoC) :  ![starts](https://img.shields.io/github/stars/Nxvh1337/CVE-2025-63406-PoC.svg) ![forks](https://img.shields.io/github/forks/Nxvh1337/CVE-2025-63406-PoC.svg)


## CVE-2025-60736
 code-projects Online Medicine Guide 1.0 is vulnerable to SQL Injection in /login.php via the upass parameter.

- [https://github.com/Nxvh1337/CVE-2025-60736](https://github.com/Nxvh1337/CVE-2025-60736) :  ![starts](https://img.shields.io/github/stars/Nxvh1337/CVE-2025-60736.svg) ![forks](https://img.shields.io/github/forks/Nxvh1337/CVE-2025-60736.svg)


## CVE-2025-59287
 Deserialization of untrusted data in Windows Server Update Service allows an unauthorized attacker to execute code over a network.

- [https://github.com/GhoStZA-debug/PoC-CVE-collection](https://github.com/GhoStZA-debug/PoC-CVE-collection) :  ![starts](https://img.shields.io/github/stars/GhoStZA-debug/PoC-CVE-collection.svg) ![forks](https://img.shields.io/github/forks/GhoStZA-debug/PoC-CVE-collection.svg)


## CVE-2025-55182
 A pre-authentication remote code execution vulnerability exists in React Server Components versions 19.0.0, 19.1.0, 19.1.1, and 19.2.0 including the following packages: react-server-dom-parcel, react-server-dom-turbopack, and react-server-dom-webpack. The vulnerable code unsafely deserializes payloads from HTTP requests to Server Function endpoints.

- [https://github.com/RavinduRathnayaka/CVE-2025-55182-PoC](https://github.com/RavinduRathnayaka/CVE-2025-55182-PoC) :  ![starts](https://img.shields.io/github/stars/RavinduRathnayaka/CVE-2025-55182-PoC.svg) ![forks](https://img.shields.io/github/forks/RavinduRathnayaka/CVE-2025-55182-PoC.svg)


## CVE-2025-32463
 Sudo before 1.9.17p1 allows local users to obtain root access because /etc/nsswitch.conf from a user-controlled directory is used with the --chroot option.

- [https://github.com/12bijaya/CVE-2025-32463](https://github.com/12bijaya/CVE-2025-32463) :  ![starts](https://img.shields.io/github/stars/12bijaya/CVE-2025-32463.svg) ![forks](https://img.shields.io/github/forks/12bijaya/CVE-2025-32463.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/MKIRAHMET/CVE-2025-29927-PoC](https://github.com/MKIRAHMET/CVE-2025-29927-PoC) :  ![starts](https://img.shields.io/github/stars/MKIRAHMET/CVE-2025-29927-PoC.svg) ![forks](https://img.shields.io/github/forks/MKIRAHMET/CVE-2025-29927-PoC.svg)


## CVE-2025-11953
 The Metro Development Server, which is opened by the React Native Community CLI, binds to external interfaces by default. The server exposes an endpoint that is vulnerable to OS command injection. This allows unauthenticated network attackers to send a POST request to the server and run arbitrary executables. On Windows, the attackers can also execute arbitrary shell commands with fully controlled arguments.

- [https://github.com/GhoStZA-debug/PoC-CVE-collection](https://github.com/GhoStZA-debug/PoC-CVE-collection) :  ![starts](https://img.shields.io/github/stars/GhoStZA-debug/PoC-CVE-collection.svg) ![forks](https://img.shields.io/github/forks/GhoStZA-debug/PoC-CVE-collection.svg)


## CVE-2025-8941
 A flaw was found in linux-pam. The pam_namespace module may improperly handle user-controlled paths, allowing local users to exploit symlink attacks and race conditions to elevate their privileges to root. This CVE provides a "complete" fix for CVE-2025-6020.

- [https://github.com/GhoStZA-debug/PoC-CVE-collection](https://github.com/GhoStZA-debug/PoC-CVE-collection) :  ![starts](https://img.shields.io/github/stars/GhoStZA-debug/PoC-CVE-collection.svg) ![forks](https://img.shields.io/github/forks/GhoStZA-debug/PoC-CVE-collection.svg)


## CVE-2025-6695
 A vulnerability was found in LabRedesCefetRJ WeGIA 3.4.0 and classified as problematic. This issue affects some unknown processing of the file /html/matPat/adicionar_categoria.php of the component Additional Categoria. The manipulation of the argument Insira a nova categoria leads to cross site scripting. The attack may be initiated remotely. The exploit has been disclosed to the public and may be used. The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/TheWoodenBench/CVE-2025-66955](https://github.com/TheWoodenBench/CVE-2025-66955) :  ![starts](https://img.shields.io/github/stars/TheWoodenBench/CVE-2025-66955.svg) ![forks](https://img.shields.io/github/forks/TheWoodenBench/CVE-2025-66955.svg)
- [https://github.com/TheWoodenBench/CVE-2025-66956](https://github.com/TheWoodenBench/CVE-2025-66956) :  ![starts](https://img.shields.io/github/stars/TheWoodenBench/CVE-2025-66956.svg) ![forks](https://img.shields.io/github/forks/TheWoodenBench/CVE-2025-66956.svg)


## CVE-2024-43425
 A flaw was found in Moodle. Additional restrictions are required to avoid a remote code execution risk in calculated question types. Note: This requires the capability to add/update questions.

- [https://github.com/wvverez/CVE-2024-43425](https://github.com/wvverez/CVE-2024-43425) :  ![starts](https://img.shields.io/github/stars/wvverez/CVE-2024-43425.svg) ![forks](https://img.shields.io/github/forks/wvverez/CVE-2024-43425.svg)


## CVE-2023-38909
 An issue in TPLink Smart Bulb Tapo series L530 before 1.2.4, L510E before 1.1.0, L630 before 1.0.4, P100 before 1.5.0, and Tapo Application 2.8.14 allows a remote attacker to obtain sensitive information via the IV component in the AES128-CBC function.

- [https://github.com/davidebonav/tapoexploits](https://github.com/davidebonav/tapoexploits) :  ![starts](https://img.shields.io/github/stars/davidebonav/tapoexploits.svg) ![forks](https://img.shields.io/github/forks/davidebonav/tapoexploits.svg)


## CVE-2023-38908
 An issue in TPLink Smart Bulb Tapo series L530 before 1.2.4, L510E before 1.1.0, L630 before 1.0.4, P100 before 1.5.0, and Tapo Application 2.8.14 allows a remote attacker to obtain sensitive information via the TSKEP authentication function.

- [https://github.com/davidebonav/tapoexploits](https://github.com/davidebonav/tapoexploits) :  ![starts](https://img.shields.io/github/stars/davidebonav/tapoexploits.svg) ![forks](https://img.shields.io/github/forks/davidebonav/tapoexploits.svg)


## CVE-2023-38907
 An issue in TPLink Smart Bulb Tapo series L530 before 1.2.4, L510E before 1.1.0, L630 before 1.0.4, P100 before 1.5.0, and Tapo Application 2.8.14 allows a remote attacker to replay old messages encrypted with a still valid session key.

- [https://github.com/davidebonav/tapoexploits](https://github.com/davidebonav/tapoexploits) :  ![starts](https://img.shields.io/github/stars/davidebonav/tapoexploits.svg) ![forks](https://img.shields.io/github/forks/davidebonav/tapoexploits.svg)


## CVE-2023-38906
 An issue in TPLink Smart Bulb Tapo series L530 1.1.9, L510E 1.0.8, L630 1.0.3, P100 1.4.9, Smart Camera Tapo series C200 1.1.18, and Tapo Application 2.8.14 allows a remote attacker to obtain sensitive information via the authentication code for the UDP message.

- [https://github.com/davidebonav/tapoexploits](https://github.com/davidebonav/tapoexploits) :  ![starts](https://img.shields.io/github/stars/davidebonav/tapoexploits.svg) ![forks](https://img.shields.io/github/forks/davidebonav/tapoexploits.svg)


## CVE-2023-31902
 RPA Technology Mobile Mouse 3.6.0.4 is vulnerable to Remote Code Execution (RCE).

- [https://github.com/Karan-143/exploitation-validator](https://github.com/Karan-143/exploitation-validator) :  ![starts](https://img.shields.io/github/stars/Karan-143/exploitation-validator.svg) ![forks](https://img.shields.io/github/forks/Karan-143/exploitation-validator.svg)


## CVE-2023-27372
 SPIP before 4.2.1 allows Remote Code Execution via form values in the public area because serialization is mishandled. The fixed versions are 3.2.18, 4.0.10, 4.1.8, and 4.2.1.

- [https://github.com/scriniariii/CVE-2023-27372](https://github.com/scriniariii/CVE-2023-27372) :  ![starts](https://img.shields.io/github/stars/scriniariii/CVE-2023-27372.svg) ![forks](https://img.shields.io/github/forks/scriniariii/CVE-2023-27372.svg)


## CVE-2023-21746
 Windows NTLM Elevation of Privilege Vulnerability

- [https://github.com/TailoredSecOps/PEREDBOEMPATAT-BOF](https://github.com/TailoredSecOps/PEREDBOEMPATAT-BOF) :  ![starts](https://img.shields.io/github/stars/TailoredSecOps/PEREDBOEMPATAT-BOF.svg) ![forks](https://img.shields.io/github/forks/TailoredSecOps/PEREDBOEMPATAT-BOF.svg)


## CVE-2022-46169
This command injection vulnerability allows an unauthenticated user to execute arbitrary commands if a `poller_item` with the `action` type `POLLER_ACTION_SCRIPT_PHP` (`2`) is configured. The authorization bypass should be prevented by not allowing an attacker to make `get_client_addr` (file `lib/functions.php`) return an arbitrary IP address. This could be done by not honoring the `HTTP_...` `$_SERVER` variables. If these should be kept for compatibility reasons it should at least be prevented to fake the IP address of the server running Cacti. This vulnerability has been addressed in both the 1.2.x and 1.3.x release branches with `1.2.23` being the first release containing the patch.

- [https://github.com/svchost9913/CVE-2022-46169_unauth_remote_code_execution](https://github.com/svchost9913/CVE-2022-46169_unauth_remote_code_execution) :  ![starts](https://img.shields.io/github/stars/svchost9913/CVE-2022-46169_unauth_remote_code_execution.svg) ![forks](https://img.shields.io/github/forks/svchost9913/CVE-2022-46169_unauth_remote_code_execution.svg)


## CVE-2022-24716
 Icinga Web 2 is an open source monitoring web interface, framework and command-line interface. Unauthenticated users can leak the contents of files of the local system accessible to the web-server user, including `icingaweb2` configuration files with database credentials. This issue has been resolved in versions 2.9.6 and 2.10 of Icinga Web 2. Database credentials should be rotated.

- [https://github.com/gmh5225/CVE-2022-24716](https://github.com/gmh5225/CVE-2022-24716) :  ![starts](https://img.shields.io/github/stars/gmh5225/CVE-2022-24716.svg) ![forks](https://img.shields.io/github/forks/gmh5225/CVE-2022-24716.svg)


## CVE-2022-24715
 Icinga Web 2 is an open source monitoring web interface, framework and command-line interface. Authenticated users, with access to the configuration, can create SSH resource files in unintended directories, leading to the execution of arbitrary code. This issue has been resolved in versions 2.8.6, 2.9.6 and 2.10 of Icinga Web 2. Users unable to upgrade should limit access to the Icinga Web 2 configuration.

- [https://github.com/nimphtix/CVE-2022-24715](https://github.com/nimphtix/CVE-2022-24715) :  ![starts](https://img.shields.io/github/stars/nimphtix/CVE-2022-24715.svg) ![forks](https://img.shields.io/github/forks/nimphtix/CVE-2022-24715.svg)


## CVE-2022-2463
 Rockwell Automation ISaGRAF Workbench software versions 6.0 through 6.6.9 are affected by a Path Traversal vulnerability. A crafted malicious .7z exchange file may allow an attacker to gain the privileges of the ISaGRAF Workbench software when opened. If the software is running at the SYSTEM level, then the attacker will gain admin level privileges. User interaction is required for this exploit to be successful.

- [https://github.com/726232111/CVE-2022-24638](https://github.com/726232111/CVE-2022-24638) :  ![starts](https://img.shields.io/github/stars/726232111/CVE-2022-24638.svg) ![forks](https://img.shields.io/github/forks/726232111/CVE-2022-24638.svg)


## CVE-2022-0543
 It was discovered, that redis, a persistent key-value database, due to a packaging issue, is prone to a (Debian-specific) Lua sandbox escape, which could result in remote code execution.

- [https://github.com/abramas/CVE-2022-0543](https://github.com/abramas/CVE-2022-0543) :  ![starts](https://img.shields.io/github/stars/abramas/CVE-2022-0543.svg) ![forks](https://img.shields.io/github/forks/abramas/CVE-2022-0543.svg)


## CVE-2021-44142
 The Samba vfs_fruit module uses extended file attributes (EA, xattr) to provide "...enhanced compatibility with Apple SMB clients and interoperability with a Netatalk 3 AFP fileserver." Samba versions prior to 4.13.17, 4.14.12 and 4.15.5 with vfs_fruit configured allow out-of-bounds heap read and write via specially crafted extended file attributes. A remote attacker with write access to extended file attributes can execute arbitrary code with the privileges of smbd, typically root.

- [https://github.com/Nxvh1337/CVE-2021-44142-vulnerable-lab](https://github.com/Nxvh1337/CVE-2021-44142-vulnerable-lab) :  ![starts](https://img.shields.io/github/stars/Nxvh1337/CVE-2021-44142-vulnerable-lab.svg) ![forks](https://img.shields.io/github/forks/Nxvh1337/CVE-2021-44142-vulnerable-lab.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/honypot/CVE-2021-41773](https://github.com/honypot/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/honypot/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/honypot/CVE-2021-41773.svg)


## CVE-2021-3130
 Within the Open-AudIT up to version 3.5.3 application, the web interface hides SSH secrets, Windows passwords, and SNMP strings from users using HTML 'password field' obfuscation. By using Developer tools or similar, it is possible to change the obfuscation so that the credentials are visible.

- [https://github.com/lusterx/CVE-2021-3130](https://github.com/lusterx/CVE-2021-3130) :  ![starts](https://img.shields.io/github/stars/lusterx/CVE-2021-3130.svg) ![forks](https://img.shields.io/github/forks/lusterx/CVE-2021-3130.svg)


## CVE-2020-16938
pThe update addresses the vulnerability by correcting how the Windows kernel handles objects in memory./p

- [https://github.com/ioncodes/CVE-2020-16938](https://github.com/ioncodes/CVE-2020-16938) :  ![starts](https://img.shields.io/github/stars/ioncodes/CVE-2020-16938.svg) ![forks](https://img.shields.io/github/forks/ioncodes/CVE-2020-16938.svg)


## CVE-2020-1350
 A remote code execution vulnerability exists in Windows Domain Name System servers when they fail to properly handle requests, aka 'Windows DNS Server Remote Code Execution Vulnerability'.

- [https://github.com/sty886/CVE-2020-1350-SigRed](https://github.com/sty886/CVE-2020-1350-SigRed) :  ![starts](https://img.shields.io/github/stars/sty886/CVE-2020-1350-SigRed.svg) ![forks](https://img.shields.io/github/forks/sty886/CVE-2020-1350-SigRed.svg)


## CVE-2019-14271
 In Docker 19.03.x before 19.03.1 linked against the GNU C Library (aka glibc), code injection can occur when the nsswitch facility dynamically loads a library inside a chroot that contains the contents of the container.

- [https://github.com/ilahgl3/CVE_2019_14271](https://github.com/ilahgl3/CVE_2019_14271) :  ![starts](https://img.shields.io/github/stars/ilahgl3/CVE_2019_14271.svg) ![forks](https://img.shields.io/github/forks/ilahgl3/CVE_2019_14271.svg)


## CVE-2019-5736
 runc through 1.0-rc6, as used in Docker before 18.09.2 and other products, allows attackers to overwrite the host runc binary (and consequently obtain host root access) by leveraging the ability to execute a command as root within one of these types of containers: (1) a new container with an attacker-controlled image, or (2) an existing container, to which the attacker previously had write access, that can be attached with docker exec. This occurs because of file-descriptor mishandling, related to /proc/self/exe.

- [https://github.com/ilahgl3/CVE_2019_5736](https://github.com/ilahgl3/CVE_2019_5736) :  ![starts](https://img.shields.io/github/stars/ilahgl3/CVE_2019_5736.svg) ![forks](https://img.shields.io/github/forks/ilahgl3/CVE_2019_5736.svg)


## CVE-2017-7662
 Apache CXF Fediz ships with an OpenId Connect (OIDC) service which has a Client Registration Service, which is a simple web application that allows clients to be created, deleted, etc. A CSRF (Cross Style Request Forgery) style vulnerability has been found in this web application in Apache CXF Fediz prior to 1.4.0 and 1.3.2, meaning that a malicious web application could create new clients, or reset secrets, etc, after the admin user has logged on to the client registration service and the session is still active.

- [https://github.com/andikahilmy/CVE-2017-7662-cxf-fediz-vulnerable](https://github.com/andikahilmy/CVE-2017-7662-cxf-fediz-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2017-7662-cxf-fediz-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2017-7662-cxf-fediz-vulnerable.svg)

