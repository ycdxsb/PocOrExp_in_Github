# Update 2026-03-07
## CVE-2026-29000
 pac4j-jwt versions prior to 4.5.9, 5.7.9, and 6.3.3 contain an authentication bypass vulnerability in JwtAuthenticator when processing encrypted JWTs that allows remote attackers to forge authentication tokens. Attackers who possess the server's RSA public key can create a JWE-wrapped PlainJWT with arbitrary subject and role claims, bypassing signature verification to authenticate as any user including administrators.

- [https://github.com/kernelzeroday/CVE-2026-29000](https://github.com/kernelzeroday/CVE-2026-29000) :  ![starts](https://img.shields.io/github/stars/kernelzeroday/CVE-2026-29000.svg) ![forks](https://img.shields.io/github/forks/kernelzeroday/CVE-2026-29000.svg)


## CVE-2026-28289
 FreeScout is a free help desk and shared inbox built with PHP's Laravel framework. A patch bypass vulnerability for CVE-2026-27636 in FreeScout 1.8.206 and earlier allows any authenticated user with file upload permissions to achieve Remote Code Execution (RCE) on the server by uploading a malicious .htaccess file using a zero-width space character prefix to bypass the security check. The vulnerability exists in the sanitizeUploadedFileName() function in app/Http/Helper.php. The function contains a Time-of-Check to Time-of-Use (TOCTOU) flaw where the dot-prefix check occurs before sanitization removes invisible characters. This vulnerability is fixed in 1.8.207.

- [https://github.com/0xAshwesker/CVE-2026-28289](https://github.com/0xAshwesker/CVE-2026-28289) :  ![starts](https://img.shields.io/github/stars/0xAshwesker/CVE-2026-28289.svg) ![forks](https://img.shields.io/github/forks/0xAshwesker/CVE-2026-28289.svg)


## CVE-2026-26418
 Missing authentication and authorization in the web API of Tata Consultancy Services Cognix Recon Client v3.0 allows remote attackers to access application functionality without restriction via the network.

- [https://github.com/aksalsalimi/CVE-2026-26418](https://github.com/aksalsalimi/CVE-2026-26418) :  ![starts](https://img.shields.io/github/stars/aksalsalimi/CVE-2026-26418.svg) ![forks](https://img.shields.io/github/forks/aksalsalimi/CVE-2026-26418.svg)


## CVE-2026-26417
 A broken access control vulnerability in the password reset functionality of Tata Consultancy Services Cognix Recon Client v3.0 allows authenticated users to reset passwords of arbitrary user accounts via crafted requests.

- [https://github.com/aksalsalimi/CVE-2026-26417](https://github.com/aksalsalimi/CVE-2026-26417) :  ![starts](https://img.shields.io/github/stars/aksalsalimi/CVE-2026-26417.svg) ![forks](https://img.shields.io/github/forks/aksalsalimi/CVE-2026-26417.svg)


## CVE-2026-26416
 An authorization bypass vulnerability in Tata Consultancy Services Cognix Recon Client v3.0 allows authenticated users to escalate privileges across role boundaries via crafted requests.

- [https://github.com/aksalsalimi/CVE-2026-26416](https://github.com/aksalsalimi/CVE-2026-26416) :  ![starts](https://img.shields.io/github/stars/aksalsalimi/CVE-2026-26416.svg) ![forks](https://img.shields.io/github/forks/aksalsalimi/CVE-2026-26416.svg)


## CVE-2026-22686
 Enclave is a secure JavaScript sandbox designed for safe AI agent code execution. Prior to 2.7.0, there is a critical sandbox escape vulnerability in enclave-vm that allows untrusted, sandboxed JavaScript code to execute arbitrary code in the host Node.js runtime. When a tool invocation fails, enclave-vm exposes a host-side Error object to sandboxed code. This Error object retains its host realm prototype chain, which can be traversed to reach the host Function constructor. An attacker can intentionally trigger a host error, then climb the prototype chain. Using the host Function constructor, arbitrary JavaScript can be compiled and executed in the host context, fully bypassing the sandbox and granting access to sensitive resources such as process.env, filesystem, and network. This breaks enclave-vm’s core security guarantee of isolating untrusted code. This vulnerability is fixed in 2.7.0.

- [https://github.com/moltengama/CVE-2026-22686-RemoteCodeExecution-RCE-PoC](https://github.com/moltengama/CVE-2026-22686-RemoteCodeExecution-RCE-PoC) :  ![starts](https://img.shields.io/github/stars/moltengama/CVE-2026-22686-RemoteCodeExecution-RCE-PoC.svg) ![forks](https://img.shields.io/github/forks/moltengama/CVE-2026-22686-RemoteCodeExecution-RCE-PoC.svg)


## CVE-2026-21858
 n8n is an open source workflow automation platform. Versions starting with 1.65.0 and below 1.121.0 enable an attacker to access files on the underlying server through execution of certain form-based workflows. A vulnerable workflow could grant access to an unauthenticated remote attacker, resulting in exposure of sensitive information stored on the system and may enable further compromise depending on deployment configuration and workflow usage. This issue is fixed in version 1.121.0.

- [https://github.com/0xAshwesker/CVE-2026-21858](https://github.com/0xAshwesker/CVE-2026-21858) :  ![starts](https://img.shields.io/github/stars/0xAshwesker/CVE-2026-21858.svg) ![forks](https://img.shields.io/github/forks/0xAshwesker/CVE-2026-21858.svg)


## CVE-2026-20127
This vulnerability exists because the peering authentication mechanism in an affected system is not working properly. An attacker could exploit this vulnerability by sending crafted requests to an affected system. A successful exploit could allow the attacker to log in to an affected Cisco Catalyst SD-WAN Controller as an internal, high-privileged, non-root&nbsp;user account. Using this account, the attacker could access NETCONF, which would then allow the attacker to manipulate network configuration for the SD-WAN fabric.&nbsp;

- [https://github.com/leemuun/CVE-2026-20127](https://github.com/leemuun/CVE-2026-20127) :  ![starts](https://img.shields.io/github/stars/leemuun/CVE-2026-20127.svg) ![forks](https://img.shields.io/github/forks/leemuun/CVE-2026-20127.svg)
- [https://github.com/BugFor-Pings/CVE-2026-20127_EXP](https://github.com/BugFor-Pings/CVE-2026-20127_EXP) :  ![starts](https://img.shields.io/github/stars/BugFor-Pings/CVE-2026-20127_EXP.svg) ![forks](https://img.shields.io/github/forks/BugFor-Pings/CVE-2026-20127_EXP.svg)


## CVE-2026-20079
 This vulnerability is due to an improper system process that is created at boot time. An attacker could exploit this vulnerability by sending crafted HTTP requests to an affected device. A successful exploit could allow the attacker to execute a variety of scripts and commands that allow root access to the device.

- [https://github.com/b1gchoi/CVE-2026-20079](https://github.com/b1gchoi/CVE-2026-20079) :  ![starts](https://img.shields.io/github/stars/b1gchoi/CVE-2026-20079.svg) ![forks](https://img.shields.io/github/forks/b1gchoi/CVE-2026-20079.svg)


## CVE-2026-2978
 A vulnerability was detected in FastApiAdmin up to 2.2.0. This vulnerability affects the function upload_file_controller of the file /backend/app/api/v1/module_system/params/controller.py of the component Scheduled Task API. Performing a manipulation results in unrestricted upload. The attack can be initiated remotely. The exploit is now public and may be used.

- [https://github.com/Jvr2022/CVE-2026-29786](https://github.com/Jvr2022/CVE-2026-29786) :  ![starts](https://img.shields.io/github/stars/Jvr2022/CVE-2026-29786.svg) ![forks](https://img.shields.io/github/forks/Jvr2022/CVE-2026-29786.svg)


## CVE-2026-2636
 This vulnerability is caused by a CWE‑159: "Improper Handling of Invalid Use of Special Elements" weakness, which leads to an unrecoverable inconsistency in the CLFS.sys driver. This condition forces a call to the KeBugCheckEx function, allowing an unprivileged user to trigger a system crash. Microsoft silently fixed this vulnerability in the September 2025 cumulative update for Windows 11 2024 LTSC and Windows Server 2025. Windows 25H2 (released in September) was released with the patch. Windows 1123h2 and earlier versions remain vulnerable.

- [https://github.com/uname1able/CVE-2026-2636](https://github.com/uname1able/CVE-2026-2636) :  ![starts](https://img.shields.io/github/stars/uname1able/CVE-2026-2636.svg) ![forks](https://img.shields.io/github/forks/uname1able/CVE-2026-2636.svg)


## CVE-2025-70995
 An issue in Aranda Service Desk Web Edition (ASDK API 8.6) allows authenticated attackers to achieve remote code execution due to improper validation of uploaded files. An authenticated user can upload a crafted web.config file by sending a crafted POST request to /ASDKAPI/api/v8.6/item/addfile, which is processed by the ASP.NET runtime. The uploaded configuration file alters the execution context of the upload directory, enabling compilation and execution of attacker-controlled code (e.g., generation of an .aspx webshell). This allows remote command execution on the server without user interaction beyond authentication, impacting both On-Premise and SaaS deployments.

- [https://github.com/0xcronos/CVE](https://github.com/0xcronos/CVE) :  ![starts](https://img.shields.io/github/stars/0xcronos/CVE.svg) ![forks](https://img.shields.io/github/forks/0xcronos/CVE.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions.svg)


## CVE-2025-65320
 Abacre Restaurant Point of Sale (POS) up to 15.0.0.1656 are vulnerable to Cleartext Storage of Sensitive Information in Memory. The application leaves valid device-bound license keys in process memory during an activation attempt.

- [https://github.com/yonathanpy/CVE-2025-65320](https://github.com/yonathanpy/CVE-2025-65320) :  ![starts](https://img.shields.io/github/stars/yonathanpy/CVE-2025-65320.svg) ![forks](https://img.shields.io/github/forks/yonathanpy/CVE-2025-65320.svg)


## CVE-2025-32463
 Sudo before 1.9.17p1 allows local users to obtain root access because /etc/nsswitch.conf from a user-controlled directory is used with the --chroot option.

- [https://github.com/yonathanpy/CVE-2025-32462-CVE-2025-32463-PoC-Lab](https://github.com/yonathanpy/CVE-2025-32462-CVE-2025-32463-PoC-Lab) :  ![starts](https://img.shields.io/github/stars/yonathanpy/CVE-2025-32462-CVE-2025-32463-PoC-Lab.svg) ![forks](https://img.shields.io/github/forks/yonathanpy/CVE-2025-32462-CVE-2025-32463-PoC-Lab.svg)
- [https://github.com/0xAshwesker/CVE-2025-32463](https://github.com/0xAshwesker/CVE-2025-32463) :  ![starts](https://img.shields.io/github/stars/0xAshwesker/CVE-2025-32463.svg) ![forks](https://img.shields.io/github/forks/0xAshwesker/CVE-2025-32463.svg)


## CVE-2025-32462
 Sudo before 1.9.17p1, when used with a sudoers file that specifies a host that is neither the current host nor ALL, allows listed users to execute commands on unintended machines.

- [https://github.com/yonathanpy/CVE-2025-32462-CVE-2025-32463-PoC-Lab](https://github.com/yonathanpy/CVE-2025-32462-CVE-2025-32463-PoC-Lab) :  ![starts](https://img.shields.io/github/stars/yonathanpy/CVE-2025-32462-CVE-2025-32463-PoC-Lab.svg) ![forks](https://img.shields.io/github/forks/yonathanpy/CVE-2025-32462-CVE-2025-32463-PoC-Lab.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/maronnjapan/claude-create-CVE-2025-29927](https://github.com/maronnjapan/claude-create-CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/maronnjapan/claude-create-CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/maronnjapan/claude-create-CVE-2025-29927.svg)
- [https://github.com/0xPThree/next.js_cve-2025-29927](https://github.com/0xPThree/next.js_cve-2025-29927) :  ![starts](https://img.shields.io/github/stars/0xPThree/next.js_cve-2025-29927.svg) ![forks](https://img.shields.io/github/forks/0xPThree/next.js_cve-2025-29927.svg)


## CVE-2025-15030
 The User Profile Builder  WordPress plugin before 3.15.2 does not have a proper password reset process, allowing a few unauthenticated requests to reset the password of any user by knowing their username, such as administrator ones, and therefore gain access to their account

- [https://github.com/bastianhaxor1337/CVE-2025-15030](https://github.com/bastianhaxor1337/CVE-2025-15030) :  ![starts](https://img.shields.io/github/stars/bastianhaxor1337/CVE-2025-15030.svg) ![forks](https://img.shields.io/github/forks/bastianhaxor1337/CVE-2025-15030.svg)


## CVE-2025-14847
 Mismatched length fields in Zlib compressed protocol headers may allow a read of uninitialized heap memory by an unauthenticated client. This issue affects all MongoDB Server v7.0 prior to 7.0.28 versions, MongoDB Server v8.0 versions prior to 8.0.17, MongoDB Server v8.2 versions prior to 8.2.3, MongoDB Server v6.0 versions prior to 6.0.27, MongoDB Server v5.0 versions prior to 5.0.32, MongoDB Server v4.4 versions prior to 4.4.30, MongoDB Server v4.2 versions greater than or equal to 4.2.0, MongoDB Server v4.0 versions greater than or equal to 4.0.0, and MongoDB Server v3.6 versions greater than or equal to 3.6.0.

- [https://github.com/0xAshwesker/CVE-2025-14847](https://github.com/0xAshwesker/CVE-2025-14847) :  ![starts](https://img.shields.io/github/stars/0xAshwesker/CVE-2025-14847.svg) ![forks](https://img.shields.io/github/forks/0xAshwesker/CVE-2025-14847.svg)


## CVE-2025-9074
This can lead to execution of a wide range of privileged commands to the engine API, including controlling other containers, creating new ones, managing images etc. In some circumstances (e.g. Docker Desktop for Windows with WSL backend) it also allows mounting the host drive with the same privileges as the user running Docker Desktop.

- [https://github.com/0xmrsecurity/Public_Poc](https://github.com/0xmrsecurity/Public_Poc) :  ![starts](https://img.shields.io/github/stars/0xmrsecurity/Public_Poc.svg) ![forks](https://img.shields.io/github/forks/0xmrsecurity/Public_Poc.svg)


## CVE-2025-5777
 Insufficient input validation leading to memory overread when the NetScaler is configured as a Gateway (VPN virtual server, ICA Proxy, CVPN, RDP Proxy) OR AAA virtual server

- [https://github.com/0xAshwesker/CVE-2025-5777](https://github.com/0xAshwesker/CVE-2025-5777) :  ![starts](https://img.shields.io/github/stars/0xAshwesker/CVE-2025-5777.svg) ![forks](https://img.shields.io/github/forks/0xAshwesker/CVE-2025-5777.svg)


## CVE-2024-46987
 Camaleon CMS is a dynamic and advanced content management system based on Ruby on Rails. A path traversal vulnerability accessible via MediaController's download_private_file method allows authenticated users to download any file on the web server Camaleon CMS is running on (depending on the file permissions). This issue may lead to Information Disclosure. This issue has been addressed in release version 2.8.2. Users are advised to upgrade. There are no known workarounds for this vulnerability.

- [https://github.com/0xmrsecurity/Public_Poc](https://github.com/0xmrsecurity/Public_Poc) :  ![starts](https://img.shields.io/github/stars/0xmrsecurity/Public_Poc.svg) ![forks](https://img.shields.io/github/forks/0xmrsecurity/Public_Poc.svg)


## CVE-2024-43035
 Fonoster 0.5.5 before 0.6.1 allows ../ directory traversal to read arbitrary files via the /sounds/:file or /tts/:file VoiceServer endpoint. This occurs in serveFiles in mods/voice/src/utils.ts. NOTE: serveFiles exists in 0.5.5 but not in the next release, 0.6.1.

- [https://github.com/ZeroPathAI/Fonoster-LFI-PoC](https://github.com/ZeroPathAI/Fonoster-LFI-PoC) :  ![starts](https://img.shields.io/github/stars/ZeroPathAI/Fonoster-LFI-PoC.svg) ![forks](https://img.shields.io/github/forks/ZeroPathAI/Fonoster-LFI-PoC.svg)


## CVE-2024-25096
 Improper Control of Generation of Code ('Code Injection') vulnerability in Canto Inc. Canto allows Code Injection.This issue affects Canto: from n/a through 3.0.7.

- [https://github.com/puppetma4ster/Metasploit-Wordpress-Canto-Exploit-RCE](https://github.com/puppetma4ster/Metasploit-Wordpress-Canto-Exploit-RCE) :  ![starts](https://img.shields.io/github/stars/puppetma4ster/Metasploit-Wordpress-Canto-Exploit-RCE.svg) ![forks](https://img.shields.io/github/forks/puppetma4ster/Metasploit-Wordpress-Canto-Exploit-RCE.svg)


## CVE-2024-21626
 runc is a CLI tool for spawning and running containers on Linux according to the OCI specification. In runc 1.1.11 and earlier, due to an internal file descriptor leak, an attacker could cause a newly-spawned container process (from runc exec) to have a working directory in the host filesystem namespace, allowing for a container escape by giving access to the host filesystem ("attack 2"). The same attack could be used by a malicious image to allow a container process to gain access to the host filesystem through runc run ("attack 1"). Variants of attacks 1 and 2 could be also be used to overwrite semi-arbitrary host binaries, allowing for complete container escapes ("attack 3a" and "attack 3b"). runc 1.1.12 includes patches for this issue.

- [https://github.com/skysbsb/CVE-2024-21626-POC](https://github.com/skysbsb/CVE-2024-21626-POC) :  ![starts](https://img.shields.io/github/stars/skysbsb/CVE-2024-21626-POC.svg) ![forks](https://img.shields.io/github/forks/skysbsb/CVE-2024-21626-POC.svg)


## CVE-2024-3912
 Certain models of ASUS routers have an arbitrary firmware upload vulnerability. An unauthenticated remote attacker can exploit this vulnerability to execute arbitrary system commands on the device.

- [https://github.com/H4rk3nz0/CVE-2024-3912](https://github.com/H4rk3nz0/CVE-2024-3912) :  ![starts](https://img.shields.io/github/stars/H4rk3nz0/CVE-2024-3912.svg) ![forks](https://img.shields.io/github/forks/H4rk3nz0/CVE-2024-3912.svg)


## CVE-2024-2997
 A vulnerability was found in Bdtask Multi-Store Inventory Management System up to 20240320. It has been declared as problematic. Affected by this vulnerability is an unknown functionality. The manipulation of the argument Category Name/Model Name/Brand Name/Unit Name leads to cross site scripting. The attack can be launched remotely. The exploit has been disclosed to the public and may be used. The associated identifier of this vulnerability is VDB-258199. NOTE: The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/0xUho/CVE-2024-2997](https://github.com/0xUho/CVE-2024-2997) :  ![starts](https://img.shields.io/github/stars/0xUho/CVE-2024-2997.svg) ![forks](https://img.shields.io/github/forks/0xUho/CVE-2024-2997.svg)


## CVE-2023-3452
 The Canto plugin for WordPress is vulnerable to Remote File Inclusion in versions up to, and including, 3.0.4 via the 'wp_abspath' parameter. This allows unauthenticated attackers to include and execute arbitrary remote code on the server, provided that allow_url_include is enabled. Local File Inclusion is also possible, albeit less useful because it requires that the attacker be able to upload a malicious php file via FTP or some other means into a directory readable by the web server.

- [https://github.com/puppetma4ster/Metasploit-Wordpress-Canto-Exploit-RCE](https://github.com/puppetma4ster/Metasploit-Wordpress-Canto-Exploit-RCE) :  ![starts](https://img.shields.io/github/stars/puppetma4ster/Metasploit-Wordpress-Canto-Exploit-RCE.svg) ![forks](https://img.shields.io/github/forks/puppetma4ster/Metasploit-Wordpress-Canto-Exploit-RCE.svg)


## CVE-2023-0179
 A buffer overflow vulnerability was found in the Netfilter subsystem in the Linux Kernel. This issue could allow the leakage of both stack and heap addresses, and potentially allow Local Privilege Escalation to the root user via arbitrary code execution.

- [https://github.com/shakyanayann/CVE-2023-0179](https://github.com/shakyanayann/CVE-2023-0179) :  ![starts](https://img.shields.io/github/stars/shakyanayann/CVE-2023-0179.svg) ![forks](https://img.shields.io/github/forks/shakyanayann/CVE-2023-0179.svg)


## CVE-2022-46152
 OP-TEE Trusted OS is the secure side implementation of OP-TEE project, a Trusted Execution Environment. Versions prior to 3.19.0, contain an Improper Validation of Array Index vulnerability. The function `cleanup_shm_refs()` is called by both `entry_invoke_command()` and `entry_open_session()`. The commands `OPTEE_MSG_CMD_OPEN_SESSION` and `OPTEE_MSG_CMD_INVOKE_COMMAND` can be executed from the normal world via an OP-TEE SMC. This function is not validating the `num_params` argument, which is only limited to `OPTEE_MSG_MAX_NUM_PARAMS` (127) in the function `get_cmd_buffer()`. Therefore, an attacker in the normal world can craft an SMC call that will cause out-of-bounds reading in `cleanup_shm_refs` and potentially freeing of fake-objects in the function `mobj_put()`. A normal-world attacker with permission to execute SMC instructions may exploit this flaw. Maintainers believe this problem permits local privilege escalation from the normal world to the secure world. Version 3.19.0 contains a fix for this issue. There are no known workarounds.

- [https://github.com/qianfei11/CVE-2022-46152](https://github.com/qianfei11/CVE-2022-46152) :  ![starts](https://img.shields.io/github/stars/qianfei11/CVE-2022-46152.svg) ![forks](https://img.shields.io/github/forks/qianfei11/CVE-2022-46152.svg)


## CVE-2022-32250
 net/netfilter/nf_tables_api.c in the Linux kernel through 5.18.1 allows a local user (able to create user/net namespaces) to escalate privileges to root because an incorrect NFT_STATEFUL_EXPR check leads to a use-after-free.

- [https://github.com/LSinus/CacheMeIfYouCan](https://github.com/LSinus/CacheMeIfYouCan) :  ![starts](https://img.shields.io/github/stars/LSinus/CacheMeIfYouCan.svg) ![forks](https://img.shields.io/github/forks/LSinus/CacheMeIfYouCan.svg)


## CVE-2022-22965
 A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the application to run on Tomcat as a WAR deployment. If the application is deployed as a Spring Boot executable jar, i.e. the default, it is not vulnerable to the exploit. However, the nature of the vulnerability is more general, and there may be other ways to exploit it.

- [https://github.com/0xAshwesker/CVE-2022-22965](https://github.com/0xAshwesker/CVE-2022-22965) :  ![starts](https://img.shields.io/github/stars/0xAshwesker/CVE-2022-22965.svg) ![forks](https://img.shields.io/github/forks/0xAshwesker/CVE-2022-22965.svg)


## CVE-2022-0435
 A stack overflow flaw was found in the Linux kernel's TIPC protocol functionality in the way a user sends a packet with malicious content where the number of domain member nodes is higher than the 64 allowed. This flaw allows a remote user to crash the system or possibly escalate their privileges if they have access to the TIPC network.

- [https://github.com/Spydomain/CVE-2022-0435-Poc](https://github.com/Spydomain/CVE-2022-0435-Poc) :  ![starts](https://img.shields.io/github/stars/Spydomain/CVE-2022-0435-Poc.svg) ![forks](https://img.shields.io/github/forks/Spydomain/CVE-2022-0435-Poc.svg)


## CVE-2022-0185
 A heap-based buffer overflow flaw was found in the way the legacy_parse_param function in the Filesystem Context functionality of the Linux kernel verified the supplied parameters length. An unprivileged (in case of unprivileged user namespaces enabled, otherwise needs namespaced CAP_SYS_ADMIN privilege) local user able to open a filesystem that does not support the Filesystem Context API (and thus fallbacks to legacy handling) could use this flaw to escalate their privileges on the system.

- [https://github.com/shakyanayann/CVE-2022-0185](https://github.com/shakyanayann/CVE-2022-0185) :  ![starts](https://img.shields.io/github/stars/shakyanayann/CVE-2022-0185.svg) ![forks](https://img.shields.io/github/forks/shakyanayann/CVE-2022-0185.svg)


## CVE-2021-22555
 A heap out-of-bounds write affecting Linux since v2.6.19-rc1 was discovered in net/netfilter/x_tables.c. This allows an attacker to gain privileges or cause a DoS (via heap memory corruption) through user name space

- [https://github.com/Spydomain/CVE-2021-22555-Poc](https://github.com/Spydomain/CVE-2021-22555-Poc) :  ![starts](https://img.shields.io/github/stars/Spydomain/CVE-2021-22555-Poc.svg) ![forks](https://img.shields.io/github/forks/Spydomain/CVE-2021-22555-Poc.svg)


## CVE-2019-3980
 The Solarwinds Dameware Mini Remote Client agent v12.1.0.89 supports smart card authentication which can allow a user to upload an executable to be executed on the DWRCS.exe host. An unauthenticated, remote attacker can request smart card login and upload and execute an arbitrary executable run under the Local System account.

- [https://github.com/boydhacks/dameflare](https://github.com/boydhacks/dameflare) :  ![starts](https://img.shields.io/github/stars/boydhacks/dameflare.svg) ![forks](https://img.shields.io/github/forks/boydhacks/dameflare.svg)


## CVE-2017-1000112
 Linux kernel: Exploitable memory corruption due to UFO to non-UFO path switch. When building a UFO packet with MSG_MORE __ip_append_data() calls ip_ufo_append_data() to append. However in between two send() calls, the append path can be switched from UFO to non-UFO one, which leads to a memory corruption. In case UFO packet lengths exceeds MTU, copy = maxfraglen - skb-len becomes negative on the non-UFO path and the branch to allocate new skb is taken. This triggers fragmentation and computation of fraggap = skb_prev-len - maxfraglen. Fraggap can exceed MTU, causing copy = datalen - transhdrlen - fraggap to become negative. Subsequently skb_copy_and_csum_bits() writes out-of-bounds. A similar issue is present in IPv6 code. The bug was introduced in e89e9cf539a2 ("[IPv4/IPv6]: UFO Scatter-gather approach") on Oct 18 2005.

- [https://github.com/Spydomain/CVE-2017-1000112-PoC](https://github.com/Spydomain/CVE-2017-1000112-PoC) :  ![starts](https://img.shields.io/github/stars/Spydomain/CVE-2017-1000112-PoC.svg) ![forks](https://img.shields.io/github/forks/Spydomain/CVE-2017-1000112-PoC.svg)


## CVE-2015-9235
 In jsonwebtoken node module before 4.2.2 it is possible for an attacker to bypass verification when a token digitally signed with an asymmetric key (RS/ES family) of algorithms but instead the attacker send a token digitally signed with a symmetric algorithm (HS* family).

- [https://github.com/Nxvh1337/CVE-2015-9235_JWT_key_confusion](https://github.com/Nxvh1337/CVE-2015-9235_JWT_key_confusion) :  ![starts](https://img.shields.io/github/stars/Nxvh1337/CVE-2015-9235_JWT_key_confusion.svg) ![forks](https://img.shields.io/github/forks/Nxvh1337/CVE-2015-9235_JWT_key_confusion.svg)


## CVE-2014-6271
 GNU Bash through 4.3 processes trailing strings after function definitions in the values of environment variables, which allows remote attackers to execute arbitrary code via a crafted environment, as demonstrated by vectors involving the ForceCommand feature in OpenSSH sshd, the mod_cgi and mod_cgid modules in the Apache HTTP Server, scripts executed by unspecified DHCP clients, and other situations in which setting the environment occurs across a privilege boundary from Bash execution, aka "ShellShock."  NOTE: the original fix for this issue was incorrect; CVE-2014-7169 has been assigned to cover the vulnerability that is still present after the incorrect fix.

- [https://github.com/0xAshwesker/CVE-2014-6271](https://github.com/0xAshwesker/CVE-2014-6271) :  ![starts](https://img.shields.io/github/stars/0xAshwesker/CVE-2014-6271.svg) ![forks](https://img.shields.io/github/forks/0xAshwesker/CVE-2014-6271.svg)


## CVE-2011-1473
 OpenSSL before 0.9.8l, and 0.9.8m through 1.x, does not properly restrict client-initiated renegotiation within the SSL and TLS protocols, which might make it easier for remote attackers to cause a denial of service (CPU consumption) by performing many renegotiations within a single connection, a different vulnerability than CVE-2011-5094.  NOTE: it can also be argued that it is the responsibility of server deployments, not a security library, to prevent or limit renegotiation when it is inappropriate within a specific environment

- [https://github.com/khaledibnalwalid/CVE-2011-1473-POC](https://github.com/khaledibnalwalid/CVE-2011-1473-POC) :  ![starts](https://img.shields.io/github/stars/khaledibnalwalid/CVE-2011-1473-POC.svg) ![forks](https://img.shields.io/github/forks/khaledibnalwalid/CVE-2011-1473-POC.svg)

