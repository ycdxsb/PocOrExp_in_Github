# Update 2026-03-09
## CVE-2026-29786
 node-tar is a full-featured Tar for Node.js. Prior to version 7.5.10, tar can be tricked into creating a hardlink that points outside the extraction directory by using a drive-relative link target such as C:../target.txt, which enables file overwrite outside cwd during normal tar.x() extraction. This issue has been patched in version 7.5.10.

- [https://github.com/Jvr2022/CVE-2026-29786](https://github.com/Jvr2022/CVE-2026-29786) :  ![starts](https://img.shields.io/github/stars/Jvr2022/CVE-2026-29786.svg) ![forks](https://img.shields.io/github/forks/Jvr2022/CVE-2026-29786.svg)


## CVE-2026-29781
 Sliver is a command and control framework that uses a custom Wireguard netstack. In versions from 1.7.3 and prior, a vulnerability exists in the Sliver C2 server's Protobuf unmarshalling logic due to a systemic lack of nil-pointer validation. By extracting valid implant credentials and omitting nested fields in a signed message, an authenticated actor can trigger an unhandled runtime panic. Because the mTLS, WireGuard, and DNS transport layers lack the panic recovery middleware present in the HTTP transport, this results in a global process termination. While requiring post-authentication access (a captured implant), this flaw effectively acts as an infrastructure "kill-switch," instantly severing all active sessions across the entire fleet and requiring a manual server restart to restore operations. At time of publication, there are no publicly available patches.

- [https://github.com/skoveit/CVE-2026-29781](https://github.com/skoveit/CVE-2026-29781) :  ![starts](https://img.shields.io/github/stars/skoveit/CVE-2026-29781.svg) ![forks](https://img.shields.io/github/forks/skoveit/CVE-2026-29781.svg)


## CVE-2026-28372
 telnetd in GNU inetutils through 2.7 allows privilege escalation that can be exploited by abusing systemd service credentials support added to the login(1) implementation of util-linux in release 2.40. This is related to client control over the CREDENTIALS_DIRECTORY environment variable, and requires an unprivileged local user to create a login.noauth file.

- [https://github.com/Rohitberiwala/CVE-2026-28372](https://github.com/Rohitberiwala/CVE-2026-28372) :  ![starts](https://img.shields.io/github/stars/Rohitberiwala/CVE-2026-28372.svg) ![forks](https://img.shields.io/github/forks/Rohitberiwala/CVE-2026-28372.svg)


## CVE-2026-25643
 Frigate is a network video recorder (NVR) with realtime local object detection for IP cameras. Prior to 0.16.4, a critical Remote Command Execution (RCE) vulnerability has been identified in the Frigate integration with go2rtc. The application does not sanitize user input in the video stream configuration (config.yaml), allowing direct injection of system commands via the exec: directive. The go2rtc service executes these commands without restrictions. This vulnerability is only exploitable by an administrator or users who have exposed their Frigate install to the open internet with no authentication which allows anyone full administrative control. This vulnerability is fixed in 0.16.4.

- [https://github.com/DyniePro/CVE-2026-25643](https://github.com/DyniePro/CVE-2026-25643) :  ![starts](https://img.shields.io/github/stars/DyniePro/CVE-2026-25643.svg) ![forks](https://img.shields.io/github/forks/DyniePro/CVE-2026-25643.svg)


## CVE-2026-20127
This vulnerability exists because the peering authentication mechanism in an affected system is not working properly. An attacker could exploit this vulnerability by sending crafted requests to an affected system. A successful exploit could allow the attacker to log in to an affected Cisco Catalyst SD-WAN Controller as an internal, high-privileged, non-root&nbsp;user account. Using this account, the attacker could access NETCONF, which would then allow the attacker to manipulate network configuration for the SD-WAN fabric.&nbsp;

- [https://github.com/yonathanpy/CVE-2026-20127-Cisco-SD-WAN-Preauth-RCE](https://github.com/yonathanpy/CVE-2026-20127-Cisco-SD-WAN-Preauth-RCE) :  ![starts](https://img.shields.io/github/stars/yonathanpy/CVE-2026-20127-Cisco-SD-WAN-Preauth-RCE.svg) ![forks](https://img.shields.io/github/forks/yonathanpy/CVE-2026-20127-Cisco-SD-WAN-Preauth-RCE.svg)


## CVE-2026-1492
 The User Registration & Membership – Custom Registration Form Builder, Custom Login Form, User Profile, Content Restriction & Membership Plugin plugin for WordPress is vulnerable to improper privilege management in all versions up to, and including, 5.1.2. This is due to the plugin accepting a user-supplied role during membership registration without properly enforcing a server-side allowlist. This makes it possible for unauthenticated attackers to create administrator accounts by supplying a role value during membership registration.

- [https://github.com/dreamboyim66-boop/CVE-2026-1492-POC](https://github.com/dreamboyim66-boop/CVE-2026-1492-POC) :  ![starts](https://img.shields.io/github/stars/dreamboyim66-boop/CVE-2026-1492-POC.svg) ![forks](https://img.shields.io/github/forks/dreamboyim66-boop/CVE-2026-1492-POC.svg)


## CVE-2026-1357
 The Migration, Backup, Staging – WPvivid Backup & Migration plugin for WordPress is vulnerable to Unauthenticated Arbitrary File Upload in versions up to and including 0.9.123. This is due to improper error handling in the RSA decryption process combined with a lack of path sanitization when writing uploaded files. When the plugin fails to decrypt a session key using openssl_private_decrypt(), it does not terminate execution and instead passes the boolean false value to the phpseclib library's AES cipher initialization. The library treats this false value as a string of null bytes, allowing an attacker to encrypt a malicious payload using a predictable null-byte key. Additionally, the plugin accepts filenames from the decrypted payload without sanitization, enabling directory traversal to escape the protected backup directory. This makes it possible for unauthenticated attackers to upload arbitrary PHP files to publicly accessible directories and achieve Remote Code Execution via the wpvivid_action=send_to_site parameter.

- [https://github.com/CVEs-Labs/CVE-2026-1357](https://github.com/CVEs-Labs/CVE-2026-1357) :  ![starts](https://img.shields.io/github/stars/CVEs-Labs/CVE-2026-1357.svg) ![forks](https://img.shields.io/github/forks/CVEs-Labs/CVE-2026-1357.svg)


## CVE-2025-60787
 MotionEye v0.43.1b4 and before is vulnerable to OS Command Injection in configuration parameters such as image_file_name. Unsanitized user input is written to Motion configuration files, allowing remote authenticated attackers with admin access to achieve code execution when Motion is restarted.

- [https://github.com/Rohitberiwala/CVE-2025-60787-MotionEye-RCE](https://github.com/Rohitberiwala/CVE-2025-60787-MotionEye-RCE) :  ![starts](https://img.shields.io/github/stars/Rohitberiwala/CVE-2025-60787-MotionEye-RCE.svg) ![forks](https://img.shields.io/github/forks/Rohitberiwala/CVE-2025-60787-MotionEye-RCE.svg)


## CVE-2025-32433
 Erlang/OTP is a set of libraries for the Erlang programming language. Prior to versions OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20, a SSH server may allow an attacker to perform unauthenticated remote code execution (RCE). By exploiting a flaw in SSH protocol message handling, a malicious actor could gain unauthorized access to affected systems and execute arbitrary commands without valid credentials. This issue is patched in versions OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20. A temporary workaround involves disabling the SSH server or to prevent access via firewall rules.

- [https://github.com/joshuavanderpoll/cve-2025-32433](https://github.com/joshuavanderpoll/cve-2025-32433) :  ![starts](https://img.shields.io/github/stars/joshuavanderpoll/cve-2025-32433.svg) ![forks](https://img.shields.io/github/forks/joshuavanderpoll/cve-2025-32433.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/Heimd411/CVE-2025-29927-PoC](https://github.com/Heimd411/CVE-2025-29927-PoC) :  ![starts](https://img.shields.io/github/stars/Heimd411/CVE-2025-29927-PoC.svg) ![forks](https://img.shields.io/github/forks/Heimd411/CVE-2025-29927-PoC.svg)


## CVE-2025-8088
     from ESET.

- [https://github.com/Jessica74016/CVE-2025-8088](https://github.com/Jessica74016/CVE-2025-8088) :  ![starts](https://img.shields.io/github/stars/Jessica74016/CVE-2025-8088.svg) ![forks](https://img.shields.io/github/forks/Jessica74016/CVE-2025-8088.svg)


## CVE-2025-0401
 A vulnerability classified as critical has been found in 1902756969 reggie 1.0. Affected is the function download of the file src/main/java/com/itheima/reggie/controller/CommonController.java. The manipulation of the argument name leads to path traversal. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/JoasASantos/CVE-2025-0401](https://github.com/JoasASantos/CVE-2025-0401) :  ![starts](https://img.shields.io/github/stars/JoasASantos/CVE-2025-0401.svg) ![forks](https://img.shields.io/github/forks/JoasASantos/CVE-2025-0401.svg)


## CVE-2024-46987
 Camaleon CMS is a dynamic and advanced content management system based on Ruby on Rails. A path traversal vulnerability accessible via MediaController's download_private_file method allows authenticated users to download any file on the web server Camaleon CMS is running on (depending on the file permissions). This issue may lead to Information Disclosure. This issue has been addressed in release version 2.8.2. Users are advised to upgrade. There are no known workarounds for this vulnerability.

- [https://github.com/bootstrapbool/msf-cve-2024-46987](https://github.com/bootstrapbool/msf-cve-2024-46987) :  ![starts](https://img.shields.io/github/stars/bootstrapbool/msf-cve-2024-46987.svg) ![forks](https://img.shields.io/github/forks/bootstrapbool/msf-cve-2024-46987.svg)


## CVE-2024-45496
 A flaw was found in OpenShift. This issue occurs due to the misuse of elevated privileges in the OpenShift Container Platform's build process. During the build initialization step, the git-clone container is run with a privileged security context, allowing unrestricted access to the node. An attacker with developer-level access can provide a crafted .gitconfig file containing commands executed during the cloning process, leading to arbitrary command execution on the worker node. An attacker running code in a privileged container could escalate their permissions on the node running the container.

- [https://github.com/pwnc4t/cve-2024-45496](https://github.com/pwnc4t/cve-2024-45496) :  ![starts](https://img.shields.io/github/stars/pwnc4t/cve-2024-45496.svg) ![forks](https://img.shields.io/github/forks/pwnc4t/cve-2024-45496.svg)


## CVE-2024-31317
 In multiple functions of ZygoteProcess.java, there is a possible way to achieve code execution as any app via WRITE_SECURE_SETTINGS due to unsafe deserialization. This could lead to local escalation of privilege with User execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/chengfeng30121/CVE-2024-31317-PoC](https://github.com/chengfeng30121/CVE-2024-31317-PoC) :  ![starts](https://img.shields.io/github/stars/chengfeng30121/CVE-2024-31317-PoC.svg) ![forks](https://img.shields.io/github/forks/chengfeng30121/CVE-2024-31317-PoC.svg)


## CVE-2024-7387
 A flaw was found in openshift/builder. This vulnerability allows command injection via path traversal, where a malicious user can execute arbitrary commands on the OpenShift node running the builder container. When using the “Docker” strategy, executable files inside the privileged build container can be overridden using the `spec.source.secrets.secret.destinationDir` attribute of the `BuildConfig` definition. An attacker running code in a privileged container could escalate their permissions on the node running the container.

- [https://github.com/pwnc4t/cve-2024-7387](https://github.com/pwnc4t/cve-2024-7387) :  ![starts](https://img.shields.io/github/stars/pwnc4t/cve-2024-7387.svg) ![forks](https://img.shields.io/github/forks/pwnc4t/cve-2024-7387.svg)


## CVE-2023-5044
 Code injection via nginx.ingress.kubernetes.io/permanent-redirect annotation.

- [https://github.com/r0binak/CVE-2023-5044](https://github.com/r0binak/CVE-2023-5044) :  ![starts](https://img.shields.io/github/stars/r0binak/CVE-2023-5044.svg) ![forks](https://img.shields.io/github/forks/r0binak/CVE-2023-5044.svg)
- [https://github.com/4ARMED/cve-2023-5044](https://github.com/4ARMED/cve-2023-5044) :  ![starts](https://img.shields.io/github/stars/4ARMED/cve-2023-5044.svg) ![forks](https://img.shields.io/github/forks/4ARMED/cve-2023-5044.svg)
- [https://github.com/KubernetesBachelor/CVE-2023-5044](https://github.com/KubernetesBachelor/CVE-2023-5044) :  ![starts](https://img.shields.io/github/stars/KubernetesBachelor/CVE-2023-5044.svg) ![forks](https://img.shields.io/github/forks/KubernetesBachelor/CVE-2023-5044.svg)


## CVE-2023-0297
 Code Injection in GitHub repository pyload/pyload prior to 0.5.0b3.dev31.

- [https://github.com/hazeyez/CVE-2023-0297](https://github.com/hazeyez/CVE-2023-0297) :  ![starts](https://img.shields.io/github/stars/hazeyez/CVE-2023-0297.svg) ![forks](https://img.shields.io/github/forks/hazeyez/CVE-2023-0297.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/JIYUN02/cve-2021-41773](https://github.com/JIYUN02/cve-2021-41773) :  ![starts](https://img.shields.io/github/stars/JIYUN02/cve-2021-41773.svg) ![forks](https://img.shields.io/github/forks/JIYUN02/cve-2021-41773.svg)

