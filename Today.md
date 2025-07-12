# Update 2025-07-12
## CVE-2025-53547
 Helm is a package manager for Charts for Kubernetes. Prior to 3.18.4, a specially crafted Chart.yaml file along with a specially linked Chart.lock file can lead to local code execution when dependencies are updated. Fields in a Chart.yaml file, that are carried over to a Chart.lock file when dependencies are updated and this file is written, can be crafted in a way that can cause execution if that same content were in a file that is executed (e.g., a bash.rc file or shell script). If the Chart.lock file is symlinked to one of these files updating dependencies will write the lock file content to the symlinked file. This can lead to unwanted execution. Helm warns of the symlinked file but did not stop execution due to symlinking. This issue has been resolved in Helm v3.18.4.

- [https://github.com/DVKunion/CVE-2025-53547-POC](https://github.com/DVKunion/CVE-2025-53547-POC) :  ![starts](https://img.shields.io/github/stars/DVKunion/CVE-2025-53547-POC.svg) ![forks](https://img.shields.io/github/forks/DVKunion/CVE-2025-53547-POC.svg)


## CVE-2025-48384
 Git is a fast, scalable, distributed revision control system with an unusually rich command set that provides both high-level operations and full access to internals. When reading a config value, Git strips any trailing carriage return and line feed (CRLF). When writing a config entry, values with a trailing CR are not quoted, causing the CR to be lost when the config is later read. When initializing a submodule, if the submodule path contains a trailing CR, the altered path is read resulting in the submodule being checked out to an incorrect location. If a symlink exists that points the altered path to the submodule hooks directory, and the submodule contains an executable post-checkout hook, the script may be unintentionally executed after checkout. This vulnerability is fixed in v2.43.7, v2.44.4, v2.45.4, v2.46.4, v2.47.3, v2.48.2, v2.49.1, and v2.50.1.

- [https://github.com/testdjshan/CVE-2025-48384](https://github.com/testdjshan/CVE-2025-48384) :  ![starts](https://img.shields.io/github/stars/testdjshan/CVE-2025-48384.svg) ![forks](https://img.shields.io/github/forks/testdjshan/CVE-2025-48384.svg)
- [https://github.com/NigelX/CVE-2025-48384](https://github.com/NigelX/CVE-2025-48384) :  ![starts](https://img.shields.io/github/stars/NigelX/CVE-2025-48384.svg) ![forks](https://img.shields.io/github/forks/NigelX/CVE-2025-48384.svg)
- [https://github.com/testsssssssss-sss/CVE-2025-48384](https://github.com/testsssssssss-sss/CVE-2025-48384) :  ![starts](https://img.shields.io/github/stars/testsssssssss-sss/CVE-2025-48384.svg) ![forks](https://img.shields.io/github/forks/testsssssssss-sss/CVE-2025-48384.svg)
- [https://github.com/greatyy/CVE-2025-48384-p](https://github.com/greatyy/CVE-2025-48384-p) :  ![starts](https://img.shields.io/github/stars/greatyy/CVE-2025-48384-p.svg) ![forks](https://img.shields.io/github/forks/greatyy/CVE-2025-48384-p.svg)
- [https://github.com/vinieger/CVE-2025-48384-bad-nginx](https://github.com/vinieger/CVE-2025-48384-bad-nginx) :  ![starts](https://img.shields.io/github/stars/vinieger/CVE-2025-48384-bad-nginx.svg) ![forks](https://img.shields.io/github/forks/vinieger/CVE-2025-48384-bad-nginx.svg)
- [https://github.com/vinieger/CVE-2025-48384-bad-nginx-submodule](https://github.com/vinieger/CVE-2025-48384-bad-nginx-submodule) :  ![starts](https://img.shields.io/github/stars/vinieger/CVE-2025-48384-bad-nginx-submodule.svg) ![forks](https://img.shields.io/github/forks/vinieger/CVE-2025-48384-bad-nginx-submodule.svg)


## CVE-2025-47812
 In Wing FTP Server before 7.4.4. the user and admin web interfaces mishandle '\0' bytes, ultimately allowing injection of arbitrary Lua code into user session files. This can be used to execute arbitrary system commands with the privileges of the FTP service (root or SYSTEM by default). This is thus a remote code execution vulnerability that guarantees a total server compromise. This is also exploitable via anonymous FTP accounts.

- [https://github.com/4m3rr0r/CVE-2025-47812-poc](https://github.com/4m3rr0r/CVE-2025-47812-poc) :  ![starts](https://img.shields.io/github/stars/4m3rr0r/CVE-2025-47812-poc.svg) ![forks](https://img.shields.io/github/forks/4m3rr0r/CVE-2025-47812-poc.svg)
- [https://github.com/0xcan1337/CVE-2025-47812-poC](https://github.com/0xcan1337/CVE-2025-47812-poC) :  ![starts](https://img.shields.io/github/stars/0xcan1337/CVE-2025-47812-poC.svg) ![forks](https://img.shields.io/github/forks/0xcan1337/CVE-2025-47812-poC.svg)
- [https://github.com/0xgh057r3c0n/CVE-2025-47812](https://github.com/0xgh057r3c0n/CVE-2025-47812) :  ![starts](https://img.shields.io/github/stars/0xgh057r3c0n/CVE-2025-47812.svg) ![forks](https://img.shields.io/github/forks/0xgh057r3c0n/CVE-2025-47812.svg)
- [https://github.com/pevinkumar10/CVE-2025-47812](https://github.com/pevinkumar10/CVE-2025-47812) :  ![starts](https://img.shields.io/github/stars/pevinkumar10/CVE-2025-47812.svg) ![forks](https://img.shields.io/github/forks/pevinkumar10/CVE-2025-47812.svg)
- [https://github.com/ill-deed/WingFTP-CVE-2025-47812-illdeed](https://github.com/ill-deed/WingFTP-CVE-2025-47812-illdeed) :  ![starts](https://img.shields.io/github/stars/ill-deed/WingFTP-CVE-2025-47812-illdeed.svg) ![forks](https://img.shields.io/github/forks/ill-deed/WingFTP-CVE-2025-47812-illdeed.svg)


## CVE-2025-34085
 An unrestricted file upload vulnerability in the WordPress Simple File List plugin prior to version 4.2.3 allows unauthenticated remote attackers to achieve remote code execution. The plugin's upload endpoint (ee-upload-engine.php) restricts file uploads based on extension, but lacks proper validation after file renaming. An attacker can first upload a PHP payload disguised as a .png file, then use the plugin’s ee-file-engine.php rename functionality to change the extension to .php. This bypasses upload restrictions and results in the uploaded payload being executable on the server.

- [https://github.com/MrjHaxcore/CVE-2025-34085](https://github.com/MrjHaxcore/CVE-2025-34085) :  ![starts](https://img.shields.io/github/stars/MrjHaxcore/CVE-2025-34085.svg) ![forks](https://img.shields.io/github/forks/MrjHaxcore/CVE-2025-34085.svg)


## CVE-2025-32023
 Redis is an open source, in-memory database that persists on disk. From 2.8 to before 8.0.3, 7.4.5, 7.2.10, and 6.2.19, an authenticated user may use a specially crafted string to trigger a stack/heap out of bounds write on hyperloglog operations, potentially leading to remote code execution. The bug likely affects all Redis versions with hyperloglog operations implemented. This vulnerability is fixed in 8.0.3, 7.4.5, 7.2.10, and 6.2.19. An additional workaround to mitigate the problem without patching the redis-server executable is to prevent users from executing hyperloglog operations. This can be done using ACL to restrict HLL commands.

- [https://github.com/atomicjjbod/CVE-2025-32023](https://github.com/atomicjjbod/CVE-2025-32023) :  ![starts](https://img.shields.io/github/stars/atomicjjbod/CVE-2025-32023.svg) ![forks](https://img.shields.io/github/forks/atomicjjbod/CVE-2025-32023.svg)


## CVE-2025-30208
 Vite, a provider of frontend development tooling, has a vulnerability in versions prior to 6.2.3, 6.1.2, 6.0.12, 5.4.15, and 4.5.10. `@fs` denies access to files outside of Vite serving allow list. Adding `?raw??` or `?import&raw??` to the URL bypasses this limitation and returns the file content if it exists. This bypass exists because trailing separators such as `?` are removed in several places, but are not accounted for in query string regexes. The contents of arbitrary files can be returned to the browser. Only apps explicitly exposing the Vite dev server to the network (using `--host` or `server.host` config option) are affected. Versions 6.2.3, 6.1.2, 6.0.12, 5.4.15, and 4.5.10 fix the issue.

- [https://github.com/gonn4cry/CVE-2025-30208](https://github.com/gonn4cry/CVE-2025-30208) :  ![starts](https://img.shields.io/github/stars/gonn4cry/CVE-2025-30208.svg) ![forks](https://img.shields.io/github/forks/gonn4cry/CVE-2025-30208.svg)


## CVE-2025-6554
 Type confusion in V8 in Google Chrome prior to 138.0.7204.96 allowed a remote attacker to perform arbitrary read/write via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/9Insomnie/CVE-2025-6554](https://github.com/9Insomnie/CVE-2025-6554) :  ![starts](https://img.shields.io/github/stars/9Insomnie/CVE-2025-6554.svg) ![forks](https://img.shields.io/github/forks/9Insomnie/CVE-2025-6554.svg)


## CVE-2025-6218
The specific flaw exists within the handling of file paths within archive files. A crafted file path can cause the process to traverse to unintended directories. An attacker can leverage this vulnerability to execute code in the context of the current user. Was ZDI-CAN-27198.

- [https://github.com/absholi7ly/CVE-2025-6218-WinRAR-Directory-Traversal-RCE](https://github.com/absholi7ly/CVE-2025-6218-WinRAR-Directory-Traversal-RCE) :  ![starts](https://img.shields.io/github/stars/absholi7ly/CVE-2025-6218-WinRAR-Directory-Traversal-RCE.svg) ![forks](https://img.shields.io/github/forks/absholi7ly/CVE-2025-6218-WinRAR-Directory-Traversal-RCE.svg)


## CVE-2025-5777
 Insufficient input validation leading to memory overread when the NetScaler is configured as a Gateway (VPN virtual server, ICA Proxy, CVPN, RDP Proxy) OR AAA virtual server

- [https://github.com/0xgh057r3c0n/CVE-2025-5777](https://github.com/0xgh057r3c0n/CVE-2025-5777) :  ![starts](https://img.shields.io/github/stars/0xgh057r3c0n/CVE-2025-5777.svg) ![forks](https://img.shields.io/github/forks/0xgh057r3c0n/CVE-2025-5777.svg)
- [https://github.com/bughuntar/CVE-2025-5777](https://github.com/bughuntar/CVE-2025-5777) :  ![starts](https://img.shields.io/github/stars/bughuntar/CVE-2025-5777.svg) ![forks](https://img.shields.io/github/forks/bughuntar/CVE-2025-5777.svg)


## CVE-2025-4578
 The File Provider WordPress plugin through 1.2.3 does not properly sanitise and escape a parameter before using it in a SQL statement via an AJAX action available to unauthenticated users, leading to a SQL injection

- [https://github.com/RandomRobbieBF/CVE-2025-4578](https://github.com/RandomRobbieBF/CVE-2025-4578) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2025-4578.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2025-4578.svg)


## CVE-2025-2525
 The Streamit theme for WordPress is vulnerable to arbitrary file uploads due to missing file type validation in the 'st_Authentication_Controller::edit_profile' function in all versions up to, and including, 4.0.1. This makes it possible for authenticated attackers, with subscriber-level and above permissions, to upload arbitrary files on the affected site's server which may make remote code execution possible.

- [https://github.com/barbaraogmgf/CVE-2025-25257](https://github.com/barbaraogmgf/CVE-2025-25257) :  ![starts](https://img.shields.io/github/stars/barbaraogmgf/CVE-2025-25257.svg) ![forks](https://img.shields.io/github/forks/barbaraogmgf/CVE-2025-25257.svg)


## CVE-2024-38856
Unauthenticated endpoints could allow execution of screen rendering code of screens if some preconditions are met (such as when the screen definitions don't explicitly check user's permissions because they rely on the configuration of their endpoints).

- [https://github.com/guinea-offensive-security/Ofbiz-RCE](https://github.com/guinea-offensive-security/Ofbiz-RCE) :  ![starts](https://img.shields.io/github/stars/guinea-offensive-security/Ofbiz-RCE.svg) ![forks](https://img.shields.io/github/forks/guinea-offensive-security/Ofbiz-RCE.svg)


## CVE-2024-27954
 Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') vulnerability in WP Automatic Automatic allows Path Traversal, Server Side Request Forgery.This issue affects Automatic: from n/a through 3.92.0.

- [https://github.com/r0otk3r/CVE-2024-27954](https://github.com/r0otk3r/CVE-2024-27954) :  ![starts](https://img.shields.io/github/stars/r0otk3r/CVE-2024-27954.svg) ![forks](https://img.shields.io/github/forks/r0otk3r/CVE-2024-27954.svg)


## CVE-2024-25600
 Improper Control of Generation of Code ('Code Injection') vulnerability in Codeer Limited Bricks Builder allows Code Injection.This issue affects Bricks Builder: from n/a through 1.9.6.

- [https://github.com/r0otk3r/CVE-2024-25600](https://github.com/r0otk3r/CVE-2024-25600) :  ![starts](https://img.shields.io/github/stars/r0otk3r/CVE-2024-25600.svg) ![forks](https://img.shields.io/github/forks/r0otk3r/CVE-2024-25600.svg)


## CVE-2024-3568
 The huggingface/transformers library is vulnerable to arbitrary code execution through deserialization of untrusted data within the `load_repo_checkpoint()` function of the `TFPreTrainedModel()` class. Attackers can execute arbitrary code and commands by crafting a malicious serialized payload, exploiting the use of `pickle.load()` on data from potentially untrusted sources. This vulnerability allows for remote code execution (RCE) by deceiving victims into loading a seemingly harmless checkpoint during a normal training process, thereby enabling attackers to execute arbitrary code on the targeted machine.

- [https://github.com/rooobeam/Pickle-Deserialization-Exploit-in-Transformers](https://github.com/rooobeam/Pickle-Deserialization-Exploit-in-Transformers) :  ![starts](https://img.shields.io/github/stars/rooobeam/Pickle-Deserialization-Exploit-in-Transformers.svg) ![forks](https://img.shields.io/github/forks/rooobeam/Pickle-Deserialization-Exploit-in-Transformers.svg)


## CVE-2024-3196
 A vulnerability was found in MailCleaner up to 2023.03.14. It has been declared as critical. This vulnerability affects the function getStats/Services_silentDump/Services_stopStartMTA/Config_saveDateTime/Config_hostid/Logs_StartGetStat/dumpConfiguration of the component SOAP Service. The manipulation leads to os command injection. Local access is required to approach this attack. The exploit has been disclosed to the public and may be used. It is recommended to apply a patch to fix this issue. The identifier of this vulnerability is VDB-262312.

- [https://github.com/kingfakee7/CVE-2024-31969](https://github.com/kingfakee7/CVE-2024-31969) :  ![starts](https://img.shields.io/github/stars/kingfakee7/CVE-2024-31969.svg) ![forks](https://img.shields.io/github/forks/kingfakee7/CVE-2024-31969.svg)


## CVE-2023-48795
 The SSH transport protocol with certain OpenSSH extensions, found in OpenSSH before 9.6 and other products, allows remote attackers to bypass integrity checks such that some packets are omitted (from the extension negotiation message), and a client and server may consequently end up with a connection for which some security features have been downgraded or disabled, aka a Terrapin attack. This occurs because the SSH Binary Packet Protocol (BPP), implemented by these extensions, mishandles the handshake phase and mishandles use of sequence numbers. For example, there is an effective attack against SSH's use of ChaCha20-Poly1305 (and CBC with Encrypt-then-MAC). The bypass occurs in chacha20-poly1305@openssh.com and (if CBC is used) the -etm@openssh.com MAC algorithms. This also affects Maverick Synergy Java SSH API before 3.1.0-SNAPSHOT, Dropbear through 2022.83, Ssh before 5.1.1 in Erlang/OTP, PuTTY before 0.80, AsyncSSH before 2.14.2, golang.org/x/crypto before 0.17.0, libssh before 0.10.6, libssh2 through 1.11.0, Thorn Tech SFTP Gateway before 3.4.6, Tera Term before 5.1, Paramiko before 3.4.0, jsch before 0.2.15, SFTPGo before 2.5.6, Netgate pfSense Plus through 23.09.1, Netgate pfSense CE through 2.7.2, HPN-SSH through 18.2.0, ProFTPD before 1.3.8b (and before 1.3.9rc2), ORYX CycloneSSH before 2.3.4, NetSarang XShell 7 before Build 0144, CrushFTP before 10.6.0, ConnectBot SSH library before 2.2.22, Apache MINA sshd through 2.11.0, sshj through 0.37.0, TinySSH through 20230101, trilead-ssh2 6401, LANCOM LCOS and LANconfig, FileZilla before 3.66.4, Nova before 11.8, PKIX-SSH before 14.4, SecureCRT before 9.4.3, Transmit5 before 5.10.4, Win32-OpenSSH before 9.5.0.0p1-Beta, WinSCP before 6.2.2, Bitvise SSH Server before 9.32, Bitvise SSH Client before 9.33, KiTTY through 0.76.1.13, the net-ssh gem 7.2.0 for Ruby, the mscdex ssh2 module before 1.15.0 for Node.js, the thrussh library before 0.35.1 for Rust, and the Russh crate before 0.40.2 for Rust.

- [https://github.com/Dr0xharakiri/CVE-2023-48795](https://github.com/Dr0xharakiri/CVE-2023-48795) :  ![starts](https://img.shields.io/github/stars/Dr0xharakiri/CVE-2023-48795.svg) ![forks](https://img.shields.io/github/forks/Dr0xharakiri/CVE-2023-48795.svg)


## CVE-2022-36934
 An integer overflow in WhatsApp could result in remote code execution in an established video call.

- [https://github.com/Teexo/mailenable-cve-2022-36934](https://github.com/Teexo/mailenable-cve-2022-36934) :  ![starts](https://img.shields.io/github/stars/Teexo/mailenable-cve-2022-36934.svg) ![forks](https://img.shields.io/github/forks/Teexo/mailenable-cve-2022-36934.svg)


## CVE-2022-0847
 A flaw was found in the way the "flags" member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/muhammad1596/CVE-2022-0847-DirtyPipe-Exploits](https://github.com/muhammad1596/CVE-2022-0847-DirtyPipe-Exploits) :  ![starts](https://img.shields.io/github/stars/muhammad1596/CVE-2022-0847-DirtyPipe-Exploits.svg) ![forks](https://img.shields.io/github/forks/muhammad1596/CVE-2022-0847-DirtyPipe-Exploits.svg)


## CVE-2021-29505
 XStream is software for serializing Java objects to XML and back again. A vulnerability in XStream versions prior to 1.4.17 may allow a remote attacker has sufficient rights to execute commands of the host only by manipulating the processed input stream. No user who followed the recommendation to setup XStream's security framework with a whitelist limited to the minimal required types is affected. The vulnerability is patched in version 1.4.17.

- [https://github.com/cuijiung/xstream-CVE-2021-29505](https://github.com/cuijiung/xstream-CVE-2021-29505) :  ![starts](https://img.shields.io/github/stars/cuijiung/xstream-CVE-2021-29505.svg) ![forks](https://img.shields.io/github/forks/cuijiung/xstream-CVE-2021-29505.svg)


## CVE-2021-21220
 Insufficient validation of untrusted input in V8 in Google Chrome prior to 89.0.4389.128 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

- [https://github.com/AmesianX/CVE-2021-21220](https://github.com/AmesianX/CVE-2021-21220) :  ![starts](https://img.shields.io/github/stars/AmesianX/CVE-2021-21220.svg) ![forks](https://img.shields.io/github/forks/AmesianX/CVE-2021-21220.svg)


## CVE-2021-4104
 JMSAppender in Log4j 1.2 is vulnerable to deserialization of untrusted data when the attacker has write access to the Log4j configuration. The attacker can provide TopicBindingName and TopicConnectionFactoryBindingName configurations causing JMSAppender to perform JNDI requests that result in remote code execution in a similar fashion to CVE-2021-44228. Note this issue only affects Log4j 1.2 when specifically configured to use JMSAppender, which is not the default. Apache Log4j 1.2 reached end of life in August 2015. Users should upgrade to Log4j 2 as it addresses numerous other issues from the previous versions.

- [https://github.com/cuijiung/log4j-CVE-2021-4104](https://github.com/cuijiung/log4j-CVE-2021-4104) :  ![starts](https://img.shields.io/github/stars/cuijiung/log4j-CVE-2021-4104.svg) ![forks](https://img.shields.io/github/forks/cuijiung/log4j-CVE-2021-4104.svg)


## CVE-2020-36180
 FasterXML jackson-databind 2.x before 2.9.10.8 mishandles the interaction between serialization gadgets and typing, related to org.apache.commons.dbcp2.cpdsadapter.DriverAdapterCPDS.

- [https://github.com/cuijiung/jackson-CVE-2020-36180](https://github.com/cuijiung/jackson-CVE-2020-36180) :  ![starts](https://img.shields.io/github/stars/cuijiung/jackson-CVE-2020-36180.svg) ![forks](https://img.shields.io/github/forks/cuijiung/jackson-CVE-2020-36180.svg)


## CVE-2020-26259
 XStream is a Java library to serialize objects to XML and back again. In XStream before version 1.4.15, is vulnerable to an Arbitrary File Deletion on the local host when unmarshalling. The vulnerability may allow a remote attacker to delete arbitrary know files on the host as log as the executing process has sufficient rights only by manipulating the processed input stream. If you rely on XStream's default blacklist of the Security Framework, you will have to use at least version 1.4.15. The reported vulnerability does not exist running Java 15 or higher. No user is affected, who followed the recommendation to setup XStream's Security Framework with a whitelist! Anyone relying on XStream's default blacklist can immediately switch to a whilelist for the allowed types to avoid the vulnerability. Users of XStream 1.4.14 or below who still want to use XStream default blacklist can use a workaround described in more detailed in the referenced advisories.

- [https://github.com/cuijiung/xstream-CVE-2020-26259](https://github.com/cuijiung/xstream-CVE-2020-26259) :  ![starts](https://img.shields.io/github/stars/cuijiung/xstream-CVE-2020-26259.svg) ![forks](https://img.shields.io/github/forks/cuijiung/xstream-CVE-2020-26259.svg)


## CVE-2020-26258
 XStream is a Java library to serialize objects to XML and back again. In XStream before version 1.4.15, a Server-Side Forgery Request vulnerability can be activated when unmarshalling. The vulnerability may allow a remote attacker to request data from internal resources that are not publicly available only by manipulating the processed input stream. If you rely on XStream's default blacklist of the Security Framework, you will have to use at least version 1.4.15. The reported vulnerability does not exist if running Java 15 or higher. No user is affected who followed the recommendation to setup XStream's Security Framework with a whitelist! Anyone relying on XStream's default blacklist can immediately switch to a whilelist for the allowed types to avoid the vulnerability. Users of XStream 1.4.14 or below who still want to use XStream default blacklist can use a workaround described in more detailed in the referenced advisories.

- [https://github.com/cuijiung/xstream-CVE-2020-26258](https://github.com/cuijiung/xstream-CVE-2020-26258) :  ![starts](https://img.shields.io/github/stars/cuijiung/xstream-CVE-2020-26258.svg) ![forks](https://img.shields.io/github/forks/cuijiung/xstream-CVE-2020-26258.svg)


## CVE-2020-26217
 XStream before version 1.4.14 is vulnerable to Remote Code Execution.The vulnerability may allow a remote attacker to run arbitrary shell commands only by manipulating the processed input stream. Only users who rely on blocklists are affected. Anyone using XStream's Security Framework allowlist is not affected. The linked advisory provides code workarounds for users who cannot upgrade. The issue is fixed in version 1.4.14.

- [https://github.com/cuijiung/xstream-CVE-2020-26217](https://github.com/cuijiung/xstream-CVE-2020-26217) :  ![starts](https://img.shields.io/github/stars/cuijiung/xstream-CVE-2020-26217.svg) ![forks](https://img.shields.io/github/forks/cuijiung/xstream-CVE-2020-26217.svg)


## CVE-2020-11989
 Apache Shiro before 1.5.3, when using Apache Shiro with Spring dynamic controllers, a specially crafted request may cause an authentication bypass.

- [https://github.com/cuijiung/shiro-CVE-2020-11989](https://github.com/cuijiung/shiro-CVE-2020-11989) :  ![starts](https://img.shields.io/github/stars/cuijiung/shiro-CVE-2020-11989.svg) ![forks](https://img.shields.io/github/forks/cuijiung/shiro-CVE-2020-11989.svg)


## CVE-2017-7921
 An Improper Authentication issue was discovered in Hikvision DS-2CD2xx2F-I Series V5.2.0 build 140721 to V5.4.0 build 160530, DS-2CD2xx0F-I Series V5.2.0 build 140721 to V5.4.0 Build 160401, DS-2CD2xx2FWD Series V5.3.1 build 150410 to V5.4.4 Build 161125, DS-2CD4x2xFWD Series V5.2.0 build 140721 to V5.4.0 Build 160414, DS-2CD4xx5 Series V5.2.0 build 140721 to V5.4.0 Build 160421, DS-2DFx Series V5.2.0 build 140805 to V5.4.5 Build 160928, and DS-2CD63xx Series V5.0.9 build 140305 to V5.3.5 Build 160106 devices. The improper authentication vulnerability occurs when an application does not adequately or correctly authenticate users. This may allow a malicious user to escalate his or her privileges on the system and gain access to sensitive information.

- [https://github.com/GabrielAvls/CVE-2017-7921](https://github.com/GabrielAvls/CVE-2017-7921) :  ![starts](https://img.shields.io/github/stars/GabrielAvls/CVE-2017-7921.svg) ![forks](https://img.shields.io/github/forks/GabrielAvls/CVE-2017-7921.svg)


## CVE-2014-6287
 The findMacroMarker function in parserLib.pas in Rejetto HTTP File Server (aks HFS or HttpFileServer) 2.3x before 2.3c allows remote attackers to execute arbitrary programs via a %00 sequence in a search action.

- [https://github.com/rahisec/rejetto-http-file-server-2.3.x-RCE-exploit-CVE-2014-6287](https://github.com/rahisec/rejetto-http-file-server-2.3.x-RCE-exploit-CVE-2014-6287) :  ![starts](https://img.shields.io/github/stars/rahisec/rejetto-http-file-server-2.3.x-RCE-exploit-CVE-2014-6287.svg) ![forks](https://img.shields.io/github/forks/rahisec/rejetto-http-file-server-2.3.x-RCE-exploit-CVE-2014-6287.svg)


## CVE-2007-2447
 The MS-RPC functionality in smbd in Samba 3.0.0 through 3.0.25rc3 allows remote attackers to execute arbitrary commands via shell metacharacters involving the (1) SamrChangePassword function, when the "username map script" smb.conf option is enabled, and allows remote authenticated users to execute commands via shell metacharacters involving other MS-RPC functions in the (2) remote printer and (3) file share management.

- [https://github.com/MrRoma577/exploit_cve-2007-2447_again](https://github.com/MrRoma577/exploit_cve-2007-2447_again) :  ![starts](https://img.shields.io/github/stars/MrRoma577/exploit_cve-2007-2447_again.svg) ![forks](https://img.shields.io/github/forks/MrRoma577/exploit_cve-2007-2447_again.svg)

