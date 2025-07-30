# Update 2025-07-30
## CVE-2025-53770
Microsoft is preparing and fully testing a comprehensive update to address this vulnerability.  In the meantime, please make sure that the mitigation provided in this CVE documentation is in place so that you are protected from exploitation.

- [https://github.com/daryllundy/CVE-2025-53770](https://github.com/daryllundy/CVE-2025-53770) :  ![starts](https://img.shields.io/github/stars/daryllundy/CVE-2025-53770.svg) ![forks](https://img.shields.io/github/forks/daryllundy/CVE-2025-53770.svg)
- [https://github.com/r3xbugbounty/CVE-2025-53770](https://github.com/r3xbugbounty/CVE-2025-53770) :  ![starts](https://img.shields.io/github/stars/r3xbugbounty/CVE-2025-53770.svg) ![forks](https://img.shields.io/github/forks/r3xbugbounty/CVE-2025-53770.svg)
- [https://github.com/0x-crypt/CVE-2025-53770-Scanner](https://github.com/0x-crypt/CVE-2025-53770-Scanner) :  ![starts](https://img.shields.io/github/stars/0x-crypt/CVE-2025-53770-Scanner.svg) ![forks](https://img.shields.io/github/forks/0x-crypt/CVE-2025-53770-Scanner.svg)


## CVE-2025-48384
 Git is a fast, scalable, distributed revision control system with an unusually rich command set that provides both high-level operations and full access to internals. When reading a config value, Git strips any trailing carriage return and line feed (CRLF). When writing a config entry, values with a trailing CR are not quoted, causing the CR to be lost when the config is later read. When initializing a submodule, if the submodule path contains a trailing CR, the altered path is read resulting in the submodule being checked out to an incorrect location. If a symlink exists that points the altered path to the submodule hooks directory, and the submodule contains an executable post-checkout hook, the script may be unintentionally executed after checkout. This vulnerability is fixed in v2.43.7, v2.44.4, v2.45.4, v2.46.4, v2.47.3, v2.48.2, v2.49.1, and v2.50.1.

- [https://github.com/rtefx/CVE-2025-48384](https://github.com/rtefx/CVE-2025-48384) :  ![starts](https://img.shields.io/github/stars/rtefx/CVE-2025-48384.svg) ![forks](https://img.shields.io/github/forks/rtefx/CVE-2025-48384.svg)


## CVE-2025-34077
 An authentication bypass vulnerability exists in the WordPress Pie Register plugin ≤ 3.7.1.4 that allows unauthenticated attackers to impersonate arbitrary users by submitting a crafted POST request to the login endpoint. By setting social_site=true and manipulating the user_id_social_site parameter, an attacker can generate a valid WordPress session cookie for any user ID, including administrators. Once authenticated, the attacker may exploit plugin upload functionality to install a malicious plugin containing arbitrary PHP code, resulting in remote code execution on the underlying server.

- [https://github.com/0xgh057r3c0n/CVE-2025-34077](https://github.com/0xgh057r3c0n/CVE-2025-34077) :  ![starts](https://img.shields.io/github/stars/0xgh057r3c0n/CVE-2025-34077.svg) ![forks](https://img.shields.io/github/forks/0xgh057r3c0n/CVE-2025-34077.svg)


## CVE-2025-32462
 Sudo before 1.9.17p1, when used with a sudoers file that specifies a host that is neither the current host nor ALL, allows listed users to execute commands on unintended machines.

- [https://github.com/j3r1ch0123/CVE-2025-32462](https://github.com/j3r1ch0123/CVE-2025-32462) :  ![starts](https://img.shields.io/github/stars/j3r1ch0123/CVE-2025-32462.svg) ![forks](https://img.shields.io/github/forks/j3r1ch0123/CVE-2025-32462.svg)


## CVE-2025-32429
 XWiki Platform is a generic wiki platform offering runtime services for applications built on top of it. In versions 9.4-rc-1 through 16.10.5 and 17.0.0-rc-1 through 17.2.2, it's possible for anyone to inject SQL using the parameter sort of the getdeleteddocuments.vm. It's injected as is as an ORDER BY value. This is fixed in versions 16.10.6 and 17.3.0-rc-1.

- [https://github.com/imbas007/CVE-2025-32429-Checker](https://github.com/imbas007/CVE-2025-32429-Checker) :  ![starts](https://img.shields.io/github/stars/imbas007/CVE-2025-32429-Checker.svg) ![forks](https://img.shields.io/github/forks/imbas007/CVE-2025-32429-Checker.svg)


## CVE-2025-24813
Users are recommended to upgrade to version 11.0.3, 10.1.35 or 9.0.99, which fixes the issue.

- [https://github.com/Shivshantp/CVE-2025-24813](https://github.com/Shivshantp/CVE-2025-24813) :  ![starts](https://img.shields.io/github/stars/Shivshantp/CVE-2025-24813.svg) ![forks](https://img.shields.io/github/forks/Shivshantp/CVE-2025-24813.svg)


## CVE-2025-8191
 A vulnerability, which was classified as problematic, was found in macrozheng mall up to 1.0.3. Affected is an unknown function of the file /swagger-ui/index.html of the component Swagger UI. The manipulation of the argument configUrl leads to cross site scripting. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used. The vendor deleted the GitHub issue for this vulnerability without any explanation. Afterwards the vendor was contacted early about this disclosure via email but did not respond in any way.

- [https://github.com/byteReaper77/CVE-2025-8191](https://github.com/byteReaper77/CVE-2025-8191) :  ![starts](https://img.shields.io/github/stars/byteReaper77/CVE-2025-8191.svg) ![forks](https://img.shields.io/github/forks/byteReaper77/CVE-2025-8191.svg)


## CVE-2025-5086
 A deserialization of untrusted data vulnerability affecting DELMIA Apriso from Release 2020 through Release 2025 could lead to a remote code execution.

- [https://github.com/SacX-7/CVE-2025-50866](https://github.com/SacX-7/CVE-2025-50866) :  ![starts](https://img.shields.io/github/stars/SacX-7/CVE-2025-50866.svg) ![forks](https://img.shields.io/github/forks/SacX-7/CVE-2025-50866.svg)


## CVE-2025-2294
 The Kubio AI Page Builder plugin for WordPress is vulnerable to Local File Inclusion in all versions up to, and including, 2.5.1 via thekubio_hybrid_theme_load_template function. This makes it possible for unauthenticated attackers to include and execute arbitrary files on the server, allowing the execution of any PHP code in those files. This can be used to bypass access controls, obtain sensitive data, or achieve code execution in cases where images and other “safe” file types can be uploaded and included.

- [https://github.com/r0otk3r/CVE-2025-2294](https://github.com/r0otk3r/CVE-2025-2294) :  ![starts](https://img.shields.io/github/stars/r0otk3r/CVE-2025-2294.svg) ![forks](https://img.shields.io/github/forks/r0otk3r/CVE-2025-2294.svg)


## CVE-2024-38475
Substitutions in server context that use a backreferences or variables as the first segment of the substitution are affected.  Some unsafe RewiteRules will be broken by this change and the rewrite flag "UnsafePrefixStat" can be used to opt back in once ensuring the substitution is appropriately constrained.

- [https://github.com/abrewer251/CVE-2024-38475_SonicBoom_Apache_URL_Traversal_PoC](https://github.com/abrewer251/CVE-2024-38475_SonicBoom_Apache_URL_Traversal_PoC) :  ![starts](https://img.shields.io/github/stars/abrewer251/CVE-2024-38475_SonicBoom_Apache_URL_Traversal_PoC.svg) ![forks](https://img.shields.io/github/forks/abrewer251/CVE-2024-38475_SonicBoom_Apache_URL_Traversal_PoC.svg)


## CVE-2024-23897
 Jenkins 2.441 and earlier, LTS 2.426.2 and earlier does not disable a feature of its CLI command parser that replaces an '@' character followed by a file path in an argument with the file's contents, allowing unauthenticated attackers to read arbitrary files on the Jenkins controller file system.

- [https://github.com/revkami/CVE-2024-23897-Jenkins-4.441](https://github.com/revkami/CVE-2024-23897-Jenkins-4.441) :  ![starts](https://img.shields.io/github/stars/revkami/CVE-2024-23897-Jenkins-4.441.svg) ![forks](https://img.shields.io/github/forks/revkami/CVE-2024-23897-Jenkins-4.441.svg)


## CVE-2024-4577
 In PHP versions 8.1.* before 8.1.29, 8.2.* before 8.2.20, 8.3.* before 8.3.8, when using Apache and PHP-CGI on Windows, if the system is set up to use certain code pages, Windows may use "Best-Fit" behavior to replace characters in command line given to Win32 API functions. PHP CGI module may misinterpret those characters as PHP options, which may allow a malicious user to pass options to PHP binary being run, and thus reveal the source code of scripts, run arbitrary PHP code on the server, etc.

- [https://github.com/Ra1n-60W/CVE-2024-4577](https://github.com/Ra1n-60W/CVE-2024-4577) :  ![starts](https://img.shields.io/github/stars/Ra1n-60W/CVE-2024-4577.svg) ![forks](https://img.shields.io/github/forks/Ra1n-60W/CVE-2024-4577.svg)


## CVE-2023-26136
 Versions of the package tough-cookie before 4.1.3 are vulnerable to Prototype Pollution due to improper handling of Cookies when using CookieJar in rejectPublicSuffixes=false mode. This issue arises from the manner in which the objects are initialized.

- [https://github.com/guy2610/tough-cookie-patch-cve-2023-26136](https://github.com/guy2610/tough-cookie-patch-cve-2023-26136) :  ![starts](https://img.shields.io/github/stars/guy2610/tough-cookie-patch-cve-2023-26136.svg) ![forks](https://img.shields.io/github/forks/guy2610/tough-cookie-patch-cve-2023-26136.svg)


## CVE-2022-35411
 rpc.py through 0.6.0 allows Remote Code Execution because an unpickle occurs when the "serializer: pickle" HTTP header is sent. In other words, although JSON (not Pickle) is the default data format, an unauthenticated client can cause the data to be processed with unpickle.

- [https://github.com/CSpanias/rpc-rce.py](https://github.com/CSpanias/rpc-rce.py) :  ![starts](https://img.shields.io/github/stars/CSpanias/rpc-rce.py.svg) ![forks](https://img.shields.io/github/forks/CSpanias/rpc-rce.py.svg)


## CVE-2020-15778
 scp in OpenSSH through 8.3p1 allows command injection in the scp.c toremote function, as demonstrated by backtick characters in the destination argument. NOTE: the vendor reportedly has stated that they intentionally omit validation of "anomalous argument transfers" because that could "stand a great chance of breaking existing workflows."

- [https://github.com/drackyjr/CVE-2020-15778-SCP-Command-Injection-Check](https://github.com/drackyjr/CVE-2020-15778-SCP-Command-Injection-Check) :  ![starts](https://img.shields.io/github/stars/drackyjr/CVE-2020-15778-SCP-Command-Injection-Check.svg) ![forks](https://img.shields.io/github/forks/drackyjr/CVE-2020-15778-SCP-Command-Injection-Check.svg)


## CVE-2017-6090
 Unrestricted file upload vulnerability in clients/editclient.php in PhpCollab 2.5.1 and earlier allows remote authenticated users to execute arbitrary code by uploading a file with an executable extension, then accessing it via a direct request to the file in logos_clients/.

- [https://github.com/jlk/exploit-CVE-2017-6090](https://github.com/jlk/exploit-CVE-2017-6090) :  ![starts](https://img.shields.io/github/stars/jlk/exploit-CVE-2017-6090.svg) ![forks](https://img.shields.io/github/forks/jlk/exploit-CVE-2017-6090.svg)


## CVE-2017-6079
 The HTTP web-management application on Edgewater Networks Edgemarc appliances has a hidden page that allows for user-defined commands such as specific iptables routes, etc., to be set. You can use this page as a web shell essentially to execute commands, though you get no feedback client-side from the web application: if the command is valid, it executes. An example is the wget command. The page that allows this has been confirmed in firmware as old as 2006.

- [https://github.com/MostafaSoliman/CVE-2017-6079-Blind-Command-Injection-In-Edgewater-Edgemarc-Devices-Exploit](https://github.com/MostafaSoliman/CVE-2017-6079-Blind-Command-Injection-In-Edgewater-Edgemarc-Devices-Exploit) :  ![starts](https://img.shields.io/github/stars/MostafaSoliman/CVE-2017-6079-Blind-Command-Injection-In-Edgewater-Edgemarc-Devices-Exploit.svg) ![forks](https://img.shields.io/github/forks/MostafaSoliman/CVE-2017-6079-Blind-Command-Injection-In-Edgewater-Edgemarc-Devices-Exploit.svg)


## CVE-2012-1823
 sapi/cgi/cgi_main.c in PHP before 5.3.12 and 5.4.x before 5.4.2, when configured as a CGI script (aka php-cgi), does not properly handle query strings that lack an = (equals sign) character, which allows remote attackers to execute arbitrary code by placing command-line options in the query string, related to lack of skipping a certain php_getopt for the 'd' case.

- [https://github.com/AurelSugarek/CVE-2012-1823-exploit-for-https-user-password-web](https://github.com/AurelSugarek/CVE-2012-1823-exploit-for-https-user-password-web) :  ![starts](https://img.shields.io/github/stars/AurelSugarek/CVE-2012-1823-exploit-for-https-user-password-web.svg) ![forks](https://img.shields.io/github/forks/AurelSugarek/CVE-2012-1823-exploit-for-https-user-password-web.svg)


## CVE-2001-1473
 The SSH-1 protocol allows remote servers to conduct man-in-the-middle attacks and replay a client challenge response to a target server by creating a Session ID that matches the Session ID of the target, but which uses a public key pair that is weaker than the target's public key, which allows the attacker to compute the corresponding private key and use the target's Session ID with the compromised key pair to masquerade as the target.

- [https://github.com/alexandermoro/cve-2001-1473](https://github.com/alexandermoro/cve-2001-1473) :  ![starts](https://img.shields.io/github/stars/alexandermoro/cve-2001-1473.svg) ![forks](https://img.shields.io/github/forks/alexandermoro/cve-2001-1473.svg)

