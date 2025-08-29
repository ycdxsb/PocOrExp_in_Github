# Update 2025-08-29
## CVE-2025-54309
 CrushFTP 10 before 10.8.5 and 11 before 11.3.4_23, when the DMZ proxy feature is not used, mishandles AS2 validation and consequently allows remote attackers to obtain admin access via HTTPS, as exploited in the wild in July 2025.

- [https://github.com/watchtowrlabs/watchTowr-vs-CrushFTP-Authentication-Bypass-CVE-2025-54309](https://github.com/watchtowrlabs/watchTowr-vs-CrushFTP-Authentication-Bypass-CVE-2025-54309) :  ![starts](https://img.shields.io/github/stars/watchtowrlabs/watchTowr-vs-CrushFTP-Authentication-Bypass-CVE-2025-54309.svg) ![forks](https://img.shields.io/github/forks/watchtowrlabs/watchTowr-vs-CrushFTP-Authentication-Bypass-CVE-2025-54309.svg)


## CVE-2025-52122
 Freeform 5.0.0 to before 5.10.16, a plugin for CraftCMS, contains an Server-side template injection (SSTI) vulnerability, resulting in arbitrary code injection for all users that have access to editing a form (submission title).

- [https://github.com/TimTrademark/CVE-2025-52122](https://github.com/TimTrademark/CVE-2025-52122) :  ![starts](https://img.shields.io/github/stars/TimTrademark/CVE-2025-52122.svg) ![forks](https://img.shields.io/github/forks/TimTrademark/CVE-2025-52122.svg)


## CVE-2025-50428
 In RaspAP raspap-webgui 3.3.2 and earlier, a command injection vulnerability exists in the includes/hostapd.php script. The vulnerability is due to improper sanitizing of user input passed via the interface parameter.

- [https://github.com/security-smarttecs/cve-2025-50428](https://github.com/security-smarttecs/cve-2025-50428) :  ![starts](https://img.shields.io/github/stars/security-smarttecs/cve-2025-50428.svg) ![forks](https://img.shields.io/github/forks/security-smarttecs/cve-2025-50428.svg)


## CVE-2025-48384
 Git is a fast, scalable, distributed revision control system with an unusually rich command set that provides both high-level operations and full access to internals. When reading a config value, Git strips any trailing carriage return and line feed (CRLF). When writing a config entry, values with a trailing CR are not quoted, causing the CR to be lost when the config is later read. When initializing a submodule, if the submodule path contains a trailing CR, the altered path is read resulting in the submodule being checked out to an incorrect location. If a symlink exists that points the altered path to the submodule hooks directory, and the submodule contains an executable post-checkout hook, the script may be unintentionally executed after checkout. This vulnerability is fixed in v2.43.7, v2.44.4, v2.45.4, v2.46.4, v2.47.3, v2.48.2, v2.49.1, and v2.50.1.

- [https://github.com/wzx5002/totallynotsuspicious](https://github.com/wzx5002/totallynotsuspicious) :  ![starts](https://img.shields.io/github/stars/wzx5002/totallynotsuspicious.svg) ![forks](https://img.shields.io/github/forks/wzx5002/totallynotsuspicious.svg)
- [https://github.com/wzx5002/CVE-2025-48384](https://github.com/wzx5002/CVE-2025-48384) :  ![starts](https://img.shields.io/github/stars/wzx5002/CVE-2025-48384.svg) ![forks](https://img.shields.io/github/forks/wzx5002/CVE-2025-48384.svg)


## CVE-2025-38676
maximum length.

- [https://github.com/14mb1v45h/CVE-2025-38676](https://github.com/14mb1v45h/CVE-2025-38676) :  ![starts](https://img.shields.io/github/stars/14mb1v45h/CVE-2025-38676.svg) ![forks](https://img.shields.io/github/forks/14mb1v45h/CVE-2025-38676.svg)


## CVE-2025-34161
 Coolify versions prior to v4.0.0-beta.420.7 are vulnerable to a remote code execution vulnerability in the project deployment workflow. The platform allows authenticated users, with low-level member privileges, to inject arbitrary shell commands via the Git Repository field during project creation. By submitting a crafted repository string containing command injection syntax, an attacker can execute arbitrary commands on the underlying host system, resulting in full server compromise.

- [https://github.com/Eyodav/CVE-2025-34161](https://github.com/Eyodav/CVE-2025-34161) :  ![starts](https://img.shields.io/github/stars/Eyodav/CVE-2025-34161.svg) ![forks](https://img.shields.io/github/forks/Eyodav/CVE-2025-34161.svg)


## CVE-2025-34159
 Coolify versions prior to v4.0.0-beta.420.6 are vulnerable to a remote code execution vulnerability in the application deployment workflow. The platform allows authenticated users, with low-level member privileges, to inject arbitrary Docker Compose directives during project creation. By crafting a malicious service definition that mounts the host root filesystem, an attacker can gain full root access to the underlying server.

- [https://github.com/Eyodav/CVE-2025-34159](https://github.com/Eyodav/CVE-2025-34159) :  ![starts](https://img.shields.io/github/stars/Eyodav/CVE-2025-34159.svg) ![forks](https://img.shields.io/github/forks/Eyodav/CVE-2025-34159.svg)


## CVE-2025-34157
 Coolify versions prior to v4.0.0-beta.420.6 are vulnerable to a stored cross-site scripting (XSS) attack in the project creation workflow. An authenticated user with low privileges can create a project with a maliciously crafted name containing embedded JavaScript. When an administrator attempts to delete the project or its associated resource, the payload executes in the admin’s browser context. This results in full compromise of the Coolify instance, including theft of API tokens, session cookies, and access to WebSocket-based terminal sessions on managed servers.

- [https://github.com/Eyodav/CVE-2025-34157](https://github.com/Eyodav/CVE-2025-34157) :  ![starts](https://img.shields.io/github/stars/Eyodav/CVE-2025-34157.svg) ![forks](https://img.shields.io/github/forks/Eyodav/CVE-2025-34157.svg)


## CVE-2025-32463
 Sudo before 1.9.17p1 allows local users to obtain root access because /etc/nsswitch.conf from a user-controlled directory is used with the --chroot option.

- [https://github.com/Yuy0ung/CVE-2025-32463_chwoot](https://github.com/Yuy0ung/CVE-2025-32463_chwoot) :  ![starts](https://img.shields.io/github/stars/Yuy0ung/CVE-2025-32463_chwoot.svg) ![forks](https://img.shields.io/github/forks/Yuy0ung/CVE-2025-32463_chwoot.svg)
- [https://github.com/hacieda/CVE-2025-32463](https://github.com/hacieda/CVE-2025-32463) :  ![starts](https://img.shields.io/github/stars/hacieda/CVE-2025-32463.svg) ![forks](https://img.shields.io/github/forks/hacieda/CVE-2025-32463.svg)


## CVE-2025-32433
 Erlang/OTP is a set of libraries for the Erlang programming language. Prior to versions OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20, a SSH server may allow an attacker to perform unauthenticated remote code execution (RCE). By exploiting a flaw in SSH protocol message handling, a malicious actor could gain unauthorized access to affected systems and execute arbitrary commands without valid credentials. This issue is patched in versions OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20. A temporary workaround involves disabling the SSH server or to prevent access via firewall rules.

- [https://github.com/te0rwx/CVE-2025-32433-Detection](https://github.com/te0rwx/CVE-2025-32433-Detection) :  ![starts](https://img.shields.io/github/stars/te0rwx/CVE-2025-32433-Detection.svg) ![forks](https://img.shields.io/github/forks/te0rwx/CVE-2025-32433-Detection.svg)


## CVE-2025-27363
 An out of bounds write exists in FreeType versions 2.13.0 and below (newer versions of FreeType are not vulnerable) when attempting to parse font subglyph structures related to TrueType GX and variable font files. The vulnerable code assigns a signed short value to an unsigned long and then adds a static value causing it to wrap around and allocate too small of a heap buffer. The code then writes up to 6 signed long integers out of bounds relative to this buffer. This may result in arbitrary code execution. This vulnerability may have been exploited in the wild.

- [https://github.com/tin-z/CVE-2025-27363](https://github.com/tin-z/CVE-2025-27363) :  ![starts](https://img.shields.io/github/stars/tin-z/CVE-2025-27363.svg) ![forks](https://img.shields.io/github/forks/tin-z/CVE-2025-27363.svg)


## CVE-2025-24893
 XWiki Platform is a generic wiki platform offering runtime services for applications built on top of it. Any guest can perform arbitrary remote code execution through a request to `SolrSearch`. This impacts the confidentiality, integrity and availability of the whole XWiki installation. To reproduce on an instance, without being logged in, go to `host/xwiki/bin/get/Main/SolrSearch?media=rss&text=%7D%7D%7D%7B%7Basync%20async%3Dfalse%7D%7D%7B%7Bgroovy%7D%7Dprintln%28"Hello%20from"%20%2B%20"%20search%20text%3A"%20%2B%20%2823%20%2B%2019%29%29%7B%7B%2Fgroovy%7D%7D%7B%7B%2Fasync%7D%7D%20`. If there is an output, and the title of the RSS feed contains `Hello from search text:42`, then the instance is vulnerable. This vulnerability has been patched in XWiki 15.10.11, 16.4.1 and 16.5.0RC1. Users are advised to upgrade. Users unable to upgrade may edit `Main.SolrSearchMacros` in `SolrSearchMacros.xml` on line 955 to match the `rawResponse` macro in `macros.vm#L2824` with a content type of `application/xml`, instead of simply outputting the content of the feed.

- [https://github.com/AzureADTrent/CVE-2025-24893-Reverse-Shell](https://github.com/AzureADTrent/CVE-2025-24893-Reverse-Shell) :  ![starts](https://img.shields.io/github/stars/AzureADTrent/CVE-2025-24893-Reverse-Shell.svg) ![forks](https://img.shields.io/github/forks/AzureADTrent/CVE-2025-24893-Reverse-Shell.svg)


## CVE-2025-8088
     from ESET.

- [https://github.com/pentestfunctions/best-CVE-2025-8088](https://github.com/pentestfunctions/best-CVE-2025-8088) :  ![starts](https://img.shields.io/github/stars/pentestfunctions/best-CVE-2025-8088.svg) ![forks](https://img.shields.io/github/forks/pentestfunctions/best-CVE-2025-8088.svg)
- [https://github.com/kitsuneshade/WinRAR-Exploit-Tool---Rust-Edition](https://github.com/kitsuneshade/WinRAR-Exploit-Tool---Rust-Edition) :  ![starts](https://img.shields.io/github/stars/kitsuneshade/WinRAR-Exploit-Tool---Rust-Edition.svg) ![forks](https://img.shields.io/github/forks/kitsuneshade/WinRAR-Exploit-Tool---Rust-Edition.svg)
- [https://github.com/walidpyh/CVE-2025-8088](https://github.com/walidpyh/CVE-2025-8088) :  ![starts](https://img.shields.io/github/stars/walidpyh/CVE-2025-8088.svg) ![forks](https://img.shields.io/github/forks/walidpyh/CVE-2025-8088.svg)
- [https://github.com/nyra-workspace/CVE-2025-8088](https://github.com/nyra-workspace/CVE-2025-8088) :  ![starts](https://img.shields.io/github/stars/nyra-workspace/CVE-2025-8088.svg) ![forks](https://img.shields.io/github/forks/nyra-workspace/CVE-2025-8088.svg)


## CVE-2025-6934
 The Opal Estate Pro – Property Management and Submission plugin for WordPress, used by the FullHouse - Real Estate Responsive WordPress Theme, is vulnerable to privilege escalation via in all versions up to, and including, 1.7.5. This is due to a lack of role restriction during registration in the 'on_regiser_user' function. This makes it possible for unauthenticated attackers to arbitrarily choose the role, including the Administrator role, assigned when registering.

- [https://github.com/yukinime/CVE-2025-6934](https://github.com/yukinime/CVE-2025-6934) :  ![starts](https://img.shields.io/github/stars/yukinime/CVE-2025-6934.svg) ![forks](https://img.shields.io/github/forks/yukinime/CVE-2025-6934.svg)


## CVE-2024-5083
This issue affects Nexus Repository 2 OSS/Pro versions up to and including 2.15.1.

- [https://github.com/Roronoawjd/CVE-2024-5083](https://github.com/Roronoawjd/CVE-2024-5083) :  ![starts](https://img.shields.io/github/stars/Roronoawjd/CVE-2024-5083.svg) ![forks](https://img.shields.io/github/forks/Roronoawjd/CVE-2024-5083.svg)


## CVE-2023-3609
We recommend upgrading past commit 04c55383fa5689357bcdd2c8036725a55ed632bc.

- [https://github.com/Jturnxd/CVE-2023-3609](https://github.com/Jturnxd/CVE-2023-3609) :  ![starts](https://img.shields.io/github/stars/Jturnxd/CVE-2023-3609.svg) ![forks](https://img.shields.io/github/forks/Jturnxd/CVE-2023-3609.svg)


## CVE-2022-22965
 A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the application to run on Tomcat as a WAR deployment. If the application is deployed as a Spring Boot executable jar, i.e. the default, it is not vulnerable to the exploit. However, the nature of the vulnerability is more general, and there may be other ways to exploit it.

- [https://github.com/delyee/Spring4Shell](https://github.com/delyee/Spring4Shell) :  ![starts](https://img.shields.io/github/stars/delyee/Spring4Shell.svg) ![forks](https://img.shields.io/github/forks/delyee/Spring4Shell.svg)

