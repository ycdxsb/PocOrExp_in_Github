# Update 2025-08-08
## CVE-2025-54794
 Claude Code is an agentic coding tool. In versions below 0.2.111, a path validation flaw using prefix matching instead of canonical path comparison, makes it possible to bypass directory restrictions and access files outside the CWD. Successful exploitation depends on the presence of (or ability to create) a directory with the same prefix as the CWD and the ability to add untrusted content into a Claude Code context window. This is fixed in version 0.2.111.

- [https://github.com/AdityaBhatt3010/CVE-2025-54794-Hijacking-Claude-AI-with-a-Prompt-Injection-The-Jailbreak-That-Talked-Back](https://github.com/AdityaBhatt3010/CVE-2025-54794-Hijacking-Claude-AI-with-a-Prompt-Injection-The-Jailbreak-That-Talked-Back) :  ![starts](https://img.shields.io/github/stars/AdityaBhatt3010/CVE-2025-54794-Hijacking-Claude-AI-with-a-Prompt-Injection-The-Jailbreak-That-Talked-Back.svg) ![forks](https://img.shields.io/github/forks/AdityaBhatt3010/CVE-2025-54794-Hijacking-Claude-AI-with-a-Prompt-Injection-The-Jailbreak-That-Talked-Back.svg)


## CVE-2025-54253
 Adobe Experience Manager versions 6.5.23 and earlier are affected by a Misconfiguration vulnerability that could result in arbitrary code execution. An attacker could leverage this vulnerability to bypass security mechanisms and execute code. Exploitation of this issue does not require user interaction and scope is changed.

- [https://github.com/B1ack4sh/Blackash-CVE-2025-54253](https://github.com/B1ack4sh/Blackash-CVE-2025-54253) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-54253.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-54253.svg)


## CVE-2025-50286
 A Remote Code Execution (RCE) vulnerability in Grav CMS v1.7.48 allows an authenticated admin to upload a malicious plugin via the /admin/tools/direct-install interface. Once uploaded, the plugin is automatically extracted and loaded, allowing arbitrary PHP code execution and reverse shell access.

- [https://github.com/binneko/CVE-2025-50286](https://github.com/binneko/CVE-2025-50286) :  ![starts](https://img.shields.io/github/stars/binneko/CVE-2025-50286.svg) ![forks](https://img.shields.io/github/forks/binneko/CVE-2025-50286.svg)


## CVE-2025-48384
 Git is a fast, scalable, distributed revision control system with an unusually rich command set that provides both high-level operations and full access to internals. When reading a config value, Git strips any trailing carriage return and line feed (CRLF). When writing a config entry, values with a trailing CR are not quoted, causing the CR to be lost when the config is later read. When initializing a submodule, if the submodule path contains a trailing CR, the altered path is read resulting in the submodule being checked out to an incorrect location. If a symlink exists that points the altered path to the submodule hooks directory, and the submodule contains an executable post-checkout hook, the script may be unintentionally executed after checkout. This vulnerability is fixed in v2.43.7, v2.44.4, v2.45.4, v2.46.4, v2.47.3, v2.48.2, v2.49.1, and v2.50.1.

- [https://github.com/jideasn/cve-2025-48384](https://github.com/jideasn/cve-2025-48384) :  ![starts](https://img.shields.io/github/stars/jideasn/cve-2025-48384.svg) ![forks](https://img.shields.io/github/forks/jideasn/cve-2025-48384.svg)


## CVE-2025-24893
 XWiki Platform is a generic wiki platform offering runtime services for applications built on top of it. Any guest can perform arbitrary remote code execution through a request to `SolrSearch`. This impacts the confidentiality, integrity and availability of the whole XWiki installation. To reproduce on an instance, without being logged in, go to `host/xwiki/bin/get/Main/SolrSearch?media=rss&text=%7D%7D%7D%7B%7Basync%20async%3Dfalse%7D%7D%7B%7Bgroovy%7D%7Dprintln%28"Hello%20from"%20%2B%20"%20search%20text%3A"%20%2B%20%2823%20%2B%2019%29%29%7B%7B%2Fgroovy%7D%7D%7B%7B%2Fasync%7D%7D%20`. If there is an output, and the title of the RSS feed contains `Hello from search text:42`, then the instance is vulnerable. This vulnerability has been patched in XWiki 15.10.11, 16.4.1 and 16.5.0RC1. Users are advised to upgrade. Users unable to upgrade may edit `Main.SolrSearchMacros` in `SolrSearchMacros.xml` on line 955 to match the `rawResponse` macro in `macros.vm#L2824` with a content type of `application/xml`, instead of simply outputting the content of the feed.

- [https://github.com/570RMBR3AK3R/xwiki-cve-2025-24893-poc](https://github.com/570RMBR3AK3R/xwiki-cve-2025-24893-poc) :  ![starts](https://img.shields.io/github/stars/570RMBR3AK3R/xwiki-cve-2025-24893-poc.svg) ![forks](https://img.shields.io/github/forks/570RMBR3AK3R/xwiki-cve-2025-24893-poc.svg)


## CVE-2025-24813
Users are recommended to upgrade to version 11.0.3, 10.1.35 or 9.0.99, which fixes the issue.

- [https://github.com/cyglegit/CVE-2025-24813](https://github.com/cyglegit/CVE-2025-24813) :  ![starts](https://img.shields.io/github/stars/cyglegit/CVE-2025-24813.svg) ![forks](https://img.shields.io/github/forks/cyglegit/CVE-2025-24813.svg)


## CVE-2025-4862
 A vulnerability, which was classified as problematic, has been found in PHPGurukul Directory Management System 2.0. Affected by this issue is some unknown functionality of the file /searchdata.php. The manipulation of the argument searchdata leads to cross site scripting. The attack may be launched remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/Layer1-Artist/POC-CVE-2025-48621](https://github.com/Layer1-Artist/POC-CVE-2025-48621) :  ![starts](https://img.shields.io/github/stars/Layer1-Artist/POC-CVE-2025-48621.svg) ![forks](https://img.shields.io/github/forks/Layer1-Artist/POC-CVE-2025-48621.svg)


## CVE-2024-32167
 Sourcecodester Online Medicine Ordering System 1.0 is vulnerable to Arbitrary file deletion vulnerability as the backend settings have the function of deleting pictures to delete any files.

- [https://github.com/Narsimhareddy28/CVE-2024-32167](https://github.com/Narsimhareddy28/CVE-2024-32167) :  ![starts](https://img.shields.io/github/stars/Narsimhareddy28/CVE-2024-32167.svg) ![forks](https://img.shields.io/github/forks/Narsimhareddy28/CVE-2024-32167.svg)


## CVE-2024-32019
 Netdata is an open source observability tool. In affected versions the `ndsudo` tool shipped with affected versions of the Netdata Agent allows an attacker to run arbitrary programs with root permissions. The `ndsudo` tool is packaged as a `root`-owned executable with the SUID bit set. It only runs a restricted set of external commands, but its search paths are supplied by the `PATH` environment variable. This allows an attacker to control where `ndsudo` looks for these commands, which may be a path the attacker has write access to. This may lead to local privilege escalation. This vulnerability has been addressed in versions 1.45.3 and 1.45.2-169. Users are advised to upgrade. There are no known workarounds for this vulnerability.

- [https://github.com/C0deInBlack/CVE-2024-32019-poc](https://github.com/C0deInBlack/CVE-2024-32019-poc) :  ![starts](https://img.shields.io/github/stars/C0deInBlack/CVE-2024-32019-poc.svg) ![forks](https://img.shields.io/github/forks/C0deInBlack/CVE-2024-32019-poc.svg)


## CVE-2022-31402
 ITOP v3.0.1 was discovered to contain a cross-site scripting (XSS) vulnerability via /itop/webservices/export-v2.php.

- [https://github.com/YSah44/CVE-2022-31402](https://github.com/YSah44/CVE-2022-31402) :  ![starts](https://img.shields.io/github/stars/YSah44/CVE-2022-31402.svg) ![forks](https://img.shields.io/github/forks/YSah44/CVE-2022-31402.svg)


## CVE-2022-28508
 An XSS issue was discovered in browser_search_plugin.php in MantisBT before 2.25.2. Unescaped output of the return parameter allows an attacker to inject code into a hidden input field.

- [https://github.com/YSah44/CVE-2022-28508](https://github.com/YSah44/CVE-2022-28508) :  ![starts](https://img.shields.io/github/stars/YSah44/CVE-2022-28508.svg) ![forks](https://img.shields.io/github/forks/YSah44/CVE-2022-28508.svg)


## CVE-2022-28454
 Limbas 4.3.36.1319 is vulnerable to Cross Site Scripting (XSS).

- [https://github.com/YSah44/Limbas-4.3.36.1319-is-vulnerable-to-Cross-Site-Scripting-XSS-](https://github.com/YSah44/Limbas-4.3.36.1319-is-vulnerable-to-Cross-Site-Scripting-XSS-) :  ![starts](https://img.shields.io/github/stars/YSah44/Limbas-4.3.36.1319-is-vulnerable-to-Cross-Site-Scripting-XSS-.svg) ![forks](https://img.shields.io/github/forks/YSah44/Limbas-4.3.36.1319-is-vulnerable-to-Cross-Site-Scripting-XSS-.svg)


## CVE-2022-28452
 Red Planet Laundry Management System 1.0 is vulnerable to SQL Injection.

- [https://github.com/YSah44/Red-Planet-Laundry-Management-System-1.0-is-vulnerable-to-SQL](https://github.com/YSah44/Red-Planet-Laundry-Management-System-1.0-is-vulnerable-to-SQL) :  ![starts](https://img.shields.io/github/stars/YSah44/Red-Planet-Laundry-Management-System-1.0-is-vulnerable-to-SQL.svg) ![forks](https://img.shields.io/github/forks/YSah44/Red-Planet-Laundry-Management-System-1.0-is-vulnerable-to-SQL.svg)


## CVE-2022-22965
 A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the application to run on Tomcat as a WAR deployment. If the application is deployed as a Spring Boot executable jar, i.e. the default, it is not vulnerable to the exploit. However, the nature of the vulnerability is more general, and there may be other ways to exploit it.

- [https://github.com/salo-404/firewall](https://github.com/salo-404/firewall) :  ![starts](https://img.shields.io/github/stars/salo-404/firewall.svg) ![forks](https://img.shields.io/github/forks/salo-404/firewall.svg)


## CVE-2021-3544
 Several memory leaks were found in the virtio vhost-user GPU device (vhost-user-gpu) of QEMU in versions up to and including 6.0. They exist in contrib/vhost-user-gpu/vhost-user-gpu.c and contrib/vhost-user-gpu/virgl.c due to improper release of memory (i.e., free) after effective lifetime.

- [https://github.com/Goultarde/CVE-2021-3544_RemoteMouse-3.008-RCE](https://github.com/Goultarde/CVE-2021-3544_RemoteMouse-3.008-RCE) :  ![starts](https://img.shields.io/github/stars/Goultarde/CVE-2021-3544_RemoteMouse-3.008-RCE.svg) ![forks](https://img.shields.io/github/forks/Goultarde/CVE-2021-3544_RemoteMouse-3.008-RCE.svg)


## CVE-2017-7921
 An Improper Authentication issue was discovered in Hikvision DS-2CD2xx2F-I Series V5.2.0 build 140721 to V5.4.0 build 160530, DS-2CD2xx0F-I Series V5.2.0 build 140721 to V5.4.0 Build 160401, DS-2CD2xx2FWD Series V5.3.1 build 150410 to V5.4.4 Build 161125, DS-2CD4x2xFWD Series V5.2.0 build 140721 to V5.4.0 Build 160414, DS-2CD4xx5 Series V5.2.0 build 140721 to V5.4.0 Build 160421, DS-2DFx Series V5.2.0 build 140805 to V5.4.5 Build 160928, and DS-2CD63xx Series V5.0.9 build 140305 to V5.3.5 Build 160106 devices. The improper authentication vulnerability occurs when an application does not adequately or correctly authenticate users. This may allow a malicious user to escalate his or her privileges on the system and gain access to sensitive information.

- [https://github.com/initon/Hikvision---CVE-2017-7921](https://github.com/initon/Hikvision---CVE-2017-7921) :  ![starts](https://img.shields.io/github/stars/initon/Hikvision---CVE-2017-7921.svg) ![forks](https://img.shields.io/github/forks/initon/Hikvision---CVE-2017-7921.svg)


## CVE-2011-2523
 vsftpd 2.3.4 downloaded between 20110630 and 20110703 contains a backdoor which opens a shell on port 6200/tcp.

- [https://github.com/Lynk4/CVE-2011-2523](https://github.com/Lynk4/CVE-2011-2523) :  ![starts](https://img.shields.io/github/stars/Lynk4/CVE-2011-2523.svg) ![forks](https://img.shields.io/github/forks/Lynk4/CVE-2011-2523.svg)

