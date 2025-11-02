# Update 2025-11-02
## CVE-2025-60749
 DLL Hijacking vulnerability in Trimble SketchUp desktop 2025 via crafted libcef.dll used by sketchup_webhelper.exe.

- [https://github.com/yawataa/CVE-2025-60749](https://github.com/yawataa/CVE-2025-60749) :  ![starts](https://img.shields.io/github/stars/yawataa/CVE-2025-60749.svg) ![forks](https://img.shields.io/github/forks/yawataa/CVE-2025-60749.svg)


## CVE-2025-49844
 Redis is an open source, in-memory database that persists on disk. Versions 8.2.1 and below allow an authenticated user to use a specially crafted Lua script to manipulate the garbage collector, trigger a use-after-free and potentially lead to remote code execution. The problem exists in all versions of Redis with Lua scripting. This issue is fixed in version 8.2.2. To workaround this issue without patching the redis-server executable is to prevent users from executing Lua scripts. This can be done using ACL to restrict EVAL and EVALSHA commands.

- [https://github.com/saneki/cve-2025-49844](https://github.com/saneki/cve-2025-49844) :  ![starts](https://img.shields.io/github/stars/saneki/cve-2025-49844.svg) ![forks](https://img.shields.io/github/forks/saneki/cve-2025-49844.svg)


## CVE-2025-48924
Users are recommended to upgrade to version 3.18.0, which fixes the issue.

- [https://github.com/njawalkar/apache-commons-lang2](https://github.com/njawalkar/apache-commons-lang2) :  ![starts](https://img.shields.io/github/stars/njawalkar/apache-commons-lang2.svg) ![forks](https://img.shields.io/github/forks/njawalkar/apache-commons-lang2.svg)


## CVE-2025-48384
 Git is a fast, scalable, distributed revision control system with an unusually rich command set that provides both high-level operations and full access to internals. When reading a config value, Git strips any trailing carriage return and line feed (CRLF). When writing a config entry, values with a trailing CR are not quoted, causing the CR to be lost when the config is later read. When initializing a submodule, if the submodule path contains a trailing CR, the altered path is read resulting in the submodule being checked out to an incorrect location. If a symlink exists that points the altered path to the submodule hooks directory, and the submodule contains an executable post-checkout hook, the script may be unintentionally executed after checkout. This vulnerability is fixed in v2.43.7, v2.44.4, v2.45.4, v2.46.4, v2.47.3, v2.48.2, v2.49.1, and v2.50.1.

- [https://github.com/MarcoTondolo/cve-2025-48384-poc](https://github.com/MarcoTondolo/cve-2025-48384-poc) :  ![starts](https://img.shields.io/github/stars/MarcoTondolo/cve-2025-48384-poc.svg) ![forks](https://img.shields.io/github/forks/MarcoTondolo/cve-2025-48384-poc.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/R3verseIN/Nextjs-middleware-vulnerable-appdemo-CVE-2025-29927](https://github.com/R3verseIN/Nextjs-middleware-vulnerable-appdemo-CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/R3verseIN/Nextjs-middleware-vulnerable-appdemo-CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/R3verseIN/Nextjs-middleware-vulnerable-appdemo-CVE-2025-29927.svg)


## CVE-2025-26794
 Exim 4.98 before 4.98.1, when SQLite hints and ETRN serialization are used, allows remote SQL injection.

- [https://github.com/XploitGh0st/CVE-2025-26794-exploit](https://github.com/XploitGh0st/CVE-2025-26794-exploit) :  ![starts](https://img.shields.io/github/stars/XploitGh0st/CVE-2025-26794-exploit.svg) ![forks](https://img.shields.io/github/forks/XploitGh0st/CVE-2025-26794-exploit.svg)


## CVE-2025-26625
 Git LFS is a Git extension for versioning large files. In Git LFS versions 0.5.2 through 3.7.0, when populating a Git repository's working tree with the contents of Git LFS objects, certain Git LFS commands may write to files visible outside the current Git working tree if symbolic or hard links exist which collide with the paths of files tracked by Git LFS. The git lfs checkout and git lfs pull commands do not check for symbolic links before writing to files in the working tree, allowing an attacker to craft a repository containing symbolic or hard links that cause Git LFS to write to arbitrary file system locations accessible to the user running these commands. As well, when the git lfs checkout and git lfs pull commands are run in a bare repository, they could write to files visible outside the repository. The vulnerability is fixed in version 3.7.1. As a workaround, support for symlinks in Git may be disabled by setting the core.symlinks configuration option to false, after which further clones and fetches will not create symbolic links. However, any symbolic or hard links in existing repositories will still provide the opportunity for Git LFS to write to their targets.

- [https://github.com/Mitchellzhou1/CVE_2025_26625_PoC](https://github.com/Mitchellzhou1/CVE_2025_26625_PoC) :  ![starts](https://img.shields.io/github/stars/Mitchellzhou1/CVE_2025_26625_PoC.svg) ![forks](https://img.shields.io/github/forks/Mitchellzhou1/CVE_2025_26625_PoC.svg)


## CVE-2025-24893
 XWiki Platform is a generic wiki platform offering runtime services for applications built on top of it. Any guest can perform arbitrary remote code execution through a request to `SolrSearch`. This impacts the confidentiality, integrity and availability of the whole XWiki installation. To reproduce on an instance, without being logged in, go to `host/xwiki/bin/get/Main/SolrSearch?media=rss&text=%7D%7D%7D%7B%7Basync%20async%3Dfalse%7D%7D%7B%7Bgroovy%7D%7Dprintln%28"Hello%20from"%20%2B%20"%20search%20text%3A"%20%2B%20%2823%20%2B%2019%29%29%7B%7B%2Fgroovy%7D%7D%7B%7B%2Fasync%7D%7D%20`. If there is an output, and the title of the RSS feed contains `Hello from search text:42`, then the instance is vulnerable. This vulnerability has been patched in XWiki 15.10.11, 16.4.1 and 16.5.0RC1. Users are advised to upgrade. Users unable to upgrade may edit `Main.SolrSearchMacros` in `SolrSearchMacros.xml` on line 955 to match the `rawResponse` macro in `macros.vm#L2824` with a content type of `application/xml`, instead of simply outputting the content of the feed.

- [https://github.com/Y2F05p2w/CVE-2025-24893](https://github.com/Y2F05p2w/CVE-2025-24893) :  ![starts](https://img.shields.io/github/stars/Y2F05p2w/CVE-2025-24893.svg) ![forks](https://img.shields.io/github/forks/Y2F05p2w/CVE-2025-24893.svg)


## CVE-2025-6075
variables.

- [https://github.com/zer0matt/CVE-2025-60752](https://github.com/zer0matt/CVE-2025-60752) :  ![starts](https://img.shields.io/github/stars/zer0matt/CVE-2025-60752.svg) ![forks](https://img.shields.io/github/forks/zer0matt/CVE-2025-60752.svg)


## CVE-2025-1100
 A CWE-259 "Use of Hard-coded Password" for the root account in Q-Free MaxTime less than or equal to version 2.11.0 allows an unauthenticated remote attacker to execute arbitrary code with root privileges via SSH.

- [https://github.com/litolito54/CVE-2025-11001](https://github.com/litolito54/CVE-2025-11001) :  ![starts](https://img.shields.io/github/stars/litolito54/CVE-2025-11001.svg) ![forks](https://img.shields.io/github/forks/litolito54/CVE-2025-11001.svg)


## CVE-2024-39713
 A Server-Side Request Forgery (SSRF) affects Rocket.Chat's Twilio webhook endpoint before version 6.10.1.

- [https://github.com/blackcodersec/exploit-cve](https://github.com/blackcodersec/exploit-cve) :  ![starts](https://img.shields.io/github/stars/blackcodersec/exploit-cve.svg) ![forks](https://img.shields.io/github/forks/blackcodersec/exploit-cve.svg)


## CVE-2024-9047
 The WordPress File Upload plugin for WordPress is vulnerable to Path Traversal in all versions up to, and including, 4.24.11 via wfu_file_downloader.php. This makes it possible for unauthenticated attackers to read or delete files outside of the originally intended directory. Successful exploitation requires the targeted WordPress installation to be using PHP 7.4 or earlier.

- [https://github.com/amirqusairy99/WordPress-File-Upload-4.24.11---Unauthenticated-Path-Traversal](https://github.com/amirqusairy99/WordPress-File-Upload-4.24.11---Unauthenticated-Path-Traversal) :  ![starts](https://img.shields.io/github/stars/amirqusairy99/WordPress-File-Upload-4.24.11---Unauthenticated-Path-Traversal.svg) ![forks](https://img.shields.io/github/forks/amirqusairy99/WordPress-File-Upload-4.24.11---Unauthenticated-Path-Traversal.svg)


## CVE-2022-22536
 SAP NetWeaver Application Server ABAP, SAP NetWeaver Application Server Java, ABAP Platform, SAP Content Server 7.53 and SAP Web Dispatcher are vulnerable for request smuggling and request concatenation. An unauthenticated attacker can prepend a victim's request with arbitrary data. This way, the attacker can execute functions impersonating the victim or poison intermediary Web caches. A successful attack could result in complete compromise of Confidentiality, Integrity and Availability of the system.

- [https://github.com/abrewer251/CVE-2022-22536_SAP_Request_Smuggling_Scanner](https://github.com/abrewer251/CVE-2022-22536_SAP_Request_Smuggling_Scanner) :  ![starts](https://img.shields.io/github/stars/abrewer251/CVE-2022-22536_SAP_Request_Smuggling_Scanner.svg) ![forks](https://img.shields.io/github/forks/abrewer251/CVE-2022-22536_SAP_Request_Smuggling_Scanner.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/adrianmafandy/CVE-2021-41773](https://github.com/adrianmafandy/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/adrianmafandy/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/adrianmafandy/CVE-2021-41773.svg)


## CVE-2021-29447
 Wordpress is an open source CMS. A user with the ability to upload files (like an Author) can exploit an XML parsing issue in the Media Library leading to XXE attacks. This requires WordPress installation to be using PHP 8. Access to internal files is possible in a successful XXE attack. This has been patched in WordPress version 5.7.1, along with the older affected versions via a minor release. We strongly recommend you keep auto-updates enabled.

- [https://github.com/0xricksanchez/CVE-2021-29447](https://github.com/0xricksanchez/CVE-2021-29447) :  ![starts](https://img.shields.io/github/stars/0xricksanchez/CVE-2021-29447.svg) ![forks](https://img.shields.io/github/forks/0xricksanchez/CVE-2021-29447.svg)


## CVE-2021-3560
 It was found that polkit could be tricked into bypassing the credential checks for D-Bus requests, elevating the privileges of the requestor to the root user. This flaw could be used by an unprivileged local attacker to, for example, create a new local administrator. The highest threat from this vulnerability is to data confidentiality and integrity as well as system availability.

- [https://github.com/SeimuPVE/CVE-2021-3560_Polkit](https://github.com/SeimuPVE/CVE-2021-3560_Polkit) :  ![starts](https://img.shields.io/github/stars/SeimuPVE/CVE-2021-3560_Polkit.svg) ![forks](https://img.shields.io/github/forks/SeimuPVE/CVE-2021-3560_Polkit.svg)


## CVE-2015-1328
 The overlayfs implementation in the linux (aka Linux kernel) package before 3.19.0-21.21 in Ubuntu through 15.04 does not properly check permissions for file creation in the upper filesystem directory, which allows local users to obtain root access by leveraging a configuration in which overlayfs is permitted in an arbitrary mount namespace.

- [https://github.com/0xf1d0/CVE-2015-1328](https://github.com/0xf1d0/CVE-2015-1328) :  ![starts](https://img.shields.io/github/stars/0xf1d0/CVE-2015-1328.svg) ![forks](https://img.shields.io/github/forks/0xf1d0/CVE-2015-1328.svg)

