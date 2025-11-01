# Update 2025-11-01
## CVE-2025-63298
 A path traversal vulnerability was identified in SourceCodester Pet Grooming Management System 1.0, affecting the admin/manage_website.php component. An authenticated user with administrative privileges can leverage this flaw by submitting a specially crafted POST request, enabling the deletion of arbitrary files on the web server or underlying operating system.

- [https://github.com/z3rObyte/CVE-2025-63298](https://github.com/z3rObyte/CVE-2025-63298) :  ![starts](https://img.shields.io/github/stars/z3rObyte/CVE-2025-63298.svg) ![forks](https://img.shields.io/github/forks/z3rObyte/CVE-2025-63298.svg)


## CVE-2025-61481
 An issue in MikroTik RouterOS v.7.14.2 and SwOS v.2.18 exposes the WebFig management interface over cleartext HTTP by default, allowing an on-path attacker to execute injected JavaScript in the administrator’s browser and intercept credentials.

- [https://github.com/B1ack4sh/Blackash-CVE-2025-61481](https://github.com/B1ack4sh/Blackash-CVE-2025-61481) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-61481.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-61481.svg)


## CVE-2025-61196
 An issue in BusinessNext CRMnext v.10.8.3.0 allows a remote attacker to execute arbitrary code via the comments unput parameter

- [https://github.com/zsamamah/CVE-2025-61196](https://github.com/zsamamah/CVE-2025-61196) :  ![starts](https://img.shields.io/github/stars/zsamamah/CVE-2025-61196.svg) ![forks](https://img.shields.io/github/forks/zsamamah/CVE-2025-61196.svg)


## CVE-2025-59489
 Unity Runtime before 2025-10-02 on Android, Windows, macOS, and Linux allows argument injection that can result in loading of library code from an unintended location. If an application was built with a version of Unity Editor that had the vulnerable Unity Runtime code, then an adversary may be able to execute code on, and exfiltrate confidential information from, the machine on which that application is running. NOTE: product status is provided for Unity Editor because that is the information available from the Supplier. However, updating Unity Editor typically does not address the effects of the vulnerability; instead, it is necessary to rebuild and redeploy all affected applications.

- [https://github.com/moTorky/mhl_cve_2025_59489](https://github.com/moTorky/mhl_cve_2025_59489) :  ![starts](https://img.shields.io/github/stars/moTorky/mhl_cve_2025_59489.svg) ![forks](https://img.shields.io/github/forks/moTorky/mhl_cve_2025_59489.svg)


## CVE-2025-59287
 Deserialization of untrusted data in Windows Server Update Service allows an unauthorized attacker to execute code over a network.

- [https://github.com/0x7556/CVE-2025-59287](https://github.com/0x7556/CVE-2025-59287) :  ![starts](https://img.shields.io/github/stars/0x7556/CVE-2025-59287.svg) ![forks](https://img.shields.io/github/forks/0x7556/CVE-2025-59287.svg)


## CVE-2025-55752
Users are recommended to upgrade to version 11.0.11 or later, 10.1.45 or later or 9.0.109 or later, which fix the issue.

- [https://github.com/B1ack4sh/Blackash-CVE-2025-55752](https://github.com/B1ack4sh/Blackash-CVE-2025-55752) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-55752.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-55752.svg)


## CVE-2025-54957
 An issue was discovered in Dolby UDC 4.5 through 4.13. A crash of the DD+ decoder process can occur when a malformed DD+ bitstream is processed. When Evolution data is processed by evo_priv.c from the DD+ bitstream, the decoder writes that data into a buffer. The length calculation for a write can overflow due to an integer wraparound. This can lead to the allocated buffer being too small, and the out-of-bounds check of the subsequent write to be ineffective, leading to an out-of-bounds write.

- [https://github.com/AlphabugX/CVE-2025-54957](https://github.com/AlphabugX/CVE-2025-54957) :  ![starts](https://img.shields.io/github/stars/AlphabugX/CVE-2025-54957.svg) ![forks](https://img.shields.io/github/forks/AlphabugX/CVE-2025-54957.svg)


## CVE-2025-49844
 Redis is an open source, in-memory database that persists on disk. Versions 8.2.1 and below allow an authenticated user to use a specially crafted Lua script to manipulate the garbage collector, trigger a use-after-free and potentially lead to remote code execution. The problem exists in all versions of Redis with Lua scripting. This issue is fixed in version 8.2.2. To workaround this issue without patching the redis-server executable is to prevent users from executing Lua scripts. This can be done using ACL to restrict EVAL and EVALSHA commands.

- [https://github.com/B1ack4sh/Blackash-CVE-2025-49844](https://github.com/B1ack4sh/Blackash-CVE-2025-49844) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-49844.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-49844.svg)


## CVE-2025-32463
 Sudo before 1.9.17p1 allows local users to obtain root access because /etc/nsswitch.conf from a user-controlled directory is used with the --chroot option.

- [https://github.com/muhammedkayag/CVE-2025-32463](https://github.com/muhammedkayag/CVE-2025-32463) :  ![starts](https://img.shields.io/github/stars/muhammedkayag/CVE-2025-32463.svg) ![forks](https://img.shields.io/github/forks/muhammedkayag/CVE-2025-32463.svg)


## CVE-2025-26625
 Git LFS is a Git extension for versioning large files. In Git LFS versions 0.5.2 through 3.7.0, when populating a Git repository's working tree with the contents of Git LFS objects, certain Git LFS commands may write to files visible outside the current Git working tree if symbolic or hard links exist which collide with the paths of files tracked by Git LFS. The git lfs checkout and git lfs pull commands do not check for symbolic links before writing to files in the working tree, allowing an attacker to craft a repository containing symbolic or hard links that cause Git LFS to write to arbitrary file system locations accessible to the user running these commands. As well, when the git lfs checkout and git lfs pull commands are run in a bare repository, they could write to files visible outside the repository. The vulnerability is fixed in version 3.7.1. As a workaround, support for symlinks in Git may be disabled by setting the core.symlinks configuration option to false, after which further clones and fetches will not create symbolic links. However, any symbolic or hard links in existing repositories will still provide the opportunity for Git LFS to write to their targets.

- [https://github.com/Mitchellzhou1/CVE_2025_26625](https://github.com/Mitchellzhou1/CVE_2025_26625) :  ![starts](https://img.shields.io/github/stars/Mitchellzhou1/CVE_2025_26625.svg) ![forks](https://img.shields.io/github/forks/Mitchellzhou1/CVE_2025_26625.svg)


## CVE-2025-24367
 Cacti is an open source performance and fault management framework. An authenticated Cacti user can abuse graph creation and graph template functionality to create arbitrary PHP scripts in the web root of the application, leading to remote code execution on the server. This vulnerability is fixed in 1.2.29.

- [https://github.com/TheCyberGeek/CVE-2025-24367-Cacti-PoC](https://github.com/TheCyberGeek/CVE-2025-24367-Cacti-PoC) :  ![starts](https://img.shields.io/github/stars/TheCyberGeek/CVE-2025-24367-Cacti-PoC.svg) ![forks](https://img.shields.io/github/forks/TheCyberGeek/CVE-2025-24367-Cacti-PoC.svg)


## CVE-2025-10035
 A deserialization vulnerability in the License Servlet of Fortra's GoAnywhere MFT allows an actor with a validly forged license response signature to deserialize an arbitrary actor-controlled object, possibly leading to command injection.

- [https://github.com/B1ack4sh/Blackash-CVE-2025-10035](https://github.com/B1ack4sh/Blackash-CVE-2025-10035) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-10035.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-10035.svg)


## CVE-2025-6440
 The WooCommerce Designer Pro plugin for WordPress, used by the Pricom - Printing Company & Design Services WordPress theme, is vulnerable to arbitrary file uploads due to missing file type validation in the 'wcdp_save_canvas_design_ajax' function in all versions up to, and including, 1.9.26. This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible.

- [https://github.com/Pwdnx1337/CVE-2025-6440](https://github.com/Pwdnx1337/CVE-2025-6440) :  ![starts](https://img.shields.io/github/stars/Pwdnx1337/CVE-2025-6440.svg) ![forks](https://img.shields.io/github/forks/Pwdnx1337/CVE-2025-6440.svg)


## CVE-2025-6050
 Mezzanine CMS, in versions prior to 6.1.1, contains a Stored Cross-Site Scripting (XSS) vulnerability in the admin interface. The vulnerability exists in the "displayable_links_js" function, which fails to properly sanitize blog post titles before including them in JSON responses served via "/admin/displayable_links.js". An authenticated admin user can create a blog post with a malicious JavaScript payload in the title field, then trick another admin user into clicking a direct link to the "/admin/displayable_links.js" endpoint, causing the malicious script to execute in their browser.

- [https://github.com/H4zaz/CVE-2025-60503](https://github.com/H4zaz/CVE-2025-60503) :  ![starts](https://img.shields.io/github/stars/H4zaz/CVE-2025-60503.svg) ![forks](https://img.shields.io/github/forks/H4zaz/CVE-2025-60503.svg)


## CVE-2024-48990
 Qualys discovered that needrestart, before version 3.8, allows local attackers to execute arbitrary code as root by tricking needrestart into running the Python interpreter with an attacker-controlled PYTHONPATH environment variable.

- [https://github.com/Mr-DJ/CVE-2024-48990](https://github.com/Mr-DJ/CVE-2024-48990) :  ![starts](https://img.shields.io/github/stars/Mr-DJ/CVE-2024-48990.svg) ![forks](https://img.shields.io/github/forks/Mr-DJ/CVE-2024-48990.svg)
- [https://github.com/Loaxert/CVE-2024-48990-PoC](https://github.com/Loaxert/CVE-2024-48990-PoC) :  ![starts](https://img.shields.io/github/stars/Loaxert/CVE-2024-48990-PoC.svg) ![forks](https://img.shields.io/github/forks/Loaxert/CVE-2024-48990-PoC.svg)


## CVE-2024-45496
 A flaw was found in OpenShift. This issue occurs due to the misuse of elevated privileges in the OpenShift Container Platform's build process. During the build initialization step, the git-clone container is run with a privileged security context, allowing unrestricted access to the node. An attacker with developer-level access can provide a crafted .gitconfig file containing commands executed during the cloning process, leading to arbitrary command execution on the worker node. An attacker running code in a privileged container could escalate their permissions on the node running the container.

- [https://github.com/fatcatresearch/cve-2024-45496](https://github.com/fatcatresearch/cve-2024-45496) :  ![starts](https://img.shields.io/github/stars/fatcatresearch/cve-2024-45496.svg) ![forks](https://img.shields.io/github/forks/fatcatresearch/cve-2024-45496.svg)


## CVE-2024-36991
 In Splunk Enterprise on Windows versions below 9.2.2, 9.1.5, and 9.0.10, an attacker could perform a path traversal on the /modules/messaging/ endpoint in Splunk Enterprise on Windows. This vulnerability should only affect Splunk Enterprise on Windows.

- [https://github.com/0xFZin/CVE-2024-36991](https://github.com/0xFZin/CVE-2024-36991) :  ![starts](https://img.shields.io/github/stars/0xFZin/CVE-2024-36991.svg) ![forks](https://img.shields.io/github/forks/0xFZin/CVE-2024-36991.svg)


## CVE-2024-35374
 Mocodo Mocodo Online 4.2.6 and below does not properly sanitize the sql_case input field in /web/generate.php, allowing remote attackers to execute arbitrary commands and potentially command injection, leading to remote code execution (RCE) under certain conditions.

- [https://github.com/Rikoot/CVE-2024-35374](https://github.com/Rikoot/CVE-2024-35374) :  ![starts](https://img.shields.io/github/stars/Rikoot/CVE-2024-35374.svg) ![forks](https://img.shields.io/github/forks/Rikoot/CVE-2024-35374.svg)


## CVE-2024-12084
 A heap-based buffer overflow flaw was found in the rsync daemon. This issue is due to improper handling of attacker-controlled checksum lengths (s2length) in the code. When MAX_DIGEST_LEN exceeds the fixed SUM_LENGTH (16 bytes), an attacker can write out of bounds in the sum2 buffer.

- [https://github.com/fatcatresearch/cve-2024-12084](https://github.com/fatcatresearch/cve-2024-12084) :  ![starts](https://img.shields.io/github/stars/fatcatresearch/cve-2024-12084.svg) ![forks](https://img.shields.io/github/forks/fatcatresearch/cve-2024-12084.svg)


## CVE-2024-7387
 A flaw was found in openshift/builder. This vulnerability allows command injection via path traversal, where a malicious user can execute arbitrary commands on the OpenShift node running the builder container. When using the “Docker” strategy, executable files inside the privileged build container can be overridden using the `spec.source.secrets.secret.destinationDir` attribute of the `BuildConfig` definition. An attacker running code in a privileged container could escalate their permissions on the node running the container.

- [https://github.com/fatcatresearch/cve-2024-7387](https://github.com/fatcatresearch/cve-2024-7387) :  ![starts](https://img.shields.io/github/stars/fatcatresearch/cve-2024-7387.svg) ![forks](https://img.shields.io/github/forks/fatcatresearch/cve-2024-7387.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/Mahfujurjust/CVE-2021-41773](https://github.com/Mahfujurjust/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/Mahfujurjust/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/Mahfujurjust/CVE-2021-41773.svg)


## CVE-2010-3863
 Apache Shiro before 1.1.0, and JSecurity 0.9.x, does not canonicalize URI paths before comparing them to entries in the shiro.ini file, which allows remote attackers to bypass intended access restrictions via a crafted request, as demonstrated by the /./account/index.jsp URI.

- [https://github.com/sh1inroot-alt/shiro-cve-2010-3863](https://github.com/sh1inroot-alt/shiro-cve-2010-3863) :  ![starts](https://img.shields.io/github/stars/sh1inroot-alt/shiro-cve-2010-3863.svg) ![forks](https://img.shields.io/github/forks/sh1inroot-alt/shiro-cve-2010-3863.svg)

