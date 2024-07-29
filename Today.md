# Update 2024-07-29
## CVE-2024-38355
 Socket.IO is an open source, real-time, bidirectional, event-based, communication framework. A specially crafted Socket.IO packet can trigger an uncaught exception on the Socket.IO server, thus killing the Node.js process. This issue is fixed by commit `15af22fc22` which has been included in `socket.io@4.6.2` (released in May 2023). The fix was backported in the 2.x branch as well with commit `d30630ba10`. Users are advised to upgrade. Users unable to upgrade may attach a listener for the &quot;error&quot; event to catch these errors.

- [https://github.com/Y0ursTruly/socketio-cve](https://github.com/Y0ursTruly/socketio-cve) :  ![starts](https://img.shields.io/github/stars/Y0ursTruly/socketio-cve.svg) ![forks](https://img.shields.io/github/forks/Y0ursTruly/socketio-cve.svg)


## CVE-2024-34693
 Improper Input Validation vulnerability in Apache Superset, allows for an authenticated attacker to create a MariaDB connection with local_infile enabled. If both the MariaDB server (off by default) and the local mysql client on the web server are set to allow for local infile, it's possible for the attacker to execute a specific MySQL/MariaDB SQL command that is able to read files from the server and insert their content on a MariaDB database table.This issue affects Apache Superset: before 3.1.3 and version 4.0.0 Users are recommended to upgrade to version 4.0.1 or 3.1.3, which fixes the issue.

- [https://github.com/mbadanoiu/CVE-2024-34693](https://github.com/mbadanoiu/CVE-2024-34693) :  ![starts](https://img.shields.io/github/stars/mbadanoiu/CVE-2024-34693.svg) ![forks](https://img.shields.io/github/forks/mbadanoiu/CVE-2024-34693.svg)


## CVE-2024-32002
 Git is a revision control system. Prior to versions 2.45.1, 2.44.1, 2.43.4, 2.42.2, 2.41.1, 2.40.2, and 2.39.4, repositories with submodules can be crafted in a way that exploits a bug in Git whereby it can be fooled into writing files not into the submodule's worktree but into a `.git/` directory. This allows writing a hook that will be executed while the clone operation is still running, giving the user no opportunity to inspect the code that is being executed. The problem has been patched in versions 2.45.1, 2.44.1, 2.43.4, 2.42.2, 2.41.1, 2.40.2, and 2.39.4. If symbolic link support is disabled in Git (e.g. via `git config --global core.symlinks false`), the described attack won't work. As always, it is best to avoid cloning repositories from untrusted sources.

- [https://github.com/blackninja23/CVE-2024-32002](https://github.com/blackninja23/CVE-2024-32002) :  ![starts](https://img.shields.io/github/stars/blackninja23/CVE-2024-32002.svg) ![forks](https://img.shields.io/github/forks/blackninja23/CVE-2024-32002.svg)


## CVE-2024-30088
 Windows Kernel Elevation of Privilege Vulnerability

- [https://github.com/Admin9961/CVE-2024-30088](https://github.com/Admin9961/CVE-2024-30088) :  ![starts](https://img.shields.io/github/stars/Admin9961/CVE-2024-30088.svg) ![forks](https://img.shields.io/github/forks/Admin9961/CVE-2024-30088.svg)


## CVE-2024-24590
 Deserialization of untrusted data can occur in versions 0.17.0 to 1.14.2 of the client SDK of Allegro AI&#8217;s ClearML platform, enabling a maliciously uploaded artifact to run arbitrary code on an end user&#8217;s system when interacted with.

- [https://github.com/sviim/ClearML-CVE-2024-24590-RCE](https://github.com/sviim/ClearML-CVE-2024-24590-RCE) :  ![starts](https://img.shields.io/github/stars/sviim/ClearML-CVE-2024-24590-RCE.svg) ![forks](https://img.shields.io/github/forks/sviim/ClearML-CVE-2024-24590-RCE.svg)


## CVE-2024-20666
 BitLocker Security Feature Bypass Vulnerability

- [https://github.com/HYZ3K/CVE-2024-20666](https://github.com/HYZ3K/CVE-2024-20666) :  ![starts](https://img.shields.io/github/stars/HYZ3K/CVE-2024-20666.svg) ![forks](https://img.shields.io/github/forks/HYZ3K/CVE-2024-20666.svg)


## CVE-2024-4164
 A vulnerability, which was classified as critical, has been found in Tenda G3 15.11.0.17(9502). This issue affects the function formModifyPppAuthWhiteMac of the file /goform/ModifyPppAuthWhiteMac. The manipulation of the argument pppoeServerWhiteMacIndex leads to stack-based buffer overflow. The attack may be initiated remotely. The exploit has been disclosed to the public and may be used. The associated identifier of this vulnerability is VDB-261983. NOTE: The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/alemusix/CVE-2024-41640](https://github.com/alemusix/CVE-2024-41640) :  ![starts](https://img.shields.io/github/stars/alemusix/CVE-2024-41640.svg) ![forks](https://img.shields.io/github/forks/alemusix/CVE-2024-41640.svg)


## CVE-2023-41892
 Craft CMS is a platform for creating digital experiences. This is a high-impact, low-complexity attack vector. Users running Craft installations before 4.4.15 are encouraged to update to at least that version to mitigate the issue. This issue has been fixed in Craft CMS 4.4.15.

- [https://github.com/CERTologists/HTTP-Request-for-PHP-object-injection-attack-on-CVE-2023-41892](https://github.com/CERTologists/HTTP-Request-for-PHP-object-injection-attack-on-CVE-2023-41892) :  ![starts](https://img.shields.io/github/stars/CERTologists/HTTP-Request-for-PHP-object-injection-attack-on-CVE-2023-41892.svg) ![forks](https://img.shields.io/github/forks/CERTologists/HTTP-Request-for-PHP-object-injection-attack-on-CVE-2023-41892.svg)


## CVE-2023-6553
 The Backup Migration plugin for WordPress is vulnerable to Remote Code Execution in all versions up to, and including, 1.3.7 via the /includes/backup-heart.php file. This is due to an attacker being able to control the values passed to an include, and subsequently leverage that to achieve remote code execution. This makes it possible for unauthenticated attackers to easily execute code on the server.

- [https://github.com/cc3305/CVE-2023-6553](https://github.com/cc3305/CVE-2023-6553) :  ![starts](https://img.shields.io/github/stars/cc3305/CVE-2023-6553.svg) ![forks](https://img.shields.io/github/forks/cc3305/CVE-2023-6553.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/TheKernelPanic/exploit-apache2-cve-2021-41773](https://github.com/TheKernelPanic/exploit-apache2-cve-2021-41773) :  ![starts](https://img.shields.io/github/stars/TheKernelPanic/exploit-apache2-cve-2021-41773.svg) ![forks](https://img.shields.io/github/forks/TheKernelPanic/exploit-apache2-cve-2021-41773.svg)


## CVE-2010-0219
 Apache Axis2, as used in dswsbobje.war in SAP BusinessObjects Enterprise XI 3.2, CA ARCserve D2D r15, and other products, has a default password of axis2 for the admin account, which makes it easier for remote attackers to execute arbitrary code by uploading a crafted web service.

- [https://github.com/veritas-rt/CVE-2010-0219](https://github.com/veritas-rt/CVE-2010-0219) :  ![starts](https://img.shields.io/github/stars/veritas-rt/CVE-2010-0219.svg) ![forks](https://img.shields.io/github/forks/veritas-rt/CVE-2010-0219.svg)


## CVE-2003-0282
 Directory traversal vulnerability in UnZip 5.50 allows attackers to overwrite arbitrary files via invalid characters between two . (dot) characters, which are filtered and result in a &quot;..&quot; sequence.

- [https://github.com/silasol/cve-2003-0282](https://github.com/silasol/cve-2003-0282) :  ![starts](https://img.shields.io/github/stars/silasol/cve-2003-0282.svg) ![forks](https://img.shields.io/github/forks/silasol/cve-2003-0282.svg)

