# Update 2022-03-26
## CVE-2022-25636
 net/netfilter/nf_dup_netdev.c in the Linux kernel 5.4 through 5.6.10 allows local users to gain privileges because of a heap out-of-bounds write. This is related to nf_tables_offload.

- [https://github.com/chenaotian/CVE-2022-25636](https://github.com/chenaotian/CVE-2022-25636) :  ![starts](https://img.shields.io/github/stars/chenaotian/CVE-2022-25636.svg) ![forks](https://img.shields.io/github/forks/chenaotian/CVE-2022-25636.svg)


## CVE-2022-22947
 In spring cloud gateway versions prior to 3.1.1+ and 3.0.7+ , applications are vulnerable to a code injection attack when the Gateway Actuator endpoint is enabled, exposed and unsecured. A remote attacker could make a maliciously crafted request that could allow arbitrary remote execution on the remote host.

- [https://github.com/Enokiy/cve-2022-22947-spring-cloud-gateway](https://github.com/Enokiy/cve-2022-22947-spring-cloud-gateway) :  ![starts](https://img.shields.io/github/stars/Enokiy/cve-2022-22947-spring-cloud-gateway.svg) ![forks](https://img.shields.io/github/forks/Enokiy/cve-2022-22947-spring-cloud-gateway.svg)


## CVE-2022-0185
 A heap-based buffer overflow flaw was found in the way the legacy_parse_param function in the Filesystem Context functionality of the Linux kernel verified the supplied parameters length. An unprivileged (in case of unprivileged user namespaces enabled, otherwise needs namespaced CAP_SYS_ADMIN privilege) local user able to open a filesystem that does not support the Filesystem Context API (and thus fallbacks to legacy handling) could use this flaw to escalate their privileges on the system.

- [https://github.com/chenaotian/CVE-2022-25636](https://github.com/chenaotian/CVE-2022-25636) :  ![starts](https://img.shields.io/github/stars/chenaotian/CVE-2022-25636.svg) ![forks](https://img.shields.io/github/forks/chenaotian/CVE-2022-25636.svg)


## CVE-2021-42671
 An incorrect access control vulnerability exists in Sourcecodester Engineers Online Portal in PHP in nia_munoz_monitoring_system/admin/uploads. An attacker can leverage this vulnerability in order to bypass access controls and access all the files uploaded to the web server without the need of authentication or authorization.

- [https://github.com/0xDeku/CVE-2021-42671](https://github.com/0xDeku/CVE-2021-42671) :  ![starts](https://img.shields.io/github/stars/0xDeku/CVE-2021-42671.svg) ![forks](https://img.shields.io/github/forks/0xDeku/CVE-2021-42671.svg)


## CVE-2021-42670
 A SQL injection vulnerability exists in Sourcecodester Engineers Online Portal in PHP via the id parameter to the announcements_student.php web page. As a result a malicious user can extract sensitive data from the web server and in some cases use this vulnerability in order to get a remote code execution on the remote web server.

- [https://github.com/0xDeku/CVE-2021-42670](https://github.com/0xDeku/CVE-2021-42670) :  ![starts](https://img.shields.io/github/stars/0xDeku/CVE-2021-42670.svg) ![forks](https://img.shields.io/github/forks/0xDeku/CVE-2021-42670.svg)


## CVE-2021-42669
 A file upload vulnerability exists in Sourcecodester Engineers Online Portal in PHP via dashboard_teacher.php, which allows changing the avatar through teacher_avatar.php. Once an avatar gets uploaded it is getting uploaded to the /admin/uploads/ directory, and is accessible by all users. By uploading a php webshell containing &quot;&lt;?php system($_GET[&quot;cmd&quot;]); ?&gt;&quot; the attacker can execute commands on the web server with - /admin/uploads/php-webshell?cmd=id.

- [https://github.com/0xDeku/CVE-2021-42669](https://github.com/0xDeku/CVE-2021-42669) :  ![starts](https://img.shields.io/github/stars/0xDeku/CVE-2021-42669.svg) ![forks](https://img.shields.io/github/forks/0xDeku/CVE-2021-42669.svg)


## CVE-2021-42668
 A SQL Injection vulnerability exists in Sourcecodester Engineers Online Portal in PHP via the id parameter in the my_classmates.php web page.. As a result, an attacker can extract sensitive data from the web server and in some cases can use this vulnerability in order to get a remote code execution on the remote web server.

- [https://github.com/0xDeku/CVE-2021-42668](https://github.com/0xDeku/CVE-2021-42668) :  ![starts](https://img.shields.io/github/stars/0xDeku/CVE-2021-42668.svg) ![forks](https://img.shields.io/github/forks/0xDeku/CVE-2021-42668.svg)


## CVE-2021-42667
 A SQL Injection vulnerability exists in Sourcecodester Online Event Booking and Reservation System in PHP in event-management/views. An attacker can leverage this vulnerability in order to manipulate the sql query performed. As a result he can extract sensitive data from the web server and in some cases he can use this vulnerability in order to get a remote code execution on the remote web server.

- [https://github.com/0xDeku/CVE-2021-42667](https://github.com/0xDeku/CVE-2021-42667) :  ![starts](https://img.shields.io/github/stars/0xDeku/CVE-2021-42667.svg) ![forks](https://img.shields.io/github/forks/0xDeku/CVE-2021-42667.svg)


## CVE-2021-42666
 A SQL Injection vulnerability exists in Sourcecodester Engineers Online Portal in PHP via the id parameter to quiz_question.php, which could let a malicious user extract sensitive data from the web server and in some cases use this vulnerability in order to get a remote code execution on the remote web server.

- [https://github.com/0xDeku/CVE-2021-42666](https://github.com/0xDeku/CVE-2021-42666) :  ![starts](https://img.shields.io/github/stars/0xDeku/CVE-2021-42666.svg) ![forks](https://img.shields.io/github/forks/0xDeku/CVE-2021-42666.svg)


## CVE-2021-42665
 An SQL Injection vulnerability exists in Sourcecodester Engineers Online Portal in PHP via the login form inside of index.php, which can allow an attacker to bypass authentication.

- [https://github.com/0xDeku/CVE-2021-42665](https://github.com/0xDeku/CVE-2021-42665) :  ![starts](https://img.shields.io/github/stars/0xDeku/CVE-2021-42665.svg) ![forks](https://img.shields.io/github/forks/0xDeku/CVE-2021-42665.svg)


## CVE-2021-42664
 A Stored Cross Site Scripting (XSS) Vulneraibiilty exists in Sourcecodester Engineers Online Portal in PHP via the (1) Quiz title and (2) quiz description parameters to add_quiz.php. An attacker can leverage this vulnerability in order to run javascript commands on the web server surfers behalf, which can lead to cookie stealing and more.

- [https://github.com/0xDeku/CVE-2021-42664](https://github.com/0xDeku/CVE-2021-42664) :  ![starts](https://img.shields.io/github/stars/0xDeku/CVE-2021-42664.svg) ![forks](https://img.shields.io/github/forks/0xDeku/CVE-2021-42664.svg)


## CVE-2021-42663
 An HTML injection vulnerability exists in Sourcecodester Online Event Booking and Reservation System in PHP/MySQL via the msg parameter to /event-management/index.php. An attacker can leverage this vulnerability in order to change the visibility of the website. Once the target user clicks on a given link he will display the content of the HTML code of the attacker's choice.

- [https://github.com/0xDeku/CVE-2021-42663](https://github.com/0xDeku/CVE-2021-42663) :  ![starts](https://img.shields.io/github/stars/0xDeku/CVE-2021-42663.svg) ![forks](https://img.shields.io/github/forks/0xDeku/CVE-2021-42663.svg)


## CVE-2021-42662
 A Stored Cross Site Scripting (XSS) vulnerability exists in Sourcecodester Online Event Booking and Reservation System in PHP/MySQL via the Holiday reason parameter. An attacker can leverage this vulnerability in order to run javascript commands on the web server surfers behalf, which can lead to cookie stealing and more.

- [https://github.com/0xDeku/CVE-2021-42662](https://github.com/0xDeku/CVE-2021-42662) :  ![starts](https://img.shields.io/github/stars/0xDeku/CVE-2021-42662.svg) ![forks](https://img.shields.io/github/forks/0xDeku/CVE-2021-42662.svg)


## CVE-2021-21300
 Git is an open-source distributed revision control system. In affected versions of Git a specially crafted repository that contains symbolic links as well as files using a clean/smudge filter such as Git LFS, may cause just-checked out script to be executed while cloning onto a case-insensitive file system such as NTFS, HFS+ or APFS (i.e. the default file systems on Windows and macOS). Note that clean/smudge filters have to be configured for that. Git for Windows configures Git LFS by default, and is therefore vulnerable. The problem has been patched in the versions published on Tuesday, March 9th, 2021. As a workaound, if symbolic link support is disabled in Git (e.g. via `git config --global core.symlinks false`), the described attack won't work. Likewise, if no clean/smudge filters such as Git LFS are configured globally (i.e. _before_ cloning), the attack is foiled. As always, it is best to avoid cloning repositories from untrusted sources. The earliest impacted version is 2.14.2. The fix versions are: 2.30.1, 2.29.3, 2.28.1, 2.27.1, 2.26.3, 2.25.5, 2.24.4, 2.23.4, 2.22.5, 2.21.4, 2.20.5, 2.19.6, 2.18.5, 2.17.62.17.6.

- [https://github.com/Jiang59991/cve-2021-21300-plus](https://github.com/Jiang59991/cve-2021-21300-plus) :  ![starts](https://img.shields.io/github/stars/Jiang59991/cve-2021-21300-plus.svg) ![forks](https://img.shields.io/github/forks/Jiang59991/cve-2021-21300-plus.svg)


## CVE-2018-20250
 In WinRAR versions prior to and including 5.61, There is path traversal vulnerability when crafting the filename field of the ACE format (in UNACEV2.dll). When the filename field is manipulated with specific patterns, the destination (extraction) folder is ignored, thus treating the filename as an absolute path.

- [https://github.com/tzwlhack/CVE-2018-20250](https://github.com/tzwlhack/CVE-2018-20250) :  ![starts](https://img.shields.io/github/stars/tzwlhack/CVE-2018-20250.svg) ![forks](https://img.shields.io/github/forks/tzwlhack/CVE-2018-20250.svg)


## CVE-2018-12326
 Buffer overflow in redis-cli of Redis before 4.0.10 and 5.x before 5.0 RC3 allows an attacker to achieve code execution and escalate to higher privileges via a crafted command line. NOTE: It is unclear whether there are any common situations in which redis-cli is used with, for example, a -h (aka hostname) argument from an untrusted source.

- [https://github.com/spasm5/CVE-2018-12326](https://github.com/spasm5/CVE-2018-12326) :  ![starts](https://img.shields.io/github/stars/spasm5/CVE-2018-12326.svg) ![forks](https://img.shields.io/github/forks/spasm5/CVE-2018-12326.svg)


## CVE-2017-3248
 Vulnerability in the Oracle WebLogic Server component of Oracle Fusion Middleware (subcomponent: Core Components). Supported versions that are affected are 10.3.6.0, 12.1.3.0, 12.2.1.0 and 12.2.1.1. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3 to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS v3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts).

- [https://github.com/0xn0ne/weblogicScanner](https://github.com/0xn0ne/weblogicScanner) :  ![starts](https://img.shields.io/github/stars/0xn0ne/weblogicScanner.svg) ![forks](https://img.shields.io/github/forks/0xn0ne/weblogicScanner.svg)

