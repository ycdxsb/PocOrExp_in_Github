# Update 2022-03-09
## CVE-2022-25636
 net/netfilter/nf_dup_netdev.c in the Linux kernel 5.4 through 5.6.10 allows local users to gain privileges because of a heap out-of-bounds write. This is related to nf_tables_offload.

- [https://github.com/Bonfee/CVE-2022-25636](https://github.com/Bonfee/CVE-2022-25636) :  ![starts](https://img.shields.io/github/stars/Bonfee/CVE-2022-25636.svg) ![forks](https://img.shields.io/github/forks/Bonfee/CVE-2022-25636.svg)


## CVE-2022-25257
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/RobertDra/CVE-2022-25257](https://github.com/RobertDra/CVE-2022-25257) :  ![starts](https://img.shields.io/github/stars/RobertDra/CVE-2022-25257.svg) ![forks](https://img.shields.io/github/forks/RobertDra/CVE-2022-25257.svg)


## CVE-2022-25256
 SAS Web Report Studio 4.4 allows XSS. /SASWebReportStudio/logonAndRender.do has two parameters: saspfs_request_backlabel_list and saspfs_request_backurl_list. The first one affects the content of the button placed in the top left. The second affects the page to which the user is directed after pressing the button, e.g., a malicious web page. In addition, the second parameter executes JavaScript, which means XSS is possible by adding a javascript: URL.

- [https://github.com/RobertDra/CVE-2022-25256](https://github.com/RobertDra/CVE-2022-25256) :  ![starts](https://img.shields.io/github/stars/RobertDra/CVE-2022-25256.svg) ![forks](https://img.shields.io/github/forks/RobertDra/CVE-2022-25256.svg)


## CVE-2022-25064
 TP-LINK TL-WR840N(ES)_V6.20_180709 was discovered to contain a remote code execution (RCE) vulnerability via the function oal_wan6_setIpAddr.

- [https://github.com/exploitwritter/CVE-2022-25064](https://github.com/exploitwritter/CVE-2022-25064) :  ![starts](https://img.shields.io/github/stars/exploitwritter/CVE-2022-25064.svg) ![forks](https://img.shields.io/github/forks/exploitwritter/CVE-2022-25064.svg)


## CVE-2022-25063
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/exploitwritter/CVE-2022-25063](https://github.com/exploitwritter/CVE-2022-25063) :  ![starts](https://img.shields.io/github/stars/exploitwritter/CVE-2022-25063.svg) ![forks](https://img.shields.io/github/forks/exploitwritter/CVE-2022-25063.svg)


## CVE-2022-25062
 TP-LINK TL-WR840N(ES)_V6.20_180709 was discovered to contain an integer overflow via the function dm_checkString. This vulnerability allows attackers to cause a Denial of Service (DoS) via a crafted HTTP request.

- [https://github.com/exploitwritter/CVE-2022-25062](https://github.com/exploitwritter/CVE-2022-25062) :  ![starts](https://img.shields.io/github/stars/exploitwritter/CVE-2022-25062.svg) ![forks](https://img.shields.io/github/forks/exploitwritter/CVE-2022-25062.svg)


## CVE-2022-25061
 TP-LINK TL-WR840N(ES)_V6.20_180709 was discovered to contain a command injection vulnerability via the component oal_setIp6DefaultRoute.

- [https://github.com/exploitwritter/CVE-2022-25061](https://github.com/exploitwritter/CVE-2022-25061) :  ![starts](https://img.shields.io/github/stars/exploitwritter/CVE-2022-25061.svg) ![forks](https://img.shields.io/github/forks/exploitwritter/CVE-2022-25061.svg)


## CVE-2022-25060
 TP-LINK TL-WR840N(ES)_V6.20_180709 was discovered to contain a command injection vulnerability via the component oal_startPing.

- [https://github.com/exploitwritter/CVE-2022-25060](https://github.com/exploitwritter/CVE-2022-25060) :  ![starts](https://img.shields.io/github/stars/exploitwritter/CVE-2022-25060.svg) ![forks](https://img.shields.io/github/forks/exploitwritter/CVE-2022-25060.svg)


## CVE-2022-24990
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/Jaky5155/CVE-2022-24990-TerraMaster-TOS--PHP-](https://github.com/Jaky5155/CVE-2022-24990-TerraMaster-TOS--PHP-) :  ![starts](https://img.shields.io/github/stars/Jaky5155/CVE-2022-24990-TerraMaster-TOS--PHP-.svg) ![forks](https://img.shields.io/github/forks/Jaky5155/CVE-2022-24990-TerraMaster-TOS--PHP-.svg)


## CVE-2022-23940
 SuiteCRM through 7.12.1 and 8.x through 8.0.1 allows Remote Code Execution. Authenticated users with access to the Scheduled Reports module can achieve this by leveraging PHP deserialization in the email_recipients property. By using a crafted request, they can create a malicious report, containing a PHP-deserialization payload in the email_recipients field. Once someone accesses this report, the backend will deserialize the content of the email_recipients field and the payload gets executed. Project dependencies include a number of interesting PHP deserialization gadgets (e.g., Monolog/RCE1 from phpggc) that can be used for Code Execution.

- [https://github.com/manuelz120/CVE-2022-23940](https://github.com/manuelz120/CVE-2022-23940) :  ![starts](https://img.shields.io/github/stars/manuelz120/CVE-2022-23940.svg) ![forks](https://img.shields.io/github/forks/manuelz120/CVE-2022-23940.svg)


## CVE-2022-22947
 In spring cloud gateway versions prior to 3.1.1+ and 3.0.7+ , applications are vulnerable to a code injection attack when the Gateway Actuator endpoint is enabled, exposed and unsecured. A remote attacker could make a maliciously crafted request that could allow arbitrary remote execution on the remote host.

- [https://github.com/mrknow001/CVE-2022-22947](https://github.com/mrknow001/CVE-2022-22947) :  ![starts](https://img.shields.io/github/stars/mrknow001/CVE-2022-22947.svg) ![forks](https://img.shields.io/github/forks/mrknow001/CVE-2022-22947.svg)
- [https://github.com/YutuSec/SpEL](https://github.com/YutuSec/SpEL) :  ![starts](https://img.shields.io/github/stars/YutuSec/SpEL.svg) ![forks](https://img.shields.io/github/forks/YutuSec/SpEL.svg)
- [https://github.com/darkb1rd/cve-2022-22947](https://github.com/darkb1rd/cve-2022-22947) :  ![starts](https://img.shields.io/github/stars/darkb1rd/cve-2022-22947.svg) ![forks](https://img.shields.io/github/forks/darkb1rd/cve-2022-22947.svg)
- [https://github.com/j-jasson/CVE-2022-22947-Spring-Cloud-Gateway-SpelRCE](https://github.com/j-jasson/CVE-2022-22947-Spring-Cloud-Gateway-SpelRCE) :  ![starts](https://img.shields.io/github/stars/j-jasson/CVE-2022-22947-Spring-Cloud-Gateway-SpelRCE.svg) ![forks](https://img.shields.io/github/forks/j-jasson/CVE-2022-22947-Spring-Cloud-Gateway-SpelRCE.svg)
- [https://github.com/Jun-5heng/CVE-2022-22947](https://github.com/Jun-5heng/CVE-2022-22947) :  ![starts](https://img.shields.io/github/stars/Jun-5heng/CVE-2022-22947.svg) ![forks](https://img.shields.io/github/forks/Jun-5heng/CVE-2022-22947.svg)


## CVE-2022-21907
 HTTP Protocol Stack Remote Code Execution Vulnerability.

- [https://github.com/mauricelambert/CVE-2021-31166](https://github.com/mauricelambert/CVE-2021-31166) :  ![starts](https://img.shields.io/github/stars/mauricelambert/CVE-2021-31166.svg) ![forks](https://img.shields.io/github/forks/mauricelambert/CVE-2021-31166.svg)


## CVE-2022-0847
 A flaw was found in the way the &quot;flags&quot; member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system. This flaw affects Linux kernel versions prior to 5.17-rc6.

- [https://github.com/Al1ex/LinuxEelvation](https://github.com/Al1ex/LinuxEelvation) :  ![starts](https://img.shields.io/github/stars/Al1ex/LinuxEelvation.svg) ![forks](https://img.shields.io/github/forks/Al1ex/LinuxEelvation.svg)
- [https://github.com/Arinerron/CVE-2022-0847-DirtyPipe-Exploit](https://github.com/Arinerron/CVE-2022-0847-DirtyPipe-Exploit) :  ![starts](https://img.shields.io/github/stars/Arinerron/CVE-2022-0847-DirtyPipe-Exploit.svg) ![forks](https://img.shields.io/github/forks/Arinerron/CVE-2022-0847-DirtyPipe-Exploit.svg)
- [https://github.com/bbaranoff/CVE-2022-0847](https://github.com/bbaranoff/CVE-2022-0847) :  ![starts](https://img.shields.io/github/stars/bbaranoff/CVE-2022-0847.svg) ![forks](https://img.shields.io/github/forks/bbaranoff/CVE-2022-0847.svg)
- [https://github.com/imfiver/CVE-2022-0847](https://github.com/imfiver/CVE-2022-0847) :  ![starts](https://img.shields.io/github/stars/imfiver/CVE-2022-0847.svg) ![forks](https://img.shields.io/github/forks/imfiver/CVE-2022-0847.svg)
- [https://github.com/Udyz/CVE-2022-0847](https://github.com/Udyz/CVE-2022-0847) :  ![starts](https://img.shields.io/github/stars/Udyz/CVE-2022-0847.svg) ![forks](https://img.shields.io/github/forks/Udyz/CVE-2022-0847.svg)
- [https://github.com/carlosevieira/Dirty-Pipe](https://github.com/carlosevieira/Dirty-Pipe) :  ![starts](https://img.shields.io/github/stars/carlosevieira/Dirty-Pipe.svg) ![forks](https://img.shields.io/github/forks/carlosevieira/Dirty-Pipe.svg)
- [https://github.com/xndpxs/CVE-2022-0847](https://github.com/xndpxs/CVE-2022-0847) :  ![starts](https://img.shields.io/github/stars/xndpxs/CVE-2022-0847.svg) ![forks](https://img.shields.io/github/forks/xndpxs/CVE-2022-0847.svg)
- [https://github.com/2xYuan/CVE-2022-0847](https://github.com/2xYuan/CVE-2022-0847) :  ![starts](https://img.shields.io/github/stars/2xYuan/CVE-2022-0847.svg) ![forks](https://img.shields.io/github/forks/2xYuan/CVE-2022-0847.svg)
- [https://github.com/lucksec/CVE-2022-0847](https://github.com/lucksec/CVE-2022-0847) :  ![starts](https://img.shields.io/github/stars/lucksec/CVE-2022-0847.svg) ![forks](https://img.shields.io/github/forks/lucksec/CVE-2022-0847.svg)
- [https://github.com/rahul1406/cve-2022-0847dirtypipe-exploit](https://github.com/rahul1406/cve-2022-0847dirtypipe-exploit) :  ![starts](https://img.shields.io/github/stars/rahul1406/cve-2022-0847dirtypipe-exploit.svg) ![forks](https://img.shields.io/github/forks/rahul1406/cve-2022-0847dirtypipe-exploit.svg)


## CVE-2022-0492
 A vulnerability was found in the Linux kernel&#8217;s cgroup_release_agent_write in the kernel/cgroup/cgroup-v1.c function. This flaw, under certain circumstances, allows the use of the cgroups v1 release_agent feature to escalate privileges and bypass the namespace isolation unexpectedly.

- [https://github.com/puckiestyle/CVE-2022-0492](https://github.com/puckiestyle/CVE-2022-0492) :  ![starts](https://img.shields.io/github/stars/puckiestyle/CVE-2022-0492.svg) ![forks](https://img.shields.io/github/forks/puckiestyle/CVE-2022-0492.svg)


## CVE-2021-44132
 A command injection vulnerability in the function formImportOMCIShell of C-DATA ONU4FERW V2.1.13_X139 allows attackers to execute arbitrary commands via a crafted file.

- [https://github.com/exploitwritter/CVE-2021-44132](https://github.com/exploitwritter/CVE-2021-44132) :  ![starts](https://img.shields.io/github/stars/exploitwritter/CVE-2021-44132.svg) ![forks](https://img.shields.io/github/forks/exploitwritter/CVE-2021-44132.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/byteofandri/CVE-2021-41773](https://github.com/byteofandri/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/byteofandri/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/byteofandri/CVE-2021-41773.svg)


## CVE-2021-40870
 An issue was discovered in Aviatrix Controller 6.x before 6.5-1804.1922. Unrestricted upload of a file with a dangerous type is possible, which allows an unauthenticated user to execute arbitrary code via directory traversal.

- [https://github.com/byteofandri/CVE-2021-40870](https://github.com/byteofandri/CVE-2021-40870) :  ![starts](https://img.shields.io/github/stars/byteofandri/CVE-2021-40870.svg) ![forks](https://img.shields.io/github/forks/byteofandri/CVE-2021-40870.svg)


## CVE-2021-38314
 The Gutenberg Template Library &amp; Redux Framework plugin &lt;= 4.2.11 for WordPress registered several AJAX actions available to unauthenticated users in the `includes` function in `redux-core/class-redux-core.php` that were unique to a given site but deterministic and predictable given that they were based on an md5 hash of the site URL with a known salt value of '-redux' and an md5 hash of the previous hash with a known salt value of '-support'. These AJAX actions could be used to retrieve a list of active plugins and their versions, the site's PHP version, and an unsalted md5 hash of site&#8217;s `AUTH_KEY` concatenated with the `SECURE_AUTH_KEY`.

- [https://github.com/byteofandri/CVE-2021-38314](https://github.com/byteofandri/CVE-2021-38314) :  ![starts](https://img.shields.io/github/stars/byteofandri/CVE-2021-38314.svg) ![forks](https://img.shields.io/github/forks/byteofandri/CVE-2021-38314.svg)


## CVE-2021-31166
 HTTP Protocol Stack Remote Code Execution Vulnerability

- [https://github.com/mauricelambert/CVE-2021-31166](https://github.com/mauricelambert/CVE-2021-31166) :  ![starts](https://img.shields.io/github/stars/mauricelambert/CVE-2021-31166.svg) ![forks](https://img.shields.io/github/forks/mauricelambert/CVE-2021-31166.svg)


## CVE-2021-30573
 Use after free in GPU in Google Chrome prior to 92.0.4515.107 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

- [https://github.com/byteofandri/CVE-2021-30573](https://github.com/byteofandri/CVE-2021-30573) :  ![starts](https://img.shields.io/github/stars/byteofandri/CVE-2021-30573.svg) ![forks](https://img.shields.io/github/forks/byteofandri/CVE-2021-30573.svg)


## CVE-2021-27651
 In versions 8.2.1 through 8.5.2 of Pega Infinity, the password reset functionality for local accounts can be used to bypass local authentication checks.

- [https://github.com/byteofandri/CVE-2021-27651](https://github.com/byteofandri/CVE-2021-27651) :  ![starts](https://img.shields.io/github/stars/byteofandri/CVE-2021-27651.svg) ![forks](https://img.shields.io/github/forks/byteofandri/CVE-2021-27651.svg)


## CVE-2021-26084
 In affected versions of Confluence Server and Data Center, an OGNL injection vulnerability exists that would allow an unauthenticated attacker to execute arbitrary code on a Confluence Server or Data Center instance. The affected versions are before version 6.13.23, from version 6.14.0 before 7.4.11, from version 7.5.0 before 7.11.6, and from version 7.12.0 before 7.12.5.

- [https://github.com/byteofandri/CVE-2021-26084](https://github.com/byteofandri/CVE-2021-26084) :  ![starts](https://img.shields.io/github/stars/byteofandri/CVE-2021-26084.svg) ![forks](https://img.shields.io/github/forks/byteofandri/CVE-2021-26084.svg)


## CVE-2021-22893
 Pulse Connect Secure 9.0R3/9.1R1 and higher is vulnerable to an authentication bypass vulnerability exposed by the Windows File Share Browser and Pulse Secure Collaboration features of Pulse Connect Secure that can allow an unauthenticated user to perform remote arbitrary code execution on the Pulse Connect Secure gateway. This vulnerability has been exploited in the wild.

- [https://github.com/byteofandri/CVE-2021-22893](https://github.com/byteofandri/CVE-2021-22893) :  ![starts](https://img.shields.io/github/stars/byteofandri/CVE-2021-22893.svg) ![forks](https://img.shields.io/github/forks/byteofandri/CVE-2021-22893.svg)


## CVE-2021-21972
 The vSphere Client (HTML5) contains a remote code execution vulnerability in a vCenter Server plugin. A malicious actor with network access to port 443 may exploit this issue to execute commands with unrestricted privileges on the underlying operating system that hosts vCenter Server. This affects VMware vCenter Server (7.x before 7.0 U1c, 6.7 before 6.7 U3l and 6.5 before 6.5 U3n) and VMware Cloud Foundation (4.x before 4.2 and 3.x before 3.10.1.2).

- [https://github.com/byteofandri/CVE-2021-21972](https://github.com/byteofandri/CVE-2021-21972) :  ![starts](https://img.shields.io/github/stars/byteofandri/CVE-2021-21972.svg) ![forks](https://img.shields.io/github/forks/byteofandri/CVE-2021-21972.svg)


## CVE-2021-20837
 Movable Type 7 r.5002 and earlier (Movable Type 7 Series), Movable Type 6.8.2 and earlier (Movable Type 6 Series), Movable Type Advanced 7 r.5002 and earlier (Movable Type Advanced 7 Series), Movable Type Advanced 6.8.2 and earlier (Movable Type Advanced 6 Series), Movable Type Premium 1.46 and earlier, and Movable Type Premium Advanced 1.46 and earlier allow remote attackers to execute arbitrary OS commands via unspecified vectors. Note that all versions of Movable Type 4.0 or later including unsupported (End-of-Life, EOL) versions are also affected by this vulnerability.

- [https://github.com/byteofandri/CVE-2021-20837](https://github.com/byteofandri/CVE-2021-20837) :  ![starts](https://img.shields.io/github/stars/byteofandri/CVE-2021-20837.svg) ![forks](https://img.shields.io/github/forks/byteofandri/CVE-2021-20837.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/aus-mate/CVE-2021-4034-POC](https://github.com/aus-mate/CVE-2021-4034-POC) :  ![starts](https://img.shields.io/github/stars/aus-mate/CVE-2021-4034-POC.svg) ![forks](https://img.shields.io/github/forks/aus-mate/CVE-2021-4034-POC.svg)
- [https://github.com/pengalaman-1t/CVE-2021-4034](https://github.com/pengalaman-1t/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/pengalaman-1t/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/pengalaman-1t/CVE-2021-4034.svg)
- [https://github.com/JoyGhoshs/CVE-2021-4034](https://github.com/JoyGhoshs/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/JoyGhoshs/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/JoyGhoshs/CVE-2021-4034.svg)


## CVE-2021-3019
 ffay lanproxy 0.1 allows Directory Traversal to read /../conf/config.properties to obtain credentials for a connection to the intranet.

- [https://github.com/0xf4n9x/CVE-2021-3019](https://github.com/0xf4n9x/CVE-2021-3019) :  ![starts](https://img.shields.io/github/stars/0xf4n9x/CVE-2021-3019.svg) ![forks](https://img.shields.io/github/forks/0xf4n9x/CVE-2021-3019.svg)


## CVE-2020-0796
 A remote code execution vulnerability exists in the way that the Microsoft Server Message Block 3.1.1 (SMBv3) protocol handles certain requests, aka 'Windows SMBv3 Client/Server Remote Code Execution Vulnerability'.

- [https://github.com/byteofandri/CVE-2020-0796](https://github.com/byteofandri/CVE-2020-0796) :  ![starts](https://img.shields.io/github/stars/byteofandri/CVE-2020-0796.svg) ![forks](https://img.shields.io/github/forks/byteofandri/CVE-2020-0796.svg)


## CVE-2019-15858
 admin/includes/class.import.snippet.php in the &quot;Woody ad snippets&quot; plugin before 2.2.5 for WordPress allows unauthenticated options import, as demonstrated by storing an XSS payload for remote code execution.

- [https://github.com/byteofandri/CVE-2019-15858](https://github.com/byteofandri/CVE-2019-15858) :  ![starts](https://img.shields.io/github/stars/byteofandri/CVE-2019-15858.svg) ![forks](https://img.shields.io/github/forks/byteofandri/CVE-2019-15858.svg)


## CVE-2019-11933
 A heap buffer overflow bug in libpl_droidsonroids_gif before 1.2.19, as used in WhatsApp for Android before version 2.19.291 could allow remote attackers to execute arbitrary code or cause a denial of service.

- [https://github.com/NatleoJ/CVE-2019-11933](https://github.com/NatleoJ/CVE-2019-11933) :  ![starts](https://img.shields.io/github/stars/NatleoJ/CVE-2019-11933.svg) ![forks](https://img.shields.io/github/forks/NatleoJ/CVE-2019-11933.svg)


## CVE-2018-15961
 Adobe ColdFusion versions July 12 release (2018.0.0.310739), Update 6 and earlier, and Update 14 and earlier have an unrestricted file upload vulnerability. Successful exploitation could lead to arbitrary code execution.

- [https://github.com/byteofandri/CVE-2018-15961](https://github.com/byteofandri/CVE-2018-15961) :  ![starts](https://img.shields.io/github/stars/byteofandri/CVE-2018-15961.svg) ![forks](https://img.shields.io/github/forks/byteofandri/CVE-2018-15961.svg)


## CVE-2016-5195
 Race condition in mm/gup.c in the Linux kernel 2.x through 4.x before 4.8.3 allows local users to gain privileges by leveraging incorrect handling of a copy-on-write (COW) feature to write to a read-only memory mapping, as exploited in the wild in October 2016, aka &quot;Dirty COW.&quot;

- [https://github.com/imfiver/CVE-2022-0847](https://github.com/imfiver/CVE-2022-0847) :  ![starts](https://img.shields.io/github/stars/imfiver/CVE-2022-0847.svg) ![forks](https://img.shields.io/github/forks/imfiver/CVE-2022-0847.svg)

