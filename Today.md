# Update 2023-05-25
## CVE-2023-32784
 In KeePass 2.x before 2.54, it is possible to recover the cleartext master password from a memory dump, even when a workspace is locked or no longer running. The memory dump can be a KeePass process dump, swap file (pagefile.sys), hibernation file (hiberfil.sys), or RAM dump of the entire system. The first character cannot be recovered. In 2.54, there is different API usage and/or random string insertion for mitigation.

- [https://github.com/LeDocteurDesBits/cve-2023-32784](https://github.com/LeDocteurDesBits/cve-2023-32784) :  ![starts](https://img.shields.io/github/stars/LeDocteurDesBits/cve-2023-32784.svg) ![forks](https://img.shields.io/github/forks/LeDocteurDesBits/cve-2023-32784.svg)


## CVE-2023-32243
 Improper Authentication vulnerability in WPDeveloper Essential Addons for Elementor allows Privilege Escalation. This issue affects Essential Addons for Elementor: from 5.4.0 through 5.7.1.

- [https://github.com/domainhigh/Mass-CVE-2023-32243](https://github.com/domainhigh/Mass-CVE-2023-32243) :  ![starts](https://img.shields.io/github/stars/domainhigh/Mass-CVE-2023-32243.svg) ![forks](https://img.shields.io/github/forks/domainhigh/Mass-CVE-2023-32243.svg)
- [https://github.com/manavvedawala/CVE-2023-32243-POC](https://github.com/manavvedawala/CVE-2023-32243-POC) :  ![starts](https://img.shields.io/github/stars/manavvedawala/CVE-2023-32243-POC.svg) ![forks](https://img.shields.io/github/forks/manavvedawala/CVE-2023-32243-POC.svg)
- [https://github.com/manavvedawala/CVE-2023-32243-proof-of-concept](https://github.com/manavvedawala/CVE-2023-32243-proof-of-concept) :  ![starts](https://img.shields.io/github/stars/manavvedawala/CVE-2023-32243-proof-of-concept.svg) ![forks](https://img.shields.io/github/forks/manavvedawala/CVE-2023-32243-proof-of-concept.svg)


## CVE-2023-31779
 Wekan v6.84 and earlier is vulnerable to Cross Site Scripting (XSS). An attacker with user privilege on kanban board can insert JavaScript code in in &quot;Reaction to comment&quot; feature.

- [https://github.com/jet-pentest/CVE-2023-31779](https://github.com/jet-pentest/CVE-2023-31779) :  ![starts](https://img.shields.io/github/stars/jet-pentest/CVE-2023-31779.svg) ![forks](https://img.shields.io/github/forks/jet-pentest/CVE-2023-31779.svg)


## CVE-2023-31595
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/Yozarseef95/CVE-2023-31595](https://github.com/Yozarseef95/CVE-2023-31595) :  ![starts](https://img.shields.io/github/stars/Yozarseef95/CVE-2023-31595.svg) ![forks](https://img.shields.io/github/forks/Yozarseef95/CVE-2023-31595.svg)


## CVE-2023-31594
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/Yozarseef95/CVE-2023-31594](https://github.com/Yozarseef95/CVE-2023-31594) :  ![starts](https://img.shields.io/github/stars/Yozarseef95/CVE-2023-31594.svg) ![forks](https://img.shields.io/github/forks/Yozarseef95/CVE-2023-31594.svg)


## CVE-2023-29923
 PowerJob V4.3.1 is vulnerable to Insecure Permissions. via the list job interface.

- [https://github.com/1820112015/CVE-2023-29923](https://github.com/1820112015/CVE-2023-29923) :  ![starts](https://img.shields.io/github/stars/1820112015/CVE-2023-29923.svg) ![forks](https://img.shields.io/github/forks/1820112015/CVE-2023-29923.svg)


## CVE-2023-29922
 PowerJob V4.3.1 is vulnerable to Incorrect Access Control via the create user/save interface.

- [https://github.com/1820112015/CVE-2023-29923](https://github.com/1820112015/CVE-2023-29923) :  ![starts](https://img.shields.io/github/stars/1820112015/CVE-2023-29923.svg) ![forks](https://img.shields.io/github/forks/1820112015/CVE-2023-29923.svg)


## CVE-2023-24055
 ** DISPUTED ** KeePass through 2.53 (in a default installation) allows an attacker, who has write access to the XML configuration file, to obtain the cleartext passwords by adding an export trigger. NOTE: the vendor's position is that the password database is not intended to be secure against an attacker who has that level of access to the local PC.

- [https://github.com/ATTACKnDEFEND/CVE-2023-24055](https://github.com/ATTACKnDEFEND/CVE-2023-24055) :  ![starts](https://img.shields.io/github/stars/ATTACKnDEFEND/CVE-2023-24055.svg) ![forks](https://img.shields.io/github/forks/ATTACKnDEFEND/CVE-2023-24055.svg)


## CVE-2022-42889
 Apache Commons Text performs variable interpolation, allowing properties to be dynamically evaluated and expanded. The standard format for interpolation is &quot;${prefix:name}&quot;, where &quot;prefix&quot; is used to locate an instance of org.apache.commons.text.lookup.StringLookup that performs the interpolation. Starting with version 1.5 and continuing through 1.9, the set of default Lookup instances included interpolators that could result in arbitrary code execution or contact with remote servers. These lookups are: - &quot;script&quot; - execute expressions using the JVM script execution engine (javax.script) - &quot;dns&quot; - resolve dns records - &quot;url&quot; - load values from urls, including from remote servers Applications using the interpolation defaults in the affected versions may be vulnerable to remote code execution or unintentional contact with remote servers if untrusted configuration values are used. Users are recommended to upgrade to Apache Commons Text 1.10.0, which disables the problematic interpolators by default.

- [https://github.com/aaronm-sysdig/text4shell-docker](https://github.com/aaronm-sysdig/text4shell-docker) :  ![starts](https://img.shields.io/github/stars/aaronm-sysdig/text4shell-docker.svg) ![forks](https://img.shields.io/github/forks/aaronm-sysdig/text4shell-docker.svg)


## CVE-2022-22947
 In spring cloud gateway versions prior to 3.1.1+ and 3.0.7+ , applications are vulnerable to a code injection attack when the Gateway Actuator endpoint is enabled, exposed and unsecured. A remote attacker could make a maliciously crafted request that could allow arbitrary remote execution on the remote host.

- [https://github.com/al4xs/CVE-2022-22947-Spring-Cloud](https://github.com/al4xs/CVE-2022-22947-Spring-Cloud) :  ![starts](https://img.shields.io/github/stars/al4xs/CVE-2022-22947-Spring-Cloud.svg) ![forks](https://img.shields.io/github/forks/al4xs/CVE-2022-22947-Spring-Cloud.svg)


## CVE-2022-0847
 A flaw was found in the way the &quot;flags&quot; member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/al4xs/CVE-2022-0847-Dirty-Pipe](https://github.com/al4xs/CVE-2022-0847-Dirty-Pipe) :  ![starts](https://img.shields.io/github/stars/al4xs/CVE-2022-0847-Dirty-Pipe.svg) ![forks](https://img.shields.io/github/forks/al4xs/CVE-2022-0847-Dirty-Pipe.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/MatanelGordon/docker-cve-2021-41773](https://github.com/MatanelGordon/docker-cve-2021-41773) :  ![starts](https://img.shields.io/github/stars/MatanelGordon/docker-cve-2021-41773.svg) ![forks](https://img.shields.io/github/forks/MatanelGordon/docker-cve-2021-41773.svg)


## CVE-2021-3560
 It was found that polkit could be tricked into bypassing the credential checks for D-Bus requests, elevating the privileges of the requestor to the root user. This flaw could be used by an unprivileged local attacker to, for example, create a new local administrator. The highest threat from this vulnerability is to data confidentiality and integrity as well as system availability.

- [https://github.com/iSTAR-Lab/CVE-2021-3560_PoC](https://github.com/iSTAR-Lab/CVE-2021-3560_PoC) :  ![starts](https://img.shields.io/github/stars/iSTAR-Lab/CVE-2021-3560_PoC.svg) ![forks](https://img.shields.io/github/forks/iSTAR-Lab/CVE-2021-3560_PoC.svg)


## CVE-2021-3129
 Ignition before 2.5.2, as used in Laravel and other products, allows unauthenticated remote attackers to execute arbitrary code because of insecure usage of file_get_contents() and file_put_contents(). This is exploitable on sites using debug mode with Laravel before 8.4.2.

- [https://github.com/knqyf263/CVE-2021-3129](https://github.com/knqyf263/CVE-2021-3129) :  ![starts](https://img.shields.io/github/stars/knqyf263/CVE-2021-3129.svg) ![forks](https://img.shields.io/github/forks/knqyf263/CVE-2021-3129.svg)


## CVE-2020-9547
 FasterXML jackson-databind 2.x before 2.9.10.4 mishandles the interaction between serialization gadgets and typing, related to com.ibatis.sqlmap.engine.transaction.jta.JtaTransactionConfig (aka ibatis-sqlmap).

- [https://github.com/fairyming/CVE-2020-9547](https://github.com/fairyming/CVE-2020-9547) :  ![starts](https://img.shields.io/github/stars/fairyming/CVE-2020-9547.svg) ![forks](https://img.shields.io/github/forks/fairyming/CVE-2020-9547.svg)


## CVE-2020-1066
 An elevation of privilege vulnerability exists in .NET Framework which could allow an attacker to elevate their privilege level.To exploit the vulnerability, an attacker would first have to access the local machine, and then run a malicious program.The update addresses the vulnerability by correcting how .NET Framework activates COM objects., aka '.NET Framework Elevation of Privilege Vulnerability'.

- [https://github.com/Al1ex/WindowsElevation](https://github.com/Al1ex/WindowsElevation) :  ![starts](https://img.shields.io/github/stars/Al1ex/WindowsElevation.svg) ![forks](https://img.shields.io/github/forks/Al1ex/WindowsElevation.svg)


## CVE-2019-19492
 FreeSWITCH 1.6.10 through 1.10.1 has a default password in event_socket.conf.xml.

- [https://github.com/Chocapikk/CVE-2019-19492](https://github.com/Chocapikk/CVE-2019-19492) :  ![starts](https://img.shields.io/github/stars/Chocapikk/CVE-2019-19492.svg) ![forks](https://img.shields.io/github/forks/Chocapikk/CVE-2019-19492.svg)
- [https://github.com/tucommenceapousser/CVE-2019-19492-2](https://github.com/tucommenceapousser/CVE-2019-19492-2) :  ![starts](https://img.shields.io/github/stars/tucommenceapousser/CVE-2019-19492-2.svg) ![forks](https://img.shields.io/github/forks/tucommenceapousser/CVE-2019-19492-2.svg)
- [https://github.com/tucommenceapousser/CVE-2019-19492](https://github.com/tucommenceapousser/CVE-2019-19492) :  ![starts](https://img.shields.io/github/stars/tucommenceapousser/CVE-2019-19492.svg) ![forks](https://img.shields.io/github/forks/tucommenceapousser/CVE-2019-19492.svg)


## CVE-2019-9053
 An issue was discovered in CMS Made Simple 2.2.8. It is possible with the News module, through a crafted URL, to achieve unauthenticated blind time-based SQL injection via the m1_idlist parameter.

- [https://github.com/AppyAppy/super-octo-carnival](https://github.com/AppyAppy/super-octo-carnival) :  ![starts](https://img.shields.io/github/stars/AppyAppy/super-octo-carnival.svg) ![forks](https://img.shields.io/github/forks/AppyAppy/super-octo-carnival.svg)

