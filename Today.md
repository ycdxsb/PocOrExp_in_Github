# Update 2023-06-11
## CVE-2023-34960
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/Aituglo/CVE-2023-34960](https://github.com/Aituglo/CVE-2023-34960) :  ![starts](https://img.shields.io/github/stars/Aituglo/CVE-2023-34960.svg) ![forks](https://img.shields.io/github/forks/Aituglo/CVE-2023-34960.svg)


## CVE-2023-29336
 Win32k Elevation of Privilege Vulnerability

- [https://github.com/m-cetin/CVE-2023-29336](https://github.com/m-cetin/CVE-2023-29336) :  ![starts](https://img.shields.io/github/stars/m-cetin/CVE-2023-29336.svg) ![forks](https://img.shields.io/github/forks/m-cetin/CVE-2023-29336.svg)


## CVE-2023-3163
 A vulnerability was found in y_project RuoYi up to 4.7.7. It has been classified as problematic. Affected is the function filterKeyword. The manipulation of the argument value leads to resource consumption. VDB-231090 is the identifier assigned to this vulnerability.

- [https://github.com/George0Papasotiriou/CVE-2023-3163-SQL-Injection-Prevention](https://github.com/George0Papasotiriou/CVE-2023-3163-SQL-Injection-Prevention) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2023-3163-SQL-Injection-Prevention.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2023-3163-SQL-Injection-Prevention.svg)


## CVE-2023-2986
 The Abandoned Cart Lite for WooCommerce plugin for WordPress is vulnerable to authentication bypass in versions up to, and including, 5.14.2. This is due to insufficient encryption on the user being supplied during the abandoned cart link decode through the plugin. This allows unauthenticated attackers to log in as users who have abandoned the cart, which users are typically customers.

- [https://github.com/Ayantaker/CVE-2023-2986](https://github.com/Ayantaker/CVE-2023-2986) :  ![starts](https://img.shields.io/github/stars/Ayantaker/CVE-2023-2986.svg) ![forks](https://img.shields.io/github/forks/Ayantaker/CVE-2023-2986.svg)


## CVE-2023-2868
 A remote command injection vulnerability exists in the Barracuda Email Security Gateway (appliance form factor only) product effecting versions 5.1.3.001-9.2.0.006. The vulnerability arises out of a failure to comprehensively sanitize the processing of .tar file (tape archives). The vulnerability stems from incomplete input validation of a user-supplied .tar file as it pertains to the names of the files contained within the archive. As a consequence, a remote attacker can specifically format these file names in a particular manner that will result in remotely executing a system command through Perl's qx operator with the privileges of the Email Security Gateway product. This issue was fixed as part of BNSF-36456 patch. This patch was automatically applied to all customer appliances.

- [https://github.com/hheeyywweellccoommee/CVE-2023-2868-lchvp](https://github.com/hheeyywweellccoommee/CVE-2023-2868-lchvp) :  ![starts](https://img.shields.io/github/stars/hheeyywweellccoommee/CVE-2023-2868-lchvp.svg) ![forks](https://img.shields.io/github/forks/hheeyywweellccoommee/CVE-2023-2868-lchvp.svg)


## CVE-2023-0630
 The Slimstat Analytics WordPress plugin before 4.9.3.3 does not prevent subscribers from rendering shortcodes that concatenates attributes directly into an SQL query.

- [https://github.com/RandomRobbieBF/CVE-2023-0630](https://github.com/RandomRobbieBF/CVE-2023-0630) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2023-0630.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2023-0630.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/mightysai1997/cve-2021-41773](https://github.com/mightysai1997/cve-2021-41773) :  ![starts](https://img.shields.io/github/stars/mightysai1997/cve-2021-41773.svg) ![forks](https://img.shields.io/github/forks/mightysai1997/cve-2021-41773.svg)


## CVE-2021-4104
 JMSAppender in Log4j 1.2 is vulnerable to deserialization of untrusted data when the attacker has write access to the Log4j configuration. The attacker can provide TopicBindingName and TopicConnectionFactoryBindingName configurations causing JMSAppender to perform JNDI requests that result in remote code execution in a similar fashion to CVE-2021-44228. Note this issue only affects Log4j 1.2 when specifically configured to use JMSAppender, which is not the default. Apache Log4j 1.2 reached end of life in August 2015. Users should upgrade to Log4j 2 as it addresses numerous other issues from the previous versions.

- [https://github.com/HynekPetrak/log4shell-finder](https://github.com/HynekPetrak/log4shell-finder) :  ![starts](https://img.shields.io/github/stars/HynekPetrak/log4shell-finder.svg) ![forks](https://img.shields.io/github/forks/HynekPetrak/log4shell-finder.svg)


## CVE-2019-1096
 An information disclosure vulnerability exists when the win32k component improperly provides kernel information, aka 'Win32k Information Disclosure Vulnerability'.

- [https://github.com/CrackerCat/cve-2019-1096-poc](https://github.com/CrackerCat/cve-2019-1096-poc) :  ![starts](https://img.shields.io/github/stars/CrackerCat/cve-2019-1096-poc.svg) ![forks](https://img.shields.io/github/forks/CrackerCat/cve-2019-1096-poc.svg)


## CVE-2018-19052
 An issue was discovered in mod_alias_physical_handler in mod_alias.c in lighttpd before 1.4.50. There is potential ../ path traversal of a single directory above an alias target, with a specific mod_alias configuration where the matched alias lacks a trailing '/' character, but the alias target filesystem path does have a trailing '/' character.

- [https://github.com/iveresk/cve-2018-19052](https://github.com/iveresk/cve-2018-19052) :  ![starts](https://img.shields.io/github/stars/iveresk/cve-2018-19052.svg) ![forks](https://img.shields.io/github/forks/iveresk/cve-2018-19052.svg)


## CVE-2018-8004
 There are multiple HTTP smuggling and cache poisoning issues when clients making malicious requests interact with Apache Traffic Server (ATS). This affects versions 6.0.0 to 6.2.2 and 7.0.0 to 7.1.3. To resolve this issue users running 6.x should upgrade to 6.2.3 or later versions and 7.x users should upgrade to 7.1.4 or later versions.

- [https://github.com/mosesrenegade/CVE-2018-8004](https://github.com/mosesrenegade/CVE-2018-8004) :  ![starts](https://img.shields.io/github/stars/mosesrenegade/CVE-2018-8004.svg) ![forks](https://img.shields.io/github/forks/mosesrenegade/CVE-2018-8004.svg)


## CVE-2012-4869
 The callme_startcall function in recordings/misc/callme_page.php in FreePBX 2.9, 2.10, and earlier allows remote attackers to execute arbitrary commands via the callmenum parameter in a c action.

- [https://github.com/AndyCyberSec/OSCP](https://github.com/AndyCyberSec/OSCP) :  ![starts](https://img.shields.io/github/stars/AndyCyberSec/OSCP.svg) ![forks](https://img.shields.io/github/forks/AndyCyberSec/OSCP.svg)

