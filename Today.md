# Update 2023-08-29
## CVE-2023-38831
 RARLabs WinRAR before 6.23 allows attackers to execute arbitrary code when a user attempts to view a benign file within a ZIP archive. The issue occurs because a ZIP archive may include a benign file (such as an ordinary .JPG file) and also a folder that has the same name as the benign file, and the contents of the folder (which may include executable content) are processed during an attempt to access only the benign file. This was exploited in the wild in April through August 2023.

- [https://github.com/Garck3h/cve-2023-38831](https://github.com/Garck3h/cve-2023-38831) :  ![starts](https://img.shields.io/github/stars/Garck3h/cve-2023-38831.svg) ![forks](https://img.shields.io/github/forks/Garck3h/cve-2023-38831.svg)
- [https://github.com/HDCE-inc/CVE-2023-38831](https://github.com/HDCE-inc/CVE-2023-38831) :  ![starts](https://img.shields.io/github/stars/HDCE-inc/CVE-2023-38831.svg) ![forks](https://img.shields.io/github/forks/HDCE-inc/CVE-2023-38831.svg)
- [https://github.com/ignis-sec/CVE-2023-38831-RaRCE](https://github.com/ignis-sec/CVE-2023-38831-RaRCE) :  ![starts](https://img.shields.io/github/stars/ignis-sec/CVE-2023-38831-RaRCE.svg) ![forks](https://img.shields.io/github/forks/ignis-sec/CVE-2023-38831-RaRCE.svg)
- [https://github.com/IR-HuntGuardians/CVE-2023-38831-HUNT](https://github.com/IR-HuntGuardians/CVE-2023-38831-HUNT) :  ![starts](https://img.shields.io/github/stars/IR-HuntGuardians/CVE-2023-38831-HUNT.svg) ![forks](https://img.shields.io/github/forks/IR-HuntGuardians/CVE-2023-38831-HUNT.svg)


## CVE-2023-24489
 A vulnerability has been discovered in the customer-managed ShareFile storage zones controller which, if exploited, could allow an unauthenticated attacker to remotely compromise the customer-managed ShareFile storage zones controller.

- [https://github.com/whalebone7/CVE-2023-24489-poc](https://github.com/whalebone7/CVE-2023-24489-poc) :  ![starts](https://img.shields.io/github/stars/whalebone7/CVE-2023-24489-poc.svg) ![forks](https://img.shields.io/github/forks/whalebone7/CVE-2023-24489-poc.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/mightysai1997/cve-2021-41773](https://github.com/mightysai1997/cve-2021-41773) :  ![starts](https://img.shields.io/github/stars/mightysai1997/cve-2021-41773.svg) ![forks](https://img.shields.io/github/forks/mightysai1997/cve-2021-41773.svg)


## CVE-2021-26084
 In affected versions of Confluence Server and Data Center, an OGNL injection vulnerability exists that would allow an unauthenticated attacker to execute arbitrary code on a Confluence Server or Data Center instance. The affected versions are before version 6.13.23, from version 6.14.0 before 7.4.11, from version 7.5.0 before 7.11.6, and from version 7.12.0 before 7.12.5.

- [https://github.com/kkin77/CVE-2021-26084-Confluence-OGNL](https://github.com/kkin77/CVE-2021-26084-Confluence-OGNL) :  ![starts](https://img.shields.io/github/stars/kkin77/CVE-2021-26084-Confluence-OGNL.svg) ![forks](https://img.shields.io/github/forks/kkin77/CVE-2021-26084-Confluence-OGNL.svg)


## CVE-2019-2025
 In binder_thread_read of binder.c, there is a possible use-after-free due to improper locking. This could lead to local escalation of privilege in the kernel with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-116855682References: Upstream kernel

- [https://github.com/jltxgcy/CVE_2019_2025_EXP](https://github.com/jltxgcy/CVE_2019_2025_EXP) :  ![starts](https://img.shields.io/github/stars/jltxgcy/CVE_2019_2025_EXP.svg) ![forks](https://img.shields.io/github/forks/jltxgcy/CVE_2019_2025_EXP.svg)


## CVE-2017-9841
 Util/PHP/eval-stdin.php in PHPUnit before 4.8.28 and 5.x before 5.6.3 allows remote attackers to execute arbitrary PHP code via HTTP POST data beginning with a &quot;&lt;?php &quot; substring, as demonstrated by an attack on a site with an exposed /vendor folder, i.e., external access to the /vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php URI.

- [https://github.com/Chocapikk/CVE-2017-9841](https://github.com/Chocapikk/CVE-2017-9841) :  ![starts](https://img.shields.io/github/stars/Chocapikk/CVE-2017-9841.svg) ![forks](https://img.shields.io/github/forks/Chocapikk/CVE-2017-9841.svg)

