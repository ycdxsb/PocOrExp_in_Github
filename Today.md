# Update 2021-10-24
## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/BabyTeam1024/CVE-2021-41773](https://github.com/BabyTeam1024/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/BabyTeam1024/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/BabyTeam1024/CVE-2021-41773.svg)


## CVE-2021-35215
 Insecure deserialization leading to Remote Code Execution was detected in the Orion Platform version 2020.2.5. Authentication is required to exploit this vulnerability.

- [https://github.com/Y4er/CVE-2021-35215](https://github.com/Y4er/CVE-2021-35215) :  ![starts](https://img.shields.io/github/stars/Y4er/CVE-2021-35215.svg) ![forks](https://img.shields.io/github/forks/Y4er/CVE-2021-35215.svg)


## CVE-2021-2471
 Vulnerability in the MySQL Connectors product of Oracle MySQL (component: Connector/J). Supported versions that are affected are 8.0.26 and prior. Difficult to exploit vulnerability allows high privileged attacker with network access via multiple protocols to compromise MySQL Connectors. Successful attacks of this vulnerability can result in unauthorized access to critical data or complete access to all MySQL Connectors accessible data and unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of MySQL Connectors. CVSS 3.1 Base Score 5.9 (Confidentiality and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:N/A:H).

- [https://github.com/SecCoder-Security-Lab/jdbc-sqlxml-xxe](https://github.com/SecCoder-Security-Lab/jdbc-sqlxml-xxe) :  ![starts](https://img.shields.io/github/stars/SecCoder-Security-Lab/jdbc-sqlxml-xxe.svg) ![forks](https://img.shields.io/github/forks/SecCoder-Security-Lab/jdbc-sqlxml-xxe.svg)
- [https://github.com/DrunkenShells/CVE-2021-2471](https://github.com/DrunkenShells/CVE-2021-2471) :  ![starts](https://img.shields.io/github/stars/DrunkenShells/CVE-2021-2471.svg) ![forks](https://img.shields.io/github/forks/DrunkenShells/CVE-2021-2471.svg)
- [https://github.com/cckuailong/CVE-2021-2471](https://github.com/cckuailong/CVE-2021-2471) :  ![starts](https://img.shields.io/github/stars/cckuailong/CVE-2021-2471.svg) ![forks](https://img.shields.io/github/forks/cckuailong/CVE-2021-2471.svg)


## CVE-2020-25213
 The File Manager (wp-file-manager) plugin before 6.9 for WordPress allows remote attackers to upload and execute arbitrary PHP code because it renames an unsafe example elFinder connector file to have the .php extension. This, for example, allows attackers to run the elFinder upload (or mkfile and put) command to write PHP code into the wp-content/plugins/wp-file-manager/lib/files/ directory. This was exploited in the wild in August and September 2020.

- [https://github.com/0000000O0Oo/Wordpress-CVE-2020-25213](https://github.com/0000000O0Oo/Wordpress-CVE-2020-25213) :  ![starts](https://img.shields.io/github/stars/0000000O0Oo/Wordpress-CVE-2020-25213.svg) ![forks](https://img.shields.io/github/forks/0000000O0Oo/Wordpress-CVE-2020-25213.svg)


## CVE-2019-19609
 The Strapi framework before 3.0.0-beta.17.8 is vulnerable to Remote Code Execution in the Install and Uninstall Plugin components of the Admin panel, because it does not sanitize the plugin name, and attackers can inject arbitrary shell commands to be executed by the execa function.

- [https://github.com/z9fr/CVE-2019-19609](https://github.com/z9fr/CVE-2019-19609) :  ![starts](https://img.shields.io/github/stars/z9fr/CVE-2019-19609.svg) ![forks](https://img.shields.io/github/forks/z9fr/CVE-2019-19609.svg)


## CVE-2018-1123
 procps-ng before version 3.3.15 is vulnerable to a denial of service in ps via mmap buffer overflow. Inbuilt protection in ps maps a guard page at the end of the overflowed buffer, ensuring that the impact of this flaw is limited to a crash (temporary denial of service).

- [https://github.com/aravinddathd/CVE-2018-1123](https://github.com/aravinddathd/CVE-2018-1123) :  ![starts](https://img.shields.io/github/stars/aravinddathd/CVE-2018-1123.svg) ![forks](https://img.shields.io/github/forks/aravinddathd/CVE-2018-1123.svg)

