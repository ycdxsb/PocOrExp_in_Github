# Update 2021-12-28
## CVE-2021-45105
 Apache Log4j2 versions 2.0-alpha1 through 2.16.0 (excluding 2.12.3) did not protect from uncontrolled recursion from self-referential lookups. This allows an attacker with control over Thread Context Map data to cause a denial of service when a crafted string is interpreted. This issue was fixed in Log4j 2.17.0 and 2.12.3.

- [https://github.com/pfichtner/log4shell-hunter](https://github.com/pfichtner/log4shell-hunter) :  ![starts](https://img.shields.io/github/stars/pfichtner/log4shell-hunter.svg) ![forks](https://img.shields.io/github/forks/pfichtner/log4shell-hunter.svg)


## CVE-2021-45046
 It was found that the fix to address CVE-2021-44228 in Apache Log4j 2.15.0 was incomplete in certain non-default configurations. This could allows attackers with control over Thread Context Map (MDC) input data when the logging configuration uses a non-default Pattern Layout with either a Context Lookup (for example, $${ctx:loginId}) or a Thread Context Map pattern (%X, %mdc, or %MDC) to craft malicious input data using a JNDI Lookup pattern resulting in an information leak and remote code execution in some environments and local code execution in all environments. Log4j 2.16.0 (Java 8) and 2.12.2 (Java 7) fix this issue by removing support for message lookup patterns and disabling JNDI functionality by default.

- [https://github.com/pfichtner/log4shell-hunter](https://github.com/pfichtner/log4shell-hunter) :  ![starts](https://img.shields.io/github/stars/pfichtner/log4shell-hunter.svg) ![forks](https://img.shields.io/github/forks/pfichtner/log4shell-hunter.svg)


## CVE-2021-43821
 Opencast is an Open Source Lecture Capture &amp; Video Management for Education. Opencast before version 9.10 or 10.6 allows references to local file URLs in ingested media packages, allowing attackers to include local files from Opencast's host machines and making them available via the web interface. Before Opencast 9.10 and 10.6, Opencast would open and include local files during ingests. Attackers could exploit this to include most local files the process has read access to, extracting secrets from the host machine. An attacker would need to have the privileges required to add new media to exploit this. But these are often widely given. The issue has been fixed in Opencast 10.6 and 11.0. You can mitigate this issue by narrowing down the read access Opencast has to files on the file system using UNIX permissions or mandatory access control systems like SELinux. This cannot prevent access to files Opencast needs to read though and we highly recommend updating.

- [https://github.com/Jackey0/opencast-CVE-2021-43821-env](https://github.com/Jackey0/opencast-CVE-2021-43821-env) :  ![starts](https://img.shields.io/github/stars/Jackey0/opencast-CVE-2021-43821-env.svg) ![forks](https://img.shields.io/github/forks/Jackey0/opencast-CVE-2021-43821-env.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/K1p2y3/CVE-2021-41773](https://github.com/K1p2y3/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/K1p2y3/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/K1p2y3/CVE-2021-41773.svg)
- [https://github.com/Ming119/CVE-2021-41773_Exploit](https://github.com/Ming119/CVE-2021-41773_Exploit) :  ![starts](https://img.shields.io/github/stars/Ming119/CVE-2021-41773_Exploit.svg) ![forks](https://img.shields.io/github/forks/Ming119/CVE-2021-41773_Exploit.svg)


## CVE-2019-19609
 The Strapi framework before 3.0.0-beta.17.8 is vulnerable to Remote Code Execution in the Install and Uninstall Plugin components of the Admin panel, because it does not sanitize the plugin name, and attackers can inject arbitrary shell commands to be executed by the execa function.

- [https://github.com/Invertebr4do/strapiRCE](https://github.com/Invertebr4do/strapiRCE) :  ![starts](https://img.shields.io/github/stars/Invertebr4do/strapiRCE.svg) ![forks](https://img.shields.io/github/forks/Invertebr4do/strapiRCE.svg)


## CVE-2019-18818
 strapi before 3.0.0-beta.17.5 mishandles password resets within packages/strapi-admin/controllers/Auth.js and packages/strapi-plugin-users-permissions/controllers/Auth.js.

- [https://github.com/Invertebr4do/strapiRCE](https://github.com/Invertebr4do/strapiRCE) :  ![starts](https://img.shields.io/github/stars/Invertebr4do/strapiRCE.svg) ![forks](https://img.shields.io/github/forks/Invertebr4do/strapiRCE.svg)


## CVE-2017-5487
 wp-includes/rest-api/endpoints/class-wp-rest-users-controller.php in the REST API implementation in WordPress 4.7 before 4.7.1 does not properly restrict listings of post authors, which allows remote attackers to obtain sensitive information via a wp-json/wp/v2/users request.

- [https://github.com/patilkr/wp-CVE-2017-5487-exploit](https://github.com/patilkr/wp-CVE-2017-5487-exploit) :  ![starts](https://img.shields.io/github/stars/patilkr/wp-CVE-2017-5487-exploit.svg) ![forks](https://img.shields.io/github/forks/patilkr/wp-CVE-2017-5487-exploit.svg)

