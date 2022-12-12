# Update 2022-12-12
## CVE-2022-42889
 Apache Commons Text performs variable interpolation, allowing properties to be dynamically evaluated and expanded. The standard format for interpolation is &quot;${prefix:name}&quot;, where &quot;prefix&quot; is used to locate an instance of org.apache.commons.text.lookup.StringLookup that performs the interpolation. Starting with version 1.5 and continuing through 1.9, the set of default Lookup instances included interpolators that could result in arbitrary code execution or contact with remote servers. These lookups are: - &quot;script&quot; - execute expressions using the JVM script execution engine (javax.script) - &quot;dns&quot; - resolve dns records - &quot;url&quot; - load values from urls, including from remote servers Applications using the interpolation defaults in the affected versions may be vulnerable to remote code execution or unintentional contact with remote servers if untrusted configuration values are used. Users are recommended to upgrade to Apache Commons Text 1.10.0, which disables the problematic interpolators by default.

- [https://github.com/gokul-ramesh/text4shell-exploit](https://github.com/gokul-ramesh/text4shell-exploit) :  ![starts](https://img.shields.io/github/stars/gokul-ramesh/text4shell-exploit.svg) ![forks](https://img.shields.io/github/forks/gokul-ramesh/text4shell-exploit.svg)


## CVE-2022-41082
 Microsoft Exchange Server Remote Code Execution Vulnerability.

- [https://github.com/PyterSmithDarkGhost/ZERODAYENCADEAMENTOCVE2022-41040-CVE2022-41082](https://github.com/PyterSmithDarkGhost/ZERODAYENCADEAMENTOCVE2022-41040-CVE2022-41082) :  ![starts](https://img.shields.io/github/stars/PyterSmithDarkGhost/ZERODAYENCADEAMENTOCVE2022-41040-CVE2022-41082.svg) ![forks](https://img.shields.io/github/forks/PyterSmithDarkGhost/ZERODAYENCADEAMENTOCVE2022-41040-CVE2022-41082.svg)


## CVE-2022-22818
 The {% debug %} template tag in Django 2.2 before 2.2.27, 3.2 before 3.2.12, and 4.0 before 4.0.2 does not properly encode the current context. This may lead to XSS.

- [https://github.com/Prikalel/django-xss-example](https://github.com/Prikalel/django-xss-example) :  ![starts](https://img.shields.io/github/stars/Prikalel/django-xss-example.svg) ![forks](https://img.shields.io/github/forks/Prikalel/django-xss-example.svg)


## CVE-2022-0848
 OS Command Injection in GitHub repository part-db/part-db prior to 0.5.11.

- [https://github.com/Lay0us1/CVE-2022-0848-RCE](https://github.com/Lay0us1/CVE-2022-0848-RCE) :  ![starts](https://img.shields.io/github/stars/Lay0us1/CVE-2022-0848-RCE.svg) ![forks](https://img.shields.io/github/forks/Lay0us1/CVE-2022-0848-RCE.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/wolf1892/CVE-2021-41773](https://github.com/wolf1892/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/wolf1892/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/wolf1892/CVE-2021-41773.svg)
- [https://github.com/honypot/CVE-2021-41773](https://github.com/honypot/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/honypot/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/honypot/CVE-2021-41773.svg)
- [https://github.com/hab1b0x/CVE-2021-41773](https://github.com/hab1b0x/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/hab1b0x/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/hab1b0x/CVE-2021-41773.svg)


## CVE-2017-9841
 Util/PHP/eval-stdin.php in PHPUnit before 4.8.28 and 5.x before 5.6.3 allows remote attackers to execute arbitrary PHP code via HTTP POST data beginning with a &quot;&lt;?php &quot; substring, as demonstrated by an attack on a site with an exposed /vendor folder, i.e., external access to the /vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php URI.

- [https://github.com/incogbyte/laravel-phpunit-rce-masscaner](https://github.com/incogbyte/laravel-phpunit-rce-masscaner) :  ![starts](https://img.shields.io/github/stars/incogbyte/laravel-phpunit-rce-masscaner.svg) ![forks](https://img.shields.io/github/forks/incogbyte/laravel-phpunit-rce-masscaner.svg)


## CVE-2007-4559
 Directory traversal vulnerability in the (1) extract and (2) extractall functions in the tarfile module in Python allows user-assisted remote attackers to overwrite arbitrary files via a .. (dot dot) sequence in filenames in a TAR archive, a related issue to CVE-2001-1267.

- [https://github.com/Ooscaar/MALW](https://github.com/Ooscaar/MALW) :  ![starts](https://img.shields.io/github/stars/Ooscaar/MALW.svg) ![forks](https://img.shields.io/github/forks/Ooscaar/MALW.svg)

