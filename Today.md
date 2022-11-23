# Update 2022-11-23
## CVE-2022-42889
 Apache Commons Text performs variable interpolation, allowing properties to be dynamically evaluated and expanded. The standard format for interpolation is &quot;${prefix:name}&quot;, where &quot;prefix&quot; is used to locate an instance of org.apache.commons.text.lookup.StringLookup that performs the interpolation. Starting with version 1.5 and continuing through 1.9, the set of default Lookup instances included interpolators that could result in arbitrary code execution or contact with remote servers. These lookups are: - &quot;script&quot; - execute expressions using the JVM script execution engine (javax.script) - &quot;dns&quot; - resolve dns records - &quot;url&quot; - load values from urls, including from remote servers Applications using the interpolation defaults in the affected versions may be vulnerable to remote code execution or unintentional contact with remote servers if untrusted configuration values are used. Users are recommended to upgrade to Apache Commons Text 1.10.0, which disables the problematic interpolators by default.

- [https://github.com/pwnb0y/Text4shell-exploit](https://github.com/pwnb0y/Text4shell-exploit) :  ![starts](https://img.shields.io/github/stars/pwnb0y/Text4shell-exploit.svg) ![forks](https://img.shields.io/github/forks/pwnb0y/Text4shell-exploit.svg)


## CVE-2022-41352
 An issue was discovered in Zimbra Collaboration (ZCS) 8.8.15 and 9.0. An attacker can upload arbitrary files through amavisd via a cpio loophole (extraction to /opt/zimbra/jetty/webapps/zimbra/public) that can lead to incorrect access to any other user accounts. Zimbra recommends pax over cpio. Also, pax is in the prerequisites of Zimbra on Ubuntu; however, pax is no longer part of a default Red Hat installation after RHEL 6 (or CentOS 6). Once pax is installed, amavisd automatically prefers it over cpio.

- [https://github.com/aryrz/cve-2022-41352-zimbra-rce](https://github.com/aryrz/cve-2022-41352-zimbra-rce) :  ![starts](https://img.shields.io/github/stars/aryrz/cve-2022-41352-zimbra-rce.svg) ![forks](https://img.shields.io/github/forks/aryrz/cve-2022-41352-zimbra-rce.svg)


## CVE-2022-29464
 Certain WSO2 products allow unrestricted file upload with resultant remote code execution. The attacker must use a /fileupload endpoint with a Content-Disposition directory traversal sequence to reach a directory under the web root, such as a ../../../../repository/deployment/server/webapps directory. This affects WSO2 API Manager 2.2.0 and above through 4.0.0; WSO2 Identity Server 5.2.0 and above through 5.11.0; WSO2 Identity Server Analytics 5.4.0, 5.4.1, 5.5.0, and 5.6.0; WSO2 Identity Server as Key Manager 5.3.0 and above through 5.10.0; and WSO2 Enterprise Integrator 6.2.0 and above through 6.6.0.

- [https://github.com/Jhonsonwannaa/CVE-2022-29464-](https://github.com/Jhonsonwannaa/CVE-2022-29464-) :  ![starts](https://img.shields.io/github/stars/Jhonsonwannaa/CVE-2022-29464-.svg) ![forks](https://img.shields.io/github/forks/Jhonsonwannaa/CVE-2022-29464-.svg)


## CVE-2022-22954
 VMware Workspace ONE Access and Identity Manager contain a remote code execution vulnerability due to server-side template injection. A malicious actor with network access can trigger a server-side template injection that may result in remote code execution.

- [https://github.com/Jhonsonwannaa/CVE-2022-22954](https://github.com/Jhonsonwannaa/CVE-2022-22954) :  ![starts](https://img.shields.io/github/stars/Jhonsonwannaa/CVE-2022-22954.svg) ![forks](https://img.shields.io/github/forks/Jhonsonwannaa/CVE-2022-22954.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/puckiestyle/CVE-2021-41773](https://github.com/puckiestyle/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/puckiestyle/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/puckiestyle/CVE-2021-41773.svg)
- [https://github.com/Plunder283/CVE-2021-41773](https://github.com/Plunder283/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/Plunder283/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/Plunder283/CVE-2021-41773.svg)
- [https://github.com/Evil-d0Zz/CVE-2021-41773-](https://github.com/Evil-d0Zz/CVE-2021-41773-) :  ![starts](https://img.shields.io/github/stars/Evil-d0Zz/CVE-2021-41773-.svg) ![forks](https://img.shields.io/github/forks/Evil-d0Zz/CVE-2021-41773-.svg)


## CVE-2021-34470
 Microsoft Exchange Server Elevation of Privilege Vulnerability This CVE ID is unique from CVE-2021-33768, CVE-2021-34523.

- [https://github.com/technion/CVE-2021-34470scanner](https://github.com/technion/CVE-2021-34470scanner) :  ![starts](https://img.shields.io/github/stars/technion/CVE-2021-34470scanner.svg) ![forks](https://img.shields.io/github/forks/technion/CVE-2021-34470scanner.svg)


## CVE-2020-1472
 An elevation of privilege vulnerability exists when an attacker establishes a vulnerable Netlogon secure channel connection to a domain controller, using the Netlogon Remote Protocol (MS-NRPC), aka 'Netlogon Elevation of Privilege Vulnerability'.

- [https://github.com/dr4g0n23/CVE-2020-1472](https://github.com/dr4g0n23/CVE-2020-1472) :  ![starts](https://img.shields.io/github/stars/dr4g0n23/CVE-2020-1472.svg) ![forks](https://img.shields.io/github/forks/dr4g0n23/CVE-2020-1472.svg)


## CVE-2018-6574
 Go before 1.8.7, Go 1.9.x before 1.9.4, and Go 1.10 pre-releases before Go 1.10rc2 allow &quot;go get&quot; remote command execution during source code build, by leveraging the gcc or clang plugin feature, because -fplugin= and -plugin= arguments were not blocked.

- [https://github.com/jaya522/CVE-2018-6574-go-get-RCE](https://github.com/jaya522/CVE-2018-6574-go-get-RCE) :  ![starts](https://img.shields.io/github/stars/jaya522/CVE-2018-6574-go-get-RCE.svg) ![forks](https://img.shields.io/github/forks/jaya522/CVE-2018-6574-go-get-RCE.svg)


## CVE-2017-9841
 Util/PHP/eval-stdin.php in PHPUnit before 4.8.28 and 5.x before 5.6.3 allows remote attackers to execute arbitrary PHP code via HTTP POST data beginning with a &quot;&lt;?php &quot; substring, as demonstrated by an attack on a site with an exposed /vendor folder, i.e., external access to the /vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php URI.

- [https://github.com/Jhonsonwannaa/CVE-2017-9841-](https://github.com/Jhonsonwannaa/CVE-2017-9841-) :  ![starts](https://img.shields.io/github/stars/Jhonsonwannaa/CVE-2017-9841-.svg) ![forks](https://img.shields.io/github/forks/Jhonsonwannaa/CVE-2017-9841-.svg)

