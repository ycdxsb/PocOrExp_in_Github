# Update 2022-10-22
## CVE-2022-42889
 Apache Commons Text performs variable interpolation, allowing properties to be dynamically evaluated and expanded. The standard format for interpolation is &quot;${prefix:name}&quot;, where &quot;prefix&quot; is used to locate an instance of org.apache.commons.text.lookup.StringLookup that performs the interpolation. Starting with version 1.5 and continuing through 1.9, the set of default Lookup instances included interpolators that could result in arbitrary code execution or contact with remote servers. These lookups are: - &quot;script&quot; - execute expressions using the JVM script execution engine (javax.script) - &quot;dns&quot; - resolve dns records - &quot;url&quot; - load values from urls, including from remote servers Applications using the interpolation defaults in the affected versions may be vulnerable to remote code execution or unintentional contact with remote servers if untrusted configuration values are used. Users are recommended to upgrade to Apache Commons Text 1.10.0, which disables the problematic interpolators by default.

- [https://github.com/HKirito/CVE-2022-33980](https://github.com/HKirito/CVE-2022-33980) :  ![starts](https://img.shields.io/github/stars/HKirito/CVE-2022-33980.svg) ![forks](https://img.shields.io/github/forks/HKirito/CVE-2022-33980.svg)
- [https://github.com/uk0/cve-2022-42889-intercept](https://github.com/uk0/cve-2022-42889-intercept) :  ![starts](https://img.shields.io/github/stars/uk0/cve-2022-42889-intercept.svg) ![forks](https://img.shields.io/github/forks/uk0/cve-2022-42889-intercept.svg)
- [https://github.com/RIP-Network/cve-2022-42889-scanner](https://github.com/RIP-Network/cve-2022-42889-scanner) :  ![starts](https://img.shields.io/github/stars/RIP-Network/cve-2022-42889-scanner.svg) ![forks](https://img.shields.io/github/forks/RIP-Network/cve-2022-42889-scanner.svg)
- [https://github.com/securekomodo/text4shell-poc](https://github.com/securekomodo/text4shell-poc) :  ![starts](https://img.shields.io/github/stars/securekomodo/text4shell-poc.svg) ![forks](https://img.shields.io/github/forks/securekomodo/text4shell-poc.svg)


## CVE-2022-41082
 Microsoft Exchange Server Remote Code Execution Vulnerability.

- [https://github.com/trhacknon/CVE-2022-41082-MASS-SCANNER](https://github.com/trhacknon/CVE-2022-41082-MASS-SCANNER) :  ![starts](https://img.shields.io/github/stars/trhacknon/CVE-2022-41082-MASS-SCANNER.svg) ![forks](https://img.shields.io/github/forks/trhacknon/CVE-2022-41082-MASS-SCANNER.svg)


## CVE-2022-41040
 Microsoft Exchange Server Elevation of Privilege Vulnerability.

- [https://github.com/trhacknon/CVE-2022-41040-metasploit-ProxyNotShell](https://github.com/trhacknon/CVE-2022-41040-metasploit-ProxyNotShell) :  ![starts](https://img.shields.io/github/stars/trhacknon/CVE-2022-41040-metasploit-ProxyNotShell.svg) ![forks](https://img.shields.io/github/forks/trhacknon/CVE-2022-41040-metasploit-ProxyNotShell.svg)


## CVE-2022-22965
 A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the application to run on Tomcat as a WAR deployment. If the application is deployed as a Spring Boot executable jar, i.e. the default, it is not vulnerable to the exploit. However, the nature of the vulnerability is more general, and there may be other ways to exploit it.

- [https://github.com/iyamroshan/CVE-2022-22965](https://github.com/iyamroshan/CVE-2022-22965) :  ![starts](https://img.shields.io/github/stars/iyamroshan/CVE-2022-22965.svg) ![forks](https://img.shields.io/github/forks/iyamroshan/CVE-2022-22965.svg)


## CVE-2022-22954
 VMware Workspace ONE Access and Identity Manager contain a remote code execution vulnerability due to server-side template injection. A malicious actor with network access can trigger a server-side template injection that may result in remote code execution.

- [https://github.com/lolminerxmrig/CVE-2022-22954_](https://github.com/lolminerxmrig/CVE-2022-22954_) :  ![starts](https://img.shields.io/github/stars/lolminerxmrig/CVE-2022-22954_.svg) ![forks](https://img.shields.io/github/forks/lolminerxmrig/CVE-2022-22954_.svg)


## CVE-2022-22947
 In spring cloud gateway versions prior to 3.1.1+ and 3.0.7+ , applications are vulnerable to a code injection attack when the Gateway Actuator endpoint is enabled, exposed and unsecured. A remote attacker could make a maliciously crafted request that could allow arbitrary remote execution on the remote host.

- [https://github.com/trhacknon/CVE-2022-22947](https://github.com/trhacknon/CVE-2022-22947) :  ![starts](https://img.shields.io/github/stars/trhacknon/CVE-2022-22947.svg) ![forks](https://img.shields.io/github/forks/trhacknon/CVE-2022-22947.svg)


## CVE-2022-21970
 Microsoft Edge (Chromium-based) Elevation of Privilege Vulnerability. This CVE ID is unique from CVE-2022-21954.

- [https://github.com/Malwareman007/CVE-2022-21970](https://github.com/Malwareman007/CVE-2022-21970) :  ![starts](https://img.shields.io/github/stars/Malwareman007/CVE-2022-21970.svg) ![forks](https://img.shields.io/github/forks/Malwareman007/CVE-2022-21970.svg)


## CVE-2021-3560
 It was found that polkit could be tricked into bypassing the credential checks for D-Bus requests, elevating the privileges of the requestor to the root user. This flaw could be used by an unprivileged local attacker to, for example, create a new local administrator. The highest threat from this vulnerability is to data confidentiality and integrity as well as system availability.

- [https://github.com/Almorabea/Polkit-exploit](https://github.com/Almorabea/Polkit-exploit) :  ![starts](https://img.shields.io/github/stars/Almorabea/Polkit-exploit.svg) ![forks](https://img.shields.io/github/forks/Almorabea/Polkit-exploit.svg)
- [https://github.com/oxagast/oxasploits](https://github.com/oxagast/oxasploits) :  ![starts](https://img.shields.io/github/stars/oxagast/oxasploits.svg) ![forks](https://img.shields.io/github/forks/oxagast/oxasploits.svg)
- [https://github.com/f4T1H21/CVE-2021-3560-Polkit-DBus](https://github.com/f4T1H21/CVE-2021-3560-Polkit-DBus) :  ![starts](https://img.shields.io/github/stars/f4T1H21/CVE-2021-3560-Polkit-DBus.svg) ![forks](https://img.shields.io/github/forks/f4T1H21/CVE-2021-3560-Polkit-DBus.svg)
- [https://github.com/innxrmxst/CVE-2021-3560](https://github.com/innxrmxst/CVE-2021-3560) :  ![starts](https://img.shields.io/github/stars/innxrmxst/CVE-2021-3560.svg) ![forks](https://img.shields.io/github/forks/innxrmxst/CVE-2021-3560.svg)


## CVE-2020-13942
 It is possible to inject malicious OGNL or MVEL scripts into the /context.json public endpoint. This was partially fixed in 1.5.1 but a new attack vector was found. In Apache Unomi version 1.5.2 scripts are now completely filtered from the input. It is highly recommended to upgrade to the latest available version of the 1.5.x release to fix this problem.

- [https://github.com/Prodrious/CVE-2020-13942](https://github.com/Prodrious/CVE-2020-13942) :  ![starts](https://img.shields.io/github/stars/Prodrious/CVE-2020-13942.svg) ![forks](https://img.shields.io/github/forks/Prodrious/CVE-2020-13942.svg)


## CVE-2017-9841
 Util/PHP/eval-stdin.php in PHPUnit before 4.8.28 and 5.x before 5.6.3 allows remote attackers to execute arbitrary PHP code via HTTP POST data beginning with a &quot;&lt;?php &quot; substring, as demonstrated by an attack on a site with an exposed /vendor folder, i.e., external access to the /vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php URI.

- [https://github.com/mileticluka1/eval-stdin](https://github.com/mileticluka1/eval-stdin) :  ![starts](https://img.shields.io/github/stars/mileticluka1/eval-stdin.svg) ![forks](https://img.shields.io/github/forks/mileticluka1/eval-stdin.svg)

