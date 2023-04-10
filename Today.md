# Update 2023-04-10
## CVE-2023-29017
 vm2 is a sandbox that can run untrusted code with whitelisted Node's built-in modules. Prior to version 3.9.15, vm2 was not properly handling host objects passed to `Error.prepareStackTrace` in case of unhandled async errors. A threat actor could bypass the sandbox protections to gain remote code execution rights on the host running the sandbox. This vulnerability was patched in the release of version 3.9.15 of vm2. There are no known workarounds.

- [https://github.com/timb-machine-mirrors/seongil-wi-CVE-2023-29017](https://github.com/timb-machine-mirrors/seongil-wi-CVE-2023-29017) :  ![starts](https://img.shields.io/github/stars/timb-machine-mirrors/seongil-wi-CVE-2023-29017.svg) ![forks](https://img.shields.io/github/forks/timb-machine-mirrors/seongil-wi-CVE-2023-29017.svg)


## CVE-2022-42889
 Apache Commons Text performs variable interpolation, allowing properties to be dynamically evaluated and expanded. The standard format for interpolation is &quot;${prefix:name}&quot;, where &quot;prefix&quot; is used to locate an instance of org.apache.commons.text.lookup.StringLookup that performs the interpolation. Starting with version 1.5 and continuing through 1.9, the set of default Lookup instances included interpolators that could result in arbitrary code execution or contact with remote servers. These lookups are: - &quot;script&quot; - execute expressions using the JVM script execution engine (javax.script) - &quot;dns&quot; - resolve dns records - &quot;url&quot; - load values from urls, including from remote servers Applications using the interpolation defaults in the affected versions may be vulnerable to remote code execution or unintentional contact with remote servers if untrusted configuration values are used. Users are recommended to upgrade to Apache Commons Text 1.10.0, which disables the problematic interpolators by default.

- [https://github.com/dgor2023/cve-2022-42889-text4shell-docker](https://github.com/dgor2023/cve-2022-42889-text4shell-docker) :  ![starts](https://img.shields.io/github/stars/dgor2023/cve-2022-42889-text4shell-docker.svg) ![forks](https://img.shields.io/github/forks/dgor2023/cve-2022-42889-text4shell-docker.svg)


## CVE-2022-2602
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/vnc1106/CVE-2022-2602](https://github.com/vnc1106/CVE-2022-2602) :  ![starts](https://img.shields.io/github/stars/vnc1106/CVE-2022-2602.svg) ![forks](https://img.shields.io/github/forks/vnc1106/CVE-2022-2602.svg)


## CVE-2022-2588
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/Markakd/CVE-2022-2588](https://github.com/Markakd/CVE-2022-2588) :  ![starts](https://img.shields.io/github/stars/Markakd/CVE-2022-2588.svg) ![forks](https://img.shields.io/github/forks/Markakd/CVE-2022-2588.svg)


## CVE-2022-0739
 The BookingPress WordPress plugin before 1.0.11 fails to properly sanitize user supplied POST data before it is used in a dynamically constructed SQL query via the bookingpress_front_get_category_services AJAX action (available to unauthenticated users), leading to an unauthenticated SQL Injection

- [https://github.com/lhamouche/Bash-exploit-for-CVE-2022-0739](https://github.com/lhamouche/Bash-exploit-for-CVE-2022-0739) :  ![starts](https://img.shields.io/github/stars/lhamouche/Bash-exploit-for-CVE-2022-0739.svg) ![forks](https://img.shields.io/github/forks/lhamouche/Bash-exploit-for-CVE-2022-0739.svg)


## CVE-2021-45046
 It was found that the fix to address CVE-2021-44228 in Apache Log4j 2.15.0 was incomplete in certain non-default configurations. This could allows attackers with control over Thread Context Map (MDC) input data when the logging configuration uses a non-default Pattern Layout with either a Context Lookup (for example, $${ctx:loginId}) or a Thread Context Map pattern (%X, %mdc, or %MDC) to craft malicious input data using a JNDI Lookup pattern resulting in an information leak and remote code execution in some environments and local code execution in all environments. Log4j 2.16.0 (Java 8) and 2.12.2 (Java 7) fix this issue by removing support for message lookup patterns and disabling JNDI functionality by default.

- [https://github.com/dtact/divd-2021-00038--log4j-scanner](https://github.com/dtact/divd-2021-00038--log4j-scanner) :  ![starts](https://img.shields.io/github/stars/dtact/divd-2021-00038--log4j-scanner.svg) ![forks](https://img.shields.io/github/forks/dtact/divd-2021-00038--log4j-scanner.svg)
- [https://github.com/xsultan/log4jshield](https://github.com/xsultan/log4jshield) :  ![starts](https://img.shields.io/github/stars/xsultan/log4jshield.svg) ![forks](https://img.shields.io/github/forks/xsultan/log4jshield.svg)
- [https://github.com/demonrvm/Log4ShellRemediation](https://github.com/demonrvm/Log4ShellRemediation) :  ![starts](https://img.shields.io/github/stars/demonrvm/Log4ShellRemediation.svg) ![forks](https://img.shields.io/github/forks/demonrvm/Log4ShellRemediation.svg)


## CVE-2021-42321
 Microsoft Exchange Server Remote Code Execution Vulnerability

- [https://github.com/timb-machine-mirrors/testanull-CVE-2021-42321_poc.py](https://github.com/timb-machine-mirrors/testanull-CVE-2021-42321_poc.py) :  ![starts](https://img.shields.io/github/stars/timb-machine-mirrors/testanull-CVE-2021-42321_poc.py.svg) ![forks](https://img.shields.io/github/forks/timb-machine-mirrors/testanull-CVE-2021-42321_poc.py.svg)


## CVE-2021-30955
 A race condition was addressed with improved state handling. This issue is fixed in macOS Monterey 12.1, watchOS 8.3, iOS 15.2 and iPadOS 15.2, tvOS 15.2. A malicious application may be able to execute arbitrary code with kernel privileges.

- [https://github.com/timb-machine-mirrors/jakeajames-CVE-2021-30955](https://github.com/timb-machine-mirrors/jakeajames-CVE-2021-30955) :  ![starts](https://img.shields.io/github/stars/timb-machine-mirrors/jakeajames-CVE-2021-30955.svg) ![forks](https://img.shields.io/github/forks/timb-machine-mirrors/jakeajames-CVE-2021-30955.svg)


## CVE-2021-28482
 Microsoft Exchange Server Remote Code Execution Vulnerability This CVE ID is unique from CVE-2021-28480, CVE-2021-28481, CVE-2021-28483.

- [https://github.com/timb-machine-mirrors/testanull-CVE-2021-28482.py](https://github.com/timb-machine-mirrors/testanull-CVE-2021-28482.py) :  ![starts](https://img.shields.io/github/stars/timb-machine-mirrors/testanull-CVE-2021-28482.py.svg) ![forks](https://img.shields.io/github/forks/timb-machine-mirrors/testanull-CVE-2021-28482.py.svg)


## CVE-2021-22005
 The vCenter Server contains an arbitrary file upload vulnerability in the Analytics service. A malicious actor with network access to port 443 on vCenter Server may exploit this issue to execute code on vCenter Server by uploading a specially crafted file.

- [https://github.com/timb-machine-mirrors/testanull-CVE-2021-22005.py](https://github.com/timb-machine-mirrors/testanull-CVE-2021-22005.py) :  ![starts](https://img.shields.io/github/stars/timb-machine-mirrors/testanull-CVE-2021-22005.py.svg) ![forks](https://img.shields.io/github/forks/timb-machine-mirrors/testanull-CVE-2021-22005.py.svg)


## CVE-2021-3060
 An OS command injection vulnerability in the Simple Certificate Enrollment Protocol (SCEP) feature of PAN-OS software allows an unauthenticated network-based attacker with specific knowledge of the firewall configuration to execute arbitrary code with root user privileges. The attacker must have network access to the GlobalProtect interfaces to exploit this issue. This issue impacts: PAN-OS 8.1 versions earlier than PAN-OS 8.1.20-h1; PAN-OS 9.0 versions earlier than PAN-OS 9.0.14-h3; PAN-OS 9.1 versions earlier than PAN-OS 9.1.11-h2; PAN-OS 10.0 versions earlier than PAN-OS 10.0.8; PAN-OS 10.1 versions earlier than PAN-OS 10.1.3. Prisma Access customers with Prisma Access 2.1 Preferred and Prisma Access 2.1 Innovation firewalls are impacted by this issue.

- [https://github.com/timb-machine-mirrors/rqu1-cve-2021-3060.py](https://github.com/timb-machine-mirrors/rqu1-cve-2021-3060.py) :  ![starts](https://img.shields.io/github/stars/timb-machine-mirrors/rqu1-cve-2021-3060.py.svg) ![forks](https://img.shields.io/github/forks/timb-machine-mirrors/rqu1-cve-2021-3060.py.svg)


## CVE-2019-8942
 WordPress before 4.9.9 and 5.x before 5.0.1 allows remote code execution because an _wp_attached_file Post Meta entry can be changed to an arbitrary string, such as one ending with a .jpg?file.php substring. An attacker with author privileges can execute arbitrary code by uploading a crafted image containing PHP code in the Exif metadata. Exploitation can leverage CVE-2019-8943.

- [https://github.com/synacktiv/CVE-2019-8942](https://github.com/synacktiv/CVE-2019-8942) :  ![starts](https://img.shields.io/github/stars/synacktiv/CVE-2019-8942.svg) ![forks](https://img.shields.io/github/forks/synacktiv/CVE-2019-8942.svg)


## CVE-2018-11631
 Rondaful M1 Wristband Smart Band 1 devices allow remote attackers to send an arbitrary number of call or SMS notifications via crafted Bluetooth Low Energy (BLE) traffic.

- [https://github.com/ColeShelly/bandexploit](https://github.com/ColeShelly/bandexploit) :  ![starts](https://img.shields.io/github/stars/ColeShelly/bandexploit.svg) ![forks](https://img.shields.io/github/forks/ColeShelly/bandexploit.svg)

