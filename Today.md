# Update 2023-09-07
## CVE-2023-41080
 URL Redirection to Untrusted Site ('Open Redirect') vulnerability in FORM authentication feature Apache Tomcat.This issue affects Apache Tomcat: from 11.0.0-M1 through 11.0.0-M10, from 10.1.0-M1 through 10.0.12, from 9.0.0-M1 through 9.0.79 and from 8.5.0 through 8.5.92. The vulnerability is limited to the ROOT (default) web application.

- [https://github.com/thperchi/CVE-2023-41080](https://github.com/thperchi/CVE-2023-41080) :  ![starts](https://img.shields.io/github/stars/thperchi/CVE-2023-41080.svg) ![forks](https://img.shields.io/github/forks/thperchi/CVE-2023-41080.svg)


## CVE-2023-39362
 Cacti is an open source operational monitoring and fault management framework. In Cacti 1.2.24, under certain conditions, an authenticated privileged user, can use a malicious string in the SNMP options of a Device, performing command injection and obtaining remote code execution on the underlying server. The `lib/snmp.php` file has a set of functions, with similar behavior, that accept in input some variables and place them into an `exec` call without a proper escape or validation. This issue has been addressed in version 1.2.25. Users are advised to upgrade. There are no known workarounds for this vulnerability.

- [https://github.com/m3ssap0/cacti-rce-snmp-options-vulnerable-application](https://github.com/m3ssap0/cacti-rce-snmp-options-vulnerable-application) :  ![starts](https://img.shields.io/github/stars/m3ssap0/cacti-rce-snmp-options-vulnerable-application.svg) ![forks](https://img.shields.io/github/forks/m3ssap0/cacti-rce-snmp-options-vulnerable-application.svg)


## CVE-2023-34039
 Aria Operations for Networks contains an Authentication Bypass vulnerability due to a lack of unique cryptographic key generation. A malicious actor with network access to Aria Operations for Networks could bypass SSH authentication to gain access to the Aria Operations for Networks CLI.

- [https://github.com/getdrive/PoC](https://github.com/getdrive/PoC) :  ![starts](https://img.shields.io/github/stars/getdrive/PoC.svg) ![forks](https://img.shields.io/github/forks/getdrive/PoC.svg)


## CVE-2023-33246
 For RocketMQ versions 5.1.0 and below, under certain conditions, there is a risk of remote command execution. Several components of RocketMQ, including NameServer, Broker, and Controller, are leaked on the extranet and lack permission verification, an attacker can exploit this vulnerability by using the update configuration function to execute commands as the system users that RocketMQ is running as. Additionally, an attacker can achieve the same effect by forging the RocketMQ protocol content. To prevent these attacks, users are recommended to upgrade to version 5.1.1 or above for using RocketMQ 5.x or 4.9.6 or above for using RocketMQ 4.x .

- [https://github.com/vulncheck-oss/fetch-broker-conf](https://github.com/vulncheck-oss/fetch-broker-conf) :  ![starts](https://img.shields.io/github/stars/vulncheck-oss/fetch-broker-conf.svg) ![forks](https://img.shields.io/github/forks/vulncheck-oss/fetch-broker-conf.svg)


## CVE-2023-20025
 A vulnerability in the web-based management interface of Cisco Small Business RV042 Series Routers could allow an unauthenticated, remote attacker to bypass authentication on the affected device. This vulnerability is due to incorrect user input validation of incoming HTTP packets. An attacker could exploit this vulnerability by sending crafted requests to the web-based management interface. A successful exploit could allow the attacker to gain root privileges on the affected device.

- [https://github.com/lnversed/CVE-2023-20025](https://github.com/lnversed/CVE-2023-20025) :  ![starts](https://img.shields.io/github/stars/lnversed/CVE-2023-20025.svg) ![forks](https://img.shields.io/github/forks/lnversed/CVE-2023-20025.svg)


## CVE-2023-4634
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/Patrowl/CVE-2023-4634](https://github.com/Patrowl/CVE-2023-4634) :  ![starts](https://img.shields.io/github/stars/Patrowl/CVE-2023-4634.svg) ![forks](https://img.shields.io/github/forks/Patrowl/CVE-2023-4634.svg)


## CVE-2023-3124
 The Elementor Pro plugin for WordPress is vulnerable to unauthorized data modification due to a missing capability check on the update_page_option function in versions up to, and including, 3.11.6. This makes it possible for authenticated attackers with subscriber-level capabilities to update arbitrary site options, which can lead to privilege escalation.

- [https://github.com/AmirWhiteHat/CVE-2023-3124](https://github.com/AmirWhiteHat/CVE-2023-3124) :  ![starts](https://img.shields.io/github/stars/AmirWhiteHat/CVE-2023-3124.svg) ![forks](https://img.shields.io/github/forks/AmirWhiteHat/CVE-2023-3124.svg)


## CVE-2022-44268
 ImageMagick 7.1.0-49 is vulnerable to Information Disclosure. When it parses a PNG image (e.g., for resize), the resulting image could have embedded the content of an arbitrary. file (if the magick binary has permissions to read it).

- [https://github.com/atici/Exploit-for-ImageMagick-CVE-2022-44268](https://github.com/atici/Exploit-for-ImageMagick-CVE-2022-44268) :  ![starts](https://img.shields.io/github/stars/atici/Exploit-for-ImageMagick-CVE-2022-44268.svg) ![forks](https://img.shields.io/github/forks/atici/Exploit-for-ImageMagick-CVE-2022-44268.svg)


## CVE-2022-42889
 Apache Commons Text performs variable interpolation, allowing properties to be dynamically evaluated and expanded. The standard format for interpolation is &quot;${prefix:name}&quot;, where &quot;prefix&quot; is used to locate an instance of org.apache.commons.text.lookup.StringLookup that performs the interpolation. Starting with version 1.5 and continuing through 1.9, the set of default Lookup instances included interpolators that could result in arbitrary code execution or contact with remote servers. These lookups are: - &quot;script&quot; - execute expressions using the JVM script execution engine (javax.script) - &quot;dns&quot; - resolve dns records - &quot;url&quot; - load values from urls, including from remote servers Applications using the interpolation defaults in the affected versions may be vulnerable to remote code execution or unintentional contact with remote servers if untrusted configuration values are used. Users are recommended to upgrade to Apache Commons Text 1.10.0, which disables the problematic interpolators by default.

- [https://github.com/Sic4rio/CVE-2022-42889](https://github.com/Sic4rio/CVE-2022-42889) :  ![starts](https://img.shields.io/github/stars/Sic4rio/CVE-2022-42889.svg) ![forks](https://img.shields.io/github/forks/Sic4rio/CVE-2022-42889.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/habibiefaried/CVE-2021-41773-PoC](https://github.com/habibiefaried/CVE-2021-41773-PoC) :  ![starts](https://img.shields.io/github/stars/habibiefaried/CVE-2021-41773-PoC.svg) ![forks](https://img.shields.io/github/forks/habibiefaried/CVE-2021-41773-PoC.svg)
- [https://github.com/kubota/POC-CVE-2021-41773](https://github.com/kubota/POC-CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/kubota/POC-CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/kubota/POC-CVE-2021-41773.svg)
- [https://github.com/walnutsecurity/cve-2021-41773](https://github.com/walnutsecurity/cve-2021-41773) :  ![starts](https://img.shields.io/github/stars/walnutsecurity/cve-2021-41773.svg) ![forks](https://img.shields.io/github/forks/walnutsecurity/cve-2021-41773.svg)
- [https://github.com/vida003/Scanner-CVE-2021-41773](https://github.com/vida003/Scanner-CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/vida003/Scanner-CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/vida003/Scanner-CVE-2021-41773.svg)
- [https://github.com/zer0qs/CVE-2021-41773](https://github.com/zer0qs/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/zer0qs/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/zer0qs/CVE-2021-41773.svg)


## CVE-2021-3156
 Sudo before 1.9.5p2 contains an off-by-one error that can result in a heap-based buffer overflow, which allows privilege escalation to root via &quot;sudoedit -s&quot; and a command-line argument that ends with a single backslash character.

- [https://github.com/asepsaepdin/CVE-2021-3156](https://github.com/asepsaepdin/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/asepsaepdin/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/asepsaepdin/CVE-2021-3156.svg)


## CVE-2020-10882
 This vulnerability allows network-adjacent attackers to execute arbitrary code on affected installations of TP-Link Archer A7 Firmware Ver: 190726 AC1750 routers. Authentication is not required to exploit this vulnerability. The specific flaw exists within the tdpServer service, which listens on UDP port 20002 by default. When parsing the slave_mac parameter, the process does not properly validate a user-supplied string before using it to execute a system call. An attacker can leverage this vulnerability to execute code in the context of the root user. Was ZDI-CAN-9650.

- [https://github.com/lnversed/CVE-2020-10882](https://github.com/lnversed/CVE-2020-10882) :  ![starts](https://img.shields.io/github/stars/lnversed/CVE-2020-10882.svg) ![forks](https://img.shields.io/github/forks/lnversed/CVE-2020-10882.svg)


## CVE-2019-9978
 The social-warfare plugin before 3.5.3 for WordPress has stored XSS via the wp-admin/admin-post.php?swp_debug=load_options swp_url parameter, as exploited in the wild in March 2019. This affects Social Warfare and Social Warfare Pro.

- [https://github.com/h8handles/CVE-2019-9978-Python3](https://github.com/h8handles/CVE-2019-9978-Python3) :  ![starts](https://img.shields.io/github/stars/h8handles/CVE-2019-9978-Python3.svg) ![forks](https://img.shields.io/github/forks/h8handles/CVE-2019-9978-Python3.svg)


## CVE-2019-2725
 Vulnerability in the Oracle WebLogic Server component of Oracle Fusion Middleware (subcomponent: Web Services). Supported versions that are affected are 10.3.6.0.0 and 12.1.3.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/kerlingcode/CVE-2019-2725](https://github.com/kerlingcode/CVE-2019-2725) :  ![starts](https://img.shields.io/github/stars/kerlingcode/CVE-2019-2725.svg) ![forks](https://img.shields.io/github/forks/kerlingcode/CVE-2019-2725.svg)
- [https://github.com/ianxtianxt/CVE-2019-2725](https://github.com/ianxtianxt/CVE-2019-2725) :  ![starts](https://img.shields.io/github/stars/ianxtianxt/CVE-2019-2725.svg) ![forks](https://img.shields.io/github/forks/ianxtianxt/CVE-2019-2725.svg)
- [https://github.com/1stPeak/CVE-2019-2725-environment](https://github.com/1stPeak/CVE-2019-2725-environment) :  ![starts](https://img.shields.io/github/stars/1stPeak/CVE-2019-2725-environment.svg) ![forks](https://img.shields.io/github/forks/1stPeak/CVE-2019-2725-environment.svg)


## CVE-2019-0604
 A remote code execution vulnerability exists in Microsoft SharePoint when the software fails to check the source markup of an application package, aka 'Microsoft SharePoint Remote Code Execution Vulnerability'. This CVE ID is unique from CVE-2019-0594.

- [https://github.com/davidlebr1/cve-2019-0604-SP2010-netv3.5](https://github.com/davidlebr1/cve-2019-0604-SP2010-netv3.5) :  ![starts](https://img.shields.io/github/stars/davidlebr1/cve-2019-0604-SP2010-netv3.5.svg) ![forks](https://img.shields.io/github/forks/davidlebr1/cve-2019-0604-SP2010-netv3.5.svg)


## CVE-2018-6574
 Go before 1.8.7, Go 1.9.x before 1.9.4, and Go 1.10 pre-releases before Go 1.10rc2 allow &quot;go get&quot; remote command execution during source code build, by leveraging the gcc or clang plugin feature, because -fplugin= and -plugin= arguments were not blocked.

- [https://github.com/noname-nohost/CVE-2018-6574](https://github.com/noname-nohost/CVE-2018-6574) :  ![starts](https://img.shields.io/github/stars/noname-nohost/CVE-2018-6574.svg) ![forks](https://img.shields.io/github/forks/noname-nohost/CVE-2018-6574.svg)


## CVE-2017-7529
 Nginx versions since 0.5.6 up to and including 1.13.2 are vulnerable to integer overflow vulnerability in nginx range filter module resulting into leak of potentially sensitive information triggered by specially crafted request.

- [https://github.com/MaxSecurity/CVE-2017-7529-POC](https://github.com/MaxSecurity/CVE-2017-7529-POC) :  ![starts](https://img.shields.io/github/stars/MaxSecurity/CVE-2017-7529-POC.svg) ![forks](https://img.shields.io/github/forks/MaxSecurity/CVE-2017-7529-POC.svg)

