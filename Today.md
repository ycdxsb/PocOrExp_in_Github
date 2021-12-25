# Update 2021-12-25
## CVE-2021-45105
 Apache Log4j2 versions 2.0-alpha1 through 2.16.0 (excluding 2.12.3) did not protect from uncontrolled recursion from self-referential lookups. This allows an attacker with control over Thread Context Map data to cause a denial of service when a crafted string is interpreted. This issue was fixed in Log4j 2.17.0 and 2.12.3.

- [https://github.com/sakuraji-labs/log4j-remediation](https://github.com/sakuraji-labs/log4j-remediation) :  ![starts](https://img.shields.io/github/stars/sakuraji-labs/log4j-remediation.svg) ![forks](https://img.shields.io/github/forks/sakuraji-labs/log4j-remediation.svg)
- [https://github.com/dileepdkumar/https-github.com-pravin-pp-log4j2-CVE-2021-45105-1](https://github.com/dileepdkumar/https-github.com-pravin-pp-log4j2-CVE-2021-45105-1) :  ![starts](https://img.shields.io/github/stars/dileepdkumar/https-github.com-pravin-pp-log4j2-CVE-2021-45105-1.svg) ![forks](https://img.shields.io/github/forks/dileepdkumar/https-github.com-pravin-pp-log4j2-CVE-2021-45105-1.svg)
- [https://github.com/dileepdkumar/https-github.com-pravin-pp-log4j2-CVE-2021-45105](https://github.com/dileepdkumar/https-github.com-pravin-pp-log4j2-CVE-2021-45105) :  ![starts](https://img.shields.io/github/stars/dileepdkumar/https-github.com-pravin-pp-log4j2-CVE-2021-45105.svg) ![forks](https://img.shields.io/github/forks/dileepdkumar/https-github.com-pravin-pp-log4j2-CVE-2021-45105.svg)
- [https://github.com/dileepdkumar/https-github.com-dileepdkumar-https-github.com-pravin-pp-log4j2-CVE-2021-45105](https://github.com/dileepdkumar/https-github.com-dileepdkumar-https-github.com-pravin-pp-log4j2-CVE-2021-45105) :  ![starts](https://img.shields.io/github/stars/dileepdkumar/https-github.com-dileepdkumar-https-github.com-pravin-pp-log4j2-CVE-2021-45105.svg) ![forks](https://img.shields.io/github/forks/dileepdkumar/https-github.com-dileepdkumar-https-github.com-pravin-pp-log4j2-CVE-2021-45105.svg)
- [https://github.com/dileepdkumar/https-github.com-dileepdkumar-https-github.com-pravin-pp-log4j2-CVE-2021-45105-v](https://github.com/dileepdkumar/https-github.com-dileepdkumar-https-github.com-pravin-pp-log4j2-CVE-2021-45105-v) :  ![starts](https://img.shields.io/github/stars/dileepdkumar/https-github.com-dileepdkumar-https-github.com-pravin-pp-log4j2-CVE-2021-45105-v.svg) ![forks](https://img.shields.io/github/forks/dileepdkumar/https-github.com-dileepdkumar-https-github.com-pravin-pp-log4j2-CVE-2021-45105-v.svg)
- [https://github.com/Afrouper/Log4j-Scanner](https://github.com/Afrouper/Log4j-Scanner) :  ![starts](https://img.shields.io/github/stars/Afrouper/Log4j-Scanner.svg) ![forks](https://img.shields.io/github/forks/Afrouper/Log4j-Scanner.svg)
- [https://github.com/richardbischof/log4j-detector-to-csv](https://github.com/richardbischof/log4j-detector-to-csv) :  ![starts](https://img.shields.io/github/stars/richardbischof/log4j-detector-to-csv.svg) ![forks](https://img.shields.io/github/forks/richardbischof/log4j-detector-to-csv.svg)


## CVE-2021-45046
 It was found that the fix to address CVE-2021-44228 in Apache Log4j 2.15.0 was incomplete in certain non-default configurations. This could allows attackers with control over Thread Context Map (MDC) input data when the logging configuration uses a non-default Pattern Layout with either a Context Lookup (for example, $${ctx:loginId}) or a Thread Context Map pattern (%X, %mdc, or %MDC) to craft malicious input data using a JNDI Lookup pattern resulting in an information leak and remote code execution in some environments and local code execution in all environments. Log4j 2.16.0 (Java 8) and 2.12.2 (Java 7) fix this issue by removing support for message lookup patterns and disabling JNDI functionality by default.

- [https://github.com/Afrouper/Log4j-Scanner](https://github.com/Afrouper/Log4j-Scanner) :  ![starts](https://img.shields.io/github/stars/Afrouper/Log4j-Scanner.svg) ![forks](https://img.shields.io/github/forks/Afrouper/Log4j-Scanner.svg)
- [https://github.com/richardbischof/log4j-detector-to-csv](https://github.com/richardbischof/log4j-detector-to-csv) :  ![starts](https://img.shields.io/github/stars/richardbischof/log4j-detector-to-csv.svg) ![forks](https://img.shields.io/github/forks/richardbischof/log4j-detector-to-csv.svg)


## CVE-2021-44733
 A use-after-free exists in drivers/tee/tee_shm.c in the TEE subsystem in the Linux kernel through 5.15.11. This occurs because of a race condition in tee_shm_get_from_id during an attempt to free a shared memory object.

- [https://github.com/pjlantz/optee-qemu](https://github.com/pjlantz/optee-qemu) :  ![starts](https://img.shields.io/github/stars/pjlantz/optee-qemu.svg) ![forks](https://img.shields.io/github/forks/pjlantz/optee-qemu.svg)


## CVE-2021-44228
 Apache Log4j2 2.0-beta9 through 2.12.1 and 2.13.0 through 2.15.0 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled. From log4j 2.15.0, this behavior has been disabled by default. From version 2.16.0, this functionality has been completely removed. Note that this vulnerability is specific to log4j-core and does not affect log4net, log4cxx, or other Apache Logging Services projects.

- [https://github.com/Nanitor/log4fix](https://github.com/Nanitor/log4fix) :  ![starts](https://img.shields.io/github/stars/Nanitor/log4fix.svg) ![forks](https://img.shields.io/github/forks/Nanitor/log4fix.svg)


## CVE-2021-42013
 It was found that the fix for CVE-2021-41773 in Apache HTTP Server 2.4.50 was insufficient. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue only affects Apache 2.4.49 and Apache 2.4.50 and not earlier versions.

- [https://github.com/asaotomo/CVE-2021-42013-Apache-RCE-Poc-Exp](https://github.com/asaotomo/CVE-2021-42013-Apache-RCE-Poc-Exp) :  ![starts](https://img.shields.io/github/stars/asaotomo/CVE-2021-42013-Apache-RCE-Poc-Exp.svg) ![forks](https://img.shields.io/github/forks/asaotomo/CVE-2021-42013-Apache-RCE-Poc-Exp.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/asaotomo/CVE-2021-42013-Apache-RCE-Poc-Exp](https://github.com/asaotomo/CVE-2021-42013-Apache-RCE-Poc-Exp) :  ![starts](https://img.shields.io/github/stars/asaotomo/CVE-2021-42013-Apache-RCE-Poc-Exp.svg) ![forks](https://img.shields.io/github/forks/asaotomo/CVE-2021-42013-Apache-RCE-Poc-Exp.svg)


## CVE-2020-7661
 all versions of url-regex are vulnerable to Regular Expression Denial of Service. An attacker providing a very long string in String.test can cause a Denial of Service.

- [https://github.com/spamscanner/url-regex-safe](https://github.com/spamscanner/url-regex-safe) :  ![starts](https://img.shields.io/github/stars/spamscanner/url-regex-safe.svg) ![forks](https://img.shields.io/github/forks/spamscanner/url-regex-safe.svg)


## CVE-2020-1472
 An elevation of privilege vulnerability exists when an attacker establishes a vulnerable Netlogon secure channel connection to a domain controller, using the Netlogon Remote Protocol (MS-NRPC), aka 'Netlogon Elevation of Privilege Vulnerability'.

- [https://github.com/Privia-Security/ADZero](https://github.com/Privia-Security/ADZero) :  ![starts](https://img.shields.io/github/stars/Privia-Security/ADZero.svg) ![forks](https://img.shields.io/github/forks/Privia-Security/ADZero.svg)
- [https://github.com/murataydemir/CVE-2020-1472](https://github.com/murataydemir/CVE-2020-1472) :  ![starts](https://img.shields.io/github/stars/murataydemir/CVE-2020-1472.svg) ![forks](https://img.shields.io/github/forks/murataydemir/CVE-2020-1472.svg)
- [https://github.com/mingchen-script/CVE-2020-1472-visualizer](https://github.com/mingchen-script/CVE-2020-1472-visualizer) :  ![starts](https://img.shields.io/github/stars/mingchen-script/CVE-2020-1472-visualizer.svg) ![forks](https://img.shields.io/github/forks/mingchen-script/CVE-2020-1472-visualizer.svg)


## CVE-2018-14847
 MikroTik RouterOS through 6.42 allows unauthenticated remote attackers to read arbitrary files and remote authenticated attackers to write arbitrary files due to a directory traversal vulnerability in the WinBox interface.

- [https://github.com/Tr33-He11/winboxPOC](https://github.com/Tr33-He11/winboxPOC) :  ![starts](https://img.shields.io/github/stars/Tr33-He11/winboxPOC.svg) ![forks](https://img.shields.io/github/forks/Tr33-He11/winboxPOC.svg)

