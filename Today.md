# Update 2022-11-04
## CVE-2022-42889
 Apache Commons Text performs variable interpolation, allowing properties to be dynamically evaluated and expanded. The standard format for interpolation is &quot;${prefix:name}&quot;, where &quot;prefix&quot; is used to locate an instance of org.apache.commons.text.lookup.StringLookup that performs the interpolation. Starting with version 1.5 and continuing through 1.9, the set of default Lookup instances included interpolators that could result in arbitrary code execution or contact with remote servers. These lookups are: - &quot;script&quot; - execute expressions using the JVM script execution engine (javax.script) - &quot;dns&quot; - resolve dns records - &quot;url&quot; - load values from urls, including from remote servers Applications using the interpolation defaults in the affected versions may be vulnerable to remote code execution or unintentional contact with remote servers if untrusted configuration values are used. Users are recommended to upgrade to Apache Commons Text 1.10.0, which disables the problematic interpolators by default.

- [https://github.com/Hack4rLIFE/CVE-2022-42889](https://github.com/Hack4rLIFE/CVE-2022-42889) :  ![starts](https://img.shields.io/github/stars/Hack4rLIFE/CVE-2022-42889.svg) ![forks](https://img.shields.io/github/forks/Hack4rLIFE/CVE-2022-42889.svg)


## CVE-2022-33079
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/Bdenneu/CVE-2022-33079](https://github.com/Bdenneu/CVE-2022-33079) :  ![starts](https://img.shields.io/github/stars/Bdenneu/CVE-2022-33079.svg) ![forks](https://img.shields.io/github/forks/Bdenneu/CVE-2022-33079.svg)


## CVE-2022-3786
 A buffer overrun can be triggered in X.509 certificate verification, specifically in name constraint checking. Note that this occurs after certificate chain signature verification and requires either a CA to have signed a malicious certificate or for an application to continue certificate verification despite failure to construct a path to a trusted issuer. An attacker can craft a malicious email address in a certificate to overflow an arbitrary number of bytes containing the `.' character (decimal 46) on the stack. This buffer overflow could result in a crash (causing a denial of service). In a TLS client, this can be triggered by connecting to a malicious server. In a TLS server, this can be triggered if the server requests client authentication and a malicious client connects. Fixed in OpenSSL 3.0.7 (Affected 3.0.0,3.0.1,3.0.2,3.0.3,3.0.4,3.0.5,3.0.6).

- [https://github.com/NCSC-NL/OpenSSL-2022](https://github.com/NCSC-NL/OpenSSL-2022) :  ![starts](https://img.shields.io/github/stars/NCSC-NL/OpenSSL-2022.svg) ![forks](https://img.shields.io/github/forks/NCSC-NL/OpenSSL-2022.svg)
- [https://github.com/rbowes-r7/cve-2022-3602-and-cve-2022-3786-openssl-poc](https://github.com/rbowes-r7/cve-2022-3602-and-cve-2022-3786-openssl-poc) :  ![starts](https://img.shields.io/github/stars/rbowes-r7/cve-2022-3602-and-cve-2022-3786-openssl-poc.svg) ![forks](https://img.shields.io/github/forks/rbowes-r7/cve-2022-3602-and-cve-2022-3786-openssl-poc.svg)


## CVE-2022-3602
 A buffer overrun can be triggered in X.509 certificate verification, specifically in name constraint checking. Note that this occurs after certificate chain signature verification and requires either a CA to have signed the malicious certificate or for the application to continue certificate verification despite failure to construct a path to a trusted issuer. An attacker can craft a malicious email address to overflow four attacker-controlled bytes on the stack. This buffer overflow could result in a crash (causing a denial of service) or potentially remote code execution. Many platforms implement stack overflow protections which would mitigate against the risk of remote code execution. The risk may be further mitigated based on stack layout for any given platform/compiler. Pre-announcements of CVE-2022-3602 described this issue as CRITICAL. Further analysis based on some of the mitigating factors described above have led this to be downgraded to HIGH. Users are still encouraged to upgrade to a new version as soon as possible. In a TLS client, this can be triggered by connecting to a malicious server. In a TLS server, this can be triggered if the server requests client authentication and a malicious client connects. Fixed in OpenSSL 3.0.7 (Affected 3.0.0,3.0.1,3.0.2,3.0.3,3.0.4,3.0.5,3.0.6).

- [https://github.com/NCSC-NL/OpenSSL-2022](https://github.com/NCSC-NL/OpenSSL-2022) :  ![starts](https://img.shields.io/github/stars/NCSC-NL/OpenSSL-2022.svg) ![forks](https://img.shields.io/github/forks/NCSC-NL/OpenSSL-2022.svg)
- [https://github.com/rbowes-r7/cve-2022-3602-and-cve-2022-3786-openssl-poc](https://github.com/rbowes-r7/cve-2022-3602-and-cve-2022-3786-openssl-poc) :  ![starts](https://img.shields.io/github/stars/rbowes-r7/cve-2022-3602-and-cve-2022-3786-openssl-poc.svg) ![forks](https://img.shields.io/github/forks/rbowes-r7/cve-2022-3602-and-cve-2022-3786-openssl-poc.svg)
- [https://github.com/alicangnll/SpookySSL-Scanner](https://github.com/alicangnll/SpookySSL-Scanner) :  ![starts](https://img.shields.io/github/stars/alicangnll/SpookySSL-Scanner.svg) ![forks](https://img.shields.io/github/forks/alicangnll/SpookySSL-Scanner.svg)
- [https://github.com/fox-it/spookyssl-pcaps](https://github.com/fox-it/spookyssl-pcaps) :  ![starts](https://img.shields.io/github/stars/fox-it/spookyssl-pcaps.svg) ![forks](https://img.shields.io/github/forks/fox-it/spookyssl-pcaps.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/Undefind404/cve_2021_41773](https://github.com/Undefind404/cve_2021_41773) :  ![starts](https://img.shields.io/github/stars/Undefind404/cve_2021_41773.svg) ![forks](https://img.shields.io/github/forks/Undefind404/cve_2021_41773.svg)


## CVE-2021-27905
 The ReplicationHandler (normally registered at &quot;/replication&quot; under a Solr core) in Apache Solr has a &quot;masterUrl&quot; (also &quot;leaderUrl&quot; alias) parameter that is used to designate another ReplicationHandler on another Solr core to replicate index data into the local core. To prevent a SSRF vulnerability, Solr ought to check these parameters against a similar configuration it uses for the &quot;shards&quot; parameter. Prior to this bug getting fixed, it did not. This problem affects essentially all Solr versions prior to it getting fixed in 8.8.2.

- [https://github.com/pdelteil/CVE-2021-27905.POC](https://github.com/pdelteil/CVE-2021-27905.POC) :  ![starts](https://img.shields.io/github/stars/pdelteil/CVE-2021-27905.POC.svg) ![forks](https://img.shields.io/github/forks/pdelteil/CVE-2021-27905.POC.svg)


## CVE-2020-0910
 A remote code execution vulnerability exists when Windows Hyper-V on a host server fails to properly validate input from an authenticated user on a guest operating system, aka 'Windows Hyper-V Remote Code Execution Vulnerability'.

- [https://github.com/kfmgang/CVE-2020-0910](https://github.com/kfmgang/CVE-2020-0910) :  ![starts](https://img.shields.io/github/stars/kfmgang/CVE-2020-0910.svg) ![forks](https://img.shields.io/github/forks/kfmgang/CVE-2020-0910.svg)


## CVE-2015-3306
 The mod_copy module in ProFTPD 1.3.5 allows remote attackers to read and write to arbitrary files via the site cpfr and site cpto commands.

- [https://github.com/shk0x/cpx_proftpd](https://github.com/shk0x/cpx_proftpd) :  ![starts](https://img.shields.io/github/stars/shk0x/cpx_proftpd.svg) ![forks](https://img.shields.io/github/forks/shk0x/cpx_proftpd.svg)

