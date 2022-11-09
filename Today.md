# Update 2022-11-09
## CVE-2022-44889
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/Qualys/text4scanwin](https://github.com/Qualys/text4scanwin) :  ![starts](https://img.shields.io/github/stars/Qualys/text4scanwin.svg) ![forks](https://img.shields.io/github/forks/Qualys/text4scanwin.svg)


## CVE-2022-42889
 Apache Commons Text performs variable interpolation, allowing properties to be dynamically evaluated and expanded. The standard format for interpolation is &quot;${prefix:name}&quot;, where &quot;prefix&quot; is used to locate an instance of org.apache.commons.text.lookup.StringLookup that performs the interpolation. Starting with version 1.5 and continuing through 1.9, the set of default Lookup instances included interpolators that could result in arbitrary code execution or contact with remote servers. These lookups are: - &quot;script&quot; - execute expressions using the JVM script execution engine (javax.script) - &quot;dns&quot; - resolve dns records - &quot;url&quot; - load values from urls, including from remote servers Applications using the interpolation defaults in the affected versions may be vulnerable to remote code execution or unintentional contact with remote servers if untrusted configuration values are used. Users are recommended to upgrade to Apache Commons Text 1.10.0, which disables the problematic interpolators by default.

- [https://github.com/cryxnet/CVE-2022-42889-RCE](https://github.com/cryxnet/CVE-2022-42889-RCE) :  ![starts](https://img.shields.io/github/stars/cryxnet/CVE-2022-42889-RCE.svg) ![forks](https://img.shields.io/github/forks/cryxnet/CVE-2022-42889-RCE.svg)
- [https://github.com/adarshpv9746/Text4shell--Automated-exploit---CVE-2022-42889](https://github.com/adarshpv9746/Text4shell--Automated-exploit---CVE-2022-42889) :  ![starts](https://img.shields.io/github/stars/adarshpv9746/Text4shell--Automated-exploit---CVE-2022-42889.svg) ![forks](https://img.shields.io/github/forks/adarshpv9746/Text4shell--Automated-exploit---CVE-2022-42889.svg)


## CVE-2022-28079
 College Management System v1.0 was discovered to contain a SQL injection vulnerability via the course_code parameter.

- [https://github.com/erengozaydin/College-Management-System-course_code-SQL-Injection-Authenticated](https://github.com/erengozaydin/College-Management-System-course_code-SQL-Injection-Authenticated) :  ![starts](https://img.shields.io/github/stars/erengozaydin/College-Management-System-course_code-SQL-Injection-Authenticated.svg) ![forks](https://img.shields.io/github/forks/erengozaydin/College-Management-System-course_code-SQL-Injection-Authenticated.svg)


## CVE-2022-3786
 A buffer overrun can be triggered in X.509 certificate verification, specifically in name constraint checking. Note that this occurs after certificate chain signature verification and requires either a CA to have signed a malicious certificate or for an application to continue certificate verification despite failure to construct a path to a trusted issuer. An attacker can craft a malicious email address in a certificate to overflow an arbitrary number of bytes containing the `.' character (decimal 46) on the stack. This buffer overflow could result in a crash (causing a denial of service). In a TLS client, this can be triggered by connecting to a malicious server. In a TLS server, this can be triggered if the server requests client authentication and a malicious client connects.

- [https://github.com/cybersecurityworks553/CVE-2022-3602-and-CVE-2022-3786](https://github.com/cybersecurityworks553/CVE-2022-3602-and-CVE-2022-3786) :  ![starts](https://img.shields.io/github/stars/cybersecurityworks553/CVE-2022-3602-and-CVE-2022-3786.svg) ![forks](https://img.shields.io/github/forks/cybersecurityworks553/CVE-2022-3602-and-CVE-2022-3786.svg)


## CVE-2022-3602
 A buffer overrun can be triggered in X.509 certificate verification, specifically in name constraint checking. Note that this occurs after certificate chain signature verification and requires either a CA to have signed the malicious certificate or for the application to continue certificate verification despite failure to construct a path to a trusted issuer. An attacker can craft a malicious email address to overflow four attacker-controlled bytes on the stack. This buffer overflow could result in a crash (causing a denial of service) or potentially remote code execution. Many platforms implement stack overflow protections which would mitigate against the risk of remote code execution. The risk may be further mitigated based on stack layout for any given platform/compiler. Pre-announcements of CVE-2022-3602 described this issue as CRITICAL. Further analysis based on some of the mitigating factors described above have led this to be downgraded to HIGH. Users are still encouraged to upgrade to a new version as soon as possible. In a TLS client, this can be triggered by connecting to a malicious server. In a TLS server, this can be triggered if the server requests client authentication and a malicious client connects. Fixed in OpenSSL 3.0.7 (Affected 3.0.0,3.0.1,3.0.2,3.0.3,3.0.4,3.0.5,3.0.6).

- [https://github.com/cybersecurityworks553/CVE-2022-3602-and-CVE-2022-3786](https://github.com/cybersecurityworks553/CVE-2022-3602-and-CVE-2022-3786) :  ![starts](https://img.shields.io/github/stars/cybersecurityworks553/CVE-2022-3602-and-CVE-2022-3786.svg) ![forks](https://img.shields.io/github/forks/cybersecurityworks553/CVE-2022-3602-and-CVE-2022-3786.svg)


## CVE-2021-43657
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/c0n5n3d/CVE-2021-43657](https://github.com/c0n5n3d/CVE-2021-43657) :  ![starts](https://img.shields.io/github/stars/c0n5n3d/CVE-2021-43657.svg) ![forks](https://img.shields.io/github/forks/c0n5n3d/CVE-2021-43657.svg)


## CVE-2021-26084
 In affected versions of Confluence Server and Data Center, an OGNL injection vulnerability exists that would allow an unauthenticated attacker to execute arbitrary code on a Confluence Server or Data Center instance. The affected versions are before version 6.13.23, from version 6.14.0 before 7.4.11, from version 7.5.0 before 7.11.6, and from version 7.12.0 before 7.12.5.

- [https://github.com/Udyz/CVE-2021-26084](https://github.com/Udyz/CVE-2021-26084) :  ![starts](https://img.shields.io/github/stars/Udyz/CVE-2021-26084.svg) ![forks](https://img.shields.io/github/forks/Udyz/CVE-2021-26084.svg)
- [https://github.com/BeRserKerSec/CVE-2021-26084-Nuclei-template](https://github.com/BeRserKerSec/CVE-2021-26084-Nuclei-template) :  ![starts](https://img.shields.io/github/stars/BeRserKerSec/CVE-2021-26084-Nuclei-template.svg) ![forks](https://img.shields.io/github/forks/BeRserKerSec/CVE-2021-26084-Nuclei-template.svg)
- [https://github.com/quesodipesto/conflucheck](https://github.com/quesodipesto/conflucheck) :  ![starts](https://img.shields.io/github/stars/quesodipesto/conflucheck.svg) ![forks](https://img.shields.io/github/forks/quesodipesto/conflucheck.svg)


## CVE-2019-11932
 A double free vulnerability in the DDGifSlurp function in decoding.c in the android-gif-drawable library before version 1.2.18, as used in WhatsApp for Android before version 2.19.244 and many other Android applications, allows remote attackers to execute arbitrary code or cause a denial of service when the library is used to parse a specially crafted GIF image.

- [https://github.com/primebeast/CVE-2019-11932](https://github.com/primebeast/CVE-2019-11932) :  ![starts](https://img.shields.io/github/stars/primebeast/CVE-2019-11932.svg) ![forks](https://img.shields.io/github/forks/primebeast/CVE-2019-11932.svg)


## CVE-2016-5195
 Race condition in mm/gup.c in the Linux kernel 2.x through 4.x before 4.8.3 allows local users to gain privileges by leveraging incorrect handling of a copy-on-write (COW) feature to write to a read-only memory mapping, as exploited in the wild in October 2016, aka &quot;Dirty COW.&quot;

- [https://github.com/shanuka-ashen/Dirty-Cow-Explanation-CVE-2016-5195-](https://github.com/shanuka-ashen/Dirty-Cow-Explanation-CVE-2016-5195-) :  ![starts](https://img.shields.io/github/stars/shanuka-ashen/Dirty-Cow-Explanation-CVE-2016-5195-.svg) ![forks](https://img.shields.io/github/forks/shanuka-ashen/Dirty-Cow-Explanation-CVE-2016-5195-.svg)

