# Update 2023-12-06
## CVE-2023-38831
 RARLAB WinRAR before 6.23 allows attackers to execute arbitrary code when a user attempts to view a benign file within a ZIP archive. The issue occurs because a ZIP archive may include a benign file (such as an ordinary .JPG file) and also a folder that has the same name as the benign file, and the contents of the folder (which may include executable content) are processed during an attempt to access only the benign file. This was exploited in the wild in April through October 2023.

- [https://github.com/MyStuffYT/CVE-2023-38831-POC](https://github.com/MyStuffYT/CVE-2023-38831-POC) :  ![starts](https://img.shields.io/github/stars/MyStuffYT/CVE-2023-38831-POC.svg) ![forks](https://img.shields.io/github/forks/MyStuffYT/CVE-2023-38831-POC.svg)


## CVE-2023-25690
 Some mod_proxy configurations on Apache HTTP Server versions 2.4.0 through 2.4.55 allow a HTTP Request Smuggling attack. Configurations are affected when mod_proxy is enabled along with some form of RewriteRule or ProxyPassMatch in which a non-specific pattern matches some portion of the user-supplied request-target (URL) data and is then re-inserted into the proxied request-target using variable substitution. For example, something like: RewriteEngine on RewriteRule &quot;^/here/(.*)&quot; &quot;http://example.com:8080/elsewhere?$1&quot;; [P] ProxyPassReverse /here/ http://example.com:8080/ Request splitting/smuggling could result in bypass of access controls in the proxy server, proxying unintended URLs to existing origin servers, and cache poisoning. Users are recommended to update to at least version 2.4.56 of Apache HTTP Server.

- [https://github.com/thanhlam-attt/CVE-2023-25690](https://github.com/thanhlam-attt/CVE-2023-25690) :  ![starts](https://img.shields.io/github/stars/thanhlam-attt/CVE-2023-25690.svg) ![forks](https://img.shields.io/github/forks/thanhlam-attt/CVE-2023-25690.svg)


## CVE-2023-23752
 An issue was discovered in Joomla! 4.0.0 through 4.2.7. An improper access check allows unauthorized access to webservice endpoints.

- [https://github.com/yusinomy/CVE-2023-23752](https://github.com/yusinomy/CVE-2023-23752) :  ![starts](https://img.shields.io/github/stars/yusinomy/CVE-2023-23752.svg) ![forks](https://img.shields.io/github/forks/yusinomy/CVE-2023-23752.svg)
- [https://github.com/K3ysTr0K3R/CVE-2023-23752-EXPLOIT](https://github.com/K3ysTr0K3R/CVE-2023-23752-EXPLOIT) :  ![starts](https://img.shields.io/github/stars/K3ysTr0K3R/CVE-2023-23752-EXPLOIT.svg) ![forks](https://img.shields.io/github/forks/K3ysTr0K3R/CVE-2023-23752-EXPLOIT.svg)


## CVE-2023-2024
 Improper authentication in OpenBlue Enterprise Manager Data Collector versions prior to 3.2.5.75 allow access to an unauthorized user under certain circumstances.

- [https://github.com/team890/CVE-2023-2024](https://github.com/team890/CVE-2023-2024) :  ![starts](https://img.shields.io/github/stars/team890/CVE-2023-2024.svg) ![forks](https://img.shields.io/github/forks/team890/CVE-2023-2024.svg)


## CVE-2022-42889
 Apache Commons Text performs variable interpolation, allowing properties to be dynamically evaluated and expanded. The standard format for interpolation is &quot;${prefix:name}&quot;, where &quot;prefix&quot; is used to locate an instance of org.apache.commons.text.lookup.StringLookup that performs the interpolation. Starting with version 1.5 and continuing through 1.9, the set of default Lookup instances included interpolators that could result in arbitrary code execution or contact with remote servers. These lookups are: - &quot;script&quot; - execute expressions using the JVM script execution engine (javax.script) - &quot;dns&quot; - resolve dns records - &quot;url&quot; - load values from urls, including from remote servers Applications using the interpolation defaults in the affected versions may be vulnerable to remote code execution or unintentional contact with remote servers if untrusted configuration values are used. Users are recommended to upgrade to Apache Commons Text 1.10.0, which disables the problematic interpolators by default.

- [https://github.com/f0ng/text4shellburpscanner](https://github.com/f0ng/text4shellburpscanner) :  ![starts](https://img.shields.io/github/stars/f0ng/text4shellburpscanner.svg) ![forks](https://img.shields.io/github/forks/f0ng/text4shellburpscanner.svg)
- [https://github.com/hotblac/text4shell](https://github.com/hotblac/text4shell) :  ![starts](https://img.shields.io/github/stars/hotblac/text4shell.svg) ![forks](https://img.shields.io/github/forks/hotblac/text4shell.svg)


## CVE-2021-44790
 A carefully crafted request body can cause a buffer overflow in the mod_lua multipart parser (r:parsebody() called from Lua scripts). The Apache httpd team is not aware of an exploit for the vulnerabilty though it might be possible to craft one. This issue affects Apache HTTP Server 2.4.51 and earlier.

- [https://github.com/nuPacaChi/-CVE-2021-44790](https://github.com/nuPacaChi/-CVE-2021-44790) :  ![starts](https://img.shields.io/github/stars/nuPacaChi/-CVE-2021-44790.svg) ![forks](https://img.shields.io/github/forks/nuPacaChi/-CVE-2021-44790.svg)


## CVE-2021-3317
 KLog Server through 2.4.1 allows authenticated command injection. async.php calls shell_exec() on the original value of the source parameter.

- [https://github.com/Al1ex/CVE-2021-3317](https://github.com/Al1ex/CVE-2021-3317) :  ![starts](https://img.shields.io/github/stars/Al1ex/CVE-2021-3317.svg) ![forks](https://img.shields.io/github/forks/Al1ex/CVE-2021-3317.svg)


## CVE-2020-17519
 A change introduced in Apache Flink 1.11.0 (and released in 1.11.1 and 1.11.2 as well) allows attackers to read any file on the local filesystem of the JobManager through the REST interface of the JobManager process. Access is restricted to files accessible by the JobManager process. All users should upgrade to Flink 1.11.3 or 1.12.0 if their Flink instance(s) are exposed. The issue was fixed in commit b561010b0ee741543c3953306037f00d7a9f0801 from apache/flink:master.

- [https://github.com/Osyanina/westone-CVE-2020-17519-scanner](https://github.com/Osyanina/westone-CVE-2020-17519-scanner) :  ![starts](https://img.shields.io/github/stars/Osyanina/westone-CVE-2020-17519-scanner.svg) ![forks](https://img.shields.io/github/forks/Osyanina/westone-CVE-2020-17519-scanner.svg)


## CVE-2020-15436
 Use-after-free vulnerability in fs/block_dev.c in the Linux kernel before 5.8 allows local users to gain privileges or cause a denial of service by leveraging improper access to a certain error field.

- [https://github.com/Trinadh465/linux-4.19.72_CVE-2020-15436](https://github.com/Trinadh465/linux-4.19.72_CVE-2020-15436) :  ![starts](https://img.shields.io/github/stars/Trinadh465/linux-4.19.72_CVE-2020-15436.svg) ![forks](https://img.shields.io/github/forks/Trinadh465/linux-4.19.72_CVE-2020-15436.svg)


## CVE-2018-16490
 A prototype pollution vulnerability was found in module mpath &lt;0.5.1 that allows an attacker to inject arbitrary properties onto Object.prototype.

- [https://github.com/ossf-cve-benchmark/CVE-2018-16490](https://github.com/ossf-cve-benchmark/CVE-2018-16490) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2018-16490.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2018-16490.svg)


## CVE-2015-3837
 The OpenSSLX509Certificate class in org/conscrypt/OpenSSLX509Certificate.java in Android before 5.1.1 LMY48I improperly includes certain context data during serialization and deserialization, which allows attackers to execute arbitrary code via an application that sends a crafted Intent, aka internal bug 21437603.

- [https://github.com/roeeh/conscryptchecker](https://github.com/roeeh/conscryptchecker) :  ![starts](https://img.shields.io/github/stars/roeeh/conscryptchecker.svg) ![forks](https://img.shields.io/github/forks/roeeh/conscryptchecker.svg)


## CVE-2014-0224
 OpenSSL before 0.9.8za, 1.0.0 before 1.0.0m, and 1.0.1 before 1.0.1h does not properly restrict processing of ChangeCipherSpec messages, which allows man-in-the-middle attackers to trigger use of a zero-length master key in certain OpenSSL-to-OpenSSL communications, and consequently hijack sessions or obtain sensitive information, via a crafted TLS handshake, aka the &quot;CCS Injection&quot; vulnerability.

- [https://github.com/secretnonempty/CVE-2014-0224](https://github.com/secretnonempty/CVE-2014-0224) :  ![starts](https://img.shields.io/github/stars/secretnonempty/CVE-2014-0224.svg) ![forks](https://img.shields.io/github/forks/secretnonempty/CVE-2014-0224.svg)
- [https://github.com/iph0n3/CVE-2014-0224](https://github.com/iph0n3/CVE-2014-0224) :  ![starts](https://img.shields.io/github/stars/iph0n3/CVE-2014-0224.svg) ![forks](https://img.shields.io/github/forks/iph0n3/CVE-2014-0224.svg)

