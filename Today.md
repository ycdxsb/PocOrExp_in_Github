# Update 2023-04-20
## CVE-2023-27216
 An issue found in D-Link DSL-3782 v.1.03 allows remote authenticated users to execute arbitrary code as root via the network settings page.

- [https://github.com/FzBacon/CVE-2023-27216_D-Link_DSL-3782_Router_command_injection](https://github.com/FzBacon/CVE-2023-27216_D-Link_DSL-3782_Router_command_injection) :  ![starts](https://img.shields.io/github/stars/FzBacon/CVE-2023-27216_D-Link_DSL-3782_Router_command_injection.svg) ![forks](https://img.shields.io/github/forks/FzBacon/CVE-2023-27216_D-Link_DSL-3782_Router_command_injection.svg)


## CVE-2023-25136
 OpenSSH server (sshd) 9.1 introduced a double-free vulnerability during options.kex_algorithms handling. This is fixed in OpenSSH 9.2. The double free can be leveraged, by an unauthenticated remote attacker in the default configuration, to jump to any location in the sshd address space. One third-party report states &quot;remote code execution is theoretically possible.&quot;

- [https://github.com/adhikara13/CVE-2023-25136](https://github.com/adhikara13/CVE-2023-25136) :  ![starts](https://img.shields.io/github/stars/adhikara13/CVE-2023-25136.svg) ![forks](https://img.shields.io/github/forks/adhikara13/CVE-2023-25136.svg)


## CVE-2023-21554
 Microsoft Message Queuing Remote Code Execution Vulnerability

- [https://github.com/Hashi0x/PoC-CVE-2023-21554](https://github.com/Hashi0x/PoC-CVE-2023-21554) :  ![starts](https://img.shields.io/github/stars/Hashi0x/PoC-CVE-2023-21554.svg) ![forks](https://img.shields.io/github/forks/Hashi0x/PoC-CVE-2023-21554.svg)


## CVE-2023-2002
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/lrh2000/CVE-2023-2002](https://github.com/lrh2000/CVE-2023-2002) :  ![starts](https://img.shields.io/github/stars/lrh2000/CVE-2023-2002.svg) ![forks](https://img.shields.io/github/forks/lrh2000/CVE-2023-2002.svg)


## CVE-2023-0215
 The public API function BIO_new_NDEF is a helper function used for streaming ASN.1 data via a BIO. It is primarily used internally to OpenSSL to support the SMIME, CMS and PKCS7 streaming capabilities, but may also be called directly by end user applications. The function receives a BIO from the caller, prepends a new BIO_f_asn1 filter BIO onto the front of it to form a BIO chain, and then returns the new head of the BIO chain to the caller. Under certain conditions, for example if a CMS recipient public key is invalid, the new filter BIO is freed and the function returns a NULL result indicating a failure. However, in this case, the BIO chain is not properly cleaned up and the BIO passed by the caller still retains internal pointers to the previously freed filter BIO. If the caller then goes on to call BIO_pop() on the BIO then a use-after-free will occur. This will most likely result in a crash. This scenario occurs directly in the internal function B64_write_ASN1() which may cause BIO_new_NDEF() to be called and will subsequently call BIO_pop() on the BIO. This internal function is in turn called by the public API functions PEM_write_bio_ASN1_stream, PEM_write_bio_CMS_stream, PEM_write_bio_PKCS7_stream, SMIME_write_ASN1, SMIME_write_CMS and SMIME_write_PKCS7. Other public API functions that may be impacted by this include i2d_ASN1_bio_stream, BIO_new_CMS, BIO_new_PKCS7, i2d_CMS_bio_stream and i2d_PKCS7_bio_stream. The OpenSSL cms and smime command line applications are similarly affected.

- [https://github.com/nidhi7598/OPENSSL_1.0.2_G2.5_CVE-2023-0215](https://github.com/nidhi7598/OPENSSL_1.0.2_G2.5_CVE-2023-0215) :  ![starts](https://img.shields.io/github/stars/nidhi7598/OPENSSL_1.0.2_G2.5_CVE-2023-0215.svg) ![forks](https://img.shields.io/github/forks/nidhi7598/OPENSSL_1.0.2_G2.5_CVE-2023-0215.svg)


## CVE-2022-42889
 Apache Commons Text performs variable interpolation, allowing properties to be dynamically evaluated and expanded. The standard format for interpolation is &quot;${prefix:name}&quot;, where &quot;prefix&quot; is used to locate an instance of org.apache.commons.text.lookup.StringLookup that performs the interpolation. Starting with version 1.5 and continuing through 1.9, the set of default Lookup instances included interpolators that could result in arbitrary code execution or contact with remote servers. These lookups are: - &quot;script&quot; - execute expressions using the JVM script execution engine (javax.script) - &quot;dns&quot; - resolve dns records - &quot;url&quot; - load values from urls, including from remote servers Applications using the interpolation defaults in the affected versions may be vulnerable to remote code execution or unintentional contact with remote servers if untrusted configuration values are used. Users are recommended to upgrade to Apache Commons Text 1.10.0, which disables the problematic interpolators by default.

- [https://github.com/Dima2021/cve-2022-42889-text4shell](https://github.com/Dima2021/cve-2022-42889-text4shell) :  ![starts](https://img.shields.io/github/stars/Dima2021/cve-2022-42889-text4shell.svg) ![forks](https://img.shields.io/github/forks/Dima2021/cve-2022-42889-text4shell.svg)


## CVE-2022-34169
 The Apache Xalan Java XSLT library is vulnerable to an integer truncation issue when processing malicious XSLT stylesheets. This can be used to corrupt Java class files generated by the internal XSLTC compiler and execute arbitrary Java bytecode. The Apache Xalan Java project is dormant and in the process of being retired. No future releases of Apache Xalan Java to address this issue are expected. Note: Java runtimes (such as OpenJDK) include repackaged copies of Xalan.

- [https://github.com/bor8/CVE-2022-34169](https://github.com/bor8/CVE-2022-34169) :  ![starts](https://img.shields.io/github/stars/bor8/CVE-2022-34169.svg) ![forks](https://img.shields.io/github/forks/bor8/CVE-2022-34169.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/DoTuan1/Reserch-CVE-2021-41773](https://github.com/DoTuan1/Reserch-CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/DoTuan1/Reserch-CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/DoTuan1/Reserch-CVE-2021-41773.svg)
- [https://github.com/mightysai1997/CVE-2021-41773-i-](https://github.com/mightysai1997/CVE-2021-41773-i-) :  ![starts](https://img.shields.io/github/stars/mightysai1997/CVE-2021-41773-i-.svg) ![forks](https://img.shields.io/github/forks/mightysai1997/CVE-2021-41773-i-.svg)


## CVE-2021-3129
 Ignition before 2.5.2, as used in Laravel and other products, allows unauthenticated remote attackers to execute arbitrary code because of insecure usage of file_get_contents() and file_put_contents(). This is exploitable on sites using debug mode with Laravel before 8.4.2.

- [https://github.com/zhzyker/vulmap](https://github.com/zhzyker/vulmap) :  ![starts](https://img.shields.io/github/stars/zhzyker/vulmap.svg) ![forks](https://img.shields.io/github/forks/zhzyker/vulmap.svg)


## CVE-2019-1458
 An elevation of privilege vulnerability exists in Windows when the Win32k component fails to properly handle objects in memory, aka 'Win32k Elevation of Privilege Vulnerability'.

- [https://github.com/Eternit7/CVE-2019-1458](https://github.com/Eternit7/CVE-2019-1458) :  ![starts](https://img.shields.io/github/stars/Eternit7/CVE-2019-1458.svg) ![forks](https://img.shields.io/github/forks/Eternit7/CVE-2019-1458.svg)


## CVE-2019-1132
 An elevation of privilege vulnerability exists in Windows when the Win32k component fails to properly handle objects in memory, aka 'Win32k Elevation of Privilege Vulnerability'.

- [https://github.com/Vlad-tri/CVE-2019-1132](https://github.com/Vlad-tri/CVE-2019-1132) :  ![starts](https://img.shields.io/github/stars/Vlad-tri/CVE-2019-1132.svg) ![forks](https://img.shields.io/github/forks/Vlad-tri/CVE-2019-1132.svg)


## CVE-2018-16373
 Frog CMS 0.9.5 has an Upload vulnerability that can create files via /admin/?/plugin/file_manager/save.

- [https://github.com/snappyJack/CVE-2018-16373](https://github.com/snappyJack/CVE-2018-16373) :  ![starts](https://img.shields.io/github/stars/snappyJack/CVE-2018-16373.svg) ![forks](https://img.shields.io/github/forks/snappyJack/CVE-2018-16373.svg)


## CVE-2017-18353
 Rendertron 1.0.0 includes an _ah/stop route to shutdown the Chrome instance responsible for serving render requests to all users. Visiting this route with a GET request allows any unauthorized remote attacker to disable the core service of the application.

- [https://github.com/ossf-cve-benchmark/CVE-2017-18353](https://github.com/ossf-cve-benchmark/CVE-2017-18353) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-18353.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-18353.svg)

