# Update 2023-11-10
## CVE-2023-46604
 Apache ActiveMQ is vulnerable to Remote Code Execution.The vulnerability may allow a remote attacker with network access to a broker to run arbitrary shell commands by manipulating serialized class types in the OpenWire protocol to cause the broker to instantiate any class on the classpath. Users are recommended to upgrade to version 5.15.16, 5.16.7, 5.17.6, or 5.18.3, which fixes this issue.

- [https://github.com/justdoit-cai/CVE-2023-46604-Apache-ActiveMQ-RCE-exp](https://github.com/justdoit-cai/CVE-2023-46604-Apache-ActiveMQ-RCE-exp) :  ![starts](https://img.shields.io/github/stars/justdoit-cai/CVE-2023-46604-Apache-ActiveMQ-RCE-exp.svg) ![forks](https://img.shields.io/github/forks/justdoit-cai/CVE-2023-46604-Apache-ActiveMQ-RCE-exp.svg)


## CVE-2023-38408
 The PKCS#11 feature in ssh-agent in OpenSSH before 9.3p2 has an insufficiently trustworthy search path, leading to remote code execution if an agent is forwarded to an attacker-controlled system. (Code in /usr/lib is not necessarily safe for loading into ssh-agent.) NOTE: this issue exists because of an incomplete fix for CVE-2016-10009.

- [https://github.com/LucasPDiniz/CVE-2023-38408](https://github.com/LucasPDiniz/CVE-2023-38408) :  ![starts](https://img.shields.io/github/stars/LucasPDiniz/CVE-2023-38408.svg) ![forks](https://img.shields.io/github/forks/LucasPDiniz/CVE-2023-38408.svg)


## CVE-2023-34048
 vCenter Server contains an out-of-bounds write vulnerability in the implementation of the DCERPC protocol. A malicious actor with network access to vCenter Server may trigger an out-of-bounds write potentially leading to remote code execution.

- [https://github.com/K1i7n/CVE-2023-34048-findings](https://github.com/K1i7n/CVE-2023-34048-findings) :  ![starts](https://img.shields.io/github/stars/K1i7n/CVE-2023-34048-findings.svg) ![forks](https://img.shields.io/github/forks/K1i7n/CVE-2023-34048-findings.svg)


## CVE-2023-22515
 Atlassian has been made aware of an issue reported by a handful of customers where external attackers may have exploited a previously unknown vulnerability in publicly accessible Confluence Data Center and Server instances to create unauthorized Confluence administrator accounts and access Confluence instances. Atlassian Cloud sites are not affected by this vulnerability. If your Confluence site is accessed via an atlassian.net domain, it is hosted by Atlassian and is not vulnerable to this issue.

- [https://github.com/LucasPDiniz/CVE-2023-22515](https://github.com/LucasPDiniz/CVE-2023-22515) :  ![starts](https://img.shields.io/github/stars/LucasPDiniz/CVE-2023-22515.svg) ![forks](https://img.shields.io/github/forks/LucasPDiniz/CVE-2023-22515.svg)


## CVE-2023-4911
 A buffer overflow was discovered in the GNU C Library's dynamic loader ld.so while processing the GLIBC_TUNABLES environment variable. This issue could allow a local attacker to use maliciously crafted GLIBC_TUNABLES environment variables when launching binaries with SUID permission to execute code with elevated privileges.

- [https://github.com/teraGL/looneyCVE](https://github.com/teraGL/looneyCVE) :  ![starts](https://img.shields.io/github/stars/teraGL/looneyCVE.svg) ![forks](https://img.shields.io/github/forks/teraGL/looneyCVE.svg)


## CVE-2023-1718
 Improper file stream access in /desktop_app/file.ajax.php?action=uploadfile in Bitrix24 22.0.300 allows unauthenticated remote attackers to cause denial-of-service via a crafted &quot;tmp_url&quot;.

- [https://github.com/jhonnybonny/Bitrix24DoS](https://github.com/jhonnybonny/Bitrix24DoS) :  ![starts](https://img.shields.io/github/stars/jhonnybonny/Bitrix24DoS.svg) ![forks](https://img.shields.io/github/forks/jhonnybonny/Bitrix24DoS.svg)


## CVE-2022-38766
 The remote keyless system on Renault ZOE 2021 vehicles sends 433.92 MHz RF signals from the same Rolling Codes set for each door-open request, which allows for a replay attack.

- [https://github.com/AUTOCRYPT-RED/CVE-2022-38766](https://github.com/AUTOCRYPT-RED/CVE-2022-38766) :  ![starts](https://img.shields.io/github/stars/AUTOCRYPT-RED/CVE-2022-38766.svg) ![forks](https://img.shields.io/github/forks/AUTOCRYPT-RED/CVE-2022-38766.svg)


## CVE-2022-3786
 A buffer overrun can be triggered in X.509 certificate verification, specifically in name constraint checking. Note that this occurs after certificate chain signature verification and requires either a CA to have signed a malicious certificate or for an application to continue certificate verification despite failure to construct a path to a trusted issuer. An attacker can craft a malicious email address in a certificate to overflow an arbitrary number of bytes containing the `.' character (decimal 46) on the stack. This buffer overflow could result in a crash (causing a denial of service). In a TLS client, this can be triggered by connecting to a malicious server. In a TLS server, this can be triggered if the server requests client authentication and a malicious client connects.

- [https://github.com/rbowes-r7/cve-2022-3602-and-cve-2022-3786-openssl-poc](https://github.com/rbowes-r7/cve-2022-3602-and-cve-2022-3786-openssl-poc) :  ![starts](https://img.shields.io/github/stars/rbowes-r7/cve-2022-3602-and-cve-2022-3786-openssl-poc.svg) ![forks](https://img.shields.io/github/forks/rbowes-r7/cve-2022-3602-and-cve-2022-3786-openssl-poc.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/mightysai1997/cve-2021-41773](https://github.com/mightysai1997/cve-2021-41773) :  ![starts](https://img.shields.io/github/stars/mightysai1997/cve-2021-41773.svg) ![forks](https://img.shields.io/github/forks/mightysai1997/cve-2021-41773.svg)
- [https://github.com/shiomiyan/CVE-2021-41773](https://github.com/shiomiyan/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/shiomiyan/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/shiomiyan/CVE-2021-41773.svg)
- [https://github.com/Plunder283/CVE-2021-41773](https://github.com/Plunder283/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/Plunder283/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/Plunder283/CVE-2021-41773.svg)
- [https://github.com/puckiestyle/CVE-2021-41773](https://github.com/puckiestyle/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/puckiestyle/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/puckiestyle/CVE-2021-41773.svg)


## CVE-2021-36749
 In the Druid ingestion system, the InputSource is used for reading data from a certain data source. However, the HTTP InputSource allows authenticated users to read data from other sources than intended, such as the local file system, with the privileges of the Druid server process. This is not an elevation of privilege when users access Druid directly, since Druid also provides the Local InputSource, which allows the same level of access. But it is problematic when users interact with Druid indirectly through an application that allows users to specify the HTTP InputSource, but not the Local InputSource. In this case, users could bypass the application-level restriction by passing a file URL to the HTTP InputSource. This issue was previously mentioned as being fixed in 0.21.0 as per CVE-2021-26920 but was not fixed in 0.21.0 or 0.21.1.

- [https://github.com/sma11new/PocList](https://github.com/sma11new/PocList) :  ![starts](https://img.shields.io/github/stars/sma11new/PocList.svg) ![forks](https://img.shields.io/github/forks/sma11new/PocList.svg)


## CVE-2021-26084
 In affected versions of Confluence Server and Data Center, an OGNL injection vulnerability exists that would allow an unauthenticated attacker to execute arbitrary code on a Confluence Server or Data Center instance. The affected versions are before version 6.13.23, from version 6.14.0 before 7.4.11, from version 7.5.0 before 7.11.6, and from version 7.12.0 before 7.12.5.

- [https://github.com/sma11new/PocList](https://github.com/sma11new/PocList) :  ![starts](https://img.shields.io/github/stars/sma11new/PocList.svg) ![forks](https://img.shields.io/github/forks/sma11new/PocList.svg)


## CVE-2020-14882
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Console). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0, 12.2.1.4.0 and 14.1.1.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/LucasPDiniz/CVE-2020-14882](https://github.com/LucasPDiniz/CVE-2020-14882) :  ![starts](https://img.shields.io/github/stars/LucasPDiniz/CVE-2020-14882.svg) ![forks](https://img.shields.io/github/forks/LucasPDiniz/CVE-2020-14882.svg)


## CVE-2020-2509
 A command injection vulnerability has been reported to affect QTS and QuTS hero. If exploited, this vulnerability allows attackers to execute arbitrary commands in a compromised application. We have already fixed this vulnerability in the following versions: QTS 4.5.2.1566 Build 20210202 and later QTS 4.5.1.1495 Build 20201123 and later QTS 4.3.6.1620 Build 20210322 and later QTS 4.3.4.1632 Build 20210324 and later QTS 4.3.3.1624 Build 20210416 and later QTS 4.2.6 Build 20210327 and later QuTS hero h4.5.1.1491 build 20201119 and later

- [https://github.com/jbaines-r7/overkill](https://github.com/jbaines-r7/overkill) :  ![starts](https://img.shields.io/github/stars/jbaines-r7/overkill.svg) ![forks](https://img.shields.io/github/forks/jbaines-r7/overkill.svg)


## CVE-2020-0181
 In exif_data_load_data_thumbnail of exif-data.c, there is a possible denial of service due to an integer overflow. This could lead to remote denial of service with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-10Android ID: A-145075076

- [https://github.com/Trinadh465/external_libexif_AOSP10_r33_CVE-2020-0181](https://github.com/Trinadh465/external_libexif_AOSP10_r33_CVE-2020-0181) :  ![starts](https://img.shields.io/github/stars/Trinadh465/external_libexif_AOSP10_r33_CVE-2020-0181.svg) ![forks](https://img.shields.io/github/forks/Trinadh465/external_libexif_AOSP10_r33_CVE-2020-0181.svg)


## CVE-2019-20372
 NGINX before 1.17.7, with certain error_page configurations, allows HTTP request smuggling, as demonstrated by the ability of an attacker to read unauthorized web pages in environments where NGINX is being fronted by a load balancer.

- [https://github.com/0xleft/CVE-2019-20372](https://github.com/0xleft/CVE-2019-20372) :  ![starts](https://img.shields.io/github/stars/0xleft/CVE-2019-20372.svg) ![forks](https://img.shields.io/github/forks/0xleft/CVE-2019-20372.svg)


## CVE-2019-15107
 An issue was discovered in Webmin &lt;=1.920. The parameter old in password_change.cgi contains a command injection vulnerability.

- [https://github.com/olingo99/CVE-2019-15107](https://github.com/olingo99/CVE-2019-15107) :  ![starts](https://img.shields.io/github/stars/olingo99/CVE-2019-15107.svg) ![forks](https://img.shields.io/github/forks/olingo99/CVE-2019-15107.svg)


## CVE-2019-12725
 Zeroshell 3.9.0 is prone to a remote command execution vulnerability. Specifically, this issue occurs because the web application mishandles a few HTTP parameters. An unauthenticated attacker can exploit this issue by injecting OS commands inside the vulnerable parameters.

- [https://github.com/sma11new/PocList](https://github.com/sma11new/PocList) :  ![starts](https://img.shields.io/github/stars/sma11new/PocList.svg) ![forks](https://img.shields.io/github/forks/sma11new/PocList.svg)


## CVE-2019-9978
 The social-warfare plugin before 3.5.3 for WordPress has stored XSS via the wp-admin/admin-post.php?swp_debug=load_options swp_url parameter, as exploited in the wild in March 2019. This affects Social Warfare and Social Warfare Pro.

- [https://github.com/0xMoonrise/cve-2019-9978](https://github.com/0xMoonrise/cve-2019-9978) :  ![starts](https://img.shields.io/github/stars/0xMoonrise/cve-2019-9978.svg) ![forks](https://img.shields.io/github/forks/0xMoonrise/cve-2019-9978.svg)


## CVE-2018-12798
 Adobe Acrobat and Reader 2018.011.20040 and earlier, 2017.011.30080 and earlier, and 2015.006.30418 and earlier versions have a Heap Overflow vulnerability. Successful exploitation could lead to arbitrary code execution in the context of the current user.

- [https://github.com/sharmasandeepkr/cve-2018-12798](https://github.com/sharmasandeepkr/cve-2018-12798) :  ![starts](https://img.shields.io/github/stars/sharmasandeepkr/cve-2018-12798.svg) ![forks](https://img.shields.io/github/forks/sharmasandeepkr/cve-2018-12798.svg)


## CVE-2018-6574
 Go before 1.8.7, Go 1.9.x before 1.9.4, and Go 1.10 pre-releases before Go 1.10rc2 allow &quot;go get&quot; remote command execution during source code build, by leveraging the gcc or clang plugin feature, because -fplugin= and -plugin= arguments were not blocked.

- [https://github.com/Ashved9/Orange](https://github.com/Ashved9/Orange) :  ![starts](https://img.shields.io/github/stars/Ashved9/Orange.svg) ![forks](https://img.shields.io/github/forks/Ashved9/Orange.svg)


## CVE-2017-8570
 Microsoft Office allows a remote code execution vulnerability due to the way that it handles objects in memory, aka &quot;Microsoft Office Remote Code Execution Vulnerability&quot;. This CVE ID is unique from CVE-2017-0243.

- [https://github.com/temesgeny/ppsx-file-generator](https://github.com/temesgeny/ppsx-file-generator) :  ![starts](https://img.shields.io/github/stars/temesgeny/ppsx-file-generator.svg) ![forks](https://img.shields.io/github/forks/temesgeny/ppsx-file-generator.svg)


## CVE-2016-0702
 The MOD_EXP_CTIME_COPY_FROM_PREBUF function in crypto/bn/bn_exp.c in OpenSSL 1.0.1 before 1.0.1s and 1.0.2 before 1.0.2g does not properly consider cache-bank access times during modular exponentiation, which makes it easier for local users to discover RSA keys by running a crafted application on the same Intel Sandy Bridge CPU core as a victim and leveraging cache-bank conflicts, aka a &quot;CacheBleed&quot; attack.

- [https://github.com/Trinadh465/OpenSSL-1_0_1g_CVE-2016-0702](https://github.com/Trinadh465/OpenSSL-1_0_1g_CVE-2016-0702) :  ![starts](https://img.shields.io/github/stars/Trinadh465/OpenSSL-1_0_1g_CVE-2016-0702.svg) ![forks](https://img.shields.io/github/forks/Trinadh465/OpenSSL-1_0_1g_CVE-2016-0702.svg)


## CVE-2014-5139
 The ssl_set_client_disabled function in t1_lib.c in OpenSSL 1.0.1 before 1.0.1i allows remote SSL servers to cause a denial of service (NULL pointer dereference and client application crash) via a ServerHello message that includes an SRP ciphersuite without the required negotiation of that ciphersuite with the client.

- [https://github.com/uthrasri/G2.5_openssl_CVE-2014-5139](https://github.com/uthrasri/G2.5_openssl_CVE-2014-5139) :  ![starts](https://img.shields.io/github/stars/uthrasri/G2.5_openssl_CVE-2014-5139.svg) ![forks](https://img.shields.io/github/forks/uthrasri/G2.5_openssl_CVE-2014-5139.svg)


## CVE-2009-1151
 Static code injection vulnerability in setup.php in phpMyAdmin 2.11.x before 2.11.9.5 and 3.x before 3.1.3.1 allows remote attackers to inject arbitrary PHP code into a configuration file via the save action.

- [https://github.com/adpast/pocs](https://github.com/adpast/pocs) :  ![starts](https://img.shields.io/github/stars/adpast/pocs.svg) ![forks](https://img.shields.io/github/forks/adpast/pocs.svg)

