# Update 2022-04-22
## CVE-2022-29464
 Certain WSO2 products allow unrestricted file upload with resultant remote code execution. This affects WSO2 API Manager 2.2.0 and above through 4.0.0; WSO2 Identity Server 5.2.0 and above through 5.11.0; WSO2 Identity Server Analytics 5.4.0, 5.4.1, 5.5.0, and 5.6.0; WSO2 Identity Server as Key Manager 5.3.0 and above through 5.10.0; and WSO2 Enterprise Integrator 6.2.0 and above through 6.6.0.

- [https://github.com/hakivvi/CVE-2022-29464](https://github.com/hakivvi/CVE-2022-29464) :  ![starts](https://img.shields.io/github/stars/hakivvi/CVE-2022-29464.svg) ![forks](https://img.shields.io/github/forks/hakivvi/CVE-2022-29464.svg)


## CVE-2022-26809
 Remote Procedure Call Runtime Remote Code Execution Vulnerability. This CVE ID is unique from CVE-2022-24492, CVE-2022-24528.

- [https://github.com/DESC0N0C1D0/CVE-2022-26809-RCE](https://github.com/DESC0N0C1D0/CVE-2022-26809-RCE) :  ![starts](https://img.shields.io/github/stars/DESC0N0C1D0/CVE-2022-26809-RCE.svg) ![forks](https://img.shields.io/github/forks/DESC0N0C1D0/CVE-2022-26809-RCE.svg)


## CVE-2022-21449
 Vulnerability in the Oracle Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component: Libraries). Supported versions that are affected are Oracle Java SE: 7u331, 8u321, 11.0.14, 17.0.2, 18; Oracle GraalVM Enterprise Edition: 20.3.5, 21.3.1 and 22.0.0.2. Easily exploitable vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise Oracle Java SE, Oracle GraalVM Enterprise Edition. Successful attacks of this vulnerability can result in unauthorized creation, deletion or modification access to critical data or all Oracle Java SE, Oracle GraalVM Enterprise Edition accessible data. Note: This vulnerability applies to Java deployments, typically in clients running sandboxed Java Web Start applications or sandboxed Java applets, that load and run untrusted code (e.g., code that comes from the internet) and rely on the Java sandbox for security. This vulnerability can also be exploited by using APIs in the specified Component, e.g., through a web service which supplies data to the APIs. CVSS 3.1 Base Score 7.5 (Integrity impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N).

- [https://github.com/jmiettinen/CVE-2022-21449-vuln-test](https://github.com/jmiettinen/CVE-2022-21449-vuln-test) :  ![starts](https://img.shields.io/github/stars/jmiettinen/CVE-2022-21449-vuln-test.svg) ![forks](https://img.shields.io/github/forks/jmiettinen/CVE-2022-21449-vuln-test.svg)
- [https://github.com/jfrog/jfrog-CVE-2022-21449](https://github.com/jfrog/jfrog-CVE-2022-21449) :  ![starts](https://img.shields.io/github/stars/jfrog/jfrog-CVE-2022-21449.svg) ![forks](https://img.shields.io/github/forks/jfrog/jfrog-CVE-2022-21449.svg)
- [https://github.com/khalednassar/CVE-2022-21449-TLS-PoC](https://github.com/khalednassar/CVE-2022-21449-TLS-PoC) :  ![starts](https://img.shields.io/github/stars/khalednassar/CVE-2022-21449-TLS-PoC.svg) ![forks](https://img.shields.io/github/forks/khalednassar/CVE-2022-21449-TLS-PoC.svg)


## CVE-2022-0778
 The BN_mod_sqrt() function, which computes a modular square root, contains a bug that can cause it to loop forever for non-prime moduli. Internally this function is used when parsing certificates that contain elliptic curve public keys in compressed form or explicit elliptic curve parameters with a base point encoded in compressed form. It is possible to trigger the infinite loop by crafting a certificate that has invalid explicit curve parameters. Since certificate parsing happens prior to verification of the certificate signature, any process that parses an externally supplied certificate may thus be subject to a denial of service attack. The infinite loop can also be reached when parsing crafted private keys as they can contain explicit elliptic curve parameters. Thus vulnerable situations include: - TLS clients consuming server certificates - TLS servers consuming client certificates - Hosting providers taking certificates or private keys from customers - Certificate authorities parsing certification requests from subscribers - Anything else which parses ASN.1 elliptic curve parameters Also any other applications that use the BN_mod_sqrt() where the attacker can control the parameter values are vulnerable to this DoS issue. In the OpenSSL 1.0.2 version the public key is not parsed during initial parsing of the certificate which makes it slightly harder to trigger the infinite loop. However any operation which requires the public key from the certificate will trigger the infinite loop. In particular the attacker can use a self-signed certificate to trigger the loop during verification of the certificate signature. This issue affects OpenSSL versions 1.0.2, 1.1.1 and 3.0. It was addressed in the releases of 1.1.1n and 3.0.2 on the 15th March 2022. Fixed in OpenSSL 3.0.2 (Affected 3.0.0,3.0.1). Fixed in OpenSSL 1.1.1n (Affected 1.1.1-1.1.1m). Fixed in OpenSSL 1.0.2zd (Affected 1.0.2-1.0.2zc).

- [https://github.com/0xUhaw/CVE-2022-0778](https://github.com/0xUhaw/CVE-2022-0778) :  ![starts](https://img.shields.io/github/stars/0xUhaw/CVE-2022-0778.svg) ![forks](https://img.shields.io/github/forks/0xUhaw/CVE-2022-0778.svg)


## CVE-2021-36981
 In the server in SerNet verinice before 1.22.2, insecure Java deserialization allows remote authenticated attackers to execute arbitrary code.

- [https://github.com/0xBrAinsTorM/CVE-2021-36981](https://github.com/0xBrAinsTorM/CVE-2021-36981) :  ![starts](https://img.shields.io/github/stars/0xBrAinsTorM/CVE-2021-36981.svg) ![forks](https://img.shields.io/github/forks/0xBrAinsTorM/CVE-2021-36981.svg)


## CVE-2021-36798
 A Denial-of-Service (DoS) vulnerability was discovered in Team Server in HelpSystems Cobalt Strike 4.2 and 4.3. It allows remote attackers to crash the C2 server thread and block beacons' communication with it.

- [https://github.com/hariomenkel/CobaltSploit](https://github.com/hariomenkel/CobaltSploit) :  ![starts](https://img.shields.io/github/stars/hariomenkel/CobaltSploit.svg) ![forks](https://img.shields.io/github/forks/hariomenkel/CobaltSploit.svg)


## CVE-2021-27905
 The ReplicationHandler (normally registered at &quot;/replication&quot; under a Solr core) in Apache Solr has a &quot;masterUrl&quot; (also &quot;leaderUrl&quot; alias) parameter that is used to designate another ReplicationHandler on another Solr core to replicate index data into the local core. To prevent a SSRF vulnerability, Solr ought to check these parameters against a similar configuration it uses for the &quot;shards&quot; parameter. Prior to this bug getting fixed, it did not. This problem affects essentially all Solr versions prior to it getting fixed in 8.8.2.

- [https://github.com/CLincat/vulcat](https://github.com/CLincat/vulcat) :  ![starts](https://img.shields.io/github/stars/CLincat/vulcat.svg) ![forks](https://img.shields.io/github/forks/CLincat/vulcat.svg)


## CVE-2021-0510
 In decrypt_1_2 of CryptoPlugin.cpp, there is a possible out of bounds write due to an integer overflow. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-9 Android-10 Android-11 Android-8.1Android ID: A-176444622

- [https://github.com/pazhanivel07/hardware_interfaces-A10_r33_CVE-2021-0510](https://github.com/pazhanivel07/hardware_interfaces-A10_r33_CVE-2021-0510) :  ![starts](https://img.shields.io/github/stars/pazhanivel07/hardware_interfaces-A10_r33_CVE-2021-0510.svg) ![forks](https://img.shields.io/github/forks/pazhanivel07/hardware_interfaces-A10_r33_CVE-2021-0510.svg)


## CVE-2021-0475
 In on_l2cap_data_ind of btif_sock_l2cap.cc, there is possible memory corruption due to a use after free. This could lead to remote code execution over Bluetooth with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-11 Android-10Android ID: A-175686168

- [https://github.com/ShaikUsaf/system_bt_AOSP10_r33_CVE-2021-0475](https://github.com/ShaikUsaf/system_bt_AOSP10_r33_CVE-2021-0475) :  ![starts](https://img.shields.io/github/stars/ShaikUsaf/system_bt_AOSP10_r33_CVE-2021-0475.svg) ![forks](https://img.shields.io/github/forks/ShaikUsaf/system_bt_AOSP10_r33_CVE-2021-0475.svg)


## CVE-2021-0433
 In onCreate of DeviceChooserActivity.java, there is a possible way to bypass user consent when pairing a Bluetooth device due to a tapjacking/overlay attack. This could lead to local escalation of privilege and pairing malicious devices with no additional execution privileges needed. User interaction is needed for exploitation.Product: AndroidVersions: Android-8.1 Android-9 Android-10 Android-11Android ID: A-171221090

- [https://github.com/Trinadh465/frameworks_base_AOSP10_r33_CVE-2021-0433](https://github.com/Trinadh465/frameworks_base_AOSP10_r33_CVE-2021-0433) :  ![starts](https://img.shields.io/github/stars/Trinadh465/frameworks_base_AOSP10_r33_CVE-2021-0433.svg) ![forks](https://img.shields.io/github/forks/Trinadh465/frameworks_base_AOSP10_r33_CVE-2021-0433.svg)


## CVE-2020-36109
 ASUS RT-AX86U router firmware below version under 9.0.0.4_386 has a buffer overflow in the blocking_request.cgi function of the httpd module that can cause code execution when an attacker constructs malicious data.

- [https://github.com/sunn1day/CVE-2020-36109-POC](https://github.com/sunn1day/CVE-2020-36109-POC) :  ![starts](https://img.shields.io/github/stars/sunn1day/CVE-2020-36109-POC.svg) ![forks](https://img.shields.io/github/forks/sunn1day/CVE-2020-36109-POC.svg)


## CVE-2020-0458
 In SPDIFEncoder::writeBurstBufferBytes and related methods of SPDIFEncoder.cpp, there is a possible out of bounds write due to an integer overflow. This could lead to remote code execution with no additional execution privileges needed. User interaction is needed for exploitation.Product: AndroidVersions: Android-9 Android-10 Android-8.0 Android-8.1Android ID: A-160265164

- [https://github.com/nanopathi/system_media_AOSP10_r33_CVE-2020-0458](https://github.com/nanopathi/system_media_AOSP10_r33_CVE-2020-0458) :  ![starts](https://img.shields.io/github/stars/nanopathi/system_media_AOSP10_r33_CVE-2020-0458.svg) ![forks](https://img.shields.io/github/forks/nanopathi/system_media_AOSP10_r33_CVE-2020-0458.svg)


## CVE-2019-12086
 A Polymorphic Typing issue was discovered in FasterXML jackson-databind 2.x before 2.9.9. When Default Typing is enabled (either globally or for a specific property) for an externally exposed JSON endpoint, the service has the mysql-connector-java jar (8.0.14 or earlier) in the classpath, and an attacker can host a crafted MySQL server reachable by the victim, an attacker can send a crafted JSON message that allows them to read arbitrary local files on the server. This occurs because of missing com.mysql.cj.jdbc.admin.MiniAdmin validation.

- [https://github.com/SimoLin/CVE-2019-12086-jackson-databind-file-read](https://github.com/SimoLin/CVE-2019-12086-jackson-databind-file-read) :  ![starts](https://img.shields.io/github/stars/SimoLin/CVE-2019-12086-jackson-databind-file-read.svg) ![forks](https://img.shields.io/github/forks/SimoLin/CVE-2019-12086-jackson-databind-file-read.svg)


## CVE-2018-14714
 System command injection in appGet.cgi on ASUS RT-AC3200 version 3.0.0.4.382.50010 allows attackers to execute system commands via the &quot;load_script&quot; URL parameter.

- [https://github.com/sunn1day/CVE-2018-14714-POC](https://github.com/sunn1day/CVE-2018-14714-POC) :  ![starts](https://img.shields.io/github/stars/sunn1day/CVE-2018-14714-POC.svg) ![forks](https://img.shields.io/github/forks/sunn1day/CVE-2018-14714-POC.svg)


## CVE-2018-6574
 Go before 1.8.7, Go 1.9.x before 1.9.4, and Go 1.10 pre-releases before Go 1.10rc2 allow &quot;go get&quot; remote command execution during source code build, by leveraging the gcc or clang plugin feature, because -fplugin= and -plugin= arguments were not blocked.

- [https://github.com/yavolo/CVE-2018-6574](https://github.com/yavolo/CVE-2018-6574) :  ![starts](https://img.shields.io/github/stars/yavolo/CVE-2018-6574.svg) ![forks](https://img.shields.io/github/forks/yavolo/CVE-2018-6574.svg)


## CVE-2017-9841
 Util/PHP/eval-stdin.php in PHPUnit before 4.8.28 and 5.x before 5.6.3 allows remote attackers to execute arbitrary PHP code via HTTP POST data beginning with a &quot;&lt;?php &quot; substring, as demonstrated by an attack on a site with an exposed /vendor folder, i.e., external access to the /vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php URI.

- [https://github.com/mbrasile/CVE-2017-9841](https://github.com/mbrasile/CVE-2017-9841) :  ![starts](https://img.shields.io/github/stars/mbrasile/CVE-2017-9841.svg) ![forks](https://img.shields.io/github/forks/mbrasile/CVE-2017-9841.svg)
- [https://github.com/akr3ch/CVE-2017-9841](https://github.com/akr3ch/CVE-2017-9841) :  ![starts](https://img.shields.io/github/stars/akr3ch/CVE-2017-9841.svg) ![forks](https://img.shields.io/github/forks/akr3ch/CVE-2017-9841.svg)
- [https://github.com/jax7sec/CVE-2017-9841](https://github.com/jax7sec/CVE-2017-9841) :  ![starts](https://img.shields.io/github/stars/jax7sec/CVE-2017-9841.svg) ![forks](https://img.shields.io/github/forks/jax7sec/CVE-2017-9841.svg)


## CVE-2016-10924
 The ebook-download plugin before 1.2 for WordPress has directory traversal.

- [https://github.com/rvizx/CVE-2016-10924](https://github.com/rvizx/CVE-2016-10924) :  ![starts](https://img.shields.io/github/stars/rvizx/CVE-2016-10924.svg) ![forks](https://img.shields.io/github/forks/rvizx/CVE-2016-10924.svg)

