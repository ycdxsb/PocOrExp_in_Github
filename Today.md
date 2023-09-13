# Update 2023-09-13
## CVE-2023-42471
 The wave.ai.browser application through 1.0.35 for Android allows a remote attacker to execute arbitrary JavaScript code via a crafted intent. It contains a manifest entry that exports the wave.ai.browser.ui.splash.SplashScreen activity. This activity uses a WebView component to display web content and doesn't adequately validate or sanitize the URI or any extra data passed in the intent by a third party application (with no permissions).

- [https://github.com/actuator/wave.ai.browser](https://github.com/actuator/wave.ai.browser) :  ![starts](https://img.shields.io/github/stars/actuator/wave.ai.browser.svg) ![forks](https://img.shields.io/github/forks/actuator/wave.ai.browser.svg)


## CVE-2023-42470
 The Imou Life com.mm.android.smartlifeiot application through 6.8.0 for Android allows Remote Code Execution via a crafted intent to an exported component. This relates to the com.mm.android.easy4ip.MainActivity activity. JavaScript execution is enabled in the WebView, and direct web content loading occurs.

- [https://github.com/actuator/imou](https://github.com/actuator/imou) :  ![starts](https://img.shields.io/github/stars/actuator/imou.svg) ![forks](https://img.shields.io/github/forks/actuator/imou.svg)


## CVE-2023-42469
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/actuator/com.full.dialer.top.secure.encrypted](https://github.com/actuator/com.full.dialer.top.secure.encrypted) :  ![starts](https://img.shields.io/github/stars/actuator/com.full.dialer.top.secure.encrypted.svg) ![forks](https://img.shields.io/github/forks/actuator/com.full.dialer.top.secure.encrypted.svg)


## CVE-2023-42468
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/actuator/com.cutestudio.colordialer](https://github.com/actuator/com.cutestudio.colordialer) :  ![starts](https://img.shields.io/github/stars/actuator/com.cutestudio.colordialer.svg) ![forks](https://img.shields.io/github/forks/actuator/com.cutestudio.colordialer.svg)


## CVE-2023-41362
 MyBB before 1.8.36 allows Code Injection by users with certain high privileges. Templates in Admin CP intentionally use eval, and there was some validation of the input to eval, but type juggling interfered with this when using PCRE within PHP.

- [https://github.com/SorceryIE/CVE-2023-41362_MyBB_ACP_RCE](https://github.com/SorceryIE/CVE-2023-41362_MyBB_ACP_RCE) :  ![starts](https://img.shields.io/github/stars/SorceryIE/CVE-2023-41362_MyBB_ACP_RCE.svg) ![forks](https://img.shields.io/github/forks/SorceryIE/CVE-2023-41362_MyBB_ACP_RCE.svg)


## CVE-2023-35674
 In onCreate of WindowState.java, there is a possible way to launch a background activity due to a logic error in the code. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/Thampakon/CVE-2023-35674](https://github.com/Thampakon/CVE-2023-35674) :  ![starts](https://img.shields.io/github/stars/Thampakon/CVE-2023-35674.svg) ![forks](https://img.shields.io/github/forks/Thampakon/CVE-2023-35674.svg)


## CVE-2023-27470
 BASupSrvcUpdater.exe in N-able Take Control Agent through 7.0.41.1141 before 7.0.43 has a TOCTOU Race Condition via a pseudo-symlink at %PROGRAMDATA%\GetSupportService_N-Central\PushUpdates, leading to arbitrary file deletion.

- [https://github.com/3lp4tr0n/CVE-2023-27470_Exercise](https://github.com/3lp4tr0n/CVE-2023-27470_Exercise) :  ![starts](https://img.shields.io/github/stars/3lp4tr0n/CVE-2023-27470_Exercise.svg) ![forks](https://img.shields.io/github/forks/3lp4tr0n/CVE-2023-27470_Exercise.svg)


## CVE-2023-4350
 Inappropriate implementation in Fullscreen in Google Chrome on Android prior to 116.0.5845.96 allowed a remote attacker to potentially spoof the contents of the Omnibox (URL bar) via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/0nyx-hkr/cve-2023-4350](https://github.com/0nyx-hkr/cve-2023-4350) :  ![starts](https://img.shields.io/github/stars/0nyx-hkr/cve-2023-4350.svg) ![forks](https://img.shields.io/github/forks/0nyx-hkr/cve-2023-4350.svg)


## CVE-2023-4238
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/codeb0ss/CVE-2023-4238-PoC](https://github.com/codeb0ss/CVE-2023-4238-PoC) :  ![starts](https://img.shields.io/github/stars/codeb0ss/CVE-2023-4238-PoC.svg) ![forks](https://img.shields.io/github/forks/codeb0ss/CVE-2023-4238-PoC.svg)


## CVE-2023-2916
 The InfiniteWP Client plugin for WordPress is vulnerable to Sensitive Information Exposure in versions up to, and including, 1.11.1 via the 'admin_notice' function. This can allow authenticated attackers with subscriber-level permissions or above to extract sensitive data including configuration. It can only be exploited if the plugin has not been configured yet. If combined with another arbitrary plugin installation and activation vulnerability, it may be possible to connect a site to InfiniteWP which would make remote management possible and allow for elevation of privileges.

- [https://github.com/d0rb/CVE-2023-2916](https://github.com/d0rb/CVE-2023-2916) :  ![starts](https://img.shields.io/github/stars/d0rb/CVE-2023-2916.svg) ![forks](https://img.shields.io/github/forks/d0rb/CVE-2023-2916.svg)


## CVE-2023-1273
 The ND Shortcodes WordPress plugin before 7.0 does not validate some shortcode attributes before using them to generate paths passed to include function/s, allowing any authenticated users such as subscriber to perform LFI attacks

- [https://github.com/codeb0ss/CVE-2023-1273-PoC](https://github.com/codeb0ss/CVE-2023-1273-PoC) :  ![starts](https://img.shields.io/github/stars/codeb0ss/CVE-2023-1273-PoC.svg) ![forks](https://img.shields.io/github/forks/codeb0ss/CVE-2023-1273-PoC.svg)


## CVE-2023-0159
 The Extensive VC Addons for WPBakery page builder WordPress plugin before 1.9.1 does not validate a parameter passed to the php extract function when loading templates, allowing an unauthenticated attacker to override the template path to read arbitrary files from the hosts file system.

- [https://github.com/im-hanzou/EVCer](https://github.com/im-hanzou/EVCer) :  ![starts](https://img.shields.io/github/stars/im-hanzou/EVCer.svg) ![forks](https://img.shields.io/github/forks/im-hanzou/EVCer.svg)


## CVE-2022-4063
 The InPost Gallery WordPress plugin before 2.1.4.1 insecurely uses PHP's extract() function when rendering HTML views, allowing attackers to force the inclusion of malicious files &amp; URLs, which may enable them to run code on servers.

- [https://github.com/im-hanzou/INPGer](https://github.com/im-hanzou/INPGer) :  ![starts](https://img.shields.io/github/stars/im-hanzou/INPGer.svg) ![forks](https://img.shields.io/github/forks/im-hanzou/INPGer.svg)


## CVE-2022-0778
 The BN_mod_sqrt() function, which computes a modular square root, contains a bug that can cause it to loop forever for non-prime moduli. Internally this function is used when parsing certificates that contain elliptic curve public keys in compressed form or explicit elliptic curve parameters with a base point encoded in compressed form. It is possible to trigger the infinite loop by crafting a certificate that has invalid explicit curve parameters. Since certificate parsing happens prior to verification of the certificate signature, any process that parses an externally supplied certificate may thus be subject to a denial of service attack. The infinite loop can also be reached when parsing crafted private keys as they can contain explicit elliptic curve parameters. Thus vulnerable situations include: - TLS clients consuming server certificates - TLS servers consuming client certificates - Hosting providers taking certificates or private keys from customers - Certificate authorities parsing certification requests from subscribers - Anything else which parses ASN.1 elliptic curve parameters Also any other applications that use the BN_mod_sqrt() where the attacker can control the parameter values are vulnerable to this DoS issue. In the OpenSSL 1.0.2 version the public key is not parsed during initial parsing of the certificate which makes it slightly harder to trigger the infinite loop. However any operation which requires the public key from the certificate will trigger the infinite loop. In particular the attacker can use a self-signed certificate to trigger the loop during verification of the certificate signature. This issue affects OpenSSL versions 1.0.2, 1.1.1 and 3.0. It was addressed in the releases of 1.1.1n and 3.0.2 on the 15th March 2022. Fixed in OpenSSL 3.0.2 (Affected 3.0.0,3.0.1). Fixed in OpenSSL 1.1.1n (Affected 1.1.1-1.1.1m). Fixed in OpenSSL 1.0.2zd (Affected 1.0.2-1.0.2zc).

- [https://github.com/Trinadh465/openssl-1.1.1g_CVE-2022-0778](https://github.com/Trinadh465/openssl-1.1.1g_CVE-2022-0778) :  ![starts](https://img.shields.io/github/stars/Trinadh465/openssl-1.1.1g_CVE-2022-0778.svg) ![forks](https://img.shields.io/github/forks/Trinadh465/openssl-1.1.1g_CVE-2022-0778.svg)
- [https://github.com/nidhi7598/OPENSSL_1.1.1g_CVE-2022-0778](https://github.com/nidhi7598/OPENSSL_1.1.1g_CVE-2022-0778) :  ![starts](https://img.shields.io/github/stars/nidhi7598/OPENSSL_1.1.1g_CVE-2022-0778.svg) ![forks](https://img.shields.io/github/forks/nidhi7598/OPENSSL_1.1.1g_CVE-2022-0778.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/mightysai1997/CVE-2021-41773-L-](https://github.com/mightysai1997/CVE-2021-41773-L-) :  ![starts](https://img.shields.io/github/stars/mightysai1997/CVE-2021-41773-L-.svg) ![forks](https://img.shields.io/github/forks/mightysai1997/CVE-2021-41773-L-.svg)
- [https://github.com/mightysai1997/cve-2021-41773](https://github.com/mightysai1997/cve-2021-41773) :  ![starts](https://img.shields.io/github/stars/mightysai1997/cve-2021-41773.svg) ![forks](https://img.shields.io/github/forks/mightysai1997/cve-2021-41773.svg)


## CVE-2021-36749
 In the Druid ingestion system, the InputSource is used for reading data from a certain data source. However, the HTTP InputSource allows authenticated users to read data from other sources than intended, such as the local file system, with the privileges of the Druid server process. This is not an elevation of privilege when users access Druid directly, since Druid also provides the Local InputSource, which allows the same level of access. But it is problematic when users interact with Druid indirectly through an application that allows users to specify the HTTP InputSource, but not the Local InputSource. In this case, users could bypass the application-level restriction by passing a file URL to the HTTP InputSource. This issue was previously mentioned as being fixed in 0.21.0 as per CVE-2021-26920 but was not fixed in 0.21.0 or 0.21.1.

- [https://github.com/zwlsix/apache_druid_CVE-2021-36749](https://github.com/zwlsix/apache_druid_CVE-2021-36749) :  ![starts](https://img.shields.io/github/stars/zwlsix/apache_druid_CVE-2021-36749.svg) ![forks](https://img.shields.io/github/forks/zwlsix/apache_druid_CVE-2021-36749.svg)


## CVE-2021-23840
 Calls to EVP_CipherUpdate, EVP_EncryptUpdate and EVP_DecryptUpdate may overflow the output length argument in some cases where the input length is close to the maximum permissable length for an integer on the platform. In such cases the return value from the function call will be 1 (indicating success), but the output length value will be negative. This could cause applications to behave incorrectly or crash. OpenSSL versions 1.1.1i and below are affected by this issue. Users of these versions should upgrade to OpenSSL 1.1.1j. OpenSSL versions 1.0.2x and below are affected by this issue. However OpenSSL 1.0.2 is out of support and no longer receiving public updates. Premium support customers of OpenSSL 1.0.2 should upgrade to 1.0.2y. Other users should upgrade to 1.1.1j. Fixed in OpenSSL 1.1.1j (Affected 1.1.1-1.1.1i). Fixed in OpenSSL 1.0.2y (Affected 1.0.2-1.0.2x).

- [https://github.com/Trinadh465/openssl-1.1.1g_CVE-2021-23840](https://github.com/Trinadh465/openssl-1.1.1g_CVE-2021-23840) :  ![starts](https://img.shields.io/github/stars/Trinadh465/openssl-1.1.1g_CVE-2021-23840.svg) ![forks](https://img.shields.io/github/forks/Trinadh465/openssl-1.1.1g_CVE-2021-23840.svg)


## CVE-2021-4160
 There is a carry propagation bug in the MIPS32 and MIPS64 squaring procedure. Many EC algorithms are affected, including some of the TLS 1.3 default curves. Impact was not analyzed in detail, because the pre-requisites for attack are considered unlikely and include reusing private keys. Analysis suggests that attacks against RSA and DSA as a result of this defect would be very difficult to perform and are not believed likely. Attacks against DH are considered just feasible (although very difficult) because most of the work necessary to deduce information about a private key may be performed offline. The amount of resources required for such an attack would be significant. However, for an attack on TLS to be meaningful, the server would have to share the DH private key among multiple clients, which is no longer an option since CVE-2016-0701. This issue affects OpenSSL versions 1.0.2, 1.1.1 and 3.0.0. It was addressed in the releases of 1.1.1m and 3.0.1 on the 15th of December 2021. For the 1.0.2 release it is addressed in git commit 6fc1aaaf3 that is available to premium support customers only. It will be made available in 1.0.2zc when it is released. The issue only affects OpenSSL on MIPS platforms. Fixed in OpenSSL 3.0.1 (Affected 3.0.0). Fixed in OpenSSL 1.1.1m (Affected 1.1.1-1.1.1l). Fixed in OpenSSL 1.0.2zc-dev (Affected 1.0.2-1.0.2zb).

- [https://github.com/nidhi7598/OPENSSL_1.1.1g_CVE-2021-4160](https://github.com/nidhi7598/OPENSSL_1.1.1g_CVE-2021-4160) :  ![starts](https://img.shields.io/github/stars/nidhi7598/OPENSSL_1.1.1g_CVE-2021-4160.svg) ![forks](https://img.shields.io/github/forks/nidhi7598/OPENSSL_1.1.1g_CVE-2021-4160.svg)


## CVE-2020-12077
 The mappress-google-maps-for-wordpress plugin before 2.53.9 for WordPress does not correctly implement AJAX functions with nonces (or capability checks), leading to remote code execution.

- [https://github.com/RandomRobbieBF/CVE-2020-12077](https://github.com/RandomRobbieBF/CVE-2020-12077) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2020-12077.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2020-12077.svg)


## CVE-2020-8908
 A temp directory creation vulnerability exists in all versions of Guava, allowing an attacker with access to the machine to potentially access data in a temporary directory created by the Guava API com.google.common.io.Files.createTempDir(). By default, on unix-like systems, the created directory is world-readable (readable by an attacker with access to the system). The method in question has been marked @Deprecated in versions 30.0 and later and should not be used. For Android developers, we recommend choosing a temporary directory API provided by Android, such as context.getCacheDir(). For other Java developers, we recommend migrating to the Java 7 API java.nio.file.Files.createTempDirectory() which explicitly configures permissions of 700, or configuring the Java runtime's java.io.tmpdir system property to point to a location whose permissions are appropriately configured.

- [https://github.com/nidhi7598/guava-v18.0_CVE-2020-8908](https://github.com/nidhi7598/guava-v18.0_CVE-2020-8908) :  ![starts](https://img.shields.io/github/stars/nidhi7598/guava-v18.0_CVE-2020-8908.svg) ![forks](https://img.shields.io/github/forks/nidhi7598/guava-v18.0_CVE-2020-8908.svg)


## CVE-2020-0688
 A remote code execution vulnerability exists in Microsoft Exchange software when the software fails to properly handle objects in memory, aka 'Microsoft Exchange Memory Corruption Vulnerability'.

- [https://github.com/7heKnight/CVE-2020-0688](https://github.com/7heKnight/CVE-2020-0688) :  ![starts](https://img.shields.io/github/stars/7heKnight/CVE-2020-0688.svg) ![forks](https://img.shields.io/github/forks/7heKnight/CVE-2020-0688.svg)


## CVE-2020-0022
 In reassemble_and_dispatch of packet_fragmenter.cc, there is possible out of bounds write due to an incorrect bounds calculation. This could lead to remote code execution over Bluetooth with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-8.0 Android-8.1 Android-9 Android-10Android ID: A-143894715

- [https://github.com/themmokhtar/CVE-2020-0022](https://github.com/themmokhtar/CVE-2020-0022) :  ![starts](https://img.shields.io/github/stars/themmokhtar/CVE-2020-0022.svg) ![forks](https://img.shields.io/github/forks/themmokhtar/CVE-2020-0022.svg)


## CVE-2018-14667
 The RichFaces Framework 3.X through 3.3.4 is vulnerable to Expression Language (EL) injection via the UserResource resource. A remote, unauthenticated attacker could exploit this to execute arbitrary code using a chain of java serialized objects via org.ajax4jsf.resource.UserResource$UriData.

- [https://github.com/zeroto01/CVE-2018-14667](https://github.com/zeroto01/CVE-2018-14667) :  ![starts](https://img.shields.io/github/stars/zeroto01/CVE-2018-14667.svg) ![forks](https://img.shields.io/github/forks/zeroto01/CVE-2018-14667.svg)


## CVE-2018-4280
 A memory corruption issue was addressed with improved memory handling. This issue affected versions prior to iOS 11.4.1, macOS High Sierra 10.13.6, tvOS 11.4.1, watchOS 4.3.2.

- [https://github.com/bazad/launchd-portrep](https://github.com/bazad/launchd-portrep) :  ![starts](https://img.shields.io/github/stars/bazad/launchd-portrep.svg) ![forks](https://img.shields.io/github/forks/bazad/launchd-portrep.svg)


## CVE-2016-0792
 Multiple unspecified API endpoints in Jenkins before 1.650 and LTS before 1.642.2 allow remote authenticated users to execute arbitrary code via serialized data in an XML file, related to XStream and groovy.util.Expando.

- [https://github.com/R0B1NL1N/java-deserialization-exploits](https://github.com/R0B1NL1N/java-deserialization-exploits) :  ![starts](https://img.shields.io/github/stars/R0B1NL1N/java-deserialization-exploits.svg) ![forks](https://img.shields.io/github/forks/R0B1NL1N/java-deserialization-exploits.svg)


## CVE-2013-4434
 Dropbear SSH Server before 2013.59 generates error messages for a failed logon attempt with different time delays depending on whether the user account exists, which allows remote attackers to discover valid usernames.

- [https://github.com/styx00/Dropbear_CVE-2013-4434](https://github.com/styx00/Dropbear_CVE-2013-4434) :  ![starts](https://img.shields.io/github/stars/styx00/Dropbear_CVE-2013-4434.svg) ![forks](https://img.shields.io/github/forks/styx00/Dropbear_CVE-2013-4434.svg)

