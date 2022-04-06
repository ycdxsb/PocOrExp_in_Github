# Update 2022-04-06
## CVE-2022-22965
 A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the application to run on Tomcat as a WAR deployment. If the application is deployed as a Spring Boot executable jar, i.e. the default, it is not vulnerable to the exploit. However, the nature of the vulnerability is more general, and there may be other ways to exploit it.

- [https://github.com/netcode/Spring4shell-CVE-2022-22965-POC](https://github.com/netcode/Spring4shell-CVE-2022-22965-POC) :  ![starts](https://img.shields.io/github/stars/netcode/Spring4shell-CVE-2022-22965-POC.svg) ![forks](https://img.shields.io/github/forks/netcode/Spring4shell-CVE-2022-22965-POC.svg)
- [https://github.com/sunnyvale-it/CVE-2022-22965-PoC](https://github.com/sunnyvale-it/CVE-2022-22965-PoC) :  ![starts](https://img.shields.io/github/stars/sunnyvale-it/CVE-2022-22965-PoC.svg) ![forks](https://img.shields.io/github/forks/sunnyvale-it/CVE-2022-22965-PoC.svg)
- [https://github.com/Qualys/spring4scanwin](https://github.com/Qualys/spring4scanwin) :  ![starts](https://img.shields.io/github/stars/Qualys/spring4scanwin.svg) ![forks](https://img.shields.io/github/forks/Qualys/spring4scanwin.svg)
- [https://github.com/twseptian/cve-2022-22965](https://github.com/twseptian/cve-2022-22965) :  ![starts](https://img.shields.io/github/stars/twseptian/cve-2022-22965.svg) ![forks](https://img.shields.io/github/forks/twseptian/cve-2022-22965.svg)
- [https://github.com/anair-it/springshell-vuln-POC](https://github.com/anair-it/springshell-vuln-POC) :  ![starts](https://img.shields.io/github/stars/anair-it/springshell-vuln-POC.svg) ![forks](https://img.shields.io/github/forks/anair-it/springshell-vuln-POC.svg)
- [https://github.com/fracturelabs/go-scan-spring](https://github.com/fracturelabs/go-scan-spring) :  ![starts](https://img.shields.io/github/stars/fracturelabs/go-scan-spring.svg) ![forks](https://img.shields.io/github/forks/fracturelabs/go-scan-spring.svg)
- [https://github.com/daniel0x00/Invoke-CVE-2022-22965-SafeCheck](https://github.com/daniel0x00/Invoke-CVE-2022-22965-SafeCheck) :  ![starts](https://img.shields.io/github/stars/daniel0x00/Invoke-CVE-2022-22965-SafeCheck.svg) ![forks](https://img.shields.io/github/forks/daniel0x00/Invoke-CVE-2022-22965-SafeCheck.svg)
- [https://github.com/fracturelabs/spring4shell_victim](https://github.com/fracturelabs/spring4shell_victim) :  ![starts](https://img.shields.io/github/stars/fracturelabs/spring4shell_victim.svg) ![forks](https://img.shields.io/github/forks/fracturelabs/spring4shell_victim.svg)
- [https://github.com/gpiechnik2/nmap-spring4shell](https://github.com/gpiechnik2/nmap-spring4shell) :  ![starts](https://img.shields.io/github/stars/gpiechnik2/nmap-spring4shell.svg) ![forks](https://img.shields.io/github/forks/gpiechnik2/nmap-spring4shell.svg)


## CVE-2022-22963
 In Spring Cloud Function versions 3.1.6, 3.2.2 and older unsupported versions, when using routing functionality it is possible for a user to provide a specially crafted SpEL as a routing-expression that may result in remote code execution and access to local resources.

- [https://github.com/Qualys/spring4scanwin](https://github.com/Qualys/spring4scanwin) :  ![starts](https://img.shields.io/github/stars/Qualys/spring4scanwin.svg) ![forks](https://img.shields.io/github/forks/Qualys/spring4scanwin.svg)


## CVE-2022-0778
 The BN_mod_sqrt() function, which computes a modular square root, contains a bug that can cause it to loop forever for non-prime moduli. Internally this function is used when parsing certificates that contain elliptic curve public keys in compressed form or explicit elliptic curve parameters with a base point encoded in compressed form. It is possible to trigger the infinite loop by crafting a certificate that has invalid explicit curve parameters. Since certificate parsing happens prior to verification of the certificate signature, any process that parses an externally supplied certificate may thus be subject to a denial of service attack. The infinite loop can also be reached when parsing crafted private keys as they can contain explicit elliptic curve parameters. Thus vulnerable situations include: - TLS clients consuming server certificates - TLS servers consuming client certificates - Hosting providers taking certificates or private keys from customers - Certificate authorities parsing certification requests from subscribers - Anything else which parses ASN.1 elliptic curve parameters Also any other applications that use the BN_mod_sqrt() where the attacker can control the parameter values are vulnerable to this DoS issue. In the OpenSSL 1.0.2 version the public key is not parsed during initial parsing of the certificate which makes it slightly harder to trigger the infinite loop. However any operation which requires the public key from the certificate will trigger the infinite loop. In particular the attacker can use a self-signed certificate to trigger the loop during verification of the certificate signature. This issue affects OpenSSL versions 1.0.2, 1.1.1 and 3.0. It was addressed in the releases of 1.1.1n and 3.0.2 on the 15th March 2022. Fixed in OpenSSL 3.0.2 (Affected 3.0.0,3.0.1). Fixed in OpenSSL 1.1.1n (Affected 1.1.1-1.1.1m). Fixed in OpenSSL 1.0.2zd (Affected 1.0.2-1.0.2zc).

- [https://github.com/yywing/cve-2022-0778](https://github.com/yywing/cve-2022-0778) :  ![starts](https://img.shields.io/github/stars/yywing/cve-2022-0778.svg) ![forks](https://img.shields.io/github/forks/yywing/cve-2022-0778.svg)


## CVE-2021-45105
 Apache Log4j2 versions 2.0-alpha1 through 2.16.0 (excluding 2.12.3 and 2.3.1) did not protect from uncontrolled recursion from self-referential lookups. This allows an attacker with control over Thread Context Map data to cause a denial of service when a crafted string is interpreted. This issue was fixed in Log4j 2.17.0, 2.12.3, and 2.3.1.

- [https://github.com/dtact/divd-2021-00038--log4j-scanner](https://github.com/dtact/divd-2021-00038--log4j-scanner) :  ![starts](https://img.shields.io/github/stars/dtact/divd-2021-00038--log4j-scanner.svg) ![forks](https://img.shields.io/github/forks/dtact/divd-2021-00038--log4j-scanner.svg)
- [https://github.com/iAmSOScArEd/log4j2_dos_exploit](https://github.com/iAmSOScArEd/log4j2_dos_exploit) :  ![starts](https://img.shields.io/github/stars/iAmSOScArEd/log4j2_dos_exploit.svg) ![forks](https://img.shields.io/github/forks/iAmSOScArEd/log4j2_dos_exploit.svg)
- [https://github.com/thedevappsecguy/Log4J-Mitigation-CVE-2021-44228--CVE-2021-45046--CVE-2021-45105--CVE-2021-44832](https://github.com/thedevappsecguy/Log4J-Mitigation-CVE-2021-44228--CVE-2021-45046--CVE-2021-45105--CVE-2021-44832) :  ![starts](https://img.shields.io/github/stars/thedevappsecguy/Log4J-Mitigation-CVE-2021-44228--CVE-2021-45046--CVE-2021-45105--CVE-2021-44832.svg) ![forks](https://img.shields.io/github/forks/thedevappsecguy/Log4J-Mitigation-CVE-2021-44228--CVE-2021-45046--CVE-2021-45105--CVE-2021-44832.svg)
- [https://github.com/pravin-pp/log4j2-CVE-2021-45105](https://github.com/pravin-pp/log4j2-CVE-2021-45105) :  ![starts](https://img.shields.io/github/stars/pravin-pp/log4j2-CVE-2021-45105.svg) ![forks](https://img.shields.io/github/forks/pravin-pp/log4j2-CVE-2021-45105.svg)


## CVE-2021-42013
 It was found that the fix for CVE-2021-41773 in Apache HTTP Server 2.4.50 was insufficient. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue only affects Apache 2.4.49 and Apache 2.4.50 and not earlier versions.

- [https://github.com/CalfCrusher/Path-traversal-RCE-Apache-2.4.49-2.4.50-Exploit](https://github.com/CalfCrusher/Path-traversal-RCE-Apache-2.4.49-2.4.50-Exploit) :  ![starts](https://img.shields.io/github/stars/CalfCrusher/Path-traversal-RCE-Apache-2.4.49-2.4.50-Exploit.svg) ![forks](https://img.shields.io/github/forks/CalfCrusher/Path-traversal-RCE-Apache-2.4.49-2.4.50-Exploit.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/CalfCrusher/Path-traversal-RCE-Apache-2.4.49-2.4.50-Exploit](https://github.com/CalfCrusher/Path-traversal-RCE-Apache-2.4.49-2.4.50-Exploit) :  ![starts](https://img.shields.io/github/stars/CalfCrusher/Path-traversal-RCE-Apache-2.4.49-2.4.50-Exploit.svg) ![forks](https://img.shields.io/github/forks/CalfCrusher/Path-traversal-RCE-Apache-2.4.49-2.4.50-Exploit.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/PentesterSoham/CVE-2021-4034-exploit](https://github.com/PentesterSoham/CVE-2021-4034-exploit) :  ![starts](https://img.shields.io/github/stars/PentesterSoham/CVE-2021-4034-exploit.svg) ![forks](https://img.shields.io/github/forks/PentesterSoham/CVE-2021-4034-exploit.svg)
- [https://github.com/luckythandel/CVE-2021-4034](https://github.com/luckythandel/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/luckythandel/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/luckythandel/CVE-2021-4034.svg)


## CVE-2021-0476
 In FindOrCreatePeer of btif_av.cc, there is a possible use after free due to a race condition. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-11 Android-9 Android-10Android ID: A-169252501

- [https://github.com/nanopathi/system_bt_AOSP10_r33_CVE-2021-0476](https://github.com/nanopathi/system_bt_AOSP10_r33_CVE-2021-0476) :  ![starts](https://img.shields.io/github/stars/nanopathi/system_bt_AOSP10_r33_CVE-2021-0476.svg) ![forks](https://img.shields.io/github/forks/nanopathi/system_bt_AOSP10_r33_CVE-2021-0476.svg)


## CVE-2020-24186
 A Remote Code Execution vulnerability exists in the gVectors wpDiscuz plugin 7.0 through 7.0.4 for WordPress, which allows unauthenticated users to upload any type of file, including PHP files via the wmuUploadFiles AJAX action.

- [https://github.com/Sakura-501/CVE-2020-24186-exploit](https://github.com/Sakura-501/CVE-2020-24186-exploit) :  ![starts](https://img.shields.io/github/stars/Sakura-501/CVE-2020-24186-exploit.svg) ![forks](https://img.shields.io/github/forks/Sakura-501/CVE-2020-24186-exploit.svg)


## CVE-2020-14871
 Vulnerability in the Oracle Solaris product of Oracle Systems (component: Pluggable authentication module). Supported versions that are affected are 10 and 11. Easily exploitable vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise Oracle Solaris. While the vulnerability is in Oracle Solaris, attacks may significantly impact additional products. Successful attacks of this vulnerability can result in takeover of Oracle Solaris. Note: This CVE is not exploitable for Solaris 11.1 and later releases, and ZFSSA 8.7 and later releases, thus the CVSS Base Score is 0.0. CVSS 3.1 Base Score 10.0 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H).

- [https://github.com/hackingyseguridad/ssha](https://github.com/hackingyseguridad/ssha) :  ![starts](https://img.shields.io/github/stars/hackingyseguridad/ssha.svg) ![forks](https://img.shields.io/github/forks/hackingyseguridad/ssha.svg)


## CVE-2018-16706
 LG SuperSign CMS allows TVs to be rebooted remotely without authentication via a direct HTTP request to /qsr_server/device/reboot on port 9080.

- [https://github.com/Nurdilin/CVE-2018-16706](https://github.com/Nurdilin/CVE-2018-16706) :  ![starts](https://img.shields.io/github/stars/Nurdilin/CVE-2018-16706.svg) ![forks](https://img.shields.io/github/forks/Nurdilin/CVE-2018-16706.svg)


## CVE-2015-5119
 Use-after-free vulnerability in the ByteArray class in the ActionScript 3 (AS3) implementation in Adobe Flash Player 13.x through 13.0.0.296 and 14.x through 18.0.0.194 on Windows and OS X and 11.x through 11.2.202.468 on Linux allows remote attackers to execute arbitrary code or cause a denial of service (memory corruption) via crafted Flash content that overrides a valueOf function, as exploited in the wild in July 2015.

- [https://github.com/dangokyo/CVE-2015-5119](https://github.com/dangokyo/CVE-2015-5119) :  ![starts](https://img.shields.io/github/stars/dangokyo/CVE-2015-5119.svg) ![forks](https://img.shields.io/github/forks/dangokyo/CVE-2015-5119.svg)

