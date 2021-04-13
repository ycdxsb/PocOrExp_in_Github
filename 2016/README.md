## CVE-2016-1000229
 swagger-ui has XSS in key names



- [https://github.com/ossf-cve-benchmark/CVE-2016-1000229](https://github.com/ossf-cve-benchmark/CVE-2016-1000229) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2016-1000229.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2016-1000229.svg)

## CVE-2016-1000027
 Pivotal Spring Framework 4.1.4 suffers from a potential remote code execution (RCE) issue if used for Java deserialization of untrusted data. Depending on how the library is implemented within a product, this issue may or not occur, and authentication may be required.



- [https://github.com/artem-smotrakov/cve-2016-1000027-poc](https://github.com/artem-smotrakov/cve-2016-1000027-poc) :  ![starts](https://img.shields.io/github/stars/artem-smotrakov/cve-2016-1000027-poc.svg) ![forks](https://img.shields.io/github/forks/artem-smotrakov/cve-2016-1000027-poc.svg)

## CVE-2016-10725
 In Bitcoin Core before v0.13.0, a non-final alert is able to block the special &quot;final alert&quot; (which is supposed to override all other alerts) because operations occur in the wrong order. This behavior occurs in the remote network alert system (deprecated since Q1 2016). This affects other uses of the codebase, such as Bitcoin Knots before v0.13.0.knots20160814 and many altcoins.



- [https://github.com/JinBean/CVE-Extension](https://github.com/JinBean/CVE-Extension) :  ![starts](https://img.shields.io/github/stars/JinBean/CVE-Extension.svg) ![forks](https://img.shields.io/github/forks/JinBean/CVE-Extension.svg)

## CVE-2016-10724
 Bitcoin Core before v0.13.0 allows denial of service (memory exhaustion) triggered by the remote network alert system (deprecated since Q1 2016) if an attacker can sign a message with a certain private key that had been known by unintended actors, because of an infinitely sized map. This affects other uses of the codebase, such as Bitcoin Knots before v0.13.0.knots20160814 and many altcoins.



- [https://github.com/JinBean/CVE-Extension](https://github.com/JinBean/CVE-Extension) :  ![starts](https://img.shields.io/github/stars/JinBean/CVE-Extension.svg) ![forks](https://img.shields.io/github/forks/JinBean/CVE-Extension.svg)

## CVE-2016-10709
 pfSense before 2.3 allows remote authenticated users to execute arbitrary OS commands via a '|' character in the status_rrd_graph_img.php graph parameter, related to _rrd_graph_img.php.



- [https://github.com/wetw0rk/Exploit-Development](https://github.com/wetw0rk/Exploit-Development) :  ![starts](https://img.shields.io/github/stars/wetw0rk/Exploit-Development.svg) ![forks](https://img.shields.io/github/forks/wetw0rk/Exploit-Development.svg)

## CVE-2016-10555
 Since &quot;algorithm&quot; isn't enforced in jwt.decode()in jwt-simple 0.3.0 and earlier, a malicious user could choose what algorithm is sent sent to the server. If the server is expecting RSA but is sent HMAC-SHA with RSA's public key, the server will think the public key is actually an HMAC private key. This could be used to forge any data an attacker wants.



- [https://github.com/thepcn3rd/jwtToken-CVE-2016-10555](https://github.com/thepcn3rd/jwtToken-CVE-2016-10555) :  ![starts](https://img.shields.io/github/stars/thepcn3rd/jwtToken-CVE-2016-10555.svg) ![forks](https://img.shields.io/github/forks/thepcn3rd/jwtToken-CVE-2016-10555.svg)

## CVE-2016-10277
 An elevation of privilege vulnerability in the Motorola bootloader could enable a local malicious application to execute arbitrary code within the context of the bootloader. This issue is rated as Critical due to the possibility of a local permanent device compromise, which may require reflashing the operating system to repair the device. Product: Android. Versions: Kernel-3.10, Kernel-3.18. Android ID: A-33840490.



- [https://github.com/alephsecurity/initroot](https://github.com/alephsecurity/initroot) :  ![starts](https://img.shields.io/github/stars/alephsecurity/initroot.svg) ![forks](https://img.shields.io/github/forks/alephsecurity/initroot.svg)

- [https://github.com/leosol/initroot](https://github.com/leosol/initroot) :  ![starts](https://img.shields.io/github/stars/leosol/initroot.svg) ![forks](https://img.shields.io/github/forks/leosol/initroot.svg)

## CVE-2016-10045
 The isMail transport in PHPMailer before 5.2.20 might allow remote attackers to pass extra parameters to the mail command and consequently execute arbitrary code by leveraging improper interaction between the escapeshellarg function and internal escaping performed in the mail function in PHP. NOTE: this vulnerability exists because of an incorrect fix for CVE-2016-10033.



- [https://github.com/Zenexer/safeshell](https://github.com/Zenexer/safeshell) :  ![starts](https://img.shields.io/github/stars/Zenexer/safeshell.svg) ![forks](https://img.shields.io/github/forks/Zenexer/safeshell.svg)

- [https://github.com/pedro823/cve-2016-10033-45](https://github.com/pedro823/cve-2016-10033-45) :  ![starts](https://img.shields.io/github/stars/pedro823/cve-2016-10033-45.svg) ![forks](https://img.shields.io/github/forks/pedro823/cve-2016-10033-45.svg)

## CVE-2016-10034
 The setFrom function in the Sendmail adapter in the zend-mail component before 2.4.11, 2.5.x, 2.6.x, and 2.7.x before 2.7.2, and Zend Framework before 2.4.11 might allow remote attackers to pass extra parameters to the mail command and consequently execute arbitrary code via a \&quot; (backslash double quote) in a crafted e-mail address.



- [https://github.com/heikipikker/exploit-CVE-2016-10034](https://github.com/heikipikker/exploit-CVE-2016-10034) :  ![starts](https://img.shields.io/github/stars/heikipikker/exploit-CVE-2016-10034.svg) ![forks](https://img.shields.io/github/forks/heikipikker/exploit-CVE-2016-10034.svg)

## CVE-2016-10033
 The mailSend function in the isMail transport in PHPMailer before 5.2.18 might allow remote attackers to pass extra parameters to the mail command and consequently execute arbitrary code via a \&quot; (backslash double quote) in a crafted Sender property.



- [https://github.com/opsxcq/exploit-CVE-2016-10033](https://github.com/opsxcq/exploit-CVE-2016-10033) :  ![starts](https://img.shields.io/github/stars/opsxcq/exploit-CVE-2016-10033.svg) ![forks](https://img.shields.io/github/forks/opsxcq/exploit-CVE-2016-10033.svg)

- [https://github.com/GeneralTesler/CVE-2016-10033](https://github.com/GeneralTesler/CVE-2016-10033) :  ![starts](https://img.shields.io/github/stars/GeneralTesler/CVE-2016-10033.svg) ![forks](https://img.shields.io/github/forks/GeneralTesler/CVE-2016-10033.svg)

- [https://github.com/Zenexer/safeshell](https://github.com/Zenexer/safeshell) :  ![starts](https://img.shields.io/github/stars/Zenexer/safeshell.svg) ![forks](https://img.shields.io/github/forks/Zenexer/safeshell.svg)

- [https://github.com/0x00-0x00/CVE-2016-10033](https://github.com/0x00-0x00/CVE-2016-10033) :  ![starts](https://img.shields.io/github/stars/0x00-0x00/CVE-2016-10033.svg) ![forks](https://img.shields.io/github/forks/0x00-0x00/CVE-2016-10033.svg)

- [https://github.com/paralelo14/CVE_2016-10033](https://github.com/paralelo14/CVE_2016-10033) :  ![starts](https://img.shields.io/github/stars/paralelo14/CVE_2016-10033.svg) ![forks](https://img.shields.io/github/forks/paralelo14/CVE_2016-10033.svg)

- [https://github.com/chipironcin/CVE-2016-10033](https://github.com/chipironcin/CVE-2016-10033) :  ![starts](https://img.shields.io/github/stars/chipironcin/CVE-2016-10033.svg) ![forks](https://img.shields.io/github/forks/chipironcin/CVE-2016-10033.svg)

- [https://github.com/pedro823/cve-2016-10033-45](https://github.com/pedro823/cve-2016-10033-45) :  ![starts](https://img.shields.io/github/stars/pedro823/cve-2016-10033-45.svg) ![forks](https://img.shields.io/github/forks/pedro823/cve-2016-10033-45.svg)

- [https://github.com/awidardi/opsxcq-cve-2016-10033](https://github.com/awidardi/opsxcq-cve-2016-10033) :  ![starts](https://img.shields.io/github/stars/awidardi/opsxcq-cve-2016-10033.svg) ![forks](https://img.shields.io/github/forks/awidardi/opsxcq-cve-2016-10033.svg)

- [https://github.com/cved-sources/cve-2016-10033](https://github.com/cved-sources/cve-2016-10033) :  ![starts](https://img.shields.io/github/stars/cved-sources/cve-2016-10033.svg) ![forks](https://img.shields.io/github/forks/cved-sources/cve-2016-10033.svg)

- [https://github.com/qwertyuiop12138/CVE-2016-10033](https://github.com/qwertyuiop12138/CVE-2016-10033) :  ![starts](https://img.shields.io/github/stars/qwertyuiop12138/CVE-2016-10033.svg) ![forks](https://img.shields.io/github/forks/qwertyuiop12138/CVE-2016-10033.svg)

- [https://github.com/liusec/WP-CVE-2016-10033](https://github.com/liusec/WP-CVE-2016-10033) :  ![starts](https://img.shields.io/github/stars/liusec/WP-CVE-2016-10033.svg) ![forks](https://img.shields.io/github/forks/liusec/WP-CVE-2016-10033.svg)

- [https://github.com/Bajunan/CVE-2016-10033](https://github.com/Bajunan/CVE-2016-10033) :  ![starts](https://img.shields.io/github/stars/Bajunan/CVE-2016-10033.svg) ![forks](https://img.shields.io/github/forks/Bajunan/CVE-2016-10033.svg)

## CVE-2016-0974
 Use-after-free vulnerability in Adobe Flash Player before 18.0.0.329 and 19.x and 20.x before 20.0.0.306 on Windows and OS X and before 11.2.202.569 on Linux, Adobe AIR before 20.0.0.260, Adobe AIR SDK before 20.0.0.260, and Adobe AIR SDK &amp; Compiler before 20.0.0.260 allows attackers to execute arbitrary code via unspecified vectors, a different vulnerability than CVE-2016-0973, CVE-2016-0975, CVE-2016-0982, CVE-2016-0983, and CVE-2016-0984.



- [https://github.com/Fullmetal5/FlashHax](https://github.com/Fullmetal5/FlashHax) :  ![starts](https://img.shields.io/github/stars/Fullmetal5/FlashHax.svg) ![forks](https://img.shields.io/github/forks/Fullmetal5/FlashHax.svg)

## CVE-2016-0856
 Multiple stack-based buffer overflows in Advantech WebAccess before 8.1 allow remote attackers to execute arbitrary code via unspecified vectors.



- [https://github.com/thezdi/PoC](https://github.com/thezdi/PoC) :  ![starts](https://img.shields.io/github/stars/thezdi/PoC.svg) ![forks](https://img.shields.io/github/forks/thezdi/PoC.svg)

## CVE-2016-0846
 libs/binder/IMemory.cpp in the IMemory Native Interface in Android 4.x before 4.4.4, 5.0.x before 5.0.2, 5.1.x before 5.1.1, and 6.x before 2016-04-01 does not properly consider the heap size, which allows attackers to gain privileges via a crafted application, as demonstrated by obtaining Signature or SignatureOrSystem access, aka internal bug 26877992.



- [https://github.com/secmob/CVE-2016-0846](https://github.com/secmob/CVE-2016-0846) :  ![starts](https://img.shields.io/github/stars/secmob/CVE-2016-0846.svg) ![forks](https://img.shields.io/github/forks/secmob/CVE-2016-0846.svg)

- [https://github.com/b0b0505/CVE-2016-0846-PoC](https://github.com/b0b0505/CVE-2016-0846-PoC) :  ![starts](https://img.shields.io/github/stars/b0b0505/CVE-2016-0846-PoC.svg) ![forks](https://img.shields.io/github/forks/b0b0505/CVE-2016-0846-PoC.svg)

## CVE-2016-0805
 The performance event manager for Qualcomm ARM processors in Android 4.x before 4.4.4, 5.x before 5.1.1 LMY49G, and 6.x before 2016-02-01 allows attackers to gain privileges via a crafted application, aka internal bug 25773204.



- [https://github.com/hulovebin/cve-2016-0805](https://github.com/hulovebin/cve-2016-0805) :  ![starts](https://img.shields.io/github/stars/hulovebin/cve-2016-0805.svg) ![forks](https://img.shields.io/github/forks/hulovebin/cve-2016-0805.svg)

## CVE-2016-0801
 The Broadcom Wi-Fi driver in the kernel in Android 4.x before 4.4.4, 5.x before 5.1.1 LMY49G, and 6.x before 2016-02-01 allows remote attackers to execute arbitrary code or cause a denial of service (memory corruption) via crafted wireless control message packets, aka internal bug 25662029.



- [https://github.com/abdsec/CVE-2016-0801](https://github.com/abdsec/CVE-2016-0801) :  ![starts](https://img.shields.io/github/stars/abdsec/CVE-2016-0801.svg) ![forks](https://img.shields.io/github/forks/abdsec/CVE-2016-0801.svg)

- [https://github.com/zsaurus/CVE-2016-0801-test](https://github.com/zsaurus/CVE-2016-0801-test) :  ![starts](https://img.shields.io/github/stars/zsaurus/CVE-2016-0801-test.svg) ![forks](https://img.shields.io/github/forks/zsaurus/CVE-2016-0801-test.svg)

## CVE-2016-0800
 The SSLv2 protocol, as used in OpenSSL before 1.0.1s and 1.0.2 before 1.0.2g and other products, requires a server to send a ServerVerify message before establishing that a client possesses certain plaintext RSA data, which makes it easier for remote attackers to decrypt TLS ciphertext data by leveraging a Bleichenbacher RSA padding oracle, aka a &quot;DROWN&quot; attack.



- [https://github.com/nyc-tophile/A2SV--SSL-VUL-Scan](https://github.com/nyc-tophile/A2SV--SSL-VUL-Scan) :  ![starts](https://img.shields.io/github/stars/nyc-tophile/A2SV--SSL-VUL-Scan.svg) ![forks](https://img.shields.io/github/forks/nyc-tophile/A2SV--SSL-VUL-Scan.svg)

## CVE-2016-0793
 Incomplete blacklist vulnerability in the servlet filter restriction mechanism in WildFly (formerly JBoss Application Server) before 10.0.0.Final on Windows allows remote attackers to read the sensitive files in the (1) WEB-INF or (2) META-INF directory via a request that contains (a) lowercase or (b) &quot;meaningless&quot; characters.



- [https://github.com/tafamace/CVE-2016-0793](https://github.com/tafamace/CVE-2016-0793) :  ![starts](https://img.shields.io/github/stars/tafamace/CVE-2016-0793.svg) ![forks](https://img.shields.io/github/forks/tafamace/CVE-2016-0793.svg)

## CVE-2016-0792
 Multiple unspecified API endpoints in Jenkins before 1.650 and LTS before 1.642.2 allow remote authenticated users to execute arbitrary code via serialized data in an XML file, related to XStream and groovy.util.Expando.



- [https://github.com/jpiechowka/jenkins-cve-2016-0792](https://github.com/jpiechowka/jenkins-cve-2016-0792) :  ![starts](https://img.shields.io/github/stars/jpiechowka/jenkins-cve-2016-0792.svg) ![forks](https://img.shields.io/github/forks/jpiechowka/jenkins-cve-2016-0792.svg)

- [https://github.com/s0wr0b1ndef/java-deserialization-exploits](https://github.com/s0wr0b1ndef/java-deserialization-exploits) :  ![starts](https://img.shields.io/github/stars/s0wr0b1ndef/java-deserialization-exploits.svg) ![forks](https://img.shields.io/github/forks/s0wr0b1ndef/java-deserialization-exploits.svg)

## CVE-2016-0772
 The smtplib library in CPython (aka Python) before 2.7.12, 3.x before 3.4.5, and 3.5.x before 3.5.2 does not return an error when StartTLS fails, which might allow man-in-the-middle attackers to bypass the TLS protections by leveraging a network position between the client and the registry to block the StartTLS command, aka a &quot;StartTLS stripping attack.&quot;



- [https://github.com/tintinweb/pub](https://github.com/tintinweb/pub) :  ![starts](https://img.shields.io/github/stars/tintinweb/pub.svg) ![forks](https://img.shields.io/github/forks/tintinweb/pub.svg)

## CVE-2016-0752
 Directory traversal vulnerability in Action View in Ruby on Rails before 3.2.22.1, 4.0.x and 4.1.x before 4.1.14.1, 4.2.x before 4.2.5.1, and 5.x before 5.0.0.beta1.1 allows remote attackers to read arbitrary files by leveraging an application's unrestricted use of the render method and providing a .. (dot dot) in a pathname.



- [https://github.com/forced-request/rails-rce-cve-2016-0752](https://github.com/forced-request/rails-rce-cve-2016-0752) :  ![starts](https://img.shields.io/github/stars/forced-request/rails-rce-cve-2016-0752.svg) ![forks](https://img.shields.io/github/forks/forced-request/rails-rce-cve-2016-0752.svg)

- [https://github.com/julianmunoz/Rails-Dynamic-Render-vuln](https://github.com/julianmunoz/Rails-Dynamic-Render-vuln) :  ![starts](https://img.shields.io/github/stars/julianmunoz/Rails-Dynamic-Render-vuln.svg) ![forks](https://img.shields.io/github/forks/julianmunoz/Rails-Dynamic-Render-vuln.svg)

- [https://github.com/dachidahu/CVE-2016-0752](https://github.com/dachidahu/CVE-2016-0752) :  ![starts](https://img.shields.io/github/stars/dachidahu/CVE-2016-0752.svg) ![forks](https://img.shields.io/github/forks/dachidahu/CVE-2016-0752.svg)

## CVE-2016-0728
 The join_session_keyring function in security/keys/process_keys.c in the Linux kernel before 4.4.1 mishandles object references in a certain error case, which allows local users to gain privileges or cause a denial of service (integer overflow and use-after-free) via crafted keyctl commands.



- [https://github.com/nardholio/cve-2016-0728](https://github.com/nardholio/cve-2016-0728) :  ![starts](https://img.shields.io/github/stars/nardholio/cve-2016-0728.svg) ![forks](https://img.shields.io/github/forks/nardholio/cve-2016-0728.svg)

- [https://github.com/bittorrent3389/cve-2016-0728](https://github.com/bittorrent3389/cve-2016-0728) :  ![starts](https://img.shields.io/github/stars/bittorrent3389/cve-2016-0728.svg) ![forks](https://img.shields.io/github/forks/bittorrent3389/cve-2016-0728.svg)

- [https://github.com/sunnyjiang/cve_2016_0728](https://github.com/sunnyjiang/cve_2016_0728) :  ![starts](https://img.shields.io/github/stars/sunnyjiang/cve_2016_0728.svg) ![forks](https://img.shields.io/github/forks/sunnyjiang/cve_2016_0728.svg)

- [https://github.com/neuschaefer/cve-2016-0728-testbed](https://github.com/neuschaefer/cve-2016-0728-testbed) :  ![starts](https://img.shields.io/github/stars/neuschaefer/cve-2016-0728-testbed.svg) ![forks](https://img.shields.io/github/forks/neuschaefer/cve-2016-0728-testbed.svg)

- [https://github.com/fochess/cve_2016_0728](https://github.com/fochess/cve_2016_0728) :  ![starts](https://img.shields.io/github/stars/fochess/cve_2016_0728.svg) ![forks](https://img.shields.io/github/forks/fochess/cve_2016_0728.svg)

- [https://github.com/bjzz/cve_2016_0728_exploit](https://github.com/bjzz/cve_2016_0728_exploit) :  ![starts](https://img.shields.io/github/stars/bjzz/cve_2016_0728_exploit.svg) ![forks](https://img.shields.io/github/forks/bjzz/cve_2016_0728_exploit.svg)

- [https://github.com/kennetham/cve_2016_0728](https://github.com/kennetham/cve_2016_0728) :  ![starts](https://img.shields.io/github/stars/kennetham/cve_2016_0728.svg) ![forks](https://img.shields.io/github/forks/kennetham/cve_2016_0728.svg)

- [https://github.com/mfer/cve_2016_0728](https://github.com/mfer/cve_2016_0728) :  ![starts](https://img.shields.io/github/stars/mfer/cve_2016_0728.svg) ![forks](https://img.shields.io/github/forks/mfer/cve_2016_0728.svg)

- [https://github.com/sugarvillela/CVE](https://github.com/sugarvillela/CVE) :  ![starts](https://img.shields.io/github/stars/sugarvillela/CVE.svg) ![forks](https://img.shields.io/github/forks/sugarvillela/CVE.svg)

- [https://github.com/isnuryusuf/cve_2016_0728](https://github.com/isnuryusuf/cve_2016_0728) :  ![starts](https://img.shields.io/github/stars/isnuryusuf/cve_2016_0728.svg) ![forks](https://img.shields.io/github/forks/isnuryusuf/cve_2016_0728.svg)

- [https://github.com/sibilleg/exploit_cve-2016-0728](https://github.com/sibilleg/exploit_cve-2016-0728) :  ![starts](https://img.shields.io/github/stars/sibilleg/exploit_cve-2016-0728.svg) ![forks](https://img.shields.io/github/forks/sibilleg/exploit_cve-2016-0728.svg)

- [https://github.com/hal0taso/CVE-2016-0728](https://github.com/hal0taso/CVE-2016-0728) :  ![starts](https://img.shields.io/github/stars/hal0taso/CVE-2016-0728.svg) ![forks](https://img.shields.io/github/forks/hal0taso/CVE-2016-0728.svg)

- [https://github.com/googleweb/CVE-2016-0728](https://github.com/googleweb/CVE-2016-0728) :  ![starts](https://img.shields.io/github/stars/googleweb/CVE-2016-0728.svg) ![forks](https://img.shields.io/github/forks/googleweb/CVE-2016-0728.svg)

- [https://github.com/idl3r/cve-2016-0728](https://github.com/idl3r/cve-2016-0728) :  ![starts](https://img.shields.io/github/stars/idl3r/cve-2016-0728.svg) ![forks](https://img.shields.io/github/forks/idl3r/cve-2016-0728.svg)

- [https://github.com/th30d00r/Linux-Vulnerability-CVE-2016-0728-and-Exploit](https://github.com/th30d00r/Linux-Vulnerability-CVE-2016-0728-and-Exploit) :  ![starts](https://img.shields.io/github/stars/th30d00r/Linux-Vulnerability-CVE-2016-0728-and-Exploit.svg) ![forks](https://img.shields.io/github/forks/th30d00r/Linux-Vulnerability-CVE-2016-0728-and-Exploit.svg)

## CVE-2016-0701
 The DH_check_pub_key function in crypto/dh/dh_check.c in OpenSSL 1.0.2 before 1.0.2f does not ensure that prime numbers are appropriate for Diffie-Hellman (DH) key exchange, which makes it easier for remote attackers to discover a private DH exponent by making multiple handshakes with a peer that chose an inappropriate number, as demonstrated by a number in an X9.42 file.



- [https://github.com/luanjampa/cve-2016-0701](https://github.com/luanjampa/cve-2016-0701) :  ![starts](https://img.shields.io/github/stars/luanjampa/cve-2016-0701.svg) ![forks](https://img.shields.io/github/forks/luanjampa/cve-2016-0701.svg)

## CVE-2016-0638
 Unspecified vulnerability in the Oracle WebLogic Server component in Oracle Fusion Middleware 10.3.6, 12.1.2, 12.1.3, and 12.2.1 allows remote attackers to affect confidentiality, integrity, and availability via vectors related to Java Messaging Service.



- [https://github.com/0xn0ne/weblogicScanner](https://github.com/0xn0ne/weblogicScanner) :  ![starts](https://img.shields.io/github/stars/0xn0ne/weblogicScanner.svg) ![forks](https://img.shields.io/github/forks/0xn0ne/weblogicScanner.svg)

- [https://github.com/zhzhdoai/Weblogic_Vuln](https://github.com/zhzhdoai/Weblogic_Vuln) :  ![starts](https://img.shields.io/github/stars/zhzhdoai/Weblogic_Vuln.svg) ![forks](https://img.shields.io/github/forks/zhzhdoai/Weblogic_Vuln.svg)

## CVE-2016-0199
 Microsoft Internet Explorer 9 through 11 allows remote attackers to execute arbitrary code or cause a denial of service (memory corruption) via a crafted web site, aka &quot;Internet Explorer Memory Corruption Vulnerability,&quot; a different vulnerability than CVE-2016-0200 and CVE-2016-3211.



- [https://github.com/LeoonZHANG/CVE-2016-0199](https://github.com/LeoonZHANG/CVE-2016-0199) :  ![starts](https://img.shields.io/github/stars/LeoonZHANG/CVE-2016-0199.svg) ![forks](https://img.shields.io/github/forks/LeoonZHANG/CVE-2016-0199.svg)

## CVE-2016-0189
 The Microsoft (1) JScript 5.8 and (2) VBScript 5.7 and 5.8 engines, as used in Internet Explorer 9 through 11 and other products, allow remote attackers to execute arbitrary code or cause a denial of service (memory corruption) via a crafted web site, aka &quot;Scripting Engine Memory Corruption Vulnerability,&quot; a different vulnerability than CVE-2016-0187.



- [https://github.com/theori-io/cve-2016-0189](https://github.com/theori-io/cve-2016-0189) :  ![starts](https://img.shields.io/github/stars/theori-io/cve-2016-0189.svg) ![forks](https://img.shields.io/github/forks/theori-io/cve-2016-0189.svg)

- [https://github.com/deamwork/MS16-051-poc](https://github.com/deamwork/MS16-051-poc) :  ![starts](https://img.shields.io/github/stars/deamwork/MS16-051-poc.svg) ![forks](https://img.shields.io/github/forks/deamwork/MS16-051-poc.svg)

## CVE-2016-0100
 Microsoft Windows Vista SP2 and Server 2008 SP2 mishandle library loading, which allows local users to gain privileges via a crafted application, aka &quot;Library Loading Input Validation Remote Code Execution Vulnerability.&quot;



- [https://github.com/zi0Black/CVE-2016-010033-010045](https://github.com/zi0Black/CVE-2016-010033-010045) :  ![starts](https://img.shields.io/github/stars/zi0Black/CVE-2016-010033-010045.svg) ![forks](https://img.shields.io/github/forks/zi0Black/CVE-2016-010033-010045.svg)

## CVE-2016-0099
 The Secondary Logon Service in Microsoft Windows Vista SP2, Windows Server 2008 SP2 and R2 SP1, Windows 7 SP1, Windows 8.1, Windows Server 2012 Gold and R2, Windows RT 8.1, and Windows 10 Gold and 1511 does not properly process request handles, which allows local users to gain privileges via a crafted application, aka &quot;Secondary Logon Elevation of Privilege Vulnerability.&quot;



- [https://github.com/zcgonvh/MS16-032](https://github.com/zcgonvh/MS16-032) :  ![starts](https://img.shields.io/github/stars/zcgonvh/MS16-032.svg) ![forks](https://img.shields.io/github/forks/zcgonvh/MS16-032.svg)

## CVE-2016-0095
 The kernel-mode driver in Microsoft Windows Vista SP2, Windows Server 2008 SP2 and R2 SP1, Windows 7 SP1, Windows 8.1, Windows Server 2012 Gold and R2, Windows RT 8.1, and Windows 10 Gold and 1511 allows local users to gain privileges via a crafted application, aka &quot;Win32k Elevation of Privilege Vulnerability,&quot; a different vulnerability than CVE-2016-0093, CVE-2016-0094, and CVE-2016-0096.



- [https://github.com/fengjixuchui/cve-2016-0095-x64](https://github.com/fengjixuchui/cve-2016-0095-x64) :  ![starts](https://img.shields.io/github/stars/fengjixuchui/cve-2016-0095-x64.svg) ![forks](https://img.shields.io/github/forks/fengjixuchui/cve-2016-0095-x64.svg)

## CVE-2016-0051
 The WebDAV client in Microsoft Windows Vista SP2, Windows Server 2008 SP2 and R2 SP1, Windows 7 SP1, Windows 8.1, Windows Server 2012 Gold and R2, Windows RT 8.1, and Windows 10 Gold and 1511 allows local users to gain privileges via a crafted application, aka &quot;WebDAV Elevation of Privilege Vulnerability.&quot;



- [https://github.com/koczkatamas/CVE-2016-0051](https://github.com/koczkatamas/CVE-2016-0051) :  ![starts](https://img.shields.io/github/stars/koczkatamas/CVE-2016-0051.svg) ![forks](https://img.shields.io/github/forks/koczkatamas/CVE-2016-0051.svg)

- [https://github.com/hexx0r/CVE-2016-0051](https://github.com/hexx0r/CVE-2016-0051) :  ![starts](https://img.shields.io/github/stars/hexx0r/CVE-2016-0051.svg) ![forks](https://img.shields.io/github/forks/hexx0r/CVE-2016-0051.svg)

- [https://github.com/ganrann/CVE-2016-0051](https://github.com/ganrann/CVE-2016-0051) :  ![starts](https://img.shields.io/github/stars/ganrann/CVE-2016-0051.svg) ![forks](https://img.shields.io/github/forks/ganrann/CVE-2016-0051.svg)

## CVE-2016-0049
 Kerberos in Microsoft Windows Vista SP2, Windows Server 2008 SP2 and R2 SP1, Windows 7 SP1, Windows 8.1, Windows Server 2012 Gold and R2, and Windows 10 Gold and 1511 does not properly validate password changes, which allows remote attackers to bypass authentication by deploying a crafted Key Distribution Center (KDC) and then performing a sign-in action, aka &quot;Windows Kerberos Security Feature Bypass.&quot;



- [https://github.com/JackOfMostTrades/bluebox](https://github.com/JackOfMostTrades/bluebox) :  ![starts](https://img.shields.io/github/stars/JackOfMostTrades/bluebox.svg) ![forks](https://img.shields.io/github/forks/JackOfMostTrades/bluebox.svg)

## CVE-2016-0040
 The kernel in Microsoft Windows Vista SP2, Windows Server 2008 SP2 and R2 SP1, and Windows 7 SP1 allows local users to gain privileges via a crafted application, aka &quot;Windows Elevation of Privilege Vulnerability.&quot;



- [https://github.com/Rootkitsmm-zz/cve-2016-0040](https://github.com/Rootkitsmm-zz/cve-2016-0040) :  ![starts](https://img.shields.io/github/stars/Rootkitsmm-zz/cve-2016-0040.svg) ![forks](https://img.shields.io/github/forks/Rootkitsmm-zz/cve-2016-0040.svg)

- [https://github.com/de7ec7ed/CVE-2016-0040](https://github.com/de7ec7ed/CVE-2016-0040) :  ![starts](https://img.shields.io/github/stars/de7ec7ed/CVE-2016-0040.svg) ![forks](https://img.shields.io/github/forks/de7ec7ed/CVE-2016-0040.svg)

## CVE-2016-0034
 Microsoft Silverlight 5 before 5.1.41212.0 mishandles negative offsets during decoding, which allows remote attackers to execute arbitrary code or cause a denial of service (object-header corruption) via a crafted web site, aka &quot;Silverlight Runtime Remote Code Execution Vulnerability.&quot;



- [https://github.com/DiamondHunters/CVE-2016-0034-Decompile](https://github.com/DiamondHunters/CVE-2016-0034-Decompile) :  ![starts](https://img.shields.io/github/stars/DiamondHunters/CVE-2016-0034-Decompile.svg) ![forks](https://img.shields.io/github/forks/DiamondHunters/CVE-2016-0034-Decompile.svg)
