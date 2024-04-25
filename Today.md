# Update 2024-04-25
## CVE-2024-27199
 In JetBrains TeamCity before 2023.11.4 path traversal allowing to perform limited admin actions was possible

- [https://github.com/Stuub/RCity-CVE-2024-27198](https://github.com/Stuub/RCity-CVE-2024-27198) :  ![starts](https://img.shields.io/github/stars/Stuub/RCity-CVE-2024-27198.svg) ![forks](https://img.shields.io/github/forks/Stuub/RCity-CVE-2024-27198.svg)


## CVE-2024-27198
 In JetBrains TeamCity before 2023.11.4 authentication bypass allowing to perform admin actions was possible

- [https://github.com/Stuub/RCity-CVE-2024-27198](https://github.com/Stuub/RCity-CVE-2024-27198) :  ![starts](https://img.shields.io/github/stars/Stuub/RCity-CVE-2024-27198.svg) ![forks](https://img.shields.io/github/forks/Stuub/RCity-CVE-2024-27198.svg)


## CVE-2024-25277
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/maen08/CVE-2024-25277](https://github.com/maen08/CVE-2024-25277) :  ![starts](https://img.shields.io/github/stars/maen08/CVE-2024-25277.svg) ![forks](https://img.shields.io/github/forks/maen08/CVE-2024-25277.svg)


## CVE-2024-21338
 Windows Kernel Elevation of Privilege Vulnerability

- [https://github.com/varwara/CVE-2024-21338](https://github.com/varwara/CVE-2024-21338) :  ![starts](https://img.shields.io/github/stars/varwara/CVE-2024-21338.svg) ![forks](https://img.shields.io/github/forks/varwara/CVE-2024-21338.svg)


## CVE-2023-51409
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/imhunterand/CVE-2023-51409](https://github.com/imhunterand/CVE-2023-51409) :  ![starts](https://img.shields.io/github/stars/imhunterand/CVE-2023-51409.svg) ![forks](https://img.shields.io/github/forks/imhunterand/CVE-2023-51409.svg)


## CVE-2023-34040
 In Spring for Apache Kafka 3.0.9 and earlier and versions 2.9.10 and earlier, a possible deserialization attack vector existed, but only if unusual configuration was applied. An attacker would have to construct a malicious serialized object in one of the deserialization exception record headers. Specifically, an application is vulnerable when all of the following are true: * The user does not configure an ErrorHandlingDeserializer for the key and/or value of the record * The user explicitly sets container properties checkDeserExWhenKeyNull and/or checkDeserExWhenValueNull container properties to true. * The user allows untrusted sources to publish to a Kafka topic By default, these properties are false, and the container only attempts to deserialize the headers if an ErrorHandlingDeserializer is configured. The ErrorHandlingDeserializer prevents the vulnerability by removing any such malicious headers before processing the record.

- [https://github.com/buiduchoang24/CVE-2023-34040](https://github.com/buiduchoang24/CVE-2023-34040) :  ![starts](https://img.shields.io/github/stars/buiduchoang24/CVE-2023-34040.svg) ![forks](https://img.shields.io/github/forks/buiduchoang24/CVE-2023-34040.svg)


## CVE-2022-35914
 /vendor/htmlawed/htmlawed/htmLawedTest.php in the htmlawed module for GLPI through 10.0.2 allows PHP code injection.

- [https://github.com/allendemoura/CVE-2022-35914](https://github.com/allendemoura/CVE-2022-35914) :  ![starts](https://img.shields.io/github/stars/allendemoura/CVE-2022-35914.svg) ![forks](https://img.shields.io/github/forks/allendemoura/CVE-2022-35914.svg)


## CVE-2022-4774
 The Bit Form WordPress plugin before 1.9 does not validate the file types uploaded via it's file upload form field, allowing unauthenticated users to upload arbitrary files types such as PHP or HTML files to the server, leading to Remote Code Execution.

- [https://github.com/codeb0ss/xWP-2](https://github.com/codeb0ss/xWP-2) :  ![starts](https://img.shields.io/github/stars/codeb0ss/xWP-2.svg) ![forks](https://img.shields.io/github/forks/codeb0ss/xWP-2.svg)


## CVE-2022-4611
 A vulnerability, which was classified as problematic, was found in Click Studios Passwordstate and Passwordstate Browser Extension Chrome. This affects an unknown part. The manipulation leads to hard-coded credentials. It is possible to initiate the attack remotely. The exploit has been disclosed to the public and may be used. It is recommended to upgrade the affected component. The identifier VDB-216273 was assigned to this vulnerability.

- [https://github.com/Phamchie/CVE-2022-4611](https://github.com/Phamchie/CVE-2022-4611) :  ![starts](https://img.shields.io/github/stars/Phamchie/CVE-2022-4611.svg) ![forks](https://img.shields.io/github/forks/Phamchie/CVE-2022-4611.svg)
- [https://github.com/fgsoftware1/CVE-2022-4611](https://github.com/fgsoftware1/CVE-2022-4611) :  ![starts](https://img.shields.io/github/stars/fgsoftware1/CVE-2022-4611.svg) ![forks](https://img.shields.io/github/forks/fgsoftware1/CVE-2022-4611.svg)


## CVE-2022-4543
 A flaw named &quot;EntryBleed&quot; was found in the Linux Kernel Page Table Isolation (KPTI). This issue could allow a local attacker to leak KASLR base via prefetch side-channels based on TLB timing for Intel systems.

- [https://github.com/sunichi/cve-2022-4543-wrapper](https://github.com/sunichi/cve-2022-4543-wrapper) :  ![starts](https://img.shields.io/github/stars/sunichi/cve-2022-4543-wrapper.svg) ![forks](https://img.shields.io/github/forks/sunichi/cve-2022-4543-wrapper.svg)


## CVE-2022-4510
 A path traversal vulnerability was identified in ReFirm Labs binwalk from version 2.1.2b through 2.3.3 included. By crafting a malicious PFS filesystem file, an attacker can get binwalk's PFS extractor to extract files at arbitrary locations when binwalk is run in extraction mode (-e option). Remote code execution can be achieved by building a PFS filesystem that, upon extraction, would extract a malicious binwalk module into the folder .config/binwalk/plugins. This vulnerability is associated with program files src/binwalk/plugins/unpfs.py. This issue affects binwalk from 2.1.2b through 2.3.3 included.

- [https://github.com/adhikara13/CVE-2022-4510-WalkingPath](https://github.com/adhikara13/CVE-2022-4510-WalkingPath) :  ![starts](https://img.shields.io/github/stars/adhikara13/CVE-2022-4510-WalkingPath.svg) ![forks](https://img.shields.io/github/forks/adhikara13/CVE-2022-4510-WalkingPath.svg)
- [https://github.com/electr0sm0g/CVE-2022-4510](https://github.com/electr0sm0g/CVE-2022-4510) :  ![starts](https://img.shields.io/github/stars/electr0sm0g/CVE-2022-4510.svg) ![forks](https://img.shields.io/github/forks/electr0sm0g/CVE-2022-4510.svg)
- [https://github.com/Kalagious/BadPfs](https://github.com/Kalagious/BadPfs) :  ![starts](https://img.shields.io/github/stars/Kalagious/BadPfs.svg) ![forks](https://img.shields.io/github/forks/Kalagious/BadPfs.svg)


## CVE-2022-4395
 The Membership For WooCommerce WordPress plugin before 2.1.7 does not validate uploaded files, which could allow unauthenticated users to upload arbitrary files, such as malicious PHP code, and achieve RCE.

- [https://github.com/MrG3P5/CVE-2022-4395](https://github.com/MrG3P5/CVE-2022-4395) :  ![starts](https://img.shields.io/github/stars/MrG3P5/CVE-2022-4395.svg) ![forks](https://img.shields.io/github/forks/MrG3P5/CVE-2022-4395.svg)


## CVE-2022-4304
 A timing based side channel exists in the OpenSSL RSA Decryption implementation which could be sufficient to recover a plaintext across a network in a Bleichenbacher style attack. To achieve a successful decryption an attacker would have to be able to send a very large number of trial messages for decryption. The vulnerability affects all RSA padding modes: PKCS#1 v1.5, RSA-OEAP and RSASVE. For example, in a TLS connection, RSA is commonly used by a client to send an encrypted pre-master secret to the server. An attacker that had observed a genuine connection between a client and a server could use this flaw to send trial messages to the server and record the time taken to process them. After a sufficiently large number of messages the attacker could recover the pre-master secret used for the original connection and thus be able to decrypt the application data sent over that connection.

- [https://github.com/Trinadh465/Openssl-1.1.1g_CVE-2022-4304](https://github.com/Trinadh465/Openssl-1.1.1g_CVE-2022-4304) :  ![starts](https://img.shields.io/github/stars/Trinadh465/Openssl-1.1.1g_CVE-2022-4304.svg) ![forks](https://img.shields.io/github/forks/Trinadh465/Openssl-1.1.1g_CVE-2022-4304.svg)


## CVE-2022-4262
 Type confusion in V8 in Google Chrome prior to 108.0.5359.94 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/bjrjk/CVE-2022-4262](https://github.com/bjrjk/CVE-2022-4262) :  ![starts](https://img.shields.io/github/stars/bjrjk/CVE-2022-4262.svg) ![forks](https://img.shields.io/github/forks/bjrjk/CVE-2022-4262.svg)
- [https://github.com/mistymntncop/CVE-2022-4262](https://github.com/mistymntncop/CVE-2022-4262) :  ![starts](https://img.shields.io/github/stars/mistymntncop/CVE-2022-4262.svg) ![forks](https://img.shields.io/github/forks/mistymntncop/CVE-2022-4262.svg)
- [https://github.com/quangnh89/CVE-2022-4262](https://github.com/quangnh89/CVE-2022-4262) :  ![starts](https://img.shields.io/github/stars/quangnh89/CVE-2022-4262.svg) ![forks](https://img.shields.io/github/forks/quangnh89/CVE-2022-4262.svg)


## CVE-2022-4096
 Server-Side Request Forgery (SSRF) in GitHub repository appsmithorg/appsmith prior to 1.8.2.

- [https://github.com/aminetitrofine/CVE-2022-4096](https://github.com/aminetitrofine/CVE-2022-4096) :  ![starts](https://img.shields.io/github/stars/aminetitrofine/CVE-2022-4096.svg) ![forks](https://img.shields.io/github/forks/aminetitrofine/CVE-2022-4096.svg)


## CVE-2022-4063
 The InPost Gallery WordPress plugin before 2.1.4.1 insecurely uses PHP's extract() function when rendering HTML views, allowing attackers to force the inclusion of malicious files &amp; URLs, which may enable them to run code on servers.

- [https://github.com/im-hanzou/INPGer](https://github.com/im-hanzou/INPGer) :  ![starts](https://img.shields.io/github/stars/im-hanzou/INPGer.svg) ![forks](https://img.shields.io/github/forks/im-hanzou/INPGer.svg)


## CVE-2022-4061
 The JobBoardWP WordPress plugin before 1.2.2 does not properly validate file names and types in its file upload functionalities, allowing unauthenticated users to upload arbitrary files such as PHP.

- [https://github.com/im-hanzou/JBWPer](https://github.com/im-hanzou/JBWPer) :  ![starts](https://img.shields.io/github/stars/im-hanzou/JBWPer.svg) ![forks](https://img.shields.io/github/forks/im-hanzou/JBWPer.svg)


## CVE-2022-4060
 The User Post Gallery WordPress plugin through 2.19 does not limit what callback functions can be called by users, making it possible to any visitors to run code on sites running it.

- [https://github.com/im-hanzou/UPGer](https://github.com/im-hanzou/UPGer) :  ![starts](https://img.shields.io/github/stars/im-hanzou/UPGer.svg) ![forks](https://img.shields.io/github/forks/im-hanzou/UPGer.svg)


## CVE-2022-4047
 The Return Refund and Exchange For WooCommerce WordPress plugin before 4.0.9 does not validate attachment files to be uploaded via an AJAX action available to unauthenticated users, which could allow them to upload arbitrary files such as PHP and lead to RCE

- [https://github.com/im-hanzou/WooRefer](https://github.com/im-hanzou/WooRefer) :  ![starts](https://img.shields.io/github/stars/im-hanzou/WooRefer.svg) ![forks](https://img.shields.io/github/forks/im-hanzou/WooRefer.svg)
- [https://github.com/entroychang/CVE-2022-4047](https://github.com/entroychang/CVE-2022-4047) :  ![starts](https://img.shields.io/github/stars/entroychang/CVE-2022-4047.svg) ![forks](https://img.shields.io/github/forks/entroychang/CVE-2022-4047.svg)


## CVE-2022-3992
 A vulnerability classified as problematic was found in SourceCodester Sanitization Management System. Affected by this vulnerability is an unknown functionality of the file admin/?page=system_info of the component Banner Image Handler. The manipulation leads to cross site scripting. The attack can be launched remotely. The associated identifier of this vulnerability is VDB-213571.

- [https://github.com/Urban4/CVE-2022-3992](https://github.com/Urban4/CVE-2022-3992) :  ![starts](https://img.shields.io/github/stars/Urban4/CVE-2022-3992.svg) ![forks](https://img.shields.io/github/forks/Urban4/CVE-2022-3992.svg)


## CVE-2022-3949
 A vulnerability, which was classified as problematic, has been found in Sourcecodester Simple Cashiering System. This issue affects some unknown processing of the component User Account Handler. The manipulation of the argument fullname leads to cross site scripting. The attack may be initiated remotely. The associated identifier of this vulnerability is VDB-213455.

- [https://github.com/maikroservice/CVE-2022-3949](https://github.com/maikroservice/CVE-2022-3949) :  ![starts](https://img.shields.io/github/stars/maikroservice/CVE-2022-3949.svg) ![forks](https://img.shields.io/github/forks/maikroservice/CVE-2022-3949.svg)


## CVE-2022-3942
 A vulnerability was found in SourceCodester Sanitization Management System and classified as problematic. This issue affects some unknown processing of the file php-sms/?p=request_quote. The manipulation leads to cross site scripting. The attack may be initiated remotely. The identifier VDB-213449 was assigned to this vulnerability.

- [https://github.com/maikroservice/CVE-2022-3942](https://github.com/maikroservice/CVE-2022-3942) :  ![starts](https://img.shields.io/github/stars/maikroservice/CVE-2022-3942.svg) ![forks](https://img.shields.io/github/forks/maikroservice/CVE-2022-3942.svg)


## CVE-2022-3910
 Use After Free vulnerability in Linux Kernel allows Privilege Escalation. An improper Update of Reference Count in io_uring leads to Use-After-Free and Local Privilege Escalation. When io_msg_ring was invoked with a fixed file, it called io_fput_file() which improperly decreased its reference count (leading to Use-After-Free and Local Privilege Escalation). Fixed files are permanently registered to the ring, and should not be put separately. We recommend upgrading past commit https://github.com/torvalds/linux/commit/fc7222c3a9f56271fba02aabbfbae999042f1679 https://github.com/torvalds/linux/commit/fc7222c3a9f56271fba02aabbfbae999042f1679

- [https://github.com/veritas501/CVE-2022-3910](https://github.com/veritas501/CVE-2022-3910) :  ![starts](https://img.shields.io/github/stars/veritas501/CVE-2022-3910.svg) ![forks](https://img.shields.io/github/forks/veritas501/CVE-2022-3910.svg)


## CVE-2022-3904
 The MonsterInsights WordPress plugin before 8.9.1 does not sanitize or escape page titles in the top posts/pages section, allowing an unauthenticated attacker to inject arbitrary web scripts into the titles by spoofing requests to google analytics.

- [https://github.com/RandomRobbieBF/CVE-2022-3904](https://github.com/RandomRobbieBF/CVE-2022-3904) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2022-3904.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2022-3904.svg)


## CVE-2022-3786
 A buffer overrun can be triggered in X.509 certificate verification, specifically in name constraint checking. Note that this occurs after certificate chain signature verification and requires either a CA to have signed a malicious certificate or for an application to continue certificate verification despite failure to construct a path to a trusted issuer. An attacker can craft a malicious email address in a certificate to overflow an arbitrary number of bytes containing the `.' character (decimal 46) on the stack. This buffer overflow could result in a crash (causing a denial of service). In a TLS client, this can be triggered by connecting to a malicious server. In a TLS server, this can be triggered if the server requests client authentication and a malicious client connects.

- [https://github.com/NCSC-NL/OpenSSL-2022](https://github.com/NCSC-NL/OpenSSL-2022) :  ![starts](https://img.shields.io/github/stars/NCSC-NL/OpenSSL-2022.svg) ![forks](https://img.shields.io/github/forks/NCSC-NL/OpenSSL-2022.svg)
- [https://github.com/rbowes-r7/cve-2022-3602-and-cve-2022-3786-openssl-poc](https://github.com/rbowes-r7/cve-2022-3602-and-cve-2022-3786-openssl-poc) :  ![starts](https://img.shields.io/github/stars/rbowes-r7/cve-2022-3602-and-cve-2022-3786-openssl-poc.svg) ![forks](https://img.shields.io/github/forks/rbowes-r7/cve-2022-3602-and-cve-2022-3786-openssl-poc.svg)
- [https://github.com/Qualys/osslscanwin](https://github.com/Qualys/osslscanwin) :  ![starts](https://img.shields.io/github/stars/Qualys/osslscanwin.svg) ![forks](https://img.shields.io/github/forks/Qualys/osslscanwin.svg)
- [https://github.com/WhatTheFuzz/openssl-fuzz](https://github.com/WhatTheFuzz/openssl-fuzz) :  ![starts](https://img.shields.io/github/stars/WhatTheFuzz/openssl-fuzz.svg) ![forks](https://img.shields.io/github/forks/WhatTheFuzz/openssl-fuzz.svg)
- [https://github.com/cybersecurityworks553/CVE-2022-3602-and-CVE-2022-3786](https://github.com/cybersecurityworks553/CVE-2022-3602-and-CVE-2022-3786) :  ![starts](https://img.shields.io/github/stars/cybersecurityworks553/CVE-2022-3602-and-CVE-2022-3786.svg) ![forks](https://img.shields.io/github/forks/cybersecurityworks553/CVE-2022-3602-and-CVE-2022-3786.svg)
- [https://github.com/hi-artem/find-spooky-prismacloud](https://github.com/hi-artem/find-spooky-prismacloud) :  ![starts](https://img.shields.io/github/stars/hi-artem/find-spooky-prismacloud.svg) ![forks](https://img.shields.io/github/forks/hi-artem/find-spooky-prismacloud.svg)
- [https://github.com/micr0sh0ft/certscare-openssl3-exploit](https://github.com/micr0sh0ft/certscare-openssl3-exploit) :  ![starts](https://img.shields.io/github/stars/micr0sh0ft/certscare-openssl3-exploit.svg) ![forks](https://img.shields.io/github/forks/micr0sh0ft/certscare-openssl3-exploit.svg)


## CVE-2022-3699
 A privilege escalation vulnerability was reported in the Lenovo HardwareScanPlugin prior to version 1.3.1.2 and Lenovo Diagnostics prior to version 4.45 that could allow a local user to execute code with elevated privileges.

- [https://github.com/alfarom256/CVE-2022-3699](https://github.com/alfarom256/CVE-2022-3699) :  ![starts](https://img.shields.io/github/stars/alfarom256/CVE-2022-3699.svg) ![forks](https://img.shields.io/github/forks/alfarom256/CVE-2022-3699.svg)
- [https://github.com/estimated1337/lenovo_exec](https://github.com/estimated1337/lenovo_exec) :  ![starts](https://img.shields.io/github/stars/estimated1337/lenovo_exec.svg) ![forks](https://img.shields.io/github/forks/estimated1337/lenovo_exec.svg)
- [https://github.com/passion1337/byovd-exploit](https://github.com/passion1337/byovd-exploit) :  ![starts](https://img.shields.io/github/stars/passion1337/byovd-exploit.svg) ![forks](https://img.shields.io/github/forks/passion1337/byovd-exploit.svg)


## CVE-2022-3656
 Insufficient data validation in File System in Google Chrome prior to 107.0.5304.62 allowed a remote attacker to bypass file system restrictions via a crafted HTML page. (Chromium security severity: Medium)

- [https://github.com/momika233/CVE-2022-3656](https://github.com/momika233/CVE-2022-3656) :  ![starts](https://img.shields.io/github/stars/momika233/CVE-2022-3656.svg) ![forks](https://img.shields.io/github/forks/momika233/CVE-2022-3656.svg)


## CVE-2022-3602
 A buffer overrun can be triggered in X.509 certificate verification, specifically in name constraint checking. Note that this occurs after certificate chain signature verification and requires either a CA to have signed the malicious certificate or for the application to continue certificate verification despite failure to construct a path to a trusted issuer. An attacker can craft a malicious email address to overflow four attacker-controlled bytes on the stack. This buffer overflow could result in a crash (causing a denial of service) or potentially remote code execution. Many platforms implement stack overflow protections which would mitigate against the risk of remote code execution. The risk may be further mitigated based on stack layout for any given platform/compiler. Pre-announcements of CVE-2022-3602 described this issue as CRITICAL. Further analysis based on some of the mitigating factors described above have led this to be downgraded to HIGH. Users are still encouraged to upgrade to a new version as soon as possible. In a TLS client, this can be triggered by connecting to a malicious server. In a TLS server, this can be triggered if the server requests client authentication and a malicious client connects. Fixed in OpenSSL 3.0.7 (Affected 3.0.0,3.0.1,3.0.2,3.0.3,3.0.4,3.0.5,3.0.6).

- [https://github.com/NCSC-NL/OpenSSL-2022](https://github.com/NCSC-NL/OpenSSL-2022) :  ![starts](https://img.shields.io/github/stars/NCSC-NL/OpenSSL-2022.svg) ![forks](https://img.shields.io/github/forks/NCSC-NL/OpenSSL-2022.svg)
- [https://github.com/colmmacc/CVE-2022-3602](https://github.com/colmmacc/CVE-2022-3602) :  ![starts](https://img.shields.io/github/stars/colmmacc/CVE-2022-3602.svg) ![forks](https://img.shields.io/github/forks/colmmacc/CVE-2022-3602.svg)
- [https://github.com/rbowes-r7/cve-2022-3602-and-cve-2022-3786-openssl-poc](https://github.com/rbowes-r7/cve-2022-3602-and-cve-2022-3786-openssl-poc) :  ![starts](https://img.shields.io/github/stars/rbowes-r7/cve-2022-3602-and-cve-2022-3786-openssl-poc.svg) ![forks](https://img.shields.io/github/forks/rbowes-r7/cve-2022-3602-and-cve-2022-3786-openssl-poc.svg)
- [https://github.com/eatscrayon/CVE-2022-3602-poc](https://github.com/eatscrayon/CVE-2022-3602-poc) :  ![starts](https://img.shields.io/github/stars/eatscrayon/CVE-2022-3602-poc.svg) ![forks](https://img.shields.io/github/forks/eatscrayon/CVE-2022-3602-poc.svg)
- [https://github.com/fox-it/spookyssl-pcaps](https://github.com/fox-it/spookyssl-pcaps) :  ![starts](https://img.shields.io/github/stars/fox-it/spookyssl-pcaps.svg) ![forks](https://img.shields.io/github/forks/fox-it/spookyssl-pcaps.svg)
- [https://github.com/Qualys/osslscanwin](https://github.com/Qualys/osslscanwin) :  ![starts](https://img.shields.io/github/stars/Qualys/osslscanwin.svg) ![forks](https://img.shields.io/github/forks/Qualys/osslscanwin.svg)
- [https://github.com/corelight/CVE-2022-3602](https://github.com/corelight/CVE-2022-3602) :  ![starts](https://img.shields.io/github/stars/corelight/CVE-2022-3602.svg) ![forks](https://img.shields.io/github/forks/corelight/CVE-2022-3602.svg)
- [https://github.com/attilaszia/cve-2022-3602](https://github.com/attilaszia/cve-2022-3602) :  ![starts](https://img.shields.io/github/stars/attilaszia/cve-2022-3602.svg) ![forks](https://img.shields.io/github/forks/attilaszia/cve-2022-3602.svg)
- [https://github.com/cybersecurityworks553/CVE-2022-3602-and-CVE-2022-3786](https://github.com/cybersecurityworks553/CVE-2022-3602-and-CVE-2022-3786) :  ![starts](https://img.shields.io/github/stars/cybersecurityworks553/CVE-2022-3602-and-CVE-2022-3786.svg) ![forks](https://img.shields.io/github/forks/cybersecurityworks553/CVE-2022-3602-and-CVE-2022-3786.svg)
- [https://github.com/alicangnll/SpookySSL-Scanner](https://github.com/alicangnll/SpookySSL-Scanner) :  ![starts](https://img.shields.io/github/stars/alicangnll/SpookySSL-Scanner.svg) ![forks](https://img.shields.io/github/forks/alicangnll/SpookySSL-Scanner.svg)
- [https://github.com/hi-artem/find-spooky-prismacloud](https://github.com/hi-artem/find-spooky-prismacloud) :  ![starts](https://img.shields.io/github/stars/hi-artem/find-spooky-prismacloud.svg) ![forks](https://img.shields.io/github/forks/hi-artem/find-spooky-prismacloud.svg)
- [https://github.com/micr0sh0ft/certscare-openssl3-exploit](https://github.com/micr0sh0ft/certscare-openssl3-exploit) :  ![starts](https://img.shields.io/github/stars/micr0sh0ft/certscare-openssl3-exploit.svg) ![forks](https://img.shields.io/github/forks/micr0sh0ft/certscare-openssl3-exploit.svg)


## CVE-2022-3590
 WordPress is affected by an unauthenticated blind SSRF in the pingback feature. Because of a TOCTOU race condition between the validation checks and the HTTP request, attackers can reach internal hosts that are explicitly forbidden.

- [https://github.com/hxlxmjxbbxs/CVE-2022-3590-WordPress-Vulnerability-Scanner](https://github.com/hxlxmjxbbxs/CVE-2022-3590-WordPress-Vulnerability-Scanner) :  ![starts](https://img.shields.io/github/stars/hxlxmjxbbxs/CVE-2022-3590-WordPress-Vulnerability-Scanner.svg) ![forks](https://img.shields.io/github/forks/hxlxmjxbbxs/CVE-2022-3590-WordPress-Vulnerability-Scanner.svg)


## CVE-2022-3564
 A vulnerability classified as critical was found in Linux Kernel. Affected by this vulnerability is the function l2cap_reassemble_sdu of the file net/bluetooth/l2cap_core.c of the component Bluetooth. The manipulation leads to use after free. It is recommended to apply a patch to fix this issue. The associated identifier of this vulnerability is VDB-211087.

- [https://github.com/Trinadh465/linux-4.1.15_CVE-2022-3564](https://github.com/Trinadh465/linux-4.1.15_CVE-2022-3564) :  ![starts](https://img.shields.io/github/stars/Trinadh465/linux-4.1.15_CVE-2022-3564.svg) ![forks](https://img.shields.io/github/forks/Trinadh465/linux-4.1.15_CVE-2022-3564.svg)


## CVE-2022-3552
 Unrestricted Upload of File with Dangerous Type in GitHub repository boxbilling/boxbilling prior to 0.0.1.

- [https://github.com/kabir0x23/CVE-2022-3552](https://github.com/kabir0x23/CVE-2022-3552) :  ![starts](https://img.shields.io/github/stars/kabir0x23/CVE-2022-3552.svg) ![forks](https://img.shields.io/github/forks/kabir0x23/CVE-2022-3552.svg)


## CVE-2022-3546
 A vulnerability was found in SourceCodester Simple Cold Storage Management System 1.0 and classified as problematic. Affected by this issue is some unknown functionality of the file /csms/admin/?page=user/list of the component Create User Handler. The manipulation of the argument First Name/Last Name leads to cross site scripting. The attack may be launched remotely. The exploit has been disclosed to the public and may be used. VDB-211046 is the identifier assigned to this vulnerability.

- [https://github.com/thehackingverse/CVE-2022-3546](https://github.com/thehackingverse/CVE-2022-3546) :  ![starts](https://img.shields.io/github/stars/thehackingverse/CVE-2022-3546.svg) ![forks](https://img.shields.io/github/forks/thehackingverse/CVE-2022-3546.svg)


## CVE-2022-3518
 A vulnerability classified as problematic has been found in SourceCodester Sanitization Management System 1.0. Affected is an unknown function of the component User Creation Handler. The manipulation of the argument First Name/Middle Name/Last Name leads to cross site scripting. It is possible to launch the attack remotely. VDB-211014 is the identifier assigned to this vulnerability.

- [https://github.com/lohith19/CVE-2022-3518](https://github.com/lohith19/CVE-2022-3518) :  ![starts](https://img.shields.io/github/stars/lohith19/CVE-2022-3518.svg) ![forks](https://img.shields.io/github/forks/lohith19/CVE-2022-3518.svg)


## CVE-2022-3464
 A vulnerability classified as problematic has been found in puppyCMS up to 5.1. This affects an unknown part of the file /admin/settings.php. The manipulation of the argument site_name leads to cross site scripting. It is possible to initiate the attack remotely. The associated identifier of this vulnerability is VDB-210699.

- [https://github.com/GYLQ/CVE-2022-3464](https://github.com/GYLQ/CVE-2022-3464) :  ![starts](https://img.shields.io/github/stars/GYLQ/CVE-2022-3464.svg) ![forks](https://img.shields.io/github/forks/GYLQ/CVE-2022-3464.svg)


## CVE-2022-3368
 A vulnerability within the Software Updater functionality of Avira Security for Windows allowed an attacker with write access to the filesystem, to escalate his privileges in certain scenarios. The issue was fixed with Avira Security version 1.1.72.30556.

- [https://github.com/Wh04m1001/CVE-2022-3368](https://github.com/Wh04m1001/CVE-2022-3368) :  ![starts](https://img.shields.io/github/stars/Wh04m1001/CVE-2022-3368.svg) ![forks](https://img.shields.io/github/forks/Wh04m1001/CVE-2022-3368.svg)


## CVE-2022-3328
 Race condition in snap-confine's must_mkdir_and_open_with_perms()

- [https://github.com/Mr-xn/CVE-2022-3328](https://github.com/Mr-xn/CVE-2022-3328) :  ![starts](https://img.shields.io/github/stars/Mr-xn/CVE-2022-3328.svg) ![forks](https://img.shields.io/github/forks/Mr-xn/CVE-2022-3328.svg)


## CVE-2022-3317
 Insufficient validation of untrusted input in Intents in Google Chrome on Android prior to 106.0.5249.62 allowed a remote attacker to bypass navigation restrictions via a crafted HTML page. (Chromium security severity: Low)

- [https://github.com/hfh86/CVE-2022-3317](https://github.com/hfh86/CVE-2022-3317) :  ![starts](https://img.shields.io/github/stars/hfh86/CVE-2022-3317.svg) ![forks](https://img.shields.io/github/forks/hfh86/CVE-2022-3317.svg)


## CVE-2022-3172
 A security issue was discovered in kube-apiserver that allows an aggregated API server to redirect client traffic to any URL. This could lead to the client performing unexpected actions as well as forwarding the client's API server credentials to third parties.

- [https://github.com/UgOrange/CVE-2022-3172](https://github.com/UgOrange/CVE-2022-3172) :  ![starts](https://img.shields.io/github/stars/UgOrange/CVE-2022-3172.svg) ![forks](https://img.shields.io/github/forks/UgOrange/CVE-2022-3172.svg)


## CVE-2022-3168
 ** REJECT ** DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: none. Reason: This candidate is unused by its CNA. Notes: none.

- [https://github.com/irsl/CVE-2022-3168-adb-unexpected-reverse-forwards](https://github.com/irsl/CVE-2022-3168-adb-unexpected-reverse-forwards) :  ![starts](https://img.shields.io/github/stars/irsl/CVE-2022-3168-adb-unexpected-reverse-forwards.svg) ![forks](https://img.shields.io/github/forks/irsl/CVE-2022-3168-adb-unexpected-reverse-forwards.svg)


## CVE-2021-4428
 A vulnerability has been found in what3words Autosuggest Plugin up to 4.0.0 on WordPress and classified as problematic. Affected by this vulnerability is the function enqueue_scripts of the file w3w-autosuggest/public/class-w3w-autosuggest-public.php of the component Setting Handler. The manipulation leads to information disclosure. The attack can be launched remotely. Upgrading to version 4.0.1 is able to address this issue. The patch is named dd59cbac5f86057d6a73b87007c08b8bfa0c32ac. It is recommended to upgrade the affected component. The associated identifier of this vulnerability is VDB-234247.

- [https://github.com/lov3r/cve-2021-44228-log4j-exploits](https://github.com/lov3r/cve-2021-44228-log4j-exploits) :  ![starts](https://img.shields.io/github/stars/lov3r/cve-2021-44228-log4j-exploits.svg) ![forks](https://img.shields.io/github/forks/lov3r/cve-2021-44228-log4j-exploits.svg)
- [https://github.com/Grupo-Kapa-7/CVE-2021-44228-Log4j-PoC-RCE](https://github.com/Grupo-Kapa-7/CVE-2021-44228-Log4j-PoC-RCE) :  ![starts](https://img.shields.io/github/stars/Grupo-Kapa-7/CVE-2021-44228-Log4j-PoC-RCE.svg) ![forks](https://img.shields.io/github/forks/Grupo-Kapa-7/CVE-2021-44228-Log4j-PoC-RCE.svg)
- [https://github.com/CERT-hr/Log4Shell](https://github.com/CERT-hr/Log4Shell) :  ![starts](https://img.shields.io/github/stars/CERT-hr/Log4Shell.svg) ![forks](https://img.shields.io/github/forks/CERT-hr/Log4Shell.svg)


## CVE-2021-4204
 An out-of-bounds (OOB) memory access flaw was found in the Linux kernel's eBPF due to an Improper Input Validation. This flaw allows a local attacker with a special privilege to crash the system or leak internal information.

- [https://github.com/tr3ee/CVE-2021-4204](https://github.com/tr3ee/CVE-2021-4204) :  ![starts](https://img.shields.io/github/stars/tr3ee/CVE-2021-4204.svg) ![forks](https://img.shields.io/github/forks/tr3ee/CVE-2021-4204.svg)


## CVE-2021-4191
 An issue has been discovered in GitLab CE/EE affecting versions 13.0 to 14.6.5, 14.7 to 14.7.4, and 14.8 to 14.8.2. Private GitLab instances with restricted sign-ups may be vulnerable to user enumeration to unauthenticated users through the GraphQL API.

- [https://github.com/K3ysTr0K3R/CVE-2021-4191-EXPLOIT](https://github.com/K3ysTr0K3R/CVE-2021-4191-EXPLOIT) :  ![starts](https://img.shields.io/github/stars/K3ysTr0K3R/CVE-2021-4191-EXPLOIT.svg) ![forks](https://img.shields.io/github/forks/K3ysTr0K3R/CVE-2021-4191-EXPLOIT.svg)
- [https://github.com/Adelittle/CVE-2021-4191_Exploits](https://github.com/Adelittle/CVE-2021-4191_Exploits) :  ![starts](https://img.shields.io/github/stars/Adelittle/CVE-2021-4191_Exploits.svg) ![forks](https://img.shields.io/github/forks/Adelittle/CVE-2021-4191_Exploits.svg)


## CVE-2021-4154
 A use-after-free flaw was found in cgroup1_parse_param in kernel/cgroup/cgroup-v1.c in the Linux kernel's cgroup v1 parser. A local attacker with a user privilege could cause a privilege escalation by exploiting the fsconfig syscall parameter leading to a container breakout and a denial of service on the system.

- [https://github.com/Markakd/CVE-2021-4154](https://github.com/Markakd/CVE-2021-4154) :  ![starts](https://img.shields.io/github/stars/Markakd/CVE-2021-4154.svg) ![forks](https://img.shields.io/github/forks/Markakd/CVE-2021-4154.svg)
- [https://github.com/veritas501/CVE-2021-4154](https://github.com/veritas501/CVE-2021-4154) :  ![starts](https://img.shields.io/github/stars/veritas501/CVE-2021-4154.svg) ![forks](https://img.shields.io/github/forks/veritas501/CVE-2021-4154.svg)


## CVE-2021-4104
 JMSAppender in Log4j 1.2 is vulnerable to deserialization of untrusted data when the attacker has write access to the Log4j configuration. The attacker can provide TopicBindingName and TopicConnectionFactoryBindingName configurations causing JMSAppender to perform JNDI requests that result in remote code execution in a similar fashion to CVE-2021-44228. Note this issue only affects Log4j 1.2 when specifically configured to use JMSAppender, which is not the default. Apache Log4j 1.2 reached end of life in August 2015. Users should upgrade to Log4j 2 as it addresses numerous other issues from the previous versions.

- [https://github.com/NCSC-NL/log4shell](https://github.com/NCSC-NL/log4shell) :  ![starts](https://img.shields.io/github/stars/NCSC-NL/log4shell.svg) ![forks](https://img.shields.io/github/forks/NCSC-NL/log4shell.svg)
- [https://github.com/logpresso/CVE-2021-44228-Scanner](https://github.com/logpresso/CVE-2021-44228-Scanner) :  ![starts](https://img.shields.io/github/stars/logpresso/CVE-2021-44228-Scanner.svg) ![forks](https://img.shields.io/github/forks/logpresso/CVE-2021-44228-Scanner.svg)
- [https://github.com/Qualys/log4jscanwin](https://github.com/Qualys/log4jscanwin) :  ![starts](https://img.shields.io/github/stars/Qualys/log4jscanwin.svg) ![forks](https://img.shields.io/github/forks/Qualys/log4jscanwin.svg)
- [https://github.com/HynekPetrak/log4shell-finder](https://github.com/HynekPetrak/log4shell-finder) :  ![starts](https://img.shields.io/github/stars/HynekPetrak/log4shell-finder.svg) ![forks](https://img.shields.io/github/forks/HynekPetrak/log4shell-finder.svg)
- [https://github.com/cckuailong/log4shell_1.x](https://github.com/cckuailong/log4shell_1.x) :  ![starts](https://img.shields.io/github/stars/cckuailong/log4shell_1.x.svg) ![forks](https://img.shields.io/github/forks/cckuailong/log4shell_1.x.svg)
- [https://github.com/thl-cmk/CVE-log4j-check_mk-plugin](https://github.com/thl-cmk/CVE-log4j-check_mk-plugin) :  ![starts](https://img.shields.io/github/stars/thl-cmk/CVE-log4j-check_mk-plugin.svg) ![forks](https://img.shields.io/github/forks/thl-cmk/CVE-log4j-check_mk-plugin.svg)
- [https://github.com/TheInterception/Log4J-Simulation-Tool](https://github.com/TheInterception/Log4J-Simulation-Tool) :  ![starts](https://img.shields.io/github/stars/TheInterception/Log4J-Simulation-Tool.svg) ![forks](https://img.shields.io/github/forks/TheInterception/Log4J-Simulation-Tool.svg)
- [https://github.com/open-AIMS/log4j](https://github.com/open-AIMS/log4j) :  ![starts](https://img.shields.io/github/stars/open-AIMS/log4j.svg) ![forks](https://img.shields.io/github/forks/open-AIMS/log4j.svg)


## CVE-2021-4045
 TP-Link Tapo C200 IP camera, on its 1.1.15 firmware version and below, is affected by an unauthenticated RCE vulnerability, present in the uhttpd binary running by default as root. The exploitation of this vulnerability allows an attacker to take full control of the camera.

- [https://github.com/hacefresko/CVE-2021-4045-PoC](https://github.com/hacefresko/CVE-2021-4045-PoC) :  ![starts](https://img.shields.io/github/stars/hacefresko/CVE-2021-4045-PoC.svg) ![forks](https://img.shields.io/github/forks/hacefresko/CVE-2021-4045-PoC.svg)
- [https://github.com/onebytex/CVE-2021-4045](https://github.com/onebytex/CVE-2021-4045) :  ![starts](https://img.shields.io/github/stars/onebytex/CVE-2021-4045.svg) ![forks](https://img.shields.io/github/forks/onebytex/CVE-2021-4045.svg)
- [https://github.com/pl4int3xt/CVE-2021-4045](https://github.com/pl4int3xt/CVE-2021-4045) :  ![starts](https://img.shields.io/github/stars/pl4int3xt/CVE-2021-4045.svg) ![forks](https://img.shields.io/github/forks/pl4int3xt/CVE-2021-4045.svg)


## CVE-2021-4043
 NULL Pointer Dereference in GitHub repository gpac/gpac prior to 1.1.0.

- [https://github.com/cyberark/PwnKit-Hunter](https://github.com/cyberark/PwnKit-Hunter) :  ![starts](https://img.shields.io/github/stars/cyberark/PwnKit-Hunter.svg) ![forks](https://img.shields.io/github/forks/cyberark/PwnKit-Hunter.svg)


## CVE-2021-4036
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/khulnasoft-lab/awesome-security](https://github.com/khulnasoft-lab/awesome-security) :  ![starts](https://img.shields.io/github/stars/khulnasoft-lab/awesome-security.svg) ![forks](https://img.shields.io/github/forks/khulnasoft-lab/awesome-security.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/berdav/CVE-2021-4034](https://github.com/berdav/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/berdav/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/berdav/CVE-2021-4034.svg)
- [https://github.com/jm33-m0/emp3r0r](https://github.com/jm33-m0/emp3r0r) :  ![starts](https://img.shields.io/github/stars/jm33-m0/emp3r0r.svg) ![forks](https://img.shields.io/github/forks/jm33-m0/emp3r0r.svg)
- [https://github.com/arthepsy/CVE-2021-4034](https://github.com/arthepsy/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/arthepsy/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/arthepsy/CVE-2021-4034.svg)
- [https://github.com/ly4k/PwnKit](https://github.com/ly4k/PwnKit) :  ![starts](https://img.shields.io/github/stars/ly4k/PwnKit.svg) ![forks](https://img.shields.io/github/forks/ly4k/PwnKit.svg)
- [https://github.com/Al1ex/LinuxEelvation](https://github.com/Al1ex/LinuxEelvation) :  ![starts](https://img.shields.io/github/stars/Al1ex/LinuxEelvation.svg) ![forks](https://img.shields.io/github/forks/Al1ex/LinuxEelvation.svg)
- [https://github.com/PwnFunction/CVE-2021-4034](https://github.com/PwnFunction/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/PwnFunction/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/PwnFunction/CVE-2021-4034.svg)
- [https://github.com/joeammond/CVE-2021-4034](https://github.com/joeammond/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/joeammond/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/joeammond/CVE-2021-4034.svg)
- [https://github.com/dzonerzy/poc-cve-2021-4034](https://github.com/dzonerzy/poc-cve-2021-4034) :  ![starts](https://img.shields.io/github/stars/dzonerzy/poc-cve-2021-4034.svg) ![forks](https://img.shields.io/github/forks/dzonerzy/poc-cve-2021-4034.svg)
- [https://github.com/Rvn0xsy/CVE-2021-4034](https://github.com/Rvn0xsy/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/Rvn0xsy/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/Rvn0xsy/CVE-2021-4034.svg)
- [https://github.com/Ayrx/CVE-2021-4034](https://github.com/Ayrx/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/Ayrx/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/Ayrx/CVE-2021-4034.svg)
- [https://github.com/luijait/PwnKit-Exploit](https://github.com/luijait/PwnKit-Exploit) :  ![starts](https://img.shields.io/github/stars/luijait/PwnKit-Exploit.svg) ![forks](https://img.shields.io/github/forks/luijait/PwnKit-Exploit.svg)
- [https://github.com/Nickguitar/YAPS](https://github.com/Nickguitar/YAPS) :  ![starts](https://img.shields.io/github/stars/Nickguitar/YAPS.svg) ![forks](https://img.shields.io/github/forks/Nickguitar/YAPS.svg)
- [https://github.com/EstamelGG/CVE-2021-4034-NoGCC](https://github.com/EstamelGG/CVE-2021-4034-NoGCC) :  ![starts](https://img.shields.io/github/stars/EstamelGG/CVE-2021-4034-NoGCC.svg) ![forks](https://img.shields.io/github/forks/EstamelGG/CVE-2021-4034-NoGCC.svg)
- [https://github.com/ryaagard/CVE-2021-4034](https://github.com/ryaagard/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/ryaagard/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/ryaagard/CVE-2021-4034.svg)
- [https://github.com/nikaiw/CVE-2021-4034](https://github.com/nikaiw/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/nikaiw/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/nikaiw/CVE-2021-4034.svg)
- [https://github.com/zhzyker/CVE-2021-4034](https://github.com/zhzyker/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/zhzyker/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/zhzyker/CVE-2021-4034.svg)
- [https://github.com/jm33-m0/go-lpe](https://github.com/jm33-m0/go-lpe) :  ![starts](https://img.shields.io/github/stars/jm33-m0/go-lpe.svg) ![forks](https://img.shields.io/github/forks/jm33-m0/go-lpe.svg)
- [https://github.com/DanaEpp/pwncat_pwnkit](https://github.com/DanaEpp/pwncat_pwnkit) :  ![starts](https://img.shields.io/github/stars/DanaEpp/pwncat_pwnkit.svg) ![forks](https://img.shields.io/github/forks/DanaEpp/pwncat_pwnkit.svg)
- [https://github.com/PeterGottesman/pwnkit-exploit](https://github.com/PeterGottesman/pwnkit-exploit) :  ![starts](https://img.shields.io/github/stars/PeterGottesman/pwnkit-exploit.svg) ![forks](https://img.shields.io/github/forks/PeterGottesman/pwnkit-exploit.svg)
- [https://github.com/c3l3si4n/pwnkit](https://github.com/c3l3si4n/pwnkit) :  ![starts](https://img.shields.io/github/stars/c3l3si4n/pwnkit.svg) ![forks](https://img.shields.io/github/forks/c3l3si4n/pwnkit.svg)
- [https://github.com/mebeim/CVE-2021-4034](https://github.com/mebeim/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/mebeim/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/mebeim/CVE-2021-4034.svg)
- [https://github.com/ck00004/CVE-2021-4034](https://github.com/ck00004/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/ck00004/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/ck00004/CVE-2021-4034.svg)
- [https://github.com/c3c/CVE-2021-4034](https://github.com/c3c/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/c3c/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/c3c/CVE-2021-4034.svg)
- [https://github.com/kimusan/pkwner](https://github.com/kimusan/pkwner) :  ![starts](https://img.shields.io/github/stars/kimusan/pkwner.svg) ![forks](https://img.shields.io/github/forks/kimusan/pkwner.svg)
- [https://github.com/evdenis/lsm_bpf_check_argc0](https://github.com/evdenis/lsm_bpf_check_argc0) :  ![starts](https://img.shields.io/github/stars/evdenis/lsm_bpf_check_argc0.svg) ![forks](https://img.shields.io/github/forks/evdenis/lsm_bpf_check_argc0.svg)
- [https://github.com/dadvlingd/CVE-2021-4034](https://github.com/dadvlingd/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/dadvlingd/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/dadvlingd/CVE-2021-4034.svg)
- [https://github.com/Almorabea/pkexec-exploit](https://github.com/Almorabea/pkexec-exploit) :  ![starts](https://img.shields.io/github/stars/Almorabea/pkexec-exploit.svg) ![forks](https://img.shields.io/github/forks/Almorabea/pkexec-exploit.svg)
- [https://github.com/n3onhacks/CVE-2021-4034](https://github.com/n3onhacks/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/n3onhacks/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/n3onhacks/CVE-2021-4034.svg)
- [https://github.com/JohnHammond/CVE-2021-4034](https://github.com/JohnHammond/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/JohnHammond/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/JohnHammond/CVE-2021-4034.svg)
- [https://github.com/khulnasoft-lab/awesome-security](https://github.com/khulnasoft-lab/awesome-security) :  ![starts](https://img.shields.io/github/stars/khulnasoft-lab/awesome-security.svg) ![forks](https://img.shields.io/github/forks/khulnasoft-lab/awesome-security.svg)
- [https://github.com/An00bRektn/CVE-2021-4034](https://github.com/An00bRektn/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/An00bRektn/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/An00bRektn/CVE-2021-4034.svg)
- [https://github.com/chenaotian/CVE-2021-4034](https://github.com/chenaotian/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/chenaotian/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/chenaotian/CVE-2021-4034.svg)
- [https://github.com/drapl0n/pwnKit](https://github.com/drapl0n/pwnKit) :  ![starts](https://img.shields.io/github/stars/drapl0n/pwnKit.svg) ![forks](https://img.shields.io/github/forks/drapl0n/pwnKit.svg)
- [https://github.com/Bin4xin/bin4xin.github.io](https://github.com/Bin4xin/bin4xin.github.io) :  ![starts](https://img.shields.io/github/stars/Bin4xin/bin4xin.github.io.svg) ![forks](https://img.shields.io/github/forks/Bin4xin/bin4xin.github.io.svg)
- [https://github.com/wudicainiao/cve-2021-4034](https://github.com/wudicainiao/cve-2021-4034) :  ![starts](https://img.shields.io/github/stars/wudicainiao/cve-2021-4034.svg) ![forks](https://img.shields.io/github/forks/wudicainiao/cve-2021-4034.svg)
- [https://github.com/Audiobahn/CVE-2021-4034](https://github.com/Audiobahn/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/Audiobahn/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/Audiobahn/CVE-2021-4034.svg)
- [https://github.com/sofire/polkit-0.96-CVE-2021-4034](https://github.com/sofire/polkit-0.96-CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/sofire/polkit-0.96-CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/sofire/polkit-0.96-CVE-2021-4034.svg)
- [https://github.com/rvizx/CVE-2021-4034](https://github.com/rvizx/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/rvizx/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/rvizx/CVE-2021-4034.svg)
- [https://github.com/Kirill89/CVE-2021-4034](https://github.com/Kirill89/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/Kirill89/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/Kirill89/CVE-2021-4034.svg)
- [https://github.com/clubby789/CVE-2021-4034](https://github.com/clubby789/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/clubby789/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/clubby789/CVE-2021-4034.svg)
- [https://github.com/jpmcb/pwnkit-go](https://github.com/jpmcb/pwnkit-go) :  ![starts](https://img.shields.io/github/stars/jpmcb/pwnkit-go.svg) ![forks](https://img.shields.io/github/forks/jpmcb/pwnkit-go.svg)
- [https://github.com/Y3A/CVE-2021-4034](https://github.com/Y3A/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/Y3A/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/Y3A/CVE-2021-4034.svg)
- [https://github.com/Yakumwamba/POC-CVE-2021-4034](https://github.com/Yakumwamba/POC-CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/Yakumwamba/POC-CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/Yakumwamba/POC-CVE-2021-4034.svg)
- [https://github.com/OXDBXKXO/ez-pwnkit](https://github.com/OXDBXKXO/ez-pwnkit) :  ![starts](https://img.shields.io/github/stars/OXDBXKXO/ez-pwnkit.svg) ![forks](https://img.shields.io/github/forks/OXDBXKXO/ez-pwnkit.svg)
- [https://github.com/tahaafarooq/poppy](https://github.com/tahaafarooq/poppy) :  ![starts](https://img.shields.io/github/stars/tahaafarooq/poppy.svg) ![forks](https://img.shields.io/github/forks/tahaafarooq/poppy.svg)
- [https://github.com/FDlucifer/Pwnkit-go](https://github.com/FDlucifer/Pwnkit-go) :  ![starts](https://img.shields.io/github/stars/FDlucifer/Pwnkit-go.svg) ![forks](https://img.shields.io/github/forks/FDlucifer/Pwnkit-go.svg)
- [https://github.com/callrbx/pkexec-lpe-poc](https://github.com/callrbx/pkexec-lpe-poc) :  ![starts](https://img.shields.io/github/stars/callrbx/pkexec-lpe-poc.svg) ![forks](https://img.shields.io/github/forks/callrbx/pkexec-lpe-poc.svg)
- [https://github.com/TheJoyOfHacking/berdav-CVE-2021-4034](https://github.com/TheJoyOfHacking/berdav-CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/TheJoyOfHacking/berdav-CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/TheJoyOfHacking/berdav-CVE-2021-4034.svg)
- [https://github.com/navisec/CVE-2021-4034-PwnKit](https://github.com/navisec/CVE-2021-4034-PwnKit) :  ![starts](https://img.shields.io/github/stars/navisec/CVE-2021-4034-PwnKit.svg) ![forks](https://img.shields.io/github/forks/navisec/CVE-2021-4034-PwnKit.svg)
- [https://github.com/Al1ex/CVE-2021-4034](https://github.com/Al1ex/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/Al1ex/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/Al1ex/CVE-2021-4034.svg)
- [https://github.com/artemis-mike/cve-2021-4034](https://github.com/artemis-mike/cve-2021-4034) :  ![starts](https://img.shields.io/github/stars/artemis-mike/cve-2021-4034.svg) ![forks](https://img.shields.io/github/forks/artemis-mike/cve-2021-4034.svg)
- [https://github.com/x04000/CVE-2021-4034](https://github.com/x04000/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/x04000/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/x04000/CVE-2021-4034.svg)
- [https://github.com/flux10n/CVE-2021-4034](https://github.com/flux10n/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/flux10n/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/flux10n/CVE-2021-4034.svg)
- [https://github.com/whokilleddb/CVE-2021-4034](https://github.com/whokilleddb/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/whokilleddb/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/whokilleddb/CVE-2021-4034.svg)
- [https://github.com/NiS3x/CVE-2021-4034](https://github.com/NiS3x/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/NiS3x/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/NiS3x/CVE-2021-4034.svg)
- [https://github.com/codiobert/pwnkit-scanner](https://github.com/codiobert/pwnkit-scanner) :  ![starts](https://img.shields.io/github/stars/codiobert/pwnkit-scanner.svg) ![forks](https://img.shields.io/github/forks/codiobert/pwnkit-scanner.svg)
- [https://github.com/hackingyseguridad/CVE-2021-4034](https://github.com/hackingyseguridad/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/hackingyseguridad/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/hackingyseguridad/CVE-2021-4034.svg)
- [https://github.com/Anonymous-Family/CVE-2021-4034](https://github.com/Anonymous-Family/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/Anonymous-Family/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/Anonymous-Family/CVE-2021-4034.svg)
- [https://github.com/locksec/CVE-2021-4034](https://github.com/locksec/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/locksec/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/locksec/CVE-2021-4034.svg)
- [https://github.com/gbrsh/CVE-2021-4034](https://github.com/gbrsh/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/gbrsh/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/gbrsh/CVE-2021-4034.svg)
- [https://github.com/LJP-TW/CVE-2021-4034](https://github.com/LJP-TW/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/LJP-TW/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/LJP-TW/CVE-2021-4034.svg)
- [https://github.com/Pixailz/CVE-2021-4034](https://github.com/Pixailz/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/Pixailz/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/Pixailz/CVE-2021-4034.svg)
- [https://github.com/deoxykev/CVE-2021-4034-Rust](https://github.com/deoxykev/CVE-2021-4034-Rust) :  ![starts](https://img.shields.io/github/stars/deoxykev/CVE-2021-4034-Rust.svg) ![forks](https://img.shields.io/github/forks/deoxykev/CVE-2021-4034-Rust.svg)
- [https://github.com/x04000/AutoPwnkit](https://github.com/x04000/AutoPwnkit) :  ![starts](https://img.shields.io/github/stars/x04000/AutoPwnkit.svg) ![forks](https://img.shields.io/github/forks/x04000/AutoPwnkit.svg)
- [https://github.com/Nosferatuvjr/PwnKit](https://github.com/Nosferatuvjr/PwnKit) :  ![starts](https://img.shields.io/github/stars/Nosferatuvjr/PwnKit.svg) ![forks](https://img.shields.io/github/forks/Nosferatuvjr/PwnKit.svg)
- [https://github.com/mutur4/Hacking-Scripts](https://github.com/mutur4/Hacking-Scripts) :  ![starts](https://img.shields.io/github/stars/mutur4/Hacking-Scripts.svg) ![forks](https://img.shields.io/github/forks/mutur4/Hacking-Scripts.svg)
- [https://github.com/sentryCyberSec/sentryCyberSec.github.io](https://github.com/sentryCyberSec/sentryCyberSec.github.io) :  ![starts](https://img.shields.io/github/stars/sentryCyberSec/sentryCyberSec.github.io.svg) ![forks](https://img.shields.io/github/forks/sentryCyberSec/sentryCyberSec.github.io.svg)
- [https://github.com/ch4rum/CVE-2021-4034](https://github.com/ch4rum/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/ch4rum/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/ch4rum/CVE-2021-4034.svg)
- [https://github.com/battleoverflow/CVE-2021-4034](https://github.com/battleoverflow/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/battleoverflow/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/battleoverflow/CVE-2021-4034.svg)
- [https://github.com/oreosec/pwnkit](https://github.com/oreosec/pwnkit) :  ![starts](https://img.shields.io/github/stars/oreosec/pwnkit.svg) ![forks](https://img.shields.io/github/forks/oreosec/pwnkit.svg)
- [https://github.com/moldabekov/CVE-2021-4034](https://github.com/moldabekov/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/moldabekov/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/moldabekov/CVE-2021-4034.svg)
- [https://github.com/ayypril/CVE-2021-4034](https://github.com/ayypril/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/ayypril/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/ayypril/CVE-2021-4034.svg)
- [https://github.com/Immersive-Labs-Sec/CVE-2021-4034](https://github.com/Immersive-Labs-Sec/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/Immersive-Labs-Sec/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/Immersive-Labs-Sec/CVE-2021-4034.svg)
- [https://github.com/0x01-sec/CVE-2021-4034-](https://github.com/0x01-sec/CVE-2021-4034-) :  ![starts](https://img.shields.io/github/stars/0x01-sec/CVE-2021-4034-.svg) ![forks](https://img.shields.io/github/forks/0x01-sec/CVE-2021-4034-.svg)
- [https://github.com/mutur4/CVE-2021-4034](https://github.com/mutur4/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/mutur4/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/mutur4/CVE-2021-4034.svg)
- [https://github.com/JoyGhoshs/CVE-2021-4034](https://github.com/JoyGhoshs/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/JoyGhoshs/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/JoyGhoshs/CVE-2021-4034.svg)
- [https://github.com/cerodah/CVE-2021-4034](https://github.com/cerodah/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/cerodah/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/cerodah/CVE-2021-4034.svg)
- [https://github.com/thatstraw/CVE-2021-4034](https://github.com/thatstraw/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/thatstraw/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/thatstraw/CVE-2021-4034.svg)
- [https://github.com/HrishitJoshi/CVE-2021-4034](https://github.com/HrishitJoshi/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/HrishitJoshi/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/HrishitJoshi/CVE-2021-4034.svg)
- [https://github.com/defhacks/cve-2021-4034](https://github.com/defhacks/cve-2021-4034) :  ![starts](https://img.shields.io/github/stars/defhacks/cve-2021-4034.svg) ![forks](https://img.shields.io/github/forks/defhacks/cve-2021-4034.svg)
- [https://github.com/vilasboasph/CVE-2021-4034](https://github.com/vilasboasph/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/vilasboasph/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/vilasboasph/CVE-2021-4034.svg)
- [https://github.com/cd80-ctf/CVE-2021-4034](https://github.com/cd80-ctf/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/cd80-ctf/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/cd80-ctf/CVE-2021-4034.svg)
- [https://github.com/LukeGix/CVE-2021-4034](https://github.com/LukeGix/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/LukeGix/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/LukeGix/CVE-2021-4034.svg)
- [https://github.com/Tanmay-N/CVE-2021-4034](https://github.com/Tanmay-N/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/Tanmay-N/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/Tanmay-N/CVE-2021-4034.svg)
- [https://github.com/wongwaituck/CVE-2021-4034](https://github.com/wongwaituck/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/wongwaituck/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/wongwaituck/CVE-2021-4034.svg)
- [https://github.com/hahaleyile/CVE-2021-4034](https://github.com/hahaleyile/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/hahaleyile/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/hahaleyile/CVE-2021-4034.svg)
- [https://github.com/CYB3RK1D/CVE-2021-4034-POC](https://github.com/CYB3RK1D/CVE-2021-4034-POC) :  ![starts](https://img.shields.io/github/stars/CYB3RK1D/CVE-2021-4034-POC.svg) ![forks](https://img.shields.io/github/forks/CYB3RK1D/CVE-2021-4034-POC.svg)
- [https://github.com/jehovah2002/CVE-2021-4034-pwnkit](https://github.com/jehovah2002/CVE-2021-4034-pwnkit) :  ![starts](https://img.shields.io/github/stars/jehovah2002/CVE-2021-4034-pwnkit.svg) ![forks](https://img.shields.io/github/forks/jehovah2002/CVE-2021-4034-pwnkit.svg)
- [https://github.com/JoaoFukuda/CVE-2021-4034_POC](https://github.com/JoaoFukuda/CVE-2021-4034_POC) :  ![starts](https://img.shields.io/github/stars/JoaoFukuda/CVE-2021-4034_POC.svg) ![forks](https://img.shields.io/github/forks/JoaoFukuda/CVE-2021-4034_POC.svg)
- [https://github.com/cdxiaodong/CVE-2021-4034-touch](https://github.com/cdxiaodong/CVE-2021-4034-touch) :  ![starts](https://img.shields.io/github/stars/cdxiaodong/CVE-2021-4034-touch.svg) ![forks](https://img.shields.io/github/forks/cdxiaodong/CVE-2021-4034-touch.svg)
- [https://github.com/jcatala/f_poc_cve-2021-4034](https://github.com/jcatala/f_poc_cve-2021-4034) :  ![starts](https://img.shields.io/github/stars/jcatala/f_poc_cve-2021-4034.svg) ![forks](https://img.shields.io/github/forks/jcatala/f_poc_cve-2021-4034.svg)
- [https://github.com/wechicken456/CVE-2021-4034-CTF-writeup](https://github.com/wechicken456/CVE-2021-4034-CTF-writeup) :  ![starts](https://img.shields.io/github/stars/wechicken456/CVE-2021-4034-CTF-writeup.svg) ![forks](https://img.shields.io/github/forks/wechicken456/CVE-2021-4034-CTF-writeup.svg)
- [https://github.com/0xalwayslucky/log4j-polkit-poc](https://github.com/0xalwayslucky/log4j-polkit-poc) :  ![starts](https://img.shields.io/github/stars/0xalwayslucky/log4j-polkit-poc.svg) ![forks](https://img.shields.io/github/forks/0xalwayslucky/log4j-polkit-poc.svg)
- [https://github.com/xcanwin/CVE-2021-4034-UniontechOS](https://github.com/xcanwin/CVE-2021-4034-UniontechOS) :  ![starts](https://img.shields.io/github/stars/xcanwin/CVE-2021-4034-UniontechOS.svg) ![forks](https://img.shields.io/github/forks/xcanwin/CVE-2021-4034-UniontechOS.svg)
- [https://github.com/n3onhacks/CVE-2021-4034-BASH-One-File-Exploit](https://github.com/n3onhacks/CVE-2021-4034-BASH-One-File-Exploit) :  ![starts](https://img.shields.io/github/stars/n3onhacks/CVE-2021-4034-BASH-One-File-Exploit.svg) ![forks](https://img.shields.io/github/forks/n3onhacks/CVE-2021-4034-BASH-One-File-Exploit.svg)


## CVE-2021-3972
 A potential vulnerability by a driver used during manufacturing process on some consumer Lenovo Notebook devices' BIOS that was mistakenly not deactivated may allow an attacker with elevated privileges to modify secure boot setting by modifying an NVRAM variable.

- [https://github.com/killvxk/CVE-2021-3972](https://github.com/killvxk/CVE-2021-3972) :  ![starts](https://img.shields.io/github/stars/killvxk/CVE-2021-3972.svg) ![forks](https://img.shields.io/github/forks/killvxk/CVE-2021-3972.svg)


## CVE-2021-3929
 A DMA reentrancy issue was found in the NVM Express Controller (NVME) emulation in QEMU. This CVE is similar to CVE-2021-3750 and, just like it, when the reentrancy write triggers the reset function nvme_ctrl_reset(), data structs will be freed leading to a use-after-free issue. A malicious guest could use this flaw to crash the QEMU process on the host, resulting in a denial of service condition or, potentially, executing arbitrary code within the context of the QEMU process on the host.

- [https://github.com/QiuhaoLi/CVE-2021-3929-3947](https://github.com/QiuhaoLi/CVE-2021-3929-3947) :  ![starts](https://img.shields.io/github/stars/QiuhaoLi/CVE-2021-3929-3947.svg) ![forks](https://img.shields.io/github/forks/QiuhaoLi/CVE-2021-3929-3947.svg)


## CVE-2021-3899
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/liumuqing/CVE-2021-3899_PoC](https://github.com/liumuqing/CVE-2021-3899_PoC) :  ![starts](https://img.shields.io/github/stars/liumuqing/CVE-2021-3899_PoC.svg) ![forks](https://img.shields.io/github/forks/liumuqing/CVE-2021-3899_PoC.svg)


## CVE-2021-3864
 A flaw was found in the way the dumpable flag setting was handled when certain SUID binaries executed its descendants. The prerequisite is a SUID binary that sets real UID equal to effective UID, and real GID equal to effective GID. The descendant will then have a dumpable value set to 1. As a result, if the descendant process crashes and core_pattern is set to a relative value, its core dump is stored in the current directory with uid:gid permissions. An unprivileged local user with eligible root SUID binary could use this flaw to place core dumps into root-owned directories, potentially resulting in escalation of privileges.

- [https://github.com/walac/cve-2021-3864](https://github.com/walac/cve-2021-3864) :  ![starts](https://img.shields.io/github/stars/walac/cve-2021-3864.svg) ![forks](https://img.shields.io/github/forks/walac/cve-2021-3864.svg)


## CVE-2021-3754
 A flaw was found in keycloak where an attacker is able to register himself with the username same as the email ID of any existing user. This may cause trouble in getting password recovery email in case the user forgets the password.

- [https://github.com/7Ragnarok7/CVE-2021-3754](https://github.com/7Ragnarok7/CVE-2021-3754) :  ![starts](https://img.shields.io/github/stars/7Ragnarok7/CVE-2021-3754.svg) ![forks](https://img.shields.io/github/forks/7Ragnarok7/CVE-2021-3754.svg)


## CVE-2021-3749
 axios is vulnerable to Inefficient Regular Expression Complexity

- [https://github.com/T-Guerrero/axios-redos](https://github.com/T-Guerrero/axios-redos) :  ![starts](https://img.shields.io/github/stars/T-Guerrero/axios-redos.svg) ![forks](https://img.shields.io/github/forks/T-Guerrero/axios-redos.svg)


## CVE-2021-3708
 D-Link router DSL-2750U with firmware vME1.16 or prior versions is vulnerable to OS command injection. An unauthenticated attacker on the local network may exploit this, with CVE-2021-3707, to execute any OS commands on the vulnerable device.

- [https://github.com/HadiMed/DSL-2750U-Full-chain](https://github.com/HadiMed/DSL-2750U-Full-chain) :  ![starts](https://img.shields.io/github/stars/HadiMed/DSL-2750U-Full-chain.svg) ![forks](https://img.shields.io/github/forks/HadiMed/DSL-2750U-Full-chain.svg)


## CVE-2021-3707
 D-Link router DSL-2750U with firmware vME1.16 or prior versions is vulnerable to unauthorized configuration modification. An unauthenticated attacker on the local network may exploit this, with CVE-2021-3708, to execute any OS commands on the vulnerable device.

- [https://github.com/HadiMed/DSL-2750U-Full-chain](https://github.com/HadiMed/DSL-2750U-Full-chain) :  ![starts](https://img.shields.io/github/stars/HadiMed/DSL-2750U-Full-chain.svg) ![forks](https://img.shields.io/github/forks/HadiMed/DSL-2750U-Full-chain.svg)


## CVE-2021-3679
 A lack of CPU resource in the Linux kernel tracing module functionality in versions prior to 5.14-rc3 was found in the way user uses trace ring buffer in a specific way. Only privileged local users (with CAP_SYS_ADMIN capability) could use this flaw to starve the resources causing denial of service.

- [https://github.com/aegistudio/RingBufferDetonator](https://github.com/aegistudio/RingBufferDetonator) :  ![starts](https://img.shields.io/github/stars/aegistudio/RingBufferDetonator.svg) ![forks](https://img.shields.io/github/forks/aegistudio/RingBufferDetonator.svg)


## CVE-2021-3656
 A flaw was found in the KVM's AMD code for supporting SVM nested virtualization. The flaw occurs when processing the VMCB (virtual machine control block) provided by the L1 guest to spawn/handle a nested guest (L2). Due to improper validation of the &quot;virt_ext&quot; field, this issue could allow a malicious L1 to disable both VMLOAD/VMSAVE intercepts and VLS (Virtual VMLOAD/VMSAVE) for the L2 guest. As a result, the L2 guest would be allowed to read/write physical pages of the host, resulting in a crash of the entire system, leak of sensitive data or potential guest-to-host escape.

- [https://github.com/rami08448/CVE-2021-3656-Demo](https://github.com/rami08448/CVE-2021-3656-Demo) :  ![starts](https://img.shields.io/github/stars/rami08448/CVE-2021-3656-Demo.svg) ![forks](https://img.shields.io/github/forks/rami08448/CVE-2021-3656-Demo.svg)


## CVE-2021-3625
 Buffer overflow in Zephyr USB DFU DNLOAD. Zephyr versions &gt;= v2.5.0 contain Heap-based Buffer Overflow (CWE-122). For more information, see https://github.com/zephyrproject-rtos/zephyr/security/advisories/GHSA-c3gr-hgvr-f363

- [https://github.com/szymonh/zephyr_cve-2021-3625](https://github.com/szymonh/zephyr_cve-2021-3625) :  ![starts](https://img.shields.io/github/stars/szymonh/zephyr_cve-2021-3625.svg) ![forks](https://img.shields.io/github/forks/szymonh/zephyr_cve-2021-3625.svg)


## CVE-2021-3560
 It was found that polkit could be tricked into bypassing the credential checks for D-Bus requests, elevating the privileges of the requestor to the root user. This flaw could be used by an unprivileged local attacker to, for example, create a new local administrator. The highest threat from this vulnerability is to data confidentiality and integrity as well as system availability.

- [https://github.com/liamg/traitor](https://github.com/liamg/traitor) :  ![starts](https://img.shields.io/github/stars/liamg/traitor.svg) ![forks](https://img.shields.io/github/forks/liamg/traitor.svg)
- [https://github.com/Almorabea/Polkit-exploit](https://github.com/Almorabea/Polkit-exploit) :  ![starts](https://img.shields.io/github/stars/Almorabea/Polkit-exploit.svg) ![forks](https://img.shields.io/github/forks/Almorabea/Polkit-exploit.svg)
- [https://github.com/RicterZ/CVE-2021-3560-Authentication-Agent](https://github.com/RicterZ/CVE-2021-3560-Authentication-Agent) :  ![starts](https://img.shields.io/github/stars/RicterZ/CVE-2021-3560-Authentication-Agent.svg) ![forks](https://img.shields.io/github/forks/RicterZ/CVE-2021-3560-Authentication-Agent.svg)
- [https://github.com/secnigma/CVE-2021-3560-Polkit-Privilege-Esclation](https://github.com/secnigma/CVE-2021-3560-Polkit-Privilege-Esclation) :  ![starts](https://img.shields.io/github/stars/secnigma/CVE-2021-3560-Polkit-Privilege-Esclation.svg) ![forks](https://img.shields.io/github/forks/secnigma/CVE-2021-3560-Polkit-Privilege-Esclation.svg)
- [https://github.com/swapravo/polkadots](https://github.com/swapravo/polkadots) :  ![starts](https://img.shields.io/github/stars/swapravo/polkadots.svg) ![forks](https://img.shields.io/github/forks/swapravo/polkadots.svg)
- [https://github.com/hakivvi/CVE-2021-3560](https://github.com/hakivvi/CVE-2021-3560) :  ![starts](https://img.shields.io/github/stars/hakivvi/CVE-2021-3560.svg) ![forks](https://img.shields.io/github/forks/hakivvi/CVE-2021-3560.svg)
- [https://github.com/WinMin/CVE-2021-3560](https://github.com/WinMin/CVE-2021-3560) :  ![starts](https://img.shields.io/github/stars/WinMin/CVE-2021-3560.svg) ![forks](https://img.shields.io/github/forks/WinMin/CVE-2021-3560.svg)
- [https://github.com/AssassinUKG/Polkit-CVE-2021-3560](https://github.com/AssassinUKG/Polkit-CVE-2021-3560) :  ![starts](https://img.shields.io/github/stars/AssassinUKG/Polkit-CVE-2021-3560.svg) ![forks](https://img.shields.io/github/forks/AssassinUKG/Polkit-CVE-2021-3560.svg)
- [https://github.com/oxagast/oxasploits](https://github.com/oxagast/oxasploits) :  ![starts](https://img.shields.io/github/stars/oxagast/oxasploits.svg) ![forks](https://img.shields.io/github/forks/oxagast/oxasploits.svg)
- [https://github.com/khulnasoft-lab/awesome-security](https://github.com/khulnasoft-lab/awesome-security) :  ![starts](https://img.shields.io/github/stars/khulnasoft-lab/awesome-security.svg) ![forks](https://img.shields.io/github/forks/khulnasoft-lab/awesome-security.svg)
- [https://github.com/0dayNinja/CVE-2021-3560](https://github.com/0dayNinja/CVE-2021-3560) :  ![starts](https://img.shields.io/github/stars/0dayNinja/CVE-2021-3560.svg) ![forks](https://img.shields.io/github/forks/0dayNinja/CVE-2021-3560.svg)
- [https://github.com/Bin4xin/bin4xin.github.io](https://github.com/Bin4xin/bin4xin.github.io) :  ![starts](https://img.shields.io/github/stars/Bin4xin/bin4xin.github.io.svg) ![forks](https://img.shields.io/github/forks/Bin4xin/bin4xin.github.io.svg)
- [https://github.com/chenaotian/CVE-2021-3560](https://github.com/chenaotian/CVE-2021-3560) :  ![starts](https://img.shields.io/github/stars/chenaotian/CVE-2021-3560.svg) ![forks](https://img.shields.io/github/forks/chenaotian/CVE-2021-3560.svg)
- [https://github.com/UNICORDev/exploit-CVE-2021-3560](https://github.com/UNICORDev/exploit-CVE-2021-3560) :  ![starts](https://img.shields.io/github/stars/UNICORDev/exploit-CVE-2021-3560.svg) ![forks](https://img.shields.io/github/forks/UNICORDev/exploit-CVE-2021-3560.svg)
- [https://github.com/rexpository/linux-privilege-escalation](https://github.com/rexpository/linux-privilege-escalation) :  ![starts](https://img.shields.io/github/stars/rexpository/linux-privilege-escalation.svg) ![forks](https://img.shields.io/github/forks/rexpository/linux-privilege-escalation.svg)
- [https://github.com/aancw/polkit-auto-exploit](https://github.com/aancw/polkit-auto-exploit) :  ![starts](https://img.shields.io/github/stars/aancw/polkit-auto-exploit.svg) ![forks](https://img.shields.io/github/forks/aancw/polkit-auto-exploit.svg)
- [https://github.com/f4T1H21/CVE-2021-3560-Polkit-DBus](https://github.com/f4T1H21/CVE-2021-3560-Polkit-DBus) :  ![starts](https://img.shields.io/github/stars/f4T1H21/CVE-2021-3560-Polkit-DBus.svg) ![forks](https://img.shields.io/github/forks/f4T1H21/CVE-2021-3560-Polkit-DBus.svg)
- [https://github.com/n3onhacks/CVE-2021-3560](https://github.com/n3onhacks/CVE-2021-3560) :  ![starts](https://img.shields.io/github/stars/n3onhacks/CVE-2021-3560.svg) ![forks](https://img.shields.io/github/forks/n3onhacks/CVE-2021-3560.svg)
- [https://github.com/BizarreLove/CVE-2021-3560](https://github.com/BizarreLove/CVE-2021-3560) :  ![starts](https://img.shields.io/github/stars/BizarreLove/CVE-2021-3560.svg) ![forks](https://img.shields.io/github/forks/BizarreLove/CVE-2021-3560.svg)
- [https://github.com/sentryCyberSec/sentryCyberSec.github.io](https://github.com/sentryCyberSec/sentryCyberSec.github.io) :  ![starts](https://img.shields.io/github/stars/sentryCyberSec/sentryCyberSec.github.io.svg) ![forks](https://img.shields.io/github/forks/sentryCyberSec/sentryCyberSec.github.io.svg)
- [https://github.com/cpu0x00/CVE-2021-3560](https://github.com/cpu0x00/CVE-2021-3560) :  ![starts](https://img.shields.io/github/stars/cpu0x00/CVE-2021-3560.svg) ![forks](https://img.shields.io/github/forks/cpu0x00/CVE-2021-3560.svg)
- [https://github.com/innxrmxst/CVE-2021-3560](https://github.com/innxrmxst/CVE-2021-3560) :  ![starts](https://img.shields.io/github/stars/innxrmxst/CVE-2021-3560.svg) ![forks](https://img.shields.io/github/forks/innxrmxst/CVE-2021-3560.svg)
- [https://github.com/TieuLong21Prosper/CVE-2021-3560](https://github.com/TieuLong21Prosper/CVE-2021-3560) :  ![starts](https://img.shields.io/github/stars/TieuLong21Prosper/CVE-2021-3560.svg) ![forks](https://img.shields.io/github/forks/TieuLong21Prosper/CVE-2021-3560.svg)
- [https://github.com/curtishoughton/CVE-2021-3560](https://github.com/curtishoughton/CVE-2021-3560) :  ![starts](https://img.shields.io/github/stars/curtishoughton/CVE-2021-3560.svg) ![forks](https://img.shields.io/github/forks/curtishoughton/CVE-2021-3560.svg)
- [https://github.com/TomMalvoRiddle/CVE-2021-3560](https://github.com/TomMalvoRiddle/CVE-2021-3560) :  ![starts](https://img.shields.io/github/stars/TomMalvoRiddle/CVE-2021-3560.svg) ![forks](https://img.shields.io/github/forks/TomMalvoRiddle/CVE-2021-3560.svg)
- [https://github.com/asepsaepdin/CVE-2021-3560](https://github.com/asepsaepdin/CVE-2021-3560) :  ![starts](https://img.shields.io/github/stars/asepsaepdin/CVE-2021-3560.svg) ![forks](https://img.shields.io/github/forks/asepsaepdin/CVE-2021-3560.svg)
- [https://github.com/LucasPDiniz/CVE-2021-3560](https://github.com/LucasPDiniz/CVE-2021-3560) :  ![starts](https://img.shields.io/github/stars/LucasPDiniz/CVE-2021-3560.svg) ![forks](https://img.shields.io/github/forks/LucasPDiniz/CVE-2021-3560.svg)
- [https://github.com/Kyyomaa/CVE-2021-3560-EXPLOIT](https://github.com/Kyyomaa/CVE-2021-3560-EXPLOIT) :  ![starts](https://img.shields.io/github/stars/Kyyomaa/CVE-2021-3560-EXPLOIT.svg) ![forks](https://img.shields.io/github/forks/Kyyomaa/CVE-2021-3560-EXPLOIT.svg)
- [https://github.com/pashayogi/ROOT-CVE-2021-3560](https://github.com/pashayogi/ROOT-CVE-2021-3560) :  ![starts](https://img.shields.io/github/stars/pashayogi/ROOT-CVE-2021-3560.svg) ![forks](https://img.shields.io/github/forks/pashayogi/ROOT-CVE-2021-3560.svg)
- [https://github.com/iSTAR-Lab/CVE-2021-3560_PoC](https://github.com/iSTAR-Lab/CVE-2021-3560_PoC) :  ![starts](https://img.shields.io/github/stars/iSTAR-Lab/CVE-2021-3560_PoC.svg) ![forks](https://img.shields.io/github/forks/iSTAR-Lab/CVE-2021-3560_PoC.svg)
- [https://github.com/markyu0401/CVE-2021-3560-Polkit-Privilege-Escalation](https://github.com/markyu0401/CVE-2021-3560-Polkit-Privilege-Escalation) :  ![starts](https://img.shields.io/github/stars/markyu0401/CVE-2021-3560-Polkit-Privilege-Escalation.svg) ![forks](https://img.shields.io/github/forks/markyu0401/CVE-2021-3560-Polkit-Privilege-Escalation.svg)


## CVE-2021-3516
 There's a flaw in libxml2's xmllint in versions before 2.9.11. An attacker who is able to submit a crafted file to be processed by xmllint could trigger a use-after-free. The greatest impact of this flaw is to confidentiality, integrity, and availability.

- [https://github.com/dja2TaqkGEEfA45/CVE-2021-3516](https://github.com/dja2TaqkGEEfA45/CVE-2021-3516) :  ![starts](https://img.shields.io/github/stars/dja2TaqkGEEfA45/CVE-2021-3516.svg) ![forks](https://img.shields.io/github/forks/dja2TaqkGEEfA45/CVE-2021-3516.svg)


## CVE-2021-3493
 The overlayfs implementation in the linux kernel did not properly validate with respect to user namespaces the setting of file capabilities on files in an underlying file system. Due to the combination of unprivileged user namespaces along with a patch carried in the Ubuntu kernel to allow unprivileged overlay mounts, an attacker could use this to gain elevated privileges.

- [https://github.com/briskets/CVE-2021-3493](https://github.com/briskets/CVE-2021-3493) :  ![starts](https://img.shields.io/github/stars/briskets/CVE-2021-3493.svg) ![forks](https://img.shields.io/github/forks/briskets/CVE-2021-3493.svg)
- [https://github.com/inspiringz/CVE-2021-3493](https://github.com/inspiringz/CVE-2021-3493) :  ![starts](https://img.shields.io/github/stars/inspiringz/CVE-2021-3493.svg) ![forks](https://img.shields.io/github/forks/inspiringz/CVE-2021-3493.svg)
- [https://github.com/oneoy/CVE-2021-3493](https://github.com/oneoy/CVE-2021-3493) :  ![starts](https://img.shields.io/github/stars/oneoy/CVE-2021-3493.svg) ![forks](https://img.shields.io/github/forks/oneoy/CVE-2021-3493.svg)
- [https://github.com/cerodah/overlayFS-CVE-2021-3493](https://github.com/cerodah/overlayFS-CVE-2021-3493) :  ![starts](https://img.shields.io/github/stars/cerodah/overlayFS-CVE-2021-3493.svg) ![forks](https://img.shields.io/github/forks/cerodah/overlayFS-CVE-2021-3493.svg)
- [https://github.com/fei9747/CVE-2021-3493](https://github.com/fei9747/CVE-2021-3493) :  ![starts](https://img.shields.io/github/stars/fei9747/CVE-2021-3493.svg) ![forks](https://img.shields.io/github/forks/fei9747/CVE-2021-3493.svg)
- [https://github.com/derek-turing/CVE-2021-3493](https://github.com/derek-turing/CVE-2021-3493) :  ![starts](https://img.shields.io/github/stars/derek-turing/CVE-2021-3493.svg) ![forks](https://img.shields.io/github/forks/derek-turing/CVE-2021-3493.svg)
- [https://github.com/puckiestyle/CVE-2021-3493](https://github.com/puckiestyle/CVE-2021-3493) :  ![starts](https://img.shields.io/github/stars/puckiestyle/CVE-2021-3493.svg) ![forks](https://img.shields.io/github/forks/puckiestyle/CVE-2021-3493.svg)
- [https://github.com/Senz4wa/CVE-2021-3493](https://github.com/Senz4wa/CVE-2021-3493) :  ![starts](https://img.shields.io/github/stars/Senz4wa/CVE-2021-3493.svg) ![forks](https://img.shields.io/github/forks/Senz4wa/CVE-2021-3493.svg)
- [https://github.com/Abdennour-py/CVE-2021-3493](https://github.com/Abdennour-py/CVE-2021-3493) :  ![starts](https://img.shields.io/github/stars/Abdennour-py/CVE-2021-3493.svg) ![forks](https://img.shields.io/github/forks/Abdennour-py/CVE-2021-3493.svg)
- [https://github.com/smallkill/CVE-2021-3493](https://github.com/smallkill/CVE-2021-3493) :  ![starts](https://img.shields.io/github/stars/smallkill/CVE-2021-3493.svg) ![forks](https://img.shields.io/github/forks/smallkill/CVE-2021-3493.svg)
- [https://github.com/ptkhai15/OverlayFS---CVE-2021-3493](https://github.com/ptkhai15/OverlayFS---CVE-2021-3493) :  ![starts](https://img.shields.io/github/stars/ptkhai15/OverlayFS---CVE-2021-3493.svg) ![forks](https://img.shields.io/github/forks/ptkhai15/OverlayFS---CVE-2021-3493.svg)
- [https://github.com/pmihsan/OverlayFS-CVE-2021-3493](https://github.com/pmihsan/OverlayFS-CVE-2021-3493) :  ![starts](https://img.shields.io/github/stars/pmihsan/OverlayFS-CVE-2021-3493.svg) ![forks](https://img.shields.io/github/forks/pmihsan/OverlayFS-CVE-2021-3493.svg)


## CVE-2021-3492
 Shiftfs, an out-of-tree stacking file system included in Ubuntu Linux kernels, did not properly handle faults occurring during copy_from_user() correctly. These could lead to either a double-free situation or memory not being freed at all. An attacker could use this to cause a denial of service (kernel memory exhaustion) or gain privileges via executing arbitrary code. AKA ZDI-CAN-13562.

- [https://github.com/synacktiv/CVE-2021-3492](https://github.com/synacktiv/CVE-2021-3492) :  ![starts](https://img.shields.io/github/stars/synacktiv/CVE-2021-3492.svg) ![forks](https://img.shields.io/github/forks/synacktiv/CVE-2021-3492.svg)


## CVE-2021-3490
 The eBPF ALU32 bounds tracking for bitwise ops (AND, OR and XOR) in the Linux kernel did not properly update 32-bit bounds, which could be turned into out of bounds reads and writes in the Linux kernel and therefore, arbitrary code execution. This issue was fixed via commit 049c4e13714e (&quot;bpf: Fix alu32 const subreg bound tracking on bitwise operations&quot;) (v5.13-rc4) and backported to the stable kernels in v5.12.4, v5.11.21, and v5.10.37. The AND/OR issues were introduced by commit 3f50f132d840 (&quot;bpf: Verifier, do explicit ALU32 bounds tracking&quot;) (5.7-rc1) and the XOR variant was introduced by 2921c90d4718 (&quot;bpf:Fix a verifier failure with xor&quot;) ( 5.10-rc1).

- [https://github.com/chompie1337/Linux_LPE_eBPF_CVE-2021-3490](https://github.com/chompie1337/Linux_LPE_eBPF_CVE-2021-3490) :  ![starts](https://img.shields.io/github/stars/chompie1337/Linux_LPE_eBPF_CVE-2021-3490.svg) ![forks](https://img.shields.io/github/forks/chompie1337/Linux_LPE_eBPF_CVE-2021-3490.svg)
- [https://github.com/pivik271/CVE-2021-3490](https://github.com/pivik271/CVE-2021-3490) :  ![starts](https://img.shields.io/github/stars/pivik271/CVE-2021-3490.svg) ![forks](https://img.shields.io/github/forks/pivik271/CVE-2021-3490.svg)


## CVE-2021-3449
 An OpenSSL TLS server may crash if sent a maliciously crafted renegotiation ClientHello message from a client. If a TLSv1.2 renegotiation ClientHello omits the signature_algorithms extension (where it was present in the initial ClientHello), but includes a signature_algorithms_cert extension then a NULL pointer dereference will result, leading to a crash and a denial of service attack. A server is only vulnerable if it has TLSv1.2 and renegotiation enabled (which is the default configuration). OpenSSL TLS clients are not impacted by this issue. All OpenSSL 1.1.1 versions are affected by this issue. Users of these versions should upgrade to OpenSSL 1.1.1k. OpenSSL 1.0.2 is not impacted by this issue. Fixed in OpenSSL 1.1.1k (Affected 1.1.1-1.1.1j).

- [https://github.com/riptl/cve-2021-3449](https://github.com/riptl/cve-2021-3449) :  ![starts](https://img.shields.io/github/stars/riptl/cve-2021-3449.svg) ![forks](https://img.shields.io/github/forks/riptl/cve-2021-3449.svg)


## CVE-2021-3441
 A potential security vulnerability has been identified for the HP OfficeJet 7110 Wide Format ePrinter that enables Cross-Site Scripting (XSS).

- [https://github.com/tcbutler320/CVE-2021-3441-check](https://github.com/tcbutler320/CVE-2021-3441-check) :  ![starts](https://img.shields.io/github/stars/tcbutler320/CVE-2021-3441-check.svg) ![forks](https://img.shields.io/github/forks/tcbutler320/CVE-2021-3441-check.svg)


## CVE-2021-3438
 A potential buffer overflow in the software drivers for certain HP LaserJet products and Samsung product printers could lead to an escalation of privilege.

- [https://github.com/CrackerCat/CVE-2021-3438](https://github.com/CrackerCat/CVE-2021-3438) :  ![starts](https://img.shields.io/github/stars/CrackerCat/CVE-2021-3438.svg) ![forks](https://img.shields.io/github/forks/CrackerCat/CVE-2021-3438.svg)
- [https://github.com/TobiasS1402/CVE-2021-3438](https://github.com/TobiasS1402/CVE-2021-3438) :  ![starts](https://img.shields.io/github/stars/TobiasS1402/CVE-2021-3438.svg) ![forks](https://img.shields.io/github/forks/TobiasS1402/CVE-2021-3438.svg)


## CVE-2021-3395
 A cross-site scripting (XSS) vulnerability in Pryaniki 6.44.3 allows remote authenticated users to upload an arbitrary file. The JavaScript code will execute when someone visits the attachment.

- [https://github.com/jet-pentest/CVE-2021-3395](https://github.com/jet-pentest/CVE-2021-3395) :  ![starts](https://img.shields.io/github/stars/jet-pentest/CVE-2021-3395.svg) ![forks](https://img.shields.io/github/forks/jet-pentest/CVE-2021-3395.svg)


## CVE-2021-3378
 FortiLogger 4.4.2.2 is affected by Arbitrary File Upload by sending a &quot;Content-Type: image/png&quot; header to Config/SaveUploadedHotspotLogoFile and then visiting Assets/temp/hotspot/img/logohotspot.asp.

- [https://github.com/erberkan/fortilogger_arbitrary_fileupload](https://github.com/erberkan/fortilogger_arbitrary_fileupload) :  ![starts](https://img.shields.io/github/stars/erberkan/fortilogger_arbitrary_fileupload.svg) ![forks](https://img.shields.io/github/forks/erberkan/fortilogger_arbitrary_fileupload.svg)


## CVE-2021-3360
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/tcbutler320/CVE-2021-3360](https://github.com/tcbutler320/CVE-2021-3360) :  ![starts](https://img.shields.io/github/stars/tcbutler320/CVE-2021-3360.svg) ![forks](https://img.shields.io/github/forks/tcbutler320/CVE-2021-3360.svg)


## CVE-2021-3347
 An issue was discovered in the Linux kernel through 5.10.11. PI futexes have a kernel stack use-after-free during fault handling, allowing local users to execute code in the kernel, aka CID-34b1a1ce1458.

- [https://github.com/nanopathi/linux-4.19.72_CVE-2021-3347](https://github.com/nanopathi/linux-4.19.72_CVE-2021-3347) :  ![starts](https://img.shields.io/github/stars/nanopathi/linux-4.19.72_CVE-2021-3347.svg) ![forks](https://img.shields.io/github/forks/nanopathi/linux-4.19.72_CVE-2021-3347.svg)


## CVE-2021-3345
 _gcry_md_block_write in cipher/hash-common.c in Libgcrypt version 1.9.0 has a heap-based buffer overflow when the digest final function sets a large count value. It is recommended to upgrade to 1.9.1 or later.

- [https://github.com/MLGRadish/CVE-2021-3345](https://github.com/MLGRadish/CVE-2021-3345) :  ![starts](https://img.shields.io/github/stars/MLGRadish/CVE-2021-3345.svg) ![forks](https://img.shields.io/github/forks/MLGRadish/CVE-2021-3345.svg)
- [https://github.com/SpiralBL0CK/CVE-2021-3345](https://github.com/SpiralBL0CK/CVE-2021-3345) :  ![starts](https://img.shields.io/github/stars/SpiralBL0CK/CVE-2021-3345.svg) ![forks](https://img.shields.io/github/forks/SpiralBL0CK/CVE-2021-3345.svg)


## CVE-2021-3310
 Western Digital My Cloud OS 5 devices before 5.10.122 mishandle Symbolic Link Following on SMB and AFP shares. This can lead to code execution and information disclosure (by reading local files).

- [https://github.com/piffd0s/CVE-2021-3310](https://github.com/piffd0s/CVE-2021-3310) :  ![starts](https://img.shields.io/github/stars/piffd0s/CVE-2021-3310.svg) ![forks](https://img.shields.io/github/forks/piffd0s/CVE-2021-3310.svg)


## CVE-2021-3291
 Zen Cart 1.5.7b allows admins to execute arbitrary OS commands by inspecting an HTML radio input element (within the modules edit page) and inserting a command.

- [https://github.com/ImHades101/CVE-2021-3291](https://github.com/ImHades101/CVE-2021-3291) :  ![starts](https://img.shields.io/github/stars/ImHades101/CVE-2021-3291.svg) ![forks](https://img.shields.io/github/forks/ImHades101/CVE-2021-3291.svg)


## CVE-2021-3281
 In Django 2.2 before 2.2.18, 3.0 before 3.0.12, and 3.1 before 3.1.6, the django.utils.archive.extract method (used by &quot;startapp --template&quot; and &quot;startproject --template&quot;) allows directory traversal via an archive with absolute paths or relative paths with dot segments.

- [https://github.com/HxDDD/CVE-PoC](https://github.com/HxDDD/CVE-PoC) :  ![starts](https://img.shields.io/github/stars/HxDDD/CVE-PoC.svg) ![forks](https://img.shields.io/github/forks/HxDDD/CVE-PoC.svg)
- [https://github.com/lwzSoviet/CVE-2021-3281](https://github.com/lwzSoviet/CVE-2021-3281) :  ![starts](https://img.shields.io/github/stars/lwzSoviet/CVE-2021-3281.svg) ![forks](https://img.shields.io/github/forks/lwzSoviet/CVE-2021-3281.svg)


## CVE-2021-3279
 sz.chat version 4 allows injection of web scripts and HTML in the message box.

- [https://github.com/rafaelchriss/CVE-2021-3279](https://github.com/rafaelchriss/CVE-2021-3279) :  ![starts](https://img.shields.io/github/stars/rafaelchriss/CVE-2021-3279.svg) ![forks](https://img.shields.io/github/forks/rafaelchriss/CVE-2021-3279.svg)


## CVE-2021-3229
 Denial of service in ASUSWRT ASUS RT-AX3000 firmware versions 3.0.0.4.384_10177 and earlier versions allows an attacker to disrupt the use of device setup services via continuous login error.

- [https://github.com/fullbbadda1208/CVE-2021-3229](https://github.com/fullbbadda1208/CVE-2021-3229) :  ![starts](https://img.shields.io/github/stars/fullbbadda1208/CVE-2021-3229.svg) ![forks](https://img.shields.io/github/forks/fullbbadda1208/CVE-2021-3229.svg)


## CVE-2021-3223
 Node-RED-Dashboard before 2.26.2 allows ui_base/js/..%2f directory traversal to read files.

- [https://github.com/CLincat/vulcat](https://github.com/CLincat/vulcat) :  ![starts](https://img.shields.io/github/stars/CLincat/vulcat.svg) ![forks](https://img.shields.io/github/forks/CLincat/vulcat.svg)


## CVE-2021-3166
 An issue was discovered on ASUS DSL-N14U-B1 1.1.2.3_805 devices. An attacker can upload arbitrary file content as a firmware update when the filename Settings_DSL-N14U-B1.trx is used. Once this file is loaded, shutdown measures on a wide range of services are triggered as if it were a real update, resulting in a persistent outage of those services.

- [https://github.com/kaisersource/CVE-2021-3166](https://github.com/kaisersource/CVE-2021-3166) :  ![starts](https://img.shields.io/github/stars/kaisersource/CVE-2021-3166.svg) ![forks](https://img.shields.io/github/forks/kaisersource/CVE-2021-3166.svg)


## CVE-2021-3164
 ChurchRota 2.6.4 is vulnerable to authenticated remote code execution. The user does not need to have file upload permission in order to upload and execute an arbitrary file via a POST request to resources.php.

- [https://github.com/rmccarth/cve-2021-3164](https://github.com/rmccarth/cve-2021-3164) :  ![starts](https://img.shields.io/github/stars/rmccarth/cve-2021-3164.svg) ![forks](https://img.shields.io/github/forks/rmccarth/cve-2021-3164.svg)


## CVE-2021-3157
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/CrackerCat/cve-2021-3157](https://github.com/CrackerCat/cve-2021-3157) :  ![starts](https://img.shields.io/github/stars/CrackerCat/cve-2021-3157.svg) ![forks](https://img.shields.io/github/forks/CrackerCat/cve-2021-3157.svg)


## CVE-2021-3156
 Sudo before 1.9.5p2 contains an off-by-one error that can result in a heap-based buffer overflow, which allows privilege escalation to root via &quot;sudoedit -s&quot; and a command-line argument that ends with a single backslash character.

- [https://github.com/blasty/CVE-2021-3156](https://github.com/blasty/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/blasty/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/blasty/CVE-2021-3156.svg)
- [https://github.com/worawit/CVE-2021-3156](https://github.com/worawit/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/worawit/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/worawit/CVE-2021-3156.svg)
- [https://github.com/stong/CVE-2021-3156](https://github.com/stong/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/stong/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/stong/CVE-2021-3156.svg)
- [https://github.com/Al1ex/LinuxEelvation](https://github.com/Al1ex/LinuxEelvation) :  ![starts](https://img.shields.io/github/stars/Al1ex/LinuxEelvation.svg) ![forks](https://img.shields.io/github/forks/Al1ex/LinuxEelvation.svg)
- [https://github.com/LiveOverflow/pwnedit](https://github.com/LiveOverflow/pwnedit) :  ![starts](https://img.shields.io/github/stars/LiveOverflow/pwnedit.svg) ![forks](https://img.shields.io/github/forks/LiveOverflow/pwnedit.svg)
- [https://github.com/Rvn0xsy/CVE-2021-3156-plus](https://github.com/Rvn0xsy/CVE-2021-3156-plus) :  ![starts](https://img.shields.io/github/stars/Rvn0xsy/CVE-2021-3156-plus.svg) ![forks](https://img.shields.io/github/forks/Rvn0xsy/CVE-2021-3156-plus.svg)
- [https://github.com/CptGibbon/CVE-2021-3156](https://github.com/CptGibbon/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/CptGibbon/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/CptGibbon/CVE-2021-3156.svg)
- [https://github.com/reverse-ex/CVE-2021-3156](https://github.com/reverse-ex/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/reverse-ex/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/reverse-ex/CVE-2021-3156.svg)
- [https://github.com/0x4ndy/clif](https://github.com/0x4ndy/clif) :  ![starts](https://img.shields.io/github/stars/0x4ndy/clif.svg) ![forks](https://img.shields.io/github/forks/0x4ndy/clif.svg)
- [https://github.com/0xdevil/CVE-2021-3156](https://github.com/0xdevil/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/0xdevil/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/0xdevil/CVE-2021-3156.svg)
- [https://github.com/mbcrump/CVE-2021-3156](https://github.com/mbcrump/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/mbcrump/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/mbcrump/CVE-2021-3156.svg)
- [https://github.com/mr-r3b00t/CVE-2021-3156](https://github.com/mr-r3b00t/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/mr-r3b00t/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/mr-r3b00t/CVE-2021-3156.svg)
- [https://github.com/PhuketIsland/CVE-2021-3156-centos7](https://github.com/PhuketIsland/CVE-2021-3156-centos7) :  ![starts](https://img.shields.io/github/stars/PhuketIsland/CVE-2021-3156-centos7.svg) ![forks](https://img.shields.io/github/forks/PhuketIsland/CVE-2021-3156-centos7.svg)
- [https://github.com/kernelzeroday/CVE-2021-3156-Baron-Samedit](https://github.com/kernelzeroday/CVE-2021-3156-Baron-Samedit) :  ![starts](https://img.shields.io/github/stars/kernelzeroday/CVE-2021-3156-Baron-Samedit.svg) ![forks](https://img.shields.io/github/forks/kernelzeroday/CVE-2021-3156-Baron-Samedit.svg)
- [https://github.com/jm33-m0/CVE-2021-3156](https://github.com/jm33-m0/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/jm33-m0/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/jm33-m0/CVE-2021-3156.svg)
- [https://github.com/teamtopkarl/CVE-2021-3156](https://github.com/teamtopkarl/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/teamtopkarl/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/teamtopkarl/CVE-2021-3156.svg)
- [https://github.com/apogiatzis/docker-CVE-2021-3156](https://github.com/apogiatzis/docker-CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/apogiatzis/docker-CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/apogiatzis/docker-CVE-2021-3156.svg)
- [https://github.com/chenaotian/CVE-2021-3156](https://github.com/chenaotian/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/chenaotian/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/chenaotian/CVE-2021-3156.svg)
- [https://github.com/redhawkeye/sudo-exploit](https://github.com/redhawkeye/sudo-exploit) :  ![starts](https://img.shields.io/github/stars/redhawkeye/sudo-exploit.svg) ![forks](https://img.shields.io/github/forks/redhawkeye/sudo-exploit.svg)
- [https://github.com/yaunsky/cve-2021-3156](https://github.com/yaunsky/cve-2021-3156) :  ![starts](https://img.shields.io/github/stars/yaunsky/cve-2021-3156.svg) ![forks](https://img.shields.io/github/forks/yaunsky/cve-2021-3156.svg)
- [https://github.com/1N53C/CVE-2021-3156-PoC](https://github.com/1N53C/CVE-2021-3156-PoC) :  ![starts](https://img.shields.io/github/stars/1N53C/CVE-2021-3156-PoC.svg) ![forks](https://img.shields.io/github/forks/1N53C/CVE-2021-3156-PoC.svg)
- [https://github.com/baka9moe/CVE-2021-3156-Exp](https://github.com/baka9moe/CVE-2021-3156-Exp) :  ![starts](https://img.shields.io/github/stars/baka9moe/CVE-2021-3156-Exp.svg) ![forks](https://img.shields.io/github/forks/baka9moe/CVE-2021-3156-Exp.svg)
- [https://github.com/dinhbaouit/CVE-2021-3156](https://github.com/dinhbaouit/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/dinhbaouit/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/dinhbaouit/CVE-2021-3156.svg)
- [https://github.com/Mhackiori/CVE-2021-3156](https://github.com/Mhackiori/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/Mhackiori/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/Mhackiori/CVE-2021-3156.svg)
- [https://github.com/lmol/CVE-2021-3156](https://github.com/lmol/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/lmol/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/lmol/CVE-2021-3156.svg)
- [https://github.com/elbee-cyber/CVE-2021-3156-PATCHER](https://github.com/elbee-cyber/CVE-2021-3156-PATCHER) :  ![starts](https://img.shields.io/github/stars/elbee-cyber/CVE-2021-3156-PATCHER.svg) ![forks](https://img.shields.io/github/forks/elbee-cyber/CVE-2021-3156-PATCHER.svg)
- [https://github.com/ph4ntonn/CVE-2021-3156](https://github.com/ph4ntonn/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/ph4ntonn/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/ph4ntonn/CVE-2021-3156.svg)
- [https://github.com/kal1gh0st/CVE-2021-3156](https://github.com/kal1gh0st/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/kal1gh0st/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/kal1gh0st/CVE-2021-3156.svg)
- [https://github.com/unauth401/CVE-2021-3156](https://github.com/unauth401/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/unauth401/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/unauth401/CVE-2021-3156.svg)
- [https://github.com/Q4n/CVE-2021-3156](https://github.com/Q4n/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/Q4n/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/Q4n/CVE-2021-3156.svg)
- [https://github.com/musergi/CVE-2021-3156](https://github.com/musergi/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/musergi/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/musergi/CVE-2021-3156.svg)
- [https://github.com/ypl6/heaplens](https://github.com/ypl6/heaplens) :  ![starts](https://img.shields.io/github/stars/ypl6/heaplens.svg) ![forks](https://img.shields.io/github/forks/ypl6/heaplens.svg)
- [https://github.com/oneoy/CVE-2021-3156](https://github.com/oneoy/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/oneoy/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/oneoy/CVE-2021-3156.svg)
- [https://github.com/RodricBr/CVE-2021-3156](https://github.com/RodricBr/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/RodricBr/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/RodricBr/CVE-2021-3156.svg)
- [https://github.com/0x7183/CVE-2021-3156](https://github.com/0x7183/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/0x7183/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/0x7183/CVE-2021-3156.svg)
- [https://github.com/donghyunlee00/CVE-2021-3156](https://github.com/donghyunlee00/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/donghyunlee00/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/donghyunlee00/CVE-2021-3156.svg)
- [https://github.com/BearCat4/CVE-2021-3156](https://github.com/BearCat4/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/BearCat4/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/BearCat4/CVE-2021-3156.svg)
- [https://github.com/puckiestyle/CVE-2021-3156](https://github.com/puckiestyle/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/puckiestyle/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/puckiestyle/CVE-2021-3156.svg)
- [https://github.com/TheFlash2k/CVE-2021-3156](https://github.com/TheFlash2k/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/TheFlash2k/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/TheFlash2k/CVE-2021-3156.svg)
- [https://github.com/nobodyatall648/CVE-2021-3156](https://github.com/nobodyatall648/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/nobodyatall648/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/nobodyatall648/CVE-2021-3156.svg)
- [https://github.com/q77190858/CVE-2021-3156](https://github.com/q77190858/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/q77190858/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/q77190858/CVE-2021-3156.svg)
- [https://github.com/binw2018/CVE-2021-3156-SCRIPT](https://github.com/binw2018/CVE-2021-3156-SCRIPT) :  ![starts](https://img.shields.io/github/stars/binw2018/CVE-2021-3156-SCRIPT.svg) ![forks](https://img.shields.io/github/forks/binw2018/CVE-2021-3156-SCRIPT.svg)
- [https://github.com/SantiagoSerrao/ScannerCVE-2021-3156](https://github.com/SantiagoSerrao/ScannerCVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/SantiagoSerrao/ScannerCVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/SantiagoSerrao/ScannerCVE-2021-3156.svg)
- [https://github.com/PurpleOzone/PE_CVE-CVE-2021-3156](https://github.com/PurpleOzone/PE_CVE-CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/PurpleOzone/PE_CVE-CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/PurpleOzone/PE_CVE-CVE-2021-3156.svg)
- [https://github.com/r3k4t/how-to-solve-sudo-heap-based-bufferoverflow-vulnerability](https://github.com/r3k4t/how-to-solve-sudo-heap-based-bufferoverflow-vulnerability) :  ![starts](https://img.shields.io/github/stars/r3k4t/how-to-solve-sudo-heap-based-bufferoverflow-vulnerability.svg) ![forks](https://img.shields.io/github/forks/r3k4t/how-to-solve-sudo-heap-based-bufferoverflow-vulnerability.svg)
- [https://github.com/AbdullahRizwan101/Baron-Samedit](https://github.com/AbdullahRizwan101/Baron-Samedit) :  ![starts](https://img.shields.io/github/stars/AbdullahRizwan101/Baron-Samedit.svg) ![forks](https://img.shields.io/github/forks/AbdullahRizwan101/Baron-Samedit.svg)
- [https://github.com/pmihsan/Sudo-HeapBased-Buffer-Overflow](https://github.com/pmihsan/Sudo-HeapBased-Buffer-Overflow) :  ![starts](https://img.shields.io/github/stars/pmihsan/Sudo-HeapBased-Buffer-Overflow.svg) ![forks](https://img.shields.io/github/forks/pmihsan/Sudo-HeapBased-Buffer-Overflow.svg)
- [https://github.com/usr2r00t/patches](https://github.com/usr2r00t/patches) :  ![starts](https://img.shields.io/github/stars/usr2r00t/patches.svg) ![forks](https://img.shields.io/github/forks/usr2r00t/patches.svg)
- [https://github.com/CyberCommands/CVE-2021-3156](https://github.com/CyberCommands/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/CyberCommands/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/CyberCommands/CVE-2021-3156.svg)
- [https://github.com/ymrsmns/CVE-2021-3156](https://github.com/ymrsmns/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/ymrsmns/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/ymrsmns/CVE-2021-3156.svg)
- [https://github.com/Jauler/cve2021-3156-sudo-heap-overflow](https://github.com/Jauler/cve2021-3156-sudo-heap-overflow) :  ![starts](https://img.shields.io/github/stars/Jauler/cve2021-3156-sudo-heap-overflow.svg) ![forks](https://img.shields.io/github/forks/Jauler/cve2021-3156-sudo-heap-overflow.svg)
- [https://github.com/halissha/CVE-2021-3156](https://github.com/halissha/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/halissha/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/halissha/CVE-2021-3156.svg)
- [https://github.com/ret2basic/SudoScience](https://github.com/ret2basic/SudoScience) :  ![starts](https://img.shields.io/github/stars/ret2basic/SudoScience.svg) ![forks](https://img.shields.io/github/forks/ret2basic/SudoScience.svg)
- [https://github.com/barebackbandit/CVE-2021-3156](https://github.com/barebackbandit/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/barebackbandit/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/barebackbandit/CVE-2021-3156.svg)
- [https://github.com/gmldbd94/cve-2021-3156](https://github.com/gmldbd94/cve-2021-3156) :  ![starts](https://img.shields.io/github/stars/gmldbd94/cve-2021-3156.svg) ![forks](https://img.shields.io/github/forks/gmldbd94/cve-2021-3156.svg)
- [https://github.com/password520/CVE-2021-3156](https://github.com/password520/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/password520/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/password520/CVE-2021-3156.svg)
- [https://github.com/wurwur/CVE-2021-3156](https://github.com/wurwur/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/wurwur/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/wurwur/CVE-2021-3156.svg)
- [https://github.com/Y3A/CVE-2021-3156](https://github.com/Y3A/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/Y3A/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/Y3A/CVE-2021-3156.svg)
- [https://github.com/DDayLuong/CVE-2021-3156](https://github.com/DDayLuong/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/DDayLuong/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/DDayLuong/CVE-2021-3156.svg)
- [https://github.com/mutur4/CVE-2021-3156](https://github.com/mutur4/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/mutur4/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/mutur4/CVE-2021-3156.svg)
- [https://github.com/Exodusro/CVE-2021-3156](https://github.com/Exodusro/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/Exodusro/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/Exodusro/CVE-2021-3156.svg)
- [https://github.com/arvindshima/CVE-2021-3156](https://github.com/arvindshima/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/arvindshima/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/arvindshima/CVE-2021-3156.svg)
- [https://github.com/freeFV/CVE-2021-3156](https://github.com/freeFV/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/freeFV/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/freeFV/CVE-2021-3156.svg)
- [https://github.com/meowhua15/CVE-2021-3156](https://github.com/meowhua15/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/meowhua15/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/meowhua15/CVE-2021-3156.svg)
- [https://github.com/voidlsd/CVE-2021-3156](https://github.com/voidlsd/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/voidlsd/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/voidlsd/CVE-2021-3156.svg)
- [https://github.com/d3c3ptic0n/CVE-2021-3156](https://github.com/d3c3ptic0n/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/d3c3ptic0n/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/d3c3ptic0n/CVE-2021-3156.svg)
- [https://github.com/capturingcats/CVE-2021-3156](https://github.com/capturingcats/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/capturingcats/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/capturingcats/CVE-2021-3156.svg)
- [https://github.com/asepsaepdin/CVE-2021-3156](https://github.com/asepsaepdin/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/asepsaepdin/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/asepsaepdin/CVE-2021-3156.svg)
- [https://github.com/nexcess/sudo_cve-2021-3156](https://github.com/nexcess/sudo_cve-2021-3156) :  ![starts](https://img.shields.io/github/stars/nexcess/sudo_cve-2021-3156.svg) ![forks](https://img.shields.io/github/forks/nexcess/sudo_cve-2021-3156.svg)
- [https://github.com/SamTruss/LMU-CVE-2021-3156](https://github.com/SamTruss/LMU-CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/SamTruss/LMU-CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/SamTruss/LMU-CVE-2021-3156.svg)
- [https://github.com/cdeletre/Serpentiel-CVE-2021-3156](https://github.com/cdeletre/Serpentiel-CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/cdeletre/Serpentiel-CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/cdeletre/Serpentiel-CVE-2021-3156.svg)
- [https://github.com/Ashish-dawani/CVE-2021-3156-Patch](https://github.com/Ashish-dawani/CVE-2021-3156-Patch) :  ![starts](https://img.shields.io/github/stars/Ashish-dawani/CVE-2021-3156-Patch.svg) ![forks](https://img.shields.io/github/forks/Ashish-dawani/CVE-2021-3156-Patch.svg)
- [https://github.com/sharkmoos/Baron-Samedit](https://github.com/sharkmoos/Baron-Samedit) :  ![starts](https://img.shields.io/github/stars/sharkmoos/Baron-Samedit.svg) ![forks](https://img.shields.io/github/forks/sharkmoos/Baron-Samedit.svg)
- [https://github.com/ajtech-hue/CVE-2021-3156-Mitigation-ShellScript-Build](https://github.com/ajtech-hue/CVE-2021-3156-Mitigation-ShellScript-Build) :  ![starts](https://img.shields.io/github/stars/ajtech-hue/CVE-2021-3156-Mitigation-ShellScript-Build.svg) ![forks](https://img.shields.io/github/forks/ajtech-hue/CVE-2021-3156-Mitigation-ShellScript-Build.svg)
- [https://github.com/perlun/sudo-1.8.3p1-patched](https://github.com/perlun/sudo-1.8.3p1-patched) :  ![starts](https://img.shields.io/github/stars/perlun/sudo-1.8.3p1-patched.svg) ![forks](https://img.shields.io/github/forks/perlun/sudo-1.8.3p1-patched.svg)
- [https://github.com/DanielAzulayy/CTF-2021](https://github.com/DanielAzulayy/CTF-2021) :  ![starts](https://img.shields.io/github/stars/DanielAzulayy/CTF-2021.svg) ![forks](https://img.shields.io/github/forks/DanielAzulayy/CTF-2021.svg)


## CVE-2021-3138
 In Discourse 2.7.0 through beta1, a rate-limit bypass leads to a bypass of the 2FA requirement for certain forms.

- [https://github.com/Mesh3l911/CVE-2021-3138](https://github.com/Mesh3l911/CVE-2021-3138) :  ![starts](https://img.shields.io/github/stars/Mesh3l911/CVE-2021-3138.svg) ![forks](https://img.shields.io/github/forks/Mesh3l911/CVE-2021-3138.svg)


## CVE-2021-3131
 The Web server in 1C:Enterprise 8 before 8.3.17.1851 sends base64 encoded credentials in the creds URL parameter.

- [https://github.com/jet-pentest/CVE-2021-3131](https://github.com/jet-pentest/CVE-2021-3131) :  ![starts](https://img.shields.io/github/stars/jet-pentest/CVE-2021-3131.svg) ![forks](https://img.shields.io/github/forks/jet-pentest/CVE-2021-3131.svg)


## CVE-2021-3130
 Within the Open-AudIT up to version 3.5.3 application, the web interface hides SSH secrets, Windows passwords, and SNMP strings from users using HTML 'password field' obfuscation. By using Developer tools or similar, it is possible to change the obfuscation so that the credentials are visible.

- [https://github.com/jet-pentest/CVE-2021-3130](https://github.com/jet-pentest/CVE-2021-3130) :  ![starts](https://img.shields.io/github/stars/jet-pentest/CVE-2021-3130.svg) ![forks](https://img.shields.io/github/forks/jet-pentest/CVE-2021-3130.svg)


## CVE-2021-3129
 Ignition before 2.5.2, as used in Laravel and other products, allows unauthenticated remote attackers to execute arbitrary code because of insecure usage of file_get_contents() and file_put_contents(). This is exploitable on sites using debug mode with Laravel before 8.4.2.

- [https://github.com/zhzyker/vulmap](https://github.com/zhzyker/vulmap) :  ![starts](https://img.shields.io/github/stars/zhzyker/vulmap.svg) ![forks](https://img.shields.io/github/forks/zhzyker/vulmap.svg)
- [https://github.com/ambionics/laravel-exploits](https://github.com/ambionics/laravel-exploits) :  ![starts](https://img.shields.io/github/stars/ambionics/laravel-exploits.svg) ![forks](https://img.shields.io/github/forks/ambionics/laravel-exploits.svg)
- [https://github.com/zhzyker/CVE-2021-3129](https://github.com/zhzyker/CVE-2021-3129) :  ![starts](https://img.shields.io/github/stars/zhzyker/CVE-2021-3129.svg) ![forks](https://img.shields.io/github/forks/zhzyker/CVE-2021-3129.svg)
- [https://github.com/SNCKER/CVE-2021-3129](https://github.com/SNCKER/CVE-2021-3129) :  ![starts](https://img.shields.io/github/stars/SNCKER/CVE-2021-3129.svg) ![forks](https://img.shields.io/github/forks/SNCKER/CVE-2021-3129.svg)
- [https://github.com/SecPros-Team/laravel-CVE-2021-3129-EXP](https://github.com/SecPros-Team/laravel-CVE-2021-3129-EXP) :  ![starts](https://img.shields.io/github/stars/SecPros-Team/laravel-CVE-2021-3129-EXP.svg) ![forks](https://img.shields.io/github/forks/SecPros-Team/laravel-CVE-2021-3129-EXP.svg)
- [https://github.com/joshuavanderpoll/CVE-2021-3129](https://github.com/joshuavanderpoll/CVE-2021-3129) :  ![starts](https://img.shields.io/github/stars/joshuavanderpoll/CVE-2021-3129.svg) ![forks](https://img.shields.io/github/forks/joshuavanderpoll/CVE-2021-3129.svg)
- [https://github.com/nth347/CVE-2021-3129_exploit](https://github.com/nth347/CVE-2021-3129_exploit) :  ![starts](https://img.shields.io/github/stars/nth347/CVE-2021-3129_exploit.svg) ![forks](https://img.shields.io/github/forks/nth347/CVE-2021-3129_exploit.svg)
- [https://github.com/crisprss/Laravel_CVE-2021-3129_EXP](https://github.com/crisprss/Laravel_CVE-2021-3129_EXP) :  ![starts](https://img.shields.io/github/stars/crisprss/Laravel_CVE-2021-3129_EXP.svg) ![forks](https://img.shields.io/github/forks/crisprss/Laravel_CVE-2021-3129_EXP.svg)
- [https://github.com/knqyf263/CVE-2021-3129](https://github.com/knqyf263/CVE-2021-3129) :  ![starts](https://img.shields.io/github/stars/knqyf263/CVE-2021-3129.svg) ![forks](https://img.shields.io/github/forks/knqyf263/CVE-2021-3129.svg)
- [https://github.com/cuongtop4598/CVE-2021-3129-Script](https://github.com/cuongtop4598/CVE-2021-3129-Script) :  ![starts](https://img.shields.io/github/stars/cuongtop4598/CVE-2021-3129-Script.svg) ![forks](https://img.shields.io/github/forks/cuongtop4598/CVE-2021-3129-Script.svg)
- [https://github.com/simonlee-hello/CVE-2021-3129](https://github.com/simonlee-hello/CVE-2021-3129) :  ![starts](https://img.shields.io/github/stars/simonlee-hello/CVE-2021-3129.svg) ![forks](https://img.shields.io/github/forks/simonlee-hello/CVE-2021-3129.svg)
- [https://github.com/shadowabi/Laravel-CVE-2021-3129](https://github.com/shadowabi/Laravel-CVE-2021-3129) :  ![starts](https://img.shields.io/github/stars/shadowabi/Laravel-CVE-2021-3129.svg) ![forks](https://img.shields.io/github/forks/shadowabi/Laravel-CVE-2021-3129.svg)
- [https://github.com/0nion1/CVE-2021-3129](https://github.com/0nion1/CVE-2021-3129) :  ![starts](https://img.shields.io/github/stars/0nion1/CVE-2021-3129.svg) ![forks](https://img.shields.io/github/forks/0nion1/CVE-2021-3129.svg)
- [https://github.com/ajisai-babu/CVE-2021-3129-exp](https://github.com/ajisai-babu/CVE-2021-3129-exp) :  ![starts](https://img.shields.io/github/stars/ajisai-babu/CVE-2021-3129-exp.svg) ![forks](https://img.shields.io/github/forks/ajisai-babu/CVE-2021-3129-exp.svg)
- [https://github.com/Axianke/CVE-2021-3129](https://github.com/Axianke/CVE-2021-3129) :  ![starts](https://img.shields.io/github/stars/Axianke/CVE-2021-3129.svg) ![forks](https://img.shields.io/github/forks/Axianke/CVE-2021-3129.svg)
- [https://github.com/FunPhishing/Laravel-8.4.2-rce-CVE-2021-3129](https://github.com/FunPhishing/Laravel-8.4.2-rce-CVE-2021-3129) :  ![starts](https://img.shields.io/github/stars/FunPhishing/Laravel-8.4.2-rce-CVE-2021-3129.svg) ![forks](https://img.shields.io/github/forks/FunPhishing/Laravel-8.4.2-rce-CVE-2021-3129.svg)
- [https://github.com/MadExploits/Laravel-debug-Checker](https://github.com/MadExploits/Laravel-debug-Checker) :  ![starts](https://img.shields.io/github/stars/MadExploits/Laravel-debug-Checker.svg) ![forks](https://img.shields.io/github/forks/MadExploits/Laravel-debug-Checker.svg)
- [https://github.com/idea-oss/laravel-CVE-2021-3129-EXP](https://github.com/idea-oss/laravel-CVE-2021-3129-EXP) :  ![starts](https://img.shields.io/github/stars/idea-oss/laravel-CVE-2021-3129-EXP.svg) ![forks](https://img.shields.io/github/forks/idea-oss/laravel-CVE-2021-3129-EXP.svg)
- [https://github.com/withmasday/CVE-2021-3129](https://github.com/withmasday/CVE-2021-3129) :  ![starts](https://img.shields.io/github/stars/withmasday/CVE-2021-3129.svg) ![forks](https://img.shields.io/github/forks/withmasday/CVE-2021-3129.svg)
- [https://github.com/keyuan15/CVE-2021-3129](https://github.com/keyuan15/CVE-2021-3129) :  ![starts](https://img.shields.io/github/stars/keyuan15/CVE-2021-3129.svg) ![forks](https://img.shields.io/github/forks/keyuan15/CVE-2021-3129.svg)
- [https://github.com/JacobEbben/CVE-2021-3129](https://github.com/JacobEbben/CVE-2021-3129) :  ![starts](https://img.shields.io/github/stars/JacobEbben/CVE-2021-3129.svg) ![forks](https://img.shields.io/github/forks/JacobEbben/CVE-2021-3129.svg)
- [https://github.com/miko550/CVE-2021-3129](https://github.com/miko550/CVE-2021-3129) :  ![starts](https://img.shields.io/github/stars/miko550/CVE-2021-3129.svg) ![forks](https://img.shields.io/github/forks/miko550/CVE-2021-3129.svg)
- [https://github.com/Zoo1sondv/CVE-2021-3129](https://github.com/Zoo1sondv/CVE-2021-3129) :  ![starts](https://img.shields.io/github/stars/Zoo1sondv/CVE-2021-3129.svg) ![forks](https://img.shields.io/github/forks/Zoo1sondv/CVE-2021-3129.svg)
- [https://github.com/qaisarafridi/cve-2021-3129](https://github.com/qaisarafridi/cve-2021-3129) :  ![starts](https://img.shields.io/github/stars/qaisarafridi/cve-2021-3129.svg) ![forks](https://img.shields.io/github/forks/qaisarafridi/cve-2021-3129.svg)
- [https://github.com/hupe1980/CVE-2021-3129](https://github.com/hupe1980/CVE-2021-3129) :  ![starts](https://img.shields.io/github/stars/hupe1980/CVE-2021-3129.svg) ![forks](https://img.shields.io/github/forks/hupe1980/CVE-2021-3129.svg)
- [https://github.com/aurelien-vilminot/ENSIMAG_EXPLOIT_CVE2_3A](https://github.com/aurelien-vilminot/ENSIMAG_EXPLOIT_CVE2_3A) :  ![starts](https://img.shields.io/github/stars/aurelien-vilminot/ENSIMAG_EXPLOIT_CVE2_3A.svg) ![forks](https://img.shields.io/github/forks/aurelien-vilminot/ENSIMAG_EXPLOIT_CVE2_3A.svg)
- [https://github.com/banyaksepuh/Mass-CVE-2021-3129-Scanner](https://github.com/banyaksepuh/Mass-CVE-2021-3129-Scanner) :  ![starts](https://img.shields.io/github/stars/banyaksepuh/Mass-CVE-2021-3129-Scanner.svg) ![forks](https://img.shields.io/github/forks/banyaksepuh/Mass-CVE-2021-3129-Scanner.svg)


## CVE-2021-3064
 A memory corruption vulnerability exists in Palo Alto Networks GlobalProtect portal and gateway interfaces that enables an unauthenticated network-based attacker to disrupt system processes and potentially execute arbitrary code with root privileges. The attacker must have network access to the GlobalProtect interface to exploit this issue. This issue impacts PAN-OS 8.1 versions earlier than PAN-OS 8.1.17. Prisma Access customers are not impacted by this issue.

- [https://github.com/0xhaggis/CVE-2021-3064](https://github.com/0xhaggis/CVE-2021-3064) :  ![starts](https://img.shields.io/github/stars/0xhaggis/CVE-2021-3064.svg) ![forks](https://img.shields.io/github/forks/0xhaggis/CVE-2021-3064.svg)


## CVE-2021-3060
 An OS command injection vulnerability in the Simple Certificate Enrollment Protocol (SCEP) feature of PAN-OS software allows an unauthenticated network-based attacker with specific knowledge of the firewall configuration to execute arbitrary code with root user privileges. The attacker must have network access to the GlobalProtect interfaces to exploit this issue. This issue impacts: PAN-OS 8.1 versions earlier than PAN-OS 8.1.20-h1; PAN-OS 9.0 versions earlier than PAN-OS 9.0.14-h3; PAN-OS 9.1 versions earlier than PAN-OS 9.1.11-h2; PAN-OS 10.0 versions earlier than PAN-OS 10.0.8; PAN-OS 10.1 versions earlier than PAN-OS 10.1.3. Prisma Access customers with Prisma Access 2.1 Preferred and Prisma Access 2.1 Innovation firewalls are impacted by this issue.

- [https://github.com/timb-machine-mirrors/rqu1-cve-2021-3060.py](https://github.com/timb-machine-mirrors/rqu1-cve-2021-3060.py) :  ![starts](https://img.shields.io/github/stars/timb-machine-mirrors/rqu1-cve-2021-3060.py.svg) ![forks](https://img.shields.io/github/forks/timb-machine-mirrors/rqu1-cve-2021-3060.py.svg)
- [https://github.com/anmolksachan/CVE-2021-3060](https://github.com/anmolksachan/CVE-2021-3060) :  ![starts](https://img.shields.io/github/stars/anmolksachan/CVE-2021-3060.svg) ![forks](https://img.shields.io/github/forks/anmolksachan/CVE-2021-3060.svg)


## CVE-2021-3036
 An information exposure through log file vulnerability exists in Palo Alto Networks PAN-OS software where secrets in PAN-OS XML API requests are logged in cleartext to the web server logs when the API is used incorrectly. This vulnerability applies only to PAN-OS appliances that are configured to use the PAN-OS XML API and exists only when a client includes a duplicate API parameter in API requests. Logged information includes the cleartext username, password, and API key of the administrator making the PAN-OS XML API request.

- [https://github.com/0xhaggis/CVE-2021-3064](https://github.com/0xhaggis/CVE-2021-3064) :  ![starts](https://img.shields.io/github/stars/0xhaggis/CVE-2021-3064.svg) ![forks](https://img.shields.io/github/forks/0xhaggis/CVE-2021-3064.svg)


## CVE-2021-3019
 ffay lanproxy 0.1 allows Directory Traversal to read /../conf/config.properties to obtain credentials for a connection to the intranet.

- [https://github.com/0xf4n9x/CVE-2021-3019](https://github.com/0xf4n9x/CVE-2021-3019) :  ![starts](https://img.shields.io/github/stars/0xf4n9x/CVE-2021-3019.svg) ![forks](https://img.shields.io/github/forks/0xf4n9x/CVE-2021-3019.svg)
- [https://github.com/B1anda0/CVE-2021-3019](https://github.com/B1anda0/CVE-2021-3019) :  ![starts](https://img.shields.io/github/stars/B1anda0/CVE-2021-3019.svg) ![forks](https://img.shields.io/github/forks/B1anda0/CVE-2021-3019.svg)
- [https://github.com/Maksim-venus/CVE-2021-3019](https://github.com/Maksim-venus/CVE-2021-3019) :  ![starts](https://img.shields.io/github/stars/Maksim-venus/CVE-2021-3019.svg) ![forks](https://img.shields.io/github/forks/Maksim-venus/CVE-2021-3019.svg)
- [https://github.com/murataydemir/CVE-2021-3019](https://github.com/murataydemir/CVE-2021-3019) :  ![starts](https://img.shields.io/github/stars/murataydemir/CVE-2021-3019.svg) ![forks](https://img.shields.io/github/forks/murataydemir/CVE-2021-3019.svg)
- [https://github.com/givemefivw/CVE-2021-3019](https://github.com/givemefivw/CVE-2021-3019) :  ![starts](https://img.shields.io/github/stars/givemefivw/CVE-2021-3019.svg) ![forks](https://img.shields.io/github/forks/givemefivw/CVE-2021-3019.svg)
- [https://github.com/qiezi-maozi/CVE-2021-3019-Lanproxy](https://github.com/qiezi-maozi/CVE-2021-3019-Lanproxy) :  ![starts](https://img.shields.io/github/stars/qiezi-maozi/CVE-2021-3019-Lanproxy.svg) ![forks](https://img.shields.io/github/forks/qiezi-maozi/CVE-2021-3019-Lanproxy.svg)
- [https://github.com/a1665454764/CVE-2021-3019](https://github.com/a1665454764/CVE-2021-3019) :  ![starts](https://img.shields.io/github/stars/a1665454764/CVE-2021-3019.svg) ![forks](https://img.shields.io/github/forks/a1665454764/CVE-2021-3019.svg)
- [https://github.com/Aoyuh/cve-2021-3019](https://github.com/Aoyuh/cve-2021-3019) :  ![starts](https://img.shields.io/github/stars/Aoyuh/cve-2021-3019.svg) ![forks](https://img.shields.io/github/forks/Aoyuh/cve-2021-3019.svg)


## CVE-2021-3007
 ** DISPUTED ** Laminas Project laminas-http before 2.14.2, and Zend Framework 3.0.0, has a deserialization vulnerability that can lead to remote code execution if the content is controllable, related to the __destruct method of the Zend\Http\Response\Stream class in Stream.php. NOTE: Zend Framework is no longer supported by the maintainer. NOTE: the laminas-http vendor considers this a &quot;vulnerability in the PHP language itself&quot; but has added certain type checking as a way to prevent exploitation in (unrecommended) use cases where attacker-supplied data can be deserialized.

- [https://github.com/Vulnmachines/ZF3_CVE-2021-3007](https://github.com/Vulnmachines/ZF3_CVE-2021-3007) :  ![starts](https://img.shields.io/github/stars/Vulnmachines/ZF3_CVE-2021-3007.svg) ![forks](https://img.shields.io/github/forks/Vulnmachines/ZF3_CVE-2021-3007.svg)


## CVE-2021-2471
 Vulnerability in the MySQL Connectors product of Oracle MySQL (component: Connector/J). Supported versions that are affected are 8.0.26 and prior. Difficult to exploit vulnerability allows high privileged attacker with network access via multiple protocols to compromise MySQL Connectors. Successful attacks of this vulnerability can result in unauthorized access to critical data or complete access to all MySQL Connectors accessible data and unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of MySQL Connectors. CVSS 3.1 Base Score 5.9 (Confidentiality and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:N/A:H).

- [https://github.com/SecCoder-Security-Lab/jdbc-sqlxml-xxe](https://github.com/SecCoder-Security-Lab/jdbc-sqlxml-xxe) :  ![starts](https://img.shields.io/github/stars/SecCoder-Security-Lab/jdbc-sqlxml-xxe.svg) ![forks](https://img.shields.io/github/forks/SecCoder-Security-Lab/jdbc-sqlxml-xxe.svg)
- [https://github.com/DrunkenShells/CVE-2021-2471](https://github.com/DrunkenShells/CVE-2021-2471) :  ![starts](https://img.shields.io/github/stars/DrunkenShells/CVE-2021-2471.svg) ![forks](https://img.shields.io/github/forks/DrunkenShells/CVE-2021-2471.svg)
- [https://github.com/cckuailong/CVE-2021-2471](https://github.com/cckuailong/CVE-2021-2471) :  ![starts](https://img.shields.io/github/stars/cckuailong/CVE-2021-2471.svg) ![forks](https://img.shields.io/github/forks/cckuailong/CVE-2021-2471.svg)


## CVE-2021-2456
 Vulnerability in the Oracle Business Intelligence Enterprise Edition product of Oracle Fusion Middleware (component: Analytics Web General). The supported version that is affected is 12.2.1.4.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Business Intelligence Enterprise Edition. Successful attacks of this vulnerability can result in takeover of Oracle Business Intelligence Enterprise Edition. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/peterjson31337/CVE-2021-2456](https://github.com/peterjson31337/CVE-2021-2456) :  ![starts](https://img.shields.io/github/stars/peterjson31337/CVE-2021-2456.svg) ![forks](https://img.shields.io/github/forks/peterjson31337/CVE-2021-2456.svg)


## CVE-2021-2394
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Core). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0, 12.2.1.4.0 and 14.1.1.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3, IIOP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/lz2y/CVE-2021-2394](https://github.com/lz2y/CVE-2021-2394) :  ![starts](https://img.shields.io/github/stars/lz2y/CVE-2021-2394.svg) ![forks](https://img.shields.io/github/forks/lz2y/CVE-2021-2394.svg)
- [https://github.com/freeide/CVE-2021-2394](https://github.com/freeide/CVE-2021-2394) :  ![starts](https://img.shields.io/github/stars/freeide/CVE-2021-2394.svg) ![forks](https://img.shields.io/github/forks/freeide/CVE-2021-2394.svg)
- [https://github.com/BabyTeam1024/CVE-2021-2394](https://github.com/BabyTeam1024/CVE-2021-2394) :  ![starts](https://img.shields.io/github/stars/BabyTeam1024/CVE-2021-2394.svg) ![forks](https://img.shields.io/github/forks/BabyTeam1024/CVE-2021-2394.svg)
- [https://github.com/fasanhlieu/CVE-2021-2394](https://github.com/fasanhlieu/CVE-2021-2394) :  ![starts](https://img.shields.io/github/stars/fasanhlieu/CVE-2021-2394.svg) ![forks](https://img.shields.io/github/forks/fasanhlieu/CVE-2021-2394.svg)


## CVE-2021-2302
 Vulnerability in the Oracle Platform Security for Java product of Oracle Fusion Middleware (component: OPSS). Supported versions that are affected are 11.1.1.9.0, 12.2.1.3.0 and 12.2.1.4.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Platform Security for Java. Successful attacks of this vulnerability can result in takeover of Oracle Platform Security for Java. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/quynhle7821/CVE-2021-2302](https://github.com/quynhle7821/CVE-2021-2302) :  ![starts](https://img.shields.io/github/stars/quynhle7821/CVE-2021-2302.svg) ![forks](https://img.shields.io/github/forks/quynhle7821/CVE-2021-2302.svg)


## CVE-2021-2175
 Vulnerability in the Database Vault component of Oracle Database Server. Supported versions that are affected are 12.1.0.2, 12.2.0.1, 18c and 19c. Easily exploitable vulnerability allows high privileged attacker having Create Any View, Select Any View privilege with network access via Oracle Net to compromise Database Vault. Successful attacks of this vulnerability can result in unauthorized read access to a subset of Database Vault accessible data. CVSS 3.1 Base Score 2.7 (Confidentiality impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:N/A:N).

- [https://github.com/emad-almousa/CVE-2021-2175](https://github.com/emad-almousa/CVE-2021-2175) :  ![starts](https://img.shields.io/github/stars/emad-almousa/CVE-2021-2175.svg) ![forks](https://img.shields.io/github/forks/emad-almousa/CVE-2021-2175.svg)


## CVE-2021-2173
 Vulnerability in the Recovery component of Oracle Database Server. Supported versions that are affected are 12.1.0.2, 12.2.0.1, 18c and 19c. Easily exploitable vulnerability allows high privileged attacker having DBA Level Account privilege with network access via Oracle Net to compromise Recovery. While the vulnerability is in Recovery, attacks may significantly impact additional products. Successful attacks of this vulnerability can result in unauthorized read access to a subset of Recovery accessible data. CVSS 3.1 Base Score 4.1 (Confidentiality impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:L/I:N/A:N).

- [https://github.com/emad-almousa/CVE-2021-2173](https://github.com/emad-almousa/CVE-2021-2173) :  ![starts](https://img.shields.io/github/stars/emad-almousa/CVE-2021-2173.svg) ![forks](https://img.shields.io/github/forks/emad-almousa/CVE-2021-2173.svg)


## CVE-2021-2119
 Vulnerability in the Oracle VM VirtualBox product of Oracle Virtualization (component: Core). The supported version that is affected is Prior to 6.1.18. Easily exploitable vulnerability allows high privileged attacker with logon to the infrastructure where Oracle VM VirtualBox executes to compromise Oracle VM VirtualBox. While the vulnerability is in Oracle VM VirtualBox, attacks may significantly impact additional products. Successful attacks of this vulnerability can result in unauthorized access to critical data or complete access to all Oracle VM VirtualBox accessible data. CVSS 3.1 Base Score 6.0 (Confidentiality impacts). CVSS Vector: (CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:N/A:N).

- [https://github.com/Sauercloud/RWCTF21-VirtualBox-61-escape](https://github.com/Sauercloud/RWCTF21-VirtualBox-61-escape) :  ![starts](https://img.shields.io/github/stars/Sauercloud/RWCTF21-VirtualBox-61-escape.svg) ![forks](https://img.shields.io/github/forks/Sauercloud/RWCTF21-VirtualBox-61-escape.svg)
- [https://github.com/shi10587s/Sauercloude](https://github.com/shi10587s/Sauercloude) :  ![starts](https://img.shields.io/github/stars/shi10587s/Sauercloude.svg) ![forks](https://img.shields.io/github/forks/shi10587s/Sauercloude.svg)
- [https://github.com/chatbottesisgmailh/Sauercloude](https://github.com/chatbottesisgmailh/Sauercloude) :  ![starts](https://img.shields.io/github/stars/chatbottesisgmailh/Sauercloude.svg) ![forks](https://img.shields.io/github/forks/chatbottesisgmailh/Sauercloude.svg)


## CVE-2021-2109
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Console). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0, 12.2.1.4.0 and 14.1.1.0.0. Easily exploitable vulnerability allows high privileged attacker with network access via HTTP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.1 Base Score 7.2 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/1n7erface/PocList](https://github.com/1n7erface/PocList) :  ![starts](https://img.shields.io/github/stars/1n7erface/PocList.svg) ![forks](https://img.shields.io/github/forks/1n7erface/PocList.svg)
- [https://github.com/Al1ex/CVE-2021-2109](https://github.com/Al1ex/CVE-2021-2109) :  ![starts](https://img.shields.io/github/stars/Al1ex/CVE-2021-2109.svg) ![forks](https://img.shields.io/github/forks/Al1ex/CVE-2021-2109.svg)
- [https://github.com/somatrasss/weblogic2021](https://github.com/somatrasss/weblogic2021) :  ![starts](https://img.shields.io/github/stars/somatrasss/weblogic2021.svg) ![forks](https://img.shields.io/github/forks/somatrasss/weblogic2021.svg)
- [https://github.com/rabbitsafe/CVE-2021-2109](https://github.com/rabbitsafe/CVE-2021-2109) :  ![starts](https://img.shields.io/github/stars/rabbitsafe/CVE-2021-2109.svg) ![forks](https://img.shields.io/github/forks/rabbitsafe/CVE-2021-2109.svg)
- [https://github.com/yuaneuro/CVE-2021-2109_poc](https://github.com/yuaneuro/CVE-2021-2109_poc) :  ![starts](https://img.shields.io/github/stars/yuaneuro/CVE-2021-2109_poc.svg) ![forks](https://img.shields.io/github/forks/yuaneuro/CVE-2021-2109_poc.svg)
- [https://github.com/Vulnmachines/oracle-weblogic-CVE-2021-2109](https://github.com/Vulnmachines/oracle-weblogic-CVE-2021-2109) :  ![starts](https://img.shields.io/github/stars/Vulnmachines/oracle-weblogic-CVE-2021-2109.svg) ![forks](https://img.shields.io/github/forks/Vulnmachines/oracle-weblogic-CVE-2021-2109.svg)
- [https://github.com/dinosn/CVE-2021-2109](https://github.com/dinosn/CVE-2021-2109) :  ![starts](https://img.shields.io/github/stars/dinosn/CVE-2021-2109.svg) ![forks](https://img.shields.io/github/forks/dinosn/CVE-2021-2109.svg)
- [https://github.com/coco0x0a/CVE-2021-2109](https://github.com/coco0x0a/CVE-2021-2109) :  ![starts](https://img.shields.io/github/stars/coco0x0a/CVE-2021-2109.svg) ![forks](https://img.shields.io/github/forks/coco0x0a/CVE-2021-2109.svg)


## CVE-2021-2108
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Core Components). The supported version that is affected is 12.1.3.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via IIOP, T3 to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/somatrasss/weblogic2021](https://github.com/somatrasss/weblogic2021) :  ![starts](https://img.shields.io/github/stars/somatrasss/weblogic2021.svg) ![forks](https://img.shields.io/github/forks/somatrasss/weblogic2021.svg)


## CVE-2021-2075
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Samples). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0, 12.2.1.4.0 and 14.1.1.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via IIOP, T3 to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/somatrasss/weblogic2021](https://github.com/somatrasss/weblogic2021) :  ![starts](https://img.shields.io/github/stars/somatrasss/weblogic2021.svg) ![forks](https://img.shields.io/github/forks/somatrasss/weblogic2021.svg)


## CVE-2021-2064
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Core Components). The supported version that is affected is 12.1.3.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via IIOP, T3 to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/somatrasss/weblogic2021](https://github.com/somatrasss/weblogic2021) :  ![starts](https://img.shields.io/github/stars/somatrasss/weblogic2021.svg) ![forks](https://img.shields.io/github/forks/somatrasss/weblogic2021.svg)


## CVE-2021-2047
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Core Components). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, and 12.2.1.3.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via IIOP, T3 to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/somatrasss/weblogic2021](https://github.com/somatrasss/weblogic2021) :  ![starts](https://img.shields.io/github/stars/somatrasss/weblogic2021.svg) ![forks](https://img.shields.io/github/forks/somatrasss/weblogic2021.svg)


## CVE-2021-2022
 Vulnerability in the MySQL Server product of Oracle MySQL (component: InnoDB). Supported versions that are affected are 5.6.50 and prior, 5.7.32 and prior and 8.0.22 and prior. Difficult to exploit vulnerability allows high privileged attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of MySQL Server. CVSS 3.1 Base Score 4.4 (Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:N/I:N/A:H).

- [https://github.com/Lotus6/ConfluenceMemshell](https://github.com/Lotus6/ConfluenceMemshell) :  ![starts](https://img.shields.io/github/stars/Lotus6/ConfluenceMemshell.svg) ![forks](https://img.shields.io/github/forks/Lotus6/ConfluenceMemshell.svg)
- [https://github.com/team-v-2022/Cosine-Percentage-Calculation](https://github.com/team-v-2022/Cosine-Percentage-Calculation) :  ![starts](https://img.shields.io/github/stars/team-v-2022/Cosine-Percentage-Calculation.svg) ![forks](https://img.shields.io/github/forks/team-v-2022/Cosine-Percentage-Calculation.svg)


## CVE-2021-2021
 Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Optimizer). Supported versions that are affected are 8.0.22 and prior. Easily exploitable vulnerability allows high privileged attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of MySQL Server. CVSS 3.1 Base Score 4.9 (Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H).

- [https://github.com/TheCryingGame/CVE-2021-2021good](https://github.com/TheCryingGame/CVE-2021-2021good) :  ![starts](https://img.shields.io/github/stars/TheCryingGame/CVE-2021-2021good.svg) ![forks](https://img.shields.io/github/forks/TheCryingGame/CVE-2021-2021good.svg)


## CVE-2020-3580
 Multiple vulnerabilities in the web services interface of Cisco Adaptive Security Appliance (ASA) Software and Cisco Firepower Threat Defense (FTD) Software could allow an unauthenticated, remote attacker to conduct cross-site scripting (XSS) attacks against a user of the web services interface of an affected device. The vulnerabilities are due to insufficient validation of user-supplied input by the web services interface of an affected device. An attacker could exploit these vulnerabilities by persuading a user of the interface to click a crafted link. A successful exploit could allow the attacker to execute arbitrary script code in the context of the interface or allow the attacker to access sensitive, browser-based information. Note: These vulnerabilities affect only specific AnyConnect and WebVPN configurations. For more information, see the Vulnerable Products section.

- [https://github.com/adarshvs/CVE-2020-3580](https://github.com/adarshvs/CVE-2020-3580) :  ![starts](https://img.shields.io/github/stars/adarshvs/CVE-2020-3580.svg) ![forks](https://img.shields.io/github/forks/adarshvs/CVE-2020-3580.svg)
- [https://github.com/Hudi233/CVE-2020-3580](https://github.com/Hudi233/CVE-2020-3580) :  ![starts](https://img.shields.io/github/stars/Hudi233/CVE-2020-3580.svg) ![forks](https://img.shields.io/github/forks/Hudi233/CVE-2020-3580.svg)
- [https://github.com/catatonicprime/CVE-2020-3580](https://github.com/catatonicprime/CVE-2020-3580) :  ![starts](https://img.shields.io/github/stars/catatonicprime/CVE-2020-3580.svg) ![forks](https://img.shields.io/github/forks/catatonicprime/CVE-2020-3580.svg)
- [https://github.com/imhunterand/CVE-2020-3580](https://github.com/imhunterand/CVE-2020-3580) :  ![starts](https://img.shields.io/github/stars/imhunterand/CVE-2020-3580.svg) ![forks](https://img.shields.io/github/forks/imhunterand/CVE-2020-3580.svg)
- [https://github.com/cruxN3T/CVE-2020-3580](https://github.com/cruxN3T/CVE-2020-3580) :  ![starts](https://img.shields.io/github/stars/cruxN3T/CVE-2020-3580.svg) ![forks](https://img.shields.io/github/forks/cruxN3T/CVE-2020-3580.svg)


## CVE-2020-2950
 Vulnerability in the Oracle Business Intelligence Enterprise Edition product of Oracle Fusion Middleware (component: Analytics Web General). Supported versions that are affected are 5.5.0.0.0, 11.1.1.9.0, 12.2.1.3.0 and 12.2.1.4.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Business Intelligence Enterprise Edition. Successful attacks of this vulnerability can result in takeover of Oracle Business Intelligence Enterprise Edition. CVSS 3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/hktalent/CVE_2020_2546](https://github.com/hktalent/CVE_2020_2546) :  ![starts](https://img.shields.io/github/stars/hktalent/CVE_2020_2546.svg) ![forks](https://img.shields.io/github/forks/hktalent/CVE_2020_2546.svg)
- [https://github.com/tuo4n8/CVE-2020-2950](https://github.com/tuo4n8/CVE-2020-2950) :  ![starts](https://img.shields.io/github/stars/tuo4n8/CVE-2020-2950.svg) ![forks](https://img.shields.io/github/forks/tuo4n8/CVE-2020-2950.svg)


## CVE-2020-2915
 Vulnerability in the Oracle Coherence product of Oracle Fusion Middleware (component: Caching, CacheStore, Invocation). Supported versions that are affected are 3.7.1.0, 12.1.3.0.0, 12.2.1.3.0 and 12.2.1.4.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via IIOP, T3 to compromise Oracle Coherence. Successful attacks of this vulnerability can result in takeover of Oracle Coherence. CVSS 3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/hktalent/CVE_2020_2546](https://github.com/hktalent/CVE_2020_2546) :  ![starts](https://img.shields.io/github/stars/hktalent/CVE_2020_2546.svg) ![forks](https://img.shields.io/github/forks/hktalent/CVE_2020_2546.svg)


## CVE-2020-2884
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Core). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0 and 12.2.1.4.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via IIOP, T3 to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/hktalent/CVE_2020_2546](https://github.com/hktalent/CVE_2020_2546) :  ![starts](https://img.shields.io/github/stars/hktalent/CVE_2020_2546.svg) ![forks](https://img.shields.io/github/forks/hktalent/CVE_2020_2546.svg)


## CVE-2020-2883
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Core). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0 and 12.2.1.4.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via IIOP, T3 to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/zhzyker/exphub](https://github.com/zhzyker/exphub) :  ![starts](https://img.shields.io/github/stars/zhzyker/exphub.svg) ![forks](https://img.shields.io/github/forks/zhzyker/exphub.svg)
- [https://github.com/zhzyker/vulmap](https://github.com/zhzyker/vulmap) :  ![starts](https://img.shields.io/github/stars/zhzyker/vulmap.svg) ![forks](https://img.shields.io/github/forks/zhzyker/vulmap.svg)
- [https://github.com/0xn0ne/weblogicScanner](https://github.com/0xn0ne/weblogicScanner) :  ![starts](https://img.shields.io/github/stars/0xn0ne/weblogicScanner.svg) ![forks](https://img.shields.io/github/forks/0xn0ne/weblogicScanner.svg)
- [https://github.com/Y4er/WebLogic-Shiro-shell](https://github.com/Y4er/WebLogic-Shiro-shell) :  ![starts](https://img.shields.io/github/stars/Y4er/WebLogic-Shiro-shell.svg) ![forks](https://img.shields.io/github/forks/Y4er/WebLogic-Shiro-shell.svg)
- [https://github.com/Y4er/CVE-2020-2883](https://github.com/Y4er/CVE-2020-2883) :  ![starts](https://img.shields.io/github/stars/Y4er/CVE-2020-2883.svg) ![forks](https://img.shields.io/github/forks/Y4er/CVE-2020-2883.svg)
- [https://github.com/hktalent/CVE_2020_2546](https://github.com/hktalent/CVE_2020_2546) :  ![starts](https://img.shields.io/github/stars/hktalent/CVE_2020_2546.svg) ![forks](https://img.shields.io/github/forks/hktalent/CVE_2020_2546.svg)
- [https://github.com/zzwlpx/weblogicPoc](https://github.com/zzwlpx/weblogicPoc) :  ![starts](https://img.shields.io/github/stars/zzwlpx/weblogicPoc.svg) ![forks](https://img.shields.io/github/forks/zzwlpx/weblogicPoc.svg)
- [https://github.com/MagicZer0/Weblogic_CVE-2020-2883_POC](https://github.com/MagicZer0/Weblogic_CVE-2020-2883_POC) :  ![starts](https://img.shields.io/github/stars/MagicZer0/Weblogic_CVE-2020-2883_POC.svg) ![forks](https://img.shields.io/github/forks/MagicZer0/Weblogic_CVE-2020-2883_POC.svg)
- [https://github.com/Al1ex/CVE-2020-2883](https://github.com/Al1ex/CVE-2020-2883) :  ![starts](https://img.shields.io/github/stars/Al1ex/CVE-2020-2883.svg) ![forks](https://img.shields.io/github/forks/Al1ex/CVE-2020-2883.svg)
- [https://github.com/FancyDoesSecurity/CVE-2020-2883](https://github.com/FancyDoesSecurity/CVE-2020-2883) :  ![starts](https://img.shields.io/github/stars/FancyDoesSecurity/CVE-2020-2883.svg) ![forks](https://img.shields.io/github/forks/FancyDoesSecurity/CVE-2020-2883.svg)
- [https://github.com/ZZZWD/CVE-2020-2883](https://github.com/ZZZWD/CVE-2020-2883) :  ![starts](https://img.shields.io/github/stars/ZZZWD/CVE-2020-2883.svg) ![forks](https://img.shields.io/github/forks/ZZZWD/CVE-2020-2883.svg)
- [https://github.com/Qynklee/POC_CVE-2020-2883](https://github.com/Qynklee/POC_CVE-2020-2883) :  ![starts](https://img.shields.io/github/stars/Qynklee/POC_CVE-2020-2883.svg) ![forks](https://img.shields.io/github/forks/Qynklee/POC_CVE-2020-2883.svg)


## CVE-2020-2801
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Core). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0 and 12.2.1.4.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via IIOP, T3 to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. Note: The patch for this issue will address the vulnerability only if the WLS instance is using JDK 1.7.0_191 or later, or JDK 1.8.0_181 or later. CVSS 3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/hktalent/CVE_2020_2546](https://github.com/hktalent/CVE_2020_2546) :  ![starts](https://img.shields.io/github/stars/hktalent/CVE_2020_2546.svg) ![forks](https://img.shields.io/github/forks/hktalent/CVE_2020_2546.svg)


## CVE-2020-2798
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: WLS Web Services). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0 and 12.2.1.4.0. Easily exploitable vulnerability allows high privileged attacker with network access via IIOP, T3 to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.0 Base Score 7.2 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/hktalent/CVE_2020_2546](https://github.com/hktalent/CVE_2020_2546) :  ![starts](https://img.shields.io/github/stars/hktalent/CVE_2020_2546.svg) ![forks](https://img.shields.io/github/forks/hktalent/CVE_2020_2546.svg)


## CVE-2020-2655
 Vulnerability in the Java SE product of Oracle Java SE (component: JSSE). Supported versions that are affected are Java SE: 11.0.5 and 13.0.1. Difficult to exploit vulnerability allows unauthenticated attacker with network access via HTTPS to compromise Java SE. Successful attacks of this vulnerability can result in unauthorized update, insert or delete access to some of Java SE accessible data as well as unauthorized read access to a subset of Java SE accessible data. Note: This vulnerability applies to Java deployments, typically in clients running sandboxed Java Web Start applications or sandboxed Java applets (in Java SE 8), that load and run untrusted code (e.g., code that comes from the internet) and rely on the Java sandbox for security. This vulnerability can also be exploited by using APIs in the specified Component, e.g., through a web service which supplies data to the APIs. CVSS 3.0 Base Score 4.8 (Confidentiality and Integrity impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N).

- [https://github.com/RUB-NDS/CVE-2020-2655-DemoServer](https://github.com/RUB-NDS/CVE-2020-2655-DemoServer) :  ![starts](https://img.shields.io/github/stars/RUB-NDS/CVE-2020-2655-DemoServer.svg) ![forks](https://img.shields.io/github/forks/RUB-NDS/CVE-2020-2655-DemoServer.svg)


## CVE-2020-2556
 Vulnerability in the Primavera P6 Enterprise Project Portfolio Management product of Oracle Construction and Engineering (component: Core). Supported versions that are affected are 16.2.0.0-16.2.19.0, 17.12.0.0-17.12.16.0, 18.8.0.0-18.8.16.0, 19.12.0.0 and 20.1.0.0. Easily exploitable vulnerability allows low privileged attacker with logon to the infrastructure where Primavera P6 Enterprise Project Portfolio Management executes to compromise Primavera P6 Enterprise Project Portfolio Management. Successful attacks require human interaction from a person other than the attacker and while the vulnerability is in Primavera P6 Enterprise Project Portfolio Management, attacks may significantly impact additional products. Successful attacks of this vulnerability can result in unauthorized creation, deletion or modification access to critical data or all Primavera P6 Enterprise Project Portfolio Management accessible data as well as unauthorized read access to a subset of Primavera P6 Enterprise Project Portfolio Management accessible data and unauthorized ability to cause a partial denial of service (partial DOS) of Primavera P6 Enterprise Project Portfolio Management. CVSS 3.0 Base Score 7.3 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:C/C:L/I:H/A:L).

- [https://github.com/5l1v3r1/CVE-2020-2556](https://github.com/5l1v3r1/CVE-2020-2556) :  ![starts](https://img.shields.io/github/stars/5l1v3r1/CVE-2020-2556.svg) ![forks](https://img.shields.io/github/forks/5l1v3r1/CVE-2020-2556.svg)


## CVE-2020-2555
 Vulnerability in the Oracle Coherence product of Oracle Fusion Middleware (component: Caching,CacheStore,Invocation). Supported versions that are affected are 3.7.1.0, 12.1.3.0.0, 12.2.1.3.0 and 12.2.1.4.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3 to compromise Oracle Coherence. Successful attacks of this vulnerability can result in takeover of Oracle Coherence. CVSS 3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/zhzyker/exphub](https://github.com/zhzyker/exphub) :  ![starts](https://img.shields.io/github/stars/zhzyker/exphub.svg) ![forks](https://img.shields.io/github/forks/zhzyker/exphub.svg)
- [https://github.com/zhzyker/vulmap](https://github.com/zhzyker/vulmap) :  ![starts](https://img.shields.io/github/stars/zhzyker/vulmap.svg) ![forks](https://img.shields.io/github/forks/zhzyker/vulmap.svg)
- [https://github.com/0xn0ne/weblogicScanner](https://github.com/0xn0ne/weblogicScanner) :  ![starts](https://img.shields.io/github/stars/0xn0ne/weblogicScanner.svg) ![forks](https://img.shields.io/github/forks/0xn0ne/weblogicScanner.svg)
- [https://github.com/Y4er/CVE-2020-2555](https://github.com/Y4er/CVE-2020-2555) :  ![starts](https://img.shields.io/github/stars/Y4er/CVE-2020-2555.svg) ![forks](https://img.shields.io/github/forks/Y4er/CVE-2020-2555.svg)
- [https://github.com/zzwlpx/weblogicPoc](https://github.com/zzwlpx/weblogicPoc) :  ![starts](https://img.shields.io/github/stars/zzwlpx/weblogicPoc.svg) ![forks](https://img.shields.io/github/forks/zzwlpx/weblogicPoc.svg)
- [https://github.com/wsfengfan/CVE-2020-2555](https://github.com/wsfengfan/CVE-2020-2555) :  ![starts](https://img.shields.io/github/stars/wsfengfan/CVE-2020-2555.svg) ![forks](https://img.shields.io/github/forks/wsfengfan/CVE-2020-2555.svg)
- [https://github.com/feihong-cs/Attacking_Shiro_with_CVE_2020_2555](https://github.com/feihong-cs/Attacking_Shiro_with_CVE_2020_2555) :  ![starts](https://img.shields.io/github/stars/feihong-cs/Attacking_Shiro_with_CVE_2020_2555.svg) ![forks](https://img.shields.io/github/forks/feihong-cs/Attacking_Shiro_with_CVE_2020_2555.svg)
- [https://github.com/Maskhe/cve-2020-2555](https://github.com/Maskhe/cve-2020-2555) :  ![starts](https://img.shields.io/github/stars/Maskhe/cve-2020-2555.svg) ![forks](https://img.shields.io/github/forks/Maskhe/cve-2020-2555.svg)
- [https://github.com/adm1in/CodeTest](https://github.com/adm1in/CodeTest) :  ![starts](https://img.shields.io/github/stars/adm1in/CodeTest.svg) ![forks](https://img.shields.io/github/forks/adm1in/CodeTest.svg)
- [https://github.com/Hu3sky/CVE-2020-2555](https://github.com/Hu3sky/CVE-2020-2555) :  ![starts](https://img.shields.io/github/stars/Hu3sky/CVE-2020-2555.svg) ![forks](https://img.shields.io/github/forks/Hu3sky/CVE-2020-2555.svg)
- [https://github.com/5l1v3r1/CVE-2020-2556](https://github.com/5l1v3r1/CVE-2020-2556) :  ![starts](https://img.shields.io/github/stars/5l1v3r1/CVE-2020-2556.svg) ![forks](https://img.shields.io/github/forks/5l1v3r1/CVE-2020-2556.svg)
- [https://github.com/Qynklee/POC_CVE-2020-2555](https://github.com/Qynklee/POC_CVE-2020-2555) :  ![starts](https://img.shields.io/github/stars/Qynklee/POC_CVE-2020-2555.svg) ![forks](https://img.shields.io/github/forks/Qynklee/POC_CVE-2020-2555.svg)
- [https://github.com/Uvemode/CVE-2020-2555](https://github.com/Uvemode/CVE-2020-2555) :  ![starts](https://img.shields.io/github/stars/Uvemode/CVE-2020-2555.svg) ![forks](https://img.shields.io/github/forks/Uvemode/CVE-2020-2555.svg)


## CVE-2020-2553
 Vulnerability in the Oracle Knowledge product of Oracle Knowledge (component: Information Manager Console). Supported versions that are affected are 8.6.0-8.6.3. Difficult to exploit vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Knowledge. Successful attacks of this vulnerability can result in unauthorized update, insert or delete access to some of Oracle Knowledge accessible data as well as unauthorized read access to a subset of Oracle Knowledge accessible data. CVSS 3.0 Base Score 4.8 (Confidentiality and Integrity impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N).

- [https://github.com/5l1v3r1/CVE-2020-2553](https://github.com/5l1v3r1/CVE-2020-2553) :  ![starts](https://img.shields.io/github/stars/5l1v3r1/CVE-2020-2553.svg) ![forks](https://img.shields.io/github/forks/5l1v3r1/CVE-2020-2553.svg)


## CVE-2020-2551
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: WLS Core Components). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0 and 12.2.1.4.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via IIOP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/zhzyker/exphub](https://github.com/zhzyker/exphub) :  ![starts](https://img.shields.io/github/stars/zhzyker/exphub.svg) ![forks](https://img.shields.io/github/forks/zhzyker/exphub.svg)
- [https://github.com/0xn0ne/weblogicScanner](https://github.com/0xn0ne/weblogicScanner) :  ![starts](https://img.shields.io/github/stars/0xn0ne/weblogicScanner.svg) ![forks](https://img.shields.io/github/forks/0xn0ne/weblogicScanner.svg)
- [https://github.com/Y4er/CVE-2020-2551](https://github.com/Y4er/CVE-2020-2551) :  ![starts](https://img.shields.io/github/stars/Y4er/CVE-2020-2551.svg) ![forks](https://img.shields.io/github/forks/Y4er/CVE-2020-2551.svg)
- [https://github.com/hktalent/CVE-2020-2551](https://github.com/hktalent/CVE-2020-2551) :  ![starts](https://img.shields.io/github/stars/hktalent/CVE-2020-2551.svg) ![forks](https://img.shields.io/github/forks/hktalent/CVE-2020-2551.svg)
- [https://github.com/zzwlpx/weblogicPoc](https://github.com/zzwlpx/weblogicPoc) :  ![starts](https://img.shields.io/github/stars/zzwlpx/weblogicPoc.svg) ![forks](https://img.shields.io/github/forks/zzwlpx/weblogicPoc.svg)
- [https://github.com/DSO-Lab/defvul](https://github.com/DSO-Lab/defvul) :  ![starts](https://img.shields.io/github/stars/DSO-Lab/defvul.svg) ![forks](https://img.shields.io/github/forks/DSO-Lab/defvul.svg)
- [https://github.com/jas502n/CVE-2020-2551](https://github.com/jas502n/CVE-2020-2551) :  ![starts](https://img.shields.io/github/stars/jas502n/CVE-2020-2551.svg) ![forks](https://img.shields.io/github/forks/jas502n/CVE-2020-2551.svg)
- [https://github.com/Dido1960/Weblogic-CVE-2020-2551-To-Internet](https://github.com/Dido1960/Weblogic-CVE-2020-2551-To-Internet) :  ![starts](https://img.shields.io/github/stars/Dido1960/Weblogic-CVE-2020-2551-To-Internet.svg) ![forks](https://img.shields.io/github/forks/Dido1960/Weblogic-CVE-2020-2551-To-Internet.svg)
- [https://github.com/0xAbbarhSF/CVE-Exploit](https://github.com/0xAbbarhSF/CVE-Exploit) :  ![starts](https://img.shields.io/github/stars/0xAbbarhSF/CVE-Exploit.svg) ![forks](https://img.shields.io/github/forks/0xAbbarhSF/CVE-Exploit.svg)
- [https://github.com/5l1v3r1/CVE-2020-2553](https://github.com/5l1v3r1/CVE-2020-2553) :  ![starts](https://img.shields.io/github/stars/5l1v3r1/CVE-2020-2553.svg) ![forks](https://img.shields.io/github/forks/5l1v3r1/CVE-2020-2553.svg)
- [https://github.com/LTiDi2000/CVE-2020-2551](https://github.com/LTiDi2000/CVE-2020-2551) :  ![starts](https://img.shields.io/github/stars/LTiDi2000/CVE-2020-2551.svg) ![forks](https://img.shields.io/github/forks/LTiDi2000/CVE-2020-2551.svg)
- [https://github.com/DaMinGshidashi/CVE-2020-2551](https://github.com/DaMinGshidashi/CVE-2020-2551) :  ![starts](https://img.shields.io/github/stars/DaMinGshidashi/CVE-2020-2551.svg) ![forks](https://img.shields.io/github/forks/DaMinGshidashi/CVE-2020-2551.svg)


## CVE-2020-2546
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Application Container - JavaEE). Supported versions that are affected are 10.3.6.0.0 and 12.1.3.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3 to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/hktalent/CVE_2020_2546](https://github.com/hktalent/CVE_2020_2546) :  ![starts](https://img.shields.io/github/stars/hktalent/CVE_2020_2546.svg) ![forks](https://img.shields.io/github/forks/hktalent/CVE_2020_2546.svg)


## CVE-2020-2509
 A command injection vulnerability has been reported to affect QTS and QuTS hero. If exploited, this vulnerability allows attackers to execute arbitrary commands in a compromised application. We have already fixed this vulnerability in the following versions: QTS 4.5.2.1566 Build 20210202 and later QTS 4.5.1.1495 Build 20201123 and later QTS 4.3.6.1620 Build 20210322 and later QTS 4.3.4.1632 Build 20210324 and later QTS 4.3.3.1624 Build 20210416 and later QTS 4.2.6 Build 20210327 and later QuTS hero h4.5.1.1491 build 20201119 and later

- [https://github.com/jbaines-r7/overkill](https://github.com/jbaines-r7/overkill) :  ![starts](https://img.shields.io/github/stars/jbaines-r7/overkill.svg) ![forks](https://img.shields.io/github/forks/jbaines-r7/overkill.svg)


## CVE-2020-2501
 A stack-based buffer overflow vulnerability has been reported to affect QNAP NAS devices running Surveillance Station. If exploited, this vulnerability allows attackers to execute arbitrary code. QNAP have already fixed this vulnerability in the following versions: Surveillance Station 5.1.5.4.3 (and later) for ARM CPU NAS (64bit OS) and x86 CPU NAS (64bit OS) Surveillance Station 5.1.5.3.3 (and later) for ARM CPU NAS (32bit OS) and x86 CPU NAS (32bit OS)

- [https://github.com/Alonzozzz/alonzzzo](https://github.com/Alonzozzz/alonzzzo) :  ![starts](https://img.shields.io/github/stars/Alonzozzz/alonzzzo.svg) ![forks](https://img.shields.io/github/forks/Alonzozzz/alonzzzo.svg)


## CVE-2020-2333
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/section-c/CVE-2020-2333](https://github.com/section-c/CVE-2020-2333) :  ![starts](https://img.shields.io/github/stars/section-c/CVE-2020-2333.svg) ![forks](https://img.shields.io/github/forks/section-c/CVE-2020-2333.svg)


## CVE-2020-2038
 An OS Command Injection vulnerability in the PAN-OS management interface that allows authenticated administrators to execute arbitrary OS commands with root privileges. This issue impacts: PAN-OS 9.0 versions earlier than 9.0.10; PAN-OS 9.1 versions earlier than 9.1.4; PAN-OS 10.0 versions earlier than 10.0.1.

- [https://github.com/und3sc0n0c1d0/CVE-2020-2038](https://github.com/und3sc0n0c1d0/CVE-2020-2038) :  ![starts](https://img.shields.io/github/stars/und3sc0n0c1d0/CVE-2020-2038.svg) ![forks](https://img.shields.io/github/forks/und3sc0n0c1d0/CVE-2020-2038.svg)


## CVE-2020-2034
 An OS Command Injection vulnerability in the PAN-OS GlobalProtect portal allows an unauthenticated network based attacker to execute arbitrary OS commands with root privileges. An attacker requires some knowledge of the firewall to exploit this issue. This issue can not be exploited if GlobalProtect portal feature is not enabled. This issue impacts PAN-OS 9.1 versions earlier than PAN-OS 9.1.3; PAN-OS 8.1 versions earlier than PAN-OS 8.1.15; PAN-OS 9.0 versions earlier than PAN-OS 9.0.9; all versions of PAN-OS 8.0 and PAN-OS 7.1. Prisma Access services are not impacted by this vulnerability.

- [https://github.com/blackhatethicalhacking/CVE-2020-2034-POC](https://github.com/blackhatethicalhacking/CVE-2020-2034-POC) :  ![starts](https://img.shields.io/github/stars/blackhatethicalhacking/CVE-2020-2034-POC.svg) ![forks](https://img.shields.io/github/forks/blackhatethicalhacking/CVE-2020-2034-POC.svg)


## CVE-2020-2023
 Kata Containers doesn't restrict containers from accessing the guest's root filesystem device. Malicious containers can exploit this to gain code execution on the guest and masquerade as the kata-agent. This issue affects Kata Containers 1.11 versions earlier than 1.11.1; Kata Containers 1.10 versions earlier than 1.10.5; and Kata Containers 1.9 and earlier versions.

- [https://github.com/ssst0n3/kata-cve-2020-2023-poc](https://github.com/ssst0n3/kata-cve-2020-2023-poc) :  ![starts](https://img.shields.io/github/stars/ssst0n3/kata-cve-2020-2023-poc.svg) ![forks](https://img.shields.io/github/forks/ssst0n3/kata-cve-2020-2023-poc.svg)


## CVE-2020-2021
 When Security Assertion Markup Language (SAML) authentication is enabled and the 'Validate Identity Provider Certificate' option is disabled (unchecked), improper verification of signatures in PAN-OS SAML authentication enables an unauthenticated network-based attacker to access protected resources. The attacker must have network access to the vulnerable server to exploit this vulnerability. This issue affects PAN-OS 9.1 versions earlier than PAN-OS 9.1.3; PAN-OS 9.0 versions earlier than PAN-OS 9.0.9; PAN-OS 8.1 versions earlier than PAN-OS 8.1.15, and all versions of PAN-OS 8.0 (EOL). This issue does not affect PAN-OS 7.1. This issue cannot be exploited if SAML is not used for authentication. This issue cannot be exploited if the 'Validate Identity Provider Certificate' option is enabled (checked) in the SAML Identity Provider Server Profile. Resources that can be protected by SAML-based single sign-on (SSO) authentication are: GlobalProtect Gateway, GlobalProtect Portal, GlobalProtect Clientless VPN, Authentication and Captive Portal, PAN-OS next-generation firewalls (PA-Series, VM-Series) and Panorama web interfaces, Prisma Access In the case of GlobalProtect Gateways, GlobalProtect Portal, Clientless VPN, Captive Portal, and Prisma Access, an unauthenticated attacker with network access to the affected servers can gain access to protected resources if allowed by configured authentication and Security policies. There is no impact on the integrity and availability of the gateway, portal or VPN server. An attacker cannot inspect or tamper with sessions of regular users. In the worst case, this is a critical severity vulnerability with a CVSS Base Score of 10.0 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N). In the case of PAN-OS and Panorama web interfaces, this issue allows an unauthenticated attacker with network access to the PAN-OS or Panorama web interfaces to log in as an administrator and perform administrative actions. In the worst-case scenario, this is a critical severity vulnerability with a CVSS Base Score of 10.0 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H). If the web interfaces are only accessible to a restricted management network, then the issue is lowered to a CVSS Base Score of 9.6 (CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H). Palo Alto Networks is not aware of any malicious attempts to exploit this vulnerability.

- [https://github.com/mr-r3b00t/CVE-2020-2021](https://github.com/mr-r3b00t/CVE-2020-2021) :  ![starts](https://img.shields.io/github/stars/mr-r3b00t/CVE-2020-2021.svg) ![forks](https://img.shields.io/github/forks/mr-r3b00t/CVE-2020-2021.svg)


## CVE-2020-1971
 The X.509 GeneralName type is a generic type for representing different types of names. One of those name types is known as EDIPartyName. OpenSSL provides a function GENERAL_NAME_cmp which compares different instances of a GENERAL_NAME to see if they are equal or not. This function behaves incorrectly when both GENERAL_NAMEs contain an EDIPARTYNAME. A NULL pointer dereference and a crash may occur leading to a possible denial of service attack. OpenSSL itself uses the GENERAL_NAME_cmp function for two purposes: 1) Comparing CRL distribution point names between an available CRL and a CRL distribution point embedded in an X509 certificate 2) When verifying that a timestamp response token signer matches the timestamp authority name (exposed via the API functions TS_RESP_verify_response and TS_RESP_verify_token) If an attacker can control both items being compared then that attacker could trigger a crash. For example if the attacker can trick a client or server into checking a malicious certificate against a malicious CRL then this may occur. Note that some applications automatically download CRLs based on a URL embedded in a certificate. This checking happens prior to the signatures on the certificate and CRL being verified. OpenSSL's s_server, s_client and verify tools have support for the &quot;-crl_download&quot; option which implements automatic CRL downloading and this attack has been demonstrated to work against those tools. Note that an unrelated bug means that affected versions of OpenSSL cannot parse or construct correct encodings of EDIPARTYNAME. However it is possible to construct a malformed EDIPARTYNAME that OpenSSL's parser will accept and hence trigger this attack. All OpenSSL 1.1.1 and 1.0.2 versions are affected by this issue. Other OpenSSL releases are out of support and have not been checked. Fixed in OpenSSL 1.1.1i (Affected 1.1.1-1.1.1h). Fixed in OpenSSL 1.0.2x (Affected 1.0.2-1.0.2w).

- [https://github.com/MBHudson/CVE-2020-1971](https://github.com/MBHudson/CVE-2020-1971) :  ![starts](https://img.shields.io/github/stars/MBHudson/CVE-2020-1971.svg) ![forks](https://img.shields.io/github/forks/MBHudson/CVE-2020-1971.svg)
- [https://github.com/Metztli/debian-openssl-1.1.1i](https://github.com/Metztli/debian-openssl-1.1.1i) :  ![starts](https://img.shields.io/github/stars/Metztli/debian-openssl-1.1.1i.svg) ![forks](https://img.shields.io/github/forks/Metztli/debian-openssl-1.1.1i.svg)


## CVE-2020-1967
 Server or client applications that call the SSL_check_chain() function during or after a TLS 1.3 handshake may crash due to a NULL pointer dereference as a result of incorrect handling of the &quot;signature_algorithms_cert&quot; TLS extension. The crash occurs if an invalid or unrecognised signature algorithm is received from the peer. This could be exploited by a malicious peer in a Denial of Service attack. OpenSSL version 1.1.1d, 1.1.1e, and 1.1.1f are affected by this issue. This issue did not affect OpenSSL versions prior to 1.1.1d. Fixed in OpenSSL 1.1.1g (Affected 1.1.1d-1.1.1f).

- [https://github.com/irsl/CVE-2020-1967](https://github.com/irsl/CVE-2020-1967) :  ![starts](https://img.shields.io/github/stars/irsl/CVE-2020-1967.svg) ![forks](https://img.shields.io/github/forks/irsl/CVE-2020-1967.svg)


## CVE-2020-1958
 When LDAP authentication is enabled in Apache Druid 0.17.0, callers of Druid APIs with a valid set of LDAP credentials can bypass the credentialsValidator.userSearch filter barrier that determines if a valid LDAP user is allowed to authenticate with Druid. They are still subject to role-based authorization checks, if configured. Callers of Druid APIs can also retrieve any LDAP attribute values of users that exist on the LDAP server, so long as that information is visible to the Druid server. This information disclosure does not require the caller itself to be a valid LDAP user.

- [https://github.com/ggolawski/CVE-2020-1958](https://github.com/ggolawski/CVE-2020-1958) :  ![starts](https://img.shields.io/github/stars/ggolawski/CVE-2020-1958.svg) ![forks](https://img.shields.io/github/forks/ggolawski/CVE-2020-1958.svg)


## CVE-2020-1956
 Apache Kylin 2.3.0, and releases up to 2.6.5 and 3.0.1 has some restful apis which will concatenate os command with the user input string, a user is likely to be able to execute any os command without any protection or validation.

- [https://github.com/b510/CVE-2020-1956](https://github.com/b510/CVE-2020-1956) :  ![starts](https://img.shields.io/github/stars/b510/CVE-2020-1956.svg) ![forks](https://img.shields.io/github/forks/b510/CVE-2020-1956.svg)


## CVE-2020-1948
 This vulnerability can affect all Dubbo users stay on version 2.7.6 or lower. An attacker can send RPC requests with unrecognized service name or method name along with some malicious parameter payloads. When the malicious parameter is deserialized, it will execute some malicious code. More details can be found below.

- [https://github.com/DSO-Lab/defvul](https://github.com/DSO-Lab/defvul) :  ![starts](https://img.shields.io/github/stars/DSO-Lab/defvul.svg) ![forks](https://img.shields.io/github/forks/DSO-Lab/defvul.svg)
- [https://github.com/ctlyz123/CVE-2020-1948](https://github.com/ctlyz123/CVE-2020-1948) :  ![starts](https://img.shields.io/github/stars/ctlyz123/CVE-2020-1948.svg) ![forks](https://img.shields.io/github/forks/ctlyz123/CVE-2020-1948.svg)
- [https://github.com/L0kiii/Dubbo-deserialization](https://github.com/L0kiii/Dubbo-deserialization) :  ![starts](https://img.shields.io/github/stars/L0kiii/Dubbo-deserialization.svg) ![forks](https://img.shields.io/github/forks/L0kiii/Dubbo-deserialization.svg)
- [https://github.com/txrw/Dubbo-CVE-2020-1948](https://github.com/txrw/Dubbo-CVE-2020-1948) :  ![starts](https://img.shields.io/github/stars/txrw/Dubbo-CVE-2020-1948.svg) ![forks](https://img.shields.io/github/forks/txrw/Dubbo-CVE-2020-1948.svg)
- [https://github.com/M3g4Byt3/cve-2020-1948-poc](https://github.com/M3g4Byt3/cve-2020-1948-poc) :  ![starts](https://img.shields.io/github/stars/M3g4Byt3/cve-2020-1948-poc.svg) ![forks](https://img.shields.io/github/forks/M3g4Byt3/cve-2020-1948-poc.svg)


## CVE-2020-1947
 In Apache ShardingSphere(incubator) 4.0.0-RC3 and 4.0.0, the ShardingSphere's web console uses the SnakeYAML library for parsing YAML inputs to load datasource configuration. SnakeYAML allows to unmarshal data to a Java type By using the YAML tag. Unmarshalling untrusted data can lead to security flaws of RCE.

- [https://github.com/jas502n/CVE-2020-1947](https://github.com/jas502n/CVE-2020-1947) :  ![starts](https://img.shields.io/github/stars/jas502n/CVE-2020-1947.svg) ![forks](https://img.shields.io/github/forks/jas502n/CVE-2020-1947.svg)
- [https://github.com/wsfengfan/CVE-2020-1947](https://github.com/wsfengfan/CVE-2020-1947) :  ![starts](https://img.shields.io/github/stars/wsfengfan/CVE-2020-1947.svg) ![forks](https://img.shields.io/github/forks/wsfengfan/CVE-2020-1947.svg)
- [https://github.com/shadowsock5/ShardingSphere_CVE-2020-1947](https://github.com/shadowsock5/ShardingSphere_CVE-2020-1947) :  ![starts](https://img.shields.io/github/stars/shadowsock5/ShardingSphere_CVE-2020-1947.svg) ![forks](https://img.shields.io/github/forks/shadowsock5/ShardingSphere_CVE-2020-1947.svg)
- [https://github.com/EdwardChristmas/CVE-2020-1947](https://github.com/EdwardChristmas/CVE-2020-1947) :  ![starts](https://img.shields.io/github/stars/EdwardChristmas/CVE-2020-1947.svg) ![forks](https://img.shields.io/github/forks/EdwardChristmas/CVE-2020-1947.svg)
- [https://github.com/5l1v3r1/CVE-2020-1947](https://github.com/5l1v3r1/CVE-2020-1947) :  ![starts](https://img.shields.io/github/stars/5l1v3r1/CVE-2020-1947.svg) ![forks](https://img.shields.io/github/forks/5l1v3r1/CVE-2020-1947.svg)


## CVE-2020-1938
 When using the Apache JServ Protocol (AJP), care must be taken when trusting incoming connections to Apache Tomcat. Tomcat treats AJP connections as having higher trust than, for example, a similar HTTP connection. If such connections are available to an attacker, they can be exploited in ways that may be surprising. In Apache Tomcat 9.0.0.M1 to 9.0.0.30, 8.5.0 to 8.5.50 and 7.0.0 to 7.0.99, Tomcat shipped with an AJP Connector enabled by default that listened on all configured IP addresses. It was expected (and recommended in the security guide) that this Connector would be disabled if not required. This vulnerability report identified a mechanism that allowed: - returning arbitrary files from anywhere in the web application - processing any file in the web application as a JSP Further, if the web application allowed file upload and stored those files within the web application (or the attacker was able to control the content of the web application by some other means) then this, along with the ability to process a file as a JSP, made remote code execution possible. It is important to note that mitigation is only required if an AJP port is accessible to untrusted users. Users wishing to take a defence-in-depth approach and block the vector that permits returning arbitrary files and execution as JSP may upgrade to Apache Tomcat 9.0.31, 8.5.51 or 7.0.100 or later. A number of changes were made to the default AJP Connector configuration in 9.0.31 to harden the default configuration. It is likely that users upgrading to 9.0.31, 8.5.51 or 7.0.100 or later will need to make small changes to their configurations.

- [https://github.com/zhzyker/exphub](https://github.com/zhzyker/exphub) :  ![starts](https://img.shields.io/github/stars/zhzyker/exphub.svg) ![forks](https://img.shields.io/github/forks/zhzyker/exphub.svg)
- [https://github.com/LandGrey/ClassHound](https://github.com/LandGrey/ClassHound) :  ![starts](https://img.shields.io/github/stars/LandGrey/ClassHound.svg) ![forks](https://img.shields.io/github/forks/LandGrey/ClassHound.svg)
- [https://github.com/hypn0s/AJPy](https://github.com/hypn0s/AJPy) :  ![starts](https://img.shields.io/github/stars/hypn0s/AJPy.svg) ![forks](https://img.shields.io/github/forks/hypn0s/AJPy.svg)
- [https://github.com/00theway/Ghostcat-CNVD-2020-10487](https://github.com/00theway/Ghostcat-CNVD-2020-10487) :  ![starts](https://img.shields.io/github/stars/00theway/Ghostcat-CNVD-2020-10487.svg) ![forks](https://img.shields.io/github/forks/00theway/Ghostcat-CNVD-2020-10487.svg)
- [https://github.com/bkfish/CNVD-2020-10487-Tomcat-Ajp-lfi-Scanner](https://github.com/bkfish/CNVD-2020-10487-Tomcat-Ajp-lfi-Scanner) :  ![starts](https://img.shields.io/github/stars/bkfish/CNVD-2020-10487-Tomcat-Ajp-lfi-Scanner.svg) ![forks](https://img.shields.io/github/forks/bkfish/CNVD-2020-10487-Tomcat-Ajp-lfi-Scanner.svg)
- [https://github.com/tpt11fb/AttackTomcat](https://github.com/tpt11fb/AttackTomcat) :  ![starts](https://img.shields.io/github/stars/tpt11fb/AttackTomcat.svg) ![forks](https://img.shields.io/github/forks/tpt11fb/AttackTomcat.svg)
- [https://github.com/nibiwodong/CNVD-2020-10487-Tomcat-ajp-POC](https://github.com/nibiwodong/CNVD-2020-10487-Tomcat-ajp-POC) :  ![starts](https://img.shields.io/github/stars/nibiwodong/CNVD-2020-10487-Tomcat-ajp-POC.svg) ![forks](https://img.shields.io/github/forks/nibiwodong/CNVD-2020-10487-Tomcat-ajp-POC.svg)
- [https://github.com/sv3nbeast/CVE-2020-1938-Tomact-file_include-file_read](https://github.com/sv3nbeast/CVE-2020-1938-Tomact-file_include-file_read) :  ![starts](https://img.shields.io/github/stars/sv3nbeast/CVE-2020-1938-Tomact-file_include-file_read.svg) ![forks](https://img.shields.io/github/forks/sv3nbeast/CVE-2020-1938-Tomact-file_include-file_read.svg)
- [https://github.com/xindongzhuaizhuai/CVE-2020-1938](https://github.com/xindongzhuaizhuai/CVE-2020-1938) :  ![starts](https://img.shields.io/github/stars/xindongzhuaizhuai/CVE-2020-1938.svg) ![forks](https://img.shields.io/github/forks/xindongzhuaizhuai/CVE-2020-1938.svg)
- [https://github.com/laolisafe/CVE-2020-1938](https://github.com/laolisafe/CVE-2020-1938) :  ![starts](https://img.shields.io/github/stars/laolisafe/CVE-2020-1938.svg) ![forks](https://img.shields.io/github/forks/laolisafe/CVE-2020-1938.svg)
- [https://github.com/woaiqiukui/CVE-2020-1938TomcatAjpScanner](https://github.com/woaiqiukui/CVE-2020-1938TomcatAjpScanner) :  ![starts](https://img.shields.io/github/stars/woaiqiukui/CVE-2020-1938TomcatAjpScanner.svg) ![forks](https://img.shields.io/github/forks/woaiqiukui/CVE-2020-1938TomcatAjpScanner.svg)
- [https://github.com/ze0r/GhostCat-LFI-exp](https://github.com/ze0r/GhostCat-LFI-exp) :  ![starts](https://img.shields.io/github/stars/ze0r/GhostCat-LFI-exp.svg) ![forks](https://img.shields.io/github/forks/ze0r/GhostCat-LFI-exp.svg)
- [https://github.com/fairyming/CVE-2020-1938](https://github.com/fairyming/CVE-2020-1938) :  ![starts](https://img.shields.io/github/stars/fairyming/CVE-2020-1938.svg) ![forks](https://img.shields.io/github/forks/fairyming/CVE-2020-1938.svg)
- [https://github.com/doggycheng/CNVD-2020-10487](https://github.com/doggycheng/CNVD-2020-10487) :  ![starts](https://img.shields.io/github/stars/doggycheng/CNVD-2020-10487.svg) ![forks](https://img.shields.io/github/forks/doggycheng/CNVD-2020-10487.svg)
- [https://github.com/dacade/CVE-2020-1938](https://github.com/dacade/CVE-2020-1938) :  ![starts](https://img.shields.io/github/stars/dacade/CVE-2020-1938.svg) ![forks](https://img.shields.io/github/forks/dacade/CVE-2020-1938.svg)
- [https://github.com/Hancheng-Lei/Hacking-Vulnerability-CVE-2020-1938-Ghostcat](https://github.com/Hancheng-Lei/Hacking-Vulnerability-CVE-2020-1938-Ghostcat) :  ![starts](https://img.shields.io/github/stars/Hancheng-Lei/Hacking-Vulnerability-CVE-2020-1938-Ghostcat.svg) ![forks](https://img.shields.io/github/forks/Hancheng-Lei/Hacking-Vulnerability-CVE-2020-1938-Ghostcat.svg)
- [https://github.com/fatal0/tomcat-cve-2020-1938-check](https://github.com/fatal0/tomcat-cve-2020-1938-check) :  ![starts](https://img.shields.io/github/stars/fatal0/tomcat-cve-2020-1938-check.svg) ![forks](https://img.shields.io/github/forks/fatal0/tomcat-cve-2020-1938-check.svg)
- [https://github.com/w4fz5uck5/CVE-2020-1938-Clean-Version](https://github.com/w4fz5uck5/CVE-2020-1938-Clean-Version) :  ![starts](https://img.shields.io/github/stars/w4fz5uck5/CVE-2020-1938-Clean-Version.svg) ![forks](https://img.shields.io/github/forks/w4fz5uck5/CVE-2020-1938-Clean-Version.svg)
- [https://github.com/Just1ceP4rtn3r/CVE-2020-1938-Tool](https://github.com/Just1ceP4rtn3r/CVE-2020-1938-Tool) :  ![starts](https://img.shields.io/github/stars/Just1ceP4rtn3r/CVE-2020-1938-Tool.svg) ![forks](https://img.shields.io/github/forks/Just1ceP4rtn3r/CVE-2020-1938-Tool.svg)
- [https://github.com/YounesTasra-R4z3rSw0rd/CVE-2020-1938](https://github.com/YounesTasra-R4z3rSw0rd/CVE-2020-1938) :  ![starts](https://img.shields.io/github/stars/YounesTasra-R4z3rSw0rd/CVE-2020-1938.svg) ![forks](https://img.shields.io/github/forks/YounesTasra-R4z3rSw0rd/CVE-2020-1938.svg)
- [https://github.com/h7hac9/CVE-2020-1938](https://github.com/h7hac9/CVE-2020-1938) :  ![starts](https://img.shields.io/github/stars/h7hac9/CVE-2020-1938.svg) ![forks](https://img.shields.io/github/forks/h7hac9/CVE-2020-1938.svg)
- [https://github.com/delsadan/CNVD-2020-10487-Bulk-verification](https://github.com/delsadan/CNVD-2020-10487-Bulk-verification) :  ![starts](https://img.shields.io/github/stars/delsadan/CNVD-2020-10487-Bulk-verification.svg) ![forks](https://img.shields.io/github/forks/delsadan/CNVD-2020-10487-Bulk-verification.svg)
- [https://github.com/sgdream/CVE-2020-1938](https://github.com/sgdream/CVE-2020-1938) :  ![starts](https://img.shields.io/github/stars/sgdream/CVE-2020-1938.svg) ![forks](https://img.shields.io/github/forks/sgdream/CVE-2020-1938.svg)
- [https://github.com/shaunmclernon/ghostcat-verification](https://github.com/shaunmclernon/ghostcat-verification) :  ![starts](https://img.shields.io/github/stars/shaunmclernon/ghostcat-verification.svg) ![forks](https://img.shields.io/github/forks/shaunmclernon/ghostcat-verification.svg)
- [https://github.com/Umesh2807/Ghostcat](https://github.com/Umesh2807/Ghostcat) :  ![starts](https://img.shields.io/github/stars/Umesh2807/Ghostcat.svg) ![forks](https://img.shields.io/github/forks/Umesh2807/Ghostcat.svg)
- [https://github.com/Warelock/cve-2020-1938](https://github.com/Warelock/cve-2020-1938) :  ![starts](https://img.shields.io/github/stars/Warelock/cve-2020-1938.svg) ![forks](https://img.shields.io/github/forks/Warelock/cve-2020-1938.svg)
- [https://github.com/Neko-chanQwQ/CVE-2020-1938](https://github.com/Neko-chanQwQ/CVE-2020-1938) :  ![starts](https://img.shields.io/github/stars/Neko-chanQwQ/CVE-2020-1938.svg) ![forks](https://img.shields.io/github/forks/Neko-chanQwQ/CVE-2020-1938.svg)
- [https://github.com/streghstreek/CVE-2020-1938](https://github.com/streghstreek/CVE-2020-1938) :  ![starts](https://img.shields.io/github/stars/streghstreek/CVE-2020-1938.svg) ![forks](https://img.shields.io/github/forks/streghstreek/CVE-2020-1938.svg)
- [https://github.com/einzbernnn/CVE-2020-1938Scan](https://github.com/einzbernnn/CVE-2020-1938Scan) :  ![starts](https://img.shields.io/github/stars/einzbernnn/CVE-2020-1938Scan.svg) ![forks](https://img.shields.io/github/forks/einzbernnn/CVE-2020-1938Scan.svg)
- [https://github.com/jptr218/ghostcat](https://github.com/jptr218/ghostcat) :  ![starts](https://img.shields.io/github/stars/jptr218/ghostcat.svg) ![forks](https://img.shields.io/github/forks/jptr218/ghostcat.svg)
- [https://github.com/haerin7427/CVE_2020_1938](https://github.com/haerin7427/CVE_2020_1938) :  ![starts](https://img.shields.io/github/stars/haerin7427/CVE_2020_1938.svg) ![forks](https://img.shields.io/github/forks/haerin7427/CVE_2020_1938.svg)
- [https://github.com/I-Runtime-Error/CVE-2020-1938](https://github.com/I-Runtime-Error/CVE-2020-1938) :  ![starts](https://img.shields.io/github/stars/I-Runtime-Error/CVE-2020-1938.svg) ![forks](https://img.shields.io/github/forks/I-Runtime-Error/CVE-2020-1938.svg)
- [https://github.com/b1cat/CVE_2020_1938_ajp_poc](https://github.com/b1cat/CVE_2020_1938_ajp_poc) :  ![starts](https://img.shields.io/github/stars/b1cat/CVE_2020_1938_ajp_poc.svg) ![forks](https://img.shields.io/github/forks/b1cat/CVE_2020_1938_ajp_poc.svg)
- [https://github.com/Zaziki1337/Ghostcat-CVE-2020-1938](https://github.com/Zaziki1337/Ghostcat-CVE-2020-1938) :  ![starts](https://img.shields.io/github/stars/Zaziki1337/Ghostcat-CVE-2020-1938.svg) ![forks](https://img.shields.io/github/forks/Zaziki1337/Ghostcat-CVE-2020-1938.svg)
- [https://github.com/acodervic/CVE-2020-1938-MSF-MODULE](https://github.com/acodervic/CVE-2020-1938-MSF-MODULE) :  ![starts](https://img.shields.io/github/stars/acodervic/CVE-2020-1938-MSF-MODULE.svg) ![forks](https://img.shields.io/github/forks/acodervic/CVE-2020-1938-MSF-MODULE.svg)
- [https://github.com/MateoSec/ghostcatch](https://github.com/MateoSec/ghostcatch) :  ![starts](https://img.shields.io/github/stars/MateoSec/ghostcatch.svg) ![forks](https://img.shields.io/github/forks/MateoSec/ghostcatch.svg)


## CVE-2020-1937
 Kylin has some restful apis which will concatenate SQLs with the user input string, a user is likely to be able to run malicious database queries.

- [https://github.com/shanika04/apache_kylin](https://github.com/shanika04/apache_kylin) :  ![starts](https://img.shields.io/github/stars/shanika04/apache_kylin.svg) ![forks](https://img.shields.io/github/forks/shanika04/apache_kylin.svg)


## CVE-2020-1764
 A hard-coded cryptographic key vulnerability in the default configuration file was found in Kiali, all versions prior to 1.15.1. A remote attacker could abuse this flaw by creating their own JWT signed tokens and bypass Kiali authentication mechanisms, possibly gaining privileges to view and alter the Istio configuration.

- [https://github.com/jpts/cve-2020-1764-poc](https://github.com/jpts/cve-2020-1764-poc) :  ![starts](https://img.shields.io/github/stars/jpts/cve-2020-1764-poc.svg) ![forks](https://img.shields.io/github/forks/jpts/cve-2020-1764-poc.svg)


## CVE-2020-1611
 A Local File Inclusion vulnerability in Juniper Networks Junos Space allows an attacker to view all files on the target when the device receives malicious HTTP packets. This issue affects: Juniper Networks Junos Space versions prior to 19.4R1.

- [https://github.com/Ibonok/CVE-2020-1611](https://github.com/Ibonok/CVE-2020-1611) :  ![starts](https://img.shields.io/github/stars/Ibonok/CVE-2020-1611.svg) ![forks](https://img.shields.io/github/forks/Ibonok/CVE-2020-1611.svg)


## CVE-2020-1493
 An information disclosure vulnerability exists when attaching files to Outlook messages. This vulnerability could potentially allow users to share attached files such that they are accessible by anonymous users where they should be restricted to specific users. To exploit this vulnerability, an attacker would have to attach a file as a link to an email. The email could then be shared with individuals that should not have access to the files, ignoring the default organizational setting. The security update addresses the vulnerability by correcting how Outlook handles file attachment links.

- [https://github.com/0neb1n/CVE-2020-1493](https://github.com/0neb1n/CVE-2020-1493) :  ![starts](https://img.shields.io/github/stars/0neb1n/CVE-2020-1493.svg) ![forks](https://img.shields.io/github/forks/0neb1n/CVE-2020-1493.svg)


## CVE-2020-1481
 A remote code execution vulnerability exists in the ESLint extension for Visual Studio Code when it validates source code after opening a project, aka 'Visual Studio Code ESLint Extention Remote Code Execution Vulnerability'.

- [https://github.com/Rival420/CVE-2020-14181](https://github.com/Rival420/CVE-2020-14181) :  ![starts](https://img.shields.io/github/stars/Rival420/CVE-2020-14181.svg) ![forks](https://img.shields.io/github/forks/Rival420/CVE-2020-14181.svg)


## CVE-2020-1472
 An elevation of privilege vulnerability exists when an attacker establishes a vulnerable Netlogon secure channel connection to a domain controller, using the Netlogon Remote Protocol (MS-NRPC). An attacker who successfully exploited the vulnerability could run a specially crafted application on a device on the network. To exploit the vulnerability, an unauthenticated attacker would be required to use MS-NRPC to connect to a domain controller to obtain domain administrator access. Microsoft is addressing the vulnerability in a phased two-part rollout. These updates address the vulnerability by modifying how Netlogon handles the usage of Netlogon secure channels. For guidelines on how to manage the changes required for this vulnerability and more information on the phased rollout, see How to manage the changes in Netlogon secure channel connections associated with CVE-2020-1472 (updated September 28, 2020). When the second phase of Windows updates become available in Q1 2021, customers will be notified via a revision to this security vulnerability. If you wish to be notified when these updates are released, we recommend that you register for the security notifications mailer to be alerted of content changes to this advisory. See Microsoft Technical Security Notifications.

- [https://github.com/SecuraBV/CVE-2020-1472](https://github.com/SecuraBV/CVE-2020-1472) :  ![starts](https://img.shields.io/github/stars/SecuraBV/CVE-2020-1472.svg) ![forks](https://img.shields.io/github/forks/SecuraBV/CVE-2020-1472.svg)
- [https://github.com/dirkjanm/CVE-2020-1472](https://github.com/dirkjanm/CVE-2020-1472) :  ![starts](https://img.shields.io/github/stars/dirkjanm/CVE-2020-1472.svg) ![forks](https://img.shields.io/github/forks/dirkjanm/CVE-2020-1472.svg)
- [https://github.com/risksense/zerologon](https://github.com/risksense/zerologon) :  ![starts](https://img.shields.io/github/stars/risksense/zerologon.svg) ![forks](https://img.shields.io/github/forks/risksense/zerologon.svg)
- [https://github.com/VoidSec/CVE-2020-1472](https://github.com/VoidSec/CVE-2020-1472) :  ![starts](https://img.shields.io/github/stars/VoidSec/CVE-2020-1472.svg) ![forks](https://img.shields.io/github/forks/VoidSec/CVE-2020-1472.svg)
- [https://github.com/bb00/zer0dump](https://github.com/bb00/zer0dump) :  ![starts](https://img.shields.io/github/stars/bb00/zer0dump.svg) ![forks](https://img.shields.io/github/forks/bb00/zer0dump.svg)
- [https://github.com/mstxq17/cve-2020-1472](https://github.com/mstxq17/cve-2020-1472) :  ![starts](https://img.shields.io/github/stars/mstxq17/cve-2020-1472.svg) ![forks](https://img.shields.io/github/forks/mstxq17/cve-2020-1472.svg)
- [https://github.com/Rvn0xsy/ZeroLogon](https://github.com/Rvn0xsy/ZeroLogon) :  ![starts](https://img.shields.io/github/stars/Rvn0xsy/ZeroLogon.svg) ![forks](https://img.shields.io/github/forks/Rvn0xsy/ZeroLogon.svg)
- [https://github.com/k8gege/CVE-2020-1472-EXP](https://github.com/k8gege/CVE-2020-1472-EXP) :  ![starts](https://img.shields.io/github/stars/k8gege/CVE-2020-1472-EXP.svg) ![forks](https://img.shields.io/github/forks/k8gege/CVE-2020-1472-EXP.svg)
- [https://github.com/zeronetworks/zerologon](https://github.com/zeronetworks/zerologon) :  ![starts](https://img.shields.io/github/stars/zeronetworks/zerologon.svg) ![forks](https://img.shields.io/github/forks/zeronetworks/zerologon.svg)
- [https://github.com/cube0x0/CVE-2020-1472](https://github.com/cube0x0/CVE-2020-1472) :  ![starts](https://img.shields.io/github/stars/cube0x0/CVE-2020-1472.svg) ![forks](https://img.shields.io/github/forks/cube0x0/CVE-2020-1472.svg)
- [https://github.com/Privia-Security/ADZero](https://github.com/Privia-Security/ADZero) :  ![starts](https://img.shields.io/github/stars/Privia-Security/ADZero.svg) ![forks](https://img.shields.io/github/forks/Privia-Security/ADZero.svg)
- [https://github.com/sho-luv/zerologon](https://github.com/sho-luv/zerologon) :  ![starts](https://img.shields.io/github/stars/sho-luv/zerologon.svg) ![forks](https://img.shields.io/github/forks/sho-luv/zerologon.svg)
- [https://github.com/NickSanzotta/zeroscan](https://github.com/NickSanzotta/zeroscan) :  ![starts](https://img.shields.io/github/stars/NickSanzotta/zeroscan.svg) ![forks](https://img.shields.io/github/forks/NickSanzotta/zeroscan.svg)
- [https://github.com/sv3nbeast/CVE-2020-1472](https://github.com/sv3nbeast/CVE-2020-1472) :  ![starts](https://img.shields.io/github/stars/sv3nbeast/CVE-2020-1472.svg) ![forks](https://img.shields.io/github/forks/sv3nbeast/CVE-2020-1472.svg)
- [https://github.com/WiIs0n/Zerologon_CVE-2020-1472](https://github.com/WiIs0n/Zerologon_CVE-2020-1472) :  ![starts](https://img.shields.io/github/stars/WiIs0n/Zerologon_CVE-2020-1472.svg) ![forks](https://img.shields.io/github/forks/WiIs0n/Zerologon_CVE-2020-1472.svg)
- [https://github.com/YossiSassi/ZeroLogon-Exploitation-Check](https://github.com/YossiSassi/ZeroLogon-Exploitation-Check) :  ![starts](https://img.shields.io/github/stars/YossiSassi/ZeroLogon-Exploitation-Check.svg) ![forks](https://img.shields.io/github/forks/YossiSassi/ZeroLogon-Exploitation-Check.svg)
- [https://github.com/thatonesecguy/zerologon-CVE-2020-1472](https://github.com/thatonesecguy/zerologon-CVE-2020-1472) :  ![starts](https://img.shields.io/github/stars/thatonesecguy/zerologon-CVE-2020-1472.svg) ![forks](https://img.shields.io/github/forks/thatonesecguy/zerologon-CVE-2020-1472.svg)
- [https://github.com/CPO-EH/CVE-2020-1472_ZeroLogonChecker](https://github.com/CPO-EH/CVE-2020-1472_ZeroLogonChecker) :  ![starts](https://img.shields.io/github/stars/CPO-EH/CVE-2020-1472_ZeroLogonChecker.svg) ![forks](https://img.shields.io/github/forks/CPO-EH/CVE-2020-1472_ZeroLogonChecker.svg)
- [https://github.com/striveben/CVE-2020-1472](https://github.com/striveben/CVE-2020-1472) :  ![starts](https://img.shields.io/github/stars/striveben/CVE-2020-1472.svg) ![forks](https://img.shields.io/github/forks/striveben/CVE-2020-1472.svg)
- [https://github.com/CanciuCostin/CVE-2020-1472](https://github.com/CanciuCostin/CVE-2020-1472) :  ![starts](https://img.shields.io/github/stars/CanciuCostin/CVE-2020-1472.svg) ![forks](https://img.shields.io/github/forks/CanciuCostin/CVE-2020-1472.svg)
- [https://github.com/0xcccc666/cve-2020-1472_Tool-collection](https://github.com/0xcccc666/cve-2020-1472_Tool-collection) :  ![starts](https://img.shields.io/github/stars/0xcccc666/cve-2020-1472_Tool-collection.svg) ![forks](https://img.shields.io/github/forks/0xcccc666/cve-2020-1472_Tool-collection.svg)
- [https://github.com/murataydemir/CVE-2020-1472](https://github.com/murataydemir/CVE-2020-1472) :  ![starts](https://img.shields.io/github/stars/murataydemir/CVE-2020-1472.svg) ![forks](https://img.shields.io/github/forks/murataydemir/CVE-2020-1472.svg)
- [https://github.com/0xkami/CVE-2020-1472](https://github.com/0xkami/CVE-2020-1472) :  ![starts](https://img.shields.io/github/stars/0xkami/CVE-2020-1472.svg) ![forks](https://img.shields.io/github/forks/0xkami/CVE-2020-1472.svg)
- [https://github.com/Udyz/Zerologon](https://github.com/Udyz/Zerologon) :  ![starts](https://img.shields.io/github/stars/Udyz/Zerologon.svg) ![forks](https://img.shields.io/github/forks/Udyz/Zerologon.svg)
- [https://github.com/NAXG/CVE-2020-1472](https://github.com/NAXG/CVE-2020-1472) :  ![starts](https://img.shields.io/github/stars/NAXG/CVE-2020-1472.svg) ![forks](https://img.shields.io/github/forks/NAXG/CVE-2020-1472.svg)
- [https://github.com/npocmak/CVE-2020-1472](https://github.com/npocmak/CVE-2020-1472) :  ![starts](https://img.shields.io/github/stars/npocmak/CVE-2020-1472.svg) ![forks](https://img.shields.io/github/forks/npocmak/CVE-2020-1472.svg)
- [https://github.com/Akash7350/CVE-2020-1472](https://github.com/Akash7350/CVE-2020-1472) :  ![starts](https://img.shields.io/github/stars/Akash7350/CVE-2020-1472.svg) ![forks](https://img.shields.io/github/forks/Akash7350/CVE-2020-1472.svg)
- [https://github.com/shanfenglan/cve-2020-1472](https://github.com/shanfenglan/cve-2020-1472) :  ![starts](https://img.shields.io/github/stars/shanfenglan/cve-2020-1472.svg) ![forks](https://img.shields.io/github/forks/shanfenglan/cve-2020-1472.svg)
- [https://github.com/McKinnonIT/zabbix-template-CVE-2020-1472](https://github.com/McKinnonIT/zabbix-template-CVE-2020-1472) :  ![starts](https://img.shields.io/github/stars/McKinnonIT/zabbix-template-CVE-2020-1472.svg) ![forks](https://img.shields.io/github/forks/McKinnonIT/zabbix-template-CVE-2020-1472.svg)
- [https://github.com/rhymeswithmogul/Set-ZerologonMitigation](https://github.com/rhymeswithmogul/Set-ZerologonMitigation) :  ![starts](https://img.shields.io/github/stars/rhymeswithmogul/Set-ZerologonMitigation.svg) ![forks](https://img.shields.io/github/forks/rhymeswithmogul/Set-ZerologonMitigation.svg)
- [https://github.com/RicYaben/CVE-2020-1472-LAB](https://github.com/RicYaben/CVE-2020-1472-LAB) :  ![starts](https://img.shields.io/github/stars/RicYaben/CVE-2020-1472-LAB.svg) ![forks](https://img.shields.io/github/forks/RicYaben/CVE-2020-1472-LAB.svg)
- [https://github.com/Sajuwithgithub/CVE2020-1472](https://github.com/Sajuwithgithub/CVE2020-1472) :  ![starts](https://img.shields.io/github/stars/Sajuwithgithub/CVE2020-1472.svg) ![forks](https://img.shields.io/github/forks/Sajuwithgithub/CVE2020-1472.svg)
- [https://github.com/jiushill/CVE-2020-1472](https://github.com/jiushill/CVE-2020-1472) :  ![starts](https://img.shields.io/github/stars/jiushill/CVE-2020-1472.svg) ![forks](https://img.shields.io/github/forks/jiushill/CVE-2020-1472.svg)
- [https://github.com/Fa1c0n35/CVE-2020-1472](https://github.com/Fa1c0n35/CVE-2020-1472) :  ![starts](https://img.shields.io/github/stars/Fa1c0n35/CVE-2020-1472.svg) ![forks](https://img.shields.io/github/forks/Fa1c0n35/CVE-2020-1472.svg)
- [https://github.com/b1ack0wl/CVE-2020-1472](https://github.com/b1ack0wl/CVE-2020-1472) :  ![starts](https://img.shields.io/github/stars/b1ack0wl/CVE-2020-1472.svg) ![forks](https://img.shields.io/github/forks/b1ack0wl/CVE-2020-1472.svg)
- [https://github.com/victim10wq3/CVE-2020-1472](https://github.com/victim10wq3/CVE-2020-1472) :  ![starts](https://img.shields.io/github/stars/victim10wq3/CVE-2020-1472.svg) ![forks](https://img.shields.io/github/forks/victim10wq3/CVE-2020-1472.svg)
- [https://github.com/mingchen-script/CVE-2020-1472-visualizer](https://github.com/mingchen-script/CVE-2020-1472-visualizer) :  ![starts](https://img.shields.io/github/stars/mingchen-script/CVE-2020-1472-visualizer.svg) ![forks](https://img.shields.io/github/forks/mingchen-script/CVE-2020-1472-visualizer.svg)
- [https://github.com/midpipps/CVE-2020-1472-Easy](https://github.com/midpipps/CVE-2020-1472-Easy) :  ![starts](https://img.shields.io/github/stars/midpipps/CVE-2020-1472-Easy.svg) ![forks](https://img.shields.io/github/forks/midpipps/CVE-2020-1472-Easy.svg)
- [https://github.com/Fa1c0n35/SecuraBV-CVE-2020-1472](https://github.com/Fa1c0n35/SecuraBV-CVE-2020-1472) :  ![starts](https://img.shields.io/github/stars/Fa1c0n35/SecuraBV-CVE-2020-1472.svg) ![forks](https://img.shields.io/github/forks/Fa1c0n35/SecuraBV-CVE-2020-1472.svg)
- [https://github.com/whoami-chmod777/Zerologon-Attack-CVE-2020-1472-POC](https://github.com/whoami-chmod777/Zerologon-Attack-CVE-2020-1472-POC) :  ![starts](https://img.shields.io/github/stars/whoami-chmod777/Zerologon-Attack-CVE-2020-1472-POC.svg) ![forks](https://img.shields.io/github/forks/whoami-chmod777/Zerologon-Attack-CVE-2020-1472-POC.svg)
- [https://github.com/guglia001/MassZeroLogon](https://github.com/guglia001/MassZeroLogon) :  ![starts](https://img.shields.io/github/stars/guglia001/MassZeroLogon.svg) ![forks](https://img.shields.io/github/forks/guglia001/MassZeroLogon.svg)
- [https://github.com/wrathfulDiety/zerologon](https://github.com/wrathfulDiety/zerologon) :  ![starts](https://img.shields.io/github/stars/wrathfulDiety/zerologon.svg) ![forks](https://img.shields.io/github/forks/wrathfulDiety/zerologon.svg)
- [https://github.com/hell-moon/ZeroLogon-Exploit](https://github.com/hell-moon/ZeroLogon-Exploit) :  ![starts](https://img.shields.io/github/stars/hell-moon/ZeroLogon-Exploit.svg) ![forks](https://img.shields.io/github/forks/hell-moon/ZeroLogon-Exploit.svg)
- [https://github.com/Anonymous-Family/Zero-day-scanning](https://github.com/Anonymous-Family/Zero-day-scanning) :  ![starts](https://img.shields.io/github/stars/Anonymous-Family/Zero-day-scanning.svg) ![forks](https://img.shields.io/github/forks/Anonymous-Family/Zero-day-scanning.svg)
- [https://github.com/carlos55ml/zerologon](https://github.com/carlos55ml/zerologon) :  ![starts](https://img.shields.io/github/stars/carlos55ml/zerologon.svg) ![forks](https://img.shields.io/github/forks/carlos55ml/zerologon.svg)
- [https://github.com/Whippet0/CVE-2020-1472](https://github.com/Whippet0/CVE-2020-1472) :  ![starts](https://img.shields.io/github/stars/Whippet0/CVE-2020-1472.svg) ![forks](https://img.shields.io/github/forks/Whippet0/CVE-2020-1472.svg)
- [https://github.com/Anonymous-Family/CVE-2020-1472](https://github.com/Anonymous-Family/CVE-2020-1472) :  ![starts](https://img.shields.io/github/stars/Anonymous-Family/CVE-2020-1472.svg) ![forks](https://img.shields.io/github/forks/Anonymous-Family/CVE-2020-1472.svg)
- [https://github.com/puckiestyle/CVE-2020-1472](https://github.com/puckiestyle/CVE-2020-1472) :  ![starts](https://img.shields.io/github/stars/puckiestyle/CVE-2020-1472.svg) ![forks](https://img.shields.io/github/forks/puckiestyle/CVE-2020-1472.svg)
- [https://github.com/Ken-Abruzzi/cve-2020-1472](https://github.com/Ken-Abruzzi/cve-2020-1472) :  ![starts](https://img.shields.io/github/stars/Ken-Abruzzi/cve-2020-1472.svg) ![forks](https://img.shields.io/github/forks/Ken-Abruzzi/cve-2020-1472.svg)
- [https://github.com/hectorgie/CVE-2020-1472](https://github.com/hectorgie/CVE-2020-1472) :  ![starts](https://img.shields.io/github/stars/hectorgie/CVE-2020-1472.svg) ![forks](https://img.shields.io/github/forks/hectorgie/CVE-2020-1472.svg)
- [https://github.com/itssmikefm/CVE-2020-1472](https://github.com/itssmikefm/CVE-2020-1472) :  ![starts](https://img.shields.io/github/stars/itssmikefm/CVE-2020-1472.svg) ![forks](https://img.shields.io/github/forks/itssmikefm/CVE-2020-1472.svg)
- [https://github.com/mos165/CVE-20200-1472](https://github.com/mos165/CVE-20200-1472) :  ![starts](https://img.shields.io/github/stars/mos165/CVE-20200-1472.svg) ![forks](https://img.shields.io/github/forks/mos165/CVE-20200-1472.svg)
- [https://github.com/SaharAttackit/CVE-2020-1472](https://github.com/SaharAttackit/CVE-2020-1472) :  ![starts](https://img.shields.io/github/stars/SaharAttackit/CVE-2020-1472.svg) ![forks](https://img.shields.io/github/forks/SaharAttackit/CVE-2020-1472.svg)
- [https://github.com/t31m0/CVE-2020-1472](https://github.com/t31m0/CVE-2020-1472) :  ![starts](https://img.shields.io/github/stars/t31m0/CVE-2020-1472.svg) ![forks](https://img.shields.io/github/forks/t31m0/CVE-2020-1472.svg)
- [https://github.com/grupooruss/CVE-2020-1472](https://github.com/grupooruss/CVE-2020-1472) :  ![starts](https://img.shields.io/github/stars/grupooruss/CVE-2020-1472.svg) ![forks](https://img.shields.io/github/forks/grupooruss/CVE-2020-1472.svg)
- [https://github.com/dr4g0n23/CVE-2020-1472](https://github.com/dr4g0n23/CVE-2020-1472) :  ![starts](https://img.shields.io/github/stars/dr4g0n23/CVE-2020-1472.svg) ![forks](https://img.shields.io/github/forks/dr4g0n23/CVE-2020-1472.svg)
- [https://github.com/TheJoyOfHacking/dirkjanm-CVE-2020-1472](https://github.com/TheJoyOfHacking/dirkjanm-CVE-2020-1472) :  ![starts](https://img.shields.io/github/stars/TheJoyOfHacking/dirkjanm-CVE-2020-1472.svg) ![forks](https://img.shields.io/github/forks/TheJoyOfHacking/dirkjanm-CVE-2020-1472.svg)
- [https://github.com/Tobey123/CVE-2020-1472-visualizer](https://github.com/Tobey123/CVE-2020-1472-visualizer) :  ![starts](https://img.shields.io/github/stars/Tobey123/CVE-2020-1472-visualizer.svg) ![forks](https://img.shields.io/github/forks/Tobey123/CVE-2020-1472-visualizer.svg)
- [https://github.com/JolynNgSC/Zerologon_CVE-2020-1472](https://github.com/JolynNgSC/Zerologon_CVE-2020-1472) :  ![starts](https://img.shields.io/github/stars/JolynNgSC/Zerologon_CVE-2020-1472.svg) ![forks](https://img.shields.io/github/forks/JolynNgSC/Zerologon_CVE-2020-1472.svg)
- [https://github.com/Fa1c0n35/CVE-2020-1472-02-](https://github.com/Fa1c0n35/CVE-2020-1472-02-) :  ![starts](https://img.shields.io/github/stars/Fa1c0n35/CVE-2020-1472-02-.svg) ![forks](https://img.shields.io/github/forks/Fa1c0n35/CVE-2020-1472-02-.svg)
- [https://github.com/TheJoyOfHacking/SecuraBV-CVE-2020-1472](https://github.com/TheJoyOfHacking/SecuraBV-CVE-2020-1472) :  ![starts](https://img.shields.io/github/stars/TheJoyOfHacking/SecuraBV-CVE-2020-1472.svg) ![forks](https://img.shields.io/github/forks/TheJoyOfHacking/SecuraBV-CVE-2020-1472.svg)
- [https://github.com/johnpathe/zerologon-cve-2020-1472-notes](https://github.com/johnpathe/zerologon-cve-2020-1472-notes) :  ![starts](https://img.shields.io/github/stars/johnpathe/zerologon-cve-2020-1472-notes.svg) ![forks](https://img.shields.io/github/forks/johnpathe/zerologon-cve-2020-1472-notes.svg)
- [https://github.com/technion/ZeroLogonAssess](https://github.com/technion/ZeroLogonAssess) :  ![starts](https://img.shields.io/github/stars/technion/ZeroLogonAssess.svg) ![forks](https://img.shields.io/github/forks/technion/ZeroLogonAssess.svg)
- [https://github.com/logg-1/0logon](https://github.com/logg-1/0logon) :  ![starts](https://img.shields.io/github/stars/logg-1/0logon.svg) ![forks](https://img.shields.io/github/forks/logg-1/0logon.svg)
- [https://github.com/likeww/MassZeroLogon](https://github.com/likeww/MassZeroLogon) :  ![starts](https://img.shields.io/github/stars/likeww/MassZeroLogon.svg) ![forks](https://img.shields.io/github/forks/likeww/MassZeroLogon.svg)
- [https://github.com/maikelnight/zerologon](https://github.com/maikelnight/zerologon) :  ![starts](https://img.shields.io/github/stars/maikelnight/zerologon.svg) ![forks](https://img.shields.io/github/forks/maikelnight/zerologon.svg)
- [https://github.com/JayP232/The_big_Zero](https://github.com/JayP232/The_big_Zero) :  ![starts](https://img.shields.io/github/stars/JayP232/The_big_Zero.svg) ![forks](https://img.shields.io/github/forks/JayP232/The_big_Zero.svg)
- [https://github.com/botfather0x0/ZeroLogon-to-Shell](https://github.com/botfather0x0/ZeroLogon-to-Shell) :  ![starts](https://img.shields.io/github/stars/botfather0x0/ZeroLogon-to-Shell.svg) ![forks](https://img.shields.io/github/forks/botfather0x0/ZeroLogon-to-Shell.svg)


## CVE-2020-1362
 An elevation of privilege vulnerability exists in the way that the Windows WalletService handles objects in memory, aka 'Windows WalletService Elevation of Privilege Vulnerability'. This CVE ID is unique from CVE-2020-1344, CVE-2020-1369.

- [https://github.com/Al1ex/WindowsElevation](https://github.com/Al1ex/WindowsElevation) :  ![starts](https://img.shields.io/github/stars/Al1ex/WindowsElevation.svg) ![forks](https://img.shields.io/github/forks/Al1ex/WindowsElevation.svg)
- [https://github.com/Q4n/CVE-2020-1362](https://github.com/Q4n/CVE-2020-1362) :  ![starts](https://img.shields.io/github/stars/Q4n/CVE-2020-1362.svg) ![forks](https://img.shields.io/github/forks/Q4n/CVE-2020-1362.svg)


## CVE-2020-1350
 A remote code execution vulnerability exists in Windows Domain Name System servers when they fail to properly handle requests, aka 'Windows DNS Server Remote Code Execution Vulnerability'.

- [https://github.com/ZephrFish/CVE-2020-1350_HoneyPoC](https://github.com/ZephrFish/CVE-2020-1350_HoneyPoC) :  ![starts](https://img.shields.io/github/stars/ZephrFish/CVE-2020-1350_HoneyPoC.svg) ![forks](https://img.shields.io/github/forks/ZephrFish/CVE-2020-1350_HoneyPoC.svg)
- [https://github.com/maxpl0it/CVE-2020-1350-DoS](https://github.com/maxpl0it/CVE-2020-1350-DoS) :  ![starts](https://img.shields.io/github/stars/maxpl0it/CVE-2020-1350-DoS.svg) ![forks](https://img.shields.io/github/forks/maxpl0it/CVE-2020-1350-DoS.svg)
- [https://github.com/psc4re/NSE-scripts](https://github.com/psc4re/NSE-scripts) :  ![starts](https://img.shields.io/github/stars/psc4re/NSE-scripts.svg) ![forks](https://img.shields.io/github/forks/psc4re/NSE-scripts.svg)
- [https://github.com/tinkersec/cve-2020-1350](https://github.com/tinkersec/cve-2020-1350) :  ![starts](https://img.shields.io/github/stars/tinkersec/cve-2020-1350.svg) ![forks](https://img.shields.io/github/forks/tinkersec/cve-2020-1350.svg)
- [https://github.com/captainGeech42/CVE-2020-1350](https://github.com/captainGeech42/CVE-2020-1350) :  ![starts](https://img.shields.io/github/stars/captainGeech42/CVE-2020-1350.svg) ![forks](https://img.shields.io/github/forks/captainGeech42/CVE-2020-1350.svg)
- [https://github.com/T13nn3s/CVE-2020-1350](https://github.com/T13nn3s/CVE-2020-1350) :  ![starts](https://img.shields.io/github/stars/T13nn3s/CVE-2020-1350.svg) ![forks](https://img.shields.io/github/forks/T13nn3s/CVE-2020-1350.svg)
- [https://github.com/connormcgarr/CVE-2020-1350](https://github.com/connormcgarr/CVE-2020-1350) :  ![starts](https://img.shields.io/github/stars/connormcgarr/CVE-2020-1350.svg) ![forks](https://img.shields.io/github/forks/connormcgarr/CVE-2020-1350.svg)
- [https://github.com/corelight/SIGRed](https://github.com/corelight/SIGRed) :  ![starts](https://img.shields.io/github/stars/corelight/SIGRed.svg) ![forks](https://img.shields.io/github/forks/corelight/SIGRed.svg)
- [https://github.com/zoomerxsec/Fake_CVE-2020-1350](https://github.com/zoomerxsec/Fake_CVE-2020-1350) :  ![starts](https://img.shields.io/github/stars/zoomerxsec/Fake_CVE-2020-1350.svg) ![forks](https://img.shields.io/github/forks/zoomerxsec/Fake_CVE-2020-1350.svg)
- [https://github.com/mr-r3b00t/CVE-2020-1350](https://github.com/mr-r3b00t/CVE-2020-1350) :  ![starts](https://img.shields.io/github/stars/mr-r3b00t/CVE-2020-1350.svg) ![forks](https://img.shields.io/github/forks/mr-r3b00t/CVE-2020-1350.svg)
- [https://github.com/Plazmaz/CVE-2020-1350-poc](https://github.com/Plazmaz/CVE-2020-1350-poc) :  ![starts](https://img.shields.io/github/stars/Plazmaz/CVE-2020-1350-poc.svg) ![forks](https://img.shields.io/github/forks/Plazmaz/CVE-2020-1350-poc.svg)
- [https://github.com/simeononsecurity/CVE-2020-1350-Fix](https://github.com/simeononsecurity/CVE-2020-1350-Fix) :  ![starts](https://img.shields.io/github/stars/simeononsecurity/CVE-2020-1350-Fix.svg) ![forks](https://img.shields.io/github/forks/simeononsecurity/CVE-2020-1350-Fix.svg)
- [https://github.com/graph-inc/CVE-2020-1350](https://github.com/graph-inc/CVE-2020-1350) :  ![starts](https://img.shields.io/github/stars/graph-inc/CVE-2020-1350.svg) ![forks](https://img.shields.io/github/forks/graph-inc/CVE-2020-1350.svg)
- [https://github.com/jmaddington/dRMM-CVE-2020-1350-response](https://github.com/jmaddington/dRMM-CVE-2020-1350-response) :  ![starts](https://img.shields.io/github/stars/jmaddington/dRMM-CVE-2020-1350-response.svg) ![forks](https://img.shields.io/github/forks/jmaddington/dRMM-CVE-2020-1350-response.svg)
- [https://github.com/CVEmaster/CVE-2020-1350](https://github.com/CVEmaster/CVE-2020-1350) :  ![starts](https://img.shields.io/github/stars/CVEmaster/CVE-2020-1350.svg) ![forks](https://img.shields.io/github/forks/CVEmaster/CVE-2020-1350.svg)
- [https://github.com/gdwnet/cve-2020-1350](https://github.com/gdwnet/cve-2020-1350) :  ![starts](https://img.shields.io/github/stars/gdwnet/cve-2020-1350.svg) ![forks](https://img.shields.io/github/forks/gdwnet/cve-2020-1350.svg)
- [https://github.com/ejlevin99/CVE---2020---1350](https://github.com/ejlevin99/CVE---2020---1350) :  ![starts](https://img.shields.io/github/stars/ejlevin99/CVE---2020---1350.svg) ![forks](https://img.shields.io/github/forks/ejlevin99/CVE---2020---1350.svg)
- [https://github.com/5l1v3r1/CVE-2020-1350-checker.ps1](https://github.com/5l1v3r1/CVE-2020-1350-checker.ps1) :  ![starts](https://img.shields.io/github/stars/5l1v3r1/CVE-2020-1350-checker.ps1.svg) ![forks](https://img.shields.io/github/forks/5l1v3r1/CVE-2020-1350-checker.ps1.svg)


## CVE-2020-1349
 A remote code execution vulnerability exists in Microsoft Outlook software when it fails to properly handle objects in memory, aka 'Microsoft Outlook Remote Code Execution Vulnerability'.

- [https://github.com/0neb1n/CVE-2020-1349](https://github.com/0neb1n/CVE-2020-1349) :  ![starts](https://img.shields.io/github/stars/0neb1n/CVE-2020-1349.svg) ![forks](https://img.shields.io/github/forks/0neb1n/CVE-2020-1349.svg)


## CVE-2020-1337
 An elevation of privilege vulnerability exists when the Windows Print Spooler service improperly allows arbitrary writing to the file system. An attacker who successfully exploited this vulnerability could run arbitrary code with elevated system privileges. An attacker could then install programs; view, change, or delete data; or create new accounts with full user rights. To exploit this vulnerability, an attacker would have to log on to an affected system and run a specially crafted script or application. The update addresses the vulnerability by correcting how the Windows Print Spooler Component writes to the file system.

- [https://github.com/Al1ex/WindowsElevation](https://github.com/Al1ex/WindowsElevation) :  ![starts](https://img.shields.io/github/stars/Al1ex/WindowsElevation.svg) ![forks](https://img.shields.io/github/forks/Al1ex/WindowsElevation.svg)
- [https://github.com/sailay1996/cve-2020-1337-poc](https://github.com/sailay1996/cve-2020-1337-poc) :  ![starts](https://img.shields.io/github/stars/sailay1996/cve-2020-1337-poc.svg) ![forks](https://img.shields.io/github/forks/sailay1996/cve-2020-1337-poc.svg)
- [https://github.com/math1as/CVE-2020-1337-exploit](https://github.com/math1as/CVE-2020-1337-exploit) :  ![starts](https://img.shields.io/github/stars/math1as/CVE-2020-1337-exploit.svg) ![forks](https://img.shields.io/github/forks/math1as/CVE-2020-1337-exploit.svg)
- [https://github.com/neofito/CVE-2020-1337](https://github.com/neofito/CVE-2020-1337) :  ![starts](https://img.shields.io/github/stars/neofito/CVE-2020-1337.svg) ![forks](https://img.shields.io/github/forks/neofito/CVE-2020-1337.svg)
- [https://github.com/VoidSec/CVE-2020-1337](https://github.com/VoidSec/CVE-2020-1337) :  ![starts](https://img.shields.io/github/stars/VoidSec/CVE-2020-1337.svg) ![forks](https://img.shields.io/github/forks/VoidSec/CVE-2020-1337.svg)
- [https://github.com/password520/cve-2020-1337-poc](https://github.com/password520/cve-2020-1337-poc) :  ![starts](https://img.shields.io/github/stars/password520/cve-2020-1337-poc.svg) ![forks](https://img.shields.io/github/forks/password520/cve-2020-1337-poc.svg)


## CVE-2020-1313
 An elevation of privilege vulnerability exists when the Windows Update Orchestrator Service improperly handles file operations, aka 'Windows Update Orchestrator Service Elevation of Privilege Vulnerability'.

- [https://github.com/irsl/CVE-2020-1313](https://github.com/irsl/CVE-2020-1313) :  ![starts](https://img.shields.io/github/stars/irsl/CVE-2020-1313.svg) ![forks](https://img.shields.io/github/forks/irsl/CVE-2020-1313.svg)


## CVE-2020-1301
 A remote code execution vulnerability exists in the way that the Microsoft Server Message Block 1.0 (SMBv1) server handles certain requests, aka 'Windows SMB Remote Code Execution Vulnerability'.

- [https://github.com/shubham0d/CVE-2020-1301](https://github.com/shubham0d/CVE-2020-1301) :  ![starts](https://img.shields.io/github/stars/shubham0d/CVE-2020-1301.svg) ![forks](https://img.shields.io/github/forks/shubham0d/CVE-2020-1301.svg)


## CVE-2020-1283
 A denial of service vulnerability exists when Windows improperly handles objects in memory, aka 'Windows Denial of Service Vulnerability'.

- [https://github.com/RedyOpsResearchLabs/CVE-2020-1283_Windows-Denial-of-Service-Vulnerability](https://github.com/RedyOpsResearchLabs/CVE-2020-1283_Windows-Denial-of-Service-Vulnerability) :  ![starts](https://img.shields.io/github/stars/RedyOpsResearchLabs/CVE-2020-1283_Windows-Denial-of-Service-Vulnerability.svg) ![forks](https://img.shields.io/github/forks/RedyOpsResearchLabs/CVE-2020-1283_Windows-Denial-of-Service-Vulnerability.svg)


## CVE-2020-1206
 An information disclosure vulnerability exists in the way that the Microsoft Server Message Block 3.1.1 (SMBv3) protocol handles certain requests, aka 'Windows SMBv3 Client/Server Information Disclosure Vulnerability'.

- [https://github.com/jamf/CVE-2020-1206-POC](https://github.com/jamf/CVE-2020-1206-POC) :  ![starts](https://img.shields.io/github/stars/jamf/CVE-2020-1206-POC.svg) ![forks](https://img.shields.io/github/forks/jamf/CVE-2020-1206-POC.svg)
- [https://github.com/jamf/SMBGhost-SMBleed-scanner](https://github.com/jamf/SMBGhost-SMBleed-scanner) :  ![starts](https://img.shields.io/github/stars/jamf/SMBGhost-SMBleed-scanner.svg) ![forks](https://img.shields.io/github/forks/jamf/SMBGhost-SMBleed-scanner.svg)
- [https://github.com/datntsec/CVE-2020-1206](https://github.com/datntsec/CVE-2020-1206) :  ![starts](https://img.shields.io/github/stars/datntsec/CVE-2020-1206.svg) ![forks](https://img.shields.io/github/forks/datntsec/CVE-2020-1206.svg)
- [https://github.com/Info-Security-Solution-Kolkata/CVE-2020-1206-Exploit](https://github.com/Info-Security-Solution-Kolkata/CVE-2020-1206-Exploit) :  ![starts](https://img.shields.io/github/stars/Info-Security-Solution-Kolkata/CVE-2020-1206-Exploit.svg) ![forks](https://img.shields.io/github/forks/Info-Security-Solution-Kolkata/CVE-2020-1206-Exploit.svg)
- [https://github.com/Info-Security-Solution-Kolkata/Smbleed-CVE-2020-1206-Exploit](https://github.com/Info-Security-Solution-Kolkata/Smbleed-CVE-2020-1206-Exploit) :  ![starts](https://img.shields.io/github/stars/Info-Security-Solution-Kolkata/Smbleed-CVE-2020-1206-Exploit.svg) ![forks](https://img.shields.io/github/forks/Info-Security-Solution-Kolkata/Smbleed-CVE-2020-1206-Exploit.svg)


## CVE-2020-1066
 An elevation of privilege vulnerability exists in .NET Framework which could allow an attacker to elevate their privilege level.To exploit the vulnerability, an attacker would first have to access the local machine, and then run a malicious program.The update addresses the vulnerability by correcting how .NET Framework activates COM objects., aka '.NET Framework Elevation of Privilege Vulnerability'.

- [https://github.com/Al1ex/WindowsElevation](https://github.com/Al1ex/WindowsElevation) :  ![starts](https://img.shields.io/github/stars/Al1ex/WindowsElevation.svg) ![forks](https://img.shields.io/github/forks/Al1ex/WindowsElevation.svg)
- [https://github.com/cbwang505/CVE-2020-1066-EXP](https://github.com/cbwang505/CVE-2020-1066-EXP) :  ![starts](https://img.shields.io/github/stars/cbwang505/CVE-2020-1066-EXP.svg) ![forks](https://img.shields.io/github/forks/cbwang505/CVE-2020-1066-EXP.svg)
- [https://github.com/xyddnljydd/cve-2020-1066](https://github.com/xyddnljydd/cve-2020-1066) :  ![starts](https://img.shields.io/github/stars/xyddnljydd/cve-2020-1066.svg) ![forks](https://img.shields.io/github/forks/xyddnljydd/cve-2020-1066.svg)


## CVE-2020-1054
 An elevation of privilege vulnerability exists in Windows when the Windows kernel-mode driver fails to properly handle objects in memory, aka 'Win32k Elevation of Privilege Vulnerability'. This CVE ID is unique from CVE-2020-1143.

- [https://github.com/Al1ex/WindowsElevation](https://github.com/Al1ex/WindowsElevation) :  ![starts](https://img.shields.io/github/stars/Al1ex/WindowsElevation.svg) ![forks](https://img.shields.io/github/forks/Al1ex/WindowsElevation.svg)
- [https://github.com/0xeb-bp/cve-2020-1054](https://github.com/0xeb-bp/cve-2020-1054) :  ![starts](https://img.shields.io/github/stars/0xeb-bp/cve-2020-1054.svg) ![forks](https://img.shields.io/github/forks/0xeb-bp/cve-2020-1054.svg)
- [https://github.com/KaLendsi/CVE-2020-1054](https://github.com/KaLendsi/CVE-2020-1054) :  ![starts](https://img.shields.io/github/stars/KaLendsi/CVE-2020-1054.svg) ![forks](https://img.shields.io/github/forks/KaLendsi/CVE-2020-1054.svg)
- [https://github.com/Iamgublin/CVE-2020-1054](https://github.com/Iamgublin/CVE-2020-1054) :  ![starts](https://img.shields.io/github/stars/Iamgublin/CVE-2020-1054.svg) ![forks](https://img.shields.io/github/forks/Iamgublin/CVE-2020-1054.svg)
- [https://github.com/Graham382/CVE-2020-1054](https://github.com/Graham382/CVE-2020-1054) :  ![starts](https://img.shields.io/github/stars/Graham382/CVE-2020-1054.svg) ![forks](https://img.shields.io/github/forks/Graham382/CVE-2020-1054.svg)


## CVE-2020-1048
 An elevation of privilege vulnerability exists when the Windows Print Spooler service improperly allows arbitrary writing to the file system, aka 'Windows Print Spooler Elevation of Privilege Vulnerability'. This CVE ID is unique from CVE-2020-1070.

- [https://github.com/neofito/CVE-2020-1337](https://github.com/neofito/CVE-2020-1337) :  ![starts](https://img.shields.io/github/stars/neofito/CVE-2020-1337.svg) ![forks](https://img.shields.io/github/forks/neofito/CVE-2020-1337.svg)
- [https://github.com/shubham0d/CVE-2020-1048](https://github.com/shubham0d/CVE-2020-1048) :  ![starts](https://img.shields.io/github/stars/shubham0d/CVE-2020-1048.svg) ![forks](https://img.shields.io/github/forks/shubham0d/CVE-2020-1048.svg)
- [https://github.com/VoidSec/CVE-2020-1337](https://github.com/VoidSec/CVE-2020-1337) :  ![starts](https://img.shields.io/github/stars/VoidSec/CVE-2020-1337.svg) ![forks](https://img.shields.io/github/forks/VoidSec/CVE-2020-1337.svg)
- [https://github.com/zveriu/CVE-2009-0229-PoC](https://github.com/zveriu/CVE-2009-0229-PoC) :  ![starts](https://img.shields.io/github/stars/zveriu/CVE-2009-0229-PoC.svg) ![forks](https://img.shields.io/github/forks/zveriu/CVE-2009-0229-PoC.svg)
- [https://github.com/Ken-Abruzzi/CVE-2020-1048](https://github.com/Ken-Abruzzi/CVE-2020-1048) :  ![starts](https://img.shields.io/github/stars/Ken-Abruzzi/CVE-2020-1048.svg) ![forks](https://img.shields.io/github/forks/Ken-Abruzzi/CVE-2020-1048.svg)
- [https://github.com/Y3A/cve-2020-1048](https://github.com/Y3A/cve-2020-1048) :  ![starts](https://img.shields.io/github/stars/Y3A/cve-2020-1048.svg) ![forks](https://img.shields.io/github/forks/Y3A/cve-2020-1048.svg)


## CVE-2020-1034
 &lt;p&gt;An elevation of privilege vulnerability exists in the way that the Windows Kernel handles objects in memory. An attacker who successfully exploited the vulnerability could execute code with elevated permissions.&lt;/p&gt; &lt;p&gt;To exploit the vulnerability, a locally authenticated attacker could run a specially crafted application.&lt;/p&gt; &lt;p&gt;The security update addresses the vulnerability by ensuring the Windows Kernel properly handles objects in memory.&lt;/p&gt;

- [https://github.com/yardenshafir/CVE-2020-1034](https://github.com/yardenshafir/CVE-2020-1034) :  ![starts](https://img.shields.io/github/stars/yardenshafir/CVE-2020-1034.svg) ![forks](https://img.shields.io/github/forks/yardenshafir/CVE-2020-1034.svg)
- [https://github.com/GeorgyFirsov/CVE-2020-1034](https://github.com/GeorgyFirsov/CVE-2020-1034) :  ![starts](https://img.shields.io/github/stars/GeorgyFirsov/CVE-2020-1034.svg) ![forks](https://img.shields.io/github/forks/GeorgyFirsov/CVE-2020-1034.svg)


## CVE-2020-1020
 A remote code execution vulnerability exists in Microsoft Windows when the Windows Adobe Type Manager Library improperly handles a specially-crafted multi-master font - Adobe Type 1 PostScript format.For all systems except Windows 10, an attacker who successfully exploited the vulnerability could execute code remotely, aka 'Adobe Font Manager Library Remote Code Execution Vulnerability'. This CVE ID is unique from CVE-2020-0938.

- [https://github.com/KaLendsi/CVE-2020-1020](https://github.com/KaLendsi/CVE-2020-1020) :  ![starts](https://img.shields.io/github/stars/KaLendsi/CVE-2020-1020.svg) ![forks](https://img.shields.io/github/forks/KaLendsi/CVE-2020-1020.svg)
- [https://github.com/CrackerCat/CVE-2020-1020-Exploit](https://github.com/CrackerCat/CVE-2020-1020-Exploit) :  ![starts](https://img.shields.io/github/stars/CrackerCat/CVE-2020-1020-Exploit.svg) ![forks](https://img.shields.io/github/forks/CrackerCat/CVE-2020-1020-Exploit.svg)


## CVE-2020-1015
 An elevation of privilege vulnerability exists in the way that the User-Mode Power Service (UMPS) handles objects in memory, aka 'Windows Elevation of Privilege Vulnerability'. This CVE ID is unique from CVE-2020-0934, CVE-2020-0983, CVE-2020-1009, CVE-2020-1011.

- [https://github.com/0xeb-bp/cve-2020-1015](https://github.com/0xeb-bp/cve-2020-1015) :  ![starts](https://img.shields.io/github/stars/0xeb-bp/cve-2020-1015.svg) ![forks](https://img.shields.io/github/forks/0xeb-bp/cve-2020-1015.svg)


## CVE-2019-9670
 mailboxd component in Synacor Zimbra Collaboration Suite 8.7.x before 8.7.11p10 has an XML External Entity injection (XXE) vulnerability, as demonstrated by Autodiscover/Autodiscover.xml.

- [https://github.com/Cappricio-Securities/CVE-2019-9670](https://github.com/Cappricio-Securities/CVE-2019-9670) :  ![starts](https://img.shields.io/github/stars/Cappricio-Securities/CVE-2019-9670.svg) ![forks](https://img.shields.io/github/forks/Cappricio-Securities/CVE-2019-9670.svg)


## CVE-2019-2025
 In binder_thread_read of binder.c, there is a possible use-after-free due to improper locking. This could lead to local escalation of privilege in the kernel with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-116855682References: Upstream kernel

- [https://github.com/jltxgcy/CVE_2019_2025_EXP](https://github.com/jltxgcy/CVE_2019_2025_EXP) :  ![starts](https://img.shields.io/github/stars/jltxgcy/CVE_2019_2025_EXP.svg) ![forks](https://img.shields.io/github/forks/jltxgcy/CVE_2019_2025_EXP.svg)


## CVE-2019-2022
 In rw_t3t_act_handle_fmt_rsp and rw_t3t_act_handle_sro_rsp of rw_t3t.cc, there is a possible out-of-bound read due to a missing bounds check. This could lead to local information disclosure with no additional execution privileges needed. User interaction is needed for exploitation.Product: AndroidVersions: Android-7.0 Android-7.1.1 Android-7.1.2 Android-8.0 Android-8.1 Android-9Android ID: A-120506143

- [https://github.com/AhnSungHoon/Kali_CVE](https://github.com/AhnSungHoon/Kali_CVE) :  ![starts](https://img.shields.io/github/stars/AhnSungHoon/Kali_CVE.svg) ![forks](https://img.shields.io/github/forks/AhnSungHoon/Kali_CVE.svg)


## CVE-2019-2017
 In rw_t2t_handle_tlv_detect_rsp of rw_t2t_ndef.cc, there is a possible out-of-bound write due to a missing bounds check. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is needed for exploitation.Product: AndroidVersions: Android-7.0 Android-7.1.1 Android-7.1.2 Android-8.0 Android-8.1 Android-9Android ID: A-121035711

- [https://github.com/grmono/CVE2019-2017_POC](https://github.com/grmono/CVE2019-2017_POC) :  ![starts](https://img.shields.io/github/stars/grmono/CVE2019-2017_POC.svg) ![forks](https://img.shields.io/github/forks/grmono/CVE2019-2017_POC.svg)


## CVE-2019-1821
 A vulnerability in the web-based management interface of Cisco Prime Infrastructure (PI) and Cisco Evolved Programmable Network (EPN) Manager could allow an authenticated, remote attacker to execute code with root-level privileges on the underlying operating system. This vulnerability exist because the software improperly validates user-supplied input. An attacker could exploit this vulnerability by uploading a malicious file to the administrative web interface. A successful exploit could allow the attacker to execute code with root-level privileges on the underlying operating system.

- [https://github.com/k8gege/CiscoExploit](https://github.com/k8gege/CiscoExploit) :  ![starts](https://img.shields.io/github/stars/k8gege/CiscoExploit.svg) ![forks](https://img.shields.io/github/forks/k8gege/CiscoExploit.svg)


## CVE-2019-1759
 A vulnerability in access control list (ACL) functionality of the Gigabit Ethernet Management interface of Cisco IOS XE Software could allow an unauthenticated, remote attacker to reach the configured IP addresses on the Gigabit Ethernet Management interface. The vulnerability is due to a logic error that was introduced in the Cisco IOS XE Software 16.1.1 Release, which prevents the ACL from working when applied against the management interface. An attacker could exploit this issue by attempting to access the device via the management interface.

- [https://github.com/r3m0t3nu11/CVE-2019-1759-csrf-js-rce](https://github.com/r3m0t3nu11/CVE-2019-1759-csrf-js-rce) :  ![starts](https://img.shields.io/github/stars/r3m0t3nu11/CVE-2019-1759-csrf-js-rce.svg) ![forks](https://img.shields.io/github/forks/r3m0t3nu11/CVE-2019-1759-csrf-js-rce.svg)


## CVE-2019-1663
 A vulnerability in the web-based management interface of the Cisco RV110W Wireless-N VPN Firewall, Cisco RV130W Wireless-N Multifunction VPN Router, and Cisco RV215W Wireless-N VPN Router could allow an unauthenticated, remote attacker to execute arbitrary code on an affected device. The vulnerability is due to improper validation of user-supplied data in the web-based management interface. An attacker could exploit this vulnerability by sending malicious HTTP requests to a targeted device. A successful exploit could allow the attacker to execute arbitrary code on the underlying operating system of the affected device as a high-privilege user. RV110W Wireless-N VPN Firewall versions prior to 1.2.2.1 are affected. RV130W Wireless-N Multifunction VPN Router versions prior to 1.0.3.45 are affected. RV215W Wireless-N VPN Router versions prior to 1.3.1.1 are affected.

- [https://github.com/StealYourCode/CVE-2019-1663](https://github.com/StealYourCode/CVE-2019-1663) :  ![starts](https://img.shields.io/github/stars/StealYourCode/CVE-2019-1663.svg) ![forks](https://img.shields.io/github/forks/StealYourCode/CVE-2019-1663.svg)
- [https://github.com/Oraxiage/CVE-2019-1663](https://github.com/Oraxiage/CVE-2019-1663) :  ![starts](https://img.shields.io/github/stars/Oraxiage/CVE-2019-1663.svg) ![forks](https://img.shields.io/github/forks/Oraxiage/CVE-2019-1663.svg)
- [https://github.com/e180175/CVE-2019-1663-vuln](https://github.com/e180175/CVE-2019-1663-vuln) :  ![starts](https://img.shields.io/github/stars/e180175/CVE-2019-1663-vuln.svg) ![forks](https://img.shields.io/github/forks/e180175/CVE-2019-1663-vuln.svg)


## CVE-2019-1653
 A vulnerability in the web-based management interface of Cisco Small Business RV320 and RV325 Dual Gigabit WAN VPN Routers could allow an unauthenticated, remote attacker to retrieve sensitive information. The vulnerability is due to improper access controls for URLs. An attacker could exploit this vulnerability by connecting to an affected device via HTTP or HTTPS and requesting specific URLs. A successful exploit could allow the attacker to download the router configuration or detailed diagnostic information. Cisco has released firmware updates that address this vulnerability.

- [https://github.com/0x27/CiscoRV320Dump](https://github.com/0x27/CiscoRV320Dump) :  ![starts](https://img.shields.io/github/stars/0x27/CiscoRV320Dump.svg) ![forks](https://img.shields.io/github/forks/0x27/CiscoRV320Dump.svg)
- [https://github.com/k8gege/CiscoExploit](https://github.com/k8gege/CiscoExploit) :  ![starts](https://img.shields.io/github/stars/k8gege/CiscoExploit.svg) ![forks](https://img.shields.io/github/forks/k8gege/CiscoExploit.svg)
- [https://github.com/shaheemirza/CiscoSpill](https://github.com/shaheemirza/CiscoSpill) :  ![starts](https://img.shields.io/github/stars/shaheemirza/CiscoSpill.svg) ![forks](https://img.shields.io/github/forks/shaheemirza/CiscoSpill.svg)
- [https://github.com/dubfr33/CVE-2019-1653](https://github.com/dubfr33/CVE-2019-1653) :  ![starts](https://img.shields.io/github/stars/dubfr33/CVE-2019-1653.svg) ![forks](https://img.shields.io/github/forks/dubfr33/CVE-2019-1653.svg)
- [https://github.com/S3ntinelX/nmap-scripts](https://github.com/S3ntinelX/nmap-scripts) :  ![starts](https://img.shields.io/github/stars/S3ntinelX/nmap-scripts.svg) ![forks](https://img.shields.io/github/forks/S3ntinelX/nmap-scripts.svg)
- [https://github.com/ibrahimzx/CVE-2019-1653](https://github.com/ibrahimzx/CVE-2019-1653) :  ![starts](https://img.shields.io/github/stars/ibrahimzx/CVE-2019-1653.svg) ![forks](https://img.shields.io/github/forks/ibrahimzx/CVE-2019-1653.svg)


## CVE-2019-1652
 A vulnerability in the web-based management interface of Cisco Small Business RV320 and RV325 Dual Gigabit WAN VPN Routers could allow an authenticated, remote attacker with administrative privileges on an affected device to execute arbitrary commands. The vulnerability is due to improper validation of user-supplied input. An attacker could exploit this vulnerability by sending malicious HTTP POST requests to the web-based management interface of an affected device. A successful exploit could allow the attacker to execute arbitrary commands on the underlying Linux shell as root. Cisco has released firmware updates that address this vulnerability.

- [https://github.com/0x27/CiscoRV320Dump](https://github.com/0x27/CiscoRV320Dump) :  ![starts](https://img.shields.io/github/stars/0x27/CiscoRV320Dump.svg) ![forks](https://img.shields.io/github/forks/0x27/CiscoRV320Dump.svg)


## CVE-2019-1579
 Remote Code Execution in PAN-OS 7.1.18 and earlier, PAN-OS 8.0.11-h1 and earlier, and PAN-OS 8.1.2 and earlier with GlobalProtect Portal or GlobalProtect Gateway Interface enabled may allow an unauthenticated remote attacker to execute arbitrary code.

- [https://github.com/securifera/CVE-2019-1579](https://github.com/securifera/CVE-2019-1579) :  ![starts](https://img.shields.io/github/stars/securifera/CVE-2019-1579.svg) ![forks](https://img.shields.io/github/forks/securifera/CVE-2019-1579.svg)
- [https://github.com/Elsfa7-110/CVE-2019-1579](https://github.com/Elsfa7-110/CVE-2019-1579) :  ![starts](https://img.shields.io/github/stars/Elsfa7-110/CVE-2019-1579.svg) ![forks](https://img.shields.io/github/forks/Elsfa7-110/CVE-2019-1579.svg)


## CVE-2019-1477
 An elevation of privilege vulnerability exists when the Windows Printer Service improperly validates file paths while loading printer drivers, aka 'Windows Printer Service Elevation of Privilege Vulnerability'.

- [https://github.com/2yong1/CVE-2019-1477](https://github.com/2yong1/CVE-2019-1477) :  ![starts](https://img.shields.io/github/stars/2yong1/CVE-2019-1477.svg) ![forks](https://img.shields.io/github/forks/2yong1/CVE-2019-1477.svg)


## CVE-2019-1476
 An elevation of privilege vulnerability exists when Windows AppX Deployment Service (AppXSVC) improperly handles hard links, aka 'Windows Elevation of Privilege Vulnerability'. This CVE ID is unique from CVE-2019-1483.

- [https://github.com/sgabe/CVE-2019-1476](https://github.com/sgabe/CVE-2019-1476) :  ![starts](https://img.shields.io/github/stars/sgabe/CVE-2019-1476.svg) ![forks](https://img.shields.io/github/forks/sgabe/CVE-2019-1476.svg)


## CVE-2019-1458
 An elevation of privilege vulnerability exists in Windows when the Win32k component fails to properly handle objects in memory, aka 'Win32k Elevation of Privilege Vulnerability'.

- [https://github.com/piotrflorczyk/cve-2019-1458_POC](https://github.com/piotrflorczyk/cve-2019-1458_POC) :  ![starts](https://img.shields.io/github/stars/piotrflorczyk/cve-2019-1458_POC.svg) ![forks](https://img.shields.io/github/forks/piotrflorczyk/cve-2019-1458_POC.svg)
- [https://github.com/rip1s/CVE-2019-1458](https://github.com/rip1s/CVE-2019-1458) :  ![starts](https://img.shields.io/github/stars/rip1s/CVE-2019-1458.svg) ![forks](https://img.shields.io/github/forks/rip1s/CVE-2019-1458.svg)
- [https://github.com/Eternit7/CVE-2019-1458](https://github.com/Eternit7/CVE-2019-1458) :  ![starts](https://img.shields.io/github/stars/Eternit7/CVE-2019-1458.svg) ![forks](https://img.shields.io/github/forks/Eternit7/CVE-2019-1458.svg)


## CVE-2019-1422
 An elevation of privilege vulnerability exists in the way that the iphlpsvc.dll handles file creation allowing for a file overwrite, aka 'Windows Elevation of Privilege Vulnerability'. This CVE ID is unique from CVE-2019-1420, CVE-2019-1423.

- [https://github.com/ze0r/cve-2019-1422](https://github.com/ze0r/cve-2019-1422) :  ![starts](https://img.shields.io/github/stars/ze0r/cve-2019-1422.svg) ![forks](https://img.shields.io/github/forks/ze0r/cve-2019-1422.svg)


## CVE-2019-1405
 An elevation of privilege vulnerability exists when the Windows Universal Plug and Play (UPnP) service improperly allows COM object creation, aka 'Windows UPnP Service Elevation of Privilege Vulnerability'.

- [https://github.com/Al1ex/WindowsElevation](https://github.com/Al1ex/WindowsElevation) :  ![starts](https://img.shields.io/github/stars/Al1ex/WindowsElevation.svg) ![forks](https://img.shields.io/github/forks/Al1ex/WindowsElevation.svg)
- [https://github.com/apt69/COMahawk](https://github.com/apt69/COMahawk) :  ![starts](https://img.shields.io/github/stars/apt69/COMahawk.svg) ![forks](https://img.shields.io/github/forks/apt69/COMahawk.svg)


## CVE-2019-1402
 An information disclosure vulnerability exists in Microsoft Office software when the software fails to properly handle objects in memory, aka 'Microsoft Office Information Disclosure Vulnerability'.

- [https://github.com/lauxjpn/CorruptQueryAccessWorkaround](https://github.com/lauxjpn/CorruptQueryAccessWorkaround) :  ![starts](https://img.shields.io/github/stars/lauxjpn/CorruptQueryAccessWorkaround.svg) ![forks](https://img.shields.io/github/forks/lauxjpn/CorruptQueryAccessWorkaround.svg)


## CVE-2019-1388
 An elevation of privilege vulnerability exists in the Windows Certificate Dialog when it does not properly enforce user privileges, aka 'Windows Certificate Dialog Elevation of Privilege Vulnerability'.

- [https://github.com/jas502n/CVE-2019-1388](https://github.com/jas502n/CVE-2019-1388) :  ![starts](https://img.shields.io/github/stars/jas502n/CVE-2019-1388.svg) ![forks](https://img.shields.io/github/forks/jas502n/CVE-2019-1388.svg)
- [https://github.com/sv3nbeast/CVE-2019-1388](https://github.com/sv3nbeast/CVE-2019-1388) :  ![starts](https://img.shields.io/github/stars/sv3nbeast/CVE-2019-1388.svg) ![forks](https://img.shields.io/github/forks/sv3nbeast/CVE-2019-1388.svg)
- [https://github.com/nobodyatall648/CVE-2019-1388](https://github.com/nobodyatall648/CVE-2019-1388) :  ![starts](https://img.shields.io/github/stars/nobodyatall648/CVE-2019-1388.svg) ![forks](https://img.shields.io/github/forks/nobodyatall648/CVE-2019-1388.svg)
- [https://github.com/suprise4u/CVE-2019-1388](https://github.com/suprise4u/CVE-2019-1388) :  ![starts](https://img.shields.io/github/stars/suprise4u/CVE-2019-1388.svg) ![forks](https://img.shields.io/github/forks/suprise4u/CVE-2019-1388.svg)
- [https://github.com/jaychouzzk/CVE-2019-1388](https://github.com/jaychouzzk/CVE-2019-1388) :  ![starts](https://img.shields.io/github/stars/jaychouzzk/CVE-2019-1388.svg) ![forks](https://img.shields.io/github/forks/jaychouzzk/CVE-2019-1388.svg)


## CVE-2019-1385
 An elevation of privilege vulnerability exists when the Windows AppX Deployment Extensions improperly performs privilege management, resulting in access to system files.To exploit this vulnerability, an authenticated attacker would need to run a specially crafted application to elevate privileges.The security update addresses the vulnerability by correcting how AppX Deployment Extensions manages privileges., aka 'Windows AppX Deployment Extensions Elevation of Privilege Vulnerability'.

- [https://github.com/0x413x4/CVE-2019-1385](https://github.com/0x413x4/CVE-2019-1385) :  ![starts](https://img.shields.io/github/stars/0x413x4/CVE-2019-1385.svg) ![forks](https://img.shields.io/github/forks/0x413x4/CVE-2019-1385.svg)


## CVE-2019-1351
 A tampering vulnerability exists when Git for Visual Studio improperly handles virtual drive paths, aka 'Git for Visual Studio Tampering Vulnerability'.

- [https://github.com/JonasDL/PruebaCVE20191351](https://github.com/JonasDL/PruebaCVE20191351) :  ![starts](https://img.shields.io/github/stars/JonasDL/PruebaCVE20191351.svg) ![forks](https://img.shields.io/github/forks/JonasDL/PruebaCVE20191351.svg)


## CVE-2019-1332
 A cross-site scripting (XSS) vulnerability exists when Microsoft SQL Server Reporting Services (SSRS) does not properly sanitize a specially-crafted web request to an affected SSRS server, aka 'Microsoft SQL Server Reporting Services XSS Vulnerability'.

- [https://github.com/mbadanoiu/CVE-2019-1332](https://github.com/mbadanoiu/CVE-2019-1332) :  ![starts](https://img.shields.io/github/stars/mbadanoiu/CVE-2019-1332.svg) ![forks](https://img.shields.io/github/forks/mbadanoiu/CVE-2019-1332.svg)


## CVE-2019-1322
 An elevation of privilege vulnerability exists when Windows improperly handles authentication requests, aka 'Microsoft Windows Elevation of Privilege Vulnerability'. This CVE ID is unique from CVE-2019-1320, CVE-2019-1340.

- [https://github.com/apt69/COMahawk](https://github.com/apt69/COMahawk) :  ![starts](https://img.shields.io/github/stars/apt69/COMahawk.svg) ![forks](https://img.shields.io/github/forks/apt69/COMahawk.svg)


## CVE-2019-1315
 An elevation of privilege vulnerability exists when Windows Error Reporting manager improperly handles hard links, aka 'Windows Error Reporting Manager Elevation of Privilege Vulnerability'. This CVE ID is unique from CVE-2019-1339, CVE-2019-1342.

- [https://github.com/Mayter/CVE-2019-1315](https://github.com/Mayter/CVE-2019-1315) :  ![starts](https://img.shields.io/github/stars/Mayter/CVE-2019-1315.svg) ![forks](https://img.shields.io/github/forks/Mayter/CVE-2019-1315.svg)


## CVE-2019-1253
 An elevation of privilege vulnerability exists when the Windows AppX Deployment Server improperly handles junctions.To exploit this vulnerability, an attacker would first have to gain execution on the victim system, aka 'Windows Elevation of Privilege Vulnerability'. This CVE ID is unique from CVE-2019-1215, CVE-2019-1278, CVE-2019-1303.

- [https://github.com/padovah4ck/CVE-2019-1253](https://github.com/padovah4ck/CVE-2019-1253) :  ![starts](https://img.shields.io/github/stars/padovah4ck/CVE-2019-1253.svg) ![forks](https://img.shields.io/github/forks/padovah4ck/CVE-2019-1253.svg)
- [https://github.com/rogue-kdc/CVE-2019-1253](https://github.com/rogue-kdc/CVE-2019-1253) :  ![starts](https://img.shields.io/github/stars/rogue-kdc/CVE-2019-1253.svg) ![forks](https://img.shields.io/github/forks/rogue-kdc/CVE-2019-1253.svg)
- [https://github.com/sgabe/CVE-2019-1253](https://github.com/sgabe/CVE-2019-1253) :  ![starts](https://img.shields.io/github/stars/sgabe/CVE-2019-1253.svg) ![forks](https://img.shields.io/github/forks/sgabe/CVE-2019-1253.svg)
- [https://github.com/likescam/CVE-2019-1253](https://github.com/likescam/CVE-2019-1253) :  ![starts](https://img.shields.io/github/stars/likescam/CVE-2019-1253.svg) ![forks](https://img.shields.io/github/forks/likescam/CVE-2019-1253.svg)
- [https://github.com/offsec-ttps/CVE2019-1253-Compiled](https://github.com/offsec-ttps/CVE2019-1253-Compiled) :  ![starts](https://img.shields.io/github/stars/offsec-ttps/CVE2019-1253-Compiled.svg) ![forks](https://img.shields.io/github/forks/offsec-ttps/CVE2019-1253-Compiled.svg)


## CVE-2019-1221
 A remote code execution vulnerability exists in the way that the scripting engine handles objects in memory in Internet Explorer, aka 'Scripting Engine Memory Corruption Vulnerability'.

- [https://github.com/ZwCreatePhoton/CVE-2019-1221](https://github.com/ZwCreatePhoton/CVE-2019-1221) :  ![starts](https://img.shields.io/github/stars/ZwCreatePhoton/CVE-2019-1221.svg) ![forks](https://img.shields.io/github/forks/ZwCreatePhoton/CVE-2019-1221.svg)


## CVE-2019-1218
 A spoofing vulnerability exists in the way Microsoft Outlook iOS software parses specifically crafted email messages, aka 'Outlook iOS Spoofing Vulnerability'.

- [https://github.com/d0gukank/CVE-2019-1218](https://github.com/d0gukank/CVE-2019-1218) :  ![starts](https://img.shields.io/github/stars/d0gukank/CVE-2019-1218.svg) ![forks](https://img.shields.io/github/forks/d0gukank/CVE-2019-1218.svg)


## CVE-2019-1215
 An elevation of privilege vulnerability exists in the way that ws2ifsl.sys (Winsock) handles objects in memory, aka 'Windows Elevation of Privilege Vulnerability'. This CVE ID is unique from CVE-2019-1253, CVE-2019-1278, CVE-2019-1303.

- [https://github.com/bluefrostsecurity/CVE-2019-1215](https://github.com/bluefrostsecurity/CVE-2019-1215) :  ![starts](https://img.shields.io/github/stars/bluefrostsecurity/CVE-2019-1215.svg) ![forks](https://img.shields.io/github/forks/bluefrostsecurity/CVE-2019-1215.svg)


## CVE-2019-1182
 A remote code execution vulnerability exists in Remote Desktop Services &#8364;&#8220; formerly known as Terminal Services &#8364;&#8220; when an unauthenticated attacker connects to the target system using RDP and sends specially crafted requests, aka 'Remote Desktop Services Remote Code Execution Vulnerability'. This CVE ID is unique from CVE-2019-1181, CVE-2019-1222, CVE-2019-1226.

- [https://github.com/chefphenix25/vuln-rabilit-windows7](https://github.com/chefphenix25/vuln-rabilit-windows7) :  ![starts](https://img.shields.io/github/stars/chefphenix25/vuln-rabilit-windows7.svg) ![forks](https://img.shields.io/github/forks/chefphenix25/vuln-rabilit-windows7.svg)


## CVE-2019-1181
 A remote code execution vulnerability exists in Remote Desktop Services &#8364;&#8220; formerly known as Terminal Services &#8364;&#8220; when an unauthenticated attacker connects to the target system using RDP and sends specially crafted requests, aka 'Remote Desktop Services Remote Code Execution Vulnerability'. This CVE ID is unique from CVE-2019-1182, CVE-2019-1222, CVE-2019-1226.

- [https://github.com/major203/cve-2019-1181](https://github.com/major203/cve-2019-1181) :  ![starts](https://img.shields.io/github/stars/major203/cve-2019-1181.svg) ![forks](https://img.shields.io/github/forks/major203/cve-2019-1181.svg)
- [https://github.com/chefphenix25/vuln-rabilit-windows7](https://github.com/chefphenix25/vuln-rabilit-windows7) :  ![starts](https://img.shields.io/github/stars/chefphenix25/vuln-rabilit-windows7.svg) ![forks](https://img.shields.io/github/forks/chefphenix25/vuln-rabilit-windows7.svg)


## CVE-2019-1132
 An elevation of privilege vulnerability exists in Windows when the Win32k component fails to properly handle objects in memory, aka 'Win32k Elevation of Privilege Vulnerability'.

- [https://github.com/Vlad-tri/CVE-2019-1132](https://github.com/Vlad-tri/CVE-2019-1132) :  ![starts](https://img.shields.io/github/stars/Vlad-tri/CVE-2019-1132.svg) ![forks](https://img.shields.io/github/forks/Vlad-tri/CVE-2019-1132.svg)
- [https://github.com/petercc/CVE-2019-1132](https://github.com/petercc/CVE-2019-1132) :  ![starts](https://img.shields.io/github/stars/petercc/CVE-2019-1132.svg) ![forks](https://img.shields.io/github/forks/petercc/CVE-2019-1132.svg)


## CVE-2019-1130
 An elevation of privilege vulnerability exists when Windows AppX Deployment Service (AppXSVC) improperly handles hard links, aka 'Windows Elevation of Privilege Vulnerability'. This CVE ID is unique from CVE-2019-1129.

- [https://github.com/S3cur3Th1sSh1t/SharpByeBear](https://github.com/S3cur3Th1sSh1t/SharpByeBear) :  ![starts](https://img.shields.io/github/stars/S3cur3Th1sSh1t/SharpByeBear.svg) ![forks](https://img.shields.io/github/forks/S3cur3Th1sSh1t/SharpByeBear.svg)


## CVE-2019-1129
 An elevation of privilege vulnerability exists when Windows AppX Deployment Service (AppXSVC) improperly handles hard links, aka 'Windows Elevation of Privilege Vulnerability'. This CVE ID is unique from CVE-2019-1130.

- [https://github.com/S3cur3Th1sSh1t/SharpByeBear](https://github.com/S3cur3Th1sSh1t/SharpByeBear) :  ![starts](https://img.shields.io/github/stars/S3cur3Th1sSh1t/SharpByeBear.svg) ![forks](https://img.shields.io/github/forks/S3cur3Th1sSh1t/SharpByeBear.svg)


## CVE-2019-1125
 An information disclosure vulnerability exists when certain central processing units (CPU) speculatively access memory, aka 'Windows Kernel Information Disclosure Vulnerability'. This CVE ID is unique from CVE-2019-1071, CVE-2019-1073.

- [https://github.com/bitdefender/swapgs-attack-poc](https://github.com/bitdefender/swapgs-attack-poc) :  ![starts](https://img.shields.io/github/stars/bitdefender/swapgs-attack-poc.svg) ![forks](https://img.shields.io/github/forks/bitdefender/swapgs-attack-poc.svg)


## CVE-2019-1108
 An information disclosure vulnerability exists when the Windows RDP client improperly discloses the contents of its memory, aka 'Remote Desktop Protocol Client Information Disclosure Vulnerability'.

- [https://github.com/Lanph3re/cve-2019-1108](https://github.com/Lanph3re/cve-2019-1108) :  ![starts](https://img.shields.io/github/stars/Lanph3re/cve-2019-1108.svg) ![forks](https://img.shields.io/github/forks/Lanph3re/cve-2019-1108.svg)


## CVE-2019-1096
 An information disclosure vulnerability exists when the win32k component improperly provides kernel information, aka 'Win32k Information Disclosure Vulnerability'.

- [https://github.com/CrackerCat/cve-2019-1096-poc](https://github.com/CrackerCat/cve-2019-1096-poc) :  ![starts](https://img.shields.io/github/stars/CrackerCat/cve-2019-1096-poc.svg) ![forks](https://img.shields.io/github/forks/CrackerCat/cve-2019-1096-poc.svg)


## CVE-2019-1083
 A denial of service vulnerability exists when Microsoft Common Object Runtime Library improperly handles web requests, aka '.NET Denial of Service Vulnerability'.

- [https://github.com/stevenseeley/HowCVE-2019-1083Works](https://github.com/stevenseeley/HowCVE-2019-1083Works) :  ![starts](https://img.shields.io/github/stars/stevenseeley/HowCVE-2019-1083Works.svg) ![forks](https://img.shields.io/github/forks/stevenseeley/HowCVE-2019-1083Works.svg)


## CVE-2019-1069
 An elevation of privilege vulnerability exists in the way the Task Scheduler Service validates certain file operations, aka 'Task Scheduler Elevation of Privilege Vulnerability'.

- [https://github.com/S3cur3Th1sSh1t/SharpPolarBear](https://github.com/S3cur3Th1sSh1t/SharpPolarBear) :  ![starts](https://img.shields.io/github/stars/S3cur3Th1sSh1t/SharpPolarBear.svg) ![forks](https://img.shields.io/github/forks/S3cur3Th1sSh1t/SharpPolarBear.svg)


## CVE-2019-1068
 A remote code execution vulnerability exists in Microsoft SQL Server when it incorrectly handles processing of internal functions, aka 'Microsoft SQL Server Remote Code Execution Vulnerability'.

- [https://github.com/Vulnerability-Playground/CVE-2019-1068](https://github.com/Vulnerability-Playground/CVE-2019-1068) :  ![starts](https://img.shields.io/github/stars/Vulnerability-Playground/CVE-2019-1068.svg) ![forks](https://img.shields.io/github/forks/Vulnerability-Playground/CVE-2019-1068.svg)


## CVE-2019-1064
 An elevation of privilege vulnerability exists when Windows AppX Deployment Service (AppXSVC) improperly handles hard links, aka 'Windows Elevation of Privilege Vulnerability'.

- [https://github.com/RythmStick/CVE-2019-1064](https://github.com/RythmStick/CVE-2019-1064) :  ![starts](https://img.shields.io/github/stars/RythmStick/CVE-2019-1064.svg) ![forks](https://img.shields.io/github/forks/RythmStick/CVE-2019-1064.svg)
- [https://github.com/0x00-0x00/CVE-2019-1064](https://github.com/0x00-0x00/CVE-2019-1064) :  ![starts](https://img.shields.io/github/stars/0x00-0x00/CVE-2019-1064.svg) ![forks](https://img.shields.io/github/forks/0x00-0x00/CVE-2019-1064.svg)
- [https://github.com/attackgithub/CVE-2019-1064](https://github.com/attackgithub/CVE-2019-1064) :  ![starts](https://img.shields.io/github/stars/attackgithub/CVE-2019-1064.svg) ![forks](https://img.shields.io/github/forks/attackgithub/CVE-2019-1064.svg)


## CVE-2019-1041
 An elevation of privilege vulnerability exists when the Windows kernel fails to properly handle objects in memory, aka 'Windows Kernel Elevation of Privilege Vulnerability'. This CVE ID is unique from CVE-2019-1065.

- [https://github.com/5l1v3r1/CVE-2019-1041](https://github.com/5l1v3r1/CVE-2019-1041) :  ![starts](https://img.shields.io/github/stars/5l1v3r1/CVE-2019-1041.svg) ![forks](https://img.shields.io/github/forks/5l1v3r1/CVE-2019-1041.svg)


## CVE-2019-1040
 A tampering vulnerability exists in Microsoft Windows when a man-in-the-middle attacker is able to successfully bypass the NTLM MIC (Message Integrity Check) protection, aka 'Windows NTLM Tampering Vulnerability'.

- [https://github.com/fox-it/cve-2019-1040-scanner](https://github.com/fox-it/cve-2019-1040-scanner) :  ![starts](https://img.shields.io/github/stars/fox-it/cve-2019-1040-scanner.svg) ![forks](https://img.shields.io/github/forks/fox-it/cve-2019-1040-scanner.svg)
- [https://github.com/Ridter/CVE-2019-1040](https://github.com/Ridter/CVE-2019-1040) :  ![starts](https://img.shields.io/github/stars/Ridter/CVE-2019-1040.svg) ![forks](https://img.shields.io/github/forks/Ridter/CVE-2019-1040.svg)
- [https://github.com/QAX-A-Team/dcpwn](https://github.com/QAX-A-Team/dcpwn) :  ![starts](https://img.shields.io/github/stars/QAX-A-Team/dcpwn.svg) ![forks](https://img.shields.io/github/forks/QAX-A-Team/dcpwn.svg)
- [https://github.com/Ridter/CVE-2019-1040-dcpwn](https://github.com/Ridter/CVE-2019-1040-dcpwn) :  ![starts](https://img.shields.io/github/stars/Ridter/CVE-2019-1040-dcpwn.svg) ![forks](https://img.shields.io/github/forks/Ridter/CVE-2019-1040-dcpwn.svg)
- [https://github.com/lazaars/UltraRealy_with_CVE-2019-1040](https://github.com/lazaars/UltraRealy_with_CVE-2019-1040) :  ![starts](https://img.shields.io/github/stars/lazaars/UltraRealy_with_CVE-2019-1040.svg) ![forks](https://img.shields.io/github/forks/lazaars/UltraRealy_with_CVE-2019-1040.svg)


## CVE-2019-1006
 An authentication bypass vulnerability exists in Windows Communication Foundation (WCF) and Windows Identity Foundation (WIF), allowing signing of SAML tokens with arbitrary symmetric keys, aka 'WCF/WIF SAML Token Authentication Bypass Vulnerability'.

- [https://github.com/521526/CVE-2019-1006](https://github.com/521526/CVE-2019-1006) :  ![starts](https://img.shields.io/github/stars/521526/CVE-2019-1006.svg) ![forks](https://img.shields.io/github/forks/521526/CVE-2019-1006.svg)


## CVE-2018-8617
 A remote code execution vulnerability exists in the way that the Chakra scripting engine handles objects in memory in Microsoft Edge, aka &quot;Chakra Scripting Engine Memory Corruption Vulnerability.&quot; This affects Microsoft Edge, ChakraCore. This CVE ID is unique from CVE-2018-8583, CVE-2018-8618, CVE-2018-8624, CVE-2018-8629.

- [https://github.com/bb33bb/cve-2018-8617-aab-r-w-](https://github.com/bb33bb/cve-2018-8617-aab-r-w-) :  ![starts](https://img.shields.io/github/stars/bb33bb/cve-2018-8617-aab-r-w-.svg) ![forks](https://img.shields.io/github/forks/bb33bb/cve-2018-8617-aab-r-w-.svg)


## CVE-2018-8033
 In Apache OFBiz 16.11.01 to 16.11.04, the OFBiz HTTP engine (org.apache.ofbiz.service.engine.HttpEngine.java) handles requests for HTTP services via the /webtools/control/httpService endpoint. Both POST and GET requests to the httpService endpoint may contain three parameters: serviceName, serviceMode, and serviceContext. The exploitation occurs by having DOCTYPEs pointing to external references that trigger a payload that returns secret information from the host.

- [https://github.com/Cappricio-Securities/CVE-2018-8033](https://github.com/Cappricio-Securities/CVE-2018-8033) :  ![starts](https://img.shields.io/github/stars/Cappricio-Securities/CVE-2018-8033.svg) ![forks](https://img.shields.io/github/forks/Cappricio-Securities/CVE-2018-8033.svg)


## CVE-2018-1932
 IBM API Connect 5.0.0.0 through 5.0.8.4 is affected by a vulnerability in the role-based access control in the management server that could allow an authenticated user to obtain highly sensitive information. IBM X-Force ID: 153175.

- [https://github.com/BKreisel/CVE-2018-1932X](https://github.com/BKreisel/CVE-2018-1932X) :  ![starts](https://img.shields.io/github/stars/BKreisel/CVE-2018-1932X.svg) ![forks](https://img.shields.io/github/forks/BKreisel/CVE-2018-1932X.svg)


## CVE-2018-1335
 From Apache Tika versions 1.7 to 1.17, clients could send carefully crafted headers to tika-server that could be used to inject commands into the command line of the server running tika-server. This vulnerability only affects those running tika-server on a server that is open to untrusted clients. The mitigation is to upgrade to Tika 1.18.

- [https://github.com/SkyBlueEternal/CVE-2018-1335-EXP-GUI](https://github.com/SkyBlueEternal/CVE-2018-1335-EXP-GUI) :  ![starts](https://img.shields.io/github/stars/SkyBlueEternal/CVE-2018-1335-EXP-GUI.svg) ![forks](https://img.shields.io/github/forks/SkyBlueEternal/CVE-2018-1335-EXP-GUI.svg)
- [https://github.com/canumay/cve-2018-1335](https://github.com/canumay/cve-2018-1335) :  ![starts](https://img.shields.io/github/stars/canumay/cve-2018-1335.svg) ![forks](https://img.shields.io/github/forks/canumay/cve-2018-1335.svg)
- [https://github.com/siramk/CVE-2018-1335](https://github.com/siramk/CVE-2018-1335) :  ![starts](https://img.shields.io/github/stars/siramk/CVE-2018-1335.svg) ![forks](https://img.shields.io/github/forks/siramk/CVE-2018-1335.svg)
- [https://github.com/N0b1e6/CVE-2018-1335-Python3](https://github.com/N0b1e6/CVE-2018-1335-Python3) :  ![starts](https://img.shields.io/github/stars/N0b1e6/CVE-2018-1335-Python3.svg) ![forks](https://img.shields.io/github/forks/N0b1e6/CVE-2018-1335-Python3.svg)


## CVE-2018-1324
 A specially crafted ZIP archive can be used to cause an infinite loop inside of Apache Commons Compress' extra field parser used by the ZipFile and ZipArchiveInputStream classes in versions 1.11 to 1.15. This can be used to mount a denial of service attack against services that use Compress' zip package.

- [https://github.com/tafamace/CVE-2018-1324](https://github.com/tafamace/CVE-2018-1324) :  ![starts](https://img.shields.io/github/stars/tafamace/CVE-2018-1324.svg) ![forks](https://img.shields.io/github/forks/tafamace/CVE-2018-1324.svg)


## CVE-2018-1313
 In Apache Derby 10.3.1.4 to 10.14.1.0, a specially-crafted network packet can be used to request the Derby Network Server to boot a database whose location and contents are under the user's control. If the Derby Network Server is not running with a Java Security Manager policy file, the attack is successful. If the server is using a policy file, the policy file must permit the database location to be read for the attack to work. The default Derby Network Server policy file distributed with the affected releases includes a permissive policy as the default Network Server policy, which allows the attack to work.

- [https://github.com/tafamace/CVE-2018-1313](https://github.com/tafamace/CVE-2018-1313) :  ![starts](https://img.shields.io/github/stars/tafamace/CVE-2018-1313.svg) ![forks](https://img.shields.io/github/forks/tafamace/CVE-2018-1313.svg)


## CVE-2018-1311
 The Apache Xerces-C 3.0.0 to 3.2.3 XML parser contains a use-after-free error triggered during the scanning of external DTDs. This flaw has not been addressed in the maintained version of the library and has no current mitigation other than to disable DTD processing. This can be accomplished via the DOM using a standard parser feature, or via SAX using the XERCES_DISABLE_DTD environment variable.

- [https://github.com/johnjamesmccann/xerces-3.2.3-DTD-hotfix](https://github.com/johnjamesmccann/xerces-3.2.3-DTD-hotfix) :  ![starts](https://img.shields.io/github/stars/johnjamesmccann/xerces-3.2.3-DTD-hotfix.svg) ![forks](https://img.shields.io/github/forks/johnjamesmccann/xerces-3.2.3-DTD-hotfix.svg)


## CVE-2018-1306
 The PortletV3AnnotatedDemo Multipart Portlet war file code provided in Apache Pluto version 3.0.0 could allow a remote attacker to obtain sensitive information, caused by the failure to restrict path information provided during a file upload. An attacker could exploit this vulnerability to obtain configuration data and other sensitive information.

- [https://github.com/JJSO12/Apache-Pluto-3.0.0--CVE-2018-1306](https://github.com/JJSO12/Apache-Pluto-3.0.0--CVE-2018-1306) :  ![starts](https://img.shields.io/github/stars/JJSO12/Apache-Pluto-3.0.0--CVE-2018-1306.svg) ![forks](https://img.shields.io/github/forks/JJSO12/Apache-Pluto-3.0.0--CVE-2018-1306.svg)


## CVE-2018-1305
 Security constraints defined by annotations of Servlets in Apache Tomcat 9.0.0.M1 to 9.0.4, 8.5.0 to 8.5.27, 8.0.0.RC1 to 8.0.49 and 7.0.0 to 7.0.84 were only applied once a Servlet had been loaded. Because security constraints defined in this way apply to the URL pattern and any URLs below that point, it was possible - depending on the order Servlets were loaded - for some security constraints not to be applied. This could have exposed resources to users who were not authorised to access them.

- [https://github.com/Pa55w0rd/CVE-2018-1305](https://github.com/Pa55w0rd/CVE-2018-1305) :  ![starts](https://img.shields.io/github/stars/Pa55w0rd/CVE-2018-1305.svg) ![forks](https://img.shields.io/github/forks/Pa55w0rd/CVE-2018-1305.svg)


## CVE-2018-1304
 The URL pattern of &quot;&quot; (the empty string) which exactly maps to the context root was not correctly handled in Apache Tomcat 9.0.0.M1 to 9.0.4, 8.5.0 to 8.5.27, 8.0.0.RC1 to 8.0.49 and 7.0.0 to 7.0.84 when used as part of a security constraint definition. This caused the constraint to be ignored. It was, therefore, possible for unauthorised users to gain access to web application resources that should have been protected. Only security constraints with a URL pattern of the empty string were affected.

- [https://github.com/knqyf263/CVE-2018-1304](https://github.com/knqyf263/CVE-2018-1304) :  ![starts](https://img.shields.io/github/stars/knqyf263/CVE-2018-1304.svg) ![forks](https://img.shields.io/github/forks/knqyf263/CVE-2018-1304.svg)
- [https://github.com/thariyarox/tomcat_CVE-2018-1304_testing](https://github.com/thariyarox/tomcat_CVE-2018-1304_testing) :  ![starts](https://img.shields.io/github/stars/thariyarox/tomcat_CVE-2018-1304_testing.svg) ![forks](https://img.shields.io/github/forks/thariyarox/tomcat_CVE-2018-1304_testing.svg)


## CVE-2018-1297
 When using Distributed Test only (RMI based), Apache JMeter 2.x and 3.x uses an unsecured RMI connection. This could allow an attacker to get Access to JMeterEngine and send unauthorized code.

- [https://github.com/Al1ex/CVE-2018-1297](https://github.com/Al1ex/CVE-2018-1297) :  ![starts](https://img.shields.io/github/stars/Al1ex/CVE-2018-1297.svg) ![forks](https://img.shields.io/github/forks/Al1ex/CVE-2018-1297.svg)
- [https://github.com/48484848484848/Jmeter-CVE-2018-1297-](https://github.com/48484848484848/Jmeter-CVE-2018-1297-) :  ![starts](https://img.shields.io/github/stars/48484848484848/Jmeter-CVE-2018-1297-.svg) ![forks](https://img.shields.io/github/forks/48484848484848/Jmeter-CVE-2018-1297-.svg)


## CVE-2018-1288
 In Apache Kafka 0.9.0.0 to 0.9.0.1, 0.10.0.0 to 0.10.2.1, 0.11.0.0 to 0.11.0.2, and 1.0.0, authenticated Kafka users may perform action reserved for the Broker via a manually created fetch request interfering with data replication, resulting in data loss.

- [https://github.com/joegallagher4/CVE-2018-1288-](https://github.com/joegallagher4/CVE-2018-1288-) :  ![starts](https://img.shields.io/github/stars/joegallagher4/CVE-2018-1288-.svg) ![forks](https://img.shields.io/github/forks/joegallagher4/CVE-2018-1288-.svg)


## CVE-2018-1285
 Apache log4net versions before 2.0.10 do not disable XML external entities when parsing log4net configuration files. This allows for XXE-based attacks in applications that accept attacker-controlled log4net configuration files.

- [https://github.com/alex-ermolaev/Log4NetSolarWindsSNMP-](https://github.com/alex-ermolaev/Log4NetSolarWindsSNMP-) :  ![starts](https://img.shields.io/github/stars/alex-ermolaev/Log4NetSolarWindsSNMP-.svg) ![forks](https://img.shields.io/github/forks/alex-ermolaev/Log4NetSolarWindsSNMP-.svg)


## CVE-2018-1273
 Spring Data Commons, versions prior to 1.13 to 1.13.10, 2.0 to 2.0.5, and older unsupported versions, contain a property binder vulnerability caused by improper neutralization of special elements. An unauthenticated remote malicious user (or attacker) can supply specially crafted request parameters against Spring Data REST backed HTTP resources or using Spring Data's projection-based request payload binding hat can lead to a remote code execution attack.

- [https://github.com/AabyssZG/SpringBoot-Scan](https://github.com/AabyssZG/SpringBoot-Scan) :  ![starts](https://img.shields.io/github/stars/AabyssZG/SpringBoot-Scan.svg) ![forks](https://img.shields.io/github/forks/AabyssZG/SpringBoot-Scan.svg)
- [https://github.com/sule01u/SBSCAN](https://github.com/sule01u/SBSCAN) :  ![starts](https://img.shields.io/github/stars/sule01u/SBSCAN.svg) ![forks](https://img.shields.io/github/forks/sule01u/SBSCAN.svg)
- [https://github.com/jas502n/cve-2018-1273](https://github.com/jas502n/cve-2018-1273) :  ![starts](https://img.shields.io/github/stars/jas502n/cve-2018-1273.svg) ![forks](https://img.shields.io/github/forks/jas502n/cve-2018-1273.svg)
- [https://github.com/wearearima/poc-cve-2018-1273](https://github.com/wearearima/poc-cve-2018-1273) :  ![starts](https://img.shields.io/github/stars/wearearima/poc-cve-2018-1273.svg) ![forks](https://img.shields.io/github/forks/wearearima/poc-cve-2018-1273.svg)
- [https://github.com/knqyf263/CVE-2018-1273](https://github.com/knqyf263/CVE-2018-1273) :  ![starts](https://img.shields.io/github/stars/knqyf263/CVE-2018-1273.svg) ![forks](https://img.shields.io/github/forks/knqyf263/CVE-2018-1273.svg)
- [https://github.com/webr0ck/poc-cve-2018-1273](https://github.com/webr0ck/poc-cve-2018-1273) :  ![starts](https://img.shields.io/github/stars/webr0ck/poc-cve-2018-1273.svg) ![forks](https://img.shields.io/github/forks/webr0ck/poc-cve-2018-1273.svg)
- [https://github.com/cved-sources/cve-2018-1273](https://github.com/cved-sources/cve-2018-1273) :  ![starts](https://img.shields.io/github/stars/cved-sources/cve-2018-1273.svg) ![forks](https://img.shields.io/github/forks/cved-sources/cve-2018-1273.svg)


## CVE-2018-1270
 Spring Framework, versions 5.0 prior to 5.0.5 and versions 4.3 prior to 4.3.15 and older unsupported versions, allow applications to expose STOMP over WebSocket endpoints with a simple, in-memory STOMP broker through the spring-messaging module. A malicious user (or attacker) can craft a message to the broker that can lead to a remote code execution attack.

- [https://github.com/CaledoniaProject/CVE-2018-1270](https://github.com/CaledoniaProject/CVE-2018-1270) :  ![starts](https://img.shields.io/github/stars/CaledoniaProject/CVE-2018-1270.svg) ![forks](https://img.shields.io/github/forks/CaledoniaProject/CVE-2018-1270.svg)
- [https://github.com/genxor/CVE-2018-1270_EXP](https://github.com/genxor/CVE-2018-1270_EXP) :  ![starts](https://img.shields.io/github/stars/genxor/CVE-2018-1270_EXP.svg) ![forks](https://img.shields.io/github/forks/genxor/CVE-2018-1270_EXP.svg)
- [https://github.com/Venscor/CVE-2018-1270](https://github.com/Venscor/CVE-2018-1270) :  ![starts](https://img.shields.io/github/stars/Venscor/CVE-2018-1270.svg) ![forks](https://img.shields.io/github/forks/Venscor/CVE-2018-1270.svg)
- [https://github.com/tafamace/CVE-2018-1270](https://github.com/tafamace/CVE-2018-1270) :  ![starts](https://img.shields.io/github/stars/tafamace/CVE-2018-1270.svg) ![forks](https://img.shields.io/github/forks/tafamace/CVE-2018-1270.svg)
- [https://github.com/mprunet/owasp-formation-cve-2018-1270](https://github.com/mprunet/owasp-formation-cve-2018-1270) :  ![starts](https://img.shields.io/github/stars/mprunet/owasp-formation-cve-2018-1270.svg) ![forks](https://img.shields.io/github/forks/mprunet/owasp-formation-cve-2018-1270.svg)


## CVE-2018-1263
 Addresses partial fix in CVE-2018-1261. Pivotal spring-integration-zip, versions prior to 1.0.2, exposes an arbitrary file write vulnerability, that can be achieved using a specially crafted zip archive (affects other archives as well, bzip2, tar, xz, war, cpio, 7z), that holds path traversal filenames. So when the filename gets concatenated to the target extraction directory, the final path ends up outside of the target folder.

- [https://github.com/sakib570/CVE-2018-1263-Demo](https://github.com/sakib570/CVE-2018-1263-Demo) :  ![starts](https://img.shields.io/github/stars/sakib570/CVE-2018-1263-Demo.svg) ![forks](https://img.shields.io/github/forks/sakib570/CVE-2018-1263-Demo.svg)


## CVE-2018-1259
 Spring Data Commons, versions 1.13 prior to 1.13.12 and 2.0 prior to 2.0.7, used in combination with XMLBeam 1.4.14 or earlier versions, contains a property binder vulnerability caused by improper restriction of XML external entity references as underlying library XMLBeam does not restrict external reference expansion. An unauthenticated remote malicious user can supply specially crafted request parameters against Spring Data's projection-based request payload binding to access arbitrary files on the system.

- [https://github.com/tafamace/CVE-2018-1259](https://github.com/tafamace/CVE-2018-1259) :  ![starts](https://img.shields.io/github/stars/tafamace/CVE-2018-1259.svg) ![forks](https://img.shields.io/github/forks/tafamace/CVE-2018-1259.svg)


## CVE-2018-1235
 Dell EMC RecoverPoint versions prior to 5.1.2 and RecoverPoint for VMs versions prior to 5.1.1.3, contain a command injection vulnerability. An unauthenticated remote attacker may potentially exploit this vulnerability to execute arbitrary commands on the affected system with root privilege.

- [https://github.com/AbsoZed/CVE-2018-1235](https://github.com/AbsoZed/CVE-2018-1235) :  ![starts](https://img.shields.io/github/stars/AbsoZed/CVE-2018-1235.svg) ![forks](https://img.shields.io/github/forks/AbsoZed/CVE-2018-1235.svg)


## CVE-2018-1207
 Dell EMC iDRAC7/iDRAC8, versions prior to 2.52.52.52, contain CGI injection vulnerability which could be used to execute remote code. A remote unauthenticated attacker may potentially be able to use CGI variables to execute remote code.

- [https://github.com/mgargiullo/cve-2018-1207](https://github.com/mgargiullo/cve-2018-1207) :  ![starts](https://img.shields.io/github/stars/mgargiullo/cve-2018-1207.svg) ![forks](https://img.shields.io/github/forks/mgargiullo/cve-2018-1207.svg)
- [https://github.com/un4gi/CVE-2018-1207](https://github.com/un4gi/CVE-2018-1207) :  ![starts](https://img.shields.io/github/stars/un4gi/CVE-2018-1207.svg) ![forks](https://img.shields.io/github/forks/un4gi/CVE-2018-1207.svg)


## CVE-2018-1160
 Netatalk before 3.1.12 is vulnerable to an out of bounds write in dsi_opensess.c. This is due to lack of bounds checking on attacker controlled data. A remote unauthenticated attacker can leverage this vulnerability to achieve arbitrary code execution.

- [https://github.com/SachinThanushka/CVE-2018-1160](https://github.com/SachinThanushka/CVE-2018-1160) :  ![starts](https://img.shields.io/github/stars/SachinThanushka/CVE-2018-1160.svg) ![forks](https://img.shields.io/github/forks/SachinThanushka/CVE-2018-1160.svg)


## CVE-2018-1133
 An issue was discovered in Moodle 3.x. A Teacher creating a Calculated question can intentionally cause remote code execution on the server, aka eval injection.

- [https://github.com/cocomelonc/vulnexipy](https://github.com/cocomelonc/vulnexipy) :  ![starts](https://img.shields.io/github/stars/cocomelonc/vulnexipy.svg) ![forks](https://img.shields.io/github/forks/cocomelonc/vulnexipy.svg)
- [https://github.com/darrynten/MoodleExploit](https://github.com/darrynten/MoodleExploit) :  ![starts](https://img.shields.io/github/stars/darrynten/MoodleExploit.svg) ![forks](https://img.shields.io/github/forks/darrynten/MoodleExploit.svg)
- [https://github.com/That-Guy-Steve/CVE-2018-1133-Exploit](https://github.com/That-Guy-Steve/CVE-2018-1133-Exploit) :  ![starts](https://img.shields.io/github/stars/That-Guy-Steve/CVE-2018-1133-Exploit.svg) ![forks](https://img.shields.io/github/forks/That-Guy-Steve/CVE-2018-1133-Exploit.svg)
- [https://github.com/Feidao-fei/MOODLE-3.X-Remote-Code-Execution](https://github.com/Feidao-fei/MOODLE-3.X-Remote-Code-Execution) :  ![starts](https://img.shields.io/github/stars/Feidao-fei/MOODLE-3.X-Remote-Code-Execution.svg) ![forks](https://img.shields.io/github/forks/Feidao-fei/MOODLE-3.X-Remote-Code-Execution.svg)


## CVE-2018-1123
 procps-ng before version 3.3.15 is vulnerable to a denial of service in ps via mmap buffer overflow. Inbuilt protection in ps maps a guard page at the end of the overflowed buffer, ensuring that the impact of this flaw is limited to a crash (temporary denial of service).

- [https://github.com/aravinddathd/CVE-2018-1123](https://github.com/aravinddathd/CVE-2018-1123) :  ![starts](https://img.shields.io/github/stars/aravinddathd/CVE-2018-1123.svg) ![forks](https://img.shields.io/github/forks/aravinddathd/CVE-2018-1123.svg)


## CVE-2018-1112
 glusterfs server before versions 3.10.12, 4.0.2 is vulnerable when using 'auth.allow' option which allows any unauthenticated gluster client to connect from any network to mount gluster storage volumes. NOTE: this vulnerability exists because of a CVE-2018-1088 regression.

- [https://github.com/MauroEldritch/GEVAUDAN](https://github.com/MauroEldritch/GEVAUDAN) :  ![starts](https://img.shields.io/github/stars/MauroEldritch/GEVAUDAN.svg) ![forks](https://img.shields.io/github/forks/MauroEldritch/GEVAUDAN.svg)


## CVE-2018-1111
 DHCP packages in Red Hat Enterprise Linux 6 and 7, Fedora 28, and earlier are vulnerable to a command injection flaw in the NetworkManager integration script included in the DHCP client. A malicious DHCP server, or an attacker on the local network able to spoof DHCP responses, could use this flaw to execute arbitrary commands with root privileges on systems using NetworkManager and configured to obtain network configuration using the DHCP protocol.

- [https://github.com/knqyf263/CVE-2018-1111](https://github.com/knqyf263/CVE-2018-1111) :  ![starts](https://img.shields.io/github/stars/knqyf263/CVE-2018-1111.svg) ![forks](https://img.shields.io/github/forks/knqyf263/CVE-2018-1111.svg)
- [https://github.com/kkirsche/CVE-2018-1111](https://github.com/kkirsche/CVE-2018-1111) :  ![starts](https://img.shields.io/github/stars/kkirsche/CVE-2018-1111.svg) ![forks](https://img.shields.io/github/forks/kkirsche/CVE-2018-1111.svg)
- [https://github.com/baldassarreFe/FEP3370-advanced-ethical-hacking](https://github.com/baldassarreFe/FEP3370-advanced-ethical-hacking) :  ![starts](https://img.shields.io/github/stars/baldassarreFe/FEP3370-advanced-ethical-hacking.svg) ![forks](https://img.shields.io/github/forks/baldassarreFe/FEP3370-advanced-ethical-hacking.svg)


## CVE-2018-1088
 A privilege escalation flaw was found in gluster 3.x snapshot scheduler. Any gluster client allowed to mount gluster volumes could also mount shared gluster storage volume and escalate privileges by scheduling malicious cronjob via symlink.

- [https://github.com/MauroEldritch/GEVAUDAN](https://github.com/MauroEldritch/GEVAUDAN) :  ![starts](https://img.shields.io/github/stars/MauroEldritch/GEVAUDAN.svg) ![forks](https://img.shields.io/github/forks/MauroEldritch/GEVAUDAN.svg)


## CVE-2018-1042
 Moodle 3.x has Server Side Request Forgery in the filepicker.

- [https://github.com/UDPsycho/Moodle-CVE-2018-1042](https://github.com/UDPsycho/Moodle-CVE-2018-1042) :  ![starts](https://img.shields.io/github/stars/UDPsycho/Moodle-CVE-2018-1042.svg) ![forks](https://img.shields.io/github/forks/UDPsycho/Moodle-CVE-2018-1042.svg)


## CVE-2018-1026
 A remote code execution vulnerability exists in Microsoft Office software when the software fails to properly handle objects in memory, aka &quot;Microsoft Office Remote Code Execution Vulnerability.&quot; This affects Microsoft Office. This CVE ID is unique from CVE-2018-1030.

- [https://github.com/ymgh96/Detecting-the-CVE-2018-1026-and-its-patch](https://github.com/ymgh96/Detecting-the-CVE-2018-1026-and-its-patch) :  ![starts](https://img.shields.io/github/stars/ymgh96/Detecting-the-CVE-2018-1026-and-its-patch.svg) ![forks](https://img.shields.io/github/forks/ymgh96/Detecting-the-CVE-2018-1026-and-its-patch.svg)


## CVE-2018-1010
 A remote code execution vulnerability exists when the Windows font library improperly handles specially crafted embedded fonts, aka &quot;Microsoft Graphics Remote Code Execution Vulnerability.&quot; This affects Windows 7, Windows Server 2012 R2, Windows RT 8.1, Windows Server 2008, Windows Server 2012, Windows 8.1, Windows Server 2016, Windows Server 2008 R2, Windows 10, Windows 10 Servers. This CVE ID is unique from CVE-2018-1012, CVE-2018-1013, CVE-2018-1015, CVE-2018-1016.

- [https://github.com/ymgh96/Detecting-the-patch-of-CVE-2018-1010](https://github.com/ymgh96/Detecting-the-patch-of-CVE-2018-1010) :  ![starts](https://img.shields.io/github/stars/ymgh96/Detecting-the-patch-of-CVE-2018-1010.svg) ![forks](https://img.shields.io/github/forks/ymgh96/Detecting-the-patch-of-CVE-2018-1010.svg)


## CVE-2017-1635
 IBM Tivoli Monitoring V6 6.2.2.x could allow a remote attacker to execute arbitrary code on the system, caused by a use-after-free error. A remote attacker could exploit this vulnerability to execute arbitrary code on the system or cause the application to crash. IBM X-Force ID: 133243.

- [https://github.com/emcalv/tivoli-poc](https://github.com/emcalv/tivoli-poc) :  ![starts](https://img.shields.io/github/stars/emcalv/tivoli-poc.svg) ![forks](https://img.shields.io/github/forks/emcalv/tivoli-poc.svg)
- [https://github.com/bcdannyboy/cve-2017-1635-PoC](https://github.com/bcdannyboy/cve-2017-1635-PoC) :  ![starts](https://img.shields.io/github/stars/bcdannyboy/cve-2017-1635-PoC.svg) ![forks](https://img.shields.io/github/forks/bcdannyboy/cve-2017-1635-PoC.svg)


## CVE-2015-20107
 In Python (aka CPython) up to 3.10.8, the mailcap module does not add escape characters into commands discovered in the system mailcap file. This may allow attackers to inject shell commands into applications that call mailcap.findmatch with untrusted input (if they lack validation of user-provided filenames or arguments). The fix is also back-ported to 3.7, 3.8, 3.9

- [https://github.com/codeskipper/Snake-Patrol](https://github.com/codeskipper/Snake-Patrol) :  ![starts](https://img.shields.io/github/stars/codeskipper/Snake-Patrol.svg) ![forks](https://img.shields.io/github/forks/codeskipper/Snake-Patrol.svg)

