# Update 2023-02-05
## CVE-2023-25139
 sprintf in the GNU C Library (glibc) 2.37 has a buffer overflow (out-of-bounds write) in some situations with a correct buffer size. This is unrelated to CWE-676. It may write beyond the bounds of the destination buffer when attempting to write a padded, thousands-separated string representation of a number, if the buffer is allocated the exact size required to represent that number as a string. For example, 1,234,567 (with padding to 13) overflows by two bytes.

- [https://github.com/Live-Hack-CVE/CVE-2023-25139](https://github.com/Live-Hack-CVE/CVE-2023-25139) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-25139.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-25139.svg)


## CVE-2023-25136
 OpenSSH server (sshd) 9.1 introduced a double-free vulnerability during options.kex_algorithms handling. This is fixed in OpenSSH 9.2. The double free can be triggered by an unauthenticated attacker in the default configuration; however, the vulnerability discoverer reports that &quot;exploiting this vulnerability will not be easy.&quot;

- [https://github.com/Live-Hack-CVE/CVE-2023-25136](https://github.com/Live-Hack-CVE/CVE-2023-25136) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-25136.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-25136.svg)


## CVE-2023-25135
 vBulletin before 5.6.9 PL1 allows an unauthenticated remote attacker to execute arbitrary code via a crafted HTTP request that triggers deserialization. This occurs because verify_serialized checks that a value is serialized by calling unserialize and then checking for errors. The fixed versions are 5.6.7 PL1, 5.6.8 PL1, and 5.6.9 PL1.

- [https://github.com/Live-Hack-CVE/CVE-2023-25135](https://github.com/Live-Hack-CVE/CVE-2023-25135) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-25135.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-25135.svg)


## CVE-2023-24806
 ** REJECT ** DO NOT USE THIS CANDIDATE NUMBER. Reason: This CVE has been rejected as it was incorrectly assigned. All references and descriptions in this candidate have been removed to prevent accidental usage.

- [https://github.com/Live-Hack-CVE/CVE-2023-24806](https://github.com/Live-Hack-CVE/CVE-2023-24806) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24806.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24806.svg)


## CVE-2023-24426
 Jenkins Azure AD Plugin 303.va_91ef20ee49f and earlier does not invalidate the previous session on login.

- [https://github.com/Live-Hack-CVE/CVE-2023-24426](https://github.com/Live-Hack-CVE/CVE-2023-24426) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24426.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24426.svg)


## CVE-2023-24425
 Jenkins Kubernetes Credentials Provider Plugin 1.208.v128ee9800c04 and earlier does not set the appropriate context for Kubernetes credentials lookup, allowing attackers with Item/Configure permission to access and potentially capture Kubernetes credentials they are not entitled to.

- [https://github.com/Live-Hack-CVE/CVE-2023-24425](https://github.com/Live-Hack-CVE/CVE-2023-24425) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24425.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24425.svg)


## CVE-2023-24138
 TOTOLINK CA300-PoE V6.2c.884 was discovered to contain a command injection vulnerability via the host_time parameter in the NTPSyncWithHost function.

- [https://github.com/Live-Hack-CVE/CVE-2023-24138](https://github.com/Live-Hack-CVE/CVE-2023-24138) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24138.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24138.svg)


## CVE-2023-23615
 Discourse is an open source discussion platform. The embeddable comments can be exploited to create new topics as any user but without any clear title or content. This issue is patched in the latest stable, beta and tests-passed versions of Discourse. As a workaround, disable embeddable comments by deleting all embeddable hosts.

- [https://github.com/Live-Hack-CVE/CVE-2023-23615](https://github.com/Live-Hack-CVE/CVE-2023-23615) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23615.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23615.svg)


## CVE-2023-23130
 ** DISPUTED ** Connectwise Automate 2022.11 is vulnerable to Cleartext authentication. Authentication is being done via HTTP (cleartext) with SSL disabled. OTE: the vendor's position is that, by design, this is controlled by a configuration option in which a customer can choose to use HTTP (rather than HTTPS) during troubleshooting.

- [https://github.com/Live-Hack-CVE/CVE-2023-23130](https://github.com/Live-Hack-CVE/CVE-2023-23130) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23130.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23130.svg)


## CVE-2023-23126
 ** DISPUTED ** Connectwise Automate 2022.11 is vulnerable to Clickjacking. The login screen can be iframed and used to manipulate users to perform unintended actions. NOTE: the vendor's position is that a Content-Security-Policy HTTP response header is present to block this attack.

- [https://github.com/Live-Hack-CVE/CVE-2023-23126](https://github.com/Live-Hack-CVE/CVE-2023-23126) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23126.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23126.svg)


## CVE-2023-23120
 The use of the cyclic redundancy check (CRC) algorithm for integrity check during firmware update makes TRENDnet TV-IP651WI Network Camera firmware version v1.07.01 and earlier vulnerable to firmware modification attacks. An attacker can conduct a man-in-the-middle (MITM) attack to modify the new firmware image and bypass the checksum verification.

- [https://github.com/Live-Hack-CVE/CVE-2023-23120](https://github.com/Live-Hack-CVE/CVE-2023-23120) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23120.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23120.svg)


## CVE-2023-23119
 The use of the cyclic redundancy check (CRC) algorithm for integrity check during firmware update makes Ubiquiti airFiber AF2X Radio firmware version 3.2.2 and earlier vulnerable to firmware modification attacks. An attacker can conduct a man-in-the-middle (MITM) attack to modify the new firmware image and bypass the checksum verification.

- [https://github.com/Live-Hack-CVE/CVE-2023-23119](https://github.com/Live-Hack-CVE/CVE-2023-23119) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23119.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23119.svg)


## CVE-2023-23082
 A heap buffer overflow vulnerability in Kodi Home Theater Software up to 19.5 allows attackers to cause a denial of service due to an improper length of the value passed to the offset argument.

- [https://github.com/Live-Hack-CVE/CVE-2023-23082](https://github.com/Live-Hack-CVE/CVE-2023-23082) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23082.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23082.svg)


## CVE-2023-22746
 CKAN is an open-source DMS (data management system) for powering data hubs and data portals. When creating a new container based on one of the Docker images listed below, the same secret key was being used by default. If the users didn't set a custom value via environment variables in the `.env` file, that key was shared across different CKAN instances, making it easy to forge authentication requests. Users overriding the default secret key in their own `.env` file are not affected by this issue. Note that the legacy images (ckan/ckan) located in the main CKAN repo are not affected by this issue. The affected images are ckan/ckan-docker, (ckan/ckan-base images), okfn/docker-ckan (openknowledge/ckan-base and openknowledge/ckan-dev images) keitaroinc/docker-ckan (keitaro/ckan images).

- [https://github.com/Live-Hack-CVE/CVE-2023-22746](https://github.com/Live-Hack-CVE/CVE-2023-22746) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22746.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22746.svg)


## CVE-2023-0549
 A vulnerability, which was classified as problematic, has been found in YAFNET up to 3.1.10. This issue affects some unknown processing of the file /forum/PostPrivateMessage of the component Private Message Handler. The manipulation of the argument subject/message leads to cross site scripting. The attack may be initiated remotely. The exploit has been disclosed to the public and may be used. Upgrading to version 3.1.11 is able to address this issue. The name of the patch is 2237a9d552e258a43570bb478a92a5505e7c8797. It is recommended to upgrade the affected component. The identifier VDB-219665 was assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2023-0549](https://github.com/Live-Hack-CVE/CVE-2023-0549) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0549.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0549.svg)


## CVE-2023-0124
 Delta Electronics DOPSoft versions 4.00.16.22 and prior are vulnerable to an out-of-bounds write, which could allow an attacker to remotely execute arbitrary code when a malformed file is introduced to the software.

- [https://github.com/Live-Hack-CVE/CVE-2023-0124](https://github.com/Live-Hack-CVE/CVE-2023-0124) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0124.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0124.svg)


## CVE-2023-0123
 Delta Electronics DOPSoft versions 4.00.16.22 and prior are vulnerable to a stack-based buffer overflow, which could allow an attacker to remotely execute arbitrary code when a malformed file is introduced to the software.

- [https://github.com/Live-Hack-CVE/CVE-2023-0123](https://github.com/Live-Hack-CVE/CVE-2023-0123) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0123.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0123.svg)


## CVE-2023-0045
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/es0j/CVE-2023-0045](https://github.com/es0j/CVE-2023-0045) :  ![starts](https://img.shields.io/github/stars/es0j/CVE-2023-0045.svg) ![forks](https://img.shields.io/github/forks/es0j/CVE-2023-0045.svg)


## CVE-2022-48311
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/swzhouu/CVE-2022-48311](https://github.com/swzhouu/CVE-2022-48311) :  ![starts](https://img.shields.io/github/stars/swzhouu/CVE-2022-48311.svg) ![forks](https://img.shields.io/github/forks/swzhouu/CVE-2022-48311.svg)


## CVE-2022-48074
 An issue in NoMachine before v8.2.3 allows attackers to execute arbitrary commands via a crafted .nxs file.

- [https://github.com/Live-Hack-CVE/CVE-2022-48074](https://github.com/Live-Hack-CVE/CVE-2022-48074) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-48074.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-48074.svg)


## CVE-2022-48010
 LimeSurvey v5.4.15 was discovered to contain a stored cross-site scripting (XSS) vulnerability in the component /index.php/surveyAdministration/rendersidemenulink?subaction=surveytexts. This vulnerability allows attackers to execute arbitrary web scripts or HTML via a crafted payload injected into the Description or Welcome-message text fields.

- [https://github.com/Live-Hack-CVE/CVE-2022-48010](https://github.com/Live-Hack-CVE/CVE-2022-48010) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-48010.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-48010.svg)


## CVE-2022-48008
 An arbitrary file upload vulnerability in the plugin manager of LimeSurvey v5.4.15 allows attackers to execute arbitrary code via a crafted PHP file.

- [https://github.com/Live-Hack-CVE/CVE-2022-48008](https://github.com/Live-Hack-CVE/CVE-2022-48008) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-48008.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-48008.svg)


## CVE-2022-48007
 A stored cross-site scripting (XSS) vulnerability in identification.php of Piwigo v13.4.0 allows attackers to execute arbitrary web scripts or HTML via a crafted payload injected into the User-Agent.

- [https://github.com/Live-Hack-CVE/CVE-2022-48007](https://github.com/Live-Hack-CVE/CVE-2022-48007) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-48007.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-48007.svg)


## CVE-2022-46689
 A race condition was addressed with additional validation. This issue is fixed in tvOS 16.2, macOS Monterey 12.6.2, macOS Ventura 13.1, macOS Big Sur 11.7.2, iOS 15.7.2 and iPadOS 15.7.2, iOS 16.2 and iPadOS 16.2, watchOS 9.2. An app may be able to execute arbitrary code with kernel privileges.

- [https://github.com/BomberFish/Whitelist](https://github.com/BomberFish/Whitelist) :  ![starts](https://img.shields.io/github/stars/BomberFish/Whitelist.svg) ![forks](https://img.shields.io/github/forks/BomberFish/Whitelist.svg)


## CVE-2022-46604
 An issue in Tecrail Responsive FileManager v9.9.5 and below allows attackers to bypass the file extension check mechanism and upload a crafted PHP file, leading to arbitrary code execution.

- [https://github.com/galoget/ResponsiveFileManager-CVE-2022-46604](https://github.com/galoget/ResponsiveFileManager-CVE-2022-46604) :  ![starts](https://img.shields.io/github/stars/galoget/ResponsiveFileManager-CVE-2022-46604.svg) ![forks](https://img.shields.io/github/forks/galoget/ResponsiveFileManager-CVE-2022-46604.svg)


## CVE-2022-44268
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/jnschaeffer/cve-2022-44268-detector](https://github.com/jnschaeffer/cve-2022-44268-detector) :  ![starts](https://img.shields.io/github/stars/jnschaeffer/cve-2022-44268-detector.svg) ![forks](https://img.shields.io/github/forks/jnschaeffer/cve-2022-44268-detector.svg)
- [https://github.com/agathanon/cve-2022-44268](https://github.com/agathanon/cve-2022-44268) :  ![starts](https://img.shields.io/github/stars/agathanon/cve-2022-44268.svg) ![forks](https://img.shields.io/github/forks/agathanon/cve-2022-44268.svg)
- [https://github.com/Ashifcoder/CVE-2022-44268-automated-poc](https://github.com/Ashifcoder/CVE-2022-44268-automated-poc) :  ![starts](https://img.shields.io/github/stars/Ashifcoder/CVE-2022-44268-automated-poc.svg) ![forks](https://img.shields.io/github/forks/Ashifcoder/CVE-2022-44268-automated-poc.svg)


## CVE-2022-40998
 Several stack-based buffer overflow vulnerabilities exist in the DetranCLI command parsing functionality of Siretta QUARTZ-GOLD G5.0.1.5-210720-141020. A specially-crafted network packet can lead to arbitrary command execution. An attacker can send a sequence of requests to trigger these vulnerabilities.This buffer overflow is in the function that manages the 'no gre index &lt;1-8&gt; destination A.B.C.D/M description (WORD|null)' command template.

- [https://github.com/Live-Hack-CVE/CVE-2022-40998](https://github.com/Live-Hack-CVE/CVE-2022-40998) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-40998.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-40998.svg)


## CVE-2022-34138
 Insecure direct object references (IDOR) in the web server of Biltema IP and Baby Camera Software v124 allows attackers to access sensitive information.

- [https://github.com/Live-Hack-CVE/CVE-2022-34138](https://github.com/Live-Hack-CVE/CVE-2022-34138) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-34138.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-34138.svg)


## CVE-2022-31144
 Redis is an in-memory database that persists on disk. A specially crafted `XAUTOCLAIM` command on a stream key in a specific state may result with heap overflow, and potentially remote code execution. This problem affects versions on the 7.x branch prior to 7.0.4. The patch is released in version 7.0.4.

- [https://github.com/SpiralBL0CK/CVE-2022-31144](https://github.com/SpiralBL0CK/CVE-2022-31144) :  ![starts](https://img.shields.io/github/stars/SpiralBL0CK/CVE-2022-31144.svg) ![forks](https://img.shields.io/github/forks/SpiralBL0CK/CVE-2022-31144.svg)


## CVE-2022-28711
 A memory corruption vulnerability exists in the cgi.c unescape functionality of ArduPilot APWeb master branch 50b6b7ac - master branch 46177cb9. A specially-crafted HTTP request can lead to memory corruption. An attacker can send a network request to trigger this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2022-28711](https://github.com/Live-Hack-CVE/CVE-2022-28711) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-28711.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-28711.svg)


## CVE-2022-24895
 Symfony is a PHP framework for web and console applications and a set of reusable PHP components. When authenticating users Symfony by default regenerates the session ID upon login, but preserves the rest of session attributes. Because this does not clear CSRF tokens upon login, this might enables same-site attackers to bypass the CSRF protection mechanism by performing an attack similar to a session-fixation. This issue has been fixed in the 4.4 branch.

- [https://github.com/Live-Hack-CVE/CVE-2022-24895](https://github.com/Live-Hack-CVE/CVE-2022-24895) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-24895.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-24895.svg)


## CVE-2022-24894
 Symfony is a PHP framework for web and console applications and a set of reusable PHP components. The Symfony HTTP cache system, acts as a reverse proxy: It caches entire responses (including headers) and returns them to the clients. In a recent change in the `AbstractSessionListener`, the response might contain a `Set-Cookie` header. If the Symfony HTTP cache system is enabled, this response might bill stored and return to the next clients. An attacker can use this vulnerability to retrieve the victim's session. This issue has been patched and is available for branch 4.4.

- [https://github.com/Live-Hack-CVE/CVE-2022-24894](https://github.com/Live-Hack-CVE/CVE-2022-24894) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-24894.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-24894.svg)


## CVE-2022-23498
 Grafana is an open-source platform for monitoring and observability. When datasource query caching is enabled, Grafana caches all headers, including `grafana_session`. As a result, any user that queries a datasource where the caching is enabled can acquire another user&#8217;s session. To mitigate the vulnerability you can disable datasource query caching for all datasources. This issue has been patched in versions 9.2.10 and 9.3.4.

- [https://github.com/Live-Hack-CVE/CVE-2022-23498](https://github.com/Live-Hack-CVE/CVE-2022-23498) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-23498.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-23498.svg)


## CVE-2022-3452
 A vulnerability was found in SourceCodester Book Store Management System 1.0. It has been declared as problematic. This vulnerability affects unknown code of the file /category.php. The manipulation of the argument category_name leads to cross site scripting. The attack can be initiated remotely. The identifier of this vulnerability is VDB-210436.

- [https://github.com/Live-Hack-CVE/CVE-2022-3452](https://github.com/Live-Hack-CVE/CVE-2022-3452) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-3452.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-3452.svg)


## CVE-2022-2327
 io_uring use work_flags to determine which identity need to grab from the calling process to make sure it is consistent with the calling process when executing IORING_OP. Some operations are missing some types, which can lead to incorrect reference counts which can then lead to a double free. We recommend upgrading the kernel past commit df3f3bb5059d20ef094d6b2f0256c4bf4127a859

- [https://github.com/Live-Hack-CVE/CVE-2022-2327](https://github.com/Live-Hack-CVE/CVE-2022-2327) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2327.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2327.svg)


## CVE-2022-2044
 MOXA NPort 5110: Firmware Versions 2.10 is vulnerable to an out-of-bounds write that may allow an attacker to overwrite values in memory, causing a denial-of-service condition or potentially bricking the device.

- [https://github.com/Live-Hack-CVE/CVE-2022-2044](https://github.com/Live-Hack-CVE/CVE-2022-2044) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2044.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2044.svg)


## CVE-2021-45868
 In the Linux kernel before 5.15.3, fs/quota/quota_tree.c does not validate the block number in the quota tree (on disk). This can, for example, lead to a kernel/locking/rwsem.c use-after-free if there is a corrupted quota file.

- [https://github.com/Live-Hack-CVE/CVE-2021-45868](https://github.com/Live-Hack-CVE/CVE-2021-45868) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-45868.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-45868.svg)


## CVE-2021-39217
 OpenMage LTS is an e-commerce platform. Prior to versions 19.4.22 and 20.0.19, Custom Layout enabled admin users to execute arbitrary commands via block methods. Versions 19.4.22 and 20.0.19 contain patches for this issue.

- [https://github.com/Live-Hack-CVE/CVE-2021-39217](https://github.com/Live-Hack-CVE/CVE-2021-39217) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-39217.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-39217.svg)


## CVE-2021-28116
 Squid through 4.14 and 5.x through 5.0.5, in some configurations, allows information disclosure because of an out-of-bounds read in WCCP protocol data. This can be leveraged as part of a chain for remote code execution as nobody.

- [https://github.com/Live-Hack-CVE/CVE-2021-28116](https://github.com/Live-Hack-CVE/CVE-2021-28116) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-28116.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-28116.svg)


## CVE-2021-24467
 The Leaflet Map WordPress plugin before 3.0.0 does not verify the CSRF nonce when saving its settings, which allows attackers to make a logged in admin update the settings via a Cross-Site Request Forgery attack. This could lead to Cross-Site Scripting issues by either changing the URL of the JavaScript library being used, or using malicious attributions which will be executed in all page with an embed map from the plugin

- [https://github.com/Live-Hack-CVE/CVE-2021-24467](https://github.com/Live-Hack-CVE/CVE-2021-24467) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-24467.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-24467.svg)


## CVE-2021-24374
 The Jetpack Carousel module of the JetPack WordPress plugin before 9.8 allows users to create a &quot;carousel&quot; type image gallery and allows users to comment on the images. A security vulnerability was found within the Jetpack Carousel module by nguyenhg_vcs that allowed the comments of non-published page/posts to be leaked.

- [https://github.com/Live-Hack-CVE/CVE-2021-24374](https://github.com/Live-Hack-CVE/CVE-2021-24374) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-24374.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-24374.svg)


## CVE-2021-21781
 An information disclosure vulnerability exists in the ARM SIGPAGE functionality of Linux Kernel v5.4.66 and v5.4.54. The latest version (5.11-rc4) seems to still be vulnerable. A userland application can read the contents of the sigpage, which can leak kernel memory contents. An attacker can read a process&#8217;s memory at a specific offset to trigger this vulnerability. This was fixed in kernel releases: 4.14.222 4.19.177 5.4.99 5.10.17 5.11

- [https://github.com/Live-Hack-CVE/CVE-2021-21781](https://github.com/Live-Hack-CVE/CVE-2021-21781) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-21781.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-21781.svg)


## CVE-2021-4310
 A vulnerability was found in 01-Scripts 01-Artikelsystem. It has been classified as problematic. Affected is an unknown function of the file 01article.php. The manipulation of the argument $_SERVER['PHP_SELF'] leads to cross site scripting. It is possible to launch the attack remotely. The name of the patch is ae849b347a58c2cb1be38d04bbe56fc883d5d84a. It is recommended to apply a patch to fix this issue. VDB-217662 is the identifier assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2021-4310](https://github.com/Live-Hack-CVE/CVE-2021-4310) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-4310.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-4310.svg)


## CVE-2021-3114
 In Go before 1.14.14 and 1.15.x before 1.15.7, crypto/elliptic/p224.go can generate incorrect outputs, related to an underflow of the lowest limb during the final complete reduction in the P-224 field.

- [https://github.com/Live-Hack-CVE/CVE-2021-3114](https://github.com/Live-Hack-CVE/CVE-2021-3114) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-3114.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-3114.svg)


## CVE-2020-36403
 HTSlib through 1.10.2 allows out-of-bounds write access in vcf_parse_format (called from vcf_parse and vcf_read).

- [https://github.com/Live-Hack-CVE/CVE-2020-36403](https://github.com/Live-Hack-CVE/CVE-2020-36403) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-36403.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-36403.svg)


## CVE-2020-26732
 SKYWORTH GN542VF Boa version 0.94.13 does not set the Secure flag for the session cookie in an HTTPS session, which makes it easier for remote attackers to capture this cookie by intercepting its transmission within an HTTP session.

- [https://github.com/Live-Hack-CVE/CVE-2020-26732](https://github.com/Live-Hack-CVE/CVE-2020-26732) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-26732.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-26732.svg)


## CVE-2020-26664
 A vulnerability in EbmlTypeDispatcher::send in VideoLAN VLC media player 3.0.11 allows attackers to trigger a heap-based buffer overflow via a crafted .mkv file.

- [https://github.com/Live-Hack-CVE/CVE-2020-26664](https://github.com/Live-Hack-CVE/CVE-2020-26664) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-26664.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-26664.svg)


## CVE-2020-16898
 A remote code execution vulnerability exists when the Windows TCP/IP stack improperly handles ICMPv6 Router Advertisement packets, aka 'Windows TCP/IP Remote Code Execution Vulnerability'.

- [https://github.com/komomon/CVE-2020-16898--EXP-POC](https://github.com/komomon/CVE-2020-16898--EXP-POC) :  ![starts](https://img.shields.io/github/stars/komomon/CVE-2020-16898--EXP-POC.svg) ![forks](https://img.shields.io/github/forks/komomon/CVE-2020-16898--EXP-POC.svg)


## CVE-2020-16118
 In GNOME Balsa before 2.6.0, a malicious server operator or man in the middle can trigger a NULL pointer dereference and client crash by sending a PREAUTH response to imap_mbox_connect in libbalsa/imap/imap-handle.c.

- [https://github.com/Live-Hack-CVE/CVE-2020-16118](https://github.com/Live-Hack-CVE/CVE-2020-16118) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-16118.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-16118.svg)


## CVE-2020-15803
 Zabbix before 3.0.32rc1, 4.x before 4.0.22rc1, 4.1.x through 4.4.x before 4.4.10rc1, and 5.x before 5.0.2rc1 allows stored XSS in the URL Widget.

- [https://github.com/Live-Hack-CVE/CVE-2020-15803](https://github.com/Live-Hack-CVE/CVE-2020-15803) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-15803.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-15803.svg)


## CVE-2020-14871
 Vulnerability in the Oracle Solaris product of Oracle Systems (component: Pluggable authentication module). Supported versions that are affected are 10 and 11. Easily exploitable vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise Oracle Solaris. While the vulnerability is in Oracle Solaris, attacks may significantly impact additional products. Successful attacks of this vulnerability can result in takeover of Oracle Solaris. Note: This CVE is not exploitable for Solaris 11.1 and later releases, and ZFSSA 8.7 and later releases, thus the CVSS Base Score is 0.0. CVSS 3.1 Base Score 10.0 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H).

- [https://github.com/hackingyseguridad/ssha](https://github.com/hackingyseguridad/ssha) :  ![starts](https://img.shields.io/github/stars/hackingyseguridad/ssha.svg) ![forks](https://img.shields.io/github/forks/hackingyseguridad/ssha.svg)


## CVE-2020-14347
 A flaw was found in the way xserver memory was not properly initialized. This could leak parts of server memory to the X client. In cases where Xorg server runs with elevated privileges, this could result in possible ASLR bypass. Xorg-server before version 1.20.9 is vulnerable.

- [https://github.com/Live-Hack-CVE/CVE-2020-14347](https://github.com/Live-Hack-CVE/CVE-2020-14347) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-14347.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-14347.svg)


## CVE-2020-13300
 GitLab CE/EE version 13.3 prior to 13.3.4 was vulnerable to an OAuth authorization scope change without user consent in the middle of the authorization flow.

- [https://github.com/Live-Hack-CVE/CVE-2020-13300](https://github.com/Live-Hack-CVE/CVE-2020-13300) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-13300.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-13300.svg)


## CVE-2020-10963
 FrozenNode Laravel-Administrator through 5.0.12 allows unrestricted file upload (and consequently Remote Code Execution) via admin/tips_image/image/file_upload image upload with PHP content within a GIF image that has the .php extension. NOTE: this product is discontinued.

- [https://github.com/Live-Hack-CVE/CVE-2020-10963](https://github.com/Live-Hack-CVE/CVE-2020-10963) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-10963.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-10963.svg)


## CVE-2020-10883
 This vulnerability allows local attackers to escalate privileges on affected installations of TP-Link Archer A7 Firmware Ver: 190726 AC1750 routers. An attacker must first obtain the ability to execute low-privileged code on the target system in order to exploit this vulnerability. The specific flaw exists within the file system. The issue lies in the lack of proper permissions set on the file system. An attacker can leverage this vulnerability to escalate privileges. Was ZDI-CAN-9651.

- [https://github.com/Live-Hack-CVE/CVE-2020-10883](https://github.com/Live-Hack-CVE/CVE-2020-10883) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-10883.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-10883.svg)


## CVE-2020-10882
 This vulnerability allows network-adjacent attackers to execute arbitrary code on affected installations of TP-Link Archer A7 Firmware Ver: 190726 AC1750 routers. Authentication is not required to exploit this vulnerability. The specific flaw exists within the tdpServer service, which listens on UDP port 20002 by default. When parsing the slave_mac parameter, the process does not properly validate a user-supplied string before using it to execute a system call. An attacker can leverage this vulnerability to execute code in the context of the root user. Was ZDI-CAN-9650.

- [https://github.com/Live-Hack-CVE/CVE-2020-10882](https://github.com/Live-Hack-CVE/CVE-2020-10882) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-10882.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-10882.svg)


## CVE-2020-10675
 The Library API in buger jsonparser through 2019-12-04 allows attackers to cause a denial of service (infinite loop) via a Delete call.

- [https://github.com/Live-Hack-CVE/CVE-2020-10675](https://github.com/Live-Hack-CVE/CVE-2020-10675) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-10675.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-10675.svg)


## CVE-2020-6806
 By carefully crafting promise resolutions, it was possible to cause an out-of-bounds read off the end of an array resized during script execution. This could have led to memory corruption and a potentially exploitable crash. This vulnerability affects Thunderbird &lt; 68.6, Firefox &lt; 74, Firefox &lt; ESR68.6, and Firefox ESR &lt; 68.6.

- [https://github.com/Live-Hack-CVE/CVE-2020-6806](https://github.com/Live-Hack-CVE/CVE-2020-6806) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-6806.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-6806.svg)


## CVE-2020-6287
 SAP NetWeaver AS JAVA (LM Configuration Wizard), versions - 7.30, 7.31, 7.40, 7.50, does not perform an authentication check which allows an attacker without prior authentication to execute configuration tasks to perform critical actions against the SAP Java system, including the ability to create an administrative user, and therefore compromising Confidentiality, Integrity and Availability of the system, leading to Missing Authentication Check.

- [https://github.com/chipik/SAP_RECON](https://github.com/chipik/SAP_RECON) :  ![starts](https://img.shields.io/github/stars/chipik/SAP_RECON.svg) ![forks](https://img.shields.io/github/forks/chipik/SAP_RECON.svg)


## CVE-2020-5267
 In ActionView before versions 6.0.2.2 and 5.2.4.2, there is a possible XSS vulnerability in ActionView's JavaScript literal escape helpers. Views that use the `j` or `escape_javascript` methods may be susceptible to XSS attacks. The issue is fixed in versions 6.0.2.2 and 5.2.4.2.

- [https://github.com/Live-Hack-CVE/CVE-2020-5267](https://github.com/Live-Hack-CVE/CVE-2020-5267) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-5267.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-5267.svg)


## CVE-2020-4788
 IBM Power9 (AIX 7.1, 7.2, and VIOS 3.1) processors could allow a local user to obtain sensitive information from the data in the L1 cache under extenuating circumstances. IBM X-Force ID: 189296.

- [https://github.com/Live-Hack-CVE/CVE-2020-4788](https://github.com/Live-Hack-CVE/CVE-2020-4788) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-4788.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-4788.svg)


## CVE-2020-3580
 Multiple vulnerabilities in the web services interface of Cisco Adaptive Security Appliance (ASA) Software and Cisco Firepower Threat Defense (FTD) Software could allow an unauthenticated, remote attacker to conduct cross-site scripting (XSS) attacks against a user of the web services interface of an affected device. The vulnerabilities are due to insufficient validation of user-supplied input by the web services interface of an affected device. An attacker could exploit these vulnerabilities by persuading a user of the interface to click a crafted link. A successful exploit could allow the attacker to execute arbitrary script code in the context of the interface or allow the attacker to access sensitive, browser-based information. Note: These vulnerabilities affect only specific AnyConnect and WebVPN configurations. For more information, see the Vulnerable Products section.

- [https://github.com/adarshvs/CVE-2020-3580](https://github.com/adarshvs/CVE-2020-3580) :  ![starts](https://img.shields.io/github/stars/adarshvs/CVE-2020-3580.svg) ![forks](https://img.shields.io/github/forks/adarshvs/CVE-2020-3580.svg)


## CVE-2020-1878
 Huawei smartphone OxfordS-AN00A with versions earlier than 10.0.1.152D(C735E152R3P3),versions earlier than 10.0.1.160(C00E160R4P1) have an improper authentication vulnerability. Authentication to target component is improper when device performs an operation. Attackers exploit this vulnerability to obtain some information by loading malicious application, leading to information leak.

- [https://github.com/Live-Hack-CVE/CVE-2020-1878](https://github.com/Live-Hack-CVE/CVE-2020-1878) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-1878.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-1878.svg)


## CVE-2020-0305
 In cdev_get of char_dev.c, there is a possible use-after-free due to a race condition. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-10Android ID: A-153467744

- [https://github.com/Live-Hack-CVE/CVE-2020-0305](https://github.com/Live-Hack-CVE/CVE-2020-0305) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-0305.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-0305.svg)


## CVE-2019-25101
 A vulnerability classified as critical has been found in OnShift TurboGears 1.0.11.10. This affects an unknown part of the file turbogears/controllers.py of the component HTTP Header Handler. The manipulation leads to http response splitting. It is possible to initiate the attack remotely. Upgrading to version 1.0.11.11 is able to address this issue. The name of the patch is f68bbaba47f4474e1da553aa51564a73e1d92a84. It is recommended to upgrade the affected component. The associated identifier of this vulnerability is VDB-220059.

- [https://github.com/Live-Hack-CVE/CVE-2019-25101](https://github.com/Live-Hack-CVE/CVE-2019-25101) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-25101.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-25101.svg)


## CVE-2019-25096
 A vulnerability has been found in soerennb eXtplorer up to 2.1.12 and classified as problematic. Affected by this vulnerability is an unknown functionality. The manipulation leads to cross site scripting. The attack can be launched remotely. Upgrading to version 2.1.13 is able to address this issue. The name of the patch is b8fcb888f4ff5e171c16797a4b075c6c6f50bf46. It is recommended to upgrade the affected component. The associated identifier of this vulnerability is VDB-217435.

- [https://github.com/Live-Hack-CVE/CVE-2019-25096](https://github.com/Live-Hack-CVE/CVE-2019-25096) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-25096.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-25096.svg)


## CVE-2019-20485
 qemu/qemu_driver.c in libvirt before 6.0.0 mishandles the holding of a monitor job during a query to a guest agent, which allows attackers to cause a denial of service (API blockage).

- [https://github.com/Live-Hack-CVE/CVE-2019-20485](https://github.com/Live-Hack-CVE/CVE-2019-20485) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-20485.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-20485.svg)


## CVE-2019-18422
 An issue was discovered in Xen through 4.12.x allowing ARM guest OS users to cause a denial of service or gain privileges by leveraging the erroneous enabling of interrupts. Interrupts are unconditionally unmasked in exception handlers. When an exception occurs on an ARM system which is handled without changing processor level, some interrupts are unconditionally enabled during exception entry. So exceptions which occur when interrupts are masked will effectively unmask the interrupts. A malicious guest might contrive to arrange for critical Xen code to run with interrupts erroneously enabled. This could lead to data corruption, denial of service, or possibly even privilege escalation. However a precise attack technique has not been identified.

- [https://github.com/Live-Hack-CVE/CVE-2019-18422](https://github.com/Live-Hack-CVE/CVE-2019-18422) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-18422.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-18422.svg)


## CVE-2019-17675
 WordPress before 5.2.4 does not properly consider type confusion during validation of the referer in the admin pages, possibly leading to CSRF.

- [https://github.com/Live-Hack-CVE/CVE-2019-17675](https://github.com/Live-Hack-CVE/CVE-2019-17675) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-17675.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-17675.svg)


## CVE-2019-17674
 WordPress before 5.2.4 is vulnerable to stored XSS (cross-site scripting) via the Customizer.

- [https://github.com/Live-Hack-CVE/CVE-2019-17674](https://github.com/Live-Hack-CVE/CVE-2019-17674) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-17674.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-17674.svg)


## CVE-2019-17672
 WordPress before 5.2.4 is vulnerable to a stored XSS attack to inject JavaScript into STYLE elements.

- [https://github.com/Live-Hack-CVE/CVE-2019-17672](https://github.com/Live-Hack-CVE/CVE-2019-17672) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-17672.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-17672.svg)


## CVE-2019-17671
 In WordPress before 5.2.4, unauthenticated viewing of certain content is possible because the static query property is mishandled.

- [https://github.com/Live-Hack-CVE/CVE-2019-17671](https://github.com/Live-Hack-CVE/CVE-2019-17671) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-17671.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-17671.svg)


## CVE-2019-17350
 An issue was discovered in Xen through 4.12.x allowing Arm domU attackers to cause a denial of service (infinite loop) involving a compare-and-exchange operation.

- [https://github.com/Live-Hack-CVE/CVE-2019-17350](https://github.com/Live-Hack-CVE/CVE-2019-17350) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-17350.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-17350.svg)


## CVE-2019-17342
 An issue was discovered in Xen through 4.11.x allowing x86 PV guest OS users to cause a denial of service or gain privileges by leveraging a race condition that arose when XENMEM_exchange was introduced.

- [https://github.com/Live-Hack-CVE/CVE-2019-17342](https://github.com/Live-Hack-CVE/CVE-2019-17342) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-17342.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-17342.svg)


## CVE-2019-17341
 An issue was discovered in Xen through 4.11.x allowing x86 PV guest OS users to cause a denial of service or gain privileges by leveraging a page-writability race condition during addition of a passed-through PCI device.

- [https://github.com/Live-Hack-CVE/CVE-2019-17341](https://github.com/Live-Hack-CVE/CVE-2019-17341) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-17341.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-17341.svg)


## CVE-2019-16972
 In FusionPBX up to 4.5.7, the file app\contacts\contact_addresses.php uses an unsanitized &quot;id&quot; variable coming from the URL, which is reflected in HTML, leading to XSS.

- [https://github.com/Live-Hack-CVE/CVE-2019-16972](https://github.com/Live-Hack-CVE/CVE-2019-16972) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-16972.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-16972.svg)


## CVE-2019-16968
 An issue was discovered in FusionPBX up to 4.5.7. In the file app\conference_controls\conference_control_details.php, an unsanitized id variable coming from the URL is reflected in HTML on 2 occasions, leading to XSS.

- [https://github.com/Live-Hack-CVE/CVE-2019-16968](https://github.com/Live-Hack-CVE/CVE-2019-16968) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-16968.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-16968.svg)


## CVE-2019-16965
 resources/cmd.php in FusionPBX up to 4.5.7 suffers from a command injection vulnerability due to a lack of input validation, which allows authenticated administrative attackers to execute any commands on the host as www-data.

- [https://github.com/Live-Hack-CVE/CVE-2019-16965](https://github.com/Live-Hack-CVE/CVE-2019-16965) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-16965.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-16965.svg)


## CVE-2019-16095
 Symonics libmysofa 0.7 has an invalid read in getDimension in hrtf/reader.c.

- [https://github.com/Live-Hack-CVE/CVE-2019-16095](https://github.com/Live-Hack-CVE/CVE-2019-16095) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-16095.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-16095.svg)


## CVE-2019-16094
 Symonics libmysofa 0.7 has an invalid read in readOHDRHeaderMessageDataLayout in hdf/dataobject.c.

- [https://github.com/Live-Hack-CVE/CVE-2019-16094](https://github.com/Live-Hack-CVE/CVE-2019-16094) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-16094.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-16094.svg)


## CVE-2019-16093
 Symonics libmysofa 0.7 has an invalid write in readOHDRHeaderMessageDataLayout in hdf/dataobject.c.

- [https://github.com/Live-Hack-CVE/CVE-2019-16093](https://github.com/Live-Hack-CVE/CVE-2019-16093) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-16093.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-16093.svg)


## CVE-2019-16092
 Symonics libmysofa 0.7 has a NULL pointer dereference in getHrtf in hrtf/reader.c.

- [https://github.com/Live-Hack-CVE/CVE-2019-16092](https://github.com/Live-Hack-CVE/CVE-2019-16092) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-16092.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-16092.svg)


## CVE-2019-16091
 Symonics libmysofa 0.7 has an out-of-bounds read in directblockRead in hdf/fractalhead.c.

- [https://github.com/Live-Hack-CVE/CVE-2019-16091](https://github.com/Live-Hack-CVE/CVE-2019-16091) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-16091.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-16091.svg)


## CVE-2019-15654
 Comba AC2400 devices are prone to password disclosure via a simple crafted /09/business/upgrade/upcfgAction.php?download=true request to the web management server. The request doesn't require any authentication and will lead to saving the DBconfig.cfg file. At the end of the file, the login information is stored in cleartext.

- [https://github.com/Live-Hack-CVE/CVE-2019-15654](https://github.com/Live-Hack-CVE/CVE-2019-15654) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-15654.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-15654.svg)


## CVE-2019-15017
 The SSH service is enabled on the Zingbox Inspector versions 1.294 and earlier, exposing SSH to the local network. When combined with PAN-SA-2019-0027, this can allow an attacker to authenticate to the service using hardcoded credentials.

- [https://github.com/Live-Hack-CVE/CVE-2019-15017](https://github.com/Live-Hack-CVE/CVE-2019-15017) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-15017.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-15017.svg)


## CVE-2019-15016
 An SQL injection vulnerability exists in the management interface of Zingbox Inspector versions 1.288 and earlier, that allows for unsanitized data provided by an authenticated user to be passed from the web UI into the database.

- [https://github.com/Live-Hack-CVE/CVE-2019-15016](https://github.com/Live-Hack-CVE/CVE-2019-15016) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-15016.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-15016.svg)


## CVE-2019-15015
 In the Zingbox Inspector, versions 1.294 and earlier, hardcoded credentials for root and inspector user accounts are present in the system software, which can result in unauthorized users gaining access to the system.

- [https://github.com/Live-Hack-CVE/CVE-2019-15015](https://github.com/Live-Hack-CVE/CVE-2019-15015) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-15015.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-15015.svg)


## CVE-2019-13754
 Insufficient policy enforcement in extensions in Google Chrome prior to 79.0.3945.79 allowed a remote attacker to bypass navigation restrictions via a crafted HTML page.

- [https://github.com/Live-Hack-CVE/CVE-2019-13754](https://github.com/Live-Hack-CVE/CVE-2019-13754) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-13754.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-13754.svg)


## CVE-2019-13750
 Insufficient data validation in SQLite in Google Chrome prior to 79.0.3945.79 allowed a remote attacker to bypass defense-in-depth measures via a crafted HTML page.

- [https://github.com/Live-Hack-CVE/CVE-2019-13750](https://github.com/Live-Hack-CVE/CVE-2019-13750) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-13750.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-13750.svg)


## CVE-2019-13749
 Incorrect security UI in Omnibox in Google Chrome on iOS prior to 79.0.3945.79 allowed a remote attacker to spoof the contents of the Omnibox (URL bar) via a crafted HTML page.

- [https://github.com/Live-Hack-CVE/CVE-2019-13749](https://github.com/Live-Hack-CVE/CVE-2019-13749) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-13749.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-13749.svg)


## CVE-2019-13748
 Insufficient policy enforcement in developer tools in Google Chrome prior to 79.0.3945.79 allowed a local attacker to obtain potentially sensitive information from process memory via a crafted HTML page.

- [https://github.com/Live-Hack-CVE/CVE-2019-13748](https://github.com/Live-Hack-CVE/CVE-2019-13748) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-13748.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-13748.svg)


## CVE-2019-13746
 Insufficient policy enforcement in Omnibox in Google Chrome prior to 79.0.3945.79 allowed a remote attacker to spoof the contents of the Omnibox (URL bar) via a crafted HTML page.

- [https://github.com/Live-Hack-CVE/CVE-2019-13746](https://github.com/Live-Hack-CVE/CVE-2019-13746) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-13746.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-13746.svg)


## CVE-2019-13744
 Insufficient policy enforcement in cookies in Google Chrome prior to 79.0.3945.79 allowed a remote attacker to leak cross-origin data via a crafted HTML page.

- [https://github.com/Live-Hack-CVE/CVE-2019-13744](https://github.com/Live-Hack-CVE/CVE-2019-13744) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-13744.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-13744.svg)


## CVE-2019-13725
 Use-after-free in Bluetooth in Google Chrome prior to 79.0.3945.79 allowed a remote attacker to execute arbitrary code via a crafted HTML page.

- [https://github.com/Live-Hack-CVE/CVE-2019-13725](https://github.com/Live-Hack-CVE/CVE-2019-13725) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-13725.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-13725.svg)


## CVE-2019-10443
 Jenkins iceScrum Plugin 1.1.4 and earlier stored credentials unencrypted in job config.xml files on the Jenkins master where they could be viewed by users with Extended Read permission, or access to the master file system.

- [https://github.com/Live-Hack-CVE/CVE-2019-10443](https://github.com/Live-Hack-CVE/CVE-2019-10443) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-10443.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-10443.svg)


## CVE-2019-10440
 Jenkins NeoLoad Plugin 2.2.5 and earlier stored credentials unencrypted in its global configuration file and in job config.xml files on the Jenkins master where they could be viewed by users with Extended Read permission, or access to the master file system.

- [https://github.com/Live-Hack-CVE/CVE-2019-10440](https://github.com/Live-Hack-CVE/CVE-2019-10440) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-10440.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-10440.svg)


## CVE-2019-10163
 A Vulnerability has been found in PowerDNS Authoritative Server before versions 4.1.9, 4.0.8 allowing a remote, authorized master server to cause a high CPU load or even prevent any further updates to any slave zone by sending a large number of NOTIFY messages. Note that only servers configured as slaves are affected by this issue.

- [https://github.com/Live-Hack-CVE/CVE-2019-10163](https://github.com/Live-Hack-CVE/CVE-2019-10163) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-10163.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-10163.svg)


## CVE-2019-10129
 A vulnerability was found in postgresql versions 11.x prior to 11.3. Using a purpose-crafted insert to a partitioned table, an attacker can read arbitrary bytes of server memory. In the default configuration, any user can create a partitioned table suitable for this attack. (Exploit prerequisites are the same as for CVE-2018-1052).

- [https://github.com/Live-Hack-CVE/CVE-2019-10129](https://github.com/Live-Hack-CVE/CVE-2019-10129) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-10129.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-10129.svg)


## CVE-2019-6648
 On version 1.9.0, If DEBUG logging is enable, F5 Container Ingress Service (CIS) for Kubernetes and Red Hat OpenShift (k8s-bigip-ctlr) log files may contain BIG-IP secrets such as SSL Private Keys and Private key Passphrases as provided as inputs by an AS3 Declaration.

- [https://github.com/Live-Hack-CVE/CVE-2019-6648](https://github.com/Live-Hack-CVE/CVE-2019-6648) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-6648.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-6648.svg)


## CVE-2019-6643
 On versions 14.1.0-14.1.0.5, 14.0.0-14.0.0.4, 13.0.0-13.1.2, 12.1.0-12.1.4.1, and 11.5.2-11.6.4, an attacker sending specifically crafted DHCPv6 requests through a BIG-IP virtual server configured with a DHCPv6 profile may be able to cause the TMM process to produce a core file.

- [https://github.com/Live-Hack-CVE/CVE-2019-6643](https://github.com/Live-Hack-CVE/CVE-2019-6643) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-6643.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-6643.svg)


## CVE-2019-4309
 IBM Security Guardium Big Data Intelligence (SonarG) 4.0 uses hard coded credentials which could allow a local user to obtain highly sensitive information. IBM X-Force ID: 161035.

- [https://github.com/Live-Hack-CVE/CVE-2019-4309](https://github.com/Live-Hack-CVE/CVE-2019-4309) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-4309.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-4309.svg)


## CVE-2019-4296
 IBM Robotic Process Automation with Automation Anywhere 11 information disclosure could allow a local user to obtain e-mail contents from the client debug log file. IBM X-Force ID: 160759.

- [https://github.com/Live-Hack-CVE/CVE-2019-4296](https://github.com/Live-Hack-CVE/CVE-2019-4296) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-4296.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-4296.svg)


## CVE-2019-4295
 IBM Robotic Process Automation with Automation Anywhere 11 could allow an attacker with specialized access to obtain highly sensitive from the credential vault. IBM X-Force ID: 160758.

- [https://github.com/Live-Hack-CVE/CVE-2019-4295](https://github.com/Live-Hack-CVE/CVE-2019-4295) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-4295.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-4295.svg)


## CVE-2019-4269
 IBM WebSphere Application Server 7.0, 8.0, 8.5, and 9.0 Admin Console could allow a remote attacker to obtain sensitive information when a specially crafted url causes a stack trace to be dumped. IBM X-Force ID: 160202.

- [https://github.com/Live-Hack-CVE/CVE-2019-4269](https://github.com/Live-Hack-CVE/CVE-2019-4269) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-4269.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-4269.svg)


## CVE-2019-4263
 IBM Content Navigator 3.0CD is vulnerable to local file inclusion, allowing an attacker to access a configuration file in the ICN server. IBM X-Force ID: 160015.

- [https://github.com/Live-Hack-CVE/CVE-2019-4263](https://github.com/Live-Hack-CVE/CVE-2019-4263) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-4263.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-4263.svg)


## CVE-2019-4260
 IBM Daeja ViewONE Professional, Standard &amp; Virtual 5.0 through 5.0.5 could allow an unauthorized user to download server files resulting in sensitive information disclosure. IBM X-Force ID: 160012.

- [https://github.com/Live-Hack-CVE/CVE-2019-4260](https://github.com/Live-Hack-CVE/CVE-2019-4260) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-4260.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-4260.svg)


## CVE-2019-4257
 IBM InfoSphere Information Server 11.5 and 11.7 is affected by an information disclosure vulnerability. Sensitive information in an error message may be used to conduct further attacks against the system. IBM X-Force ID: 159945.

- [https://github.com/Live-Hack-CVE/CVE-2019-4257](https://github.com/Live-Hack-CVE/CVE-2019-4257) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-4257.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-4257.svg)


## CVE-2019-4252
 IBM Rational Collaborative Lifecycle Management 6.0 through 6.0.6.1 could allow a remote attacker to traverse directories on the system. An attacker could send a specially-crafted URL request containing &quot;dot dot&quot; sequences (/../) to view arbitrary files on the system. IBM X-Force ID: 159883.

- [https://github.com/Live-Hack-CVE/CVE-2019-4252](https://github.com/Live-Hack-CVE/CVE-2019-4252) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-4252.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-4252.svg)


## CVE-2019-4250
 IBM Jazz Foundation products (IBM Rational Collaborative Lifecycle Management 6.0 through 6.0.6.1) is vulnerable to cross-site scripting. This vulnerability allows users to embed arbitrary JavaScript code in the Web UI thus altering the intended functionality potentially leading to credentials disclosure within a trusted session. IBM X-Force ID: 159648.

- [https://github.com/Live-Hack-CVE/CVE-2019-4250](https://github.com/Live-Hack-CVE/CVE-2019-4250) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-4250.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-4250.svg)


## CVE-2019-4173
 IBM Cognos Controller 10.2.0, 10.2.1, 10.3.0, 10.3.1, and 10.4.0 could allow a remote attacker to obtain sensitive information, caused by a flaw in the HTTP OPTIONS method, aka Optionsbleed. By sending an OPTIONS HTTP request, a remote attacker could exploit this vulnerability to read secret data from process memory and obtain sensitive information. IBM X-Force ID: 158878.

- [https://github.com/Live-Hack-CVE/CVE-2019-4173](https://github.com/Live-Hack-CVE/CVE-2019-4173) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-4173.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-4173.svg)


## CVE-2019-4166
 IBM StoredIQ 7.6 could allow a remote attacker to conduct phishing attacks, using an open redirect attack. By persuading a victim to visit a specially-crafted Web site, a remote attacker could exploit this vulnerability to spoof the URL displayed to redirect a user to a malicious Web site that would appear to be trusted. This could allow the attacker to obtain highly sensitive information or conduct further attacks against the victim. IBM X-Force ID: 158699.

- [https://github.com/Live-Hack-CVE/CVE-2019-4166](https://github.com/Live-Hack-CVE/CVE-2019-4166) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-4166.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-4166.svg)


## CVE-2019-4162
 IBM Security Information Queue (ISIQ) 1.0.0, 1.0.1, and 1.0.2 is missing the HTTP Strict Transport Security header. Users can navigate by mistake to the unencrypted version of the web application or accept invalid certificates. This leads to sensitive data being sent unencrypted over the wire. IBM X-Force ID: 158661.

- [https://github.com/Live-Hack-CVE/CVE-2019-4162](https://github.com/Live-Hack-CVE/CVE-2019-4162) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-4162.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-4162.svg)


## CVE-2019-4157
 IBM Security Access Manager 9.0.1 through 9.0.6 is vulnerable to cross-site scripting. This vulnerability allows users to embed arbitrary JavaScript code in the Web UI thus altering the intended functionality potentially leading to credentials disclosure within a trusted session. IBM X-Force ID: 158573.

- [https://github.com/Live-Hack-CVE/CVE-2019-4157](https://github.com/Live-Hack-CVE/CVE-2019-4157) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-4157.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-4157.svg)


## CVE-2019-4156
 IBM Security Access Manager 9.0.1 through 9.0.6 uses weaker than expected cryptographic algorithms that could allow an attacker to decrypt highly sensitive information. IBM X-Force ID: 158572.

- [https://github.com/Live-Hack-CVE/CVE-2019-4156](https://github.com/Live-Hack-CVE/CVE-2019-4156) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-4156.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-4156.svg)


## CVE-2019-4140
 IBM Tivoli Storage Manager Server (IBM Spectrum Protect 7.1 and 8.1) could allow a local user to replace existing databases by restoring old data. IBM X-Force ID: 158336.

- [https://github.com/Live-Hack-CVE/CVE-2019-4140](https://github.com/Live-Hack-CVE/CVE-2019-4140) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-4140.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-4140.svg)


## CVE-2019-4103
 IBM Tivoli Netcool/Impact 7.1.0 allows for remote execution of command by low privileged User. Remote code execution allow to execute arbitrary code on system which lead to take control over the system. IBM X-Force ID: 158094.

- [https://github.com/Live-Hack-CVE/CVE-2019-4103](https://github.com/Live-Hack-CVE/CVE-2019-4103) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-4103.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-4103.svg)


## CVE-2019-4080
 IBM WebSphere Application Server Admin Console 7.5, 8.0, 8.5, and 9.0 is vulnerable to a potential denial of service, caused by improper parameter parsing. A remote attacker could exploit this to consume all available CPU resources. IBM X-Force ID: 157380.

- [https://github.com/Live-Hack-CVE/CVE-2019-4080](https://github.com/Live-Hack-CVE/CVE-2019-4080) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-4080.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-4080.svg)


## CVE-2019-4070
 IBM Intelligent Operations Center (IOC) 5.1.0 through 5.2.0 is vulnerable to cross-site scripting. This vulnerability allows users to embed arbitrary JavaScript code in the Web UI thus altering the intended functionality potentially leading to credentials disclosure within a trusted session. IBM X-Force ID: 157015.

- [https://github.com/Live-Hack-CVE/CVE-2019-4070](https://github.com/Live-Hack-CVE/CVE-2019-4070) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-4070.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-4070.svg)


## CVE-2019-4067
 IBM Intelligent Operations Center (IOC) 5.1.0 through 5.2.0 does not require that users should have strong passwords by default, which makes it easier for attackers to compromise user accounts. IBM X-Force ID: 157012.

- [https://github.com/Live-Hack-CVE/CVE-2019-4067](https://github.com/Live-Hack-CVE/CVE-2019-4067) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-4067.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-4067.svg)


## CVE-2019-4063
 IBM Sterling B2B Integrator 5.2.0.1 through 6.0.0.0 Standard Edition could allow highly sensitive information to be transmitted in plain text. An attacker could obtain this information using man in the middle techniques. IBM X-ForceID: 157008.

- [https://github.com/Live-Hack-CVE/CVE-2019-4063](https://github.com/Live-Hack-CVE/CVE-2019-4063) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-4063.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-4063.svg)


## CVE-2019-4062
 IBM i2 Intelligent Analyis Platform 9.0.0 through 9.1.1 is vulnerable to an XML External Entity Injection (XXE) attack when processing XML data. A remote attacker could exploit this vulnerability to expose sensitive information or consume memory resources. IBM X-Force ID: 157007.

- [https://github.com/Live-Hack-CVE/CVE-2019-4062](https://github.com/Live-Hack-CVE/CVE-2019-4062) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-4062.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-4062.svg)


## CVE-2019-4052
 IBM API Connect 2018.1 and 2018.4.1.2 apis can be leveraged by unauthenticated users to discover login ids of registered users. IBM X-Force ID: 156544.

- [https://github.com/Live-Hack-CVE/CVE-2019-4052](https://github.com/Live-Hack-CVE/CVE-2019-4052) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-4052.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-4052.svg)


## CVE-2019-3721
 Dell EMC Open Manage System Administrator (OMSA) versions prior to 9.3.0 contain an Improper Range Header Processing Vulnerability. A remote unauthenticated attacker may send crafted requests with overlapping ranges to cause the application to compress each of the requested bytes, resulting in a crash due to excessive memory consumption and preventing users from accessing the system.

- [https://github.com/Live-Hack-CVE/CVE-2019-3721](https://github.com/Live-Hack-CVE/CVE-2019-3721) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-3721.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-3721.svg)


## CVE-2019-3612
 Information Disclosure vulnerability in McAfee DXL Platform and TIE Server in DXL prior to 5.0.1 HF2 and TIE prior to 2.3.1 HF1 allows Authenticated users to view sensitive information in plain text via the GUI or command line.

- [https://github.com/Live-Hack-CVE/CVE-2019-3612](https://github.com/Live-Hack-CVE/CVE-2019-3612) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-3612.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-3612.svg)


## CVE-2019-2924
 Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Security: Encryption). Supported versions that are affected are 5.6.45 and prior and 5.7.27 and prior. Easily exploitable vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this vulnerability can result in unauthorized read access to a subset of MySQL Server accessible data. CVSS 3.0 Base Score 5.3 (Confidentiality impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N).

- [https://github.com/Live-Hack-CVE/CVE-2019-2924](https://github.com/Live-Hack-CVE/CVE-2019-2924) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-2924.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-2924.svg)


## CVE-2019-2923
 Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Security: Encryption). Supported versions that are affected are 5.6.45 and prior and 5.7.27 and prior. Easily exploitable vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this vulnerability can result in unauthorized read access to a subset of MySQL Server accessible data. CVSS 3.0 Base Score 5.3 (Confidentiality impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N).

- [https://github.com/Live-Hack-CVE/CVE-2019-2923](https://github.com/Live-Hack-CVE/CVE-2019-2923) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-2923.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-2923.svg)


## CVE-2019-2922
 Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Security: Encryption). Supported versions that are affected are 5.6.45 and prior and 5.7.27 and prior. Easily exploitable vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this vulnerability can result in unauthorized read access to a subset of MySQL Server accessible data. CVSS 3.0 Base Score 5.3 (Confidentiality impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N).

- [https://github.com/Live-Hack-CVE/CVE-2019-2922](https://github.com/Live-Hack-CVE/CVE-2019-2922) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-2922.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-2922.svg)


## CVE-2019-2920
 Vulnerability in the MySQL Connectors product of Oracle MySQL (component: Connector/ODBC). Supported versions that are affected are 5.3.13 and prior and 8.0.17 and prior. Easily exploitable vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise MySQL Connectors. Successful attacks of this vulnerability can result in unauthorized ability to cause a partial denial of service (partial DOS) of MySQL Connectors. CVSS 3.0 Base Score 5.3 (Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L).

- [https://github.com/Live-Hack-CVE/CVE-2019-2920](https://github.com/Live-Hack-CVE/CVE-2019-2920) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-2920.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-2920.svg)


## CVE-2019-2890
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Web Services). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0 and 12.2.1.3.0. Easily exploitable vulnerability allows high privileged attacker with network access via T3 to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.0 Base Score 7.2 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/jas502n/CVE-2019-2890](https://github.com/jas502n/CVE-2019-2890) :  ![starts](https://img.shields.io/github/stars/jas502n/CVE-2019-2890.svg) ![forks](https://img.shields.io/github/forks/jas502n/CVE-2019-2890.svg)


## CVE-2019-1040
 A tampering vulnerability exists in Microsoft Windows when a man-in-the-middle attacker is able to successfully bypass the NTLM MIC (Message Integrity Check) protection, aka 'Windows NTLM Tampering Vulnerability'.

- [https://github.com/wzxmt/CVE-2019-1040](https://github.com/wzxmt/CVE-2019-1040) :  ![starts](https://img.shields.io/github/stars/wzxmt/CVE-2019-1040.svg) ![forks](https://img.shields.io/github/forks/wzxmt/CVE-2019-1040.svg)


## CVE-2018-25080
 A vulnerability, which was classified as problematic, has been found in MobileDetect 2.8.31. This issue affects the function initLayoutType of the file examples/session_example.php of the component Example. The manipulation of the argument $_SERVER['PHP_SELF'] leads to cross site scripting. The attack may be initiated remotely. The exploit has been disclosed to the public and may be used. Upgrading to version 2.8.32 is able to address this issue. The name of the patch is 31818a441b095bdc4838602dbb17b8377d1e5cce. It is recommended to upgrade the affected component. The identifier VDB-220061 was assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2018-25080](https://github.com/Live-Hack-CVE/CVE-2018-25080) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2018-25080.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2018-25080.svg)


## CVE-2018-25079
 A vulnerability was found in Segmentio is-url up to 1.2.2. It has been rated as problematic. Affected by this issue is some unknown functionality of the file index.js. The manipulation leads to inefficient regular expression complexity. The attack may be launched remotely. Upgrading to version 1.2.3 is able to address this issue. The name of the patch is 149550935c63a98c11f27f694a7c4a9479e53794. It is recommended to upgrade the affected component. VDB-220058 is the identifier assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2018-25079](https://github.com/Live-Hack-CVE/CVE-2018-25079) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2018-25079.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2018-25079.svg)


## CVE-2018-3861
 A specially crafted TIFF image processed via the application can lead to an out-of-bounds write, overwriting arbitrary data. An attacker can deliver a TIFF image to trigger this vulnerability and gain code execution.

- [https://github.com/Live-Hack-CVE/CVE-2018-3861](https://github.com/Live-Hack-CVE/CVE-2018-3861) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2018-3861.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2018-3861.svg)


## CVE-2018-3836
 An exploitable command injection vulnerability exists in the gplotMakeOutput function of Leptonica 1.74.4. A specially crafted gplot rootname argument can cause a command injection resulting in arbitrary code execution. An attacker can provide a malicious path as input to an application that passes attacker data to this function to trigger this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2018-3836](https://github.com/Live-Hack-CVE/CVE-2018-3836) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2018-3836.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2018-3836.svg)


## CVE-2018-3835
 An exploitable out of bounds write vulnerability exists in version 2.2 of the Per Face Texture mapping application known as PTEX. The vulnerability is present in the reading of a file without proper parameter checking. The value read in, is not verified to be valid and its use can lead to a buffer overflow, potentially resulting in code execution.

- [https://github.com/Live-Hack-CVE/CVE-2018-3835](https://github.com/Live-Hack-CVE/CVE-2018-3835) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2018-3835.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2018-3835.svg)


## CVE-2018-3834
 An exploitable permanent denial of service vulnerability exists in Insteon Hub running firmware version 1013. The firmware upgrade functionality, triggered via PubNub, retrieves signed firmware binaries using plain HTTP requests. The device doesn't check the kind of firmware image that is going to be installed and thus allows for flashing any signed firmware into any MCU. Since the device contains different and incompatible MCUs, flashing one firmware to the wrong MCU will result in a permanent brick condition. To trigger this vulnerability, an attacker needs to impersonate the remote server &quot;cache.insteon.com&quot; and serve a signed firmware image.

- [https://github.com/Live-Hack-CVE/CVE-2018-3834](https://github.com/Live-Hack-CVE/CVE-2018-3834) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2018-3834.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2018-3834.svg)


## CVE-2017-14448
 An exploitable code execution vulnerability exists in the XCF image rendering functionality of SDL2_image-2.0.2. A specially crafted XCF image can cause a heap overflow resulting in code execution. An attacker can display a specially crafted image to trigger this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2017-14448](https://github.com/Live-Hack-CVE/CVE-2017-14448) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2017-14448.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2017-14448.svg)


## CVE-2017-11358
 The read_samples function in hcom.c in Sound eXchange (SoX) 14.4.2 allows remote attackers to cause a denial of service (invalid memory read and application crash) via a crafted hcom file.

- [https://github.com/Live-Hack-CVE/CVE-2017-11358](https://github.com/Live-Hack-CVE/CVE-2017-11358) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2017-11358.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2017-11358.svg)


## CVE-2015-10072
 A vulnerability classified as problematic was found in NREL api-umbrella-web 0.7.1. This vulnerability affects unknown code of the component Flash Message Handler. The manipulation leads to cross site scripting. The attack can be initiated remotely. Upgrading to version 0.8.0 is able to address this issue. The name of the patch is bcc0e922c61d30367678c8f17a435950969315cd. It is recommended to upgrade the affected component. The identifier of this vulnerability is VDB-220060.

- [https://github.com/Live-Hack-CVE/CVE-2015-10072](https://github.com/Live-Hack-CVE/CVE-2015-10072) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2015-10072.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2015-10072.svg)


## CVE-2013-10018
 A vulnerability was found in fanzila WebFinance 0.5. It has been declared as critical. Affected by this vulnerability is an unknown functionality of the file htdocs/prospection/save_contact.php. The manipulation of the argument nom/prenom/email/tel/mobile/client/fonction/note leads to sql injection. The name of the patch is 165dfcaa0520ee0179b7c1282efb84f5a03df114. It is recommended to apply a patch to fix this issue. The identifier VDB-220057 was assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2013-10018](https://github.com/Live-Hack-CVE/CVE-2013-10018) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2013-10018.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2013-10018.svg)


## CVE-2013-10017
 A vulnerability was found in fanzila WebFinance 0.5. It has been classified as critical. Affected is an unknown function of the file htdocs/admin/save_roles.php. The manipulation of the argument id leads to sql injection. The name of the patch is 6cfeb2f6b35c1b3a7320add07cd0493e4f752af3. It is recommended to apply a patch to fix this issue. The identifier of this vulnerability is VDB-220056.

- [https://github.com/Live-Hack-CVE/CVE-2013-10017](https://github.com/Live-Hack-CVE/CVE-2013-10017) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2013-10017.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2013-10017.svg)


## CVE-2007-2447
 The MS-RPC functionality in smbd in Samba 3.0.0 through 3.0.25rc3 allows remote attackers to execute arbitrary commands via shell metacharacters involving the (1) SamrChangePassword function, when the &quot;username map script&quot; smb.conf option is enabled, and allows remote authenticated users to execute commands via shell metacharacters involving other MS-RPC functions in the (2) remote printer and (3) file share management.

- [https://github.com/bdunlap9/CVE-2007-2447_python](https://github.com/bdunlap9/CVE-2007-2447_python) :  ![starts](https://img.shields.io/github/stars/bdunlap9/CVE-2007-2447_python.svg) ![forks](https://img.shields.io/github/forks/bdunlap9/CVE-2007-2447_python.svg)

