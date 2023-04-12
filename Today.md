# Update 2023-04-12
## CVE-2023-30459
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/Toxich4/CVE-2023-30459](https://github.com/Toxich4/CVE-2023-30459) :  ![starts](https://img.shields.io/github/stars/Toxich4/CVE-2023-30459.svg) ![forks](https://img.shields.io/github/forks/Toxich4/CVE-2023-30459.svg)


## CVE-2023-29017
 vm2 is a sandbox that can run untrusted code with whitelisted Node's built-in modules. Prior to version 3.9.15, vm2 was not properly handling host objects passed to `Error.prepareStackTrace` in case of unhandled async errors. A threat actor could bypass the sandbox protections to gain remote code execution rights on the host running the sandbox. This vulnerability was patched in the release of version 3.9.15 of vm2. There are no known workarounds.

- [https://github.com/Kaneki-hash/CVE-2023-29017-reverse-shell](https://github.com/Kaneki-hash/CVE-2023-29017-reverse-shell) :  ![starts](https://img.shields.io/github/stars/Kaneki-hash/CVE-2023-29017-reverse-shell.svg) ![forks](https://img.shields.io/github/forks/Kaneki-hash/CVE-2023-29017-reverse-shell.svg)


## CVE-2022-46689
 A race condition was addressed with additional validation. This issue is fixed in tvOS 16.2, macOS Monterey 12.6.2, macOS Ventura 13.1, macOS Big Sur 11.7.2, iOS 15.7.2 and iPadOS 15.7.2, iOS 16.2 and iPadOS 16.2, watchOS 9.2. An app may be able to execute arbitrary code with kernel privileges.

- [https://github.com/BomberFish/AbsoluteSolver](https://github.com/BomberFish/AbsoluteSolver) :  ![starts](https://img.shields.io/github/stars/BomberFish/AbsoluteSolver.svg) ![forks](https://img.shields.io/github/forks/BomberFish/AbsoluteSolver.svg)
- [https://github.com/BomberFish/DirtyCowKit](https://github.com/BomberFish/DirtyCowKit) :  ![starts](https://img.shields.io/github/stars/BomberFish/DirtyCowKit.svg) ![forks](https://img.shields.io/github/forks/BomberFish/DirtyCowKit.svg)


## CVE-2022-27666
 A heap buffer overflow flaw was found in IPsec ESP transformation code in net/ipv4/esp4.c and net/ipv6/esp6.c. This flaw allows a local attacker with a normal user privilege to overwrite kernel heap objects and may cause a local privilege escalation threat.

- [https://github.com/Albocoder/cve-2022-27666-exploits](https://github.com/Albocoder/cve-2022-27666-exploits) :  ![starts](https://img.shields.io/github/stars/Albocoder/cve-2022-27666-exploits.svg) ![forks](https://img.shields.io/github/forks/Albocoder/cve-2022-27666-exploits.svg)


## CVE-2022-22963
 In Spring Cloud Function versions 3.1.6, 3.2.2 and older unsupported versions, when using routing functionality it is possible for a user to provide a specially crafted SpEL as a routing-expression that may result in remote code execution and access to local resources.

- [https://github.com/SourM1lk/CVE-2022-22963-Exploit](https://github.com/SourM1lk/CVE-2022-22963-Exploit) :  ![starts](https://img.shields.io/github/stars/SourM1lk/CVE-2022-22963-Exploit.svg) ![forks](https://img.shields.io/github/forks/SourM1lk/CVE-2022-22963-Exploit.svg)


## CVE-2021-38314
 The Gutenberg Template Library &amp; Redux Framework plugin &lt;= 4.2.11 for WordPress registered several AJAX actions available to unauthenticated users in the `includes` function in `redux-core/class-redux-core.php` that were unique to a given site but deterministic and predictable given that they were based on an md5 hash of the site URL with a known salt value of '-redux' and an md5 hash of the previous hash with a known salt value of '-support'. These AJAX actions could be used to retrieve a list of active plugins and their versions, the site's PHP version, and an unsalted md5 hash of site&#8217;s `AUTH_KEY` concatenated with the `SECURE_AUTH_KEY`.

- [https://github.com/c0ff33b34n/CVE-2021-38314](https://github.com/c0ff33b34n/CVE-2021-38314) :  ![starts](https://img.shields.io/github/stars/c0ff33b34n/CVE-2021-38314.svg) ![forks](https://img.shields.io/github/forks/c0ff33b34n/CVE-2021-38314.svg)


## CVE-2020-14882
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Console). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0, 12.2.1.4.0 and 14.1.1.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/nik0nz7/CVE-2020-14882](https://github.com/nik0nz7/CVE-2020-14882) :  ![starts](https://img.shields.io/github/stars/nik0nz7/CVE-2020-14882.svg) ![forks](https://img.shields.io/github/forks/nik0nz7/CVE-2020-14882.svg)


## CVE-2019-18370
 An issue was discovered on Xiaomi Mi WiFi R3G devices before 2.28.23-stable. The backup file is in tar.gz format. After uploading, the application uses the tar zxf command to decompress, so one can control the contents of the files in the decompressed directory. In addition, the application's sh script for testing upload and download speeds reads a URL list from /tmp/speedtest_urls.xml, and there is a command injection vulnerability, as demonstrated by api/xqnetdetect/netspeed.

- [https://github.com/FzBacon/CVE-2019-18370_XiaoMi_Mi_WIFI_RCE_analysis](https://github.com/FzBacon/CVE-2019-18370_XiaoMi_Mi_WIFI_RCE_analysis) :  ![starts](https://img.shields.io/github/stars/FzBacon/CVE-2019-18370_XiaoMi_Mi_WIFI_RCE_analysis.svg) ![forks](https://img.shields.io/github/forks/FzBacon/CVE-2019-18370_XiaoMi_Mi_WIFI_RCE_analysis.svg)


## CVE-2019-9766
 Stack-based buffer overflow in Free MP3 CD Ripper 2.6, when converting a file, allows user-assisted remote attackers to execute arbitrary code via a crafted .mp3 file.

- [https://github.com/moonheadobj/CVE-2019-9766](https://github.com/moonheadobj/CVE-2019-9766) :  ![starts](https://img.shields.io/github/stars/moonheadobj/CVE-2019-9766.svg) ![forks](https://img.shields.io/github/forks/moonheadobj/CVE-2019-9766.svg)


## CVE-2014-0114
 Apache Commons BeanUtils, as distributed in lib/commons-beanutils-1.8.0.jar in Apache Struts 1.x through 1.3.10 and in other products requiring commons-beanutils through 1.9.2, does not suppress the class property, which allows remote attackers to &quot;manipulate&quot; the ClassLoader and execute arbitrary code via the class parameter, as demonstrated by the passing of this parameter to the getClass method of the ActionForm object in Struts 1.

- [https://github.com/aenlr/strutt-cve-2014-0114](https://github.com/aenlr/strutt-cve-2014-0114) :  ![starts](https://img.shields.io/github/stars/aenlr/strutt-cve-2014-0114.svg) ![forks](https://img.shields.io/github/forks/aenlr/strutt-cve-2014-0114.svg)

