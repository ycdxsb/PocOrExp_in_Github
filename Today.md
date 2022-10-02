# Update 2022-10-02
## CVE-2022-41218
 In drivers/media/dvb-core/dmxdev.c in the Linux kernel through 5.19.10, there is a use-after-free caused by refcount races, affecting dvb_demux_open and dvb_dmxdev_release.

- [https://github.com/V4bel/CVE-2022-41218](https://github.com/V4bel/CVE-2022-41218) :  ![starts](https://img.shields.io/github/stars/V4bel/CVE-2022-41218.svg) ![forks](https://img.shields.io/github/forks/V4bel/CVE-2022-41218.svg)


## CVE-2022-41082
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/jml4da/CVE-2022-41082-POC](https://github.com/jml4da/CVE-2022-41082-POC) :  ![starts](https://img.shields.io/github/stars/jml4da/CVE-2022-41082-POC.svg) ![forks](https://img.shields.io/github/forks/jml4da/CVE-2022-41082-POC.svg)


## CVE-2022-37434
 zlib through 1.2.12 has a heap-based buffer over-read or buffer overflow in inflate in inflate.c via a large gzip header extra field. NOTE: only applications that call inflateGetHeader are affected. Some common applications bundle the affected zlib source code but may be unable to call inflateGetHeader (e.g., see the nodejs/node reference).

- [https://github.com/nidhi7598/external_zlib-1.2.7_CVE-2022-37434](https://github.com/nidhi7598/external_zlib-1.2.7_CVE-2022-37434) :  ![starts](https://img.shields.io/github/stars/nidhi7598/external_zlib-1.2.7_CVE-2022-37434.svg) ![forks](https://img.shields.io/github/forks/nidhi7598/external_zlib-1.2.7_CVE-2022-37434.svg)


## CVE-2022-2588
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/ida-bro/CVE-2022-2588](https://github.com/ida-bro/CVE-2022-2588) :  ![starts](https://img.shields.io/github/stars/ida-bro/CVE-2022-2588.svg) ![forks](https://img.shields.io/github/forks/ida-bro/CVE-2022-2588.svg)


## CVE-2021-44228
 Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled. From log4j 2.15.0, this behavior has been disabled by default. From version 2.16.0 (along with 2.12.2, 2.12.3, and 2.3.1), this functionality has been completely removed. Note that this vulnerability is specific to log4j-core and does not affect log4net, log4cxx, or other Apache Logging Services projects.

- [https://github.com/tg12/PoC_CVEs](https://github.com/tg12/PoC_CVEs) :  ![starts](https://img.shields.io/github/stars/tg12/PoC_CVEs.svg) ![forks](https://img.shields.io/github/forks/tg12/PoC_CVEs.svg)


## CVE-2021-3129
 Ignition before 2.5.2, as used in Laravel and other products, allows unauthenticated remote attackers to execute arbitrary code because of insecure usage of file_get_contents() and file_put_contents(). This is exploitable on sites using debug mode with Laravel before 8.4.2.

- [https://github.com/hupe1980/CVE-2021-3129](https://github.com/hupe1980/CVE-2021-3129) :  ![starts](https://img.shields.io/github/stars/hupe1980/CVE-2021-3129.svg) ![forks](https://img.shields.io/github/forks/hupe1980/CVE-2021-3129.svg)


## CVE-2020-35314
 A remote code execution vulnerability in the installUpdateThemePluginAction function in index.php in WonderCMS 3.1.3, allows remote attackers to upload a custom plugin which can contain arbitrary code and obtain a webshell via the theme/plugin installer.

- [https://github.com/AkashLingayat/WonderCMS-CVE-2020-35314](https://github.com/AkashLingayat/WonderCMS-CVE-2020-35314) :  ![starts](https://img.shields.io/github/stars/AkashLingayat/WonderCMS-CVE-2020-35314.svg) ![forks](https://img.shields.io/github/forks/AkashLingayat/WonderCMS-CVE-2020-35314.svg)


## CVE-2014-0224
 OpenSSL before 0.9.8za, 1.0.0 before 1.0.0m, and 1.0.1 before 1.0.1h does not properly restrict processing of ChangeCipherSpec messages, which allows man-in-the-middle attackers to trigger use of a zero-length master key in certain OpenSSL-to-OpenSSL communications, and consequently hijack sessions or obtain sensitive information, via a crafted TLS handshake, aka the &quot;CCS Injection&quot; vulnerability.

- [https://github.com/secretnonempty/CVE-2014-0224](https://github.com/secretnonempty/CVE-2014-0224) :  ![starts](https://img.shields.io/github/stars/secretnonempty/CVE-2014-0224.svg) ![forks](https://img.shields.io/github/forks/secretnonempty/CVE-2014-0224.svg)
- [https://github.com/iph0n3/CVE-2014-0224](https://github.com/iph0n3/CVE-2014-0224) :  ![starts](https://img.shields.io/github/stars/iph0n3/CVE-2014-0224.svg) ![forks](https://img.shields.io/github/forks/iph0n3/CVE-2014-0224.svg)

