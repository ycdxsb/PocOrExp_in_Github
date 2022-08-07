# Update 2022-08-07
## CVE-2022-29582
 In the Linux kernel before 5.17.3, fs/io_uring.c has a use-after-free due to a race condition in io_uring timeouts. This can be triggered by a local user who has no access to any user namespace; however, the race condition perhaps can only be exploited infrequently.

- [https://github.com/Ruia-ruia/CVE-2022-29582-Exploit](https://github.com/Ruia-ruia/CVE-2022-29582-Exploit) :  ![starts](https://img.shields.io/github/stars/Ruia-ruia/CVE-2022-29582-Exploit.svg) ![forks](https://img.shields.io/github/forks/Ruia-ruia/CVE-2022-29582-Exploit.svg)


## CVE-2022-27434
 UNIT4 TETA Mobile Edition (ME) before 29.5.HF17 was discovered to contain a SQL injection vulnerability via the ProfileName parameter in the errorReporting page.

- [https://github.com/LongWayHomie/CVE-2022-27434](https://github.com/LongWayHomie/CVE-2022-27434) :  ![starts](https://img.shields.io/github/stars/LongWayHomie/CVE-2022-27434.svg) ![forks](https://img.shields.io/github/forks/LongWayHomie/CVE-2022-27434.svg)


## CVE-2021-23841
 The OpenSSL public API function X509_issuer_and_serial_hash() attempts to create a unique hash value based on the issuer and serial number data contained within an X509 certificate. However it fails to correctly handle any errors that may occur while parsing the issuer field (which might occur if the issuer field is maliciously constructed). This may subsequently result in a NULL pointer deref and a crash leading to a potential denial of service attack. The function X509_issuer_and_serial_hash() is never directly called by OpenSSL itself so applications are only vulnerable if they use this function directly and they use it on certificates that may have been obtained from untrusted sources. OpenSSL versions 1.1.1i and below are affected by this issue. Users of these versions should upgrade to OpenSSL 1.1.1j. OpenSSL versions 1.0.2x and below are affected by this issue. However OpenSSL 1.0.2 is out of support and no longer receiving public updates. Premium support customers of OpenSSL 1.0.2 should upgrade to 1.0.2y. Other users should upgrade to 1.1.1j. Fixed in OpenSSL 1.1.1j (Affected 1.1.1-1.1.1i). Fixed in OpenSSL 1.0.2y (Affected 1.0.2-1.0.2x).

- [https://github.com/Satheesh575555/Openssl_1_1_0_CVE-2021-23841](https://github.com/Satheesh575555/Openssl_1_1_0_CVE-2021-23841) :  ![starts](https://img.shields.io/github/stars/Satheesh575555/Openssl_1_1_0_CVE-2021-23841.svg) ![forks](https://img.shields.io/github/forks/Satheesh575555/Openssl_1_1_0_CVE-2021-23841.svg)


## CVE-2020-35476
 A remote code execution vulnerability occurs in OpenTSDB through 2.4.0 via command injection in the yrange parameter. The yrange value is written to a gnuplot file in the /tmp directory. This file is then executed via the mygnuplot.sh shell script. (tsd/GraphHandler.java attempted to prevent command injections by blocking backticks but this is insufficient.)

- [https://github.com/glowbase/CVE-2020-35476](https://github.com/glowbase/CVE-2020-35476) :  ![starts](https://img.shields.io/github/stars/glowbase/CVE-2020-35476.svg) ![forks](https://img.shields.io/github/forks/glowbase/CVE-2020-35476.svg)


## CVE-2020-9934
 An issue existed in the handling of environment variables. This issue was addressed with improved validation. This issue is fixed in iOS 13.6 and iPadOS 13.6, macOS Catalina 10.15.6. A local user may be able to view sensitive user information.

- [https://github.com/mattshockl/CVE-2020-9934](https://github.com/mattshockl/CVE-2020-9934) :  ![starts](https://img.shields.io/github/stars/mattshockl/CVE-2020-9934.svg) ![forks](https://img.shields.io/github/forks/mattshockl/CVE-2020-9934.svg)


## CVE-2019-8561
 A logic issue was addressed with improved validation. This issue is fixed in macOS Mojave 10.14.4. A malicious application may be able to elevate privileges.

- [https://github.com/0xmachos/CVE-2019-8561](https://github.com/0xmachos/CVE-2019-8561) :  ![starts](https://img.shields.io/github/stars/0xmachos/CVE-2019-8561.svg) ![forks](https://img.shields.io/github/forks/0xmachos/CVE-2019-8561.svg)


## CVE-2017-16894
 In Laravel framework through 5.5.21, remote attackers can obtain sensitive information (such as externally usable passwords) via a direct request for the /.env URI. NOTE: this CVE is only about Laravel framework's writeNewEnvironmentFileWith function in src/Illuminate/Foundation/Console/KeyGenerateCommand.php, which uses file_put_contents without restricting the .env permissions. The .env filename is not used exclusively by Laravel framework.

- [https://github.com/asfdc/CVE-2017-16894](https://github.com/asfdc/CVE-2017-16894) :  ![starts](https://img.shields.io/github/stars/asfdc/CVE-2017-16894.svg) ![forks](https://img.shields.io/github/forks/asfdc/CVE-2017-16894.svg)


## CVE-2015-3073
 Adobe Reader and Acrobat 10.x before 10.1.14 and 11.x before 11.0.11 on Windows and OS X allow attackers to bypass intended restrictions on JavaScript API execution via unspecified vectors, a different vulnerability than CVE-2015-3060, CVE-2015-3061, CVE-2015-3062, CVE-2015-3063, CVE-2015-3064, CVE-2015-3065, CVE-2015-3066, CVE-2015-3067, CVE-2015-3068, CVE-2015-3069, CVE-2015-3071, CVE-2015-3072, and CVE-2015-3074.

- [https://github.com/reigningshells/CVE-2015-3073](https://github.com/reigningshells/CVE-2015-3073) :  ![starts](https://img.shields.io/github/stars/reigningshells/CVE-2015-3073.svg) ![forks](https://img.shields.io/github/forks/reigningshells/CVE-2015-3073.svg)

