# Update 2023-06-03
## CVE-2023-33381
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/duality084/CVE-2023-33381-MitraStar-GPT-2741GNAC](https://github.com/duality084/CVE-2023-33381-MitraStar-GPT-2741GNAC) :  ![starts](https://img.shields.io/github/stars/duality084/CVE-2023-33381-MitraStar-GPT-2741GNAC.svg) ![forks](https://img.shields.io/github/forks/duality084/CVE-2023-33381-MitraStar-GPT-2741GNAC.svg)


## CVE-2023-33246
 For RocketMQ versions 5.1.0 and below, under certain conditions, there is a risk of remote command execution. Several components of RocketMQ, including NameServer, Broker, and Controller, are leaked on the extranet and lack permission verification, an attacker can exploit this vulnerability by using the update configuration function to execute commands as the system users that RocketMQ is running as. Additionally, an attacker can achieve the same effect by forging the RocketMQ protocol content. To prevent these attacks, users are recommended to upgrade to version 5.1.1 or above for using RocketMQ 5.x or 4.9.6 or above for using RocketMQ 4.x .

- [https://github.com/SuperZero/CVE-2023-33246](https://github.com/SuperZero/CVE-2023-33246) :  ![starts](https://img.shields.io/github/stars/SuperZero/CVE-2023-33246.svg) ![forks](https://img.shields.io/github/forks/SuperZero/CVE-2023-33246.svg)
- [https://github.com/Malayke/CVE-2023-33246_RocketMQ_RCE_EXPLOIT](https://github.com/Malayke/CVE-2023-33246_RocketMQ_RCE_EXPLOIT) :  ![starts](https://img.shields.io/github/stars/Malayke/CVE-2023-33246_RocketMQ_RCE_EXPLOIT.svg) ![forks](https://img.shields.io/github/forks/Malayke/CVE-2023-33246_RocketMQ_RCE_EXPLOIT.svg)
- [https://github.com/CKevens/CVE-2023-33246](https://github.com/CKevens/CVE-2023-33246) :  ![starts](https://img.shields.io/github/stars/CKevens/CVE-2023-33246.svg) ![forks](https://img.shields.io/github/forks/CKevens/CVE-2023-33246.svg)


## CVE-2023-29489
 An issue was discovered in cPanel before 11.109.9999.116. XSS can occur on the cpsrvd error page via an invalid webcall ID, aka SEC-669. The fixed versions are 11.109.9999.116, 11.108.0.13, 11.106.0.18, and 11.102.0.31.

- [https://github.com/Abdullah7-ma/CVE-2023-29489](https://github.com/Abdullah7-ma/CVE-2023-29489) :  ![starts](https://img.shields.io/github/stars/Abdullah7-ma/CVE-2023-29489.svg) ![forks](https://img.shields.io/github/forks/Abdullah7-ma/CVE-2023-29489.svg)


## CVE-2022-22965
 A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the application to run on Tomcat as a WAR deployment. If the application is deployed as a Spring Boot executable jar, i.e. the default, it is not vulnerable to the exploit. However, the nature of the vulnerability is more general, and there may be other ways to exploit it.

- [https://github.com/bL34cHig0/Telstra-Cybersecurity-Virtual-Experience-](https://github.com/bL34cHig0/Telstra-Cybersecurity-Virtual-Experience-) :  ![starts](https://img.shields.io/github/stars/bL34cHig0/Telstra-Cybersecurity-Virtual-Experience-.svg) ![forks](https://img.shields.io/github/forks/bL34cHig0/Telstra-Cybersecurity-Virtual-Experience-.svg)


## CVE-2022-0778
 The BN_mod_sqrt() function, which computes a modular square root, contains a bug that can cause it to loop forever for non-prime moduli. Internally this function is used when parsing certificates that contain elliptic curve public keys in compressed form or explicit elliptic curve parameters with a base point encoded in compressed form. It is possible to trigger the infinite loop by crafting a certificate that has invalid explicit curve parameters. Since certificate parsing happens prior to verification of the certificate signature, any process that parses an externally supplied certificate may thus be subject to a denial of service attack. The infinite loop can also be reached when parsing crafted private keys as they can contain explicit elliptic curve parameters. Thus vulnerable situations include: - TLS clients consuming server certificates - TLS servers consuming client certificates - Hosting providers taking certificates or private keys from customers - Certificate authorities parsing certification requests from subscribers - Anything else which parses ASN.1 elliptic curve parameters Also any other applications that use the BN_mod_sqrt() where the attacker can control the parameter values are vulnerable to this DoS issue. In the OpenSSL 1.0.2 version the public key is not parsed during initial parsing of the certificate which makes it slightly harder to trigger the infinite loop. However any operation which requires the public key from the certificate will trigger the infinite loop. In particular the attacker can use a self-signed certificate to trigger the loop during verification of the certificate signature. This issue affects OpenSSL versions 1.0.2, 1.1.1 and 3.0. It was addressed in the releases of 1.1.1n and 3.0.2 on the 15th March 2022. Fixed in OpenSSL 3.0.2 (Affected 3.0.0,3.0.1). Fixed in OpenSSL 1.1.1n (Affected 1.1.1-1.1.1m). Fixed in OpenSSL 1.0.2zd (Affected 1.0.2-1.0.2zc).

- [https://github.com/Mrlucas5550100/PoC-CVE-2022-0778-](https://github.com/Mrlucas5550100/PoC-CVE-2022-0778-) :  ![starts](https://img.shields.io/github/stars/Mrlucas5550100/PoC-CVE-2022-0778-.svg) ![forks](https://img.shields.io/github/forks/Mrlucas5550100/PoC-CVE-2022-0778-.svg)


## CVE-2022-0441
 The MasterStudy LMS WordPress plugin before 2.7.6 does to validate some parameters given when registering a new account, allowing unauthenticated users to register as an admin

- [https://github.com/tegal1337/CVE-2022-0441](https://github.com/tegal1337/CVE-2022-0441) :  ![starts](https://img.shields.io/github/stars/tegal1337/CVE-2022-0441.svg) ![forks](https://img.shields.io/github/forks/tegal1337/CVE-2022-0441.svg)


## CVE-2021-22986
 On BIG-IP versions 16.0.x before 16.0.1.1, 15.1.x before 15.1.2.1, 14.1.x before 14.1.4, 13.1.x before 13.1.3.6, and 12.1.x before 12.1.5.3 amd BIG-IQ 7.1.0.x before 7.1.0.3 and 7.0.0.x before 7.0.0.2, the iControl REST interface has an unauthenticated remote command execution vulnerability. Note: Software versions which have reached End of Software Development (EoSD) are not evaluated.

- [https://github.com/kiri-48/CVE-2021-22986](https://github.com/kiri-48/CVE-2021-22986) :  ![starts](https://img.shields.io/github/stars/kiri-48/CVE-2021-22986.svg) ![forks](https://img.shields.io/github/forks/kiri-48/CVE-2021-22986.svg)


## CVE-2019-9978
 The social-warfare plugin before 3.5.3 for WordPress has stored XSS via the wp-admin/admin-post.php?swp_debug=load_options swp_url parameter, as exploited in the wild in March 2019. This affects Social Warfare and Social Warfare Pro.

- [https://github.com/grimlockx/CVE-2019-9978](https://github.com/grimlockx/CVE-2019-9978) :  ![starts](https://img.shields.io/github/stars/grimlockx/CVE-2019-9978.svg) ![forks](https://img.shields.io/github/forks/grimlockx/CVE-2019-9978.svg)


## CVE-2014-2321
 web_shell_cmd.gch on ZTE F460 and F660 cable modems allows remote attackers to obtain administrative access via sendcmd requests, as demonstrated by using &quot;set TelnetCfg&quot; commands to enable a TELNET service with specified credentials.

- [https://github.com/injectionmethod/Windows-ZTE-Loader](https://github.com/injectionmethod/Windows-ZTE-Loader) :  ![starts](https://img.shields.io/github/stars/injectionmethod/Windows-ZTE-Loader.svg) ![forks](https://img.shields.io/github/forks/injectionmethod/Windows-ZTE-Loader.svg)

