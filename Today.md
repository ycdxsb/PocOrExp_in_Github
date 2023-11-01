# Update 2023-11-01
## CVE-2023-47103
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/quantiano/cve-2023-47103](https://github.com/quantiano/cve-2023-47103) :  ![starts](https://img.shields.io/github/stars/quantiano/cve-2023-47103.svg) ![forks](https://img.shields.io/github/forks/quantiano/cve-2023-47103.svg)


## CVE-2023-46747
 Undisclosed requests may bypass configuration utility authentication, allowing an attacker with network access to the BIG-IP system through the management port and/or self IP addresses to execute arbitrary system commands. Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated

- [https://github.com/AliBrTab/CVE-2023-46747-POC](https://github.com/AliBrTab/CVE-2023-46747-POC) :  ![starts](https://img.shields.io/github/stars/AliBrTab/CVE-2023-46747-POC.svg) ![forks](https://img.shields.io/github/forks/AliBrTab/CVE-2023-46747-POC.svg)
- [https://github.com/k0zulzr/CVE-2023-46747-Mass-RCE](https://github.com/k0zulzr/CVE-2023-46747-Mass-RCE) :  ![starts](https://img.shields.io/github/stars/k0zulzr/CVE-2023-46747-Mass-RCE.svg) ![forks](https://img.shields.io/github/forks/k0zulzr/CVE-2023-46747-Mass-RCE.svg)
- [https://github.com/TomArn1/CVE-2023-46747-PoC](https://github.com/TomArn1/CVE-2023-46747-PoC) :  ![starts](https://img.shields.io/github/stars/TomArn1/CVE-2023-46747-PoC.svg) ![forks](https://img.shields.io/github/forks/TomArn1/CVE-2023-46747-PoC.svg)


## CVE-2023-46478
 An issue in minCal v.1.0.0 allows a remote attacker to execute arbitrary code via a crafted script to the customer_data parameter.

- [https://github.com/mr-xmen786/CVE-2023-46478](https://github.com/mr-xmen786/CVE-2023-46478) :  ![starts](https://img.shields.io/github/stars/mr-xmen786/CVE-2023-46478.svg) ![forks](https://img.shields.io/github/forks/mr-xmen786/CVE-2023-46478.svg)


## CVE-2023-41064
 A buffer overflow issue was addressed with improved memory handling. This issue is fixed in iOS 16.6.1 and iPadOS 16.6.1, macOS Monterey 12.6.9, macOS Ventura 13.5.2, iOS 15.7.9 and iPadOS 15.7.9, macOS Big Sur 11.7.10. Processing a maliciously crafted image may lead to arbitrary code execution. Apple is aware of a report that this issue may have been actively exploited.

- [https://github.com/MrR0b0t19/vulnerabilidad-LibWebP-CVE-2023-41064](https://github.com/MrR0b0t19/vulnerabilidad-LibWebP-CVE-2023-41064) :  ![starts](https://img.shields.io/github/stars/MrR0b0t19/vulnerabilidad-LibWebP-CVE-2023-41064.svg) ![forks](https://img.shields.io/github/forks/MrR0b0t19/vulnerabilidad-LibWebP-CVE-2023-41064.svg)


## CVE-2023-23752
 An issue was discovered in Joomla! 4.0.0 through 4.2.7. An improper access check allows unauthorized access to webservice endpoints.

- [https://github.com/cybernetwiz/CVE-2023-23752](https://github.com/cybernetwiz/CVE-2023-23752) :  ![starts](https://img.shields.io/github/stars/cybernetwiz/CVE-2023-23752.svg) ![forks](https://img.shields.io/github/forks/cybernetwiz/CVE-2023-23752.svg)


## CVE-2023-5843
 The Ads by datafeedr.com plugin for WordPress is vulnerable to Remote Code Execution in versions up to, and including, 1.1.3 via the 'dfads_ajax_load_ads' function. This allows unauthenticated attackers to execute code on the server. The parameters of the callable function are limited, they cannot be specified arbitrarily.

- [https://github.com/codeb0ss/CVE-2023-5843-PoC](https://github.com/codeb0ss/CVE-2023-5843-PoC) :  ![starts](https://img.shields.io/github/stars/codeb0ss/CVE-2023-5843-PoC.svg) ![forks](https://img.shields.io/github/forks/codeb0ss/CVE-2023-5843-PoC.svg)


## CVE-2023-5044
 Code injection via nginx.ingress.kubernetes.io/permanent-redirect annotation.

- [https://github.com/r0binak/CVE-2023-5044](https://github.com/r0binak/CVE-2023-5044) :  ![starts](https://img.shields.io/github/stars/r0binak/CVE-2023-5044.svg) ![forks](https://img.shields.io/github/forks/r0binak/CVE-2023-5044.svg)


## CVE-2022-0778
 The BN_mod_sqrt() function, which computes a modular square root, contains a bug that can cause it to loop forever for non-prime moduli. Internally this function is used when parsing certificates that contain elliptic curve public keys in compressed form or explicit elliptic curve parameters with a base point encoded in compressed form. It is possible to trigger the infinite loop by crafting a certificate that has invalid explicit curve parameters. Since certificate parsing happens prior to verification of the certificate signature, any process that parses an externally supplied certificate may thus be subject to a denial of service attack. The infinite loop can also be reached when parsing crafted private keys as they can contain explicit elliptic curve parameters. Thus vulnerable situations include: - TLS clients consuming server certificates - TLS servers consuming client certificates - Hosting providers taking certificates or private keys from customers - Certificate authorities parsing certification requests from subscribers - Anything else which parses ASN.1 elliptic curve parameters Also any other applications that use the BN_mod_sqrt() where the attacker can control the parameter values are vulnerable to this DoS issue. In the OpenSSL 1.0.2 version the public key is not parsed during initial parsing of the certificate which makes it slightly harder to trigger the infinite loop. However any operation which requires the public key from the certificate will trigger the infinite loop. In particular the attacker can use a self-signed certificate to trigger the loop during verification of the certificate signature. This issue affects OpenSSL versions 1.0.2, 1.1.1 and 3.0. It was addressed in the releases of 1.1.1n and 3.0.2 on the 15th March 2022. Fixed in OpenSSL 3.0.2 (Affected 3.0.0,3.0.1). Fixed in OpenSSL 1.1.1n (Affected 1.1.1-1.1.1m). Fixed in OpenSSL 1.0.2zd (Affected 1.0.2-1.0.2zc).

- [https://github.com/nidhi7598/OPENSSL_1.0.1g_G2.5_CVE-2022-0778](https://github.com/nidhi7598/OPENSSL_1.0.1g_G2.5_CVE-2022-0778) :  ![starts](https://img.shields.io/github/stars/nidhi7598/OPENSSL_1.0.1g_G2.5_CVE-2022-0778.svg) ![forks](https://img.shields.io/github/forks/nidhi7598/OPENSSL_1.0.1g_G2.5_CVE-2022-0778.svg)


## CVE-2021-22911
 A improper input sanitization vulnerability exists in Rocket.Chat server 3.11, 3.12 &amp; 3.13 that could lead to unauthenticated NoSQL injection, resulting potentially in RCE.

- [https://github.com/vlrhsgody/-vlrhsgody-RocketChat-CVE-2021-22911-](https://github.com/vlrhsgody/-vlrhsgody-RocketChat-CVE-2021-22911-) :  ![starts](https://img.shields.io/github/stars/vlrhsgody/-vlrhsgody-RocketChat-CVE-2021-22911-.svg) ![forks](https://img.shields.io/github/forks/vlrhsgody/-vlrhsgody-RocketChat-CVE-2021-22911-.svg)


## CVE-2020-27216
 In Eclipse Jetty versions 1.0 thru 9.4.32.v20200930, 10.0.0.alpha1 thru 10.0.0.beta2, and 11.0.0.alpha1 thru 11.0.0.beta2O, on Unix like systems, the system's temporary directory is shared between all users on that system. A collocated user can observe the process of creating a temporary sub directory in the shared temporary directory and race to complete the creation of the temporary subdirectory. If the attacker wins the race then they will have read and write permission to the subdirectory used to unpack web applications, including their WEB-INF/lib jar files and JSP files. If any code is ever executed out of this temporary directory, this can lead to a local privilege escalation vulnerability.

- [https://github.com/nidhi7598/jetty-9.4.31_CVE-2020-27216](https://github.com/nidhi7598/jetty-9.4.31_CVE-2020-27216) :  ![starts](https://img.shields.io/github/stars/nidhi7598/jetty-9.4.31_CVE-2020-27216.svg) ![forks](https://img.shields.io/github/forks/nidhi7598/jetty-9.4.31_CVE-2020-27216.svg)


## CVE-2020-20093
 The Facebook Messenger app for iOS 227.0 and prior and Android 228.1.0.10.116 and prior user interface does not properly represent URI messages to the user, which results in URI spoofing via specially crafted messages.

- [https://github.com/zadewg/RIUS](https://github.com/zadewg/RIUS) :  ![starts](https://img.shields.io/github/stars/zadewg/RIUS.svg) ![forks](https://img.shields.io/github/forks/zadewg/RIUS.svg)


## CVE-2018-20377
 Orange Livebox 00.96.320S devices allow remote attackers to discover Wi-Fi credentials via /get_getnetworkconf.cgi on port 8080, leading to full control if the admin password equals the Wi-Fi password or has the default admin value. This is related to Firmware 01.11.2017-11:43:44, Boot v0.70.03, Modem 5.4.1.10.1.1A, Hardware 02, and Arcadyan ARV7519RW22-A-L T VR9 1.2.

- [https://github.com/zadewg/LIVEBOX-0DAY](https://github.com/zadewg/LIVEBOX-0DAY) :  ![starts](https://img.shields.io/github/stars/zadewg/LIVEBOX-0DAY.svg) ![forks](https://img.shields.io/github/forks/zadewg/LIVEBOX-0DAY.svg)


## CVE-2018-15473
 OpenSSH through 7.7 is prone to a user enumeration vulnerability due to not delaying bailout for an invalid authenticating user until after the packet containing the request has been fully parsed, related to auth2-gss.c, auth2-hostbased.c, and auth2-pubkey.c.

- [https://github.com/4xolotl/CVE-2018-15473](https://github.com/4xolotl/CVE-2018-15473) :  ![starts](https://img.shields.io/github/stars/4xolotl/CVE-2018-15473.svg) ![forks](https://img.shields.io/github/forks/4xolotl/CVE-2018-15473.svg)


## CVE-2018-1297
 When using Distributed Test only (RMI based), Apache JMeter 2.x and 3.x uses an unsecured RMI connection. This could allow an attacker to get Access to JMeterEngine and send unauthorized code.

- [https://github.com/48484848484848/Jmeter-CVE-2018-1297-](https://github.com/48484848484848/Jmeter-CVE-2018-1297-) :  ![starts](https://img.shields.io/github/stars/48484848484848/Jmeter-CVE-2018-1297-.svg) ![forks](https://img.shields.io/github/forks/48484848484848/Jmeter-CVE-2018-1297-.svg)


## CVE-2014-6271
 GNU Bash through 4.3 processes trailing strings after function definitions in the values of environment variables, which allows remote attackers to execute arbitrary code via a crafted environment, as demonstrated by vectors involving the ForceCommand feature in OpenSSH sshd, the mod_cgi and mod_cgid modules in the Apache HTTP Server, scripts executed by unspecified DHCP clients, and other situations in which setting the environment occurs across a privilege boundary from Bash execution, aka &quot;ShellShock.&quot;  NOTE: the original fix for this issue was incorrect; CVE-2014-7169 has been assigned to cover the vulnerability that is still present after the incorrect fix.

- [https://github.com/0xN7y/CVE-2014-6271](https://github.com/0xN7y/CVE-2014-6271) :  ![starts](https://img.shields.io/github/stars/0xN7y/CVE-2014-6271.svg) ![forks](https://img.shields.io/github/forks/0xN7y/CVE-2014-6271.svg)

