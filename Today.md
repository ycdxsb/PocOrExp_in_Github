# Update 2022-07-11
## CVE-2022-32532
 Apache Shiro before 1.9.1, A RegexRequestMatcher can be misconfigured to be bypassed on some servlet containers. Applications using RegExPatternMatcher with `.` in the regular expression are possibly vulnerable to an authorization bypass.

- [https://github.com/Lay0us1/CVE-2022-32532](https://github.com/Lay0us1/CVE-2022-32532) :  ![starts](https://img.shields.io/github/stars/Lay0us1/CVE-2022-32532.svg) ![forks](https://img.shields.io/github/forks/Lay0us1/CVE-2022-32532.svg)


## CVE-2022-30591
 ** DISPUTED ** quic-go through 0.27.0 allows remote attackers to cause a denial of service (CPU consumption) via a Slowloris variant in which incomplete QUIC or HTTP/3 requests are sent. This occurs because mtu_discoverer.go misparses the MTU Discovery service and consequently overflows the probe timer. NOTE: the vendor's position is that this behavior should not be listed as a vulnerability on the CVE List.

- [https://github.com/efchatz/QUIC-attacks](https://github.com/efchatz/QUIC-attacks) :  ![starts](https://img.shields.io/github/stars/efchatz/QUIC-attacks.svg) ![forks](https://img.shields.io/github/forks/efchatz/QUIC-attacks.svg)


## CVE-2022-29885
 The documentation of Apache Tomcat 10.1.0-M1 to 10.1.0-M14, 10.0.0-M1 to 10.0.20, 9.0.13 to 9.0.62 and 8.5.38 to 8.5.78 for the EncryptInterceptor incorrectly stated it enabled Tomcat clustering to run over an untrusted network. This was not correct. While the EncryptInterceptor does provide confidentiality and integrity protection, it does not protect against all risks associated with running over any untrusted network, particularly DoS risks.

- [https://github.com/quynhlab/CVE-2022-29885](https://github.com/quynhlab/CVE-2022-29885) :  ![starts](https://img.shields.io/github/stars/quynhlab/CVE-2022-29885.svg) ![forks](https://img.shields.io/github/forks/quynhlab/CVE-2022-29885.svg)


## CVE-2022-29552
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/ComparedArray/printix-CVE-2022-29554](https://github.com/ComparedArray/printix-CVE-2022-29554) :  ![starts](https://img.shields.io/github/stars/ComparedArray/printix-CVE-2022-29554.svg) ![forks](https://img.shields.io/github/forks/ComparedArray/printix-CVE-2022-29554.svg)


## CVE-2022-25845
 The package com.alibaba:fastjson before 1.2.83 are vulnerable to Deserialization of Untrusted Data by bypassing the default autoType shutdown restrictions, which is possible under certain conditions. Exploiting this vulnerability allows attacking remote servers. Workaround: If upgrading is not possible, you can enable [safeMode](https://github.com/alibaba/fastjson/wiki/fastjson_safemode).

- [https://github.com/Expl0desploit/CVE-2022-25845](https://github.com/Expl0desploit/CVE-2022-25845) :  ![starts](https://img.shields.io/github/stars/Expl0desploit/CVE-2022-25845.svg) ![forks](https://img.shields.io/github/forks/Expl0desploit/CVE-2022-25845.svg)


## CVE-2022-23222
 kernel/bpf/verifier.c in the Linux kernel through 5.15.14 allows local users to gain privileges because of the availability of pointer arithmetic via certain *_OR_NULL pointer types.

- [https://github.com/RafaelOrtizRC/CVE-2022-23222](https://github.com/RafaelOrtizRC/CVE-2022-23222) :  ![starts](https://img.shields.io/github/stars/RafaelOrtizRC/CVE-2022-23222.svg) ![forks](https://img.shields.io/github/forks/RafaelOrtizRC/CVE-2022-23222.svg)


## CVE-2022-2185
 A critical issue has been discovered in GitLab affecting all versions starting from 14.0 prior to 14.10.5, 15.0 prior to 15.0.4, and 15.1 prior to 15.1.1 where it was possible for an unauthorised user to execute arbitrary code on the server using the project import feature.

- [https://github.com/west-wind/Threat-Hunting-With-Splunk](https://github.com/west-wind/Threat-Hunting-With-Splunk) :  ![starts](https://img.shields.io/github/stars/west-wind/Threat-Hunting-With-Splunk.svg) ![forks](https://img.shields.io/github/forks/west-wind/Threat-Hunting-With-Splunk.svg)


## CVE-2021-27965
 The MsIo64.sys driver before 1.1.19.1016 in MSI Dragon Center before 2.0.98.0 has a buffer overflow that allows privilege escalation via a crafted 0x80102040, 0x80102044, 0x80102050, or 0x80102054 IOCTL request.

- [https://github.com/Exploitables/CVE-2021-27965](https://github.com/Exploitables/CVE-2021-27965) :  ![starts](https://img.shields.io/github/stars/Exploitables/CVE-2021-27965.svg) ![forks](https://img.shields.io/github/forks/Exploitables/CVE-2021-27965.svg)


## CVE-2021-25094
 The Tatsu WordPress plugin before 3.3.12 add_custom_font action can be used without prior authentication to upload a rogue zip file which is uncompressed under the WordPress's upload directory. By adding a PHP shell with a filename starting with a dot &quot;.&quot;, this can bypass extension control implemented in the plugin. Moreover, there is a race condition in the zip extraction process which makes the shell file live long enough on the filesystem to be callable by an attacker.

- [https://github.com/TUANB4DUT/typehub-exploiter](https://github.com/TUANB4DUT/typehub-exploiter) :  ![starts](https://img.shields.io/github/stars/TUANB4DUT/typehub-exploiter.svg) ![forks](https://img.shields.io/github/forks/TUANB4DUT/typehub-exploiter.svg)


## CVE-2020-8816
 Pi-hole Web v4.3.2 (aka AdminLTE) allows Remote Code Execution by privileged dashboard users via a crafted DHCP static lease.

- [https://github.com/martinsohn/CVE-2020-8816](https://github.com/martinsohn/CVE-2020-8816) :  ![starts](https://img.shields.io/github/stars/martinsohn/CVE-2020-8816.svg) ![forks](https://img.shields.io/github/forks/martinsohn/CVE-2020-8816.svg)


## CVE-2020-1967
 Server or client applications that call the SSL_check_chain() function during or after a TLS 1.3 handshake may crash due to a NULL pointer dereference as a result of incorrect handling of the &quot;signature_algorithms_cert&quot; TLS extension. The crash occurs if an invalid or unrecognised signature algorithm is received from the peer. This could be exploited by a malicious peer in a Denial of Service attack. OpenSSL version 1.1.1d, 1.1.1e, and 1.1.1f are affected by this issue. This issue did not affect OpenSSL versions prior to 1.1.1d. Fixed in OpenSSL 1.1.1g (Affected 1.1.1d-1.1.1f).

- [https://github.com/irsl/CVE-2020-1967](https://github.com/irsl/CVE-2020-1967) :  ![starts](https://img.shields.io/github/stars/irsl/CVE-2020-1967.svg) ![forks](https://img.shields.io/github/forks/irsl/CVE-2020-1967.svg)


## CVE-2019-18845
 The MsIo64.sys and MsIo32.sys drivers in Patriot Viper RGB before 1.1 allow local users (including low integrity processes) to read and write to arbitrary memory locations, and consequently gain NT AUTHORITY\SYSTEM privileges, by mapping \Device\PhysicalMemory into the calling process via ZwOpenSection and ZwMapViewOfSection.

- [https://github.com/Exploitables/CVE-2019-18845](https://github.com/Exploitables/CVE-2019-18845) :  ![starts](https://img.shields.io/github/stars/Exploitables/CVE-2019-18845.svg) ![forks](https://img.shields.io/github/forks/Exploitables/CVE-2019-18845.svg)


## CVE-2009-4049
 Heap-based buffer overflow in aswRdr.sys (aka the TDI RDR driver) in avast! Home and Professional 4.8.1356.0 allows local users to cause a denial of service (memory corruption) or possibly gain privileges via crafted arguments to IOCTL 0x80002024.

- [https://github.com/Exploitables/CVE-2009-4049](https://github.com/Exploitables/CVE-2009-4049) :  ![starts](https://img.shields.io/github/stars/Exploitables/CVE-2009-4049.svg) ![forks](https://img.shields.io/github/forks/Exploitables/CVE-2009-4049.svg)

