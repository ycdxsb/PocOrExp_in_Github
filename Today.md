# Update 2021-07-19
## CVE-2021-21315
 The System Information Library for Node.JS (npm package &quot;systeminformation&quot;) is an open source collection of functions to retrieve detailed hardware, system and OS information. In systeminformation before version 5.3.1 there is a command injection vulnerability. Problem was fixed in version 5.3.1. As a workaround instead of upgrading, be sure to check or sanitize service parameters that are passed to si.inetLatency(), si.inetChecksite(), si.services(), si.processLoad() ... do only allow strings, reject any arrays. String sanitation works as expected.

- [https://github.com/MazX0p/CVE-2021-21315-exploit](https://github.com/MazX0p/CVE-2021-21315-exploit) :  ![starts](https://img.shields.io/github/stars/MazX0p/CVE-2021-21315-exploit.svg) ![forks](https://img.shields.io/github/forks/MazX0p/CVE-2021-21315-exploit.svg)


## CVE-2020-14882
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Console). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0, 12.2.1.4.0 and 14.1.1.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/0xhatuna/CVE-2020-14882](https://github.com/0xhatuna/CVE-2020-14882) :  ![starts](https://img.shields.io/github/stars/0xhatuna/CVE-2020-14882.svg) ![forks](https://img.shields.io/github/forks/0xhatuna/CVE-2020-14882.svg)

