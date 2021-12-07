# Update 2021-12-07
## CVE-2021-41157
 FreeSWITCH is a Software Defined Telecom Stack enabling the digital transformation from proprietary telecom switches to a software implementation that runs on any commodity hardware. By default, SIP requests of the type SUBSCRIBE are not authenticated in the affected versions of FreeSWITCH. Abuse of this security issue allows attackers to subscribe to user agent event notifications without the need to authenticate. This abuse poses privacy concerns and might lead to social engineering or similar attacks. For example, attackers may be able to monitor the status of target SIP extensions. Although this issue was fixed in version v1.10.6, installations upgraded to the fixed version of FreeSWITCH from an older version, may still be vulnerable if the configuration is not updated accordingly. Software upgrades do not update the configuration by default. SIP SUBSCRIBE messages should be authenticated by default so that FreeSWITCH administrators do not need to explicitly set the `auth-subscriptions` parameter. When following such a recommendation, a new parameter can be introduced to explicitly disable authentication.

- [https://github.com/0xInfection/PewSWITCH](https://github.com/0xInfection/PewSWITCH) :  ![starts](https://img.shields.io/github/stars/0xInfection/PewSWITCH.svg) ![forks](https://img.shields.io/github/forks/0xInfection/PewSWITCH.svg)


## CVE-2021-37624
 FreeSWITCH is a Software Defined Telecom Stack enabling the digital transformation from proprietary telecom switches to a software implementation that runs on any commodity hardware. Prior to version 1.10.7, FreeSWITCH does not authenticate SIP MESSAGE requests, leading to spam and message spoofing. By default, SIP requests of the type MESSAGE (RFC 3428) are not authenticated in the affected versions of FreeSWITCH. MESSAGE requests are relayed to SIP user agents registered with the FreeSWITCH server without requiring any authentication. Although this behaviour can be changed by setting the `auth-messages` parameter to `true`, it is not the default setting. Abuse of this security issue allows attackers to send SIP MESSAGE messages to any SIP user agent that is registered with the server without requiring authentication. Additionally, since no authentication is required, chat messages can be spoofed to appear to come from trusted entities. Therefore, abuse can lead to spam and enable social engineering, phishing and similar attacks. This issue is patched in version 1.10.7. Maintainers recommend that this SIP message type is authenticated by default so that FreeSWITCH administrators do not need to be explicitly set the `auth-messages` parameter. When following such a recommendation, a new parameter can be introduced to explicitly disable authentication.

- [https://github.com/0xInfection/PewSWITCH](https://github.com/0xInfection/PewSWITCH) :  ![starts](https://img.shields.io/github/stars/0xInfection/PewSWITCH.svg) ![forks](https://img.shields.io/github/forks/0xInfection/PewSWITCH.svg)


## CVE-2021-1675
 Windows Print Spooler Elevation of Privilege Vulnerability

- [https://github.com/fumamatar/NimNightmare](https://github.com/fumamatar/NimNightmare) :  ![starts](https://img.shields.io/github/stars/fumamatar/NimNightmare.svg) ![forks](https://img.shields.io/github/forks/fumamatar/NimNightmare.svg)


## CVE-2017-8046
 Malicious PATCH requests submitted to servers using Spring Data REST versions prior to 2.6.9 (Ingalls SR9), versions prior to 3.0.1 (Kay SR1) and Spring Boot versions prior to 1.5.9, 2.0 M6 can use specially crafted JSON data to run arbitrary Java code.

- [https://github.com/bkhablenko/CVE-2017-8046](https://github.com/bkhablenko/CVE-2017-8046) :  ![starts](https://img.shields.io/github/stars/bkhablenko/CVE-2017-8046.svg) ![forks](https://img.shields.io/github/forks/bkhablenko/CVE-2017-8046.svg)


## CVE-2017-5941
 An issue was discovered in the node-serialize package 0.0.4 for Node.js. Untrusted data passed into the unserialize() function can be exploited to achieve arbitrary code execution by passing a JavaScript Object with an Immediately Invoked Function Expression (IIFE).

- [https://github.com/z0edff0x3d/CVE-2017-5941-NodeJS-RCE](https://github.com/z0edff0x3d/CVE-2017-5941-NodeJS-RCE) :  ![starts](https://img.shields.io/github/stars/z0edff0x3d/CVE-2017-5941-NodeJS-RCE.svg) ![forks](https://img.shields.io/github/forks/z0edff0x3d/CVE-2017-5941-NodeJS-RCE.svg)


## CVE-2016-2098
 Action Pack in Ruby on Rails before 3.2.22.2, 4.x before 4.1.14.2, and 4.2.x before 4.2.5.2 allows remote attackers to execute arbitrary Ruby code by leveraging an application's unrestricted use of the render method.

- [https://github.com/DanielCodex/CVE-2016-2098-my-first-exploit](https://github.com/DanielCodex/CVE-2016-2098-my-first-exploit) :  ![starts](https://img.shields.io/github/stars/DanielCodex/CVE-2016-2098-my-first-exploit.svg) ![forks](https://img.shields.io/github/forks/DanielCodex/CVE-2016-2098-my-first-exploit.svg)


## CVE-2014-6287
 The findMacroMarker function in parserLib.pas in Rejetto HTTP File Server (aks HFS or HttpFileServer) 2.3x before 2.3c allows remote attackers to execute arbitrary programs via a %00 sequence in a search action.

- [https://github.com/Mr-Intern/thm_steelmountain_CVE-2014-6287](https://github.com/Mr-Intern/thm_steelmountain_CVE-2014-6287) :  ![starts](https://img.shields.io/github/stars/Mr-Intern/thm_steelmountain_CVE-2014-6287.svg) ![forks](https://img.shields.io/github/forks/Mr-Intern/thm_steelmountain_CVE-2014-6287.svg)


## CVE-2012-1823
 sapi/cgi/cgi_main.c in PHP before 5.3.12 and 5.4.x before 5.4.2, when configured as a CGI script (aka php-cgi), does not properly handle query strings that lack an = (equals sign) character, which allows remote attackers to execute arbitrary code by placing command-line options in the query string, related to lack of skipping a certain php_getopt for the 'd' case.

- [https://github.com/tardummy01/oscp_scripts-1](https://github.com/tardummy01/oscp_scripts-1) :  ![starts](https://img.shields.io/github/stars/tardummy01/oscp_scripts-1.svg) ![forks](https://img.shields.io/github/forks/tardummy01/oscp_scripts-1.svg)


## CVE-2002-20001
 The Diffie-Hellman Key Agreement Protocol allows remote attackers (from the client side) to send arbitrary numbers that are actually not public keys, and trigger expensive server-side DHE modular-exponentiation calculations, aka a D(HE)ater attack. The client needs very little CPU resources and network bandwidth. The attack may be more disruptive in cases where a client can require a server to select its largest supported key size. The basic attack scenario is that the client must claim that it can only communicate with DHE, and the server must be configured to allow DHE.

- [https://github.com/Balasys/dheater](https://github.com/Balasys/dheater) :  ![starts](https://img.shields.io/github/stars/Balasys/dheater.svg) ![forks](https://img.shields.io/github/forks/Balasys/dheater.svg)

