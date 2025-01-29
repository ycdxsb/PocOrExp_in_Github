# Update 2025-01-29
## CVE-2025-0411
The specific flaw exists within the handling of archived files. When extracting files from a crafted archive that bears the Mark-of-the-Web, 7-Zip does not propagate the Mark-of-the-Web to the extracted files. An attacker can leverage this vulnerability to execute arbitrary code in the context of the current user. Was ZDI-CAN-25456.

- [https://github.com/iSee857/CVE-2025-0411-PoC](https://github.com/iSee857/CVE-2025-0411-PoC) :  ![starts](https://img.shields.io/github/stars/iSee857/CVE-2025-0411-PoC.svg) ![forks](https://img.shields.io/github/forks/iSee857/CVE-2025-0411-PoC.svg)


## CVE-2024-57373
 Cross Site Request Forgery vulnerability in LifestyleStore v.1.0 allows a remote attacker to execute arbitrary cod and obtain sensitive information.

- [https://github.com/cypherdavy/CVE-2024-57373](https://github.com/cypherdavy/CVE-2024-57373) :  ![starts](https://img.shields.io/github/stars/cypherdavy/CVE-2024-57373.svg) ![forks](https://img.shields.io/github/forks/cypherdavy/CVE-2024-57373.svg)


## CVE-2024-55591
 An Authentication Bypass Using an Alternate Path or Channel vulnerability [CWE-288] affecting FortiOS version 7.0.0 through 7.0.16 and FortiProxy version 7.0.0 through 7.0.19 and 7.2.0 through 7.2.12 allows a remote attacker to gain super-admin privileges via crafted requests to Node.js websocket module.

- [https://github.com/watchtowrlabs/fortios-auth-bypass-poc-CVE-2024-55591](https://github.com/watchtowrlabs/fortios-auth-bypass-poc-CVE-2024-55591) :  ![starts](https://img.shields.io/github/stars/watchtowrlabs/fortios-auth-bypass-poc-CVE-2024-55591.svg) ![forks](https://img.shields.io/github/forks/watchtowrlabs/fortios-auth-bypass-poc-CVE-2024-55591.svg)
- [https://github.com/virus-or-not/CVE-2024-55591](https://github.com/virus-or-not/CVE-2024-55591) :  ![starts](https://img.shields.io/github/stars/virus-or-not/CVE-2024-55591.svg) ![forks](https://img.shields.io/github/forks/virus-or-not/CVE-2024-55591.svg)


## CVE-2024-54507
 A type confusion issue was addressed with improved memory handling. This issue is fixed in macOS Sequoia 15.2, iOS 18.2 and iPadOS 18.2. An attacker with user privileges may be able to read kernel memory.

- [https://github.com/jprx/CVE-2024-54507](https://github.com/jprx/CVE-2024-54507) :  ![starts](https://img.shields.io/github/stars/jprx/CVE-2024-54507.svg) ![forks](https://img.shields.io/github/forks/jprx/CVE-2024-54507.svg)


## CVE-2024-12345
 A vulnerability classified as problematic was found in INW Krbyyyzo 25.2002. Affected by this vulnerability is an unknown functionality of the file /gbo.aspx of the component Daily Huddle Site. The manipulation of the argument s leads to resource consumption. It is possible to launch the attack on the local host. Other endpoints might be affected as well.

- [https://github.com/RoyaRadin/CVE-2024-12345-POC](https://github.com/RoyaRadin/CVE-2024-12345-POC) :  ![starts](https://img.shields.io/github/stars/RoyaRadin/CVE-2024-12345-POC.svg) ![forks](https://img.shields.io/github/forks/RoyaRadin/CVE-2024-12345-POC.svg)


## CVE-2024-2961
 The iconv() function in the GNU C Library versions 2.39 and older may overflow the output buffer passed to it by up to 4 bytes when converting strings to the ISO-2022-CN-EXT character set, which may be used to crash an application or overwrite a neighbouring variable.

- [https://github.com/kyotozx/CVE-2024-2961-Remote-File-Read](https://github.com/kyotozx/CVE-2024-2961-Remote-File-Read) :  ![starts](https://img.shields.io/github/stars/kyotozx/CVE-2024-2961-Remote-File-Read.svg) ![forks](https://img.shields.io/github/forks/kyotozx/CVE-2024-2961-Remote-File-Read.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/Plunder283/CVE-2021-41773](https://github.com/Plunder283/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/Plunder283/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/Plunder283/CVE-2021-41773.svg)


## CVE-2020-28042
 ServiceStack before 5.9.2 mishandles JWT signature verification unless an application has a custom ValidateToken function that establishes a valid minimum length for a signature.

- [https://github.com/z-bool/Venom-JWT](https://github.com/z-bool/Venom-JWT) :  ![starts](https://img.shields.io/github/stars/z-bool/Venom-JWT.svg) ![forks](https://img.shields.io/github/forks/z-bool/Venom-JWT.svg)


## CVE-2019-2215
 A use-after-free in binder.c allows an elevation of privilege from an application to the Linux Kernel. No user interaction is required to exploit this vulnerability, however exploitation does require either the installation of a malicious local application or a separate vulnerability in a network facing application.Product: AndroidAndroid ID: A-141720095

- [https://github.com/nicchongwb/Rootsmart-v2.0](https://github.com/nicchongwb/Rootsmart-v2.0) :  ![starts](https://img.shields.io/github/stars/nicchongwb/Rootsmart-v2.0.svg) ![forks](https://img.shields.io/github/forks/nicchongwb/Rootsmart-v2.0.svg)


## CVE-2018-0114
 A vulnerability in the Cisco node-jose open source library before 0.11.0 could allow an unauthenticated, remote attacker to re-sign tokens using a key that is embedded within the token. The vulnerability is due to node-jose following the JSON Web Signature (JWS) standard for JSON Web Tokens (JWTs). This standard specifies that a JSON Web Key (JWK) representing a public key can be embedded within the header of a JWS. This public key is then trusted for verification. An attacker could exploit this by forging valid JWS objects by removing the original signature, adding a new public key to the header, and then signing the object using the (attacker-owned) private key associated with the public key embedded in that JWS header.

- [https://github.com/z-bool/Venom-JWT](https://github.com/z-bool/Venom-JWT) :  ![starts](https://img.shields.io/github/stars/z-bool/Venom-JWT.svg) ![forks](https://img.shields.io/github/forks/z-bool/Venom-JWT.svg)


## CVE-2016-10555
 Since "algorithm" isn't enforced in jwt.decode()in jwt-simple 0.3.0 and earlier, a malicious user could choose what algorithm is sent sent to the server. If the server is expecting RSA but is sent HMAC-SHA with RSA's public key, the server will think the public key is actually an HMAC private key. This could be used to forge any data an attacker wants.

- [https://github.com/z-bool/Venom-JWT](https://github.com/z-bool/Venom-JWT) :  ![starts](https://img.shields.io/github/stars/z-bool/Venom-JWT.svg) ![forks](https://img.shields.io/github/forks/z-bool/Venom-JWT.svg)


## CVE-2015-9235
 In jsonwebtoken node module before 4.2.2 it is possible for an attacker to bypass verification when a token digitally signed with an asymmetric key (RS/ES family) of algorithms but instead the attacker send a token digitally signed with a symmetric algorithm (HS* family).

- [https://github.com/z-bool/Venom-JWT](https://github.com/z-bool/Venom-JWT) :  ![starts](https://img.shields.io/github/stars/z-bool/Venom-JWT.svg) ![forks](https://img.shields.io/github/forks/z-bool/Venom-JWT.svg)

