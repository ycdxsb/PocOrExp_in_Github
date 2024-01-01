# Update 2024-01-01
## CVE-2023-50164
 An attacker can manipulate file upload params to enable paths traversal and under some circumstances this can lead to uploading a malicious file which can be used to perform Remote Code Execution. Users are recommended to upgrade to versions Struts 2.5.33 or Struts 6.3.0.2 or greater to fix this issue.

- [https://github.com/snyk-labs/CVE-2023-50164-POC](https://github.com/snyk-labs/CVE-2023-50164-POC) :  ![starts](https://img.shields.io/github/stars/snyk-labs/CVE-2023-50164-POC.svg) ![forks](https://img.shields.io/github/forks/snyk-labs/CVE-2023-50164-POC.svg)


## CVE-2023-44372
 Adobe Acrobat Reader versions 23.006.20360 (and earlier) and 20.005.30524 (and earlier) are affected by a Use After Free vulnerability that could result in arbitrary code execution in the context of the current user. Exploitation of this issue requires user interaction in that a victim must open a malicious file.

- [https://github.com/SpiralBL0CK/cve2023-44372](https://github.com/SpiralBL0CK/cve2023-44372) :  ![starts](https://img.shields.io/github/stars/SpiralBL0CK/cve2023-44372.svg) ![forks](https://img.shields.io/github/forks/SpiralBL0CK/cve2023-44372.svg)


## CVE-2023-35985
 An arbitrary file creation vulnerability exists in the Javascript exportDataObject API of Foxit Reader 12.1.3.15356 due to a failure to properly validate a dangerous extension. A specially crafted malicious file can create files at arbitrary locations, which can lead to arbitrary code execution. An attacker needs to trick the user into opening the malicious file to trigger this vulnerability. Exploitation is also possible if a user visits a specially-crafted malicious site if the browser plugin extension is enabled.

- [https://github.com/SpiralBL0CK/-CVE-2023-35985](https://github.com/SpiralBL0CK/-CVE-2023-35985) :  ![starts](https://img.shields.io/github/stars/SpiralBL0CK/-CVE-2023-35985.svg) ![forks](https://img.shields.io/github/forks/SpiralBL0CK/-CVE-2023-35985.svg)


## CVE-2023-35813
 Multiple Sitecore products allow remote code execution. This affects Experience Manager, Experience Platform, and Experience Commerce through 10.3.

- [https://github.com/lexy-1/CVE-2023-35813](https://github.com/lexy-1/CVE-2023-35813) :  ![starts](https://img.shields.io/github/stars/lexy-1/CVE-2023-35813.svg) ![forks](https://img.shields.io/github/forks/lexy-1/CVE-2023-35813.svg)


## CVE-2023-29929
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/YSaxon/CVE-2023-29929](https://github.com/YSaxon/CVE-2023-29929) :  ![starts](https://img.shields.io/github/stars/YSaxon/CVE-2023-29929.svg) ![forks](https://img.shields.io/github/forks/YSaxon/CVE-2023-29929.svg)


## CVE-2023-3450
 A vulnerability was found in Ruijie RG-BCR860 2.5.13 and classified as critical. This issue affects some unknown processing of the component Network Diagnostic Page. The manipulation leads to os command injection. The attack may be initiated remotely. The exploit has been disclosed to the public and may be used. The associated identifier of this vulnerability is VDB-232547. NOTE: The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/caopengyan/CVE-2023-3450](https://github.com/caopengyan/CVE-2023-3450) :  ![starts](https://img.shields.io/github/stars/caopengyan/CVE-2023-3450.svg) ![forks](https://img.shields.io/github/forks/caopengyan/CVE-2023-3450.svg)


## CVE-2022-1609
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/savior-only/CVE-2022-1609](https://github.com/savior-only/CVE-2022-1609) :  ![starts](https://img.shields.io/github/stars/savior-only/CVE-2022-1609.svg) ![forks](https://img.shields.io/github/forks/savior-only/CVE-2022-1609.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/m96dg/CVE-2021-41773-exercise](https://github.com/m96dg/CVE-2021-41773-exercise) :  ![starts](https://img.shields.io/github/stars/m96dg/CVE-2021-41773-exercise.svg) ![forks](https://img.shields.io/github/forks/m96dg/CVE-2021-41773-exercise.svg)


## CVE-2021-21551
 Dell dbutil_2_3.sys driver contains an insufficient access control vulnerability which may lead to escalation of privileges, denial of service, or information disclosure. Local authenticated user access is required.

- [https://github.com/houseofxyz/CVE-2021-21551](https://github.com/houseofxyz/CVE-2021-21551) :  ![starts](https://img.shields.io/github/stars/houseofxyz/CVE-2021-21551.svg) ![forks](https://img.shields.io/github/forks/houseofxyz/CVE-2021-21551.svg)


## CVE-2020-1971
 The X.509 GeneralName type is a generic type for representing different types of names. One of those name types is known as EDIPartyName. OpenSSL provides a function GENERAL_NAME_cmp which compares different instances of a GENERAL_NAME to see if they are equal or not. This function behaves incorrectly when both GENERAL_NAMEs contain an EDIPARTYNAME. A NULL pointer dereference and a crash may occur leading to a possible denial of service attack. OpenSSL itself uses the GENERAL_NAME_cmp function for two purposes: 1) Comparing CRL distribution point names between an available CRL and a CRL distribution point embedded in an X509 certificate 2) When verifying that a timestamp response token signer matches the timestamp authority name (exposed via the API functions TS_RESP_verify_response and TS_RESP_verify_token) If an attacker can control both items being compared then that attacker could trigger a crash. For example if the attacker can trick a client or server into checking a malicious certificate against a malicious CRL then this may occur. Note that some applications automatically download CRLs based on a URL embedded in a certificate. This checking happens prior to the signatures on the certificate and CRL being verified. OpenSSL's s_server, s_client and verify tools have support for the &quot;-crl_download&quot; option which implements automatic CRL downloading and this attack has been demonstrated to work against those tools. Note that an unrelated bug means that affected versions of OpenSSL cannot parse or construct correct encodings of EDIPARTYNAME. However it is possible to construct a malformed EDIPARTYNAME that OpenSSL's parser will accept and hence trigger this attack. All OpenSSL 1.1.1 and 1.0.2 versions are affected by this issue. Other OpenSSL releases are out of support and have not been checked. Fixed in OpenSSL 1.1.1i (Affected 1.1.1-1.1.1h). Fixed in OpenSSL 1.0.2x (Affected 1.0.2-1.0.2w).

- [https://github.com/MBHudson/CVE-2020-1971](https://github.com/MBHudson/CVE-2020-1971) :  ![starts](https://img.shields.io/github/stars/MBHudson/CVE-2020-1971.svg) ![forks](https://img.shields.io/github/forks/MBHudson/CVE-2020-1971.svg)


## CVE-2020-1054
 An elevation of privilege vulnerability exists in Windows when the Windows kernel-mode driver fails to properly handle objects in memory, aka 'Win32k Elevation of Privilege Vulnerability'. This CVE ID is unique from CVE-2020-1143.

- [https://github.com/KaLendsi/CVE-2020-1054](https://github.com/KaLendsi/CVE-2020-1054) :  ![starts](https://img.shields.io/github/stars/KaLendsi/CVE-2020-1054.svg) ![forks](https://img.shields.io/github/forks/KaLendsi/CVE-2020-1054.svg)


## CVE-2020-1048
 An elevation of privilege vulnerability exists when the Windows Print Spooler service improperly allows arbitrary writing to the file system, aka 'Windows Print Spooler Elevation of Privilege Vulnerability'. This CVE ID is unique from CVE-2020-1070.

- [https://github.com/zveriu/CVE-2009-0229-PoC](https://github.com/zveriu/CVE-2009-0229-PoC) :  ![starts](https://img.shields.io/github/stars/zveriu/CVE-2009-0229-PoC.svg) ![forks](https://img.shields.io/github/forks/zveriu/CVE-2009-0229-PoC.svg)


## CVE-2018-6574
 Go before 1.8.7, Go 1.9.x before 1.9.4, and Go 1.10 pre-releases before Go 1.10rc2 allow &quot;go get&quot; remote command execution during source code build, by leveraging the gcc or clang plugin feature, because -fplugin= and -plugin= arguments were not blocked.

- [https://github.com/g-bald/ptlab-cve-2018-6574](https://github.com/g-bald/ptlab-cve-2018-6574) :  ![starts](https://img.shields.io/github/stars/g-bald/ptlab-cve-2018-6574.svg) ![forks](https://img.shields.io/github/forks/g-bald/ptlab-cve-2018-6574.svg)


## CVE-2018-2628
 Vulnerability in the Oracle WebLogic Server component of Oracle Fusion Middleware (subcomponent: WLS Core Components). Supported versions that are affected are 10.3.6.0, 12.1.3.0, 12.2.1.2 and 12.2.1.3. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3 to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/shaoshore/CVE-2018-2628](https://github.com/shaoshore/CVE-2018-2628) :  ![starts](https://img.shields.io/github/stars/shaoshore/CVE-2018-2628.svg) ![forks](https://img.shields.io/github/forks/shaoshore/CVE-2018-2628.svg)

