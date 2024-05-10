# Update 2024-05-10
## CVE-2024-26517
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/unrealjbr/CVE-2024-26517](https://github.com/unrealjbr/CVE-2024-26517) :  ![starts](https://img.shields.io/github/stars/unrealjbr/CVE-2024-26517.svg) ![forks](https://img.shields.io/github/forks/unrealjbr/CVE-2024-26517.svg)


## CVE-2024-26026
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/passwa11/CVE-2024-26026](https://github.com/passwa11/CVE-2024-26026) :  ![starts](https://img.shields.io/github/stars/passwa11/CVE-2024-26026.svg) ![forks](https://img.shields.io/github/forks/passwa11/CVE-2024-26026.svg)


## CVE-2024-21793
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/FeatherStark/CVE-2024-21793](https://github.com/FeatherStark/CVE-2024-21793) :  ![starts](https://img.shields.io/github/stars/FeatherStark/CVE-2024-21793.svg) ![forks](https://img.shields.io/github/forks/FeatherStark/CVE-2024-21793.svg)


## CVE-2024-3867
 The archive-tainacan-collection theme for WordPress is vulnerable to Reflected Cross-Site Scripting due to the use of add_query_arg without appropriate escaping on the URL in version 2.7.2. This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that execute if they can successfully trick a user into performing an action such as clicking on a link.

- [https://github.com/c4cnm/CVE-2024-3867](https://github.com/c4cnm/CVE-2024-3867) :  ![starts](https://img.shields.io/github/stars/c4cnm/CVE-2024-3867.svg) ![forks](https://img.shields.io/github/forks/c4cnm/CVE-2024-3867.svg)


## CVE-2023-31290
 Trust Wallet Core before 3.1.1, as used in the Trust Wallet browser extension before 0.0.183, allows theft of funds because the entropy is 32 bits, as exploited in the wild in December 2022 and March 2023. This occurs because the mt19937 Mersenne Twister takes a single 32-bit value as an input seed, resulting in only four billion possible mnemonics. The affected versions of the browser extension are 0.0.172 through 0.0.182. To steal funds efficiently, an attacker can identify all Ethereum addresses created since the 0.0.172 release, and check whether they are Ethereum addresses that could have been created by this extension. To respond to the risk, affected users need to upgrade the product version and also move funds to a new wallet address.

- [https://github.com/00000rest/py_trustwallet_wasm](https://github.com/00000rest/py_trustwallet_wasm) :  ![starts](https://img.shields.io/github/stars/00000rest/py_trustwallet_wasm.svg) ![forks](https://img.shields.io/github/forks/00000rest/py_trustwallet_wasm.svg)


## CVE-2022-44569
 A locally authenticated attacker with low privileges can bypass authentication due to insecure inter-process communication.

- [https://github.com/rweijnen/ivanti-automationmanager-exploit](https://github.com/rweijnen/ivanti-automationmanager-exploit) :  ![starts](https://img.shields.io/github/stars/rweijnen/ivanti-automationmanager-exploit.svg) ![forks](https://img.shields.io/github/forks/rweijnen/ivanti-automationmanager-exploit.svg)


## CVE-2021-45046
 It was found that the fix to address CVE-2021-44228 in Apache Log4j 2.15.0 was incomplete in certain non-default configurations. This could allows attackers with control over Thread Context Map (MDC) input data when the logging configuration uses a non-default Pattern Layout with either a Context Lookup (for example, $${ctx:loginId}) or a Thread Context Map pattern (%X, %mdc, or %MDC) to craft malicious input data using a JNDI Lookup pattern resulting in an information leak and remote code execution in some environments and local code execution in all environments. Log4j 2.16.0 (Java 8) and 2.12.2 (Java 7) fix this issue by removing support for message lookup patterns and disabling JNDI functionality by default.

- [https://github.com/shaily29-eng/CyberSecurity_CVE-2021-45046](https://github.com/shaily29-eng/CyberSecurity_CVE-2021-45046) :  ![starts](https://img.shields.io/github/stars/shaily29-eng/CyberSecurity_CVE-2021-45046.svg) ![forks](https://img.shields.io/github/forks/shaily29-eng/CyberSecurity_CVE-2021-45046.svg)


## CVE-2021-26700
 Visual Studio Code npm-script Extension Remote Code Execution Vulnerability

- [https://github.com/june-in-exile/CVE-2021-26700](https://github.com/june-in-exile/CVE-2021-26700) :  ![starts](https://img.shields.io/github/stars/june-in-exile/CVE-2021-26700.svg) ![forks](https://img.shields.io/github/forks/june-in-exile/CVE-2021-26700.svg)


## CVE-2020-0688
 A remote code execution vulnerability exists in Microsoft Exchange software when the software fails to properly handle objects in memory, aka 'Microsoft Exchange Memory Corruption Vulnerability'.

- [https://github.com/W01fh4cker/CVE-2020-0688-GUI](https://github.com/W01fh4cker/CVE-2020-0688-GUI) :  ![starts](https://img.shields.io/github/stars/W01fh4cker/CVE-2020-0688-GUI.svg) ![forks](https://img.shields.io/github/forks/W01fh4cker/CVE-2020-0688-GUI.svg)


## CVE-2020-0665
 An elevation of privilege vulnerability exists in Active Directory Forest trusts due to a default setting that lets an attacker in the trusting forest request delegation of a TGT for an identity from the trusted forest, aka 'Active Directory Elevation of Privilege Vulnerability'.

- [https://github.com/otterpwn/SIDplusplus](https://github.com/otterpwn/SIDplusplus) :  ![starts](https://img.shields.io/github/stars/otterpwn/SIDplusplus.svg) ![forks](https://img.shields.io/github/forks/otterpwn/SIDplusplus.svg)


## CVE-2019-13276
 TRENDnet TEW-827DRU with firmware up to and including 2.04B03 contains a stack-based buffer overflow in the ssi binary. The overflow allows an unauthenticated user to execute arbitrary code by providing a sufficiently long query string when POSTing to any valid cgi, txt, asp, or js file. The vulnerability can be exercised on the local intranet or remotely if remote administration is enabled.

- [https://github.com/5l1v3r1/CVE-2019-13276](https://github.com/5l1v3r1/CVE-2019-13276) :  ![starts](https://img.shields.io/github/stars/5l1v3r1/CVE-2019-13276.svg) ![forks](https://img.shields.io/github/forks/5l1v3r1/CVE-2019-13276.svg)


## CVE-2018-9995
 TBK DVR4104 and DVR4216 devices, as well as Novo, CeNova, QSee, Pulnix, XVR 5 in 1, Securus, Night OWL, DVR Login, HVR Login, and MDVR Login, which run re-branded versions of the original TBK DVR4104 and DVR4216 series, allow remote attackers to bypass authentication via a &quot;Cookie: uid=admin&quot; header, as demonstrated by a device.rsp?opt=user&amp;cmd=list request that provides credentials within JSON data in a response.

- [https://github.com/batmoshka55/CVE-2018-9995_dvr_credentials](https://github.com/batmoshka55/CVE-2018-9995_dvr_credentials) :  ![starts](https://img.shields.io/github/stars/batmoshka55/CVE-2018-9995_dvr_credentials.svg) ![forks](https://img.shields.io/github/forks/batmoshka55/CVE-2018-9995_dvr_credentials.svg)


## CVE-2017-0143
 The SMBv1 server in Microsoft Windows Vista SP2; Windows Server 2008 SP2 and R2 SP1; Windows 7 SP1; Windows 8.1; Windows Server 2012 Gold and R2; Windows RT 8.1; and Windows 10 Gold, 1511, and 1607; and Windows Server 2016 allows remote attackers to execute arbitrary code via crafted packets, aka &quot;Windows SMB Remote Code Execution Vulnerability.&quot; This vulnerability is different from those described in CVE-2017-0144, CVE-2017-0145, CVE-2017-0146, and CVE-2017-0148.

- [https://github.com/InTheDarkness2102/CVE-2017-0143-MS-17-010-EternalBlue](https://github.com/InTheDarkness2102/CVE-2017-0143-MS-17-010-EternalBlue) :  ![starts](https://img.shields.io/github/stars/InTheDarkness2102/CVE-2017-0143-MS-17-010-EternalBlue.svg) ![forks](https://img.shields.io/github/forks/InTheDarkness2102/CVE-2017-0143-MS-17-010-EternalBlue.svg)

