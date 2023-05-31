# Update 2023-05-31
## CVE-2023-33246
 For RocketMQ versions 5.1.0 and below, under certain conditions, there is a risk of remote command execution. Several components of RocketMQ, including NameServer, Broker, and Controller, are leaked on the extranet and lack permission verification, an attacker can exploit this vulnerability by using the update configuration function to execute commands as the system users that RocketMQ is running as. Additionally, an attacker can achieve the same effect by forging the RocketMQ protocol content. To prevent these attacks, users are recommended to upgrade to version 5.1.1 or above for using RocketMQ 5.x or 4.9.6 or above for using RocketMQ 4.x .

- [https://github.com/I5N0rth/CVE-2023-33246](https://github.com/I5N0rth/CVE-2023-33246) :  ![starts](https://img.shields.io/github/stars/I5N0rth/CVE-2023-33246.svg) ![forks](https://img.shields.io/github/forks/I5N0rth/CVE-2023-33246.svg)


## CVE-2023-32243
 Improper Authentication vulnerability in WPDeveloper Essential Addons for Elementor allows Privilege Escalation. This issue affects Essential Addons for Elementor: from 5.4.0 through 5.7.1.

- [https://github.com/thatonesecguy/Wordpress-Vulnerability-Identification-Scripts](https://github.com/thatonesecguy/Wordpress-Vulnerability-Identification-Scripts) :  ![starts](https://img.shields.io/github/stars/thatonesecguy/Wordpress-Vulnerability-Identification-Scripts.svg) ![forks](https://img.shields.io/github/forks/thatonesecguy/Wordpress-Vulnerability-Identification-Scripts.svg)


## CVE-2023-30212
 OURPHP &lt;= 7.2.0 is vulnerale to Cross Site Scripting (XSS) via /client/manage/ourphp_out.php.

- [https://github.com/kai-iszz/CVE-2023-30212](https://github.com/kai-iszz/CVE-2023-30212) :  ![starts](https://img.shields.io/github/stars/kai-iszz/CVE-2023-30212.svg) ![forks](https://img.shields.io/github/forks/kai-iszz/CVE-2023-30212.svg)


## CVE-2023-29923
 PowerJob V4.3.1 is vulnerable to Insecure Permissions. via the list job interface.

- [https://github.com/Le1a/CVE-2023-29923](https://github.com/Le1a/CVE-2023-29923) :  ![starts](https://img.shields.io/github/stars/Le1a/CVE-2023-29923.svg) ![forks](https://img.shields.io/github/forks/Le1a/CVE-2023-29923.svg)


## CVE-2022-1609
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/syscall21h/cve-2022-1609-exploit](https://github.com/syscall21h/cve-2022-1609-exploit) :  ![starts](https://img.shields.io/github/stars/syscall21h/cve-2022-1609-exploit.svg) ![forks](https://img.shields.io/github/forks/syscall21h/cve-2022-1609-exploit.svg)


## CVE-2021-31233
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/gabesolomon/CVE-2021-31233](https://github.com/gabesolomon/CVE-2021-31233) :  ![starts](https://img.shields.io/github/stars/gabesolomon/CVE-2021-31233.svg) ![forks](https://img.shields.io/github/forks/gabesolomon/CVE-2021-31233.svg)


## CVE-2020-10148
 The SolarWinds Orion API is vulnerable to an authentication bypass that could allow a remote attacker to execute API commands. This vulnerability could allow a remote attacker to bypass authentication and execute API commands which may result in a compromise of the SolarWinds instance. SolarWinds Orion Platform versions 2019.4 HF 5, 2020.2 with no hotfix installed, and 2020.2 HF 1 are affected.

- [https://github.com/B1anda0/CVE-2020-10148](https://github.com/B1anda0/CVE-2020-10148) :  ![starts](https://img.shields.io/github/stars/B1anda0/CVE-2020-10148.svg) ![forks](https://img.shields.io/github/forks/B1anda0/CVE-2020-10148.svg)
- [https://github.com/rdoix/CVE-2020-10148-Solarwinds-Orion](https://github.com/rdoix/CVE-2020-10148-Solarwinds-Orion) :  ![starts](https://img.shields.io/github/stars/rdoix/CVE-2020-10148-Solarwinds-Orion.svg) ![forks](https://img.shields.io/github/forks/rdoix/CVE-2020-10148-Solarwinds-Orion.svg)


## CVE-2020-1971
 The X.509 GeneralName type is a generic type for representing different types of names. One of those name types is known as EDIPartyName. OpenSSL provides a function GENERAL_NAME_cmp which compares different instances of a GENERAL_NAME to see if they are equal or not. This function behaves incorrectly when both GENERAL_NAMEs contain an EDIPARTYNAME. A NULL pointer dereference and a crash may occur leading to a possible denial of service attack. OpenSSL itself uses the GENERAL_NAME_cmp function for two purposes: 1) Comparing CRL distribution point names between an available CRL and a CRL distribution point embedded in an X509 certificate 2) When verifying that a timestamp response token signer matches the timestamp authority name (exposed via the API functions TS_RESP_verify_response and TS_RESP_verify_token) If an attacker can control both items being compared then that attacker could trigger a crash. For example if the attacker can trick a client or server into checking a malicious certificate against a malicious CRL then this may occur. Note that some applications automatically download CRLs based on a URL embedded in a certificate. This checking happens prior to the signatures on the certificate and CRL being verified. OpenSSL's s_server, s_client and verify tools have support for the &quot;-crl_download&quot; option which implements automatic CRL downloading and this attack has been demonstrated to work against those tools. Note that an unrelated bug means that affected versions of OpenSSL cannot parse or construct correct encodings of EDIPARTYNAME. However it is possible to construct a malformed EDIPARTYNAME that OpenSSL's parser will accept and hence trigger this attack. All OpenSSL 1.1.1 and 1.0.2 versions are affected by this issue. Other OpenSSL releases are out of support and have not been checked. Fixed in OpenSSL 1.1.1i (Affected 1.1.1-1.1.1h). Fixed in OpenSSL 1.0.2x (Affected 1.0.2-1.0.2w).

- [https://github.com/MBHudson/CVE-2020-1971](https://github.com/MBHudson/CVE-2020-1971) :  ![starts](https://img.shields.io/github/stars/MBHudson/CVE-2020-1971.svg) ![forks](https://img.shields.io/github/forks/MBHudson/CVE-2020-1971.svg)


## CVE-2019-19658
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/jra89/CVE-2019-19658](https://github.com/jra89/CVE-2019-19658) :  ![starts](https://img.shields.io/github/stars/jra89/CVE-2019-19658.svg) ![forks](https://img.shields.io/github/forks/jra89/CVE-2019-19658.svg)


## CVE-2019-9053
 An issue was discovered in CMS Made Simple 2.2.8. It is possible with the News module, through a crafted URL, to achieve unauthenticated blind time-based SQL injection via the m1_idlist parameter.

- [https://github.com/Mahamedm/CVE-2019-9053-Exploit-Python-3](https://github.com/Mahamedm/CVE-2019-9053-Exploit-Python-3) :  ![starts](https://img.shields.io/github/stars/Mahamedm/CVE-2019-9053-Exploit-Python-3.svg) ![forks](https://img.shields.io/github/forks/Mahamedm/CVE-2019-9053-Exploit-Python-3.svg)


## CVE-2018-13341
 Crestron TSW-X60 all versions prior to 2.001.0037.001 and MC3 all versions prior to 1.502.0047.00, The passwords for special sudo accounts may be calculated using information accessible to those with regular user privileges. Attackers could decipher these passwords, which may allow them to execute hidden API calls and escape the CTP console sandbox environment with elevated privileges.

- [https://github.com/Rajchowdhury420/CVE-2018-13341](https://github.com/Rajchowdhury420/CVE-2018-13341) :  ![starts](https://img.shields.io/github/stars/Rajchowdhury420/CVE-2018-13341.svg) ![forks](https://img.shields.io/github/forks/Rajchowdhury420/CVE-2018-13341.svg)


## CVE-2018-12533
 JBoss RichFaces 3.1.0 through 3.3.4 allows unauthenticated remote attackers to inject expression language (EL) expressions and execute arbitrary Java code via a /DATA/ substring in a path with an org.richfaces.renderkit.html.Paint2DResource$ImageData object, aka RF-14310.

- [https://github.com/llamaonsecurity/CVE-2018-12533](https://github.com/llamaonsecurity/CVE-2018-12533) :  ![starts](https://img.shields.io/github/stars/llamaonsecurity/CVE-2018-12533.svg) ![forks](https://img.shields.io/github/forks/llamaonsecurity/CVE-2018-12533.svg)


## CVE-2018-1207
 Dell EMC iDRAC7/iDRAC8, versions prior to 2.52.52.52, contain CGI injection vulnerability which could be used to execute remote code. A remote unauthenticated attacker may potentially be able to use CGI variables to execute remote code.

- [https://github.com/mgargiullo/cve-2018-1207](https://github.com/mgargiullo/cve-2018-1207) :  ![starts](https://img.shields.io/github/stars/mgargiullo/cve-2018-1207.svg) ![forks](https://img.shields.io/github/forks/mgargiullo/cve-2018-1207.svg)
- [https://github.com/un4gi/CVE-2018-1207](https://github.com/un4gi/CVE-2018-1207) :  ![starts](https://img.shields.io/github/stars/un4gi/CVE-2018-1207.svg) ![forks](https://img.shields.io/github/forks/un4gi/CVE-2018-1207.svg)


## CVE-2017-0505
 An elevation of privilege vulnerability in MediaTek components, including the M4U driver, sound driver, touchscreen driver, GPU driver, and Command Queue driver, could enable a local malicious application to execute arbitrary code within the context of the kernel. This issue is rated as Critical due to the possibility of a local permanent device compromise, which may require reflashing the operating system to repair the device. Product: Android. Versions: N/A. Android ID: A-31822282. References: M-ALPS02992041.

- [https://github.com/R0rt1z2/CVE-2017-0505-mtk](https://github.com/R0rt1z2/CVE-2017-0505-mtk) :  ![starts](https://img.shields.io/github/stars/R0rt1z2/CVE-2017-0505-mtk.svg) ![forks](https://img.shields.io/github/forks/R0rt1z2/CVE-2017-0505-mtk.svg)


## CVE-2015-5122
 Use-after-free vulnerability in the DisplayObject class in the ActionScript 3 (AS3) implementation in Adobe Flash Player 13.x through 13.0.0.302 on Windows and OS X, 14.x through 18.0.0.203 on Windows and OS X, 11.x through 11.2.202.481 on Linux, and 12.x through 18.0.0.204 on Linux Chrome installations allows remote attackers to execute arbitrary code or cause a denial of service (memory corruption) via crafted Flash content that leverages improper handling of the opaqueBackground property, as exploited in the wild in July 2015.

- [https://github.com/Xattam1/Adobe-Flash-Exploits_17-18](https://github.com/Xattam1/Adobe-Flash-Exploits_17-18) :  ![starts](https://img.shields.io/github/stars/Xattam1/Adobe-Flash-Exploits_17-18.svg) ![forks](https://img.shields.io/github/forks/Xattam1/Adobe-Flash-Exploits_17-18.svg)

