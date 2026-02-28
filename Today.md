# Update 2026-02-28
## CVE-2026-27831
 rldns is an open source DNS server. Version 2.3 has a heap-based out-of-bounds read that leads to denial of service. Version 1.4 contains a patch for the issue.

- [https://github.com/bluedragonsecurity/CVE-2026-27831-POC](https://github.com/bluedragonsecurity/CVE-2026-27831-POC) :  ![starts](https://img.shields.io/github/stars/bluedragonsecurity/CVE-2026-27831-POC.svg) ![forks](https://img.shields.io/github/forks/bluedragonsecurity/CVE-2026-27831-POC.svg)


## CVE-2026-27174
 MajorDoMo (aka Major Domestic Module) allows unauthenticated remote code execution via the admin panel's PHP console feature. An include order bug in modules/panel.class.php causes execution to continue past a redirect() call that lacks an exit statement, allowing unauthenticated requests to reach the ajax handler in inc_panel_ajax.php. The console handler within that file passes user-supplied input from GET parameters (via register_globals) directly to eval() without any authentication check. An attacker can execute arbitrary PHP code by sending a crafted GET request to /admin.php with ajax_panel, op, and command parameters.

- [https://github.com/MaxMnMl/majordomo-CVE-2026-27174-poc](https://github.com/MaxMnMl/majordomo-CVE-2026-27174-poc) :  ![starts](https://img.shields.io/github/stars/MaxMnMl/majordomo-CVE-2026-27174-poc.svg) ![forks](https://img.shields.io/github/forks/MaxMnMl/majordomo-CVE-2026-27174-poc.svg)


## CVE-2026-25892
 Adminer is open-source database management software. Adminer v5.4.1 and earlier has a version check mechanism where adminer.org sends signed version info via JavaScript postMessage, which the browser then POSTs to ?script=version. This endpoint lacks origin validation and accepts POST data from any source. An attacker can POST version[] parameter which PHP converts to an array. On next page load, openssl_verify() receives this array instead of string and throws TypeError, returning HTTP 500 to all users. Upgrade to Adminer 5.4.2.

- [https://github.com/dzmind2312/CVE_2026_25892](https://github.com/dzmind2312/CVE_2026_25892) :  ![starts](https://img.shields.io/github/stars/dzmind2312/CVE_2026_25892.svg) ![forks](https://img.shields.io/github/forks/dzmind2312/CVE_2026_25892.svg)


## CVE-2026-24009
 Docling Core (or docling-core) is a library that defines core data types and transformations in the document processing application Docling. A PyYAML-related Remote Code Execution (RCE) vulnerability, namely CVE-2020-14343, is exposed in docling-core starting in version 2.21.0 and prior to version 2.48.4, specifically only if the application uses pyyaml prior to version 5.4 and invokes `docling_core.types.doc.DoclingDocument.load_from_yaml()` passing it untrusted YAML data. The vulnerability has been patched in docling-core version 2.48.4. The fix mitigates the issue by switching `PyYAML` deserialization from `yaml.FullLoader` to `yaml.SafeLoader`, ensuring that untrusted data cannot trigger code execution. Users who cannot immediately upgrade docling-core can alternatively ensure that the installed version of PyYAML is 5.4 or greater.

- [https://github.com/BiranPeretz/docling-core-CVE-2026-24009](https://github.com/BiranPeretz/docling-core-CVE-2026-24009) :  ![starts](https://img.shields.io/github/stars/BiranPeretz/docling-core-CVE-2026-24009.svg) ![forks](https://img.shields.io/github/forks/BiranPeretz/docling-core-CVE-2026-24009.svg)


## CVE-2026-23550
 Incorrect Privilege Assignment vulnerability in Modular DS allows Privilege Escalation.This issue affects Modular DS: from n/a through 2.5.1.

- [https://github.com/DedsecTeam-BlackHat/CVE-2026-23550](https://github.com/DedsecTeam-BlackHat/CVE-2026-23550) :  ![starts](https://img.shields.io/github/stars/DedsecTeam-BlackHat/CVE-2026-23550.svg) ![forks](https://img.shields.io/github/forks/DedsecTeam-BlackHat/CVE-2026-23550.svg)


## CVE-2026-21627
 The vulnerability was rooted in how the Tassos Framework plugin handled specific AJAX requests through Joomla’s com_ajax entry point. Under certain conditions, internal framework functionality could be invoked without proper restriction.

- [https://github.com/yallasec/CVE-2026-21627---Tassos-Novarain-Framework-plg_system_nrframework-Exploit---Joomla](https://github.com/yallasec/CVE-2026-21627---Tassos-Novarain-Framework-plg_system_nrframework-Exploit---Joomla) :  ![starts](https://img.shields.io/github/stars/yallasec/CVE-2026-21627---Tassos-Novarain-Framework-plg_system_nrframework-Exploit---Joomla.svg) ![forks](https://img.shields.io/github/forks/yallasec/CVE-2026-21627---Tassos-Novarain-Framework-plg_system_nrframework-Exploit---Joomla.svg)


## CVE-2026-20841
 Improper neutralization of special elements used in a command ('command injection') in Windows Notepad App allows an unauthorized attacker to execute code locally.

- [https://github.com/hamzamalik3461/CVE-2026-20841](https://github.com/hamzamalik3461/CVE-2026-20841) :  ![starts](https://img.shields.io/github/stars/hamzamalik3461/CVE-2026-20841.svg) ![forks](https://img.shields.io/github/forks/hamzamalik3461/CVE-2026-20841.svg)
- [https://github.com/404godd/CVE-2026-20841-PoC](https://github.com/404godd/CVE-2026-20841-PoC) :  ![starts](https://img.shields.io/github/stars/404godd/CVE-2026-20841-PoC.svg) ![forks](https://img.shields.io/github/forks/404godd/CVE-2026-20841-PoC.svg)


## CVE-2026-20127
This vulnerability exists because the peering authentication mechanism in an affected system is not working properly. An attacker could exploit this vulnerability by sending crafted requests to an affected system. A successful exploit could allow the attacker to log in to an affected Cisco Catalyst SD-WAN Controller as an internal, high-privileged, non-root&nbsp;user account. Using this account, the attacker could access NETCONF, which would then allow the attacker to manipulate network configuration for the SD-WAN fabric.&nbsp;

- [https://github.com/Dimchuk/CVE-2026-20127-chain](https://github.com/Dimchuk/CVE-2026-20127-chain) :  ![starts](https://img.shields.io/github/stars/Dimchuk/CVE-2026-20127-chain.svg) ![forks](https://img.shields.io/github/forks/Dimchuk/CVE-2026-20127-chain.svg)
- [https://github.com/bluefalconink/cisa-ed-26-03-tracker](https://github.com/bluefalconink/cisa-ed-26-03-tracker) :  ![starts](https://img.shields.io/github/stars/bluefalconink/cisa-ed-26-03-tracker.svg) ![forks](https://img.shields.io/github/forks/bluefalconink/cisa-ed-26-03-tracker.svg)


## CVE-2026-3171
 A flaw has been found in SourceCodester/Patrick Mvuma Patients Waiting Area Queue Management System 1.0. Affected by this vulnerability is an unknown functionality of the file /queue.php. This manipulation of the argument firstname/lastname causes cross site scripting. The attack is possible to be carried out remotely. The exploit has been published and may be used.

- [https://github.com/archana1122m/CVE-disclosures](https://github.com/archana1122m/CVE-disclosures) :  ![starts](https://img.shields.io/github/stars/archana1122m/CVE-disclosures.svg) ![forks](https://img.shields.io/github/forks/archana1122m/CVE-disclosures.svg)


## CVE-2026-3170
 A vulnerability was detected in SourceCodester/Patrick Mvuma Patients Waiting Area Queue Management System 1.0. Affected is an unknown function of the file /patient-search.php. The manipulation of the argument First Name/Last Name results in cross site scripting. The attack can be executed remotely. The exploit is now public and may be used.

- [https://github.com/archana1122m/CVE-disclosures](https://github.com/archana1122m/CVE-disclosures) :  ![starts](https://img.shields.io/github/stars/archana1122m/CVE-disclosures.svg) ![forks](https://img.shields.io/github/forks/archana1122m/CVE-disclosures.svg)


## CVE-2026-2636
 This vulnerability is caused by a CWE‑159: "Improper Handling of Invalid Use of Special Elements" weakness, which leads to an unrecoverable inconsistency in the CLFS.sys driver. This condition forces a call to the KeBugCheckEx function, allowing an unprivileged user to trigger a system crash. Microsoft silently fixed this vulnerability in the September 2025 cumulative update for Windows 11 2024 LTSC and Windows Server 2025. Windows 25H2 (released in September) was released with the patch. Windows 1123h2 and earlier versions remain vulnerable.

- [https://github.com/oxfemale/CVE-2026-2636_PoC](https://github.com/oxfemale/CVE-2026-2636_PoC) :  ![starts](https://img.shields.io/github/stars/oxfemale/CVE-2026-2636_PoC.svg) ![forks](https://img.shields.io/github/forks/oxfemale/CVE-2026-2636_PoC.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-alias](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-alias) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-alias.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-alias.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-tilde](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-tilde) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-tilde.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-tilde.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-zero-installs](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-zero-installs) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-zero-installs.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-zero-installs.svg)


## CVE-2025-56605
 A reflected Cross-Site Scripting (XSS) vulnerability exists in the register.php backend script of PuneethReddyHC Event Management System 1.0. The mobile POST parameter is improperly validated and echoed back in the HTTP response without sanitization, allowing an attacker to inject and execute arbitrary JavaScript code in the victim's browser.

- [https://github.com/Userr404/CVE-2025-56605](https://github.com/Userr404/CVE-2025-56605) :  ![starts](https://img.shields.io/github/stars/Userr404/CVE-2025-56605.svg) ![forks](https://img.shields.io/github/forks/Userr404/CVE-2025-56605.svg)


## CVE-2025-39459
 Incorrect Privilege Assignment vulnerability in Contempo Themes Real Estate 7 allows Privilege Escalation.This issue affects Real Estate 7: from n/a through 3.5.2.

- [https://github.com/Nxploited/CVE-2025-39459](https://github.com/Nxploited/CVE-2025-39459) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-39459.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-39459.svg)


## CVE-2025-32433
 Erlang/OTP is a set of libraries for the Erlang programming language. Prior to versions OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20, a SSH server may allow an attacker to perform unauthenticated remote code execution (RCE). By exploiting a flaw in SSH protocol message handling, a malicious actor could gain unauthorized access to affected systems and execute arbitrary commands without valid credentials. This issue is patched in versions OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20. A temporary workaround involves disabling the SSH server or to prevent access via firewall rules.

- [https://github.com/yonathanpy/CVE-2025-32433.py](https://github.com/yonathanpy/CVE-2025-32433.py) :  ![starts](https://img.shields.io/github/stars/yonathanpy/CVE-2025-32433.py.svg) ![forks](https://img.shields.io/github/forks/yonathanpy/CVE-2025-32433.py.svg)


## CVE-2025-24893
 XWiki Platform is a generic wiki platform offering runtime services for applications built on top of it. Any guest can perform arbitrary remote code execution through a request to `SolrSearch`. This impacts the confidentiality, integrity and availability of the whole XWiki installation. To reproduce on an instance, without being logged in, go to `host/xwiki/bin/get/Main/SolrSearch?media=rss&text=%7D%7D%7D%7B%7Basync%20async%3Dfalse%7D%7D%7B%7Bgroovy%7D%7Dprintln%28"Hello%20from"%20%2B%20"%20search%20text%3A"%20%2B%20%2823%20%2B%2019%29%29%7B%7B%2Fgroovy%7D%7D%7B%7B%2Fasync%7D%7D%20`. If there is an output, and the title of the RSS feed contains `Hello from search text:42`, then the instance is vulnerable. This vulnerability has been patched in XWiki 15.10.11, 16.4.1 and 16.5.0RC1. Users are advised to upgrade. Users unable to upgrade may edit `Main.SolrSearchMacros` in `SolrSearchMacros.xml` on line 955 to match the `rawResponse` macro in `macros.vm#L2824` with a content type of `application/xml`, instead of simply outputting the content of the feed.

- [https://github.com/ibadovulfat/CVE-2025-24893](https://github.com/ibadovulfat/CVE-2025-24893) :  ![starts](https://img.shields.io/github/stars/ibadovulfat/CVE-2025-24893.svg) ![forks](https://img.shields.io/github/forks/ibadovulfat/CVE-2025-24893.svg)


## CVE-2025-14733
 An Out-of-bounds Write vulnerability in WatchGuard Fireware OS may allow a remote unauthenticated attacker to execute arbitrary code. This vulnerability affects both the Mobile User VPN with IKEv2 and the Branch Office VPN using IKEv2 when configured with a dynamic gateway peer.This vulnerability affects Fireware OS 11.10.2 up to and including 11.12.4_Update1, 12.0 up to and including 12.11.5 and 2025.1 up to and including 2025.1.3.

- [https://github.com/kooyaniks/CVE-2025-14733-analysis](https://github.com/kooyaniks/CVE-2025-14733-analysis) :  ![starts](https://img.shields.io/github/stars/kooyaniks/CVE-2025-14733-analysis.svg) ![forks](https://img.shields.io/github/forks/kooyaniks/CVE-2025-14733-analysis.svg)


## CVE-2025-5688
Users should upgrade to the latest version and ensure any forked or derivative code is patched to incorporate the new fixes.

- [https://github.com/mbanyamer/CVE-2025-5688-FreeRTOS-Plus-TCP-Out-of-Bounds-Write](https://github.com/mbanyamer/CVE-2025-5688-FreeRTOS-Plus-TCP-Out-of-Bounds-Write) :  ![starts](https://img.shields.io/github/stars/mbanyamer/CVE-2025-5688-FreeRTOS-Plus-TCP-Out-of-Bounds-Write.svg) ![forks](https://img.shields.io/github/forks/mbanyamer/CVE-2025-5688-FreeRTOS-Plus-TCP-Out-of-Bounds-Write.svg)


## CVE-2023-43208
 NextGen Healthcare Mirth Connect before version 4.4.1 is vulnerable to unauthenticated remote code execution. Note that this vulnerability is caused by the incomplete patch of CVE-2023-37679.

- [https://github.com/az4rvs/Mirth-Connect-CVE-2023-43208](https://github.com/az4rvs/Mirth-Connect-CVE-2023-43208) :  ![starts](https://img.shields.io/github/stars/az4rvs/Mirth-Connect-CVE-2023-43208.svg) ![forks](https://img.shields.io/github/forks/az4rvs/Mirth-Connect-CVE-2023-43208.svg)


## CVE-2023-33869
Enphase Envoy versions D7.0.88 is vulnerable to a command injection exploit that may allow an attacker to execute root commands.

- [https://github.com/NAP3XD/CVE-2023-33869-RCE-PoC](https://github.com/NAP3XD/CVE-2023-33869-RCE-PoC) :  ![starts](https://img.shields.io/github/stars/NAP3XD/CVE-2023-33869-RCE-PoC.svg) ![forks](https://img.shields.io/github/forks/NAP3XD/CVE-2023-33869-RCE-PoC.svg)


## CVE-2023-24012
 An attacker can arbitrarily craft malicious DDS Participants (or ROS 2 Nodes) with valid certificates to compromise and get full control of the attacked secure DDS databus system by exploiting vulnerable attributes in the configuration of PKCS#7 certificate’s validation. This is caused by a non-compliant implementation of permission document verification used by some DDS vendors. Specifically, an improper use of the OpenSSL PKCS7_verify function used to validate S/MIME signatures.

- [https://github.com/SafeLock-D2E/Quiksand-CVE-2023-24012](https://github.com/SafeLock-D2E/Quiksand-CVE-2023-24012) :  ![starts](https://img.shields.io/github/stars/SafeLock-D2E/Quiksand-CVE-2023-24012.svg) ![forks](https://img.shields.io/github/forks/SafeLock-D2E/Quiksand-CVE-2023-24012.svg)


## CVE-2022-21445
 Vulnerability in the Oracle Application Development Framework (ADF) product of Oracle Fusion Middleware (component: ADF Faces).  Supported versions that are affected are 12.2.1.3.0 and  12.2.1.4.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Application Development Framework (ADF).  Successful attacks of this vulnerability can result in takeover of Oracle Application Development Framework (ADF). Note: Oracle Application Development Framework (ADF) is downloaded via Oracle JDeveloper Product. Please refer to Fusion Middleware Patch Advisor for more details. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/NeCr00/CVE-2022-21445](https://github.com/NeCr00/CVE-2022-21445) :  ![starts](https://img.shields.io/github/stars/NeCr00/CVE-2022-21445.svg) ![forks](https://img.shields.io/github/forks/NeCr00/CVE-2022-21445.svg)


## CVE-2022-20775
https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sd-wan-priv-E6e8tEdF

- [https://github.com/bluefalconink/cisa-ed-26-03-tracker](https://github.com/bluefalconink/cisa-ed-26-03-tracker) :  ![starts](https://img.shields.io/github/stars/bluefalconink/cisa-ed-26-03-tracker.svg) ![forks](https://img.shields.io/github/forks/bluefalconink/cisa-ed-26-03-tracker.svg)


## CVE-2022-0324
Discovered by Eugene Lim of GovTech Singapore.

- [https://github.com/ngtuonghung/CVE-2022-0324](https://github.com/ngtuonghung/CVE-2022-0324) :  ![starts](https://img.shields.io/github/stars/ngtuonghung/CVE-2022-0324.svg) ![forks](https://img.shields.io/github/forks/ngtuonghung/CVE-2022-0324.svg)


## CVE-2021-43136
 An authentication bypass issue in FormaLMS = 2.4.4 allows an attacker to bypass the authentication mechanism and obtain a valid access to the platform.

- [https://github.com/estebanzarate/Online-Traffic-Offense-Management-System-1.0-Unauthenticated-RCE-PoC](https://github.com/estebanzarate/Online-Traffic-Offense-Management-System-1.0-Unauthenticated-RCE-PoC) :  ![starts](https://img.shields.io/github/stars/estebanzarate/Online-Traffic-Offense-Management-System-1.0-Unauthenticated-RCE-PoC.svg) ![forks](https://img.shields.io/github/forks/estebanzarate/Online-Traffic-Offense-Management-System-1.0-Unauthenticated-RCE-PoC.svg)


## CVE-2021-22911
 A improper input sanitization vulnerability exists in Rocket.Chat server 3.11, 3.12 & 3.13 that could lead to unauthenticated NoSQL injection, resulting potentially in RCE.

- [https://github.com/TeneBrae93/RocketChat-NoSQLi-Chain-CVE-2021-22911](https://github.com/TeneBrae93/RocketChat-NoSQLi-Chain-CVE-2021-22911) :  ![starts](https://img.shields.io/github/stars/TeneBrae93/RocketChat-NoSQLi-Chain-CVE-2021-22911.svg) ![forks](https://img.shields.io/github/forks/TeneBrae93/RocketChat-NoSQLi-Chain-CVE-2021-22911.svg)


## CVE-2021-21239
 PySAML2 is a pure python implementation of SAML Version 2 Standard. PySAML2 before 6.5.0 has an improper verification of cryptographic signature vulnerability. Users of pysaml2 that use the default CryptoBackendXmlSec1 backend and need to verify signed SAML documents are impacted. PySAML2 does not ensure that a signed SAML document is correctly signed. The default CryptoBackendXmlSec1 backend is using the xmlsec1 binary to verify the signature of signed SAML documents, but by default xmlsec1 accepts any type of key found within the given document. xmlsec1 needs to be configured explicitly to only use only _x509 certificates_ for the verification process of the SAML document signature. This is fixed in PySAML2 6.5.0.

- [https://github.com/Crims-on/CVE-2021-21239](https://github.com/Crims-on/CVE-2021-21239) :  ![starts](https://img.shields.io/github/stars/Crims-on/CVE-2021-21239.svg) ![forks](https://img.shields.io/github/forks/Crims-on/CVE-2021-21239.svg)


## CVE-2021-3138
 In Discourse 2.7.0 through beta1, a rate-limit bypass leads to a bypass of the 2FA requirement for certain forms.

- [https://github.com/Mesh3l911/CVE-2021-3138](https://github.com/Mesh3l911/CVE-2021-3138) :  ![starts](https://img.shields.io/github/stars/Mesh3l911/CVE-2021-3138.svg) ![forks](https://img.shields.io/github/forks/Mesh3l911/CVE-2021-3138.svg)

