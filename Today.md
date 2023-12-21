# Update 2023-12-21
## CVE-2023-49103
 An issue was discovered in ownCloud owncloud/graphapi 0.2.x before 0.2.1 and 0.3.x before 0.3.1. The graphapi app relies on a third-party GetPhpInfo.php library that provides a URL. When this URL is accessed, it reveals the configuration details of the PHP environment (phpinfo). This information includes all the environment variables of the webserver. In containerized deployments, these environment variables may include sensitive data such as the ownCloud admin password, mail server credentials, and license key. Simply disabling the graphapi app does not eliminate the vulnerability. Additionally, phpinfo exposes various other potentially sensitive configuration details that could be exploited by an attacker to gather information about the system. Therefore, even if ownCloud is not running in a containerized environment, this vulnerability should still be a cause for concern. Note that Docker containers from before February 2023 are not vulnerable to the credential disclosure.

- [https://github.com/merlin-ke/OwnCloud-CVE-2023-49103](https://github.com/merlin-ke/OwnCloud-CVE-2023-49103) :  ![starts](https://img.shields.io/github/stars/merlin-ke/OwnCloud-CVE-2023-49103.svg) ![forks](https://img.shields.io/github/forks/merlin-ke/OwnCloud-CVE-2023-49103.svg)


## CVE-2023-47119
 Discourse is an open source platform for community discussion. Prior to version 3.1.3 of the `stable` branch and version 3.2.0.beta3 of the `beta` and `tests-passed` branches, some links can inject arbitrary HTML tags when rendered through our Onebox engine. The issue is patched in version 3.1.3 of the `stable` branch and version 3.2.0.beta3 of the `beta` and `tests-passed` branches. There are no known workarounds.

- [https://github.com/Cristiano100/CVE-2023-47119](https://github.com/Cristiano100/CVE-2023-47119) :  ![starts](https://img.shields.io/github/stars/Cristiano100/CVE-2023-47119.svg) ![forks](https://img.shields.io/github/forks/Cristiano100/CVE-2023-47119.svg)


## CVE-2023-41772
 Win32k Elevation of Privilege Vulnerability

- [https://github.com/R41N3RZUF477/CVE-2023-41772](https://github.com/R41N3RZUF477/CVE-2023-41772) :  ![starts](https://img.shields.io/github/stars/R41N3RZUF477/CVE-2023-41772.svg) ![forks](https://img.shields.io/github/forks/R41N3RZUF477/CVE-2023-41772.svg)


## CVE-2023-23752
 An issue was discovered in Joomla! 4.0.0 through 4.2.7. An improper access check allows unauthorized access to webservice endpoints.

- [https://github.com/gunzf0x/CVE-2023-23752](https://github.com/gunzf0x/CVE-2023-23752) :  ![starts](https://img.shields.io/github/stars/gunzf0x/CVE-2023-23752.svg) ![forks](https://img.shields.io/github/forks/gunzf0x/CVE-2023-23752.svg)


## CVE-2023-1337
 The RapidLoad Power-Up for Autoptimize plugin for WordPress is vulnerable to unauthorized data loss due to a missing capability check on the clear_uucss_logs function in versions up to, and including, 1.7.1. This makes it possible for authenticated attackers with subscriber-level access to delete plugin log files.

- [https://github.com/DARKSECshell/CVE-2023-1337](https://github.com/DARKSECshell/CVE-2023-1337) :  ![starts](https://img.shields.io/github/stars/DARKSECshell/CVE-2023-1337.svg) ![forks](https://img.shields.io/github/forks/DARKSECshell/CVE-2023-1337.svg)


## CVE-2022-3656
 Insufficient data validation in File System in Google Chrome prior to 107.0.5304.62 allowed a remote attacker to bypass file system restrictions via a crafted HTML page. (Chromium security severity: Medium)

- [https://github.com/momika233/CVE-2022-3656](https://github.com/momika233/CVE-2022-3656) :  ![starts](https://img.shields.io/github/stars/momika233/CVE-2022-3656.svg) ![forks](https://img.shields.io/github/forks/momika233/CVE-2022-3656.svg)


## CVE-2021-40449
 Win32k Elevation of Privilege Vulnerability

- [https://github.com/hakivvi/CVE-2021-40449](https://github.com/hakivvi/CVE-2021-40449) :  ![starts](https://img.shields.io/github/stars/hakivvi/CVE-2021-40449.svg) ![forks](https://img.shields.io/github/forks/hakivvi/CVE-2021-40449.svg)


## CVE-2020-25223
 A remote code execution vulnerability exists in the WebAdmin of Sophos SG UTM before v9.705 MR5, v9.607 MR7, and v9.511 MR11

- [https://github.com/darrenmartyn/sophucked](https://github.com/darrenmartyn/sophucked) :  ![starts](https://img.shields.io/github/stars/darrenmartyn/sophucked.svg) ![forks](https://img.shields.io/github/forks/darrenmartyn/sophucked.svg)


## CVE-2020-17530
 Forced OGNL evaluation, when evaluated on raw user input in tag attributes, may lead to remote code execution. Affected software : Apache Struts 2.0.0 - Struts 2.5.25.

- [https://github.com/fengziHK/CVE-2020-17530-strust2-061](https://github.com/fengziHK/CVE-2020-17530-strust2-061) :  ![starts](https://img.shields.io/github/stars/fengziHK/CVE-2020-17530-strust2-061.svg) ![forks](https://img.shields.io/github/forks/fengziHK/CVE-2020-17530-strust2-061.svg)
- [https://github.com/gh0st27/Struts2Scanner](https://github.com/gh0st27/Struts2Scanner) :  ![starts](https://img.shields.io/github/stars/gh0st27/Struts2Scanner.svg) ![forks](https://img.shields.io/github/forks/gh0st27/Struts2Scanner.svg)
- [https://github.com/keyuan15/CVE-2020-17530](https://github.com/keyuan15/CVE-2020-17530) :  ![starts](https://img.shields.io/github/stars/keyuan15/CVE-2020-17530.svg) ![forks](https://img.shields.io/github/forks/keyuan15/CVE-2020-17530.svg)


## CVE-2020-8192
 A denial of service vulnerability exists in Fastify v2.14.1 and v3.0.0-rc.4 that allows a malicious user to trigger resource exhaustion (when the allErrors option is used) with specially crafted schemas.

- [https://github.com/ossf-cve-benchmark/CVE-2020-8192](https://github.com/ossf-cve-benchmark/CVE-2020-8192) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2020-8192.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2020-8192.svg)


## CVE-2020-6287
 SAP NetWeaver AS JAVA (LM Configuration Wizard), versions - 7.30, 7.31, 7.40, 7.50, does not perform an authentication check which allows an attacker without prior authentication to execute configuration tasks to perform critical actions against the SAP Java system, including the ability to create an administrative user, and therefore compromising Confidentiality, Integrity and Availability of the system, leading to Missing Authentication Check.

- [https://github.com/murataydemir/CVE-2020-6287](https://github.com/murataydemir/CVE-2020-6287) :  ![starts](https://img.shields.io/github/stars/murataydemir/CVE-2020-6287.svg) ![forks](https://img.shields.io/github/forks/murataydemir/CVE-2020-6287.svg)


## CVE-2020-1947
 In Apache ShardingSphere(incubator) 4.0.0-RC3 and 4.0.0, the ShardingSphere's web console uses the SnakeYAML library for parsing YAML inputs to load datasource configuration. SnakeYAML allows to unmarshal data to a Java type By using the YAML tag. Unmarshalling untrusted data can lead to security flaws of RCE.

- [https://github.com/jas502n/CVE-2020-1947](https://github.com/jas502n/CVE-2020-1947) :  ![starts](https://img.shields.io/github/stars/jas502n/CVE-2020-1947.svg) ![forks](https://img.shields.io/github/forks/jas502n/CVE-2020-1947.svg)


## CVE-2020-1054
 An elevation of privilege vulnerability exists in Windows when the Windows kernel-mode driver fails to properly handle objects in memory, aka 'Win32k Elevation of Privilege Vulnerability'. This CVE ID is unique from CVE-2020-1143.

- [https://github.com/KaLendsi/CVE-2020-1054](https://github.com/KaLendsi/CVE-2020-1054) :  ![starts](https://img.shields.io/github/stars/KaLendsi/CVE-2020-1054.svg) ![forks](https://img.shields.io/github/forks/KaLendsi/CVE-2020-1054.svg)


## CVE-2019-17564
 Unsafe deserialization occurs within a Dubbo application which has HTTP remoting enabled. An attacker may submit a POST request with a Java object in it to completely compromise a Provider instance of Apache Dubbo, if this instance enables HTTP. This issue affected Apache Dubbo 2.7.0 to 2.7.4, 2.6.0 to 2.6.7, and all 2.5.x versions.

- [https://github.com/Hu3sky/CVE-2019-17564](https://github.com/Hu3sky/CVE-2019-17564) :  ![starts](https://img.shields.io/github/stars/Hu3sky/CVE-2019-17564.svg) ![forks](https://img.shields.io/github/forks/Hu3sky/CVE-2019-17564.svg)


## CVE-2017-16943
 The receive_msg function in receive.c in the SMTP daemon in Exim 4.88 and 4.89 allows remote attackers to execute arbitrary code or cause a denial of service (use-after-free) via vectors involving BDAT commands.

- [https://github.com/beraphin/CVE-2017-16943](https://github.com/beraphin/CVE-2017-16943) :  ![starts](https://img.shields.io/github/stars/beraphin/CVE-2017-16943.svg) ![forks](https://img.shields.io/github/forks/beraphin/CVE-2017-16943.svg)


## CVE-2009-3103
 Array index error in the SMBv2 protocol implementation in srv2.sys in Microsoft Windows Vista Gold, SP1, and SP2, Windows Server 2008 Gold and SP2, and Windows 7 RC allows remote attackers to execute arbitrary code or cause a denial of service (system crash) via an &amp; (ampersand) character in a Process ID High header field in a NEGOTIATE PROTOCOL REQUEST packet, which triggers an attempted dereference of an out-of-bounds memory location, aka &quot;SMBv2 Negotiation Vulnerability.&quot; NOTE: some of these details are obtained from third party information.

- [https://github.com/Sic4rio/CVE-2009-3103---srv2.sys-SMB-Code-Execution-Python-MS09-050-](https://github.com/Sic4rio/CVE-2009-3103---srv2.sys-SMB-Code-Execution-Python-MS09-050-) :  ![starts](https://img.shields.io/github/stars/Sic4rio/CVE-2009-3103---srv2.sys-SMB-Code-Execution-Python-MS09-050-.svg) ![forks](https://img.shields.io/github/forks/Sic4rio/CVE-2009-3103---srv2.sys-SMB-Code-Execution-Python-MS09-050-.svg)

