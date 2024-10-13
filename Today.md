# Update 2024-10-13
## CVE-2024-23113
 A use of externally-controlled format string in Fortinet FortiOS versions 7.4.0 through 7.4.2, 7.2.0 through 7.2.6, 7.0.0 through 7.0.13, FortiProxy versions 7.4.0 through 7.4.2, 7.2.0 through 7.2.8, 7.0.0 through 7.0.14, FortiPAM versions 1.2.0, 1.1.0 through 1.1.2, 1.0.0 through 1.0.3, FortiSwitchManager versions 7.2.0 through 7.2.3, 7.0.0 through 7.0.3 allows attacker to execute unauthorized code or commands via specially crafted packets.

- [https://github.com/OxLmahdi/cve-2024-23113](https://github.com/OxLmahdi/cve-2024-23113) :  ![starts](https://img.shields.io/github/stars/OxLmahdi/cve-2024-23113.svg) ![forks](https://img.shields.io/github/forks/OxLmahdi/cve-2024-23113.svg)
- [https://github.com/CheckCve2/CVE-2024-23113](https://github.com/CheckCve2/CVE-2024-23113) :  ![starts](https://img.shields.io/github/stars/CheckCve2/CVE-2024-23113.svg) ![forks](https://img.shields.io/github/forks/CheckCve2/CVE-2024-23113.svg)


## CVE-2024-5932
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/OxLmahdi/cve-2024-5932](https://github.com/OxLmahdi/cve-2024-5932) :  ![starts](https://img.shields.io/github/stars/OxLmahdi/cve-2024-5932.svg) ![forks](https://img.shields.io/github/forks/OxLmahdi/cve-2024-5932.svg)


## CVE-2024-4690
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/devhaozi/CVE-2024-46901](https://github.com/devhaozi/CVE-2024-46901) :  ![starts](https://img.shields.io/github/stars/devhaozi/CVE-2024-46901.svg) ![forks](https://img.shields.io/github/forks/devhaozi/CVE-2024-46901.svg)


## CVE-2024-4577
 In PHP versions 8.1.* before 8.1.29, 8.2.* before 8.2.20, 8.3.* before 8.3.8, when using Apache and PHP-CGI on Windows, if the system is set up to use certain code pages, Windows may use &quot;Best-Fit&quot; behavior to replace characters in command line given to Win32 API functions. PHP CGI module may misinterpret those characters as PHP options, which may allow a malicious user to pass options to PHP binary being run, and thus reveal the source code of scripts, run arbitrary PHP code on the server, etc.

- [https://github.com/PhinehasNarh/CVE-2024-4577-LetsDefend-walkthrough](https://github.com/PhinehasNarh/CVE-2024-4577-LetsDefend-walkthrough) :  ![starts](https://img.shields.io/github/stars/PhinehasNarh/CVE-2024-4577-LetsDefend-walkthrough.svg) ![forks](https://img.shields.io/github/forks/PhinehasNarh/CVE-2024-4577-LetsDefend-walkthrough.svg)


## CVE-2024-4264
 A remote code execution (RCE) vulnerability exists in the berriai/litellm project due to improper control of the generation of code when using the `eval` function unsafely in the `litellm.get_secret()` method. Specifically, when the server utilizes Google KMS, untrusted data is passed to the `eval` function without any sanitization. Attackers can exploit this vulnerability by injecting malicious values into environment variables through the `/config/update` endpoint, which allows for the update of settings in `proxy_server_config.yaml`.

- [https://github.com/rvizx/CVE-2024-42640](https://github.com/rvizx/CVE-2024-42640) :  ![starts](https://img.shields.io/github/stars/rvizx/CVE-2024-42640.svg) ![forks](https://img.shields.io/github/forks/rvizx/CVE-2024-42640.svg)


## CVE-2023-36845
 A PHP External Variable Modification vulnerability in J-Web of Juniper Networks Junos OS on EX Series and SRX Series allows an unauthenticated, network-based attacker to remotely execute code. Using a crafted request which sets the variable PHPRC an attacker is able to modify the PHP execution environment allowing the injection und execution of code. This issue affects Juniper Networks Junos OS on EX Series and SRX Series: * All versions prior to 20.4R3-S9; * 21.1 versions 21.1R1 and later; * 21.2 versions prior to 21.2R3-S7; * 21.3 versions prior to 21.3R3-S5; * 21.4 versions prior to 21.4R3-S5; * 22.1 versions prior to 22.1R3-S4; * 22.2 versions prior to 22.2R3-S2; * 22.3 versions prior to 22.3R2-S2, 22.3R3-S1; * 22.4 versions prior to 22.4R2-S1, 22.4R3; * 23.2 versions prior to 23.2R1-S1, 23.2R2.

- [https://github.com/functionofpwnosec/CVE-2023-36845](https://github.com/functionofpwnosec/CVE-2023-36845) :  ![starts](https://img.shields.io/github/stars/functionofpwnosec/CVE-2023-36845.svg) ![forks](https://img.shields.io/github/forks/functionofpwnosec/CVE-2023-36845.svg)


## CVE-2023-3824
 In PHP version 8.0.* before 8.0.30, 8.1.* before 8.1.22, and 8.2.* before 8.2.8, when loading phar file, while reading PHAR directory entries, insufficient length checking may lead to a stack buffer overflow, leading potentially to memory corruption or RCE.

- [https://github.com/baesh3r/poc-CVE-2023-3824](https://github.com/baesh3r/poc-CVE-2023-3824) :  ![starts](https://img.shields.io/github/stars/baesh3r/poc-CVE-2023-3824.svg) ![forks](https://img.shields.io/github/forks/baesh3r/poc-CVE-2023-3824.svg)


## CVE-2022-1329
 The Elementor Website Builder plugin for WordPress is vulnerable to unauthorized execution of several AJAX actions due to a missing capability check in the ~/core/app/modules/onboarding/module.php file that make it possible for attackers to modify site data in addition to uploading malicious files that can be used to obtain remote code execution, in versions 3.6.0 to 3.6.2.

- [https://github.com/AgustinESI/CVE-2022-1329](https://github.com/AgustinESI/CVE-2022-1329) :  ![starts](https://img.shields.io/github/stars/AgustinESI/CVE-2022-1329.svg) ![forks](https://img.shields.io/github/forks/AgustinESI/CVE-2022-1329.svg)


## CVE-2021-40859
 Backdoors were discovered in Auerswald COMpact 5500R 7.8A and 8.0B devices, that allow attackers with access to the web based management application full administrative access to the device.

- [https://github.com/0xr001/CVE-2021-40859](https://github.com/0xr001/CVE-2021-40859) :  ![starts](https://img.shields.io/github/stars/0xr001/CVE-2021-40859.svg) ![forks](https://img.shields.io/github/forks/0xr001/CVE-2021-40859.svg)


## CVE-2021-40539
 Zoho ManageEngine ADSelfService Plus version 6113 and prior is vulnerable to REST API authentication bypass with resultant remote code execution.

- [https://github.com/lpyzds/CVE-2021-40539](https://github.com/lpyzds/CVE-2021-40539) :  ![starts](https://img.shields.io/github/stars/lpyzds/CVE-2021-40539.svg) ![forks](https://img.shields.io/github/forks/lpyzds/CVE-2021-40539.svg)


## CVE-2021-36750
 ENC DataVault before 7.2 and VaultAPI v67 mishandle key derivation, making it easier for attackers to determine the passwords of all DataVault users (across USB drives sold under multiple brand names).

- [https://github.com/mamba-4-ever/CVE-2021-36750](https://github.com/mamba-4-ever/CVE-2021-36750) :  ![starts](https://img.shields.io/github/stars/mamba-4-ever/CVE-2021-36750.svg) ![forks](https://img.shields.io/github/forks/mamba-4-ever/CVE-2021-36750.svg)


## CVE-2021-33044
 The identity authentication bypass vulnerability found in some Dahua products during the login process. Attackers can bypass device identity authentication by constructing malicious data packets.

- [https://github.com/Spy0x7/CVE-2021-33044](https://github.com/Spy0x7/CVE-2021-33044) :  ![starts](https://img.shields.io/github/stars/Spy0x7/CVE-2021-33044.svg) ![forks](https://img.shields.io/github/forks/Spy0x7/CVE-2021-33044.svg)


## CVE-2021-26084
 In affected versions of Confluence Server and Data Center, an OGNL injection vulnerability exists that would allow an unauthenticated attacker to execute arbitrary code on a Confluence Server or Data Center instance. The affected versions are before version 6.13.23, from version 6.14.0 before 7.4.11, from version 7.5.0 before 7.11.6, and from version 7.12.0 before 7.12.5.

- [https://github.com/attacker-codeninja/CVE-2021-26084](https://github.com/attacker-codeninja/CVE-2021-26084) :  ![starts](https://img.shields.io/github/stars/attacker-codeninja/CVE-2021-26084.svg) ![forks](https://img.shields.io/github/forks/attacker-codeninja/CVE-2021-26084.svg)


## CVE-2020-1938
 When using the Apache JServ Protocol (AJP), care must be taken when trusting incoming connections to Apache Tomcat. Tomcat treats AJP connections as having higher trust than, for example, a similar HTTP connection. If such connections are available to an attacker, they can be exploited in ways that may be surprising. In Apache Tomcat 9.0.0.M1 to 9.0.0.30, 8.5.0 to 8.5.50 and 7.0.0 to 7.0.99, Tomcat shipped with an AJP Connector enabled by default that listened on all configured IP addresses. It was expected (and recommended in the security guide) that this Connector would be disabled if not required. This vulnerability report identified a mechanism that allowed: - returning arbitrary files from anywhere in the web application - processing any file in the web application as a JSP Further, if the web application allowed file upload and stored those files within the web application (or the attacker was able to control the content of the web application by some other means) then this, along with the ability to process a file as a JSP, made remote code execution possible. It is important to note that mitigation is only required if an AJP port is accessible to untrusted users. Users wishing to take a defence-in-depth approach and block the vector that permits returning arbitrary files and execution as JSP may upgrade to Apache Tomcat 9.0.31, 8.5.51 or 7.0.100 or later. A number of changes were made to the default AJP Connector configuration in 9.0.31 to harden the default configuration. It is likely that users upgrading to 9.0.31, 8.5.51 or 7.0.100 or later will need to make small changes to their configurations.

- [https://github.com/s3nd3rjz/poc-CVE-2020-1938](https://github.com/s3nd3rjz/poc-CVE-2020-1938) :  ![starts](https://img.shields.io/github/stars/s3nd3rjz/poc-CVE-2020-1938.svg) ![forks](https://img.shields.io/github/forks/s3nd3rjz/poc-CVE-2020-1938.svg)

