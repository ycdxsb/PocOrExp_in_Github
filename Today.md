# Update 2022-08-23
## CVE-2022-36446
 software/apt-lib.pl in Webmin before 1.997 lacks HTML escaping for a UI command.

- [https://github.com/monzaviman/CVE_2022_36446](https://github.com/monzaviman/CVE_2022_36446) :  ![starts](https://img.shields.io/github/stars/monzaviman/CVE_2022_36446.svg) ![forks](https://img.shields.io/github/forks/monzaviman/CVE_2022_36446.svg)


## CVE-2022-26809
 Remote Procedure Call Runtime Remote Code Execution Vulnerability. This CVE ID is unique from CVE-2022-24492, CVE-2022-24528.

- [https://github.com/crypt0r00t/CVE-2022-26809](https://github.com/crypt0r00t/CVE-2022-26809) :  ![starts](https://img.shields.io/github/stars/crypt0r00t/CVE-2022-26809.svg) ![forks](https://img.shields.io/github/forks/crypt0r00t/CVE-2022-26809.svg)


## CVE-2021-43811
 Sockeye is an open-source sequence-to-sequence framework for Neural Machine Translation built on PyTorch. Sockeye uses YAML to store model and data configurations on disk. Versions below 2.3.24 use unsafe YAML loading, which can be made to execute arbitrary code embedded in config files. An attacker can add malicious code to the config file of a trained model and attempt to convince users to download and run it. If users run the model, the embedded code will run locally. The issue is fixed in version 2.3.24.

- [https://github.com/s-index/CVE-2021-43811](https://github.com/s-index/CVE-2021-43811) :  ![starts](https://img.shields.io/github/stars/s-index/CVE-2021-43811.svg) ![forks](https://img.shields.io/github/forks/s-index/CVE-2021-43811.svg)


## CVE-2021-21907
 A directory traversal vulnerability exists in the CMA CLI getenv command functionality of Garrett Metal Detectors&#8217; iC Module CMA Version 5.0. A specially-crafted command line argument can lead to local file inclusion. An attacker can provide malicious input to trigger this vulnerability.

- [https://github.com/wr0x00/Lizard](https://github.com/wr0x00/Lizard) :  ![starts](https://img.shields.io/github/stars/wr0x00/Lizard.svg) ![forks](https://img.shields.io/github/forks/wr0x00/Lizard.svg)


## CVE-2020-1938
 When using the Apache JServ Protocol (AJP), care must be taken when trusting incoming connections to Apache Tomcat. Tomcat treats AJP connections as having higher trust than, for example, a similar HTTP connection. If such connections are available to an attacker, they can be exploited in ways that may be surprising. In Apache Tomcat 9.0.0.M1 to 9.0.0.30, 8.5.0 to 8.5.50 and 7.0.0 to 7.0.99, Tomcat shipped with an AJP Connector enabled by default that listened on all configured IP addresses. It was expected (and recommended in the security guide) that this Connector would be disabled if not required. This vulnerability report identified a mechanism that allowed: - returning arbitrary files from anywhere in the web application - processing any file in the web application as a JSP Further, if the web application allowed file upload and stored those files within the web application (or the attacker was able to control the content of the web application by some other means) then this, along with the ability to process a file as a JSP, made remote code execution possible. It is important to note that mitigation is only required if an AJP port is accessible to untrusted users. Users wishing to take a defence-in-depth approach and block the vector that permits returning arbitrary files and execution as JSP may upgrade to Apache Tomcat 9.0.31, 8.5.51 or 7.0.100 or later. A number of changes were made to the default AJP Connector configuration in 9.0.31 to harden the default configuration. It is likely that users upgrading to 9.0.31, 8.5.51 or 7.0.100 or later will need to make small changes to their configurations.

- [https://github.com/YounesTasra-R4z3rSw0rd/CVE-2020-1938](https://github.com/YounesTasra-R4z3rSw0rd/CVE-2020-1938) :  ![starts](https://img.shields.io/github/stars/YounesTasra-R4z3rSw0rd/CVE-2020-1938.svg) ![forks](https://img.shields.io/github/forks/YounesTasra-R4z3rSw0rd/CVE-2020-1938.svg)


## CVE-2020-0181
 In exif_data_load_data_thumbnail of exif-data.c, there is a possible denial of service due to an integer overflow. This could lead to remote denial of service with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-10Android ID: A-145075076

- [https://github.com/Trinadh465/external_libexif_AOSP10_r33_CVE-2020-0181](https://github.com/Trinadh465/external_libexif_AOSP10_r33_CVE-2020-0181) :  ![starts](https://img.shields.io/github/stars/Trinadh465/external_libexif_AOSP10_r33_CVE-2020-0181.svg) ![forks](https://img.shields.io/github/forks/Trinadh465/external_libexif_AOSP10_r33_CVE-2020-0181.svg)


## CVE-2020-0041
 In binder_transaction of binder.c, there is a possible out of bounds write due to an incorrect bounds check. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-145988638References: Upstream kernel

- [https://github.com/j4nn/CVE-2020-0041](https://github.com/j4nn/CVE-2020-0041) :  ![starts](https://img.shields.io/github/stars/j4nn/CVE-2020-0041.svg) ![forks](https://img.shields.io/github/forks/j4nn/CVE-2020-0041.svg)


## CVE-2019-14450
 A directory traversal vulnerability was discovered in RepetierServer.exe in Repetier-Server 0.8 through 0.91 that allows for the creation of a user controlled XML file at an unintended location. When this is combined with CVE-2019-14451, an attacker can upload an &quot;external command&quot; configuration as a printer configuration, and achieve remote code execution. After exploitation, loading of the external command configuration is dependent on a system reboot or service restart.

- [https://github.com/securifera/CVE-2019-14450](https://github.com/securifera/CVE-2019-14450) :  ![starts](https://img.shields.io/github/stars/securifera/CVE-2019-14450.svg) ![forks](https://img.shields.io/github/forks/securifera/CVE-2019-14450.svg)


## CVE-2019-14040
 Using memory after being freed in qsee due to wrong implementation can lead to unexpected behavior such as execution of unknown code in Snapdragon Auto, Snapdragon Compute, Snapdragon Consumer IOT, Snapdragon Industrial IOT, Snapdragon IoT, Snapdragon Mobile, Snapdragon Voice &amp; Music, Snapdragon Wearables in APQ8009, APQ8017, APQ8053, APQ8096AU, APQ8098, MDM9150, MDM9206, MDM9207C, MDM9607, MDM9640, MDM9650, MSM8905, MSM8909W, MSM8917, MSM8920, MSM8937, MSM8940, MSM8953, MSM8996AU, MSM8998, QCS605, QM215, SDA660, SDA845, SDM429, SDM429W, SDM439, SDM450, SDM630, SDM632, SDM636, SDM660, SDM845, SDX20, SDX24, SM8150, SXR1130

- [https://github.com/tamirzb/CVE-2019-14040](https://github.com/tamirzb/CVE-2019-14040) :  ![starts](https://img.shields.io/github/stars/tamirzb/CVE-2019-14040.svg) ![forks](https://img.shields.io/github/forks/tamirzb/CVE-2019-14040.svg)


## CVE-2019-10149
 A flaw was found in Exim versions 4.87 to 4.91 (inclusive). Improper validation of recipient address in deliver_message() function in /src/deliver.c may lead to remote command execution.

- [https://github.com/bananaphones/exim-rce-quickfix](https://github.com/bananaphones/exim-rce-quickfix) :  ![starts](https://img.shields.io/github/stars/bananaphones/exim-rce-quickfix.svg) ![forks](https://img.shields.io/github/forks/bananaphones/exim-rce-quickfix.svg)
- [https://github.com/cowbe0x004/eximrce-CVE-2019-10149](https://github.com/cowbe0x004/eximrce-CVE-2019-10149) :  ![starts](https://img.shields.io/github/stars/cowbe0x004/eximrce-CVE-2019-10149.svg) ![forks](https://img.shields.io/github/forks/cowbe0x004/eximrce-CVE-2019-10149.svg)
- [https://github.com/Diefunction/CVE-2019-10149](https://github.com/Diefunction/CVE-2019-10149) :  ![starts](https://img.shields.io/github/stars/Diefunction/CVE-2019-10149.svg) ![forks](https://img.shields.io/github/forks/Diefunction/CVE-2019-10149.svg)
- [https://github.com/MNEMO-CERT/PoC--CVE-2019-10149_Exim](https://github.com/MNEMO-CERT/PoC--CVE-2019-10149_Exim) :  ![starts](https://img.shields.io/github/stars/MNEMO-CERT/PoC--CVE-2019-10149_Exim.svg) ![forks](https://img.shields.io/github/forks/MNEMO-CERT/PoC--CVE-2019-10149_Exim.svg)
- [https://github.com/AzizMea/CVE-2019-10149-privilege-escalation](https://github.com/AzizMea/CVE-2019-10149-privilege-escalation) :  ![starts](https://img.shields.io/github/stars/AzizMea/CVE-2019-10149-privilege-escalation.svg) ![forks](https://img.shields.io/github/forks/AzizMea/CVE-2019-10149-privilege-escalation.svg)
- [https://github.com/Chris-dev1/exim.exp](https://github.com/Chris-dev1/exim.exp) :  ![starts](https://img.shields.io/github/stars/Chris-dev1/exim.exp.svg) ![forks](https://img.shields.io/github/forks/Chris-dev1/exim.exp.svg)
- [https://github.com/darsigovrustam/CVE-2019-10149](https://github.com/darsigovrustam/CVE-2019-10149) :  ![starts](https://img.shields.io/github/stars/darsigovrustam/CVE-2019-10149.svg) ![forks](https://img.shields.io/github/forks/darsigovrustam/CVE-2019-10149.svg)
- [https://github.com/Brets0150/StickyExim](https://github.com/Brets0150/StickyExim) :  ![starts](https://img.shields.io/github/stars/Brets0150/StickyExim.svg) ![forks](https://img.shields.io/github/forks/Brets0150/StickyExim.svg)
- [https://github.com/aishee/CVE-2019-10149-quick](https://github.com/aishee/CVE-2019-10149-quick) :  ![starts](https://img.shields.io/github/stars/aishee/CVE-2019-10149-quick.svg) ![forks](https://img.shields.io/github/forks/aishee/CVE-2019-10149-quick.svg)
- [https://github.com/Stick-U235/CVE-2019-10149-Exploit](https://github.com/Stick-U235/CVE-2019-10149-Exploit) :  ![starts](https://img.shields.io/github/stars/Stick-U235/CVE-2019-10149-Exploit.svg) ![forks](https://img.shields.io/github/forks/Stick-U235/CVE-2019-10149-Exploit.svg)
- [https://github.com/Dilshan-Eranda/CVE-2019-10149](https://github.com/Dilshan-Eranda/CVE-2019-10149) :  ![starts](https://img.shields.io/github/stars/Dilshan-Eranda/CVE-2019-10149.svg) ![forks](https://img.shields.io/github/forks/Dilshan-Eranda/CVE-2019-10149.svg)
- [https://github.com/cloudflare/exim-cve-2019-10149-data](https://github.com/cloudflare/exim-cve-2019-10149-data) :  ![starts](https://img.shields.io/github/stars/cloudflare/exim-cve-2019-10149-data.svg) ![forks](https://img.shields.io/github/forks/cloudflare/exim-cve-2019-10149-data.svg)


## CVE-2019-1181
 A remote code execution vulnerability exists in Remote Desktop Services &#8364;&#8220; formerly known as Terminal Services &#8364;&#8220; when an unauthenticated attacker connects to the target system using RDP and sends specially crafted requests, aka 'Remote Desktop Services Remote Code Execution Vulnerability'. This CVE ID is unique from CVE-2019-1182, CVE-2019-1222, CVE-2019-1226.

- [https://github.com/major203/cve-2019-1181](https://github.com/major203/cve-2019-1181) :  ![starts](https://img.shields.io/github/stars/major203/cve-2019-1181.svg) ![forks](https://img.shields.io/github/forks/major203/cve-2019-1181.svg)


## CVE-2018-20463
 An issue was discovered in the JSmol2WP plugin 1.07 for WordPress. There is an arbitrary file read vulnerability via ../ directory traversal in query=php://filter/resource= in the jsmol.php query string. This can also be used for SSRF.

- [https://github.com/Henry4E36/CVE-2018-20463](https://github.com/Henry4E36/CVE-2018-20463) :  ![starts](https://img.shields.io/github/stars/Henry4E36/CVE-2018-20463.svg) ![forks](https://img.shields.io/github/forks/Henry4E36/CVE-2018-20463.svg)


## CVE-2018-9995
 TBK DVR4104 and DVR4216 devices, as well as Novo, CeNova, QSee, Pulnix, XVR 5 in 1, Securus, Night OWL, DVR Login, HVR Login, and MDVR Login, which run re-branded versions of the original TBK DVR4104 and DVR4216 series, allow remote attackers to bypass authentication via a &quot;Cookie: uid=admin&quot; header, as demonstrated by a device.rsp?opt=user&amp;cmd=list request that provides credentials within JSON data in a response.

- [https://github.com/wr0x00/Lizard](https://github.com/wr0x00/Lizard) :  ![starts](https://img.shields.io/github/stars/wr0x00/Lizard.svg) ![forks](https://img.shields.io/github/forks/wr0x00/Lizard.svg)

