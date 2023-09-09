# Update 2023-09-09
## CVE-2023-41593
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/MATRIXDEVIL/CVE](https://github.com/MATRIXDEVIL/CVE) :  ![starts](https://img.shields.io/github/stars/MATRIXDEVIL/CVE.svg) ![forks](https://img.shields.io/github/forks/MATRIXDEVIL/CVE.svg)


## CVE-2023-41535
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/Sh33talUmath/CVE-2023-41535](https://github.com/Sh33talUmath/CVE-2023-41535) :  ![starts](https://img.shields.io/github/stars/Sh33talUmath/CVE-2023-41535.svg) ![forks](https://img.shields.io/github/forks/Sh33talUmath/CVE-2023-41535.svg)


## CVE-2023-41534
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/Sh33talUmath/CVE-2023-41534](https://github.com/Sh33talUmath/CVE-2023-41534) :  ![starts](https://img.shields.io/github/stars/Sh33talUmath/CVE-2023-41534.svg) ![forks](https://img.shields.io/github/forks/Sh33talUmath/CVE-2023-41534.svg)


## CVE-2023-41533
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/Sh33talUmath/CVE-2023-41533](https://github.com/Sh33talUmath/CVE-2023-41533) :  ![starts](https://img.shields.io/github/stars/Sh33talUmath/CVE-2023-41533.svg) ![forks](https://img.shields.io/github/forks/Sh33talUmath/CVE-2023-41533.svg)


## CVE-2023-40930
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/NSnidie/-CVE-2023-40930](https://github.com/NSnidie/-CVE-2023-40930) :  ![starts](https://img.shields.io/github/stars/NSnidie/-CVE-2023-40930.svg) ![forks](https://img.shields.io/github/forks/NSnidie/-CVE-2023-40930.svg)


## CVE-2023-40031
 Notepad++ is a free and open-source source code editor. Versions 8.5.6 and prior are vulnerable to heap buffer write overflow in `Utf8_16_Read::convert`. This issue may lead to arbitrary code execution. As of time of publication, no known patches are available in existing versions of Notepad++.

- [https://github.com/webraybtl/CVE-2023-40031](https://github.com/webraybtl/CVE-2023-40031) :  ![starts](https://img.shields.io/github/stars/webraybtl/CVE-2023-40031.svg) ![forks](https://img.shields.io/github/forks/webraybtl/CVE-2023-40031.svg)


## CVE-2023-38831
 RARLabs WinRAR before 6.23 allows attackers to execute arbitrary code when a user attempts to view a benign file within a ZIP archive. The issue occurs because a ZIP archive may include a benign file (such as an ordinary .JPG file) and also a folder that has the same name as the benign file, and the contents of the folder (which may include executable content) are processed during an attempt to access only the benign file. This was exploited in the wild in April through August 2023.

- [https://github.com/GOTonyGO/CVE-2023-38831-winrar](https://github.com/GOTonyGO/CVE-2023-38831-winrar) :  ![starts](https://img.shields.io/github/stars/GOTonyGO/CVE-2023-38831-winrar.svg) ![forks](https://img.shields.io/github/forks/GOTonyGO/CVE-2023-38831-winrar.svg)


## CVE-2023-36812
 OpenTSDB is a open source, distributed, scalable Time Series Database (TSDB). OpenTSDB is vulnerable to Remote Code Execution vulnerability by writing user-controlled input to Gnuplot configuration file and running Gnuplot with the generated configuration. This issue has been patched in commit `07c4641471c` and further refined in commit `fa88d3e4b`. These patches are available in the `2.4.2` release. Users are advised to upgrade. User unable to upgrade may disable Gunuplot via the config option`tsd.core.enable_ui = true` and remove the shell files `mygnuplot.bat` and `mygnuplot.sh`.

- [https://github.com/ErikWynter/opentsdb_key_cmd_injection](https://github.com/ErikWynter/opentsdb_key_cmd_injection) :  ![starts](https://img.shields.io/github/stars/ErikWynter/opentsdb_key_cmd_injection.svg) ![forks](https://img.shields.io/github/forks/ErikWynter/opentsdb_key_cmd_injection.svg)


## CVE-2023-30943
 The vulnerability was found Moodle which exists because the application allows a user to control path of the older to create in TinyMCE loaders. A remote user can send a specially crafted HTTP request and create arbitrary folders on the system.

- [https://github.com/Chocapikk/CVE-2023-30943](https://github.com/Chocapikk/CVE-2023-30943) :  ![starts](https://img.shields.io/github/stars/Chocapikk/CVE-2023-30943.svg) ![forks](https://img.shields.io/github/forks/Chocapikk/CVE-2023-30943.svg)


## CVE-2023-27372
 SPIP before 4.2.1 allows Remote Code Execution via form values in the public area because serialization is mishandled. The fixed versions are 3.2.18, 4.0.10, 4.1.8, and 4.2.1.

- [https://github.com/redboltsec/CVE-2023-27372-PoC](https://github.com/redboltsec/CVE-2023-27372-PoC) :  ![starts](https://img.shields.io/github/stars/redboltsec/CVE-2023-27372-PoC.svg) ![forks](https://img.shields.io/github/forks/redboltsec/CVE-2023-27372-PoC.svg)


## CVE-2023-25826
 Due to insufficient validation of parameters passed to the legacy HTTP query API, it is possible to inject crafted OS commands into multiple parameters and execute malicious code on the OpenTSDB host system. This exploit exists due to an incomplete fix that was made when this vulnerability was previously disclosed as CVE-2020-35476. Regex validation that was implemented to restrict allowed input to the query API does not work as intended, allowing crafted commands to bypass validation.

- [https://github.com/ErikWynter/opentsdb_key_cmd_injection](https://github.com/ErikWynter/opentsdb_key_cmd_injection) :  ![starts](https://img.shields.io/github/stars/ErikWynter/opentsdb_key_cmd_injection.svg) ![forks](https://img.shields.io/github/forks/ErikWynter/opentsdb_key_cmd_injection.svg)


## CVE-2023-23946
 Git, a revision control system, is vulnerable to path traversal prior to versions 2.39.2, 2.38.4, 2.37.6, 2.36.5, 2.35.7, 2.34.7, 2.33.7, 2.32.6, 2.31.7, and 2.30.8. By feeding a crafted input to `git apply`, a path outside the working tree can be overwritten as the user who is running `git apply`. A fix has been prepared and will appear in v2.39.2, v2.38.4, v2.37.6, v2.36.5, v2.35.7, v2.34.7, v2.33.7, v2.32.6, v2.31.7, and v2.30.8. As a workaround, use `git apply --stat` to inspect a patch before applying; avoid applying one that creates a symbolic link and then creates a file beyond the symbolic link.

- [https://github.com/bruno-1337/CVE-2023-23946-POC](https://github.com/bruno-1337/CVE-2023-23946-POC) :  ![starts](https://img.shields.io/github/stars/bruno-1337/CVE-2023-23946-POC.svg) ![forks](https://img.shields.io/github/forks/bruno-1337/CVE-2023-23946-POC.svg)


## CVE-2022-2274
 The OpenSSL 3.0.4 release introduced a serious bug in the RSA implementation for X86_64 CPUs supporting the AVX512IFMA instructions. This issue makes the RSA implementation with 2048 bit private keys incorrect on such machines and memory corruption will happen during the computation. As a consequence of the memory corruption an attacker may be able to trigger a remote code execution on the machine performing the computation. SSL/TLS servers or other servers using 2048 bit RSA private keys running on machines supporting AVX512IFMA instructions of the X86_64 architecture are affected by this issue.

- [https://github.com/DesmondSanctity/CVE-2022-2274](https://github.com/DesmondSanctity/CVE-2022-2274) :  ![starts](https://img.shields.io/github/stars/DesmondSanctity/CVE-2022-2274.svg) ![forks](https://img.shields.io/github/forks/DesmondSanctity/CVE-2022-2274.svg)


## CVE-2022-0591
 The FormCraft WordPress plugin before 3.8.28 does not validate the URL parameter in the formcraft3_get AJAX action, leading to SSRF issues exploitable by unauthenticated users

- [https://github.com/im-hanzou/FC3er](https://github.com/im-hanzou/FC3er) :  ![starts](https://img.shields.io/github/stars/im-hanzou/FC3er.svg) ![forks](https://img.shields.io/github/forks/im-hanzou/FC3er.svg)


## CVE-2021-20021
 A vulnerability in the SonicWall Email Security version 10.0.9.x allows an attacker to create an administrative account by sending a crafted HTTP request to the remote host.

- [https://github.com/SUPRAAA-1337/CVE-2021-20021](https://github.com/SUPRAAA-1337/CVE-2021-20021) :  ![starts](https://img.shields.io/github/stars/SUPRAAA-1337/CVE-2021-20021.svg) ![forks](https://img.shields.io/github/forks/SUPRAAA-1337/CVE-2021-20021.svg)


## CVE-2020-29607
 A file upload restriction bypass vulnerability in Pluck CMS before 4.7.13 allows an admin privileged user to gain access in the host through the &quot;manage files&quot; functionality, which may result in remote code execution.

- [https://github.com/0xAbbarhSF/CVE-2020-29607](https://github.com/0xAbbarhSF/CVE-2020-29607) :  ![starts](https://img.shields.io/github/stars/0xAbbarhSF/CVE-2020-29607.svg) ![forks](https://img.shields.io/github/forks/0xAbbarhSF/CVE-2020-29607.svg)


## CVE-2017-0541
 A remote code execution vulnerability in sonivox in Mediaserver could enable an attacker using a specially crafted file to cause memory corruption during media file and data processing. This issue is rated as Critical due to the possibility of remote code execution within the context of the Mediaserver process. Product: Android. Versions: 4.4.4, 5.0.2, 5.1.1, 6.0, 6.0.1, 7.0, 7.1.1. Android ID: A-34031018.

- [https://github.com/likescam/CVE-2017-0541](https://github.com/likescam/CVE-2017-0541) :  ![starts](https://img.shields.io/github/stars/likescam/CVE-2017-0541.svg) ![forks](https://img.shields.io/github/forks/likescam/CVE-2017-0541.svg)

