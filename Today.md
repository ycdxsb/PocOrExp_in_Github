# Update 2026-02-26
## CVE-2026-27507
 Binardat 10G08-0800GSM network switch firmware version V300SP10260209 and prior contain hard-coded administrative credentials that cannot be changed by users. Knowledge of these credentials allows full administrative access to the device.

- [https://github.com/RootAid/CVE-2026-27507](https://github.com/RootAid/CVE-2026-27507) :  ![starts](https://img.shields.io/github/stars/RootAid/CVE-2026-27507.svg) ![forks](https://img.shields.io/github/forks/RootAid/CVE-2026-27507.svg)


## CVE-2026-27211
 Cloud Hypervisor is a Virtual Machine Monitor for Cloud workloads. Versions 34.0 through 50.0 arevulnerable to arbitrary host file exfiltration (constrained by process privileges) when using virtio-block devices backed by raw images. A malicious guest can overwrite its disk header with a crafted QCOW2 structure pointing to a sensitive host path. Upon the next VM boot or disk scan, the image format auto-detection parses this header and serves the host file's contents to the guest. Guest-initiated VM reboots are sufficient to trigger a disk scan and do not cause the Cloud Hypervisor process to exit. Therefore, a single VM can perform this attack without needing interaction from the management stack. Successful exploitation requires the backing image to be either writable by the guest or sourced from an untrusted origin. Deployments utilizing only trusted, read-only images are not affected. This issue has been fixed in version 50.1. To workaround, enable land lock sandboxing and restrict process privileges and access.

- [https://github.com/glitchhawks/CVE-2026-27211](https://github.com/glitchhawks/CVE-2026-27211) :  ![starts](https://img.shields.io/github/stars/glitchhawks/CVE-2026-27211.svg) ![forks](https://img.shields.io/github/forks/glitchhawks/CVE-2026-27211.svg)


## CVE-2026-26331
 yt-dlp is a command-line audio/video downloader. Starting in version 2023.06.21 and prior to version 2026.02.21, when yt-dlp's `--netrc-cmd` command-line option (or `netrc_cmd` Python API parameter) is used, an attacker could achieve arbitrary command injection on the user's system with a maliciously crafted URL. yt-dlp maintainers assume the impact of this vulnerability to be high for anyone who uses `--netrc-cmd` in their command/configuration or `netrc_cmd` in their Python scripts. Even though the maliciously crafted URL itself will look very suspicious to many users, it would be trivial for a maliciously crafted webpage with an inconspicuous URL to covertly exploit this vulnerability via HTTP redirect. Users without `--netrc-cmd` in their arguments or `netrc_cmd` in their scripts are unaffected. No evidence has been found of this exploit being used in the wild. yt-dlp version 2026.02.21 fixes this issue by validating all netrc "machine" values and raising an error upon unexpected input. As a workaround, users who are unable to upgrade should avoid using the `--netrc-cmd` command-line option (or `netrc_cmd` Python API parameter), or they should at least not pass a placeholder (`{}`) in their `--netrc-cmd` argument.

- [https://github.com/dxlerYT/CVE-2026-26331](https://github.com/dxlerYT/CVE-2026-26331) :  ![starts](https://img.shields.io/github/stars/dxlerYT/CVE-2026-26331.svg) ![forks](https://img.shields.io/github/forks/dxlerYT/CVE-2026-26331.svg)


## CVE-2026-26198
 Ormar is a async mini ORM for Python. In versions 0.9.9 through 0.22.0, when performing aggregate queries, Ormar ORM constructs SQL expressions by passing user-supplied column names directly into `sqlalchemy.text()` without any validation or sanitization. The `min()` and `max()` methods in the `QuerySet` class accept arbitrary string input as the column parameter. While `sum()` and `avg()` are partially protected by an `is_numeric` type check that rejects non-existent fields, `min()` and `max()` skip this validation entirely. As a result, an attacker-controlled string is embedded as raw SQL inside the aggregate function call. Any unauthorized user can exploit this vulnerability to read the entire database contents, including tables unrelated to the queried model, by injecting a subquery as the column parameter. Version 0.23.0 contains a patch.

- [https://github.com/blackhatlegend/CVE-2026-26198](https://github.com/blackhatlegend/CVE-2026-26198) :  ![starts](https://img.shields.io/github/stars/blackhatlegend/CVE-2026-26198.svg) ![forks](https://img.shields.io/github/forks/blackhatlegend/CVE-2026-26198.svg)


## CVE-2026-26030
 Semantic Kernel, Microsoft's semantic kernel Python SDK, has a remote code execution vulnerability in versions prior to 1.39.4, specifically within the `InMemoryVectorStore` filter functionality. The problem has been fixed in version `python-1.39.4`. Users should upgrade this version or higher. As a workaround, avoid using `InMemoryVectorStore` for production scenarios.

- [https://github.com/mbanyamer/CVE-2026-26030-Microsoft-Semantic-Kernel-1.39.4-RCE](https://github.com/mbanyamer/CVE-2026-26030-Microsoft-Semantic-Kernel-1.39.4-RCE) :  ![starts](https://img.shields.io/github/stars/mbanyamer/CVE-2026-26030-Microsoft-Semantic-Kernel-1.39.4-RCE.svg) ![forks](https://img.shields.io/github/forks/mbanyamer/CVE-2026-26030-Microsoft-Semantic-Kernel-1.39.4-RCE.svg)


## CVE-2026-25755
 jsPDF is a library to generate PDFs in JavaScript. Prior to 4.2.0, user control of the argument of the `addJS` method allows an attacker to inject arbitrary PDF objects into the generated document. By crafting a payload that escapes the JavaScript string delimiter, an attacker can execute malicious actions or alter the document structure, impacting any user who opens the generated PDF. The vulnerability has been fixed in jspdf@4.2.0. As a workaround, escape parentheses in user-provided JavaScript code before passing them to the `addJS` method.

- [https://github.com/absholi7ly/jsPDF-Object-Injection](https://github.com/absholi7ly/jsPDF-Object-Injection) :  ![starts](https://img.shields.io/github/stars/absholi7ly/jsPDF-Object-Injection.svg) ![forks](https://img.shields.io/github/forks/absholi7ly/jsPDF-Object-Injection.svg)


## CVE-2026-25643
 Frigate is a network video recorder (NVR) with realtime local object detection for IP cameras. Prior to 0.16.4, a critical Remote Command Execution (RCE) vulnerability has been identified in the Frigate integration with go2rtc. The application does not sanitize user input in the video stream configuration (config.yaml), allowing direct injection of system commands via the exec: directive. The go2rtc service executes these commands without restrictions. This vulnerability is only exploitable by an administrator or users who have exposed their Frigate install to the open internet with no authentication which allows anyone full administrative control. This vulnerability is fixed in 0.16.4.

- [https://github.com/joshuavanderpoll/CVE-2026-25643](https://github.com/joshuavanderpoll/CVE-2026-25643) :  ![starts](https://img.shields.io/github/stars/joshuavanderpoll/CVE-2026-25643.svg) ![forks](https://img.shields.io/github/forks/joshuavanderpoll/CVE-2026-25643.svg)


## CVE-2026-21858
 n8n is an open source workflow automation platform. Versions starting with 1.65.0 and below 1.121.0 enable an attacker to access files on the underlying server through execution of certain form-based workflows. A vulnerable workflow could grant access to an unauthenticated remote attacker, resulting in exposure of sensitive information stored on the system and may enable further compromise depending on deployment configuration and workflow usage. This issue is fixed in version 1.121.0.

- [https://github.com/bamov970/CVE-2026-21858](https://github.com/bamov970/CVE-2026-21858) :  ![starts](https://img.shields.io/github/stars/bamov970/CVE-2026-21858.svg) ![forks](https://img.shields.io/github/forks/bamov970/CVE-2026-21858.svg)


## CVE-2026-3062
 Out of bounds read and write in Tint in Google Chrome on Mac prior to 145.0.7632.116 allowed a remote attacker to perform out of bounds memory access via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/z3r0h3ro/CVE-2026-3062-chain](https://github.com/z3r0h3ro/CVE-2026-3062-chain) :  ![starts](https://img.shields.io/github/stars/z3r0h3ro/CVE-2026-3062-chain.svg) ![forks](https://img.shields.io/github/forks/z3r0h3ro/CVE-2026-3062-chain.svg)


## CVE-2026-2898
 A vulnerability was detected in funadmin up to 7.1.0-rc4. This issue affects the function getMember of the file app/common/service/AuthCloudService.php of the component Backend Endpoint. The manipulation of the argument cloud_account results in deserialization. The attack may be performed from remote. The exploit is now public and may be used. The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/aykhan32/CVE-2026-2898-FunAdmin-Deserialization](https://github.com/aykhan32/CVE-2026-2898-FunAdmin-Deserialization) :  ![starts](https://img.shields.io/github/stars/aykhan32/CVE-2026-2898-FunAdmin-Deserialization.svg) ![forks](https://img.shields.io/github/forks/aykhan32/CVE-2026-2898-FunAdmin-Deserialization.svg)


## CVE-2026-2441
 Use after free in CSS in Google Chrome prior to 145.0.7632.75 allowed a remote attacker to execute arbitrary code inside a sandbox via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/NetVanguard-cmd/CVE-2026-2441](https://github.com/NetVanguard-cmd/CVE-2026-2441) :  ![starts](https://img.shields.io/github/stars/NetVanguard-cmd/CVE-2026-2441.svg) ![forks](https://img.shields.io/github/forks/NetVanguard-cmd/CVE-2026-2441.svg)


## CVE-2026-0770
The specific flaw exists within the handling of the exec_globals parameter provided to the validate endpoint. The issue results from the inclusion of a resource from an untrusted control sphere. An attacker can leverage this vulnerability to execute code in the context of root. Was ZDI-CAN-27325.

- [https://github.com/0xgh057r3c0n/CVE-2026-0770](https://github.com/0xgh057r3c0n/CVE-2026-0770) :  ![starts](https://img.shields.io/github/stars/0xgh057r3c0n/CVE-2026-0770.svg) ![forks](https://img.shields.io/github/forks/0xgh057r3c0n/CVE-2026-0770.svg)


## CVE-2025-67445
 TOTOLINK X5000R V9.1.0cu.2415_B20250515 contains a denial-of-service vulnerability in /cgi-bin/cstecgi.cgi. The CGI reads the CONTENT_LENGTH environment variable and allocates memory using malloc (CONTENT_LENGTH + 1) without sufficient bounds checking. When lighttpd s request size limit is not enforced, a crafted large POST request can cause memory exhaustion or a segmentation fault, leading to a crash of the management CGI and loss of availability of the web interface.

- [https://github.com/DaRkSpOoOk/CVE-2025-67445](https://github.com/DaRkSpOoOk/CVE-2025-67445) :  ![starts](https://img.shields.io/github/stars/DaRkSpOoOk/CVE-2025-67445.svg) ![forks](https://img.shields.io/github/forks/DaRkSpOoOk/CVE-2025-67445.svg)


## CVE-2025-55182
 A pre-authentication remote code execution vulnerability exists in React Server Components versions 19.0.0, 19.1.0, 19.1.1, and 19.2.0 including the following packages: react-server-dom-parcel, react-server-dom-turbopack, and react-server-dom-webpack. The vulnerable code unsafely deserializes payloads from HTTP requests to Server Function endpoints.

- [https://github.com/MuhammadWaseem29/React2Shell_Rce-cve-2025-55182](https://github.com/MuhammadWaseem29/React2Shell_Rce-cve-2025-55182) :  ![starts](https://img.shields.io/github/stars/MuhammadWaseem29/React2Shell_Rce-cve-2025-55182.svg) ![forks](https://img.shields.io/github/forks/MuhammadWaseem29/React2Shell_Rce-cve-2025-55182.svg)


## CVE-2025-47812
 In Wing FTP Server before 7.4.4. the user and admin web interfaces mishandle '\0' bytes, ultimately allowing injection of arbitrary Lua code into user session files. This can be used to execute arbitrary system commands with the privileges of the FTP service (root or SYSTEM by default). This is thus a remote code execution vulnerability that guarantees a total server compromise. This is also exploitable via anonymous FTP accounts.

- [https://github.com/0xjuarez/CVE-2025-47812](https://github.com/0xjuarez/CVE-2025-47812) :  ![starts](https://img.shields.io/github/stars/0xjuarez/CVE-2025-47812.svg) ![forks](https://img.shields.io/github/forks/0xjuarez/CVE-2025-47812.svg)


## CVE-2025-38352
anyway in this case.

- [https://github.com/jordelmir/Elysium-Vanguard-Sentinel-Audit](https://github.com/jordelmir/Elysium-Vanguard-Sentinel-Audit) :  ![starts](https://img.shields.io/github/stars/jordelmir/Elysium-Vanguard-Sentinel-Audit.svg) ![forks](https://img.shields.io/github/forks/jordelmir/Elysium-Vanguard-Sentinel-Audit.svg)


## CVE-2025-32433
 Erlang/OTP is a set of libraries for the Erlang programming language. Prior to versions OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20, a SSH server may allow an attacker to perform unauthenticated remote code execution (RCE). By exploiting a flaw in SSH protocol message handling, a malicious actor could gain unauthorized access to affected systems and execute arbitrary commands without valid credentials. This issue is patched in versions OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20. A temporary workaround involves disabling the SSH server or to prevent access via firewall rules.

- [https://github.com/carlosalbertotuma/CVE-2025-32433](https://github.com/carlosalbertotuma/CVE-2025-32433) :  ![starts](https://img.shields.io/github/stars/carlosalbertotuma/CVE-2025-32433.svg) ![forks](https://img.shields.io/github/forks/carlosalbertotuma/CVE-2025-32433.svg)


## CVE-2025-29631
 An issue in Gardyn 4 allows a remote attacker execute arbitrary code

- [https://github.com/MichaelAdamGroberman/ICSA-26-055-03](https://github.com/MichaelAdamGroberman/ICSA-26-055-03) :  ![starts](https://img.shields.io/github/stars/MichaelAdamGroberman/ICSA-26-055-03.svg) ![forks](https://img.shields.io/github/forks/MichaelAdamGroberman/ICSA-26-055-03.svg)


## CVE-2025-29629
 An issue in Gardyn 4 allows a remote attacker to obtain sensitive information and execute arbitrary code via the Gardyn Home component

- [https://github.com/MichaelAdamGroberman/ICSA-26-055-03](https://github.com/MichaelAdamGroberman/ICSA-26-055-03) :  ![starts](https://img.shields.io/github/stars/MichaelAdamGroberman/ICSA-26-055-03.svg) ![forks](https://img.shields.io/github/forks/MichaelAdamGroberman/ICSA-26-055-03.svg)


## CVE-2025-29628
 An issue in Gardyn 4 allows a remote attacker to obtain sensitive information and execute arbitrary code via a request

- [https://github.com/MichaelAdamGroberman/ICSA-26-055-03](https://github.com/MichaelAdamGroberman/ICSA-26-055-03) :  ![starts](https://img.shields.io/github/stars/MichaelAdamGroberman/ICSA-26-055-03.svg) ![forks](https://img.shields.io/github/forks/MichaelAdamGroberman/ICSA-26-055-03.svg)


## CVE-2025-8088
     from ESET.

- [https://github.com/IsmaelCosma/CVE-2025-8088](https://github.com/IsmaelCosma/CVE-2025-8088) :  ![starts](https://img.shields.io/github/stars/IsmaelCosma/CVE-2025-8088.svg) ![forks](https://img.shields.io/github/forks/IsmaelCosma/CVE-2025-8088.svg)


## CVE-2024-54330
 Server-Side Request Forgery (SSRF) vulnerability in Hep Hep Hurra (HHH) Hurrakify allows Server Side Request Forgery.This issue affects Hurrakify: from n/a through 2.4.

- [https://github.com/RandomRobbieBF/CVE-2024-54330](https://github.com/RandomRobbieBF/CVE-2024-54330) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-54330.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-54330.svg)


## CVE-2023-43208
 NextGen Healthcare Mirth Connect before version 4.4.1 is vulnerable to unauthenticated remote code execution. Note that this vulnerability is caused by the incomplete patch of CVE-2023-37679.

- [https://github.com/predyy/CVE-2023-43208](https://github.com/predyy/CVE-2023-43208) :  ![starts](https://img.shields.io/github/stars/predyy/CVE-2023-43208.svg) ![forks](https://img.shields.io/github/forks/predyy/CVE-2023-43208.svg)
- [https://github.com/D3m0nicw0lf/CVE-2023-43208](https://github.com/D3m0nicw0lf/CVE-2023-43208) :  ![starts](https://img.shields.io/github/stars/D3m0nicw0lf/CVE-2023-43208.svg) ![forks](https://img.shields.io/github/forks/D3m0nicw0lf/CVE-2023-43208.svg)
- [https://github.com/coreraw/Mirth-Connect-CVE-2023-43208](https://github.com/coreraw/Mirth-Connect-CVE-2023-43208) :  ![starts](https://img.shields.io/github/stars/coreraw/Mirth-Connect-CVE-2023-43208.svg) ![forks](https://img.shields.io/github/forks/coreraw/Mirth-Connect-CVE-2023-43208.svg)


## CVE-2023-38831
 RARLAB WinRAR before 6.23 allows attackers to execute arbitrary code when a user attempts to view a benign file within a ZIP archive. The issue occurs because a ZIP archive may include a benign file (such as an ordinary .JPG file) and also a folder that has the same name as the benign file, and the contents of the folder (which may include executable content) are processed during an attempt to access only the benign file. This was exploited in the wild in April through October 2023.

- [https://github.com/ngothienan/CVE-2023-38831](https://github.com/ngothienan/CVE-2023-38831) :  ![starts](https://img.shields.io/github/stars/ngothienan/CVE-2023-38831.svg) ![forks](https://img.shields.io/github/forks/ngothienan/CVE-2023-38831.svg)


## CVE-2023-30258
 Command Injection vulnerability in MagnusSolution magnusbilling 6.x and 7.x allows remote attackers to run arbitrary commands via unauthenticated HTTP request.

- [https://github.com/estebanzarate/CVE-2023-30258-Magnus-Billing-v7-Command-Injection-PoC](https://github.com/estebanzarate/CVE-2023-30258-Magnus-Billing-v7-Command-Injection-PoC) :  ![starts](https://img.shields.io/github/stars/estebanzarate/CVE-2023-30258-Magnus-Billing-v7-Command-Injection-PoC.svg) ![forks](https://img.shields.io/github/forks/estebanzarate/CVE-2023-30258-Magnus-Billing-v7-Command-Injection-PoC.svg)


## CVE-2023-4966
 Sensitive information disclosure in NetScaler ADC and NetScaler Gateway when configured as a Gateway (VPN virtual server, ICA Proxy, CVPN, RDP Proxy) or AAA  virtual server.

- [https://github.com/vignesh-hp/LockBit-Ransomware-Analysis](https://github.com/vignesh-hp/LockBit-Ransomware-Analysis) :  ![starts](https://img.shields.io/github/stars/vignesh-hp/LockBit-Ransomware-Analysis.svg) ![forks](https://img.shields.io/github/forks/vignesh-hp/LockBit-Ransomware-Analysis.svg)


## CVE-2022-24481
 Windows Common Log File System Driver Elevation of Privilege Vulnerability

- [https://github.com/uname1able/CVE-2022-24481](https://github.com/uname1able/CVE-2022-24481) :  ![starts](https://img.shields.io/github/stars/uname1able/CVE-2022-24481.svg) ![forks](https://img.shields.io/github/forks/uname1able/CVE-2022-24481.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/wolf1892/CVE-2021-41773](https://github.com/wolf1892/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/wolf1892/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/wolf1892/CVE-2021-41773.svg)
- [https://github.com/honypot/CVE-2021-41773](https://github.com/honypot/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/honypot/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/honypot/CVE-2021-41773.svg)


## CVE-2021-22555
 A heap out-of-bounds write affecting Linux since v2.6.19-rc1 was discovered in net/netfilter/x_tables.c. This allows an attacker to gain privileges or cause a DoS (via heap memory corruption) through user name space

- [https://github.com/glutton-su/CVE-2021-22555](https://github.com/glutton-su/CVE-2021-22555) :  ![starts](https://img.shields.io/github/stars/glutton-su/CVE-2021-22555.svg) ![forks](https://img.shields.io/github/forks/glutton-su/CVE-2021-22555.svg)


## CVE-2021-3493
 The overlayfs implementation in the linux kernel did not properly validate with respect to user namespaces the setting of file capabilities on files in an underlying file system. Due to the combination of unprivileged user namespaces along with a patch carried in the Ubuntu kernel to allow unprivileged overlay mounts, an attacker could use this to gain elevated privileges.

- [https://github.com/Psychopath-Traveler/CVE-2021-3493](https://github.com/Psychopath-Traveler/CVE-2021-3493) :  ![starts](https://img.shields.io/github/stars/Psychopath-Traveler/CVE-2021-3493.svg) ![forks](https://img.shields.io/github/forks/Psychopath-Traveler/CVE-2021-3493.svg)


## CVE-2019-20085
 TVT NVMS-1000 devices allow GET /.. Directory Traversal

- [https://github.com/Z3R0space/CVE-2019-20085](https://github.com/Z3R0space/CVE-2019-20085) :  ![starts](https://img.shields.io/github/stars/Z3R0space/CVE-2019-20085.svg) ![forks](https://img.shields.io/github/forks/Z3R0space/CVE-2019-20085.svg)

