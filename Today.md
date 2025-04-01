# Update 2025-04-01
## CVE-2025-30208
 Vite, a provider of frontend development tooling, has a vulnerability in versions prior to 6.2.3, 6.1.2, 6.0.12, 5.4.15, and 4.5.10. `@fs` denies access to files outside of Vite serving allow list. Adding `?raw??` or `?import&raw??` to the URL bypasses this limitation and returns the file content if it exists. This bypass exists because trailing separators such as `?` are removed in several places, but are not accounted for in query string regexes. The contents of arbitrary files can be returned to the browser. Only apps explicitly exposing the Vite dev server to the network (using `--host` or `server.host` config option) are affected. Versions 6.2.3, 6.1.2, 6.0.12, 5.4.15, and 4.5.10 fix the issue.

- [https://github.com/Ahmed-mostafa03/CVE-2025-30208-EXP](https://github.com/Ahmed-mostafa03/CVE-2025-30208-EXP) :  ![starts](https://img.shields.io/github/stars/Ahmed-mostafa03/CVE-2025-30208-EXP.svg) ![forks](https://img.shields.io/github/forks/Ahmed-mostafa03/CVE-2025-30208-EXP.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Prior to 14.2.25 and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 14.2.25 and 15.2.3.

- [https://github.com/ayato-shitomi/WebLab_CVE-2025-29927](https://github.com/ayato-shitomi/WebLab_CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/ayato-shitomi/WebLab_CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/ayato-shitomi/WebLab_CVE-2025-29927.svg)
- [https://github.com/Kamal-418/Vulnerable-Lab-NextJS-CVE-2025-29927](https://github.com/Kamal-418/Vulnerable-Lab-NextJS-CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/Kamal-418/Vulnerable-Lab-NextJS-CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/Kamal-418/Vulnerable-Lab-NextJS-CVE-2025-29927.svg)


## CVE-2025-27840
 Espressif ESP32 chips allow 29 hidden HCI commands, such as 0xFC02 (Write memory).

- [https://github.com/demining/Bluetooth-Attacks-CVE-2025-27840](https://github.com/demining/Bluetooth-Attacks-CVE-2025-27840) :  ![starts](https://img.shields.io/github/stars/demining/Bluetooth-Attacks-CVE-2025-27840.svg) ![forks](https://img.shields.io/github/forks/demining/Bluetooth-Attacks-CVE-2025-27840.svg)


## CVE-2025-27152
 axios is a promise based HTTP client for the browser and node.js. The issue occurs when passing absolute URLs rather than protocol-relative URLs to axios. Even if ⁠baseURL is set, axios sends the request to the specified absolute URL, potentially causing SSRF and credential leakage. This issue impacts both server-side and client-side usage of axios. This issue is fixed in 1.8.2.

- [https://github.com/andreglock/axios-ssrf](https://github.com/andreglock/axios-ssrf) :  ![starts](https://img.shields.io/github/stars/andreglock/axios-ssrf.svg) ![forks](https://img.shields.io/github/forks/andreglock/axios-ssrf.svg)


## CVE-2025-24813
Users are recommended to upgrade to version 11.0.3, 10.1.35 or 9.0.99, which fixes the issue.

- [https://github.com/manjula-aw/CVE-2025-24813](https://github.com/manjula-aw/CVE-2025-24813) :  ![starts](https://img.shields.io/github/stars/manjula-aw/CVE-2025-24813.svg) ![forks](https://img.shields.io/github/forks/manjula-aw/CVE-2025-24813.svg)


## CVE-2025-24514
 A security issue was discovered in  ingress-nginx https://github.com/kubernetes/ingress-nginx  where the `auth-url` Ingress annotation can be used to inject configuration into nginx. This can lead to arbitrary code execution in the context of the ingress-nginx controller, and disclosure of Secrets accessible to the controller. (Note that in the default installation, the controller can access all Secrets cluster-wide.)

- [https://github.com/Esonhugh/ingressNightmare-CVE-2025-1974-exps](https://github.com/Esonhugh/ingressNightmare-CVE-2025-1974-exps) :  ![starts](https://img.shields.io/github/stars/Esonhugh/ingressNightmare-CVE-2025-1974-exps.svg) ![forks](https://img.shields.io/github/forks/Esonhugh/ingressNightmare-CVE-2025-1974-exps.svg)
- [https://github.com/lufeirider/IngressNightmare-PoC](https://github.com/lufeirider/IngressNightmare-PoC) :  ![starts](https://img.shields.io/github/stars/lufeirider/IngressNightmare-PoC.svg) ![forks](https://img.shields.io/github/forks/lufeirider/IngressNightmare-PoC.svg)


## CVE-2025-1974
 A security issue was discovered in Kubernetes where under certain conditions, an unauthenticated attacker with access to the pod network can achieve arbitrary code execution in the context of the ingress-nginx controller. This can lead to disclosure of Secrets accessible to the controller. (Note that in the default installation, the controller can access all Secrets cluster-wide.)

- [https://github.com/lufeirider/IngressNightmare-PoC](https://github.com/lufeirider/IngressNightmare-PoC) :  ![starts](https://img.shields.io/github/stars/lufeirider/IngressNightmare-PoC.svg) ![forks](https://img.shields.io/github/forks/lufeirider/IngressNightmare-PoC.svg)
- [https://github.com/Ar05un05kau05ndal/2025-1](https://github.com/Ar05un05kau05ndal/2025-1) :  ![starts](https://img.shields.io/github/stars/Ar05un05kau05ndal/2025-1.svg) ![forks](https://img.shields.io/github/forks/Ar05un05kau05ndal/2025-1.svg)


## CVE-2025-1734
 In PHP from 8.1.* before 8.1.32, from 8.2.* before 8.2.28, from 8.3.* before 8.3.19, from 8.4.* before 8.4.5, when receiving headers from HTTP server, the headers missing a colon (:) are treated as valid headers even though they are not. This may confuse applications into accepting invalid headers.

- [https://github.com/WolfThere/cve_2025-1734](https://github.com/WolfThere/cve_2025-1734) :  ![starts](https://img.shields.io/github/stars/WolfThere/cve_2025-1734.svg) ![forks](https://img.shields.io/github/forks/WolfThere/cve_2025-1734.svg)


## CVE-2025-1098
 A security issue was discovered in  ingress-nginx https://github.com/kubernetes/ingress-nginx  where the `mirror-target` and `mirror-host` Ingress annotations can be used to inject arbitrary configuration into nginx. This can lead to arbitrary code execution in the context of the ingress-nginx controller, and disclosure of Secrets accessible to the controller. (Note that in the default installation, the controller can access all Secrets cluster-wide.)

- [https://github.com/Esonhugh/ingressNightmare-CVE-2025-1974-exps](https://github.com/Esonhugh/ingressNightmare-CVE-2025-1974-exps) :  ![starts](https://img.shields.io/github/stars/Esonhugh/ingressNightmare-CVE-2025-1974-exps.svg) ![forks](https://img.shields.io/github/forks/Esonhugh/ingressNightmare-CVE-2025-1974-exps.svg)
- [https://github.com/lufeirider/IngressNightmare-PoC](https://github.com/lufeirider/IngressNightmare-PoC) :  ![starts](https://img.shields.io/github/stars/lufeirider/IngressNightmare-PoC.svg) ![forks](https://img.shields.io/github/forks/lufeirider/IngressNightmare-PoC.svg)


## CVE-2025-1097
 A security issue was discovered in  ingress-nginx https://github.com/kubernetes/ingress-nginx  where the `auth-tls-match-cn` Ingress annotation can be used to inject configuration into nginx. This can lead to arbitrary code execution in the context of the ingress-nginx controller, and disclosure of Secrets accessible to the controller. (Note that in the default installation, the controller can access all Secrets cluster-wide.)

- [https://github.com/Esonhugh/ingressNightmare-CVE-2025-1974-exps](https://github.com/Esonhugh/ingressNightmare-CVE-2025-1974-exps) :  ![starts](https://img.shields.io/github/stars/Esonhugh/ingressNightmare-CVE-2025-1974-exps.svg) ![forks](https://img.shields.io/github/forks/Esonhugh/ingressNightmare-CVE-2025-1974-exps.svg)
- [https://github.com/lufeirider/IngressNightmare-PoC](https://github.com/lufeirider/IngressNightmare-PoC) :  ![starts](https://img.shields.io/github/stars/lufeirider/IngressNightmare-PoC.svg) ![forks](https://img.shields.io/github/forks/lufeirider/IngressNightmare-PoC.svg)


## CVE-2024-50379
Users are recommended to upgrade to version 11.0.2, 10.1.34 or 9.0.98, which fixes the issue.

- [https://github.com/thunww/CVE-2024-50379](https://github.com/thunww/CVE-2024-50379) :  ![starts](https://img.shields.io/github/stars/thunww/CVE-2024-50379.svg) ![forks](https://img.shields.io/github/forks/thunww/CVE-2024-50379.svg)


## CVE-2024-36991
 In Splunk Enterprise on Windows versions below 9.2.2, 9.1.5, and 9.0.10, an attacker could perform a path traversal on the /modules/messaging/ endpoint in Splunk Enterprise on Windows. This vulnerability should only affect Splunk Enterprise on Windows.

- [https://github.com/jaytiwari05/CVE-2024-36991](https://github.com/jaytiwari05/CVE-2024-36991) :  ![starts](https://img.shields.io/github/stars/jaytiwari05/CVE-2024-36991.svg) ![forks](https://img.shields.io/github/forks/jaytiwari05/CVE-2024-36991.svg)
- [https://github.com/TcchSquad/CVE-2024-36991-Tool](https://github.com/TcchSquad/CVE-2024-36991-Tool) :  ![starts](https://img.shields.io/github/stars/TcchSquad/CVE-2024-36991-Tool.svg) ![forks](https://img.shields.io/github/forks/TcchSquad/CVE-2024-36991-Tool.svg)


## CVE-2023-45878
 GibbonEdu Gibbon version 25.0.1 and before allows Arbitrary File Write because rubrics_visualise_saveAjax.phps does not require authentication. The endpoint accepts the img, path, and gibbonPersonID parameters. The img parameter is expected to be a base64 encoded image. If the path parameter is set, the defined path is used as the destination folder, concatenated with the absolute path of the installation directory. The content of the img parameter is base64 decoded and written to the defined file path. This allows creation of PHP files that permit Remote Code Execution (unauthenticated).

- [https://github.com/davidzzo23/CVE-2023-45878](https://github.com/davidzzo23/CVE-2023-45878) :  ![starts](https://img.shields.io/github/stars/davidzzo23/CVE-2023-45878.svg) ![forks](https://img.shields.io/github/forks/davidzzo23/CVE-2023-45878.svg)
- [https://github.com/0xyy66/CVE-2023-45878_to_RCE](https://github.com/0xyy66/CVE-2023-45878_to_RCE) :  ![starts](https://img.shields.io/github/stars/0xyy66/CVE-2023-45878_to_RCE.svg) ![forks](https://img.shields.io/github/forks/0xyy66/CVE-2023-45878_to_RCE.svg)


## CVE-2023-34960
 A command injection vulnerability in the wsConvertPpt component of Chamilo v1.11.* up to v1.11.18 allows attackers to execute arbitrary commands via a SOAP API call with a crafted PowerPoint name.

- [https://github.com/mr-won/cve-2023-34960](https://github.com/mr-won/cve-2023-34960) :  ![starts](https://img.shields.io/github/stars/mr-won/cve-2023-34960.svg) ![forks](https://img.shields.io/github/forks/mr-won/cve-2023-34960.svg)


## CVE-2022-26134
 In affected versions of Confluence Server and Data Center, an OGNL injection vulnerability exists that would allow an unauthenticated attacker to execute arbitrary code on a Confluence Server or Data Center instance. The affected versions are from 1.3.0 before 7.4.17, from 7.13.0 before 7.13.7, from 7.14.0 before 7.14.3, from 7.15.0 before 7.15.2, from 7.16.0 before 7.16.4, from 7.17.0 before 7.17.4, and from 7.18.0 before 7.18.1.

- [https://github.com/mr-won/cve-2022-26134](https://github.com/mr-won/cve-2022-26134) :  ![starts](https://img.shields.io/github/stars/mr-won/cve-2022-26134.svg) ![forks](https://img.shields.io/github/forks/mr-won/cve-2022-26134.svg)


## CVE-2021-4045
 TP-Link Tapo C200 IP camera, on its 1.1.15 firmware version and below, is affected by an unauthenticated RCE vulnerability, present in the uhttpd binary running by default as root. The exploitation of this vulnerability allows an attacker to take full control of the camera.

- [https://github.com/DorskFR/tapodate](https://github.com/DorskFR/tapodate) :  ![starts](https://img.shields.io/github/stars/DorskFR/tapodate.svg) ![forks](https://img.shields.io/github/forks/DorskFR/tapodate.svg)


## CVE-2019-9053
 An issue was discovered in CMS Made Simple 2.2.8. It is possible with the News module, through a crafted URL, to achieve unauthenticated blind time-based SQL injection via the m1_idlist parameter.

- [https://github.com/so1icitx/CVE-2019-9053](https://github.com/so1icitx/CVE-2019-9053) :  ![starts](https://img.shields.io/github/stars/so1icitx/CVE-2019-9053.svg) ![forks](https://img.shields.io/github/forks/so1icitx/CVE-2019-9053.svg)


## CVE-2018-10562
 An issue was discovered on Dasan GPON home routers. Command Injection can occur via the dest_host parameter in a diag_action=ping request to a GponForm/diag_Form URI. Because the router saves ping results in /tmp and transmits them to the user when the user revisits /diag.html, it's quite simple to execute commands and retrieve their output.

- [https://github.com/mr-won/backdoor.mirai.helloworld](https://github.com/mr-won/backdoor.mirai.helloworld) :  ![starts](https://img.shields.io/github/stars/mr-won/backdoor.mirai.helloworld.svg) ![forks](https://img.shields.io/github/forks/mr-won/backdoor.mirai.helloworld.svg)


## CVE-2018-0239
 A vulnerability in the egress packet processing functionality of the Cisco StarOS operating system for Cisco Aggregation Services Router (ASR) 5700 Series devices and Virtualized Packet Core (VPC) System Software could allow an unauthenticated, remote attacker to cause an interface on the device to cease forwarding packets. The device may need to be manually reloaded to clear this Interface Forwarding Denial of Service condition. The vulnerability is due to the failure to properly check that the length of a packet to transmit does not exceed the maximum supported length of the network interface card (NIC). An attacker could exploit this vulnerability by sending a crafted IP packet or a series of crafted IP fragments through an interface on the targeted device. A successful exploit could allow the attacker to cause the network interface to cease forwarding packets. This vulnerability could be triggered by either IPv4 or IPv6 network traffic. This vulnerability affects the following Cisco products when they are running the StarOS operating system and a virtual interface card is installed on the device: Aggregation Services Router (ASR) 5700 Series, Virtualized Packet Core-Distributed Instance (VPC-DI) System Software, Virtualized Packet Core-Single Instance (VPC-SI) System Software. Cisco Bug IDs: CSCvf32385.

- [https://github.com/mr-won/CVE-2018-0239](https://github.com/mr-won/CVE-2018-0239) :  ![starts](https://img.shields.io/github/stars/mr-won/CVE-2018-0239.svg) ![forks](https://img.shields.io/github/forks/mr-won/CVE-2018-0239.svg)


## CVE-2013-3900
Exploitation of this vulnerability requires that a user or application run or install a specially crafted, signed PE file. An attacker could modify an... See more at https://msrc.microsoft.com/update-guide/vulnerability/CVE-2013-3900

- [https://github.com/DavidBr27/CVE-2013-3900-Remediation-Script](https://github.com/DavidBr27/CVE-2013-3900-Remediation-Script) :  ![starts](https://img.shields.io/github/stars/DavidBr27/CVE-2013-3900-Remediation-Script.svg) ![forks](https://img.shields.io/github/forks/DavidBr27/CVE-2013-3900-Remediation-Script.svg)
- [https://github.com/piranhap/CVE-2013-3900_Remediation_PowerShell](https://github.com/piranhap/CVE-2013-3900_Remediation_PowerShell) :  ![starts](https://img.shields.io/github/stars/piranhap/CVE-2013-3900_Remediation_PowerShell.svg) ![forks](https://img.shields.io/github/forks/piranhap/CVE-2013-3900_Remediation_PowerShell.svg)


## CVE-2012-4869
 The callme_startcall function in recordings/misc/callme_page.php in FreePBX 2.9, 2.10, and earlier allows remote attackers to execute arbitrary commands via the callmenum parameter in a c action.

- [https://github.com/cyberdesu/Elastix-2.2.0-CVE-2012-4869](https://github.com/cyberdesu/Elastix-2.2.0-CVE-2012-4869) :  ![starts](https://img.shields.io/github/stars/cyberdesu/Elastix-2.2.0-CVE-2012-4869.svg) ![forks](https://img.shields.io/github/forks/cyberdesu/Elastix-2.2.0-CVE-2012-4869.svg)


## CVE-2012-2982
 file/show.cgi in Webmin 1.590 and earlier allows remote authenticated users to execute arbitrary commands via an invalid character in a pathname, as demonstrated by a | (pipe) character.

- [https://github.com/Gvmyz/CVE-2012-2982_Python](https://github.com/Gvmyz/CVE-2012-2982_Python) :  ![starts](https://img.shields.io/github/stars/Gvmyz/CVE-2012-2982_Python.svg) ![forks](https://img.shields.io/github/forks/Gvmyz/CVE-2012-2982_Python.svg)
- [https://github.com/lpuv/CVE-2012-2982](https://github.com/lpuv/CVE-2012-2982) :  ![starts](https://img.shields.io/github/stars/lpuv/CVE-2012-2982.svg) ![forks](https://img.shields.io/github/forks/lpuv/CVE-2012-2982.svg)


## CVE-2010-2075
 UnrealIRCd 3.2.8.1, as distributed on certain mirror sites from November 2009 through June 2010, contains an externally introduced modification (Trojan Horse) in the DEBUG3_DOLOG_SYSTEM macro, which allows remote attackers to execute arbitrary commands.

- [https://github.com/abhinavsinghx/PenTest-Lab](https://github.com/abhinavsinghx/PenTest-Lab) :  ![starts](https://img.shields.io/github/stars/abhinavsinghx/PenTest-Lab.svg) ![forks](https://img.shields.io/github/forks/abhinavsinghx/PenTest-Lab.svg)


## CVE-2009-1151
 Static code injection vulnerability in setup.php in phpMyAdmin 2.11.x before 2.11.9.5 and 3.x before 3.1.3.1 allows remote attackers to inject arbitrary PHP code into a configuration file via the save action.

- [https://github.com/mr-won/ZmEu](https://github.com/mr-won/ZmEu) :  ![starts](https://img.shields.io/github/stars/mr-won/ZmEu.svg) ![forks](https://img.shields.io/github/forks/mr-won/ZmEu.svg)

