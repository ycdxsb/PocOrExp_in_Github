# Update 2025-04-17
## CVE-2025-30406
 Gladinet CentreStack through 16.1.10296.56315 (fixed in 16.4.10315.56368) has a deserialization vulnerability due to the CentreStack portal's hardcoded machineKey use, as exploited in the wild in March 2025. This enables threat actors (who know the machineKey) to serialize a payload for server-side deserialization to achieve remote code execution. NOTE: a CentreStack admin can manually delete the machineKey defined in portal\web.config.

- [https://github.com/bronsoneaver/CVE-2025-30406](https://github.com/bronsoneaver/CVE-2025-30406) :  ![starts](https://img.shields.io/github/stars/bronsoneaver/CVE-2025-30406.svg) ![forks](https://img.shields.io/github/forks/bronsoneaver/CVE-2025-30406.svg)


## CVE-2025-29705
 code-gen =2.0.6 is vulnerable to Incorrect Access Control. The project does not have permission control allowing anyone to access such projects.

- [https://github.com/yxzrw/CVE-2025-29705](https://github.com/yxzrw/CVE-2025-29705) :  ![starts](https://img.shields.io/github/stars/yxzrw/CVE-2025-29705.svg) ![forks](https://img.shields.io/github/forks/yxzrw/CVE-2025-29705.svg)


## CVE-2025-24799
 GLPI is a free asset and IT management software package. An unauthenticated user can perform a SQL injection through the inventory endpoint. This vulnerability is fixed in 10.0.18.

- [https://github.com/MatheuZSecurity/Exploit-CVE-2025-24799](https://github.com/MatheuZSecurity/Exploit-CVE-2025-24799) :  ![starts](https://img.shields.io/github/stars/MatheuZSecurity/Exploit-CVE-2025-24799.svg) ![forks](https://img.shields.io/github/forks/MatheuZSecurity/Exploit-CVE-2025-24799.svg)


## CVE-2025-24016
 Wazuh is a free and open source platform used for threat prevention, detection, and response. Starting in version 4.4.0 and prior to version 4.9.1, an unsafe deserialization vulnerability allows for remote code execution on Wazuh servers. DistributedAPI parameters are a serialized as JSON and deserialized using `as_wazuh_object` (in `framework/wazuh/core/cluster/common.py`). If an attacker manages to inject an unsanitized dictionary in DAPI request/response, they can forge an unhandled exception (`__unhandled_exc__`) to evaluate arbitrary python code. The vulnerability can be triggered by anybody with API access (compromised dashboard or Wazuh servers in the cluster) or, in certain configurations, even by a compromised agent. Version 4.9.1 contains a fix.

- [https://github.com/celsius026/poc_CVE-2025-24016](https://github.com/celsius026/poc_CVE-2025-24016) :  ![starts](https://img.shields.io/github/stars/celsius026/poc_CVE-2025-24016.svg) ![forks](https://img.shields.io/github/forks/celsius026/poc_CVE-2025-24016.svg)


## CVE-2025-2972
 This CVE ID has been rejected or withdrawn by its CVE Numbering Authority.

- [https://github.com/cypherdavy/CVE-2025-29722](https://github.com/cypherdavy/CVE-2025-29722) :  ![starts](https://img.shields.io/github/stars/cypherdavy/CVE-2025-29722.svg) ![forks](https://img.shields.io/github/forks/cypherdavy/CVE-2025-29722.svg)


## CVE-2025-2927
 A vulnerability was found in ESAFENET CDG 5.6.3.154.205. It has been classified as critical. Affected is an unknown function of the file /parameter/getFileTypeList.jsp. The manipulation of the argument typename leads to sql injection. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used. The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/0xBl4nk/CVE-2025-29278](https://github.com/0xBl4nk/CVE-2025-29278) :  ![starts](https://img.shields.io/github/stars/0xBl4nk/CVE-2025-29278.svg) ![forks](https://img.shields.io/github/forks/0xBl4nk/CVE-2025-29278.svg)
- [https://github.com/0xBl4nk/CVE-2025-29277](https://github.com/0xBl4nk/CVE-2025-29277) :  ![starts](https://img.shields.io/github/stars/0xBl4nk/CVE-2025-29277.svg) ![forks](https://img.shields.io/github/forks/0xBl4nk/CVE-2025-29277.svg)
- [https://github.com/0xBl4nk/CVE-2025-29279](https://github.com/0xBl4nk/CVE-2025-29279) :  ![starts](https://img.shields.io/github/stars/0xBl4nk/CVE-2025-29279.svg) ![forks](https://img.shields.io/github/forks/0xBl4nk/CVE-2025-29279.svg)
- [https://github.com/0xBl4nk/CVE-2025-29275](https://github.com/0xBl4nk/CVE-2025-29275) :  ![starts](https://img.shields.io/github/stars/0xBl4nk/CVE-2025-29275.svg) ![forks](https://img.shields.io/github/forks/0xBl4nk/CVE-2025-29275.svg)
- [https://github.com/0xBl4nk/CVE-2025-29276](https://github.com/0xBl4nk/CVE-2025-29276) :  ![starts](https://img.shields.io/github/stars/0xBl4nk/CVE-2025-29276.svg) ![forks](https://img.shields.io/github/forks/0xBl4nk/CVE-2025-29276.svg)


## CVE-2025-2294
 The Kubio AI Page Builder plugin for WordPress is vulnerable to Local File Inclusion in all versions up to, and including, 2.5.1 via thekubio_hybrid_theme_load_template function. This makes it possible for unauthenticated attackers to include and execute arbitrary files on the server, allowing the execution of any PHP code in those files. This can be used to bypass access controls, obtain sensitive data, or achieve code execution in cases where images and other “safe” file types can be uploaded and included.

- [https://github.com/rhz0d/CVE-2025-2294](https://github.com/rhz0d/CVE-2025-2294) :  ![starts](https://img.shields.io/github/stars/rhz0d/CVE-2025-2294.svg) ![forks](https://img.shields.io/github/forks/rhz0d/CVE-2025-2294.svg)


## CVE-2024-52550
 Jenkins Pipeline: Groovy Plugin 3990.vd281dd77a_388 and earlier, except 3975.3977.v478dd9e956c3 does not check whether the main (Jenkinsfile) script for a rebuilt build is approved, allowing attackers with Item/Build permission to rebuild a previous build whose (Jenkinsfile) script is no longer approved.

- [https://github.com/Anton-ai111/CVE-2024-52550](https://github.com/Anton-ai111/CVE-2024-52550) :  ![starts](https://img.shields.io/github/stars/Anton-ai111/CVE-2024-52550.svg) ![forks](https://img.shields.io/github/forks/Anton-ai111/CVE-2024-52550.svg)


## CVE-2024-38063
 Windows TCP/IP Remote Code Execution Vulnerability

- [https://github.com/fredagsguf/Windows-CVE-2024-38063](https://github.com/fredagsguf/Windows-CVE-2024-38063) :  ![starts](https://img.shields.io/github/stars/fredagsguf/Windows-CVE-2024-38063.svg) ![forks](https://img.shields.io/github/forks/fredagsguf/Windows-CVE-2024-38063.svg)


## CVE-2024-35250
 Windows Kernel-Mode Driver Elevation of Privilege Vulnerability

- [https://github.com/0xROOTPLS/GiveMeKernel](https://github.com/0xROOTPLS/GiveMeKernel) :  ![starts](https://img.shields.io/github/stars/0xROOTPLS/GiveMeKernel.svg) ![forks](https://img.shields.io/github/forks/0xROOTPLS/GiveMeKernel.svg)


## CVE-2024-5521
 Two Cross-Site Scripting vulnerabilities have been discovered in Alkacon's OpenCMS affecting version 16, which could allow a user having the roles of gallery editor or VFS resource manager will have the permission to upload images in the .svg format containing JavaScript code. The code will be executed the moment another user accesses the image.

- [https://github.com/micaelmaciel/CVE-2024-55211](https://github.com/micaelmaciel/CVE-2024-55211) :  ![starts](https://img.shields.io/github/stars/micaelmaciel/CVE-2024-55211.svg) ![forks](https://img.shields.io/github/forks/micaelmaciel/CVE-2024-55211.svg)


## CVE-2023-34844
 Play With Docker  0.0.2 has an insecure CAP_SYS_ADMIN privileged mode causing the docker container to escape.

- [https://github.com/shkch02/cve_2023_34844](https://github.com/shkch02/cve_2023_34844) :  ![starts](https://img.shields.io/github/stars/shkch02/cve_2023_34844.svg) ![forks](https://img.shields.io/github/forks/shkch02/cve_2023_34844.svg)


## CVE-2022-28171
 The web module in some Hikvision Hybrid SAN/Cluster Storage products have the following security vulnerability. Due to the insufficient input validation, attacker can exploit the vulnerability to execute restricted commands by sending messages with malicious commands to the affected device.

- [https://github.com/NyaMeeEain/CVE-2022-28171-POC](https://github.com/NyaMeeEain/CVE-2022-28171-POC) :  ![starts](https://img.shields.io/github/stars/NyaMeeEain/CVE-2022-28171-POC.svg) ![forks](https://img.shields.io/github/forks/NyaMeeEain/CVE-2022-28171-POC.svg)


## CVE-2021-27289
 A replay attack vulnerability was discovered in a Zigbee smart home kit manufactured by Ksix (Zigbee Gateway Module = v1.0.3, Door Sensor = v1.0.7, Motion Sensor = v1.0.12), where the Zigbee anti-replay mechanism - based on the frame counter field - is improperly implemented. As a result, an attacker within wireless range can resend captured packets with a higher sequence number, which the devices incorrectly accept as legitimate messages. This allows spoofed commands to be injected without authentication, triggering false alerts and misleading the user through notifications in the mobile application used to monitor the network.

- [https://github.com/TheMalwareGuardian/CVE-2021-27289](https://github.com/TheMalwareGuardian/CVE-2021-27289) :  ![starts](https://img.shields.io/github/stars/TheMalwareGuardian/CVE-2021-27289.svg) ![forks](https://img.shields.io/github/forks/TheMalwareGuardian/CVE-2021-27289.svg)


## CVE-2020-1054
 An elevation of privilege vulnerability exists in Windows when the Windows kernel-mode driver fails to properly handle objects in memory, aka 'Win32k Elevation of Privilege Vulnerability'. This CVE ID is unique from CVE-2020-1143.

- [https://github.com/Naman2701B/CVE-2020-1054](https://github.com/Naman2701B/CVE-2020-1054) :  ![starts](https://img.shields.io/github/stars/Naman2701B/CVE-2020-1054.svg) ![forks](https://img.shields.io/github/forks/Naman2701B/CVE-2020-1054.svg)


## CVE-2019-9053
 An issue was discovered in CMS Made Simple 2.2.8. It is possible with the News module, through a crafted URL, to achieve unauthenticated blind time-based SQL injection via the m1_idlist parameter.

- [https://github.com/kaizoku73/CVE-2019-9053](https://github.com/kaizoku73/CVE-2019-9053) :  ![starts](https://img.shields.io/github/stars/kaizoku73/CVE-2019-9053.svg) ![forks](https://img.shields.io/github/forks/kaizoku73/CVE-2019-9053.svg)
- [https://github.com/Hackheart-tech/-exploit-lab](https://github.com/Hackheart-tech/-exploit-lab) :  ![starts](https://img.shields.io/github/stars/Hackheart-tech/-exploit-lab.svg) ![forks](https://img.shields.io/github/forks/Hackheart-tech/-exploit-lab.svg)


## CVE-2019-5029
 An exploitable command injection vulnerability exists in the Config editor of the Exhibitor Web UI versions 1.0.9 to 1.7.1. Arbitrary shell commands surrounded by backticks or $() can be inserted into the editor and will be executed by the Exhibitor process when it launches ZooKeeper. An attacker can execute any command as the user running the Exhibitor process.

- [https://github.com/yZeetje/CVE-2019-5029](https://github.com/yZeetje/CVE-2019-5029) :  ![starts](https://img.shields.io/github/stars/yZeetje/CVE-2019-5029.svg) ![forks](https://img.shields.io/github/forks/yZeetje/CVE-2019-5029.svg)


## CVE-2015-6420
 Serialized-object interfaces in certain Cisco Collaboration and Social Media; Endpoint Clients and Client Software; Network Application, Service, and Acceleration; Network and Content Security Devices; Network Management and Provisioning; Routing and Switching - Enterprise and Service Provider; Unified Computing; Voice and Unified Communications Devices; Video, Streaming, TelePresence, and Transcoding Devices; Wireless; and Cisco Hosted Services products allow remote attackers to execute arbitrary commands via a crafted serialized Java object, related to the Apache Commons Collections (ACC) library.

- [https://github.com/Leeziao/CVE-2015-6420](https://github.com/Leeziao/CVE-2015-6420) :  ![starts](https://img.shields.io/github/stars/Leeziao/CVE-2015-6420.svg) ![forks](https://img.shields.io/github/forks/Leeziao/CVE-2015-6420.svg)


## CVE-2014-1266
 The SSLVerifySignedServerKeyExchange function in libsecurity_ssl/lib/sslKeyExchange.c in the Secure Transport feature in the Data Security component in Apple iOS 6.x before 6.1.6 and 7.x before 7.0.6, Apple TV 6.x before 6.0.2, and Apple OS X 10.9.x before 10.9.2 does not check the signature in a TLS Server Key Exchange message, which allows man-in-the-middle attackers to spoof SSL servers by (1) using an arbitrary private key for the signing step or (2) omitting the signing step.

- [https://github.com/macressler/SSLPatch](https://github.com/macressler/SSLPatch) :  ![starts](https://img.shields.io/github/stars/macressler/SSLPatch.svg) ![forks](https://img.shields.io/github/forks/macressler/SSLPatch.svg)

