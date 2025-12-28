# Update 2025-12-28
## CVE-2025-68613
 n8n is an open source workflow automation platform. Versions starting with 0.211.0 and prior to 1.120.4, 1.121.1, and 1.122.0 contain a critical Remote Code Execution (RCE) vulnerability in their workflow expression evaluation system. Under certain conditions, expressions supplied by authenticated users during workflow configuration may be evaluated in an execution context that is not sufficiently isolated from the underlying runtime. An authenticated attacker could abuse this behavior to execute arbitrary code with the privileges of the n8n process. Successful exploitation may lead to full compromise of the affected instance, including unauthorized access to sensitive data, modification of workflows, and execution of system-level operations. This issue has been fixed in versions 1.120.4, 1.121.1, and 1.122.0. Users are strongly advised to upgrade to a patched version, which introduces additional safeguards to restrict expression evaluation. If upgrading is not immediately possible, administrators should consider the following temporary mitigations: Limit workflow creation and editing permissions to fully trusted users only; and/or deploy n8n in a hardened environment with restricted operating system privileges and network access to reduce the impact of potential exploitation. These workarounds do not fully eliminate the risk and should only be used as short-term measures.

- [https://github.com/LingerANR/n8n-CVE-2025-68613](https://github.com/LingerANR/n8n-CVE-2025-68613) :  ![starts](https://img.shields.io/github/stars/LingerANR/n8n-CVE-2025-68613.svg) ![forks](https://img.shields.io/github/forks/LingerANR/n8n-CVE-2025-68613.svg)
- [https://github.com/releaseown/Analysis-n8n-CVE-2025-68613](https://github.com/releaseown/Analysis-n8n-CVE-2025-68613) :  ![starts](https://img.shields.io/github/stars/releaseown/Analysis-n8n-CVE-2025-68613.svg) ![forks](https://img.shields.io/github/forks/releaseown/Analysis-n8n-CVE-2025-68613.svg)
- [https://github.com/Dlanang/homelab-CVE-2025-68613](https://github.com/Dlanang/homelab-CVE-2025-68613) :  ![starts](https://img.shields.io/github/stars/Dlanang/homelab-CVE-2025-68613.svg) ![forks](https://img.shields.io/github/forks/Dlanang/homelab-CVE-2025-68613.svg)
- [https://github.com/Khin-96/n8n-cve-2025-68613-thm](https://github.com/Khin-96/n8n-cve-2025-68613-thm) :  ![starts](https://img.shields.io/github/stars/Khin-96/n8n-cve-2025-68613-thm.svg) ![forks](https://img.shields.io/github/forks/Khin-96/n8n-cve-2025-68613-thm.svg)
- [https://github.com/Ak-cybe/CVE-2025-68613-n8n-rce-analysis](https://github.com/Ak-cybe/CVE-2025-68613-n8n-rce-analysis) :  ![starts](https://img.shields.io/github/stars/Ak-cybe/CVE-2025-68613-n8n-rce-analysis.svg) ![forks](https://img.shields.io/github/forks/Ak-cybe/CVE-2025-68613-n8n-rce-analysis.svg)
- [https://github.com/J4ck3LSyN-Gen2/n8n-CVE-2025-68613-TryHackMe](https://github.com/J4ck3LSyN-Gen2/n8n-CVE-2025-68613-TryHackMe) :  ![starts](https://img.shields.io/github/stars/J4ck3LSyN-Gen2/n8n-CVE-2025-68613-TryHackMe.svg) ![forks](https://img.shields.io/github/forks/J4ck3LSyN-Gen2/n8n-CVE-2025-68613-TryHackMe.svg)


## CVE-2025-66947
 SQL injection vulnerability in krishanmuraiji SMS v.1.0, within the /studentms/admin/edit-class-detail.php via the editid GET parameter. An attacker can trigger controlled delays using SQL SLEEP() to infer database contents. Successful exploitation may lead to full database compromise, especially within an administrative module.

- [https://github.com/kabir0104k/CVE-2025-66947](https://github.com/kabir0104k/CVE-2025-66947) :  ![starts](https://img.shields.io/github/stars/kabir0104k/CVE-2025-66947.svg) ![forks](https://img.shields.io/github/forks/kabir0104k/CVE-2025-66947.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/RavinduRathnayaka/CVE-2025-55182-PoC](https://github.com/RavinduRathnayaka/CVE-2025-55182-PoC) :  ![starts](https://img.shields.io/github/stars/RavinduRathnayaka/CVE-2025-55182-PoC.svg) ![forks](https://img.shields.io/github/forks/RavinduRathnayaka/CVE-2025-55182-PoC.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-range](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-range) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-range.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-range.svg)


## CVE-2025-59287
 Deserialization of untrusted data in Windows Server Update Service allows an unauthorized attacker to execute code over a network.

- [https://github.com/gud425/gud425.github.io](https://github.com/gud425/gud425.github.io) :  ![starts](https://img.shields.io/github/stars/gud425/gud425.github.io.svg) ![forks](https://img.shields.io/github/forks/gud425/gud425.github.io.svg)


## CVE-2025-55182
 A pre-authentication remote code execution vulnerability exists in React Server Components versions 19.0.0, 19.1.0, 19.1.1, and 19.2.0 including the following packages: react-server-dom-parcel, react-server-dom-turbopack, and react-server-dom-webpack. The vulnerable code unsafely deserializes payloads from HTTP requests to Server Function endpoints.

- [https://github.com/Syrins/CVE-2025-55182-React2Shell-RCE](https://github.com/Syrins/CVE-2025-55182-React2Shell-RCE) :  ![starts](https://img.shields.io/github/stars/Syrins/CVE-2025-55182-React2Shell-RCE.svg) ![forks](https://img.shields.io/github/forks/Syrins/CVE-2025-55182-React2Shell-RCE.svg)
- [https://github.com/BlackTechX011/React2Shell](https://github.com/BlackTechX011/React2Shell) :  ![starts](https://img.shields.io/github/stars/BlackTechX011/React2Shell.svg) ![forks](https://img.shields.io/github/forks/BlackTechX011/React2Shell.svg)


## CVE-2025-50505
 Clash Verge Rev thru 2.2.3 forces the installation of system services(clash-verge-service) by default and exposes key functions through the unauthorized HTTP API `/start_clash`, allowing local users to submit arbitrary bin_path parameters and pass them directly to the service process for execution, resulting in local privilege escalation.

- [https://github.com/aljoharasubaie/CVE-2025-505050](https://github.com/aljoharasubaie/CVE-2025-505050) :  ![starts](https://img.shields.io/github/stars/aljoharasubaie/CVE-2025-505050.svg) ![forks](https://img.shields.io/github/forks/aljoharasubaie/CVE-2025-505050.svg)


## CVE-2025-14847
 Mismatched length fields in Zlib compressed protocol headers may allow a read of uninitialized heap memory by an unauthenticated client. This issue affects all MongoDB Server v7.0 prior to 7.0.28 versions, MongoDB Server v8.0 versions prior to 8.0.17, MongoDB Server v8.2 versions prior to 8.2.3, MongoDB Server v6.0 versions prior to 6.0.27, MongoDB Server v5.0 versions prior to 5.0.32, MongoDB Server v4.4 versions prior to 4.4.30, MongoDB Server v4.2 versions greater than or equal to 4.2.0, MongoDB Server v4.0 versions greater than or equal to 4.0.0, and MongoDB Server v3.6 versions greater than or equal to 3.6.0.

- [https://github.com/ProbiusOfficial/CVE-2025-14847](https://github.com/ProbiusOfficial/CVE-2025-14847) :  ![starts](https://img.shields.io/github/stars/ProbiusOfficial/CVE-2025-14847.svg) ![forks](https://img.shields.io/github/forks/ProbiusOfficial/CVE-2025-14847.svg)
- [https://github.com/onewinner/CVE-2025-14847](https://github.com/onewinner/CVE-2025-14847) :  ![starts](https://img.shields.io/github/stars/onewinner/CVE-2025-14847.svg) ![forks](https://img.shields.io/github/forks/onewinner/CVE-2025-14847.svg)


## CVE-2025-9074
This can lead to execution of a wide range of privileged commands to the engine API, including controlling other containers, creating new ones, managing images etc. In some circumstances (e.g. Docker Desktop for Windows with WSL backend) it also allows mounting the host drive with the same privileges as the user running Docker Desktop.

- [https://github.com/Shaoshi17/CVE-2025-9074-Docker-Exploit](https://github.com/Shaoshi17/CVE-2025-9074-Docker-Exploit) :  ![starts](https://img.shields.io/github/stars/Shaoshi17/CVE-2025-9074-Docker-Exploit.svg) ![forks](https://img.shields.io/github/forks/Shaoshi17/CVE-2025-9074-Docker-Exploit.svg)


## CVE-2025-5432
 A vulnerability has been found in AssamLook CMS 1.0 and classified as critical. Affected by this vulnerability is an unknown functionality of the file /view_tender.php. The manipulation of the argument ID leads to sql injection. The attack can be launched remotely. The exploit has been disclosed to the public and may be used. The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/Sachinart/CVE-2025-54322](https://github.com/Sachinart/CVE-2025-54322) :  ![starts](https://img.shields.io/github/stars/Sachinart/CVE-2025-54322.svg) ![forks](https://img.shields.io/github/forks/Sachinart/CVE-2025-54322.svg)


## CVE-2024-3553
 The Tutor LMS – eLearning and online course solution plugin for WordPress is vulnerable to unauthorized modification of data due to a missing capability check on the hide_notices function in all versions up to, and including, 2.6.2. This makes it possible for unauthenticated attackers to enable user registration on sites that may have it disabled.

- [https://github.com/RandomRobbieBF/CVE-2024-3553](https://github.com/RandomRobbieBF/CVE-2024-3553) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-3553.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-3553.svg)


## CVE-2018-9995
 TBK DVR4104 and DVR4216 devices, as well as Novo, CeNova, QSee, Pulnix, XVR 5 in 1, Securus, Night OWL, DVR Login, HVR Login, and MDVR Login, which run re-branded versions of the original TBK DVR4104 and DVR4216 series, allow remote attackers to bypass authentication via a "Cookie: uid=admin" header, as demonstrated by a device.rsp?opt=user&cmd=list request that provides credentials within JSON data in a response.

- [https://github.com/mesutozsoycom/cve-2018-9995](https://github.com/mesutozsoycom/cve-2018-9995) :  ![starts](https://img.shields.io/github/stars/mesutozsoycom/cve-2018-9995.svg) ![forks](https://img.shields.io/github/forks/mesutozsoycom/cve-2018-9995.svg)


## CVE-2018-9206
 Unauthenticated arbitrary file upload vulnerability in Blueimp jQuery-File-Upload = v9.22.0

- [https://github.com/flame-11/CVE-2018-9206-jquery-file-upload](https://github.com/flame-11/CVE-2018-9206-jquery-file-upload) :  ![starts](https://img.shields.io/github/stars/flame-11/CVE-2018-9206-jquery-file-upload.svg) ![forks](https://img.shields.io/github/forks/flame-11/CVE-2018-9206-jquery-file-upload.svg)

