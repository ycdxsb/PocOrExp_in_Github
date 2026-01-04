# Update 2026-01-04
## CVE-2026-21436
 eopkg is a Solus package manager implemented in python3. In versions prior to 4.4.0, a malicious package could escape the directory set by `--destdir`. This requires the installation of a package from a malicious or compromised source. Files in such packages would not be installed in the path given by `--destdir`, but on a different location on the host. The issue has been fixed in v4.4.0. Users only installing packages from the Solus repositories are not affected.

- [https://github.com/osmancanvural/CVE-2026-21436](https://github.com/osmancanvural/CVE-2026-21436) :  ![starts](https://img.shields.io/github/stars/osmancanvural/CVE-2026-21436.svg) ![forks](https://img.shields.io/github/forks/osmancanvural/CVE-2026-21436.svg)


## CVE-2026-0547
 A vulnerability was found in PHPGurukul Online Course Registration up to 3.1. This issue affects some unknown processing of the file /admin/edit-student-profile.php of the component Student Registration Page. The manipulation of the argument photo results in unrestricted upload. The attack may be launched remotely. The exploit has been made public and could be used.

- [https://github.com/rsecroot/CVE-2026-0547](https://github.com/rsecroot/CVE-2026-0547) :  ![starts](https://img.shields.io/github/stars/rsecroot/CVE-2026-0547.svg) ![forks](https://img.shields.io/github/forks/rsecroot/CVE-2026-0547.svg)


## CVE-2025-68613
 n8n is an open source workflow automation platform. Versions starting with 0.211.0 and prior to 1.120.4, 1.121.1, and 1.122.0 contain a critical Remote Code Execution (RCE) vulnerability in their workflow expression evaluation system. Under certain conditions, expressions supplied by authenticated users during workflow configuration may be evaluated in an execution context that is not sufficiently isolated from the underlying runtime. An authenticated attacker could abuse this behavior to execute arbitrary code with the privileges of the n8n process. Successful exploitation may lead to full compromise of the affected instance, including unauthorized access to sensitive data, modification of workflows, and execution of system-level operations. This issue has been fixed in versions 1.120.4, 1.121.1, and 1.122.0. Users are strongly advised to upgrade to a patched version, which introduces additional safeguards to restrict expression evaluation. If upgrading is not immediately possible, administrators should consider the following temporary mitigations: Limit workflow creation and editing permissions to fully trusted users only; and/or deploy n8n in a hardened environment with restricted operating system privileges and network access to reduce the impact of potential exploitation. These workarounds do not fully eliminate the risk and should only be used as short-term measures.

- [https://github.com/ahmedshamsddin/n8n-RCE-CVE-2025-68613](https://github.com/ahmedshamsddin/n8n-RCE-CVE-2025-68613) :  ![starts](https://img.shields.io/github/stars/ahmedshamsddin/n8n-RCE-CVE-2025-68613.svg) ![forks](https://img.shields.io/github/forks/ahmedshamsddin/n8n-RCE-CVE-2025-68613.svg)


## CVE-2025-67160
 An issue in Vatilon v1.12.37-20240124 allows attackers to access sensitive directories and files via a directory traversal.

- [https://github.com/Remenis/CVE-2025-67160](https://github.com/Remenis/CVE-2025-67160) :  ![starts](https://img.shields.io/github/stars/Remenis/CVE-2025-67160.svg) ![forks](https://img.shields.io/github/forks/Remenis/CVE-2025-67160.svg)


## CVE-2025-67159
 Vatilon v1.12.37-20240124 was discovered to transmit user credentials in plaintext.

- [https://github.com/Remenis/CVE-2025-67159](https://github.com/Remenis/CVE-2025-67159) :  ![starts](https://img.shields.io/github/stars/Remenis/CVE-2025-67159.svg) ![forks](https://img.shields.io/github/forks/Remenis/CVE-2025-67159.svg)


## CVE-2025-67158
 An authentication bypass in the /cgi-bin/jvsweb.cgi endpoint of Revotech I6032W-FHW v1.0.0014 - 20210517 allows attackers to access sensitive information and escalate privileges via a crafted HTTP request.

- [https://github.com/Remenis/CVE-2025-67158](https://github.com/Remenis/CVE-2025-67158) :  ![starts](https://img.shields.io/github/stars/Remenis/CVE-2025-67158.svg) ![forks](https://img.shields.io/github/forks/Remenis/CVE-2025-67158.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo.svg)


## CVE-2025-61922
 PrestaShop Checkout is the PrestaShop official payment module in partnership with PayPal. Starting in version 1.3.0 and prior to versions 4.4.1 and 5.0.5, missing validation on the Express Checkout feature allows silent login, enabling account takeover via email. The vulnerability is fixed in versions 4.4.1 and 5.0.5. No known workarounds exist.

- [https://github.com/g0vguy/CVE-2025-61922-PoC](https://github.com/g0vguy/CVE-2025-61922-PoC) :  ![starts](https://img.shields.io/github/stars/g0vguy/CVE-2025-61922-PoC.svg) ![forks](https://img.shields.io/github/forks/g0vguy/CVE-2025-61922-PoC.svg)


## CVE-2025-59287
 Deserialization of untrusted data in Windows Server Update Service allows an unauthorized attacker to execute code over a network.

- [https://github.com/vtntkmfyyftrem/CVE-2025-59287](https://github.com/vtntkmfyyftrem/CVE-2025-59287) :  ![starts](https://img.shields.io/github/stars/vtntkmfyyftrem/CVE-2025-59287.svg) ![forks](https://img.shields.io/github/forks/vtntkmfyyftrem/CVE-2025-59287.svg)


## CVE-2025-55184
 A pre-authentication denial of service vulnerability exists in React Server Components versions 19.0.0, 19.0.1 19.1.0, 19.1.1, 19.1.2, 19.2.0 and 19.2.1, including the following packages: react-server-dom-parcel, react-server-dom-turbopack, and react-server-dom-webpack. The vulnerable code unsafely deserializes payloads from HTTP requests to Server Function endpoints, which can cause an infinite loop that hangs the server process and may prevent future HTTP requests from being served.

- [https://github.com/yogeshkumar09/CVE-2025-55184_Testing](https://github.com/yogeshkumar09/CVE-2025-55184_Testing) :  ![starts](https://img.shields.io/github/stars/yogeshkumar09/CVE-2025-55184_Testing.svg) ![forks](https://img.shields.io/github/forks/yogeshkumar09/CVE-2025-55184_Testing.svg)
- [https://github.com/yogeshkumar09/yogeshkumar09.github.io](https://github.com/yogeshkumar09/yogeshkumar09.github.io) :  ![starts](https://img.shields.io/github/stars/yogeshkumar09/yogeshkumar09.github.io.svg) ![forks](https://img.shields.io/github/forks/yogeshkumar09/yogeshkumar09.github.io.svg)


## CVE-2025-55182
 A pre-authentication remote code execution vulnerability exists in React Server Components versions 19.0.0, 19.1.0, 19.1.1, and 19.2.0 including the following packages: react-server-dom-parcel, react-server-dom-turbopack, and react-server-dom-webpack. The vulnerable code unsafely deserializes payloads from HTTP requests to Server Function endpoints.

- [https://github.com/sudo-Yangziran/CVE-2025-55182POC](https://github.com/sudo-Yangziran/CVE-2025-55182POC) :  ![starts](https://img.shields.io/github/stars/sudo-Yangziran/CVE-2025-55182POC.svg) ![forks](https://img.shields.io/github/forks/sudo-Yangziran/CVE-2025-55182POC.svg)


## CVE-2025-43529
 A use-after-free issue was addressed with improved memory management. This issue is fixed in watchOS 26.2, Safari 26.2, iOS 18.7.3 and iPadOS 18.7.3, iOS 26.2 and iPadOS 26.2, macOS Tahoe 26.2, visionOS 26.2, tvOS 26.2. Processing maliciously crafted web content may lead to arbitrary code execution. Apple is aware of a report that this issue may have been exploited in an extremely sophisticated attack against specific targeted individuals on versions of iOS before iOS 26. CVE-2025-14174 was also issued in response to this report.

- [https://github.com/zeroxjf/CVE-2025-43529-analysis](https://github.com/zeroxjf/CVE-2025-43529-analysis) :  ![starts](https://img.shields.io/github/stars/zeroxjf/CVE-2025-43529-analysis.svg) ![forks](https://img.shields.io/github/forks/zeroxjf/CVE-2025-43529-analysis.svg)


## CVE-2025-34462
 This CVE ID was rejected because it was reserved but not used for a vulnerability disclosure.

- [https://github.com/NSM-Barii/CVE-2025-34462](https://github.com/NSM-Barii/CVE-2025-34462) :  ![starts](https://img.shields.io/github/stars/NSM-Barii/CVE-2025-34462.svg) ![forks](https://img.shields.io/github/forks/NSM-Barii/CVE-2025-34462.svg)


## CVE-2025-27591
 A privilege escalation vulnerability existed in the Below service prior to v0.9.0 due to the creation of a world-writable directory at /var/log/below. This could have allowed local unprivileged users to escalate to root privileges through symlink attacks that manipulate files such as /etc/shadow.

- [https://github.com/Stp1t/CVE-2025-27591](https://github.com/Stp1t/CVE-2025-27591) :  ![starts](https://img.shields.io/github/stars/Stp1t/CVE-2025-27591.svg) ![forks](https://img.shields.io/github/forks/Stp1t/CVE-2025-27591.svg)


## CVE-2025-14847
 Mismatched length fields in Zlib compressed protocol headers may allow a read of uninitialized heap memory by an unauthenticated client. This issue affects all MongoDB Server v7.0 prior to 7.0.28 versions, MongoDB Server v8.0 versions prior to 8.0.17, MongoDB Server v8.2 versions prior to 8.2.3, MongoDB Server v6.0 versions prior to 6.0.27, MongoDB Server v5.0 versions prior to 5.0.32, MongoDB Server v4.4 versions prior to 4.4.30, MongoDB Server v4.2 versions greater than or equal to 4.2.0, MongoDB Server v4.0 versions greater than or equal to 4.0.0, and MongoDB Server v3.6 versions greater than or equal to 3.6.0.

- [https://github.com/demetriusford/mongobleed](https://github.com/demetriusford/mongobleed) :  ![starts](https://img.shields.io/github/stars/demetriusford/mongobleed.svg) ![forks](https://img.shields.io/github/forks/demetriusford/mongobleed.svg)
- [https://github.com/ElJoamy/MongoBleed-exploit](https://github.com/ElJoamy/MongoBleed-exploit) :  ![starts](https://img.shields.io/github/stars/ElJoamy/MongoBleed-exploit.svg) ![forks](https://img.shields.io/github/forks/ElJoamy/MongoBleed-exploit.svg)


## CVE-2025-14174
 Out of bounds memory access in ANGLE in Google Chrome on Mac prior to 143.0.7499.110 allowed a remote attacker to perform out of bounds memory access via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/zeroxjf/CVE-2025-14174-analysis](https://github.com/zeroxjf/CVE-2025-14174-analysis) :  ![starts](https://img.shields.io/github/stars/zeroxjf/CVE-2025-14174-analysis.svg) ![forks](https://img.shields.io/github/forks/zeroxjf/CVE-2025-14174-analysis.svg)


## CVE-2025-8088
     from ESET.

- [https://github.com/vitalichkaa/CVE-2025-8088](https://github.com/vitalichkaa/CVE-2025-8088) :  ![starts](https://img.shields.io/github/stars/vitalichkaa/CVE-2025-8088.svg) ![forks](https://img.shields.io/github/forks/vitalichkaa/CVE-2025-8088.svg)


## CVE-2025-6731
 A vulnerability was found in yzcheng90 X-SpringBoot up to 5.0 and classified as critical. Affected by this issue is the function uploadApk of the file /sys/oss/upload/apk of the component APK File Handler. The manipulation of the argument File leads to path traversal. The attack may be launched remotely. The exploit has been disclosed to the public and may be used. The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/r-pradyun/CVE-2025-67315](https://github.com/r-pradyun/CVE-2025-67315) :  ![starts](https://img.shields.io/github/stars/r-pradyun/CVE-2025-67315.svg) ![forks](https://img.shields.io/github/forks/r-pradyun/CVE-2025-67315.svg)


## CVE-2024-55374
 REDCap 14.3.13 allows an attacker to enumerate usernames due to an observable discrepancy between login attempts.

- [https://github.com/T3slaa/CVE-2024-55374](https://github.com/T3slaa/CVE-2024-55374) :  ![starts](https://img.shields.io/github/stars/T3slaa/CVE-2024-55374.svg) ![forks](https://img.shields.io/github/forks/T3slaa/CVE-2024-55374.svg)


## CVE-2024-53677
You can find more details in  https://cwiki.apache.org/confluence/display/WW/S2-067

- [https://github.com/MartinxMax/CVE-2024-53677](https://github.com/MartinxMax/CVE-2024-53677) :  ![starts](https://img.shields.io/github/stars/MartinxMax/CVE-2024-53677.svg) ![forks](https://img.shields.io/github/forks/MartinxMax/CVE-2024-53677.svg)


## CVE-2024-36401
Versions 2.22.6, 2.23.6, 2.24.4, and 2.25.2 contain a patch for the issue. A workaround exists by removing the `gt-complex-x.y.jar` file from the GeoServer where `x.y` is the GeoTools version (e.g., `gt-complex-31.1.jar` if running GeoServer 2.25.1). This will remove the vulnerable code from GeoServer but may break some GeoServer functionality or prevent GeoServer from deploying if the gt-complex module is needed.

- [https://github.com/reveravip/Exploit-CVE-2024-36401](https://github.com/reveravip/Exploit-CVE-2024-36401) :  ![starts](https://img.shields.io/github/stars/reveravip/Exploit-CVE-2024-36401.svg) ![forks](https://img.shields.io/github/forks/reveravip/Exploit-CVE-2024-36401.svg)


## CVE-2023-49785
 NextChat, also known as ChatGPT-Next-Web, is a cross-platform chat user interface for use with ChatGPT. Versions 2.11.2 and prior are vulnerable to server-side request forgery and cross-site scripting. This vulnerability enables read access to internal HTTP endpoints but also write access using HTTP POST, PUT, and other methods. Attackers can also use this vulnerability to mask their source IP by forwarding malicious traffic intended for other Internet targets through these open proxies. As of time of publication, no patch is available, but other mitigation strategies are available. Users may avoid exposing the application to the public internet or, if exposing the application to the internet, ensure it is an isolated network with no access to any other internal resources.

- [https://github.com/hyunnna/NextChat_SSRF_CVE-2023-49785](https://github.com/hyunnna/NextChat_SSRF_CVE-2023-49785) :  ![starts](https://img.shields.io/github/stars/hyunnna/NextChat_SSRF_CVE-2023-49785.svg) ![forks](https://img.shields.io/github/forks/hyunnna/NextChat_SSRF_CVE-2023-49785.svg)


## CVE-2023-46604
which fixes this issue.

- [https://github.com/fiza-naeem0902/Vulnerability-Assessment](https://github.com/fiza-naeem0902/Vulnerability-Assessment) :  ![starts](https://img.shields.io/github/stars/fiza-naeem0902/Vulnerability-Assessment.svg) ![forks](https://img.shields.io/github/forks/fiza-naeem0902/Vulnerability-Assessment.svg)


## CVE-2022-41099
 BitLocker Security Feature Bypass Vulnerability

- [https://github.com/tylermontneyacc/UpdateWindowsRE-CVE-2022-41099](https://github.com/tylermontneyacc/UpdateWindowsRE-CVE-2022-41099) :  ![starts](https://img.shields.io/github/stars/tylermontneyacc/UpdateWindowsRE-CVE-2022-41099.svg) ![forks](https://img.shields.io/github/forks/tylermontneyacc/UpdateWindowsRE-CVE-2022-41099.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/puckiestyle/CVE-2021-41773](https://github.com/puckiestyle/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/puckiestyle/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/puckiestyle/CVE-2021-41773.svg)
- [https://github.com/JIYUN02/cve-2021-41773](https://github.com/JIYUN02/cve-2021-41773) :  ![starts](https://img.shields.io/github/stars/JIYUN02/cve-2021-41773.svg) ![forks](https://img.shields.io/github/forks/JIYUN02/cve-2021-41773.svg)
- [https://github.com/Taldrid1/cve-2021-41773](https://github.com/Taldrid1/cve-2021-41773) :  ![starts](https://img.shields.io/github/stars/Taldrid1/cve-2021-41773.svg) ![forks](https://img.shields.io/github/forks/Taldrid1/cve-2021-41773.svg)


## CVE-2018-15832
 upc.exe in Ubisoft Uplay Desktop Client versions 63.0.5699.0 allows remote attackers to execute arbitrary code. User interaction is required to exploit this vulnerability in that the target must visit a malicious page or open a malicious file. The specific flaw exists within the processing of URI handlers. The issue results from the lack of proper validation of a user-supplied string before using it to execute a system call. An attacker can leverage this vulnerability to execute code under the context of the current process.

- [https://github.com/anon135792408/Ubisoft-Uplay-Desktop-Client-63.0.5699.0](https://github.com/anon135792408/Ubisoft-Uplay-Desktop-Client-63.0.5699.0) :  ![starts](https://img.shields.io/github/stars/anon135792408/Ubisoft-Uplay-Desktop-Client-63.0.5699.0.svg) ![forks](https://img.shields.io/github/forks/anon135792408/Ubisoft-Uplay-Desktop-Client-63.0.5699.0.svg)

