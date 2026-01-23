# Update 2026-01-23
## CVE-2026-23947
 Orval generates type-safe JS clients (TypeScript) from any valid OpenAPI v3 or Swagger v2 specification. Versions prior to 7.19.0 until 8.0.2 are vulnerable to arbitrary code execution in environments consuming generated clients. This issue is similar in nature to CVE-2026-22785, but affects a different code path in @orval/core that was not addressed by CVE-2026-22785's fix. The vulnerability allows untrusted OpenAPI specifications to inject arbitrary TypeScript/JavaScript code into generated clients via the x-enumDescriptions field, which is embedded without proper escaping in getEnumImplementation(). I have confirmed that the injection occurs during const enum generation and results in executable code within the generated schema files. Orval 7.19.0 and 8.0.2 contain a fix for the issue.

- [https://github.com/boroeurnprach/CVE-2026-23947-PoC](https://github.com/boroeurnprach/CVE-2026-23947-PoC) :  ![starts](https://img.shields.io/github/stars/boroeurnprach/CVE-2026-23947-PoC.svg) ![forks](https://img.shields.io/github/forks/boroeurnprach/CVE-2026-23947-PoC.svg)


## CVE-2026-22844
 A Command Injection vulnerability in Zoom Node Multimedia Routers (MMRs) before version 5.2.1716.0 may allow a meeting participant to conduct remote code execution of the MMR via network access.

- [https://github.com/Ashwesker/Ashwesker-CVE-2026-22844](https://github.com/Ashwesker/Ashwesker-CVE-2026-22844) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2026-22844.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2026-22844.svg)


## CVE-2026-21962
 Vulnerability in the Oracle HTTP Server, Oracle Weblogic Server Proxy Plug-in product of Oracle Fusion Middleware (component: Weblogic Server Proxy Plug-in for Apache HTTP Server, Weblogic Server Proxy Plug-in for IIS).  Supported versions that are affected are 12.2.1.4.0, 14.1.1.0.0 and  14.1.2.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle HTTP Server, Oracle Weblogic Server Proxy Plug-in.  While the vulnerability is in Oracle HTTP Server, Oracle Weblogic Server Proxy Plug-in, attacks may significantly impact additional products (scope change).  Successful attacks of this vulnerability can result in  unauthorized creation, deletion or modification access to critical data or all Oracle HTTP Server, Oracle Weblogic Server Proxy Plug-in accessible data as well as  unauthorized access to critical data or complete access to all Oracle HTTP Server, Oracle Weblogic Server Proxy Plug-in accessible data. Note: Affected version for Weblogic Server Proxy Plug-in for IIS is 12.2.1.4.0 only. CVSS 3.1 Base Score 10.0 (Confidentiality and Integrity impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N).

- [https://github.com/Ashwesker/Ashwesker-CVE-2026-21962](https://github.com/Ashwesker/Ashwesker-CVE-2026-21962) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2026-21962.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2026-21962.svg)


## CVE-2026-21858
 n8n is an open source workflow automation platform. Versions starting with 1.65.0 and below 1.121.0 enable an attacker to access files on the underlying server through execution of certain form-based workflows. A vulnerable workflow could grant access to an unauthenticated remote attacker, resulting in exposure of sensitive information stored on the system and may enable further compromise depending on deployment configuration and workflow usage. This issue is fixed in version 1.121.0.

- [https://github.com/MOGMUNI/CVE-2026-21858](https://github.com/MOGMUNI/CVE-2026-21858) :  ![starts](https://img.shields.io/github/stars/MOGMUNI/CVE-2026-21858.svg) ![forks](https://img.shields.io/github/forks/MOGMUNI/CVE-2026-21858.svg)
- [https://github.com/MOGMUNI/mogmuni.github.io](https://github.com/MOGMUNI/mogmuni.github.io) :  ![starts](https://img.shields.io/github/stars/MOGMUNI/mogmuni.github.io.svg) ![forks](https://img.shields.io/github/forks/MOGMUNI/mogmuni.github.io.svg)


## CVE-2026-0834
V1_251215

- [https://github.com/mattgsys/CVE-2026-0834](https://github.com/mattgsys/CVE-2026-0834) :  ![starts](https://img.shields.io/github/stars/mattgsys/CVE-2026-0834.svg) ![forks](https://img.shields.io/github/forks/mattgsys/CVE-2026-0834.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-14x](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-14x) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-14x.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-14x.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-git-dep](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-git-dep) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-git-dep.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-git-dep.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-berry](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-berry) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-berry.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-berry.svg)


## CVE-2025-61686
 React Router is a router for React. In @react-router/node versions 7.0.0 through 7.9.3, @remix-run/deno prior to version 2.17.2, and @remix-run/node prior to version 2.17.2, if createFileSessionStorage() is being used from @react-router/node (or @remix-run/node/@remix-run/deno in Remix v2) with an unsigned cookie, it is possible for an attacker to cause the session to try to read/write from a location outside the specified session file directory. The success of the attack would depend on the permissions of the web server process to access those files. Read files cannot be returned directly to the attacker. Session file reads would only succeed if the file matched the expected session file format. If the file matched the session file format, the data would be populated into the server side session but not directly returned to the attacker unless the application logic returned specific session information. This issue has been patched in @react-router/node version 7.9.4, @remix-run/deno version 2.17.2, and @remix-run/node version 2.17.2.

- [https://github.com/boroeurnprach/CVE-2025-61686-PoC](https://github.com/boroeurnprach/CVE-2025-61686-PoC) :  ![starts](https://img.shields.io/github/stars/boroeurnprach/CVE-2025-61686-PoC.svg) ![forks](https://img.shields.io/github/forks/boroeurnprach/CVE-2025-61686-PoC.svg)


## CVE-2025-60021
2. Apply this patch ( https://github.com/apache/brpc/pull/3101 ) manually.

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-60021](https://github.com/Ashwesker/Ashwesker-CVE-2025-60021) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-60021.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-60021.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/maronnjapan/claude-create-CVE-2025-29927](https://github.com/maronnjapan/claude-create-CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/maronnjapan/claude-create-CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/maronnjapan/claude-create-CVE-2025-29927.svg)


## CVE-2025-14847
 Mismatched length fields in Zlib compressed protocol headers may allow a read of uninitialized heap memory by an unauthenticated client. This issue affects all MongoDB Server v7.0 prior to 7.0.28 versions, MongoDB Server v8.0 versions prior to 8.0.17, MongoDB Server v8.2 versions prior to 8.2.3, MongoDB Server v6.0 versions prior to 6.0.27, MongoDB Server v5.0 versions prior to 5.0.32, MongoDB Server v4.4 versions prior to 4.4.30, MongoDB Server v4.2 versions greater than or equal to 4.2.0, MongoDB Server v4.0 versions greater than or equal to 4.0.0, and MongoDB Server v3.6 versions greater than or equal to 3.6.0.

- [https://github.com/InfoSecAntara/CVE-2025-14847-MongoDB](https://github.com/InfoSecAntara/CVE-2025-14847-MongoDB) :  ![starts](https://img.shields.io/github/stars/InfoSecAntara/CVE-2025-14847-MongoDB.svg) ![forks](https://img.shields.io/github/forks/InfoSecAntara/CVE-2025-14847-MongoDB.svg)


## CVE-2025-9876
 The Ird Slider plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the plugin's 'irdslider' shortcode in all versions up to, and including, 1.0.2 due to insufficient input sanitization and output escaping on user supplied attributes. This makes it possible for authenticated attackers, with contributor-level access and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.

- [https://github.com/titanmaster96/cve-2025-9876](https://github.com/titanmaster96/cve-2025-9876) :  ![starts](https://img.shields.io/github/stars/titanmaster96/cve-2025-9876.svg) ![forks](https://img.shields.io/github/forks/titanmaster96/cve-2025-9876.svg)


## CVE-2025-7771
 ThrottleStop.sys, a legitimate driver, exposes two IOCTL interfaces that allow arbitrary read and write access to physical memory via the MmMapIoSpace function. This insecure implementation can be exploited by a malicious user-mode application to patch the running Windows kernel and invoke arbitrary kernel functions with ring-0 privileges. The vulnerability enables local attackers to execute arbitrary code in kernel context, resulting in privilege escalation and potential follow-on attacks, such as disabling security software or bypassing kernel-level protections. ThrottleStop.sys version 3.0.0.0 and possibly others are affected. Apply updates per vendor instructions.

- [https://github.com/lzty/CVE-2025-7771](https://github.com/lzty/CVE-2025-7771) :  ![starts](https://img.shields.io/github/stars/lzty/CVE-2025-7771.svg) ![forks](https://img.shields.io/github/forks/lzty/CVE-2025-7771.svg)


## CVE-2025-6946
This issue affects Firebox: from 12.0 through 12.11.2.

- [https://github.com/Tagoletta/CVE-2025-69460](https://github.com/Tagoletta/CVE-2025-69460) :  ![starts](https://img.shields.io/github/stars/Tagoletta/CVE-2025-69460.svg) ![forks](https://img.shields.io/github/forks/Tagoletta/CVE-2025-69460.svg)


## CVE-2025-6945
 GitLab has remediated an issue in GitLab EE affecting all versions from 17.8 before 18.3.6, 18.4 before 18.4.4, and 18.5 before 18.5.2 that could have allowed an authenticated attacker to leak sensitive information from confidential issues by injecting hidden prompts into merge request comments.

- [https://github.com/Tagoletta/CVE-2025-69459](https://github.com/Tagoletta/CVE-2025-69459) :  ![starts](https://img.shields.io/github/stars/Tagoletta/CVE-2025-69459.svg) ![forks](https://img.shields.io/github/forks/Tagoletta/CVE-2025-69459.svg)
- [https://github.com/Tagoletta/CVE-2025-69457](https://github.com/Tagoletta/CVE-2025-69457) :  ![starts](https://img.shields.io/github/stars/Tagoletta/CVE-2025-69457.svg) ![forks](https://img.shields.io/github/forks/Tagoletta/CVE-2025-69457.svg)
- [https://github.com/Tagoletta/CVE-2025-69458](https://github.com/Tagoletta/CVE-2025-69458) :  ![starts](https://img.shields.io/github/stars/Tagoletta/CVE-2025-69458.svg) ![forks](https://img.shields.io/github/forks/Tagoletta/CVE-2025-69458.svg)


## CVE-2025-1383
 The Podlove Podcast Publisher plugin for WordPress is vulnerable to Cross-Site Request Forgery in all versions up to, and including, 4.2.2. This is due to missing or incorrect nonce validation on the ajax_transcript_delete() function. This makes it possible for unauthenticated attackers to delete arbitrary episode transcripts via a forged request granted they can trick a site administrator into performing an action such as clicking on a link.

- [https://github.com/sastraadiwiguna-purpleeliteteaming/CVE-2025-13834-A-Bluetooth-RFCOMM-Out-of-Bounds-Read-Vulnerability-in-Modern-Wireless-Devices](https://github.com/sastraadiwiguna-purpleeliteteaming/CVE-2025-13834-A-Bluetooth-RFCOMM-Out-of-Bounds-Read-Vulnerability-in-Modern-Wireless-Devices) :  ![starts](https://img.shields.io/github/stars/sastraadiwiguna-purpleeliteteaming/CVE-2025-13834-A-Bluetooth-RFCOMM-Out-of-Bounds-Read-Vulnerability-in-Modern-Wireless-Devices.svg) ![forks](https://img.shields.io/github/forks/sastraadiwiguna-purpleeliteteaming/CVE-2025-13834-A-Bluetooth-RFCOMM-Out-of-Bounds-Read-Vulnerability-in-Modern-Wireless-Devices.svg)


## CVE-2024-58290
 Xhibiter NFT Marketplace 1.10.2 contains a SQL injection vulnerability in the collections endpoint that allows attackers to manipulate database queries through the 'id' parameter. Attackers can exploit boolean-based, time-based, and UNION-based SQL injection techniques to potentially extract or manipulate database information by sending crafted payloads to the collections page.

- [https://github.com/SohelYousef/CVE-2024-58290-Xhibiter-SQLi](https://github.com/SohelYousef/CVE-2024-58290-Xhibiter-SQLi) :  ![starts](https://img.shields.io/github/stars/SohelYousef/CVE-2024-58290-Xhibiter-SQLi.svg) ![forks](https://img.shields.io/github/forks/SohelYousef/CVE-2024-58290-Xhibiter-SQLi.svg)


## CVE-2024-53704
 An Improper Authentication vulnerability in the SSLVPN authentication mechanism allows a remote attacker to bypass authentication.

- [https://github.com/sfewer-r7/SonicSessionLeak](https://github.com/sfewer-r7/SonicSessionLeak) :  ![starts](https://img.shields.io/github/stars/sfewer-r7/SonicSessionLeak.svg) ![forks](https://img.shields.io/github/forks/sfewer-r7/SonicSessionLeak.svg)


## CVE-2024-38476
Users are recommended to upgrade to version 2.4.60, which fixes this issue.

- [https://github.com/abanop22333/Apache-Authentication-Flaw-Research-CVE-2024-38476-](https://github.com/abanop22333/Apache-Authentication-Flaw-Research-CVE-2024-38476-) :  ![starts](https://img.shields.io/github/stars/abanop22333/Apache-Authentication-Flaw-Research-CVE-2024-38476-.svg) ![forks](https://img.shields.io/github/forks/abanop22333/Apache-Authentication-Flaw-Research-CVE-2024-38476-.svg)


## CVE-2024-38063
 Windows TCP/IP Remote Code Execution Vulnerability

- [https://github.com/Avidan1/CVE-2024-38063](https://github.com/Avidan1/CVE-2024-38063) :  ![starts](https://img.shields.io/github/stars/Avidan1/CVE-2024-38063.svg) ![forks](https://img.shields.io/github/forks/Avidan1/CVE-2024-38063.svg)


## CVE-2024-2370
 DO NOT USE THIS CVE ID NUMBER. Consult IDs: CVE-2018-5341. Reason: This CVE Record is a duplicate of CVE-2018-5341. Notes: All CVE users should reference CVE-2018-5341 instead of this record.

- [https://github.com/canyie/CVE-2024-23700](https://github.com/canyie/CVE-2024-23700) :  ![starts](https://img.shields.io/github/stars/canyie/CVE-2024-23700.svg) ![forks](https://img.shields.io/github/forks/canyie/CVE-2024-23700.svg)


## CVE-2023-52271
 The wsftprm.sys kernel driver 2.0.0.0 in Topaz Antifraud allows low-privileged attackers to kill any (Protected Process Light) process via an IOCTL (which will be named at a later time).

- [https://github.com/victoni/BYOVD-CVE-2023-52271-POC](https://github.com/victoni/BYOVD-CVE-2023-52271-POC) :  ![starts](https://img.shields.io/github/stars/victoni/BYOVD-CVE-2023-52271-POC.svg) ![forks](https://img.shields.io/github/forks/victoni/BYOVD-CVE-2023-52271-POC.svg)


## CVE-2023-44487
 The HTTP/2 protocol allows a denial of service (server resource consumption) because request cancellation can reset many streams quickly, as exploited in the wild in August through October 2023.

- [https://github.com/xsss9188-DADHACKS/Exploit-Title-HTTP-2-2.0---Denial-Of-Service-DOS-](https://github.com/xsss9188-DADHACKS/Exploit-Title-HTTP-2-2.0---Denial-Of-Service-DOS-) :  ![starts](https://img.shields.io/github/stars/xsss9188-DADHACKS/Exploit-Title-HTTP-2-2.0---Denial-Of-Service-DOS-.svg) ![forks](https://img.shields.io/github/forks/xsss9188-DADHACKS/Exploit-Title-HTTP-2-2.0---Denial-Of-Service-DOS-.svg)


## CVE-2023-38890
 Online Shopping Portal Project 3.1 allows remote attackers to execute arbitrary SQL commands/queries via the login form, leading to unauthorized access and potential data manipulation. This vulnerability arises due to insufficient validation of user-supplied input in the username field, enabling SQL Injection attacks.

- [https://github.com/Tagoletta/CVE-2023-38890](https://github.com/Tagoletta/CVE-2023-38890) :  ![starts](https://img.shields.io/github/stars/Tagoletta/CVE-2023-38890.svg) ![forks](https://img.shields.io/github/forks/Tagoletta/CVE-2023-38890.svg)


## CVE-2022-30190
Please see the MSRC Blog Entry for important information about steps you can take to protect your system from this vulnerability.

- [https://github.com/nimesh895/Malware-Analysis-Follina-CVE-2022-30190](https://github.com/nimesh895/Malware-Analysis-Follina-CVE-2022-30190) :  ![starts](https://img.shields.io/github/stars/nimesh895/Malware-Analysis-Follina-CVE-2022-30190.svg) ![forks](https://img.shields.io/github/forks/nimesh895/Malware-Analysis-Follina-CVE-2022-30190.svg)


## CVE-2022-29464
 Certain WSO2 products allow unrestricted file upload with resultant remote code execution. The attacker must use a /fileupload endpoint with a Content-Disposition directory traversal sequence to reach a directory under the web root, such as a ../../../../repository/deployment/server/webapps directory. This affects WSO2 API Manager 2.2.0 up to 4.0.0, WSO2 Identity Server 5.2.0 up to 5.11.0, WSO2 Identity Server Analytics 5.4.0, 5.4.1, 5.5.0 and 5.6.0, WSO2 Identity Server as Key Manager 5.3.0 up to 5.11.0, WSO2 Enterprise Integrator 6.2.0 up to 6.6.0, WSO2 Open Banking AM 1.4.0 up to 2.0.0 and WSO2 Open Banking KM 1.4.0, up to 2.0.0.

- [https://github.com/SystemVll/CVE-2022-29464](https://github.com/SystemVll/CVE-2022-29464) :  ![starts](https://img.shields.io/github/stars/SystemVll/CVE-2022-29464.svg) ![forks](https://img.shields.io/github/forks/SystemVll/CVE-2022-29464.svg)


## CVE-2021-36260
 A command injection vulnerability in the web server of some Hikvision product. Due to the insufficient input validation, attacker can exploit the vulnerability to launch a command injection attack by sending some messages with malicious commands.

- [https://github.com/yanxinwu946/hikvision-unauthenticated-rce-cve-2021-36260](https://github.com/yanxinwu946/hikvision-unauthenticated-rce-cve-2021-36260) :  ![starts](https://img.shields.io/github/stars/yanxinwu946/hikvision-unauthenticated-rce-cve-2021-36260.svg) ![forks](https://img.shields.io/github/forks/yanxinwu946/hikvision-unauthenticated-rce-cve-2021-36260.svg)
- [https://github.com/saaydmr/hikvision-exploiter](https://github.com/saaydmr/hikvision-exploiter) :  ![starts](https://img.shields.io/github/stars/saaydmr/hikvision-exploiter.svg) ![forks](https://img.shields.io/github/forks/saaydmr/hikvision-exploiter.svg)


## CVE-2021-26086
 Affected versions of Atlassian Jira Server and Data Center allow remote attackers to read particular files via a path traversal vulnerability in the /WEB-INF/web.xml endpoint. The affected versions are before version 8.5.14, from version 8.6.0 before 8.13.6, and from version 8.14.0 before 8.16.1.

- [https://github.com/Official-BlackHat13/CVE-2021-26086](https://github.com/Official-BlackHat13/CVE-2021-26086) :  ![starts](https://img.shields.io/github/stars/Official-BlackHat13/CVE-2021-26086.svg) ![forks](https://img.shields.io/github/forks/Official-BlackHat13/CVE-2021-26086.svg)


## CVE-2019-16098
 The driver in Micro-Star MSI Afterburner 4.6.2.15658 (aka RTCore64.sys and RTCore32.sys) allows any authenticated user to read and write to arbitrary memory, I/O ports, and MSRs. This can be exploited for privilege escalation, code execution under high privileges, and information disclosure. These signed drivers can also be used to bypass the Microsoft driver-signing policy to deploy malicious code.

- [https://github.com/VortexCry-Organization/VortexCry-Ransomware-Release](https://github.com/VortexCry-Organization/VortexCry-Ransomware-Release) :  ![starts](https://img.shields.io/github/stars/VortexCry-Organization/VortexCry-Ransomware-Release.svg) ![forks](https://img.shields.io/github/forks/VortexCry-Organization/VortexCry-Ransomware-Release.svg)


## CVE-2017-0143
 The SMBv1 server in Microsoft Windows Vista SP2; Windows Server 2008 SP2 and R2 SP1; Windows 7 SP1; Windows 8.1; Windows Server 2012 Gold and R2; Windows RT 8.1; and Windows 10 Gold, 1511, and 1607; and Windows Server 2016 allows remote attackers to execute arbitrary code via crafted packets, aka "Windows SMB Remote Code Execution Vulnerability." This vulnerability is different from those described in CVE-2017-0144, CVE-2017-0145, CVE-2017-0146, and CVE-2017-0148.

- [https://github.com/hackingyseguridad/smb](https://github.com/hackingyseguridad/smb) :  ![starts](https://img.shields.io/github/stars/hackingyseguridad/smb.svg) ![forks](https://img.shields.io/github/forks/hackingyseguridad/smb.svg)


## CVE-2016-5195
 Race condition in mm/gup.c in the Linux kernel 2.x through 4.x before 4.8.3 allows local users to gain privileges by leveraging incorrect handling of a copy-on-write (COW) feature to write to a read-only memory mapping, as exploited in the wild in October 2016, aka "Dirty COW."

- [https://github.com/ramahmdr/dirtycow](https://github.com/ramahmdr/dirtycow) :  ![starts](https://img.shields.io/github/stars/ramahmdr/dirtycow.svg) ![forks](https://img.shields.io/github/forks/ramahmdr/dirtycow.svg)

