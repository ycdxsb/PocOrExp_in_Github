# Update 2026-01-16
## CVE-2026-20856
 Improper input validation in Windows Server Update Service allows an unauthorized attacker to execute code over a network.

- [https://github.com/b1gchoi/poc-CVE-2026-20856](https://github.com/b1gchoi/poc-CVE-2026-20856) :  ![starts](https://img.shields.io/github/stars/b1gchoi/poc-CVE-2026-20856.svg) ![forks](https://img.shields.io/github/forks/b1gchoi/poc-CVE-2026-20856.svg)


## CVE-2026-20805
 Exposure of sensitive information to an unauthorized actor in Desktop Windows Manager allows an authorized attacker to disclose information locally.

- [https://github.com/fevar54/CVE-2026-20805-POC](https://github.com/fevar54/CVE-2026-20805-POC) :  ![starts](https://img.shields.io/github/stars/fevar54/CVE-2026-20805-POC.svg) ![forks](https://img.shields.io/github/forks/fevar54/CVE-2026-20805-POC.svg)


## CVE-2025-68472
 MindsDB is a platform for building artificial intelligence from enterprise data. Prior to version 25.11.1, an unauthenticated path traversal in the file upload API lets any caller read arbitrary files from the server filesystem and move them into MindsDB’s storage, exposing sensitive data. The PUT handler in file.py directly joins user-controlled data into a filesystem path when the request body is JSON and source_type is not "url". Only multipart uploads and URL-sourced uploads receive sanitization; JSON uploads lack any call to clear_filename or equivalent checks. This vulnerability is fixed in 25.11.1.

- [https://github.com/ExploreUnknowed/CVE-2025-68472](https://github.com/ExploreUnknowed/CVE-2025-68472) :  ![starts](https://img.shields.io/github/stars/ExploreUnknowed/CVE-2025-68472.svg) ![forks](https://img.shields.io/github/forks/ExploreUnknowed/CVE-2025-68472.svg)


## CVE-2025-68428
 jsPDF is a library to generate PDFs in JavaScript. Prior to version 4.0.0, user control of the first argument of the loadFile method in the node.js build allows local file inclusion/path traversal. If given the possibility to pass unsanitized paths to the loadFile method, a user can retrieve file contents of arbitrary files in the local file system the node process is running in. The file contents are included verbatim in the generated PDFs. Other affected methods are `addImage`, `html`, and `addFont`. Only the node.js builds of the library are affected, namely the `dist/jspdf.node.js` and `dist/jspdf.node.min.js` files. The vulnerability has been fixed in jsPDF@4.0.0. This version restricts file system access per default. This semver-major update does not introduce other breaking changes. Some workarounds areavailable. With recent node versions, jsPDF recommends using the `--permission` flag in production. The feature was introduced experimentally in v20.0.0 and is stable since v22.13.0/v23.5.0/v24.0.0. For older node versions, sanitize user-provided paths before passing them to jsPDF.

- [https://github.com/Nurjaman2004/jsPDF-Bulk-Detector-CVE-2025-68428-](https://github.com/Nurjaman2004/jsPDF-Bulk-Detector-CVE-2025-68428-) :  ![starts](https://img.shields.io/github/stars/Nurjaman2004/jsPDF-Bulk-Detector-CVE-2025-68428-.svg) ![forks](https://img.shields.io/github/forks/Nurjaman2004/jsPDF-Bulk-Detector-CVE-2025-68428-.svg)


## CVE-2025-67779
 It was found that the fix addressing CVE-2025-55184 in React Server Components was incomplete and does not prevent a denial of service attack in a specific case. React Server Components versions 19.0.2, 19.1.3 and 19.2.2 are affected, allowing unsafe deserialization of payloads from HTTP requests to Server Function endpoints. This can cause an infinite loop that hangs the server process and may prevent future HTTP requests from being served.

- [https://github.com/JSH-data/CVE-2025-55184_CVE-2025-67779](https://github.com/JSH-data/CVE-2025-55184_CVE-2025-67779) :  ![starts](https://img.shields.io/github/stars/JSH-data/CVE-2025-55184_CVE-2025-67779.svg) ![forks](https://img.shields.io/github/forks/JSH-data/CVE-2025-55184_CVE-2025-67779.svg)


## CVE-2025-67399
 An issue in AIRTH SMART HOME AQI MONITOR Bootloader v.1.005 allows a physically proximate attacker to obtain sensitive information via the UART port of the BK7231N controller (Wi-Fi and BLE module) on the device is open to access

- [https://github.com/rupeshsurve04/CVE-2025-67399](https://github.com/rupeshsurve04/CVE-2025-67399) :  ![starts](https://img.shields.io/github/stars/rupeshsurve04/CVE-2025-67399.svg) ![forks](https://img.shields.io/github/forks/rupeshsurve04/CVE-2025-67399.svg)


## CVE-2025-67303
 An issue in ComfyUI-Manager prior to version 3.38 allowed remote attackers to potentially manipulate its configuration and critical data. This was due to the application storing its files in an insufficiently protected location that was accessible via the web interface

- [https://github.com/maybe-O/CVE-2025-67303](https://github.com/maybe-O/CVE-2025-67303) :  ![starts](https://img.shields.io/github/stars/maybe-O/CVE-2025-67303.svg) ![forks](https://img.shields.io/github/forks/maybe-O/CVE-2025-67303.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-range](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-range) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-range.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-range.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-pnpm-overrides](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-pnpm-overrides) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-pnpm-overrides.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-pnpm-overrides.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-optional-deps](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-optional-deps) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-optional-deps.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-optional-deps.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions.svg)


## CVE-2025-64459
Django would like to thank cyberstan for reporting this issue.

- [https://github.com/purehate/CVE-2025-64459-hunter](https://github.com/purehate/CVE-2025-64459-hunter) :  ![starts](https://img.shields.io/github/stars/purehate/CVE-2025-64459-hunter.svg) ![forks](https://img.shields.io/github/forks/purehate/CVE-2025-64459-hunter.svg)


## CVE-2025-64155
 An improper neutralization of special elements used in an os command ('os command injection') vulnerability in Fortinet FortiSIEM 7.4.0, FortiSIEM 7.3.0 through 7.3.4, FortiSIEM 7.1.0 through 7.1.8, FortiSIEM 7.0.0 through 7.0.4, FortiSIEM 6.7.0 through 6.7.10 may allow an attacker to execute unauthorized code or commands via  crafted TCP requests.

- [https://github.com/purehate/CVE-2025-64155-hunter](https://github.com/purehate/CVE-2025-64155-hunter) :  ![starts](https://img.shields.io/github/stars/purehate/CVE-2025-64155-hunter.svg) ![forks](https://img.shields.io/github/forks/purehate/CVE-2025-64155-hunter.svg)


## CVE-2025-55184
 A pre-authentication denial of service vulnerability exists in React Server Components versions 19.0.0, 19.0.1 19.1.0, 19.1.1, 19.1.2, 19.2.0 and 19.2.1, including the following packages: react-server-dom-parcel, react-server-dom-turbopack, and react-server-dom-webpack. The vulnerable code unsafely deserializes payloads from HTTP requests to Server Function endpoints, which can cause an infinite loop that hangs the server process and may prevent future HTTP requests from being served.

- [https://github.com/JSH-data/CVE-2025-55184_CVE-2025-67779](https://github.com/JSH-data/CVE-2025-55184_CVE-2025-67779) :  ![starts](https://img.shields.io/github/stars/JSH-data/CVE-2025-55184_CVE-2025-67779.svg) ![forks](https://img.shields.io/github/forks/JSH-data/CVE-2025-55184_CVE-2025-67779.svg)


## CVE-2025-55182
 A pre-authentication remote code execution vulnerability exists in React Server Components versions 19.0.0, 19.1.0, 19.1.1, and 19.2.0 including the following packages: react-server-dom-parcel, react-server-dom-turbopack, and react-server-dom-webpack. The vulnerable code unsafely deserializes payloads from HTTP requests to Server Function endpoints.

- [https://github.com/Faithtiannn/CVE-2025-55182](https://github.com/Faithtiannn/CVE-2025-55182) :  ![starts](https://img.shields.io/github/stars/Faithtiannn/CVE-2025-55182.svg) ![forks](https://img.shields.io/github/forks/Faithtiannn/CVE-2025-55182.svg)


## CVE-2025-54136
 Cursor is a code editor built for programming with AI. In versions 1.2.4 and below, attackers can achieve remote and persistent code execution by modifying an already trusted MCP configuration file inside a shared GitHub repository or editing the file locally on the target's machine. Once a collaborator accepts a harmless MCP, the attacker can silently swap it for a malicious command (e.g., calc.exe) without triggering any warning or re-prompt. If an attacker has write permissions on a user's active branches of a source repository that contains existing MCP servers the user has previously approved, or allows an attacker has arbitrary file-write locally, the attacker can achieve arbitrary code execution. This is fixed in version 1.3.

- [https://github.com/PRE5T0/CVE-2025-54136](https://github.com/PRE5T0/CVE-2025-54136) :  ![starts](https://img.shields.io/github/stars/PRE5T0/CVE-2025-54136.svg) ![forks](https://img.shields.io/github/forks/PRE5T0/CVE-2025-54136.svg)


## CVE-2025-53783
 Heap-based buffer overflow in Microsoft Teams allows an unauthorized attacker to execute code over a network.

- [https://github.com/ksgassama-lab/MSTeams---Vulnerability---Remediation](https://github.com/ksgassama-lab/MSTeams---Vulnerability---Remediation) :  ![starts](https://img.shields.io/github/stars/ksgassama-lab/MSTeams---Vulnerability---Remediation.svg) ![forks](https://img.shields.io/github/forks/ksgassama-lab/MSTeams---Vulnerability---Remediation.svg)


## CVE-2025-40019
it's also checked for decryption and in-place encryption.

- [https://github.com/0xAtharv/CVE-2025-40019-POC](https://github.com/0xAtharv/CVE-2025-40019-POC) :  ![starts](https://img.shields.io/github/stars/0xAtharv/CVE-2025-40019-POC.svg) ![forks](https://img.shields.io/github/forks/0xAtharv/CVE-2025-40019-POC.svg)


## CVE-2025-14847
 Mismatched length fields in Zlib compressed protocol headers may allow a read of uninitialized heap memory by an unauthenticated client. This issue affects all MongoDB Server v7.0 prior to 7.0.28 versions, MongoDB Server v8.0 versions prior to 8.0.17, MongoDB Server v8.2 versions prior to 8.2.3, MongoDB Server v6.0 versions prior to 6.0.27, MongoDB Server v5.0 versions prior to 5.0.32, MongoDB Server v4.4 versions prior to 4.4.30, MongoDB Server v4.2 versions greater than or equal to 4.2.0, MongoDB Server v4.0 versions greater than or equal to 4.0.0, and MongoDB Server v3.6 versions greater than or equal to 3.6.0.

- [https://github.com/pedrocruz2202/pedrocruz2202.github.io](https://github.com/pedrocruz2202/pedrocruz2202.github.io) :  ![starts](https://img.shields.io/github/stars/pedrocruz2202/pedrocruz2202.github.io.svg) ![forks](https://img.shields.io/github/forks/pedrocruz2202/pedrocruz2202.github.io.svg)
- [https://github.com/pedrocruz2202/mongobleed-scanner](https://github.com/pedrocruz2202/mongobleed-scanner) :  ![starts](https://img.shields.io/github/stars/pedrocruz2202/mongobleed-scanner.svg) ![forks](https://img.shields.io/github/forks/pedrocruz2202/mongobleed-scanner.svg)


## CVE-2025-9501
 The W3 Total Cache WordPress plugin before 2.8.13 is vulnerable to command injection via the _parse_dynamic_mfunc function, allowing unauthenticated users to execute PHP commands by submitting a comment with a malicious payload to a post.

- [https://github.com/InnerFireZ/CVE-2025_9501-POC](https://github.com/InnerFireZ/CVE-2025_9501-POC) :  ![starts](https://img.shields.io/github/stars/InnerFireZ/CVE-2025_9501-POC.svg) ![forks](https://img.shields.io/github/forks/InnerFireZ/CVE-2025_9501-POC.svg)


## CVE-2025-7089
 A vulnerability was found in Belkin F9K1122 1.00.33 and classified as critical. This issue affects the function formWanTcpipSetup of the file /goform/formWanTcpipSetup of the component webs. The manipulation of the argument pppUserName leads to stack-based buffer overflow. The attack may be initiated remotely. The exploit has been disclosed to the public and may be used. The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/mathavamoorthi/CVE-2025-70899](https://github.com/mathavamoorthi/CVE-2025-70899) :  ![starts](https://img.shields.io/github/stars/mathavamoorthi/CVE-2025-70899.svg) ![forks](https://img.shields.io/github/forks/mathavamoorthi/CVE-2025-70899.svg)


## CVE-2025-2907
 The Order Delivery Date WordPress plugin before 12.3.1 does not have authorization and CSRF checks when importing settings. Furthermore it also lacks proper checks to only update options relevant to the Order Delivery Date WordPress plugin before 12.3.1. This leads to attackers being able to modify the default_user_role to administrator and users_can_register, allowing them to register as an administrator of the site for complete site takeover.

- [https://github.com/Yucaerin/CVE-2025-2907](https://github.com/Yucaerin/CVE-2025-2907) :  ![starts](https://img.shields.io/github/stars/Yucaerin/CVE-2025-2907.svg) ![forks](https://img.shields.io/github/forks/Yucaerin/CVE-2025-2907.svg)


## CVE-2023-22809
 In Sudo before 1.9.12p2, the sudoedit (aka -e) feature mishandles extra arguments passed in the user-provided environment variables (SUDO_EDITOR, VISUAL, and EDITOR), allowing a local attacker to append arbitrary entries to the list of files to process. This can lead to privilege escalation. Affected versions are 1.8.0 through 1.9.12.p1. The problem exists because a user-specified editor may contain a "--" argument that defeats a protection mechanism, e.g., an EDITOR='vim -- /path/to/extra/file' value.

- [https://github.com/ValeuDoamne/CVE-2023-22809](https://github.com/ValeuDoamne/CVE-2023-22809) :  ![starts](https://img.shields.io/github/stars/ValeuDoamne/CVE-2023-22809.svg) ![forks](https://img.shields.io/github/forks/ValeuDoamne/CVE-2023-22809.svg)


## CVE-2023-20938
 In binder_transaction_buffer_release of binder.c, there is a possible use after free due to improper input validation. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-257685302References: Upstream kernel

- [https://github.com/0xAtharv/CVE-2023-20938-Public](https://github.com/0xAtharv/CVE-2023-20938-Public) :  ![starts](https://img.shields.io/github/stars/0xAtharv/CVE-2023-20938-Public.svg) ![forks](https://img.shields.io/github/forks/0xAtharv/CVE-2023-20938-Public.svg)


## CVE-2023-2002
 A vulnerability was found in the HCI sockets implementation due to a missing capability check in net/bluetooth/hci_sock.c in the Linux Kernel. This flaw allows an attacker to unauthorized execution of management commands, compromising the confidentiality, integrity, and availability of Bluetooth communication.

- [https://github.com/lrh2000/CVE-2023-2002](https://github.com/lrh2000/CVE-2023-2002) :  ![starts](https://img.shields.io/github/stars/lrh2000/CVE-2023-2002.svg) ![forks](https://img.shields.io/github/forks/lrh2000/CVE-2023-2002.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/ch4os443/CVE-2021-41773](https://github.com/ch4os443/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/ch4os443/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/ch4os443/CVE-2021-41773.svg)
- [https://github.com/Fa1c0n35/CVE-2021-41773](https://github.com/Fa1c0n35/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/Fa1c0n35/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/Fa1c0n35/CVE-2021-41773.svg)
- [https://github.com/skentagon/CVE-2021-41773](https://github.com/skentagon/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/skentagon/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/skentagon/CVE-2021-41773.svg)
- [https://github.com/vuongnv3389-sec/cve-2021-41773](https://github.com/vuongnv3389-sec/cve-2021-41773) :  ![starts](https://img.shields.io/github/stars/vuongnv3389-sec/cve-2021-41773.svg) ![forks](https://img.shields.io/github/forks/vuongnv3389-sec/cve-2021-41773.svg)


## CVE-2021-36260
 A command injection vulnerability in the web server of some Hikvision product. Due to the insufficient input validation, attacker can exploit the vulnerability to launch a command injection attack by sending some messages with malicious commands.

- [https://github.com/shubtheone/CVE-2021-36260-hikvision](https://github.com/shubtheone/CVE-2021-36260-hikvision) :  ![starts](https://img.shields.io/github/stars/shubtheone/CVE-2021-36260-hikvision.svg) ![forks](https://img.shields.io/github/forks/shubtheone/CVE-2021-36260-hikvision.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/zaaraZiof0/pkexec-exploit-CVE](https://github.com/zaaraZiof0/pkexec-exploit-CVE) :  ![starts](https://img.shields.io/github/stars/zaaraZiof0/pkexec-exploit-CVE.svg) ![forks](https://img.shields.io/github/forks/zaaraZiof0/pkexec-exploit-CVE.svg)


## CVE-2021-3560
 It was found that polkit could be tricked into bypassing the credential checks for D-Bus requests, elevating the privileges of the requestor to the root user. This flaw could be used by an unprivileged local attacker to, for example, create a new local administrator. The highest threat from this vulnerability is to data confidentiality and integrity as well as system availability.

- [https://github.com/realatharva15/polkit-CVE-2021-3560_writeup](https://github.com/realatharva15/polkit-CVE-2021-3560_writeup) :  ![starts](https://img.shields.io/github/stars/realatharva15/polkit-CVE-2021-3560_writeup.svg) ![forks](https://img.shields.io/github/forks/realatharva15/polkit-CVE-2021-3560_writeup.svg)


## CVE-2020-1938
 When using the Apache JServ Protocol (AJP), care must be taken when trusting incoming connections to Apache Tomcat. Tomcat treats AJP connections as having higher trust than, for example, a similar HTTP connection. If such connections are available to an attacker, they can be exploited in ways that may be surprising. In Apache Tomcat 9.0.0.M1 to 9.0.0.30, 8.5.0 to 8.5.50 and 7.0.0 to 7.0.99, Tomcat shipped with an AJP Connector enabled by default that listened on all configured IP addresses. It was expected (and recommended in the security guide) that this Connector would be disabled if not required. This vulnerability report identified a mechanism that allowed: - returning arbitrary files from anywhere in the web application - processing any file in the web application as a JSP Further, if the web application allowed file upload and stored those files within the web application (or the attacker was able to control the content of the web application by some other means) then this, along with the ability to process a file as a JSP, made remote code execution possible. It is important to note that mitigation is only required if an AJP port is accessible to untrusted users. Users wishing to take a defence-in-depth approach and block the vector that permits returning arbitrary files and execution as JSP may upgrade to Apache Tomcat 9.0.31, 8.5.51 or 7.0.100 or later. A number of changes were made to the default AJP Connector configuration in 9.0.31 to harden the default configuration. It is likely that users upgrading to 9.0.31, 8.5.51 or 7.0.100 or later will need to make small changes to their configurations.

- [https://github.com/RedTeam-Rediron/CVE-2020-1938](https://github.com/RedTeam-Rediron/CVE-2020-1938) :  ![starts](https://img.shields.io/github/stars/RedTeam-Rediron/CVE-2020-1938.svg) ![forks](https://img.shields.io/github/forks/RedTeam-Rediron/CVE-2020-1938.svg)


## CVE-2018-1049
 In systemd prior to 234 a race condition exists between .mount and .automount units such that automount requests from kernel may not be serviced by systemd resulting in kernel holding the mountpoint and any processes that try to use said mount will hang. A race condition like this may lead to denial of service, until mount points are unmounted.

- [https://github.com/lukehebe/CVE-2018-1049-POC](https://github.com/lukehebe/CVE-2018-1049-POC) :  ![starts](https://img.shields.io/github/stars/lukehebe/CVE-2018-1049-POC.svg) ![forks](https://img.shields.io/github/forks/lukehebe/CVE-2018-1049-POC.svg)

