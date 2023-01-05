# Update 2023-01-05
## CVE-2023-22456
 ViewVC, a browser interface for CVS and Subversion version control repositories, as a cross-site scripting vulnerability that affects versions prior to 1.2.2 and 1.1.29. The impact of this vulnerability is mitigated by the need for an attacker to have commit privileges to a Subversion repository exposed by an otherwise trusted ViewVC instance. The attack vector involves files with unsafe names (names that, when embedded into an HTML stream, would cause the browser to run unwanted code), which themselves can be challenging to create. Users should update to at least version 1.2.2 (if they are using a 1.2.x version of ViewVC) or 1.1.29 (if they are using a 1.1.x version). ViewVC 1.0.x is no longer supported, so users of that release lineage should implement a workaround. Users can edit their ViewVC EZT view templates to manually HTML-escape changed paths during rendering. Locate in your template set's `revision.ezt` file references to those changed paths, and wrap them with `[format &quot;html&quot;]` and `[end]`. For most users, that means that references to `[changes.path]` will become `[format &quot;html&quot;][changes.path][end]`. (This workaround should be reverted after upgrading to a patched version of ViewVC, else changed path names will be doubly escaped.)

- [https://github.com/Live-Hack-CVE/CVE-2023-22456](https://github.com/Live-Hack-CVE/CVE-2023-22456) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22456.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22456.svg)


## CVE-2023-0039
 The User Post Gallery - UPG plugin for WordPress is vulnerable to authorization bypass which leads to remote command execution due to the use of a nopriv AJAX action and user supplied function calls and parameters in versions up to, and including 2.19. This makes it possible for unauthenticated attackers to call arbitrary PHP functions and perform actions like adding new files that can be webshells and updating the site's options to allow anyone to register as an administrator.

- [https://github.com/Live-Hack-CVE/CVE-2023-0039](https://github.com/Live-Hack-CVE/CVE-2023-0039) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0039.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0039.svg)


## CVE-2023-0038
 The &quot;Survey Maker &#8211; Best WordPress Survey Plugin&quot; plugin for WordPress is vulnerable to Stored Cross-Site Scripting via survey answers in versions up to, and including, 3.1.3 due to insufficient input sanitization and output escaping. This makes it possible for unauthenticated attackers to inject arbitrary web scripts when submitting quizzes that will execute whenever a user accesses the submissions page.

- [https://github.com/Live-Hack-CVE/CVE-2023-0038](https://github.com/Live-Hack-CVE/CVE-2023-0038) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0038.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0038.svg)


## CVE-2022-46689
 A race condition was addressed with additional validation. This issue is fixed in tvOS 16.2, macOS Monterey 12.6.2, macOS Ventura 13.1, macOS Big Sur 11.7.2, iOS 15.7.2 and iPadOS 15.7.2, iOS 16.2 and iPadOS 16.2, watchOS 9.2. An app may be able to execute arbitrary code with kernel privileges.

- [https://github.com/straight-tamago/NoCameraSound](https://github.com/straight-tamago/NoCameraSound) :  ![starts](https://img.shields.io/github/stars/straight-tamago/NoCameraSound.svg) ![forks](https://img.shields.io/github/forks/straight-tamago/NoCameraSound.svg)
- [https://github.com/straight-tamago/NoHomeBar](https://github.com/straight-tamago/NoHomeBar) :  ![starts](https://img.shields.io/github/stars/straight-tamago/NoHomeBar.svg) ![forks](https://img.shields.io/github/forks/straight-tamago/NoHomeBar.svg)
- [https://github.com/straight-tamago/DockTransparent](https://github.com/straight-tamago/DockTransparent) :  ![starts](https://img.shields.io/github/stars/straight-tamago/DockTransparent.svg) ![forks](https://img.shields.io/github/forks/straight-tamago/DockTransparent.svg)


## CVE-2022-46164
 NodeBB is an open source Node.js based forum software. Due to a plain object with a prototype being used in socket.io message handling a specially crafted payload can be used to impersonate other users and takeover accounts. This vulnerability has been patched in version 2.6.1. Users are advised to upgrade. Users unable to upgrade may cherry-pick commit `48d143921753914da45926cca6370a92ed0c46b8` into their codebase to patch the exploit.

- [https://github.com/stephenbradshaw/CVE-2022-46164-poc](https://github.com/stephenbradshaw/CVE-2022-46164-poc) :  ![starts](https://img.shields.io/github/stars/stephenbradshaw/CVE-2022-46164-poc.svg) ![forks](https://img.shields.io/github/forks/stephenbradshaw/CVE-2022-46164-poc.svg)


## CVE-2022-46081
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/Live-Hack-CVE/CVE-2022-46081](https://github.com/Live-Hack-CVE/CVE-2022-46081) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-46081.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-46081.svg)


## CVE-2022-45867
 MyBB before 1.8.33 allows Directory Traversal. The Admin CP Languages module allows remote authenticated users, with high privileges, to achieve local file inclusion and execution.

- [https://github.com/Live-Hack-CVE/CVE-2022-45867](https://github.com/Live-Hack-CVE/CVE-2022-45867) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-45867.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-45867.svg)


## CVE-2022-45143
 The JsonErrorReportValve in Apache Tomcat 8.5.83, 9.0.40 to 9.0.68 and 10.1.0-M1 to 10.1.1 did not escape the type, message or description values. In some circumstances these are constructed from user provided data and it was therefore possible for users to supply values that invalidated or manipulated the JSON output.

- [https://github.com/Live-Hack-CVE/CVE-2022-45143](https://github.com/Live-Hack-CVE/CVE-2022-45143) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-45143.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-45143.svg)


## CVE-2022-44036
 ** DISPUTED ** In b2evolution 7.2.5, if configured with admins_can_manipulate_sensitive_files, arbitrary file upload is allowed for admins, leading to command execution. NOTE: the vendor's position is that this is &quot;very obviously a feature not an issue and if you don't like that feature it is very obvious how to disable it.&quot;

- [https://github.com/Live-Hack-CVE/CVE-2022-44036](https://github.com/Live-Hack-CVE/CVE-2022-44036) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-44036.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-44036.svg)


## CVE-2022-42710
 Nice (formerly Nortek) Linear eMerge E3-Series 0.32-08f, 0.32-07p, 0.32-07e, 0.32-09c, 0.32-09b, 0.32-09a, and 0.32-08e devices are vulnerable to Stored Cross-Site Scripting (XSS).

- [https://github.com/Live-Hack-CVE/CVE-2022-42710](https://github.com/Live-Hack-CVE/CVE-2022-42710) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-42710.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-42710.svg)


## CVE-2022-42471
 An improper neutralization of CRLF sequences in HTTP headers ('HTTP Response Splitting') vulnerability [CWE-113] In FortiWeb version 7.0.0 through 7.0.2, FortiWeb version 6.4.0 through 6.4.2, FortiWeb version 6.3.6 through 6.3.20 may allow an authenticated and remote attacker to inject arbitrary headers.

- [https://github.com/Live-Hack-CVE/CVE-2022-42471](https://github.com/Live-Hack-CVE/CVE-2022-42471) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-42471.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-42471.svg)


## CVE-2022-42435
 IBM Business Automation Workflow 18.0.0, 18.0.1, 18.0.2, 19.0.1, 19.0.2, 19.0.3, 20.0.1, 20.0.2, 20.0.3, 21.0.1, 21.0.2, 21.0.3, and 22.0.1 is vulnerable to cross-site request forgery which could allow an attacker to execute malicious and unauthorized actions transmitted from a user that the website trusts. IBM X-Force ID: 238054.

- [https://github.com/Live-Hack-CVE/CVE-2022-42435](https://github.com/Live-Hack-CVE/CVE-2022-42435) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-42435.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-42435.svg)


## CVE-2022-41336
 An improper neutralization of input during web page generation vulnerability [CWE-79] in FortiPortal versions 6.0.0 through 6.0.11 and all versions of 5.3, 5.2, 5.1, 5.0 management interface may allow a remote authenticated attacker to perform a stored cross site scripting (XSS) attack via sending request with specially crafted columnindex parameter.

- [https://github.com/Live-Hack-CVE/CVE-2022-41336](https://github.com/Live-Hack-CVE/CVE-2022-41336) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-41336.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-41336.svg)


## CVE-2022-39947
 A improper neutralization of special elements used in an os command ('os command injection') in Fortinet FortiADC version 7.0.0 through 7.0.2, FortiADC version 6.2.0 through 6.2.3, FortiADC version version 6.1.0 through 6.1.6, FortiADC version 6.0.0 through 6.0.4, FortiADC version 5.4.0 through 5.4.5 may allow an attacker to execute unauthorized code or commands via specifically crafted HTTP requests.

- [https://github.com/Live-Hack-CVE/CVE-2022-39947](https://github.com/Live-Hack-CVE/CVE-2022-39947) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-39947.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-39947.svg)


## CVE-2022-38766
 The remote keyless system on Renault ZOE 2021 vehicles sends 433.92 MHz RF signals from the same Rolling Codes set for each door-open request, which allows for a replay attack.

- [https://github.com/Live-Hack-CVE/CVE-2022-38766](https://github.com/Live-Hack-CVE/CVE-2022-38766) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-38766.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-38766.svg)


## CVE-2022-38723
 Gravitee API Management before 3.15.13 allows path traversal through HTML injection.

- [https://github.com/Live-Hack-CVE/CVE-2022-38723](https://github.com/Live-Hack-CVE/CVE-2022-38723) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-38723.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-38723.svg)


## CVE-2022-35845
 Multiple improper neutralization of special elements used in an OS Command ('OS Command Injection') vulnerabilities [CWE-78] in FortiTester 7.1.0, 7.0 all versions, 4.0.0 through 4.2.0, 2.3.0 through 3.9.1 may allow an authenticated attacker to execute arbitrary commands in the underlying shell.

- [https://github.com/Live-Hack-CVE/CVE-2022-35845](https://github.com/Live-Hack-CVE/CVE-2022-35845) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35845.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35845.svg)


## CVE-2022-32653
 In mtk-aie, there is a possible use after free due to a logic error. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS07262518; Issue ID: ALPS07262518.

- [https://github.com/Live-Hack-CVE/CVE-2022-32653](https://github.com/Live-Hack-CVE/CVE-2022-32653) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-32653.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-32653.svg)


## CVE-2022-32652
 In mtk-aie, there is a possible use after free due to a logic error. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS07262617; Issue ID: ALPS07262617.

- [https://github.com/Live-Hack-CVE/CVE-2022-32652](https://github.com/Live-Hack-CVE/CVE-2022-32652) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-32652.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-32652.svg)


## CVE-2022-32651
 In mtk-aie, there is a possible use after free due to a logic error. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS07225857; Issue ID: ALPS07225857.

- [https://github.com/Live-Hack-CVE/CVE-2022-32651](https://github.com/Live-Hack-CVE/CVE-2022-32651) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-32651.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-32651.svg)


## CVE-2022-32650
 In mtk-isp, there is a possible use after free due to a logic error. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS07225853; Issue ID: ALPS07225853.

- [https://github.com/Live-Hack-CVE/CVE-2022-32650](https://github.com/Live-Hack-CVE/CVE-2022-32650) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-32650.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-32650.svg)


## CVE-2022-32649
 In jpeg, there is a possible use after free due to a logic error. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS07225840; Issue ID: ALPS07225840.

- [https://github.com/Live-Hack-CVE/CVE-2022-32649](https://github.com/Live-Hack-CVE/CVE-2022-32649) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-32649.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-32649.svg)


## CVE-2022-32648
 In disp, there is a possible use after free due to a race condition. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS06535964; Issue ID: ALPS06535964.

- [https://github.com/Live-Hack-CVE/CVE-2022-32648](https://github.com/Live-Hack-CVE/CVE-2022-32648) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-32648.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-32648.svg)


## CVE-2022-32647
 In ccu, there is a possible out of bounds write due to improper input validation. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS07554646; Issue ID: ALPS07554646.

- [https://github.com/Live-Hack-CVE/CVE-2022-32647](https://github.com/Live-Hack-CVE/CVE-2022-32647) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-32647.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-32647.svg)


## CVE-2022-32646
 In gpu drm, there is a possible stack overflow due to a missing bounds check. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS07363501; Issue ID: ALPS07363501.

- [https://github.com/Live-Hack-CVE/CVE-2022-32646](https://github.com/Live-Hack-CVE/CVE-2022-32646) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-32646.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-32646.svg)


## CVE-2022-32645
 In vow, there is a possible information disclosure due to a race condition. This could lead to local information disclosure with System execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS07494477; Issue ID: ALPS07494477.

- [https://github.com/Live-Hack-CVE/CVE-2022-32645](https://github.com/Live-Hack-CVE/CVE-2022-32645) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-32645.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-32645.svg)


## CVE-2022-32644
 In vow, there is a possible use after free due to a race condition. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS07494473; Issue ID: ALPS07494473.

- [https://github.com/Live-Hack-CVE/CVE-2022-32644](https://github.com/Live-Hack-CVE/CVE-2022-32644) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-32644.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-32644.svg)


## CVE-2022-32641
 In meta wifi, there is a possible out of bounds read due to a missing bounds check. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS07453594; Issue ID: ALPS07453594.

- [https://github.com/Live-Hack-CVE/CVE-2022-32641](https://github.com/Live-Hack-CVE/CVE-2022-32641) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-32641.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-32641.svg)


## CVE-2022-32640
 In meta wifi, there is a possible out of bounds write due to a missing bounds check. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS07441652; Issue ID: ALPS07441652.

- [https://github.com/Live-Hack-CVE/CVE-2022-32640](https://github.com/Live-Hack-CVE/CVE-2022-32640) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-32640.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-32640.svg)


## CVE-2022-32639
 In watchdog, there is a possible out of bounds read due to a missing bounds check. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS07494487; Issue ID: ALPS07494487.

- [https://github.com/Live-Hack-CVE/CVE-2022-32639](https://github.com/Live-Hack-CVE/CVE-2022-32639) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-32639.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-32639.svg)


## CVE-2022-32638
 In isp, there is a possible out of bounds write due to a race condition. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS07494449; Issue ID: ALPS07494449.

- [https://github.com/Live-Hack-CVE/CVE-2022-32638](https://github.com/Live-Hack-CVE/CVE-2022-32638) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-32638.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-32638.svg)


## CVE-2022-32637
 In hevc decoder, there is a possible out of bounds write due to a missing bounds check. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS07491374; Issue ID: ALPS07491374.

- [https://github.com/Live-Hack-CVE/CVE-2022-32637](https://github.com/Live-Hack-CVE/CVE-2022-32637) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-32637.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-32637.svg)


## CVE-2022-32636
 In keyinstall, there is a possible out of bounds write due to an integer overflow. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS07510064; Issue ID: ALPS07510064.

- [https://github.com/Live-Hack-CVE/CVE-2022-32636](https://github.com/Live-Hack-CVE/CVE-2022-32636) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-32636.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-32636.svg)


## CVE-2022-32635
 In gps, there is a possible out of bounds write due to a missing bounds check. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS07573237; Issue ID: ALPS07573237.

- [https://github.com/Live-Hack-CVE/CVE-2022-32635](https://github.com/Live-Hack-CVE/CVE-2022-32635) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-32635.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-32635.svg)


## CVE-2022-32623
 In mdp, there is a possible out of bounds write due to incorrect error handling. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS07342114; Issue ID: ALPS07342114.

- [https://github.com/Live-Hack-CVE/CVE-2022-32623](https://github.com/Live-Hack-CVE/CVE-2022-32623) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-32623.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-32623.svg)


## CVE-2022-28672
 This vulnerability allows remote attackers to execute arbitrary code on affected installations of Foxit PDF Reader 11.2.1.53537. User interaction is required to exploit this vulnerability in that the target must visit a malicious page or open a malicious file. The specific flaw exists within the handling of Doc objects. The issue results from the lack of validating the existence of an object prior to performing operations on the object. An attacker can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-16640.

- [https://github.com/fastmo/CVE-2022-28672](https://github.com/fastmo/CVE-2022-28672) :  ![starts](https://img.shields.io/github/stars/fastmo/CVE-2022-28672.svg) ![forks](https://img.shields.io/github/forks/fastmo/CVE-2022-28672.svg)


## CVE-2022-28388
 usb_8dev_start_xmit in drivers/net/can/usb/usb_8dev.c in the Linux kernel through 5.17.1 has a double free.

- [https://github.com/Live-Hack-CVE/CVE-2022-28388](https://github.com/Live-Hack-CVE/CVE-2022-28388) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-28388.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-28388.svg)


## CVE-2022-23506
 Spinnaker is an open source, multi-cloud continuous delivery platform for releasing software changes, and Spinnaker's Rosco microservice produces machine images. Rosco prior to versions 1.29.2, 1.28.4, and 1.27.3 does not property mask secrets generated via packer builds. This can lead to exposure of sensitive AWS credentials in packer log files. Versions 1.29.2, 1.28.4, and 1.27.3 of Rosco contain fixes for this issue. A workaround is available. It's recommended to use short lived credentials via role assumption and IAM profiles. Additionally, credentials can be set in `/home/spinnaker/.aws/credentials` and `/home/spinnaker/.aws/config` as a volume mount for Rosco pods vs. setting credentials in roscos bake config properties. Last even with those it's recommend to use IAM Roles vs. long lived credentials. This drastically mitigates the risk of credentials exposure. If users have used static credentials, it's recommended to purge any bake logs for AWS, evaluate whether AWS_ACCESS_KEY, SECRET_KEY and/or other sensitive data has been introduced in log files and bake job logs. Then, rotate these credentials and evaluate potential improper use of those credentials.

- [https://github.com/Live-Hack-CVE/CVE-2022-23506](https://github.com/Live-Hack-CVE/CVE-2022-23506) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-23506.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-23506.svg)


## CVE-2022-22965
 A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the application to run on Tomcat as a WAR deployment. If the application is deployed as a Spring Boot executable jar, i.e. the default, it is not vulnerable to the exploit. However, the nature of the vulnerability is more general, and there may be other ways to exploit it.

- [https://github.com/ajith737/Spring4Shell-CVE-2022-22965-POC](https://github.com/ajith737/Spring4Shell-CVE-2022-22965-POC) :  ![starts](https://img.shields.io/github/stars/ajith737/Spring4Shell-CVE-2022-22965-POC.svg) ![forks](https://img.shields.io/github/forks/ajith737/Spring4Shell-CVE-2022-22965-POC.svg)


## CVE-2022-20473
 In toLanguageTag of LocaleListCache.cpp, there is a possible out of bounds read due to an incorrect bounds check. This could lead to remote code execution with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-10 Android-11 Android-12 Android-12L Android-13Android ID: A-239267173

- [https://github.com/Trinadh465/frameworks_minikin_AOSP10_r33-CVE-2022-20473](https://github.com/Trinadh465/frameworks_minikin_AOSP10_r33-CVE-2022-20473) :  ![starts](https://img.shields.io/github/stars/Trinadh465/frameworks_minikin_AOSP10_r33-CVE-2022-20473.svg) ![forks](https://img.shields.io/github/forks/Trinadh465/frameworks_minikin_AOSP10_r33-CVE-2022-20473.svg)


## CVE-2022-4871
 A vulnerability classified as problematic was found in ummmmm nflpick-em.com up to 2.2.x. This vulnerability affects the function _Load_Users of the file html/includes/runtime/admin/JSON/LoadUsers.php. The manipulation of the argument sort leads to sql injection. The attack can be initiated remotely. The name of the patch is dd77a35942f527ea0beef5e0ec62b92e8b93211e. It is recommended to apply a patch to fix this issue. VDB-217270 is the identifier assigned to this vulnerability. NOTE: JSON entrypoint is only accessible via an admin account

- [https://github.com/Live-Hack-CVE/CVE-2022-4871](https://github.com/Live-Hack-CVE/CVE-2022-4871) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4871.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4871.svg)


## CVE-2022-4663
 The Members Import plugin for WordPress is vulnerable to Self Cross-Site Scripting via the user_login parameter in an imported CSV file in versions up to, and including, 1.4.2 due to insufficient input sanitization and output escaping. This makes it possible for attackers to inject arbitrary web scripts in pages that execute if they can successfully trick a site's administrator into uploading a CSV file with the malicious payload.

- [https://github.com/Live-Hack-CVE/CVE-2022-4663](https://github.com/Live-Hack-CVE/CVE-2022-4663) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4663.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4663.svg)


## CVE-2022-4228
 A vulnerability classified as problematic has been found in SourceCodester Book Store Management System 1.0. This affects an unknown part of the file /bsms_ci/index.php/user/edit_user/. The manipulation of the argument password leads to information disclosure. It is possible to initiate the attack remotely. The exploit has been disclosed to the public and may be used. The associated identifier of this vulnerability is VDB-214587.

- [https://github.com/Live-Hack-CVE/CVE-2022-4228](https://github.com/Live-Hack-CVE/CVE-2022-4228) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4228.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4228.svg)


## CVE-2022-3614
 In affected versions of Octopus Deploy users of certain browsers using AD to sign-in to Octopus Server were able to bypass authentication checks and be redirected to the configured redirect url without any validation.

- [https://github.com/Live-Hack-CVE/CVE-2022-3614](https://github.com/Live-Hack-CVE/CVE-2022-3614) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-3614.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-3614.svg)


## CVE-2022-3274
 Cross-Site Request Forgery (CSRF) in GitHub repository ikus060/rdiffweb prior to 2.4.7.

- [https://github.com/Live-Hack-CVE/CVE-2022-3274](https://github.com/Live-Hack-CVE/CVE-2022-3274) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-3274.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-3274.svg)


## CVE-2022-2967
 Prosys OPC UA Simulation Server version prior to v5.3.0-64 and UA Modbus Server versions 1.4.18-5 and prior do not sufficiently protect credentials, which could allow an attacker to obtain user credentials and gain access to system data.

- [https://github.com/Live-Hack-CVE/CVE-2022-2967](https://github.com/Live-Hack-CVE/CVE-2022-2967) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2967.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2967.svg)


## CVE-2022-0847
 A flaw was found in the way the &quot;flags&quot; member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/pmihsan/Dirty-Pipe-CVE-2022-0847](https://github.com/pmihsan/Dirty-Pipe-CVE-2022-0847) :  ![starts](https://img.shields.io/github/stars/pmihsan/Dirty-Pipe-CVE-2022-0847.svg) ![forks](https://img.shields.io/github/forks/pmihsan/Dirty-Pipe-CVE-2022-0847.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/scarmandef/CVE-2021-41773](https://github.com/scarmandef/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/scarmandef/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/scarmandef/CVE-2021-41773.svg)
- [https://github.com/McSl0vv/CVE-2021-41773](https://github.com/McSl0vv/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/McSl0vv/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/McSl0vv/CVE-2021-41773.svg)
- [https://github.com/12345qwert123456/CVE-2021-41773](https://github.com/12345qwert123456/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/12345qwert123456/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/12345qwert123456/CVE-2021-41773.svg)
- [https://github.com/Live-Hack-CVE/CVE-2021-41773](https://github.com/Live-Hack-CVE/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-41773.svg)


## CVE-2021-37706
 PJSIP is a free and open source multimedia communication library written in C language implementing standard based protocols such as SIP, SDP, RTP, STUN, TURN, and ICE. In affected versions if the incoming STUN message contains an ERROR-CODE attribute, the header length is not checked before performing a subtraction operation, potentially resulting in an integer underflow scenario. This issue affects all users that use STUN. A malicious actor located within the victim&#8217;s network may forge and send a specially crafted UDP (STUN) message that could remotely execute arbitrary code on the victim&#8217;s machine. Users are advised to upgrade as soon as possible. There are no known workarounds.

- [https://github.com/Live-Hack-CVE/CVE-2021-37706](https://github.com/Live-Hack-CVE/CVE-2021-37706) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-37706.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-37706.svg)


## CVE-2021-32824
 Apache Dubbo is a java based, open source RPC framework. Versions prior to 2.6.10 and 2.7.10 are vulnerable to pre-auth remote code execution via arbitrary bean manipulation in the Telnet handler. The Dubbo main service port can be used to access a Telnet Handler which offers some basic methods to collect information about the providers and methods exposed by the service and it can even allow to shutdown the service. This endpoint is unprotected. Additionally, a provider method can be invoked using the `invoke` handler. This handler uses a safe version of FastJson to process the call arguments. However, the resulting list is later processed with `PojoUtils.realize` which can be used to instantiate arbitrary classes and invoke its setters. Even though FastJson is properly protected with a default blocklist, `PojoUtils.realize` is not, and an attacker can leverage that to achieve remote code execution. Versions 2.6.10 and 2.7.10 contain fixes for this issue.

- [https://github.com/Live-Hack-CVE/CVE-2021-32824](https://github.com/Live-Hack-CVE/CVE-2021-32824) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-32824.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-32824.svg)


## CVE-2021-32821
 MooTools is a collection of JavaScript utilities for JavaScript developers. All known versions include a CSS selector parser that is vulnerable to Regular Expression Denial of Service (ReDoS). An attack requires that an attacker can inject a string into a CSS selector at runtime, which is quite common with e.g. jQuery CSS selectors. No patches are available for this issue.

- [https://github.com/Live-Hack-CVE/CVE-2021-32821](https://github.com/Live-Hack-CVE/CVE-2021-32821) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-32821.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-32821.svg)


## CVE-2021-3929
 A DMA reentrancy issue was found in the NVM Express Controller (NVME) emulation in QEMU. This CVE is similar to CVE-2021-3750 and, just like it, when the reentrancy write triggers the reset function nvme_ctrl_reset(), data structs will be freed leading to a use-after-free issue. A malicious guest could use this flaw to crash the QEMU process on the host, resulting in a denial of service condition or, potentially, executing arbitrary code within the context of the QEMU process on the host.

- [https://github.com/Live-Hack-CVE/CVE-2021-3929](https://github.com/Live-Hack-CVE/CVE-2021-3929) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-3929.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-3929.svg)


## CVE-2021-3291
 Zen Cart 1.5.7b allows admins to execute arbitrary OS commands by inspecting an HTML radio input element (within the modules edit page) and inserting a command.

- [https://github.com/ImHades101/CVE-2021-3291](https://github.com/ImHades101/CVE-2021-3291) :  ![starts](https://img.shields.io/github/stars/ImHades101/CVE-2021-3291.svg) ![forks](https://img.shields.io/github/forks/ImHades101/CVE-2021-3291.svg)


## CVE-2020-36639
 A vulnerability has been found in AlliedModders AMX Mod X and classified as critical. This vulnerability affects the function cmdVoteMap of the file plugins/adminvote.sma of the component Console Command Handler. The manipulation of the argument amx_votemap leads to path traversal. The name of the patch is a5f2b5539f6d61050b68df8b22ebb343a2862681. It is recommended to apply a patch to fix this issue. VDB-217354 is the identifier assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2020-36639](https://github.com/Live-Hack-CVE/CVE-2020-36639) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-36639.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-36639.svg)


## CVE-2019-25094
 A vulnerability, which was classified as problematic, was found in innologi appointments Extension up to 2.0.5. This affects an unknown part of the component Appointment Handler. The manipulation of the argument formfield leads to cross site scripting. It is possible to initiate the attack remotely. Upgrading to version 2.0.6 is able to address this issue. The name of the patch is 986d3cb34e5e086c6f04e061f600ffc5837abe7f. It is recommended to upgrade the affected component. The identifier VDB-217353 was assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2019-25094](https://github.com/Live-Hack-CVE/CVE-2019-25094) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-25094.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-25094.svg)


## CVE-2018-19320
 The GDrv low-level driver in GIGABYTE APP Center v1.05.21 and earlier, AORUS GRAPHICS ENGINE before 1.57, XTREME GAMING ENGINE before 1.26, and OC GURU II v2.08 exposes ring0 memcpy-like functionality that could allow a local attacker to take complete control of the affected system.

- [https://github.com/houseofxyz/CVE-2018-19320](https://github.com/houseofxyz/CVE-2018-19320) :  ![starts](https://img.shields.io/github/stars/houseofxyz/CVE-2018-19320.svg) ![forks](https://img.shields.io/github/forks/houseofxyz/CVE-2018-19320.svg)


## CVE-2018-16763
 FUEL CMS 1.4.1 allows PHP Code Evaluation via the pages/select/ filter parameter or the preview/ data parameter. This can lead to Pre-Auth Remote Code Execution.

- [https://github.com/not1cyyy/CVE-2018-16763](https://github.com/not1cyyy/CVE-2018-16763) :  ![starts](https://img.shields.io/github/stars/not1cyyy/CVE-2018-16763.svg) ![forks](https://img.shields.io/github/forks/not1cyyy/CVE-2018-16763.svg)


## CVE-2017-8570
 Microsoft Office allows a remote code execution vulnerability due to the way that it handles objects in memory, aka &quot;Microsoft Office Remote Code Execution Vulnerability&quot;. This CVE ID is unique from CVE-2017-0243.

- [https://github.com/5l1v3r1/rtfkit](https://github.com/5l1v3r1/rtfkit) :  ![starts](https://img.shields.io/github/stars/5l1v3r1/rtfkit.svg) ![forks](https://img.shields.io/github/forks/5l1v3r1/rtfkit.svg)


## CVE-2017-5645
 In Apache Log4j 2.x before 2.8.2, when using the TCP socket server or UDP socket server to receive serialized log events from another application, a specially crafted binary payload can be sent that, when deserialized, can execute arbitrary code.

- [https://github.com/pimps/CVE-2017-5645](https://github.com/pimps/CVE-2017-5645) :  ![starts](https://img.shields.io/github/stars/pimps/CVE-2017-5645.svg) ![forks](https://img.shields.io/github/forks/pimps/CVE-2017-5645.svg)


## CVE-2016-15008
 A vulnerability was found in oxguy3 coebot-www and classified as problematic. This issue affects the function displayChannelCommands/displayChannelQuotes/displayChannelAutoreplies/showChannelHighlights/showChannelBoir of the file js/channel.js. The manipulation leads to cross site scripting. The attack may be initiated remotely. The name of the patch is c1a6c44092585da4236237e0e7da94ee2996a0ca. It is recommended to apply a patch to fix this issue. The associated identifier of this vulnerability is VDB-217355.

- [https://github.com/Live-Hack-CVE/CVE-2016-15008](https://github.com/Live-Hack-CVE/CVE-2016-15008) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-15008.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-15008.svg)


## CVE-2016-0792
 Multiple unspecified API endpoints in Jenkins before 1.650 and LTS before 1.642.2 allow remote authenticated users to execute arbitrary code via serialized data in an XML file, related to XStream and groovy.util.Expando.

- [https://github.com/Aviksaikat/CVE-2016-0792](https://github.com/Aviksaikat/CVE-2016-0792) :  ![starts](https://img.shields.io/github/stars/Aviksaikat/CVE-2016-0792.svg) ![forks](https://img.shields.io/github/forks/Aviksaikat/CVE-2016-0792.svg)


## CVE-2014-125039
 A vulnerability, which was classified as problematic, has been found in kkokko NeoXplora. Affected by this issue is some unknown functionality of the component Trainer Handler. The manipulation leads to cross site scripting. The attack may be launched remotely. The name of the patch is dce1aecd6ee050a29f953ffd8f02f21c7c13f1e6. It is recommended to apply a patch to fix this issue. The identifier of this vulnerability is VDB-217352.

- [https://github.com/Live-Hack-CVE/CVE-2014-125039](https://github.com/Live-Hack-CVE/CVE-2014-125039) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2014-125039.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2014-125039.svg)


## CVE-2010-10003
 A vulnerability classified as critical was found in gesellix titlelink. Affected by this vulnerability is an unknown functionality of the file plugin_content_title.php. The manipulation of the argument phrase leads to sql injection. The name of the patch is b4604e523853965fa981a4e79aef4b554a535db0. It is recommended to apply a patch to fix this issue. The associated identifier of this vulnerability is VDB-217351.

- [https://github.com/Live-Hack-CVE/CVE-2010-10003](https://github.com/Live-Hack-CVE/CVE-2010-10003) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2010-10003.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2010-10003.svg)


## CVE-2006-3392
 Webmin before 1.290 and Usermin before 1.220 calls the simplify_path function before decoding HTML, which allows remote attackers to read arbitrary files, as demonstrated using &quot;..%01&quot; sequences, which bypass the removal of &quot;../&quot; sequences before bytes such as &quot;%01&quot; are removed from the filename.  NOTE: This is a different issue than CVE-2006-3274.

- [https://github.com/g1vi/CVE-2006-3392](https://github.com/g1vi/CVE-2006-3392) :  ![starts](https://img.shields.io/github/stars/g1vi/CVE-2006-3392.svg) ![forks](https://img.shields.io/github/forks/g1vi/CVE-2006-3392.svg)

