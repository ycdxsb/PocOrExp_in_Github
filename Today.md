# Update 2025-10-07
## CVE-2025-61882
 Vulnerability in the Oracle Concurrent Processing product of Oracle E-Business Suite (component: BI Publisher Integration).  Supported versions that are affected are 12.2.3-12.2.14. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Concurrent Processing.  Successful attacks of this vulnerability can result in takeover of Oracle Concurrent Processing. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/rxerium/CVE-2025-61882](https://github.com/rxerium/CVE-2025-61882) :  ![starts](https://img.shields.io/github/stars/rxerium/CVE-2025-61882.svg) ![forks](https://img.shields.io/github/forks/rxerium/CVE-2025-61882.svg)


## CVE-2025-56132
 LiquidFiles filetransfer server is vulnerable to a user enumeration issue in its password reset functionality. The application returns distinguishable responses for valid and invalid email addresses, allowing unauthenticated attackers to determine the existence of user accounts. Version 4.2 introduces user-based lockout mechanisms to mitigate brute-force attacks, user enumeration remains possible by default. In versions prior to 4.2, no such user-level protection is in place, only basic IP-based rate limiting is enforced. This IP-based protection can be bypassed by distributing requests across multiple IPs (e.g., rotating IP or proxies). Effectively bypassing both login and password reset security controls. Successful exploitation allows an attacker to enumerate valid email addresses registered for the application, increasing the risk of follow-up attacks such as password spraying.

- [https://github.com/fredericgoossens/CVE-2025-56132-Liquidfiles](https://github.com/fredericgoossens/CVE-2025-56132-Liquidfiles) :  ![starts](https://img.shields.io/github/stars/fredericgoossens/CVE-2025-56132-Liquidfiles.svg) ![forks](https://img.shields.io/github/forks/fredericgoossens/CVE-2025-56132-Liquidfiles.svg)


## CVE-2025-53770
Microsoft is preparing and fully testing a comprehensive update to address this vulnerability.  In the meantime, please make sure that the mitigation provided in this CVE documentation is in place so that you are protected from exploitation.

- [https://github.com/victormbogu1/LetsDefend-SOC342-CVE-2025-53770-SharePoint-ToolShell-Auth-Bypass-andRCE-EventID-320](https://github.com/victormbogu1/LetsDefend-SOC342-CVE-2025-53770-SharePoint-ToolShell-Auth-Bypass-andRCE-EventID-320) :  ![starts](https://img.shields.io/github/stars/victormbogu1/LetsDefend-SOC342-CVE-2025-53770-SharePoint-ToolShell-Auth-Bypass-andRCE-EventID-320.svg) ![forks](https://img.shields.io/github/forks/victormbogu1/LetsDefend-SOC342-CVE-2025-53770-SharePoint-ToolShell-Auth-Bypass-andRCE-EventID-320.svg)


## CVE-2025-52970
 A improper handling of parameters in Fortinet FortiWeb versions 7.6.3 and below, versions 7.4.7 and below, versions 7.2.10 and below, and 7.0.10 and below may allow an unauthenticated remote attacker with non-public information pertaining to the device and targeted user to gain admin privileges on the device via a specially crafted request.

- [https://github.com/imbas007/POC-CVE-2025-52970](https://github.com/imbas007/POC-CVE-2025-52970) :  ![starts](https://img.shields.io/github/stars/imbas007/POC-CVE-2025-52970.svg) ![forks](https://img.shields.io/github/forks/imbas007/POC-CVE-2025-52970.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/KaztoRay/CVE-2025-29927-Research](https://github.com/KaztoRay/CVE-2025-29927-Research) :  ![starts](https://img.shields.io/github/stars/KaztoRay/CVE-2025-29927-Research.svg) ![forks](https://img.shields.io/github/forks/KaztoRay/CVE-2025-29927-Research.svg)


## CVE-2025-6934
 The Opal Estate Pro – Property Management and Submission plugin for WordPress, used by the FullHouse - Real Estate Responsive WordPress Theme, is vulnerable to privilege escalation via in all versions up to, and including, 1.7.5. This is due to a lack of role restriction during registration in the 'on_regiser_user' function. This makes it possible for unauthenticated attackers to arbitrarily choose the role, including the Administrator role, assigned when registering.

- [https://github.com/Jenderal92/WP-CVE-2025-6934](https://github.com/Jenderal92/WP-CVE-2025-6934) :  ![starts](https://img.shields.io/github/stars/Jenderal92/WP-CVE-2025-6934.svg) ![forks](https://img.shields.io/github/forks/Jenderal92/WP-CVE-2025-6934.svg)


## CVE-2025-6554
 Type confusion in V8 in Google Chrome prior to 138.0.7204.96 allowed a remote attacker to perform arbitrary read/write via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/mistymntncop/CVE-2025-6554](https://github.com/mistymntncop/CVE-2025-6554) :  ![starts](https://img.shields.io/github/stars/mistymntncop/CVE-2025-6554.svg) ![forks](https://img.shields.io/github/forks/mistymntncop/CVE-2025-6554.svg)


## CVE-2025-5561
 A vulnerability was found in PHPGurukul Curfew e-Pass Management System 1.0. It has been declared as critical. Affected by this vulnerability is an unknown functionality of the file /admin/view-pass-detail.php. The manipulation of the argument viewid leads to sql injection. The attack can be launched remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/livepwn/CVE-2025-55616](https://github.com/livepwn/CVE-2025-55616) :  ![starts](https://img.shields.io/github/stars/livepwn/CVE-2025-55616.svg) ![forks](https://img.shields.io/github/forks/livepwn/CVE-2025-55616.svg)


## CVE-2025-2568
 The Vayu Blocks – Gutenberg Blocks for WordPress & WooCommerce plugin for WordPress is vulnerable to unauthorized access and modification of data due to missing capability checks on the 'vayu_blocks_get_toggle_switch_values_callback' and 'vayu_blocks_save_toggle_switch_callback' function in versions 1.0.4 to 1.2.1. This makes it possible for unauthenticated attackers to read plugin options and update any option with a key name ending in '_value'.

- [https://github.com/shinigami-777/PoC_CVE-2025-2568](https://github.com/shinigami-777/PoC_CVE-2025-2568) :  ![starts](https://img.shields.io/github/stars/shinigami-777/PoC_CVE-2025-2568.svg) ![forks](https://img.shields.io/github/forks/shinigami-777/PoC_CVE-2025-2568.svg)


## CVE-2024-28157
 Jenkins GitBucket Plugin 0.8 and earlier does not sanitize Gitbucket URLs on build views, resulting in a stored cross-site scripting (XSS) vulnerability exploitable by attackers able to configure jobs.

- [https://github.com/shinigami-777/PoC_CVE-2024-28157](https://github.com/shinigami-777/PoC_CVE-2024-28157) :  ![starts](https://img.shields.io/github/stars/shinigami-777/PoC_CVE-2024-28157.svg) ![forks](https://img.shields.io/github/forks/shinigami-777/PoC_CVE-2024-28157.svg)


## CVE-2024-11972
 The Hunk Companion WordPress plugin before 1.9.0 does not correctly authorize some REST API endpoints, allowing unauthenticated requests to install and activate arbitrary Hunk Companion WordPress plugin before 1.9.0 from the WordPress.org repo, including vulnerable Hunk Companion WordPress plugin before 1.9.0 that have been closed.

- [https://github.com/NoxPengwin/exploit-CVE-2024-11972](https://github.com/NoxPengwin/exploit-CVE-2024-11972) :  ![starts](https://img.shields.io/github/stars/NoxPengwin/exploit-CVE-2024-11972.svg) ![forks](https://img.shields.io/github/forks/NoxPengwin/exploit-CVE-2024-11972.svg)


## CVE-2024-3094
Through a series of complex obfuscations, the liblzma build process extracts a prebuilt object file from a disguised test file existing in the source code, which is then used to modify specific functions in the liblzma code. This results in a modified liblzma library that can be used by any software linked against this library, intercepting and modifying the data interaction with this library.

- [https://github.com/zpxlz/CVE-2024-3094](https://github.com/zpxlz/CVE-2024-3094) :  ![starts](https://img.shields.io/github/stars/zpxlz/CVE-2024-3094.svg) ![forks](https://img.shields.io/github/forks/zpxlz/CVE-2024-3094.svg)


## CVE-2023-51770
We recommend users to upgrade Apache DolphinScheduler to version 3.2.1, which fixes the issue.

- [https://github.com/shoucheng3/apache__dolphinscheduler_CVE-2023-51770_3-2-00](https://github.com/shoucheng3/apache__dolphinscheduler_CVE-2023-51770_3-2-00) :  ![starts](https://img.shields.io/github/stars/shoucheng3/apache__dolphinscheduler_CVE-2023-51770_3-2-00.svg) ![forks](https://img.shields.io/github/forks/shoucheng3/apache__dolphinscheduler_CVE-2023-51770_3-2-00.svg)


## CVE-2023-34468
You are recommended to upgrade to version 1.22.0 or later which fixes this issue.

- [https://github.com/shoucheng3/asf__nifi_CVE-2023-34468_1-21-00](https://github.com/shoucheng3/asf__nifi_CVE-2023-34468_1-21-00) :  ![starts](https://img.shields.io/github/stars/shoucheng3/asf__nifi_CVE-2023-34468_1-21-00.svg) ![forks](https://img.shields.io/github/forks/shoucheng3/asf__nifi_CVE-2023-34468_1-21-00.svg)


## CVE-2023-24057
 HL7 (Health Level 7) FHIR Core Libraries before 5.6.92 allow attackers to extract files into arbitrary directories via directory traversal from a crafted ZIP or TGZ archive (for a prepackaged terminology cache, NPM package, or comparison archive).

- [https://github.com/shoucheng3/hapifhir__org_hl7_fhir_core_CVE-2023-24057_5-6-911](https://github.com/shoucheng3/hapifhir__org_hl7_fhir_core_CVE-2023-24057_5-6-911) :  ![starts](https://img.shields.io/github/stars/shoucheng3/hapifhir__org_hl7_fhir_core_CVE-2023-24057_5-6-911.svg) ![forks](https://img.shields.io/github/forks/shoucheng3/hapifhir__org_hl7_fhir_core_CVE-2023-24057_5-6-911.svg)


## CVE-2023-5966
 An authenticated privileged attacker could upload a specially crafted zip to the EspoCRM server in version 7.2.5, via the extension deployment form, which could lead to arbitrary PHP code execution.

- [https://github.com/ll104567/cve-2023-5966](https://github.com/ll104567/cve-2023-5966) :  ![starts](https://img.shields.io/github/stars/ll104567/cve-2023-5966.svg) ![forks](https://img.shields.io/github/forks/ll104567/cve-2023-5966.svg)
- [https://github.com/josemlwdf/CVE-2023-5965](https://github.com/josemlwdf/CVE-2023-5965) :  ![starts](https://img.shields.io/github/stars/josemlwdf/CVE-2023-5965.svg) ![forks](https://img.shields.io/github/forks/josemlwdf/CVE-2023-5965.svg)


## CVE-2023-5965
 An authenticated privileged attacker could upload a specially crafted zip to the EspoCRM server in version 7.2.5, via the update form, which could lead to arbitrary PHP code execution.

- [https://github.com/josemlwdf/CVE-2023-5965](https://github.com/josemlwdf/CVE-2023-5965) :  ![starts](https://img.shields.io/github/stars/josemlwdf/CVE-2023-5965.svg) ![forks](https://img.shields.io/github/forks/josemlwdf/CVE-2023-5965.svg)


## CVE-2022-39299
 Passport-SAML is a SAML 2.0 authentication provider for Passport, the Node.js authentication library. A remote attacker may be able to bypass SAML authentication on a website using passport-saml. A successful attack requires that the attacker is in possession of an arbitrary IDP signed XML element. Depending on the IDP used, fully unauthenticated attacks (e.g without access to a valid user) might also be feasible if generation of a signed message can be triggered. Users should upgrade to passport-saml version 3.2.2 or newer. The issue was also present in the beta releases of `node-saml` before version 4.0.0-beta.5. If you cannot upgrade, disabling SAML authentication may be done as a workaround.

- [https://github.com/KaztoRay/CVE-2022-39299-Research](https://github.com/KaztoRay/CVE-2022-39299-Research) :  ![starts](https://img.shields.io/github/stars/KaztoRay/CVE-2022-39299-Research.svg) ![forks](https://img.shields.io/github/forks/KaztoRay/CVE-2022-39299-Research.svg)


## CVE-2022-33140
 The optional ShellUserGroupProvider in Apache NiFi 1.10.0 to 1.16.2 and Apache NiFi Registry 0.6.0 to 1.16.2 does not neutralize arguments for group resolution commands, allowing injection of operating system commands on Linux and macOS platforms. The ShellUserGroupProvider is not included in the default configuration. Command injection requires ShellUserGroupProvider to be one of the enabled User Group Providers in the Authorizers configuration. Command injection also requires an authenticated user with elevated privileges. Apache NiFi requires an authenticated user with authorization to modify access policies in order to execute the command. Apache NiFi Registry requires an authenticated user with authorization to read user groups in order to execute the command. The resolution removes command formatting based on user-provided arguments.

- [https://github.com/shoucheng3/apache__nifi_CVE-2022-33140_1-16-22](https://github.com/shoucheng3/apache__nifi_CVE-2022-33140_1-16-22) :  ![starts](https://img.shields.io/github/stars/shoucheng3/apache__nifi_CVE-2022-33140_1-16-22.svg) ![forks](https://img.shields.io/github/forks/shoucheng3/apache__nifi_CVE-2022-33140_1-16-22.svg)


## CVE-2022-31159
 The AWS SDK for Java enables Java developers to work with Amazon Web Services. A partial-path traversal issue exists within the `downloadDirectory` method in the AWS S3 TransferManager component of the AWS SDK for Java v1 prior to version 1.12.261. Applications using the SDK control the `destinationDirectory` argument, but S3 object keys are determined by the application that uploaded the objects. The `downloadDirectory` method allows the caller to pass a filesystem object in the object key but contained an issue in the validation logic for the key name. A knowledgeable actor could bypass the validation logic by including a UNIX double-dot in the bucket key. Under certain conditions, this could permit them to retrieve a directory from their S3 bucket that is one level up in the filesystem from their working directory. This issue’s scope is limited to directories whose name prefix matches the destinationDirectory. E.g. for destination directory`/tmp/foo`, the actor can cause a download to `/tmp/foo-bar`, but not `/tmp/bar`. If `com.amazonaws.services.s3.transfer.TransferManager::downloadDirectory` is used to download an untrusted buckets contents, the contents of that bucket can be written outside of the intended destination directory. Version 1.12.261 contains a patch for this issue. As a workaround, when calling `com.amazonaws.services.s3.transfer.TransferManager::downloadDirectory`, pass a `KeyFilter` that forbids `S3ObjectSummary` objects that `getKey` method return a string containing the substring `..` .

- [https://github.com/shoucheng3/aws__aws-sdk-java_CVE-2022-31159_1-12-2600](https://github.com/shoucheng3/aws__aws-sdk-java_CVE-2022-31159_1-12-2600) :  ![starts](https://img.shields.io/github/stars/shoucheng3/aws__aws-sdk-java_CVE-2022-31159_1-12-2600.svg) ![forks](https://img.shields.io/github/forks/shoucheng3/aws__aws-sdk-java_CVE-2022-31159_1-12-2600.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/teelrabbit/Polkit-pkexec-exploit-for-Linux](https://github.com/teelrabbit/Polkit-pkexec-exploit-for-Linux) :  ![starts](https://img.shields.io/github/stars/teelrabbit/Polkit-pkexec-exploit-for-Linux.svg) ![forks](https://img.shields.io/github/forks/teelrabbit/Polkit-pkexec-exploit-for-Linux.svg)


## CVE-2020-26217
 XStream before version 1.4.14 is vulnerable to Remote Code Execution.The vulnerability may allow a remote attacker to run arbitrary shell commands only by manipulating the processed input stream. Only users who rely on blocklists are affected. Anyone using XStream's Security Framework allowlist is not affected. The linked advisory provides code workarounds for users who cannot upgrade. The issue is fixed in version 1.4.14.

- [https://github.com/shoucheng3/x-stream__xstream_CVE-2020-26217_1-4-14-java77](https://github.com/shoucheng3/x-stream__xstream_CVE-2020-26217_1-4-14-java77) :  ![starts](https://img.shields.io/github/stars/shoucheng3/x-stream__xstream_CVE-2020-26217_1-4-14-java77.svg) ![forks](https://img.shields.io/github/forks/shoucheng3/x-stream__xstream_CVE-2020-26217_1-4-14-java77.svg)


## CVE-2019-14287
 In Sudo before 1.8.28, an attacker with access to a Runas ALL sudoer account can bypass certain policy blacklists and session PAM modules, and can cause incorrect logging, by invoking sudo with a crafted user ID. For example, this allows bypass of !root configuration, and USER= logging, for a "sudo -u \#$((0xffffffff))" command.

- [https://github.com/sachinthadesilva/Exploit-CVE-2019-14287](https://github.com/sachinthadesilva/Exploit-CVE-2019-14287) :  ![starts](https://img.shields.io/github/stars/sachinthadesilva/Exploit-CVE-2019-14287.svg) ![forks](https://img.shields.io/github/forks/sachinthadesilva/Exploit-CVE-2019-14287.svg)


## CVE-2018-16763
 FUEL CMS 1.4.1 allows PHP Code Evaluation via the pages/select/ filter parameter or the preview/ data parameter. This can lead to Pre-Auth Remote Code Execution.

- [https://github.com/Cyberuser-hash/CVE-2018-16763](https://github.com/Cyberuser-hash/CVE-2018-16763) :  ![starts](https://img.shields.io/github/stars/Cyberuser-hash/CVE-2018-16763.svg) ![forks](https://img.shields.io/github/forks/Cyberuser-hash/CVE-2018-16763.svg)

