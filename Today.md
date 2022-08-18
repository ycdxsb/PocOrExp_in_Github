# Update 2022-08-18
## CVE-2022-36271
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/SaumyajeetDas/POC-of-CVE-2022-36271](https://github.com/SaumyajeetDas/POC-of-CVE-2022-36271) :  ![starts](https://img.shields.io/github/stars/SaumyajeetDas/POC-of-CVE-2022-36271.svg) ![forks](https://img.shields.io/github/forks/SaumyajeetDas/POC-of-CVE-2022-36271.svg)


## CVE-2022-30592
 liblsquic/lsquic_qenc_hdl.c in LiteSpeed QUIC (aka LSQUIC) before 3.1.0 mishandles MAX_TABLE_CAPACITY.

- [https://github.com/efchatz/HTTP3-attacks](https://github.com/efchatz/HTTP3-attacks) :  ![starts](https://img.shields.io/github/stars/efchatz/HTTP3-attacks.svg) ![forks](https://img.shields.io/github/forks/efchatz/HTTP3-attacks.svg)


## CVE-2022-29247
 Electron is a framework for writing cross-platform desktop applications using JavaScript (JS), HTML, and CSS. A vulnerability in versions prior to 18.0.0-beta.6, 17.2.0, 16.2.6, and 15.5.5 allows a renderer with JS execution to obtain access to a new renderer process with `nodeIntegrationInSubFrames` enabled which in turn allows effective access to `ipcRenderer`. The `nodeIntegrationInSubFrames` option does not implicitly grant Node.js access. Rather, it depends on the existing sandbox setting. If an application is sandboxed, then `nodeIntegrationInSubFrames` just gives access to the sandboxed renderer APIs, which include `ipcRenderer`. If the application then additionally exposes IPC messages without IPC `senderFrame` validation that perform privileged actions or return confidential data this access to `ipcRenderer` can in turn compromise your application / user even with the sandbox enabled. Electron versions 18.0.0-beta.6, 17.2.0, 16.2.6, and 15.5.5 contain a fix for this issue. As a workaround, ensure that all IPC message handlers appropriately validate `senderFrame`.

- [https://github.com/a1ise/CVE-2022-29247](https://github.com/a1ise/CVE-2022-29247) :  ![starts](https://img.shields.io/github/stars/a1ise/CVE-2022-29247.svg) ![forks](https://img.shields.io/github/forks/a1ise/CVE-2022-29247.svg)


## CVE-2022-20229
 In bta_hf_client_handle_cind_list_item of bta_hf_client_at.cc, there is a possible out of bounds write due to a missing bounds check. This could lead to remote code execution with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-10 Android-11 Android-12 Android-12LAndroid ID: A-224536184

- [https://github.com/ShaikUsaf/system_bt_AOSP10_r33_CVE-2022-20229](https://github.com/ShaikUsaf/system_bt_AOSP10_r33_CVE-2022-20229) :  ![starts](https://img.shields.io/github/stars/ShaikUsaf/system_bt_AOSP10_r33_CVE-2022-20229.svg) ![forks](https://img.shields.io/github/forks/ShaikUsaf/system_bt_AOSP10_r33_CVE-2022-20229.svg)


## CVE-2022-20224
 In AT_SKIP_REST of bta_hf_client_at.cc, there is a possible out of bounds read due to an incorrect bounds check. This could lead to remote information disclosure in the Bluetooth stack with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-10 Android-11 Android-12 Android-12LAndroid ID: A-220732646

- [https://github.com/ShaikUsaf/system_bt_AOSP10_r33_CVE-2022-20224](https://github.com/ShaikUsaf/system_bt_AOSP10_r33_CVE-2022-20224) :  ![starts](https://img.shields.io/github/stars/ShaikUsaf/system_bt_AOSP10_r33_CVE-2022-20224.svg) ![forks](https://img.shields.io/github/forks/ShaikUsaf/system_bt_AOSP10_r33_CVE-2022-20224.svg)


## CVE-2022-20223
 In assertSafeToStartCustomActivity of AppRestrictionsFragment.java, there is a possible way to start a phone call without permissions due to a confused deputy. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-10 Android-11 Android-12 Android-12LAndroid ID: A-223578534

- [https://github.com/nidhi7598/packages_apps_Settings_AOSP_10_r33_CVE-2022-20223](https://github.com/nidhi7598/packages_apps_Settings_AOSP_10_r33_CVE-2022-20223) :  ![starts](https://img.shields.io/github/stars/nidhi7598/packages_apps_Settings_AOSP_10_r33_CVE-2022-20223.svg) ![forks](https://img.shields.io/github/forks/nidhi7598/packages_apps_Settings_AOSP_10_r33_CVE-2022-20223.svg)


## CVE-2021-4104
 JMSAppender in Log4j 1.2 is vulnerable to deserialization of untrusted data when the attacker has write access to the Log4j configuration. The attacker can provide TopicBindingName and TopicConnectionFactoryBindingName configurations causing JMSAppender to perform JNDI requests that result in remote code execution in a similar fashion to CVE-2021-44228. Note this issue only affects Log4j 1.2 when specifically configured to use JMSAppender, which is not the default. Apache Log4j 1.2 reached end of life in August 2015. Users should upgrade to Log4j 2 as it addresses numerous other issues from the previous versions.

- [https://github.com/Qualys/log4jscanwin](https://github.com/Qualys/log4jscanwin) :  ![starts](https://img.shields.io/github/stars/Qualys/log4jscanwin.svg) ![forks](https://img.shields.io/github/forks/Qualys/log4jscanwin.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/pengalaman-1t/CVE-2021-4034](https://github.com/pengalaman-1t/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/pengalaman-1t/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/pengalaman-1t/CVE-2021-4034.svg)
- [https://github.com/JoyGhoshs/CVE-2021-4034](https://github.com/JoyGhoshs/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/JoyGhoshs/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/JoyGhoshs/CVE-2021-4034.svg)
- [https://github.com/aus-mate/CVE-2021-4034-POC](https://github.com/aus-mate/CVE-2021-4034-POC) :  ![starts](https://img.shields.io/github/stars/aus-mate/CVE-2021-4034-POC.svg) ![forks](https://img.shields.io/github/forks/aus-mate/CVE-2021-4034-POC.svg)
- [https://github.com/Silencecyber/cve-2021-4034](https://github.com/Silencecyber/cve-2021-4034) :  ![starts](https://img.shields.io/github/stars/Silencecyber/cve-2021-4034.svg) ![forks](https://img.shields.io/github/forks/Silencecyber/cve-2021-4034.svg)

