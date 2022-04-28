# Update 2022-04-28
## CVE-2022-29464
 Certain WSO2 products allow unrestricted file upload with resultant remote code execution. The attacker must use a /fileupload endpoint with a Content-Disposition directory traversal sequence to reach a directory under the web root, such as a ../../../../repository/deployment/server/webapps directory. This affects WSO2 API Manager 2.2.0 and above through 4.0.0; WSO2 Identity Server 5.2.0 and above through 5.11.0; WSO2 Identity Server Analytics 5.4.0, 5.4.1, 5.5.0, and 5.6.0; WSO2 Identity Server as Key Manager 5.3.0 and above through 5.10.0; and WSO2 Enterprise Integrator 6.2.0 and above through 6.6.0.

- [https://github.com/lowkey0808/cve-2022-29464](https://github.com/lowkey0808/cve-2022-29464) :  ![starts](https://img.shields.io/github/stars/lowkey0808/cve-2022-29464.svg) ![forks](https://img.shields.io/github/forks/lowkey0808/cve-2022-29464.svg)


## CVE-2022-28346
 An issue was discovered in Django 2.2 before 2.2.28, 3.2 before 3.2.13, and 4.0 before 4.0.4. QuerySet.annotate(), aggregate(), and extra() methods are subject to SQL injection in column aliases via a crafted dictionary (with dictionary expansion) as the passed **kwargs.

- [https://github.com/DeEpinGh0st/CVE-2022-28346](https://github.com/DeEpinGh0st/CVE-2022-28346) :  ![starts](https://img.shields.io/github/stars/DeEpinGh0st/CVE-2022-28346.svg) ![forks](https://img.shields.io/github/forks/DeEpinGh0st/CVE-2022-28346.svg)


## CVE-2022-22947
 In spring cloud gateway versions prior to 3.1.1+ and 3.0.7+ , applications are vulnerable to a code injection attack when the Gateway Actuator endpoint is enabled, exposed and unsecured. A remote attacker could make a maliciously crafted request that could allow arbitrary remote execution on the remote host.

- [https://github.com/whwlsfb/cve-2022-22947-godzilla-memshell](https://github.com/whwlsfb/cve-2022-22947-godzilla-memshell) :  ![starts](https://img.shields.io/github/stars/whwlsfb/cve-2022-22947-godzilla-memshell.svg) ![forks](https://img.shields.io/github/forks/whwlsfb/cve-2022-22947-godzilla-memshell.svg)


## CVE-2021-39704
 In deleteNotificationChannelGroup of NotificationManagerService.java, there is a possible way to run foreground service without user notification due to a permissions bypass. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-10 Android-11 Android-12Android ID: A-209965481

- [https://github.com/nanopathi/framework_base_AOSP10_r33_CVE-2021-39704](https://github.com/nanopathi/framework_base_AOSP10_r33_CVE-2021-39704) :  ![starts](https://img.shields.io/github/stars/nanopathi/framework_base_AOSP10_r33_CVE-2021-39704.svg) ![forks](https://img.shields.io/github/forks/nanopathi/framework_base_AOSP10_r33_CVE-2021-39704.svg)


## CVE-2021-39692
 In onCreate of SetupLayoutActivity.java, there is a possible way to setup a work profile bypassing user consent due to a tapjacking/overlay attack. This could lead to local escalation of privilege with User execution privileges needed. User interaction is needed for exploitation.Product: AndroidVersions: Android-10 Android-11 Android-12Android ID: A-209611539

- [https://github.com/nanopathi/packages_apps_ManagedProvisioning_CVE-2021-39692](https://github.com/nanopathi/packages_apps_ManagedProvisioning_CVE-2021-39692) :  ![starts](https://img.shields.io/github/stars/nanopathi/packages_apps_ManagedProvisioning_CVE-2021-39692.svg) ![forks](https://img.shields.io/github/forks/nanopathi/packages_apps_ManagedProvisioning_CVE-2021-39692.svg)


## CVE-2021-36394
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/lavclash75/CVE-2021-36394-Pre-Auth-RCE-in-Moodle](https://github.com/lavclash75/CVE-2021-36394-Pre-Auth-RCE-in-Moodle) :  ![starts](https://img.shields.io/github/stars/lavclash75/CVE-2021-36394-Pre-Auth-RCE-in-Moodle.svg) ![forks](https://img.shields.io/github/forks/lavclash75/CVE-2021-36394-Pre-Auth-RCE-in-Moodle.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/0x4ndy/CVE-2021-4034-PoC](https://github.com/0x4ndy/CVE-2021-4034-PoC) :  ![starts](https://img.shields.io/github/stars/0x4ndy/CVE-2021-4034-PoC.svg) ![forks](https://img.shields.io/github/forks/0x4ndy/CVE-2021-4034-PoC.svg)


## CVE-2021-3347
 An issue was discovered in the Linux kernel through 5.10.11. PI futexes have a kernel stack use-after-free during fault handling, allowing local users to execute code in the kernel, aka CID-34b1a1ce1458.

- [https://github.com/nanopathi/linux-4.19.72_CVE-2021-3347](https://github.com/nanopathi/linux-4.19.72_CVE-2021-3347) :  ![starts](https://img.shields.io/github/stars/nanopathi/linux-4.19.72_CVE-2021-3347.svg) ![forks](https://img.shields.io/github/forks/nanopathi/linux-4.19.72_CVE-2021-3347.svg)


## CVE-2021-0394
 In android_os_Parcel_readString8 of android_os_Parcel.cpp, there is a possible out of bounds read due to a missing bounds check. This could lead to local information disclosure with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-11 Android-8.1 Android-9 Android-10Android ID: A-172655291

- [https://github.com/nanopathi/packages_apps_Settings_CVE-2021-0394](https://github.com/nanopathi/packages_apps_Settings_CVE-2021-0394) :  ![starts](https://img.shields.io/github/stars/nanopathi/packages_apps_Settings_CVE-2021-0394.svg) ![forks](https://img.shields.io/github/forks/nanopathi/packages_apps_Settings_CVE-2021-0394.svg)


## CVE-2021-0326
 In p2p_copy_client_info of p2p.c, there is a possible out of bounds write due to a missing bounds check. This could lead to remote code execution if the target device is performing a Wi-Fi Direct search, with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-10 Android-11 Android-8.1 Android-9Android ID: A-172937525

- [https://github.com/nanopathi/wpa_supplicant_8_CVE-2021-0326.](https://github.com/nanopathi/wpa_supplicant_8_CVE-2021-0326.) :  ![starts](https://img.shields.io/github/stars/nanopathi/wpa_supplicant_8_CVE-2021-0326..svg) ![forks](https://img.shields.io/github/forks/nanopathi/wpa_supplicant_8_CVE-2021-0326..svg)
- [https://github.com/nanopathi/Packages_wpa_supplicant8_CVE-2021-0326](https://github.com/nanopathi/Packages_wpa_supplicant8_CVE-2021-0326) :  ![starts](https://img.shields.io/github/stars/nanopathi/Packages_wpa_supplicant8_CVE-2021-0326.svg) ![forks](https://img.shields.io/github/forks/nanopathi/Packages_wpa_supplicant8_CVE-2021-0326.svg)
- [https://github.com/Satheesh575555/external_wpa_supplicant_8_AOSP10_r33_CVE-2021-0326](https://github.com/Satheesh575555/external_wpa_supplicant_8_AOSP10_r33_CVE-2021-0326) :  ![starts](https://img.shields.io/github/stars/Satheesh575555/external_wpa_supplicant_8_AOSP10_r33_CVE-2021-0326.svg) ![forks](https://img.shields.io/github/forks/Satheesh575555/external_wpa_supplicant_8_AOSP10_r33_CVE-2021-0326.svg)


## CVE-2021-0315
 In onCreate of GrantCredentialsPermissionActivity.java, there is a possible way to convince the user to grant an app access to an account due to a tapjacking/overlay attack. This could lead to local escalation of privilege with User execution privileges needed. User interaction is needed for exploitation. Product: Android; Versions: Android-8.1, Android-9, Android-10, Android-11, Android-8.0; Android ID: A-169763814.

- [https://github.com/nanopathi/framework_base_AOSP10_r33_CVE-2021-0315](https://github.com/nanopathi/framework_base_AOSP10_r33_CVE-2021-0315) :  ![starts](https://img.shields.io/github/stars/nanopathi/framework_base_AOSP10_r33_CVE-2021-0315.svg) ![forks](https://img.shields.io/github/forks/nanopathi/framework_base_AOSP10_r33_CVE-2021-0315.svg)
- [https://github.com/pazhanivel07/frameworks_base_Aosp10_r33_CVE-2021-0315](https://github.com/pazhanivel07/frameworks_base_Aosp10_r33_CVE-2021-0315) :  ![starts](https://img.shields.io/github/stars/pazhanivel07/frameworks_base_Aosp10_r33_CVE-2021-0315.svg) ![forks](https://img.shields.io/github/forks/pazhanivel07/frameworks_base_Aosp10_r33_CVE-2021-0315.svg)
- [https://github.com/nanopathi/-home-administrator-Desktop-CVE-2021-0315-base-13758c1cf243851b2821c3a9596c84a9d967c9ec.tar.gz](https://github.com/nanopathi/-home-administrator-Desktop-CVE-2021-0315-base-13758c1cf243851b2821c3a9596c84a9d967c9ec.tar.gz) :  ![starts](https://img.shields.io/github/stars/nanopathi/-home-administrator-Desktop-CVE-2021-0315-base-13758c1cf243851b2821c3a9596c84a9d967c9ec.tar.gz.svg) ![forks](https://img.shields.io/github/forks/nanopathi/-home-administrator-Desktop-CVE-2021-0315-base-13758c1cf243851b2821c3a9596c84a9d967c9ec.tar.gz.svg)


## CVE-2020-0394
 In onCreate of BluetoothPairingDialog.java, there is a possible tapjacking vector due to an insecure default value. This could lead to local escalation of privilege and untrusted devices accessing contact lists with no additional execution privileges needed. User interaction is needed for exploitation.Product: AndroidVersions: Android-8.0 Android-8.1 Android-9 Android-10 Android-11Android ID: A-155648639

- [https://github.com/pazhanivel07/Settings_10-r33_CVE-2020-0394](https://github.com/pazhanivel07/Settings_10-r33_CVE-2020-0394) :  ![starts](https://img.shields.io/github/stars/pazhanivel07/Settings_10-r33_CVE-2020-0394.svg) ![forks](https://img.shields.io/github/forks/pazhanivel07/Settings_10-r33_CVE-2020-0394.svg)
- [https://github.com/pazhanivel07/Settings_10-r33_CVE-2020-0394_02](https://github.com/pazhanivel07/Settings_10-r33_CVE-2020-0394_02) :  ![starts](https://img.shields.io/github/stars/pazhanivel07/Settings_10-r33_CVE-2020-0394_02.svg) ![forks](https://img.shields.io/github/forks/pazhanivel07/Settings_10-r33_CVE-2020-0394_02.svg)


## CVE-2019-13272
 In the Linux kernel before 5.1.17, ptrace_link in kernel/ptrace.c mishandles the recording of the credentials of a process that wants to create a ptrace relationship, which allows local users to obtain root access by leveraging certain scenarios with a parent-child process relationship, where a parent drops privileges and calls execve (potentially allowing control by an attacker). One contributing factor is an object lifetime issue (which can also cause a panic). Another contributing factor is incorrect marking of a ptrace relationship as privileged, which is exploitable through (for example) Polkit's pkexec helper with PTRACE_TRACEME. NOTE: SELinux deny_ptrace might be a usable workaround in some environments.

- [https://github.com/RashmikaEkanayake/Privilege-Escalation-CVE-2019-13272-](https://github.com/RashmikaEkanayake/Privilege-Escalation-CVE-2019-13272-) :  ![starts](https://img.shields.io/github/stars/RashmikaEkanayake/Privilege-Escalation-CVE-2019-13272-.svg) ![forks](https://img.shields.io/github/forks/RashmikaEkanayake/Privilege-Escalation-CVE-2019-13272-.svg)


## CVE-2019-5624
 Rapid7 Metasploit Framework suffers from an instance of CWE-22, Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in the Zip import function of Metasploit. Exploiting this vulnerability can allow an attacker to execute arbitrary code in Metasploit at the privilege level of the user running Metasploit. This issue affects: Rapid7 Metasploit Framework version 4.14.0 and prior versions.

- [https://github.com/VoidSec/CVE-2019-5624](https://github.com/VoidSec/CVE-2019-5624) :  ![starts](https://img.shields.io/github/stars/VoidSec/CVE-2019-5624.svg) ![forks](https://img.shields.io/github/forks/VoidSec/CVE-2019-5624.svg)


## CVE-2019-1130
 An elevation of privilege vulnerability exists when Windows AppX Deployment Service (AppXSVC) improperly handles hard links, aka 'Windows Elevation of Privilege Vulnerability'. This CVE ID is unique from CVE-2019-1129.

- [https://github.com/S3cur3Th1sSh1t/SharpByeBear](https://github.com/S3cur3Th1sSh1t/SharpByeBear) :  ![starts](https://img.shields.io/github/stars/S3cur3Th1sSh1t/SharpByeBear.svg) ![forks](https://img.shields.io/github/forks/S3cur3Th1sSh1t/SharpByeBear.svg)


## CVE-2016-4656
 The kernel in Apple iOS before 9.3.5 allows attackers to execute arbitrary code in a privileged context or cause a denial of service (memory corruption) via a crafted app.

- [https://github.com/liangle1986126z/jndok](https://github.com/liangle1986126z/jndok) :  ![starts](https://img.shields.io/github/stars/liangle1986126z/jndok.svg) ![forks](https://img.shields.io/github/forks/liangle1986126z/jndok.svg)


## CVE-2016-4655
 The kernel in Apple iOS before 9.3.5 allows attackers to obtain sensitive information from memory via a crafted app.

- [https://github.com/liangle1986126z/jndok](https://github.com/liangle1986126z/jndok) :  ![starts](https://img.shields.io/github/stars/liangle1986126z/jndok.svg) ![forks](https://img.shields.io/github/forks/liangle1986126z/jndok.svg)

