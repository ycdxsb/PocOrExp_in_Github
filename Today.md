# Update 2022-04-30
## CVE-2022-28452
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/YavuzSahbaz/Red-Planet-Laundry-Management-System-1.0-is-vulnerable-to-SQL](https://github.com/YavuzSahbaz/Red-Planet-Laundry-Management-System-1.0-is-vulnerable-to-SQL) :  ![starts](https://img.shields.io/github/stars/YavuzSahbaz/Red-Planet-Laundry-Management-System-1.0-is-vulnerable-to-SQL.svg) ![forks](https://img.shields.io/github/forks/YavuzSahbaz/Red-Planet-Laundry-Management-System-1.0-is-vulnerable-to-SQL.svg)


## CVE-2022-24449
 Solar appScreener through 3.10.4, when a valid license is not present, allows XXE and SSRF attacks via a crafted XML document.

- [https://github.com/jet-pentest/CVE-2022-24449](https://github.com/jet-pentest/CVE-2022-24449) :  ![starts](https://img.shields.io/github/stars/jet-pentest/CVE-2022-24449.svg) ![forks](https://img.shields.io/github/forks/jet-pentest/CVE-2022-24449.svg)


## CVE-2022-23990
 Expat (aka libexpat) before 2.4.4 has an integer overflow in the doProlog function.

- [https://github.com/Satheesh575555/external_expat_AOSP10_r33_CVE-2022-23990](https://github.com/Satheesh575555/external_expat_AOSP10_r33_CVE-2022-23990) :  ![starts](https://img.shields.io/github/stars/Satheesh575555/external_expat_AOSP10_r33_CVE-2022-23990.svg) ![forks](https://img.shields.io/github/forks/Satheesh575555/external_expat_AOSP10_r33_CVE-2022-23990.svg)


## CVE-2022-21728
 Tensorflow is an Open Source Machine Learning Framework. The implementation of shape inference for `ReverseSequence` does not fully validate the value of `batch_dim` and can result in a heap OOB read. There is a check to make sure the value of `batch_dim` does not go over the rank of the input, but there is no check for negative values. Negative dimensions are allowed in some cases to mimic Python's negative indexing (i.e., indexing from the end of the array), however if the value is too negative then the implementation of `Dim` would access elements before the start of an array. The fix will be included in TensorFlow 2.8.0. We will also cherrypick this commit on TensorFlow 2.7.1, TensorFlow 2.6.3, and TensorFlow 2.5.3, as these are also affected and still in supported range.

- [https://github.com/mwina/CVE-2022-21728-test](https://github.com/mwina/CVE-2022-21728-test) :  ![starts](https://img.shields.io/github/stars/mwina/CVE-2022-21728-test.svg) ![forks](https://img.shields.io/github/forks/mwina/CVE-2022-21728-test.svg)


## CVE-2022-1521
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/w1023913214/CVE-2022-15213](https://github.com/w1023913214/CVE-2022-15213) :  ![starts](https://img.shields.io/github/stars/w1023913214/CVE-2022-15213.svg) ![forks](https://img.shields.io/github/forks/w1023913214/CVE-2022-15213.svg)


## CVE-2021-39706
 In onResume of CredentialStorage.java, there is a possible way to cleanup content of credentials storage due to a missing permission check. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is needed for exploitation.Product: AndroidVersions: Android-10 Android-11 Android-12Android ID: A-200164168

- [https://github.com/Trinadh465/packages_apps_Settings_AOSP10_r33_CVE-2021-39706](https://github.com/Trinadh465/packages_apps_Settings_AOSP10_r33_CVE-2021-39706) :  ![starts](https://img.shields.io/github/stars/Trinadh465/packages_apps_Settings_AOSP10_r33_CVE-2021-39706.svg) ![forks](https://img.shields.io/github/forks/Trinadh465/packages_apps_Settings_AOSP10_r33_CVE-2021-39706.svg)


## CVE-2021-33034
 In the Linux kernel before 5.12.4, net/bluetooth/hci_event.c has a use-after-free when destroying an hci_chan, aka CID-5c4c8c954409. This leads to writing an arbitrary value.

- [https://github.com/Trinadh465/device_renesas_kernel_AOSP10_r33_CVE-2021-33034](https://github.com/Trinadh465/device_renesas_kernel_AOSP10_r33_CVE-2021-33034) :  ![starts](https://img.shields.io/github/stars/Trinadh465/device_renesas_kernel_AOSP10_r33_CVE-2021-33034.svg) ![forks](https://img.shields.io/github/forks/Trinadh465/device_renesas_kernel_AOSP10_r33_CVE-2021-33034.svg)


## CVE-2021-30937
 A memory corruption vulnerability was addressed with improved locking. This issue is fixed in macOS Big Sur 11.6.2, tvOS 15.2, macOS Monterey 12.1, Security Update 2021-008 Catalina, iOS 15.2 and iPadOS 15.2, watchOS 8.3. A malicious application may be able to execute arbitrary code with kernel privileges.

- [https://github.com/realrodri/ExploiteameEsta](https://github.com/realrodri/ExploiteameEsta) :  ![starts](https://img.shields.io/github/stars/realrodri/ExploiteameEsta.svg) ![forks](https://img.shields.io/github/forks/realrodri/ExploiteameEsta.svg)


## CVE-2021-25837
 Cosmos Network Ethermint &lt;= v0.4.0 is affected by cache lifecycle inconsistency in the EVM module. Due to the inconsistency between the Storage caching cycle and the Tx processing cycle, Storage changes caused by a failed transaction are improperly reserved in memory. Although the bad storage cache data will be discarded at EndBlock, it is still valid in the current block, which enables many possible attacks such as an &quot;arbitrary mint token&quot;.

- [https://github.com/iczc/Ethermint-CVE-2021-25837](https://github.com/iczc/Ethermint-CVE-2021-25837) :  ![starts](https://img.shields.io/github/stars/iczc/Ethermint-CVE-2021-25837.svg) ![forks](https://img.shields.io/github/forks/iczc/Ethermint-CVE-2021-25837.svg)


## CVE-2021-24507
 The Astra Pro Addon WordPress plugin before 3.5.2 did not properly sanitise or escape some of the POST parameters from the astra_pagination_infinite and astra_shop_pagination_infinite AJAX action (available to both unauthenticated and authenticated user) before using them in SQL statement, leading to an SQL Injection issues

- [https://github.com/RandomRobbieBF/CVE-2021-24507](https://github.com/RandomRobbieBF/CVE-2021-24507) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2021-24507.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2021-24507.svg)


## CVE-2021-22204
 Improper neutralization of user data in the DjVu file format in ExifTool versions 7.44 and up allows arbitrary code execution when parsing the malicious image

- [https://github.com/UNICORDev/exploit-CVE-2021-22204](https://github.com/UNICORDev/exploit-CVE-2021-22204) :  ![starts](https://img.shields.io/github/stars/UNICORDev/exploit-CVE-2021-22204.svg) ![forks](https://img.shields.io/github/forks/UNICORDev/exploit-CVE-2021-22204.svg)


## CVE-2021-4045
 TP-Link Tapo C200 IP camera, on its 1.1.15 firmware version and below, is affected by an unauthenticated RCE vulnerability, present in the uhttpd binary running by default as root. The exploitation of this vulnerability allows an attacker to take full control of the camera.

- [https://github.com/hacefresko/CVE-2021-4045-PoC](https://github.com/hacefresko/CVE-2021-4045-PoC) :  ![starts](https://img.shields.io/github/stars/hacefresko/CVE-2021-4045-PoC.svg) ![forks](https://img.shields.io/github/forks/hacefresko/CVE-2021-4045-PoC.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/dzonerzy/poc-cve-2021-4034](https://github.com/dzonerzy/poc-cve-2021-4034) :  ![starts](https://img.shields.io/github/stars/dzonerzy/poc-cve-2021-4034.svg) ![forks](https://img.shields.io/github/forks/dzonerzy/poc-cve-2021-4034.svg)
- [https://github.com/joeammond/CVE-2021-4034](https://github.com/joeammond/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/joeammond/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/joeammond/CVE-2021-4034.svg)
- [https://github.com/Nickguitar/YAPS](https://github.com/Nickguitar/YAPS) :  ![starts](https://img.shields.io/github/stars/Nickguitar/YAPS.svg) ![forks](https://img.shields.io/github/forks/Nickguitar/YAPS.svg)
- [https://github.com/DanaEpp/pwncat_pwnkit](https://github.com/DanaEpp/pwncat_pwnkit) :  ![starts](https://img.shields.io/github/stars/DanaEpp/pwncat_pwnkit.svg) ![forks](https://img.shields.io/github/forks/DanaEpp/pwncat_pwnkit.svg)
- [https://github.com/jm33-m0/go-lpe](https://github.com/jm33-m0/go-lpe) :  ![starts](https://img.shields.io/github/stars/jm33-m0/go-lpe.svg) ![forks](https://img.shields.io/github/forks/jm33-m0/go-lpe.svg)
- [https://github.com/PeterGottesman/pwnkit-exploit](https://github.com/PeterGottesman/pwnkit-exploit) :  ![starts](https://img.shields.io/github/stars/PeterGottesman/pwnkit-exploit.svg) ![forks](https://img.shields.io/github/forks/PeterGottesman/pwnkit-exploit.svg)
- [https://github.com/JohnHammond/CVE-2021-4034](https://github.com/JohnHammond/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/JohnHammond/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/JohnHammond/CVE-2021-4034.svg)
- [https://github.com/codiobert/pwnkit-scanner](https://github.com/codiobert/pwnkit-scanner) :  ![starts](https://img.shields.io/github/stars/codiobert/pwnkit-scanner.svg) ![forks](https://img.shields.io/github/forks/codiobert/pwnkit-scanner.svg)
- [https://github.com/LJP-TW/CVE-2021-4034](https://github.com/LJP-TW/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/LJP-TW/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/LJP-TW/CVE-2021-4034.svg)
- [https://github.com/HrishitJoshi/CVE-2021-4034](https://github.com/HrishitJoshi/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/HrishitJoshi/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/HrishitJoshi/CVE-2021-4034.svg)
- [https://github.com/TheJoyOfHacking/berdav-CVE-2021-4034](https://github.com/TheJoyOfHacking/berdav-CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/TheJoyOfHacking/berdav-CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/TheJoyOfHacking/berdav-CVE-2021-4034.svg)
- [https://github.com/n3onhacks/CVE-2021-4034-BASH-One-File-Exploit](https://github.com/n3onhacks/CVE-2021-4034-BASH-One-File-Exploit) :  ![starts](https://img.shields.io/github/stars/n3onhacks/CVE-2021-4034-BASH-One-File-Exploit.svg) ![forks](https://img.shields.io/github/forks/n3onhacks/CVE-2021-4034-BASH-One-File-Exploit.svg)
- [https://github.com/pengalaman-1t/CVE-2021-4034](https://github.com/pengalaman-1t/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/pengalaman-1t/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/pengalaman-1t/CVE-2021-4034.svg)
- [https://github.com/JoyGhoshs/CVE-2021-4034](https://github.com/JoyGhoshs/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/JoyGhoshs/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/JoyGhoshs/CVE-2021-4034.svg)
- [https://github.com/aus-mate/CVE-2021-4034-POC](https://github.com/aus-mate/CVE-2021-4034-POC) :  ![starts](https://img.shields.io/github/stars/aus-mate/CVE-2021-4034-POC.svg) ![forks](https://img.shields.io/github/forks/aus-mate/CVE-2021-4034-POC.svg)


## CVE-2021-0516
 In p2p_process_prov_disc_req of p2p_pd.c, there is a possible out of bounds read and write due to a use after free. This could lead to remote escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-11 Android-8.1 Android-9 Android-10Android ID: A-181660448

- [https://github.com/Satheesh575555/external_wpa_supplicant_8_AOSP10_r33_CVE-2021-0516](https://github.com/Satheesh575555/external_wpa_supplicant_8_AOSP10_r33_CVE-2021-0516) :  ![starts](https://img.shields.io/github/stars/Satheesh575555/external_wpa_supplicant_8_AOSP10_r33_CVE-2021-0516.svg) ![forks](https://img.shields.io/github/forks/Satheesh575555/external_wpa_supplicant_8_AOSP10_r33_CVE-2021-0516.svg)


## CVE-2021-0329
 In several native functions called by AdvertiseManager.java, there is a possible out of bounds write due to a missing bounds check. This could lead to local escalation of privilege in the Bluetooth server with User execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-9 Android-10 Android-11 Android-8.1Android ID: A-171400004

- [https://github.com/ShaikUsaf/packages_apps_Bluetooth_AOSP10_r33_CVE-2021-0329](https://github.com/ShaikUsaf/packages_apps_Bluetooth_AOSP10_r33_CVE-2021-0329) :  ![starts](https://img.shields.io/github/stars/ShaikUsaf/packages_apps_Bluetooth_AOSP10_r33_CVE-2021-0329.svg) ![forks](https://img.shields.io/github/forks/ShaikUsaf/packages_apps_Bluetooth_AOSP10_r33_CVE-2021-0329.svg)


## CVE-2021-0328
 In onBatchScanReports and deliverBatchScan of GattService.java, there is a possible way to retrieve Bluetooth scan results without permissions due to a missing permission check. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-10 Android-11 Android-8.1 Android-9Android ID: A-172670415

- [https://github.com/ShaikUsaf/packages_apps_Bluetooth_AOSP10_r33_CVE-2021-0328](https://github.com/ShaikUsaf/packages_apps_Bluetooth_AOSP10_r33_CVE-2021-0328) :  ![starts](https://img.shields.io/github/stars/ShaikUsaf/packages_apps_Bluetooth_AOSP10_r33_CVE-2021-0328.svg) ![forks](https://img.shields.io/github/forks/ShaikUsaf/packages_apps_Bluetooth_AOSP10_r33_CVE-2021-0328.svg)


## CVE-2020-0453
 In updateNotification of BeamTransferManager.java, there is a possible permission bypass due to an unsafe PendingIntent. This could lead to local information disclosure with User execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-9 Android-8.0 Android-8.1Android ID: A-159060474

- [https://github.com/Trinadh465/packages_apps_Nfc_AOSP10_r33_CVE-2020-0453](https://github.com/Trinadh465/packages_apps_Nfc_AOSP10_r33_CVE-2020-0453) :  ![starts](https://img.shields.io/github/stars/Trinadh465/packages_apps_Nfc_AOSP10_r33_CVE-2020-0453.svg) ![forks](https://img.shields.io/github/forks/Trinadh465/packages_apps_Nfc_AOSP10_r33_CVE-2020-0453.svg)


## CVE-2020-0452
 In exif_entry_get_value of exif-entry.c, there is a possible out of bounds write due to an integer overflow. This could lead to remote code execution if a third party app used this library to process remote image data with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-8.1 Android-9 Android-10 Android-11 Android-8.0Android ID: A-159625731

- [https://github.com/ShaikUsaf/external_libexif_AOSP10_CVE-2020-0452](https://github.com/ShaikUsaf/external_libexif_AOSP10_CVE-2020-0452) :  ![starts](https://img.shields.io/github/stars/ShaikUsaf/external_libexif_AOSP10_CVE-2020-0452.svg) ![forks](https://img.shields.io/github/forks/ShaikUsaf/external_libexif_AOSP10_CVE-2020-0452.svg)


## CVE-2020-0198
 In exif_data_load_data_content of exif-data.c, there is a possible UBSAN abort due to an integer overflow. This could lead to remote denial of service with no additional execution privileges needed. User interaction is needed for exploitation.Product: AndroidVersions: Android-10Android ID: A-146428941

- [https://github.com/Trinadh465/external_libexif_AOSP10_r33_CVE-2020-0198](https://github.com/Trinadh465/external_libexif_AOSP10_r33_CVE-2020-0198) :  ![starts](https://img.shields.io/github/stars/Trinadh465/external_libexif_AOSP10_r33_CVE-2020-0198.svg) ![forks](https://img.shields.io/github/forks/Trinadh465/external_libexif_AOSP10_r33_CVE-2020-0198.svg)


## CVE-2020-0181
 In exif_data_load_data_thumbnail of exif-data.c, there is a possible denial of service due to an integer overflow. This could lead to remote denial of service with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-10Android ID: A-145075076

- [https://github.com/Trinadh465/external_libexif_AOSP10_r33_CVE-2020-0181](https://github.com/Trinadh465/external_libexif_AOSP10_r33_CVE-2020-0181) :  ![starts](https://img.shields.io/github/stars/Trinadh465/external_libexif_AOSP10_r33_CVE-2020-0181.svg) ![forks](https://img.shields.io/github/forks/Trinadh465/external_libexif_AOSP10_r33_CVE-2020-0181.svg)


## CVE-2020-0155
 In phNxpNciHal_send_ese_hal_cmd of phNxpNciHal_ext.cc, there is a possible out of bounds write due to a missing bounds check. This could lead to local escalation of privilege with User execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-10Android ID: A-139736386

- [https://github.com/Trinadh465/hardware_nxp_nfc_AOSP10_r33_CVE-2020-0155](https://github.com/Trinadh465/hardware_nxp_nfc_AOSP10_r33_CVE-2020-0155) :  ![starts](https://img.shields.io/github/stars/Trinadh465/hardware_nxp_nfc_AOSP10_r33_CVE-2020-0155.svg) ![forks](https://img.shields.io/github/forks/Trinadh465/hardware_nxp_nfc_AOSP10_r33_CVE-2020-0155.svg)

