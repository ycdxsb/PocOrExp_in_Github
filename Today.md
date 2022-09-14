# Update 2022-09-14
## CVE-2022-37706
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/MaherAzzouzi/CVE-2022-37706-LPE-exploit](https://github.com/MaherAzzouzi/CVE-2022-37706-LPE-exploit) :  ![starts](https://img.shields.io/github/stars/MaherAzzouzi/CVE-2022-37706-LPE-exploit.svg) ![forks](https://img.shields.io/github/forks/MaherAzzouzi/CVE-2022-37706-LPE-exploit.svg)


## CVE-2022-36446
 software/apt-lib.pl in Webmin before 1.997 lacks HTML escaping for a UI command.

- [https://github.com/emirpolatt/CVE-2022-36446](https://github.com/emirpolatt/CVE-2022-36446) :  ![starts](https://img.shields.io/github/stars/emirpolatt/CVE-2022-36446.svg) ![forks](https://img.shields.io/github/forks/emirpolatt/CVE-2022-36446.svg)


## CVE-2022-34918
 An issue was discovered in the Linux kernel through 5.18.9. A type confusion bug in nft_set_elem_init (leading to a buffer overflow) could be used by a local attacker to escalate privileges, a different vulnerability than CVE-2022-32250. (The attacker can obtain root access, but must start with an unprivileged user namespace to obtain CAP_NET_ADMIN access.) This can be fixed in nft_setelem_parse_data in net/netfilter/nf_tables_api.c.

- [https://github.com/randorisec/CVE-2022-34918-LPE-PoC](https://github.com/randorisec/CVE-2022-34918-LPE-PoC) :  ![starts](https://img.shields.io/github/stars/randorisec/CVE-2022-34918-LPE-PoC.svg) ![forks](https://img.shields.io/github/forks/randorisec/CVE-2022-34918-LPE-PoC.svg)


## CVE-2022-32548
 An issue was discovered on certain DrayTek Vigor routers before July 2022 such as the Vigor3910 before 4.3.1.1. /cgi-bin/wlogin.cgi has a buffer overflow via the username or password to the aa or ab field.

- [https://github.com/rftg1000/CVE-2022-32548-RCE-POC](https://github.com/rftg1000/CVE-2022-32548-RCE-POC) :  ![starts](https://img.shields.io/github/stars/rftg1000/CVE-2022-32548-RCE-POC.svg) ![forks](https://img.shields.io/github/forks/rftg1000/CVE-2022-32548-RCE-POC.svg)


## CVE-2022-30075
 In TP-Link Router AX50 firmware 210730 and older, import of a malicious backup file via web interface can lead to remote code execution due to improper validation.

- [https://github.com/M4fiaB0y/CVE-2022-30075](https://github.com/M4fiaB0y/CVE-2022-30075) :  ![starts](https://img.shields.io/github/stars/M4fiaB0y/CVE-2022-30075.svg) ![forks](https://img.shields.io/github/forks/M4fiaB0y/CVE-2022-30075.svg)


## CVE-2022-27925
 Zimbra Collaboration (aka ZCS) 8.8.15 and 9.0 has mboximport functionality that receives a ZIP archive and extracts files from it. An authenticated user with administrator rights has the ability to upload arbitrary files to the system, leading to directory traversal.

- [https://github.com/akincibor/CVE-2022-27925](https://github.com/akincibor/CVE-2022-27925) :  ![starts](https://img.shields.io/github/stars/akincibor/CVE-2022-27925.svg) ![forks](https://img.shields.io/github/forks/akincibor/CVE-2022-27925.svg)


## CVE-2022-20361
 In btif_dm_auth_cmpl_evt of btif_dm.cc, there is a possible vulnerability in Cross-Transport Key Derivation due to Weakness in Bluetooth Standard. This could lead to remote escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-10 Android-11 Android-12 Android-12LAndroid ID: A-231161832

- [https://github.com/nidhi7598/system_bt_AOSP_10_r33_CVE-2022-20361](https://github.com/nidhi7598/system_bt_AOSP_10_r33_CVE-2022-20361) :  ![starts](https://img.shields.io/github/stars/nidhi7598/system_bt_AOSP_10_r33_CVE-2022-20361.svg) ![forks](https://img.shields.io/github/forks/nidhi7598/system_bt_AOSP_10_r33_CVE-2022-20361.svg)


## CVE-2022-20344
 In stealReceiveChannel of EventThread.cpp, there is a possible way to interfere with process communication due to a race condition. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-10 Android-11 Android-12 Android-12LAndroid ID: A-232541124

- [https://github.com/nidhi7598/frameworks_native_AOSP_10_r33_CVE-2022-20344](https://github.com/nidhi7598/frameworks_native_AOSP_10_r33_CVE-2022-20344) :  ![starts](https://img.shields.io/github/stars/nidhi7598/frameworks_native_AOSP_10_r33_CVE-2022-20344.svg) ![forks](https://img.shields.io/github/forks/nidhi7598/frameworks_native_AOSP_10_r33_CVE-2022-20344.svg)


## CVE-2022-2639
 An integer coercion error was found in the openvswitch kernel module. Given a sufficiently large number of actions, while copying and reserving memory for a new action of a new flow, the reserve_sfa_size() function does not return -EMSGSIZE as expected, potentially leading to an out-of-bounds write access. This flaw allows a local user to crash or potentially escalate their privileges on the system.

- [https://github.com/avboy1337/CVE-2022-2639-PipeVersion](https://github.com/avboy1337/CVE-2022-2639-PipeVersion) :  ![starts](https://img.shields.io/github/stars/avboy1337/CVE-2022-2639-PipeVersion.svg) ![forks](https://img.shields.io/github/forks/avboy1337/CVE-2022-2639-PipeVersion.svg)


## CVE-2019-17662
 ThinVNC 1.0b1 is vulnerable to arbitrary file read, which leads to a compromise of the VNC server. The vulnerability exists even when authentication is turned on during the deployment of the VNC server. The password for authentication is stored in cleartext in a file that can be read via a ../../ThinVnc.ini directory traversal attack vector.

- [https://github.com/bl4ck574r/CVE-2019-17662](https://github.com/bl4ck574r/CVE-2019-17662) :  ![starts](https://img.shields.io/github/stars/bl4ck574r/CVE-2019-17662.svg) ![forks](https://img.shields.io/github/forks/bl4ck574r/CVE-2019-17662.svg)


## CVE-2019-3929
 The Crestron AM-100 firmware 1.6.0.2, Crestron AM-101 firmware 2.7.0.1, Barco wePresent WiPG-1000P firmware 2.3.0.10, Barco wePresent WiPG-1600W before firmware 2.4.1.19, Extron ShareLink 200/250 firmware 2.0.3.4, Teq AV IT WIPS710 firmware 1.1.0.7, SHARP PN-L703WA firmware 1.4.2.3, Optoma WPS-Pro firmware 1.0.0.5, Blackbox HD WPS firmware 1.0.0.5, InFocus LiteShow3 firmware 1.0.16, and InFocus LiteShow4 2.0.0.7 are vulnerable to command injection via the file_transfer.cgi HTTP endpoint. A remote, unauthenticated attacker can use this vulnerability to execute operating system commands as root.

- [https://github.com/xfox64x/CVE-2019-3929](https://github.com/xfox64x/CVE-2019-3929) :  ![starts](https://img.shields.io/github/stars/xfox64x/CVE-2019-3929.svg) ![forks](https://img.shields.io/github/forks/xfox64x/CVE-2019-3929.svg)


## CVE-2019-0193
 In Apache Solr, the DataImportHandler, an optional but popular module to pull in data from databases and other sources, has a feature in which the whole DIH configuration can come from a request's &quot;dataConfig&quot; parameter. The debug mode of the DIH admin screen uses this to allow convenient debugging / development of a DIH config. Since a DIH config can contain scripts, this parameter is a security risk. Starting with version 8.2.0 of Solr, use of this parameter requires setting the Java System property &quot;enable.dih.dataConfigParam&quot; to true.

- [https://github.com/jdr2021/ApacheSolrRCE](https://github.com/jdr2021/ApacheSolrRCE) :  ![starts](https://img.shields.io/github/stars/jdr2021/ApacheSolrRCE.svg) ![forks](https://img.shields.io/github/forks/jdr2021/ApacheSolrRCE.svg)

