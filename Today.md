# Update 2026-10-28
## CVE-2026-116488
 NXP MCUXpresso SDK USB middleware (mcuxsdk-middleware-usb) before 2.13.0 contains a heap buffer overflow in host audio, video and CDC class drivers that trust device-supplied bNumEndpoints and bLength values. A malicious USB device can supply crafted descriptors that write endpoint entries past the fixed-size epList array, corrupting heap memory for code execution or denial of service.

- [https://github.com/D7EAD/CVE-2026-116488](https://github.com/D7EAD/CVE-2026-116488) :  ![starts](https://img.shields.io/github/stars/D7EAD/CVE-2026-116488.svg) ![forks](https://img.shields.io/github/forks/D7EAD/CVE-2026-116488.svg)


## CVE-2026-116487
 NXP MCUXpresso SDK USB middleware (mcuxsdk-middleware-usb) before 2.13.0 contains an out-of-bounds read vulnerability in USB_DeviceCdcRndisSetCommand() that trusts a host-supplied informationBufferOffset. A malicious USB host can send RNDIS SET messages for OID_GEN_CURRENT_PACKET_FILTER or OID_802_3_MULTICAST_LIST with an out-of-range offset to read and disclose device memory.

- [https://github.com/D7EAD/CVE-2026-116487](https://github.com/D7EAD/CVE-2026-116487) :  ![starts](https://img.shields.io/github/stars/D7EAD/CVE-2026-116487.svg) ![forks](https://img.shields.io/github/forks/D7EAD/CVE-2026-116487.svg)


## CVE-2026-116370
 A security flaw has been discovered in 2K Games Sid Meier's Civilization IV 1.0.12.68. The affected element is the function loadstring of the component Lua sandbox. Performing a manipulation results in type confusion. The attack may be initiated remotely. The exploit has been released to the public and may be used for attacks. The vendor was contacted early about this disclosure.

- [https://github.com/drbloop2000/Sid-Meier-s-Civilization-VI-RCE](https://github.com/drbloop2000/Sid-Meier-s-Civilization-VI-RCE) :  ![starts](https://img.shields.io/github/stars/drbloop2000/Sid-Meier-s-Civilization-VI-RCE.svg) ![forks](https://img.shields.io/github/forks/drbloop2000/Sid-Meier-s-Civilization-VI-RCE.svg)


## CVE-2026-116106
 A security vulnerability has been detected in HeyCyan App 1.0.103 on Android. Affected by this vulnerability is an unknown functionality of the component FileProvider. The manipulation leads to improper access controls. The attack may be initiated remotely. The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/ohackercego/CVE-2026-116106](https://github.com/ohackercego/CVE-2026-116106) :  ![starts](https://img.shields.io/github/stars/ohackercego/CVE-2026-116106.svg) ![forks](https://img.shields.io/github/forks/ohackercego/CVE-2026-116106.svg)


## CVE-2026-116105
 A weakness has been identified in HeyCyan App 1.0.103 on Android. Affected is an unknown function of the file AndroidManifest.xml of the component Network Security Configuration. Executing a manipulation can lead to cleartext transmission of sensitive information. The attack can be launched remotely. The attack requires a high level of complexity. The exploitability is told to be difficult. The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/ohackercego/CVE-2026-116105](https://github.com/ohackercego/CVE-2026-116105) :  ![starts](https://img.shields.io/github/stars/ohackercego/CVE-2026-116105.svg) ![forks](https://img.shields.io/github/forks/ohackercego/CVE-2026-116105.svg)


## CVE-2026-116063
 A weakness has been identified in DedeCMS up to 5.7.118. Impacted is the function require_once of the file dede/update_guide.php. This manipulation of the argument vtime causes code injection. Remote exploitation of the attack is possible. The exploit has been made available to the public and could be used for attacks.

- [https://github.com/SDshadow/CVE-2026-116063](https://github.com/SDshadow/CVE-2026-116063) :  ![starts](https://img.shields.io/github/stars/SDshadow/CVE-2026-116063.svg) ![forks](https://img.shields.io/github/forks/SDshadow/CVE-2026-116063.svg)


## CVE-2026-116004
 A security vulnerability has been detected in onyx-dot-app Onyx up to 5.0.0. Impacted is an unknown function of the file web/src/app/craft/components/output-panel/PreviewTab.tsx. The manipulation leads to cross site scripting. The attack can be initiated remotely. The exploit has been disclosed publicly and may be used. The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/capivara-research/CVE-2026-116004](https://github.com/capivara-research/CVE-2026-116004) :  ![starts](https://img.shields.io/github/stars/capivara-research/CVE-2026-116004.svg) ![forks](https://img.shields.io/github/forks/capivara-research/CVE-2026-116004.svg)


## CVE-2026-116000
 A security flaw has been discovered in Zylon PrivateGPT 1.0.0/1.0.1. This vulnerability affects the function load_file_from_uri of the file private_gpt/server/ingest/uri_loader.py of the component URI Artifact Loader. Performing a manipulation of the argument Value results in server-side request forgery. It is possible to initiate the attack remotely. The exploit has been released to the public and may be used for attacks. The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/capivara-research/CVE-2026-116000](https://github.com/capivara-research/CVE-2026-116000) :  ![starts](https://img.shields.io/github/stars/capivara-research/CVE-2026-116000.svg) ![forks](https://img.shields.io/github/forks/capivara-research/CVE-2026-116000.svg)


## CVE-2026-111497
Users need to update any Brotli libraries or binaries between 1.0.3 through 1.2.0 to the latest available version: 1.0.10 or 1.1.1 or 1.2.1.

- [https://github.com/0xBlackash/CVE-2026-111497](https://github.com/0xBlackash/CVE-2026-111497) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-111497.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-111497.svg)
- [https://github.com/axisops/CVE-2026-111497](https://github.com/axisops/CVE-2026-111497) :  ![starts](https://img.shields.io/github/stars/axisops/CVE-2026-111497.svg) ![forks](https://img.shields.io/github/forks/axisops/CVE-2026-111497.svg)
- [https://github.com/piecar21/CVE-2026-111497](https://github.com/piecar21/CVE-2026-111497) :  ![starts](https://img.shields.io/github/stars/piecar21/CVE-2026-111497.svg) ![forks](https://img.shields.io/github/forks/piecar21/CVE-2026-111497.svg)
- [https://github.com/AdapptOnAzure/CVE-2026-111497-DotNetBrotliScan](https://github.com/AdapptOnAzure/CVE-2026-111497-DotNetBrotliScan) :  ![starts](https://img.shields.io/github/stars/AdapptOnAzure/CVE-2026-111497-DotNetBrotliScan.svg) ![forks](https://img.shields.io/github/forks/AdapptOnAzure/CVE-2026-111497-DotNetBrotliScan.svg)
- [https://github.com/jeffschafer/Bigfix-NodeJS-Vulnerability-Scanner-Content-CVE-2026-111497](https://github.com/jeffschafer/Bigfix-NodeJS-Vulnerability-Scanner-Content-CVE-2026-111497) :  ![starts](https://img.shields.io/github/stars/jeffschafer/Bigfix-NodeJS-Vulnerability-Scanner-Content-CVE-2026-111497.svg) ![forks](https://img.shields.io/github/forks/jeffschafer/Bigfix-NodeJS-Vulnerability-Scanner-Content-CVE-2026-111497.svg)
- [https://github.com/bastet-ai/brotli-firing-range](https://github.com/bastet-ai/brotli-firing-range) :  ![starts](https://img.shields.io/github/stars/bastet-ai/brotli-firing-range.svg) ![forks](https://img.shields.io/github/forks/bastet-ai/brotli-firing-range.svg)
- [https://github.com/amier-ge/node2shell-checker](https://github.com/amier-ge/node2shell-checker) :  ![starts](https://img.shields.io/github/stars/amier-ge/node2shell-checker.svg) ![forks](https://img.shields.io/github/forks/amier-ge/node2shell-checker.svg)
- [https://github.com/queso/formbricks-patched](https://github.com/queso/formbricks-patched) :  ![starts](https://img.shields.io/github/stars/queso/formbricks-patched.svg) ![forks](https://img.shields.io/github/forks/queso/formbricks-patched.svg)
- [https://github.com/datmt/vulcheck](https://github.com/datmt/vulcheck) :  ![starts](https://img.shields.io/github/stars/datmt/vulcheck.svg) ![forks](https://img.shields.io/github/forks/datmt/vulcheck.svg)
- [https://github.com/FranklinF25/http2shell](https://github.com/FranklinF25/http2shell) :  ![starts](https://img.shields.io/github/stars/FranklinF25/http2shell.svg) ![forks](https://img.shields.io/github/forks/FranklinF25/http2shell.svg)
- [https://github.com/CompleTetech-Security/http2shell-check](https://github.com/CompleTetech-Security/http2shell-check) :  ![starts](https://img.shields.io/github/stars/CompleTetech-Security/http2shell-check.svg) ![forks](https://img.shields.io/github/forks/CompleTetech-Security/http2shell-check.svg)
- [https://github.com/ionsec/node2shell-detector](https://github.com/ionsec/node2shell-detector) :  ![starts](https://img.shields.io/github/stars/ionsec/node2shell-detector.svg) ![forks](https://img.shields.io/github/forks/ionsec/node2shell-detector.svg)


## CVE-2026-109619
 PHP has various global state that temporarily points into request memory. In some scenarios, global state may not be correctly reset, or may be repopulated after being reset. The global state may then refer to request memory even after it has been freed. Subsequent requests may read or branch on this stale state before it is fully initialized. Multiple strategies can trigger this condition and produce remote code execution (RCE).

- [https://github.com/cumakurt/php2shell-scan](https://github.com/cumakurt/php2shell-scan) :  ![starts](https://img.shields.io/github/stars/cumakurt/php2shell-scan.svg) ![forks](https://img.shields.io/github/forks/cumakurt/php2shell-scan.svg)
- [https://github.com/softjapan/php74-cve-patched](https://github.com/softjapan/php74-cve-patched) :  ![starts](https://img.shields.io/github/stars/softjapan/php74-cve-patched.svg) ![forks](https://img.shields.io/github/forks/softjapan/php74-cve-patched.svg)
- [https://github.com/dev-maple/php2shell-CVE-2026-109619](https://github.com/dev-maple/php2shell-CVE-2026-109619) :  ![starts](https://img.shields.io/github/stars/dev-maple/php2shell-CVE-2026-109619.svg) ![forks](https://img.shields.io/github/forks/dev-maple/php2shell-CVE-2026-109619.svg)
- [https://github.com/zake1god/php2shell](https://github.com/zake1god/php2shell) :  ![starts](https://img.shields.io/github/stars/zake1god/php2shell.svg) ![forks](https://img.shields.io/github/forks/zake1god/php2shell.svg)
- [https://github.com/Secragon/php2shell-radar](https://github.com/Secragon/php2shell-radar) :  ![starts](https://img.shields.io/github/stars/Secragon/php2shell-radar.svg) ![forks](https://img.shields.io/github/forks/Secragon/php2shell-radar.svg)
- [https://github.com/naravid19/php2shell-ioc](https://github.com/naravid19/php2shell-ioc) :  ![starts](https://img.shields.io/github/stars/naravid19/php2shell-ioc.svg) ![forks](https://img.shields.io/github/forks/naravid19/php2shell-ioc.svg)
- [https://github.com/kjry8sb/php2shell-wordpress-rce-fullchain](https://github.com/kjry8sb/php2shell-wordpress-rce-fullchain) :  ![starts](https://img.shields.io/github/stars/kjry8sb/php2shell-wordpress-rce-fullchain.svg) ![forks](https://img.shields.io/github/forks/kjry8sb/php2shell-wordpress-rce-fullchain.svg)


## CVE-2026-109618
 PHP uses longjmp() for out-of-memory (OOM) errors to exit the current context and abort handling of the request. Some contexts may not properly account for this scenario and leave request memory in an uninitialized state before performing an allocation. The subsequent request cleanup procedure may read or branch on this memory. Multiple OOM strategies can consistently trigger this condition and lead to remote code execution (RCE).

- [https://github.com/cumakurt/php2shell-scan](https://github.com/cumakurt/php2shell-scan) :  ![starts](https://img.shields.io/github/stars/cumakurt/php2shell-scan.svg) ![forks](https://img.shields.io/github/forks/cumakurt/php2shell-scan.svg)
- [https://github.com/softjapan/php74-cve-patched](https://github.com/softjapan/php74-cve-patched) :  ![starts](https://img.shields.io/github/stars/softjapan/php74-cve-patched.svg) ![forks](https://img.shields.io/github/forks/softjapan/php74-cve-patched.svg)
- [https://github.com/ggsec-de/php2shell-analysis](https://github.com/ggsec-de/php2shell-analysis) :  ![starts](https://img.shields.io/github/stars/ggsec-de/php2shell-analysis.svg) ![forks](https://img.shields.io/github/forks/ggsec-de/php2shell-analysis.svg)
- [https://github.com/Ethen1212/php2shell-CVE-2026-109618](https://github.com/Ethen1212/php2shell-CVE-2026-109618) :  ![starts](https://img.shields.io/github/stars/Ethen1212/php2shell-CVE-2026-109618.svg) ![forks](https://img.shields.io/github/forks/Ethen1212/php2shell-CVE-2026-109618.svg)
- [https://github.com/meuhland/php-legacy-windows-builds](https://github.com/meuhland/php-legacy-windows-builds) :  ![starts](https://img.shields.io/github/stars/meuhland/php-legacy-windows-builds.svg) ![forks](https://img.shields.io/github/forks/meuhland/php-legacy-windows-builds.svg)
- [https://github.com/EngOREOO/php2shell-CVE-2026-109618-CVE-2026-109619-PoC](https://github.com/EngOREOO/php2shell-CVE-2026-109618-CVE-2026-109619-PoC) :  ![starts](https://img.shields.io/github/stars/EngOREOO/php2shell-CVE-2026-109618-CVE-2026-109619-PoC.svg) ![forks](https://img.shields.io/github/forks/EngOREOO/php2shell-CVE-2026-109618-CVE-2026-109619-PoC.svg)
- [https://github.com/Andrew2142/php73-backport](https://github.com/Andrew2142/php73-backport) :  ![starts](https://img.shields.io/github/stars/Andrew2142/php73-backport.svg) ![forks](https://img.shields.io/github/forks/Andrew2142/php73-backport.svg)
- [https://github.com/eagleofanadolu/php2shell-poc](https://github.com/eagleofanadolu/php2shell-poc) :  ![starts](https://img.shields.io/github/stars/eagleofanadolu/php2shell-poc.svg) ![forks](https://img.shields.io/github/forks/eagleofanadolu/php2shell-poc.svg)
- [https://github.com/seppegadeyne/php2shell-runcloud-builds](https://github.com/seppegadeyne/php2shell-runcloud-builds) :  ![starts](https://img.shields.io/github/stars/seppegadeyne/php2shell-runcloud-builds.svg) ![forks](https://img.shields.io/github/forks/seppegadeyne/php2shell-runcloud-builds.svg)


## CVE-2026-107656
 An authentication bypass using an alternate path or channel vulnerability in Fortinet FortiSandbox 5.0.0 through 5.0.6, FortiSandbox 4.4.0 through 4.4.9, FortiSandbox 4.2 all versions, FortiSandbox PaaS 5.0.0 through 5.0.6, FortiSandbox PaaS 4.4 all versions, FortiSandbox PaaS 4.2 all versions may allow attacker to execute unauthorized code or commands via crafted HTTP requests

- [https://github.com/Ghost-Bx1/Fortinet-Exploits-CVE-2026-39808-106173-107656](https://github.com/Ghost-Bx1/Fortinet-Exploits-CVE-2026-39808-106173-107656) :  ![starts](https://img.shields.io/github/stars/Ghost-Bx1/Fortinet-Exploits-CVE-2026-39808-106173-107656.svg) ![forks](https://img.shields.io/github/forks/Ghost-Bx1/Fortinet-Exploits-CVE-2026-39808-106173-107656.svg)


## CVE-2026-107092
 NexoPOS v6.2.4 is vulnerable to Directory Traversal via the api/update endpoint.

- [https://github.com/raivenLockdown/CVE-2026-107092](https://github.com/raivenLockdown/CVE-2026-107092) :  ![starts](https://img.shields.io/github/stars/raivenLockdown/CVE-2026-107092.svg) ![forks](https://img.shields.io/github/forks/raivenLockdown/CVE-2026-107092.svg)


## CVE-2026-106781
 An issue in WCH CH340/CH341 USB-to-Serial Windows Driver setup package CH341SER.EXE version 4.0 allows a local attacker to escalate privileges.

- [https://github.com/tanuj8124/CVE-2026-106781](https://github.com/tanuj8124/CVE-2026-106781) :  ![starts](https://img.shields.io/github/stars/tanuj8124/CVE-2026-106781.svg) ![forks](https://img.shields.io/github/forks/tanuj8124/CVE-2026-106781.svg)


## CVE-2026-106173
 A improper limitation of a pathname to a restricted directory ('path traversal') vulnerability in Fortinet FortiSIEM 7.5.0 may allow attacker to execute unauthorized code or commands via specially crafted packets.

- [https://github.com/aduli198/CVE-2026-106173](https://github.com/aduli198/CVE-2026-106173) :  ![starts](https://img.shields.io/github/stars/aduli198/CVE-2026-106173.svg) ![forks](https://img.shields.io/github/forks/aduli198/CVE-2026-106173.svg)


## CVE-2026-101767
 Vulnerability in the Oracle Application Object Library product of Oracle E-Business Suite (component: Core).  Supported versions that are affected are 12.2.3-12.2.15. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Application Object Library.  Successful attacks of this vulnerability can result in takeover of Oracle Application Object Library. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/0xBlackash/CVE-2026-101767](https://github.com/0xBlackash/CVE-2026-101767) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-101767.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-101767.svg)
- [https://github.com/seck19/CVE-2026-101767-POC](https://github.com/seck19/CVE-2026-101767-POC) :  ![starts](https://img.shields.io/github/stars/seck19/CVE-2026-101767-POC.svg) ![forks](https://img.shields.io/github/forks/seck19/CVE-2026-101767-POC.svg)


## CVE-2026-98260
[ tglx: Move the cleanup right after de_thread() ]

- [https://github.com/Lw5959/xring-cve-2026-98260](https://github.com/Lw5959/xring-cve-2026-98260) :  ![starts](https://img.shields.io/github/stars/Lw5959/xring-cve-2026-98260.svg) ![forks](https://img.shields.io/github/forks/Lw5959/xring-cve-2026-98260.svg)
- [https://github.com/AzirX1337/CVE-2026-98260-OnePlus16-PYB110-Jailbreak](https://github.com/AzirX1337/CVE-2026-98260-OnePlus16-PYB110-Jailbreak) :  ![starts](https://img.shields.io/github/stars/AzirX1337/CVE-2026-98260-OnePlus16-PYB110-Jailbreak.svg) ![forks](https://img.shields.io/github/forks/AzirX1337/CVE-2026-98260-OnePlus16-PYB110-Jailbreak.svg)
- [https://github.com/woshigenm/CVE-2026-98260](https://github.com/woshigenm/CVE-2026-98260) :  ![starts](https://img.shields.io/github/stars/woshigenm/CVE-2026-98260.svg) ![forks](https://img.shields.io/github/forks/woshigenm/CVE-2026-98260.svg)
- [https://github.com/villager1314/CVE-2026-98260-Analysis](https://github.com/villager1314/CVE-2026-98260-Analysis) :  ![starts](https://img.shields.io/github/stars/villager1314/CVE-2026-98260-Analysis.svg) ![forks](https://img.shields.io/github/forks/villager1314/CVE-2026-98260-Analysis.svg)
- [https://github.com/addxemmm/CVE-2026-98260-pudding-android](https://github.com/addxemmm/CVE-2026-98260-pudding-android) :  ![starts](https://img.shields.io/github/stars/addxemmm/CVE-2026-98260-pudding-android.svg) ![forks](https://img.shields.io/github/forks/addxemmm/CVE-2026-98260-pudding-android.svg)
- [https://github.com/ChaYeWuu/prague-CVE-2026-98260-OS4.0](https://github.com/ChaYeWuu/prague-CVE-2026-98260-OS4.0) :  ![starts](https://img.shields.io/github/stars/ChaYeWuu/prague-CVE-2026-98260-OS4.0.svg) ![forks](https://img.shields.io/github/forks/ChaYeWuu/prague-CVE-2026-98260-OS4.0.svg)
- [https://github.com/ChaYeWuu/violin-CVE-2026-98260-OS4.0](https://github.com/ChaYeWuu/violin-CVE-2026-98260-OS4.0) :  ![starts](https://img.shields.io/github/stars/ChaYeWuu/violin-CVE-2026-98260-OS4.0.svg) ![forks](https://img.shields.io/github/forks/ChaYeWuu/violin-CVE-2026-98260-OS4.0.svg)


## CVE-2026-97229
 GitLab has remediated an issue in GitLab CE/EE affecting all versions from 19.2 before 19.2.8, 19.3 before 19.3.5, and 19.4 before 19.4.2 that, under certain conditions, could have allowed an unauthenticated user to execute arbitrary code on the GitLab server via a specially crafted regular expression in a CI/CD configuration, due to insufficient regular expression validation.

- [https://github.com/Noshadi-sec/CVE-2026-97229](https://github.com/Noshadi-sec/CVE-2026-97229) :  ![starts](https://img.shields.io/github/stars/Noshadi-sec/CVE-2026-97229.svg) ![forks](https://img.shields.io/github/forks/Noshadi-sec/CVE-2026-97229.svg)


## CVE-2026-91403
 Vulnerability in the Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component: JSSE).  Supported versions that are affected are Oracle Java SE: 8u511, 8u511-perf, 11.0.33, 17.0.21, 21.0.13, 25.0.5, 27.0.1; Oracle GraalVM for JDK: 17.0.21 and  21.0.13; Oracle GraalVM Enterprise Edition: 21.3.20. Easily exploitable vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition.  Successful attacks of this vulnerability can result in  unauthorized creation, deletion or modification access to critical data or all Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition accessible data as well as  unauthorized access to critical data or complete access to all Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition accessible data. Note: This vulnerability can be exploited by using APIs in the specified Component, e.g., through a web service which supplies data to the APIs. This vulnerability also applies to Java deployments, typically in clients running sandboxed Java Web Start applications or sandboxed Java applets, that load and run untrusted code (e.g., code that comes from the internet) and rely on the Java sandbox for security. CVSS 3.1 Base Score 9.1 (Confidentiality and Integrity impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N).

- [https://github.com/emirwtz/CVE-2026-91403](https://github.com/emirwtz/CVE-2026-91403) :  ![starts](https://img.shields.io/github/stars/emirwtz/CVE-2026-91403.svg) ![forks](https://img.shields.io/github/forks/emirwtz/CVE-2026-91403.svg)


## CVE-2026-90932
 LaraDashboard versions 0.9.2 through 1.2.2 contain a path traversal vulnerability in the core-upgrade backup handling. CoreUpgradeController and BackupService (e.g. BackupService::deleteBackup()) concatenate the user-supplied backup_file/filename value directly onto the backup directory path without normalisation, without applying basename(), and without verifying that the resolved path remains inside storage/app/core-backups; the corresponding form requests only validate the value as a bounded string. An authenticated user holding only the delegated settings.edit permission (not Superadmin) can supply ../ traversal sequences to delete arbitrary files reachable on the host filesystem, including outside the application tree, or to restore a ZIP archive from an arbitrary on-disk location, writing arbitrary files into the application directories and achieving remote code execution. Note: the advisory states the vulnerable concatenation was introduced in the v0.9.7 release line. No patched version was available at the time of publication.

- [https://github.com/capivara-research/CVE-2026-90932](https://github.com/capivara-research/CVE-2026-90932) :  ![starts](https://img.shields.io/github/stars/capivara-research/CVE-2026-90932.svg) ![forks](https://img.shields.io/github/forks/capivara-research/CVE-2026-90932.svg)


## CVE-2026-90931
 LaraDashboard versions 0.9.0 through 1.2.2 fail to sanitize SVG file content during media upload, allowing authenticated users with only the media.create permission to upload malicious SVG files containing script tags. When any user including administrators opens the stored SVG file served inline from the application origin, the embedded JavaScript executes in the dashboard context, enabling session hijacking and administrative account takeover.

- [https://github.com/capivara-research/CVE-2026-90931](https://github.com/capivara-research/CVE-2026-90931) :  ![starts](https://img.shields.io/github/stars/capivara-research/CVE-2026-90931.svg) ![forks](https://img.shields.io/github/forks/capivara-research/CVE-2026-90931.svg)


## CVE-2026-84589
 A permissions issue was addressed with additional restrictions. This issue is fixed in macOS Golden Gate 27. An app may be able to modify Privacy preferences.

- [https://github.com/isaiahehlert/CVE-2026-84589-macOS-TCC-Bypass](https://github.com/isaiahehlert/CVE-2026-84589-macOS-TCC-Bypass) :  ![starts](https://img.shields.io/github/stars/isaiahehlert/CVE-2026-84589-macOS-TCC-Bypass.svg) ![forks](https://img.shields.io/github/forks/isaiahehlert/CVE-2026-84589-macOS-TCC-Bypass.svg)


## CVE-2026-77647
 SPIP before 4.4.20 allows unauthenticated remote attackers to execute arbitrary code, as exploited in the wild in August 2026. This is related to incorrect identification of ?php blocks, and var_export's mishandling of certain cases such as presence of a '' character.

- [https://github.com/Nxploited/CVE-2026-77647](https://github.com/Nxploited/CVE-2026-77647) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2026-77647.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2026-77647.svg)


## CVE-2026-76466
Note: Cisco Expressway Series refers to Cisco Expressway Core (Expressway-C) devices and Cisco Expressway Edge (Expressway-E) devices.

- [https://github.com/emirwtz/CVE-2026-76466](https://github.com/emirwtz/CVE-2026-76466) :  ![starts](https://img.shields.io/github/stars/emirwtz/CVE-2026-76466.svg) ![forks](https://img.shields.io/github/forks/emirwtz/CVE-2026-76466.svg)


## CVE-2026-75650
 Adobe Commerce is affected by an Improper Neutralization of Special Elements Used in a Template Engine vulnerability that could result in arbitrary code execution in the context of the current user. An attacker could exploit this vulnerability to execute arbitrary code. Exploitation of this issue does not require user interaction. Scope is changed.

- [https://github.com/basesixtythree/B63-POC-CVE-2026-75650](https://github.com/basesixtythree/B63-POC-CVE-2026-75650) :  ![starts](https://img.shields.io/github/stars/basesixtythree/B63-POC-CVE-2026-75650.svg) ![forks](https://img.shields.io/github/forks/basesixtythree/B63-POC-CVE-2026-75650.svg)


## CVE-2026-43621
 Simple Machines Forum (SMF) through 2.1.7, fixed in commit 6f0dc61, contains an authorization state-confusion vulnerability in the profile loader that allows authenticated low-privileged users to gain administrator access by supplying multiple values for the user parameter. Attackers can exploit the mismatch between Profile::$member and User::$me-is_owner during sequential profile loading to be treated as the owner of an administrator profile, enabling unauthorized password changes and full account takeover.

- [https://github.com/KharalDipendra/CVE-2026-43621](https://github.com/KharalDipendra/CVE-2026-43621) :  ![starts](https://img.shields.io/github/stars/KharalDipendra/CVE-2026-43621.svg) ![forks](https://img.shields.io/github/forks/KharalDipendra/CVE-2026-43621.svg)


## CVE-2026-43499
  	changelog ]

- [https://github.com/ihamn/matisse-public](https://github.com/ihamn/matisse-public) :  ![starts](https://img.shields.io/github/stars/ihamn/matisse-public.svg) ![forks](https://img.shields.io/github/forks/ihamn/matisse-public.svg)


## CVE-2026-42945
 NGINX Plus and NGINX Open Source have a vulnerability in the ngx_http_rewrite_module module. This vulnerability exists when the rewrite directive is followed by a rewrite, if, or set directive and an unnamed Perl-Compatible Regular Expression (PCRE) capture (for example, $1, $2) with a replacement string that includes a question mark (?). An unauthenticated attacker along with conditions beyond its control can exploit this vulnerability by sending crafted HTTP requests. This may cause a heap buffer overflow in the NGINX worker process leading to a restart. Additionally, attackers can execute code on systems with Address Space Layout Randomization (ASLR) disabled or when the attacker can bypass ASLR.  Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/x0xr00t/sl0ppy-riftscan-CVE-2026-42945](https://github.com/x0xr00t/sl0ppy-riftscan-CVE-2026-42945) :  ![starts](https://img.shields.io/github/stars/x0xr00t/sl0ppy-riftscan-CVE-2026-42945.svg) ![forks](https://img.shields.io/github/forks/x0xr00t/sl0ppy-riftscan-CVE-2026-42945.svg)


## CVE-2026-31158
 SQL Injection vulnerability in CRM SOFTTRADE Infotech (aka softtradeindia) 1.0 allows a remote attacker to execute arbitrary code via the Login Page

- [https://github.com/Hardik007007/CVE-2026-31158-Boolean-Based-SQL-Injection-in-CRM-Login](https://github.com/Hardik007007/CVE-2026-31158-Boolean-Based-SQL-Injection-in-CRM-Login) :  ![starts](https://img.shields.io/github/stars/Hardik007007/CVE-2026-31158-Boolean-Based-SQL-Injection-in-CRM-Login.svg) ![forks](https://img.shields.io/github/forks/Hardik007007/CVE-2026-31158-Boolean-Based-SQL-Injection-in-CRM-Login.svg)


## CVE-2026-22679
 Weaver (Fanwei) E-cology 10.0 versions prior to 20260312 contain an unauthenticated remote code execution vulnerability in the /papi/esearch/data/devops/dubboApi/debug/method endpoint that allows attackers to execute arbitrary commands by invoking exposed debug functionality. Attackers can craft POST requests with attacker-controlled interfaceName and methodName parameters to reach command-execution helpers and achieve arbitrary command execution on the system. Exploitation evidence was first observed by the Shadowserver Foundation on 2026-03-31 (UTC).

- [https://github.com/piecar21/CVE-2026-22679](https://github.com/piecar21/CVE-2026-22679) :  ![starts](https://img.shields.io/github/stars/piecar21/CVE-2026-22679.svg) ![forks](https://img.shields.io/github/forks/piecar21/CVE-2026-22679.svg)


## CVE-2026-21902
This issue does not affect Junos OS.

- [https://github.com/piecar21/CVE-2026-21902](https://github.com/piecar21/CVE-2026-21902) :  ![starts](https://img.shields.io/github/stars/piecar21/CVE-2026-21902.svg) ![forks](https://img.shields.io/github/forks/piecar21/CVE-2026-21902.svg)


## CVE-2026-20131
Note: If the FMC management interface does not have public internet access, the attack surface that is associated with this vulnerability is reduced.

- [https://github.com/basesixtythree/B63-POC-CVE-2026-20131](https://github.com/basesixtythree/B63-POC-CVE-2026-20131) :  ![starts](https://img.shields.io/github/stars/basesixtythree/B63-POC-CVE-2026-20131.svg) ![forks](https://img.shields.io/github/forks/basesixtythree/B63-POC-CVE-2026-20131.svg)


## CVE-2026-18107
The practical impact on Red Hat products is limited by several factors: checkpoint/restore requires root privileges (podman) or cluster-admin RBAC (OpenShift) to trigger and cannot be initiated from within the container itself; on OpenShift prior to 4.17 the feature required explicit opt-in, and on 4.17+ the kubelet checkpoint API RBAC is not configured by default; OpenShift enforces user namespaces by default for regular workloads (hostUsers is gated behind admin-only SCCs), which makes the spoofed capabilities namespace-scoped and ineffective for privilege escalation; SELinux type enforcement (container_t) blocks privilege transitions independently of capabilities; seccomp filters persist through checkpoint/restore and cannot be corrupted via the parasite; and kernel mount namespace ownership checks on RHEL 9/10 kernels prevent mount-based container escape even with spoofed capabilities.

- [https://github.com/robalb/criu-exploit](https://github.com/robalb/criu-exploit) :  ![starts](https://img.shields.io/github/stars/robalb/criu-exploit.svg) ![forks](https://img.shields.io/github/forks/robalb/criu-exploit.svg)


## CVE-2026-11556
 A security flaw has been discovered in Tenda F451 1.0.0.7/1.0.0.9. Impacted is the function formWriteFacMac of the file /goform/WriteFacMac of the component Web Management Interface. Performing a manipulation of the argument mac results in os command injection. Remote exploitation of the attack is possible. The exploit has been released to the public and may be used for attacks.

- [https://github.com/Pr0fEs0r-X/PHP-CVE-2026-115560-Cheker-v-1.0](https://github.com/Pr0fEs0r-X/PHP-CVE-2026-115560-Cheker-v-1.0) :  ![starts](https://img.shields.io/github/stars/Pr0fEs0r-X/PHP-CVE-2026-115560-Cheker-v-1.0.svg) ![forks](https://img.shields.io/github/forks/Pr0fEs0r-X/PHP-CVE-2026-115560-Cheker-v-1.0.svg)


## CVE-2026-10961
 Use after free in Chrome for iOS in Google Chrome on iOS prior to 149.0.7827.53 allowed a remote attacker who had compromised the renderer process to potentially perform a sandbox escape via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/cyberkiddle/CVE-2026-109618](https://github.com/cyberkiddle/CVE-2026-109618) :  ![starts](https://img.shields.io/github/stars/cyberkiddle/CVE-2026-109618.svg) ![forks](https://img.shields.io/github/forks/cyberkiddle/CVE-2026-109618.svg)
- [https://github.com/RuanSerraAzul/CVE-2026-109618-POC](https://github.com/RuanSerraAzul/CVE-2026-109618-POC) :  ![starts](https://img.shields.io/github/stars/RuanSerraAzul/CVE-2026-109618-POC.svg) ![forks](https://img.shields.io/github/forks/RuanSerraAzul/CVE-2026-109618-POC.svg)
- [https://github.com/Pr0fEs0r-X/PHP2ShellX-CVE-2026-109618-109619](https://github.com/Pr0fEs0r-X/PHP2ShellX-CVE-2026-109618-109619) :  ![starts](https://img.shields.io/github/stars/Pr0fEs0r-X/PHP2ShellX-CVE-2026-109618-109619.svg) ![forks](https://img.shields.io/github/forks/Pr0fEs0r-X/PHP2ShellX-CVE-2026-109618-109619.svg)
- [https://github.com/franckferman/CVE-2026-109619](https://github.com/franckferman/CVE-2026-109619) :  ![starts](https://img.shields.io/github/stars/franckferman/CVE-2026-109619.svg) ![forks](https://img.shields.io/github/forks/franckferman/CVE-2026-109619.svg)
- [https://github.com/franckferman/CVE-2026-109618](https://github.com/franckferman/CVE-2026-109618) :  ![starts](https://img.shields.io/github/stars/franckferman/CVE-2026-109618.svg) ![forks](https://img.shields.io/github/forks/franckferman/CVE-2026-109618.svg)
- [https://github.com/tuanhoma/CVE-2026-109618](https://github.com/tuanhoma/CVE-2026-109618) :  ![starts](https://img.shields.io/github/stars/tuanhoma/CVE-2026-109618.svg) ![forks](https://img.shields.io/github/forks/tuanhoma/CVE-2026-109618.svg)
- [https://github.com/mefulton/CVE-2026-109618-php56-public](https://github.com/mefulton/CVE-2026-109618-php56-public) :  ![starts](https://img.shields.io/github/stars/mefulton/CVE-2026-109618-php56-public.svg) ![forks](https://img.shields.io/github/forks/mefulton/CVE-2026-109618-php56-public.svg)
- [https://github.com/gagaltotal/CVE-2026-109618-109619-php2shell](https://github.com/gagaltotal/CVE-2026-109618-109619-php2shell) :  ![starts](https://img.shields.io/github/stars/gagaltotal/CVE-2026-109618-109619-php2shell.svg) ![forks](https://img.shields.io/github/forks/gagaltotal/CVE-2026-109618-109619-php2shell.svg)
- [https://github.com/hack-ita/php2shell-cve-2026-109618-109619](https://github.com/hack-ita/php2shell-cve-2026-109618-109619) :  ![starts](https://img.shields.io/github/stars/hack-ita/php2shell-cve-2026-109618-109619.svg) ![forks](https://img.shields.io/github/forks/hack-ita/php2shell-cve-2026-109618-109619.svg)
- [https://github.com/piecar21/CVE-2026-109618](https://github.com/piecar21/CVE-2026-109618) :  ![starts](https://img.shields.io/github/stars/piecar21/CVE-2026-109618.svg) ![forks](https://img.shields.io/github/forks/piecar21/CVE-2026-109618.svg)


## CVE-2026-10668
The fix monitors the IN-token and new-SETUP events (k_event) and only arms control Data IN when an IN token is present and no new SETUP has arrived, cancelling the current transfer on a new SETUP. Affects boards using the Nuvoton NuMaker HSUSBD controller (CONFIG_UDC_NUMAKER with DT_HAS_NUVOTON_NUMAKER_HSUSBD_ENABLED); shipped in v4.4.0.

- [https://github.com/zfzhou0202/CVE-2026-106686](https://github.com/zfzhou0202/CVE-2026-106686) :  ![starts](https://img.shields.io/github/stars/zfzhou0202/CVE-2026-106686.svg) ![forks](https://img.shields.io/github/forks/zfzhou0202/CVE-2026-106686.svg)


## CVE-2026-4372
 A critical remote code execution vulnerability exists in all versions of the HuggingFace transformers library prior to version 5.3.0. The vulnerability allows an attacker to craft a malicious `config.json` file containing the `_attn_implementation_internal` field set to an attacker-controlled HuggingFace Hub repository ID. When a victim loads this model using the standard `AutoModelForCausalLM.from_pretrained()` API, the library downloads and executes arbitrary Python code from the attacker's repository with the victim's full OS privileges. This issue arises due to unfiltered deserialization of configuration attributes, insufficient sanitization of internal fields, and unsandboxed execution of downloaded kernels. The vulnerability bypasses the `trust_remote_code` security mechanism, is invisible to the victim, and exploits the standard documented usage pattern, making it particularly severe. Users are advised to upgrade to version 5.3.0 or later to mitigate this issue.

- [https://github.com/alvin21mfmlai/SE6013_Project](https://github.com/alvin21mfmlai/SE6013_Project) :  ![starts](https://img.shields.io/github/stars/alvin21mfmlai/SE6013_Project.svg) ![forks](https://img.shields.io/github/forks/alvin21mfmlai/SE6013_Project.svg)


## CVE-2026-3143
 The Total Upkeep – WordPress Backup Plugin plus Restore & Migrate by BoldGrid plugin for WordPress is vulnerable to unauthorized modification of data due to a missing capability check on the 'wp_ajax_cli_cancel' function in all versions up to, and including, 1.17.1. This makes it possible for unauthenticated attackers to cancel a pending rollback, potentially preventing a WordPress installation from automatically reverting a failed update.

- [https://github.com/hans362/CVE-2026-31431-Copy-Fail-Container-Escape](https://github.com/hans362/CVE-2026-31431-Copy-Fail-Container-Escape) :  ![starts](https://img.shields.io/github/stars/hans362/CVE-2026-31431-Copy-Fail-Container-Escape.svg) ![forks](https://img.shields.io/github/forks/hans362/CVE-2026-31431-Copy-Fail-Container-Escape.svg)
- [https://github.com/StackOverflowExcept1on/CVE-2026-31431](https://github.com/StackOverflowExcept1on/CVE-2026-31431) :  ![starts](https://img.shields.io/github/stars/StackOverflowExcept1on/CVE-2026-31431.svg) ![forks](https://img.shields.io/github/forks/StackOverflowExcept1on/CVE-2026-31431.svg)


## CVE-2026-1281
 A code injection in Ivanti Endpoint Manager Mobile allowing attackers to achieve unauthenticated remote code execution.

- [https://github.com/piecar21/CVE-2026-1281](https://github.com/piecar21/CVE-2026-1281) :  ![starts](https://img.shields.io/github/stars/piecar21/CVE-2026-1281.svg) ![forks](https://img.shields.io/github/forks/piecar21/CVE-2026-1281.svg)


## CVE-2026-1096
 The Best-wp-google-map plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the 'latitude' and 'longitudinal' parameters of the 'google_map_view' shortcode in all versions up to, and including, 2.1 due to insufficient input sanitization and output escaping. This makes it possible for authenticated attackers, with Contributor-level access and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.

- [https://github.com/tuwiliyt/cve-2026-109618](https://github.com/tuwiliyt/cve-2026-109618) :  ![starts](https://img.shields.io/github/stars/tuwiliyt/cve-2026-109618.svg) ![forks](https://img.shields.io/github/forks/tuwiliyt/cve-2026-109618.svg)
- [https://github.com/zhaoboy9692/CVE-2026-109618_](https://github.com/zhaoboy9692/CVE-2026-109618_) :  ![starts](https://img.shields.io/github/stars/zhaoboy9692/CVE-2026-109618_.svg) ![forks](https://img.shields.io/github/forks/zhaoboy9692/CVE-2026-109618_.svg)
- [https://github.com/MorphingYU/CVE-2026-109618](https://github.com/MorphingYU/CVE-2026-109618) :  ![starts](https://img.shields.io/github/stars/MorphingYU/CVE-2026-109618.svg) ![forks](https://img.shields.io/github/forks/MorphingYU/CVE-2026-109618.svg)


## CVE-2026-0303
 A code execution vulnerability in Palo Alto Networks Checkov by Prisma® Cloud can allow arbitrary code execution when Checkov scans a directory that contains an attacker-controlled configuration file.

- [https://github.com/piecar21/CVE-2026-0303](https://github.com/piecar21/CVE-2026-0303) :  ![starts](https://img.shields.io/github/stars/piecar21/CVE-2026-0303.svg) ![forks](https://img.shields.io/github/forks/piecar21/CVE-2026-0303.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/axisops/CVE-2025-29927](https://github.com/axisops/CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/axisops/CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/axisops/CVE-2025-29927.svg)


## CVE-2025-27740
 Weak authentication in Windows Active Directory Certificate Services allows an authorized attacker to elevate privileges over a network.

- [https://github.com/Dannners/CVE-2025-27740_POC](https://github.com/Dannners/CVE-2025-27740_POC) :  ![starts](https://img.shields.io/github/stars/Dannners/CVE-2025-27740_POC.svg) ![forks](https://img.shields.io/github/forks/Dannners/CVE-2025-27740_POC.svg)


## CVE-2025-6647
The specific flaw exists within the parsing of U3D files. The issue results from the lack of proper validation of user-supplied data, which can result in a write past the end of an allocated object. An attacker can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-26644.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo.svg)


## CVE-2025-5548
 A vulnerability, which was classified as critical, was found in FreeFloat FTP Server 1.0. Affected is an unknown function of the component NOOP Command Handler. The manipulation leads to buffer overflow. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/jessoan/CVE-2025-5548](https://github.com/jessoan/CVE-2025-5548) :  ![starts](https://img.shields.io/github/stars/jessoan/CVE-2025-5548.svg) ![forks](https://img.shields.io/github/forks/jessoan/CVE-2025-5548.svg)
- [https://github.com/jessoan/Cyber](https://github.com/jessoan/Cyber) :  ![starts](https://img.shields.io/github/stars/jessoan/Cyber.svg) ![forks](https://img.shields.io/github/forks/jessoan/Cyber.svg)
- [https://github.com/FreemanHack/CVE-2025-5548](https://github.com/FreemanHack/CVE-2025-5548) :  ![starts](https://img.shields.io/github/stars/FreemanHack/CVE-2025-5548.svg) ![forks](https://img.shields.io/github/forks/FreemanHack/CVE-2025-5548.svg)
- [https://github.com/libeazu/CVE-2025-5548](https://github.com/libeazu/CVE-2025-5548) :  ![starts](https://img.shields.io/github/stars/libeazu/CVE-2025-5548.svg) ![forks](https://img.shields.io/github/forks/libeazu/CVE-2025-5548.svg)
- [https://github.com/dc04265/CVE-2025-5548-Practica-Modulo-6](https://github.com/dc04265/CVE-2025-5548-Practica-Modulo-6) :  ![starts](https://img.shields.io/github/stars/dc04265/CVE-2025-5548-Practica-Modulo-6.svg) ![forks](https://img.shields.io/github/forks/dc04265/CVE-2025-5548-Practica-Modulo-6.svg)


## CVE-2025-2992
 A vulnerability classified as critical was found in Tenda FH1202 1.2.0.14(408). Affected by this vulnerability is an unknown functionality of the file /goform/AdvSetWrlsafeset of the component Web Management Interface. The manipulation leads to improper access controls. The attack can be launched remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/hujiaozhuzhu/CVE-2025-29927__Next.js](https://github.com/hujiaozhuzhu/CVE-2025-29927__Next.js) :  ![starts](https://img.shields.io/github/stars/hujiaozhuzhu/CVE-2025-29927__Next.js.svg) ![forks](https://img.shields.io/github/forks/hujiaozhuzhu/CVE-2025-29927__Next.js.svg)


## CVE-2024-39924
 An issue was discovered in Vaultwarden (formerly Bitwarden_RS) 1.30.3. A vulnerability has been identified in the authentication and authorization process of the endpoint responsible for altering the metadata of an emergency access. It permits an attacker with granted emergency access to escalate their privileges by changing the access level and modifying the wait time. Consequently, the attacker can gain full control over the vault (when only intended to have read access) while bypassing the necessary wait period.

- [https://github.com/l4rm4nd/PoC-CVE-2024-39924](https://github.com/l4rm4nd/PoC-CVE-2024-39924) :  ![starts](https://img.shields.io/github/stars/l4rm4nd/PoC-CVE-2024-39924.svg) ![forks](https://img.shields.io/github/forks/l4rm4nd/PoC-CVE-2024-39924.svg)


## CVE-2024-13985
 A command injection vulnerability in Dahua EIMS versions prior to 2240008 allows unauthenticated remote attackers to execute arbitrary system commands via the capture_handle.action interface. The flaw stems from improper input validation in the captureCommand parameter, which is processed without sanitization or authentication. By sending crafted HTTP requests, attackers can inject OS-level commands that are executed on the server, leading to full system compromise. Exploitation evidence was first observed by the Shadowserver Foundation on 2024-04-06 UTC.

- [https://github.com/piecar21/CVE-2024-13985](https://github.com/piecar21/CVE-2024-13985) :  ![starts](https://img.shields.io/github/stars/piecar21/CVE-2024-13985.svg) ![forks](https://img.shields.io/github/forks/piecar21/CVE-2024-13985.svg)


## CVE-2024-6387
 A security regression (CVE-2006-5051) was discovered in OpenSSH's server (sshd). There is a race condition which can lead sshd to handle some signals in an unsafe manner. An unauthenticated, remote attacker may be able to trigger it by failing to authenticate within a set time period.

- [https://github.com/axisops/CVE-2024-6387](https://github.com/axisops/CVE-2024-6387) :  ![starts](https://img.shields.io/github/stars/axisops/CVE-2024-6387.svg) ![forks](https://img.shields.io/github/forks/axisops/CVE-2024-6387.svg)


## CVE-2024-3094
Through a series of complex obfuscations, the liblzma build process extracts a prebuilt object file from a disguised test file existing in the source code, which is then used to modify specific functions in the liblzma code. This results in a modified liblzma library that can be used by any software linked against this library, intercepting and modifying the data interaction with this library.

- [https://github.com/axisops/CVE-2024-3094](https://github.com/axisops/CVE-2024-3094) :  ![starts](https://img.shields.io/github/stars/axisops/CVE-2024-3094.svg) ![forks](https://img.shields.io/github/forks/axisops/CVE-2024-3094.svg)


## CVE-2024-1561
 An issue was discovered in gradio-app/gradio, where the `/component_server` endpoint improperly allows the invocation of any method on a `Component` class with attacker-controlled arguments. Specifically, by exploiting the `move_resource_to_block_cache()` method of the `Block` class, an attacker can copy any file on the filesystem to a temporary directory and subsequently retrieve it. This vulnerability enables unauthorized local file read access, posing a significant risk especially when the application is exposed to the internet via `launch(share=True)`, thereby allowing remote attackers to read files on the host machine. Furthermore, gradio apps hosted on `huggingface.co` are also affected, potentially leading to the exposure of sensitive information such as API keys and credentials stored in environment variables.

- [https://github.com/WeiTao712/hdu-is-work1](https://github.com/WeiTao712/hdu-is-work1) :  ![starts](https://img.shields.io/github/stars/WeiTao712/hdu-is-work1.svg) ![forks](https://img.shields.io/github/forks/WeiTao712/hdu-is-work1.svg)


## CVE-2023-37569
Successful exploitation of this vulnerability could allow the attacker to execute arbitrary code on targeted system.

- [https://github.com/piecar21/CVE-2023-37569](https://github.com/piecar21/CVE-2023-37569) :  ![starts](https://img.shields.io/github/stars/piecar21/CVE-2023-37569.svg) ![forks](https://img.shields.io/github/forks/piecar21/CVE-2023-37569.svg)


## CVE-2023-28771
 Improper error message handling in Zyxel ZyWALL/USG series firmware versions 4.60 through 4.73, VPN series firmware versions 4.60 through 5.35, USG FLEX series firmware versions 4.60 through 5.35, and ATP series firmware versions 4.60 through 5.35, which could allow an unauthenticated attacker to execute some OS commands remotely by sending crafted packets to an affected device.

- [https://github.com/piecar21/CVE-2023-28771](https://github.com/piecar21/CVE-2023-28771) :  ![starts](https://img.shields.io/github/stars/piecar21/CVE-2023-28771.svg) ![forks](https://img.shields.io/github/forks/piecar21/CVE-2023-28771.svg)


## CVE-2022-38694
 In BootRom, there is a possible unchecked write address. This could lead to local escalation of privilege with no additional execution privileges needed.

- [https://github.com/Milordick/unisoc-tool-rs](https://github.com/Milordick/unisoc-tool-rs) :  ![starts](https://img.shields.io/github/stars/Milordick/unisoc-tool-rs.svg) ![forks](https://img.shields.io/github/forks/Milordick/unisoc-tool-rs.svg)


## CVE-2022-24803
 Asciidoctor-include-ext is Asciidoctor’s standard include processor reimplemented as an extension. Versions prior to 0.4.0, when used to render user-supplied input in AsciiDoc markup, may allow an attacker to execute arbitrary system commands on the host operating system. This attack is possible even when `allow-uri-read` is disabled! The problem has been patched in the referenced commits.

- [https://github.com/Udyz/CVE-2022-24803](https://github.com/Udyz/CVE-2022-24803) :  ![starts](https://img.shields.io/github/stars/Udyz/CVE-2022-24803.svg) ![forks](https://img.shields.io/github/forks/Udyz/CVE-2022-24803.svg)


## CVE-2022-24355
 This vulnerability allows network-adjacent attackers to execute arbitrary code on affected installations of TP-Link TL-WR940N 3.20.1 Build 200316 Rel.34392n (5553) routers. Authentication is not required to exploit this vulnerability. The specific flaw exists within the parsing of file name extensions. The issue results from the lack of proper validation of the length of user-supplied data prior to copying it to a fixed-length stack-based buffer. An attacker can leverage this vulnerability to execute code in the context of root. Was ZDI-CAN-13910.

- [https://github.com/ExLuck/CVE-2022-24355](https://github.com/ExLuck/CVE-2022-24355) :  ![starts](https://img.shields.io/github/stars/ExLuck/CVE-2022-24355.svg) ![forks](https://img.shields.io/github/forks/ExLuck/CVE-2022-24355.svg)


## CVE-2022-2639
 An integer coercion error was found in the openvswitch kernel module. Given a sufficiently large number of actions, while copying and reserving memory for a new action of a new flow, the reserve_sfa_size() function does not return -EMSGSIZE as expected, potentially leading to an out-of-bounds write access. This flaw allows a local user to crash or potentially escalate their privileges on the system.

- [https://github.com/aix567/Aurora](https://github.com/aix567/Aurora) :  ![starts](https://img.shields.io/github/stars/aix567/Aurora.svg) ![forks](https://img.shields.io/github/forks/aix567/Aurora.svg)


## CVE-2022-0847
 A flaw was found in the way the "flags" member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/Greetdawn/CVE-2022-0847-DirtyPipe](https://github.com/Greetdawn/CVE-2022-0847-DirtyPipe) :  ![starts](https://img.shields.io/github/stars/Greetdawn/CVE-2022-0847-DirtyPipe.svg) ![forks](https://img.shields.io/github/forks/Greetdawn/CVE-2022-0847-DirtyPipe.svg)
- [https://github.com/MingqiZhang7710/cve-2022-0847-poc-dockerimage](https://github.com/MingqiZhang7710/cve-2022-0847-poc-dockerimage) :  ![starts](https://img.shields.io/github/stars/MingqiZhang7710/cve-2022-0847-poc-dockerimage.svg) ![forks](https://img.shields.io/github/forks/MingqiZhang7710/cve-2022-0847-poc-dockerimage.svg)
- [https://github.com/osungjinwoo/CVE-2022-0847-Dirty-Pipe](https://github.com/osungjinwoo/CVE-2022-0847-Dirty-Pipe) :  ![starts](https://img.shields.io/github/stars/osungjinwoo/CVE-2022-0847-Dirty-Pipe.svg) ![forks](https://img.shields.io/github/forks/osungjinwoo/CVE-2022-0847-Dirty-Pipe.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/dishantsehgal/CVE-2021-41773](https://github.com/dishantsehgal/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/dishantsehgal/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/dishantsehgal/CVE-2021-41773.svg)


## CVE-2021-28164
 In Eclipse Jetty 9.4.37.v20210219 to 9.4.38.v20210224, the default compliance mode allows requests with URIs that contain %2e or %2e%2e segments to access protected resources within the WEB-INF directory. For example a request to /context/%2e/WEB-INF/web.xml can retrieve the web.xml file. This can reveal sensitive information regarding the implementation of a web application.

- [https://github.com/Guanyu-Zhou/work1-api](https://github.com/Guanyu-Zhou/work1-api) :  ![starts](https://img.shields.io/github/stars/Guanyu-Zhou/work1-api.svg) ![forks](https://img.shields.io/github/forks/Guanyu-Zhou/work1-api.svg)
- [https://github.com/Guanyu-Zhou/wor1-secure-api](https://github.com/Guanyu-Zhou/wor1-secure-api) :  ![starts](https://img.shields.io/github/stars/Guanyu-Zhou/wor1-secure-api.svg) ![forks](https://img.shields.io/github/forks/Guanyu-Zhou/wor1-secure-api.svg)


## CVE-2021-4422
 The POST SMTP Mailer plugin for WordPress is vulnerable to Cross-Site Request Forgery in versions up to, and including, 2.0.20. This is due to missing or incorrect nonce validation on the handleCsvExport() function. This makes it possible for unauthenticated attackers to trigger a CSV export via a forged request granted they can trick a site administrator into performing an action such as clicking on a link.

- [https://github.com/Super-Binary/cve-2021-44228](https://github.com/Super-Binary/cve-2021-44228) :  ![starts](https://img.shields.io/github/stars/Super-Binary/cve-2021-44228.svg) ![forks](https://img.shields.io/github/forks/Super-Binary/cve-2021-44228.svg)


## CVE-2021-3560
 It was found that polkit could be tricked into bypassing the credential checks for D-Bus requests, elevating the privileges of the requestor to the root user. This flaw could be used by an unprivileged local attacker to, for example, create a new local administrator. The highest threat from this vulnerability is to data confidentiality and integrity as well as system availability.

- [https://github.com/AntorDOS/CVE-2021-3560-Polkit-Privesc-Exploit](https://github.com/AntorDOS/CVE-2021-3560-Polkit-Privesc-Exploit) :  ![starts](https://img.shields.io/github/stars/AntorDOS/CVE-2021-3560-Polkit-Privesc-Exploit.svg) ![forks](https://img.shields.io/github/forks/AntorDOS/CVE-2021-3560-Polkit-Privesc-Exploit.svg)


## CVE-2017-7921
 An Improper Authentication issue was discovered in Hikvision DS-2CD2xx2F-I Series V5.2.0 build 140721 to V5.4.0 build 160530, DS-2CD2xx0F-I Series V5.2.0 build 140721 to V5.4.0 Build 160401, DS-2CD2xx2FWD Series V5.3.1 build 150410 to V5.4.4 Build 161125, DS-2CD4x2xFWD Series V5.2.0 build 140721 to V5.4.0 Build 160414, DS-2CD4xx5 Series V5.2.0 build 140721 to V5.4.0 Build 160421, DS-2DFx Series V5.2.0 build 140805 to V5.4.5 Build 160928, and DS-2CD63xx Series V5.0.9 build 140305 to V5.3.5 Build 160106 devices. The improper authentication vulnerability occurs when an application does not adequately or correctly authenticate users. This may allow a malicious user to escalate his or her privileges on the system and gain access to sensitive information.

- [https://github.com/MK-ULTRA-MK-ULTRA/CVE-2017-7921-2026-writeup](https://github.com/MK-ULTRA-MK-ULTRA/CVE-2017-7921-2026-writeup) :  ![starts](https://img.shields.io/github/stars/MK-ULTRA-MK-ULTRA/CVE-2017-7921-2026-writeup.svg) ![forks](https://img.shields.io/github/forks/MK-ULTRA-MK-ULTRA/CVE-2017-7921-2026-writeup.svg)


## CVE-2017-0143
 The SMBv1 server in Microsoft Windows Vista SP2; Windows Server 2008 SP2 and R2 SP1; Windows 7 SP1; Windows 8.1; Windows Server 2012 Gold and R2; Windows RT 8.1; and Windows 10 Gold, 1511, and 1607; and Windows Server 2016 allows remote attackers to execute arbitrary code via crafted packets, aka "Windows SMB Remote Code Execution Vulnerability." This vulnerability is different from those described in CVE-2017-0144, CVE-2017-0145, CVE-2017-0146, and CVE-2017-0148.

- [https://github.com/NeoCoderFSG/explotacion-post-CVE-2017-0143](https://github.com/NeoCoderFSG/explotacion-post-CVE-2017-0143) :  ![starts](https://img.shields.io/github/stars/NeoCoderFSG/explotacion-post-CVE-2017-0143.svg) ![forks](https://img.shields.io/github/forks/NeoCoderFSG/explotacion-post-CVE-2017-0143.svg)
- [https://github.com/NeoCoderFSG/post-explotacion-CVE-2017-0143](https://github.com/NeoCoderFSG/post-explotacion-CVE-2017-0143) :  ![starts](https://img.shields.io/github/stars/NeoCoderFSG/post-explotacion-CVE-2017-0143.svg) ![forks](https://img.shields.io/github/forks/NeoCoderFSG/post-explotacion-CVE-2017-0143.svg)
- [https://github.com/NeoCoderFSG/Laboratorio-Hacking-Etico-Vulnerabilidad-CVE-2017-0143](https://github.com/NeoCoderFSG/Laboratorio-Hacking-Etico-Vulnerabilidad-CVE-2017-0143) :  ![starts](https://img.shields.io/github/stars/NeoCoderFSG/Laboratorio-Hacking-Etico-Vulnerabilidad-CVE-2017-0143.svg) ![forks](https://img.shields.io/github/forks/NeoCoderFSG/Laboratorio-Hacking-Etico-Vulnerabilidad-CVE-2017-0143.svg)


## CVE-2011-0104
 Microsoft Excel 2002 SP3 and 2003 SP3, Office 2004 and 2008 for Mac, and Open XML File Format Converter for Mac allow remote attackers to execute arbitrary code or cause a denial of service (memory corruption) via a crafted HLink record in an Excel file, aka "Excel Buffer Overwrite Vulnerability."

- [https://github.com/Sunqiz/CVE-2011-0104-reproduction](https://github.com/Sunqiz/CVE-2011-0104-reproduction) :  ![starts](https://img.shields.io/github/stars/Sunqiz/CVE-2011-0104-reproduction.svg) ![forks](https://img.shields.io/github/forks/Sunqiz/CVE-2011-0104-reproduction.svg)

