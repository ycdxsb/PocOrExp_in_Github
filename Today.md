# Update 2026-05-13
## CVE-2026-43893
 exiftool-vendored provides cross-platform Node.js access to ExifTool. Prior to 35.19.0, exiftool-vendored starts ExifTool in -stay_open True -@ - mode, where arguments are read from stdin one per line. In affected versions, several caller-supplied strings were interpolated into ExifTool arguments without rejecting line delimiters. A newline or carriage return inside one of those strings could split a single intended argument into multiple ExifTool arguments, allowing argument injection. The fix also rejects NUL bytes as unsafe control characters. Applications that pass attacker-controlled strings to affected APIs may allow an attacker to make ExifTool read files accessible to the ExifTool process, or write output to attacker-chosen file system paths accessible to that process. No remote code execution has been demonstrated. This vulnerability is fixed in 35.19.0.

- [https://github.com/Dobby153/CVE-2026-43893](https://github.com/Dobby153/CVE-2026-43893) :  ![starts](https://img.shields.io/github/stars/Dobby153/CVE-2026-43893.svg) ![forks](https://img.shields.io/github/forks/Dobby153/CVE-2026-43893.svg)


## CVE-2026-43500
page_pool RX, GRO).  The OOM/trace handling already in place is reused.

- [https://github.com/linnemanlabs/dirtyfrag-arm64](https://github.com/linnemanlabs/dirtyfrag-arm64) :  ![starts](https://img.shields.io/github/stars/linnemanlabs/dirtyfrag-arm64.svg) ![forks](https://img.shields.io/github/forks/linnemanlabs/dirtyfrag-arm64.svg)
- [https://github.com/haydenjames/dirty-frag-check](https://github.com/haydenjames/dirty-frag-check) :  ![starts](https://img.shields.io/github/stars/haydenjames/dirty-frag-check.svg) ![forks](https://img.shields.io/github/forks/haydenjames/dirty-frag-check.svg)
- [https://github.com/krisiasty/vcheck](https://github.com/krisiasty/vcheck) :  ![starts](https://img.shields.io/github/stars/krisiasty/vcheck.svg) ![forks](https://img.shields.io/github/forks/krisiasty/vcheck.svg)
- [https://github.com/0xlane/pagecache-guard](https://github.com/0xlane/pagecache-guard) :  ![starts](https://img.shields.io/github/stars/0xlane/pagecache-guard.svg) ![forks](https://img.shields.io/github/forks/0xlane/pagecache-guard.svg)
- [https://github.com/mym0us3r/DIRTY-FRAG-Detection-with-Wazuh-4.14.4](https://github.com/mym0us3r/DIRTY-FRAG-Detection-with-Wazuh-4.14.4) :  ![starts](https://img.shields.io/github/stars/mym0us3r/DIRTY-FRAG-Detection-with-Wazuh-4.14.4.svg) ![forks](https://img.shields.io/github/forks/mym0us3r/DIRTY-FRAG-Detection-with-Wazuh-4.14.4.svg)
- [https://github.com/AK777177/Dirty-Frag-Analysis](https://github.com/AK777177/Dirty-Frag-Analysis) :  ![starts](https://img.shields.io/github/stars/AK777177/Dirty-Frag-Analysis.svg) ![forks](https://img.shields.io/github/forks/AK777177/Dirty-Frag-Analysis.svg)
- [https://github.com/attaattaatta/CVE-2026-43500](https://github.com/attaattaatta/CVE-2026-43500) :  ![starts](https://img.shields.io/github/stars/attaattaatta/CVE-2026-43500.svg) ![forks](https://img.shields.io/github/forks/attaattaatta/CVE-2026-43500.svg)
- [https://github.com/gagaltotal/CVE-2026-43284-CVE-2026-43500-scan](https://github.com/gagaltotal/CVE-2026-43284-CVE-2026-43500-scan) :  ![starts](https://img.shields.io/github/stars/gagaltotal/CVE-2026-43284-CVE-2026-43500-scan.svg) ![forks](https://img.shields.io/github/forks/gagaltotal/CVE-2026-43284-CVE-2026-43500-scan.svg)
- [https://github.com/XRSecCD/202605_dirty_frag](https://github.com/XRSecCD/202605_dirty_frag) :  ![starts](https://img.shields.io/github/stars/XRSecCD/202605_dirty_frag.svg) ![forks](https://img.shields.io/github/forks/XRSecCD/202605_dirty_frag.svg)
- [https://github.com/liamromanis101/DirtyFrag-Detector](https://github.com/liamromanis101/DirtyFrag-Detector) :  ![starts](https://img.shields.io/github/stars/liamromanis101/DirtyFrag-Detector.svg) ![forks](https://img.shields.io/github/forks/liamromanis101/DirtyFrag-Detector.svg)
- [https://github.com/vorkampfer/dirty_frag_mitigation](https://github.com/vorkampfer/dirty_frag_mitigation) :  ![starts](https://img.shields.io/github/stars/vorkampfer/dirty_frag_mitigation.svg) ![forks](https://img.shields.io/github/forks/vorkampfer/dirty_frag_mitigation.svg)
- [https://github.com/metalx1993/dirtyfrag-patches](https://github.com/metalx1993/dirtyfrag-patches) :  ![starts](https://img.shields.io/github/stars/metalx1993/dirtyfrag-patches.svg) ![forks](https://img.shields.io/github/forks/metalx1993/dirtyfrag-patches.svg)


## CVE-2026-43284
destination-frag path or fall back to skb_cow_data().

- [https://github.com/0xlane/pagecache-guard](https://github.com/0xlane/pagecache-guard) :  ![starts](https://img.shields.io/github/stars/0xlane/pagecache-guard.svg) ![forks](https://img.shields.io/github/forks/0xlane/pagecache-guard.svg)
- [https://github.com/gagaltotal/CVE-2026-43284-CVE-2026-43500-scan](https://github.com/gagaltotal/CVE-2026-43284-CVE-2026-43500-scan) :  ![starts](https://img.shields.io/github/stars/gagaltotal/CVE-2026-43284-CVE-2026-43500-scan.svg) ![forks](https://img.shields.io/github/forks/gagaltotal/CVE-2026-43284-CVE-2026-43500-scan.svg)
- [https://github.com/XRSecCD/202605_dirty_frag](https://github.com/XRSecCD/202605_dirty_frag) :  ![starts](https://img.shields.io/github/stars/XRSecCD/202605_dirty_frag.svg) ![forks](https://img.shields.io/github/forks/XRSecCD/202605_dirty_frag.svg)
- [https://github.com/liamromanis101/DirtyFrag-Detector](https://github.com/liamromanis101/DirtyFrag-Detector) :  ![starts](https://img.shields.io/github/stars/liamromanis101/DirtyFrag-Detector.svg) ![forks](https://img.shields.io/github/forks/liamromanis101/DirtyFrag-Detector.svg)


## CVE-2026-42569
 phpVMS is a PHP application to run and simulate an airline. Prior to version 7.0.6, a critical vulnerability in phpVMS allowed unauthenticated access to a legacy import feature. This issue has been patched in version 7.0.6.

- [https://github.com/0xBlackash/CVE-2026-42569](https://github.com/0xBlackash/CVE-2026-42569) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-42569.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-42569.svg)


## CVE-2026-41940
 cPanel and WHM versions after 11.40 contain an authentication bypass vulnerability in the login flow that allows unauthenticated remote attackers to gain unauthorized access to the control panel.

- [https://github.com/anach-ai/CVE-2026-41940](https://github.com/anach-ai/CVE-2026-41940) :  ![starts](https://img.shields.io/github/stars/anach-ai/CVE-2026-41940.svg) ![forks](https://img.shields.io/github/forks/anach-ai/CVE-2026-41940.svg)
- [https://github.com/zycoder0day/CVE-2026-41940](https://github.com/zycoder0day/CVE-2026-41940) :  ![starts](https://img.shields.io/github/stars/zycoder0day/CVE-2026-41940.svg) ![forks](https://img.shields.io/github/forks/zycoder0day/CVE-2026-41940.svg)


## CVE-2026-34486
Users are recommended to upgrade to version 11.0.21, 10.1.54 or 9.0.117, which fix the issue.

- [https://github.com/striga-ai/CVE-2026-34486](https://github.com/striga-ai/CVE-2026-34486) :  ![starts](https://img.shields.io/github/stars/striga-ai/CVE-2026-34486.svg) ![forks](https://img.shields.io/github/forks/striga-ai/CVE-2026-34486.svg)


## CVE-2026-33657
 EspoCRM is an open source customer relationship management application. Versions 9.3.3 and below have a stored HTML injection vulnerability that allows any authenticated user with standard (non-administrative) privileges to inject arbitrary HTML into system-generated email notifications by crafting malicious content in the post field of stream activity notes. The vulnerability exists because server-side Handlebars templates render the post field using unescaped triple-brace syntax, the Markdown processor preserves inline HTML by default, and the rendering pipeline explicitly skips sanitization for fields present in additionalData, creating a path where attacker-controlled HTML is accepted, stored, and rendered directly into emails without any escaping. Since the emails are sent using the system's configured SMTP identity (such as an administrative sender address), the injected content appears fully trusted to recipients, enabling phishing attacks, user tracking via embedded resources like image beacons, and UI manipulation within email content. The @mention feature further increases the impact by allowing targeted delivery of malicious emails to specific users. This issue has been fixed in version 9.3.4.

- [https://github.com/EntroVyx/CVE-2026-33657](https://github.com/EntroVyx/CVE-2026-33657) :  ![starts](https://img.shields.io/github/stars/EntroVyx/CVE-2026-33657.svg) ![forks](https://img.shields.io/github/forks/EntroVyx/CVE-2026-33657.svg)


## CVE-2026-31431
AD directly.

- [https://github.com/EynaExp/Copy-Fail-CVE-2026-31431-modernized](https://github.com/EynaExp/Copy-Fail-CVE-2026-31431-modernized) :  ![starts](https://img.shields.io/github/stars/EynaExp/Copy-Fail-CVE-2026-31431-modernized.svg) ![forks](https://img.shields.io/github/forks/EynaExp/Copy-Fail-CVE-2026-31431-modernized.svg)
- [https://github.com/sudoytang/copyfail-arm64](https://github.com/sudoytang/copyfail-arm64) :  ![starts](https://img.shields.io/github/stars/sudoytang/copyfail-arm64.svg) ![forks](https://img.shields.io/github/forks/sudoytang/copyfail-arm64.svg)
- [https://github.com/guiimoraes/CVE-2026-31431](https://github.com/guiimoraes/CVE-2026-31431) :  ![starts](https://img.shields.io/github/stars/guiimoraes/CVE-2026-31431.svg) ![forks](https://img.shields.io/github/forks/guiimoraes/CVE-2026-31431.svg)


## CVE-2026-28992
 A memory corruption vulnerability was addressed with improved locking. This issue is fixed in iOS 18.7.9 and iPadOS 18.7.9, iOS 26.5 and iPadOS 26.5, macOS Sequoia 15.7.7, macOS Sonoma 14.8.7, macOS Tahoe 26.5, tvOS 26.5, visionOS 26.5, watchOS 26.5. An attacker may be able to cause unexpected app termination.

- [https://github.com/zeroxjf/CVE-2026-28992-IOHIDFamily-FastPathUserClient-Race-Conditions](https://github.com/zeroxjf/CVE-2026-28992-IOHIDFamily-FastPathUserClient-Race-Conditions) :  ![starts](https://img.shields.io/github/stars/zeroxjf/CVE-2026-28992-IOHIDFamily-FastPathUserClient-Race-Conditions.svg) ![forks](https://img.shields.io/github/forks/zeroxjf/CVE-2026-28992-IOHIDFamily-FastPathUserClient-Race-Conditions.svg)


## CVE-2026-23918
Users are recommended to upgrade to version 2.4.67, which fixes the issue.

- [https://github.com/striga-ai/CVE-2026-23918](https://github.com/striga-ai/CVE-2026-23918) :  ![starts](https://img.shields.io/github/stars/striga-ai/CVE-2026-23918.svg) ![forks](https://img.shields.io/github/forks/striga-ai/CVE-2026-23918.svg)


## CVE-2026-8260
 A vulnerability was found in D-Link DCS-935L up to 1.10.01. The impacted element is the function SetDeviceSettings of the file /web/cgi-bin/hnap/hnap_service of the component HNAP Service. The manipulation of the argument AdminPassword results in buffer overflow. The attack can be executed remotely. The exploit has been made public and could be used.

- [https://github.com/CryptReaper12/CVE-2026-8260](https://github.com/CryptReaper12/CVE-2026-8260) :  ![starts](https://img.shields.io/github/stars/CryptReaper12/CVE-2026-8260.svg) ![forks](https://img.shields.io/github/forks/CryptReaper12/CVE-2026-8260.svg)


## CVE-2026-5682
 A vulnerability has been found in Meesho Online Shopping App up to 27.3 on Android. Affected is an unknown function of the file /api/endpoint of the component com.meesho.supply. Such manipulation leads to risky cryptographic algorithm. The attack may be performed from remote. The attack requires a high level of complexity. The exploitability is told to be difficult. The exploit has been disclosed to the public and may be used.

- [https://github.com/honestcorrupt/meesho-android-improper-encryption-cve-2026-5682](https://github.com/honestcorrupt/meesho-android-improper-encryption-cve-2026-5682) :  ![starts](https://img.shields.io/github/stars/honestcorrupt/meesho-android-improper-encryption-cve-2026-5682.svg) ![forks](https://img.shields.io/github/forks/honestcorrupt/meesho-android-improper-encryption-cve-2026-5682.svg)


## CVE-2026-4257
 The Contact Form by Supsystic plugin for WordPress is vulnerable to Server-Side Template Injection (SSTI) leading to Remote Code Execution (RCE) in all versions up to, and including, 1.7.36. This is due to the plugin using the Twig `Twig_Loader_String` template engine without sandboxing, combined with the `cfsPreFill` prefill functionality that allows unauthenticated users to inject arbitrary Twig expressions into form field values via GET parameters. This makes it possible for unauthenticated attackers to execute arbitrary PHP functions and OS commands on the server by leveraging Twig's `registerUndefinedFilterCallback()` method to register arbitrary PHP callbacks.

- [https://github.com/shootcannon/CVE-2026-4257](https://github.com/shootcannon/CVE-2026-4257) :  ![starts](https://img.shields.io/github/stars/shootcannon/CVE-2026-4257.svg) ![forks](https://img.shields.io/github/forks/shootcannon/CVE-2026-4257.svg)


## CVE-2026-0740
 The Ninja Forms - File Uploads plugin for WordPress is vulnerable to arbitrary file uploads due to missing file type validation in the 'NF_FU_AJAX_Controllers_Uploads::handle_upload' function in all versions up to, and including, 3.3.26. This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible. Note: The vulnerability was partially patched in version 3.3.25 and fully patched in version 3.3.27.

- [https://github.com/zycoder0day/CVE-2026-0740](https://github.com/zycoder0day/CVE-2026-0740) :  ![starts](https://img.shields.io/github/stars/zycoder0day/CVE-2026-0740.svg) ![forks](https://img.shields.io/github/forks/zycoder0day/CVE-2026-0740.svg)


## CVE-2026-0300
Prisma Access, Cloud NGFW and Panorama appliances are not impacted by this vulnerability.

- [https://github.com/ByteWraith1/CVE-2026-0300](https://github.com/ByteWraith1/CVE-2026-0300) :  ![starts](https://img.shields.io/github/stars/ByteWraith1/CVE-2026-0300.svg) ![forks](https://img.shields.io/github/forks/ByteWraith1/CVE-2026-0300.svg)


## CVE-2025-57819
 FreePBX is an open-source web-based graphical user interface. FreePBX 15, 16, and 17 endpoints are vulnerable due to insufficiently sanitized user-supplied data allowing unauthenticated access to FreePBX Administrator leading to arbitrary database manipulation and remote code execution. This issue has been patched in endpoint versions 15.0.66, 16.0.89, and 17.0.3.

- [https://github.com/blueisbeautiful/CVE-2025-57819](https://github.com/blueisbeautiful/CVE-2025-57819) :  ![starts](https://img.shields.io/github/stars/blueisbeautiful/CVE-2025-57819.svg) ![forks](https://img.shields.io/github/forks/blueisbeautiful/CVE-2025-57819.svg)


## CVE-2025-54309
 CrushFTP 10 before 10.8.5 and 11 before 11.3.4_23, when the DMZ proxy feature is not used, mishandles AS2 validation and consequently allows remote attackers to obtain admin access via HTTPS, as exploited in the wild in July 2025.

- [https://github.com/blueisbeautiful/CVE-2025-54309](https://github.com/blueisbeautiful/CVE-2025-54309) :  ![starts](https://img.shields.io/github/stars/blueisbeautiful/CVE-2025-54309.svg) ![forks](https://img.shields.io/github/forks/blueisbeautiful/CVE-2025-54309.svg)


## CVE-2025-54068
 Livewire is a full-stack framework for Laravel. In Livewire v3 up to and including v3.6.3, a vulnerability allows unauthenticated attackers to achieve remote command execution in specific scenarios. The issue stems from how certain component property updates are hydrated. This vulnerability is unique to Livewire v3 and does not affect prior major versions. Exploitation requires a component to be mounted and configured in a particular way, but does not require authentication or user interaction. This issue has been patched in Livewire v3.6.4. All users are strongly encouraged to upgrade to this version or later as soon as possible. No known workarounds are available.

- [https://github.com/zycoder0day/CVE-2025-54068](https://github.com/zycoder0day/CVE-2025-54068) :  ![starts](https://img.shields.io/github/stars/zycoder0day/CVE-2025-54068.svg) ![forks](https://img.shields.io/github/forks/zycoder0day/CVE-2025-54068.svg)


## CVE-2025-53694
 Exposure of Sensitive Information to an Unauthorized Actor vulnerability in Sitecore Sitecore Experience Manager (XM), Sitecore Experience Platform (XP).This issue affects Sitecore Experience Manager (XM): from 9.2 through 10.4; Experience Platform (XP): from 9.2 through 10.4.

- [https://github.com/blueisbeautiful/CVE-2025-53694](https://github.com/blueisbeautiful/CVE-2025-53694) :  ![starts](https://img.shields.io/github/stars/blueisbeautiful/CVE-2025-53694.svg) ![forks](https://img.shields.io/github/forks/blueisbeautiful/CVE-2025-53694.svg)
- [https://github.com/blueisbeautiful/CVE-2025-53694-to-CVE-2025-53691](https://github.com/blueisbeautiful/CVE-2025-53694-to-CVE-2025-53691) :  ![starts](https://img.shields.io/github/stars/blueisbeautiful/CVE-2025-53694-to-CVE-2025-53691.svg) ![forks](https://img.shields.io/github/forks/blueisbeautiful/CVE-2025-53694-to-CVE-2025-53691.svg)


## CVE-2025-53693
 Use of Externally-Controlled Input to Select Classes or Code ('Unsafe Reflection') vulnerability in Sitecore Sitecore Experience Manager (XM), Sitecore Experience Platform (XP) allows Cache Poisoning.This issue affects Sitecore Experience Manager (XM): from 9.0 through 9.3, from 10.0 through 10.4; Experience Platform (XP): from 9.0 through 9.3, from 10.0 through 10.4.

- [https://github.com/blueisbeautiful/CVE-2025-53693](https://github.com/blueisbeautiful/CVE-2025-53693) :  ![starts](https://img.shields.io/github/stars/blueisbeautiful/CVE-2025-53693.svg) ![forks](https://img.shields.io/github/forks/blueisbeautiful/CVE-2025-53693.svg)


## CVE-2025-53691
 Deserialization of Untrusted Data vulnerability in Sitecore Experience Manager (XM), Sitecore Experience Platform (XP) allows Remote Code Execution (RCE).This issue affects Experience Manager (XM): from 9.0 through 9.3, from 10.0 through 10.4; Experience Platform (XP): from 9.0 through 9.3, from 10.0 through 10.4.

- [https://github.com/blueisbeautiful/CVE-2025-53691](https://github.com/blueisbeautiful/CVE-2025-53691) :  ![starts](https://img.shields.io/github/stars/blueisbeautiful/CVE-2025-53691.svg) ![forks](https://img.shields.io/github/forks/blueisbeautiful/CVE-2025-53691.svg)
- [https://github.com/blueisbeautiful/CVE-2025-53694-to-CVE-2025-53691](https://github.com/blueisbeautiful/CVE-2025-53694-to-CVE-2025-53691) :  ![starts](https://img.shields.io/github/stars/blueisbeautiful/CVE-2025-53694-to-CVE-2025-53691.svg) ![forks](https://img.shields.io/github/forks/blueisbeautiful/CVE-2025-53694-to-CVE-2025-53691.svg)


## CVE-2025-48757
 An insufficient database Row-Level Security policy in Lovable through 2025-04-15 allows remote unauthenticated attackers to read or write to arbitrary database tables of generated sites. NOTE: this is disputed by the Supplier because each individual customer of the Lovable platform accepts a responsibility over protecting the data of their application.

- [https://github.com/Omji-krypto/db-fortress](https://github.com/Omji-krypto/db-fortress) :  ![starts](https://img.shields.io/github/stars/Omji-krypto/db-fortress.svg) ![forks](https://img.shields.io/github/forks/Omji-krypto/db-fortress.svg)


## CVE-2025-31133
 runc is a CLI tool for spawning and running containers according to the OCI specification. In versions 1.2.7 and below, 1.3.0-rc.1 through 1.3.1, 1.4.0-rc.1 and 1.4.0-rc.2 files, runc would not perform sufficient verification that the source of the bind-mount (i.e., the container's /dev/null) was actually a real /dev/null inode when using the container's /dev/null to mask. This exposes two methods of attack:  an arbitrary mount gadget, leading to host information disclosure, host denial of service, container escape, or a bypassing of maskedPaths. This issue is fixed in versions 1.2.8, 1.3.3 and 1.4.0-rc.3.

- [https://github.com/Glitched-Airis/CVE-2025-31133-Compose-Build-Lab](https://github.com/Glitched-Airis/CVE-2025-31133-Compose-Build-Lab) :  ![starts](https://img.shields.io/github/stars/Glitched-Airis/CVE-2025-31133-Compose-Build-Lab.svg) ![forks](https://img.shields.io/github/forks/Glitched-Airis/CVE-2025-31133-Compose-Build-Lab.svg)


## CVE-2025-5154
 A vulnerability, which was classified as problematic, was found in PhonePe App 25.03.21.0 on Android. Affected is an unknown function of the file /data/data/com.phonepe.app/databases/ of the component SQLite Database. The manipulation leads to cleartext storage in a file or on disk. Local access is required to approach this attack. The exploit has been disclosed to the public and may be used.

- [https://github.com/honestcorrupt/phonepe-sensitive-data-exposure-cve-2025-5154](https://github.com/honestcorrupt/phonepe-sensitive-data-exposure-cve-2025-5154) :  ![starts](https://img.shields.io/github/stars/honestcorrupt/phonepe-sensitive-data-exposure-cve-2025-5154.svg) ![forks](https://img.shields.io/github/forks/honestcorrupt/phonepe-sensitive-data-exposure-cve-2025-5154.svg)


## CVE-2025-3515
 The Drag and Drop Multiple File Upload for Contact Form 7 plugin for WordPress is vulnerable to arbitrary file uploads due to insufficient file type validation in all versions up to, and including, 1.3.8.9. This makes it possible for unauthenticated attackers to bypass the plugin's blacklist and upload .phar or other dangerous file types on the affected site's server, which may make remote code execution possible on the servers that are configured to handle .phar files as executable PHP scripts, particularly in default Apache+mod_php configurations where the file extension is not strictly validated before being passed to the PHP interpreter.

- [https://github.com/blueisbeautiful/CVE-2025-3515](https://github.com/blueisbeautiful/CVE-2025-3515) :  ![starts](https://img.shields.io/github/stars/blueisbeautiful/CVE-2025-3515.svg) ![forks](https://img.shields.io/github/forks/blueisbeautiful/CVE-2025-3515.svg)


## CVE-2024-37742
 Insecure Access Control in Safe Exam Browser (SEB) = 3.5.0 on Windows. The vulnerability allows an attacker to share clipboard data between the SEB kiosk mode and the underlying system, compromising exam integrity. By exploiting this flaw, an attacker can bypass exam controls and gain an unfair advantage during exams.

- [https://github.com/tungdn9988/CVE-2024-37742](https://github.com/tungdn9988/CVE-2024-37742) :  ![starts](https://img.shields.io/github/stars/tungdn9988/CVE-2024-37742.svg) ![forks](https://img.shields.io/github/forks/tungdn9988/CVE-2024-37742.svg)


## CVE-2023-38831
 RARLAB WinRAR before 6.23 allows attackers to execute arbitrary code when a user attempts to view a benign file within a ZIP archive. The issue occurs because a ZIP archive may include a benign file (such as an ordinary .JPG file) and also a folder that has the same name as the benign file, and the contents of the folder (which may include executable content) are processed during an attempt to access only the benign file. This was exploited in the wild in April through October 2023.

- [https://github.com/olowostandard1/CVE-2023-38831-WinRAR-Vulnerability-Analysis](https://github.com/olowostandard1/CVE-2023-38831-WinRAR-Vulnerability-Analysis) :  ![starts](https://img.shields.io/github/stars/olowostandard1/CVE-2023-38831-WinRAR-Vulnerability-Analysis.svg) ![forks](https://img.shields.io/github/forks/olowostandard1/CVE-2023-38831-WinRAR-Vulnerability-Analysis.svg)


## CVE-2023-27163
 request-baskets up to v1.2.1 was discovered to contain a Server-Side Request Forgery (SSRF) via the component /api/baskets/{name}. This vulnerability allows attackers to access network resources and sensitive information via a crafted API request.

- [https://github.com/Jeanback1/CVE-2023-27163-exploit](https://github.com/Jeanback1/CVE-2023-27163-exploit) :  ![starts](https://img.shields.io/github/stars/Jeanback1/CVE-2023-27163-exploit.svg) ![forks](https://img.shields.io/github/forks/Jeanback1/CVE-2023-27163-exploit.svg)


## CVE-2022-43973
 An arbitrary code execution vulnerability exisits in Linksys WRT54GL Wireless-G Broadband Router with firmware = 4.30.18.006. The Check_TSSI function within the httpd binary uses unvalidated user input in the construction of a system command. An authenticated attacker with administrator privileges can leverage this vulnerability over the network via a malicious POST request to /apply.cgi to execute arbitrary commands on the underlying Linux operating system as root.

- [https://github.com/UmbertoDellaMonica/Linksys-WRT54GL-Exploitation](https://github.com/UmbertoDellaMonica/Linksys-WRT54GL-Exploitation) :  ![starts](https://img.shields.io/github/stars/UmbertoDellaMonica/Linksys-WRT54GL-Exploitation.svg) ![forks](https://img.shields.io/github/forks/UmbertoDellaMonica/Linksys-WRT54GL-Exploitation.svg)


## CVE-2021-21220
 Insufficient validation of untrusted input in V8 in Google Chrome prior to 89.0.4389.128 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

- [https://github.com/JacobTaylor3/C2-and-Post-Exploitation-Framework](https://github.com/JacobTaylor3/C2-and-Post-Exploitation-Framework) :  ![starts](https://img.shields.io/github/stars/JacobTaylor3/C2-and-Post-Exploitation-Framework.svg) ![forks](https://img.shields.io/github/forks/JacobTaylor3/C2-and-Post-Exploitation-Framework.svg)


## CVE-2021-3129
 Ignition before 2.5.2, as used in Laravel and other products, allows unauthenticated remote attackers to execute arbitrary code because of insecure usage of file_get_contents() and file_put_contents(). This is exploitable on sites using debug mode with Laravel before 8.4.2.

- [https://github.com/krumoist/applemc-full-disclosure](https://github.com/krumoist/applemc-full-disclosure) :  ![starts](https://img.shields.io/github/stars/krumoist/applemc-full-disclosure.svg) ![forks](https://img.shields.io/github/forks/krumoist/applemc-full-disclosure.svg)


## CVE-2020-11800
 Zabbix Server 2.2.x and 3.0.x before 3.0.31, and 3.2 allows remote attackers to execute arbitrary code.

- [https://github.com/ycseo-git/CVE-2020-11800](https://github.com/ycseo-git/CVE-2020-11800) :  ![starts](https://img.shields.io/github/stars/ycseo-git/CVE-2020-11800.svg) ![forks](https://img.shields.io/github/forks/ycseo-git/CVE-2020-11800.svg)


## CVE-2019-9053
 An issue was discovered in CMS Made Simple 2.2.8. It is possible with the News module, through a crafted URL, to achieve unauthenticated blind time-based SQL injection via the m1_idlist parameter.

- [https://github.com/Ap0cryph1c/CVE-2019-9053](https://github.com/Ap0cryph1c/CVE-2019-9053) :  ![starts](https://img.shields.io/github/stars/Ap0cryph1c/CVE-2019-9053.svg) ![forks](https://img.shields.io/github/forks/Ap0cryph1c/CVE-2019-9053.svg)


## CVE-2019-1182
The update addresses the vulnerability by correcting how Remote Desktop Services handles connection requests.

- [https://github.com/gousseine-systems/vuln-rabilit-windows7](https://github.com/gousseine-systems/vuln-rabilit-windows7) :  ![starts](https://img.shields.io/github/stars/gousseine-systems/vuln-rabilit-windows7.svg) ![forks](https://img.shields.io/github/forks/gousseine-systems/vuln-rabilit-windows7.svg)


## CVE-2019-1181
The update addresses the vulnerability by correcting how Remote Desktop Services handles connection requests.

- [https://github.com/gousseine-systems/vuln-rabilit-windows7](https://github.com/gousseine-systems/vuln-rabilit-windows7) :  ![starts](https://img.shields.io/github/stars/gousseine-systems/vuln-rabilit-windows7.svg) ![forks](https://img.shields.io/github/forks/gousseine-systems/vuln-rabilit-windows7.svg)


## CVE-2017-8759
 Microsoft .NET Framework 2.0, 3.5, 3.5.1, 4.5.2, 4.6, 4.6.1, 4.6.2 and 4.7 allow an attacker to execute code remotely via a malicious document or application, aka ".NET Framework Remote Code Execution Vulnerability."

- [https://github.com/gousseine-systems/vuln-rabilit-windows7](https://github.com/gousseine-systems/vuln-rabilit-windows7) :  ![starts](https://img.shields.io/github/stars/gousseine-systems/vuln-rabilit-windows7.svg) ![forks](https://img.shields.io/github/forks/gousseine-systems/vuln-rabilit-windows7.svg)


## CVE-2017-0143
 The SMBv1 server in Microsoft Windows Vista SP2; Windows Server 2008 SP2 and R2 SP1; Windows 7 SP1; Windows 8.1; Windows Server 2012 Gold and R2; Windows RT 8.1; and Windows 10 Gold, 1511, and 1607; and Windows Server 2016 allows remote attackers to execute arbitrary code via crafted packets, aka "Windows SMB Remote Code Execution Vulnerability." This vulnerability is different from those described in CVE-2017-0144, CVE-2017-0145, CVE-2017-0146, and CVE-2017-0148.

- [https://github.com/gousseine-systems/vuln-rabilit-windows7](https://github.com/gousseine-systems/vuln-rabilit-windows7) :  ![starts](https://img.shields.io/github/stars/gousseine-systems/vuln-rabilit-windows7.svg) ![forks](https://img.shields.io/github/forks/gousseine-systems/vuln-rabilit-windows7.svg)


## CVE-2015-1701
 Win32k.sys in the kernel-mode drivers in Microsoft Windows Server 2003 SP2, Vista SP2, and Server 2008 SP2 allows local users to gain privileges via a crafted application, as exploited in the wild in April 2015, aka "Win32k Elevation of Privilege Vulnerability."

- [https://github.com/gousseine-systems/vuln-rabilit-windows7](https://github.com/gousseine-systems/vuln-rabilit-windows7) :  ![starts](https://img.shields.io/github/stars/gousseine-systems/vuln-rabilit-windows7.svg) ![forks](https://img.shields.io/github/forks/gousseine-systems/vuln-rabilit-windows7.svg)


## CVE-2014-4114
 Microsoft Windows Vista SP2, Windows Server 2008 SP2 and R2 SP1, Windows 7 SP1, Windows 8, Windows 8.1, Windows Server 2012 Gold and R2, and Windows RT Gold and 8.1 allow remote attackers to execute arbitrary code via a crafted OLE object in an Office document, as exploited in the wild with a "Sandworm" attack in June through October 2014, aka "Windows OLE Remote Code Execution Vulnerability."

- [https://github.com/gousseine-systems/vuln-rabilit-windows7](https://github.com/gousseine-systems/vuln-rabilit-windows7) :  ![starts](https://img.shields.io/github/stars/gousseine-systems/vuln-rabilit-windows7.svg) ![forks](https://img.shields.io/github/forks/gousseine-systems/vuln-rabilit-windows7.svg)


## CVE-2012-0003
 Unspecified vulnerability in winmm.dll in Windows Multimedia Library in Windows Media Player (WMP) in Microsoft Windows XP SP2 and SP3, Server 2003 SP2, Vista SP2, and Server 2008 SP2 allows remote attackers to execute arbitrary code via a crafted MIDI file, aka "MIDI Remote Code Execution Vulnerability."

- [https://github.com/gousseine-systems/vuln-rabilit-windows7](https://github.com/gousseine-systems/vuln-rabilit-windows7) :  ![starts](https://img.shields.io/github/stars/gousseine-systems/vuln-rabilit-windows7.svg) ![forks](https://img.shields.io/github/forks/gousseine-systems/vuln-rabilit-windows7.svg)


## CVE-2010-3333
 Stack-based buffer overflow in Microsoft Office XP SP3, Office 2003 SP3, Office 2007 SP2, Office 2010, Office 2004 and 2008 for Mac, Office for Mac 2011, and Open XML File Format Converter for Mac allows remote attackers to execute arbitrary code via crafted RTF data, aka "RTF Stack Buffer Overflow Vulnerability."

- [https://github.com/gousseine-systems/vuln-rabilit-windows7](https://github.com/gousseine-systems/vuln-rabilit-windows7) :  ![starts](https://img.shields.io/github/stars/gousseine-systems/vuln-rabilit-windows7.svg) ![forks](https://img.shields.io/github/forks/gousseine-systems/vuln-rabilit-windows7.svg)


## CVE-2010-2039
 Cross-site request forgery (CSRF) vulnerability in gpEasy CMS 1.6.2, 1.6.1, and earlier allows remote attackers to hijack the authentication of administrators for requests that create new administrative users via an Admin_Users action to index.php.  NOTE: some of these details are obtained from third party information.

- [https://github.com/RajeshTiwiva/CVE-2010-2039](https://github.com/RajeshTiwiva/CVE-2010-2039) :  ![starts](https://img.shields.io/github/stars/RajeshTiwiva/CVE-2010-2039.svg) ![forks](https://img.shields.io/github/forks/RajeshTiwiva/CVE-2010-2039.svg)

