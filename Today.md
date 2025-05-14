# Update 2025-05-14
## CVE-2025-31258
 This issue was addressed by removing the vulnerable code. This issue is fixed in macOS Sequoia 15.5. An app may be able to break out of its sandbox.

- [https://github.com/wh1te4ever/CVE-2025-31258-PoC](https://github.com/wh1te4ever/CVE-2025-31258-PoC) :  ![starts](https://img.shields.io/github/stars/wh1te4ever/CVE-2025-31258-PoC.svg) ![forks](https://img.shields.io/github/forks/wh1te4ever/CVE-2025-31258-PoC.svg)


## CVE-2025-24203
 The issue was addressed with improved checks. This issue is fixed in macOS Ventura 13.7.5, iPadOS 17.7.6, macOS Sequoia 15.4, macOS Sonoma 14.7.5. An app may be able to modify protected parts of the file system.

- [https://github.com/GeoSn0w/CVE-2025-24203-iOS-Exploit-in-Swift](https://github.com/GeoSn0w/CVE-2025-24203-iOS-Exploit-in-Swift) :  ![starts](https://img.shields.io/github/stars/GeoSn0w/CVE-2025-24203-iOS-Exploit-in-Swift.svg) ![forks](https://img.shields.io/github/forks/GeoSn0w/CVE-2025-24203-iOS-Exploit-in-Swift.svg)


## CVE-2024-55466
 An arbitrary file upload vulnerability in the Image Gallery of ThingsBoard Community, ThingsBoard Cloud and ThingsBoard Professional v3.8.1 allows attackers to execute arbitrary code via uploading a crafted file.

- [https://github.com/cybsecsid/ThingsBoard-CVE-2024-55466](https://github.com/cybsecsid/ThingsBoard-CVE-2024-55466) :  ![starts](https://img.shields.io/github/stars/cybsecsid/ThingsBoard-CVE-2024-55466.svg) ![forks](https://img.shields.io/github/forks/cybsecsid/ThingsBoard-CVE-2024-55466.svg)
- [https://github.com/cybsecsid/ThingsBoard-IoT-Platform-CVE-2024-55466](https://github.com/cybsecsid/ThingsBoard-IoT-Platform-CVE-2024-55466) :  ![starts](https://img.shields.io/github/stars/cybsecsid/ThingsBoard-IoT-Platform-CVE-2024-55466.svg) ![forks](https://img.shields.io/github/forks/cybsecsid/ThingsBoard-IoT-Platform-CVE-2024-55466.svg)


## CVE-2024-43788
 Webpack is a module bundler. Its main purpose is to bundle JavaScript files for usage in a browser, yet it is also capable of transforming, bundling, or packaging just about any resource or asset. The webpack developers have discovered a DOM Clobbering vulnerability in Webpack’s `AutoPublicPathRuntimeModule`. The DOM Clobbering gadget in the module can lead to cross-site scripting (XSS) in web pages where scriptless attacker-controlled HTML elements (e.g., an `img` tag with an unsanitized `name` attribute) are present. Real-world exploitation of this gadget has been observed in the Canvas LMS which allows a XSS attack to happen through a javascript code compiled by Webpack (the vulnerable part is from Webpack). DOM Clobbering is a type of code-reuse attack where the attacker first embeds a piece of non-script, seemingly benign HTML markups in the webpage (e.g. through a post or comment) and leverages the gadgets (pieces of js code) living in the existing javascript code to transform it into executable code. This vulnerability can lead to cross-site scripting (XSS) on websites that include Webpack-generated files and allow users to inject certain scriptless HTML tags with improperly sanitized name or id attributes. This issue has been addressed in release version 5.94.0. All users are advised to upgrade. There are no known workarounds for this issue.

- [https://github.com/batzionb/webpack-cve-2024-43788](https://github.com/batzionb/webpack-cve-2024-43788) :  ![starts](https://img.shields.io/github/stars/batzionb/webpack-cve-2024-43788.svg) ![forks](https://img.shields.io/github/forks/batzionb/webpack-cve-2024-43788.svg)


## CVE-2024-10220
 The Kubernetes kubelet component allows arbitrary command execution via specially crafted gitRepo volumes.This issue affects kubelet: through 1.28.11, from 1.29.0 through 1.29.6, from 1.30.0 through 1.30.2.

- [https://github.com/orgC/CVE-2024-10220-demo](https://github.com/orgC/CVE-2024-10220-demo) :  ![starts](https://img.shields.io/github/stars/orgC/CVE-2024-10220-demo.svg) ![forks](https://img.shields.io/github/forks/orgC/CVE-2024-10220-demo.svg)


## CVE-2024-4577
 In PHP versions 8.1.* before 8.1.29, 8.2.* before 8.2.20, 8.3.* before 8.3.8, when using Apache and PHP-CGI on Windows, if the system is set up to use certain code pages, Windows may use "Best-Fit" behavior to replace characters in command line given to Win32 API functions. PHP CGI module may misinterpret those characters as PHP options, which may allow a malicious user to pass options to PHP binary being run, and thus reveal the source code of scripts, run arbitrary PHP code on the server, etc.

- [https://github.com/tntrock/CVE-2024-4577_PowerShell](https://github.com/tntrock/CVE-2024-4577_PowerShell) :  ![starts](https://img.shields.io/github/stars/tntrock/CVE-2024-4577_PowerShell.svg) ![forks](https://img.shields.io/github/forks/tntrock/CVE-2024-4577_PowerShell.svg)


## CVE-2023-41992
 The issue was addressed with improved checks. This issue is fixed in macOS Monterey 12.7, iOS 16.7 and iPadOS 16.7, macOS Ventura 13.6. A local attacker may be able to elevate their privileges. Apple is aware of a report that this issue may have been actively exploited against versions of iOS before iOS 16.7.

- [https://github.com/karzanWang/CVE-2023-41992](https://github.com/karzanWang/CVE-2023-41992) :  ![starts](https://img.shields.io/github/stars/karzanWang/CVE-2023-41992.svg) ![forks](https://img.shields.io/github/forks/karzanWang/CVE-2023-41992.svg)


## CVE-2023-34732
 An issue in the userId parameter in the change password function of Flytxt NEON-dX v0.0.1-SNAPSHOT-6.9-qa-2-9-g5502a0c allows attackers to execute brute force attacks to discover user passwords.

- [https://github.com/saykino/CVE-2023-34732](https://github.com/saykino/CVE-2023-34732) :  ![starts](https://img.shields.io/github/stars/saykino/CVE-2023-34732.svg) ![forks](https://img.shields.io/github/forks/saykino/CVE-2023-34732.svg)


## CVE-2023-30800
 The web server used by MikroTik RouterOS version 6 is affected by a heap memory corruption issue. A remote and unauthenticated attacker can corrupt the server's heap memory by sending a crafted HTTP request. As a result, the web interface crashes and is immediately restarted. The issue was fixed in RouterOS 6.49.10 stable. RouterOS version 7 is not affected.

- [https://github.com/diemaxxing/cve-2023-30800-multithread-doser](https://github.com/diemaxxing/cve-2023-30800-multithread-doser) :  ![starts](https://img.shields.io/github/stars/diemaxxing/cve-2023-30800-multithread-doser.svg) ![forks](https://img.shields.io/github/forks/diemaxxing/cve-2023-30800-multithread-doser.svg)


## CVE-2022-21661
 WordPress is a free and open-source content management system written in PHP and paired with a MariaDB database. Due to improper sanitization in WP_Query, there can be cases where SQL injection is possible through plugins or themes that use it in a certain way. This has been patched in WordPress version 5.8.3. Older affected versions are also fixed via security release, that go back till 3.7.37. We strongly recommend that you keep auto-updates enabled. There are no known workarounds for this vulnerability.

- [https://github.com/Fauzan-Aldi/CVE-2022-21661](https://github.com/Fauzan-Aldi/CVE-2022-21661) :  ![starts](https://img.shields.io/github/stars/Fauzan-Aldi/CVE-2022-21661.svg) ![forks](https://img.shields.io/github/forks/Fauzan-Aldi/CVE-2022-21661.svg)


## CVE-2022-0847
 A flaw was found in the way the "flags" member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/cypherlobo/DirtyPipe-BSI](https://github.com/cypherlobo/DirtyPipe-BSI) :  ![starts](https://img.shields.io/github/stars/cypherlobo/DirtyPipe-BSI.svg) ![forks](https://img.shields.io/github/forks/cypherlobo/DirtyPipe-BSI.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/puckiestyle/CVE-2021-41773](https://github.com/puckiestyle/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/puckiestyle/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/puckiestyle/CVE-2021-41773.svg)
- [https://github.com/JIYUN02/cve-2021-41773](https://github.com/JIYUN02/cve-2021-41773) :  ![starts](https://img.shields.io/github/stars/JIYUN02/cve-2021-41773.svg) ![forks](https://img.shields.io/github/forks/JIYUN02/cve-2021-41773.svg)
- [https://github.com/honypot/CVE-2021-41773](https://github.com/honypot/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/honypot/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/honypot/CVE-2021-41773.svg)


## CVE-2019-15107
 An issue was discovered in Webmin =1.920. The parameter old in password_change.cgi contains a command injection vulnerability.

- [https://github.com/ch4ko/webmin_CVE-2019-15107](https://github.com/ch4ko/webmin_CVE-2019-15107) :  ![starts](https://img.shields.io/github/stars/ch4ko/webmin_CVE-2019-15107.svg) ![forks](https://img.shields.io/github/forks/ch4ko/webmin_CVE-2019-15107.svg)


## CVE-2018-14498
 get_8bit_row in rdbmp.c in libjpeg-turbo through 1.5.90 and MozJPEG through 3.3.1 allows attackers to cause a denial of service (heap-based buffer over-read and application crash) via a crafted 8-bit BMP in which one or more of the color indices is out of range for the number of palette entries.

- [https://github.com/h31md4llr/libjpeg_cve-2018-14498](https://github.com/h31md4llr/libjpeg_cve-2018-14498) :  ![starts](https://img.shields.io/github/stars/h31md4llr/libjpeg_cve-2018-14498.svg) ![forks](https://img.shields.io/github/forks/h31md4llr/libjpeg_cve-2018-14498.svg)


## CVE-2017-6736
 The Simple Network Management Protocol (SNMP) subsystem of Cisco IOS 12.0 through 12.4 and 15.0 through 15.6 and IOS XE 2.2 through 3.17 contains multiple vulnerabilities that could allow an authenticated, remote attacker to remotely execute code on an affected system or cause an affected system to reload. An attacker could exploit these vulnerabilities by sending a crafted SNMP packet to an affected system via IPv4 or IPv6. Only traffic directed to an affected system can be used to exploit these vulnerabilities. The vulnerabilities are due to a buffer overflow condition in the SNMP subsystem of the affected software. The vulnerabilities affect all versions of SNMP: Versions 1, 2c, and 3. To exploit these vulnerabilities via SNMP Version 2c or earlier, the attacker must know the SNMP read-only community string for the affected system. To exploit these vulnerabilities via SNMP Version 3, the attacker must have user credentials for the affected system. All devices that have enabled SNMP and have not explicitly excluded the affected MIBs or OIDs should be considered vulnerable. Cisco Bug IDs: CSCve57697.

- [https://github.com/garnetsunset/CiscoIOSSNMPToolkit](https://github.com/garnetsunset/CiscoIOSSNMPToolkit) :  ![starts](https://img.shields.io/github/stars/garnetsunset/CiscoIOSSNMPToolkit.svg) ![forks](https://img.shields.io/github/forks/garnetsunset/CiscoIOSSNMPToolkit.svg)
- [https://github.com/garnetsunset/CiscoSpectreTakeover](https://github.com/garnetsunset/CiscoSpectreTakeover) :  ![starts](https://img.shields.io/github/stars/garnetsunset/CiscoSpectreTakeover.svg) ![forks](https://img.shields.io/github/forks/garnetsunset/CiscoSpectreTakeover.svg)


## CVE-2017-5753
 Systems with microprocessors utilizing speculative execution and branch prediction may allow unauthorized disclosure of information to an attacker with local user access via a side-channel analysis.

- [https://github.com/garnetsunset/CiscoSpectreTakeover](https://github.com/garnetsunset/CiscoSpectreTakeover) :  ![starts](https://img.shields.io/github/stars/garnetsunset/CiscoSpectreTakeover.svg) ![forks](https://img.shields.io/github/forks/garnetsunset/CiscoSpectreTakeover.svg)


## CVE-2017-5715
 Systems with microprocessors utilizing speculative execution and indirect branch prediction may allow unauthorized disclosure of information to an attacker with local user access via a side-channel analysis.

- [https://github.com/garnetsunset/CiscoSpectreTakeover](https://github.com/garnetsunset/CiscoSpectreTakeover) :  ![starts](https://img.shields.io/github/stars/garnetsunset/CiscoSpectreTakeover.svg) ![forks](https://img.shields.io/github/forks/garnetsunset/CiscoSpectreTakeover.svg)

