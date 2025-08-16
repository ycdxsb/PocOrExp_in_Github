# Update 2025-08-16
## CVE-2025-54424
 1Panel is a web interface and MCP Server that manages websites, files, containers, databases, and LLMs on a Linux server. In versions 2.0.5 and below, the HTTPS protocol used for communication between the Core and Agent endpoints has incomplete certificate verification during certificate validation, leading to unauthorized interface access. Due to the presence of numerous command execution or high-privilege interfaces in 1Panel, this results in Remote Code Execution (RCE). This is fixed in version 2.0.6. The CVE has been translated from Simplified Chinese using GitHub Copilot.

- [https://github.com/hophtien/CVE-2025-54424](https://github.com/hophtien/CVE-2025-54424) :  ![starts](https://img.shields.io/github/stars/hophtien/CVE-2025-54424.svg) ![forks](https://img.shields.io/github/forks/hophtien/CVE-2025-54424.svg)


## CVE-2025-53770
Microsoft is preparing and fully testing a comprehensive update to address this vulnerability.  In the meantime, please make sure that the mitigation provided in this CVE documentation is in place so that you are protected from exploitation.

- [https://github.com/ghostn4444/CVE-2025-53770](https://github.com/ghostn4444/CVE-2025-53770) :  ![starts](https://img.shields.io/github/stars/ghostn4444/CVE-2025-53770.svg) ![forks](https://img.shields.io/github/forks/ghostn4444/CVE-2025-53770.svg)


## CVE-2024-49138
 Windows Common Log File System Driver Elevation of Privilege Vulnerability

- [https://github.com/1rhino2/SCRAPPED](https://github.com/1rhino2/SCRAPPED) :  ![starts](https://img.shields.io/github/stars/1rhino2/SCRAPPED.svg) ![forks](https://img.shields.io/github/forks/1rhino2/SCRAPPED.svg)


## CVE-2024-47533
 Cobbler, a Linux installation server that allows for rapid setup of network installation environments, has an improper authentication vulnerability starting in version 3.0.0 and prior to versions 3.2.3 and 3.3.7. `utils.get_shared_secret()` always returns `-1`, which allows anyone to connect to cobbler XML-RPC as user `''` password `-1` and make any changes. This gives anyone with network access to a cobbler server full control of the server. Versions 3.2.3 and 3.3.7 fix the issue.

- [https://github.com/okkotsu1/CVE-2024-47533](https://github.com/okkotsu1/CVE-2024-47533) :  ![starts](https://img.shields.io/github/stars/okkotsu1/CVE-2024-47533.svg) ![forks](https://img.shields.io/github/forks/okkotsu1/CVE-2024-47533.svg)


## CVE-2024-46982
 Next.js is a React framework for building full-stack web applications. By sending a crafted HTTP request, it is possible to poison the cache of a non-dynamic server-side rendered route in the pages router (this does not affect the app router). When this crafted request is sent it could coerce Next.js to cache a route that is meant to not be cached and send a `Cache-Control: s-maxage=1, stale-while-revalidate` header which some upstream CDNs may cache as well. To be potentially affected all of the following must apply: 1. Next.js between 13.5.1 and 14.2.9, 2. Using pages router, & 3. Using non-dynamic server-side rendered routes e.g. `pages/dashboard.tsx` not `pages/blog/[slug].tsx`. This vulnerability was resolved in Next.js v13.5.7, v14.2.10, and later. We recommend upgrading regardless of whether you can reproduce the issue or not. There are no official or recommended workarounds for this issue, we recommend that users patch to a safe version.

- [https://github.com/Lercas/CVE-2024-46982](https://github.com/Lercas/CVE-2024-46982) :  ![starts](https://img.shields.io/github/stars/Lercas/CVE-2024-46982.svg) ![forks](https://img.shields.io/github/forks/Lercas/CVE-2024-46982.svg)
- [https://github.com/CodePontiff/next_js_poisoning](https://github.com/CodePontiff/next_js_poisoning) :  ![starts](https://img.shields.io/github/stars/CodePontiff/next_js_poisoning.svg) ![forks](https://img.shields.io/github/forks/CodePontiff/next_js_poisoning.svg)


## CVE-2024-46981
 Redis is an open source, in-memory database that persists on disk. An authenticated user may use a specially crafted Lua script to manipulate the garbage collector and potentially lead to remote code execution. The problem is fixed in 7.4.2, 7.2.7, and 6.2.17. An additional workaround to mitigate the problem without patching the redis-server executable is to prevent users from executing Lua scripts. This can be done using ACL to restrict EVAL and EVALSHA commands.

- [https://github.com/publicqi/CVE-2024-46981](https://github.com/publicqi/CVE-2024-46981) :  ![starts](https://img.shields.io/github/stars/publicqi/CVE-2024-46981.svg) ![forks](https://img.shields.io/github/forks/publicqi/CVE-2024-46981.svg)
- [https://github.com/xsshk/CVE-2024-46981](https://github.com/xsshk/CVE-2024-46981) :  ![starts](https://img.shields.io/github/stars/xsshk/CVE-2024-46981.svg) ![forks](https://img.shields.io/github/forks/xsshk/CVE-2024-46981.svg)


## CVE-2024-46658
 Syrotech SY-GOPON-8OLT-L3 v1.6.0_240629 was discovered to contain an authenticated command injection vulnerability.

- [https://github.com/jackalkarlos/CVE-2024-46658](https://github.com/jackalkarlos/CVE-2024-46658) :  ![starts](https://img.shields.io/github/stars/jackalkarlos/CVE-2024-46658.svg) ![forks](https://img.shields.io/github/forks/jackalkarlos/CVE-2024-46658.svg)


## CVE-2024-46542
 Veritas / Arctera Data Insight before 7.1.1 allows Application Administrators to conduct SQL injection attacks.

- [https://github.com/MarioTesoro/CVE-2024-46542](https://github.com/MarioTesoro/CVE-2024-46542) :  ![starts](https://img.shields.io/github/stars/MarioTesoro/CVE-2024-46542.svg) ![forks](https://img.shields.io/github/forks/MarioTesoro/CVE-2024-46542.svg)


## CVE-2024-46532
 SQL Injection vulnerability in OpenHIS v.1.0 allows an attacker to execute arbitrary code via the refund function in the PayController.class.php component.

- [https://github.com/KamenRiderDarker/CVE-2024-46532](https://github.com/KamenRiderDarker/CVE-2024-46532) :  ![starts](https://img.shields.io/github/stars/KamenRiderDarker/CVE-2024-46532.svg) ![forks](https://img.shields.io/github/forks/KamenRiderDarker/CVE-2024-46532.svg)


## CVE-2024-46310
 Incorrect Access Control in Cfx.re FXServer v9601 and earlier allows unauthenticated users to modify and read arbitrary user data via exposed API endpoint

- [https://github.com/PRX5Y/CVE-2024-46310](https://github.com/PRX5Y/CVE-2024-46310) :  ![starts](https://img.shields.io/github/stars/PRX5Y/CVE-2024-46310.svg) ![forks](https://img.shields.io/github/forks/PRX5Y/CVE-2024-46310.svg)


## CVE-2024-46209
 A stored cross-site scripting (XSS) vulnerability in the component /media/test.html of REDAXO CMS v5.17.1 allows attackers to execute arbitrary web scripts or HTML via injecting a crafted payload into the password parameter.

- [https://github.com/h4ckr4v3n/CVE-2024-46209](https://github.com/h4ckr4v3n/CVE-2024-46209) :  ![starts](https://img.shields.io/github/stars/h4ckr4v3n/CVE-2024-46209.svg) ![forks](https://img.shields.io/github/forks/h4ckr4v3n/CVE-2024-46209.svg)


## CVE-2024-23741
 An issue in Hyper on macOS version 3.4.1 and before, allows remote attackers to execute arbitrary code via the RunAsNode and enableNodeClilnspectArguments settings.

- [https://github.com/giovannipajeu1/CVE-2024-23741](https://github.com/giovannipajeu1/CVE-2024-23741) :  ![starts](https://img.shields.io/github/stars/giovannipajeu1/CVE-2024-23741.svg) ![forks](https://img.shields.io/github/forks/giovannipajeu1/CVE-2024-23741.svg)


## CVE-2024-23740
 An issue in Kap for macOS version 3.6.0 and before, allows remote attackers to execute arbitrary code via the RunAsNode and enableNodeClilnspectArguments settings.

- [https://github.com/giovannipajeu1/CVE-2024-23740](https://github.com/giovannipajeu1/CVE-2024-23740) :  ![starts](https://img.shields.io/github/stars/giovannipajeu1/CVE-2024-23740.svg) ![forks](https://img.shields.io/github/forks/giovannipajeu1/CVE-2024-23740.svg)


## CVE-2024-23727
 The YI Smart Kami Vision com.kamivision.yismart application through 1.0.0_20231219 for Android allows a remote attacker to execute arbitrary JavaScript code via an implicit intent to the com.ants360.yicamera.activity.WebViewActivity component.

- [https://github.com/actuator/yi](https://github.com/actuator/yi) :  ![starts](https://img.shields.io/github/stars/actuator/yi.svg) ![forks](https://img.shields.io/github/forks/actuator/yi.svg)


## CVE-2024-23726
 Ubee DDW365 XCNDDW365 devices have predictable default WPA2 PSKs that could lead to unauthorized remote access. A remote attacker (in proximity to a Wi-Fi network) can derive the default WPA2-PSK value by observing a beacon frame. A PSK is generated by using the first six characters of the SSID and the last six of the BSSID, decrementing the last digit.

- [https://github.com/actuator/BSIDES-Security-Las-Vegas-2024](https://github.com/actuator/BSIDES-Security-Las-Vegas-2024) :  ![starts](https://img.shields.io/github/stars/actuator/BSIDES-Security-Las-Vegas-2024.svg) ![forks](https://img.shields.io/github/forks/actuator/BSIDES-Security-Las-Vegas-2024.svg)


## CVE-2024-23709
 In multiple locations, there is a possible out of bounds write due to a heap buffer overflow. This could lead to remote information disclosure with no additional execution privileges needed. User interaction is needed for exploitation.

- [https://github.com/AbrarKhan/external_sonivox_CVE-2024-23709](https://github.com/AbrarKhan/external_sonivox_CVE-2024-23709) :  ![starts](https://img.shields.io/github/stars/AbrarKhan/external_sonivox_CVE-2024-23709.svg) ![forks](https://img.shields.io/github/forks/AbrarKhan/external_sonivox_CVE-2024-23709.svg)


## CVE-2024-23666
at least version 7.4.0 and 7.2.0 through 7.2.6 and 7.0.1 through 7.0.6 and 6.4.5 through 6.4.7 and 6.2.5, FortiManager version 7.4.0 through 7.4.1 and 7.2.0 through 7.2.4 and 7.0.0 through 7.0.11 and 6.4.0 through 6.4.14, FortiAnalyzer version 7.4.0 through 7.4.1 and 7.2.0 through 7.2.4 and 7.0.0 through 7.0.11 and 6.4.0 through 6.4.14 allows attacker to improper access control via crafted requests.

- [https://github.com/synacktiv/CVE-2023-42791_CVE-2024-23666](https://github.com/synacktiv/CVE-2023-42791_CVE-2024-23666) :  ![starts](https://img.shields.io/github/stars/synacktiv/CVE-2023-42791_CVE-2024-23666.svg) ![forks](https://img.shields.io/github/forks/synacktiv/CVE-2023-42791_CVE-2024-23666.svg)


## CVE-2024-23653
 BuildKit is a toolkit for converting source code to build artifacts in an efficient, expressive and repeatable manner. In addition to running containers as build steps, BuildKit also provides APIs for running interactive containers based on built images. It was possible to use these APIs to ask BuildKit to run a container with elevated privileges. Normally, running such containers is only allowed if special `security.insecure` entitlement is enabled both by buildkitd configuration and allowed by the user initializing the build request. The issue has been fixed in v0.12.5 . Avoid using BuildKit frontends from untrusted sources. 

- [https://github.com/666asd/CVE-2024-23653](https://github.com/666asd/CVE-2024-23653) :  ![starts](https://img.shields.io/github/stars/666asd/CVE-2024-23653.svg) ![forks](https://img.shields.io/github/forks/666asd/CVE-2024-23653.svg)
- [https://github.com/shkch02/cve_2024_23653](https://github.com/shkch02/cve_2024_23653) :  ![starts](https://img.shields.io/github/stars/shkch02/cve_2024_23653.svg) ![forks](https://img.shields.io/github/forks/shkch02/cve_2024_23653.svg)


## CVE-2024-23651
 BuildKit is a toolkit for converting source code to build artifacts in an efficient, expressive and repeatable manner. Two malicious build steps running in parallel sharing the same cache mounts with subpaths could cause a race condition that can lead to files from the host system being accessible to the build container. The issue has been fixed in v0.12.5. Workarounds include, avoiding using BuildKit frontend from an untrusted source or building an untrusted Dockerfile containing cache mounts with --mount=type=cache,source=... options.

- [https://github.com/shkch02/cve_2024_23651](https://github.com/shkch02/cve_2024_23651) :  ![starts](https://img.shields.io/github/stars/shkch02/cve_2024_23651.svg) ![forks](https://img.shields.io/github/forks/shkch02/cve_2024_23651.svg)
- [https://github.com/shkch02/eBPF_cve_2024_23651](https://github.com/shkch02/eBPF_cve_2024_23651) :  ![starts](https://img.shields.io/github/stars/shkch02/eBPF_cve_2024_23651.svg) ![forks](https://img.shields.io/github/forks/shkch02/eBPF_cve_2024_23651.svg)


## CVE-2024-23334
 aiohttp is an asynchronous HTTP client/server framework for asyncio and Python. When using aiohttp as a web server and configuring static routes, it is necessary to specify the root path for static files. Additionally, the option 'follow_symlinks' can be used to determine whether to follow symbolic links outside the static root directory. When 'follow_symlinks' is set to True, there is no validation to check if reading a file is within the root directory. This can lead to directory traversal vulnerabilities, resulting in unauthorized access to arbitrary files on the system, even when symlinks are not present.  Disabling follow_symlinks and using a reverse proxy are encouraged mitigations.  Version 3.9.2 fixes this issue.

- [https://github.com/jhonnybonny/CVE-2024-23334](https://github.com/jhonnybonny/CVE-2024-23334) :  ![starts](https://img.shields.io/github/stars/jhonnybonny/CVE-2024-23334.svg) ![forks](https://img.shields.io/github/forks/jhonnybonny/CVE-2024-23334.svg)
- [https://github.com/z3rObyte/CVE-2024-23334-PoC](https://github.com/z3rObyte/CVE-2024-23334-PoC) :  ![starts](https://img.shields.io/github/stars/z3rObyte/CVE-2024-23334-PoC.svg) ![forks](https://img.shields.io/github/forks/z3rObyte/CVE-2024-23334-PoC.svg)
- [https://github.com/ox1111/CVE-2024-23334](https://github.com/ox1111/CVE-2024-23334) :  ![starts](https://img.shields.io/github/stars/ox1111/CVE-2024-23334.svg) ![forks](https://img.shields.io/github/forks/ox1111/CVE-2024-23334.svg)
- [https://github.com/wizarddos/CVE-2024-23334](https://github.com/wizarddos/CVE-2024-23334) :  ![starts](https://img.shields.io/github/stars/wizarddos/CVE-2024-23334.svg) ![forks](https://img.shields.io/github/forks/wizarddos/CVE-2024-23334.svg)
- [https://github.com/s4botai/CVE-2024-23334-PoC](https://github.com/s4botai/CVE-2024-23334-PoC) :  ![starts](https://img.shields.io/github/stars/s4botai/CVE-2024-23334-PoC.svg) ![forks](https://img.shields.io/github/forks/s4botai/CVE-2024-23334-PoC.svg)
- [https://github.com/sxyrxyy/aiohttp-exploit-CVE-2024-23334-certstream](https://github.com/sxyrxyy/aiohttp-exploit-CVE-2024-23334-certstream) :  ![starts](https://img.shields.io/github/stars/sxyrxyy/aiohttp-exploit-CVE-2024-23334-certstream.svg) ![forks](https://img.shields.io/github/forks/sxyrxyy/aiohttp-exploit-CVE-2024-23334-certstream.svg)
- [https://github.com/TheRedP4nther/LFI-aiohttp-CVE-2024-23334-PoC](https://github.com/TheRedP4nther/LFI-aiohttp-CVE-2024-23334-PoC) :  ![starts](https://img.shields.io/github/stars/TheRedP4nther/LFI-aiohttp-CVE-2024-23334-PoC.svg) ![forks](https://img.shields.io/github/forks/TheRedP4nther/LFI-aiohttp-CVE-2024-23334-PoC.svg)
- [https://github.com/Betan423/CVE-2024-23334-PoC](https://github.com/Betan423/CVE-2024-23334-PoC) :  ![starts](https://img.shields.io/github/stars/Betan423/CVE-2024-23334-PoC.svg) ![forks](https://img.shields.io/github/forks/Betan423/CVE-2024-23334-PoC.svg)
- [https://github.com/Arc4he/CVE-2024-23334-PoC](https://github.com/Arc4he/CVE-2024-23334-PoC) :  ![starts](https://img.shields.io/github/stars/Arc4he/CVE-2024-23334-PoC.svg) ![forks](https://img.shields.io/github/forks/Arc4he/CVE-2024-23334-PoC.svg)
- [https://github.com/Pylonet/CVE-2024-23334](https://github.com/Pylonet/CVE-2024-23334) :  ![starts](https://img.shields.io/github/stars/Pylonet/CVE-2024-23334.svg) ![forks](https://img.shields.io/github/forks/Pylonet/CVE-2024-23334.svg)
- [https://github.com/binaryninja/CVE-2024-23334](https://github.com/binaryninja/CVE-2024-23334) :  ![starts](https://img.shields.io/github/stars/binaryninja/CVE-2024-23334.svg) ![forks](https://img.shields.io/github/forks/binaryninja/CVE-2024-23334.svg)
- [https://github.com/brian-edgar-re/poc-cve-2024-23334](https://github.com/brian-edgar-re/poc-cve-2024-23334) :  ![starts](https://img.shields.io/github/stars/brian-edgar-re/poc-cve-2024-23334.svg) ![forks](https://img.shields.io/github/forks/brian-edgar-re/poc-cve-2024-23334.svg)
- [https://github.com/BestDevOfc/CVE-2024-23334-PoC](https://github.com/BestDevOfc/CVE-2024-23334-PoC) :  ![starts](https://img.shields.io/github/stars/BestDevOfc/CVE-2024-23334-PoC.svg) ![forks](https://img.shields.io/github/forks/BestDevOfc/CVE-2024-23334-PoC.svg)


## CVE-2022-46689
 A race condition was addressed with additional validation. This issue is fixed in tvOS 16.2, macOS Monterey 12.6.2, macOS Ventura 13.1, macOS Big Sur 11.7.2, iOS 15.7.2 and iPadOS 15.7.2, iOS 16.2 and iPadOS 16.2, watchOS 9.2. An app may be able to execute arbitrary code with kernel privileges.

- [https://github.com/iswaxan/JailedCement](https://github.com/iswaxan/JailedCement) :  ![starts](https://img.shields.io/github/stars/iswaxan/JailedCement.svg) ![forks](https://img.shields.io/github/forks/iswaxan/JailedCement.svg)


## CVE-2019-17572
 In Apache RocketMQ 4.2.0 to 4.6.0, when the automatic topic creation in the broker is turned on by default, an evil topic like “../../../../topic2020” is sent from rocketmq-client to the broker, a topic folder will be created in the parent directory in brokers, which leads to a directory traversal vulnerability. Users of the affected versions should apply one of the following: Upgrade to Apache RocketMQ 4.6.1 or later.

- [https://github.com/shoucheng3/apache__rocketmq_CVE-2019-17572_4-6-0](https://github.com/shoucheng3/apache__rocketmq_CVE-2019-17572_4-6-0) :  ![starts](https://img.shields.io/github/stars/shoucheng3/apache__rocketmq_CVE-2019-17572_4-6-0.svg) ![forks](https://img.shields.io/github/forks/shoucheng3/apache__rocketmq_CVE-2019-17572_4-6-0.svg)


## CVE-2019-10392
 Jenkins Git Client Plugin 2.8.4 and earlier and 3.0.0-rc did not properly restrict values passed as URL argument to an invocation of 'git ls-remote', resulting in OS command injection.

- [https://github.com/shoucheng3/jenkinsci__git-client-plugin_CVE-2019-10392_2-8-4](https://github.com/shoucheng3/jenkinsci__git-client-plugin_CVE-2019-10392_2-8-4) :  ![starts](https://img.shields.io/github/stars/shoucheng3/jenkinsci__git-client-plugin_CVE-2019-10392_2-8-4.svg) ![forks](https://img.shields.io/github/forks/shoucheng3/jenkinsci__git-client-plugin_CVE-2019-10392_2-8-4.svg)


## CVE-2019-0207
 Tapestry processes assets `/assets/ctx` using classes chain `StaticFilesFilter - AssetDispatcher - ContextResource`, which doesn't filter the character `\`, so attacker can perform a path traversal attack to read any files on Windows platform.

- [https://github.com/shoucheng3/tapestry-5-cve-2019-0207](https://github.com/shoucheng3/tapestry-5-cve-2019-0207) :  ![starts](https://img.shields.io/github/stars/shoucheng3/tapestry-5-cve-2019-0207.svg) ![forks](https://img.shields.io/github/forks/shoucheng3/tapestry-5-cve-2019-0207.svg)
- [https://github.com/shoucheng3/asf__tapestry-5_CVE-2019-0207_5-4-4](https://github.com/shoucheng3/asf__tapestry-5_CVE-2019-0207_5-4-4) :  ![starts](https://img.shields.io/github/stars/shoucheng3/asf__tapestry-5_CVE-2019-0207_5-4-4.svg) ![forks](https://img.shields.io/github/forks/shoucheng3/asf__tapestry-5_CVE-2019-0207_5-4-4.svg)


## CVE-2018-1000129
 An XSS vulnerability exists in the Jolokia agent version 1.3.7 in the HTTP servlet that allows an attacker to execute malicious javascript in the victim's browser.

- [https://github.com/shoucheng3/rhuss__jolokia_CVE-2018-1000129_1-4-0](https://github.com/shoucheng3/rhuss__jolokia_CVE-2018-1000129_1-4-0) :  ![starts](https://img.shields.io/github/stars/shoucheng3/rhuss__jolokia_CVE-2018-1000129_1-4-0.svg) ![forks](https://img.shields.io/github/forks/shoucheng3/rhuss__jolokia_CVE-2018-1000129_1-4-0.svg)


## CVE-2018-11776
 Apache Struts versions 2.3 to 2.3.34 and 2.5 to 2.5.16 suffer from possible Remote Code Execution when alwaysSelectFullNamespace is true (either by user or a plugin like Convention Plugin) and then: results are used with no namespace and in same time, its upper package have no or wildcard namespace and similar to results, same possibility when using url tag which doesn't have value and action set and in same time, its upper package have no or wildcard namespace.

- [https://github.com/arlyone/Apache-Struts-0Day-Exploit](https://github.com/arlyone/Apache-Struts-0Day-Exploit) :  ![starts](https://img.shields.io/github/stars/arlyone/Apache-Struts-0Day-Exploit.svg) ![forks](https://img.shields.io/github/forks/arlyone/Apache-Struts-0Day-Exploit.svg)


## CVE-2018-6574
 Go before 1.8.7, Go 1.9.x before 1.9.4, and Go 1.10 pre-releases before Go 1.10rc2 allow "go get" remote command execution during source code build, by leveraging the gcc or clang plugin feature, because -fplugin= and -plugin= arguments were not blocked.

- [https://github.com/solovvway/CVE-2018-6574](https://github.com/solovvway/CVE-2018-6574) :  ![starts](https://img.shields.io/github/stars/solovvway/CVE-2018-6574.svg) ![forks](https://img.shields.io/github/forks/solovvway/CVE-2018-6574.svg)


## CVE-2017-11317
 Telerik.Web.UI in Progress Telerik UI for ASP.NET AJAX before R1 2017 and R2 before R2 2017 SP2 uses weak RadAsyncUpload encryption, which allows remote attackers to perform arbitrary file uploads or execute arbitrary code.

- [https://github.com/0xr2r/CVE-2017-11317-auto-exploit-](https://github.com/0xr2r/CVE-2017-11317-auto-exploit-) :  ![starts](https://img.shields.io/github/stars/0xr2r/CVE-2017-11317-auto-exploit-.svg) ![forks](https://img.shields.io/github/forks/0xr2r/CVE-2017-11317-auto-exploit-.svg)


## CVE-2016-10726
 The XMLUI feature in DSpace before 3.6, 4.x before 4.5, and 5.x before 5.5 allows directory traversal via the themes/ path in an attack with two or more arbitrary characters and a colon before a pathname, as demonstrated by a themes/Reference/aa:etc/passwd URI.

- [https://github.com/shoucheng3/DSpace__DSpace_CVE-2016-10726_4-4](https://github.com/shoucheng3/DSpace__DSpace_CVE-2016-10726_4-4) :  ![starts](https://img.shields.io/github/stars/shoucheng3/DSpace__DSpace_CVE-2016-10726_4-4.svg) ![forks](https://img.shields.io/github/forks/shoucheng3/DSpace__DSpace_CVE-2016-10726_4-4.svg)


## CVE-2014-4725
 The MailPoet Newsletters (wysija-newsletters) plugin before 2.6.7 for WordPress allows remote attackers to bypass authentication and execute arbitrary PHP code by uploading a crafted theme using wp-admin/admin-post.php and accessing the theme in wp-content/uploads/wysija/themes/mailp/.

- [https://github.com/Pwdnx1337/MASS-CVE-2014-4725](https://github.com/Pwdnx1337/MASS-CVE-2014-4725) :  ![starts](https://img.shields.io/github/stars/Pwdnx1337/MASS-CVE-2014-4725.svg) ![forks](https://img.shields.io/github/forks/Pwdnx1337/MASS-CVE-2014-4725.svg)


## CVE-2014-3656
 JBoss KeyCloak: XSS in login-status-iframe.html

- [https://github.com/shoucheng3/keycloak__keycloak_CVE-2014-3656_1-0-5-Final](https://github.com/shoucheng3/keycloak__keycloak_CVE-2014-3656_1-0-5-Final) :  ![starts](https://img.shields.io/github/stars/shoucheng3/keycloak__keycloak_CVE-2014-3656_1-0-5-Final.svg) ![forks](https://img.shields.io/github/forks/shoucheng3/keycloak__keycloak_CVE-2014-3656_1-0-5-Final.svg)


## CVE-2011-4367
 Multiple directory traversal vulnerabilities in MyFaces JavaServer Faces (JSF) in Apache MyFaces Core 2.0.x before 2.0.12 and 2.1.x before 2.1.6 allow remote attackers to read arbitrary files via a .. (dot dot) in the (1) ln parameter to faces/javax.faces.resource/web.xml or (2) the PATH_INFO to faces/javax.faces.resource/.

- [https://github.com/shoucheng3/apache__myfaces_CVE-2011-4367_2-0-11](https://github.com/shoucheng3/apache__myfaces_CVE-2011-4367_2-0-11) :  ![starts](https://img.shields.io/github/stars/shoucheng3/apache__myfaces_CVE-2011-4367_2-0-11.svg) ![forks](https://img.shields.io/github/forks/shoucheng3/apache__myfaces_CVE-2011-4367_2-0-11.svg)

