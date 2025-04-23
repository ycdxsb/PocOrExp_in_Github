# Update 2025-04-23
## CVE-2025-31200
 A memory corruption issue was addressed with improved bounds checking. This issue is fixed in tvOS 18.4.1, visionOS 2.4.1, iOS iOS 18.4.1 and iPadOS 18.4.1, macOS Sequoia 15.4.1. Processing an audio stream in a maliciously crafted media file may result in code execution. Apple is aware of a report that this issue may have been exploited in an extremely sophisticated attack against specific targeted individuals on iOS.

- [https://github.com/zhuowei/apple-positional-audio-codec-invalid-header](https://github.com/zhuowei/apple-positional-audio-codec-invalid-header) :  ![starts](https://img.shields.io/github/stars/zhuowei/apple-positional-audio-codec-invalid-header.svg) ![forks](https://img.shields.io/github/forks/zhuowei/apple-positional-audio-codec-invalid-header.svg)


## CVE-2025-31161
 CrushFTP 10 before 10.8.4 and 11 before 11.3.1 allows authentication bypass and takeover of the crushadmin account (unless a DMZ proxy instance is used), as exploited in the wild in March and April 2025, aka "Unauthenticated HTTP(S) port access." A race condition exists in the AWS4-HMAC (compatible with S3) authorization method of the HTTP component of the FTP server. The server first verifies the existence of the user by performing a call to login_user_pass() with no password requirement. This will authenticate the session through the HMAC verification process and up until the server checks for user verification once more. The vulnerability can be further stabilized, eliminating the need for successfully triggering a race condition, by sending a mangled AWS4-HMAC header. By providing only the username and a following slash (/), the server will successfully find a username, which triggers the successful anypass authentication process, but the server will fail to find the expected SignedHeaders entry, resulting in an index-out-of-bounds error that stops the code from reaching the session cleanup. Together, these issues make it trivial to authenticate as any known or guessable user (e.g., crushadmin), and can lead to a full compromise of the system by obtaining an administrative account.

- [https://github.com/TX-One/CVE-2025-31161](https://github.com/TX-One/CVE-2025-31161) :  ![starts](https://img.shields.io/github/stars/TX-One/CVE-2025-31161.svg) ![forks](https://img.shields.io/github/forks/TX-One/CVE-2025-31161.svg)


## CVE-2025-30208
 Vite, a provider of frontend development tooling, has a vulnerability in versions prior to 6.2.3, 6.1.2, 6.0.12, 5.4.15, and 4.5.10. `@fs` denies access to files outside of Vite serving allow list. Adding `?raw??` or `?import&raw??` to the URL bypasses this limitation and returns the file content if it exists. This bypass exists because trailing separators such as `?` are removed in several places, but are not accounted for in query string regexes. The contents of arbitrary files can be returned to the browser. Only apps explicitly exposing the Vite dev server to the network (using `--host` or `server.host` config option) are affected. Versions 6.2.3, 6.1.2, 6.0.12, 5.4.15, and 4.5.10 fix the issue.

- [https://github.com/imbas007/CVE-2025-30208-template](https://github.com/imbas007/CVE-2025-30208-template) :  ![starts](https://img.shields.io/github/stars/imbas007/CVE-2025-30208-template.svg) ![forks](https://img.shields.io/github/forks/imbas007/CVE-2025-30208-template.svg)


## CVE-2025-30065
Users are recommended to upgrade to version 1.15.1, which fixes the issue.

- [https://github.com/ThreatRadarAI/TRA-001-Critical-RCE-Vulnerability-in-Apache-Parquet-CVE-2025-30065-Simulation-](https://github.com/ThreatRadarAI/TRA-001-Critical-RCE-Vulnerability-in-Apache-Parquet-CVE-2025-30065-Simulation-) :  ![starts](https://img.shields.io/github/stars/ThreatRadarAI/TRA-001-Critical-RCE-Vulnerability-in-Apache-Parquet-CVE-2025-30065-Simulation-.svg) ![forks](https://img.shields.io/github/forks/ThreatRadarAI/TRA-001-Critical-RCE-Vulnerability-in-Apache-Parquet-CVE-2025-30065-Simulation-.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/pouriam23/Next.js-Middleware-Bypass-CVE-2025-29927-](https://github.com/pouriam23/Next.js-Middleware-Bypass-CVE-2025-29927-) :  ![starts](https://img.shields.io/github/stars/pouriam23/Next.js-Middleware-Bypass-CVE-2025-29927-.svg) ![forks](https://img.shields.io/github/forks/pouriam23/Next.js-Middleware-Bypass-CVE-2025-29927-.svg)


## CVE-2025-28121
 code-projects Online Exam Mastering System 1.0 is vulnerable to Cross Site Scripting (XSS) in feedback.php via the "q" parameter allowing remote attackers to execute arbitrary code.

- [https://github.com/pruthuraut/CVE-2025-28121](https://github.com/pruthuraut/CVE-2025-28121) :  ![starts](https://img.shields.io/github/stars/pruthuraut/CVE-2025-28121.svg) ![forks](https://img.shields.io/github/forks/pruthuraut/CVE-2025-28121.svg)


## CVE-2025-24071
 Exposure of sensitive information to an unauthorized actor in Windows File Explorer allows an unauthorized attacker to perform spoofing over a network.

- [https://github.com/pswalia2u/CVE-2025-24071_POC](https://github.com/pswalia2u/CVE-2025-24071_POC) :  ![starts](https://img.shields.io/github/stars/pswalia2u/CVE-2025-24071_POC.svg) ![forks](https://img.shields.io/github/forks/pswalia2u/CVE-2025-24071_POC.svg)


## CVE-2025-24016
 Wazuh is a free and open source platform used for threat prevention, detection, and response. Starting in version 4.4.0 and prior to version 4.9.1, an unsafe deserialization vulnerability allows for remote code execution on Wazuh servers. DistributedAPI parameters are a serialized as JSON and deserialized using `as_wazuh_object` (in `framework/wazuh/core/cluster/common.py`). If an attacker manages to inject an unsanitized dictionary in DAPI request/response, they can forge an unhandled exception (`__unhandled_exc__`) to evaluate arbitrary python code. The vulnerability can be triggered by anybody with API access (compromised dashboard or Wazuh servers in the cluster) or, in certain configurations, even by a compromised agent. Version 4.9.1 contains a fix.

- [https://github.com/cybersecplayground/CVE-2025-24016-Wazuh-Remote-Code-Execution-RCE-PoC](https://github.com/cybersecplayground/CVE-2025-24016-Wazuh-Remote-Code-Execution-RCE-PoC) :  ![starts](https://img.shields.io/github/stars/cybersecplayground/CVE-2025-24016-Wazuh-Remote-Code-Execution-RCE-PoC.svg) ![forks](https://img.shields.io/github/forks/cybersecplayground/CVE-2025-24016-Wazuh-Remote-Code-Execution-RCE-PoC.svg)


## CVE-2025-2971
 This CVE ID has been rejected or withdrawn by its CVE Numbering Authority.

- [https://github.com/SteamPunk424/CVE-2025-29712-TAKASHI-Wireless-Instant-Router-And-Repeater-WebApp-Authenticated-Stored-XSS](https://github.com/SteamPunk424/CVE-2025-29712-TAKASHI-Wireless-Instant-Router-And-Repeater-WebApp-Authenticated-Stored-XSS) :  ![starts](https://img.shields.io/github/stars/SteamPunk424/CVE-2025-29712-TAKASHI-Wireless-Instant-Router-And-Repeater-WebApp-Authenticated-Stored-XSS.svg) ![forks](https://img.shields.io/github/forks/SteamPunk424/CVE-2025-29712-TAKASHI-Wireless-Instant-Router-And-Repeater-WebApp-Authenticated-Stored-XSS.svg)
- [https://github.com/SteamPunk424/CVE-2025-29711-TAKASHI-Wireless-Instant-Router-And-Repeater-WebApp-Incorrect-Access-Control](https://github.com/SteamPunk424/CVE-2025-29711-TAKASHI-Wireless-Instant-Router-And-Repeater-WebApp-Incorrect-Access-Control) :  ![starts](https://img.shields.io/github/stars/SteamPunk424/CVE-2025-29711-TAKASHI-Wireless-Instant-Router-And-Repeater-WebApp-Incorrect-Access-Control.svg) ![forks](https://img.shields.io/github/forks/SteamPunk424/CVE-2025-29711-TAKASHI-Wireless-Instant-Router-And-Repeater-WebApp-Incorrect-Access-Control.svg)


## CVE-2024-57394
 The quarantine - restore function in Qi-ANXIN Tianqing Endpoint Security Management System v10.0 allows user to restore a malicious file to an arbitrary file path. Attackers can write malicious DLL to system path and perform privilege escalation by leveraging Windows DLL hijacking vulnerabilities.

- [https://github.com/cwjchoi01/CVE-2024-57394](https://github.com/cwjchoi01/CVE-2024-57394) :  ![starts](https://img.shields.io/github/stars/cwjchoi01/CVE-2024-57394.svg) ![forks](https://img.shields.io/github/forks/cwjchoi01/CVE-2024-57394.svg)


## CVE-2024-37606
 A Stack overflow vulnerability in D-Link DCS-932L REVB_FIRMWARE_2.18.01 allows attackers to cause a Denial of Service (DoS) via a crafted HTTP request.

- [https://github.com/itwizardo/DCS932L-Emulation-CVE-2024-37606-Attack](https://github.com/itwizardo/DCS932L-Emulation-CVE-2024-37606-Attack) :  ![starts](https://img.shields.io/github/stars/itwizardo/DCS932L-Emulation-CVE-2024-37606-Attack.svg) ![forks](https://img.shields.io/github/forks/itwizardo/DCS932L-Emulation-CVE-2024-37606-Attack.svg)


## CVE-2024-28987
 The SolarWinds Web Help Desk (WHD) software is affected by a hardcoded credential vulnerability, allowing remote unauthenticated user to access internal functionality and modify data.

- [https://github.com/alecclyde/CVE-2024-28987](https://github.com/alecclyde/CVE-2024-28987) :  ![starts](https://img.shields.io/github/stars/alecclyde/CVE-2024-28987.svg) ![forks](https://img.shields.io/github/forks/alecclyde/CVE-2024-28987.svg)


## CVE-2024-4044
 A deserialization of untrusted data vulnerability exists in common code used by FlexLogger and InstrumentStudio that may result in remote code execution.  Successful exploitation requires an attacker to get a user to open a specially crafted project file.  This vulnerability affects NI FlexLogger 2024 Q1 and prior versions as well as NI InstrumentStudio 2024 Q1 and prior versions.

- [https://github.com/TaiYou-TW/CVE-2024-40445_CVE-2024-40446](https://github.com/TaiYou-TW/CVE-2024-40445_CVE-2024-40446) :  ![starts](https://img.shields.io/github/stars/TaiYou-TW/CVE-2024-40445_CVE-2024-40446.svg) ![forks](https://img.shields.io/github/forks/TaiYou-TW/CVE-2024-40445_CVE-2024-40446.svg)


## CVE-2023-25157
 GeoServer is an open source software server written in Java that allows users to share and edit geospatial data. GeoServer includes support for the OGC Filter expression language and the OGC Common Query Language (CQL) as part of the Web Feature Service (WFS) and Web Map Service (WMS) protocols.  CQL is also supported through the Web Coverage Service (WCS) protocol for ImageMosaic coverages. Users are advised to upgrade to either version 2.21.4, or version 2.22.2 to resolve this issue. Users unable to upgrade should disable the PostGIS Datastore *encode functions* setting to mitigate ``strEndsWith``, ``strStartsWith`` and ``PropertyIsLike `` misuse and enable the PostGIS DataStore *preparedStatements* setting to mitigate the ``FeatureId`` misuse.

- [https://github.com/custiya/geoserver-CVE-2023-25157](https://github.com/custiya/geoserver-CVE-2023-25157) :  ![starts](https://img.shields.io/github/stars/custiya/geoserver-CVE-2023-25157.svg) ![forks](https://img.shields.io/github/forks/custiya/geoserver-CVE-2023-25157.svg)


## CVE-2022-35914
 /vendor/htmlawed/htmlawed/htmLawedTest.php in the htmlawed module for GLPI through 10.0.2 allows PHP code injection.

- [https://github.com/joelindra/HTMLawedChecker](https://github.com/joelindra/HTMLawedChecker) :  ![starts](https://img.shields.io/github/stars/joelindra/HTMLawedChecker.svg) ![forks](https://img.shields.io/github/forks/joelindra/HTMLawedChecker.svg)


## CVE-2022-0847
 A flaw was found in the way the "flags" member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/byteReaper77/Dirty-Pipe](https://github.com/byteReaper77/Dirty-Pipe) :  ![starts](https://img.shields.io/github/stars/byteReaper77/Dirty-Pipe.svg) ![forks](https://img.shields.io/github/forks/byteReaper77/Dirty-Pipe.svg)


## CVE-2021-41351
 Microsoft Edge (Chrome based) Spoofing on IE Mode

- [https://github.com/ImuSpirit/CVE-2021-41351-POC](https://github.com/ImuSpirit/CVE-2021-41351-POC) :  ![starts](https://img.shields.io/github/stars/ImuSpirit/CVE-2021-41351-POC.svg) ![forks](https://img.shields.io/github/forks/ImuSpirit/CVE-2021-41351-POC.svg)


## CVE-2021-38666
 Remote Desktop Client Remote Code Execution Vulnerability

- [https://github.com/ImuSpirit/CVE-2021-38666](https://github.com/ImuSpirit/CVE-2021-38666) :  ![starts](https://img.shields.io/github/stars/ImuSpirit/CVE-2021-38666.svg) ![forks](https://img.shields.io/github/forks/ImuSpirit/CVE-2021-38666.svg)


## CVE-2021-34371
 Neo4j through 3.4.18 (with the shell server enabled) exposes an RMI service that arbitrarily deserializes Java objects, e.g., through setSessionVariable. An attacker can abuse this for remote code execution because there are dependencies with exploitable gadget chains.

- [https://github.com/tavgar/CVE-2021-34371](https://github.com/tavgar/CVE-2021-34371) :  ![starts](https://img.shields.io/github/stars/tavgar/CVE-2021-34371.svg) ![forks](https://img.shields.io/github/forks/tavgar/CVE-2021-34371.svg)

