# Update 2026-02-08
## CVE-2026-25731
 calibre is an e-book manager. Prior to 9.2.0, a Server-Side Template Injection (SSTI) vulnerability in Calibre's Templite templating engine allows arbitrary code execution when a user converts an ebook using a malicious custom template file via the --template-html or --template-html-index command-line options. This vulnerability is fixed in 9.2.0.

- [https://github.com/dxlerYT/CVE-2026-25731](https://github.com/dxlerYT/CVE-2026-25731) :  ![starts](https://img.shields.io/github/stars/dxlerYT/CVE-2026-25731.svg) ![forks](https://img.shields.io/github/forks/dxlerYT/CVE-2026-25731.svg)


## CVE-2026-25643
 Frigate is a network video recorder (NVR) with realtime local object detection for IP cameras. Prior to 0.16.4, a critical Remote Command Execution (RCE) vulnerability has been identified in the Frigate integration with go2rtc. The application does not sanitize user input in the video stream configuration (config.yaml), allowing direct injection of system commands via the exec: directive. The go2rtc service executes these commands without restrictions. This vulnerability is only exploitable by an administrator or users who have exposed their Frigate install to the open internet with no authentication which allows anyone full administrative control. This vulnerability is fixed in 0.16.4.

- [https://github.com/jduardo2704/CVE-2026-25643-Frigate-RCE](https://github.com/jduardo2704/CVE-2026-25643-Frigate-RCE) :  ![starts](https://img.shields.io/github/stars/jduardo2704/CVE-2026-25643-Frigate-RCE.svg) ![forks](https://img.shields.io/github/forks/jduardo2704/CVE-2026-25643-Frigate-RCE.svg)


## CVE-2026-25253
 OpenClaw (aka clawdbot or Moltbot) before 2026.1.29 obtains a gatewayUrl value from a query string and automatically makes a WebSocket connection without prompting, sending a token value.

- [https://github.com/Joseph19820124/openclaw-vuln-report](https://github.com/Joseph19820124/openclaw-vuln-report) :  ![starts](https://img.shields.io/github/stars/Joseph19820124/openclaw-vuln-report.svg) ![forks](https://img.shields.io/github/forks/Joseph19820124/openclaw-vuln-report.svg)


## CVE-2026-25050
 Vendure is an open-source headless commerce platform. Prior to version 3.5.3, the `NativeAuthenticationStrategy.authenticate()` method is vulnerable to a timing attack that allows attackers to enumerate valid usernames (email addresses). In `packages/core/src/config/auth/native-authentication-strategy.ts`, the authenticate method returns immediately if a user is not found. The significant timing difference (~200-400ms for bcrypt vs ~1-5ms for DB miss) allows attackers to reliably distinguish between existing and non-existing accounts. Version 3.5.3 fixes the issue.

- [https://github.com/Christbowel/CVE-2026-25050](https://github.com/Christbowel/CVE-2026-25050) :  ![starts](https://img.shields.io/github/stars/Christbowel/CVE-2026-25050.svg) ![forks](https://img.shields.io/github/forks/Christbowel/CVE-2026-25050.svg)


## CVE-2026-24300
 Azure Front Door Elevation of Privilege Vulnerability

- [https://github.com/stephaniesahnihi/CVE-2026-24300](https://github.com/stephaniesahnihi/CVE-2026-24300) :  ![starts](https://img.shields.io/github/stars/stephaniesahnihi/CVE-2026-24300.svg) ![forks](https://img.shields.io/github/forks/stephaniesahnihi/CVE-2026-24300.svg)


## CVE-2026-24135
 Gogs is an open source self-hosted Git service. In version 0.13.3 and prior, a path traversal vulnerability exists in the updateWikiPage function of Gogs. The vulnerability allows an authenticated user with write access to a repository's wiki to delete arbitrary files on the server by manipulating the old_title parameter in the wiki editing form. This issue has been patched in versions 0.13.4 and 0.14.0+dev.

- [https://github.com/reschjonas/CVE-2026-24135](https://github.com/reschjonas/CVE-2026-24135) :  ![starts](https://img.shields.io/github/stars/reschjonas/CVE-2026-24135.svg) ![forks](https://img.shields.io/github/forks/reschjonas/CVE-2026-24135.svg)


## CVE-2026-24061
 telnetd in GNU Inetutils through 2.7 allows remote authentication bypass via a "-f root" value for the USER environment variable.

- [https://github.com/shivam-bathla/CVE-2026-24061-setup](https://github.com/shivam-bathla/CVE-2026-24061-setup) :  ![starts](https://img.shields.io/github/stars/shivam-bathla/CVE-2026-24061-setup.svg) ![forks](https://img.shields.io/github/forks/shivam-bathla/CVE-2026-24061-setup.svg)
- [https://github.com/scumfrog/cve-2026-24061](https://github.com/scumfrog/cve-2026-24061) :  ![starts](https://img.shields.io/github/stars/scumfrog/cve-2026-24061.svg) ![forks](https://img.shields.io/github/forks/scumfrog/cve-2026-24061.svg)
- [https://github.com/nrnw/CVE-2026-24061-GNU-inetutils-Telnet-Detector](https://github.com/nrnw/CVE-2026-24061-GNU-inetutils-Telnet-Detector) :  ![starts](https://img.shields.io/github/stars/nrnw/CVE-2026-24061-GNU-inetutils-Telnet-Detector.svg) ![forks](https://img.shields.io/github/forks/nrnw/CVE-2026-24061-GNU-inetutils-Telnet-Detector.svg)


## CVE-2026-21643
 An improper neutralization of special elements used in an sql command ('sql injection') vulnerability in Fortinet FortiClientEMS 7.4.4 may allow an unauthenticated attacker to execute unauthorized code or commands via specifically crafted HTTP requests.

- [https://github.com/DarkSploits/CVE-2026-21643-Exploit](https://github.com/DarkSploits/CVE-2026-21643-Exploit) :  ![starts](https://img.shields.io/github/stars/DarkSploits/CVE-2026-21643-Exploit.svg) ![forks](https://img.shields.io/github/forks/DarkSploits/CVE-2026-21643-Exploit.svg)


## CVE-2026-1337
Proof of concept exploit:  https://github.com/JoakimBulow/CVE-2026-1337

- [https://github.com/JoakimBulow/CVE-2026-1337](https://github.com/JoakimBulow/CVE-2026-1337) :  ![starts](https://img.shields.io/github/stars/JoakimBulow/CVE-2026-1337.svg) ![forks](https://img.shields.io/github/forks/JoakimBulow/CVE-2026-1337.svg)


## CVE-2025-68921
 SteelSeries Nahimic 3 1.10.7 allows Directory traversal.

- [https://github.com/kalibb/CVE-2025-68921](https://github.com/kalibb/CVE-2025-68921) :  ![starts](https://img.shields.io/github/stars/kalibb/CVE-2025-68921.svg) ![forks](https://img.shields.io/github/forks/kalibb/CVE-2025-68921.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp.svg)


## CVE-2025-53770
Microsoft is preparing and fully testing a comprehensive update to address this vulnerability.  In the meantime, please make sure that the mitigation provided in this CVE documentation is in place so that you are protected from exploitation.

- [https://github.com/chrisalee27-dotcom/SOC-Incident-Response-Portfolio](https://github.com/chrisalee27-dotcom/SOC-Incident-Response-Portfolio) :  ![starts](https://img.shields.io/github/stars/chrisalee27-dotcom/SOC-Incident-Response-Portfolio.svg) ![forks](https://img.shields.io/github/forks/chrisalee27-dotcom/SOC-Incident-Response-Portfolio.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/Grand-Moomin/Vuln-Next.js-CVE-2025-29927](https://github.com/Grand-Moomin/Vuln-Next.js-CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/Grand-Moomin/Vuln-Next.js-CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/Grand-Moomin/Vuln-Next.js-CVE-2025-29927.svg)


## CVE-2025-14847
 Mismatched length fields in Zlib compressed protocol headers may allow a read of uninitialized heap memory by an unauthenticated client. This issue affects all MongoDB Server v7.0 prior to 7.0.28 versions, MongoDB Server v8.0 versions prior to 8.0.17, MongoDB Server v8.2 versions prior to 8.2.3, MongoDB Server v6.0 versions prior to 6.0.27, MongoDB Server v5.0 versions prior to 5.0.32, MongoDB Server v4.4 versions prior to 4.4.30, MongoDB Server v4.2 versions greater than or equal to 4.2.0, MongoDB Server v4.0 versions greater than or equal to 4.0.0, and MongoDB Server v3.6 versions greater than or equal to 3.6.0.

- [https://github.com/im-hanzou/mongobleed](https://github.com/im-hanzou/mongobleed) :  ![starts](https://img.shields.io/github/stars/im-hanzou/mongobleed.svg) ![forks](https://img.shields.io/github/forks/im-hanzou/mongobleed.svg)
- [https://github.com/sho-luv/MongoBleed](https://github.com/sho-luv/MongoBleed) :  ![starts](https://img.shields.io/github/stars/sho-luv/MongoBleed.svg) ![forks](https://img.shields.io/github/forks/sho-luv/MongoBleed.svg)


## CVE-2025-6743
 The Woodmart theme for WordPress is vulnerable to Stored Cross-Site Scripting via the plugin's 'multiple_markers' attribute in all versions up to, and including, 8.2.3 due to insufficient input sanitization and output escaping on user supplied attributes. This makes it possible for authenticated attackers, with contributor-level access and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.

- [https://github.com/RajChowdhury240/CVE-2025-67435-PoC](https://github.com/RajChowdhury240/CVE-2025-67435-PoC) :  ![starts](https://img.shields.io/github/stars/RajChowdhury240/CVE-2025-67435-PoC.svg) ![forks](https://img.shields.io/github/forks/RajChowdhury240/CVE-2025-67435-PoC.svg)


## CVE-2025-2304
When a user wishes to change his password, the 'updated_ajax' method of the UsersController is called. The vulnerability stems from the use of the dangerous permit! method, which allows all parameters to pass through without any filtering.

- [https://github.com/CsuriBird/CVE-2025-2304](https://github.com/CsuriBird/CVE-2025-2304) :  ![starts](https://img.shields.io/github/stars/CsuriBird/CVE-2025-2304.svg) ![forks](https://img.shields.io/github/forks/CsuriBird/CVE-2025-2304.svg)


## CVE-2024-21413
 Microsoft Outlook Remote Code Execution Vulnerability

- [https://github.com/securenetexpert/CVE-2024-21413-Moniker-Link-Writeup](https://github.com/securenetexpert/CVE-2024-21413-Moniker-Link-Writeup) :  ![starts](https://img.shields.io/github/stars/securenetexpert/CVE-2024-21413-Moniker-Link-Writeup.svg) ![forks](https://img.shields.io/github/forks/securenetexpert/CVE-2024-21413-Moniker-Link-Writeup.svg)


## CVE-2023-39910
 The cryptocurrency wallet entropy seeding mechanism used in Libbitcoin Explorer 3.0.0 through 3.6.0 is weak, aka the Milk Sad issue. The use of an mt19937 Mersenne Twister PRNG restricts the internal entropy to 32 bits regardless of settings. This allows remote attackers to recover any wallet private keys generated from "bx seed" entropy output and steal funds. (Affected users need to move funds to a secure new cryptocurrency wallet.) NOTE: the vendor's position is that there was sufficient documentation advising against "bx seed" but others disagree. NOTE: this was exploited in the wild in June and July 2023.

- [https://github.com/demining/RAMnesia-Attack](https://github.com/demining/RAMnesia-Attack) :  ![starts](https://img.shields.io/github/stars/demining/RAMnesia-Attack.svg) ![forks](https://img.shields.io/github/forks/demining/RAMnesia-Attack.svg)


## CVE-2023-0386
 A flaw was found in the Linux kernel, where unauthorized access to the execution of the setuid file with capabilities was found in the Linux kernel’s OverlayFS subsystem in how a user copies a capable file from a nosuid mount into another mount. This uid mapping bug allows a local user to escalate their privileges on the system.

- [https://github.com/huovnn/CVE-2023-0386-go-poc](https://github.com/huovnn/CVE-2023-0386-go-poc) :  ![starts](https://img.shields.io/github/stars/huovnn/CVE-2023-0386-go-poc.svg) ![forks](https://img.shields.io/github/forks/huovnn/CVE-2023-0386-go-poc.svg)


## CVE-2020-1472
When the second phase of Windows updates become available in Q1 2021, customers will be notified via a revision to this security vulnerability. If you wish to be notified when these updates are released, we recommend that you register for the security notifications mailer to be alerted of content changes to this advisory. See Microsoft Technical Security Notifications.

- [https://github.com/bvcyber/CVE-2020-1472](https://github.com/bvcyber/CVE-2020-1472) :  ![starts](https://img.shields.io/github/stars/bvcyber/CVE-2020-1472.svg) ![forks](https://img.shields.io/github/forks/bvcyber/CVE-2020-1472.svg)


## CVE-2020-0796
 A remote code execution vulnerability exists in the way that the Microsoft Server Message Block 3.1.1 (SMBv3) protocol handles certain requests, aka 'Windows SMBv3 Client/Server Remote Code Execution Vulnerability'.

- [https://github.com/thai1012/cve-2020-0796](https://github.com/thai1012/cve-2020-0796) :  ![starts](https://img.shields.io/github/stars/thai1012/cve-2020-0796.svg) ![forks](https://img.shields.io/github/forks/thai1012/cve-2020-0796.svg)


## CVE-2020-0096
 In startActivities of ActivityStartController.java, there is a possible escalation of privilege due to a confused deputy. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-8.0 Android-8.1 Android-9Android ID: A-145669109

- [https://github.com/it4ch1-007/poc_strandhogg2_cve_2020_0096](https://github.com/it4ch1-007/poc_strandhogg2_cve_2020_0096) :  ![starts](https://img.shields.io/github/stars/it4ch1-007/poc_strandhogg2_cve_2020_0096.svg) ![forks](https://img.shields.io/github/forks/it4ch1-007/poc_strandhogg2_cve_2020_0096.svg)


## CVE-2020-0022
 In reassemble_and_dispatch of packet_fragmenter.cc, there is possible out of bounds write due to an incorrect bounds calculation. This could lead to remote code execution over Bluetooth with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-8.0 Android-8.1 Android-9 Android-10Android ID: A-143894715

- [https://github.com/kalibb/CVE-2020-0022](https://github.com/kalibb/CVE-2020-0022) :  ![starts](https://img.shields.io/github/stars/kalibb/CVE-2020-0022.svg) ![forks](https://img.shields.io/github/forks/kalibb/CVE-2020-0022.svg)

