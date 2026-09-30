# Update 2026-09-30
## CVE-2026-101055
 A security flaw has been discovered in Thinkware U3000 up to 1.02.04. Affected by this vulnerability is the function GET_STATUS of the component TCP Service. The manipulation of the argument wifi_info results in information disclosure. The attack can be executed remotely. The exploit has been released to the public and may be used for attacks. The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/turretsec/u3000py](https://github.com/turretsec/u3000py) :  ![starts](https://img.shields.io/github/stars/turretsec/u3000py.svg) ![forks](https://img.shields.io/github/forks/turretsec/u3000py.svg)
- [https://github.com/turretsec/disclosure-thinkware-u3000](https://github.com/turretsec/disclosure-thinkware-u3000) :  ![starts](https://img.shields.io/github/stars/turretsec/disclosure-thinkware-u3000.svg) ![forks](https://img.shields.io/github/forks/turretsec/disclosure-thinkware-u3000.svg)


## CVE-2026-101054
 A vulnerability was identified in Thinkware U3000 up to 1.02.04. Affected is the function get_file of the file /tmp/wpa_supplicant.conf of the component TCP Service. The manipulation leads to improper access controls. Remote exploitation of the attack is possible. The exploit is publicly available and might be used. The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/turretsec/u3000py](https://github.com/turretsec/u3000py) :  ![starts](https://img.shields.io/github/stars/turretsec/u3000py.svg) ![forks](https://img.shields.io/github/forks/turretsec/u3000py.svg)
- [https://github.com/turretsec/disclosure-thinkware-u3000](https://github.com/turretsec/disclosure-thinkware-u3000) :  ![starts](https://img.shields.io/github/stars/turretsec/disclosure-thinkware-u3000.svg) ![forks](https://img.shields.io/github/forks/turretsec/disclosure-thinkware-u3000.svg)


## CVE-2026-101053
 A vulnerability was determined in Thinkware U3000 up to 1.02.04. This impacts the function PUT_FILE of the file /tmp/wpa_supplicant.conf of the component TCP Service. Executing a manipulation of the argument path can lead to improper access controls. The attack may be launched remotely. The exploit has been publicly disclosed and may be utilized. The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/turretsec/u3000py](https://github.com/turretsec/u3000py) :  ![starts](https://img.shields.io/github/stars/turretsec/u3000py.svg) ![forks](https://img.shields.io/github/forks/turretsec/u3000py.svg)
- [https://github.com/turretsec/disclosure-thinkware-u3000](https://github.com/turretsec/disclosure-thinkware-u3000) :  ![starts](https://img.shields.io/github/stars/turretsec/disclosure-thinkware-u3000.svg) ![forks](https://img.shields.io/github/forks/turretsec/disclosure-thinkware-u3000.svg)


## CVE-2026-100903
 A vulnerability was identified in ООО НПО Ритм GEOritm up to 2.45.1. This affects an unknown part of the file /restapi/objects/obj-groups of the component REST API. Such manipulation of the argument objectId leads to missing authentication. The attack can be launched remotely. The exploit is publicly available and might be used. Upgrading to version 2.46 is able to mitigate this issue. It is advisable to upgrade the affected component. The vendor confirms: "In August 2026, NPO Ritm received an official vulnerability notification from the Russian Federal Service for Technical and Export Control (FSTEC Russia). The vulnerability was registered under identifier BDU:2026-11235. Following our internal investigation, we confirmed the vulnerability and implemented the necessary security fixes. The vulnerability has been fixed on our hosted GEO.RITM server at geo.ritm.ru. The fix has also been included in GEO.RITM version 2.46, which is already being distributed to our customers."

- [https://github.com/4ybrick/CVE-2026-100903](https://github.com/4ybrick/CVE-2026-100903) :  ![starts](https://img.shields.io/github/stars/4ybrick/CVE-2026-100903.svg) ![forks](https://img.shields.io/github/forks/4ybrick/CVE-2026-100903.svg)


## CVE-2026-100886
 A vulnerability was identified in Seetong T8108, T8108P, T8116 and T8232 4.6.1.4-build202604241011. The affected element is an unknown function of the component Debug Service. Such manipulation leads to improper authentication. The attack may be launched remotely. The exploit is publicly available and might be used. The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/heapframe/seetong-ts81xxd3x-rce](https://github.com/heapframe/seetong-ts81xxd3x-rce) :  ![starts](https://img.shields.io/github/stars/heapframe/seetong-ts81xxd3x-rce.svg) ![forks](https://img.shields.io/github/forks/heapframe/seetong-ts81xxd3x-rce.svg)


## CVE-2026-100721
 vm2 before 3.12.2 contains an authorization bypass in the NodeVM external-module resolver. When an embedder configures `require.external` with a custom resolver (and `context: 'host'`), `LegacyResolver.customResolve` in lib/resolver-compat.js records the resolved module directory in `this.externals` as `new RegExp('^' + escapeRegExp(resolvedPath))`, without requiring a path separator or end-of-string boundary. Untrusted guest code can therefore require the allowlisted module (e.g. `foo`) and then require the absolute path of a non-allowlisted sibling whose path merely shares the resolved prefix (e.g. `.../node_modules/foo2/index.js`); the sibling passes `isPathAllowedForModule` and is loaded through `hostRequire`, so its top-level code runs in the host process before the exports are wrapped with `vm.readonly`, resulting in a sandbox escape and arbitrary code execution in the host context.

- [https://github.com/murrez/CVE-2026-100721](https://github.com/murrez/CVE-2026-100721) :  ![starts](https://img.shields.io/github/stars/murrez/CVE-2026-100721.svg) ![forks](https://img.shields.io/github/forks/murrez/CVE-2026-100721.svg)


## CVE-2026-93958
 A vulnerability was found in D-Link R95 BE9500_1.00.16. This vulnerability affects the function system of the file /bin/ssi of the component DHMAPI. The manipulation of the argument NTPServer results in os command injection. The attack can be executed remotely. The exploit has been made public and could be used.

- [https://github.com/murrez/CVE-2026-93958](https://github.com/murrez/CVE-2026-93958) :  ![starts](https://img.shields.io/github/stars/murrez/CVE-2026-93958.svg) ![forks](https://img.shields.io/github/forks/murrez/CVE-2026-93958.svg)


## CVE-2026-88778
This issue affects ADC: before 14.1-73.37, before 13.1-64.23, before 14.1-73.37 FIPS, and before 13.1.37.279 FIPS and NDcPP; Gateway: before 14.1-73.37 and before 13.1-64.23.

- [https://github.com/ThomasPoppelgaard/netscaler-ctx697096-checker](https://github.com/ThomasPoppelgaard/netscaler-ctx697096-checker) :  ![starts](https://img.shields.io/github/stars/ThomasPoppelgaard/netscaler-ctx697096-checker.svg) ![forks](https://img.shields.io/github/forks/ThomasPoppelgaard/netscaler-ctx697096-checker.svg)


## CVE-2026-88777
This issue affects ADC: before 14.1-73.37, before 13.1-64.23, before 14.1-73.37 FIPS, and before 13.1.37.279 FIPS and NDcPP; Gateway: before 14.1-73.37 and before 13.1-64.23  leading to unpredictable or erroneous behavior or Denial of Service

- [https://github.com/ThomasPoppelgaard/netscaler-ctx697096-checker](https://github.com/ThomasPoppelgaard/netscaler-ctx697096-checker) :  ![starts](https://img.shields.io/github/stars/ThomasPoppelgaard/netscaler-ctx697096-checker.svg) ![forks](https://img.shields.io/github/forks/ThomasPoppelgaard/netscaler-ctx697096-checker.svg)


## CVE-2026-88776
This issue affects ADC: before 14.1-73.37, before 13.1-64.23, before 14.1-73.37 FIPS, and before 13.1.37.279 FIPS and NDcPP; Gateway: before 14.1-73.37 and before 13.1-64.23  leading to unpredictable or erroneous behavior or Denial of Service

- [https://github.com/ThomasPoppelgaard/netscaler-ctx697096-checker](https://github.com/ThomasPoppelgaard/netscaler-ctx697096-checker) :  ![starts](https://img.shields.io/github/stars/ThomasPoppelgaard/netscaler-ctx697096-checker.svg) ![forks](https://img.shields.io/github/forks/ThomasPoppelgaard/netscaler-ctx697096-checker.svg)


## CVE-2026-88775
This issue affects ADC: before 14.1-73.37, before 13.1-64.23, before 14.1-73.37 FIPS, and before 13.1.37.279 FIPS and NDcPP; Gateway: before 14.1-73.37 and before 13.1-64.23 leading Memory overflow vulnerability leading to unpredictable or erroneous behavior or Denial of Service

- [https://github.com/ThomasPoppelgaard/netscaler-ctx697096-checker](https://github.com/ThomasPoppelgaard/netscaler-ctx697096-checker) :  ![starts](https://img.shields.io/github/stars/ThomasPoppelgaard/netscaler-ctx697096-checker.svg) ![forks](https://img.shields.io/github/forks/ThomasPoppelgaard/netscaler-ctx697096-checker.svg)


## CVE-2026-88774
This issue affects ADC: before 14.1-73.37, before 13.1-64.23, before 14.1-73.37 FIPS, and before 13.1.37.279 FIPS and NDcPP; Gateway: before 14.1-73.37 and before 13.1-64.23 leading to a feature policy bypass due to improper HTTP URL based expression usage.

- [https://github.com/ThomasPoppelgaard/netscaler-ctx697096-checker](https://github.com/ThomasPoppelgaard/netscaler-ctx697096-checker) :  ![starts](https://img.shields.io/github/stars/ThomasPoppelgaard/netscaler-ctx697096-checker.svg) ![forks](https://img.shields.io/github/forks/ThomasPoppelgaard/netscaler-ctx697096-checker.svg)


## CVE-2026-88773
This issue affects ADC: before 14.1-73.37, before 13.1-64.23, before 14.1-73.37 FIPS, and before 13.1-37.279 and NDcPP; Gateway: before 14.1-73.37 FIPS and before 13.1-64.23.

- [https://github.com/ThomasPoppelgaard/netscaler-ctx697096-checker](https://github.com/ThomasPoppelgaard/netscaler-ctx697096-checker) :  ![starts](https://img.shields.io/github/stars/ThomasPoppelgaard/netscaler-ctx697096-checker.svg) ![forks](https://img.shields.io/github/forks/ThomasPoppelgaard/netscaler-ctx697096-checker.svg)


## CVE-2026-88772
This issue affects ADC: before 14.1-73.37, before 13.1-64.23, before 14.1-73.37 FIPS, and before 13.1.37.279 FIPS and NDcPP; Gateway: before 14.1-73.37 and before 13.1-64.23 leading to Remote Code Execution or Denial of Service

- [https://github.com/FollowerSeize/CVE-2026-88772-POC](https://github.com/FollowerSeize/CVE-2026-88772-POC) :  ![starts](https://img.shields.io/github/stars/FollowerSeize/CVE-2026-88772-POC.svg) ![forks](https://img.shields.io/github/forks/FollowerSeize/CVE-2026-88772-POC.svg)
- [https://github.com/technion/netscaler_scanner](https://github.com/technion/netscaler_scanner) :  ![starts](https://img.shields.io/github/stars/technion/netscaler_scanner.svg) ![forks](https://img.shields.io/github/forks/technion/netscaler_scanner.svg)
- [https://github.com/ThomasPoppelgaard/netscaler-ctx697096-checker](https://github.com/ThomasPoppelgaard/netscaler-ctx697096-checker) :  ![starts](https://img.shields.io/github/stars/ThomasPoppelgaard/netscaler-ctx697096-checker.svg) ![forks](https://img.shields.io/github/forks/ThomasPoppelgaard/netscaler-ctx697096-checker.svg)


## CVE-2026-88771
This issue affects ADC: before 14.1-73.37, before 13.1-64.23, before 14.1-73.37 FIPS, and before 13.1.37.279 FIPS and NDcPP; Gateway: before 14.1-73.37 and before 13.1-64.23 leading to an unauthenticated attacker to execute arbitrary commands.

- [https://github.com/securekomodo/citrixInspector](https://github.com/securekomodo/citrixInspector) :  ![starts](https://img.shields.io/github/stars/securekomodo/citrixInspector.svg) ![forks](https://img.shields.io/github/forks/securekomodo/citrixInspector.svg)
- [https://github.com/watchtowrlabs/watchTowr-vs-Citrix-Netscaler-CVE-2026-88771](https://github.com/watchtowrlabs/watchTowr-vs-Citrix-Netscaler-CVE-2026-88771) :  ![starts](https://img.shields.io/github/stars/watchtowrlabs/watchTowr-vs-Citrix-Netscaler-CVE-2026-88771.svg) ![forks](https://img.shields.io/github/forks/watchtowrlabs/watchTowr-vs-Citrix-Netscaler-CVE-2026-88771.svg)
- [https://github.com/EXEcution-py/CVE-2026-88771-POC](https://github.com/EXEcution-py/CVE-2026-88771-POC) :  ![starts](https://img.shields.io/github/stars/EXEcution-py/CVE-2026-88771-POC.svg) ![forks](https://img.shields.io/github/forks/EXEcution-py/CVE-2026-88771-POC.svg)
- [https://github.com/techupdate24/citrix-netscaler-cve-2026-88771-rce](https://github.com/techupdate24/citrix-netscaler-cve-2026-88771-rce) :  ![starts](https://img.shields.io/github/stars/techupdate24/citrix-netscaler-cve-2026-88771-rce.svg) ![forks](https://img.shields.io/github/forks/techupdate24/citrix-netscaler-cve-2026-88771-rce.svg)
- [https://github.com/technion/netscaler_scanner](https://github.com/technion/netscaler_scanner) :  ![starts](https://img.shields.io/github/stars/technion/netscaler_scanner.svg) ![forks](https://img.shields.io/github/forks/technion/netscaler_scanner.svg)
- [https://github.com/ThomasPoppelgaard/netscaler-ctx697096-checker](https://github.com/ThomasPoppelgaard/netscaler-ctx697096-checker) :  ![starts](https://img.shields.io/github/stars/ThomasPoppelgaard/netscaler-ctx697096-checker.svg) ![forks](https://img.shields.io/github/forks/ThomasPoppelgaard/netscaler-ctx697096-checker.svg)


## CVE-2026-87902
 An unauthenticated attacker can make `get_page_template()` page-template resolution include a chosen readable local `.php` file outside the active theme directories. If relevant pre-conditions for both the server and the active theme are met, this can lead to RCE.

- [https://github.com/HackfutSecRoot/CVE-2026-87902](https://github.com/HackfutSecRoot/CVE-2026-87902) :  ![starts](https://img.shields.io/github/stars/HackfutSecRoot/CVE-2026-87902.svg) ![forks](https://img.shields.io/github/forks/HackfutSecRoot/CVE-2026-87902.svg)
- [https://github.com/MRdark-ops/CVE-2026-87902](https://github.com/MRdark-ops/CVE-2026-87902) :  ![starts](https://img.shields.io/github/stars/MRdark-ops/CVE-2026-87902.svg) ![forks](https://img.shields.io/github/forks/MRdark-ops/CVE-2026-87902.svg)


## CVE-2026-86950
 An out-of-bounds write issue was addressed with improved bounds checking. This issue is fixed in iOS 26.7.1 and iPadOS 26.7.1, macOS Sequoia 15.8.1, macOS Tahoe 26.7.1. Processing a maliciously crafted file may lead to arbitrary code execution. Apple is aware of a report that this issue may have been exploited in an extremely sophisticated attack against specific targeted individuals on versions of iOS before iOS 27.

- [https://github.com/DeAurity/CVE-2026-86950-POC](https://github.com/DeAurity/CVE-2026-86950-POC) :  ![starts](https://img.shields.io/github/stars/DeAurity/CVE-2026-86950-POC.svg) ![forks](https://img.shields.io/github/forks/DeAurity/CVE-2026-86950-POC.svg)


## CVE-2026-85984
 The miniOrange OTP Login, Verification and SMS Notifications plugin for WordPress is vulnerable to Authentication Bypass via the mo_wp_login_intent parameter in all versions up to, and including, 5.5.5. This is due to a missing password-intent guard in the skip_pass_fallback-enabled configuration branch of the mo_by_pass_login() function, which treats administrator role membership alone as sufficient authentication whenever the unauthenticated, unverified POST parameter mo_wp_login_intent is submitted with the value otp, causing mo_get_user() to skip wp_authenticate_username_password() and resolve a WP_User purely from a username lookup. This makes it possible for unauthenticated attackers to log in as any existing administrator account by supplying only a known username and an empty password alongside mo_wp_login_intent=otp, with no password or OTP verification required. Exploitation is conditional on a site administrator having simultaneously enabled the following plugin options: WP Login OTP, Login with Only OTP, Allow Users to Login with Username and Password, and Admin OTP Bypass.

- [https://github.com/murrez/CVE-2026-85984](https://github.com/murrez/CVE-2026-85984) :  ![starts](https://img.shields.io/github/stars/murrez/CVE-2026-85984.svg) ![forks](https://img.shields.io/github/forks/murrez/CVE-2026-85984.svg)


## CVE-2026-85706
 GitLab has remediated an issue in GitLab CE/EE affecting all versions from 18.7 before 18.11.12, 19.0 before 19.0.9, 19.1 before 19.1.8, 19.2 before 19.2.6, and 19.3 before 19.3.2 that, under certain conditions, an unauthenticated user could have read arbitrary files from the GitLab server due to improper path confinement and missing authentication enforcement in the repository commits API.

- [https://github.com/EQSTLab/CVE-2026-85706](https://github.com/EQSTLab/CVE-2026-85706) :  ![starts](https://img.shields.io/github/stars/EQSTLab/CVE-2026-85706.svg) ![forks](https://img.shields.io/github/forks/EQSTLab/CVE-2026-85706.svg)


## CVE-2026-82384
 Deserialization of Untrusted Data in Apache Roller 6.1.5 allows an unauthenticated remote attacker to cause deserialization of attacker-controlled bytes, because the XML-RPC endpoint accepts vendor extension types that are deserialized during request parsing, before authentication. The servlet is mapped unconditionally, so parsing occurs even when the global XML-RPC feature is set to disabled; no non-default configuration is required for this path. This can lead to remote code execution. Users are recommended to upgrade to Apache Roller 6.1.6 or later, which disables the extension types and rejects requests when the XML-RPC feature is disabled.

- [https://github.com/murrez/CVE-2026-82384](https://github.com/murrez/CVE-2026-82384) :  ![starts](https://img.shields.io/github/stars/murrez/CVE-2026-82384.svg) ![forks](https://img.shields.io/github/forks/murrez/CVE-2026-82384.svg)


## CVE-2026-81000
other allocation paths.

- [https://github.com/suominen/tunderflow](https://github.com/suominen/tunderflow) :  ![starts](https://img.shields.io/github/stars/suominen/tunderflow.svg) ![forks](https://img.shields.io/github/forks/suominen/tunderflow.svg)
- [https://github.com/mym0us3r/Detect-Quartet-of-Linux-local-root-vulns-with-Wazuh](https://github.com/mym0us3r/Detect-Quartet-of-Linux-local-root-vulns-with-Wazuh) :  ![starts](https://img.shields.io/github/stars/mym0us3r/Detect-Quartet-of-Linux-local-root-vulns-with-Wazuh.svg) ![forks](https://img.shields.io/github/forks/mym0us3r/Detect-Quartet-of-Linux-local-root-vulns-with-Wazuh.svg)


## CVE-2026-80844
errors to the existing AH6 input and output error paths.

- [https://github.com/suominen/dirtyah6](https://github.com/suominen/dirtyah6) :  ![starts](https://img.shields.io/github/stars/suominen/dirtyah6.svg) ![forks](https://img.shields.io/github/forks/suominen/dirtyah6.svg)
- [https://github.com/mym0us3r/Detect-Quartet-of-Linux-local-root-vulns-with-Wazuh](https://github.com/mym0us3r/Detect-Quartet-of-Linux-local-root-vulns-with-Wazuh) :  ![starts](https://img.shields.io/github/stars/mym0us3r/Detect-Quartet-of-Linux-local-root-vulns-with-Wazuh.svg) ![forks](https://img.shields.io/github/forks/mym0us3r/Detect-Quartet-of-Linux-local-root-vulns-with-Wazuh.svg)


## CVE-2026-75604
 Next.js is a React framework for building full-stack web applications. From 13.4.0 until 15.5.24 and 16.3.3, Next.js applications using Pages Router or App Router without Cache Components on Windows-hosted servers do not consistently escape backslashes in route segments before constructing incremental-cache paths. In packages/next/src/shared/lib/router/utils/escape-path-delimiters.ts and packages/next/src/server/lib/incremental-cache/file-system-cache.ts, a remote request can supply encoded Windows path separators that traverse outside the intended cache root and expose private build data, including the server-reference-manifest encryption key. Disclosure of that key can enable remote code execution in the affected application. This issue is fixed in versions 15.5.24 and 16.3.3.

- [https://github.com/ZeroDayEvil/CVE-2026-75604-PoC](https://github.com/ZeroDayEvil/CVE-2026-75604-PoC) :  ![starts](https://img.shields.io/github/stars/ZeroDayEvil/CVE-2026-75604-PoC.svg) ![forks](https://img.shields.io/github/forks/ZeroDayEvil/CVE-2026-75604-PoC.svg)


## CVE-2026-74469
to return its existing transport at the limit.

- [https://github.com/suominen/diagspill](https://github.com/suominen/diagspill) :  ![starts](https://img.shields.io/github/stars/suominen/diagspill.svg) ![forks](https://img.shields.io/github/forks/suominen/diagspill.svg)
- [https://github.com/mym0us3r/Detect-Quartet-of-Linux-local-root-vulns-with-Wazuh](https://github.com/mym0us3r/Detect-Quartet-of-Linux-local-root-vulns-with-Wazuh) :  ![starts](https://img.shields.io/github/stars/mym0us3r/Detect-Quartet-of-Linux-local-root-vulns-with-Wazuh.svg) ![forks](https://img.shields.io/github/forks/mym0us3r/Detect-Quartet-of-Linux-local-root-vulns-with-Wazuh.svg)


## CVE-2026-68121
relocates the head.

- [https://github.com/suominen/pppoeject](https://github.com/suominen/pppoeject) :  ![starts](https://img.shields.io/github/stars/suominen/pppoeject.svg) ![forks](https://img.shields.io/github/forks/suominen/pppoeject.svg)
- [https://github.com/mym0us3r/Detect-Quartet-of-Linux-local-root-vulns-with-Wazuh](https://github.com/mym0us3r/Detect-Quartet-of-Linux-local-root-vulns-with-Wazuh) :  ![starts](https://img.shields.io/github/stars/mym0us3r/Detect-Quartet-of-Linux-local-root-vulns-with-Wazuh.svg) ![forks](https://img.shields.io/github/forks/mym0us3r/Detect-Quartet-of-Linux-local-root-vulns-with-Wazuh.svg)


## CVE-2026-64561
far from ideal; that flaw will be addressed separately.

- [https://github.com/suominen/zapscape](https://github.com/suominen/zapscape) :  ![starts](https://img.shields.io/github/stars/suominen/zapscape.svg) ![forks](https://img.shields.io/github/forks/suominen/zapscape.svg)


## CVE-2026-63030
 WordPress 6.9.x before 6.9.5 and 7.0.x before 7.0.2 is affected by a REST API batch endpoint route confusion issue which, combined with the author__not_in WP_Query SQL Injection (CVE-2026-60137), could allow an attacker to perform SQL Injection and achieve Remote Code Execution.

- [https://github.com/K52-ai/wp2shell](https://github.com/K52-ai/wp2shell) :  ![starts](https://img.shields.io/github/stars/K52-ai/wp2shell.svg) ![forks](https://img.shields.io/github/forks/K52-ai/wp2shell.svg)


## CVE-2026-62911
 Authentication bypass by capture-replay in Microsoft Exchange Server allows an authorized attacker to elevate privileges over a network.

- [https://github.com/ZeroDayEvil/CVE-2026-62911](https://github.com/ZeroDayEvil/CVE-2026-62911) :  ![starts](https://img.shields.io/github/stars/ZeroDayEvil/CVE-2026-62911.svg) ![forks](https://img.shields.io/github/forks/ZeroDayEvil/CVE-2026-62911.svg)


## CVE-2026-62878
 Stack-based buffer overflow in Windows DNS allows an unauthorized attacker to execute code over a network.

- [https://github.com/nmlz/CVE-2026-62878](https://github.com/nmlz/CVE-2026-62878) :  ![starts](https://img.shields.io/github/stars/nmlz/CVE-2026-62878.svg) ![forks](https://img.shields.io/github/forks/nmlz/CVE-2026-62878.svg)


## CVE-2026-60137
 WordPress 6.8.x before 6.8.6, 6.9.x before 6.9.5, and 7.0.x before 7.0.2 does not properly sanitise the author__not_in parameter of WP_Query, which could allow SQL Injection when a plugin or theme passes untrusted input to the parameter.

- [https://github.com/K52-ai/wp2shell](https://github.com/K52-ai/wp2shell) :  ![starts](https://img.shields.io/github/stars/K52-ai/wp2shell.svg) ![forks](https://img.shields.io/github/forks/K52-ai/wp2shell.svg)


## CVE-2026-58225
This issue affects postgrex: from 0.16.0 before 0.22.3.

- [https://github.com/sifatnotes/Learn-SecByte-CMS-CVE-Shell-to-Root-Privilege-Escalation-CTF-Labs](https://github.com/sifatnotes/Learn-SecByte-CMS-CVE-Shell-to-Root-Privilege-Escalation-CTF-Labs) :  ![starts](https://img.shields.io/github/stars/sifatnotes/Learn-SecByte-CMS-CVE-Shell-to-Root-Privilege-Escalation-CTF-Labs.svg) ![forks](https://img.shields.io/github/forks/sifatnotes/Learn-SecByte-CMS-CVE-Shell-to-Root-Privilege-Escalation-CTF-Labs.svg)


## CVE-2026-54121
 Improper authorization in Active Directory Certificate Services (AD CS) allows an authorized attacker to elevate privileges over a network.

- [https://github.com/ZeroDayEvil/CVE-2026-54121](https://github.com/ZeroDayEvil/CVE-2026-54121) :  ![starts](https://img.shields.io/github/stars/ZeroDayEvil/CVE-2026-54121.svg) ![forks](https://img.shields.io/github/forks/ZeroDayEvil/CVE-2026-54121.svg)


## CVE-2026-43499
  	changelog ]

- [https://github.com/ZeroDayEvil/CVE-2026-43499](https://github.com/ZeroDayEvil/CVE-2026-43499) :  ![starts](https://img.shields.io/github/stars/ZeroDayEvil/CVE-2026-43499.svg) ![forks](https://img.shields.io/github/forks/ZeroDayEvil/CVE-2026-43499.svg)
- [https://github.com/a2333c/DFRoot](https://github.com/a2333c/DFRoot) :  ![starts](https://img.shields.io/github/stars/a2333c/DFRoot.svg) ![forks](https://img.shields.io/github/forks/a2333c/DFRoot.svg)
- [https://github.com/zenyxx-xd/RootMyVivo-Exploit](https://github.com/zenyxx-xd/RootMyVivo-Exploit) :  ![starts](https://img.shields.io/github/stars/zenyxx-xd/RootMyVivo-Exploit.svg) ![forks](https://img.shields.io/github/forks/zenyxx-xd/RootMyVivo-Exploit.svg)


## CVE-2026-43284
destination-frag path or fall back to skb_cow_data().

- [https://github.com/coey0814/DirtyFrag-Galaxy](https://github.com/coey0814/DirtyFrag-Galaxy) :  ![starts](https://img.shields.io/github/stars/coey0814/DirtyFrag-Galaxy.svg) ![forks](https://img.shields.io/github/forks/coey0814/DirtyFrag-Galaxy.svg)


## CVE-2026-42980
 Integer underflow (wrap or wraparound) in Windows NT OS Kernel allows an authorized attacker to elevate privileges locally.

- [https://github.com/ZeroDayEvil/CVE-2026-42980-PoC](https://github.com/ZeroDayEvil/CVE-2026-42980-PoC) :  ![starts](https://img.shields.io/github/stars/ZeroDayEvil/CVE-2026-42980-PoC.svg) ![forks](https://img.shields.io/github/forks/ZeroDayEvil/CVE-2026-42980-PoC.svg)


## CVE-2026-41940
 cPanel and WHM versions after 11.40 contain an authentication bypass vulnerability in the login flow that allows unauthenticated remote attackers to gain unauthorized access to the control panel.

- [https://github.com/ZeroDayEvil/CVE-2026-41940-PoC](https://github.com/ZeroDayEvil/CVE-2026-41940-PoC) :  ![starts](https://img.shields.io/github/stars/ZeroDayEvil/CVE-2026-41940-PoC.svg) ![forks](https://img.shields.io/github/forks/ZeroDayEvil/CVE-2026-41940-PoC.svg)


## CVE-2026-41651
3. Late flag read at execution time (lines 2273–2277): The scheduler's idle callback reads cached_transaction_flags at dispatch time, not at authorization time. If flags were overwritten between authorization and execution, the backend sees the attacker's flags.

- [https://github.com/ZeroDayEvil/CVE-2026-41651](https://github.com/ZeroDayEvil/CVE-2026-41651) :  ![starts](https://img.shields.io/github/stars/ZeroDayEvil/CVE-2026-41651.svg) ![forks](https://img.shields.io/github/forks/ZeroDayEvil/CVE-2026-41651.svg)


## CVE-2026-40369
 Heap-based buffer overflow in Windows Kernel allows an authorized attacker to elevate privileges locally.

- [https://github.com/ZeroDayEvil/CVE-2026-40369-EXPLOIT](https://github.com/ZeroDayEvil/CVE-2026-40369-EXPLOIT) :  ![starts](https://img.shields.io/github/stars/ZeroDayEvil/CVE-2026-40369-EXPLOIT.svg) ![forks](https://img.shields.io/github/forks/ZeroDayEvil/CVE-2026-40369-EXPLOIT.svg)


## CVE-2026-39987
 marimo is a reactive Python notebook. Prior to 0.23.0, Marimo has a Pre-Auth RCE vulnerability. The terminal WebSocket endpoint /terminal/ws lacks authentication validation, allowing an unauthenticated attacker to obtain a full PTY shell and execute arbitrary system commands. Unlike other WebSocket endpoints (e.g., /ws) that correctly call validate_auth() for authentication, the /terminal/ws endpoint only checks the running mode and platform support before accepting connections, completely skipping authentication verification. This vulnerability is fixed in 0.23.0.

- [https://github.com/LaArana12/CVE-2026-39987-Marimo-Preauth-RCE](https://github.com/LaArana12/CVE-2026-39987-Marimo-Preauth-RCE) :  ![starts](https://img.shields.io/github/stars/LaArana12/CVE-2026-39987-Marimo-Preauth-RCE.svg) ![forks](https://img.shields.io/github/forks/LaArana12/CVE-2026-39987-Marimo-Preauth-RCE.svg)


## CVE-2026-38526
 An authenticated arbitrary file upload vulnerability in the /admin/tinymce/upload endpoint of Webkul Krayin CRM v2.2.x allows attackers to execute arbitrary code via uploading a crafted PHP file.

- [https://github.com/MRdark-ops/CVE-2026-38526](https://github.com/MRdark-ops/CVE-2026-38526) :  ![starts](https://img.shields.io/github/stars/MRdark-ops/CVE-2026-38526.svg) ![forks](https://img.shields.io/github/forks/MRdark-ops/CVE-2026-38526.svg)
- [https://github.com/Harry178945/CVE-2026-38526](https://github.com/Harry178945/CVE-2026-38526) :  ![starts](https://img.shields.io/github/stars/Harry178945/CVE-2026-38526.svg) ![forks](https://img.shields.io/github/forks/Harry178945/CVE-2026-38526.svg)


## CVE-2026-34990
 OpenPrinting CUPS is an open source printing system for Linux and other Unix-like operating systems. In versions 2.4.16 and prior, a local unprivileged user can coerce cupsd into authenticating to an attacker-controlled localhost IPP service with a reusable Authorization: Local ... token. That token is enough to drive /admin/ requests on localhost, and the attacker can combine CUPS-Create-Local-Printer with printer-is-shared=true to persist a file:///... queue even though the normal FileDevice policy rejects such URIs. Printing to that queue gives an arbitrary root file overwrite; the PoC below uses that primitive to drop a sudoers fragment and demonstrate root command execution. At time of publication, there are no publicly available patches.

- [https://github.com/Noorkhalel/CVE-2026-34990-CUPS-LPE-PoC](https://github.com/Noorkhalel/CVE-2026-34990-CUPS-LPE-PoC) :  ![starts](https://img.shields.io/github/stars/Noorkhalel/CVE-2026-34990-CUPS-LPE-PoC.svg) ![forks](https://img.shields.io/github/forks/Noorkhalel/CVE-2026-34990-CUPS-LPE-PoC.svg)
- [https://github.com/ungabunga-ctf/CVE-2026-34990](https://github.com/ungabunga-ctf/CVE-2026-34990) :  ![starts](https://img.shields.io/github/stars/ungabunga-ctf/CVE-2026-34990.svg) ![forks](https://img.shields.io/github/forks/ungabunga-ctf/CVE-2026-34990.svg)
- [https://github.com/OffensiveBias20/CVE-2026-34990-POC](https://github.com/OffensiveBias20/CVE-2026-34990-POC) :  ![starts](https://img.shields.io/github/stars/OffensiveBias20/CVE-2026-34990-POC.svg) ![forks](https://img.shields.io/github/forks/OffensiveBias20/CVE-2026-34990-POC.svg)
- [https://github.com/bara-almustafa/CVE-2026-34990-poc](https://github.com/bara-almustafa/CVE-2026-34990-poc) :  ![starts](https://img.shields.io/github/stars/bara-almustafa/CVE-2026-34990-poc.svg) ![forks](https://img.shields.io/github/forks/bara-almustafa/CVE-2026-34990-poc.svg)
- [https://github.com/offesivezapper/cve-2026-34990-POC](https://github.com/offesivezapper/cve-2026-34990-POC) :  ![starts](https://img.shields.io/github/stars/offesivezapper/cve-2026-34990-POC.svg) ![forks](https://img.shields.io/github/forks/offesivezapper/cve-2026-34990-POC.svg)


## CVE-2026-32740
 libheif is a HEIF and AVIF file format decoder and encoder. Versions 1.21.2 and prior contain a heap-buffer-overflow (write) vulnerability in the grid tile compositing, allowing an attacker to write 64 bytes of fully attacker-controlled data past the end of a chroma plane heap allocation by crafting a HEIF/AVIF file with a 1×4 grid of odd-height tiles. The overflow is triggered during normal image decoding with default build configuration. The written bytes are chroma (Cb/Cr) pixel values from the attacking tile, giving the attacker full control over the overflow content. This issue has been fixed in version 1.22.0.

- [https://github.com/FORTBRIDGE-UK/libheif-grid-nextjs-rce](https://github.com/FORTBRIDGE-UK/libheif-grid-nextjs-rce) :  ![starts](https://img.shields.io/github/stars/FORTBRIDGE-UK/libheif-grid-nextjs-rce.svg) ![forks](https://img.shields.io/github/forks/FORTBRIDGE-UK/libheif-grid-nextjs-rce.svg)


## CVE-2026-31431
AD directly.

- [https://github.com/mahradbt/copyfail-mitigation](https://github.com/mahradbt/copyfail-mitigation) :  ![starts](https://img.shields.io/github/stars/mahradbt/copyfail-mitigation.svg) ![forks](https://img.shields.io/github/forks/mahradbt/copyfail-mitigation.svg)


## CVE-2026-28912
 A logic issue was addressed with improved restrictions. This issue is fixed in macOS Sequoia 15.7.8, macOS Sonoma 14.8.7, macOS Tahoe 26.6. A user may be able to elevate privileges.

- [https://github.com/jvidhan/cve-2026-28912](https://github.com/jvidhan/cve-2026-28912) :  ![starts](https://img.shields.io/github/stars/jvidhan/cve-2026-28912.svg) ![forks](https://img.shields.io/github/forks/jvidhan/cve-2026-28912.svg)


## CVE-2026-24061
 telnetd in GNU Inetutils through 2.7 allows remote authentication bypass via a "-f root" value for the USER environment variable.

- [https://github.com/ZeroDayEvil/CVE-2026-24061](https://github.com/ZeroDayEvil/CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/ZeroDayEvil/CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/ZeroDayEvil/CVE-2026-24061.svg)


## CVE-2026-23111
skip active elements, process inactive ones.

- [https://github.com/imeiplus/CVE-2026-23111-PoC](https://github.com/imeiplus/CVE-2026-23111-PoC) :  ![starts](https://img.shields.io/github/stars/imeiplus/CVE-2026-23111-PoC.svg) ![forks](https://img.shields.io/github/forks/imeiplus/CVE-2026-23111-PoC.svg)


## CVE-2026-22777
 ComfyUI-Manager is an extension designed to enhance the usability of ComfyUI. Prior to versions 3.39.2 and 4.0.5, an attacker can inject special characters into HTTP query parameters to add arbitrary configuration values to the config.ini file. This can lead to security setting tampering or modification of application behavior. This issue has been patched in versions 3.39.2 and 4.0.5.

- [https://github.com/e5dfdd568a75282b712b6d93a7a18e12/CVE-2026-22777](https://github.com/e5dfdd568a75282b712b6d93a7a18e12/CVE-2026-22777) :  ![starts](https://img.shields.io/github/stars/e5dfdd568a75282b712b6d93a7a18e12/CVE-2026-22777.svg) ![forks](https://img.shields.io/github/forks/e5dfdd568a75282b712b6d93a7a18e12/CVE-2026-22777.svg)


## CVE-2026-20817
 Improper handling of insufficient permissions or privileges in Windows Error Reporting allows an authorized attacker to elevate privileges locally.

- [https://github.com/ZeroDayEvil/CVE-2026-20817](https://github.com/ZeroDayEvil/CVE-2026-20817) :  ![starts](https://img.shields.io/github/stars/ZeroDayEvil/CVE-2026-20817.svg) ![forks](https://img.shields.io/github/forks/ZeroDayEvil/CVE-2026-20817.svg)


## CVE-2026-18143
 The Request a Quote for WooCommerce plugin for WordPress is vulnerable to Arbitrary File Upload in all versions up to, and including, 2.9.2 via the `afrfq_submit_quote_via_popup()` function. This is due to missing file extension and MIME type validation in the popup upload handler, which uses the raw attacker-supplied filename directly as the destination for `move_uploaded_file()`. This makes it possible for unauthenticated attackers to upload executable files, such as PHP files, to a web-accessible temporary RFQ upload directory when a public quote rule with the multi-page popup flow is enabled.

- [https://github.com/Wayang1337/CVE-2026-18143](https://github.com/Wayang1337/CVE-2026-18143) :  ![starts](https://img.shields.io/github/stars/Wayang1337/CVE-2026-18143.svg) ![forks](https://img.shields.io/github/forks/Wayang1337/CVE-2026-18143.svg)


## CVE-2026-18110
 Concrete CMS 9 (9.0.0 through 9.5.2) does not perform an authorization check on the user selector autocomplete endpoint (/ccm/system/user/autocomplete), which backs the "Preview as User" panel and other user-selector components. The endpoint validates only a CSRF-style access token that is bound to the selector's display options rather than to the caller's identity or permissions, and that token is issued to anonymous visitors because the selector renders without an authorization check. Because an empty query resolves to a match-all filter, an unauthenticated attacker can submit an empty search and paginate the results to enumerate every backend account, disclosing the internal user ID, username, and email address of all administrative users, including the super-administrator (user ID 1). No password hashes or session material are disclosed The Concrete CMS security team gave this vulnerability a CVSS v4.0 score of 8.7 with vector CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N. Thanks thirtythree and YesWeHack for reporting.

- [https://github.com/flenz00/CVE-2026-18110-PoC](https://github.com/flenz00/CVE-2026-18110-PoC) :  ![starts](https://img.shields.io/github/stars/flenz00/CVE-2026-18110-PoC.svg) ![forks](https://img.shields.io/github/forks/flenz00/CVE-2026-18110-PoC.svg)


## CVE-2026-8452
 Memory overflow vulnerability NetScaler ADC and NetScaler Gateway leading to unpredictable or erroneous behavior and Denial of Service if the appliance is configured as a Gateway (SSL VPN, ICA Proxy, CVPN, RDP Proxy) or AAA virtual server

- [https://github.com/securekomodo/citrixInspector](https://github.com/securekomodo/citrixInspector) :  ![starts](https://img.shields.io/github/stars/securekomodo/citrixInspector.svg) ![forks](https://img.shields.io/github/forks/securekomodo/citrixInspector.svg)


## CVE-2026-6951
 Versions of the package simple-git before 3.36.0 are vulnerable to Remote Code Execution (RCE) due to an incomplete fix for [CVE-2022-25912](https://security.snyk.io/vuln/SNYK-JS-SIMPLEGIT-3112221) that blocks the -c option but not the equivalent --config form. If untrusted input can reach the options argument passed to simple-git, an attacker may still achieve remote code execution by enabling protocol.ext.allow=always and using an ext:: clone source.

- [https://github.com/EQSTLab/CVE-2026-6951](https://github.com/EQSTLab/CVE-2026-6951) :  ![starts](https://img.shields.io/github/stars/EQSTLab/CVE-2026-6951.svg) ![forks](https://img.shields.io/github/forks/EQSTLab/CVE-2026-6951.svg)


## CVE-2026-6913
 The Shortcodely plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the 'widget_area' parameter in all versions up to, and including, 1.0.1 due to insufficient input sanitization and output escaping. This makes it possible for authenticated attackers, with contributor-level access and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.

- [https://github.com/EntroVyx/CVE-2026-69137](https://github.com/EntroVyx/CVE-2026-69137) :  ![starts](https://img.shields.io/github/stars/EntroVyx/CVE-2026-69137.svg) ![forks](https://img.shields.io/github/forks/EntroVyx/CVE-2026-69137.svg)


## CVE-2026-5054
The specific flaw exists within the handling of command line parameters. The issue results from the lack of proper validation of a user-supplied path prior to using it in file operations. An attacker can leverage this vulnerability to escalate privileges and execute arbitrary code in the context of root. Was ZDI-CAN-28630.

- [https://github.com/do4choo/CVE-2026-5054](https://github.com/do4choo/CVE-2026-5054) :  ![starts](https://img.shields.io/github/stars/do4choo/CVE-2026-5054.svg) ![forks](https://img.shields.io/github/forks/do4choo/CVE-2026-5054.svg)


## CVE-2026-5053
The specific flaw exists within the handling of environment variables. The issue results from the lack of proper validation of a user-supplied path prior to using it in file operations. An attacker can leverage this vulnerability to delete files in the context of root. Was ZDI-CAN-28644.

- [https://github.com/do4choo/CVE-2026-5053](https://github.com/do4choo/CVE-2026-5053) :  ![starts](https://img.shields.io/github/stars/do4choo/CVE-2026-5053.svg) ![forks](https://img.shields.io/github/forks/do4choo/CVE-2026-5053.svg)


## CVE-2026-4349
 A vulnerability was determined in Duende IdentityServer4 up to 4.1.2. The affected element is an unknown function of the file /connect/authorize of the component Token Renewal Endpoint. This manipulation of the argument id_token_hint causes improper authentication. It is possible to initiate the attack remotely. The attack is considered to have high complexity. The exploitability is described as difficult. This vulnerability only affects products that are no longer supported by the maintainer.

- [https://github.com/qsvggff-spec/oppo-A5-PRO-5G-CVE-2026-43499](https://github.com/qsvggff-spec/oppo-A5-PRO-5G-CVE-2026-43499) :  ![starts](https://img.shields.io/github/stars/qsvggff-spec/oppo-A5-PRO-5G-CVE-2026-43499.svg) ![forks](https://img.shields.io/github/forks/qsvggff-spec/oppo-A5-PRO-5G-CVE-2026-43499.svg)


## CVE-2026-3143
 The Total Upkeep – WordPress Backup Plugin plus Restore & Migrate by BoldGrid plugin for WordPress is vulnerable to unauthorized modification of data due to a missing capability check on the 'wp_ajax_cli_cancel' function in all versions up to, and including, 1.17.1. This makes it possible for unauthenticated attackers to cancel a pending rollback, potentially preventing a WordPress installation from automatically reverting a failed update.

- [https://github.com/scriptzteam/Paranoid-Copy-Fail-CVE-2026-31431](https://github.com/scriptzteam/Paranoid-Copy-Fail-CVE-2026-31431) :  ![starts](https://img.shields.io/github/stars/scriptzteam/Paranoid-Copy-Fail-CVE-2026-31431.svg) ![forks](https://img.shields.io/github/forks/scriptzteam/Paranoid-Copy-Fail-CVE-2026-31431.svg)
- [https://github.com/ZeroDayEvil/CVE-2026-31431](https://github.com/ZeroDayEvil/CVE-2026-31431) :  ![starts](https://img.shields.io/github/stars/ZeroDayEvil/CVE-2026-31431.svg) ![forks](https://img.shields.io/github/forks/ZeroDayEvil/CVE-2026-31431.svg)


## CVE-2025-67303
 An issue in ComfyUI-Manager prior to version 3.38 allowed remote attackers to potentially manipulate its configuration and critical data. This was due to the application storing its files in an insufficiently protected location that was accessible via the web interface

- [https://github.com/e5dfdd568a75282b712b6d93a7a18e12/CVE-2026-22777](https://github.com/e5dfdd568a75282b712b6d93a7a18e12/CVE-2026-22777) :  ![starts](https://img.shields.io/github/stars/e5dfdd568a75282b712b6d93a7a18e12/CVE-2026-22777.svg) ![forks](https://img.shields.io/github/forks/e5dfdd568a75282b712b6d93a7a18e12/CVE-2026-22777.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-14x](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-14x) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-14x.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-14x.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp.svg)


## CVE-2025-63353
 A vulnerability in FiberHome GPON ONU HG6145F1 RP4423 allows the device's factory default Wi-Fi password (WPA/WPA2 pre-shared key) to be predicted from the SSID. The device generates default passwords using a deterministic algorithm that derives the router passphrase from the SSID, enabling an attacker who can observe the SSID to predict the default password without authentication or user interaction.

- [https://github.com/zvckster/CVE-2025-63353](https://github.com/zvckster/CVE-2025-63353) :  ![starts](https://img.shields.io/github/stars/zvckster/CVE-2025-63353.svg) ![forks](https://img.shields.io/github/forks/zvckster/CVE-2025-63353.svg)


## CVE-2025-55182
 A pre-authentication remote code execution vulnerability exists in React Server Components versions 19.0.0, 19.1.0, 19.1.1, and 19.2.0 including the following packages: react-server-dom-parcel, react-server-dom-turbopack, and react-server-dom-webpack. The vulnerable code unsafely deserializes payloads from HTTP requests to Server Function endpoints.

- [https://github.com/timsonner/React2Shell-CVE-2025-55182](https://github.com/timsonner/React2Shell-CVE-2025-55182) :  ![starts](https://img.shields.io/github/stars/timsonner/React2Shell-CVE-2025-55182.svg) ![forks](https://img.shields.io/github/forks/timsonner/React2Shell-CVE-2025-55182.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/Heimd411/CVE-2025-29927-PoC](https://github.com/Heimd411/CVE-2025-29927-PoC) :  ![starts](https://img.shields.io/github/stars/Heimd411/CVE-2025-29927-PoC.svg) ![forks](https://img.shields.io/github/forks/Heimd411/CVE-2025-29927-PoC.svg)


## CVE-2025-6647
The specific flaw exists within the parsing of U3D files. The issue results from the lack of proper validation of user-supplied data, which can result in a write past the end of an allocated object. An attacker can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-26644.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-packagemanager-field](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-packagemanager-field) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-packagemanager-field.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-packagemanager-field.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-15x](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-15x) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-15x.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-15x.svg)


## CVE-2025-5777
 Insufficient input validation leading to memory overread when the NetScaler is configured as a Gateway (VPN virtual server, ICA Proxy, CVPN, RDP Proxy) OR AAA virtual server

- [https://github.com/securekomodo/citrixInspector](https://github.com/securekomodo/citrixInspector) :  ![starts](https://img.shields.io/github/stars/securekomodo/citrixInspector.svg) ![forks](https://img.shields.io/github/forks/securekomodo/citrixInspector.svg)


## CVE-2024-54767
 An access control issue in the component /juis_boxinfo.xml of AVM FRITZ!Box 7530 AX v7.59 allows attackers to obtain sensitive information without authentication. NOTE: this is disputed by the Supplier because it cannot be reproduced, and the issue report focuses on an unintended configuration with direct Internet exposure.

- [https://github.com/sysadmin420/AVM-FRITZ-Box-CVE-2024-54767-Exploit](https://github.com/sysadmin420/AVM-FRITZ-Box-CVE-2024-54767-Exploit) :  ![starts](https://img.shields.io/github/stars/sysadmin420/AVM-FRITZ-Box-CVE-2024-54767-Exploit.svg) ![forks](https://img.shields.io/github/forks/sysadmin420/AVM-FRITZ-Box-CVE-2024-54767-Exploit.svg)


## CVE-2024-32002
 Git is a revision control system. Prior to versions 2.45.1, 2.44.1, 2.43.4, 2.42.2, 2.41.1, 2.40.2, and 2.39.4, repositories with submodules can be crafted in a way that exploits a bug in Git whereby it can be fooled into writing files not into the submodule's worktree but into a `.git/` directory. This allows writing a hook that will be executed while the clone operation is still running, giving the user no opportunity to inspect the code that is being executed. The problem has been patched in versions 2.45.1, 2.44.1, 2.43.4, 2.42.2, 2.41.1, 2.40.2, and 2.39.4. If symbolic link support is disabled in Git (e.g. via `git config --global core.symlinks false`), the described attack won't work. As always, it is best to avoid cloning repositories from untrusted sources.

- [https://github.com/happymimimix/Break-This-Repo-Even-Further](https://github.com/happymimimix/Break-This-Repo-Even-Further) :  ![starts](https://img.shields.io/github/stars/happymimimix/Break-This-Repo-Even-Further.svg) ![forks](https://img.shields.io/github/forks/happymimimix/Break-This-Repo-Even-Further.svg)


## CVE-2021-43718
 An Authentication Bypass vulnerability exists in EPSON EH-TW5350 EPSON 150075647YWWV110, which could let a remote malicious user cause a Denial of Service via specially crafted series of HTTP..

- [https://github.com/dpfkdlemtp/CVE-2021-43718](https://github.com/dpfkdlemtp/CVE-2021-43718) :  ![starts](https://img.shields.io/github/stars/dpfkdlemtp/CVE-2021-43718.svg) ![forks](https://img.shields.io/github/forks/dpfkdlemtp/CVE-2021-43718.svg)


## CVE-2021-43717
 An issue exists in pson EH-TW5350 Epson iProjection.apk v3.2.6. If you identify a projector equipped with an iProjection function, you can access the projector using hard-coded authentication information and control the projector maliciously.

- [https://github.com/dpfkdlemtp/CVE-2021-43717](https://github.com/dpfkdlemtp/CVE-2021-43717) :  ![starts](https://img.shields.io/github/stars/dpfkdlemtp/CVE-2021-43717.svg) ![forks](https://img.shields.io/github/forks/dpfkdlemtp/CVE-2021-43717.svg)


## CVE-2021-43716
 Verification Bypass vulnerability exists in EPSON 150075647YWWV110 EasyMP Network Updater Ver.1.20. The Epson projector can be updated by encrypted firmware through USB.

- [https://github.com/dpfkdlemtp/CVE-2021-43716](https://github.com/dpfkdlemtp/CVE-2021-43716) :  ![starts](https://img.shields.io/github/stars/dpfkdlemtp/CVE-2021-43716.svg) ![forks](https://img.shields.io/github/forks/dpfkdlemtp/CVE-2021-43716.svg)


## CVE-2021-21315
 The System Information Library for Node.JS (npm package "systeminformation") is an open source collection of functions to retrieve detailed hardware, system and OS information. In systeminformation before version 5.3.1 there is a command injection vulnerability. Problem was fixed in version 5.3.1. As a workaround instead of upgrading, be sure to check or sanitize service parameters that are passed to si.inetLatency(), si.inetChecksite(), si.services(), si.processLoad() ... do only allow strings, reject any arrays. String sanitation works as expected.

- [https://github.com/jimahub/scenario-d-kev](https://github.com/jimahub/scenario-d-kev) :  ![starts](https://img.shields.io/github/stars/jimahub/scenario-d-kev.svg) ![forks](https://img.shields.io/github/forks/jimahub/scenario-d-kev.svg)


## CVE-2021-4422
 The POST SMTP Mailer plugin for WordPress is vulnerable to Cross-Site Request Forgery in versions up to, and including, 2.0.20. This is due to missing or incorrect nonce validation on the handleCsvExport() function. This makes it possible for unauthenticated attackers to trigger a CSV export via a forged request granted they can trick a site administrator into performing an action such as clicking on a link.

- [https://github.com/asd58584388/CVE-2021-44228](https://github.com/asd58584388/CVE-2021-44228) :  ![starts](https://img.shields.io/github/stars/asd58584388/CVE-2021-44228.svg) ![forks](https://img.shields.io/github/forks/asd58584388/CVE-2021-44228.svg)


## CVE-2021-4177
 livehelperchat is vulnerable to Generation of Error Message Containing Sensitive Information

- [https://github.com/sixpacksecurity/CVE-2021-41773](https://github.com/sixpacksecurity/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/sixpacksecurity/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/sixpacksecurity/CVE-2021-41773.svg)


## CVE-2020-28707
 The Stockdio Historical Chart plugin before 2.8.1 for WordPress is affected by Cross Site Scripting (XSS) via stockdio_chart_historical-wp.js in wp-content/plugins/stockdio-historical-chart/assets/ because the origin of a postMessage() event is not validated. The stockdio_eventer function listens for any postMessage event. After a message event is sent to the application, this function sets the "e" variable as the event and checks that the types of the data and data.method are not undefined (empty) before proceeding to eval the data.method received from the postMessage. However, on a different website. JavaScript code can call window.open for the vulnerable WordPress instance and do a postMessage(msg,'*') for that object.

- [https://github.com/sifatnotes/Learn-SecByte-Venus-Rips-Recon-PHP-CVE-CTF-Labs](https://github.com/sifatnotes/Learn-SecByte-Venus-Rips-Recon-PHP-CVE-CTF-Labs) :  ![starts](https://img.shields.io/github/stars/sifatnotes/Learn-SecByte-Venus-Rips-Recon-PHP-CVE-CTF-Labs.svg) ![forks](https://img.shields.io/github/forks/sifatnotes/Learn-SecByte-Venus-Rips-Recon-PHP-CVE-CTF-Labs.svg)


## CVE-2020-13664
 Arbitrary PHP code execution vulnerability in Drupal Core under certain circumstances. An attacker could trick an administrator into visiting a malicious site that could result in creating a carefully named directory on the file system. With this directory in place, an attacker could attempt to brute force a remote code execution vulnerability. Windows servers are most likely to be affected. This issue affects: Drupal Drupal Core 8.8.x versions prior to 8.8.8; 8.9.x versions prior to 8.9.1; 9.0.1 versions prior to 9.0.1.

- [https://github.com/lorenzog/CVE-2020-13664](https://github.com/lorenzog/CVE-2020-13664) :  ![starts](https://img.shields.io/github/stars/lorenzog/CVE-2020-13664.svg) ![forks](https://img.shields.io/github/forks/lorenzog/CVE-2020-13664.svg)


## CVE-2019-10744
 Versions of lodash lower than 4.17.12 are vulnerable to Prototype Pollution. The function defaultsDeep could be tricked into adding or modifying properties of Object.prototype using a constructor payload.

- [https://github.com/jimahub/scenario-b-warn](https://github.com/jimahub/scenario-b-warn) :  ![starts](https://img.shields.io/github/stars/jimahub/scenario-b-warn.svg) ![forks](https://img.shields.io/github/forks/jimahub/scenario-b-warn.svg)


## CVE-2017-5941
 An issue was discovered in the node-serialize package 0.0.4 for Node.js. Untrusted data passed into the unserialize() function can be exploited to achieve arbitrary code execution by passing a JavaScript Object with an Immediately Invoked Function Expression (IIFE).

- [https://github.com/jimahub/scenario-c-block](https://github.com/jimahub/scenario-c-block) :  ![starts](https://img.shields.io/github/stars/jimahub/scenario-c-block.svg) ![forks](https://img.shields.io/github/forks/jimahub/scenario-c-block.svg)

