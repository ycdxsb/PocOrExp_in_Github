# Update 2025-12-29
## CVE-2025-68664
 LangChain is a framework for building agents and LLM-powered applications. Prior to versions 0.3.81 and 1.2.5, a serialization injection vulnerability exists in LangChain's dumps() and dumpd() functions. The functions do not escape dictionaries with 'lc' keys when serializing free-form dictionaries. The 'lc' key is used internally by LangChain to mark serialized objects. When user-controlled data contains this key structure, it is treated as a legitimate LangChain object during deserialization rather than plain user data. This issue has been patched in versions 0.3.81 and 1.2.5.

- [https://github.com/Ak-cybe/CVE-2025-68664-LangGrinch-PoC](https://github.com/Ak-cybe/CVE-2025-68664-LangGrinch-PoC) :  ![starts](https://img.shields.io/github/stars/Ak-cybe/CVE-2025-68664-LangGrinch-PoC.svg) ![forks](https://img.shields.io/github/forks/Ak-cybe/CVE-2025-68664-LangGrinch-PoC.svg)


## CVE-2025-68613
 n8n is an open source workflow automation platform. Versions starting with 0.211.0 and prior to 1.120.4, 1.121.1, and 1.122.0 contain a critical Remote Code Execution (RCE) vulnerability in their workflow expression evaluation system. Under certain conditions, expressions supplied by authenticated users during workflow configuration may be evaluated in an execution context that is not sufficiently isolated from the underlying runtime. An authenticated attacker could abuse this behavior to execute arbitrary code with the privileges of the n8n process. Successful exploitation may lead to full compromise of the affected instance, including unauthorized access to sensitive data, modification of workflows, and execution of system-level operations. This issue has been fixed in versions 1.120.4, 1.121.1, and 1.122.0. Users are strongly advised to upgrade to a patched version, which introduces additional safeguards to restrict expression evaluation. If upgrading is not immediately possible, administrators should consider the following temporary mitigations: Limit workflow creation and editing permissions to fully trusted users only; and/or deploy n8n in a hardened environment with restricted operating system privileges and network access to reduce the impact of potential exploitation. These workarounds do not fully eliminate the risk and should only be used as short-term measures.

- [https://github.com/releaseown/analysis-and-poc-n8n-CVE-2025-68613](https://github.com/releaseown/analysis-and-poc-n8n-CVE-2025-68613) :  ![starts](https://img.shields.io/github/stars/releaseown/analysis-and-poc-n8n-CVE-2025-68613.svg) ![forks](https://img.shields.io/github/forks/releaseown/analysis-and-poc-n8n-CVE-2025-68613.svg)
- [https://github.com/reem-012/poc_CVE-2025-68613](https://github.com/reem-012/poc_CVE-2025-68613) :  ![starts](https://img.shields.io/github/stars/reem-012/poc_CVE-2025-68613.svg) ![forks](https://img.shields.io/github/forks/reem-012/poc_CVE-2025-68613.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-rsc-webpack](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-rsc-webpack) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-rsc-webpack.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-rsc-webpack.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-transitive](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-transitive) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-transitive.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-transitive.svg)


## CVE-2025-59719
 An improper verification of cryptographic signature vulnerability in Fortinet FortiWeb 8.0.0, FortiWeb 7.6.0 through 7.6.4, FortiWeb 7.4.0 through 7.4.9 may allow an unauthenticated attacker to bypass the FortiCloud SSO login authentication via a crafted SAML response message.

- [https://github.com/moften/CVE-2025-59718-Fortinet-Poc](https://github.com/moften/CVE-2025-59718-Fortinet-Poc) :  ![starts](https://img.shields.io/github/stars/moften/CVE-2025-59718-Fortinet-Poc.svg) ![forks](https://img.shields.io/github/forks/moften/CVE-2025-59718-Fortinet-Poc.svg)


## CVE-2025-59718
 A improper verification of cryptographic signature vulnerability in Fortinet FortiOS 7.6.0 through 7.6.3, FortiOS 7.4.0 through 7.4.8, FortiOS 7.2.0 through 7.2.11, FortiOS 7.0.0 through 7.0.17, FortiProxy 7.6.0 through 7.6.3, FortiProxy 7.4.0 through 7.4.10, FortiProxy 7.2.0 through 7.2.14, FortiProxy 7.0.0 through 7.0.21, FortiSwitchManager 7.2.0 through 7.2.6, FortiSwitchManager 7.0.0 through 7.0.5 allows an unauthenticated attacker to bypass the FortiCloud SSO login authentication via a crafted SAML response message.

- [https://github.com/moften/CVE-2025-59718-Fortinet-Poc](https://github.com/moften/CVE-2025-59718-Fortinet-Poc) :  ![starts](https://img.shields.io/github/stars/moften/CVE-2025-59718-Fortinet-Poc.svg) ![forks](https://img.shields.io/github/forks/moften/CVE-2025-59718-Fortinet-Poc.svg)


## CVE-2025-56513
 NiceHash QuickMiner 6.12.0 perform software updates over HTTP without validating digital signatures or hash checks. An attacker capable of intercepting or redirecting traffic to the update url and can hijack the update process and deliver arbitrary executables that are automatically executed, resulting in full remote code execution. This constitutes a critical supply chain attack vector.

- [https://github.com/psycho-prince/CVE-2025-56513-NiceHash-Update-Chain-Compromise](https://github.com/psycho-prince/CVE-2025-56513-NiceHash-Update-Chain-Compromise) :  ![starts](https://img.shields.io/github/stars/psycho-prince/CVE-2025-56513-NiceHash-Update-Chain-Compromise.svg) ![forks](https://img.shields.io/github/forks/psycho-prince/CVE-2025-56513-NiceHash-Update-Chain-Compromise.svg)


## CVE-2025-55182
 A pre-authentication remote code execution vulnerability exists in React Server Components versions 19.0.0, 19.1.0, 19.1.1, and 19.2.0 including the following packages: react-server-dom-parcel, react-server-dom-turbopack, and react-server-dom-webpack. The vulnerable code unsafely deserializes payloads from HTTP requests to Server Function endpoints.

- [https://github.com/alfazhossain/CVE-2025-55182-Exploiter](https://github.com/alfazhossain/CVE-2025-55182-Exploiter) :  ![starts](https://img.shields.io/github/stars/alfazhossain/CVE-2025-55182-Exploiter.svg) ![forks](https://img.shields.io/github/forks/alfazhossain/CVE-2025-55182-Exploiter.svg)


## CVE-2025-54424
 1Panel is a web interface and MCP Server that manages websites, files, containers, databases, and LLMs on a Linux server. In versions 2.0.5 and below, the HTTPS protocol used for communication between the Core and Agent endpoints has incomplete certificate verification during certificate validation, leading to unauthorized interface access. Due to the presence of numerous command execution or high-privilege interfaces in 1Panel, this results in Remote Code Execution (RCE). This is fixed in version 2.0.6. The CVE has been translated from Simplified Chinese using GitHub Copilot.

- [https://github.com/anonnymous5/1Panel-CVE-2025-54424-](https://github.com/anonnymous5/1Panel-CVE-2025-54424-) :  ![starts](https://img.shields.io/github/stars/anonnymous5/1Panel-CVE-2025-54424-.svg) ![forks](https://img.shields.io/github/forks/anonnymous5/1Panel-CVE-2025-54424-.svg)


## CVE-2025-54322
 Xspeeder SXZOS through 2025-12-26 allows root remote code execution via base64-encoded Python code in the chkid parameter to vLogin.py. The title and oIP parameters are also used.

- [https://github.com/Sachinart/CVE-2025-54322](https://github.com/Sachinart/CVE-2025-54322) :  ![starts](https://img.shields.io/github/stars/Sachinart/CVE-2025-54322.svg) ![forks](https://img.shields.io/github/forks/Sachinart/CVE-2025-54322.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/0xPThree/next.js_cve-2025-29927](https://github.com/0xPThree/next.js_cve-2025-29927) :  ![starts](https://img.shields.io/github/stars/0xPThree/next.js_cve-2025-29927.svg) ![forks](https://img.shields.io/github/forks/0xPThree/next.js_cve-2025-29927.svg)
- [https://github.com/Grand-Moomin/Vuln-Next.js-CVE-2025-29927](https://github.com/Grand-Moomin/Vuln-Next.js-CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/Grand-Moomin/Vuln-Next.js-CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/Grand-Moomin/Vuln-Next.js-CVE-2025-29927.svg)


## CVE-2025-26529
required additional sanitizing to prevent a stored XSS risk.

- [https://github.com/hxuu/moodle-cve](https://github.com/hxuu/moodle-cve) :  ![starts](https://img.shields.io/github/stars/hxuu/moodle-cve.svg) ![forks](https://img.shields.io/github/forks/hxuu/moodle-cve.svg)


## CVE-2025-24071
 Exposure of sensitive information to an unauthorized actor in Windows File Explorer allows an unauthorized attacker to perform spoofing over a network.

- [https://github.com/ephunter/CVE-2025-24071-Exploit](https://github.com/ephunter/CVE-2025-24071-Exploit) :  ![starts](https://img.shields.io/github/stars/ephunter/CVE-2025-24071-Exploit.svg) ![forks](https://img.shields.io/github/forks/ephunter/CVE-2025-24071-Exploit.svg)


## CVE-2025-14847
 Mismatched length fields in Zlib compressed protocol headers may allow a read of uninitialized heap memory by an unauthenticated client. This issue affects all MongoDB Server v7.0 prior to 7.0.28 versions, MongoDB Server v8.0 versions prior to 8.0.17, MongoDB Server v8.2 versions prior to 8.2.3, MongoDB Server v6.0 versions prior to 6.0.27, MongoDB Server v5.0 versions prior to 5.0.32, MongoDB Server v4.4 versions prior to 4.4.30, MongoDB Server v4.2 versions greater than or equal to 4.2.0, MongoDB Server v4.0 versions greater than or equal to 4.0.0, and MongoDB Server v3.6 versions greater than or equal to 3.6.0.

- [https://github.com/cybertechajju/CVE-2025-14847_Expolit](https://github.com/cybertechajju/CVE-2025-14847_Expolit) :  ![starts](https://img.shields.io/github/stars/cybertechajju/CVE-2025-14847_Expolit.svg) ![forks](https://img.shields.io/github/forks/cybertechajju/CVE-2025-14847_Expolit.svg)
- [https://github.com/Ashwesker/Blackash-CVE-2025-14847](https://github.com/Ashwesker/Blackash-CVE-2025-14847) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Blackash-CVE-2025-14847.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Blackash-CVE-2025-14847.svg)
- [https://github.com/KingHacker353/CVE-2025-14847_Expolit](https://github.com/KingHacker353/CVE-2025-14847_Expolit) :  ![starts](https://img.shields.io/github/stars/KingHacker353/CVE-2025-14847_Expolit.svg) ![forks](https://img.shields.io/github/forks/KingHacker353/CVE-2025-14847_Expolit.svg)
- [https://github.com/saereya/CVE-2025-14847---MongoBleed](https://github.com/saereya/CVE-2025-14847---MongoBleed) :  ![starts](https://img.shields.io/github/stars/saereya/CVE-2025-14847---MongoBleed.svg) ![forks](https://img.shields.io/github/forks/saereya/CVE-2025-14847---MongoBleed.svg)
- [https://github.com/nma-io/mongobleed](https://github.com/nma-io/mongobleed) :  ![starts](https://img.shields.io/github/stars/nma-io/mongobleed.svg) ![forks](https://img.shields.io/github/forks/nma-io/mongobleed.svg)
- [https://github.com/Black1hp/mongobleed-scanner](https://github.com/Black1hp/mongobleed-scanner) :  ![starts](https://img.shields.io/github/stars/Black1hp/mongobleed-scanner.svg) ![forks](https://img.shields.io/github/forks/Black1hp/mongobleed-scanner.svg)


## CVE-2024-46506
 NetAlertX 23.01.14 through 24.x before 24.10.12 allows unauthenticated command injection via settings update because function=savesettings lacks an authentication requirement, as exploited in the wild in May 2025. This is related to settings.php and util.php.

- [https://github.com/fufu-byte/CVE-2024-46506](https://github.com/fufu-byte/CVE-2024-46506) :  ![starts](https://img.shields.io/github/stars/fufu-byte/CVE-2024-46506.svg) ![forks](https://img.shields.io/github/forks/fufu-byte/CVE-2024-46506.svg)


## CVE-2024-44762
 A discrepancy in error messages for invalid login attempts in Webmin Usermin v2.100 allows attackers to enumerate valid user accounts.

- [https://github.com/arbaaz29/CVE-2024-44762-webmin-userenum](https://github.com/arbaaz29/CVE-2024-44762-webmin-userenum) :  ![starts](https://img.shields.io/github/stars/arbaaz29/CVE-2024-44762-webmin-userenum.svg) ![forks](https://img.shields.io/github/forks/arbaaz29/CVE-2024-44762-webmin-userenum.svg)


## CVE-2024-3016
 NEC Platforms DT900 and DT900S Series 5.0.0.0 – v5.3.4.4, v5.4.0.0 – v5.6.0.20 allows an attacker to access a non-documented the system settings to change settings via local network with unauthenticated user.

- [https://github.com/RIZZZIOM/CVE-2024-30167](https://github.com/RIZZZIOM/CVE-2024-30167) :  ![starts](https://img.shields.io/github/stars/RIZZZIOM/CVE-2024-30167.svg) ![forks](https://img.shields.io/github/forks/RIZZZIOM/CVE-2024-30167.svg)


## CVE-2023-47248
If it is not possible to upgrade, we provide a separate package `pyarrow-hotfix` that disables the vulnerability on older PyArrow versions. See  https://pypi.org/project/pyarrow-hotfix/  for instructions.

- [https://github.com/Prodigysec/pyarrow-CVE-2023-47248](https://github.com/Prodigysec/pyarrow-CVE-2023-47248) :  ![starts](https://img.shields.io/github/stars/Prodigysec/pyarrow-CVE-2023-47248.svg) ![forks](https://img.shields.io/github/forks/Prodigysec/pyarrow-CVE-2023-47248.svg)


## CVE-2023-5360
 The Royal Elementor Addons and Templates WordPress plugin before 1.3.79 does not properly validate uploaded files, which could allow unauthenticated users to upload arbitrary files, such as PHP and achieve RCE.

- [https://github.com/LaviruDilshan/CVE-2023-5360-exploit-with-native-libraries](https://github.com/LaviruDilshan/CVE-2023-5360-exploit-with-native-libraries) :  ![starts](https://img.shields.io/github/stars/LaviruDilshan/CVE-2023-5360-exploit-with-native-libraries.svg) ![forks](https://img.shields.io/github/forks/LaviruDilshan/CVE-2023-5360-exploit-with-native-libraries.svg)


## CVE-2021-26855
 Microsoft Exchange Server Remote Code Execution Vulnerability

- [https://github.com/dorkerdevil/CVE_2021_26855_Exploit_Hub](https://github.com/dorkerdevil/CVE_2021_26855_Exploit_Hub) :  ![starts](https://img.shields.io/github/stars/dorkerdevil/CVE_2021_26855_Exploit_Hub.svg) ![forks](https://img.shields.io/github/forks/dorkerdevil/CVE_2021_26855_Exploit_Hub.svg)
- [https://github.com/haotiku/CVE-2021-26855-exploit-Exchange](https://github.com/haotiku/CVE-2021-26855-exploit-Exchange) :  ![starts](https://img.shields.io/github/stars/haotiku/CVE-2021-26855-exploit-Exchange.svg) ![forks](https://img.shields.io/github/forks/haotiku/CVE-2021-26855-exploit-Exchange.svg)
- [https://github.com/antichown/Scan-Vuln-CVE-2021-26855](https://github.com/antichown/Scan-Vuln-CVE-2021-26855) :  ![starts](https://img.shields.io/github/stars/antichown/Scan-Vuln-CVE-2021-26855.svg) ![forks](https://img.shields.io/github/forks/antichown/Scan-Vuln-CVE-2021-26855.svg)


## CVE-2020-7961
 Deserialization of Untrusted Data in Liferay Portal prior to 7.2.1 CE GA2 allows remote attackers to execute arbitrary code via JSON web services (JSONWS).

- [https://github.com/Alaa-abdulridha/POC-CVE-2020-7961-Token-iterate](https://github.com/Alaa-abdulridha/POC-CVE-2020-7961-Token-iterate) :  ![starts](https://img.shields.io/github/stars/Alaa-abdulridha/POC-CVE-2020-7961-Token-iterate.svg) ![forks](https://img.shields.io/github/forks/Alaa-abdulridha/POC-CVE-2020-7961-Token-iterate.svg)
- [https://github.com/Alaa-abdulridha/GLiferay-CVE-2020-7961-golang](https://github.com/Alaa-abdulridha/GLiferay-CVE-2020-7961-golang) :  ![starts](https://img.shields.io/github/stars/Alaa-abdulridha/GLiferay-CVE-2020-7961-golang.svg) ![forks](https://img.shields.io/github/forks/Alaa-abdulridha/GLiferay-CVE-2020-7961-golang.svg)


## CVE-2012-2836
 The exif_data_load_data function in exif-data.c in the EXIF Tag Parsing Library (aka libexif) before 0.6.21 allows remote attackers to cause a denial of service (out-of-bounds read) or possibly obtain sensitive information from process memory via crafted EXIF tags in an image.

- [https://github.com/ngtuonghung/CVE-2009-3895-CVE-2012-2836](https://github.com/ngtuonghung/CVE-2009-3895-CVE-2012-2836) :  ![starts](https://img.shields.io/github/stars/ngtuonghung/CVE-2009-3895-CVE-2012-2836.svg) ![forks](https://img.shields.io/github/forks/ngtuonghung/CVE-2009-3895-CVE-2012-2836.svg)


## CVE-2009-3895
 Heap-based buffer overflow in the exif_entry_fix function (aka the tag fixup routine) in libexif/exif-entry.c in libexif 0.6.18 allows remote attackers to cause a denial of service or possibly execute arbitrary code via an invalid EXIF image.  NOTE: some of these details are obtained from third party information.

- [https://github.com/ngtuonghung/CVE-2009-3895-CVE-2012-2836](https://github.com/ngtuonghung/CVE-2009-3895-CVE-2012-2836) :  ![starts](https://img.shields.io/github/stars/ngtuonghung/CVE-2009-3895-CVE-2012-2836.svg) ![forks](https://img.shields.io/github/forks/ngtuonghung/CVE-2009-3895-CVE-2012-2836.svg)

