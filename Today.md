# Update 2025-12-30
## CVE-2025-68615
 net-snmp is a SNMP application library, tools and daemon. Prior to versions 5.9.5 and 5.10.pre2, a specially crafted packet to an net-snmp snmptrapd daemon can cause a buffer overflow and the daemon to crash. This issue has been patched in versions 5.9.5 and 5.10.pre2.

- [https://github.com/b1gchoi/CVE-2025-68615](https://github.com/b1gchoi/CVE-2025-68615) :  ![starts](https://img.shields.io/github/stars/b1gchoi/CVE-2025-68615.svg) ![forks](https://img.shields.io/github/forks/b1gchoi/CVE-2025-68615.svg)


## CVE-2025-68613
 n8n is an open source workflow automation platform. Versions starting with 0.211.0 and prior to 1.120.4, 1.121.1, and 1.122.0 contain a critical Remote Code Execution (RCE) vulnerability in their workflow expression evaluation system. Under certain conditions, expressions supplied by authenticated users during workflow configuration may be evaluated in an execution context that is not sufficiently isolated from the underlying runtime. An authenticated attacker could abuse this behavior to execute arbitrary code with the privileges of the n8n process. Successful exploitation may lead to full compromise of the affected instance, including unauthorized access to sensitive data, modification of workflows, and execution of system-level operations. This issue has been fixed in versions 1.120.4, 1.121.1, and 1.122.0. Users are strongly advised to upgrade to a patched version, which introduces additional safeguards to restrict expression evaluation. If upgrading is not immediately possible, administrators should consider the following temporary mitigations: Limit workflow creation and editing permissions to fully trusted users only; and/or deploy n8n in a hardened environment with restricted operating system privileges and network access to reduce the impact of potential exploitation. These workarounds do not fully eliminate the risk and should only be used as short-term measures.

- [https://github.com/gagaltotal/n8n-cve-2025-68613](https://github.com/gagaltotal/n8n-cve-2025-68613) :  ![starts](https://img.shields.io/github/stars/gagaltotal/n8n-cve-2025-68613.svg) ![forks](https://img.shields.io/github/forks/gagaltotal/n8n-cve-2025-68613.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/gagaltotal/tot-react-rce-CVE-2025-55182](https://github.com/gagaltotal/tot-react-rce-CVE-2025-55182) :  ![starts](https://img.shields.io/github/stars/gagaltotal/tot-react-rce-CVE-2025-55182.svg) ![forks](https://img.shields.io/github/forks/gagaltotal/tot-react-rce-CVE-2025-55182.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-packagemanager-field](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-packagemanager-field) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-packagemanager-field.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-packagemanager-field.svg)


## CVE-2025-46295
 Apache Commons Text versions prior to 1.10.0 included interpolation features that could be abused when applications passed untrusted input into the text-substitution API. Because some interpolators could trigger actions like executing commands or accessing external resources, an attacker could potentially achieve remote code execution. This vulnerability has been fully addressed in FileMaker Server 22.0.4.

- [https://github.com/soliantconsulting/CVE-2025-46295-fix-fms](https://github.com/soliantconsulting/CVE-2025-46295-fix-fms) :  ![starts](https://img.shields.io/github/stars/soliantconsulting/CVE-2025-46295-fix-fms.svg) ![forks](https://img.shields.io/github/forks/soliantconsulting/CVE-2025-46295-fix-fms.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/sn1p3rt3s7/NextJS_CVE-2025-29927](https://github.com/sn1p3rt3s7/NextJS_CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/sn1p3rt3s7/NextJS_CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/sn1p3rt3s7/NextJS_CVE-2025-29927.svg)


## CVE-2025-24893
 XWiki Platform is a generic wiki platform offering runtime services for applications built on top of it. Any guest can perform arbitrary remote code execution through a request to `SolrSearch`. This impacts the confidentiality, integrity and availability of the whole XWiki installation. To reproduce on an instance, without being logged in, go to `host/xwiki/bin/get/Main/SolrSearch?media=rss&text=%7D%7D%7D%7B%7Basync%20async%3Dfalse%7D%7D%7B%7Bgroovy%7D%7Dprintln%28"Hello%20from"%20%2B%20"%20search%20text%3A"%20%2B%20%2823%20%2B%2019%29%29%7B%7B%2Fgroovy%7D%7D%7B%7B%2Fasync%7D%7D%20`. If there is an output, and the title of the RSS feed contains `Hello from search text:42`, then the instance is vulnerable. This vulnerability has been patched in XWiki 15.10.11, 16.4.1 and 16.5.0RC1. Users are advised to upgrade. Users unable to upgrade may edit `Main.SolrSearchMacros` in `SolrSearchMacros.xml` on line 955 to match the `rawResponse` macro in `macros.vm#L2824` with a content type of `application/xml`, instead of simply outputting the content of the feed.

- [https://github.com/BreakingRohit/CVE-2025-24893-PoC](https://github.com/BreakingRohit/CVE-2025-24893-PoC) :  ![starts](https://img.shields.io/github/stars/BreakingRohit/CVE-2025-24893-PoC.svg) ![forks](https://img.shields.io/github/forks/BreakingRohit/CVE-2025-24893-PoC.svg)


## CVE-2025-14847
 Mismatched length fields in Zlib compressed protocol headers may allow a read of uninitialized heap memory by an unauthenticated client. This issue affects all MongoDB Server v7.0 prior to 7.0.28 versions, MongoDB Server v8.0 versions prior to 8.0.17, MongoDB Server v8.2 versions prior to 8.2.3, MongoDB Server v6.0 versions prior to 6.0.27, MongoDB Server v5.0 versions prior to 5.0.32, MongoDB Server v4.4 versions prior to 4.4.30, MongoDB Server v4.2 versions greater than or equal to 4.2.0, MongoDB Server v4.0 versions greater than or equal to 4.0.0, and MongoDB Server v3.6 versions greater than or equal to 3.6.0.

- [https://github.com/franksec42/mongobleed-exploit-CVE-2025-14847](https://github.com/franksec42/mongobleed-exploit-CVE-2025-14847) :  ![starts](https://img.shields.io/github/stars/franksec42/mongobleed-exploit-CVE-2025-14847.svg) ![forks](https://img.shields.io/github/forks/franksec42/mongobleed-exploit-CVE-2025-14847.svg)
- [https://github.com/JemHadar/MongoBleed-DFIR-Triage-Script-CVE-2025-14847](https://github.com/JemHadar/MongoBleed-DFIR-Triage-Script-CVE-2025-14847) :  ![starts](https://img.shields.io/github/stars/JemHadar/MongoBleed-DFIR-Triage-Script-CVE-2025-14847.svg) ![forks](https://img.shields.io/github/forks/JemHadar/MongoBleed-DFIR-Triage-Script-CVE-2025-14847.svg)


## CVE-2024-10924
 The Really Simple Security (Free, Pro, and Pro Multisite) plugins for WordPress are vulnerable to authentication bypass in versions 9.0.0 to 9.1.1.1. This is due to improper user check error handling in the two-factor REST API actions with the 'check_login_and_get_user' function. This makes it possible for unauthenticated attackers to log in as any existing user on the site, such as an administrator, when the "Two-Factor Authentication" setting is enabled (disabled by default).

- [https://github.com/bodoinon/CVE-2024-10924](https://github.com/bodoinon/CVE-2024-10924) :  ![starts](https://img.shields.io/github/stars/bodoinon/CVE-2024-10924.svg) ![forks](https://img.shields.io/github/forks/bodoinon/CVE-2024-10924.svg)


## CVE-2024-3094
Through a series of complex obfuscations, the liblzma build process extracts a prebuilt object file from a disguised test file existing in the source code, which is then used to modify specific functions in the liblzma code. This results in a modified liblzma library that can be used by any software linked against this library, intercepting and modifying the data interaction with this library.

- [https://github.com/hariskhalil555000-sketch/What-utility-does-CVE-2024-3094-refer-to-](https://github.com/hariskhalil555000-sketch/What-utility-does-CVE-2024-3094-refer-to-) :  ![starts](https://img.shields.io/github/stars/hariskhalil555000-sketch/What-utility-does-CVE-2024-3094-refer-to-.svg) ![forks](https://img.shields.io/github/forks/hariskhalil555000-sketch/What-utility-does-CVE-2024-3094-refer-to-.svg)


## CVE-2023-20938
 In binder_transaction_buffer_release of binder.c, there is a possible use after free due to improper input validation. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-257685302References: Upstream kernel

- [https://github.com/0xAtharv/CVE-2023-20938](https://github.com/0xAtharv/CVE-2023-20938) :  ![starts](https://img.shields.io/github/stars/0xAtharv/CVE-2023-20938.svg) ![forks](https://img.shields.io/github/forks/0xAtharv/CVE-2023-20938.svg)


## CVE-2022-4556
 A vulnerability was found in Alinto SOGo up to 5.7.1 and classified as problematic. Affected by this issue is the function _migrateMailIdentities of the file SoObjects/SOGo/SOGoUserDefaults.m of the component Identity Handler. The manipulation of the argument fullName leads to cross site scripting. The attack may be launched remotely. Upgrading to version 5.8.0 is able to address this issue. The name of the patch is efac49ae91a4a325df9931e78e543f707a0f8e5e. It is recommended to upgrade the affected component. The identifier of this vulnerability is VDB-215960.

- [https://github.com/AshkanRafiee/CVE-2022-4556](https://github.com/AshkanRafiee/CVE-2022-4556) :  ![starts](https://img.shields.io/github/stars/AshkanRafiee/CVE-2022-4556.svg) ![forks](https://img.shields.io/github/forks/AshkanRafiee/CVE-2022-4556.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/RizqiSec/CVE-2021-41773](https://github.com/RizqiSec/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/RizqiSec/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/RizqiSec/CVE-2021-41773.svg)
- [https://github.com/ch4os443/CVE-2021-41773](https://github.com/ch4os443/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/ch4os443/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/ch4os443/CVE-2021-41773.svg)


## CVE-2021-4250
 A vulnerability classified as problematic has been found in cgriego active_attr up to 0.15.2. This affects the function call of the file lib/active_attr/typecasting/boolean_typecaster.rb of the component Regex Handler. The manipulation of the argument value leads to denial of service. The exploit has been disclosed to the public and may be used. Upgrading to version 0.15.3 is able to address this issue. The name of the patch is dab95e5843b01525444b82bd7b336ef1d79377df. It is recommended to upgrade the affected component. The associated identifier of this vulnerability is VDB-216207.

- [https://github.com/nyambiblaise/MedJed---Barracuda-Drive-insecure-folder-permissions-CVE-2021-42505-or-similar-Walkthrough](https://github.com/nyambiblaise/MedJed---Barracuda-Drive-insecure-folder-permissions-CVE-2021-42505-or-similar-Walkthrough) :  ![starts](https://img.shields.io/github/stars/nyambiblaise/MedJed---Barracuda-Drive-insecure-folder-permissions-CVE-2021-42505-or-similar-Walkthrough.svg) ![forks](https://img.shields.io/github/forks/nyambiblaise/MedJed---Barracuda-Drive-insecure-folder-permissions-CVE-2021-42505-or-similar-Walkthrough.svg)


## CVE-2020-14883
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Console). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0, 12.2.1.4.0 and 14.1.1.0.0. Easily exploitable vulnerability allows high privileged attacker with network access via HTTP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.1 Base Score 7.2 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/Ashwesker/Ashwesker-CVE-2020-14883](https://github.com/Ashwesker/Ashwesker-CVE-2020-14883) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2020-14883.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2020-14883.svg)


## CVE-2020-14882
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Console). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0, 12.2.1.4.0 and 14.1.1.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/Ashwesker/Ashwesker-CVE-2020-14882](https://github.com/Ashwesker/Ashwesker-CVE-2020-14882) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2020-14882.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2020-14882.svg)


## CVE-2020-10135
 Legacy pairing and secure-connections pairing authentication in Bluetooth BR/EDR Core Specification v5.2 and earlier may allow an unauthenticated user to complete authentication without pairing credentials via adjacent access. An unauthenticated, adjacent attacker could impersonate a Bluetooth BR/EDR master or slave to pair with a previously paired remote device to successfully complete the authentication procedure without knowing the link key.

- [https://github.com/BrainsBook/bias](https://github.com/BrainsBook/bias) :  ![starts](https://img.shields.io/github/stars/BrainsBook/bias.svg) ![forks](https://img.shields.io/github/forks/BrainsBook/bias.svg)


## CVE-2020-5902
 In BIG-IP versions 15.0.0-15.1.0.3, 14.1.0-14.1.2.5, 13.1.0-13.1.3.3, 12.1.0-12.1.5.1, and 11.6.1-11.6.5.1, the Traffic Management User Interface (TMUI), also referred to as the Configuration utility, has a Remote Code Execution (RCE) vulnerability in undisclosed pages.

- [https://github.com/Ashwesker/Ashwesker-CVE-2020-5902](https://github.com/Ashwesker/Ashwesker-CVE-2020-5902) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2020-5902.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2020-5902.svg)


## CVE-2020-2551
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: WLS Core Components). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0 and 12.2.1.4.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via IIOP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/Ashwesker/Ashwesker-CVE-2020-2551](https://github.com/Ashwesker/Ashwesker-CVE-2020-2551) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2020-2551.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2020-2551.svg)


## CVE-2019-13288
 In Xpdf 4.01.01, the Parser::getObj() function in Parser.cc may cause infinite recursion via a crafted file. A remote attacker can leverage this for a DoS attack. This is similar to CVE-2018-16646.

- [https://github.com/ngtuonghung/CVE-2019-13288](https://github.com/ngtuonghung/CVE-2019-13288) :  ![starts](https://img.shields.io/github/stars/ngtuonghung/CVE-2019-13288.svg) ![forks](https://img.shields.io/github/forks/ngtuonghung/CVE-2019-13288.svg)


## CVE-2019-9506
 The Bluetooth BR/EDR specification up to and including version 5.1 permits sufficiently low encryption key length and does not prevent an attacker from influencing the key length negotiation. This allows practical brute-force attacks (aka "KNOB") that can decrypt traffic and inject arbitrary ciphertext without the victim noticing.

- [https://github.com/BrainsBook/knob](https://github.com/BrainsBook/knob) :  ![starts](https://img.shields.io/github/stars/BrainsBook/knob.svg) ![forks](https://img.shields.io/github/forks/BrainsBook/knob.svg)


## CVE-2018-15133
 In Laravel Framework through 5.5.40 and 5.6.x through 5.6.29, remote code execution might occur as a result of an unserialize call on a potentially untrusted X-XSRF-TOKEN value. This involves the decrypt method in Illuminate/Encryption/Encrypter.php and PendingBroadcast in gadgetchains/Laravel/RCE/3/chain.php in phpggc. The attacker must know the application key, which normally would never occur, but could happen if the attacker previously had privileged access or successfully accomplished a previous attack.

- [https://github.com/flame-11/CVE-2018-15133-laravel-framework](https://github.com/flame-11/CVE-2018-15133-laravel-framework) :  ![starts](https://img.shields.io/github/stars/flame-11/CVE-2018-15133-laravel-framework.svg) ![forks](https://img.shields.io/github/forks/flame-11/CVE-2018-15133-laravel-framework.svg)


## CVE-2017-0144
 The SMBv1 server in Microsoft Windows Vista SP2; Windows Server 2008 SP2 and R2 SP1; Windows 7 SP1; Windows 8.1; Windows Server 2012 Gold and R2; Windows RT 8.1; and Windows 10 Gold, 1511, and 1607; and Windows Server 2016 allows remote attackers to execute arbitrary code via crafted packets, aka "Windows SMB Remote Code Execution Vulnerability." This vulnerability is different from those described in CVE-2017-0143, CVE-2017-0145, CVE-2017-0146, and CVE-2017-0148.

- [https://github.com/FireTemple/Blackash-CVE-2017-0144](https://github.com/FireTemple/Blackash-CVE-2017-0144) :  ![starts](https://img.shields.io/github/stars/FireTemple/Blackash-CVE-2017-0144.svg) ![forks](https://img.shields.io/github/forks/FireTemple/Blackash-CVE-2017-0144.svg)

