# Update 2025-12-14
## CVE-2025-66516
Second, the original report failed to mention that in the 1.x Tika releases, the PDFParser was in the "org.apache.tika:tika-parsers" module.

- [https://github.com/chasingimpact/CVE-2025-66516-Writeup-POC](https://github.com/chasingimpact/CVE-2025-66516-Writeup-POC) :  ![starts](https://img.shields.io/github/stars/chasingimpact/CVE-2025-66516-Writeup-POC.svg) ![forks](https://img.shields.io/github/forks/chasingimpact/CVE-2025-66516-Writeup-POC.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/gagaltotal/tot-react-rce-CVE-2025-55182](https://github.com/gagaltotal/tot-react-rce-CVE-2025-55182) :  ![starts](https://img.shields.io/github/stars/gagaltotal/tot-react-rce-CVE-2025-55182.svg) ![forks](https://img.shields.io/github/forks/gagaltotal/tot-react-rce-CVE-2025-55182.svg)


## CVE-2025-64512
 Pdfminer.six is a community maintained fork of the original PDFMiner, a tool for extracting information from PDF documents. Prior to version 20251107, pdfminer.six will execute arbitrary code from a malicious pickle file if provided with a malicious PDF file. The `CMapDB._load_data()` function in pdfminer.six uses `pickle.loads()` to deserialize pickle files. These pickle files are supposed to be part of the pdfminer.six distribution stored in the `cmap/` directory, but a malicious PDF can specify an alternative directory and filename as long as the filename ends in `.pickle.gz`. A malicious, zipped pickle file can then contain code which will automatically execute when the PDF is processed. Version 20251107 fixes the issue.

- [https://github.com/luigigubello/CVE-2025-64512-Polyglot-PoC](https://github.com/luigigubello/CVE-2025-64512-Polyglot-PoC) :  ![starts](https://img.shields.io/github/stars/luigigubello/CVE-2025-64512-Polyglot-PoC.svg) ![forks](https://img.shields.io/github/forks/luigigubello/CVE-2025-64512-Polyglot-PoC.svg)


## CVE-2025-58360
 GeoServer is an open source server that allows users to share and edit geospatial data. From version 2.26.0 to before 2.26.2 and before 2.25.6, an XML External Entity (XXE) vulnerability was identified. The application accepts XML input through a specific endpoint /geoserver/wms operation GetMap. However, this input is not sufficiently sanitized or restricted, allowing an attacker to define external entities within the XML request. This issue has been patched in GeoServer 2.25.6, GeoServer 2.26.3, and GeoServer 2.27.0.

- [https://github.com/rxerium/CVE-2025-58360](https://github.com/rxerium/CVE-2025-58360) :  ![starts](https://img.shields.io/github/stars/rxerium/CVE-2025-58360.svg) ![forks](https://img.shields.io/github/forks/rxerium/CVE-2025-58360.svg)
- [https://github.com/Joker-Wiggin/CVE-2025-58360-GeoServer-XXE](https://github.com/Joker-Wiggin/CVE-2025-58360-GeoServer-XXE) :  ![starts](https://img.shields.io/github/stars/Joker-Wiggin/CVE-2025-58360-GeoServer-XXE.svg) ![forks](https://img.shields.io/github/forks/Joker-Wiggin/CVE-2025-58360-GeoServer-XXE.svg)


## CVE-2025-55184
 A pre-authentication denial of service vulnerability exists in React Server Components versions 19.0.0, 19.0.1 19.1.0, 19.1.1, 19.1.2, 19.2.0 and 19.2.1, including the following packages: react-server-dom-parcel, react-server-dom-turbopack, and react-server-dom-webpack. The vulnerable code unsafely deserializes payloads from HTTP requests to Server Function endpoints, which can cause an infinite loop that hangs the server process and may prevent future HTTP requests from being served.

- [https://github.com/bountyyfi/lonkero](https://github.com/bountyyfi/lonkero) :  ![starts](https://img.shields.io/github/stars/bountyyfi/lonkero.svg) ![forks](https://img.shields.io/github/forks/bountyyfi/lonkero.svg)
- [https://github.com/BakhodiribnYashinibnMansur/CVE-2025-55184](https://github.com/BakhodiribnYashinibnMansur/CVE-2025-55184) :  ![starts](https://img.shields.io/github/stars/BakhodiribnYashinibnMansur/CVE-2025-55184.svg) ![forks](https://img.shields.io/github/forks/BakhodiribnYashinibnMansur/CVE-2025-55184.svg)
- [https://github.com/caohungphu/react2shell](https://github.com/caohungphu/react2shell) :  ![starts](https://img.shields.io/github/stars/caohungphu/react2shell.svg) ![forks](https://img.shields.io/github/forks/caohungphu/react2shell.svg)
- [https://github.com/StealthMoud/react-server-cve-lab](https://github.com/StealthMoud/react-server-cve-lab) :  ![starts](https://img.shields.io/github/stars/StealthMoud/react-server-cve-lab.svg) ![forks](https://img.shields.io/github/forks/StealthMoud/react-server-cve-lab.svg)
- [https://github.com/abdozkaya/rsc-security-auditor](https://github.com/abdozkaya/rsc-security-auditor) :  ![starts](https://img.shields.io/github/stars/abdozkaya/rsc-security-auditor.svg) ![forks](https://img.shields.io/github/forks/abdozkaya/rsc-security-auditor.svg)


## CVE-2025-55183
 An information leak vulnerability exists in specific configurations of React Server Components versions 19.0.0, 19.0.1 19.1.0, 19.1.1, 19.1.2, 19.2.0 and 19.2.1, including the following packages: react-server-dom-parcel, react-server-dom-turbopack, and react-server-dom-webpack. A specifically crafted HTTP request sent to a vulnerable Server Function may unsafely return the source code of any Server Function. Exploitation requires the existence of a Server Function which explicitly or implicitly exposes a stringified argument.

- [https://github.com/bountyyfi/lonkero](https://github.com/bountyyfi/lonkero) :  ![starts](https://img.shields.io/github/stars/bountyyfi/lonkero.svg) ![forks](https://img.shields.io/github/forks/bountyyfi/lonkero.svg)
- [https://github.com/williavs/nextjs-security-update](https://github.com/williavs/nextjs-security-update) :  ![starts](https://img.shields.io/github/stars/williavs/nextjs-security-update.svg) ![forks](https://img.shields.io/github/forks/williavs/nextjs-security-update.svg)
- [https://github.com/X-Cotang/CVE-2025-55183_POC](https://github.com/X-Cotang/CVE-2025-55183_POC) :  ![starts](https://img.shields.io/github/stars/X-Cotang/CVE-2025-55183_POC.svg) ![forks](https://img.shields.io/github/forks/X-Cotang/CVE-2025-55183_POC.svg)
- [https://github.com/kimtruth/CVE-2025-55183-poc](https://github.com/kimtruth/CVE-2025-55183-poc) :  ![starts](https://img.shields.io/github/stars/kimtruth/CVE-2025-55183-poc.svg) ![forks](https://img.shields.io/github/forks/kimtruth/CVE-2025-55183-poc.svg)
- [https://github.com/omaidnebari/RSC-Scanner-POC](https://github.com/omaidnebari/RSC-Scanner-POC) :  ![starts](https://img.shields.io/github/stars/omaidnebari/RSC-Scanner-POC.svg) ![forks](https://img.shields.io/github/forks/omaidnebari/RSC-Scanner-POC.svg)
- [https://github.com/StealthMoud/react-server-cve-lab](https://github.com/StealthMoud/react-server-cve-lab) :  ![starts](https://img.shields.io/github/stars/StealthMoud/react-server-cve-lab.svg) ![forks](https://img.shields.io/github/forks/StealthMoud/react-server-cve-lab.svg)


## CVE-2025-55182
 A pre-authentication remote code execution vulnerability exists in React Server Components versions 19.0.0, 19.1.0, 19.1.1, and 19.2.0 including the following packages: react-server-dom-parcel, react-server-dom-turbopack, and react-server-dom-webpack. The vulnerable code unsafely deserializes payloads from HTTP requests to Server Function endpoints.

- [https://github.com/bountyyfi/lonkero](https://github.com/bountyyfi/lonkero) :  ![starts](https://img.shields.io/github/stars/bountyyfi/lonkero.svg) ![forks](https://img.shields.io/github/forks/bountyyfi/lonkero.svg)
- [https://github.com/VeilVulp/RscScan-cve-2025-55182](https://github.com/VeilVulp/RscScan-cve-2025-55182) :  ![starts](https://img.shields.io/github/stars/VeilVulp/RscScan-cve-2025-55182.svg) ![forks](https://img.shields.io/github/forks/VeilVulp/RscScan-cve-2025-55182.svg)
- [https://github.com/sho-luv/React2Shell](https://github.com/sho-luv/React2Shell) :  ![starts](https://img.shields.io/github/stars/sho-luv/React2Shell.svg) ![forks](https://img.shields.io/github/forks/sho-luv/React2Shell.svg)
- [https://github.com/rubensuxo-eh/react2shell-exploit](https://github.com/rubensuxo-eh/react2shell-exploit) :  ![starts](https://img.shields.io/github/stars/rubensuxo-eh/react2shell-exploit.svg) ![forks](https://img.shields.io/github/forks/rubensuxo-eh/react2shell-exploit.svg)
- [https://github.com/timsonner/React2Shell-CVE-2025-55182](https://github.com/timsonner/React2Shell-CVE-2025-55182) :  ![starts](https://img.shields.io/github/stars/timsonner/React2Shell-CVE-2025-55182.svg) ![forks](https://img.shields.io/github/forks/timsonner/React2Shell-CVE-2025-55182.svg)
- [https://github.com/anuththara2007-W/CVE-2025-55182-Exploit-extension](https://github.com/anuththara2007-W/CVE-2025-55182-Exploit-extension) :  ![starts](https://img.shields.io/github/stars/anuththara2007-W/CVE-2025-55182-Exploit-extension.svg) ![forks](https://img.shields.io/github/forks/anuththara2007-W/CVE-2025-55182-Exploit-extension.svg)
- [https://github.com/Pantheon-Security/medusa](https://github.com/Pantheon-Security/medusa) :  ![starts](https://img.shields.io/github/stars/Pantheon-Security/medusa.svg) ![forks](https://img.shields.io/github/forks/Pantheon-Security/medusa.svg)


## CVE-2025-43426
 A logging issue was addressed with improved data redaction. This issue is fixed in iOS 26.1 and iPadOS 26.1. An app may be able to access sensitive user data.

- [https://github.com/csrXamfi/CVE-2025-43426](https://github.com/csrXamfi/CVE-2025-43426) :  ![starts](https://img.shields.io/github/stars/csrXamfi/CVE-2025-43426.svg) ![forks](https://img.shields.io/github/forks/csrXamfi/CVE-2025-43426.svg)


## CVE-2025-43400
 An out-of-bounds write issue was addressed with improved bounds checking. This issue is fixed in watchOS 26.1, tvOS 26.1. Processing a maliciously crafted font may lead to unexpected app termination or corrupt process memory.

- [https://github.com/csrXamfi/CVE-2025-43400](https://github.com/csrXamfi/CVE-2025-43400) :  ![starts](https://img.shields.io/github/stars/csrXamfi/CVE-2025-43400.svg) ![forks](https://img.shields.io/github/forks/csrXamfi/CVE-2025-43400.svg)


## CVE-2025-36924
 In ss_DecodeLcsAssistDataReqMsg(void) of ss_LcsManagement.c, there is a possible out of bounds write due to an incorrect bounds check. This could lead to remote (proximal/adjacent) escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/margaretegpid/CVE-2025-36924](https://github.com/margaretegpid/CVE-2025-36924) :  ![starts](https://img.shields.io/github/stars/margaretegpid/CVE-2025-36924.svg) ![forks](https://img.shields.io/github/forks/margaretegpid/CVE-2025-36924.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/0xPThree/next.js_cve-2025-29927](https://github.com/0xPThree/next.js_cve-2025-29927) :  ![starts](https://img.shields.io/github/stars/0xPThree/next.js_cve-2025-29927.svg) ![forks](https://img.shields.io/github/forks/0xPThree/next.js_cve-2025-29927.svg)


## CVE-2025-24367
 Cacti is an open source performance and fault management framework. An authenticated Cacti user can abuse graph creation and graph template functionality to create arbitrary PHP scripts in the web root of the application, leading to remote code execution on the server. This vulnerability is fixed in 1.2.29.

- [https://github.com/r0tn3x/CVE-2025-24367](https://github.com/r0tn3x/CVE-2025-24367) :  ![starts](https://img.shields.io/github/stars/r0tn3x/CVE-2025-24367.svg) ![forks](https://img.shields.io/github/forks/r0tn3x/CVE-2025-24367.svg)


## CVE-2025-13780
 pgAdmin versions up to 9.10 are affected by a Remote Code Execution (RCE) vulnerability that occurs when running in server mode and performing restores from PLAIN-format dump files. This issue allows attackers to inject and execute arbitrary commands on the server hosting pgAdmin, posing a critical risk to the integrity and security of the database management system and underlying data.

- [https://github.com/meenakshisl/PoC-CVE-2025-13780](https://github.com/meenakshisl/PoC-CVE-2025-13780) :  ![starts](https://img.shields.io/github/stars/meenakshisl/PoC-CVE-2025-13780.svg) ![forks](https://img.shields.io/github/forks/meenakshisl/PoC-CVE-2025-13780.svg)


## CVE-2025-11001
The specific flaw exists within the handling of symbolic links in ZIP files. Crafted data in a ZIP file can cause the process to traverse to unintended directories. An attacker can leverage this vulnerability to execute code in the context of a service account. Was ZDI-CAN-26753.

- [https://github.com/I3r1h0n/7Ziprowler](https://github.com/I3r1h0n/7Ziprowler) :  ![starts](https://img.shields.io/github/stars/I3r1h0n/7Ziprowler.svg) ![forks](https://img.shields.io/github/forks/I3r1h0n/7Ziprowler.svg)


## CVE-2025-7441
 The StoryChief plugin for WordPress is vulnerable to arbitrary file uploads in all versions up to, and including, 1.0.42. This vulnerability occurs through the /wp-json/storychief/webhook REST-API endpoint that does not have sufficient filetype validation. This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible.

- [https://github.com/AnotherSec/CVE-2025-7441](https://github.com/AnotherSec/CVE-2025-7441) :  ![starts](https://img.shields.io/github/stars/AnotherSec/CVE-2025-7441.svg) ![forks](https://img.shields.io/github/forks/AnotherSec/CVE-2025-7441.svg)


## CVE-2025-6934
 The Opal Estate Pro – Property Management and Submission plugin for WordPress, used by the FullHouse - Real Estate Responsive WordPress Theme, is vulnerable to privilege escalation via in all versions up to, and including, 1.7.5. This is due to a lack of role restriction during registration in the 'on_regiser_user' function. This makes it possible for unauthenticated attackers to arbitrarily choose the role, including the Administrator role, assigned when registering.

- [https://github.com/AnotherSec/CVE-2025-6934](https://github.com/AnotherSec/CVE-2025-6934) :  ![starts](https://img.shields.io/github/stars/AnotherSec/CVE-2025-6934.svg) ![forks](https://img.shields.io/github/forks/AnotherSec/CVE-2025-6934.svg)


## CVE-2025-6440
 The WooCommerce Designer Pro plugin for WordPress, used by the Pricom - Printing Company & Design Services WordPress theme, is vulnerable to arbitrary file uploads due to missing file type validation in the 'wcdp_save_canvas_design_ajax' function in all versions up to, and including, 1.9.26. This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible.

- [https://github.com/AnotherSec/CVE-2025-6440](https://github.com/AnotherSec/CVE-2025-6440) :  ![starts](https://img.shields.io/github/stars/AnotherSec/CVE-2025-6440.svg) ![forks](https://img.shields.io/github/forks/AnotherSec/CVE-2025-6440.svg)


## CVE-2025-6218
The specific flaw exists within the handling of file paths within archive files. A crafted file path can cause the process to traverse to unintended directories. An attacker can leverage this vulnerability to execute code in the context of the current user. Was ZDI-CAN-27198.

- [https://github.com/hatchepsoout/sigma-rules](https://github.com/hatchepsoout/sigma-rules) :  ![starts](https://img.shields.io/github/stars/hatchepsoout/sigma-rules.svg) ![forks](https://img.shields.io/github/forks/hatchepsoout/sigma-rules.svg)


## CVE-2024-42758
 A Cross-site Scripting (XSS) vulnerability exists in version v2024-01-05 of the indexmenu plugin when is used and enabled in Dokuwiki (Open Source Wiki Engine). A malicious attacker can input XSS payloads for example when creating or editing existing page, to trigger the XSS on Dokuwiki, which is then stored in .txt file (due to nature of how Dokuwiki is designed), which presents stored XSS.

- [https://github.com/1s1ldur/CVE-2024-42758](https://github.com/1s1ldur/CVE-2024-42758) :  ![starts](https://img.shields.io/github/stars/1s1ldur/CVE-2024-42758.svg) ![forks](https://img.shields.io/github/forks/1s1ldur/CVE-2024-42758.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/wolf1892/CVE-2021-41773](https://github.com/wolf1892/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/wolf1892/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/wolf1892/CVE-2021-41773.svg)
- [https://github.com/honypot/CVE-2021-41773](https://github.com/honypot/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/honypot/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/honypot/CVE-2021-41773.svg)


## CVE-2021-3129
 Ignition before 2.5.2, as used in Laravel and other products, allows unauthenticated remote attackers to execute arbitrary code because of insecure usage of file_get_contents() and file_put_contents(). This is exploitable on sites using debug mode with Laravel before 8.4.2.

- [https://github.com/0nion1/CVE-2021-3129](https://github.com/0nion1/CVE-2021-3129) :  ![starts](https://img.shields.io/github/stars/0nion1/CVE-2021-3129.svg) ![forks](https://img.shields.io/github/forks/0nion1/CVE-2021-3129.svg)


## CVE-2020-36847
 The Simple-File-List Plugin for WordPress is vulnerable to Remote Code Execution in versions up to, and including, 4.2.2 via the rename function which can be used to rename uploaded PHP code with a png extension to use a php extension. This allows unauthenticated attackers to execute code on the server.

- [https://github.com/ftz7/PoC-CVE-2020-36847-WordPress-Plugin-4.2.2-RCE](https://github.com/ftz7/PoC-CVE-2020-36847-WordPress-Plugin-4.2.2-RCE) :  ![starts](https://img.shields.io/github/stars/ftz7/PoC-CVE-2020-36847-WordPress-Plugin-4.2.2-RCE.svg) ![forks](https://img.shields.io/github/forks/ftz7/PoC-CVE-2020-36847-WordPress-Plugin-4.2.2-RCE.svg)


## CVE-2020-25681
 A flaw was found in dnsmasq before version 2.83. A heap-based buffer overflow was discovered in the way RRSets are sorted before validating with DNSSEC data. An attacker on the network, who can forge DNS replies such as that they are accepted as valid, could use this flaw to cause a buffer overflow with arbitrary data in a heap memory segment, possibly executing code on the machine. The highest threat from this vulnerability is to data confidentiality and integrity as well as system availability.

- [https://github.com/nuliljj/CVE-2020-25681](https://github.com/nuliljj/CVE-2020-25681) :  ![starts](https://img.shields.io/github/stars/nuliljj/CVE-2020-25681.svg) ![forks](https://img.shields.io/github/forks/nuliljj/CVE-2020-25681.svg)
- [https://github.com/nuliljj/kimocoder-CVE-2020-25681](https://github.com/nuliljj/kimocoder-CVE-2020-25681) :  ![starts](https://img.shields.io/github/stars/nuliljj/kimocoder-CVE-2020-25681.svg) ![forks](https://img.shields.io/github/forks/nuliljj/kimocoder-CVE-2020-25681.svg)


## CVE-2019-3396
 The Widget Connector macro in Atlassian Confluence Server before version 6.6.12 (the fixed version for 6.6.x), from version 6.7.0 before 6.12.3 (the fixed version for 6.12.x), from version 6.13.0 before 6.13.3 (the fixed version for 6.13.x), and from version 6.14.0 before 6.14.2 (the fixed version for 6.14.x), allows remote attackers to achieve path traversal and remote code execution on a Confluence Server or Data Center instance via server-side template injection.

- [https://github.com/tranphuc2005/CVE-2019-3396](https://github.com/tranphuc2005/CVE-2019-3396) :  ![starts](https://img.shields.io/github/stars/tranphuc2005/CVE-2019-3396.svg) ![forks](https://img.shields.io/github/forks/tranphuc2005/CVE-2019-3396.svg)


## CVE-2018-19207
 The Van Ons WP GDPR Compliance (aka wp-gdpr-compliance) plugin before 1.4.3 for WordPress allows remote attackers to execute arbitrary code because $wpdb-prepare() input is mishandled, as exploited in the wild in November 2018.

- [https://github.com/AnotherSec/CVE-2018-19207](https://github.com/AnotherSec/CVE-2018-19207) :  ![starts](https://img.shields.io/github/stars/AnotherSec/CVE-2018-19207.svg) ![forks](https://img.shields.io/github/forks/AnotherSec/CVE-2018-19207.svg)


## CVE-2017-9822
 DNN (aka DotNetNuke) before 9.1.1 has Remote Code Execution via a cookie, aka "2017-08 (Critical) Possible remote code execution on DNN sites."

- [https://github.com/tranphuc2005/CVE-2017-9822](https://github.com/tranphuc2005/CVE-2017-9822) :  ![starts](https://img.shields.io/github/stars/tranphuc2005/CVE-2017-9822.svg) ![forks](https://img.shields.io/github/forks/tranphuc2005/CVE-2017-9822.svg)


## CVE-2016-2183
 The DES and Triple DES ciphers, as used in the TLS, SSH, and IPSec protocols and other protocols and products, have a birthday bound of approximately four billion blocks, which makes it easier for remote attackers to obtain cleartext data via a birthday attack against a long-duration encrypted session, as demonstrated by an HTTPS session using Triple DES in CBC mode, aka a "Sweet32" attack.

- [https://github.com/ZakyHermawan/Simple-Sweet32](https://github.com/ZakyHermawan/Simple-Sweet32) :  ![starts](https://img.shields.io/github/stars/ZakyHermawan/Simple-Sweet32.svg) ![forks](https://img.shields.io/github/forks/ZakyHermawan/Simple-Sweet32.svg)

