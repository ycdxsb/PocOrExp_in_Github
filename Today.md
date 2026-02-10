# Update 2026-02-10
## CVE-2026-25857
 Tenda G300-F router firmware versio 16.01.14.2 and prior contain an OS command injection vulnerability in the WAN diagnostic functionality (formSetWanDiag). The implementation constructs a shell command that invokes curl and incorporates attacker-controlled input into the command line without adequate neutralization. As a result, a remote attacker with access to the affected management interface can inject additional shell syntax and execute arbitrary commands on the device with the privileges of the management process.

- [https://github.com/eeeeeeeeeevan/CVE-2026-25857](https://github.com/eeeeeeeeeevan/CVE-2026-25857) :  ![starts](https://img.shields.io/github/stars/eeeeeeeeeevan/CVE-2026-25857.svg) ![forks](https://img.shields.io/github/forks/eeeeeeeeeevan/CVE-2026-25857.svg)


## CVE-2026-25732
 NiceGUI is a Python-based UI framework. Prior to 3.7.0, NiceGUI's FileUpload.name property exposes client-supplied filename metadata without sanitization, enabling path traversal when developers use the pattern UPLOAD_DIR / file.name. Malicious filenames containing ../ sequences allow attackers to write files outside intended directories, with potential for remote code execution through application file overwrites in vulnerable deployment patterns. This design creates a prevalent security footgun affecting applications following common community patterns. Note: Exploitation requires application code incorporating file.name into filesystem paths without sanitization. Applications using fixed paths, generated filenames, or explicit sanitization are not affected. This vulnerability is fixed in 3.7.0.

- [https://github.com/mbanyamer/CVE-2026-25732-NiceGUI-3.6.1](https://github.com/mbanyamer/CVE-2026-25732-NiceGUI-3.6.1) :  ![starts](https://img.shields.io/github/stars/mbanyamer/CVE-2026-25732-NiceGUI-3.6.1.svg) ![forks](https://img.shields.io/github/forks/mbanyamer/CVE-2026-25732-NiceGUI-3.6.1.svg)


## CVE-2026-25253
 OpenClaw (aka clawdbot or Moltbot) before 2026.1.29 obtains a gatewayUrl value from a query string and automatically makes a WebSocket connection without prompting, sending a token value.

- [https://github.com/al4n4n/CVE-2026-25253-research](https://github.com/al4n4n/CVE-2026-25253-research) :  ![starts](https://img.shields.io/github/stars/al4n4n/CVE-2026-25253-research.svg) ![forks](https://img.shields.io/github/forks/al4n4n/CVE-2026-25253-research.svg)


## CVE-2026-1862
 Type Confusion in V8 in Google Chrome prior to 144.0.7559.132 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/b1gchoi/CVE-2026-1862-exp](https://github.com/b1gchoi/CVE-2026-1862-exp) :  ![starts](https://img.shields.io/github/stars/b1gchoi/CVE-2026-1862-exp.svg) ![forks](https://img.shields.io/github/forks/b1gchoi/CVE-2026-1862-exp.svg)


## CVE-2025-55182
 A pre-authentication remote code execution vulnerability exists in React Server Components versions 19.0.0, 19.1.0, 19.1.1, and 19.2.0 including the following packages: react-server-dom-parcel, react-server-dom-turbopack, and react-server-dom-webpack. The vulnerable code unsafely deserializes payloads from HTTP requests to Server Function endpoints.

- [https://github.com/techgaun/cve-2025-55182-scanner](https://github.com/techgaun/cve-2025-55182-scanner) :  ![starts](https://img.shields.io/github/stars/techgaun/cve-2025-55182-scanner.svg) ![forks](https://img.shields.io/github/forks/techgaun/cve-2025-55182-scanner.svg)


## CVE-2025-49132
 Pterodactyl is a free, open-source game server management panel. Prior to version 1.11.11, using the /locales/locale.json with the locale and namespace query parameters, a malicious actor is able to execute arbitrary code without being authenticated. With the ability to execute arbitrary code it could be used to gain access to the Panel's server, read credentials from the Panel's config, extract sensitive information from the database, access files of servers managed by the panel, etc. This issue has been patched in version 1.11.11. There are no software workarounds for this vulnerability, but use of an external Web Application Firewall (WAF) could help mitigate this attack.

- [https://github.com/YoyoChaud/CVE-2025-49132](https://github.com/YoyoChaud/CVE-2025-49132) :  ![starts](https://img.shields.io/github/stars/YoyoChaud/CVE-2025-49132.svg) ![forks](https://img.shields.io/github/forks/YoyoChaud/CVE-2025-49132.svg)
- [https://github.com/ramzihafiz/CVE-2025-49132](https://github.com/ramzihafiz/CVE-2025-49132) :  ![starts](https://img.shields.io/github/stars/ramzihafiz/CVE-2025-49132.svg) ![forks](https://img.shields.io/github/forks/ramzihafiz/CVE-2025-49132.svg)
- [https://github.com/malw0re/CVE-2025-49132---Pterodactyl-RCE-HTB-Season-10-](https://github.com/malw0re/CVE-2025-49132---Pterodactyl-RCE-HTB-Season-10-) :  ![starts](https://img.shields.io/github/stars/malw0re/CVE-2025-49132---Pterodactyl-RCE-HTB-Season-10-.svg) ![forks](https://img.shields.io/github/forks/malw0re/CVE-2025-49132---Pterodactyl-RCE-HTB-Season-10-.svg)
- [https://github.com/kerburenthusiasm/CVE-2025-49132-PoC](https://github.com/kerburenthusiasm/CVE-2025-49132-PoC) :  ![starts](https://img.shields.io/github/stars/kerburenthusiasm/CVE-2025-49132-PoC.svg) ![forks](https://img.shields.io/github/forks/kerburenthusiasm/CVE-2025-49132-PoC.svg)


## CVE-2024-46987
 Camaleon CMS is a dynamic and advanced content management system based on Ruby on Rails. A path traversal vulnerability accessible via MediaController's download_private_file method allows authenticated users to download any file on the web server Camaleon CMS is running on (depending on the file permissions). This issue may lead to Information Disclosure. This issue has been addressed in release version 2.8.2. Users are advised to upgrade. There are no known workarounds for this vulnerability.

- [https://github.com/rabouzia/CVE-2024-46987](https://github.com/rabouzia/CVE-2024-46987) :  ![starts](https://img.shields.io/github/stars/rabouzia/CVE-2024-46987.svg) ![forks](https://img.shields.io/github/forks/rabouzia/CVE-2024-46987.svg)


## CVE-2023-23638
This issue affects Apache Dubbo 2.7.x version 2.7.21 and prior versions; Apache Dubbo 3.0.x version 3.0.13 and prior versions; Apache Dubbo 3.1.x version 3.1.5 and prior versions. 

- [https://github.com/X1r0z/dubbo-rce](https://github.com/X1r0z/dubbo-rce) :  ![starts](https://img.shields.io/github/stars/X1r0z/dubbo-rce.svg) ![forks](https://img.shields.io/github/forks/X1r0z/dubbo-rce.svg)


## CVE-2023-3463
All versions of GE Digital CIMPLICITY that are not adhering to SDG guidance and accepting documents from untrusted sources are vulnerable to memory corruption issues due to insufficient input validation, including issues such as out-of-bounds reads and writes, use-after-free, stack-based buffer overflows, uninitialized pointers, and a heap-based buffer overflow. Successful exploitation could allow an attacker to execute arbitrary code.

- [https://github.com/ssophiz/CVE-2023-34632](https://github.com/ssophiz/CVE-2023-34632) :  ![starts](https://img.shields.io/github/stars/ssophiz/CVE-2023-34632.svg) ![forks](https://img.shields.io/github/forks/ssophiz/CVE-2023-34632.svg)


## CVE-2021-31712
 react-draft-wysiwyg (aka React Draft Wysiwyg) before 1.14.6 allows a javascript: URi in a Link Target of the link decorator in decorators/Link/index.js when a draft is shared across users, leading to XSS.

- [https://github.com/CQ-Tools/CVE-2021-31712-fixed](https://github.com/CQ-Tools/CVE-2021-31712-fixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2021-31712-fixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2021-31712-fixed.svg)
- [https://github.com/CQ-Tools/CVE-2021-31712-unfixed](https://github.com/CQ-Tools/CVE-2021-31712-unfixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2021-31712-unfixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2021-31712-unfixed.svg)


## CVE-2021-3711
 In order to decrypt SM2 encrypted data an application is expected to call the API function EVP_PKEY_decrypt(). Typically an application will call this function twice. The first time, on entry, the "out" parameter can be NULL and, on exit, the "outlen" parameter is populated with the buffer size required to hold the decrypted plaintext. The application can then allocate a sufficiently sized buffer and call EVP_PKEY_decrypt() again, but this time passing a non-NULL value for the "out" parameter. A bug in the implementation of the SM2 decryption code means that the calculation of the buffer size required to hold the plaintext returned by the first call to EVP_PKEY_decrypt() can be smaller than the actual size required by the second call. This can lead to a buffer overflow when EVP_PKEY_decrypt() is called by the application a second time with a buffer that is too small. A malicious attacker who is able present SM2 content for decryption to an application could cause attacker chosen data to overflow the buffer by up to a maximum of 62 bytes altering the contents of other data held after the buffer, possibly changing application behaviour or causing the application to crash. The location of the buffer is application dependent but is typically heap allocated. Fixed in OpenSSL 1.1.1l (Affected 1.1.1-1.1.1k).

- [https://github.com/Truyen08/CVE_2021_3711](https://github.com/Truyen08/CVE_2021_3711) :  ![starts](https://img.shields.io/github/stars/Truyen08/CVE_2021_3711.svg) ![forks](https://img.shields.io/github/forks/Truyen08/CVE_2021_3711.svg)


## CVE-2020-26256
 Fast-csv is an npm package for parsing and formatting CSVs or any other delimited value file in node. In fast-cvs before version 4.3.6 there is a possible ReDoS vulnerability (Regular Expression Denial of Service) when using ignoreEmpty option when parsing. This has been patched in `v4.3.6` You will only be affected by this if you use the `ignoreEmpty` parsing option. If you do use this option it is recommended that you upgrade to the latest version `v4.3.6` This vulnerability was found using a CodeQL query which identified `EMPTY_ROW_REGEXP` regular expression as vulnerable.

- [https://github.com/CQ-Tools/CVE-2020-26256-unfixed](https://github.com/CQ-Tools/CVE-2020-26256-unfixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2020-26256-unfixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2020-26256-unfixed.svg)
- [https://github.com/CQ-Tools/CVE-2020-26256-fixed](https://github.com/CQ-Tools/CVE-2020-26256-fixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2020-26256-fixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2020-26256-fixed.svg)


## CVE-2020-26226
 In the npm package semantic-release before version 17.2.3, secrets that would normally be masked by `semantic-release` can be accidentally disclosed if they contain characters that become encoded when included in a URL. Secrets that do not contain characters that become encoded when included in a URL are already masked properly. The issue is fixed in version 17.2.3.

- [https://github.com/CQ-Tools/CVE-2020-26226-fixed](https://github.com/CQ-Tools/CVE-2020-26226-fixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2020-26226-fixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2020-26226-fixed.svg)
- [https://github.com/CQ-Tools/CVE-2020-26226-unfixed](https://github.com/CQ-Tools/CVE-2020-26226-unfixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2020-26226-unfixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2020-26226-unfixed.svg)


## CVE-2020-16012
 Side-channel information leakage in graphics in Google Chrome prior to 87.0.4280.66 allowed a remote attacker to leak cross-origin data via a crafted HTML page.

- [https://github.com/leopoldabgn/CVE-2020-16012-PoC](https://github.com/leopoldabgn/CVE-2020-16012-PoC) :  ![starts](https://img.shields.io/github/stars/leopoldabgn/CVE-2020-16012-PoC.svg) ![forks](https://img.shields.io/github/forks/leopoldabgn/CVE-2020-16012-PoC.svg)


## CVE-2020-15156
 In nodebb-plugin-blog-comments before version 0.7.0, a logged in user is vulnerable to an XSS attack which could allow a third party to post on their behalf on the forum. This is due to lack of CSRF validation.

- [https://github.com/CQ-Tools/CVE-2020-15156-unfixed](https://github.com/CQ-Tools/CVE-2020-15156-unfixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2020-15156-unfixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2020-15156-unfixed.svg)
- [https://github.com/CQ-Tools/CVE-2020-15156-fixed](https://github.com/CQ-Tools/CVE-2020-15156-fixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2020-15156-fixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2020-15156-fixed.svg)


## CVE-2020-11981
 An issue was found in Apache Airflow versions 1.10.10 and below. When using CeleryExecutor, if an attacker can connect to the broker (Redis, RabbitMQ) directly, it is possible to inject commands, resulting in the celery worker running arbitrary commands.

- [https://github.com/Evillm/CVE-2020-11981-PoC](https://github.com/Evillm/CVE-2020-11981-PoC) :  ![starts](https://img.shields.io/github/stars/Evillm/CVE-2020-11981-PoC.svg) ![forks](https://img.shields.io/github/forks/Evillm/CVE-2020-11981-PoC.svg)


## CVE-2020-11021
 Actions Http-Client (NPM @actions/http-client) before version 1.0.8 can disclose Authorization headers to incorrect domain in certain redirect scenarios. The conditions in which this happens are if consumers of the http-client: 1. make an http request with an authorization header 2. that request leads to a redirect (302) and 3. the redirect url redirects to another domain or hostname Then the authorization header will get passed to the other domain. The problem is fixed in version 1.0.8.

- [https://github.com/CQ-Tools/CVE-2020-11021-unfixed](https://github.com/CQ-Tools/CVE-2020-11021-unfixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2020-11021-unfixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2020-11021-unfixed.svg)
- [https://github.com/CQ-Tools/CVE-2020-11021-fixed](https://github.com/CQ-Tools/CVE-2020-11021-fixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2020-11021-fixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2020-11021-fixed.svg)


## CVE-2020-8244
 A buffer over-read vulnerability exists in bl 4.0.3, 3.0.1, 2.2.1, and 1.2.3 which could allow an attacker to supply user input (even typed) that if it ends up in consume() argument and can become negative, the BufferList state can be corrupted, tricking it into exposing uninitialized memory via regular .slice() calls.

- [https://github.com/CQ-Tools/CVE-2020-8244-fixed](https://github.com/CQ-Tools/CVE-2020-8244-fixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2020-8244-fixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2020-8244-fixed.svg)
- [https://github.com/CQ-Tools/CVE-2020-8244-unfixed](https://github.com/CQ-Tools/CVE-2020-8244-unfixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2020-8244-unfixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2020-8244-unfixed.svg)


## CVE-2020-8192
 A denial of service vulnerability exists in Fastify v2.14.1 and v3.0.0-rc.4 that allows a malicious user to trigger resource exhaustion (when the allErrors option is used) with specially crafted schemas.

- [https://github.com/CQ-Tools/CVE-2020-8192-unfixed](https://github.com/CQ-Tools/CVE-2020-8192-unfixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2020-8192-unfixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2020-8192-unfixed.svg)
- [https://github.com/CQ-Tools/CVE-2020-8192-fixed](https://github.com/CQ-Tools/CVE-2020-8192-fixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2020-8192-fixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2020-8192-fixed.svg)


## CVE-2020-8163
 The is a code injection vulnerability in versions of Rails prior to 5.0.1 that wouldallow an attacker who controlled the `locals` argument of a `render` call to perform a RCE.

- [https://github.com/lucasamorimca/CVE-2020-8163](https://github.com/lucasamorimca/CVE-2020-8163) :  ![starts](https://img.shields.io/github/stars/lucasamorimca/CVE-2020-8163.svg) ![forks](https://img.shields.io/github/forks/lucasamorimca/CVE-2020-8163.svg)


## CVE-2020-8116
 Prototype pollution vulnerability in dot-prop npm package versions before 4.2.1 and versions 5.x before 5.1.1 allows an attacker to add arbitrary properties to JavaScript language constructs such as objects.

- [https://github.com/CQ-Tools/CVE-2020-8116-unfixed](https://github.com/CQ-Tools/CVE-2020-8116-unfixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2020-8116-unfixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2020-8116-unfixed.svg)
- [https://github.com/CQ-Tools/CVE-2020-8116-fixed](https://github.com/CQ-Tools/CVE-2020-8116-fixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2020-8116-fixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2020-8116-fixed.svg)


## CVE-2020-7763
 This affects the package phantom-html-to-pdf before 0.6.1.

- [https://github.com/CQ-Tools/CVE-2020-7763-fixed](https://github.com/CQ-Tools/CVE-2020-7763-fixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2020-7763-fixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2020-7763-fixed.svg)
- [https://github.com/CQ-Tools/CVE-2020-7763-unfixed](https://github.com/CQ-Tools/CVE-2020-7763-unfixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2020-7763-unfixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2020-7763-unfixed.svg)


## CVE-2020-7699
 This affects the package express-fileupload before 1.1.8. If the parseNested option is enabled, sending a corrupt HTTP request can lead to denial of service or arbitrary code execution.

- [https://github.com/CQ-Tools/CVE-2020-7699-unfixed](https://github.com/CQ-Tools/CVE-2020-7699-unfixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2020-7699-unfixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2020-7699-unfixed.svg)
- [https://github.com/CQ-Tools/CVE-2020-7699-fixed](https://github.com/CQ-Tools/CVE-2020-7699-fixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2020-7699-fixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2020-7699-fixed.svg)


## CVE-2020-7662
 websocket-extensions npm module prior to 0.1.4 allows Denial of Service (DoS) via Regex Backtracking. The extension parser may take quadratic time when parsing a header containing an unclosed string parameter value whose content is a repeating two-byte sequence of a backslash and some other character. This could be abused by an attacker to conduct Regex Denial Of Service (ReDoS) on a single-threaded server by providing a malicious payload with the Sec-WebSocket-Extensions header.

- [https://github.com/CQ-Tools/CVE-2020-7662-unfixed](https://github.com/CQ-Tools/CVE-2020-7662-unfixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2020-7662-unfixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2020-7662-unfixed.svg)
- [https://github.com/CQ-Tools/CVE-2020-7662-fixed](https://github.com/CQ-Tools/CVE-2020-7662-fixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2020-7662-fixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2020-7662-fixed.svg)


## CVE-2020-7660
 serialize-javascript prior to 3.1.0 allows remote attackers to inject arbitrary code via the function "deleteFunctions" within "index.js".

- [https://github.com/CQ-Tools/CVE-2020-7660-fixed](https://github.com/CQ-Tools/CVE-2020-7660-fixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2020-7660-fixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2020-7660-fixed.svg)
- [https://github.com/CQ-Tools/CVE-2020-7660-unfixed](https://github.com/CQ-Tools/CVE-2020-7660-unfixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2020-7660-unfixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2020-7660-unfixed.svg)


## CVE-2020-7656
 jquery prior to 1.9.0 allows Cross-site Scripting attacks via the load method. The load method fails to recognize and remove "script" HTML tags that contain a whitespace character, i.e: "/script ", which results in the enclosed script logic to be executed.

- [https://github.com/CQ-Tools/CVE-2020-7656-fixed](https://github.com/CQ-Tools/CVE-2020-7656-fixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2020-7656-fixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2020-7656-fixed.svg)
- [https://github.com/CQ-Tools/CVE-2020-7656-unfixed](https://github.com/CQ-Tools/CVE-2020-7656-unfixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2020-7656-unfixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2020-7656-unfixed.svg)


## CVE-2020-6836
 grammar-parser.jison in the hot-formula-parser package before 3.0.1 for Node.js is vulnerable to arbitrary code injection. The package fails to sanitize values passed to the parse function and concatenates them in an eval call. If a value of the formula is taken from user-controlled input, it may allow attackers to run arbitrary commands on the server.

- [https://github.com/CQ-Tools/CVE-2020-6836-fixed](https://github.com/CQ-Tools/CVE-2020-6836-fixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2020-6836-fixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2020-6836-fixed.svg)
- [https://github.com/CQ-Tools/CVE-2020-6836-unfixed](https://github.com/CQ-Tools/CVE-2020-6836-unfixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2020-6836-unfixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2020-6836-unfixed.svg)


## CVE-2020-5902
 In BIG-IP versions 15.0.0-15.1.0.3, 14.1.0-14.1.2.5, 13.1.0-13.1.3.3, 12.1.0-12.1.5.1, and 11.6.1-11.6.5.1, the Traffic Management User Interface (TMUI), also referred to as the Configuration utility, has a Remote Code Execution (RCE) vulnerability in undisclosed pages.

- [https://github.com/DeepSecurity-Pe/GoF5-CVE-2020-5902](https://github.com/DeepSecurity-Pe/GoF5-CVE-2020-5902) :  ![starts](https://img.shields.io/github/stars/DeepSecurity-Pe/GoF5-CVE-2020-5902.svg) ![forks](https://img.shields.io/github/forks/DeepSecurity-Pe/GoF5-CVE-2020-5902.svg)


## CVE-2020-5258
 In affected versions of dojo (NPM package), the deepCopy method is vulnerable to Prototype Pollution. Prototype Pollution refers to the ability to inject properties into existing JavaScript language construct prototypes, such as objects. An attacker manipulates these attributes to overwrite, or pollute, a JavaScript application object prototype of the base object by injecting other values. This has been patched in versions 1.12.8, 1.13.7, 1.14.6, 1.15.3 and 1.16.2

- [https://github.com/CQ-Tools/CVE-2020-5258-fixed](https://github.com/CQ-Tools/CVE-2020-5258-fixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2020-5258-fixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2020-5258-fixed.svg)
- [https://github.com/CQ-Tools/CVE-2020-5258-unfixed](https://github.com/CQ-Tools/CVE-2020-5258-unfixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2020-5258-unfixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2020-5258-unfixed.svg)


## CVE-2020-4066
 In Limdu before 0.95, the trainBatch function has a command injection vulnerability. Clients of the Limdu library are unlikely to be aware of this, so they might unwittingly write code that contains a vulnerability. This has been patched in 0.95.

- [https://github.com/CQ-Tools/CVE-2020-4066-unfixed](https://github.com/CQ-Tools/CVE-2020-4066-unfixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2020-4066-unfixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2020-4066-unfixed.svg)
- [https://github.com/CQ-Tools/CVE-2020-4066-fixed](https://github.com/CQ-Tools/CVE-2020-4066-fixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2020-4066-fixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2020-4066-fixed.svg)

