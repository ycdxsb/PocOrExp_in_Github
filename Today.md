# Update 2026-03-15
## CVE-2026-29000
 pac4j-jwt versions prior to 4.5.9, 5.7.9, and 6.3.3 contain an authentication bypass vulnerability in JwtAuthenticator when processing encrypted JWTs that allows remote attackers to forge authentication tokens. Attackers who possess the server's RSA public key can create a JWE-wrapped PlainJWT with arbitrary subject and role claims, bypassing signature verification to authenticate as any user including administrators.

- [https://github.com/otuva/CVE-2026-29000](https://github.com/otuva/CVE-2026-29000) :  ![starts](https://img.shields.io/github/stars/otuva/CVE-2026-29000.svg) ![forks](https://img.shields.io/github/forks/otuva/CVE-2026-29000.svg)
- [https://github.com/Crims-on/CVE-2026-29000](https://github.com/Crims-on/CVE-2026-29000) :  ![starts](https://img.shields.io/github/stars/Crims-on/CVE-2026-29000.svg) ![forks](https://img.shields.io/github/forks/Crims-on/CVE-2026-29000.svg)
- [https://github.com/manbahadurthapa1248/CVE-2026-29000---pac4j-jwt-Authentication-Bypass-PoC](https://github.com/manbahadurthapa1248/CVE-2026-29000---pac4j-jwt-Authentication-Bypass-PoC) :  ![starts](https://img.shields.io/github/stars/manbahadurthapa1248/CVE-2026-29000---pac4j-jwt-Authentication-Bypass-PoC.svg) ![forks](https://img.shields.io/github/forks/manbahadurthapa1248/CVE-2026-29000---pac4j-jwt-Authentication-Bypass-PoC.svg)
- [https://github.com/alihussainzada/CVE-2026-29000-Python-PoC-pac4j-JWT-AuthenticationBypass-Poc](https://github.com/alihussainzada/CVE-2026-29000-Python-PoC-pac4j-JWT-AuthenticationBypass-Poc) :  ![starts](https://img.shields.io/github/stars/alihussainzada/CVE-2026-29000-Python-PoC-pac4j-JWT-AuthenticationBypass-Poc.svg) ![forks](https://img.shields.io/github/forks/alihussainzada/CVE-2026-29000-Python-PoC-pac4j-JWT-AuthenticationBypass-Poc.svg)


## CVE-2026-27470
 ZoneMinder is a free, open source closed-circuit television software application. In versions 1.36.37 and below and 1.37.61 through 1.38.0, there is a second-order SQL Injection vulnerability in the web/ajax/status.php file within the getNearEvents() function. Event field values (specifically Name and Cause) are stored safely via parameterized queries but are later retrieved and concatenated directly into SQL WHERE clauses without escaping. An authenticated user with Events edit and view permissions can exploit this to execute arbitrary SQL queries.

- [https://github.com/d3vn0mi/CVE-2026-27470-POC](https://github.com/d3vn0mi/CVE-2026-27470-POC) :  ![starts](https://img.shields.io/github/stars/d3vn0mi/CVE-2026-27470-POC.svg) ![forks](https://img.shields.io/github/forks/d3vn0mi/CVE-2026-27470-POC.svg)


## CVE-2026-27097
 Improper Control of Filename for Include/Require Statement in PHP Program ('PHP Remote File Inclusion') vulnerability in AncoraThemes CasaMia | Property Rental Real Estate WordPress Theme casamia allows PHP Local File Inclusion.This issue affects CasaMia | Property Rental Real Estate WordPress Theme: from n/a through = 1.1.2.

- [https://github.com/hacker1337itme/CVE-2026-27097](https://github.com/hacker1337itme/CVE-2026-27097) :  ![starts](https://img.shields.io/github/stars/hacker1337itme/CVE-2026-27097.svg) ![forks](https://img.shields.io/github/forks/hacker1337itme/CVE-2026-27097.svg)


## CVE-2026-21858
 n8n is an open source workflow automation platform. Versions starting with 1.65.0 and below 1.121.0 enable an attacker to access files on the underlying server through execution of certain form-based workflows. A vulnerable workflow could grant access to an unauthenticated remote attacker, resulting in exposure of sensitive information stored on the system and may enable further compromise depending on deployment configuration and workflow usage. This issue is fixed in version 1.121.0.

- [https://github.com/Yati2/Ni8mare-CVE-2026-21858](https://github.com/Yati2/Ni8mare-CVE-2026-21858) :  ![starts](https://img.shields.io/github/stars/Yati2/Ni8mare-CVE-2026-21858.svg) ![forks](https://img.shields.io/github/forks/Yati2/Ni8mare-CVE-2026-21858.svg)


## CVE-2026-3891
 The Pix for WooCommerce plugin for WordPress is vulnerable to arbitrary file uploads due to missing capability check and missing file type validation in the 'lkn_pix_for_woocommerce_c6_save_settings' function in all versions up to, and including, 1.5.0. This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible.

- [https://github.com/joshuavanderpoll/CVE-2026-3891](https://github.com/joshuavanderpoll/CVE-2026-3891) :  ![starts](https://img.shields.io/github/stars/joshuavanderpoll/CVE-2026-3891.svg) ![forks](https://img.shields.io/github/forks/joshuavanderpoll/CVE-2026-3891.svg)


## CVE-2026-1311
 The Worry Proof Backup plugin for WordPress is vulnerable to Path Traversal in all versions up to, and including, 0.2.4 via the backup upload functionality. This makes it possible for authenticated attackers, with Subscriber-level access and above, to upload a malicious ZIP archive with path traversal sequences to write arbitrary files anywhere on the server, including executable PHP files. This can lead to remote code execution.

- [https://github.com/hacker1337itme/CVE-2026-1311](https://github.com/hacker1337itme/CVE-2026-1311) :  ![starts](https://img.shields.io/github/stars/hacker1337itme/CVE-2026-1311.svg) ![forks](https://img.shields.io/github/forks/hacker1337itme/CVE-2026-1311.svg)


## CVE-2025-69516
 A Server-Side Template Injection (SSTI) vulnerability in the /reporting/templates/preview/ endpoint of Amidaware Tactical RMM, affecting versions equal to or earlier than v1.3.1, allows low-privileged users with Report Viewer or Report Manager permissions to achieve remote command execution on the server. This occurs due to improper sanitization of the template_md parameter, enabling direct injection of Jinja2 templates. This occurs due to misuse of the generate_html() function, the user-controlled value is inserted into `env.from_string`, a function that processes Jinja2 templates arbitrarily, making an SSTI possible.

- [https://github.com/SNISS/CVE-2025-69516](https://github.com/SNISS/CVE-2025-69516) :  ![starts](https://img.shields.io/github/stars/SNISS/CVE-2025-69516.svg) ![forks](https://img.shields.io/github/forks/SNISS/CVE-2025-69516.svg)


## CVE-2025-66866
 An issue was discovered in function d_abi_tags in file cp-demangle.c in BinUtils 2.26 allows attackers to cause a denial of service via crafted PE file.

- [https://github.com/hacker1337itme/CVE-2025-66866](https://github.com/hacker1337itme/CVE-2025-66866) :  ![starts](https://img.shields.io/github/stars/hacker1337itme/CVE-2025-66866.svg) ![forks](https://img.shields.io/github/forks/hacker1337itme/CVE-2025-66866.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions.svg)


## CVE-2025-60787
 MotionEye v0.43.1b4 and before is vulnerable to OS Command Injection in configuration parameters such as image_file_name. Unsanitized user input is written to Motion configuration files, allowing remote authenticated attackers with admin access to achieve code execution when Motion is restarted.

- [https://github.com/d3vn0mi/CVE-2025-60787-POC](https://github.com/d3vn0mi/CVE-2025-60787-POC) :  ![starts](https://img.shields.io/github/stars/d3vn0mi/CVE-2025-60787-POC.svg) ![forks](https://img.shields.io/github/forks/d3vn0mi/CVE-2025-60787-POC.svg)


## CVE-2025-59284
 Exposure of sensitive information to an unauthorized actor in Windows NTLM allows an unauthorized attacker to perform spoofing locally.

- [https://github.com/lytnc/CVE-2025-59284-PoC](https://github.com/lytnc/CVE-2025-59284-PoC) :  ![starts](https://img.shields.io/github/stars/lytnc/CVE-2025-59284-PoC.svg) ![forks](https://img.shields.io/github/forks/lytnc/CVE-2025-59284-PoC.svg)


## CVE-2025-49844
 Redis is an open source, in-memory database that persists on disk. Versions 8.2.1 and below allow an authenticated user to use a specially crafted Lua script to manipulate the garbage collector, trigger a use-after-free and potentially lead to remote code execution. The problem exists in all versions of Redis with Lua scripting. This issue is fixed in version 8.2.2. To workaround this issue without patching the redis-server executable is to prevent users from executing Lua scripts. This can be done using ACL to restrict EVAL and EVALSHA commands.

- [https://github.com/Cilectiy/CVE-2025-49844](https://github.com/Cilectiy/CVE-2025-49844) :  ![starts](https://img.shields.io/github/stars/Cilectiy/CVE-2025-49844.svg) ![forks](https://img.shields.io/github/forks/Cilectiy/CVE-2025-49844.svg)


## CVE-2025-31722
 In Jenkins Templating Engine Plugin 2.5.3 and earlier, libraries defined in folders are not subject to sandbox protection, allowing attackers with Item/Configure permission to execute arbitrary code in the context of the Jenkins controller JVM.

- [https://github.com/h3raklez/CVE-2025-31722](https://github.com/h3raklez/CVE-2025-31722) :  ![starts](https://img.shields.io/github/stars/h3raklez/CVE-2025-31722.svg) ![forks](https://img.shields.io/github/forks/h3raklez/CVE-2025-31722.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/MKIRAHMET/CVE-2025-29927-PoC](https://github.com/MKIRAHMET/CVE-2025-29927-PoC) :  ![starts](https://img.shields.io/github/stars/MKIRAHMET/CVE-2025-29927-PoC.svg) ![forks](https://img.shields.io/github/forks/MKIRAHMET/CVE-2025-29927-PoC.svg)


## CVE-2025-6934
 The Opal Estate Pro – Property Management and Submission plugin for WordPress, used by the FullHouse - Real Estate Responsive WordPress Theme, is vulnerable to privilege escalation via in all versions up to, and including, 1.7.5. This is due to a lack of role restriction during registration in the 'on_regiser_user' function. This makes it possible for unauthenticated attackers to arbitrarily choose the role, including the Administrator role, assigned when registering.

- [https://github.com/0xTerror/CVE-2025-6934](https://github.com/0xTerror/CVE-2025-6934) :  ![starts](https://img.shields.io/github/stars/0xTerror/CVE-2025-6934.svg) ![forks](https://img.shields.io/github/forks/0xTerror/CVE-2025-6934.svg)


## CVE-2025-5548
 A vulnerability, which was classified as critical, was found in FreeFloat FTP Server 1.0. Affected is an unknown function of the component NOOP Command Handler. The manipulation leads to buffer overflow. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/LorenzoPorrasDuque/CVE-2025-5548-POC](https://github.com/LorenzoPorrasDuque/CVE-2025-5548-POC) :  ![starts](https://img.shields.io/github/stars/LorenzoPorrasDuque/CVE-2025-5548-POC.svg) ![forks](https://img.shields.io/github/forks/LorenzoPorrasDuque/CVE-2025-5548-POC.svg)


## CVE-2024-47176
 CUPS is a standards-based, open-source printing system, and `cups-browsed` contains network printing functionality including, but not limited to, auto-discovering print services and shared printers. `cups-browsed` binds to `INADDR_ANY:631`, causing it to trust any packet from any source, and can cause the `Get-Printer-Attributes` IPP request to an attacker controlled URL. When combined with other vulnerabilities, such as CVE-2024-47076, CVE-2024-47175, and CVE-2024-47177, an attacker can execute arbitrary commands remotely on the target machine without authentication when a malicious printer is printed to.

- [https://github.com/deancooreman/CVE-2024-47176](https://github.com/deancooreman/CVE-2024-47176) :  ![starts](https://img.shields.io/github/stars/deancooreman/CVE-2024-47176.svg) ![forks](https://img.shields.io/github/forks/deancooreman/CVE-2024-47176.svg)


## CVE-2024-23222
 A type confusion issue was addressed with improved checks. This issue is fixed in iOS 17.3 and iPadOS 17.3, macOS Sonoma 14.3, tvOS 17.3, iOS 16.7.5 and iPadOS 16.7.5, iOS 15.8.7 and iPadOS 15.8.7. Processing maliciously crafted web content may lead to arbitrary code execution. Apple is aware of a report that this issue may have been exploited.

- [https://github.com/FuzzySecurity/Cassowary-CVE-2024-23222-x86_64](https://github.com/FuzzySecurity/Cassowary-CVE-2024-23222-x86_64) :  ![starts](https://img.shields.io/github/stars/FuzzySecurity/Cassowary-CVE-2024-23222-x86_64.svg) ![forks](https://img.shields.io/github/forks/FuzzySecurity/Cassowary-CVE-2024-23222-x86_64.svg)


## CVE-2024-14027
a71874379ec8 ("xattr: switch to CLASS(fd)").

- [https://github.com/lcfr-eth/CVE-2024-14027_slop](https://github.com/lcfr-eth/CVE-2024-14027_slop) :  ![starts](https://img.shields.io/github/stars/lcfr-eth/CVE-2024-14027_slop.svg) ![forks](https://img.shields.io/github/forks/lcfr-eth/CVE-2024-14027_slop.svg)


## CVE-2024-3094
Through a series of complex obfuscations, the liblzma build process extracts a prebuilt object file from a disguised test file existing in the source code, which is then used to modify specific functions in the liblzma code. This results in a modified liblzma library that can be used by any software linked against this library, intercepting and modifying the data interaction with this library.

- [https://github.com/extracoding-dozen/CVE-2024-3094](https://github.com/extracoding-dozen/CVE-2024-3094) :  ![starts](https://img.shields.io/github/stars/extracoding-dozen/CVE-2024-3094.svg) ![forks](https://img.shields.io/github/forks/extracoding-dozen/CVE-2024-3094.svg)


## CVE-2024-1208
 The LearnDash LMS plugin for WordPress is vulnerable to Sensitive Information Exposure in all versions up to, and including, 4.10.2 via API. This makes it possible for unauthenticated attackers to obtain access to quiz questions.

- [https://github.com/karlemilnikka/CVE-2024-1208-and-CVE-2024-1210](https://github.com/karlemilnikka/CVE-2024-1208-and-CVE-2024-1210) :  ![starts](https://img.shields.io/github/stars/karlemilnikka/CVE-2024-1208-and-CVE-2024-1210.svg) ![forks](https://img.shields.io/github/forks/karlemilnikka/CVE-2024-1208-and-CVE-2024-1210.svg)
- [https://github.com/Cappricio-Securities/CVE-2024-1208](https://github.com/Cappricio-Securities/CVE-2024-1208) :  ![starts](https://img.shields.io/github/stars/Cappricio-Securities/CVE-2024-1208.svg) ![forks](https://img.shields.io/github/forks/Cappricio-Securities/CVE-2024-1208.svg)
- [https://github.com/Cappricio-Securities/.github](https://github.com/Cappricio-Securities/.github) :  ![starts](https://img.shields.io/github/stars/Cappricio-Securities/.github.svg) ![forks](https://img.shields.io/github/forks/Cappricio-Securities/.github.svg)


## CVE-2023-43208
 NextGen Healthcare Mirth Connect before version 4.4.1 is vulnerable to unauthenticated remote code execution. Note that this vulnerability is caused by the incomplete patch of CVE-2023-37679.

- [https://github.com/Criz117/CVE-2023-43208-PoC](https://github.com/Criz117/CVE-2023-43208-PoC) :  ![starts](https://img.shields.io/github/stars/Criz117/CVE-2023-43208-PoC.svg) ![forks](https://img.shields.io/github/forks/Criz117/CVE-2023-43208-PoC.svg)


## CVE-2022-29599
 In Apache Maven maven-shared-utils prior to version 3.3.3, the Commandline class can emit double-quoted strings without proper escaping, allowing shell injection attacks.

- [https://github.com/dawetmaster/CVE-2022-29599-maven-shared-utils-vulnerable](https://github.com/dawetmaster/CVE-2022-29599-maven-shared-utils-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2022-29599-maven-shared-utils-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2022-29599-maven-shared-utils-vulnerable.svg)


## CVE-2022-23457
 ESAPI (The OWASP Enterprise Security API) is a free, open source, web application security control library. Prior to version 2.3.0.0, the default implementation of `Validator.getValidDirectoryPath(String, String, File, boolean)` may incorrectly treat the tested input string as a child of the specified parent directory. This potentially could allow control-flow bypass checks to be defeated if an attack can specify the entire string representing the 'input' path. This vulnerability is patched in release 2.3.0.0 of ESAPI. As a workaround, it is possible to write one's own implementation of the Validator interface. However, maintainers do not recommend this.

- [https://github.com/dawetmaster/CVE-2022-23457-esapi-java-legacy-vulnerable](https://github.com/dawetmaster/CVE-2022-23457-esapi-java-legacy-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2022-23457-esapi-java-legacy-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2022-23457-esapi-java-legacy-vulnerable.svg)


## CVE-2022-0847
 A flaw was found in the way the "flags" member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/mattlloyddavies/ps-lab-cve-2022-0847](https://github.com/mattlloyddavies/ps-lab-cve-2022-0847) :  ![starts](https://img.shields.io/github/stars/mattlloyddavies/ps-lab-cve-2022-0847.svg) ![forks](https://img.shields.io/github/forks/mattlloyddavies/ps-lab-cve-2022-0847.svg)


## CVE-2021-43859
 XStream is an open source java library to serialize objects to XML and back again. Versions prior to 1.4.19 may allow a remote attacker to allocate 100% CPU time on the target system depending on CPU type or parallel execution of such a payload resulting in a denial of service only by manipulating the processed input stream. XStream 1.4.19 monitors and accumulates the time it takes to add elements to collections and throws an exception if a set threshold is exceeded. Users are advised to upgrade as soon as possible. Users unable to upgrade may set the NO_REFERENCE mode to prevent recursion. See GHSA-rmr5-cpv2-vgjf for further details on a workaround if an upgrade is not possible.

- [https://github.com/dawetmaster/CVE-2021-43859-xstream-vulnerable](https://github.com/dawetmaster/CVE-2021-43859-xstream-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2021-43859-xstream-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2021-43859-xstream-vulnerable.svg)


## CVE-2021-41269
 cron-utils is a Java library to define, parse, validate, migrate crons as well as get human readable descriptions for them. In affected versions A template Injection was identified in cron-utils enabling attackers to inject arbitrary Java EL expressions, leading to unauthenticated Remote Code Execution (RCE) vulnerability. Versions up to 9.1.2 are susceptible to this vulnerability. Please note, that only projects using the @Cron annotation to validate untrusted Cron expressions are affected. The issue was patched and a new version was released. Please upgrade to version 9.1.6. There are no known workarounds known.

- [https://github.com/dawetmaster/CVE-2021-41269-cron-utils-vulnerable](https://github.com/dawetmaster/CVE-2021-41269-cron-utils-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2021-41269-cron-utils-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2021-41269-cron-utils-vulnerable.svg)


## CVE-2021-36090
 When reading a specially crafted ZIP archive, Compress can be made to allocate large amounts of memory that finally leads to an out of memory error even for very small inputs. This could be used to mount a denial of service attack against services that use Compress' zip package.

- [https://github.com/dawetmaster/CVE-2021-36090-commons-compress-vulnerable](https://github.com/dawetmaster/CVE-2021-36090-commons-compress-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2021-36090-commons-compress-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2021-36090-commons-compress-vulnerable.svg)


## CVE-2021-35517
 When reading a specially crafted TAR archive, Compress can be made to allocate large amounts of memory that finally leads to an out of memory error even for very small inputs. This could be used to mount a denial of service attack against services that use Compress' tar package.

- [https://github.com/dawetmaster/CVE-2021-35517-commons-compress-vulnerable](https://github.com/dawetmaster/CVE-2021-35517-commons-compress-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2021-35517-commons-compress-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2021-35517-commons-compress-vulnerable.svg)


## CVE-2021-35516
 When reading a specially crafted 7Z archive, Compress can be made to allocate large amounts of memory that finally leads to an out of memory error even for very small inputs. This could be used to mount a denial of service attack against services that use Compress' sevenz package.

- [https://github.com/dawetmaster/CVE-2021-35516-commons-compress-vulnerable](https://github.com/dawetmaster/CVE-2021-35516-commons-compress-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2021-35516-commons-compress-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2021-35516-commons-compress-vulnerable.svg)


## CVE-2021-35515
 When reading a specially crafted 7Z archive, the construction of the list of codecs that decompress an entry can result in an infinite loop. This could be used to mount a denial of service attack against services that use Compress' sevenz package.

- [https://github.com/dawetmaster/CVE-2021-35515-commons-compress-vulnerable](https://github.com/dawetmaster/CVE-2021-35515-commons-compress-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2021-35515-commons-compress-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2021-35515-commons-compress-vulnerable.svg)


## CVE-2021-31684
 A vulnerability was discovered in the indexOf function of JSONParserByteArray in JSON Smart versions 1.3 and 2.4 which causes a denial of service (DOS) via a crafted web request.

- [https://github.com/dawetmaster/CVE-2021-31684-json-smart-v2-vulnerable](https://github.com/dawetmaster/CVE-2021-31684-json-smart-v2-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2021-31684-json-smart-v2-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2021-31684-json-smart-v2-vulnerable.svg)


## CVE-2021-21364
 swagger-codegen is an open-source project which contains a template-driven engine to generate documentation, API clients and server stubs in different languages by parsing your OpenAPI / Swagger definition. In swagger-codegen before version 2.4.19, on Unix-Like systems, the system temporary directory is shared between all local users. When files/directories are created, the default `umask` settings for the process are respected. As a result, by default, most processes/apis will create files/directories with the permissions `-rw-r--r--` and `drwxr-xr-x` respectively, unless an API that explicitly sets safe file permissions is used. Because this vulnerability impacts generated code, the generated code will remain vulnerable until fixed manually! This vulnerability is fixed in version 2.4.19. Note this is a distinct vulnerability from CVE-2021-21363.

- [https://github.com/dawetmaster/CVE-2021-21364-swagger-codegen-vulnerable](https://github.com/dawetmaster/CVE-2021-21364-swagger-codegen-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2021-21364-swagger-codegen-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2021-21364-swagger-codegen-vulnerable.svg)


## CVE-2021-21363
 swagger-codegen is an open-source project which contains a template-driven engine to generate documentation, API clients and server stubs in different languages by parsing your OpenAPI / Swagger definition. In swagger-codegen before version 2.4.19, on Unix like systems, the system's temporary directory is shared between all users on that system. A collocated user can observe the process of creating a temporary sub directory in the shared temporary directory and race to complete the creation of the temporary subdirectory. This vulnerability is local privilege escalation because the contents of the `outputFolder` can be appended to by an attacker. As such, code written to this directory, when executed can be attacker controlled. For more details refer to the referenced GitHub Security Advisory. This vulnerability is fixed in version 2.4.19. Note this is a distinct vulnerability from CVE-2021-21364.

- [https://github.com/dawetmaster/CVE-2021-21363-swagger-codegen-vulnerable](https://github.com/dawetmaster/CVE-2021-21363-swagger-codegen-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2021-21363-swagger-codegen-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2021-21363-swagger-codegen-vulnerable.svg)


## CVE-2021-20190
 A flaw was found in jackson-databind before 2.9.10.7. FasterXML mishandles the interaction between serialization gadgets and typing. The highest threat from this vulnerability is to data confidentiality and integrity as well as system availability.

- [https://github.com/dawetmaster/CVE-2021-20190-jackson-databind-vulnerable](https://github.com/dawetmaster/CVE-2021-20190-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2021-20190-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2021-20190-jackson-databind-vulnerable.svg)


## CVE-2020-36518
 jackson-databind before 2.13.0 allows a Java StackOverflow exception and denial of service via a large depth of nested objects.

- [https://github.com/dawetmaster/CVE-2020-36518-jackson-databind-vulnerable](https://github.com/dawetmaster/CVE-2020-36518-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2020-36518-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2020-36518-jackson-databind-vulnerable.svg)


## CVE-2020-36189
 FasterXML jackson-databind 2.x before 2.9.10.8 mishandles the interaction between serialization gadgets and typing, related to com.newrelic.agent.deps.ch.qos.logback.core.db.DriverManagerConnectionSource.

- [https://github.com/dawetmaster/CVE-2020-36189-jackson-databind-vulnerable](https://github.com/dawetmaster/CVE-2020-36189-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2020-36189-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2020-36189-jackson-databind-vulnerable.svg)


## CVE-2020-36188
 FasterXML jackson-databind 2.x before 2.9.10.8 mishandles the interaction between serialization gadgets and typing, related to com.newrelic.agent.deps.ch.qos.logback.core.db.JNDIConnectionSource.

- [https://github.com/dawetmaster/CVE-2020-36188-jackson-databind-vulnerable](https://github.com/dawetmaster/CVE-2020-36188-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2020-36188-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2020-36188-jackson-databind-vulnerable.svg)


## CVE-2020-36187
 FasterXML jackson-databind 2.x before 2.9.10.8 mishandles the interaction between serialization gadgets and typing, related to org.apache.tomcat.dbcp.dbcp.datasources.SharedPoolDataSource.

- [https://github.com/dawetmaster/CVE-2020-36187-jackson-databind-vulnerable](https://github.com/dawetmaster/CVE-2020-36187-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2020-36187-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2020-36187-jackson-databind-vulnerable.svg)


## CVE-2020-36186
 FasterXML jackson-databind 2.x before 2.9.10.8 mishandles the interaction between serialization gadgets and typing, related to org.apache.tomcat.dbcp.dbcp.datasources.PerUserPoolDataSource.

- [https://github.com/dawetmaster/CVE-2020-36186-jackson-databind-vulnerable](https://github.com/dawetmaster/CVE-2020-36186-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2020-36186-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2020-36186-jackson-databind-vulnerable.svg)


## CVE-2020-36185
 FasterXML jackson-databind 2.x before 2.9.10.8 mishandles the interaction between serialization gadgets and typing, related to org.apache.tomcat.dbcp.dbcp2.datasources.SharedPoolDataSource.

- [https://github.com/dawetmaster/CVE-2020-36185-jackson-databind-vulnerable](https://github.com/dawetmaster/CVE-2020-36185-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2020-36185-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2020-36185-jackson-databind-vulnerable.svg)


## CVE-2020-36184
 FasterXML jackson-databind 2.x before 2.9.10.8 mishandles the interaction between serialization gadgets and typing, related to org.apache.tomcat.dbcp.dbcp2.datasources.PerUserPoolDataSource.

- [https://github.com/dawetmaster/CVE-2020-36184-jackson-databind-vulnerable](https://github.com/dawetmaster/CVE-2020-36184-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2020-36184-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2020-36184-jackson-databind-vulnerable.svg)


## CVE-2020-36183
 FasterXML jackson-databind 2.x before 2.9.10.8 mishandles the interaction between serialization gadgets and typing, related to org.docx4j.org.apache.xalan.lib.sql.JNDIConnectionPool.

- [https://github.com/dawetmaster/CVE-2020-36183-jackson-databind-vulnerable](https://github.com/dawetmaster/CVE-2020-36183-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2020-36183-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2020-36183-jackson-databind-vulnerable.svg)


## CVE-2020-36182
 FasterXML jackson-databind 2.x before 2.9.10.8 mishandles the interaction between serialization gadgets and typing, related to org.apache.tomcat.dbcp.dbcp2.cpdsadapter.DriverAdapterCPDS.

- [https://github.com/dawetmaster/CVE-2020-36182-jackson-databind-vulnerable](https://github.com/dawetmaster/CVE-2020-36182-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2020-36182-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2020-36182-jackson-databind-vulnerable.svg)


## CVE-2020-36181
 FasterXML jackson-databind 2.x before 2.9.10.8 mishandles the interaction between serialization gadgets and typing, related to org.apache.tomcat.dbcp.dbcp.cpdsadapter.DriverAdapterCPDS.

- [https://github.com/dawetmaster/CVE-2020-36181-jackson-databind-vulnerable](https://github.com/dawetmaster/CVE-2020-36181-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2020-36181-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2020-36181-jackson-databind-vulnerable.svg)


## CVE-2020-36180
 FasterXML jackson-databind 2.x before 2.9.10.8 mishandles the interaction between serialization gadgets and typing, related to org.apache.commons.dbcp2.cpdsadapter.DriverAdapterCPDS.

- [https://github.com/dawetmaster/CVE-2020-36180-jackson-databind-vulnerable](https://github.com/dawetmaster/CVE-2020-36180-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2020-36180-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2020-36180-jackson-databind-vulnerable.svg)


## CVE-2020-36179
 FasterXML jackson-databind 2.x before 2.9.10.8 mishandles the interaction between serialization gadgets and typing, related to oadd.org.apache.commons.dbcp.cpdsadapter.DriverAdapterCPDS.

- [https://github.com/dawetmaster/CVE-2020-36179-jackson-databind-vulnerable](https://github.com/dawetmaster/CVE-2020-36179-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2020-36179-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2020-36179-jackson-databind-vulnerable.svg)


## CVE-2020-35728
 FasterXML jackson-databind 2.x before 2.9.10.8 mishandles the interaction between serialization gadgets and typing, related to com.oracle.wls.shaded.org.apache.xalan.lib.sql.JNDIConnectionPool (aka embedded Xalan in org.glassfish.web/javax.servlet.jsp.jstl).

- [https://github.com/dawetmaster/CVE-2020-35728-jackson-databind-vulnerable](https://github.com/dawetmaster/CVE-2020-35728-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2020-35728-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2020-35728-jackson-databind-vulnerable.svg)


## CVE-2020-35491
 FasterXML jackson-databind 2.x before 2.9.10.8 mishandles the interaction between serialization gadgets and typing, related to org.apache.commons.dbcp2.datasources.SharedPoolDataSource.

- [https://github.com/dawetmaster/CVE-2020-35491-jackson-databind-vulnerable](https://github.com/dawetmaster/CVE-2020-35491-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2020-35491-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2020-35491-jackson-databind-vulnerable.svg)


## CVE-2020-35490
 FasterXML jackson-databind 2.x before 2.9.10.8 mishandles the interaction between serialization gadgets and typing, related to org.apache.commons.dbcp2.datasources.PerUserPoolDataSource.

- [https://github.com/dawetmaster/CVE-2020-35490-jackson-databind-vulnerable](https://github.com/dawetmaster/CVE-2020-35490-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2020-35490-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2020-35490-jackson-databind-vulnerable.svg)


## CVE-2020-35217
 Vert.x-Web framework v4.0 milestone 1-4 does not perform a correct CSRF verification. Instead of comparing the CSRF token in the request with the CSRF token in the cookie, it compares the CSRF token in the cookie against a CSRF token that is stored in the session. An attacker does not even need to provide a CSRF token in the request because the framework does not consider it. The cookies are automatically sent by the browser and the verification will always succeed, leading to a successful CSRF attack.

- [https://github.com/dawetmaster/CVE-2020-35217-vertx-web-vulnerable](https://github.com/dawetmaster/CVE-2020-35217-vertx-web-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2020-35217-vertx-web-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2020-35217-vertx-web-vulnerable.svg)


## CVE-2020-28491
 This affects the package com.fasterxml.jackson.dataformat:jackson-dataformat-cbor from 0 and before 2.11.4, from 2.12.0-rc1 and before 2.12.1. Unchecked allocation of byte buffer can cause a java.lang.OutOfMemoryError exception.

- [https://github.com/dawetmaster/CVE-2020-28491-jackson-dataformats-binary-vulnerable](https://github.com/dawetmaster/CVE-2020-28491-jackson-dataformats-binary-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2020-28491-jackson-dataformats-binary-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2020-28491-jackson-dataformats-binary-vulnerable.svg)


## CVE-2020-26259
 XStream is a Java library to serialize objects to XML and back again. In XStream before version 1.4.15, is vulnerable to an Arbitrary File Deletion on the local host when unmarshalling. The vulnerability may allow a remote attacker to delete arbitrary know files on the host as log as the executing process has sufficient rights only by manipulating the processed input stream. If you rely on XStream's default blacklist of the Security Framework, you will have to use at least version 1.4.15. The reported vulnerability does not exist running Java 15 or higher. No user is affected, who followed the recommendation to setup XStream's Security Framework with a whitelist! Anyone relying on XStream's default blacklist can immediately switch to a whilelist for the allowed types to avoid the vulnerability. Users of XStream 1.4.14 or below who still want to use XStream default blacklist can use a workaround described in more detailed in the referenced advisories.

- [https://github.com/dawetmaster/CVE-2020-26259-xstream-vulnerable](https://github.com/dawetmaster/CVE-2020-26259-xstream-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2020-26259-xstream-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2020-26259-xstream-vulnerable.svg)


## CVE-2020-26258
 XStream is a Java library to serialize objects to XML and back again. In XStream before version 1.4.15, a Server-Side Forgery Request vulnerability can be activated when unmarshalling. The vulnerability may allow a remote attacker to request data from internal resources that are not publicly available only by manipulating the processed input stream. If you rely on XStream's default blacklist of the Security Framework, you will have to use at least version 1.4.15. The reported vulnerability does not exist if running Java 15 or higher. No user is affected who followed the recommendation to setup XStream's Security Framework with a whitelist! Anyone relying on XStream's default blacklist can immediately switch to a whilelist for the allowed types to avoid the vulnerability. Users of XStream 1.4.14 or below who still want to use XStream default blacklist can use a workaround described in more detailed in the referenced advisories.

- [https://github.com/dawetmaster/CVE-2020-26258-xstream-vulnerable](https://github.com/dawetmaster/CVE-2020-26258-xstream-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2020-26258-xstream-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2020-26258-xstream-vulnerable.svg)


## CVE-2020-26217
 XStream before version 1.4.14 is vulnerable to Remote Code Execution.The vulnerability may allow a remote attacker to run arbitrary shell commands only by manipulating the processed input stream. Only users who rely on blocklists are affected. Anyone using XStream's Security Framework allowlist is not affected. The linked advisory provides code workarounds for users who cannot upgrade. The issue is fixed in version 1.4.14.

- [https://github.com/dawetmaster/CVE-2020-26217-xstream-vulnerable](https://github.com/dawetmaster/CVE-2020-26217-xstream-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2020-26217-xstream-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2020-26217-xstream-vulnerable.svg)


## CVE-2020-25649
 A flaw was found in FasterXML Jackson Databind, where it did not have entity expansion secured properly. This flaw allows vulnerability to XML external entity (XXE) attacks. The highest threat from this vulnerability is data integrity.

- [https://github.com/dawetmaster/CVE-2020-25649-jackson-databind-vulnerable](https://github.com/dawetmaster/CVE-2020-25649-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2020-25649-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2020-25649-jackson-databind-vulnerable.svg)


## CVE-2020-24750
 FasterXML jackson-databind 2.x before 2.9.10.6 mishandles the interaction between serialization gadgets and typing, related to com.pastdev.httpcomponents.configuration.JndiConfiguration.

- [https://github.com/dawetmaster/CVE-2020-24750-jackson-databind-vulnerable](https://github.com/dawetmaster/CVE-2020-24750-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2020-24750-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2020-24750-jackson-databind-vulnerable.svg)


## CVE-2020-24616
 FasterXML jackson-databind 2.x before 2.9.10.6 mishandles the interaction between serialization gadgets and typing, related to br.com.anteros.dbcp.AnterosDBCPDataSource (aka Anteros-DBCP).

- [https://github.com/dawetmaster/CVE-2020-24616-jackson-databind-vulnerable](https://github.com/dawetmaster/CVE-2020-24616-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2020-24616-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2020-24616-jackson-databind-vulnerable.svg)


## CVE-2020-15250
 In JUnit4 from version 4.7 and before 4.13.1, the test rule TemporaryFolder contains a local information disclosure vulnerability. On Unix like systems, the system's temporary directory is shared between all users on that system. Because of this, when files and directories are written into this directory they are, by default, readable by other users on that same system. This vulnerability does not allow other users to overwrite the contents of these directories or files. This is purely an information disclosure vulnerability. This vulnerability impacts you if the JUnit tests write sensitive information, like API keys or passwords, into the temporary folder, and the JUnit tests execute in an environment where the OS has other untrusted users. Because certain JDK file system APIs were only added in JDK 1.7, this this fix is dependent upon the version of the JDK you are using. For Java 1.7 and higher users: this vulnerability is fixed in 4.13.1. For Java 1.6 and lower users: no patch is available, you must use the workaround below. If you are unable to patch, or are stuck running on Java 1.6, specifying the `java.io.tmpdir` system environment variable to a directory that is exclusively owned by the executing user will fix this vulnerability. For more information, including an example of vulnerable code, see the referenced GitHub Security Advisory.

- [https://github.com/dawetmaster/CVE-2020-15250-junit4-vulnerable](https://github.com/dawetmaster/CVE-2020-15250-junit4-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2020-15250-junit4-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2020-15250-junit4-vulnerable.svg)


## CVE-2020-14195
 FasterXML jackson-databind 2.x before 2.9.10.5 mishandles the interaction between serialization gadgets and typing, related to org.jsecurity.realm.jndi.JndiRealmFactory (aka org.jsecurity).

- [https://github.com/dawetmaster/CVE-2020-14195-jackson-databind-vulnerable](https://github.com/dawetmaster/CVE-2020-14195-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2020-14195-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2020-14195-jackson-databind-vulnerable.svg)


## CVE-2020-14062
 FasterXML jackson-databind 2.x before 2.9.10.5 mishandles the interaction between serialization gadgets and typing, related to com.sun.org.apache.xalan.internal.lib.sql.JNDIConnectionPool (aka xalan2).

- [https://github.com/dawetmaster/CVE-2020-14062-jackson-databind-vulnerable](https://github.com/dawetmaster/CVE-2020-14062-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2020-14062-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2020-14062-jackson-databind-vulnerable.svg)


## CVE-2020-14061
 FasterXML jackson-databind 2.x before 2.9.10.5 mishandles the interaction between serialization gadgets and typing, related to oracle.jms.AQjmsQueueConnectionFactory, oracle.jms.AQjmsXATopicConnectionFactory, oracle.jms.AQjmsTopicConnectionFactory, oracle.jms.AQjmsXAQueueConnectionFactory, and oracle.jms.AQjmsXAConnectionFactory (aka weblogic/oracle-aqjms).

- [https://github.com/dawetmaster/CVE-2020-14061-jackson-databind-vulnerable](https://github.com/dawetmaster/CVE-2020-14061-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2020-14061-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2020-14061-jackson-databind-vulnerable.svg)


## CVE-2020-14060
 FasterXML jackson-databind 2.x before 2.9.10.5 mishandles the interaction between serialization gadgets and typing, related to oadd.org.apache.xalan.lib.sql.JNDIConnectionPool (aka apache/drill).

- [https://github.com/dawetmaster/CVE-2020-14060-jackson-databind-vulnerable](https://github.com/dawetmaster/CVE-2020-14060-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2020-14060-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2020-14060-jackson-databind-vulnerable.svg)


## CVE-2020-13959
 The default error page for VelocityView in Apache Velocity Tools prior to 3.1 reflects back the vm file that was entered as part of the URL. An attacker can set an XSS payload file as this vm file in the URL which results in this payload being executed. XSS vulnerabilities allow attackers to execute arbitrary JavaScript in the context of the attacked website and the attacked user. This can be abused to steal session cookies, perform requests in the name of the victim or for phishing attacks.

- [https://github.com/dawetmaster/CVE-2020-13959-velocity-tools-vulnerable](https://github.com/dawetmaster/CVE-2020-13959-velocity-tools-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2020-13959-velocity-tools-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2020-13959-velocity-tools-vulnerable.svg)


## CVE-2020-11620
 FasterXML jackson-databind 2.x before 2.9.10.4 mishandles the interaction between serialization gadgets and typing, related to org.apache.commons.jelly.impl.Embedded (aka commons-jelly).

- [https://github.com/dawetmaster/CVE-2020-11620-jackson-databind-vulnerable](https://github.com/dawetmaster/CVE-2020-11620-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2020-11620-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2020-11620-jackson-databind-vulnerable.svg)


## CVE-2020-11619
 FasterXML jackson-databind 2.x before 2.9.10.4 mishandles the interaction between serialization gadgets and typing, related to org.springframework.aop.config.MethodLocatingFactoryBean (aka spring-aop).

- [https://github.com/dawetmaster/CVE-2020-11619-jackson-databind-vulnerable](https://github.com/dawetmaster/CVE-2020-11619-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2020-11619-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2020-11619-jackson-databind-vulnerable.svg)


## CVE-2020-11113
 FasterXML jackson-databind 2.x before 2.9.10.4 mishandles the interaction between serialization gadgets and typing, related to org.apache.openjpa.ee.WASRegistryManagedRuntime (aka openjpa).

- [https://github.com/dawetmaster/CVE-2020-11113-jackson-databind-vulnerable](https://github.com/dawetmaster/CVE-2020-11113-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2020-11113-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2020-11113-jackson-databind-vulnerable.svg)


## CVE-2020-11112
 FasterXML jackson-databind 2.x before 2.9.10.4 mishandles the interaction between serialization gadgets and typing, related to org.apache.commons.proxy.provider.remoting.RmiProvider (aka apache/commons-proxy).

- [https://github.com/dawetmaster/CVE-2020-11112-jackson-databind-vulnerable](https://github.com/dawetmaster/CVE-2020-11112-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2020-11112-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2020-11112-jackson-databind-vulnerable.svg)


## CVE-2020-11111
 FasterXML jackson-databind 2.x before 2.9.10.4 mishandles the interaction between serialization gadgets and typing, related to org.apache.activemq.* (aka activemq-jms, activemq-core, activemq-pool, and activemq-pool-jms).

- [https://github.com/dawetmaster/CVE-2020-11111-jackson-databind-vulnerable](https://github.com/dawetmaster/CVE-2020-11111-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2020-11111-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2020-11111-jackson-databind-vulnerable.svg)


## CVE-2020-10969
 FasterXML jackson-databind 2.x before 2.9.10.4 mishandles the interaction between serialization gadgets and typing, related to javax.swing.JEditorPane.

- [https://github.com/dawetmaster/CVE-2020-10969-jackson-databind-vulnerable](https://github.com/dawetmaster/CVE-2020-10969-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2020-10969-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2020-10969-jackson-databind-vulnerable.svg)


## CVE-2020-10968
 FasterXML jackson-databind 2.x before 2.9.10.4 mishandles the interaction between serialization gadgets and typing, related to org.aoju.bus.proxy.provider.remoting.RmiProvider (aka bus-proxy).

- [https://github.com/dawetmaster/CVE-2020-10968-jackson-databind-vulnerable](https://github.com/dawetmaster/CVE-2020-10968-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2020-10968-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2020-10968-jackson-databind-vulnerable.svg)


## CVE-2020-9548
 FasterXML jackson-databind 2.x before 2.9.10.4 mishandles the interaction between serialization gadgets and typing, related to br.com.anteros.dbcp.AnterosDBCPConfig (aka anteros-core).

- [https://github.com/dawetmaster/CVE-2020-9548-jackson-databind-vulnerable](https://github.com/dawetmaster/CVE-2020-9548-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2020-9548-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2020-9548-jackson-databind-vulnerable.svg)


## CVE-2020-9547
 FasterXML jackson-databind 2.x before 2.9.10.4 mishandles the interaction between serialization gadgets and typing, related to com.ibatis.sqlmap.engine.transaction.jta.JtaTransactionConfig (aka ibatis-sqlmap).

- [https://github.com/dawetmaster/CVE-2020-9547-jackson-databind-vulnerable](https://github.com/dawetmaster/CVE-2020-9547-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2020-9547-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2020-9547-jackson-databind-vulnerable.svg)


## CVE-2020-9546
 FasterXML jackson-databind 2.x before 2.9.10.4 mishandles the interaction between serialization gadgets and typing, related to org.apache.hadoop.shaded.com.zaxxer.hikari.HikariConfig (aka shaded hikari-config).

- [https://github.com/dawetmaster/CVE-2020-9546-jackson-databind-vulnerable](https://github.com/dawetmaster/CVE-2020-9546-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2020-9546-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2020-9546-jackson-databind-vulnerable.svg)


## CVE-2020-8840
 FasterXML jackson-databind 2.0.0 through 2.9.10.2 lacks certain xbean-reflect/JNDI blocking, as demonstrated by org.apache.xbean.propertyeditor.JndiConverter.

- [https://github.com/dawetmaster/CVE-2020-8840-jackson-databind-vulnerable](https://github.com/dawetmaster/CVE-2020-8840-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2020-8840-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2020-8840-jackson-databind-vulnerable.svg)


## CVE-2020-7692
 PKCE support is not implemented in accordance with the RFC for OAuth 2.0 for Native Apps. Without the use of PKCE, the authorization code returned by an authorization server is not enough to guarantee that the client that issued the initial authorization request is the one that will be authorized. An attacker is able to obtain the authorization code using a malicious app on the client-side and use it to gain authorization to the protected resource. This affects the package com.google.oauth-client:google-oauth-client before 1.31.0.

- [https://github.com/dawetmaster/CVE-2020-7692-google-oauth-java-client-vulnerable](https://github.com/dawetmaster/CVE-2020-7692-google-oauth-java-client-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2020-7692-google-oauth-java-client-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2020-7692-google-oauth-java-client-vulnerable.svg)


## CVE-2020-5752
 Relative path traversal in Druva inSync Windows Client 6.6.3 allows a local, unauthenticated attacker to execute arbitrary operating system commands with SYSTEM privileges.

- [https://github.com/yevh/CVE-2020-5752-Druva-inSync-Windows-Client-6.6.3---Local-Privilege-Escalation-PowerShell-](https://github.com/yevh/CVE-2020-5752-Druva-inSync-Windows-Client-6.6.3---Local-Privilege-Escalation-PowerShell-) :  ![starts](https://img.shields.io/github/stars/yevh/CVE-2020-5752-Druva-inSync-Windows-Client-6.6.3---Local-Privilege-Escalation-PowerShell-.svg) ![forks](https://img.shields.io/github/forks/yevh/CVE-2020-5752-Druva-inSync-Windows-Client-6.6.3---Local-Privilege-Escalation-PowerShell-.svg)
- [https://github.com/x0rbeexd/CVE-2020-5752](https://github.com/x0rbeexd/CVE-2020-5752) :  ![starts](https://img.shields.io/github/stars/x0rbeexd/CVE-2020-5752.svg) ![forks](https://img.shields.io/github/forks/x0rbeexd/CVE-2020-5752.svg)


## CVE-2020-1695
 A flaw was found in all resteasy 3.x.x versions prior to 3.12.0.Final and all resteasy 4.x.x versions prior to 4.6.0.Final, where an improper input validation results in returning an illegal header that integrates into the server's response. This flaw may result in an injection, which leads to unexpected behavior when the HTTP response is constructed.

- [https://github.com/dawetmaster/CVE-2020-1695-Resteasy-vulnerable](https://github.com/dawetmaster/CVE-2020-1695-Resteasy-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2020-1695-Resteasy-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2020-1695-Resteasy-vulnerable.svg)


## CVE-2019-1003010
 A cross-site request forgery vulnerability exists in Jenkins Git Plugin 3.9.1 and earlier in src/main/java/hudson/plugins/git/GitTagAction.java that allows attackers to create a Git tag in a workspace and attach corresponding metadata to a build record.

- [https://github.com/dawetmaster/CVE-2019-1003010-Prasanna-vulnerable](https://github.com/dawetmaster/CVE-2019-1003010-Prasanna-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2019-1003010-Prasanna-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2019-1003010-Prasanna-vulnerable.svg)


## CVE-2019-1003000
 A sandbox bypass vulnerability exists in Script Security Plugin 1.49 and earlier in src/main/java/org/jenkinsci/plugins/scriptsecurity/sandbox/groovy/GroovySandbox.java that allows attackers with the ability to provide sandboxed scripts to execute arbitrary code on the Jenkins master JVM.

- [https://github.com/dawetmaster/CVE-2019-1003000-script-security-plugin-vulnerable](https://github.com/dawetmaster/CVE-2019-1003000-script-security-plugin-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2019-1003000-script-security-plugin-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2019-1003000-script-security-plugin-vulnerable.svg)


## CVE-2019-20330
 FasterXML jackson-databind 2.x before 2.9.10.2 lacks certain net.sf.ehcache blocking.

- [https://github.com/dawetmaster/CVE-2019-20330-jackson-databind-vulnerable](https://github.com/dawetmaster/CVE-2019-20330-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2019-20330-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2019-20330-jackson-databind-vulnerable.svg)


## CVE-2019-18394
 A Server Side Request Forgery (SSRF) vulnerability in FaviconServlet.java in Ignite Realtime Openfire through 4.4.2 allows attackers to send arbitrary HTTP GET requests.

- [https://github.com/dawetmaster/CVE-2019-18394-Openfire-vulnerable](https://github.com/dawetmaster/CVE-2019-18394-Openfire-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2019-18394-Openfire-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2019-18394-Openfire-vulnerable.svg)


## CVE-2019-18393
 PluginServlet.java in Ignite Realtime Openfire through 4.4.2 does not ensure that retrieved files are located under the Openfire home directory, aka a directory traversal vulnerability.

- [https://github.com/dawetmaster/CVE-2019-18393-Openfire-vulnerable](https://github.com/dawetmaster/CVE-2019-18393-Openfire-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2019-18393-Openfire-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2019-18393-Openfire-vulnerable.svg)


## CVE-2019-17531
 A Polymorphic Typing issue was discovered in FasterXML jackson-databind 2.0.0 through 2.9.10. When Default Typing is enabled (either globally or for a specific property) for an externally exposed JSON endpoint and the service has the apache-log4j-extra (version 1.2.x) jar in the classpath, and an attacker can provide a JNDI service to access, it is possible to make the service execute a malicious payload.

- [https://github.com/dawetmaster/CVE-2019-17531-jackson-databind-vulnerable](https://github.com/dawetmaster/CVE-2019-17531-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2019-17531-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2019-17531-jackson-databind-vulnerable.svg)


## CVE-2019-17267
 A Polymorphic Typing issue was discovered in FasterXML jackson-databind before 2.9.10. It is related to net.sf.ehcache.hibernate.EhcacheJtaTransactionManagerLookup.

- [https://github.com/dawetmaster/CVE-2019-17267-jackson-databind-vulnerable](https://github.com/dawetmaster/CVE-2019-17267-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2019-17267-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2019-17267-jackson-databind-vulnerable.svg)


## CVE-2019-16943
 A Polymorphic Typing issue was discovered in FasterXML jackson-databind 2.0.0 through 2.9.10. When Default Typing is enabled (either globally or for a specific property) for an externally exposed JSON endpoint and the service has the p6spy (3.8.6) jar in the classpath, and an attacker can find an RMI service endpoint to access, it is possible to make the service execute a malicious payload. This issue exists because of com.p6spy.engine.spy.P6DataSource mishandling.

- [https://github.com/dawetmaster/CVE-2019-16943-jackson-databind-vulnerable](https://github.com/dawetmaster/CVE-2019-16943-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2019-16943-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2019-16943-jackson-databind-vulnerable.svg)


## CVE-2019-16942
 A Polymorphic Typing issue was discovered in FasterXML jackson-databind 2.0.0 through 2.9.10. When Default Typing is enabled (either globally or for a specific property) for an externally exposed JSON endpoint and the service has the commons-dbcp (1.4) jar in the classpath, and an attacker can find an RMI service endpoint to access, it is possible to make the service execute a malicious payload. This issue exists because of org.apache.commons.dbcp.datasources.SharedPoolDataSource and org.apache.commons.dbcp.datasources.PerUserPoolDataSource mishandling.

- [https://github.com/dawetmaster/CVE-2019-16942-jackson-databind-vulnerable](https://github.com/dawetmaster/CVE-2019-16942-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2019-16942-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2019-16942-jackson-databind-vulnerable.svg)


## CVE-2019-16335
 A Polymorphic Typing issue was discovered in FasterXML jackson-databind before 2.9.10. It is related to com.zaxxer.hikari.HikariDataSource. This is a different vulnerability than CVE-2019-14540.

- [https://github.com/dawetmaster/CVE-2019-16335-jackson-databind-vulnerable](https://github.com/dawetmaster/CVE-2019-16335-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2019-16335-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2019-16335-jackson-databind-vulnerable.svg)


## CVE-2019-14893
 A flaw was discovered in FasterXML jackson-databind in all versions before 2.9.10 and 2.10.0, where it would permit polymorphic deserialization of malicious objects using the xalan JNDI gadget when used in conjunction with polymorphic type handling methods such as `enableDefaultTyping()` or when @JsonTypeInfo is using `Id.CLASS` or `Id.MINIMAL_CLASS` or in any other way which ObjectMapper.readValue might instantiate objects from unsafe sources. An attacker could use this flaw to execute arbitrary code.

- [https://github.com/dawetmaster/CVE-2019-14893-jackson-databind-vulnerable](https://github.com/dawetmaster/CVE-2019-14893-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2019-14893-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2019-14893-jackson-databind-vulnerable.svg)


## CVE-2019-14892
 A flaw was discovered in jackson-databind in versions before 2.9.10, 2.8.11.5 and 2.6.7.3, where it would permit polymorphic deserialization of a malicious object using commons-configuration 1 and 2 JNDI classes. An attacker could use this flaw to execute arbitrary code.

- [https://github.com/dawetmaster/CVE-2019-14892-jackson-databind-vulnerable](https://github.com/dawetmaster/CVE-2019-14892-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2019-14892-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2019-14892-jackson-databind-vulnerable.svg)


## CVE-2019-14540
 A Polymorphic Typing issue was discovered in FasterXML jackson-databind before 2.9.10. It is related to com.zaxxer.hikari.HikariConfig.

- [https://github.com/dawetmaster/CVE-2019-14540-jackson-databind-vulnerable](https://github.com/dawetmaster/CVE-2019-14540-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2019-14540-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2019-14540-jackson-databind-vulnerable.svg)


## CVE-2019-14439
 A Polymorphic Typing issue was discovered in FasterXML jackson-databind 2.x before 2.9.9.2. This occurs when Default Typing is enabled (either globally or for a specific property) for an externally exposed JSON endpoint and the service has the logback jar in the classpath.

- [https://github.com/dawetmaster/CVE-2019-14439-jackson-databind-vulnerable](https://github.com/dawetmaster/CVE-2019-14439-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2019-14439-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2019-14439-jackson-databind-vulnerable.svg)


## CVE-2019-14379
 SubTypeValidator.java in FasterXML jackson-databind before 2.9.9.2 mishandles default typing when ehcache is used (because of net.sf.ehcache.transaction.manager.DefaultTransactionManagerLookup), leading to remote code execution.

- [https://github.com/dawetmaster/CVE-2019-14379-jackson-databind-vulnerable](https://github.com/dawetmaster/CVE-2019-14379-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2019-14379-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2019-14379-jackson-databind-vulnerable.svg)


## CVE-2019-12814
 A Polymorphic Typing issue was discovered in FasterXML jackson-databind 2.x through 2.9.9. When Default Typing is enabled (either globally or for a specific property) for an externally exposed JSON endpoint and the service has JDOM 1.x or 2.x jar in the classpath, an attacker can send a specifically crafted JSON message that allows them to read arbitrary local files on the server.

- [https://github.com/dawetmaster/CVE-2019-12814-jackson-databind-vulnerable](https://github.com/dawetmaster/CVE-2019-12814-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2019-12814-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2019-12814-jackson-databind-vulnerable.svg)


## CVE-2019-12402
 The file name encoding algorithm used internally in Apache Commons Compress 1.15 to 1.18 can get into an infinite loop when faced with specially crafted inputs. This can lead to a denial of service attack if an attacker can choose the file names inside of an archive created by Compress.

- [https://github.com/dawetmaster/CVE-2019-12402-commons-compress-vulnerable](https://github.com/dawetmaster/CVE-2019-12402-commons-compress-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2019-12402-commons-compress-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2019-12402-commons-compress-vulnerable.svg)


## CVE-2019-12400
 In version 2.0.3 Apache Santuario XML Security for Java, a caching mechanism was introduced to speed up creating new XML documents using a static pool of DocumentBuilders. However, if some untrusted code can register a malicious implementation with the thread context class loader first, then this implementation might be cached and re-used by Apache Santuario - XML Security for Java, leading to potential security flaws when validating signed documents, etc. The vulnerability affects Apache Santuario - XML Security for Java 2.0.x releases from 2.0.3 and all 2.1.x releases before 2.1.4.

- [https://github.com/dawetmaster/CVE-2019-12400-santuario-java-vulnerable](https://github.com/dawetmaster/CVE-2019-12400-santuario-java-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2019-12400-santuario-java-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2019-12400-santuario-java-vulnerable.svg)


## CVE-2019-12384
 FasterXML jackson-databind 2.x before 2.9.9.1 might allow attackers to have a variety of impacts by leveraging failure to block the logback-core class from polymorphic deserialization. Depending on the classpath content, remote code execution may be possible.

- [https://github.com/dawetmaster/CVE-2019-12384-jackson-databind-vulnerable](https://github.com/dawetmaster/CVE-2019-12384-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2019-12384-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2019-12384-jackson-databind-vulnerable.svg)


## CVE-2019-12086
 A Polymorphic Typing issue was discovered in FasterXML jackson-databind 2.x before 2.9.9. When Default Typing is enabled (either globally or for a specific property) for an externally exposed JSON endpoint, the service has the mysql-connector-java jar (8.0.14 or earlier) in the classpath, and an attacker can host a crafted MySQL server reachable by the victim, an attacker can send a crafted JSON message that allows them to read arbitrary local files on the server. This occurs because of missing com.mysql.cj.jdbc.admin.MiniAdmin validation.

- [https://github.com/dawetmaster/CVE-2019-12086-jackson-databind-vulnerable](https://github.com/dawetmaster/CVE-2019-12086-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2019-12086-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2019-12086-jackson-databind-vulnerable.svg)


## CVE-2019-10219
 A vulnerability was found in Hibernate-Validator. The SafeHtml validator annotation fails to properly sanitize payloads consisting of potentially malicious code in HTML comments and instructions. This vulnerability can result in an XSS attack.

- [https://github.com/dawetmaster/CVE-2019-10219-hibernate-validator-vulnerable](https://github.com/dawetmaster/CVE-2019-10219-hibernate-validator-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2019-10219-hibernate-validator-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2019-10219-hibernate-validator-vulnerable.svg)


## CVE-2019-0201
 An issue is present in Apache ZooKeeper 1.0.0 to 3.4.13 and 3.5.0-alpha to 3.5.4-beta. ZooKeeper’s getACL() command doesn’t check any permission when retrieves the ACLs of the requested node and returns all information contained in the ACL Id field as plaintext string. DigestAuthenticationProvider overloads the Id field with the hash value that is used for user authentication. As a consequence, if Digest Authentication is in use, the unsalted hash value will be disclosed by getACL() request for unauthenticated or unprivileged users.

- [https://github.com/dawetmaster/CVE-2019-0201-zookeeper-vulnerable](https://github.com/dawetmaster/CVE-2019-0201-zookeeper-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2019-0201-zookeeper-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2019-0201-zookeeper-vulnerable.svg)


## CVE-2018-1002201
 zt-zip before 1.13 is vulnerable to directory traversal, allowing attackers to write to arbitrary files via a ../ (dot dot slash) in a Zip archive entry that is mishandled during extraction. This vulnerability is also known as 'Zip-Slip'.

- [https://github.com/dawetmaster/CVE-2018-1002201-zt-zip-vulnerable](https://github.com/dawetmaster/CVE-2018-1002201-zt-zip-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2018-1002201-zt-zip-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2018-1002201-zt-zip-vulnerable.svg)


## CVE-2018-1002200
 plexus-archiver before 3.6.0 is vulnerable to directory traversal, allowing attackers to write to arbitrary files via a ../ (dot dot slash) in an archive entry that is mishandled during extraction. This vulnerability is also known as 'Zip-Slip'.

- [https://github.com/dawetmaster/CVE-2018-1002200-plexus-archiver-vulnerable](https://github.com/dawetmaster/CVE-2018-1002200-plexus-archiver-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2018-1002200-plexus-archiver-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2018-1002200-plexus-archiver-vulnerable.svg)


## CVE-2018-1000873
 Fasterxml Jackson version Before 2.9.8 contains a CWE-20: Improper Input Validation vulnerability in Jackson-Modules-Java8 that can result in Causes a denial-of-service (DoS). This attack appear to be exploitable via The victim deserializes malicious input, specifically very large values in the nanoseconds field of a time value. This vulnerability appears to have been fixed in 2.9.8.

- [https://github.com/dawetmaster/CVE-2018-1000873-jackson-modules-java8-vulnerable](https://github.com/dawetmaster/CVE-2018-1000873-jackson-modules-java8-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2018-1000873-jackson-modules-java8-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2018-1000873-jackson-modules-java8-vulnerable.svg)


## CVE-2018-1000844
 Square Open Source Retrofit version Prior to commit 4a693c5aeeef2be6c7ecf80e7b5ec79f6ab59437 contains a XML External Entity (XXE) vulnerability in JAXB that can result in An attacker could use this to remotely read files from the file system or to perform SSRF.. This vulnerability appears to have been fixed in After commit 4a693c5aeeef2be6c7ecf80e7b5ec79f6ab59437.

- [https://github.com/dawetmaster/CVE-2018-1000844-retrofit-vulnerable](https://github.com/dawetmaster/CVE-2018-1000844-retrofit-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2018-1000844-retrofit-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2018-1000844-retrofit-vulnerable.svg)


## CVE-2018-1000822
 codelibs fess version before commit faa265b contains a XML External Entity (XXE) vulnerability in GSA XML file parser that can result in Disclosure of confidential data, denial of service, SSRF, port scanning. This attack appear to be exploitable via specially crafted GSA XML files. This vulnerability appears to have been fixed in after commit faa265b.

- [https://github.com/dawetmaster/CVE-2018-1000822-fess-vulnerable](https://github.com/dawetmaster/CVE-2018-1000822-fess-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2018-1000822-fess-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2018-1000822-fess-vulnerable.svg)


## CVE-2018-1000531
 inversoft prime-jwt version prior to commit abb0d479389a2509f939452a6767dc424bb5e6ba contains a CWE-20 vulnerability in JWTDecoder.decode that can result in an incorrect signature validation of a JWT token. This attack can be exploitable when an attacker crafts a JWT token with a valid header using 'none' as algorithm and a body to requests it be validated. This vulnerability was fixed after commit abb0d479389a2509f939452a6767dc424bb5e6ba.

- [https://github.com/dawetmaster/CVE-2018-1000531-prime-jwt-vulnerable](https://github.com/dawetmaster/CVE-2018-1000531-prime-jwt-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2018-1000531-prime-jwt-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2018-1000531-prime-jwt-vulnerable.svg)


## CVE-2018-1000125
 inversoft prime-jwt version prior to version 1.3.0 or prior to commit 0d94dcef0133d699f21d217e922564adbb83a227 contains an input validation vulnerability in JWTDecoder.decode that can result in a JWT that is decoded and thus implicitly validated even if it lacks a valid signature. This attack appear to be exploitable via an attacker crafting a token with a valid header and body and then requests it to be validated. This vulnerability appears to have been fixed in 1.3.0 and later or after commit 0d94dcef0133d699f21d217e922564adbb83a227.

- [https://github.com/dawetmaster/CVE-2018-1000125-prime-jwt-vulnerable](https://github.com/dawetmaster/CVE-2018-1000125-prime-jwt-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2018-1000125-prime-jwt-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2018-1000125-prime-jwt-vulnerable.svg)


## CVE-2018-20318
 An issue was discovered in weixin-java-tools v3.2.0. There is an XXE vulnerability in the getXmlDoc method of the BaseWxPayResult.java file.

- [https://github.com/dawetmaster/CVE-2018-20318-weixin-java-tools-vulnerable](https://github.com/dawetmaster/CVE-2018-20318-weixin-java-tools-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2018-20318-weixin-java-tools-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2018-20318-weixin-java-tools-vulnerable.svg)


## CVE-2018-20227
 RDF4J 2.4.2 allows Directory Traversal via ../ in an entry in a ZIP archive.

- [https://github.com/dawetmaster/CVE-2018-20227-rdf4j-vulnerable](https://github.com/dawetmaster/CVE-2018-20227-rdf4j-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2018-20227-rdf4j-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2018-20227-rdf4j-vulnerable.svg)


## CVE-2018-19362
 FasterXML jackson-databind 2.x before 2.9.8 might allow attackers to have unspecified impact by leveraging failure to block the jboss-common-core class from polymorphic deserialization.

- [https://github.com/dawetmaster/CVE-2018-19362-jackson-databind-vulnerable](https://github.com/dawetmaster/CVE-2018-19362-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2018-19362-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2018-19362-jackson-databind-vulnerable.svg)


## CVE-2018-19361
 FasterXML jackson-databind 2.x before 2.9.8 might allow attackers to have unspecified impact by leveraging failure to block the openjpa class from polymorphic deserialization.

- [https://github.com/dawetmaster/CVE-2018-19361-jackson-databind-vulnerable](https://github.com/dawetmaster/CVE-2018-19361-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2018-19361-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2018-19361-jackson-databind-vulnerable.svg)


## CVE-2018-19360
 FasterXML jackson-databind 2.x before 2.9.8 might allow attackers to have unspecified impact by leveraging failure to block the axis2-transport-jms class from polymorphic deserialization.

- [https://github.com/dawetmaster/CVE-2018-19360-jackson-databind-vulnerable](https://github.com/dawetmaster/CVE-2018-19360-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2018-19360-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2018-19360-jackson-databind-vulnerable.svg)


## CVE-2018-17187
 The Apache Qpid Proton-J transport includes an optional wrapper layer to perform TLS, enabled by use of the 'transport.ssl(...)' methods. Unless a verification mode was explicitly configured, client and server modes previously defaulted as documented to not verifying a peer certificate, with options to configure this explicitly or select a certificate verification mode with or without hostname verification being performed. The latter hostname verifying mode was not implemented in Apache Qpid Proton-J versions 0.3 to 0.29.0, with attempts to use it resulting in an exception. This left only the option to verify the certificate is trusted, leaving such a client vulnerable to Man In The Middle (MITM) attack. Uses of the Proton-J protocol engine which do not utilise the optional transport TLS wrapper are not impacted, e.g. usage within Qpid JMS. Uses of Proton-J utilising the optional transport TLS wrapper layer that wish to enable hostname verification must be upgraded to version 0.30.0 or later and utilise the VerifyMode#VERIFY_PEER_NAME configuration, which is now the default for client mode usage unless configured otherwise.

- [https://github.com/dawetmaster/CVE-2018-17187-qpid-proton-j-vulnerable](https://github.com/dawetmaster/CVE-2018-17187-qpid-proton-j-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2018-17187-qpid-proton-j-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2018-17187-qpid-proton-j-vulnerable.svg)


## CVE-2018-14721
 FasterXML jackson-databind 2.x before 2.9.7 might allow remote attackers to conduct server-side request forgery (SSRF) attacks by leveraging failure to block the axis2-jaxws class from polymorphic deserialization.

- [https://github.com/dawetmaster/CVE-2018-14721-jackson-databind-vulnerable](https://github.com/dawetmaster/CVE-2018-14721-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2018-14721-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2018-14721-jackson-databind-vulnerable.svg)


## CVE-2018-14720
 FasterXML jackson-databind 2.x before 2.9.7 might allow attackers to conduct external XML entity (XXE) attacks by leveraging failure to block unspecified JDK classes from polymorphic deserialization.

- [https://github.com/dawetmaster/CVE-2018-14720-jackson-databind-vulnerable](https://github.com/dawetmaster/CVE-2018-14720-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2018-14720-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2018-14720-jackson-databind-vulnerable.svg)


## CVE-2018-14719
 FasterXML jackson-databind 2.x before 2.9.7 might allow remote attackers to execute arbitrary code by leveraging failure to block the blaze-ds-opt and blaze-ds-core classes from polymorphic deserialization.

- [https://github.com/dawetmaster/CVE-2018-14719-jackson-databind-vulnerable](https://github.com/dawetmaster/CVE-2018-14719-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2018-14719-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2018-14719-jackson-databind-vulnerable.svg)


## CVE-2018-14718
 FasterXML jackson-databind 2.x before 2.9.7 might allow remote attackers to execute arbitrary code by leveraging failure to block the slf4j-ext class from polymorphic deserialization.

- [https://github.com/dawetmaster/CVE-2018-14718-jackson-databind-vulnerable](https://github.com/dawetmaster/CVE-2018-14718-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2018-14718-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2018-14718-jackson-databind-vulnerable.svg)


## CVE-2018-12544
 In version from 3.5.Beta1 to 3.5.3 of Eclipse Vert.x, the OpenAPI XML type validator creates XML parsers without taking appropriate defense against XML attacks. This mechanism is exclusively when the developer uses the Eclipse Vert.x OpenAPI XML type validator to validate a provided schema.

- [https://github.com/dawetmaster/CVE-2018-12544-vertx-web-vulnerable](https://github.com/dawetmaster/CVE-2018-12544-vertx-web-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2018-12544-vertx-web-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2018-12544-vertx-web-vulnerable.svg)


## CVE-2018-12542
 In version from 3.0.0 to 3.5.3 of Eclipse Vert.x, the StaticHandler uses external input to construct a pathname that should be within a restricted directory, but it does not properly neutralize '\' (forward slashes) sequences that can resolve to a location that is outside of that directory when running on Windows Operating Systems.

- [https://github.com/dawetmaster/CVE-2018-12542-vertx-web-vulnerable](https://github.com/dawetmaster/CVE-2018-12542-vertx-web-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2018-12542-vertx-web-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2018-12542-vertx-web-vulnerable.svg)


## CVE-2018-12541
 In version from 3.0.0 to 3.5.3 of Eclipse Vert.x, the WebSocket HTTP upgrade implementation buffers the full http request before doing the handshake, holding the entire request body in memory. There should be a reasonnable limit (8192 bytes) above which the WebSocket gets an HTTP response with the 413 status code and the connection gets closed.

- [https://github.com/dawetmaster/CVE-2018-12541-vert.x-vulnerable](https://github.com/dawetmaster/CVE-2018-12541-vert.x-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2018-12541-vert.x-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2018-12541-vert.x-vulnerable.svg)


## CVE-2018-12540
 In version from 3.0.0 to 3.5.2 of Eclipse Vert.x, the CSRFHandler do not assert that the XSRF Cookie matches the returned XSRF header/form parameter. This allows replay attacks with previously issued tokens which are not expired yet.

- [https://github.com/dawetmaster/CVE-2018-12540-vertx-web-vulnerable](https://github.com/dawetmaster/CVE-2018-12540-vertx-web-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2018-12540-vertx-web-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2018-12540-vertx-web-vulnerable.svg)


## CVE-2018-12537
 In Eclipse Vert.x version 3.0 to 3.5.1, the HttpServer response headers and HttpClient request headers do not filter carriage return and line feed characters from the header value. This allow unfiltered values to inject a new header in the client request or server response.

- [https://github.com/dawetmaster/CVE-2018-12537-vert.x-vulnerable](https://github.com/dawetmaster/CVE-2018-12537-vert.x-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2018-12537-vert.x-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2018-12537-vert.x-vulnerable.svg)


## CVE-2018-12023
 An issue was discovered in FasterXML jackson-databind prior to 2.7.9.4, 2.8.11.2, and 2.9.6. When Default Typing is enabled (either globally or for a specific property), the service has the Oracle JDBC jar in the classpath, and an attacker can provide an LDAP service to access, it is possible to make the service execute a malicious payload.

- [https://github.com/dawetmaster/CVE-2018-12023-jackson-databind-vulnerable](https://github.com/dawetmaster/CVE-2018-12023-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2018-12023-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2018-12023-jackson-databind-vulnerable.svg)


## CVE-2018-12022
 An issue was discovered in FasterXML jackson-databind prior to 2.7.9.4, 2.8.11.2, and 2.9.6. When Default Typing is enabled (either globally or for a specific property), the service has the Jodd-db jar (for database access for the Jodd framework) in the classpath, and an attacker can provide an LDAP service to access, it is possible to make the service execute a malicious payload.

- [https://github.com/dawetmaster/CVE-2018-12022-jackson-databind-vulnerable](https://github.com/dawetmaster/CVE-2018-12022-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2018-12022-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2018-12022-jackson-databind-vulnerable.svg)


## CVE-2018-11771
 When reading a specially crafted ZIP archive, the read method of Apache Commons Compress 1.7 to 1.17's ZipArchiveInputStream can fail to return the correct EOF indication after the end of the stream has been reached. When combined with a java.io.InputStreamReader this can lead to an infinite stream, which can be used to mount a denial of service attack against services that use Compress' zip package.

- [https://github.com/dawetmaster/CVE-2018-11771-commons-compress-vulnerable](https://github.com/dawetmaster/CVE-2018-11771-commons-compress-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2018-11771-commons-compress-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2018-11771-commons-compress-vulnerable.svg)


## CVE-2018-11307
 An issue was discovered in FasterXML jackson-databind 2.0.0 through 2.9.5. Use of Jackson default typing along with a gadget class from iBatis allows exfiltration of content. Fixed in 2.7.9.4, 2.8.11.2, and 2.9.6.

- [https://github.com/dawetmaster/CVE-2018-11307-jackson-databind-vulnerable](https://github.com/dawetmaster/CVE-2018-11307-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2018-11307-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2018-11307-jackson-databind-vulnerable.svg)


## CVE-2018-10936
 A weakness was found in postgresql-jdbc before version 42.2.5. It was possible to provide an SSL Factory and not check the host name if a host name verifier was not provided to the driver. This could lead to a condition where a man-in-the-middle attacker could masquerade as a trusted server by providing a certificate for the wrong host, as long as it was signed by a trusted CA.

- [https://github.com/dawetmaster/CVE-2018-10936-pgjdbc-vulnerable](https://github.com/dawetmaster/CVE-2018-10936-pgjdbc-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2018-10936-pgjdbc-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2018-10936-pgjdbc-vulnerable.svg)


## CVE-2018-9159
 In Spark before 2.7.2, a remote attacker can read unintended static files via various representations of absolute or relative pathnames, as demonstrated by file: URLs and directory traversal sequences. NOTE: this product is unrelated to Ignite Realtime Spark.

- [https://github.com/dawetmaster/CVE-2018-9159-perwendel-spark-vulnerable](https://github.com/dawetmaster/CVE-2018-9159-perwendel-spark-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2018-9159-perwendel-spark-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2018-9159-perwendel-spark-vulnerable.svg)


## CVE-2018-8030
 A Denial of Service vulnerability was found in Apache Qpid Broker-J versions 7.0.0-7.0.4 when AMQP protocols 0-8, 0-9 or 0-91 are used to publish messages with size greater than allowed maximum message size limit (100MB by default). The broker crashes due to the defect. AMQP protocols 0-10 and 1.0 are not affected.

- [https://github.com/dawetmaster/CVE-2018-8030-qpid-broker-j-vulnerable](https://github.com/dawetmaster/CVE-2018-8030-qpid-broker-j-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2018-8030-qpid-broker-j-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2018-8030-qpid-broker-j-vulnerable.svg)


## CVE-2018-7489
 FasterXML jackson-databind before 2.7.9.3, 2.8.x before 2.8.11.1 and 2.9.x before 2.9.5 allows unauthenticated remote code execution because of an incomplete fix for the CVE-2017-7525 deserialization flaw. This is exploitable by sending maliciously crafted JSON input to the readValue method of the ObjectMapper, bypassing a blacklist that is ineffective if the c3p0 libraries are available in the classpath.

- [https://github.com/dawetmaster/CVE-2018-7489-jackson-databind-vulnerable](https://github.com/dawetmaster/CVE-2018-7489-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2018-7489-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2018-7489-jackson-databind-vulnerable.svg)


## CVE-2018-5968
 FasterXML jackson-databind through 2.8.11 and 2.9.x through 2.9.3 allows unauthenticated remote code execution because of an incomplete fix for the CVE-2017-7525 and CVE-2017-17485 deserialization flaws. This is exploitable via two different gadgets that bypass a blacklist.

- [https://github.com/dawetmaster/CVE-2018-5968-jackson-databind-vulnerable](https://github.com/dawetmaster/CVE-2018-5968-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2018-5968-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2018-5968-jackson-databind-vulnerable.svg)


## CVE-2018-1337
 In Apache Directory LDAP API before 1.0.2, a bug in the way the SSL Filter was setup made it possible for another thread to use the connection before the TLS layer has been established, if the connection has already been used and put back in a pool of connections, leading to leaking any information contained in this request (including the credentials when sending a BIND request).

- [https://github.com/dawetmaster/CVE-2018-1337-directory-ldap-api-vulnerable](https://github.com/dawetmaster/CVE-2018-1337-directory-ldap-api-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2018-1337-directory-ldap-api-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2018-1337-directory-ldap-api-vulnerable.svg)


## CVE-2018-1324
 A specially crafted ZIP archive can be used to cause an infinite loop inside of Apache Commons Compress' extra field parser used by the ZipFile and ZipArchiveInputStream classes in versions 1.11 to 1.15. This can be used to mount a denial of service attack against services that use Compress' zip package.

- [https://github.com/dawetmaster/CVE-2018-1324-commons-compress-vulnerable](https://github.com/dawetmaster/CVE-2018-1324-commons-compress-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2018-1324-commons-compress-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2018-1324-commons-compress-vulnerable.svg)


## CVE-2018-1306
 The PortletV3AnnotatedDemo Multipart Portlet war file code provided in Apache Pluto version 3.0.0 could allow a remote attacker to obtain sensitive information, caused by the failure to restrict path information provided during a file upload. An attacker could exploit this vulnerability to obtain configuration data and other sensitive information.

- [https://github.com/dawetmaster/CVE-2018-1306-portals-pluto-vulnerable](https://github.com/dawetmaster/CVE-2018-1306-portals-pluto-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2018-1306-portals-pluto-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2018-1306-portals-pluto-vulnerable.svg)


## CVE-2018-1274
 Spring Data Commons, versions 1.13 to 1.13.10, 2.0 to 2.0.5, and older unsupported versions, contain a property path parser vulnerability caused by unlimited resource allocation. An unauthenticated remote malicious user (or attacker) can issue requests against Spring Data REST endpoints or endpoints using property path parsing which can cause a denial of service (CPU and memory consumption).

- [https://github.com/dawetmaster/CVE-2018-1274-spring-data-commons-vulnerable](https://github.com/dawetmaster/CVE-2018-1274-spring-data-commons-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2018-1274-spring-data-commons-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2018-1274-spring-data-commons-vulnerable.svg)


## CVE-2018-1273
 Spring Data Commons, versions prior to 1.13 to 1.13.10, 2.0 to 2.0.5, and older unsupported versions, contain a property binder vulnerability caused by improper neutralization of special elements. An unauthenticated remote malicious user (or attacker) can supply specially crafted request parameters against Spring Data REST backed HTTP resources or using Spring Data's projection-based request payload binding hat can lead to a remote code execution attack.

- [https://github.com/dawetmaster/CVE-2018-1273-spring-data-commons-vulnerable](https://github.com/dawetmaster/CVE-2018-1273-spring-data-commons-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2018-1273-spring-data-commons-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2018-1273-spring-data-commons-vulnerable.svg)


## CVE-2018-1114
 It was found that URLResource.getLastModified() in Undertow closes the file descriptors only when they are finalized which can cause file descriptors to exhaust. This leads to a file handler leak.

- [https://github.com/dawetmaster/CVE-2018-1114-undertow-vulnerable](https://github.com/dawetmaster/CVE-2018-1114-undertow-vulnerable) :  ![starts](https://img.shields.io/github/stars/dawetmaster/CVE-2018-1114-undertow-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dawetmaster/CVE-2018-1114-undertow-vulnerable.svg)

