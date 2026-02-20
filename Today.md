# Update 2026-02-20
## CVE-2026-26221
 Hyland OnBase contains an unauthenticated .NET Remoting exposure in the OnBase Workflow Timer Service (Hyland.Core.Workflow.NTService.exe). An attacker who can reach the service can send crafted .NET Remoting requests to default HTTP channel endpoints on TCP/8900 (e.g., TimerServiceAPI.rem and TimerServiceEvents.rem for Workflow) to trigger unsafe object unmarshalling, enabling arbitrary file read/write. By writing attacker-controlled content into web-accessible locations or chaining with other OnBase features, this can lead to remote code execution. The same primitive can be abused by supplying a UNC path to coerce outbound NTLM authentication (SMB coercion) to an attacker-controlled host.

- [https://github.com/mbanyamer/CVE-2026-26221-Hyland-OnBase-Timer-Service-Unauthenticated-RCE](https://github.com/mbanyamer/CVE-2026-26221-Hyland-OnBase-Timer-Service-Unauthenticated-RCE) :  ![starts](https://img.shields.io/github/stars/mbanyamer/CVE-2026-26221-Hyland-OnBase-Timer-Service-Unauthenticated-RCE.svg) ![forks](https://img.shields.io/github/forks/mbanyamer/CVE-2026-26221-Hyland-OnBase-Timer-Service-Unauthenticated-RCE.svg)


## CVE-2026-26012
 vaultwarden is an unofficial Bitwarden compatible server written in Rust, formerly known as bitwarden_rs. Prior to 1.35.3, a regular organization member can retrieve all ciphers within an organization, regardless of collection permissions. The endpoint /ciphers/organization-details is accessible to any organization member and internally uses Cipher::find_by_org to retrieve all ciphers. These ciphers are returned with CipherSyncType::Organization without enforcing collection-level access control. This vulnerability is fixed in 1.35.3.

- [https://github.com/diegobaelen/CVE-2026-26012](https://github.com/diegobaelen/CVE-2026-26012) :  ![starts](https://img.shields.io/github/stars/diegobaelen/CVE-2026-26012.svg) ![forks](https://img.shields.io/github/forks/diegobaelen/CVE-2026-26012.svg)


## CVE-2026-24061
 telnetd in GNU Inetutils through 2.7 allows remote authentication bypass via a "-f root" value for the USER environment variable.

- [https://github.com/mbanyamer/CVE-2026-24061-GNU-Inetutils-telnetd-Remote-Authentication-Bypass-Root-Shell-](https://github.com/mbanyamer/CVE-2026-24061-GNU-Inetutils-telnetd-Remote-Authentication-Bypass-Root-Shell-) :  ![starts](https://img.shields.io/github/stars/mbanyamer/CVE-2026-24061-GNU-Inetutils-telnetd-Remote-Authentication-Bypass-Root-Shell-.svg) ![forks](https://img.shields.io/github/forks/mbanyamer/CVE-2026-24061-GNU-Inetutils-telnetd-Remote-Authentication-Bypass-Root-Shell-.svg)


## CVE-2026-21957
 Vulnerability in the Oracle VM VirtualBox product of Oracle Virtualization (component: Core).  Supported versions that are affected are 7.1.14 and  7.2.4. Difficult to exploit vulnerability allows high privileged attacker with logon to the infrastructure where Oracle VM VirtualBox executes to compromise Oracle VM VirtualBox.  While the vulnerability is in Oracle VM VirtualBox, attacks may significantly impact additional products (scope change).  Successful attacks of this vulnerability can result in takeover of Oracle VM VirtualBox. CVSS 3.1 Base Score 7.5 (Confidentiality, Integrity and Availability impacts).  CVSS Vector: (CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:C/C:H/I:H/A:H).

- [https://github.com/jermaine22sei/CVE-2026-21957-exp](https://github.com/jermaine22sei/CVE-2026-21957-exp) :  ![starts](https://img.shields.io/github/stars/jermaine22sei/CVE-2026-21957-exp.svg) ![forks](https://img.shields.io/github/forks/jermaine22sei/CVE-2026-21957-exp.svg)


## CVE-2026-20817
 Improper handling of insufficient permissions or privileges in Windows Error Reporting allows an authorized attacker to elevate privileges locally.

- [https://github.com/oxfemale/CVE-2026-20817](https://github.com/oxfemale/CVE-2026-20817) :  ![starts](https://img.shields.io/github/stars/oxfemale/CVE-2026-20817.svg) ![forks](https://img.shields.io/github/forks/oxfemale/CVE-2026-20817.svg)


## CVE-2026-20700
 A memory corruption issue was addressed with improved state management. This issue is fixed in watchOS 26.3, tvOS 26.3, macOS Tahoe 26.3, visionOS 26.3, iOS 26.3 and iPadOS 26.3. An attacker with memory write capability may be able to execute arbitrary code. Apple is aware of a report that this issue may have been exploited in an extremely sophisticated attack against specific targeted individuals on versions of iOS before iOS 26. CVE-2025-14174 and CVE-2025-43529 were also issued in response to this report.

- [https://github.com/sundenovak/CVE-2026-20700-An-analysis-WIP](https://github.com/sundenovak/CVE-2026-20700-An-analysis-WIP) :  ![starts](https://img.shields.io/github/stars/sundenovak/CVE-2026-20700-An-analysis-WIP.svg) ![forks](https://img.shields.io/github/forks/sundenovak/CVE-2026-20700-An-analysis-WIP.svg)


## CVE-2026-2441
 Use after free in CSS in Google Chrome prior to 145.0.7632.75 allowed a remote attacker to execute arbitrary code inside a sandbox via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/huseyinstif/CVE-2026-2441-PoC](https://github.com/huseyinstif/CVE-2026-2441-PoC) :  ![starts](https://img.shields.io/github/stars/huseyinstif/CVE-2026-2441-PoC.svg) ![forks](https://img.shields.io/github/forks/huseyinstif/CVE-2026-2441-PoC.svg)
- [https://github.com/jermaine22sei/CVE-2026-2441](https://github.com/jermaine22sei/CVE-2026-2441) :  ![starts](https://img.shields.io/github/stars/jermaine22sei/CVE-2026-2441.svg) ![forks](https://img.shields.io/github/forks/jermaine22sei/CVE-2026-2441.svg)


## CVE-2026-1731
 BeyondTrust Remote Support (RS) and certain older versions of Privileged Remote Access (PRA) contain a critical pre-authentication remote code execution vulnerability. By sending specially crafted requests, an unauthenticated remote attacker may be able to execute operating system commands in the context of the site user.

- [https://github.com/jakubie07/CVE-2026-1731](https://github.com/jakubie07/CVE-2026-1731) :  ![starts](https://img.shields.io/github/stars/jakubie07/CVE-2026-1731.svg) ![forks](https://img.shields.io/github/forks/jakubie07/CVE-2026-1731.svg)


## CVE-2026-0915
 Calling getnetbyaddr or getnetbyaddr_r with a configured nsswitch.conf that specifies the library's DNS backend for networks and queries for a zero-valued network in the GNU C Library version 2.0 to version 2.42 can leak stack contents to the configured DNS resolver.

- [https://github.com/cyberwulfy200-dev/CVE-2026-0915-json-Patch.-V2.0](https://github.com/cyberwulfy200-dev/CVE-2026-0915-json-Patch.-V2.0) :  ![starts](https://img.shields.io/github/stars/cyberwulfy200-dev/CVE-2026-0915-json-Patch.-V2.0.svg) ![forks](https://img.shields.io/github/forks/cyberwulfy200-dev/CVE-2026-0915-json-Patch.-V2.0.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-alias](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-alias) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-alias.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-alias.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-zero-installs](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-zero-installs) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-zero-installs.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-zero-installs.svg)


## CVE-2025-65791
 ZoneMinder v1.36.34 is vulnerable to Command Injection in web/views/image.php. The application passes unsanitized user input directly to the exec() function.

- [https://github.com/rishavand1/CVE-2025-65791](https://github.com/rishavand1/CVE-2025-65791) :  ![starts](https://img.shields.io/github/stars/rishavand1/CVE-2025-65791.svg) ![forks](https://img.shields.io/github/forks/rishavand1/CVE-2025-65791.svg)


## CVE-2025-59287
 Deserialization of untrusted data in Windows Server Update Service allows an unauthorized attacker to execute code over a network.

- [https://github.com/ross-ns/WSUS-CVE-2025-59287](https://github.com/ross-ns/WSUS-CVE-2025-59287) :  ![starts](https://img.shields.io/github/stars/ross-ns/WSUS-CVE-2025-59287.svg) ![forks](https://img.shields.io/github/forks/ross-ns/WSUS-CVE-2025-59287.svg)


## CVE-2025-55752
Users are recommended to upgrade to version 11.0.11 or later, 10.1.45 or later or 9.0.109 or later, which fix the issue.

- [https://github.com/Jimmy01240397/CVE-2025-55752](https://github.com/Jimmy01240397/CVE-2025-55752) :  ![starts](https://img.shields.io/github/stars/Jimmy01240397/CVE-2025-55752.svg) ![forks](https://img.shields.io/github/forks/Jimmy01240397/CVE-2025-55752.svg)


## CVE-2025-47812
 In Wing FTP Server before 7.4.4. the user and admin web interfaces mishandle '\0' bytes, ultimately allowing injection of arbitrary Lua code into user session files. This can be used to execute arbitrary system commands with the privileges of the FTP service (root or SYSTEM by default). This is thus a remote code execution vulnerability that guarantees a total server compromise. This is also exploitable via anonymous FTP accounts.

- [https://github.com/shadowgit30/CVE-2025-47812](https://github.com/shadowgit30/CVE-2025-47812) :  ![starts](https://img.shields.io/github/stars/shadowgit30/CVE-2025-47812.svg) ![forks](https://img.shields.io/github/forks/shadowgit30/CVE-2025-47812.svg)
- [https://github.com/Nara-sakurai/CVE-2025-47812-PoC](https://github.com/Nara-sakurai/CVE-2025-47812-PoC) :  ![starts](https://img.shields.io/github/stars/Nara-sakurai/CVE-2025-47812-PoC.svg) ![forks](https://img.shields.io/github/forks/Nara-sakurai/CVE-2025-47812-PoC.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/0xb1lal/CVE-2025-29927](https://github.com/0xb1lal/CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/0xb1lal/CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/0xb1lal/CVE-2025-29927.svg)
- [https://github.com/rgvillanueva28/vulnbox-easy-CVE-2025-29927](https://github.com/rgvillanueva28/vulnbox-easy-CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/rgvillanueva28/vulnbox-easy-CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/rgvillanueva28/vulnbox-easy-CVE-2025-29927.svg)


## CVE-2025-4517
Note that none of these vulnerabilities significantly affect the installation of source distributions which are tar archives as source distributions already allow arbitrary code execution during the build process. However when evaluating source distributions it's important to avoid installing source distributions with suspicious links.

- [https://github.com/bgutowski/CVE-2025-4517-POC-Sudoers](https://github.com/bgutowski/CVE-2025-4517-POC-Sudoers) :  ![starts](https://img.shields.io/github/stars/bgutowski/CVE-2025-4517-POC-Sudoers.svg) ![forks](https://img.shields.io/github/forks/bgutowski/CVE-2025-4517-POC-Sudoers.svg)
- [https://github.com/ben-slates/CVE-2025-4517-POC-HTB-WINGDATA](https://github.com/ben-slates/CVE-2025-4517-POC-HTB-WINGDATA) :  ![starts](https://img.shields.io/github/stars/ben-slates/CVE-2025-4517-POC-HTB-WINGDATA.svg) ![forks](https://img.shields.io/github/forks/ben-slates/CVE-2025-4517-POC-HTB-WINGDATA.svg)


## CVE-2025-2563
 The User Registration & Membership  WordPress plugin before 4.1.2 does not prevent users to set their account role when the Membership Addon is enabled, leading to a privilege escalation issue and allowing unauthenticated users to gain admin privileges

- [https://github.com/0axz-tools/CVE-2025-2563-POC](https://github.com/0axz-tools/CVE-2025-2563-POC) :  ![starts](https://img.shields.io/github/stars/0axz-tools/CVE-2025-2563-POC.svg) ![forks](https://img.shields.io/github/forks/0axz-tools/CVE-2025-2563-POC.svg)


## CVE-2024-25600
 Improper Control of Generation of Code ('Code Injection') vulnerability in Codeer Limited Bricks Builder allows Code Injection.This issue affects Bricks Builder: from n/a through 1.9.6.

- [https://github.com/estebanzarate/CVE-2024-25600-WordPress-Bricks-Builder-RCE-PoC](https://github.com/estebanzarate/CVE-2024-25600-WordPress-Bricks-Builder-RCE-PoC) :  ![starts](https://img.shields.io/github/stars/estebanzarate/CVE-2024-25600-WordPress-Bricks-Builder-RCE-PoC.svg) ![forks](https://img.shields.io/github/forks/estebanzarate/CVE-2024-25600-WordPress-Bricks-Builder-RCE-PoC.svg)


## CVE-2024-4041
 The Yoast SEO plugin for WordPress is vulnerable to Reflected Cross-Site Scripting via URLs in all versions up to, and including, 22.5 due to insufficient input sanitization and output escaping. This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that execute if they can successfully trick a user into performing an action such as clicking on a link.

- [https://github.com/RandomRobbieBF/CVE-2024-4041](https://github.com/RandomRobbieBF/CVE-2024-4041) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-4041.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-4041.svg)


## CVE-2022-41840
 Unauth. Directory Traversal vulnerability in Welcart eCommerce plugin = 2.7.7 on WordPress.

- [https://github.com/PrinceAikinsBaidoo/CVE-2022-41840-PoC](https://github.com/PrinceAikinsBaidoo/CVE-2022-41840-PoC) :  ![starts](https://img.shields.io/github/stars/PrinceAikinsBaidoo/CVE-2022-41840-PoC.svg) ![forks](https://img.shields.io/github/forks/PrinceAikinsBaidoo/CVE-2022-41840-PoC.svg)


## CVE-2022-29599
 In Apache Maven maven-shared-utils prior to version 3.3.3, the Commandline class can emit double-quoted strings without proper escaping, allowing shell injection attacks.

- [https://github.com/andikahilmy/CVE-2022-29599-maven-shared-utils-vulnerable](https://github.com/andikahilmy/CVE-2022-29599-maven-shared-utils-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2022-29599-maven-shared-utils-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2022-29599-maven-shared-utils-vulnerable.svg)


## CVE-2022-24521
 Windows Common Log File System Driver Elevation of Privilege Vulnerability

- [https://github.com/uname1able/CVE-2022-24521](https://github.com/uname1able/CVE-2022-24521) :  ![starts](https://img.shields.io/github/stars/uname1able/CVE-2022-24521.svg) ![forks](https://img.shields.io/github/forks/uname1able/CVE-2022-24521.svg)


## CVE-2022-23457
 ESAPI (The OWASP Enterprise Security API) is a free, open source, web application security control library. Prior to version 2.3.0.0, the default implementation of `Validator.getValidDirectoryPath(String, String, File, boolean)` may incorrectly treat the tested input string as a child of the specified parent directory. This potentially could allow control-flow bypass checks to be defeated if an attack can specify the entire string representing the 'input' path. This vulnerability is patched in release 2.3.0.0 of ESAPI. As a workaround, it is possible to write one's own implementation of the Validator interface. However, maintainers do not recommend this.

- [https://github.com/andikahilmy/CVE-2022-23457-esapi-java-legacy-vulnerable](https://github.com/andikahilmy/CVE-2022-23457-esapi-java-legacy-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2022-23457-esapi-java-legacy-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2022-23457-esapi-java-legacy-vulnerable.svg)


## CVE-2022-22980
 A Spring Data MongoDB application is vulnerable to SpEL Injection when using @Query or @Aggregation-annotated query methods with SpEL expressions that contain query parameter placeholders for value binding if the input is not sanitized.

- [https://github.com/Eliasdekiniweek/CVE-2022-22980](https://github.com/Eliasdekiniweek/CVE-2022-22980) :  ![starts](https://img.shields.io/github/stars/Eliasdekiniweek/CVE-2022-22980.svg) ![forks](https://img.shields.io/github/forks/Eliasdekiniweek/CVE-2022-22980.svg)


## CVE-2021-43859
 XStream is an open source java library to serialize objects to XML and back again. Versions prior to 1.4.19 may allow a remote attacker to allocate 100% CPU time on the target system depending on CPU type or parallel execution of such a payload resulting in a denial of service only by manipulating the processed input stream. XStream 1.4.19 monitors and accumulates the time it takes to add elements to collections and throws an exception if a set threshold is exceeded. Users are advised to upgrade as soon as possible. Users unable to upgrade may set the NO_REFERENCE mode to prevent recursion. See GHSA-rmr5-cpv2-vgjf for further details on a workaround if an upgrade is not possible.

- [https://github.com/andikahilmy/CVE-2021-43859-xstream-vulnerable](https://github.com/andikahilmy/CVE-2021-43859-xstream-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2021-43859-xstream-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2021-43859-xstream-vulnerable.svg)


## CVE-2021-35517
 When reading a specially crafted TAR archive, Compress can be made to allocate large amounts of memory that finally leads to an out of memory error even for very small inputs. This could be used to mount a denial of service attack against services that use Compress' tar package.

- [https://github.com/andikahilmy/CVE-2021-35517-commons-compress-vulnerable](https://github.com/andikahilmy/CVE-2021-35517-commons-compress-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2021-35517-commons-compress-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2021-35517-commons-compress-vulnerable.svg)


## CVE-2021-35516
 When reading a specially crafted 7Z archive, Compress can be made to allocate large amounts of memory that finally leads to an out of memory error even for very small inputs. This could be used to mount a denial of service attack against services that use Compress' sevenz package.

- [https://github.com/andikahilmy/CVE-2021-35516-commons-compress-vulnerable](https://github.com/andikahilmy/CVE-2021-35516-commons-compress-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2021-35516-commons-compress-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2021-35516-commons-compress-vulnerable.svg)


## CVE-2021-31684
 A vulnerability was discovered in the indexOf function of JSONParserByteArray in JSON Smart versions 1.3 and 2.4 which causes a denial of service (DOS) via a crafted web request.

- [https://github.com/andikahilmy/CVE-2021-31684-json-smart-v2-vulnerable](https://github.com/andikahilmy/CVE-2021-31684-json-smart-v2-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2021-31684-json-smart-v2-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2021-31684-json-smart-v2-vulnerable.svg)


## CVE-2021-21364
 swagger-codegen is an open-source project which contains a template-driven engine to generate documentation, API clients and server stubs in different languages by parsing your OpenAPI / Swagger definition. In swagger-codegen before version 2.4.19, on Unix-Like systems, the system temporary directory is shared between all local users. When files/directories are created, the default `umask` settings for the process are respected. As a result, by default, most processes/apis will create files/directories with the permissions `-rw-r--r--` and `drwxr-xr-x` respectively, unless an API that explicitly sets safe file permissions is used. Because this vulnerability impacts generated code, the generated code will remain vulnerable until fixed manually! This vulnerability is fixed in version 2.4.19. Note this is a distinct vulnerability from CVE-2021-21363.

- [https://github.com/andikahilmy/CVE-2021-21364-swagger-codegen-vulnerable](https://github.com/andikahilmy/CVE-2021-21364-swagger-codegen-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2021-21364-swagger-codegen-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2021-21364-swagger-codegen-vulnerable.svg)


## CVE-2021-20190
 A flaw was found in jackson-databind before 2.9.10.7. FasterXML mishandles the interaction between serialization gadgets and typing. The highest threat from this vulnerability is to data confidentiality and integrity as well as system availability.

- [https://github.com/andikahilmy/CVE-2021-20190-jackson-databind-vulnerable](https://github.com/andikahilmy/CVE-2021-20190-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2021-20190-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2021-20190-jackson-databind-vulnerable.svg)


## CVE-2020-36518
 jackson-databind before 2.13.0 allows a Java StackOverflow exception and denial of service via a large depth of nested objects.

- [https://github.com/andikahilmy/CVE-2020-36518-jackson-databind-vulnerable](https://github.com/andikahilmy/CVE-2020-36518-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2020-36518-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2020-36518-jackson-databind-vulnerable.svg)


## CVE-2020-36188
 FasterXML jackson-databind 2.x before 2.9.10.8 mishandles the interaction between serialization gadgets and typing, related to com.newrelic.agent.deps.ch.qos.logback.core.db.JNDIConnectionSource.

- [https://github.com/andikahilmy/CVE-2020-36188-jackson-databind-vulnerable](https://github.com/andikahilmy/CVE-2020-36188-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2020-36188-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2020-36188-jackson-databind-vulnerable.svg)


## CVE-2020-36187
 FasterXML jackson-databind 2.x before 2.9.10.8 mishandles the interaction between serialization gadgets and typing, related to org.apache.tomcat.dbcp.dbcp.datasources.SharedPoolDataSource.

- [https://github.com/andikahilmy/CVE-2020-36187-jackson-databind-vulnerable](https://github.com/andikahilmy/CVE-2020-36187-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2020-36187-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2020-36187-jackson-databind-vulnerable.svg)


## CVE-2020-36185
 FasterXML jackson-databind 2.x before 2.9.10.8 mishandles the interaction between serialization gadgets and typing, related to org.apache.tomcat.dbcp.dbcp2.datasources.SharedPoolDataSource.

- [https://github.com/andikahilmy/CVE-2020-36185-jackson-databind-vulnerable](https://github.com/andikahilmy/CVE-2020-36185-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2020-36185-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2020-36185-jackson-databind-vulnerable.svg)


## CVE-2020-36183
 FasterXML jackson-databind 2.x before 2.9.10.8 mishandles the interaction between serialization gadgets and typing, related to org.docx4j.org.apache.xalan.lib.sql.JNDIConnectionPool.

- [https://github.com/andikahilmy/CVE-2020-36183-jackson-databind-vulnerable](https://github.com/andikahilmy/CVE-2020-36183-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2020-36183-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2020-36183-jackson-databind-vulnerable.svg)


## CVE-2020-36180
 FasterXML jackson-databind 2.x before 2.9.10.8 mishandles the interaction between serialization gadgets and typing, related to org.apache.commons.dbcp2.cpdsadapter.DriverAdapterCPDS.

- [https://github.com/andikahilmy/CVE-2020-36180-jackson-databind-vulnerable](https://github.com/andikahilmy/CVE-2020-36180-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2020-36180-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2020-36180-jackson-databind-vulnerable.svg)


## CVE-2020-36179
 FasterXML jackson-databind 2.x before 2.9.10.8 mishandles the interaction between serialization gadgets and typing, related to oadd.org.apache.commons.dbcp.cpdsadapter.DriverAdapterCPDS.

- [https://github.com/andikahilmy/CVE-2020-36179-jackson-databind-vulnerable](https://github.com/andikahilmy/CVE-2020-36179-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2020-36179-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2020-36179-jackson-databind-vulnerable.svg)


## CVE-2020-35491
 FasterXML jackson-databind 2.x before 2.9.10.8 mishandles the interaction between serialization gadgets and typing, related to org.apache.commons.dbcp2.datasources.SharedPoolDataSource.

- [https://github.com/andikahilmy/CVE-2020-35491-jackson-databind-vulnerable](https://github.com/andikahilmy/CVE-2020-35491-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2020-35491-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2020-35491-jackson-databind-vulnerable.svg)


## CVE-2020-35217
 Vert.x-Web framework v4.0 milestone 1-4 does not perform a correct CSRF verification. Instead of comparing the CSRF token in the request with the CSRF token in the cookie, it compares the CSRF token in the cookie against a CSRF token that is stored in the session. An attacker does not even need to provide a CSRF token in the request because the framework does not consider it. The cookies are automatically sent by the browser and the verification will always succeed, leading to a successful CSRF attack.

- [https://github.com/andikahilmy/CVE-2020-35217-vertx-web-vulnerable](https://github.com/andikahilmy/CVE-2020-35217-vertx-web-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2020-35217-vertx-web-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2020-35217-vertx-web-vulnerable.svg)


## CVE-2020-26259
 XStream is a Java library to serialize objects to XML and back again. In XStream before version 1.4.15, is vulnerable to an Arbitrary File Deletion on the local host when unmarshalling. The vulnerability may allow a remote attacker to delete arbitrary know files on the host as log as the executing process has sufficient rights only by manipulating the processed input stream. If you rely on XStream's default blacklist of the Security Framework, you will have to use at least version 1.4.15. The reported vulnerability does not exist running Java 15 or higher. No user is affected, who followed the recommendation to setup XStream's Security Framework with a whitelist! Anyone relying on XStream's default blacklist can immediately switch to a whilelist for the allowed types to avoid the vulnerability. Users of XStream 1.4.14 or below who still want to use XStream default blacklist can use a workaround described in more detailed in the referenced advisories.

- [https://github.com/andikahilmy/CVE-2020-26259-xstream-vulnerable](https://github.com/andikahilmy/CVE-2020-26259-xstream-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2020-26259-xstream-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2020-26259-xstream-vulnerable.svg)


## CVE-2020-26258
 XStream is a Java library to serialize objects to XML and back again. In XStream before version 1.4.15, a Server-Side Forgery Request vulnerability can be activated when unmarshalling. The vulnerability may allow a remote attacker to request data from internal resources that are not publicly available only by manipulating the processed input stream. If you rely on XStream's default blacklist of the Security Framework, you will have to use at least version 1.4.15. The reported vulnerability does not exist if running Java 15 or higher. No user is affected who followed the recommendation to setup XStream's Security Framework with a whitelist! Anyone relying on XStream's default blacklist can immediately switch to a whilelist for the allowed types to avoid the vulnerability. Users of XStream 1.4.14 or below who still want to use XStream default blacklist can use a workaround described in more detailed in the referenced advisories.

- [https://github.com/andikahilmy/CVE-2020-26258-xstream-vulnerable](https://github.com/andikahilmy/CVE-2020-26258-xstream-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2020-26258-xstream-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2020-26258-xstream-vulnerable.svg)


## CVE-2020-24616
 FasterXML jackson-databind 2.x before 2.9.10.6 mishandles the interaction between serialization gadgets and typing, related to br.com.anteros.dbcp.AnterosDBCPDataSource (aka Anteros-DBCP).

- [https://github.com/andikahilmy/CVE-2020-24616-jackson-databind-vulnerable](https://github.com/andikahilmy/CVE-2020-24616-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2020-24616-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2020-24616-jackson-databind-vulnerable.svg)


## CVE-2020-15250
 In JUnit4 from version 4.7 and before 4.13.1, the test rule TemporaryFolder contains a local information disclosure vulnerability. On Unix like systems, the system's temporary directory is shared between all users on that system. Because of this, when files and directories are written into this directory they are, by default, readable by other users on that same system. This vulnerability does not allow other users to overwrite the contents of these directories or files. This is purely an information disclosure vulnerability. This vulnerability impacts you if the JUnit tests write sensitive information, like API keys or passwords, into the temporary folder, and the JUnit tests execute in an environment where the OS has other untrusted users. Because certain JDK file system APIs were only added in JDK 1.7, this this fix is dependent upon the version of the JDK you are using. For Java 1.7 and higher users: this vulnerability is fixed in 4.13.1. For Java 1.6 and lower users: no patch is available, you must use the workaround below. If you are unable to patch, or are stuck running on Java 1.6, specifying the `java.io.tmpdir` system environment variable to a directory that is exclusively owned by the executing user will fix this vulnerability. For more information, including an example of vulnerable code, see the referenced GitHub Security Advisory.

- [https://github.com/andikahilmy/CVE-2020-15250-junit4-vulnerable](https://github.com/andikahilmy/CVE-2020-15250-junit4-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2020-15250-junit4-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2020-15250-junit4-vulnerable.svg)


## CVE-2020-14060
 FasterXML jackson-databind 2.x before 2.9.10.5 mishandles the interaction between serialization gadgets and typing, related to oadd.org.apache.xalan.lib.sql.JNDIConnectionPool (aka apache/drill).

- [https://github.com/andikahilmy/CVE-2020-14060-jackson-databind-vulnerable](https://github.com/andikahilmy/CVE-2020-14060-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2020-14060-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2020-14060-jackson-databind-vulnerable.svg)


## CVE-2020-13959
 The default error page for VelocityView in Apache Velocity Tools prior to 3.1 reflects back the vm file that was entered as part of the URL. An attacker can set an XSS payload file as this vm file in the URL which results in this payload being executed. XSS vulnerabilities allow attackers to execute arbitrary JavaScript in the context of the attacked website and the attacked user. This can be abused to steal session cookies, perform requests in the name of the victim or for phishing attacks.

- [https://github.com/andikahilmy/CVE-2020-13959-velocity-tools-vulnerable](https://github.com/andikahilmy/CVE-2020-13959-velocity-tools-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2020-13959-velocity-tools-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2020-13959-velocity-tools-vulnerable.svg)


## CVE-2020-11620
 FasterXML jackson-databind 2.x before 2.9.10.4 mishandles the interaction between serialization gadgets and typing, related to org.apache.commons.jelly.impl.Embedded (aka commons-jelly).

- [https://github.com/andikahilmy/CVE-2020-11620-jackson-databind-vulnerable](https://github.com/andikahilmy/CVE-2020-11620-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2020-11620-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2020-11620-jackson-databind-vulnerable.svg)


## CVE-2020-11112
 FasterXML jackson-databind 2.x before 2.9.10.4 mishandles the interaction between serialization gadgets and typing, related to org.apache.commons.proxy.provider.remoting.RmiProvider (aka apache/commons-proxy).

- [https://github.com/andikahilmy/CVE-2020-11112-jackson-databind-vulnerable](https://github.com/andikahilmy/CVE-2020-11112-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2020-11112-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2020-11112-jackson-databind-vulnerable.svg)


## CVE-2020-10969
 FasterXML jackson-databind 2.x before 2.9.10.4 mishandles the interaction between serialization gadgets and typing, related to javax.swing.JEditorPane.

- [https://github.com/andikahilmy/CVE-2020-10969-jackson-databind-vulnerable](https://github.com/andikahilmy/CVE-2020-10969-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2020-10969-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2020-10969-jackson-databind-vulnerable.svg)


## CVE-2020-9547
 FasterXML jackson-databind 2.x before 2.9.10.4 mishandles the interaction between serialization gadgets and typing, related to com.ibatis.sqlmap.engine.transaction.jta.JtaTransactionConfig (aka ibatis-sqlmap).

- [https://github.com/andikahilmy/CVE-2020-9547-jackson-databind-vulnerable](https://github.com/andikahilmy/CVE-2020-9547-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2020-9547-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2020-9547-jackson-databind-vulnerable.svg)


## CVE-2020-8840
 FasterXML jackson-databind 2.0.0 through 2.9.10.2 lacks certain xbean-reflect/JNDI blocking, as demonstrated by org.apache.xbean.propertyeditor.JndiConverter.

- [https://github.com/andikahilmy/CVE-2020-8840-jackson-databind-vulnerable](https://github.com/andikahilmy/CVE-2020-8840-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2020-8840-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2020-8840-jackson-databind-vulnerable.svg)


## CVE-2020-0688
 A remote code execution vulnerability exists in Microsoft Exchange software when the software fails to properly handle objects in memory, aka 'Microsoft Exchange Memory Corruption Vulnerability'.

- [https://github.com/iamwajd/Cyber-Attack-Analysis](https://github.com/iamwajd/Cyber-Attack-Analysis) :  ![starts](https://img.shields.io/github/stars/iamwajd/Cyber-Attack-Analysis.svg) ![forks](https://img.shields.io/github/forks/iamwajd/Cyber-Attack-Analysis.svg)


## CVE-2019-1003000
 A sandbox bypass vulnerability exists in Script Security Plugin 1.49 and earlier in src/main/java/org/jenkinsci/plugins/scriptsecurity/sandbox/groovy/GroovySandbox.java that allows attackers with the ability to provide sandboxed scripts to execute arbitrary code on the Jenkins master JVM.

- [https://github.com/andikahilmy/CVE-2019-1003000-script-security-plugin-vulnerable](https://github.com/andikahilmy/CVE-2019-1003000-script-security-plugin-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2019-1003000-script-security-plugin-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2019-1003000-script-security-plugin-vulnerable.svg)


## CVE-2019-20330
 FasterXML jackson-databind 2.x before 2.9.10.2 lacks certain net.sf.ehcache blocking.

- [https://github.com/andikahilmy/CVE-2019-20330-jackson-databind-vulnerable](https://github.com/andikahilmy/CVE-2019-20330-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2019-20330-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2019-20330-jackson-databind-vulnerable.svg)


## CVE-2019-18394
 A Server Side Request Forgery (SSRF) vulnerability in FaviconServlet.java in Ignite Realtime Openfire through 4.4.2 allows attackers to send arbitrary HTTP GET requests.

- [https://github.com/andikahilmy/CVE-2019-18394-Openfire-vulnerable](https://github.com/andikahilmy/CVE-2019-18394-Openfire-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2019-18394-Openfire-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2019-18394-Openfire-vulnerable.svg)


## CVE-2019-17267
 A Polymorphic Typing issue was discovered in FasterXML jackson-databind before 2.9.10. It is related to net.sf.ehcache.hibernate.EhcacheJtaTransactionManagerLookup.

- [https://github.com/andikahilmy/CVE-2019-17267-jackson-databind-vulnerable](https://github.com/andikahilmy/CVE-2019-17267-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2019-17267-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2019-17267-jackson-databind-vulnerable.svg)


## CVE-2019-16335
 A Polymorphic Typing issue was discovered in FasterXML jackson-databind before 2.9.10. It is related to com.zaxxer.hikari.HikariDataSource. This is a different vulnerability than CVE-2019-14540.

- [https://github.com/andikahilmy/CVE-2019-16335-jackson-databind-vulnerable](https://github.com/andikahilmy/CVE-2019-16335-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2019-16335-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2019-16335-jackson-databind-vulnerable.svg)


## CVE-2019-14892
 A flaw was discovered in jackson-databind in versions before 2.9.10, 2.8.11.5 and 2.6.7.3, where it would permit polymorphic deserialization of a malicious object using commons-configuration 1 and 2 JNDI classes. An attacker could use this flaw to execute arbitrary code.

- [https://github.com/andikahilmy/CVE-2019-14892-jackson-databind-vulnerable](https://github.com/andikahilmy/CVE-2019-14892-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2019-14892-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2019-14892-jackson-databind-vulnerable.svg)


## CVE-2019-12402
 The file name encoding algorithm used internally in Apache Commons Compress 1.15 to 1.18 can get into an infinite loop when faced with specially crafted inputs. This can lead to a denial of service attack if an attacker can choose the file names inside of an archive created by Compress.

- [https://github.com/andikahilmy/CVE-2019-12402-commons-compress-vulnerable](https://github.com/andikahilmy/CVE-2019-12402-commons-compress-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2019-12402-commons-compress-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2019-12402-commons-compress-vulnerable.svg)


## CVE-2019-10219
 A vulnerability was found in Hibernate-Validator. The SafeHtml validator annotation fails to properly sanitize payloads consisting of potentially malicious code in HTML comments and instructions. This vulnerability can result in an XSS attack.

- [https://github.com/andikahilmy/CVE-2019-10219-hibernate-validator-vulnerable](https://github.com/andikahilmy/CVE-2019-10219-hibernate-validator-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2019-10219-hibernate-validator-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2019-10219-hibernate-validator-vulnerable.svg)


## CVE-2019-9194
 elFinder before 2.1.48 has a command injection vulnerability in the PHP connector.

- [https://github.com/estebanzarate/CVE-2019-9194-elFinder-Command-Injection-PoC](https://github.com/estebanzarate/CVE-2019-9194-elFinder-Command-Injection-PoC) :  ![starts](https://img.shields.io/github/stars/estebanzarate/CVE-2019-9194-elFinder-Command-Injection-PoC.svg) ![forks](https://img.shields.io/github/forks/estebanzarate/CVE-2019-9194-elFinder-Command-Injection-PoC.svg)


## CVE-2019-7609
 Kibana versions before 5.6.15 and 6.6.1 contain an arbitrary code execution flaw in the Timelion visualizer. An attacker with access to the Timelion application could send a request that will attempt to execute javascript code. This could possibly lead to an attacker executing arbitrary commands with permissions of the Kibana process on the host system.

- [https://github.com/toxaker/CVE-2019-7609](https://github.com/toxaker/CVE-2019-7609) :  ![starts](https://img.shields.io/github/stars/toxaker/CVE-2019-7609.svg) ![forks](https://img.shields.io/github/forks/toxaker/CVE-2019-7609.svg)


## CVE-2019-0201
 An issue is present in Apache ZooKeeper 1.0.0 to 3.4.13 and 3.5.0-alpha to 3.5.4-beta. ZooKeeper’s getACL() command doesn’t check any permission when retrieves the ACLs of the requested node and returns all information contained in the ACL Id field as plaintext string. DigestAuthenticationProvider overloads the Id field with the hash value that is used for user authentication. As a consequence, if Digest Authentication is in use, the unsalted hash value will be disclosed by getACL() request for unauthenticated or unprivileged users.

- [https://github.com/andikahilmy/CVE-2019-0201-zookeeper-vulnerable](https://github.com/andikahilmy/CVE-2019-0201-zookeeper-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2019-0201-zookeeper-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2019-0201-zookeeper-vulnerable.svg)


## CVE-2018-1002200
 plexus-archiver before 3.6.0 is vulnerable to directory traversal, allowing attackers to write to arbitrary files via a ../ (dot dot slash) in an archive entry that is mishandled during extraction. This vulnerability is also known as 'Zip-Slip'.

- [https://github.com/andikahilmy/CVE-2018-1002200-plexus-archiver-vulnerable](https://github.com/andikahilmy/CVE-2018-1002200-plexus-archiver-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2018-1002200-plexus-archiver-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2018-1002200-plexus-archiver-vulnerable.svg)


## CVE-2018-1000873
 Fasterxml Jackson version Before 2.9.8 contains a CWE-20: Improper Input Validation vulnerability in Jackson-Modules-Java8 that can result in Causes a denial-of-service (DoS). This attack appear to be exploitable via The victim deserializes malicious input, specifically very large values in the nanoseconds field of a time value. This vulnerability appears to have been fixed in 2.9.8.

- [https://github.com/andikahilmy/CVE-2018-1000873-jackson-modules-java8-vulnerable](https://github.com/andikahilmy/CVE-2018-1000873-jackson-modules-java8-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2018-1000873-jackson-modules-java8-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2018-1000873-jackson-modules-java8-vulnerable.svg)


## CVE-2018-1000822
 codelibs fess version before commit faa265b contains a XML External Entity (XXE) vulnerability in GSA XML file parser that can result in Disclosure of confidential data, denial of service, SSRF, port scanning. This attack appear to be exploitable via specially crafted GSA XML files. This vulnerability appears to have been fixed in after commit faa265b.

- [https://github.com/andikahilmy/CVE-2018-1000822-fess-vulnerable](https://github.com/andikahilmy/CVE-2018-1000822-fess-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2018-1000822-fess-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2018-1000822-fess-vulnerable.svg)


## CVE-2018-19361
 FasterXML jackson-databind 2.x before 2.9.8 might allow attackers to have unspecified impact by leveraging failure to block the openjpa class from polymorphic deserialization.

- [https://github.com/andikahilmy/CVE-2018-19361-jackson-databind-vulnerable](https://github.com/andikahilmy/CVE-2018-19361-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2018-19361-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2018-19361-jackson-databind-vulnerable.svg)


## CVE-2018-17187
 The Apache Qpid Proton-J transport includes an optional wrapper layer to perform TLS, enabled by use of the 'transport.ssl(...)' methods. Unless a verification mode was explicitly configured, client and server modes previously defaulted as documented to not verifying a peer certificate, with options to configure this explicitly or select a certificate verification mode with or without hostname verification being performed. The latter hostname verifying mode was not implemented in Apache Qpid Proton-J versions 0.3 to 0.29.0, with attempts to use it resulting in an exception. This left only the option to verify the certificate is trusted, leaving such a client vulnerable to Man In The Middle (MITM) attack. Uses of the Proton-J protocol engine which do not utilise the optional transport TLS wrapper are not impacted, e.g. usage within Qpid JMS. Uses of Proton-J utilising the optional transport TLS wrapper layer that wish to enable hostname verification must be upgraded to version 0.30.0 or later and utilise the VerifyMode#VERIFY_PEER_NAME configuration, which is now the default for client mode usage unless configured otherwise.

- [https://github.com/andikahilmy/CVE-2018-17187-qpid-proton-j-vulnerable](https://github.com/andikahilmy/CVE-2018-17187-qpid-proton-j-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2018-17187-qpid-proton-j-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2018-17187-qpid-proton-j-vulnerable.svg)


## CVE-2018-12544
 In version from 3.5.Beta1 to 3.5.3 of Eclipse Vert.x, the OpenAPI XML type validator creates XML parsers without taking appropriate defense against XML attacks. This mechanism is exclusively when the developer uses the Eclipse Vert.x OpenAPI XML type validator to validate a provided schema.

- [https://github.com/andikahilmy/CVE-2018-12544-vertx-web-vulnerable](https://github.com/andikahilmy/CVE-2018-12544-vertx-web-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2018-12544-vertx-web-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2018-12544-vertx-web-vulnerable.svg)


## CVE-2018-12541
 In version from 3.0.0 to 3.5.3 of Eclipse Vert.x, the WebSocket HTTP upgrade implementation buffers the full http request before doing the handshake, holding the entire request body in memory. There should be a reasonnable limit (8192 bytes) above which the WebSocket gets an HTTP response with the 413 status code and the connection gets closed.

- [https://github.com/andikahilmy/CVE-2018-12541-vert.x-vulnerable](https://github.com/andikahilmy/CVE-2018-12541-vert.x-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2018-12541-vert.x-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2018-12541-vert.x-vulnerable.svg)


## CVE-2018-12537
 In Eclipse Vert.x version 3.0 to 3.5.1, the HttpServer response headers and HttpClient request headers do not filter carriage return and line feed characters from the header value. This allow unfiltered values to inject a new header in the client request or server response.

- [https://github.com/andikahilmy/CVE-2018-12537-vert.x-vulnerable](https://github.com/andikahilmy/CVE-2018-12537-vert.x-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2018-12537-vert.x-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2018-12537-vert.x-vulnerable.svg)


## CVE-2018-7489
 FasterXML jackson-databind before 2.7.9.3, 2.8.x before 2.8.11.1 and 2.9.x before 2.9.5 allows unauthenticated remote code execution because of an incomplete fix for the CVE-2017-7525 deserialization flaw. This is exploitable by sending maliciously crafted JSON input to the readValue method of the ObjectMapper, bypassing a blacklist that is ineffective if the c3p0 libraries are available in the classpath.

- [https://github.com/andikahilmy/CVE-2018-7489-jackson-databind-vulnerable](https://github.com/andikahilmy/CVE-2018-7489-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2018-7489-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2018-7489-jackson-databind-vulnerable.svg)


## CVE-2018-1337
 In Apache Directory LDAP API before 1.0.2, a bug in the way the SSL Filter was setup made it possible for another thread to use the connection before the TLS layer has been established, if the connection has already been used and put back in a pool of connections, leading to leaking any information contained in this request (including the credentials when sending a BIND request).

- [https://github.com/andikahilmy/CVE-2018-1337-directory-ldap-api-vulnerable](https://github.com/andikahilmy/CVE-2018-1337-directory-ldap-api-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2018-1337-directory-ldap-api-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2018-1337-directory-ldap-api-vulnerable.svg)


## CVE-2017-2666
 It was discovered in Undertow that the code that parsed the HTTP request line permitted invalid characters. This could be exploited, in conjunction with a proxy that also permitted the invalid characters but with a different interpretation, to inject data into the HTTP response. By manipulating the HTTP response the attacker could poison a web-cache, perform an XSS attack, or obtain sensitive information from requests other than their own.

- [https://github.com/andikahilmy/CVE-2017-2666-undertow-vulnerable](https://github.com/andikahilmy/CVE-2017-2666-undertow-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2017-2666-undertow-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2017-2666-undertow-vulnerable.svg)


## CVE-2016-4437
 Apache Shiro before 1.2.5, when a cipher key has not been configured for the "remember me" feature, allows remote attackers to execute arbitrary code or bypass intended access restrictions via an unspecified request parameter.

- [https://github.com/35789-gh/cve-2016-4437](https://github.com/35789-gh/cve-2016-4437) :  ![starts](https://img.shields.io/github/stars/35789-gh/cve-2016-4437.svg) ![forks](https://img.shields.io/github/forks/35789-gh/cve-2016-4437.svg)


## CVE-2013-6465
 Multiple cross-site scripting (XSS) vulnerabilities in JBPM KIE Workbench 6.0.x allow remote authenticated users to inject arbitrary web script or HTML via vectors related to task name html inputs.

- [https://github.com/andikahilmy/CVE-2013-6465-jjbpm-wbbpm-vulnerable](https://github.com/andikahilmy/CVE-2013-6465-jjbpm-wbbpm-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2013-6465-jjbpm-wbbpm-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2013-6465-jjbpm-wbbpm-vulnerable.svg)


## CVE-2013-5960
 The authenticated-encryption feature in the symmetric-encryption implementation in the OWASP Enterprise Security API (ESAPI) for Java 2.x before 2.1.0.1 does not properly resist tampering with serialized ciphertext, which makes it easier for remote attackers to bypass intended cryptographic protection mechanisms via an attack against the intended cipher mode in a non-default configuration, a different vulnerability than CVE-2013-5679.

- [https://github.com/andikahilmy/CVE-2013-5960-esapi-java-legacy-vulnerable](https://github.com/andikahilmy/CVE-2013-5960-esapi-java-legacy-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2013-5960-esapi-java-legacy-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2013-5960-esapi-java-legacy-vulnerable.svg)


## CVE-2013-5679
 The authenticated-encryption feature in the symmetric-encryption implementation in the OWASP Enterprise Security API (ESAPI) for Java 2.x before 2.1.0 does not properly resist tampering with serialized ciphertext, which makes it easier for remote attackers to bypass intended cryptographic protection mechanisms via an attack against authenticity in the default configuration, involving a null MAC and a zero MAC length.

- [https://github.com/andikahilmy/CVE-2013-5679-esapi-java-legacy-vulnerable](https://github.com/andikahilmy/CVE-2013-5679-esapi-java-legacy-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2013-5679-esapi-java-legacy-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2013-5679-esapi-java-legacy-vulnerable.svg)


## CVE-2013-4517
 Apache Santuario XML Security for Java before 1.5.6, when applying Transforms, allows remote attackers to cause a denial of service (memory consumption) via crafted Document Type Definitions (DTDs), related to signatures.

- [https://github.com/andikahilmy/CVE-2013-4517-santuario-java-vulnerable](https://github.com/andikahilmy/CVE-2013-4517-santuario-java-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2013-4517-santuario-java-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2013-4517-santuario-java-vulnerable.svg)


## CVE-2013-2186
 The DiskFileItem class in Apache Commons FileUpload, as used in Red Hat JBoss BRMS 5.3.1; JBoss Portal 4.3 CP07, 5.2.2, and 6.0.0; and Red Hat JBoss Web Server 1.0.2 allows remote attackers to write to arbitrary files via a NULL byte in a file name in a serialized instance.

- [https://github.com/andikahilmy/CVE-2013-2186-commons-fileupload-vulnerable](https://github.com/andikahilmy/CVE-2013-2186-commons-fileupload-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2013-2186-commons-fileupload-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2013-2186-commons-fileupload-vulnerable.svg)


## CVE-2013-2172
 jcp/xml/dsig/internal/dom/DOMCanonicalizationMethod.java in Apache Santuario XML Security for Java 1.4.x before 1.4.8 and 1.5.x before 1.5.5 allows context-dependent attackers to spoof an XML Signature by using the CanonicalizationMethod parameter to specify an arbitrary weak "canonicalization algorithm to apply to the SignedInfo part of the Signature."

- [https://github.com/andikahilmy/CVE-2013-2172-santuario-java-vulnerable](https://github.com/andikahilmy/CVE-2013-2172-santuario-java-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2013-2172-santuario-java-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2013-2172-santuario-java-vulnerable.svg)


## CVE-2011-4367
 Multiple directory traversal vulnerabilities in MyFaces JavaServer Faces (JSF) in Apache MyFaces Core 2.0.x before 2.0.12 and 2.1.x before 2.1.6 allow remote attackers to read arbitrary files via a .. (dot dot) in the (1) ln parameter to faces/javax.faces.resource/web.xml or (2) the PATH_INFO to faces/javax.faces.resource/.

- [https://github.com/andikahilmy/CVE-2011-4367-myfaces-vulnerable](https://github.com/andikahilmy/CVE-2011-4367-myfaces-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2011-4367-myfaces-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2011-4367-myfaces-vulnerable.svg)

