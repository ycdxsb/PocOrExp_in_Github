# Update 2026-01-03
## CVE-2026-21437
 eopkg is a Solus package manager implemented in python3. In versions prior to 4.4.0, a malicious package could include files that are not tracked by `eopkg`. This requires the installation of a package from a malicious or compromised source. Files in such packages would not be shown by `lseopkg` and related tools. The issue has been fixed in v4.4.0. Users only installing packages from the Solus repositories are not affected.

- [https://github.com/osmancanvural/CVE-2026-21437](https://github.com/osmancanvural/CVE-2026-21437) :  ![starts](https://img.shields.io/github/stars/osmancanvural/CVE-2026-21437.svg) ![forks](https://img.shields.io/github/forks/osmancanvural/CVE-2026-21437.svg)


## CVE-2025-68645
 A Local File Inclusion (LFI) vulnerability exists in the Webmail Classic UI of Zimbra Collaboration (ZCS) 10.0 and 10.1 because of improper handling of user-supplied request parameters in the RestFilter servlet. An unauthenticated remote attacker can craft requests to the /h/rest endpoint to influence internal request dispatching, allowing inclusion of arbitrary files from the WebRoot directory.

- [https://github.com/MaxMnMl/zimbramail-CVE-2025-68645-poc](https://github.com/MaxMnMl/zimbramail-CVE-2025-68645-poc) :  ![starts](https://img.shields.io/github/stars/MaxMnMl/zimbramail-CVE-2025-68645-poc.svg) ![forks](https://img.shields.io/github/forks/MaxMnMl/zimbramail-CVE-2025-68645-poc.svg)


## CVE-2025-67730
 Frappe Learning Management System (LMS) is a learning system that helps users structure their content. Versions prior to 2.42.0 allow authenticated users to add malicious HTML and JavaScript through description fields in the Job, Course and Batch forms. This issue is fixed in version 2.42.0.

- [https://github.com/Dharan10/CVE-2025-67730](https://github.com/Dharan10/CVE-2025-67730) :  ![starts](https://img.shields.io/github/stars/Dharan10/CVE-2025-67730.svg) ![forks](https://img.shields.io/github/forks/Dharan10/CVE-2025-67730.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-berry](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-berry) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-berry.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-berry.svg)


## CVE-2025-54068
 Livewire is a full-stack framework for Laravel. In Livewire v3 up to and including v3.6.3, a vulnerability allows unauthenticated attackers to achieve remote command execution in specific scenarios. The issue stems from how certain component property updates are hydrated. This vulnerability is unique to Livewire v3 and does not affect prior major versions. Exploitation requires a component to be mounted and configured in a particular way, but does not require authentication or user interaction. This issue has been patched in Livewire v3.6.4. All users are strongly encouraged to upgrade to this version or later as soon as possible. No known workarounds are available.

- [https://github.com/z0d131482700x/Livewire2025CVE](https://github.com/z0d131482700x/Livewire2025CVE) :  ![starts](https://img.shields.io/github/stars/z0d131482700x/Livewire2025CVE.svg) ![forks](https://img.shields.io/github/forks/z0d131482700x/Livewire2025CVE.svg)


## CVE-2025-48769
Users of virtual filesystem based services with write access especially when exposed over the network (i.e. FTP) are affected and recommended to upgrade to version 12.11.0 that fixes the issue.

- [https://github.com/b1gchoi/CVE-2025-48769](https://github.com/b1gchoi/CVE-2025-48769) :  ![starts](https://img.shields.io/github/stars/b1gchoi/CVE-2025-48769.svg) ![forks](https://img.shields.io/github/forks/b1gchoi/CVE-2025-48769.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/KaztoRay/CVE-2025-29927-Research](https://github.com/KaztoRay/CVE-2025-29927-Research) :  ![starts](https://img.shields.io/github/stars/KaztoRay/CVE-2025-29927-Research.svg) ![forks](https://img.shields.io/github/forks/KaztoRay/CVE-2025-29927-Research.svg)


## CVE-2025-15406
 A flaw has been found in PHPGurukul Online Course Registration up to 3.1. This affects an unknown function. This manipulation causes missing authorization. Remote exploitation of the attack is possible. The exploit has been published and may be used.

- [https://github.com/rsecroot/CVE-2025-15406](https://github.com/rsecroot/CVE-2025-15406) :  ![starts](https://img.shields.io/github/stars/rsecroot/CVE-2025-15406.svg) ![forks](https://img.shields.io/github/forks/rsecroot/CVE-2025-15406.svg)


## CVE-2025-15390
 A security flaw has been discovered in PHPGurukul Small CRM 4.0. This impacts an unknown function of the file /admin/edit-user.php. The manipulation results in missing authorization. It is possible to launch the attack remotely. The exploit has been released to the public and may be exploited.

- [https://github.com/rsecroot/CVE-2025-15390](https://github.com/rsecroot/CVE-2025-15390) :  ![starts](https://img.shields.io/github/stars/rsecroot/CVE-2025-15390.svg) ![forks](https://img.shields.io/github/forks/rsecroot/CVE-2025-15390.svg)


## CVE-2025-14847
 Mismatched length fields in Zlib compressed protocol headers may allow a read of uninitialized heap memory by an unauthenticated client. This issue affects all MongoDB Server v7.0 prior to 7.0.28 versions, MongoDB Server v8.0 versions prior to 8.0.17, MongoDB Server v8.2 versions prior to 8.2.3, MongoDB Server v6.0 versions prior to 6.0.27, MongoDB Server v5.0 versions prior to 5.0.32, MongoDB Server v4.4 versions prior to 4.4.30, MongoDB Server v4.2 versions greater than or equal to 4.2.0, MongoDB Server v4.0 versions greater than or equal to 4.0.0, and MongoDB Server v3.6 versions greater than or equal to 3.6.0.

- [https://github.com/Systemhaus-Schulz/MongoBleed-CVE-2025-14847](https://github.com/Systemhaus-Schulz/MongoBleed-CVE-2025-14847) :  ![starts](https://img.shields.io/github/stars/Systemhaus-Schulz/MongoBleed-CVE-2025-14847.svg) ![forks](https://img.shields.io/github/forks/Systemhaus-Schulz/MongoBleed-CVE-2025-14847.svg)


## CVE-2025-14783
 The Easy Digital Downloads plugin for WordPress is vulnerable to Unvalidated Redirect in all versions up to, and including, 3.6.2. This is due to insufficient validation on the redirect url supplied via the 'edd_redirect' parameter. This makes it possible for unauthenticated attackers to redirect users with the password reset email to potentially malicious sites if they can successfully trick them into performing an action.

- [https://github.com/ZeroEthical/CVE-2025-14783-POC](https://github.com/ZeroEthical/CVE-2025-14783-POC) :  ![starts](https://img.shields.io/github/stars/ZeroEthical/CVE-2025-14783-POC.svg) ![forks](https://img.shields.io/github/forks/ZeroEthical/CVE-2025-14783-POC.svg)


## CVE-2025-6716
 The Photos, Files, YouTube, Twitter, Instagram, TikTok, Ecommerce Contest Gallery – Upload, Vote, Sell via PayPal or Stripe, Social Share Buttons, OpenAI plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the 'upload[1][title]' parameter in all versions up to, and including, 26.0.8 due to insufficient input sanitization and output escaping. This makes it possible for authenticated attackers, with Author-level access and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.

- [https://github.com/Remenis/CVE-2025-67160](https://github.com/Remenis/CVE-2025-67160) :  ![starts](https://img.shields.io/github/stars/Remenis/CVE-2025-67160.svg) ![forks](https://img.shields.io/github/forks/Remenis/CVE-2025-67160.svg)


## CVE-2025-6715
 The LatePoint  WordPress plugin before 5.1.94 is vulnerable to Local File Inclusion via the layout parameter. This makes it possible for attackers to include and execute PHP files on the server, allowing the execution of any PHP code in those files.

- [https://github.com/Remenis/CVE-2025-67158](https://github.com/Remenis/CVE-2025-67158) :  ![starts](https://img.shields.io/github/stars/Remenis/CVE-2025-67158.svg) ![forks](https://img.shields.io/github/forks/Remenis/CVE-2025-67158.svg)
- [https://github.com/Remenis/CVE-2025-67159](https://github.com/Remenis/CVE-2025-67159) :  ![starts](https://img.shields.io/github/stars/Remenis/CVE-2025-67159.svg) ![forks](https://img.shields.io/github/forks/Remenis/CVE-2025-67159.svg)


## CVE-2025-0288
 Various Paragon Software products contain an arbitrary kernel memory vulnerability within biontdrv.sys, facilitated by the memmove function, which does not validate or sanitize user controlled input, allowing an attacker the ability to write arbitrary kernel memory and perform privilege escalation.

- [https://github.com/MeisamEb/CVE-2025-0288](https://github.com/MeisamEb/CVE-2025-0288) :  ![starts](https://img.shields.io/github/stars/MeisamEb/CVE-2025-0288.svg) ![forks](https://img.shields.io/github/forks/MeisamEb/CVE-2025-0288.svg)


## CVE-2024-41997
 An issue was discovered in version of Warp Terminal prior to 2024.07.18 (v0.2024.07.16.08.02). A command injection vulnerability exists in the Docker integration functionality. An attacker can create a specially crafted hyperlink using the `warp://action/docker/open_subshell` intent that when clicked by the victim results in command execution on the victim's machine.

- [https://github.com/xpcmdshell/CVE-2024-41997](https://github.com/xpcmdshell/CVE-2024-41997) :  ![starts](https://img.shields.io/github/stars/xpcmdshell/CVE-2024-41997.svg) ![forks](https://img.shields.io/github/forks/xpcmdshell/CVE-2024-41997.svg)


## CVE-2024-25641
 Cacti provides an operational monitoring and fault management framework. Prior to version 1.2.27, an arbitrary file write vulnerability, exploitable through the "Package Import" feature, allows authenticated users having the "Import Templates" permission to execute arbitrary PHP code on the web server. The vulnerability is located within the `import_package()` function defined into the `/lib/import.php` script. The function blindly trusts the filename and file content provided within the XML data, and writes such files into the Cacti base path (or even outside, since path traversal sequences are not filtered). This can be exploited to write or overwrite arbitrary files on the web server, leading to execution of arbitrary PHP code or other security impacts. Version 1.2.27 contains a patch for this issue.

- [https://github.com/declanmiddleton/thorndrop](https://github.com/declanmiddleton/thorndrop) :  ![starts](https://img.shields.io/github/stars/declanmiddleton/thorndrop.svg) ![forks](https://img.shields.io/github/forks/declanmiddleton/thorndrop.svg)


## CVE-2024-21413
 Microsoft Outlook Remote Code Execution Vulnerability

- [https://github.com/eylommaayan/THM---CVE-2024-21413-Moniker-Link-Microsoft-Outlook-](https://github.com/eylommaayan/THM---CVE-2024-21413-Moniker-Link-Microsoft-Outlook-) :  ![starts](https://img.shields.io/github/stars/eylommaayan/THM---CVE-2024-21413-Moniker-Link-Microsoft-Outlook-.svg) ![forks](https://img.shields.io/github/forks/eylommaayan/THM---CVE-2024-21413-Moniker-Link-Microsoft-Outlook-.svg)


## CVE-2024-5356
 A vulnerability, which was classified as critical, was found in anji-plus AJ-Report up to 1.4.1. Affected is an unknown function of the file /dataSet/testTransform;swagger-ui. The manipulation of the argument dynSentence leads to sql injection. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used. The identifier of this vulnerability is VDB-266268.

- [https://github.com/droyuu/Aj-Report-sql-CVE-2024-5356-POC](https://github.com/droyuu/Aj-Report-sql-CVE-2024-5356-POC) :  ![starts](https://img.shields.io/github/stars/droyuu/Aj-Report-sql-CVE-2024-5356-POC.svg) ![forks](https://img.shields.io/github/forks/droyuu/Aj-Report-sql-CVE-2024-5356-POC.svg)


## CVE-2024-5124
 A timing attack vulnerability exists in the gaizhenbiao/chuanhuchatgpt repository, specifically within the password comparison logic. The vulnerability is present in version 20240310 of the software, where passwords are compared using the '=' operator in Python. This method of comparison allows an attacker to guess passwords based on the timing of each character's comparison. The issue arises from the code segment that checks a password for a particular username, which can lead to the exposure of sensitive information to an unauthorized actor. An attacker exploiting this vulnerability could potentially guess user passwords, compromising the security of the system.

- [https://github.com/XiaomingX/cve-2024-5124-poc](https://github.com/XiaomingX/cve-2024-5124-poc) :  ![starts](https://img.shields.io/github/stars/XiaomingX/cve-2024-5124-poc.svg) ![forks](https://img.shields.io/github/forks/XiaomingX/cve-2024-5124-poc.svg)
- [https://github.com/gogo2464/CVE-2024-5124](https://github.com/gogo2464/CVE-2024-5124) :  ![starts](https://img.shields.io/github/stars/gogo2464/CVE-2024-5124.svg) ![forks](https://img.shields.io/github/forks/gogo2464/CVE-2024-5124.svg)


## CVE-2024-3094
Through a series of complex obfuscations, the liblzma build process extracts a prebuilt object file from a disguised test file existing in the source code, which is then used to modify specific functions in the liblzma code. This results in a modified liblzma library that can be used by any software linked against this library, intercepting and modifying the data interaction with this library.

- [https://github.com/HackerHermanos/CVE-2024-3094_xz_check](https://github.com/HackerHermanos/CVE-2024-3094_xz_check) :  ![starts](https://img.shields.io/github/stars/HackerHermanos/CVE-2024-3094_xz_check.svg) ![forks](https://img.shields.io/github/forks/HackerHermanos/CVE-2024-3094_xz_check.svg)


## CVE-2022-42889
 Apache Commons Text performs variable interpolation, allowing properties to be dynamically evaluated and expanded. The standard format for interpolation is "${prefix:name}", where "prefix" is used to locate an instance of org.apache.commons.text.lookup.StringLookup that performs the interpolation. Starting with version 1.5 and continuing through 1.9, the set of default Lookup instances included interpolators that could result in arbitrary code execution or contact with remote servers. These lookups are: - "script" - execute expressions using the JVM script execution engine (javax.script) - "dns" - resolve dns records - "url" - load values from urls, including from remote servers Applications using the interpolation defaults in the affected versions may be vulnerable to remote code execution or unintentional contact with remote servers if untrusted configuration values are used. Users are recommended to upgrade to Apache Commons Text 1.10.0, which disables the problematic interpolators by default.

- [https://github.com/Goultarde/CVE-2022-42889-text4shell](https://github.com/Goultarde/CVE-2022-42889-text4shell) :  ![starts](https://img.shields.io/github/stars/Goultarde/CVE-2022-42889-text4shell.svg) ![forks](https://img.shields.io/github/forks/Goultarde/CVE-2022-42889-text4shell.svg)


## CVE-2022-39299
 Passport-SAML is a SAML 2.0 authentication provider for Passport, the Node.js authentication library. A remote attacker may be able to bypass SAML authentication on a website using passport-saml. A successful attack requires that the attacker is in possession of an arbitrary IDP signed XML element. Depending on the IDP used, fully unauthenticated attacks (e.g without access to a valid user) might also be feasible if generation of a signed message can be triggered. Users should upgrade to passport-saml version 3.2.2 or newer. The issue was also present in the beta releases of `node-saml` before version 4.0.0-beta.5. If you cannot upgrade, disabling SAML authentication may be done as a workaround.

- [https://github.com/KaztoRay/CVE-2022-39299-Research](https://github.com/KaztoRay/CVE-2022-39299-Research) :  ![starts](https://img.shields.io/github/stars/KaztoRay/CVE-2022-39299-Research.svg) ![forks](https://img.shields.io/github/forks/KaztoRay/CVE-2022-39299-Research.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/Fa1c0n35/CVE-2021-41773](https://github.com/Fa1c0n35/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/Fa1c0n35/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/Fa1c0n35/CVE-2021-41773.svg)
- [https://github.com/vuongnv3389-sec/cve-2021-41773](https://github.com/vuongnv3389-sec/cve-2021-41773) :  ![starts](https://img.shields.io/github/stars/vuongnv3389-sec/cve-2021-41773.svg) ![forks](https://img.shields.io/github/forks/vuongnv3389-sec/cve-2021-41773.svg)
- [https://github.com/skentagon/CVE-2021-41773](https://github.com/skentagon/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/skentagon/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/skentagon/CVE-2021-41773.svg)


## CVE-2021-3156
 Sudo before 1.9.5p2 contains an off-by-one error that can result in a heap-based buffer overflow, which allows privilege escalation to root via "sudoedit -s" and a command-line argument that ends with a single backslash character.

- [https://github.com/VilmarTuminskii/cve-2021-3156-sudo-lab](https://github.com/VilmarTuminskii/cve-2021-3156-sudo-lab) :  ![starts](https://img.shields.io/github/stars/VilmarTuminskii/cve-2021-3156-sudo-lab.svg) ![forks](https://img.shields.io/github/forks/VilmarTuminskii/cve-2021-3156-sudo-lab.svg)


## CVE-2019-14462
 An issue was discovered in libmodbus before 3.0.7 and 3.1.x before 3.1.5. There is an out-of-bounds read for the MODBUS_FC_WRITE_MULTIPLE_COILS case, aka VD-1302.

- [https://github.com/spanwich/sel4-ics-gateway-demo](https://github.com/spanwich/sel4-ics-gateway-demo) :  ![starts](https://img.shields.io/github/stars/spanwich/sel4-ics-gateway-demo.svg) ![forks](https://img.shields.io/github/forks/spanwich/sel4-ics-gateway-demo.svg)


## CVE-2017-12149
 In Jboss Application Server as shipped with Red Hat Enterprise Application Platform 5.2, it was found that the doFilter method in the ReadOnlyAccessFilter of the HTTP Invoker does not restrict classes for which it performs deserialization and thus allowing an attacker to execute arbitrary code via crafted serialized data.

- [https://github.com/galois17/cve-2017-12149-playground](https://github.com/galois17/cve-2017-12149-playground) :  ![starts](https://img.shields.io/github/stars/galois17/cve-2017-12149-playground.svg) ![forks](https://img.shields.io/github/forks/galois17/cve-2017-12149-playground.svg)


## CVE-2012-1823
 sapi/cgi/cgi_main.c in PHP before 5.3.12 and 5.4.x before 5.4.2, when configured as a CGI script (aka php-cgi), does not properly handle query strings that lack an = (equals sign) character, which allows remote attackers to execute arbitrary code by placing command-line options in the query string, related to lack of skipping a certain php_getopt for the 'd' case.

- [https://github.com/waburig/Open-Worldwide-Application-Security-Project-OWASP-](https://github.com/waburig/Open-Worldwide-Application-Security-Project-OWASP-) :  ![starts](https://img.shields.io/github/stars/waburig/Open-Worldwide-Application-Security-Project-OWASP-.svg) ![forks](https://img.shields.io/github/forks/waburig/Open-Worldwide-Application-Security-Project-OWASP-.svg)

