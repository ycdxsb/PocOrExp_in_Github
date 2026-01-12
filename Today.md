# Update 2026-01-12
## CVE-2025-68664
 LangChain is a framework for building agents and LLM-powered applications. Prior to versions 0.3.81 and 1.2.5, a serialization injection vulnerability exists in LangChain's dumps() and dumpd() functions. The functions do not escape dictionaries with 'lc' keys when serializing free-form dictionaries. The 'lc' key is used internally by LangChain to mark serialized objects. When user-controlled data contains this key structure, it is treated as a legitimate LangChain object during deserialization rather than plain user data. This issue has been patched in versions 0.3.81 and 1.2.5.

- [https://github.com/comerc/CVE-2025-68664](https://github.com/comerc/CVE-2025-68664) :  ![starts](https://img.shields.io/github/stars/comerc/CVE-2025-68664.svg) ![forks](https://img.shields.io/github/forks/comerc/CVE-2025-68664.svg)


## CVE-2025-55182
 A pre-authentication remote code execution vulnerability exists in React Server Components versions 19.0.0, 19.1.0, 19.1.1, and 19.2.0 including the following packages: react-server-dom-parcel, react-server-dom-turbopack, and react-server-dom-webpack. The vulnerable code unsafely deserializes payloads from HTTP requests to Server Function endpoints.

- [https://github.com/alfazhossain/CVE-2025-55182-Exploiter](https://github.com/alfazhossain/CVE-2025-55182-Exploiter) :  ![starts](https://img.shields.io/github/stars/alfazhossain/CVE-2025-55182-Exploiter.svg) ![forks](https://img.shields.io/github/forks/alfazhossain/CVE-2025-55182-Exploiter.svg)


## CVE-2025-34171
 CasaOS versions up to and including 0.4.15 expose multiple unauthenticated endpoints that allow remote attackers to retrieve sensitive configuration files and system debug information. The /v1/users/image endpoint can be abused with a user-controlled path parameter to access files under /var/lib/casaos/1/, which reveals installed applications and configuration details. Additionally, /v1/sys/debug discloses host operating system, kernel, hardware, and storage information. The endpoints also return distinct error messages, enabling file existence enumeration of arbitrary paths on the underlying host filesystem. This information disclosure can be used for reconnaissance and to facilitate targeted follow-up attacks against services deployed on the host.

- [https://github.com/Eyodav/CVE-2025-34171](https://github.com/Eyodav/CVE-2025-34171) :  ![starts](https://img.shields.io/github/stars/Eyodav/CVE-2025-34171.svg) ![forks](https://img.shields.io/github/forks/Eyodav/CVE-2025-34171.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/Grand-Moomin/Vuln-Next.js-CVE-2025-29927](https://github.com/Grand-Moomin/Vuln-Next.js-CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/Grand-Moomin/Vuln-Next.js-CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/Grand-Moomin/Vuln-Next.js-CVE-2025-29927.svg)


## CVE-2025-15495
 A vulnerability was found in BiggiDroid Simple PHP CMS 1.0. This impacts an unknown function of the file /admin/editsite.php. The manipulation of the argument image results in unrestricted upload. The attack can be launched remotely. The exploit has been made public and could be used. The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/Asim-QAZi/RCE-Simplephpblog-biggiedroid](https://github.com/Asim-QAZi/RCE-Simplephpblog-biggiedroid) :  ![starts](https://img.shields.io/github/stars/Asim-QAZi/RCE-Simplephpblog-biggiedroid.svg) ![forks](https://img.shields.io/github/forks/Asim-QAZi/RCE-Simplephpblog-biggiedroid.svg)


## CVE-2025-6680
 The Tutor LMS – eLearning and online course solution plugin for WordPress is vulnerable to Sensitive Information Exposure in all versions up to, and including, 3.8.3. This makes it possible for authenticated attackers, with tutor-level access and above, to view assignments for courses they don't teach which may contain sensitive information.

- [https://github.com/mtgsjr/CVE-2025-66802](https://github.com/mtgsjr/CVE-2025-66802) :  ![starts](https://img.shields.io/github/stars/mtgsjr/CVE-2025-66802.svg) ![forks](https://img.shields.io/github/forks/mtgsjr/CVE-2025-66802.svg)


## CVE-2025-6514
 mcp-remote is exposed to OS command injection when connecting to untrusted MCP servers due to crafted input from the authorization_endpoint response URL

- [https://github.com/dotsetlabs/overwatch](https://github.com/dotsetlabs/overwatch) :  ![starts](https://img.shields.io/github/stars/dotsetlabs/overwatch.svg) ![forks](https://img.shields.io/github/forks/dotsetlabs/overwatch.svg)


## CVE-2025-6331
 A vulnerability classified as critical was found in PHPGurukul Directory Management System 1.0. Affected by this vulnerability is an unknown functionality of the file /admin/search-directory.php. The manipulation of the argument searchdata leads to sql injection. The attack can be launched remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/padayali-JD/CVE-2025-63314](https://github.com/padayali-JD/CVE-2025-63314) :  ![starts](https://img.shields.io/github/stars/padayali-JD/CVE-2025-63314.svg) ![forks](https://img.shields.io/github/forks/padayali-JD/CVE-2025-63314.svg)


## CVE-2024-5153
 The Startklar Elementor Addons plugin for WordPress is vulnerable to Directory Traversal in all versions up to, and including, 1.7.15 via the 'dropzone_hash' parameter. This makes it possible for unauthenticated attackers to copy the contents of arbitrary files on the server, which can contain sensitive information, and to delete arbitrary directories, including the root WordPress directory.

- [https://github.com/Sudo-WP/sudowp-dropzone-elementor](https://github.com/Sudo-WP/sudowp-dropzone-elementor) :  ![starts](https://img.shields.io/github/stars/Sudo-WP/sudowp-dropzone-elementor.svg) ![forks](https://img.shields.io/github/forks/Sudo-WP/sudowp-dropzone-elementor.svg)


## CVE-2024-3094
Through a series of complex obfuscations, the liblzma build process extracts a prebuilt object file from a disguised test file existing in the source code, which is then used to modify specific functions in the liblzma code. This results in a modified liblzma library that can be used by any software linked against this library, intercepting and modifying the data interaction with this library.

- [https://github.com/gayatriracha/CVE-2024-3094-Nmap-NSE-script](https://github.com/gayatriracha/CVE-2024-3094-Nmap-NSE-script) :  ![starts](https://img.shields.io/github/stars/gayatriracha/CVE-2024-3094-Nmap-NSE-script.svg) ![forks](https://img.shields.io/github/forks/gayatriracha/CVE-2024-3094-Nmap-NSE-script.svg)


## CVE-2022-4782
 The ClickFunnels WordPress plugin through 3.1.1 does not validate and escape one of its shortcode attributes, which could allow users with a role as low as contributor to perform Stored Cross-Site Scripting attack.

- [https://github.com/Sudo-WP/clickfunnels-zurich](https://github.com/Sudo-WP/clickfunnels-zurich) :  ![starts](https://img.shields.io/github/stars/Sudo-WP/clickfunnels-zurich.svg) ![forks](https://img.shields.io/github/forks/Sudo-WP/clickfunnels-zurich.svg)


## CVE-2022-0847
 A flaw was found in the way the "flags" member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/stfnw/Debugging_Dirty_Pipe_CVE-2022-0847](https://github.com/stfnw/Debugging_Dirty_Pipe_CVE-2022-0847) :  ![starts](https://img.shields.io/github/stars/stfnw/Debugging_Dirty_Pipe_CVE-2022-0847.svg) ![forks](https://img.shields.io/github/forks/stfnw/Debugging_Dirty_Pipe_CVE-2022-0847.svg)


## CVE-2015-6967
 Unrestricted file upload vulnerability in the My Image plugin in Nibbleblog before 4.0.5 allows remote administrators to execute arbitrary code by uploading a file with an executable extension, then accessing it via a direct request to the file in content/private/plugins/my_image/image.php.

- [https://github.com/declanmiddleton/nibbleblog_4.0.3_rce](https://github.com/declanmiddleton/nibbleblog_4.0.3_rce) :  ![starts](https://img.shields.io/github/stars/declanmiddleton/nibbleblog_4.0.3_rce.svg) ![forks](https://img.shields.io/github/forks/declanmiddleton/nibbleblog_4.0.3_rce.svg)


## CVE-2015-3224
 request.rb in Web Console before 2.1.3, as used with Ruby on Rails 3.x and 4.x, does not properly restrict the use of X-Forwarded-For headers in determining a client's IP address, which allows remote attackers to bypass the whitelisted_ips protection mechanism via a crafted request.

- [https://github.com/SQU4NCH/CVE-2015-3224](https://github.com/SQU4NCH/CVE-2015-3224) :  ![starts](https://img.shields.io/github/stars/SQU4NCH/CVE-2015-3224.svg) ![forks](https://img.shields.io/github/forks/SQU4NCH/CVE-2015-3224.svg)


## CVE-2011-2523
 vsftpd 2.3.4 downloaded between 20110630 and 20110703 contains a backdoor which opens a shell on port 6200/tcp.

- [https://github.com/Mirza-22144/Vulnerability-Assessment-Exploitation-Lab](https://github.com/Mirza-22144/Vulnerability-Assessment-Exploitation-Lab) :  ![starts](https://img.shields.io/github/stars/Mirza-22144/Vulnerability-Assessment-Exploitation-Lab.svg) ![forks](https://img.shields.io/github/forks/Mirza-22144/Vulnerability-Assessment-Exploitation-Lab.svg)

