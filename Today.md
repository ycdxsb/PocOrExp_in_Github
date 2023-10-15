# Update 2023-10-15
## CVE-2023-45542
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/ahrixia/CVE-2023-45542](https://github.com/ahrixia/CVE-2023-45542) :  ![starts](https://img.shields.io/github/stars/ahrixia/CVE-2023-45542.svg) ![forks](https://img.shields.io/github/forks/ahrixia/CVE-2023-45542.svg)


## CVE-2023-45540
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/soundarkutty/CVE-2023-45540](https://github.com/soundarkutty/CVE-2023-45540) :  ![starts](https://img.shields.io/github/stars/soundarkutty/CVE-2023-45540.svg) ![forks](https://img.shields.io/github/forks/soundarkutty/CVE-2023-45540.svg)


## CVE-2023-44487
 The HTTP/2 protocol allows a denial of service (server resource consumption) because request cancellation can reset many streams quickly, as exploited in the wild in August through October 2023.

- [https://github.com/secengjeff/rapidresetclient](https://github.com/secengjeff/rapidresetclient) :  ![starts](https://img.shields.io/github/stars/secengjeff/rapidresetclient.svg) ![forks](https://img.shields.io/github/forks/secengjeff/rapidresetclient.svg)


## CVE-2023-43804
 urllib3 is a user-friendly HTTP client library for Python. urllib3 doesn't treat the `Cookie` HTTP header special or provide any helpers for managing cookies over HTTP, that is the responsibility of the user. However, it is possible for a user to specify a `Cookie` header and unknowingly leak information via HTTP redirects to a different origin if that user doesn't disable redirects explicitly. This issue has been patched in urllib3 version 1.26.17 or 2.0.5.

- [https://github.com/JawadPy/CVE-2023-43804-Exploit](https://github.com/JawadPy/CVE-2023-43804-Exploit) :  ![starts](https://img.shields.io/github/stars/JawadPy/CVE-2023-43804-Exploit.svg) ![forks](https://img.shields.io/github/forks/JawadPy/CVE-2023-43804-Exploit.svg)


## CVE-2023-43144
 Projectworldsl Assets-management-system-in-php 1.0 is vulnerable to SQL Injection via the &quot;id&quot; parameter in delete.php.

- [https://github.com/Pegasus0xx/CVE-2023-43144](https://github.com/Pegasus0xx/CVE-2023-43144) :  ![starts](https://img.shields.io/github/stars/Pegasus0xx/CVE-2023-43144.svg) ![forks](https://img.shields.io/github/forks/Pegasus0xx/CVE-2023-43144.svg)


## CVE-2023-41105
 An issue was discovered in Python 3.11 through 3.11.4. If a path containing '\0' bytes is passed to os.path.normpath(), the path will be truncated unexpectedly at the first '\0' byte. There are plausible cases in which an application would have rejected a filename for security reasons in Python 3.10.x or earlier, but that filename is no longer rejected in Python 3.11.x.

- [https://github.com/JawadPy/CVE-2023-41105-Exploit](https://github.com/JawadPy/CVE-2023-41105-Exploit) :  ![starts](https://img.shields.io/github/stars/JawadPy/CVE-2023-41105-Exploit.svg) ![forks](https://img.shields.io/github/forks/JawadPy/CVE-2023-41105-Exploit.svg)


## CVE-2023-38146
 Windows Themes Remote Code Execution Vulnerability

- [https://github.com/Jnnshschl/CVE-2023-38146](https://github.com/Jnnshschl/CVE-2023-38146) :  ![starts](https://img.shields.io/github/stars/Jnnshschl/CVE-2023-38146.svg) ![forks](https://img.shields.io/github/forks/Jnnshschl/CVE-2023-38146.svg)


## CVE-2023-30861
 Flask is a lightweight WSGI web application framework. When all of the following conditions are met, a response containing data intended for one client may be cached and subsequently sent by the proxy to other clients. If the proxy also caches `Set-Cookie` headers, it may send one client's `session` cookie to other clients. The severity depends on the application's use of the session and the proxy's behavior regarding cookies. The risk depends on all these conditions being met. 1. The application must be hosted behind a caching proxy that does not strip cookies or ignore responses with cookies. 2. The application sets `session.permanent = True` 3. The application does not access or modify the session at any point during a request. 4. `SESSION_REFRESH_EACH_REQUEST` enabled (the default). 5. The application does not set a `Cache-Control` header to indicate that a page is private or should not be cached. This happens because vulnerable versions of Flask only set the `Vary: Cookie` header when the session is accessed or modified, not when it is refreshed (re-sent to update the expiration) without being accessed or modified. This issue has been fixed in versions 2.3.2 and 2.2.5.

- [https://github.com/JawadPy/CVE-2023-30861-Exploit](https://github.com/JawadPy/CVE-2023-30861-Exploit) :  ![starts](https://img.shields.io/github/stars/JawadPy/CVE-2023-30861-Exploit.svg) ![forks](https://img.shields.io/github/forks/JawadPy/CVE-2023-30861-Exploit.svg)


## CVE-2023-24538
 Templates do not properly consider backticks (`) as Javascript string delimiters, and do not escape them as expected. Backticks are used, since ES6, for JS template literals. If a template contains a Go template action within a Javascript template literal, the contents of the action can be used to terminate the literal, injecting arbitrary Javascript code into the Go template. As ES6 template literals are rather complex, and themselves can do string interpolation, the decision was made to simply disallow Go template actions from being used inside of them (e.g. &quot;var a = {{.}}&quot;), since there is no obviously safe way to allow this behavior. This takes the same approach as github.com/google/safehtml. With fix, Template.Parse returns an Error when it encounters templates like this, with an ErrorCode of value 12. This ErrorCode is currently unexported, but will be exported in the release of Go 1.21. Users who rely on the previous behavior can re-enable it using the GODEBUG flag jstmpllitinterp=1, with the caveat that backticks will now be escaped. This should be used with caution.

- [https://github.com/skulkarni-mv/goIssue_kirkstone](https://github.com/skulkarni-mv/goIssue_kirkstone) :  ![starts](https://img.shields.io/github/stars/skulkarni-mv/goIssue_kirkstone.svg) ![forks](https://img.shields.io/github/forks/skulkarni-mv/goIssue_kirkstone.svg)


## CVE-2023-24329
 An issue in the urllib.parse component of Python before 3.11.4 allows attackers to bypass blocklisting methods by supplying a URL that starts with blank characters.

- [https://github.com/JawadPy/CVE-2023-24329-Exploit](https://github.com/JawadPy/CVE-2023-24329-Exploit) :  ![starts](https://img.shields.io/github/stars/JawadPy/CVE-2023-24329-Exploit.svg) ![forks](https://img.shields.io/github/forks/JawadPy/CVE-2023-24329-Exploit.svg)


## CVE-2023-22515
 Atlassian has been made aware of an issue reported by a handful of customers where external attackers may have exploited a previously unknown vulnerability in publicly accessible Confluence Data Center and Server instances to create unauthorized Confluence administrator accounts and access Confluence instances. Atlassian Cloud sites are not affected by this vulnerability. If your Confluence site is accessed via an atlassian.net domain, it is hosted by Atlassian and is not vulnerable to this issue. For more details, please review the linked advisory on this CVE.

- [https://github.com/Le1a/CVE-2023-22515](https://github.com/Le1a/CVE-2023-22515) :  ![starts](https://img.shields.io/github/stars/Le1a/CVE-2023-22515.svg) ![forks](https://img.shields.io/github/forks/Le1a/CVE-2023-22515.svg)
- [https://github.com/iveresk/CVE-2023-22515](https://github.com/iveresk/CVE-2023-22515) :  ![starts](https://img.shields.io/github/stars/iveresk/CVE-2023-22515.svg) ![forks](https://img.shields.io/github/forks/iveresk/CVE-2023-22515.svg)
- [https://github.com/Vulnmachines/confluence-cve-2023-22515](https://github.com/Vulnmachines/confluence-cve-2023-22515) :  ![starts](https://img.shields.io/github/stars/Vulnmachines/confluence-cve-2023-22515.svg) ![forks](https://img.shields.io/github/forks/Vulnmachines/confluence-cve-2023-22515.svg)


## CVE-2023-21272
 In readFrom of Uri.java, there is a possible bad URI permission grant due to improper input validation. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/nidhi7598/frameworks_base_AOSP_06_r22_CVE-2023-21272](https://github.com/nidhi7598/frameworks_base_AOSP_06_r22_CVE-2023-21272) :  ![starts](https://img.shields.io/github/stars/nidhi7598/frameworks_base_AOSP_06_r22_CVE-2023-21272.svg) ![forks](https://img.shields.io/github/forks/nidhi7598/frameworks_base_AOSP_06_r22_CVE-2023-21272.svg)


## CVE-2023-4911
 A buffer overflow was discovered in the GNU C Library's dynamic loader ld.so while processing the GLIBC_TUNABLES environment variable. This issue could allow a local attacker to use maliciously crafted GLIBC_TUNABLES environment variables when launching binaries with SUID permission to execute code with elevated privileges.

- [https://github.com/guffre/CVE-2023-4911](https://github.com/guffre/CVE-2023-4911) :  ![starts](https://img.shields.io/github/stars/guffre/CVE-2023-4911.svg) ![forks](https://img.shields.io/github/forks/guffre/CVE-2023-4911.svg)


## CVE-2023-3712
 Files or Directories Accessible to External Parties vulnerability in Honeywell PM43 on 32 bit, ARM (Printer web page modules) allows Privilege Escalation.This issue affects PM43 versions prior to P10.19.050004. Update to the latest available firmware version of the respective printers to version MR19.5 (e.g. P10.19.050006).

- [https://github.com/vpxuser/CVE-2023-3712-POC](https://github.com/vpxuser/CVE-2023-3712-POC) :  ![starts](https://img.shields.io/github/stars/vpxuser/CVE-2023-3712-POC.svg) ![forks](https://img.shields.io/github/forks/vpxuser/CVE-2023-3712-POC.svg)


## CVE-2023-3711
 Session Fixation vulnerability in Honeywell PM43 on 32 bit, ARM (Printer web page modules) allows Session Credential Falsification through Prediction.This issue affects PM43 versions prior to P10.19.050004. Update to the latest available firmware version of the respective printers to version MR19.5 (e.g. P10.19.050006).

- [https://github.com/vpxuser/CVE-2023-3711-POC](https://github.com/vpxuser/CVE-2023-3711-POC) :  ![starts](https://img.shields.io/github/stars/vpxuser/CVE-2023-3711-POC.svg) ![forks](https://img.shields.io/github/forks/vpxuser/CVE-2023-3711-POC.svg)


## CVE-2023-3710
 Improper Input Validation vulnerability in Honeywell PM43 on 32 bit, ARM (Printer web page modules) allows Command Injection.This issue affects PM43 versions prior to P10.19.050004. Update to the latest available firmware version of the respective printers to version MR19.5 (e.g. P10.19.050006).

- [https://github.com/vpxuser/CVE-2023-3710-POC](https://github.com/vpxuser/CVE-2023-3710-POC) :  ![starts](https://img.shields.io/github/stars/vpxuser/CVE-2023-3710-POC.svg) ![forks](https://img.shields.io/github/forks/vpxuser/CVE-2023-3710-POC.svg)


## CVE-2022-44268
 ImageMagick 7.1.0-49 is vulnerable to Information Disclosure. When it parses a PNG image (e.g., for resize), the resulting image could have embedded the content of an arbitrary. file (if the magick binary has permissions to read it).

- [https://github.com/Vagebondcur/IMAGE-MAGICK-CVE-2022-44268](https://github.com/Vagebondcur/IMAGE-MAGICK-CVE-2022-44268) :  ![starts](https://img.shields.io/github/stars/Vagebondcur/IMAGE-MAGICK-CVE-2022-44268.svg) ![forks](https://img.shields.io/github/forks/Vagebondcur/IMAGE-MAGICK-CVE-2022-44268.svg)


## CVE-2022-22817
 PIL.ImageMath.eval in Pillow before 9.0.0 allows evaluation of arbitrary expressions, such as ones that use the Python exec method. A lambda expression could also be used,

- [https://github.com/JawadPy/CVE-2022-22817-Exploit](https://github.com/JawadPy/CVE-2022-22817-Exploit) :  ![starts](https://img.shields.io/github/stars/JawadPy/CVE-2022-22817-Exploit.svg) ![forks](https://img.shields.io/github/forks/JawadPy/CVE-2022-22817-Exploit.svg)


## CVE-2022-2602
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/LukeGix/CVE-2022-2602](https://github.com/LukeGix/CVE-2022-2602) :  ![starts](https://img.shields.io/github/stars/LukeGix/CVE-2022-2602.svg) ![forks](https://img.shields.io/github/forks/LukeGix/CVE-2022-2602.svg)


## CVE-2022-2588
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/PolymorphicOpcode/CVE-2022-2588](https://github.com/PolymorphicOpcode/CVE-2022-2588) :  ![starts](https://img.shields.io/github/stars/PolymorphicOpcode/CVE-2022-2588.svg) ![forks](https://img.shields.io/github/forks/PolymorphicOpcode/CVE-2022-2588.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/drapl0n/pwnKit](https://github.com/drapl0n/pwnKit) :  ![starts](https://img.shields.io/github/stars/drapl0n/pwnKit.svg) ![forks](https://img.shields.io/github/forks/drapl0n/pwnKit.svg)
- [https://github.com/wudicainiao/cve-2021-4034](https://github.com/wudicainiao/cve-2021-4034) :  ![starts](https://img.shields.io/github/stars/wudicainiao/cve-2021-4034.svg) ![forks](https://img.shields.io/github/forks/wudicainiao/cve-2021-4034.svg)
- [https://github.com/OXDBXKXO/ez-pwnkit](https://github.com/OXDBXKXO/ez-pwnkit) :  ![starts](https://img.shields.io/github/stars/OXDBXKXO/ez-pwnkit.svg) ![forks](https://img.shields.io/github/forks/OXDBXKXO/ez-pwnkit.svg)
- [https://github.com/moldabekov/CVE-2021-4034](https://github.com/moldabekov/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/moldabekov/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/moldabekov/CVE-2021-4034.svg)


## CVE-2020-2501
 A stack-based buffer overflow vulnerability has been reported to affect QNAP NAS devices running Surveillance Station. If exploited, this vulnerability allows attackers to execute arbitrary code. QNAP have already fixed this vulnerability in the following versions: Surveillance Station 5.1.5.4.3 (and later) for ARM CPU NAS (64bit OS) and x86 CPU NAS (64bit OS) Surveillance Station 5.1.5.3.3 (and later) for ARM CPU NAS (32bit OS) and x86 CPU NAS (32bit OS)

- [https://github.com/Alonzozzz/alonzzzo](https://github.com/Alonzozzz/alonzzzo) :  ![starts](https://img.shields.io/github/stars/Alonzozzz/alonzzzo.svg) ![forks](https://img.shields.io/github/forks/Alonzozzz/alonzzzo.svg)


## CVE-2018-1000224
 Godot Engine version All versions prior to 2.1.5, all 3.0 versions prior to 3.0.6. contains a Signed/unsigned comparison, wrong buffer size chackes, integer overflow, missing padding initialization vulnerability in (De)Serialization functions (core/io/marshalls.cpp) that can result in DoS (packet of death), possible leak of uninitialized memory. This attack appear to be exploitable via A malformed packet is received over the network by a Godot application that uses built-in serialization (e.g. game server, or game client). Could be triggered by multiplayer opponent. This vulnerability appears to have been fixed in 2.1.5, 3.0.6, master branch after commit feaf03421dda0213382b51aff07bd5a96b29487b.

- [https://github.com/zann1x/ITS](https://github.com/zann1x/ITS) :  ![starts](https://img.shields.io/github/stars/zann1x/ITS.svg) ![forks](https://img.shields.io/github/forks/zann1x/ITS.svg)

