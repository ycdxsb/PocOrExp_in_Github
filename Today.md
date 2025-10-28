# Update 2025-10-28
## CVE-2025-62376
 pwn.college DOJO is an education platform for learning cybersecurity. In versions up to and including commit 781d91157cfc234a434d0bab45cbcf97894c642e, the /workspace endpoint contains an improper authentication vulnerability that allows an attacker to access any active Windows VM without proper authorization. The vulnerability occurs in the view_desktop function where the user is retrieved via a URL parameter without verifying that the requester has administrative privileges. An attacker can supply any user ID and arbitrary password in the request parameters to impersonate another user. When requesting a Windows desktop service, the function does not validate the supplied password before generating access credentials, allowing the attacker to obtain an iframe source URL that grants full access to the target user's Windows VM. This impacts all users with active Windows VMs, as an attacker can access and modify data on the Windows machine and in the home directory of the associated Linux machine via the Z: drive. This issue has been patched in commit 467db0b9ea0d9a929dc89b41f6eb59f7cfc68bef. No known workarounds exist.

- [https://github.com/ghostroots/CVE-2025-62376](https://github.com/ghostroots/CVE-2025-62376) :  ![starts](https://img.shields.io/github/stars/ghostroots/CVE-2025-62376.svg) ![forks](https://img.shields.io/github/forks/ghostroots/CVE-2025-62376.svg)


## CVE-2025-61884
 Vulnerability in the Oracle Configurator product of Oracle E-Business Suite (component: Runtime UI).  Supported versions that are affected are 12.2.3-12.2.14. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Configurator.  Successful attacks of this vulnerability can result in  unauthorized access to critical data or complete access to all Oracle Configurator accessible data. CVSS 3.1 Base Score 7.5 (Confidentiality impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N).

- [https://github.com/shinyhunt/CVE-2025-61884](https://github.com/shinyhunt/CVE-2025-61884) :  ![starts](https://img.shields.io/github/stars/shinyhunt/CVE-2025-61884.svg) ![forks](https://img.shields.io/github/forks/shinyhunt/CVE-2025-61884.svg)


## CVE-2025-55315
 Inconsistent interpretation of http requests ('http request/response smuggling') in ASP.NET Core allows an authorized attacker to bypass a security feature over a network.

- [https://github.com/blackquantas/CVE-2025-55315](https://github.com/blackquantas/CVE-2025-55315) :  ![starts](https://img.shields.io/github/stars/blackquantas/CVE-2025-55315.svg) ![forks](https://img.shields.io/github/forks/blackquantas/CVE-2025-55315.svg)


## CVE-2025-49844
 Redis is an open source, in-memory database that persists on disk. Versions 8.2.1 and below allow an authenticated user to use a specially crafted Lua script to manipulate the garbage collector, trigger a use-after-free and potentially lead to remote code execution. The problem exists in all versions of Redis with Lua scripting. This issue is fixed in version 8.2.2. To workaround this issue without patching the redis-server executable is to prevent users from executing Lua scripts. This can be done using ACL to restrict EVAL and EVALSHA commands.

- [https://github.com/ksnnd32/redis_exploit](https://github.com/ksnnd32/redis_exploit) :  ![starts](https://img.shields.io/github/stars/ksnnd32/redis_exploit.svg) ![forks](https://img.shields.io/github/forks/ksnnd32/redis_exploit.svg)


## CVE-2025-49553
 Adobe Connect versions 12.9 and earlier are affected by a DOM-based Cross-Site Scripting (XSS) vulnerability that could be exploited by an attacker to execute malicious scripts in a victim's browser. Exploitation of this issue requires user interaction in that a victim must navigate to a crafted web page. A successful attacker can abuse this to achieve session takeover, increasing the confidentiality and integrity impact as high. Scope is changed.

- [https://github.com/glitchhawks/CVE-2025-49553](https://github.com/glitchhawks/CVE-2025-49553) :  ![starts](https://img.shields.io/github/stars/glitchhawks/CVE-2025-49553.svg) ![forks](https://img.shields.io/github/forks/glitchhawks/CVE-2025-49553.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/KaztoRay/CVE-2025-29927-Research](https://github.com/KaztoRay/CVE-2025-29927-Research) :  ![starts](https://img.shields.io/github/stars/KaztoRay/CVE-2025-29927-Research.svg) ![forks](https://img.shields.io/github/forks/KaztoRay/CVE-2025-29927-Research.svg)


## CVE-2025-11832
 Allocation of Resources Without Limits or Throttling vulnerability in Azure Access Technology BLU-IC2, Azure Access Technology BLU-IC4 allows Flooding.This issue affects BLU-IC2: through 1.19.5; BLU-IC4: through 1.19.5.

- [https://github.com/blackhatlegend/CVE-2025-11832](https://github.com/blackhatlegend/CVE-2025-11832) :  ![starts](https://img.shields.io/github/stars/blackhatlegend/CVE-2025-11832.svg) ![forks](https://img.shields.io/github/forks/blackhatlegend/CVE-2025-11832.svg)


## CVE-2025-9967
 The Orion SMS OTP Verification plugin for WordPress is vulnerable to privilege escalation via account takeover in all versions up to, and including, 1.1.7. This is due to the plugin not properly validating a user's identity prior to updating their password. This makes it possible for unauthenticated attackers to change arbitrary user's password to a one-time password if the attacker knows the user's phone number

- [https://github.com/glitchhawks/CVE-2025-9967](https://github.com/glitchhawks/CVE-2025-9967) :  ![starts](https://img.shields.io/github/stars/glitchhawks/CVE-2025-9967.svg) ![forks](https://img.shields.io/github/forks/glitchhawks/CVE-2025-9967.svg)


## CVE-2025-6514
 mcp-remote is exposed to OS command injection when connecting to untrusted MCP servers due to crafted input from the authorization_endpoint response URL

- [https://github.com/Cyberency/CVE-2025-6514](https://github.com/Cyberency/CVE-2025-6514) :  ![starts](https://img.shields.io/github/stars/Cyberency/CVE-2025-6514.svg) ![forks](https://img.shields.io/github/forks/Cyberency/CVE-2025-6514.svg)


## CVE-2025-5353
 A hardcoded key in Ivanti Workspace Control before version 10.19.10.0 allows a local authenticated attacker to decrypt stored SQL credentials.

- [https://github.com/moezbouzayani9/Pi-hole-XSS-CVE-2025-53533](https://github.com/moezbouzayani9/Pi-hole-XSS-CVE-2025-53533) :  ![starts](https://img.shields.io/github/stars/moezbouzayani9/Pi-hole-XSS-CVE-2025-53533.svg) ![forks](https://img.shields.io/github/forks/moezbouzayani9/Pi-hole-XSS-CVE-2025-53533.svg)


## CVE-2025-3052
 An arbitrary write vulnerability in Microsoft signed UEFI firmware allows for code execution of untrusted software. This allows an attacker to control its value, leading to arbitrary memory writes, including modification of critical firmware settings stored in NVRAM. Exploiting this vulnerability could enable security bypasses, persistence mechanisms, or full system compromise.

- [https://github.com/yonatanasd232132/talkingBen](https://github.com/yonatanasd232132/talkingBen) :  ![starts](https://img.shields.io/github/stars/yonatanasd232132/talkingBen.svg) ![forks](https://img.shields.io/github/forks/yonatanasd232132/talkingBen.svg)


## CVE-2024-31317
 In multiple functions of ZygoteProcess.java, there is a possible way to achieve code execution as any app via WRITE_SECURE_SETTINGS due to unsafe deserialization. This could lead to local escalation of privilege with User execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/wqry085/PoC-Deployer-System](https://github.com/wqry085/PoC-Deployer-System) :  ![starts](https://img.shields.io/github/stars/wqry085/PoC-Deployer-System.svg) ![forks](https://img.shields.io/github/forks/wqry085/PoC-Deployer-System.svg)


## CVE-2024-23897
 Jenkins 2.441 and earlier, LTS 2.426.2 and earlier does not disable a feature of its CLI command parser that replaces an '@' character followed by a file path in an argument with the file's contents, allowing unauthenticated attackers to read arbitrary files on the Jenkins controller file system.

- [https://github.com/aadi0258/Exploit-CVE-2024-23897](https://github.com/aadi0258/Exploit-CVE-2024-23897) :  ![starts](https://img.shields.io/github/stars/aadi0258/Exploit-CVE-2024-23897.svg) ![forks](https://img.shields.io/github/forks/aadi0258/Exploit-CVE-2024-23897.svg)


## CVE-2023-4944
 The Awesome Weather Widget for WordPress plugin for WordPress is vulnerable to Stored Cross-Site Scripting via 'awesome-weather' shortcode in versions up to, and including, 3.0.2 due to insufficient input sanitization and output escaping on user supplied attributes. This makes it possible for authenticated attackers with contributor-level and above permissions to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.

- [https://github.com/KernelCipher/CVE-2023-49440-POC](https://github.com/KernelCipher/CVE-2023-49440-POC) :  ![starts](https://img.shields.io/github/stars/KernelCipher/CVE-2023-49440-POC.svg) ![forks](https://img.shields.io/github/forks/KernelCipher/CVE-2023-49440-POC.svg)


## CVE-2022-39299
 Passport-SAML is a SAML 2.0 authentication provider for Passport, the Node.js authentication library. A remote attacker may be able to bypass SAML authentication on a website using passport-saml. A successful attack requires that the attacker is in possession of an arbitrary IDP signed XML element. Depending on the IDP used, fully unauthenticated attacks (e.g without access to a valid user) might also be feasible if generation of a signed message can be triggered. Users should upgrade to passport-saml version 3.2.2 or newer. The issue was also present in the beta releases of `node-saml` before version 4.0.0-beta.5. If you cannot upgrade, disabling SAML authentication may be done as a workaround.

- [https://github.com/KaztoRay/CVE-2022-39299-Research](https://github.com/KaztoRay/CVE-2022-39299-Research) :  ![starts](https://img.shields.io/github/stars/KaztoRay/CVE-2022-39299-Research.svg) ![forks](https://img.shields.io/github/forks/KaztoRay/CVE-2022-39299-Research.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/RizqiSec/CVE-2021-41773](https://github.com/RizqiSec/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/RizqiSec/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/RizqiSec/CVE-2021-41773.svg)
- [https://github.com/ch4os443/CVE-2021-41773](https://github.com/ch4os443/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/ch4os443/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/ch4os443/CVE-2021-41773.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/Jesrat/make_me_root](https://github.com/Jesrat/make_me_root) :  ![starts](https://img.shields.io/github/stars/Jesrat/make_me_root.svg) ![forks](https://img.shields.io/github/forks/Jesrat/make_me_root.svg)


## CVE-2020-29607
 A file upload restriction bypass vulnerability in Pluck CMS before 4.7.13 allows an admin privileged user to gain access in the host through the "manage files" functionality, which may result in remote code execution.

- [https://github.com/CaelumIsMe/CVE-2020-29607-POC](https://github.com/CaelumIsMe/CVE-2020-29607-POC) :  ![starts](https://img.shields.io/github/stars/CaelumIsMe/CVE-2020-29607-POC.svg) ![forks](https://img.shields.io/github/forks/CaelumIsMe/CVE-2020-29607-POC.svg)


## CVE-2018-15473
 OpenSSH through 7.7 is prone to a user enumeration vulnerability due to not delaying bailout for an invalid authenticating user until after the packet containing the request has been fully parsed, related to auth2-gss.c, auth2-hostbased.c, and auth2-pubkey.c.

- [https://github.com/jubeenshah/CVE-2018-15473-Exploit](https://github.com/jubeenshah/CVE-2018-15473-Exploit) :  ![starts](https://img.shields.io/github/stars/jubeenshah/CVE-2018-15473-Exploit.svg) ![forks](https://img.shields.io/github/forks/jubeenshah/CVE-2018-15473-Exploit.svg)


## CVE-2017-5638
 The Jakarta Multipart parser in Apache Struts 2 2.3.x before 2.3.32 and 2.5.x before 2.5.10.1 has incorrect exception handling and error-message generation during file-upload attempts, which allows remote attackers to execute arbitrary commands via a crafted Content-Type, Content-Disposition, or Content-Length HTTP header, as exploited in the wild in March 2017 with a Content-Type header containing a #cmd= string.

- [https://github.com/timothyjxhn/DeliberatelyVulnerableWebApp](https://github.com/timothyjxhn/DeliberatelyVulnerableWebApp) :  ![starts](https://img.shields.io/github/stars/timothyjxhn/DeliberatelyVulnerableWebApp.svg) ![forks](https://img.shields.io/github/forks/timothyjxhn/DeliberatelyVulnerableWebApp.svg)

