# Update 2025-09-28
## CVE-2025-56383
 Notepad++ v8.8.3 has a DLL hijacking vulnerability, which can replace the original DLL file to execute malicious code.

- [https://github.com/zer0t0/CVE-2025-56383-Proof-of-Concept](https://github.com/zer0t0/CVE-2025-56383-Proof-of-Concept) :  ![starts](https://img.shields.io/github/stars/zer0t0/CVE-2025-56383-Proof-of-Concept.svg) ![forks](https://img.shields.io/github/forks/zer0t0/CVE-2025-56383-Proof-of-Concept.svg)


## CVE-2025-39866
wb_wakeup_delayed() finished.

- [https://github.com/byteReaper77/CVE-2025-39866](https://github.com/byteReaper77/CVE-2025-39866) :  ![starts](https://img.shields.io/github/stars/byteReaper77/CVE-2025-39866.svg) ![forks](https://img.shields.io/github/forks/byteReaper77/CVE-2025-39866.svg)


## CVE-2025-31161
 CrushFTP 10 before 10.8.4 and 11 before 11.3.1 allows authentication bypass and takeover of the crushadmin account (unless a DMZ proxy instance is used), as exploited in the wild in March and April 2025, aka "Unauthenticated HTTP(S) port access." A race condition exists in the AWS4-HMAC (compatible with S3) authorization method of the HTTP component of the FTP server. The server first verifies the existence of the user by performing a call to login_user_pass() with no password requirement. This will authenticate the session through the HMAC verification process and up until the server checks for user verification once more. The vulnerability can be further stabilized, eliminating the need for successfully triggering a race condition, by sending a mangled AWS4-HMAC header. By providing only the username and a following slash (/), the server will successfully find a username, which triggers the successful anypass authentication process, but the server will fail to find the expected SignedHeaders entry, resulting in an index-out-of-bounds error that stops the code from reaching the session cleanup. Together, these issues make it trivial to authenticate as any known or guessable user (e.g., crushadmin), and can lead to a full compromise of the system by obtaining an administrative account.

- [https://github.com/Teexo/CVE-2025-31161](https://github.com/Teexo/CVE-2025-31161) :  ![starts](https://img.shields.io/github/stars/Teexo/CVE-2025-31161.svg) ![forks](https://img.shields.io/github/forks/Teexo/CVE-2025-31161.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/Viperazor/CVE-2025-29927-Research](https://github.com/Viperazor/CVE-2025-29927-Research) :  ![starts](https://img.shields.io/github/stars/Viperazor/CVE-2025-29927-Research.svg) ![forks](https://img.shields.io/github/forks/Viperazor/CVE-2025-29927-Research.svg)


## CVE-2025-22777
 Deserialization of Untrusted Data vulnerability in GiveWP GiveWP allows Object Injection.This issue affects GiveWP: from n/a through 3.19.3.

- [https://github.com/RandomRobbieBF/CVE-2025-22777](https://github.com/RandomRobbieBF/CVE-2025-22777) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2025-22777.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2025-22777.svg)


## CVE-2025-8422
 The Propovoice: All-in-One Client Management System plugin for WordPress is vulnerable to Arbitrary File Read in all versions up to, and including, 1.7.6.7 via the send_email() function. This makes it possible for unauthenticated attackers to read the contents of arbitrary files on the server, which can contain sensitive information.

- [https://github.com/RandomRobbieBF/CVE-2025-8422](https://github.com/RandomRobbieBF/CVE-2025-8422) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2025-8422.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2025-8422.svg)


## CVE-2025-8088
     from ESET.

- [https://github.com/kyomber/CVE-2025-8088](https://github.com/kyomber/CVE-2025-8088) :  ![starts](https://img.shields.io/github/stars/kyomber/CVE-2025-8088.svg) ![forks](https://img.shields.io/github/forks/kyomber/CVE-2025-8088.svg)


## CVE-2025-7771
 ThrottleStop.sys, a legitimate driver, exposes two IOCTL interfaces that allow arbitrary read and write access to physical memory via the MmMapIoSpace function. This insecure implementation can be exploited by a malicious user-mode application to patch the running Windows kernel and invoke arbitrary kernel functions with ring-0 privileges. The vulnerability enables local attackers to execute arbitrary code in kernel context, resulting in privilege escalation and potential follow-on attacks, such as disabling security software or bypassing kernel-level protections. ThrottleStop.sys version 3.0.0.0 and possibly others are affected. Apply updates per vendor instructions.

- [https://github.com/fxrstor/ThrottleStopPoC](https://github.com/fxrstor/ThrottleStopPoC) :  ![starts](https://img.shields.io/github/stars/fxrstor/ThrottleStopPoC.svg) ![forks](https://img.shields.io/github/forks/fxrstor/ThrottleStopPoC.svg)


## CVE-2025-6384
This issue affects CrafterCMS: from 4.0.0 through 4.2.2.

- [https://github.com/maestro-ant/CrafterCMS-CVE-2025-6384](https://github.com/maestro-ant/CrafterCMS-CVE-2025-6384) :  ![starts](https://img.shields.io/github/stars/maestro-ant/CrafterCMS-CVE-2025-6384.svg) ![forks](https://img.shields.io/github/forks/maestro-ant/CrafterCMS-CVE-2025-6384.svg)


## CVE-2025-5679
 A vulnerability classified as critical has been found in Shenzhen Dashi Tongzhou Information Technology AgileBPM up to 2.5.0. Affected is the function parseStrByFreeMarker of the file /src/main/java/com/dstz/sys/rest/controller/SysToolsController.java. The manipulation of the argument str leads to deserialization. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/B1tBreaker/CVE-2025-56795](https://github.com/B1tBreaker/CVE-2025-56795) :  ![starts](https://img.shields.io/github/stars/B1tBreaker/CVE-2025-56795.svg) ![forks](https://img.shields.io/github/forks/B1tBreaker/CVE-2025-56795.svg)


## CVE-2025-5581
 A vulnerability was found in CodeAstro Real Estate Management System 1.0. It has been declared as critical. This vulnerability affects unknown code of the file /admin/index.php. The manipulation of the argument User leads to sql injection. The attack can be initiated remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/5qu1n7/CVE-2025-55817](https://github.com/5qu1n7/CVE-2025-55817) :  ![starts](https://img.shields.io/github/stars/5qu1n7/CVE-2025-55817.svg) ![forks](https://img.shields.io/github/forks/5qu1n7/CVE-2025-55817.svg)


## CVE-2025-5419
 Out of bounds read and write in V8 in Google Chrome prior to 137.0.7151.68 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/somprasong-tukman/CVE-2025-5419](https://github.com/somprasong-tukman/CVE-2025-5419) :  ![starts](https://img.shields.io/github/stars/somprasong-tukman/CVE-2025-5419.svg) ![forks](https://img.shields.io/github/forks/somprasong-tukman/CVE-2025-5419.svg)


## CVE-2025-4840
 The inprosysmedia-likes-dislikes-post WordPress plugin through 1.0.0 does not properly sanitise and escape a parameter before using it in a SQL statement via an AJAX action available to unauthenticated users, leading to a SQL injection

- [https://github.com/RandomRobbieBF/CVE-2025-4840](https://github.com/RandomRobbieBF/CVE-2025-4840) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2025-4840.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2025-4840.svg)


## CVE-2025-3515
 The Drag and Drop Multiple File Upload for Contact Form 7 plugin for WordPress is vulnerable to arbitrary file uploads due to insufficient file type validation in all versions up to, and including, 1.3.8.9. This makes it possible for unauthenticated attackers to bypass the plugin's blacklist and upload .phar or other dangerous file types on the affected site's server, which may make remote code execution possible on the servers that are configured to handle .phar files as executable PHP scripts, particularly in default Apache+mod_php configurations where the file extension is not strictly validated before being passed to the PHP interpreter.

- [https://github.com/robertskimengote/lab-cve-2025-3515](https://github.com/robertskimengote/lab-cve-2025-3515) :  ![starts](https://img.shields.io/github/stars/robertskimengote/lab-cve-2025-3515.svg) ![forks](https://img.shields.io/github/forks/robertskimengote/lab-cve-2025-3515.svg)


## CVE-2024-13184
 The The Ultimate WordPress Toolkit – WP Extended plugin for WordPress is vulnerable to time-based SQL Injection via the Login Attempts module in all versions up to, and including, 3.0.12 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query.  This makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database.

- [https://github.com/RandomRobbieBF/CVE-2024-13184](https://github.com/RandomRobbieBF/CVE-2024-13184) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-13184.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-13184.svg)


## CVE-2024-12877
 The GiveWP – Donation Plugin and Fundraising Platform plugin for WordPress is vulnerable to PHP Object Injection in all versions up to, and including, 3.19.2 via deserialization of untrusted input from the donation form like 'firstName'. This makes it possible for unauthenticated attackers to inject a PHP Object. The additional presence of a POP chain allows attackers to delete arbitrary files on the server that makes remote code execution possible. Please note this was only partially patched in 3.19.3, a fully sufficient patch was not released until 3.19.4. However, another CVE was assigned by another CNA for version 3.19.3 so we will leave this as affecting 3.19.2 and before. We have recommended the vendor use JSON encoding to prevent any further deserialization vulnerabilities from being present.

- [https://github.com/RandomRobbieBF/CVE-2024-12877](https://github.com/RandomRobbieBF/CVE-2024-12877) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-12877.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-12877.svg)


## CVE-2024-0582
 A memory leak flaw was found in the Linux kernel’s io_uring functionality in how a user registers a buffer ring with IORING_REGISTER_PBUF_RING, mmap() it, and then frees it. This flaw allows a local user to crash or potentially escalate their privileges on the system.

- [https://github.com/pwnmonk/io_uring-n-day](https://github.com/pwnmonk/io_uring-n-day) :  ![starts](https://img.shields.io/github/stars/pwnmonk/io_uring-n-day.svg) ![forks](https://img.shields.io/github/forks/pwnmonk/io_uring-n-day.svg)


## CVE-2023-45612
 In JetBrains Ktor before 2.3.5 default configuration of ContentNegotiation with XML format was vulnerable to XXE

- [https://github.com/bbugdigger/ktor-xxe-poc](https://github.com/bbugdigger/ktor-xxe-poc) :  ![starts](https://img.shields.io/github/stars/bbugdigger/ktor-xxe-poc.svg) ![forks](https://img.shields.io/github/forks/bbugdigger/ktor-xxe-poc.svg)


## CVE-2023-36802
 Microsoft Streaming Service Proxy Elevation of Privilege Vulnerability

- [https://github.com/rahul0xkr/Reproducing-CVE-2023-36802](https://github.com/rahul0xkr/Reproducing-CVE-2023-36802) :  ![starts](https://img.shields.io/github/stars/rahul0xkr/Reproducing-CVE-2023-36802.svg) ![forks](https://img.shields.io/github/forks/rahul0xkr/Reproducing-CVE-2023-36802.svg)


## CVE-2023-1405
 The Formidable Forms WordPress plugin before 6.2 unserializes user input, which could allow anonymous users to perform PHP Object Injection when a suitable gadget is present.

- [https://github.com/RandomRobbieBF/CVE-2023-1405](https://github.com/RandomRobbieBF/CVE-2023-1405) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2023-1405.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2023-1405.svg)


## CVE-2022-39299
 Passport-SAML is a SAML 2.0 authentication provider for Passport, the Node.js authentication library. A remote attacker may be able to bypass SAML authentication on a website using passport-saml. A successful attack requires that the attacker is in possession of an arbitrary IDP signed XML element. Depending on the IDP used, fully unauthenticated attacks (e.g without access to a valid user) might also be feasible if generation of a signed message can be triggered. Users should upgrade to passport-saml version 3.2.2 or newer. The issue was also present in the beta releases of `node-saml` before version 4.0.0-beta.5. If you cannot upgrade, disabling SAML authentication may be done as a workaround.

- [https://github.com/Viperazor/CVE-2022-39299-Research](https://github.com/Viperazor/CVE-2022-39299-Research) :  ![starts](https://img.shields.io/github/stars/Viperazor/CVE-2022-39299-Research.svg) ![forks](https://img.shields.io/github/forks/Viperazor/CVE-2022-39299-Research.svg)

