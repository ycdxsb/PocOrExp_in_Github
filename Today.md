# Update 2025-04-15
## CVE-2025-32395
 Vite is a frontend tooling framework for javascript. Prior to 6.2.6, 6.1.5, 6.0.15, 5.4.18, and 4.5.13, the contents of arbitrary files can be returned to the browser if the dev server is running on Node or Bun. HTTP 1.1 spec (RFC 9112) does not allow # in request-target. Although an attacker can send such a request. For those requests with an invalid request-line (it includes request-target), the spec recommends to reject them with 400 or 301. The same can be said for HTTP 2. On Node and Bun, those requests are not rejected internally and is passed to the user land. For those requests, the value of http.IncomingMessage.url contains #. Vite assumed req.url won't contain # when checking server.fs.deny, allowing those kinds of requests to bypass the check. Only apps explicitly exposing the Vite dev server to the network (using --host or server.host config option) and running the Vite dev server on runtimes that are not Deno (e.g. Node, Bun) are affected. This vulnerability is fixed in 6.2.6, 6.1.5, 6.0.15, 5.4.18, and 4.5.13.

- [https://github.com/xuemian168/CVE-2025-30208](https://github.com/xuemian168/CVE-2025-30208) :  ![starts](https://img.shields.io/github/stars/xuemian168/CVE-2025-30208.svg) ![forks](https://img.shields.io/github/forks/xuemian168/CVE-2025-30208.svg)


## CVE-2025-31125
 Vite is a frontend tooling framework for javascript. Vite exposes content of non-allowed files using ?inline&import or ?raw?import. Only apps explicitly exposing the Vite dev server to the network (using --host or server.host config option) are affected. This vulnerability is fixed in 6.2.4, 6.1.3, 6.0.13, 5.4.16, and 4.5.11.

- [https://github.com/xuemian168/CVE-2025-30208](https://github.com/xuemian168/CVE-2025-30208) :  ![starts](https://img.shields.io/github/stars/xuemian168/CVE-2025-30208.svg) ![forks](https://img.shields.io/github/forks/xuemian168/CVE-2025-30208.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/ethanol1310/POC-CVE-2025-29927-](https://github.com/ethanol1310/POC-CVE-2025-29927-) :  ![starts](https://img.shields.io/github/stars/ethanol1310/POC-CVE-2025-29927-.svg) ![forks](https://img.shields.io/github/forks/ethanol1310/POC-CVE-2025-29927-.svg)


## CVE-2025-21298
 Windows OLE Remote Code Execution Vulnerability

- [https://github.com/mr-big-leach/CVE-2025-21298](https://github.com/mr-big-leach/CVE-2025-21298) :  ![starts](https://img.shields.io/github/stars/mr-big-leach/CVE-2025-21298.svg) ![forks](https://img.shields.io/github/forks/mr-big-leach/CVE-2025-21298.svg)


## CVE-2024-5359
 A vulnerability was found in PHPGurukul Zoo Management System 2.1. It has been classified as critical. This affects an unknown part of the file /admin/foreigner-search.php. The manipulation of the argument searchdata leads to sql injection. It is possible to initiate the attack remotely. The exploit has been disclosed to the public and may be used. The associated identifier of this vulnerability is VDB-266271.

- [https://github.com/aljoharasubaie/CVE-2024-53591](https://github.com/aljoharasubaie/CVE-2024-53591) :  ![starts](https://img.shields.io/github/stars/aljoharasubaie/CVE-2024-53591.svg) ![forks](https://img.shields.io/github/forks/aljoharasubaie/CVE-2024-53591.svg)


## CVE-2024-4367
 A type check was missing when handling fonts in PDF.js, which would allow arbitrary JavaScript execution in the PDF.js context. This vulnerability affects Firefox  126, Firefox ESR  115.11, and Thunderbird  115.11.

- [https://github.com/Bhavyakcwestern/Hacking-pdf.js-vulnerability](https://github.com/Bhavyakcwestern/Hacking-pdf.js-vulnerability) :  ![starts](https://img.shields.io/github/stars/Bhavyakcwestern/Hacking-pdf.js-vulnerability.svg) ![forks](https://img.shields.io/github/forks/Bhavyakcwestern/Hacking-pdf.js-vulnerability.svg)


## CVE-2024-0582
 A memory leak flaw was found in the Linux kernel’s io_uring functionality in how a user registers a buffer ring with IORING_REGISTER_PBUF_RING, mmap() it, and then frees it. This flaw allows a local user to crash or potentially escalate their privileges on the system.

- [https://github.com/kuzeyardabulut/CVE-2024-0582](https://github.com/kuzeyardabulut/CVE-2024-0582) :  ![starts](https://img.shields.io/github/stars/kuzeyardabulut/CVE-2024-0582.svg) ![forks](https://img.shields.io/github/forks/kuzeyardabulut/CVE-2024-0582.svg)


## CVE-2023-46818
 An issue was discovered in ISPConfig before 3.2.11p1. PHP code injection can be achieved in the language file editor by an admin if admin_allow_langedit is enabled.

- [https://github.com/blindma1den/CVE-2023-46818-Exploit](https://github.com/blindma1den/CVE-2023-46818-Exploit) :  ![starts](https://img.shields.io/github/stars/blindma1den/CVE-2023-46818-Exploit.svg) ![forks](https://img.shields.io/github/forks/blindma1den/CVE-2023-46818-Exploit.svg)
- [https://github.com/ajdumanhug/CVE-2023-46818](https://github.com/ajdumanhug/CVE-2023-46818) :  ![starts](https://img.shields.io/github/stars/ajdumanhug/CVE-2023-46818.svg) ![forks](https://img.shields.io/github/forks/ajdumanhug/CVE-2023-46818.svg)


## CVE-2023-45878
 GibbonEdu Gibbon version 25.0.1 and before allows Arbitrary File Write because rubrics_visualise_saveAjax.phps does not require authentication. The endpoint accepts the img, path, and gibbonPersonID parameters. The img parameter is expected to be a base64 encoded image. If the path parameter is set, the defined path is used as the destination folder, concatenated with the absolute path of the installation directory. The content of the img parameter is base64 decoded and written to the defined file path. This allows creation of PHP files that permit Remote Code Execution (unauthenticated).

- [https://github.com/Can0I0Ever0Enter/CVE-2023-45878](https://github.com/Can0I0Ever0Enter/CVE-2023-45878) :  ![starts](https://img.shields.io/github/stars/Can0I0Ever0Enter/CVE-2023-45878.svg) ![forks](https://img.shields.io/github/forks/Can0I0Ever0Enter/CVE-2023-45878.svg)


## CVE-2023-35085
Update the UniFi Switches to Version 6.5.59 or later.

- [https://github.com/maoruiQa/CVE-2023-35085-POC-EXP](https://github.com/maoruiQa/CVE-2023-35085-POC-EXP) :  ![starts](https://img.shields.io/github/stars/maoruiQa/CVE-2023-35085-POC-EXP.svg) ![forks](https://img.shields.io/github/forks/maoruiQa/CVE-2023-35085-POC-EXP.svg)


## CVE-2023-27350
 This vulnerability allows remote attackers to bypass authentication on affected installations of PaperCut NG 22.0.5 (Build 63914). Authentication is not required to exploit this vulnerability. The specific flaw exists within the SetupCompleted class. The issue results from improper access control. An attacker can leverage this vulnerability to bypass authentication and execute arbitrary code in the context of SYSTEM. Was ZDI-CAN-18987.

- [https://github.com/0xB0y426/CVE-2023-27350-PoC](https://github.com/0xB0y426/CVE-2023-27350-PoC) :  ![starts](https://img.shields.io/github/stars/0xB0y426/CVE-2023-27350-PoC.svg) ![forks](https://img.shields.io/github/forks/0xB0y426/CVE-2023-27350-PoC.svg)


## CVE-2023-3128
This leads to account takeover and authentication bypass when Azure AD OAuth is configured with a multi-tenant app.

- [https://github.com/spyata123/CVE-2023-3128](https://github.com/spyata123/CVE-2023-3128) :  ![starts](https://img.shields.io/github/stars/spyata123/CVE-2023-3128.svg) ![forks](https://img.shields.io/github/forks/spyata123/CVE-2023-3128.svg)


## CVE-2011-2523
 vsftpd 2.3.4 downloaded between 20110630 and 20110703 contains a backdoor which opens a shell on port 6200/tcp.

- [https://github.com/JohanMV/explotacion-vsftpd-nmap_Laboratorio_1](https://github.com/JohanMV/explotacion-vsftpd-nmap_Laboratorio_1) :  ![starts](https://img.shields.io/github/stars/JohanMV/explotacion-vsftpd-nmap_Laboratorio_1.svg) ![forks](https://img.shields.io/github/forks/JohanMV/explotacion-vsftpd-nmap_Laboratorio_1.svg)

