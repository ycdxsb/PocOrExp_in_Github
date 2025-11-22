# Update 2025-11-22
## CVE-2025-64446
 A relative path traversal vulnerability in Fortinet FortiWeb 8.0.0 through 8.0.1, FortiWeb 7.6.0 through 7.6.4, FortiWeb 7.4.0 through 7.4.9, FortiWeb 7.2.0 through 7.2.11, FortiWeb 7.0.0 through 7.0.11 may allow an attacker to execute administrative commands on the system via crafted HTTP or HTTPS requests.

- [https://github.com/lincemorado97/CVE-2025-64446_CVE-2025-58034](https://github.com/lincemorado97/CVE-2025-64446_CVE-2025-58034) :  ![starts](https://img.shields.io/github/stars/lincemorado97/CVE-2025-64446_CVE-2025-58034.svg) ![forks](https://img.shields.io/github/forks/lincemorado97/CVE-2025-64446_CVE-2025-58034.svg)


## CVE-2025-64027
 Snipe-IT v8.3.4 (build 20218) contains a reflected cross-site scripting (XSS) vulnerability in the CSV Import workflow. When an invalid CSV file is uploaded, the application returns a progress_message value that is rendered as raw HTML in the admin interface. An attacker can intercept and modify the POST /livewire/update request to inject arbitrary HTML or JavaScript into the progress_message. Because the server accepts the modified input without sanitization and reflects it back to the user, arbitrary JavaScript executes in the browser of any authenticated admin who views the import page.

- [https://github.com/cybercrewinc/CVE-2025-64027](https://github.com/cybercrewinc/CVE-2025-64027) :  ![starts](https://img.shields.io/github/stars/cybercrewinc/CVE-2025-64027.svg) ![forks](https://img.shields.io/github/forks/cybercrewinc/CVE-2025-64027.svg)


## CVE-2025-63888
 The read function in file thinkphp\library\think\template\driver\File.php in ThinkPHP 5.0.24 contains a remote code execution vulnerability.

- [https://github.com/AN5I/cve-2025-63888-exploit](https://github.com/AN5I/cve-2025-63888-exploit) :  ![starts](https://img.shields.io/github/stars/AN5I/cve-2025-63888-exploit.svg) ![forks](https://img.shields.io/github/forks/AN5I/cve-2025-63888-exploit.svg)


## CVE-2025-63848
 Stored cross site scripting (xss) vulnerability in SWISH prolog thru 2.2.0 allowing attackers to execute arbitrary code via crafted web IDE notebook.

- [https://github.com/coderMohammed1/CVE-2025-63848](https://github.com/coderMohammed1/CVE-2025-63848) :  ![starts](https://img.shields.io/github/stars/coderMohammed1/CVE-2025-63848.svg) ![forks](https://img.shields.io/github/forks/coderMohammed1/CVE-2025-63848.svg)


## CVE-2025-63708
 Cross-Site Scripting (XSS) vulnerability exists in SourceCodester AI Font Matcher (nid=18425, 2025-10-10) that allows remote attackers to execute arbitrary JavaScript in victims' browsers. The vulnerability occurs in the webfonts API handling mechanism where font family names are not properly sanitized. An attacker can intercept fetch requests to the webfonts endpoint and inject malicious JavaScript payloads through font family names, resulting in session cookie theft, account hijacking, and unauthorized actions performed on behalf of authenticated users. The vulnerability can be exploited by injecting a fetch hook that returns controlled font data containing malicious scripts.

- [https://github.com/DylanDavis1/CVE-2025-63708](https://github.com/DylanDavis1/CVE-2025-63708) :  ![starts](https://img.shields.io/github/stars/DylanDavis1/CVE-2025-63708.svg) ![forks](https://img.shields.io/github/forks/DylanDavis1/CVE-2025-63708.svg)


## CVE-2025-63700
 An issue was discovered in Clerk-js 5.88.0 allowing attackers to bypass the OAuth authentication flow by manipulating the request at the OTP verification stage.

- [https://github.com/itsnishat08/CVE-2025-63700](https://github.com/itsnishat08/CVE-2025-63700) :  ![starts](https://img.shields.io/github/stars/itsnishat08/CVE-2025-63700.svg) ![forks](https://img.shields.io/github/forks/itsnishat08/CVE-2025-63700.svg)


## CVE-2025-61765
 python-socketio is a Python implementation of the Socket.IO realtime client and server. A remote code execution vulnerability in python-socketio versions prior to 5.14.0 allows attackers to execute arbitrary Python code through malicious pickle deserialization in multi-server deployments on which the attacker previously gained access to the message queue that the servers use for internal communications. When Socket.IO servers are configured to use a message queue backend such as Redis for inter-server communication, messages sent between the servers are encoded using the `pickle` Python module. When a server receives one of these messages through the message queue, it assumes it is trusted and immediately deserializes it. The vulnerability stems from deserialization of messages using Python's `pickle.loads()` function. Having previously obtained access to the message queue, the attacker can send a python-socketio server a crafted pickle payload that executes arbitrary code during deserialization via Python's `__reduce__` method. This vulnerability only affects deployments with a compromised message queue. The attack can lead to the attacker executing random code in the context of, and with the privileges of a Socket.IO server process. Single-server systems that do not use a message queue, and multi-server systems with a secure message queue are not vulnerable. In addition to making sure standard security practices are followed in the deployment of the message queue, users of the python-socketio package can upgrade to version 5.14.0 or newer, which remove the `pickle` module and use the much safer JSON encoding for inter-server messaging.

- [https://github.com/locus-x64/CVE-2025-61765_PoC](https://github.com/locus-x64/CVE-2025-61765_PoC) :  ![starts](https://img.shields.io/github/stars/locus-x64/CVE-2025-61765_PoC.svg) ![forks](https://img.shields.io/github/forks/locus-x64/CVE-2025-61765_PoC.svg)


## CVE-2025-61757
 Vulnerability in the Identity Manager product of Oracle Fusion Middleware (component: REST WebServices).  Supported versions that are affected are 12.2.1.4.0 and  14.1.2.1.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Identity Manager.  Successful attacks of this vulnerability can result in takeover of Identity Manager. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/B1ack4sh/Blackash-CVE-2025-61757](https://github.com/B1ack4sh/Blackash-CVE-2025-61757) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-61757.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-61757.svg)


## CVE-2025-59501
 Authentication bypass by spoofing in Microsoft Configuration Manager allows an authorized attacker to perform spoofing over an adjacent network.

- [https://github.com/garrettfoster13/CVE-2025-59501](https://github.com/garrettfoster13/CVE-2025-59501) :  ![starts](https://img.shields.io/github/stars/garrettfoster13/CVE-2025-59501.svg) ![forks](https://img.shields.io/github/forks/garrettfoster13/CVE-2025-59501.svg)


## CVE-2025-59287
 Deserialization of untrusted data in Windows Server Update Service allows an unauthorized attacker to execute code over a network.

- [https://github.com/Adel-kaka-dz/cve-2025-59287](https://github.com/Adel-kaka-dz/cve-2025-59287) :  ![starts](https://img.shields.io/github/stars/Adel-kaka-dz/cve-2025-59287.svg) ![forks](https://img.shields.io/github/forks/Adel-kaka-dz/cve-2025-59287.svg)


## CVE-2025-58034
 An Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') vulnerability [CWE-78] vulnerability in Fortinet FortiWeb 8.0.0 through 8.0.1, FortiWeb 7.6.0 through 7.6.5, FortiWeb 7.4.0 through 7.4.10, FortiWeb 7.2.0 through 7.2.11, FortiWeb 7.0.0 through 7.0.11 may allow an authenticated attacker to execute unauthorized code on the underlying system via crafted HTTP requests or CLI commands.

- [https://github.com/lincemorado97/CVE-2025-64446_CVE-2025-58034](https://github.com/lincemorado97/CVE-2025-64446_CVE-2025-58034) :  ![starts](https://img.shields.io/github/stars/lincemorado97/CVE-2025-64446_CVE-2025-58034.svg) ![forks](https://img.shields.io/github/forks/lincemorado97/CVE-2025-64446_CVE-2025-58034.svg)


## CVE-2025-23247
 NVIDIA CUDA Toolkit for all platforms contains a vulnerability in the cuobjdump binary, where a failure to check the length of a buffer could allow a user to cause the tool to crash or execute arbitrary code by passing in a malformed ELF file. A successful exploit of this vulnerability might lead to arbitrary code execution.

- [https://github.com/SpiralBL0CK/CVE-2025-23247](https://github.com/SpiralBL0CK/CVE-2025-23247) :  ![starts](https://img.shields.io/github/stars/SpiralBL0CK/CVE-2025-23247.svg) ![forks](https://img.shields.io/github/forks/SpiralBL0CK/CVE-2025-23247.svg)


## CVE-2025-13425
 A bug in the filesystem traversal fallback path causes fs/diriterate/diriterate.go:Next() to overindex an empty slice when ReadDir returns nil for an empty directory, resulting in a panic (index out of range) and an application crash (denial of service) in OSV-SCALIBR.

- [https://github.com/0xXA/google-poc](https://github.com/0xXA/google-poc) :  ![starts](https://img.shields.io/github/stars/0xXA/google-poc.svg) ![forks](https://img.shields.io/github/forks/0xXA/google-poc.svg)


## CVE-2025-12735
 The expr-eval library is a JavaScript expression parser and evaluator designed to safely evaluate mathematical expressions with user-defined variables. However, due to insufficient input validation, an attacker can pass a crafted context object or use MEMBER of the context object into the evaluate() function and trigger arbitrary code execution.

- [https://github.com/AN5I/cve-2025-12735-expr-eval-rce](https://github.com/AN5I/cve-2025-12735-expr-eval-rce) :  ![starts](https://img.shields.io/github/stars/AN5I/cve-2025-12735-expr-eval-rce.svg) ![forks](https://img.shields.io/github/forks/AN5I/cve-2025-12735-expr-eval-rce.svg)
- [https://github.com/alnashawatirohwederb2167-max/cve-2025-12735-expr-eval-rce](https://github.com/alnashawatirohwederb2167-max/cve-2025-12735-expr-eval-rce) :  ![starts](https://img.shields.io/github/stars/alnashawatirohwederb2167-max/cve-2025-12735-expr-eval-rce.svg) ![forks](https://img.shields.io/github/forks/alnashawatirohwederb2167-max/cve-2025-12735-expr-eval-rce.svg)


## CVE-2025-11001
The specific flaw exists within the handling of symbolic links in ZIP files. Crafted data in a ZIP file can cause the process to traverse to unintended directories. An attacker can leverage this vulnerability to execute code in the context of a service account. Was ZDI-CAN-26753.

- [https://github.com/lastvocher/7zip-CVE-2025-11001](https://github.com/lastvocher/7zip-CVE-2025-11001) :  ![starts](https://img.shields.io/github/stars/lastvocher/7zip-CVE-2025-11001.svg) ![forks](https://img.shields.io/github/forks/lastvocher/7zip-CVE-2025-11001.svg)


## CVE-2025-7892
 A vulnerability classified as problematic has been found in IDnow App up to 9.6.0 on Android. This affects an unknown part of the file AndroidManifest.xml of the component de.idnow. The manipulation leads to improper export of android application components. Local access is required to approach this attack. The exploit has been disclosed to the public and may be used. The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/FlyingLemonade/CVE-2025-7892-Proof-of-Concept-Login-Form](https://github.com/FlyingLemonade/CVE-2025-7892-Proof-of-Concept-Login-Form) :  ![starts](https://img.shields.io/github/stars/FlyingLemonade/CVE-2025-7892-Proof-of-Concept-Login-Form.svg) ![forks](https://img.shields.io/github/forks/FlyingLemonade/CVE-2025-7892-Proof-of-Concept-Login-Form.svg)


## CVE-2025-6391
 unauthorized access, session hijacking, and information disclosure.

- [https://github.com/WxDou/CVE-2025-63914](https://github.com/WxDou/CVE-2025-63914) :  ![starts](https://img.shields.io/github/stars/WxDou/CVE-2025-63914.svg) ![forks](https://img.shields.io/github/forks/WxDou/CVE-2025-63914.svg)


## CVE-2025-3248
code.

- [https://github.com/drackyjr/cve-2025-3248-exploit](https://github.com/drackyjr/cve-2025-3248-exploit) :  ![starts](https://img.shields.io/github/stars/drackyjr/cve-2025-3248-exploit.svg) ![forks](https://img.shields.io/github/forks/drackyjr/cve-2025-3248-exploit.svg)


## CVE-2025-1297
 This CVE ID has been rejected or withdrawn by its CVE Numbering Authority.

- [https://github.com/d0n601/CVE-2025-12973](https://github.com/d0n601/CVE-2025-12973) :  ![starts](https://img.shields.io/github/stars/d0n601/CVE-2025-12973.svg) ![forks](https://img.shields.io/github/forks/d0n601/CVE-2025-12973.svg)


## CVE-2025-1213
 A vulnerability was found in pihome-shc PiHome 1.77. It has been rated as problematic. Affected by this issue is some unknown functionality of the file /index.php. The manipulation of the argument $_SERVER['PHP_SELF'] leads to cross site scripting. The attack may be launched remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/d0n601/CVE-2025-12135](https://github.com/d0n601/CVE-2025-12135) :  ![starts](https://img.shields.io/github/stars/d0n601/CVE-2025-12135.svg) ![forks](https://img.shields.io/github/forks/d0n601/CVE-2025-12135.svg)


## CVE-2024-3721
 A vulnerability was found in TBK DVR-4104 and DVR-4216 up to 20240412 and classified as critical. This issue affects some unknown processing of the file /device.rsp?opt=sys&cmd=___S_O_S_T_R_E_A_MAX___. The manipulation of the argument mdb/mdc leads to os command injection. The attack may be initiated remotely. The exploit has been disclosed to the public and may be used. The identifier VDB-260573 was assigned to this vulnerability.

- [https://github.com/qalvynn/Mirai-Based-CVE-2024-3721-Selfrep](https://github.com/qalvynn/Mirai-Based-CVE-2024-3721-Selfrep) :  ![starts](https://img.shields.io/github/stars/qalvynn/Mirai-Based-CVE-2024-3721-Selfrep.svg) ![forks](https://img.shields.io/github/forks/qalvynn/Mirai-Based-CVE-2024-3721-Selfrep.svg)


## CVE-2023-38831
 RARLAB WinRAR before 6.23 allows attackers to execute arbitrary code when a user attempts to view a benign file within a ZIP archive. The issue occurs because a ZIP archive may include a benign file (such as an ordinary .JPG file) and also a folder that has the same name as the benign file, and the contents of the folder (which may include executable content) are processed during an attempt to access only the benign file. This was exploited in the wild in April through October 2023.

- [https://github.com/anelya0333/Exploiting-CVE-2023-38831](https://github.com/anelya0333/Exploiting-CVE-2023-38831) :  ![starts](https://img.shields.io/github/stars/anelya0333/Exploiting-CVE-2023-38831.svg) ![forks](https://img.shields.io/github/forks/anelya0333/Exploiting-CVE-2023-38831.svg)


## CVE-2022-22965
 A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the application to run on Tomcat as a WAR deployment. If the application is deployed as a Spring Boot executable jar, i.e. the default, it is not vulnerable to the exploit. However, the nature of the vulnerability is more general, and there may be other ways to exploit it.

- [https://github.com/mylo-2001/GhostStrike](https://github.com/mylo-2001/GhostStrike) :  ![starts](https://img.shields.io/github/stars/mylo-2001/GhostStrike.svg) ![forks](https://img.shields.io/github/forks/mylo-2001/GhostStrike.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/drackyjr/CVE-2021-42013](https://github.com/drackyjr/CVE-2021-42013) :  ![starts](https://img.shields.io/github/stars/drackyjr/CVE-2021-42013.svg) ![forks](https://img.shields.io/github/forks/drackyjr/CVE-2021-42013.svg)

