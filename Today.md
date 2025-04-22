# Update 2025-04-22
## CVE-2025-43929
 open_actions.py in kitty before 0.41.0 does not ask for user confirmation before running a local executable file that may have been linked from an untrusted document (e.g., a document opened in KDE ghostwriter).

- [https://github.com/0xBenCantCode/CVE-2025-43929](https://github.com/0xBenCantCode/CVE-2025-43929) :  ![starts](https://img.shields.io/github/stars/0xBenCantCode/CVE-2025-43929.svg) ![forks](https://img.shields.io/github/forks/0xBenCantCode/CVE-2025-43929.svg)


## CVE-2025-43921
 GNU Mailman 2.1.39, as bundled in cPanel (and WHM), allows unauthenticated attackers to create lists via the /mailman/create endpoint.

- [https://github.com/0NYX-MY7H/CVE-2025-43921](https://github.com/0NYX-MY7H/CVE-2025-43921) :  ![starts](https://img.shields.io/github/stars/0NYX-MY7H/CVE-2025-43921.svg) ![forks](https://img.shields.io/github/forks/0NYX-MY7H/CVE-2025-43921.svg)


## CVE-2025-43920
 GNU Mailman 2.1.39, as bundled in cPanel (and WHM), allows unauthenticated attackers to execute arbitrary OS commands via shell metacharacters in an email Subject line.

- [https://github.com/0NYX-MY7H/CVE-2025-43920](https://github.com/0NYX-MY7H/CVE-2025-43920) :  ![starts](https://img.shields.io/github/stars/0NYX-MY7H/CVE-2025-43920.svg) ![forks](https://img.shields.io/github/forks/0NYX-MY7H/CVE-2025-43920.svg)


## CVE-2025-43919
 GNU Mailman 2.1.39, as bundled in cPanel (and WHM), allows unauthenticated attackers to read arbitrary files via ../ directory traversal at /mailman/private/mailman (aka the private archive authentication endpoint) via the username parameter.

- [https://github.com/0NYX-MY7H/CVE-2025-43919](https://github.com/0NYX-MY7H/CVE-2025-43919) :  ![starts](https://img.shields.io/github/stars/0NYX-MY7H/CVE-2025-43919.svg) ![forks](https://img.shields.io/github/forks/0NYX-MY7H/CVE-2025-43919.svg)


## CVE-2025-3102
 The SureTriggers: All-in-One Automation Platform plugin for WordPress is vulnerable to an authentication bypass leading to administrative account creation due to a missing empty value check on the 'secret_key' value in the 'autheticate_user' function in all versions up to, and including, 1.0.78. This makes it possible for unauthenticated attackers to create administrator accounts on the target website when the plugin is installed and activated but not configured with an API key.

- [https://github.com/dennisec/CVE-2025-3102](https://github.com/dennisec/CVE-2025-3102) :  ![starts](https://img.shields.io/github/stars/dennisec/CVE-2025-3102.svg) ![forks](https://img.shields.io/github/forks/dennisec/CVE-2025-3102.svg)


## CVE-2025-0054
 SAP NetWeaver Application Server Java does not sufficiently handle user input, resulting in a stored cross-site scripting vulnerability. The application allows attackers with basic user privileges to store a Javascript payload on the server, which could be later executed in the victim's web browser. With this the attacker might be able to read or modify information associated with the vulnerable web page.

- [https://github.com/z3usx01/CVE-2025-0054](https://github.com/z3usx01/CVE-2025-0054) :  ![starts](https://img.shields.io/github/stars/z3usx01/CVE-2025-0054.svg) ![forks](https://img.shields.io/github/forks/z3usx01/CVE-2025-0054.svg)


## CVE-2024-4577
 In PHP versions 8.1.* before 8.1.29, 8.2.* before 8.2.20, 8.3.* before 8.3.8, when using Apache and PHP-CGI on Windows, if the system is set up to use certain code pages, Windows may use "Best-Fit" behavior to replace characters in command line given to Win32 API functions. PHP CGI module may misinterpret those characters as PHP options, which may allow a malicious user to pass options to PHP binary being run, and thus reveal the source code of scripts, run arbitrary PHP code on the server, etc.

- [https://github.com/cheerfulempl/CVE-2024-4577-PHP-RCE](https://github.com/cheerfulempl/CVE-2024-4577-PHP-RCE) :  ![starts](https://img.shields.io/github/stars/cheerfulempl/CVE-2024-4577-PHP-RCE.svg) ![forks](https://img.shields.io/github/forks/cheerfulempl/CVE-2024-4577-PHP-RCE.svg)


## CVE-2023-50257
 eProsima Fast DDS (formerly Fast RTPS) is a C++ implementation of the Data Distribution Service standard of the Object Management Group. Even with the application of SROS2, due to the issue where the data (`p[UD]`) and `guid` values used to disconnect between nodes are not encrypted, a vulnerability has been discovered where a malicious attacker can forcibly disconnect a Subscriber and can deny a Subscriber attempting to connect. Afterwards, if the attacker sends the packet for disconnecting, which is data (`p[UD]`), to the Global Data Space (`239.255.0.1:7400`) using the said Publisher ID, all the Subscribers (Listeners) connected to the Publisher (Talker) will not receive any data and their connection will be disconnected. Moreover, if this disconnection packet is sent continuously, the Subscribers (Listeners) trying to connect will not be able to do so. Since the initial commit of the `SecurityManager.cpp` code (`init`, `on_process_handshake`) on Nov 8, 2016, the Disconnect Vulnerability in RTPS Packets Used by SROS2 has been present prior to versions 2.13.0, 2.12.2, 2.11.3, 2.10.3, and 2.6.7.

- [https://github.com/Jminis/CVE-2023-50257](https://github.com/Jminis/CVE-2023-50257) :  ![starts](https://img.shields.io/github/stars/Jminis/CVE-2023-50257.svg) ![forks](https://img.shields.io/github/forks/Jminis/CVE-2023-50257.svg)


## CVE-2023-43770
 Roundcube before 1.4.14, 1.5.x before 1.5.4, and 1.6.x before 1.6.3 allows XSS via text/plain e-mail messages with crafted links because of program/lib/Roundcube/rcube_string_replacer.php behavior.

- [https://github.com/skyllpro/CVE-2021-44026-PoC](https://github.com/skyllpro/CVE-2021-44026-PoC) :  ![starts](https://img.shields.io/github/stars/skyllpro/CVE-2021-44026-PoC.svg) ![forks](https://img.shields.io/github/forks/skyllpro/CVE-2021-44026-PoC.svg)


## CVE-2023-32233
 In the Linux kernel through 6.3.1, a use-after-free in Netfilter nf_tables when processing batch requests can be abused to perform arbitrary read and write operations on kernel memory. Unprivileged local users can obtain root privileges. This occurs because anonymous sets are mishandled.

- [https://github.com/mr-spongebob/a-CVE-2023-32233](https://github.com/mr-spongebob/a-CVE-2023-32233) :  ![starts](https://img.shields.io/github/stars/mr-spongebob/a-CVE-2023-32233.svg) ![forks](https://img.shields.io/github/forks/mr-spongebob/a-CVE-2023-32233.svg)


## CVE-2023-21554
 Microsoft Message Queuing (MSMQ) Remote Code Execution Vulnerability

- [https://github.com/leongxudong/MSMQ-Vulnerability](https://github.com/leongxudong/MSMQ-Vulnerability) :  ![starts](https://img.shields.io/github/stars/leongxudong/MSMQ-Vulnerability.svg) ![forks](https://img.shields.io/github/forks/leongxudong/MSMQ-Vulnerability.svg)


## CVE-2021-41788
 MediaTek microchips, as used in NETGEAR devices through 2021-12-13 and other devices, mishandle attempts at Wi-Fi authentication flooding. (Affected Chipsets MT7603E, MT7612, MT7613, MT7615, MT7622, MT7628, MT7629, MT7915; Affected Software Versions 7.4.0.0).

- [https://github.com/efchatz/easy-exploits](https://github.com/efchatz/easy-exploits) :  ![starts](https://img.shields.io/github/stars/efchatz/easy-exploits.svg) ![forks](https://img.shields.io/github/forks/efchatz/easy-exploits.svg)


## CVE-2021-41437
 An HTTP response splitting attack in web application in ASUS RT-AX88U before v3.0.0.4.388.20558 allows an attacker to craft a specific URL that if an authenticated victim visits it, the URL will give access to the cloud storage of the attacker.

- [https://github.com/efchatz/easy-exploits](https://github.com/efchatz/easy-exploits) :  ![starts](https://img.shields.io/github/stars/efchatz/easy-exploits.svg) ![forks](https://img.shields.io/github/forks/efchatz/easy-exploits.svg)


## CVE-2021-41160
 FreeRDP is a free implementation of the Remote Desktop Protocol (RDP), released under the Apache license. In affected versions a malicious server might trigger out of bound writes in a connected client. Connections using GDI or SurfaceCommands to send graphics updates to the client might send `0` width/height or out of bound rectangles to trigger out of bound writes. With `0` width or heigth the memory allocation will be `0` but the missing bounds checks allow writing to the pointer at this (not allocated) region. This issue has been patched in FreeRDP 2.4.1.

- [https://github.com/Jajangjaman/CVE-2021-41160](https://github.com/Jajangjaman/CVE-2021-41160) :  ![starts](https://img.shields.io/github/stars/Jajangjaman/CVE-2021-41160.svg) ![forks](https://img.shields.io/github/forks/Jajangjaman/CVE-2021-41160.svg)


## CVE-2020-0796
 A remote code execution vulnerability exists in the way that the Microsoft Server Message Block 3.1.1 (SMBv3) protocol handles certain requests, aka 'Windows SMBv3 Client/Server Remote Code Execution Vulnerability'.

- [https://github.com/DannyRavi/nmap-scripts](https://github.com/DannyRavi/nmap-scripts) :  ![starts](https://img.shields.io/github/stars/DannyRavi/nmap-scripts.svg) ![forks](https://img.shields.io/github/forks/DannyRavi/nmap-scripts.svg)


## CVE-2019-7238
 Sonatype Nexus Repository Manager before 3.15.0 has Incorrect Access Control.

- [https://github.com/DannyRavi/nmap-scripts](https://github.com/DannyRavi/nmap-scripts) :  ![starts](https://img.shields.io/github/stars/DannyRavi/nmap-scripts.svg) ![forks](https://img.shields.io/github/forks/DannyRavi/nmap-scripts.svg)


## CVE-2017-10910
 MQTT.js 2.x.x prior to 2.15.0 issue in handling PUBLISH tickets may lead to an attacker causing a denial-of-service condition.

- [https://github.com/ossf-cve-benchmark/CVE-2017-10910](https://github.com/ossf-cve-benchmark/CVE-2017-10910) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-10910.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-10910.svg)

