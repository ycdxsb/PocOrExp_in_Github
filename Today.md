# Update 2025-02-16
## CVE-2025-0108
This issue does not affect Cloud NGFW or Prisma Access software.

- [https://github.com/FOLKS-iwd/CVE-2025-0108-PoC](https://github.com/FOLKS-iwd/CVE-2025-0108-PoC) :  ![starts](https://img.shields.io/github/stars/FOLKS-iwd/CVE-2025-0108-PoC.svg) ![forks](https://img.shields.io/github/forks/FOLKS-iwd/CVE-2025-0108-PoC.svg)


## CVE-2024-57778
 An issue in Orbe ONetView Roeador Onet-1200 Orbe 1680210096 allows a remote attacker to escalate privileges via the servers response from status code 500 to status code 200.

- [https://github.com/KUK3N4N/CVE-2024-57778](https://github.com/KUK3N4N/CVE-2024-57778) :  ![starts](https://img.shields.io/github/stars/KUK3N4N/CVE-2024-57778.svg) ![forks](https://img.shields.io/github/forks/KUK3N4N/CVE-2024-57778.svg)


## CVE-2024-57725
 An issue in the Arcadyan Livebox Fibra PRV3399B_B_LT allows a remote or local attacker to modify the GPON link value without authentication, causing an internet service disruption via the /firstconnection.cgi endpoint.

- [https://github.com/pointedsec/CVE-2024-57725](https://github.com/pointedsec/CVE-2024-57725) :  ![starts](https://img.shields.io/github/stars/pointedsec/CVE-2024-57725.svg) ![forks](https://img.shields.io/github/forks/pointedsec/CVE-2024-57725.svg)


## CVE-2024-38819
 Applications serving static resources through the functional web frameworks WebMvc.fn or WebFlux.fn are vulnerable to path traversal attacks. An attacker can craft malicious HTTP requests and obtain any file on the file system that is also accessible to the process in which the Spring application is running.

- [https://github.com/skrkcb2/cve-2024-38819](https://github.com/skrkcb2/cve-2024-38819) :  ![starts](https://img.shields.io/github/stars/skrkcb2/cve-2024-38819.svg) ![forks](https://img.shields.io/github/forks/skrkcb2/cve-2024-38819.svg)


## CVE-2024-36401
Versions 2.23.6, 2.24.4, and 2.25.2 contain a patch for the issue. A workaround exists by removing the `gt-complex-x.y.jar` file from the GeoServer where `x.y` is the GeoTools version (e.g., `gt-complex-31.1.jar` if running GeoServer 2.25.1). This will remove the vulnerable code from GeoServer but may break some GeoServer functionality or prevent GeoServer from deploying if the gt-complex module is needed.

- [https://github.com/unlinedvol/CVE-2024-36401](https://github.com/unlinedvol/CVE-2024-36401) :  ![starts](https://img.shields.io/github/stars/unlinedvol/CVE-2024-36401.svg) ![forks](https://img.shields.io/github/forks/unlinedvol/CVE-2024-36401.svg)


## CVE-2024-10924
 The Really Simple Security (Free, Pro, and Pro Multisite) plugins for WordPress are vulnerable to authentication bypass in versions 9.0.0 to 9.1.1.1. This is due to improper user check error handling in the two-factor REST API actions with the 'check_login_and_get_user' function. This makes it possible for unauthenticated attackers to log in as any existing user on the site, such as an administrator, when the "Two-Factor Authentication" setting is enabled (disabled by default).

- [https://github.com/h8sU/wordpress-cve-2024-10924-exploit](https://github.com/h8sU/wordpress-cve-2024-10924-exploit) :  ![starts](https://img.shields.io/github/stars/h8sU/wordpress-cve-2024-10924-exploit.svg) ![forks](https://img.shields.io/github/forks/h8sU/wordpress-cve-2024-10924-exploit.svg)


## CVE-2024-10914
 A vulnerability was found in D-Link DNS-320, DNS-320LW, DNS-325 and DNS-340L up to 20241028. It has been declared as critical. Affected by this vulnerability is the function cgi_user_add of the file /cgi-bin/account_mgr.cgi?cmd=cgi_user_add. The manipulation of the argument name leads to os command injection. The attack can be launched remotely. The complexity of an attack is rather high. The exploitation appears to be difficult. The exploit has been disclosed to the public and may be used.

- [https://github.com/silverxpymaster/CVE-2024-10914-Exploit](https://github.com/silverxpymaster/CVE-2024-10914-Exploit) :  ![starts](https://img.shields.io/github/stars/silverxpymaster/CVE-2024-10914-Exploit.svg) ![forks](https://img.shields.io/github/forks/silverxpymaster/CVE-2024-10914-Exploit.svg)


## CVE-2024-5452
 A remote code execution (RCE) vulnerability exists in the lightning-ai/pytorch-lightning library version 2.2.1 due to improper handling of deserialized user input and mismanagement of dunder attributes by the `deepdiff` library. The library uses `deepdiff.Delta` objects to modify application state based on frontend actions. However, it is possible to bypass the intended restrictions on modifying dunder attributes, allowing an attacker to construct a serialized delta that passes the deserializer whitelist and contains dunder attributes. When processed, this can be exploited to access other modules, classes, and instances, leading to arbitrary attribute write and total RCE on any self-hosted pytorch-lightning application in its default configuration, as the delta endpoint is enabled by default.

- [https://github.com/skrkcb2/CVE-2024-5452](https://github.com/skrkcb2/CVE-2024-5452) :  ![starts](https://img.shields.io/github/stars/skrkcb2/CVE-2024-5452.svg) ![forks](https://img.shields.io/github/forks/skrkcb2/CVE-2024-5452.svg)


## CVE-2024-4577
 In PHP versions 8.1.* before 8.1.29, 8.2.* before 8.2.20, 8.3.* before 8.3.8, when using Apache and PHP-CGI on Windows, if the system is set up to use certain code pages, Windows may use "Best-Fit" behavior to replace characters in command line given to Win32 API functions. PHP CGI module may misinterpret those characters as PHP options, which may allow a malicious user to pass options to PHP binary being run, and thus reveal the source code of scripts, run arbitrary PHP code on the server, etc.

- [https://github.com/chihyeonwon/php-cgi-cve-2024-4577](https://github.com/chihyeonwon/php-cgi-cve-2024-4577) :  ![starts](https://img.shields.io/github/stars/chihyeonwon/php-cgi-cve-2024-4577.svg) ![forks](https://img.shields.io/github/forks/chihyeonwon/php-cgi-cve-2024-4577.svg)
- [https://github.com/Didarul342/CVE-2024-4577](https://github.com/Didarul342/CVE-2024-4577) :  ![starts](https://img.shields.io/github/stars/Didarul342/CVE-2024-4577.svg) ![forks](https://img.shields.io/github/forks/Didarul342/CVE-2024-4577.svg)

