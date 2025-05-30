# Update 2025-05-30
## CVE-2025-22252
 A missing authentication for critical function in Fortinet FortiProxy versions 7.6.0 through 7.6.1, FortiSwitchManager version 7.2.5, and FortiOS versions 7.4.4 through 7.4.6 and version 7.6.0 may allow an attacker with knowledge of an existing admin account to access the device as a valid admin via an authentication bypass.

- [https://github.com/korden-c/CVE-2025-22252](https://github.com/korden-c/CVE-2025-22252) :  ![starts](https://img.shields.io/github/stars/korden-c/CVE-2025-22252.svg) ![forks](https://img.shields.io/github/forks/korden-c/CVE-2025-22252.svg)


## CVE-2025-5287
 The Likes and Dislikes Plugin plugin for WordPress is vulnerable to SQL Injection via the 'post' parameter in all versions up to, and including, 1.0.0 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query.  This makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database.

- [https://github.com/Nxploited/CVE-2025-5287](https://github.com/Nxploited/CVE-2025-5287) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-5287.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-5287.svg)


## CVE-2025-2539
 The File Away plugin for WordPress is vulnerable to unauthorized access of data due to a missing capability check on the ajax() function in all versions up to, and including, 3.9.9.0.1. This makes it possible for unauthenticated attackers, leveraging the use of a reversible weak algorithm,  to read the contents of arbitrary files on the server, which can contain sensitive information.

- [https://github.com/verylazytech/CVE-2025-2539](https://github.com/verylazytech/CVE-2025-2539) :  ![starts](https://img.shields.io/github/stars/verylazytech/CVE-2025-2539.svg) ![forks](https://img.shields.io/github/forks/verylazytech/CVE-2025-2539.svg)


## CVE-2025-1461
Version 2.x of Vuetify is End-of-Life and will not receive any updates to address this issue. For more information see  here https://v2.vuetifyjs.com/en/about/eol/ .

- [https://github.com/neverendingsupport/nes-vuetify-cve-2025-1461](https://github.com/neverendingsupport/nes-vuetify-cve-2025-1461) :  ![starts](https://img.shields.io/github/stars/neverendingsupport/nes-vuetify-cve-2025-1461.svg) ![forks](https://img.shields.io/github/forks/neverendingsupport/nes-vuetify-cve-2025-1461.svg)


## CVE-2024-32462
 Flatpak is a system for building, distributing, and running sandboxed desktop applications on Linux. in versions before 1.10.9, 1.12.9, 1.14.6, and 1.15.8, a malicious or compromised Flatpak app could execute arbitrary code outside its sandbox. Normally, the `--command` argument of `flatpak run` expects to be given a command to run in the specified Flatpak app, optionally along with some arguments. However it is possible to instead pass `bwrap` arguments to `--command=`, such as `--bind`. It's possible to pass an arbitrary `commandline` to the portal interface `org.freedesktop.portal.Background.RequestBackground` from within a Flatpak app. When this is converted into a `--command` and arguments, it achieves the same effect of passing arguments directly to `bwrap`, and thus can be used for a sandbox escape. The solution is to pass the `--` argument to `bwrap`, which makes it stop processing options. This has been supported since bubblewrap 0.3.0. All supported versions of Flatpak require at least that version of bubblewrap. xdg-desktop-portal version 1.18.4 will mitigate this vulnerability by only allowing Flatpak apps to create .desktop files for commands that do not start with --. The vulnerability is patched in 1.15.8, 1.10.9, 1.12.9, and 1.14.6.

- [https://github.com/SpiralBL0CK/CVE-2024-32462](https://github.com/SpiralBL0CK/CVE-2024-32462) :  ![starts](https://img.shields.io/github/stars/SpiralBL0CK/CVE-2024-32462.svg) ![forks](https://img.shields.io/github/forks/SpiralBL0CK/CVE-2024-32462.svg)


## CVE-2024-28995
SolarWinds Serv-U was susceptible to a directory transversal vulnerability that would allow access to read sensitive files on the host machine.    

- [https://github.com/ibrahimsql/CVE-2024-28995](https://github.com/ibrahimsql/CVE-2024-28995) :  ![starts](https://img.shields.io/github/stars/ibrahimsql/CVE-2024-28995.svg) ![forks](https://img.shields.io/github/forks/ibrahimsql/CVE-2024-28995.svg)


## CVE-2024-3094
Through a series of complex obfuscations, the liblzma build process extracts a prebuilt object file from a disguised test file existing in the source code, which is then used to modify specific functions in the liblzma code. This results in a modified liblzma library that can be used by any software linked against this library, intercepting and modifying the data interaction with this library.

- [https://github.com/KaminaDuck/ansible-CVE-2024-3094](https://github.com/KaminaDuck/ansible-CVE-2024-3094) :  ![starts](https://img.shields.io/github/stars/KaminaDuck/ansible-CVE-2024-3094.svg) ![forks](https://img.shields.io/github/forks/KaminaDuck/ansible-CVE-2024-3094.svg)


## CVE-2023-46818
 An issue was discovered in ISPConfig before 3.2.11p1. PHP code injection can be achieved in the language file editor by an admin if admin_allow_langedit is enabled.

- [https://github.com/engranaabubakar/CVE-2023-46818](https://github.com/engranaabubakar/CVE-2023-46818) :  ![starts](https://img.shields.io/github/stars/engranaabubakar/CVE-2023-46818.svg) ![forks](https://img.shields.io/github/forks/engranaabubakar/CVE-2023-46818.svg)


## CVE-2023-38600
 The issue was addressed with improved checks. This issue is fixed in iOS 16.6 and iPadOS 16.6, tvOS 16.6, macOS Ventura 13.5, Safari 16.6, watchOS 9.6. Processing web content may lead to arbitrary code execution.

- [https://github.com/afrojack1/cve202338600test.github.io](https://github.com/afrojack1/cve202338600test.github.io) :  ![starts](https://img.shields.io/github/stars/afrojack1/cve202338600test.github.io.svg) ![forks](https://img.shields.io/github/forks/afrojack1/cve202338600test.github.io.svg)


## CVE-2022-42889
 Apache Commons Text performs variable interpolation, allowing properties to be dynamically evaluated and expanded. The standard format for interpolation is "${prefix:name}", where "prefix" is used to locate an instance of org.apache.commons.text.lookup.StringLookup that performs the interpolation. Starting with version 1.5 and continuing through 1.9, the set of default Lookup instances included interpolators that could result in arbitrary code execution or contact with remote servers. These lookups are: - "script" - execute expressions using the JVM script execution engine (javax.script) - "dns" - resolve dns records - "url" - load values from urls, including from remote servers Applications using the interpolation defaults in the affected versions may be vulnerable to remote code execution or unintentional contact with remote servers if untrusted configuration values are used. Users are recommended to upgrade to Apache Commons Text 1.10.0, which disables the problematic interpolators by default.

- [https://github.com/purpl3ph03n1x/Text4ShellPayloads](https://github.com/purpl3ph03n1x/Text4ShellPayloads) :  ![starts](https://img.shields.io/github/stars/purpl3ph03n1x/Text4ShellPayloads.svg) ![forks](https://img.shields.io/github/forks/purpl3ph03n1x/Text4ShellPayloads.svg)


## CVE-2021-3156
 Sudo before 1.9.5p2 contains an off-by-one error that can result in a heap-based buffer overflow, which allows privilege escalation to root via "sudoedit -s" and a command-line argument that ends with a single backslash character.

- [https://github.com/duongdz96/CVE-2021-3156-main](https://github.com/duongdz96/CVE-2021-3156-main) :  ![starts](https://img.shields.io/github/stars/duongdz96/CVE-2021-3156-main.svg) ![forks](https://img.shields.io/github/forks/duongdz96/CVE-2021-3156-main.svg)


## CVE-2018-8097
 io/mongo/parser.py in Eve (aka pyeve) before 0.7.5 allows remote attackers to execute arbitrary code via Code Injection in the where parameter.

- [https://github.com/StellarDriftLabs/CVE-2018-8097-PoC](https://github.com/StellarDriftLabs/CVE-2018-8097-PoC) :  ![starts](https://img.shields.io/github/stars/StellarDriftLabs/CVE-2018-8097-PoC.svg) ![forks](https://img.shields.io/github/forks/StellarDriftLabs/CVE-2018-8097-PoC.svg)

