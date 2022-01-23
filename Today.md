# Update 2022-01-23
## CVE-2022-23305
 By design, the JDBCAppender in Log4j 1.2.x accepts an SQL statement as a configuration parameter where the values to be inserted are converters from PatternLayout. The message converter, %m, is likely to always be included. This allows attackers to manipulate the SQL by entering crafted strings into input fields or headers of an application that are logged allowing unintended SQL queries to be executed. Note this issue only affects Log4j 1.x when specifically configured to use the JDBCAppender, which is not the default. Beginning in version 2.0-beta8, the JDBCAppender was re-introduced with proper support for parameterized SQL queries and further customization over the columns written to in logs. Apache Log4j 1.2 reached end of life in August 2015. Users should upgrade to Log4j 2 as it addresses numerous other issues from the previous versions.

- [https://github.com/AlphabugX/CVE-2022-RCE](https://github.com/AlphabugX/CVE-2022-RCE) :  ![starts](https://img.shields.io/github/stars/AlphabugX/CVE-2022-RCE.svg) ![forks](https://img.shields.io/github/forks/AlphabugX/CVE-2022-RCE.svg)


## CVE-2022-22296
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/vlakhani28/CVE-2022-22296](https://github.com/vlakhani28/CVE-2022-22296) :  ![starts](https://img.shields.io/github/stars/vlakhani28/CVE-2022-22296.svg) ![forks](https://img.shields.io/github/forks/vlakhani28/CVE-2022-22296.svg)


## CVE-2022-21658
 Rust is a multi-paradigm, general-purpose programming language designed for performance and safety, especially safe concurrency. The Rust Security Response WG was notified that the `std::fs::remove_dir_all` standard library function is vulnerable a race condition enabling symlink following (CWE-363). An attacker could use this security issue to trick a privileged program into deleting files and directories the attacker couldn't otherwise access or delete. Rust 1.0.0 through Rust 1.58.0 is affected by this vulnerability with 1.58.1 containing a patch. Note that the following build targets don't have usable APIs to properly mitigate the attack, and are thus still vulnerable even with a patched toolchain: macOS before version 10.10 (Yosemite) and REDOX. We recommend everyone to update to Rust 1.58.1 as soon as possible, especially people developing programs expected to run in privileged contexts (including system daemons and setuid binaries), as those have the highest risk of being affected by this. Note that adding checks in your codebase before calling remove_dir_all will not mitigate the vulnerability, as they would also be vulnerable to race conditions like remove_dir_all itself. The existing mitigation is working as intended outside of race conditions.

- [https://github.com/sagittarius-a/cve-2022-21658](https://github.com/sagittarius-a/cve-2022-21658) :  ![starts](https://img.shields.io/github/stars/sagittarius-a/cve-2022-21658.svg) ![forks](https://img.shields.io/github/forks/sagittarius-a/cve-2022-21658.svg)


## CVE-2021-44593
 Simple College Website 1.0 is vulnerable to unauthenticated file upload &amp; remote code execution via UNION-based SQL injection in the username parameter on /admin/login.php.

- [https://github.com/Mister-Joe/CVE-2021-44593](https://github.com/Mister-Joe/CVE-2021-44593) :  ![starts](https://img.shields.io/github/stars/Mister-Joe/CVE-2021-44593.svg) ![forks](https://img.shields.io/github/forks/Mister-Joe/CVE-2021-44593.svg)


## CVE-2021-3560
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/Almorabea/Polkit-exploit](https://github.com/Almorabea/Polkit-exploit) :  ![starts](https://img.shields.io/github/stars/Almorabea/Polkit-exploit.svg) ![forks](https://img.shields.io/github/forks/Almorabea/Polkit-exploit.svg)
- [https://github.com/oxagast/oxasploits](https://github.com/oxagast/oxasploits) :  ![starts](https://img.shields.io/github/stars/oxagast/oxasploits.svg) ![forks](https://img.shields.io/github/forks/oxagast/oxasploits.svg)


## CVE-2021-1675
 Windows Print Spooler Elevation of Privilege Vulnerability

- [https://github.com/eversinc33/NimNightmare](https://github.com/eversinc33/NimNightmare) :  ![starts](https://img.shields.io/github/stars/eversinc33/NimNightmare.svg) ![forks](https://img.shields.io/github/forks/eversinc33/NimNightmare.svg)


## CVE-2019-17240
 bl-kernel/security.class.php in Bludit 3.9.2 allows attackers to bypass a brute-force protection mechanism by using many different forged X-Forwarded-For or Client-IP HTTP headers.

- [https://github.com/0xk4sra/CVE-2019-17240](https://github.com/0xk4sra/CVE-2019-17240) :  ![starts](https://img.shields.io/github/stars/0xk4sra/CVE-2019-17240.svg) ![forks](https://img.shields.io/github/forks/0xk4sra/CVE-2019-17240.svg)


## CVE-2019-16113
 Bludit 3.9.2 allows remote code execution via bl-kernel/ajax/upload-images.php because PHP code can be entered with a .jpg file name, and then this PHP code can write other PHP code to a ../ pathname.

- [https://github.com/0xk4sra/CVE-2019-16113](https://github.com/0xk4sra/CVE-2019-16113) :  ![starts](https://img.shields.io/github/stars/0xk4sra/CVE-2019-16113.svg) ![forks](https://img.shields.io/github/forks/0xk4sra/CVE-2019-16113.svg)

