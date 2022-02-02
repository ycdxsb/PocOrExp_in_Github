## CVE-2022-24032
 Adenza AxiomSL ControllerView through 10.8.1 is vulnerable to user enumeration. An attacker can identify valid usernames on the platform because a failed login attempt produces a different error message when the username is valid.



- [https://github.com/jdordonezn/CVE-2022-24032](https://github.com/jdordonezn/CVE-2022-24032) :  ![starts](https://img.shields.io/github/stars/jdordonezn/CVE-2022-24032.svg) ![forks](https://img.shields.io/github/forks/jdordonezn/CVE-2022-24032.svg)

## CVE-2022-23967
 In TightVNC 1.3.10, there is an integer signedness error and resultant heap-based buffer overflow in InitialiseRFBConnection in rfbproto.c (for the vncviewer component). There is no check on the size given to malloc, e.g., -1 is accepted. This allocates a chunk of size zero, which will give a heap pointer. However, one can send 0xffffffff bytes of data, which can have a DoS impact or lead to remote code execution.



- [https://github.com/MaherAzzouzi/CVE-2022-23967](https://github.com/MaherAzzouzi/CVE-2022-23967) :  ![starts](https://img.shields.io/github/stars/MaherAzzouzi/CVE-2022-23967.svg) ![forks](https://img.shields.io/github/forks/MaherAzzouzi/CVE-2022-23967.svg)

## CVE-2022-23307
 CVE-2020-9493 identified a deserialization issue that was present in Apache Chainsaw. Prior to Chainsaw V2.0 Chainsaw was a component of Apache Log4j 1.2.x where the same issue exists.



- [https://github.com/logpresso/CVE-2021-44228-Scanner](https://github.com/logpresso/CVE-2021-44228-Scanner) :  ![starts](https://img.shields.io/github/stars/logpresso/CVE-2021-44228-Scanner.svg) ![forks](https://img.shields.io/github/forks/logpresso/CVE-2021-44228-Scanner.svg)

- [https://github.com/HynekPetrak/log4shell-finder](https://github.com/HynekPetrak/log4shell-finder) :  ![starts](https://img.shields.io/github/stars/HynekPetrak/log4shell-finder.svg) ![forks](https://img.shields.io/github/forks/HynekPetrak/log4shell-finder.svg)

## CVE-2022-23305
 By design, the JDBCAppender in Log4j 1.2.x accepts an SQL statement as a configuration parameter where the values to be inserted are converters from PatternLayout. The message converter, %m, is likely to always be included. This allows attackers to manipulate the SQL by entering crafted strings into input fields or headers of an application that are logged allowing unintended SQL queries to be executed. Note this issue only affects Log4j 1.x when specifically configured to use the JDBCAppender, which is not the default. Beginning in version 2.0-beta8, the JDBCAppender was re-introduced with proper support for parameterized SQL queries and further customization over the columns written to in logs. Apache Log4j 1.2 reached end of life in August 2015. Users should upgrade to Log4j 2 as it addresses numerous other issues from the previous versions.



- [https://github.com/logpresso/CVE-2021-44228-Scanner](https://github.com/logpresso/CVE-2021-44228-Scanner) :  ![starts](https://img.shields.io/github/stars/logpresso/CVE-2021-44228-Scanner.svg) ![forks](https://img.shields.io/github/forks/logpresso/CVE-2021-44228-Scanner.svg)

- [https://github.com/HynekPetrak/log4shell-finder](https://github.com/HynekPetrak/log4shell-finder) :  ![starts](https://img.shields.io/github/stars/HynekPetrak/log4shell-finder.svg) ![forks](https://img.shields.io/github/forks/HynekPetrak/log4shell-finder.svg)

- [https://github.com/AlphabugX/CVE-2022-RCE](https://github.com/AlphabugX/CVE-2022-RCE) :  ![starts](https://img.shields.io/github/stars/AlphabugX/CVE-2022-RCE.svg) ![forks](https://img.shields.io/github/forks/AlphabugX/CVE-2022-RCE.svg)

## CVE-2022-23302
 JMSSink in all versions of Log4j 1.x is vulnerable to deserialization of untrusted data when the attacker has write access to the Log4j configuration or if the configuration references an LDAP service the attacker has access to. The attacker can provide a TopicConnectionFactoryBindingName configuration causing JMSSink to perform JNDI requests that result in remote code execution in a similar fashion to CVE-2021-4104. Note this issue only affects Log4j 1.x when specifically configured to use JMSSink, which is not the default. Apache Log4j 1.2 reached end of life in August 2015. Users should upgrade to Log4j 2 as it addresses numerous other issues from the previous versions.



- [https://github.com/logpresso/CVE-2021-44228-Scanner](https://github.com/logpresso/CVE-2021-44228-Scanner) :  ![starts](https://img.shields.io/github/stars/logpresso/CVE-2021-44228-Scanner.svg) ![forks](https://img.shields.io/github/forks/logpresso/CVE-2021-44228-Scanner.svg)

- [https://github.com/HynekPetrak/log4shell-finder](https://github.com/HynekPetrak/log4shell-finder) :  ![starts](https://img.shields.io/github/stars/HynekPetrak/log4shell-finder.svg) ![forks](https://img.shields.io/github/forks/HynekPetrak/log4shell-finder.svg)

## CVE-2022-23046
 PhpIPAM v1.4.4 allows an authenticated admin user to inject SQL sentences in the &quot;subnet&quot; parameter while searching a subnet via app/admin/routing/edit-bgp-mapping-search.php



- [https://github.com/jcarabantes/CVE-2022-23046](https://github.com/jcarabantes/CVE-2022-23046) :  ![starts](https://img.shields.io/github/stars/jcarabantes/CVE-2022-23046.svg) ![forks](https://img.shields.io/github/forks/jcarabantes/CVE-2022-23046.svg)

## CVE-2022-22919
 Adenza AxiomSL ControllerView through 10.8.1 allows redirection for SSO login URLs.



- [https://github.com/jdordonezn/CVE-2022-22919](https://github.com/jdordonezn/CVE-2022-22919) :  ![starts](https://img.shields.io/github/stars/jdordonezn/CVE-2022-22919.svg) ![forks](https://img.shields.io/github/forks/jdordonezn/CVE-2022-22919.svg)

## CVE-2022-22852
 A Stored Cross Site Scripting (XSS) vulnerability exists in Sourcecodtester Hospital's Patient Records Management System 1.0 via the description parameter in room_list.



- [https://github.com/Sant268/CVE-2022-22852](https://github.com/Sant268/CVE-2022-22852) :  ![starts](https://img.shields.io/github/stars/Sant268/CVE-2022-22852.svg) ![forks](https://img.shields.io/github/forks/Sant268/CVE-2022-22852.svg)

## CVE-2022-22851
 A Stored Cross Site Scripting (XSS) vulnerability exists in Sourcecodtester Hospital's Patient Records Management System 1.0 via the specialization parameter in doctors.php



- [https://github.com/Sant268/CVE-2022-22851](https://github.com/Sant268/CVE-2022-22851) :  ![starts](https://img.shields.io/github/stars/Sant268/CVE-2022-22851.svg) ![forks](https://img.shields.io/github/forks/Sant268/CVE-2022-22851.svg)

## CVE-2022-22850
 A Stored Cross Site Scripting (XSS) vulnerability exists in Sourcecodtester Hospital's Patient Records Management System 1.0 via the description parameter in room_types.



- [https://github.com/Sant268/CVE-2022-22850](https://github.com/Sant268/CVE-2022-22850) :  ![starts](https://img.shields.io/github/stars/Sant268/CVE-2022-22850.svg) ![forks](https://img.shields.io/github/forks/Sant268/CVE-2022-22850.svg)

## CVE-2022-22828
 An insecure direct object reference for the file-download URL in Synametrics SynaMan before 5.0 allows a remote attacker to access unshared files via a modified base64-encoded filename string.



- [https://github.com/videnlabs/CVE-2022-22828](https://github.com/videnlabs/CVE-2022-22828) :  ![starts](https://img.shields.io/github/stars/videnlabs/CVE-2022-22828.svg) ![forks](https://img.shields.io/github/forks/videnlabs/CVE-2022-22828.svg)

## CVE-2022-22296
 Sourcecodester Hospital's Patient Records Management System 1.0 is vulnerable to Insecure Permissions via the id parameter in manage_user endpoint. Simply change the value and data of other users can be displayed.



- [https://github.com/vlakhani28/CVE-2022-22296](https://github.com/vlakhani28/CVE-2022-22296) :  ![starts](https://img.shields.io/github/stars/vlakhani28/CVE-2022-22296.svg) ![forks](https://img.shields.io/github/forks/vlakhani28/CVE-2022-22296.svg)

## CVE-2022-21907
 HTTP Protocol Stack Remote Code Execution Vulnerability.



- [https://github.com/antx-code/CVE-2022-21907](https://github.com/antx-code/CVE-2022-21907) :  ![starts](https://img.shields.io/github/stars/antx-code/CVE-2022-21907.svg) ![forks](https://img.shields.io/github/forks/antx-code/CVE-2022-21907.svg)

- [https://github.com/p0dalirius/CVE-2022-21907-http.sys](https://github.com/p0dalirius/CVE-2022-21907-http.sys) :  ![starts](https://img.shields.io/github/stars/p0dalirius/CVE-2022-21907-http.sys.svg) ![forks](https://img.shields.io/github/forks/p0dalirius/CVE-2022-21907-http.sys.svg)

- [https://github.com/mauricelambert/CVE-2022-21907](https://github.com/mauricelambert/CVE-2022-21907) :  ![starts](https://img.shields.io/github/stars/mauricelambert/CVE-2022-21907.svg) ![forks](https://img.shields.io/github/forks/mauricelambert/CVE-2022-21907.svg)

- [https://github.com/corelight/cve-2022-21907](https://github.com/corelight/cve-2022-21907) :  ![starts](https://img.shields.io/github/stars/corelight/cve-2022-21907.svg) ![forks](https://img.shields.io/github/forks/corelight/cve-2022-21907.svg)

- [https://github.com/RtlCyclone/CVE_2022_21907-poc](https://github.com/RtlCyclone/CVE_2022_21907-poc) :  ![starts](https://img.shields.io/github/stars/RtlCyclone/CVE_2022_21907-poc.svg) ![forks](https://img.shields.io/github/forks/RtlCyclone/CVE_2022_21907-poc.svg)

- [https://github.com/michelep/CVE-2022-21907-Vulnerability-PoC](https://github.com/michelep/CVE-2022-21907-Vulnerability-PoC) :  ![starts](https://img.shields.io/github/stars/michelep/CVE-2022-21907-Vulnerability-PoC.svg) ![forks](https://img.shields.io/github/forks/michelep/CVE-2022-21907-Vulnerability-PoC.svg)

- [https://github.com/xiska62314/CVE-2022-21907](https://github.com/xiska62314/CVE-2022-21907) :  ![starts](https://img.shields.io/github/stars/xiska62314/CVE-2022-21907.svg) ![forks](https://img.shields.io/github/forks/xiska62314/CVE-2022-21907.svg)

## CVE-2022-21882
 Win32k Elevation of Privilege Vulnerability. This CVE ID is unique from CVE-2022-21887.



- [https://github.com/KaLendsi/CVE-2022-21882](https://github.com/KaLendsi/CVE-2022-21882) :  ![starts](https://img.shields.io/github/stars/KaLendsi/CVE-2022-21882.svg) ![forks](https://img.shields.io/github/forks/KaLendsi/CVE-2022-21882.svg)

- [https://github.com/David-Honisch/CVE-2022-21882](https://github.com/David-Honisch/CVE-2022-21882) :  ![starts](https://img.shields.io/github/stars/David-Honisch/CVE-2022-21882.svg) ![forks](https://img.shields.io/github/forks/David-Honisch/CVE-2022-21882.svg)

## CVE-2022-21661
 WordPress is a free and open-source content management system written in PHP and paired with a MariaDB database. Due to improper sanitization in WP_Query, there can be cases where SQL injection is possible through plugins or themes that use it in a certain way. This has been patched in WordPress version 5.8.3. Older affected versions are also fixed via security release, that go back till 3.7.37. We strongly recommend that you keep auto-updates enabled. There are no known workarounds for this vulnerability.



- [https://github.com/TAPESH-TEAM/CVE-2022-21661-WordPress-Core-5.8.2-WP_Query-SQL-Injection](https://github.com/TAPESH-TEAM/CVE-2022-21661-WordPress-Core-5.8.2-WP_Query-SQL-Injection) :  ![starts](https://img.shields.io/github/stars/TAPESH-TEAM/CVE-2022-21661-WordPress-Core-5.8.2-WP_Query-SQL-Injection.svg) ![forks](https://img.shields.io/github/forks/TAPESH-TEAM/CVE-2022-21661-WordPress-Core-5.8.2-WP_Query-SQL-Injection.svg)

## CVE-2022-21660
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.



- [https://github.com/UzJu/Gin-Vue-admin-poc-CVE-2022-21660](https://github.com/UzJu/Gin-Vue-admin-poc-CVE-2022-21660) :  ![starts](https://img.shields.io/github/stars/UzJu/Gin-Vue-admin-poc-CVE-2022-21660.svg) ![forks](https://img.shields.io/github/forks/UzJu/Gin-Vue-admin-poc-CVE-2022-21660.svg)

## CVE-2022-21658
 Rust is a multi-paradigm, general-purpose programming language designed for performance and safety, especially safe concurrency. The Rust Security Response WG was notified that the `std::fs::remove_dir_all` standard library function is vulnerable a race condition enabling symlink following (CWE-363). An attacker could use this security issue to trick a privileged program into deleting files and directories the attacker couldn't otherwise access or delete. Rust 1.0.0 through Rust 1.58.0 is affected by this vulnerability with 1.58.1 containing a patch. Note that the following build targets don't have usable APIs to properly mitigate the attack, and are thus still vulnerable even with a patched toolchain: macOS before version 10.10 (Yosemite) and REDOX. We recommend everyone to update to Rust 1.58.1 as soon as possible, especially people developing programs expected to run in privileged contexts (including system daemons and setuid binaries), as those have the highest risk of being affected by this. Note that adding checks in your codebase before calling remove_dir_all will not mitigate the vulnerability, as they would also be vulnerable to race conditions like remove_dir_all itself. The existing mitigation is working as intended outside of race conditions.



- [https://github.com/sagittarius-a/cve-2022-21658](https://github.com/sagittarius-a/cve-2022-21658) :  ![starts](https://img.shields.io/github/stars/sagittarius-a/cve-2022-21658.svg) ![forks](https://img.shields.io/github/forks/sagittarius-a/cve-2022-21658.svg)

## CVE-2022-21371
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Web Container). Supported versions that are affected are 12.1.3.0.0, 12.2.1.3.0, 12.2.1.4.0 and 14.1.1.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in unauthorized access to critical data or complete access to all Oracle WebLogic Server accessible data. CVSS 3.1 Base Score 7.5 (Confidentiality impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N).



- [https://github.com/Mr-xn/CVE-2022-21371](https://github.com/Mr-xn/CVE-2022-21371) :  ![starts](https://img.shields.io/github/stars/Mr-xn/CVE-2022-21371.svg) ![forks](https://img.shields.io/github/forks/Mr-xn/CVE-2022-21371.svg)

## CVE-2022-0332
 A flaw was found in Moodle in versions 3.11 to 3.11.4. An SQL injection risk was identified in the h5p activity web service responsible for fetching user attempt data.



- [https://github.com/numanturle/CVE-2022-0332](https://github.com/numanturle/CVE-2022-0332) :  ![starts](https://img.shields.io/github/stars/numanturle/CVE-2022-0332.svg) ![forks](https://img.shields.io/github/forks/numanturle/CVE-2022-0332.svg)

## CVE-2022-0236
 The WP Import Export WordPress plugin (both free and premium versions) is vulnerable to unauthenticated sensitive data disclosure due to a missing capability check on the download function wpie_process_file_download found in the ~/includes/classes/class-wpie-general.php file. This made it possible for unauthenticated attackers to download any imported or exported information from a vulnerable site which can contain sensitive information like user data. This affects versions up to, and including, 3.9.15.



- [https://github.com/qurbat/CVE-2022-0236](https://github.com/qurbat/CVE-2022-0236) :  ![starts](https://img.shields.io/github/stars/qurbat/CVE-2022-0236.svg) ![forks](https://img.shields.io/github/forks/qurbat/CVE-2022-0236.svg)

- [https://github.com/xiska62314/CVE-2022-0236](https://github.com/xiska62314/CVE-2022-0236) :  ![starts](https://img.shields.io/github/stars/xiska62314/CVE-2022-0236.svg) ![forks](https://img.shields.io/github/forks/xiska62314/CVE-2022-0236.svg)

## CVE-2022-0219
 Improper Restriction of XML External Entity Reference in GitHub repository skylot/jadx prior to 1.3.2.



- [https://github.com/Haxatron/CVE-2022-0219](https://github.com/Haxatron/CVE-2022-0219) :  ![starts](https://img.shields.io/github/stars/Haxatron/CVE-2022-0219.svg) ![forks](https://img.shields.io/github/forks/Haxatron/CVE-2022-0219.svg)

## CVE-2022-0185
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.



- [https://github.com/Crusaders-of-Rust/CVE-2022-0185](https://github.com/Crusaders-of-Rust/CVE-2022-0185) :  ![starts](https://img.shields.io/github/stars/Crusaders-of-Rust/CVE-2022-0185.svg) ![forks](https://img.shields.io/github/forks/Crusaders-of-Rust/CVE-2022-0185.svg)

- [https://github.com/discordianfish/cve-2022-0185-crash-poc](https://github.com/discordianfish/cve-2022-0185-crash-poc) :  ![starts](https://img.shields.io/github/stars/discordianfish/cve-2022-0185-crash-poc.svg) ![forks](https://img.shields.io/github/forks/discordianfish/cve-2022-0185-crash-poc.svg)

- [https://github.com/khaclep007/CVE-2022-0185](https://github.com/khaclep007/CVE-2022-0185) :  ![starts](https://img.shields.io/github/stars/khaclep007/CVE-2022-0185.svg) ![forks](https://img.shields.io/github/forks/khaclep007/CVE-2022-0185.svg)
