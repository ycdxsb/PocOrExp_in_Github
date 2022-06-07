# Update 2022-06-07
## CVE-2022-30190
 Microsoft Windows Support Diagnostic Tool (MSDT) Remote Code Execution Vulnerability.

- [https://github.com/ItsNee/Folina-CVE-2022-30190-POC](https://github.com/ItsNee/Folina-CVE-2022-30190-POC) :  ![starts](https://img.shields.io/github/stars/ItsNee/Folina-CVE-2022-30190-POC.svg) ![forks](https://img.shields.io/github/forks/ItsNee/Folina-CVE-2022-30190-POC.svg)
- [https://github.com/tej7gandhi/CVE-2022-30190-Zero-Click-Zero-Day-in-msdt](https://github.com/tej7gandhi/CVE-2022-30190-Zero-Click-Zero-Day-in-msdt) :  ![starts](https://img.shields.io/github/stars/tej7gandhi/CVE-2022-30190-Zero-Click-Zero-Day-in-msdt.svg) ![forks](https://img.shields.io/github/forks/tej7gandhi/CVE-2022-30190-Zero-Click-Zero-Day-in-msdt.svg)


## CVE-2022-29622
 An arbitrary file upload vulnerability in formidable v3.1.4 allows attackers to execute arbitrary code via a crafted filename. NOTE: some third parties dispute this issue because the product has common use cases in which uploading arbitrary files is the desired behavior. Also, there are configuration options in all versions that can change the default behavior of how files are handled.

- [https://github.com/keymandll/CVE-2022-29622](https://github.com/keymandll/CVE-2022-29622) :  ![starts](https://img.shields.io/github/stars/keymandll/CVE-2022-29622.svg) ![forks](https://img.shields.io/github/forks/keymandll/CVE-2022-29622.svg)


## CVE-2022-26134
 In affected versions of Confluence Server and Data Center, an OGNL injection vulnerability exists that would allow an unauthenticated attacker to execute arbitrary code on a Confluence Server or Data Center instance. The affected versions are from 1.3.0 before 7.4.17, from 7.13.0 before 7.13.7, from 7.14.0 before 7.14.3, from 7.15.0 before 7.15.2, from 7.16.0 before 7.16.4, from 7.17.0 before 7.17.4, and from 7.18.0 before 7.18.1.

- [https://github.com/tr0uble-mAker/POC-bomber](https://github.com/tr0uble-mAker/POC-bomber) :  ![starts](https://img.shields.io/github/stars/tr0uble-mAker/POC-bomber.svg) ![forks](https://img.shields.io/github/forks/tr0uble-mAker/POC-bomber.svg)
- [https://github.com/1rm/Confluence-CVE-2022-26134](https://github.com/1rm/Confluence-CVE-2022-26134) :  ![starts](https://img.shields.io/github/stars/1rm/Confluence-CVE-2022-26134.svg) ![forks](https://img.shields.io/github/forks/1rm/Confluence-CVE-2022-26134.svg)
- [https://github.com/axingde/CVE-2022-26134](https://github.com/axingde/CVE-2022-26134) :  ![starts](https://img.shields.io/github/stars/axingde/CVE-2022-26134.svg) ![forks](https://img.shields.io/github/forks/axingde/CVE-2022-26134.svg)
- [https://github.com/Vulnmachines/Confluence-CVE-2022-26134](https://github.com/Vulnmachines/Confluence-CVE-2022-26134) :  ![starts](https://img.shields.io/github/stars/Vulnmachines/Confluence-CVE-2022-26134.svg) ![forks](https://img.shields.io/github/forks/Vulnmachines/Confluence-CVE-2022-26134.svg)
- [https://github.com/h3v0x/CVE-2022-26134](https://github.com/h3v0x/CVE-2022-26134) :  ![starts](https://img.shields.io/github/stars/h3v0x/CVE-2022-26134.svg) ![forks](https://img.shields.io/github/forks/h3v0x/CVE-2022-26134.svg)
- [https://github.com/0xAgun/CVE-2022-26134](https://github.com/0xAgun/CVE-2022-26134) :  ![starts](https://img.shields.io/github/stars/0xAgun/CVE-2022-26134.svg) ![forks](https://img.shields.io/github/forks/0xAgun/CVE-2022-26134.svg)
- [https://github.com/abhishekmorla/CVE-2022-26134](https://github.com/abhishekmorla/CVE-2022-26134) :  ![starts](https://img.shields.io/github/stars/abhishekmorla/CVE-2022-26134.svg) ![forks](https://img.shields.io/github/forks/abhishekmorla/CVE-2022-26134.svg)
- [https://github.com/rodnt/CVE_2022_26134-detect](https://github.com/rodnt/CVE_2022_26134-detect) :  ![starts](https://img.shields.io/github/stars/rodnt/CVE_2022_26134-detect.svg) ![forks](https://img.shields.io/github/forks/rodnt/CVE_2022_26134-detect.svg)


## CVE-2022-24713
 regex is an implementation of regular expressions for the Rust language. The regex crate features built-in mitigations to prevent denial of service attacks caused by untrusted regexes, or untrusted input matched by trusted regexes. Those (tunable) mitigations already provide sane defaults to prevent attacks. This guarantee is documented and it's considered part of the crate's API. Unfortunately a bug was discovered in the mitigations designed to prevent untrusted regexes to take an arbitrary amount of time during parsing, and it's possible to craft regexes that bypass such mitigations. This makes it possible to perform denial of service attacks by sending specially crafted regexes to services accepting user-controlled, untrusted regexes. All versions of the regex crate before or equal to 1.5.4 are affected by this issue. The fix is include starting from regex 1.5.5. All users accepting user-controlled regexes are recommended to upgrade immediately to the latest version of the regex crate. Unfortunately there is no fixed set of problematic regexes, as there are practically infinite regexes that could be crafted to exploit this vulnerability. Because of this, it us not recommend to deny known problematic regexes.

- [https://github.com/ItzSwirlz/CVE-2022-24713-POC](https://github.com/ItzSwirlz/CVE-2022-24713-POC) :  ![starts](https://img.shields.io/github/stars/ItzSwirlz/CVE-2022-24713-POC.svg) ![forks](https://img.shields.io/github/forks/ItzSwirlz/CVE-2022-24713-POC.svg)


## CVE-2022-22965
 A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the application to run on Tomcat as a WAR deployment. If the application is deployed as a Spring Boot executable jar, i.e. the default, it is not vulnerable to the exploit. However, the nature of the vulnerability is more general, and there may be other ways to exploit it.

- [https://github.com/iwarsong/CVE-2022-22965-POC](https://github.com/iwarsong/CVE-2022-22965-POC) :  ![starts](https://img.shields.io/github/stars/iwarsong/CVE-2022-22965-POC.svg) ![forks](https://img.shields.io/github/forks/iwarsong/CVE-2022-22965-POC.svg)


## CVE-2022-22954
 VMware Workspace ONE Access and Identity Manager contain a remote code execution vulnerability due to server-side template injection. A malicious actor with network access can trigger a server-side template injection that may result in remote code execution.

- [https://github.com/avboy1337/CVE-2022-22954-VMware-RCE](https://github.com/avboy1337/CVE-2022-22954-VMware-RCE) :  ![starts](https://img.shields.io/github/stars/avboy1337/CVE-2022-22954-VMware-RCE.svg) ![forks](https://img.shields.io/github/forks/avboy1337/CVE-2022-22954-VMware-RCE.svg)


## CVE-2022-22947
 In spring cloud gateway versions prior to 3.1.1+ and 3.0.7+ , applications are vulnerable to a code injection attack when the Gateway Actuator endpoint is enabled, exposed and unsecured. A remote attacker could make a maliciously crafted request that could allow arbitrary remote execution on the remote host.

- [https://github.com/nanaao/CVE-2022-22947-POC](https://github.com/nanaao/CVE-2022-22947-POC) :  ![starts](https://img.shields.io/github/stars/nanaao/CVE-2022-22947-POC.svg) ![forks](https://img.shields.io/github/forks/nanaao/CVE-2022-22947-POC.svg)


## CVE-2021-35064
 KramerAV VIAWare, all tested versions, allow privilege escalation through misconfiguration of sudo. Sudoers permits running of multiple dangerous commands, including unzip, systemctl and dpkg.

- [https://github.com/Trhackno/CVE-2021-35064](https://github.com/Trhackno/CVE-2021-35064) :  ![starts](https://img.shields.io/github/stars/Trhackno/CVE-2021-35064.svg) ![forks](https://img.shields.io/github/forks/Trhackno/CVE-2021-35064.svg)


## CVE-2020-24186
 A Remote Code Execution vulnerability exists in the gVectors wpDiscuz plugin 7.0 through 7.0.4 for WordPress, which allows unauthenticated users to upload any type of file, including PHP files via the wmuUploadFiles AJAX action.

- [https://github.com/diurs/CVE-2020-24186-wordpress-wpDiscuz](https://github.com/diurs/CVE-2020-24186-wordpress-wpDiscuz) :  ![starts](https://img.shields.io/github/stars/diurs/CVE-2020-24186-wordpress-wpDiscuz.svg) ![forks](https://img.shields.io/github/forks/diurs/CVE-2020-24186-wordpress-wpDiscuz.svg)


## CVE-2019-5420
 A remote code execution vulnerability in development mode Rails &lt;5.2.2.1, &lt;6.0.0.beta3 can allow an attacker to guess the automatically generated development mode secret token. This secret token can be used in combination with other Rails internals to escalate to a remote code execution exploit.

- [https://github.com/PenTestical/CVE-2019-5420](https://github.com/PenTestical/CVE-2019-5420) :  ![starts](https://img.shields.io/github/stars/PenTestical/CVE-2019-5420.svg) ![forks](https://img.shields.io/github/forks/PenTestical/CVE-2019-5420.svg)


## CVE-2018-15473
 OpenSSH through 7.7 is prone to a user enumeration vulnerability due to not delaying bailout for an invalid authenticating user until after the packet containing the request has been fully parsed, related to auth2-gss.c, auth2-hostbased.c, and auth2-pubkey.c.

- [https://github.com/0xrobiul/CVE-2018-15473](https://github.com/0xrobiul/CVE-2018-15473) :  ![starts](https://img.shields.io/github/stars/0xrobiul/CVE-2018-15473.svg) ![forks](https://img.shields.io/github/forks/0xrobiul/CVE-2018-15473.svg)


## CVE-2004-0230
 TCP, when using a large Window Size, makes it easier for remote attackers to guess sequence numbers and cause a denial of service (connection loss) to persistent TCP connections by repeatedly injecting a TCP RST packet, especially in protocols that use long-lived connections, such as BGP.

- [https://github.com/RakeshShinde97/CVE-2004-0230-TCP-Sequence-Number-Approximation-Based-Denial-of-Service](https://github.com/RakeshShinde97/CVE-2004-0230-TCP-Sequence-Number-Approximation-Based-Denial-of-Service) :  ![starts](https://img.shields.io/github/stars/RakeshShinde97/CVE-2004-0230-TCP-Sequence-Number-Approximation-Based-Denial-of-Service.svg) ![forks](https://img.shields.io/github/forks/RakeshShinde97/CVE-2004-0230-TCP-Sequence-Number-Approximation-Based-Denial-of-Service.svg)

