# Update 2024-06-29
## CVE-2024-34350
 Next.js is a React framework that can provide building blocks to create web applications. Prior to 13.5.1, an inconsistent interpretation of a crafted HTTP request meant that requests are treated as both a single request, and two separate requests by Next.js, leading to desynchronized responses. This led to a response queue poisoning vulnerability in the affected Next.js versions. For a request to be exploitable, the affected route also had to be making use of the [rewrites](https://nextjs.org/docs/app/api-reference/next-config-js/rewrites) feature in Next.js. The vulnerability is resolved in Next.js `13.5.1` and newer.

- [https://github.com/Sudistark/rewrites-nextjs-CVE-2024-34350](https://github.com/Sudistark/rewrites-nextjs-CVE-2024-34350) :  ![starts](https://img.shields.io/github/stars/Sudistark/rewrites-nextjs-CVE-2024-34350.svg) ![forks](https://img.shields.io/github/forks/Sudistark/rewrites-nextjs-CVE-2024-34350.svg)


## CVE-2024-34102
 Adobe Commerce versions 2.4.7, 2.4.6-p5, 2.4.5-p7, 2.4.4-p8 and earlier are affected by an Improper Restriction of XML External Entity Reference ('XXE') vulnerability that could result in arbitrary code execution. An attacker could exploit this vulnerability by sending a crafted XML document that references external entities. Exploitation of this issue does not require user interaction.

- [https://github.com/th3gokul/CVE-2024-34102](https://github.com/th3gokul/CVE-2024-34102) :  ![starts](https://img.shields.io/github/stars/th3gokul/CVE-2024-34102.svg) ![forks](https://img.shields.io/github/forks/th3gokul/CVE-2024-34102.svg)
- [https://github.com/bigb0x/CVE-2024-34102](https://github.com/bigb0x/CVE-2024-34102) :  ![starts](https://img.shields.io/github/stars/bigb0x/CVE-2024-34102.svg) ![forks](https://img.shields.io/github/forks/bigb0x/CVE-2024-34102.svg)
- [https://github.com/ArturArz1/TestCVE-2024-34102](https://github.com/ArturArz1/TestCVE-2024-34102) :  ![starts](https://img.shields.io/github/stars/ArturArz1/TestCVE-2024-34102.svg) ![forks](https://img.shields.io/github/forks/ArturArz1/TestCVE-2024-34102.svg)
- [https://github.com/dr3u1d/CVE-2024-34102-RCE](https://github.com/dr3u1d/CVE-2024-34102-RCE) :  ![starts](https://img.shields.io/github/stars/dr3u1d/CVE-2024-34102-RCE.svg) ![forks](https://img.shields.io/github/forks/dr3u1d/CVE-2024-34102-RCE.svg)


## CVE-2024-30088
 Windows Kernel Elevation of Privilege Vulnerability

- [https://github.com/NextGenPentesters/CVE-2024-30088-](https://github.com/NextGenPentesters/CVE-2024-30088-) :  ![starts](https://img.shields.io/github/stars/NextGenPentesters/CVE-2024-30088-.svg) ![forks](https://img.shields.io/github/forks/NextGenPentesters/CVE-2024-30088-.svg)


## CVE-2024-29943
 An attacker was able to perform an out-of-bounds read or write on a JavaScript object by fooling range-based bounds check elimination. This vulnerability affects Firefox &lt; 124.0.1.

- [https://github.com/bjrjk/CVE-2024-29943](https://github.com/bjrjk/CVE-2024-29943) :  ![starts](https://img.shields.io/github/stars/bjrjk/CVE-2024-29943.svg) ![forks](https://img.shields.io/github/forks/bjrjk/CVE-2024-29943.svg)


## CVE-2024-21754
 A use of password hash with insufficient computational effort vulnerability [CWE-916] affecting FortiOS version 7.4.3 and below, 7.2 all versions, 7.0 all versions, 6.4 all versions and FortiProxy version 7.4.2 and below, 7.2 all versions, 7.0 all versions, 2.0 all versions may allow a privileged attacker with super-admin profile and CLI access to decrypting the backup file.

- [https://github.com/CyberSecuritist/CVE-2024-21754-Forti-RCE](https://github.com/CyberSecuritist/CVE-2024-21754-Forti-RCE) :  ![starts](https://img.shields.io/github/stars/CyberSecuritist/CVE-2024-21754-Forti-RCE.svg) ![forks](https://img.shields.io/github/forks/CyberSecuritist/CVE-2024-21754-Forti-RCE.svg)


## CVE-2023-49103
 An issue was discovered in ownCloud owncloud/graphapi 0.2.x before 0.2.1 and 0.3.x before 0.3.1. The graphapi app relies on a third-party GetPhpInfo.php library that provides a URL. When this URL is accessed, it reveals the configuration details of the PHP environment (phpinfo). This information includes all the environment variables of the webserver. In containerized deployments, these environment variables may include sensitive data such as the ownCloud admin password, mail server credentials, and license key. Simply disabling the graphapi app does not eliminate the vulnerability. Additionally, phpinfo exposes various other potentially sensitive configuration details that could be exploited by an attacker to gather information about the system. Therefore, even if ownCloud is not running in a containerized environment, this vulnerability should still be a cause for concern. Note that Docker containers from before February 2023 are not vulnerable to the credential disclosure.

- [https://github.com/d0rb/CVE-2023-49103](https://github.com/d0rb/CVE-2023-49103) :  ![starts](https://img.shields.io/github/stars/d0rb/CVE-2023-49103.svg) ![forks](https://img.shields.io/github/forks/d0rb/CVE-2023-49103.svg)


## CVE-2023-27163
 request-baskets up to v1.2.1 was discovered to contain a Server-Side Request Forgery (SSRF) via the component /api/baskets/{name}. This vulnerability allows attackers to access network resources and sensitive information via a crafted API request.

- [https://github.com/Rishabh-Kumar-Cyber-Sec/CVE-2023-27163-ssrf-to-port-scanning](https://github.com/Rishabh-Kumar-Cyber-Sec/CVE-2023-27163-ssrf-to-port-scanning) :  ![starts](https://img.shields.io/github/stars/Rishabh-Kumar-Cyber-Sec/CVE-2023-27163-ssrf-to-port-scanning.svg) ![forks](https://img.shields.io/github/forks/Rishabh-Kumar-Cyber-Sec/CVE-2023-27163-ssrf-to-port-scanning.svg)


## CVE-2022-38694
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/TheGammaSqueeze/Bootloader_Unlock_Anbernic_T820](https://github.com/TheGammaSqueeze/Bootloader_Unlock_Anbernic_T820) :  ![starts](https://img.shields.io/github/stars/TheGammaSqueeze/Bootloader_Unlock_Anbernic_T820.svg) ![forks](https://img.shields.io/github/forks/TheGammaSqueeze/Bootloader_Unlock_Anbernic_T820.svg)


## CVE-2022-34729
 Windows GDI Elevation of Privilege Vulnerability

- [https://github.com/5l1v3r1/CVE-2022-34729](https://github.com/5l1v3r1/CVE-2022-34729) :  ![starts](https://img.shields.io/github/stars/5l1v3r1/CVE-2022-34729.svg) ![forks](https://img.shields.io/github/forks/5l1v3r1/CVE-2022-34729.svg)


## CVE-2022-28282
 By using a link with &lt;code&gt;rel=&quot;localization&quot;&lt;/code&gt; a use-after-free could have been triggered by destroying an object during JavaScript execution and then referencing the object through a freed pointer, leading to a potential exploitable crash. This vulnerability affects Thunderbird &lt; 91.8, Firefox &lt; 99, and Firefox ESR &lt; 91.8.

- [https://github.com/bb33bb/CVE-2022-28282-firefox](https://github.com/bb33bb/CVE-2022-28282-firefox) :  ![starts](https://img.shields.io/github/stars/bb33bb/CVE-2022-28282-firefox.svg) ![forks](https://img.shields.io/github/forks/bb33bb/CVE-2022-28282-firefox.svg)


## CVE-2020-35717
 zonote through 0.4.0 allows XSS via a crafted note, with resultant Remote Code Execution (because nodeIntegration in webPreferences is true).

- [https://github.com/Redfox-Secuirty/Hacking-Electron-Apps-CVE-2020-35717-](https://github.com/Redfox-Secuirty/Hacking-Electron-Apps-CVE-2020-35717-) :  ![starts](https://img.shields.io/github/stars/Redfox-Secuirty/Hacking-Electron-Apps-CVE-2020-35717-.svg) ![forks](https://img.shields.io/github/forks/Redfox-Secuirty/Hacking-Electron-Apps-CVE-2020-35717-.svg)


## CVE-2018-13382
 An Improper Authorization vulnerability in Fortinet FortiOS 6.0.0 to 6.0.4, 5.6.0 to 5.6.8 and 5.4.1 to 5.4.10 and FortiProxy 2.0.0, 1.2.0 to 1.2.8, 1.1.0 to 1.1.6, 1.0.0 to 1.0.7 under SSL VPN web portal allows an unauthenticated attacker to modify the password of an SSL VPN web portal user via specially crafted HTTP requests

- [https://github.com/milo2012/CVE-2018-13382](https://github.com/milo2012/CVE-2018-13382) :  ![starts](https://img.shields.io/github/stars/milo2012/CVE-2018-13382.svg) ![forks](https://img.shields.io/github/forks/milo2012/CVE-2018-13382.svg)
- [https://github.com/tumikoto/Exploit-FortinetMagicBackdoor](https://github.com/tumikoto/Exploit-FortinetMagicBackdoor) :  ![starts](https://img.shields.io/github/stars/tumikoto/Exploit-FortinetMagicBackdoor.svg) ![forks](https://img.shields.io/github/forks/tumikoto/Exploit-FortinetMagicBackdoor.svg)


## CVE-2017-12617
 When running Apache Tomcat versions 9.0.0.M1 to 9.0.0, 8.5.0 to 8.5.22, 8.0.0.RC1 to 8.0.46 and 7.0.0 to 7.0.81 with HTTP PUTs enabled (e.g. via setting the readonly initialisation parameter of the Default servlet to false) it was possible to upload a JSP file to the server via a specially crafted request. This JSP could then be requested and any code it contained would be executed by the server.

- [https://github.com/scirusvulgaris/CVE-2017-12617](https://github.com/scirusvulgaris/CVE-2017-12617) :  ![starts](https://img.shields.io/github/stars/scirusvulgaris/CVE-2017-12617.svg) ![forks](https://img.shields.io/github/forks/scirusvulgaris/CVE-2017-12617.svg)


## CVE-2002-1614
 Buffer overflow in HP Tru64 UNIX allows local users to execute arbitrary code via a long argument to /usr/bin/at.

- [https://github.com/wlensinas/CVE-2002-1614](https://github.com/wlensinas/CVE-2002-1614) :  ![starts](https://img.shields.io/github/stars/wlensinas/CVE-2002-1614.svg) ![forks](https://img.shields.io/github/forks/wlensinas/CVE-2002-1614.svg)

