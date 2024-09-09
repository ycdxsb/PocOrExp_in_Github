# Update 2024-09-09
## CVE-2024-38063
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/FrancescoDiSalesGithub/quick-fix-cve-2024-38063](https://github.com/FrancescoDiSalesGithub/quick-fix-cve-2024-38063) :  ![starts](https://img.shields.io/github/stars/FrancescoDiSalesGithub/quick-fix-cve-2024-38063.svg) ![forks](https://img.shields.io/github/forks/FrancescoDiSalesGithub/quick-fix-cve-2024-38063.svg)


## CVE-2024-29184
 FreeScout is a self-hosted help desk and shared mailbox. A Stored Cross-Site Scripting (XSS) vulnerability has been identified within the Signature Input Field of the FreeScout Application prior to version 1.8.128. Stored XSS occurs when user input is not properly sanitized and is stored on the server, allowing an attacker to inject malicious scripts that will be executed when other users access the affected page. In this case, the Support Agent User can inject malicious scripts into their signature, which will then be executed when viewed by the Administrator. The application protects users against XSS attacks by enforcing a CSP policy, the CSP Policy is: `script-src 'self' 'nonce-abcd' `. The CSP policy only allows the inclusion of JS files that are present on the application server and doesn't allow any inline script or script other than nonce-abcd. The CSP policy was bypassed by uploading a JS file to the server by a POST request to /conversation/upload endpoint. After this, a working XSS payload was crafted by including the uploaded JS file link as the src of the script. This bypassed the CSP policy and XSS attacks became possible. The impact of this vulnerability is severe as it allows an attacker to compromise the FreeScout Application. By exploiting this vulnerability, the attacker can perform various malicious actions such as forcing the Administrator to execute actions without their knowledge or consent. For instance, the attacker can force the Administrator to add a new administrator controlled by the attacker, thereby giving the attacker full control over the application. Alternatively, the attacker can elevate the privileges of a low-privileged user to Administrator, further compromising the security of the application. Attackers can steal sensitive information such as login credentials, session tokens, personal identifiable information (PII), and financial data. The vulnerability can also lead to defacement of the Application. Version 1.8.128 contains a patch for this issue.

- [https://github.com/abdulbugblaster/CVE-2024-29184](https://github.com/abdulbugblaster/CVE-2024-29184) :  ![starts](https://img.shields.io/github/stars/abdulbugblaster/CVE-2024-29184.svg) ![forks](https://img.shields.io/github/forks/abdulbugblaster/CVE-2024-29184.svg)


## CVE-2024-28116
 Grav is an open-source, flat-file content management system. Grav CMS prior to version 1.7.45 is vulnerable to a Server-Side Template Injection (SSTI), which allows any authenticated user (editor permissions are sufficient) to execute arbitrary code on the remote server bypassing the existing security sandbox. Version 1.7.45 contains a patch for this issue.

- [https://github.com/gunzf0x/Grav-CMS-RCE-Authenticated](https://github.com/gunzf0x/Grav-CMS-RCE-Authenticated) :  ![starts](https://img.shields.io/github/stars/gunzf0x/Grav-CMS-RCE-Authenticated.svg) ![forks](https://img.shields.io/github/forks/gunzf0x/Grav-CMS-RCE-Authenticated.svg)


## CVE-2024-1212
 Unauthenticated remote attackers can access the system through the LoadMaster management interface, enabling arbitrary system command execution.

- [https://github.com/hack-with-rohit/CVE-2024-1212](https://github.com/hack-with-rohit/CVE-2024-1212) :  ![starts](https://img.shields.io/github/stars/hack-with-rohit/CVE-2024-1212.svg) ![forks](https://img.shields.io/github/forks/hack-with-rohit/CVE-2024-1212.svg)


## CVE-2024-0195
 A vulnerability, which was classified as critical, was found in spider-flow 0.4.3. Affected is the function FunctionService.saveFunction of the file src/main/java/org/spiderflow/controller/FunctionController.java. The manipulation leads to code injection. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used. VDB-249510 is the identifier assigned to this vulnerability.

- [https://github.com/hack-with-rohit/CVE-2024-0195-SpiderFlow](https://github.com/hack-with-rohit/CVE-2024-0195-SpiderFlow) :  ![starts](https://img.shields.io/github/stars/hack-with-rohit/CVE-2024-0195-SpiderFlow.svg) ![forks](https://img.shields.io/github/forks/hack-with-rohit/CVE-2024-0195-SpiderFlow.svg)


## CVE-2023-21768
 Windows Ancillary Function Driver for WinSock Elevation of Privilege Vulnerability

- [https://github.com/ldrx30/CVE-2023-21768](https://github.com/ldrx30/CVE-2023-21768) :  ![starts](https://img.shields.io/github/stars/ldrx30/CVE-2023-21768.svg) ![forks](https://img.shields.io/github/forks/ldrx30/CVE-2023-21768.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/shiomiyan/CVE-2021-41773](https://github.com/shiomiyan/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/shiomiyan/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/shiomiyan/CVE-2021-41773.svg)
- [https://github.com/puckiestyle/CVE-2021-41773](https://github.com/puckiestyle/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/puckiestyle/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/puckiestyle/CVE-2021-41773.svg)


## CVE-2021-30573
 Use after free in GPU in Google Chrome prior to 92.0.4515.107 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

- [https://github.com/s4e-io/CVE-2021-30573-PoC-Google-Chrome](https://github.com/s4e-io/CVE-2021-30573-PoC-Google-Chrome) :  ![starts](https://img.shields.io/github/stars/s4e-io/CVE-2021-30573-PoC-Google-Chrome.svg) ![forks](https://img.shields.io/github/forks/s4e-io/CVE-2021-30573-PoC-Google-Chrome.svg)

