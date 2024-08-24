# Update 2024-08-24
## CVE-2024-38856
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/0x20c/CVE-2024-38856-EXP](https://github.com/0x20c/CVE-2024-38856-EXP) :  ![starts](https://img.shields.io/github/stars/0x20c/CVE-2024-38856-EXP.svg) ![forks](https://img.shields.io/github/forks/0x20c/CVE-2024-38856-EXP.svg)


## CVE-2024-38063
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/zaneoblaneo/cve_2024_38063_research](https://github.com/zaneoblaneo/cve_2024_38063_research) :  ![starts](https://img.shields.io/github/stars/zaneoblaneo/cve_2024_38063_research.svg) ![forks](https://img.shields.io/github/forks/zaneoblaneo/cve_2024_38063_research.svg)


## CVE-2024-34351
 Next.js is a React framework that can provide building blocks to create web applications. A Server-Side Request Forgery (SSRF) vulnerability was identified in Next.js Server Actions. If the `Host` header is modified, and the below conditions are also met, an attacker may be able to make requests that appear to be originating from the Next.js application server itself. The required conditions are 1) Next.js is running in a self-hosted manner; 2) the Next.js application makes use of Server Actions; and 3) the Server Action performs a redirect to a relative path which starts with a `/`. This vulnerability was fixed in Next.js `14.1.1`.

- [https://github.com/God4n/nextjs-CVE-2024-34351-_exploit](https://github.com/God4n/nextjs-CVE-2024-34351-_exploit) :  ![starts](https://img.shields.io/github/stars/God4n/nextjs-CVE-2024-34351-_exploit.svg) ![forks](https://img.shields.io/github/forks/God4n/nextjs-CVE-2024-34351-_exploit.svg)


## CVE-2024-28000
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/explls/CVE-2024-28000](https://github.com/explls/CVE-2024-28000) :  ![starts](https://img.shields.io/github/stars/explls/CVE-2024-28000.svg) ![forks](https://img.shields.io/github/forks/explls/CVE-2024-28000.svg)


## CVE-2024-4299
 The system configuration interface of HGiga iSherlock (including MailSherlock, SpamSherock, AuditSherlock) fails to filter special characters in certain function parameters, allowing remote attackers with administrative privileges to exploit this vulnerability for Command Injection attacks, enabling execution of arbitrary system commands.

- [https://github.com/juwenyi/CVE-2024-42992](https://github.com/juwenyi/CVE-2024-42992) :  ![starts](https://img.shields.io/github/stars/juwenyi/CVE-2024-42992.svg) ![forks](https://img.shields.io/github/forks/juwenyi/CVE-2024-42992.svg)


## CVE-2023-41425
 Cross Site Scripting vulnerability in Wonder CMS v.3.2.0 thru v.3.4.2 allows a remote attacker to execute arbitrary code via a crafted script uploaded to the installModule component.

- [https://github.com/tiyeume25112004/CVE-2023-41425](https://github.com/tiyeume25112004/CVE-2023-41425) :  ![starts](https://img.shields.io/github/stars/tiyeume25112004/CVE-2023-41425.svg) ![forks](https://img.shields.io/github/forks/tiyeume25112004/CVE-2023-41425.svg)


## CVE-2020-2021
 When Security Assertion Markup Language (SAML) authentication is enabled and the 'Validate Identity Provider Certificate' option is disabled (unchecked), improper verification of signatures in PAN-OS SAML authentication enables an unauthenticated network-based attacker to access protected resources. The attacker must have network access to the vulnerable server to exploit this vulnerability. This issue affects PAN-OS 9.1 versions earlier than PAN-OS 9.1.3; PAN-OS 9.0 versions earlier than PAN-OS 9.0.9; PAN-OS 8.1 versions earlier than PAN-OS 8.1.15, and all versions of PAN-OS 8.0 (EOL). This issue does not affect PAN-OS 7.1. This issue cannot be exploited if SAML is not used for authentication. This issue cannot be exploited if the 'Validate Identity Provider Certificate' option is enabled (checked) in the SAML Identity Provider Server Profile. Resources that can be protected by SAML-based single sign-on (SSO) authentication are: GlobalProtect Gateway, GlobalProtect Portal, GlobalProtect Clientless VPN, Authentication and Captive Portal, PAN-OS next-generation firewalls (PA-Series, VM-Series) and Panorama web interfaces, Prisma Access In the case of GlobalProtect Gateways, GlobalProtect Portal, Clientless VPN, Captive Portal, and Prisma Access, an unauthenticated attacker with network access to the affected servers can gain access to protected resources if allowed by configured authentication and Security policies. There is no impact on the integrity and availability of the gateway, portal or VPN server. An attacker cannot inspect or tamper with sessions of regular users. In the worst case, this is a critical severity vulnerability with a CVSS Base Score of 10.0 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N). In the case of PAN-OS and Panorama web interfaces, this issue allows an unauthenticated attacker with network access to the PAN-OS or Panorama web interfaces to log in as an administrator and perform administrative actions. In the worst-case scenario, this is a critical severity vulnerability with a CVSS Base Score of 10.0 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H). If the web interfaces are only accessible to a restricted management network, then the issue is lowered to a CVSS Base Score of 9.6 (CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H). Palo Alto Networks is not aware of any malicious attempts to exploit this vulnerability.

- [https://github.com/mr-r3b00t/CVE-2020-2021](https://github.com/mr-r3b00t/CVE-2020-2021) :  ![starts](https://img.shields.io/github/stars/mr-r3b00t/CVE-2020-2021.svg) ![forks](https://img.shields.io/github/forks/mr-r3b00t/CVE-2020-2021.svg)


## CVE-2015-8351
 PHP remote file inclusion vulnerability in the Gwolle Guestbook plugin before 1.5.4 for WordPress, when allow_url_include is enabled, allows remote authenticated users to execute arbitrary PHP code via a URL in the abspath parameter to frontend/captcha/ajaxresponse.php.  NOTE: this can also be leveraged to include and execute arbitrary local files via directory traversal sequences regardless of whether allow_url_include is enabled.

- [https://github.com/G4sp4rCS/exploit-CVE-2015-8351](https://github.com/G4sp4rCS/exploit-CVE-2015-8351) :  ![starts](https://img.shields.io/github/stars/G4sp4rCS/exploit-CVE-2015-8351.svg) ![forks](https://img.shields.io/github/forks/G4sp4rCS/exploit-CVE-2015-8351.svg)

