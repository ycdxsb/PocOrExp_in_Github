# Update 2023-01-19
## CVE-2023-23749
 The 'LDAP Integration with Active Directory and OpenLDAP - NTLM &amp; Kerberos Login' extension is vulnerable to LDAP Injection since is not properly sanitizing the 'username' POST parameter. An attacker can manipulate this paramter to dump arbitrary contents form the LDAP Database.

- [https://github.com/Live-Hack-CVE/CVE-2023-23749](https://github.com/Live-Hack-CVE/CVE-2023-23749) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23749.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23749.svg)


## CVE-2023-23589
 The SafeSocks option in Tor before 0.4.7.13 has a logic error in which the unsafe SOCKS4 protocol can be used but not the safe SOCKS4a protocol, aka TROVE-2022-002.

- [https://github.com/Live-Hack-CVE/CVE-2023-23589](https://github.com/Live-Hack-CVE/CVE-2023-23589) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23589.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23589.svg)


## CVE-2023-22734
 Shopware is an open source commerce platform based on Symfony Framework and Vue js. The newsletter double opt-in validation was not checked properly, and it was possible to skip the complete double opt in process. As a result operators may have inconsistencies in their newsletter systems. This problem has been fixed with version 6.4.18.1. Users are advised to upgrade. Users unable to upgrade may find security measures are available via a plugin for major versions 6.1, 6.2, and 6.3. Users may also disable newsletter registration completely.

- [https://github.com/Live-Hack-CVE/CVE-2023-22734](https://github.com/Live-Hack-CVE/CVE-2023-22734) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22734.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22734.svg)


## CVE-2023-22733
 Shopware is an open source commerce platform based on Symfony Framework and Vue js. In affected versions the log module would write out all kind of sent mails. An attacker with access to either the local system logs or a centralized logging store may have access to other users accounts. This issue has been addressed in version 6.4.18.1. For older versions of 6.1, 6.2, and 6.3, corresponding security measures are also available via a plugin. For the full range of functions, we recommend updating to the latest Shopware version. Users unable to upgrade may remove from all users the log module ACL rights or disable logging.

- [https://github.com/Live-Hack-CVE/CVE-2023-22733](https://github.com/Live-Hack-CVE/CVE-2023-22733) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22733.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22733.svg)


## CVE-2023-22732
 Shopware is an open source commerce platform based on Symfony Framework and Vue js. The Administration session expiration was set to one week, when an attacker has stolen the session cookie they could use it for a long period of time. In version 6.4.18.1 an automatic logout into the Administration session has been added. As a result the user will be logged out when they are inactive. Users are advised to upgrade. There are no known workarounds for this issue.

- [https://github.com/Live-Hack-CVE/CVE-2023-22732](https://github.com/Live-Hack-CVE/CVE-2023-22732) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22732.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22732.svg)


## CVE-2023-22731
 Shopware is an open source commerce platform based on Symfony Framework and Vue js. In a Twig environment **without the Sandbox extension**, it is possible to refer to PHP functions in twig filters like `map`, `filter`, `sort`. This allows a template to call any global PHP function and thus execute arbitrary code. The attacker must have access to a Twig environment in order to exploit this vulnerability. This problem has been fixed with 6.4.18.1 with an override of the specified filters until the integration of the Sandbox extension has been finished. Users are advised to upgrade. Users of major versions 6.1, 6.2, and 6.3 may also receive this fix via a plugin.

- [https://github.com/Live-Hack-CVE/CVE-2023-22731](https://github.com/Live-Hack-CVE/CVE-2023-22731) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22731.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22731.svg)


## CVE-2023-22730
 Shopware is an open source commerce platform based on Symfony Framework and Vue js. In affected versions It was possible to put the same line item multiple times in the cart using the AP. The Cart Validators checked the line item's individuality and the user was able to bypass quantity limits in sales. This problem has been fixed with version 6.4.18.1. Users on major versions 6.1, 6.2, and 6.3 may also obtain this fix via a plugin.

- [https://github.com/Live-Hack-CVE/CVE-2023-22730](https://github.com/Live-Hack-CVE/CVE-2023-22730) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22730.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22730.svg)


## CVE-2023-22624
 Zoho ManageEngine Exchange Reporter Plus before 5708 allows attackers to conduct XXE attacks.

- [https://github.com/Live-Hack-CVE/CVE-2023-22624](https://github.com/Live-Hack-CVE/CVE-2023-22624) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22624.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22624.svg)


## CVE-2023-22491
 Gatsby is a free and open source framework based on React that helps developers build websites and apps. The gatsby-transformer-remark plugin prior to versions 5.25.1 and 6.3.2 passes input through to the `gray-matter` npm package, which is vulnerable to JavaScript injection in its default configuration, unless input is sanitized. The vulnerability is present in gatsby-transformer-remark when passing input in data mode (querying MarkdownRemark nodes via GraphQL). Injected JavaScript executes in the context of the build server. To exploit this vulnerability untrusted/unsanitized input would need to be sourced by or added into a file processed by gatsby-transformer-remark. A patch has been introduced in `gatsby-transformer-remark@5.25.1` and `gatsby-transformer-remark@6.3.2` which mitigates the issue by disabling the `gray-matter` JavaScript Frontmatter engine. As a workaround, if an older version of `gatsby-transformer-remark` must be used, input passed into the plugin should be sanitized ahead of processing. It is encouraged for projects to upgrade to the latest major release branch for all Gatsby plugins to ensure the latest security updates and bug fixes are received in a timely manner.

- [https://github.com/Live-Hack-CVE/CVE-2023-22491](https://github.com/Live-Hack-CVE/CVE-2023-22491) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22491.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22491.svg)


## CVE-2023-22489
 Flarum is a discussion platform for websites. If the first post of a discussion is permanently deleted but the discussion stays visible, any actor who can view the discussion is able to create a new reply via the REST API, no matter the reply permission or lock status. This includes users that don't have a validated email. Guests cannot successfully create a reply because the API will fail with a 500 error when the user ID 0 is inserted into the database. This happens because when the first post of a discussion is permanently deleted, the `first_post_id` attribute of the discussion becomes `null` which causes access control to be skipped for all new replies. Flarum automatically makes discussions with zero comments invisible so an additional condition for this vulnerability is that the discussion must have at least one approved reply so that `discussions.comment_count` is still above zero after the post deletion. This can open the discussion to uncontrolled spam or just unintentional replies if users still had their tab open before the vulnerable discussion was locked and then post a reply when they shouldn't be able to. In combination with the email notification settings, this could also be used as a way to send unsolicited emails. Versions between `v1.3.0` and `v1.6.3` are impacted. The vulnerability has been fixed and published as flarum/core v1.6.3. All communities running Flarum should upgrade as soon as possible. There are no known workarounds.

- [https://github.com/Live-Hack-CVE/CVE-2023-22489](https://github.com/Live-Hack-CVE/CVE-2023-22489) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22489.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22489.svg)


## CVE-2023-22366
 CX-Motion-MCH v2.32 and earlier contains an access of uninitialized pointer vulnerability. Having a user to open a specially crafted project file may lead to information disclosure and/or arbitrary code execution.

- [https://github.com/Live-Hack-CVE/CVE-2023-22366](https://github.com/Live-Hack-CVE/CVE-2023-22366) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22366.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22366.svg)


## CVE-2023-22357
 Active debug code exists in OMRON CP1L-EL20DR-D all versions, which may lead to a command that is not specified in FINS protocol being executed without authentication. A remote unauthenticated attacker may read/write in arbitrary area of the device memory, which may lead to overwriting the firmware, causing a denial-of-service (DoS) condition, and/or arbitrary code execution.

- [https://github.com/Live-Hack-CVE/CVE-2023-22357](https://github.com/Live-Hack-CVE/CVE-2023-22357) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22357.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22357.svg)


## CVE-2023-22316
 Hidden functionality vulnerability in PIX-RT100 versions RT100_TEQ_2.1.1_EQ101 and RT100_TEQ_2.1.2_EQ101 allows a network-adjacent attacker to access the product via undocumented Telnet or SSH services.

- [https://github.com/Live-Hack-CVE/CVE-2023-22316](https://github.com/Live-Hack-CVE/CVE-2023-22316) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22316.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22316.svg)


## CVE-2023-22304
 OS command injection vulnerability in PIX-RT100 versions RT100_TEQ_2.1.1_EQ101 and RT100_TEQ_2.1.2_EQ101 allows a network-adjacent attacker who can access product settings to execute an arbitrary OS command.

- [https://github.com/Live-Hack-CVE/CVE-2023-22304](https://github.com/Live-Hack-CVE/CVE-2023-22304) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22304.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22304.svg)


## CVE-2023-22303
 TP-Link SG105PE firmware prior to 'TL-SG105PE(UN) 1.0_1.0.0 Build 20221208' contains an authentication bypass vulnerability. Under the certain conditions, an attacker may impersonate an administrator of the product. As a result, information may be obtained and/or the product's settings may be altered with the privilege of the administrator.

- [https://github.com/Live-Hack-CVE/CVE-2023-22303](https://github.com/Live-Hack-CVE/CVE-2023-22303) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22303.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22303.svg)


## CVE-2023-22298
 Open redirect vulnerability in pgAdmin 4 versions prior to v6.14 allows a remote unauthenticated attacker to redirect a user to an arbitrary web site and conduct a phishing attack by having a user to access a specially crafted URL.

- [https://github.com/Live-Hack-CVE/CVE-2023-22298](https://github.com/Live-Hack-CVE/CVE-2023-22298) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22298.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22298.svg)


## CVE-2023-22296
 Reflected cross-site scripting vulnerability in MAHO-PBX NetDevancer series MAHO-PBX NetDevancer Lite/Uni/Pro/Cloud prior to Ver.1.11.00, MAHO-PBX NetDevancer VSG Lite/Uni prior to Ver.1.11.00, and MAHO-PBX NetDevancer MobileGate Home/Office prior to Ver.1.11.00 allows a remote unauthenticated attacker to inject an arbitrary script.

- [https://github.com/Live-Hack-CVE/CVE-2023-22296](https://github.com/Live-Hack-CVE/CVE-2023-22296) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22296.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22296.svg)


## CVE-2023-22286
 Cross-site request forgery (CSRF) vulnerability in MAHO-PBX NetDevancer Lite/Uni/Pro/Cloud prior to Ver.1.11.00, MAHO-PBX NetDevancer VSG Lite/Uni prior to Ver.1.11.00, and MAHO-PBX NetDevancer MobileGate Home/Office prior to Ver.1.11.00 allows a remote unauthenticated attacker to hijack the user authentication and conduct user's unintended operations by having a user to view a malicious page while logged in.

- [https://github.com/Live-Hack-CVE/CVE-2023-22286](https://github.com/Live-Hack-CVE/CVE-2023-22286) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22286.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22286.svg)


## CVE-2023-22280
 MAHO-PBX NetDevancer Lite/Uni/Pro/Cloud prior to Ver.1.11.00, MAHO-PBX NetDevancer VSG Lite/Uni prior to Ver.1.11.00, and MAHO-PBX NetDevancer MobileGate Home/Office prior to Ver.1.11.00 allow a remote authenticated attacker with an administrative privilege to execute an arbitrary OS command.

- [https://github.com/Live-Hack-CVE/CVE-2023-22280](https://github.com/Live-Hack-CVE/CVE-2023-22280) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22280.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22280.svg)


## CVE-2023-22279
 MAHO-PBX NetDevancer Lite/Uni/Pro/Cloud prior to Ver.1.11.00, MAHO-PBX NetDevancer VSG Lite/Uni prior to Ver.1.11.00, and MAHO-PBX NetDevancer MobileGate Home/Office prior to Ver.1.11.00 allow a remote unauthenticated attacker to execute an arbitrary OS command.

- [https://github.com/Live-Hack-CVE/CVE-2023-22279](https://github.com/Live-Hack-CVE/CVE-2023-22279) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22279.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22279.svg)


## CVE-2023-22278
 m-FILTER prior to Ver.5.70R01 (Ver.5 Series) and m-FILTER prior to Ver.4.87R04 (Ver.4 Series) allows a remote unauthenticated attacker to bypass authentication and send users' unintended email when email is being sent under the certain conditions. The attacks exploiting this vulnerability have been observed.

- [https://github.com/Live-Hack-CVE/CVE-2023-22278](https://github.com/Live-Hack-CVE/CVE-2023-22278) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22278.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22278.svg)


## CVE-2023-21891
 Vulnerability in the Oracle Business Intelligence Enterprise Edition product of Oracle Fusion Middleware (component: Visual Analyzer). Supported versions that are affected are 5.9.0.0.0 and 6.4.0.0.0. Easily exploitable vulnerability allows low privileged attacker with network access via HTTP to compromise Oracle Business Intelligence Enterprise Edition. Successful attacks require human interaction from a person other than the attacker and while the vulnerability is in Oracle Business Intelligence Enterprise Edition, attacks may significantly impact additional products (scope change). Successful attacks of this vulnerability can result in unauthorized update, insert or delete access to some of Oracle Business Intelligence Enterprise Edition accessible data as well as unauthorized read access to a subset of Oracle Business Intelligence Enterprise Edition accessible data. CVSS 3.1 Base Score 5.4 (Confidentiality and Integrity impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N).

- [https://github.com/Live-Hack-CVE/CVE-2023-21891](https://github.com/Live-Hack-CVE/CVE-2023-21891) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21891.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21891.svg)


## CVE-2023-21864
 Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Optimizer). Supported versions that are affected are 8.0.30 and prior. Easily exploitable vulnerability allows high privileged attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of MySQL Server. CVSS 3.1 Base Score 4.9 (Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H).

- [https://github.com/Live-Hack-CVE/CVE-2023-21864](https://github.com/Live-Hack-CVE/CVE-2023-21864) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21864.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21864.svg)


## CVE-2023-21853
 Vulnerability in the Oracle Mobile Field Service product of Oracle E-Business Suite (component: Synchronization). Supported versions that are affected are 12.2.3-12.2.12. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Mobile Field Service. Successful attacks of this vulnerability can result in unauthorized creation, deletion or modification access to critical data or all Oracle Mobile Field Service accessible data. CVSS 3.1 Base Score 7.5 (Integrity impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N).

- [https://github.com/Live-Hack-CVE/CVE-2023-21853](https://github.com/Live-Hack-CVE/CVE-2023-21853) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21853.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21853.svg)


## CVE-2023-21850
 Vulnerability in the Oracle Demantra Demand Management product of Oracle Supply Chain (component: E-Business Collections). Supported versions that are affected are 12.1 and 12.2. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Demantra Demand Management. Successful attacks of this vulnerability can result in unauthorized creation, deletion or modification access to critical data or all Oracle Demantra Demand Management accessible data. CVSS 3.1 Base Score 7.5 (Integrity impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N).

- [https://github.com/Live-Hack-CVE/CVE-2023-21850](https://github.com/Live-Hack-CVE/CVE-2023-21850) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21850.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21850.svg)


## CVE-2023-21849
 Vulnerability in the Oracle Applications DBA product of Oracle E-Business Suite (component: Java utils). Supported versions that are affected are 12.2.3-12.2.12. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Applications DBA. Successful attacks of this vulnerability can result in unauthorized creation, deletion or modification access to critical data or all Oracle Applications DBA accessible data. CVSS 3.1 Base Score 7.5 (Integrity impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N).

- [https://github.com/Live-Hack-CVE/CVE-2023-21849](https://github.com/Live-Hack-CVE/CVE-2023-21849) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21849.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21849.svg)


## CVE-2023-21847
 Vulnerability in the Oracle Web Applications Desktop Integrator product of Oracle E-Business Suite (component: Download). Supported versions that are affected are 12.2.3-12.2.12. Easily exploitable vulnerability allows low privileged attacker with network access via HTTP to compromise Oracle Web Applications Desktop Integrator. Successful attacks require human interaction from a person other than the attacker and while the vulnerability is in Oracle Web Applications Desktop Integrator, attacks may significantly impact additional products (scope change). Successful attacks of this vulnerability can result in unauthorized update, insert or delete access to some of Oracle Web Applications Desktop Integrator accessible data as well as unauthorized read access to a subset of Oracle Web Applications Desktop Integrator accessible data. CVSS 3.1 Base Score 5.4 (Confidentiality and Integrity impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N).

- [https://github.com/Live-Hack-CVE/CVE-2023-21847](https://github.com/Live-Hack-CVE/CVE-2023-21847) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21847.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21847.svg)


## CVE-2023-21846
 Vulnerability in the Oracle BI Publisher product of Oracle Fusion Middleware (component: Security). Supported versions that are affected are 5.9.0.0.0, 6.4.0.0.0 and 12.2.1.4.0. Easily exploitable vulnerability allows low privileged attacker with network access via multiple protocols to compromise Oracle BI Publisher. Successful attacks of this vulnerability can result in takeover of Oracle BI Publisher. CVSS 3.1 Base Score 8.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/Live-Hack-CVE/CVE-2023-21846](https://github.com/Live-Hack-CVE/CVE-2023-21846) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21846.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21846.svg)


## CVE-2023-21843
 Vulnerability in the Oracle Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component: Sound). Supported versions that are affected are Oracle Java SE: 8u351, 8u351-perf, 11.0.17, 17.0.5, 19.0.1; Oracle GraalVM Enterprise Edition: 20.3.8, 21.3.4 and 22.3.0. Difficult to exploit vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise Oracle Java SE, Oracle GraalVM Enterprise Edition. Successful attacks of this vulnerability can result in unauthorized update, insert or delete access to some of Oracle Java SE, Oracle GraalVM Enterprise Edition accessible data. Note: This vulnerability applies to Java deployments, typically in clients running sandboxed Java Web Start applications or sandboxed Java applets, that load and run untrusted code (e.g., code that comes from the internet) and rely on the Java sandbox for security. This vulnerability does not apply to Java deployments, typically in servers, that load and run only trusted code (e.g., code installed by an administrator). CVSS 3.1 Base Score 3.7 (Integrity impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N).

- [https://github.com/Live-Hack-CVE/CVE-2023-21843](https://github.com/Live-Hack-CVE/CVE-2023-21843) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21843.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21843.svg)


## CVE-2023-21841
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Core). Supported versions that are affected are 12.2.1.3.0, 12.2.1.4.0 and 14.1.1.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3, IIOP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in unauthorized access to critical data or complete access to all Oracle WebLogic Server accessible data. CVSS 3.1 Base Score 7.5 (Confidentiality impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N).

- [https://github.com/Live-Hack-CVE/CVE-2023-21841](https://github.com/Live-Hack-CVE/CVE-2023-21841) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21841.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21841.svg)


## CVE-2023-21840
 Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: PS). Supported versions that are affected are 5.7.40 and prior. Easily exploitable vulnerability allows high privileged attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of MySQL Server. CVSS 3.1 Base Score 4.9 (Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H).

- [https://github.com/Live-Hack-CVE/CVE-2023-21840](https://github.com/Live-Hack-CVE/CVE-2023-21840) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21840.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21840.svg)


## CVE-2023-21839
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Core). Supported versions that are affected are 12.2.1.3.0, 12.2.1.4.0 and 14.1.1.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3, IIOP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in unauthorized access to critical data or complete access to all Oracle WebLogic Server accessible data. CVSS 3.1 Base Score 7.5 (Confidentiality impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N).

- [https://github.com/Live-Hack-CVE/CVE-2023-21839](https://github.com/Live-Hack-CVE/CVE-2023-21839) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21839.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21839.svg)


## CVE-2023-21837
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Core). Supported versions that are affected are 12.2.1.3.0, 12.2.1.4.0 and 14.1.1.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via IIOP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in unauthorized access to critical data or complete access to all Oracle WebLogic Server accessible data. CVSS 3.1 Base Score 7.5 (Confidentiality impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N).

- [https://github.com/Live-Hack-CVE/CVE-2023-21837](https://github.com/Live-Hack-CVE/CVE-2023-21837) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21837.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21837.svg)


## CVE-2023-21835
 Vulnerability in the Oracle Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component: JSSE). Supported versions that are affected are Oracle Java SE: 11.0.17, 17.0.5, 19.0.1; Oracle GraalVM Enterprise Edition: 20.3.8, 21.3.4 and 22.3.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via DTLS to compromise Oracle Java SE, Oracle GraalVM Enterprise Edition. Successful attacks of this vulnerability can result in unauthorized ability to cause a partial denial of service (partial DOS) of Oracle Java SE, Oracle GraalVM Enterprise Edition. Note: This vulnerability applies to Java deployments, typically in clients running sandboxed Java Web Start applications or sandboxed Java applets, that load and run untrusted code (e.g., code that comes from the internet) and rely on the Java sandbox for security. This vulnerability does not apply to Java deployments, typically in servers, that load and run only trusted code (e.g., code installed by an administrator). CVSS 3.1 Base Score 5.3 (Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L).

- [https://github.com/Live-Hack-CVE/CVE-2023-21835](https://github.com/Live-Hack-CVE/CVE-2023-21835) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21835.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21835.svg)


## CVE-2023-21832
 Vulnerability in the Oracle BI Publisher product of Oracle Fusion Middleware (component: Security). Supported versions that are affected are 5.9.0.0.0, 6.4.0.0.0 and 12.2.1.4.0. Easily exploitable vulnerability allows low privileged attacker with network access via multiple protocols to compromise Oracle BI Publisher. Successful attacks of this vulnerability can result in takeover of Oracle BI Publisher. CVSS 3.1 Base Score 8.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/Live-Hack-CVE/CVE-2023-21832](https://github.com/Live-Hack-CVE/CVE-2023-21832) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21832.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21832.svg)


## CVE-2023-21830
 Vulnerability in the Oracle Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component: Serialization). Supported versions that are affected are Oracle Java SE: 8u351, 8u351-perf; Oracle GraalVM Enterprise Edition: 20.3.8 and 21.3.4. Easily exploitable vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise Oracle Java SE, Oracle GraalVM Enterprise Edition. Successful attacks of this vulnerability can result in unauthorized update, insert or delete access to some of Oracle Java SE, Oracle GraalVM Enterprise Edition accessible data. Note: This vulnerability applies to Java deployments, typically in clients running sandboxed Java Web Start applications or sandboxed Java applets, that load and run untrusted code (e.g., code that comes from the internet) and rely on the Java sandbox for security. This vulnerability does not apply to Java deployments, typically in servers, that load and run only trusted code (e.g., code installed by an administrator). CVSS 3.1 Base Score 5.3 (Integrity impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N).

- [https://github.com/Live-Hack-CVE/CVE-2023-21830](https://github.com/Live-Hack-CVE/CVE-2023-21830) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21830.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21830.svg)


## CVE-2023-21829
 Vulnerability in the Oracle Database RDBMS Security component of Oracle Database Server. Supported versions that are affected are 19c and 21c. Easily exploitable vulnerability allows low privileged attacker having Create Session privilege with network access via Oracle Net to compromise Oracle Database RDBMS Security. Successful attacks require human interaction from a person other than the attacker. Successful attacks of this vulnerability can result in unauthorized creation, deletion or modification access to critical data or all Oracle Database RDBMS Security accessible data as well as unauthorized read access to a subset of Oracle Database RDBMS Security accessible data. CVSS 3.1 Base Score 6.3 (Confidentiality and Integrity impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:H/A:N).

- [https://github.com/Live-Hack-CVE/CVE-2023-21829](https://github.com/Live-Hack-CVE/CVE-2023-21829) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21829.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21829.svg)


## CVE-2023-21827
 Vulnerability in the Oracle Database Data Redaction component of Oracle Database Server. Supported versions that are affected are 19c and 21c. Easily exploitable vulnerability allows low privileged attacker having Create Session privilege with network access via Oracle Net to compromise Oracle Database Data Redaction. Successful attacks of this vulnerability can result in unauthorized read access to a subset of Oracle Database Data Redaction accessible data. CVSS 3.1 Base Score 4.3 (Confidentiality impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N).

- [https://github.com/Live-Hack-CVE/CVE-2023-21827](https://github.com/Live-Hack-CVE/CVE-2023-21827) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21827.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21827.svg)


## CVE-2023-21825
 Vulnerability in the Oracle iSupplier Portal product of Oracle E-Business Suite (component: Supplier Management). Supported versions that are affected are 12.2.6-12.2.8. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle iSupplier Portal. Successful attacks of this vulnerability can result in unauthorized read access to a subset of Oracle iSupplier Portal accessible data. CVSS 3.1 Base Score 5.3 (Confidentiality impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N).

- [https://github.com/Live-Hack-CVE/CVE-2023-21825](https://github.com/Live-Hack-CVE/CVE-2023-21825) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21825.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21825.svg)


## CVE-2023-21730
 Microsoft Cryptographic Services Elevation of Privilege Vulnerability. This CVE ID is unique from CVE-2023-21551, CVE-2023-21561.

- [https://github.com/Live-Hack-CVE/CVE-2023-21561](https://github.com/Live-Hack-CVE/CVE-2023-21561) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21561.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21561.svg)
- [https://github.com/Live-Hack-CVE/CVE-2023-21551](https://github.com/Live-Hack-CVE/CVE-2023-21551) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21551.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21551.svg)


## CVE-2023-21681
 Microsoft WDAC OLE DB provider for SQL Server Remote Code Execution Vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2023-21681](https://github.com/Live-Hack-CVE/CVE-2023-21681) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21681.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21681.svg)


## CVE-2023-21680
 Windows Win32k Elevation of Privilege Vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2023-21680](https://github.com/Live-Hack-CVE/CVE-2023-21680) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21680.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21680.svg)


## CVE-2023-21679
 Windows Layer 2 Tunneling Protocol (L2TP) Remote Code Execution Vulnerability. This CVE ID is unique from CVE-2023-21543, CVE-2023-21546, CVE-2023-21555, CVE-2023-21556.

- [https://github.com/Live-Hack-CVE/CVE-2023-21543](https://github.com/Live-Hack-CVE/CVE-2023-21543) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21543.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21543.svg)
- [https://github.com/Live-Hack-CVE/CVE-2023-21546](https://github.com/Live-Hack-CVE/CVE-2023-21546) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21546.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21546.svg)
- [https://github.com/Live-Hack-CVE/CVE-2023-21555](https://github.com/Live-Hack-CVE/CVE-2023-21555) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21555.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21555.svg)


## CVE-2023-21561
 Microsoft Cryptographic Services Elevation of Privilege Vulnerability. This CVE ID is unique from CVE-2023-21551, CVE-2023-21730.

- [https://github.com/Live-Hack-CVE/CVE-2023-21561](https://github.com/Live-Hack-CVE/CVE-2023-21561) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21561.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21561.svg)
- [https://github.com/Live-Hack-CVE/CVE-2023-21551](https://github.com/Live-Hack-CVE/CVE-2023-21551) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21551.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21551.svg)


## CVE-2023-21559
 Windows Cryptographic Information Disclosure Vulnerability. This CVE ID is unique from CVE-2023-21540, CVE-2023-21550.

- [https://github.com/Live-Hack-CVE/CVE-2023-21559](https://github.com/Live-Hack-CVE/CVE-2023-21559) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21559.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21559.svg)
- [https://github.com/Live-Hack-CVE/CVE-2023-21550](https://github.com/Live-Hack-CVE/CVE-2023-21550) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21550.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21550.svg)


## CVE-2023-21556
 Windows Layer 2 Tunneling Protocol (L2TP) Remote Code Execution Vulnerability. This CVE ID is unique from CVE-2023-21543, CVE-2023-21546, CVE-2023-21555, CVE-2023-21679.

- [https://github.com/Live-Hack-CVE/CVE-2023-21543](https://github.com/Live-Hack-CVE/CVE-2023-21543) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21543.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21543.svg)
- [https://github.com/Live-Hack-CVE/CVE-2023-21555](https://github.com/Live-Hack-CVE/CVE-2023-21555) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21555.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21555.svg)
- [https://github.com/Live-Hack-CVE/CVE-2023-21546](https://github.com/Live-Hack-CVE/CVE-2023-21546) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21546.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21546.svg)


## CVE-2023-21555
 Windows Layer 2 Tunneling Protocol (L2TP) Remote Code Execution Vulnerability. This CVE ID is unique from CVE-2023-21543, CVE-2023-21546, CVE-2023-21556, CVE-2023-21679.

- [https://github.com/Live-Hack-CVE/CVE-2023-21555](https://github.com/Live-Hack-CVE/CVE-2023-21555) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21555.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21555.svg)
- [https://github.com/Live-Hack-CVE/CVE-2023-21543](https://github.com/Live-Hack-CVE/CVE-2023-21543) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21543.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21543.svg)
- [https://github.com/Live-Hack-CVE/CVE-2023-21546](https://github.com/Live-Hack-CVE/CVE-2023-21546) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21546.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21546.svg)


## CVE-2023-21551
 Microsoft Cryptographic Services Elevation of Privilege Vulnerability. This CVE ID is unique from CVE-2023-21561, CVE-2023-21730.

- [https://github.com/Live-Hack-CVE/CVE-2023-21551](https://github.com/Live-Hack-CVE/CVE-2023-21551) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21551.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21551.svg)
- [https://github.com/Live-Hack-CVE/CVE-2023-21561](https://github.com/Live-Hack-CVE/CVE-2023-21561) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21561.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21561.svg)


## CVE-2023-21550
 Windows Cryptographic Information Disclosure Vulnerability. This CVE ID is unique from CVE-2023-21540, CVE-2023-21559.

- [https://github.com/Live-Hack-CVE/CVE-2023-21550](https://github.com/Live-Hack-CVE/CVE-2023-21550) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21550.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21550.svg)
- [https://github.com/Live-Hack-CVE/CVE-2023-21559](https://github.com/Live-Hack-CVE/CVE-2023-21559) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21559.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21559.svg)


## CVE-2023-21549
 Windows SMB Witness Service Elevation of Privilege Vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2023-21549](https://github.com/Live-Hack-CVE/CVE-2023-21549) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21549.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21549.svg)


## CVE-2023-21547
 Internet Key Exchange (IKE) Protocol Denial of Service Vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2023-21547](https://github.com/Live-Hack-CVE/CVE-2023-21547) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21547.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21547.svg)


## CVE-2023-21546
 Windows Layer 2 Tunneling Protocol (L2TP) Remote Code Execution Vulnerability. This CVE ID is unique from CVE-2023-21543, CVE-2023-21555, CVE-2023-21556, CVE-2023-21679.

- [https://github.com/Live-Hack-CVE/CVE-2023-21546](https://github.com/Live-Hack-CVE/CVE-2023-21546) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21546.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21546.svg)
- [https://github.com/Live-Hack-CVE/CVE-2023-21543](https://github.com/Live-Hack-CVE/CVE-2023-21543) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21543.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21543.svg)
- [https://github.com/Live-Hack-CVE/CVE-2023-21555](https://github.com/Live-Hack-CVE/CVE-2023-21555) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21555.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21555.svg)


## CVE-2023-21543
 Windows Layer 2 Tunneling Protocol (L2TP) Remote Code Execution Vulnerability. This CVE ID is unique from CVE-2023-21546, CVE-2023-21555, CVE-2023-21556, CVE-2023-21679.

- [https://github.com/Live-Hack-CVE/CVE-2023-21543](https://github.com/Live-Hack-CVE/CVE-2023-21543) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21543.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21543.svg)
- [https://github.com/Live-Hack-CVE/CVE-2023-21546](https://github.com/Live-Hack-CVE/CVE-2023-21546) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21546.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21546.svg)
- [https://github.com/Live-Hack-CVE/CVE-2023-21555](https://github.com/Live-Hack-CVE/CVE-2023-21555) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21555.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21555.svg)


## CVE-2023-21540
 Windows Cryptographic Information Disclosure Vulnerability. This CVE ID is unique from CVE-2023-21550, CVE-2023-21559.

- [https://github.com/Live-Hack-CVE/CVE-2023-21559](https://github.com/Live-Hack-CVE/CVE-2023-21559) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21559.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21559.svg)
- [https://github.com/Live-Hack-CVE/CVE-2023-21550](https://github.com/Live-Hack-CVE/CVE-2023-21550) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21550.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21550.svg)


## CVE-2023-0338
 Cross-site Scripting (XSS) - Reflected in GitHub repository lirantal/daloradius prior to master-branch.

- [https://github.com/Live-Hack-CVE/CVE-2023-0338](https://github.com/Live-Hack-CVE/CVE-2023-0338) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0338.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0338.svg)


## CVE-2023-0337
 Cross-site Scripting (XSS) - Reflected in GitHub repository lirantal/daloradius prior to master-branch.

- [https://github.com/Live-Hack-CVE/CVE-2023-0337](https://github.com/Live-Hack-CVE/CVE-2023-0337) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0337.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0337.svg)


## CVE-2023-0332
 A vulnerability was found in SourceCodester Online Food Ordering System 2.0. It has been classified as critical. Affected is an unknown function of the file admin/manage_user.php. The manipulation of the argument id leads to sql injection. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used. The identifier of this vulnerability is VDB-218472.

- [https://github.com/Live-Hack-CVE/CVE-2023-0332](https://github.com/Live-Hack-CVE/CVE-2023-0332) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0332.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0332.svg)


## CVE-2023-0158
 NLnet Labs Krill supports direct access to the RRDP repository content through its built-in web server at the &quot;/rrdp&quot; endpoint. Prior to 0.12.1 a direct query for any existing directory under &quot;/rrdp/&quot;, rather than an RRDP file such as &quot;/rrdp/notification.xml&quot; as would be expected, causes Krill to crash. If the built-in &quot;/rrdp&quot; endpoint is exposed directly to the internet, then malicious remote parties can cause the publication server to crash. The repository content is not affected by this, but the availability of the server and repository can cause issues if this attack is persistent and is not mitigated.

- [https://github.com/Live-Hack-CVE/CVE-2023-0158](https://github.com/Live-Hack-CVE/CVE-2023-0158) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0158.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0158.svg)


## CVE-2022-48091
 Tramyardg hotel-mgmt-system version 2022.4 is vulnerable to Cross Site Scripting (XSS) via process_update_profile.php.

- [https://github.com/Live-Hack-CVE/CVE-2022-48091](https://github.com/Live-Hack-CVE/CVE-2022-48091) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-48091.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-48091.svg)


## CVE-2022-48090
 Tramyardg hotel-mgmt-system version 2022.4 is vulnerable to SQL Injection via /app/dao/CustomerDAO.php.

- [https://github.com/Live-Hack-CVE/CVE-2022-48090](https://github.com/Live-Hack-CVE/CVE-2022-48090) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-48090.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-48090.svg)


## CVE-2022-47911
 Sewio&#8217;s Real-Time Location System (RTLS) Studio version 2.0.0 up to and including version 2.6.2 does not properly validate the input module name to the backup services of the software. This could allow a remote attacker to access sensitive functions of the application and execute arbitrary system commands.

- [https://github.com/Live-Hack-CVE/CVE-2022-47911](https://github.com/Live-Hack-CVE/CVE-2022-47911) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-47911.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-47911.svg)


## CVE-2022-47395
 Sewio&#8217;s Real-Time Location System (RTLS) Studio version 2.0.0 up to and including version 2.6.2 is vulnerable to cross-site request forgery in its monitor services. An attacker could take advantage of this vulnerability to execute arbitrary maintenance operations and cause a denial-of-service condition.

- [https://github.com/Live-Hack-CVE/CVE-2022-47395](https://github.com/Live-Hack-CVE/CVE-2022-47395) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-47395.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-47395.svg)


## CVE-2022-47318
 ruby-git versions prior to v1.13.0 allows a remote authenticated attacker to execute an arbitrary ruby code by having a user to load a repository containing a specially crafted filename to the product. This vulnerability is different from CVE-2022-46648.

- [https://github.com/Live-Hack-CVE/CVE-2022-47318](https://github.com/Live-Hack-CVE/CVE-2022-47318) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-47318.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-47318.svg)
- [https://github.com/Live-Hack-CVE/CVE-2022-46648](https://github.com/Live-Hack-CVE/CVE-2022-46648) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-46648.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-46648.svg)


## CVE-2022-46891
 An issue was discovered in the Arm Mali GPU Kernel Driver. There is a use-after-free. A non-privileged user can make improper GPU processing operations to gain access to already freed memory. This affects Midgard r13p0 through r32p0, Bifrost r1p0 through r40p0, and Valhall r19p0 through r40p0.

- [https://github.com/Live-Hack-CVE/CVE-2022-46891](https://github.com/Live-Hack-CVE/CVE-2022-46891) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-46891.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-46891.svg)


## CVE-2022-46733
 Sewio&#8217;s Real-Time Location System (RTLS) Studio version 2.0.0 up to and including version 2.6.2 is vulnerable to cross-site scripting in its backup services. An attacker could take advantage of this vulnerability to execute arbitrary commands.

- [https://github.com/Live-Hack-CVE/CVE-2022-46733](https://github.com/Live-Hack-CVE/CVE-2022-46733) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-46733.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-46733.svg)


## CVE-2022-46660
 An unauthorized user could alter or write files with full control over the path and content of the file.

- [https://github.com/Live-Hack-CVE/CVE-2022-46660](https://github.com/Live-Hack-CVE/CVE-2022-46660) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-46660.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-46660.svg)


## CVE-2022-46648
 ruby-git versions prior to v1.13.0 allows a remote authenticated attacker to execute an arbitrary ruby code by having a user to load a repository containing a specially crafted filename to the product. This vulnerability is different from CVE-2022-47318.

- [https://github.com/Live-Hack-CVE/CVE-2022-46648](https://github.com/Live-Hack-CVE/CVE-2022-46648) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-46648.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-46648.svg)
- [https://github.com/Live-Hack-CVE/CVE-2022-47318](https://github.com/Live-Hack-CVE/CVE-2022-47318) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-47318.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-47318.svg)


## CVE-2022-46463
 An access control issue in Harbor v1.X.X to v2.5.3 allows attackers to access public and private image repositories without authentication.

- [https://github.com/nu0l/CVE-2022-46463](https://github.com/nu0l/CVE-2022-46463) :  ![starts](https://img.shields.io/github/stars/nu0l/CVE-2022-46463.svg) ![forks](https://img.shields.io/github/forks/nu0l/CVE-2022-46463.svg)
- [https://github.com/lanqingaa/CVE-2022-46463](https://github.com/lanqingaa/CVE-2022-46463) :  ![starts](https://img.shields.io/github/stars/lanqingaa/CVE-2022-46463.svg) ![forks](https://img.shields.io/github/forks/lanqingaa/CVE-2022-46463.svg)


## CVE-2022-45444
 Sewio&#8217;s Real-Time Location System (RTLS) Studio version 2.0.0 up to and including version 2.6.2 contains hard-coded passwords for select users in the application&#8217;s database. This could allow a remote attacker to login to the database with unrestricted access.

- [https://github.com/Live-Hack-CVE/CVE-2022-45444](https://github.com/Live-Hack-CVE/CVE-2022-45444) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-45444.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-45444.svg)


## CVE-2022-45127
 Sewio&#8217;s Real-Time Location System (RTLS) Studio version 2.0.0 up to and including version 2.6.2 is vulnerable to cross-site request forgery in its backup services. An attacker could take advantage of this vulnerability to execute arbitrary backup operations and cause a denial-of-service condition.

- [https://github.com/Live-Hack-CVE/CVE-2022-45127](https://github.com/Live-Hack-CVE/CVE-2022-45127) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-45127.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-45127.svg)


## CVE-2022-43483
 Sewio&#8217;s Real-Time Location System (RTLS) Studio version 2.0.0 up to and including version 2.6.2 does not properly validate the input module name to the monitor services of the software. This could allow a remote attacker to access sensitive functions of the application and execute arbitrary system commands.

- [https://github.com/Live-Hack-CVE/CVE-2022-43483](https://github.com/Live-Hack-CVE/CVE-2022-43483) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-43483.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-43483.svg)


## CVE-2022-42475
 A heap-based buffer overflow vulnerability [CWE-122] in FortiOS SSL-VPN 7.2.0 through 7.2.2, 7.0.0 through 7.0.8, 6.4.0 through 6.4.10, 6.2.0 through 6.2.11, 6.0.15 and earlier and FortiProxy SSL-VPN 7.2.0 through 7.2.1, 7.0.7 and earlier may allow a remote unauthenticated attacker to execute arbitrary code or commands via specifically crafted requests.

- [https://github.com/bryanster/ioc-cve-2022-42475](https://github.com/bryanster/ioc-cve-2022-42475) :  ![starts](https://img.shields.io/github/stars/bryanster/ioc-cve-2022-42475.svg) ![forks](https://img.shields.io/github/forks/bryanster/ioc-cve-2022-42475.svg)


## CVE-2022-41989
 Sewio&#8217;s Real-Time Location System (RTLS) Studio version 2.0.0 up to and including version 2.6.2 does not validate the length of RTLS report payloads during communication. This allows an attacker to send an exceedingly long payload, resulting in an out-of-bounds write to cause a denial-of-service condition or code execution.

- [https://github.com/Live-Hack-CVE/CVE-2022-41989](https://github.com/Live-Hack-CVE/CVE-2022-41989) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-41989.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-41989.svg)


## CVE-2022-41953
 Git GUI is a convenient graphical tool that comes with Git for Windows. Its target audience is users who are uncomfortable with using Git on the command-line. Git GUI has a function to clone repositories. Immediately after the local clone is available, Git GUI will automatically post-process it, among other things running a spell checker called `aspell.exe` if it was found. Git GUI is implemented as a Tcl/Tk script. Due to the unfortunate design of Tcl on Windows, the search path when looking for an executable _always includes the current directory_. Therefore, malicious repositories can ship with an `aspell.exe` in their top-level directory which is executed by Git GUI without giving the user a chance to inspect it first, i.e. running untrusted code. This issue has been addressed in version 2.39.1. Users are advised to upgrade. Users unable to upgrade should avoid using Git GUI for cloning. If that is not a viable option, at least avoid cloning from untrusted sources.

- [https://github.com/Live-Hack-CVE/CVE-2022-41953](https://github.com/Live-Hack-CVE/CVE-2022-41953) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-41953.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-41953.svg)


## CVE-2022-41861
 A flaw was found in freeradius. A malicious RADIUS client or home server can send a malformed abinary attribute which can cause the server to crash.

- [https://github.com/Live-Hack-CVE/CVE-2022-41861](https://github.com/Live-Hack-CVE/CVE-2022-41861) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-41861.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-41861.svg)


## CVE-2022-41860
 In freeradius, when an EAP-SIM supplicant sends an unknown SIM option, the server will try to look that option up in the internal dictionaries. This lookup will fail, but the SIM code will not check for that failure. Instead, it will dereference a NULL pointer, and cause the server to crash.

- [https://github.com/Live-Hack-CVE/CVE-2022-41860](https://github.com/Live-Hack-CVE/CVE-2022-41860) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-41860.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-41860.svg)


## CVE-2022-41859
 In freeradius, the EAP-PWD function compute_password_element() leaks information about the password which allows an attacker to substantially reduce the size of an offline dictionary attack.

- [https://github.com/Live-Hack-CVE/CVE-2022-41859](https://github.com/Live-Hack-CVE/CVE-2022-41859) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-41859.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-41859.svg)


## CVE-2022-41858
 A flaw was found in the Linux kernel. A NULL pointer dereference may occur while a slip driver is in progress to detach in sl_tx_timeout in drivers/net/slip/slip.c. This issue could allow an attacker to crash the system or leak internal kernel information.

- [https://github.com/Live-Hack-CVE/CVE-2022-41858](https://github.com/Live-Hack-CVE/CVE-2022-41858) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-41858.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-41858.svg)


## CVE-2022-41099
 BitLocker Security Feature Bypass Vulnerability.

- [https://github.com/o0MattE0o/CVE-2022-41099-Fix](https://github.com/o0MattE0o/CVE-2022-41099-Fix) :  ![starts](https://img.shields.io/github/stars/o0MattE0o/CVE-2022-41099-Fix.svg) ![forks](https://img.shields.io/github/forks/o0MattE0o/CVE-2022-41099-Fix.svg)


## CVE-2022-40684
 An authentication bypass using an alternate path or channel [CWE-288] in Fortinet FortiOS version 7.2.0 through 7.2.1 and 7.0.0 through 7.0.6, FortiProxy version 7.2.0 and version 7.0.0 through 7.0.6 and FortiSwitchManager version 7.2.0 and 7.0.0 allows an unauthenticated atttacker to perform operations on the administrative interface via specially crafted HTTP or HTTPS requests.

- [https://github.com/notareaperbutDR34P3r/CVE-2022-40684-Rust](https://github.com/notareaperbutDR34P3r/CVE-2022-40684-Rust) :  ![starts](https://img.shields.io/github/stars/notareaperbutDR34P3r/CVE-2022-40684-Rust.svg) ![forks](https://img.shields.io/github/forks/notareaperbutDR34P3r/CVE-2022-40684-Rust.svg)


## CVE-2022-39429
 Vulnerability in the Java VM component of Oracle Database Server. Supported versions that are affected are 19c and 21c. Easily exploitable vulnerability allows low privileged attacker having Create Procedure privilege with network access via Oracle Net to compromise Java VM. Successful attacks of this vulnerability can result in unauthorized ability to cause a partial denial of service (partial DOS) of Java VM. CVSS 3.1 Base Score 4.3 (Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L).

- [https://github.com/Live-Hack-CVE/CVE-2022-39429](https://github.com/Live-Hack-CVE/CVE-2022-39429) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-39429.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-39429.svg)


## CVE-2022-37436
 Prior to Apache HTTP Server 2.4.55, a malicious backend can cause the response headers to be truncated early, resulting in some headers being incorporated into the response body. If the later headers have any security purpose, they will not be interpreted by the client.

- [https://github.com/Live-Hack-CVE/CVE-2022-37436](https://github.com/Live-Hack-CVE/CVE-2022-37436) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-37436.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-37436.svg)


## CVE-2022-36760
 Inconsistent Interpretation of HTTP Requests ('HTTP Request Smuggling') vulnerability in mod_proxy_ajp of Apache HTTP Server allows an attacker to smuggle requests to the AJP server it forwards requests to. This issue affects Apache HTTP Server Apache HTTP Server 2.4 version 2.4.54 and prior versions.

- [https://github.com/Live-Hack-CVE/CVE-2022-36760](https://github.com/Live-Hack-CVE/CVE-2022-36760) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36760.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36760.svg)


## CVE-2022-34718
 Windows TCP/IP Remote Code Execution Vulnerability.

- [https://github.com/Ascotbe/Kernelhub](https://github.com/Ascotbe/Kernelhub) :  ![starts](https://img.shields.io/github/stars/Ascotbe/Kernelhub.svg) ![forks](https://img.shields.io/github/forks/Ascotbe/Kernelhub.svg)


## CVE-2022-33679
 Windows Kerberos Elevation of Privilege Vulnerability. This CVE ID is unique from CVE-2022-33647.

- [https://github.com/Ascotbe/Kernelhub](https://github.com/Ascotbe/Kernelhub) :  ![starts](https://img.shields.io/github/stars/Ascotbe/Kernelhub.svg) ![forks](https://img.shields.io/github/forks/Ascotbe/Kernelhub.svg)


## CVE-2022-31697
 The vCenter Server contains an information disclosure vulnerability due to the logging of credentials in plaintext. A malicious actor with access to a workstation that invoked a vCenter Server Appliance ISO operation (Install/Upgrade/Migrate/Restore) can access plaintext passwords used during that operation.

- [https://github.com/Live-Hack-CVE/CVE-2022-31697](https://github.com/Live-Hack-CVE/CVE-2022-31697) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-31697.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-31697.svg)


## CVE-2022-30544
 Cross-Site Request Forgery (CSRF) in MiKa's OSM &#8211; OpenStreetMap plugin &lt;= 6.0.1 versions.

- [https://github.com/Live-Hack-CVE/CVE-2022-30544](https://github.com/Live-Hack-CVE/CVE-2022-30544) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-30544.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-30544.svg)


## CVE-2022-30206
 Windows Print Spooler Elevation of Privilege Vulnerability. This CVE ID is unique from CVE-2022-22022, CVE-2022-22041, CVE-2022-30226.

- [https://github.com/Ascotbe/Kernelhub](https://github.com/Ascotbe/Kernelhub) :  ![starts](https://img.shields.io/github/stars/Ascotbe/Kernelhub.svg) ![forks](https://img.shields.io/github/forks/Ascotbe/Kernelhub.svg)


## CVE-2022-27518
 Unauthenticated remote arbitrary code execution

- [https://github.com/dolby360/CVE-2022-27518_POC](https://github.com/dolby360/CVE-2022-27518_POC) :  ![starts](https://img.shields.io/github/stars/dolby360/CVE-2022-27518_POC.svg) ![forks](https://img.shields.io/github/forks/dolby360/CVE-2022-27518_POC.svg)


## CVE-2022-26937
 Windows Network File System Remote Code Execution Vulnerability.

- [https://github.com/Ascotbe/Kernelhub](https://github.com/Ascotbe/Kernelhub) :  ![starts](https://img.shields.io/github/stars/Ascotbe/Kernelhub.svg) ![forks](https://img.shields.io/github/forks/Ascotbe/Kernelhub.svg)


## CVE-2022-23540
 In versions `&lt;=8.5.1` of `jsonwebtoken` library, lack of algorithm definition in the `jwt.verify()` function can lead to signature validation bypass due to defaulting to the `none` algorithm for signature verification. Users are affected if you do not specify algorithms in the `jwt.verify()` function. This issue has been fixed, please update to version 9.0.0 which removes the default support for the none algorithm in the `jwt.verify()` method. There will be no impact, if you update to version 9.0.0 and you don&#8217;t need to allow for the `none` algorithm. If you need 'none' algorithm, you have to explicitly specify that in `jwt.verify()` options.

- [https://github.com/jsirichai/CVE-2022-23540-PoC](https://github.com/jsirichai/CVE-2022-23540-PoC) :  ![starts](https://img.shields.io/github/stars/jsirichai/CVE-2022-23540-PoC.svg) ![forks](https://img.shields.io/github/forks/jsirichai/CVE-2022-23540-PoC.svg)


## CVE-2022-20583
 In ppmp_unprotect_mfcfw_buf of drm_fw.c, there is a possible out of bounds write due to improper input validation. This could lead to local escalation of privilege in S-EL1 with System execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-234859169References: N/A

- [https://github.com/Live-Hack-CVE/CVE-2022-20583](https://github.com/Live-Hack-CVE/CVE-2022-20583) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-20583.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-20583.svg)


## CVE-2022-20413
 In start of Threads.cpp, there is a possible way to record audio during a phone call due to a logic error in the code. This could lead to local information disclosure with User execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-10 Android-11 Android-12 Android-12L Android-13Android ID: A-235850634

- [https://github.com/pazhanivel07/frameworks_av-r33_CVE-2022-20413](https://github.com/pazhanivel07/frameworks_av-r33_CVE-2022-20413) :  ![starts](https://img.shields.io/github/stars/pazhanivel07/frameworks_av-r33_CVE-2022-20413.svg) ![forks](https://img.shields.io/github/forks/pazhanivel07/frameworks_av-r33_CVE-2022-20413.svg)


## CVE-2022-4891
 A vulnerability has been found in Sisimai up to 4.25.14p11 and classified as problematic. This vulnerability affects the function to_plain of the file lib/sisimai/string.rb. The manipulation leads to inefficient regular expression complexity. The exploit has been disclosed to the public and may be used. Upgrading to version 4.25.14p12 is able to address this issue. The name of the patch is 51fe2e6521c9c02b421b383943dc9e4bbbe65d4e. It is recommended to upgrade the affected component. The identifier of this vulnerability is VDB-218452.

- [https://github.com/Live-Hack-CVE/CVE-2022-4891](https://github.com/Live-Hack-CVE/CVE-2022-4891) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4891.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4891.svg)


## CVE-2022-4643
 A vulnerability was found in docconv up to 1.2.0. It has been declared as critical. This vulnerability affects the function ConvertPDFImages of the file pdf_ocr.go. The manipulation of the argument path leads to os command injection. The attack can be initiated remotely. Upgrading to version 1.2.1 is able to address this issue. The name of the patch is b19021ade3d0b71c89d35cb00eb9e589a121faa5. It is recommended to upgrade the affected component. VDB-216502 is the identifier assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2022-4643](https://github.com/Live-Hack-CVE/CVE-2022-4643) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4643.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4643.svg)


## CVE-2022-4621
 Panasonic Sanyo CCTV Network Cameras versions 1.02-05 and 2.03-0x are vulnerable to CSRFs that can be exploited to allow an attacker to perform changes with administrator level privileges.

- [https://github.com/Live-Hack-CVE/CVE-2022-4621](https://github.com/Live-Hack-CVE/CVE-2022-4621) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4621.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4621.svg)


## CVE-2022-4249
 A vulnerability, which was classified as problematic, was found in Movie Ticket Booking System. Affected is an unknown function of the component POST Request Handler. The manipulation of the argument ORDER_ID leads to cross site scripting. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used. VDB-214626 is the identifier assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2022-4249](https://github.com/Live-Hack-CVE/CVE-2022-4249) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4249.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4249.svg)


## CVE-2022-4121
 In libetpan a null pointer dereference in mailimap_mailbox_data_status_free in low-level/imap/mailimap_types.c was found that could lead to a remote denial of service or other potential consequences.

- [https://github.com/Live-Hack-CVE/CVE-2022-4121](https://github.com/Live-Hack-CVE/CVE-2022-4121) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4121.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4121.svg)


## CVE-2022-3091
 RONDS EPM version 1.19.5 has a vulnerability in which a function could allow unauthenticated users to leak credentials. In some circumstances, an attacker can exploit this vulnerability to execute operating system (OS) commands.

- [https://github.com/Live-Hack-CVE/CVE-2022-3091](https://github.com/Live-Hack-CVE/CVE-2022-3091) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-3091.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-3091.svg)


## CVE-2022-2982
 Use After Free in GitHub repository vim/vim prior to 9.0.0260.

- [https://github.com/Live-Hack-CVE/CVE-2022-2982](https://github.com/Live-Hack-CVE/CVE-2022-2982) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2982.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2982.svg)


## CVE-2022-2893
 RONDS EPM version 1.19.5 does not properly validate the filename parameter, which could allow an unauthorized user to specify file paths and download files.

- [https://github.com/Live-Hack-CVE/CVE-2022-2893](https://github.com/Live-Hack-CVE/CVE-2022-2893) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2893.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2893.svg)


## CVE-2022-2516
 The Visual Composer Website Builder plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the post/page 'Title' value in versions up to, and including, 45.0 due to insufficient input sanitization and output escaping. This makes it possible for authenticated attackers with access to the visual composer editor to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.

- [https://github.com/Live-Hack-CVE/CVE-2022-2516](https://github.com/Live-Hack-CVE/CVE-2022-2516) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2516.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2516.svg)


## CVE-2022-1427
 Out-of-bounds Read in mrb_obj_is_kind_of in in GitHub repository mruby/mruby prior to 3.2. # Impact: Possible arbitrary code execution if being exploited.

- [https://github.com/Live-Hack-CVE/CVE-2022-1427](https://github.com/Live-Hack-CVE/CVE-2022-1427) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-1427.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-1427.svg)


## CVE-2022-1201
 NULL Pointer Dereference in mrb_vm_exec with super in GitHub repository mruby/mruby prior to 3.2. This vulnerability is capable of making the mruby interpreter crash, thus affecting the availability of the system.

- [https://github.com/Live-Hack-CVE/CVE-2022-1201](https://github.com/Live-Hack-CVE/CVE-2022-1201) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-1201.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-1201.svg)


## CVE-2022-0614
 Use of Out-of-range Pointer Offset in Homebrew mruby prior to 3.2.

- [https://github.com/Live-Hack-CVE/CVE-2022-0614](https://github.com/Live-Hack-CVE/CVE-2022-0614) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-0614.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-0614.svg)


## CVE-2021-32837
 mechanize, a library for automatically interacting with HTTP web servers, contains a regular expression that is vulnerable to regular expression denial of service (ReDoS) prior to version 0.4.6. If a web server responds in a malicious way, then mechanize could crash. Version 0.4.6 has a patch for the issue.

- [https://github.com/Live-Hack-CVE/CVE-2021-32837](https://github.com/Live-Hack-CVE/CVE-2021-32837) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-32837.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-32837.svg)


## CVE-2021-30128
 Apache OFBiz has unsafe deserialization prior to 17.12.07 version

- [https://github.com/LioTree/CVE-2021-30128-EXP](https://github.com/LioTree/CVE-2021-30128-EXP) :  ![starts](https://img.shields.io/github/stars/LioTree/CVE-2021-30128-EXP.svg) ![forks](https://img.shields.io/github/forks/LioTree/CVE-2021-30128-EXP.svg)


## CVE-2021-26385
 ** REJECT ** DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: none. Reason: This candidate is unused by its CNA. Notes: none.

- [https://github.com/Live-Hack-CVE/CVE-2021-26385](https://github.com/Live-Hack-CVE/CVE-2021-26385) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-26385.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-26385.svg)


## CVE-2021-26358
 ** REJECT ** DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: none. Reason: This candidate is unused by its CNA. Notes: none.

- [https://github.com/Live-Hack-CVE/CVE-2021-26358](https://github.com/Live-Hack-CVE/CVE-2021-26358) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-26358.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-26358.svg)


## CVE-2021-26357
 ** REJECT ** DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: none. Reason: This candidate is unused by its CNA. Notes: none.

- [https://github.com/Live-Hack-CVE/CVE-2021-26357](https://github.com/Live-Hack-CVE/CVE-2021-26357) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-26357.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-26357.svg)


## CVE-2021-26319
 ** REJECT ** DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: none. Reason: This candidate is unused by its CNA. Notes: none.

- [https://github.com/Live-Hack-CVE/CVE-2021-26319](https://github.com/Live-Hack-CVE/CVE-2021-26319) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-26319.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-26319.svg)


## CVE-2020-36654
 A vulnerability classified as problematic has been found in GENI Portal. This affects the function no_invocation_id_error of the file portal/www/portal/sliceresource.php. The manipulation of the argument invocation_id/invocation_user leads to cross site scripting. It is possible to initiate the attack remotely. The name of the patch is 39a96fb4b822bd3497442a96135de498d4a81337. It is recommended to apply a patch to fix this issue. The associated identifier of this vulnerability is VDB-218475.

- [https://github.com/Live-Hack-CVE/CVE-2020-36654](https://github.com/Live-Hack-CVE/CVE-2020-36654) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-36654.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-36654.svg)


## CVE-2020-36653
 A vulnerability was found in GENI Portal. It has been rated as problematic. Affected by this issue is some unknown functionality of the file portal/www/portal/error-text.php. The manipulation of the argument error leads to cross site scripting. The attack may be launched remotely. The name of the patch is c2356cc41260551073bfaa3a94d1ab074f554938. It is recommended to apply a patch to fix this issue. VDB-218474 is the identifier assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2020-36653](https://github.com/Live-Hack-CVE/CVE-2020-36653) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-36653.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-36653.svg)


## CVE-2020-13802
 Rebar3 versions 3.0.0-beta.3 to 3.13.2 are vulnerable to OS command injection via URL parameter of dependency specification.

- [https://github.com/vulnbe/poc-rebar3](https://github.com/vulnbe/poc-rebar3) :  ![starts](https://img.shields.io/github/stars/vulnbe/poc-rebar3.svg) ![forks](https://img.shields.io/github/forks/vulnbe/poc-rebar3.svg)


## CVE-2019-12460
 Web Port 1.19.1 allows XSS via the /access/setup type parameter.

- [https://github.com/EmreOvunc/WebPort-v1.19.1-Reflected-XSS](https://github.com/EmreOvunc/WebPort-v1.19.1-Reflected-XSS) :  ![starts](https://img.shields.io/github/stars/EmreOvunc/WebPort-v1.19.1-Reflected-XSS.svg) ![forks](https://img.shields.io/github/forks/EmreOvunc/WebPort-v1.19.1-Reflected-XSS.svg)


## CVE-2019-8979
 Kohana through 3.3.6 has SQL Injection when the order_by() parameter can be controlled.

- [https://github.com/elttam/ko7demo](https://github.com/elttam/ko7demo) :  ![starts](https://img.shields.io/github/stars/elttam/ko7demo.svg) ![forks](https://img.shields.io/github/forks/elttam/ko7demo.svg)


## CVE-2019-1132
 An elevation of privilege vulnerability exists in Windows when the Win32k component fails to properly handle objects in memory, aka 'Win32k Elevation of Privilege Vulnerability'.

- [https://github.com/Vlad-tri/CVE-2019-1132](https://github.com/Vlad-tri/CVE-2019-1132) :  ![starts](https://img.shields.io/github/stars/Vlad-tri/CVE-2019-1132.svg) ![forks](https://img.shields.io/github/forks/Vlad-tri/CVE-2019-1132.svg)


## CVE-2018-14628
 An information leak vulnerability was discovered in Samba's LDAP server. Due to missing access control checks, an authenticated but unprivileged attacker could discover the names and preserved attributes of deleted objects in the LDAP store.

- [https://github.com/Live-Hack-CVE/CVE-2018-14628](https://github.com/Live-Hack-CVE/CVE-2018-14628) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2018-14628.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2018-14628.svg)


## CVE-2018-6622
 An issue was discovered that affects all producers of BIOS firmware who make a certain realistic interpretation of an obscure portion of the Trusted Computing Group (TCG) Trusted Platform Module (TPM) 2.0 specification. An abnormal case is not handled properly by this firmware while S3 sleep and can clear TPM 2.0. It allows local users to overwrite static PCRs of TPM and neutralize the security features of it, such as seal/unseal and remote attestation.

- [https://github.com/kkamagui/bitleaker](https://github.com/kkamagui/bitleaker) :  ![starts](https://img.shields.io/github/stars/kkamagui/bitleaker.svg) ![forks](https://img.shields.io/github/forks/kkamagui/bitleaker.svg)


## CVE-2018-5146
 An out of bounds memory write while processing Vorbis audio data was reported through the Pwn2Own contest. This vulnerability affects Firefox &lt; 59.0.1, Firefox ESR &lt; 52.7.2, and Thunderbird &lt; 52.7.

- [https://github.com/Live-Hack-CVE/CVE-2020-20412](https://github.com/Live-Hack-CVE/CVE-2020-20412) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-20412.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-20412.svg)


## CVE-2017-20173
 A vulnerability was found in AlexRed contentmap. It has been rated as critical. Affected by this issue is the function Load of the file contentmap.php. The manipulation of the argument contentid leads to sql injection. The name of the patch is dd265d23ff4abac97422835002c6a47f45ae2a66. It is recommended to apply a patch to fix this issue. The identifier of this vulnerability is VDB-218492.

- [https://github.com/Live-Hack-CVE/CVE-2017-20173](https://github.com/Live-Hack-CVE/CVE-2017-20173) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2017-20173.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2017-20173.svg)


## CVE-2016-4565
 The InfiniBand (aka IB) stack in the Linux kernel before 4.5.3 incorrectly relies on the write system call, which allows local users to cause a denial of service (kernel memory write operation) or possibly have unspecified other impact via a uAPI interface.

- [https://github.com/Live-Hack-CVE/CVE-2016-4565](https://github.com/Live-Hack-CVE/CVE-2016-4565) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-4565.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-4565.svg)


## CVE-2016-4557
 The replace_map_fd_with_map_ptr function in kernel/bpf/verifier.c in the Linux kernel before 4.5.5 does not properly maintain an fd data structure, which allows local users to gain privileges or cause a denial of service (use-after-free) via crafted BPF instructions that reference an incorrect file descriptor.

- [https://github.com/Live-Hack-CVE/CVE-2016-4557](https://github.com/Live-Hack-CVE/CVE-2016-4557) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-4557.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-4557.svg)


## CVE-2016-4440
 arch/x86/kvm/vmx.c in the Linux kernel through 4.6.3 mishandles the APICv on/off state, which allows guest OS users to obtain direct APIC MSR access on the host OS, and consequently cause a denial of service (host OS crash) or possibly execute arbitrary code on the host OS, via x2APIC mode.

- [https://github.com/Live-Hack-CVE/CVE-2016-4440](https://github.com/Live-Hack-CVE/CVE-2016-4440) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-4440.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-4440.svg)


## CVE-2016-3135
 Integer overflow in the xt_alloc_table_info function in net/netfilter/x_tables.c in the Linux kernel through 4.5.2 on 32-bit platforms allows local users to gain privileges or cause a denial of service (heap memory corruption) via an IPT_SO_SET_REPLACE setsockopt call.

- [https://github.com/Live-Hack-CVE/CVE-2016-3135](https://github.com/Live-Hack-CVE/CVE-2016-3135) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-3135.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-3135.svg)


## CVE-2016-2070
 The tcp_cwnd_reduction function in net/ipv4/tcp_input.c in the Linux kernel before 4.3.5 allows remote attackers to cause a denial of service (divide-by-zero error and system crash) via crafted TCP traffic.

- [https://github.com/Live-Hack-CVE/CVE-2016-2070](https://github.com/Live-Hack-CVE/CVE-2016-2070) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-2070.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-2070.svg)


## CVE-2016-1583
 The ecryptfs_privileged_open function in fs/ecryptfs/kthread.c in the Linux kernel before 4.6.3 allows local users to gain privileges or cause a denial of service (stack memory consumption) via vectors involving crafted mmap calls for /proc pathnames, leading to recursive pagefault handling.

- [https://github.com/Live-Hack-CVE/CVE-2016-1583](https://github.com/Live-Hack-CVE/CVE-2016-1583) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-1583.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-1583.svg)


## CVE-2015-10068
 A vulnerability classified as critical was found in danynab movify-j. This vulnerability affects the function getByMovieId of the file app/business/impl/ReviewServiceImpl.java. The manipulation of the argument movieId/username leads to sql injection. The name of the patch is c3085e01936a4d7eff1eda3093f25d56cc4d2ec5. It is recommended to apply a patch to fix this issue. The identifier of this vulnerability is VDB-218476.

- [https://github.com/Live-Hack-CVE/CVE-2015-10068](https://github.com/Live-Hack-CVE/CVE-2015-10068) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2015-10068.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2015-10068.svg)


## CVE-2015-10067
 A vulnerability was found in oznetmaster SSharpSmartThreadPool. It has been classified as problematic. This affects an unknown part of the file SSharpSmartThreadPool/SmartThreadPool.cs. The manipulation leads to race condition within a thread. The name of the patch is 0e58073c831093aad75e077962e9fb55cad0dc5f. It is recommended to apply a patch to fix this issue. The associated identifier of this vulnerability is VDB-218463.

- [https://github.com/Live-Hack-CVE/CVE-2015-10067](https://github.com/Live-Hack-CVE/CVE-2015-10067) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2015-10067.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2015-10067.svg)


## CVE-2015-10039
 A vulnerability was found in dobos domino. It has been rated as critical. Affected by this issue is some unknown functionality in the library src/Complex.Domino.Lib/Lib/EntityFactory.cs. The manipulation leads to sql injection. Upgrading to version 0.1.5524.38553 is able to address this issue. The name of the patch is 16f039073709a21a76526110d773a6cce0ce753a. It is recommended to upgrade the affected component. The identifier of this vulnerability is VDB-218024.

- [https://github.com/Live-Hack-CVE/CVE-2015-10039](https://github.com/Live-Hack-CVE/CVE-2015-10039) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2015-10039.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2015-10039.svg)


## CVE-2015-10038
 A vulnerability was found in nym3r0s pplv2. It has been declared as critical. Affected by this vulnerability is an unknown functionality. The manipulation leads to sql injection. The name of the patch is 28f8b0550104044da09f04659797487c59f85b00. It is recommended to apply a patch to fix this issue. The associated identifier of this vulnerability is VDB-218023.

- [https://github.com/Live-Hack-CVE/CVE-2015-10038](https://github.com/Live-Hack-CVE/CVE-2015-10038) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2015-10038.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2015-10038.svg)


## CVE-2015-10037
 A vulnerability, which was classified as critical, was found in ACI_Escola. This affects an unknown part. The manipulation leads to sql injection. The name of the patch is 34eed1f7b9295d1424912f79989d8aba5de41e9f. It is recommended to apply a patch to fix this issue. The identifier VDB-217965 was assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2015-10037](https://github.com/Live-Hack-CVE/CVE-2015-10037) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2015-10037.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2015-10037.svg)


## CVE-2015-10036
 A vulnerability was found in kylebebak dronfelipe. It has been declared as critical. Affected by this vulnerability is an unknown functionality. The manipulation leads to sql injection. The name of the patch is 87405b74fe651892d79d0dff62ed17a7eaef6a60. It is recommended to apply a patch to fix this issue. The associated identifier of this vulnerability is VDB-217951.

- [https://github.com/Live-Hack-CVE/CVE-2015-10036](https://github.com/Live-Hack-CVE/CVE-2015-10036) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2015-10036.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2015-10036.svg)


## CVE-2015-3288
 mm/memory.c in the Linux kernel before 4.1.4 mishandles anonymous pages, which allows local users to gain privileges or cause a denial of service (page tainting) via a crafted application that triggers writing to page zero.

- [https://github.com/Live-Hack-CVE/CVE-2015-3288](https://github.com/Live-Hack-CVE/CVE-2015-3288) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2015-3288.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2015-3288.svg)


## CVE-2014-9914
 Race condition in the ip4_datagram_release_cb function in net/ipv4/datagram.c in the Linux kernel before 3.15.2 allows local users to gain privileges or cause a denial of service (use-after-free) by leveraging incorrect expectations about locking during multithreaded access to internal data structures for IPv4 UDP sockets.

- [https://github.com/Live-Hack-CVE/CVE-2014-9914](https://github.com/Live-Hack-CVE/CVE-2014-9914) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2014-9914.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2014-9914.svg)


## CVE-2014-9904
 The snd_compress_check_input function in sound/core/compress_offload.c in the ALSA subsystem in the Linux kernel before 3.17 does not properly check for an integer overflow, which allows local users to cause a denial of service (insufficient memory allocation) or possibly have unspecified other impact via a crafted SNDRV_COMPRESS_SET_PARAMS ioctl call.

- [https://github.com/Live-Hack-CVE/CVE-2014-9904](https://github.com/Live-Hack-CVE/CVE-2014-9904) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2014-9904.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2014-9904.svg)


## CVE-2014-7145
 The SMB2_tcon function in fs/cifs/smb2pdu.c in the Linux kernel before 3.16.3 allows remote CIFS servers to cause a denial of service (NULL pointer dereference and client system crash) or possibly have unspecified other impact by deleting the IPC$ share during resolution of DFS referrals.

- [https://github.com/Live-Hack-CVE/CVE-2014-7145](https://github.com/Live-Hack-CVE/CVE-2014-7145) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2014-7145.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2014-7145.svg)


## CVE-2014-6416
 Buffer overflow in net/ceph/auth_x.c in Ceph, as used in the Linux kernel before 3.16.3, allows remote attackers to cause a denial of service (memory corruption and panic) or possibly have unspecified other impact via a long unencrypted auth ticket.

- [https://github.com/Live-Hack-CVE/CVE-2014-6416](https://github.com/Live-Hack-CVE/CVE-2014-6416) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2014-6416.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2014-6416.svg)


## CVE-2013-4247
 Off-by-one error in the build_unc_path_to_root function in fs/cifs/connect.c in the Linux kernel before 3.9.6 allows remote attackers to cause a denial of service (memory corruption and system crash) via a DFS share mount operation that triggers use of an unexpected DFS referral name length.

- [https://github.com/Live-Hack-CVE/CVE-2013-4247](https://github.com/Live-Hack-CVE/CVE-2013-4247) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2013-4247.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2013-4247.svg)


## CVE-2013-1059
 net/ceph/auth_none.c in the Linux kernel through 3.10 allows remote attackers to cause a denial of service (NULL pointer dereference and system crash) or possibly have unspecified other impact via an auth_reply message that triggers an attempted build_request operation.

- [https://github.com/Live-Hack-CVE/CVE-2013-1059](https://github.com/Live-Hack-CVE/CVE-2013-1059) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2013-1059.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2013-1059.svg)


## CVE-2012-10006
 A vulnerability classified as critical has been found in ale7714 sigeprosi. This affects an unknown part. The manipulation leads to sql injection. The name of the patch is 5291886f6c992316407c376145d331169c55f25b. It is recommended to apply a patch to fix this issue. The identifier VDB-218493 was assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2012-10006](https://github.com/Live-Hack-CVE/CVE-2012-10006) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2012-10006.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2012-10006.svg)


## CVE-2012-10004
 A vulnerability was found in backdrop-contrib Basic Cart. It has been classified as problematic. Affected is the function basic_cart_checkout_form_submit of the file basic_cart.cart.inc. The manipulation leads to cross site scripting. It is possible to launch the attack remotely. Upgrading to version 1.x-1.1.1 is able to address this issue. The name of the patch is a10424ccd4b3b4b433cf33b73c1ad608b11890b4. It is recommended to upgrade the affected component. VDB-217950 is the identifier assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2012-10004](https://github.com/Live-Hack-CVE/CVE-2012-10004) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2012-10004.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2012-10004.svg)


## CVE-2012-6704
 The sock_setsockopt function in net/core/sock.c in the Linux kernel before 3.5 mishandles negative values of sk_sndbuf and sk_rcvbuf, which allows local users to cause a denial of service (memory corruption and system crash) or possibly have unspecified other impact by leveraging the CAP_NET_ADMIN capability for a crafted setsockopt system call with the (1) SO_SNDBUF or (2) SO_RCVBUF option.

- [https://github.com/Live-Hack-CVE/CVE-2012-6704](https://github.com/Live-Hack-CVE/CVE-2012-6704) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2012-6704.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2012-6704.svg)


## CVE-2012-6703
 Integer overflow in the snd_compr_allocate_buffer function in sound/core/compress_offload.c in the ALSA subsystem in the Linux kernel before 3.6-rc6-next-20120917 allows local users to cause a denial of service (insufficient memory allocation) or possibly have unspecified other impact via a crafted SNDRV_COMPRESS_SET_PARAMS ioctl call.

- [https://github.com/Live-Hack-CVE/CVE-2012-6703](https://github.com/Live-Hack-CVE/CVE-2012-6703) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2012-6703.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2012-6703.svg)


## CVE-2012-6701
 Integer overflow in fs/aio.c in the Linux kernel before 3.4.1 allows local users to cause a denial of service or possibly have unspecified other impact via a large AIO iovec.

- [https://github.com/Live-Hack-CVE/CVE-2012-6701](https://github.com/Live-Hack-CVE/CVE-2012-6701) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2012-6701.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2012-6701.svg)


## CVE-2012-6638
 The tcp_rcv_state_process function in net/ipv4/tcp_input.c in the Linux kernel before 3.2.24 allows remote attackers to cause a denial of service (kernel resource consumption) via a flood of SYN+FIN TCP packets, a different vulnerability than CVE-2012-2663.

- [https://github.com/Live-Hack-CVE/CVE-2012-6638](https://github.com/Live-Hack-CVE/CVE-2012-6638) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2012-6638.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2012-6638.svg)


## CVE-2012-3400
 Heap-based buffer overflow in the udf_load_logicalvol function in fs/udf/super.c in the Linux kernel before 3.4.5 allows remote attackers to cause a denial of service (system crash) or possibly have unspecified other impact via a crafted UDF filesystem.

- [https://github.com/Live-Hack-CVE/CVE-2012-3400](https://github.com/Live-Hack-CVE/CVE-2012-3400) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2012-3400.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2012-3400.svg)


## CVE-2012-2663
 extensions/libxt_tcp.c in iptables through 1.4.21 does not match TCP SYN+FIN packets in --syn rules, which might allow remote attackers to bypass intended firewall restrictions via crafted packets.  NOTE: the CVE-2012-6638 fix makes this issue less relevant.

- [https://github.com/Live-Hack-CVE/CVE-2012-6638](https://github.com/Live-Hack-CVE/CVE-2012-6638) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2012-6638.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2012-6638.svg)


## CVE-2011-10001
 A vulnerability was found in iamdroppy phoenixcf. It has been declared as critical. Affected by this vulnerability is an unknown functionality of the file content/2-Community/articles.cfm. The manipulation leads to sql injection. The name of the patch is d156faf8bc36cd49c3b10d3697ef14167ad451d8. It is recommended to apply a patch to fix this issue. The associated identifier of this vulnerability is VDB-218491.

- [https://github.com/Live-Hack-CVE/CVE-2011-10001](https://github.com/Live-Hack-CVE/CVE-2011-10001) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2011-10001.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2011-10001.svg)


## CVE-2010-10007
 ** UNSUPPORTED WHEN ASSIGNED ** A vulnerability was found in lierdakil click-reminder. It has been rated as critical. This issue affects the function db_query of the file src/backend/include/BaseAction.php. The manipulation leads to sql injection. The name of the patch is 41213b660e8eb01b22c8074f06208f59a73ca8dc. It is recommended to apply a patch to fix this issue. The identifier VDB-218465 was assigned to this vulnerability. NOTE: This vulnerability only affects products that are no longer supported by the maintainer.

- [https://github.com/Live-Hack-CVE/CVE-2010-10007](https://github.com/Live-Hack-CVE/CVE-2010-10007) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2010-10007.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2010-10007.svg)


## CVE-2010-10006
 A vulnerability, which was classified as problematic, was found in michaelliao jopenid. Affected is the function getAuthentication of the file JOpenId/src/org/expressme/openid/OpenIdManager.java. The manipulation leads to observable timing discrepancy. Upgrading to version 1.08 is able to address this issue. The name of the patch is c9baaa976b684637f0d5a50268e91846a7a719ab. It is recommended to upgrade the affected component. The identifier of this vulnerability is VDB-218460.

- [https://github.com/Live-Hack-CVE/CVE-2010-10006](https://github.com/Live-Hack-CVE/CVE-2010-10006) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2010-10006.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2010-10006.svg)


## CVE-2007-6601
 The DBLink module in PostgreSQL 8.2 before 8.2.6, 8.1 before 8.1.11, 8.0 before 8.0.15, 7.4 before 7.4.19, and 7.3 before 7.3.21, when local trust or ident authentication is used, allows remote attackers to gain privileges via unspecified vectors.  NOTE: this issue exists because of an incomplete fix for CVE-2007-3278.

- [https://github.com/Live-Hack-CVE/CVE-2007-6601](https://github.com/Live-Hack-CVE/CVE-2007-6601) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2007-6601.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2007-6601.svg)


## CVE-2007-3278
 PostgreSQL 8.1 and probably later versions, when local trust authentication is enabled and the Database Link library (dblink) is installed, allows remote attackers to access arbitrary accounts and execute arbitrary SQL queries via a dblink host parameter that proxies the connection from 127.0.0.1.

- [https://github.com/Live-Hack-CVE/CVE-2007-6601](https://github.com/Live-Hack-CVE/CVE-2007-6601) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2007-6601.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2007-6601.svg)


## CVE-2006-3360
 Directory traversal vulnerability in index.php in phpSysInfo 2.5.1 allows remote attackers to determine the existence of arbitrary files via a .. (dot dot) sequence and a trailing null (%00) byte in the lng parameter, which will display a different error message if the file exists.

- [https://github.com/Live-Hack-CVE/CVE-2006-3360](https://github.com/Live-Hack-CVE/CVE-2006-3360) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2006-3360.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2006-3360.svg)

