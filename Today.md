# Update 2023-08-11
## CVE-2023-38646
 Metabase open source before 0.46.6.1 and Metabase Enterprise before 1.46.6.1 allow attackers to execute arbitrary commands on the server, at the server's privilege level. Authentication is not required for exploitation. The other fixed versions are 0.45.4.1, 1.45.4.1, 0.44.7.1, 1.44.7.1, 0.43.7.2, and 1.43.7.2.

- [https://github.com/robotmikhro/CVE-2023-38646](https://github.com/robotmikhro/CVE-2023-38646) :  ![starts](https://img.shields.io/github/stars/robotmikhro/CVE-2023-38646.svg) ![forks](https://img.shields.io/github/forks/robotmikhro/CVE-2023-38646.svg)


## CVE-2023-38408
 The PKCS#11 feature in ssh-agent in OpenSSH before 9.3p2 has an insufficiently trustworthy search path, leading to remote code execution if an agent is forwarded to an attacker-controlled system. (Code in /usr/lib is not necessarily safe for loading into ssh-agent.) NOTE: this issue exists because of an incomplete fix for CVE-2016-10009.

- [https://github.com/kali-mx/CVE-2023-38408](https://github.com/kali-mx/CVE-2023-38408) :  ![starts](https://img.shields.io/github/stars/kali-mx/CVE-2023-38408.svg) ![forks](https://img.shields.io/github/forks/kali-mx/CVE-2023-38408.svg)


## CVE-2023-35885
 CloudPanel 2 before 2.3.1 has insecure file-manager cookie authentication.

- [https://github.com/getdrive/PoC](https://github.com/getdrive/PoC) :  ![starts](https://img.shields.io/github/stars/getdrive/PoC.svg) ![forks](https://img.shields.io/github/forks/getdrive/PoC.svg)


## CVE-2023-30533
 SheetJS Community Edition before 0.19.3 allows Prototype Pollution via a crafted file.

- [https://github.com/BenEdridge/CVE-2023-30533](https://github.com/BenEdridge/CVE-2023-30533) :  ![starts](https://img.shields.io/github/stars/BenEdridge/CVE-2023-30533.svg) ![forks](https://img.shields.io/github/forks/BenEdridge/CVE-2023-30533.svg)


## CVE-2023-28771
 Improper error message handling in Zyxel ZyWALL/USG series firmware versions 4.60 through 4.73, VPN series firmware versions 4.60 through 5.35, USG FLEX series firmware versions 4.60 through 5.35, and ATP series firmware versions 4.60 through 5.35, which could allow an unauthenticated attacker to execute some OS commands remotely by sending crafted packets to an affected device.

- [https://github.com/getdrive/PoC](https://github.com/getdrive/PoC) :  ![starts](https://img.shields.io/github/stars/getdrive/PoC.svg) ![forks](https://img.shields.io/github/forks/getdrive/PoC.svg)


## CVE-2023-28121
 An issue in WooCommerce Payments plugin for WordPress (versions 5.6.1 and lower) allows an unauthenticated attacker to send requests on behalf of an elevated user, like administrator. This allows a remote, unauthenticated attacker to gain admin access on a site that has the affected version of the plugin activated.

- [https://github.com/getdrive/PoC](https://github.com/getdrive/PoC) :  ![starts](https://img.shields.io/github/stars/getdrive/PoC.svg) ![forks](https://img.shields.io/github/forks/getdrive/PoC.svg)


## CVE-2023-27163
 request-baskets up to v1.2.1 was discovered to contain a Server-Side Request Forgery (SSRF) via the component /api/baskets/{name}. This vulnerability allows attackers to access network resources and sensitive information via a crafted API request.

- [https://github.com/rvizx/CVE-2023-27163](https://github.com/rvizx/CVE-2023-27163) :  ![starts](https://img.shields.io/github/stars/rvizx/CVE-2023-27163.svg) ![forks](https://img.shields.io/github/forks/rvizx/CVE-2023-27163.svg)


## CVE-2023-26360
 Adobe ColdFusion versions 2018 Update 15 (and earlier) and 2021 Update 5 (and earlier) are affected by an Improper Access Control vulnerability that could result in arbitrary code execution in the context of the current user. Exploitation of this issue does not require user interaction.

- [https://github.com/getdrive/PoC](https://github.com/getdrive/PoC) :  ![starts](https://img.shields.io/github/stars/getdrive/PoC.svg) ![forks](https://img.shields.io/github/forks/getdrive/PoC.svg)


## CVE-2023-2650
 Issue summary: Processing some specially crafted ASN.1 object identifiers or data containing them may be very slow. Impact summary: Applications that use OBJ_obj2txt() directly, or use any of the OpenSSL subsystems OCSP, PKCS7/SMIME, CMS, CMP/CRMF or TS with no message size limit may experience notable to very long delays when processing those messages, which may lead to a Denial of Service. An OBJECT IDENTIFIER is composed of a series of numbers - sub-identifiers - most of which have no size limit. OBJ_obj2txt() may be used to translate an ASN.1 OBJECT IDENTIFIER given in DER encoding form (using the OpenSSL type ASN1_OBJECT) to its canonical numeric text form, which are the sub-identifiers of the OBJECT IDENTIFIER in decimal form, separated by periods. When one of the sub-identifiers in the OBJECT IDENTIFIER is very large (these are sizes that are seen as absurdly large, taking up tens or hundreds of KiBs), the translation to a decimal number in text may take a very long time. The time complexity is O(n^2) with 'n' being the size of the sub-identifiers in bytes (*). With OpenSSL 3.0, support to fetch cryptographic algorithms using names / identifiers in string form was introduced. This includes using OBJECT IDENTIFIERs in canonical numeric text form as identifiers for fetching algorithms. Such OBJECT IDENTIFIERs may be received through the ASN.1 structure AlgorithmIdentifier, which is commonly used in multiple protocols to specify what cryptographic algorithm should be used to sign or verify, encrypt or decrypt, or digest passed data. Applications that call OBJ_obj2txt() directly with untrusted data are affected, with any version of OpenSSL. If the use is for the mere purpose of display, the severity is considered low. In OpenSSL 3.0 and newer, this affects the subsystems OCSP, PKCS7/SMIME, CMS, CMP/CRMF or TS. It also impacts anything that processes X.509 certificates, including simple things like verifying its signature. The impact on TLS is relatively low, because all versions of OpenSSL have a 100KiB limit on the peer's certificate chain. Additionally, this only impacts clients, or servers that have explicitly enabled client authentication. In OpenSSL 1.1.1 and 1.0.2, this only affects displaying diverse objects, such as X.509 certificates. This is assumed to not happen in such a way that it would cause a Denial of Service, so these versions are considered not affected by this issue in such a way that it would be cause for concern, and the severity is therefore considered low.

- [https://github.com/hshivhare67/OpenSSL_1.1.1g_CVE-2023-2650](https://github.com/hshivhare67/OpenSSL_1.1.1g_CVE-2023-2650) :  ![starts](https://img.shields.io/github/stars/hshivhare67/OpenSSL_1.1.1g_CVE-2023-2650.svg) ![forks](https://img.shields.io/github/forks/hshivhare67/OpenSSL_1.1.1g_CVE-2023-2650.svg)


## CVE-2022-30190
 Microsoft Windows Support Diagnostic Tool (MSDT) Remote Code Execution Vulnerability.

- [https://github.com/khulnasoft-lab/awesome-security](https://github.com/khulnasoft-lab/awesome-security) :  ![starts](https://img.shields.io/github/stars/khulnasoft-lab/awesome-security.svg) ![forks](https://img.shields.io/github/forks/khulnasoft-lab/awesome-security.svg)


## CVE-2022-26134
 In affected versions of Confluence Server and Data Center, an OGNL injection vulnerability exists that would allow an unauthenticated attacker to execute arbitrary code on a Confluence Server or Data Center instance. The affected versions are from 1.3.0 before 7.4.17, from 7.13.0 before 7.13.7, from 7.14.0 before 7.14.3, from 7.15.0 before 7.15.2, from 7.16.0 before 7.16.4, from 7.17.0 before 7.17.4, and from 7.18.0 before 7.18.1.

- [https://github.com/khulnasoft-lab/awesome-security](https://github.com/khulnasoft-lab/awesome-security) :  ![starts](https://img.shields.io/github/stars/khulnasoft-lab/awesome-security.svg) ![forks](https://img.shields.io/github/forks/khulnasoft-lab/awesome-security.svg)


## CVE-2022-24124
 The query API in Casdoor before 1.13.1 has a SQL injection vulnerability related to the field and value parameters, as demonstrated by api/get-organizations.

- [https://github.com/b1gdog/CVE-2022-24124_POC](https://github.com/b1gdog/CVE-2022-24124_POC) :  ![starts](https://img.shields.io/github/stars/b1gdog/CVE-2022-24124_POC.svg) ![forks](https://img.shields.io/github/forks/b1gdog/CVE-2022-24124_POC.svg)


## CVE-2022-22965
 A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the application to run on Tomcat as a WAR deployment. If the application is deployed as a Spring Boot executable jar, i.e. the default, it is not vulnerable to the exploit. However, the nature of the vulnerability is more general, and there may be other ways to exploit it.

- [https://github.com/khulnasoft-lab/awesome-security](https://github.com/khulnasoft-lab/awesome-security) :  ![starts](https://img.shields.io/github/stars/khulnasoft-lab/awesome-security.svg) ![forks](https://img.shields.io/github/forks/khulnasoft-lab/awesome-security.svg)


## CVE-2022-22963
 In Spring Cloud Function versions 3.1.6, 3.2.2 and older unsupported versions, when using routing functionality it is possible for a user to provide a specially crafted SpEL as a routing-expression that may result in remote code execution and access to local resources.

- [https://github.com/khulnasoft-lab/awesome-security](https://github.com/khulnasoft-lab/awesome-security) :  ![starts](https://img.shields.io/github/stars/khulnasoft-lab/awesome-security.svg) ![forks](https://img.shields.io/github/forks/khulnasoft-lab/awesome-security.svg)


## CVE-2022-0165
 The Page Builder KingComposer WordPress plugin through 2.9.6 does not validate the id parameter before redirecting the user to it via the kc_get_thumbn AJAX action available to both unauthenticated and authenticated users

- [https://github.com/K3ysTr0K3R/CVE-2022-0165-EXPLOIT](https://github.com/K3ysTr0K3R/CVE-2022-0165-EXPLOIT) :  ![starts](https://img.shields.io/github/stars/K3ysTr0K3R/CVE-2022-0165-EXPLOIT.svg) ![forks](https://img.shields.io/github/forks/K3ysTr0K3R/CVE-2022-0165-EXPLOIT.svg)


## CVE-2021-45105
 Apache Log4j2 versions 2.0-alpha1 through 2.16.0 (excluding 2.12.3 and 2.3.1) did not protect from uncontrolled recursion from self-referential lookups. This allows an attacker with control over Thread Context Map data to cause a denial of service when a crafted string is interpreted. This issue was fixed in Log4j 2.17.0, 2.12.3, and 2.3.1.

- [https://github.com/khulnasoft-lab/awesome-security](https://github.com/khulnasoft-lab/awesome-security) :  ![starts](https://img.shields.io/github/stars/khulnasoft-lab/awesome-security.svg) ![forks](https://img.shields.io/github/forks/khulnasoft-lab/awesome-security.svg)


## CVE-2021-45046
 It was found that the fix to address CVE-2021-44228 in Apache Log4j 2.15.0 was incomplete in certain non-default configurations. This could allows attackers with control over Thread Context Map (MDC) input data when the logging configuration uses a non-default Pattern Layout with either a Context Lookup (for example, $${ctx:loginId}) or a Thread Context Map pattern (%X, %mdc, or %MDC) to craft malicious input data using a JNDI Lookup pattern resulting in an information leak and remote code execution in some environments and local code execution in all environments. Log4j 2.16.0 (Java 8) and 2.12.2 (Java 7) fix this issue by removing support for message lookup patterns and disabling JNDI functionality by default.

- [https://github.com/khulnasoft-lab/awesome-security](https://github.com/khulnasoft-lab/awesome-security) :  ![starts](https://img.shields.io/github/stars/khulnasoft-lab/awesome-security.svg) ![forks](https://img.shields.io/github/forks/khulnasoft-lab/awesome-security.svg)


## CVE-2021-44593
 Simple College Website 1.0 is vulnerable to unauthenticated file upload &amp; remote code execution via UNION-based SQL injection in the username parameter on /admin/login.php.

- [https://github.com/khulnasoft-lab/awesome-security](https://github.com/khulnasoft-lab/awesome-security) :  ![starts](https://img.shields.io/github/stars/khulnasoft-lab/awesome-security.svg) ![forks](https://img.shields.io/github/forks/khulnasoft-lab/awesome-security.svg)


## CVE-2021-34621
 A vulnerability in the user registration component found in the ~/src/Classes/RegistrationAuth.php file of the ProfilePress WordPress plugin made it possible for users to register on sites as an administrator. This issue affects versions 3.0.0 - 3.1.3. .

- [https://github.com/RandomRobbieBF/CVE-2021-34621](https://github.com/RandomRobbieBF/CVE-2021-34621) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2021-34621.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2021-34621.svg)


## CVE-2021-34527
 Windows Print Spooler Remote Code Execution Vulnerability

- [https://github.com/khulnasoft-lab/awesome-security](https://github.com/khulnasoft-lab/awesome-security) :  ![starts](https://img.shields.io/github/stars/khulnasoft-lab/awesome-security.svg) ![forks](https://img.shields.io/github/forks/khulnasoft-lab/awesome-security.svg)


## CVE-2021-25032
 The PublishPress Capabilities WordPress plugin before 2.3.1, PublishPress Capabilities Pro WordPress plugin before 2.3.1 does not have authorisation and CSRF checks when updating the plugin's settings via the init hook, and does not ensure that the options to be updated belong to the plugin. As a result, unauthenticated attackers could update arbitrary blog options, such as the default role and make any new registered user with an administrator role.

- [https://github.com/RandomRobbieBF/CVE-2021-25032](https://github.com/RandomRobbieBF/CVE-2021-25032) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2021-25032.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2021-25032.svg)


## CVE-2021-24356
 In the Simple 301 Redirects by BetterLinks WordPress plugin before 2.0.4, a lack of capability checks and insufficient nonce check on the AJAX action, simple301redirects/admin/activate_plugin, made it possible for authenticated users to activate arbitrary plugins installed on vulnerable sites.

- [https://github.com/RandomRobbieBF/CVE-2021-24356](https://github.com/RandomRobbieBF/CVE-2021-24356) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2021-24356.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2021-24356.svg)


## CVE-2021-4036
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/khulnasoft-lab/awesome-security](https://github.com/khulnasoft-lab/awesome-security) :  ![starts](https://img.shields.io/github/stars/khulnasoft-lab/awesome-security.svg) ![forks](https://img.shields.io/github/forks/khulnasoft-lab/awesome-security.svg)


## CVE-2021-3560
 It was found that polkit could be tricked into bypassing the credential checks for D-Bus requests, elevating the privileges of the requestor to the root user. This flaw could be used by an unprivileged local attacker to, for example, create a new local administrator. The highest threat from this vulnerability is to data confidentiality and integrity as well as system availability.

- [https://github.com/khulnasoft-lab/awesome-security](https://github.com/khulnasoft-lab/awesome-security) :  ![starts](https://img.shields.io/github/stars/khulnasoft-lab/awesome-security.svg) ![forks](https://img.shields.io/github/forks/khulnasoft-lab/awesome-security.svg)


## CVE-2020-0796
 A remote code execution vulnerability exists in the way that the Microsoft Server Message Block 3.1.1 (SMBv3) protocol handles certain requests, aka 'Windows SMBv3 Client/Server Remote Code Execution Vulnerability'.

- [https://github.com/khulnasoft-lab/awesome-security](https://github.com/khulnasoft-lab/awesome-security) :  ![starts](https://img.shields.io/github/stars/khulnasoft-lab/awesome-security.svg) ![forks](https://img.shields.io/github/forks/khulnasoft-lab/awesome-security.svg)


## CVE-2020-0787
 An elevation of privilege vulnerability exists when the Windows Background Intelligent Transfer Service (BITS) improperly handles symbolic links, aka 'Windows Background Intelligent Transfer Service Elevation of Privilege Vulnerability'.

- [https://github.com/khulnasoft-lab/awesome-security](https://github.com/khulnasoft-lab/awesome-security) :  ![starts](https://img.shields.io/github/stars/khulnasoft-lab/awesome-security.svg) ![forks](https://img.shields.io/github/forks/khulnasoft-lab/awesome-security.svg)

