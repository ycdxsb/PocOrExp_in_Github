# Update 2023-01-21
## CVE-2023-23690
 Cloud Mobility for Dell EMC Storage, versions 1.3.0.X and below contains an Improper Check for Certificate Revocation vulnerability. A threat actor does not need any specific privileges to potentially exploit this vulnerability. An attacker could perform a man-in-the-middle attack and eavesdrop on encrypted communications from Cloud Mobility to Cloud Storage devices. Exploitation could lead to the compromise of secret and sensitive information, cloud storage connection downtime, and the integrity of the connection to the Cloud devices.

- [https://github.com/Live-Hack-CVE/CVE-2023-23690](https://github.com/Live-Hack-CVE/CVE-2023-23690) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23690.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23690.svg)


## CVE-2023-22745
 tpm2-tss is an open source software implementation of the Trusted Computing Group (TCG) Trusted Platform Module (TPM) 2 Software Stack (TSS2). In affected versions `Tss2_RC_SetHandler` and `Tss2_RC_Decode` both index into `layer_handler` with an 8 bit layer number, but the array only has `TPM2_ERROR_TSS2_RC_LAYER_COUNT` entries, so trying to add a handler for higher-numbered layers or decode a response code with such a layer number reads/writes past the end of the buffer. This Buffer overrun, could result in arbitrary code execution. An example attack would be a MiTM bus attack that returns 0xFFFFFFFF for the RC. Given the common use case of TPM modules an attacker must have local access to the target machine with local system privileges which allows access to the TPM system. Usually TPM access requires administrative privilege.

- [https://github.com/Live-Hack-CVE/CVE-2023-22745](https://github.com/Live-Hack-CVE/CVE-2023-22745) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22745.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22745.svg)


## CVE-2023-22741
 Sofia-SIP is an open-source SIP User-Agent library, compliant with the IETF RFC3261 specification. In affected versions Sofia-SIP **lacks both message length and attributes length checks** when it handles STUN packets, leading to controllable heap-over-flow. For example, in stun_parse_attribute(), after we get the attribute's type and length value, the length will be used directly to copy from the heap, regardless of the message's left size. Since network users control the overflowed length, and the data is written to heap chunks later, attackers may achieve remote code execution by heap grooming or other exploitation methods. The bug was introduced 16 years ago in sofia-sip 1.12.4 (plus some patches through 12/21/2006) to in tree libs with git-svn-id: http://svn.freeswitch.org/svn/freeswitch/trunk@3774 d0543943-73ff-0310-b7d9-9358b9ac24b2. Users are advised to upgrade. There are no known workarounds for this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2023-22741](https://github.com/Live-Hack-CVE/CVE-2023-22741) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22741.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22741.svg)


## CVE-2023-20522
 Insufficient input validation in ASP may allow an attacker with a malicious BIOS to potentially cause a denial of service.

- [https://github.com/Live-Hack-CVE/CVE-2023-20522](https://github.com/Live-Hack-CVE/CVE-2023-20522) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-20522.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-20522.svg)


## CVE-2023-0406
 Cross-Site Request Forgery (CSRF) in GitHub repository modoboa/modoboa prior to 2.0.4.

- [https://github.com/Live-Hack-CVE/CVE-2023-0406](https://github.com/Live-Hack-CVE/CVE-2023-0406) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0406.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0406.svg)


## CVE-2023-0404
 The Events Made Easy plugin for WordPress is vulnerable to authorization bypass due to a missing capability check on several functions related to AJAX actions in versions up to, and including, 2.3.16. This makes it possible for authenticated attackers, with subscriber-level permissions and above, to invoke those functions intended for administrator use. While the plugin is still pending review from the WordPress repository, site owners can download a copy of the patched version directly from the developer's Github at https://github.com/liedekef/events-made-easy

- [https://github.com/Live-Hack-CVE/CVE-2023-0404](https://github.com/Live-Hack-CVE/CVE-2023-0404) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0404.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0404.svg)


## CVE-2023-0403
 The Social Warfare plugin for WordPress is vulnerable to Cross-Site Request Forgery in versions up to, and including, 4.4.0. This is due to missing or incorrect nonce validation on several AJAX actions. This makes it possible for unauthenticated attackers to delete post meta information and reset network access tokens, via forged request granted they can trick a site administrator into performing an action such as clicking on a link.

- [https://github.com/Live-Hack-CVE/CVE-2023-0403](https://github.com/Live-Hack-CVE/CVE-2023-0403) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0403.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0403.svg)


## CVE-2023-0402
 The Social Warfare plugin for WordPress is vulnerable to authorization bypass due to a missing capability check on several AJAX actions in versions up to, and including, 4.3.0. This makes it possible for authenticated attackers, with subscriber-level permissions and above, to delete post meta information and reset network access tokens.

- [https://github.com/Live-Hack-CVE/CVE-2023-0402](https://github.com/Live-Hack-CVE/CVE-2023-0402) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0402.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0402.svg)


## CVE-2023-0398
 Cross-Site Request Forgery (CSRF) in GitHub repository modoboa/modoboa prior to 2.0.4.

- [https://github.com/Live-Hack-CVE/CVE-2023-0398](https://github.com/Live-Hack-CVE/CVE-2023-0398) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0398.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0398.svg)


## CVE-2023-0397
 A malicious / defect bluetooth controller can cause a Denial of Service due to unchecked input in le_read_buffer_size_complete.

- [https://github.com/Live-Hack-CVE/CVE-2023-0397](https://github.com/Live-Hack-CVE/CVE-2023-0397) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0397.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0397.svg)


## CVE-2023-0126
 Pre-authentication path traversal vulnerability in SMA1000 firmware version 12.4.2, which allows an unauthenticated attacker to access arbitrary files and directories stored outside the web root directory.

- [https://github.com/Live-Hack-CVE/CVE-2023-0126](https://github.com/Live-Hack-CVE/CVE-2023-0126) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0126.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0126.svg)


## CVE-2022-47966
 Multiple Zoho ManageEngine on-premise products, such as ServiceDesk Plus through 14003, allow remote code execution due to use of Apache xmlsec (aka XML Security for Java) 1.4.1, because the xmlsec XSLT features, by design in that version, make the application responsible for certain security protections, and the ManageEngine applications did not provide those protections.

- [https://github.com/horizon3ai/CVE-2022-47966](https://github.com/horizon3ai/CVE-2022-47966) :  ![starts](https://img.shields.io/github/stars/horizon3ai/CVE-2022-47966.svg) ![forks](https://img.shields.io/github/forks/horizon3ai/CVE-2022-47966.svg)
- [https://github.com/shameem-testing/PoC-for-ME-SAML-Vulnerability](https://github.com/shameem-testing/PoC-for-ME-SAML-Vulnerability) :  ![starts](https://img.shields.io/github/stars/shameem-testing/PoC-for-ME-SAML-Vulnerability.svg) ![forks](https://img.shields.io/github/forks/shameem-testing/PoC-for-ME-SAML-Vulnerability.svg)
- [https://github.com/p33d/CVE-2022-47966](https://github.com/p33d/CVE-2022-47966) :  ![starts](https://img.shields.io/github/stars/p33d/CVE-2022-47966.svg) ![forks](https://img.shields.io/github/forks/p33d/CVE-2022-47966.svg)


## CVE-2022-47766
 PopojiCMS v2.0.1 backend plugin function has a file upload vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2022-47766](https://github.com/Live-Hack-CVE/CVE-2022-47766) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-47766.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-47766.svg)


## CVE-2022-47745
 ZenTao 16.4 to 18.0.beta1 is vulnerable to SQL injection. After logging in with any user, you can complete SQL injection by constructing a special request and sending it to function importNotice.

- [https://github.com/Live-Hack-CVE/CVE-2022-47745](https://github.com/Live-Hack-CVE/CVE-2022-47745) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-47745.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-47745.svg)


## CVE-2022-47740
 Seltmann GmbH Content Management System 6 is vulnerable to SQL Injection via /index.php.

- [https://github.com/Live-Hack-CVE/CVE-2022-47740](https://github.com/Live-Hack-CVE/CVE-2022-47740) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-47740.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-47740.svg)


## CVE-2022-47197
 An insecure default vulnerability exists in the Post Creation functionality of Ghost Foundation Ghost 5.9.4. Default installations of Ghost allow non-administrator users to inject arbitrary Javascript in posts, which allow privilege escalation to administrator via XSS. To trigger this vulnerability, an attacker can send an HTTP request to inject Javascript in a post to trick an administrator into visiting the post.A stored XSS vulnerability exists in the `codeinjection_foot` for a post.

- [https://github.com/Live-Hack-CVE/CVE-2022-47197](https://github.com/Live-Hack-CVE/CVE-2022-47197) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-47197.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-47197.svg)


## CVE-2022-47196
 An insecure default vulnerability exists in the Post Creation functionality of Ghost Foundation Ghost 5.9.4. Default installations of Ghost allow non-administrator users to inject arbitrary Javascript in posts, which allow privilege escalation to administrator via XSS. To trigger this vulnerability, an attacker can send an HTTP request to inject Javascript in a post to trick an administrator into visiting the post.A stored XSS vulnerability exists in the `codeinjection_head` for a post.

- [https://github.com/Live-Hack-CVE/CVE-2022-47196](https://github.com/Live-Hack-CVE/CVE-2022-47196) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-47196.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-47196.svg)


## CVE-2022-47195
 An insecure default vulnerability exists in the Post Creation functionality of Ghost Foundation Ghost 5.9.4. Default installations of Ghost allow non-administrator users to inject arbitrary Javascript in posts, which allow privilege escalation to administrator via XSS. To trigger this vulnerability, an attacker can send an HTTP request to inject Javascript in a post to trick an administrator into visiting the post.A stored XSS vulnerability exists in the `facebook` field for a user.

- [https://github.com/Live-Hack-CVE/CVE-2022-47195](https://github.com/Live-Hack-CVE/CVE-2022-47195) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-47195.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-47195.svg)


## CVE-2022-47194
 An insecure default vulnerability exists in the Post Creation functionality of Ghost Foundation Ghost 5.9.4. Default installations of Ghost allow non-administrator users to inject arbitrary Javascript in posts, which allow privilege escalation to administrator via XSS. To trigger this vulnerability, an attacker can send an HTTP request to inject Javascript in a post to trick an administrator into visiting the post.A stored XSS vulnerability exists in the `twitter` field for a user.

- [https://github.com/Live-Hack-CVE/CVE-2022-47194](https://github.com/Live-Hack-CVE/CVE-2022-47194) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-47194.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-47194.svg)


## CVE-2022-47105
 Jeecg-boot v3.4.4 was discovered to contain a SQL injection vulnerability via the component /sys/dict/queryTableData.

- [https://github.com/Live-Hack-CVE/CVE-2022-47105](https://github.com/Live-Hack-CVE/CVE-2022-47105) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-47105.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-47105.svg)


## CVE-2022-46890
 Weak access control in NexusPHP before 1.7.33 allows a remote authenticated user to edit any post in the forum (this is caused by a lack of checks performed by the /forums.php?action=post page).

- [https://github.com/Live-Hack-CVE/CVE-2022-46890](https://github.com/Live-Hack-CVE/CVE-2022-46890) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-46890.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-46890.svg)


## CVE-2022-46889
 A persistent cross-site scripting (XSS) vulnerability in NexusPHP before 1.7.33 allows remote authenticated attackers to permanently inject arbitrary web script or HTML via the title parameter used in /subtitles.php.

- [https://github.com/Live-Hack-CVE/CVE-2022-46889](https://github.com/Live-Hack-CVE/CVE-2022-46889) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-46889.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-46889.svg)


## CVE-2022-46888
 Multiple reflective cross-site scripting (XSS) vulnerabilities in NexusPHP before 1.7.33 allow remote attackers to inject arbitrary web script or HTML via the secret parameter in /login.php; q parameter in /user-ban-log.php; query parameter in /log.php; text parameter in /moresmiles.php; q parameter in myhr.php; or id parameter in /viewrequests.php.

- [https://github.com/Live-Hack-CVE/CVE-2022-46888](https://github.com/Live-Hack-CVE/CVE-2022-46888) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-46888.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-46888.svg)


## CVE-2022-46887
 Multiple SQL injection vulnerabilities in NexusPHP before 1.7.33 allow remote attackers to execute arbitrary SQL commands via the conuser[] parameter in takeconfirm.php; the delcheater parameter in cheaterbox.php; or the usernw parameter in nowarn.php.

- [https://github.com/Live-Hack-CVE/CVE-2022-46887](https://github.com/Live-Hack-CVE/CVE-2022-46887) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-46887.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-46887.svg)


## CVE-2022-46476
 D-Link DIR-859 A1 1.05 was discovered to contain a command injection vulnerability via the service= variable in the soapcgi_main function.

- [https://github.com/Live-Hack-CVE/CVE-2022-46476](https://github.com/Live-Hack-CVE/CVE-2022-46476) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-46476.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-46476.svg)


## CVE-2022-45934
 An issue was discovered in the Linux kernel through 6.0.10. l2cap_config_req in net/bluetooth/l2cap_core.c has an integer wraparound via L2CAP_CONF_REQ packets.

- [https://github.com/nidhi7598/linux-3.0.35_CVE-2022-45934](https://github.com/nidhi7598/linux-3.0.35_CVE-2022-45934) :  ![starts](https://img.shields.io/github/stars/nidhi7598/linux-3.0.35_CVE-2022-45934.svg) ![forks](https://img.shields.io/github/forks/nidhi7598/linux-3.0.35_CVE-2022-45934.svg)
- [https://github.com/Trinadh465/linux-4.19.72_CVE-2022-45934](https://github.com/Trinadh465/linux-4.19.72_CVE-2022-45934) :  ![starts](https://img.shields.io/github/stars/Trinadh465/linux-4.19.72_CVE-2022-45934.svg) ![forks](https://img.shields.io/github/forks/Trinadh465/linux-4.19.72_CVE-2022-45934.svg)


## CVE-2022-40697
 Auth. (admin+) Stored Cross-Site Scripting (XSS) vulnerability in 3com &#8211; Asesor de Cookies para normativa espaola plugin &lt;= 3.4.3 versions.

- [https://github.com/Live-Hack-CVE/CVE-2022-40697](https://github.com/Live-Hack-CVE/CVE-2022-40697) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-40697.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-40697.svg)


## CVE-2022-39167
 IBM Spectrum Virtualize 8.5, 8.4, 8.3, 8.2, and 7.8, under certain configurations, could disclose sensitive information to an attacker using man-in-the-middle techniques. IBM X-Force ID: 235408.

- [https://github.com/Live-Hack-CVE/CVE-2022-39167](https://github.com/Live-Hack-CVE/CVE-2022-39167) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-39167.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-39167.svg)


## CVE-2022-36588
 In D-Link DAP1650 v1.04 firmware, the fileaccess.cgi program in the firmware has a buffer overflow vulnerability caused by strncpy.

- [https://github.com/Live-Hack-CVE/CVE-2022-36588](https://github.com/Live-Hack-CVE/CVE-2022-36588) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36588.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36588.svg)


## CVE-2022-31901
 Buffer overflow in function Notepad_plus::addHotSpot in Notepad++ v8.4.3 and earlier allows attackers to crash the application via two crafted files.

- [https://github.com/Live-Hack-CVE/CVE-2022-31901](https://github.com/Live-Hack-CVE/CVE-2022-31901) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-31901.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-31901.svg)


## CVE-2022-27778
 A use of incorrectly resolved name vulnerability fixed in 7.83.1 might remove the wrong file when `--no-clobber` is used together with `--remove-on-error`.

- [https://github.com/Live-Hack-CVE/CVE-2022-27778](https://github.com/Live-Hack-CVE/CVE-2022-27778) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-27778.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-27778.svg)


## CVE-2022-27223
 In drivers/usb/gadget/udc/udc-xilinx.c in the Linux kernel before 5.16.12, the endpoint index is not validated and might be manipulated by the host for out-of-array access.

- [https://github.com/Live-Hack-CVE/CVE-2022-27223](https://github.com/Live-Hack-CVE/CVE-2022-27223) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-27223.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-27223.svg)


## CVE-2022-23521
 Git is distributed revision control system. gitattributes are a mechanism to allow defining attributes for paths. These attributes can be defined by adding a `.gitattributes` file to the repository, which contains a set of file patterns and the attributes that should be set for paths matching this pattern. When parsing gitattributes, multiple integer overflows can occur when there is a huge number of path patterns, a huge number of attributes for a single pattern, or when the declared attribute names are huge. These overflows can be triggered via a crafted `.gitattributes` file that may be part of the commit history. Git silently splits lines longer than 2KB when parsing gitattributes from a file, but not when parsing them from the index. Consequentially, the failure mode depends on whether the file exists in the working tree, the index or both. This integer overflow can result in arbitrary heap reads and writes, which may result in remote code execution. The problem has been patched in the versions published on 2023-01-17, going back to v2.30.7. Users are advised to upgrade. There are no known workarounds for this issue.

- [https://github.com/0xDSousa/CVE-2022-23521](https://github.com/0xDSousa/CVE-2022-23521) :  ![starts](https://img.shields.io/github/stars/0xDSousa/CVE-2022-23521.svg) ![forks](https://img.shields.io/github/forks/0xDSousa/CVE-2022-23521.svg)


## CVE-2022-21661
 WordPress is a free and open-source content management system written in PHP and paired with a MariaDB database. Due to improper sanitization in WP_Query, there can be cases where SQL injection is possible through plugins or themes that use it in a certain way. This has been patched in WordPress version 5.8.3. Older affected versions are also fixed via security release, that go back till 3.7.37. We strongly recommend that you keep auto-updates enabled. There are no known workarounds for this vulnerability.

- [https://github.com/WellingtonEspindula/SSI-CVE-2022-21661](https://github.com/WellingtonEspindula/SSI-CVE-2022-21661) :  ![starts](https://img.shields.io/github/stars/WellingtonEspindula/SSI-CVE-2022-21661.svg) ![forks](https://img.shields.io/github/forks/WellingtonEspindula/SSI-CVE-2022-21661.svg)


## CVE-2022-4892
 A vulnerability was found in MyCMS. It has been classified as problematic. This affects the function build_view of the file lib/gener/view.php of the component Visitors Module. The manipulation of the argument original/converted leads to cross site scripting. It is possible to initiate the attack remotely. The name of the patch is d64fcba4882a50e21cdbec3eb4a080cb694d26ee. It is recommended to apply a patch to fix this issue. The associated identifier of this vulnerability is VDB-218895.

- [https://github.com/Live-Hack-CVE/CVE-2022-4892](https://github.com/Live-Hack-CVE/CVE-2022-4892) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4892.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4892.svg)


## CVE-2022-4874
 Authentication bypass in Netcomm router models NF20MESH, NF20, and NL1902 allows an unauthenticated user to access content. In order to serve static content, the application performs a check for the existence of specific characters in the URL (.css, .png etc). If it exists, it performs a &quot;fake login&quot; to give the request an active session to load the file and not redirect to the login page.

- [https://github.com/Live-Hack-CVE/CVE-2022-4874](https://github.com/Live-Hack-CVE/CVE-2022-4874) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4874.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4874.svg)


## CVE-2022-4873
 On Netcomm router models NF20MESH, NF20, and NL1902 a stack based buffer overflow affects the sessionKey parameter. By providing a specific number of bytes, the instruction pointer is able to be overwritten on the stack and crashes the application at a known location.

- [https://github.com/Live-Hack-CVE/CVE-2022-4873](https://github.com/Live-Hack-CVE/CVE-2022-4873) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4873.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4873.svg)


## CVE-2022-4543
 A flaw named &quot;EntryBleed&quot; was found in the Linux Kernel Page Table Isolation (KPTI). This issue could allow a local attacker to leak KASLR base via prefetch side-channels based on TLB timing for Intel systems.

- [https://github.com/Live-Hack-CVE/CVE-2022-4543](https://github.com/Live-Hack-CVE/CVE-2022-4543) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4543.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4543.svg)


## CVE-2022-4415
 A vulnerability was found in systemd. This security flaw can cause a local information leak due to systemd-coredump not respecting the fs.suid_dumpable kernel setting.

- [https://github.com/Live-Hack-CVE/CVE-2022-4415](https://github.com/Live-Hack-CVE/CVE-2022-4415) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4415.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4415.svg)


## CVE-2022-3915
 The Dokan WordPress plugin before 3.7.6 does not properly sanitise and escape a parameter before using it in a SQL statement, leading to a SQL injection exploitable by unauthenticated users

- [https://github.com/Live-Hack-CVE/CVE-2022-3915](https://github.com/Live-Hack-CVE/CVE-2022-3915) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-3915.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-3915.svg)


## CVE-2022-3738
 The vulnerability allows a remote unauthenticated attacker to download a backup file, if one exists. That backup file might contain sensitive information like credentials and cryptographic material. A valid user has to create a backup after the last reboot for this attack to be successfull.

- [https://github.com/Live-Hack-CVE/CVE-2022-3738](https://github.com/Live-Hack-CVE/CVE-2022-3738) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-3738.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-3738.svg)


## CVE-2022-2602
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/kiks7/CVE-2022-2602-Kernel-Exploit](https://github.com/kiks7/CVE-2022-2602-Kernel-Exploit) :  ![starts](https://img.shields.io/github/stars/kiks7/CVE-2022-2602-Kernel-Exploit.svg) ![forks](https://img.shields.io/github/forks/kiks7/CVE-2022-2602-Kernel-Exploit.svg)


## CVE-2022-2361
 The WP Social Chat WordPress plugin before 6.0.5 does not sanitise and escape some of its settings, which could allow high privilege users such as admin to perform Stored Cross-Site Scripting attacks.

- [https://github.com/Live-Hack-CVE/CVE-2022-2361](https://github.com/Live-Hack-CVE/CVE-2022-2361) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2361.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2361.svg)


## CVE-2022-1676
 ** REJECT ** DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: none. Reason: This candidate was withdrawn by its CNA. Further investigation showed that it was not a security issue. Notes: none.

- [https://github.com/Live-Hack-CVE/CVE-2022-1676](https://github.com/Live-Hack-CVE/CVE-2022-1676) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-1676.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-1676.svg)


## CVE-2022-0863
 The WP SVG Icons WordPress plugin through 3.2.3 does not properly validate uploaded custom icon packs, allowing an high privileged user like an admin to upload a zip file containing malicious php code, leading to remote code execution.

- [https://github.com/Live-Hack-CVE/CVE-2022-0863](https://github.com/Live-Hack-CVE/CVE-2022-0863) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-0863.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-0863.svg)


## CVE-2022-0544
 An integer underflow in the DDS loader of Blender leads to an out-of-bounds read, possibly allowing an attacker to read sensitive data using a crafted DDS image file. This flaw affects Blender versions prior to 2.83.19, 2.93.8 and 3.1.

- [https://github.com/Live-Hack-CVE/CVE-2022-0544](https://github.com/Live-Hack-CVE/CVE-2022-0544) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-0544.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-0544.svg)


## CVE-2021-37774
 An issue was discovered in function httpProcDataSrv in TL-WDR7660 2.0.30 that allows attackers to execute arbitrary code.

- [https://github.com/Live-Hack-CVE/CVE-2021-37774](https://github.com/Live-Hack-CVE/CVE-2021-37774) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-37774.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-37774.svg)


## CVE-2021-31800
 Multiple path traversal vulnerabilities exist in smbserver.py in Impacket through 0.9.22. An attacker that connects to a running smbserver instance can list and write to arbitrary files via ../ directory traversal. This could potentially be abused to achieve arbitrary code execution by replacing /etc/shadow or an SSH authorized key.

- [https://github.com/p0dalirius/CVE-2021-31800-Impacket-SMB-Server-Arbitrary-file-read-write](https://github.com/p0dalirius/CVE-2021-31800-Impacket-SMB-Server-Arbitrary-file-read-write) :  ![starts](https://img.shields.io/github/stars/p0dalirius/CVE-2021-31800-Impacket-SMB-Server-Arbitrary-file-read-write.svg) ![forks](https://img.shields.io/github/forks/p0dalirius/CVE-2021-31800-Impacket-SMB-Server-Arbitrary-file-read-write.svg)


## CVE-2020-36649
 A vulnerability was found in mholt PapaParse up to 5.1.x. It has been classified as problematic. Affected is an unknown function of the file papaparse.js. The manipulation leads to inefficient regular expression complexity. Upgrading to version 5.2.0 is able to address this issue. The name of the patch is 235a12758cd77266d2e98fd715f53536b34ad621. It is recommended to upgrade the affected component. The identifier of this vulnerability is VDB-218004.

- [https://github.com/Live-Hack-CVE/CVE-2020-36649](https://github.com/Live-Hack-CVE/CVE-2020-36649) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-36649.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-36649.svg)


## CVE-2020-25714
 ** REJECT ** DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: none. Reason: The CNA or individual who requested this candidate did not associate it with any vulnerability during 2020. Notes: none.

- [https://github.com/Live-Hack-CVE/CVE-2020-25714](https://github.com/Live-Hack-CVE/CVE-2020-25714) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-25714.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-25714.svg)


## CVE-2020-25679
 ** REJECT ** DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: none. Reason: The CNA or individual who requested this candidate did not associate it with any vulnerability during 2020. Notes: none.

- [https://github.com/Live-Hack-CVE/CVE-2020-25679](https://github.com/Live-Hack-CVE/CVE-2020-25679) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-25679.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-25679.svg)


## CVE-2020-10765
 ** REJECT ** DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: none. Reason: The CNA or individual who requested this candidate did not associate it with any vulnerability during 2020. Notes: none.

- [https://github.com/Live-Hack-CVE/CVE-2020-10765](https://github.com/Live-Hack-CVE/CVE-2020-10765) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-10765.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-10765.svg)


## CVE-2020-10764
 ** REJECT ** DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: none. Reason: The CNA or individual who requested this candidate did not associate it with any vulnerability during 2020. Notes: none.

- [https://github.com/Live-Hack-CVE/CVE-2020-10764](https://github.com/Live-Hack-CVE/CVE-2020-10764) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-10764.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-10764.svg)


## CVE-2020-10694
 ** REJECT ** DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: none. Reason: The CNA or individual who requested this candidate did not associate it with any vulnerability during 2020. Notes: none.

- [https://github.com/Live-Hack-CVE/CVE-2020-10694](https://github.com/Live-Hack-CVE/CVE-2020-10694) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-10694.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-10694.svg)


## CVE-2020-10692
 ** REJECT ** DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: none. Reason: The CNA or individual who requested this candidate did not associate it with any vulnerability during 2020. Notes: none.

- [https://github.com/Live-Hack-CVE/CVE-2020-10692](https://github.com/Live-Hack-CVE/CVE-2020-10692) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-10692.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-10692.svg)


## CVE-2020-3153
 A vulnerability in the installer component of Cisco AnyConnect Secure Mobility Client for Windows could allow an authenticated local attacker to copy user-supplied files to system level directories with system level privileges. The vulnerability is due to the incorrect handling of directory paths. An attacker could exploit this vulnerability by creating a malicious file and copying the file to a system directory. An exploit could allow the attacker to copy malicious files to arbitrary locations with system level privileges. This could include DLL pre-loading, DLL hijacking, and other related attacks. To exploit this vulnerability, the attacker needs valid credentials on the Windows system.

- [https://github.com/shubham0d/CVE-2020-3153](https://github.com/shubham0d/CVE-2020-3153) :  ![starts](https://img.shields.io/github/stars/shubham0d/CVE-2020-3153.svg) ![forks](https://img.shields.io/github/forks/shubham0d/CVE-2020-3153.svg)


## CVE-2020-1715
 ** REJECT ** DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: none. Reason: The CNA or individual who requested this candidate did not associate it with any vulnerability during 2020. Notes: none.

- [https://github.com/Live-Hack-CVE/CVE-2020-1715](https://github.com/Live-Hack-CVE/CVE-2020-1715) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-1715.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-1715.svg)


## CVE-2020-1713
 ** REJECT ** DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: none. Reason: The CNA or individual who requested this candidate did not associate it with any vulnerability during 2020. Notes: none.

- [https://github.com/Live-Hack-CVE/CVE-2020-1713](https://github.com/Live-Hack-CVE/CVE-2020-1713) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-1713.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-1713.svg)


## CVE-2019-15504
 drivers/net/wireless/rsi/rsi_91x_usb.c in the Linux kernel through 5.2.9 has a Double Free via crafted USB device traffic (which may be remote via usbip or usbredir).

- [https://github.com/Live-Hack-CVE/CVE-2019-15504](https://github.com/Live-Hack-CVE/CVE-2019-15504) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-15504.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-15504.svg)


## CVE-2019-15107
 An issue was discovered in Webmin &lt;=1.920. The parameter old in password_change.cgi contains a command injection vulnerability.

- [https://github.com/d3b0o/WebMin-1.890-exploit](https://github.com/d3b0o/WebMin-1.890-exploit) :  ![starts](https://img.shields.io/github/stars/d3b0o/WebMin-1.890-exploit.svg) ![forks](https://img.shields.io/github/forks/d3b0o/WebMin-1.890-exploit.svg)


## CVE-2018-20961
 In the Linux kernel before 4.16.4, a double free vulnerability in the f_midi_set_alt function of drivers/usb/gadget/function/f_midi.c in the f_midi driver may allow attackers to cause a denial of service or possibly have unspecified other impact.

- [https://github.com/Live-Hack-CVE/CVE-2018-20961](https://github.com/Live-Hack-CVE/CVE-2018-20961) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2018-20961.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2018-20961.svg)


## CVE-2018-11093
 Cross-site scripting (XSS) vulnerability in the Link package for CKEditor 5 before 10.0.1 allows remote attackers to inject arbitrary web script through a crafted href attribute of a link (A) element.

- [https://github.com/ossf-cve-benchmark/CVE-2018-11093](https://github.com/ossf-cve-benchmark/CVE-2018-11093) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2018-11093.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2018-11093.svg)


## CVE-2017-16335
 Multiple exploitable buffer overflow vulnerabilities exist in the PubNub message handler for the &quot;cc&quot; channel of Insteon Hub running firmware version 1012. Specially crafted commands sent through the PubNub service can cause a stack-based buffer overflow overwriting arbitrary data. An attacker should send an authenticated HTTP request to trigger this vulnerability. In cmd s_event_var, at 0x9d01ee70, the value for the `s_offset` key is copied using `strcpy` to the buffer at `$sp+0x2b0`.This buffer is 32 bytes large, sending anything longer will cause a buffer overflow.

- [https://github.com/Live-Hack-CVE/CVE-2017-16335](https://github.com/Live-Hack-CVE/CVE-2017-16335) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2017-16335.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2017-16335.svg)


## CVE-2017-16334
 Multiple exploitable buffer overflow vulnerabilities exist in the PubNub message handler for the &quot;cc&quot; channel of Insteon Hub running firmware version 1012. Specially crafted commands sent through the PubNub service can cause a stack-based buffer overflow overwriting arbitrary data. An attacker should send an authenticated HTTP request to trigger this vulnerability. In cmd s_event, at 0x9d01edb8, the value for the `s_raw` key is copied using `strcpy` to the buffer at `$sp+0x10`.This buffer is 244 bytes large, sending anything longer will cause a buffer overflow.

- [https://github.com/Live-Hack-CVE/CVE-2017-16334](https://github.com/Live-Hack-CVE/CVE-2017-16334) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2017-16334.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2017-16334.svg)


## CVE-2017-16332
 Multiple exploitable buffer overflow vulnerabilities exist in the PubNub message handler for the &quot;cc&quot; channel of Insteon Hub running firmware version 1012. Specially crafted commands sent through the PubNub service can cause a stack-based buffer overflow overwriting arbitrary data. An attacker should send an authenticated HTTP request to trigger this vulnerability. In cmd s_event_alarm, at 0x9d01ec34, the value for the `s_aid` key is copied using `strcpy` to the buffer at `$sp+0x2b0`.This buffer is 32 bytes large, sending anything longer will cause a buffer overflow.

- [https://github.com/Live-Hack-CVE/CVE-2017-16332](https://github.com/Live-Hack-CVE/CVE-2017-16332) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2017-16332.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2017-16332.svg)


## CVE-2017-16331
 Multiple exploitable buffer overflow vulnerabilities exist in the PubNub message handler for the &quot;cc&quot; channel of Insteon Hub running firmware version 1012. Specially crafted commands sent through the PubNub service can cause a stack-based buffer overflow overwriting arbitrary data. An attacker should send an authenticated HTTP request to trigger this vulnerability. In cmd s_event_alarm, at 0x9d01ebd4, the value for the `s_tid` key is copied using `strcpy` to the buffer at `$sp+0x2b0`.This buffer is 32 bytes large, sending anything longer will cause a buffer overflow.

- [https://github.com/Live-Hack-CVE/CVE-2017-16331](https://github.com/Live-Hack-CVE/CVE-2017-16331) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2017-16331.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2017-16331.svg)


## CVE-2017-16330
 Multiple exploitable buffer overflow vulnerabilities exist in the PubNub message handler for the &quot;cc&quot; channel of Insteon Hub running firmware version 1012. Specially crafted commands sent through the PubNub service can cause a stack-based buffer overflow overwriting arbitrary data. An attacker should send an authenticated HTTP request to trigger this vulnerability. In cmd s_event_alarm, at 0x9d01eb8c, the value for the `s_event_group` key is copied using `strcpy` to the buffer at `$sp+0x2b0`.This buffer is 32 bytes large, sending anything longer will cause a buffer overflow.

- [https://github.com/Live-Hack-CVE/CVE-2017-16330](https://github.com/Live-Hack-CVE/CVE-2017-16330) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2017-16330.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2017-16330.svg)


## CVE-2017-16329
 Multiple exploitable buffer overflow vulnerabilities exist in the PubNub message handler for the &quot;cc&quot; channel of Insteon Hub running firmware version 1012. Specially crafted commands sent through the PubNub service can cause a stack-based buffer overflow overwriting arbitrary data. An attacker should send an authenticated HTTP request to trigger this vulnerability. In cmd s_event_alarm, at 0x9d01eb44, the value for the `s_event_delay` key is copied using `strcpy` to the buffer at `$sp+0x2b0`.This buffer is 32 bytes large, sending anything longer will cause a buffer overflow.

- [https://github.com/Live-Hack-CVE/CVE-2017-16329](https://github.com/Live-Hack-CVE/CVE-2017-16329) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2017-16329.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2017-16329.svg)


## CVE-2017-16328
 Multiple exploitable buffer overflow vulnerabilities exist in the PubNub message handler for the &quot;cc&quot; channel of Insteon Hub running firmware version 1012. Specially crafted commands sent through the PubNub service can cause a stack-based buffer overflow overwriting arbitrary data. An attacker should send an authenticated HTTP request to trigger this vulnerability. In cmd s_event_alarm, at 0x9d01eb08, the value for the `s_event_offset` key is copied using `strcpy` to the buffer at `$sp+0x2b0`.This buffer is 32 bytes large, sending anything longer will cause a buffer overflow.

- [https://github.com/Live-Hack-CVE/CVE-2017-16328](https://github.com/Live-Hack-CVE/CVE-2017-16328) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2017-16328.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2017-16328.svg)


## CVE-2017-16320
 Multiple exploitable buffer overflow vulnerabilities exist in the PubNub message handler for the &quot;cc&quot; channel of Insteon Hub running firmware version 1012. Specially crafted commands sent through the PubNub service can cause a stack-based buffer overflow overwriting arbitrary data. An attacker should send an authenticated HTTP request to trigger this vulnerability. In cmd s_sonos, at 0x9d01ddd4, the value for the `s_sonos_cmd` key is copied using `strcpy` to the buffer at `$sp+0x290`.This buffer is 32 bytes large, sending anything longer will cause a buffer overflow.

- [https://github.com/Live-Hack-CVE/CVE-2017-16320](https://github.com/Live-Hack-CVE/CVE-2017-16320) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2017-16320.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2017-16320.svg)


## CVE-2017-16319
 Multiple exploitable buffer overflow vulnerabilities exist in the PubNub message handler for the &quot;cc&quot; channel of Insteon Hub running firmware version 1012. Specially crafted commands sent through the PubNub service can cause a stack-based buffer overflow overwriting arbitrary data. An attacker should send an authenticated HTTP request to trigger this vulnerability. In cmd s_sonos, at 0x9d01d7a8, the value for the `g_sonos_index` key is copied using `strcpy` to the buffer at `$sp+0x1b4`.This buffer is 8 bytes large, sending anything longer will cause a buffer overflow.

- [https://github.com/Live-Hack-CVE/CVE-2017-16319](https://github.com/Live-Hack-CVE/CVE-2017-16319) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2017-16319.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2017-16319.svg)


## CVE-2017-16318
 Multiple exploitable buffer overflow vulnerabilities exist in the PubNub message handler for the &quot;cc&quot; channel of Insteon Hub running firmware version 1012. Specially crafted commands sent through the PubNub service can cause a stack-based buffer overflow overwriting arbitrary data. An attacker should send an authenticated HTTP request to trigger this vulnerability. In cmd s_sonos, at 0x9d01d16c, the value for the `g_group_off` key is copied using `strcpy` to the buffer at `$sp+0x2b0`.This buffer is 32 bytes large, sending anything longer will cause a buffer overflow.

- [https://github.com/Live-Hack-CVE/CVE-2017-16318](https://github.com/Live-Hack-CVE/CVE-2017-16318) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2017-16318.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2017-16318.svg)


## CVE-2017-16317
 Multiple exploitable buffer overflow vulnerabilities exist in the PubNub message handler for the &quot;cc&quot; channel of Insteon Hub running firmware version 1012. Specially crafted commands sent through the PubNub service can cause a stack-based buffer overflow overwriting arbitrary data. An attacker should send an authenticated HTTP request to trigger this vulnerability. In cmd s_sonos, at 0x9d01d068, the value for the `g_group` key is copied using `strcpy` to the buffer at `$sp+0x2b0`.This buffer is 32 bytes large, sending anything longer will cause a buffer overflow.

- [https://github.com/Live-Hack-CVE/CVE-2017-16317](https://github.com/Live-Hack-CVE/CVE-2017-16317) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2017-16317.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2017-16317.svg)


## CVE-2017-16316
 Multiple exploitable buffer overflow vulnerabilities exist in the PubNub message handler for the &quot;cc&quot; channel of Insteon Hub running firmware version 1012. Specially crafted commands sent through the PubNub service can cause a stack-based buffer overflow overwriting arbitrary data. An attacker should send an authenticated HTTP request to trigger this vulnerability. In cmd s_sonos, at 0x9d01c898, the value for the `g_meta_page` key is copied using `strcpy` to the buffer at `$sp+0x2b0`.This buffer is 32 bytes large, sending anything longer will cause a buffer overflow.

- [https://github.com/Live-Hack-CVE/CVE-2017-16316](https://github.com/Live-Hack-CVE/CVE-2017-16316) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2017-16316.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2017-16316.svg)


## CVE-2017-16315
 Multiple exploitable buffer overflow vulnerabilities exist in the PubNub message handler for the &quot;cc&quot; channel of Insteon Hub running firmware version 1012. Specially crafted commands sent through the PubNub service can cause a stack-based buffer overflow overwriting arbitrary data. An attacker should send an authenticated HTTP request to trigger this vulnerability. In cmd s_sonos, at 0x9d01c3a0, the value for the `s_state` key is copied using `strcpy` to the buffer at `$sp+0x2b0`.This buffer is 32 bytes large, sending anything longer will cause a buffer overflow.

- [https://github.com/Live-Hack-CVE/CVE-2017-16315](https://github.com/Live-Hack-CVE/CVE-2017-16315) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2017-16315.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2017-16315.svg)


## CVE-2017-16314
 Multiple exploitable buffer overflow vulnerabilities exist in the PubNub message handler for the &quot;cc&quot; channel of Insteon Hub running firmware version 1012. Specially crafted commands sent through the PubNub service can cause a stack-based buffer overflow overwriting arbitrary data. An attacker should send an authenticated HTTP request to trigger this vulnerability. In cmd s_sonos, at 0x9d01c1cc, the value for the `s_speaker` key is copied using `strcpy` to the buffer at `$sp+0x2b0`.This buffer is 32 bytes large, sending anything longer will cause a buffer overflow.

- [https://github.com/Live-Hack-CVE/CVE-2017-16314](https://github.com/Live-Hack-CVE/CVE-2017-16314) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2017-16314.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2017-16314.svg)


## CVE-2017-16313
 Multiple exploitable buffer overflow vulnerabilities exist in the PubNub message handler for the &quot;cc&quot; channel of Insteon Hub running firmware version 1012. Specially crafted commands sent through the PubNub service can cause a stack-based buffer overflow overwriting arbitrary data. An attacker should send an authenticated HTTP request to trigger this vulnerability. In cmd s_sonos, at 0x9d01c084, the value for the `s_ddelay` key is copied using `strcpy` to the buffer at `$sp+0x2b0`.This buffer is 32 bytes large, sending anything longer will cause a buffer overflow.

- [https://github.com/Live-Hack-CVE/CVE-2017-16313](https://github.com/Live-Hack-CVE/CVE-2017-16313) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2017-16313.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2017-16313.svg)


## CVE-2017-16312
 Multiple exploitable buffer overflow vulnerabilities exist in the PubNub message handler for the &quot;cc&quot; channel of Insteon Hub running firmware version 1012. Specially crafted commands sent through the PubNub service can cause a stack-based buffer overflow overwriting arbitrary data. An attacker should send an authenticated HTTP request to trigger this vulnerability. In cmd s_sonos, at 0x9d01c028, the value for the `sn_discover` key is copied using `strcpy` to the buffer at `$sp+0x2b0`.This buffer is 32 bytes large, sending anything longer will cause a buffer overflow.

- [https://github.com/Live-Hack-CVE/CVE-2017-16312](https://github.com/Live-Hack-CVE/CVE-2017-16312) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2017-16312.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2017-16312.svg)


## CVE-2017-16311
 Multiple exploitable buffer overflow vulnerabilities exist in the PubNub message handler for the &quot;cc&quot; channel of Insteon Hub running firmware version 1012. Specially crafted commands sent through the PubNub service can cause a stack-based buffer overflow overwriting arbitrary data. An attacker should send an authenticated HTTP request to trigger this vulnerability. In cmd UpdateCheck, at 0x9d01bb64, the value for the `type` key is copied using `strcpy` to the buffer at `$sp+0x270`.This buffer is 16 bytes large, sending anything longer will cause a buffer overflow.

- [https://github.com/Live-Hack-CVE/CVE-2017-16311](https://github.com/Live-Hack-CVE/CVE-2017-16311) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2017-16311.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2017-16311.svg)


## CVE-2017-16310
 Multiple exploitable buffer overflow vulnerabilities exist in the PubNub message handler for the &quot;cc&quot; channel of Insteon Hub running firmware version 1012. Specially crafted commands sent through the PubNub service can cause a stack-based buffer overflow overwriting arbitrary data. An attacker should send an authenticated HTTP request to trigger this vulnerability. In cmd s_ch, at 0x9d01b7b0, the value for the `ch` key is copied using `strcpy` to the buffer at `$sp+0x334`.This buffer is 100 bytes large, sending anything longer will cause a buffer overflow.

- [https://github.com/Live-Hack-CVE/CVE-2017-16310](https://github.com/Live-Hack-CVE/CVE-2017-16310) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2017-16310.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2017-16310.svg)


## CVE-2017-16304
 Multiple exploitable buffer overflow vulnerabilities exist in the PubNub message handler for the &quot;cc&quot; channel of Insteon Hub running firmware version 1012. Specially crafted commands sent through the PubNub service can cause a stack-based buffer overflow overwriting arbitrary data. An attacker should send an authenticated HTTP request to trigger this vulnerability. In cmd sn_ex, at 0x9d01ae40, the value for the `d` key is copied using `strcpy` to the buffer at `$sp+0x334`.This buffer is 100 bytes large, sending anything longer will cause a buffer overflow.

- [https://github.com/Live-Hack-CVE/CVE-2017-16304](https://github.com/Live-Hack-CVE/CVE-2017-16304) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2017-16304.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2017-16304.svg)


## CVE-2017-16292
 Multiple exploitable buffer overflow vulnerabilities exist in the PubNub message handler for the &quot;cc&quot; channel of Insteon Hub running firmware version 1012. Specially crafted commands sent through the PubNub service can cause a stack-based buffer overflow overwriting arbitrary data. An attacker should send an authenticated HTTP request to trigger this vulnerability. In cmd g_schd, at 0x9d019c50, the value for the `grp` key is copied using `strcpy` to the buffer at `$sp+0x1b4`.This buffer is 8 bytes large, sending anything longer will cause a buffer overflow.

- [https://github.com/Live-Hack-CVE/CVE-2017-16292](https://github.com/Live-Hack-CVE/CVE-2017-16292) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2017-16292.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2017-16292.svg)


## CVE-2017-16291
 Multiple exploitable buffer overflow vulnerabilities exist in the PubNub message handler for the &quot;cc&quot; channel of Insteon Hub running firmware version 1012. Specially crafted commands sent through the PubNub service can cause a stack-based buffer overflow overwriting arbitrary data. An attacker should send an authenticated HTTP request to trigger this vulnerability. In cmd s_sun, at 0x9d019854, the value for the `sunset` key is copied using `strcpy` to the buffer at `$sp+0x334`.This buffer is 100 bytes large, sending anything longer will cause a buffer overflow.

- [https://github.com/Live-Hack-CVE/CVE-2017-16291](https://github.com/Live-Hack-CVE/CVE-2017-16291) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2017-16291.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2017-16291.svg)


## CVE-2017-16290
 Multiple exploitable buffer overflow vulnerabilities exist in the PubNub message handler for the &quot;cc&quot; channel of Insteon Hub running firmware version 1012. Specially crafted commands sent through the PubNub service can cause a stack-based buffer overflow overwriting arbitrary data. An attacker should send an authenticated HTTP request to trigger this vulnerability. In cmd s_sun, at 0x9d01980c, the value for the `sunrise` key is copied using `strcpy` to the buffer at `$sp+0x2d0`.This buffer is 100 bytes large, sending anything longer will cause a buffer overflow.

- [https://github.com/Live-Hack-CVE/CVE-2017-16290](https://github.com/Live-Hack-CVE/CVE-2017-16290) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2017-16290.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2017-16290.svg)


## CVE-2017-16288
 Multiple exploitable buffer overflow vulnerabilities exist in the PubNub message handler for the &quot;cc&quot; channel of Insteon Hub running firmware version 1012. Specially crafted commands sent through the PubNub service can cause a stack-based buffer overflow overwriting arbitrary data. An attacker should send an authenticated HTTP request to trigger this vulnerability. In cmd s_time, at 0x9d018f60, the value for the `dst` key is copied using `strcpy` to the buffer at `$sp+0x2b0`.This buffer is 32 bytes large, sending anything longer will cause a buffer overflow.

- [https://github.com/Live-Hack-CVE/CVE-2017-16288](https://github.com/Live-Hack-CVE/CVE-2017-16288) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2017-16288.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2017-16288.svg)


## CVE-2017-16287
 Multiple exploitable buffer overflow vulnerabilities exist in the PubNub message handler for the &quot;cc&quot; channel of Insteon Hub running firmware version 1012. Specially crafted commands sent through the PubNub service can cause a stack-based buffer overflow overwriting arbitrary data. An attacker should send an authenticated HTTP request to trigger this vulnerability. In cmd s_time, at 0x9d018f00, the value for the `dstend` key is copied using `strcpy` to the buffer at `$sp+0x270`.This buffer is 16 bytes large, sending anything longer will cause a buffer overflow.

- [https://github.com/Live-Hack-CVE/CVE-2017-16287](https://github.com/Live-Hack-CVE/CVE-2017-16287) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2017-16287.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2017-16287.svg)


## CVE-2017-16285
 Multiple exploitable buffer overflow vulnerabilities exist in the PubNub message handler for the &quot;cc&quot; channel of Insteon Hub running firmware version 1012. Specially crafted commands sent through the PubNub service can cause a stack-based buffer overflow overwriting arbitrary data. An attacker should send an authenticated HTTP request to trigger this vulnerability. In cmd s_time, at 0x9d018e58, the value for the `offset` key is copied using `strcpy` to the buffer at `$sp+0x2d0`.This buffer is 100 bytes large, sending anything longer will cause a buffer overflow.

- [https://github.com/Live-Hack-CVE/CVE-2017-16285](https://github.com/Live-Hack-CVE/CVE-2017-16285) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2017-16285.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2017-16285.svg)


## CVE-2017-16284
 Multiple exploitable buffer overflow vulnerabilities exist in the PubNub message handler for the &quot;cc&quot; channel of Insteon Hub running firmware version 1012. Specially crafted commands sent through the PubNub service can cause a stack-based buffer overflow overwriting arbitrary data. An attacker should send an authenticated HTTP request to trigger this vulnerability. In cmd s_name, at 0x9d018958, the value for the `city` key is copied using `strcpy` to the buffer at `$sp+0x290`.This buffer is 32 bytes large, sending anything longer will cause a buffer overflow.

- [https://github.com/Live-Hack-CVE/CVE-2017-16284](https://github.com/Live-Hack-CVE/CVE-2017-16284) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2017-16284.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2017-16284.svg)


## CVE-2017-16283
 Multiple exploitable buffer overflow vulnerabilities exist in the PubNub message handler for the &quot;cc&quot; channel of Insteon Hub running firmware version 1012. Specially crafted commands sent through the PubNub service can cause a stack-based buffer overflow overwriting arbitrary data. An attacker should send an authenticated HTTP request to trigger this vulnerability. In cmd s_name, at 0x9d0188a8, the value for the `name` key is copied using `strcpy` to the buffer at `$sp+0x2b0`.This buffer is 32 bytes large, sending anything longer will cause a buffer overflow.

- [https://github.com/Live-Hack-CVE/CVE-2017-16283](https://github.com/Live-Hack-CVE/CVE-2017-16283) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2017-16283.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2017-16283.svg)


## CVE-2017-16282
 Multiple exploitable buffer overflow vulnerabilities exist in the PubNub message handler for the &quot;cc&quot; channel of Insteon Hub running firmware version 1012. Specially crafted commands sent through the PubNub service can cause a stack-based buffer overflow overwriting arbitrary data. An attacker should send an authenticated HTTP request to trigger this vulnerability. In cmd s_net, at 0x9d01827c, the value for the `dhcp` key is copied using `strcpy` to the buffer at `$sp+0x270`.This buffer is 16 bytes large, sending anything longer will cause a buffer overflow.

- [https://github.com/Live-Hack-CVE/CVE-2017-16282](https://github.com/Live-Hack-CVE/CVE-2017-16282) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2017-16282.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2017-16282.svg)


## CVE-2017-16281
 Multiple exploitable buffer overflow vulnerabilities exist in the PubNub message handler for the &quot;cc&quot; channel of Insteon Hub running firmware version 1012. Specially crafted commands sent through the PubNub service can cause a stack-based buffer overflow overwriting arbitrary data. An attacker should send an authenticated HTTP request to trigger this vulnerability. In cmd s_net, at 0x9d018234, the value for the `sub` key is copied using `strcpy` to the buffer at `$sp+0x2b0`.This buffer is 32 bytes large, sending anything longer will cause a buffer overflow.

- [https://github.com/Live-Hack-CVE/CVE-2017-16281](https://github.com/Live-Hack-CVE/CVE-2017-16281) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2017-16281.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2017-16281.svg)


## CVE-2017-16278
 Multiple exploitable buffer overflow vulnerabilities exist in the PubNub message handler for the &quot;cc&quot; channel of Insteon Hub running firmware version 1012. Specially crafted commands sent through the PubNub service can cause a stack-based buffer overflow overwriting arbitrary data. An attacker should send an authenticated HTTP request to trigger this vulnerability. In cmd s_net, at 0x9d01815c, the value for the `ip` key is copied using `strcpy` to the buffer at `$sp+0x2d0`.This buffer is 100 bytes large, sending anything longer will cause a buffer overflow.

- [https://github.com/Live-Hack-CVE/CVE-2017-16278](https://github.com/Live-Hack-CVE/CVE-2017-16278) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2017-16278.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2017-16278.svg)


## CVE-2017-16272
 Multiple exploitable buffer overflow vulnerabilities exist in the PubNub message handler for the &quot;cc&quot; channel of Insteon Hub running firmware version 1012. Specially crafted commands sent through the PubNub service can cause a stack-based buffer overflow overwriting arbitrary data. An attacker should send an authenticated HTTP request to trigger this vulnerability. In cmd e_l, at 0x9d016cf0, the value for the `grp` key is copied using `strcpy` to the buffer at `$sp+0x1b4`.This buffer is 8 bytes large, sending anything longer will cause a buffer overflow.

- [https://github.com/Live-Hack-CVE/CVE-2017-16272](https://github.com/Live-Hack-CVE/CVE-2017-16272) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2017-16272.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2017-16272.svg)


## CVE-2017-16259
 Multiple exploitable buffer overflow vulnerabilities exist in the PubNub message handler for the &quot;cc&quot; channel of Insteon Hub running firmware version 1012. Specially crafted commands sent through the PubNub service can cause a stack-based buffer overflow overwriting arbitrary data. An attacker should send an authenticated HTTP request to trigger this vulnerability. In cmd s_auth, at 0x9d015430, the value for the `usr` key is copied using `strcpy` to the buffer at `$sp+0x290`.This buffer is 32 bytes large, sending anything longer will cause a buffer overflow.

- [https://github.com/Live-Hack-CVE/CVE-2017-16259](https://github.com/Live-Hack-CVE/CVE-2017-16259) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2017-16259.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2017-16259.svg)


## CVE-2017-7615
 MantisBT through 2.3.0 allows arbitrary password reset and unauthenticated admin access via an empty confirm_hash value to verify.php.

- [https://github.com/Live-Hack-CVE/CVE-2017-7615](https://github.com/Live-Hack-CVE/CVE-2017-7615) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2017-7615.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2017-7615.svg)


## CVE-2016-4154
 Unspecified vulnerability in Adobe Flash Player 21.0.0.242 and earlier, as used in the Adobe Flash libraries in Microsoft Internet Explorer 10 and 11 and Microsoft Edge, has unknown impact and attack vectors, a different vulnerability than other CVEs listed in MS16-083.

- [https://github.com/Live-Hack-CVE/CVE-2016-4154](https://github.com/Live-Hack-CVE/CVE-2016-4154) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-4154.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-4154.svg)


## CVE-2016-4153
 Unspecified vulnerability in Adobe Flash Player 21.0.0.242 and earlier, as used in the Adobe Flash libraries in Microsoft Internet Explorer 10 and 11 and Microsoft Edge, has unknown impact and attack vectors, a different vulnerability than other CVEs listed in MS16-083.

- [https://github.com/Live-Hack-CVE/CVE-2016-4153](https://github.com/Live-Hack-CVE/CVE-2016-4153) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-4153.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-4153.svg)


## CVE-2016-2434
 The NVIDIA video driver in Android before 2016-05-01 on Nexus 9 devices allows attackers to gain privileges via a crafted application, aka internal bug 27251090.

- [https://github.com/jianqiangzhao/CVE-2016-2434](https://github.com/jianqiangzhao/CVE-2016-2434) :  ![starts](https://img.shields.io/github/stars/jianqiangzhao/CVE-2016-2434.svg) ![forks](https://img.shields.io/github/forks/jianqiangzhao/CVE-2016-2434.svg)


## CVE-2016-1033
 Adobe Flash Player before 18.0.0.343 and 19.x through 21.x before 21.0.0.213 on Windows and OS X and before 11.2.202.616 on Linux allows attackers to execute arbitrary code or cause a denial of service (memory corruption) via unspecified vectors, a different vulnerability than CVE-2016-1012, CVE-2016-1020, CVE-2016-1021, CVE-2016-1022, CVE-2016-1023, CVE-2016-1024, CVE-2016-1025, CVE-2016-1026, CVE-2016-1027, CVE-2016-1028, CVE-2016-1029, and CVE-2016-1032.

- [https://github.com/Live-Hack-CVE/CVE-2016-1033](https://github.com/Live-Hack-CVE/CVE-2016-1033) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-1033.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-1033.svg)


## CVE-2016-1020
 Adobe Flash Player before 18.0.0.343 and 19.x through 21.x before 21.0.0.213 on Windows and OS X and before 11.2.202.616 on Linux allows attackers to execute arbitrary code or cause a denial of service (memory corruption) via unspecified vectors, a different vulnerability than CVE-2016-1012, CVE-2016-1021, CVE-2016-1022, CVE-2016-1023, CVE-2016-1024, CVE-2016-1025, CVE-2016-1026, CVE-2016-1027, CVE-2016-1028, CVE-2016-1029, CVE-2016-1032, and CVE-2016-1033.

- [https://github.com/Live-Hack-CVE/CVE-2016-1033](https://github.com/Live-Hack-CVE/CVE-2016-1033) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-1033.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-1033.svg)


## CVE-2016-1012
 Adobe Flash Player before 18.0.0.343 and 19.x through 21.x before 21.0.0.213 on Windows and OS X and before 11.2.202.616 on Linux allows attackers to execute arbitrary code or cause a denial of service (memory corruption) via unspecified vectors, a different vulnerability than CVE-2016-1020, CVE-2016-1021, CVE-2016-1022, CVE-2016-1023, CVE-2016-1024, CVE-2016-1025, CVE-2016-1026, CVE-2016-1027, CVE-2016-1028, CVE-2016-1029, CVE-2016-1032, and CVE-2016-1033.

- [https://github.com/Live-Hack-CVE/CVE-2016-1033](https://github.com/Live-Hack-CVE/CVE-2016-1033) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-1033.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-1033.svg)


## CVE-2015-4003
 The oz_usb_handle_ep_data function in drivers/staging/ozwpan/ozusbsvc1.c in the OZWPAN driver in the Linux kernel through 4.0.5 allows remote attackers to cause a denial of service (divide-by-zero error and system crash) via a crafted packet.

- [https://github.com/Live-Hack-CVE/CVE-2015-4003](https://github.com/Live-Hack-CVE/CVE-2015-4003) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2015-4003.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2015-4003.svg)


## CVE-2014-9428
 The batadv_frag_merge_packets function in net/batman-adv/fragmentation.c in the B.A.T.M.A.N. implementation in the Linux kernel through 3.18.1 uses an incorrect length field during a calculation of an amount of memory, which allows remote attackers to cause a denial of service (mesh-node system crash) via fragmented packets.

- [https://github.com/Live-Hack-CVE/CVE-2014-9428](https://github.com/Live-Hack-CVE/CVE-2014-9428) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2014-9428.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2014-9428.svg)


## CVE-2012-6689
 The netlink_sendmsg function in net/netlink/af_netlink.c in the Linux kernel before 3.5.5 does not validate the dst_pid field, which allows local users to have an unspecified impact by spoofing Netlink messages.

- [https://github.com/Live-Hack-CVE/CVE-2012-6689](https://github.com/Live-Hack-CVE/CVE-2012-6689) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2012-6689.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2012-6689.svg)

