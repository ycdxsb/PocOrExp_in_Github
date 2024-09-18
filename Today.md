# Update 2024-09-18
## CVE-2024-32651
 changedetection.io is an open source web page change detection, website watcher, restock monitor and notification service. There is a Server Side Template Injection (SSTI) in Jinja2 that allows Remote Command Execution on the server host. Attackers can run any system command without any restriction and they could use a reverse shell. The impact is critical as the attacker can completely takeover the server machine. This can be reduced if changedetection is behind a login page, but this isn't required by the application (not by default and not enforced).

- [https://github.com/s0ck3t-s3c/CVE-2024-32651-changedetection-RCE](https://github.com/s0ck3t-s3c/CVE-2024-32651-changedetection-RCE) :  ![starts](https://img.shields.io/github/stars/s0ck3t-s3c/CVE-2024-32651-changedetection-RCE.svg) ![forks](https://img.shields.io/github/forks/s0ck3t-s3c/CVE-2024-32651-changedetection-RCE.svg)


## CVE-2024-29847
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/sinsinology/CVE-2024-29847](https://github.com/sinsinology/CVE-2024-29847) :  ![starts](https://img.shields.io/github/stars/sinsinology/CVE-2024-29847.svg) ![forks](https://img.shields.io/github/forks/sinsinology/CVE-2024-29847.svg)


## CVE-2024-5458
 In PHP versions 8.1.* before 8.1.29, 8.2.* before 8.2.20, 8.3.* before 8.3.8, due to a code logic error, filtering functions such as filter_var when validating URLs (FILTER_VALIDATE_URL) for certain types of URLs the function will result in invalid user information (username + password part of URLs) being treated as valid user information. This may lead to the downstream code accepting invalid URLs as valid and parsing them incorrectly.

- [https://github.com/justmexD8/CVE-2024-5458-POC](https://github.com/justmexD8/CVE-2024-5458-POC) :  ![starts](https://img.shields.io/github/stars/justmexD8/CVE-2024-5458-POC.svg) ![forks](https://img.shields.io/github/forks/justmexD8/CVE-2024-5458-POC.svg)


## CVE-2024-4400
 The Post and Page Builder by BoldGrid &#8211; Visual Drag and Drop Editor plguin for WordPress is vulnerable to Stored Cross-Site Scripting via an unknown parameter in versions up to, and including, 1.26.4 due to insufficient input sanitization and output escaping. This makes it possible for authenticated attackers, with contributor-level permissions and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.

- [https://github.com/ifqygazhar/CVE-2024-44000-LiteSpeed-Cache](https://github.com/ifqygazhar/CVE-2024-44000-LiteSpeed-Cache) :  ![starts](https://img.shields.io/github/stars/ifqygazhar/CVE-2024-44000-LiteSpeed-Cache.svg) ![forks](https://img.shields.io/github/forks/ifqygazhar/CVE-2024-44000-LiteSpeed-Cache.svg)


## CVE-2024-4071
 A vulnerability was found in Kashipara Online Furniture Shopping Ecommerce Website 1.0 and classified as critical. This issue affects some unknown processing of the file prodInfo.php. The manipulation of the argument prodId leads to sql injection. The attack may be initiated remotely. The exploit has been disclosed to the public and may be used. The identifier VDB-261797 was assigned to this vulnerability.

- [https://github.com/watchtowrlabs/CVE-2024-40711](https://github.com/watchtowrlabs/CVE-2024-40711) :  ![starts](https://img.shields.io/github/stars/watchtowrlabs/CVE-2024-40711.svg) ![forks](https://img.shields.io/github/forks/watchtowrlabs/CVE-2024-40711.svg)


## CVE-2023-28324
 A improper input validation vulnerability exists in Ivanti Endpoint Manager 2022 and below that could allow privilege escalation or remote code execution.

- [https://github.com/horizon3ai/CVE-2023-28324](https://github.com/horizon3ai/CVE-2023-28324) :  ![starts](https://img.shields.io/github/stars/horizon3ai/CVE-2023-28324.svg) ![forks](https://img.shields.io/github/forks/horizon3ai/CVE-2023-28324.svg)


## CVE-2022-34265
 An issue was discovered in Django 3.2 before 3.2.14 and 4.0 before 4.0.6. The Trunc() and Extract() database functions are subject to SQL injection if untrusted data is used as a kind/lookup_name value. Applications that constrain the lookup name and kind choice to a known safe list are unaffected.

- [https://github.com/lnwza0x0a/CTF_Django_CVE-2022-34265](https://github.com/lnwza0x0a/CTF_Django_CVE-2022-34265) :  ![starts](https://img.shields.io/github/stars/lnwza0x0a/CTF_Django_CVE-2022-34265.svg) ![forks](https://img.shields.io/github/forks/lnwza0x0a/CTF_Django_CVE-2022-34265.svg)


## CVE-2021-3493
 The overlayfs implementation in the linux kernel did not properly validate with respect to user namespaces the setting of file capabilities on files in an underlying file system. Due to the combination of unprivileged user namespaces along with a patch carried in the Ubuntu kernel to allow unprivileged overlay mounts, an attacker could use this to gain elevated privileges.

- [https://github.com/fathallah17/OverlayFS-CVE-2021-3493](https://github.com/fathallah17/OverlayFS-CVE-2021-3493) :  ![starts](https://img.shields.io/github/stars/fathallah17/OverlayFS-CVE-2021-3493.svg) ![forks](https://img.shields.io/github/forks/fathallah17/OverlayFS-CVE-2021-3493.svg)


## CVE-2021-2109
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Console). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0, 12.2.1.4.0 and 14.1.1.0.0. Easily exploitable vulnerability allows high privileged attacker with network access via HTTP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.1 Base Score 7.2 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/lnwza0x0a/CVE-2021-2109](https://github.com/lnwza0x0a/CVE-2021-2109) :  ![starts](https://img.shields.io/github/stars/lnwza0x0a/CVE-2021-2109.svg) ![forks](https://img.shields.io/github/forks/lnwza0x0a/CVE-2021-2109.svg)


## CVE-2020-29599
 ImageMagick before 6.9.11-40 and 7.x before 7.0.10-40 mishandles the -authenticate option, which allows setting a password for password-protected PDF files. The user-controlled password was not properly escaped/sanitized and it was therefore possible to inject additional shell commands via coders/pdf.c.

- [https://github.com/lnwza0x0a/CVE-2020-29599](https://github.com/lnwza0x0a/CVE-2020-29599) :  ![starts](https://img.shields.io/github/stars/lnwza0x0a/CVE-2020-29599.svg) ![forks](https://img.shields.io/github/forks/lnwza0x0a/CVE-2020-29599.svg)


## CVE-2020-9484
 When using Apache Tomcat versions 10.0.0-M1 to 10.0.0-M4, 9.0.0.M1 to 9.0.34, 8.5.0 to 8.5.54 and 7.0.0 to 7.0.103 if a) an attacker is able to control the contents and name of a file on the server; and b) the server is configured to use the PersistenceManager with a FileStore; and c) the PersistenceManager is configured with sessionAttributeValueClassNameFilter=&quot;null&quot; (the default unless a SecurityManager is used) or a sufficiently lax filter to allow the attacker provided object to be deserialized; and d) the attacker knows the relative file path from the storage location used by FileStore to the file the attacker has control over; then, using a specifically crafted request, the attacker will be able to trigger remote code execution via deserialization of the file under their control. Note that all of conditions a) to d) must be true for the attack to succeed.

- [https://github.com/0dayCTF/CVE-2020-9484](https://github.com/0dayCTF/CVE-2020-9484) :  ![starts](https://img.shields.io/github/stars/0dayCTF/CVE-2020-9484.svg) ![forks](https://img.shields.io/github/forks/0dayCTF/CVE-2020-9484.svg)


## CVE-2020-3952
 Under certain conditions, vmdir that ships with VMware vCenter Server, as part of an embedded or external Platform Services Controller (PSC), does not correctly implement access controls.

- [https://github.com/chronoloper/CVE-2020-3952](https://github.com/chronoloper/CVE-2020-3952) :  ![starts](https://img.shields.io/github/stars/chronoloper/CVE-2020-3952.svg) ![forks](https://img.shields.io/github/forks/chronoloper/CVE-2020-3952.svg)


## CVE-2018-6574
 Go before 1.8.7, Go 1.9.x before 1.9.4, and Go 1.10 pre-releases before Go 1.10rc2 allow &quot;go get&quot; remote command execution during source code build, by leveraging the gcc or clang plugin feature, because -fplugin= and -plugin= arguments were not blocked.

- [https://github.com/Saboor-Hakimi/CVE-2018-6574](https://github.com/Saboor-Hakimi/CVE-2018-6574) :  ![starts](https://img.shields.io/github/stars/Saboor-Hakimi/CVE-2018-6574.svg) ![forks](https://img.shields.io/github/forks/Saboor-Hakimi/CVE-2018-6574.svg)


## CVE-2000-0114
 Frontpage Server Extensions allows remote attackers to determine the name of the anonymous account via an RPC POST request to shtml.dll in the /_vti_bin/ virtual directory.

- [https://github.com/adhamelhansye/CVE-2000-0114](https://github.com/adhamelhansye/CVE-2000-0114) :  ![starts](https://img.shields.io/github/stars/adhamelhansye/CVE-2000-0114.svg) ![forks](https://img.shields.io/github/forks/adhamelhansye/CVE-2000-0114.svg)

