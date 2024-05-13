# Update 2024-05-13
## CVE-2024-32523
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/truonghuuphuc/CVE-2024-32523-Poc](https://github.com/truonghuuphuc/CVE-2024-32523-Poc) :  ![starts](https://img.shields.io/github/stars/truonghuuphuc/CVE-2024-32523-Poc.svg) ![forks](https://img.shields.io/github/forks/truonghuuphuc/CVE-2024-32523-Poc.svg)


## CVE-2024-22393
 Unrestricted Upload of File with Dangerous Type vulnerability in Apache Answer.This issue affects Apache Answer: through 1.2.1. Pixel Flood Attack by uploading large pixel files will cause server out of memory. A logged-in user can cause such an attack by uploading an image when posting content. Users are recommended to upgrade to version [1.2.5], which fixes the issue.

- [https://github.com/omranisecurity/CVE-2024-22393](https://github.com/omranisecurity/CVE-2024-22393) :  ![starts](https://img.shields.io/github/stars/omranisecurity/CVE-2024-22393.svg) ![forks](https://img.shields.io/github/forks/omranisecurity/CVE-2024-22393.svg)


## CVE-2024-21413
 Microsoft Outlook Remote Code Execution Vulnerability

- [https://github.com/th3Hellion/CVE-2024-21413](https://github.com/th3Hellion/CVE-2024-21413) :  ![starts](https://img.shields.io/github/stars/th3Hellion/CVE-2024-21413.svg) ![forks](https://img.shields.io/github/forks/th3Hellion/CVE-2024-21413.svg)


## CVE-2024-3422
 A vulnerability was found in SourceCodester Online Courseware 1.0. It has been declared as critical. This vulnerability affects unknown code of the file admin/activatestud.php. The manipulation of the argument selector leads to sql injection. The attack can be initiated remotely. The exploit has been disclosed to the public and may be used. VDB-259594 is the identifier assigned to this vulnerability.

- [https://github.com/dovankha/CVE-2024-34225](https://github.com/dovankha/CVE-2024-34225) :  ![starts](https://img.shields.io/github/stars/dovankha/CVE-2024-34225.svg) ![forks](https://img.shields.io/github/forks/dovankha/CVE-2024-34225.svg)
- [https://github.com/dovankha/CVE-2024-34224](https://github.com/dovankha/CVE-2024-34224) :  ![starts](https://img.shields.io/github/stars/dovankha/CVE-2024-34224.svg) ![forks](https://img.shields.io/github/forks/dovankha/CVE-2024-34224.svg)
- [https://github.com/dovankha/CVE-2024-34222](https://github.com/dovankha/CVE-2024-34222) :  ![starts](https://img.shields.io/github/stars/dovankha/CVE-2024-34222.svg) ![forks](https://img.shields.io/github/forks/dovankha/CVE-2024-34222.svg)
- [https://github.com/dovankha/CVE-2024-34226](https://github.com/dovankha/CVE-2024-34226) :  ![starts](https://img.shields.io/github/stars/dovankha/CVE-2024-34226.svg) ![forks](https://img.shields.io/github/forks/dovankha/CVE-2024-34226.svg)
- [https://github.com/dovankha/CVE-2024-34223](https://github.com/dovankha/CVE-2024-34223) :  ![starts](https://img.shields.io/github/stars/dovankha/CVE-2024-34223.svg) ![forks](https://img.shields.io/github/forks/dovankha/CVE-2024-34223.svg)
- [https://github.com/dovankha/CVE-2024-34221](https://github.com/dovankha/CVE-2024-34221) :  ![starts](https://img.shields.io/github/stars/dovankha/CVE-2024-34221.svg) ![forks](https://img.shields.io/github/forks/dovankha/CVE-2024-34221.svg)


## CVE-2024-1561
 An issue was discovered in gradio-app/gradio, where the `/component_server` endpoint improperly allows the invocation of any method on a `Component` class with attacker-controlled arguments. Specifically, by exploiting the `move_resource_to_block_cache()` method of the `Block` class, an attacker can copy any file on the filesystem to a temporary directory and subsequently retrieve it. This vulnerability enables unauthorized local file read access, posing a significant risk especially when the application is exposed to the internet via `launch(share=True)`, thereby allowing remote attackers to read files on the host machine. Furthermore, gradio apps hosted on `huggingface.co` are also affected, potentially leading to the exposure of sensitive information such as API keys and credentials stored in environment variables.

- [https://github.com/DiabloHTB/CVE-2024-1561](https://github.com/DiabloHTB/CVE-2024-1561) :  ![starts](https://img.shields.io/github/stars/DiabloHTB/CVE-2024-1561.svg) ![forks](https://img.shields.io/github/forks/DiabloHTB/CVE-2024-1561.svg)


## CVE-2023-46604
 The Java OpenWire protocol marshaller is vulnerable to Remote Code Execution. This vulnerability may allow a remote attacker with network access to either a Java-based OpenWire broker or client to run arbitrary shell commands by manipulating serialized class types in the OpenWire protocol to cause either the client or the broker (respectively) to instantiate any class on the classpath. Users are recommended to upgrade both brokers and clients to version 5.15.16, 5.16.7, 5.17.6, or 5.18.3 which fixes this issue.

- [https://github.com/infokek/activemq-honeypot](https://github.com/infokek/activemq-honeypot) :  ![starts](https://img.shields.io/github/stars/infokek/activemq-honeypot.svg) ![forks](https://img.shields.io/github/forks/infokek/activemq-honeypot.svg)


## CVE-2023-40000
 Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability in LiteSpeed Technologies LiteSpeed Cache allows Stored XSS.This issue affects LiteSpeed Cache: from n/a through 5.7.

- [https://github.com/quantiom/litespeed-cache-xss-poc](https://github.com/quantiom/litespeed-cache-xss-poc) :  ![starts](https://img.shields.io/github/stars/quantiom/litespeed-cache-xss-poc.svg) ![forks](https://img.shields.io/github/forks/quantiom/litespeed-cache-xss-poc.svg)


## CVE-2023-27524
 Session Validation attacks in Apache Superset versions up to and including 2.0.1. Installations that have not altered the default configured SECRET_KEY according to installation instructions allow for an attacker to authenticate and access unauthorized resources. This does not affect Superset administrators who have changed the default value for SECRET_KEY config. All superset installations should always set a unique secure random SECRET_KEY. Your SECRET_KEY is used to securely sign all session cookies and encrypting sensitive information on the database. Add a strong SECRET_KEY to your `superset_config.py` file like: SECRET_KEY = &lt;YOUR_OWN_RANDOM_GENERATED_SECRET_KEY&gt; Alternatively you can set it with `SUPERSET_SECRET_KEY` environment variable.

- [https://github.com/karthi-the-hacker/CVE-2023-27524](https://github.com/karthi-the-hacker/CVE-2023-27524) :  ![starts](https://img.shields.io/github/stars/karthi-the-hacker/CVE-2023-27524.svg) ![forks](https://img.shields.io/github/forks/karthi-the-hacker/CVE-2023-27524.svg)
- [https://github.com/Cappricio-Securities/CVE-2023-2752](https://github.com/Cappricio-Securities/CVE-2023-2752) :  ![starts](https://img.shields.io/github/stars/Cappricio-Securities/CVE-2023-2752.svg) ![forks](https://img.shields.io/github/forks/Cappricio-Securities/CVE-2023-2752.svg)


## CVE-2020-14882
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Console). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0, 12.2.1.4.0 and 14.1.1.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/lolminerxmrig/CVE-2020-14882_ALL](https://github.com/lolminerxmrig/CVE-2020-14882_ALL) :  ![starts](https://img.shields.io/github/stars/lolminerxmrig/CVE-2020-14882_ALL.svg) ![forks](https://img.shields.io/github/forks/lolminerxmrig/CVE-2020-14882_ALL.svg)

