## CVE-2023-25396
 Privilege escalation in the MSI repair functionality in Caphyon Advanced Installer 20.0 and below allows attackers to access and manipulate system files.



- [https://github.com/Live-Hack-CVE/CVE-2023-25396](https://github.com/Live-Hack-CVE/CVE-2023-25396) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-25396.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-25396.svg)

## CVE-2023-25194
 A possible security vulnerability has been identified in Apache Kafka Connect. This requires access to a Kafka Connect worker, and the ability to create/modify connectors on it with an arbitrary Kafka client SASL JAAS config and a SASL-based security protocol, which has been possible on Kafka Connect clusters since Apache Kafka 2.3.0. When configuring the connector via the Kafka Connect REST API, an authenticated operator can set the `sasl.jaas.config` property for any of the connector's Kafka clients to &quot;com.sun.security.auth.module.JndiLoginModule&quot;, which can be done via the `producer.override.sasl.jaas.config`, `consumer.override.sasl.jaas.config`, or `admin.override.sasl.jaas.config` properties. This will allow the server to connect to the attacker's LDAP server and deserialize the LDAP response, which the attacker can use to execute java deserialization gadget chains on the Kafka connect server. Attacker can cause unrestricted deserialization of untrusted data (or) RCE vulnerability when there are gadgets in the classpath. Since Apache Kafka 3.0.0, users are allowed to specify these properties in connector configurations for Kafka Connect clusters running with out-of-the-box configurations. Before Apache Kafka 3.0.0, users may not specify these properties unless the Kafka Connect cluster has been reconfigured with a connector client override policy that permits them. Since Apache Kafka 3.4.0, we have added a system property (&quot;-Dorg.apache.kafka.disallowed.login.modules&quot;) to disable the problematic login modules usage in SASL JAAS configuration. Also by default &quot;com.sun.security.auth.module.JndiLoginModule&quot; is disabled in Apache Kafka 3.4.0. We advise the Kafka Connect users to validate connector configurations and only allow trusted JNDI configurations. Also examine connector dependencies for vulnerable versions and either upgrade their connectors, upgrading that specific dependency, or removing the connectors as options for remediation. Finally, in addition to leveraging the &quot;org.apache.kafka.disallowed.login.modules&quot; system property, Kafka Connect users can also implement their own connector client config override policy, which can be used to control which Kafka client properties can be overridden directly in a connector config and which cannot.



- [https://github.com/ohnonoyesyes/CVE-2023-25194](https://github.com/ohnonoyesyes/CVE-2023-25194) :  ![starts](https://img.shields.io/github/stars/ohnonoyesyes/CVE-2023-25194.svg) ![forks](https://img.shields.io/github/forks/ohnonoyesyes/CVE-2023-25194.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-25194](https://github.com/Live-Hack-CVE/CVE-2023-25194) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-25194.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-25194.svg)

## CVE-2023-25193
 hb-ot-layout-gsubgpos.hh in HarfBuzz through 6.0.0 allows attackers to trigger O(n^2) growth via consecutive marks during the process of looking back for base glyphs when attaching marks.



- [https://github.com/Live-Hack-CVE/CVE-2023-25193](https://github.com/Live-Hack-CVE/CVE-2023-25193) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-25193.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-25193.svg)

## CVE-2023-25168
 Wings is Pterodactyl's server control plane. This vulnerability can be used to delete files and directories recursively on the host system. This vulnerability can be combined with `GHSA-p8r3-83r8-jwj5` to overwrite files on the host system. In order to use this exploit, an attacker must have an existing &quot;server&quot; allocated and controlled by Wings. This vulnerability has been resolved in version `v1.11.4` of Wings, and has been back-ported to the 1.7 release series in `v1.7.4`. Anyone running `v1.11.x` should upgrade to `v1.11.4` and anyone running `v1.7.x` should upgrade to `v1.7.4`. There are no known workarounds for this issue.



- [https://github.com/Live-Hack-CVE/CVE-2023-25168](https://github.com/Live-Hack-CVE/CVE-2023-25168) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-25168.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-25168.svg)

## CVE-2023-25163
 Argo CD is a declarative, GitOps continuous delivery tool for Kubernetes. All versions of Argo CD starting with v2.6.0-rc1 have an output sanitization bug which leaks repository access credentials in error messages. These error messages are visible to the user, and they are logged. The error message is visible when a user attempts to create or update an Application via the Argo CD API (and therefor the UI or CLI). The user must have `applications, create` or `applications, update` RBAC access to reach the code which may produce the error. The user is not guaranteed to be able to trigger the error message. They may attempt to spam the API with requests to trigger a rate limit error from the upstream repository. If the user has `repositories, update` access, they may edit an existing repository to introduce a URL typo or otherwise force an error message. But if they have that level of access, they are probably intended to have access to the credentials anyway. A patch for this vulnerability has been released in version 2.6.1. Users are advised to upgrade. There are no known workarounds for this vulnerability.



- [https://github.com/Live-Hack-CVE/CVE-2023-25163](https://github.com/Live-Hack-CVE/CVE-2023-25163) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-25163.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-25163.svg)

## CVE-2023-25152
 Wings is Pterodactyl's server control plane. Affected versions are subject to a vulnerability which can be used to create new files and directory structures on the host system that previously did not exist, potentially allowing attackers to change their resource allocations, promote their containers to privileged mode, or potentially add ssh authorized keys to allow the attacker access to a remote shell on the target machine. In order to use this exploit, an attacker must have an existing &quot;server&quot; allocated and controlled by the Wings Daemon. This vulnerability has been resolved in version `v1.11.3` of the Wings Daemon, and has been back-ported to the 1.7 release series in `v1.7.3`. Anyone running `v1.11.x` should upgrade to `v1.11.3` and anyone running `v1.7.x` should upgrade to `v1.7.3`. There are no known workarounds for this vulnerability. ### Workarounds None at this time.



- [https://github.com/Live-Hack-CVE/CVE-2023-25152](https://github.com/Live-Hack-CVE/CVE-2023-25152) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-25152.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-25152.svg)

## CVE-2023-25139
 sprintf in the GNU C Library (glibc) 2.37 has a buffer overflow (out-of-bounds write) in some situations with a correct buffer size. This is unrelated to CWE-676. It may write beyond the bounds of the destination buffer when attempting to write a padded, thousands-separated string representation of a number, if the buffer is allocated the exact size required to represent that number as a string. For example, 1,234,567 (with padding to 13) overflows by two bytes.



- [https://github.com/Live-Hack-CVE/CVE-2023-25139](https://github.com/Live-Hack-CVE/CVE-2023-25139) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-25139.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-25139.svg)

## CVE-2023-25136
 OpenSSH server (sshd) 9.1 introduced a double-free vulnerability during options.kex_algorithms handling. This is fixed in OpenSSH 9.2. The double free can be triggered by an unauthenticated attacker in the default configuration. One third-party report states &quot;remote code execution is theoretically possible.&quot;



- [https://github.com/jfrog/jfrog-CVE-2023-25136-OpenSSH_Double-Free](https://github.com/jfrog/jfrog-CVE-2023-25136-OpenSSH_Double-Free) :  ![starts](https://img.shields.io/github/stars/jfrog/jfrog-CVE-2023-25136-OpenSSH_Double-Free.svg) ![forks](https://img.shields.io/github/forks/jfrog/jfrog-CVE-2023-25136-OpenSSH_Double-Free.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-25136](https://github.com/Live-Hack-CVE/CVE-2023-25136) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-25136.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-25136.svg)

## CVE-2023-25135
 vBulletin before 5.6.9 PL1 allows an unauthenticated remote attacker to execute arbitrary code via a crafted HTTP request that triggers deserialization. This occurs because verify_serialized checks that a value is serialized by calling unserialize and then checking for errors. The fixed versions are 5.6.7 PL1, 5.6.8 PL1, and 5.6.9 PL1.



- [https://github.com/Live-Hack-CVE/CVE-2023-25135](https://github.com/Live-Hack-CVE/CVE-2023-25135) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-25135.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-25135.svg)

## CVE-2023-25015
 Clockwork Web before 0.1.2, when Rails before 5.2 is used, allows CSRF.



- [https://github.com/Live-Hack-CVE/CVE-2023-25015](https://github.com/Live-Hack-CVE/CVE-2023-25015) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-25015.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-25015.svg)

## CVE-2023-25012
 The Linux kernel through 6.1.9 has a Use-After-Free in bigben_remove in drivers/hid/hid-bigbenff.c via a crafted USB device because the LED controllers remain registered for too long.



- [https://github.com/Live-Hack-CVE/CVE-2023-25012](https://github.com/Live-Hack-CVE/CVE-2023-25012) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-25012.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-25012.svg)

## CVE-2023-24997
 Deserialization of Untrusted Data vulnerability in Apache Software Foundation Apache InLong.This issue affects Apache InLong: from 1.1.0 through 1.5.0. Users are advised to upgrade to Apache InLong's latest version or cherry-pick https://github.com/apache/inlong/pull/7223 https://github.com/apache/inlong/pull/7223 to solve it.



- [https://github.com/Live-Hack-CVE/CVE-2023-24997](https://github.com/Live-Hack-CVE/CVE-2023-24997) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24997.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24997.svg)

## CVE-2023-24977
 Out-of-bounds Read vulnerability in Apache Software Foundation Apache InLong.This issue affects Apache InLong: from 1.1.0 through 1.5.0. Users are advised to upgrade to Apache InLong's latest version or cherry-pick https://github.com/apache/inlong/pull/7214 https://github.com/apache/inlong/pull/7214 to solve it.



- [https://github.com/Live-Hack-CVE/CVE-2023-24977](https://github.com/Live-Hack-CVE/CVE-2023-24977) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24977.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24977.svg)

## CVE-2023-24956
 Forget Heart Message Box v1.1 was discovered to contain a SQL injection vulnerability via the name parameter at /cha.php.



- [https://github.com/Live-Hack-CVE/CVE-2023-24956](https://github.com/Live-Hack-CVE/CVE-2023-24956) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24956.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24956.svg)

## CVE-2023-24829
 Incorrect Authorization vulnerability in Apache Software Foundation Apache IoTDB.This issue affects the iotdb-web-workbench component from 0.13.0 before 0.13.3. iotdb-web-workbench is an optional component of IoTDB, providing a web console of the database. This problem is fixed from version 0.13.3 of iotdb-web-workbench onwards.



- [https://github.com/Live-Hack-CVE/CVE-2023-24829](https://github.com/Live-Hack-CVE/CVE-2023-24829) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24829.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24829.svg)

## CVE-2023-24828
 Onedev is a self-hosted Git Server with CI/CD and Kanban. In versions prior to 7.9.12 the algorithm used to generate access token and password reset keys was not cryptographically secure. Existing normal users (or everyone if it allows self-registration) may exploit this to elevate privilege to obtain administrator permission. This issue is has been addressed in version 7.9.12. Users are advised to upgrade. There are no known workarounds for this vulnerability.



- [https://github.com/Live-Hack-CVE/CVE-2023-24828](https://github.com/Live-Hack-CVE/CVE-2023-24828) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24828.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24828.svg)

## CVE-2023-24827
 syft is a a CLI tool and Go library for generating a Software Bill of Materials (SBOM) from container images and filesystems. A password disclosure flaw was found in Syft versions v0.69.0 and v0.69.1. This flaw leaks the password stored in the SYFT_ATTEST_PASSWORD environment variable. The `SYFT_ATTEST_PASSWORD` environment variable is for the `syft attest` command to generate attested SBOMs for the given container image. This environment variable is used to decrypt the private key (provided with `syft attest --key &lt;path-to-key-file&gt;`) during the signing process while generating an SBOM attestation. This vulnerability affects users running syft that have the `SYFT_ATTEST_PASSWORD` environment variable set with credentials (regardless of if the attest command is being used or not). Users that do not have the environment variable `SYFT_ATTEST_PASSWORD` set are not affected by this issue. The credentials are leaked in two ways: in the syft logs when `-vv` or `-vvv` are used in the syft command (which is any log level &gt;= `DEBUG`) and in the attestation or SBOM only when the `syft-json` format is used. Note that as of v0.69.0 any generated attestations by the `syft attest` command are uploaded to the OCI registry (if you have write access to that registry) in the same way `cosign attach` is done. This means that any attestations generated for the affected versions of syft when the `SYFT_ATTEST_PASSWORD` environment variable was set would leak credentials in the attestation payload uploaded to the OCI registry. This issue has been patched in commit `9995950c70` and has been released as v0.70.0. There are no workarounds for this vulnerability. Users are advised to upgrade.



- [https://github.com/Live-Hack-CVE/CVE-2023-24827](https://github.com/Live-Hack-CVE/CVE-2023-24827) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24827.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24827.svg)

## CVE-2023-24815
 Vert.x-Web is a set of building blocks for building web applications in the java programming language. When running vertx web applications that serve files using `StaticHandler` on Windows Operating Systems and Windows File Systems, if the mount point is a wildcard (`*`) then an attacker can exfiltrate any class path resource. When computing the relative path to locate the resource, in case of wildcards, the code: `return &quot;/&quot; + rest;` from `Utils.java` returns the user input (without validation) as the segment to lookup. Even though checks are performed to avoid escaping the sandbox, given that the input was not sanitized `\` are not properly handled and an attacker can build a path that is valid within the classpath. This issue only affects users deploying in windows environments and upgrading is the advised remediation path. There are no known workarounds for this vulnerability.



- [https://github.com/Live-Hack-CVE/CVE-2023-24815](https://github.com/Live-Hack-CVE/CVE-2023-24815) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24815.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24815.svg)

## CVE-2023-24808
 PDFio is a C library for reading and writing PDF files. In versions prior to 1.1.0 a denial of service (DOS) vulnerability exists in the pdfio parser. Crafted pdf files can cause the program to run at 100% utilization and never terminate. The pdf which causes this crash found in testing is about 28kb in size and was discovered via fuzzing. Anyone who uses this library either as a standalone binary or as a library can be DOSed when attempting to parse this type of file. Web servers or other automated processes which rely on this code to turn pdf submissions into plaintext can be DOSed when an attacker uploads the pdf. Please see the linked GHSA for an example pdf. Users are advised to upgrade. There are no known workarounds for this vulnerability.



- [https://github.com/Live-Hack-CVE/CVE-2023-24808](https://github.com/Live-Hack-CVE/CVE-2023-24808) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24808.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24808.svg)

## CVE-2023-24806
 ** REJECT ** DO NOT USE THIS CANDIDATE NUMBER. Reason: This CVE has been rejected as it was incorrectly assigned. All references and descriptions in this candidate have been removed to prevent accidental usage.



- [https://github.com/Live-Hack-CVE/CVE-2023-24806](https://github.com/Live-Hack-CVE/CVE-2023-24806) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24806.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24806.svg)

## CVE-2023-24689
 An issue in Mojoportal v2.7.0.0 and below allows an authenticated attacker to list all css files inside the root path of the webserver via manipulation of the &quot;s&quot; parameter in /DesignTools/ManageSkin.aspx



- [https://github.com/Live-Hack-CVE/CVE-2023-24689](https://github.com/Live-Hack-CVE/CVE-2023-24689) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24689.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24689.svg)

## CVE-2023-24688
 An issue in Mojoportal v2.7.0.0 allows an unauthenticated attacker to register a new user even if the Allow User Registrations feature is disabled.



- [https://github.com/Live-Hack-CVE/CVE-2023-24688](https://github.com/Live-Hack-CVE/CVE-2023-24688) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24688.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24688.svg)

## CVE-2023-24687
 Mojoportal v2.7.0.0 was discovered to contain a stored cross-site scripting (XSS) vulnerability in the Company Info Settings component. This vulnerability allows attackers to execute arbitrary web scripts or HTML via a crafted payload injected into the txtCompanyName parameter.



- [https://github.com/Live-Hack-CVE/CVE-2023-24687](https://github.com/Live-Hack-CVE/CVE-2023-24687) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24687.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24687.svg)

## CVE-2023-24623
 Paranoidhttp before 0.3.0 allows SSRF because [::] is equivalent to the 127.0.0.1 address, but does not match the filter for private addresses.



- [https://github.com/Live-Hack-CVE/CVE-2023-24623](https://github.com/Live-Hack-CVE/CVE-2023-24623) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24623.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24623.svg)

## CVE-2023-24622
 isInList in the safeurl-python package before 1.2 for Python has an insufficiently restrictive regular expression for external domains, leading to SSRF.



- [https://github.com/Live-Hack-CVE/CVE-2023-24622](https://github.com/Live-Hack-CVE/CVE-2023-24622) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24622.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24622.svg)

## CVE-2023-24612
 The PdfBook extension through 2.0.5 before b07b6a64 for MediaWiki allows command injection via an option.



- [https://github.com/Live-Hack-CVE/CVE-2023-24612](https://github.com/Live-Hack-CVE/CVE-2023-24612) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24612.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24612.svg)

## CVE-2023-24610
 NOSH 4a5cfdb allows remote authenticated users to execute PHP arbitrary code via the &quot;practice logo&quot; upload feature. The client-side checks can be bypassed. This may allow attackers to steal Protected Health Information because the product is for health charting.



- [https://github.com/abbisQQ/CVE-2023-24610](https://github.com/abbisQQ/CVE-2023-24610) :  ![starts](https://img.shields.io/github/stars/abbisQQ/CVE-2023-24610.svg) ![forks](https://img.shields.io/github/forks/abbisQQ/CVE-2023-24610.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-24610](https://github.com/Live-Hack-CVE/CVE-2023-24610) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24610.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24610.svg)

## CVE-2023-24508
 Baicells Nova 227, Nova 233, and Nova 243 LTE TDD eNodeB and Nova 246 devices with firmware through RTS/RTD 3.6.6 are vulnerable to remote shell code exploitation via HTTP command injections. Commands are executed using pre-login execution and executed with root permissions. The following methods below have been tested and validated by a 3rd party analyst and has been confirmed exploitable special thanks to Rustam Amin for providing the steps to reproduce.



- [https://github.com/Live-Hack-CVE/CVE-2023-24508](https://github.com/Live-Hack-CVE/CVE-2023-24508) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24508.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24508.svg)

## CVE-2023-24495
 A Server Side Request Forgery (SSRF) vulnerability exists in Tenable.sc due to improper validation of session &amp; user-accessible input data. A privileged, authenticated remote attacker could interact with external and internal services covertly.



- [https://github.com/Live-Hack-CVE/CVE-2023-24495](https://github.com/Live-Hack-CVE/CVE-2023-24495) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24495.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24495.svg)

## CVE-2023-24494
 A stored cross-site scripting (XSS) vulnerability exists in Tenable.sc due to improper validation of user-supplied input before returning it to users. An authenticated, remote attacker can exploit this by convincing a user to click a specially crafted URL, to execute arbitrary script code in a user's browser session.



- [https://github.com/Live-Hack-CVE/CVE-2023-24494](https://github.com/Live-Hack-CVE/CVE-2023-24494) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24494.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24494.svg)

## CVE-2023-24493
 A formula injection vulnerability exists in Tenable.sc due to improper validation of user-supplied input before returning it to users. An authenticated attacker could leverage the reporting system to export reports containing formulas, which would then require a victim to approve and execute on a host.



- [https://github.com/Live-Hack-CVE/CVE-2023-24493](https://github.com/Live-Hack-CVE/CVE-2023-24493) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24493.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24493.svg)

## CVE-2023-24459
 A missing permission check in Jenkins BearyChat Plugin 3.0.2 and earlier allows attackers with Overall/Read permission to connect to an attacker-specified URL.



- [https://github.com/Live-Hack-CVE/CVE-2023-24459](https://github.com/Live-Hack-CVE/CVE-2023-24459) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24459.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24459.svg)

## CVE-2023-24458
 A cross-site request forgery (CSRF) vulnerability in Jenkins BearyChat Plugin 3.0.2 and earlier allows attackers to connect to an attacker-specified URL.



- [https://github.com/Live-Hack-CVE/CVE-2023-24458](https://github.com/Live-Hack-CVE/CVE-2023-24458) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24458.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24458.svg)

## CVE-2023-24457
 A cross-site request forgery (CSRF) vulnerability in Jenkins Keycloak Authentication Plugin 2.3.0 and earlier allows attackers to trick users into logging in to the attacker's account.



- [https://github.com/Live-Hack-CVE/CVE-2023-24457](https://github.com/Live-Hack-CVE/CVE-2023-24457) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24457.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24457.svg)

## CVE-2023-24456
 Jenkins Keycloak Authentication Plugin 2.3.0 and earlier does not invalidate the previous session on login.



- [https://github.com/Live-Hack-CVE/CVE-2023-24456](https://github.com/Live-Hack-CVE/CVE-2023-24456) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24456.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24456.svg)

## CVE-2023-24455
 Jenkins visualexpert Plugin 1.3 and earlier does not restrict the names of files in methods implementing form validation, allowing attackers with Item/Configure permission to check for the existence of an attacker-specified file path on the Jenkins controller file system.



- [https://github.com/Live-Hack-CVE/CVE-2023-24455](https://github.com/Live-Hack-CVE/CVE-2023-24455) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24455.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24455.svg)

## CVE-2023-24454
 Jenkins TestQuality Updater Plugin 1.3 and earlier stores the TestQuality Updater password unencrypted in its global configuration file on the Jenkins controller where it can be viewed by users with access to the Jenkins controller file system.



- [https://github.com/Live-Hack-CVE/CVE-2023-24454](https://github.com/Live-Hack-CVE/CVE-2023-24454) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24454.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24454.svg)

## CVE-2023-24453
 A missing check in Jenkins TestQuality Updater Plugin 1.3 and earlier allows attackers with Overall/Read permission to connect to an attacker-specified URL using attacker-specified username and password.



- [https://github.com/Live-Hack-CVE/CVE-2023-24453](https://github.com/Live-Hack-CVE/CVE-2023-24453) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24453.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24453.svg)

## CVE-2023-24452
 A cross-site request forgery (CSRF) vulnerability in Jenkins TestQuality Updater Plugin 1.3 and earlier allows attackers to connect to an attacker-specified URL using attacker-specified username and password.



- [https://github.com/Live-Hack-CVE/CVE-2023-24452](https://github.com/Live-Hack-CVE/CVE-2023-24452) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24452.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24452.svg)

## CVE-2023-24445
 Jenkins OpenID Plugin 2.4 and earlier improperly determines that a redirect URL after login is legitimately pointing to Jenkins.



- [https://github.com/Live-Hack-CVE/CVE-2023-24445](https://github.com/Live-Hack-CVE/CVE-2023-24445) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24445.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24445.svg)

## CVE-2023-24440
 Jenkins JIRA Pipeline Steps Plugin 2.0.165.v8846cf59f3db and earlier transmits the private key in plain text as part of the global Jenkins configuration form, potentially resulting in their exposure.



- [https://github.com/Live-Hack-CVE/CVE-2023-24440](https://github.com/Live-Hack-CVE/CVE-2023-24440) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24440.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24440.svg)

## CVE-2023-24439
 Jenkins JIRA Pipeline Steps Plugin 2.0.165.v8846cf59f3db and earlier stores the private keys unencrypted in its global configuration file on the Jenkins controller where it can be viewed by users with access to the Jenkins controller file system.



- [https://github.com/Live-Hack-CVE/CVE-2023-24439](https://github.com/Live-Hack-CVE/CVE-2023-24439) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24439.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24439.svg)

## CVE-2023-24438
 A missing permission check in Jenkins JIRA Pipeline Steps Plugin 2.0.165.v8846cf59f3db and earlier allows attackers with Overall/Read permission to connect to an attacker-specified URL using attacker-specified credentials IDs obtained through another method, capturing credentials stored in Jenkins.



- [https://github.com/Live-Hack-CVE/CVE-2023-24438](https://github.com/Live-Hack-CVE/CVE-2023-24438) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24438.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24438.svg)

## CVE-2023-24430
 Jenkins Semantic Versioning Plugin 1.14 and earlier does not configure its XML parser to prevent XML external entity (XXE) attacks.



- [https://github.com/Live-Hack-CVE/CVE-2023-24430](https://github.com/Live-Hack-CVE/CVE-2023-24430) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24430.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24430.svg)

## CVE-2023-24429
 Jenkins Semantic Versioning Plugin 1.14 and earlier does not restrict execution of an controller/agent message to agents, and implements no limitations about the file path that can be parsed, allowing attackers able to control agent processes to have Jenkins parse a crafted file that uses external entities for extraction of secrets from the Jenkins controller or server-side request forgery.



- [https://github.com/Live-Hack-CVE/CVE-2023-24429](https://github.com/Live-Hack-CVE/CVE-2023-24429) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24429.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24429.svg)

## CVE-2023-24428
 A cross-site request forgery (CSRF) vulnerability in Jenkins Bitbucket OAuth Plugin 0.12 and earlier allows attackers to trick users into logging in to the attacker's account.



- [https://github.com/Live-Hack-CVE/CVE-2023-24428](https://github.com/Live-Hack-CVE/CVE-2023-24428) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24428.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24428.svg)

## CVE-2023-24427
 Jenkins Bitbucket OAuth Plugin 0.12 and earlier does not invalidate the previous session on login.



- [https://github.com/Live-Hack-CVE/CVE-2023-24427](https://github.com/Live-Hack-CVE/CVE-2023-24427) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24427.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24427.svg)

## CVE-2023-24426
 Jenkins Azure AD Plugin 303.va_91ef20ee49f and earlier does not invalidate the previous session on login.



- [https://github.com/Live-Hack-CVE/CVE-2023-24426](https://github.com/Live-Hack-CVE/CVE-2023-24426) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24426.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24426.svg)

## CVE-2023-24425
 Jenkins Kubernetes Credentials Provider Plugin 1.208.v128ee9800c04 and earlier does not set the appropriate context for Kubernetes credentials lookup, allowing attackers with Item/Configure permission to access and potentially capture Kubernetes credentials they are not entitled to.



- [https://github.com/Live-Hack-CVE/CVE-2023-24425](https://github.com/Live-Hack-CVE/CVE-2023-24425) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24425.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24425.svg)

## CVE-2023-24422
 A sandbox bypass vulnerability involving map constructors in Jenkins Script Security Plugin 1228.vd93135a_2fb_25 and earlier allows attackers with permission to define and run sandboxed scripts, including Pipelines, to bypass the sandbox protection and execute arbitrary code in the context of the Jenkins controller JVM.



- [https://github.com/Live-Hack-CVE/CVE-2023-24422](https://github.com/Live-Hack-CVE/CVE-2023-24422) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24422.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24422.svg)

## CVE-2023-24323
 Mojoportal v2.7 was discovered to contain an authenticated XML external entity (XXE) injection vulnerability.



- [https://github.com/Live-Hack-CVE/CVE-2023-24323](https://github.com/Live-Hack-CVE/CVE-2023-24323) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24323.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24323.svg)

## CVE-2023-24322
 A reflected cross-site scripting (XSS) vulnerability in the FileDialog.aspx component of mojoPortal v2.7.0.0 allows attackers to execute arbitrary web scripts or HTML via a crafted payload injected into the ed and tbi parameters.



- [https://github.com/Live-Hack-CVE/CVE-2023-24322](https://github.com/Live-Hack-CVE/CVE-2023-24322) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24322.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24322.svg)

## CVE-2023-24276
 TOTOlink A7100RU(V7.4cu.2313_B20191024) was discovered to contain a command injection vulnerability via the country parameter at setting/delStaticDhcpRules.



- [https://github.com/Live-Hack-CVE/CVE-2023-24276](https://github.com/Live-Hack-CVE/CVE-2023-24276) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24276.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24276.svg)

## CVE-2023-24241
 Forget Heart Message Box v1.1 was discovered to contain a SQL injection vulnerability via the name parameter at /admin/loginpost.php.



- [https://github.com/Live-Hack-CVE/CVE-2023-24241](https://github.com/Live-Hack-CVE/CVE-2023-24241) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24241.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24241.svg)

## CVE-2023-24202
 Raffle Draw System v1.0 was discovered to contain a local file inclusion vulnerability via the page parameter in index.php.



- [https://github.com/Live-Hack-CVE/CVE-2023-24202](https://github.com/Live-Hack-CVE/CVE-2023-24202) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24202.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24202.svg)

## CVE-2023-24201
 Raffle Draw System v1.0 was discovered to contain a SQL injection vulnerability via the id parameter at get_ticket.php.



- [https://github.com/Live-Hack-CVE/CVE-2023-24201](https://github.com/Live-Hack-CVE/CVE-2023-24201) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24201.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24201.svg)

## CVE-2023-24200
 Raffle Draw System v1.0 was discovered to contain a SQL injection vulnerability via the id parameter at save_ticket.php.



- [https://github.com/Live-Hack-CVE/CVE-2023-24200](https://github.com/Live-Hack-CVE/CVE-2023-24200) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24200.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24200.svg)

## CVE-2023-24199
 Raffle Draw System v1.0 was discovered to contain a SQL injection vulnerability via the id parameter at delete_ticket.php.



- [https://github.com/Live-Hack-CVE/CVE-2023-24199](https://github.com/Live-Hack-CVE/CVE-2023-24199) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24199.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24199.svg)

## CVE-2023-24198
 Raffle Draw System v1.0 was discovered to contain multiple SQL injection vulnerabilities at save_winner.php via the ticket_id and draw parameters.



- [https://github.com/Live-Hack-CVE/CVE-2023-24198](https://github.com/Live-Hack-CVE/CVE-2023-24198) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24198.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24198.svg)

## CVE-2023-24197
 Online Food Ordering System v2 was discovered to contain a SQL injection vulnerability via the id parameter at view_order.php.



- [https://github.com/Live-Hack-CVE/CVE-2023-24197](https://github.com/Live-Hack-CVE/CVE-2023-24197) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24197.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24197.svg)

## CVE-2023-24195
 Online Food Ordering System v2 was discovered to contain a cross-site scripting (XSS) vulnerability via the page parameter in index.php.



- [https://github.com/Live-Hack-CVE/CVE-2023-24195](https://github.com/Live-Hack-CVE/CVE-2023-24195) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24195.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24195.svg)

## CVE-2023-24194
 Online Food Ordering System v2 was discovered to contain a cross-site scripting (XSS) vulnerability via the page parameter in navbar.php.



- [https://github.com/Live-Hack-CVE/CVE-2023-24194](https://github.com/Live-Hack-CVE/CVE-2023-24194) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24194.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24194.svg)

## CVE-2023-24192
 Online Food Ordering System v2 was discovered to contain a cross-site scripting (XSS) vulnerability via the redirect parameter in login.php.



- [https://github.com/Live-Hack-CVE/CVE-2023-24192](https://github.com/Live-Hack-CVE/CVE-2023-24192) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24192.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24192.svg)

## CVE-2023-24191
 Online Food Ordering System v2 was discovered to contain a cross-site scripting (XSS) vulnerability via the redirect parameter in signup.php.



- [https://github.com/Live-Hack-CVE/CVE-2023-24191](https://github.com/Live-Hack-CVE/CVE-2023-24191) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24191.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24191.svg)

## CVE-2023-24170
 Tenda AC18 V15.03.05.19 is vulnerable to Buffer Overflow via /goform/fromSetWirelessRepeat.



- [https://github.com/Live-Hack-CVE/CVE-2023-24170](https://github.com/Live-Hack-CVE/CVE-2023-24170) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24170.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24170.svg)

## CVE-2023-24169
 Tenda AC18 V15.03.05.19 is vulnerable to Buffer Overflow via /goform/FUN_0007343c.



- [https://github.com/Live-Hack-CVE/CVE-2023-24169](https://github.com/Live-Hack-CVE/CVE-2023-24169) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24169.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24169.svg)

## CVE-2023-24167
 Tenda AC18 V15.03.05.19 is vulnerable to Buffer Overflow via /goform/add_white_node.



- [https://github.com/Live-Hack-CVE/CVE-2023-24167](https://github.com/Live-Hack-CVE/CVE-2023-24167) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24167.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24167.svg)

## CVE-2023-24166
 Tenda AC18 V15.03.05.19 is vulnerable to Buffer Overflow via /goform/formWifiBasicSet.



- [https://github.com/Live-Hack-CVE/CVE-2023-24166](https://github.com/Live-Hack-CVE/CVE-2023-24166) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24166.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24166.svg)

## CVE-2023-24165
 Tenda AC18 V15.03.05.19 is vulnerable to Buffer Overflow via /goform/initIpAddrInfo.



- [https://github.com/Live-Hack-CVE/CVE-2023-24165](https://github.com/Live-Hack-CVE/CVE-2023-24165) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24165.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24165.svg)

## CVE-2023-24164
 Tenda AC18 V15.03.05.19 is vulnerable to Buffer Overflow via /goform/FUN_000c2318.



- [https://github.com/Live-Hack-CVE/CVE-2023-24164](https://github.com/Live-Hack-CVE/CVE-2023-24164) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24164.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24164.svg)

## CVE-2023-24163
 SQL Inection vulnerability in Dromara hutool v5.8.11 allows attacker to execute arbitrary code via the aviator template engine.



- [https://github.com/Live-Hack-CVE/CVE-2023-24163](https://github.com/Live-Hack-CVE/CVE-2023-24163) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24163.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24163.svg)

## CVE-2023-24162
 Deserialization vulnerability in Dromara Hutool v5.8.11 allows attacker to execute arbitrary code via the XmlUtil.readObjectFromXml parameter.



- [https://github.com/Live-Hack-CVE/CVE-2023-24162](https://github.com/Live-Hack-CVE/CVE-2023-24162) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24162.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24162.svg)

## CVE-2023-24138
 TOTOLINK CA300-PoE V6.2c.884 was discovered to contain a command injection vulnerability via the host_time parameter in the NTPSyncWithHost function.



- [https://github.com/Live-Hack-CVE/CVE-2023-24138](https://github.com/Live-Hack-CVE/CVE-2023-24138) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24138.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24138.svg)

## CVE-2023-24070
 app/View/AuthKeys/authkey_display.ctp in MISP through 2.4.167 has an XSS in authkey add via a Referer field.



- [https://github.com/Live-Hack-CVE/CVE-2023-24070](https://github.com/Live-Hack-CVE/CVE-2023-24070) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24070.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24070.svg)

## CVE-2023-24069
 ** DISPUTED ** Signal Desktop before 6.2.0 on Windows, Linux, and macOS allows an attacker to obtain potentially sensitive attachments sent in messages from the attachments.noindex directory. Cached attachments are not effectively cleared. In some cases, even after a self-initiated file deletion, an attacker can still recover the file if it was previously replied to in a conversation. (Local filesystem access is needed by the attacker.) NOTE: the vendor disputes the relevance of this finding because the product is not intended to protect against adversaries with this degree of local access.



- [https://github.com/Live-Hack-CVE/CVE-2023-24069](https://github.com/Live-Hack-CVE/CVE-2023-24069) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24069.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24069.svg)

## CVE-2023-24068
 ** DISPUTED ** Signal Desktop before 6.2.0 on Windows, Linux, and macOS allows an attacker to modify conversation attachments within the attachments.noindex directory. Client mechanisms fail to validate modifications of existing cached files, resulting in an attacker's ability to insert malicious code into pre-existing attachments or replace them completely. A threat actor can forward the existing attachment in the corresponding conversation to external groups, and the name and size of the file will not change, allowing the malware to masquerade as another file. NOTE: the vendor disputes the relevance of this finding because the product is not intended to protect against adversaries with this degree of local access.



- [https://github.com/Live-Hack-CVE/CVE-2023-24068](https://github.com/Live-Hack-CVE/CVE-2023-24068) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24068.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24068.svg)

## CVE-2023-24065
 NOSH 4a5cfdb allows stored XSS via the create user page. For example, a first name (of a physician, assistant, or billing user) can have a JavaScript payload that is executed upon visiting the /users/2/1 page. This may allow attackers to steal Protected Health Information because the product is for health charting.



- [https://github.com/Live-Hack-CVE/CVE-2023-24065](https://github.com/Live-Hack-CVE/CVE-2023-24065) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24065.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24065.svg)

## CVE-2023-24060
 Haven 5d15944 allows Server-Side Request Forgery (SSRF) via the feed[url]= Feeds functionality. Authenticated users with the ability to create new RSS Feeds or add RSS Feeds can supply an arbitrary hostname (or even the hostname of the Haven server itself). NOTE: this product has significant usage but does not have numbered releases; ordinary end users may typically use the master branch.



- [https://github.com/Live-Hack-CVE/CVE-2023-24060](https://github.com/Live-Hack-CVE/CVE-2023-24060) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24060.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24060.svg)

## CVE-2023-24059
 Grand Theft Auto V for PC allows attackers to achieve partial remote code execution or modify files on a PC, as exploited in the wild in January 2023.



- [https://github.com/Live-Hack-CVE/CVE-2023-24059](https://github.com/Live-Hack-CVE/CVE-2023-24059) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24059.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24059.svg)

## CVE-2023-24058
 Booked Scheduler 2.5.5 allows authenticated users to create and schedule events for any other user via a modified userId value to reservation_save.php. NOTE: 2.5.5 is a version from 2014; the latest version of Booked Scheduler is not affected. However, LabArchives Scheduler (Sep 6, 2022 Feature Release) is affected.



- [https://github.com/Live-Hack-CVE/CVE-2023-24058](https://github.com/Live-Hack-CVE/CVE-2023-24058) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24058.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24058.svg)

## CVE-2023-24057
 HL7 (Health Level 7) FHIR Core Libraries before 5.6.92 allow attackers to extract files into arbitrary directories via directory traversal from a crafted ZIP or TGZ archive (for a prepackaged terminology cache, NPM package, or comparison archive).



- [https://github.com/Live-Hack-CVE/CVE-2023-24057](https://github.com/Live-Hack-CVE/CVE-2023-24057) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24057.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24057.svg)

## CVE-2023-24056
 In pkgconf through 1.9.3, variable duplication can cause unbounded string expansion due to incorrect checks in libpkgconf/tuple.c:pkgconf_tuple_parse. For example, a .pc file containing a few hundred bytes can expand to one billion bytes.



- [https://github.com/Live-Hack-CVE/CVE-2023-24056](https://github.com/Live-Hack-CVE/CVE-2023-24056) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24056.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24056.svg)

## CVE-2023-24055
 ** DISPUTED ** KeePass through 2.53 (in a default installation) allows an attacker, who has write access to the XML configuration file, to obtain the cleartext passwords by adding an export trigger. NOTE: the vendor's position is that the password database is not intended to be secure against an attacker who has that level of access to the local PC.



- [https://github.com/alt3kx/CVE-2023-24055_PoC](https://github.com/alt3kx/CVE-2023-24055_PoC) :  ![starts](https://img.shields.io/github/stars/alt3kx/CVE-2023-24055_PoC.svg) ![forks](https://img.shields.io/github/forks/alt3kx/CVE-2023-24055_PoC.svg)

- [https://github.com/deetl/CVE-2023-24055](https://github.com/deetl/CVE-2023-24055) :  ![starts](https://img.shields.io/github/stars/deetl/CVE-2023-24055.svg) ![forks](https://img.shields.io/github/forks/deetl/CVE-2023-24055.svg)

- [https://github.com/ATTACKnDEFEND/CVE-2023-24055](https://github.com/ATTACKnDEFEND/CVE-2023-24055) :  ![starts](https://img.shields.io/github/stars/ATTACKnDEFEND/CVE-2023-24055.svg) ![forks](https://img.shields.io/github/forks/ATTACKnDEFEND/CVE-2023-24055.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-24055](https://github.com/Live-Hack-CVE/CVE-2023-24055) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24055.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24055.svg)

- [https://github.com/julesbozouklian/PoC_CVE-2023-24055](https://github.com/julesbozouklian/PoC_CVE-2023-24055) :  ![starts](https://img.shields.io/github/stars/julesbozouklian/PoC_CVE-2023-24055.svg) ![forks](https://img.shields.io/github/forks/julesbozouklian/PoC_CVE-2023-24055.svg)

- [https://github.com/Cyb3rtus/keepass_CVE-2023-24055_yara_rule](https://github.com/Cyb3rtus/keepass_CVE-2023-24055_yara_rule) :  ![starts](https://img.shields.io/github/stars/Cyb3rtus/keepass_CVE-2023-24055_yara_rule.svg) ![forks](https://img.shields.io/github/forks/Cyb3rtus/keepass_CVE-2023-24055_yara_rule.svg)

- [https://github.com/digital-dev/KeePass-TriggerLess](https://github.com/digital-dev/KeePass-TriggerLess) :  ![starts](https://img.shields.io/github/stars/digital-dev/KeePass-TriggerLess.svg) ![forks](https://img.shields.io/github/forks/digital-dev/KeePass-TriggerLess.svg)

## CVE-2023-24044
 A Host Header Injection issue on the Login page of Plesk Obsidian through 18.0.49 allows attackers to redirect users to malicious websites via a Host request header.



- [https://github.com/Live-Hack-CVE/CVE-2023-24044](https://github.com/Live-Hack-CVE/CVE-2023-24044) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24044.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24044.svg)

## CVE-2023-24042
 A race condition in LightFTP through 2.2 allows an attacker to achieve path traversal via a malformed FTP request. A handler thread can use an overwritten context-&gt;FileName.



- [https://github.com/Live-Hack-CVE/CVE-2023-24042](https://github.com/Live-Hack-CVE/CVE-2023-24042) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24042.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24042.svg)

## CVE-2023-24040
 ** UNSUPPORTED WHEN ASSIGNED ** dtprintinfo in Common Desktop Environment 1.6 has a bug in the parser of lpstat (an invoked external command) during listing of the names of available printers. This allows low-privileged local users to inject arbitrary printer names via the $HOME/.printers file. This injection allows those users to manipulate the control flow and disclose memory contents on Solaris 10 systems. NOTE: This vulnerability only affects products that are no longer supported by the maintainer.



- [https://github.com/Live-Hack-CVE/CVE-2023-24040](https://github.com/Live-Hack-CVE/CVE-2023-24040) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24040.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24040.svg)

## CVE-2023-24039
 ** UNSUPPORTED WHEN ASSIGNED ** A stack-based buffer overflow in ParseColors in libXm in Common Desktop Environment 1.6 can be exploited by local low-privileged users via the dtprintinfo setuid binary to escalate their privileges to root on Solaris 10 systems. NOTE: This vulnerability only affects products that are no longer supported by the maintainer.



- [https://github.com/Live-Hack-CVE/CVE-2023-24039](https://github.com/Live-Hack-CVE/CVE-2023-24039) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24039.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24039.svg)

## CVE-2023-24038
 The HTML-StripScripts module through 1.06 for Perl allows _hss_attval_style ReDoS because of catastrophic backtracking for HTML content with certain style attributes.



- [https://github.com/Live-Hack-CVE/CVE-2023-24038](https://github.com/Live-Hack-CVE/CVE-2023-24038) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24038.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24038.svg)

## CVE-2023-24028
 In MISP 2.4.167, app/Controller/Component/ACLComponent.php has incorrect access control for the decaying import function.



- [https://github.com/Live-Hack-CVE/CVE-2023-24028](https://github.com/Live-Hack-CVE/CVE-2023-24028) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24028.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24028.svg)

## CVE-2023-24027
 In MISP 2.4.167, app/webroot/js/action_table.js allows XSS via a network history name.



- [https://github.com/Live-Hack-CVE/CVE-2023-24027](https://github.com/Live-Hack-CVE/CVE-2023-24027) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24027.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24027.svg)

## CVE-2023-24026
 In MISP 2.4.167, app/webroot/js/event-graph.js has an XSS vulnerability via an event-graph preview payload.



- [https://github.com/Live-Hack-CVE/CVE-2023-24026](https://github.com/Live-Hack-CVE/CVE-2023-24026) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24026.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24026.svg)

## CVE-2023-24025
 CRYSTALS-DILITHIUM (in Post-Quantum Cryptography Selected Algorithms 2022) in PQClean d03da30 may allow universal forgeries of digital signatures via a template side-channel attack because of intermediate data leakage of one vector.



- [https://github.com/Live-Hack-CVE/CVE-2023-24025](https://github.com/Live-Hack-CVE/CVE-2023-24025) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24025.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24025.svg)

## CVE-2023-24022
 Baicells Nova 227, Nova 233, and Nova 243 LTE TDD eNodeB devices with firmware through RTS/RTD 3.7.11.3 have hardcoded credentials that are easily discovered and can be used by remote attackers to authenticate via ssh. (The credentials are stored in the firmware, encrypted by the crypt function.)



- [https://github.com/Live-Hack-CVE/CVE-2023-24022](https://github.com/Live-Hack-CVE/CVE-2023-24022) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24022.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24022.svg)

## CVE-2023-24021
 Incorrect handling of '\0' bytes in file uploads in ModSecurity before 2.9.7 may allow for Web Application Firewall bypasses and buffer over-reads on the Web Application Firewall when executing rules that read the FILES_TMP_CONTENT collection.



- [https://github.com/Live-Hack-CVE/CVE-2023-24021](https://github.com/Live-Hack-CVE/CVE-2023-24021) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24021.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24021.svg)

## CVE-2023-24020
 Snap One Wattbox WB-300-IP-3 versions WB10.9a17 and prior could bypass the brute force protection, allowing multiple attempts to force a login.



- [https://github.com/Live-Hack-CVE/CVE-2023-24020](https://github.com/Live-Hack-CVE/CVE-2023-24020) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24020.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24020.svg)

## CVE-2023-23969
 In Django 3.2 before 3.2.17, 4.0 before 4.0.9, and 4.1 before 4.1.6, the parsed values of Accept-Language headers are cached in order to avoid repetitive parsing. This leads to a potential denial-of-service vector via excessive memory usage if the raw value of Accept-Language headers is very large.



- [https://github.com/Live-Hack-CVE/CVE-2023-23969](https://github.com/Live-Hack-CVE/CVE-2023-23969) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23969.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23969.svg)

## CVE-2023-23924
 Dompdf is an HTML to PDF converter. The URI validation on dompdf 2.0.1 can be bypassed on SVG parsing by passing `&lt;image&gt;` tags with uppercase letters. This may lead to arbitrary object unserialize on PHP &lt; 8, through the `phar` URL wrapper. An attacker can exploit the vulnerability to call arbitrary URL with arbitrary protocols, if they can provide a SVG file to dompdf. In PHP versions before 8.0.0, it leads to arbitrary unserialize, that will lead to the very least to an arbitrary file deletion and even remote code execution, depending on classes that are available.



- [https://github.com/motikan2010/CVE-2023-23924](https://github.com/motikan2010/CVE-2023-23924) :  ![starts](https://img.shields.io/github/stars/motikan2010/CVE-2023-23924.svg) ![forks](https://img.shields.io/github/forks/motikan2010/CVE-2023-23924.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-23924](https://github.com/Live-Hack-CVE/CVE-2023-23924) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23924.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23924.svg)

## CVE-2023-23912
 A vulnerability, found in EdgeRouters Version 2.0.9-hotfix.5 and earlier and UniFi Security Gateways (USG) Version 4.4.56 and earlier with their DHCPv6 prefix delegation set to dhcpv6-stateless or dhcpv6-stateful, allows a malicious actor directly connected to the WAN interface of an affected device to create a remote code execution vulnerability.



- [https://github.com/Live-Hack-CVE/CVE-2023-23912](https://github.com/Live-Hack-CVE/CVE-2023-23912) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23912.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23912.svg)

## CVE-2023-23849
 Versions of Coverity Connect prior to 2022.12.0 are vulnerable to an unauthenticated Cross-Site Scripting vulnerability. Any web service hosted on the same sub domain can set a cookie for the whole subdomain which can be used to bypass other mitigations in place for malicious purposes. CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H/RL:O/RC:C



- [https://github.com/Live-Hack-CVE/CVE-2023-23849](https://github.com/Live-Hack-CVE/CVE-2023-23849) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23849.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23849.svg)

## CVE-2023-23846
 Due to insufficient length validation in the Open5GS GTP library versions prior to versions 2.4.13 and 2.5.7, when parsing extension headers in GPRS tunneling protocol (GPTv1-U) messages, a protocol payload with any extension header length set to zero causes an infinite loop. The affected process becomes immediately unresponsive, resulting in denial of service and excessive resource consumption. CVSS3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H/E:P/RL:O/RC:C



- [https://github.com/Live-Hack-CVE/CVE-2023-23846](https://github.com/Live-Hack-CVE/CVE-2023-23846) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23846.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23846.svg)

## CVE-2023-23751
 An issue was discovered in Joomla! 4.0.0 through 4.2.4. A missing ACL check allows non super-admin users to access com_actionlogs.



- [https://github.com/Live-Hack-CVE/CVE-2023-23751](https://github.com/Live-Hack-CVE/CVE-2023-23751) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23751.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23751.svg)

## CVE-2023-23750
 An issue was discovered in Joomla! 4.0.0 through 4.2.6. A missing token check causes a CSRF vulnerability in the handling of post-installation messages.



- [https://github.com/Live-Hack-CVE/CVE-2023-23750](https://github.com/Live-Hack-CVE/CVE-2023-23750) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23750.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23750.svg)

## CVE-2023-23749
 The 'LDAP Integration with Active Directory and OpenLDAP - NTLM &amp; Kerberos Login' extension is vulnerable to LDAP Injection since is not properly sanitizing the 'username' POST parameter. An attacker can manipulate this paramter to dump arbitrary contents form the LDAP Database.



- [https://github.com/Live-Hack-CVE/CVE-2023-23749](https://github.com/Live-Hack-CVE/CVE-2023-23749) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23749.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23749.svg)

## CVE-2023-23696
 Dell Command Intel vPro Out of Band, versions prior to 4.3.1, contain an Improper Authorization vulnerability. A locally authenticated malicious users could potentially exploit this vulnerability in order to write arbitrary files to the system.



- [https://github.com/Live-Hack-CVE/CVE-2023-23696](https://github.com/Live-Hack-CVE/CVE-2023-23696) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23696.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23696.svg)

## CVE-2023-23692
 Dell EMC prior to version DDOS 7.9 contain(s) an OS command injection Vulnerability. An authenticated non admin attacker could potentially exploit this vulnerability, leading to the execution of arbitrary OS commands on the application's underlying OS, with the privileges of the vulnerable application.



- [https://github.com/Live-Hack-CVE/CVE-2023-23692](https://github.com/Live-Hack-CVE/CVE-2023-23692) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23692.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23692.svg)

## CVE-2023-23691
 Dell EMC PV ME5, versions ME5.1.0.0.0 and ME5.1.0.1.0, contains a Client-side desync Vulnerability. An unauthenticated attacker could potentially exploit this vulnerability to force a victim's browser to desynchronize its connection with the website, typically leading to XSS and DoS.



- [https://github.com/Live-Hack-CVE/CVE-2023-23691](https://github.com/Live-Hack-CVE/CVE-2023-23691) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23691.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23691.svg)

## CVE-2023-23690
 Cloud Mobility for Dell EMC Storage, versions 1.3.0.X and below contains an Improper Check for Certificate Revocation vulnerability. A threat actor does not need any specific privileges to potentially exploit this vulnerability. An attacker could perform a man-in-the-middle attack and eavesdrop on encrypted communications from Cloud Mobility to Cloud Storage devices. Exploitation could lead to the compromise of secret and sensitive information, cloud storage connection downtime, and the integrity of the connection to the Cloud devices.



- [https://github.com/Live-Hack-CVE/CVE-2023-23690](https://github.com/Live-Hack-CVE/CVE-2023-23690) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23690.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23690.svg)

## CVE-2023-23636
 In Jellyfin 10.8.x through 10.8.3, the name of a playlist is vulnerable to stored XSS. This allows an attacker to steal access tokens from the localStorage of the victim.



- [https://github.com/Live-Hack-CVE/CVE-2023-23636](https://github.com/Live-Hack-CVE/CVE-2023-23636) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23636.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23636.svg)

## CVE-2023-23627
 Sanitize is an allowlist-based HTML and CSS sanitizer. Versions 5.0.0 and later, prior to 6.0.1, are vulnerable to Cross-site Scripting. When Sanitize is configured with a custom allowlist that allows `noscript` elements, attackers are able to include arbitrary HTML, resulting in XSS (cross-site scripting) or other undesired behavior when that HTML is rendered in a browser. The default configurations do not allow `noscript` elements and are not vulnerable. This issue only affects users who are using a custom config that adds `noscript` to the element allowlist. This issue has been patched in version 6.0.1. Users who are unable to upgrade can prevent this issue by using one of Sanitize's default configs or by ensuring that their custom config does not include `noscript` in the element allowlist.



- [https://github.com/Live-Hack-CVE/CVE-2023-23627](https://github.com/Live-Hack-CVE/CVE-2023-23627) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23627.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23627.svg)

## CVE-2023-23624
 Discourse is an open-source discussion platform. Prior to version 3.0.1 on the `stable` branch and version 3.1.0.beta2 on the `beta` and `tests-passed` branches, someone can use the `exclude_tag param` to filter out topics and deduce which ones were using a specific hidden tag. This affects any Discourse site using hidden tags in public categories. This issue is patched in version 3.0.1 on the `stable` branch and version 3.1.0.beta2 on the `beta` and `tests-passed` branches. As a workaround, secure any categories that are using hidden tags, change any existing hidden tags to not include private data, or remove any hidden tags currently in use.



- [https://github.com/Live-Hack-CVE/CVE-2023-23624](https://github.com/Live-Hack-CVE/CVE-2023-23624) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23624.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23624.svg)

## CVE-2023-23621
 Discourse is an open-source discussion platform. Prior to version 3.0.1 on the `stable` branch and version 3.1.0.beta2 on the `beta` and `tests-passed` branches, a malicious user can cause a regular expression denial of service using a carefully crafted user agent. This issue is patched in version 3.0.1 on the `stable` branch and version 3.1.0.beta2 on the `beta` and `tests-passed` branches. There are no known workarounds.



- [https://github.com/Live-Hack-CVE/CVE-2023-23621](https://github.com/Live-Hack-CVE/CVE-2023-23621) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23621.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23621.svg)

## CVE-2023-23620
 Discourse is an open-source discussion platform. Prior to version 3.0.1 on the `stable` branch and 3.1.0.beta2 on the `beta` and `tests-passed` branches, the contents of latest/top routes for restricted tags can be accessed by unauthorized users. This issue is patched in version 3.0.1 on the `stable` branch and 3.1.0.beta2 on the `beta` and `tests-passed` branches. There are no known workarounds.



- [https://github.com/Live-Hack-CVE/CVE-2023-23620](https://github.com/Live-Hack-CVE/CVE-2023-23620) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23620.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23620.svg)

## CVE-2023-23617
 OpenMage LTS is an e-commerce platform. Versions prior to 19.4.22 and 20.0.19 contain an infinite loop in malicious code filter in certain conditions. Versions 19.4.22 and 20.0.19 have a fix for this issue. There are no known workarounds.



- [https://github.com/Live-Hack-CVE/CVE-2023-23617](https://github.com/Live-Hack-CVE/CVE-2023-23617) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23617.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23617.svg)

## CVE-2023-23616
 Discourse is an open-source discussion platform. Prior to version 3.0.1 on the `stable` branch and 3.1.0.beta2 on the `beta` and `tests-passed` branches, when submitting a membership request, there is no character limit for the reason provided with the request. This could potentially allow a user to flood the database with a large amount of data. However it is unlikely this could be used as part of a DoS attack, as the paths reading back the reasons are only available to administrators. Starting in version 3.0.1 on the `stable` branch and 3.1.0.beta2 on the `beta` and `tests-passed` branches, a limit of 280 characters has been introduced for membership requests.



- [https://github.com/Live-Hack-CVE/CVE-2023-23616](https://github.com/Live-Hack-CVE/CVE-2023-23616) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23616.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23616.svg)

## CVE-2023-23615
 Discourse is an open source discussion platform. The embeddable comments can be exploited to create new topics as any user but without any clear title or content. This issue is patched in the latest stable, beta and tests-passed versions of Discourse. As a workaround, disable embeddable comments by deleting all embeddable hosts.



- [https://github.com/Live-Hack-CVE/CVE-2023-23615](https://github.com/Live-Hack-CVE/CVE-2023-23615) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23615.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23615.svg)

## CVE-2023-23614
 Pi-hole's Web interface (based off of AdminLTE) provides a central location to manage your Pi-hole. Versions 4.0 and above, prior to 5.18.3 are vulnerable to Insufficient Session Expiration. Improper use of admin WEBPASSWORD hash as &quot;Remember me for 7 days&quot; cookie value makes it possible for an attacker to &quot;pass the hash&quot; to login or reuse a theoretically expired &quot;remember me&quot; cookie. It also exposes the hash over the network and stores it unnecessarily in the browser. The cookie itself is set to expire after 7 days but its value will remain valid as long as the admin password doesn't change. If a cookie is leaked or compromised it could be used forever as long as the admin password is not changed. An attacker that obtained the password hash via an other attack vector (for example a path traversal vulnerability) could use it to login as the admin by setting the hash as the cookie value without the need to crack it to obtain the admin password (pass the hash). The hash is exposed over the network and in the browser where the cookie is transmitted and stored. This issue is patched in version 5.18.3.



- [https://github.com/Live-Hack-CVE/CVE-2023-23614](https://github.com/Live-Hack-CVE/CVE-2023-23614) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23614.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23614.svg)

## CVE-2023-23609
 Contiki-NG is an open-source, cross-platform operating system for Next-Generation IoT devices. Versions prior to and including 4.8 are vulnerable to an out-of-bounds write that can occur in the BLE-L2CAP module. The Bluetooth Low Energy - Logical Link Control and Adaptation Layer Protocol (BLE-L2CAP) module handles fragmentation of packets up the configured MTU size. When fragments are reassembled, they are stored in a packet buffer of a configurable size, but there is no check to verify that the packet buffer is large enough to hold the reassembled packet. In Contiki-NG's default configuration, it is possible that an out-of-bounds write of up to 1152 bytes occurs. The vulnerability has been patched in the &quot;develop&quot; branch of Contiki-NG, and will be included in release 4.9. The problem can be fixed by applying the patch in Contiki-NG pull request #2254 prior to the release of version 4.9.



- [https://github.com/Live-Hack-CVE/CVE-2023-23609](https://github.com/Live-Hack-CVE/CVE-2023-23609) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23609.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23609.svg)

## CVE-2023-23607
 erohtar/Dasherr is a dashboard for self-hosted services. In affected versions unrestricted file upload allows any unauthenticated user to execute arbitrary code on the server. The file /www/include/filesave.php allows for any file to uploaded to anywhere. If an attacker uploads a php file they can execute code on the server. This issue has been addressed in version 1.05.00. Users are advised to upgrade. There are no known workarounds for this issue.



- [https://github.com/Live-Hack-CVE/CVE-2023-23607](https://github.com/Live-Hack-CVE/CVE-2023-23607) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23607.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23607.svg)

## CVE-2023-23596
 jc21 NGINX Proxy Manager through 2.9.19 allows OS command injection. When creating an access list, the backend builds an htpasswd file with crafted username and/or password input that is concatenated without any validation, and is directly passed to the exec command, potentially allowing an authenticated attacker to execute arbitrary commands on the system. NOTE: this is not part of any NGINX software shipped by F5.



- [https://github.com/Live-Hack-CVE/CVE-2023-23596](https://github.com/Live-Hack-CVE/CVE-2023-23596) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23596.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23596.svg)

## CVE-2023-23595
 BlueCat Device Registration Portal 2.2 allows XXE attacks that exfiltrate single-line files. A single-line file might contain credentials, such as &quot;machine example.com login daniel password qwerty&quot; in the documentation example for the .netrc file format. NOTE: 2.x versions are no longer supported. There is no available information about whether any later version is affected.



- [https://github.com/Live-Hack-CVE/CVE-2023-23595](https://github.com/Live-Hack-CVE/CVE-2023-23595) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23595.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23595.svg)

## CVE-2023-23590
 Mercedes-Benz XENTRY Retail Data Storage 7.8.1 allows remote attackers to cause a denial of service (device restart) via an unauthenticated API request. The attacker must be on the same network as the device.



- [https://github.com/Live-Hack-CVE/CVE-2023-23590](https://github.com/Live-Hack-CVE/CVE-2023-23590) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23590.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23590.svg)

## CVE-2023-23589
 The SafeSocks option in Tor before 0.4.7.13 has a logic error in which the unsafe SOCKS4 protocol can be used but not the safe SOCKS4a protocol, aka TROVE-2022-002.



- [https://github.com/Live-Hack-CVE/CVE-2023-23589](https://github.com/Live-Hack-CVE/CVE-2023-23589) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23589.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23589.svg)

## CVE-2023-23582
 Snap One Wattbox WB-300-IP-3 versions WB10.9a17 and prior are vulnerable to a heap-based buffer overflow, which could allow an attacker to execute arbitrary code or crash the device remotely.



- [https://github.com/Live-Hack-CVE/CVE-2023-23582](https://github.com/Live-Hack-CVE/CVE-2023-23582) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23582.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23582.svg)

## CVE-2023-23560
 In certain Lexmark products through 2023-01-12, SSRF can occur because of a lack of input validation.



- [https://github.com/Live-Hack-CVE/CVE-2023-23560](https://github.com/Live-Hack-CVE/CVE-2023-23560) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23560.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23560.svg)

## CVE-2023-23559
 In rndis_query_oid in drivers/net/wireless/rndis_wlan.c in the Linux kernel through 6.1.5, there is an integer overflow in an addition.



- [https://github.com/Live-Hack-CVE/CVE-2023-23559](https://github.com/Live-Hack-CVE/CVE-2023-23559) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23559.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23559.svg)

## CVE-2023-23492
 The Login with Phone Number WordPress Plugin, version &lt; 1.4.2, is affected by an authenticated SQL injection vulnerability in the 'ID' parameter of its 'lwp_forgot_password' action.



- [https://github.com/Live-Hack-CVE/CVE-2023-23492](https://github.com/Live-Hack-CVE/CVE-2023-23492) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23492.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23492.svg)

## CVE-2023-23489
 The Easy Digital Downloads WordPress Plugin, version &lt; 3.1.0.4, is affected by an unauthenticated SQL injection vulnerability in the 's' parameter of its 'edd_download_search' action.



- [https://github.com/Live-Hack-CVE/CVE-2023-23489](https://github.com/Live-Hack-CVE/CVE-2023-23489) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23489.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23489.svg)

## CVE-2023-23488
 The Paid Memberships Pro WordPress Plugin, version &lt; 2.9.8, is affected by an unauthenticated SQL injection vulnerability in the 'code' parameter of the '/pmpro/v1/order' REST route.



- [https://github.com/r3nt0n/CVE-2023-23488-PoC](https://github.com/r3nt0n/CVE-2023-23488-PoC) :  ![starts](https://img.shields.io/github/stars/r3nt0n/CVE-2023-23488-PoC.svg) ![forks](https://img.shields.io/github/forks/r3nt0n/CVE-2023-23488-PoC.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-23488](https://github.com/Live-Hack-CVE/CVE-2023-23488) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23488.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23488.svg)

## CVE-2023-23475
 IBM Infosphere Information Server 11.7 is vulnerable to cross-site scripting. This vulnerability allows users to embed arbitrary JavaScript code in the Web UI thus altering the intended functionality potentially leading to credentials disclosure within a trusted session. IBM X-Force ID: 245423.



- [https://github.com/Live-Hack-CVE/CVE-2023-23475](https://github.com/Live-Hack-CVE/CVE-2023-23475) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23475.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23475.svg)

## CVE-2023-23469
 IBM ICP4A - Automation Decision Services 18.0.0, 18.0.1, 18.0.2, 19.0.1, 19.0.2, 19.0.3, 20.0.1, 20.0.2, 20.0.3, 21.0.1, 21.0.2, 21.0.3, 22.0.1, and 22.0.2 allows web pages to be stored locally which can be read by another user on the system. IBM X-Force ID: 244504.



- [https://github.com/Live-Hack-CVE/CVE-2023-23469](https://github.com/Live-Hack-CVE/CVE-2023-23469) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23469.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23469.svg)

## CVE-2023-23457
 A Segmentation fault was found in UPX in PackLinuxElf64::invert_pt_dynamic() in p_lx_elf.cpp. An attacker with a crafted input file allows invalid memory address access that could lead to a denial of service.



- [https://github.com/Live-Hack-CVE/CVE-2023-23457](https://github.com/Live-Hack-CVE/CVE-2023-23457) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23457.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23457.svg)

## CVE-2023-23456
 A heap-based buffer overflow issue was discovered in UPX in PackTmt::pack() in p_tmt.cpp file. The flow allows an attacker to cause a denial of service (abort) via a crafted file.



- [https://github.com/Live-Hack-CVE/CVE-2023-23456](https://github.com/Live-Hack-CVE/CVE-2023-23456) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23456.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23456.svg)

## CVE-2023-23455
 atm_tc_enqueue in net/sched/sch_atm.c in the Linux kernel through 6.1.4 allows attackers to cause a denial of service because of type confusion (non-negative numbers can sometimes indicate a TC_ACT_SHOT condition rather than valid classification results).



- [https://github.com/Live-Hack-CVE/CVE-2023-23455](https://github.com/Live-Hack-CVE/CVE-2023-23455) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23455.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23455.svg)

## CVE-2023-23454
 cbq_classify in net/sched/sch_cbq.c in the Linux kernel through 6.1.4 allows attackers to cause a denial of service (slab-out-of-bounds read) because of type confusion (non-negative numbers can sometimes indicate a TC_ACT_SHOT condition rather than valid classification results).



- [https://github.com/Live-Hack-CVE/CVE-2023-23454](https://github.com/Live-Hack-CVE/CVE-2023-23454) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23454.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23454.svg)

## CVE-2023-23333
 There is a command injection vulnerability in SolarView Compact through 6.00, attackers can execute commands by bypassing internal restrictions through downloader.php.



- [https://github.com/Timorlover/CVE-2023-23333](https://github.com/Timorlover/CVE-2023-23333) :  ![starts](https://img.shields.io/github/stars/Timorlover/CVE-2023-23333.svg) ![forks](https://img.shields.io/github/forks/Timorlover/CVE-2023-23333.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-23333](https://github.com/Live-Hack-CVE/CVE-2023-23333) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23333.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23333.svg)

## CVE-2023-23331
 Amano Xoffice parking solutions 7.1.3879 is vulnerable to SQL Injection.



- [https://github.com/Live-Hack-CVE/CVE-2023-23331](https://github.com/Live-Hack-CVE/CVE-2023-23331) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23331.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23331.svg)

## CVE-2023-23314
 An arbitrary file upload vulnerability in the /api/upload component of zdir v3.2.0 allows attackers to execute arbitrary code via a crafted .ssh file.



- [https://github.com/Live-Hack-CVE/CVE-2023-23314](https://github.com/Live-Hack-CVE/CVE-2023-23314) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23314.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23314.svg)

## CVE-2023-23136
 lmxcms v1.41 was discovered to contain an arbitrary file deletion vulnerability via BackdbAction.class.php.



- [https://github.com/Live-Hack-CVE/CVE-2023-23136](https://github.com/Live-Hack-CVE/CVE-2023-23136) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23136.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23136.svg)

## CVE-2023-23135
 An arbitrary file upload vulnerability in Ftdms v3.1.6 allows attackers to execute arbitrary code via uploading a crafted JPG file.



- [https://github.com/Live-Hack-CVE/CVE-2023-23135](https://github.com/Live-Hack-CVE/CVE-2023-23135) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23135.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23135.svg)

## CVE-2023-23132
 Selfwealth iOS mobile App 3.3.1 is vulnerable to Sensitive key disclosure. The application reveals hardcoded API keys.



- [https://github.com/l00neyhacker/CVE-2023-23132](https://github.com/l00neyhacker/CVE-2023-23132) :  ![starts](https://img.shields.io/github/stars/l00neyhacker/CVE-2023-23132.svg) ![forks](https://img.shields.io/github/forks/l00neyhacker/CVE-2023-23132.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-23132](https://github.com/Live-Hack-CVE/CVE-2023-23132) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23132.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23132.svg)

## CVE-2023-23131
 Selfwealth iOS mobile App 3.3.1 is vulnerable to Insecure App Transport Security (ATS) Settings.



- [https://github.com/l00neyhacker/CVE-2023-23131](https://github.com/l00neyhacker/CVE-2023-23131) :  ![starts](https://img.shields.io/github/stars/l00neyhacker/CVE-2023-23131.svg) ![forks](https://img.shields.io/github/forks/l00neyhacker/CVE-2023-23131.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-23131](https://github.com/Live-Hack-CVE/CVE-2023-23131) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23131.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23131.svg)

## CVE-2023-23130
 ** DISPUTED ** Connectwise Automate 2022.11 is vulnerable to Cleartext authentication. Authentication is being done via HTTP (cleartext) with SSL disabled. OTE: the vendor's position is that, by design, this is controlled by a configuration option in which a customer can choose to use HTTP (rather than HTTPS) during troubleshooting.



- [https://github.com/l00neyhacker/CVE-2023-23130](https://github.com/l00neyhacker/CVE-2023-23130) :  ![starts](https://img.shields.io/github/stars/l00neyhacker/CVE-2023-23130.svg) ![forks](https://img.shields.io/github/forks/l00neyhacker/CVE-2023-23130.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-23130](https://github.com/Live-Hack-CVE/CVE-2023-23130) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23130.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23130.svg)

## CVE-2023-23128
 Connectwise Control 22.8.10013.8329 is vulnerable to Cross Origin Resource Sharing (CORS). The vendor's position is that two endpoints have Access-Control-Allow-Origin wildcarding to support product functionality, and that there is no risk from this behavior. The vulnerability report is thus not valid.



- [https://github.com/l00neyhacker/CVE-2023-23128](https://github.com/l00neyhacker/CVE-2023-23128) :  ![starts](https://img.shields.io/github/stars/l00neyhacker/CVE-2023-23128.svg) ![forks](https://img.shields.io/github/forks/l00neyhacker/CVE-2023-23128.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-23128](https://github.com/Live-Hack-CVE/CVE-2023-23128) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23128.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23128.svg)

## CVE-2023-23127
 In Connectwise Control 22.8.10013.8329, the login page does not implement HSTS headers therefore not enforcing HTTPS. NOTE: the vendor's position is that, by design, this is controlled by a configuration option in which a customer can choose to use HTTP (rather than HTTPS) during troubleshooting.



- [https://github.com/l00neyhacker/CVE-2023-23127](https://github.com/l00neyhacker/CVE-2023-23127) :  ![starts](https://img.shields.io/github/stars/l00neyhacker/CVE-2023-23127.svg) ![forks](https://img.shields.io/github/forks/l00neyhacker/CVE-2023-23127.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-23127](https://github.com/Live-Hack-CVE/CVE-2023-23127) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23127.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23127.svg)

## CVE-2023-23126
 ** DISPUTED ** Connectwise Automate 2022.11 is vulnerable to Clickjacking. The login screen can be iframed and used to manipulate users to perform unintended actions. NOTE: the vendor's position is that a Content-Security-Policy HTTP response header is present to block this attack.



- [https://github.com/l00neyhacker/CVE-2023-23126](https://github.com/l00neyhacker/CVE-2023-23126) :  ![starts](https://img.shields.io/github/stars/l00neyhacker/CVE-2023-23126.svg) ![forks](https://img.shields.io/github/forks/l00neyhacker/CVE-2023-23126.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-23126](https://github.com/Live-Hack-CVE/CVE-2023-23126) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23126.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23126.svg)

## CVE-2023-23120
 The use of the cyclic redundancy check (CRC) algorithm for integrity check during firmware update makes TRENDnet TV-IP651WI Network Camera firmware version v1.07.01 and earlier vulnerable to firmware modification attacks. An attacker can conduct a man-in-the-middle (MITM) attack to modify the new firmware image and bypass the checksum verification.



- [https://github.com/Live-Hack-CVE/CVE-2023-23120](https://github.com/Live-Hack-CVE/CVE-2023-23120) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23120.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23120.svg)

## CVE-2023-23119
 The use of the cyclic redundancy check (CRC) algorithm for integrity check during firmware update makes Ubiquiti airFiber AF2X Radio firmware version 3.2.2 and earlier vulnerable to firmware modification attacks. An attacker can conduct a man-in-the-middle (MITM) attack to modify the new firmware image and bypass the checksum verification.



- [https://github.com/Live-Hack-CVE/CVE-2023-23119](https://github.com/Live-Hack-CVE/CVE-2023-23119) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23119.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23119.svg)

## CVE-2023-23110
 An exploitable firmware modification vulnerability was discovered in certain Netgear products. The data integrity of the uploaded firmware image is ensured with a fixed checksum number. Therefore, an attacker can conduct a MITM attack to modify the user-uploaded firmware image and bypass the checksum verification. This affects WNR612v2 Wireless Routers 1.0.0.3 and earlier, DGN1000v3 Modem Router 1.0.0.22 and earlier, D6100 WiFi DSL Modem Routers 1.0.0.63 and earlier, WNR1000v2 Wireless Routers 1.1.2.60 and earlier, XAVN2001v2 Wireless-N Extenders 0.4.0.7 and earlier, WNR2200 Wireless Routers 1.0.1.102 and earlier, WNR2500 Wireless Routers 1.0.0.34 and earlier, R8900 Smart WiFi Routers 1.0.3.6 and earlier, and R9000 Smart WiFi Routers 1.0.3.6 and earlier.



- [https://github.com/Live-Hack-CVE/CVE-2023-23110](https://github.com/Live-Hack-CVE/CVE-2023-23110) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23110.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23110.svg)

## CVE-2023-23082
 A heap buffer overflow vulnerability in Kodi Home Theater Software up to 19.5 allows attackers to cause a denial of service due to an improper length of the value passed to the offset argument.



- [https://github.com/Live-Hack-CVE/CVE-2023-23082](https://github.com/Live-Hack-CVE/CVE-2023-23082) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23082.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23082.svg)

## CVE-2023-23073
 Cross site scripting (XSS) vulnerability in Zoho ManageEngine ServiceDesk Plus 14 via PO in the purchase component.



- [https://github.com/Live-Hack-CVE/CVE-2023-23073](https://github.com/Live-Hack-CVE/CVE-2023-23073) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23073.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23073.svg)

## CVE-2023-23026
 Cross site scripting (XSS) vulnerability in sourcecodester oretnom23 sales management system 1.0, allows attackers to execute arbitrary code via the product_name and product_price inputs in file print.php.



- [https://github.com/Live-Hack-CVE/CVE-2023-23026](https://github.com/Live-Hack-CVE/CVE-2023-23026) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23026.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23026.svg)

## CVE-2023-23014
 Cross Site Scripting (XSS) vulnerability in InventorySystem thru commit e08fbbe17902146313501ed0b5feba81d58f455c (on Apr 23, 2021) via edit_store_name and edit_active inputs in file InventorySystem.php.



- [https://github.com/Live-Hack-CVE/CVE-2023-23014](https://github.com/Live-Hack-CVE/CVE-2023-23014) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23014.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23014.svg)

## CVE-2023-23012
 Cross Site Scripting (XSS) vulnerability in craigrodway classroombookings 2.6.4 allows attackers to execute arbitrary code or other unspecified impacts via the input bgcol in file Weeks.php.



- [https://github.com/Live-Hack-CVE/CVE-2023-23012](https://github.com/Live-Hack-CVE/CVE-2023-23012) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23012.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23012.svg)

## CVE-2023-23011
 Cross Site Scripting (XSS) vulnerability in InvoicePlane 1.6 via filter_product input to file modal_product_lookups.php.



- [https://github.com/Live-Hack-CVE/CVE-2023-23011](https://github.com/Live-Hack-CVE/CVE-2023-23011) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23011.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23011.svg)

## CVE-2023-23010
 Cross Site Scripting (XSS) vulnerability in Ecommerce-CodeIgniter-Bootstrap thru commit d5904379ca55014c5df34c67deda982c73dc7fe5 (on Dec 27, 2022), allows attackers to execute arbitrary code via the languages and trans_load parameters in file add_product.php.



- [https://github.com/Live-Hack-CVE/CVE-2023-23010](https://github.com/Live-Hack-CVE/CVE-2023-23010) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23010.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23010.svg)

## CVE-2023-22963
 The personnummer implementation before 3.0.3 for Dart mishandles numbers in which the last four digits match the ^000[0-9]$ regular expression.



- [https://github.com/Live-Hack-CVE/CVE-2023-22963](https://github.com/Live-Hack-CVE/CVE-2023-22963) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22963.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22963.svg)

## CVE-2023-22960
 Lexmark products through 2023-01-10 have Improper Control of Interaction Frequency.



- [https://github.com/t3l3machus/CVE-2023-22960](https://github.com/t3l3machus/CVE-2023-22960) :  ![starts](https://img.shields.io/github/stars/t3l3machus/CVE-2023-22960.svg) ![forks](https://img.shields.io/github/forks/t3l3machus/CVE-2023-22960.svg)

- [https://github.com/manas3c/CVE-2023-22960](https://github.com/manas3c/CVE-2023-22960) :  ![starts](https://img.shields.io/github/stars/manas3c/CVE-2023-22960.svg) ![forks](https://img.shields.io/github/forks/manas3c/CVE-2023-22960.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-22960](https://github.com/Live-Hack-CVE/CVE-2023-22960) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22960.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22960.svg)

## CVE-2023-22959
 WebChess through 0.9.0 and 1.0.0.rc2 allows SQL injection: mainmenu.php, chess.php, and opponentspassword.php (txtFirstName, txtLastName).



- [https://github.com/Live-Hack-CVE/CVE-2023-22959](https://github.com/Live-Hack-CVE/CVE-2023-22959) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22959.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22959.svg)

## CVE-2023-22958
 The Syracom Secure Login plugin before 3.1.1.0 for Jira may allow spoofing of 2FA PIN validation via the plugins/servlet/twofactor/public/pinvalidation target parameter.



- [https://github.com/Live-Hack-CVE/CVE-2023-22958](https://github.com/Live-Hack-CVE/CVE-2023-22958) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22958.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22958.svg)

## CVE-2023-22952
 In SugarCRM before 12.0. Hotfix 91155, a crafted request can inject custom PHP code through the EmailTemplates because of missing input validation.



- [https://github.com/Live-Hack-CVE/CVE-2023-22952](https://github.com/Live-Hack-CVE/CVE-2023-22952) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22952.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22952.svg)

## CVE-2023-22947
 ** DISPUTED ** Insecure folder permissions in the Windows installation path of Shibboleth Service Provider (SP) before 3.4.1 allow an unprivileged local attacker to escalate privileges to SYSTEM via DLL planting in the service executable's folder. This occurs because the installation goes under C:\opt (rather than C:\Program Files) by default. NOTE: the vendor disputes the significance of this report, stating that &quot;We consider the ACLs a best effort thing&quot; and &quot;it was a documentation mistake.&quot;



- [https://github.com/Live-Hack-CVE/CVE-2023-22947](https://github.com/Live-Hack-CVE/CVE-2023-22947) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22947.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22947.svg)

## CVE-2023-22945
 In the GrowthExperiments extension for MediaWiki through 1.39, the growthmanagementorlist API allows blocked users (blocked in ApiManageMentorList) to enroll as mentors or edit any of their mentorship-related properties.



- [https://github.com/Live-Hack-CVE/CVE-2023-22945](https://github.com/Live-Hack-CVE/CVE-2023-22945) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22945.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22945.svg)

## CVE-2023-22912
 An issue was discovered in MediaWiki before 1.35.9, 1.36.x through 1.38.x before 1.38.5, and 1.39.x before 1.39.1. CheckUser TokenManager insecurely uses AES-CTR encryption with a repeated (aka re-used) nonce, allowing an adversary to decrypt.



- [https://github.com/Live-Hack-CVE/CVE-2023-22912](https://github.com/Live-Hack-CVE/CVE-2023-22912) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22912.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22912.svg)

## CVE-2023-22911
 An issue was discovered in MediaWiki before 1.35.9, 1.36.x through 1.38.x before 1.38.5, and 1.39.x before 1.39.1. E-Widgets does widget replacement in HTML attributes, which can lead to XSS, because widget authors often do not expect that their widget is executed in an HTML attribute context.



- [https://github.com/Live-Hack-CVE/CVE-2023-22911](https://github.com/Live-Hack-CVE/CVE-2023-22911) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22911.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22911.svg)

## CVE-2023-22910
 An issue was discovered in MediaWiki before 1.35.9, 1.36.x through 1.38.x before 1.38.5, and 1.39.x before 1.39.1. There is XSS in Wikibase date formatting via wikibase-time-precision-* fields. This allows JavaScript execution by staff/admin users who do not intentionally have the editsitejs capability.



- [https://github.com/Live-Hack-CVE/CVE-2023-22910](https://github.com/Live-Hack-CVE/CVE-2023-22910) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22910.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22910.svg)

## CVE-2023-22909
 An issue was discovered in MediaWiki before 1.35.9, 1.36.x through 1.38.x before 1.38.5, and 1.39.x before 1.39.1. SpecialMobileHistory allows remote attackers to cause a denial of service because database queries are slow.



- [https://github.com/Live-Hack-CVE/CVE-2023-22909](https://github.com/Live-Hack-CVE/CVE-2023-22909) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22909.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22909.svg)

## CVE-2023-22903
 api/views/user.py in LibrePhotos before e19e539 has incorrect access control.



- [https://github.com/Live-Hack-CVE/CVE-2023-22903](https://github.com/Live-Hack-CVE/CVE-2023-22903) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22903.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22903.svg)

## CVE-2023-22900
 Efence login function has insufficient validation for user input. An unauthenticated remote attacker can exploit this vulnerability to inject arbitrary SQL commands to access, modify or delete database.



- [https://github.com/Live-Hack-CVE/CVE-2023-22900](https://github.com/Live-Hack-CVE/CVE-2023-22900) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22900.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22900.svg)

## CVE-2023-22885
 ** REJECT ** DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: none. Reason: This candidate is unused by its CNA. Notes: none.



- [https://github.com/Live-Hack-CVE/CVE-2023-22885](https://github.com/Live-Hack-CVE/CVE-2023-22885) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22885.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22885.svg)

## CVE-2023-22884
 Improper Neutralization of Special Elements used in a Command ('Command Injection') vulnerability in Apache Software Foundation Apache Airflow, Apache Software Foundation Apache Airflow MySQL Provider.This issue affects Apache Airflow: before 2.5.1; Apache Airflow MySQL Provider: before 4.0.0.



- [https://github.com/Live-Hack-CVE/CVE-2023-22884](https://github.com/Live-Hack-CVE/CVE-2023-22884) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22884.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22884.svg)

## CVE-2023-22875
 IBM QRadar SIEM 7.4 and 7.5copies certificate key files used for SSL/TLS in the QRadar web user interface to managed hosts in the deployment that do not require that key. IBM X-Force ID: 244356.



- [https://github.com/Live-Hack-CVE/CVE-2023-22875](https://github.com/Live-Hack-CVE/CVE-2023-22875) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22875.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22875.svg)

## CVE-2023-22855
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.



- [https://github.com/patrickhener/CVE-2023-22855](https://github.com/patrickhener/CVE-2023-22855) :  ![starts](https://img.shields.io/github/stars/patrickhener/CVE-2023-22855.svg) ![forks](https://img.shields.io/github/forks/patrickhener/CVE-2023-22855.svg)

## CVE-2023-22853
 Tiki before 24.1, when feature_create_webhelp is enabled, allows lib/structures/structlib.php PHP Object Injection because of an eval.



- [https://github.com/Live-Hack-CVE/CVE-2023-22853](https://github.com/Live-Hack-CVE/CVE-2023-22853) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22853.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22853.svg)

## CVE-2023-22852
 Tiki through 25.0 allows CSRF attacks that are related to tiki-importer.php and tiki-import_sheet.php.



- [https://github.com/Live-Hack-CVE/CVE-2023-22852](https://github.com/Live-Hack-CVE/CVE-2023-22852) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22852.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22852.svg)

## CVE-2023-22850
 Tiki before 24.1, when the Spreadsheets feature is enabled, allows lib/sheet/grid.php PHP Object Injection because of an unserialize call.



- [https://github.com/Live-Hack-CVE/CVE-2023-22850](https://github.com/Live-Hack-CVE/CVE-2023-22850) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22850.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22850.svg)

## CVE-2023-22849
 An improper neutralization of input during web page generation ('Cross-site Scripting') [CWE-79] vulnerability in Sling App CMS version 1.1.4 and prior may allow an authenticated remote attacker to perform a reflected cross-site scripting (XSS) attack in multiple features. Upgrade to Apache Sling App CMS &gt;= 1.1.6



- [https://github.com/Live-Hack-CVE/CVE-2023-22849](https://github.com/Live-Hack-CVE/CVE-2023-22849) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22849.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22849.svg)

## CVE-2023-22809
 In Sudo before 1.9.12p2, the sudoedit (aka -e) feature mishandles extra arguments passed in the user-provided environment variables (SUDO_EDITOR, VISUAL, and EDITOR), allowing a local attacker to append arbitrary entries to the list of files to process. This can lead to privilege escalation. Affected versions are 1.8.0 through 1.9.12.p1. The problem exists because a user-specified editor may contain a &quot;--&quot; argument that defeats a protection mechanism, e.g., an EDITOR='vim -- /path/to/extra/file' value.



- [https://github.com/n3m1dotsys/CVE-2023-22809-sudoedit-privesc](https://github.com/n3m1dotsys/CVE-2023-22809-sudoedit-privesc) :  ![starts](https://img.shields.io/github/stars/n3m1dotsys/CVE-2023-22809-sudoedit-privesc.svg) ![forks](https://img.shields.io/github/forks/n3m1dotsys/CVE-2023-22809-sudoedit-privesc.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-22809](https://github.com/Live-Hack-CVE/CVE-2023-22809) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22809.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22809.svg)

## CVE-2023-22799
 A ReDoS based DoS vulnerability in the GlobalID &lt;1.0.1 which could allow an attacker supplying a carefully crafted input can cause the regular expression engine to take an unexpected amount of time. All users running an affected release should either upgrade or use one of the workarounds immediately.



- [https://github.com/Live-Hack-CVE/CVE-2023-22799](https://github.com/Live-Hack-CVE/CVE-2023-22799) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22799.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22799.svg)

## CVE-2023-22798
 Prior to commit 51867e0d15a6d7f80d5b714fd0e9976b9c160bb0, https://github.com/brave/adblock-lists removed redirect interceptors on some websites like Facebook in which the redirect interceptor may have been there for security purposes. This could potentially cause open redirects on these websites. Brave's redirect interceptor removal feature is known as &quot;debouncing&quot; and is intended to remove unnecessary redirects that track users across the web.



- [https://github.com/Live-Hack-CVE/CVE-2023-22798](https://github.com/Live-Hack-CVE/CVE-2023-22798) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22798.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22798.svg)

## CVE-2023-22797
 An open redirect vulnerability is fixed in Rails 7.0.4.1 with the new protection against open redirects from calling redirect_to with untrusted user input. In prior versions the developer was fully responsible for only providing trusted input. However the check introduced could allow an attacker to bypass with a carefully crafted URL resulting in an open redirect vulnerability.



- [https://github.com/Live-Hack-CVE/CVE-2023-22797](https://github.com/Live-Hack-CVE/CVE-2023-22797) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22797.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22797.svg)

## CVE-2023-22796
 A regular expression based DoS vulnerability in Active Support &lt;6.1.7.1 and &lt;7.0.4.1. A specially crafted string passed to the underscore method can cause the regular expression engine to enter a state of catastrophic backtracking. This can cause the process to use large amounts of CPU and memory, leading to a possible DoS vulnerability.



- [https://github.com/Live-Hack-CVE/CVE-2023-22796](https://github.com/Live-Hack-CVE/CVE-2023-22796) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22796.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22796.svg)

## CVE-2023-22795
 A regular expression based DoS vulnerability in Action Dispatch &lt;6.1.7.1 and &lt;7.0.4.1 related to the If-None-Match header. A specially crafted HTTP If-None-Match header can cause the regular expression engine to enter a state of catastrophic backtracking, when on a version of Ruby below 3.2.0. This can cause the process to use large amounts of CPU and memory, leading to a possible DoS vulnerability All users running an affected release should either upgrade or use one of the workarounds immediately.



- [https://github.com/Live-Hack-CVE/CVE-2023-22795](https://github.com/Live-Hack-CVE/CVE-2023-22795) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22795.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22795.svg)

## CVE-2023-22794
 A vulnerability in ActiveRecord &lt;6.0.6.1, v6.1.7.1 and v7.0.4.1 related to the sanitization of comments. If malicious user input is passed to either the `annotate` query method, the `optimizer_hints` query method, or through the QueryLogs interface which automatically adds annotations, it may be sent to the database withinsufficient sanitization and be able to inject SQL outside of the comment.



- [https://github.com/Live-Hack-CVE/CVE-2023-22794](https://github.com/Live-Hack-CVE/CVE-2023-22794) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22794.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22794.svg)

## CVE-2023-22792
 A regular expression based DoS vulnerability in Action Dispatch &lt;6.0.6.1,&lt; 6.1.7.1, and &lt;7.0.4.1. Specially crafted cookies, in combination with a specially crafted X_FORWARDED_HOST header can cause the regular expression engine to enter a state of catastrophic backtracking. This can cause the process to use large amounts of CPU and memory, leading to a possible DoS vulnerability All users running an affected release should either upgrade or use one of the workarounds immediately.



- [https://github.com/Live-Hack-CVE/CVE-2023-22792](https://github.com/Live-Hack-CVE/CVE-2023-22792) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22792.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22792.svg)

## CVE-2023-22746
 CKAN is an open-source DMS (data management system) for powering data hubs and data portals. When creating a new container based on one of the Docker images listed below, the same secret key was being used by default. If the users didn't set a custom value via environment variables in the `.env` file, that key was shared across different CKAN instances, making it easy to forge authentication requests. Users overriding the default secret key in their own `.env` file are not affected by this issue. Note that the legacy images (ckan/ckan) located in the main CKAN repo are not affected by this issue. The affected images are ckan/ckan-docker, (ckan/ckan-base images), okfn/docker-ckan (openknowledge/ckan-base and openknowledge/ckan-dev images) keitaroinc/docker-ckan (keitaro/ckan images).



- [https://github.com/Live-Hack-CVE/CVE-2023-22746](https://github.com/Live-Hack-CVE/CVE-2023-22746) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22746.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22746.svg)

## CVE-2023-22745
 tpm2-tss is an open source software implementation of the Trusted Computing Group (TCG) Trusted Platform Module (TPM) 2 Software Stack (TSS2). In affected versions `Tss2_RC_SetHandler` and `Tss2_RC_Decode` both index into `layer_handler` with an 8 bit layer number, but the array only has `TPM2_ERROR_TSS2_RC_LAYER_COUNT` entries, so trying to add a handler for higher-numbered layers or decode a response code with such a layer number reads/writes past the end of the buffer. This Buffer overrun, could result in arbitrary code execution. An example attack would be a MiTM bus attack that returns 0xFFFFFFFF for the RC. Given the common use case of TPM modules an attacker must have local access to the target machine with local system privileges which allows access to the TPM system. Usually TPM access requires administrative privilege.



- [https://github.com/Live-Hack-CVE/CVE-2023-22745](https://github.com/Live-Hack-CVE/CVE-2023-22745) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22745.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22745.svg)

## CVE-2023-22742
 libgit2 is a cross-platform, linkable library implementation of Git. When using an SSH remote with the optional libssh2 backend, libgit2 does not perform certificate checking by default. Prior versions of libgit2 require the caller to set the `certificate_check` field of libgit2's `git_remote_callbacks` structure - if a certificate check callback is not set, libgit2 does not perform any certificate checking. This means that by default - without configuring a certificate check callback, clients will not perform validation on the server SSH keys and may be subject to a man-in-the-middle attack. Users are encouraged to upgrade to v1.4.5 or v1.5.1. Users unable to upgrade should ensure that all relevant certificates are manually checked.



- [https://github.com/Live-Hack-CVE/CVE-2023-22742](https://github.com/Live-Hack-CVE/CVE-2023-22742) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22742.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22742.svg)

## CVE-2023-22741
 Sofia-SIP is an open-source SIP User-Agent library, compliant with the IETF RFC3261 specification. In affected versions Sofia-SIP **lacks both message length and attributes length checks** when it handles STUN packets, leading to controllable heap-over-flow. For example, in stun_parse_attribute(), after we get the attribute's type and length value, the length will be used directly to copy from the heap, regardless of the message's left size. Since network users control the overflowed length, and the data is written to heap chunks later, attackers may achieve remote code execution by heap grooming or other exploitation methods. The bug was introduced 16 years ago in sofia-sip 1.12.4 (plus some patches through 12/21/2006) to in tree libs with git-svn-id: http://svn.freeswitch.org/svn/freeswitch/trunk@3774 d0543943-73ff-0310-b7d9-9358b9ac24b2. Users are advised to upgrade. There are no known workarounds for this vulnerability.



- [https://github.com/Live-Hack-CVE/CVE-2023-22741](https://github.com/Live-Hack-CVE/CVE-2023-22741) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22741.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22741.svg)

## CVE-2023-22740
 Discourse is an open source platform for community discussion. Versions prior to 3.1.0.beta1 (beta) (tests-passed) are vulnerable to Allocation of Resources Without Limits. Users can create chat drafts of an unlimited length, which can cause a denial of service by generating an excessive load on the server. Additionally, an unlimited number of drafts were loaded when loading the user. This issue has been patched in version 2.1.0.beta1 (beta) and (tests-passed). Users should upgrade to the latest version where a limit has been introduced. There are no workarounds available.



- [https://github.com/Live-Hack-CVE/CVE-2023-22740](https://github.com/Live-Hack-CVE/CVE-2023-22740) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22740.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22740.svg)

## CVE-2023-22737
 wire-server provides back end services for Wire, a team communication and collaboration platform. Prior to version 2022-12-09, every member of a Conversation can remove a Bot from a Conversation due to a missing permissions check. Only Conversation admins should be able to remove Bots. Regular Conversations are not allowed to do so. The issue is fixed in wire-server 2022-12-09 and is already deployed on all Wire managed services. On-premise instances of wire-server need to be updated to 2022-12-09/Chart 4.29.0, so that their backends are no longer affected. There are no known workarounds.



- [https://github.com/Live-Hack-CVE/CVE-2023-22737](https://github.com/Live-Hack-CVE/CVE-2023-22737) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22737.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22737.svg)

## CVE-2023-22736
 Argo CD is a declarative, GitOps continuous delivery tool for Kubernetes. Versions starting with 2.5.0-rc1 and above, prior to 2.5.8, and version 2.6.0-rc4, are vulnerable to an authorization bypass bug which allows a malicious Argo CD user to deploy Applications outside the configured allowed namespaces. Reconciled Application namespaces are specified as a comma-delimited list of glob patterns. When sharding is enabled on the Application controller, it does not enforce that list of patterns when reconciling Applications. For example, if Application namespaces are configured to be argocd-*, the Application controller may reconcile an Application installed in a namespace called other, even though it does not start with argocd-. Reconciliation of the out-of-bounds Application is only triggered when the Application is updated, so the attacker must be able to cause an update operation on the Application resource. This bug only applies to users who have explicitly enabled the &quot;apps-in-any-namespace&quot; feature by setting `application.namespaces` in the argocd-cmd-params-cm ConfigMap or otherwise setting the `--application-namespaces` flags on the Application controller and API server components. The apps-in-any-namespace feature is in beta as of this Security Advisory's publish date. The bug is also limited to Argo CD instances where sharding is enabled by increasing the `replicas` count for the Application controller. Finally, the AppProjects' `sourceNamespaces` field acts as a secondary check against this exploit. To cause reconciliation of an Application in an out-of-bounds namespace, an AppProject must be available which permits Applications in the out-of-bounds namespace. A patch for this vulnerability has been released in versions 2.5.8 and 2.6.0-rc5. As a workaround, running only one replica of the Application controller will prevent exploitation of this bug. Making sure all AppProjects' sourceNamespaces are restricted within the confines of the configured Application namespaces will also prevent exploitation of this bug.



- [https://github.com/Live-Hack-CVE/CVE-2023-22736](https://github.com/Live-Hack-CVE/CVE-2023-22736) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22736.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22736.svg)

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

## CVE-2023-22726
 act is a project which allows for local running of github actions. The artifact server that stores artifacts from Github Action runs does not sanitize path inputs. This allows an attacker to download and overwrite arbitrary files on the host from a Github Action. This issue may lead to privilege escalation. The /upload endpoint is vulnerable to path traversal as filepath is user controlled, and ultimately flows into os.Mkdir and os.Open. The /artifact endpoint is vulnerable to path traversal as the path is variable is user controlled, and the specified file is ultimately returned by the server. This has been addressed in version 0.2.40. Users are advised to upgrade. Users unable to upgrade may, during implementation of Open and OpenAtEnd for FS, ensure to use ValidPath() to check against path traversal or clean the user-provided paths manually.



- [https://github.com/Live-Hack-CVE/CVE-2023-22726](https://github.com/Live-Hack-CVE/CVE-2023-22726) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22726.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22726.svg)

## CVE-2023-22724
 GLPI is a Free Asset and IT Management Software package. Versions prior to 10.0.6 are subject to Cross-site Scripting via malicious RSS feeds. An Administrator can import a malicious RSS feed that contains Cross Site Scripting (XSS) payloads inside RSS links. Victims who wish to visit an RSS content and click on the link will execute the Javascript. This issue is patched in 10.0.6.



- [https://github.com/Live-Hack-CVE/CVE-2023-22724](https://github.com/Live-Hack-CVE/CVE-2023-22724) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22724.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22724.svg)

## CVE-2023-22722
 GLPI is a Free Asset and IT Management Software package. Versions 9.4.0 and above, prior to 10.0.6 are subject to Cross-site Scripting. An attacker can persuade a victim into opening a URL containing a payload exploiting this vulnerability. After exploited, the attacker can make actions as the victim or exfiltrate session cookies. This issue is patched in version 10.0.6.



- [https://github.com/Live-Hack-CVE/CVE-2023-22722](https://github.com/Live-Hack-CVE/CVE-2023-22722) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22722.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22722.svg)

## CVE-2023-22671
 Ghidra/RuntimeScripts/Linux/support/launch.sh in NSA Ghidra through 10.2.2 passes user-provided input into eval, leading to command injection when calling analyzeHeadless with untrusted input.



- [https://github.com/Live-Hack-CVE/CVE-2023-22671](https://github.com/Live-Hack-CVE/CVE-2023-22671) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22671.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22671.svg)

## CVE-2023-22664
 On BIG-IP versions 17.0.x before 17.0.0.2 and 16.1.x before 16.1.3.3, and BIG-IP SPK starting in version 1.6.0, when a client-side HTTP/2 profile and the HTTP MRF Router option are enabled for a virtual server, undisclosed requests can cause an increase in memory resource utilization. Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.



- [https://github.com/Live-Hack-CVE/CVE-2023-22664](https://github.com/Live-Hack-CVE/CVE-2023-22664) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22664.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22664.svg)

## CVE-2023-22657
 On F5OS-A beginning in version 1.2.0 to before 1.3.0 and F5OS-C beginning in version 1.3.0 to before 1.5.0, processing F5OS tenant file names may allow for command injection. Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.



- [https://github.com/Live-Hack-CVE/CVE-2023-22657](https://github.com/Live-Hack-CVE/CVE-2023-22657) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22657.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22657.svg)

## CVE-2023-22643
 An Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') vulnerability in libzypp-plugin-appdata of SUSE Linux Enterprise Server for SAP 15-SP3; openSUSE Leap 15.4 allows attackers that can trick users to use specially crafted REPO_ALIAS, REPO_TYPE or REPO_METADATA_PATH settings to execute code as root. This issue affects: SUSE Linux Enterprise Server for SAP 15-SP3 libzypp-plugin-appdata versions prior to 1.0.1+git.20180426. openSUSE Leap 15.4 libzypp-plugin-appdata versions prior to 1.0.1+git.20180426.



- [https://github.com/Live-Hack-CVE/CVE-2023-22643](https://github.com/Live-Hack-CVE/CVE-2023-22643) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22643.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22643.svg)

## CVE-2023-22630
 IzyBat Orange casiers before 20221102_1 allows SQL Injection via a getCasier.php?taille= URI.



- [https://github.com/Live-Hack-CVE/CVE-2023-22630](https://github.com/Live-Hack-CVE/CVE-2023-22630) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22630.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22630.svg)

## CVE-2023-22626
 PgHero before 3.1.0 allows Information Disclosure via EXPLAIN because query results may be present in an error message. (Depending on database user privileges, this may only be information from the database, or may be information from file contents on the database server.)



- [https://github.com/Live-Hack-CVE/CVE-2023-22626](https://github.com/Live-Hack-CVE/CVE-2023-22626) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22626.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22626.svg)

## CVE-2023-22624
 Zoho ManageEngine Exchange Reporter Plus before 5708 allows attackers to conduct XXE attacks.



- [https://github.com/Live-Hack-CVE/CVE-2023-22624](https://github.com/Live-Hack-CVE/CVE-2023-22624) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22624.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22624.svg)

## CVE-2023-22622
 WordPress through 6.1.1 depends on unpredictable client visits to cause wp-cron.php execution and the resulting security updates, and the source code describes &quot;the scenario where a site may not receive enough visits to execute scheduled tasks in a timely manner,&quot; but neither the installation guide nor the security guide mentions this default behavior, or alerts the user about security risks on installations with very few visits.



- [https://github.com/Live-Hack-CVE/CVE-2023-22622](https://github.com/Live-Hack-CVE/CVE-2023-22622) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22622.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22622.svg)

## CVE-2023-22617
 A remote attacker might be able to cause infinite recursion in PowerDNS Recursor 4.8.0 via a DNS query that retrieves DS records for a misconfigured domain, because QName minimization is used in QM fallback mode. This is fixed in 4.8.1.



- [https://github.com/Live-Hack-CVE/CVE-2023-22617](https://github.com/Live-Hack-CVE/CVE-2023-22617) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22617.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22617.svg)

## CVE-2023-22611
 A CWE-200: Exposure of Sensitive Information to an Unauthorized Actor vulnerability exists that could cause information disclosure when specific messages are sent to the server over the database server TCP port. Affected Products: EcoStruxure Geo SCADA Expert 2019 - 2021 (formerly known as ClearSCADA) (Versions prior to October 2022)



- [https://github.com/Live-Hack-CVE/CVE-2023-22611](https://github.com/Live-Hack-CVE/CVE-2023-22611) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22611.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22611.svg)

## CVE-2023-22610
 A CWE-285: Improper Authorization vulnerability exists that could cause Denial of Service against the Geo SCADA server when specific messages are sent to the server over the database server TCP port. Affected Products: EcoStruxure Geo SCADA Expert 2019 - 2021 (formerly known as ClearSCADA) (Versions prior to October 2022)



- [https://github.com/Live-Hack-CVE/CVE-2023-22610](https://github.com/Live-Hack-CVE/CVE-2023-22610) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22610.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22610.svg)

## CVE-2023-22602
 When using Apache Shiro before 1.11.0 together with Spring Boot 2.6+, a specially crafted HTTP request may cause an authentication bypass. The authentication bypass occurs when Shiro and Spring Boot are using different pattern-matching techniques. Both Shiro and Spring Boot &lt; 2.6 default to Ant style pattern matching. Mitigation: Update to Apache Shiro 1.11.0, or set the following Spring Boot configuration value: `spring.mvc.pathmatch.matching-strategy = ant_path_matcher`



- [https://github.com/Live-Hack-CVE/CVE-2023-22602](https://github.com/Live-Hack-CVE/CVE-2023-22602) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22602.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22602.svg)

## CVE-2023-22597
 InHand Networks InRouter 302, prior to version IR302 V3.5.56, and InRouter 615, prior to version InRouter6XX-S-V2.3.0.r5542, contain vulnerability CWE-319: Cleartext Transmission of Sensitive Information. They use an unsecured channel to communicate with the cloud platform by default. An unauthorized user could intercept this communication and steal sensitive information such as configuration information and MQTT credentials; this could allow MQTT command injection.



- [https://github.com/Live-Hack-CVE/CVE-2023-22597](https://github.com/Live-Hack-CVE/CVE-2023-22597) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22597.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22597.svg)

## CVE-2023-22575
 Dell PowerScale OneFS 9.0.0.x - 9.4.0.x contain an insertion of sensitive information into log file vulnerability in celog. A low privileges user could potentially exploit this vulnerability, leading to information disclosure and escalation of privileges.



- [https://github.com/Live-Hack-CVE/CVE-2023-22575](https://github.com/Live-Hack-CVE/CVE-2023-22575) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22575.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22575.svg)

## CVE-2023-22574
 Dell PowerScale OneFS 9.0.0.x - 9.4.0.x contain an insertion of sensitive information into log file vulnerability in platform API of IPMI module. A low-privileged user with permission to read logs on the cluster could potentially exploit this vulnerability, leading to Information disclosure and denial of service.



- [https://github.com/Live-Hack-CVE/CVE-2023-22574](https://github.com/Live-Hack-CVE/CVE-2023-22574) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22574.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22574.svg)

## CVE-2023-22573
 Dell PowerScale OneFS 9.0.0.x-9.4.0.x contain an insertion of sensitive information into log file vulnerability in cloudpool. A low privileged local attacker could potentially exploit this vulnerability, leading to sensitive information disclosure.



- [https://github.com/Live-Hack-CVE/CVE-2023-22573](https://github.com/Live-Hack-CVE/CVE-2023-22573) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22573.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22573.svg)

## CVE-2023-22572
 Dell PowerScale OneFS 9.1.0.x-9.4.0.x contain an insertion of sensitive information into log file vulnerability in change password api. A low privilege local attacker could potentially exploit this vulnerability, leading to system takeover.



- [https://github.com/Live-Hack-CVE/CVE-2023-22572](https://github.com/Live-Hack-CVE/CVE-2023-22572) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22572.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22572.svg)

## CVE-2023-22551
 The FTP (aka &quot;Implementation of a simple FTP client and server&quot;) project through 96c1a35 allows remote attackers to cause a denial of service (memory consumption) by engaging in client activity, such as establishing and then terminating a connection. This occurs because malloc is used but free is not.



- [https://github.com/Live-Hack-CVE/CVE-2023-22551](https://github.com/Live-Hack-CVE/CVE-2023-22551) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22551.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22551.svg)

## CVE-2023-22501
 An authentication vulnerability was discovered in Jira Service Management Server and Data Center which allows an attacker to impersonate another user and gain access to a Jira Service Management instance under certain circumstances_._ With write access to a User Directory and outgoing email enabled on a Jira Service Management instance, an attacker could gain access to signup tokens sent to users with accounts that have never been logged into. Access to these tokens can be obtained in two cases: * If the attacker is included on Jira issues or requests with these users, or * If the attacker is forwarded or otherwise gains access to emails containing a &#8220;View Request&#8221; link from these users. Bot accounts are particularly susceptible to this scenario. On instances with single sign-on, external customer accounts can be affected in projects where anyone can create their own account.



- [https://github.com/Live-Hack-CVE/CVE-2023-22501](https://github.com/Live-Hack-CVE/CVE-2023-22501) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22501.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22501.svg)

## CVE-2023-22500
 GLPI is a Free Asset and IT Management Software package. Versions 10.0.0 and above, prior to 10.0.6 are vulnerable to Incorrect Authorization. This vulnerability allow unauthorized access to inventory files. Thus, if anonymous access to FAQ is allowed, inventory files are accessbile by unauthenticated users. This issue is patched in version 10.0.6. As a workaround, disable native inventory and delete inventory files from server (default location is `files/_inventory`).



- [https://github.com/Live-Hack-CVE/CVE-2023-22500](https://github.com/Live-Hack-CVE/CVE-2023-22500) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22500.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22500.svg)

## CVE-2023-22499
 Deno is a runtime for JavaScript and TypeScript that uses V8 and is built in Rust. Multi-threaded programs were able to spoof interactive permission prompt by rewriting the prompt to suggest that program is waiting on user confirmation to unrelated action. A malicious program could clear the terminal screen after permission prompt was shown and write a generic message. This situation impacts users who use Web Worker API and relied on interactive permission prompt. The reproduction is very timing sensitive and can&#8217;t be reliably reproduced on every try. This problem can not be exploited on systems that do not attach an interactive prompt (for example headless servers). The problem has been fixed in Deno v1.29.3; it is recommended all users update to this version. Users are advised to upgrade. Users unable to upgrade may run with --no-prompt flag to disable interactive permission prompts.



- [https://github.com/Live-Hack-CVE/CVE-2023-22499](https://github.com/Live-Hack-CVE/CVE-2023-22499) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22499.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22499.svg)

## CVE-2023-22494
 ** REJECT ** DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: CVE-2016-20018. Reason: This candidate is a reservation duplicate of CVE-2016-20018. Notes: All CVE users should reference CVE-2016-20018 instead of this candidate. All references and descriptions in this candidate have been removed to prevent accidental usage.



- [https://github.com/Live-Hack-CVE/CVE-2023-22494](https://github.com/Live-Hack-CVE/CVE-2023-22494) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22494.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22494.svg)

## CVE-2023-22493
 RSSHub is an open source RSS feed generator. RSSHub is vulnerable to Server-Side Request Forgery (SSRF) attacks. This vulnerability allows an attacker to send arbitrary HTTP requests from the server to other servers or resources on the network. An attacker can exploit this vulnerability by sending a request to the affected routes with a malicious URL. An attacker could also use this vulnerability to send requests to internal or any other servers or resources on the network, potentially gain access to sensitive information that would not normally be accessible and amplifying the impact of the attack. The patch for this issue can be found in commit a66cbcf.



- [https://github.com/Live-Hack-CVE/CVE-2023-22493](https://github.com/Live-Hack-CVE/CVE-2023-22493) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22493.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22493.svg)

## CVE-2023-22492
 ZITADEL is a combination of Auth0 and Keycloak. RefreshTokens is an OAuth 2.0 feature that allows applications to retrieve new access tokens and refresh the user's session without the need for interacting with a UI. RefreshTokens were not invalidated when a user was locked or deactivated. The deactivated or locked user was able to obtain a valid access token only through a refresh token grant. When the locked or deactivated user&#8217;s session was already terminated (&#8220;logged out&#8221;) then it was not possible to create a new session. Renewal of access token through a refresh token grant is limited to the configured amount of time (RefreshTokenExpiration). As a workaround, ensure the RefreshTokenExpiration in the OIDC settings of your instance is set according to your security requirements. This issue has been patched in versions 2.17.3 and 2.16.4.



- [https://github.com/Live-Hack-CVE/CVE-2023-22492](https://github.com/Live-Hack-CVE/CVE-2023-22492) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22492.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22492.svg)

## CVE-2023-22491
 Gatsby is a free and open source framework based on React that helps developers build websites and apps. The gatsby-transformer-remark plugin prior to versions 5.25.1 and 6.3.2 passes input through to the `gray-matter` npm package, which is vulnerable to JavaScript injection in its default configuration, unless input is sanitized. The vulnerability is present in gatsby-transformer-remark when passing input in data mode (querying MarkdownRemark nodes via GraphQL). Injected JavaScript executes in the context of the build server. To exploit this vulnerability untrusted/unsanitized input would need to be sourced by or added into a file processed by gatsby-transformer-remark. A patch has been introduced in `gatsby-transformer-remark@5.25.1` and `gatsby-transformer-remark@6.3.2` which mitigates the issue by disabling the `gray-matter` JavaScript Frontmatter engine. As a workaround, if an older version of `gatsby-transformer-remark` must be used, input passed into the plugin should be sanitized ahead of processing. It is encouraged for projects to upgrade to the latest major release branch for all Gatsby plugins to ensure the latest security updates and bug fixes are received in a timely manner.



- [https://github.com/Live-Hack-CVE/CVE-2023-22491](https://github.com/Live-Hack-CVE/CVE-2023-22491) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22491.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22491.svg)

## CVE-2023-22489
 Flarum is a discussion platform for websites. If the first post of a discussion is permanently deleted but the discussion stays visible, any actor who can view the discussion is able to create a new reply via the REST API, no matter the reply permission or lock status. This includes users that don't have a validated email. Guests cannot successfully create a reply because the API will fail with a 500 error when the user ID 0 is inserted into the database. This happens because when the first post of a discussion is permanently deleted, the `first_post_id` attribute of the discussion becomes `null` which causes access control to be skipped for all new replies. Flarum automatically makes discussions with zero comments invisible so an additional condition for this vulnerability is that the discussion must have at least one approved reply so that `discussions.comment_count` is still above zero after the post deletion. This can open the discussion to uncontrolled spam or just unintentional replies if users still had their tab open before the vulnerable discussion was locked and then post a reply when they shouldn't be able to. In combination with the email notification settings, this could also be used as a way to send unsolicited emails. Versions between `v1.3.0` and `v1.6.3` are impacted. The vulnerability has been fixed and published as flarum/core v1.6.3. All communities running Flarum should upgrade as soon as possible. There are no known workarounds.



- [https://github.com/Live-Hack-CVE/CVE-2023-22489](https://github.com/Live-Hack-CVE/CVE-2023-22489) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22489.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22489.svg)

## CVE-2023-22488
 Flarum is a forum software for building communities. Using the notifications feature, one can read restricted/private content and bypass access checks that would be in place for such content. The notification-sending component does not check that the subject of the notification can be seen by the receiver, and proceeds to send notifications through their different channels. The alerts do not leak data despite this as they are listed based on a visibility check, however, emails are still sent out. This means that, for extensions which restrict access to posts, any actor can bypass the restriction by subscribing to the discussion if the Subscriptions extension is enabled. The attack allows the leaking of some posts in the forum database, including posts awaiting approval, posts in tags the user has no access to if they could subscribe to a discussion before it becomes private, and posts restricted by third-party extensions. All Flarum versions prior to v1.6.3 are affected. The vulnerability has been fixed and published as flarum/core v1.6.3. All communities running Flarum should upgrade as soon as possible to v1.6.3. As a workaround, disable the Flarum Subscriptions extension or disable email notifications altogether. There are no other supported workarounds for this issue for Flarum versions below 1.6.3.



- [https://github.com/Live-Hack-CVE/CVE-2023-22488](https://github.com/Live-Hack-CVE/CVE-2023-22488) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22488.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22488.svg)

## CVE-2023-22487
 Flarum is a forum software for building communities. Using the mentions feature provided by the flarum/mentions extension, users can mention any post ID on the forum with the special `@&quot;&lt;username&gt;&quot;#p&lt;id&gt;` syntax. The following behavior never changes no matter if the actor should be able to read the mentioned post or not: A URL to the mentioned post is inserted into the actor post HTML, leaking its discussion ID and post number. The `mentionsPosts` relationship included in the `POST /api/posts` and `PATCH /api/posts/&lt;id&gt;` JSON responses leaks the full JSON:API payload of all mentioned posts without any access control. This includes the content, date, number and attributes added by other extensions. An attacker only needs the ability to create new posts on the forum to exploit the vulnerability. This works even if new posts require approval. If they have the ability to edit posts, the attack can be performed even more discreetly by using a single post to scan any size of database and hiding the attack post content afterward. The attack allows the leaking of all posts in the forum database, including posts awaiting approval, posts in tags the user has no access to, and private discussions created by other extensions like FriendsOfFlarum Byobu. This also includes non-comment posts like tag changes or renaming events. The discussion payload is not leaked but using the mention HTML payload it's possible to extract the discussion ID of all posts and combine all posts back together into their original discussions even if the discussion title remains unknown. All Flarum versions prior to 1.6.3 are affected. The vulnerability has been fixed and published as flarum/core v1.6.3. As a workaround, user can disable the mentions extension.



- [https://github.com/Live-Hack-CVE/CVE-2023-22487](https://github.com/Live-Hack-CVE/CVE-2023-22487) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22487.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22487.svg)

## CVE-2023-22485
 cmark-gfm is GitHub's fork of cmark, a CommonMark parsing and rendering library and program in C. In versions prior 0.29.0.gfm.7, a crafted markdown document can trigger an out-of-bounds read in the `validate_protocol` function. We believe this bug is harmless in practice, because the out-of-bounds read accesses `malloc` metadata without causing any visible damage.This vulnerability has been patched in 0.29.0.gfm.7.



- [https://github.com/Live-Hack-CVE/CVE-2023-22485](https://github.com/Live-Hack-CVE/CVE-2023-22485) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22485.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22485.svg)

## CVE-2023-22484
 cmark-gfm is GitHub's fork of cmark, a CommonMark parsing and rendering library and program in C. Versions prior to 0.29.0.gfm.7 are subject to a polynomial time complexity issue in cmark-gfm that may lead to unbounded resource exhaustion and subsequent denial of service. This vulnerability has been patched in 0.29.0.gfm.7.



- [https://github.com/Live-Hack-CVE/CVE-2023-22484](https://github.com/Live-Hack-CVE/CVE-2023-22484) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22484.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22484.svg)

## CVE-2023-22483
 cmark-gfm is GitHub's fork of cmark, a CommonMark parsing and rendering library and program in C. Versions prior to 0.29.0.gfm.7 are subject to several polynomial time complexity issues in cmark-gfm that may lead to unbounded resource exhaustion and subsequent denial of service. Various commands, when piped to cmark-gfm with large values, cause the running time to increase quadratically. These vulnerabilities have been patched in version 0.29.0.gfm.7.



- [https://github.com/Live-Hack-CVE/CVE-2023-22483](https://github.com/Live-Hack-CVE/CVE-2023-22483) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22483.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22483.svg)

## CVE-2023-22479
 KubePi is a modern Kubernetes panel. A session fixation attack allows an attacker to hijack a legitimate user session, versions 1.6.3 and below are susceptible. A patch will be released in version 1.6.4.



- [https://github.com/Live-Hack-CVE/CVE-2023-22479](https://github.com/Live-Hack-CVE/CVE-2023-22479) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22479.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22479.svg)

## CVE-2023-22477
 Mercurius is a GraphQL adapter for Fastify. Any users of Mercurius until version 10.5.0 are subjected to a denial of service attack by sending a malformed packet over WebSocket to `/graphql`. This issue was patched in #940. As a workaround, users can disable subscriptions.



- [https://github.com/Live-Hack-CVE/CVE-2023-22477](https://github.com/Live-Hack-CVE/CVE-2023-22477) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22477.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22477.svg)

## CVE-2023-22475
 Canarytokens is an open source tool which helps track activity and actions on your network. A Cross-Site Scripting vulnerability was identified in the history page of triggered Canarytokens prior to sha-fb61290. An attacker who discovers an HTTP-based Canarytoken (a URL) can use this to execute Javascript in the Canarytoken's trigger history page (domain: canarytokens.org) when the history page is later visited by the Canarytoken's creator. This vulnerability could be used to disable or delete the affected Canarytoken, or view its activation history. It might also be used as a stepping stone towards revealing more information about the Canarytoken's creator to the attacker. For example, an attacker could recover the email address tied to the Canarytoken, or place Javascript on the history page that redirect the creator towards an attacker-controlled Canarytoken to show the creator's network location. This vulnerability is similar to CVE-2022-31113, but affected parameters reported differently from the Canarytoken trigger request. An attacker could only act on the discovered Canarytoken. This issue did not expose other Canarytokens or other Canarytoken creators. Canarytokens Docker images sha-fb61290 and later contain a patch for this issue.



- [https://github.com/Live-Hack-CVE/CVE-2023-22475](https://github.com/Live-Hack-CVE/CVE-2023-22475) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22475.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22475.svg)

## CVE-2023-22472
 Deck is a kanban style organization tool aimed at personal planning and project organization for teams integrated with Nextcloud. It is possible to make a user send any POST request with an arbitrary body given they click on a malicious deep link on a Windows computer. (e.g. in an email, chat link, etc). There are currently no known workarounds. It is recommended that the Nextcloud Desktop client is upgraded to 3.6.2.



- [https://github.com/Live-Hack-CVE/CVE-2023-22472](https://github.com/Live-Hack-CVE/CVE-2023-22472) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22472.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22472.svg)

## CVE-2023-22469
 Deck is a kanban style organization tool aimed at personal planning and project organization for teams integrated with Nextcloud. When getting the reference preview for Deck cards the user has no access to, unauthorized user could eventually get the cached data of a user that has access. There are currently no known workarounds. It is recommended that the Nextcloud app Deck is upgraded to 1.8.2.



- [https://github.com/Live-Hack-CVE/CVE-2023-22469](https://github.com/Live-Hack-CVE/CVE-2023-22469) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22469.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22469.svg)

## CVE-2023-22467
 Luxon is a library for working with dates and times in JavaScript. On the 1.x branch prior to 1.38.1, the 2.x branch prior to 2.5.2, and the 3.x branch on 3.2.1, Luxon's `DateTime.fromRFC2822() has quadratic (N^2) complexity on some specific inputs. This causes a noticeable slowdown for inputs with lengths above 10k characters. Users providing untrusted data to this method are therefore vulnerable to (Re)DoS attacks. This issue also appears in Moment as CVE-2022-31129. Versions 1.38.1, 2.5.2, and 3.2.1 contain patches for this issue. As a workaround, limit the length of the input.



- [https://github.com/Live-Hack-CVE/CVE-2023-22467](https://github.com/Live-Hack-CVE/CVE-2023-22467) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22467.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22467.svg)

## CVE-2023-22466
 Tokio is a runtime for writing applications with Rust. Starting with version 1.7.0 and prior to versions 1.18.4, 1.20.3, and 1.23.1, when configuring a Windows named pipe server, setting `pipe_mode` will reset `reject_remote_clients` to `false`. If the application has previously configured `reject_remote_clients` to `true`, this effectively undoes the configuration. Remote clients may only access the named pipe if the named pipe's associated path is accessible via a publicly shared folder (SMB). Versions 1.23.1, 1.20.3, and 1.18.4 have been patched. The fix will also be present in all releases starting from version 1.24.0. Named pipes were introduced to Tokio in version 1.7.0, so releases older than 1.7.0 are not affected. As a workaround, ensure that `pipe_mode` is set first after initializing a `ServerOptions`.



- [https://github.com/Live-Hack-CVE/CVE-2023-22466](https://github.com/Live-Hack-CVE/CVE-2023-22466) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22466.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22466.svg)

## CVE-2023-22464
 ViewVC is a browser interface for CVS and Subversion version control repositories. Versions prior to 1.2.3 and 1.1.30 are vulnerable to cross-site scripting. The impact of this vulnerability is mitigated by the need for an attacker to have commit privileges to a Subversion repository exposed by an otherwise trusted ViewVC instance. The attack vector involves files with unsafe names (names that, when embedded into an HTML stream, would cause the browser to run unwanted code), which themselves can be challenging to create. Users should update to at least version 1.2.3 (if they are using a 1.2.x version of ViewVC) or 1.1.30 (if they are using a 1.1.x version). ViewVC 1.0.x is no longer supported, so users of that release lineage should implement one of the following workarounds. Users can edit their ViewVC EZT view templates to manually HTML-escape changed path &quot;copyfrom paths&quot; during rendering. Locate in your template set's `revision.ezt` file references to those changed paths, and wrap them with `[format &quot;html&quot;]` and `[end]`. For most users, that means that references to `[changes.copy_path]` will become `[format &quot;html&quot;][changes.copy_path][end]`. (This workaround should be reverted after upgrading to a patched version of ViewVC, else &quot;copyfrom path&quot; names will be doubly escaped.)



- [https://github.com/Live-Hack-CVE/CVE-2023-22464](https://github.com/Live-Hack-CVE/CVE-2023-22464) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22464.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22464.svg)

## CVE-2023-22463
 KubePi is a k8s panel. The jwt authentication function of KubePi through version 1.6.2 uses hard-coded Jwtsigkeys, resulting in the same Jwtsigkeys for all online projects. This means that an attacker can forge any jwt token to take over the administrator account of any online project. Furthermore, they may use the administrator to take over the k8s cluster of the target enterprise. `session.go`, the use of hard-coded JwtSigKey, allows an attacker to use this value to forge jwt tokens arbitrarily. The JwtSigKey is confidential and should not be hard-coded in the code. The vulnerability has been fixed in 1.6.3. In the patch, JWT key is specified in app.yml. If the user leaves it blank, a random key will be used. There are no workarounds aside from upgrading.



- [https://github.com/Live-Hack-CVE/CVE-2023-22463](https://github.com/Live-Hack-CVE/CVE-2023-22463) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22463.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22463.svg)

## CVE-2023-22458
 Redis is an in-memory database that persists on disk. Authenticated users can issue a `HRANDFIELD` or `ZRANDMEMBER` command with specially crafted arguments to trigger a denial-of-service by crashing Redis with an assertion failure. This problem affects Redis versions 6.2 or newer up to but not including 6.2.9 as well as versions 7.0 up to but not including 7.0.8. Users are advised to upgrade. There are no known workarounds for this vulnerability.



- [https://github.com/Live-Hack-CVE/CVE-2023-22458](https://github.com/Live-Hack-CVE/CVE-2023-22458) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22458.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22458.svg)

## CVE-2023-22456
 ViewVC, a browser interface for CVS and Subversion version control repositories, as a cross-site scripting vulnerability that affects versions prior to 1.2.2 and 1.1.29. The impact of this vulnerability is mitigated by the need for an attacker to have commit privileges to a Subversion repository exposed by an otherwise trusted ViewVC instance. The attack vector involves files with unsafe names (names that, when embedded into an HTML stream, would cause the browser to run unwanted code), which themselves can be challenging to create. Users should update to at least version 1.2.2 (if they are using a 1.2.x version of ViewVC) or 1.1.29 (if they are using a 1.1.x version). ViewVC 1.0.x is no longer supported, so users of that release lineage should implement a workaround. Users can edit their ViewVC EZT view templates to manually HTML-escape changed paths during rendering. Locate in your template set's `revision.ezt` file references to those changed paths, and wrap them with `[format &quot;html&quot;]` and `[end]`. For most users, that means that references to `[changes.path]` will become `[format &quot;html&quot;][changes.path][end]`. (This workaround should be reverted after upgrading to a patched version of ViewVC, else changed path names will be doubly escaped.)



- [https://github.com/Live-Hack-CVE/CVE-2023-22456](https://github.com/Live-Hack-CVE/CVE-2023-22456) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22456.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22456.svg)

## CVE-2023-22454
 Discourse is an option source discussion platform. Prior to version 2.8.14 on the `stable` branch and version 3.0.0.beta16 on the `beta` and `tests-passed` branches, pending post titles can be used for cross-site scripting attacks. Pending posts can be created by unprivileged users when a category has the &quot;require moderator approval of all new topics&quot; setting set. This vulnerability can lead to a full XSS on sites which have modified or disabled Discourse&#8217;s default Content Security Policy. A patch is available in versions 2.8.14 and 3.0.0.beta16.



- [https://github.com/Live-Hack-CVE/CVE-2023-22454](https://github.com/Live-Hack-CVE/CVE-2023-22454) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22454.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22454.svg)

## CVE-2023-22453
 Discourse is an option source discussion platform. Prior to version 2.8.14 on the `stable` branch and version 3.0.0.beta16 on the `beta` and `tests-passed` branches, the number of times a user posted in an arbitrary topic is exposed to unauthorized users through the `/u/username.json` endpoint. The issue is patched in version 2.8.14 and 3.0.0.beta16. There is no known workaround.



- [https://github.com/Live-Hack-CVE/CVE-2023-22453](https://github.com/Live-Hack-CVE/CVE-2023-22453) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22453.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22453.svg)

## CVE-2023-22452
 kenny2automate is a Discord bot. In the web interface for server settings, form elements were generated with Discord channel IDs as part of input names. Prior to commit a947d7c, no validation was performed to ensure that the channel IDs submitted actually belonged to the server being configured. Thus anyone who has access to the channel ID they wish to change settings for and the server settings panel for any server could change settings for the requested channel no matter which server it belonged to. Commit a947d7c resolves the issue and has been deployed to the official instance of the bot. The only workaround that exists is to disable the web config entirely by changing it to run on localhost. Note that a workaround is only necessary for those who run their own instance of the bot.



- [https://github.com/Live-Hack-CVE/CVE-2023-22452](https://github.com/Live-Hack-CVE/CVE-2023-22452) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22452.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22452.svg)

## CVE-2023-22451
 Kiwi TCMS is an open source test management system. In version 11.6 and prior, when users register new accounts and/or change passwords, there is no validation in place which would prevent them from picking an easy to guess password. This issue is resolved by providing defaults for the `AUTH_PASSWORD_VALIDATORS` configuration setting. As of version 11.7, the password can&#8217;t be too similar to other personal information, must contain at least 10 characters, can&#8217;t be a commonly used password, and can&#8217;t be entirely numeric. As a workaround, an administrator may reset all passwords in Kiwi TCMS if they think a weak password may have been chosen.



- [https://github.com/Live-Hack-CVE/CVE-2023-22451](https://github.com/Live-Hack-CVE/CVE-2023-22451) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22451.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22451.svg)

## CVE-2023-22422
 On BIG-IP versions 17.0.x before 17.0.0.2 and 16.1.x before 16.1.3.3, when a HTTP profile with the non-default Enforcement options of Enforce HTTP Compliance and Unknown Methods: Reject are configured on a virtual server, undisclosed requests can cause the Traffic Management Microkernel (TMM) to terminate. Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.



- [https://github.com/Live-Hack-CVE/CVE-2023-22422](https://github.com/Live-Hack-CVE/CVE-2023-22422) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22422.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22422.svg)

## CVE-2023-22418
 On versions 17.0.x before 17.0.0.2, 16.1.x before 16.1.3.3, 15.1.x before 15.1.7, 14.1.x before 14.1.5.3, and all versions of 13.1.x, an open redirect vulnerability exists on virtual servers enabled with a BIG-IP APM access policy. This vulnerability allows an unauthenticated malicious attacker to build an open redirect URI. Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.



- [https://github.com/Live-Hack-CVE/CVE-2023-22418](https://github.com/Live-Hack-CVE/CVE-2023-22418) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22418.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22418.svg)

## CVE-2023-22417
 A Missing Release of Memory after Effective Lifetime vulnerability in the Flow Processing Daemon (flowd) of Juniper Networks Junos OS allows a network-based, unauthenticated attacker to cause a Denial of Service (DoS). In an IPsec VPN environment, a memory leak will be seen if a DH or ECDH group is configured. Eventually the flowd process will crash and restart. This issue affects Juniper Networks Junos OS on SRX Series: All versions prior to 19.3R3-S7; 19.4 versions prior to 19.4R2-S8, 19.4R3-S10; 20.2 versions prior to 20.2R3-S6; 20.3 versions prior to 20.3R3-S5; 20.4 versions prior to 20.4R3-S5; 21.1 versions prior to 21.1R3-S4; 21.2 versions prior to 21.2R3; 21.3 versions prior to 21.3R3; 21.4 versions prior to 21.4R2.



- [https://github.com/Live-Hack-CVE/CVE-2023-22417](https://github.com/Live-Hack-CVE/CVE-2023-22417) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22417.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22417.svg)

## CVE-2023-22416
 A Buffer Overflow vulnerability in SIP ALG of Juniper Networks Junos OS allows a network-based, unauthenticated attacker to cause a Denial of Service (DoS). On all MX Series and SRX Series platform with SIP ALG enabled, when a malformed SIP packet is received, the flow processing daemon (flowd) will crash and restart. This issue affects: Juniper Networks Junos OS on MX Series and SRX Series 20.4 versions prior to 20.4R3-S5; 21.1 versions prior to 21.1R3-S4; 21.2 versions prior to 21.2R3-S2; 21.3 versions prior to 21.3R3-S1; 21.4 versions prior to 21.4R3; 22.1 versions prior to 22.1R1-S2, 22.1R2; 22.2 versions prior to 22.2R1-S1, 22.2R2. This issue does not affect Juniper Networks Junos OS versions prior to 20.4R1 on SRX Series.



- [https://github.com/Live-Hack-CVE/CVE-2023-22416](https://github.com/Live-Hack-CVE/CVE-2023-22416) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22416.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22416.svg)

## CVE-2023-22415
 An Out-of-Bounds Write vulnerability in the H.323 ALG of Juniper Networks Junos OS allows an unauthenticated, network-based attacker to cause Denial of Service (DoS). On all MX Series and SRX Series platform, when H.323 ALG is enabled and specific H.323 packets are received simultaneously, a flow processing daemon (flowd) crash will occur. Continued receipt of these specific packets will cause a sustained Denial of Service (DoS) condition. This issue affects: Juniper Networks Junos OS on MX Series and SRX Series All versions prior to 19.4R3-S10; 20.2 versions prior to 20.2R3-S6; 20.3 versions prior to 20.3R3-S6; 20.4 versions prior to 20.4R3-S5; 21.1 versions prior to 21.1R3-S4; 21.2 versions prior to 21.2R3-S3; 21.3 versions prior to 21.3R3-S3; 21.4 versions prior to 21.4R3; 22.1 versions prior to 22.1R2-S1, 22.1R3; 22.2 versions prior to 22.2R1-S2, 22.2R2.



- [https://github.com/Live-Hack-CVE/CVE-2023-22415](https://github.com/Live-Hack-CVE/CVE-2023-22415) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22415.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22415.svg)

## CVE-2023-22414
 A Missing Release of Memory after Effective Lifetime vulnerability in Flexible PIC Concentrator (FPC) of Juniper Networks Junos OS allows an adjacent, unauthenticated attacker from the same shared physical or logical network, to cause a heap memory leak and leading to FPC crash. On all Junos PTX Series and QFX10000 Series, when specific EVPN VXLAN Multicast packets are processed, an FPC heap memory leak is observed. The FPC memory usage can be monitored using the CLI command &quot;show heap extensive&quot;. Following is an example output. ID Base Total(b) Free(b) Used(b) % Name Peak used % -- -------- --------- --------- --------- --- ----------- ----------- 0 37dcf000 3221225472 1694526368 1526699104 47 Kernel 47 1 17dcf000 1048576 1048576 0 0 TOE DMA 0 2 17ecf000 1048576 1048576 0 0 DMA 0 3 17fcf000 534773760 280968336 253805424 47 Packet DMA 47 This issue affects: Juniper Networks Junos OS PTX Series and QFX10000 Series 20.2 versions prior to 20.2R3-S6; 20.3 versions prior to 20.3R3-S6; 20.4 versions prior to 20.4R3-S4; 21.1 versions prior to 21.1R3-S3; 21.2 versions prior to 21.2R3-S1; 21.3 versions prior to 21.3R3; 21.4 versions prior to 21.4R3; 22.1 versions prior to 22.1R2; 22.2 versions prior to 22.2R2. This issue does not affect Juniper Networks Junos OS versions prior to 20.1R1 on PTX Series and QFX10000 Series.



- [https://github.com/Live-Hack-CVE/CVE-2023-22414](https://github.com/Live-Hack-CVE/CVE-2023-22414) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22414.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22414.svg)

## CVE-2023-22413
 An Improper Check or Handling of Exceptional Conditions vulnerability in the IPsec library of Juniper Networks Junos OS allows a network-based, unauthenticated attacker to cause Denial of Service (DoS). On all MX platforms with MS-MPC or MS-MIC card, when specific IPv4 packets are processed by an IPsec6 tunnel, the Multiservices PIC Management Daemon (mspmand) process will core and restart. This will lead to FPC crash. Traffic flow is impacted while mspmand restarts. Continued receipt of these specific packets will cause a sustained Denial of Service (DoS) condition. This issue only occurs if an IPv4 address is not configured on the multiservice interface. This issue affects: Juniper Networks Junos OS on MX Series All versions prior to 19.4R3-S9; 20.1 version 20.1R3-S5 and later versions; 20.2 versions prior to 20.2R3-S5; 20.3 versions prior to 20.3R3-S5; 20.4 versions prior to 20.4R3-S4; 21.1 versions prior to 21.1R3-S3; 21.2 versions prior to 21.2R3-S1; 21.3 versions prior to 21.3R3; 21.4 versions prior to 21.4R2-S1, 21.4R3; 22.1 versions prior to 22.1R2.



- [https://github.com/Live-Hack-CVE/CVE-2023-22413](https://github.com/Live-Hack-CVE/CVE-2023-22413) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22413.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22413.svg)

## CVE-2023-22412
 An Improper Locking vulnerability in the SIP ALG of Juniper Networks Junos OS on MX Series with MS-MPC or MS-MIC card and SRX Series allows an unauthenticated, network-based attacker to cause a flow processing daemon (flowd) crash and thereby a Denial of Service (DoS). Continued receipt of these specific packets will cause a sustained Denial of Service condition. This issue occurs when SIP ALG is enabled and specific SIP messages are processed simultaneously. This issue affects: Juniper Networks Junos OS on MX Series and SRX Series 20.4 versions prior to 20.4R3-S4; 21.1 versions prior to 21.1R3-S3; 21.2 versions prior to 21.2R3-S2; 21.3 versions prior to 21.3R3; 21.4 versions prior to 21.4R3; 22.1 versions prior to 22.1R2. This issue does not affect Juniper Networks Junos OS versions prior to 20.4R1 on MX Series, or SRX Series.



- [https://github.com/Live-Hack-CVE/CVE-2023-22412](https://github.com/Live-Hack-CVE/CVE-2023-22412) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22412.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22412.svg)

## CVE-2023-22411
 An Out-of-Bounds Write vulnerability in Flow Processing Daemon (flowd) of Juniper Networks Junos OS allows an unauthenticated, network-based attacker to cause Denial of Service (DoS). On SRX Series devices using Unified Policies with IPv6, when a specific IPv6 packet goes through a dynamic-application filter which will generate an ICMP deny message, the flowd core is observed and the PFE is restarted. This issue affects: Juniper Networks Junos OS on SRX Series: 19.2 versions prior to 19.2R3-S6; 19.3 versions prior to 19.3R3-S6; 19.4 versions prior to 19.4R3-S9; 20.2 versions prior to 20.2R3-S5; 20.3 versions prior to 20.3R3-S4; 20.4 versions prior to 20.4R3-S3; 21.1 versions prior to 21.1R3; 21.2 versions prior to 21.2R3; 21.3 versions prior to 21.3R2; 21.4 versions prior to 21.4R2.



- [https://github.com/Live-Hack-CVE/CVE-2023-22411](https://github.com/Live-Hack-CVE/CVE-2023-22411) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22411.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22411.svg)

## CVE-2023-22410
 A Missing Release of Memory after Effective Lifetime vulnerability in the Juniper Networks Junos OS on MX Series platforms with MPC10/MPC11 line cards, allows an unauthenticated adjacent attacker to cause a Denial of Service (DoS). Devices are only vulnerable when the Suspicious Control Flow Detection (scfd) feature is enabled. Upon enabling this specific feature, an attacker sending specific traffic is causing memory to be allocated dynamically and it is not freed. Memory is not freed even after deactivating this feature. Sustained processing of such traffic will eventually lead to an out of memory condition that prevents all services from continuing to function, and requires a manual restart to recover. The FPC memory usage can be monitored using the CLI command &quot;show chassis fpc&quot;. On running the above command, the memory of AftDdosScfdFlow can be observed to detect the memory leak. This issue affects Juniper Networks Junos OS on MX Series: All versions prior to 20.2R3-S5; 20.3 version 20.3R1 and later versions.



- [https://github.com/Live-Hack-CVE/CVE-2023-22410](https://github.com/Live-Hack-CVE/CVE-2023-22410) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22410.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22410.svg)

## CVE-2023-22409
 An Unchecked Input for Loop Condition vulnerability in a NAT library of Juniper Networks Junos OS allows a local authenticated attacker with low privileges to cause a Denial of Service (DoS). When an inconsistent &quot;deterministic NAT&quot; configuration is present on an SRX, or MX with SPC3 and then a specific CLI command is issued the SPC will crash and restart. Repeated execution of this command will lead to a sustained DoS. Such a configuration is characterized by the total number of port blocks being greater than the total number of hosts. An example for such configuration is: [ services nat source pool TEST-POOL address x.x.x.0/32 to x.x.x.15/32 ] [ services nat source pool TEST-POOL port deterministic block-size 1008 ] [ services nat source pool TEST-POOL port deterministic host address y.y.y.0/24] [ services nat source pool TEST-POOL port deterministic include-boundary-addresses] where according to the following calculation: 65536-1024=64512 (number of usable ports per IP address, implicit) 64512/1008=64 (number of port blocks per Nat IP) x.x.x.0/32 to x.x.x.15/32 = 16 (NAT IP addresses available in NAT pool) total port blocks in NAT Pool = 64 blocks per IP * 16 IPs = 1024 Port blocks host address y.y.y.0/24 = 256 hosts (with include-boundary-addresses) If the port block size is configured to be 4032, then the total port blocks are (64512/4032) * 16 = 256 which is equivalent to the total host addresses of 256, and the issue will not be seen. This issue affects Juniper Networks Junos OS on SRX Series, and MX Series with SPC3: All versions prior to 19.4R3-S10; 20.1 version 20.1R1 and later versions; 20.2 versions prior to 20.2R3-S6; 20.3 versions prior to 20.3R3-S6; 20.4 versions prior to 20.4R3-S5; 21.1 versions prior to 21.1R3-S4; 21.2 versions prior to 21.2R3-S3; 21.3 versions prior to 21.3R3-S3; 21.4 versions prior to 21.4R3-S1; 22.1 versions prior to 22.1R2-S2, 22.1R3; 22.2 versions prior to 22.2R2.



- [https://github.com/Live-Hack-CVE/CVE-2023-22409](https://github.com/Live-Hack-CVE/CVE-2023-22409) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22409.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22409.svg)

## CVE-2023-22408
 An Improper Validation of Array Index vulnerability in the SIP ALG of Juniper Networks Junos OS on SRX 5000 Series allows a network-based, unauthenticated attacker to cause a Denial of Service (DoS). When an attacker sends an SIP packets with a malformed SDP field then the SIP ALG can not process it which will lead to an FPC crash and restart. Continued receipt of these specific packets will lead to a sustained Denial of Service. This issue can only occur when both below mentioned conditions are fulfilled: 1. Call distribution needs to be enabled: [security alg sip enable-call-distribution] 2. The SIP ALG needs to be enabled, either implicitly / by default or by way of configuration. To confirm whether SIP ALG is enabled on SRX, and MX with SPC3 use the following command: user@host&gt; show security alg status | match sip SIP : Enabled This issue affects Juniper Networks Junos OS on SRX 5000 Series: 20.4 versions prior to 20.4R3-S5; 21.1 versions prior to 21.1R3-S4; 21.2 versions prior to 21.2R3-S3; 21.3 versions prior to 21.3R3-S3; 21.4 versions prior to 21.4R3-S2; 22.1 versions prior to 22.1R2-S2, 22.1R3; 22.2 versions prior to 22.2R3; 22.3 versions prior to 22.3R1-S1, 22.3R2. This issue does not affect Juniper Networks Junos OS versions prior to 20.4R1.



- [https://github.com/Live-Hack-CVE/CVE-2023-22408](https://github.com/Live-Hack-CVE/CVE-2023-22408) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22408.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22408.svg)

## CVE-2023-22407
 An Incomplete Cleanup vulnerability in the Routing Protocol Daemon (rpd) of Juniper Networks Junos OS and Junos OS Evolved allows an adjacent, unauthenticated attacker to cause a Denial of Service (DoS). An rpd crash can occur when an MPLS TE tunnel configuration change occurs on a directly connected router. This issue affects: Juniper Networks Junos OS All versions prior to 18.4R2-S7; 19.1 versions prior to 19.1R3-S2; 19.2 versions prior to 19.2R3; 19.3 versions prior to 19.3R3; 19.4 versions prior to 19.4R3; 20.1 versions prior to 20.1R2; 20.2 versions prior to 20.2R2. Juniper Networks Junos OS Evolved All versions prior to 19.2R3-EVO; 19.3 versions prior to 19.3R3-EVO; 19.4 versions prior to 19.4R3-EVO; 20.1 versions prior to 20.1R3-EVO; 20.2 versions prior to 20.2R2-EVO.



- [https://github.com/Live-Hack-CVE/CVE-2023-22407](https://github.com/Live-Hack-CVE/CVE-2023-22407) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22407.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22407.svg)

## CVE-2023-22406
 A Missing Release of Memory after Effective Lifetime vulnerability in the kernel of Juniper Networks Junos OS and Junos OS Evolved allows an adjacent, unauthenticated attacker to cause a Denial of Service (DoS). In a segment-routing scenario with OSPF as IGP, when a peer interface continuously flaps, next-hop churn will happen and a continuous increase in Routing Protocol Daemon (rpd) memory consumption will be observed. This will eventually lead to an rpd crash and restart when the memory is full. The memory consumption can be monitored using the CLI command &quot;show task memory detail&quot; as shown in the following example: user@host&gt; show task memory detail | match &quot;RT_NEXTHOPS_TEMPLATE|RT_TEMPLATE_BOOK_KEE&quot; RT_NEXTHOPS_TEMPLATE 1008 1024 T 50 51200 50 51200 RT_NEXTHOPS_TEMPLATE 688 768 T 50 38400 50 38400 RT_NEXTHOPS_TEMPLATE 368 384 T 412330 158334720 412330 158334720 RT_TEMPLATE_BOOK_KEE 2064 2560 T 33315 85286400 33315 85286400 user@host&gt; show task memory detail | match &quot;RT_NEXTHOPS_TEMPLATE|RT_TEMPLATE_BOOK_KEE&quot; RT_NEXTHOPS_TEMPLATE 1008 1024 T 50 51200 50 51200 RT_NEXTHOPS_TEMPLATE 688 768 T 50 38400 50 38400 RT_NEXTHOPS_TEMPLATE 368 384 T 419005 160897920 419005 160897920 &lt;=== RT_TEMPLATE_BOOK_KEE 2064 2560 T 39975 102336000 39975 10233600 &lt;=== This issue affects: Juniper Networks Junos OS All versions prior to 19.3R3-S7; 19.4 versions prior to 19.4R2-S8, 19.4R3-S9; 20.2 versions prior to 20.2R3-S5; 20.3 versions prior to 20.3R3-S5; 20.4 versions prior to 20.4R3-S4; 21.1 versions prior to 21.1R3-S3; 21.2 versions prior to 21.2R3-S2; 21.3 versions prior to 21.3R3-S1; 21.4 versions prior to 21.4R2-S1, 21.4R3; 22.1 versions prior to 22.1R2. Juniper Networks Junos OS Evolved All versions prior to 20.4R3-S4-EVO; 21.4 versions prior to 21.4R2-S1-EVO, 21.4R3-EVO; 22.1 versions prior to 22.1R2-EVO.



- [https://github.com/Live-Hack-CVE/CVE-2023-22406](https://github.com/Live-Hack-CVE/CVE-2023-22406) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22406.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22406.svg)

## CVE-2023-22405
 An Improper Preservation of Consistency Between Independent Representations of Shared State vulnerability in the Packet Forwarding Engine (PFE) of Juniper Networks Junos OS allows an adjacent, unauthenticated attacker to cause a Denial of Service (DoS) to device due to out of resources. When a device is configured with &quot;service-provider/SP style&quot; switching, and mac-limiting is configured on an Aggregated Ethernet (ae) interface, and then a PFE is restarted or the device is rebooted, mac-limiting doesn't work anymore. Please note that the issue might not be apparent as traffic will continue to flow through the device although the mac table and respective logs will indicate that mac limit is reached. Functionality can be restored by removing and re-adding the MAC limit configuration. This issue affects Juniper Networks Junos OS on QFX5k Series, EX46xx Series: All versions prior to 20.2R3-S5; 20.3 versions prior to 20.3R3-S5; 20.4 versions prior to 20.4R3-S4; 21.1 versions prior to 21.1R3-S3; 21.2 versions prior to 21.2R3-S1; 21.3 versions prior to 21.3R3 on; 21.4 versions prior to 21.4R3 on; 22.1 versions prior to 22.1R2 on.



- [https://github.com/Live-Hack-CVE/CVE-2023-22405](https://github.com/Live-Hack-CVE/CVE-2023-22405) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22405.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22405.svg)

## CVE-2023-22404
 An Out-of-bounds Write vulnerability in the Internet Key Exchange Protocol daemon (iked) of Juniper Networks Junos OS on SRX series and MX with SPC3 allows an authenticated, network-based attacker to cause a Denial of Service (DoS). iked will crash and restart, and the tunnel will not come up when a peer sends a specifically formatted payload during the negotiation. This will impact other IKE negotiations happening at the same time. Continued receipt of this specifically formatted payload will lead to continuous crashing of iked and thereby the inability for any IKE negotiations to take place. Note that this payload is only processed after the authentication has successfully completed. So the issue can only be exploited by an attacker who can successfully authenticate. This issue affects Juniper Networks Junos OS on SRX Series, and MX Series with SPC3: All versions prior to 19.3R3-S7; 19.4 versions prior to 19.4R3-S9; 20.2 versions prior to 20.2R3-S5; 20.3 versions prior to 20.3R3-S5; 20.4 versions prior to 20.4R3-S4; 21.1 versions prior to 21.1R3-S3; 21.2 versions prior to 21.2R3-S2; 21.3 versions prior to 21.3R3-S1; 21.4 versions prior to 21.4R2-S1, 21.4R3; 22.1 versions prior to 22.1R1-S2, 22.1R2.



- [https://github.com/Live-Hack-CVE/CVE-2023-22404](https://github.com/Live-Hack-CVE/CVE-2023-22404) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22404.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22404.svg)

## CVE-2023-22403
 An Allocation of Resources Without Limits or Throttling vulnerability in the Packet Forwarding Engine (PFE) of Juniper Networks Junos OS allows a network-based, unauthenticated attacker to cause a Denial of Service (DoS). On QFX10k Series Inter-Chassis Control Protocol (ICCP) is used in MC-LAG topologies to exchange control information between the devices in the topology. ICCP connection flaps and sync issues will be observed due to excessive specific traffic to the local device. This issue affects Juniper Networks Junos OS: All versions prior to 20.2R3-S7; 20.4 versions prior to 20.4R3-S4; 21.1 versions prior to 21.1R3-S3; 21.2 versions prior to 21.2R3-S1; 21.3 versions prior to 21.3R3; 21.4 versions prior to 21.4R3; 22.1 versions prior to 22.1R2.



- [https://github.com/Live-Hack-CVE/CVE-2023-22403](https://github.com/Live-Hack-CVE/CVE-2023-22403) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22403.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22403.svg)

## CVE-2023-22402
 A Use After Free vulnerability in the kernel of Juniper Networks Junos OS Evolved allows an unauthenticated, network-based attacker to cause a Denial of Service (DoS). In a Non Stop Routing (NSR) scenario, an unexpected kernel restart might be observed if &quot;bgp auto-discovery&quot; is enabled and if there is a BGP neighbor flap of auto-discovery sessions for any reason. This is a race condition which is outside of an attackers direct control and it depends on system internal timing whether this issue occurs. This issue affects Juniper Networks Junos OS Evolved: 21.3 versions prior to 21.3R3-EVO; 21.4 versions prior to 21.4R2-EVO; 22.1 versions prior to 22.1R2-EVO; 22.2 versions prior to 22.2R1-S1-EVO, 22.2R2-EVO.



- [https://github.com/Live-Hack-CVE/CVE-2023-22402](https://github.com/Live-Hack-CVE/CVE-2023-22402) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22402.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22402.svg)

## CVE-2023-22401
 An Improper Validation of Array Index vulnerability in the Advanced Forwarding Toolkit Manager daemon (aftmand) of Juniper Networks Junos OS and Junos OS Evolved allows an unauthenticated, network-based attacker to cause a Denial of Service (DoS). On the PTX10008 and PTX10016 platforms running Junos OS or Junos OS Evolved, when a specific SNMP MIB is queried this will cause a PFE crash and the FPC will go offline and not automatically recover. A system restart is required to get the affected FPC in an operational state again. This issue affects: Juniper Networks Junos OS 22.1 version 22.1R2 and later versions; 22.1 versions prior to 22.1R3; 22.2 versions prior to 22.2R2. Juniper Networks Junos OS Evolved 21.3-EVO version 21.3R3-EVO and later versions; 21.4-EVO version 21.4R1-S2-EVO, 21.4R2-EVO and later versions prior to 21.4R2-S1-EVO; 22.1-EVO version 22.1R2-EVO and later versions prior to 22.1R3-EVO; 22.2-EVO versions prior to 22.2R1-S1-EVO, 22.2R2-EVO.



- [https://github.com/Live-Hack-CVE/CVE-2023-22401](https://github.com/Live-Hack-CVE/CVE-2023-22401) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22401.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22401.svg)

## CVE-2023-22400
 An Uncontrolled Resource Consumption vulnerability in the PFE management daemon (evo-pfemand) of Juniper Networks Junos OS Evolved allows an unauthenticated, network-based attacker to cause an FPC crash leading to a Denial of Service (DoS). When a specific SNMP GET operation or a specific CLI command is executed this will cause a GUID resource leak, eventually leading to exhaustion and result in an FPC crash and reboot. GUID exhaustion will trigger a syslog message like one of the following for example: evo-pfemand[&lt;pid&gt;]: get_next_guid: Ran out of Guid Space ... evo-aftmand-zx[&lt;pid&gt;]: get_next_guid: Ran out of Guid Space ... This leak can be monitored by running the following command and taking note of the value in the rightmost column labeled Guids: user@host&gt; show platform application-info allocations app evo-pfemand | match &quot;IFDId|IFLId|Context&quot; Node Application Context Name Live Allocs Fails Guids re0 evo-pfemand net::juniper::interfaces::IFDId 0 3448 0 3448 re0 evo-pfemand net::juniper::interfaces::IFLId 0 561 0 561 user@host&gt; show platform application-info allocations app evo-pfemand | match &quot;IFDId|IFLId|Context&quot; Node Application Context Name Live Allocs Fails Guids re0 evo-pfemand net::juniper::interfaces::IFDId 0 3784 0 3784 re0 evo-pfemand net::juniper::interfaces::IFLId 0 647 0 647 This issue affects Juniper Networks Junos OS Evolved: All versions prior to 20.4R3-S3-EVO; 21.1-EVO version 21.1R1-EVO and later versions; 21.2-EVO versions prior to 21.2R3-S4-EVO; 21.3-EVO version 21.3R1-EVO and later versions; 21.4-EVO versions prior to 21.4R2-EVO.



- [https://github.com/Live-Hack-CVE/CVE-2023-22400](https://github.com/Live-Hack-CVE/CVE-2023-22400) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22400.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22400.svg)

## CVE-2023-22399
 When sFlow is enabled and it monitors a packet forwarded via ECMP, a buffer management vulnerability in the dcpfe process of Juniper Networks Junos OS on QFX10K Series systems allows an attacker to cause the Packet Forwarding Engine (PFE) to crash and restart by sending specific genuine packets to the device, resulting in a Denial of Service (DoS) condition. The dcpfe process tries to copy more data into a smaller buffer, which overflows and corrupts the buffer, causing a crash of the dcpfe process. Continued receipt and processing of these packets will create a sustained Denial of Service (DoS) condition. This issue affects Juniper Networks Junos OS on QFX10K Series: All versions prior to 19.4R3-S9; 20.2 versions prior to 20.2R3-S6; 20.3 versions prior to 20.3R3-S6; 20.4 versions prior to 20.4R3-S5; 21.1 versions prior to 21.1R3-S4; 21.2 versions prior to 21.2R3-S3; 21.3 versions prior to 21.3R3-S2; 21.4 versions prior to 21.4R2-S2, 21.4R3; 22.1 versions prior to 22.1R2; 22.2 versions prior to 22.2R1-S2, 22.2R2.



- [https://github.com/Live-Hack-CVE/CVE-2023-22399](https://github.com/Live-Hack-CVE/CVE-2023-22399) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22399.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22399.svg)

## CVE-2023-22398
 An Access of Uninitialized Pointer vulnerability in the Routing Protocol Daemon (rpd) of Juniper Networks Junos OS and Junos OS Evolved allows a locally authenticated attacker with low privileges to cause a Denial of Service (DoS). When an MPLS ping is performed on BGP LSPs, the RPD might crash. Repeated execution of this operation will lead to a sustained DoS. This issue affects: Juniper Networks Junos OS: 15.1 versions prior to 15.1R7-S12; 19.1 versions prior to 19.1R3-S9; 19.2 versions prior to 19.2R1-S9, 19.2R3-S5; 19.3 versions prior to 19.3R3-S6; 19.4 versions prior to 19.4R2-S7, 19.4R3-S8; 20.1 versions prior to 20.1R3-S4; 20.2 versions prior to 20.2R3-S5; 20.3 versions prior to 20.3R3-S5; 20.4 versions prior to 20.4R3-S4; 21.1 versions prior to 21.1R1-S1, 21.1R2; Juniper Networks Junos OS Evolved: All versions prior to 20.4R3-S4; 21.1 versions prior to 21.1R2-EVO.



- [https://github.com/Live-Hack-CVE/CVE-2023-22398](https://github.com/Live-Hack-CVE/CVE-2023-22398) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22398.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22398.svg)

## CVE-2023-22397
 An Allocation of Resources Without Limits or Throttling weakness in the memory management of the Packet Forwarding Engine (PFE) on Juniper Networks Junos OS Evolved PTX10003 Series devices allows an adjacently located attacker who has established certain preconditions and knowledge of the environment to send certain specific genuine packets to begin a Time-of-check Time-of-use (TOCTOU) Race Condition attack which will cause a memory leak to begin. Once this condition begins, and as long as the attacker is able to sustain the offending traffic, a Distributed Denial of Service (DDoS) event occurs. As a DDoS event, the offending packets sent by the attacker will continue to flow from one device to another as long as they are received and processed by any devices, ultimately causing a cascading outage to any vulnerable devices. Devices not vulnerable to the memory leak will process and forward the offending packet(s) to neighboring devices. Due to internal anti-flood security controls and mechanisms reaching their maximum limit of response in the worst-case scenario, all affected Junos OS Evolved devices will reboot in as little as 1.5 days. Reboots to restore services cannot be avoided once the memory leak begins. The device will self-recover after crashing and rebooting. Operator intervention isn't required to restart the device. This issue affects: Juniper Networks Junos OS Evolved on PTX10003: All versions prior to 20.4R3-S4-EVO; 21.3 versions prior to 21.3R3-S1-EVO; 21.4 versions prior to 21.4R2-S2-EVO, 21.4R3-EVO; 22.1 versions prior to 22.1R1-S2-EVO, 22.1R2-EVO; 22.2 versions prior to 22.2R2-EVO. To check memory, customers may VTY to the PFE first then execute the following show statement: show jexpr jtm ingress-main-memory chip 255 | no-more Alternatively one may execute from the RE CLI: request pfe execute target fpc0 command &quot;show jexpr jtm ingress-main-memory chip 255 | no-more&quot; Iteration 1: Example output: Mem type: NH, alloc type: JTM 136776 bytes used (max 138216 bytes used) 911568 bytes available (909312 bytes from free pages) Iteration 2: Example output: Mem type: NH, alloc type: JTM 137288 bytes used (max 138216 bytes used) 911056 bytes available (909312 bytes from free pages) The same can be seen in the CLI below, assuming the scale does not change: show npu memory info Example output: FPC0:NPU16 mem-util-jnh-nh-size 2097152 FPC0:NPU16 mem-util-jnh-nh-allocated 135272 FPC0:NPU16 mem-util-jnh-nh-utilization 6



- [https://github.com/Live-Hack-CVE/CVE-2023-22397](https://github.com/Live-Hack-CVE/CVE-2023-22397) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22397.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22397.svg)

## CVE-2023-22395
 A Missing Release of Memory after Effective Lifetime vulnerability in the kernel of Juniper Networks Junos OS allows an unauthenticated, adjacent attacker to cause a Denial of Service (DoS). In an MPLS scenario specific packets destined to an Integrated Routing and Bridging (irb) interface of the device will cause a buffer (mbuf) to leak. Continued receipt of these specific packets will eventually cause a loss of connectivity to and from the device, and requires a reboot to recover. These mbufs can be monitored by using the CLI command 'show system buffers': user@host&gt; show system buffers 783/1497/2280 mbufs in use (current/cache/total) user@host&gt; show system buffers 793/1487/2280 mbufs in use (current/cache/total) &lt;&lt;&lt;&lt;&lt;&lt; mbuf usage increased This issue affects Juniper Networks Junos OS: All versions prior to 19.3R3-S7; 19.4 versions prior to 19.4R3-S9; 20.1 version 20.1R1 and later versions; 20.2 versions prior to 20.2R3-S5; 20.3 versions prior to 20.3R3-S5; 20.4 versions prior to 20.4R3-S4; 21.1 versions prior to 21.1R3-S3; 21.2 versions prior to 21.2R3-S2; 21.3 versions prior to 21.3R3-S1; 21.4 versions prior to 21.4R3; 22.1 versions prior to 22.1R2.



- [https://github.com/Live-Hack-CVE/CVE-2023-22395](https://github.com/Live-Hack-CVE/CVE-2023-22395) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22395.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22395.svg)

## CVE-2023-22389
 Snap One Wattbox WB-300-IP-3 versions WB10.9a17 and prior store passwords in a plaintext file when the device configuration is exported via Save/Restore&#8211;&gt;Backup Settings, which could be read by any user accessing the file.



- [https://github.com/Live-Hack-CVE/CVE-2023-22389](https://github.com/Live-Hack-CVE/CVE-2023-22389) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22389.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22389.svg)

## CVE-2023-22374
 In BIG-IP starting in versions 17.0.0, 16.1.2.2, 15.1.5.1, 14.1.4.6, and 13.1.5 on their respective branches, a format string vulnerability exists in iControl SOAP that allows an authenticated attacker to crash the iControl SOAP CGI process or, potentially execute arbitrary code. In appliance mode BIG-IP, a successful exploit of this vulnerability can allow the attacker to cross a security boundary. Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.



- [https://github.com/Live-Hack-CVE/CVE-2023-22374](https://github.com/Live-Hack-CVE/CVE-2023-22374) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22374.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22374.svg)

## CVE-2023-22373
 Cross-site scripting vulnerability in CONPROSYS HMI System (CHS) Ver.3.4.5 and earlier allows a remote authenticated attacker to inject an arbitrary script and obtain the sensitive information.



- [https://github.com/Live-Hack-CVE/CVE-2023-22373](https://github.com/Live-Hack-CVE/CVE-2023-22373) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22373.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22373.svg)

## CVE-2023-22366
 CX-Motion-MCH v2.32 and earlier contains an access of uninitialized pointer vulnerability. Having a user to open a specially crafted project file may lead to information disclosure and/or arbitrary code execution.



- [https://github.com/Live-Hack-CVE/CVE-2023-22366](https://github.com/Live-Hack-CVE/CVE-2023-22366) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22366.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22366.svg)

## CVE-2023-22358
 In versions beginning with 7.2.2 to before 7.2.3.1, a DLL hijacking vulnerability exists in the BIG-IP Edge Client Windows Installer. Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.



- [https://github.com/Live-Hack-CVE/CVE-2023-22358](https://github.com/Live-Hack-CVE/CVE-2023-22358) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22358.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22358.svg)

## CVE-2023-22357
 Active debug code exists in OMRON CP1L-EL20DR-D all versions, which may lead to a command that is not specified in FINS protocol being executed without authentication. A remote unauthenticated attacker may read/write in arbitrary area of the device memory, which may lead to overwriting the firmware, causing a denial-of-service (DoS) condition, and/or arbitrary code execution.



- [https://github.com/Live-Hack-CVE/CVE-2023-22357](https://github.com/Live-Hack-CVE/CVE-2023-22357) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22357.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22357.svg)

## CVE-2023-22341
 On version 14.1.x before 14.1.5.3, and all versions of 13.1.x, when the BIG-IP APM system is configured with all the following elements, undisclosed requests may cause the Traffic Management Microkernel (TMM) to terminate: * An OAuth Server that references an OAuth Provider * An OAuth profile with the Authorization Endpoint set to '/' * An access profile that references the above OAuth profile and is associated with an HTTPS virtual server Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.



- [https://github.com/Live-Hack-CVE/CVE-2023-22341](https://github.com/Live-Hack-CVE/CVE-2023-22341) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22341.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22341.svg)

## CVE-2023-22340
 On BIG-IP versions 16.1.x before 16.1.3.3, 15.1.x before 15.1.8, 14.1.x before 14.1.5.3, and all versions of 13.1.x, when a SIP profile is configured on a Message Routing type virtual server, undisclosed traffic can cause TMM to terminate. Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.



- [https://github.com/Live-Hack-CVE/CVE-2023-22340](https://github.com/Live-Hack-CVE/CVE-2023-22340) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22340.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22340.svg)

## CVE-2023-22339
 Improper access control vulnerability in CONPROSYS HMI System (CHS) Ver.3.4.5 and earlier allows a remote unauthenticated attacker to bypass access restriction and obtain the server certificate including the private key of the product.



- [https://github.com/Live-Hack-CVE/CVE-2023-22339](https://github.com/Live-Hack-CVE/CVE-2023-22339) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22339.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22339.svg)

## CVE-2023-22334
 Use of password hash instead of password for authentication vulnerability in CONPROSYS HMI System (CHS) Ver.3.4.5 and earlier allows a remote authenticated attacker to obtain user credentials information via a man-in-the-middle attack.



- [https://github.com/Live-Hack-CVE/CVE-2023-22334](https://github.com/Live-Hack-CVE/CVE-2023-22334) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22334.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22334.svg)

## CVE-2023-22333
 Cross-site scripting vulnerability in EasyMail 2.00.130 and earlier allows a remote unauthenticated attacker to inject an arbitrary script.



- [https://github.com/Live-Hack-CVE/CVE-2023-22333](https://github.com/Live-Hack-CVE/CVE-2023-22333) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22333.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22333.svg)

## CVE-2023-22332
 Information disclosure vulnerability exists in Pgpool-II 4.4.0 to 4.4.1 (4.4 series), 4.3.0 to 4.3.4 (4.3 series), 4.2.0 to 4.2.11 (4.2 series), 4.1.0 to 4.1.14 (4.1 series), 4.0.0 to 4.0.21 (4.0 series), All versions of 3.7 series, All versions of 3.6 series, All versions of 3.5 series, All versions of 3.4 series, and All versions of 3.3 series. A specific database user's authentication information may be obtained by another database user. As a result, the information stored in the database may be altered and/or database may be suspended by a remote attacker who successfully logged in the product with the obtained credentials.



- [https://github.com/Live-Hack-CVE/CVE-2023-22332](https://github.com/Live-Hack-CVE/CVE-2023-22332) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22332.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22332.svg)

## CVE-2023-22331
 Use of default credentials vulnerability in CONPROSYS HMI System (CHS) Ver.3.4.5 and earlier allows a remote unauthenticated attacker to alter user credentials information.



- [https://github.com/Live-Hack-CVE/CVE-2023-22331](https://github.com/Live-Hack-CVE/CVE-2023-22331) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22331.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22331.svg)

## CVE-2023-22326
 In BIG-IP versions 17.0.x before 17.0.0.2, 16.1.x before 16.1.3.3, 15.1.x before 15.1.8.1, 14.1.x before 14.1.5.3, and all versions of 13.1.x, and all versions of BIG-IQ 8.x and 7.1.x, incorrect permission assignment vulnerabilities exist in the iControl REST and TMOS shell (tmsh) dig command which may allow an authenticated attacker with resource administrator or administrator role privileges to view sensitive information. Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.



- [https://github.com/Live-Hack-CVE/CVE-2023-22326](https://github.com/Live-Hack-CVE/CVE-2023-22326) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22326.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22326.svg)

## CVE-2023-22324
 SQL injection vulnerability in the CONPROSYS HMI System (CHS) Ver.3.5.0 and earlier allows a remote authenticated attacker to execute an arbitrary SQL command. As a result, information stored in the database may be obtained.



- [https://github.com/Live-Hack-CVE/CVE-2023-22324](https://github.com/Live-Hack-CVE/CVE-2023-22324) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22324.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22324.svg)

## CVE-2023-22323
 In BIP-IP versions 17.0.x before 17.0.0.2, 16.1.x before 16.1.3.3, 15.1.x before 15.1.8.1, 14.1.x before 14.1.5.3, and all versions of 13.1.x, when OCSP authentication profile is configured on a virtual server, undisclosed requests can cause an increase in CPU resource utilization. Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.



- [https://github.com/Live-Hack-CVE/CVE-2023-22323](https://github.com/Live-Hack-CVE/CVE-2023-22323) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22323.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22323.svg)

## CVE-2023-22322
 Improper restriction of XML external entity reference (XXE) vulnerability exists in OMRON CX-Motion Pro 1.4.6.013 and earlier. If a user opens a specially crafted project file created by an attacker, sensitive information in the file system where CX-Motion Pro is installed may be disclosed.



- [https://github.com/Live-Hack-CVE/CVE-2023-22322](https://github.com/Live-Hack-CVE/CVE-2023-22322) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22322.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22322.svg)

## CVE-2023-22320
 OpenAM Web Policy Agent (OpenAM Consortium Edition) provided by OpenAM Consortium parses URLs improperly, leading to a path traversal vulnerability(CWE-22). Furthermore, a crafted URL may be evaluated incorrectly.



- [https://github.com/Live-Hack-CVE/CVE-2023-22320](https://github.com/Live-Hack-CVE/CVE-2023-22320) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22320.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22320.svg)

## CVE-2023-22316
 Hidden functionality vulnerability in PIX-RT100 versions RT100_TEQ_2.1.1_EQ101 and RT100_TEQ_2.1.2_EQ101 allows a network-adjacent attacker to access the product via undocumented Telnet or SSH services.



- [https://github.com/Live-Hack-CVE/CVE-2023-22316](https://github.com/Live-Hack-CVE/CVE-2023-22316) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22316.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22316.svg)

## CVE-2023-22315
 Snap One Wattbox WB-300-IP-3 versions WB10.9a17 and prior use a proprietary local area network (LAN) protocol that does not verify updates to the device. An attacker could upload a malformed update file to the device and execute arbitrary code.



- [https://github.com/Live-Hack-CVE/CVE-2023-22315](https://github.com/Live-Hack-CVE/CVE-2023-22315) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22315.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22315.svg)

## CVE-2023-22304
 OS command injection vulnerability in PIX-RT100 versions RT100_TEQ_2.1.1_EQ101 and RT100_TEQ_2.1.2_EQ101 allows a network-adjacent attacker who can access product settings to execute an arbitrary OS command.



- [https://github.com/Live-Hack-CVE/CVE-2023-22304](https://github.com/Live-Hack-CVE/CVE-2023-22304) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22304.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22304.svg)

## CVE-2023-22303
 TP-Link SG105PE firmware prior to 'TL-SG105PE(UN) 1.0_1.0.0 Build 20221208' contains an authentication bypass vulnerability. Under the certain conditions, an attacker may impersonate an administrator of the product. As a result, information may be obtained and/or the product's settings may be altered with the privilege of the administrator.



- [https://github.com/Live-Hack-CVE/CVE-2023-22303](https://github.com/Live-Hack-CVE/CVE-2023-22303) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22303.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22303.svg)

## CVE-2023-22302
 In BIG-IP versions 17.0.x before 17.0.0.2, and 16.1.x beginning in 16.1.2.2 to before 16.1.3.3, when an HTTP profile is configured on a virtual server and conditions beyond the attacker&#8217;s control exist on the target pool member, undisclosed requests sent to the BIG-IP system can cause the Traffic Management Microkernel (TMM) to terminate. Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.



- [https://github.com/Live-Hack-CVE/CVE-2023-22302](https://github.com/Live-Hack-CVE/CVE-2023-22302) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22302.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22302.svg)

## CVE-2023-22298
 Open redirect vulnerability in pgAdmin 4 versions prior to v6.14 allows a remote unauthenticated attacker to redirect a user to an arbitrary web site and conduct a phishing attack by having a user to access a specially crafted URL.



- [https://github.com/Live-Hack-CVE/CVE-2023-22298](https://github.com/Live-Hack-CVE/CVE-2023-22298) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22298.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22298.svg)

## CVE-2023-22296
 Reflected cross-site scripting vulnerability in MAHO-PBX NetDevancer series MAHO-PBX NetDevancer Lite/Uni/Pro/Cloud prior to Ver.1.11.00, MAHO-PBX NetDevancer VSG Lite/Uni prior to Ver.1.11.00, and MAHO-PBX NetDevancer MobileGate Home/Office prior to Ver.1.11.00 allows a remote unauthenticated attacker to inject an arbitrary script.



- [https://github.com/Live-Hack-CVE/CVE-2023-22296](https://github.com/Live-Hack-CVE/CVE-2023-22296) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22296.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22296.svg)

## CVE-2023-22286
 Cross-site request forgery (CSRF) vulnerability in MAHO-PBX NetDevancer Lite/Uni/Pro/Cloud prior to Ver.1.11.00, MAHO-PBX NetDevancer VSG Lite/Uni prior to Ver.1.11.00, and MAHO-PBX NetDevancer MobileGate Home/Office prior to Ver.1.11.00 allows a remote unauthenticated attacker to hijack the user authentication and conduct user's unintended operations by having a user to view a malicious page while logged in.



- [https://github.com/Live-Hack-CVE/CVE-2023-22286](https://github.com/Live-Hack-CVE/CVE-2023-22286) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22286.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22286.svg)

## CVE-2023-22283
 On versions beginning in 7.1.5 to before 7.2.3.1, a DLL hijacking vulnerability exists in the BIG-IP Edge Client for Windows. User interaction and administrative privileges are required to exploit this vulnerability because the victim user needs to run the executable on the system and the attacker requires administrative privileges for modifying the files in the trusted search path. Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.



- [https://github.com/Live-Hack-CVE/CVE-2023-22283](https://github.com/Live-Hack-CVE/CVE-2023-22283) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22283.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22283.svg)

## CVE-2023-22281
 On versions 17.0.x before 17.0.0.2, 16.1.x before 16.1.3.3, 15.1.x before 15.1.8, 14.1.x before 14.1.5.3, and all versions of 13.1.x, when a BIG-IP AFM NAT policy with a destination NAT rule is configured on a FastL4 virtual server, undisclosed traffic can cause the Traffic Management Microkernel (TMM) to terminate. Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.



- [https://github.com/Live-Hack-CVE/CVE-2023-22281](https://github.com/Live-Hack-CVE/CVE-2023-22281) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22281.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22281.svg)

## CVE-2023-22280
 MAHO-PBX NetDevancer Lite/Uni/Pro/Cloud prior to Ver.1.11.00, MAHO-PBX NetDevancer VSG Lite/Uni prior to Ver.1.11.00, and MAHO-PBX NetDevancer MobileGate Home/Office prior to Ver.1.11.00 allow a remote authenticated attacker with an administrative privilege to execute an arbitrary OS command.



- [https://github.com/Live-Hack-CVE/CVE-2023-22280](https://github.com/Live-Hack-CVE/CVE-2023-22280) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22280.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22280.svg)

## CVE-2023-22279
 MAHO-PBX NetDevancer Lite/Uni/Pro/Cloud prior to Ver.1.11.00, MAHO-PBX NetDevancer VSG Lite/Uni prior to Ver.1.11.00, and MAHO-PBX NetDevancer MobileGate Home/Office prior to Ver.1.11.00 allow a remote unauthenticated attacker to execute an arbitrary OS command.



- [https://github.com/Live-Hack-CVE/CVE-2023-22279](https://github.com/Live-Hack-CVE/CVE-2023-22279) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22279.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22279.svg)

## CVE-2023-22278
 m-FILTER prior to Ver.5.70R01 (Ver.5 Series) and m-FILTER prior to Ver.4.87R04 (Ver.4 Series) allows a remote unauthenticated attacker to bypass authentication and send users' unintended email when email is being sent under the certain conditions. The attacks exploiting this vulnerability have been observed.



- [https://github.com/Live-Hack-CVE/CVE-2023-22278](https://github.com/Live-Hack-CVE/CVE-2023-22278) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22278.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22278.svg)

## CVE-2023-22242
 Adobe Acrobat Reader versions 22.003.20282 (and earlier), 22.003.20281 (and earlier) and 20.005.30418 (and earlier) are affected by an out-of-bounds write vulnerability that could result in arbitrary code execution in the context of the current user. Exploitation of this issue requires user interaction in that a victim must open a malicious file.



- [https://github.com/Live-Hack-CVE/CVE-2023-22242](https://github.com/Live-Hack-CVE/CVE-2023-22242) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22242.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22242.svg)

## CVE-2023-22241
 Adobe Acrobat Reader versions 22.003.20282 (and earlier), 22.003.20281 (and earlier) and 20.005.30418 (and earlier) are affected by an out-of-bounds write vulnerability that could result in arbitrary code execution in the context of the current user. Exploitation of this issue requires user interaction in that a victim must open a malicious file.



- [https://github.com/Live-Hack-CVE/CVE-2023-22241](https://github.com/Live-Hack-CVE/CVE-2023-22241) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22241.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22241.svg)

## CVE-2023-22240
 Adobe Acrobat Reader versions 22.003.20282 (and earlier), 22.003.20281 (and earlier) and 20.005.30418 (and earlier) are affected by an out-of-bounds write vulnerability that could result in arbitrary code execution in the context of the current user. Exploitation of this issue requires user interaction in that a victim must open a malicious file.



- [https://github.com/Live-Hack-CVE/CVE-2023-22240](https://github.com/Live-Hack-CVE/CVE-2023-22240) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22240.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22240.svg)

## CVE-2023-21900
 Vulnerability in the Oracle Solaris product of Oracle Systems (component: NSSwitch). Supported versions that are affected are 10 and 11. Difficult to exploit vulnerability allows high privileged attacker with network access via multiple protocols to compromise Oracle Solaris. Successful attacks require human interaction from a person other than the attacker and while the vulnerability is in Oracle Solaris, attacks may significantly impact additional products (scope change). Successful attacks of this vulnerability can result in unauthorized update, insert or delete access to some of Oracle Solaris accessible data and unauthorized ability to cause a partial denial of service (partial DOS) of Oracle Solaris. CVSS 3.1 Base Score 4.0 (Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:C/C:N/I:L/A:L).



- [https://github.com/Live-Hack-CVE/CVE-2023-21900](https://github.com/Live-Hack-CVE/CVE-2023-21900) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21900.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21900.svg)

## CVE-2023-21899
 Vulnerability in the Oracle VM VirtualBox product of Oracle Virtualization (component: Core). Supported versions that are affected are Prior to 6.1.42 and prior to 7.0.6. Easily exploitable vulnerability allows low privileged attacker with logon to the infrastructure where Oracle VM VirtualBox executes to compromise Oracle VM VirtualBox. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of Oracle VM VirtualBox. Note: Applies to VirtualBox VMs running Windows 7 and later. CVSS 3.1 Base Score 5.5 (Availability impacts). CVSS Vector: (CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H).



- [https://github.com/Live-Hack-CVE/CVE-2023-21899](https://github.com/Live-Hack-CVE/CVE-2023-21899) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21899.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21899.svg)

## CVE-2023-21898
 Vulnerability in the Oracle VM VirtualBox product of Oracle Virtualization (component: Core). Supported versions that are affected are Prior to 6.1.42 and prior to 7.0.6. Easily exploitable vulnerability allows low privileged attacker with logon to the infrastructure where Oracle VM VirtualBox executes to compromise Oracle VM VirtualBox. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of Oracle VM VirtualBox. Note: Applies to VirtualBox VMs running Windows 7 and later. CVSS 3.1 Base Score 5.5 (Availability impacts). CVSS Vector: (CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H).



- [https://github.com/Live-Hack-CVE/CVE-2023-21898](https://github.com/Live-Hack-CVE/CVE-2023-21898) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21898.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21898.svg)

## CVE-2023-21894
 Vulnerability in the Oracle Global Lifecycle Management NextGen OUI Framework product of Oracle Fusion Middleware (component: NextGen Installer issues). Supported versions that are affected are Prior to 13.9.4.2.11. Easily exploitable vulnerability allows low privileged attacker with logon to the infrastructure where Oracle Global Lifecycle Management NextGen OUI Framework executes to compromise Oracle Global Lifecycle Management NextGen OUI Framework. Successful attacks require human interaction from a person other than the attacker. Successful attacks of this vulnerability can result in takeover of Oracle Global Lifecycle Management NextGen OUI Framework. CVSS 3.1 Base Score 7.3 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H).



- [https://github.com/Live-Hack-CVE/CVE-2023-21894](https://github.com/Live-Hack-CVE/CVE-2023-21894) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21894.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21894.svg)

## CVE-2023-21893
 Vulnerability in the Oracle Data Provider for .NET component of Oracle Database Server. Supported versions that are affected are 19c and 21c. Difficult to exploit vulnerability allows unauthenticated attacker with network access via TCPS to compromise Oracle Data Provider for .NET. Successful attacks require human interaction from a person other than the attacker. Successful attacks of this vulnerability can result in takeover of Oracle Data Provider for .NET. Note: Applies also to Database client-only on Windows platform. CVSS 3.1 Base Score 7.5 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H).



- [https://github.com/Live-Hack-CVE/CVE-2023-21893](https://github.com/Live-Hack-CVE/CVE-2023-21893) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21893.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21893.svg)

## CVE-2023-21892
 Vulnerability in the Oracle Business Intelligence Enterprise Edition product of Oracle Fusion Middleware (component: Visual Analyzer). Supported versions that are affected are 5.9.0.0.0 and 6.4.0.0.0. Easily exploitable vulnerability allows low privileged attacker with network access via HTTP to compromise Oracle Business Intelligence Enterprise Edition. Successful attacks require human interaction from a person other than the attacker and while the vulnerability is in Oracle Business Intelligence Enterprise Edition, attacks may significantly impact additional products (scope change). Successful attacks of this vulnerability can result in unauthorized update, insert or delete access to some of Oracle Business Intelligence Enterprise Edition accessible data as well as unauthorized read access to a subset of Oracle Business Intelligence Enterprise Edition accessible data. CVSS 3.1 Base Score 5.4 (Confidentiality and Integrity impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N).



- [https://github.com/Live-Hack-CVE/CVE-2023-21892](https://github.com/Live-Hack-CVE/CVE-2023-21892) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21892.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21892.svg)

## CVE-2023-21891
 Vulnerability in the Oracle Business Intelligence Enterprise Edition product of Oracle Fusion Middleware (component: Visual Analyzer). Supported versions that are affected are 5.9.0.0.0 and 6.4.0.0.0. Easily exploitable vulnerability allows low privileged attacker with network access via HTTP to compromise Oracle Business Intelligence Enterprise Edition. Successful attacks require human interaction from a person other than the attacker and while the vulnerability is in Oracle Business Intelligence Enterprise Edition, attacks may significantly impact additional products (scope change). Successful attacks of this vulnerability can result in unauthorized update, insert or delete access to some of Oracle Business Intelligence Enterprise Edition accessible data as well as unauthorized read access to a subset of Oracle Business Intelligence Enterprise Edition accessible data. CVSS 3.1 Base Score 5.4 (Confidentiality and Integrity impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N).



- [https://github.com/Live-Hack-CVE/CVE-2023-21891](https://github.com/Live-Hack-CVE/CVE-2023-21891) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21891.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21891.svg)

## CVE-2023-21890
 Vulnerability in the Oracle Communications Converged Application Server product of Oracle Communications (component: Core). Supported versions that are affected are 7.1.0 and 8.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via UDP to compromise Oracle Communications Converged Application Server. Successful attacks of this vulnerability can result in takeover of Oracle Communications Converged Application Server. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).



- [https://github.com/Live-Hack-CVE/CVE-2023-21890](https://github.com/Live-Hack-CVE/CVE-2023-21890) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21890.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21890.svg)

## CVE-2023-21889
 Vulnerability in the Oracle VM VirtualBox product of Oracle Virtualization (component: Core). Supported versions that are affected are Prior to 6.1.42 and prior to 7.0.6. Easily exploitable vulnerability allows low privileged attacker with logon to the infrastructure where Oracle VM VirtualBox executes to compromise Oracle VM VirtualBox. While the vulnerability is in Oracle VM VirtualBox, attacks may significantly impact additional products (scope change). Successful attacks of this vulnerability can result in unauthorized read access to a subset of Oracle VM VirtualBox accessible data. CVSS 3.1 Base Score 3.8 (Confidentiality impacts). CVSS Vector: (CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:L/I:N/A:N).



- [https://github.com/Live-Hack-CVE/CVE-2023-21889](https://github.com/Live-Hack-CVE/CVE-2023-21889) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21889.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21889.svg)

## CVE-2023-21888
 Vulnerability in the Primavera Gateway product of Oracle Construction and Engineering (component: WebUI). Supported versions that are affected are 18.8.0-18.8.15, 19.12.0-19.12.15, 20.12.0-20.12.10 and 21.12.0-21.12.8. Easily exploitable vulnerability allows low privileged attacker with network access via HTTP to compromise Primavera Gateway. Successful attacks require human interaction from a person other than the attacker and while the vulnerability is in Primavera Gateway, attacks may significantly impact additional products (scope change). Successful attacks of this vulnerability can result in unauthorized update, insert or delete access to some of Primavera Gateway accessible data as well as unauthorized read access to a subset of Primavera Gateway accessible data. CVSS 3.1 Base Score 5.4 (Confidentiality and Integrity impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N).



- [https://github.com/Live-Hack-CVE/CVE-2023-21888](https://github.com/Live-Hack-CVE/CVE-2023-21888) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21888.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21888.svg)

## CVE-2023-21887
 Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: GIS). Supported versions that are affected are 8.0.31 and prior. Easily exploitable vulnerability allows high privileged attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of MySQL Server. CVSS 3.1 Base Score 4.9 (Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H).



- [https://github.com/Live-Hack-CVE/CVE-2023-21887](https://github.com/Live-Hack-CVE/CVE-2023-21887) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21887.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21887.svg)

## CVE-2023-21886
 Vulnerability in the Oracle VM VirtualBox product of Oracle Virtualization (component: Core). Supported versions that are affected are Prior to 6.1.42 and prior to 7.0.6. Difficult to exploit vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise Oracle VM VirtualBox. Successful attacks of this vulnerability can result in takeover of Oracle VM VirtualBox. CVSS 3.1 Base Score 8.1 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H).



- [https://github.com/Live-Hack-CVE/CVE-2023-21886](https://github.com/Live-Hack-CVE/CVE-2023-21886) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21886.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21886.svg)

## CVE-2023-21885
 Vulnerability in the Oracle VM VirtualBox product of Oracle Virtualization (component: Core). Supported versions that are affected are Prior to 6.1.42 and prior to 7.0.6. Easily exploitable vulnerability allows low privileged attacker with logon to the infrastructure where Oracle VM VirtualBox executes to compromise Oracle VM VirtualBox. While the vulnerability is in Oracle VM VirtualBox, attacks may significantly impact additional products (scope change). Successful attacks of this vulnerability can result in unauthorized read access to a subset of Oracle VM VirtualBox accessible data. Note: Applies to Windows only. CVSS 3.1 Base Score 3.8 (Confidentiality impacts). CVSS Vector: (CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:L/I:N/A:N).



- [https://github.com/Live-Hack-CVE/CVE-2023-21885](https://github.com/Live-Hack-CVE/CVE-2023-21885) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21885.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21885.svg)

## CVE-2023-21884
 Vulnerability in the Oracle VM VirtualBox product of Oracle Virtualization (component: Core). Supported versions that are affected are Prior to 6.1.42 and prior to 7.0.6. Easily exploitable vulnerability allows high privileged attacker with logon to the infrastructure where Oracle VM VirtualBox executes to compromise Oracle VM VirtualBox. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of Oracle VM VirtualBox. CVSS 3.1 Base Score 4.4 (Availability impacts). CVSS Vector: (CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H).



- [https://github.com/Live-Hack-CVE/CVE-2023-21884](https://github.com/Live-Hack-CVE/CVE-2023-21884) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21884.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21884.svg)

## CVE-2023-21882
 Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Optimizer). Supported versions that are affected are 8.0.31 and prior. Easily exploitable vulnerability allows high privileged attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this vulnerability can result in unauthorized update, insert or delete access to some of MySQL Server accessible data. CVSS 3.1 Base Score 2.7 (Integrity impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:N).



- [https://github.com/Live-Hack-CVE/CVE-2023-21882](https://github.com/Live-Hack-CVE/CVE-2023-21882) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21882.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21882.svg)

## CVE-2023-21879
 Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Optimizer). Supported versions that are affected are 8.0.31 and prior. Easily exploitable vulnerability allows high privileged attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of MySQL Server. CVSS 3.1 Base Score 4.9 (Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H).



- [https://github.com/Live-Hack-CVE/CVE-2023-21879](https://github.com/Live-Hack-CVE/CVE-2023-21879) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21879.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21879.svg)

## CVE-2023-21878
 Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Optimizer). Supported versions that are affected are 8.0.31 and prior. Easily exploitable vulnerability allows high privileged attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of MySQL Server. CVSS 3.1 Base Score 4.9 (Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H).



- [https://github.com/Live-Hack-CVE/CVE-2023-21878](https://github.com/Live-Hack-CVE/CVE-2023-21878) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21878.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21878.svg)

## CVE-2023-21877
 Vulnerability in the MySQL Server product of Oracle MySQL (component: InnoDB). Supported versions that are affected are 8.0.31 and prior. Easily exploitable vulnerability allows high privileged attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of MySQL Server as well as unauthorized update, insert or delete access to some of MySQL Server accessible data. CVSS 3.1 Base Score 5.5 (Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:H).



- [https://github.com/Live-Hack-CVE/CVE-2023-21877](https://github.com/Live-Hack-CVE/CVE-2023-21877) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21877.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21877.svg)

## CVE-2023-21876
 Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Optimizer). Supported versions that are affected are 8.0.31 and prior. Easily exploitable vulnerability allows high privileged attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of MySQL Server. CVSS 3.1 Base Score 4.9 (Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H).



- [https://github.com/Live-Hack-CVE/CVE-2023-21876](https://github.com/Live-Hack-CVE/CVE-2023-21876) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21876.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21876.svg)

## CVE-2023-21875
 Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Security: Encryption). Supported versions that are affected are 8.0.31 and prior. Difficult to exploit vulnerability allows high privileged attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this vulnerability can result in unauthorized creation, deletion or modification access to critical data or all MySQL Server accessible data and unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of MySQL Server. CVSS 3.1 Base Score 5.9 (Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:N/I:H/A:H).



- [https://github.com/Live-Hack-CVE/CVE-2023-21875](https://github.com/Live-Hack-CVE/CVE-2023-21875) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21875.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21875.svg)

## CVE-2023-21874
 Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Thread Pooling). Supported versions that are affected are 8.0.30 and prior. Easily exploitable vulnerability allows high privileged attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this vulnerability can result in unauthorized ability to cause a partial denial of service (partial DOS) of MySQL Server. CVSS 3.1 Base Score 2.7 (Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:L).



- [https://github.com/Live-Hack-CVE/CVE-2023-21874](https://github.com/Live-Hack-CVE/CVE-2023-21874) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21874.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21874.svg)

## CVE-2023-21873
 Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Optimizer). Supported versions that are affected are 8.0.31 and prior. Easily exploitable vulnerability allows high privileged attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of MySQL Server. CVSS 3.1 Base Score 4.9 (Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H).



- [https://github.com/Live-Hack-CVE/CVE-2023-21873](https://github.com/Live-Hack-CVE/CVE-2023-21873) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21873.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21873.svg)

## CVE-2023-21872
 Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Optimizer). Supported versions that are affected are 8.0.29 and prior. Easily exploitable vulnerability allows high privileged attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of MySQL Server as well as unauthorized update, insert or delete access to some of MySQL Server accessible data. CVSS 3.1 Base Score 5.5 (Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:H).



- [https://github.com/Live-Hack-CVE/CVE-2023-21872](https://github.com/Live-Hack-CVE/CVE-2023-21872) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21872.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21872.svg)

## CVE-2023-21871
 Vulnerability in the MySQL Server product of Oracle MySQL (component: InnoDB). Supported versions that are affected are 8.0.31 and prior. Easily exploitable vulnerability allows high privileged attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of MySQL Server. CVSS 3.1 Base Score 4.9 (Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H).



- [https://github.com/Live-Hack-CVE/CVE-2023-21871](https://github.com/Live-Hack-CVE/CVE-2023-21871) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21871.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21871.svg)

## CVE-2023-21870
 Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Optimizer). Supported versions that are affected are 8.0.31 and prior. Easily exploitable vulnerability allows high privileged attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of MySQL Server. CVSS 3.1 Base Score 4.9 (Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H).



- [https://github.com/Live-Hack-CVE/CVE-2023-21870](https://github.com/Live-Hack-CVE/CVE-2023-21870) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21870.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21870.svg)

## CVE-2023-21869
 Vulnerability in the MySQL Server product of Oracle MySQL (component: InnoDB). Supported versions that are affected are 8.0.31 and prior. Easily exploitable vulnerability allows high privileged attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of MySQL Server as well as unauthorized update, insert or delete access to some of MySQL Server accessible data. CVSS 3.1 Base Score 5.5 (Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:H).



- [https://github.com/Live-Hack-CVE/CVE-2023-21869](https://github.com/Live-Hack-CVE/CVE-2023-21869) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21869.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21869.svg)

## CVE-2023-21868
 Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Optimizer). Supported versions that are affected are 8.0.31 and prior. Easily exploitable vulnerability allows low privileged attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of MySQL Server. CVSS 3.1 Base Score 6.5 (Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H).



- [https://github.com/Live-Hack-CVE/CVE-2023-21868](https://github.com/Live-Hack-CVE/CVE-2023-21868) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21868.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21868.svg)

## CVE-2023-21867
 Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Optimizer). Supported versions that are affected are 8.0.31 and prior. Easily exploitable vulnerability allows high privileged attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of MySQL Server. CVSS 3.1 Base Score 4.9 (Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H).



- [https://github.com/Live-Hack-CVE/CVE-2023-21867](https://github.com/Live-Hack-CVE/CVE-2023-21867) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21867.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21867.svg)

## CVE-2023-21866
 Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Optimizer). Supported versions that are affected are 8.0.28 and prior. Easily exploitable vulnerability allows high privileged attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of MySQL Server. CVSS 3.1 Base Score 4.9 (Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H).



- [https://github.com/Live-Hack-CVE/CVE-2023-21866](https://github.com/Live-Hack-CVE/CVE-2023-21866) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21866.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21866.svg)

## CVE-2023-21865
 Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Optimizer). Supported versions that are affected are 8.0.30 and prior. Easily exploitable vulnerability allows high privileged attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of MySQL Server. CVSS 3.1 Base Score 4.9 (Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H).



- [https://github.com/Live-Hack-CVE/CVE-2023-21865](https://github.com/Live-Hack-CVE/CVE-2023-21865) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21865.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21865.svg)

## CVE-2023-21864
 Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Optimizer). Supported versions that are affected are 8.0.30 and prior. Easily exploitable vulnerability allows high privileged attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of MySQL Server. CVSS 3.1 Base Score 4.9 (Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H).



- [https://github.com/Live-Hack-CVE/CVE-2023-21864](https://github.com/Live-Hack-CVE/CVE-2023-21864) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21864.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21864.svg)

## CVE-2023-21863
 Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Optimizer). Supported versions that are affected are 8.0.31 and prior. Easily exploitable vulnerability allows high privileged attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of MySQL Server. CVSS 3.1 Base Score 4.9 (Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H).



- [https://github.com/Live-Hack-CVE/CVE-2023-21863](https://github.com/Live-Hack-CVE/CVE-2023-21863) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21863.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21863.svg)

## CVE-2023-21860
 Vulnerability in the MySQL Cluster product of Oracle MySQL (component: Cluster: Internal Operations). Supported versions that are affected are 7.4.38 and prior, 7.5.28 and prior, 7.6.24 and prior and 8.0.31 and prior. Difficult to exploit vulnerability allows high privileged attacker with access to the physical communication segment attached to the hardware where the MySQL Cluster executes to compromise MySQL Cluster. Successful attacks require human interaction from a person other than the attacker. Successful attacks of this vulnerability can result in takeover of MySQL Cluster. CVSS 3.1 Base Score 6.3 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:A/AC:H/PR:H/UI:R/S:U/C:H/I:H/A:H).



- [https://github.com/Live-Hack-CVE/CVE-2023-21860](https://github.com/Live-Hack-CVE/CVE-2023-21860) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21860.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21860.svg)

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



- [https://github.com/fakenews2025/CVE-2023-21839](https://github.com/fakenews2025/CVE-2023-21839) :  ![starts](https://img.shields.io/github/stars/fakenews2025/CVE-2023-21839.svg) ![forks](https://img.shields.io/github/forks/fakenews2025/CVE-2023-21839.svg)

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

## CVE-2023-21796
 Microsoft Edge (Chromium-based) Elevation of Privilege Vulnerability. This CVE ID is unique from CVE-2023-21795.



- [https://github.com/Live-Hack-CVE/CVE-2023-21796](https://github.com/Live-Hack-CVE/CVE-2023-21796) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21796.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21796.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21795](https://github.com/Live-Hack-CVE/CVE-2023-21795) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21795.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21795.svg)

## CVE-2023-21795
 Microsoft Edge (Chromium-based) Elevation of Privilege Vulnerability. This CVE ID is unique from CVE-2023-21796.



- [https://github.com/Live-Hack-CVE/CVE-2023-21795](https://github.com/Live-Hack-CVE/CVE-2023-21795) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21795.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21795.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21796](https://github.com/Live-Hack-CVE/CVE-2023-21796) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21796.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21796.svg)

## CVE-2023-21793
 3D Builder Remote Code Execution Vulnerability. This CVE ID is unique from CVE-2023-21780, CVE-2023-21781, CVE-2023-21782, CVE-2023-21783, CVE-2023-21784, CVE-2023-21785, CVE-2023-21786, CVE-2023-21787, CVE-2023-21788, CVE-2023-21789, CVE-2023-21790, CVE-2023-21791, CVE-2023-21792.



- [https://github.com/Live-Hack-CVE/CVE-2023-21793](https://github.com/Live-Hack-CVE/CVE-2023-21793) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21793.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21793.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21782](https://github.com/Live-Hack-CVE/CVE-2023-21782) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21782.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21782.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21781](https://github.com/Live-Hack-CVE/CVE-2023-21781) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21781.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21781.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21787](https://github.com/Live-Hack-CVE/CVE-2023-21787) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21787.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21787.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21786](https://github.com/Live-Hack-CVE/CVE-2023-21786) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21786.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21786.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21788](https://github.com/Live-Hack-CVE/CVE-2023-21788) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21788.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21788.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21790](https://github.com/Live-Hack-CVE/CVE-2023-21790) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21790.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21790.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21780](https://github.com/Live-Hack-CVE/CVE-2023-21780) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21780.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21780.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21784](https://github.com/Live-Hack-CVE/CVE-2023-21784) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21784.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21784.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21785](https://github.com/Live-Hack-CVE/CVE-2023-21785) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21785.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21785.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21789](https://github.com/Live-Hack-CVE/CVE-2023-21789) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21789.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21789.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21783](https://github.com/Live-Hack-CVE/CVE-2023-21783) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21783.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21783.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21791](https://github.com/Live-Hack-CVE/CVE-2023-21791) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21791.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21791.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21792](https://github.com/Live-Hack-CVE/CVE-2023-21792) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21792.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21792.svg)

## CVE-2023-21792
 3D Builder Remote Code Execution Vulnerability. This CVE ID is unique from CVE-2023-21780, CVE-2023-21781, CVE-2023-21782, CVE-2023-21783, CVE-2023-21784, CVE-2023-21785, CVE-2023-21786, CVE-2023-21787, CVE-2023-21788, CVE-2023-21789, CVE-2023-21790, CVE-2023-21791, CVE-2023-21793.



- [https://github.com/Live-Hack-CVE/CVE-2023-21792](https://github.com/Live-Hack-CVE/CVE-2023-21792) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21792.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21792.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21790](https://github.com/Live-Hack-CVE/CVE-2023-21790) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21790.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21790.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21782](https://github.com/Live-Hack-CVE/CVE-2023-21782) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21782.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21782.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21793](https://github.com/Live-Hack-CVE/CVE-2023-21793) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21793.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21793.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21787](https://github.com/Live-Hack-CVE/CVE-2023-21787) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21787.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21787.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21786](https://github.com/Live-Hack-CVE/CVE-2023-21786) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21786.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21786.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21788](https://github.com/Live-Hack-CVE/CVE-2023-21788) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21788.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21788.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21791](https://github.com/Live-Hack-CVE/CVE-2023-21791) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21791.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21791.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21780](https://github.com/Live-Hack-CVE/CVE-2023-21780) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21780.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21780.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21784](https://github.com/Live-Hack-CVE/CVE-2023-21784) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21784.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21784.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21781](https://github.com/Live-Hack-CVE/CVE-2023-21781) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21781.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21781.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21789](https://github.com/Live-Hack-CVE/CVE-2023-21789) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21789.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21789.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21783](https://github.com/Live-Hack-CVE/CVE-2023-21783) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21783.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21783.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21785](https://github.com/Live-Hack-CVE/CVE-2023-21785) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21785.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21785.svg)

## CVE-2023-21791
 3D Builder Remote Code Execution Vulnerability. This CVE ID is unique from CVE-2023-21780, CVE-2023-21781, CVE-2023-21782, CVE-2023-21783, CVE-2023-21784, CVE-2023-21785, CVE-2023-21786, CVE-2023-21787, CVE-2023-21788, CVE-2023-21789, CVE-2023-21790, CVE-2023-21792, CVE-2023-21793.



- [https://github.com/Live-Hack-CVE/CVE-2023-21791](https://github.com/Live-Hack-CVE/CVE-2023-21791) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21791.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21791.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21790](https://github.com/Live-Hack-CVE/CVE-2023-21790) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21790.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21790.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21782](https://github.com/Live-Hack-CVE/CVE-2023-21782) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21782.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21782.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21793](https://github.com/Live-Hack-CVE/CVE-2023-21793) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21793.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21793.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21792](https://github.com/Live-Hack-CVE/CVE-2023-21792) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21792.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21792.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21787](https://github.com/Live-Hack-CVE/CVE-2023-21787) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21787.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21787.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21786](https://github.com/Live-Hack-CVE/CVE-2023-21786) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21786.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21786.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21788](https://github.com/Live-Hack-CVE/CVE-2023-21788) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21788.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21788.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21780](https://github.com/Live-Hack-CVE/CVE-2023-21780) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21780.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21780.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21784](https://github.com/Live-Hack-CVE/CVE-2023-21784) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21784.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21784.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21781](https://github.com/Live-Hack-CVE/CVE-2023-21781) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21781.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21781.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21789](https://github.com/Live-Hack-CVE/CVE-2023-21789) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21789.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21789.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21783](https://github.com/Live-Hack-CVE/CVE-2023-21783) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21783.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21783.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21785](https://github.com/Live-Hack-CVE/CVE-2023-21785) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21785.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21785.svg)

## CVE-2023-21790
 3D Builder Remote Code Execution Vulnerability. This CVE ID is unique from CVE-2023-21780, CVE-2023-21781, CVE-2023-21782, CVE-2023-21783, CVE-2023-21784, CVE-2023-21785, CVE-2023-21786, CVE-2023-21787, CVE-2023-21788, CVE-2023-21789, CVE-2023-21791, CVE-2023-21792, CVE-2023-21793.



- [https://github.com/Live-Hack-CVE/CVE-2023-21790](https://github.com/Live-Hack-CVE/CVE-2023-21790) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21790.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21790.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21782](https://github.com/Live-Hack-CVE/CVE-2023-21782) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21782.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21782.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21793](https://github.com/Live-Hack-CVE/CVE-2023-21793) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21793.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21793.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21786](https://github.com/Live-Hack-CVE/CVE-2023-21786) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21786.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21786.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21788](https://github.com/Live-Hack-CVE/CVE-2023-21788) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21788.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21788.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21780](https://github.com/Live-Hack-CVE/CVE-2023-21780) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21780.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21780.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21784](https://github.com/Live-Hack-CVE/CVE-2023-21784) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21784.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21784.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21785](https://github.com/Live-Hack-CVE/CVE-2023-21785) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21785.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21785.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21789](https://github.com/Live-Hack-CVE/CVE-2023-21789) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21789.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21789.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21783](https://github.com/Live-Hack-CVE/CVE-2023-21783) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21783.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21783.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21787](https://github.com/Live-Hack-CVE/CVE-2023-21787) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21787.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21787.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21781](https://github.com/Live-Hack-CVE/CVE-2023-21781) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21781.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21781.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21791](https://github.com/Live-Hack-CVE/CVE-2023-21791) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21791.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21791.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21792](https://github.com/Live-Hack-CVE/CVE-2023-21792) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21792.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21792.svg)

## CVE-2023-21789
 3D Builder Remote Code Execution Vulnerability. This CVE ID is unique from CVE-2023-21780, CVE-2023-21781, CVE-2023-21782, CVE-2023-21783, CVE-2023-21784, CVE-2023-21785, CVE-2023-21786, CVE-2023-21787, CVE-2023-21788, CVE-2023-21790, CVE-2023-21791, CVE-2023-21792, CVE-2023-21793.



- [https://github.com/Live-Hack-CVE/CVE-2023-21789](https://github.com/Live-Hack-CVE/CVE-2023-21789) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21789.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21789.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21782](https://github.com/Live-Hack-CVE/CVE-2023-21782) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21782.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21782.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21790](https://github.com/Live-Hack-CVE/CVE-2023-21790) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21790.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21790.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21793](https://github.com/Live-Hack-CVE/CVE-2023-21793) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21793.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21793.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21781](https://github.com/Live-Hack-CVE/CVE-2023-21781) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21781.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21781.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21787](https://github.com/Live-Hack-CVE/CVE-2023-21787) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21787.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21787.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21786](https://github.com/Live-Hack-CVE/CVE-2023-21786) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21786.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21786.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21785](https://github.com/Live-Hack-CVE/CVE-2023-21785) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21785.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21785.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21783](https://github.com/Live-Hack-CVE/CVE-2023-21783) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21783.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21783.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21788](https://github.com/Live-Hack-CVE/CVE-2023-21788) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21788.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21788.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21780](https://github.com/Live-Hack-CVE/CVE-2023-21780) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21780.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21780.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21784](https://github.com/Live-Hack-CVE/CVE-2023-21784) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21784.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21784.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21791](https://github.com/Live-Hack-CVE/CVE-2023-21791) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21791.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21791.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21792](https://github.com/Live-Hack-CVE/CVE-2023-21792) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21792.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21792.svg)

## CVE-2023-21788
 3D Builder Remote Code Execution Vulnerability. This CVE ID is unique from CVE-2023-21780, CVE-2023-21781, CVE-2023-21782, CVE-2023-21783, CVE-2023-21784, CVE-2023-21785, CVE-2023-21786, CVE-2023-21787, CVE-2023-21789, CVE-2023-21790, CVE-2023-21791, CVE-2023-21792, CVE-2023-21793.



- [https://github.com/Live-Hack-CVE/CVE-2023-21788](https://github.com/Live-Hack-CVE/CVE-2023-21788) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21788.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21788.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21793](https://github.com/Live-Hack-CVE/CVE-2023-21793) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21793.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21793.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21782](https://github.com/Live-Hack-CVE/CVE-2023-21782) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21782.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21782.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21787](https://github.com/Live-Hack-CVE/CVE-2023-21787) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21787.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21787.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21786](https://github.com/Live-Hack-CVE/CVE-2023-21786) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21786.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21786.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21780](https://github.com/Live-Hack-CVE/CVE-2023-21780) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21780.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21780.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21784](https://github.com/Live-Hack-CVE/CVE-2023-21784) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21784.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21784.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21781](https://github.com/Live-Hack-CVE/CVE-2023-21781) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21781.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21781.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21790](https://github.com/Live-Hack-CVE/CVE-2023-21790) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21790.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21790.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21785](https://github.com/Live-Hack-CVE/CVE-2023-21785) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21785.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21785.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21783](https://github.com/Live-Hack-CVE/CVE-2023-21783) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21783.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21783.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21789](https://github.com/Live-Hack-CVE/CVE-2023-21789) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21789.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21789.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21791](https://github.com/Live-Hack-CVE/CVE-2023-21791) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21791.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21791.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21792](https://github.com/Live-Hack-CVE/CVE-2023-21792) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21792.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21792.svg)

## CVE-2023-21787
 3D Builder Remote Code Execution Vulnerability. This CVE ID is unique from CVE-2023-21780, CVE-2023-21781, CVE-2023-21782, CVE-2023-21783, CVE-2023-21784, CVE-2023-21785, CVE-2023-21786, CVE-2023-21788, CVE-2023-21789, CVE-2023-21790, CVE-2023-21791, CVE-2023-21792, CVE-2023-21793.



- [https://github.com/Live-Hack-CVE/CVE-2023-21787](https://github.com/Live-Hack-CVE/CVE-2023-21787) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21787.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21787.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21782](https://github.com/Live-Hack-CVE/CVE-2023-21782) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21782.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21782.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21790](https://github.com/Live-Hack-CVE/CVE-2023-21790) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21790.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21790.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21793](https://github.com/Live-Hack-CVE/CVE-2023-21793) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21793.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21793.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21788](https://github.com/Live-Hack-CVE/CVE-2023-21788) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21788.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21788.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21780](https://github.com/Live-Hack-CVE/CVE-2023-21780) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21780.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21780.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21784](https://github.com/Live-Hack-CVE/CVE-2023-21784) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21784.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21784.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21785](https://github.com/Live-Hack-CVE/CVE-2023-21785) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21785.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21785.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21789](https://github.com/Live-Hack-CVE/CVE-2023-21789) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21789.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21789.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21783](https://github.com/Live-Hack-CVE/CVE-2023-21783) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21783.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21783.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21786](https://github.com/Live-Hack-CVE/CVE-2023-21786) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21786.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21786.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21781](https://github.com/Live-Hack-CVE/CVE-2023-21781) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21781.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21781.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21791](https://github.com/Live-Hack-CVE/CVE-2023-21791) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21791.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21791.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21792](https://github.com/Live-Hack-CVE/CVE-2023-21792) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21792.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21792.svg)

## CVE-2023-21786
 3D Builder Remote Code Execution Vulnerability. This CVE ID is unique from CVE-2023-21780, CVE-2023-21781, CVE-2023-21782, CVE-2023-21783, CVE-2023-21784, CVE-2023-21785, CVE-2023-21787, CVE-2023-21788, CVE-2023-21789, CVE-2023-21790, CVE-2023-21791, CVE-2023-21792, CVE-2023-21793.



- [https://github.com/Live-Hack-CVE/CVE-2023-21786](https://github.com/Live-Hack-CVE/CVE-2023-21786) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21786.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21786.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21790](https://github.com/Live-Hack-CVE/CVE-2023-21790) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21790.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21790.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21782](https://github.com/Live-Hack-CVE/CVE-2023-21782) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21782.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21782.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21787](https://github.com/Live-Hack-CVE/CVE-2023-21787) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21787.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21787.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21793](https://github.com/Live-Hack-CVE/CVE-2023-21793) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21793.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21793.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21781](https://github.com/Live-Hack-CVE/CVE-2023-21781) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21781.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21781.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21788](https://github.com/Live-Hack-CVE/CVE-2023-21788) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21788.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21788.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21791](https://github.com/Live-Hack-CVE/CVE-2023-21791) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21791.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21791.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21792](https://github.com/Live-Hack-CVE/CVE-2023-21792) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21792.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21792.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21780](https://github.com/Live-Hack-CVE/CVE-2023-21780) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21780.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21780.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21784](https://github.com/Live-Hack-CVE/CVE-2023-21784) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21784.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21784.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21785](https://github.com/Live-Hack-CVE/CVE-2023-21785) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21785.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21785.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21783](https://github.com/Live-Hack-CVE/CVE-2023-21783) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21783.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21783.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21789](https://github.com/Live-Hack-CVE/CVE-2023-21789) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21789.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21789.svg)

## CVE-2023-21785
 3D Builder Remote Code Execution Vulnerability. This CVE ID is unique from CVE-2023-21780, CVE-2023-21781, CVE-2023-21782, CVE-2023-21783, CVE-2023-21784, CVE-2023-21786, CVE-2023-21787, CVE-2023-21788, CVE-2023-21789, CVE-2023-21790, CVE-2023-21791, CVE-2023-21792, CVE-2023-21793.



- [https://github.com/Live-Hack-CVE/CVE-2023-21785](https://github.com/Live-Hack-CVE/CVE-2023-21785) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21785.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21785.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21793](https://github.com/Live-Hack-CVE/CVE-2023-21793) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21793.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21793.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21782](https://github.com/Live-Hack-CVE/CVE-2023-21782) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21782.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21782.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21787](https://github.com/Live-Hack-CVE/CVE-2023-21787) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21787.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21787.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21788](https://github.com/Live-Hack-CVE/CVE-2023-21788) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21788.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21788.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21790](https://github.com/Live-Hack-CVE/CVE-2023-21790) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21790.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21790.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21780](https://github.com/Live-Hack-CVE/CVE-2023-21780) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21780.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21780.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21784](https://github.com/Live-Hack-CVE/CVE-2023-21784) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21784.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21784.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21783](https://github.com/Live-Hack-CVE/CVE-2023-21783) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21783.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21783.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21789](https://github.com/Live-Hack-CVE/CVE-2023-21789) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21789.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21789.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21781](https://github.com/Live-Hack-CVE/CVE-2023-21781) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21781.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21781.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21786](https://github.com/Live-Hack-CVE/CVE-2023-21786) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21786.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21786.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21791](https://github.com/Live-Hack-CVE/CVE-2023-21791) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21791.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21791.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21792](https://github.com/Live-Hack-CVE/CVE-2023-21792) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21792.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21792.svg)

## CVE-2023-21784
 3D Builder Remote Code Execution Vulnerability. This CVE ID is unique from CVE-2023-21780, CVE-2023-21781, CVE-2023-21782, CVE-2023-21783, CVE-2023-21785, CVE-2023-21786, CVE-2023-21787, CVE-2023-21788, CVE-2023-21789, CVE-2023-21790, CVE-2023-21791, CVE-2023-21792, CVE-2023-21793.



- [https://github.com/Live-Hack-CVE/CVE-2023-21784](https://github.com/Live-Hack-CVE/CVE-2023-21784) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21784.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21784.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21790](https://github.com/Live-Hack-CVE/CVE-2023-21790) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21790.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21790.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21782](https://github.com/Live-Hack-CVE/CVE-2023-21782) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21782.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21782.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21793](https://github.com/Live-Hack-CVE/CVE-2023-21793) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21793.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21793.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21780](https://github.com/Live-Hack-CVE/CVE-2023-21780) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21780.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21780.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21787](https://github.com/Live-Hack-CVE/CVE-2023-21787) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21787.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21787.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21786](https://github.com/Live-Hack-CVE/CVE-2023-21786) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21786.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21786.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21788](https://github.com/Live-Hack-CVE/CVE-2023-21788) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21788.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21788.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21781](https://github.com/Live-Hack-CVE/CVE-2023-21781) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21781.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21781.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21792](https://github.com/Live-Hack-CVE/CVE-2023-21792) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21792.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21792.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21791](https://github.com/Live-Hack-CVE/CVE-2023-21791) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21791.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21791.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21789](https://github.com/Live-Hack-CVE/CVE-2023-21789) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21789.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21789.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21783](https://github.com/Live-Hack-CVE/CVE-2023-21783) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21783.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21783.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21785](https://github.com/Live-Hack-CVE/CVE-2023-21785) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21785.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21785.svg)

## CVE-2023-21783
 3D Builder Remote Code Execution Vulnerability. This CVE ID is unique from CVE-2023-21780, CVE-2023-21781, CVE-2023-21782, CVE-2023-21784, CVE-2023-21785, CVE-2023-21786, CVE-2023-21787, CVE-2023-21788, CVE-2023-21789, CVE-2023-21790, CVE-2023-21791, CVE-2023-21792, CVE-2023-21793.



- [https://github.com/Live-Hack-CVE/CVE-2023-21783](https://github.com/Live-Hack-CVE/CVE-2023-21783) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21783.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21783.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21782](https://github.com/Live-Hack-CVE/CVE-2023-21782) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21782.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21782.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21790](https://github.com/Live-Hack-CVE/CVE-2023-21790) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21790.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21790.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21793](https://github.com/Live-Hack-CVE/CVE-2023-21793) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21793.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21793.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21781](https://github.com/Live-Hack-CVE/CVE-2023-21781) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21781.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21781.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21787](https://github.com/Live-Hack-CVE/CVE-2023-21787) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21787.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21787.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21786](https://github.com/Live-Hack-CVE/CVE-2023-21786) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21786.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21786.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21785](https://github.com/Live-Hack-CVE/CVE-2023-21785) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21785.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21785.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21789](https://github.com/Live-Hack-CVE/CVE-2023-21789) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21789.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21789.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21788](https://github.com/Live-Hack-CVE/CVE-2023-21788) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21788.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21788.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21780](https://github.com/Live-Hack-CVE/CVE-2023-21780) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21780.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21780.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21784](https://github.com/Live-Hack-CVE/CVE-2023-21784) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21784.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21784.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21791](https://github.com/Live-Hack-CVE/CVE-2023-21791) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21791.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21791.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21792](https://github.com/Live-Hack-CVE/CVE-2023-21792) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21792.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21792.svg)

## CVE-2023-21782
 3D Builder Remote Code Execution Vulnerability. This CVE ID is unique from CVE-2023-21780, CVE-2023-21781, CVE-2023-21783, CVE-2023-21784, CVE-2023-21785, CVE-2023-21786, CVE-2023-21787, CVE-2023-21788, CVE-2023-21789, CVE-2023-21790, CVE-2023-21791, CVE-2023-21792, CVE-2023-21793.



- [https://github.com/Live-Hack-CVE/CVE-2023-21782](https://github.com/Live-Hack-CVE/CVE-2023-21782) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21782.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21782.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21790](https://github.com/Live-Hack-CVE/CVE-2023-21790) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21790.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21790.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21793](https://github.com/Live-Hack-CVE/CVE-2023-21793) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21793.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21793.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21787](https://github.com/Live-Hack-CVE/CVE-2023-21787) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21787.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21787.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21786](https://github.com/Live-Hack-CVE/CVE-2023-21786) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21786.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21786.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21788](https://github.com/Live-Hack-CVE/CVE-2023-21788) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21788.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21788.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21780](https://github.com/Live-Hack-CVE/CVE-2023-21780) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21780.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21780.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21784](https://github.com/Live-Hack-CVE/CVE-2023-21784) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21784.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21784.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21781](https://github.com/Live-Hack-CVE/CVE-2023-21781) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21781.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21781.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21785](https://github.com/Live-Hack-CVE/CVE-2023-21785) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21785.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21785.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21783](https://github.com/Live-Hack-CVE/CVE-2023-21783) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21783.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21783.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21789](https://github.com/Live-Hack-CVE/CVE-2023-21789) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21789.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21789.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21791](https://github.com/Live-Hack-CVE/CVE-2023-21791) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21791.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21791.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21792](https://github.com/Live-Hack-CVE/CVE-2023-21792) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21792.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21792.svg)

## CVE-2023-21781
 3D Builder Remote Code Execution Vulnerability. This CVE ID is unique from CVE-2023-21780, CVE-2023-21782, CVE-2023-21783, CVE-2023-21784, CVE-2023-21785, CVE-2023-21786, CVE-2023-21787, CVE-2023-21788, CVE-2023-21789, CVE-2023-21790, CVE-2023-21791, CVE-2023-21792, CVE-2023-21793.



- [https://github.com/Live-Hack-CVE/CVE-2023-21781](https://github.com/Live-Hack-CVE/CVE-2023-21781) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21781.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21781.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21790](https://github.com/Live-Hack-CVE/CVE-2023-21790) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21790.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21790.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21782](https://github.com/Live-Hack-CVE/CVE-2023-21782) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21782.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21782.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21793](https://github.com/Live-Hack-CVE/CVE-2023-21793) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21793.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21793.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21787](https://github.com/Live-Hack-CVE/CVE-2023-21787) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21787.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21787.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21786](https://github.com/Live-Hack-CVE/CVE-2023-21786) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21786.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21786.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21780](https://github.com/Live-Hack-CVE/CVE-2023-21780) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21780.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21780.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21784](https://github.com/Live-Hack-CVE/CVE-2023-21784) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21784.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21784.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21788](https://github.com/Live-Hack-CVE/CVE-2023-21788) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21788.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21788.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21789](https://github.com/Live-Hack-CVE/CVE-2023-21789) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21789.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21789.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21783](https://github.com/Live-Hack-CVE/CVE-2023-21783) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21783.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21783.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21785](https://github.com/Live-Hack-CVE/CVE-2023-21785) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21785.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21785.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21792](https://github.com/Live-Hack-CVE/CVE-2023-21792) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21792.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21792.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21791](https://github.com/Live-Hack-CVE/CVE-2023-21791) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21791.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21791.svg)

## CVE-2023-21780
 3D Builder Remote Code Execution Vulnerability. This CVE ID is unique from CVE-2023-21781, CVE-2023-21782, CVE-2023-21783, CVE-2023-21784, CVE-2023-21785, CVE-2023-21786, CVE-2023-21787, CVE-2023-21788, CVE-2023-21789, CVE-2023-21790, CVE-2023-21791, CVE-2023-21792, CVE-2023-21793.



- [https://github.com/Live-Hack-CVE/CVE-2023-21780](https://github.com/Live-Hack-CVE/CVE-2023-21780) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21780.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21780.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21790](https://github.com/Live-Hack-CVE/CVE-2023-21790) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21790.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21790.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21784](https://github.com/Live-Hack-CVE/CVE-2023-21784) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21784.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21784.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21787](https://github.com/Live-Hack-CVE/CVE-2023-21787) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21787.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21787.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21786](https://github.com/Live-Hack-CVE/CVE-2023-21786) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21786.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21786.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21788](https://github.com/Live-Hack-CVE/CVE-2023-21788) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21788.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21788.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21793](https://github.com/Live-Hack-CVE/CVE-2023-21793) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21793.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21793.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21782](https://github.com/Live-Hack-CVE/CVE-2023-21782) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21782.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21782.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21789](https://github.com/Live-Hack-CVE/CVE-2023-21789) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21789.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21789.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21783](https://github.com/Live-Hack-CVE/CVE-2023-21783) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21783.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21783.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21785](https://github.com/Live-Hack-CVE/CVE-2023-21785) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21785.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21785.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21792](https://github.com/Live-Hack-CVE/CVE-2023-21792) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21792.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21792.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21791](https://github.com/Live-Hack-CVE/CVE-2023-21791) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21791.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21791.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21781](https://github.com/Live-Hack-CVE/CVE-2023-21781) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21781.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21781.svg)

## CVE-2023-21776
 Windows Kernel Information Disclosure Vulnerability.



- [https://github.com/Live-Hack-CVE/CVE-2023-21776](https://github.com/Live-Hack-CVE/CVE-2023-21776) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21776.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21776.svg)

## CVE-2023-21775
 Microsoft Edge (Chromium-based) Remote Code Execution Vulnerability.



- [https://github.com/Live-Hack-CVE/CVE-2023-21775](https://github.com/Live-Hack-CVE/CVE-2023-21775) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21775.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21775.svg)

## CVE-2023-21774
 Windows Kernel Elevation of Privilege Vulnerability. This CVE ID is unique from CVE-2023-21675, CVE-2023-21747, CVE-2023-21748, CVE-2023-21749, CVE-2023-21750, CVE-2023-21754, CVE-2023-21755, CVE-2023-21772, CVE-2023-21773.



- [https://github.com/Live-Hack-CVE/CVE-2023-21774](https://github.com/Live-Hack-CVE/CVE-2023-21774) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21774.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21774.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21748](https://github.com/Live-Hack-CVE/CVE-2023-21748) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21748.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21748.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21773](https://github.com/Live-Hack-CVE/CVE-2023-21773) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21773.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21773.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21772](https://github.com/Live-Hack-CVE/CVE-2023-21772) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21772.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21772.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21754](https://github.com/Live-Hack-CVE/CVE-2023-21754) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21754.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21754.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21747](https://github.com/Live-Hack-CVE/CVE-2023-21747) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21747.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21747.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21675](https://github.com/Live-Hack-CVE/CVE-2023-21675) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21675.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21675.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21749](https://github.com/Live-Hack-CVE/CVE-2023-21749) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21749.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21749.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21755](https://github.com/Live-Hack-CVE/CVE-2023-21755) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21755.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21755.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21750](https://github.com/Live-Hack-CVE/CVE-2023-21750) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21750.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21750.svg)

## CVE-2023-21773
 Windows Kernel Elevation of Privilege Vulnerability. This CVE ID is unique from CVE-2023-21675, CVE-2023-21747, CVE-2023-21748, CVE-2023-21749, CVE-2023-21750, CVE-2023-21754, CVE-2023-21755, CVE-2023-21772, CVE-2023-21774.



- [https://github.com/Live-Hack-CVE/CVE-2023-21773](https://github.com/Live-Hack-CVE/CVE-2023-21773) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21773.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21773.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21774](https://github.com/Live-Hack-CVE/CVE-2023-21774) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21774.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21774.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21755](https://github.com/Live-Hack-CVE/CVE-2023-21755) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21755.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21755.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21754](https://github.com/Live-Hack-CVE/CVE-2023-21754) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21754.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21754.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21772](https://github.com/Live-Hack-CVE/CVE-2023-21772) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21772.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21772.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21748](https://github.com/Live-Hack-CVE/CVE-2023-21748) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21748.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21748.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21747](https://github.com/Live-Hack-CVE/CVE-2023-21747) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21747.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21747.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21675](https://github.com/Live-Hack-CVE/CVE-2023-21675) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21675.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21675.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21749](https://github.com/Live-Hack-CVE/CVE-2023-21749) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21749.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21749.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21750](https://github.com/Live-Hack-CVE/CVE-2023-21750) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21750.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21750.svg)

## CVE-2023-21772
 Windows Kernel Elevation of Privilege Vulnerability. This CVE ID is unique from CVE-2023-21675, CVE-2023-21747, CVE-2023-21748, CVE-2023-21749, CVE-2023-21750, CVE-2023-21754, CVE-2023-21755, CVE-2023-21773, CVE-2023-21774.



- [https://github.com/Live-Hack-CVE/CVE-2023-21772](https://github.com/Live-Hack-CVE/CVE-2023-21772) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21772.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21772.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21755](https://github.com/Live-Hack-CVE/CVE-2023-21755) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21755.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21755.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21774](https://github.com/Live-Hack-CVE/CVE-2023-21774) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21774.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21774.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21754](https://github.com/Live-Hack-CVE/CVE-2023-21754) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21754.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21754.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21750](https://github.com/Live-Hack-CVE/CVE-2023-21750) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21750.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21750.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21773](https://github.com/Live-Hack-CVE/CVE-2023-21773) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21773.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21773.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21675](https://github.com/Live-Hack-CVE/CVE-2023-21675) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21675.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21675.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21749](https://github.com/Live-Hack-CVE/CVE-2023-21749) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21749.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21749.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21747](https://github.com/Live-Hack-CVE/CVE-2023-21747) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21747.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21747.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21748](https://github.com/Live-Hack-CVE/CVE-2023-21748) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21748.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21748.svg)

## CVE-2023-21771
 Windows Local Session Manager (LSM) Elevation of Privilege Vulnerability.



- [https://github.com/Live-Hack-CVE/CVE-2023-21771](https://github.com/Live-Hack-CVE/CVE-2023-21771) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21771.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21771.svg)

## CVE-2023-21768
 Windows Ancillary Function Driver for WinSock Elevation of Privilege Vulnerability.



- [https://github.com/Live-Hack-CVE/CVE-2023-21768](https://github.com/Live-Hack-CVE/CVE-2023-21768) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21768.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21768.svg)

## CVE-2023-21767
 Windows Overlay Filter Elevation of Privilege Vulnerability.



- [https://github.com/Live-Hack-CVE/CVE-2023-21767](https://github.com/Live-Hack-CVE/CVE-2023-21767) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21767.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21767.svg)

## CVE-2023-21766
 Windows Overlay Filter Information Disclosure Vulnerability.



- [https://github.com/Live-Hack-CVE/CVE-2023-21766](https://github.com/Live-Hack-CVE/CVE-2023-21766) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21766.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21766.svg)

## CVE-2023-21765
 Windows Print Spooler Elevation of Privilege Vulnerability. This CVE ID is unique from CVE-2023-21678, CVE-2023-21760.



- [https://github.com/Live-Hack-CVE/CVE-2023-21765](https://github.com/Live-Hack-CVE/CVE-2023-21765) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21765.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21765.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21678](https://github.com/Live-Hack-CVE/CVE-2023-21678) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21678.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21678.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21760](https://github.com/Live-Hack-CVE/CVE-2023-21760) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21760.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21760.svg)

## CVE-2023-21764
 Microsoft Exchange Server Elevation of Privilege Vulnerability. This CVE ID is unique from CVE-2023-21763.



- [https://github.com/Live-Hack-CVE/CVE-2023-21764](https://github.com/Live-Hack-CVE/CVE-2023-21764) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21764.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21764.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21763](https://github.com/Live-Hack-CVE/CVE-2023-21763) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21763.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21763.svg)

## CVE-2023-21763
 Microsoft Exchange Server Elevation of Privilege Vulnerability. This CVE ID is unique from CVE-2023-21764.



- [https://github.com/Live-Hack-CVE/CVE-2023-21763](https://github.com/Live-Hack-CVE/CVE-2023-21763) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21763.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21763.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21764](https://github.com/Live-Hack-CVE/CVE-2023-21764) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21764.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21764.svg)

## CVE-2023-21762
 Microsoft Exchange Server Spoofing Vulnerability. This CVE ID is unique from CVE-2023-21745.



- [https://github.com/Live-Hack-CVE/CVE-2023-21762](https://github.com/Live-Hack-CVE/CVE-2023-21762) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21762.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21762.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21745](https://github.com/Live-Hack-CVE/CVE-2023-21745) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21745.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21745.svg)

## CVE-2023-21761
 Microsoft Exchange Server Information Disclosure Vulnerability.



- [https://github.com/Live-Hack-CVE/CVE-2023-21761](https://github.com/Live-Hack-CVE/CVE-2023-21761) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21761.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21761.svg)

## CVE-2023-21760
 Windows Print Spooler Elevation of Privilege Vulnerability. This CVE ID is unique from CVE-2023-21678, CVE-2023-21765.



- [https://github.com/Live-Hack-CVE/CVE-2023-21760](https://github.com/Live-Hack-CVE/CVE-2023-21760) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21760.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21760.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21678](https://github.com/Live-Hack-CVE/CVE-2023-21678) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21678.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21678.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21765](https://github.com/Live-Hack-CVE/CVE-2023-21765) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21765.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21765.svg)

## CVE-2023-21759
 Windows Smart Card Resource Management Server Security Feature Bypass Vulnerability.



- [https://github.com/Live-Hack-CVE/CVE-2023-21759](https://github.com/Live-Hack-CVE/CVE-2023-21759) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21759.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21759.svg)

## CVE-2023-21758
 Windows Internet Key Exchange (IKE) Extension Denial of Service Vulnerability. This CVE ID is unique from CVE-2023-21677, CVE-2023-21683.



- [https://github.com/Live-Hack-CVE/CVE-2023-21758](https://github.com/Live-Hack-CVE/CVE-2023-21758) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21758.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21758.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21677](https://github.com/Live-Hack-CVE/CVE-2023-21677) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21677.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21677.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21683](https://github.com/Live-Hack-CVE/CVE-2023-21683) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21683.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21683.svg)

## CVE-2023-21757
 Windows Layer 2 Tunneling Protocol (L2TP) Denial of Service Vulnerability.



- [https://github.com/Live-Hack-CVE/CVE-2023-21757](https://github.com/Live-Hack-CVE/CVE-2023-21757) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21757.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21757.svg)

## CVE-2023-21755
 Windows Kernel Elevation of Privilege Vulnerability. This CVE ID is unique from CVE-2023-21675, CVE-2023-21747, CVE-2023-21748, CVE-2023-21749, CVE-2023-21750, CVE-2023-21754, CVE-2023-21772, CVE-2023-21773, CVE-2023-21774.



- [https://github.com/Live-Hack-CVE/CVE-2023-21755](https://github.com/Live-Hack-CVE/CVE-2023-21755) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21755.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21755.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21754](https://github.com/Live-Hack-CVE/CVE-2023-21754) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21754.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21754.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21774](https://github.com/Live-Hack-CVE/CVE-2023-21774) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21774.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21774.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21773](https://github.com/Live-Hack-CVE/CVE-2023-21773) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21773.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21773.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21748](https://github.com/Live-Hack-CVE/CVE-2023-21748) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21748.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21748.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21772](https://github.com/Live-Hack-CVE/CVE-2023-21772) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21772.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21772.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21747](https://github.com/Live-Hack-CVE/CVE-2023-21747) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21747.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21747.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21675](https://github.com/Live-Hack-CVE/CVE-2023-21675) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21675.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21675.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21749](https://github.com/Live-Hack-CVE/CVE-2023-21749) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21749.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21749.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21750](https://github.com/Live-Hack-CVE/CVE-2023-21750) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21750.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21750.svg)

## CVE-2023-21754
 Windows Kernel Elevation of Privilege Vulnerability. This CVE ID is unique from CVE-2023-21675, CVE-2023-21747, CVE-2023-21748, CVE-2023-21749, CVE-2023-21750, CVE-2023-21755, CVE-2023-21772, CVE-2023-21773, CVE-2023-21774.



- [https://github.com/Live-Hack-CVE/CVE-2023-21754](https://github.com/Live-Hack-CVE/CVE-2023-21754) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21754.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21754.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21774](https://github.com/Live-Hack-CVE/CVE-2023-21774) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21774.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21774.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21755](https://github.com/Live-Hack-CVE/CVE-2023-21755) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21755.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21755.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21772](https://github.com/Live-Hack-CVE/CVE-2023-21772) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21772.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21772.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21748](https://github.com/Live-Hack-CVE/CVE-2023-21748) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21748.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21748.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21773](https://github.com/Live-Hack-CVE/CVE-2023-21773) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21773.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21773.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21747](https://github.com/Live-Hack-CVE/CVE-2023-21747) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21747.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21747.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21675](https://github.com/Live-Hack-CVE/CVE-2023-21675) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21675.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21675.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21749](https://github.com/Live-Hack-CVE/CVE-2023-21749) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21749.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21749.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21750](https://github.com/Live-Hack-CVE/CVE-2023-21750) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21750.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21750.svg)

## CVE-2023-21753
 Event Tracing for Windows Information Disclosure Vulnerability. This CVE ID is unique from CVE-2023-21536.



- [https://github.com/Live-Hack-CVE/CVE-2023-21753](https://github.com/Live-Hack-CVE/CVE-2023-21753) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21753.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21753.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21536](https://github.com/Live-Hack-CVE/CVE-2023-21536) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21536.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21536.svg)

## CVE-2023-21752
 Windows Backup Service Elevation of Privilege Vulnerability.



- [https://github.com/Wh04m1001/CVE-2023-21752](https://github.com/Wh04m1001/CVE-2023-21752) :  ![starts](https://img.shields.io/github/stars/Wh04m1001/CVE-2023-21752.svg) ![forks](https://img.shields.io/github/forks/Wh04m1001/CVE-2023-21752.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21752](https://github.com/Live-Hack-CVE/CVE-2023-21752) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21752.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21752.svg)

## CVE-2023-21750
 Windows Kernel Elevation of Privilege Vulnerability. This CVE ID is unique from CVE-2023-21675, CVE-2023-21747, CVE-2023-21748, CVE-2023-21749, CVE-2023-21754, CVE-2023-21755, CVE-2023-21772, CVE-2023-21773, CVE-2023-21774.



- [https://github.com/Live-Hack-CVE/CVE-2023-21750](https://github.com/Live-Hack-CVE/CVE-2023-21750) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21750.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21750.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21754](https://github.com/Live-Hack-CVE/CVE-2023-21754) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21754.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21754.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21774](https://github.com/Live-Hack-CVE/CVE-2023-21774) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21774.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21774.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21773](https://github.com/Live-Hack-CVE/CVE-2023-21773) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21773.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21773.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21755](https://github.com/Live-Hack-CVE/CVE-2023-21755) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21755.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21755.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21748](https://github.com/Live-Hack-CVE/CVE-2023-21748) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21748.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21748.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21772](https://github.com/Live-Hack-CVE/CVE-2023-21772) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21772.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21772.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21747](https://github.com/Live-Hack-CVE/CVE-2023-21747) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21747.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21747.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21675](https://github.com/Live-Hack-CVE/CVE-2023-21675) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21675.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21675.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21749](https://github.com/Live-Hack-CVE/CVE-2023-21749) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21749.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21749.svg)

## CVE-2023-21749
 Windows Kernel Elevation of Privilege Vulnerability. This CVE ID is unique from CVE-2023-21675, CVE-2023-21747, CVE-2023-21748, CVE-2023-21750, CVE-2023-21754, CVE-2023-21755, CVE-2023-21772, CVE-2023-21773, CVE-2023-21774.



- [https://github.com/Live-Hack-CVE/CVE-2023-21749](https://github.com/Live-Hack-CVE/CVE-2023-21749) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21749.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21749.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21675](https://github.com/Live-Hack-CVE/CVE-2023-21675) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21675.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21675.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21755](https://github.com/Live-Hack-CVE/CVE-2023-21755) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21755.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21755.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21774](https://github.com/Live-Hack-CVE/CVE-2023-21774) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21774.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21774.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21748](https://github.com/Live-Hack-CVE/CVE-2023-21748) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21748.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21748.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21773](https://github.com/Live-Hack-CVE/CVE-2023-21773) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21773.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21773.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21772](https://github.com/Live-Hack-CVE/CVE-2023-21772) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21772.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21772.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21754](https://github.com/Live-Hack-CVE/CVE-2023-21754) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21754.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21754.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21747](https://github.com/Live-Hack-CVE/CVE-2023-21747) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21747.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21747.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21750](https://github.com/Live-Hack-CVE/CVE-2023-21750) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21750.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21750.svg)

## CVE-2023-21748
 Windows Kernel Elevation of Privilege Vulnerability. This CVE ID is unique from CVE-2023-21675, CVE-2023-21747, CVE-2023-21749, CVE-2023-21750, CVE-2023-21754, CVE-2023-21755, CVE-2023-21772, CVE-2023-21773, CVE-2023-21774.



- [https://github.com/Live-Hack-CVE/CVE-2023-21748](https://github.com/Live-Hack-CVE/CVE-2023-21748) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21748.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21748.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21774](https://github.com/Live-Hack-CVE/CVE-2023-21774) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21774.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21774.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21755](https://github.com/Live-Hack-CVE/CVE-2023-21755) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21755.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21755.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21754](https://github.com/Live-Hack-CVE/CVE-2023-21754) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21754.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21754.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21772](https://github.com/Live-Hack-CVE/CVE-2023-21772) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21772.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21772.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21773](https://github.com/Live-Hack-CVE/CVE-2023-21773) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21773.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21773.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21747](https://github.com/Live-Hack-CVE/CVE-2023-21747) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21747.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21747.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21675](https://github.com/Live-Hack-CVE/CVE-2023-21675) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21675.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21675.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21749](https://github.com/Live-Hack-CVE/CVE-2023-21749) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21749.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21749.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21750](https://github.com/Live-Hack-CVE/CVE-2023-21750) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21750.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21750.svg)

## CVE-2023-21747
 Windows Kernel Elevation of Privilege Vulnerability. This CVE ID is unique from CVE-2023-21675, CVE-2023-21748, CVE-2023-21749, CVE-2023-21750, CVE-2023-21754, CVE-2023-21755, CVE-2023-21772, CVE-2023-21773, CVE-2023-21774.



- [https://github.com/Live-Hack-CVE/CVE-2023-21747](https://github.com/Live-Hack-CVE/CVE-2023-21747) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21747.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21747.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21755](https://github.com/Live-Hack-CVE/CVE-2023-21755) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21755.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21755.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21773](https://github.com/Live-Hack-CVE/CVE-2023-21773) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21773.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21773.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21772](https://github.com/Live-Hack-CVE/CVE-2023-21772) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21772.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21772.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21754](https://github.com/Live-Hack-CVE/CVE-2023-21754) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21754.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21754.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21675](https://github.com/Live-Hack-CVE/CVE-2023-21675) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21675.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21675.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21749](https://github.com/Live-Hack-CVE/CVE-2023-21749) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21749.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21749.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21774](https://github.com/Live-Hack-CVE/CVE-2023-21774) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21774.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21774.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21748](https://github.com/Live-Hack-CVE/CVE-2023-21748) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21748.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21748.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21750](https://github.com/Live-Hack-CVE/CVE-2023-21750) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21750.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21750.svg)

## CVE-2023-21746
 Windows NTLM Elevation of Privilege Vulnerability.



- [https://github.com/Live-Hack-CVE/CVE-2023-21746](https://github.com/Live-Hack-CVE/CVE-2023-21746) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21746.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21746.svg)

## CVE-2023-21745
 Microsoft Exchange Server Spoofing Vulnerability. This CVE ID is unique from CVE-2023-21762.



- [https://github.com/Live-Hack-CVE/CVE-2023-21745](https://github.com/Live-Hack-CVE/CVE-2023-21745) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21745.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21745.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21762](https://github.com/Live-Hack-CVE/CVE-2023-21762) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21762.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21762.svg)

## CVE-2023-21744
 Microsoft SharePoint Server Remote Code Execution Vulnerability. This CVE ID is unique from CVE-2023-21742.



- [https://github.com/Live-Hack-CVE/CVE-2023-21744](https://github.com/Live-Hack-CVE/CVE-2023-21744) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21744.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21744.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21742](https://github.com/Live-Hack-CVE/CVE-2023-21742) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21742.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21742.svg)

## CVE-2023-21743
 Microsoft SharePoint Server Security Feature Bypass Vulnerability.



- [https://github.com/Live-Hack-CVE/CVE-2023-21743](https://github.com/Live-Hack-CVE/CVE-2023-21743) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21743.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21743.svg)

## CVE-2023-21742
 Microsoft SharePoint Server Remote Code Execution Vulnerability. This CVE ID is unique from CVE-2023-21744.



- [https://github.com/Live-Hack-CVE/CVE-2023-21742](https://github.com/Live-Hack-CVE/CVE-2023-21742) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21742.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21742.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21744](https://github.com/Live-Hack-CVE/CVE-2023-21744) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21744.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21744.svg)

## CVE-2023-21739
 Windows Bluetooth Driver Elevation of Privilege Vulnerability.



- [https://github.com/Live-Hack-CVE/CVE-2023-21739](https://github.com/Live-Hack-CVE/CVE-2023-21739) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21739.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21739.svg)

## CVE-2023-21738
 Microsoft Office Visio Remote Code Execution Vulnerability. This CVE ID is unique from CVE-2023-21736, CVE-2023-21737.



- [https://github.com/Live-Hack-CVE/CVE-2023-21736](https://github.com/Live-Hack-CVE/CVE-2023-21736) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21736.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21736.svg)

## CVE-2023-21737
 Microsoft Office Visio Remote Code Execution Vulnerability. This CVE ID is unique from CVE-2023-21736, CVE-2023-21738.



- [https://github.com/Live-Hack-CVE/CVE-2023-21736](https://github.com/Live-Hack-CVE/CVE-2023-21736) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21736.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21736.svg)

## CVE-2023-21736
 Microsoft Office Visio Remote Code Execution Vulnerability. This CVE ID is unique from CVE-2023-21737, CVE-2023-21738.



- [https://github.com/Live-Hack-CVE/CVE-2023-21736](https://github.com/Live-Hack-CVE/CVE-2023-21736) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21736.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21736.svg)

## CVE-2023-21735
 Microsoft Office Remote Code Execution Vulnerability. This CVE ID is unique from CVE-2023-21734.



- [https://github.com/Live-Hack-CVE/CVE-2023-21735](https://github.com/Live-Hack-CVE/CVE-2023-21735) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21735.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21735.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21734](https://github.com/Live-Hack-CVE/CVE-2023-21734) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21734.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21734.svg)

## CVE-2023-21734
 Microsoft Office Remote Code Execution Vulnerability. This CVE ID is unique from CVE-2023-21735.



- [https://github.com/Live-Hack-CVE/CVE-2023-21734](https://github.com/Live-Hack-CVE/CVE-2023-21734) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21734.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21734.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21735](https://github.com/Live-Hack-CVE/CVE-2023-21735) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21735.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21735.svg)

## CVE-2023-21733
 Windows Bind Filter Driver Elevation of Privilege Vulnerability.



- [https://github.com/Live-Hack-CVE/CVE-2023-21733](https://github.com/Live-Hack-CVE/CVE-2023-21733) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21733.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21733.svg)

## CVE-2023-21732
 Microsoft ODBC Driver Remote Code Execution Vulnerability.



- [https://github.com/Live-Hack-CVE/CVE-2023-21732](https://github.com/Live-Hack-CVE/CVE-2023-21732) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21732.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21732.svg)

## CVE-2023-21730
 Microsoft Cryptographic Services Elevation of Privilege Vulnerability. This CVE ID is unique from CVE-2023-21551, CVE-2023-21561.



- [https://github.com/Live-Hack-CVE/CVE-2023-21730](https://github.com/Live-Hack-CVE/CVE-2023-21730) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21730.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21730.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21561](https://github.com/Live-Hack-CVE/CVE-2023-21561) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21561.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21561.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21551](https://github.com/Live-Hack-CVE/CVE-2023-21551) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21551.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21551.svg)

## CVE-2023-21728
 Windows Netlogon Denial of Service Vulnerability.



- [https://github.com/Live-Hack-CVE/CVE-2023-21728](https://github.com/Live-Hack-CVE/CVE-2023-21728) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21728.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21728.svg)

## CVE-2023-21726
 Windows Credential Manager User Interface Elevation of Privilege Vulnerability.



- [https://github.com/Live-Hack-CVE/CVE-2023-21726](https://github.com/Live-Hack-CVE/CVE-2023-21726) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21726.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21726.svg)

## CVE-2023-21725
 Windows Malicious Software Removal Tool Elevation of Privilege Vulnerability.



- [https://github.com/Live-Hack-CVE/CVE-2023-21725](https://github.com/Live-Hack-CVE/CVE-2023-21725) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21725.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21725.svg)

## CVE-2023-21724
 Microsoft DWM Core Library Elevation of Privilege Vulnerability.



- [https://github.com/Live-Hack-CVE/CVE-2023-21724](https://github.com/Live-Hack-CVE/CVE-2023-21724) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21724.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21724.svg)

## CVE-2023-21719
 Microsoft Edge (Chromium-based) Security Feature Bypass Vulnerability.



- [https://github.com/Live-Hack-CVE/CVE-2023-21719](https://github.com/Live-Hack-CVE/CVE-2023-21719) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21719.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21719.svg)

## CVE-2023-21683
 Windows Internet Key Exchange (IKE) Extension Denial of Service Vulnerability. This CVE ID is unique from CVE-2023-21677, CVE-2023-21758.



- [https://github.com/Live-Hack-CVE/CVE-2023-21683](https://github.com/Live-Hack-CVE/CVE-2023-21683) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21683.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21683.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21677](https://github.com/Live-Hack-CVE/CVE-2023-21677) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21677.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21677.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21758](https://github.com/Live-Hack-CVE/CVE-2023-21758) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21758.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21758.svg)

## CVE-2023-21682
 Windows Point-to-Point Protocol (PPP) Information Disclosure Vulnerability.



- [https://github.com/Live-Hack-CVE/CVE-2023-21682](https://github.com/Live-Hack-CVE/CVE-2023-21682) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21682.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21682.svg)

## CVE-2023-21681
 Microsoft WDAC OLE DB provider for SQL Server Remote Code Execution Vulnerability.



- [https://github.com/Live-Hack-CVE/CVE-2023-21681](https://github.com/Live-Hack-CVE/CVE-2023-21681) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21681.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21681.svg)

## CVE-2023-21680
 Windows Win32k Elevation of Privilege Vulnerability.



- [https://github.com/Live-Hack-CVE/CVE-2023-21680](https://github.com/Live-Hack-CVE/CVE-2023-21680) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21680.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21680.svg)

## CVE-2023-21679
 Windows Layer 2 Tunneling Protocol (L2TP) Remote Code Execution Vulnerability. This CVE ID is unique from CVE-2023-21543, CVE-2023-21546, CVE-2023-21555, CVE-2023-21556.



- [https://github.com/Live-Hack-CVE/CVE-2023-21679](https://github.com/Live-Hack-CVE/CVE-2023-21679) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21679.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21679.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21543](https://github.com/Live-Hack-CVE/CVE-2023-21543) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21543.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21543.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21546](https://github.com/Live-Hack-CVE/CVE-2023-21546) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21546.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21546.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21555](https://github.com/Live-Hack-CVE/CVE-2023-21555) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21555.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21555.svg)

## CVE-2023-21678
 Windows Print Spooler Elevation of Privilege Vulnerability. This CVE ID is unique from CVE-2023-21760, CVE-2023-21765.



- [https://github.com/Live-Hack-CVE/CVE-2023-21678](https://github.com/Live-Hack-CVE/CVE-2023-21678) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21678.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21678.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21765](https://github.com/Live-Hack-CVE/CVE-2023-21765) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21765.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21765.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21760](https://github.com/Live-Hack-CVE/CVE-2023-21760) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21760.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21760.svg)

## CVE-2023-21677
 Windows Internet Key Exchange (IKE) Extension Denial of Service Vulnerability. This CVE ID is unique from CVE-2023-21683, CVE-2023-21758.



- [https://github.com/Live-Hack-CVE/CVE-2023-21677](https://github.com/Live-Hack-CVE/CVE-2023-21677) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21677.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21677.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21758](https://github.com/Live-Hack-CVE/CVE-2023-21758) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21758.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21758.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21683](https://github.com/Live-Hack-CVE/CVE-2023-21683) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21683.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21683.svg)

## CVE-2023-21676
 Windows Lightweight Directory Access Protocol (LDAP) Remote Code Execution Vulnerability.



- [https://github.com/Live-Hack-CVE/CVE-2023-21676](https://github.com/Live-Hack-CVE/CVE-2023-21676) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21676.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21676.svg)

## CVE-2023-21675
 Windows Kernel Elevation of Privilege Vulnerability. This CVE ID is unique from CVE-2023-21747, CVE-2023-21748, CVE-2023-21749, CVE-2023-21750, CVE-2023-21754, CVE-2023-21755, CVE-2023-21772, CVE-2023-21773, CVE-2023-21774.



- [https://github.com/Live-Hack-CVE/CVE-2023-21675](https://github.com/Live-Hack-CVE/CVE-2023-21675) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21675.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21675.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21755](https://github.com/Live-Hack-CVE/CVE-2023-21755) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21755.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21755.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21748](https://github.com/Live-Hack-CVE/CVE-2023-21748) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21748.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21748.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21773](https://github.com/Live-Hack-CVE/CVE-2023-21773) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21773.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21773.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21772](https://github.com/Live-Hack-CVE/CVE-2023-21772) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21772.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21772.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21747](https://github.com/Live-Hack-CVE/CVE-2023-21747) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21747.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21747.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21749](https://github.com/Live-Hack-CVE/CVE-2023-21749) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21749.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21749.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21750](https://github.com/Live-Hack-CVE/CVE-2023-21750) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21750.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21750.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21754](https://github.com/Live-Hack-CVE/CVE-2023-21754) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21754.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21754.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21774](https://github.com/Live-Hack-CVE/CVE-2023-21774) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21774.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21774.svg)

## CVE-2023-21674
 Windows Advanced Local Procedure Call (ALPC) Elevation of Privilege Vulnerability.



- [https://github.com/Live-Hack-CVE/CVE-2023-21674](https://github.com/Live-Hack-CVE/CVE-2023-21674) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21674.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21674.svg)

## CVE-2023-21608
 Adobe Acrobat Reader versions 22.003.20282 (and earlier), 22.003.20281 (and earlier) and 20.005.30418 (and earlier) are affected by a Use After Free vulnerability that could result in arbitrary code execution in the context of the current user. Exploitation of this issue requires user interaction in that a victim must open a malicious file.



- [https://github.com/hacksysteam/CVE-2023-21608](https://github.com/hacksysteam/CVE-2023-21608) :  ![starts](https://img.shields.io/github/stars/hacksysteam/CVE-2023-21608.svg) ![forks](https://img.shields.io/github/forks/hacksysteam/CVE-2023-21608.svg)

- [https://github.com/PyterSmithDarkGhost/CVE-2023-21608-EXPLOIT](https://github.com/PyterSmithDarkGhost/CVE-2023-21608-EXPLOIT) :  ![starts](https://img.shields.io/github/stars/PyterSmithDarkGhost/CVE-2023-21608-EXPLOIT.svg) ![forks](https://img.shields.io/github/forks/PyterSmithDarkGhost/CVE-2023-21608-EXPLOIT.svg)

## CVE-2023-21606
 Adobe Acrobat Reader versions 22.003.20282 (and earlier), 22.003.20281 (and earlier) and 20.005.30418 (and earlier) are affected by an out-of-bounds write vulnerability that could result in arbitrary code execution in the context of the current user. Exploitation of this issue requires user interaction in that a victim must open a malicious file.



- [https://github.com/Live-Hack-CVE/CVE-2023-21606](https://github.com/Live-Hack-CVE/CVE-2023-21606) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21606.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21606.svg)

## CVE-2023-21605
 Adobe Acrobat Reader versions 22.003.20282 (and earlier), 22.003.20281 (and earlier) and 20.005.30418 (and earlier) are affected by a Heap-based Buffer Overflow vulnerability that could result in arbitrary code execution in the context of the current user. Exploitation of this issue requires user interaction in that a victim must open a malicious file.



- [https://github.com/Live-Hack-CVE/CVE-2023-21605](https://github.com/Live-Hack-CVE/CVE-2023-21605) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21605.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21605.svg)

## CVE-2023-21603
 Adobe Dimension version 3.4.6 (and earlier) are affected by an out-of-bounds read vulnerability that could lead to disclosure of sensitive memory. An attacker could leverage this vulnerability to bypass mitigations such as ASLR. Exploitation of this issue requires user interaction in that a victim must open a malicious file.



- [https://github.com/Live-Hack-CVE/CVE-2023-21603](https://github.com/Live-Hack-CVE/CVE-2023-21603) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21603.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21603.svg)

## CVE-2023-21601
 Adobe Dimension version 3.4.6 (and earlier) are affected by a Use After Free vulnerability that could lead to disclosure of sensitive memory. An attacker could leverage this vulnerability to bypass mitigations such as ASLR. Exploitation of this issue requires user interaction in that a victim must open a malicious file.



- [https://github.com/Live-Hack-CVE/CVE-2023-21601](https://github.com/Live-Hack-CVE/CVE-2023-21601) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21601.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21601.svg)

## CVE-2023-21599
 Adobe InCopy versions 18.0 (and earlier), 17.4 (and earlier) are affected by an out-of-bounds read vulnerability that could lead to disclosure of sensitive memory. An attacker could leverage this vulnerability to bypass mitigations such as ASLR. Exploitation of this issue requires user interaction in that a victim must open a malicious file.



- [https://github.com/Live-Hack-CVE/CVE-2023-21599](https://github.com/Live-Hack-CVE/CVE-2023-21599) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21599.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21599.svg)

## CVE-2023-21598
 Adobe InCopy versions 18.0 (and earlier), 17.4 (and earlier) are affected by a Use After Free vulnerability that could lead to disclosure of sensitive memory. An attacker could leverage this vulnerability to bypass mitigations such as ASLR. Exploitation of this issue requires user interaction in that a victim must open a malicious file.



- [https://github.com/Live-Hack-CVE/CVE-2023-21598](https://github.com/Live-Hack-CVE/CVE-2023-21598) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21598.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21598.svg)

## CVE-2023-21597
 Adobe InCopy versions 18.0 (and earlier), 17.4 (and earlier) are affected by an out-of-bounds write vulnerability that could result in arbitrary code execution in the context of the current user. Exploitation of this issue requires user interaction in that a victim must open a malicious file.



- [https://github.com/Live-Hack-CVE/CVE-2023-21597](https://github.com/Live-Hack-CVE/CVE-2023-21597) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21597.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21597.svg)

## CVE-2023-21596
 Adobe InCopy versions 18.0 (and earlier), 17.4 (and earlier) are affected by an Improper Input Validation vulnerability that could result in arbitrary code execution in the context of the current user. Exploitation of this issue requires user interaction in that a victim must open a malicious file.



- [https://github.com/Live-Hack-CVE/CVE-2023-21596](https://github.com/Live-Hack-CVE/CVE-2023-21596) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21596.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21596.svg)

## CVE-2023-21595
 Adobe InCopy versions 18.0 (and earlier), 17.4 (and earlier) are affected by an out-of-bounds write vulnerability that could result in arbitrary code execution in the context of the current user. Exploitation of this issue requires user interaction in that a victim must open a malicious file.



- [https://github.com/Live-Hack-CVE/CVE-2023-21595](https://github.com/Live-Hack-CVE/CVE-2023-21595) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21595.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21595.svg)

## CVE-2023-21594
 Adobe InCopy versions 18.0 (and earlier), 17.4 (and earlier) are affected by a Heap-based Buffer Overflow vulnerability that could result in arbitrary code execution in the context of the current user. Exploitation of this issue requires user interaction in that a victim must open a malicious file.



- [https://github.com/Live-Hack-CVE/CVE-2023-21594](https://github.com/Live-Hack-CVE/CVE-2023-21594) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21594.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21594.svg)

## CVE-2023-21592
 Adobe InDesign version 18.0 (and earlier), 17.4 (and earlier) are affected by an out-of-bounds read vulnerability that could lead to disclosure of sensitive memory. An attacker could leverage this vulnerability to bypass mitigations such as ASLR. Exploitation of this issue requires user interaction in that a victim must open a malicious file.



- [https://github.com/Live-Hack-CVE/CVE-2023-21592](https://github.com/Live-Hack-CVE/CVE-2023-21592) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21592.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21592.svg)

## CVE-2023-21591
 Adobe InDesign version 18.0 (and earlier), 17.4 (and earlier) are affected by an out-of-bounds read vulnerability that could lead to disclosure of sensitive memory. An attacker could leverage this vulnerability to bypass mitigations such as ASLR. Exploitation of this issue requires user interaction in that a victim must open a malicious file.



- [https://github.com/Live-Hack-CVE/CVE-2023-21591](https://github.com/Live-Hack-CVE/CVE-2023-21591) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21591.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21591.svg)

## CVE-2023-21590
 Adobe InDesign version 18.0 (and earlier), 17.4 (and earlier) are affected by an out-of-bounds write vulnerability that could result in arbitrary code execution in the context of the current user. Exploitation of this issue requires user interaction in that a victim must open a malicious file.



- [https://github.com/Live-Hack-CVE/CVE-2023-21590](https://github.com/Live-Hack-CVE/CVE-2023-21590) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21590.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21590.svg)

## CVE-2023-21589
 Adobe InDesign version 18.0 (and earlier), 17.4 (and earlier) are affected by an out-of-bounds write vulnerability that could result in arbitrary code execution in the context of the current user. Exploitation of this issue requires user interaction in that a victim must open a malicious file.



- [https://github.com/Live-Hack-CVE/CVE-2023-21589](https://github.com/Live-Hack-CVE/CVE-2023-21589) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21589.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21589.svg)

## CVE-2023-21588
 Adobe InDesign version 18.0 (and earlier), 17.4 (and earlier) are affected by an Improper Input Validation vulnerability that could result in arbitrary code execution in the context of the current user. Exploitation of this issue requires user interaction in that a victim must open a malicious file.



- [https://github.com/Live-Hack-CVE/CVE-2023-21588](https://github.com/Live-Hack-CVE/CVE-2023-21588) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21588.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21588.svg)

## CVE-2023-21587
 Adobe InDesign version 18.0 (and earlier), 17.4 (and earlier) are affected by a Heap-based Buffer Overflow vulnerability that could result in arbitrary code execution in the context of the current user. Exploitation of this issue requires user interaction in that a victim must open a malicious file.



- [https://github.com/Live-Hack-CVE/CVE-2023-21587](https://github.com/Live-Hack-CVE/CVE-2023-21587) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21587.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21587.svg)

## CVE-2023-21563
 BitLocker Security Feature Bypass Vulnerability.



- [https://github.com/Live-Hack-CVE/CVE-2023-21563](https://github.com/Live-Hack-CVE/CVE-2023-21563) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21563.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21563.svg)

## CVE-2023-21561
 Microsoft Cryptographic Services Elevation of Privilege Vulnerability. This CVE ID is unique from CVE-2023-21551, CVE-2023-21730.



- [https://github.com/Live-Hack-CVE/CVE-2023-21561](https://github.com/Live-Hack-CVE/CVE-2023-21561) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21561.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21561.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21730](https://github.com/Live-Hack-CVE/CVE-2023-21730) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21730.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21730.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21551](https://github.com/Live-Hack-CVE/CVE-2023-21551) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21551.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21551.svg)

## CVE-2023-21560
 Windows Boot Manager Security Feature Bypass Vulnerability.



- [https://github.com/Live-Hack-CVE/CVE-2023-21560](https://github.com/Live-Hack-CVE/CVE-2023-21560) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21560.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21560.svg)

## CVE-2023-21559
 Windows Cryptographic Information Disclosure Vulnerability. This CVE ID is unique from CVE-2023-21540, CVE-2023-21550.



- [https://github.com/Live-Hack-CVE/CVE-2023-21559](https://github.com/Live-Hack-CVE/CVE-2023-21559) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21559.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21559.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21540](https://github.com/Live-Hack-CVE/CVE-2023-21540) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21540.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21540.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21550](https://github.com/Live-Hack-CVE/CVE-2023-21550) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21550.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21550.svg)

## CVE-2023-21558
 Windows Error Reporting Service Elevation of Privilege Vulnerability.



- [https://github.com/Live-Hack-CVE/CVE-2023-21558](https://github.com/Live-Hack-CVE/CVE-2023-21558) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21558.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21558.svg)

## CVE-2023-21556
 Windows Layer 2 Tunneling Protocol (L2TP) Remote Code Execution Vulnerability. This CVE ID is unique from CVE-2023-21543, CVE-2023-21546, CVE-2023-21555, CVE-2023-21679.



- [https://github.com/Live-Hack-CVE/CVE-2023-21543](https://github.com/Live-Hack-CVE/CVE-2023-21543) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21543.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21543.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21555](https://github.com/Live-Hack-CVE/CVE-2023-21555) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21555.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21555.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21679](https://github.com/Live-Hack-CVE/CVE-2023-21679) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21679.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21679.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21546](https://github.com/Live-Hack-CVE/CVE-2023-21546) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21546.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21546.svg)

## CVE-2023-21555
 Windows Layer 2 Tunneling Protocol (L2TP) Remote Code Execution Vulnerability. This CVE ID is unique from CVE-2023-21543, CVE-2023-21546, CVE-2023-21556, CVE-2023-21679.



- [https://github.com/Live-Hack-CVE/CVE-2023-21555](https://github.com/Live-Hack-CVE/CVE-2023-21555) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21555.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21555.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21543](https://github.com/Live-Hack-CVE/CVE-2023-21543) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21543.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21543.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21679](https://github.com/Live-Hack-CVE/CVE-2023-21679) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21679.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21679.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21546](https://github.com/Live-Hack-CVE/CVE-2023-21546) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21546.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21546.svg)

## CVE-2023-21552
 Windows GDI Elevation of Privilege Vulnerability. This CVE ID is unique from CVE-2023-21532.



- [https://github.com/Live-Hack-CVE/CVE-2023-21532](https://github.com/Live-Hack-CVE/CVE-2023-21532) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21532.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21532.svg)

## CVE-2023-21551
 Microsoft Cryptographic Services Elevation of Privilege Vulnerability. This CVE ID is unique from CVE-2023-21561, CVE-2023-21730.



- [https://github.com/Live-Hack-CVE/CVE-2023-21551](https://github.com/Live-Hack-CVE/CVE-2023-21551) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21551.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21551.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21730](https://github.com/Live-Hack-CVE/CVE-2023-21730) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21730.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21730.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21561](https://github.com/Live-Hack-CVE/CVE-2023-21561) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21561.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21561.svg)

## CVE-2023-21550
 Windows Cryptographic Information Disclosure Vulnerability. This CVE ID is unique from CVE-2023-21540, CVE-2023-21559.



- [https://github.com/Live-Hack-CVE/CVE-2023-21550](https://github.com/Live-Hack-CVE/CVE-2023-21550) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21550.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21550.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21559](https://github.com/Live-Hack-CVE/CVE-2023-21559) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21559.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21559.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21540](https://github.com/Live-Hack-CVE/CVE-2023-21540) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21540.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21540.svg)

## CVE-2023-21549
 Windows SMB Witness Service Elevation of Privilege Vulnerability.



- [https://github.com/Live-Hack-CVE/CVE-2023-21549](https://github.com/Live-Hack-CVE/CVE-2023-21549) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21549.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21549.svg)

## CVE-2023-21548
 Windows Secure Socket Tunneling Protocol (SSTP) Remote Code Execution Vulnerability. This CVE ID is unique from CVE-2023-21535.



- [https://github.com/Live-Hack-CVE/CVE-2023-21548](https://github.com/Live-Hack-CVE/CVE-2023-21548) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21548.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21548.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21535](https://github.com/Live-Hack-CVE/CVE-2023-21535) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21535.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21535.svg)

## CVE-2023-21547
 Internet Key Exchange (IKE) Protocol Denial of Service Vulnerability.



- [https://github.com/Live-Hack-CVE/CVE-2023-21547](https://github.com/Live-Hack-CVE/CVE-2023-21547) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21547.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21547.svg)

## CVE-2023-21546
 Windows Layer 2 Tunneling Protocol (L2TP) Remote Code Execution Vulnerability. This CVE ID is unique from CVE-2023-21543, CVE-2023-21555, CVE-2023-21556, CVE-2023-21679.



- [https://github.com/Live-Hack-CVE/CVE-2023-21546](https://github.com/Live-Hack-CVE/CVE-2023-21546) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21546.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21546.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21543](https://github.com/Live-Hack-CVE/CVE-2023-21543) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21543.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21543.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21679](https://github.com/Live-Hack-CVE/CVE-2023-21679) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21679.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21679.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21555](https://github.com/Live-Hack-CVE/CVE-2023-21555) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21555.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21555.svg)

## CVE-2023-21543
 Windows Layer 2 Tunneling Protocol (L2TP) Remote Code Execution Vulnerability. This CVE ID is unique from CVE-2023-21546, CVE-2023-21555, CVE-2023-21556, CVE-2023-21679.



- [https://github.com/Live-Hack-CVE/CVE-2023-21543](https://github.com/Live-Hack-CVE/CVE-2023-21543) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21543.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21543.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21679](https://github.com/Live-Hack-CVE/CVE-2023-21679) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21679.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21679.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21546](https://github.com/Live-Hack-CVE/CVE-2023-21546) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21546.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21546.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21555](https://github.com/Live-Hack-CVE/CVE-2023-21555) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21555.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21555.svg)

## CVE-2023-21542
 Windows Installer Elevation of Privilege Vulnerability.



- [https://github.com/Live-Hack-CVE/CVE-2023-21542](https://github.com/Live-Hack-CVE/CVE-2023-21542) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21542.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21542.svg)

## CVE-2023-21541
 Windows Task Scheduler Elevation of Privilege Vulnerability.



- [https://github.com/Live-Hack-CVE/CVE-2023-21541](https://github.com/Live-Hack-CVE/CVE-2023-21541) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21541.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21541.svg)

## CVE-2023-21540
 Windows Cryptographic Information Disclosure Vulnerability. This CVE ID is unique from CVE-2023-21550, CVE-2023-21559.



- [https://github.com/Live-Hack-CVE/CVE-2023-21540](https://github.com/Live-Hack-CVE/CVE-2023-21540) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21540.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21540.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21559](https://github.com/Live-Hack-CVE/CVE-2023-21559) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21559.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21559.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21550](https://github.com/Live-Hack-CVE/CVE-2023-21550) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21550.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21550.svg)

## CVE-2023-21539
 Windows Authentication Remote Code Execution Vulnerability.



- [https://github.com/Live-Hack-CVE/CVE-2023-21539](https://github.com/Live-Hack-CVE/CVE-2023-21539) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21539.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21539.svg)

## CVE-2023-21538
 .NET Denial of Service Vulnerability.



- [https://github.com/Live-Hack-CVE/CVE-2023-21538](https://github.com/Live-Hack-CVE/CVE-2023-21538) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21538.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21538.svg)

## CVE-2023-21537
 Microsoft Message Queuing (MSMQ) Elevation of Privilege Vulnerability.



- [https://github.com/Live-Hack-CVE/CVE-2023-21537](https://github.com/Live-Hack-CVE/CVE-2023-21537) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21537.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21537.svg)

## CVE-2023-21536
 Event Tracing for Windows Information Disclosure Vulnerability. This CVE ID is unique from CVE-2023-21753.



- [https://github.com/Live-Hack-CVE/CVE-2023-21536](https://github.com/Live-Hack-CVE/CVE-2023-21536) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21536.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21536.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21753](https://github.com/Live-Hack-CVE/CVE-2023-21753) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21753.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21753.svg)

## CVE-2023-21535
 Windows Secure Socket Tunneling Protocol (SSTP) Remote Code Execution Vulnerability. This CVE ID is unique from CVE-2023-21548.



- [https://github.com/Live-Hack-CVE/CVE-2023-21535](https://github.com/Live-Hack-CVE/CVE-2023-21535) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21535.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21535.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-21548](https://github.com/Live-Hack-CVE/CVE-2023-21548) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21548.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21548.svg)

## CVE-2023-21532
 Windows GDI Elevation of Privilege Vulnerability. This CVE ID is unique from CVE-2023-21552.



- [https://github.com/Live-Hack-CVE/CVE-2023-21532](https://github.com/Live-Hack-CVE/CVE-2023-21532) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21532.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21532.svg)

## CVE-2023-21531
 Azure Service Fabric Container Elevation of Privilege Vulnerability.



- [https://github.com/Live-Hack-CVE/CVE-2023-21531](https://github.com/Live-Hack-CVE/CVE-2023-21531) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21531.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21531.svg)

## CVE-2023-21527
 Windows iSCSI Service Denial of Service Vulnerability.



- [https://github.com/Live-Hack-CVE/CVE-2023-21527](https://github.com/Live-Hack-CVE/CVE-2023-21527) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21527.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21527.svg)

## CVE-2023-21525
 Remote Procedure Call Runtime Denial of Service Vulnerability.



- [https://github.com/Live-Hack-CVE/CVE-2023-21525](https://github.com/Live-Hack-CVE/CVE-2023-21525) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21525.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21525.svg)

## CVE-2023-21524
 Windows Local Security Authority (LSA) Elevation of Privilege Vulnerability.



- [https://github.com/Live-Hack-CVE/CVE-2023-21524](https://github.com/Live-Hack-CVE/CVE-2023-21524) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21524.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21524.svg)

## CVE-2023-20922
 In setMimeGroup of PackageManagerService.java, there is a possible crash loop due to resource exhaustion. This could lead to local denial of service with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-11 Android-12 Android-12L Android-13Android ID: A-237291548



- [https://github.com/Live-Hack-CVE/CVE-2023-20922](https://github.com/Live-Hack-CVE/CVE-2023-20922) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-20922.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-20922.svg)

## CVE-2023-20921
 In onPackageRemoved of AccessibilityManagerService.java, there is a possibility to automatically grant accessibility services due to a logic error in the code. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is needed for exploitation.Product: AndroidVersions: Android-10 Android-11 Android-12 Android-12L Android-13Android ID: A-243378132



- [https://github.com/Live-Hack-CVE/CVE-2023-20921](https://github.com/Live-Hack-CVE/CVE-2023-20921) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-20921.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-20921.svg)

## CVE-2023-20920
 In queue of UsbRequest.java, there is a possible way to corrupt memory due to a use after free. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-10 Android-11 Android-12 Android-12L Android-13Android ID: A-204584366



- [https://github.com/Live-Hack-CVE/CVE-2023-20920](https://github.com/Live-Hack-CVE/CVE-2023-20920) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-20920.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-20920.svg)

## CVE-2023-20919
 In getStringsForPrefix of Settings.java, there is a possible prevention of package uninstallation due to a logic error in the code. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-13Android ID: A-252663068



- [https://github.com/Live-Hack-CVE/CVE-2023-20919](https://github.com/Live-Hack-CVE/CVE-2023-20919) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-20919.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-20919.svg)

## CVE-2023-20916
 In getMainActivityLaunchIntent of LauncherAppsService.java, there is a possible way to bypass the restrictions on starting activities from the background due to a missing permission check. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-12 Android-12LAndroid ID: A-229256049



- [https://github.com/Live-Hack-CVE/CVE-2023-20916](https://github.com/Live-Hack-CVE/CVE-2023-20916) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-20916.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-20916.svg)

## CVE-2023-20856
 VMware vRealize Operations (vROps) contains a CSRF bypass vulnerability. A malicious user could execute actions on the vROps platform on behalf of the authenticated victim user.



- [https://github.com/Live-Hack-CVE/CVE-2023-20856](https://github.com/Live-Hack-CVE/CVE-2023-20856) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-20856.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-20856.svg)

## CVE-2023-20532
 Insufficient input validation in the SMU may allow an attacker to improperly lock resources, potentially resulting in a denial of service.



- [https://github.com/Live-Hack-CVE/CVE-2023-20532](https://github.com/Live-Hack-CVE/CVE-2023-20532) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-20532.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-20532.svg)

## CVE-2023-20531
 Insufficient bound checks in the SMU may allow an attacker to update the SRAM from/to address space to an invalid value potentially resulting in a denial of service.



- [https://github.com/Live-Hack-CVE/CVE-2023-20531](https://github.com/Live-Hack-CVE/CVE-2023-20531) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-20531.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-20531.svg)

## CVE-2023-20530
 Insufficient input validation of BIOS mailbox messages in SMU may result in out-of-bounds memory reads potentially resulting in a denial of service.



- [https://github.com/Live-Hack-CVE/CVE-2023-20530](https://github.com/Live-Hack-CVE/CVE-2023-20530) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-20530.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-20530.svg)

## CVE-2023-20529
 Insufficient bound checks in the SMU may allow an attacker to update the from/to address space to an invalid value potentially resulting in a denial of service.



- [https://github.com/Live-Hack-CVE/CVE-2023-20529](https://github.com/Live-Hack-CVE/CVE-2023-20529) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-20529.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-20529.svg)

## CVE-2023-20528
 Insufficient input validation in the SMU may allow a physical attacker to exfiltrate SMU memory contents over the I2C bus potentially leading to a loss of confidentiality.



- [https://github.com/Live-Hack-CVE/CVE-2023-20528](https://github.com/Live-Hack-CVE/CVE-2023-20528) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-20528.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-20528.svg)

## CVE-2023-20527
 Improper syscall input validation in the ASP Bootloader may allow a privileged attacker to read memory out-of-bounds, potentially leading to a denial-of-service.



- [https://github.com/Live-Hack-CVE/CVE-2023-20527](https://github.com/Live-Hack-CVE/CVE-2023-20527) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-20527.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-20527.svg)

## CVE-2023-20525
 Insufficient syscall input validation in the ASP Bootloader may allow a privileged attacker to read memory outside the bounds of a mapped register potentially leading to a denial of service.



- [https://github.com/Live-Hack-CVE/CVE-2023-20525](https://github.com/Live-Hack-CVE/CVE-2023-20525) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-20525.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-20525.svg)

## CVE-2023-20523
 TOCTOU in the ASP may allow a physical attacker to write beyond the buffer bounds, potentially leading to a loss of integrity or denial of service.



- [https://github.com/Live-Hack-CVE/CVE-2023-20523](https://github.com/Live-Hack-CVE/CVE-2023-20523) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-20523.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-20523.svg)

## CVE-2023-20522
 Insufficient input validation in ASP may allow an attacker with a malicious BIOS to potentially cause a denial of service.



- [https://github.com/Live-Hack-CVE/CVE-2023-20522](https://github.com/Live-Hack-CVE/CVE-2023-20522) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-20522.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-20522.svg)

## CVE-2023-20057
 A vulnerability in the URL filtering mechanism of Cisco AsyncOS Software for Cisco Email Security Appliance (ESA) could allow an unauthenticated, remote attacker to bypass the URL reputation filters on an affected device. This vulnerability is due to improper processing of URLs. An attacker could exploit this vulnerability by crafting a URL in a particular way. A successful exploit could allow the attacker to bypass the URL reputation filters that are configured for an affected device, which could allow malicious URLs to pass through the device.



- [https://github.com/Live-Hack-CVE/CVE-2023-20057](https://github.com/Live-Hack-CVE/CVE-2023-20057) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-20057.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-20057.svg)

## CVE-2023-20043
 A vulnerability in Cisco CX Cloud Agent of could allow an authenticated, local attacker to elevate their privileges. This vulnerability is due to insecure file permissions. An attacker could exploit this vulnerability by calling the script with sudo. A successful exploit could allow the attacker to take complete control of the affected device.



- [https://github.com/Live-Hack-CVE/CVE-2023-20043](https://github.com/Live-Hack-CVE/CVE-2023-20043) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-20043.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-20043.svg)

## CVE-2023-20020
 A vulnerability in the Device Management Servlet application of Cisco BroadWorks Application Delivery Platform and Cisco BroadWorks Xtended Services Platform could allow an unauthenticated, remote attacker to cause a denial of service (DoS) condition on an affected device. This vulnerability is due to improper input validation when parsing HTTP requests. An attacker could exploit this vulnerability by sending a sustained stream of crafted requests to an affected device. A successful exploit could allow the attacker to cause all subsequent requests to be dropped, resulting in a DoS condition.



- [https://github.com/Live-Hack-CVE/CVE-2023-20020](https://github.com/Live-Hack-CVE/CVE-2023-20020) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-20020.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-20020.svg)

## CVE-2023-20019
 A vulnerability in the web-based management interface of Cisco BroadWorks Application Delivery Platform, Cisco BroadWorks Application Server, and Cisco BroadWorks Xtended Services Platform could allow an unauthenticated, remote attacker to conduct a cross-site scripting (XSS) attack against a user of the interface of an affected device. This vulnerability exists because the web-based management interface does not properly validate user-supplied input. An attacker could exploit this vulnerability by persuading a user of the interface to click a crafted link. A successful exploit could allow the attacker to execute arbitrary script code in the context of the affected interface or access sensitive, browser-based information.



- [https://github.com/Live-Hack-CVE/CVE-2023-20019](https://github.com/Live-Hack-CVE/CVE-2023-20019) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-20019.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-20019.svg)

## CVE-2023-20007
 A vulnerability in the web-based management interface of Cisco Small Business RV340, RV340W, RV345, and RV345P Dual WAN Gigabit VPN Routers could allow an authenticated, remote attacker to execute arbitrary code or cause the web-based management process on the device to restart unexpectedly, resulting in a denial of service (DoS) condition. The attacker must have valid administrator credentials. This vulnerability is due to insufficient validation of user-supplied input to the web-based management interface. An attacker could exploit this vulnerability by sending crafted HTTP input to an affected device. A successful exploit could allow the attacker to execute arbitrary code as the root user on the underlying operating system or cause the web-based management process to restart, resulting in a DoS condition.



- [https://github.com/Live-Hack-CVE/CVE-2023-20007](https://github.com/Live-Hack-CVE/CVE-2023-20007) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-20007.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-20007.svg)

## CVE-2023-0760
 Heap-based Buffer Overflow in GitHub repository gpac/gpac prior to V2.1.0-DEV.



- [https://github.com/Live-Hack-CVE/CVE-2023-0760](https://github.com/Live-Hack-CVE/CVE-2023-0760) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0760.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0760.svg)

## CVE-2023-0759
 Privilege Chaining in GitHub repository cockpit-hq/cockpit prior to 2.3.8.



- [https://github.com/Live-Hack-CVE/CVE-2023-0759](https://github.com/Live-Hack-CVE/CVE-2023-0759) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0759.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0759.svg)

## CVE-2023-0758
 A vulnerability was found in glorylion JFinalOA 1.0.2 and classified as critical. This issue affects some unknown processing of the file src/main/java/com/pointlion/mvc/common/model/SysOrg.java. The manipulation of the argument id leads to sql injection. The attack may be initiated remotely. The exploit has been disclosed to the public and may be used. The identifier VDB-220469 was assigned to this vulnerability.



- [https://github.com/Live-Hack-CVE/CVE-2023-0758](https://github.com/Live-Hack-CVE/CVE-2023-0758) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0758.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0758.svg)

## CVE-2023-0748
 Open Redirect in GitHub repository btcpayserver/btcpayserver prior to 1.7.6.



- [https://github.com/Live-Hack-CVE/CVE-2023-0748](https://github.com/Live-Hack-CVE/CVE-2023-0748) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0748.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0748.svg)

## CVE-2023-0747
 Cross-site Scripting (XSS) - Stored in GitHub repository btcpayserver/btcpayserver prior to 1.7.6.



- [https://github.com/Live-Hack-CVE/CVE-2023-0747](https://github.com/Live-Hack-CVE/CVE-2023-0747) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0747.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0747.svg)

## CVE-2023-0744
 Improper Access Control in GitHub repository answerdev/answer prior to 1.0.4.



- [https://github.com/Live-Hack-CVE/CVE-2023-0744](https://github.com/Live-Hack-CVE/CVE-2023-0744) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0744.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0744.svg)

## CVE-2023-0743
 Cross-site Scripting (XSS) - Generic in GitHub repository answerdev/answer prior to 1.0.4.



- [https://github.com/Live-Hack-CVE/CVE-2023-0743](https://github.com/Live-Hack-CVE/CVE-2023-0743) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0743.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0743.svg)

## CVE-2023-0742
 Cross-site Scripting (XSS) - Stored in GitHub repository answerdev/answer prior to 1.0.4.



- [https://github.com/Live-Hack-CVE/CVE-2023-0742](https://github.com/Live-Hack-CVE/CVE-2023-0742) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0742.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0742.svg)

## CVE-2023-0741
 Cross-site Scripting (XSS) - DOM in GitHub repository answerdev/answer prior to 1.0.4.



- [https://github.com/Live-Hack-CVE/CVE-2023-0741](https://github.com/Live-Hack-CVE/CVE-2023-0741) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0741.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0741.svg)

## CVE-2023-0740
 Cross-site Scripting (XSS) - Stored in GitHub repository answerdev/answer prior to 1.0.4.



- [https://github.com/Live-Hack-CVE/CVE-2023-0740](https://github.com/Live-Hack-CVE/CVE-2023-0740) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0740.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0740.svg)

## CVE-2023-0739
 Race Condition in Switch in GitHub repository answerdev/answer prior to 1.0.4.



- [https://github.com/Live-Hack-CVE/CVE-2023-0739](https://github.com/Live-Hack-CVE/CVE-2023-0739) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0739.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0739.svg)

## CVE-2023-0736
 Cross-site Scripting (XSS) - Stored in GitHub repository wallabag/wallabag prior to 2.5.4.



- [https://github.com/Live-Hack-CVE/CVE-2023-0736](https://github.com/Live-Hack-CVE/CVE-2023-0736) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0736.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0736.svg)

## CVE-2023-0735
 Cross-Site Request Forgery (CSRF) in GitHub repository wallabag/wallabag prior to 2.5.4.



- [https://github.com/Live-Hack-CVE/CVE-2023-0735](https://github.com/Live-Hack-CVE/CVE-2023-0735) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0735.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0735.svg)

## CVE-2023-0732
 A vulnerability has been found in SourceCodester Online Eyewear Shop 1.0 and classified as problematic. Affected by this vulnerability is the function registration of the file oews/classes/Users.php of the component POST Request Handler. The manipulation of the argument firstname/middlename/lastname/email/contact leads to cross site scripting. The attack can be launched remotely. The identifier VDB-220369 was assigned to this vulnerability.



- [https://github.com/Live-Hack-CVE/CVE-2023-0732](https://github.com/Live-Hack-CVE/CVE-2023-0732) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0732.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0732.svg)

## CVE-2023-0731
 The Interactive Geo Maps plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the action content parameter in versions up to, and including, 1.5.9 due to insufficient input sanitization and output escaping on user supplied attributes. This makes it possible for authenticated attackers with editor level and above permissions to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.



- [https://github.com/Live-Hack-CVE/CVE-2023-0731](https://github.com/Live-Hack-CVE/CVE-2023-0731) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0731.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0731.svg)

## CVE-2023-0730
 The Wicked Folders plugin for WordPress is vulnerable to Cross-Site Request Forgery in versions up to, and including, 2.18.16. This is due to missing or incorrect nonce validation on the ajax_save_folder_order function. This makes it possible for unauthenticated attackers to invoke this function via forged request granted they can trick a site administrator into performing an action such as clicking on a link leading them to perform actions intended for administrators such as changing the folder structure maintained by the plugin.



- [https://github.com/Live-Hack-CVE/CVE-2023-0730](https://github.com/Live-Hack-CVE/CVE-2023-0730) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0730.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0730.svg)

## CVE-2023-0728
 The Wicked Folders plugin for WordPress is vulnerable to Cross-Site Request Forgery in versions up to, and including, 2.18.16. This is due to missing or incorrect nonce validation on the ajax_save_folder function. This makes it possible for unauthenticated attackers to invoke this function via forged request granted they can trick a site administrator into performing an action such as clicking on a link leading them to perform actions intended for administrators such as changing the folder structure maintained by the plugin.



- [https://github.com/Live-Hack-CVE/CVE-2023-0728](https://github.com/Live-Hack-CVE/CVE-2023-0728) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0728.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0728.svg)

## CVE-2023-0727
 The Wicked Folders plugin for WordPress is vulnerable to Cross-Site Request Forgery in versions up to, and including, 2.18.16. This is due to missing or incorrect nonce validation on the ajax_delete_folder function. This makes it possible for unauthenticated attackers to invoke this function via forged request granted they can trick a site administrator into performing an action such as clicking on a link leading them to perform actions intended for administrators such as changing the folder structure maintained by the plugin.



- [https://github.com/Live-Hack-CVE/CVE-2023-0727](https://github.com/Live-Hack-CVE/CVE-2023-0727) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0727.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0727.svg)

## CVE-2023-0726
 The Wicked Folders plugin for WordPress is vulnerable to Cross-Site Request Forgery in versions up to, and including, 2.18.16. This is due to missing or incorrect nonce validation on the ajax_edit_folder function. This makes it possible for unauthenticated attackers to invoke this function via forged request granted they can trick a site administrator into performing an action such as clicking on a link leading them to perform actions intended for administrators such as changing the folder structure maintained by the plugin.



- [https://github.com/Live-Hack-CVE/CVE-2023-0726](https://github.com/Live-Hack-CVE/CVE-2023-0726) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0726.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0726.svg)

## CVE-2023-0725
 The Wicked Folders plugin for WordPress is vulnerable to Cross-Site Request Forgery in versions up to, and including, 2.18.16. This is due to missing or incorrect nonce validation on the ajax_clone_folder function. This makes it possible for unauthenticated attackers to invoke this function via forged request granted they can trick a site administrator into performing an action such as clicking on a link leading them to perform actions intended for administrators such as changing the folder structure maintained by the plugin.



- [https://github.com/Live-Hack-CVE/CVE-2023-0725](https://github.com/Live-Hack-CVE/CVE-2023-0725) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0725.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0725.svg)

## CVE-2023-0724
 The Wicked Folders plugin for WordPress is vulnerable to Cross-Site Request Forgery in versions up to, and including, 2.18.16. This is due to missing or incorrect nonce validation on the ajax_add_folder function. This makes it possible for unauthenticated attackers to invoke this function via forged request granted they can trick a site administrator into performing an action such as clicking on a link leading them to perform actions intended for administrators such as changing the folder structure maintained by the plugin.



- [https://github.com/Live-Hack-CVE/CVE-2023-0724](https://github.com/Live-Hack-CVE/CVE-2023-0724) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0724.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0724.svg)

## CVE-2023-0723
 The Wicked Folders plugin for WordPress is vulnerable to Cross-Site Request Forgery in versions up to, and including, 2.18.16. This is due to missing or incorrect nonce validation on the ajax_move_object function. This makes it possible for unauthenticated attackers to invoke this function via forged request granted they can trick a site administrator into performing an action such as clicking on a link leading them to perform actions intended for administrators such as changing the folder structure maintained by the plugin.



- [https://github.com/Live-Hack-CVE/CVE-2023-0723](https://github.com/Live-Hack-CVE/CVE-2023-0723) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0723.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0723.svg)

## CVE-2023-0722
 The Wicked Folders plugin for WordPress is vulnerable to Cross-Site Request Forgery in versions up to, and including, 2.18.16. This is due to missing or incorrect nonce validation on the ajax_save_state function. This makes it possible for unauthenticated attackers to invoke this function via forged request granted they can trick a site administrator into performing an action such as clicking on a link leading them to perform actions intended for administrators such as changing the folder structure maintained by the plugin.



- [https://github.com/Live-Hack-CVE/CVE-2023-0722](https://github.com/Live-Hack-CVE/CVE-2023-0722) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0722.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0722.svg)

## CVE-2023-0720
 The Wicked Folders plugin for WordPress is vulnerable to authorization bypass due to a missing capability check on the ajax_save_folder_order function in versions up to, and including, 2.18.16. This makes it possible for authenticated attackers, with subscriber-level permissions and above, to invoke this function and perform actions intended for administrators such as modifying the folder structure maintained by the plugin.



- [https://github.com/Live-Hack-CVE/CVE-2023-0720](https://github.com/Live-Hack-CVE/CVE-2023-0720) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0720.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0720.svg)

## CVE-2023-0719
 The Wicked Folders plugin for WordPress is vulnerable to authorization bypass due to a missing capability check on the ajax_save_sort_order function in versions up to, and including, 2.18.16. This makes it possible for authenticated attackers, with subscriber-level permissions and above, to invoke this function and perform actions intended for administrators such as modifying the folder structure maintained by the plugin.



- [https://github.com/Live-Hack-CVE/CVE-2023-0719](https://github.com/Live-Hack-CVE/CVE-2023-0719) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0719.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0719.svg)

## CVE-2023-0718
 The Wicked Folders plugin for WordPress is vulnerable to authorization bypass due to a missing capability check on the ajax_save_folder function in versions up to, and including, 2.18.16. This makes it possible for authenticated attackers, with subscriber-level permissions and above, to invoke this function and perform actions intended for administrators such as modifying the folder structure maintained by the plugin.



- [https://github.com/Live-Hack-CVE/CVE-2023-0718](https://github.com/Live-Hack-CVE/CVE-2023-0718) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0718.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0718.svg)

## CVE-2023-0717
 The Wicked Folders plugin for WordPress is vulnerable to authorization bypass due to a missing capability check on the ajax_delete_folder function in versions up to, and including, 2.18.16. This makes it possible for authenticated attackers, with subscriber-level permissions and above, to invoke this function and perform actions intended for administrators such as modifying the folder structure maintained by the plugin.



- [https://github.com/Live-Hack-CVE/CVE-2023-0717](https://github.com/Live-Hack-CVE/CVE-2023-0717) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0717.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0717.svg)

## CVE-2023-0716
 The Wicked Folders plugin for WordPress is vulnerable to authorization bypass due to a missing capability check on the ajax_edit_folder function in versions up to, and including, 2.18.16. This makes it possible for authenticated attackers, with subscriber-level permissions and above, to invoke this function and perform actions intended for administrators such as modifying the folder structure maintained by the plugin.



- [https://github.com/Live-Hack-CVE/CVE-2023-0716](https://github.com/Live-Hack-CVE/CVE-2023-0716) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0716.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0716.svg)

## CVE-2023-0715
 The Wicked Folders plugin for WordPress is vulnerable to authorization bypass due to a missing capability check on the ajax_clone_folder function in versions up to, and including, 2.18.16. This makes it possible for authenticated attackers, with subscriber-level permissions and above, to invoke this function and perform actions intended for administrators such as modifying the folder structure maintained by the plugin.



- [https://github.com/Live-Hack-CVE/CVE-2023-0715](https://github.com/Live-Hack-CVE/CVE-2023-0715) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0715.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0715.svg)

## CVE-2023-0713
 The Wicked Folders plugin for WordPress is vulnerable to authorization bypass due to a missing capability check on the ajax_add_folder function in versions up to, and including, 2.18.16. This makes it possible for authenticated attackers, with subscriber-level permissions and above, to invoke this function and perform actions intended for administrators such as modifying the folder structure maintained by the plugin.



- [https://github.com/Live-Hack-CVE/CVE-2023-0713](https://github.com/Live-Hack-CVE/CVE-2023-0713) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0713.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0713.svg)

## CVE-2023-0712
 The Wicked Folders plugin for WordPress is vulnerable to authorization bypass due to a missing capability check on the ajax_move_object function in versions up to, and including, 2.18.16. This makes it possible for authenticated attackers, with subscriber-level permissions and above, to invoke this function and perform actions intended for administrators such as modifying the folder structure maintained by the plugin.



- [https://github.com/Live-Hack-CVE/CVE-2023-0712](https://github.com/Live-Hack-CVE/CVE-2023-0712) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0712.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0712.svg)

## CVE-2023-0711
 The Wicked Folders plugin for WordPress is vulnerable to authorization bypass due to a missing capability check on the ajax_save_state function in versions up to, and including, 2.18.16. This makes it possible for authenticated attackers, with subscriber-level permissions and above, to invoke this function and perform actions intended for administrators such as modifying the view state of the folder structure maintained by the plugin.



- [https://github.com/Live-Hack-CVE/CVE-2023-0711](https://github.com/Live-Hack-CVE/CVE-2023-0711) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0711.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0711.svg)

## CVE-2023-0707
 A vulnerability was found in SourceCodester Medical Certificate Generator App 1.0. It has been rated as critical. Affected by this issue is the function delete_record of the file function.php. The manipulation of the argument id leads to sql injection. VDB-220346 is the identifier assigned to this vulnerability.



- [https://github.com/Live-Hack-CVE/CVE-2023-0707](https://github.com/Live-Hack-CVE/CVE-2023-0707) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0707.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0707.svg)

## CVE-2023-0706
 A vulnerability, which was classified as critical, has been found in SourceCodester Medical Certificate Generator App 1.0. Affected by this issue is some unknown functionality of the file manage_record.php. The manipulation of the argument id leads to sql injection. The attack may be launched remotely. The identifier of this vulnerability is VDB-220340.



- [https://github.com/Live-Hack-CVE/CVE-2023-0706](https://github.com/Live-Hack-CVE/CVE-2023-0706) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0706.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0706.svg)

## CVE-2023-0690
 HashiCorp Boundary from 0.10.0 through 0.11.2 contain an issue where when using a PKI-based worker with a Key Management Service (KMS) defined in the configuration file, new credentials created after an automatic rotation may not have been encrypted via the intended KMS. This would result in the credentials being stored in plaintext on the Boundary PKI worker&#8217;s disk. This issue is fixed in version 0.12.0.



- [https://github.com/Live-Hack-CVE/CVE-2023-0690](https://github.com/Live-Hack-CVE/CVE-2023-0690) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0690.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0690.svg)

## CVE-2023-0685
 The Wicked Folders plugin for WordPress is vulnerable to Cross-Site Request Forgery in versions up to, and including, 2.18.16. This is due to missing or incorrect nonce validation on the ajax_unassign_folders function. This makes it possible for unauthenticated attackers to invoke this function via forged request granted they can trick a site administrator into performing an action such as clicking on a link leading them to perform actions intended for administrators such as changing the folder structure maintained by the plugin..



- [https://github.com/Live-Hack-CVE/CVE-2023-0685](https://github.com/Live-Hack-CVE/CVE-2023-0685) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0685.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0685.svg)

## CVE-2023-0684
 The Wicked Folders plugin for WordPress is vulnerable to authorization bypass due to a missing capability check on the ajax_unassign_folders function in versions up to, and including, 2.18.16. This makes it possible for authenticated attackers, with subscriber-level permissions and above, to invoke this function and perform actions intended for administrators such as changing the folder structure maintained by the plugin.



- [https://github.com/Live-Hack-CVE/CVE-2023-0684](https://github.com/Live-Hack-CVE/CVE-2023-0684) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0684.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0684.svg)

## CVE-2023-0679
 A vulnerability was found in SourceCodester Canteen Management System 1.0. It has been rated as critical. Affected by this issue is some unknown functionality of the file removeUser.php. The manipulation of the argument id leads to sql injection. The attack may be launched remotely. The exploit has been disclosed to the public and may be used. The identifier of this vulnerability is VDB-220220.



- [https://github.com/Live-Hack-CVE/CVE-2023-0679](https://github.com/Live-Hack-CVE/CVE-2023-0679) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0679.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0679.svg)

## CVE-2023-0678
 Improper Authorization in GitHub repository phpipam/phpipam prior to v1.5.1.



- [https://github.com/Live-Hack-CVE/CVE-2023-0678](https://github.com/Live-Hack-CVE/CVE-2023-0678) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0678.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0678.svg)

## CVE-2023-0677
 Cross-site Scripting (XSS) - Reflected in GitHub repository phpipam/phpipam prior to v1.5.1.



- [https://github.com/Live-Hack-CVE/CVE-2023-0677](https://github.com/Live-Hack-CVE/CVE-2023-0677) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0677.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0677.svg)

## CVE-2023-0676
 Cross-site Scripting (XSS) - Reflected in GitHub repository phpipam/phpipam prior to 1.5.1.



- [https://github.com/Live-Hack-CVE/CVE-2023-0676](https://github.com/Live-Hack-CVE/CVE-2023-0676) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0676.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0676.svg)

## CVE-2023-0675
 A vulnerability, which was classified as critical, was found in Calendar Event Management System 2.3.0. This affects an unknown part. The manipulation of the argument start/end leads to sql injection. It is possible to initiate the attack remotely. The exploit has been disclosed to the public and may be used. The identifier VDB-220197 was assigned to this vulnerability.



- [https://github.com/Live-Hack-CVE/CVE-2023-0675](https://github.com/Live-Hack-CVE/CVE-2023-0675) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0675.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0675.svg)

## CVE-2023-0674
 A vulnerability, which was classified as problematic, has been found in XXL-JOB 2.3.1. Affected by this issue is some unknown functionality of the file /user/updatePwd of the component New Password Handler. The manipulation leads to cross-site request forgery. The attack may be launched remotely. The exploit has been disclosed to the public and may be used. The identifier of this vulnerability is VDB-220196.



- [https://github.com/Live-Hack-CVE/CVE-2023-0674](https://github.com/Live-Hack-CVE/CVE-2023-0674) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0674.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0674.svg)

## CVE-2023-0673
 A vulnerability classified as critical was found in SourceCodester Online Eyewear Shop 1.0. Affected by this vulnerability is an unknown functionality of the file oews/?p=products/view_product.php. The manipulation of the argument id leads to sql injection. The attack can be launched remotely. The associated identifier of this vulnerability is VDB-220195.



- [https://github.com/Live-Hack-CVE/CVE-2023-0673](https://github.com/Live-Hack-CVE/CVE-2023-0673) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0673.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0673.svg)

## CVE-2023-0671
 Code Injection in GitHub repository froxlor/froxlor prior to 2.0.10.



- [https://github.com/Live-Hack-CVE/CVE-2023-0671](https://github.com/Live-Hack-CVE/CVE-2023-0671) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0671.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0671.svg)

## CVE-2023-0669
 Fortra (formerly, HelpSystems) GoAnywhere MFT suffers from a pre-authentication command injection vulnerability in the License Response Servlet due to deserializing an arbitrary attacker-controlled object. This issue was patched in version 7.1.2.



- [https://github.com/Live-Hack-CVE/CVE-2023-0669](https://github.com/Live-Hack-CVE/CVE-2023-0669) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0669.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0669.svg)

## CVE-2023-0663
 A vulnerability was found in Calendar Event Management System 2.3.0. It has been rated as critical. This issue affects some unknown processing of the component Login Page. The manipulation of the argument name/pwd leads to sql injection. The attack may be initiated remotely. The exploit has been disclosed to the public and may be used. The associated identifier of this vulnerability is VDB-220175.



- [https://github.com/Live-Hack-CVE/CVE-2023-0663](https://github.com/Live-Hack-CVE/CVE-2023-0663) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0663.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0663.svg)

## CVE-2023-0658
 A vulnerability, which was classified as critical, was found in Multilaser RE057 and RE170 2.1/2.2. This affects an unknown part of the file /param.file.tgz of the component Backup File Handler. The manipulation leads to information disclosure. It is possible to initiate the attack remotely. The identifier VDB-220053 was assigned to this vulnerability.



- [https://github.com/Live-Hack-CVE/CVE-2023-0658](https://github.com/Live-Hack-CVE/CVE-2023-0658) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0658.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0658.svg)

## CVE-2023-0651
 A vulnerability was found in FastCMS 0.1.0. It has been classified as critical. Affected is an unknown function of the component Template Management. The manipulation leads to unrestricted upload. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used. VDB-220038 is the identifier assigned to this vulnerability.



- [https://github.com/Live-Hack-CVE/CVE-2023-0651](https://github.com/Live-Hack-CVE/CVE-2023-0651) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0651.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0651.svg)

## CVE-2023-0650
 A vulnerability was found in YAFNET up to 3.1.11 and classified as problematic. This issue affects some unknown processing of the component Signature Handler. The manipulation leads to cross site scripting. The attack may be initiated remotely. The exploit has been disclosed to the public and may be used. Upgrading to version 3.1.12 is able to address this issue. The name of the patch is a1442a2bacc3335461b44c250e81f8d99c60735f. It is recommended to upgrade the affected component. The identifier VDB-220037 was assigned to this vulnerability.



- [https://github.com/Live-Hack-CVE/CVE-2023-0650](https://github.com/Live-Hack-CVE/CVE-2023-0650) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0650.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0650.svg)

## CVE-2023-0643
 Improper Handling of Additional Special Element in GitHub repository squidex/squidex prior to 7.4.0.



- [https://github.com/Live-Hack-CVE/CVE-2023-0643](https://github.com/Live-Hack-CVE/CVE-2023-0643) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0643.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0643.svg)

## CVE-2023-0642
 Cross-Site Request Forgery (CSRF) in GitHub repository squidex/squidex prior to 7.4.0.



- [https://github.com/Live-Hack-CVE/CVE-2023-0642](https://github.com/Live-Hack-CVE/CVE-2023-0642) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0642.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0642.svg)

## CVE-2023-0641
 A vulnerability was found in PHPGurukul Employee Leaves Management System 1.0. It has been declared as problematic. Affected by this vulnerability is an unknown functionality of the file changepassword.php. The manipulation of the argument newpassword/confirmpassword leads to weak password requirements. The attack can be launched remotely. The exploit has been disclosed to the public and may be used. The identifier VDB-220021 was assigned to this vulnerability.



- [https://github.com/Live-Hack-CVE/CVE-2023-0641](https://github.com/Live-Hack-CVE/CVE-2023-0641) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0641.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0641.svg)

## CVE-2023-0640
 A vulnerability was found in TRENDnet TEW-652BRP 3.04b01. It has been classified as critical. Affected is an unknown function of the file ping.ccp of the component Web Interface. The manipulation leads to command injection. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used. The identifier of this vulnerability is VDB-220020.



- [https://github.com/Live-Hack-CVE/CVE-2023-0640](https://github.com/Live-Hack-CVE/CVE-2023-0640) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0640.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0640.svg)

## CVE-2023-0639
 A vulnerability was found in TRENDnet TEW-652BRP 3.04b01 and classified as problematic. This issue affects some unknown processing of the file get_set.ccp of the component Web Management Interface. The manipulation of the argument nextPage leads to cross site scripting. The attack may be initiated remotely. The associated identifier of this vulnerability is VDB-220019.



- [https://github.com/Live-Hack-CVE/CVE-2023-0639](https://github.com/Live-Hack-CVE/CVE-2023-0639) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0639.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0639.svg)

## CVE-2023-0638
 A vulnerability has been found in TRENDnet TEW-811DRU 1.0.10.0 and classified as critical. This vulnerability affects unknown code of the component Web Interface. The manipulation leads to command injection. The attack can be initiated remotely. The exploit has been disclosed to the public and may be used. VDB-220018 is the identifier assigned to this vulnerability.



- [https://github.com/Live-Hack-CVE/CVE-2023-0638](https://github.com/Live-Hack-CVE/CVE-2023-0638) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0638.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0638.svg)

## CVE-2023-0637
 A vulnerability, which was classified as critical, was found in TRENDnet TEW-811DRU 1.0.10.0. This affects an unknown part of the file wan.asp of the component Web Management Interface. The manipulation leads to memory corruption. It is possible to initiate the attack remotely. The exploit has been disclosed to the public and may be used. The identifier VDB-220017 was assigned to this vulnerability.



- [https://github.com/Live-Hack-CVE/CVE-2023-0637](https://github.com/Live-Hack-CVE/CVE-2023-0637) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0637.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0637.svg)

## CVE-2023-0634
 ** REJECT ** DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: none. Reason: This candidate was withdrawn by its CNA. Further investigation showed that it was not a security issue. Notes: none.



- [https://github.com/Live-Hack-CVE/CVE-2023-0634](https://github.com/Live-Hack-CVE/CVE-2023-0634) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0634.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0634.svg)

## CVE-2023-0624
 OrangeScrum version 2.0.11 allows an external attacker to obtain arbitrary user accounts from the application. This is possible because the application returns malicious user input in the response with the content-type set to text/html.



- [https://github.com/Live-Hack-CVE/CVE-2023-0624](https://github.com/Live-Hack-CVE/CVE-2023-0624) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0624.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0624.svg)

## CVE-2023-0619
 The Kraken.io Image Optimizer plugin for WordPress is vulnerable to authorization bypass due to a missing capability check on its AJAX actions in versions up to, and including, 2.6.8. This makes it possible for authenticated attackers, with subscriber-level permissions and above, to reset image optimizations.



- [https://github.com/Live-Hack-CVE/CVE-2023-0619](https://github.com/Live-Hack-CVE/CVE-2023-0619) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0619.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0619.svg)

## CVE-2023-0618
 A vulnerability was found in TRENDnet TEW-652BRP 3.04B01. It has been declared as critical. This vulnerability affects unknown code of the file cfg_op.ccp of the component Web Service. The manipulation leads to memory corruption. The attack can be initiated remotely. The exploit has been disclosed to the public and may be used. VDB-219958 is the identifier assigned to this vulnerability.



- [https://github.com/Live-Hack-CVE/CVE-2023-0618](https://github.com/Live-Hack-CVE/CVE-2023-0618) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0618.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0618.svg)

## CVE-2023-0617
 A vulnerability was found in TRENDNet TEW-811DRU 1.0.10.0. It has been classified as critical. This affects an unknown part of the file /wireless/guestnetwork.asp of the component httpd. The manipulation leads to buffer overflow. It is possible to initiate the attack remotely. The exploit has been disclosed to the public and may be used. The identifier VDB-219957 was assigned to this vulnerability.



- [https://github.com/Live-Hack-CVE/CVE-2023-0617](https://github.com/Live-Hack-CVE/CVE-2023-0617) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0617.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0617.svg)

## CVE-2023-0615
 A memory leak flaw and potential divide by zero and Integer overflow was found in the Linux kernel V4L2 and vivid test code functionality. This issue occurs when a user triggers ioctls, such as VIDIOC_S_DV_TIMINGS ioctl. This could allow a local user to crash the system if vivid test code enabled.



- [https://github.com/Live-Hack-CVE/CVE-2023-0615](https://github.com/Live-Hack-CVE/CVE-2023-0615) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0615.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0615.svg)

## CVE-2023-0613
 A vulnerability has been found in TRENDnet TEW-811DRU 1.0.10.0 and classified as critical. Affected by this vulnerability is an unknown functionality of the file /wireless/security.asp of the component httpd. The manipulation leads to memory corruption. The attack can be launched remotely. The exploit has been disclosed to the public and may be used. The identifier VDB-219937 was assigned to this vulnerability.



- [https://github.com/Live-Hack-CVE/CVE-2023-0613](https://github.com/Live-Hack-CVE/CVE-2023-0613) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0613.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0613.svg)

## CVE-2023-0612
 A vulnerability, which was classified as critical, was found in TRENDnet TEW-811DRU 1.0.10.0. Affected is an unknown function of the file /wireless/basic.asp of the component httpd. The manipulation leads to buffer overflow. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used. The identifier of this vulnerability is VDB-219936.



- [https://github.com/Live-Hack-CVE/CVE-2023-0612](https://github.com/Live-Hack-CVE/CVE-2023-0612) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0612.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0612.svg)

## CVE-2023-0611
 A vulnerability, which was classified as critical, has been found in TRENDnet TEW-652BRP 3.04B01. This issue affects some unknown processing of the file get_set.ccp of the component Web Management Interface. The manipulation leads to command injection. The attack may be initiated remotely. The exploit has been disclosed to the public and may be used. The associated identifier of this vulnerability is VDB-219935.



- [https://github.com/Live-Hack-CVE/CVE-2023-0611](https://github.com/Live-Hack-CVE/CVE-2023-0611) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0611.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0611.svg)

## CVE-2023-0610
 Improper Authorization in GitHub repository wallabag/wallabag prior to 2.5.3.



- [https://github.com/Live-Hack-CVE/CVE-2023-0610](https://github.com/Live-Hack-CVE/CVE-2023-0610) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0610.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0610.svg)

## CVE-2023-0609
 Improper Authorization in GitHub repository wallabag/wallabag prior to 2.5.3.



- [https://github.com/Live-Hack-CVE/CVE-2023-0609](https://github.com/Live-Hack-CVE/CVE-2023-0609) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0609.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0609.svg)

## CVE-2023-0608
 Cross-site Scripting (XSS) - DOM in GitHub repository microweber/microweber prior to 1.3.2.



- [https://github.com/Live-Hack-CVE/CVE-2023-0608](https://github.com/Live-Hack-CVE/CVE-2023-0608) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0608.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0608.svg)

## CVE-2023-0607
 Cross-site Scripting (XSS) - Stored in GitHub repository projectsend/projectsend prior to r1606.



- [https://github.com/Live-Hack-CVE/CVE-2023-0607](https://github.com/Live-Hack-CVE/CVE-2023-0607) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0607.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0607.svg)

## CVE-2023-0599
 Rapid7 Metasploit Pro versions 4.21.2 and lower suffer from a stored cross site scripting vulnerability, due to a lack of JavaScript request string sanitization. Using this vulnerability, an authenticated attacker can execute arbitrary HTML and script code in the target browser against another Metasploit Pro user using a specially crafted request. Note that in most deployments, all Metasploit Pro users tend to enjoy privileges equivalent to local administrator.



- [https://github.com/Live-Hack-CVE/CVE-2023-0599](https://github.com/Live-Hack-CVE/CVE-2023-0599) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0599.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0599.svg)

## CVE-2023-0593
 A path traversal vulnerability affects yaffshiv YAFFS filesystem extractor. By crafting a malicious YAFFS file, an attacker could force yaffshiv to write outside of the extraction directory. This issue affects yaffshiv up to version 0.1 included, which is the most recent at time of publication.



- [https://github.com/Live-Hack-CVE/CVE-2023-0593](https://github.com/Live-Hack-CVE/CVE-2023-0593) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0593.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0593.svg)

## CVE-2023-0592
 A path traversal vulnerability affects jefferson's JFFS2 filesystem extractor. By crafting malicious JFFS2 files, attackers could force jefferson to write outside of the extraction directory.This issue affects jefferson: before 0.4.1.



- [https://github.com/Live-Hack-CVE/CVE-2023-0592](https://github.com/Live-Hack-CVE/CVE-2023-0592) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0592.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0592.svg)

## CVE-2023-0591
 ubireader_extract_files is vulnerable to path traversal when run against specifically crafted UBIFS files, allowing the attacker to overwrite files outside of the extraction directory (provided the process has write access to that file or directory). This is due to the fact that a node name (dent_node.name) is considered trusted and joined to the extraction directory path during processing, then the node content is written to that joined path. By crafting a malicious UBIFS file with node names holding path traversal payloads (e.g. ../../tmp/outside.txt), it's possible to force ubi_reader to write outside of the extraction directory. This issue affects ubi-reader before 0.8.5.



- [https://github.com/Live-Hack-CVE/CVE-2023-0591](https://github.com/Live-Hack-CVE/CVE-2023-0591) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0591.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0591.svg)

## CVE-2023-0587
 A file upload vulnerability in exists in Trend Micro Apex One server build 11110. Using a malformed Content-Length header in an HTTP PUT message sent to URL /officescan/console/html/cgi/fcgiOfcDDA.exe, an unauthenticated remote attacker can upload arbitrary files to the SampleSubmission directory (i.e., \PCCSRV\TEMP\SampleSubmission) on the server. The attacker can upload a large number of large files to fill up the file system on which the Apex One server is installed.



- [https://github.com/Live-Hack-CVE/CVE-2023-0587](https://github.com/Live-Hack-CVE/CVE-2023-0587) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0587.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0587.svg)

## CVE-2023-0581
 The PrivateContent plugin for WordPress is vulnerable to protection mechanism bypass due to the use of client side validation in versions up to, and including, 8.4.3. This is due to the plugin checking if an IP had been blocklist via client-side scripts rather than server-side. This makes it possible for unauthenticated attackers to bypass any login restrictions that may prevent a brute force attack.



- [https://github.com/Live-Hack-CVE/CVE-2023-0581](https://github.com/Live-Hack-CVE/CVE-2023-0581) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0581.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0581.svg)

## CVE-2023-0572
 Unchecked Error Condition in GitHub repository froxlor/froxlor prior to 2.0.10.



- [https://github.com/Live-Hack-CVE/CVE-2023-0572](https://github.com/Live-Hack-CVE/CVE-2023-0572) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0572.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0572.svg)

## CVE-2023-0571
 A vulnerability has been found in SourceCodester Canteen Management System 1.0 and classified as problematic. This vulnerability affects unknown code of the file createcustomer.php of the component Add Customer. The manipulation of the argument name leads to cross site scripting. The attack can be initiated remotely. The exploit has been disclosed to the public and may be used. VDB-219730 is the identifier assigned to this vulnerability.



- [https://github.com/Live-Hack-CVE/CVE-2023-0571](https://github.com/Live-Hack-CVE/CVE-2023-0571) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0571.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0571.svg)

## CVE-2023-0570
 A vulnerability, which was classified as critical, was found in SourceCodester Online Tours &amp; Travels Management System 1.0. This affects an unknown part of the file user\operations\payment_operation.php. The manipulation of the argument booking_id leads to sql injection. It is possible to initiate the attack remotely. The exploit has been disclosed to the public and may be used. The identifier VDB-219729 was assigned to this vulnerability.



- [https://github.com/Live-Hack-CVE/CVE-2023-0570](https://github.com/Live-Hack-CVE/CVE-2023-0570) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0570.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0570.svg)

## CVE-2023-0569
 Weak Password Requirements in GitHub repository publify/publify prior to 9.2.10.



- [https://github.com/Live-Hack-CVE/CVE-2023-0569](https://github.com/Live-Hack-CVE/CVE-2023-0569) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0569.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0569.svg)

## CVE-2023-0566
 Static Code Injection in GitHub repository froxlor/froxlor prior to 2.0.10.



- [https://github.com/Live-Hack-CVE/CVE-2023-0566](https://github.com/Live-Hack-CVE/CVE-2023-0566) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0566.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0566.svg)

## CVE-2023-0565
 Business Logic Errors in GitHub repository froxlor/froxlor prior to 2.0.10.



- [https://github.com/Live-Hack-CVE/CVE-2023-0565](https://github.com/Live-Hack-CVE/CVE-2023-0565) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0565.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0565.svg)

## CVE-2023-0564
 Weak Password Requirements in GitHub repository froxlor/froxlor prior to 2.0.10.



- [https://github.com/Live-Hack-CVE/CVE-2023-0564](https://github.com/Live-Hack-CVE/CVE-2023-0564) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0564.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0564.svg)

## CVE-2023-0563
 A vulnerability classified as problematic has been found in PHPGurukul Bank Locker Management System 1.0. This affects an unknown part of the file add-locker-form.php of the component Assign Locker. The manipulation of the argument ahname leads to cross site scripting. It is possible to initiate the attack remotely. The exploit has been disclosed to the public and may be used. The identifier VDB-219717 was assigned to this vulnerability.



- [https://github.com/Live-Hack-CVE/CVE-2023-0563](https://github.com/Live-Hack-CVE/CVE-2023-0563) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0563.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0563.svg)

## CVE-2023-0562
 A vulnerability was found in PHPGurukul Bank Locker Management System 1.0. It has been rated as critical. Affected by this issue is some unknown functionality of the file index.php of the component Login. The manipulation of the argument username leads to sql injection. The attack may be launched remotely. The exploit has been disclosed to the public and may be used. The identifier of this vulnerability is VDB-219716.



- [https://github.com/Live-Hack-CVE/CVE-2023-0562](https://github.com/Live-Hack-CVE/CVE-2023-0562) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0562.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0562.svg)

## CVE-2023-0561
 A vulnerability, which was classified as critical, was found in SourceCodester Online Tours &amp; Travels Management System 1.0. Affected is an unknown function of the file /user/s.php. The manipulation of the argument id leads to sql injection. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used. VDB-219702 is the identifier assigned to this vulnerability.



- [https://github.com/Live-Hack-CVE/CVE-2023-0561](https://github.com/Live-Hack-CVE/CVE-2023-0561) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0561.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0561.svg)

## CVE-2023-0560
 A vulnerability, which was classified as critical, has been found in SourceCodester Online Tours &amp; Travels Management System 1.0. This issue affects some unknown processing of the file admin/practice_pdf.php. The manipulation of the argument id leads to sql injection. The attack may be initiated remotely. The exploit has been disclosed to the public and may be used. The identifier VDB-219701 was assigned to this vulnerability.



- [https://github.com/Live-Hack-CVE/CVE-2023-0560](https://github.com/Live-Hack-CVE/CVE-2023-0560) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0560.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0560.svg)

## CVE-2023-0558
 The ContentStudio plugin for WordPress is vulnerable to authorization bypass due to an unsecure token check that is susceptible to type juggling in versions up to, and including, 1.2.5. This makes it possible for unauthenticated attackers to execute functions intended for use by users with proper API keys.



- [https://github.com/Live-Hack-CVE/CVE-2023-0558](https://github.com/Live-Hack-CVE/CVE-2023-0558) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0558.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0558.svg)

## CVE-2023-0557
 The ContentStudio plugin for WordPress is vulnerable to Sensitive Information Exposure in versions up to, and including, 1.2.5. This could allow unauthenticated attackers to obtain a nonce needed for the creation of posts.



- [https://github.com/Live-Hack-CVE/CVE-2023-0557](https://github.com/Live-Hack-CVE/CVE-2023-0557) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0557.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0557.svg)

## CVE-2023-0556
 The ContentStudio plugin for WordPress is vulnerable to authorization bypass due to a missing capability check on several functions in versions up to, and including, 1.2.5. This makes it possible for unauthenticated attackers to obtain the blog metadata (via the function cstu_get_metadata) that includes the plugin's contentstudio_token. Knowing this token allows for other interactions with the plugin such as creating posts in versions prior to 1.2.5, which added other requirements to posting and updating.



- [https://github.com/Live-Hack-CVE/CVE-2023-0556](https://github.com/Live-Hack-CVE/CVE-2023-0556) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0556.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0556.svg)

## CVE-2023-0555
 The Quick Restaurant Menu plugin for WordPress is vulnerable to authorization bypass due to a missing capability check on its AJAX actions in versions up to, and including, 2.0.2. This makes it possible for authenticated attackers, with subscriber-level permissions and above, to invoke those actions intended for administrator use. Actions include menu item creation, update and deletion and other menu management functions. Since the plugin does not verify that a post ID passed to one of its AJAX actions belongs to a menu item, this can lead to arbitrary post deletion/alteration.



- [https://github.com/Live-Hack-CVE/CVE-2023-0555](https://github.com/Live-Hack-CVE/CVE-2023-0555) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0555.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0555.svg)

## CVE-2023-0554
 The Quick Restaurant Menu plugin for WordPress is vulnerable to Cross-Site Request Forgery in versions up to, and including, 2.0.2. This is due to missing or incorrect nonce validation on its AJAX actions. This makes it possible for unauthenticated attackers to update menu items, via forged request granted they can trick a site administrator into performing an action such as clicking on a link.



- [https://github.com/Live-Hack-CVE/CVE-2023-0554](https://github.com/Live-Hack-CVE/CVE-2023-0554) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0554.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0554.svg)

## CVE-2023-0553
 The Quick Restaurant Menu plugin for WordPress is vulnerable to Stored Cross-Site Scripting via its settings parameters in versions up to, and including, 2.0.2 due to insufficient input sanitization and output escaping. This makes it possible for authenticated attackers, with administrator-level permissions and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.



- [https://github.com/Live-Hack-CVE/CVE-2023-0553](https://github.com/Live-Hack-CVE/CVE-2023-0553) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0553.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0553.svg)

## CVE-2023-0550
 The Quick Restaurant Menu plugin for WordPress is vulnerable to Insecure Direct Object Reference in versions up to, and including, 2.0.2. This is due to the fact that during menu item deletion/modification, the plugin does not verify that the post ID provided to the AJAX action is indeed a menu item. This makes it possible for authenticated attackers, with subscriber-level access or higher, to modify or delete arbitrary posts.



- [https://github.com/Live-Hack-CVE/CVE-2023-0550](https://github.com/Live-Hack-CVE/CVE-2023-0550) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0550.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0550.svg)

## CVE-2023-0549
 A vulnerability, which was classified as problematic, has been found in YAFNET up to 3.1.10. This issue affects some unknown processing of the file /forum/PostPrivateMessage of the component Private Message Handler. The manipulation of the argument subject/message leads to cross site scripting. The attack may be initiated remotely. The exploit has been disclosed to the public and may be used. Upgrading to version 3.1.11 is able to address this issue. The name of the patch is 2237a9d552e258a43570bb478a92a5505e7c8797. It is recommended to upgrade the affected component. The identifier VDB-219665 was assigned to this vulnerability.



- [https://github.com/Live-Hack-CVE/CVE-2023-0549](https://github.com/Live-Hack-CVE/CVE-2023-0549) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0549.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0549.svg)

## CVE-2023-0534
 A vulnerability, which was classified as critical, was found in SourceCodester Online Tours &amp; Travels Management System 1.0. This affects an unknown part of the file admin/expense_report.php. The manipulation of the argument to_date leads to sql injection. It is possible to initiate the attack remotely. The exploit has been disclosed to the public and may be used. The associated identifier of this vulnerability is VDB-219603.



- [https://github.com/Live-Hack-CVE/CVE-2023-0534](https://github.com/Live-Hack-CVE/CVE-2023-0534) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0534.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0534.svg)

## CVE-2023-0533
 A vulnerability, which was classified as critical, has been found in SourceCodester Online Tours &amp; Travels Management System 1.0. Affected by this issue is some unknown functionality of the file admin/expense_report.php. The manipulation of the argument from_date leads to sql injection. The attack may be launched remotely. The exploit has been disclosed to the public and may be used. VDB-219602 is the identifier assigned to this vulnerability.



- [https://github.com/Live-Hack-CVE/CVE-2023-0533](https://github.com/Live-Hack-CVE/CVE-2023-0533) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0533.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0533.svg)

## CVE-2023-0532
 A vulnerability classified as critical was found in SourceCodester Online Tours &amp; Travels Management System 1.0. Affected by this vulnerability is an unknown functionality of the file admin/disapprove_user.php. The manipulation of the argument id leads to sql injection. The attack can be launched remotely. The exploit has been disclosed to the public and may be used. The identifier VDB-219601 was assigned to this vulnerability.



- [https://github.com/Live-Hack-CVE/CVE-2023-0532](https://github.com/Live-Hack-CVE/CVE-2023-0532) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0532.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0532.svg)

## CVE-2023-0531
 A vulnerability classified as critical has been found in SourceCodester Online Tours &amp; Travels Management System 1.0. Affected is an unknown function of the file admin/booking_report.php. The manipulation of the argument to_date leads to sql injection. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used. The identifier of this vulnerability is VDB-219600.



- [https://github.com/Live-Hack-CVE/CVE-2023-0531](https://github.com/Live-Hack-CVE/CVE-2023-0531) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0531.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0531.svg)

## CVE-2023-0530
 A vulnerability was found in SourceCodester Online Tours &amp; Travels Management System 1.0. It has been rated as critical. This issue affects some unknown processing of the file admin/approve_user.php. The manipulation of the argument id leads to sql injection. The attack may be initiated remotely. The exploit has been disclosed to the public and may be used. The associated identifier of this vulnerability is VDB-219599.



- [https://github.com/Live-Hack-CVE/CVE-2023-0530](https://github.com/Live-Hack-CVE/CVE-2023-0530) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0530.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0530.svg)

## CVE-2023-0529
 A vulnerability was found in SourceCodester Online Tours &amp; Travels Management System 1.0. It has been declared as critical. This vulnerability affects unknown code of the file admin/add_payment.php. The manipulation of the argument id leads to sql injection. The attack can be initiated remotely. The exploit has been disclosed to the public and may be used. VDB-219598 is the identifier assigned to this vulnerability.



- [https://github.com/Live-Hack-CVE/CVE-2023-0529](https://github.com/Live-Hack-CVE/CVE-2023-0529) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0529.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0529.svg)

## CVE-2023-0528
 A vulnerability was found in SourceCodester Online Tours &amp; Travels Management System 1.0. It has been classified as critical. This affects an unknown part of the file admin/abc.php. The manipulation of the argument id leads to sql injection. It is possible to initiate the attack remotely. The exploit has been disclosed to the public and may be used. The identifier VDB-219597 was assigned to this vulnerability.



- [https://github.com/Live-Hack-CVE/CVE-2023-0528](https://github.com/Live-Hack-CVE/CVE-2023-0528) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0528.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0528.svg)

## CVE-2023-0527
 A vulnerability was found in PHPGurukul Online Security Guards Hiring System 1.0 and classified as problematic. Affected by this issue is some unknown functionality of the file search-request.php. The manipulation of the argument searchdata with the input &quot;&gt;&lt;script&gt;alert(document.domain)&lt;/script&gt; leads to cross site scripting. The attack may be launched remotely. The exploit has been disclosed to the public and may be used. The identifier of this vulnerability is VDB-219596.



- [https://github.com/Live-Hack-CVE/CVE-2023-0527](https://github.com/Live-Hack-CVE/CVE-2023-0527) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0527.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0527.svg)

## CVE-2023-0524
 As part of our Security Development Lifecycle, a potential privilege escalation issue was identified internally. This could allow a malicious actor with sufficient permissions to modify environment variables and abuse an impacted plugin in order to escalate privileges. We have resolved the issue and also made several defense-in-depth fixes alongside. While the probability of successful exploitation is low, Tenable is committed to securing our customers&#8217; environments and our products. The updates have been distributed via the Tenable plugin feed in feed serial numbers equal to or greater than #202212212055.



- [https://github.com/Live-Hack-CVE/CVE-2023-0524](https://github.com/Live-Hack-CVE/CVE-2023-0524) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0524.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0524.svg)

## CVE-2023-0519
 Cross-site Scripting (XSS) - Stored in GitHub repository modoboa/modoboa prior to 2.0.4.



- [https://github.com/Live-Hack-CVE/CVE-2023-0519](https://github.com/Live-Hack-CVE/CVE-2023-0519) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0519.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0519.svg)

## CVE-2023-0493
 Improper Neutralization of Equivalent Special Elements in GitHub repository btcpayserver/btcpayserver prior to 1.7.5.



- [https://github.com/Live-Hack-CVE/CVE-2023-0493](https://github.com/Live-Hack-CVE/CVE-2023-0493) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0493.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0493.svg)

## CVE-2023-0474
 Use after free in GuestView in Google Chrome prior to 109.0.5414.119 allowed an attacker who convinced a user to install a malicious extension to potentially exploit heap corruption via a Chrome web app. (Chromium security severity: Medium)



- [https://github.com/Live-Hack-CVE/CVE-2023-0474](https://github.com/Live-Hack-CVE/CVE-2023-0474) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0474.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0474.svg)

## CVE-2023-0473
 Type Confusion in ServiceWorker API in Google Chrome prior to 109.0.5414.119 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: Medium)



- [https://github.com/Live-Hack-CVE/CVE-2023-0473](https://github.com/Live-Hack-CVE/CVE-2023-0473) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0473.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0473.svg)

## CVE-2023-0472
 Use after free in WebRTC in Google Chrome prior to 109.0.5414.119 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)



- [https://github.com/Live-Hack-CVE/CVE-2023-0472](https://github.com/Live-Hack-CVE/CVE-2023-0472) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0472.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0472.svg)

## CVE-2023-0471
 Use after free in WebTransport in Google Chrome prior to 109.0.5414.119 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)



- [https://github.com/Live-Hack-CVE/CVE-2023-0471](https://github.com/Live-Hack-CVE/CVE-2023-0471) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0471.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0471.svg)

## CVE-2023-0454
 OrangeScrum version 2.0.11 allows an authenticated external attacker to delete arbitrary local files from the server. This is possible because the application uses an unsanitized attacker-controlled parameter to construct an internal path.



- [https://github.com/Live-Hack-CVE/CVE-2023-0454](https://github.com/Live-Hack-CVE/CVE-2023-0454) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0454.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0454.svg)

## CVE-2023-0451
 All versions of Econolite EOS traffic control software are vulnerable to CWE-284: Improper Access Control, and lack a password requirement for gaining &#8220;READONLY&#8221; access to log files, as well as certain database and configuration files. One such file contains tables with message-digest algorithm 5 (MD5) hashes and usernames for all defined users in the control software, including administrators and technicians.



- [https://github.com/Live-Hack-CVE/CVE-2023-0451](https://github.com/Live-Hack-CVE/CVE-2023-0451) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0451.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0451.svg)

## CVE-2023-0444
 A privilege escalation vulnerability exists in Delta Electronics InfraSuite Device Master 00.00.02a. A default user 'User', which is in the 'Read Only User' group, can view the password of another default user 'Administrator', which is in the 'Administrator' group. This allows any lower privileged user to log in as an administrator.



- [https://github.com/Live-Hack-CVE/CVE-2023-0444](https://github.com/Live-Hack-CVE/CVE-2023-0444) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0444.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0444.svg)

## CVE-2023-0440
 Exposure of Sensitive Information to an Unauthorized Actor in GitHub repository healthchecks/healthchecks prior to v2.6.



- [https://github.com/Live-Hack-CVE/CVE-2023-0440](https://github.com/Live-Hack-CVE/CVE-2023-0440) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0440.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0440.svg)

## CVE-2023-0438
 Cross-Site Request Forgery (CSRF) in GitHub repository modoboa/modoboa prior to 2.0.4.



- [https://github.com/Live-Hack-CVE/CVE-2023-0438](https://github.com/Live-Hack-CVE/CVE-2023-0438) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0438.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0438.svg)

## CVE-2023-0435
 Excessive Attack Surface in GitHub repository pyload/pyload prior to 0.5.0b3.dev41.



- [https://github.com/Live-Hack-CVE/CVE-2023-0435](https://github.com/Live-Hack-CVE/CVE-2023-0435) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0435.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0435.svg)

## CVE-2023-0434
 Improper Input Validation in GitHub repository pyload/pyload prior to 0.5.0b3.dev40.



- [https://github.com/Live-Hack-CVE/CVE-2023-0434](https://github.com/Live-Hack-CVE/CVE-2023-0434) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0434.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0434.svg)

## CVE-2023-0433
 Heap-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.1225.



- [https://github.com/Live-Hack-CVE/CVE-2023-0433](https://github.com/Live-Hack-CVE/CVE-2023-0433) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0433.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0433.svg)

## CVE-2023-0417
 Memory leak in the NFS dissector in Wireshark 4.0.0 to 4.0.2 and 3.6.0 to 3.6.10 and allows denial of service via packet injection or crafted capture file



- [https://github.com/Live-Hack-CVE/CVE-2023-0417](https://github.com/Live-Hack-CVE/CVE-2023-0417) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0417.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0417.svg)

## CVE-2023-0416
 GNW dissector crash in Wireshark 4.0.0 to 4.0.2 and 3.6.0 to 3.6.10 and allows denial of service via packet injection or crafted capture file



- [https://github.com/Live-Hack-CVE/CVE-2023-0416](https://github.com/Live-Hack-CVE/CVE-2023-0416) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0416.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0416.svg)

## CVE-2023-0415
 iSCSI dissector crash in Wireshark 4.0.0 to 4.0.2 and 3.6.0 to 3.6.10 and allows denial of service via packet injection or crafted capture file



- [https://github.com/Live-Hack-CVE/CVE-2023-0415](https://github.com/Live-Hack-CVE/CVE-2023-0415) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0415.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0415.svg)

## CVE-2023-0414
 Crash in the EAP dissector in Wireshark 4.0.0 to 4.0.2 allows denial of service via packet injection or crafted capture file



- [https://github.com/Live-Hack-CVE/CVE-2023-0414](https://github.com/Live-Hack-CVE/CVE-2023-0414) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0414.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0414.svg)

## CVE-2023-0413
 Dissection engine bug in Wireshark 4.0.0 to 4.0.2 and 3.6.0 to 3.6.10 and allows denial of service via packet injection or crafted capture file



- [https://github.com/Live-Hack-CVE/CVE-2023-0413](https://github.com/Live-Hack-CVE/CVE-2023-0413) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0413.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0413.svg)

## CVE-2023-0412
 TIPC dissector crash in Wireshark 4.0.0 to 4.0.2 and 3.6.0 to 3.6.10 and allows denial of service via packet injection or crafted capture file



- [https://github.com/Live-Hack-CVE/CVE-2023-0412](https://github.com/Live-Hack-CVE/CVE-2023-0412) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0412.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0412.svg)

## CVE-2023-0411
 Excessive loops in multiple dissectors in Wireshark 4.0.0 to 4.0.2 and 3.6.0 to 3.6.10 and allows denial of service via packet injection or crafted capture file



- [https://github.com/Live-Hack-CVE/CVE-2023-0411](https://github.com/Live-Hack-CVE/CVE-2023-0411) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0411.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0411.svg)

## CVE-2023-0410
 Cross-site Scripting (XSS) - Generic in GitHub repository builderio/qwik prior to 0.1.0-beta5.



- [https://github.com/Live-Hack-CVE/CVE-2023-0410](https://github.com/Live-Hack-CVE/CVE-2023-0410) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0410.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0410.svg)

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

## CVE-2023-0400
 The protection bypass vulnerability in DLP for Windows 11.9.x is addressed in version 11.10.0. This allowed a local user to bypass DLP controls when uploading sensitive data from a mapped drive into a web email client. Loading from a local driver was correctly prevented. Versions prior to 11.9 correctly detected and blocked the attempted upload of sensitive data.



- [https://github.com/Live-Hack-CVE/CVE-2023-0400](https://github.com/Live-Hack-CVE/CVE-2023-0400) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0400.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0400.svg)

## CVE-2023-0398
 Cross-Site Request Forgery (CSRF) in GitHub repository modoboa/modoboa prior to 2.0.4.



- [https://github.com/Live-Hack-CVE/CVE-2023-0398](https://github.com/Live-Hack-CVE/CVE-2023-0398) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0398.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0398.svg)

## CVE-2023-0397
 A malicious / defect bluetooth controller can cause a Denial of Service due to unchecked input in le_read_buffer_size_complete.



- [https://github.com/Live-Hack-CVE/CVE-2023-0397](https://github.com/Live-Hack-CVE/CVE-2023-0397) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0397.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0397.svg)

## CVE-2023-0396
 A malicious / defective bluetooth controller can cause buffer overreads in the most functions that process HCI command responses.



- [https://github.com/Live-Hack-CVE/CVE-2023-0396](https://github.com/Live-Hack-CVE/CVE-2023-0396) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0396.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0396.svg)

## CVE-2023-0385
 The Custom 404 Pro plugin for WordPress is vulnerable to Cross-Site Request Forgery in versions up to, and including, 3.7.1. This is due to missing or incorrect nonce validation on the custom_404_pro_admin_init function. This makes it possible for unauthenticated attackers to delete logs, via forged request granted they can trick a site administrator into performing an action such as clicking on a link.



- [https://github.com/Live-Hack-CVE/CVE-2023-0385](https://github.com/Live-Hack-CVE/CVE-2023-0385) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0385.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0385.svg)

## CVE-2023-0358
 Use After Free in GitHub repository gpac/gpac prior to 2.3.0-DEV.



- [https://github.com/Live-Hack-CVE/CVE-2023-0358](https://github.com/Live-Hack-CVE/CVE-2023-0358) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0358.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0358.svg)

## CVE-2023-0356
 SOCOMEC MODULYS GP Netvision versions 7.20 and prior lack strong encryption for credentials on HTTP connections, which could result in threat actors obtaining sensitive information.



- [https://github.com/Live-Hack-CVE/CVE-2023-0356](https://github.com/Live-Hack-CVE/CVE-2023-0356) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0356.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0356.svg)

## CVE-2023-0341
 A stack buffer overflow exists in the ec_glob function of editorconfig-core-c before v0.12.6 which allowed an attacker to arbitrarily write to the stack and possibly allows remote code execution. editorconfig-core-c v0.12.6 resolved this vulnerability by bound checking all write operations over the p_pcre buffer.



- [https://github.com/Live-Hack-CVE/CVE-2023-0341](https://github.com/Live-Hack-CVE/CVE-2023-0341) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0341.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0341.svg)

## CVE-2023-0338
 Cross-site Scripting (XSS) - Reflected in GitHub repository lirantal/daloradius prior to master-branch.



- [https://github.com/Live-Hack-CVE/CVE-2023-0338](https://github.com/Live-Hack-CVE/CVE-2023-0338) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0338.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0338.svg)

## CVE-2023-0337
 Cross-site Scripting (XSS) - Reflected in GitHub repository lirantal/daloradius prior to master-branch.



- [https://github.com/Live-Hack-CVE/CVE-2023-0337](https://github.com/Live-Hack-CVE/CVE-2023-0337) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0337.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0337.svg)

## CVE-2023-0332
 A vulnerability was found in SourceCodester Online Food Ordering System 2.0. It has been classified as critical. Affected is an unknown function of the file admin/manage_user.php. The manipulation of the argument id leads to sql injection. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used. The identifier of this vulnerability is VDB-218472.



- [https://github.com/Live-Hack-CVE/CVE-2023-0332](https://github.com/Live-Hack-CVE/CVE-2023-0332) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0332.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0332.svg)

## CVE-2023-0327
 A vulnerability was found in saemorris TheRadSystem. It has been classified as problematic. Affected is an unknown function of the file users.php. The manipulation of the argument q leads to cross site scripting. It is possible to launch the attack remotely. VDB-218454 is the identifier assigned to this vulnerability.



- [https://github.com/Live-Hack-CVE/CVE-2023-0327](https://github.com/Live-Hack-CVE/CVE-2023-0327) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0327.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0327.svg)

## CVE-2023-0323
 Cross-site Scripting (XSS) - Stored in GitHub repository pimcore/pimcore prior to 10.5.14.



- [https://github.com/Live-Hack-CVE/CVE-2023-0323](https://github.com/Live-Hack-CVE/CVE-2023-0323) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0323.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0323.svg)

## CVE-2023-0321
 Campbell Scientific dataloggers CR6, CR300, CR800, CR1000 and CR3000 may allow an attacker to download configuration files, which may contain sensitive information about the internal network. From factory defaults, the mentioned datalogges have HTTP and PakBus enabled. The devices, with the default configuration, allow this situation via the PakBus port. The exploitation of this vulnerability may allow an attacker to download, modify, and upload new configuration files.



- [https://github.com/Live-Hack-CVE/CVE-2023-0321](https://github.com/Live-Hack-CVE/CVE-2023-0321) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0321.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0321.svg)

## CVE-2023-0316
 Path Traversal: '\..\filename' in GitHub repository froxlor/froxlor prior to 2.0.0.



- [https://github.com/Live-Hack-CVE/CVE-2023-0316](https://github.com/Live-Hack-CVE/CVE-2023-0316) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0316.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0316.svg)

## CVE-2023-0315
 Command Injection in GitHub repository froxlor/froxlor prior to 2.0.8.



- [https://github.com/mhaskar/CVE-2023-0315](https://github.com/mhaskar/CVE-2023-0315) :  ![starts](https://img.shields.io/github/stars/mhaskar/CVE-2023-0315.svg) ![forks](https://img.shields.io/github/forks/mhaskar/CVE-2023-0315.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-0315](https://github.com/Live-Hack-CVE/CVE-2023-0315) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0315.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0315.svg)

## CVE-2023-0314
 Cross-site Scripting (XSS) - Reflected in GitHub repository thorsten/phpmyfaq prior to 3.1.10.



- [https://github.com/Live-Hack-CVE/CVE-2023-0314](https://github.com/Live-Hack-CVE/CVE-2023-0314) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0314.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0314.svg)

## CVE-2023-0313
 Cross-site Scripting (XSS) - Stored in GitHub repository thorsten/phpmyfaq prior to 3.1.10.



- [https://github.com/Live-Hack-CVE/CVE-2023-0313](https://github.com/Live-Hack-CVE/CVE-2023-0313) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0313.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0313.svg)

## CVE-2023-0312
 Cross-site Scripting (XSS) - Stored in GitHub repository thorsten/phpmyfaq prior to 3.1.10.



- [https://github.com/Live-Hack-CVE/CVE-2023-0312](https://github.com/Live-Hack-CVE/CVE-2023-0312) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0312.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0312.svg)

## CVE-2023-0311
 Improper Authentication in GitHub repository thorsten/phpmyfaq prior to 3.1.10.



- [https://github.com/Live-Hack-CVE/CVE-2023-0311](https://github.com/Live-Hack-CVE/CVE-2023-0311) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0311.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0311.svg)

## CVE-2023-0310
 Cross-site Scripting (XSS) - Stored in GitHub repository thorsten/phpmyfaq prior to 3.1.10.



- [https://github.com/Live-Hack-CVE/CVE-2023-0310](https://github.com/Live-Hack-CVE/CVE-2023-0310) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0310.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0310.svg)

## CVE-2023-0309
 Cross-site Scripting (XSS) - Stored in GitHub repository thorsten/phpmyfaq prior to 3.1.10.



- [https://github.com/Live-Hack-CVE/CVE-2023-0309](https://github.com/Live-Hack-CVE/CVE-2023-0309) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0309.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0309.svg)

## CVE-2023-0308
 Cross-site Scripting (XSS) - Stored in GitHub repository thorsten/phpmyfaq prior to 3.1.10.



- [https://github.com/Live-Hack-CVE/CVE-2023-0308](https://github.com/Live-Hack-CVE/CVE-2023-0308) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0308.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0308.svg)

## CVE-2023-0307
 Weak Password Requirements in GitHub repository thorsten/phpmyfaq prior to 3.1.10.



- [https://github.com/Live-Hack-CVE/CVE-2023-0307](https://github.com/Live-Hack-CVE/CVE-2023-0307) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0307.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0307.svg)

## CVE-2023-0306
 Cross-site Scripting (XSS) - Stored in GitHub repository thorsten/phpmyfaq prior to 3.1.10.



- [https://github.com/Live-Hack-CVE/CVE-2023-0306](https://github.com/Live-Hack-CVE/CVE-2023-0306) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0306.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0306.svg)

## CVE-2023-0305
 A vulnerability classified as critical was found in SourceCodester Online Food Ordering System. This vulnerability affects unknown code of the file admin_class.php of the component Login Module. The manipulation of the argument username leads to sql injection. The attack can be initiated remotely. The exploit has been disclosed to the public and may be used. VDB-218386 is the identifier assigned to this vulnerability.



- [https://github.com/Live-Hack-CVE/CVE-2023-0305](https://github.com/Live-Hack-CVE/CVE-2023-0305) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0305.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0305.svg)

## CVE-2023-0304
 A vulnerability classified as critical has been found in SourceCodester Online Food Ordering System. This affects an unknown part of the file admin_class.php of the component Signup Module. The manipulation of the argument email leads to sql injection. It is possible to initiate the attack remotely. The exploit has been disclosed to the public and may be used. The identifier VDB-218385 was assigned to this vulnerability.



- [https://github.com/Live-Hack-CVE/CVE-2023-0304](https://github.com/Live-Hack-CVE/CVE-2023-0304) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0304.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0304.svg)

## CVE-2023-0303
 A vulnerability was found in SourceCodester Online Food Ordering System. It has been rated as critical. Affected by this issue is some unknown functionality of the file view_prod.php. The manipulation of the argument id leads to sql injection. The attack may be launched remotely. The exploit has been disclosed to the public and may be used. The identifier of this vulnerability is VDB-218384.



- [https://github.com/Live-Hack-CVE/CVE-2023-0303](https://github.com/Live-Hack-CVE/CVE-2023-0303) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0303.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0303.svg)

## CVE-2023-0302
 Failure to Sanitize Special Elements into a Different Plane (Special Element Injection) in GitHub repository radareorg/radare2 prior to 5.8.2.



- [https://github.com/Live-Hack-CVE/CVE-2023-0302](https://github.com/Live-Hack-CVE/CVE-2023-0302) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0302.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0302.svg)

## CVE-2023-0301
 Cross-site Scripting (XSS) - Stored in GitHub repository alfio-event/alf.io prior to Alf.io 2.0-M4-2301.



- [https://github.com/Live-Hack-CVE/CVE-2023-0301](https://github.com/Live-Hack-CVE/CVE-2023-0301) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0301.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0301.svg)

## CVE-2023-0300
 Cross-site Scripting (XSS) - Reflected in GitHub repository alfio-event/alf.io prior to 2.0-M4-2301.



- [https://github.com/Live-Hack-CVE/CVE-2023-0300](https://github.com/Live-Hack-CVE/CVE-2023-0300) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0300.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0300.svg)

## CVE-2023-0299
 Improper Input Validation in GitHub repository publify/publify prior to 9.2.10.



- [https://github.com/Live-Hack-CVE/CVE-2023-0299](https://github.com/Live-Hack-CVE/CVE-2023-0299) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0299.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0299.svg)

## CVE-2023-0298
 Improper Authorization in GitHub repository firefly-iii/firefly-iii prior to 5.8.0.



- [https://github.com/Live-Hack-CVE/CVE-2023-0298](https://github.com/Live-Hack-CVE/CVE-2023-0298) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0298.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0298.svg)

## CVE-2023-0297
 Code Injection in GitHub repository pyload/pyload prior to 0.5.0b3.dev31.



- [https://github.com/bAuh0lz/CVE-2023-0297_Pre-auth_RCE_in_pyLoad](https://github.com/bAuh0lz/CVE-2023-0297_Pre-auth_RCE_in_pyLoad) :  ![starts](https://img.shields.io/github/stars/bAuh0lz/CVE-2023-0297_Pre-auth_RCE_in_pyLoad.svg) ![forks](https://img.shields.io/github/forks/bAuh0lz/CVE-2023-0297_Pre-auth_RCE_in_pyLoad.svg)

- [https://github.com/Live-Hack-CVE/CVE-2023-0297](https://github.com/Live-Hack-CVE/CVE-2023-0297) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0297.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0297.svg)

## CVE-2023-0296
 The Birthday attack against 64-bit block ciphers (CVE-2016-2183) was reported for the health checks port (9979) on the etcd grpc-proxy component. Even though the CVE-2016-2183 has been fixed in the etcd components, to enable periodic health checks from kubelet, it was necessary to open up a new port (9979) on etcd grpc-proxy. Therefore, this port might still be considered vulnerable to the same type of attack. The health checks on etcd grpc-proxy do not contain sensitive data, only metrics data. The potential impact related to this vulnerability is minimal. The CVE-2023-0296 has been assigned to this issue to track the permanent fix in the etcd component.



- [https://github.com/Live-Hack-CVE/CVE-2023-0296](https://github.com/Live-Hack-CVE/CVE-2023-0296) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0296.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0296.svg)

## CVE-2023-0295
 The Launchpad plugin for WordPress is vulnerable to Stored Cross-Site Scripting via several of its settings parameters in versions up to, and including, 1.0.13 due to insufficient input sanitization and output escaping. This makes it possible for authenticated attackers, with administrator-level permissions and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page. This only affects multi-site installations and installations where unfiltered_html has been disabled.



- [https://github.com/Live-Hack-CVE/CVE-2023-0295](https://github.com/Live-Hack-CVE/CVE-2023-0295) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0295.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0295.svg)

## CVE-2023-0294
 The Mediamatic &#8211; Media Library Folders plugin for WordPress is vulnerable to Cross-Site Request Forgery in versions up to, and including, 2.8.1. This is due to missing or incorrect nonce validation on its AJAX actions function. This makes it possible for unauthenticated attackers to change image categories used by the plugin, via forged request granted they can trick a site administrator into performing an action such as clicking on a link.



- [https://github.com/Live-Hack-CVE/CVE-2023-0294](https://github.com/Live-Hack-CVE/CVE-2023-0294) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0294.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0294.svg)

## CVE-2023-0293
 The Mediamatic &#8211; Media Library Folders plugin for WordPress is vulnerable to authorization bypass due to a missing capability check on its AJAX actions in versions up to, and including, 2.8.1. This makes it possible for authenticated attackers, with subscriber-level permissions and above, to change image categories, which it uses to arrange them in folder views.



- [https://github.com/Live-Hack-CVE/CVE-2023-0293](https://github.com/Live-Hack-CVE/CVE-2023-0293) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0293.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0293.svg)

## CVE-2023-0290
 Rapid7 Velociraptor did not properly sanitize the client ID parameter to the CreateCollection API, allowing a directory traversal in where the collection task could be written. It was possible to provide a client id of &quot;../clients/server&quot; to schedule the collection for the server (as a server artifact), but only require privileges to schedule collections on the client. Normally, to schedule an artifact on the server, the COLLECT_SERVER permission is required. This permission is normally only granted to &quot;administrator&quot; role. Due to this issue, it is sufficient to have the COLLECT_CLIENT privilege, which is normally granted to the &quot;investigator&quot; role. To exploit this vulnerability, the attacker must already have a Velociraptor user account at least &quot;investigator&quot; level, and be able to authenticate to the GUI and issue an API call to the backend. Typically, most users deploy Velociraptor with limited access to a trusted group, and most users will already be administrators within the GUI. This issue affects Velociraptor versions before 0.6.7-5. Version 0.6.7-5, released January 16, 2023, fixes the issue.



- [https://github.com/Live-Hack-CVE/CVE-2023-0290](https://github.com/Live-Hack-CVE/CVE-2023-0290) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0290.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0290.svg)

## CVE-2023-0289
 Cross-site Scripting (XSS) - Stored in GitHub repository craigk5n/webcalendar prior to master.



- [https://github.com/Live-Hack-CVE/CVE-2023-0289](https://github.com/Live-Hack-CVE/CVE-2023-0289) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0289.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0289.svg)

## CVE-2023-0288
 Heap-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.1189.



- [https://github.com/Live-Hack-CVE/CVE-2023-0288](https://github.com/Live-Hack-CVE/CVE-2023-0288) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0288.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0288.svg)

## CVE-2023-0287
 A vulnerability was found in ityouknow favorites-web. It has been rated as problematic. Affected by this issue is some unknown functionality of the component Comment Handler. The manipulation leads to cross site scripting. The attack may be launched remotely. The exploit has been disclosed to the public and may be used. VDB-218294 is the identifier assigned to this vulnerability.



- [https://github.com/Live-Hack-CVE/CVE-2023-0287](https://github.com/Live-Hack-CVE/CVE-2023-0287) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0287.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0287.svg)

## CVE-2023-0284
 Improper Input Validation of LDAP user IDs in Tribe29 Checkmk allows attackers that can control LDAP user IDs to manipulate files on the server. Checkmk &lt;= 2.1.0p19, Checkmk &lt;= 2.0.0p32, and all versions of Checkmk 1.6.0 (EOL) are affected.



- [https://github.com/Live-Hack-CVE/CVE-2023-0284](https://github.com/Live-Hack-CVE/CVE-2023-0284) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0284.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0284.svg)

## CVE-2023-0283
 A vulnerability classified as critical has been found in SourceCodester Online Flight Booking Management System. This affects an unknown part of the file review_search.php of the component POST Parameter Handler. The manipulation of the argument txtsearch leads to sql injection. It is possible to initiate the attack remotely. The exploit has been disclosed to the public and may be used. The identifier VDB-218277 was assigned to this vulnerability.



- [https://github.com/Live-Hack-CVE/CVE-2023-0283](https://github.com/Live-Hack-CVE/CVE-2023-0283) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0283.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0283.svg)

## CVE-2023-0281
 A vulnerability was found in SourceCodester Online Flight Booking Management System. It has been rated as critical. Affected by this issue is some unknown functionality of the file judge_panel.php. The manipulation of the argument subevent_id leads to sql injection. The attack may be launched remotely. The exploit has been disclosed to the public and may be used. The identifier of this vulnerability is VDB-218276.



- [https://github.com/Live-Hack-CVE/CVE-2023-0281](https://github.com/Live-Hack-CVE/CVE-2023-0281) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0281.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0281.svg)

## CVE-2023-0266
 A use after free vulnerability exists in the ALSA PCM package in the Linux Kernel. SNDRV_CTL_IOCTL_ELEM_{READ|WRITE}32 is missing locks that can be used in a use-after-free that can result in a priviledge escalation to gain ring0 access from the system user. We recommend upgrading past commit 56b88b50565cd8b946a2d00b0c83927b7ebb055e



- [https://github.com/Live-Hack-CVE/CVE-2023-0266](https://github.com/Live-Hack-CVE/CVE-2023-0266) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0266.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0266.svg)

## CVE-2023-0258
 A vulnerability was found in SourceCodester Online Food Ordering System 2.0. It has been rated as problematic. Affected by this issue is some unknown functionality of the component Category List Handler. The manipulation of the argument Reason with the input &quot;&gt;&lt;script&gt;prompt(1)&lt;/script&gt; leads to cross site scripting. The attack may be launched remotely. VDB-218186 is the identifier assigned to this vulnerability.



- [https://github.com/Live-Hack-CVE/CVE-2023-0258](https://github.com/Live-Hack-CVE/CVE-2023-0258) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0258.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0258.svg)

## CVE-2023-0257
 A vulnerability was found in SourceCodester Online Food Ordering System 2.0. It has been declared as critical. Affected by this vulnerability is an unknown functionality of the file /fos/admin/index.php?page=menu of the component Menu Form. The manipulation of the argument Image with the input &lt;?php system($_GET['c']); ?&gt; leads to unrestricted upload. The attack can be launched remotely. The identifier VDB-218185 was assigned to this vulnerability.



- [https://github.com/Live-Hack-CVE/CVE-2023-0257](https://github.com/Live-Hack-CVE/CVE-2023-0257) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0257.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0257.svg)

## CVE-2023-0256
 A vulnerability was found in SourceCodester Online Food Ordering System 2.0. It has been classified as critical. Affected is an unknown function of the file /fos/admin/ajax.php?action=login of the component Login Page. The manipulation of the argument Username leads to sql injection. It is possible to launch the attack remotely. The identifier of this vulnerability is VDB-218184.



- [https://github.com/Live-Hack-CVE/CVE-2023-0256](https://github.com/Live-Hack-CVE/CVE-2023-0256) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0256.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0256.svg)

## CVE-2023-0254
 The Simple Membership WP user Import plugin for WordPress is vulnerable to SQL Injection via the &#8216;orderby&#8217; parameter in versions up to, and including, 1.7 due to insufficient escaping on the user supplied parameter. This makes it possible for authenticated attackers with administrative privileges to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database.



- [https://github.com/Live-Hack-CVE/CVE-2023-0254](https://github.com/Live-Hack-CVE/CVE-2023-0254) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0254.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0254.svg)

## CVE-2023-0252
 The Contextual Related Posts WordPress plugin before 3.3.1 does not validate and escape some of its block options before outputting them back in a page/post where the block is embed, which could allow users with the contributor role and above to perform Stored Cross-Site Scripting attacks



- [https://github.com/Live-Hack-CVE/CVE-2023-0252](https://github.com/Live-Hack-CVE/CVE-2023-0252) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0252.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0252.svg)

## CVE-2023-0251
 Delta Electronics DIAScreen versions 1.2.1.23 and prior are vulnerable to a buffer overflow through improper restrictions of operations within memory, which could allow an attacker to remotely execute arbitrary code.



- [https://github.com/Live-Hack-CVE/CVE-2023-0251](https://github.com/Live-Hack-CVE/CVE-2023-0251) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0251.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0251.svg)

## CVE-2023-0250
 Delta Electronics DIAScreen versions 1.2.1.23 and prior are vulnerable to a stack-based buffer overflow, which could allow an attacker to remotely execute arbitrary code.



- [https://github.com/Live-Hack-CVE/CVE-2023-0250](https://github.com/Live-Hack-CVE/CVE-2023-0250) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0250.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0250.svg)

## CVE-2023-0249
 Delta Electronics DIAScreen versions 1.2.1.23 and prior are vulnerable to out-of-bounds write, which may allow an attacker to remotely execute arbitrary code.



- [https://github.com/Live-Hack-CVE/CVE-2023-0249](https://github.com/Live-Hack-CVE/CVE-2023-0249) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0249.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0249.svg)

## CVE-2023-0247
 Uncontrolled Search Path Element in GitHub repository bits-and-blooms/bloom prior to 3.3.1.



- [https://github.com/Live-Hack-CVE/CVE-2023-0247](https://github.com/Live-Hack-CVE/CVE-2023-0247) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0247.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0247.svg)

## CVE-2023-0246
 A vulnerability, which was classified as problematic, was found in earclink ESPCMS P8.21120101. Affected is an unknown function of the component Content Handler. The manipulation leads to cross site scripting. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used. VDB-218154 is the identifier assigned to this vulnerability.



- [https://github.com/Live-Hack-CVE/CVE-2023-0246](https://github.com/Live-Hack-CVE/CVE-2023-0246) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0246.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0246.svg)

## CVE-2023-0245
 A vulnerability, which was classified as critical, has been found in SourceCodester Online Flight Booking Management System. This issue affects some unknown processing of the file add_contestant.php. The manipulation of the argument add_contestant leads to sql injection. The attack may be initiated remotely. The exploit has been disclosed to the public and may be used. The identifier VDB-218153 was assigned to this vulnerability.



- [https://github.com/Live-Hack-CVE/CVE-2023-0245](https://github.com/Live-Hack-CVE/CVE-2023-0245) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0245.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0245.svg)

## CVE-2023-0244
 A vulnerability classified as critical was found in TuziCMS 2.0.6. This vulnerability affects the function delall of the file \App\Manage\Controller\KefuController.class.php. The manipulation of the argument id leads to sql injection. The attack can be initiated remotely. The exploit has been disclosed to the public and may be used. The identifier of this vulnerability is VDB-218152.



- [https://github.com/Live-Hack-CVE/CVE-2023-0244](https://github.com/Live-Hack-CVE/CVE-2023-0244) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0244.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0244.svg)

## CVE-2023-0242
 Rapid7 Velociraptor allows users to be created with different privileges on the server. Administrators are generally allowed to run any command on the server including writing arbitrary files. However, lower privilege users are generally forbidden from writing or modifying files on the server. The VQL copy() function applies permission checks for reading files but does not check for permission to write files. This allows a low privilege user (usually, users with the Velociraptor &quot;investigator&quot; role) to overwrite files on the server, including Velociraptor configuration files. To exploit this vulnerability, the attacker must already have a Velociraptor user account at a low privilege level (at least &quot;analyst&quot;) and be able to log into the GUI and create a notebook where they can run the VQL query invoking the copy() VQL function. Typically, most users deploy Velociraptor with limited access to a trusted group (most users will be administrators within the GUI). This vulnerability is associated with program files https://github.Com/Velocidex/velociraptor/blob/master/vql/filesystem/copy.go https://github.Com/Velocidex/velociraptor/blob/master/vql/filesystem/copy.go and program routines copy(). This issue affects Velociraptor versions before 0.6.7-5. Version 0.6.7-5, released January 16, 2023, fixes the issue.



- [https://github.com/Live-Hack-CVE/CVE-2023-0242](https://github.com/Live-Hack-CVE/CVE-2023-0242) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0242.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0242.svg)

## CVE-2023-0240
 There is a logic error in io_uring's implementation which can be used to trigger a use-after-free vulnerability leading to privilege escalation. In the io_prep_async_work function the assumption that the last io_grab_identity call cannot return false is not true, and in this case the function will use the init_cred or the previous linked requests identity to do operations instead of using the current identity. This can lead to reference counting issues causing use-after-free. We recommend upgrading past version 5.10.161.



- [https://github.com/Live-Hack-CVE/CVE-2023-0240](https://github.com/Live-Hack-CVE/CVE-2023-0240) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0240.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0240.svg)

## CVE-2023-0237
 ** REJECT ** DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: none. Reason: This candidate is unused by its CNA. Notes: none.



- [https://github.com/Live-Hack-CVE/CVE-2023-0237](https://github.com/Live-Hack-CVE/CVE-2023-0237) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0237.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0237.svg)

## CVE-2023-0235
 ** REJECT ** DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: none. Reason: This candidate is unused by its CNA. Notes: none.



- [https://github.com/Live-Hack-CVE/CVE-2023-0235](https://github.com/Live-Hack-CVE/CVE-2023-0235) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0235.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0235.svg)

## CVE-2023-0234
 The SiteGround Security WordPress plugin before 1.3.1 does not properly sanitize user input before using it in an SQL query, leading to an authenticated SQL injection issue.



- [https://github.com/Live-Hack-CVE/CVE-2023-0234](https://github.com/Live-Hack-CVE/CVE-2023-0234) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0234.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0234.svg)

## CVE-2023-0229
 A flaw was found in github.com/openshift/apiserver-library-go, used in OpenShift 4.12 and 4.11, that contains an issue that can allow low-privileged users to set the seccomp profile for pods they control to &quot;unconfined.&quot; By default, the seccomp profile used in the restricted-v2 Security Context Constraint (SCC) is &quot;runtime/default,&quot; allowing users to disable seccomp for pods they can create and modify.



- [https://github.com/Live-Hack-CVE/CVE-2023-0229](https://github.com/Live-Hack-CVE/CVE-2023-0229) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0229.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0229.svg)

## CVE-2023-0227
 Insufficient Session Expiration in GitHub repository pyload/pyload prior to 0.5.0b3.dev36.



- [https://github.com/Live-Hack-CVE/CVE-2023-0227](https://github.com/Live-Hack-CVE/CVE-2023-0227) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0227.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0227.svg)

## CVE-2023-0221
 Product security bypass vulnerability in ACC prior to version 8.3.4 allows a locally logged-in attacker with administrator privileges to bypass the execution controls provided by ACC using the utilman program.



- [https://github.com/Live-Hack-CVE/CVE-2023-0221](https://github.com/Live-Hack-CVE/CVE-2023-0221) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0221.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0221.svg)

## CVE-2023-0214
 A cross-site scripting vulnerability in Skyhigh SWG in main releases 11.x prior to 11.2.6, 10.x prior to 10.2.17, and controlled release 12.x prior to 12.0.1 allows a remote attacker to craft SWG-specific internal requests with URL paths to any third-party website, causing arbitrary content to be injected into the response when accessed through SWG.



- [https://github.com/Live-Hack-CVE/CVE-2023-0214](https://github.com/Live-Hack-CVE/CVE-2023-0214) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0214.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0214.svg)

## CVE-2023-0179
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.



- [https://github.com/TurtleARM/CVE-2023-0179-PoC](https://github.com/TurtleARM/CVE-2023-0179-PoC) :  ![starts](https://img.shields.io/github/stars/TurtleARM/CVE-2023-0179-PoC.svg) ![forks](https://img.shields.io/github/forks/TurtleARM/CVE-2023-0179-PoC.svg)

## CVE-2023-0170
 The Html5 Audio Player WordPress plugin before 2.1.12 does not validate and escape some of its shortcode attributes before outputting them back in a page/post where the shortcode is embed, which could allow users with the contributor role and above to perform Stored Cross-Site Scripting attacks.



- [https://github.com/Live-Hack-CVE/CVE-2023-0170](https://github.com/Live-Hack-CVE/CVE-2023-0170) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0170.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0170.svg)

## CVE-2023-0164
 OrangeScrum version 2.0.11 allows an authenticated external attacker to execute arbitrary commands on the server. This is possible because the application injects an attacker-controlled parameter into a system function.



- [https://github.com/Live-Hack-CVE/CVE-2023-0164](https://github.com/Live-Hack-CVE/CVE-2023-0164) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0164.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0164.svg)

## CVE-2023-0162
 The CPO Companion plugin for WordPress is vulnerable to Stored Cross-Site Scripting via several of its content type settings parameters in versions up to, and including, 1.0.4 due to insufficient input sanitization and output escaping. This makes it possible for authenticated attackers, with administrator-level permissions and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.



- [https://github.com/Live-Hack-CVE/CVE-2023-0162](https://github.com/Live-Hack-CVE/CVE-2023-0162) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0162.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0162.svg)

## CVE-2023-0161
 ** REJECT ** DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: none. Reason: This candidate is unused by its CNA. Notes: none.



- [https://github.com/Live-Hack-CVE/CVE-2023-0161](https://github.com/Live-Hack-CVE/CVE-2023-0161) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0161.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0161.svg)

## CVE-2023-0158
 NLnet Labs Krill supports direct access to the RRDP repository content through its built-in web server at the &quot;/rrdp&quot; endpoint. Prior to 0.12.1 a direct query for any existing directory under &quot;/rrdp/&quot;, rather than an RRDP file such as &quot;/rrdp/notification.xml&quot; as would be expected, causes Krill to crash. If the built-in &quot;/rrdp&quot; endpoint is exposed directly to the internet, then malicious remote parties can cause the publication server to crash. The repository content is not affected by this, but the availability of the server and repository can cause issues if this attack is persistent and is not mitigated.



- [https://github.com/Live-Hack-CVE/CVE-2023-0158](https://github.com/Live-Hack-CVE/CVE-2023-0158) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0158.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0158.svg)

## CVE-2023-0149
 The WordPrezi WordPress plugin through 0.8.2 does not validate and escape some of its shortcode attributes before outputting them back in a page/post where the shortcode is embed, which could allow users with the contributor role and above to perform Stored Cross-Site Scripting attacks



- [https://github.com/Live-Hack-CVE/CVE-2023-0149](https://github.com/Live-Hack-CVE/CVE-2023-0149) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0149.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0149.svg)

## CVE-2023-0148
 The Gallery Factory Lite WordPress plugin through 2.0.0 does not validate and escape some of its shortcode attributes before outputting them back in a page/post where the shortcode is embed, which could allow users with the contributor role and above to perform Stored Cross-Site Scripting attacks.



- [https://github.com/Live-Hack-CVE/CVE-2023-0148](https://github.com/Live-Hack-CVE/CVE-2023-0148) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0148.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0148.svg)

## CVE-2023-0141
 Insufficient policy enforcement in CORS in Google Chrome prior to 109.0.5414.74 allowed a remote attacker to leak cross-origin data via a crafted HTML page. (Chromium security severity: Low)



- [https://github.com/Live-Hack-CVE/CVE-2023-0141](https://github.com/Live-Hack-CVE/CVE-2023-0141) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0141.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0141.svg)

## CVE-2023-0140
 Inappropriate implementation in in File System API in Google Chrome on Windows prior to 109.0.5414.74 allowed a remote attacker to bypass file system restrictions via a crafted HTML page. (Chromium security severity: Low)



- [https://github.com/Live-Hack-CVE/CVE-2023-0140](https://github.com/Live-Hack-CVE/CVE-2023-0140) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0140.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0140.svg)

## CVE-2023-0139
 Insufficient validation of untrusted input in Downloads in Google Chrome on Windows prior to 109.0.5414.74 allowed a remote attacker to bypass download restrictions via a crafted HTML page. (Chromium security severity: Low)



- [https://github.com/Live-Hack-CVE/CVE-2023-0139](https://github.com/Live-Hack-CVE/CVE-2023-0139) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0139.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0139.svg)

## CVE-2023-0138
 Heap buffer overflow in libphonenumber in Google Chrome prior to 109.0.5414.74 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: Low)



- [https://github.com/Live-Hack-CVE/CVE-2023-0138](https://github.com/Live-Hack-CVE/CVE-2023-0138) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0138.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0138.svg)

## CVE-2023-0137
 Heap buffer overflow in Platform Apps in Google Chrome on Chrome OS prior to 109.0.5414.74 allowed an attacker who convinced a user to install a malicious extension to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: Medium)



- [https://github.com/Live-Hack-CVE/CVE-2023-0137](https://github.com/Live-Hack-CVE/CVE-2023-0137) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0137.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0137.svg)

## CVE-2023-0136
 Inappropriate implementation in in Fullscreen API in Google Chrome on Android prior to 109.0.5414.74 allowed a remote attacker to execute incorrect security UI via a crafted HTML page. (Chromium security severity: Medium)



- [https://github.com/Live-Hack-CVE/CVE-2023-0136](https://github.com/Live-Hack-CVE/CVE-2023-0136) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0136.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0136.svg)

## CVE-2023-0135
 Use after free in Cart in Google Chrome prior to 109.0.5414.74 allowed an attacker who convinced a user to install a malicious extension to potentially exploit heap corruption via database corruption and a crafted HTML page. (Chromium security severity: Medium)



- [https://github.com/Live-Hack-CVE/CVE-2023-0135](https://github.com/Live-Hack-CVE/CVE-2023-0135) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0135.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0135.svg)

## CVE-2023-0134
 Use after free in Cart in Google Chrome prior to 109.0.5414.74 allowed an attacker who convinced a user to install a malicious extension to potentially exploit heap corruption via database corruption and a crafted HTML page. (Chromium security severity: Medium)



- [https://github.com/Live-Hack-CVE/CVE-2023-0134](https://github.com/Live-Hack-CVE/CVE-2023-0134) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0134.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0134.svg)

## CVE-2023-0133
 Inappropriate implementation in in Permission prompts in Google Chrome on Android prior to 109.0.5414.74 allowed a remote attacker to bypass main origin permission delegation via a crafted HTML page. (Chromium security severity: Medium)



- [https://github.com/Live-Hack-CVE/CVE-2023-0133](https://github.com/Live-Hack-CVE/CVE-2023-0133) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0133.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0133.svg)

## CVE-2023-0132
 Inappropriate implementation in in Permission prompts in Google Chrome on Windows prior to 109.0.5414.74 allowed a remote attacker to force acceptance of a permission prompt via a crafted HTML page. (Chromium security severity: Medium)



- [https://github.com/Live-Hack-CVE/CVE-2023-0132](https://github.com/Live-Hack-CVE/CVE-2023-0132) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0132.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0132.svg)

## CVE-2023-0131
 Inappropriate implementation in in iframe Sandbox in Google Chrome prior to 109.0.5414.74 allowed a remote attacker to bypass file download restrictions via a crafted HTML page. (Chromium security severity: Medium)



- [https://github.com/Live-Hack-CVE/CVE-2023-0131](https://github.com/Live-Hack-CVE/CVE-2023-0131) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0131.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0131.svg)

## CVE-2023-0130
 Inappropriate implementation in in Fullscreen API in Google Chrome on Android prior to 109.0.5414.74 allowed a remote attacker to spoof the contents of the Omnibox (URL bar) via a crafted HTML page. (Chromium security severity: Medium)



- [https://github.com/Live-Hack-CVE/CVE-2023-0130](https://github.com/Live-Hack-CVE/CVE-2023-0130) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0130.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0130.svg)

## CVE-2023-0129
 Heap buffer overflow in Network Service in Google Chrome prior to 109.0.5414.74 allowed an attacker who convinced a user to install a malicious extension to potentially exploit heap corruption via a crafted HTML page and specific interactions. (Chromium security severity: High)



- [https://github.com/Live-Hack-CVE/CVE-2023-0129](https://github.com/Live-Hack-CVE/CVE-2023-0129) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0129.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0129.svg)

## CVE-2023-0128
 Use after free in Overview Mode in Google Chrome on Chrome OS prior to 109.0.5414.74 allowed a remote attacker who convinced a user to engage in specific UI interactions to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)



- [https://github.com/Live-Hack-CVE/CVE-2023-0128](https://github.com/Live-Hack-CVE/CVE-2023-0128) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0128.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0128.svg)

## CVE-2023-0126
 Pre-authentication path traversal vulnerability in SMA1000 firmware version 12.4.2, which allows an unauthenticated attacker to access arbitrary files and directories stored outside the web root directory.



- [https://github.com/Live-Hack-CVE/CVE-2023-0126](https://github.com/Live-Hack-CVE/CVE-2023-0126) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0126.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0126.svg)

## CVE-2023-0125
 A vulnerability was found in Control iD Panel. It has been declared as problematic. Affected by this vulnerability is an unknown functionality of the component Web Interface. The manipulation of the argument Nome leads to cross site scripting. The attack can be launched remotely. The exploit has been disclosed to the public and may be used. The identifier VDB-217717 was assigned to this vulnerability.



- [https://github.com/Live-Hack-CVE/CVE-2023-0125](https://github.com/Live-Hack-CVE/CVE-2023-0125) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0125.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0125.svg)

## CVE-2023-0124
 Delta Electronics DOPSoft versions 4.00.16.22 and prior are vulnerable to an out-of-bounds write, which could allow an attacker to remotely execute arbitrary code when a malformed file is introduced to the software.



- [https://github.com/Live-Hack-CVE/CVE-2023-0124](https://github.com/Live-Hack-CVE/CVE-2023-0124) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0124.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0124.svg)

## CVE-2023-0123
 Delta Electronics DOPSoft versions 4.00.16.22 and prior are vulnerable to a stack-based buffer overflow, which could allow an attacker to remotely execute arbitrary code when a malformed file is introduced to the software.



- [https://github.com/Live-Hack-CVE/CVE-2023-0123](https://github.com/Live-Hack-CVE/CVE-2023-0123) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0123.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0123.svg)

## CVE-2023-0122
 A NULL pointer dereference vulnerability in the Linux kernel NVMe functionality, in nvmet_setup_auth(), allows an attacker to perform a Pre-Auth Denial of Service (DoS) attack on a remote machine. Affected versions v6.0-rc1 to v6.0-rc3, fixed in v6.0-rc4.



- [https://github.com/Live-Hack-CVE/CVE-2023-0122](https://github.com/Live-Hack-CVE/CVE-2023-0122) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0122.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0122.svg)

## CVE-2023-0115
 This CVE ID has been rejected or withdrawn by its CVE Numbering Authority.



- [https://github.com/Live-Hack-CVE/CVE-2023-0115](https://github.com/Live-Hack-CVE/CVE-2023-0115) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0115.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0115.svg)

## CVE-2023-0114
 A vulnerability was found in Netis Netcore Router. It has been rated as problematic. Affected by this issue is some unknown functionality of the file param.file.tgz of the component Backup Handler. The manipulation leads to cleartext storage in a file or on disk. Local access is required to approach this attack. The identifier of this vulnerability is VDB-217592.



- [https://github.com/Live-Hack-CVE/CVE-2023-0114](https://github.com/Live-Hack-CVE/CVE-2023-0114) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0114.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0114.svg)

## CVE-2023-0113
 A vulnerability was found in Netis Netcore Router up to 2.2.6. It has been declared as problematic. Affected by this vulnerability is an unknown functionality of the file param.file.tgz of the component Backup Handler. The manipulation leads to information disclosure. The attack can be launched remotely. The associated identifier of this vulnerability is VDB-217591.



- [https://github.com/Live-Hack-CVE/CVE-2023-0113](https://github.com/Live-Hack-CVE/CVE-2023-0113) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0113.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0113.svg)

## CVE-2023-0112
 Cross-site Scripting (XSS) - Stored in GitHub repository usememos/memos prior to 0.10.0.



- [https://github.com/Live-Hack-CVE/CVE-2023-0112](https://github.com/Live-Hack-CVE/CVE-2023-0112) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0112.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0112.svg)

## CVE-2023-0111
 Cross-site Scripting (XSS) - Stored in GitHub repository usememos/memos prior to 0.10.0.



- [https://github.com/Live-Hack-CVE/CVE-2023-0111](https://github.com/Live-Hack-CVE/CVE-2023-0111) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0111.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0111.svg)

## CVE-2023-0110
 Cross-site Scripting (XSS) - Stored in GitHub repository usememos/memos prior to 0.10.0.



- [https://github.com/Live-Hack-CVE/CVE-2023-0110](https://github.com/Live-Hack-CVE/CVE-2023-0110) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0110.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0110.svg)

- [https://github.com/emotest1/cve_2023_0110](https://github.com/emotest1/cve_2023_0110) :  ![starts](https://img.shields.io/github/stars/emotest1/cve_2023_0110.svg) ![forks](https://img.shields.io/github/forks/emotest1/cve_2023_0110.svg)

## CVE-2023-0108
 Cross-site Scripting (XSS) - Stored in GitHub repository usememos/memos prior to 0.10.0.



- [https://github.com/Live-Hack-CVE/CVE-2023-0108](https://github.com/Live-Hack-CVE/CVE-2023-0108) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0108.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0108.svg)

## CVE-2023-0107
 Cross-site Scripting (XSS) - Stored in GitHub repository usememos/memos prior to 0.10.0.



- [https://github.com/Live-Hack-CVE/CVE-2023-0107](https://github.com/Live-Hack-CVE/CVE-2023-0107) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0107.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0107.svg)

## CVE-2023-0106
 Cross-site Scripting (XSS) - Stored in GitHub repository usememos/memos prior to 0.10.0.



- [https://github.com/Live-Hack-CVE/CVE-2023-0106](https://github.com/Live-Hack-CVE/CVE-2023-0106) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0106.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0106.svg)

## CVE-2023-0105
 A flaw was found in Keycloak. This flaw allows impersonation and lockout due to the email trust not being handled correctly in Keycloak. An attacker can shadow other users with the same email and lockout or impersonate them.



- [https://github.com/Live-Hack-CVE/CVE-2023-0105](https://github.com/Live-Hack-CVE/CVE-2023-0105) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0105.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0105.svg)

## CVE-2023-0101
 A privilege escalation vulnerability was identified in Nessus versions 8.10.1 through 8.15.8 and 10.0.0 through 10.4.1. An authenticated attacker could potentially execute a specially crafted file to obtain root or NT AUTHORITY / SYSTEM privileges on the Nessus host.



- [https://github.com/Live-Hack-CVE/CVE-2023-0101](https://github.com/Live-Hack-CVE/CVE-2023-0101) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0101.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0101.svg)

## CVE-2023-0097
 The Post Grid, Post Carousel, &amp; List Category Posts WordPress plugin before 2.4.19 does not validate and escape some of its block options before outputting them back in a page/post where the block is embed, which could allow users with the contributor role and above to perform Stored Cross-Site Scripting attacks.



- [https://github.com/Live-Hack-CVE/CVE-2023-0097](https://github.com/Live-Hack-CVE/CVE-2023-0097) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0097.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0097.svg)

## CVE-2023-0088
 The Swifty Page Manager plugin for WordPress is vulnerable to Cross-Site Request Forgery in versions up to, and including, 3.0.1. This is due to missing or incorrect nonce validation on several AJAX actions handling page creation and deletion among other things. This makes it possible for unauthenticated attackers to invoke those functions, via forged request granted they can trick a site administrator into performing an action such as clicking on a link.



- [https://github.com/Live-Hack-CVE/CVE-2023-0088](https://github.com/Live-Hack-CVE/CVE-2023-0088) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0088.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0088.svg)

## CVE-2023-0087
 The Swifty Page Manager plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the &#8216;spm_plugin_options_page_tree_max_width&#8217; parameter in versions up to, and including, 3.0.1 due to insufficient input sanitization and output escaping. This makes it possible for authenticated attackers, with administrator-level permissions and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page. This only affects multi-site installations and installations where unfiltered_html has been disabled.



- [https://github.com/Live-Hack-CVE/CVE-2023-0087](https://github.com/Live-Hack-CVE/CVE-2023-0087) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0087.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0087.svg)

## CVE-2023-0086
 The JetWidgets for Elementor plugin for WordPress is vulnerable to Cross-Site Request Forgery in versions up to, and including, 1.0.12. This is due to missing nonce validation on the save() function. This makes it possible for unauthenticated attackers to to modify the plugin's settings via a forged request granted they can trick a site administrator into performing an action such as clicking on a link. This can be used to enable SVG uploads that could make Cross-Site Scripting possible.



- [https://github.com/Live-Hack-CVE/CVE-2023-0086](https://github.com/Live-Hack-CVE/CVE-2023-0086) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0086.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0086.svg)

## CVE-2023-0077
 Integer overflow or wraparound vulnerability in CGI component in Synology Router Manager (SRM) before 1.2.5-8227-6 and 1.3.1-9346-3 allows remote attackers to overflow buffers via unspecified vectors.



- [https://github.com/Live-Hack-CVE/CVE-2023-0077](https://github.com/Live-Hack-CVE/CVE-2023-0077) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0077.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0077.svg)

## CVE-2023-0074
 The WP Social Widget WordPress plugin before 2.2.4 does not validate and escape some of its shortcode attributes before outputting them back in a page/post where the shortcode is embed, which could allow users with the contributor role and above to perform Stored Cross-Site Scripting attacks.



- [https://github.com/Live-Hack-CVE/CVE-2023-0074](https://github.com/Live-Hack-CVE/CVE-2023-0074) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0074.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0074.svg)

## CVE-2023-0072
 The WC Vendors Marketplace WordPress plugin before 2.4.5 does not validate and escape some of its shortcode attributes before outputting them back in a page/post where the shortcode is embed, which could allow users with the contributor role and above to perform Stored Cross-Site Scripting attacks.



- [https://github.com/Live-Hack-CVE/CVE-2023-0072](https://github.com/Live-Hack-CVE/CVE-2023-0072) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0072.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0072.svg)

## CVE-2023-0071
 The WP Tabs WordPress plugin before 2.1.17 does not validate and escape some of its shortcode attributes before outputting them back in a page/post where the shortcode is embed, which could allow users with the contributor role and above to perform Stored Cross-Site Scripting attacks.



- [https://github.com/Live-Hack-CVE/CVE-2023-0071](https://github.com/Live-Hack-CVE/CVE-2023-0071) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0071.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0071.svg)

## CVE-2023-0057
 Improper Restriction of Rendered UI Layers or Frames in GitHub repository pyload/pyload prior to 0.5.0b3.dev33.



- [https://github.com/Live-Hack-CVE/CVE-2023-0057](https://github.com/Live-Hack-CVE/CVE-2023-0057) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0057.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0057.svg)

## CVE-2023-0055
 Sensitive Cookie in HTTPS Session Without 'Secure' Attribute in GitHub repository pyload/pyload prior to 0.5.0b3.dev32.



- [https://github.com/Live-Hack-CVE/CVE-2023-0055](https://github.com/Live-Hack-CVE/CVE-2023-0055) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0055.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0055.svg)

## CVE-2023-0054
 Out-of-bounds Write in GitHub repository vim/vim prior to 9.0.1145.



- [https://github.com/Live-Hack-CVE/CVE-2023-0054](https://github.com/Live-Hack-CVE/CVE-2023-0054) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0054.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0054.svg)

## CVE-2023-0052
 SAUTER Controls Nova 200&#8211;220 Series with firmware version 3.3-006 and prior and BACnetstac version 4.2.1 and prior allows the execution of commands without credentials. As Telnet and file transfer protocol (FTP) are the only protocols available for device management, an unauthorized user could access the system and modify the device configuration, which could result in the unauthorized user executing unrestricted malicious commands.



- [https://github.com/Live-Hack-CVE/CVE-2023-0052](https://github.com/Live-Hack-CVE/CVE-2023-0052) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0052.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0052.svg)

## CVE-2023-0049
 Out-of-bounds Read in GitHub repository vim/vim prior to 9.0.1143.



- [https://github.com/Live-Hack-CVE/CVE-2023-0049](https://github.com/Live-Hack-CVE/CVE-2023-0049) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0049.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0049.svg)

## CVE-2023-0048
 Code Injection in GitHub repository lirantal/daloradius prior to master-branch.



- [https://github.com/Live-Hack-CVE/CVE-2023-0048](https://github.com/Live-Hack-CVE/CVE-2023-0048) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0048.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0048.svg)

## CVE-2023-0047
 ** REJECT ** DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: none. Reason: This candidate was in a CNA pool that was not assigned to any issues during 2023. Notes: none.



- [https://github.com/Live-Hack-CVE/CVE-2023-0047](https://github.com/Live-Hack-CVE/CVE-2023-0047) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0047.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0047.svg)

## CVE-2023-0046
 Improper Restriction of Names for Files and Other Resources in GitHub repository lirantal/daloradius prior to master-branch.



- [https://github.com/Live-Hack-CVE/CVE-2023-0046](https://github.com/Live-Hack-CVE/CVE-2023-0046) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0046.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0046.svg)

## CVE-2023-0045
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.



- [https://github.com/es0j/CVE-2023-0045](https://github.com/es0j/CVE-2023-0045) :  ![starts](https://img.shields.io/github/stars/es0j/CVE-2023-0045.svg) ![forks](https://img.shields.io/github/forks/es0j/CVE-2023-0045.svg)

- [https://github.com/missyes/CVE-2023-0045](https://github.com/missyes/CVE-2023-0045) :  ![starts](https://img.shields.io/github/stars/missyes/CVE-2023-0045.svg) ![forks](https://img.shields.io/github/forks/missyes/CVE-2023-0045.svg)

## CVE-2023-0042
 An issue has been discovered in GitLab CE/EE affecting all versions starting from 11.4 prior to 15.5.7, 15.6 prior to 15.6.4, and 15.7 prior to 15.7.2. GitLab Pages allows redirection to arbitrary protocols.



- [https://github.com/Live-Hack-CVE/CVE-2023-0042](https://github.com/Live-Hack-CVE/CVE-2023-0042) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0042.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0042.svg)

## CVE-2023-0040
 Versions of Async HTTP Client prior to 1.13.2 are vulnerable to a form of targeted request manipulation called CRLF injection. This vulnerability was the result of insufficient validation of HTTP header field values before sending them to the network. Users are vulnerable if they pass untrusted data into HTTP header field values without prior sanitisation. Common use-cases here might be to place usernames from a database into HTTP header fields. This vulnerability allows attackers to inject new HTTP header fields, or entirely new requests, into the data stream. This can cause requests to be understood very differently by the remote server than was intended. In general, this is unlikely to result in data disclosure, but it can result in a number of logical errors and other misbehaviours.



- [https://github.com/Live-Hack-CVE/CVE-2023-0040](https://github.com/Live-Hack-CVE/CVE-2023-0040) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0040.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0040.svg)

## CVE-2023-0039
 The User Post Gallery - UPG plugin for WordPress is vulnerable to authorization bypass which leads to remote command execution due to the use of a nopriv AJAX action and user supplied function calls and parameters in versions up to, and including 2.19. This makes it possible for unauthenticated attackers to call arbitrary PHP functions and perform actions like adding new files that can be webshells and updating the site's options to allow anyone to register as an administrator.



- [https://github.com/Live-Hack-CVE/CVE-2023-0039](https://github.com/Live-Hack-CVE/CVE-2023-0039) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0039.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0039.svg)

## CVE-2023-0038
 The &quot;Survey Maker &#8211; Best WordPress Survey Plugin&quot; plugin for WordPress is vulnerable to Stored Cross-Site Scripting via survey answers in versions up to, and including, 3.1.3 due to insufficient input sanitization and output escaping. This makes it possible for unauthenticated attackers to inject arbitrary web scripts when submitting quizzes that will execute whenever a user accesses the submissions page.



- [https://github.com/Live-Hack-CVE/CVE-2023-0038](https://github.com/Live-Hack-CVE/CVE-2023-0038) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0038.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0038.svg)

## CVE-2023-0036
 platform_callback_stub in misc subsystem within OpenHarmony-v3.0.5 and prior versions has an authentication bypass vulnerability which allows an &quot;SA relay attack&quot;.Local attackers can bypass authentication and attack other SAs with high privilege.



- [https://github.com/Live-Hack-CVE/CVE-2023-0036](https://github.com/Live-Hack-CVE/CVE-2023-0036) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0036.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0036.svg)

## CVE-2023-0035
 softbus_client_stub in communication subsystem within OpenHarmony-v3.0.5 and prior versions has an authentication bypass vulnerability which allows an &quot;SA relay attack&quot;.Local attackers can bypass authentication and attack other SAs with high privilege.



- [https://github.com/Live-Hack-CVE/CVE-2023-0035](https://github.com/Live-Hack-CVE/CVE-2023-0035) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0035.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0035.svg)

## CVE-2023-0033
 The PDF Viewer WordPress plugin before 1.0.0 does not validate and escape one of its shortcode attributes, which could allow users with a role as low as contributor to perform Stored Cross-Site Scripting attack.



- [https://github.com/Live-Hack-CVE/CVE-2023-0033](https://github.com/Live-Hack-CVE/CVE-2023-0033) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0033.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0033.svg)

## CVE-2023-0029
 A vulnerability was found in Multilaser RE708 RE1200R4GC-2T2R-V3_v3411b_MUL029B. It has been rated as problematic. This issue affects some unknown processing of the component Telnet Service. The manipulation leads to denial of service. The attack may be initiated remotely. The identifier VDB-217169 was assigned to this vulnerability.



- [https://github.com/Live-Hack-CVE/CVE-2023-0029](https://github.com/Live-Hack-CVE/CVE-2023-0029) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0029.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0029.svg)

## CVE-2023-0028
 Cross-site Scripting (XSS) - Stored in GitHub repository linagora/twake prior to 2023.Q1.1200+.



- [https://github.com/Live-Hack-CVE/CVE-2023-0028](https://github.com/Live-Hack-CVE/CVE-2023-0028) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0028.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0028.svg)

## CVE-2023-0023
 In SAP Bank Account Management (Manage Banks) application, when a user clicks a smart link to navigate to another app, personal data is shown directly in the URL. They might get captured in log files, bookmarks, and so on disclosing sensitive data of the application.



- [https://github.com/Live-Hack-CVE/CVE-2023-0023](https://github.com/Live-Hack-CVE/CVE-2023-0023) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0023.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0023.svg)

## CVE-2023-0022
 SAP BusinessObjects Business Intelligence Analysis edition for OLAP allows an authenticated attacker to inject malicious code that can be executed by the application over the network. On successful exploitation, an attacker can perform operations that may completely compromise the application causing a high impact on the confidentiality, integrity, and availability of the application.



- [https://github.com/Live-Hack-CVE/CVE-2023-0022](https://github.com/Live-Hack-CVE/CVE-2023-0022) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0022.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0022.svg)

## CVE-2023-0018
 Due to improper input sanitization of user-controlled input in SAP BusinessObjects Business Intelligence Platform CMC application - versions 420, and 430, an attacker with basic user-level privileges can modify/upload crystal reports containing a malicious payload. Once these reports are viewable, anyone who opens those reports would be susceptible to stored XSS attacks. As a result of the attack, information maintained in the victim's web browser can be read, modified, and sent to the attacker.



- [https://github.com/Live-Hack-CVE/CVE-2023-0018](https://github.com/Live-Hack-CVE/CVE-2023-0018) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0018.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0018.svg)

## CVE-2023-0017
 An unauthenticated attacker in SAP NetWeaver AS for Java - version 7.50, due to improper access control, can attach to an open interface and make use of an open naming and directory API to access services which can be used to perform unauthorized operations affecting users and data on the current system. This could allow the attacker to have full read access to user data, make modifications to user data, and make services within the system unavailable.



- [https://github.com/Live-Hack-CVE/CVE-2023-0017](https://github.com/Live-Hack-CVE/CVE-2023-0017) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0017.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0017.svg)

## CVE-2023-0016
 SAP BPC MS 10.0 - version 810, allows an unauthorized attacker to execute crafted database queries. The exploitation of this issue could lead to SQL injection vulnerability and could allow an attacker to access, modify, and/or delete data from the backend database.



- [https://github.com/Live-Hack-CVE/CVE-2023-0016](https://github.com/Live-Hack-CVE/CVE-2023-0016) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0016.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0016.svg)

## CVE-2023-0015
 In SAP BusinessObjects Business Intelligence Platform (Web Intelligence user interface) - version 420, some calls return json with wrong content type in the header of the response. As a result, a custom application that calls directly the jsp of Web Intelligence DHTML may be vulnerable to XSS attacks. On successful exploitation an attacker can cause limited impact on confidentiality and integrity of the application.



- [https://github.com/Live-Hack-CVE/CVE-2023-0015](https://github.com/Live-Hack-CVE/CVE-2023-0015) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0015.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0015.svg)

## CVE-2023-0014
 SAP NetWeaver ABAP Server and ABAP Platform - versions SAP_BASIS 700, 701, 702, 710, 711, 730, 731, 740, 750, 751, 752, 753, 754, 755, 756, 757, KERNEL 7.22, 7.53, 7.77, 7.81, 7.85, 7.89, KRNL64UC 7.22, 7.22EXT, 7.53, KRNL64NUC 7.22, 7.22EXT, creates information about system identity in an ambiguous format. This could lead to capture-replay vulnerability and may be exploited by malicious users to obtain illegitimate access to the system.



- [https://github.com/Live-Hack-CVE/CVE-2023-0014](https://github.com/Live-Hack-CVE/CVE-2023-0014) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0014.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0014.svg)

## CVE-2023-0013
 The ABAP Keyword Documentation of SAP NetWeaver Application Server - versions 702, 731, 740, 750, 751, 752, 753, 754, 755, 756, 757, for ABAP and ABAP Platform does not sufficiently encode user-controlled inputs, resulting in Cross-Site Scripting (XSS) vulnerability. On successful exploitation an attacker can cause limited impact on confidentiality and integrity of the application.



- [https://github.com/Live-Hack-CVE/CVE-2023-0013](https://github.com/Live-Hack-CVE/CVE-2023-0013) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0013.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0013.svg)

## CVE-2023-0012
 In SAP Host Agent (Windows) - versions 7.21, 7.22, an attacker who gains local membership to SAP_LocalAdmin could be able to replace executables with a malicious file that will be started under a privileged account. Note that by default all user members of SAP_LocaAdmin are denied the ability to logon locally by security policy so that this can only occur if the system has already been compromised.



- [https://github.com/Live-Hack-CVE/CVE-2023-0012](https://github.com/Live-Hack-CVE/CVE-2023-0012) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0012.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0012.svg)

## CVE-2023-0003
 A file disclosure vulnerability in the Palo Alto Networks Cortex XSOAR server software enables an authenticated user with access to the web interface to read local files from the server.



- [https://github.com/Live-Hack-CVE/CVE-2023-0003](https://github.com/Live-Hack-CVE/CVE-2023-0003) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0003.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0003.svg)

## CVE-2023-0002
 A problem with a protection mechanism in the Palo Alto Networks Cortex XDR agent on Windows devices allows a local user to execute privileged cytool commands that disable or uninstall the agent.



- [https://github.com/Live-Hack-CVE/CVE-2023-0002](https://github.com/Live-Hack-CVE/CVE-2023-0002) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0002.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0002.svg)

## CVE-2023-0001
 An information exposure vulnerability in the Palo Alto Networks Cortex XDR agent on Windows devices allows a local system administrator to disclose the admin password for the agent in cleartext, which bad actors can then use to execute privileged cytool commands that disable or uninstall the agent.



- [https://github.com/Live-Hack-CVE/CVE-2023-0001](https://github.com/Live-Hack-CVE/CVE-2023-0001) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0001.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0001.svg)
