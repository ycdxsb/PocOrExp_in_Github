# Update 2023-02-09
## CVE-2023-25194
 A possible security vulnerability has been identified in Apache Kafka Connect. This requires access to a Kafka Connect worker, and the ability to create/modify connectors on it with an arbitrary Kafka client SASL JAAS config and a SASL-based security protocol, which has been possible on Kafka Connect clusters since Apache Kafka 2.3.0. When configuring the connector via the Kafka Connect REST API, an authenticated operator can set the `sasl.jaas.config` property for any of the connector's Kafka clients to &quot;com.sun.security.auth.module.JndiLoginModule&quot;, which can be done via the `producer.override.sasl.jaas.config`, `consumer.override.sasl.jaas.config`, or `admin.override.sasl.jaas.config` properties. This will allow the server to connect to the attacker's LDAP server and deserialize the LDAP response, which the attacker can use to execute java deserialization gadget chains on the Kafka connect server. Attacker can cause unrestricted deserialization of untrusted data (or) RCE vulnerability when there are gadgets in the classpath. Since Apache Kafka 3.0.0, users are allowed to specify these properties in connector configurations for Kafka Connect clusters running with out-of-the-box configurations. Before Apache Kafka 3.0.0, users may not specify these properties unless the Kafka Connect cluster has been reconfigured with a connector client override policy that permits them. Since Apache Kafka 3.4.0, we have added a system property (&quot;-Dorg.apache.kafka.disallowed.login.modules&quot;) to disable the problematic login modules usage in SASL JAAS configuration. Also by default &quot;com.sun.security.auth.module.JndiLoginModule&quot; is disabled in Apache Kafka 3.4.0. We advise the Kafka Connect users to validate connector configurations and only allow trusted JNDI configurations. Also examine connector dependencies for vulnerable versions and either upgrade their connectors, upgrading that specific dependency, or removing the connectors as options for remediation. Finally, in addition to leveraging the &quot;org.apache.kafka.disallowed.login.modules&quot; system property, Kafka Connect users can also implement their own connector client config override policy, which can be used to control which Kafka client properties can be overridden directly in a connector config and which cannot.

- [https://github.com/Live-Hack-CVE/CVE-2023-25194](https://github.com/Live-Hack-CVE/CVE-2023-25194) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-25194.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-25194.svg)


## CVE-2023-25136
 OpenSSH server (sshd) 9.1 introduced a double-free vulnerability during options.kex_algorithms handling. This is fixed in OpenSSH 9.2. The double free can be triggered by an unauthenticated attacker in the default configuration; however, the vulnerability discoverer reports that &quot;exploiting this vulnerability will not be easy.&quot;

- [https://github.com/jfrog/jfrog-CVE-2023-25136-OpenSSH_Double-Free](https://github.com/jfrog/jfrog-CVE-2023-25136-OpenSSH_Double-Free) :  ![starts](https://img.shields.io/github/stars/jfrog/jfrog-CVE-2023-25136-OpenSSH_Double-Free.svg) ![forks](https://img.shields.io/github/forks/jfrog/jfrog-CVE-2023-25136-OpenSSH_Double-Free.svg)


## CVE-2023-24828
 Onedev is a self-hosted Git Server with CI/CD and Kanban. In versions prior to 7.9.12 the algorithm used to generate access token and password reset keys was not cryptographically secure. Existing normal users (or everyone if it allows self-registration) may exploit this to elevate privilege to obtain administrator permission. This issue is has been addressed in version 7.9.12. Users are advised to upgrade. There are no known workarounds for this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2023-24828](https://github.com/Live-Hack-CVE/CVE-2023-24828) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24828.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24828.svg)


## CVE-2023-24827
 syft is a a CLI tool and Go library for generating a Software Bill of Materials (SBOM) from container images and filesystems. A password disclosure flaw was found in Syft versions v0.69.0 and v0.69.1. This flaw leaks the password stored in the SYFT_ATTEST_PASSWORD environment variable. The `SYFT_ATTEST_PASSWORD` environment variable is for the `syft attest` command to generate attested SBOMs for the given container image. This environment variable is used to decrypt the private key (provided with `syft attest --key &lt;path-to-key-file&gt;`) during the signing process while generating an SBOM attestation. This vulnerability affects users running syft that have the `SYFT_ATTEST_PASSWORD` environment variable set with credentials (regardless of if the attest command is being used or not). Users that do not have the environment variable `SYFT_ATTEST_PASSWORD` set are not affected by this issue. The credentials are leaked in two ways: in the syft logs when `-vv` or `-vvv` are used in the syft command (which is any log level &gt;= `DEBUG`) and in the attestation or SBOM only when the `syft-json` format is used. Note that as of v0.69.0 any generated attestations by the `syft attest` command are uploaded to the OCI registry (if you have write access to that registry) in the same way `cosign attach` is done. This means that any attestations generated for the affected versions of syft when the `SYFT_ATTEST_PASSWORD` environment variable was set would leak credentials in the attestation payload uploaded to the OCI registry. This issue has been patched in commit `9995950c70` and has been released as v0.70.0. There are no workarounds for this vulnerability. Users are advised to upgrade.

- [https://github.com/Live-Hack-CVE/CVE-2023-24827](https://github.com/Live-Hack-CVE/CVE-2023-24827) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24827.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24827.svg)


## CVE-2023-24808
 PDFio is a C library for reading and writing PDF files. In versions prior to 1.1.0 a denial of service (DOS) vulnerability exists in the pdfio parser. Crafted pdf files can cause the program to run at 100% utilization and never terminate. The pdf which causes this crash found in testing is about 28kb in size and was discovered via fuzzing. Anyone who uses this library either as a standalone binary or as a library can be DOSed when attempting to parse this type of file. Web servers or other automated processes which rely on this code to turn pdf submissions into plaintext can be DOSed when an attacker uploads the pdf. Please see the linked GHSA for an example pdf. Users are advised to upgrade. There are no known workarounds for this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2023-24808](https://github.com/Live-Hack-CVE/CVE-2023-24808) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24808.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24808.svg)


## CVE-2023-23696
 Dell Command Intel vPro Out of Band, versions prior to 4.3.1, contain an Improper Authorization vulnerability. A locally authenticated malicious users could potentially exploit this vulnerability in order to write arbitrary files to the system.

- [https://github.com/Live-Hack-CVE/CVE-2023-23696](https://github.com/Live-Hack-CVE/CVE-2023-23696) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23696.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23696.svg)


## CVE-2023-23609
 Contiki-NG is an open-source, cross-platform operating system for Next-Generation IoT devices. Versions prior to and including 4.8 are vulnerable to an out-of-bounds write that can occur in the BLE-L2CAP module. The Bluetooth Low Energy - Logical Link Control and Adaptation Layer Protocol (BLE-L2CAP) module handles fragmentation of packets up the configured MTU size. When fragments are reassembled, they are stored in a packet buffer of a configurable size, but there is no check to verify that the packet buffer is large enough to hold the reassembled packet. In Contiki-NG's default configuration, it is possible that an out-of-bounds write of up to 1152 bytes occurs. The vulnerability has been patched in the &quot;develop&quot; branch of Contiki-NG, and will be included in release 4.9. The problem can be fixed by applying the patch in Contiki-NG pull request #2254 prior to the release of version 4.9.

- [https://github.com/Live-Hack-CVE/CVE-2023-23609](https://github.com/Live-Hack-CVE/CVE-2023-23609) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23609.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23609.svg)


## CVE-2023-23582
 Snap One Wattbox WB-300-IP-3 versions WB10.9a17 and prior are vulnerable to a heap-based buffer overflow, which could allow an attacker to execute arbitrary code or crash the device remotely.

- [https://github.com/Live-Hack-CVE/CVE-2023-23582](https://github.com/Live-Hack-CVE/CVE-2023-23582) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23582.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23582.svg)


## CVE-2023-23026
 Cross site scripting (XSS) vulnerability in sourcecodester oretnom23 sales management system 1.0, allows attackers to execute arbitrary code via the product_name and product_price inputs in file print.php.

- [https://github.com/Live-Hack-CVE/CVE-2023-23026](https://github.com/Live-Hack-CVE/CVE-2023-23026) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23026.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23026.svg)


## CVE-2023-23011
 Cross Site Scripting (XSS) vulnerability in InvoicePlane 1.6 via filter_product input to file modal_product_lookups.php.

- [https://github.com/Live-Hack-CVE/CVE-2023-23011](https://github.com/Live-Hack-CVE/CVE-2023-23011) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23011.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23011.svg)


## CVE-2023-22736
 Argo CD is a declarative, GitOps continuous delivery tool for Kubernetes. Versions starting with 2.5.0-rc1 and above, prior to 2.5.8, and version 2.6.0-rc4, are vulnerable to an authorization bypass bug which allows a malicious Argo CD user to deploy Applications outside the configured allowed namespaces. Reconciled Application namespaces are specified as a comma-delimited list of glob patterns. When sharding is enabled on the Application controller, it does not enforce that list of patterns when reconciling Applications. For example, if Application namespaces are configured to be argocd-*, the Application controller may reconcile an Application installed in a namespace called other, even though it does not start with argocd-. Reconciliation of the out-of-bounds Application is only triggered when the Application is updated, so the attacker must be able to cause an update operation on the Application resource. This bug only applies to users who have explicitly enabled the &quot;apps-in-any-namespace&quot; feature by setting `application.namespaces` in the argocd-cmd-params-cm ConfigMap or otherwise setting the `--application-namespaces` flags on the Application controller and API server components. The apps-in-any-namespace feature is in beta as of this Security Advisory's publish date. The bug is also limited to Argo CD instances where sharding is enabled by increasing the `replicas` count for the Application controller. Finally, the AppProjects' `sourceNamespaces` field acts as a secondary check against this exploit. To cause reconciliation of an Application in an out-of-bounds namespace, an AppProject must be available which permits Applications in the out-of-bounds namespace. A patch for this vulnerability has been released in versions 2.5.8 and 2.6.0-rc5. As a workaround, running only one replica of the Application controller will prevent exploitation of this bug. Making sure all AppProjects' sourceNamespaces are restricted within the confines of the configured Application namespaces will also prevent exploitation of this bug.

- [https://github.com/Live-Hack-CVE/CVE-2023-22736](https://github.com/Live-Hack-CVE/CVE-2023-22736) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22736.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22736.svg)


## CVE-2023-22643
 An Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') vulnerability in libzypp-plugin-appdata of SUSE Linux Enterprise Server for SAP 15-SP3; openSUSE Leap 15.4 allows attackers that can trick users to use specially crafted REPO_ALIAS, REPO_TYPE or REPO_METADATA_PATH settings to execute code as root. This issue affects: SUSE Linux Enterprise Server for SAP 15-SP3 libzypp-plugin-appdata versions prior to 1.0.1+git.20180426. openSUSE Leap 15.4 libzypp-plugin-appdata versions prior to 1.0.1+git.20180426.

- [https://github.com/Live-Hack-CVE/CVE-2023-22643](https://github.com/Live-Hack-CVE/CVE-2023-22643) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22643.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22643.svg)


## CVE-2023-22611
 A CWE-200: Exposure of Sensitive Information to an Unauthorized Actor vulnerability exists that could cause information disclosure when specific messages are sent to the server over the database server TCP port. Affected Products: EcoStruxure Geo SCADA Expert 2019 - 2021 (formerly known as ClearSCADA) (Versions prior to October 2022)

- [https://github.com/Live-Hack-CVE/CVE-2023-22611](https://github.com/Live-Hack-CVE/CVE-2023-22611) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22611.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22611.svg)


## CVE-2023-22389
 Snap One Wattbox WB-300-IP-3 versions WB10.9a17 and prior store passwords in a plaintext file when the device configuration is exported via Save/Restore&#8211;&gt;Backup Settings, which could be read by any user accessing the file.

- [https://github.com/Live-Hack-CVE/CVE-2023-22389](https://github.com/Live-Hack-CVE/CVE-2023-22389) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22389.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22389.svg)


## CVE-2023-0736
 Cross-site Scripting (XSS) - Stored in GitHub repository wallabag/wallabag prior to 2.5.4.

- [https://github.com/Live-Hack-CVE/CVE-2023-0736](https://github.com/Live-Hack-CVE/CVE-2023-0736) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0736.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0736.svg)


## CVE-2023-0735
 Cross-Site Request Forgery (CSRF) in GitHub repository wallabag/wallabag prior to 2.5.4.

- [https://github.com/Live-Hack-CVE/CVE-2023-0735](https://github.com/Live-Hack-CVE/CVE-2023-0735) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0735.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0735.svg)


## CVE-2023-0732
 A vulnerability has been found in SourceCodester Online Eyewear Shop 1.0 and classified as problematic. Affected by this vulnerability is an unknown functionality of the file oews/classes/Users.php of the component POST Request Handler. The manipulation of the argument firstname/middlename/lastname/lastname/contact leads to cross site scripting. The attack can be launched remotely. The identifier VDB-220369 was assigned to this vulnerability.

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


## CVE-2023-0723
 The Wicked Folders plugin for WordPress is vulnerable to Cross-Site Request Forgery in versions up to, and including, 2.18.16. This is due to missing or incorrect nonce validation on the ajax_move_object function. This makes it possible for unauthenticated attackers to invoke this function via forged request granted they can trick a site administrator into performing an action such as clicking on a link leading them to perform actions intended for administrators such as changing the folder structure maintained by the plugin.

- [https://github.com/Live-Hack-CVE/CVE-2023-0723](https://github.com/Live-Hack-CVE/CVE-2023-0723) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0723.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0723.svg)


## CVE-2023-0719
 The Wicked Folders plugin for WordPress is vulnerable to authorization bypass due to a missing capability check on the ajax_save_sort_order function in versions up to, and including, 2.18.16. This makes it possible for authenticated attackers, with subscriber-level permissions and above, to invoke this function and perform actions intended for administrators such as modifying the folder structure maintained by the plugin.

- [https://github.com/Live-Hack-CVE/CVE-2023-0719](https://github.com/Live-Hack-CVE/CVE-2023-0719) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0719.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0719.svg)


## CVE-2023-0718
 The Wicked Folders plugin for WordPress is vulnerable to authorization bypass due to a missing capability check on the ajax_save_folder function in versions up to, and including, 2.18.16. This makes it possible for authenticated attackers, with subscriber-level permissions and above, to invoke this function and perform actions intended for administrators such as modifying the folder structure maintained by the plugin.

- [https://github.com/Live-Hack-CVE/CVE-2023-0718](https://github.com/Live-Hack-CVE/CVE-2023-0718) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0718.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0718.svg)


## CVE-2023-0713
 The Wicked Folders plugin for WordPress is vulnerable to authorization bypass due to a missing capability check on the ajax_add_folder function in versions up to, and including, 2.18.16. This makes it possible for authenticated attackers, with subscriber-level permissions and above, to invoke this function and perform actions intended for administrators such as modifying the folder structure maintained by the plugin.

- [https://github.com/Live-Hack-CVE/CVE-2023-0713](https://github.com/Live-Hack-CVE/CVE-2023-0713) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0713.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0713.svg)


## CVE-2023-0712
 The Wicked Folders plugin for WordPress is vulnerable to authorization bypass due to a missing capability check on the ajax_move_object function in versions up to, and including, 2.18.16. This makes it possible for authenticated attackers, with subscriber-level permissions and above, to invoke this function and perform actions intended for administrators such as modifying the folder structure maintained by the plugin.

- [https://github.com/Live-Hack-CVE/CVE-2023-0712](https://github.com/Live-Hack-CVE/CVE-2023-0712) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0712.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0712.svg)


## CVE-2023-0707
 A vulnerability was found in SourceCodester Medical Certificate Generator App 1.0. It has been rated as critical. Affected by this issue is the function delete_record of the file function.php. The manipulation of the argument id leads to sql injection. VDB-220346 is the identifier assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2023-0707](https://github.com/Live-Hack-CVE/CVE-2023-0707) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0707.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0707.svg)


## CVE-2023-0706
 A vulnerability, which was classified as critical, has been found in SourceCodester Medical Certificate Generator App 1.0. Affected by this issue is some unknown functionality of the file manage_record.php. The manipulation of the argument id leads to sql injection. The attack may be launched remotely. The identifier of this vulnerability is VDB-220340.

- [https://github.com/Live-Hack-CVE/CVE-2023-0706](https://github.com/Live-Hack-CVE/CVE-2023-0706) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0706.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0706.svg)


## CVE-2023-0074
 The WP Social Widget WordPress plugin before 2.2.4 does not validate and escape some of its shortcode attributes before outputting them back in a page/post where the shortcode is embed, which could allow users with the contributor role and above to perform Stored Cross-Site Scripting attacks.

- [https://github.com/Live-Hack-CVE/CVE-2023-0074](https://github.com/Live-Hack-CVE/CVE-2023-0074) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0074.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0074.svg)


## CVE-2023-0071
 The WP Tabs WordPress plugin before 2.1.17 does not validate and escape some of its shortcode attributes before outputting them back in a page/post where the shortcode is embed, which could allow users with the contributor role and above to perform Stored Cross-Site Scripting attacks.

- [https://github.com/Live-Hack-CVE/CVE-2023-0071](https://github.com/Live-Hack-CVE/CVE-2023-0071) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0071.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0071.svg)


## CVE-2023-0045
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/missyes/CVE-2023-0045](https://github.com/missyes/CVE-2023-0045) :  ![starts](https://img.shields.io/github/stars/missyes/CVE-2023-0045.svg) ![forks](https://img.shields.io/github/forks/missyes/CVE-2023-0045.svg)


## CVE-2023-0033
 The PDF Viewer WordPress plugin before 1.0.0 does not validate and escape one of its shortcode attributes, which could allow users with a role as low as contributor to perform Stored Cross-Site Scripting attack.

- [https://github.com/Live-Hack-CVE/CVE-2023-0033](https://github.com/Live-Hack-CVE/CVE-2023-0033) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0033.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0033.svg)


## CVE-2022-47770
 Serenissima Informatica Fast Checkin version v1.0 is vulnerable to Unauthenticated SQL Injection.

- [https://github.com/Live-Hack-CVE/CVE-2022-47770](https://github.com/Live-Hack-CVE/CVE-2022-47770) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-47770.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-47770.svg)


## CVE-2022-47419
 An XSS vulnerability was discovered in the Mayan EDMS DMS. Successful XSS exploitation was observed in the in-product tagging system.

- [https://github.com/Live-Hack-CVE/CVE-2022-47419](https://github.com/Live-Hack-CVE/CVE-2022-47419) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-47419.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-47419.svg)


## CVE-2022-47418
 LogicalDOC Enterprise and Community Edition (CE) are vulnerable to a stored (persistent, or &quot;Type II&quot;) cross-site scripting (XSS) condition in the document version comments.

- [https://github.com/Live-Hack-CVE/CVE-2022-47418](https://github.com/Live-Hack-CVE/CVE-2022-47418) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-47418.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-47418.svg)


## CVE-2022-47417
 LogicalDOC Enterprise and Community Edition (CE) are vulnerable to a stored (persistent, or &quot;Type II&quot;) cross-site scripting (XSS) condition in the document file name.

- [https://github.com/Live-Hack-CVE/CVE-2022-47417](https://github.com/Live-Hack-CVE/CVE-2022-47417) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-47417.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-47417.svg)


## CVE-2022-47416
 LogicalDOC Enterprise is vulnerable to a stored (persistent, or &quot;Type II&quot;) cross-site scripting (XSS) condition in the in-app chat system.

- [https://github.com/Live-Hack-CVE/CVE-2022-47416](https://github.com/Live-Hack-CVE/CVE-2022-47416) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-47416.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-47416.svg)


## CVE-2022-47415
 LogicalDOC Enterprise and Community Edition (CE) are vulnerable to a stored (persistent, or &quot;Type II&quot;) cross-site scripting (XSS) condition in the in-app messaging system (both subject and message bodies).

- [https://github.com/Live-Hack-CVE/CVE-2022-47415](https://github.com/Live-Hack-CVE/CVE-2022-47415) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-47415.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-47415.svg)


## CVE-2022-47414
 If an attacker has access to the console for OpenKM (and is authenticated), a stored XSS vulnerability is reachable in the document &quot;note&quot; functionality.

- [https://github.com/Live-Hack-CVE/CVE-2022-47414](https://github.com/Live-Hack-CVE/CVE-2022-47414) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-47414.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-47414.svg)


## CVE-2022-47413
 Given a malicious document provided by an attacker, the OpenKM DMS is vulnerable to a stored (persistent, or &quot;Type II&quot;) XSS condition.

- [https://github.com/Live-Hack-CVE/CVE-2022-47413](https://github.com/Live-Hack-CVE/CVE-2022-47413) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-47413.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-47413.svg)


## CVE-2022-47412
 Given a malicious document provided by an attacker, the ONLYOFFICE Workspace DMS is vulnerable to a stored (persistent, or &quot;Type II&quot;) cross-site scripting (XSS) condition.

- [https://github.com/Live-Hack-CVE/CVE-2022-47412](https://github.com/Live-Hack-CVE/CVE-2022-47412) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-47412.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-47412.svg)


## CVE-2022-46663
 In GNU Less before 609, crafted data can result in &quot;less -R&quot; not filtering ANSI escape sequences sent to the terminal.

- [https://github.com/Live-Hack-CVE/CVE-2022-46663](https://github.com/Live-Hack-CVE/CVE-2022-46663) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-46663.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-46663.svg)


## CVE-2022-46621
 ** REJECT ** DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: none. Reason: This candidate was withdrawn by its CNA. Further investigation showed that it was not a security issue. Notes: none.

- [https://github.com/Live-Hack-CVE/CVE-2022-46621](https://github.com/Live-Hack-CVE/CVE-2022-46621) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-46621.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-46621.svg)


## CVE-2022-46620
 ** REJECT ** DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: none. Reason: This candidate was withdrawn by its CNA. Further investigation showed that it was not a security issue. Notes: none.

- [https://github.com/Live-Hack-CVE/CVE-2022-46620](https://github.com/Live-Hack-CVE/CVE-2022-46620) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-46620.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-46620.svg)


## CVE-2022-45674
 Tenda AC6V1.0 V15.03.05.19 is vulnerable to Cross Site Request Forgery (CSRF) via function fromSysToolReboot.

- [https://github.com/Live-Hack-CVE/CVE-2022-45674](https://github.com/Live-Hack-CVE/CVE-2022-45674) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-45674.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-45674.svg)


## CVE-2022-45544
 Insecure Permission vulnerability in Schlix Web Inc SCHLIX CMS 2.2.7-2 allows attacker to upload arbitrary files and execute arbitrary code via the tristao parameter.

- [https://github.com/Live-Hack-CVE/CVE-2022-45544](https://github.com/Live-Hack-CVE/CVE-2022-45544) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-45544.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-45544.svg)


## CVE-2022-45441
 A cross-site scripting (XSS) vulnerability in Zyxel NBG-418N v2 firmware versions prior to V1.00(AARP.13)C0, which could allow an attacker to store malicious scripts in the Logs page of the GUI on a vulnerable device. A successful XSS attack could force an authenticated user to execute the stored malicious scripts and then result in a denial-of-service (DoS) condition when the user visits the Logs page of the GUI on the device.

- [https://github.com/Live-Hack-CVE/CVE-2022-45441](https://github.com/Live-Hack-CVE/CVE-2022-45441) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-45441.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-45441.svg)


## CVE-2022-45192
 An issue was discovered on Microchip RN4870 1.43 devices. An attacker within BLE radio range can cause a denial of service by sending a cleartext encryption pause request.

- [https://github.com/Live-Hack-CVE/CVE-2022-45192](https://github.com/Live-Hack-CVE/CVE-2022-45192) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-45192.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-45192.svg)


## CVE-2022-45191
 An issue was discovered on Microchip RN4870 1.43 devices. An attacker within BLE radio range can cause a denial of service by sending a pair confirm message with wrong values.

- [https://github.com/Live-Hack-CVE/CVE-2022-45191](https://github.com/Live-Hack-CVE/CVE-2022-45191) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-45191.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-45191.svg)


## CVE-2022-45190
 An issue was discovered on Microchip RN4870 1.43 devices. An attacker within BLE radio range can bypass passkey entry in the legacy pairing of the device.

- [https://github.com/Live-Hack-CVE/CVE-2022-45190](https://github.com/Live-Hack-CVE/CVE-2022-45190) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-45190.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-45190.svg)


## CVE-2022-43759
 A Improper Privilege Management vulnerability in SUSE Rancher, allows users with access to the escalate verb on PRTBs to escalate permissions for any -promoted resource in any cluster. This issue affects: SUSE Rancher Rancher versions prior to 2.5.17; Rancher versions prior to 2.6.10.

- [https://github.com/Live-Hack-CVE/CVE-2022-43759](https://github.com/Live-Hack-CVE/CVE-2022-43759) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-43759.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-43759.svg)


## CVE-2022-43758
 A Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') vulnerability in SUSE Rancher allows code execution for user with the ability to add an untrusted Helm catalog or modifying the URL configuration used to download KDM (only admin users by default) This issue affects: SUSE Rancher Rancher versions prior to 2.5.17; Rancher versions prior to 2.6.10; Rancher versions prior to 2.7.1.

- [https://github.com/Live-Hack-CVE/CVE-2022-43758](https://github.com/Live-Hack-CVE/CVE-2022-43758) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-43758.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-43758.svg)


## CVE-2022-43757
 A Cleartext Storage of Sensitive Information vulnerability in SUSE Rancher allows users on managed clusters to gain access to credentials. The impact depends on the credentials exposed This issue affects: SUSE Rancher Rancher versions prior to 2.5.17; Rancher versions prior to 2.6.10; Rancher versions prior to 2.7.1.

- [https://github.com/Live-Hack-CVE/CVE-2022-43757](https://github.com/Live-Hack-CVE/CVE-2022-43757) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-43757.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-43757.svg)


## CVE-2022-43756
 A Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') vulnerability in SUSE Rancher allows remote attackers to cause denial of service by supplying specially crafted git credentials. This issue affects: SUSE Rancher wrangler version 0.7.3 and prior versions; wrangler version 0.8.4 and prior versions; wrangler version 1.0.0 and prior versions.

- [https://github.com/Live-Hack-CVE/CVE-2022-43756](https://github.com/Live-Hack-CVE/CVE-2022-43756) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-43756.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-43756.svg)


## CVE-2022-43755
 A Insufficient Entropy vulnerability in SUSE Rancher allows attackers that gained knowledge of the cattle-token to continue abusing this even after the token was renewed. This issue affects: SUSE Rancher Rancher versions prior to 2.6.10; Rancher versions prior to 2.7.1.

- [https://github.com/Live-Hack-CVE/CVE-2022-43755](https://github.com/Live-Hack-CVE/CVE-2022-43755) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-43755.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-43755.svg)


## CVE-2022-43591
 A buffer overflow vulnerability exists in the QML QtScript Reflect API of Qt Project Qt 6.3.2. A specially-crafted javascript code can trigger an out-of-bounds memory access, which can lead to arbitrary code execution. Target application would need to access a malicious web page to trigger this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2022-43591](https://github.com/Live-Hack-CVE/CVE-2022-43591) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-43591.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-43591.svg)


## CVE-2022-41313
 A stored cross-site scripting vulnerability exists in the web application functionality of Moxa SDS-3008 Series Industrial Ethernet Switch 2.1. A specially-crafted HTTP request can lead to arbitrary Javascript execution. An attacker can send an HTTP request to trigger this vulnerability.Form field id=&quot;switch_contact&quot;

- [https://github.com/Live-Hack-CVE/CVE-2022-41313](https://github.com/Live-Hack-CVE/CVE-2022-41313) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-41313.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-41313.svg)


## CVE-2022-41312
 A stored cross-site scripting vulnerability exists in the web application functionality of Moxa SDS-3008 Series Industrial Ethernet Switch 2.1. A specially-crafted HTTP request can lead to arbitrary Javascript execution. An attacker can send an HTTP request to trigger this vulnerability.Form field id=&quot;Switch Description&quot;, name &quot;switch_description&quot;

- [https://github.com/Live-Hack-CVE/CVE-2022-41312](https://github.com/Live-Hack-CVE/CVE-2022-41312) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-41312.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-41312.svg)


## CVE-2022-41311
 A stored cross-site scripting vulnerability exists in the web application functionality of Moxa SDS-3008 Series Industrial Ethernet Switch 2.1. A specially-crafted HTTP request can lead to arbitrary Javascript execution. An attacker can send an HTTP request to trigger this vulnerability.Form field id=&quot;webLocationMessage_text&quot; name=&quot;webLocationMessage_text&quot;

- [https://github.com/Live-Hack-CVE/CVE-2022-41311](https://github.com/Live-Hack-CVE/CVE-2022-41311) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-41311.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-41311.svg)


## CVE-2022-40693
 A cleartext transmission vulnerability exists in the web application functionality of Moxa SDS-3008 Series Industrial Ethernet Switch 2.1. A specially-crafted network sniffing can lead to a disclosure of sensitive information. An attacker can sniff network traffic to trigger this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2022-40693](https://github.com/Live-Hack-CVE/CVE-2022-40693) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-40693.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-40693.svg)


## CVE-2022-40691
 An information disclosure vulnerability exists in the web application functionality of Moxa SDS-3008 Series Industrial Ethernet Switch 2.1. A specially-crafted HTTP request can lead to a disclosure of sensitive information. An attacker can send an HTTP request to trigger this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2022-40691](https://github.com/Live-Hack-CVE/CVE-2022-40691) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-40691.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-40691.svg)


## CVE-2022-40480
 Nordic Semiconductor, Microchip Technology NRF5340-DK DT100112 was discovered to contain an issue which allows attackers to cause a Denial of Service (DoS) via a crafted ConReq packet.

- [https://github.com/Live-Hack-CVE/CVE-2022-40480](https://github.com/Live-Hack-CVE/CVE-2022-40480) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-40480.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-40480.svg)


## CVE-2022-40224
 A denial of service vulnerability exists in the web server functionality of Moxa SDS-3008 Series Industrial Ethernet Switch 2.1. A specially-crafted HTTP message header can lead to denial of service. An attacker can send an HTTP request to trigger this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2022-40224](https://github.com/Live-Hack-CVE/CVE-2022-40224) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-40224.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-40224.svg)


## CVE-2022-37184
 The application manage_website.php on Garage Management System 1.0 is vulnerable to Shell File Upload. The already authenticated malicious user, can upload a dangerous RCE or LCE exploit file.

- [https://github.com/Live-Hack-CVE/CVE-2022-37184](https://github.com/Live-Hack-CVE/CVE-2022-37184) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-37184.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-37184.svg)


## CVE-2022-32523
 A CWE-120: Buffer Copy without Checking Size of Input vulnerability exists that could cause a stack-based buffer overflow, potentially leading to remote code execution when an attacker sends specially crafted online data request messages. Affected Products: IGSS Data Server - IGSSdataServer.exe (Versions prior to V15.0.0.22170)

- [https://github.com/Live-Hack-CVE/CVE-2022-32523](https://github.com/Live-Hack-CVE/CVE-2022-32523) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-32523.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-32523.svg)


## CVE-2022-32520
 A CWE-522: Insufficiently Protected Credentials vulnerability exists that could result in unwanted access to a DCE instance when performed over a network by a malicious third-party. This CVE is unique from CVE-2022-32518. Affected Products: Data Center Expert (Versions prior to V7.9.0)

- [https://github.com/Live-Hack-CVE/CVE-2022-32518](https://github.com/Live-Hack-CVE/CVE-2022-32518) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-32518.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-32518.svg)


## CVE-2022-32518
 A CWE-522: Insufficiently Protected Credentials vulnerability exists that could result in unwanted access to a DCE instance when performed over a network by a malicious third-party. This CVE is unique from CVE-2022-32520. Affected Products: Data Center Expert (Versions prior to V7.9.0)

- [https://github.com/Live-Hack-CVE/CVE-2022-32518](https://github.com/Live-Hack-CVE/CVE-2022-32518) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-32518.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-32518.svg)


## CVE-2022-31611
 NVIDIA GeForce Experience contains an uncontrolled search path vulnerability in all its client installers, where an attacker with user level privileges may cause the installer to load an arbitrary DLL when the installer is launched. A successful exploit of this vulnerability could lead to escalation of privileges and code execution.

- [https://github.com/Live-Hack-CVE/CVE-2022-31611](https://github.com/Live-Hack-CVE/CVE-2022-31611) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-31611.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-31611.svg)


## CVE-2022-31254
 A Incorrect Default Permissions vulnerability in rmt-server-regsharing service of SUSE Linux Enterprise Server for SAP 15, SUSE Linux Enterprise Server for SAP 15-SP1, SUSE Manager Server 4.1; openSUSE Leap 15.3, openSUSE Leap 15.4 allows local attackers with access to the _rmt user to escalate to root. This issue affects: SUSE Linux Enterprise Server for SAP 15 rmt-server versions prior to 2.10. SUSE Linux Enterprise Server for SAP 15-SP1 rmt-server versions prior to 2.10. SUSE Manager Server 4.1 rmt-server versions prior to 2.10. openSUSE Leap 15.3 rmt-server versions prior to 2.10. openSUSE Leap 15.4 rmt-server versions prior to 2.10.

- [https://github.com/Live-Hack-CVE/CVE-2022-31254](https://github.com/Live-Hack-CVE/CVE-2022-31254) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-31254.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-31254.svg)


## CVE-2022-31249
 A Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') vulnerability in wrangler of SUSE Rancher allows remote attackers to inject commands in the underlying host via crafted commands passed to Wrangler. This issue affects: SUSE Rancher wrangler version 0.7.3 and prior versions; wrangler version 0.8.4 and prior versions; wrangler version 1.0.0 and prior versions.

- [https://github.com/Live-Hack-CVE/CVE-2022-31249](https://github.com/Live-Hack-CVE/CVE-2022-31249) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-31249.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-31249.svg)


## CVE-2022-24990
 TerraMaster NAS 4.2.29 and earlier allows remote attackers to discover the administrative password by sending &quot;User-Agent: TNAS&quot; to module/api.php?mobile/webNasIPS and then reading the PWD field in the response.

- [https://github.com/Live-Hack-CVE/CVE-2022-24990](https://github.com/Live-Hack-CVE/CVE-2022-24990) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-24990.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-24990.svg)


## CVE-2022-23935
 lib/Image/ExifTool.pm in ExifTool before 12.38 mishandles a $file =~ /\|$/ check, leading to command injection.

- [https://github.com/0xFTW/CVE-2022-23935](https://github.com/0xFTW/CVE-2022-23935) :  ![starts](https://img.shields.io/github/stars/0xFTW/CVE-2022-23935.svg) ![forks](https://img.shields.io/github/forks/0xFTW/CVE-2022-23935.svg)


## CVE-2022-21953
 A Missing Authorization vulnerability in of SUSE Rancher allows authenticated user to create an unauthorized shell pod and kubectl access in the local cluster This issue affects: SUSE Rancher Rancher versions prior to 2.5.17; Rancher versions prior to 2.6.10; Rancher versions prior to 2.7.1.

- [https://github.com/Live-Hack-CVE/CVE-2022-21953](https://github.com/Live-Hack-CVE/CVE-2022-21953) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-21953.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-21953.svg)


## CVE-2022-21948
 An Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability in paste allows remote attackers to place Javascript into SVG files. This issue affects: openSUSE paste paste version b57b9f87e303a3db9465776e657378e96845493b and prior versions.

- [https://github.com/Live-Hack-CVE/CVE-2022-21948](https://github.com/Live-Hack-CVE/CVE-2022-21948) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-21948.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-21948.svg)


## CVE-2022-4763
 The Icon Widget WordPress plugin before 1.3.0 does not validate and escape some of its shortcode attributes before outputting them back in the page, which could allow users with a role as low as contributor to perform Stored Cross-Site Scripting attacks which could be used against high privilege users such as admins.

- [https://github.com/Live-Hack-CVE/CVE-2022-4763](https://github.com/Live-Hack-CVE/CVE-2022-4763) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4763.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4763.svg)


## CVE-2022-4352
 The Qe SEO Handyman WordPress plugin through 1.0 does not properly sanitize and escape a parameter before using it in a SQL statement, leading to a SQL injection exploitable by high privilege users such as admin

- [https://github.com/Live-Hack-CVE/CVE-2022-4352](https://github.com/Live-Hack-CVE/CVE-2022-4352) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4352.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4352.svg)


## CVE-2022-4285
 An illegal memory access flaw was found in the binutils package. Parsing an ELF file containing corrupt symbol version information may result in a denial of service. This issue is the result of an incomplete fix for CVE-2020-16599.

- [https://github.com/Live-Hack-CVE/CVE-2022-4285](https://github.com/Live-Hack-CVE/CVE-2022-4285) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4285.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4285.svg)


## CVE-2022-4258
 In multiple versions of HIMA PC based Software an unquoted Windows search path vulnerability might allow local users to gain privileges via a malicious .exe file and gain full access to the system.

- [https://github.com/Live-Hack-CVE/CVE-2022-4258](https://github.com/Live-Hack-CVE/CVE-2022-4258) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4258.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4258.svg)


## CVE-2022-4182
 Inappropriate implementation in Fenced Frames in Google Chrome prior to 108.0.5359.71 allowed a remote attacker to bypass fenced frame restrictions via a crafted HTML page. (Chromium security severity: Medium)

- [https://github.com/Live-Hack-CVE/CVE-2022-4182](https://github.com/Live-Hack-CVE/CVE-2022-4182) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4182.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4182.svg)


## CVE-2022-4139
 An incorrect TLB flush issue was found in the Linux kernel&#8217;s GPU i915 kernel driver, potentially leading to random memory corruption or data leaks. This flaw could allow a local user to crash the system or escalate their privileges on the system.

- [https://github.com/Live-Hack-CVE/CVE-2022-4139](https://github.com/Live-Hack-CVE/CVE-2022-4139) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4139.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4139.svg)


## CVE-2022-4034
 The Appointment Hour Booking Plugin for WordPress is vulnerable to CSV Injection in versions up to, and including, 1.3.72. This makes it possible for unauthenticated attackers to embed untrusted input into content during booking creation that may be exported as a CSV file when a site's administrator exports booking details. This can result in code execution when these files are downloaded and opened on a local system with a vulnerable configuration.

- [https://github.com/Live-Hack-CVE/CVE-2022-4034](https://github.com/Live-Hack-CVE/CVE-2022-4034) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4034.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4034.svg)


## CVE-2022-2842
 A vulnerability classified as critical has been found in SourceCodester Gym Management System. This affects an unknown part of the file login.php. The manipulation of the argument user_email leads to sql injection. It is possible to initiate the attack remotely. The exploit has been disclosed to the public and may be used. The associated identifier of this vulnerability is VDB-206451.

- [https://github.com/Live-Hack-CVE/CVE-2022-2842](https://github.com/Live-Hack-CVE/CVE-2022-2842) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2842.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2842.svg)


## CVE-2022-2389
 The Abandoned Cart Recovery for WooCommerce, Follow Up Emails, Newsletter Builder &amp; Marketing Automation By Autonami WordPress plugin before 2.1.2 does not have authorisation and CSRF checks in one of its AJAX action, allowing any authenticated users, such as subscriber to create automations

- [https://github.com/Live-Hack-CVE/CVE-2022-2389](https://github.com/Live-Hack-CVE/CVE-2022-2389) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2389.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2389.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/shiomiyan/CVE-2021-41773](https://github.com/shiomiyan/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/shiomiyan/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/shiomiyan/CVE-2021-41773.svg)
- [https://github.com/puckiestyle/CVE-2021-41773](https://github.com/puckiestyle/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/puckiestyle/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/puckiestyle/CVE-2021-41773.svg)
- [https://github.com/Plunder283/CVE-2021-41773](https://github.com/Plunder283/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/Plunder283/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/Plunder283/CVE-2021-41773.svg)


## CVE-2021-38828
 Xiongmai Camera XM-JPR2-LX V4.02.R12.A6420987.10002.147502.00000 is vulnerable to plain-text traffic sniffing.

- [https://github.com/Live-Hack-CVE/CVE-2021-38828](https://github.com/Live-Hack-CVE/CVE-2021-38828) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-38828.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-38828.svg)


## CVE-2021-37491
 An issue discovered in src/wallet/wallet.cpp in Dogecoin Project Dogecoin Core 1.14.3 and earlier allows attackers to view sensitive information via CWallet::CreateTransaction() function.

- [https://github.com/Live-Hack-CVE/CVE-2021-37491](https://github.com/Live-Hack-CVE/CVE-2021-37491) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-37491.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-37491.svg)


## CVE-2021-36471
 Directory Traversal vulnerability in AdminLTE 3.1.0 allows remote attackers to gain escalated privilege and view sensitive information via /admin/index2.html, /admin/index3.html URIs.

- [https://github.com/Live-Hack-CVE/CVE-2021-36471](https://github.com/Live-Hack-CVE/CVE-2021-36471) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-36471.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-36471.svg)


## CVE-2021-22986
 On BIG-IP versions 16.0.x before 16.0.1.1, 15.1.x before 15.1.2.1, 14.1.x before 14.1.4, 13.1.x before 13.1.3.6, and 12.1.x before 12.1.5.3 amd BIG-IQ 7.1.0.x before 7.1.0.3 and 7.0.0.x before 7.0.0.2, the iControl REST interface has an unauthenticated remote command execution vulnerability. Note: Software versions which have reached End of Software Development (EoSD) are not evaluated.

- [https://github.com/amitlttwo/CVE-2021-22986](https://github.com/amitlttwo/CVE-2021-22986) :  ![starts](https://img.shields.io/github/stars/amitlttwo/CVE-2021-22986.svg) ![forks](https://img.shields.io/github/forks/amitlttwo/CVE-2021-22986.svg)


## CVE-2020-16599
 A Null Pointer Dereference vulnerability exists in the Binary File Descriptor (BFD) library (aka libbfd), as distributed in GNU Binutils 2.35, in _bfd_elf_get_symbol_version_string, as demonstrated in nm-new, that can cause a denial of service via a crafted file.

- [https://github.com/Live-Hack-CVE/CVE-2022-4285](https://github.com/Live-Hack-CVE/CVE-2022-4285) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4285.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4285.svg)


## CVE-2020-7934
 In LifeRay Portal CE 7.1.0 through 7.2.1 GA2, the First Name, Middle Name, and Last Name fields for user accounts in MyAccountPortlet are all vulnerable to a persistent XSS issue. Any user can modify these fields with a particular XSS payload, and it will be stored in the database. The payload will then be rendered when a user utilizes the search feature to search for other users (i.e., if a user with modified fields occurs in the search results). This issue was fixed in Liferay Portal CE version 7.3.0 GA1.

- [https://github.com/3ndG4me/liferay-xss-7.2.1GA2-poc-report-CVE-2020-7934](https://github.com/3ndG4me/liferay-xss-7.2.1GA2-poc-report-CVE-2020-7934) :  ![starts](https://img.shields.io/github/stars/3ndG4me/liferay-xss-7.2.1GA2-poc-report-CVE-2020-7934.svg) ![forks](https://img.shields.io/github/forks/3ndG4me/liferay-xss-7.2.1GA2-poc-report-CVE-2020-7934.svg)


## CVE-2020-6090
 An exploitable code execution vulnerability exists in the Web-Based Management (WBM) functionality of WAGO PFC 200 03.03.10(15). A specially crafted series of HTTP requests can cause code execution resulting in remote code execution. An attacker can make an authenticated HTTP request to trigger this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2020-6090](https://github.com/Live-Hack-CVE/CVE-2020-6090) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-6090.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-6090.svg)


## CVE-2019-5795
 Integer overflow in PDFium in Google Chrome prior to 73.0.3683.75 allowed a remote attacker to potentially perform out of bounds memory access via a crafted PDF file.

- [https://github.com/Live-Hack-CVE/CVE-2019-5795](https://github.com/Live-Hack-CVE/CVE-2019-5795) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-5795.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-5795.svg)


## CVE-2018-14632
 An out of bound write can occur when patching an Openshift object using the 'oc patch' functionality in OpenShift Container Platform before 3.7. An attacker can use this flaw to cause a denial of service attack on the Openshift master api service which provides cluster management.

- [https://github.com/Live-Hack-CVE/CVE-2018-14632](https://github.com/Live-Hack-CVE/CVE-2018-14632) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2018-14632.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2018-14632.svg)


## CVE-2017-18079
 drivers/input/serio/i8042.c in the Linux kernel before 4.12.4 allows attackers to cause a denial of service (NULL pointer dereference and system crash) or possibly have unspecified other impact because the port-&gt;exists value can change after it is validated.

- [https://github.com/Live-Hack-CVE/CVE-2017-18079](https://github.com/Live-Hack-CVE/CVE-2017-18079) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2017-18079.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2017-18079.svg)


## CVE-2017-18075
 crypto/pcrypt.c in the Linux kernel before 4.14.13 mishandles freeing instances, allowing a local user able to access the AF_ALG-based AEAD interface (CONFIG_CRYPTO_USER_API_AEAD) and pcrypt (CONFIG_CRYPTO_PCRYPT) to cause a denial of service (kfree of an incorrect pointer) or possibly have unspecified other impact by executing a crafted sequence of system calls.

- [https://github.com/Live-Hack-CVE/CVE-2017-18075](https://github.com/Live-Hack-CVE/CVE-2017-18075) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2017-18075.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2017-18075.svg)


## CVE-2017-17857
 The check_stack_boundary function in kernel/bpf/verifier.c in the Linux kernel through 4.14.8 allows local users to cause a denial of service (memory corruption) or possibly have unspecified other impact by leveraging mishandling of invalid variable stack read operations.

- [https://github.com/Live-Hack-CVE/CVE-2017-17857](https://github.com/Live-Hack-CVE/CVE-2017-17857) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2017-17857.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2017-17857.svg)


## CVE-2017-17856
 kernel/bpf/verifier.c in the Linux kernel through 4.14.8 allows local users to cause a denial of service (memory corruption) or possibly have unspecified other impact by leveraging the lack of stack-pointer alignment enforcement.

- [https://github.com/Live-Hack-CVE/CVE-2017-17856](https://github.com/Live-Hack-CVE/CVE-2017-17856) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2017-17856.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2017-17856.svg)


## CVE-2017-17855
 kernel/bpf/verifier.c in the Linux kernel through 4.14.8 allows local users to cause a denial of service (memory corruption) or possibly have unspecified other impact by leveraging improper use of pointers in place of scalars.

- [https://github.com/Live-Hack-CVE/CVE-2017-17855](https://github.com/Live-Hack-CVE/CVE-2017-17855) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2017-17855.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2017-17855.svg)


## CVE-2017-17854
 kernel/bpf/verifier.c in the Linux kernel through 4.14.8 allows local users to cause a denial of service (integer overflow and memory corruption) or possibly have unspecified other impact by leveraging unrestricted integer values for pointer arithmetic.

- [https://github.com/Live-Hack-CVE/CVE-2017-17854](https://github.com/Live-Hack-CVE/CVE-2017-17854) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2017-17854.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2017-17854.svg)


## CVE-2016-5195
 Race condition in mm/gup.c in the Linux kernel 2.x through 4.x before 4.8.3 allows local users to gain privileges by leveraging incorrect handling of a copy-on-write (COW) feature to write to a read-only memory mapping, as exploited in the wild in October 2016, aka &quot;Dirty COW.&quot;

- [https://github.com/guy-davidi/DirtyCow](https://github.com/guy-davidi/DirtyCow) :  ![starts](https://img.shields.io/github/stars/guy-davidi/DirtyCow.svg) ![forks](https://img.shields.io/github/forks/guy-davidi/DirtyCow.svg)

