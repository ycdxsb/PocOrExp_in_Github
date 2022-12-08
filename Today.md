# Update 2022-12-08
## CVE-2022-33891
 The Apache Spark UI offers the possibility to enable ACLs via the configuration option spark.acls.enable. With an authentication filter, this checks whether a user has access permissions to view or modify the application. If ACLs are enabled, a code path in HttpSecurityFilter can allow someone to perform impersonation by providing an arbitrary user name. A malicious user might then be able to reach a permission check function that will ultimately build a Unix shell command based on their input, and execute it. This will result in arbitrary shell command execution as the user Spark is currently running as. This affects Apache Spark versions 3.0.3 and earlier, versions 3.1.1 to 3.1.2, and versions 3.2.0 to 3.2.1.

- [https://github.com/ps-interactive/lab_security_apache_spark_emulation_detection](https://github.com/ps-interactive/lab_security_apache_spark_emulation_detection) :  ![starts](https://img.shields.io/github/stars/ps-interactive/lab_security_apache_spark_emulation_detection.svg) ![forks](https://img.shields.io/github/forks/ps-interactive/lab_security_apache_spark_emulation_detection.svg)


## CVE-2022-31626
 In PHP versions 7.4.x below 7.4.30, 8.0.x below 8.0.20, and 8.1.x below 8.1.7, when pdo_mysql extension with mysqlnd driver, if the third party is allowed to supply host to connect to and the password for the connection, password of excessive length can trigger a buffer overflow in PHP, which can lead to a remote code execution vulnerability.

- [https://github.com/amitlttwo/CVE-2022-31626](https://github.com/amitlttwo/CVE-2022-31626) :  ![starts](https://img.shields.io/github/stars/amitlttwo/CVE-2022-31626.svg) ![forks](https://img.shields.io/github/forks/amitlttwo/CVE-2022-31626.svg)


## CVE-2022-2414
 Access to external entities when parsing XML documents can lead to XML external entity (XXE) attacks. This flaw allows a remote attacker to potentially retrieve the content of arbitrary files by sending specially crafted HTTP requests.

- [https://github.com/amitlttwo/CVE-2022-2414-Proof-Of-Concept](https://github.com/amitlttwo/CVE-2022-2414-Proof-Of-Concept) :  ![starts](https://img.shields.io/github/stars/amitlttwo/CVE-2022-2414-Proof-Of-Concept.svg) ![forks](https://img.shields.io/github/forks/amitlttwo/CVE-2022-2414-Proof-Of-Concept.svg)


## CVE-2022-1388
 On F5 BIG-IP 16.1.x versions prior to 16.1.2.2, 15.1.x versions prior to 15.1.5.1, 14.1.x versions prior to 14.1.4.6, 13.1.x versions prior to 13.1.5, and all 12.1.x and 11.6.x versions, undisclosed requests may bypass iControl REST authentication. Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated

- [https://github.com/amitlttwo/CVE-2022-1388](https://github.com/amitlttwo/CVE-2022-1388) :  ![starts](https://img.shields.io/github/stars/amitlttwo/CVE-2022-1388.svg) ![forks](https://img.shields.io/github/forks/amitlttwo/CVE-2022-1388.svg)


## CVE-2022-1111
 A business logic error in Project Import in GitLab CE/EE versions 14.9 prior to 14.9.2, 14.8 prior to 14.8.5, and 14.0 prior to 14.7.7 under certain conditions caused imported projects to show an incorrect user in the 'Access Granted' column in the project membership pages

- [https://github.com/sdfbjaksff/CVE-2022-11111111](https://github.com/sdfbjaksff/CVE-2022-11111111) :  ![starts](https://img.shields.io/github/stars/sdfbjaksff/CVE-2022-11111111.svg) ![forks](https://img.shields.io/github/forks/sdfbjaksff/CVE-2022-11111111.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/sixpacksecurity/CVE-2021-41773](https://github.com/sixpacksecurity/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/sixpacksecurity/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/sixpacksecurity/CVE-2021-41773.svg)
- [https://github.com/xMohamed0/CVE-2021-41773](https://github.com/xMohamed0/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/xMohamed0/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/xMohamed0/CVE-2021-41773.svg)
- [https://github.com/DoTuan1/Reserch-CVE-2021-41773](https://github.com/DoTuan1/Reserch-CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/DoTuan1/Reserch-CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/DoTuan1/Reserch-CVE-2021-41773.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/Sakura-nee/CVE-2021-4034](https://github.com/Sakura-nee/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/Sakura-nee/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/Sakura-nee/CVE-2021-4034.svg)


## CVE-2021-3138
 In Discourse 2.7.0 through beta1, a rate-limit bypass leads to a bypass of the 2FA requirement for certain forms.

- [https://github.com/Mesh3l911/CVE-2021-3138](https://github.com/Mesh3l911/CVE-2021-3138) :  ![starts](https://img.shields.io/github/stars/Mesh3l911/CVE-2021-3138.svg) ![forks](https://img.shields.io/github/forks/Mesh3l911/CVE-2021-3138.svg)


## CVE-2019-9745
 CloudCTI HIP Integrator Recognition Configuration Tool allows privilege escalation via its EXQUISE integration. This tool communicates with a service (Recognition Update Client Service) via an insecure communication channel (Named Pipe). The data (JSON) sent via this channel is used to import data from CRM software using plugins (.dll files). The plugin to import data from the EXQUISE software (DatasourceExquiseExporter.dll) can be persuaded to start arbitrary programs (including batch files) that are executed using the same privileges as Recognition Update Client Service (NT AUTHORITY\SYSTEM), thus elevating privileges. This occurs because a higher-privileged process executes scripts from a directory writable by a lower-privileged user.

- [https://github.com/KPN-CISO/CVE-2019-9745](https://github.com/KPN-CISO/CVE-2019-9745) :  ![starts](https://img.shields.io/github/stars/KPN-CISO/CVE-2019-9745.svg) ![forks](https://img.shields.io/github/forks/KPN-CISO/CVE-2019-9745.svg)


## CVE-2018-11776
 Apache Struts versions 2.3 to 2.3.34 and 2.5 to 2.5.16 suffer from possible Remote Code Execution when alwaysSelectFullNamespace is true (either by user or a plugin like Convention Plugin) and then: results are used with no namespace and in same time, its upper package have no or wildcard namespace and similar to results, same possibility when using url tag which doesn't have value and action set and in same time, its upper package have no or wildcard namespace.

- [https://github.com/showerlemon/Apache-Struts-0Day-Exploit](https://github.com/showerlemon/Apache-Struts-0Day-Exploit) :  ![starts](https://img.shields.io/github/stars/showerlemon/Apache-Struts-0Day-Exploit.svg) ![forks](https://img.shields.io/github/forks/showerlemon/Apache-Struts-0Day-Exploit.svg)


## CVE-2018-7422
 A Local File Inclusion vulnerability in the Site Editor plugin through 1.1.1 for WordPress allows remote attackers to retrieve arbitrary files via the ajax_path parameter to editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php, aka absolute path traversal.

- [https://github.com/JacobEbben/CVE-2018-7422](https://github.com/JacobEbben/CVE-2018-7422) :  ![starts](https://img.shields.io/github/stars/JacobEbben/CVE-2018-7422.svg) ![forks](https://img.shields.io/github/forks/JacobEbben/CVE-2018-7422.svg)


## CVE-2017-9841
 Util/PHP/eval-stdin.php in PHPUnit before 4.8.28 and 5.x before 5.6.3 allows remote attackers to execute arbitrary PHP code via HTTP POST data beginning with a &quot;&lt;?php &quot; substring, as demonstrated by an attack on a site with an exposed /vendor folder, i.e., external access to the /vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php URI.

- [https://github.com/MadExploits/PHPunit-Exploit](https://github.com/MadExploits/PHPunit-Exploit) :  ![starts](https://img.shields.io/github/stars/MadExploits/PHPunit-Exploit.svg) ![forks](https://img.shields.io/github/forks/MadExploits/PHPunit-Exploit.svg)

