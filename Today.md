# Update 2023-01-08
## CVE-2023-22671
 Ghidra/RuntimeScripts/Linux/support/launch.sh in NSA Ghidra through 10.2.2 passes user-provided input into eval, leading to command injection when calling analyzeHeadless with untrusted input.

- [https://github.com/Live-Hack-CVE/CVE-2023-22671](https://github.com/Live-Hack-CVE/CVE-2023-22671) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22671.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22671.svg)


## CVE-2023-22475
 Canarytokens is an open source tool which helps track activity and actions on your network. A Cross-Site Scripting vulnerability was identified in the history page of triggered Canarytokens prior to sha-fb61290. An attacker who discovers an HTTP-based Canarytoken (a URL) can use this to execute Javascript in the Canarytoken's trigger history page (domain: canarytokens.org) when the history page is later visited by the Canarytoken's creator. This vulnerability could be used to disable or delete the affected Canarytoken, or view its activation history. It might also be used as a stepping stone towards revealing more information about the Canarytoken's creator to the attacker. For example, an attacker could recover the email address tied to the Canarytoken, or place Javascript on the history page that redirect the creator towards an attacker-controlled Canarytoken to show the creator's network location. This vulnerability is similar to CVE-2022-31113, but affected parameters reported differently from the Canarytoken trigger request. An attacker could only act on the discovered Canarytoken. This issue did not expose other Canarytokens or other Canarytoken creators. Canarytokens Docker images sha-fb61290 and later contain a patch for this issue.

- [https://github.com/Live-Hack-CVE/CVE-2023-22475](https://github.com/Live-Hack-CVE/CVE-2023-22475) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22475.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22475.svg)


## CVE-2023-0028
 Cross-site Scripting (XSS) - Stored in GitHub repository linagora/twake prior to 2023.Q1.1200+.

- [https://github.com/Live-Hack-CVE/CVE-2023-0028](https://github.com/Live-Hack-CVE/CVE-2023-0028) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0028.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0028.svg)


## CVE-2022-46172
 authentik is an open-source Identity provider focused on flexibility and versatility. In versions prior to 2022.10.4, and 2022.11.4, any authenticated user can create an arbitrary number of accounts through the default flows. This would circumvent any policy in a situation where it is undesirable for users to create new accounts by themselves. This may also affect other applications as these new basic accounts would exist throughout the SSO infrastructure. By default the newly created accounts cannot be logged into as no password reset exists by default. However password resets are likely to be enabled by most installations. This vulnerability pertains to the user context used in the default-user-settings-flow, /api/v3/flows/instances/default-user-settings-flow/execute/. This issue has been fixed in versions 2022.10.4 and 2022.11.4.

- [https://github.com/Live-Hack-CVE/CVE-2022-46172](https://github.com/Live-Hack-CVE/CVE-2022-46172) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-46172.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-46172.svg)


## CVE-2022-45935
 Usage of temporary files with insecure permissions by the Apache James server allows an attacker with local access to access private user data in transit. Vulnerable components includes the SMTP stack and IMAP APPEND command. This issue affects Apache James server version 3.7.2 and prior versions.

- [https://github.com/Live-Hack-CVE/CVE-2022-45935](https://github.com/Live-Hack-CVE/CVE-2022-45935) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-45935.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-45935.svg)


## CVE-2022-45913
 An issue was discovered in Zimbra Collaboration (ZCS) 9.0. XSS can occur via one of attributes in webmail URLs to execute arbitrary JavaScript code, leading to information disclosure.

- [https://github.com/Live-Hack-CVE/CVE-2022-45913](https://github.com/Live-Hack-CVE/CVE-2022-45913) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-45913.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-45913.svg)


## CVE-2022-45911
 An issue was discovered in Zimbra Collaboration (ZCS) 9.0. XSS can occur on the Classic UI login page by injecting arbitrary JavaScript code in the username field. This occurs before the user logs into the system, which means that even if the attacker executes arbitrary JavaScript, they will not get any sensitive information.

- [https://github.com/Live-Hack-CVE/CVE-2022-45911](https://github.com/Live-Hack-CVE/CVE-2022-45911) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-45911.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-45911.svg)


## CVE-2022-45787
 Unproper laxist permissions on the temporary files used by MIME4J TempFileStorageProvider may lead to information disclosure to other local users. This issue affects Apache James MIME4J version 0.8.8 and prior versions. We recommend users to upgrade to MIME4j version 0.8.9 or later.

- [https://github.com/Live-Hack-CVE/CVE-2022-45787](https://github.com/Live-Hack-CVE/CVE-2022-45787) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-45787.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-45787.svg)


## CVE-2022-44939
 Efs Software Easy Chat Server Version 3.1 was discovered to contain a DLL hijacking vulnerability via the component TextShaping.dll. This vulnerability allows attackers to execute arbitrary code via a crafted DLL.

- [https://github.com/Live-Hack-CVE/CVE-2022-44939](https://github.com/Live-Hack-CVE/CVE-2022-44939) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-44939.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-44939.svg)


## CVE-2022-44877
 RESERVED An issue in the /login/index.php component of Centos Web Panel 7 before v0.9.8.1147 allows unauthenticated attackers to execute arbitrary system commands via crafted HTTP requests.

- [https://github.com/komomon/CVE-2022-44877-RCE](https://github.com/komomon/CVE-2022-44877-RCE) :  ![starts](https://img.shields.io/github/stars/komomon/CVE-2022-44877-RCE.svg) ![forks](https://img.shields.io/github/forks/komomon/CVE-2022-44877-RCE.svg)


## CVE-2022-44149
 The web service on Nexxt Amp300 ARN02304U8 42.103.1.5095 devices allows remote OS command execution by placing &amp;telnetd in the JSON host field to the ping feature of the goform/sysTools component. Authentication is required.

- [https://github.com/Live-Hack-CVE/CVE-2022-44149](https://github.com/Live-Hack-CVE/CVE-2022-44149) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-44149.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-44149.svg)
- [https://github.com/yerodin/CVE-2022-44149](https://github.com/yerodin/CVE-2022-44149) :  ![starts](https://img.shields.io/github/stars/yerodin/CVE-2022-44149.svg) ![forks](https://img.shields.io/github/forks/yerodin/CVE-2022-44149.svg)


## CVE-2022-42256
 NVIDIA GPU Display Driver for Linux contains a vulnerability in the kernel mode layer (nvidia.ko), where an integer overflow in index validation may lead to denial of service, information disclosure, or data tampering.

- [https://github.com/Live-Hack-CVE/CVE-2022-42256](https://github.com/Live-Hack-CVE/CVE-2022-42256) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-42256.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-42256.svg)


## CVE-2022-42255
 NVIDIA GPU Display Driver for Linux contains a vulnerability in the kernel mode layer (nvidia.ko), where an out-of-bounds array access may lead to denial of service, information disclosure, or data tampering.

- [https://github.com/Live-Hack-CVE/CVE-2022-42255](https://github.com/Live-Hack-CVE/CVE-2022-42255) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-42255.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-42255.svg)


## CVE-2022-41967
 Dragonfly is a Java runtime dependency management library. Dragonfly v0.3.0-SNAPSHOT does not configure DocumentBuilderFactory to prevent XML external entity (XXE) attacks. This issue is patched in 0.3.1-SNAPSHOT. As a workaround, since Dragonfly only parses XML `SNAPSHOT` versions are being resolved, this vulnerability may be avoided by not trying to resolve `SNAPSHOT` versions.

- [https://github.com/Live-Hack-CVE/CVE-2022-41967](https://github.com/Live-Hack-CVE/CVE-2022-41967) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-41967.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-41967.svg)


## CVE-2022-41966
 XStream serializes Java objects to XML and back again. Versions prior to 1.4.20 may allow a remote attacker to terminate the application with a stack overflow error, resulting in a denial of service only via manipulation the processed input stream. The attack uses the hash code implementation for collections and maps to force recursive hash calculation causing a stack overflow. This issue is patched in version 1.4.20 which handles the stack overflow and raises an InputManipulationException instead. A potential workaround for users who only use HashMap or HashSet and whose XML refers these only as default map or set, is to change the default implementation of java.util.Map and java.util per the code example in the referenced advisory. However, this implies that your application does not care about the implementation of the map and all elements are comparable.

- [https://github.com/Live-Hack-CVE/CVE-2022-41966](https://github.com/Live-Hack-CVE/CVE-2022-41966) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-41966.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-41966.svg)


## CVE-2022-41613
 Bentley Systems MicroStation Connect versions 10.17.0.209 and prior are vulnerable to an Out-of-Bounds Read when when parsing DGN files, which may allow an attacker to crash the product, disclose sensitive information, or execute arbitrary code.

- [https://github.com/Live-Hack-CVE/CVE-2022-41613](https://github.com/Live-Hack-CVE/CVE-2022-41613) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-41613.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-41613.svg)


## CVE-2022-40201
 Bentley Systems MicroStation Connect versions 10.17.0.209 and prior are vulnerable to a Stack-Based Buffer Overflow when a malformed design (DGN) file is parsed. This may allow an attacker to execute arbitrary code.

- [https://github.com/Live-Hack-CVE/CVE-2022-40201](https://github.com/Live-Hack-CVE/CVE-2022-40201) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-40201.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-40201.svg)


## CVE-2022-36678
 Simple Task Scheduling System v1.0 was discovered to contain a SQL injection vulnerability via the id parameter at /classes/Master.php?f=delete_category.

- [https://github.com/Live-Hack-CVE/CVE-2022-36678](https://github.com/Live-Hack-CVE/CVE-2022-36678) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36678.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36678.svg)


## CVE-2022-34683
 NVIDIA GPU Display Driver for Windows contains a vulnerability in the kernel mode layer (nvlddmkm.sys) handler for DxgkDdiEscape, where a null-pointer dereference occurs, which may lead to denial of service.

- [https://github.com/Live-Hack-CVE/CVE-2022-34683](https://github.com/Live-Hack-CVE/CVE-2022-34683) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-34683.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-34683.svg)


## CVE-2022-34682
 NVIDIA GPU Display Driver for Linux contains a vulnerability in the kernel mode layer, where an unprivileged regular user can cause a null-pointer dereference, which may lead to denial of service.

- [https://github.com/Live-Hack-CVE/CVE-2022-34682](https://github.com/Live-Hack-CVE/CVE-2022-34682) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-34682.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-34682.svg)


## CVE-2022-34681
 NVIDIA GPU Display Driver for Windows contains a vulnerability in the kernel mode layer (nvlddmkm.sys) handler, where improper input validation of a display-related data structure may lead to denial of service.

- [https://github.com/Live-Hack-CVE/CVE-2022-34681](https://github.com/Live-Hack-CVE/CVE-2022-34681) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-34681.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-34681.svg)


## CVE-2022-34679
 NVIDIA GPU Display Driver for Linux contains a vulnerability in the kernel mode layer handler, where an unhandled return value can lead to a null-pointer dereference, which may lead to denial of service.

- [https://github.com/Live-Hack-CVE/CVE-2022-34679](https://github.com/Live-Hack-CVE/CVE-2022-34679) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-34679.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-34679.svg)


## CVE-2022-25923
 Versions of the package exec-local-bin before 1.2.0 are vulnerable to Command Injection via the theProcess() functionality due to improper user-input sanitization.

- [https://github.com/Live-Hack-CVE/CVE-2022-25923](https://github.com/Live-Hack-CVE/CVE-2022-25923) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-25923.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-25923.svg)


## CVE-2022-23555
 authentik is an open-source Identity Provider focused on flexibility and versatility. Versions prior to 2022.11.4 and 2022.10.4 are vulnerable to Improper Authentication. Token reuse in invitation URLs leads to access control bypass via the use of a different enrollment flow than in the one provided. The vulnerability allows an attacker that knows different invitation flows names (e.g. `enrollment-invitation-test` and `enrollment-invitation-admin`) via either different invite links or via brute forcing to signup via a single invitation url for any valid invite link received (it can even be a url for a third flow as long as it's a valid invite) as the token used in the `Invitations` section of the Admin interface does NOT change when a different `enrollment flow` is selected via the interface and it is NOT bound to the selected flow, so it will be valid for any flow when used. This issue is patched in authentik 2022.11.4,2022.10.4 and 2022.12.0. Only configurations that use invitations and have multiple enrollment flows with invitation stages that grant different permissions are affected. The default configuration is not vulnerable, and neither are configurations with a single enrollment flow. As a workaround, fixed data can be added to invitations which can be checked in the flow to deny requests. Alternatively, an identifier with high entropy (like a UUID) can be used as flow slug, mitigating the attack vector by exponentially decreasing the possibility of discovering other flows.

- [https://github.com/Live-Hack-CVE/CVE-2022-23555](https://github.com/Live-Hack-CVE/CVE-2022-23555) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-23555.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-23555.svg)


## CVE-2022-20867
 A vulnerability in web-based management interface of the of Cisco Email Security Appliance and Cisco Secure Email and Web Manager could allow an authenticated, remote attacker to conduct SQL injection attacks as root on an affected system. The attacker must have the credentials of a high-privileged user account. This vulnerability is due to improper validation of user-submitted parameters. An attacker could exploit this vulnerability by authenticating to the application and sending malicious requests to an affected system. A successful exploit could allow the attacker to obtain data or modify data that is stored in the underlying database of the affected system.

- [https://github.com/Live-Hack-CVE/CVE-2022-20867](https://github.com/Live-Hack-CVE/CVE-2022-20867) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-20867.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-20867.svg)


## CVE-2022-4879
 A vulnerability was found in Forged Alliance Forever up to 3746. It has been declared as critical. Affected by this vulnerability is an unknown functionality of the component Vote Handler. The manipulation leads to improper authorization. Upgrading to version 3747 is able to address this issue. The name of the patch is 6880971bd3d73d942384aff62d53058c206ce644. It is recommended to upgrade the affected component. The associated identifier of this vulnerability is VDB-217555.

- [https://github.com/Live-Hack-CVE/CVE-2022-4879](https://github.com/Live-Hack-CVE/CVE-2022-4879) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4879.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4879.svg)


## CVE-2022-4878
 A vulnerability classified as critical has been found in JATOS. Affected is the function ZipUtil of the file modules/common/app/utils/common/ZipUtil.java of the component ZIP Handler. The manipulation leads to path traversal. Upgrading to version 3.7.5-alpha is able to address this issue. The name of the patch is 2b42519f309d8164e8811392770ce604cdabb5da. It is recommended to upgrade the affected component. The identifier of this vulnerability is VDB-217548.

- [https://github.com/Live-Hack-CVE/CVE-2022-4878](https://github.com/Live-Hack-CVE/CVE-2022-4878) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4878.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4878.svg)


## CVE-2022-4861
 Incorrect implementation in authentication protocol in M-Files Client before 22.5.11356.0 allows high privileged user to get other users tokens to another resource.

- [https://github.com/Live-Hack-CVE/CVE-2022-4861](https://github.com/Live-Hack-CVE/CVE-2022-4861) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4861.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4861.svg)


## CVE-2022-4860
 A vulnerability was found in KBase Metrics. It has been classified as critical. This affects the function upload_user_data of the file source/daily_cron_jobs/methods_upload_user_stats.py. The manipulation leads to sql injection. The name of the patch is 959dfb6b05991e30b0fa972a1ecdcaae8e1dae6d. It is recommended to apply a patch to fix this issue. The associated identifier of this vulnerability is VDB-217059.

- [https://github.com/Live-Hack-CVE/CVE-2022-4860](https://github.com/Live-Hack-CVE/CVE-2022-4860) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4860.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4860.svg)


## CVE-2022-4858
 Insertion of Sensitive Information into Log Files in M-Files Server before 22.10.11846.0 could allow to obtain sensitive tokens from logs, if specific configurations were set.

- [https://github.com/Live-Hack-CVE/CVE-2022-4858](https://github.com/Live-Hack-CVE/CVE-2022-4858) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4858.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4858.svg)


## CVE-2022-4823
 A vulnerability, which was classified as problematic, was found in InSTEDD Nuntium. Affected is an unknown function of the file app/controllers/geopoll_controller.rb. The manipulation of the argument signature leads to observable timing discrepancy. It is possible to launch the attack remotely. The name of the patch is 77236f7fd71a0e2eefeea07f9866b069d612cf0d. It is recommended to apply a patch to fix this issue. VDB-217002 is the identifier assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2022-4823](https://github.com/Live-Hack-CVE/CVE-2022-4823) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4823.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4823.svg)


## CVE-2022-4817
 A vulnerability was found in centic9 jgit-cookbook. It has been declared as problematic. This vulnerability affects unknown code. The manipulation leads to insecure temporary file. The attack can be initiated remotely. The name of the patch is b8cb29b43dc704708d598c60ac1881db7cf8e9c3. It is recommended to apply a patch to fix this issue. The identifier of this vulnerability is VDB-216988.

- [https://github.com/Live-Hack-CVE/CVE-2022-4817](https://github.com/Live-Hack-CVE/CVE-2022-4817) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4817.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4817.svg)


## CVE-2022-4779
 StreamX applications from versions 6.02.01 to 6.04.34 are affected by a logic bug that allows to bypass the implemented authentication scheme. StreamX applications using StreamView HTML component with the public web server feature activated are affected.

- [https://github.com/Live-Hack-CVE/CVE-2022-4779](https://github.com/Live-Hack-CVE/CVE-2022-4779) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4779.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4779.svg)


## CVE-2022-4778
 StreamX applications from versions 6.02.01 to 6.04.34 are affected by a path traversal vulnerability that allows authenticated users to get unauthorized access to files on the server's filesystem. StreamX applications using StreamView HTML component with the public web server feature activated are affected.

- [https://github.com/Live-Hack-CVE/CVE-2022-4778](https://github.com/Live-Hack-CVE/CVE-2022-4778) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4778.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4778.svg)


## CVE-2022-4773
 ** UNSUPPORTED WHEN ASSIGNED ** A vulnerability classified as problematic was found in cloudsync. Affected by this vulnerability is the function getItem of the file src/main/java/cloudsync/connector/LocalFilesystemConnector.java. The manipulation leads to path traversal. It is possible to launch the attack on the local host. The name of the patch is 3ad796833398af257c28e0ebeade68518e0e612a. It is recommended to apply a patch to fix this issue. The associated identifier of this vulnerability is VDB-216919. NOTE: This vulnerability only affects products that are no longer supported by the maintainer.

- [https://github.com/Live-Hack-CVE/CVE-2022-4773](https://github.com/Live-Hack-CVE/CVE-2022-4773) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4773.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4773.svg)


## CVE-2022-4766
 A vulnerability was found in dolibarr_project_timesheet up to 4.5.5. It has been declared as problematic. This vulnerability affects unknown code of the component Form Handler. The manipulation leads to cross-site request forgery. The attack can be initiated remotely. Upgrading to version 4.5.6.a is able to address this issue. The name of the patch is 082282e9dab43963e6c8f03cfaddd7921de377f4. It is recommended to upgrade the affected component. The identifier of this vulnerability is VDB-216880.

- [https://github.com/Live-Hack-CVE/CVE-2022-4766](https://github.com/Live-Hack-CVE/CVE-2022-4766) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4766.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4766.svg)


## CVE-2022-3577
 An out-of-bounds memory write flaw was found in the Linux kernel&#8217;s Kid-friendly Wired Controller driver. This flaw allows a local user to crash or potentially escalate their privileges on the system. It is in bigben_probe of drivers/hid/hid-bigbenff.c. The reason is incorrect assumption - bigben devices all have inputs. However, malicious devices can break this assumption, leaking to out-of-bound write.

- [https://github.com/Live-Hack-CVE/CVE-2022-3577](https://github.com/Live-Hack-CVE/CVE-2022-3577) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-3577.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-3577.svg)


## CVE-2022-3376
 Weak Password Requirements in GitHub repository ikus060/rdiffweb prior to 2.5.0a4.

- [https://github.com/Live-Hack-CVE/CVE-2022-3376](https://github.com/Live-Hack-CVE/CVE-2022-3376) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-3376.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-3376.svg)


## CVE-2022-3156
 A remote code execution vulnerability exists in Rockwell Automation Studio 5000 Logix Emulate software. Users are granted elevated permissions on certain product services when the software is installed. Due to this misconfiguration, a malicious user could potentially achieve remote code execution on the targeted software.

- [https://github.com/Live-Hack-CVE/CVE-2022-3156](https://github.com/Live-Hack-CVE/CVE-2022-3156) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-3156.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-3156.svg)


## CVE-2022-2484
 The signature check in the Nokia ASIK AirScale system module version 474021A.101 can be bypassed allowing an attacker to run modified firmware. This could result in the execution of a malicious kernel, arbitrary programs, or modified Nokia programs.

- [https://github.com/Live-Hack-CVE/CVE-2022-2484](https://github.com/Live-Hack-CVE/CVE-2022-2484) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2484.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2484.svg)


## CVE-2022-2483
 The bootloader in the Nokia ASIK AirScale system module (versions 474021A.101 and 474021A.102) loads public keys for firmware verification signature. If an attacker modifies the flash contents to corrupt the keys, secure boot could be permanently disabled on a given device.

- [https://github.com/Live-Hack-CVE/CVE-2022-2483](https://github.com/Live-Hack-CVE/CVE-2022-2483) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2483.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2483.svg)


## CVE-2022-2482
 A vulnerability exists in Nokia&#8217;s ASIK AirScale system module (versions 474021A.101 and 474021A.102) that could allow an attacker to place a script on the file system accessible from Linux. A script placed in the appropriate place could allow for arbitrary code execution in the bootloader.

- [https://github.com/Live-Hack-CVE/CVE-2022-2482](https://github.com/Live-Hack-CVE/CVE-2022-2482) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2482.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2482.svg)


## CVE-2022-0739
 The BookingPress WordPress plugin before 1.0.11 fails to properly sanitize user supplied POST data before it is used in a dynamically constructed SQL query via the bookingpress_front_get_category_services AJAX action (available to unauthenticated users), leading to an unauthenticated SQL Injection

- [https://github.com/viardant/CVE-2022-0739](https://github.com/viardant/CVE-2022-0739) :  ![starts](https://img.shields.io/github/stars/viardant/CVE-2022-0739.svg) ![forks](https://img.shields.io/github/forks/viardant/CVE-2022-0739.svg)


## CVE-2021-38003
 Inappropriate implementation in V8 in Google Chrome prior to 95.0.4638.69 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

- [https://github.com/SpiralBL0CK/Chrome-V8-RCE-CVE-2021-38003](https://github.com/SpiralBL0CK/Chrome-V8-RCE-CVE-2021-38003) :  ![starts](https://img.shields.io/github/stars/SpiralBL0CK/Chrome-V8-RCE-CVE-2021-38003.svg) ![forks](https://img.shields.io/github/forks/SpiralBL0CK/Chrome-V8-RCE-CVE-2021-38003.svg)


## CVE-2021-21551
 Dell dbutil_2_3.sys driver contains an insufficient access control vulnerability which may lead to escalation of privileges, denial of service, or information disclosure. Local authenticated user access is required.

- [https://github.com/nanabingies/CVE-2021-21551](https://github.com/nanabingies/CVE-2021-21551) :  ![starts](https://img.shields.io/github/stars/nanabingies/CVE-2021-21551.svg) ![forks](https://img.shields.io/github/forks/nanabingies/CVE-2021-21551.svg)


## CVE-2021-4296
 A vulnerability, which was classified as problematic, has been found in w3c Unicorn. This issue affects the function ValidatorNuMessage of the file src/org/w3c/unicorn/response/impl/ValidatorNuMessage.java. The manipulation of the argument message leads to cross site scripting. The attack may be initiated remotely. The name of the patch is 51f75c31f7fc33859a9a571311c67ae4e95d9c68. It is recommended to apply a patch to fix this issue. The associated identifier of this vulnerability is VDB-217019.

- [https://github.com/Live-Hack-CVE/CVE-2021-4296](https://github.com/Live-Hack-CVE/CVE-2021-4296) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-4296.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-4296.svg)


## CVE-2021-4295
 A vulnerability classified as problematic was found in ONC code-validator-api up to 1.0.30. This vulnerability affects the function vocabularyValidationConfigurations of the file src/main/java/org/sitenv/vocabularies/configuration/CodeValidatorApiConfiguration.java of the component XML Handler. The manipulation leads to xml external entity reference. Upgrading to version 1.0.31 is able to address this issue. The name of the patch is fbd8ea121755a2d3d116b13f235bc8b61d8449af. It is recommended to upgrade the affected component. VDB-217018 is the identifier assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2021-4295](https://github.com/Live-Hack-CVE/CVE-2021-4295) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-4295.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-4295.svg)


## CVE-2021-4294
 A vulnerability was found in OpenShift OSIN. It has been classified as problematic. This affects the function ClientSecretMatches/CheckClientSecret. The manipulation of the argument secret leads to observable timing discrepancy. The name of the patch is 8612686d6dda34ae9ef6b5a974e4b7accb4fea29. It is recommended to apply a patch to fix this issue. The associated identifier of this vulnerability is VDB-216987.

- [https://github.com/Live-Hack-CVE/CVE-2021-4294](https://github.com/Live-Hack-CVE/CVE-2021-4294) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-4294.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-4294.svg)


## CVE-2021-4289
 A vulnerability classified as problematic was found in OpenMRS openmrs-module-referenceapplication up to 2.11.x. Affected by this vulnerability is the function post of the file omod/src/main/java/org/openmrs/module/referenceapplication/page/controller/UserAppPageController.java of the component User App Page. The manipulation of the argument AppId leads to cross site scripting. The attack can be launched remotely. Upgrading to version 2.12.0 is able to address this issue. The name of the patch is 0410c091d46eed3c132fe0fcafe5964182659f74. It is recommended to upgrade the affected component. The associated identifier of this vulnerability is VDB-216883.

- [https://github.com/Live-Hack-CVE/CVE-2021-4289](https://github.com/Live-Hack-CVE/CVE-2021-4289) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-4289.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-4289.svg)


## CVE-2021-4288
 A vulnerability was found in OpenMRS openmrs-module-referenceapplication up to 2.11.x. It has been rated as problematic. This issue affects some unknown processing of the file omod/src/main/webapp/pages/userApp.gsp. The manipulation leads to cross site scripting. The attack may be initiated remotely. Upgrading to version 2.12.0 is able to address this issue. The name of the patch is 35f81901a4cb925747a9615b8706f5079d2196a1. It is recommended to upgrade the affected component. The identifier VDB-216881 was assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2021-4288](https://github.com/Live-Hack-CVE/CVE-2021-4288) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-4288.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-4288.svg)


## CVE-2021-3532
 A flaw was found in Ansible where the secret information present in async_files are getting disclosed when the user changes the jobdir to a world readable directory. Any secret information in an async status file will be readable by a malicious user on that system. This flaw affects Ansible Tower 3.7 and Ansible Automation Platform 1.2.

- [https://github.com/Live-Hack-CVE/CVE-2021-3532](https://github.com/Live-Hack-CVE/CVE-2021-3532) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-3532.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-3532.svg)


## CVE-2020-36644
 A vulnerability has been found in jamesmartin Inline SVG up to 1.7.1 and classified as problematic. Affected by this vulnerability is an unknown functionality of the file lib/inline_svg/action_view/helpers.rb of the component URL Parameter Handler. The manipulation of the argument filename leads to cross site scripting. The attack can be launched remotely. Upgrading to version 1.7.2 is able to address this issue. The name of the patch is f5363b351508486021f99e083c92068cf2943621. It is recommended to upgrade the affected component. The identifier VDB-217597 was assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2020-36644](https://github.com/Live-Hack-CVE/CVE-2020-36644) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-36644.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-36644.svg)


## CVE-2020-36643
 A vulnerability was found in intgr uqm-wasm. It has been classified as critical. This affects the function log_displayBox in the library sc2/src/libs/log/msgbox_macosx.m. The manipulation leads to format string. The name of the patch is 1d5cbf3350a02c423ad6bef6dfd5300d38aa828f. It is recommended to apply a patch to fix this issue. The associated identifier of this vulnerability is VDB-217563.

- [https://github.com/Live-Hack-CVE/CVE-2020-36643](https://github.com/Live-Hack-CVE/CVE-2020-36643) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-36643.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-36643.svg)


## CVE-2020-36642
 A vulnerability was found in trampgeek jobe up to 1.6.x and classified as critical. This issue affects the function run_in_sandbox of the file application/libraries/LanguageTask.php. The manipulation leads to command injection. Upgrading to version 1.7.0 is able to address this issue. The name of the patch is 8f43daf50c943b98eaf0c542da901a4a16e85b02. It is recommended to upgrade the affected component. The identifier VDB-217553 was assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2020-36642](https://github.com/Live-Hack-CVE/CVE-2020-36642) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-36642.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-36642.svg)


## CVE-2020-36638
 ** UNSUPPORTED WHEN ASSIGNED ** A vulnerability was found in Chris92de AdminServ. It has been rated as problematic. This issue affects some unknown processing of the file resources/core/adminserv.php. The manipulation of the argument error leads to cross site scripting. The attack may be initiated remotely. The name of the patch is 9a45087814295de6fb3a3fe38f96293665234da1. It is recommended to apply a patch to fix this issue. The associated identifier of this vulnerability is VDB-217043. NOTE: This vulnerability only affects products that are no longer supported by the maintainer.

- [https://github.com/Live-Hack-CVE/CVE-2020-36638](https://github.com/Live-Hack-CVE/CVE-2020-36638) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-36638.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-36638.svg)


## CVE-2020-36637
 ** UNSUPPORTED WHEN ASSIGNED ** A vulnerability was found in Chris92de AdminServ. It has been declared as problematic. This vulnerability affects unknown code of the file resources/core/adminserv.php. The manipulation of the argument text leads to cross site scripting. The attack can be initiated remotely. The name of the patch is 3ed17dab3b4d6e8bf1c82ddfbf882314365e9cd7. It is recommended to apply a patch to fix this issue. VDB-217042 is the identifier assigned to this vulnerability. NOTE: This vulnerability only affects products that are no longer supported by the maintainer.

- [https://github.com/Live-Hack-CVE/CVE-2020-36637](https://github.com/Live-Hack-CVE/CVE-2020-36637) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-36637.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-36637.svg)


## CVE-2020-36567
 Unsanitized input in the default logger in github.com/gin-gonic/gin before v1.6.0 allows remote attackers to inject arbitrary log lines.

- [https://github.com/Live-Hack-CVE/CVE-2020-36567](https://github.com/Live-Hack-CVE/CVE-2020-36567) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-36567.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-36567.svg)


## CVE-2020-36563
 XML Digital Signatures generated and validated using this package use SHA-1, which may allow an attacker to craft inputs which cause hash collisions depending on their control over the input.

- [https://github.com/Live-Hack-CVE/CVE-2020-36563](https://github.com/Live-Hack-CVE/CVE-2020-36563) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-36563.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-36563.svg)


## CVE-2020-36562
 Due to unchecked type assertions, maliciously crafted messages can cause panics, which may be used as a denial of service vector.

- [https://github.com/Live-Hack-CVE/CVE-2020-36562](https://github.com/Live-Hack-CVE/CVE-2020-36562) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-36562.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-36562.svg)


## CVE-2020-36559
 Due to improper santization of user input, HTTPEngine.Handle allows for directory traversal, allowing an attacker to read files outside of the target directory that the server has permission to read.

- [https://github.com/Live-Hack-CVE/CVE-2020-36559](https://github.com/Live-Hack-CVE/CVE-2020-36559) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-36559.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-36559.svg)


## CVE-2020-24645
 CVE was unused by HPE.

- [https://github.com/Live-Hack-CVE/CVE-2020-24645](https://github.com/Live-Hack-CVE/CVE-2020-24645) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-24645.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-24645.svg)


## CVE-2020-24644
 CVE was unused by HPE.

- [https://github.com/Live-Hack-CVE/CVE-2020-24644](https://github.com/Live-Hack-CVE/CVE-2020-24644) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-24644.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-24644.svg)


## CVE-2020-24643
 CVE was unused by HPE.

- [https://github.com/Live-Hack-CVE/CVE-2020-24643](https://github.com/Live-Hack-CVE/CVE-2020-24643) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-24643.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-24643.svg)


## CVE-2020-24642
 CVE was unused by HPE.

- [https://github.com/Live-Hack-CVE/CVE-2020-24642](https://github.com/Live-Hack-CVE/CVE-2020-24642) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-24642.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-24642.svg)


## CVE-2020-7118
 CVE was unused by HPE.

- [https://github.com/Live-Hack-CVE/CVE-2020-7118](https://github.com/Live-Hack-CVE/CVE-2020-7118) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-7118.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-7118.svg)


## CVE-2020-7112
 CVE was unused by HPE.

- [https://github.com/Live-Hack-CVE/CVE-2020-7112](https://github.com/Live-Hack-CVE/CVE-2020-7112) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-7112.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-7112.svg)


## CVE-2019-25099
 A vulnerability classified as critical was found in Arthmoor QSF-Portal. This vulnerability affects unknown code of the file index.php. The manipulation of the argument a leads to path traversal. The name of the patch is ea4f61e23ecb83247d174bc2e2cbab521c751a7d. It is recommended to apply a patch to fix this issue. VDB-217558 is the identifier assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2019-25099](https://github.com/Live-Hack-CVE/CVE-2019-25099) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-25099.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-25099.svg)


## CVE-2019-25092
 A vulnerability classified as problematic was found in Nakiami Mellivora up to 2.1.x. Affected by this vulnerability is the function print_user_ip_log of the file include/layout/user.inc.php of the component Admin Panel. The manipulation of the argument $entry['ip'] leads to cross site scripting. The attack can be launched remotely. Upgrading to version 2.2.0 is able to address this issue. The name of the patch is e0b6965f8dde608a3d2621617c05695eb406cbb9. It is recommended to upgrade the affected component. The associated identifier of this vulnerability is VDB-216955.

- [https://github.com/Live-Hack-CVE/CVE-2019-25092](https://github.com/Live-Hack-CVE/CVE-2019-25092) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-25092.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-25092.svg)


## CVE-2019-25091
 A vulnerability classified as problematic has been found in nsupdate.info. This affects an unknown part of the file src/nsupdate/settings/base.py of the component CSRF Cookie Handler. The manipulation of the argument CSRF_COOKIE_HTTPONLY leads to cookie without 'httponly' flag. It is possible to initiate the attack remotely. The name of the patch is 60a3fe559c453bc36b0ec3e5dd39c1303640a59a. It is recommended to apply a patch to fix this issue. The identifier VDB-216909 was assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2019-25091](https://github.com/Live-Hack-CVE/CVE-2019-25091) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-25091.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-25091.svg)


## CVE-2019-25073
 Improper path santiziation in github.com/goadesign/goa before v3.0.9, v2.0.10, or v1.4.3 allow remote attackers to read files outside of the intended directory.

- [https://github.com/Live-Hack-CVE/CVE-2019-25073](https://github.com/Live-Hack-CVE/CVE-2019-25073) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-25073.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-25073.svg)


## CVE-2019-25072
 Due to support of Gzip compression in request bodies, as well as a lack of limiting response body sizes, a malicious server can cause a client to consume a significant amount of system resources, which may be used as a denial of service vector.

- [https://github.com/Live-Hack-CVE/CVE-2019-25072](https://github.com/Live-Hack-CVE/CVE-2019-25072) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-25072.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-25072.svg)


## CVE-2019-16724
 File Sharing Wizard 1.5.0 allows a remote attacker to obtain arbitrary code execution by exploiting a Structured Exception Handler (SEH) based buffer overflow in an HTTP POST parameter, a similar issue to CVE-2010-2330 and CVE-2010-2331.

- [https://github.com/nanabingies/CVE-2019-16724](https://github.com/nanabingies/CVE-2019-16724) :  ![starts](https://img.shields.io/github/stars/nanabingies/CVE-2019-16724.svg) ![forks](https://img.shields.io/github/forks/nanabingies/CVE-2019-16724.svg)


## CVE-2019-6773
 This vulnerability allows remote attackers to disclose sensitive information on vulnerable installations of Foxit Reader 9.4.1.16828. User interaction is required to exploit this vulnerability in that the target must visit a malicious page or open a malicious file. The specific flaw exists within the handling of the richValue property of a Field object within AcroForms. The issue results from the lack of validating the existence of an object prior to performing operations on the object. An attacker can leverage this in conjunction with other vulnerabilities to execute code in the context of the current process. Was ZDI-CAN-8272.

- [https://github.com/Live-Hack-CVE/CVE-2019-6773](https://github.com/Live-Hack-CVE/CVE-2019-6773) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-6773.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-6773.svg)


## CVE-2019-5325
 CVE was unused by HPE.

- [https://github.com/Live-Hack-CVE/CVE-2019-5325](https://github.com/Live-Hack-CVE/CVE-2019-5325) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-5325.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-5325.svg)


## CVE-2019-5316
 CVE was unused by HPE.

- [https://github.com/Live-Hack-CVE/CVE-2019-5316](https://github.com/Live-Hack-CVE/CVE-2019-5316) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-5316.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-5316.svg)


## CVE-2019-5313
 CVE was unused by HPE.

- [https://github.com/Live-Hack-CVE/CVE-2019-5313](https://github.com/Live-Hack-CVE/CVE-2019-5313) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-5313.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-5313.svg)


## CVE-2018-25071
 A vulnerability was found in roxlukas LMeve up to 0.1.58. It has been rated as critical. Affected by this issue is the function insert_log of the file wwwroot/ccpwgl/proxy.php. The manipulation of the argument fetch leads to sql injection. Upgrading to version 0.1.59-beta is able to address this issue. The name of the patch is c25ff7fe83a2cda1fcb365b182365adc3ffae332. It is recommended to upgrade the affected component. VDB-217610 is the identifier assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2018-25071](https://github.com/Live-Hack-CVE/CVE-2018-25071) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2018-25071.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2018-25071.svg)


## CVE-2018-25070
 A vulnerability has been found in polterguy Phosphorus Five up to 8.2 and classified as critical. This vulnerability affects the function csv.Read of the file plugins/extras/p5.mysql/NonQuery.cs of the component CSV Import. The manipulation leads to sql injection. Upgrading to version 8.3 is able to address this issue. The name of the patch is c179a3d0703db55cfe0cb939b89593f2e7a87246. It is recommended to upgrade the affected component. VDB-217606 is the identifier assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2018-25070](https://github.com/Live-Hack-CVE/CVE-2018-25070) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2018-25070.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2018-25070.svg)


## CVE-2018-25069
 A vulnerability classified as critical has been found in Netis Netcore Router. This affects an unknown part. The manipulation leads to use of hard-coded password. It is possible to initiate the attack remotely. The identifier VDB-217593 was assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2018-25069](https://github.com/Live-Hack-CVE/CVE-2018-25069) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2018-25069.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2018-25069.svg)


## CVE-2018-25068
 A vulnerability has been found in devent globalpom-utils up to 4.5.0 and classified as critical. This vulnerability affects the function createTmpDir of the file globalpomutils-fileresources/src/main/java/com/anrisoftware/globalpom/fileresourcemanager/FileResourceManagerProvider.java. The manipulation leads to insecure temporary file. The attack can be initiated remotely. Upgrading to version 4.5.1 is able to address this issue. The name of the patch is 77a820bac2f68e662ce261ecb050c643bd7ee560. It is recommended to upgrade the affected component. VDB-217570 is the identifier assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2018-25068](https://github.com/Live-Hack-CVE/CVE-2018-25068) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2018-25068.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2018-25068.svg)


## CVE-2018-25067
 A vulnerability, which was classified as critical, was found in JoomGallery up to 3.3.3. This affects an unknown part of the file administrator/components/com_joomgallery/views/config/tmpl/default.php of the component Image Sort Handler. The manipulation leads to sql injection. Upgrading to version 3.3.4 is able to address this issue. The name of the patch is dc414ee954e849082260f8613e15a1c1e1d354a1. It is recommended to upgrade the affected component. The identifier VDB-217569 was assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2018-25067](https://github.com/Live-Hack-CVE/CVE-2018-25067) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2018-25067.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2018-25067.svg)


## CVE-2018-25054
 A vulnerability was found in shred cilla. It has been classified as problematic. Affected is an unknown function of the file cilla-xample/src/main/webapp/WEB-INF/jsp/view/search.jsp of the component Search Handler. The manipulation of the argument details leads to cross site scripting. It is possible to launch the attack remotely. The name of the patch is d345e6bc7798bd717a583ec7f545ca387819d5c7. It is recommended to apply a patch to fix this issue. The identifier of this vulnerability is VDB-216960.

- [https://github.com/Live-Hack-CVE/CVE-2018-25054](https://github.com/Live-Hack-CVE/CVE-2018-25054) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2018-25054.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2018-25054.svg)


## CVE-2018-25050
 A vulnerability, which was classified as problematic, has been found in Harvest Chosen up to 1.8.6. Affected by this issue is the function AbstractChosen of the file coffee/lib/abstract-chosen.coffee. The manipulation of the argument group_label leads to cross site scripting. The attack may be launched remotely. Upgrading to version 1.8.7 is able to address this issue. The name of the patch is 77fd031d541e77510268d1041ed37798fdd1017e. It is recommended to upgrade the affected component. The identifier of this vulnerability is VDB-216956.

- [https://github.com/Live-Hack-CVE/CVE-2018-25050](https://github.com/Live-Hack-CVE/CVE-2018-25050) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2018-25050.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2018-25050.svg)


## CVE-2018-25046
 Due to improper path santization, archives containing relative file paths can cause files to be written (or overwritten) outside of the target directory.

- [https://github.com/Live-Hack-CVE/CVE-2018-25046](https://github.com/Live-Hack-CVE/CVE-2018-25046) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2018-25046.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2018-25046.svg)


## CVE-2018-19321
 The GPCIDrv and GDrv low-level drivers in GIGABYTE APP Center v1.05.21 and earlier, AORUS GRAPHICS ENGINE before 1.57, XTREME GAMING ENGINE before 1.26, and OC GURU II v2.08 expose functionality to read and write arbitrary physical memory. This could be leveraged by a local attacker to elevate privileges.

- [https://github.com/nanabingies/CVE-2018-19321](https://github.com/nanabingies/CVE-2018-19321) :  ![starts](https://img.shields.io/github/stars/nanabingies/CVE-2018-19321.svg) ![forks](https://img.shields.io/github/forks/nanabingies/CVE-2018-19321.svg)


## CVE-2018-7600
 Drupal before 7.58, 8.x before 8.3.9, 8.4.x before 8.4.6, and 8.5.x before 8.5.1 allows remote attackers to execute arbitrary code because of an issue affecting multiple subsystems with default or common module configurations.

- [https://github.com/demetrius-ford/CVE-2018-7600](https://github.com/demetrius-ford/CVE-2018-7600) :  ![starts](https://img.shields.io/github/stars/demetrius-ford/CVE-2018-7600.svg) ![forks](https://img.shields.io/github/forks/demetrius-ford/CVE-2018-7600.svg)


## CVE-2017-20150
 A vulnerability was found in challenge website. It has been rated as critical. This issue affects some unknown processing. The manipulation leads to sql injection. The name of the patch is f1644b1d3502e5aa5284f31ea80d2623817f4d42. It is recommended to apply a patch to fix this issue. The identifier VDB-216989 was assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2017-20150](https://github.com/Live-Hack-CVE/CVE-2017-20150) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2017-20150.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2017-20150.svg)


## CVE-2016-15012
 ** UNSUPPORTED WHEN ASSIGNED ** A vulnerability was found in forcedotcom SalesforceMobileSDK-Windows up to 4.x. It has been rated as critical. This issue affects the function ComputeCountSql of the file SalesforceSDK/SmartStore/Store/QuerySpec.cs. The manipulation leads to sql injection. Upgrading to version 5.0.0 is able to address this issue. The name of the patch is 83b3e91e0c1e84873a6d3ca3c5887eb5b4f5a3d8. It is recommended to upgrade the affected component. The associated identifier of this vulnerability is VDB-217619. NOTE: This vulnerability only affects products that are no longer supported by the maintainer.

- [https://github.com/Live-Hack-CVE/CVE-2016-15012](https://github.com/Live-Hack-CVE/CVE-2016-15012) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-15012.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-15012.svg)


## CVE-2015-10027
 A vulnerability, which was classified as problematic, has been found in hydrian TTRSS-Auth-LDAP. Affected by this issue is some unknown functionality of the component Username Handler. The manipulation leads to ldap injection. Upgrading to version 2.0b1 is able to address this issue. The name of the patch is a7f7a5a82d9202a5c40d606a5c519ba61b224eb8. It is recommended to upgrade the affected component. VDB-217622 is the identifier assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2015-10027](https://github.com/Live-Hack-CVE/CVE-2015-10027) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2015-10027.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2015-10027.svg)


## CVE-2015-10026
 A vulnerability was found in tiredtyrant flairbot. It has been declared as critical. This vulnerability affects unknown code of the file flair.py. The manipulation leads to sql injection. The name of the patch is 5e112b68c6faad1d4699d02c1ebbb7daf48ef8fb. It is recommended to apply a patch to fix this issue. VDB-217618 is the identifier assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2015-10026](https://github.com/Live-Hack-CVE/CVE-2015-10026) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2015-10026.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2015-10026.svg)


## CVE-2015-10025
 A vulnerability has been found in luelista miniConf up to 1.7.6 and classified as problematic. Affected by this vulnerability is an unknown functionality of the file miniConf/MessageView.cs of the component URL Scanning. The manipulation leads to denial of service. Upgrading to version 1.7.7 and 1.8.0 is able to address this issue. The name of the patch is c06c2e5116c306e4e1bc79779f0eda2d1182f655. It is recommended to upgrade the affected component. The associated identifier of this vulnerability is VDB-217615.

- [https://github.com/Live-Hack-CVE/CVE-2015-10025](https://github.com/Live-Hack-CVE/CVE-2015-10025) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2015-10025.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2015-10025.svg)


## CVE-2015-10024
 A vulnerability classified as critical was found in hoffie larasync. This vulnerability affects unknown code of the file repository/content/file_storage.go. The manipulation leads to path traversal. The name of the patch is 776bad422f4bd4930d09491711246bbeb1be9ba5. It is recommended to apply a patch to fix this issue. The identifier of this vulnerability is VDB-217612.

- [https://github.com/Live-Hack-CVE/CVE-2015-10024](https://github.com/Live-Hack-CVE/CVE-2015-10024) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2015-10024.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2015-10024.svg)


## CVE-2015-10023
 A vulnerability classified as critical has been found in Fumon trello-octometric. This affects the function main of the file metrics-ui/server/srv.go. The manipulation of the argument num leads to sql injection. The name of the patch is a1f1754933fbf21e2221fbc671c81a47de6a04ef. It is recommended to apply a patch to fix this issue. The associated identifier of this vulnerability is VDB-217611.

- [https://github.com/Live-Hack-CVE/CVE-2015-10023](https://github.com/Live-Hack-CVE/CVE-2015-10023) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2015-10023.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2015-10023.svg)


## CVE-2015-10022
 A vulnerability was found in IISH nlgis2. It has been declared as critical. Affected by this vulnerability is an unknown functionality of the file scripts/etl/custom_import.pl. The manipulation leads to sql injection. The name of the patch is 8bdb6fcf7209584eaf1232437f0f53e735b2b34c. It is recommended to apply a patch to fix this issue. The identifier VDB-217609 was assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2015-10022](https://github.com/Live-Hack-CVE/CVE-2015-10022) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2015-10022.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2015-10022.svg)


## CVE-2015-10021
 A vulnerability was found in ritterim definely. It has been classified as problematic. Affected is an unknown function of the file src/database.js. The manipulation leads to cross site scripting. It is possible to launch the attack remotely. The name of the patch is b31a022ba4d8d17148445a13ebb5a42ad593dbaa. It is recommended to apply a patch to fix this issue. The identifier of this vulnerability is VDB-217608.

- [https://github.com/Live-Hack-CVE/CVE-2015-10021](https://github.com/Live-Hack-CVE/CVE-2015-10021) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2015-10021.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2015-10021.svg)


## CVE-2015-10019
 A vulnerability, which was classified as problematic, has been found in foxoverflow MySimplifiedSQL. This issue affects some unknown processing of the file MySimplifiedSQL_Examples.php. The manipulation of the argument FirstName/LastName leads to cross site scripting. The attack may be initiated remotely. The name of the patch is 3b7481c72786f88041b7c2d83bb4f219f77f1293. It is recommended to apply a patch to fix this issue. The associated identifier of this vulnerability is VDB-217595.

- [https://github.com/Live-Hack-CVE/CVE-2015-10019](https://github.com/Live-Hack-CVE/CVE-2015-10019) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2015-10019.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2015-10019.svg)


## CVE-2014-125062
 A vulnerability classified as critical was found in ananich bitstorm. Affected by this vulnerability is an unknown functionality of the file announce.php. The manipulation of the argument event leads to sql injection. The name of the patch is ea8da92f94cdb78ee7831e1f7af6258473ab396a. It is recommended to apply a patch to fix this issue. The identifier VDB-217621 was assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2014-125062](https://github.com/Live-Hack-CVE/CVE-2014-125062) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2014-125062.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2014-125062.svg)


## CVE-2014-125061
 ** UNSUPPORTED WHEN ASSIGNED ** A vulnerability was found in peel filebroker and classified as critical. Affected by this issue is the function select_transfer_status_desc of the file lib/common.rb. The manipulation leads to sql injection. The name of the patch is 91097e26a6c84d3208a351afaa52e0f62e5853ef. It is recommended to apply a patch to fix this issue. The identifier of this vulnerability is VDB-217616. NOTE: This vulnerability only affects products that are no longer supported by the maintainer.

- [https://github.com/Live-Hack-CVE/CVE-2014-125061](https://github.com/Live-Hack-CVE/CVE-2014-125061) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2014-125061.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2014-125061.svg)


## CVE-2014-125060
 A vulnerability, which was classified as critical, was found in holdennb CollabCal. Affected is the function handleGet of the file calenderServer.cpp. The manipulation leads to improper authentication. It is possible to launch the attack remotely. The name of the patch is b80f6d1893607c99e5113967592417d0fe310ce6. It is recommended to apply a patch to fix this issue. VDB-217614 is the identifier assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2014-125060](https://github.com/Live-Hack-CVE/CVE-2014-125060) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2014-125060.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2014-125060.svg)


## CVE-2014-125059
 A vulnerability, which was classified as problematic, has been found in sternenseemann sternenblog. This issue affects the function blog_index of the file main.c. The manipulation of the argument post_path leads to file inclusion. The attack may be initiated remotely. Upgrading to version 0.1.0 is able to address this issue. The name of the patch is cf715d911d8ce17969a7926dea651e930c27e71a. It is recommended to upgrade the affected component. The identifier VDB-217613 was assigned to this vulnerability. NOTE: This case is rather theoretical and probably won't happen. Maybe only on obscure Web servers.

- [https://github.com/Live-Hack-CVE/CVE-2014-125059](https://github.com/Live-Hack-CVE/CVE-2014-125059) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2014-125059.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2014-125059.svg)


## CVE-2014-125058
 A vulnerability was found in LearnMeSomeCodes project3 and classified as critical. This issue affects the function search_first_name of the file search.rb. The manipulation leads to sql injection. The name of the patch is d3efa17ae9f6b2fc25a6bbcf165cefed17c7035e. It is recommended to apply a patch to fix this issue. The associated identifier of this vulnerability is VDB-217607. NOTE: Maintainer is aware of this issue as remarked in the source code.

- [https://github.com/Live-Hack-CVE/CVE-2014-125058](https://github.com/Live-Hack-CVE/CVE-2014-125058) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2014-125058.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2014-125058.svg)


## CVE-2014-125057
 A vulnerability was found in mrobit robitailletheknot. It has been classified as problematic. This affects an unknown part of the file app/filters.php of the component CSRF Token Handler. The manipulation of the argument _token leads to incorrect comparison. It is possible to initiate the attack remotely. The name of the patch is 6b2813696ccb88d0576dfb305122ee880eb36197. It is recommended to apply a patch to fix this issue. The associated identifier of this vulnerability is VDB-217599.

- [https://github.com/Live-Hack-CVE/CVE-2014-125057](https://github.com/Live-Hack-CVE/CVE-2014-125057) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2014-125057.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2014-125057.svg)


## CVE-2014-125056
 A vulnerability was found in Pylons horus and classified as problematic. Affected by this issue is some unknown functionality of the file horus/flows/local/services.py. The manipulation leads to observable timing discrepancy. The name of the patch is fd56ccb62ce3cbdab0484fe4f9c25c4eda6c57ec. It is recommended to apply a patch to fix this issue. VDB-217598 is the identifier assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2014-125056](https://github.com/Live-Hack-CVE/CVE-2014-125056) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2014-125056.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2014-125056.svg)


## CVE-2014-125055
 A vulnerability, which was classified as problematic, was found in agnivade easy-scrypt. Affected is the function VerifyPassphrase of the file scrypt.go. The manipulation leads to observable timing discrepancy. Upgrading to version 1.0.0 is able to address this issue. The name of the patch is 477c10cf3b144ddf96526aa09f5fdea613f21812. It is recommended to upgrade the affected component. The identifier of this vulnerability is VDB-217596.

- [https://github.com/Live-Hack-CVE/CVE-2014-125055](https://github.com/Live-Hack-CVE/CVE-2014-125055) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2014-125055.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2014-125055.svg)


## CVE-2014-125054
 A vulnerability classified as critical was found in koroket RedditOnRails. This vulnerability affects unknown code of the component Vote Handler. The manipulation leads to improper access controls. The attack can be initiated remotely. The name of the patch is 7f3c7407d95d532fcc342b00d68d0ea09ca71030. It is recommended to apply a patch to fix this issue. VDB-217594 is the identifier assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2014-125054](https://github.com/Live-Hack-CVE/CVE-2014-125054) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2014-125054.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2014-125054.svg)


## CVE-2014-125053
 A vulnerability was found in Piwigo-Guest-Book up to 1.3.0. It has been declared as critical. This vulnerability affects unknown code of the file include/guestbook.inc.php of the component Navigation Bar. The manipulation of the argument start leads to sql injection. Upgrading to version 1.3.1 is able to address this issue. The name of the patch is 0cdd1c388edf15089c3a7541cefe7756e560581d. It is recommended to upgrade the affected component. VDB-217582 is the identifier assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2014-125053](https://github.com/Live-Hack-CVE/CVE-2014-125053) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2014-125053.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2014-125053.svg)


## CVE-2014-125052
 A vulnerability was found in JervenBolleman sparql-identifiers and classified as critical. This issue affects some unknown processing of the file src/main/java/org/identifiers/db/RegistryDao.java. The manipulation leads to sql injection. The name of the patch is 44bb0db91c064e305b192fc73521d1dfd25bde52. It is recommended to apply a patch to fix this issue. The associated identifier of this vulnerability is VDB-217571.

- [https://github.com/Live-Hack-CVE/CVE-2014-125052](https://github.com/Live-Hack-CVE/CVE-2014-125052) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2014-125052.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2014-125052.svg)


## CVE-2013-10008
 A vulnerability was found in sheilazpy eShop. It has been classified as critical. Affected is an unknown function. The manipulation leads to sql injection. The name of the patch is e096c5849c4dc09e1074104531014a62a5413884. It is recommended to apply a patch to fix this issue. The identifier of this vulnerability is VDB-217572.

- [https://github.com/Live-Hack-CVE/CVE-2013-10008](https://github.com/Live-Hack-CVE/CVE-2013-10008) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2013-10008.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2013-10008.svg)

