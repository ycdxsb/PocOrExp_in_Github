# Update 2023-01-27
## CVE-2023-24055
 ** DISPUTED ** KeePass through 2.53 (in a default installation) allows an attacker, who has write access to the XML configuration file, to obtain the cleartext passwords by adding an export trigger. NOTE: the vendor's position is that the password database is not intended to be secure against an attacker who has that level of access to the local PC.

- [https://github.com/alt3kx/CVE-2023-24055_PoC](https://github.com/alt3kx/CVE-2023-24055_PoC) :  ![starts](https://img.shields.io/github/stars/alt3kx/CVE-2023-24055_PoC.svg) ![forks](https://img.shields.io/github/forks/alt3kx/CVE-2023-24055_PoC.svg)


## CVE-2023-22875
 IBM QRadar SIEM 7.4 and 7.5copies certificate key files used for SSL/TLS in the QRadar web user interface to managed hosts in the deployment that do not require that key. IBM X-Force ID: 244356.

- [https://github.com/Live-Hack-CVE/CVE-2023-22875](https://github.com/Live-Hack-CVE/CVE-2023-22875) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22875.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22875.svg)


## CVE-2023-22850
 Tiki before 24.1, when the Spreadsheets feature is enabled, allows lib/sheet/grid.php PHP Object Injection because of an unserialize call.

- [https://github.com/Live-Hack-CVE/CVE-2023-22850](https://github.com/Live-Hack-CVE/CVE-2023-22850) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22850.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22850.svg)


## CVE-2023-22499
 Deno is a runtime for JavaScript and TypeScript that uses V8 and is built in Rust. Multi-threaded programs were able to spoof interactive permission prompt by rewriting the prompt to suggest that program is waiting on user confirmation to unrelated action. A malicious program could clear the terminal screen after permission prompt was shown and write a generic message. This situation impacts users who use Web Worker API and relied on interactive permission prompt. The reproduction is very timing sensitive and can&#8217;t be reliably reproduced on every try. This problem can not be exploited on systems that do not attach an interactive prompt (for example headless servers). The problem has been fixed in Deno v1.29.3; it is recommended all users update to this version. Users are advised to upgrade. Users unable to upgrade may run with --no-prompt flag to disable interactive permission prompts.

- [https://github.com/Live-Hack-CVE/CVE-2023-22499](https://github.com/Live-Hack-CVE/CVE-2023-22499) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22499.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22499.svg)


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


## CVE-2023-21860
 Vulnerability in the MySQL Cluster product of Oracle MySQL (component: Cluster: Internal Operations). Supported versions that are affected are 7.4.38 and prior, 7.5.28 and prior, 7.6.24 and prior and 8.0.31 and prior. Difficult to exploit vulnerability allows high privileged attacker with access to the physical communication segment attached to the hardware where the MySQL Cluster executes to compromise MySQL Cluster. Successful attacks require human interaction from a person other than the attacker. Successful attacks of this vulnerability can result in takeover of MySQL Cluster. CVSS 3.1 Base Score 6.3 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:A/AC:H/PR:H/UI:R/S:U/C:H/I:H/A:H).

- [https://github.com/Live-Hack-CVE/CVE-2023-21860](https://github.com/Live-Hack-CVE/CVE-2023-21860) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21860.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21860.svg)


## CVE-2022-47950
 An issue was discovered in OpenStack Swift before 2.28.1, 2.29.x before 2.29.2, and 2.30.0. By supplying crafted XML files, an authenticated user may coerce the S3 API into returning arbitrary file contents from the host server, resulting in unauthorized read access to potentially sensitive data. This impacts both s3api deployments (Rocky or later), and swift3 deployments (Queens and earlier, no longer actively developed).

- [https://github.com/Live-Hack-CVE/CVE-2022-47950](https://github.com/Live-Hack-CVE/CVE-2022-47950) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-47950.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-47950.svg)


## CVE-2022-46331
 An unauthorized user could possibly delete any file on the system.

- [https://github.com/Live-Hack-CVE/CVE-2022-46331](https://github.com/Live-Hack-CVE/CVE-2022-46331) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-46331.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-46331.svg)


## CVE-2022-45558
 Cross site scripting (XSS) vulnerability in Hundredrabbits Left 7.1.5 for MacOS allows attackers to execute arbitrary code via the meta tag.

- [https://github.com/Live-Hack-CVE/CVE-2022-45558](https://github.com/Live-Hack-CVE/CVE-2022-45558) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-45558.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-45558.svg)


## CVE-2022-45557
 Cross site scripting (XSS) vulnerability in Hundredrabbits Left 7.1.5 for MacOS allows attackers to execute arbitrary code via file names.

- [https://github.com/Live-Hack-CVE/CVE-2022-45557](https://github.com/Live-Hack-CVE/CVE-2022-45557) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-45557.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-45557.svg)


## CVE-2022-45542
 EyouCMS &lt;= 1.6.0 was discovered a reflected-XSS in the FileManager component in GET parameter &quot;filename&quot; when editing any file.

- [https://github.com/Live-Hack-CVE/CVE-2022-45542](https://github.com/Live-Hack-CVE/CVE-2022-45542) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-45542.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-45542.svg)


## CVE-2022-43522
 Multiple vulnerabilities in the web-based management interface of Aruba EdgeConnect Enterprise Orchestrator could allow an authenticated remote attacker to conduct SQL injection attacks against the Aruba EdgeConnect Enterprise Orchestrator instance. An attacker could exploit these vulnerabilities to obtain and modify sensitive information in the underlying database potentially leading to complete compromise of the Aruba EdgeConnect Enterprise Orchestrator host in Aruba EdgeConnect Enterprise Orchestration Software version(s): Aruba EdgeConnect Enterprise Orchestrator (on-premises), Aruba EdgeConnect Enterprise Orchestrator-as-a-Service, Aruba EdgeConnect Enterprise Orchestrator-SP and Aruba EdgeConnect Enterprise Orchestrator Global Enterprise Tenant Orchestrators - Orchestrator 9.2.1.40179 and below, - Orchestrator 9.1.4.40436 and below, - Orchestrator 9.0.7.40110 and below, - Orchestrator 8.10.23.40015 and below, - Any older branches of Orchestrator not specifically mentioned.

- [https://github.com/Live-Hack-CVE/CVE-2022-43522](https://github.com/Live-Hack-CVE/CVE-2022-43522) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-43522.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-43522.svg)


## CVE-2022-43494
 An unauthorized user could be able to read any file on the system, potentially exposing sensitive information.

- [https://github.com/Live-Hack-CVE/CVE-2022-43494](https://github.com/Live-Hack-CVE/CVE-2022-43494) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-43494.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-43494.svg)


## CVE-2022-43455
 Sewio&#8217;s Real-Time Location System (RTLS) Studio version 2.0.0 up to and including version 2.6.2 is vulnerable to improper input validation of user input to the service_start, service_stop, and service_restart modules of the software. This could allow an attacker to start, stop, or restart arbitrary services running on the server.

- [https://github.com/Live-Hack-CVE/CVE-2022-43455](https://github.com/Live-Hack-CVE/CVE-2022-43455) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-43455.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-43455.svg)


## CVE-2022-43406
 A sandbox bypass vulnerability in Jenkins Pipeline: Deprecated Groovy Libraries Plugin 583.vf3b_454e43966 and earlier allows attackers with permission to define untrusted Pipeline libraries and to define and run sandboxed scripts, including Pipelines, to bypass the sandbox protection and execute arbitrary code in the context of the Jenkins controller JVM.

- [https://github.com/Live-Hack-CVE/CVE-2022-43406](https://github.com/Live-Hack-CVE/CVE-2022-43406) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-43406.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-43406.svg)


## CVE-2022-41903
 Git is distributed revision control system. `git log` can display commits in an arbitrary format using its `--format` specifiers. This functionality is also exposed to `git archive` via the `export-subst` gitattribute. When processing the padding operators, there is a integer overflow in `pretty.c::format_and_pad_commit()` where a `size_t` is stored improperly as an `int`, and then added as an offset to a `memcpy()`. This overflow can be triggered directly by a user running a command which invokes the commit formatting machinery (e.g., `git log --format=...`). It may also be triggered indirectly through git archive via the export-subst mechanism, which expands format specifiers inside of files within the repository during a git archive. This integer overflow can result in arbitrary heap writes, which may result in arbitrary code execution. The problem has been patched in the versions published on 2023-01-17, going back to v2.30.7. Users are advised to upgrade. Users who are unable to upgrade should disable `git archive` in untrusted repositories. If you expose git archive via `git daemon`, disable it by running `git config --global daemon.uploadArch false`.

- [https://github.com/Live-Hack-CVE/CVE-2022-41903](https://github.com/Live-Hack-CVE/CVE-2022-41903) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-41903.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-41903.svg)


## CVE-2022-41627
 The physical IoT device of the AliveCor's KardiaMobile, a smartphone-based personal electrocardiogram (EKG) has no encryption for its data-over-sound protocols. Exploiting this vulnerability could allow an attacker to read patient EKG results or create a denial-of-service condition by emitting sounds at similar frequencies as the device, disrupting the smartphone microphone&#8217;s ability to accurately read the data. To carry out this attack, the attacker must be close (less than 5 feet) to pick up and emit sound waves.

- [https://github.com/Live-Hack-CVE/CVE-2022-41627](https://github.com/Live-Hack-CVE/CVE-2022-41627) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-41627.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-41627.svg)


## CVE-2022-40634
 Improper Control of Dynamically-Managed Code Resources vulnerability in Crafter Studio of Crafter CMS allows authenticated developers to execute OS commands via FreeMarker SSTI.

- [https://github.com/Live-Hack-CVE/CVE-2022-40634](https://github.com/Live-Hack-CVE/CVE-2022-40634) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-40634.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-40634.svg)


## CVE-2022-40319
 The LISTSERV 17 web interface allows remote attackers to conduct Insecure Direct Object References (IDOR) attacks via a modified email address in a wa.exe URL. The impact is unauthorized modification of a victim's LISTSERV account.

- [https://github.com/Live-Hack-CVE/CVE-2022-40319](https://github.com/Live-Hack-CVE/CVE-2022-40319) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-40319.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-40319.svg)


## CVE-2022-38469
 An unauthorized user with network access and the decryption key could decrypt sensitive data, such as usernames and passwords.

- [https://github.com/Live-Hack-CVE/CVE-2022-38469](https://github.com/Live-Hack-CVE/CVE-2022-38469) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-38469.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-38469.svg)


## CVE-2022-30190
 Microsoft Windows Support Diagnostic Tool (MSDT) Remote Code Execution Vulnerability.

- [https://github.com/Lucaskrell/go_follina](https://github.com/Lucaskrell/go_follina) :  ![starts](https://img.shields.io/github/stars/Lucaskrell/go_follina.svg) ![forks](https://img.shields.io/github/forks/Lucaskrell/go_follina.svg)


## CVE-2022-23739
 An incorrect authorization vulnerability was identified in GitHub Enterprise Server, allowing for escalation of privileges in GraphQL API requests from GitHub Apps. This vulnerability allowed an app installed on an organization to gain access to and modify most organization-level resources that are not tied to a repository regardless of granted permissions, such as users and organization-wide projects. Resources associated with repositories were not impacted, such as repository file content, repository-specific projects, issues, or pull requests. This vulnerability affected all versions of GitHub Enterprise Server prior to 3.7.1 and was fixed in versions 3.3.16, 3.4.11, 3.5.8, 3.6.4, 3.7.1. This vulnerability was reported via the GitHub Bug Bounty program.

- [https://github.com/Live-Hack-CVE/CVE-2022-23739](https://github.com/Live-Hack-CVE/CVE-2022-23739) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-23739.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-23739.svg)


## CVE-2022-4465
 The WP Video Lightbox WordPress plugin before 1.9.7 does not validate and escape some of its shortcode attributes before outputting them back in the page, which could allow users with a role as low as contributor to perform Stored Cross-Site Scripting attacks which could be used against high privilege users such as admin.

- [https://github.com/Live-Hack-CVE/CVE-2022-4465](https://github.com/Live-Hack-CVE/CVE-2022-4465) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4465.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4465.svg)


## CVE-2022-4295
 The Show All Comments WordPress plugin before 7.0.1 does not sanitise and escape a parameter before outputting it back in the page, leading to a Reflected Cross-Site Scripting which could be used against a logged in high privilege users such as admin.

- [https://github.com/Live-Hack-CVE/CVE-2022-4295](https://github.com/Live-Hack-CVE/CVE-2022-4295) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4295.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4295.svg)


## CVE-2022-4045
 A denial-of-service vulnerability in the Mattermost allows an authenticated user to crash the server via multiple requests to one of the API endpoints which could fetch a large amount of data.

- [https://github.com/Live-Hack-CVE/CVE-2022-4045](https://github.com/Live-Hack-CVE/CVE-2022-4045) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4045.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4045.svg)


## CVE-2022-3826
 A vulnerability was found in Huaxia ERP. It has been classified as problematic. This affects an unknown part of the file /depotHead/list of the component Retail Management. The manipulation of the argument search leads to information disclosure. It is possible to initiate the attack remotely. The exploit has been disclosed to the public and may be used. The identifier VDB-212793 was assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2022-3826](https://github.com/Live-Hack-CVE/CVE-2022-3826) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-3826.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-3826.svg)


## CVE-2022-3782
 keycloak: path traversal via double URL encoding. A flaw was found in Keycloak, where it does not properly validate URLs included in a redirect. An attacker can use this flaw to construct a malicious request to bypass validation and access other URLs and potentially sensitive information within the domain or possibly conduct further attacks. This flaw affects any client that utilizes a wildcard in the Valid Redirect URIs field.

- [https://github.com/Live-Hack-CVE/CVE-2022-3782](https://github.com/Live-Hack-CVE/CVE-2022-3782) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-3782.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-3782.svg)


## CVE-2022-3650
 A privilege escalation flaw was found in Ceph. Ceph-crash.service allows a local attacker to escalate privileges to root in the form of a crash dump, and dump privileged information.

- [https://github.com/Live-Hack-CVE/CVE-2022-3650](https://github.com/Live-Hack-CVE/CVE-2022-3650) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-3650.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-3650.svg)


## CVE-2022-3553
 A vulnerability, which was classified as problematic, was found in X.org Server. This affects an unknown part of the file hw/xquartz/X11Controller.m of the component xquartz. The manipulation leads to denial of service. It is recommended to apply a patch to fix this issue. The identifier VDB-211053 was assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2022-3553](https://github.com/Live-Hack-CVE/CVE-2022-3553) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-3553.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-3553.svg)


## CVE-2022-3143
 wildfly-elytron: possible timing attacks via use of unsafe comparator. A flaw was found in Wildfly-elytron. Wildfly-elytron uses java.util.Arrays.equals in several places, which is unsafe and vulnerable to timing attacks. To compare values securely, use java.security.MessageDigest.isEqual instead. This flaw allows an attacker to access secure information or impersonate an authed user.

- [https://github.com/Live-Hack-CVE/CVE-2022-3143](https://github.com/Live-Hack-CVE/CVE-2022-3143) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-3143.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-3143.svg)


## CVE-2022-2907
 An issue has been discovered in GitLab CE/EE affecting all versions starting from 12.9 before 15.1.6, all versions starting from 15.2 before 15.2.4, all versions starting from 15.3 before 15.3.2. It was possible to read repository content by an unauthorised user if a project member used a crafted link.

- [https://github.com/Live-Hack-CVE/CVE-2022-2907](https://github.com/Live-Hack-CVE/CVE-2022-2907) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2907.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2907.svg)


## CVE-2022-2251
 Improper sanitization of branch names in GitLab Runner affecting all versions prior to 15.3.5, 15.4 prior to 15.4.4, and 15.5 prior to 15.5.2 allows a user who creates a branch with a specially crafted name and gets another user to trigger a pipeline to execute commands in the runner as that other user.

- [https://github.com/Live-Hack-CVE/CVE-2022-2251](https://github.com/Live-Hack-CVE/CVE-2022-2251) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2251.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2251.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/m96dg/CVE-2021-41773-exercise](https://github.com/m96dg/CVE-2021-41773-exercise) :  ![starts](https://img.shields.io/github/stars/m96dg/CVE-2021-41773-exercise.svg) ![forks](https://img.shields.io/github/forks/m96dg/CVE-2021-41773-exercise.svg)
- [https://github.com/scarmandef/CVE-2021-41773](https://github.com/scarmandef/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/scarmandef/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/scarmandef/CVE-2021-41773.svg)
- [https://github.com/McSl0vv/CVE-2021-41773](https://github.com/McSl0vv/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/McSl0vv/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/McSl0vv/CVE-2021-41773.svg)
- [https://github.com/12345qwert123456/CVE-2021-41773](https://github.com/12345qwert123456/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/12345qwert123456/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/12345qwert123456/CVE-2021-41773.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/mutur4/CVE-2021-4034](https://github.com/mutur4/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/mutur4/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/mutur4/CVE-2021-4034.svg)


## CVE-2020-36651
 A vulnerability has been found in youngerheart nodeserver and classified as critical. Affected by this vulnerability is an unknown functionality of the file nodeserver.js. The manipulation leads to path traversal. The name of the patch is c4c0f0138ab5afbac58e03915d446680421bde28. It is recommended to apply a patch to fix this issue. The identifier VDB-218461 was assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2020-36651](https://github.com/Live-Hack-CVE/CVE-2020-36651) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-36651.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-36651.svg)


## CVE-2020-1472
 An elevation of privilege vulnerability exists when an attacker establishes a vulnerable Netlogon secure channel connection to a domain controller, using the Netlogon Remote Protocol (MS-NRPC), aka 'Netlogon Elevation of Privilege Vulnerability'.

- [https://github.com/cube0x0/CVE-2020-1472](https://github.com/cube0x0/CVE-2020-1472) :  ![starts](https://img.shields.io/github/stars/cube0x0/CVE-2020-1472.svg) ![forks](https://img.shields.io/github/forks/cube0x0/CVE-2020-1472.svg)
- [https://github.com/sv3nbeast/CVE-2020-1472](https://github.com/sv3nbeast/CVE-2020-1472) :  ![starts](https://img.shields.io/github/stars/sv3nbeast/CVE-2020-1472.svg) ![forks](https://img.shields.io/github/forks/sv3nbeast/CVE-2020-1472.svg)
- [https://github.com/CanciuCostin/CVE-2020-1472](https://github.com/CanciuCostin/CVE-2020-1472) :  ![starts](https://img.shields.io/github/stars/CanciuCostin/CVE-2020-1472.svg) ![forks](https://img.shields.io/github/forks/CanciuCostin/CVE-2020-1472.svg)
- [https://github.com/Sajuwithgithub/CVE2020-1472](https://github.com/Sajuwithgithub/CVE2020-1472) :  ![starts](https://img.shields.io/github/stars/Sajuwithgithub/CVE2020-1472.svg) ![forks](https://img.shields.io/github/forks/Sajuwithgithub/CVE2020-1472.svg)
- [https://github.com/Whippet0/CVE-2020-1472](https://github.com/Whippet0/CVE-2020-1472) :  ![starts](https://img.shields.io/github/stars/Whippet0/CVE-2020-1472.svg) ![forks](https://img.shields.io/github/forks/Whippet0/CVE-2020-1472.svg)
- [https://github.com/midpipps/CVE-2020-1472-Easy](https://github.com/midpipps/CVE-2020-1472-Easy) :  ![starts](https://img.shields.io/github/stars/midpipps/CVE-2020-1472-Easy.svg) ![forks](https://img.shields.io/github/forks/midpipps/CVE-2020-1472-Easy.svg)
- [https://github.com/TheJoyOfHacking/dirkjanm-CVE-2020-1472](https://github.com/TheJoyOfHacking/dirkjanm-CVE-2020-1472) :  ![starts](https://img.shields.io/github/stars/TheJoyOfHacking/dirkjanm-CVE-2020-1472.svg) ![forks](https://img.shields.io/github/forks/TheJoyOfHacking/dirkjanm-CVE-2020-1472.svg)


## CVE-2019-5444
 Path traversal vulnerability in version up to v1.1.3 in serve-here.js npm module allows attackers to list any file in arbitrary folder.

- [https://github.com/Live-Hack-CVE/CVE-2019-5444](https://github.com/Live-Hack-CVE/CVE-2019-5444) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-5444.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-5444.svg)


## CVE-2018-25077
 A vulnerability was found in melnaron mel-spintax. It has been rated as problematic. Affected by this issue is some unknown functionality of the file lib/spintax.js. The manipulation of the argument text leads to inefficient regular expression complexity. The name of the patch is 37767617846e27b87b63004e30216e8f919637d3. It is recommended to apply a patch to fix this issue. The identifier of this vulnerability is VDB-218456.

- [https://github.com/Live-Hack-CVE/CVE-2018-25077](https://github.com/Live-Hack-CVE/CVE-2018-25077) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2018-25077.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2018-25077.svg)


## CVE-2017-8625
 Internet Explorer in Windows 10 Gold, 1511, 1607, 1703, and Windows Server 2016 allows an attacker to bypass Device Guard User Mode Code Integrity (UMCI) policies due to Internet Explorer failing to validate UMCI policies, aka &quot;Internet Explorer Security Feature Bypass Vulnerability&quot;.

- [https://github.com/homjxi0e/CVE-2017-8625_Bypass_UMCI](https://github.com/homjxi0e/CVE-2017-8625_Bypass_UMCI) :  ![starts](https://img.shields.io/github/stars/homjxi0e/CVE-2017-8625_Bypass_UMCI.svg) ![forks](https://img.shields.io/github/forks/homjxi0e/CVE-2017-8625_Bypass_UMCI.svg)


## CVE-2016-7020
 Use-after-free vulnerability in Adobe Flash Player before 18.0.0.366 and 19.x through 22.x before 22.0.0.209 on Windows and OS X and before 11.2.202.632 on Linux allows attackers to execute arbitrary code via unspecified vectors, a different vulnerability than CVE-2016-4173, CVE-2016-4174, CVE-2016-4222, CVE-2016-4226, CVE-2016-4227, CVE-2016-4228, CVE-2016-4229, CVE-2016-4230, CVE-2016-4231, and CVE-2016-4248.

- [https://github.com/Live-Hack-CVE/CVE-2016-7020](https://github.com/Live-Hack-CVE/CVE-2016-7020) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-7020.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-7020.svg)


## CVE-2016-4248
 Use-after-free vulnerability in Adobe Flash Player before 18.0.0.366 and 19.x through 22.x before 22.0.0.209 on Windows and OS X and before 11.2.202.632 on Linux allows attackers to execute arbitrary code via unspecified vectors, a different vulnerability than CVE-2016-4173, CVE-2016-4174, CVE-2016-4222, CVE-2016-4226, CVE-2016-4227, CVE-2016-4228, CVE-2016-4229, CVE-2016-4230, and CVE-2016-4231.

- [https://github.com/Live-Hack-CVE/CVE-2016-4248](https://github.com/Live-Hack-CVE/CVE-2016-4248) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-4248.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-4248.svg)


## CVE-2016-4231
 Use-after-free vulnerability in Adobe Flash Player before 18.0.0.366 and 19.x through 22.x before 22.0.0.209 on Windows and OS X and before 11.2.202.632 on Linux allows attackers to execute arbitrary code via unspecified vectors, a different vulnerability than CVE-2016-4173, CVE-2016-4174, CVE-2016-4222, CVE-2016-4226, CVE-2016-4227, CVE-2016-4228, CVE-2016-4229, CVE-2016-4230, and CVE-2016-4248.

- [https://github.com/Live-Hack-CVE/CVE-2016-4231](https://github.com/Live-Hack-CVE/CVE-2016-4231) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-4231.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-4231.svg)


## CVE-2016-4230
 Use-after-free vulnerability in Adobe Flash Player before 18.0.0.366 and 19.x through 22.x before 22.0.0.209 on Windows and OS X and before 11.2.202.632 on Linux allows attackers to execute arbitrary code via unspecified vectors, a different vulnerability than CVE-2016-4173, CVE-2016-4174, CVE-2016-4222, CVE-2016-4226, CVE-2016-4227, CVE-2016-4228, CVE-2016-4229, CVE-2016-4231, and CVE-2016-4248.

- [https://github.com/Live-Hack-CVE/CVE-2016-4230](https://github.com/Live-Hack-CVE/CVE-2016-4230) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-4230.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-4230.svg)


## CVE-2016-4229
 Use-after-free vulnerability in Adobe Flash Player before 18.0.0.366 and 19.x through 22.x before 22.0.0.209 on Windows and OS X and before 11.2.202.632 on Linux allows attackers to execute arbitrary code via unspecified vectors, a different vulnerability than CVE-2016-4173, CVE-2016-4174, CVE-2016-4222, CVE-2016-4226, CVE-2016-4227, CVE-2016-4228, CVE-2016-4230, CVE-2016-4231, and CVE-2016-4248.

- [https://github.com/Live-Hack-CVE/CVE-2016-4229](https://github.com/Live-Hack-CVE/CVE-2016-4229) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-4229.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-4229.svg)


## CVE-2016-4228
 Use-after-free vulnerability in Adobe Flash Player before 18.0.0.366 and 19.x through 22.x before 22.0.0.209 on Windows and OS X and before 11.2.202.632 on Linux allows attackers to execute arbitrary code via unspecified vectors, a different vulnerability than CVE-2016-4173, CVE-2016-4174, CVE-2016-4222, CVE-2016-4226, CVE-2016-4227, CVE-2016-4229, CVE-2016-4230, CVE-2016-4231, and CVE-2016-4248.

- [https://github.com/Live-Hack-CVE/CVE-2016-4228](https://github.com/Live-Hack-CVE/CVE-2016-4228) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-4228.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-4228.svg)


## CVE-2016-4227
 Use-after-free vulnerability in Adobe Flash Player before 18.0.0.366 and 19.x through 22.x before 22.0.0.209 on Windows and OS X and before 11.2.202.632 on Linux allows attackers to execute arbitrary code via unspecified vectors, a different vulnerability than CVE-2016-4173, CVE-2016-4174, CVE-2016-4222, CVE-2016-4226, CVE-2016-4228, CVE-2016-4229, CVE-2016-4230, CVE-2016-4231, and CVE-2016-4248.

- [https://github.com/Live-Hack-CVE/CVE-2016-4227](https://github.com/Live-Hack-CVE/CVE-2016-4227) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-4227.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-4227.svg)
- [https://github.com/Live-Hack-CVE/CVE-2016-4222](https://github.com/Live-Hack-CVE/CVE-2016-4222) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-4222.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-4222.svg)
- [https://github.com/Live-Hack-CVE/CVE-2016-4226](https://github.com/Live-Hack-CVE/CVE-2016-4226) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-4226.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-4226.svg)


## CVE-2016-4226
 Use-after-free vulnerability in Adobe Flash Player before 18.0.0.366 and 19.x through 22.x before 22.0.0.209 on Windows and OS X and before 11.2.202.632 on Linux allows attackers to execute arbitrary code via unspecified vectors, a different vulnerability than CVE-2016-4173, CVE-2016-4174, CVE-2016-4222, CVE-2016-4227, CVE-2016-4228, CVE-2016-4229, CVE-2016-4230, CVE-2016-4231, and CVE-2016-4248.

- [https://github.com/Live-Hack-CVE/CVE-2016-4226](https://github.com/Live-Hack-CVE/CVE-2016-4226) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-4226.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-4226.svg)
- [https://github.com/Live-Hack-CVE/CVE-2016-4228](https://github.com/Live-Hack-CVE/CVE-2016-4228) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-4228.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-4228.svg)
- [https://github.com/Live-Hack-CVE/CVE-2016-4227](https://github.com/Live-Hack-CVE/CVE-2016-4227) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-4227.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-4227.svg)
- [https://github.com/Live-Hack-CVE/CVE-2016-4231](https://github.com/Live-Hack-CVE/CVE-2016-4231) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-4231.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-4231.svg)
- [https://github.com/Live-Hack-CVE/CVE-2016-4229](https://github.com/Live-Hack-CVE/CVE-2016-4229) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-4229.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-4229.svg)
- [https://github.com/Live-Hack-CVE/CVE-2016-4248](https://github.com/Live-Hack-CVE/CVE-2016-4248) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-4248.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-4248.svg)
- [https://github.com/Live-Hack-CVE/CVE-2016-7020](https://github.com/Live-Hack-CVE/CVE-2016-7020) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-7020.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-7020.svg)
- [https://github.com/Live-Hack-CVE/CVE-2016-4230](https://github.com/Live-Hack-CVE/CVE-2016-4230) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-4230.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-4230.svg)
- [https://github.com/Live-Hack-CVE/CVE-2016-4222](https://github.com/Live-Hack-CVE/CVE-2016-4222) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-4222.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-4222.svg)


## CVE-2016-4225
 Adobe Flash Player before 18.0.0.366 and 19.x through 22.x before 22.0.0.209 on Windows and OS X and before 11.2.202.632 on Linux allows attackers to execute arbitrary code by leveraging an unspecified &quot;type confusion,&quot; a different vulnerability than CVE-2016-4223 and CVE-2016-4224.

- [https://github.com/Live-Hack-CVE/CVE-2016-4225](https://github.com/Live-Hack-CVE/CVE-2016-4225) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-4225.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-4225.svg)
- [https://github.com/Live-Hack-CVE/CVE-2016-4224](https://github.com/Live-Hack-CVE/CVE-2016-4224) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-4224.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-4224.svg)
- [https://github.com/Live-Hack-CVE/CVE-2016-4223](https://github.com/Live-Hack-CVE/CVE-2016-4223) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-4223.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-4223.svg)


## CVE-2016-4224
 Adobe Flash Player before 18.0.0.366 and 19.x through 22.x before 22.0.0.209 on Windows and OS X and before 11.2.202.632 on Linux allows attackers to execute arbitrary code by leveraging an unspecified &quot;type confusion,&quot; a different vulnerability than CVE-2016-4223 and CVE-2016-4225.

- [https://github.com/Live-Hack-CVE/CVE-2016-4224](https://github.com/Live-Hack-CVE/CVE-2016-4224) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-4224.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-4224.svg)
- [https://github.com/Live-Hack-CVE/CVE-2016-4223](https://github.com/Live-Hack-CVE/CVE-2016-4223) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-4223.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-4223.svg)
- [https://github.com/Live-Hack-CVE/CVE-2016-4225](https://github.com/Live-Hack-CVE/CVE-2016-4225) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-4225.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-4225.svg)


## CVE-2016-4223
 Adobe Flash Player before 18.0.0.366 and 19.x through 22.x before 22.0.0.209 on Windows and OS X and before 11.2.202.632 on Linux allows attackers to execute arbitrary code by leveraging an unspecified &quot;type confusion,&quot; a different vulnerability than CVE-2016-4224 and CVE-2016-4225.

- [https://github.com/Live-Hack-CVE/CVE-2016-4223](https://github.com/Live-Hack-CVE/CVE-2016-4223) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-4223.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-4223.svg)
- [https://github.com/Live-Hack-CVE/CVE-2016-4224](https://github.com/Live-Hack-CVE/CVE-2016-4224) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-4224.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-4224.svg)
- [https://github.com/Live-Hack-CVE/CVE-2016-4225](https://github.com/Live-Hack-CVE/CVE-2016-4225) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-4225.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-4225.svg)


## CVE-2016-4222
 Use-after-free vulnerability in Adobe Flash Player before 18.0.0.366 and 19.x through 22.x before 22.0.0.209 on Windows and OS X and before 11.2.202.632 on Linux allows attackers to execute arbitrary code via unspecified vectors, a different vulnerability than CVE-2016-4173, CVE-2016-4174, CVE-2016-4226, CVE-2016-4227, CVE-2016-4228, CVE-2016-4229, CVE-2016-4230, CVE-2016-4231, and CVE-2016-4248.

- [https://github.com/Live-Hack-CVE/CVE-2016-4222](https://github.com/Live-Hack-CVE/CVE-2016-4222) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-4222.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-4222.svg)
- [https://github.com/Live-Hack-CVE/CVE-2016-4230](https://github.com/Live-Hack-CVE/CVE-2016-4230) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-4230.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-4230.svg)
- [https://github.com/Live-Hack-CVE/CVE-2016-4226](https://github.com/Live-Hack-CVE/CVE-2016-4226) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-4226.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-4226.svg)
- [https://github.com/Live-Hack-CVE/CVE-2016-4229](https://github.com/Live-Hack-CVE/CVE-2016-4229) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-4229.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-4229.svg)
- [https://github.com/Live-Hack-CVE/CVE-2016-4248](https://github.com/Live-Hack-CVE/CVE-2016-4248) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-4248.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-4248.svg)
- [https://github.com/Live-Hack-CVE/CVE-2016-4228](https://github.com/Live-Hack-CVE/CVE-2016-4228) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-4228.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-4228.svg)
- [https://github.com/Live-Hack-CVE/CVE-2016-4227](https://github.com/Live-Hack-CVE/CVE-2016-4227) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-4227.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-4227.svg)
- [https://github.com/Live-Hack-CVE/CVE-2016-7020](https://github.com/Live-Hack-CVE/CVE-2016-7020) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-7020.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-7020.svg)
- [https://github.com/Live-Hack-CVE/CVE-2016-4231](https://github.com/Live-Hack-CVE/CVE-2016-4231) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-4231.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-4231.svg)


## CVE-2016-4174
 Use-after-free vulnerability in Adobe Flash Player before 18.0.0.366 and 19.x through 22.x before 22.0.0.209 on Windows and OS X and before 11.2.202.632 on Linux allows attackers to execute arbitrary code via unspecified vectors, a different vulnerability than CVE-2016-4173, CVE-2016-4222, CVE-2016-4226, CVE-2016-4227, CVE-2016-4228, CVE-2016-4229, CVE-2016-4230, CVE-2016-4231, and CVE-2016-4248.

- [https://github.com/Live-Hack-CVE/CVE-2016-4227](https://github.com/Live-Hack-CVE/CVE-2016-4227) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-4227.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-4227.svg)
- [https://github.com/Live-Hack-CVE/CVE-2016-4228](https://github.com/Live-Hack-CVE/CVE-2016-4228) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-4228.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-4228.svg)
- [https://github.com/Live-Hack-CVE/CVE-2016-4230](https://github.com/Live-Hack-CVE/CVE-2016-4230) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-4230.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-4230.svg)
- [https://github.com/Live-Hack-CVE/CVE-2016-4226](https://github.com/Live-Hack-CVE/CVE-2016-4226) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-4226.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-4226.svg)
- [https://github.com/Live-Hack-CVE/CVE-2016-4248](https://github.com/Live-Hack-CVE/CVE-2016-4248) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-4248.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-4248.svg)
- [https://github.com/Live-Hack-CVE/CVE-2016-4229](https://github.com/Live-Hack-CVE/CVE-2016-4229) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-4229.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-4229.svg)
- [https://github.com/Live-Hack-CVE/CVE-2016-4231](https://github.com/Live-Hack-CVE/CVE-2016-4231) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-4231.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-4231.svg)
- [https://github.com/Live-Hack-CVE/CVE-2016-4222](https://github.com/Live-Hack-CVE/CVE-2016-4222) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-4222.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-4222.svg)
- [https://github.com/Live-Hack-CVE/CVE-2016-7020](https://github.com/Live-Hack-CVE/CVE-2016-7020) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-7020.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-7020.svg)


## CVE-2016-4173
 Use-after-free vulnerability in Adobe Flash Player before 18.0.0.366 and 19.x through 22.x before 22.0.0.209 on Windows and OS X and before 11.2.202.632 on Linux allows attackers to execute arbitrary code via unspecified vectors, a different vulnerability than CVE-2016-4174, CVE-2016-4222, CVE-2016-4226, CVE-2016-4227, CVE-2016-4228, CVE-2016-4229, CVE-2016-4230, CVE-2016-4231, and CVE-2016-4248.

- [https://github.com/Live-Hack-CVE/CVE-2016-4231](https://github.com/Live-Hack-CVE/CVE-2016-4231) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-4231.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-4231.svg)
- [https://github.com/Live-Hack-CVE/CVE-2016-4230](https://github.com/Live-Hack-CVE/CVE-2016-4230) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-4230.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-4230.svg)
- [https://github.com/Live-Hack-CVE/CVE-2016-4226](https://github.com/Live-Hack-CVE/CVE-2016-4226) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-4226.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-4226.svg)
- [https://github.com/Live-Hack-CVE/CVE-2016-4227](https://github.com/Live-Hack-CVE/CVE-2016-4227) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-4227.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-4227.svg)
- [https://github.com/Live-Hack-CVE/CVE-2016-4228](https://github.com/Live-Hack-CVE/CVE-2016-4228) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-4228.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-4228.svg)
- [https://github.com/Live-Hack-CVE/CVE-2016-4248](https://github.com/Live-Hack-CVE/CVE-2016-4248) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-4248.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-4248.svg)
- [https://github.com/Live-Hack-CVE/CVE-2016-4229](https://github.com/Live-Hack-CVE/CVE-2016-4229) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-4229.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-4229.svg)
- [https://github.com/Live-Hack-CVE/CVE-2016-4222](https://github.com/Live-Hack-CVE/CVE-2016-4222) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-4222.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-4222.svg)
- [https://github.com/Live-Hack-CVE/CVE-2016-7020](https://github.com/Live-Hack-CVE/CVE-2016-7020) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-7020.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-7020.svg)


## CVE-2016-2183
 The DES and Triple DES ciphers, as used in the TLS, SSH, and IPSec protocols and other protocols and products, have a birthday bound of approximately four billion blocks, which makes it easier for remote attackers to obtain cleartext data via a birthday attack against a long-duration encrypted session, as demonstrated by an HTTPS session using Triple DES in CBC mode, aka a &quot;Sweet32&quot; attack.

- [https://github.com/Live-Hack-CVE/CVE-2023-0296](https://github.com/Live-Hack-CVE/CVE-2023-0296) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0296.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0296.svg)


## CVE-2016-1031
 Use-after-free vulnerability in Adobe Flash Player before 18.0.0.343 and 19.x through 21.x before 21.0.0.213 on Windows and OS X and before 11.2.202.616 on Linux allows attackers to execute arbitrary code via unspecified vectors, a different vulnerability than CVE-2016-1011, CVE-2016-1013, CVE-2016-1016, and CVE-2016-1017.

- [https://github.com/Live-Hack-CVE/CVE-2016-1031](https://github.com/Live-Hack-CVE/CVE-2016-1031) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-1031.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-1031.svg)


## CVE-2016-1017
 Use-after-free vulnerability in the LoadVars.decode function in Adobe Flash Player before 18.0.0.343 and 19.x through 21.x before 21.0.0.213 on Windows and OS X and before 11.2.202.616 on Linux allows attackers to execute arbitrary code via unspecified vectors, a different vulnerability than CVE-2016-1011, CVE-2016-1013, CVE-2016-1016, and CVE-2016-1031.

- [https://github.com/Live-Hack-CVE/CVE-2016-1017](https://github.com/Live-Hack-CVE/CVE-2016-1017) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-1017.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-1017.svg)
- [https://github.com/Live-Hack-CVE/CVE-2016-1013](https://github.com/Live-Hack-CVE/CVE-2016-1013) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-1013.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-1013.svg)
- [https://github.com/Live-Hack-CVE/CVE-2016-1011](https://github.com/Live-Hack-CVE/CVE-2016-1011) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-1011.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-1011.svg)


## CVE-2016-1016
 Use-after-free vulnerability in the Transform object implementation in Adobe Flash Player before 18.0.0.343 and 19.x through 21.x before 21.0.0.213 on Windows and OS X and before 11.2.202.616 on Linux allows attackers to execute arbitrary code via a flash.geom.Matrix callback, a different vulnerability than CVE-2016-1011, CVE-2016-1013, CVE-2016-1017, and CVE-2016-1031.

- [https://github.com/Live-Hack-CVE/CVE-2016-1016](https://github.com/Live-Hack-CVE/CVE-2016-1016) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-1016.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-1016.svg)
- [https://github.com/Live-Hack-CVE/CVE-2016-1013](https://github.com/Live-Hack-CVE/CVE-2016-1013) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-1013.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-1013.svg)
- [https://github.com/Live-Hack-CVE/CVE-2016-1011](https://github.com/Live-Hack-CVE/CVE-2016-1011) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-1011.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-1011.svg)
- [https://github.com/Live-Hack-CVE/CVE-2016-1031](https://github.com/Live-Hack-CVE/CVE-2016-1031) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-1031.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-1031.svg)


## CVE-2016-1013
 Use-after-free vulnerability in Adobe Flash Player before 18.0.0.343 and 19.x through 21.x before 21.0.0.213 on Windows and OS X and before 11.2.202.616 on Linux allows attackers to execute arbitrary code via unspecified vectors, a different vulnerability than CVE-2016-1011, CVE-2016-1016, CVE-2016-1017, and CVE-2016-1031.

- [https://github.com/Live-Hack-CVE/CVE-2016-1013](https://github.com/Live-Hack-CVE/CVE-2016-1013) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-1013.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-1013.svg)
- [https://github.com/Live-Hack-CVE/CVE-2016-1011](https://github.com/Live-Hack-CVE/CVE-2016-1011) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-1011.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-1011.svg)
- [https://github.com/Live-Hack-CVE/CVE-2016-1031](https://github.com/Live-Hack-CVE/CVE-2016-1031) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-1031.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-1031.svg)


## CVE-2016-1011
 Use-after-free vulnerability in Adobe Flash Player before 18.0.0.343 and 19.x through 21.x before 21.0.0.213 on Windows and OS X and before 11.2.202.616 on Linux allows attackers to execute arbitrary code via unspecified vectors, a different vulnerability than CVE-2016-1013, CVE-2016-1016, CVE-2016-1017, and CVE-2016-1031.

- [https://github.com/Live-Hack-CVE/CVE-2016-1011](https://github.com/Live-Hack-CVE/CVE-2016-1011) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-1011.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-1011.svg)
- [https://github.com/Live-Hack-CVE/CVE-2016-1013](https://github.com/Live-Hack-CVE/CVE-2016-1013) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-1013.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-1013.svg)
- [https://github.com/Live-Hack-CVE/CVE-2016-1031](https://github.com/Live-Hack-CVE/CVE-2016-1031) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-1031.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-1031.svg)
- [https://github.com/Live-Hack-CVE/CVE-2016-1017](https://github.com/Live-Hack-CVE/CVE-2016-1017) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-1017.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-1017.svg)


## CVE-2014-2383
 dompdf.php in dompdf before 0.6.1, when DOMPDF_ENABLE_PHP is enabled, allows context-dependent attackers to bypass chroot protections and read arbitrary files via a PHP protocol and wrappers in the input_file parameter, as demonstrated by a php://filter/read=convert.base64-encode/resource in the input_file parameter.

- [https://github.com/Live-Hack-CVE/CVE-2014-2383](https://github.com/Live-Hack-CVE/CVE-2014-2383) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2014-2383.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2014-2383.svg)
- [https://github.com/Relativ3Pa1n/CVE-2014-2383-LFI-to-RCE-Escalation](https://github.com/Relativ3Pa1n/CVE-2014-2383-LFI-to-RCE-Escalation) :  ![starts](https://img.shields.io/github/stars/Relativ3Pa1n/CVE-2014-2383-LFI-to-RCE-Escalation.svg) ![forks](https://img.shields.io/github/forks/Relativ3Pa1n/CVE-2014-2383-LFI-to-RCE-Escalation.svg)

