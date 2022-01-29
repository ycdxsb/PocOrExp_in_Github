# Update 2022-01-29
## CVE-2022-23307
 CVE-2020-9493 identified a deserialization issue that was present in Apache Chainsaw. Prior to Chainsaw V2.0 Chainsaw was a component of Apache Log4j 1.2.x where the same issue exists.

- [https://github.com/logpresso/CVE-2021-44228-Scanner](https://github.com/logpresso/CVE-2021-44228-Scanner) :  ![starts](https://img.shields.io/github/stars/logpresso/CVE-2021-44228-Scanner.svg) ![forks](https://img.shields.io/github/forks/logpresso/CVE-2021-44228-Scanner.svg)


## CVE-2022-23305
 By design, the JDBCAppender in Log4j 1.2.x accepts an SQL statement as a configuration parameter where the values to be inserted are converters from PatternLayout. The message converter, %m, is likely to always be included. This allows attackers to manipulate the SQL by entering crafted strings into input fields or headers of an application that are logged allowing unintended SQL queries to be executed. Note this issue only affects Log4j 1.x when specifically configured to use the JDBCAppender, which is not the default. Beginning in version 2.0-beta8, the JDBCAppender was re-introduced with proper support for parameterized SQL queries and further customization over the columns written to in logs. Apache Log4j 1.2 reached end of life in August 2015. Users should upgrade to Log4j 2 as it addresses numerous other issues from the previous versions.

- [https://github.com/logpresso/CVE-2021-44228-Scanner](https://github.com/logpresso/CVE-2021-44228-Scanner) :  ![starts](https://img.shields.io/github/stars/logpresso/CVE-2021-44228-Scanner.svg) ![forks](https://img.shields.io/github/forks/logpresso/CVE-2021-44228-Scanner.svg)


## CVE-2022-23302
 JMSSink in all versions of Log4j 1.x is vulnerable to deserialization of untrusted data when the attacker has write access to the Log4j configuration or if the configuration references an LDAP service the attacker has access to. The attacker can provide a TopicConnectionFactoryBindingName configuration causing JMSSink to perform JNDI requests that result in remote code execution in a similar fashion to CVE-2021-4104. Note this issue only affects Log4j 1.x when specifically configured to use JMSSink, which is not the default. Apache Log4j 1.2 reached end of life in August 2015. Users should upgrade to Log4j 2 as it addresses numerous other issues from the previous versions.

- [https://github.com/logpresso/CVE-2021-44228-Scanner](https://github.com/logpresso/CVE-2021-44228-Scanner) :  ![starts](https://img.shields.io/github/stars/logpresso/CVE-2021-44228-Scanner.svg) ![forks](https://img.shields.io/github/forks/logpresso/CVE-2021-44228-Scanner.svg)


## CVE-2022-0185
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/khaclep007/CVE-2022-0185](https://github.com/khaclep007/CVE-2022-0185) :  ![starts](https://img.shields.io/github/stars/khaclep007/CVE-2022-0185.svg) ![forks](https://img.shields.io/github/forks/khaclep007/CVE-2022-0185.svg)


## CVE-2021-46005
 Sourcecodester Car Rental Management System 1.0 is vulnerable to Cross Site Scripting (XSS) via vehicalorcview parameter.

- [https://github.com/nawed20002/CVE-2021-46005](https://github.com/nawed20002/CVE-2021-46005) :  ![starts](https://img.shields.io/github/stars/nawed20002/CVE-2021-46005.svg) ![forks](https://img.shields.io/github/forks/nawed20002/CVE-2021-46005.svg)


## CVE-2021-45416
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/86x/CVE-2021-45416](https://github.com/86x/CVE-2021-45416) :  ![starts](https://img.shields.io/github/stars/86x/CVE-2021-45416.svg) ![forks](https://img.shields.io/github/forks/86x/CVE-2021-45416.svg)


## CVE-2021-43789
 PrestaShop is an Open Source e-commerce web application. Versions of PrestaShop prior to 1.7.8.2 are vulnerable to blind SQL injection using search filters with `orderBy` and `sortOrder` parameters. The problem is fixed in version 1.7.8.2.

- [https://github.com/numanturle/CVE-2021-43789](https://github.com/numanturle/CVE-2021-43789) :  ![starts](https://img.shields.io/github/stars/numanturle/CVE-2021-43789.svg) ![forks](https://img.shields.io/github/forks/numanturle/CVE-2021-43789.svg)


## CVE-2021-25646
 Apache Druid includes the ability to execute user-provided JavaScript code embedded in various types of requests. This functionality is intended for use in high-trust environments, and is disabled by default. However, in Druid 0.20.0 and earlier, it is possible for an authenticated user to send a specially-crafted request that forces Druid to run user-provided JavaScript code for that request, regardless of server configuration. This can be leveraged to execute code on the target machine with the privileges of the Druid server process.

- [https://github.com/Ormicron/CVE-2021-25646-GUI](https://github.com/Ormicron/CVE-2021-25646-GUI) :  ![starts](https://img.shields.io/github/stars/Ormicron/CVE-2021-25646-GUI.svg) ![forks](https://img.shields.io/github/forks/Ormicron/CVE-2021-25646-GUI.svg)


## CVE-2021-21551
 Dell dbutil_2_3.sys driver contains an insufficient access control vulnerability which may lead to escalation of privileges, denial of service, or information disclosure. Local authenticated user access is required.

- [https://github.com/hfiref0x/KDU](https://github.com/hfiref0x/KDU) :  ![starts](https://img.shields.io/github/stars/hfiref0x/KDU.svg) ![forks](https://img.shields.io/github/forks/hfiref0x/KDU.svg)


## CVE-2021-4034
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/0xTRAW/CVE-2021-4034](https://github.com/0xTRAW/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/0xTRAW/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/0xTRAW/CVE-2021-4034.svg)
- [https://github.com/rayheffer/CVE-2021-4034](https://github.com/rayheffer/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/rayheffer/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/rayheffer/CVE-2021-4034.svg)
- [https://github.com/luckythandel/CVE-2021-4034](https://github.com/luckythandel/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/luckythandel/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/luckythandel/CVE-2021-4034.svg)
- [https://github.com/NiS3x/CVE-2021-4034](https://github.com/NiS3x/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/NiS3x/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/NiS3x/CVE-2021-4034.svg)
- [https://github.com/pengalaman-1t/CVE-2021-4034](https://github.com/pengalaman-1t/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/pengalaman-1t/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/pengalaman-1t/CVE-2021-4034.svg)
- [https://github.com/MedKH1684/Pwnkit-CVE-2021-4034](https://github.com/MedKH1684/Pwnkit-CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/MedKH1684/Pwnkit-CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/MedKH1684/Pwnkit-CVE-2021-4034.svg)
- [https://github.com/Plethore/CVE-2021-4034](https://github.com/Plethore/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/Plethore/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/Plethore/CVE-2021-4034.svg)
- [https://github.com/nikip72/CVE-2021-4034](https://github.com/nikip72/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/nikip72/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/nikip72/CVE-2021-4034.svg)
- [https://github.com/puckiestyle/CVE-2021-4034](https://github.com/puckiestyle/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/puckiestyle/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/puckiestyle/CVE-2021-4034.svg)
- [https://github.com/c3c/CVE-2021-4034](https://github.com/c3c/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/c3c/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/c3c/CVE-2021-4034.svg)
- [https://github.com/Fato07/Pwnkit-exploit](https://github.com/Fato07/Pwnkit-exploit) :  ![starts](https://img.shields.io/github/stars/Fato07/Pwnkit-exploit.svg) ![forks](https://img.shields.io/github/forks/Fato07/Pwnkit-exploit.svg)
- [https://github.com/DosAmp/pkwned](https://github.com/DosAmp/pkwned) :  ![starts](https://img.shields.io/github/stars/DosAmp/pkwned.svg) ![forks](https://img.shields.io/github/forks/DosAmp/pkwned.svg)
- [https://github.com/tahaafarooq/poppy](https://github.com/tahaafarooq/poppy) :  ![starts](https://img.shields.io/github/stars/tahaafarooq/poppy.svg) ![forks](https://img.shields.io/github/forks/tahaafarooq/poppy.svg)
- [https://github.com/n3onhacks/CVE-2021-4034-BASH-One-File-Exploit](https://github.com/n3onhacks/CVE-2021-4034-BASH-One-File-Exploit) :  ![starts](https://img.shields.io/github/stars/n3onhacks/CVE-2021-4034-BASH-One-File-Exploit.svg) ![forks](https://img.shields.io/github/forks/n3onhacks/CVE-2021-4034-BASH-One-File-Exploit.svg)
- [https://github.com/evdenis/lsm_bpf_check_argc0](https://github.com/evdenis/lsm_bpf_check_argc0) :  ![starts](https://img.shields.io/github/stars/evdenis/lsm_bpf_check_argc0.svg) ![forks](https://img.shields.io/github/forks/evdenis/lsm_bpf_check_argc0.svg)
- [https://github.com/jpmcb/pwnkit-go](https://github.com/jpmcb/pwnkit-go) :  ![starts](https://img.shields.io/github/stars/jpmcb/pwnkit-go.svg) ![forks](https://img.shields.io/github/forks/jpmcb/pwnkit-go.svg)


## CVE-2021-4032
 A vulnerability was found in the Linux kernel's KVM subsystem in arch/x86/kvm/lapic.c kvm_free_lapic when a failure allocation was detected. In this flaw the KVM subsystem may crash the kernel due to mishandling of memory errors that happens during VCPU construction, which allows an attacker with special user privilege to cause a denial of service. This flaw affects kernel versions prior to 5.15 rc7.

- [https://github.com/EstamelGG/CVE-2021-4032-NoGCC](https://github.com/EstamelGG/CVE-2021-4032-NoGCC) :  ![starts](https://img.shields.io/github/stars/EstamelGG/CVE-2021-4032-NoGCC.svg) ![forks](https://img.shields.io/github/forks/EstamelGG/CVE-2021-4032-NoGCC.svg)


## CVE-2021-4024
 A flaw was found in podman. The `podman machine` function (used to create and manage Podman virtual machine containing a Podman process) spawns a `gvproxy` process on the host system. The `gvproxy` API is accessible on port 7777 on all IP addresses on the host. If that port is open on the host's firewall, an attacker can potentially use the `gvproxy` API to forward ports on the host to ports in the VM, making private services on the VM accessible to the network. This issue could be also used to interrupt the host's services by forwarding all ports to the VM.

- [https://github.com/deoxykev/CVE-2021-4024-Rust](https://github.com/deoxykev/CVE-2021-4024-Rust) :  ![starts](https://img.shields.io/github/stars/deoxykev/CVE-2021-4024-Rust.svg) ![forks](https://img.shields.io/github/forks/deoxykev/CVE-2021-4024-Rust.svg)


## CVE-2021-3708
 D-Link router DSL-2750U with firmware vME1.16 or prior versions is vulnerable to OS command injection. An unauthenticated attacker on the local network may exploit this, with CVE-2021-3707, to execute any OS commands on the vulnerable device.

- [https://github.com/HadiMed/DSL-2750U-Full-chain](https://github.com/HadiMed/DSL-2750U-Full-chain) :  ![starts](https://img.shields.io/github/stars/HadiMed/DSL-2750U-Full-chain.svg) ![forks](https://img.shields.io/github/forks/HadiMed/DSL-2750U-Full-chain.svg)


## CVE-2021-3707
 D-Link router DSL-2750U with firmware vME1.16 or prior versions is vulnerable to unauthorized configuration modification. An unauthenticated attacker on the local network may exploit this, with CVE-2021-3708, to execute any OS commands on the vulnerable device.

- [https://github.com/HadiMed/DSL-2750U-Full-chain](https://github.com/HadiMed/DSL-2750U-Full-chain) :  ![starts](https://img.shields.io/github/stars/HadiMed/DSL-2750U-Full-chain.svg) ![forks](https://img.shields.io/github/forks/HadiMed/DSL-2750U-Full-chain.svg)


## CVE-2020-29599
 ImageMagick before 6.9.11-40 and 7.x before 7.0.10-40 mishandles the -authenticate option, which allows setting a password for password-protected PDF files. The user-controlled password was not properly escaped/sanitized and it was therefore possible to inject additional shell commands via coders/pdf.c.

- [https://github.com/genjix2/CVE-2020-29599](https://github.com/genjix2/CVE-2020-29599) :  ![starts](https://img.shields.io/github/stars/genjix2/CVE-2020-29599.svg) ![forks](https://img.shields.io/github/forks/genjix2/CVE-2020-29599.svg)


## CVE-2020-14882
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Console). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0, 12.2.1.4.0 and 14.1.1.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/Ormicron/CVE-2020-14882-GUI-Test](https://github.com/Ormicron/CVE-2020-14882-GUI-Test) :  ![starts](https://img.shields.io/github/stars/Ormicron/CVE-2020-14882-GUI-Test.svg) ![forks](https://img.shields.io/github/forks/Ormicron/CVE-2020-14882-GUI-Test.svg)


## CVE-2018-16763
 FUEL CMS 1.4.1 allows PHP Code Evaluation via the pages/select/ filter parameter or the preview/ data parameter. This can lead to Pre-Auth Remote Code Execution.

- [https://github.com/BrunoPincho/cve-2018-16763-rust](https://github.com/BrunoPincho/cve-2018-16763-rust) :  ![starts](https://img.shields.io/github/stars/BrunoPincho/cve-2018-16763-rust.svg) ![forks](https://img.shields.io/github/forks/BrunoPincho/cve-2018-16763-rust.svg)


## CVE-2018-15982
 Flash Player versions 31.0.0.153 and earlier, and 31.0.0.108 and earlier have a use after free vulnerability. Successful exploitation could lead to arbitrary code execution.

- [https://github.com/Ormicron/CVE-2018-15982_PoC](https://github.com/Ormicron/CVE-2018-15982_PoC) :  ![starts](https://img.shields.io/github/stars/Ormicron/CVE-2018-15982_PoC.svg) ![forks](https://img.shields.io/github/forks/Ormicron/CVE-2018-15982_PoC.svg)


## CVE-2018-14009
 Codiad through 2.8.4 allows Remote Code Execution, a different vulnerability than CVE-2017-11366 and CVE-2017-15689.

- [https://github.com/hidog123/Codiad-CVE-2018-14009](https://github.com/hidog123/Codiad-CVE-2018-14009) :  ![starts](https://img.shields.io/github/stars/hidog123/Codiad-CVE-2018-14009.svg) ![forks](https://img.shields.io/github/forks/hidog123/Codiad-CVE-2018-14009.svg)


## CVE-2017-15689
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem.  When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/hidog123/Codiad-CVE-2018-14009](https://github.com/hidog123/Codiad-CVE-2018-14009) :  ![starts](https://img.shields.io/github/stars/hidog123/Codiad-CVE-2018-14009.svg) ![forks](https://img.shields.io/github/forks/hidog123/Codiad-CVE-2018-14009.svg)


## CVE-2017-11366
 components/filemanager/class.filemanager.php in Codiad before 2.8.4 is vulnerable to remote command execution because shell commands can be embedded in parameter values, as demonstrated by search_file_type.

- [https://github.com/hidog123/Codiad-CVE-2018-14009](https://github.com/hidog123/Codiad-CVE-2018-14009) :  ![starts](https://img.shields.io/github/stars/hidog123/Codiad-CVE-2018-14009.svg) ![forks](https://img.shields.io/github/forks/hidog123/Codiad-CVE-2018-14009.svg)

