# Update 2024-11-05
## CVE-2024-37383
 Roundcube Webmail before 1.5.7 and 1.6.x before 1.6.7 allows XSS via SVG animate attributes.

- [https://github.com/amirzargham/CVE-2024-37383-exploit](https://github.com/amirzargham/CVE-2024-37383-exploit) :  ![starts](https://img.shields.io/github/stars/amirzargham/CVE-2024-37383-exploit.svg) ![forks](https://img.shields.io/github/forks/amirzargham/CVE-2024-37383-exploit.svg)


## CVE-2024-36823
 The encrypt() function of Ninja Core v7.0.0 was discovered to use a weak cryptographic algorithm, leading to a possible leakage of sensitive information.

- [https://github.com/JAckLosingHeart/CVE-2024-36823-POC](https://github.com/JAckLosingHeart/CVE-2024-36823-POC) :  ![starts](https://img.shields.io/github/stars/JAckLosingHeart/CVE-2024-36823-POC.svg) ![forks](https://img.shields.io/github/forks/JAckLosingHeart/CVE-2024-36823-POC.svg)


## CVE-2024-24576
 Rust is a programming language. The Rust Security Response WG was notified that the Rust standard library prior to version 1.77.2 did not properly escape arguments when invoking batch files (with the `bat` and `cmd` extensions) on Windows using the `Command`. An attacker able to control the arguments passed to the spawned process could execute arbitrary shell commands by bypassing the escaping. The severity of this vulnerability is critical for those who invoke batch files on Windows with untrusted arguments. No other platform or use is affected. The `Command::arg` and `Command::args` APIs state in their documentation that the arguments will be passed to the spawned process as-is, regardless of the content of the arguments, and will not be evaluated by a shell. This means it should be safe to pass untrusted input as an argument. On Windows, the implementation of this is more complex than other platforms, because the Windows API only provides a single string containing all the arguments to the spawned process, and it's up to the spawned process to split them. Most programs use the standard C run-time argv, which in practice results in a mostly consistent way arguments are splitted. One exception though is `cmd.exe` (used among other things to execute batch files), which has its own argument splitting logic. That forces the standard library to implement custom escaping for arguments passed to batch files. Unfortunately it was reported that our escaping logic was not thorough enough, and it was possible to pass malicious arguments that would result in arbitrary shell execution. Due to the complexity of `cmd.exe`, we didn't identify a solution that would correctly escape arguments in all cases. To maintain our API guarantees, we improved the robustness of the escaping code, and changed the `Command` API to return an `InvalidInput` error when it cannot safely escape an argument. This error will be emitted when spawning the process. The fix is included in Rust 1.77.2. Note that the new escaping logic for batch files errs on the conservative side, and could reject valid arguments. Those who implement the escaping themselves or only handle trusted inputs on Windows can also use the `CommandExt::raw_arg` method to bypass the standard library's escaping logic.

- [https://github.com/mishl-dev/CVE-2024-24576-PoC-Python](https://github.com/mishl-dev/CVE-2024-24576-PoC-Python) :  ![starts](https://img.shields.io/github/stars/mishl-dev/CVE-2024-24576-PoC-Python.svg) ![forks](https://img.shields.io/github/forks/mishl-dev/CVE-2024-24576-PoC-Python.svg)


## CVE-2024-5135
 A vulnerability was found in PHPGurukul Directory Management System 1.0. It has been rated as critical. This issue affects some unknown processing of the file /admin/index.php. The manipulation of the argument username leads to sql injection. The attack may be initiated remotely. The exploit has been disclosed to the public and may be used. The associated identifier of this vulnerability is VDB-265211.

- [https://github.com/Kov404/CVE-2024-51358](https://github.com/Kov404/CVE-2024-51358) :  ![starts](https://img.shields.io/github/stars/Kov404/CVE-2024-51358.svg) ![forks](https://img.shields.io/github/forks/Kov404/CVE-2024-51358.svg)


## CVE-2024-5113
 A vulnerability was found in Campcodes Complete Web-Based School Management System 1.0. It has been rated as critical. This issue affects some unknown processing of the file /view/student_profile1.php. The manipulation of the argument std_index leads to sql injection. The attack may be initiated remotely. The exploit has been disclosed to the public and may be used. The associated identifier of this vulnerability is VDB-265103.

- [https://github.com/JAckLosingHeart/CVE-2024-51132-POC](https://github.com/JAckLosingHeart/CVE-2024-51132-POC) :  ![starts](https://img.shields.io/github/stars/JAckLosingHeart/CVE-2024-51132-POC.svg) ![forks](https://img.shields.io/github/forks/JAckLosingHeart/CVE-2024-51132-POC.svg)


## CVE-2024-4832
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/osvaldotenorio/cve-2024-48325](https://github.com/osvaldotenorio/cve-2024-48325) :  ![starts](https://img.shields.io/github/stars/osvaldotenorio/cve-2024-48325.svg) ![forks](https://img.shields.io/github/forks/osvaldotenorio/cve-2024-48325.svg)
- [https://github.com/fabiobsj/CVE-2024-48326](https://github.com/fabiobsj/CVE-2024-48326) :  ![starts](https://img.shields.io/github/stars/fabiobsj/CVE-2024-48326.svg) ![forks](https://img.shields.io/github/forks/fabiobsj/CVE-2024-48326.svg)


## CVE-2024-4577
 In PHP versions 8.1.* before 8.1.29, 8.2.* before 8.2.20, 8.3.* before 8.3.8, when using Apache and PHP-CGI on Windows, if the system is set up to use certain code pages, Windows may use &quot;Best-Fit&quot; behavior to replace characters in command line given to Win32 API functions. PHP CGI module may misinterpret those characters as PHP options, which may allow a malicious user to pass options to PHP binary being run, and thus reveal the source code of scripts, run arbitrary PHP code on the server, etc.

- [https://github.com/ahmetramazank/CVE-2024-4577](https://github.com/ahmetramazank/CVE-2024-4577) :  ![starts](https://img.shields.io/github/stars/ahmetramazank/CVE-2024-4577.svg) ![forks](https://img.shields.io/github/forks/ahmetramazank/CVE-2024-4577.svg)


## CVE-2024-4425
 The access control in CemiPark software stores integration (e.g. FTP or SIP) credentials in plain-text. An attacker who gained unauthorized access to the device can retrieve clear text passwords used by the system.This issue affects CemiPark software: 4.5, 4.7, 5.03 and potentially others. The vendor refused to provide the specific range of affected products.

- [https://github.com/ifpdz/CVE-2024-44258](https://github.com/ifpdz/CVE-2024-44258) :  ![starts](https://img.shields.io/github/stars/ifpdz/CVE-2024-44258.svg) ![forks](https://img.shields.io/github/forks/ifpdz/CVE-2024-44258.svg)


## CVE-2024-1060
 Use after free in Canvas in Google Chrome prior to 121.0.6167.139 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/bevennyamande/CVE-2024-10605](https://github.com/bevennyamande/CVE-2024-10605) :  ![starts](https://img.shields.io/github/stars/bevennyamande/CVE-2024-10605.svg) ![forks](https://img.shields.io/github/forks/bevennyamande/CVE-2024-10605.svg)


## CVE-2023-27524
 Session Validation attacks in Apache Superset versions up to and including 2.0.1. Installations that have not altered the default configured SECRET_KEY according to installation instructions allow for an attacker to authenticate and access unauthorized resources. This does not affect Superset administrators who have changed the default value for SECRET_KEY config. All superset installations should always set a unique secure random SECRET_KEY. Your SECRET_KEY is used to securely sign all session cookies and encrypting sensitive information on the database. Add a strong SECRET_KEY to your `superset_config.py` file like: SECRET_KEY = &lt;YOUR_OWN_RANDOM_GENERATED_SECRET_KEY&gt; Alternatively you can set it with `SUPERSET_SECRET_KEY` environment variable.

- [https://github.com/h1n4mx0/Research-CVE-2023-27524](https://github.com/h1n4mx0/Research-CVE-2023-27524) :  ![starts](https://img.shields.io/github/stars/h1n4mx0/Research-CVE-2023-27524.svg) ![forks](https://img.shields.io/github/forks/h1n4mx0/Research-CVE-2023-27524.svg)


## CVE-2023-4220
 Unrestricted file upload in big file upload functionality in `/main/inc/lib/javascript/bigupload/inc/bigUpload.php` in Chamilo LMS &lt;= v1.11.24 allows unauthenticated attackers to perform stored cross-site scripting attacks and obtain remote code execution via uploading of web shell.

- [https://github.com/H4cking4All/CVE-2023-4220](https://github.com/H4cking4All/CVE-2023-4220) :  ![starts](https://img.shields.io/github/stars/H4cking4All/CVE-2023-4220.svg) ![forks](https://img.shields.io/github/forks/H4cking4All/CVE-2023-4220.svg)


## CVE-2020-1938
 When using the Apache JServ Protocol (AJP), care must be taken when trusting incoming connections to Apache Tomcat. Tomcat treats AJP connections as having higher trust than, for example, a similar HTTP connection. If such connections are available to an attacker, they can be exploited in ways that may be surprising. In Apache Tomcat 9.0.0.M1 to 9.0.0.30, 8.5.0 to 8.5.50 and 7.0.0 to 7.0.99, Tomcat shipped with an AJP Connector enabled by default that listened on all configured IP addresses. It was expected (and recommended in the security guide) that this Connector would be disabled if not required. This vulnerability report identified a mechanism that allowed: - returning arbitrary files from anywhere in the web application - processing any file in the web application as a JSP Further, if the web application allowed file upload and stored those files within the web application (or the attacker was able to control the content of the web application by some other means) then this, along with the ability to process a file as a JSP, made remote code execution possible. It is important to note that mitigation is only required if an AJP port is accessible to untrusted users. Users wishing to take a defence-in-depth approach and block the vector that permits returning arbitrary files and execution as JSP may upgrade to Apache Tomcat 9.0.31, 8.5.51 or 7.0.100 or later. A number of changes were made to the default AJP Connector configuration in 9.0.31 to harden the default configuration. It is likely that users upgrading to 9.0.31, 8.5.51 or 7.0.100 or later will need to make small changes to their configurations.

- [https://github.com/WHtig3r/CVE-2020-1938](https://github.com/WHtig3r/CVE-2020-1938) :  ![starts](https://img.shields.io/github/stars/WHtig3r/CVE-2020-1938.svg) ![forks](https://img.shields.io/github/forks/WHtig3r/CVE-2020-1938.svg)


## CVE-2016-5195
 Race condition in mm/gup.c in the Linux kernel 2.x through 4.x before 4.8.3 allows local users to gain privileges by leveraging incorrect handling of a copy-on-write (COW) feature to write to a read-only memory mapping, as exploited in the wild in October 2016, aka &quot;Dirty COW.&quot;

- [https://github.com/h1n4mx0/Research-CVE-2016-5195](https://github.com/h1n4mx0/Research-CVE-2016-5195) :  ![starts](https://img.shields.io/github/stars/h1n4mx0/Research-CVE-2016-5195.svg) ![forks](https://img.shields.io/github/forks/h1n4mx0/Research-CVE-2016-5195.svg)


## CVE-2015-3239
 Off-by-one error in the dwarf_to_unw_regnum function in include/dwarf_i.h in libunwind 1.1 allows local users to have unspecified impact via invalid dwarf opcodes.

- [https://github.com/RenukaSelvar/libunwind_CVE-2015-3239](https://github.com/RenukaSelvar/libunwind_CVE-2015-3239) :  ![starts](https://img.shields.io/github/stars/RenukaSelvar/libunwind_CVE-2015-3239.svg) ![forks](https://img.shields.io/github/forks/RenukaSelvar/libunwind_CVE-2015-3239.svg)
- [https://github.com/RenukaSelvar/libunwind_CVE-2015-3239_After](https://github.com/RenukaSelvar/libunwind_CVE-2015-3239_After) :  ![starts](https://img.shields.io/github/stars/RenukaSelvar/libunwind_CVE-2015-3239_After.svg) ![forks](https://img.shields.io/github/forks/RenukaSelvar/libunwind_CVE-2015-3239_After.svg)
- [https://github.com/RenukaSelvar/libunwind_CVE-2015-3239_AfterPatch](https://github.com/RenukaSelvar/libunwind_CVE-2015-3239_AfterPatch) :  ![starts](https://img.shields.io/github/stars/RenukaSelvar/libunwind_CVE-2015-3239_AfterPatch.svg) ![forks](https://img.shields.io/github/forks/RenukaSelvar/libunwind_CVE-2015-3239_AfterPatch.svg)


## CVE-2014-0195
 The dtls1_reassemble_fragment function in d1_both.c in OpenSSL before 0.9.8za, 1.0.0 before 1.0.0m, and 1.0.1 before 1.0.1h does not properly validate fragment lengths in DTLS ClientHello messages, which allows remote attackers to execute arbitrary code or cause a denial of service (buffer overflow and application crash) via a long non-initial fragment.

- [https://github.com/PezwariNaan/CVE-2014-0195](https://github.com/PezwariNaan/CVE-2014-0195) :  ![starts](https://img.shields.io/github/stars/PezwariNaan/CVE-2014-0195.svg) ![forks](https://img.shields.io/github/forks/PezwariNaan/CVE-2014-0195.svg)

