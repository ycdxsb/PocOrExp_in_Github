# Update 2025-08-03
## CVE-2025-50472
 The modelscope/ms-swift library thru 2.6.1 is vulnerable to arbitrary code execution through deserialization of untrusted data within the `load_model_meta()` function of the `ModelFileSystemCache()` class. Attackers can execute arbitrary code and commands by crafting a malicious serialized `.mdl` payload, exploiting the use of `pickle.load()` on data from potentially untrusted sources. This vulnerability allows for remote code execution (RCE) by deceiving victims into loading a seemingly harmless checkpoint during a normal training process, thereby enabling attackers to execute arbitrary code on the targeted machine. Note that the payload file is a hidden file, making it difficult for the victim to detect tampering. More importantly, during the model training process, after the `.mdl` file is loaded and executes arbitrary code, the normal training process remains unaffected'meaning the user remains unaware of the arbitrary code execution.

- [https://github.com/xhjy2020/CVE-2025-50472](https://github.com/xhjy2020/CVE-2025-50472) :  ![starts](https://img.shields.io/github/stars/xhjy2020/CVE-2025-50472.svg) ![forks](https://img.shields.io/github/forks/xhjy2020/CVE-2025-50472.svg)


## CVE-2025-50460
 A remote code execution (RCE) vulnerability exists in the ms-swift project version 3.3.0 due to unsafe deserialization in tests/run.py using yaml.load() from the PyYAML library (versions = 5.3.1). If an attacker can control the content of the YAML configuration file passed to the --run_config parameter, arbitrary code can be executed during deserialization. This can lead to full system compromise. The vulnerability is triggered when a malicious YAML file is loaded, allowing the execution of arbitrary Python commands such as os.system(). It is recommended to upgrade PyYAML to version 5.4 or higher, and to use yaml.safe_load() to mitigate the issue.

- [https://github.com/Anchor0221/CVE-2025-50460](https://github.com/Anchor0221/CVE-2025-50460) :  ![starts](https://img.shields.io/github/stars/Anchor0221/CVE-2025-50460.svg) ![forks](https://img.shields.io/github/forks/Anchor0221/CVE-2025-50460.svg)


## CVE-2025-48384
 Git is a fast, scalable, distributed revision control system with an unusually rich command set that provides both high-level operations and full access to internals. When reading a config value, Git strips any trailing carriage return and line feed (CRLF). When writing a config entry, values with a trailing CR are not quoted, causing the CR to be lost when the config is later read. When initializing a submodule, if the submodule path contains a trailing CR, the altered path is read resulting in the submodule being checked out to an incorrect location. If a symlink exists that points the altered path to the submodule hooks directory, and the submodule contains an executable post-checkout hook, the script may be unintentionally executed after checkout. This vulnerability is fixed in v2.43.7, v2.44.4, v2.45.4, v2.46.4, v2.47.3, v2.48.2, v2.49.1, and v2.50.1.

- [https://github.com/f1shh/CVE-2025-48384](https://github.com/f1shh/CVE-2025-48384) :  ![starts](https://img.shields.io/github/stars/f1shh/CVE-2025-48384.svg) ![forks](https://img.shields.io/github/forks/f1shh/CVE-2025-48384.svg)


## CVE-2025-46018
 CSC Pay Mobile App 2.19.4 (fixed in version 2.20.0) contains a vulnerability allowing users to bypass payment authorization by disabling Bluetooth at a specific point during a transaction. This could result in unauthorized use of laundry services and potential financial loss.

- [https://github.com/niranjangaire1995/CVE-2025-46018-CSC-Pay-Mobile-App-Payment-Authentication-Bypass](https://github.com/niranjangaire1995/CVE-2025-46018-CSC-Pay-Mobile-App-Payment-Authentication-Bypass) :  ![starts](https://img.shields.io/github/stars/niranjangaire1995/CVE-2025-46018-CSC-Pay-Mobile-App-Payment-Authentication-Bypass.svg) ![forks](https://img.shields.io/github/forks/niranjangaire1995/CVE-2025-46018-CSC-Pay-Mobile-App-Payment-Authentication-Bypass.svg)


## CVE-2025-45778
 A stored cross-site scripting (XSS) vulnerability in The Language Sloth Web Application v1.0 allows attackers to execute arbitrary web scripts or HTML via injecting a crafted payload into the Description text field.

- [https://github.com/Smarttfoxx/CVE-2025-45778](https://github.com/Smarttfoxx/CVE-2025-45778) :  ![starts](https://img.shields.io/github/stars/Smarttfoxx/CVE-2025-45778.svg) ![forks](https://img.shields.io/github/forks/Smarttfoxx/CVE-2025-45778.svg)


## CVE-2025-41373
 A SQL injection vulnerability has been found in Gandia Integra Total of TESI from version 2.1.2217.3 to v4.4.2236.1. The vulnerability allows an authenticated attacker to retrieve, create, update and delete databases through the 'idestudio' parameter in /encuestas/integraweb[_v4]/integra/html/view/hislistadoacciones.php.

- [https://github.com/byteReaper77/CVE-2025-41373](https://github.com/byteReaper77/CVE-2025-41373) :  ![starts](https://img.shields.io/github/stars/byteReaper77/CVE-2025-41373.svg) ![forks](https://img.shields.io/github/forks/byteReaper77/CVE-2025-41373.svg)


## CVE-2025-20229
 In Splunk Enterprise versions below 9.3.3, 9.2.5,  and 9.1.8, and Splunk Cloud Platform versions below 9.3.2408.104, 9.2.2406.108, 9.2.2403.114, and 9.1.2312.208, a low-privileged user that does not hold the "admin" or "power" Splunk roles could perform a Remote Code Execution (RCE) through a file upload to the "$SPLUNK_HOME/var/run/splunk/apptemp" directory due to missing authorization checks.

- [https://github.com/allinsthon/CVE-2025-20229](https://github.com/allinsthon/CVE-2025-20229) :  ![starts](https://img.shields.io/github/stars/allinsthon/CVE-2025-20229.svg) ![forks](https://img.shields.io/github/forks/allinsthon/CVE-2025-20229.svg)


## CVE-2025-5042
 A maliciously crafted RFA file, when parsed through Autodesk Revit, can force an Out-of-Bounds Read vulnerability. A malicious actor can leverage this vulnerability to cause a crash, read sensitive data, or execute arbitrary code in the context of the current process.

- [https://github.com/Landw-hub/CVE-2025-50420](https://github.com/Landw-hub/CVE-2025-50420) :  ![starts](https://img.shields.io/github/stars/Landw-hub/CVE-2025-50420.svg) ![forks](https://img.shields.io/github/forks/Landw-hub/CVE-2025-50420.svg)
- [https://github.com/Landw-hub/CVE-2025-50422](https://github.com/Landw-hub/CVE-2025-50422) :  ![starts](https://img.shields.io/github/stars/Landw-hub/CVE-2025-50422.svg) ![forks](https://img.shields.io/github/forks/Landw-hub/CVE-2025-50422.svg)


## CVE-2025-4870
 A vulnerability classified as critical was found in itsourcecode Restaurant Management System 1.0. This vulnerability affects unknown code of the file /admin/menu_save.php. The manipulation of the argument menu leads to sql injection. The attack can be initiated remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/itstarsec/CVE-2025-48703](https://github.com/itstarsec/CVE-2025-48703) :  ![starts](https://img.shields.io/github/stars/itstarsec/CVE-2025-48703.svg) ![forks](https://img.shields.io/github/forks/itstarsec/CVE-2025-48703.svg)


## CVE-2024-27804
 The issue was addressed with improved memory handling. This issue is fixed in iOS 17.5 and iPadOS 17.5, tvOS 17.5, watchOS 10.5, macOS Sonoma 14.5. An app may be able to execute arbitrary code with kernel privileges.

- [https://github.com/a0zhar/QuarkPoC](https://github.com/a0zhar/QuarkPoC) :  ![starts](https://img.shields.io/github/stars/a0zhar/QuarkPoC.svg) ![forks](https://img.shields.io/github/forks/a0zhar/QuarkPoC.svg)


## CVE-2024-8517
remote and unauthenticated attacker can execute arbitrary operating system commands by sending a crafted multipart file upload HTTP request.

- [https://github.com/saadhassan77/SPIP-BigUp-Unauthenticated-RCE-Exploit-CVE-2024-8517](https://github.com/saadhassan77/SPIP-BigUp-Unauthenticated-RCE-Exploit-CVE-2024-8517) :  ![starts](https://img.shields.io/github/stars/saadhassan77/SPIP-BigUp-Unauthenticated-RCE-Exploit-CVE-2024-8517.svg) ![forks](https://img.shields.io/github/forks/saadhassan77/SPIP-BigUp-Unauthenticated-RCE-Exploit-CVE-2024-8517.svg)


## CVE-2022-22965
 A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the application to run on Tomcat as a WAR deployment. If the application is deployed as a Spring Boot executable jar, i.e. the default, it is not vulnerable to the exploit. However, the nature of the vulnerability is more general, and there may be other ways to exploit it.

- [https://github.com/osungjinwoo/CVE-2022-22965](https://github.com/osungjinwoo/CVE-2022-22965) :  ![starts](https://img.shields.io/github/stars/osungjinwoo/CVE-2022-22965.svg) ![forks](https://img.shields.io/github/forks/osungjinwoo/CVE-2022-22965.svg)
- [https://github.com/Nosie12/fire-wall-server](https://github.com/Nosie12/fire-wall-server) :  ![starts](https://img.shields.io/github/stars/Nosie12/fire-wall-server.svg) ![forks](https://img.shields.io/github/forks/Nosie12/fire-wall-server.svg)


## CVE-2020-21365
 Directory traversal vulnerability in wkhtmltopdf through 0.12.5 allows remote attackers to read local files and disclose sensitive information via a crafted html file running with the default configurations.

- [https://github.com/andrei2308/CVE-2020-21365-PoC](https://github.com/andrei2308/CVE-2020-21365-PoC) :  ![starts](https://img.shields.io/github/stars/andrei2308/CVE-2020-21365-PoC.svg) ![forks](https://img.shields.io/github/forks/andrei2308/CVE-2020-21365-PoC.svg)


## CVE-2020-0796
 A remote code execution vulnerability exists in the way that the Microsoft Server Message Block 3.1.1 (SMBv3) protocol handles certain requests, aka 'Windows SMBv3 Client/Server Remote Code Execution Vulnerability'.

- [https://github.com/cybermads/CVE-2020-0796](https://github.com/cybermads/CVE-2020-0796) :  ![starts](https://img.shields.io/github/stars/cybermads/CVE-2020-0796.svg) ![forks](https://img.shields.io/github/forks/cybermads/CVE-2020-0796.svg)


## CVE-2019-1003000
 A sandbox bypass vulnerability exists in Script Security Plugin 1.49 and earlier in src/main/java/org/jenkinsci/plugins/scriptsecurity/sandbox/groovy/GroovySandbox.java that allows attackers with the ability to provide sandboxed scripts to execute arbitrary code on the Jenkins master JVM.

- [https://github.com/kiko123746/security-pipeline](https://github.com/kiko123746/security-pipeline) :  ![starts](https://img.shields.io/github/stars/kiko123746/security-pipeline.svg) ![forks](https://img.shields.io/github/forks/kiko123746/security-pipeline.svg)


## CVE-2017-12629
 Remote code execution occurs in Apache Solr before 7.1 with Apache Lucene before 7.1 by exploiting XXE in conjunction with use of a Config API add-listener command to reach the RunExecutableListener class. Elasticsearch, although it uses Lucene, is NOT vulnerable to this. Note that the XML external entity expansion vulnerability occurs in the XML Query Parser which is available, by default, for any query request with parameters deftype=xmlparser and can be exploited to upload malicious data to the /upload request handler or as Blind XXE using ftp wrapper in order to read arbitrary local files from the Solr server. Note also that the second vulnerability relates to remote code execution using the RunExecutableListener available on all affected versions of Solr.

- [https://github.com/captain-woof/cve-2017-12629](https://github.com/captain-woof/cve-2017-12629) :  ![starts](https://img.shields.io/github/stars/captain-woof/cve-2017-12629.svg) ![forks](https://img.shields.io/github/forks/captain-woof/cve-2017-12629.svg)


## CVE-2011-2523
 vsftpd 2.3.4 downloaded between 20110630 and 20110703 contains a backdoor which opens a shell on port 6200/tcp.

- [https://github.com/cybermads/CVE-2011-2523](https://github.com/cybermads/CVE-2011-2523) :  ![starts](https://img.shields.io/github/stars/cybermads/CVE-2011-2523.svg) ![forks](https://img.shields.io/github/forks/cybermads/CVE-2011-2523.svg)

