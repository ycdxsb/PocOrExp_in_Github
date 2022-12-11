# Update 2022-12-11
## CVE-2022-45025
 Markdown Preview Enhanced v0.6.5 and v0.19.6 for VSCode and Atom was discovered to contain a command injection vulnerability via the PDF file import function.

- [https://github.com/yuriisanin/CVE-2022-45025](https://github.com/yuriisanin/CVE-2022-45025) :  ![starts](https://img.shields.io/github/stars/yuriisanin/CVE-2022-45025.svg) ![forks](https://img.shields.io/github/forks/yuriisanin/CVE-2022-45025.svg)


## CVE-2022-42889
 Apache Commons Text performs variable interpolation, allowing properties to be dynamically evaluated and expanded. The standard format for interpolation is &quot;${prefix:name}&quot;, where &quot;prefix&quot; is used to locate an instance of org.apache.commons.text.lookup.StringLookup that performs the interpolation. Starting with version 1.5 and continuing through 1.9, the set of default Lookup instances included interpolators that could result in arbitrary code execution or contact with remote servers. These lookups are: - &quot;script&quot; - execute expressions using the JVM script execution engine (javax.script) - &quot;dns&quot; - resolve dns records - &quot;url&quot; - load values from urls, including from remote servers Applications using the interpolation defaults in the affected versions may be vulnerable to remote code execution or unintentional contact with remote servers if untrusted configuration values are used. Users are recommended to upgrade to Apache Commons Text 1.10.0, which disables the problematic interpolators by default.

- [https://github.com/f0ng/text4shellburpscanner](https://github.com/f0ng/text4shellburpscanner) :  ![starts](https://img.shields.io/github/stars/f0ng/text4shellburpscanner.svg) ![forks](https://img.shields.io/github/forks/f0ng/text4shellburpscanner.svg)


## CVE-2022-39253
 Git is an open source, scalable, distributed revision control system. Versions prior to 2.30.6, 2.31.5, 2.32.4, 2.33.5, 2.34.5, 2.35.5, 2.36.3, and 2.37.4 are subject to exposure of sensitive information to a malicious actor. When performing a local clone (where the source and target of the clone are on the same volume), Git copies the contents of the source's `$GIT_DIR/objects` directory into the destination by either creating hardlinks to the source contents, or copying them (if hardlinks are disabled via `--no-hardlinks`). A malicious actor could convince a victim to clone a repository with a symbolic link pointing at sensitive information on the victim's machine. This can be done either by having the victim clone a malicious repository on the same machine, or having them clone a malicious repository embedded as a bare repository via a submodule from any source, provided they clone with the `--recurse-submodules` option. Git does not create symbolic links in the `$GIT_DIR/objects` directory. The problem has been patched in the versions published on 2022-10-18, and backported to v2.30.x. Potential workarounds: Avoid cloning untrusted repositories using the `--local` optimization when on a shared machine, either by passing the `--no-local` option to `git clone` or cloning from a URL that uses the `file://` scheme. Alternatively, avoid cloning repositories from untrusted sources with `--recurse-submodules` or run `git config --global protocol.file.allow user`.

- [https://github.com/ssst0n3/docker-cve-2022-39253-poc](https://github.com/ssst0n3/docker-cve-2022-39253-poc) :  ![starts](https://img.shields.io/github/stars/ssst0n3/docker-cve-2022-39253-poc.svg) ![forks](https://img.shields.io/github/forks/ssst0n3/docker-cve-2022-39253-poc.svg)


## CVE-2022-36537
 ZK Framework v9.6.1, 9.6.0.1, 9.5.1.3, 9.0.1.2 and 8.6.4.1 allows attackers to access sensitive information via a crafted POST request sent to the component AuUploader.

- [https://github.com/Malwareman007/CVE-2022-36537](https://github.com/Malwareman007/CVE-2022-36537) :  ![starts](https://img.shields.io/github/stars/Malwareman007/CVE-2022-36537.svg) ![forks](https://img.shields.io/github/forks/Malwareman007/CVE-2022-36537.svg)
- [https://github.com/agnihackers/CVE-2022-36537-EXPLOIT](https://github.com/agnihackers/CVE-2022-36537-EXPLOIT) :  ![starts](https://img.shields.io/github/stars/agnihackers/CVE-2022-36537-EXPLOIT.svg) ![forks](https://img.shields.io/github/forks/agnihackers/CVE-2022-36537-EXPLOIT.svg)


## CVE-2022-2414
 Access to external entities when parsing XML documents can lead to XML external entity (XXE) attacks. This flaw allows a remote attacker to potentially retrieve the content of arbitrary files by sending specially crafted HTTP requests.

- [https://github.com/amitlttwo/CVE-2022-2414-Proof-Of-Concept](https://github.com/amitlttwo/CVE-2022-2414-Proof-Of-Concept) :  ![starts](https://img.shields.io/github/stars/amitlttwo/CVE-2022-2414-Proof-Of-Concept.svg) ![forks](https://img.shields.io/github/forks/amitlttwo/CVE-2022-2414-Proof-Of-Concept.svg)


## CVE-2022-1388
 On F5 BIG-IP 16.1.x versions prior to 16.1.2.2, 15.1.x versions prior to 15.1.5.1, 14.1.x versions prior to 14.1.4.6, 13.1.x versions prior to 13.1.5, and all 12.1.x and 11.6.x versions, undisclosed requests may bypass iControl REST authentication. Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated

- [https://github.com/M4fiaB0y/CVE-2022-1388](https://github.com/M4fiaB0y/CVE-2022-1388) :  ![starts](https://img.shields.io/github/stars/M4fiaB0y/CVE-2022-1388.svg) ![forks](https://img.shields.io/github/forks/M4fiaB0y/CVE-2022-1388.svg)


## CVE-2021-34481
 Windows Print Spooler Elevation of Privilege Vulnerability

- [https://github.com/0x97vn/CVE-2021-34481](https://github.com/0x97vn/CVE-2021-34481) :  ![starts](https://img.shields.io/github/stars/0x97vn/CVE-2021-34481.svg) ![forks](https://img.shields.io/github/forks/0x97vn/CVE-2021-34481.svg)


## CVE-2021-3129
 Ignition before 2.5.2, as used in Laravel and other products, allows unauthenticated remote attackers to execute arbitrary code because of insecure usage of file_get_contents() and file_put_contents(). This is exploitable on sites using debug mode with Laravel before 8.4.2.

- [https://github.com/MadExploits/Laravel-debug-Checker](https://github.com/MadExploits/Laravel-debug-Checker) :  ![starts](https://img.shields.io/github/stars/MadExploits/Laravel-debug-Checker.svg) ![forks](https://img.shields.io/github/forks/MadExploits/Laravel-debug-Checker.svg)


## CVE-2020-1034
 An elevation of privilege vulnerability exists in the way that the Windows Kernel handles objects in memory, aka 'Windows Kernel Elevation of Privilege Vulnerability'.

- [https://github.com/GeorgyFirsov/CVE-2020-1034](https://github.com/GeorgyFirsov/CVE-2020-1034) :  ![starts](https://img.shields.io/github/stars/GeorgyFirsov/CVE-2020-1034.svg) ![forks](https://img.shields.io/github/forks/GeorgyFirsov/CVE-2020-1034.svg)


## CVE-2019-5444
 Path traversal vulnerability in version up to v1.1.3 in serve-here.js npm module allows attackers to list any file in arbitrary folder.

- [https://github.com/ossf-cve-benchmark/CVE-2019-5444](https://github.com/ossf-cve-benchmark/CVE-2019-5444) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2019-5444.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2019-5444.svg)

