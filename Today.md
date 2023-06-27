# Update 2023-06-27
## CVE-2023-27372
 SPIP before 4.2.1 allows Remote Code Execution via form values in the public area because serialization is mishandled. The fixed versions are 3.2.18, 4.0.10, 4.1.8, and 4.2.1.

- [https://github.com/Chocapikk/CVE-2023-27372](https://github.com/Chocapikk/CVE-2023-27372) :  ![starts](https://img.shields.io/github/stars/Chocapikk/CVE-2023-27372.svg) ![forks](https://img.shields.io/github/forks/Chocapikk/CVE-2023-27372.svg)


## CVE-2023-23333
 There is a command injection vulnerability in SolarView Compact through 6.00, attackers can execute commands by bypassing internal restrictions through downloader.php.

- [https://github.com/WhiteOwl-Pub/PoC-SolarView-Compact-CVE-2023-23333](https://github.com/WhiteOwl-Pub/PoC-SolarView-Compact-CVE-2023-23333) :  ![starts](https://img.shields.io/github/stars/WhiteOwl-Pub/PoC-SolarView-Compact-CVE-2023-23333.svg) ![forks](https://img.shields.io/github/forks/WhiteOwl-Pub/PoC-SolarView-Compact-CVE-2023-23333.svg)


## CVE-2023-22809
 In Sudo before 1.9.12p2, the sudoedit (aka -e) feature mishandles extra arguments passed in the user-provided environment variables (SUDO_EDITOR, VISUAL, and EDITOR), allowing a local attacker to append arbitrary entries to the list of files to process. This can lead to privilege escalation. Affected versions are 1.8.0 through 1.9.12.p1. The problem exists because a user-specified editor may contain a &quot;--&quot; argument that defeats a protection mechanism, e.g., an EDITOR='vim -- /path/to/extra/file' value.

- [https://github.com/pashayogi/CVE-2023-22809](https://github.com/pashayogi/CVE-2023-22809) :  ![starts](https://img.shields.io/github/stars/pashayogi/CVE-2023-22809.svg) ![forks](https://img.shields.io/github/forks/pashayogi/CVE-2023-22809.svg)


## CVE-2022-44268
 ImageMagick 7.1.0-49 is vulnerable to Information Disclosure. When it parses a PNG image (e.g., for resize), the resulting image could have embedded the content of an arbitrary. file (if the magick binary has permissions to read it).

- [https://github.com/adhikara13/CVE-2022-44268-MagiLeak](https://github.com/adhikara13/CVE-2022-44268-MagiLeak) :  ![starts](https://img.shields.io/github/stars/adhikara13/CVE-2022-44268-MagiLeak.svg) ![forks](https://img.shields.io/github/forks/adhikara13/CVE-2022-44268-MagiLeak.svg)


## CVE-2021-42013
 It was found that the fix for CVE-2021-41773 in Apache HTTP Server 2.4.50 was insufficient. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue only affects Apache 2.4.49 and Apache 2.4.50 and not earlier versions.

- [https://github.com/birdlinux/CVE-2021-42013](https://github.com/birdlinux/CVE-2021-42013) :  ![starts](https://img.shields.io/github/stars/birdlinux/CVE-2021-42013.svg) ![forks](https://img.shields.io/github/forks/birdlinux/CVE-2021-42013.svg)


## CVE-2020-9496
 XML-RPC request are vulnerable to unsafe deserialization and Cross-Site Scripting issues in Apache OFBiz 17.12.03

- [https://github.com/birdlinux/CVE-2020-9496](https://github.com/birdlinux/CVE-2020-9496) :  ![starts](https://img.shields.io/github/stars/birdlinux/CVE-2020-9496.svg) ![forks](https://img.shields.io/github/forks/birdlinux/CVE-2020-9496.svg)


## CVE-2020-1048
 An elevation of privilege vulnerability exists when the Windows Print Spooler service improperly allows arbitrary writing to the file system, aka 'Windows Print Spooler Elevation of Privilege Vulnerability'. This CVE ID is unique from CVE-2020-1070.

- [https://github.com/zveriu/CVE-2009-0229-PoC](https://github.com/zveriu/CVE-2009-0229-PoC) :  ![starts](https://img.shields.io/github/stars/zveriu/CVE-2009-0229-PoC.svg) ![forks](https://img.shields.io/github/forks/zveriu/CVE-2009-0229-PoC.svg)


## CVE-2018-1324
 A specially crafted ZIP archive can be used to cause an infinite loop inside of Apache Commons Compress' extra field parser used by the ZipFile and ZipArchiveInputStream classes in versions 1.11 to 1.15. This can be used to mount a denial of service attack against services that use Compress' zip package.

- [https://github.com/tafamace/CVE-2018-1324](https://github.com/tafamace/CVE-2018-1324) :  ![starts](https://img.shields.io/github/stars/tafamace/CVE-2018-1324.svg) ![forks](https://img.shields.io/github/forks/tafamace/CVE-2018-1324.svg)

