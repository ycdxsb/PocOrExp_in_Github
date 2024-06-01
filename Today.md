# Update 2024-06-01
## CVE-2024-32002
 Git is a revision control system. Prior to versions 2.45.1, 2.44.1, 2.43.4, 2.42.2, 2.41.1, 2.40.2, and 2.39.4, repositories with submodules can be crafted in a way that exploits a bug in Git whereby it can be fooled into writing files not into the submodule's worktree but into a `.git/` directory. This allows writing a hook that will be executed while the clone operation is still running, giving the user no opportunity to inspect the code that is being executed. The problem has been patched in versions 2.45.1, 2.44.1, 2.43.4, 2.42.2, 2.41.1, 2.40.2, and 2.39.4. If symbolic link support is disabled in Git (e.g. via `git config --global core.symlinks false`), the described attack won't work. As always, it is best to avoid cloning repositories from untrusted sources.

- [https://github.com/AD-Appledog/CVE-2024-32002](https://github.com/AD-Appledog/CVE-2024-32002) :  ![starts](https://img.shields.io/github/stars/AD-Appledog/CVE-2024-32002.svg) ![forks](https://img.shields.io/github/forks/AD-Appledog/CVE-2024-32002.svg)


## CVE-2024-24919
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/emanueldosreis/CVE-2024-24919](https://github.com/emanueldosreis/CVE-2024-24919) :  ![starts](https://img.shields.io/github/stars/emanueldosreis/CVE-2024-24919.svg) ![forks](https://img.shields.io/github/forks/emanueldosreis/CVE-2024-24919.svg)
- [https://github.com/c3rrberu5/CVE-2024-24919](https://github.com/c3rrberu5/CVE-2024-24919) :  ![starts](https://img.shields.io/github/stars/c3rrberu5/CVE-2024-24919.svg) ![forks](https://img.shields.io/github/forks/c3rrberu5/CVE-2024-24919.svg)
- [https://github.com/LucasKatashi/CVE-2024-24919](https://github.com/LucasKatashi/CVE-2024-24919) :  ![starts](https://img.shields.io/github/stars/LucasKatashi/CVE-2024-24919.svg) ![forks](https://img.shields.io/github/forks/LucasKatashi/CVE-2024-24919.svg)
- [https://github.com/Bytenull00/CVE-2024-24919](https://github.com/Bytenull00/CVE-2024-24919) :  ![starts](https://img.shields.io/github/stars/Bytenull00/CVE-2024-24919.svg) ![forks](https://img.shields.io/github/forks/Bytenull00/CVE-2024-24919.svg)
- [https://github.com/eoslvs/CVE-2024-24919](https://github.com/eoslvs/CVE-2024-24919) :  ![starts](https://img.shields.io/github/stars/eoslvs/CVE-2024-24919.svg) ![forks](https://img.shields.io/github/forks/eoslvs/CVE-2024-24919.svg)
- [https://github.com/hendprw/CVE-2024-24919](https://github.com/hendprw/CVE-2024-24919) :  ![starts](https://img.shields.io/github/stars/hendprw/CVE-2024-24919.svg) ![forks](https://img.shields.io/github/forks/hendprw/CVE-2024-24919.svg)
- [https://github.com/am-eid/CVE-2024-24919](https://github.com/am-eid/CVE-2024-24919) :  ![starts](https://img.shields.io/github/stars/am-eid/CVE-2024-24919.svg) ![forks](https://img.shields.io/github/forks/am-eid/CVE-2024-24919.svg)
- [https://github.com/pewc0/CVE-2024-24919](https://github.com/pewc0/CVE-2024-24919) :  ![starts](https://img.shields.io/github/stars/pewc0/CVE-2024-24919.svg) ![forks](https://img.shields.io/github/forks/pewc0/CVE-2024-24919.svg)


## CVE-2024-4956
 Path Traversal in Sonatype Nexus Repository 3 allows an unauthenticated attacker to read system files. Fixed in version 3.68.1.

- [https://github.com/Praison001/CVE-2024-4956-Sonatype-Nexus-Repository-Manager](https://github.com/Praison001/CVE-2024-4956-Sonatype-Nexus-Repository-Manager) :  ![starts](https://img.shields.io/github/stars/Praison001/CVE-2024-4956-Sonatype-Nexus-Repository-Manager.svg) ![forks](https://img.shields.io/github/forks/Praison001/CVE-2024-4956-Sonatype-Nexus-Repository-Manager.svg)


## CVE-2024-2961
 The iconv() function in the GNU C Library versions 2.39 and older may overflow the output buffer passed to it by up to 4 bytes when converting strings to the ISO-2022-CN-EXT character set, which may be used to crash an application or overwrite a neighbouring variable.

- [https://github.com/absolutedesignltd/iconvfix](https://github.com/absolutedesignltd/iconvfix) :  ![starts](https://img.shields.io/github/stars/absolutedesignltd/iconvfix.svg) ![forks](https://img.shields.io/github/forks/absolutedesignltd/iconvfix.svg)


## CVE-2024-1208
 The LearnDash LMS plugin for WordPress is vulnerable to Sensitive Information Exposure in all versions up to, and including, 4.10.2 via API. This makes it possible for unauthenticated attackers to obtain access to quiz questions.

- [https://github.com/Cappricio-Securities/CVE-2024-1208](https://github.com/Cappricio-Securities/CVE-2024-1208) :  ![starts](https://img.shields.io/github/stars/Cappricio-Securities/CVE-2024-1208.svg) ![forks](https://img.shields.io/github/forks/Cappricio-Securities/CVE-2024-1208.svg)


## CVE-2023-46805
 An authentication bypass vulnerability in the web component of Ivanti ICS 9.x, 22.x and Ivanti Policy Secure allows a remote attacker to access restricted resources by bypassing control checks.

- [https://github.com/Cappricio-Securities/CVE-2023-46805](https://github.com/Cappricio-Securities/CVE-2023-46805) :  ![starts](https://img.shields.io/github/stars/Cappricio-Securities/CVE-2023-46805.svg) ![forks](https://img.shields.io/github/forks/Cappricio-Securities/CVE-2023-46805.svg)


## CVE-2023-46604
 The Java OpenWire protocol marshaller is vulnerable to Remote Code Execution. This vulnerability may allow a remote attacker with network access to either a Java-based OpenWire broker or client to run arbitrary shell commands by manipulating serialized class types in the OpenWire protocol to cause either the client or the broker (respectively) to instantiate any class on the classpath. Users are recommended to upgrade both brokers and clients to version 5.15.16, 5.16.7, 5.17.6, or 5.18.3 which fixes this issue.

- [https://github.com/pulentoski/CVE-2023-46604](https://github.com/pulentoski/CVE-2023-46604) :  ![starts](https://img.shields.io/github/stars/pulentoski/CVE-2023-46604.svg) ![forks](https://img.shields.io/github/forks/pulentoski/CVE-2023-46604.svg)


## CVE-2020-13973
 OWASP json-sanitizer before 1.2.1 allows XSS. An attacker who controls a substring of the input JSON, and controls another substring adjacent to a SCRIPT element in which the output is embedded as JavaScript, may be able to confuse the HTML parser as to where the SCRIPT element ends, and cause non-script content to be interpreted as JavaScript.

- [https://github.com/epicosy/json-sanitizer](https://github.com/epicosy/json-sanitizer) :  ![starts](https://img.shields.io/github/stars/epicosy/json-sanitizer.svg) ![forks](https://img.shields.io/github/forks/epicosy/json-sanitizer.svg)


## CVE-2019-15477
 Jooby before 1.6.4 has XSS via the default error handler.

- [https://github.com/epicosy/jooby](https://github.com/epicosy/jooby) :  ![starts](https://img.shields.io/github/stars/epicosy/jooby.svg) ![forks](https://img.shields.io/github/forks/epicosy/jooby.svg)


## CVE-2016-10006
 In OWASP AntiSamy before 1.5.5, by submitting a specially crafted input (a tag that supports style with active content), you could bypass the library protections and supply executable code. The impact is XSS.

- [https://github.com/epicosy/VUL4J-60](https://github.com/epicosy/VUL4J-60) :  ![starts](https://img.shields.io/github/stars/epicosy/VUL4J-60.svg) ![forks](https://img.shields.io/github/forks/epicosy/VUL4J-60.svg)


## CVE-2016-5394
 In the XSS Protection API module before 1.0.12 in Apache Sling, the encoding done by the XSSAPI.encodeForJSString() method is not restrictive enough and for some input patterns allows script tags to pass through unencoded, leading to potential XSS vulnerabilities.

- [https://github.com/epicosy/VUL4J-23](https://github.com/epicosy/VUL4J-23) :  ![starts](https://img.shields.io/github/stars/epicosy/VUL4J-23.svg) ![forks](https://img.shields.io/github/forks/epicosy/VUL4J-23.svg)


## CVE-2015-6748
 Cross-site scripting (XSS) vulnerability in jsoup before 1.8.3.

- [https://github.com/epicosy/VUL4J-59](https://github.com/epicosy/VUL4J-59) :  ![starts](https://img.shields.io/github/stars/epicosy/VUL4J-59.svg) ![forks](https://img.shields.io/github/forks/epicosy/VUL4J-59.svg)


## CVE-2013-4378
 Cross-site scripting (XSS) vulnerability in HtmlSessionInformationsReport.java in JavaMelody 1.46 and earlier allows remote attackers to inject arbitrary web script or HTML via a crafted X-Forwarded-For header.

- [https://github.com/epicosy/VUL4J-50](https://github.com/epicosy/VUL4J-50) :  ![starts](https://img.shields.io/github/stars/epicosy/VUL4J-50.svg) ![forks](https://img.shields.io/github/forks/epicosy/VUL4J-50.svg)


## CVE-2010-3124
 Untrusted search path vulnerability in bin/winvlc.c in VLC Media Player 1.1.3 and earlier allows local users, and possibly remote attackers, to execute arbitrary code and conduct DLL hijacking attacks via a Trojan horse wintab32.dll that is located in the same folder as a .mp3 file.

- [https://github.com/KOBUKOVUI/DLL_Injection_On_VLC](https://github.com/KOBUKOVUI/DLL_Injection_On_VLC) :  ![starts](https://img.shields.io/github/stars/KOBUKOVUI/DLL_Injection_On_VLC.svg) ![forks](https://img.shields.io/github/forks/KOBUKOVUI/DLL_Injection_On_VLC.svg)

