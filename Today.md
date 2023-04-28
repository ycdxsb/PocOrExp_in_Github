# Update 2023-04-28
## CVE-2023-29489
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/learnerboy88/CVE-2023-29489](https://github.com/learnerboy88/CVE-2023-29489) :  ![starts](https://img.shields.io/github/stars/learnerboy88/CVE-2023-29489.svg) ![forks](https://img.shields.io/github/forks/learnerboy88/CVE-2023-29489.svg)


## CVE-2023-29007
 Git is a revision control system. Prior to versions 2.30.9, 2.31.8, 2.32.7, 2.33.8, 2.34.8, 2.35.8, 2.36.6, 2.37.7, 2.38.5, 2.39.3, and 2.40.1, a specially crafted `.gitmodules` file with submodule URLs that are longer than 1024 characters can used to exploit a bug in `config.c::git_config_copy_or_rename_section_in_file()`. This bug can be used to inject arbitrary configuration into a user's `$GIT_DIR/config` when attempting to remove the configuration section associated with that submodule. When the attacker injects configuration values which specify executables to run (such as `core.pager`, `core.editor`, `core.sshCommand`, etc.) this can lead to a remote code execution. A fix A fix is available in versions 2.30.9, 2.31.8, 2.32.7, 2.33.8, 2.34.8, 2.35.8, 2.36.6, 2.37.7, 2.38.5, 2.39.3, and 2.40.1. As a workaround, avoid running `git submodule deinit` on untrusted repositories or without prior inspection of any submodule sections in `$GIT_DIR/config`.

- [https://github.com/ethiack/CVE-2023-29007](https://github.com/ethiack/CVE-2023-29007) :  ![starts](https://img.shields.io/github/stars/ethiack/CVE-2023-29007.svg) ![forks](https://img.shields.io/github/forks/ethiack/CVE-2023-29007.svg)


## CVE-2023-2033
 Type confusion in V8 in Google Chrome prior to 112.0.5615.121 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/sandumjacob/CVE-2023-2033-Analysis](https://github.com/sandumjacob/CVE-2023-2033-Analysis) :  ![starts](https://img.shields.io/github/stars/sandumjacob/CVE-2023-2033-Analysis.svg) ![forks](https://img.shields.io/github/forks/sandumjacob/CVE-2023-2033-Analysis.svg)


## CVE-2022-42475
 A heap-based buffer overflow vulnerability [CWE-122] in FortiOS SSL-VPN 7.2.0 through 7.2.2, 7.0.0 through 7.0.8, 6.4.0 through 6.4.10, 6.2.0 through 6.2.11, 6.0.15 and earlier and FortiProxy SSL-VPN 7.2.0 through 7.2.1, 7.0.7 and earlier may allow a remote unauthenticated attacker to execute arbitrary code or commands via specifically crafted requests.

- [https://github.com/natceil/cve-2022-42475](https://github.com/natceil/cve-2022-42475) :  ![starts](https://img.shields.io/github/stars/natceil/cve-2022-42475.svg) ![forks](https://img.shields.io/github/forks/natceil/cve-2022-42475.svg)


## CVE-2022-35914
 /vendor/htmlawed/htmlawed/htmLawedTest.php in the htmlawed module for GLPI through 10.0.2 allows PHP code injection.

- [https://github.com/franckferman/GLPI-htmLawed-CVE-2022_35914-PoC](https://github.com/franckferman/GLPI-htmLawed-CVE-2022_35914-PoC) :  ![starts](https://img.shields.io/github/stars/franckferman/GLPI-htmLawed-CVE-2022_35914-PoC.svg) ![forks](https://img.shields.io/github/forks/franckferman/GLPI-htmLawed-CVE-2022_35914-PoC.svg)


## CVE-2022-21661
 WordPress is a free and open-source content management system written in PHP and paired with a MariaDB database. Due to improper sanitization in WP_Query, there can be cases where SQL injection is possible through plugins or themes that use it in a certain way. This has been patched in WordPress version 5.8.3. Older affected versions are also fixed via security release, that go back till 3.7.37. We strongly recommend that you keep auto-updates enabled. There are no known workarounds for this vulnerability.

- [https://github.com/sealldeveloper/CVE-2022-21661-PoC](https://github.com/sealldeveloper/CVE-2022-21661-PoC) :  ![starts](https://img.shields.io/github/stars/sealldeveloper/CVE-2022-21661-PoC.svg) ![forks](https://img.shields.io/github/forks/sealldeveloper/CVE-2022-21661-PoC.svg)


## CVE-2022-20142
 In createFromParcel of GeofenceHardwareRequestParcelable.java, there is a possible arbitrary code execution due to parcel mismatch. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-10 Android-11 Android-12 Android-12LAndroid ID: A-216631962

- [https://github.com/Satheesh575555/frameworks_base_AOSP10_r33_CVE-2022-20142](https://github.com/Satheesh575555/frameworks_base_AOSP10_r33_CVE-2022-20142) :  ![starts](https://img.shields.io/github/stars/Satheesh575555/frameworks_base_AOSP10_r33_CVE-2022-20142.svg) ![forks](https://img.shields.io/github/forks/Satheesh575555/frameworks_base_AOSP10_r33_CVE-2022-20142.svg)


## CVE-2022-0847
 A flaw was found in the way the &quot;flags&quot; member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/JlSakuya/CVE-2022-0847-container-escape](https://github.com/JlSakuya/CVE-2022-0847-container-escape) :  ![starts](https://img.shields.io/github/stars/JlSakuya/CVE-2022-0847-container-escape.svg) ![forks](https://img.shields.io/github/forks/JlSakuya/CVE-2022-0847-container-escape.svg)


## CVE-2020-27786
 A flaw was found in the Linux kernel&#8217;s implementation of MIDI, where an attacker with a local account and the permissions to issue ioctl commands to midi devices could trigger a use-after-free issue. A write to this specific memory while freed and before use causes the flow of execution to change and possibly allow for memory corruption or privilege escalation. The highest threat from this vulnerability is to confidentiality, integrity, as well as system availability.

- [https://github.com/elbiazo/CVE-2020-27786](https://github.com/elbiazo/CVE-2020-27786) :  ![starts](https://img.shields.io/github/stars/elbiazo/CVE-2020-27786.svg) ![forks](https://img.shields.io/github/forks/elbiazo/CVE-2020-27786.svg)


## CVE-2020-5377
 Dell EMC OpenManage Server Administrator (OMSA) versions 9.4 and prior contain multiple path traversal vulnerabilities. An unauthenticated remote attacker could potentially exploit these vulnerabilities by sending a crafted Web API request containing directory traversal character sequences to gain file system access on the compromised management station.

- [https://github.com/und3sc0n0c1d0/AFR-in-OMSA](https://github.com/und3sc0n0c1d0/AFR-in-OMSA) :  ![starts](https://img.shields.io/github/stars/und3sc0n0c1d0/AFR-in-OMSA.svg) ![forks](https://img.shields.io/github/forks/und3sc0n0c1d0/AFR-in-OMSA.svg)


## CVE-2020-5258
 In affected versions of dojo (NPM package), the deepCopy method is vulnerable to Prototype Pollution. Prototype Pollution refers to the ability to inject properties into existing JavaScript language construct prototypes, such as objects. An attacker manipulates these attributes to overwrite, or pollute, a JavaScript application object prototype of the base object by injecting other values. This has been patched in versions 1.12.8, 1.13.7, 1.14.6, 1.15.3 and 1.16.2

- [https://github.com/ossf-cve-benchmark/CVE-2020-5258](https://github.com/ossf-cve-benchmark/CVE-2020-5258) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2020-5258.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2020-5258.svg)


## CVE-2020-3580
 Multiple vulnerabilities in the web services interface of Cisco Adaptive Security Appliance (ASA) Software and Cisco Firepower Threat Defense (FTD) Software could allow an unauthenticated, remote attacker to conduct cross-site scripting (XSS) attacks against a user of the web services interface of an affected device. The vulnerabilities are due to insufficient validation of user-supplied input by the web services interface of an affected device. An attacker could exploit these vulnerabilities by persuading a user of the interface to click a crafted link. A successful exploit could allow the attacker to execute arbitrary script code in the context of the interface or allow the attacker to access sensitive, browser-based information. Note: These vulnerabilities affect only specific AnyConnect and WebVPN configurations. For more information, see the Vulnerable Products section.

- [https://github.com/cruxN3T/CVE-2020-3580](https://github.com/cruxN3T/CVE-2020-3580) :  ![starts](https://img.shields.io/github/stars/cruxN3T/CVE-2020-3580.svg) ![forks](https://img.shields.io/github/forks/cruxN3T/CVE-2020-3580.svg)


## CVE-2019-18935
 Progress Telerik UI for ASP.NET AJAX through 2019.3.1023 contains a .NET deserialization vulnerability in the RadAsyncUpload function. This is exploitable when the encryption keys are known due to the presence of CVE-2017-11317 or CVE-2017-11357, or other means. Exploitation can result in remote code execution. (As of 2020.1.114, a default setting prevents the exploit. In 2019.3.1023, but not earlier versions, a non-default setting can prevent exploitation.)

- [https://github.com/0xAgun/CVE-2019-18935-checker](https://github.com/0xAgun/CVE-2019-18935-checker) :  ![starts](https://img.shields.io/github/stars/0xAgun/CVE-2019-18935-checker.svg) ![forks](https://img.shields.io/github/forks/0xAgun/CVE-2019-18935-checker.svg)


## CVE-2017-17485
 FasterXML jackson-databind through 2.8.10 and 2.9.x through 2.9.3 allows unauthenticated remote code execution because of an incomplete fix for the CVE-2017-7525 deserialization flaw. This is exploitable by sending maliciously crafted JSON input to the readValue method of the ObjectMapper, bypassing a blacklist that is ineffective if the Spring libraries are available in the classpath.

- [https://github.com/rootsecurity/Jackson-CVE-2017-17485](https://github.com/rootsecurity/Jackson-CVE-2017-17485) :  ![starts](https://img.shields.io/github/stars/rootsecurity/Jackson-CVE-2017-17485.svg) ![forks](https://img.shields.io/github/forks/rootsecurity/Jackson-CVE-2017-17485.svg)


## CVE-2017-5124
 Incorrect application of sandboxing in Blink in Google Chrome prior to 62.0.3202.62 allowed a remote attacker to inject arbitrary scripts or HTML (UXSS) via a crafted MHTML page.

- [https://github.com/Bo0oM/CVE-2017-5124](https://github.com/Bo0oM/CVE-2017-5124) :  ![starts](https://img.shields.io/github/stars/Bo0oM/CVE-2017-5124.svg) ![forks](https://img.shields.io/github/forks/Bo0oM/CVE-2017-5124.svg)

