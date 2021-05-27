# Update 2021-05-27
## CVE-2021-33575
 The Pixar ruby-jss gem before 1.6.0 allows remote attackers to execute arbitrary code because of the Plist gem's documented behavior of using Marshal.load during XML document processing.

- [https://github.com/JamesGeee/CVE-2021-33575](https://github.com/JamesGeee/CVE-2021-33575) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2021-33575.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2021-33575.svg)


## CVE-2021-33574
 The mq_notify function in the GNU C Library (aka glibc) through 2.33 has a use-after-free. It may use the notification thread attributes object (passed through its struct sigevent parameter) after it has been freed by the caller, leading to a denial of service (application crash) or possibly unspecified other impact.

- [https://github.com/JamesGeee/CVE-2021-33574](https://github.com/JamesGeee/CVE-2021-33574) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2021-33574.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2021-33574.svg)


## CVE-2021-33570
 Postbird 0.8.4 allows stored XSS via the onerror attribute of an IMG element in any PostgreSQL database table. This can result in reading local files via vectors involving XMLHttpRequest and open of a file:/// URL, or discovering PostgreSQL passwords via vectors involving Window.localStorage and savedConnections.

- [https://github.com/JamesGeee/CVE-2021-33570](https://github.com/JamesGeee/CVE-2021-33570) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2021-33570.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2021-33570.svg)


## CVE-2021-28112
 Draeger X-Dock Firmware before 03.00.13 has Active Debug Code on a debug port, leading to remote code execution by an authenticated attacker.

- [https://github.com/JamesGeee/CVE-2021-28112](https://github.com/JamesGeee/CVE-2021-28112) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2021-28112.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2021-28112.svg)


## CVE-2021-28111
 Draeger X-Dock Firmware before 03.00.13 has Hard-Coded Credentials, leading to remote code execution by an authenticated attacker.

- [https://github.com/JamesGeee/CVE-2021-28111](https://github.com/JamesGeee/CVE-2021-28111) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2021-28111.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2021-28111.svg)


## CVE-2021-22667
 BB-ESWGP506-2SFP-T versions 1.01.09 and prior is vulnerable due to the use of hard-coded credentials, which may allow an attacker to gain unauthorized access and permit the execution of arbitrary code on the BB-ESWGP506-2SFP-T (versions 1.01.01 and prior).

- [https://github.com/JamesGeee/CVE-2021-22667](https://github.com/JamesGeee/CVE-2021-22667) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2021-22667.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2021-22667.svg)


## CVE-2020-27216
 In Eclipse Jetty versions 1.0 thru 9.4.32.v20200930, 10.0.0.alpha1 thru 10.0.0.beta2, and 11.0.0.alpha1 thru 11.0.0.beta2O, on Unix like systems, the system's temporary directory is shared between all users on that system. A collocated user can observe the process of creating a temporary sub directory in the shared temporary directory and race to complete the creation of the temporary subdirectory. If the attacker wins the race then they will have read and write permission to the subdirectory used to unpack web applications, including their WEB-INF/lib jar files and JSP files. If any code is ever executed out of this temporary directory, this can lead to a local privilege escalation vulnerability.

- [https://github.com/JamesGeee/CVE-2020-27216](https://github.com/JamesGeee/CVE-2020-27216) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2020-27216.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2020-27216.svg)


## CVE-2017-7180
 Net Monitor for Employees Pro through 5.3.4 has an unquoted service path, which allows a Security Feature Bypass of its documented &quot;Block applications&quot; design goal. The local attacker must have privileges to write to program.exe in a protected directory, such as the %SYSTEMDRIVE% directory, and thus the issue is not interpreted as a direct privilege escalation. However, the local attacker might have the goal of executing program.exe even though program.exe is a blocked application.

- [https://github.com/JamesGeee/CVE-2017-7180](https://github.com/JamesGeee/CVE-2017-7180) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2017-7180.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2017-7180.svg)


## CVE-2016-20011
 libgrss through 0.7.0 fails to perform TLS certificate verification when downloading feeds, allowing remote attackers to manipulate the contents of feeds without detection. This occurs because of the default behavior of SoupSessionSync.

- [https://github.com/JamesGeee/CVE-2016-20011](https://github.com/JamesGeee/CVE-2016-20011) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2016-20011.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2016-20011.svg)


## CVE-2016-5063
 The RSCD agent in BMC Server Automation before 8.6 SP1 Patch 2 and 8.7 before Patch 3 on Windows might allow remote attackers to bypass authorization checks and make an RPC call via unspecified vectors.

- [https://github.com/DreadFog/RSCD_CVEs](https://github.com/DreadFog/RSCD_CVEs) :  ![starts](https://img.shields.io/github/stars/DreadFog/RSCD_CVEs.svg) ![forks](https://img.shields.io/github/forks/DreadFog/RSCD_CVEs.svg)

