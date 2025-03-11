# Update 2025-03-11
## CVE-2025-27840
 Espressif ESP32 chips allow 29 hidden HCI commands, such as 0xFC02 (Write memory).

- [https://github.com/em0gi/CVE-2025-27840](https://github.com/em0gi/CVE-2025-27840) :  ![starts](https://img.shields.io/github/stars/em0gi/CVE-2025-27840.svg) ![forks](https://img.shields.io/github/forks/em0gi/CVE-2025-27840.svg)


## CVE-2025-21333
 Windows Hyper-V NT Kernel Integration VSP Elevation of Privilege Vulnerability

- [https://github.com/Mukesh-blend/CVE-2025-21333-POC](https://github.com/Mukesh-blend/CVE-2025-21333-POC) :  ![starts](https://img.shields.io/github/stars/Mukesh-blend/CVE-2025-21333-POC.svg) ![forks](https://img.shields.io/github/forks/Mukesh-blend/CVE-2025-21333-POC.svg)


## CVE-2025-1316
 Edimax IC-7100 does not properly neutralize requests. An attacker can create specially crafted requests to achieve remote code execution on the device

- [https://github.com/Rimasue/CVE-2025-1316](https://github.com/Rimasue/CVE-2025-1316) :  ![starts](https://img.shields.io/github/stars/Rimasue/CVE-2025-1316.svg) ![forks](https://img.shields.io/github/forks/Rimasue/CVE-2025-1316.svg)


## CVE-2024-45436
 extractFromZipFile in model.go in Ollama before 0.1.47 can extract members of a ZIP archive outside of the parent directory.

- [https://github.com/pankass/CVE-2024-37032_CVE-2024-45436](https://github.com/pankass/CVE-2024-37032_CVE-2024-45436) :  ![starts](https://img.shields.io/github/stars/pankass/CVE-2024-37032_CVE-2024-45436.svg) ![forks](https://img.shields.io/github/forks/pankass/CVE-2024-37032_CVE-2024-45436.svg)


## CVE-2024-37032
 Ollama before 0.1.34 does not validate the format of the digest (sha256 with 64 hex digits) when getting the model path, and thus mishandles the TestGetBlobsPath test cases such as fewer than 64 hex digits, more than 64 hex digits, or an initial ../ substring.

- [https://github.com/pankass/CVE-2024-37032_CVE-2024-45436](https://github.com/pankass/CVE-2024-37032_CVE-2024-45436) :  ![starts](https://img.shields.io/github/stars/pankass/CVE-2024-37032_CVE-2024-45436.svg) ![forks](https://img.shields.io/github/forks/pankass/CVE-2024-37032_CVE-2024-45436.svg)


## CVE-2024-10629
 The GPX Viewer plugin for WordPress is vulnerable to arbitrary file creation due to a missing capability check and file type validation in the gpxv_file_upload() function in all versions up to, and including, 2.2.8. This makes it possible for authenticated attackers, with subscriber-level access and above, to create arbitrary files on the affected site's server which may make remote code execution possible.

- [https://github.com/Nxploited/CVE-2024-10629](https://github.com/Nxploited/CVE-2024-10629) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2024-10629.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2024-10629.svg)


## CVE-2023-40028
 Ghost is an open source content management system. Versions prior to 5.59.1 are subject to a vulnerability which allows authenticated users to upload files that are symlinks. This can be exploited to perform an arbitrary file read of any file on the host operating system. Site administrators can check for exploitation of this issue by looking for unknown symlinks within Ghost's `content/` folder. Version 5.59.1 contains a fix for this issue. All users are advised to upgrade. There are no known workarounds for this vulnerability.

- [https://github.com/monke443/CVE-2023-40028](https://github.com/monke443/CVE-2023-40028) :  ![starts](https://img.shields.io/github/stars/monke443/CVE-2023-40028.svg) ![forks](https://img.shields.io/github/forks/monke443/CVE-2023-40028.svg)


## CVE-2023-30258
 Command Injection vulnerability in MagnusSolution magnusbilling 6.x and 7.x allows remote attackers to run arbitrary commands via unauthenticated HTTP request.

- [https://github.com/sk00l/CVE-2023-30258](https://github.com/sk00l/CVE-2023-30258) :  ![starts](https://img.shields.io/github/stars/sk00l/CVE-2023-30258.svg) ![forks](https://img.shields.io/github/forks/sk00l/CVE-2023-30258.svg)


## CVE-2023-27350
 This vulnerability allows remote attackers to bypass authentication on affected installations of PaperCut NG 22.0.5 (Build 63914). Authentication is not required to exploit this vulnerability. The specific flaw exists within the SetupCompleted class. The issue results from improper access control. An attacker can leverage this vulnerability to bypass authentication and execute arbitrary code in the context of SYSTEM. Was ZDI-CAN-18987.

- [https://github.com/monke443/CVE-2023-27350](https://github.com/monke443/CVE-2023-27350) :  ![starts](https://img.shields.io/github/stars/monke443/CVE-2023-27350.svg) ![forks](https://img.shields.io/github/forks/monke443/CVE-2023-27350.svg)


## CVE-2022-0847
 A flaw was found in the way the "flags" member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/karanlvm/DirtyPipe-Exploit](https://github.com/karanlvm/DirtyPipe-Exploit) :  ![starts](https://img.shields.io/github/stars/karanlvm/DirtyPipe-Exploit.svg) ![forks](https://img.shields.io/github/forks/karanlvm/DirtyPipe-Exploit.svg)


## CVE-2021-43798
 Grafana is an open-source platform for monitoring and observability. Grafana versions 8.0.0-beta1 through 8.3.0 (except for patched versions) iss vulnerable to directory traversal, allowing access to local files. The vulnerable URL path is: `grafana_host_url/public/plugins//`, where is the plugin ID for any installed plugin. At no time has Grafana Cloud been vulnerable. Users are advised to upgrade to patched versions 8.0.7, 8.1.8, 8.2.7, or 8.3.1. The GitHub Security Advisory contains more information about vulnerable URL paths, mitigation, and the disclosure timeline.

- [https://github.com/monke443/CVE-2021-43798](https://github.com/monke443/CVE-2021-43798) :  ![starts](https://img.shields.io/github/stars/monke443/CVE-2021-43798.svg) ![forks](https://img.shields.io/github/forks/monke443/CVE-2021-43798.svg)


## CVE-2017-1182
 IBM Tivoli Monitoring Portal v6 could allow a local (network adjacent) attacker to execute arbitrary commands on the system, when default client-server default communications, HTTP, are being used. IBM X-Force ID: 123493.

- [https://github.com/Morfeen01/cve-2017-1182-TN](https://github.com/Morfeen01/cve-2017-1182-TN) :  ![starts](https://img.shields.io/github/stars/Morfeen01/cve-2017-1182-TN.svg) ![forks](https://img.shields.io/github/forks/Morfeen01/cve-2017-1182-TN.svg)

