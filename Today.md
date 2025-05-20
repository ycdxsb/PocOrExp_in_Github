# Update 2025-05-20
## CVE-2025-32756
 A stack-based buffer overflow vulnerability [CWE-121] in Fortinet FortiVoice versions 7.2.0, 7.0.0 through 7.0.6, 6.4.0 through 6.4.10, FortiRecorder versions 7.2.0 through 7.2.3, 7.0.0 through 7.0.5, 6.4.0 through 6.4.5, FortiMail versions 7.6.0 through 7.6.2, 7.4.0 through 7.4.4, 7.2.0 through 7.2.7, 7.0.0 through 7.0.8, FortiNDR versions 7.6.0, 7.4.0 through 7.4.7, 7.2.0 through 7.2.4, 7.0.0 through 7.0.6, FortiCamera versions 2.1.0 through 2.1.3, 2.0 all versions, 1.1 all versions, allows a remote unauthenticated attacker to execute arbitrary code or commands via sending HTTP requests with specially crafted hash cookie.

- [https://github.com/exfil0/CVE-2025-32756-POC](https://github.com/exfil0/CVE-2025-32756-POC) :  ![starts](https://img.shields.io/github/stars/exfil0/CVE-2025-32756-POC.svg) ![forks](https://img.shields.io/github/forks/exfil0/CVE-2025-32756-POC.svg)


## CVE-2025-32259
 Missing Authorization vulnerability in Alimir WP ULike. This issue affects WP ULike: from n/a through 4.7.9.1.

- [https://github.com/HossamEAhmed/wp-ulike-cve-2025-32259-poc](https://github.com/HossamEAhmed/wp-ulike-cve-2025-32259-poc) :  ![starts](https://img.shields.io/github/stars/HossamEAhmed/wp-ulike-cve-2025-32259-poc.svg) ![forks](https://img.shields.io/github/forks/HossamEAhmed/wp-ulike-cve-2025-32259-poc.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/KaztoRay/CVE-2025-29927-Research](https://github.com/KaztoRay/CVE-2025-29927-Research) :  ![starts](https://img.shields.io/github/stars/KaztoRay/CVE-2025-29927-Research.svg) ![forks](https://img.shields.io/github/forks/KaztoRay/CVE-2025-29927-Research.svg)


## CVE-2025-24104
 This issue was addressed with improved handling of symlinks. This issue is fixed in iPadOS 17.7.4, iOS 18.3 and iPadOS 18.3. Restoring a maliciously crafted backup file may lead to modification of protected system files.

- [https://github.com/missaels235/POC-CVE-2025-24104-Py](https://github.com/missaels235/POC-CVE-2025-24104-Py) :  ![starts](https://img.shields.io/github/stars/missaels235/POC-CVE-2025-24104-Py.svg) ![forks](https://img.shields.io/github/forks/missaels235/POC-CVE-2025-24104-Py.svg)


## CVE-2024-41713
 A vulnerability in the NuPoint Unified Messaging (NPM) component of Mitel MiCollab through 9.8 SP1 FP2 (9.8.1.201) could allow an unauthenticated attacker to conduct a path traversal attack, due to insufficient input validation. A successful exploit could allow unauthorized access, enabling the attacker to view, corrupt, or delete users' data and system configurations.

- [https://github.com/gunyakit/CVE-2024-41713-PoC-exploit](https://github.com/gunyakit/CVE-2024-41713-PoC-exploit) :  ![starts](https://img.shields.io/github/stars/gunyakit/CVE-2024-41713-PoC-exploit.svg) ![forks](https://img.shields.io/github/forks/gunyakit/CVE-2024-41713-PoC-exploit.svg)


## CVE-2023-41991
 A certificate validation issue was addressed. This issue is fixed in macOS Ventura 13.6, iOS 16.7 and iPadOS 16.7. A malicious app may be able to bypass signature validation. Apple is aware of a report that this issue may have been actively exploited against versions of iOS before iOS 16.7.

- [https://github.com/dmytrozykov/appsign](https://github.com/dmytrozykov/appsign) :  ![starts](https://img.shields.io/github/stars/dmytrozykov/appsign.svg) ![forks](https://img.shields.io/github/forks/dmytrozykov/appsign.svg)


## CVE-2022-39299
 Passport-SAML is a SAML 2.0 authentication provider for Passport, the Node.js authentication library. A remote attacker may be able to bypass SAML authentication on a website using passport-saml. A successful attack requires that the attacker is in possession of an arbitrary IDP signed XML element. Depending on the IDP used, fully unauthenticated attacks (e.g without access to a valid user) might also be feasible if generation of a signed message can be triggered. Users should upgrade to passport-saml version 3.2.2 or newer. The issue was also present in the beta releases of `node-saml` before version 4.0.0-beta.5. If you cannot upgrade, disabling SAML authentication may be done as a workaround.

- [https://github.com/KaztoRay/CVE-2022-39299-Research](https://github.com/KaztoRay/CVE-2022-39299-Research) :  ![starts](https://img.shields.io/github/stars/KaztoRay/CVE-2022-39299-Research.svg) ![forks](https://img.shields.io/github/forks/KaztoRay/CVE-2022-39299-Research.svg)


## CVE-2021-43798
 Grafana is an open-source platform for monitoring and observability. Grafana versions 8.0.0-beta1 through 8.3.0 (except for patched versions) iss vulnerable to directory traversal, allowing access to local files. The vulnerable URL path is: `grafana_host_url/public/plugins//`, where is the plugin ID for any installed plugin. At no time has Grafana Cloud been vulnerable. Users are advised to upgrade to patched versions 8.0.7, 8.1.8, 8.2.7, or 8.3.1. The GitHub Security Advisory contains more information about vulnerable URL paths, mitigation, and the disclosure timeline.

- [https://github.com/abuyazeen/CVE-2021-43798-Grafana-path-traversal-tester](https://github.com/abuyazeen/CVE-2021-43798-Grafana-path-traversal-tester) :  ![starts](https://img.shields.io/github/stars/abuyazeen/CVE-2021-43798-Grafana-path-traversal-tester.svg) ![forks](https://img.shields.io/github/forks/abuyazeen/CVE-2021-43798-Grafana-path-traversal-tester.svg)


## CVE-2018-16621
 Sonatype Nexus Repository Manager before 3.14 allows Java Expression Language Injection.

- [https://github.com/Loucy1231/Nexus-Repository-Manager3-EL-CVE-2018-16621-https-www.cve.org-CVERecord-id-CVE-2018-16621-](https://github.com/Loucy1231/Nexus-Repository-Manager3-EL-CVE-2018-16621-https-www.cve.org-CVERecord-id-CVE-2018-16621-) :  ![starts](https://img.shields.io/github/stars/Loucy1231/Nexus-Repository-Manager3-EL-CVE-2018-16621-https-www.cve.org-CVERecord-id-CVE-2018-16621-.svg) ![forks](https://img.shields.io/github/forks/Loucy1231/Nexus-Repository-Manager3-EL-CVE-2018-16621-https-www.cve.org-CVERecord-id-CVE-2018-16621-.svg)


## CVE-2011-0762
 The vsf_filename_passes_filter function in ls.c in vsftpd before 2.3.3 allows remote authenticated users to cause a denial of service (CPU consumption and process slot exhaustion) via crafted glob expressions in STAT commands in multiple FTP sessions, a different vulnerability than CVE-2010-2632.

- [https://github.com/AndreyFreitax/CVE-2011-0762](https://github.com/AndreyFreitax/CVE-2011-0762) :  ![starts](https://img.shields.io/github/stars/AndreyFreitax/CVE-2011-0762.svg) ![forks](https://img.shields.io/github/forks/AndreyFreitax/CVE-2011-0762.svg)

