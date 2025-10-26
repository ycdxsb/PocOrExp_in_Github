# Update 2025-10-26
## CVE-2025-61984
 ssh in OpenSSH before 10.1 allows control characters in usernames that originate from certain possibly untrusted sources, potentially leading to code execution when a ProxyCommand is used. The untrusted sources are the command line and %-sequence expansion of a configuration file. (A configuration file that provides a complete literal username is not categorized as an untrusted source.)

- [https://github.com/flyskyfire/cve-2025-61984-poc](https://github.com/flyskyfire/cve-2025-61984-poc) :  ![starts](https://img.shields.io/github/stars/flyskyfire/cve-2025-61984-poc.svg) ![forks](https://img.shields.io/github/forks/flyskyfire/cve-2025-61984-poc.svg)


## CVE-2025-59503
 Server-side request forgery (ssrf) in Azure Compute Gallery allows an authorized attacker to elevate privileges over a network.

- [https://github.com/Mpokes/CVE-2025-59503-Poc](https://github.com/Mpokes/CVE-2025-59503-Poc) :  ![starts](https://img.shields.io/github/stars/Mpokes/CVE-2025-59503-Poc.svg) ![forks](https://img.shields.io/github/forks/Mpokes/CVE-2025-59503-Poc.svg)


## CVE-2025-55315
 Inconsistent interpretation of http requests ('http request/response smuggling') in ASP.NET Core allows an authorized attacker to bypass a security feature over a network.

- [https://github.com/jlinebau/CVE-2025-55315-Scanner-Monitor](https://github.com/jlinebau/CVE-2025-55315-Scanner-Monitor) :  ![starts](https://img.shields.io/github/stars/jlinebau/CVE-2025-55315-Scanner-Monitor.svg) ![forks](https://img.shields.io/github/forks/jlinebau/CVE-2025-55315-Scanner-Monitor.svg)


## CVE-2025-52099
 Integer Overflow vulnerability in SQLite SQLite3 v.3.50.0 allows a remote attacker to cause a denial of service via the setupLookaside function

- [https://github.com/SCREAMBBY/CVE-2025-52099](https://github.com/SCREAMBBY/CVE-2025-52099) :  ![starts](https://img.shields.io/github/stars/SCREAMBBY/CVE-2025-52099.svg) ![forks](https://img.shields.io/github/forks/SCREAMBBY/CVE-2025-52099.svg)


## CVE-2025-48385
 Git is a fast, scalable, distributed revision control system with an unusually rich command set that provides both high-level operations and full access to internals. When cloning a repository Git knows to optionally fetch a bundle advertised by the remote server, which allows the server-side to offload parts of the clone to a CDN. The Git client does not perform sufficient validation of the advertised bundles, which allows the remote side to perform protocol injection. This protocol injection can cause the client to write the fetched bundle to a location controlled by the adversary. The fetched content is fully controlled by the server, which can in the worst case lead to arbitrary code execution. The use of bundle URIs is not enabled by default and can be controlled by the bundle.heuristic config option. Some cases of the vulnerability require that the adversary is in control of where a repository will be cloned to. This either requires social engineering or a recursive clone with submodules. These cases can thus be avoided by disabling recursive clones. This vulnerability is fixed in v2.43.7, v2.44.4, v2.45.4, v2.46.4, v2.47.3, v2.48.2, v2.49.1, and v2.50.1.

- [https://github.com/Nimisha17/Git-clone-CVE-2025-48385](https://github.com/Nimisha17/Git-clone-CVE-2025-48385) :  ![starts](https://img.shields.io/github/stars/Nimisha17/Git-clone-CVE-2025-48385.svg) ![forks](https://img.shields.io/github/forks/Nimisha17/Git-clone-CVE-2025-48385.svg)


## CVE-2025-27636
Mitigation: You can easily work around this in your Camel applications by removing the headers in your Camel routes. There are many ways of doing this, also globally or per route. This means you could use the removeHeaders EIP, to filter out anything like "cAmel, cAMEL" etc, or in general everything not starting with "Camel", "camel" or "org.apache.camel.".

- [https://github.com/Crystallen1/CVE-2025-27636-demo](https://github.com/Crystallen1/CVE-2025-27636-demo) :  ![starts](https://img.shields.io/github/stars/Crystallen1/CVE-2025-27636-demo.svg) ![forks](https://img.shields.io/github/forks/Crystallen1/CVE-2025-27636-demo.svg)


## CVE-2025-10874
 The Orbit Fox: Duplicate Page, Menu Icons, SVG Support, Cookie Notice, Custom Fonts & More WordPress plugin before 3.0.2 does not limit URLs which may be used for the stock photo import feature, allowing the user to specify arbitrary URLs. This leads to a server-side request forgery as the user may force the server to access any URL of their choosing.

- [https://github.com/ryanmroth/Orbit-Fox_SSRF_CVE-2025-10874](https://github.com/ryanmroth/Orbit-Fox_SSRF_CVE-2025-10874) :  ![starts](https://img.shields.io/github/stars/ryanmroth/Orbit-Fox_SSRF_CVE-2025-10874.svg) ![forks](https://img.shields.io/github/forks/ryanmroth/Orbit-Fox_SSRF_CVE-2025-10874.svg)


## CVE-2025-6115
 A vulnerability was found in D-Link DIR-619L 2.06B01 and classified as critical. Affected by this issue is the function form_macfilter. The manipulation of the argument mac_hostname_%d/sched_name_%d leads to stack-based buffer overflow. The attack may be launched remotely. The exploit has been disclosed to the public and may be used. This vulnerability only affects products that are no longer supported by the maintainer.

- [https://github.com/pollotherunner/CVE-2025-61155](https://github.com/pollotherunner/CVE-2025-61155) :  ![starts](https://img.shields.io/github/stars/pollotherunner/CVE-2025-61155.svg) ![forks](https://img.shields.io/github/forks/pollotherunner/CVE-2025-61155.svg)


## CVE-2025-6074
This issue affects RMC-100: from 2105457-043 through 2105457-045; RMC-100 LITE: from 2106229-015 through 2106229-016.

- [https://github.com/yawataa/CVE-2025-60749](https://github.com/yawataa/CVE-2025-60749) :  ![starts](https://img.shields.io/github/stars/yawataa/CVE-2025-60749.svg) ![forks](https://img.shields.io/github/forks/yawataa/CVE-2025-60749.svg)


## CVE-2025-6034
 There is a memory corruption vulnerability due to an out of bounds read in DefaultFontOptions() when using SymbolEditor in NI Circuit Design Suite.  This vulnerability may result in information disclosure or arbitrary code execution. Successful exploitation requires an attacker to get a user to open a specially crafted .sym file. This vulnerability affects NI Circuit Design Suite 14.3.1 and prior versions.

- [https://github.com/djackreuter/CVE-2025-60349](https://github.com/djackreuter/CVE-2025-60349) :  ![starts](https://img.shields.io/github/stars/djackreuter/CVE-2025-60349.svg) ![forks](https://img.shields.io/github/forks/djackreuter/CVE-2025-60349.svg)


## CVE-2025-5639
 A vulnerability was found in PHPGurukul Notice Board System 1.0 and classified as critical. Affected by this issue is some unknown functionality of the file /forgot-password.php. The manipulation of the argument email leads to sql injection. The attack may be launched remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/Theethat-Thamwasin/CVE-2025-56399](https://github.com/Theethat-Thamwasin/CVE-2025-56399) :  ![starts](https://img.shields.io/github/stars/Theethat-Thamwasin/CVE-2025-56399.svg) ![forks](https://img.shields.io/github/forks/Theethat-Thamwasin/CVE-2025-56399.svg)


## CVE-2025-3248
code.

- [https://github.com/bambooqj/cve-2025-3248](https://github.com/bambooqj/cve-2025-3248) :  ![starts](https://img.shields.io/github/stars/bambooqj/cve-2025-3248.svg) ![forks](https://img.shields.io/github/forks/bambooqj/cve-2025-3248.svg)


## CVE-2025-1550
 The Keras Model.load_model function permits arbitrary code execution, even with safe_mode=True, through a manually constructed, malicious .keras archive. By altering the config.json file within the archive, an attacker can specify arbitrary Python modules and functions, along with their arguments, to be loaded and executed during model loading.

- [https://github.com/ChCh0i/cve-2025-1550](https://github.com/ChCh0i/cve-2025-1550) :  ![starts](https://img.shields.io/github/stars/ChCh0i/cve-2025-1550.svg) ![forks](https://img.shields.io/github/forks/ChCh0i/cve-2025-1550.svg)


## CVE-2024-32002
 Git is a revision control system. Prior to versions 2.45.1, 2.44.1, 2.43.4, 2.42.2, 2.41.1, 2.40.2, and 2.39.4, repositories with submodules can be crafted in a way that exploits a bug in Git whereby it can be fooled into writing files not into the submodule's worktree but into a `.git/` directory. This allows writing a hook that will be executed while the clone operation is still running, giving the user no opportunity to inspect the code that is being executed. The problem has been patched in versions 2.45.1, 2.44.1, 2.43.4, 2.42.2, 2.41.1, 2.40.2, and 2.39.4. If symbolic link support is disabled in Git (e.g. via `git config --global core.symlinks false`), the described attack won't work. As always, it is best to avoid cloning repositories from untrusted sources.

- [https://github.com/srakkk/cve-2024-32002-hook](https://github.com/srakkk/cve-2024-32002-hook) :  ![starts](https://img.shields.io/github/stars/srakkk/cve-2024-32002-hook.svg) ![forks](https://img.shields.io/github/forks/srakkk/cve-2024-32002-hook.svg)
- [https://github.com/srakkk/cve-2024-32002-demo](https://github.com/srakkk/cve-2024-32002-demo) :  ![starts](https://img.shields.io/github/stars/srakkk/cve-2024-32002-demo.svg) ![forks](https://img.shields.io/github/forks/srakkk/cve-2024-32002-demo.svg)


## CVE-2024-7387
 A flaw was found in openshift/builder. This vulnerability allows command injection via path traversal, where a malicious user can execute arbitrary commands on the OpenShift node running the builder container. When using the “Docker” strategy, executable files inside the privileged build container can be overridden using the `spec.source.secrets.secret.destinationDir` attribute of the `BuildConfig` definition. An attacker running code in a privileged container could escalate their permissions on the node running the container.

- [https://github.com/0xSigSegv0x00/cve-2024-7387](https://github.com/0xSigSegv0x00/cve-2024-7387) :  ![starts](https://img.shields.io/github/stars/0xSigSegv0x00/cve-2024-7387.svg) ![forks](https://img.shields.io/github/forks/0xSigSegv0x00/cve-2024-7387.svg)


## CVE-2023-22515
Atlassian Cloud sites are not affected by this vulnerability. If your Confluence site is accessed via an atlassian.net domain, it is hosted by Atlassian and is not vulnerable to this issue. 

- [https://github.com/Arkha-Corvus/LetsDefend-SOC235-Atlassian-Confluence-Broken-Access-Control-0-Day-CVE-2023-22515-EventID-197](https://github.com/Arkha-Corvus/LetsDefend-SOC235-Atlassian-Confluence-Broken-Access-Control-0-Day-CVE-2023-22515-EventID-197) :  ![starts](https://img.shields.io/github/stars/Arkha-Corvus/LetsDefend-SOC235-Atlassian-Confluence-Broken-Access-Control-0-Day-CVE-2023-22515-EventID-197.svg) ![forks](https://img.shields.io/github/forks/Arkha-Corvus/LetsDefend-SOC235-Atlassian-Confluence-Broken-Access-Control-0-Day-CVE-2023-22515-EventID-197.svg)


## CVE-2019-7069
 Adobe Acrobat and Reader versions 2019.010.20069 and earlier, 2019.010.20069 and earlier, 2017.011.30113 and earlier version, and 2015.006.30464 and earlier have a type confusion vulnerability. Successful exploitation could lead to arbitrary code execution .

- [https://github.com/CaelumIsMe/CVE-2019-7069-POC](https://github.com/CaelumIsMe/CVE-2019-7069-POC) :  ![starts](https://img.shields.io/github/stars/CaelumIsMe/CVE-2019-7069-POC.svg) ![forks](https://img.shields.io/github/forks/CaelumIsMe/CVE-2019-7069-POC.svg)

