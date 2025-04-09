# Update 2025-04-09
## CVE-2025-31486
 Vite is a frontend tooling framework for javascript. The contents of arbitrary files can be returned to the browser. By adding ?.svg with ?.wasm?init or with sec-fetch-dest: script header, the server.fs.deny restriction was able to bypass. This bypass is only possible if the file is smaller than build.assetsInlineLimit (default: 4kB) and when using Vite 6.0+. Only apps explicitly exposing the Vite dev server to the network (using --host or server.host config option) are affected. This vulnerability is fixed in 4.5.12, 5.4.17, 6.0.14, 6.1.4, and 6.2.5.

- [https://github.com/iSee857/CVE-2025-31486-PoC](https://github.com/iSee857/CVE-2025-31486-PoC) :  ![starts](https://img.shields.io/github/stars/iSee857/CVE-2025-31486-PoC.svg) ![forks](https://img.shields.io/github/forks/iSee857/CVE-2025-31486-PoC.svg)


## CVE-2025-30065
Users are recommended to upgrade to version 1.15.1, which fixes the issue.

- [https://github.com/mouadk/parquet-rce-poc-CVE-2025-30065](https://github.com/mouadk/parquet-rce-poc-CVE-2025-30065) :  ![starts](https://img.shields.io/github/stars/mouadk/parquet-rce-poc-CVE-2025-30065.svg) ![forks](https://img.shields.io/github/forks/mouadk/parquet-rce-poc-CVE-2025-30065.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Prior to 14.2.25 and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 14.2.25 and 15.2.3.

- [https://github.com/pixilated730/NextJS-Exploit-](https://github.com/pixilated730/NextJS-Exploit-) :  ![starts](https://img.shields.io/github/stars/pixilated730/NextJS-Exploit-.svg) ![forks](https://img.shields.io/github/forks/pixilated730/NextJS-Exploit-.svg)


## CVE-2025-24813
Users are recommended to upgrade to version 11.0.3, 10.1.35 or 9.0.99, which fixes the issue.

- [https://github.com/horsehacks/CVE-2025-24813-checker](https://github.com/horsehacks/CVE-2025-24813-checker) :  ![starts](https://img.shields.io/github/stars/horsehacks/CVE-2025-24813-checker.svg) ![forks](https://img.shields.io/github/forks/horsehacks/CVE-2025-24813-checker.svg)
- [https://github.com/Heimd411/CVE-2025-24813-noPoC](https://github.com/Heimd411/CVE-2025-24813-noPoC) :  ![starts](https://img.shields.io/github/stars/Heimd411/CVE-2025-24813-noPoC.svg) ![forks](https://img.shields.io/github/forks/Heimd411/CVE-2025-24813-noPoC.svg)


## CVE-2025-3048
Users should upgrade to version 1.134.0 and ensure any forked or derivative code is patched to incorporate the new fixes. After upgrading, users must re-build their applications using the sam build --use-container to update the symlinks.

- [https://github.com/murataydemir/AWS-SAM-CLI-Vulnerabilities](https://github.com/murataydemir/AWS-SAM-CLI-Vulnerabilities) :  ![starts](https://img.shields.io/github/stars/murataydemir/AWS-SAM-CLI-Vulnerabilities.svg) ![forks](https://img.shields.io/github/forks/murataydemir/AWS-SAM-CLI-Vulnerabilities.svg)


## CVE-2025-3047
Users should upgrade to v1.133.0 or newer and ensure any forked or derivative code is patched to incorporate the new fixes.

- [https://github.com/murataydemir/AWS-SAM-CLI-Vulnerabilities](https://github.com/murataydemir/AWS-SAM-CLI-Vulnerabilities) :  ![starts](https://img.shields.io/github/stars/murataydemir/AWS-SAM-CLI-Vulnerabilities.svg) ![forks](https://img.shields.io/github/forks/murataydemir/AWS-SAM-CLI-Vulnerabilities.svg)


## CVE-2024-44871
 An arbitrary file upload vulnerability in the component /admin/index.php of moziloCMS v3.0 allows attackers to execute arbitrary code via uploading a crafted file.

- [https://github.com/vances25/CVE-2024-44871](https://github.com/vances25/CVE-2024-44871) :  ![starts](https://img.shields.io/github/stars/vances25/CVE-2024-44871.svg) ![forks](https://img.shields.io/github/forks/vances25/CVE-2024-44871.svg)


## CVE-2022-29078
 The ejs (aka Embedded JavaScript templates) package 3.1.6 for Node.js allows server-side template injection in settings[view options][outputFunctionName]. This is parsed as an internal option, and overwrites the outputFunctionName option with an arbitrary OS command (which is executed upon template compilation).

- [https://github.com/dangducloc/CVE_2022_29078](https://github.com/dangducloc/CVE_2022_29078) :  ![starts](https://img.shields.io/github/stars/dangducloc/CVE_2022_29078.svg) ![forks](https://img.shields.io/github/forks/dangducloc/CVE_2022_29078.svg)


## CVE-2019-14224
 An issue was discovered in Alfresco Community Edition 5.2 201707. By leveraging multiple components in the Alfresco Software applications, an exploit chain was observed that allows an attacker to achieve remote code execution on the victim machine. The attacker must upload malicious Solr configuration files and then receive a JMX connection from the victim, and serve a Java object that results in deserialization and code execution.

- [https://github.com/mbadanoiu/CVE-2019-14224](https://github.com/mbadanoiu/CVE-2019-14224) :  ![starts](https://img.shields.io/github/stars/mbadanoiu/CVE-2019-14224.svg) ![forks](https://img.shields.io/github/forks/mbadanoiu/CVE-2019-14224.svg)


## CVE-2019-14223
 An issue was discovered in Alfresco Community Edition versions below 5.2.6, 6.0.N and 6.1.N. The Alfresco Share application is vulnerable to an Open Redirect attack via a crafted POST request. By manipulating the POST parameters, an attacker can redirect a victim to a malicious website over any protocol the attacker desires (e.g.,http, https, ftp, smb, etc.).

- [https://github.com/mbadanoiu/CVE-2019-14223](https://github.com/mbadanoiu/CVE-2019-14223) :  ![starts](https://img.shields.io/github/stars/mbadanoiu/CVE-2019-14223.svg) ![forks](https://img.shields.io/github/forks/mbadanoiu/CVE-2019-14223.svg)


## CVE-2019-14222
 An issue was discovered in Alfresco Community Edition versions 6.0 and lower. An unauthenticated, remote attacker could authenticate to Alfresco's Solr Web Admin Interface. The vulnerability is due to the presence of a default private key that is present in all default installations. An attacker could exploit this vulnerability by using the extracted private key and bundling it into a PKCS12. A successful exploit could allow the attacker to gain information about the target system (e.g., OS type, system file locations, Java version, Solr version, etc.) as well as the ability to launch further attacks by leveraging the access to Alfresco's Solr Web Admin Interface.

- [https://github.com/mbadanoiu/CVE-2019-14222](https://github.com/mbadanoiu/CVE-2019-14222) :  ![starts](https://img.shields.io/github/stars/mbadanoiu/CVE-2019-14222.svg) ![forks](https://img.shields.io/github/forks/mbadanoiu/CVE-2019-14222.svg)


## CVE-2019-12409
 The 8.1.1 and 8.2.0 releases of Apache Solr contain an insecure setting for the ENABLE_REMOTE_JMX_OPTS configuration option in the default solr.in.sh configuration file shipping with Solr. If you use the default solr.in.sh file from the affected releases, then JMX monitoring will be enabled and exposed on RMI_PORT (default=18983), without any authentication. If this port is opened for inbound traffic in your firewall, then anyone with network access to your Solr nodes will be able to access JMX, which may in turn allow them to upload malicious code for execution on the Solr server.

- [https://github.com/mbadanoiu/CVE-2019-12409](https://github.com/mbadanoiu/CVE-2019-12409) :  ![starts](https://img.shields.io/github/stars/mbadanoiu/CVE-2019-12409.svg) ![forks](https://img.shields.io/github/forks/mbadanoiu/CVE-2019-12409.svg)


## CVE-2019-12401
 Solr versions 1.3.0 to 1.4.1, 3.1.0 to 3.6.2 and 4.0.0 to 4.10.4 are vulnerable to an XML resource consumption attack (a.k.a. Lol Bomb) via it’s update handler.?By leveraging XML DOCTYPE and ENTITY type elements, the attacker can create a pattern that will expand when the server parses the XML causing OOMs.

- [https://github.com/mbadanoiu/CVE-2019-12401](https://github.com/mbadanoiu/CVE-2019-12401) :  ![starts](https://img.shields.io/github/stars/mbadanoiu/CVE-2019-12401.svg) ![forks](https://img.shields.io/github/forks/mbadanoiu/CVE-2019-12401.svg)


## CVE-2019-11287
 Pivotal RabbitMQ, versions 3.7.x prior to 3.7.21 and 3.8.x prior to 3.8.1, and RabbitMQ for Pivotal Platform, 1.16.x versions prior to 1.16.7 and 1.17.x versions prior to 1.17.4, contain a web management plugin that is vulnerable to a denial of service attack. The "X-Reason" HTTP Header can be leveraged to insert a malicious Erlang format string that will expand and consume the heap, resulting in the server crashing.

- [https://github.com/mbadanoiu/CVE-2019-11287](https://github.com/mbadanoiu/CVE-2019-11287) :  ![starts](https://img.shields.io/github/stars/mbadanoiu/CVE-2019-11287.svg) ![forks](https://img.shields.io/github/forks/mbadanoiu/CVE-2019-11287.svg)


## CVE-2019-5418
 There is a File Content Disclosure vulnerability in Action View 5.2.2.1, 5.1.6.2, 5.0.7.2, 4.2.11.1 and v3 where specially crafted accept headers can cause contents of arbitrary files on the target system's filesystem to be exposed.

- [https://github.com/daehyeok0618/CVE-2019-5418](https://github.com/daehyeok0618/CVE-2019-5418) :  ![starts](https://img.shields.io/github/stars/daehyeok0618/CVE-2019-5418.svg) ![forks](https://img.shields.io/github/forks/daehyeok0618/CVE-2019-5418.svg)

