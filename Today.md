# Update 2021-12-14
## CVE-2021-44228
 Apache Log4j2 &lt;=2.14.1 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled. From log4j 2.15.0, this behavior has been disabled by default. In previous releases (&gt;2.10) this behavior can be mitigated by setting system property &quot;log4j2.formatMsgNoLookups&quot; to &#8220;true&#8221; or it can be mitigated in prior releases (&lt;2.10) by removing the JndiLookup class from the classpath (example: zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class).

- [https://github.com/0-x-2-2/CVE-2021-44228](https://github.com/0-x-2-2/CVE-2021-44228) :  ![starts](https://img.shields.io/github/stars/0-x-2-2/CVE-2021-44228.svg) ![forks](https://img.shields.io/github/forks/0-x-2-2/CVE-2021-44228.svg)
- [https://github.com/authomize/log4j-log4shell-affected](https://github.com/authomize/log4j-log4shell-affected) :  ![starts](https://img.shields.io/github/stars/authomize/log4j-log4shell-affected.svg) ![forks](https://img.shields.io/github/forks/authomize/log4j-log4shell-affected.svg)
- [https://github.com/fullhunt/log4j-scan](https://github.com/fullhunt/log4j-scan) :  ![starts](https://img.shields.io/github/stars/fullhunt/log4j-scan.svg) ![forks](https://img.shields.io/github/forks/fullhunt/log4j-scan.svg)
- [https://github.com/qingtengyun/cve-2021-44228-qingteng-online-patch](https://github.com/qingtengyun/cve-2021-44228-qingteng-online-patch) :  ![starts](https://img.shields.io/github/stars/qingtengyun/cve-2021-44228-qingteng-online-patch.svg) ![forks](https://img.shields.io/github/forks/qingtengyun/cve-2021-44228-qingteng-online-patch.svg)
- [https://github.com/bigsizeme/Log4j-check](https://github.com/bigsizeme/Log4j-check) :  ![starts](https://img.shields.io/github/stars/bigsizeme/Log4j-check.svg) ![forks](https://img.shields.io/github/forks/bigsizeme/Log4j-check.svg)
- [https://github.com/ssl/scan4log4j](https://github.com/ssl/scan4log4j) :  ![starts](https://img.shields.io/github/stars/ssl/scan4log4j.svg) ![forks](https://img.shields.io/github/forks/ssl/scan4log4j.svg)
- [https://github.com/infiniroot/nginx-mitigate-log4shell](https://github.com/infiniroot/nginx-mitigate-log4shell) :  ![starts](https://img.shields.io/github/stars/infiniroot/nginx-mitigate-log4shell.svg) ![forks](https://img.shields.io/github/forks/infiniroot/nginx-mitigate-log4shell.svg)
- [https://github.com/qingtengyun/cve-2021-44228-qingteng-patch](https://github.com/qingtengyun/cve-2021-44228-qingteng-patch) :  ![starts](https://img.shields.io/github/stars/qingtengyun/cve-2021-44228-qingteng-patch.svg) ![forks](https://img.shields.io/github/forks/qingtengyun/cve-2021-44228-qingteng-patch.svg)
- [https://github.com/Diverto/nse-log4shell](https://github.com/Diverto/nse-log4shell) :  ![starts](https://img.shields.io/github/stars/Diverto/nse-log4shell.svg) ![forks](https://img.shields.io/github/forks/Diverto/nse-log4shell.svg)
- [https://github.com/momos1337/Log4j-RCE](https://github.com/momos1337/Log4j-RCE) :  ![starts](https://img.shields.io/github/stars/momos1337/Log4j-RCE.svg) ![forks](https://img.shields.io/github/forks/momos1337/Log4j-RCE.svg)
- [https://github.com/pedrohavay/exploit-CVE-2021-44228](https://github.com/pedrohavay/exploit-CVE-2021-44228) :  ![starts](https://img.shields.io/github/stars/pedrohavay/exploit-CVE-2021-44228.svg) ![forks](https://img.shields.io/github/forks/pedrohavay/exploit-CVE-2021-44228.svg)
- [https://github.com/sud0x00/log4j-CVE-2021-44228](https://github.com/sud0x00/log4j-CVE-2021-44228) :  ![starts](https://img.shields.io/github/stars/sud0x00/log4j-CVE-2021-44228.svg) ![forks](https://img.shields.io/github/forks/sud0x00/log4j-CVE-2021-44228.svg)
- [https://github.com/twseptian/Spring-Boot-Log4j-CVE-2021-44228-Docker-Lab](https://github.com/twseptian/Spring-Boot-Log4j-CVE-2021-44228-Docker-Lab) :  ![starts](https://img.shields.io/github/stars/twseptian/Spring-Boot-Log4j-CVE-2021-44228-Docker-Lab.svg) ![forks](https://img.shields.io/github/forks/twseptian/Spring-Boot-Log4j-CVE-2021-44228-Docker-Lab.svg)
- [https://github.com/Malwar3Ninja/Exploitation-of-Log4j2-CVE-2021-44228](https://github.com/Malwar3Ninja/Exploitation-of-Log4j2-CVE-2021-44228) :  ![starts](https://img.shields.io/github/stars/Malwar3Ninja/Exploitation-of-Log4j2-CVE-2021-44228.svg) ![forks](https://img.shields.io/github/forks/Malwar3Ninja/Exploitation-of-Log4j2-CVE-2021-44228.svg)
- [https://github.com/unlimitedsola/log4j2-rce-poc](https://github.com/unlimitedsola/log4j2-rce-poc) :  ![starts](https://img.shields.io/github/stars/unlimitedsola/log4j2-rce-poc.svg) ![forks](https://img.shields.io/github/forks/unlimitedsola/log4j2-rce-poc.svg)
- [https://github.com/RrUZi/Awesome-CVE-2021-44228](https://github.com/RrUZi/Awesome-CVE-2021-44228) :  ![starts](https://img.shields.io/github/stars/RrUZi/Awesome-CVE-2021-44228.svg) ![forks](https://img.shields.io/github/forks/RrUZi/Awesome-CVE-2021-44228.svg)
- [https://github.com/DiCanio/CVE-2021-44228-docker-example](https://github.com/DiCanio/CVE-2021-44228-docker-example) :  ![starts](https://img.shields.io/github/stars/DiCanio/CVE-2021-44228-docker-example.svg) ![forks](https://img.shields.io/github/forks/DiCanio/CVE-2021-44228-docker-example.svg)
- [https://github.com/pravin-pp/log4j2-CVE-2021-44228](https://github.com/pravin-pp/log4j2-CVE-2021-44228) :  ![starts](https://img.shields.io/github/stars/pravin-pp/log4j2-CVE-2021-44228.svg) ![forks](https://img.shields.io/github/forks/pravin-pp/log4j2-CVE-2021-44228.svg)
- [https://github.com/alerithe/log4noshell](https://github.com/alerithe/log4noshell) :  ![starts](https://img.shields.io/github/stars/alerithe/log4noshell.svg) ![forks](https://img.shields.io/github/forks/alerithe/log4noshell.svg)
- [https://github.com/cyberxml/log4j-poc](https://github.com/cyberxml/log4j-poc) :  ![starts](https://img.shields.io/github/stars/cyberxml/log4j-poc.svg) ![forks](https://img.shields.io/github/forks/cyberxml/log4j-poc.svg)
- [https://github.com/Hydragyrum/evil-rmi-server](https://github.com/Hydragyrum/evil-rmi-server) :  ![starts](https://img.shields.io/github/stars/Hydragyrum/evil-rmi-server.svg) ![forks](https://img.shields.io/github/forks/Hydragyrum/evil-rmi-server.svg)
- [https://github.com/fireflyingup/log4j-poc](https://github.com/fireflyingup/log4j-poc) :  ![starts](https://img.shields.io/github/stars/fireflyingup/log4j-poc.svg) ![forks](https://img.shields.io/github/forks/fireflyingup/log4j-poc.svg)
- [https://github.com/ahmad4fifz-dev/CVE-2021-44228](https://github.com/ahmad4fifz-dev/CVE-2021-44228) :  ![starts](https://img.shields.io/github/stars/ahmad4fifz-dev/CVE-2021-44228.svg) ![forks](https://img.shields.io/github/forks/ahmad4fifz-dev/CVE-2021-44228.svg)
- [https://github.com/mute1997/CVE-2021-44228-research](https://github.com/mute1997/CVE-2021-44228-research) :  ![starts](https://img.shields.io/github/stars/mute1997/CVE-2021-44228-research.svg) ![forks](https://img.shields.io/github/forks/mute1997/CVE-2021-44228-research.svg)
- [https://github.com/fireeye/CVE-2021-44228](https://github.com/fireeye/CVE-2021-44228) :  ![starts](https://img.shields.io/github/stars/fireeye/CVE-2021-44228.svg) ![forks](https://img.shields.io/github/forks/fireeye/CVE-2021-44228.svg)
- [https://github.com/uint0/cve-2021-44228-helpers](https://github.com/uint0/cve-2021-44228-helpers) :  ![starts](https://img.shields.io/github/stars/uint0/cve-2021-44228-helpers.svg) ![forks](https://img.shields.io/github/forks/uint0/cve-2021-44228-helpers.svg)
- [https://github.com/kimobu/cve-2021-44228](https://github.com/kimobu/cve-2021-44228) :  ![starts](https://img.shields.io/github/stars/kimobu/cve-2021-44228.svg) ![forks](https://img.shields.io/github/forks/kimobu/cve-2021-44228.svg)
- [https://github.com/Panyaprach/Proof-CVE-2021-44228](https://github.com/Panyaprach/Proof-CVE-2021-44228) :  ![starts](https://img.shields.io/github/stars/Panyaprach/Proof-CVE-2021-44228.svg) ![forks](https://img.shields.io/github/forks/Panyaprach/Proof-CVE-2021-44228.svg)
- [https://github.com/bchaber/CVE-2021-44228](https://github.com/bchaber/CVE-2021-44228) :  ![starts](https://img.shields.io/github/stars/bchaber/CVE-2021-44228.svg) ![forks](https://img.shields.io/github/forks/bchaber/CVE-2021-44228.svg)
- [https://github.com/myyxl/cve-2021-44228-minecraft-poc](https://github.com/myyxl/cve-2021-44228-minecraft-poc) :  ![starts](https://img.shields.io/github/stars/myyxl/cve-2021-44228-minecraft-poc.svg) ![forks](https://img.shields.io/github/forks/myyxl/cve-2021-44228-minecraft-poc.svg)
- [https://github.com/uint0/cve-2021-44228--spring-hibernate](https://github.com/uint0/cve-2021-44228--spring-hibernate) :  ![starts](https://img.shields.io/github/stars/uint0/cve-2021-44228--spring-hibernate.svg) ![forks](https://img.shields.io/github/forks/uint0/cve-2021-44228--spring-hibernate.svg)
- [https://github.com/thecyberneh/LOG4J-Exploiter](https://github.com/thecyberneh/LOG4J-Exploiter) :  ![starts](https://img.shields.io/github/stars/thecyberneh/LOG4J-Exploiter.svg) ![forks](https://img.shields.io/github/forks/thecyberneh/LOG4J-Exploiter.svg)
- [https://github.com/Crane-Mocker/log4j-poc](https://github.com/Crane-Mocker/log4j-poc) :  ![starts](https://img.shields.io/github/stars/Crane-Mocker/log4j-poc.svg) ![forks](https://img.shields.io/github/forks/Crane-Mocker/log4j-poc.svg)
- [https://github.com/sunnyvale-it/CVE-2021-44228-PoC](https://github.com/sunnyvale-it/CVE-2021-44228-PoC) :  ![starts](https://img.shields.io/github/stars/sunnyvale-it/CVE-2021-44228-PoC.svg) ![forks](https://img.shields.io/github/forks/sunnyvale-it/CVE-2021-44228-PoC.svg)
- [https://github.com/guardicode/CVE-2021-44228_IoCs](https://github.com/guardicode/CVE-2021-44228_IoCs) :  ![starts](https://img.shields.io/github/stars/guardicode/CVE-2021-44228_IoCs.svg) ![forks](https://img.shields.io/github/forks/guardicode/CVE-2021-44228_IoCs.svg)
- [https://github.com/lohanichaten/log4j-cve-2021-44228](https://github.com/lohanichaten/log4j-cve-2021-44228) :  ![starts](https://img.shields.io/github/stars/lohanichaten/log4j-cve-2021-44228.svg) ![forks](https://img.shields.io/github/forks/lohanichaten/log4j-cve-2021-44228.svg)
- [https://github.com/kali-dass/CVE-2021-44228-log4Shell](https://github.com/kali-dass/CVE-2021-44228-log4Shell) :  ![starts](https://img.shields.io/github/stars/kali-dass/CVE-2021-44228-log4Shell.svg) ![forks](https://img.shields.io/github/forks/kali-dass/CVE-2021-44228-log4Shell.svg)


## CVE-2021-43936
 The software allows the attacker to upload or transfer files of dangerous types to the WebHMI portal, that may be automatically processed within the product's environment or lead to arbitrary code execution.

- [https://github.com/LongWayHomie/CVE-2021-43936](https://github.com/LongWayHomie/CVE-2021-43936) :  ![starts](https://img.shields.io/github/stars/LongWayHomie/CVE-2021-43936.svg) ![forks](https://img.shields.io/github/forks/LongWayHomie/CVE-2021-43936.svg)


## CVE-2021-43798
 Grafana is an open-source platform for monitoring and observability. Grafana versions 8.0.0-beta1 through 8.3.0 (except for patched versions) iss vulnerable to directory traversal, allowing access to local files. The vulnerable URL path is: `&lt;grafana_host_url&gt;/public/plugins//`, where is the plugin ID for any installed plugin. At no time has Grafana Cloud been vulnerable. Users are advised to upgrade to patched versions 8.0.7, 8.1.8, 8.2.7, or 8.3.1. The GitHub Security Advisory contains more information about vulnerable URL paths, mitigation, and the disclosure timeline.

- [https://github.com/gixxyboy/CVE-2021-43798](https://github.com/gixxyboy/CVE-2021-43798) :  ![starts](https://img.shields.io/github/stars/gixxyboy/CVE-2021-43798.svg) ![forks](https://img.shields.io/github/forks/gixxyboy/CVE-2021-43798.svg)
- [https://github.com/Awrrays/Grafana-CVE-2021-43798](https://github.com/Awrrays/Grafana-CVE-2021-43798) :  ![starts](https://img.shields.io/github/stars/Awrrays/Grafana-CVE-2021-43798.svg) ![forks](https://img.shields.io/github/forks/Awrrays/Grafana-CVE-2021-43798.svg)


## CVE-2021-36749
 In the Druid ingestion system, the InputSource is used for reading data from a certain data source. However, the HTTP InputSource allows authenticated users to read data from other sources than intended, such as the local file system, with the privileges of the Druid server process. This is not an elevation of privilege when users access Druid directly, since Druid also provides the Local InputSource, which allows the same level of access. But it is problematic when users interact with Druid indirectly through an application that allows users to specify the HTTP InputSource, but not the Local InputSource. In this case, users could bypass the application-level restriction by passing a file URL to the HTTP InputSource. This issue was previously mentioned as being fixed in 0.21.0 as per CVE-2021-26920 but was not fixed in 0.21.0 or 0.21.1.

- [https://github.com/Jun-5heng/CVE-2021-36749](https://github.com/Jun-5heng/CVE-2021-36749) :  ![starts](https://img.shields.io/github/stars/Jun-5heng/CVE-2021-36749.svg) ![forks](https://img.shields.io/github/forks/Jun-5heng/CVE-2021-36749.svg)


## CVE-2021-25646
 Apache Druid includes the ability to execute user-provided JavaScript code embedded in various types of requests. This functionality is intended for use in high-trust environments, and is disabled by default. However, in Druid 0.20.0 and earlier, it is possible for an authenticated user to send a specially-crafted request that forces Druid to run user-provided JavaScript code for that request, regardless of server configuration. This can be leveraged to execute code on the target machine with the privileges of the Druid server process.

- [https://github.com/j2ekim/CVE-2021-25646](https://github.com/j2ekim/CVE-2021-25646) :  ![starts](https://img.shields.io/github/stars/j2ekim/CVE-2021-25646.svg) ![forks](https://img.shields.io/github/forks/j2ekim/CVE-2021-25646.svg)


## CVE-2020-27955
 Git LFS 2.12.0 allows Remote Code Execution.

- [https://github.com/HK69s/CVE-2020-27955](https://github.com/HK69s/CVE-2020-27955) :  ![starts](https://img.shields.io/github/stars/HK69s/CVE-2020-27955.svg) ![forks](https://img.shields.io/github/forks/HK69s/CVE-2020-27955.svg)


## CVE-2020-8175
 Uncontrolled resource consumption in `jpeg-js` before 0.4.0 may allow attacker to launch denial of service attacks using specially a crafted JPEG image.

- [https://github.com/knokbak/get-pixels-updated](https://github.com/knokbak/get-pixels-updated) :  ![starts](https://img.shields.io/github/stars/knokbak/get-pixels-updated.svg) ![forks](https://img.shields.io/github/forks/knokbak/get-pixels-updated.svg)
- [https://github.com/knokbak/save-pixels-updated](https://github.com/knokbak/save-pixels-updated) :  ![starts](https://img.shields.io/github/stars/knokbak/save-pixels-updated.svg) ![forks](https://img.shields.io/github/forks/knokbak/save-pixels-updated.svg)


## CVE-2019-17571
 Included in Log4j 1.2 is a SocketServer class that is vulnerable to deserialization of untrusted data which can be exploited to remotely execute arbitrary code when combined with a deserialization gadget when listening to untrusted network traffic for log data. This affects Log4j versions up to 1.2 up to 1.2.17.

- [https://github.com/hillu/local-log4j-vuln-scanner](https://github.com/hillu/local-log4j-vuln-scanner) :  ![starts](https://img.shields.io/github/stars/hillu/local-log4j-vuln-scanner.svg) ![forks](https://img.shields.io/github/forks/hillu/local-log4j-vuln-scanner.svg)


## CVE-2019-16113
 Bludit 3.9.2 allows remote code execution via bl-kernel/ajax/upload-images.php because PHP code can be entered with a .jpg file name, and then this PHP code can write other PHP code to a ../ pathname.

- [https://github.com/zeroxninety/CVE-2019-16113-PoC](https://github.com/zeroxninety/CVE-2019-16113-PoC) :  ![starts](https://img.shields.io/github/stars/zeroxninety/CVE-2019-16113-PoC.svg) ![forks](https://img.shields.io/github/forks/zeroxninety/CVE-2019-16113-PoC.svg)


## CVE-2019-9168
 WooCommerce before 3.5.5 allows XSS via a Photoswipe caption.

- [https://github.com/tthseus/WooCommerce-CVEs](https://github.com/tthseus/WooCommerce-CVEs) :  ![starts](https://img.shields.io/github/stars/tthseus/WooCommerce-CVEs.svg) ![forks](https://img.shields.io/github/forks/tthseus/WooCommerce-CVEs.svg)


## CVE-2018-20148
 In WordPress before 4.9.9 and 5.x before 5.0.1, contributors could conduct PHP object injection attacks via crafted metadata in a wp.getMediaItem XMLRPC call. This is caused by mishandling of serialized data at phar:// URLs in the wp_get_attachment_thumb_file function in wp-includes/post.php.

- [https://github.com/tthseus/WooCommerce-CVEs](https://github.com/tthseus/WooCommerce-CVEs) :  ![starts](https://img.shields.io/github/stars/tthseus/WooCommerce-CVEs.svg) ![forks](https://img.shields.io/github/forks/tthseus/WooCommerce-CVEs.svg)


## CVE-2018-15473
 OpenSSH through 7.7 is prone to a user enumeration vulnerability due to not delaying bailout for an invalid authenticating user until after the packet containing the request has been fully parsed, related to auth2-gss.c, auth2-hostbased.c, and auth2-pubkey.c.

- [https://github.com/66quentin/shodan-CVE-2018-15473](https://github.com/66quentin/shodan-CVE-2018-15473) :  ![starts](https://img.shields.io/github/stars/66quentin/shodan-CVE-2018-15473.svg) ![forks](https://img.shields.io/github/forks/66quentin/shodan-CVE-2018-15473.svg)


## CVE-2017-12617
 When running Apache Tomcat versions 9.0.0.M1 to 9.0.0, 8.5.0 to 8.5.22, 8.0.0.RC1 to 8.0.46 and 7.0.0 to 7.0.81 with HTTP PUTs enabled (e.g. via setting the readonly initialisation parameter of the Default servlet to false) it was possible to upload a JSP file to the server via a specially crafted request. This JSP could then be requested and any code it contained would be executed by the server.

- [https://github.com/LongWayHomie/CVE-2017-12617](https://github.com/LongWayHomie/CVE-2017-12617) :  ![starts](https://img.shields.io/github/stars/LongWayHomie/CVE-2017-12617.svg) ![forks](https://img.shields.io/github/forks/LongWayHomie/CVE-2017-12617.svg)


## CVE-2017-5693
 Firmware in the Intel Puma 5, 6, and 7 Series might experience resource depletion or timeout, which allows a network attacker to create a denial of service via crafted network traffic.

- [https://github.com/LunNova/Puma6Fail](https://github.com/LunNova/Puma6Fail) :  ![starts](https://img.shields.io/github/stars/LunNova/Puma6Fail.svg) ![forks](https://img.shields.io/github/forks/LunNova/Puma6Fail.svg)


## CVE-2017-5645
 In Apache Log4j 2.x before 2.8.2, when using the TCP socket server or UDP socket server to receive serialized log events from another application, a specially crafted binary payload can be sent that, when deserialized, can execute arbitrary code.

- [https://github.com/sefayfr/log4j-RCE](https://github.com/sefayfr/log4j-RCE) :  ![starts](https://img.shields.io/github/stars/sefayfr/log4j-RCE.svg) ![forks](https://img.shields.io/github/forks/sefayfr/log4j-RCE.svg)


## CVE-2007-2447
 The MS-RPC functionality in smbd in Samba 3.0.0 through 3.0.25rc3 allows remote attackers to execute arbitrary commands via shell metacharacters involving the (1) SamrChangePassword function, when the &quot;username map script&quot; smb.conf option is enabled, and allows remote authenticated users to execute commands via shell metacharacters involving other MS-RPC functions in the (2) remote printer and (3) file share management.

- [https://github.com/SamHackingArticles/CVE-2007-2447](https://github.com/SamHackingArticles/CVE-2007-2447) :  ![starts](https://img.shields.io/github/stars/SamHackingArticles/CVE-2007-2447.svg) ![forks](https://img.shields.io/github/forks/SamHackingArticles/CVE-2007-2447.svg)

