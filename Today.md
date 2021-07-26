# Update 2021-07-26
## CVE-2021-36934
 Windows Elevation of Privilege Vulnerability

- [https://github.com/cube0x0/CVE-2021-36934](https://github.com/cube0x0/CVE-2021-36934) :  ![starts](https://img.shields.io/github/stars/cube0x0/CVE-2021-36934.svg) ![forks](https://img.shields.io/github/forks/cube0x0/CVE-2021-36934.svg)
- [https://github.com/Sp00p64/PyNightmare](https://github.com/Sp00p64/PyNightmare) :  ![starts](https://img.shields.io/github/stars/Sp00p64/PyNightmare.svg) ![forks](https://img.shields.io/github/forks/Sp00p64/PyNightmare.svg)


## CVE-2021-28906
 In function read_yin_leaf() in libyang &lt;= v1.0.225, it doesn't check whether the value of retval-&gt;ext[r] is NULL. In some cases, it can be NULL, which leads to the operation of retval-&gt;ext[r]-&gt;flags that results in a crash.

- [https://github.com/AlAIAL90/CVE-2021-28906](https://github.com/AlAIAL90/CVE-2021-28906) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2021-28906.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2021-28906.svg)


## CVE-2021-28905
 In function lys_node_free() in libyang &lt;= v1.0.225, it asserts that the value of node-&gt;module can't be NULL. But in some cases, node-&gt;module can be null, which triggers a reachable assertion (CWE-617).

- [https://github.com/AlAIAL90/CVE-2021-28905](https://github.com/AlAIAL90/CVE-2021-28905) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2021-28905.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2021-28905.svg)


## CVE-2021-28904
 In function ext_get_plugin() in libyang &lt;= v1.0.225, it doesn't check whether the value of revision is NULL. If revision is NULL, the operation of strcmp(revision, ext_plugins[u].revision) will lead to a crash.

- [https://github.com/AlAIAL90/CVE-2021-28904](https://github.com/AlAIAL90/CVE-2021-28904) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2021-28904.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2021-28904.svg)


## CVE-2021-28903
 A stack overflow in libyang &lt;= v1.0.225 can cause a denial of service through function lyxml_parse_mem(). lyxml_parse_elem() function will be called recursively, which will consume stack space and lead to crash.

- [https://github.com/AlAIAL90/CVE-2021-28903](https://github.com/AlAIAL90/CVE-2021-28903) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2021-28903.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2021-28903.svg)


## CVE-2021-28902
 In function read_yin_container() in libyang &lt;= v1.0.225, it doesn't check whether the value of retval-&gt;ext[r] is NULL. In some cases, it can be NULL, which leads to the operation of retval-&gt;ext[r]-&gt;flags that results in a crash.

- [https://github.com/AlAIAL90/CVE-2021-28902](https://github.com/AlAIAL90/CVE-2021-28902) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2021-28902.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2021-28902.svg)


## CVE-2020-36281
 Leptonica before 1.80.0 allows a heap-based buffer over-read in pixFewColorsOctcubeQuantMixed in colorquant1.c.

- [https://github.com/AlAIAL90/CVE-2020-36281](https://github.com/AlAIAL90/CVE-2020-36281) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2020-36281.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2020-36281.svg)


## CVE-2020-36280
 Leptonica before 1.80.0 allows a heap-based buffer over-read in pixReadFromTiffStream, related to tiffio.c.

- [https://github.com/AlAIAL90/CVE-2020-36280](https://github.com/AlAIAL90/CVE-2020-36280) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2020-36280.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2020-36280.svg)


## CVE-2020-36279
 Leptonica before 1.80.0 allows a heap-based buffer over-read in rasteropGeneralLow, related to adaptmap_reg.c and adaptmap.c.

- [https://github.com/AlAIAL90/CVE-2020-36279](https://github.com/AlAIAL90/CVE-2020-36279) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2020-36279.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2020-36279.svg)


## CVE-2020-36278
 Leptonica before 1.80.0 allows a heap-based buffer over-read in findNextBorderPixel in ccbord.c.

- [https://github.com/AlAIAL90/CVE-2020-36278](https://github.com/AlAIAL90/CVE-2020-36278) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2020-36278.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2020-36278.svg)


## CVE-2020-36277
 Leptonica before 1.80.0 allows a denial of service (application crash) via an incorrect left shift in pixConvert2To8 in pixconv.c.

- [https://github.com/AlAIAL90/CVE-2020-36277](https://github.com/AlAIAL90/CVE-2020-36277) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2020-36277.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2020-36277.svg)


## CVE-2020-35846
 Agentejo Cockpit before 0.11.2 allows NoSQL injection via the Controller/Auth.php check function.

- [https://github.com/JohnHammond/CVE-2020-35846](https://github.com/JohnHammond/CVE-2020-35846) :  ![starts](https://img.shields.io/github/stars/JohnHammond/CVE-2020-35846.svg) ![forks](https://img.shields.io/github/forks/JohnHammond/CVE-2020-35846.svg)


## CVE-2020-35545
 Time-based SQL injection exists in Spotweb 1.4.9 via the query string.

- [https://github.com/bousalman/CVE-2020-35545](https://github.com/bousalman/CVE-2020-35545) :  ![starts](https://img.shields.io/github/stars/bousalman/CVE-2020-35545.svg) ![forks](https://img.shields.io/github/forks/bousalman/CVE-2020-35545.svg)


## CVE-2020-14410
 SDL (Simple DirectMedia Layer) through 2.0.12 has a heap-based buffer over-read in Blit_3or4_to_3or4__inversed_rgb in video/SDL_blit_N.c via a crafted .BMP file.

- [https://github.com/AlAIAL90/CVE-2020-14410](https://github.com/AlAIAL90/CVE-2020-14410) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2020-14410.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2020-14410.svg)


## CVE-2020-14409
 SDL (Simple DirectMedia Layer) through 2.0.12 has an Integer Overflow (and resultant SDL_memcpy heap corruption) in SDL_BlitCopy in video/SDL_blit_copy.c via a crafted .BMP file.

- [https://github.com/AlAIAL90/CVE-2020-14409](https://github.com/AlAIAL90/CVE-2020-14409) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2020-14409.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2020-14409.svg)


## CVE-2020-13959
 The default error page for VelocityView in Apache Velocity Tools prior to 3.1 reflects back the vm file that was entered as part of the URL. An attacker can set an XSS payload file as this vm file in the URL which results in this payload being executed. XSS vulnerabilities allow attackers to execute arbitrary JavaScript in the context of the attacked website and the attacked user. This can be abused to steal session cookies, perform requests in the name of the victim or for phishing attacks.

- [https://github.com/AlAIAL90/CVE-2020-13959](https://github.com/AlAIAL90/CVE-2020-13959) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2020-13959.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2020-13959.svg)


## CVE-2020-13936
 An attacker that is able to modify Velocity templates may execute arbitrary Java code or run arbitrary system commands with the same privileges as the account running the Servlet container. This applies to applications that allow untrusted users to upload/modify velocity templates running Apache Velocity Engine versions up to 2.2.

- [https://github.com/AlAIAL90/CVE-2020-13936](https://github.com/AlAIAL90/CVE-2020-13936) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2020-13936.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2020-13936.svg)


## CVE-2019-20933
 InfluxDB before 1.7.6 has an authentication bypass vulnerability in the authenticate function in services/httpd/handler.go because a JWT token may have an empty SharedSecret (aka shared secret).

- [https://github.com/Hydragyrum/CVE-2019-20933](https://github.com/Hydragyrum/CVE-2019-20933) :  ![starts](https://img.shields.io/github/stars/Hydragyrum/CVE-2019-20933.svg) ![forks](https://img.shields.io/github/forks/Hydragyrum/CVE-2019-20933.svg)


## CVE-2019-10181
 It was found that in icedtea-web up to and including 1.7.2 and 1.8.2 executable code could be injected in a JAR file without compromising the signature verification. An attacker could use this flaw to inject code in a trusted JAR. The code would be executed inside the sandbox.

- [https://github.com/AlAIAL90/CVE-2019-10181](https://github.com/AlAIAL90/CVE-2019-10181) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2019-10181.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2019-10181.svg)


## CVE-2017-15361
 The Infineon RSA library 1.02.013 in Infineon Trusted Platform Module (TPM) firmware, such as versions before 0000000000000422 - 4.34, before 000000000000062b - 6.43, and before 0000000000008521 - 133.33, mishandles RSA key generation, which makes it easier for attackers to defeat various cryptographic protection mechanisms via targeted attacks, aka ROCA. Examples of affected technologies include BitLocker with TPM 1.2, YubiKey 4 (before 4.3.5) PGP key generation, and the Cached User Data encryption feature in Chrome OS.

- [https://github.com/Elbarbons/Attacco-ROCA-sulla-vulnerabilita-CVE-2017-15361](https://github.com/Elbarbons/Attacco-ROCA-sulla-vulnerabilita-CVE-2017-15361) :  ![starts](https://img.shields.io/github/stars/Elbarbons/Attacco-ROCA-sulla-vulnerabilita-CVE-2017-15361.svg) ![forks](https://img.shields.io/github/forks/Elbarbons/Attacco-ROCA-sulla-vulnerabilita-CVE-2017-15361.svg)
- [https://github.com/0xxon/roca](https://github.com/0xxon/roca) :  ![starts](https://img.shields.io/github/stars/0xxon/roca.svg) ![forks](https://img.shields.io/github/forks/0xxon/roca.svg)

