# Update 2021-11-22
## CVE-2021-36749
 In the Druid ingestion system, the InputSource is used for reading data from a certain data source. However, the HTTP InputSource allows authenticated users to read data from other sources than intended, such as the local file system, with the privileges of the Druid server process. This is not an elevation of privilege when users access Druid directly, since Druid also provides the Local InputSource, which allows the same level of access. But it is problematic when users interact with Druid indirectly through an application that allows users to specify the HTTP InputSource, but not the Local InputSource. In this case, users could bypass the application-level restriction by passing a file URL to the HTTP InputSource. This issue was previously mentioned as being fixed in 0.21.0 as per CVE-2021-26920 but was not fixed in 0.21.0 or 0.21.1.

- [https://github.com/zwlsix/apache_druid_CVE-2021-36749](https://github.com/zwlsix/apache_druid_CVE-2021-36749) :  ![starts](https://img.shields.io/github/stars/zwlsix/apache_druid_CVE-2021-36749.svg) ![forks](https://img.shields.io/github/forks/zwlsix/apache_druid_CVE-2021-36749.svg)

