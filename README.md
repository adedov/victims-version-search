# Victims CVE Database Version Search
This script allows searching for vulnerabilities associated with specific versions of Java archives (jar files) using database provided by [victims-cve-db](https://github.com/victims/victims-cve-db).

For each jar file the version information is retrieved:

1. Using Maven manifest (pom.xml), if it does exist within jar.
2. Using version included into filename and filename as artifactId.
3. Using version from META-INF/MANIFEST.MF with filename as artifactId.

The utility takes into account affected versions, fixed-in versions with series information, stored in victims DB. According to our brief testing, script gives quite accurate results (when jar files are not patched locally without version changing).

## Requirements
- Python 2.6+
- [PyYAML](http://pyyaml.org/)
- SQLite3 support in Python
- Local copy of [victims-cve-db](https://github.com/victims/victims-cve-db) database.

## Usage

**Scan Individual File**

```
% ./victims-version-search.py --victims-cve-db=../victims-cve-db ~/jars/commons-fileupload-1.2.2.jar
CONFIRMED CVE-2013-0248 ??? commons-fileupload-1.2.2.jar (commons-fileupload:commons-fileupload:1.2.2) version match <=1.2.2,1	FIXED IN [>=1.3,1]
CONFIRMED CVE-2013-2186 ??? commons-fileupload-1.2.2.jar (commons-fileupload:commons-fileupload:1.2.2) version match <=1.3,1	FIXED IN [>=1.3.1,1]
CONFIRMED CVE-2014-0050 5.0 commons-fileupload-1.2.2.jar (commons-fileupload:commons-fileupload:1.2.2) version match <=1.3	FIXED IN [>=1.3.1]
```

**Scan Directory**

```
% ./victims-version-search.py --victims-cve-db=../victims-cve-db ~/java/jboss-eap-6.3
CONFIRMED CVE-2013-5855 5.0 jsf-impl-1.2_15-b01-redhat-11.jar (javax.faces:jsf-impl:1.2_15-b01-redhat-11) version match >=1.2_03,1	FIXED IN []
CONFIRMED CVE-2013-5855 5.0 jsf-impl-2.1.28.redhat-3.jar (com.sun.faces:jsf-impl:2.1.28.redhat-3) version match <=2.2.5,2	FIXED IN [>=2.2.6]
...
```

**Loglevel**

The --loglevel allows you to add verbosity into the process, e.g. to understand what CVE was considered and why tool decided to include or not include them into report:

- loglevel=warn (default) will lead to showing only confirmed CVE-s.
- loglevel=info will show CVE candidates per jar file and decision factors.
- loglevel=debug will add more verbosity about process.

**Searchable CVE Database**

The script produces SQLite3 database for all CVE-s from victims-cve-db as an intermediate product. But it might be useful for someone as it allows easily search by both CVE number and artifact name:

```
% sqlite3 cvemap.db
sqlite> select * from cve limit 10;
cve         cvss        groupid            artifactid    version                            fixedin
----------  ----------  -----------------  ------------  ---------------------------------  -------------------------------
2008-6504               org.apache.struts  struts2-core  ["<=2.0.11.2,2.0", "<=2.1.2,2.1"]  [">=2.0.12,2.0", ">=2.1.3,2.1"]
2008-6504               org.apache.jackra  oak-core      [">=0.5,0"]                        [">=2.1.3,2.1"]
2008-6504               opensymphony       xwork         ["<=1.0.3,1.0"]                    [">=1.0.3.1,1.0.3"]
2008-6504               com.opensymphony   xwork         ["<=2.0.5,2.0", "<=2.1.1,2.1"]     [">=2.0.6,2.0", ">=2.1.2,2.1"]
2009-0217               org.apache.santua  xmlsec        ["<=1.4.2,1.4"]                    [">=1.4.3"]
2009-1190   5.0         org.springframewo  spring-core   ["<=1.2.9,1", "<=2.5.6,2", "<=3.0  [">=2.5.6.SEC01,2", ">=3.0.1.RE
2009-2625               xerces             xercesImpl    ["<=2.9.1", "<=2.9.1-jbossas-1,2.  [">=2.10.0", ">=2.9.1-jbossas-2
2009-4269   2.1         org.apache.derby   derby         ["<=10.5.3.0_1,10.5"]              [">=10.6.1.0"]
2010-1330   5.0         jline              jline         ["==0.9.93"]                       ""
2010-1330   5.0         org.jruby.joni     joni          ["==1.0.2"]                        ""
```

## Restrictions

- Multiple pom.xml files under META-INF/maven are not taken into account currently (TODO?).
- Currently unaffected section from victims-cve-db is not used (though it is not used in database too).
