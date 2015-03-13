# Victims CVE Database Version Search
This script allows searching for vulnerabilities associated with specific versions of Java archives (jar files) using database provided by [victims-cve-db](https://github.com/victims/victims-cve-db).

For each jar file the version information is retrieved:

1. Using Maven manifest (pom.xml), if it does exist within jar.
2. Using version included into filename and filename as artifactId.
3. Using version from META-INF/MANIFEST.MF with filename as artifactId.

The utility takes into account affected versions, fixed-in versions with series information, stored in victims DB. According to our brief testing, script gives quite accurate results (when jar files are not patched locally without version changing).

## Requirements
- Python 2.6+
- (PyYAML)[http://pyyaml.org/]
- Local copy of [victims-cve-db](https://github.com/victims/victims-cve-db) database.

## Usage

**Scan Individual File**

```
% ./victims-version-search.py --victims-cve-db=../victims-cve-db --loglevel=error ~/jars/commons-fileupload-1.2.2.jar
CONFIRMED CVE-2013-0248 ??? commons-fileupload-1.2.2.jar (commons-fileupload:commons-fileupload:1.2.2) version match <=1.2.2,1	FIXED IN [>=1.3,1]
CONFIRMED CVE-2013-2186 ??? commons-fileupload-1.2.2.jar (commons-fileupload:commons-fileupload:1.2.2) version match <=1.3,1	FIXED IN [>=1.3.1,1]
CONFIRMED CVE-2014-0050 5.0 commons-fileupload-1.2.2.jar (commons-fileupload:commons-fileupload:1.2.2) version match <=1.3	FIXED IN [>=1.3.1]
```

**Scan Directory**

```
% ./victims-version-search.py --victims-cve-db=../victims-cve-db --loglevel=error ~/java/jboss-eap-6.3
CONFIRMED CVE-2013-5855 5.0 jsf-impl-1.2_15-b01-redhat-11.jar (javax.faces:jsf-impl:1.2_15-b01-redhat-11) version match >=1.2_03,1	FIXED IN []
CONFIRMED CVE-2013-5855 5.0 jsf-impl-2.1.28.redhat-3.jar (com.sun.faces:jsf-impl:2.1.28.redhat-3) version match <=2.2.5,2	FIXED IN [>=2.2.6]
...
```

**Loglevel**

The --loglevel allows you to add verbosity into the process, e.g. to understand what CVE was considered and why tool decided to include or not include them into report:

- loglevel=error will lead to showing only confirmed CVE-s.
- loglevel=warn (default) will show CVE candidates and decision factors.
- loglevel=info and loglevel=debug will add more verbosity about process.
