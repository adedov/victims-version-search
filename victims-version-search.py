#!/usr/bin/python
# vim: set ts=4 sts=4 sw=4 et:
import hashlib
import json
import getopt
import logging
import os
import re
import sqlite3
import sys

from io import BytesIO
from zipfile import ZipFile
from xml.etree import ElementTree
from distutils.version import LooseVersion

class Config:
    loglevel = "WARN"
    victimsdb = "."
    dirs = []
    artifacts = []
    cvemapdb = ":memory:"
    initdb = True
    con = None
    ignore_errors = False
    show_full_path = False
    report_json = False
    verbose = False

class Report:
    def __init__(self):
        self.issues = []
        self.total = 0
        self.scanned = 0

    def add_cve(self, path, cve, component, cve_match):
        class ComponentCVE:
            pass

        issue = ComponentCVE()
        self.issues.append(issue)

        issue.path = path
        issue.cve = cve
        issue.component = component
        issue.cve_match = cve_match

        if path == repr(component):
            issue.sha1 = "unknown"
        else:
            with file(path, "rb") as f:
                h = hashlib.sha1()
                while True:
                    b = f.read(2**10)
                    if not b: break
                    h.update(b)
                issue.sha1 = h.hexdigest()[:7]

    def show(self):
        for issue in self.issues:
            cve = issue.cve
            target = issue.path if config.show_full_path else os.path.basename(issue.path)
            component = issue.component
            cve_match = issue.cve_match
            print "CVE-%s %s (%s) sha1:%s %s" % (cve.cve, cve.cvss, component, issue.sha1, target)

        if config.verbose:
            print "%d of %d jar files was scanned." % (self.scanned, self.total)
            if self.total != self.scanned:
                print "%d jar files do not contain any reliable version information." % (self.total - self.scanned,)

    def to_json(self):
        rep_issues = []
        for issue in self.issues:
            rep_issues.append({
                "file" :    issue.path,
                "sha1" :    issue.sha1,
                "component" : repr(issue.component),
                "cve" :     issue.cve.cve,
                "cvss" :    issue.cve.cvss
            })

        report = {
            "stats" : {
                "total_jars" : self.total,
                "scanned_jars" : self.scanned
            },

            "issues" : rep_issues
        }

        return json.dumps(report, indent=4, sort_keys=True)

config = Config()
report = Report()

class Component:
    def __init__(self, groupid, artid, version):
        self.groupid = groupid
        self.artifactid = artid
        self.version = LooseVersion(version)
        self.__version = version

    def __repr__(self):
        return "%s:%s:%s" % (self.groupid, self.artifactid, self.__version)

class VersionMatch:
    VERSION_RE = re.compile("^(?P<condition>[><=]=)(?P<version>[^, ]+)(?:,(?P<series>[^, ]+)){0,1}$")

    COND_MAP = {
        "<"  : lambda x, y: x < y,
        "<=" : lambda x, y: x <= y,
        "==" : lambda x, y: x == y,
        "="  : lambda x, y: x == y,
        ">"  : lambda x, y: x > y,
        ">=" : lambda x, y: x >= y
    }

    def __init__(self, version):
        v = VersionMatch.VERSION_RE.match(version)
        if not v:
            raise Exception("Incorrect version '%s'" % version)

        self.condition = v.group("condition")
        self.version = LooseVersion(v.group("version"))
        self.series = v.group("series")
        self.__repr = version

    def match(self, cver):
        if self.series is not None:
            if not str(cver).startswith(self.series):
                return None

        return VersionMatch.COND_MAP[self.condition](cver, self.version)

    def __repr__(self):
        return self.__repr

class CVE:
    def __init__(self, cve, cvss, component, versions, fixedin):
        self.cve = cve
        self.cvss = cvss
        if cvss is None:
            self.cvss = "???"
        self.component = component
        self.versions = [ VersionMatch(v) for v in versions ]
        self.fixedin = [ VersionMatch(v) for v in fixedin ]

    def __repr__(self):
        return "CVE-%s %s component %s FOUND IN %s FIXED IN %s" % (self.cve, self.cvss, self.component, self.versions, self.fixedin)

    def match(self, component):
        # TODO match notaffected
        version_match = None
        fixed_match = None

        for v in self.versions:
            if v.match(component.version):
                logging.info("CVE-%s version match component %s to version %s" % (self.cve, component, v))
                version_match = v
                break

        for v in self.fixedin:
            if v.match(component.version):
                logging.info("CVE-%s component %s fixed in %s" % (self.cve, component, v))
                fixed_match = v
                break

        if fixed_match is not None:
            return None

        return version_match

def configure_db():
    config.con = sqlite3.connect(config.cvemapdb)

def init_temp_db():
    config.con.execute("DROP TABLE IF EXISTS cve")
    config.con.execute("""
    CREATE TABLE cve(
        cve VARCHAR,
        cvss FLOAT,
        groupid VARCHAR,
        artifactid VARCHAR,
        version VARCHAR,
        fixedin VARCHAR
    )
    """)

def parse_cve_file(f):
    import yaml
    cve = yaml.load(f)

    cur = config.con.cursor()
    for comp in cve['affected']:
        cveid = cve['cve']
        cvss = cve.get('cvss_v2', None)
        groupid = comp['groupId']
        artid = comp['artifactId']
        versions = comp['version']
        fixedin = comp.get('fixedin', "")

        cur.execute("INSERT INTO cve (cve, cvss, groupid, artifactid, version, fixedin) VALUES (?, ?, ?, ?, ?, ?)",
            (cveid, cvss, groupid, artid, json.dumps(versions), json.dumps(fixedin)))

    # TODO parse notaffected
    config.con.commit()

def parse_victims_db(root):
    for root, dirs, files in os.walk(root):
        for f in files:
            if f.endswith(".yaml"):
                with file(os.path.join(root, f)) as cve_file:
                    parse_cve_file(cve_file)

def read_maven_info(jarfile):
    class ParseState:
        def __init__(self):
            self.groupid = None
            self.artid = None
            self.version = None

    def cleanse_unicode(inp):
        # delete all Unicode regardless of good or broken
        t = "".join([ chr(x) for x in xrange(128) ]) + "?"*128
        return BytesIO(inp.read().translate(t))

    def tag_comp(tag, name):
        ns = lambda s: "{http://maven.apache.org/POM/4.0.0}" + s
        return tag.tag == ns(name) or tag.tag == name

    jar = ZipFile(jarfile)
    pomlist = [ x for x in jar.namelist() if x.startswith("META-INF/maven") and x.endswith("/pom.xml") ]

    if not len(pomlist):
        # Not maven componet
        return None

    if len(pomlist) > 1:
        logging.debug("Multiple pom.xml is not supported")
        return None

    pomname = pomlist[0]
    pomxml = cleanse_unicode(jar.open(pomname))

    # Iterative parsing is required. Usual parser may be broken by pom files with multiple colons in tag names, like 
    # <pluginVersion:org.codehaus.mojo:build-helper-maven-plugin>1.8</pluginVersion:org.codehaus.mojo:build-helper-maven-plugin>
    itparse = ElementTree.iterparse(pomxml, events = ("start",))
    proj = None

    for _, tag in itparse:
        if tag_comp(tag, "project"):
            proj = tag
            break

    if proj is None:
        logging.debug("pom.xml without <project> tag, ignore")
        return None

    root = proj.getchildren()
    state = ParseState()

    def search_artifact(nodes):
        for tag in nodes:
            if tag_comp(tag, "groupId"):
                state.groupid = tag.text
            if tag_comp(tag, "artifactId"):
                state.artid = tag.text
            if tag_comp(tag, "version"):
                state.version = tag.text

    for tag in root:
        if tag_comp(tag, "parent"):
            search_artifact(tag.getchildren())

    search_artifact(root)

    return Component(state.groupid, state.artid, state.version)

def read_filename_info(jarfile):
    namever = os.path.basename(jarfile)
    m = re.match("(.*)-(([0123456789]*\.)*)jar", namever)

    if m is None:
        return None

    name = m.group(1)
    version = m.group(2).rstrip(".")
    return Component(None, name, version)

def read_manifest_info(jarfile):
    jar = ZipFile(jarfile)
    try:
        manifest = jar.open("META-INF/MANIFEST.MF")
    except:
        return None

    version = None
    for ln in manifest.readlines():
        if ln.startswith("Implementation-Version:"):
            version = ln[ln.index(":"):].strip("\r\n\t: ")
            break

    if version is None:
        return None

    name = os.path.splitext(os.path.basename(jarfile))[0]
    return Component(None, name, version)

def read_component_cve(component):
    cur = config.con.cursor()

    if component.groupid is not None:
        q = "SELECT cve, cvss, version, fixedin FROM cve WHERE groupid = ? AND artifactid = ?"
        rs = cur.execute(q, (component.groupid, component.artifactid))
    else:
        # hack for non-maven components
        q = "SELECT cve, cvss, version, fixedin FROM cve WHERE artifactid = ?"
        rs = cur.execute(q, (component.artifactid,))

    rv = []

    component_name = "%s:%s" % (component.groupid, component.artifactid)
    for x in rs.fetchall():
        rv.append(CVE(x[0], x[1], component_name, json.loads(x[2]), json.loads(x[3])))

    return rv

def process_component(component, target):
    logging.debug("Component: " + str(component))

    for cve in read_component_cve(component):
        logging.info("Candidate: " + str(cve))
        cve_match = cve.match(component)
        if cve_match is not None:
            report.add_cve(target, cve, component, cve_match)

def process_jar(target):
    logging.debug("Working with " + target)
    report.total += 1

    try:
        mycomponent = read_maven_info(target)

        if mycomponent is None:
            logging.debug("Not maven component, try parse filename")
            mycomponent = read_filename_info(target)

        if mycomponent is None:
            logging.debug("Filename does not contain version")
            mycomponent = read_manifest_info(target)

        if mycomponent is None:
            logging.debug("Fail to retrive jar version info, ignore")
            return

            target = os.path.basename(target)
        process_component(mycomponent, target)
        report.scanned += 1

    except Exception, e:
        if config.ignore_errors:
            logging.warn("Error during processing %s: %s" % (target, str(e)))
            return
        else:
            raise e


def process_artifacts():
    for art in config.artifacts:
        groupid, artid, ver = art.split(":")
        process_component(Component(groupid, artid, ver), art)

def process_jar_files():
    def traverse(_, d, files):
        for f in files:
            if f.endswith(".jar"):
                process_jar(os.path.join(d, f))

    for p in config.dirs:
        if os.path.isfile(p):
            process_jar(p)
            continue

        os.path.walk(p, traverse, None)

def parse_options():
    usage = """The victims-cve-db scanner based solely on Jar/Package version.
Usage:
	%(cmd)s --help
	%(cmd)s [options] <file|dir|artifact> ...

Where:
    artifact : groupId:artifactId:version

Options:
    --victims-cve-db=path   Path to clone of victims-cve-db repo (default is current dir).

    --dump-db=file.db       Dump victims-cve-db into SQLite representation.

    --load-db=file.db       Load victims-cve-db from SQLite rather than from repo.

    --ignore-errors         Ignore errors during parsing individual jar files.

    --loglevel              Verbosity level: debug | info | warn

    --full-path             Show jar file's full path in report.

    --json                  Print report in form of JSON.

    --verbose               Prints additional information along the way.

""" % { "cmd" : os.path.basename(sys.argv[0]) }

    def msg_usage_exit(msg = None, code = 0):
        if msg:
            sys.stderr.write(msg + "\n\n")

        sys.stderr.write(usage)
        sys.exit(code)

    try:
        supported = ["help", "loglevel=", "victims-cve-db=", "load-db=", "dump-db=", "full-path", "json", "ignore-errors", "verbose"]
        opts, args = getopt.getopt(sys.argv[1:], "", supported)
    except getopt.GetoptError, e:
        msg_usage_exit("E: " + str(e), 1)

    global config
    nothing_todo = True

    for o, a in opts:
        if o == "--help":
            msg_usage_exit()
        elif o == "--loglevel":
            config.loglevel = a
        elif o == "--victims-cve-db":
            config.victimsdb = a
        elif o == "--load-db":
            config.initdb = False
            config.cvemapdb = a
        elif o == "--dump-db":
            nothing_todo = False
            config.cvemapdb = a
        elif o == "--full-path":
            config.show_full_path = True
        elif o == "--json":
            config.report_json = True
        elif o == "--ignore-errors":
            config.ignore_errors = True
        elif o == "--verbose":
            config.verbose = True

    if not args and nothing_todo:
        msg_usage_exit("E: File or directory required.", 1)

    for x in args:
        if x.count(":") == 2:
            config.artifacts.append(x)
        else:
            config.dirs.append(x)

def configure_logger():
    logging.basicConfig(
        format = "* %(message)s",
        level = getattr(logging, config.loglevel.upper(), None)
    )

#
# Main
#
if __name__ == "__main__":
    parse_options()
    configure_logger()
    configure_db()

    if config.initdb:
        init_temp_db()
        parse_victims_db(os.path.join(config.victimsdb, "database", "java"))

    process_artifacts()
    process_jar_files()

    if config.report_json:
        print report.to_json()
    else:
        report.show()
