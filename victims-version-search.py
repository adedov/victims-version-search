#!/usr/bin/python
import json
import getopt
import logging
import os
import re
import sqlite3
import sys
import yaml

from zipfile import ZipFile
from xml.etree import ElementTree
from distutils.version import LooseVersion

class Config:
    loglevel = "WARN"
    victimsdb = "."
    dirs = []

config = Config()

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
                logging.warn("CVE-%s version match component %s to version %s" % (self.cve, component, v))
                version_match = v
                break

        for v in self.fixedin:
            if v.match(component.version):
                logging.warn("CVE-%ss component %s fixed in %s" % (self.cve, component, v))
                fixed_match = v
                break

        if fixed_match is not None:
            return None

        return version_match

con = sqlite3.Connection("cvemap.db")

def init_temp_db():
    con.execute("DROP TABLE IF EXISTS cve")
    con.execute("""
    CREATE TABLE cve(
        cve VARCHAR,
        cvss FLOAT,
        groupid VARCHAR,
        artifactid VARCHAR,
        version VARCHAR,
        fixedin VARCHAR
    )
    """)

def parse_cve_file(f, con):
    cve = yaml.load(f)
    
    cur = con.cursor()
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
    con.commit()

def parse_victims_db(root):
    for root, dirs, files in os.walk(root):
        for f in files:
            if f.endswith(".yaml"):
                with file(os.path.join(root, f)) as cve_file:
                    parse_cve_file(cve_file, con)

       
def read_maven_info(jarfile):
    jar = ZipFile(jarfile)
    pomlist = [ x for x in jar.namelist() if x.startswith("META-INF/maven") and x.endswith("/pom.xml") ]
    
    if not len(pomlist):
        # Not maven componet
        return None

    if len(pomlist) > 1:
        logging.debug("Multiple pom.xml is not supported")
        return None

    pomname = pomlist[0]
    pomxml = jar.open(pomname)
    ns = lambda s: "{http://maven.apache.org/POM/4.0.0}" + s
    
    class ParseState:
        def __init__(self):
            self.groupid = None
            self.artid = None
            self.version = None

    # Iterative parsing is required. Usual parser may be broken by pom files with multiple colons in tag names, like 
    # <pluginVersion:org.codehaus.mojo:build-helper-maven-plugin>1.8</pluginVersion:org.codehaus.mojo:build-helper-maven-plugin>
    itparse = ElementTree.iterparse(pomxml, events = ("start",))
    _, proj = next(itparse)
    assert(proj.tag == ns("project"))
    root = proj.getchildren()
    state = ParseState()

    def search_artifact(nodes):
        for tag in nodes:
            if tag.tag == ns("groupId"):
                state.groupid = tag.text
            if tag.tag == ns("artifactId"):
                state.artid = tag.text
            if tag.tag == ns("version"):
                state.version = tag.text

    for tag in root:
        if tag.tag == ns("parent"):
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
    manifest = jar.open("META-INF/MANIFEST.MF")

    if not manifest:
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

def read_component_cve(component, con):
    cur = con.cursor()

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

def process_jar(target):
    logging.info("Working with " + target)
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

    logging.debug("Component: " + str(mycomponent))

    for cve in read_component_cve(mycomponent, con):
        logging.warn("Candidate: " + str(cve))
        cve_match = cve.match(mycomponent)
        if cve_match is not None:
            print "CONFIRMED CVE-%s %s %s (%s) version match %s\tFIXED IN %s" % (cve.cve, cve.cvss, os.path.basename(target), mycomponent, cve_match, cve.fixedin) 

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
    usage = lambda: sys.stderr.write("""The victims-cve-db scanner based solely on Jar/Package version.
Usage:
	%(cmd)s --help
	%(cmd)s [--victims-cve-db=<path>] [--loglevel=<lvl>] <file|dir> ...
	
""" % { "cmd" : sys.argv[0] })

    global config
    opts, args = getopt.getopt(sys.argv[1:], "", ["help", "loglevel=", "victims-cve-db="])

    for o, a in opts:
        if o == "--help":
            usage()
            sys.exit(0)
        elif o == "--loglevel":
            config.loglevel = a
        elif o == "--victims-cve-db":
            config.victimsdb = a

    if not args:
        raise Exception("File or directory required")

    config.dirs = args

def configure_logger():
    logging.basicConfig(
        format = "* %(message)s",
        level = getattr(logging, config.loglevel.upper(), None)
    )

#
# Main
#
def main():
    # init
    parse_options()
    configure_logger()
    init_temp_db()
    parse_victims_db(os.path.join(config.victimsdb, "database", "java"))

    # process target files
    process_jar_files()

#try:
main()
#except Exception, e:
#    print "E: " + str(e)
#    sys.exit(1)
