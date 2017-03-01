#!/usr/bin/env python
# Modified svnperms.py to retrieve users and groups from LDAP.
# Request/specification by Andreas Hasenack for the Mandriva Linux
# repository. Changes in the code by Bogdano Arendartchuk.

# $HeadURL: http://svn.collab.net/repos/svn/branches/1.4.x/tools/hook-scripts/svnperms.py $
# $LastChangedDate: 2005-09-23 18:19:04 +0000 (Fri, 23 Sep 2005) $
# $LastChangedBy: niemeyer $
# $LastChangedRevision: 16232 $

import commands
import sys, os
import getopt
import re
import string

__author__ = "Gustavo Niemeyer <gustavo@niemeyer.net>"

class Error(Exception): pass

class ConfigError(Error): pass

class LDAPError(ConfigError):
    def __init__(self, ldaperr):
        self.ldaperr = ldaperr
        name = ldaperr.__class__.__name__
        desc = ldaperr.message["desc"]
        self.message = "LDAP error %s: %s" % (name, desc)
        self.args = self.message,

SECTION = re.compile(r'\[([^]]+?)(?:\s+extends\s+([^]]+))?\]')
OPTION = re.compile(r'(\S+)\s*=\s*(.*)$')

perms_sources = {}

class Config:
    def __init__(self, filename):
        # Options are stored in __sections_list like this:
        # [(sectname, [(optname, optval), ...]), ...]
        self._sections_list = []
        self._sections_dict = {}
        self._read(filename)

    def _read(self, filename):
        # Use the same logic as in ConfigParser.__read()
        file = open(filename)
        cursectdict = None
        optname = None
        lineno = 0
        for line in file.xreadlines():
            lineno = lineno + 1
            if line.isspace() or line[0] == '#':
                continue
            if line[0].isspace() and cursectdict is not None and optname:
                value = line.strip()
                cursectdict[optname] = "%s %s" % (cursectdict[optname], value)
                cursectlist[-1][1] = "%s %s" % (cursectlist[-1][1], value)
            else:
                m = SECTION.match(line)
                if m:
                    sectname = m.group(1)
                    parentsectname = m.group(2)
                    if parentsectname is None:
                        # No parent section defined, so start a new section
                        cursectdict = self._sections_dict.setdefault \
                            (sectname, {})
                        cursectlist = []
                    else:
                        # Copy the parent section into the new section
                        parentsectdict = self._sections_dict.get \
                            (parentsectname, {})
                        cursectdict = self._sections_dict.setdefault \
                            (sectname, parentsectdict.copy())
                        cursectlist = self.walk(parentsectname)
                    self._sections_list.append((sectname, cursectlist))
                    optname = None
                elif cursectdict is None:
                    raise Error, "%s:%d: no section header" % \
                                 (filename, lineno)
                else:
                    m = OPTION.match(line)
                    if m:
                        optname, optval = m.groups()
                        optval = optval.strip()
                        cursectdict[optname] = optval
                        cursectlist.append([optname, optval])
                    else:
                        raise Error, "%s:%d: parsing error" % \
                                     (filename, lineno)

    def sections(self):
        return self._sections_dict.keys()

    def options(self, section):
        return self._sections_dict.get(section, {}).keys()

    def get(self, section, option, default=None):
        optsdic = self._sections_dict.get(section, default)
        if optsdic is default:
            return optsdic
        return optsdic.get(option, default)

    def walk(self, section, option=None):
        ret = []
        for sectname, options in self._sections_list:
            if sectname == section:
                for optname, value in options:
                    if not option or optname == option:
                        ret.append((optname, value))
        return ret


class Permission:
    def __init__(self, config):
        self.config = config
        self._group = {}
        self._permlist = []

    def parse_groups(self, groupsiter):
        for option, value in groupsiter:
            self._group[option] = value.split()

    def parse_perms(self, permsiter):
        for option, value in permsiter:
            # Paths never start with /, so remove it if provided
            if option[0] == "/":
                option = option[1:]
            pattern = re.compile("^%s$" % option)
            for entry in value.split():
                openpar, closepar = entry.find("("), entry.find(")")
                groupsusers = entry[:openpar].split(",")
                perms = entry[openpar+1:closepar].split(",")
                users = []
                groups = []
                for groupuser in groupsusers:
                    if groupuser[0] == "@":
                        groupname = groupuser[1:]
                        try:
                            users.extend(self._group[groupname])
                        except KeyError:
                            #raise Error, "group '%s' not found" % \
                            #             groupuser[1:]
                            pass # unknown groups may be present in grp
                            #XXX groups not found will be ignored
                        groups.append(groupname)
                    else:
                        users.append(groupuser)
                self._permlist.append((pattern, users, perms, groups))

    def get(self, user, path):
        ret = []
        for pattern, users, perms, groups in self._permlist:
            if pattern.match(path) and (user in users or "*" in users or
                    self._matchgroup(user, groups)):
                ret = perms
        return ret

    def _matchgroup(self, user, groups):
        "Checks if the given user is member of one of the given groups"
        return False

perms_sources["default"] = Permission


class GRPPermission(Permission):
    def __init__(self, *args, **kwargs):
        Permission.__init__(self, *args, **kwargs)
        import grp
        self._mod_grp = grp
        self._grpgroups = {}
        self._usergroups = {}

    def _matchgroup(self, user, groups):
        matches = False
        usergroups = self._usergroups.get(user)
        if usergroups:
            #FIXME too expensive:
            matches = bool(usergroups.intersection(groups)) 
        if matches is False:
            for group in groups:
                try:
                    grset = self._grpgroups[group]
                except KeyError:
                    try:
                        grent = self._mod_grp.getgrnam(group)
                    except KeyError, e:
                        raise ConfigError, str(e)
                    grset = self._grpgroups[group] = set(grent.gr_mem)
                if user in grset:
                    self._usergroups.setdefault(user, set()).add(group)
                    matches = True
                    break
        return matches

perms_sources["grp"] = GRPPermission


class LDAPPermission(Permission):
    def __init__(self, *args, **kwargs):
        Permission.__init__(self, *args, **kwargs)
        try:
            import ldap
            import ldap.filter
        except ImportError:
            raise ConfigError, "the module 'ldap' is needed"
        self._mod_ldap = ldap
        self._usergroups = {}
        self._get_options(self.config)

    def _get_options(self, config):
        # XXX seems "ldap" is not a good group name
        confgroup = "ldap"
        self.uri = config.get(confgroup, "uri")
        if not self.uri:
            host = config.get(confgroup, "host")
            if host is None:
                raise ConfigError, "LDAP host name is required when no "\
                        "URI is provided"
            try:
                port = int(config.get(confgroup, "port", 389))
            except ValueError:
                raise ConfigError, "LDAP port number should be an integer"
            self.uri = "ldap://%s:%s/" % (host, port)
        self.starttls = False
        raw = config.get(confgroup, "use-starttls")
        if raw:
            accepts = {"yes": True, "no": False}
            try:
                self.starttls = accepts[raw]
            except KeyError, e:
                raise ConfigError, "invalid use-starttls value %s, use "\
                        "'yes' or 'no'" % e
        self.binddn = config.get(confgroup, "binddn")
        self.bindpw = config.get(confgroup, "bindpw", "")
        self.basedn = config.get(confgroup, "basedn")
        if self.basedn is None:
            raise ConfigError, "LDAP basedn is required"
        rawfilter = config.get(confgroup, "groups-filter-format")
        if rawfilter is None:
            raise ConfigError, "groups-filter-format is required"
        self.filterfmt = string.Template(rawfilter)
        # usually something like
        # (&(objectClass=groupOfNames)(member=$username,ou=People,dc=example,dc=com))
        self.groupattr = config.get(confgroup, "groups-name-attribute", "cn")
        scopes = {
            "one": self._mod_ldap.SCOPE_ONELEVEL, 
            "sub": self._mod_ldap.SCOPE_SUBTREE, 
            "base": self._mod_ldap.SCOPE_BASE
        }
        scopename = config.get(confgroup, "scope", "one")
        try:
            self.scope = scopes[scopename]
        except KeyError:
            raise ConfigError, "invalid search scope %r, must be one of "\
                    "%s." % (scopename, ", ".join(scopes))

    def _searchgroups(self, user):
        try:
            l = self._mod_ldap.initialize(self.uri)
            if self.starttls:
                l.start_tls_s()
            if self.binddn:
                l.bind_s(self.binddn, self.bindpw)
            try:
                user = self._mod_ldap.filter.escape_filter_chars(user)
                try:
                    filter = self.filterfmt.substitute({"user": user})
                except KeyError, e:
                    raise ConfigError, "filter variable not found: %s" % e
                found = l.search_s(self.basedn, self.scope, filter,
                        [self.groupattr])
            finally:
                l.unbind_s()
        except self._mod_ldap.LDAPError, e:
            raise LDAPError(e)
        if found:
            try:
                usergroups = frozenset(e[self.groupattr][0] for dn, e in found)
            except KeyError, e:
                raise ConfigError, "group name attribute %s not in "\
                        "LDAP result" % e
            return usergroups
        return frozenset()

    def _matchgroup(self, user, groups):
        try:
            usergroups = self._usergroups[user] 
        except KeyError:
            usergroups = self._usergroups[user] = self._searchgroups(user)
        return bool(usergroups.intersection(groups))

perms_sources["ldap"] = LDAPPermission

class SVNLook:
    def __init__(self, repospath, txn=None, rev=None):
        self.repospath = repospath
        self.txn = txn
        self.rev = rev

    def _execcmd(self, *cmd, **kwargs):
        cmdstr = " ".join(cmd)
        status, output = commands.getstatusoutput(cmdstr)
        if status != 0:
            sys.stderr.write(cmdstr)
            sys.stderr.write("\n")
            sys.stderr.write(output)
            raise Error, "command failed: %s\n%s" % (cmdstr, output)
        return status, output

    def _execsvnlook(self, cmd, *args, **kwargs):
        execcmd_args = ["svnlook", cmd, self.repospath]
        self._add_txnrev(execcmd_args, kwargs)
        execcmd_args += args
        execcmd_kwargs = {}
        keywords = ["show", "noerror"]
        for key in keywords:
            if kwargs.has_key(key):
                execcmd_kwargs[key] = kwargs[key]
        return self._execcmd(*execcmd_args, **execcmd_kwargs)

    def _add_txnrev(self, cmd_args, received_kwargs):
        if received_kwargs.has_key("txn"):
            txn = received_kwargs.get("txn")
            if txn is not None:
                cmd_args += ["-t", txn]
        elif self.txn is not None:
            cmd_args += ["-t", self.txn]
        if received_kwargs.has_key("rev"):
            rev = received_kwargs.get("rev")
            if rev is not None:
                cmd_args += ["-r", rev]
        elif self.rev is not None:
            cmd_args += ["-r", self.rev]

    def changed(self, **kwargs):
        status, output = self._execsvnlook("changed", **kwargs)
        if status != 0:
            return None
        changes = []
        for line in output.splitlines():
            line = line.rstrip()
            if not line: continue
            entry = [None, None, None]
            changedata, changeprop, path = None, None, None
            if line[0] != "_":
                changedata = line[0]
            if line[1] != " ":
                changeprop = line[1]
            path = line[4:]
            changes.append((changedata, changeprop, path))
        return changes

    def author(self, **kwargs):
        status, output = self._execsvnlook("author", **kwargs)
        if status != 0:
            return None
        return output.strip()


def check_perms(filename, section, repos, txn=None, rev=None, author=None):
    svnlook = SVNLook(repos, txn=txn, rev=rev)
    if author is None:
        author = svnlook.author()
    changes = svnlook.changed()
    try:
        config = Config(filename)
    except IOError:
        raise ConfigError, "can't read config file "+filename
    if not section in config.sections():
        raise ConfigError, "section '%s' not found in config file" % section
    source_name = config.get("global", "permissions-source", "default")
    try:
        source_klass = perms_sources[source_name]
    except KeyError:
        raise ConfigError, "invalid permissions source %r" % source_name
    perm = source_klass(config)
    perm.parse_groups(config.walk("groups"))
    perm.parse_groups(config.walk(section+" groups"))
    perm.parse_perms(config.walk(section))
    permerrors = []
    for changedata, changeprop, path in changes:
        pathperms = perm.get(author, path)
        if changedata == "A" and "add" not in pathperms:
            permerrors.append("you can't add "+path)
        elif changedata == "U" and "update" not in pathperms:
            permerrors.append("you can't update "+path)
        elif changedata == "D" and "remove" not in pathperms:
            permerrors.append("you can't remove "+path)
        elif changeprop == "U" and "update" not in pathperms:
            permerrors.append("you can't update properties of "+path)
        #else:
        #    print "cdata=%s cprop=%s path=%s perms=%s" % \
        #          (str(changedata), str(changeprop), path, str(pathperms))
    if permerrors:
        permerrors.insert(0, "you don't have enough permissions for "
                             "this transaction:")
        raise Error, "\n".join(permerrors)


# Command:

USAGE = """\
Usage: svnperms.py OPTIONS

Options:
    -r PATH    Use repository at PATH to check transactions
    -t TXN     Query transaction TXN for commit information
    -f PATH    Use PATH as configuration file (default is repository
               path + /conf/svnperms.conf)
    -s NAME    Use section NAME as permission section (default is
               repository name, extracted from repository path)
    -R REV     Query revision REV for commit information (for tests)
    -A AUTHOR  Check commit as if AUTHOR had commited it (for tests)
    -h         Show this message
"""

class MissingArgumentsException(Exception):
    "Thrown when required arguments are missing."
    pass

def parse_options():
    try:
        opts, args = getopt.getopt(sys.argv[1:], "f:s:r:t:R:A:h", ["help"])
    except getopt.GetoptError, e:
        raise Error, e.msg
    class Options: pass
    obj = Options()
    obj.filename = None
    obj.section = None
    obj.repository = None
    obj.transaction = None
    obj.revision = None
    obj.author = None
    for opt, val in opts:
        if opt == "-f":
            obj.filename = val
        elif opt == "-s":
            obj.section = val
        elif opt == "-r":
            obj.repository = val
        elif opt == "-t":
            obj.transaction = val
        elif opt == "-R":
            obj.revision = val
        elif opt == "-A":
            obj.author = val
        elif opt in ["-h", "--help"]:
            sys.stdout.write(USAGE)
            sys.exit(0)
    missingopts = []
    if not obj.repository:
        missingopts.append("repository")
    if not (obj.transaction or obj.revision):
        missingopts.append("either transaction or a revision")
    if missingopts:
        raise MissingArgumentsException, \
              "missing required option(s): " + ", ".join(missingopts)
    obj.repository = os.path.abspath(obj.repository)
    if obj.filename is None:
        obj.filename = os.path.join(obj.repository, "conf", "svnperms.conf")
    if obj.section is None:
        obj.section = os.path.basename(obj.repository)
    if not (os.path.isdir(obj.repository) and
            os.path.isdir(os.path.join(obj.repository, "db")) and
            os.path.isdir(os.path.join(obj.repository, "hooks")) and
            os.path.isfile(os.path.join(obj.repository, "format"))):
        raise Error, "path '%s' doesn't look like a repository" % \
                     obj.repository

    return obj

def main():
    try:
        opts = parse_options()
        check_perms(opts.filename, opts.section,
                    opts.repository, opts.transaction, opts.revision,
                    opts.author)
    except MissingArgumentsException, e:
        sys.stderr.write("%s\n" % str(e))
        sys.stderr.write(USAGE)
        sys.exit(1)
    except ConfigError, e:
        sys.stderr.write("svnperms configuration error: %s\n" % str(e))
        sys.exit(2)
    except Error, e:
        sys.stderr.write("error: %s\n" % str(e))
        sys.exit(1)

if __name__ == "__main__":
    main()

# vim:et:ts=4:sw=4
