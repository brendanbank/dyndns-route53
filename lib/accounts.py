
import glob
import importlib
import sys
import os
import uuid
import ipaddress
import re
import dns.resolver

from .log import log
from os import environ


class BaseAccount:
    _priority = 255


    def __init__(self, account: dict):
        self._account = account
        self._account['id'] = account.get('id', str(uuid.uuid4()))
        self._account['description'] = account.get('description', '')
        self._state = {}
        self._zones = {}
        self._resolver = dns.resolver.get_default_resolver()

        log.debug("created resolver")

        # Accept domains from account dict (DB-backed), fall back to env var
        domains = account.get('domains', [])
        if domains:
            for zone in domains:
                self._zones[zone] = zone
        elif environ.get('DOMAINS'):
            for zone in environ.get('DOMAINS').split(','):
                self._zones[zone] = zone

    @staticmethod
    def known_services():
        return []

    @property
    def id(self):
        """ account unique id
        """
        return self._account['id']

    @property
    def settings(self):
        return self._account

    @staticmethod
    def match(account):
        """ Does this account fit for the provided specification
        """
        return False

    @property
    def description(self):
        return ("%(id)s [%(service)s - %(description)s] " % self._account)

    @property
    def is_verbose(self):
        return self._account.get('verbose') is True

    def gethostedzones(self):
        return(self._zones.keys())

    @staticmethod
    def getip (ip):
        try:
            ip_object = ipaddress.ip_address(ip)
            log.debug(f'IP address {ip} is a valid ip address')
            return(ip_object)
        except Exception as e:
            log.critical(f'IP address {ip} is not a valid ip address: {e}')
            return (False)

    @staticmethod
    def getiptype (ip):
        try:
            ip_object = ipaddress.ip_address(ip)
            log.debug(f'IP address {ip} is a valid ip address')
        except Exception as e:
            log.critical(f'IP address {ip} is not a valid ip address: {e}')
            return (False)

        log.debug(f'ip_object = {type(ip_object)}')
        if isinstance(ip_object, ipaddress.IPv4Address):
            return ("A")
        elif isinstance(ip_object, ipaddress.IPv6Address):
            return ("AAAA")
        else:
            return(False)

    @staticmethod
    def isvalidhostname(hostnames):

        hostnamesObj = hostnames.split(",")
        if "" in hostnamesObj:
            return(False)

        log.debug(f'hostnames = {hostnamesObj}')
        for hostname in hostnamesObj:
            if len(hostname) > 255:
                return False
            if hostname[-1] == ".":
                hostname = hostname[:-1]  # strip exactly one dot from the right, if present
            allowed = re.compile(r"(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)

            if all(allowed.match(x) for x in hostname.split(".")):
                continue
            else:
                return(False)

        log.debug(f'hostnamesObj = {hostnamesObj}')
        return (hostnamesObj)

    def domaininhostname(self, hostname):

        for domain in self._zones:
            pos_domain = hostname.lower().rfind(domain.lower())
            if pos_domain >= 0 and (pos_domain + len(domain) == len(hostname)):
                return (domain)
            else:
                continue

        return(False)

    def hostnameperzone(self, hostnamesObj):

        hostname_zones = {}

        self.gethostedzones()

        for hostname in hostnamesObj:

            domain = self.domaininhostname(hostname)

            if (not domain):
                log.critical(f"The hostname: {hostname} specified, does not exist in this user account.")
                return (False)

            if domain in hostname_zones:
                hostname_zones[domain].append(hostname)
            else:
                hostname_zones[domain] = [hostname]

        return (hostname_zones)

    def check_hostnameon_server(self,hostname, IP, rrtype='A', nameserver=None):

        log.debug(f'try to resolve hostname={hostname}, IP={IP}, rrtype={rrtype}, nameserver={nameserver}')

        resolver = dns.resolver.Resolver(configure=False)

        if nameserver is None:
            nameserver=self.get_authoritative_nameserver(hostname)
            if nameserver is None:
                nameserver='8.8.8.8'

        resolver.nameservers=[nameserver]
        rdatatype=dns.rdatatype.from_text(rrtype)

        # hostname = "hostname.bgwlan.nl"
        try:
            answers = resolver.resolve(hostname,rdatatype)
        except Exception as e:
            log.error(f'{e} for update type {self._services}')
            return (False)

        if (answers and answers[0] and (answers[0].rdtype == dns.rdatatype.A or answers[0].rdtype == dns.rdatatype.AAAA)):
            record=answers[0]
            log.debug(f'hostname={hostname} record={record.address}')
        else:
            log.error(f'hostname={hostname} does not resovle correctly (no A or AAAA record returned')
            return(False)

        IP_request= self.getip (IP)
        IP_dns= self.getip (record.address)

        if not IP_request:
            log.critical("IP address {IP} is invalid!")
            return False

        if not IP_dns:
            log.critical("IP address {IP} is invalid!")
            return False

        if (IP_request == IP_dns):
            log.info(f'IP Address for Hostname: {hostname}/{IP_request} has not changed for update type {self._services}')
            return(True)
        else:
            log.info(f'IP Address for {hostname} resolved in: {IP_dns} IP has changed to {IP_request} for update type {self._services}')
            return (False)

    def get_authoritative_nameserver(self,domain):

        n = dns.name.from_text(domain)

        depth = 2
        default = self._resolver
        nameserver = default.nameservers[0]
        log.debug(f'DNS lookup {domain}')

        last = False
        while not last:
            s = n.split(depth)

            last = s[0].to_unicode() == u'@'
            sub = s[1]

            log.debug(f'DNS s="{s}" last="{last}" sub="{sub}"')

            log.debug('Looking up %s on %s' % (sub, nameserver))
            query = dns.message.make_query(sub, dns.rdatatype.NS)
            response = dns.query.udp(query, nameserver)

            rcode = response.rcode()
            if rcode != dns.rcode.NOERROR:
                if rcode == dns.rcode.NXDOMAIN:
                    log.critical('%s does not exist. dns.rcode = %s' % (sub,rcode ))
                    return(None)
                else:
                    log.critica('Error %s' % dns.rcode.to_text(rcode))
                    return(None)


            rrset = None
            if len(response.authority) > 0:
                rrset = response.authority[0]
            else:
                rrset = response.answer[0]

            rr = rrset[0]
            if rr.rdtype == dns.rdatatype.SOA:
                log.debug('Same server is authoritative for %s' % sub)
            else:
                authority = rr.target
                log.debug('%s is authoritative for %s' % (authority, sub))
                nameserver = default.resolve(authority).rrset[0].to_text()

            depth += 1

        return nameserver

class AccountFactory:
    def __init__(self):
        self._account_classes = list()
        self._register()

    def _register(self):
        """ Register all account (type) classes.
            These usually describe a protocol (like dyndns2)
        """
        pkg_name = "%s.account" % __name__[:-len(os.path.splitext(os.path.basename(__file__))[0])-1]
        all_account_classes = list()

        for filename in glob.glob("%s/account/*.py" % os.path.dirname(__file__)):
            importlib.import_module(".%s" % os.path.splitext(os.path.basename(filename))[0], pkg_name)

        for module_name in dir(sys.modules[pkg_name]):

            for attribute_name in dir(getattr(sys.modules[pkg_name], module_name)):
                cls = getattr(getattr(sys.modules[pkg_name], module_name), attribute_name)
                if isinstance(cls, type) and issubclass(cls, BaseAccount) and cls != BaseAccount:
                    all_account_classes.append(cls)

        self._account_classes = sorted(all_account_classes, key=lambda k: k._priority)

    def get(self, account: dict):
        for handler in self._account_classes:
            if handler.match(account):
                return handler(account)

    def known_services(self):
        all_services = []
        for handler in self._account_classes:
            all_services += handler.known_services()
        return all_services

