

from ..accounts import BaseAccount
from os import environ
from . import log
import dns.update
import dns.query
import dns.tsigkeyring


class nsupdate(BaseAccount):
    _services = ['nsupdate']

    def __init__(self, account: dict):
        super().__init__(account)


    @staticmethod
    def known_services():
        return  nsupdate._services

    @staticmethod
    def match(account):
        return account.get('service') in nsupdate._services

    def _get_credentials(self):
        creds = self._account.get('credentials', {})
        return {
            'nsupdate_key': creds.get('nsupdate_key', environ.get('NSUPDATE_KEY')),
            'nsupdate_algo': creds.get('nsupdate_algo', environ.get('NSUPDATE_ALGO')),
            'nsupdate_secret': creds.get('nsupdate_secret', environ.get('NSUPDATE_SECRET')),
            'nsupdate_nameserver': creds.get('nsupdate_nameserver', environ.get('NSUPDATE_NAMESERVER')),
        }

    def createrecords(self, IP, hostname_zones, rtype="A", ttl=60):
        log.debug(f'self._zones {self._zones}')

        creds = self._get_credentials()
        required = ['nsupdate_key', 'nsupdate_algo', 'nsupdate_secret', 'nsupdate_nameserver']
        if not all(creds.get(k) for k in required):
            log.error('nsupdate credentials not configured — cannot create records')
            return {h: 'dnserr' for hosts in hostname_zones.values() for h in hosts}

        results = {}

        for zonename in hostname_zones.keys():

            for hostname in hostname_zones[zonename]:

                if (self.check_hostnameon_server(hostname, IP, rtype, nameserver=creds['nsupdate_nameserver'])):
                    results[hostname] = "nochg"
                    continue

                keyring = dns.tsigkeyring.from_text({ creds['nsupdate_key'] + '.' : creds['nsupdate_secret'] })
                update = dns.update.Update(zonename + ".", keyring = keyring, keyalgorithm = creds['nsupdate_algo'])
                update.replace(hostname + "." , ttl, rtype, IP)

                try:
                    log.debug(f'try update zonename = {zonename}, hostname = {hostname}, ttl = {ttl}, rtype = {rtype}, ttl = {ttl}, IP = {IP}')

                    response = dns.query.tcp(update, creds['nsupdate_nameserver'], timeout=10)
                except Exception as e:
                    log.critical(f'something went wrong! {e}')
                    results[hostname] = "dnserr"
                    continue

                log.debug (f'response = {response}')
                log.info(f'created dns records via nsupdate on {creds["nsupdate_nameserver"]} record: {hostname} {rtype} {IP} for update type {self._services}')
                results[hostname] = "good"

        return (results)

    def deleterecords(self, hostname_zones, rtype=None):
        log.debug(f'self._zones {self._zones}')

        creds = self._get_credentials()
        required = ['nsupdate_key', 'nsupdate_algo', 'nsupdate_secret', 'nsupdate_nameserver']
        if not all(creds.get(k) for k in required):
            log.error('nsupdate credentials not configured — cannot delete records')
            return {h: 'dnserr' for hosts in hostname_zones.values() for h in hosts}

        results = {}
        rtypes = [rtype] if rtype else ['A', 'AAAA']
        nameserver = creds['nsupdate_nameserver']

        for zonename in hostname_zones.keys():
            for hostname in hostname_zones[zonename]:
                keyring = dns.tsigkeyring.from_text({creds['nsupdate_key'] + '.': creds['nsupdate_secret']})
                update = dns.update.Update(zonename + ".", keyring=keyring, keyalgorithm=creds['nsupdate_algo'])

                for rt in rtypes:
                    update.delete(hostname + ".", rt)

                try:
                    log.debug(f'try delete zonename = {zonename}, hostname = {hostname}, rtypes = {rtypes}')
                    response = dns.query.tcp(update, nameserver, timeout=10)
                    log.debug(f'response = {response}')
                    log.info(f'deleted dns records via nsupdate on {nameserver}: {hostname} {rtypes} for update type {self._services}')
                    results[hostname] = "good"
                except Exception as e:
                    log.critical(f'something went wrong! {e}')
                    results[hostname] = "dnserr"

        return results


