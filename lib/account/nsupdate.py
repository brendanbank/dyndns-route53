

from ..accounts import BaseAccount
from os import environ
from . import log
import dns.update
import dns.query
import dns.tsigkeyring

ENV_VARS = ['NSUPDATE_KEY','NSUPDATE_ALGO', 'NSUPDATE_SECRET', 'NSUPDATE_NAMESERVER']

for ENV in ENV_VARS:
    if not environ.get(ENV):
        log.critical(f'Enviroment Variable = {ENV} is not set!')
        exit (1)
    else:
        log.debug(f'Enviroment Variable = {ENV} is set!')


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

    def createrecords(self, IP, hostname_zones, rtype="A", ttl=300):
        log.debug(f'self._zones {self._zones}')

        for zonename in hostname_zones.keys():
            
            for hostname in hostname_zones[zonename]:
                
                if (self.check_hostnameon_server(hostname, IP, rtype, nameserver=environ.get('NSUPDATE_NAMESERVER'))):
                    continue
                
                keyring = dns.tsigkeyring.from_text({ environ.get('NSUPDATE_KEY') + '.' : environ.get('NSUPDATE_SECRET') })        
                update = dns.update.Update(zonename + ".", keyring = keyring, keyalgorithm = environ.get('NSUPDATE_ALGO'))
                update.replace(hostname + "." , ttl, rtype, IP)

                try:
                    log.debug(f'try update zonename = {zonename}, hostname = {hostname}, ttl = {ttl}, rtype = {rtype}, ttl = {ttl}, IP = {IP}')
    
                    response = dns.query.tcp(update, environ.get('NSUPDATE_NAMESERVER'))
                except Exception as e:
                    log.critical(f'something went wrong! {e}')
                    return (False)
        
                log.debug (f'response = {response}')
                log.info(f'created dns records via nsupdate on {environ.get("NSUPDATE_NAMESERVER")} record: {hostname} {rtype} {IP} for update type {self._services}')
    
        return (True)
                
                

