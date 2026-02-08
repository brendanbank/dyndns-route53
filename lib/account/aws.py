

from ..accounts import BaseAccount
import boto3
from os import environ
from . import log


ENV_VARS = ['AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY']

for ENV in ENV_VARS:
    if not environ.get(ENV):
        log.critical(f'Enviroment Variable = {ENV} is not set!')
        exit (1)
    else:
        log.debug(f'Enviroment Variable = {ENV} is set!')


class AWS(BaseAccount):
    _services = ['aws']

    def __init__(self, account: dict):
        super().__init__(account)
        self.gethostedzones()

    @staticmethod
    def known_services():
        return  AWS._services

    @staticmethod
    def match(account):
        return account.get('service') in AWS._services


    def gethostedzones(self):
        client = boto3.client('route53',
            aws_access_key_id=environ.get('AWS_ACCESS_KEY_ID'),
            aws_secret_access_key=environ.get('AWS_SECRET_ACCESS_KEY'))
    
        response = client.list_hosted_zones()
    
        log.debug(f'list_hosted_zones = {response}')
        for zone in response["HostedZones"]:
            if zone["Name"].find("in-addr.arpa.") >= 0  or zone["Name"].find("ip6.arpa.") >= 0:
                continue
    
            self._zones[zone["Name"][:-1]] = zone["Id"]
    
        log.debug(f'_zones.keys = {self._zones.keys()}')
    
        return(self._zones.keys())

    def createrecords(self, IP, hostname_zones, rtype="A", ttl=300):

        client = boto3.client('route53',
            aws_access_key_id=environ.get('AWS_ACCESS_KEY_ID'),
            aws_secret_access_key=environ.get('AWS_SECRET_ACCESS_KEY'))

        log.debug(f'_zones.keys = {self._zones}')

        log.debug(f'hostname_zones {hostname_zones}')

        results = {}

        for zonename in hostname_zones.keys():
            changed_hostnames = []
            rrecords = []
            zoneId = self._zones[zonename]
            for hostname in hostname_zones[zonename]:

                if (self.check_hostnameon_server(hostname, IP, rtype)):
                    results[hostname] = "nochg"
                    continue

                rrecords.append({
                                'Action': 'UPSERT',
                                'ResourceRecordSet': {
                                    'Name': hostname,
                                'ResourceRecords': [
                                        {
                                            'Value': IP,
                                        },
                                    ],
                                    'TTL': ttl,
                                    'Type': rtype,
                                },
                            })

                changed_hostnames.append(hostname)

            if (not rrecords):
                log.debug("Nothing to do....")
                continue
            try:
                log.debug(f'try update zone id {zoneId} with {rrecords}')
                reply = client.change_resource_record_sets(
                    ChangeBatch={'Changes': rrecords}, HostedZoneId=zoneId)
            except Exception as e:
                log.critical(f'something went wrong! {e}')
                for hostname in changed_hostnames:
                    results[hostname] = "dnserr"
                continue

            log.debug (f'reply = {reply}')

            for hostname in changed_hostnames:
                results[hostname] = "good"
                log.info(f'created dns entry via route53 record: {hostname} {rtype} {IP} for update type {self._services}')

        return (results)

