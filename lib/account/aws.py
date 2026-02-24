

from ..accounts import BaseAccount
import boto3
from os import environ
from . import log


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

    def _get_credentials(self):
        creds = self._account.get('credentials', {})
        return {
            'aws_access_key_id': creds.get('aws_access_key_id', environ.get('AWS_ACCESS_KEY_ID')),
            'aws_secret_access_key': creds.get('aws_secret_access_key', environ.get('AWS_SECRET_ACCESS_KEY')),
        }

    def gethostedzones(self):
        creds = self._get_credentials()
        if not creds.get('aws_access_key_id') or not creds.get('aws_secret_access_key'):
            log.error('AWS credentials not configured')
            return self._zones.keys()

        try:
            client = boto3.client('route53', **creds)
            response = client.list_hosted_zones()
        except Exception as e:
            log.error(f'Failed to list hosted zones: {e}')
            return self._zones.keys()

        log.debug(f'list_hosted_zones = {response}')
        for zone in response["HostedZones"]:
            if zone["Name"].find("in-addr.arpa.") >= 0  or zone["Name"].find("ip6.arpa.") >= 0:
                continue

            self._zones[zone["Name"][:-1]] = zone["Id"]

        log.debug(f'_zones.keys = {self._zones.keys()}')

        return(self._zones.keys())

    def createrecords(self, IP, hostname_zones, rtype="A", ttl=60):
        creds = self._get_credentials()
        if not creds.get('aws_access_key_id') or not creds.get('aws_secret_access_key'):
            log.error('AWS credentials not configured — cannot create records')
            return {h: 'dnserr' for hosts in hostname_zones.values() for h in hosts}

        client = boto3.client('route53', **creds)

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

    def deleterecords(self, hostname_zones, rtype=None):
        creds = self._get_credentials()
        if not creds.get('aws_access_key_id') or not creds.get('aws_secret_access_key'):
            log.error('AWS credentials not configured — cannot delete records')
            return {h: 'dnserr' for hosts in hostname_zones.values() for h in hosts}

        client = boto3.client('route53', **creds)
        results = {}
        rtypes = [rtype] if rtype else ['A', 'AAAA']

        for zonename in hostname_zones.keys():
            zoneId = self._zones[zonename]

            try:
                rrsets = client.list_resource_record_sets(HostedZoneId=zoneId)
            except Exception as e:
                log.critical(f'Failed to list record sets for zone {zonename}: {e}')
                for hostname in hostname_zones[zonename]:
                    results[hostname] = "dnserr"
                continue

            for hostname in hostname_zones[zonename]:
                rrecords = []
                for rs in rrsets.get('ResourceRecordSets', []):
                    rs_name = rs['Name'].rstrip('.')
                    if rs_name.lower() != hostname.lower():
                        continue
                    if rs['Type'] in rtypes:
                        rrecords.append({
                            'Action': 'DELETE',
                            'ResourceRecordSet': rs,
                        })

                if not rrecords:
                    log.info(f'No matching records to delete for {hostname} in zone {zonename}')
                    results[hostname] = "nochg"
                    continue

                try:
                    reply = client.change_resource_record_sets(
                        ChangeBatch={'Changes': rrecords}, HostedZoneId=zoneId)
                    log.debug(f'delete reply = {reply}')
                    results[hostname] = "good"
                    log.info(f'deleted dns entry via route53: {hostname} {rtypes} for update type {self._services}')
                except Exception as e:
                    log.critical(f'Failed to delete records for {hostname}: {e}')
                    results[hostname] = "dnserr"

        return results
