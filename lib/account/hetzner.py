

from ..accounts import BaseAccount
from os import environ
from . import log
import requests


API_BASE = 'https://api.hetzner.cloud/v1'


class Hetzner(BaseAccount):
    _services = ['hetzner']

    def __init__(self, account: dict):
        super().__init__(account)
        self._api_zone_names = {}  # app domain -> actual Hetzner zone name
        self.gethostedzones()

    @staticmethod
    def known_services():
        return Hetzner._services

    @staticmethod
    def match(account):
        return account.get('service') in Hetzner._services

    def _get_credentials(self):
        creds = self._account.get('credentials', {})
        return {
            'hetzner_api_token': creds.get('hetzner_api_token', environ.get('HETZNER_API_TOKEN')),
        }

    def _headers(self):
        token = self._get_credentials().get('hetzner_api_token')
        return {'Authorization': f'Bearer {token}'}

    def _get_relative_name(self, hostname, zone_name):
        """Convert FQDN to relative name within zone. Zone apex returns '@'."""
        if hostname == zone_name:
            return '@'
        suffix = '.' + zone_name
        if hostname.endswith(suffix):
            return hostname[:-len(suffix)]
        return hostname

    def gethostedzones(self):
        creds = self._get_credentials()
        if not creds.get('hetzner_api_token'):
            log.error('Hetzner API token not configured')
            return self._zones.keys()

        try:
            response = requests.get(f'{API_BASE}/zones', headers=self._headers(), timeout=10)
            response.raise_for_status()
        except Exception as e:
            log.error(f'Failed to list hosted zones: {e}')
            return self._zones.keys()

        data = response.json()
        api_zones = {}
        for zone in data.get('zones', []):
            name = zone['name']
            if 'in-addr.arpa' in name or 'ip6.arpa' in name:
                continue
            api_zones[name] = zone['id']

        # For each app domain already in _zones, check if a Hetzner API zone
        # matches or is a parent (e.g. app domain "dyn.bgwlan.nl" under API zone
        # "bgwlan.nl"). Map the app domain to the Hetzner zone ID and remember
        # the actual API zone name for relative name computation.
        for domain in list(self._zones.keys()):
            if domain in api_zones:
                self._zones[domain] = api_zones[domain]
                self._api_zone_names[domain] = domain
            else:
                for api_name, api_id in api_zones.items():
                    if domain.endswith('.' + api_name):
                        self._zones[domain] = api_id
                        self._api_zone_names[domain] = api_name
                        break

        log.debug(f'_zones = {self._zones}')
        return self._zones.keys()

    def createrecords(self, IP, hostname_zones, rtype="A", ttl=60):
        creds = self._get_credentials()
        if not creds.get('hetzner_api_token'):
            log.error('Hetzner API token not configured — cannot create records')
            return {h: 'dnserr' for hosts in hostname_zones.values() for h in hosts}

        results = {}

        for zonename in hostname_zones.keys():
            zone_id = self._zones[zonename]

            for hostname in hostname_zones[zonename]:

                if self.check_hostnameon_server(hostname, IP, rtype):
                    results[hostname] = "nochg"
                    continue

                api_zone_name = self._api_zone_names.get(zonename, zonename)
                relative_name = self._get_relative_name(hostname, api_zone_name)

                try:
                    # Check if rrset already exists
                    resp = requests.get(
                        f'{API_BASE}/zones/{zone_id}/rrsets/{relative_name}/{rtype}',
                        headers=self._headers(),
                        timeout=10,
                    )

                    if resp.status_code == 200:
                        # Update existing rrset via set_records action
                        resp = requests.post(
                            f'{API_BASE}/zones/{zone_id}/rrsets/{relative_name}/{rtype}/actions/set_records',
                            headers=self._headers(),
                            json={'ttl': ttl, 'records': [{'value': IP}]},
                            timeout=10,
                        )
                        resp.raise_for_status()
                    else:
                        # Create new rrset
                        resp = requests.post(
                            f'{API_BASE}/zones/{zone_id}/rrsets',
                            headers=self._headers(),
                            json={
                                'name': relative_name,
                                'type': rtype,
                                'ttl': ttl,
                                'records': [{'value': IP}],
                            },
                            timeout=10,
                        )
                        resp.raise_for_status()

                    results[hostname] = "good"
                    log.info(f'created dns entry via hetzner: {hostname} {rtype} {IP} for update type {self._services}')

                except Exception as e:
                    log.critical(f'something went wrong! {e}')
                    results[hostname] = "dnserr"

        return results

    def deleterecords(self, hostname_zones, rtype=None):
        creds = self._get_credentials()
        if not creds.get('hetzner_api_token'):
            log.error('Hetzner API token not configured — cannot delete records')
            return {h: 'dnserr' for hosts in hostname_zones.values() for h in hosts}

        results = {}
        rtypes = [rtype] if rtype else ['A', 'AAAA']

        for zonename in hostname_zones.keys():
            zone_id = self._zones[zonename]

            for hostname in hostname_zones[zonename]:
                api_zone_name = self._api_zone_names.get(zonename, zonename)
                relative_name = self._get_relative_name(hostname, api_zone_name)
                deleted_any = False

                try:
                    for rt in rtypes:
                        resp = requests.delete(
                            f'{API_BASE}/zones/{zone_id}/rrsets/{relative_name}/{rt}',
                            headers=self._headers(),
                            timeout=10,
                        )
                        if resp.status_code == 404:
                            continue
                        resp.raise_for_status()
                        deleted_any = True

                    if deleted_any:
                        results[hostname] = "good"
                        log.info(f'deleted dns records via hetzner: {hostname} {rtypes} for update type {self._services}')
                    else:
                        log.info(f'No matching records to delete for {hostname} in zone {zonename}')
                        results[hostname] = "nochg"

                except Exception as e:
                    log.critical(f'something went wrong! {e}')
                    results[hostname] = "dnserr"

        return results
