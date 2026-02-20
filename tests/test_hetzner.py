from unittest.mock import patch, MagicMock


API_BASE = 'https://api.hetzner.cloud/v1'


def _make_account(domains=None, credentials=None):
    return {
        'service': 'hetzner',
        'domains': domains or ['example.com'],
        'credentials': {'hetzner_api_token': 'test-token'} if credentials is None else credentials,
    }


def _mock_zones_response():
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = {
        'zones': [
            {'id': 123, 'name': 'example.com'},
            {'id': 456, 'name': 'other.com'},
        ]
    }
    resp.raise_for_status = MagicMock()
    return resp


def _mock_zones_with_reverse():
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = {
        'zones': [
            {'id': 123, 'name': 'example.com'},
            {'id': 789, 'name': '168.192.in-addr.arpa'},
            {'id': 790, 'name': 'ip6.arpa'},
        ]
    }
    resp.raise_for_status = MagicMock()
    return resp


# --- Static method tests ---

class TestHetznerStatic:
    def test_match_hetzner(self):
        from lib.account.hetzner import Hetzner
        assert Hetzner.match({'service': 'hetzner'}) is True

    def test_match_other(self):
        from lib.account.hetzner import Hetzner
        assert Hetzner.match({'service': 'aws'}) is False

    def test_known_services(self):
        from lib.account.hetzner import Hetzner
        assert Hetzner.known_services() == ['hetzner']


# --- Credential tests ---

class TestHetznerCredentials:
    @patch('lib.account.hetzner.requests.get')
    def test_credentials_from_account(self, mock_get):
        mock_get.return_value = _mock_zones_response()
        from lib.account.hetzner import Hetzner
        account = _make_account(credentials={'hetzner_api_token': 'my-token'})
        h = Hetzner(account)
        creds = h._get_credentials()
        assert creds['hetzner_api_token'] == 'my-token'

    @patch('lib.account.hetzner.requests.get')
    def test_credentials_env_fallback(self, mock_get):
        mock_get.return_value = _mock_zones_response()
        from os import environ
        old = environ.get('HETZNER_API_TOKEN')
        environ['HETZNER_API_TOKEN'] = 'env-token'
        try:
            from lib.account.hetzner import Hetzner
            account = _make_account(credentials={})
            h = Hetzner(account)
            creds = h._get_credentials()
            assert creds['hetzner_api_token'] == 'env-token'
        finally:
            if old is None:
                environ.pop('HETZNER_API_TOKEN', None)
            else:
                environ['HETZNER_API_TOKEN'] = old


# --- gethostedzones tests ---

class TestHetznerZones:
    @patch('lib.account.hetzner.requests.get')
    def test_gethostedzones(self, mock_get):
        mock_get.return_value = _mock_zones_response()
        from lib.account.hetzner import Hetzner
        h = Hetzner(_make_account())
        assert 'example.com' in h._zones
        assert h._zones['example.com'] == 123
        # other.com is in the API but not in account domains, so not mapped
        assert 'other.com' not in h._zones

    @patch('lib.account.hetzner.requests.get')
    def test_gethostedzones_skips_reverse(self, mock_get):
        mock_get.return_value = _mock_zones_with_reverse()
        from lib.account.hetzner import Hetzner
        h = Hetzner(_make_account())
        assert 'example.com' in h._zones
        assert '168.192.in-addr.arpa' not in h._zones
        assert 'ip6.arpa' not in h._zones

    @patch('lib.account.hetzner.requests.get')
    def test_gethostedzones_api_error(self, mock_get):
        mock_get.side_effect = Exception('connection error')
        from lib.account.hetzner import Hetzner
        h = Hetzner(_make_account())
        # Should not raise, zones from account domains are preserved
        assert 'example.com' in h._zones

    def test_gethostedzones_no_credentials(self):
        from lib.account.hetzner import Hetzner
        account = _make_account(credentials={})
        h = Hetzner(account)
        # Should not raise
        assert 'example.com' in h._zones


# --- Parent zone mapping tests ---

def _mock_parent_zone_response():
    """API zone 'example.com' is parent of app domain 'dyn.example.com'."""
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = {
        'zones': [
            {'id': 840, 'name': 'example.com'},
        ]
    }
    resp.raise_for_status = MagicMock()
    return resp


class TestParentZoneMapping:
    @patch('lib.account.hetzner.requests.get')
    def test_parent_zone_maps_domain_to_api_zone_id(self, mock_get):
        """App domain 'dyn.example.com' should use zone ID from parent 'example.com'."""
        mock_get.return_value = _mock_parent_zone_response()
        from lib.account.hetzner import Hetzner
        h = Hetzner(_make_account(domains=['dyn.example.com']))
        assert h._zones['dyn.example.com'] == 840
        assert h._api_zone_names['dyn.example.com'] == 'example.com'

    @patch('lib.account.hetzner.Hetzner.check_hostnameon_server', return_value=False)
    @patch('lib.account.hetzner.requests.post')
    @patch('lib.account.hetzner.requests.get')
    def test_create_uses_correct_relative_name_for_parent_zone(self, mock_get, mock_post, mock_check):
        """windtre.dyn.example.com under API zone example.com should use relative name 'windtre.dyn'."""
        zones_resp = _mock_parent_zone_response()
        rrset_404 = MagicMock()
        rrset_404.status_code = 404
        mock_get.side_effect = [zones_resp, rrset_404]

        create_resp = MagicMock()
        create_resp.status_code = 200
        create_resp.raise_for_status = MagicMock()
        mock_post.return_value = create_resp

        from lib.account.hetzner import Hetzner
        h = Hetzner(_make_account(domains=['dyn.example.com']))
        result = h.createrecords('1.2.3.4', {'dyn.example.com': ['windtre.dyn.example.com']}, 'A')

        assert result == {'windtre.dyn.example.com': 'good'}
        call_args = mock_post.call_args
        # Should use zone ID 840, not string 'dyn.example.com'
        assert '/zones/840/' in call_args[0][0]
        # Relative name should be 'windtre.dyn' (relative to API zone 'example.com')
        assert call_args[1]['json']['name'] == 'windtre.dyn'

    @patch('lib.account.hetzner.requests.delete')
    @patch('lib.account.hetzner.requests.get')
    def test_delete_uses_correct_relative_name_for_parent_zone(self, mock_get, mock_delete):
        """Delete should also use the correct relative name for parent zones."""
        mock_get.return_value = _mock_parent_zone_response()

        delete_resp = MagicMock()
        delete_resp.status_code = 200
        delete_resp.raise_for_status = MagicMock()
        mock_delete.return_value = delete_resp

        from lib.account.hetzner import Hetzner
        h = Hetzner(_make_account(domains=['dyn.example.com']))
        result = h.deleterecords({'dyn.example.com': ['windtre.dyn.example.com']}, rtype='A')

        assert result == {'windtre.dyn.example.com': 'good'}
        assert '/zones/840/rrsets/windtre.dyn/A' in mock_delete.call_args[0][0]


# --- Relative name tests ---

class TestRelativeName:
    @patch('lib.account.hetzner.requests.get')
    def test_subdomain(self, mock_get):
        mock_get.return_value = _mock_zones_response()
        from lib.account.hetzner import Hetzner
        h = Hetzner(_make_account())
        assert h._get_relative_name('test.example.com', 'example.com') == 'test'

    @patch('lib.account.hetzner.requests.get')
    def test_multi_level_subdomain(self, mock_get):
        mock_get.return_value = _mock_zones_response()
        from lib.account.hetzner import Hetzner
        h = Hetzner(_make_account())
        assert h._get_relative_name('a.b.example.com', 'example.com') == 'a.b'

    @patch('lib.account.hetzner.requests.get')
    def test_zone_apex(self, mock_get):
        mock_get.return_value = _mock_zones_response()
        from lib.account.hetzner import Hetzner
        h = Hetzner(_make_account())
        assert h._get_relative_name('example.com', 'example.com') == '@'


# --- createrecords tests ---

class TestHetznerCreateRecords:
    @patch('lib.account.hetzner.Hetzner.check_hostnameon_server', return_value=False)
    @patch('lib.account.hetzner.requests.post')
    @patch('lib.account.hetzner.requests.get')
    def test_create_new_record(self, mock_get, mock_post, mock_check):
        zones_resp = _mock_zones_response()
        rrset_404 = MagicMock()
        rrset_404.status_code = 404
        mock_get.side_effect = [zones_resp, rrset_404]

        create_resp = MagicMock()
        create_resp.status_code = 200
        create_resp.raise_for_status = MagicMock()
        mock_post.return_value = create_resp

        from lib.account.hetzner import Hetzner
        h = Hetzner(_make_account())
        result = h.createrecords('1.2.3.4', {'example.com': ['test.example.com']}, 'A')

        assert result == {'test.example.com': 'good'}
        # Verify POST was called to create rrset
        mock_post.assert_called_once()
        call_args = mock_post.call_args
        assert '/rrsets' in call_args[0][0]
        assert call_args[1]['json']['name'] == 'test'
        assert call_args[1]['json']['type'] == 'A'
        assert call_args[1]['json']['records'] == [{'value': '1.2.3.4'}]

    @patch('lib.account.hetzner.Hetzner.check_hostnameon_server', return_value=False)
    @patch('lib.account.hetzner.requests.post')
    @patch('lib.account.hetzner.requests.get')
    def test_update_existing_record(self, mock_get, mock_post, mock_check):
        zones_resp = _mock_zones_response()
        rrset_exists = MagicMock()
        rrset_exists.status_code = 200
        rrset_exists.json.return_value = {
            'rrset': {'id': 'test/A', 'name': 'test', 'type': 'A',
                      'records': [{'value': '1.1.1.1'}]}
        }
        mock_get.side_effect = [zones_resp, rrset_exists]

        update_resp = MagicMock()
        update_resp.raise_for_status = MagicMock()
        mock_post.return_value = update_resp

        from lib.account.hetzner import Hetzner
        h = Hetzner(_make_account())
        result = h.createrecords('1.2.3.4', {'example.com': ['test.example.com']}, 'A')

        assert result == {'test.example.com': 'good'}
        # Verify set_records action was called
        call_url = mock_post.call_args[0][0]
        assert 'actions/set_records' in call_url

    @patch('lib.account.hetzner.Hetzner.check_hostnameon_server', return_value=True)
    @patch('lib.account.hetzner.requests.get')
    def test_create_nochg(self, mock_get, mock_check):
        mock_get.return_value = _mock_zones_response()

        from lib.account.hetzner import Hetzner
        h = Hetzner(_make_account())
        result = h.createrecords('1.2.3.4', {'example.com': ['test.example.com']}, 'A')

        assert result == {'test.example.com': 'nochg'}

    @patch('lib.account.hetzner.Hetzner.check_hostnameon_server', return_value=False)
    @patch('lib.account.hetzner.requests.get')
    def test_create_api_error(self, mock_get, mock_check):
        zones_resp = _mock_zones_response()
        error_resp = MagicMock()
        error_resp.status_code = 500
        error_resp.raise_for_status.side_effect = Exception('server error')
        # First call returns zones, second call (GET rrset check) raises
        mock_get.side_effect = [zones_resp, Exception('connection error')]

        from lib.account.hetzner import Hetzner
        h = Hetzner(_make_account())
        result = h.createrecords('1.2.3.4', {'example.com': ['test.example.com']}, 'A')

        assert result == {'test.example.com': 'dnserr'}

    def test_create_no_credentials(self):
        from lib.account.hetzner import Hetzner
        account = _make_account(credentials={})
        h = Hetzner(account)
        result = h.createrecords('1.2.3.4', {'example.com': ['test.example.com']}, 'A')
        assert result == {'test.example.com': 'dnserr'}


# --- deleterecords tests ---

class TestHetznerDeleteRecords:
    @patch('lib.account.hetzner.requests.delete')
    @patch('lib.account.hetzner.requests.get')
    def test_delete_existing(self, mock_get, mock_delete):
        mock_get.return_value = _mock_zones_response()

        delete_resp = MagicMock()
        delete_resp.status_code = 200
        delete_resp.raise_for_status = MagicMock()
        mock_delete.return_value = delete_resp

        from lib.account.hetzner import Hetzner
        h = Hetzner(_make_account())
        result = h.deleterecords({'example.com': ['test.example.com']}, rtype='A')

        assert result == {'test.example.com': 'good'}
        mock_delete.assert_called_once()
        assert '/rrsets/test/A' in mock_delete.call_args[0][0]

    @patch('lib.account.hetzner.requests.delete')
    @patch('lib.account.hetzner.requests.get')
    def test_delete_not_found(self, mock_get, mock_delete):
        mock_get.return_value = _mock_zones_response()

        delete_resp = MagicMock()
        delete_resp.status_code = 404
        mock_delete.return_value = delete_resp

        from lib.account.hetzner import Hetzner
        h = Hetzner(_make_account())
        result = h.deleterecords({'example.com': ['test.example.com']}, rtype='A')

        assert result == {'test.example.com': 'nochg'}

    @patch('lib.account.hetzner.requests.delete')
    @patch('lib.account.hetzner.requests.get')
    def test_delete_both_types(self, mock_get, mock_delete):
        mock_get.return_value = _mock_zones_response()

        delete_resp = MagicMock()
        delete_resp.status_code = 200
        delete_resp.raise_for_status = MagicMock()
        mock_delete.return_value = delete_resp

        from lib.account.hetzner import Hetzner
        h = Hetzner(_make_account())
        result = h.deleterecords({'example.com': ['test.example.com']}, rtype=None)

        assert result == {'test.example.com': 'good'}
        # Should have called delete for both A and AAAA
        assert mock_delete.call_count == 2

    @patch('lib.account.hetzner.requests.delete')
    @patch('lib.account.hetzner.requests.get')
    def test_delete_one_exists_one_not(self, mock_get, mock_delete):
        """Delete both types when only A exists, AAAA returns 404."""
        mock_get.return_value = _mock_zones_response()

        ok_resp = MagicMock()
        ok_resp.status_code = 200
        ok_resp.raise_for_status = MagicMock()
        not_found_resp = MagicMock()
        not_found_resp.status_code = 404
        mock_delete.side_effect = [ok_resp, not_found_resp]

        from lib.account.hetzner import Hetzner
        h = Hetzner(_make_account())
        result = h.deleterecords({'example.com': ['test.example.com']}, rtype=None)

        assert result == {'test.example.com': 'good'}

    @patch('lib.account.hetzner.requests.delete')
    @patch('lib.account.hetzner.requests.get')
    def test_delete_api_error(self, mock_get, mock_delete):
        mock_get.return_value = _mock_zones_response()
        mock_delete.side_effect = Exception('connection error')

        from lib.account.hetzner import Hetzner
        h = Hetzner(_make_account())
        result = h.deleterecords({'example.com': ['test.example.com']}, rtype='A')

        assert result == {'test.example.com': 'dnserr'}

    def test_delete_no_credentials(self):
        from lib.account.hetzner import Hetzner
        account = _make_account(credentials={})
        h = Hetzner(account)
        result = h.deleterecords({'example.com': ['test.example.com']}, rtype='A')
        assert result == {'test.example.com': 'dnserr'}
