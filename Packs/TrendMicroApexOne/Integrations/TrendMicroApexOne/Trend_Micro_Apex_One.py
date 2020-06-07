import json

import dateparser
import demistomock as demisto
import requests
import hashlib
import jwt
from CommonServerPython import *  # noqa: E402 lgtm [py/polluting-import]
from CommonServerUserPython import *  # noqa: E402 lgtm [py/polluting-import]

# IMPORTS


# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

# CONSTANTS
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'


class Client(BaseClient):
    def __init__(self, base_url, app_id, api_key, verify, proxy):
        super().__init__(base_url, app_id, api_key, verify, proxy)
        self._app_id = app_id
        self._api_key = api_key
        self._headers = {'Authorization': 'Bearer {}', 'Content-Type': 'application/json;charset=utf-8'}

    def create_checksum(self, http_method, api_path, headers, request_body):
        """
        This function creates a checksum value with is being decoded as one of the keys in JWT token.
        It contains the request's data that is being performed.
        :param http_method: HTTP method of the request
        :param api_path: a url to the requested resource
        :param headers: the headers of a request
        :param request_body: the body of a request
        :return: a checksum string
        """
        string_to_hash = http_method.upper() + '|' + api_path.lower() + '|' + headers + '|' + request_body
        base64_string = base64.b64encode(hashlib.sha256(str.encode(string_to_hash)).digest()).decode('utf-8')
        return base64_string

    def create_jwt_token(self, http_method, url, headers='', request_body='', iat=time.time(), algorithm='HS256',
                         version='V1', ):
        checksum = self.create_checksum(http_method, url, headers, request_body)

        payload = {'appid': self._app_id,
                   'iat': iat,
                   'version': version,
                   'checksum': checksum}
        token = jwt.encode(payload, self._api_key, algorithm=algorithm).decode('utf-8')
        self._headers['Authorization'] = f'Bearer {token}'
        return token

    def list_security_agents(self, entity_id, ip_address, mac_address, host_name, product, managing_server_id):
        url = '/WebApp/API/AgentResource/ProductAgents'
        self.create_jwt_token('GET', self._base_url + url)
        params = {}
        if entity_id:
            params['entity_id'] = entity_id
        if ip_address:
            params['ip_address'] = ip_address
        if mac_address:
            params['mac_address'] = mac_address
        if host_name:
            params['host_name'] = host_name
        if product:
            params['product'] = product
        if managing_server_id:
            params['managing_server_id'] = managing_server_id

        res = self._http_request('GET', url, headers=self._headers, params=params)

    def list_servers(self, entity_id, ip_address, mac_address, host_name, product, managing_server_id):
        url = '/API/ServerResource/ProductServers'
        self.create_jwt_token('GET', self._base_url + url)
        params = {}
        if entity_id:
            params['entity_id'] = entity_id
        if ip_address:
            params['ip_address'] = ip_address
        if mac_address:
            params['mac_address'] = mac_address
        if host_name:
            params['host_name'] = host_name
        if product:
            params['product'] = product
        if managing_server_id:
            params['managing_server_id'] = managing_server_id

        res = self._http_request('GET', url, headers=self._headers, params=params)


def create_live_investigation_from_registry_command(client, args):
    agent_guid = args.get('agent_guid')
    investigation_name = args.get('investigation_name')
    server_guid = args.get('server_guid')
    time_range = args.get('time_range')
    scan_schedule_id = args.get('scan_schedule_id')
    scan_schedule_guid = args.get('scan_schedule_guid')
    endpoint_url = args.get('endpoint_url')

    endpoint_name_filter = args.get('endpoint_name_filter')
    endpoint_type_filter = args.get('endpoint type_filter')  # TODO: create a drop down menu
    endpoint_ip_address_filter = args.get('endpoint_ip_address_filter')
    endpoint_operating_system_filter = args.get('endpoint_operating_system_filter')
    endpoint_user_name_filter = args.get('endpoint_user_name_filter')  # TODO: create a drop down menu

    registry_name = args.get('registry_name')
    registry_key = args.get('registry_key')
    match_option = args.get('match_option')
    registry_value = args.get('registry_value')


def create_live_investigation_from_file_command(client, args):
    agent_guid = args.get('agent_guid')
    investigation_name = args.get('investigation_name')
    server_guid = args.get('server_guid')
    time_range = args.get('time_range')
    scan_schedule_id = args.get('scan_schedule_id')
    scan_schedule_guid = args.get('scan_schedule_guid')
    endpoint_url = args.get('endpoint_url')

    endpoint_name_filter = args.get('endpoint_name_filter')
    endpoint_type_filter = args.get('endpoint type_filter')  # TODO: create a drop down menu
    endpoint_ip_address_filter = args.get('endpoint_ip_address_filter')
    endpoint_operating_system_filter = args.get('endpoint_operating_system_filter')  # TODO: create a drop down menu
    endpoint_user_name_filter = args.get('endpoint_user_name_filter')

    base64_encoded_content = args.get('base64_encoded_content')
    criteria_hash_id = args.get('criteria_hash_id')
    file_name = args.get('file_name')


def create_custom_live_investigation_command(client, args):
    agent_guid = args.get('agent_guid')
    investigation_name = args.get('investigation_name')
    server_guid = args.get('server_guid')
    time_range = args.get('time_range')
    scan_schedule_id = args.get('scan_schedule_id')
    scan_schedule_guid = args.get('scan_schedule_guid')
    endpoint_url = args.get('endpoint_url')

    endpoint_name_filter = args.get('endpoint_name_filter')  # TODO: create a drop down menu
    endpoint_type_filter = args.get('endpoint type_filter')
    endpoint_ip_address_filter = args.get('endpoint_ip_address_filter')
    endpoint_operating_system_filter = args.get('endpoint_operating_system_filter')  # TODO: create a drop down menu
    endpoint_user_name_filter = args.get('endpoint_user_name_filter')

    operator = args.get('operator')
    file_name_contains = args.get('file_name_contains')
    file_name_is = args.get('file_name_is')
    file_path_contains = args.get('file_path_contains')
    file_path_is = args.get('file_path_is')
    file_sha1 = args.get('file_sha1')
    file_md5 = args.get('file_md5')
    account_contains = args.get('account_contains')
    account_is = args.get('account_is')
    command_line_is = args.get('command_line_is')
    command_line_contains = args.get('command_line_contains')
    registry_key_is = args.get('registry_key_is')
    registry_key_contains = args.get('registry_key_contains')
    registry_name_contains = args.get('registry_name_contains')
    registry_name_is = args.get('registry_name_is')
    registry_data_contains = args.get('registry_data_contains')
    registry_data_is = args.get('registry_data_is')
    host_name_is = args.get('host_name_is')
    host_name_contains = args.get('host_name_contains')
    file_sha2 = args.get('file_sha2')


def create_scheduled_investigation_command(client, args):
    agent_guid = args.get('agent_guid')
    investigation_name = args.get('investigation_name')
    server_guid = args.get('server_guid')
    time_range = args.get('time_range')
    user_time_zone = args.get('user_time_zone')
    scan_type = args.get('scan_type')  # TODO: create a drop down menu

    endpoint_name_filter = args.get('endpoint_name_filter')  # TODO: create a drop down menu
    endpoint_type_filter = args.get('endpoint type_filter')
    endpoint_ip_address_filter = args.get('endpoint_ip_address_filter')
    endpoint_operating_system_filter = args.get('endpoint_operating_system_filter')  # TODO: create a drop down menu
    endpoint_user_name_filter = args.get('endpoint_user_name_filter')

    # TODO: add in every field description that one of this fields is mandatory
    end_date = args.get('end_date')
    repeat_type = args.get('repeat_type')
    repeat_value = args.get('repeat_value')
    start_date = args.get('start_date')

    base64_encoded_content = args.get('base64_encoded_content')
    criteria_hash_id = args.get('criteria_hash_id')
    file_name = args.get('file_name')


def create_historical_investigation_command(client, args):
    endpoint_url = args.get('endpoint_url')
    criteria_kvp = args.get('criteria_kvp')
    criteria_source = args.get('criteria_source')
    search_period = args.get('search_period')

    operator = args.get('operator')
    file_name_contains = args.get('file_name_contains')
    file_name_is = args.get('file_name_is')
    file_path_contains = args.get('file_path_contains')
    file_path_is = args.get('file_path_is')
    file_sha1 = args.get('file_sha1')
    file_md5 = args.get('file_md5')
    account_contains = args.get('account_contains')
    account_is = args.get('account_is')
    command_line_is = args.get('command_line_is')
    command_line_contains = args.get('command_line_contains')
    registry_key_is = args.get('registry_key_is')
    registry_key_contains = args.get('registry_key_contains')
    registry_name_contains = args.get('registry_name_contains')
    registry_name_is = args.get('registry_name_is')
    registry_data_contains = args.get('registry_data_contains')
    registry_data_is = args.get('registry_data_is')
    host_name_is = args.get('host_name_is')
    host_name_contains = args.get('host_name_contains')
    file_sha2 = args.get('file_sha2')


def list_servers_command(client, args):
    entity_id = args.get('entity_id')
    ip_address = args.get('ip')
    mac_address = args.get('mac_address')
    host_name = args.get('host_name')
    product = args.get('product')
    managing_server_id = args.get('managing_server_id')

    res = client.list_servers(entity_id, ip_address, mac_address, host_name, product, managing_server_id)


def list_security_agents_command(client, args):
    entity_id = args.get('entity_id')
    ip_address = args.get('ip')
    mac_address = args.get('mac_address')
    host_name = args.get('host_name')
    product = args.get('product')
    managing_server_id = args.get('managing_server_id')

    res = client.list_security_agents(entity_id, ip_address, mac_address, host_name, product, managing_server_id)


def test_module(client):
    """
    Returning 'ok' indicates that the integration works like it is supposed to. Connection to the service is successful.

    Args:
        client: HelloWorld client

    Returns:
        'ok' if test passed, anything else will fail the test.
    """

    result = client.create_jwt_token('GET', client._base_url, 'application/json', '')
    if isinstance(result, (str,)):
        return 'ok'


def fetch_incidents(client, last_run, first_fetch_time):
    """
    This function will execute each interval (default is 1 minute).

    Args:
        client (Client): HelloWorld client
        last_run (dateparser.time): The greatest incident created_time we fetched from last fetch
        first_fetch_time (dateparser.time): If last_run is None then fetch all incidents since first_fetch_time

    Returns:
        next_run: This will be last_run in the next fetch-incidents
        incidents: Incidents that will be created in Demisto
    """
    # Get the last fetch time, if exists
    last_fetch = last_run.get('last_fetch')

    # Handle first time fetch
    if last_fetch is None:
        last_fetch, _ = dateparser.parse(first_fetch_time)
    else:
        last_fetch = dateparser.parse(last_fetch)

    latest_created_time = last_fetch
    incidents = []
    items = client.list_incidents()
    for item in items:
        incident_created_time = dateparser.parse(item['created_time'])
        incident = {
            'name': item['description'],
            'occurred': incident_created_time.strftime('%Y-%m-%dT%H:%M:%SZ'),
            'rawJSON': json.dumps(item)
        }

        incidents.append(incident)

        # Update last run and add incident if the incident is newer than last fetch
        if incident_created_time > latest_created_time:
            latest_created_time = incident_created_time

    next_run = {'last_fetch': latest_created_time.strftime(DATE_FORMAT)}
    return next_run, incidents


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    base_url = demisto.params().get('url')
    app_id = demisto.params().get('app_id')
    api_key = demisto.params().get('api_key')

    verify_certificate = not demisto.params().get('insecure', False)

    # How much time before the first fetch to retrieve incidents
    first_fetch_time = demisto.params().get('fetch_time', '3 days').strip()

    proxy = demisto.params().get('proxy', False)

    LOG(f'Command being called is {demisto.command()}')
    try:
        client = Client(
            base_url=base_url,
            app_id=app_id,
            api_key=api_key,
            verify=verify_certificate,
            proxy=proxy)

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            demisto.results(result)

        elif demisto.command() == 'fetch-incidents':
            # Set and define the fetch incidents command to run after activated via integration settings.
            next_run, incidents = fetch_incidents(
                client=client,
                last_run=demisto.getLastRun(),
                first_fetch_time=first_fetch_time)

            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

        elif demisto.command() == 'trendmicro-apex-managed-servers-list':
            return_outputs(*list_servers_command(client, demisto.args()))
        elif demisto.command() == 'trendmicro-apex-security-agents-list':
            return_outputs(*list_security_agents_command(client, demisto.args()))
        elif demisto.command() == 'trendmicro-apex-create-live-investigation-from-file':
            return_outputs(*create_live_investigation_from_file_command(client, demisto.args()))
        elif demisto.command() == 'trendmicro-apex-create-live-investigation-from-registry':
            return_outputs(*create_live_investigation_from_registry_command(client, demisto.args()))
        elif demisto.command() == 'trendmicro-apex-create-custom-live-investigation':
            return_outputs(*create_custom_live_investigation_command(client, demisto.args()))
        elif demisto.command() == 'trendmicro-apex-create-historical-investigation':
            return_outputs(*create_historical_investigation_command(client, demisto.args()))
        elif demisto.command() == 'trendmicro-apex-create-scheduled-investigation':
            return_outputs(*create_scheduled_investigation_command(client, demisto.args()))
        # elif demisto.command() == 'trendmicro-logs-list':
        #     return_outputs(*list_logs_command(client, demisto.args()))
        # elif demisto.command() == 'trendmicro-apex-udso-add':
        #     return_outputs(*add_udso_command(client, demisto.args()))
        # elif demisto.command() == 'trendmicro-apex-udso-file-add':
        #     return_outputs(*add_udso_file_command(client, demisto.args()))
        # elif demisto.command() == 'trendmicro-apex-endpoint-sensors-list':
        #     return_outputs(*list_sensors_command(client, demisto.args()))
        # elif demisto.command() == 'trendmicro-apex-process-terminate':
        #     return_outputs(*process_terminate_command(client, demisto.args()))
        # elif demisto.command() == 'trendmicro-apex-root-cause-investigation-get-by-task-id':
        #     return_outputs(*get_root_cause_investigation_command(client, demisto.args()))
        # elif demisto.command() == 'trendmicro-apex-investigation-result-list-by-status':
        #     return_outputs(*get_investigation_results_list_by_status_command(client, demisto.args()))
        # elif demisto.command() == 'trendmicro-apex-investigation-result-list':
        #     return_outputs(*get_investigation_results_list_command(client, demisto.args()))

    # Log exceptions
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
