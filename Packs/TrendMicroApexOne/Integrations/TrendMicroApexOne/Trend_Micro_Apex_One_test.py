import json
import pytest

BASE_URL = 'http://test.com'


def load_test_data(json_path):
    with open(json_path) as f:
        return json.load(f)


def test_create_checksum(requests_mock):
    """
    Given:
        - Request method, headers and body.
    When
        - Every time a request is being performed.
    Then
        - A checksum value is being calculated and passes as a field in a JWT token.
    """
    from Trend_Micro_Apex_One import Client
    client = Client(BASE_URL, 'app_id', 'api_key', False, False)
    res = client.create_checksum('GET', BASE_URL, '', '')
    assert type(res) == str


def test_create_jwt_token(requests_mock):
    """
    Given:
        - http_method, api_path, headers, request_body, iat=time.time(), algorithm='HS256',
                           version='V1'
    When
        - Every time a request is being performed.
    Then
        - Creates a JWT token
    """
    # TODO: add more tests for this function
    from Trend_Micro_Apex_One import Client
    client = Client(BASE_URL, 'app_id', 'api_key', False, False)
    res = client.create_jwt_token('GET', BASE_URL, '', "{'body_key': 'body_value'}")
    assert type(res) == str
