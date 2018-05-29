import pytest
from flask import appcontext_pushed, g
from contextlib import contextmanager


@contextmanager
def user_set(app, user):
    """Set the current_user for the given application."""
    def handler(sender, **kwargs):
        g.current_user = user
    with appcontext_pushed.connected_to(handler, app):
        yield


def sample_user_graphql_configuration():
    return """{
  "data": {
    "currentUser": {
      "id": "b3572ed6-a0f0-40ed-9c9b-c51745e79a22",
      "email": "thomas@crosscloud.me",
      "is_enabled": true,
      "roles": [
        "user",
        "administrator"
      ],
      "csps": [
        {
          "csp_id": "dropbox_1498551067.4982216",
          "display_name": "Dropbox 1",
          "authentication_data": "{\"account_id\": \"dbid:AABHJTWSC00zK2URZEpz7CXWKy-aAFxgRjE\", \"token_type\": \"bearer\", \"access_token\": \"S3Ul8lwCajAAAAAAAAAFDbqJLIysR2Qggn_nleBzh6JiqHU-ou8cXZ28tq8fyV_z\", \"uid\": \"409018877\"}",
          "type": "dropbox"
        }
      ],
      "organization": {
        "display_name": "CrossCloud"
      }
    }
  }
}
"""


@pytest.fixture
def test_application():
    from config import available_settings
    from webdav import app
    app.config.from_object(available_settings.get('test'))
    return app


@pytest.fixture()
def test_client(test_application):
    return test_application.test_client()


@pytest.fixture
def user_configuration_with_providers():
    return {
        'id': '11-22-33',
        'email': 'user@crosscloud.dev',
        'is_enabled': True,
        'roles': ['user', 'administrator'],
        'csps': [{'csp_id': 'dropbox.1234',
                  'display_name': 'Dropbox 1',
                  'authentication_data': '{"account_id": "dbid:user", "access_token": "fake"}',
                  'type': 'dropbox'}],
        'organization': {'display_name': 'crosscloud'}
    }


@pytest.fixture
def user_configuration_empty_providers():
    return {
        'id': '11-22-33',
        'email': 'user@crosscloud.dev',
        'is_enabled': True,
        'roles': ['user', 'administrator'],
        'csps': [],
        'organization': {'display_name': 'crosscloud'}
    }
