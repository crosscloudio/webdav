"""Tests against the flask implementation of crosscloud webdav endpoints."""
import pprint
import jars
import datetime
import json
from io import BytesIO
from unittest import mock
from urllib.parse import quote, unquote

import requests_mock
import pytest

from webdav.models import User, StorageConfiguration
from webdav import utils
from .conftest import user_set

@pytest.fixture
def example_user(user_configuration_with_providers):
    user = User.using(user_configuration_with_providers)
    assert len(user.configured_storage_providers) > 0
    return user


@pytest.fixture
def fake_storage():
    fs = mock.Mock(spec=jars.BasicStorage)
    fs.get_tree_children.return_value = [
            ('Ordner', {'is_dir': True,
                        'size': 0,
                        'modified_date': datetime.datetime(2017, 5, 17, 13, 7, 54),
                        'version_id': 'is_dir',
                        'shared': False}),
            ('Datei.txt',  {'is_dir': False,
                            'size': 12,
                            'modified_date': datetime.datetime(2017, 5, 17, 13, 7, 54),
                            'version_id': '0x1234',
                            'shared': False}),
            ('Спасибо.txt', {'is_dir': False,
                             'size': 42,
                             'modified_date': datetime.datetime(2017, 5, 17, 13, 7, 54),
                             'version_id': '0x4321',
                             'shared': False}),
            ('обезьяна.txt', {'is_dir': False,
                              'size': 42,
                              'modified_date': datetime.datetime(2017, 5, 17, 13, 7, 54),
                              'version_id': '0x4321',
                              'shared': False}),
            ('обезьяна', {'is_dir': True,
                          'size': 0,
                          'modified_date': datetime.datetime(2017, 5, 17, 13, 7, 54),
                          'version_id': 'is_dir',
                          'shared': False}),
    ]
    fs.make_dir.return_value = 'is_dir'
    fs.storage_id = 'fakestorage'
    return fs


@pytest.mark.parametrize("has_storage", [True, False])
@pytest.mark.parametrize("allowed_method", ['GET', 'PUT', 'DELETE', 'MKCOL', 'MOVE'])
def test_with_prepared_storage_side_effects(allowed_method, has_storage, test_application, example_user, mocker):
    """Ensure that with_prepared_storage properly handles side effects."""
    fetch_configuration_mock = mock.Mock()
    extract_token_mock = mock.Mock()
    extract_token_mock.return_value = "test_token"
    mocker.patch("webdav.utils.extract_authentication_token", new=extract_token_mock)
    mocker.patch("webdav.utils.fetch_user_configuration", new=fetch_configuration_mock)
    mocker.patch("webdav.models.User.using", return_value=example_user)
    mocker.patch("webdav.models.User.has_storage", return_value=has_storage)

    test_client = test_application.test_client()

    with test_application.test_request_context():
        response = test_client.open('/unknown_storage/',
                                    method=allowed_method,
                                    headers={'Authorization': "Bearer token"})

        assert extract_token_mock.called
        fetch_configuration_mock.assert_called_once_with(extract_token_mock.return_value)
        assert response.status_code == 404


@pytest.mark.parametrize("method", ['GET', 'PUT', 'DELETE', 'MKCOL', 'MOVE'])
def test_ensure_current_user_no_token(method, test_application, example_user, mocker):
    """Ensure that with_prepared_storage properly handles side effects."""
    fetch_configuration_mock = mock.Mock()
    extract_token_mock = mock.Mock()
    extract_token_mock.return_value = None
    mocker.patch("webdav.utils.extract_authentication_token", new=extract_token_mock)
    mocker.patch("webdav.utils.fetch_user_configuration", new=fetch_configuration_mock)

    test_client = test_application.test_client()

    with test_application.test_request_context():
        response = test_client.open('/',
                                    method=method,
                                    headers={'Authorization': "Bearer token"})

        # Token is None or invalid and we should return 401.
        fetch_configuration_mock.assert_not_called()
        assert response.status_code == 401


@pytest.mark.parametrize("method", ['GET', 'PUT', 'DELETE', 'MKCOL', 'MOVE'])
def test_ensure_current_user_no_configuration(method, test_application, example_user, mocker):
    """Ensure that with_prepared_storage properly handles side effects."""
    fetch_configuration_mock = mock.Mock()
    fetch_configuration_mock.return_value = None
    user_mock = mock.Mock()
    extract_token_mock = mock.Mock()
    extract_token_mock.return_value = "test_token"
    mocker.patch("webdav.utils.extract_authentication_token", new=extract_token_mock)
    mocker.patch("webdav.utils.fetch_user_configuration", new=fetch_configuration_mock)
    mocker.patch("webdav.models.User.using", new=user_mock)

    test_client = test_application.test_client()

    with test_application.test_request_context():
        response = test_client.open('/',
                                    method=method,
                                    headers={'Authorization': "Bearer token"})

        user_mock.assert_not_called()
        assert response.status_code == 401


def test_get_provider_list(test_client, example_user, mocker):

    fetch_configuration_mock = mock.Mock()
    extract_token_mock = mock.Mock()
    extract_token_mock.return_value = "test_token"
    mocker.patch("webdav.utils.extract_authentication_token", new=extract_token_mock)
    mocker.patch("webdav.utils.fetch_user_configuration", new=fetch_configuration_mock)
    mocker.patch("webdav.models.User.using", return_value=example_user)

    response = test_client.open('/',
                                method='PROPFIND',
                                headers={'Authorization': "Bearer token"})

    assert extract_token_mock.called
    fetch_configuration_mock.assert_called_once_with(extract_token_mock.return_value)

    assert response.status_code == 200
    assert b'Dropbox 1' in response.data
    assert b'dropbox.1' in response.data


def test_get_resource_properties(test_client, example_user, fake_storage, mocker):

    fetch_configuration_mock = mock.Mock()
    extract_token_mock = mock.Mock()
    extract_token_mock.return_value = "test_token"
    mocker.patch("webdav.utils.extract_authentication_token", new=extract_token_mock)
    mocker.patch("webdav.utils.fetch_user_configuration", new=fetch_configuration_mock)
    mocker.patch("webdav.models.User.using", return_value=example_user)
    mocker.patch("webdav.utils.prepare_storage_provider", return_value=fake_storage)

    assert example_user.has_storage("dropbox.1234")
    response = test_client.open('/dropbox.1234',
                                method='PROPFIND',
                                headers={'Authorization': "Bearer token"})

    assert extract_token_mock.called
    fetch_configuration_mock.assert_called_once_with(extract_token_mock.return_value)

    # example_user.get_storage.assert_called_once_with("dropbox.1234")
    fake_storage.get_tree_children.assert_called_once_with([])


    assert response.status_code == 200
    assert b'Ordner' in response.data
    assert 'обезьяна'.encode('utf-8') in response.data


def test_create_folder(test_client, example_user, fake_storage, mocker):

    fetch_configuration_mock = mock.Mock()
    extract_token_mock = mock.Mock()
    extract_token_mock.return_value = "test_token"
    mocker.patch("webdav.utils.extract_authentication_token", new=extract_token_mock)
    mocker.patch("webdav.utils.fetch_user_configuration", new=fetch_configuration_mock)
    mocker.patch("webdav.models.User.using", return_value=example_user)
    mocker.patch("webdav.utils.prepare_storage_provider", return_value=fake_storage)
    assert example_user.has_storage("dropbox.1234")

    response = test_client.open('/dropbox.1234/doggy',
                                method='MKCOL',
                                data=BytesIO(b"123456"),
                                headers={'Authorization': "Bearer token"})

    assert extract_token_mock.called
    fetch_configuration_mock.assert_called_once_with(extract_token_mock.return_value)

    # example_user.get_storage.assert_called_once_with("dropbox.1234")
    fake_storage.make_dir.assert_called_once_with(path=['doggy'])
    assert response.status_code == 201


@pytest.mark.parametrize("side_effect, expected_status_code", [
    (jars.CurrentlyNotPossibleError(None), 503),
    (jars.UnavailableError(None, None), 500),
    (jars.AuthenticationError(None), 503),
    (jars.SevereError(None), 503),
])
def test_create_folder_side_effects(side_effect, expected_status_code, test_application, example_user, fake_storage, mocker):

    fetch_configuration_mock = mock.Mock()
    extract_token_mock = mock.Mock()
    extract_token_mock.return_value = "test_token"
    mocker.patch("webdav.utils.extract_authentication_token", new=extract_token_mock)
    mocker.patch("webdav.utils.fetch_user_configuration", new=fetch_configuration_mock)
    mocker.patch("webdav.models.User.using", return_value=example_user)
    mocker.patch("webdav.utils.prepare_storage_provider", return_value=fake_storage)
    assert example_user.has_storage("dropbox.1234")

    make_dir_mock = mock.Mock()
    make_dir_mock.side_effect = side_effect
    fake_storage.make_dir = make_dir_mock

    with test_application.test_request_context():
        response = test_application.test_client().open('/dropbox.1234/doggy',
                                    method='MKCOL',
                                    data=BytesIO(b"123456"),
                                    headers={'Authorization': "Bearer token"})
        make_dir_mock.assert_called_once_with(path=['doggy'])
        assert response.status_code == expected_status_code


def test_upload_file(test_client, example_user, fake_storage, mocker):

    fetch_configuration_mock = mock.Mock()
    extract_token_mock = mock.Mock()
    extract_token_mock.return_value = "test_token"
    mocker.patch("webdav.utils.extract_authentication_token", new=extract_token_mock)
    mocker.patch("webdav.utils.fetch_user_configuration", new=fetch_configuration_mock)
    mocker.patch("webdav.models.User.using", return_value=example_user)
    mocker.patch("webdav.utils.prepare_storage_provider", return_value=fake_storage)
    assert example_user.has_storage("dropbox.1234")

    from io import BytesIO
    buffer = BytesIO(b"123456")
    response = test_client.open('/dropbox.1234/doggy.txt',
                                method='PUT',
                                data=buffer,
                                headers={'Authorization': "Bearer token"})

    assert extract_token_mock.called
    fetch_configuration_mock.assert_called_once_with(extract_token_mock.return_value)

    # example_user.get_storage.assert_called_once_with("dropbox.1234")
    fake_storage.write.assert_called_once_with(path=['doggy.txt'],
                                               file_obj=mock.ANY,
                                               size=6,
                                               original_version_id=None)
    assert response.status_code == 201


def test_move_resource(test_client, example_user, fake_storage, mocker):

    fetch_configuration_mock = mock.Mock()
    extract_token_mock = mock.Mock()
    extract_token_mock.return_value = "test_token"
    mocker.patch("webdav.utils.extract_authentication_token", new=extract_token_mock)
    mocker.patch("webdav.utils.fetch_user_configuration", new=fetch_configuration_mock)
    mocker.patch("webdav.models.User.using", return_value=example_user)
    mocker.patch("webdav.utils.prepare_storage_provider", return_value=fake_storage)
    assert example_user.has_storage("dropbox.1234")

    response = test_client.open('/dropbox.1234/file.txt',
                                method='MOVE',
                                headers={'Authorization': "Bearer token",
                                         'If-Match': 'etag',
                                         'Destination': '/dropbox.1234/renamed.txt'})

    assert extract_token_mock.called
    fetch_configuration_mock.assert_called_once_with(extract_token_mock.return_value)

    # example_user.get_storage.assert_called_once_with("dropbox.1234")
    fake_storage.move.assert_called_once_with(source=['file.txt'],
                                              target=['renamed.txt'],
                                              expected_source_vid='etag',
                                              expected_target_vid=None)

    assert response.status_code == 204


def test_remove_resource(test_client, example_user, fake_storage, mocker):

    # FIXME: Parameterize and ensure exception handling is done properly.
    fetch_configuration_mock = mock.Mock()
    extract_token_mock = mock.Mock()
    extract_token_mock.return_value = "test_token"
    mocker.patch("webdav.utils.extract_authentication_token", new=extract_token_mock)
    mocker.patch("webdav.utils.fetch_user_configuration", new=fetch_configuration_mock)
    mocker.patch("webdav.models.User.using", return_value=example_user)
    mocker.patch("webdav.utils.prepare_storage_provider", return_value=fake_storage)

    assert example_user.has_storage("dropbox.1234")
    response = test_client.open('/dropbox.1234/A/B/C',
                                method='DELETE',
                                headers={'Authorization': "Bearer token",
                                         'If-Match': 'is_dir'})

    assert extract_token_mock.called
    fetch_configuration_mock.assert_called_once_with(extract_token_mock.return_value)

    # example_user.get_storage.assert_called_once_with("dropbox.1234")
    fake_storage.delete.assert_called_once_with(['A', 'B', 'C'], original_version_id='is_dir')
    assert response.status_code == 204


@pytest.mark.parametrize('request_uri, expected_status_code', [
    ("", 405),
    ("/", 405),
    ("/dropbox.1234/", 404), # Not mapped. Should return 404
    ("/dropbox.1234", 405),
    ("/dropbox.1234/обезьяна", 405),
    ("/dropbox.1234/обезьяна/Ordner", 405),
    ("/dropbox.1234/Datei.txt", 200),
    ("/dropbox.1234/Ordner/Datei.txt", 200),
    ("/dropbox.1234/Ordner/does.not.exist.txt", 404),
    ("/dropbox.1234/does.not.exist", 404) # Does not exist. Should return 404
])
def test_get_resource(request_uri, expected_status_code, test_client, example_user, fake_storage, mocker):
    """Ensure that we are only able to download files and not folders."""
    fetch_configuration_mock = mock.Mock()
    extract_token_mock = mock.Mock()
    extract_token_mock.return_value = "test_token"
    mocker.patch("webdav.utils.extract_authentication_token", new=extract_token_mock)
    mocker.patch("webdav.utils.fetch_user_configuration", new=fetch_configuration_mock)
    mocker.patch("webdav.models.User.using", return_value=example_user)
    mocker.patch("webdav.utils.prepare_storage_provider", return_value=fake_storage)

    activity_logger = mock.Mock()
    mocker.patch("webdav.models.ActivityLogger", return_value=activity_logger)

    assert example_user.has_storage("dropbox.1234")
    response = test_client.open(request_uri,
                                method='GET',
                                headers={'Authorization': "Bearer token",
                                         'If-Match': 'version0'})

    assert extract_token_mock.called
    fetch_configuration_mock.assert_called_once_with(extract_token_mock.return_value)

    # Ensure that we actually get the status code we expect and check that
    # we handle errors (>= 400) properly.
    assert response.status_code == expected_status_code

    if expected_status_code >= 400:
        assert not fake_storage.open_read.called

    if expected_status_code == 200:
        crosscloud_path = utils.as_crosscloud_path(request_uri)[1:]
        fake_storage.open_read.assert_called_once_with(path=crosscloud_path,
                                                       expected_version_id=mock.ANY)


METHODS = [('GET', 'DownloadSyncTask'),
           ('PUT', 'UploadSyncTask'),
           ('DELETE', 'DeleteSyncTask'),
           ('MKCOL', 'CreateDirSyncTask')]
@pytest.mark.parametrize('path', [
    '/dropbox.1234/Datei.txt',
    quote('/dropbox.1234/Ordner/обезьяна.txt'),
    quote('/dropbox.1234/обезьяна/Спасибо.txt'),
])
@pytest.mark.parametrize('method, task_type', METHODS)
def test_report_single_activity_to_backend(method, task_type, path, test_application, mocker,
                                           example_user, fake_storage):
    """When method is called on the app, the admin console must be informed."""

    test_client = test_application.test_client()

    # Set the proper fake storage id to match the incoming paths.
    fake_storage.storage_id = 'dropbox.1234'

    # FIXME: Parameterize and ensure exception handling is done properly.
    fetch_configuration_mock = mock.Mock()
    extract_token_mock = mock.Mock()
    extract_token_mock.return_value = "test_token"
    mocker.patch("webdav.utils.extract_authentication_token", new=extract_token_mock)
    mocker.patch("webdav.utils.fetch_user_configuration", new=fetch_configuration_mock)
    mocker.patch("webdav.models.User.using", return_value=example_user)
    mocker.patch("webdav.utils.prepare_storage_provider", return_value=fake_storage)

    activity_logger = mock.Mock()
    mocker.patch("webdav.models.ActivityLogger", return_value=activity_logger)


    headers = {'Authorization': "Bearer token", 'If-Match': 'version0'}

    with test_application.app_context():
        response = test_client.open(path,
                                    method=method,
                                    headers=headers)
        crosscloud_path = utils.as_crosscloud_path(path)
        assert response.status_code < 400
        activity_logger.send.assert_called_once_with(task_type=task_type,
                                                     timestamp=mock.ANY,
                                                     path=crosscloud_path[1:],
                                                     mime_type=utils.guess_mime_type(path),
                                                     encrypted=False,
                                                     storage_id=fake_storage.storage_id,
                                                     bytes_transferred=mock.ANY)


@pytest.mark.parametrize('storage_id, source_path, target_path', [
    ('dropbox.1234', '/dropbox.1234/A/B/file.txt', '/dropbox.1234/A/B/renamed.txt'),
    ('dropbox.1234', '/dropbox.1234/A/B/file.txt', '/dropbox.1234/A/B/file.txt'),
    ('dropbox.1234', quote('/dropbox.1234/Спасибо.txt'), quote('/dropbox.1234/Спасибо_renamed.txt')),
    ('dropbox.1234', quote('/dropbox.1234/folder/Спасибо.txt'), quote('/dropbox.1234/Спасибо.txt')),
    ('dropbox.1234', quote('/dropbox.1234/Спасибо/Спасибо.txt'), quote('/dropbox.1234/Спасибо/Спасибо_renamed.txt')),
])
def test_report_move_activity_to_backend(storage_id, source_path, target_path, test_application, mocker, example_user, fake_storage):
    """When method is called on the app, the admin console must be informed."""
    test_client = test_application.test_client()

    # Set the proper fake storage id to match the incoming paths.
    fake_storage.storage_id = storage_id

    activity_logger = mock.Mock()
    fetch_configuration_mock = mock.Mock()
    extract_token_mock = mock.Mock()
    extract_token_mock.return_value = "test_token"
    mocker.patch("webdav.utils.extract_authentication_token", new=extract_token_mock)
    mocker.patch("webdav.utils.fetch_user_configuration", new=fetch_configuration_mock)
    mocker.patch("webdav.models.User.using", return_value=example_user)
    mocker.patch("webdav.utils.prepare_storage_provider", return_value=fake_storage)
    mocker.patch("webdav.models.ActivityLogger", return_value=activity_logger)

    with test_application.app_context():
        response = test_client.open(source_path,
                                    method='MOVE',
                                    headers = {'Authorization': "Bearer token",
                                               'If-Match': 'version0',
                                               'Destination': target_path})

        cc_source_path = utils.as_crosscloud_path(source_path)
        cc_target_path = utils.as_crosscloud_path(target_path)

        # Make sure 'storage_id' is not part of the assertions below.
        assert storage_id not in cc_source_path[1:]
        assert storage_id not in cc_target_path[1:]

        # Ensure that we did not change 'guessed' mime types because of the rename.
        assert utils.guess_mime_type(source_path) == utils.guess_mime_type(target_path)

        # Since 'move' events are currently split into a sepearate "delete" and "upload" task/event.
        # We mirror this behaviour on the gateway to reduce confusion.
        expected_calls = [mock.call(task_type='UploadSyncTask',
                                    timestamp=mock.ANY,
                                    path=cc_target_path[1:],
                                    mime_type=utils.guess_mime_type(target_path),
                                    encrypted=False,
                                    storage_id=fake_storage.storage_id,
                                    bytes_transferred=0),
                          mock.call(task_type='DeleteSyncTask',
                                    timestamp=mock.ANY,
                                    path=cc_source_path[1:],
                                    mime_type=utils.guess_mime_type(source_path),
                                    encrypted=False,
                                    storage_id=fake_storage.storage_id,
                                    bytes_transferred=0)]
        activity_logger.send.assert_has_calls(expected_calls, any_order=False)


def test_token_writer_sends_token_to_backend(test_application, user_configuration_with_providers, mocker):
    """Ensure that the updated tokens are sent to the backend."""

    my_user = User.using(user_configuration_with_providers)
    # This currently needs to be done manually as it is not part of the "using" (yet).
    my_user.authentication_token = "valid_auth_token"

    # FIXME: Remove this when update_storage becomes obsolete!
    mocker.patch("webdav.utils.update_storage", new=mock.Mock())

    with user_set(test_application, my_user):
        with test_application.test_request_context():
            storage = utils.prepare_storage_provider(
                StorageConfiguration(
                  storage_id="gdrive_1499686470.097055",
                  authentication_data="\"old_authentication_data\"",
                  display_name="Google Drive 1",
                  type="gdrive")
            )
            assert storage.storage_display_name == 'Google Drive 1'

            # Mock the call to the backend.
            with requests_mock.Mocker() as rmock:
                rmock.register_uri('POST', 'http://api:3030/graphql', json={})
                assert storage.oauth_session.token_updater("test") == json.dumps('test')

                # Ensure the mock was called and the last request is also present.
                assert rmock.called
                assert rmock.last_request

                # Extract the mutation variables from the last request to the rmock.
                request_variables = json.loads(rmock.last_request._request.body.decode('utf-8')).get("variables")
                assert request_variables is not None

                # Ensure the variables passed to the mutation are correct.
                assert request_variables.get('csp_id', storage.storage_id)
                assert request_variables.get('old', storage.oauth_session.token)
                assert request_variables.get('new', "test")


def test_response_contains_server_version_string(test_application, mocker):
    """Ensure that the updated tokens are sent to the backend."""

    mocker.patch("webdav.__version__", new="1.2.3")

    with test_application.test_request_context():
        resp = test_application.test_client().get("/")
        # This is necessary for @after_request functions to be called.
        resp = test_application.process_response(resp)

        assert 'SERVER' in resp.headers
        assert resp.headers['SERVER'] == "webdav/1.2.3"
