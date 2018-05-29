import pprint
import json
import pytest
import jars
import jars.dropbox
import jars.webdav
import jars.owncloud
import jars.googledrive
# import jars.box
import jars.microsoft
from unittest import mock
from webdav.models import User
from webdav.models import StorageConfiguration
from .conftest import user_set


@pytest.fixture
def user_with_storage(user_configuration_with_providers):
    user = User.using(user_configuration_with_providers)
    return user


def test_user_using_empty_providers(user_configuration_empty_providers):
    """Ensure that an empty 'csps' list still creates a valid 'User' object."""
    user = User.using(user_configuration_empty_providers)
    assert user.id == '11-22-33'
    assert user.email == 'user@crosscloud.dev'
    assert user.is_enabled
    assert 'user' in user.roles
    assert 'administrator' in user.roles
    assert user.organization.display_name == "crosscloud"
    assert len(user.configured_storage_providers) == 0


@pytest.mark.parametrize('invalid_authentication_data', [None, False, '', '"', '[]'])
def test_user_using_with_invalid_attached_providers(invalid_authentication_data,
                                                    user_configuration_with_providers):
    """Ensure that a storage provider with invalid authentication data is not added."""

    # Set the test providers authentication data to an invalid value.
    config = user_configuration_with_providers['csps'][0]
    config['authentication_data'] = invalid_authentication_data

    # The User object should still be created with all relevant information.
    user = User.using(user_configuration_with_providers)
    assert user.id == '11-22-33'
    assert user.email == 'user@crosscloud.dev'
    assert user.is_enabled
    assert 'user' in user.roles
    assert 'administrator' in user.roles
    assert user.organization.display_name == "crosscloud"

    # However the list of configured/available storages should be empty.
    assert len(user.configured_storage_providers) == 0


@pytest.mark.parametrize('invalid_authentication_data', [None, False, '', '"', '[]'])
def test_user_using_one_invalid_attached_providers(invalid_authentication_data,
                                                    user_configuration_with_providers):
    """Ensure that a storage provider with invalid authentication data is not added."""

    # Add a storage provider with invalid authentication data.
    user_configuration_with_providers['csps'].append({
        'csp_id': 'invalid.1234',
        'display_name': 'Invalid Storage',
        'authentication_data': invalid_authentication_data,
        'type': 'invalid'
    })
    # The user configuration should now have both a valid and an invalid storage
    # configuration.
    assert len(user_configuration_with_providers.get('csps', [])) == 2

    # The User object be created with all relevant information.
    user = User.using(user_configuration_with_providers)
    assert user.id == '11-22-33'
    assert user.email == 'user@crosscloud.dev'
    assert user.is_enabled
    assert 'user' in user.roles
    assert 'administrator' in user.roles
    assert user.organization.display_name == "crosscloud"

    # However the list of configured/available storages should not contain the
    # invalid storage account.
    assert len(user.configured_storage_providers) == 1
    assert 'invalid.1234' not in user.configured_storage_providers

def test_user_using(user_configuration_with_providers):

    user = User.using(user_configuration_with_providers)
    assert user.id == '11-22-33'
    assert user.email == 'user@crosscloud.dev'
    assert user.is_enabled
    assert 'user' in user.roles
    assert 'administrator' in user.roles
    assert user.organization.display_name == "crosscloud"

    assert len(user.configured_storage_providers) == 1
    assert 'dropbox.1234' in user.configured_storage_providers

    storage = user.configured_storage_providers['dropbox.1234']
    assert storage.storage_id == 'dropbox.1234'
    assert storage.display_name == "Dropbox 1"
    assert storage.type == 'dropbox'
    assert storage.authentication_data is not None
    assert isinstance(json.loads(storage.authentication_data), dict)


@pytest.mark.parametrize('storage_id, expected_value', [
    ("dropbox.1234", True),
    ("dropbox", False),
    ("Dropbox 1", False),
    ("unknown", False),
    (404, False),
    ("", False),
    (None, False),
])
def test_user_has_storage(storage_id, expected_value, user_with_storage):
    """Ensure that has_storage returns True iff the given storage_id is part of the
       current_user configuration."""

    current_user = user_with_storage
    pprint.pprint(current_user.configured_storage_providers)
    assert current_user.has_storage(storage_id) == expected_value

    current_user.configured_storage_providers = {}
    assert not current_user.has_storage(storage_id)


def test_user_get_storage_with_existing_storage(user_with_storage, mocker):
    """Ensure that using an existing storage id calls prepare_storage_provider."""
    current_user = user_with_storage

    prepare_storage_provider = mock.Mock()
    prepare_storage_provider.return_value = 0xC0FF3E

    mocker.patch("webdav.utils.prepare_storage_provider", new=prepare_storage_provider)
    storage = current_user.get_storage("dropbox.1234")
    assert prepare_storage_provider.called
    assert storage == 0xC0FF3E


def test_user_get_storage_with_non_existing_storage(user_with_storage, mocker):
    """Ensure that using a non-existing storage id does not trigger storage preparation."""
    current_user = user_with_storage

    prepare_storage_provider = mock.Mock()
    prepare_storage_provider.return_value = 0xC0FF3E

    mocker.patch("webdav.utils.prepare_storage_provider", new=prepare_storage_provider)
    storage = current_user.get_storage("does.not.exist")
    prepare_storage_provider.assert_not_called()
    assert storage is None


@pytest.mark.parametrize('configuration, cls_name', [
    (StorageConfiguration("_", "_", "dropbox", '{"u":"","p":""}'), "Dropbox"),
    (StorageConfiguration("_", "_", "gdrive", '{"u":"","p":""}'), "GoogleDrive"),
])
def test_get_supported_storage(configuration, cls_name,
                               user_configuration_empty_providers, test_application,
                               mocker):

    # this patch can be removed once ~jars#15 has been resolved.
    mocker.patch('webdav.utils.update_storage')


    # Prepare empty user
    current_user = User.using(user_configuration_empty_providers)
    current_user.authentication_token = 'test'

    assert len(current_user.configured_storage_providers) == 0
    current_user.configured_storage_providers[configuration.storage_id] = configuration
    assert len(current_user.configured_storage_providers) == 1

    with user_set(test_application, current_user):
        with test_application.app_context():
            storage = current_user.get_storage(configuration.storage_id)
            assert isinstance(storage, jars.BasicStorage)
            assert storage.__class__.__name__ == cls_name
            assert storage.storage_id == configuration.storage_id
            assert storage.storage_display_name == configuration.display_name
            assert storage.storage_name == configuration.type


@pytest.mark.parametrize('configuration, expected_storage_value', [
    (StorageConfiguration("_", "_", "icloud", '{"u":"","p":""}'), None)
])
def test_get_storage(configuration, expected_storage_value, user_configuration_empty_providers, test_application):

    # Prepare empty user
    current_user = User.using(user_configuration_empty_providers)
    assert len(current_user.configured_storage_providers) == 0
    current_user.configured_storage_providers[configuration.storage_id] = configuration
    assert len(current_user.configured_storage_providers) == 1

    with test_application.app_context():
        storage = current_user.get_storage(configuration.storage_id)
        assert storage is None
