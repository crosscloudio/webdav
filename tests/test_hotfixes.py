"""Contains tests for temporary workaround and hotfixes."""

from unittest import mock
from webdav.utils import update_storage


def test_workaround_call_update_on_gdrive():
    """The current google drive implementation (jars-1.2.6) relies on the '_id' field to be present
       which for some reason does not seem to be present when calling the /drive/list endpoint directly."""

    storage = mock.Mock()
    storage.storage_name = 'gdrive'
    update_storage(storage)
    assert storage.update.called

    storage.reset_mock()
    storage.storage_name = 'dropbox'
    update_storage(storage)
    assert not storage.update.called

