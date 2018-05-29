import jars
import logging
import requests
from collections import namedtuple
import webdav.utils

from webdav import app
logger = app.logger

StorageConfiguration = namedtuple('StorageConfiguration', field_names="storage_id, display_name, type, authentication_data")

Resource = namedtuple("Resource", field_names="is_dir,version_id,content_type,content_length,display_name,href")

Organization = namedtuple('Organization', field_names="display_name")

class DummyEventSink:

    def __init__(self, storage_id):
        self.storage_id = storage_id

    def storage_create(self, *args, **kwargs):
        logger.info("'CREATE' event on storage '%s'.", self.storage_id)

    def storage_modify(self, *args, **kwargs):
        logger.info("'MODIFY' event on storage '%s'.", self.storage_id)

    def storage_move(self, *args, **kwargs):
        logger.info("'MOVE' event on storage '%s'.", self.storage_id)

    def storage_delete(self, *args, **kwargs):
        logger.info("'DELETE' event on storage '%s'.", self.storage_id)


class ActivityLogger:
    """Helper class to send events belonging to a certain user."""

    def __init__(self, user):
        self.authentication_token = user.authentication_token

    def send(self, *args, **kwargs):
        """Send event using the current_user's attached authentication token."""

        if not self.authentication_token:
            logger.error("Unable to store activity without token present!", exc_info=True)
            return

        logger.debug("Preparing event data.")
        event_data = {
            'path': kwargs.get('path'),
            'type': kwargs.get('task_type'),
            'status': 'success', # FIXME:
            'mime_type': kwargs.get('mime_type'),
            'timestamp': kwargs.get('timestamp'),
            'encrypted': kwargs.get('encrypted'),
            'bytes_transferred': kwargs.get('bytes_transferred'),
            'storage_id': kwargs.get('storage_id'),
        }

        if not webdav.utils.send_activity_log(self.authentication_token, event_data):
            logger.error("Could not store event in activity log!", exc_info=True)
            return False

        logger.info("Successfully stored event with backend!")
        return True


class User:

    def __init__(self):
        self.configured_storage_providers = {}

    @classmethod
    def using(cls, configuration):

        user = User()
        user.id = configuration['id']
        user.email = configuration['email']
        user.is_enabled = configuration['is_enabled']
        user.roles = configuration['roles']
        user.organization = Organization(display_name=configuration['organization']['display_name'])

        logger.info("Adding configured storage providers.")
        for item in configuration.get('csps',[]):
            storage = StorageConfiguration(storage_id=item['csp_id'],
                                           display_name=item['display_name'],
                                           type=item['type'],
                                           authentication_data=item['authentication_data'])

            # Some accounts stored with the admin console might not have authentication data
            # attached. Those accounts should be silently ignored and will not be listed in
            # the mobile application.
            if not webdav.utils.is_valid_authentication_data(storage.authentication_data):
                logger.info("Configuration for '%s' contained invalid authentication data",
                            storage.storage_id)
                continue

            user.configured_storage_providers[storage.storage_id] = storage
            logger.info("Added configuration for type '%s'", storage.type)

        logger.info("Added %d configured storage providers.", len(user.configured_storage_providers))
        return user


    def has_storage(self, storage_id):
        """Return True if a storage with the given storage_id is present."""
        logger.info("Checking for '%s' in available user storages.", storage_id)
        return storage_id in self.configured_storage_providers


    def get_storage(self, storage_id):
        """Get ready-to-use jars Storage class using the stored configuration.

        :param storage_id: the 'csp_id' of the remote storage to set up.
        :type storage_id: str
        :return:
        """
        if not self.has_storage(storage_id):
            logger.warning("Storage '%s' not found in current user", storage_id)
            return None

        configuration = self.configured_storage_providers.get(storage_id)

        logger.info("Preparing storage provider for '%s' storage", configuration.type)
        storage = webdav.utils.prepare_storage_provider(configuration)
        return storage

