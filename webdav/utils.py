import jars
import json
import logging
import requests
import mimetypes
import webdav.models
from functools import partial

from flask import current_app
from urllib.parse import quote, unquote

logger = logging.getLogger(__name__)

Q_USER_INFORMATION = """query
{
    currentUser
    {
        id
        email
        is_enabled
        roles
        csps
        {
            csp_id
            display_name
            authentication_data
            type
        }
        organization
        {
            display_name
        }
    }
}"""


def has_authentication_header(headers):
    """Return True if the 'Authorization' in the given headers is not empty"""
    return 'Authorization' in headers


def extract_authentication_token(headers):
    """Extracts the authentication token from the current request headers.

    :param headers: The request.headers containing the authentication field.
    :type headers: dict
    :return: None if no or an invalid token was found, the JWT otherwise.
    """
    value = headers.get('Authorization', '')
    if not value:
        logger.debug("Authorization header not found!")
        return None

    parts = value.split(" ")
    if parts and len(parts) != 2:
        logger.debug("Authorization header has invalid format!")
        return None

    _, jwt = parts
    if jwt == '':
        logger.debug("Extracted token is an empty string!")
        return None

    logger.info("Extracted JWT from Authorization header.")
    return jwt


def send_activity_log(token, event):
    """Send the given event to the associated backend's activity log."""
    session = requests.session()

    # FIXME: Make the expected api version configurable
    session.headers['X-Api-Version-Expected'] = '0.1.1'
    session.headers = {'Authorization': 'Bearer {}'.format(token)}

    crosscloud_api_url = current_app.config['ADMIN_CONSOLE_GRAPHQL']
    assert crosscloud_api_url, "Current application has no admin console url set!"
    logger.info("Trying to send event to console at '%s'.", crosscloud_api_url)

    try:
        mutation = '''mutation AddActivityLogMutation($input: ActivityLogInput!) {
                          addActivityLog(input: $input) {
                            id
                          }
                        }'''

        response = session.post(crosscloud_api_url, json={'query': mutation,
                                                          'variables': { 'input': event }})
        response.raise_for_status()
    except requests.exceptions.RequestException:
        logger.exception("Unable to fetch current user configuration from endpoint!")
        return False

    assert response.status_code == 200
    if 'errors' in response.json():
        logger.error(response.json())
        return False

    logger.info("Successfully logged event to console.")
    return True


def fetch_user_configuration(token):

    session = requests.session()

    # FIXME: Make the expected api version configurable
    session.headers['X-Api-Version-Expected'] = '0.1.1'
    session.headers = {'Authorization': 'Bearer {}'.format(token)}

    crosscloud_api_url = current_app.config['ADMIN_CONSOLE_GRAPHQL']
    assert crosscloud_api_url, "Current application has no admin console url set!"

    logger.info("Trying to get current user information from '%s'", crosscloud_api_url)

    try:
        resp = session.post(crosscloud_api_url, json={'query': Q_USER_INFORMATION, 'variables': {}})
        resp.raise_for_status()
    except requests.exceptions.RequestException:
        logger.exception("Unable to fetch current user configuration from endpoint!")
        return None

    assert resp.status_code == 200
    if 'errors' in resp.json():
        logger.error(resp.json())
        return None

    logger.info("Successfully fetched current user.")
    current_user = resp.json()['data']['currentUser']
    return current_user


def store_new_token_in_backend(new_token, old_token, auth_token, storage_id):
    """Store the new token in the backend."""

    session = requests.session()

    # FIXME: Make the expected api version configurable
    session.headers = {'Authorization': 'Bearer {}'.format(auth_token)}

    crosscloud_api_url = current_app.config['ADMIN_CONSOLE_GRAPHQL']
    assert crosscloud_api_url, "Current application has no admin console url set!"
    logger.info("Trying to send new token to console at '%s'.", crosscloud_api_url)

    try:
        mutation = '''mutation UpdateCSPAuthData($csp_id:String!,$old:String!,$new:String!) {
                          updateCspAuthData(csp_id: $csp_id,
                                            old_authentication_data: $old,
                                            new_authentication_data: $new)
                          {
                            id
                          }
                      }'''

        response = session.post(crosscloud_api_url, json={'query': mutation,
                                                          'variables': { 'csp_id': storage_id,
                                                                         'old': old_token,
                                                                         'new': new_token }})
        response.raise_for_status()
    except requests.exceptions.RequestException:
        logger.exception("Unable to fetch current user configuration from endpoint!")
        return old_token

    assert response.status_code == 200
    if 'errors' in response.json():
        logger.error(response.json())
        return old_token

    logger.info("Successfully logged event to console.")
    logger.debug("*"*80)
    return new_token


def prepare_storage_provider(configuration):
    """Prepare a ready-to-use storage provider using the given configuration.

    :param configuration: the storage configuration of a webdav.models.User object.
    :type configuration: webdav.models.StorageConfiguration
    :return:
    """
    logger.info("Requesting storage of type '%s'.", configuration.type)

    enabled_providers = current_app.config['ENABLED_STORAGES']
    assert len(enabled_providers) > 0

    if configuration.type not in enabled_providers:
        logger.error("Provider %s not available. Enabled providers are %s",
                     configuration.type,
                     enabled_providers)
        return None

    logger.debug("Found provider '%s' of type '%s'.",
                 configuration.type,
                 configuration.storage_id)

    cls = enabled_providers[configuration.type]

    def bad_token_reader(x):
        logger.info("Reading token.")
        return lambda: x

    from flask import g
    token_writer = partial(store_new_token_in_backend,
                           old_token=configuration.authentication_data,
                           auth_token=g.current_user.authentication_token,
                           storage_id=configuration.storage_id)

    storage = cls(event_sink=webdav.models.DummyEventSink(configuration.storage_id),
                  storage_id=configuration.storage_id,
                  storage_cache_dir=None,
                  storage_cred_writer=token_writer,
                  storage_cred_reader=bad_token_reader(configuration.authentication_data))
    storage.storage_display_name = configuration.display_name
    update_storage(storage)

    logger.info("Storage type '%s' prepared.", configuration.type)
    return storage


def update_storage(storage):
    """Call update on a storage."""

    # For creating a new folder google drive requires the "_id" of the parent, which is not
    # present after initialization. This ensures that `update` is called before any other
    # action on the storage is taken.
    if storage.storage_name == 'gdrive':
        logger.info("Calling 'update' for 'gdrive' storage.")
        storage.update()


def as_crosscloud_path(path):
    """Transform a given path from the storage provider path to the crosscloud domain.

    :param path: the path to transform as a string e.g. /foobar/bar/baz.
                 The path will also be automatically unquoted if it was urlencoded.
    :return: a list containing relative path for the storage.
    """

    path = unquote(path)

    if not path.startswith("/"):
        logger.info("Path not starting with / prepending...")
        path = "/{}".format(path)

    if path == '/' or path == "":
        return []

    if len(path) > 0 and path[-1] == '/':
        path = path[:-1]

    if path.startswith("/"):
        _path = path.split("/")[1:]
    else:
        _path = path.split("/")

    logger.debug("'%s' -> %s.", path, _path)
    return _path


def as_storage_provider_path(crosscloud_path):
    """Translate a given crosscloud path to the storage provider path."""
    if not len(crosscloud_path):
        # files/list_folder requires an empty string rather than '/'
        return '/'

    if len(crosscloud_path) == 1 and (crosscloud_path[0] == '' or crosscloud_path[0] == '/'):
        # files/list_folder requires an empty string rather than '/'
        return '/'

    return quote('/' + '/'.join(crosscloud_path))


def guess_mime_type(filename):
    """Return the mime type for the given file."""
    import mimetypes
    mime_type, _ = mimetypes.guess_type(filename)

    # If we cannot determine the mime type using `mimetypes` we fall back
    # to 'application/octet-stream'.
    if not mime_type:
        logger.error("Unable to determine mimetype for '%s'.", filename)
        mime_type = 'application/octet-stream'

    logger.info("Returning '%s' as mime type for '%s'", mime_type, filename)
    return mime_type


def node_to_resource(storage_id, crosscloud_path, name, properties):
    """Create a `Resource` for the given storage, path and node name/properties.

    :param storage_id: the unique id of the storage provider.
    :param crosscloud_path: the crosscloud path _on_ the storage provider.
    :param name: The resource name as returned by .get_tree_children.
    :param properties: the resource properties as returned by .get_tree_children.
    :return:
    """
    href = as_storage_provider_path([storage_id, *crosscloud_path, name])
    if properties[jars.IS_DIR]:
        logger.info("Resource '%s' is a folder.", href)
        content_type = None
        content_length = None
    else:
        logger.info("Resource '%s' is a file.", href)
        content_type=guess_mime_type(name)
        content_length=properties[jars.SIZE]

    return webdav.models.Resource(is_dir=properties[jars.IS_DIR],
                                  version_id=properties[jars.VERSION_ID],
                                  content_type=content_type,
                                  content_length=content_length,
                                  href=href,
                                  display_name=name)


def is_valid_authentication_data(authentication_data):
    """Check if the given authentication_data string appears to be valid.

    Authentication data is invalid if:
    - the resulting deserialized data type has a length of zero.
    - the given data type is not deserializable or not given in a processable format.
    - the given data is deserializable but not valid json.

    :param authentication_data: serialized json string containing the credentials for a storage.
    :type authentication_data: str
    :return: True if the string appears to be valid. False, otherwise.
    """
    try:
        data = json.loads(authentication_data)

        if not len(data):
            logger.warning("Empty 'authentication_data' provided.")
            return False

    except json.JSONDecodeError:
        logger.warning("Unable to decode attached authentication data.")
        return False
    except TypeError:
        logger.warning("Unable to deserialize given '%s' data type.", type(authentication_data))
        return False

    logger.info("Provided authentication data appears to be valid.")
    return True
