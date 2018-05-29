"""Flask implementation of Webdav, which only conatins the methods required by crosscloud
"""
__author__ = 'crosscloud GmbH'
__version__ = '0.4.7'

import datetime as dt
from functools import wraps
from io import BytesIO

from flask import Flask, Response, abort, g, render_template, request

app = Flask(__name__)
logger = app.logger

import jars
import webdav.models
import webdav.utils


def with_prepared_storage(fun):
    """Decorator that passes a storage to its decorated function."""
    @wraps(fun)
    def decorated_function(*args, **kwargs):

        storage_id = kwargs['storage_id']

        assert g.current_user is not None

        if g.current_user.has_storage(storage_id) is None:
            logger.error("User has no storage with id %s", storage_id)
            abort(404)

        storage = g.current_user.get_storage(storage_id)
        if not storage:
            logger.error("Storage not found!")
            abort(404)

        assert storage is not None

        return fun(storage, *args, **kwargs)
    return decorated_function


@app.before_request
def ensure_authorization_header():
    """Returns 401 if the current request headers do not contain any authorization header."""
    logger.debug("Ensuring authorization header is present.")
    if not webdav.utils.has_authentication_header(request.headers):
        logger.info("Authentication token not found. Returning 401.")
        abort(401)


def after_this_request(func):
    if not hasattr(g, 'call_after_request'):
        g.call_after_request = []
    g.call_after_request.append(func)
    return func


@app.after_request
def per_request_callbacks(response):
    for func in getattr(g, 'call_after_request', ()):
        response = func(response)
    return response


@app.after_request
def set_additional_response_headers(response):
    """This is used to set certain response header fields on every response."""
    response.headers["Server"] = "webdav/{}".format(webdav.__version__)
    return response


@app.before_request
def ensure_current_user():
    """Raise appropriate exceptions if user is not correctly configured."""
    logger.info("Fetching user configuration from admin console.")

    # Extract Token
    token = webdav.utils.extract_authentication_token(request.headers)
    # logger.debug(token)
    if not token:
        logger.info("Authentication token empty or invalid. Returning 401.")
        abort(401)

    # Fetch User Configuration
    configuration = webdav.utils.fetch_user_configuration(token)
    # logger.debug(configuration)
    if not configuration:
        logger.warning("Returned configuration is 'None'. Assuming authentication required!")
        abort(401)

    logger.info("Building 'current_user' from given configuration.")
    g.current_user = webdav.models.User.using(configuration)
    g.current_user.authentication_token = token
    logger.info("User setup complete.")


@app.route("/", methods=['PROPFIND'])
def get_provider_list():
    """Return the available storages."""
    return render_template('provider_list.xml', providers=g.current_user.configured_storage_providers.values())


@app.route("/<storage_id>", defaults={'path': ''}, methods=['PROPFIND'])
@app.route("/<storage_id>/<path:path>", methods=['PROPFIND'])
@with_prepared_storage
def get_resource_properties(storage, storage_id, path):
    """Get the WebDAV properties for the given resource.

    :param storage_id: The 'unique_id' of the configured storage provider
    :type storage_id: str
    :param path: The path that should be setup on the storage provider.
    :type path: str
    """
    crosscloud_path = webdav.utils.as_crosscloud_path(path)


    logger.info("Trying to get data for '%s' -> %s on %s.", path, crosscloud_path, storage_id)
    children = storage.get_tree_children(crosscloud_path)
    resources = [webdav.utils.node_to_resource(storage_id, crosscloud_path, name, props)
                 for name, props in children]
    return render_template('properties.xml', storage=storage, resources=list(resources))


@app.route("/<storage_id>", defaults={'path': ''}, methods=['GET'])
@app.route("/<storage_id>/<path:path>", methods=['GET'])
@with_prepared_storage
def get_resource(storage, storage_id, path):
    """Get the WebDAV resource.

    :param storage_id: The 'unique_id' of the configured storage provider
    :type storage_id: str
    :param path: The path to the requested file on the storage
    :type path: str
    """
    crosscloud_path = webdav.utils.as_crosscloud_path(path)

    if crosscloud_path == []:
        # A client is trying to download the storage root folder. This is not possible.
        logger.warning("Requested to download storage root folder. Aborting!")
        return 'Collections cannot be downloaded!', 405

    if len(crosscloud_path) == 1:
        logger.info("Request URI points to resource inside the storage root folder.")
        lookup_path, resource_name = [], crosscloud_path[0]
    else:
        logger.info("Request URI points to resource below the storage root folder.")
        lookup_path, resource_name = crosscloud_path[:-1], crosscloud_path[-1]

    # Get the contents of the resources parent folder.
    contents = {path: props for path, props in storage.get_tree_children(lookup_path)}

    try:
        properties = contents[resource_name]
        if properties['is_dir']:
            logger.error("Requested path points to a collection. Aborting with 405!")
            return "Collections cannot be downloaded!", 405
    except KeyError:
        logger.warning("'%s' not found in lookup path '%s'. Aborting with 404!",
                       resource_name, lookup_path)
        return "Resource not found!", 404

    logger.info("Trying to get resource '%s' -> %s on %s.", path, crosscloud_path, storage_id)
    etag = request.headers.get('If-Match')

    f_obj = storage.open_read(path=crosscloud_path, expected_version_id=etag)

    @after_this_request
    def log_activity(response):
        activity_logger = webdav.models.ActivityLogger(g.current_user)
        activity_logger.send(path=crosscloud_path, task_type='DownloadSyncTask',
                             timestamp=dt.datetime.utcnow().isoformat(),
                             mime_type=webdav.utils.guess_mime_type(path),
                             encrypted=False,
                             storage_id=storage.storage_id,
                             bytes_transferred=-1)
        return response

    return Response(f_obj, mimetype=webdav.utils.guess_mime_type(path))


@app.route("/<storage_id>", defaults={'path': ''}, methods=['MKCOL'])
@app.route("/<storage_id>/<path:path>", methods=['MKCOL'])
@with_prepared_storage
def create_folder_resource(storage, storage_id, path):
    """Create a folder on the given storage and path.

    :param storage:
    :type storage: jars.BasicStorage
    :param storage_id:
    :type storage_id: str
    :param path:
    :type path: str
    :return:
    """
    # FIXME: Make this use error_handler decorator and custom functions.
    try:
        crosscloud_path = webdav.utils.as_crosscloud_path(path)
        logger.info("Trying to create collection(s) '%s' -> %s on %s.",
                    path,
                    crosscloud_path,
                    storage_id)
        version_id = storage.make_dir(path=crosscloud_path)
        assert version_id == 'is_dir'

    except jars.CurrentlyNotPossibleError:
        logger.exception("Currently not possible to create '%s'.", crosscloud_path)
        abort(503) # Temporarily Unavailable
    except jars.UnavailableError:
        logger.exception("Storage '%s' unreachable!", storage.storage_name)
        abort(500)
    except jars.AuthenticationError:
        logger.exception("Token expired!")
        # FIXME: Update token and try again?
        abort(503)
    except jars.SevereError:
        logger.exception("Storage is not valid!")
        abort(503)

    @after_this_request
    def log_activity(response):
        activity_logger = webdav.models.ActivityLogger(g.current_user)
        activity_logger.send(path=crosscloud_path, task_type='CreateDirSyncTask',
                             timestamp=dt.datetime.utcnow().isoformat(),
                             mime_type=webdav.utils.guess_mime_type(path),
                             encrypted=False,
                             storage_id=storage.storage_id,
                             bytes_transferred=0)
        return response

    return '', 201


@app.route("/<storage_id>", defaults={'path': ''}, methods=['PUT'])
@app.route("/<storage_id>/<path:path>", methods=['PUT'])
@with_prepared_storage
def upload_file(storage, storage_id, path):
    """Upload files to a specific storage.

    :param storage: the ready-to-use storage instance.
    :type storage: jars.BasicStorage
    :param storage_id: The 'unique_id' of the configured storage provider
    :type storage_id: str
    :param path: The path the file should be uploaded to.
    :type path: str
    :return: 201 if file was uploaded successfully.
    """

    crosscloud_path = webdav.utils.as_crosscloud_path(path)
    logger.info("%s %s", crosscloud_path, len(request.data))
    original_version_id = request.headers.get('If-Match', None)

    try:
        version_id = storage.write(path=crosscloud_path,
                                   file_obj=BytesIO(request.data),
                                   original_version_id=original_version_id,
                                   size=len(request.data))
        logger.info("Successfully uploaded file '%s' %s -> %s",
                    path,
                    original_version_id,
                    version_id)
    except jars.NoSpaceError:
        logger.exception("No space left on device!")
        abort(500)
    except jars.CurrentlyNotPossibleError:
        logger.exception("Unable to write file!")
        abort(503)
    except jars.UnavailableError:
        logger.exception("Storage is currently not reachable!")
        abort(503)
    except jars.AuthenticationError:
        logger.exception("Authentication with the storage failed!")
        abort(403)
    except jars.SevereError:
        logger.exception("Severe error happened!")
        abort(500)

    @after_this_request
    def log_activity(response):
        activity_logger = webdav.models.ActivityLogger(g.current_user)
        activity_logger.send(path=crosscloud_path, task_type='UploadSyncTask',
                             timestamp=dt.datetime.utcnow().isoformat(),
                             mime_type=webdav.utils.guess_mime_type(path),
                             encrypted=False,
                             storage_id=storage.storage_id,
                             bytes_transferred=-1)
        return response

    return '', 201


@app.route("/<storage_id>", defaults={'path': ''}, methods=['MOVE'])
@app.route("/<storage_id>/<path:path>", methods=['MOVE'])
@with_prepared_storage
def move_resource(storage, storage_id, path):

    destination = request.headers['Destination']
    logger.info("'MOVE' resource from '%s' -> '%s'", path, destination)

    crosscloud_path = webdav.utils.as_crosscloud_path(path)

    destination_path = destination.split(storage_id)[1]
    crosscloud_destination_path = webdav.utils.as_crosscloud_path(destination_path)
    logger.info("Moving from %s -> %s", crosscloud_path, crosscloud_destination_path)

    try:
        storage.move(source=crosscloud_path,
                     target=crosscloud_destination_path,
                     expected_source_vid=request.headers['If-Match'],
                     expected_target_vid=None)
    except IndexError:
        logger.exception("No ETAG found or provided!")
        abort(400)
    except jars.StorageError:
        logger.exception("Could not move resource!")
        abort(500)

    @after_this_request
    def log_activity(response):
        activity_logger = webdav.models.ActivityLogger(g.current_user)
        activity_logger.send(path=crosscloud_destination_path,
                             task_type='UploadSyncTask',
                             timestamp=dt.datetime.utcnow().isoformat(),
                             mime_type=webdav.utils.guess_mime_type(path),
                             encrypted=False,
                             storage_id=storage.storage_id,
                             bytes_transferred=0)
        activity_logger.send(path=crosscloud_path,
                             task_type='DeleteSyncTask',
                             timestamp=dt.datetime.utcnow().isoformat(),
                             mime_type=webdav.utils.guess_mime_type(path),
                             encrypted=False,
                             storage_id=storage.storage_id,
                             bytes_transferred=0)
        return response

    return '', 204


@app.route("/<storage_id>", defaults={'path': ''}, methods=['DELETE'])
@app.route("/<storage_id>/<path:path>", methods=['DELETE'])
@with_prepared_storage
def delete_resource(storage, storage_id, path):
    """Get the WebDAV properties for the given resource.

    :param storage_id: The 'unique_id' of the configured storage provider
    :type storage_id: str
    :param path: The path that should be setup on the storage provider.
    :type path: str
    """
    logger.info("Delete Storage Provider '%s' and path '%s'.", storage_id, path)

    crosscloud_path = webdav.utils.as_crosscloud_path(path)

    if crosscloud_path == []:
        logger.info("Unable to remove storage provider root folder.")
        abort(403)

    try:
        version_id = request.headers['if-match']
        storage.delete(webdav.utils.as_crosscloud_path(path), original_version_id=version_id)
    except IndexError:
        logger.error("No ETAG found or provided!")
        abort(406)  # Not Acceptable
    except jars.VersionIdNotMatchingError as ex:
        logger.error("Version IDs did not match! %s", ex)
        abort(406)  # Not Acceptable
    except FileNotFoundError as ex:
        logger.error("Resource not found '%s'. %s", path, ex)
        abort(404)  # Not Found
    except jars.StorageError as ex:
        logger.error("Could not delete Resource at '%s'. %s", path, ex)
        abort(500)  # Internal Server Error

    @after_this_request
    def log_activity(response):
        activity_logger = webdav.models.ActivityLogger(g.current_user)
        activity_logger.send(path=crosscloud_path, task_type='DeleteSyncTask',
                             timestamp=dt.datetime.utcnow().isoformat(),
                             mime_type=webdav.utils.guess_mime_type(path),
                             encrypted=False,
                             storage_id=storage.storage_id,
                             bytes_transferred=0)
        return response

    return '', 204


@app.errorhandler(FileNotFoundError)
def handle_file_not_found(e):
    """Handle FileNotFoundErrors gracefully."""
    logger.warning("Resource not found '%s'.", e)
    return '', 404


