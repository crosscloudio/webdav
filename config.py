import os
# Setup Storage
import jars.dropbox
# import jars.box
import jars.webdav
import jars.microsoft
import jars.owncloud
import jars.googledrive


class Settings:
    # Create storage provider mapping to mount the proper storage upon request. 'type' -> class
    ENABLED_STORAGES = {sp.storage_name: sp for sp in jars.registered_storages}
    ENVIRONMENT = None
    ADMIN_CONSOLE_GRAPHQL = None
    DEPLOY_VIA = None
    USE_SENTRY = False


class Development(Settings):
    environment = "development"
    ADMIN_CONSOLE_GRAPHQL = os.environ.get('CC_ADMIN_CONSOLE_GRAPHQL_URL', None)
    DEBUG = True
    TESTING = False
    DEPLOY_VIA = 'werkzeug'
    USE_SENTRY = False


class Testing(Settings):
    environment = "test"
    ADMIN_CONSOLE_GRAPHQL = 'http://api:3030/graphql'
    TESTING = True
    DEBUG = False
    DEPLOY_VIA = None
    USE_SENTRY = False


class Production(Settings):
    environment = 'production'
    ADMIN_CONSOLE_GRAPHQL = os.environ.get('CC_ADMIN_CONSOLE_GRAPHQL_URL', None)
    TESTING = False
    DEBUG = False
    DEPLOY_VIA = 'waitress'
    USE_SENTRY = True

available_settings = {setting.environment: setting for setting in [Development, Testing, Production]}

