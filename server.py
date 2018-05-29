import os
import sys
import logging
from werkzeug.wsgi import DispatcherMiddleware
from config import available_settings
from webdav import __version__ as version
from raven.contrib.flask import Sentry

def get_secret(key):
    """Helper function to load 'secrets' either directly or indirectly via a file env.

    This will try to read the environment variable e.g. TEST either directly from 'TEST'
    or 'TEST_FILE' if found. Of both are specified it will raise a ValueError.

    :param key: the name of the ENV variable that should be read.
    :return: the 'secret' value stored in key or key + "_FILE".
    """
    key_file = "{}_FILE".format(key)

    if os.environ.get(key_file) and os.environ.get(key):
        raise ValueError("Both '{}' and '{}' are set but mutually exclusive.".format(key, key_file))

    key_file_location = os.environ.get(key_file, None)
    if key_file_location and os.path.exists(key_file_location):
        with open(key_file_location, 'r') as fh:
            return fh.readlines()

    return os.environ.get(key, None)


def create_app():
    from webdav import app as application

    # Enable logging to stdout.
    stdout_handler = logging.StreamHandler(sys.stdout)
    stdout_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    stdout_handler.setFormatter(stdout_formatter)
    application.logger.addHandler(stdout_handler)

    application.logger.info("Getting current environment from ENV.")
    environment = os.environ['ENV']
    settings = available_settings[environment]

    # TODO: Make logging output configurable per environment.
    logging.getLogger("webdav").setLevel(logging.DEBUG)
    #logging.getLogger("bushn").setLevel(logging.WARNING)
    #logging.getLogger("jars").setLevel(logging.INFO)
    #logging.getLogger("requests").setLevel(logging.WARNING)
    #logging.getLogger("requests_oauth").setLevel(logging.WARNING)

    application.logger.info("Loading '%s' settings based on ENV...", environment)
    application.config.from_object(settings)

    if settings.USE_SENTRY:
        application.logger.info("Configuring Sentry...")
        sentry = Sentry(application,
                        logging=True,
                        level=logging.ERROR,
                        dsn=get_secret('SENTRY_DSN'))
        sentry.client.release = version
        sentry.client.environment = environment
        application.logger.info("Sentry setup complete!")
    else:
        application.logger.warning("No Sentry configuration found. Skipping setup!")

    application.logger.info("Starting webdav v{}.".format(version))
    application.logger.info("Using '{}' environment settings.".format(settings.environment))
    application.logger.info("Enabled storages: {}.".format(settings.ENABLED_STORAGES.keys()))

    return application


if __name__ == '__main__':

    application = create_app()
    deploy_via = application.config['DEPLOY_VIA']
    host='0.0.0.0'
    port= os.environ.get('PORT', 8080)

    application = DispatcherMiddleware(application, {'/webdav': application})

    if deploy_via == 'waitress':
        from waitress import serve
        serve(application,
              host=host,
              port=port)
    elif deploy_via == 'werkzeug':
        from werkzeug.serving import run_simple
        run_simple(hostname=host,
                   port=port,
                   application=application,
                   use_reloader=True)
    else:
        print("No valid deployment option specified!")
        sys.exit(1)
