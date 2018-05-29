# Crosscloud WebDAV Service

Is a crosscloud service that allows applications to access pre-configured storage providers using
the `WebDAV` protocol. It currently supports a very limited subset of the standard.


| Branch | Build Status | Coverage | Deployed to |
| --------: | --- | --- | --- |
| `production` | [![build status](https://gitlab.crosscloud.me/crosscloud/webdav/badges/master/build.svg)](https://gitlab.crosscloud.me/crosscloud/webdav/commits/master) | [![coverage report](https://gitlab.crosscloud.me/crosscloud/webdav/badges/master/coverage.svg)](https://gitlab.crosscloud.me/crosscloud/webdav/commits/master) | https://admin.crosscloud.me/webdav |
| `master` | [![build status](https://gitlab.crosscloud.me/crosscloud/webdav/badges/master/build.svg)](https://gitlab.crosscloud.me/crosscloud/webdav/commits/master)  | [![coverage report](https://gitlab.crosscloud.me/crosscloud/webdav/badges/master/coverage.svg)](https://gitlab.crosscloud.me/crosscloud/webdav/commits/master) | https://staging.crosscloud.me/webdav |


## Developers

| Who | Responsibility | Role|
| --------: | :--- | :--- |
| @julianrath | | Master |
| @daniel | Deployment | Master |
| @james  | Code, Deployment | Master |
| @twu    | Project Owner, Code, Deployment | Master |


## Versioning

Ensure that `bumpversion` (or install it using `pip install bumpversion`) is
installed (configuration see `setup.cfg`). Call `bumpversion` with either
`major`, `minor` or `patch`. This will increase all version numbers and automatically
create a commit and tag for the new current version.


    # Current version 1.0.0. Bump version 1.0.1
    bumpversion patch

    # Push the created commit and tag!
    git push
    git push --tags


## Deployment

    tl;dr `master` automatically deployed to `staging`; deployment to `production` via manual trigger.

Changes to `master` will automatically trigger container builds and the updated container is 
then automatically deployed to the `staging` environment.

If you then want to trigger a `production` deployment for your changes either trigger the manual
action in the gitlab webinterface or use `/webdav deploy staging to production` in mattermost. This will deploy the `latest` container from the registry via rancher.

## Configuration

### Sentry

Ensure the Sentry DSN is present in the environment `SENTRY_DSN` or via `SENTRY_DSN_FILE` and
 the `config` Environment has `USE_SENTRY` set to `True`. Events will
be automatically tagged with the current environment and version of the
backend.


## Testing

### Production Container

1. Run `SSH_PRIVATE_KEY=$(cat ~/.ssh/id_rsa) ./scripts/build-production-container.sh`
   to build the container.
   This step is required also if you did **any** changes to the code or dependencies.
2. Run `docker run --rm -ti -e PORT=3000 -e CC_ADMIN_CONSOLE_GRAPHQL_URL=https://cc-testing.herokuapp.com/graphql -p 3000:3000 cc-webdav-prod` to actually start the container.
3. It should be then available on http://127.0.0.1:3000/

## Development Setup

1. Install docker based on instructions in admin console repository.
2. Checkout _bushn_ and _jars_ as subfolders of this folder.
3. Set the url for the used admin console in `config.py` or the env `CC_ADMIN_CONSOLE_GRAPHQL_URL`
4. Create a new docker network (if not created yet): `docker network create crosscloud-dev`
5. Run `docker-compose up`

If any dependencies have changed please stop `docker-compose`,
run `docker-compose build --pull` to rebuild the image and run `docker-compose up`
again.

Use the following command for testing: `docker-compose run app py.test tests/`.

