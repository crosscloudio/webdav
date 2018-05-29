import requests
from unittest import mock
import requests_mock
import pytest
from hypothesis import given
from hypothesis import strategies as st
from urllib.parse import unquote, quote
from webdav.utils import has_authentication_header, extract_authentication_token, fetch_user_configuration
from webdav.utils import as_storage_provider_path, as_crosscloud_path
from webdav.utils import guess_mime_type, node_to_resource, is_valid_authentication_data

def test_has_authorization_header():
    """Ensure that has_authorization_header returns False if no header is present."""
    assert has_authentication_header({'Authorization': "test"})
    assert has_authentication_header({'Authorization': ""})
    assert has_authentication_header({}) == False


@pytest.mark.parametrize('header, expected_value', [
    ("", None),
    ("Bearer:", None),
    ("Bearer: ", None),
    ("Bearer: too many parts", None),
    ("Bearer: token", "token"),
])
def test_extract_authentication_token(header, expected_value):
    """Ensure that extract_authentication_token returns None or the provided JWT."""
    assert extract_authentication_token({'Authorization': header}) == expected_value


@pytest.mark.parametrize('endpoint', ['http://api:3030/graphql'])
def test_fetch_user_configuration(endpoint, test_application):

    # FIXME: Parameterize this and refactor "None" tests into side-effects testcase!

    with test_application.test_request_context():

        payload = {'data': { 'currentUser': {'id': '11-22-33'}}}
        with requests_mock.Mocker() as rmock:
            rmock.register_uri("POST", endpoint, json=payload)
            configuration = fetch_user_configuration("token")
            assert isinstance(configuration, dict)
            assert configuration['id'] == '11-22-33'

        # With no Token
        configuration = fetch_user_configuration(None)
        assert configuration is None

        configuration = fetch_user_configuration('')
        assert configuration is None

        # With 401
        with requests_mock.Mocker() as rmock:
            rmock.register_uri("POST", endpoint, json=payload, status_code=401)
            configuration = fetch_user_configuration("token")
            assert configuration is None

        # With 500
        with requests_mock.Mocker() as rmock:
            rmock.register_uri("POST", endpoint, json=payload, status_code=500)
            configuration = fetch_user_configuration("token")
            assert configuration is None

        # With 500
        with requests_mock.Mocker() as rmock:
            rmock.register_uri("POST", endpoint, exc=requests.exceptions.HTTPError)
            configuration = fetch_user_configuration("token")
            assert configuration is None

        # With errors
        with requests_mock.Mocker() as rmock:
            rmock.register_uri("POST", endpoint, json={"errors": [{}]})
            configuration = fetch_user_configuration("token")
            assert configuration == None


@pytest.mark.parametrize('input, output', [
    ("/", []),
    ("", []),
    ("test.txt", ['test.txt']),
    ("/foobar", ['foobar']),
    ("foo/bar", ['foo', 'bar']),
    ("/foobar/", ['foobar']),
    ("/foobar/test.txt", ['foobar', 'test.txt']),
    ('/foobar/%C3%A4%C3%A4%C3%A4%C3%A4.txt', ['foobar', 'ääää.txt']),
])
def test_as_crosscloud_path(input, output):
    """Ensure URLs are properly transformed to the crosscloud domain."""
    assert as_crosscloud_path(input) == output


@pytest.mark.parametrize('input, output', [
    ([], "/"),
    ([''], "/"),
    (['a'], "/a"),
    (['abc'], "/abc"),
    (['foobar', 'test.txt'], '/foobar/test.txt'),
    (['foobar', 'ääää.txt'], '/foobar/%C3%A4%C3%A4%C3%A4%C3%A4.txt'),
    (['test', 'Спасибо.txt'], quote('/test/Спасибо.txt')),
    (['folder', 'Спасибо.txt'], quote('/folder/Спасибо.txt')),
    (['Спасибо', 'Спасибо.txt'], quote('/Спасибо/Спасибо.txt')),
])
def test_as_storage_provider_path(input, output):
    """Ensure crosscloud paths are properly transformed to storage provider paths."""
    assert as_storage_provider_path(input) == output


@given(path=st.lists(st.text(min_size=1,
                             alphabet=st.characters(max_codepoint=0xd7ff,
                                                    blacklist_characters=['/']))))
def test_as_storage_vs_as_crosscloud(path):
    """Ensure that transforming between the two domains works with a fairly wide character space."""
    assert as_crosscloud_path(as_storage_provider_path(path)) == path


@pytest.mark.parametrize('filename, expected_mime_type', [
    ("Filename.unknown", 'application/octet-stream'),
    ("Filename.txt", 'text/plain'),
])
def test_guess_mime_type(filename, expected_mime_type):
    """Ensure that we guess mimetypes for common files."""
    assert guess_mime_type(filename) == expected_mime_type


@pytest.mark.parametrize('input, output', [
    ('/abcdefg.txt', '/abcdefg.txt'),
    ('/äüößÄÖÜ.txt', '/%C3%A4%C3%BC%C3%B6%C3%9F%C3%84%C3%96%C3%9C.txt'),
    ('/test/foo?', '/test/foo%3F'),
    ('/a/b/ ä /', '/a/b/%20%C3%A4%20/'),
    ('/foo/bar/test  äää  111 üüü.txt', '/foo/bar/test%20%20%C3%A4%C3%A4%C3%A4%20%20111%20%C3%BC%C3%BC%C3%BC.txt'),
])
def test_quote_unquote_path(input, output):
    """Ensure that we properly quote and unquote given paths before using them."""
    assert quote(input) == output
    assert unquote(output) == input


@pytest.mark.parametrize('storage, crosscloud_path, name, properties', [
    ('gdr', ['monkey','face'], 'filename.txt', {'is_dir': False, 'version_id': '0xdead', 'size': 23}),
    ('dbx', ['b'], 'ÜÜÜÜÜÜÜÜ.txt', {'is_dir': False, 'version_id': '0xdead', 'size': 23}),
    ('dbx', ['monkey'], 'face.txt', {'is_dir': False, 'version_id': '0xdead', 'size': 23}),
    ('dbx', ['monkey'], 'folder', {'is_dir': True, 'version_id': '0xdead', 'size': 23}),
    ('dbx', ['monkey'], 'folder', {'is_dir': True, 'version_id': '0xdead'}),
])
def test_node_to_resource(storage, crosscloud_path, name, properties):
    """Ensure we properly extract the necessary attributes from the given node properties."""
    resource = node_to_resource(storage_id=storage,
                                crosscloud_path=crosscloud_path,
                                name=name,
                                properties=properties)

    # If the given meta information indicates a folder.
    # We expect certain attributes to be not set or ignored.
    if properties['is_dir']:
        assert resource.content_length is None
        assert resource.content_type is None
    else:
        assert resource.content_type == 'text/plain'
        assert resource.content_length == 23

    expected_path = quote("/" + "/".join([storage, *crosscloud_path, name]))
    assert resource.href == expected_path


@pytest.mark.parametrize('authentication_data, expected_value', [
    (None, False),
    (False, False),
    ('', False),
    ('"', False),
    ('[]', False),
    ('\"something\"', True),
])
def test_is_valid_authentication_data(authentication_data, expected_value):
    """Ensure that passed authentication data that is empty or not deserializable is detected."""
    assert is_valid_authentication_data(authentication_data) == expected_value
