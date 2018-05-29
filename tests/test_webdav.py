"""Tests against the flask implementation of crosscloud webdav endpoints."""

import pytest

from webdav import app
from flask import url_for

import os
CWD = os.path.join(os.path.dirname(__file__))
RESULTS = os.path.join(CWD, 'responses')

class TestWebDav:
    client = app.test_client()
    response = ''
    method = 'PROPFIND'
    response_file = 'get_provider.xml'
    route = '/'
    expected_status = 200
    encoding = "utf-8"

    @property
    def expected_content(self):
        response_path = os.path.join(RESULTS, self.response_file)
        with open(response_path) as response_file:
            return response_file.read()

    @property
    def response(self):
        response = self.client.open(self.route, method=self.method)
        return response

    @property
    def content(self):
        return self.response.data.decode(self.encoding)


    @pytest.mark.skip
    def test_status_code(self):
        assert self.response.status_code == self.expected_status

    @pytest.mark.skip
    def test_response(self):
        assert self.content  == self.expected_content

class TestFail(TestWebDav):
    route = 'webdav/dropbox_1498551067.4982216/'
    response_file = 'sample.xml'
