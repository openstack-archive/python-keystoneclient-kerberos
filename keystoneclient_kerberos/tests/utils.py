# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import uuid

import fixtures
from keystoneclient import fixture as ks_fixture
from oslotest import mockpatch
import requests_kerberos


# any old base url for test mocking
TEST_ROOT_URL = 'http://keystoneserver.test.com:5000/'


class KerberosMock(fixtures.Fixture):

    def __init__(self, requests_mock):
        super(KerberosMock, self).__init__()

        self.challenge_header = 'Negotiate %s' % uuid.uuid4().hex
        self.pass_header = 'Negotiate %s' % uuid.uuid4().hex
        self.requests_mock = requests_mock

    def setUp(self):
        super(KerberosMock, self).setUp()

        m = mockpatch.PatchObject(requests_kerberos.HTTPKerberosAuth,
                                  'generate_request_header',
                                  self._generate_request_header)

        self.header_fixture = self.useFixture(m)

        m = mockpatch.PatchObject(requests_kerberos.HTTPKerberosAuth,
                                  'authenticate_server',
                                  self._authenticate_server)

        self.authenticate_fixture = self.useFixture(m)

    def _generate_request_header(self, *args, **kwargs):
        return self.challenge_header

    def _authenticate_server(self, response):
        return response.headers.get('www-authenticate') == self.pass_header

    def mock_auth_success(self,
                          token_id=None,
                          token_body=None,
                          method='POST',
                          url=TEST_ROOT_URL + 'v3/auth/tokens'):
        if not token_id:
            token_id = uuid.uuid4().hex
        if not token_body:
            token_body = ks_fixture.V3Token()

        response_list = [{'text': 'Fail',
                          'status_code': 401,
                          'headers': {'WWW-Authenticate': 'Negotiate'}},
                         {'headers': {'X-Subject-Token': token_id,
                                      'Content-Type': 'application/json',
                                      'WWW-Authenticate': self.pass_header},
                          'status_code': 200,
                          'json': token_body}]

        self.requests_mock.register_uri(method,
                                        url,
                                        response_list=response_list)

        return token_id, token_body
