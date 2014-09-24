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

import json
import uuid

from keystoneclient import fixture as ks_fixture
from keystoneclient import session
import mock
import requests_kerberos
from requests_mock.contrib import fixture as requests_fixture

from keystoneclient_kerberos.tests import base
from keystoneclient_kerberos import v3


class TestKerberosAuth(base.TestCase):

    TEST_ROOT_URL = 'http://keystoneserver.test.com:5000/'

    def setUp(self):
        super(TestKerberosAuth, self).setUp()

        self.token_id = uuid.uuid4().hex
        self.token_body = ks_fixture.V3Token()

        self.requests = self.useFixture(requests_fixture.Fixture())

    @mock.patch.object(requests_kerberos.HTTPKerberosAuth,
                       'generate_request_header')
    def test_authenticate_with_kerberos_domain_scoped(self, request_header):
        header = 'Negotiate %s' % uuid.uuid4().hex
        request_header.return_value = header

        fail_resp = {'text': 'Fail',
                     'status_code': 401,
                     'headers': {'WWW-Authenticate': 'Negotiate'}}
        pass_resp = {'json': self.token_body,
                     'status_code': 200,
                     'headers': {'X-Subject-Token': self.token_id,
                                 'Content-Type': 'application/json'}}

        self.requests.register_uri('POST',
                                   self.TEST_ROOT_URL + 'v3/auth/tokens',
                                   response_list=[fail_resp, pass_resp])

        a = v3.Kerberos(self.TEST_ROOT_URL + 'v3')
        s = session.Session(a)
        token = a.get_token(s)

        req = {'auth': {'identity': {'methods': ['kerberos'],
                                     'kerberos': {}}}}

        self.assertEqual(req, json.loads(self.requests.last_request.body))
        self.assertEqual(header,
                         self.requests.last_request.headers['Authorization'])
        self.assertEqual(self.token_id, a.auth_ref.auth_token)
        self.assertEqual(self.token_id, token)
