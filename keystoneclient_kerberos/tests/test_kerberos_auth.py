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

import mock
import requests_kerberos

from keystoneclient.contrib.auth.v3 import kerberos
from keystoneclient import session
from keystoneclient.tests import utils


class TestKerberosAuth(utils.V3AuthTestCase):

    @mock.patch.object(requests_kerberos.HTTPKerberosAuth,
                       'generate_request_header')
    def test_authenticate_with_kerberos_domain_scoped(self, request_header):
        header = 'Negotiate %s' % uuid.uuid4().hex
        request_header.return_value = header

        fail_resp = {'text': 'Fail',
                     'status_code': 401,
                     'headers': {'WWW-Authenticate': 'Negotiate'}}
        pass_resp = {'json': self.TEST_RESPONSE_DICT,
                     'status_code': 200,
                     'headers': {'X-Subject-Token': self.TEST_TOKEN}}

        self.stub_url(method='POST', parts=['auth', 'tokens'],
                      response_list=[fail_resp, pass_resp])

        a = kerberos.Kerberos(self.TEST_URL)
        s = session.Session(a)
        s.get_token()

        req = {'auth': {'identity': {'methods': ['kerberos'],
                                     'kerberos': {}}}}

        self.assertRequestBodyIs(json=req)
        self.assertRequestHeaderEqual('Authorization', header)
        self.assertEqual(s.auth.auth_ref.auth_token, self.TEST_TOKEN)
