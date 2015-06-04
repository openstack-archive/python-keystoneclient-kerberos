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
from oslotest import mockpatch
import requests_kerberos


class KerberosMock(fixtures.Fixture):

    def __init__(self):
        super(KerberosMock, self).__init__()

        self.challenge_header = 'Negotiate %s' % uuid.uuid4().hex
        self.pass_header = 'Negotiate %s' % uuid.uuid4().hex

        self.fail_resp = {'text': 'Fail',
                          'status_code': 401,
                          'headers': {'WWW-Authenticate': 'Negotiate'}}
        self.pass_resp = {'status_code': 200,
                          'headers': {'WWW-Authenticate': self.pass_header}}

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

    @property
    def resp_list(self):
        """The list of responses that need to be returned for kerberos auth"""
        return [self.fail_resp, self.pass_resp]

    def _generate_request_header(self, *args, **kwargs):
        return self.challenge_header

    def _authenticate_server(self, response):
        return response.headers.get('www-authenticate') == self.pass_header
