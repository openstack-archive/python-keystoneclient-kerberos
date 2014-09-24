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

from keystoneclient import session
import mock
import requests_kerberos

from keystoneclient_kerberos import kerberos
from keystoneclient_kerberos.tests import utils


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


class V3AuthTestCase(utils.TestCase):

    TEST_ROOT_URL = 'http://127.0.0.1:5000/'
    TEST_URL = '%s%s' % (TEST_ROOT_URL, 'v3')
    TEST_ROOT_ADMIN_URL = 'http://127.0.0.1:35357/'
    TEST_ADMIN_URL = '%s%s' % (TEST_ROOT_ADMIN_URL, 'v3')

    TEST_PASS = 'password'

    TEST_SERVICE_CATALOG = [{
        "endpoints": [{
            "url": "http://cdn.admin-nets.local:8774/v1.0/",
            "region": "RegionOne",
            "interface": "public"
        }, {
            "url": "http://127.0.0.1:8774/v1.0",
            "region": "RegionOne",
            "interface": "internal"
        }, {
            "url": "http://cdn.admin-nets.local:8774/v1.0",
            "region": "RegionOne",
            "interface": "admin"
        }],
        "type": "nova_compat"
    }, {
        "endpoints": [{
            "url": "http://nova/novapi/public",
            "region": "RegionOne",
            "interface": "public"
        }, {
            "url": "http://nova/novapi/internal",
            "region": "RegionOne",
            "interface": "internal"
        }, {
            "url": "http://nova/novapi/admin",
            "region": "RegionOne",
            "interface": "admin"
        }],
        "type": "compute"
    }, {
        "endpoints": [{
            "url": "http://glance/glanceapi/public",
            "region": "RegionOne",
            "interface": "public"
        }, {
            "url": "http://glance/glanceapi/internal",
            "region": "RegionOne",
            "interface": "internal"
        }, {
            "url": "http://glance/glanceapi/admin",
            "region": "RegionOne",
            "interface": "admin"
        }],
        "type": "image",
        "name": "glance"
    }, {
        "endpoints": [{
            "url": "http://127.0.0.1:5000/v3",
            "region": "RegionOne",
            "interface": "public"
        }, {
            "url": "http://127.0.0.1:5000/v3",
            "region": "RegionOne",
            "interface": "internal"
        }, {
            "url": TEST_ADMIN_URL,
            "region": "RegionOne",
            "interface": "admin"
        }],
        "type": "identity"
    }, {
        "endpoints": [{
            "url": "http://swift/swiftapi/public",
            "region": "RegionOne",
            "interface": "public"
        }, {
            "url": "http://swift/swiftapi/internal",
            "region": "RegionOne",
            "interface": "internal"
        }, {
            "url": "http://swift/swiftapi/admin",
            "region": "RegionOne",
            "interface": "admin"
        }],
        "type": "object-store"
    }]

    def setUp(self):
        super(V3AuthTestCase, self).setUp()
        self.TEST_RESPONSE_DICT = {
            "token": {
                "methods": [
                    "token",
                    "password"
                ],

                "expires_at": "2020-01-01T00:00:10.000123Z",
                "project": {
                    "domain": {
                        "id": self.TEST_DOMAIN_ID,
                        "name": self.TEST_DOMAIN_NAME
                    },
                    "id": self.TEST_TENANT_ID,
                    "name": self.TEST_TENANT_NAME
                },
                "user": {
                    "domain": {
                        "id": self.TEST_DOMAIN_ID,
                        "name": self.TEST_DOMAIN_NAME
                    },
                    "id": self.TEST_USER,
                    "name": self.TEST_USER
                },
                "issued_at": "2013-05-29T16:55:21.468960Z",
                "catalog": self.TEST_SERVICE_CATALOG
            },
        }

    def stub_auth(self, subject_token=None, **kwargs):
        if not subject_token:
            subject_token = self.TEST_TOKEN

        self.stub_url("POST", ['auth', 'tokens'],
                      X_Subject_Token=subject_token, **kwargs)
