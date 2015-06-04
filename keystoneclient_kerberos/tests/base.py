# -*- coding: utf-8 -*-

# Copyright 2010-2011 OpenStack Foundation
# Copyright (c) 2013 Hewlett-Packard Development Company, L.P.
#
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

from oslotest import base
from requests_mock.contrib import fixture as requests_fixture

from keystoneclient_kerberos.tests import utils


REQUEST = {'auth': {'identity': {'methods': ['kerberos'],
                                 'kerberos': {}}}}


class TestCase(base.BaseTestCase):
    """Test case base class for all unit tests."""

    TEST_ROOT_URL = 'http://keystoneserver.test.com:5000/'

    def setUp(self):
        super(TestCase, self).setUp()

        self.requests_mock = self.useFixture(requests_fixture.Fixture())
        self.kerberos_mock = self.useFixture(utils.KerberosMock())

    def assertRequestBody(self, body=None):
        if not body:
            body = self.requests_mock.last_request.json()

        request = {'auth': {'identity': {'methods': ['kerberos'],
                                         'kerberos': {}}}}
        self.assertEqual(request, body)
