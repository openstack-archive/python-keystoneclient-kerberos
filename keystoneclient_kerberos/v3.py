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

from keystoneclient.auth.identity import v3
import requests_kerberos


class KerberosMethod(v3.AuthMethod):

    _method_parameters = []

    def get_auth_data(self, session, auth, headers, request_kwargs, **kwargs):
        # NOTE(jamielennox): request_kwargs is passed as a kwarg however it is
        # required and always present when called from keystoneclient.
        request_kwargs['requests_auth'] = requests_kerberos.HTTPKerberosAuth(
            mutual_authentication=requests_kerberos.OPTIONAL)
        return 'kerberos', {}


class Kerberos(v3.AuthConstructor):
    _auth_method_class = KerberosMethod
