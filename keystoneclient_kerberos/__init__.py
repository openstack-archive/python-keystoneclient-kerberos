# -*- coding: utf-8 -*-

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

import warnings

import pbr.version

from keystoneclient_kerberos import v3


warnings.warn(
    "The keystoneclient_kerberos package is deprecated in favor of "
    "keystoneauth1 and will not be supported.", DeprecationWarning)

__version__ = pbr.version.VersionInfo(
    'python-keystoneclient-kerberos').version_string()

V3Kerberos = v3.Kerberos
V3FederatedKerberos = v3.FederatedKerberos

__all__ = ('V3FederatedKerberos',
           'V3Kerberos')
