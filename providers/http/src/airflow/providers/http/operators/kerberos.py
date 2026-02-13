#
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

from __future__ import annotations

from airflow.providers.common.compat.sdk import BaseHook
from airflow.providers.http.operators.http import HttpOperator


class HttpKerberosOperator(HttpOperator):
    """
    A HttpOperator that uses Kerberos authentication and handles kinit using a keytab file.

    This operator allows you to use an arbitrary keytab and principle to send a request to an external service.
    This enables tasks to use different kerberos principals to airflow's principal for HTTP calls. This operator
    requires apache-airflow[kerberos] to be installed.

    :param principal: Kerberos Principal. This defaults to use the `login` attribute of the HTTP connection.
    :param keytab: Path to keytab file. This can be derived from the `keytab` extra in the HTTP connection.
    """

    def __init__(
        self,
        *,
        principal=None,
        keytab=None,
        **kwargs,
    ):
        self.principal = principal
        self.keytab = keytab

        super().__init__(**kwargs)

    def execute(self, context):
        from requests_kerberos import OPTIONAL, HTTPKerberosAuth

        from airflow.security.kerberos import renew_from_kt

        conn = BaseHook.get_connection(self.http_conn_id)
        if self.keytab is None:
            self.keytab = conn.extra_dejson.get("keytab")
        if self.principal is None:
            self.principal = conn.login

        renew_from_kt(self.principal, self.keytab)
        self.auth_type = HTTPKerberosAuth(principal=self.principal, mutual_authentication=OPTIONAL)

        return super().execute(context)
