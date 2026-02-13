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

from unittest import mock

import pytest
import requests_mock
from requests_kerberos import HTTPKerberosAuth

from airflow.providers.common.compat.sdk import Connection
from airflow.providers.http.operators.kerberos import HttpKerberosOperator


@mock.patch.dict("os.environ", AIRFLOW_CONN_HTTP_EXAMPLE="http://www.example.com")
class TestHttpKerberosHook:
    @pytest.fixture(autouse=True)
    def setup_connections(self, create_connection_without_db):
        create_connection_without_db(
            Connection(
                conn_id="http_default", conn_type="http", host="test:8080/", extra='{"bearer": "test"}'
            )
        )

    def test_kerberos_auth(self):
        requests_mock.get("http://www.example.com", text="Example.com fake response")
        principal = "test_principal"
        keytab = "test_keytab"
        mock_context = mock.MagicMock()
        with (
            mock.patch("airflow.security.kerberos.renew_from_kt") as mock_renew,
        ):
            op = HttpKerberosOperator(task_id="test", principal=principal, keytab=keytab)
            res = op.execute(mock_context)
        auth = op.auth_type
        assert isinstance(auth, HTTPKerberosAuth)
        assert auth.principal == principal
        mock_renew.assert_called_once_with(principal, keytab)
        assert res == "Example.com fake response"
