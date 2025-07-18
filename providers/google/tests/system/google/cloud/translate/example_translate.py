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
"""
Example Airflow DAG that translates text in Google Cloud Translate
service in the Google Cloud.
"""

from __future__ import annotations

from datetime import datetime

from airflow.models.dag import DAG
from airflow.providers.google.cloud.operators.translate import CloudTranslateTextOperator
from airflow.providers.standard.operators.bash import BashOperator

from tests_common.test_utils.version_compat import AIRFLOW_V_3_0_PLUS

DAG_ID = "gcp_translate"

with DAG(
    DAG_ID,
    schedule="@once",  # Override to match your needs
    start_date=datetime(2021, 1, 1),
    catchup=False,
    tags=["example", "translate"],
) as dag:
    # [START howto_operator_translate_text]
    product_set_create = CloudTranslateTextOperator(
        task_id="translate",
        values=["zażółć gęślą jaźń"],
        target_language="en",
        format_="text",
        source_language=None,
        model="base",
    )
    # [END howto_operator_translate_text]
    # [START howto_operator_translate_access]
    translation_access = BashOperator(
        task_id="access",
        bash_command="""
        {% if params.airflow_v3 %}
        echo '{{ task_instance.xcom_pull("translate") }}'
        {% else %}
        echo '{{ task_instance.xcom_pull("translate")[0] }}'
        {% endif %}
        """,
        params={"airflow_v3": AIRFLOW_V_3_0_PLUS},
    )
    # [END howto_operator_translate_access]
    product_set_create >> translation_access

    # ### Everything below this line is not part of example ###
    # ### Just for system tests purpose ###
    from tests_common.test_utils.watcher import watcher

    # This test needs watcher in order to properly mark success/failure
    # when "tearDown" task with trigger rule is part of the DAG
    list(dag.tasks) >> watcher()


from tests_common.test_utils.system_tests import get_test_run  # noqa: E402

# Needed to run the example DAG with pytest (see: tests/system/README.md#run_via_pytest)
test_run = get_test_run(dag)
