#  Copyright (c) ZenML GmbH 2024. All Rights Reserved.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at:
#
#       https://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
#  or implied. See the License for the specific language governing
#  permissions and limitations under the License.
"""Initialization of the CloudFlare integration.

The CloudFlare integration allows the use of R2 buckets.
"""
from typing import List, Type

from zenml.integrations.constants import CLOUDFLARE
from zenml.integrations.integration import Integration
from zenml.stack import Flavor

CLOUDFLARE_ARTIFACT_STORE_FLAVOR = "cloudflare"


class CloudFlareIntegration(Integration):
    """Definition of CloudFlare integration for ZenML."""

    NAME = CLOUDFLARE
    # boto3 isn't required for the filesystem to work, but it is required
    # for the CloudFlare connector that can be used with the artifact store.
    # NOTE: to keep the dependency resolution for botocore consistent and fast
    # between s3fs and boto3, the boto3 upper version used here should be the
    # same as the one resolved by pip when installing boto3 without a
    # restriction alongside s3fs, e.g.:
    #
    #   pip install 's3fs>2022.3.0,<=2023.4.0' boto3
    #
    # The above command installs boto3==1.26.76, so we use the same version
    # here to avoid the dependency resolution overhead.
    REQUIREMENTS = [
        "s3fs>2022.3.0",
        "boto3",
    ]

    @classmethod
    def flavors(cls) -> List[Type[Flavor]]:
        """Declare the stack component flavors for the s3 integration.

        Returns:
            List of stack component flavors for this integration.
        """
        raise NotImplementedError("Todo")
        from zenml.integrations.s3.flavors import S3ArtifactStoreFlavor

        return [S3ArtifactStoreFlavor]


CloudFlareIntegration.check_installation()
