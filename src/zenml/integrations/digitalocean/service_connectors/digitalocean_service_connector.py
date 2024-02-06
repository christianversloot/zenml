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
"""DigitalOcean Service Connector.

The DigitalOcean Service Connector allows authenticating to DigitalOcean resources.
"""
import base64
import io
from typing import Any, List, Optional, Type

from pydantic import Field, SecretStr
from pydo import Client

from zenml.exceptions import AuthorizationException
from zenml.integrations.digitalocean import (
    DIGITALOCEAN_CONNECTOR_TYPE,
    DIGITALOCEAN_BUCKET_RESOURCE_TYPE,
    DIGITALOCEAN_CONTAINER_REGISTRY_RESOURCE_TYPE,
)
from zenml.logger import get_logger
from zenml.models import (
    AuthenticationMethodModel,
    ResourceTypeModel,
    ServiceConnectorTypeModel,
)
from zenml.service_connectors.service_connector import (
    AuthenticationConfig,
    ServiceConnector,
)
from zenml.utils.enum_utils import StrEnum

logger = get_logger(__name__)


class DigitalOceanCredentials(AuthenticationConfig):
    """DigitalOcean client authentication credentials."""

    api_token: SecretStr = Field(
        title="DigitalOcean API token",
        description="The API token for DigitalOcean resources."
    )

    spaces_access_key: SecretStr = Field(
        title="DigitalOcean Spaces access key",
        description="The access key for the DigitalOcean Spaces bucket.",
    )

    spaces_secret_key: SecretStr = Field(
        title="DigitalOcean Spaces secret key",
        description="The secret key for the DigitalOcean Spaces bucket.",
    )


class DigitalOceanConfiguration(DigitalOceanCredentials):
    """DigitalOcean client configuration."""

    spaces_region: str = "ams3"


class DigitalOceanAuthenticationMethods(StrEnum):
    """DigitalOcean Authentication methods."""

    API_TOKEN = "api-token"


DIGITALOCEAN_SERVICE_CONNECTOR_TYPE_SPEC = ServiceConnectorTypeModel(
    name="DigitalOcean Service Connector",
    connector_type=DIGITALOCEAN_CONNECTOR_TYPE,
    description="""
The ZenML DigitalOcean Service Connector allows authenticating to DigitalOcean resources.

This connector provides an authenticated `pydo` client which allows users to interact
with DigitalOcean resources.
""",
    logo_url="https://public-flavor-logos.s3.eu-central-1.amazonaws.com/connectors/digitalocean/digitalocean.png",
    emoji=":ocean:",
    auth_methods=[
        AuthenticationMethodModel(
            name="API token and Spaces credentials",
            auth_method=DigitalOceanAuthenticationMethods.API_TOKEN,
            description="""
Use a DigitalOcean API token to authenticate with DigitalOcean resources. Because DigitalOcean
Spaces are configured differently, you also need to provide the access and secret keys for the
Spaces bucket.
""",
            config_class=DigitalOceanConfiguration,
        ),
    ],
    resource_types=[
        ResourceTypeModel(
            name="DigitalOcean Spaces bucket",
            resource_type=DIGITALOCEAN_BUCKET_RESOURCE_TYPE,
            description="""
Allows users to interact with DigitalOcean Spaces buckets, which can be used as
Artifacts Stores in ZenML.
""",
            auth_methods=DigitalOceanAuthenticationMethods.values(),
            supports_instances=True,
            logo_url="https://public-flavor-logos.s3.eu-central-1.amazonaws.com/connectors/digitalocean/digitalocean.png",
            emoji=":ocean:",
        ),
        ResourceTypeModel(
            name="DigitalOcean Container Registry",
            resource_type=DIGITALOCEAN_CONTAINER_REGISTRY_RESOURCE_TYPE,
            description="""
Allows users to interact with DigitalOcean Container Registries, which can be used
as Container Registries in ZenML.
""",
            auth_methods=DigitalOceanAuthenticationMethods.values(),
            supports_instances=True,
            logo_url="https://public-flavor-logos.s3.eu-central-1.amazonaws.com/connectors/digitalocean/digitalocean.png",
            emoji=":ocean:",
        ),
    ],
)


class DigitalOceanServiceConnector(ServiceConnector):
    """DigitalOcean service connector."""

    config: DigitalOceanConfiguration

    @classmethod
    def _get_connector_type(cls) -> ServiceConnectorTypeModel:
        """Get the service connector specification.

        Returns:
            The service connector specification.
        """
        return DIGITALOCEAN_SERVICE_CONNECTOR_TYPE_SPEC

    def _create_pydo_client(
        self, api_token: str
    ) -> Client:
        """Create a pydo Client based on the configuration.

        Args:
            api_token: The DigitalOcean API token.

        Returns:
            A pydo Client.

        Raises:
            AuthorizationException: If the client cannot be created.
        """
        # Connect to the DigitalOcean API
        try:
            return Client(token=api_token)
        except Exception as e:
            logger.error(
                "Unknown error while creating pydo client for DigitalOcean: %s",
                e,
            )
            raise AuthorizationException(
                "Could not create pydo client for DigitalOcean."
            )

    def _authorize_client(self, api_token: str) -> None:
        """Verify that the client can authenticate with DigitalOcean.

        Args:
            api_token: The DigitalOcean API token.
        """
        logger.info("Verifying connection to DigitalOcean...")
        
        self._create_pydo_client(api_token)

    def _connect_to_resource(
        self,
        **kwargs: Any,
    ) -> Any:
        """Connect to DigitalOcean. Returns a pydo client.

        Args:
            kwargs: Additional implementation specific keyword arguments to pass
                to the session or client constructor.

        Returns:
            A pydo client.
        """
        logger.info("Connecting to DigitalOcean...")
        assert self.resource_id is not None
        
        return self._create_pydo_client(self.config.api_token.get_secret_value())

    def _configure_local_client(
        self,
        **kwargs: Any,
    ) -> None:
        """There is no local client for the DigitalOcean connector, so it does nothing.

        Args:
            kwargs: Additional implementation specific keyword arguments to pass
                to the session or client constructor.

        Raises:
            NotImplementedError: If there is no local client for the DigitalOcean
                connector.
        """
        raise NotImplementedError(
            "There is no local client for the DigitalOcean service connector."
        )

    @classmethod
    def _auto_configure(
        cls,
        auth_method: Optional[str] = None,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        **kwargs: Any,
    ) -> "DigitalOceanServiceConnector":
        """Auto-configure the connector.

        Not supported by the DigitalOcean connector.

        Args:
            auth_method: The particular authentication method to use. If not
                specified, the connector implementation must decide which
                authentication method to use or raise an exception.
            resource_type: The type of resource to configure.
            resource_id: The ID of the resource to configure. The
                implementation may choose to either require or ignore this
                parameter if it does not support or detect an resource type that
                supports multiple instances.
            kwargs: Additional implementation specific keyword arguments to use.

        Raises:
            NotImplementedError: If the connector auto-configuration fails or
                is not supported.
        """
        raise NotImplementedError(
            "Auto-configuration is not supported by the DigitalOcean service connector."
        )
    
    def _parse_s3_resource_id(self, resource_id: str) -> str:
        """Validate and convert an S3 resource ID to an S3 bucket name.

        Args:
            resource_id: The resource ID to convert.

        Returns:
            The S3 bucket name.

        Raises:
            ValueError: If the provided resource ID is not a valid S3 bucket
                name, ARN or URI.
        """
        # The resource ID could mean different things:
        #
        # - an S3 bucket ARN
        # - an S3 bucket URI
        # - the S3 bucket name
        #
        # We need to extract the bucket name from the provided resource ID
        bucket_name: Optional[str] = None
        if re.match(
            r"^arn:aws:s3:::[a-z0-9-]+(/.*)*$",
            resource_id,
        ):
            # The resource ID is an S3 bucket ARN
            bucket_name = resource_id.split(":")[-1].split("/")[0]
        elif re.match(
            r"^s3://[a-z0-9-]+(/.*)*$",
            resource_id,
        ):
            # The resource ID is an S3 bucket URI
            bucket_name = resource_id.split("/")[2]
        elif re.match(
            r"^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$",
            resource_id,
        ):
            # The resource ID is the S3 bucket name
            bucket_name = resource_id
        else:
            raise ValueError(
                f"Invalid resource ID for an S3 bucket: {resource_id}. "
                f"Supported formats are:\n"
                f"S3 bucket ARN: arn:aws:s3:::<bucket-name>\n"
                f"S3 bucket URI: s3://<bucket-name>\n"
                f"S3 bucket name: <bucket-name>"
            )

        return bucket_name

    def _verify(
        self,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
    ) -> List[str]:
        """Verify that a connection can be established to the DigitalOcean instance.

        Args:
            resource_type: The type of the resource to verify. If omitted and
                if the connector supports multiple resource types, the
                implementation must verify that it can authenticate and connect
                to any and all of the supported resource types.
            resource_id: The ID of the resource to connect to. Omitted if a
                resource type is not specified. It has the same value as the
                default resource ID if the supplied resource type doesn't
                support multiple instances. If the supplied resource type does
                allows multiple instances, this parameter may still be omitted
                to fetch a list of resource IDs identifying all the resources
                of the indicated type that the connector can access.

        Returns:
            The resource ID if the connection can be established.

        Raises:
            ValueError: If the resource ID is not in the list of configured
                hostnames.
        """
        # Get client
        client = self._create_pydo_client(
            self.config.api_token.get_secret_value()
        )

        # Verify the resource type
        if not resource_type:
            return []
        
        # Verify if bucket resource type
        if resource_type == DIGITALOCEAN_BUCKET_RESOURCE_TYPE:
            assert resource_id is not None

            import boto3
            from botocore.exceptions import ClientError, BotoCoreError
            # Create an S3 client
            s3 = boto3.client(
                "s3",
                endpoint_url=f"https://{self.config.spaces_region}.digitaloceanspaces.com",
                aws_access_key_id=self.config.spaces_access_key.get_secret_value(),
                aws_secret_access_key=self.config.spaces_secret_key.get_secret_value(),
            )

            if not resource_id:
                # List all S3 buckets
                try:
                    response = s3.list_buckets()
                except (ClientError, BotoCoreError) as e:
                    msg = f"failed to list S3 buckets: {e}"
                    logger.error(msg)
                    raise AuthorizationException(msg) from e

                return [
                    f"s3://{bucket['Name']}" for bucket in response["Buckets"]
                ]
            else:
                # Check if the specified S3 bucket exists
                bucket_name = self._parse_s3_resource_id(resource_id)
                try:
                    s3.head_bucket(Bucket=bucket_name)
                    return [resource_id]
                except (ClientError, BotoCoreError) as e:
                    msg = f"failed to fetch S3 bucket {bucket_name}: {e}"
                    logger.error(msg)
                    raise AuthorizationException(msg) from e
