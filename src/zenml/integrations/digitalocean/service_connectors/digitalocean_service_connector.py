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

from zenml.exceptions import AuthorizationException
from zenml.integrations.hyperai import (
    HYPERAI_CONNECTOR_TYPE,
    HYPERAI_RESOURCE_TYPE,
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

    base64_ssh_key: SecretStr = Field(
        title="SSH key (base64)",
    )
    ssh_passphrase: Optional[SecretStr] = Field(
        default=None,
        title="SSH key passphrase",
    )


class DigitalOceanConfiguration(DigitalOceanCredentials):
    """DigitalOcean client configuration."""

    hostnames: List[str] = Field(
        title="Hostnames of the supported DigitalOcean instances.",
    )

    username: str = Field(
        title="Username to use to connect to the DigitalOcean instance.",
    )


class DigitalOceanAuthenticationMethods(StrEnum):
    """DigitalOcean Authentication methods."""

    RSA_KEY_OPTIONAL_PASSPHRASE = "rsa-key"
    DSA_KEY_OPTIONAL_PASSPHRASE = "dsa-key"
    ECDSA_KEY_OPTIONAL_PASSPHRASE = "ecdsa-key"
    ED25519_KEY_OPTIONAL_PASSPHRASE = "ed25519-key"


HYPERAI_SERVICE_CONNECTOR_TYPE_SPEC = ServiceConnectorTypeModel(
    name="DigitalOcean Service Connector",
    connector_type=HYPERAI_CONNECTOR_TYPE,
    description="""
The ZenML DigitalOcean Service Connector allows authenticating to DigitalOcean (hyperai.ai)
GPU equipped instances.

This connector provides an SSH connection to your DigitalOcean instance, which can be
used to run ZenML pipelines.

The instance must be configured to allow SSH connections from the ZenML server.
Docker and Docker Compose must be installed on the DigitalOcean instance. If you want
to use scheduled pipeline runs, also ensure that a working cron daemon is installed
and running on the DigitalOcean instance.
""",
    logo_url="https://public-flavor-logos.s3.eu-central-1.amazonaws.com/connectors/hyperai/hyperai.png",
    emoji=":robot_face:",
    auth_methods=[
        AuthenticationMethodModel(
            name="RSA key with optional passphrase",
            auth_method=DigitalOceanAuthenticationMethods.RSA_KEY_OPTIONAL_PASSPHRASE,
            description="""
Use an RSA private key to authenticate with a DigitalOcean instance. The key may be
encrypted with a passphrase. If the key is encrypted, the passphrase must be
provided. Make sure to provide the key as a Base64 encoded string.
""",
            config_class=DigitalOceanConfiguration,
        ),
        AuthenticationMethodModel(
            name="DSA/DSS key with optional passphrase",
            auth_method=DigitalOceanAuthenticationMethods.DSA_KEY_OPTIONAL_PASSPHRASE,
            description="""
Use a DSA/DSS private key to authenticate with a DigitalOcean instance. The key may be
encrypted with a passphrase. If the key is encrypted, the passphrase must be
provided. Make sure to provide the key as a Base64 encoded string.
""",
            config_class=DigitalOceanConfiguration,
        ),
        AuthenticationMethodModel(
            name="ECDSA key with optional passphrase",
            auth_method=DigitalOceanAuthenticationMethods.ECDSA_KEY_OPTIONAL_PASSPHRASE,
            description="""
Use an ECDSA private key to authenticate with a DigitalOcean instance. The key may be
encrypted with a passphrase. If the key is encrypted, the passphrase must be
provided. Make sure to provide the key as a Base64 encoded string.
""",
            config_class=DigitalOceanConfiguration,
        ),
        AuthenticationMethodModel(
            name="Ed25519 key with optional passphrase",
            auth_method=DigitalOceanAuthenticationMethods.ED25519_KEY_OPTIONAL_PASSPHRASE,
            description="""
Use an Ed25519 private key to authenticate with a DigitalOcean instance. The key may be
encrypted with a passphrase. If the key is encrypted, the passphrase must be
provided. Make sure to provide the key as a Base64 encoded string.
""",
            config_class=DigitalOceanConfiguration,
        ),
    ],
    resource_types=[
        ResourceTypeModel(
            name="DigitalOcean instance",
            resource_type=HYPERAI_RESOURCE_TYPE,
            description="""
Allows users to access a DigitalOcean instance as a resource. When used by
connector consumers, they are provided a pre-authenticated SSH client
instance.
""",
            auth_methods=DigitalOceanAuthenticationMethods.values(),
            supports_instances=True,
            logo_url="https://public-flavor-logos.s3.eu-central-1.amazonaws.com/connectors/hyperai/hyperai.png",
            emoji=":robot_face:",
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
        return HYPERAI_SERVICE_CONNECTOR_TYPE_SPEC

    def _paramiko_key_type_given_auth_method(self) -> Type[paramiko.PKey]:
        """Get the Paramiko key type given the authentication method.

        Returns:
            The Paramiko key type.

        Raises:
            ValueError: If the authentication method is invalid.
        """
        mapping = {
            DigitalOceanAuthenticationMethods.RSA_KEY_OPTIONAL_PASSPHRASE: paramiko.RSAKey,
            DigitalOceanAuthenticationMethods.DSA_KEY_OPTIONAL_PASSPHRASE: paramiko.DSSKey,
            DigitalOceanAuthenticationMethods.ECDSA_KEY_OPTIONAL_PASSPHRASE: paramiko.ECDSAKey,
            DigitalOceanAuthenticationMethods.ED25519_KEY_OPTIONAL_PASSPHRASE: paramiko.Ed25519Key,
        }

        try:
            return mapping[DigitalOceanAuthenticationMethods(self.auth_method)]
        except KeyError:
            raise ValueError(
                f"Invalid authentication method: {self.auth_method}"
            )

    def _create_paramiko_client(
        self, hostname: str
    ) -> paramiko.client.SSHClient:
        """Create a Paramiko SSH client based on the configuration.

        Args:
            hostname: The hostname of the DigitalOcean instance.

        Returns:
            A Paramiko SSH client.

        Raises:
            AuthorizationException: If the client cannot be created.
        """
        if self.config.ssh_passphrase is None:
            ssh_passphrase = None
        else:
            ssh_passphrase = self.config.ssh_passphrase.get_secret_value()

        # Connect to the DigitalOcean instance
        try:
            # Convert the SSH key from base64 to string
            base64_key_value = self.config.base64_ssh_key.get_secret_value()
            ssh_key = base64.b64decode(base64_key_value).decode("utf-8")
            paramiko_key = None

            with io.StringIO(ssh_key) as f:
                paramiko_key = self._paramiko_key_type_given_auth_method().from_private_key(
                    f, password=ssh_passphrase
                )

            # Trim whitespace from the IP address
            hostname = hostname.strip()

            paramiko_client = paramiko.client.SSHClient()
            paramiko_client.set_missing_host_key_policy(
                paramiko.AutoAddPolicy()  # nosec
            )
            paramiko_client.connect(
                hostname=hostname,
                username=self.config.username,
                pkey=paramiko_key,
                timeout=30,
            )

            return paramiko_client

        except paramiko.ssh_exception.BadHostKeyException as e:
            logger.error("Bad host key: %s", e)
        except paramiko.ssh_exception.AuthenticationException as e:
            logger.error("Authentication failed: %s", e)
        except paramiko.ssh_exception.SSHException as e:
            logger.error(
                "SSH error: %s. A common cause for this error is selection of the wrong key type in your service connector.",
                e,
            )
        except Exception as e:
            logger.error(
                "Unknown error while connecting to DigitalOcean instance: %s. Please check your network connection, IP address, and authentication details.",
                e,
            )

        raise AuthorizationException(
            "Could not create SSH client for DigitalOcean instance."
        )

    def _authorize_client(self, hostname: str) -> None:
        """Verify that the client can authenticate with the DigitalOcean instance.

        Args:
            hostname: The hostname of the DigitalOcean instance.
        """
        logger.info("Verifying connection to DigitalOcean instance...")

        paramiko_client = self._create_paramiko_client(hostname)
        paramiko_client.close()

    def _connect_to_resource(
        self,
        **kwargs: Any,
    ) -> Any:
        """Connect to a DigitalOcean instance. Returns an authenticated SSH client.

        Args:
            kwargs: Additional implementation specific keyword arguments to pass
                to the session or client constructor.

        Returns:
            An authenticated Paramiko SSH client.
        """
        logger.info("Connecting to DigitalOcean instance...")
        assert self.resource_id is not None

        paramiko_client = self._create_paramiko_client(self.resource_id)
        return paramiko_client

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
            "There is no local client for the DigitalOcean connector."
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
            "Auto-configuration is not supported by the DigitalOcean connector."
        )

    def _verify(
        self,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
    ) -> List[str]:
        """Verify that a connection can be established to the DigitalOcean instance.

        Args:
            resource_type: The type of resource to verify. Must be set to the
                Docker resource type.
            resource_id: The DigitalOcean instance to verify.

        Returns:
            The resource ID if the connection can be established.

        Raises:
            ValueError: If the resource ID is not in the list of configured
                hostnames.
        """
        if resource_id:
            if resource_id not in self.config.hostnames:
                raise ValueError(
                    f"The supplied hostname '{resource_id}' is not in the list "
                    f"of configured hostnames: {self.config.hostnames}. Please "
                    f"check your configuration."
                )
            hostnames = [resource_id]
        else:
            hostnames = self.config.hostnames

        resources = []
        for hostname in hostnames:
            self._authorize_client(hostname)
            resources.append(hostname)

        return resources
