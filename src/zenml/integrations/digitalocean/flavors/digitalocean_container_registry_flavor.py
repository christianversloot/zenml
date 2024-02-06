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
"""DigitalOcean container registry flavor."""

from typing import TYPE_CHECKING, Optional, Type

from pydantic import validator

from zenml.constants import DOCKER_REGISTRY_RESOURCE_TYPE
from zenml.container_registries.base_container_registry import (
    BaseContainerRegistryConfig,
    BaseContainerRegistryFlavor,
)
from zenml.integrations.digitalocean import (
    DIGITALOCEAN_CONNECTOR_TYPE,
    DIGITALOCEAN_CONTAINER_REGISTRY_FLAVOR,
)
from zenml.models import ServiceConnectorRequirements

if TYPE_CHECKING:
    from zenml.integrations.digitalocean.container_registries import (
        DigitalOceanContainerRegistry,
    )


class DigitalOceanContainerRegistryConfig(BaseContainerRegistryConfig):
    """Configuration for DigitalOcean Container Registry."""
    pass


class DigitalOceanContainerRegistryFlavor(BaseContainerRegistryFlavor):
    """DigitalOcean Container Registry flavor."""

    @property
    def name(self) -> str:
        """Name of the flavor.

        Returns:
            The name of the flavor.
        """
        return DIGITALOCEAN_CONTAINER_REGISTRY_FLAVOR

    @property
    def service_connector_requirements(
        self,
    ) -> Optional[ServiceConnectorRequirements]:
        """Service connector resource requirements for service connectors.

        Specifies resource requirements that are used to filter the available
        service connector types that are compatible with this flavor.

        Returns:
            Requirements for compatible service connectors, if a service
            connector is required for this flavor.
        """
        return ServiceConnectorRequirements(
            connector_type=DIGITALOCEAN_CONNECTOR_TYPE,
            resource_type=DOCKER_REGISTRY_RESOURCE_TYPE,
            resource_id_attr="uri",
        )

    @property
    def docs_url(self) -> Optional[str]:
        """A url to point at docs explaining this flavor.

        Returns:
            A flavor docs url.
        """
        return self.generate_default_docs_url()

    @property
    def sdk_docs_url(self) -> Optional[str]:
        """A url to point at SDK docs explaining this flavor.

        Returns:
            A flavor SDK docs url.
        """
        return self.generate_default_sdk_docs_url()

    @property
    def logo_url(self) -> str:
        """A url to represent the flavor in the dashboard.

        Returns:
            The flavor logo.
        """
        return "https://public-flavor-logos.s3.eu-central-1.amazonaws.com/container_registry/digitalocean.png"

    @property
    def config_class(self) -> Type[DigitalOceanContainerRegistryConfig]:
        """Config class for this flavor.

        Returns:
            The config class.
        """
        return DigitalOceanContainerRegistryConfig

    @property
    def implementation_class(self) -> Type["DigitalOceanContainerRegistry"]:
        """Implementation class.

        Returns:
            The implementation class.
        """
        from zenml.integrations.digitalocean.container_registries import (
            DigitalOceanContainerRegistry,
        )

        return DigitalOceanContainerRegistry
