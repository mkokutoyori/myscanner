"""
HashiCorp Vault Service
Secure credential storage and retrieval
"""
import hvac
import logging
from typing import Dict, Any, Optional
from backend.core.config import settings

logger = logging.getLogger(__name__)


class VaultService:
    """
    Service for interacting with HashiCorp Vault
    Handles secure storage and retrieval of credentials
    """

    def __init__(self):
        """Initialize Vault client"""
        self.client = None
        self._initialize_client()

    def _initialize_client(self):
        """Initialize Vault client with configuration"""
        try:
            self.client = hvac.Client(
                url=settings.VAULT_ADDR,
                token=settings.VAULT_TOKEN
            )

            if self.client.is_authenticated():
                logger.info("Successfully authenticated with Vault")
            else:
                logger.warning("Vault client initialized but not authenticated")

        except Exception as e:
            logger.error(f"Failed to initialize Vault client: {str(e)}")
            self.client = None

    def is_available(self) -> bool:
        """
        Check if Vault is available and authenticated

        Returns:
            bool: True if Vault is available and authenticated
        """
        try:
            return self.client is not None and self.client.is_authenticated()
        except Exception as e:
            logger.error(f"Error checking Vault availability: {str(e)}")
            return False

    def store_credential(
        self,
        path: str,
        credential: Dict[str, Any],
        mount_point: str = None
    ) -> bool:
        """
        Store a credential in Vault

        Args:
            path: Path in Vault (e.g., "credentials/ssh/server1")
            credential: Dictionary containing credential data
            mount_point: Vault mount point (default from settings)

        Returns:
            bool: True if successful

        Example:
            vault.store_credential(
                "credentials/ssh/server1",
                {
                    "username": "admin",
                    "password": "secret",
                    "private_key": "-----BEGIN RSA PRIVATE KEY-----..."
                }
            )
        """
        if not self.is_available():
            logger.error("Vault is not available")
            return False

        mount_point = mount_point or settings.VAULT_MOUNT_POINT
        full_path = f"{settings.VAULT_PATH_PREFIX}/{path}"

        try:
            self.client.secrets.kv.v2.create_or_update_secret(
                path=full_path,
                secret=credential,
                mount_point=mount_point
            )
            logger.info(f"Successfully stored credential at {full_path}")
            return True

        except Exception as e:
            logger.error(f"Failed to store credential at {full_path}: {str(e)}")
            return False

    def get_credential(
        self,
        path: str,
        mount_point: str = None
    ) -> Optional[Dict[str, Any]]:
        """
        Retrieve a credential from Vault

        Args:
            path: Path in Vault
            mount_point: Vault mount point (default from settings)

        Returns:
            Dictionary containing credential data, or None if not found

        Example:
            cred = vault.get_credential("credentials/ssh/server1")
            username = cred.get("username")
            password = cred.get("password")
        """
        if not self.is_available():
            logger.error("Vault is not available")
            return None

        mount_point = mount_point or settings.VAULT_MOUNT_POINT
        full_path = f"{settings.VAULT_PATH_PREFIX}/{path}"

        try:
            response = self.client.secrets.kv.v2.read_secret_version(
                path=full_path,
                mount_point=mount_point
            )

            credential = response['data']['data']
            logger.info(f"Successfully retrieved credential from {full_path}")
            return credential

        except hvac.exceptions.InvalidPath:
            logger.warning(f"Credential not found at {full_path}")
            return None

        except Exception as e:
            logger.error(f"Failed to retrieve credential from {full_path}: {str(e)}")
            return None

    def delete_credential(
        self,
        path: str,
        mount_point: str = None
    ) -> bool:
        """
        Delete a credential from Vault

        Args:
            path: Path in Vault
            mount_point: Vault mount point (default from settings)

        Returns:
            bool: True if successful
        """
        if not self.is_available():
            logger.error("Vault is not available")
            return False

        mount_point = mount_point or settings.VAULT_MOUNT_POINT
        full_path = f"{settings.VAULT_PATH_PREFIX}/{path}"

        try:
            self.client.secrets.kv.v2.delete_metadata_and_all_versions(
                path=full_path,
                mount_point=mount_point
            )
            logger.info(f"Successfully deleted credential at {full_path}")
            return True

        except Exception as e:
            logger.error(f"Failed to delete credential at {full_path}: {str(e)}")
            return False

    def list_credentials(
        self,
        path: str = "",
        mount_point: str = None
    ) -> Optional[list]:
        """
        List credentials at a path

        Args:
            path: Path in Vault
            mount_point: Vault mount point (default from settings)

        Returns:
            List of credential names, or None if error
        """
        if not self.is_available():
            logger.error("Vault is not available")
            return None

        mount_point = mount_point or settings.VAULT_MOUNT_POINT
        full_path = f"{settings.VAULT_PATH_PREFIX}/{path}" if path else settings.VAULT_PATH_PREFIX

        try:
            response = self.client.secrets.kv.v2.list_secrets(
                path=full_path,
                mount_point=mount_point
            )

            keys = response['data']['keys']
            logger.info(f"Successfully listed {len(keys)} credentials at {full_path}")
            return keys

        except hvac.exceptions.InvalidPath:
            logger.warning(f"No credentials found at {full_path}")
            return []

        except Exception as e:
            logger.error(f"Failed to list credentials at {full_path}: {str(e)}")
            return None


# Global Vault service instance
vault_service = VaultService()


# Convenience functions
def store_ssh_credential(asset_id: int, username: str, password: str = None, private_key: str = None) -> bool:
    """Store SSH credential for an asset"""
    credential = {"username": username}
    if password:
        credential["password"] = password
    if private_key:
        credential["private_key"] = private_key

    return vault_service.store_credential(f"ssh/asset_{asset_id}", credential)


def get_ssh_credential(asset_id: int) -> Optional[Dict[str, Any]]:
    """Get SSH credential for an asset"""
    return vault_service.get_credential(f"ssh/asset_{asset_id}")


def store_db_credential(asset_id: int, username: str, password: str, db_type: str) -> bool:
    """Store database credential for an asset"""
    credential = {
        "username": username,
        "password": password,
        "db_type": db_type
    }
    return vault_service.store_credential(f"database/asset_{asset_id}", credential)


def get_db_credential(asset_id: int) -> Optional[Dict[str, Any]]:
    """Get database credential for an asset"""
    return vault_service.get_credential(f"database/asset_{asset_id}")
