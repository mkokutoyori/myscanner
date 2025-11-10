"""
Credentials API endpoints
Manage credentials for authenticated scanning
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc
from typing import List, Optional
from pydantic import BaseModel, Field
from datetime import datetime

from backend.models import get_db, Credential, CredentialType
from backend.core.config import settings

router = APIRouter()


# Pydantic schemas
class CredentialCreate(BaseModel):
    """Create credential request"""
    name: str = Field(..., min_length=1, max_length=255, description="Friendly name for this credential")
    description: Optional[str] = Field(None, description="Description of where this credential is used")
    credential_type: CredentialType = Field(..., description="Type of credential (ssh, winrm, api_key, etc.)")
    username: Optional[str] = Field(None, description="Username (for SSH, WinRM)")
    password: Optional[str] = Field(None, description="Password (will be encrypted)")
    private_key: Optional[str] = Field(None, description="SSH private key (will be encrypted)")
    api_key: Optional[str] = Field(None, description="API key (will be encrypted)")
    metadata: dict = Field(default_factory=dict, description="Additional credential metadata")


class CredentialUpdate(BaseModel):
    """Update credential request"""
    name: Optional[str] = None
    description: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    private_key: Optional[str] = None
    api_key: Optional[str] = None
    metadata: Optional[dict] = None


class CredentialResponse(BaseModel):
    """Credential response schema (secrets are NOT included)"""
    id: int
    name: str
    description: Optional[str]
    credential_type: CredentialType
    username: Optional[str]
    vault_path: Optional[str]
    has_password: bool = False
    has_private_key: bool = False
    has_api_key: bool = False
    metadata: dict
    created_at: datetime
    updated_at: Optional[datetime]
    created_by: Optional[str]
    last_used_at: Optional[datetime]

    class Config:
        from_attributes = True


class CredentialListResponse(BaseModel):
    """Paginated credential list response"""
    total: int
    page: int
    page_size: int
    credentials: List[CredentialResponse]


class CredentialSecrets(BaseModel):
    """Credential secrets (only returned on explicit request)"""
    username: Optional[str] = None
    password: Optional[str] = None
    private_key: Optional[str] = None
    api_key: Optional[str] = None
    metadata: dict = {}


@router.post("/credentials", response_model=CredentialResponse, status_code=201)
async def create_credential(
    credential_data: CredentialCreate,
    db: Session = Depends(get_db)
):
    """
    Create a new credential for authenticated scanning.

    Secrets (password, private_key, api_key) are:
    1. Stored in Vault if available
    2. Or encrypted and stored in database as fallback

    The API never returns secrets in list/get operations.
    Use GET /credentials/{id}/secrets to retrieve secrets.
    """
    # Check if credential with same name exists
    existing = db.query(Credential).filter(Credential.name == credential_data.name).first()
    if existing:
        raise HTTPException(status_code=409, detail=f"Credential with name '{credential_data.name}' already exists")

    # Validate credential data based on type
    if credential_data.credential_type == CredentialType.SSH:
        if not credential_data.username:
            raise HTTPException(status_code=400, detail="Username is required for SSH credentials")
        if not credential_data.password and not credential_data.private_key:
            raise HTTPException(status_code=400, detail="Either password or private_key is required for SSH credentials")

    elif credential_data.credential_type == CredentialType.WINRM:
        if not credential_data.username or not credential_data.password:
            raise HTTPException(status_code=400, detail="Username and password are required for WinRM credentials")

    elif credential_data.credential_type == CredentialType.API_KEY:
        if not credential_data.api_key:
            raise HTTPException(status_code=400, detail="API key is required for API_KEY credentials")

    # Create credential object
    credential = Credential(
        name=credential_data.name,
        description=credential_data.description,
        credential_type=credential_data.credential_type,
        username=credential_data.username,
        asset_metadata=credential_data.metadata,
        created_by="system"  # TODO: Get from auth
    )

    # Store secrets
    # TODO: Implement Vault integration
    # For POC, we store encrypted in DB
    try:
        from backend.services.vault_service import store_credential_secrets
        vault_path = store_credential_secrets(
            credential_id=credential.name,
            secrets={
                "username": credential_data.username,
                "password": credential_data.password,
                "private_key": credential_data.private_key,
                "api_key": credential_data.api_key
            }
        )
        credential.vault_path = vault_path
    except Exception as e:
        # Fallback: store encrypted in DB
        import base64
        import json
        from cryptography.fernet import Fernet

        # Generate encryption key (in production, this should be from config/env)
        # For POC, we use a simple key
        key = base64.urlsafe_b64encode(settings.SECRET_KEY[:32].encode().ljust(32)[:32])
        fernet = Fernet(key)

        secrets = {
            "username": credential_data.username,
            "password": credential_data.password,
            "private_key": credential_data.private_key,
            "api_key": credential_data.api_key
        }

        encrypted_secrets = fernet.encrypt(json.dumps(secrets).encode())
        credential.encrypted_secrets = encrypted_secrets.decode()

    db.add(credential)
    db.commit()
    db.refresh(credential)

    return _credential_to_response(credential)


@router.get("/credentials", response_model=CredentialListResponse)
async def list_credentials(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    credential_type: Optional[CredentialType] = None,
    search: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """
    List all credentials (without secrets).

    - **page**: Page number (starting from 1)
    - **page_size**: Number of items per page (max 100)
    - **credential_type**: Filter by credential type
    - **search**: Search by name or description
    """
    query = db.query(Credential)

    # Apply filters
    if credential_type:
        query = query.filter(Credential.credential_type == credential_type)

    if search:
        query = query.filter(
            (Credential.name.ilike(f"%{search}%")) |
            (Credential.description.ilike(f"%{search}%"))
        )

    # Count total
    total = query.count()

    # Paginate
    credentials = query.order_by(desc(Credential.created_at)).offset((page - 1) * page_size).limit(page_size).all()

    # Convert to response (without secrets)
    credential_responses = [_credential_to_response(cred) for cred in credentials]

    return CredentialListResponse(
        total=total,
        page=page,
        page_size=page_size,
        credentials=credential_responses
    )


@router.get("/credentials/{credential_id}", response_model=CredentialResponse)
async def get_credential(credential_id: int, db: Session = Depends(get_db)):
    """
    Get credential by ID (without secrets).

    Use GET /credentials/{id}/secrets to retrieve secrets.
    """
    credential = db.query(Credential).filter(Credential.id == credential_id).first()
    if not credential:
        raise HTTPException(status_code=404, detail="Credential not found")

    return _credential_to_response(credential)


@router.get("/credentials/{credential_id}/secrets", response_model=CredentialSecrets)
async def get_credential_secrets(credential_id: int, db: Session = Depends(get_db)):
    """
    Get credential secrets (password, private_key, api_key).

    ⚠️ WARNING: This endpoint returns sensitive data.
    In production, this should require elevated permissions.
    """
    credential = db.query(Credential).filter(Credential.id == credential_id).first()
    if not credential:
        raise HTTPException(status_code=404, detail="Credential not found")

    # Update last_used_at
    credential.last_used_at = datetime.utcnow()
    db.commit()

    # Retrieve secrets
    try:
        # Try Vault first
        if credential.vault_path:
            from backend.services.vault_service import get_credential_secrets
            secrets = get_credential_secrets(credential.vault_path)
            return CredentialSecrets(**secrets)
    except Exception as e:
        pass

    # Fallback: decrypt from DB
    if credential.encrypted_secrets:
        import base64
        import json
        from cryptography.fernet import Fernet

        key = base64.urlsafe_b64encode(settings.SECRET_KEY[:32].encode().ljust(32)[:32])
        fernet = Fernet(key)

        try:
            decrypted = fernet.decrypt(credential.encrypted_secrets.encode())
            secrets = json.loads(decrypted.decode())
            return CredentialSecrets(**secrets)
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to decrypt secrets: {str(e)}")

    raise HTTPException(status_code=500, detail="No secrets available")


@router.patch("/credentials/{credential_id}", response_model=CredentialResponse)
async def update_credential(
    credential_id: int,
    credential_data: CredentialUpdate,
    db: Session = Depends(get_db)
):
    """
    Update credential information.

    To update secrets, provide new password/private_key/api_key values.
    """
    credential = db.query(Credential).filter(Credential.id == credential_id).first()
    if not credential:
        raise HTTPException(status_code=404, detail="Credential not found")

    # Update non-secret fields
    if credential_data.name is not None:
        credential.name = credential_data.name
    if credential_data.description is not None:
        credential.description = credential_data.description
    if credential_data.username is not None:
        credential.username = credential_data.username
    if credential_data.metadata is not None:
        credential.asset_metadata = credential_data.metadata

    # Update secrets if provided
    if any([credential_data.password, credential_data.private_key, credential_data.api_key]):
        # Get current secrets
        current_secrets = {}
        if credential.encrypted_secrets:
            import base64
            import json
            from cryptography.fernet import Fernet

            key = base64.urlsafe_b64encode(settings.SECRET_KEY[:32].encode().ljust(32)[:32])
            fernet = Fernet(key)

            try:
                decrypted = fernet.decrypt(credential.encrypted_secrets.encode())
                current_secrets = json.loads(decrypted.decode())
            except:
                pass

        # Update with new values
        if credential_data.password is not None:
            current_secrets["password"] = credential_data.password
        if credential_data.private_key is not None:
            current_secrets["private_key"] = credential_data.private_key
        if credential_data.api_key is not None:
            current_secrets["api_key"] = credential_data.api_key

        current_secrets["username"] = credential.username

        # Re-encrypt
        import base64
        import json
        from cryptography.fernet import Fernet

        key = base64.urlsafe_b64encode(settings.SECRET_KEY[:32].encode().ljust(32)[:32])
        fernet = Fernet(key)

        encrypted_secrets = fernet.encrypt(json.dumps(current_secrets).encode())
        credential.encrypted_secrets = encrypted_secrets.decode()

    credential.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(credential)

    return _credential_to_response(credential)


@router.delete("/credentials/{credential_id}", status_code=204)
async def delete_credential(credential_id: int, db: Session = Depends(get_db)):
    """
    Delete a credential.

    ⚠️ WARNING: This will prevent any scans using this credential from running.
    """
    credential = db.query(Credential).filter(Credential.id == credential_id).first()
    if not credential:
        raise HTTPException(status_code=404, detail="Credential not found")

    # TODO: Delete from Vault if stored there
    if credential.vault_path:
        try:
            from backend.services.vault_service import delete_credential_secrets
            delete_credential_secrets(credential.vault_path)
        except:
            pass

    db.delete(credential)
    db.commit()

    return None


def _credential_to_response(credential: Credential) -> CredentialResponse:
    """Convert Credential model to response (without secrets)"""
    return CredentialResponse(
        id=credential.id,
        name=credential.name,
        description=credential.description,
        credential_type=credential.credential_type,
        username=credential.username,
        vault_path=credential.vault_path,
        has_password=bool(credential.encrypted_secrets and "password" in credential.encrypted_secrets),
        has_private_key=bool(credential.encrypted_secrets and "private_key" in credential.encrypted_secrets),
        has_api_key=bool(credential.encrypted_secrets and "api_key" in credential.encrypted_secrets),
        metadata=credential.asset_metadata or {},
        created_at=credential.created_at,
        updated_at=credential.updated_at,
        created_by=credential.created_by,
        last_used_at=credential.last_used_at
    )
