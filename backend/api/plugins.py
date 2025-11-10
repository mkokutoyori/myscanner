"""
Plugins API endpoints
Manage scanning plugins
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List, Optional, Dict, Any
from pydantic import BaseModel

from backend.models import get_db, Plugin, AssetType

router = APIRouter()


# Pydantic schemas
class PluginResponse(BaseModel):
    """Plugin response schema"""
    id: int
    name: str
    display_name: str
    description: Optional[str]
    version: str
    author: Optional[str]
    vendor: Optional[str]
    asset_types: List[str]
    requires_authentication: bool
    is_intrusive: bool
    config_schema: Dict[str, Any]
    is_enabled: bool
    is_verified: bool

    class Config:
        from_attributes = True


class PluginListResponse(BaseModel):
    """Plugin list response"""
    total: int
    plugins: List[PluginResponse]


@router.get("/plugins", response_model=PluginListResponse)
async def list_plugins(
    vendor: Optional[str] = None,
    asset_type: Optional[AssetType] = None,
    enabled_only: bool = False,
    db: Session = Depends(get_db)
):
    """
    List all available plugins

    - **vendor**: Filter by vendor (cisco, juniper, linux, windows, etc.)
    - **asset_type**: Filter by supported asset type
    - **enabled_only**: Only return enabled plugins
    """
    query = db.query(Plugin)

    if vendor:
        query = query.filter(Plugin.vendor == vendor)

    if enabled_only:
        query = query.filter(Plugin.is_enabled == True)

    plugins = query.all()

    # Filter by asset type if specified
    if asset_type:
        plugins = [p for p in plugins if asset_type.value in (p.asset_types or [])]

    return PluginListResponse(
        total=len(plugins),
        plugins=plugins
    )


@router.get("/plugins/{plugin_name}", response_model=PluginResponse)
async def get_plugin(plugin_name: str, db: Session = Depends(get_db)):
    """
    Get plugin by name
    """
    plugin = db.query(Plugin).filter(Plugin.name == plugin_name).first()
    if not plugin:
        raise HTTPException(status_code=404, detail="Plugin not found")

    return plugin


@router.patch("/plugins/{plugin_name}/enable")
async def enable_plugin(plugin_name: str, db: Session = Depends(get_db)):
    """
    Enable a plugin
    """
    plugin = db.query(Plugin).filter(Plugin.name == plugin_name).first()
    if not plugin:
        raise HTTPException(status_code=404, detail="Plugin not found")

    plugin.is_enabled = True
    db.commit()

    return {"message": f"Plugin {plugin_name} enabled"}


@router.patch("/plugins/{plugin_name}/disable")
async def disable_plugin(plugin_name: str, db: Session = Depends(get_db)):
    """
    Disable a plugin
    """
    plugin = db.query(Plugin).filter(Plugin.name == plugin_name).first()
    if not plugin:
        raise HTTPException(status_code=404, detail="Plugin not found")

    plugin.is_enabled = False
    db.commit()

    return {"message": f"Plugin {plugin_name} disabled"}
