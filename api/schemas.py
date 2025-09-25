#!/usr/bin/env python3
"""
API Schemas for Network AI Platform
Pydantic models for request/response validation
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Union, Literal

from pydantic import BaseModel, Field, field_validator, computed_field, ConfigDict


# Enums for validation
class DeviceType(str, Enum):
    ROUTER = "Router"
    SWITCH = "Switch"
    LAYER3_SWITCH = "Layer3Switch"
    FIREWALL = "Firewall"
    UNKNOWN = "Unknown"


class QueryType(str, Enum):
    ANALYSIS = "analysis"
    CONFIG_GENERATION = "config_generation"
    TROUBLESHOOTING = "troubleshooting"
    NETWORK_DISCOVERY = "network_discovery"
    OPTIMIZATION = "optimization"


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# Request Models
class ConfigUploadRequest(BaseModel):
    """Request model for config upload (multipart form data)"""
    hostname: Optional[str] = Field(None, description="Override hostname from config")
    device_type: Optional[DeviceType] = Field(None, description="Device type if known")


class QueryRequest(BaseModel):
    """Request model for AI queries"""
    query: str = Field(..., min_length=1, max_length=1000, description="Natural language query")
    context: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Additional context")
    session_id: Optional[int] = Field(None, description="Network session ID")
    device_ids: Optional[List[int]] = Field(default_factory=list, description="Specific devices to query")

    @field_validator("query", mode="before")
    @classmethod
    def validate_query(cls, v: Any) -> str:
        if isinstance(v, str):
            v = v.strip()
        if not v:
            raise ValueError("query cannot be empty")
        return v


class NetworkSessionCreate(BaseModel):
    """Create a new network session"""
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=1000)
    device_ids: List[int] = Field(default_factory=list)


class ConfigChangeRequest(BaseModel):
    """Request to apply configuration changes"""
    device_id: int
    config_changes: List[str] = Field(..., description="List of configuration commands")
    dry_run: bool = Field(default=True, description="Preview changes without applying")
    risk_assessment: bool = Field(default=True, description="Perform risk assessment")


# Response Models
class ConfigUploadResponse(BaseModel):
    """Response for config upload"""
    device_id: int
    hostname: str
    device_type: str
    interfaces_count: int
    vlans_count: int
    vrfs_count: int
    message: str
    warnings: Optional[List[str]] = Field(default_factory=list)


class DeviceInfo(BaseModel):
    """Basic device information"""
    id: int
    hostname: str
    device_type: str
    mgmt_ip: Optional[str] = None
    interfaces_count: int
    vlans_count: int
    vrfs_count: int
    is_active: bool = True
    last_updated: datetime

    model_config = ConfigDict(from_attributes=True)


class InterfaceInfo(BaseModel):
    """Interface information"""
    name: str
    description: Optional[str] = None
    ip_address: Optional[str] = None
    subnet_mask: Optional[str] = None
    vrf_name: Optional[str] = None
    access_vlan: Optional[int] = None
    trunk_vlans: Optional[List[int]] = Field(default_factory=list)
    admin_status: Optional[str] = None
    oper_status: Optional[str] = None


class VLANInfo(BaseModel):
    """VLAN information"""
    vlan_id: int
    name: Optional[str] = None
    status: Optional[str] = None
    access_ports: List[str] = Field(default_factory=list)
    trunk_ports: List[str] = Field(default_factory=list)


class VRFInfo(BaseModel):
    """VRF information"""
    name: str
    rd: Optional[str] = None
    import_targets: List[str] = Field(default_factory=list)
    export_targets: List[str] = Field(default_factory=list)
    interfaces: List[str] = Field(default_factory=list)


class RouteInfo(BaseModel):
    """Route information"""
    network: str
    mask: Optional[str] = None
    next_hop: Optional[str] = None
    interface: Optional[str] = None
    protocol: Optional[str] = None
    admin_distance: Optional[int] = None
    metric: Optional[int] = None
    vrf_name: Optional[str] = None


class DeviceDetail(BaseModel):
    """Detailed device information"""
    id: int
    hostname: str
    device_type: str
    vendor: Optional[str] = None
    model: Optional[str] = None
    ios_version: Optional[str] = None
    mgmt_ip: Optional[str] = None
    interfaces: List[InterfaceInfo] = Field(default_factory=list)
    vlans: List[VLANInfo] = Field(default_factory=list)
    vrfs: List[VRFInfo] = Field(default_factory=list)
    routes: List[RouteInfo] = Field(default_factory=list)
    is_active: bool = True
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ConfigChangeInfo(BaseModel):
    """Configuration change information"""
    device_hostname: str
    commands: List[str]
    description: str
    risk_level: RiskLevel
    impact_description: Optional[str] = None


class QueryResponse(BaseModel):
    """Response for AI queries"""
    query: str
    response: str
    query_type: Optional[QueryType] = None
    config_changes: List[ConfigChangeInfo] = Field(default_factory=list)
    affected_devices: List[str] = Field(default_factory=list)
    confidence: float = Field(0.0, ge=0.0, le=1.0, description="Confidence score 0-1")
    suggestions: Optional[List[str]] = Field(default_factory=list)
    warnings: Optional[List[str]] = Field(default_factory=list)
    processing_time: Optional[float] = None


class TopologyNode(BaseModel):
    """Network topology node"""
    id: str
    hostname: str
    device_type: str
    mgmt_ip: Optional[str] = None
    position: Optional[Dict[str, float]] = Field(default_factory=dict)  # x, y coordinates
    interfaces: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class TopologyLink(BaseModel):
    """Network topology link"""
    id: str
    source: str  # Source device hostname
    target: str  # Target device hostname
    source_interface: str
    target_interface: str
    link_type: Optional[str] = None
    speed: Optional[str] = None
    discovered_by: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class NetworkTopology(BaseModel):
    """Complete network topology"""
    nodes: List[TopologyNode] = Field(default_factory=list)
    links: List[TopologyLink] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class NetworkSummaryResponse(BaseModel):
    """Network overview summary"""
    total_devices: int
    total_interfaces: int
    total_vlans: int
    total_vrfs: int
    device_types: Dict[str, int] = Field(default_factory=dict)
    topology: Optional[Dict[str, Any]] = Field(default_factory=dict)
    health_score: Optional[float] = Field(None, ge=0.0, le=100.0)
    last_updated: datetime = Field(default_factory=datetime.now)


class RoutingPath(BaseModel):
    """Routing path between two endpoints"""
    source: str
    destination: str
    hops: List[Dict[str, str]] = Field(default_factory=list)  # List of {device, interface, next_hop}
    total_cost: Optional[int] = None
    path_type: Optional[str] = None  # primary, backup, equal-cost


class PathAnalysisResponse(BaseModel):
    """Response for path analysis"""
    source: str
    destination: str
    paths: List[RoutingPath] = Field(default_factory=list)
    analysis: Optional[str] = None
    recommendations: List[str] = Field(default_factory=list)


class NetworkSessionResponse(BaseModel):
    """Network session information"""
    id: int
    name: str
    description: Optional[str] = None
    device_count: int
    devices: List[DeviceInfo] = Field(default_factory=list)
    is_active: bool = True
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class QueryHistoryResponse(BaseModel):
    """Query history information"""
    id: int
    query_text: str
    response_text: str
    query_type: Optional[QueryType] = None
    confidence_score: Optional[float] = None
    processing_time: Optional[float] = None
    user_rating: Optional[int] = Field(None, ge=1, le=5)
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class NetworkHealthCheck(BaseModel):
    """Network health check results"""
    overall_health: float = Field(..., ge=0.0, le=100.0)
    checks: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    recommendations: List[str] = Field(default_factory=list)
    critical_issues: List[str] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=datetime.now)


class BestPracticesReport(BaseModel):
    """Best practices compliance report"""
    device_hostname: str
    overall_score: float = Field(..., ge=0.0, le=100.0)
    categories: Dict[str, Dict[str, Any]] = Field(default_factory=dict)  # security, performance, etc.
    violations: List[Dict[str, str]] = Field(default_factory=list)
    recommendations: List[Dict[str, str]] = Field(default_factory=list)
    compliance_level: str  # excellent, good, fair, poor


class ConfigValidationResponse(BaseModel):
    """Configuration validation results"""
    is_valid: bool
    syntax_errors: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)
    suggestions: List[str] = Field(default_factory=list)
    risk_assessment: Optional[Dict[str, Any]] = None


class BulkConfigChangeRequest(BaseModel):
    """Bulk configuration change request"""
    changes: List[ConfigChangeRequest]
    description: str
    schedule_time: Optional[datetime] = None
    rollback_timeout: int = Field(default=300, description="Rollback timeout in seconds")


class BulkConfigChangeResponse(BaseModel):
    """Bulk configuration change response"""
    job_id: str
    total_devices: int
    status: str  # pending, running, completed, failed
    results: List[Dict[str, Any]] = Field(default_factory=list)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None


# Error Response Models
class ErrorResponse(BaseModel):
    """Standard error response"""
    error: str
    detail: Optional[str] = None
    error_code: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.now)


class ValidationErrorResponse(BaseModel):
    """Validation error response"""
    error: str = "Validation Error"
    detail: List[Dict[str, Any]] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=datetime.now)


# WebSocket Message Models
class WebSocketMessage(BaseModel):
    """Base WebSocket message"""
    type: str
    timestamp: datetime = Field(default_factory=datetime.now)
    data: Dict[str, Any] = Field(default_factory=dict)


class NetworkStatusUpdate(WebSocketMessage):
    """Network status update via WebSocket"""
    type: str = "network_status"
    devices_online: int
    devices_offline: int
    active_sessions: int
    recent_queries: int


class DeviceStatusUpdate(WebSocketMessage):
    """Device status update via WebSocket"""
    type: str = "device_status"
    device_id: int
    hostname: str
    status: str  # online, offline, unreachable
    last_seen: datetime


class ConfigChangeNotification(WebSocketMessage):
    """Configuration change notification"""
    type: str = "config_change"
    device_id: int
    hostname: str
    change_summary: str
    risk_level: RiskLevel
    status: str  # pending, applied, failed


# Utility Models
class PaginationParams(BaseModel):
    """Pagination parameters"""
    page: int = Field(1, ge=1, description="Page number starting from 1")
    size: int = Field(50, ge=1, le=1000, description="Number of items per page")
    sort_by: Optional[str] = Field(None, description="Sort field")
    sort_order: Optional[Literal["asc", "desc"]] = Field("asc", description="Sort order")


class PaginatedResponse(BaseModel):
    """Paginated response wrapper"""
    items: List[Any]
    total: int
    page: int
    size: int

    @computed_field
    @property
    def pages(self) -> int:
        size = max(1, int(self.size or 1))
        # ceil(total / size), minimum 1
        return max(1, (int(self.total or 0) + size - 1) // size)

    @computed_field
    @property
    def has_next(self) -> bool:
        return int(self.page or 1) < self.pages

    @computed_field
    @property
    def has_prev(self) -> bool:
        return int(self.page or 1) > 1