#!/usr/bin/env python3
"""
Database Models for Network AI Platform
SQLAlchemy models for storing network configuration data
"""

from sqlalchemy import Column, Integer, String, Text, DateTime, JSON, Boolean, ForeignKey, Float
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from datetime import datetime
import json

Base = declarative_base()

class Device(Base):
    """Device configuration and parsed data"""
    __tablename__ = "devices"
    
    id = Column(Integer, primary_key=True, index=True)
    hostname = Column(String(255), unique=True, index=True, nullable=False)
    device_type = Column(String(50), default="Unknown")  # Router, Switch, Layer3Switch, etc.
    vendor = Column(String(50), default="Cisco")
    model = Column(String(100))
    ios_version = Column(String(100))
    
    # Configuration data
    config_text = Column(Text, nullable=False)  # Raw configuration
    config_hash = Column(String(64))  # MD5 hash for change detection
    
    # Parsed structured data (JSON)
    parsed_data = Column(JSON)  # All parsed interfaces, VLANs, VRFs, etc.
    
    # Management info
    mgmt_ip = Column(String(45))  # IPv4 or IPv6
    snmp_community = Column(String(255))
    
    # Status
    is_active = Column(Boolean, default=True)
    last_seen = Column(DateTime)
    
    # Timestamps
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())
    
    # Relationships
    interfaces = relationship("Interface", back_populates="device", cascade="all, delete-orphan")
    vlans = relationship("VLAN", back_populates="device", cascade="all, delete-orphan")
    vrfs = relationship("VRF", back_populates="device", cascade="all, delete-orphan")
    routes = relationship("Route", back_populates="device", cascade="all, delete-orphan")
    # Remove the problematic relationship - we'll use JSON device_ids instead
    
    def __repr__(self):
        return f"<Device(hostname='{self.hostname}', type='{self.device_type}')>"
    
    def to_dict(self):
        """Convert to dictionary for JSON serialization"""
        return {
            'id': self.id,
            'hostname': self.hostname,
            'device_type': self.device_type,
            'vendor': self.vendor,
            'model': self.model,
            'ios_version': self.ios_version,
            'mgmt_ip': self.mgmt_ip,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

class Interface(Base):
    """Network interface details"""
    __tablename__ = "interfaces"
    
    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(Integer, ForeignKey("devices.id"), nullable=False)
    
    # Interface identification
    name = Column(String(100), nullable=False)  # GigabitEthernet1/1, Vlan10, etc.
    description = Column(String(255))
    interface_type = Column(String(50))  # Physical, SVI, Loopback, etc.
    
    # Layer 3 configuration
    ip_address = Column(String(45))
    subnet_mask = Column(String(45))
    vrf_name = Column(String(100))
    
    # Layer 2 configuration
    access_vlan = Column(Integer)
    native_vlan = Column(Integer)
    trunk_vlans = Column(JSON)  # List of allowed VLANs
    
    # Status
    admin_status = Column(String(20))  # up, down, administratively down
    oper_status = Column(String(20))   # up, down
    speed = Column(String(20))
    duplex = Column(String(20))
    
    # Physical attributes
    media_type = Column(String(50))
    port_channel_id = Column(Integer)
    
    # Timestamps
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())
    
    # Relationships
    device = relationship("Device", back_populates="interfaces")
    
    def __repr__(self):
        return f"<Interface(name='{self.name}', device='{self.device.hostname if self.device else 'Unknown'}')>"

class VLAN(Base):
    """VLAN configuration"""
    __tablename__ = "vlans"
    
    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(Integer, ForeignKey("devices.id"), nullable=False)
    
    # VLAN details
    vlan_id = Column(Integer, nullable=False)
    name = Column(String(255))
    status = Column(String(20))  # active, suspend, etc.
    
    # Associated interfaces (JSON list)
    access_ports = Column(JSON)  # Interfaces with this VLAN as access
    trunk_ports = Column(JSON)   # Interfaces trunking this VLAN
    
    # Timestamps
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())
    
    # Relationships
    device = relationship("Device", back_populates="vlans")
    
    def __repr__(self):
        return f"<VLAN(id={self.vlan_id}, name='{self.name}', device='{self.device.hostname if self.device else 'Unknown'}')>"

class VRF(Base):
    """VRF (Virtual Routing and Forwarding) configuration"""
    __tablename__ = "vrfs"
    
    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(Integer, ForeignKey("devices.id"), nullable=False)
    
    # VRF details
    name = Column(String(100), nullable=False)
    rd = Column(String(50))  # Route Distinguisher
    
    # Route targets (JSON lists)
    import_targets = Column(JSON)
    export_targets = Column(JSON)
    
    # Associated interfaces
    interfaces = Column(JSON)  # List of interface names
    
    # Timestamps
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())
    
    # Relationships  
    device = relationship("Device", back_populates="vrfs")
    
    def __repr__(self):
        return f"<VRF(name='{self.name}', rd='{self.rd}', device='{self.device.hostname if self.device else 'Unknown'}')>"

class Route(Base):
    """Routing table entries"""
    __tablename__ = "routes"
    
    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(Integer, ForeignKey("devices.id"), nullable=False)
    
    # Route details
    network = Column(String(45), nullable=False)
    mask = Column(String(45))
    prefix_length = Column(Integer)  # CIDR notation
    
    # Routing info
    next_hop = Column(String(45))
    interface = Column(String(100))
    protocol = Column(String(20))  # Static, OSPF, EIGRP, BGP, Connected, etc.
    
    # Metrics
    admin_distance = Column(Integer)
    metric = Column(Integer)
    
    # VRF context
    vrf_name = Column(String(100))
    
    # Timestamps
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())
    
    # Relationships
    device = relationship("Device", back_populates="routes")
    
    def __repr__(self):
        return f"<Route(network='{self.network}', next_hop='{self.next_hop}', protocol='{self.protocol}')>"

class NetworkSession(Base):
    """Network analysis sessions"""
    __tablename__ = "network_sessions"
    
    id = Column(Integer, primary_key=True, index=True)
    
    # Session details
    name = Column(String(255), nullable=False)
    description = Column(Text)
    
    # Associated devices (store as JSON list of device IDs)
    device_ids = Column(JSON, default=list)  # List of device IDs in this session
    
    # Session data
    topology_data = Column(JSON, default=dict)  # Calculated topology information
    analysis_results = Column(JSON, default=dict)  # AI analysis results
    
    # Status
    is_active = Column(Boolean, default=True)
    
    # Timestamps
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())
    
    # Keep the queries relationship since it has proper foreign key
    queries = relationship("QueryHistory", back_populates="session")
    
    def __repr__(self):
        return f"<NetworkSession(name='{self.name}', devices={len(self.device_ids or [])})>"
    
    def get_devices(self, db_session):
        """Get actual device objects for this session"""
        if not self.device_ids:
            return []
        return db_session.query(Device).filter(Device.id.in_(self.device_ids)).all()

class QueryHistory(Base):
    """History of AI queries and responses"""
    __tablename__ = "query_history"
    
    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(Integer, ForeignKey("network_sessions.id"))
    
    # Query details
    query_text = Column(Text, nullable=False)
    query_type = Column(String(50))  # analysis, config_generation, troubleshooting, etc.
    
    # Response
    response_text = Column(Text)
    config_changes = Column(JSON)  # Generated configuration changes
    affected_devices = Column(JSON)  # List of device IDs affected
    
    # Metadata
    confidence_score = Column(Float)
    processing_time = Column(Float)  # Seconds
    
    # User feedback
    user_rating = Column(Integer)  # 1-5 stars
    user_feedback = Column(Text)
    
    # Timestamps
    created_at = Column(DateTime, server_default=func.now())
    
    # Relationships
    session = relationship("NetworkSession", back_populates="queries")
    
    def __repr__(self):
        return f"<QueryHistory(query='{self.query_text[:50]}...', confidence={self.confidence_score})>"

class ConfigChange(Base):
    """Track configuration changes and their impact"""
    __tablename__ = "config_changes"
    
    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(Integer, ForeignKey("devices.id"), nullable=False)
    query_id = Column(Integer, ForeignKey("query_history.id"))
    
    # Change details
    change_type = Column(String(50))  # add, modify, delete
    config_section = Column(String(100))  # interface, vlan, routing, etc.
    
    # Configuration
    old_config = Column(Text)
    new_config = Column(Text)
    config_diff = Column(Text)
    
    # Impact analysis
    risk_level = Column(String(20))  # low, medium, high, critical
    impact_description = Column(Text)
    rollback_config = Column(Text)
    
    # Status
    status = Column(String(20))  # pending, applied, failed, rolled_back
    applied_at = Column(DateTime)
    rollback_at = Column(DateTime)
    
    # Timestamps
    created_at = Column(DateTime, server_default=func.now())
    
    def __repr__(self):
        return f"<ConfigChange(type='{self.change_type}', section='{self.config_section}', risk='{self.risk_level}')>"

class NetworkTopologyLink(Base):
    """Network topology connections between devices"""
    __tablename__ = "topology_links"
    
    id = Column(Integer, primary_key=True, index=True)
    
    # Source device and interface
    source_device_id = Column(Integer, ForeignKey("devices.id"), nullable=False)
    source_interface = Column(String(100), nullable=False)
    
    # Destination device and interface  
    dest_device_id = Column(Integer, ForeignKey("devices.id"), nullable=False)
    dest_interface = Column(String(100), nullable=False)
    
    # Link properties
    link_type = Column(String(50))  # ethernet, serial, tunnel, etc.
    speed = Column(String(20))
    duplex = Column(String(20))
    
    # Discovery method
    discovered_by = Column(String(50))  # cdp, lldp, manual, inferred
    
    # Status
    is_active = Column(Boolean, default=True)
    
    # Timestamps
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())
    
    def __repr__(self):
        return f"<TopologyLink(src_device={self.source_device_id}, dst_device={self.dest_device_id})>"