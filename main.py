#!/usr/bin/env python3
"""
Network AI Platform - FastAPI Backend
Main application entry point
"""

from fastapi import FastAPI, HTTPException, UploadFile, File, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import uvicorn
import logging
from typing import List, Dict, Any, Optional
import asyncio
from contextlib import asynccontextmanager

# Local imports
from config_parser.cisco_parser import TextFSMParser
from network_model.topology import NetworkTopology
from ai_engine.query_processor import NetworkQueryProcessor
from database.models import Device, NetworkSession
from database.database import get_db, init_db
from api.schemas import (
    ConfigUploadResponse, 
    NetworkSummaryResponse,
    QueryRequest,
    QueryResponse,
    DeviceInfo
)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan events"""
    # Startup
    logger.info("Starting Network AI Platform...")
    await init_db()
    logger.info("Database initialized")
    
    yield
    
    # Shutdown
    logger.info("Shutting down Network AI Platform...")

# Initialize FastAPI app
app = FastAPI(
    title="Network AI Platform",
    description="AI-powered network analysis and automation platform for Cisco networks",
    version="1.0.0",
    lifespan=lifespan
)

# CORS middleware for frontend integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173"],  # React dev servers
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global network topology instance
network_topology = NetworkTopology()
query_processor = NetworkQueryProcessor()

@app.get("/")
async def root():
    """Health check endpoint"""
    return {"message": "Network AI Platform API", "status": "healthy"}

@app.get("/health")
async def health_check():
    """Detailed health check"""
    return {
        "status": "healthy",
        "services": {
            "api": "running",
            "database": "connected",
            "ai_engine": "ready"
        }
    }

@app.post("/api/v1/upload-config", response_model=ConfigUploadResponse)
async def upload_config(
    file: UploadFile = File(...),
    hostname: Optional[str] = None,
    db_session = Depends(get_db)
):
    """Upload and parse a Cisco configuration file"""
    try:
        # Validate file type
        if not file.filename.endswith(('.txt', '.cfg', '.conf')):
            raise HTTPException(status_code=400, detail="Invalid file type. Please upload a .txt, .cfg, or .conf file")
        
        # Read file content
        content = await file.read()
        config_text = content.decode('utf-8')
        
        # Parse configuration
        parser = TextFSMParser(text=config_text, hostname=hostname)

        # Upsert device record
        existing_device = db_session.query(Device).filter(Device.hostname == parser.hostname).first()
        summary = parser.get_summary()
        device_type = getattr(parser, 'device_type', 'Unknown')
        vendor = getattr(parser, 'vendor', 'Cisco')
        model = getattr(parser, 'model', None)
        ios_version = getattr(parser, 'ios_version', None)

        if existing_device:
            device = existing_device
            device.config_text = config_text
            device.device_type = device_type
            device.vendor = vendor
            device.model = model
            device.ios_version = ios_version
            device.parsed_data = summary
        else:
            device = Device(
                hostname=parser.hostname,
                config_text=config_text,
                device_type=device_type,
                vendor=vendor,
                model=model,
                ios_version=ios_version,
                parsed_data=summary
            )
            db_session.add(device)

        db_session.commit()
        db_session.refresh(device)

        # Refresh topology state for this device
        if existing_device:
            await network_topology.remove_device(parser.hostname)
        await network_topology.add_device(parser)
        
        logger.info(f"Successfully parsed and stored config for device: {parser.hostname}")
        
        return ConfigUploadResponse(
            device_id=device.id,
            hostname=parser.hostname,
            device_type=getattr(parser, 'device_type', 'Unknown'),
            interfaces_count=len(parser.interfaces),
            vlans_count=len(parser.vlans),
            vrfs_count=len(parser.vrfs),
            message="Configuration uploaded and parsed successfully"
        )
        
    except Exception as e:
        logger.error(f"Error processing config upload: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error processing configuration: {str(e)}")

@app.get("/api/v1/devices", response_model=List[DeviceInfo])
async def get_devices(db_session = Depends(get_db)):
    """Get all devices in the network"""
    try:
        devices = db_session.query(Device).all()
        
        device_list = []
        for device in devices:
            device_info = DeviceInfo(
                id=device.id,
                hostname=device.hostname,
                device_type=device.device_type,
                interfaces_count=len(device.parsed_data.get('interfaces', {})),
                vlans_count=len(device.parsed_data.get('vlans', {})),
                vrfs_count=len(device.parsed_data.get('vrfs', {})),
                last_updated=device.updated_at
            )
            device_list.append(device_info)
        
        return device_list
        
    except Exception as e:
        logger.error(f"Error retrieving devices: {str(e)}")
        raise HTTPException(status_code=500, detail="Error retrieving devices")

@app.get("/api/v1/devices/{device_id}")
async def get_device(device_id: int, db_session = Depends(get_db)):
    """Get detailed information about a specific device"""
    try:
        device = db_session.query(Device).filter(Device.id == device_id).first()
        
        if not device:
            raise HTTPException(status_code=404, detail="Device not found")
        
        return {
            "id": device.id,
            "hostname": device.hostname,
            "device_type": device.device_type,
            "config_text": device.config_text,
            "parsed_data": device.parsed_data,
            "created_at": device.created_at,
            "updated_at": device.updated_at
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error retrieving device {device_id}: {str(e)}")
        raise HTTPException(status_code=500, detail="Error retrieving device")

@app.get("/api/v1/network/summary", response_model=NetworkSummaryResponse)
async def get_network_summary(db_session = Depends(get_db)):
    """Get overall network summary and topology information"""
    try:
        devices = db_session.query(Device).all()
        
        total_interfaces = 0
        total_vlans = set()
        total_vrfs = set()
        device_types = {}
        
        for device in devices:
            parsed_data = device.parsed_data
            total_interfaces += len(parsed_data.get('interfaces', {}))
            
            # Collect unique VLANs and VRFs across all devices
            for vlan_id in parsed_data.get('vlans', {}):
                total_vlans.add(vlan_id)
            
            for vrf_name in parsed_data.get('vrfs', {}):
                total_vrfs.add(vrf_name)
            
            # Count device types
            device_type = device.device_type
            device_types[device_type] = device_types.get(device_type, 0) + 1
        
        # Get topology information
        topology_info = await network_topology.get_topology_summary()
        
        return NetworkSummaryResponse(
            total_devices=len(devices),
            total_interfaces=total_interfaces,
            total_vlans=len(total_vlans),
            total_vrfs=len(total_vrfs),
            device_types=device_types,
            topology=topology_info
        )
        
    except Exception as e:
        logger.error(f"Error generating network summary: {str(e)}")
        raise HTTPException(status_code=500, detail="Error generating network summary")

@app.post("/api/v1/query", response_model=QueryResponse)
async def process_query(query_request: QueryRequest, db_session = Depends(get_db)):
    """Process natural language queries about the network"""
    try:
        # Get all devices for context
        devices = db_session.query(Device).all()
        
        # Process query with AI engine
        response = await query_processor.process_query(
            query=query_request.query,
            devices=devices,
            context=query_request.context
        )
        
        return QueryResponse(
            query=query_request.query,
            response=response.get('response', ''),
            config_changes=response.get('config_changes', []),
            affected_devices=response.get('affected_devices', []),
            confidence=response.get('confidence', 0.0)
        )
        
    except Exception as e:
        logger.error(f"Error processing query: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error processing query: {str(e)}")

@app.get("/api/v1/network/topology")
async def get_network_topology():
    """Get network topology visualization data"""
    try:
        topology_data = await network_topology.generate_topology_data()
        return topology_data
        
    except Exception as e:
        logger.error(f"Error generating topology data: {str(e)}")
        raise HTTPException(status_code=500, detail="Error generating topology data")

@app.delete("/api/v1/devices/{device_id}")
async def delete_device(device_id: int, db_session = Depends(get_db)):
    """Delete a device from the network"""
    try:
        device = db_session.query(Device).filter(Device.id == device_id).first()
        
        if not device:
            raise HTTPException(status_code=404, detail="Device not found")
        
        # Remove from topology
        await network_topology.remove_device(device.hostname)
        
        # Delete from database
        db_session.delete(device)
        db_session.commit()
        
        return {"message": f"Device {device.hostname} deleted successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting device {device_id}: {str(e)}")
        raise HTTPException(status_code=500, detail="Error deleting device")

@app.get("/api/v1/network/paths")
async def get_routing_paths(source: str, destination: str):
    """Get routing paths between two network endpoints"""
    try:
        paths = await network_topology.find_paths(source, destination)
        return {"source": source, "destination": destination, "paths": paths}
        
    except Exception as e:
        logger.error(f"Error finding paths from {source} to {destination}: {str(e)}")
        raise HTTPException(status_code=500, detail="Error calculating routing paths")

# WebSocket endpoint for real-time updates
@app.websocket("/ws")
async def websocket_endpoint(websocket):
    """WebSocket for real-time network updates"""
    await websocket.accept()
    try:
        while True:
            # Send periodic network status updates
            await asyncio.sleep(10)
            status = await network_topology.get_status()
            await websocket.send_json(status)
    except Exception as e:
        logger.error(f"WebSocket error: {str(e)}")

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
