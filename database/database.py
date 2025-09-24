#!/usr/bin/env python3
"""
Database Configuration and Setup
SQLAlchemy database connection and session management
"""

import os
import logging
from sqlalchemy import create_engine, event
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import StaticPool
from contextlib import contextmanager
import asyncio

# Import models to ensure they're registered
from database.models import Base

logger = logging.getLogger(__name__)

# Database configuration
DATABASE_URL = os.getenv(
    "DATABASE_URL", 
    "sqlite:///./network_ai_platform.db"  # Default to SQLite for development
)

# For production, use PostgreSQL:
# DATABASE_URL = "postgresql://username:password@localhost:5432/network_ai_platform"

# Create engine
if DATABASE_URL.startswith("sqlite"):
    # SQLite configuration
    engine = create_engine(
        DATABASE_URL,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        echo=False  # Set to True for SQL debugging
    )
else:
    # PostgreSQL/MySQL configuration
    engine = create_engine(
        DATABASE_URL,
        pool_size=20,
        max_overflow=0,
        pool_pre_ping=True,
        echo=False
    )

# Create session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Enable foreign key constraints for SQLite
@event.listens_for(engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    """Enable foreign key constraints for SQLite"""
    if 'sqlite' in str(engine.url):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

async def init_db():
    """Initialize database tables"""
    try:
        logger.info("Creating database tables...")
        Base.metadata.create_all(bind=engine)
        logger.info("Database tables created successfully")
        
        # Create initial data if needed
        await create_initial_data()
        
    except Exception as e:
        logger.error(f"Error initializing database: {str(e)}")
        raise

async def create_initial_data():
    """Create initial data for the application"""
    try:
        db = SessionLocal()
        
        # Check if we already have data
        from database.models import NetworkSession
        existing_sessions = db.query(NetworkSession).count()
        
        if existing_sessions == 0:
            # Create default network session
            default_session = NetworkSession(
                name="Default Network",
                description="Default network analysis session",
                device_ids=[],
                topology_data={},
                analysis_results={}
            )
            
            db.add(default_session)
            db.commit()
            logger.info("Created default network session")
        
        db.close()
        
    except Exception as e:
        logger.error(f"Error creating initial data: {str(e)}")

def get_db() -> Session:
    """Dependency to get database session"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@contextmanager
def get_db_session():
    """Context manager for database sessions"""
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception as e:
        db.rollback()
        logger.error(f"Database session error: {str(e)}")
        raise
    finally:
        db.close()

class DatabaseManager:
    """Database management utilities"""
    
    def __init__(self):
        self.engine = engine
        self.SessionLocal = SessionLocal
    
    def create_tables(self):
        """Create all database tables"""
        Base.metadata.create_all(bind=self.engine)
    
    def drop_tables(self):
        """Drop all database tables (use with caution!)"""
        Base.metadata.drop_all(bind=self.engine)
    
    def reset_database(self):
        """Reset database (drop and recreate all tables)"""
        logger.warning("Resetting database - all data will be lost!")
        self.drop_tables()
        self.create_tables()
        logger.info("Database reset completed")
    
    def backup_database(self, backup_path: str):
        """Backup database (SQLite only)"""
        if not DATABASE_URL.startswith("sqlite"):
            raise NotImplementedError("Backup only supported for SQLite databases")
        
        import shutil
        db_path = DATABASE_URL.replace("sqlite:///", "")
        shutil.copy2(db_path, backup_path)
        logger.info(f"Database backed up to {backup_path}")
    
    def get_table_stats(self):
        """Get statistics about database tables"""
        with get_db_session() as db:
            from database.models import Device, Interface, VLAN, VRF, Route, NetworkSession, QueryHistory
            
            stats = {
                'devices': db.query(Device).count(),
                'interfaces': db.query(Interface).count(),
                'vlans': db.query(VLAN).count(),
                'vrfs': db.query(VRF).count(),
                'routes': db.query(Route).count(),
                'sessions': db.query(NetworkSession).count(),
                'queries': db.query(QueryHistory).count()
            }
            
            return stats
    
    def cleanup_old_data(self, days_to_keep: int = 30):
        """Clean up old query history and inactive sessions"""
        from datetime import datetime, timedelta
        from database.models import QueryHistory, NetworkSession
        
        cutoff_date = datetime.now() - timedelta(days=days_to_keep)
        
        with get_db_session() as db:
            # Clean up old query history
            old_queries = db.query(QueryHistory).filter(
                QueryHistory.created_at < cutoff_date
            ).count()
            
            if old_queries > 0:
                db.query(QueryHistory).filter(
                    QueryHistory.created_at < cutoff_date
                ).delete()
                logger.info(f"Cleaned up {old_queries} old query records")
            
            # Clean up inactive sessions (optional)
            inactive_sessions = db.query(NetworkSession).filter(
                NetworkSession.is_active == False,
                NetworkSession.updated_at < cutoff_date
            ).count()
            
            if inactive_sessions > 0:
                db.query(NetworkSession).filter(
                    NetworkSession.is_active == False,
                    NetworkSession.updated_at < cutoff_date
                ).delete()
                logger.info(f"Cleaned up {inactive_sessions} inactive sessions")

# Database utility functions
def create_device_with_relationships(db: Session, device_data: dict, parsed_data: dict):
    """Create a device with all its related data (interfaces, VLANs, VRFs, etc.)"""
    from database.models import Device, Interface, VLAN, VRF, Route
    
    try:
        # Create device
        device = Device(**device_data)
        db.add(device)
        db.flush()  # Get the device ID
        
        # Create interfaces
        for intf_name, intf_data in parsed_data.get('interfaces', {}).items():
            interface = Interface(
                device_id=device.id,
                name=intf_name,
                description=intf_data.get('description', ''),
                ip_address=intf_data.get('ip_address', ''),
                subnet_mask=intf_data.get('subnet_mask', ''),
                vrf_name=intf_data.get('vrf', ''),
                access_vlan=int(intf_data.get('access_vlan')) if intf_data.get('access_vlan') else None,
                trunk_vlans=intf_data.get('trunk_vlans', []),
                admin_status=intf_data.get('status', ''),
                oper_status=intf_data.get('protocol', '')
            )
            db.add(interface)
        
        # Create VLANs
        for vlan_id, vlan_data in parsed_data.get('vlans', {}).items():
            vlan = VLAN(
                device_id=device.id,
                vlan_id=int(vlan_id) if str(vlan_id).isdigit() else 0,
                name=vlan_data.get('name', ''),
                status=vlan_data.get('status', '')
            )
            db.add(vlan)
        
        # Create VRFs
        for vrf_name, vrf_data in parsed_data.get('vrfs', {}).items():
            vrf = VRF(
                device_id=device.id,
                name=vrf_name,
                rd=vrf_data.get('rd', ''),
                import_targets=vrf_data.get('import_targets', []),
                export_targets=vrf_data.get('export_targets', []),
                interfaces=vrf_data.get('interfaces', [])
            )
            db.add(vrf)
        
        # Create routes if available
        for route_data in parsed_data.get('routes', []):
            route = Route(
                device_id=device.id,
                network=route_data.get('network', ''),
                mask=route_data.get('mask', ''),
                next_hop=route_data.get('next_hop', ''),
                interface=route_data.get('interface', ''),
                protocol=route_data.get('protocol', ''),
                admin_distance=route_data.get('distance'),
                metric=route_data.get('metric'),
                vrf_name=route_data.get('vrf', '')
            )
            db.add(route)
        
        db.commit()
        logger.info(f"Successfully created device {device.hostname} with all relationships")
        return device
        
    except Exception as e:
        db.rollback()
        logger.error(f"Error creating device with relationships: {str(e)}")
        raise

def update_device_parsed_data(db: Session, device_id: int, new_parsed_data: dict):
    """Update device's parsed data and related tables"""
    from database.models import Device
    
    try:
        device = db.query(Device).filter(Device.id == device_id).first()
        if not device:
            raise ValueError(f"Device with ID {device_id} not found")
        
        # Update the JSON parsed_data field
        device.parsed_data = new_parsed_data
        
        # Optionally recreate relationships
        # (This is a simple approach; in production you might want to do incremental updates)
        
        db.commit()
        logger.info(f"Updated parsed data for device {device.hostname}")
        
    except Exception as e:
        db.rollback()
        logger.error(f"Error updating device parsed data: {str(e)}")
        raise

def search_devices(db: Session, search_term: str, device_type: str = None, limit: int = 50):
    """Search devices by hostname, IP, or other criteria"""
    from database.models import Device
    
    query = db.query(Device)
    
    if search_term:
        query = query.filter(
            Device.hostname.contains(search_term) |
            Device.mgmt_ip.contains(search_term)
        )
    
    if device_type:
        query = query.filter(Device.device_type == device_type)
    
    return query.limit(limit).all()

def get_network_statistics(db: Session):
    """Get comprehensive network statistics"""
    from database.models import Device, Interface, VLAN, VRF
    from sqlalchemy import func
    
    stats = {}
    
    # Device statistics
    device_stats = db.query(
        Device.device_type,
        func.count(Device.id).label('count')
    ).group_by(Device.device_type).all()
    
    stats['devices_by_type'] = {stat.device_type: stat.count for stat in device_stats}
    stats['total_devices'] = sum(stats['devices_by_type'].values())
    
    # Interface statistics
    stats['total_interfaces'] = db.query(Interface).count()
    
    # VLAN statistics
    stats['total_vlans'] = db.query(VLAN).count()
    unique_vlans = db.query(VLAN.vlan_id).distinct().count()
    stats['unique_vlan_ids'] = unique_vlans
    
    # VRF statistics
    stats['total_vrfs'] = db.query(VRF).count()
    unique_vrfs = db.query(VRF.name).distinct().count()
    stats['unique_vrf_names'] = unique_vrfs
    
    return stats

# Initialize database manager instance
db_manager = DatabaseManager()

if __name__ == "__main__":
    # Script to initialize/manage database
    import sys
    
    if len(sys.argv) > 1:
        command = sys.argv[1]
        
        if command == "init":
            asyncio.run(init_db())
            print("Database initialized successfully")
            
        elif command == "reset":
            confirm = input("This will delete all data. Are you sure? (y/N): ")
            if confirm.lower() == 'y':
                db_manager.reset_database()
                asyncio.run(create_initial_data())
                print("Database reset completed")
            else:
                print("Database reset cancelled")
                
        elif command == "stats":
            with get_db_session() as db:
                stats = get_network_statistics(db)
                print("Database Statistics:")
                for key, value in stats.items():
                    print(f"  {key}: {value}")
                    
        elif command == "backup":
            if len(sys.argv) > 2:
                backup_path = sys.argv[2]
                db_manager.backup_database(backup_path)
                print(f"Database backed up to {backup_path}")
            else:
                print("Please provide backup file path")
                
        elif command == "cleanup":
            days = int(sys.argv[2]) if len(sys.argv) > 2 else 30
            db_manager.cleanup_old_data(days)
            print(f"Cleaned up data older than {days} days")
            
        else:
            print("Available commands: init, reset, stats, backup, cleanup")
    else:
        print("Usage: python database.py <command>")
        print("Commands: init, reset, stats, backup <path>, cleanup [days]")