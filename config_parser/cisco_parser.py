#!/usr/bin/env python3
"""
Cisco Configuration Parser using TextFSM Templates
More robust parsing using established TextFSM templates
"""

import textfsm
import io
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from pathlib import Path
import json
import ipaddress

@dataclass
class Interface:
    name: str
    description: str = ""
    ip_address: str = ""
    subnet_mask: str = ""
    vrf: str = ""
    status: str = ""
    protocol: str = ""
    shutdown: bool = False
    trunk_vlans: List[str] = field(default_factory=list)
    access_vlan: str = ""
    port_channel: Optional[str] = None
    
@dataclass
class VLAN:
    id: str
    name: str = ""
    status: str = ""
    interfaces: List[str] = field(default_factory=list)
    
@dataclass
class VRF:
    name: str
    rd: str = ""
    interfaces: List[str] = field(default_factory=list)
    import_targets: List[str] = field(default_factory=list)
    export_targets: List[str] = field(default_factory=list)

@dataclass
class Route:
    network: str
    mask: str
    distance: str = ""
    metric: str = ""
    next_hop: str = ""
    interface: str = ""
    vrf: str = ""
    protocol: str = ""

@dataclass
class OSPFNeighbor:
    neighbor_id: str
    priority: str = ""
    state: str = ""
    dead_time: str = ""
    address: str = ""
    interface: str = ""

class TextFSMParser:
    """Parser using TextFSM templates for robust config parsing"""
    
    def __init__(self, config_text: str, templates_dir: str = "templates"):
        self.config_text = config_text
        self.templates_dir = Path(templates_dir)
        self.hostname = self._extract_hostname()
        
        # Initialize data structures
        self.interfaces: Dict[str, Interface] = {}
        self.vlans: Dict[str, VLAN] = {}
        self.vrfs: Dict[str, VRF] = {}
        self.routes: List[Route] = []
        self.ospf_neighbors: List[OSPFNeighbor] = []
        
        # Create templates directory and default templates
        self._create_templates()
        
        # Parse all components
        self.parse_all()
    
    def _extract_hostname(self) -> str:
        """Simple hostname extraction"""
        lines = self.config_text.split('\n')
        for line in lines:
            if line.strip().startswith('hostname '):
                return line.strip().replace('hostname ', '')
        return "Unknown"
    
    def _create_templates(self):
        """Create TextFSM templates for parsing"""
        self.templates_dir.mkdir(exist_ok=True)
        
        # Interface template
        interface_template = """Value INTERFACE (\S+)
Value DESCRIPTION (.*)
Value IP_ADDRESS (\d+\.\d+\.\d+\.\d+)
Value SUBNET_MASK (\d+\.\d+\.\d+\.\d+)
Value VRF (\S+)
Value STATUS (up|down|administratively down)
Value PROTOCOL (up|down)
Value ACCESS_VLAN (\d+)
Value TRUNK_VLANS (.*)

Start
  ^interface\s+${INTERFACE} -> Interface

Interface
  ^\s+description\s+${DESCRIPTION}
  ^\s+ip\s+address\s+${IP_ADDRESS}\s+${SUBNET_MASK}
  ^\s+vrf\s+forwarding\s+${VRF}
  ^\s+switchport\s+access\s+vlan\s+${ACCESS_VLAN}
  ^\s+switchport\s+trunk\s+allowed\s+vlan\s+${TRUNK_VLANS}
  ^interface\s+\S+ -> Record Start
  ^! -> Record Start
  ^end -> Record Start

EOF"""
        
        # VLAN template
        vlan_template = """Value VLAN_ID (\d+)
Value VLAN_NAME (\S+)
Value STATUS (active|suspend|act/lshut|sus/lshut)

Start
  ^${VLAN_ID}\s+${VLAN_NAME}\s+${STATUS} -> Record

EOF"""

        # VRF template  
        vrf_template = """Value VRF_NAME (\S+)
Value RD (\S+)
Value Import_RT (.*)
Value Export_RT (.*)

Start
  ^vrf\s+definition\s+${VRF_NAME} -> VRF
  ^ip\s+vrf\s+${VRF_NAME} -> VRF

VRF
  ^\s+rd\s+${RD}
  ^\s+route-target\s+import\s+${Import_RT}
  ^\s+route-target\s+export\s+${Export_RT}
  ^vrf\s+definition\s+\S+ -> Record Start
  ^ip\s+vrf\s+\S+ -> Record Start  
  ^! -> Record Start
  ^interface -> Record Start

EOF"""

        # Route template
        route_template = """Value PROTOCOL (\w)
Value NETWORK (\d+\.\d+\.\d+\.\d+/\d+|\d+\.\d+\.\d+\.\d+)
Value MASK (\d+\.\d+\.\d+\.\d+)
Value DISTANCE (\d+)
Value METRIC (\d+)
Value NEXT_HOP (\d+\.\d+\.\d+\.\d+)
Value INTERFACE (\S+)
Value VRF (\S+)

Start
  ^${PROTOCOL}.*${NETWORK}(?:\s+${MASK})?\s+\[${DISTANCE}/${METRIC}\]\s+via\s+${NEXT_HOP}(?:,\s+${INTERFACE})? -> Record
  ^${PROTOCOL}.*${NETWORK}(?:\s+${MASK})?\s+is\s+directly\s+connected,\s+${INTERFACE} -> Record

EOF"""

        # OSPF neighbor template
        ospf_neighbor_template = """Value NEIGHBOR_ID (\d+\.\d+\.\d+\.\d+)
Value PRIORITY (\d+)
Value STATE (\w+/?\w*)
Value DEAD_TIME (\S+)
Value ADDRESS (\d+\.\d+\.\d+\.\d+)
Value INTERFACE (\S+)

Start
  ^${NEIGHBOR_ID}\s+${PRIORITY}\s+${STATE}\s+${DEAD_TIME}\s+${ADDRESS}\s+${INTERFACE} -> Record

EOF"""
        
        # Write templates to files
        templates = {
            'cisco_interface.textfsm': interface_template,
            'cisco_vlan.textfsm': vlan_template,
            'cisco_vrf.textfsm': vrf_template,
            'cisco_route.textfsm': route_template,
            'cisco_ospf_neighbor.textfsm': ospf_neighbor_template
        }
        
        for filename, template_content in templates.items():
            template_path = self.templates_dir / filename
            template_path.write_text(template_content)
    
    def _parse_with_template(self, template_name: str, config_section: str = None) -> List[Dict]:
        """Parse configuration using specified TextFSM template"""
        template_path = self.templates_dir / template_name
        
        if not template_path.exists():
            print(f"Template {template_name} not found")
            return []
        
        template_text = template_path.read_text()
        template = textfsm.TextFSM(io.StringIO(template_text))
        
        # Use full config or specific section
        config_to_parse = config_section if config_section else self.config_text
        
        try:
            results = template.ParseText(config_to_parse)
            headers = [h.lower() for h in template.header]
            
            # Convert to list of dictionaries
            parsed_data = []
            for result in results:
                parsed_data.append(dict(zip(headers, result)))
            
            return parsed_data
        except Exception as e:
            print(f"Error parsing with template {template_name}: {e}")
            return []
    
    def parse_all(self):
        """Parse all configuration components"""
        self._parse_interfaces()
        self._parse_vlans() 
        self._parse_vrfs()
        self._parse_routes()
        self._parse_ospf_neighbors()
    
    def _parse_interfaces(self):
        """Parse interface configurations"""
        results = self._parse_with_template('cisco_interface.textfsm')
        
        for intf_data in results:
            if not intf_data.get('interface'):
                continue
                
            interface = Interface(
                name=intf_data.get('interface', ''),
                description=intf_data.get('description', ''),
                ip_address=intf_data.get('ip_address', ''),
                subnet_mask=intf_data.get('subnet_mask', ''),
                vrf=intf_data.get('vrf', ''),
                status=intf_data.get('status', ''),
                protocol=intf_data.get('protocol', ''),
                access_vlan=intf_data.get('access_vlan', ''),
                trunk_vlans=intf_data.get('trunk_vlans', '').split(',') if intf_data.get('trunk_vlans') else []
            )
            
            self.interfaces[interface.name] = interface
    
    def _parse_vlans(self):
        """Parse VLAN configurations"""
        # First try to extract VLAN section
        vlan_section = self._extract_show_vlan_output()
        
        if vlan_section:
            results = self._parse_with_template('cisco_vlan.textfsm', vlan_section)
        else:
            # Fallback to parsing VLAN configuration commands
            results = self._parse_vlan_config_commands()
        
        for vlan_data in results:
            if not vlan_data.get('vlan_id'):
                continue
                
            vlan = VLAN(
                id=vlan_data.get('vlan_id', ''),
                name=vlan_data.get('vlan_name', ''),
                status=vlan_data.get('status', '')
            )
            
            self.vlans[vlan.id] = vlan
    
    def _parse_vrfs(self):
        """Parse VRF configurations"""
        results = self._parse_with_template('cisco_vrf.textfsm')
        
        for vrf_data in results:
            if not vrf_data.get('vrf_name'):
                continue
                
            vrf = VRF(
                name=vrf_data.get('vrf_name', ''),
                rd=vrf_data.get('rd', '')
            )
            
            # Handle route targets
            if vrf_data.get('import_rt'):
                vrf.import_targets = [vrf_data.get('import_rt')]
            if vrf_data.get('export_rt'):
                vrf.export_targets = [vrf_data.get('export_rt')]
            
            self.vrfs[vrf.name] = vrf
    
    def _parse_routes(self):
        """Parse routing table"""
        # Extract routing table section if present
        route_section = self._extract_routing_table()
        
        if route_section:
            results = self._parse_with_template('cisco_route.textfsm', route_section)
            
            for route_data in results:
                if not route_data.get('network'):
                    continue
                    
                route = Route(
                    network=route_data.get('network', ''),
                    mask=route_data.get('mask', ''),
                    distance=route_data.get('distance', ''),
                    metric=route_data.get('metric', ''),
                    next_hop=route_data.get('next_hop', ''),
                    interface=route_data.get('interface', ''),
                    protocol=route_data.get('protocol', '')
                )
                
                self.routes.append(route)
    
    def _parse_ospf_neighbors(self):
        """Parse OSPF neighbor information"""
        neighbor_section = self._extract_ospf_neighbors()
        
        if neighbor_section:
            results = self._parse_with_template('cisco_ospf_neighbor.textfsm', neighbor_section)
            
            for neighbor_data in results:
                if not neighbor_data.get('neighbor_id'):
                    continue
                    
                neighbor = OSPFNeighbor(
                    neighbor_id=neighbor_data.get('neighbor_id', ''),
                    priority=neighbor_data.get('priority', ''),
                    state=neighbor_data.get('state', ''),
                    dead_time=neighbor_data.get('dead_time', ''),
                    address=neighbor_data.get('address', ''),
                    interface=neighbor_data.get('interface', '')
                )
                
                self.ospf_neighbors.append(neighbor)
    
    def _extract_show_vlan_output(self) -> str:
        """Extract 'show vlan' command output if present"""
        lines = self.config_text.split('\n')
        in_vlan_section = False
        vlan_lines = []
        
        for line in lines:
            if 'show vlan' in line.lower() or 'VLAN Name' in line:
                in_vlan_section = True
                continue
            elif in_vlan_section and (line.startswith('!') or line.startswith('#') or not line.strip()):
                if vlan_lines:  # Only break if we've collected some data
                    break
            elif in_vlan_section:
                vlan_lines.append(line)
        
        return '\n'.join(vlan_lines) if vlan_lines else ""
    
    def _extract_routing_table(self) -> str:
        """Extract routing table output if present"""
        lines = self.config_text.split('\n')
        in_route_section = False
        route_lines = []
        
        for line in lines:
            if 'show ip route' in line.lower() or 'Gateway of last resort' in line:
                in_route_section = True
                continue
            elif in_route_section and (line.startswith('!') or line.startswith('#')):
                break
            elif in_route_section and line.strip():
                route_lines.append(line)
        
        return '\n'.join(route_lines) if route_lines else ""
    
    def _extract_ospf_neighbors(self) -> str:
        """Extract OSPF neighbor output if present"""
        lines = self.config_text.split('\n')
        in_ospf_section = False
        ospf_lines = []
        
        for line in lines:
            if 'show ip ospf neighbor' in line.lower() or 'Neighbor ID' in line:
                in_ospf_section = True
                continue
            elif in_ospf_section and (line.startswith('!') or line.startswith('#') or not line.strip()):
                if ospf_lines:
                    break
            elif in_ospf_section:
                ospf_lines.append(line)
        
        return '\n'.join(ospf_lines) if ospf_lines else ""
    
    def _parse_vlan_config_commands(self) -> List[Dict]:
        """Fallback: Parse VLAN configuration commands"""
        lines = self.config_text.split('\n')
        vlans = []
        current_vlan = None
        
        for line in lines:
            line = line.strip()
            if line.startswith('vlan ') and line.replace('vlan ', '').isdigit():
                if current_vlan:
                    vlans.append(current_vlan)
                current_vlan = {'vlan_id': line.replace('vlan ', ''), 'vlan_name': '', 'status': 'active'}
            elif current_vlan and line.startswith('name '):
                current_vlan['vlan_name'] = line.replace('name ', '')
        
        if current_vlan:
            vlans.append(current_vlan)
        
        return vlans
    
    def get_summary(self) -> Dict[str, Any]:
        """Get a summary of parsed network data"""
        return {
            'hostname': self.hostname,
            'interfaces': {name: {
                'name': intf.name,
                'description': intf.description,
                'ip_address': intf.ip_address,
                'status': intf.status,
                'vrf': intf.vrf,
                'access_vlan': intf.access_vlan,
                'trunk_vlans': intf.trunk_vlans
            } for name, intf in self.interfaces.items()},
            'vlans': {vid: {
                'id': vlan.id,
                'name': vlan.name,
                'status': vlan.status
            } for vid, vlan in self.vlans.items()},
            'vrfs': {name: {
                'name': vrf.name,
                'rd': vrf.rd,
                'import_targets': vrf.import_targets,
                'export_targets': vrf.export_targets
            } for name, vrf in self.vrfs.items()},
            'routes_count': len(self.routes),
            'ospf_neighbors_count': len(self.ospf_neighbors)
        }
    
    def to_json(self) -> str:
        """Export parsed data as JSON"""
        return json.dumps(self.get_summary(), indent=2)

# Example usage
if __name__ == "__main__":
    # Sample Cisco config
    sample_config = """
hostname CORE-SW-01
!
vlan 10
 name USERS
!
vlan 20  
 name SERVERS
!
interface GigabitEthernet1/1
 description Link to Access Switch
 switchport trunk allowed vlan 10,20
!
interface Vlan10
 description User VLAN
 ip address 192.168.10.1 255.255.255.0
!
vrf definition MGMT
 rd 1:1
 route-target import 1:1
 route-target export 1:1
!
"""
    
    parser = TextFSMParser(sample_config)
    print("Parsed Network Summary:")
    print(parser.to_json())