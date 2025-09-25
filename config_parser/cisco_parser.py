#!/usr/bin/env python3
"""
Cisco Configuration Parser using TextFSM Templates
More robust parsing using established TextFSM templates
"""

import textfsm
import io
import re
from typing import Dict, List, Optional, Any, Union
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

@dataclass
class CDPNeighbor:
    local_interface: str
    remote_device: str
    remote_interface: str
    remote_ip: Optional[str] = None

@dataclass
class InterfaceStatus:
    name: str
    ip_address: str
    ok: str
    method: str
    status: str
    protocol: str

@dataclass
class ARPEntry:
    protocol: str
    address: str
    age: str
    hardware_address: str
    entry_type: str
    interface: str

@dataclass
class LineVTYEntry:
    tty: str
    line_type: str
    tx_rx: str
    a: str
    modem: str
    roty: str
    acc_o: str
    acc_i: str
    uses: str
    noise: str
    overruns: str
    interface: str

@dataclass
class OSPFLSA:
    area: str
    scope: str
    lsa_type: str
    link_state_id: str = ""
    advertising_router: str = ""
    ls_age: Optional[int] = None
    options: Optional[str] = None
    ls_seq_number: Optional[str] = None
    checksum: Optional[str] = None
    length: Optional[int] = None
    network_mask: Optional[str] = None
    metric: Optional[int] = None
    mtid: Optional[int] = None
    additional: Dict[str, Any] = field(default_factory=dict)
    links: List[Dict[str, Any]] = field(default_factory=list)

class TextFSMParser:
    """Parser using TextFSM templates for robust config parsing"""
    
    def __init__(
        self,
        *,
        text: Optional[str] = None,
        path: Optional[Union[str, Path]] = None,
        hostname: Optional[str] = None,
        templates_dir: Optional[Union[str, Path]] = None,
    ) -> None:
        if (text is None and path is None) or (text is not None and path is not None):
            raise ValueError("Provide either text or path, but not both")

        if path is not None:
            config_path = Path(path)
            if not config_path.is_file():
                raise FileNotFoundError(f"Configuration path does not exist: {config_path}")
            self.config_text = config_path.read_text(encoding="utf-8")
        else:
            # mypy/type-checker aware: text is not None here
            self.config_text = text or ""

        templates_base = templates_dir if templates_dir is not None else "templates"
        self.templates_dir = Path(templates_base)
        self.hostname = hostname or self._extract_hostname()
        
        # Initialize data structures
        self.interfaces: Dict[str, Interface] = {}
        self.vlans: Dict[str, VLAN] = {}
        self.vrfs: Dict[str, VRF] = {}
        self.routes: List[Route] = []
        self.ospf_neighbors: List[OSPFNeighbor] = []
        self.cdp_neighbors: List[CDPNeighbor] = []
        self.interface_status: Dict[str, InterfaceStatus] = {}
        self.arp_entries: List[ARPEntry] = []
        self.access_lists: Dict[str, Dict[str, Any]] = {}
        self.line_vty: List[LineVTYEntry] = []
        self.ssh_info: Dict[str, Any] = {}
        self.ospf_lsdb: List[OSPFLSA] = []
        self.ospf_processes: List[Dict[str, Any]] = []

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
        self.templates_dir.mkdir(parents=True, exist_ok=True)
        
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
        self._parse_cdp_neighbors()
        self._parse_show_ip_interface_brief()
        self._parse_show_ip_arp()
        self._parse_show_access_lists()
        self._parse_show_line_vty()
        self._parse_show_ip_ssh()
        self._parse_ospf_lsdb()
    
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

    def _extract_command_output(self, command: str) -> str:
        """Generic extractor for command outputs delimited by === markers"""
        lines = self.config_text.split('\n')
        target = f"=== {command.lower()} ==="
        capture = False
        collected: List[str] = []

        for line in lines:
            normalized = line.strip().lower()
            if normalized == target:
                capture = True
                continue

            if capture and normalized.startswith('===') and normalized != target:
                break

            if capture:
                collected.append(line.rstrip())

        return '\n'.join(collected).strip()

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

    def _extract_cdp_neighbors(self) -> str:
        """Extract 'show cdp neighbors detail' output block"""
        lines = self.config_text.split('\n')
        capture = False
        collected: List[str] = []

        for line in lines:
            normalized = line.strip().lower()
            if normalized == "=== show cdp neighbors detail ===":
                capture = True
                continue

            if capture and normalized.startswith("===") and "show cdp neighbors detail" not in normalized:
                break

            if capture:
                collected.append(line)

        return '\n'.join(collected).strip()

    def _parse_cdp_neighbors(self) -> None:
        """Parse CDP neighbor details from the configuration text"""
        section = self._extract_cdp_neighbors()
        if not section:
            return

        entries = [entry.strip() for entry in section.split('-------------------------') if 'Device ID:' in entry]

        for entry in entries:
            remote_device_match = re.search(r"Device ID:\s*(.+)", entry)
            local_intf_match = re.search(r"Interface:\s*([^,]+)", entry)
            remote_intf_match = re.search(r"Port ID[^:]*:\s*([^\n]+)", entry)
            ip_matches = re.findall(r"IP address:\s*([0-9.]+)", entry)

            remote_device_raw = remote_device_match.group(1).strip() if remote_device_match else ""
            remote_device = remote_device_raw.split('.')[0] if remote_device_raw else ""
            local_interface = local_intf_match.group(1).strip() if local_intf_match else ""
            remote_interface = remote_intf_match.group(1).strip() if remote_intf_match else ""
            remote_ip = ip_matches[0].strip() if ip_matches else None

            if not remote_device or not local_interface:
                continue

            neighbor = CDPNeighbor(
                local_interface=local_interface,
                remote_device=remote_device,
                remote_interface=remote_interface,
                remote_ip=remote_ip
            )
            self.cdp_neighbors.append(neighbor)

    def _parse_show_ip_interface_brief(self) -> None:
        section = self._extract_command_output('show ip interface brief')
        if not section:
            return

        lines = [line for line in section.split('\n') if line.strip()]
        data_lines = []
        for line in lines:
            if line.strip().lower().startswith('interface'):
                continue
            if line.strip().startswith('---'):
                continue
            data_lines.append(line)

        for line in data_lines:
            segments = re.split(r'\s{2,}', line.strip())
            if len(segments) < 5:
                continue

            interface = segments[0]
            ip_address = segments[1]
            ok_method = segments[2].split()
            ok = ok_method[0] if ok_method else ''
            method = ok_method[1] if len(ok_method) > 1 else ''
            status = segments[3]
            protocol = segments[4]

            self.interface_status[interface] = InterfaceStatus(
                name=interface,
                ip_address=ip_address,
                ok=ok,
                method=method,
                status=status,
                protocol=protocol
            )

    def _parse_show_ip_arp(self) -> None:
        section = self._extract_command_output('show ip arp')
        if not section:
            return

        lines = [line for line in section.split('\n') if line.strip()]
        for line in lines:
            if line.lower().startswith('protocol'):
                continue
            match = re.match(
                r"^(?P<protocol>\S+)\s+(?P<address>\S+)\s+(?P<age>[-\d]+)\s+(?P<hw>[a-f0-9.]+)\s+(?P<etype>\S+)\s+(?P<intf>\S+)",
                line.strip(),
                re.IGNORECASE
            )
            if not match:
                continue
            entry = ARPEntry(
                protocol=match.group('protocol'),
                address=match.group('address'),
                age=match.group('age'),
                hardware_address=match.group('hw'),
                entry_type=match.group('etype'),
                interface=match.group('intf')
            )
            self.arp_entries.append(entry)

    def _parse_show_access_lists(self) -> None:
        section = self._extract_command_output('show access-lists')
        if not section:
            return

        current_acl: Optional[str] = None
        acl_type: Optional[str] = None

        for raw_line in section.split('\n'):
            line = raw_line.strip()
            if not line:
                continue

            header_match = re.match(r"^(?P<type>.+ access list)\s+(?P<name>.+)$", line, re.IGNORECASE)
            if header_match:
                acl_type = header_match.group('type').strip()
                current_acl = header_match.group('name').strip()
                self.access_lists[current_acl] = {
                    'type': acl_type,
                    'entries': []
                }
                continue

            if current_acl:
                self.access_lists[current_acl]['entries'].append(line)

    def _parse_show_line_vty(self) -> None:
        section = self._extract_command_output('show line vty 0 4')
        if not section:
            return

        lines = [line for line in section.split('\n') if line.strip()]
        data_lines = []
        for line in lines:
            if line.strip().lower().startswith('tty '):
                continue
            data_lines.append(line)

        for line in data_lines:
            tokens = line.split()
            if len(tokens) < 6:
                continue

            # Pad tokens to expected length
            while len(tokens) < 12:
                tokens.append('')

            entry = LineVTYEntry(
                tty=tokens[0],
                line_type=tokens[1],
                tx_rx=tokens[2] if len(tokens) > 2 else '',
                a=tokens[3] if len(tokens) > 3 else '',
                modem=tokens[4] if len(tokens) > 4 else '',
                roty=tokens[5] if len(tokens) > 5 else '',
                acc_o=tokens[6] if len(tokens) > 6 else '',
                acc_i=tokens[7] if len(tokens) > 7 else '',
                uses=tokens[8] if len(tokens) > 8 else '',
                noise=tokens[9] if len(tokens) > 9 else '',
                overruns=tokens[10] if len(tokens) > 10 else '',
                interface=tokens[11] if len(tokens) > 11 else ''
            )
            self.line_vty.append(entry)

    def _parse_show_ip_ssh(self) -> None:
        section = self._extract_command_output('show ip ssh')
        if not section:
            return

        lines = [line for line in section.split('\n') if line.strip()]
        if not lines:
            return

        status_line = lines[0].strip()
        status_lower = status_line.lower()
        ssh_enabled = not status_lower.startswith('ssh disabled')
        version_match = re.search(r'version\s+([0-9.]+)', status_lower)

        ssh_info: Dict[str, Any] = {
            'status': 'enabled' if ssh_enabled else 'disabled',
            'raw_status': status_line,
            'version': version_match.group(1) if version_match else None
        }

        for raw_line in lines[1:]:
            parts = [segment.strip() for segment in re.split(r';', raw_line) if segment.strip()]
            for part in parts:
                if ':' not in part:
                    continue
                key, value = part.split(':', 1)
                normalized_key = re.sub(r'[^a-z0-9_]+', '_', key.strip().lower()).strip('_')
                cleaned_value = value.strip()
                if ',' in cleaned_value:
                    values = [item.strip() for item in cleaned_value.split(',') if item.strip()]
                    ssh_info[normalized_key] = values
                else:
                    ssh_info[normalized_key] = cleaned_value

        self.ssh_info = ssh_info

    def _normalize_key(self, key: str) -> str:
        normalized = re.sub(r'[^a-z0-9]+', '_', key.lower())
        normalized = re.sub(r'_+', '_', normalized)
        return normalized.strip('_')

    def _safe_int(self, value: Optional[str]) -> Optional[int]:
        if value is None:
            return None
        try:
            return int(str(value).strip())
        except (ValueError, TypeError):
            return None

    def _extract_ospf_lsdb_section(self) -> str:
        """Retrieve OSPF LSDB output from the provided text"""
        section = self._extract_command_output('show ip ospf database')
        if section:
            return section

        command_match = re.search(r'show\s+ip\s+ospf\s+database[^\n\r]*[\r\n]+', self.config_text, re.IGNORECASE)
        if command_match:
            remainder = self.config_text[command_match.end():]
            delimiter_match = re.search(r'\n={3}\s', remainder)
            if delimiter_match:
                remainder = remainder[:delimiter_match.start()]
            return remainder.strip()

        return ""

    def _parse_ospf_lsdb(self) -> None:
        """Parse OSPF LSDB information from the configuration text."""
        section = self._extract_ospf_lsdb_section()
        if not section:
            return

        lines = [line.rstrip() for line in section.splitlines()]
        current_area: Optional[str] = None
        current_scope_label: Optional[str] = None
        current_lsa: Optional[Dict[str, Any]] = None
        current_link: Optional[Dict[str, Any]] = None
        router_id: Optional[str] = None
        process_id: Optional[str] = None

        def finalize_link() -> None:
            nonlocal current_link
            if current_link and current_lsa is not None:
                current_lsa.setdefault('links', []).append(current_link)
            current_link = None

        def finalize_lsa() -> None:
            nonlocal current_lsa, current_link
            finalize_link()
            if current_lsa is not None:
                lsa = self._build_ospf_lsa(current_lsa)
                self.ospf_lsdb.append(lsa)
            current_lsa = None

        for raw_line in lines:
            line = raw_line.strip()
            if not line:
                finalize_link()
                continue

            header_match = re.match(r'OSPF Router with ID \(([^)]+)\)(?: \(Process ID (\d+)\))?', line, re.IGNORECASE)
            if header_match:
                router_id = header_match.group(1)
                process_id = header_match.group(2)
                process_info = {
                    'router_id': router_id,
                    'process_id': process_id
                }
                if process_info not in self.ospf_processes:
                    self.ospf_processes.append(process_info)
                continue

            scope_match = re.match(r'(.+ Link States?) \(Area\s+([^\)]+)\)', line, re.IGNORECASE)
            if scope_match:
                finalize_lsa()
                current_scope_label = scope_match.group(1).strip()
                current_area = scope_match.group(2).strip()
                continue

            if line.lower().startswith('ls age:'):
                finalize_lsa()
                current_lsa = {
                    'area': current_area or '',
                    'scope': current_scope_label or '',
                    'raw': {},
                    'links': [],
                    'process_id': process_id,
                    'router_id': router_id
                }
                current_lsa['raw']['ls_age'] = line.split(':', 1)[1].strip()
                continue

            if current_lsa is None:
                continue

            if line.lower().startswith('link connected to'):
                finalize_link()
                current_link = {
                    'link_connected_to': line.split(':', 1)[1].strip()
                }
                continue

            if line.startswith('(Link ID)'):
                if current_link is None:
                    current_link = {}
                parts = line.split(':', 1)
                if len(parts) == 2:
                    suffix = parts[0].split(')', 1)[-1].strip()
                    key = self._normalize_key(f'link_id_{suffix}')
                    current_link[key] = parts[1].strip()
                continue

            if line.startswith('(Link Data)'):
                if current_link is None:
                    current_link = {}
                parts = line.split(':', 1)
                if len(parts) == 2:
                    suffix = parts[0].split(')', 1)[-1].strip()
                    key = self._normalize_key(f'link_data_{suffix}')
                    current_link[key] = parts[1].strip()
                continue

            if line.lower().startswith('number of tos metrics'):
                if current_link is None:
                    current_link = {}
                current_link['number_of_tos_metrics'] = self._safe_int(line.split(':', 1)[1].strip())
                continue

            if line.lower().startswith('tos') and 'metrics:' in line.lower():
                if current_link is None:
                    current_link = {}
                tos_parts = line.split('metrics', 1)
                tos_id = tos_parts[0].strip().split()[1]
                metric_value = tos_parts[1].split(':', 1)[-1].strip()
                current_link.setdefault('tos_metrics', {})[tos_id] = self._safe_int(metric_value)
                continue

            kv_match = re.match(r'([A-Za-z][A-Za-z0-9\s()/\-]+):\s*(.+)', line)
            if kv_match:
                key = self._normalize_key(kv_match.group(1))
                value = kv_match.group(2).strip()

                if key == 'mtid' and 'metric' in value.lower():
                    sub_pairs = re.findall(r'([A-Za-z]+):\s*([^\s]+)', value)
                    current_lsa['raw'][key] = value.split()[0]
                    for sub_key, sub_value in sub_pairs:
                        normalized_sub = self._normalize_key(sub_key)
                        current_lsa['raw'][normalized_sub] = sub_value
                    continue

                if key == 'metric' and 'mtid' in value.lower():
                    sub_pairs = re.findall(r'([A-Za-z]+):\s*([^\s]+)', value)
                    current_lsa['raw'][key] = value.split()[0]
                    for sub_key, sub_value in sub_pairs:
                        normalized_sub = self._normalize_key(sub_key)
                        current_lsa['raw'][normalized_sub] = sub_value
                    continue

                current_lsa['raw'][key] = value
                continue

        finalize_lsa()

    def _build_ospf_lsa(self, data: Dict[str, Any]) -> OSPFLSA:
        raw = data.get('raw', {})
        scope = data.get('scope', '')
        lsa_type = raw.get('ls_type', scope)
        link_state_id = raw.get('link_state_id') or raw.get('link_state_id_router_id') or ''
        advertising_router = raw.get('advertising_router') or raw.get('router') or raw.get('originating_router') or ''

        excluded_keys = {
            'ls_age', 'options', 'ls_type', 'link_state_id', 'link_state_id_router_id',
            'advertising_router', 'router', 'originating_router', 'ls_seq_number', 'checksum',
            'length', 'network_mask', 'metric', 'mtid'
        }

        additional = {k: v for k, v in raw.items() if k not in excluded_keys}

        meta = {k: data.get(k) for k in ('process_id', 'router_id') if data.get(k) is not None}
        if meta:
            additional.update(meta)

        lsa = OSPFLSA(
            area=data.get('area', ''),
            scope=scope,
            lsa_type=lsa_type,
            link_state_id=link_state_id,
            advertising_router=advertising_router,
            ls_age=self._safe_int(raw.get('ls_age')),
            options=raw.get('options'),
            ls_seq_number=raw.get('ls_seq_number'),
            checksum=raw.get('checksum'),
            length=self._safe_int(raw.get('length')),
            network_mask=raw.get('network_mask'),
            metric=self._safe_int(raw.get('metric')),
            mtid=self._safe_int(raw.get('mtid')),
            additional=additional
        )

        if data.get('links'):
            lsa.links.extend(data['links'])

        return lsa
    
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
            'ospf_neighbors_count': len(self.ospf_neighbors),
            'cdp_neighbors': [
                {
                    'local_interface': neighbor.local_interface,
                    'remote_device': neighbor.remote_device,
                    'remote_interface': neighbor.remote_interface,
                    'remote_ip': neighbor.remote_ip
                }
                for neighbor in self.cdp_neighbors
            ],
            'interface_status': {
                name: {
                    'ip_address': status.ip_address,
                    'ok': status.ok,
                    'method': status.method,
                    'status': status.status,
                    'protocol': status.protocol
                }
                for name, status in self.interface_status.items()
            },
            'arp_table': [
                {
                    'protocol': entry.protocol,
                    'address': entry.address,
                    'age': entry.age,
                    'hardware_address': entry.hardware_address,
                    'type': entry.entry_type,
                    'interface': entry.interface
                }
                for entry in self.arp_entries
            ],
            'access_lists': self.access_lists,
            'line_vty': [
                {
                    'tty': entry.tty,
                    'type': entry.line_type,
                    'tx_rx': entry.tx_rx,
                    'a': entry.a,
                    'modem': entry.modem,
                    'roty': entry.roty,
                    'acc_o': entry.acc_o,
                    'acc_i': entry.acc_i,
                    'uses': entry.uses,
                    'noise': entry.noise,
                    'overruns': entry.overruns,
                    'interface': entry.interface
                }
                for entry in self.line_vty
            ],
            'ospf_lsdb': {
                'processes': self.ospf_processes,
                'lsas': [
                    {
                        'area': lsa.area,
                        'scope': lsa.scope,
                        'lsa_type': lsa.lsa_type,
                        'link_state_id': lsa.link_state_id,
                        'advertising_router': lsa.advertising_router,
                        'ls_age': lsa.ls_age,
                        'options': lsa.options,
                        'ls_seq_number': lsa.ls_seq_number,
                        'checksum': lsa.checksum,
                        'length': lsa.length,
                        'network_mask': lsa.network_mask,
                        'metric': lsa.metric,
                        'mtid': lsa.mtid,
                        'links': lsa.links,
                        'additional': lsa.additional
                    }
                    for lsa in self.ospf_lsdb
                ]
            },
            'ssh_info': self.ssh_info
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
    
    parser = TextFSMParser(text=sample_config)
    print("Parsed Network Summary:")
    print(parser.to_json())
