import os
import re
import json
import logging
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
import ipaddress
from collections import defaultdict

OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")


def _ollama_endpoint(path: str) -> str:
    base = OLLAMA_BASE_URL.rstrip('/')
    return f"{base}{path}"


def _build_qwen3_prompt(self, query: str, network_context: Dict) -> str:
    """Build optimized prompt for Qwen3:32B with improved context awareness"""

    stats = network_context.get('stats', {})
    device_types = network_context.get('device_types', {})
    vlans = network_context.get('vlans', {})
    subnets = network_context.get('subnets', {})

    context_lines: List[str] = []

    if device_types:
        context_lines.append("Network Infrastructure:")
        for device_type, hostnames in device_types.items():
            context_lines.append(f"  - {device_type}: {', '.join(hostnames)}")

    if vlans:
        if context_lines:
            context_lines.append("")
        context_lines.append("VLAN Configuration:")
        for vlan_id, vlan_info in list(vlans.items())[:15]:
            devices = ', '.join(vlan_info.get('devices', [])) or "(no devices)"
            status = vlan_info.get('status', 'unknown')
            name = vlan_info.get('name', f'VLAN_{vlan_id}')
            context_lines.append(f"  - VLAN {vlan_id} ({name}): {devices} [Status: {status}]")

    if subnets:
        if context_lines:
            context_lines.append("")
        context_lines.append("IP Addressing & Routing:")
        for subnet, subnet_info in list(subnets.items())[:8]:
            device = subnet_info.get('device', 'Unknown')
            interface = subnet_info.get('interface', 'Unknown')
            gateway = subnet_info.get('gateway', 'Unknown')
            context_lines.append(f"  - {subnet}: Gateway {gateway} via {device}:{interface}")

    context_str = "\n".join(context_lines) if context_lines else "No additional network context available."

    system_prompt = """<|im_start|>system
You are a Principal Network Engineer and Cisco Certified Expert.
Role:
- Act as a Cisco consultant specialising in routing, switching, VLANs, OSPF, BGP, and data centre operations.
- Answer clearly, concisely, and professionally.
- Never expose internal reasoning, hidden thoughts, or <think> blocks.
- Follow Cisco best practices and call out material risks.
Response format:
**ANALYSIS:** [short technical assessment]
**SOLUTION:** [recommended actions or configuration]
**COMMANDS:** ```cisco
[commands]
```
**VERIFICATION:** [steps to confirm success]
<|im_end|>"""

    user_prompt = f"""<|im_start|>user
CURRENT NETWORK STATE:
{context_str}

NETWORK SUMMARY:
- Devices: {stats.get('total_devices', 0)}
- VLANs: {stats.get('total_vlans', 0)}
- Interfaces: {stats.get('total_interfaces', 0)}
- VRFs: {stats.get('total_vrfs', 0)}

NETWORK ENGINEER REQUEST:
{query}

Provide a comprehensive technical response using only the required sections.
<|im_end|>
<|im_start|>assistant"""

    return f"{system_prompt}\n\n{user_prompt}"

def _parse_qwen3_response(self, response: str) -> Dict[str, Any]:
    """Parse structured response from Qwen3 with improved extraction"""
    parsed = {
        'response': response,
        'config_changes': [],
        'affected_devices': []
    }
    
    try:
        # Extract Cisco commands with better patterns for Qwen3
        command_patterns = [
            r'```cisco\n(.*?)```',
            r'```ios\n(.*?)```', 
            r'```config\n(.*?)```',
            r'```\n((?:interface|vlan|router|ip route|access-list).*?)```',
            r'\*\*COMMANDS:\*\*\s*\n(.*?)(?:\n\*\*|$)',
            r'Commands?:\s*\n(.*?)(?:\n\n|\n\*\*|$)',
        ]
        
        for pattern in command_patterns:
            matches = re.findall(pattern, response, re.DOTALL | re.IGNORECASE)
            for match in matches:
                # Clean and split commands
                commands = []
                lines = match.strip().split('\n')
                for line in lines:
                    line = line.strip()
                    if line and not line.startswith('#') and not line.startswith('!'):
                        # Remove common prefixes that aren't actual commands
                        if not any(line.lower().startswith(prefix) for prefix in ['note:', 'example:', 'optional:']):
                            commands.append(line)
                
                if commands:
                    parsed['config_changes'].append({
                        'device_hostname': 'TBD',
                        'commands': commands,
                        'description': 'Configuration from Qwen3 analysis',
                        'risk_level': self._extract_risk_level(response)
                    })
        
        # Extract affected devices with improved patterns
        device_patterns = [
            r'\*\*AFFECTED DEVICES:\*\*\s*(.*?)(?:\n\*\*|$)',
            r'AFFECTED DEVICES?:\s*(.*?)(?:\n\n|\n\*\*|$)',
            r'Devices?:\s*(.*?)(?:\n\n|\n\*\*|$)',
            r'Apply (?:to|on):\s*(.*?)(?:\n\n|\n\*\*|$)'
        ]
        
        for pattern in device_patterns:
            matches = re.findall(pattern, response, re.IGNORECASE | re.DOTALL)
            for match in matches:
                # Extract device names more intelligently
                devices = []
                # Split on common separators
                parts = re.split(r'[,\n;]', match)
                for part in parts:
                    part = part.strip()
                    # Look for device-like names (letters, numbers, hyphens)
                    if re.match(r'^[A-Za-z0-9-_]+', part) and len(part) > 2:
                        devices.append(part)
                parsed['affected_devices'].extend(devices)
            
        # Remove duplicates and clean up
        parsed['affected_devices'] = list(set([d for d in parsed['affected_devices'] if d]))
    except Exception as e:
        logger.warning(f"Could not parse Qwen3 response structure: {e}")
    
    return parsed

logger = logging.getLogger(__name__)

@dataclass
class QueryIntent:
    """Structured representation of user intent"""
    action: str  # show, create, configure, analyze, troubleshoot
    target: str  # vlan, interface, device, route
    parameters: Dict[str, Any]
    confidence: float

class LocalNetworkQueryProcessor:
    """
    Rule-based network query processor that doesn't require external AI APIs
    Provides intelligent responses using network engineering logic
    """
    
    def __init__(self):
        self.query_patterns = self._build_query_patterns()
        self.config_templates = self._load_config_templates()
        
    def _build_query_patterns(self) -> Dict[str, List[Dict]]:
        """Build regex patterns for common network queries"""
        return {
            'vlan_queries': [
                {
                    'pattern': r'(?:show|list|find).*?vlan(?:s)?(?:\s+(\d+(?:,\d+)*))?',
                    'action': 'show',
                    'target': 'vlan',
                    'extract_ids': True
                },
                {
                    'pattern': r'(?:create|add|configure).*?vlan\s+(\d+)(?:\s+name\s+(\w+))?',
                    'action': 'create',
                    'target': 'vlan',
                    'extract_params': ['vlan_id', 'vlan_name']
                },
                {
                    'pattern': r'(?:which|what).*?(?:device|switch).*?(?:has|contain).*?vlan\s+(\d+)',
                    'action': 'analyze',
                    'target': 'vlan_location',
                    'extract_params': ['vlan_id']
                }
            ],
            'interface_queries': [
                {
                    'pattern': r'(?:show|list).*?interface(?:s)?(?:\s+(\S+))?',
                    'action': 'show',
                    'target': 'interface',
                    'extract_params': ['interface_name']
                },
                {
                    'pattern': r'configure.*?interface\s+(\S+)',
                    'action': 'configure',
                    'target': 'interface',
                    'extract_params': ['interface_name']
                }
            ],
            'connectivity_queries': [
                {
                    'pattern': r'(?:create|add|need).*?(?:vlan\s+(\d+)).*?(?:communicate|reach|access).*?(?:subnet|network)\s+([0-9.]+(?:/\d+)?)',
                    'action': 'analyze_connectivity',
                    'target': 'vlan_to_subnet',
                    'extract_params': ['vlan_id', 'subnet']
                },
                {
                    'pattern': r'(?:routing|path).*?(?:from|between)\s+([0-9.]+).*?(?:to|and)\s+([0-9.]+)',
                    'action': 'analyze',
                    'target': 'routing_path',
                    'extract_params': ['source_ip', 'dest_ip']
                }
            ],
            'device_queries': [
                {
                    'pattern': r'(?:show|list).*?(?:device|router|switch)(?:s)?(?:\s+type\s+(\w+))?',
                    'action': 'show',
                    'target': 'devices',
                    'extract_params': ['device_type']
                },
                {
                    'pattern': r'(?:summarize|overview).*?network',
                    'action': 'analyze',
                    'target': 'network_summary'
                }
            ],
            'troubleshooting_queries': [
                {
                    'pattern': r'(?:troubleshoot|debug|problem|issue).*?(?:connectivity|ping|reach).*?([0-9.]+)',
                    'action': 'troubleshoot',
                    'target': 'connectivity',
                    'extract_params': ['target_ip']
                },
                {
                    'pattern': r'(?:why|problem).*?(?:can\'t|cannot).*?(?:reach|ping|connect).*?([0-9.]+)',
                    'action': 'troubleshoot',
                    'target': 'connectivity',
                    'extract_params': ['target_ip']
                }
            ]
        }
    
    def _load_config_templates(self) -> Dict[str, Dict]:
        """Load configuration templates for common tasks"""
        return {
            'create_vlan': {
                'commands': [
                    'vlan {vlan_id}',
                    ' name {vlan_name}',
                    'exit'
                ],
                'description': 'Create VLAN {vlan_id}',
                'risk_level': 'low'
            },
            'create_svi': {
                'commands': [
                    'interface vlan{vlan_id}',
                    ' description {description}',
                    ' ip address {ip_address} {subnet_mask}',
                    ' no shutdown',
                    'exit'
                ],
                'description': 'Create SVI for VLAN {vlan_id}',
                'risk_level': 'medium'
            },
            'configure_access_port': {
                'commands': [
                    'interface {interface}',
                    ' switchport mode access',
                    ' switchport access vlan {vlan_id}',
                    ' description {description}',
                    'exit'
                ],
                'description': 'Configure access port for VLAN {vlan_id}',
                'risk_level': 'medium'
            },
            'add_static_route': {
                'commands': [
                    'ip route {network} {mask} {next_hop}',
                ],
                'description': 'Add static route to {network}',
                'risk_level': 'high'
            }
        }
    
    async def process_query(self, query: str, devices: List, context: Dict = None) -> Dict[str, Any]:
        """Process query using rule-based logic"""
        try:
            # Build network context
            network_context = self._build_network_context(devices)
            
            # Parse query intent
            intent = self._parse_query_intent(query)
            
            if not intent:
                return self._generate_fallback_response(query, network_context)
            
            # Route to appropriate processor
            if intent.action == 'show':
                return await self._handle_show_query(intent, network_context)
            elif intent.action == 'create':
                return await self._handle_create_query(intent, network_context)
            elif intent.action == 'configure':
                return await self._handle_configure_query(intent, network_context)
            elif intent.action == 'analyze':
                return await self._handle_analyze_query(intent, network_context)
            elif intent.action == 'analyze_connectivity':
                return await self._handle_connectivity_query(intent, network_context)
            elif intent.action == 'troubleshoot':
                return await self._handle_troubleshoot_query(intent, network_context)
            else:
                return self._generate_fallback_response(query, network_context)
                
        except Exception as e:
            logger.error(f"Error processing query: {str(e)}")
            return {
                'response': f"I encountered an error: {str(e)}",
                'config_changes': [],
                'affected_devices': [],
                'confidence': 0.1
            }
    
    def _build_network_context(self, devices: List) -> Dict[str, Any]:
        """Build comprehensive network context"""
        context = {
            'devices': {},
            'vlans': {},  # vlan_id -> {devices, name, status}
            'subnets': {},  # subnet -> {device, interface, gateway}
            'interfaces': {},  # device -> {interface -> details}
            'routing': {},  # device -> routes
            'device_types': defaultdict(list),
            'stats': {
                'total_devices': 0,
                'total_interfaces': 0,
                'total_vlans': 0,
                'total_vrfs': 0
            }
        }
        
        for device in devices:
            if not hasattr(device, 'parsed_data') or not device.parsed_data:
                continue
                
            hostname = device.hostname
            parsed = device.parsed_data
            
            # Device info
            context['devices'][hostname] = {
                'hostname': hostname,
                'type': device.device_type,
                'parsed_data': parsed
            }
            
            context['device_types'][device.device_type].append(hostname)
            context['stats']['total_devices'] += 1
            
            # Interfaces
            interfaces = parsed.get('interfaces', {})
            context['interfaces'][hostname] = interfaces
            context['stats']['total_interfaces'] += len(interfaces)
            
            # VLANs
            for vlan_id, vlan_data in parsed.get('vlans', {}).items():
                if vlan_id not in context['vlans']:
                    context['vlans'][vlan_id] = {
                        'devices': [],
                        'name': vlan_data.get('name', ''),
                        'status': vlan_data.get('status', ''),
                        'interfaces': []
                    }
                context['vlans'][vlan_id]['devices'].append(hostname)
                context['stats']['total_vlans'] += 1
            
            # Subnets from interface IPs
            for intf_name, intf_data in interfaces.items():
                ip = intf_data.get('ip_address')
                mask = intf_data.get('subnet_mask')
                
                if ip and mask:
                    try:
                        network = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
                        subnet_str = str(network.network) + f"/{network.prefixlen}"
                        
                        context['subnets'][subnet_str] = {
                            'device': hostname,
                            'interface': intf_name,
                            'gateway': ip,
                            'network': str(network.network),
                            'mask': mask
                        }
                    except:
                        pass
            
            # VRFs
            context['stats']['total_vrfs'] += len(parsed.get('vrfs', {}))
        
        return context
    
    def _parse_query_intent(self, query: str) -> Optional[QueryIntent]:
        """Parse query to extract intent using regex patterns"""
        query_lower = query.lower().strip()
        
        for category, patterns in self.query_patterns.items():
            for pattern_info in patterns:
                match = re.search(pattern_info['pattern'], query_lower)
                if match:
                    parameters = {}
                    
                    # Extract parameters based on pattern configuration
                    if 'extract_params' in pattern_info:
                        for i, param_name in enumerate(pattern_info['extract_params'], 1):
                            if i <= len(match.groups()) and match.group(i):
                                parameters[param_name] = match.group(i).strip()
                    
                    # Extract VLAN IDs if specified
                    if pattern_info.get('extract_ids'):
                        if match.group(1):
                            vlan_ids = [id.strip() for id in match.group(1).split(',')]
                            parameters['vlan_ids'] = vlan_ids
                    
                    return QueryIntent(
                        action=pattern_info['action'],
                        target=pattern_info['target'],
                        parameters=parameters,
                        confidence=0.8
                    )
        
        return None
    
    async def _handle_show_query(self, intent: QueryIntent, network_context: Dict) -> Dict[str, Any]:
        """Handle show/list queries"""
        
        if intent.target == 'vlan':
            return self._show_vlans(intent.parameters, network_context)
        elif intent.target == 'interface':
            return self._show_interfaces(intent.parameters, network_context)
        elif intent.target == 'devices':
            return self._show_devices(intent.parameters, network_context)
        
        return {'response': 'Show query not implemented for this target', 'config_changes': [], 'affected_devices': [], 'confidence': 0.3}
    
    def _show_vlans(self, params: Dict, network_context: Dict) -> Dict[str, Any]:
        """Show VLAN information"""
        vlans = network_context['vlans']
        
        if 'vlan_ids' in params:
            # Show specific VLANs
            requested_vlans = params['vlan_ids']
            response = f"VLAN Information for VLANs {', '.join(requested_vlans)}:\n\n"
            
            for vlan_id in requested_vlans:
                if vlan_id in vlans:
                    vlan_info = vlans[vlan_id]
                    response += f"VLAN {vlan_id}:\n"
                    response += f"  Name: {vlan_info['name'] or 'Not set'}\n"
                    response += f"  Status: {vlan_info['status'] or 'Unknown'}\n"
                    response += f"  Devices: {', '.join(vlan_info['devices'])}\n\n"
                else:
                    response += f"VLAN {vlan_id}: Not found in any device\n\n"
        else:
            # Show all VLANs
            response = f"All VLANs in Network ({len(vlans)} total):\n\n"
            for vlan_id, vlan_info in sorted(vlans.items(), key=lambda x: int(x[0]) if x[0].isdigit() else 999):
                response += f"VLAN {vlan_id}: {vlan_info['name']} ({len(vlan_info['devices'])} devices)\n"
        
        return {
            'response': response,
            'config_changes': [],
            'affected_devices': [],
            'confidence': 0.9
        }
    
    def _show_interfaces(self, params: Dict, network_context: Dict) -> Dict[str, Any]:
        """Show interface information"""
        interfaces_dict = network_context['interfaces']
        
        if 'interface_name' in params and params['interface_name']:
            # Show specific interface
            interface_name = params['interface_name']
            response = f"Interface {interface_name} Information:\n\n"
            
            found = False
            for hostname, interfaces in interfaces_dict.items():
                if interface_name in interfaces:
                    found = True
                    intf_data = interfaces[interface_name]
                    response += f"Device: {hostname}\n"
                    response += f"  Description: {intf_data.get('description', 'Not set')}\n"
                    response += f"  IP Address: {intf_data.get('ip_address', 'Not set')}\n"
                    response += f"  Subnet Mask: {intf_data.get('subnet_mask', 'Not set')}\n"
                    response += f"  Access VLAN: {intf_data.get('access_vlan', 'Not set')}\n"
                    response += f"  Trunk VLANs: {', '.join(map(str, intf_data.get('trunk_vlans', []))) or 'None'}\n\n"
            
            if not found:
                response += f"Interface {interface_name} not found on any device\n"
        else:
            # Show all interfaces summary
            total_interfaces = sum(len(interfaces) for interfaces in interfaces_dict.values())
            response = f"Network Interfaces Summary ({total_interfaces} total):\n\n"
            
            for hostname, interfaces in interfaces_dict.items():
                response += f"{hostname}: {len(interfaces)} interfaces\n"
                for intf_name, intf_data in list(interfaces.items())[:3]:  # Show first 3
                    ip = intf_data.get('ip_address', 'No IP')
                    desc = intf_data.get('description', 'No description')
                    response += f"  {intf_name}: {ip} - {desc}\n"
                if len(interfaces) > 3:
                    response += f"  ... and {len(interfaces) - 3} more\n"
                response += "\n"
        
        return {
            'response': response,
            'config_changes': [],
            'affected_devices': list(interfaces_dict.keys()),
            'confidence': 0.9
        }
    
    def _show_devices(self, params: Dict, network_context: Dict) -> Dict[str, Any]:
        """Show device information"""
        devices = network_context['devices']
        device_types = network_context['device_types']
        stats = network_context['stats']
        
        if 'device_type' in params and params['device_type']:
            device_type = params['device_type'].title()
            if device_type in device_types:
                response = f"{device_type} Devices:\n\n"
                for hostname in device_types[device_type]:
                    device = devices[hostname]
                    intf_count = len(network_context['interfaces'].get(hostname, {}))
                    response += f"- {hostname} ({intf_count} interfaces)\n"
            else:
                response = f"No {device_type} devices found in network\n\n"
                response += "Available device types:\n"
                for dtype, hostnames in device_types.items():
                    response += f"  {dtype}: {len(hostnames)} devices\n"
        else:
            # Show all devices
            response = f"Network Devices Summary:\n"
            response += f"Total Devices: {stats['total_devices']}\n"
            response += f"Total Interfaces: {stats['total_interfaces']}\n"
            response += f"Total VLANs: {stats['total_vlans']}\n\n"
            
            response += "Devices by Type:\n"
            for device_type, hostnames in device_types.items():
                response += f"  {device_type}: {len(hostnames)} devices\n"
                for hostname in hostnames:
                    intf_count = len(network_context['interfaces'].get(hostname, {}))
                    response += f"    - {hostname} ({intf_count} interfaces)\n"
        
        return {
            'response': response,
            'config_changes': [],
            'affected_devices': list(devices.keys()),
            'confidence': 0.9
        }
    
    async def _handle_create_query(self, intent: QueryIntent, network_context: Dict) -> Dict[str, Any]:
        """Handle creation queries (VLAN, interface, etc.)"""
        
        if intent.target == 'vlan':
            return self._create_vlan_config(intent.parameters, network_context)
        
        return {'response': 'Create query not implemented for this target', 'config_changes': [], 'affected_devices': [], 'confidence': 0.3}
    
    def _create_vlan_config(self, params: Dict, network_context: Dict) -> Dict[str, Any]:
        """Generate VLAN creation configuration"""
        vlan_id = params.get('vlan_id')
        vlan_name = params.get('vlan_name', f'VLAN_{vlan_id}')
        
        if not vlan_id:
            return {'response': 'VLAN ID is required', 'config_changes': [], 'affected_devices': [], 'confidence': 0.1}
        
        # Check if VLAN already exists
        existing_vlans = network_context['vlans']
        if vlan_id in existing_vlans:
            devices_with_vlan = existing_vlans[vlan_id]['devices']
            response = f"VLAN {vlan_id} already exists on devices: {', '.join(devices_with_vlan)}"
            return {'response': response, 'config_changes': [], 'affected_devices': [], 'confidence': 0.8}
        
        # Find switches that should have this VLAN
        switch_devices = []
        for device_type, hostnames in network_context['device_types'].items():
            if 'switch' in device_type.lower():
                switch_devices.extend(hostnames)
        
        if not switch_devices:
            return {'response': 'No switch devices found to create VLAN on', 'config_changes': [], 'affected_devices': [], 'confidence': 0.5}
        
        # Generate configuration
        template = self.config_templates['create_vlan']
        config_changes = []
        
        for device_hostname in switch_devices:
            commands = [cmd.format(vlan_id=vlan_id, vlan_name=vlan_name) for cmd in template['commands']]
            config_changes.append({
                'device_hostname': device_hostname,
                'commands': commands,
                'description': template['description'].format(vlan_id=vlan_id, vlan_name=vlan_name),
                'risk_level': template['risk_level']
            })
        
        response = f"Configuration to create VLAN {vlan_id} ({vlan_name}):\n\n"
        response += f"This will be applied to {len(switch_devices)} switch(es): {', '.join(switch_devices)}\n\n"
        response += "Commands to execute:\n"
        for cmd in template['commands']:
            response += f"  {cmd.format(vlan_id=vlan_id, vlan_name=vlan_name)}\n"
        
        return {
            'response': response,
            'config_changes': config_changes,
            'affected_devices': switch_devices,
            'confidence': 0.9
        }
    
    async def _handle_configure_query(self, intent: QueryIntent, network_context: Dict) -> Dict[str, Any]:
        """Handle configuration queries"""
        return {'response': 'Configuration queries not fully implemented yet', 'config_changes': [], 'affected_devices': [], 'confidence': 0.3}
    
    async def _handle_connectivity_query(self, intent: QueryIntent, network_context: Dict) -> Dict[str, Any]:
        """Handle VLAN to subnet connectivity analysis"""
        
        vlan_id = intent.parameters.get('vlan_id')
        target_subnet = intent.parameters.get('subnet')
        
        if not vlan_id or not target_subnet:
            return {'response': 'VLAN ID and subnet are required', 'config_changes': [], 'affected_devices': [], 'confidence': 0.1}
        
        # Analyze connectivity requirements
        analysis = self._analyze_vlan_to_subnet_connectivity(vlan_id, target_subnet, network_context)
        
        response = f"Connectivity Analysis: VLAN {vlan_id} to Subnet {target_subnet}\n\n"
        response += analysis['analysis']
        
        return {
            'response': response,
            'config_changes': analysis['config_changes'],
            'affected_devices': analysis['affected_devices'],
            'confidence': analysis['confidence']
        }
    
    def _analyze_vlan_to_subnet_connectivity(self, vlan_id: str, target_subnet: str, network_context: Dict) -> Dict:
        """Analyze what's needed for VLAN to subnet connectivity"""
        
        vlans = network_context['vlans']
        subnets = network_context['subnets']
        devices = network_context['devices']
        
        analysis_text = ""
        config_changes = []
        affected_devices = []
        
        # Check if VLAN exists
        if vlan_id not in vlans:
            analysis_text += f"❌ VLAN {vlan_id} does not exist in any device\n"
            analysis_text += f"   → Need to create VLAN {vlan_id} first\n\n"
            
            # Generate VLAN creation config
            template = self.config_templates['create_vlan']
            switch_devices = network_context['device_types'].get('Switch', []) + network_context['device_types'].get('Layer3Switch', [])
            
            for device_hostname in switch_devices:
                commands = [cmd.format(vlan_id=vlan_id, vlan_name=f'VLAN_{vlan_id}') for cmd in template['commands']]
                config_changes.append({
                    'device_hostname': device_hostname,
                    'commands': commands,
                    'description': f'Create VLAN {vlan_id}',
                    'risk_level': 'low'
                })
            
            affected_devices.extend(switch_devices)
        else:
            vlan_info = vlans[vlan_id]
            analysis_text += f"✅ VLAN {vlan_id} exists on: {', '.join(vlan_info['devices'])}\n"
        
        # Check if target subnet exists
        subnet_found = False
        subnet_gateway = None
        subnet_device = None
        
        for subnet, subnet_info in subnets.items():
            if target_subnet in subnet or subnet.startswith(target_subnet):
                subnet_found = True
                subnet_gateway = subnet_info['gateway']
                subnet_device = subnet_info['device']
                analysis_text += f"✅ Target subnet {target_subnet} found on {subnet_device} (gateway: {subnet_gateway})\n"
                break
        
        if not subnet_found:
            analysis_text += f"❌ Target subnet {target_subnet} not found in any device interface\n"
            analysis_text += f"   → Need to configure an SVI or interface for this subnet\n\n"
            
            # Find a Layer 3 device to add the SVI
            l3_devices = network_context['device_types'].get('Layer3Switch', []) + network_context['device_types'].get('Router', [])
            
            if l3_devices:
                chosen_device = l3_devices[0]  # Choose first available L3 device
                
                # Generate SVI configuration
                # Calculate a gateway IP (first usable IP in subnet)
                try:
                    if '/' in target_subnet:
                        network = ipaddress.IPv4Network(target_subnet, strict=False)
                        gateway_ip = str(network.network_address + 1)
                        subnet_mask = str(network.netmask)
                    else:
                        gateway_ip = target_subnet  # Assume it's already an IP
                        subnet_mask = "255.255.255.0"  # Default assumption
                    
                    template = self.config_templates['create_svi']
                    commands = [cmd.format(
                        vlan_id=vlan_id,
                        description=f'Gateway for VLAN {vlan_id}',
                        ip_address=gateway_ip,
                        subnet_mask=subnet_mask
                    ) for cmd in template['commands']]
                    
                    config_changes.append({
                        'device_hostname': chosen_device,
                        'commands': commands,
                        'description': f'Create SVI for VLAN {vlan_id} connectivity to {target_subnet}',
                        'risk_level': 'medium'
                    })
                    
                    affected_devices.append(chosen_device)
                    
                except Exception as e:
                    analysis_text += f"⚠️ Could not calculate subnet details: {e}\n"
        
        # Check routing requirements
        if vlan_id in vlans and subnet_found:
            analysis_text += f"\n🔍 Routing Analysis:\n"
            analysis_text += f"   VLAN {vlan_id} devices: {', '.join(vlans[vlan_id]['devices'])}\n"
            analysis_text += f"   Subnet gateway device: {subnet_device}\n"
            
            # Check if they're on the same device
            vlan_devices_set = set(vlans[vlan_id]['devices'])
            if subnet_device in vlan_devices_set:
                analysis_text += f"✅ VLAN and subnet are on the same device - routing should work\n"
            else:
                analysis_text += f"⚠️ VLAN and subnet are on different devices - may need inter-device routing\n"
        
        analysis_text += f"\n📋 Summary:\n"
        analysis_text += f"   Configuration changes needed: {len(config_changes)}\n"
        analysis_text += f"   Affected devices: {len(set(affected_devices))}\n"
        
        return {
            'analysis': analysis_text,
            'config_changes': config_changes,
            'affected_devices': list(set(affected_devices)),
            'confidence': 0.8 if config_changes else 0.6
        }
    
    async def _handle_troubleshoot_query(self, intent: QueryIntent, network_context: Dict) -> Dict[str, Any]:
        """Handle troubleshooting queries"""
        target_ip = intent.parameters.get('target_ip')
        
        if not target_ip:
            return {'response': 'Target IP is required for troubleshooting', 'config_changes': [], 'affected_devices': [], 'confidence': 0.1}
        
        response = f"Troubleshooting Connectivity to {target_ip}:\n\n"
        response += "🔍 Diagnostic Steps:\n\n"
        
        # Find if target IP exists in our network
        found_target = False
        for subnet, subnet_info in network_context['subnets'].items():
            try:
                network = ipaddress.IPv4Network(subnet, strict=False)
                target = ipaddress.IPv4Address(target_ip)
                if target in network:
                    found_target = True
                    response += f"✅ Target IP {target_ip} is in subnet {subnet}\n"
                    response += f"   Gateway: {subnet_info['gateway']} on {subnet_info['device']}\n"
                    response += f"   Interface: {subnet_info['interface']}\n\n"
                    break
            except:
                continue
        
        if not found_target:
            response += f"⚠️ Target IP {target_ip} not found in any known subnet\n"
            response += f"   This may be external or on a different network segment\n\n"
        
        response += "🛠️ Recommended Diagnostic Commands:\n"
        response += f"1. ping {target_ip}\n"
        response += f"2. traceroute {target_ip}\n"
        response += "3. show ip route\n"
        response += "4. show ip arp\n"
        response += "5. show mac address-table\n\n"
        
        response += "🔧 Common Issues to Check:\n"
        response += "• Interface status (show ip interface brief)\n"
        response += "• VLAN configuration (show vlan brief)\n"
        response += "• Routing table (show ip route)\n"
        response += "• ACL restrictions (show access-lists)\n"
        response += "• ARP table (show arp)\n"
        
        return {
            'response': response,
            'config_changes': [],
            'affected_devices': [],
            'confidence': 0.7
        }
    
    async def _handle_analyze_query(self, intent: QueryIntent, network_context: Dict) -> Dict[str, Any]:
        """Handle analysis queries"""
        
        if intent.target == 'network_summary':
            return self._generate_network_summary(network_context)
        elif intent.target == 'vlan_location':
            vlan_id = intent.parameters.get('vlan_id')
            return self._analyze_vlan_location(vlan_id, network_context)
        
        return {'response': 'Analysis not implemented for this target', 'config_changes': [], 'affected_devices': [], 'confidence': 0.3}
    
    def _generate_network_summary(self, network_context: Dict) -> Dict[str, Any]:
        """Generate comprehensive network summary"""
        stats = network_context['stats']
        device_types = network_context['device_types']
        
        response = "📊 Network Summary Report\n"
        response += "=" * 40 + "\n\n"
        
        response += f"🏢 Infrastructure Overview:\n"
        response += f"   Total Devices: {stats['total_devices']}\n"
        response += f"   Total Interfaces: {stats['total_interfaces']}\n"
        response += f"   Total VLANs: {stats['total_vlans']}\n"
        response += f"   Total VRFs: {stats['total_vrfs']}\n\n"
        
        response += f"🖥️ Device Breakdown:\n"
        for device_type, hostnames in device_types.items():
            response += f"   {device_type}: {len(hostnames)} devices\n"
        
        response += f"\n🌐 Network Segments:\n"
        response += f"   Configured Subnets: {len(network_context['subnets'])}\n"
        
        # Top 5 VLANs by device count
        vlans = network_context['vlans']
        if vlans:
            sorted_vlans = sorted(vlans.items(), key=lambda x: len(x[1]['devices']), reverse=True)[:5]
            response += f"\n🔗 Most Widespread VLANs:\n"
            for vlan_id, vlan_info in sorted_vlans:
                device_count = len(vlan_info['devices'])
                vlan_name = vlan_info['name'] or 'Unnamed'
                response += f"   VLAN {vlan_id} ({vlan_name}): {device_count} devices\n"
        
        return {
            'response': response,
            'config_changes': [],
            'affected_devices': list(network_context['devices'].keys()),
            'confidence': 0.9
        }
    
    def _analyze_vlan_location(self, vlan_id: str, network_context: Dict) -> Dict[str, Any]:
        """Analyze which devices have a specific VLAN"""
        vlans = network_context['vlans']
        
        if not vlan_id:
            return {'response': 'VLAN ID is required', 'config_changes': [], 'affected_devices': [], 'confidence': 0.1}
        
        if vlan_id not in vlans:
            response = f"VLAN {vlan_id} not found in any device.\n\n"
            response += "Available VLANs:\n"
            for vid in sorted(vlans.keys(), key=lambda x: int(x) if x.isdigit() else 999):
                response += f"  VLAN {vid}: {vlans[vid]['name'] or 'Unnamed'}\n"
        else:
            vlan_info = vlans[vlan_id]
            devices_with_vlan = vlan_info['devices']
            
            response = f"VLAN {vlan_id} Location Analysis:\n\n"
            response += f"🏷️ VLAN Name: {vlan_info['name'] or 'Not set'}\n"
            response += f"📊 Status: {vlan_info['status'] or 'Unknown'}\n"
            response += f"🖥️ Present on {len(devices_with_vlan)} device(s):\n\n"
            
            for device_hostname in devices_with_vlan:
                device_info = network_context['devices'][device_hostname]
                response += f"  • {device_hostname} ({device_info['type']})\n"
                
                # Check which interfaces use this VLAN
                interfaces = network_context['interfaces'].get(device_hostname, {})
                vlan_interfaces = []
                
                for intf_name, intf_data in interfaces.items():
                    if intf_data.get('access_vlan') == vlan_id:
                        vlan_interfaces.append(f"{intf_name} (access)")
                    elif vlan_id in intf_data.get('trunk_vlans', []):
                        vlan_interfaces.append(f"{intf_name} (trunk)")
                
                if vlan_interfaces:
                    response += f"    Interfaces: {', '.join(vlan_interfaces)}\n"
                
                response += "\n"
        
        return {
            'response': response,
            'config_changes': [],
            'affected_devices': vlans.get(vlan_id, {}).get('devices', []),
            'confidence': 0.9
        }
    
    def _generate_fallback_response(self, query: str, network_context: Dict) -> Dict[str, Any]:
        """Generate a helpful fallback response when query intent is unclear"""
        
        stats = network_context['stats']
        
        response = f"I understand you're asking about the network, but I need more specific information.\n\n"
        response += f"Your network currently has:\n"
        response += f"• {stats['total_devices']} devices\n"
        response += f"• {stats['total_interfaces']} interfaces\n"
        response += f"• {stats['total_vlans']} VLANs\n"
        response += f"• {stats['total_vrfs']} VRFs\n\n"
        
        response += "You can ask me questions like:\n"
        response += "• 'Show me all VLANs'\n"
        response += "• 'Create VLAN 100 name USERS'\n"
        response += "• 'Which devices have VLAN 50?'\n"
        response += "• 'I need VLAN 200 to communicate with subnet 192.168.1.0/24'\n"
        response += "• 'List all switch devices'\n"
        response += "• 'Troubleshoot connectivity to 10.1.1.1'\n"
        response += "• 'Summarize the network'\n"
        
        return {
            'response': response,
            'config_changes': [],
            'affected_devices': [],
            'confidence': 0.4
        }


# Qwen3:32B Ollama Processor
class Qwen3OllamaProcessor:
    """Ollama processor optimized for Qwen3:32B model"""
    
    def __init__(self, model_name: str = "qwen3:32b"):
        self.model_name = model_name
        self.available = self._check_ollama_available()
        self.model_info = self._get_model_info()
        
        if self.available:
            logger.info(f"🦙 Ollama available with Qwen3:32B model: {self.model_name}")
        else:
            logger.warning("🦙 Ollama not available - using rule-based only")
    
    def _check_ollama_available(self) -> bool:
        """Check if Ollama is available and Qwen3 model is loaded"""
        try:
            import requests
            
            # Check if Ollama is running
            response = requests.get(_ollama_endpoint("/api/tags"), timeout=3)
            if response.status_code != 200:
                return False
            
            # Check if our model is available
            models = response.json().get('models', [])
            model_names = [model.get('name', '') for model in models]
            
            # Check for Qwen3 variants
            qwen3_variants = ['qwen3:32b', 'qwen3:32b-instruct', 'qwen3:32b-chat']
            for variant in qwen3_variants:
                if variant in model_names:
                    self.model_name = variant
                    logger.info(f"🎯 Found Qwen3 model: {variant}")
                    return True
            
            # Fallback check for any qwen3 model
            for model_name in model_names:
                if 'qwen3' in model_name.lower():
                    self.model_name = model_name
                    logger.info(f"🎯 Using Qwen3 model: {model_name}")
                    return True
            
            # Last resort - any qwen model
            for model_name in model_names:
                if 'qwen' in model_name.lower():
                    self.model_name = model_name
                    logger.info(f"🎯 Using Qwen model: {model_name}")
                    return True
            
            logger.warning(f"❌ Qwen3 model not found. Available models: {model_names}")
            return False
            
        except Exception as e:
            logger.warning(f"❌ Ollama check failed: {e}")
            return False
    
    def _get_model_info(self) -> Dict:
        """Get information about the loaded model"""
        if not self.available:
            return {}
        
        try:
            import requests
            response = requests.post(
                _ollama_endpoint("/api/show"),
                json={"name": self.model_name},
                timeout=5
            )
            
            if response.status_code == 200:
                return response.json()
        except Exception as e:
            logger.warning(f"Could not get model info: {e}")
        
        return {}
    
    async def process_with_ollama(self, query: str, network_context: Dict) -> Dict[str, Any]:
        """Process query using Qwen3:32B model"""
        if not self.available:
            raise Exception("Ollama with Qwen3 not available")
        
        try:
            import requests
            
            # Build optimized prompt for Qwen3
            prompt = _build_qwen3_prompt(self, query, network_context)
            
            # Qwen3-optimized parameters
            payload = {
                "model": self.model_name,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": 0.05,  # Very low for technical accuracy with Qwen3
                    "top_p": 0.85,
                    "top_k": 30,
                    "repeat_penalty": 1.05,
                    "num_predict": 3072,  # Allow longer responses for Qwen3
                    "stop": ["</think>", "<|im_end|>", "<|endoftext|>", "Human:", "User:", "Q:", "Question:"],
                    "seed": 42  # Consistent results
                }
            }
            
            logger.info(f"🤖 Processing with Qwen3:32B - Query: {query[:50]}...")
            
            response = requests.post(
                _ollama_endpoint("/api/generate"),
                json=payload,
                timeout=90  # Longer timeout for 32B model
            )
            
            if response.status_code == 200:
                payloads: List[Dict[str, Any]] = []

                try:
                    payloads.append(response.json())
                except ValueError:
                    raw_text = response.text.strip()
                    for line in raw_text.splitlines():
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            payloads.append(json.loads(line))
                        except json.JSONDecodeError:
                            logger.warning("Unable to decode Ollama response chunk: %s", line[:120])

                if not payloads:
                    raise Exception("Empty response from Ollama generate API")

                ai_response = "".join(chunk.get("response", "") for chunk in payloads)
                ai_response = re.sub(r"<think>.*?</think>", "", ai_response, flags=re.DOTALL).strip()

                if not ai_response:
                    raise Exception("Ollama returned no response text")

                # Parse structured response if available
                parsed_response = _parse_qwen3_response(self, ai_response)
                
                logger.info(f"✅ Qwen3 response generated ({len(ai_response)} chars)")
                
                return {
                    'response': parsed_response.get('response', ai_response),
                    'config_changes': parsed_response.get('config_changes', []),
                    'affected_devices': parsed_response.get('affected_devices', []),
                    'confidence': 0.90,  # Very high confidence for Qwen3:32B
                    'model_used': self.model_name
                }
            else:
                raise Exception(f"Ollama API error: {response.status_code} - {response.text}")
                
        except Exception as e:
            logger.error(f"❌ Qwen3 processing failed: {str(e)}")
            raise
    
    def _extract_risk_level(self, response: str) -> str:
        """Extract risk level from Qwen3 response"""
        risk_patterns = [
            r'\*\*RISK LEVEL:\*\*\s*(LOW|MEDIUM|HIGH)',
            r'RISK LEVEL?:\s*(LOW|MEDIUM|HIGH)',
            r'Risk:\s*(LOW|MEDIUM|HIGH)'
        ]
        
        for pattern in risk_patterns:
            match = re.search(pattern, response, re.IGNORECASE)
            if match:
                return match.group(1).lower()
        
        # Default risk assessment based on commands
        if any(keyword in response.lower() for keyword in ['route', 'vrf', 'spanning-tree']):
            return 'high'
        elif any(keyword in response.lower() for keyword in ['interface', 'vlan', 'access-list']):
            return 'medium'
        else:
            return 'low'


# Enhanced Hybrid Processor with Qwen3
class EnhancedHybridProcessor:
    """Enhanced hybrid processor using Qwen3:32B for complex queries"""
    
    def __init__(self):
        self.rule_processor = LocalNetworkQueryProcessor()
        self.qwen3_processor = Qwen3OllamaProcessor()
        
        # Log initialization status
        if self.qwen3_processor.available:
            logger.info("🚀 Enhanced AI available: Rule-based + Qwen3:32B")
        else:
            logger.info("🔧 Using rule-based processing only")
    
    async def process_query(self, query: str, devices: List, context: Dict = None) -> Dict[str, Any]:
        """Process query with enhanced Qwen3 capabilities"""
        try:
            # Always get rule-based result first
            rule_result = await self.rule_processor.process_query(query, devices, context)
            
            # Determine if we should use Qwen3 enhancement
            should_enhance = self._should_use_qwen3(query, rule_result)
            
            if should_enhance and self.qwen3_processor.available:
                try:
                    network_context = self.rule_processor._build_network_context(devices)
                    
                    # Use Qwen3 for enhancement
                    qwen3_result = await self.qwen3_processor.process_with_ollama(query, network_context)
                    
                    # Combine results intelligently
                    return self._combine_results(rule_result, qwen3_result, query)
                    
                except Exception as e:
                    logger.warning(f"Qwen3 enhancement failed: {e}")
                    # Fall back to rule-based result with note
                    rule_result['response'] += f"\n\n(Enhanced AI temporarily unavailable - using rule-based analysis)"
                    return rule_result
            
            # Add note if using rule-based only
            if should_enhance and not self.qwen3_processor.available:
                rule_result['response'] += f"\n\n💡 For more detailed analysis, ensure Qwen3:32B is running with Ollama"
            
            return rule_result
            
        except Exception as e:
            logger.error(f"Query processing failed: {str(e)}")
            return {
                'response': f"I encountered an error processing your query: {str(e)}",
                'config_changes': [],
                'affected_devices': [],
                'confidence': 0.1
            }
    
    def _should_use_qwen3(self, query: str, rule_result: Dict) -> bool:
        """Determine if Qwen3 enhancement would be beneficial"""
        
        # Always use Qwen3 for low confidence rule results
        if rule_result.get('confidence', 0) < 0.6:
            return True
        
        # Use Qwen3 for complex/analytical queries
        complex_indicators = [
            'explain', 'analyze', 'why', 'how', 'best practice', 
            'recommend', 'optimize', 'design', 'compare', 'evaluate',
            'troubleshoot', 'debug', 'assess', 'review', 'plan'
        ]
        
        if any(indicator in query.lower() for indicator in complex_indicators):
            return True
        
        # Use Qwen3 for multi-part or detailed questions
        if len(query.split('?')) > 2 or len(query.split(' and ')) > 2:
            return True
        
        # Use Qwen3 for questions over 100 characters (likely complex)
        if len(query) > 100:
            return True
        
        return False
    
    def _combine_results(self, rule_result: Dict, qwen3_result: Dict, query: str) -> Dict[str, Any]:
        """Intelligently combine rule-based and Qwen3 results"""
        
        # Qwen3 responses are typically more comprehensive
        if qwen3_result.get('response') and len(qwen3_result['response']) > 100:
            primary_response = qwen3_result['response']
            
            # Append rule-based data if it adds specific technical details
            if rule_result.get('config_changes') and not qwen3_result.get('config_changes'):
                primary_response += f"\n\n--- Additional Technical Details ---\n{rule_result.get('response', '')}"
        else:
            primary_response = rule_result.get('response', '')
        
        # Prefer Qwen3 config changes if they're more detailed, otherwise use rule-based
        config_changes = qwen3_result.get('config_changes', [])
        if not config_changes or (rule_result.get('config_changes') and 
                                 len(rule_result['config_changes']) > len(config_changes)):
            config_changes = rule_result.get('config_changes', [])
        
        # Combine affected devices intelligently
        affected_devices = list(set(
            rule_result.get('affected_devices', []) + 
            qwen3_result.get('affected_devices', [])
        ))
        
        # Use Qwen3's higher confidence
        confidence = max(
            rule_result.get('confidence', 0),
            qwen3_result.get('confidence', 0)
        )
        
        return {
            'response': primary_response,
            'config_changes': config_changes,
            'affected_devices': affected_devices,
            'confidence': confidence,
            'processing_method': 'hybrid_qwen3_enhanced',
            'model_used': qwen3_result.get('model_used', 'rule_based')
        }


# Utility functions for network analysis
def find_vlan_spanning_devices(network_context: Dict, vlan_id: str) -> List[str]:
    """Find all devices that have a specific VLAN configured"""
    devices_with_vlan = []
    
    for hostname, device_info in network_context.get('devices', {}).items():
        # Check VLANs in parsed data
        vlans = network_context.get('vlans', {})
        if vlan_id in vlans and hostname in vlans[vlan_id]['devices']:
            devices_with_vlan.append(hostname)
        
        # Also check interfaces with access VLAN
        interfaces = network_context['interfaces'].get(hostname, {})
        for intf_data in interfaces.values():
            if intf_data.get('access_vlan') == vlan_id:
                if hostname not in devices_with_vlan:
                    devices_with_vlan.append(hostname)
                break
    
    return devices_with_vlan

def find_subnet_gateways(network_context: Dict, target_subnet: str) -> List[Dict]:
    """Find potential gateways for a subnet"""
    gateways = []
    
    for hostname, device_info in network_context.get('devices', {}).items():
        interfaces = network_context['interfaces'].get(hostname, {})
        for intf_name, intf_data in interfaces.items():
            if intf_data.get('ip_address'):
                gateways.append({
                    'device': hostname,
                    'interface': intf_name,
                    'ip': intf_data.get('ip_address'),
                    'mask': intf_data.get('subnet_mask')
                })
    
    return gateways

def analyze_vlan_connectivity(network_context: Dict, source_vlan: str, dest_subnet: str) -> Dict:
    """Analyze connectivity requirements between VLAN and subnet"""
    
    # Find devices with the source VLAN
    vlan_devices = find_vlan_spanning_devices(network_context, source_vlan)
    
    # Find potential gateways for destination subnet
    gateways = find_subnet_gateways(network_context, dest_subnet)
    
    return {
        'source_vlan_devices': vlan_devices,
        'potential_gateways': gateways,
        'routing_required': len(gateways) > 0
    }

# Main export - use the enhanced hybrid processor
HybridNetworkQueryProcessor = EnhancedHybridProcessor

# Example usage and testing
if __name__ == "__main__":
    import asyncio
    
    async def test_processor():
        """Test the local query processor"""
        processor = LocalNetworkQueryProcessor()
        
        # Mock device data for testing
        class MockDevice:
            def __init__(self, hostname, device_type, parsed_data):
                self.hostname = hostname
                self.device_type = device_type
                self.parsed_data = parsed_data
        
        devices = [
            MockDevice("CORE-SW-01", "Layer3Switch", {
                'interfaces': {
                    'GigabitEthernet1/1': {'description': 'Uplink', 'ip_address': '192.168.1.1', 'subnet_mask': '255.255.255.0'},
                    'Vlan10': {'description': 'User VLAN', 'ip_address': '10.1.10.1', 'subnet_mask': '255.255.255.0'}
                },
                'vlans': {
                    '10': {'name': 'USERS', 'status': 'active'},
                    '20': {'name': 'SERVERS', 'status': 'active'}
                },
                'vrfs': {}
            }),
            MockDevice("ACCESS-SW-01", "Switch", {
                'interfaces': {
                    'FastEthernet0/1': {'access_vlan': '10'},
                    'FastEthernet0/2': {'access_vlan': '20'}
                },
                'vlans': {
                    '10': {'name': 'USERS', 'status': 'active'},
                    '20': {'name': 'SERVERS', 'status': 'active'}
                },
                'vrfs': {}
            })
        ]
        
        ##!/usr/bin/env python3
"""
Local Network Query Processor
Rule-based intelligent network analysis without external AI APIs
Enhanced with Qwen3:32B local LLM support
"""

import re
import json
import logging
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
import ipaddress
from collections import defaultdict

logger = logging.getLogger(__name__)

@dataclass
class QueryIntent:
    """Structured representation of user intent"""
    action: str  # show, create, configure, analyze, troubleshoot
    target: str  # vlan, interface, device, route
    parameters: Dict[str, Any]
    confidence: float

class LocalNetworkQueryProcessor:
    """
    Rule-based network query processor that doesn't require external AI APIs
    Provides intelligent responses using network engineering logic
    """
    
    def __init__(self):
        self.query_patterns = self._build_query_patterns()
        self.config_templates = self._load_config_templates()
        
    def _build_query_patterns(self) -> Dict[str, List[Dict]]:
        """Build regex patterns for common network queries"""
        return {
            'vlan_queries': [
                {
                    'pattern': r'(?:show|list|find).*?vlan(?:s)?(?:\s+(\d+(?:,\d+)*))?',
                    'action': 'show',
                    'target': 'vlan',
                    'extract_ids': True
                },
                {
                    'pattern': r'(?:create|add|configure).*?vlan\s+(\d+)(?:\s+name\s+(\w+))?',
                    'action': 'create',
                    'target': 'vlan',
                    'extract_params': ['vlan_id', 'vlan_name']
                },
                {
                    'pattern': r'(?:which|what).*?(?:device|switch).*?(?:has|contain).*?vlan\s+(\d+)',
                    'action': 'analyze',
                    'target': 'vlan_location',
                    'extract_params': ['vlan_id']
                }
            ],
            'interface_queries': [
                {
                    'pattern': r'(?:show|list).*?interface(?:s)?(?:\s+(\S+))?',
                    'action': 'show',
                    'target': 'interface',
                    'extract_params': ['interface_name']
                },
                {
                    'pattern': r'configure.*?interface\s+(\S+)',
                    'action': 'configure',
                    'target': 'interface',
                    'extract_params': ['interface_name']
                }
            ],
            'connectivity_queries': [
                {
                    'pattern': r'(?:create|add|need).*?(?:vlan\s+(\d+)).*?(?:communicate|reach|access).*?(?:subnet|network)\s+([0-9.]+(?:/\d+)?)',
                    'action': 'analyze_connectivity',
                    'target': 'vlan_to_subnet',
                    'extract_params': ['vlan_id', 'subnet']
                },
                {
                    'pattern': r'(?:routing|path).*?(?:from|between)\s+([0-9.]+).*?(?:to|and)\s+([0-9.]+)',
                    'action': 'analyze',
                    'target': 'routing_path',
                    'extract_params': ['source_ip', 'dest_ip']
                }
            ],
            'device_queries': [
                {
                    'pattern': r'(?:show|list).*?(?:device|router|switch)(?:s)?(?:\s+type\s+(\w+))?',
                    'action': 'show',
                    'target': 'devices',
                    'extract_params': ['device_type']
                },
                {
                    'pattern': r'(?:summarize|overview).*?network',
                    'action': 'analyze',
                    'target': 'network_summary'
                }
            ],
            'troubleshooting_queries': [
                {
                    'pattern': r'(?:troubleshoot|debug|problem|issue).*?(?:connectivity|ping|reach).*?([0-9.]+)',
                    'action': 'troubleshoot',
                    'target': 'connectivity',
                    'extract_params': ['target_ip']
                },
                {
                    'pattern': r'(?:why|problem).*?(?:can\'t|cannot).*?(?:reach|ping|connect).*?([0-9.]+)',
                    'action': 'troubleshoot',
                    'target': 'connectivity',
                    'extract_params': ['target_ip']
                }
            ]
        }
    
    def _load_config_templates(self) -> Dict[str, Dict]:
        """Load configuration templates for common tasks"""
        return {
            'create_vlan': {
                'commands': [
                    'vlan {vlan_id}',
                    ' name {vlan_name}',
                    'exit'
                ],
                'description': 'Create VLAN {vlan_id}',
                'risk_level': 'low'
            },
            'create_svi': {
                'commands': [
                    'interface vlan{vlan_id}',
                    ' description {description}',
                    ' ip address {ip_address} {subnet_mask}',
                    ' no shutdown',
                    'exit'
                ],
                'description': 'Create SVI for VLAN {vlan_id}',
                'risk_level': 'medium'
            },
            'configure_access_port': {
                'commands': [
                    'interface {interface}',
                    ' switchport mode access',
                    ' switchport access vlan {vlan_id}',
                    ' description {description}',
                    'exit'
                ],
                'description': 'Configure access port for VLAN {vlan_id}',
                'risk_level': 'medium'
            },
            'add_static_route': {
                'commands': [
                    'ip route {network} {mask} {next_hop}',
                ],
                'description': 'Add static route to {network}',
                'risk_level': 'high'
            }
        }
    
    async def process_query(self, query: str, devices: List, context: Dict = None) -> Dict[str, Any]:
        """Process query using rule-based logic"""
        try:
            # Build network context
            network_context = self._build_network_context(devices)
            
            # Parse query intent
            intent = self._parse_query_intent(query)
            
            if not intent:
                return self._generate_fallback_response(query, network_context)
            
            # Route to appropriate processor
            if intent.action == 'show':
                return await self._handle_show_query(intent, network_context)
            elif intent.action == 'create':
                return await self._handle_create_query(intent, network_context)
            elif intent.action == 'configure':
                return await self._handle_configure_query(intent, network_context)
            elif intent.action == 'analyze':
                return await self._handle_analyze_query(intent, network_context)
            elif intent.action == 'analyze_connectivity':
                return await self._handle_connectivity_query(intent, network_context)
            elif intent.action == 'troubleshoot':
                return await self._handle_troubleshoot_query(intent, network_context)
            else:
                return self._generate_fallback_response(query, network_context)
                
        except Exception as e:
            logger.error(f"Error processing query: {str(e)}")
            return {
                'response': f"I encountered an error: {str(e)}",
                'config_changes': [],
                'affected_devices': [],
                'confidence': 0.1
            }
    
    def _build_network_context(self, devices: List) -> Dict[str, Any]:
        """Build comprehensive network context"""
        context = {
            'devices': {},
            'vlans': {},  # vlan_id -> {devices, name, status}
            'subnets': {},  # subnet -> {device, interface, gateway}
            'interfaces': {},  # device -> {interface -> details}
            'routing': {},  # device -> routes
            'device_types': defaultdict(list),
            'stats': {
                'total_devices': 0,
                'total_interfaces': 0,
                'total_vlans': 0,
                'total_vrfs': 0
            }
        }
        
        for device in devices:
            if not hasattr(device, 'parsed_data') or not device.parsed_data:
                continue
                
            hostname = device.hostname
            parsed = device.parsed_data
            
            # Device info
            context['devices'][hostname] = {
                'hostname': hostname,
                'type': device.device_type,
                'parsed_data': parsed
            }
            
            context['device_types'][device.device_type].append(hostname)
            context['stats']['total_devices'] += 1
            
            # Interfaces
            interfaces = parsed.get('interfaces', {})
            context['interfaces'][hostname] = interfaces
            context['stats']['total_interfaces'] += len(interfaces)
            
            # VLANs
            for vlan_id, vlan_data in parsed.get('vlans', {}).items():
                if vlan_id not in context['vlans']:
                    context['vlans'][vlan_id] = {
                        'devices': [],
                        'name': vlan_data.get('name', ''),
                        'status': vlan_data.get('status', ''),
                        'interfaces': []
                    }
                context['vlans'][vlan_id]['devices'].append(hostname)
                context['stats']['total_vlans'] += 1
            
            # Subnets from interface IPs
            for intf_name, intf_data in interfaces.items():
                ip = intf_data.get('ip_address')
                mask = intf_data.get('subnet_mask')
                
                if ip and mask:
                    try:
                        network = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
                        subnet_str = str(network.network) + f"/{network.prefixlen}"
                        
                        context['subnets'][subnet_str] = {
                            'device': hostname,
                            'interface': intf_name,
                            'gateway': ip,
                            'network': str(network.network),
                            'mask': mask
                        }
                    except:
                        pass
            
            # VRFs
            context['stats']['total_vrfs'] += len(parsed.get('vrfs', {}))
        
        return context
    
    def _parse_query_intent(self, query: str) -> Optional[QueryIntent]:
        """Parse query to extract intent using regex patterns"""
        query_lower = query.lower().strip()
        
        for category, patterns in self.query_patterns.items():
            for pattern_info in patterns:
                match = re.search(pattern_info['pattern'], query_lower)
                if match:
                    parameters = {}
                    
                    # Extract parameters based on pattern configuration
                    if 'extract_params' in pattern_info:
                        for i, param_name in enumerate(pattern_info['extract_params'], 1):
                            if i <= len(match.groups()) and match.group(i):
                                parameters[param_name] = match.group(i).strip()
                    
                    # Extract VLAN IDs if specified
                    if pattern_info.get('extract_ids'):
                        if match.group(1):
                            vlan_ids = [id.strip() for id in match.group(1).split(',')]
                            parameters['vlan_ids'] = vlan_ids
                    
                    return QueryIntent(
                        action=pattern_info['action'],
                        target=pattern_info['target'],
                        parameters=parameters,
                        confidence=0.8
                    )
        
        return None
    
    async def _handle_show_query(self, intent: QueryIntent, network_context: Dict) -> Dict[str, Any]:
        """Handle show/list queries"""
        
        if intent.target == 'vlan':
            return self._show_vlans(intent.parameters, network_context)
        elif intent.target == 'interface':
            return self._show_interfaces(intent.parameters, network_context)
        elif intent.target == 'devices':
            return self._show_devices(intent.parameters, network_context)
        
        return {'response': 'Show query not implemented for this target', 'config_changes': [], 'affected_devices': [], 'confidence': 0.3}
    
    def _show_vlans(self, params: Dict, network_context: Dict) -> Dict[str, Any]:
        """Show VLAN information"""
        vlans = network_context['vlans']
        
        if 'vlan_ids' in params:
            # Show specific VLANs
            requested_vlans = params['vlan_ids']
            response = f"VLAN Information for VLANs {', '.join(requested_vlans)}:\n\n"
            
            for vlan_id in requested_vlans:
                if vlan_id in vlans:
                    vlan_info = vlans[vlan_id]
                    response += f"VLAN {vlan_id}:\n"
                    response += f"  Name: {vlan_info['name'] or 'Not set'}\n"
                    response += f"  Status: {vlan_info['status'] or 'Unknown'}\n"
                    response += f"  Devices: {', '.join(vlan_info['devices'])}\n\n"
                else:
                    response += f"VLAN {vlan_id}: Not found in any device\n\n"
        else:
            # Show all VLANs
            response = f"All VLANs in Network ({len(vlans)} total):\n\n"
            for vlan_id, vlan_info in sorted(vlans.items(), key=lambda x: int(x[0]) if x[0].isdigit() else 999):
                response += f"VLAN {vlan_id}: {vlan_info['name']} ({len(vlan_info['devices'])} devices)\n"
        
        return {
            'response': response,
            'config_changes': [],
            'affected_devices': [],
            'confidence': 0.9
        }
    
    def _show_interfaces(self, params: Dict, network_context: Dict) -> Dict[str, Any]:
        """Show interface information"""
        interfaces_dict = network_context['interfaces']
        
        if 'interface_name' in params and params['interface_name']:
            # Show specific interface
            interface_name = params['interface_name']
            response = f"Interface {interface_name} Information:\n\n"
            
            found = False
            for hostname, interfaces in interfaces_dict.items():
                if interface_name in interfaces:
                    found = True
                    intf_data = interfaces[interface_name]
                    response += f"Device: {hostname}\n"
                    response += f"  Description: {intf_data.get('description', 'Not set')}\n"
                    response += f"  IP Address: {intf_data.get('ip_address', 'Not set')}\n"
                    response += f"  Subnet Mask: {intf_data.get('subnet_mask', 'Not set')}\n"
                    response += f"  Access VLAN: {intf_data.get('access_vlan', 'Not set')}\n"
                    response += f"  Trunk VLANs: {', '.join(map(str, intf_data.get('trunk_vlans', []))) or 'None'}\n\n"
            
            if not found:
                response += f"Interface {interface_name} not found on any device\n"
        else:
            # Show all interfaces summary
            total_interfaces = sum(len(interfaces) for interfaces in interfaces_dict.values())
            response = f"Network Interfaces Summary ({total_interfaces} total):\n\n"
            
            for hostname, interfaces in interfaces_dict.items():
                response += f"{hostname}: {len(interfaces)} interfaces\n"
                for intf_name, intf_data in list(interfaces.items())[:3]:  # Show first 3
                    ip = intf_data.get('ip_address', 'No IP')
                    desc = intf_data.get('description', 'No description')
                    response += f"  {intf_name}: {ip} - {desc}\n"
                if len(interfaces) > 3:
                    response += f"  ... and {len(interfaces) - 3} more\n"
                response += "\n"
        
        return {
            'response': response,
            'config_changes': [],
            'affected_devices': list(interfaces_dict.keys()),
            'confidence': 0.9
        }
    
    def _show_devices(self, params: Dict, network_context: Dict) -> Dict[str, Any]:
        """Show device information"""
        devices = network_context['devices']
        device_types = network_context['device_types']
        stats = network_context['stats']
        
        if 'device_type' in params and params['device_type']:
            device_type = params['device_type'].title()
            if device_type in device_types:
                response = f"{device_type} Devices:\n\n"
                for hostname in device_types[device_type]:
                    device = devices[hostname]
                    intf_count = len(network_context['interfaces'].get(hostname, {}))
                    response += f"- {hostname} ({intf_count} interfaces)\n"
            else:
                response = f"No {device_type} devices found in network\n\n"
                response += "Available device types:\n"
                for dtype, hostnames in device_types.items():
                    response += f"  {dtype}: {len(hostnames)} devices\n"
        else:
            # Show all devices
            response = f"Network Devices Summary:\n"
            response += f"Total Devices: {stats['total_devices']}\n"
            response += f"Total Interfaces: {stats['total_interfaces']}\n"
            response += f"Total VLANs: {stats['total_vlans']}\n\n"
            
            response += "Devices by Type:\n"
            for device_type, hostnames in device_types.items():
                response += f"  {device_type}: {len(hostnames)} devices\n"
                for hostname in hostnames:
                    intf_count = len(network_context['interfaces'].get(hostname, {}))
                    response += f"    - {hostname} ({intf_count} interfaces)\n"
        
        return {
            'response': response,
            'config_changes': [],
            'affected_devices': list(devices.keys()),
            'confidence': 0.9
        }
    
    async def _handle_create_query(self, intent: QueryIntent, network_context: Dict) -> Dict[str, Any]:
        """Handle creation queries (VLAN, interface, etc.)"""
        
        if intent.target == 'vlan':
            return self._create_vlan_config(intent.parameters, network_context)
        
        return {'response': 'Create query not implemented for this target', 'config_changes': [], 'affected_devices': [], 'confidence': 0.3}
    
    def _create_vlan_config(self, params: Dict, network_context: Dict) -> Dict[str, Any]:
        """Generate VLAN creation configuration"""
        vlan_id = params.get('vlan_id')
        vlan_name = params.get('vlan_name', f'VLAN_{vlan_id}')
        
        if not vlan_id:
            return {'response': 'VLAN ID is required', 'config_changes': [], 'affected_devices': [], 'confidence': 0.1}
        
        # Check if VLAN already exists
        existing_vlans = network_context['vlans']
        if vlan_id in existing_vlans:
            devices_with_vlan = existing_vlans[vlan_id]['devices']
            response = f"VLAN {vlan_id} already exists on devices: {', '.join(devices_with_vlan)}"
            return {'response': response, 'config_changes': [], 'affected_devices': [], 'confidence': 0.8}
        
        # Find switches that should have this VLAN
        switch_devices = []
        for device_type, hostnames in network_context['device_types'].items():
            if 'switch' in device_type.lower():
                switch_devices.extend(hostnames)
        
        if not switch_devices:
            return {'response': 'No switch devices found to create VLAN on', 'config_changes': [], 'affected_devices': [], 'confidence': 0.5}
        
        # Generate configuration
        template = self.config_templates['create_vlan']
        config_changes = []
        
        for device_hostname in switch_devices:
            commands = [cmd.format(vlan_id=vlan_id, vlan_name=vlan_name) for cmd in template['commands']]
            config_changes.append({
                'device_hostname': device_hostname,
                'commands': commands,
                'description': template['description'].format(vlan_id=vlan_id, vlan_name=vlan_name),
                'risk_level': template['risk_level']
            })
        
        response = f"Configuration to create VLAN {vlan_id} ({vlan_name}):\n\n"
        response += f"This will be applied to {len(switch_devices)} switch(es): {', '.join(switch_devices)}\n\n"
        response += "Commands to execute:\n"
        for cmd in template['commands']:
            response += f"  {cmd.format(vlan_id=vlan_id, vlan_name=vlan_name)}\n"
        
        return {
            'response': response,
            'config_changes': config_changes,
            'affected_devices': switch_devices,
            'confidence': 0.9
        }
    
    async def _handle_configure_query(self, intent: QueryIntent, network_context: Dict) -> Dict[str, Any]:
        """Handle configuration queries"""
        return {'response': 'Configuration queries not fully implemented yet', 'config_changes': [], 'affected_devices': [], 'confidence': 0.3}
    
    async def _handle_connectivity_query(self, intent: QueryIntent, network_context: Dict) -> Dict[str, Any]:
        """Handle VLAN to subnet connectivity analysis"""
        
        vlan_id = intent.parameters.get('vlan_id')
        target_subnet = intent.parameters.get('subnet')
        
        if not vlan_id or not target_subnet:
            return {'response': 'VLAN ID and subnet are required', 'config_changes': [], 'affected_devices': [], 'confidence': 0.1}
        
        # Analyze connectivity requirements
        analysis = self._analyze_vlan_to_subnet_connectivity(vlan_id, target_subnet, network_context)
        
        response = f"Connectivity Analysis: VLAN {vlan_id} to Subnet {target_subnet}\n\n"
        response += analysis['analysis']
        
        return {
            'response': response,
            'config_changes': analysis['config_changes'],
            'affected_devices': analysis['affected_devices'],
            'confidence': analysis['confidence']
        }
    
    def _analyze_vlan_to_subnet_connectivity(self, vlan_id: str, target_subnet: str, network_context: Dict) -> Dict:
        """Analyze what's needed for VLAN to subnet connectivity"""
        
        vlans = network_context['vlans']
        subnets = network_context['subnets']
        devices = network_context['devices']
        
        analysis_text = ""
        config_changes = []
        affected_devices = []
        
        # Check if VLAN exists
        if vlan_id not in vlans:
            analysis_text += f"❌ VLAN {vlan_id} does not exist in any device\n"
            analysis_text += f"   → Need to create VLAN {vlan_id} first\n\n"
            
            # Generate VLAN creation config
            template = self.config_templates['create_vlan']
            switch_devices = network_context['device_types'].get('Switch', []) + network_context['device_types'].get('Layer3Switch', [])
            
            for device_hostname in switch_devices:
                commands = [cmd.format(vlan_id=vlan_id, vlan_name=f'VLAN_{vlan_id}') for cmd in template['commands']]
                config_changes.append({
                    'device_hostname': device_hostname,
                    'commands': commands,
                    'description': f'Create VLAN {vlan_id}',
                    'risk_level': 'low'
                })
            
            affected_devices.extend(switch_devices)
        else:
            vlan_info = vlans[vlan_id]
            analysis_text += f"✅ VLAN {vlan_id} exists on: {', '.join(vlan_info['devices'])}\n"
        
        # Check if target subnet exists
        subnet_found = False
        subnet_gateway = None
        subnet_device = None
        
        for subnet, subnet_info in subnets.items():
            if target_subnet in subnet or subnet.startswith(target_subnet):
                subnet_found = True
                subnet_gateway = subnet_info['gateway']
                subnet_device = subnet_info['device']
                analysis_text += f"✅ Target subnet {target_subnet} found on {subnet_device} (gateway: {subnet_gateway})\n"
                break
        
        if not subnet_found:
            analysis_text += f"❌ Target subnet {target_subnet} not found in any device interface\n"
            analysis_text += f"   → Need to configure an SVI or interface for this subnet\n\n"
            
            # Find a Layer 3 device to add the SVI
            l3_devices = network_context['device_types'].get('Layer3Switch', []) + network_context['device_types'].get('Router', [])
            
            if l3_devices:
                chosen_device = l3_devices[0]  # Choose first available L3 device
                
                # Generate SVI configuration
                # Calculate a gateway IP (first usable IP in subnet)
                try:
                    if '/' in target_subnet:
                        network = ipaddress.IPv4Network(target_subnet, strict=False)
                        gateway_ip = str(network.network_address + 1)
                        subnet_mask = str(network.netmask)
                    else:
                        gateway_ip = target_subnet  # Assume it's already an IP
                        subnet_mask = "255.255.255.0"  # Default assumption
                    
                    template = self.config_templates['create_svi']
                    commands = [cmd.format(
                        vlan_id=vlan_id,
                        description=f'Gateway for VLAN {vlan_id}',
                        ip_address=gateway_ip,
                        subnet_mask=subnet_mask
                    ) for cmd in template['commands']]
                    
                    config_changes.append({
                        'device_hostname': chosen_device,
                        'commands': commands,
                        'description': f'Create SVI for VLAN {vlan_id} connectivity to {target_subnet}',
                        'risk_level': 'medium'
                    })
                    
                    affected_devices.append(chosen_device)
                    
                except Exception as e:
                    analysis_text += f"⚠️ Could not calculate subnet details: {e}\n"
        
        # Check routing requirements
        if vlan_id in vlans and subnet_found:
            analysis_text += f"\n🔍 Routing Analysis:\n"
            analysis_text += f"   VLAN {vlan_id} devices: {', '.join(vlans[vlan_id]['devices'])}\n"
            analysis_text += f"   Subnet gateway device: {subnet_device}\n"
            
            # Check if they're on the same device
            vlan_devices_set = set(vlans[vlan_id]['devices'])
            if subnet_device in vlan_devices_set:
                analysis_text += f"✅ VLAN and subnet are on the same device - routing should work\n"
            else:
                analysis_text += f"⚠️ VLAN and subnet are on different devices - may need inter-device routing\n"
        
        analysis_text += f"\n📋 Summary:\n"
        analysis_text += f"   Configuration changes needed: {len(config_changes)}\n"
        analysis_text += f"   Affected devices: {len(set(affected_devices))}\n"
        
        return {
            'analysis': analysis_text,
            'config_changes': config_changes,
            'affected_devices': list(set(affected_devices)),
            'confidence': 0.8 if config_changes else 0.6
        }
    
    async def _handle_troubleshoot_query(self, intent: QueryIntent, network_context: Dict) -> Dict[str, Any]:
        """Handle troubleshooting queries"""
        target_ip = intent.parameters.get('target_ip')
        
        if not target_ip:
            return {'response': 'Target IP is required for troubleshooting', 'config_changes': [], 'affected_devices': [], 'confidence': 0.1}
        
        response = f"Troubleshooting Connectivity to {target_ip}:\n\n"
        response += "🔍 Diagnostic Steps:\n\n"
        
        # Find if target IP exists in our network
        found_target = False
        for subnet, subnet_info in network_context['subnets'].items():
            try:
                network = ipaddress.IPv4Network(subnet, strict=False)
                target = ipaddress.IPv4Address(target_ip)
                if target in network:
                    found_target = True
                    response += f"✅ Target IP {target_ip} is in subnet {subnet}\n"
                    response += f"   Gateway: {subnet_info['gateway']} on {subnet_info['device']}\n"
                    response += f"   Interface: {subnet_info['interface']}\n\n"
                    break
            except:
                continue
        
        if not found_target:
            response += f"⚠️ Target IP {target_ip} not found in any known subnet\n"
            response += f"   This may be external or on a different network segment\n\n"
        
        response += "🛠️ Recommended Diagnostic Commands:\n"
        response += f"1. ping {target_ip}\n"
        response += f"2. traceroute {target_ip}\n"
        response += "3. show ip route\n"
        response += "4. show ip arp\n"
        response += "5. show mac address-table\n\n"
        
        response += "🔧 Common Issues to Check:\n"
        response += "• Interface status (show ip interface brief)\n"
        response += "• VLAN configuration (show vlan brief)\n"
        response += "• Routing table (show ip route)\n"
        response += "• ACL restrictions (show access-lists)\n"
        response += "• ARP table (show arp)\n"
        
        return {
            'response': response,
            'config_changes': [],
            'affected_devices': [],
            'confidence': 0.7
        }
    
    async def _handle_analyze_query(self, intent: QueryIntent, network_context: Dict) -> Dict[str, Any]:
        """Handle analysis queries"""
        
        if intent.target == 'network_summary':
            return self._generate_network_summary(network_context)
        elif intent.target == 'vlan_location':
            vlan_id = intent.parameters.get('vlan_id')
            return self._analyze_vlan_location(vlan_id, network_context)
        
        return {'response': 'Analysis not implemented for this target', 'config_changes': [], 'affected_devices': [], 'confidence': 0.3}
    
    def _generate_network_summary(self, network_context: Dict) -> Dict[str, Any]:
        """Generate comprehensive network summary"""
        stats = network_context['stats']
        device_types = network_context['device_types']
        
        response = "📊 Network Summary Report\n"
        response += "=" * 40 + "\n\n"
        
        response += f"🏢 Infrastructure Overview:\n"
        response += f"   Total Devices: {stats['total_devices']}\n"
        response += f"   Total Interfaces: {stats['total_interfaces']}\n"
        response += f"   Total VLANs: {stats['total_vlans']}\n"
        response += f"   Total VRFs: {stats['total_vrfs']}\n\n"
        
        response += f"🖥️ Device Breakdown:\n"
        for device_type, hostnames in device_types.items():
            response += f"   {device_type}: {len(hostnames)} devices\n"
        
        response += f"\n🌐 Network Segments:\n"
        response += f"   Configured Subnets: {len(network_context['subnets'])}\n"
        
        # Top 5 VLANs by device count
        vlans = network_context['vlans']
        if vlans:
            sorted_vlans = sorted(vlans.items(), key=lambda x: len(x[1]['devices']), reverse=True)[:5]
            response += f"\n🔗 Most Widespread VLANs:\n"
            for vlan_id, vlan_info in sorted_vlans:
                device_count = len(vlan_info['devices'])
                vlan_name = vlan_info['name'] or 'Unnamed'
                response += f"   VLAN {vlan_id} ({vlan_name}): {device_count} devices\n"
        
        return {
            'response': response,
            'config_changes': [],
            'affected_devices': list(network_context['devices'].keys()),
            'confidence': 0.9
        }
    
    def _analyze_vlan_location(self, vlan_id: str, network_context: Dict) -> Dict[str, Any]:
        """Analyze which devices have a specific VLAN"""
        vlans = network_context['vlans']
        
        if not vlan_id:
            return {'response': 'VLAN ID is required', 'config_changes': [], 'affected_devices': [], 'confidence': 0.1}
        
        if vlan_id not in vlans:
            response = f"VLAN {vlan_id} not found in any device.\n\n"
            response += "Available VLANs:\n"
            for vid in sorted(vlans.keys(), key=lambda x: int(x) if x.isdigit() else 999):
                response += f"  VLAN {vid}: {vlans[vid]['name'] or 'Unnamed'}\n"
        else:
            vlan_info = vlans[vlan_id]
            devices_with_vlan = vlan_info['devices']
            
            response = f"VLAN {vlan_id} Location Analysis:\n\n"
            response += f"🏷️ VLAN Name: {vlan_info['name'] or 'Not set'}\n"
            response += f"📊 Status: {vlan_info['status'] or 'Unknown'}\n"
            response += f"🖥️ Present on {len(devices_with_vlan)} device(s):\n\n"
            
            for device_hostname in devices_with_vlan:
                device_info = network_context['devices'][device_hostname]
                response += f"  • {device_hostname} ({device_info['type']})\n"
                
                # Check which interfaces use this VLAN
                interfaces = network_context['interfaces'].get(device_hostname, {})
                vlan_interfaces = []
                
                for intf_name, intf_data in interfaces.items():
                    if intf_data.get('access_vlan') == vlan_id:
                        vlan_interfaces.append(f"{intf_name} (access)")
                    elif vlan_id in intf_data.get('trunk_vlans', []):
                        vlan_interfaces.append(f"{intf_name} (trunk)")
                
                if vlan_interfaces:
                    response += f"    Interfaces: {', '.join(vlan_interfaces)}\n"
                
                response += "\n"
        
        return {
            'response': response,
            'config_changes': [],
            'affected_devices': vlans.get(vlan_id, {}).get('devices', []),
            'confidence': 0.9
        }
    
    def _generate_fallback_response(self, query: str, network_context: Dict) -> Dict[str, Any]:
        """Generate a helpful fallback response when query intent is unclear"""
        
        stats = network_context['stats']
        
        response = f"I understand you're asking about the network, but I need more specific information.\n\n"
        response += f"Your network currently has:\n"
        response += f"• {stats['total_devices']} devices\n"
        response += f"• {stats['total_interfaces']} interfaces\n"
        response += f"• {stats['total_vlans']} VLANs\n"
        response += f"• {stats['total_vrfs']} VRFs\n\n"
        
        response += "You can ask me questions like:\n"
        response += "• 'Show me all VLANs'\n"
        response += "• 'Create VLAN 100 name USERS'\n"
        response += "• 'Which devices have VLAN 50?'\n"
        response += "• 'I need VLAN 200 to communicate with subnet 192.168.1.0/24'\n"
        response += "• 'List all switch devices'\n"
        response += "• 'Troubleshoot connectivity to 10.1.1.1'\n"
        response += "• 'Summarize the network'\n"
        
        return {
            'response': response,
            'config_changes': [],
            'affected_devices': [],
            'confidence': 0.4
        }


# Qwen3:32B Ollama Processor
class Qwen3OllamaProcessor:
    """Ollama processor optimized for Qwen3:32B model"""
    
    def __init__(self, model_name: str = "qwen3:32b"):
        self.model_name = model_name
        self.available = self._check_ollama_available()
        self.model_info = self._get_model_info()
        
        if self.available:
            logger.info(f"🦙 Ollama available with Qwen3:32B model: {self.model_name}")
        else:
            logger.warning("🦙 Ollama not available - using rule-based only")
    
    def _check_ollama_available(self) -> bool:
        """Check if Ollama is available and Qwen3 model is loaded"""
        try:
            import requests
            
            # Check if Ollama is running
            response = requests.get(_ollama_endpoint("/api/tags"), timeout=3)
            if response.status_code != 200:
                return False
            
            # Check if our model is available
            models = response.json().get('models', [])
            model_names = [model.get('name', '') for model in models]
            
            # Check for Qwen3 variants
            qwen3_variants = ['qwen3:32b', 'qwen3:32b-instruct', 'qwen3:32b-chat']
            for variant in qwen3_variants:
                if variant in model_names:
                    self.model_name = variant
                    logger.info(f"🎯 Found Qwen3 model: {variant}")
                    return True
            
            # Fallback check for any qwen3 model
            for model_name in model_names:
                if 'qwen3' in model_name.lower():
                    self.model_name = model_name
                    logger.info(f"🎯 Using Qwen3 model: {model_name}")
                    return True
            
            # Last resort - any qwen model
            for model_name in model_names:
                if 'qwen' in model_name.lower():
                    self.model_name = model_name
                    logger.info(f"🎯 Using Qwen model: {model_name}")
                    return True
            
            logger.warning(f"❌ Qwen3 model not found. Available models: {model_names}")
            return False
            
        except Exception as e:
            logger.warning(f"❌ Ollama check failed: {e}")
            return False
    
    def _get_model_info(self) -> Dict:
        """Get information about the loaded model"""
        if not self.available:
            return {}
        
        try:
            import requests
            response = requests.post(
                _ollama_endpoint("/api/show"),
                json={"name": self.model_name},
                timeout=5
            )
            
            if response.status_code == 200:
                return response.json()
        except Exception as e:
            logger.warning(f"Could not get model info: {e}")
        
        return {}
    
    async def process_with_ollama(self, query: str, network_context: Dict) -> Dict[str, Any]:
        """Process query using Qwen3:32B model"""
        if not self.available:
            raise Exception("Ollama with Qwen3 not available")
        
        try:
            import requests
            
            # Build optimized prompt for Qwen3
            prompt = _build_qwen3_prompt(self, query, network_context)
            
            # Qwen3-optimized parameters
            payload = {
                "model": self.model_name,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": 0.05,  # Very low for technical accuracy with Qwen3
                    "top_p": 0.85,
                    "top_k": 30,
                    "repeat_penalty": 1.05,
                    "num_predict": 1024,  # Allow longer responses for Qwen3
                    "stop": ["</think>", "<|im_end|>", "<|endoftext|>", "Human:", "User:", "Q:", "Question:"],
                    "seed": 42  # Consistent results
                }
            }
            
            logger.info(f"🤖 Processing with Qwen3:32B - Query: {query[:50]}...")
            
            response = requests.post(
                _ollama_endpoint("/api/generate"),
                json=payload,
                timeout=90  # Longer timeout for 32B model
            )
            
            if response.status_code == 200:
                payloads: List[Dict[str, Any]] = []

                try:
                    payloads.append(response.json())
                except ValueError:
                    raw_text = response.text.strip()
                    for line in raw_text.splitlines():
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            payloads.append(json.loads(line))
                        except json.JSONDecodeError:
                            logger.warning("Unable to decode Ollama response chunk: %s", line[:120])

                if not payloads:
                    raise Exception("Empty response from Ollama generate API")

                ai_response = "".join(chunk.get("response", "") for chunk in payloads)
                ai_response = re.sub(r"<think>.*?</think>", "", ai_response, flags=re.DOTALL).strip()

                if not ai_response:
                    raise Exception("Ollama returned no response text")

                # Parse structured response if available
                parsed_response = _parse_qwen3_response(self, ai_response)
                
                logger.info(f"✅ Qwen3 response generated ({len(ai_response)} chars)")
                
                return {
                    'response': parsed_response.get('response', ai_response),
                    'config_changes': parsed_response.get('config_changes', []),
                    'affected_devices': parsed_response.get('affected_devices', []),
                    'confidence': 0.90,  # Very high confidence for Qwen3:32B
                    'model_used': self.model_name
                }
            else:
                raise Exception(f"Ollama API error: {response.status_code} - {response.text}")
                
        except Exception as e:
            logger.error(f"❌ Qwen3 processing failed: {str(e)}")
            raise
