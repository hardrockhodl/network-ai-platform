#!/usr/bin/env python3
"""
AI Query Processor
Handles natural language queries about network configurations
"""

import os
import json
import logging
import asyncio
from typing import Dict, List, Any, Optional
from datetime import datetime
import re

# AI libraries
try:
    import openai
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False
    logging.warning("OpenAI library not available")

# Network analysis
import networkx as nx
from database.models import Device

logger = logging.getLogger(__name__)

class NetworkQueryProcessor:
    """Process natural language queries about network infrastructure"""
    
    def __init__(self):
        self.openai_client = None
        self.network_graph = nx.Graph()
        self.setup_ai_client()
        
    def setup_ai_client(self):
        """Initialize AI client (OpenAI)"""
        if OPENAI_AVAILABLE:
            api_key = os.getenv('OPENAI_API_KEY')
            if api_key:
                self.openai_client = openai.OpenAI(api_key=api_key)
                logger.info("OpenAI client initialized")
            else:
                logger.warning("OPENAI_API_KEY not found in environment variables")
        else:
            logger.warning("OpenAI not available - using fallback query processing")
    
    async def process_query(self, query: str, devices: List[Device], context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Process a natural language query about the network"""
        try:
            # Clean and validate query
            query = query.strip()
            if not query:
                raise ValueError("Empty query")
            
            # Extract network context
            network_context = self._build_network_context(devices)
            
            # Classify query type
            query_type = self._classify_query(query)
            
            # Route to appropriate processor
            if query_type == "config_generation":
                return await self._process_config_generation(query, network_context, context)
            elif query_type == "network_analysis":
                return await self._process_network_analysis(query, network_context, context)
            elif query_type == "troubleshooting":
                return await self._process_troubleshooting(query, network_context, context)
            else:
                return await self._process_general_query(query, network_context, context)
                
        except Exception as e:
            logger.error(f"Error processing query: {str(e)}")
            return {
                'response': f"I encountered an error processing your query: {str(e)}",
                'config_changes': [],
                'affected_devices': [],
                'confidence': 0.0
            }
    
    def _build_network_context(self, devices: List[Device]) -> Dict[str, Any]:
        """Build network context from devices"""
        context = {
            'devices': {},
            'vlans': set(),
            'vrfs': set(),
            'interfaces': [],
            'subnets': set()
        }
        
        for device in devices:
            device_info = {
                'hostname': device.hostname,
                'type': device.device_type,
                'interfaces': {},
                'vlans': {},
                'vrfs': {}
            }
            
            # Extract parsed data
            if device.parsed_data:
                parsed = device.parsed_data
                
                # Interfaces
                for intf_name, intf_data in parsed.get('interfaces', {}).items():
                    device_info['interfaces'][intf_name] = intf_data
                    context['interfaces'].append({
                        'device': device.hostname,
                        'name': intf_name,
                        'ip': intf_data.get('ip_address', ''),
                        'vlan': intf_data.get('access_vlan', ''),
                        'description': intf_data.get('description', '')
                    })
                    
                    # Collect subnets
                    if intf_data.get('ip_address') and intf_data.get('subnet_mask'):
                        subnet = f"{intf_data['ip_address']}/{intf_data['subnet_mask']}"
                        context['subnets'].add(subnet)
                
                # VLANs
                for vlan_id, vlan_data in parsed.get('vlans', {}).items():
                    device_info['vlans'][vlan_id] = vlan_data
                    context['vlans'].add(vlan_id)
                
                # VRFs
                for vrf_name, vrf_data in parsed.get('vrfs', {}).items():
                    device_info['vrfs'][vrf_name] = vrf_data
                    context['vrfs'].add(vrf_name)
            
            context['devices'][device.hostname] = device_info
        
        # Convert sets to lists for JSON serialization
        context['vlans'] = list(context['vlans'])
        context['vrfs'] = list(context['vrfs'])
        context['subnets'] = list(context['subnets'])
        
        return context
    
    def _classify_query(self, query: str) -> str:
        """Classify the type of query"""
        query_lower = query.lower()
        
        # Config generation patterns
        config_patterns = [
            r'create.*vlan', r'add.*vlan', r'configure.*vlan',
            r'create.*interface', r'configure.*interface',
            r'add.*route', r'create.*route',
            r'generate.*config', r'what.*config.*need',
            r'how.*configure', r'what.*command'
        ]
        
        # Network analysis patterns
        analysis_patterns = [
            r'show.*', r'list.*', r'find.*',
            r'what.*vlan', r'which.*device', r'where.*',
            r'how many.*', r'count.*',
            r'summarize.*', r'overview.*'
        ]
        
        # Troubleshooting patterns
        troubleshoot_patterns = [
            r'troubleshoot.*', r'debug.*', r'problem.*',
            r'not working', r'can\'t reach', r'cannot.*',
            r'connectivity.*', r'ping.*fail',
            r'why.*', r'issue.*', r'error.*'
        ]
        
        for pattern in config_patterns:
            if re.search(pattern, query_lower):
                return "config_generation"
        
        for pattern in troubleshoot_patterns:
            if re.search(pattern, query_lower):
                return "troubleshooting"
        
        for pattern in analysis_patterns:
            if re.search(pattern, query_lower):
                return "network_analysis"
        
        return "general"
    
    async def _process_config_generation(self, query: str, network_context: Dict, context: Dict = None) -> Dict[str, Any]:
        """Process configuration generation queries"""
        
        if self.openai_client:
            return await self._process_with_openai(query, network_context, "config_generation")
        else:
            return self._process_config_fallback(query, network_context)
    
    async def _process_network_analysis(self, query: str, network_context: Dict, context: Dict = None) -> Dict[str, Any]:
        """Process network analysis queries"""
        
        if self.openai_client:
            return await self._process_with_openai(query, network_context, "network_analysis")
        else:
            return self._process_analysis_fallback(query, network_context)
    
    async def _process_troubleshooting(self, query: str, network_context: Dict, context: Dict = None) -> Dict[str, Any]:
        """Process troubleshooting queries"""
        
        if self.openai_client:
            return await self._process_with_openai(query, network_context, "troubleshooting")
        else:
            return self._process_troubleshooting_fallback(query, network_context)
    
    async def _process_general_query(self, query: str, network_context: Dict, context: Dict = None) -> Dict[str, Any]:
        """Process general queries"""
        
        if self.openai_client:
            return await self._process_with_openai(query, network_context, "general")
        else:
            return self._process_general_fallback(query, network_context)
    
    async def _process_with_openai(self, query: str, network_context: Dict, query_type: str) -> Dict[str, Any]:
        """Process query using OpenAI"""
        try:
            # Build system prompt based on query type
            system_prompt = self._build_system_prompt(query_type)
            
            # Build network context summary
            context_summary = self._summarize_network_context(network_context)
            
            # Create the prompt
            user_prompt = f"""
Network Context:
{context_summary}

User Query: {query}

Please provide a comprehensive response including:
1. Analysis of the request
2. Specific configuration commands if applicable
3. List of affected devices
4. Risk assessment and warnings if applicable
"""
            
            # Make API call
            response = await self._call_openai_api(system_prompt, user_prompt)
            
            # Parse response
            return self._parse_ai_response(response, network_context)
            
        except Exception as e:
            logger.error(f"OpenAI API error: {str(e)}")
            return {
                'response': f"AI processing failed: {str(e)}. Using fallback analysis.",
                'config_changes': [],
                'affected_devices': [],
                'confidence': 0.3
            }
    
    def _build_system_prompt(self, query_type: str) -> str:
        """Build system prompt based on query type"""
        base_prompt = """You are an expert Cisco network engineer with 20+ years of experience. 
You help analyze network configurations and generate accurate Cisco IOS commands.

Key guidelines:
- Always provide specific, accurate Cisco IOS commands
- Consider best practices and security implications
- Identify all devices that need changes
- Provide clear explanations for your recommendations
- Use proper Cisco command syntax
- Consider VLAN, routing, and security implications"""
        
        if query_type == "config_generation":
            return base_prompt + """
Focus on:
- Generating exact configuration commands
- Identifying all affected devices and interfaces
- Providing step-by-step configuration process
- Including verification commands
- Considering rollback procedures"""
        
        elif query_type == "network_analysis":
            return base_prompt + """
Focus on:
- Analyzing current network state
- Identifying relationships between components
- Providing clear summaries and insights
- Highlighting potential issues or improvements"""
        
        elif query_type == "troubleshooting":
            return base_prompt + """
Focus on:
- Identifying potential causes
- Providing diagnostic commands
- Suggesting step-by-step troubleshooting approach
- Considering common misconfigurations"""
        
        return base_prompt
    
    def _summarize_network_context(self, network_context: Dict) -> str:
        """Create a concise summary of network context"""
        summary = []
        
        devices = network_context.get('devices', {})
        summary.append(f"Network has {len(devices)} devices:")
        
        for hostname, device_info in devices.items():
            summary.append(f"- {hostname} ({device_info['type']})")
            summary.append(f"  Interfaces: {len(device_info['interfaces'])}")
            summary.append(f"  VLANs: {len(device_info['vlans'])}")
            summary.append(f"  VRFs: {len(device_info['vrfs'])}")
        
        summary.append(f"Total unique VLANs: {len(network_context.get('vlans', []))}")
        summary.append(f"Total unique VRFs: {len(network_context.get('vrfs', []))}")
        summary.append(f"Subnets in use: {len(network_context.get('subnets', []))}")
        
        return '\n'.join(summary)
    
    async def _call_openai_api(self, system_prompt: str, user_prompt: str) -> str:
        """Make API call to OpenAI"""
        try:
            response = await asyncio.to_thread(
                self.openai_client.chat.completions.create,
                model="gpt-4",  # or "gpt-3.5-turbo" for faster/cheaper responses
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                max_tokens=2000,
                temperature=0.1  # Lower temperature for more consistent technical responses
            )
            
            return response.choices[0].message.content
            
        except Exception as e:
            logger.error(f"OpenAI API call failed: {str(e)}")
            raise
    
    def _parse_ai_response(self, ai_response: str, network_context: Dict) -> Dict[str, Any]:
        """Parse AI response and extract structured data"""
        
        # Try to extract configuration commands
        config_changes = []
        config_pattern = r'```(?:cisco|ios)?\n?(.*?)```'
        config_matches = re.findall(config_pattern, ai_response, re.DOTALL | re.IGNORECASE)
        
        for match in config_matches:
            commands = [cmd.strip() for cmd in match.strip().split('\n') if cmd.strip()]
            if commands:
                config_changes.append({
                    'device_hostname': 'TBD',  # Will be determined by context
                    'commands': commands,
                    'description': 'Configuration from AI analysis',
                    'risk_level': 'medium'
                })
        
        # Extract affected devices mentioned in response
        affected_devices = []
        for hostname in network_context.get('devices', {}):
            if hostname.lower() in ai_response.lower():
                affected_devices.append(hostname)
        
        # Calculate confidence based on response quality
        confidence = 0.8 if config_changes else 0.6
        
        return {
            'response': ai_response,
            'config_changes': config_changes,
            'affected_devices': affected_devices,
            'confidence': confidence
        }
    
    # Fallback methods (when AI is not available)
    def _process_config_fallback(self, query: str, network_context: Dict) -> Dict[str, Any]:
        """Fallback config generation without AI"""
        
        response = "I can help with configuration, but AI processing is not available. "
        config_changes = []
        affected_devices = []
        
        # Simple VLAN creation pattern matching
        vlan_match = re.search(r'create.*vlan.*?(\d+)', query.lower())
        if vlan_match:
            vlan_id = vlan_match.group(1)
            response += f"To create VLAN {vlan_id}, you would typically use these commands:\n"
            
            config_changes.append({
                'device_hostname': 'All_Switches',
                'commands': [
                    f'vlan {vlan_id}',
                    f' name VLAN_{vlan_id}',
                    'exit'
                ],
                'description': f'Create VLAN {vlan_id}',
                'risk_level': 'low'
            })
        
        # Simple interface pattern matching
        interface_match = re.search(r'configure.*interface.*?(\S+)', query.lower())
        if interface_match:
            interface = interface_match.group(1)
            response += f"For interface {interface} configuration, basic commands would be needed."
        
        return {
            'response': response,
            'config_changes': config_changes,
            'affected_devices': affected_devices,
            'confidence': 0.4
        }
    
    def _process_analysis_fallback(self, query: str, network_context: Dict) -> Dict[str, Any]:
        """Fallback network analysis without AI"""
        
        devices = network_context.get('devices', {})
        
        if 'vlan' in query.lower():
            vlans = network_context.get('vlans', [])
            response = f"Network has {len(vlans)} unique VLANs: {', '.join(map(str, vlans))}"
        
        elif 'interface' in query.lower():
            total_interfaces = sum(len(device['interfaces']) for device in devices.values())
            response = f"Network has {total_interfaces} total interfaces across {len(devices)} devices"
        
        elif 'device' in query.lower():
            device_types = {}
            for device in devices.values():
                dtype = device['type']
                device_types[dtype] = device_types.get(dtype, 0) + 1
            
            response = f"Network devices: {dict(device_types)}"
        
        else:
            response = f"Network summary: {len(devices)} devices, {len(network_context.get('vlans', []))} VLANs, {len(network_context.get('vrfs', []))} VRFs"
        
        return {
            'response': response,
            'config_changes': [],
            'affected_devices': list(devices.keys()),
            'confidence': 0.6
        }
    
    def _process_troubleshooting_fallback(self, query: str, network_context: Dict) -> Dict[str, Any]:
        """Fallback troubleshooting without AI"""
        
        response = "For troubleshooting, I recommend these general steps:\n"
        response += "1. Check interface status: show ip interface brief\n"
        response += "2. Verify routing: show ip route\n"
        response += "3. Check VLAN configuration: show vlan brief\n"
        response += "4. Test connectivity: ping <destination>\n"
        
        return {
            'response': response,
            'config_changes': [],
            'affected_devices': [],
            'confidence': 0.5
        }
    
    def _process_general_fallback(self, query: str, network_context: Dict) -> Dict[str, Any]:
        """Fallback for general queries"""
        
        devices_count = len(network_context.get('devices', {}))
        vlans_count = len(network_context.get('vlans', []))
        
        response = f"I understand you're asking about the network. "
        response += f"Your network currently has {devices_count} devices and {vlans_count} VLANs configured. "
        response += "For more detailed analysis, please enable AI processing with OpenAI API key."
        
        return {
            'response': response,
            'config_changes': [],
            'affected_devices': [],
            'confidence': 0.3
        }

# Utility functions for network analysis
def find_vlan_spanning_devices(network_context: Dict, vlan_id: str) -> List[str]:
    """Find all devices that have a specific VLAN configured"""
    devices_with_vlan = []
    
    for hostname, device_info in network_context.get('devices', {}).items():
        if vlan_id in device_info.get('vlans', {}):
            devices_with_vlan.append(hostname)
        
        # Also check interfaces with access VLAN
        for intf_data in device_info.get('interfaces', {}).values():
            if intf_data.get('access_vlan') == vlan_id:
                devices_with_vlan.append(hostname)
                break
    
    return list(set(devices_with_vlan))

def find_subnet_gateways(network_context: Dict, target_subnet: str) -> List[Dict]:
    """Find potential gateways for a subnet"""
    gateways = []
    
    for hostname, device_info in network_context.get('devices', {}).items():
        for intf_name, intf_data in device_info.get('interfaces', {}).items():
            if intf_data.get('ip_address'):
                # Simple subnet check (would need more sophisticated IP math in production)
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