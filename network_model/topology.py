#!/usr/bin/env python3
"""
Network Topology Model
Manages network topology discovery and analysis
"""

import logging
from typing import Dict, List, Any, Optional, Set, Tuple
import networkx as nx
from collections import defaultdict
import json

logger = logging.getLogger(__name__)

class NetworkTopology:
    """
    Network topology management and analysis
    Builds and maintains a graph representation of the network
    """
    
    def __init__(self):
        self.graph = nx.Graph()  # NetworkX graph for topology
        self.devices = {}  # device_hostname -> device_data
        self.device_parsers = {}  # device_hostname -> parser_instance
        self.vlans = defaultdict(set)  # vlan_id -> set of devices
        self.subnets = {}  # subnet -> gateway_info
        self.connections = defaultdict(list)  # device -> list of connected devices
        
        logger.info("Network topology initialized")
    
    async def add_device(self, parser_instance):
        """Add a device to the topology from a parser instance"""
        try:
            hostname = parser_instance.hostname
            device_type = getattr(parser_instance, 'device_type', 'Unknown')
            
            # Store device information
            self.devices[hostname] = {
                'hostname': hostname,
                'type': device_type,
                'interfaces': getattr(parser_instance, 'interfaces', {}),
                'vlans': getattr(parser_instance, 'vlans', {}),
                'vrfs': getattr(parser_instance, 'vrfs', {}),
                'routing_table': getattr(parser_instance, 'routing_table', {}),
                'parsed_data': parser_instance.get_summary() if hasattr(parser_instance, 'get_summary') else {}
            }
            
            # Store parser reference
            self.device_parsers[hostname] = parser_instance
            
            # Add device to graph
            self.graph.add_node(hostname, **{
                'type': device_type,
                'vlans': len(getattr(parser_instance, 'vlans', {})),
                'interfaces': len(getattr(parser_instance, 'interfaces', {}))
            })
            
            # Update VLAN mappings
            for vlan_id in getattr(parser_instance, 'vlans', {}):
                self.vlans[vlan_id].add(hostname)
            
            # Extract subnet information from interfaces
            self._extract_subnets_from_device(parser_instance)

            # Add CDP neighbor-based links
            for neighbor in getattr(parser_instance, 'cdp_neighbors', []):
                remote_device = neighbor.remote_device
                if not remote_device:
                    continue

                if not self.graph.has_node(remote_device):
                    self.graph.add_node(remote_device, **{
                        'type': 'Unknown',
                        'vlans': 0,
                        'interfaces': 0
                    })

                edge_attributes = {
                    'connection_type': 'cdp',
                    'source_interface': neighbor.local_interface,
                    'target_interface': neighbor.remote_interface,
                    'remote_ip': neighbor.remote_ip
                }

                if self.graph.has_edge(hostname, remote_device):
                    self.graph[hostname][remote_device].update(edge_attributes)
                else:
                    self.graph.add_edge(hostname, remote_device, **edge_attributes)

                if remote_device not in self.connections[hostname]:
                    self.connections[hostname].append(remote_device)
                if hostname not in self.connections[remote_device]:
                    self.connections[remote_device].append(hostname)

            # Attempt to discover connections
            await self._discover_connections(hostname)
            
            logger.info(f"Added device {hostname} to topology")
            
        except Exception as e:
            logger.error(f"Error adding device to topology: {str(e)}")
            raise
    
    async def remove_device(self, hostname: str):
        """Remove a device from the topology"""
        try:
            if hostname in self.devices:
                # Remove from devices
                del self.devices[hostname]
                
                # Remove from parsers
                if hostname in self.device_parsers:
                    del self.device_parsers[hostname]
                
                # Remove from graph
                if self.graph.has_node(hostname):
                    self.graph.remove_node(hostname)
                
                # Clean up VLAN mappings
                for vlan_id, device_set in self.vlans.items():
                    device_set.discard(hostname)
                
                # Remove empty VLAN entries
                empty_vlans = [vlan_id for vlan_id, device_set in self.vlans.items() if not device_set]
                for vlan_id in empty_vlans:
                    del self.vlans[vlan_id]
                
                # Clean up subnet mappings
                subnets_to_remove = []
                for subnet, info in self.subnets.items():
                    if info.get('device') == hostname:
                        subnets_to_remove.append(subnet)
                
                for subnet in subnets_to_remove:
                    del self.subnets[subnet]
                
                logger.info(f"Removed device {hostname} from topology")
            
        except Exception as e:
            logger.error(f"Error removing device {hostname}: {str(e)}")
            raise
    
    def _extract_subnets_from_device(self, parser_instance):
        """Extract subnet information from device interfaces"""
        try:
            hostname = parser_instance.hostname
            interfaces = getattr(parser_instance, 'interfaces', {})
            
            for intf_name, intf_data in interfaces.items():
                ip_address = intf_data.get('ip_address')
                subnet_mask = intf_data.get('subnet_mask')
                
                if ip_address and subnet_mask:
                    try:
                        import ipaddress
                        network = ipaddress.IPv4Network(f"{ip_address}/{subnet_mask}", strict=False)
                        subnet_str = str(network)
                        
                        self.subnets[subnet_str] = {
                            'device': hostname,
                            'interface': intf_name,
                            'gateway': ip_address,
                            'mask': subnet_mask,
                            'network': str(network.network_address),
                            'broadcast': str(network.broadcast_address)
                        }
                        
                    except Exception as e:
                        logger.warning(f"Could not parse subnet for {hostname}:{intf_name}: {e}")
                        
        except Exception as e:
            logger.error(f"Error extracting subnets from {parser_instance.hostname}: {str(e)}")
    
    async def _discover_connections(self, hostname: str):
        """Discover connections between devices (basic implementation)"""
        try:
            device_data = self.devices[hostname]
            device_subnets = set()
            
            # Get subnets this device participates in
            for subnet, info in self.subnets.items():
                if info['device'] == hostname:
                    device_subnets.add(subnet)
            
            # Find other devices in same subnets (potential connections)
            for other_hostname, other_device in self.devices.items():
                if other_hostname == hostname:
                    continue
                
                # Check if devices share subnets
                for subnet, info in self.subnets.items():
                    if info['device'] == other_hostname and subnet in device_subnets:
                        # Devices are on the same subnet - potential connection
                        if not self.graph.has_edge(hostname, other_hostname):
                            self.graph.add_edge(hostname, other_hostname, 
                                              connection_type='subnet', 
                                              subnet=subnet)
                            logger.debug(f"Added connection: {hostname} <-> {other_hostname} via {subnet}")
            
            # Check for VLAN-based connections
            device_vlans = set(device_data.get('vlans', {}).keys())
            
            for other_hostname, other_device in self.devices.items():
                if other_hostname == hostname:
                    continue
                
                other_vlans = set(other_device.get('vlans', {}).keys())
                shared_vlans = device_vlans.intersection(other_vlans)
                
                if shared_vlans and not self.graph.has_edge(hostname, other_hostname):
                    self.graph.add_edge(hostname, other_hostname,
                                      connection_type='vlan',
                                      shared_vlans=list(shared_vlans))
                    logger.debug(f"Added VLAN connection: {hostname} <-> {other_hostname}")
            
        except Exception as e:
            logger.error(f"Error discovering connections for {hostname}: {str(e)}")
    
    async def get_topology_summary(self) -> Dict[str, Any]:
        """Get summary information about the network topology"""
        try:
            return {
                'total_devices': len(self.devices),
                'total_connections': self.graph.number_of_edges(),
                'device_types': self._get_device_type_counts(),
                'vlan_distribution': {str(k): len(v) for k, v in self.vlans.items()},
                'subnet_count': len(self.subnets),
                'connected_components': nx.number_connected_components(self.graph),
                'network_diameter': self._calculate_network_diameter()
            }
            
        except Exception as e:
            logger.error(f"Error generating topology summary: {str(e)}")
            return {}
    
    def _get_device_type_counts(self) -> Dict[str, int]:
        """Count devices by type"""
        type_counts = defaultdict(int)
        for device_data in self.devices.values():
            device_type = device_data.get('type', 'Unknown')
            type_counts[device_type] += 1
        return dict(type_counts)
    
    def _calculate_network_diameter(self) -> int:
        """Calculate the network diameter (longest shortest path)"""
        try:
            if self.graph.number_of_nodes() == 0:
                return 0
            
            if not nx.is_connected(self.graph):
                # For disconnected graphs, return diameter of largest component
                largest_cc = max(nx.connected_components(self.graph), key=len)
                subgraph = self.graph.subgraph(largest_cc)
                return nx.diameter(subgraph)
            else:
                return nx.diameter(self.graph)
                
        except Exception:
            return 0  # Return 0 if calculation fails
    
    async def generate_topology_data(self) -> Dict[str, Any]:
        """Generate topology data for visualization"""
        try:
            nodes = []
            edges = []
            
            # Generate nodes
            for hostname, device_data in self.devices.items():
                nodes.append({
                    'id': hostname,
                    'label': hostname,
                    'type': device_data.get('type', 'Unknown'),
                    'interfaces': len(device_data.get('interfaces', {})),
                    'vlans': len(device_data.get('vlans', {})),
                    'vrfs': len(device_data.get('vrfs', {}))
                })
            
            # Generate edges
            for edge in self.graph.edges(data=True):
                source, target, data = edge
                edges.append({
                    'source': source,
                    'target': target,
                    'type': data.get('connection_type', 'unknown'),
                    'label': data.get('subnet', '') or ', '.join(data.get('shared_vlans', []))
                })
            
            return {
                'nodes': nodes,
                'edges': edges,
                'summary': await self.get_topology_summary()
            }
            
        except Exception as e:
            logger.error(f"Error generating topology data: {str(e)}")
            return {'nodes': [], 'edges': [], 'summary': {}}
    
    async def find_paths(self, source: str, destination: str) -> List[List[str]]:
        """Find all paths between two devices"""
        try:
            if source not in self.devices or destination not in self.devices:
                logger.warning(f"Source ({source}) or destination ({destination}) not found in topology")
                return []
            
            if not self.graph.has_node(source) or not self.graph.has_node(destination):
                logger.warning(f"Source ({source}) or destination ({destination}) not in graph")
                return []
            
            # Find all simple paths (avoiding cycles)
            paths = list(nx.all_simple_paths(self.graph, source, destination, cutoff=10))
            
            # Sort by path length
            paths.sort(key=len)
            
            return paths
            
        except nx.NetworkXNoPath:
            logger.info(f"No path found between {source} and {destination}")
            return []
        except Exception as e:
            logger.error(f"Error finding paths between {source} and {destination}: {str(e)}")
            return []
    
    async def get_status(self) -> Dict[str, Any]:
        """Get current topology status for real-time updates"""
        try:
            return {
                'timestamp': str(self._get_current_timestamp()),
                'devices_online': len(self.devices),
                'total_vlans': len(self.vlans),
                'total_subnets': len(self.subnets),
                'graph_health': {
                    'nodes': self.graph.number_of_nodes(),
                    'edges': self.graph.number_of_edges(),
                    'connected': nx.is_connected(self.graph) if self.graph.number_of_nodes() > 0 else False
                }
            }
            
        except Exception as e:
            logger.error(f"Error getting topology status: {str(e)}")
            return {}
    
    def _get_current_timestamp(self):
        """Get current timestamp"""
        from datetime import datetime
        return datetime.now()
    
    def get_device_neighbors(self, hostname: str) -> List[str]:
        """Get neighboring devices for a given device"""
        try:
            if hostname not in self.graph:
                return []
            
            return list(self.graph.neighbors(hostname))
            
        except Exception as e:
            logger.error(f"Error getting neighbors for {hostname}: {str(e)}")
            return []
    
    def get_vlan_devices(self, vlan_id: str) -> Set[str]:
        """Get all devices that have a specific VLAN configured"""
        return self.vlans.get(vlan_id, set())
    
    def get_device_vlans(self, hostname: str) -> Set[str]:
        """Get all VLANs configured on a specific device"""
        device_data = self.devices.get(hostname, {})
        return set(device_data.get('vlans', {}).keys())
    
    def export_topology(self) -> Dict[str, Any]:
        """Export topology data for backup or analysis"""
        try:
            return {
                'devices': self.devices,
                'vlans': {k: list(v) for k, v in self.vlans.items()},
                'subnets': self.subnets,
                'graph_data': {
                    'nodes': list(self.graph.nodes(data=True)),
                    'edges': list(self.graph.edges(data=True))
                }
            }
            
        except Exception as e:
            logger.error(f"Error exporting topology: {str(e)}")
            return {}
