"""
Service for handling diagram operations including relationship extraction and layout management.
"""
from typing import Dict, List, Optional, Any
from sqlalchemy.orm import Session
from ..models import DiagramHistory, DiagramLayout, Resource
import uuid
from datetime import datetime, timezone
import logging

logger = logging.getLogger(__name__)

class DiagramService:
    def __init__(self, db: Session, project_id: str, user_id: str):
        """Initialize diagram service with project ID and user ID"""
        self.db = db
        self.project_id = project_id
        self.user_id = user_id
        logger.info(f"Initialized DiagramService for project {project_id}")

    def extract_relationships(self) -> Dict:
        """
        Extract relationships between AWS resources and format them into
        a hierarchical structure suitable for AWS architecture visualization.
        """
        logger.info("Starting relationship extraction")
        try:
            # Get all resources for the project
            resources = self.get_project_resources()
            logger.debug(f"Found {len(resources)} total resources")
            
            # Debug all resource types
            resource_types = {r.type for r in resources}
            logger.info(f"Available resource types: {resource_types}")
            
            # Debug load balancers specifically
            load_balancers = [r for r in resources if r.type == 'load_balancer']
            logger.info(f"Found {len(load_balancers)} load balancers")
            for lb in load_balancers:
                logger.info(f"Load Balancer: {lb.name}")
                logger.info(f"Load Balancer details: {lb.details_json}")
            
            # Create resource lookup by ID
            resource_map = {str(r.id): r for r in resources}
            
            # Initialize VPCs as top-level containers
            vpcs = [r for r in resources if r.type == 'vpc']
            logger.debug(f"Found {len(vpcs)} VPCs")
            
            root = {
                "id": "root",
                "name": "AWS Resources",
                "type": "root",
                "children": []
            }

            # Process each VPC
            for vpc in vpcs:
                vpc_id = str(vpc.id)
                vpc_details = vpc.details_json
                logger.debug(f"Processing VPC {vpc.name} ({vpc_id}) with details: {vpc_details}")
                
                vpc_node = {
                    "id": vpc_id,
                    "name": vpc.name,
                    "type": "vpc",
                    "details": vpc_details,
                    "children": []
                }

                # Add Internet Gateway if found in route tables
                igw_routes = []
                nat_gateways = {}  # Map of subnet_id to NAT Gateway info

                if vpc_details:
                    # First get NAT Gateway information
                    if 'nat_gateways' in vpc_details:
                        for nat in vpc_details['nat_gateways']:
                            if nat.get('subnet_id') and nat.get('state') == 'available':
                                nat_gateways[nat['subnet_id']] = nat
                                logger.debug(f"Found NAT Gateway {nat['id']} in subnet {nat['subnet_id']}")

                    # Then get IGW information
                    if 'subnets' in vpc_details:
                        for subnet in vpc_details['subnets']:
                            for route in subnet.get('routes', []):
                                if route['target'].get('type') == 'gateway' and route['target'].get('id', '').startswith('igw-'):
                                    igw_routes.append(route)
                
                if igw_routes:
                    igw_id = igw_routes[0]['target']['id']
                    igw_node = {
                        "id": igw_id,
                        "name": "Internet Gateway",
                        "type": "internet_gateway",
                        "details": {},
                        "children": []
                    }
                    vpc_node["children"].append(igw_node)
                    logger.debug(f"Added Internet Gateway {igw_id} to VPC {vpc.name}")

                # Create subnet nodes from VPC details
                if vpc_details and 'subnets' in vpc_details:
                    for subnet_info in vpc_details['subnets']:
                        subnet_node = {
                            "id": subnet_info['id'],
                            "name": f"{subnet_info['availability_zone']} - {subnet_info['cidr_block']}",
                            "type": "subnet",
                            "details": {
                                "cidr_block": subnet_info['cidr_block'],
                                "availability_zone": subnet_info['availability_zone'],
                                "state": subnet_info['state'],
                                "is_public": any(
                                    route['target'].get('type') == 'gateway' and 
                                    route['target'].get('id', '').startswith('igw-')
                                    for route in subnet_info.get('routes', [])
                                ),
                                "vpc_id": vpc_id
                            },
                            "children": []
                        }

                        # If this subnet has a NAT Gateway, add it as a child
                        if subnet_info['id'] in nat_gateways:
                            nat = nat_gateways[subnet_info['id']]
                            nat_node = {
                                "id": nat['id'],
                                "name": "NAT Gateway",
                                "type": "nat_gateway",
                                "details": {
                                    "subnet_id": subnet_info['id'],
                                    "elastic_ip_id": nat.get('elastic_ip_id'),
                                    "public_ip": nat.get('public_ip'),
                                    "private_ip": nat.get('private_ip'),
                                    "state": nat.get('state')
                                },
                                "children": []
                            }
                            subnet_node["children"].append(nat_node)
                            logger.debug(f"Added NAT Gateway {nat['id']} to subnet {subnet_info['id']}")

                        # Find resources in this subnet
                        for resource in resources:
                            if resource.type == 'ec2' and resource.details_json:
                                # Use ENIs to determine subnet placement
                                network_interfaces = resource.details_json.get('network_interfaces', [])
                                primary_eni = next((eni for eni in network_interfaces 
                                                  if eni.get('subnet_id') == subnet_info['id']), None)
                                
                                if primary_eni or resource.details_json.get('subnet_id') == subnet_info['id']:
                                    try:
                                        # Get security group details
                                        sg_details = []
                                        sg_ids = resource.details_json.get('security_groups', [])
                                        for sg_id in sg_ids:
                                            sg = next((r for r in resources 
                                                     if r.type == 'security_group' and 
                                                     r.resource_id == sg_id), None)
                                            if sg:
                                                sg_details.append({
                                                    'id': sg.resource_id,
                                                    'name': sg.name,
                                                    'description': sg.details_json.get('description'),
                                                    'inbound_rules': sg.details_json.get('inbound_rules', []),
                                                    'outbound_rules': sg.details_json.get('outbound_rules', [])
                                                })

                                        instance_node = {
                                            "id": str(resource.id),
                                            "name": resource.name,
                                            "type": "ec2",
                                            "details": {
                                                **resource.details_json,
                                                "security_groups": sg_details,
                                                "network_interface": primary_eni or {
                                                    'subnet_id': resource.details_json.get('subnet_id'),
                                                    'private_ip': resource.details_json.get('private_ip'),
                                                    'public_ip': resource.details_json.get('public_ip')
                                                }
                                            },
                                            "children": []
                                        }
                                        subnet_node["children"].append(instance_node)
                                        logger.debug(f"Added EC2 instance {resource.name} to subnet {subnet_info['id']}")
                                    except Exception as e:
                                        logger.error(f"Error adding EC2 instance to subnet: {str(e)}", exc_info=True)

                        vpc_node["children"].append(subnet_node)
                        logger.debug(f"Added subnet {subnet_info['id']} to VPC {vpc.name}")

                logger.info("Starting to process load balancers")
                for resource in resources:
                    if resource.type == 'load_balancer' and resource.details_json:
                        lb_details = resource.details_json
                        lb_type = lb_details.get('type', 'classic').lower()
                        logger.info(f"Processing load balancer: {resource.name}")
                        logger.info(f"Load balancer type: {lb_type}")
                        logger.info(f"Load balancer scheme: {lb_details.get('scheme')}")
                        logger.info(f"Load balancer AZs: {lb_details.get('availability_zones')}")
                        
                        # Get security group details for load balancer
                        sg_details = []
                        for sg in lb_details.get('security_groups', []):
                            sg_details.append({
                                'id': sg['id'],
                                'name': sg.get('name', ''),
                                'description': sg.get('description', ''),
                                'inbound_rules': sg.get('inbound_rules', []),
                                'outbound_rules': sg.get('outbound_rules', [])
                            })
                        logger.info(f"Found {len(sg_details)} security groups for load balancer")

                        # Process listeners
                        listeners = []
                        for listener in lb_details.get('listeners', []):
                            listener_info = {
                                'port': listener.get('port'),
                                'protocol': listener.get('protocol'),
                                'ssl_policy': listener.get('ssl_policy'),
                                'certificates': listener.get('certificates', [])
                            }
                            listeners.append(listener_info)
                        logger.info(f"Found {len(listeners)} listeners for load balancer")

                        lb_node = {
                            "id": str(resource.id),
                            "name": resource.name,
                            "type": f"{lb_type}_load_balancer",  # application, network, or classic
                            "details": {
                                'status': lb_details.get('status'),
                                'dns_name': lb_details.get('dns_name'),
                                'type': lb_type,
                                'scheme': lb_details.get('scheme'),
                                'vpc_id': lb_details.get('vpc_id'),
                                'availability_zones': lb_details.get('availability_zones', []),
                                'security_groups': sg_details,
                                'listeners': listeners
                            },
                            "children": []
                        }
                        logger.info(f"Created load balancer node with type {lb_node['type']}")

                        # Place load balancer based on type and scheme
                        if lb_type == 'classic':
                            # Classic ELB goes at VPC level
                            vpc_node["children"].append(lb_node)
                            logger.info(f"Added Classic ELB {resource.name} to VPC {vpc.name}")
                        else:
                            # ALB/NLB placement based on scheme
                            if lb_details.get('scheme') == 'internet-facing':
                                # Internet-facing ALB/NLB goes at VPC level
                                vpc_node["children"].append(lb_node)
                                logger.info(f"Added internet-facing {lb_type} {resource.name} to VPC {vpc.name}")
                            else:
                                # Internal ALB/NLB goes in subnet
                                placed = False
                                for az in lb_details.get('availability_zones', []):
                                    subnet_id = az.get('SubnetId')  
                                    if subnet_id:
                                        subnet_node = next((s for s in vpc_node["children"] 
                                                          if s["type"] == "subnet" and 
                                                          s["details"].get("id") == subnet_id), None)
                                        if subnet_node:
                                            subnet_node["children"].append(lb_node)
                                            logger.info(f"Added internal {lb_type} {resource.name} to subnet {subnet_id}")
                                            placed = True
                                            break  # Only add to first subnet to avoid duplication
                                if not placed:
                                    logger.warning(f"Could not place internal {lb_type} {resource.name} in any subnet, adding to VPC level")
                                    vpc_node["children"].append(lb_node)

                root["children"].append(vpc_node)
                logger.debug(f"Added VPC {vpc.name} with {len(vpc_node['children'])} children to root")

            logger.info("Successfully extracted relationships")
            logger.debug(f"Final data structure: {root}")
            return root
        except Exception as e:
            logger.error(f"Error extracting relationships: {str(e)}", exc_info=True)
            raise

    def save_diagram(self, diagram_metadata: Optional[Dict] = None) -> DiagramHistory:
        """
        Save the current state of the diagram as a new version.
        """
        logger.info("Saving diagram")
        try:
            relationships = self.extract_relationships()
            
            # Create new diagram version
            diagram = DiagramHistory(
                project_id=self.project_id,
                user_id=self.user_id,
                version=self._generate_version(),
                diagram_metadata=diagram_metadata,
            )
            self.db.add(diagram)
            self.db.commit()

            # Create default layout
            self.save_layout(str(diagram.id), relationships, True)
            
            logger.info("Diagram saved successfully")
            return diagram
        except Exception as e:
            logger.error(f"Error saving diagram: {str(e)}", exc_info=True)
            raise

    def save_layout(self, diagram_id: str, layout_data: Dict, 
                   is_default: bool = False) -> DiagramLayout:
        """
        Save layout preferences for a diagram.
        """
        logger.info(f"Saving layout for diagram {diagram_id}")
        try:
            # If this is set as default, unset any existing default layouts
            if is_default:
                self.db.query(DiagramLayout).filter(
                    DiagramLayout.diagram_id == diagram_id,
                    DiagramLayout.is_default == True
                ).update({"is_default": False})
                self.db.commit()
            
            layout = DiagramLayout(
                diagram_id=diagram_id,
                layout_data=layout_data,
                is_default=is_default
            )
            self.db.add(layout)
            self.db.commit()
            logger.info("Layout saved successfully")
            return layout
        except Exception as e:
            logger.error(f"Error saving layout: {str(e)}", exc_info=True)
            raise

    def get_layout(self, diagram_id: str) -> Optional[DiagramLayout]:
        """
        Get the layout preferences for a diagram.
        """
        logger.info(f"Getting layout for diagram {diagram_id}")
        try:
            layout = self.db.query(DiagramLayout).filter(
                DiagramLayout.diagram_id == diagram_id,
                DiagramLayout.is_default == True
            ).first()
            return layout
        except Exception as e:
            logger.error(f"Error getting layout: {str(e)}", exc_info=True)
            raise

    def get_project_resources(self) -> List[Resource]:
        """Get all resources for the current project."""
        try:
            resources = self.db.query(Resource).filter(
                Resource.project_id == self.project_id
            ).all()
            
            logger.info(f"Retrieved {len(resources)} resources for project {self.project_id}")
            for resource in resources:
                logger.debug(f"Resource: {resource.name} ({resource.type})")
                logger.debug(f"Details: {resource.details_json}")
                
                # Log specific relationships we care about
                if resource.type == 'vpc':
                    logger.debug(f"VPC {resource.name} details: {resource.details_json}")
                elif resource.type == 'subnet':
                    vpc_id = resource.details_json.get('vpc_id') if resource.details_json else None
                    logger.debug(f"Subnet {resource.name} belongs to VPC: {vpc_id}")
                elif resource.type == 'ec2':
                    subnet_id = resource.details_json.get('subnet_id') if resource.details_json else None
                    logger.debug(f"EC2 {resource.name} belongs to subnet: {subnet_id}")
                
            return resources
        except Exception as e:
            logger.error(f"Error retrieving resources: {str(e)}", exc_info=True)
            raise

    def get_diagram_history(self, limit: int = 10) -> List[DiagramHistory]:
        """Get diagram version history for a project."""
        return self.db.query(DiagramHistory).filter(
            DiagramHistory.project_id == self.project_id
        ).order_by(DiagramHistory.created_at.desc()).limit(limit).all()

    def delete_diagram(self, diagram_id: str) -> None:
        """Delete a specific diagram and its associated layouts."""
        logger.info(f"Deleting diagram {diagram_id}")
        try:
            # First delete associated layouts
            self.db.query(DiagramLayout).filter(
                DiagramLayout.diagram_id == diagram_id
            ).delete()

            # Then delete the diagram
            result = self.db.query(DiagramHistory).filter(
                DiagramHistory.id == diagram_id,
                DiagramHistory.project_id == self.project_id  # Ensure it belongs to the project
            ).delete()

            if result == 0:
                raise Exception("Diagram not found")

            self.db.commit()
            logger.info("Diagram deleted successfully")
        except Exception as e:
            self.db.rollback()
            logger.error(f"Error deleting diagram: {str(e)}", exc_info=True)
            raise

    def _generate_version(self) -> str:
        """Generate a new version string."""
        return datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")

    def _is_subnet_of(self, subnet_cidr: str, vpc_cidr: str) -> bool:
        """Check if a subnet CIDR is within a VPC CIDR."""
        try:
            from ipaddress import ip_network
            subnet_net = ip_network(subnet_cidr)
            vpc_net = ip_network(vpc_cidr)
            return subnet_net.subnet_of(vpc_net)
        except ValueError:
            return False
