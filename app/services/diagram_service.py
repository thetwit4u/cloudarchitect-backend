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
                        
                        # Find resources in this subnet
                        if 'network_interfaces' in vpc_details:
                            for eni in vpc_details['network_interfaces']:
                                if eni and isinstance(eni, dict) and eni.get('subnet_id') == subnet_info['id']:
                                    attachment = eni.get('attachment', {})
                                    if attachment and isinstance(attachment, dict):
                                        instance_id = attachment.get('instance_id')
                                        if instance_id:
                                            instance = next(
                                                (r for r in resources if r.type == 'ec2' and 
                                                 r.details_json.get('instance_id') == instance_id), 
                                                None
                                            )
                                            if instance:
                                                instance_node = {
                                                    "id": str(instance.id),
                                                    "name": instance.name,
                                                    "type": "ec2",
                                                    "details": {
                                                        **instance.details_json,
                                                        "security_groups": [
                                                            {"id": sg_id, "name": next(
                                                                (r.name for r in resources 
                                                                 if r.type == 'security_group' and 
                                                                 r.details_json.get('group_id') == sg_id),
                                                                sg_id
                                                            )}
                                                            for sg_id in eni.get('security_groups', [])
                                                        ]
                                                    },
                                                    "children": []
                                                }
                                                subnet_node["children"].append(instance_node)
                                                logger.debug(f"Added EC2 instance {instance.name} to subnet {subnet_info['id']}")

                        vpc_node["children"].append(subnet_node)
                        logger.debug(f"Added subnet {subnet_info['id']} to VPC {vpc.name}")

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
