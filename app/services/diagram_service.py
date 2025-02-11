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
        a hierarchical structure suitable for D3.js visualization.
        """
        logger.info("Starting relationship extraction")
        try:
            # Get all resources for the project
            resources = self.get_project_resources()
            logger.debug(f"Processing {len(resources)} resources for relationships")

            # Create nodes dictionary with resource IDs as keys
            nodes = {}
            for resource in resources:
                logger.debug(f"Processing resource: {resource.type} - {resource.name}")
                nodes[str(resource.id)] = {
                    "id": str(resource.id),
                    "name": resource.name,
                    "type": resource.type,
                    "details": resource.details or {},
                    "children": []
                }

            # Build relationships
            root = {
                "id": "root",
                "name": "AWS Resources",
                "type": "root",
                "children": []
            }

            # Add all nodes that don't have a parent as children of root
            for node in nodes.values():
                root["children"].append(node)

            logger.info("Successfully extracted relationships")
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

    def get_diagram_history(self, limit: int = 10) -> List[DiagramHistory]:
        """
        Get the diagram version history for the project.
        """
        logger.info(f"Fetching diagram history for project {self.project_id}")
        try:
            return self.db.query(DiagramHistory).filter(
                DiagramHistory.project_id == self.project_id
            ).order_by(DiagramHistory.created_at.desc()).limit(limit).all()
        except Exception as e:
            logger.error(f"Error fetching diagram history: {str(e)}", exc_info=True)
            raise

    def get_layout(self, diagram_id: str) -> Optional[DiagramLayout]:
        """
        Get the layout preferences for a diagram.
        """
        logger.info(f"Fetching layout for diagram {diagram_id}")
        try:
            return self.db.query(DiagramLayout).filter(
                DiagramLayout.diagram_id == diagram_id,
                DiagramLayout.is_default == True
            ).first()
        except Exception as e:
            logger.error(f"Error fetching layout: {str(e)}", exc_info=True)
            raise

    def get_project_resources(self) -> List[Resource]:
        """Get all resources for the project."""
        logger.debug(f"Fetching resources for project {self.project_id}")
        try:
            resources = self.db.query(Resource).filter(
                Resource.project_id == self.project_id
            ).all()
            logger.debug(f"Found {len(resources)} resources")
            return resources
        except Exception as e:
            logger.error(f"Error fetching project resources: {str(e)}", exc_info=True)
            raise

    def _generate_version(self) -> str:
        """Generate a version string for the diagram."""
        logger.debug("Generating version string")
        try:
            return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        except Exception as e:
            logger.error(f"Error generating version string: {str(e)}", exc_info=True)
            raise
