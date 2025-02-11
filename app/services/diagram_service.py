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

    def extract_relationships(self) -> Dict:
        """
        Extract relationships between AWS resources and format them into
        a hierarchical structure suitable for D3.js visualization.
        """
        # Get all resources for the project
        resources = self.get_project_resources()

        # Create nodes dictionary with resource IDs as keys
        nodes = {}
        for resource in resources:
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

        return root

    def save_diagram(self, diagram_metadata: Optional[Dict] = None) -> DiagramHistory:
        """
        Save the current state of the diagram as a new version.
        """
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
        return diagram

    def save_layout(self, diagram_id: str, layout_data: Dict, 
                   is_default: bool = False) -> DiagramLayout:
        """
        Save layout preferences for a diagram.
        """
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
        return layout

    def get_diagram_history(self, limit: int = 10) -> List[DiagramHistory]:
        """
        Get the diagram version history for the project.
        """
        return self.db.query(DiagramHistory).filter(
            DiagramHistory.project_id == self.project_id
        ).order_by(DiagramHistory.created_at.desc()).limit(limit).all()

    def get_layout(self, diagram_id: str) -> Optional[DiagramLayout]:
        """
        Get the layout preferences for a diagram.
        """
        return self.db.query(DiagramLayout).filter(
            DiagramLayout.diagram_id == diagram_id,
            DiagramLayout.is_default == True
        ).first()

    def get_project_resources(self) -> List[Resource]:
        """Get all resources for the project."""
        return self.db.query(Resource).filter(
            Resource.project_id == self.project_id
        ).all()

    def _generate_version(self) -> str:
        """Generate a version string for the diagram."""
        return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
