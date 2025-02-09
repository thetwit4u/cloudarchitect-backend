"""
SQLAlchemy models for AWS resources.
"""
from enum import Enum

class ResourceType(str, Enum):
    EC2 = "ec2"
    S3 = "s3"
    RDS = "rds"
    LAMBDA = "lambda"
    VPC = "vpc"
    LOAD_BALANCER = "load_balancer"
    EKS = "eks"

    @classmethod
    def _missing_(cls, value):
        """Handle case-insensitive lookup"""
        for member in cls:
            if member.value.lower() == str(value).lower():
                return member
        return None
