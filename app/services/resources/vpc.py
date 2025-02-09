from datetime import datetime
from typing import List, Dict, Any
from uuid import uuid4
from botocore.exceptions import ClientError
from .base import AWSResourceBase
from ...schemas.aws import ResourceSummary
import logging

logger = logging.getLogger(__name__)

class VPCResource(AWSResourceBase):
    def list_resources(self) -> List[ResourceSummary]:
        """List all VPC resources with detailed information"""
        resources = []
        ec2 = self.session.client('ec2')

        try:
            # Get all VPCs
            vpcs = ec2.describe_vpcs()
            for vpc in vpcs['Vpcs']:
                vpc_id = vpc['VpcId']
                details = self.get_resource_details(vpc_id)
                
                # Set creation time to current time if not available
                created_at = datetime.now()

                resources.append(ResourceSummary(
                    id=uuid4(),
                    resource_id=vpc_id,
                    type='vpc',
                    name=vpc.get('Tags', [{'Key': 'Name', 'Value': vpc_id}])[0].get('Value', vpc_id),
                    region=self.region,
                    status=vpc['State'].lower(),
                    created_at=created_at,
                    details=details
                ))

        except ClientError as e:
            self.handle_client_error(e, 'ec2', 'describe_vpcs')

        return resources

    def get_resource_details(self, resource_id: str) -> Dict[str, Any]:
        """Get detailed information about a specific VPC"""
        ec2 = self.session.client('ec2')
        details = {}

        try:
            # Get VPC details
            vpc = ec2.describe_vpcs(VpcIds=[resource_id])['Vpcs'][0]
            details.update({
                'cidr_block': vpc['CidrBlock'],
                'is_default': vpc.get('IsDefault', False),
                'state': vpc['State'],
                'dhcp_options_id': vpc.get('DhcpOptionsId'),
                'instance_tenancy': vpc.get('InstanceTenancy'),
                'tags': vpc.get('Tags', []),
                'enable_dns_hostnames': False,  # Will be updated below
                'enable_dns_support': False,    # Will be updated below
            })

            # Get DNS settings
            try:
                dns_hostnames = ec2.describe_vpc_attribute(
                    VpcId=resource_id,
                    Attribute='enableDnsHostnames'
                )
                details['enable_dns_hostnames'] = dns_hostnames['EnableDnsHostnames']['Value']
            except ClientError as e:
                self.handle_client_error(e, 'ec2', 'describe_vpc_attribute', resource_id)

            try:
                dns_support = ec2.describe_vpc_attribute(
                    VpcId=resource_id,
                    Attribute='enableDnsSupport'
                )
                details['enable_dns_support'] = dns_support['EnableDnsSupport']['Value']
            except ClientError as e:
                self.handle_client_error(e, 'ec2', 'describe_vpc_attribute', resource_id)

            # Get subnets
            try:
                subnets = ec2.describe_subnets(Filters=[{'Name': 'vpc-id', 'Values': [resource_id]}])
                details['subnets'] = []
                for subnet in subnets['Subnets']:
                    subnet_details = {
                        'id': subnet['SubnetId'],
                        'cidr_block': subnet['CidrBlock'],
                        'availability_zone': subnet['AvailabilityZone'],
                        'state': subnet['State'],
                        'available_ips': subnet['AvailableIpAddressCount'],
                        'map_public_ip': subnet.get('MapPublicIpOnLaunch', False),
                        'tags': subnet.get('Tags', [])
                    }
                    details['subnets'].append(subnet_details)
            except ClientError as e:
                self.handle_client_error(e, 'ec2', 'describe_subnets', resource_id)

            # Get route tables
            try:
                route_tables = ec2.describe_route_tables(Filters=[{'Name': 'vpc-id', 'Values': [resource_id]}])
                details['route_tables'] = []
                for rt in route_tables['RouteTables']:
                    rt_details = {
                        'id': rt['RouteTableId'],
                        'routes': rt['Routes'],
                        'associations': rt['Associations'],
                        'tags': rt.get('Tags', [])
                    }
                    details['route_tables'].append(rt_details)
            except ClientError as e:
                self.handle_client_error(e, 'ec2', 'describe_route_tables', resource_id)

            # Get internet gateways
            try:
                igws = ec2.describe_internet_gateways(Filters=[{'Name': 'attachment.vpc-id', 'Values': [resource_id]}])
                details['internet_gateways'] = []
                for igw in igws['InternetGateways']:
                    igw_details = {
                        'id': igw['InternetGatewayId'],
                        'state': igw['Attachments'][0]['State'] if igw['Attachments'] else 'detached',
                        'tags': igw.get('Tags', [])
                    }
                    details['internet_gateways'].append(igw_details)
            except ClientError as e:
                self.handle_client_error(e, 'ec2', 'describe_internet_gateways', resource_id)

            # Get NACLs
            try:
                nacls = ec2.describe_network_acls(Filters=[{'Name': 'vpc-id', 'Values': [resource_id]}])
                details['network_acls'] = []
                for nacl in nacls['NetworkAcls']:
                    nacl_details = {
                        'id': nacl['NetworkAclId'],
                        'is_default': nacl['IsDefault'],
                        'entries': nacl['Entries'],
                        'associations': nacl['Associations'],
                        'tags': nacl.get('Tags', [])
                    }
                    details['network_acls'].append(nacl_details)
            except ClientError as e:
                self.handle_client_error(e, 'ec2', 'describe_network_acls', resource_id)

            return details

        except ClientError as e:
            self.handle_client_error(e, 'ec2', 'get_resource_details', resource_id)
            details['status'] = 'error'
            return details
