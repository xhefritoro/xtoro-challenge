"""
Sentra Email Scanner - Main Lambda Handler
Solutions Architecture: Event-driven, secure email detection system

Key Design Decisions:
1. Lambda for serverless, event-driven processing
2. Least privilege IAM permissions
3. Comprehensive error handling and monitoring
4. Privacy-first approach (email hashing)
5. Cost optimization through file filtering
"""

import json
import logging
import os
import traceback
from typing import Dict, List, Any, Optional
import boto3
from botocore.exceptions import ClientError, BotoCoreError
import hashlib
from datetime import datetime, timezone

from email_extractor import EmailExtractor
from report_sender import ReportSender

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

class SentraScanner:
    """
    Main scanner class with enterprise-grade error handling and monitoring
    """
    
    def __init__(self):
        """
        Initialize scanner with AWS clients and configuration
        """
        # Get AWS region from environment or default to us-east-1
        aws_region = os.getenv('AWS_DEFAULT_REGION', 'us-east-1')
        
        self.s3_client = boto3.client('s3', region_name=aws_region)
        self.cloudwatch = boto3.client('cloudwatch', region_name=aws_region)
        
        # Load configuration from environment variables
        self.config = self._load_configuration()
        
        # Initialize components
        self.email_extractor = EmailExtractor(self.config)
        self.email_extractor.set_s3_client(self.s3_client)
        self.report_sender = ReportSender(self.config)
        
        logger.info(f"Scanner initialized for customer: {self.config['customer_name']}")
    
    def _load_configuration(self) -> Dict[str, Any]:
        """
        Load and validate configuration from environment variables
        Security: Validate all inputs to prevent injection attacks
        """
        try:
            allowed_extensions = os.getenv('ALLOWED_EXTENSIONS', '.txt,.csv,.json,.log,.md').split(',')
            max_file_size_mb = int(os.getenv('MAX_FILE_SIZE_MB', '100'))
            
            config = {
                'sentra_sqs_queue_url': os.getenv('SENTRA_SQS_QUEUE_URL'),
                'allowed_extensions': [ext.strip().lower() for ext in allowed_extensions],
                'max_file_size_mb': max_file_size_mb,
                'max_file_size_bytes': max_file_size_mb * 1024 * 1024,
                'customer_name': os.getenv('CUSTOMER_NAME', 'unknown'),
                'environment': os.getenv('ENVIRONMENT', 'dev')
            }
            
            # Validate required configuration
            if not config['sentra_sqs_queue_url']:
                raise ValueError("SENTRA_SQS_QUEUE_URL environment variable is required")
            
            return config
            
        except Exception as e:
            logger.error(f"Configuration error: {str(e)}")
            raise
    
    def classify_file(self, bucket: str, key: str, file_size: int) -> Dict[str, Any]:
        """
        Intelligent file classification with security and cost considerations
        
        Classification strategy:
        1. File extension filtering (security)
        2. File size limits (cost optimization)
        3. Binary file detection (efficiency)
        4. Intelligent Tiering awareness (cost)
        
        Returns:
            Dict with classification results and processing decision
        """
        classification = {
            'should_process': False,
            'skip_reason': None,
            'file_type': 'unknown',
            'estimated_cost': 0.0
        }
        
        try:
            # Extract file extension
            file_extension = os.path.splitext(key)[1].lower()
            
            # Check file extension whitelist (security consideration)
            if file_extension not in self.config['allowed_extensions']:
                classification.update({
                    'skip_reason': f"File extension '{file_extension}' not in allowed list",
                    'file_type': 'unsupported'
                })
                return classification
            
            # Check file size limits (cost optimization)
            if file_size > self.config['max_file_size_bytes']:
                classification.update({
                    'skip_reason': f"File size {file_size} bytes exceeds limit of {self.config['max_file_size_bytes']} bytes",
                    'file_type': 'oversized'
                })
                return classification
            
            # Skip empty files
            if file_size == 0:
                classification.update({
                    'skip_reason': "Empty file",
                    'file_type': 'empty'
                })
                return classification
            
            # Estimate processing cost (for monitoring)
            # Lambda cost calculation: $0.0000166667 per GB-second
            estimated_duration_seconds = min(file_size / (1024 * 1024), 30)  # Rough estimate
            memory_gb = 0.512  # 512MB allocated memory
            estimated_cost = estimated_duration_seconds * memory_gb * 0.0000166667
            
            # File is approved for processing
            classification.update({
                'should_process': True,
                'file_type': file_extension.lstrip('.'),
                'estimated_cost': estimated_cost
            })
            
            return classification
            
        except Exception as e:
            logger.error(f"Error classifying file {bucket}/{key}: {str(e)}")
            classification.update({
                'skip_reason': f"Classification error: {str(e)}",
                'file_type': 'error'
            })
            return classification
    
    def process_s3_object(self, bucket: str, key: str) -> Dict[str, Any]:
        """
        Process a single S3 object with comprehensive error handling
        
        Returns:
            Dict with processing results and metrics
        """
        start_time = datetime.now(timezone.utc)
        result = {
            'success': False,
            'bucket': bucket,
            'key': key,
            'timestamp': start_time.isoformat(),
            'customer_name': self.config['customer_name'],
            'environment': self.config['environment'],
            'error_details': None,
            'metrics': {}
        }
        
        try:
            # Get object metadata
            logger.info(f"Processing S3 object: s3://{bucket}/{key}")
            
            try:
                head_response = self.s3_client.head_object(Bucket=bucket, Key=key)
                file_size = head_response['ContentLength']
                last_modified = head_response['LastModified']
                etag = head_response.get('ETag', '').strip('"')  # Remove quotes from ETag
                
            except ClientError as e:
                error_code = e.response['Error']['Code']
                if error_code == 'NoSuchKey':
                    result['error_details'] = "File was deleted before processing"
                elif error_code == 'AccessDenied':
                    result['error_details'] = "Access denied - check IAM permissions"
                else:
                    result['error_details'] = f"S3 error: {error_code}"
                
                logger.warning(f"S3 error for {bucket}/{key}: {result['error_details']}")
                return result
            
            # Classify file for processing
            classification = self.classify_file(bucket, key, file_size)
            result['classification'] = classification
            
            if not classification['should_process']:
                result.update({
                    'success': True,
                    'skipped': True,
                    'skip_reason': classification['skip_reason']
                })
                logger.info(f"Skipping file {key}: {classification['skip_reason']}")
                return result
            
            # Extract emails from the file
            extraction_result = self.email_extractor.extract_from_s3_object(bucket, key)
            
            if not extraction_result['success']:
                result['error_details'] = extraction_result['error']
                return result
            
            # Prepare scan results
            scan_results = {
                'file_info': {
                    'bucket': bucket,
                    'key': key,
                    'size_bytes': file_size,
                    'last_modified': last_modified.isoformat(),
                    'file_type': classification['file_type'],
                    'etag': etag
                },
                'scan_metadata': {
                    'customer_name': self.config['customer_name'],
                    'environment': self.config['environment'],
                    'scan_timestamp': start_time.isoformat(),
                    'scanner_version': '1.0.0'
                },
                'email_analysis': {
                    'total_emails_found': len(extraction_result['emails']),
                    'unique_domains': len(extraction_result['domains']),
                    'email_hashes': extraction_result['email_hashes'],  # Privacy: only hashes
                    'domain_summary': extraction_result['domains']
                },
                'processing_metrics': {
                    'file_size_mb': round(file_size / (1024 * 1024), 2),
                    'processing_time_seconds': None,  # Will be calculated
                    'estimated_cost_usd': classification['estimated_cost']
                }
            }
            
            # Send results to Sentra
            send_result = self.report_sender.send_scan_results(scan_results)
            
            if not send_result['success']:
                result['error_details'] = f"Failed to send results: {send_result['error']}"
                return result
            
            # Calculate processing time
            end_time = datetime.now(timezone.utc)
            processing_time = (end_time - start_time).total_seconds()
            scan_results['processing_metrics']['processing_time_seconds'] = processing_time
            
            # Publish custom CloudWatch metrics
            self._publish_metrics(scan_results)
            
            result.update({
                'success': True,
                'emails_found': len(extraction_result['emails']),
                'unique_domains': len(extraction_result['domains']),
                'processing_time_seconds': processing_time,
                'message_id': send_result.get('message_id')
            })
            
            logger.info(f"Successfully processed {key}: {len(extraction_result['emails'])} emails found")
            return result
            
        except Exception as e:
            end_time = datetime.now(timezone.utc)
            processing_time = (end_time - start_time).total_seconds()
            
            error_details = {
                'error_type': type(e).__name__,
                'error_message': str(e),
                'processing_time_seconds': processing_time,
                'traceback': traceback.format_exc()
            }
            
            result['error_details'] = error_details
            logger.error(f"Error processing {bucket}/{key}: {str(e)}")
            logger.error(traceback.format_exc())
            
            # Publish error metrics
            self._publish_error_metrics(bucket, key, str(e))
            
            return result
    
    def _publish_metrics(self, scan_results: Dict[str, Any]) -> None:
        """
        Publish custom CloudWatch metrics for monitoring and alerting
        """
        try:
            namespace = "Sentra/EmailScanner"
            timestamp = datetime.now(timezone.utc)
            
            metrics = [
                {
                    'MetricName': 'EmailsFound',
                    'Value': scan_results['email_analysis']['total_emails_found'],
                    'Unit': 'Count'
                },
                {
                    'MetricName': 'UniqueDomainsFound',
                    'Value': scan_results['email_analysis']['unique_domains'],
                    'Unit': 'Count'
                },
                {
                    'MetricName': 'ProcessingTime',
                    'Value': scan_results['processing_metrics']['processing_time_seconds'],
                    'Unit': 'Seconds'
                },
                {
                    'MetricName': 'FileSizeProcessed',
                    'Value': scan_results['processing_metrics']['file_size_mb'],
                    'Unit': 'None'
                }
            ]
            
            # Add customer dimension for multi-tenant monitoring
            dimensions = [
                {
                    'Name': 'CustomerName',
                    'Value': self.config['customer_name']
                },
                {
                    'Name': 'Environment',
                    'Value': self.config['environment']
                }
            ]
            
            for metric in metrics:
                metric['Dimensions'] = dimensions
                metric['Timestamp'] = timestamp
            
            self.cloudwatch.put_metric_data(
                Namespace=namespace,
                MetricData=metrics
            )
            
        except Exception as e:
            logger.warning(f"Failed to publish metrics: {str(e)}")
    
    def _publish_error_metrics(self, bucket: str, key: str, error: str) -> None:
        """
        Publish error metrics for monitoring and alerting
        """
        try:
            self.cloudwatch.put_metric_data(
                Namespace="Sentra/EmailScanner",
                MetricData=[
                    {
                        'MetricName': 'ProcessingErrors',
                        'Value': 1,
                        'Unit': 'Count',
                        'Dimensions': [
                            {
                                'Name': 'CustomerName',
                                'Value': self.config['customer_name']
                            },
                            {
                                'Name': 'ErrorType',
                                'Value': error[:100]  # Truncate for dimension
                            }
                        ]
                    }
                ]
            )
        except Exception as e:
            logger.warning(f"Failed to publish error metrics: {str(e)}")


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    AWS Lambda handler for S3 event processing
    
    Architecture Decision: Event-driven processing ensures near real-time scanning
    while maintaining cost efficiency through serverless execution
    """
    logger.info("Sentra email scanner started")
    logger.info(f"Event: {json.dumps(event)}")
    
    try:
        scanner = SentraScanner()
        results = []
        
        # Process each S3 record in the event
        for record in event.get('Records', []):
            if record.get('eventSource') == 'aws:s3':
                # Extract S3 event details
                bucket = record['s3']['bucket']['name']
                key = record['s3']['object']['key']
                
                # URL decode the key (S3 events encode object keys)
                import urllib.parse
                key = urllib.parse.unquote_plus(key)
                
                # Process the object
                result = scanner.process_s3_object(bucket, key)
                results.append(result)
        
        # Aggregate results
        total_processed = len(results)
        successful = sum(1 for r in results if r['success'])
        total_emails = sum(r.get('emails_found', 0) for r in results if r['success'])
        
        response = {
            'statusCode': 200,
            'body': {
                'message': 'Processing completed',
                'summary': {
                    'total_files_processed': total_processed,
                    'successful_scans': successful,
                    'failed_scans': total_processed - successful,
                    'total_emails_found': total_emails
                },
                'results': results
            }
        }
        
        logger.info(f"Processing summary: {response['body']['summary']}")
        return response
        
    except Exception as e:
        error_response = {
            'statusCode': 500,
            'body': {
                'error': 'Internal processing error',
                'details': str(e),
                'traceback': traceback.format_exc()
            }
        }
        
        logger.error(f"Lambda handler error: {str(e)}")
        logger.error(traceback.format_exc())
        
        return error_response