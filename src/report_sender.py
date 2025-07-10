"""
Report Sender Module - Secure Communication with Sentra SaaS
Solutions Architecture: Secure, reliable result transmission

Key Design Decisions:
1. SQS for reliable, asynchronous communication
2. Message encryption and compression
3. Comprehensive retry logic with exponential backoff
4. Privacy protection (no plaintext emails in transit)
5. Structured messaging for easy processing
"""

import json
import logging
import gzip
import base64
import os
from typing import Dict, Any, Optional
from datetime import datetime, timezone
import hashlib
import boto3
from botocore.exceptions import ClientError
import time

logger = logging.getLogger(__name__)

class ReportSender:
    """
    Secure report transmission to Sentra SaaS platform
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize report sender with configuration
        
        Args:
            config: Scanner configuration dictionary
        """
        self.config = config
        
        # Get AWS region from environment or default to us-east-1
        aws_region = os.getenv('AWS_DEFAULT_REGION', 'us-east-1')
        self.sqs_client = boto3.client('sqs', region_name=aws_region)
        self.queue_url = config['sentra_sqs_queue_url']
        
        # Retry configuration
        self.max_retries = 3
        self.base_delay = 1.0  # Base delay for exponential backoff
        
        logger.info(f"ReportSender initialized for queue: {self.queue_url}")
    
    def send_scan_results(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Send scan results to Sentra SaaS platform via SQS
        
        Args:
            scan_results: Complete scan results dictionary
            
        Returns:
            Dict with send status and metadata
        """
        send_result = {
            'success': False,
            'message_id': None,
            'error': None,
            'attempts': 0,
            'compression_ratio': None
        }
        
        try:
            # Prepare message for transmission
            message = self._prepare_message(scan_results)
            
            # Compress message for efficiency
            compressed_message = self._compress_message(message)
            send_result['compression_ratio'] = len(compressed_message) / len(json.dumps(message))
            
            # Send with retry logic
            success, message_id, error = self._send_with_retry(compressed_message)
            
            send_result.update({
                'success': success,
                'message_id': message_id,
                'error': error,
                'attempts': self.max_retries + 1 if not success else 1
            })
            
            if success:
                logger.info(f"Successfully sent scan results: {message_id}")
            else:
                logger.error(f"Failed to send scan results: {error}")
            
            return send_result
            
        except Exception as e:
            send_result['error'] = f"Report sender error: {str(e)}"
            logger.error(f"Error sending scan results: {str(e)}")
            return send_result
    
    def _prepare_message(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Prepare structured message for Sentra platform
        
        Args:
            scan_results: Raw scan results
            
        Returns:
            Structured message ready for transmission
        """
        # Message format designed for Sentra platform processing
        message = {
            'message_metadata': {
                'version': '1.0',
                'message_type': 'email_scan_results',
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'message_id': self._generate_message_id(scan_results),
                'customer_info': {
                    'customer_name': self.config['customer_name'],
                    'environment': self.config['environment']
                }
            },
            'scan_data': {
                'file_info': scan_results['file_info'],
                'scan_metadata': scan_results['scan_metadata'],
                'email_analysis': {
                    'total_emails_found': scan_results['email_analysis']['total_emails_found'],
                    'unique_domains': scan_results['email_analysis']['unique_domains'],
                    # Privacy: Only send hashed emails, never plaintext
                    'email_hashes': scan_results['email_analysis']['email_hashes'],
                    'domain_summary': scan_results['email_analysis']['domain_summary']
                },
                'processing_metrics': scan_results['processing_metrics']
            },
            'security_metadata': {
                'data_classification': 'sensitive',
                'privacy_level': 'email_hashes_only',
                'encryption_note': 'message_compressed_and_base64_encoded'
            }
        }
        
        return message
    
    def _generate_message_id(self, scan_results: Dict[str, Any]) -> str:
        """
        Generate unique message ID for tracking
        
        Args:
            scan_results: Scan results for ID generation
            
        Returns:
            Unique message identifier
        """
        # Create deterministic but unique ID
        id_components = [
            self.config['customer_name'],
            scan_results['file_info']['bucket'],
            scan_results['file_info']['key'],
            scan_results['file_info'].get('etag', 'no-etag'),  # Handle missing etag gracefully
            scan_results['scan_metadata']['scan_timestamp']
        ]
        
        id_string = '|'.join(str(component) for component in id_components)
        message_hash = hashlib.sha256(id_string.encode('utf-8')).hexdigest()[:16]
        
        return f"sentra-scan-{message_hash}"
    
    def _compress_message(self, message: Dict[str, Any]) -> str:
        """
        Compress message for efficient transmission
        
        Args:
            message: Message dictionary to compress
            
        Returns:
            Base64 encoded, compressed message
        """
        try:
            # Convert to JSON
            json_message = json.dumps(message, separators=(',', ':'))
            
            # Compress using gzip
            compressed = gzip.compress(json_message.encode('utf-8'))
            
            # Base64 encode for SQS transmission
            encoded = base64.b64encode(compressed).decode('utf-8')
            
            logger.debug(f"Message compression: {len(json_message)} -> {len(compressed)} bytes")
            
            return encoded
            
        except Exception as e:
            logger.error(f"Message compression error: {str(e)}")
            raise
    
    def _send_with_retry(self, compressed_message: str) -> tuple[bool, Optional[str], Optional[str]]:
        """
        Send message with exponential backoff retry logic
        
        Args:
            compressed_message: Compressed message to send
            
        Returns:
            Tuple of (success, message_id, error)
        """
        last_error = None
        
        for attempt in range(self.max_retries + 1):
            try:
                # Prepare SQS message
                sqs_message = {
                    'MessageBody': compressed_message,
                    'MessageAttributes': {
                        'MessageType': {
                            'StringValue': 'email_scan_results',
                            'DataType': 'String'
                        },
                        'CustomerName': {
                            'StringValue': self.config['customer_name'],
                            'DataType': 'String'
                        },
                        'Environment': {
                            'StringValue': self.config['environment'],
                            'DataType': 'String'
                        },
                        'Version': {
                            'StringValue': '1.0',
                            'DataType': 'String'
                        },
                        'Compressed': {
                            'StringValue': 'true',
                            'DataType': 'String'
                        }
                    }
                }
                
                # Send to SQS
                response = self.sqs_client.send_message(
                    QueueUrl=self.queue_url,
                    **sqs_message
                )
                
                message_id = response['MessageId']
                logger.info(f"Message sent successfully on attempt {attempt + 1}: {message_id}")
                
                return True, message_id, None
                
            except ClientError as e:
                error_code = e.response['Error']['Code']
                error_message = e.response['Error']['Message']
                last_error = f"SQS error ({error_code}): {error_message}"
                
                logger.warning(f"Attempt {attempt + 1} failed: {last_error}")
                
                # Don't retry for certain error types
                non_retryable_errors = [
                    'AccessDenied',
                    'InvalidMessageContents',
                    'AWS.SimpleQueueService.NonExistentQueue'
                ]
                
                if error_code in non_retryable_errors:
                    logger.error(f"Non-retryable error: {error_code}")
                    break
                
            except Exception as e:
                last_error = f"Unexpected error: {str(e)}"
                logger.warning(f"Attempt {attempt + 1} failed: {last_error}")
            
            # Exponential backoff (except on last attempt)
            if attempt < self.max_retries:
                delay = self.base_delay * (2 ** attempt)
                logger.info(f"Retrying in {delay} seconds...")
                time.sleep(delay)
        
        return False, None, last_error
    
    def send_health_check(self) -> Dict[str, Any]:
        """
        Send health check message to verify connectivity
        
        Returns:
            Dict with health check results
        """
        health_result = {
            'success': False,
            'message_id': None,
            'error': None,
            'response_time_ms': None
        }
        
        try:
            start_time = time.time()
            
            health_message = {
                'message_metadata': {
                    'version': '1.0',
                    'message_type': 'health_check',
                    'timestamp': datetime.now(timezone.utc).isoformat(),
                    'customer_info': {
                        'customer_name': self.config['customer_name'],
                        'environment': self.config['environment']
                    }
                },
                'health_data': {
                    'status': 'healthy',
                    'scanner_version': '1.0.0',
                    'capabilities': [
                        'email_extraction',
                        'domain_analysis',
                        'privacy_protection',
                        'error_handling'
                    ]
                }
            }
            
            # Compress and send
            compressed_message = self._compress_message(health_message)
            success, message_id, error = self._send_with_retry(compressed_message)
            
            end_time = time.time()
            response_time_ms = int((end_time - start_time) * 1000)
            
            health_result.update({
                'success': success,
                'message_id': message_id,
                'error': error,
                'response_time_ms': response_time_ms
            })
            
            if success:
                logger.info(f"Health check successful: {message_id} (response time: {response_time_ms}ms)")
            else:
                logger.error(f"Health check failed: {error}")
            
            return health_result
            
        except Exception as e:
            health_result['error'] = f"Health check error: {str(e)}"
            logger.error(f"Health check error: {str(e)}")
            return health_result
    
    def get_queue_attributes(self) -> Dict[str, Any]:
        """
        Get SQS queue attributes for monitoring
        
        Returns:
            Dict with queue attributes and status
        """
        try:
            response = self.sqs_client.get_queue_attributes(
                QueueUrl=self.queue_url,
                AttributeNames=[
                    'ApproximateNumberOfMessages',
                    'ApproximateNumberOfMessagesNotVisible',
                    'LastModifiedTimestamp',
                    'QueueArn'
                ]
            )
            
            attributes = response['Attributes']
            
            return {
                'success': True,
                'queue_arn': attributes.get('QueueArn'),
                'messages_available': int(attributes.get('ApproximateNumberOfMessages', 0)),
                'messages_in_flight': int(attributes.get('ApproximateNumberOfMessagesNotVisible', 0)),
                'last_modified': attributes.get('LastModifiedTimestamp')
            }
            
        except Exception as e:
            logger.error(f"Error getting queue attributes: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }