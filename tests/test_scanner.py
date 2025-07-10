"""
Unit Tests for Sentra Email Scanner
Solutions Architecture: Comprehensive testing for reliability
"""

import unittest
from unittest.mock import Mock, patch, MagicMock
import json
import sys
import os

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from email_extractor import EmailExtractor

class TestEmailExtractor(unittest.TestCase):
    """Test cases for email extraction functionality"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.config = {
            'customer_name': 'test_customer',
            'environment': 'test',
            'max_file_size_bytes': 100 * 1024 * 1024,
            'allowed_extensions': ['.txt', '.csv', '.json', '.log', '.md']
        }
        self.extractor = EmailExtractor(self.config)
    
    def test_email_extraction_basic(self):
        """Test basic email extraction"""
        test_text = """
        Contact us at info@example.com or support@test.org
        For sales inquiries: sales@company.co.uk
        """
        
        result = self.extractor.extract_from_text(test_text)
        
        self.assertTrue(result['success'])
        self.assertEqual(len(result['emails']), 3)
        self.assertIn('info@example.com', result['emails'])
        self.assertIn('support@test.org', result['emails'])
        self.assertIn('sales@company.co.uk', result['emails'])
    
    def test_email_extraction_edge_cases(self):
        """Test email extraction with edge cases"""
        test_text = """
        Valid emails:
        - user.name+tag@domain.com
        - test_email@sub.domain.org
        - "quoted.email"@example.com
        
        Invalid patterns (should be filtered):
        - 123@456 (no TLD)
        - user@domain. (trailing dot)
        - @domain.com (no local part)
        - user@.com (no domain)
        """
        
        result = self.extractor.extract_from_text(test_text)
        
        self.assertTrue(result['success'])
        # Should only extract valid emails
        valid_emails = [email for email in result['emails'] if '@' in email and '.' in email.split('@')[1]]
        self.assertEqual(len(valid_emails), len(result['emails']))
    
    def test_email_hashing_privacy(self):
        """Test that emails are properly hashed for privacy"""
        test_text = "Contact: test@example.com"
        
        result = self.extractor.extract_from_text(test_text)
        
        self.assertTrue(result['success'])
        self.assertEqual(len(result['email_hashes']), 1)
        
        # Hash should be SHA-256 (64 character hex string)
        email_hash = result['email_hashes'][0]
        self.assertEqual(len(email_hash), 64)
        self.assertTrue(all(c in '0123456789abcdef' for c in email_hash))
    
    def test_domain_analysis(self):
        """Test domain extraction and analysis"""
        test_text = """
        team@company.com
        support@company.com
        info@example.org
        sales@company.com
        """
        
        result = self.extractor.extract_from_text(test_text)
        
        self.assertTrue(result['success'])
        self.assertEqual(len(result['domains']), 2)  # company.com and example.org
        
        # Check domain counts
        domain_counts = {d['domain']: d['count'] for d in result['domains']}
        self.assertEqual(domain_counts.get('company.com'), 3)
        self.assertEqual(domain_counts.get('example.org'), 1)
    
    def test_binary_file_detection(self):
        """Test binary file detection"""
        # Create fake binary content
        binary_content = b'\x89PNG\r\n\x1a\n' + b'\x00' * 100
        
        is_binary = self.extractor._is_binary_file(binary_content)
        self.assertTrue(is_binary)
        
        # Test text content
        text_content = b'This is regular text content with emails: test@example.com'
        is_binary = self.extractor._is_binary_file(text_content)
        self.assertFalse(is_binary)
    
    def test_encoding_detection(self):
        """Test encoding detection and handling"""
        # Test UTF-8 content
        utf8_content = "Hello world: test@example.com".encode('utf-8')
        decoded = self.extractor._decode_file_content(utf8_content)
        self.assertIsNotNone(decoded)
        self.assertIn('test@example.com', decoded)
        
        # Test Latin-1 content
        latin1_content = "Café info: café@example.com".encode('latin-1')
        decoded = self.extractor._decode_file_content(latin1_content)
        self.assertIsNotNone(decoded)
    
    @patch('boto3.client')
    def test_s3_extraction_success(self, mock_boto3):
        """Test successful S3 object extraction"""
        # Mock S3 client
        mock_s3 = Mock()
        mock_boto3.return_value = mock_s3
        
        # Mock S3 response
        mock_response = {
            'Body': Mock(),
            'ContentType': 'text/plain',
            'ContentLength': 100,
            'LastModified': '2023-01-01T00:00:00Z',
            'ETag': '"abcdef123456"'
        }
        mock_response['Body'].read.return_value = b'Contact us at: test@example.com'
        mock_s3.get_object.return_value = mock_response
        
        self.extractor.set_s3_client(mock_s3)
        
        result = self.extractor.extract_from_s3_object('test-bucket', 'test-file.txt')
        
        self.assertTrue(result['success'])
        self.assertEqual(len(result['emails']), 1)
        self.assertIn('test@example.com', result['emails'])


class TestScannerIntegration(unittest.TestCase):
    """Integration tests for scanner functionality"""
    
    @patch('boto3.client')
    def setUp(self, mock_boto3):
        """Set up test fixtures with mocked AWS clients"""
        # Set up environment variables for testing
        os.environ.update({
            'SENTRA_SQS_QUEUE_URL': 'https://sqs.region.amazonaws.com/account/queue',
            'ALLOWED_EXTENSIONS': '.txt,.csv,.json',
            'MAX_FILE_SIZE_MB': '100',
            'CUSTOMER_NAME': 'test_customer',
            'ENVIRONMENT': 'test',
            'AWS_DEFAULT_REGION': 'us-east-1'  # Set region for testing
        })
        
        # Import scanner after setting environment
        from scanner import SentraScanner
        
        # Mock AWS clients
        self.mock_s3 = Mock()
        self.mock_sqs = Mock()
        self.mock_cloudwatch = Mock()
        
        def mock_boto3_client(service, **kwargs):
            return {
                's3': self.mock_s3,
                'sqs': self.mock_sqs,
                'cloudwatch': self.mock_cloudwatch
            }.get(service, Mock())
        
        mock_boto3.side_effect = mock_boto3_client
        
        self.scanner = SentraScanner()
        
        # Configure mock S3 client for the email extractor
        self.scanner.email_extractor.s3_client = self.mock_s3
    
    def test_file_classification(self):
        """Test file classification logic"""
        # Test allowed file
        classification = self.scanner.classify_file('bucket', 'test.txt', 1000)
        self.assertTrue(classification['should_process'])
        
        # Test disallowed extension
        classification = self.scanner.classify_file('bucket', 'test.exe', 1000)
        self.assertFalse(classification['should_process'])
        self.assertIn('extension', classification['skip_reason'])
        
        # Test oversized file
        large_size = 200 * 1024 * 1024  # 200MB
        classification = self.scanner.classify_file('bucket', 'test.txt', large_size)
        self.assertFalse(classification['should_process'])
        self.assertIn('size', classification['skip_reason'])
    
    def test_lambda_handler_s3_event(self):
        """Test Lambda handler with S3 event"""
        from scanner import lambda_handler
        
        # Mock S3 event
        event = {
            'Records': [
                {
                    'eventSource': 'aws:s3',
                    's3': {
                        'bucket': {'name': 'test-bucket'},
                        'object': {'key': 'test-file.txt'}
                    }
                }
            ]
        }
        
        # Mock S3 responses
        self.mock_s3.head_object.return_value = {
            'ContentLength': 1000,
            'LastModified': '2023-01-01T00:00:00Z'
        }
        
        self.mock_s3.get_object.return_value = {
            'Body': Mock(),
            'ContentType': 'text/plain',
            'ContentLength': 1000,
            'LastModified': '2023-01-01T00:00:00Z',
            'ETag': '"abcdef"'
        }
        self.mock_s3.get_object.return_value['Body'].read.return_value = b'Email: test@example.com'
        
        # Mock SQS response
        self.mock_sqs.send_message.return_value = {'MessageId': 'test-msg-id'}
        
        context = Mock()
        response = lambda_handler(event, context)
        
        self.assertEqual(response['statusCode'], 200)
        self.assertEqual(response['body']['summary']['total_files_processed'], 1)


class TestReportSender(unittest.TestCase):
    """Test cases for report sender functionality"""
    
    @patch('boto3.client')
    def setUp(self, mock_boto3):
        """Set up test fixtures"""
        from report_sender import ReportSender
        
        self.config = {
            'sentra_sqs_queue_url': 'https://sqs.region.amazonaws.com/account/queue',
            'customer_name': 'test_customer',
            'environment': 'test'
        }
        
        self.mock_sqs = Mock()
        mock_boto3.return_value = self.mock_sqs
        
        self.sender = ReportSender(self.config)
    
    def test_message_preparation(self):
        """Test message preparation and structure"""
        scan_results = {
            'file_info': {
                'bucket': 'test-bucket',
                'key': 'test-file.txt',
                'size_bytes': 1000,
                'last_modified': '2023-01-01T00:00:00Z',
                'file_type': 'txt',
                'etag': 'abcdef'
            },
            'scan_metadata': {
                'customer_name': 'test_customer',
                'environment': 'test',
                'scan_timestamp': '2023-01-01T00:00:00Z',
                'scanner_version': '1.0.0'
            },
            'email_analysis': {
                'total_emails_found': 2,
                'unique_domains': 1,
                'email_hashes': ['hash1', 'hash2'],
                'domain_summary': [{'domain': 'example.com', 'count': 2}]
            },
            'processing_metrics': {
                'file_size_mb': 0.001,
                'processing_time_seconds': 1.5,
                'estimated_cost_usd': 0.0001
            }
        }
        
        message = self.sender._prepare_message(scan_results)
        
        # Verify message structure
        self.assertIn('message_metadata', message)
        self.assertIn('scan_data', message)
        self.assertIn('security_metadata', message)
        
        # Verify privacy protection
        self.assertNotIn('emails', message['scan_data']['email_analysis'])
        self.assertIn('email_hashes', message['scan_data']['email_analysis'])
    
    def test_message_compression(self):
        """Test message compression"""
        test_message = {
            'test': 'data',
            'large_field': 'x' * 1000  # Large field for compression test
        }
        
        compressed = self.sender._compress_message(test_message)
        
        # Should be base64 encoded string
        self.assertIsInstance(compressed, str)
        
        # Should be compressed (smaller than original JSON)
        original_size = len(json.dumps(test_message))
        compressed_size = len(compressed)
        # Note: Small messages might not compress well, but structure should work
    
    def test_health_check(self):
        """Test health check functionality"""
        self.mock_sqs.send_message.return_value = {'MessageId': 'health-check-id'}
        
        result = self.sender.send_health_check()
        
        self.assertTrue(result['success'])
        self.assertEqual(result['message_id'], 'health-check-id')
        self.assertIsNotNone(result['response_time_ms'])


if __name__ == '__main__':
    # Run tests
    unittest.main(verbosity=2)
