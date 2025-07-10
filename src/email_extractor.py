"""
Email Extractor Module - Smart Email Detection
Solutions Architecture: Privacy-first, efficient email extraction

Key Design Decisions:
1. Privacy protection through email hashing
2. Encoding detection for international files
3. Comprehensive regex patterns for email validation
4. Binary file detection to avoid processing errors
5. Deduplication and domain analysis
"""

import re
import logging
import hashlib
import chardet
from typing import Dict, List, Set, Any, Optional
import mimetypes
import io

logger = logging.getLogger(__name__)

class EmailExtractor:
    """
    Enterprise-grade email extraction with privacy and security considerations
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize extractor with configuration
        
        Args:
            config: Scanner configuration dictionary
        """
        self.config = config
        self.s3_client = None  # Will be set by scanner
        
        # Comprehensive email regex pattern
        # RFC 5322 compliant with practical modifications
        self.email_pattern = re.compile(
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            re.IGNORECASE
        )
        
        # Additional patterns for edge cases
        self.quoted_email_pattern = re.compile(
            r'"[^"]+"\s*@\s*[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}',
            re.IGNORECASE
        )
        
        # Domain extraction pattern
        self.domain_pattern = re.compile(r'@([A-Za-z0-9.-]+\.[A-Z|a-z]{2,})', re.IGNORECASE)
        
        # Binary file detection patterns
        self.binary_indicators = [
            b'\x00',  # Null bytes
            b'\xFF\xD8\xFF',  # JPEG
            b'\x89PNG',  # PNG
            b'PK\x03\x04',  # ZIP
            b'\x50\x4B',  # Another ZIP variant
        ]
        
        logger.info("EmailExtractor initialized")
    
    def set_s3_client(self, s3_client):
        """Set S3 client (called by scanner)"""
        self.s3_client = s3_client
    
    def extract_from_s3_object(self, bucket: str, key: str) -> Dict[str, Any]:
        """
        Extract emails from S3 object with comprehensive error handling
        
        Args:
            bucket: S3 bucket name
            key: S3 object key
            
        Returns:
            Dict with extraction results and metadata
        """
        result = {
            'success': False,
            'emails': [],
            'email_hashes': [],
            'domains': [],
            'error': None,
            'file_metadata': {}
        }
        
        try:
            logger.info(f"Extracting emails from s3://{bucket}/{key}")
            
            # Download file content
            response = self.s3_client.get_object(Bucket=bucket, Key=key)
            file_content = response['Body'].read()
            
            # Store file metadata
            result['file_metadata'] = {
                'content_type': response.get('ContentType', 'unknown'),
                'content_length': response.get('ContentLength', 0),
                'last_modified': response.get('LastModified'),
                'etag': response.get('ETag', '').strip('"')
            }
            
            # Check if file is binary
            if self._is_binary_file(file_content):
                result.update({
                    'success': True,
                    'error': 'Binary file detected - skipping email extraction'
                })
                logger.info(f"Skipping binary file: {key}")
                return result
            
            # Detect encoding and decode content
            decoded_content = self._decode_file_content(file_content)
            
            if decoded_content is None:
                result['error'] = "Failed to decode file content"
                return result
            
            # Extract emails
            emails = self._extract_emails_from_text(decoded_content)
            
            # Process and hash emails for privacy
            processed_emails = self._process_emails(emails)
            
            result.update({
                'success': True,
                'emails': processed_emails['emails'],
                'email_hashes': processed_emails['email_hashes'],
                'domains': processed_emails['domains']
            })
            
            logger.info(f"Extracted {len(emails)} emails from {key}")
            return result
            
        except Exception as e:
            result['error'] = f"Email extraction error: {str(e)}"
            logger.error(f"Error extracting emails from {bucket}/{key}: {str(e)}")
            return result
    
    def _is_binary_file(self, content: bytes) -> bool:
        """
        Detect if file content is binary to avoid processing errors
        
        Args:
            content: File content as bytes
            
        Returns:
            True if file appears to be binary
        """
        try:
            # Check for binary indicators in first 1024 bytes
            sample = content[:1024]
            
            # Look for binary file signatures
            for indicator in self.binary_indicators:
                if sample.startswith(indicator):
                    return True
            
            # Check for high percentage of null bytes or non-printable characters
            null_bytes = sample.count(b'\x00')
            if null_bytes > len(sample) * 0.1:  # More than 10% null bytes
                return True
            
            # Try to decode as text - if it fails, likely binary
            try:
                sample.decode('utf-8')
            except UnicodeDecodeError:
                try:
                    sample.decode('latin-1')
                except UnicodeDecodeError:
                    return True
            
            return False
            
        except Exception:
            # If we can't determine, assume binary to be safe
            return True
    
    def _decode_file_content(self, content: bytes) -> Optional[str]:
        """
        Smart encoding detection and decoding
        
        Args:
            content: Raw file content as bytes
            
        Returns:
            Decoded string content or None if decoding fails
        """
        try:
            # First, try to detect encoding
            detected = chardet.detect(content)
            confidence = detected.get('confidence', 0)
            encoding = detected.get('encoding', 'utf-8')
            
            logger.debug(f"Detected encoding: {encoding} (confidence: {confidence})")
            
            # If confidence is too low, try common encodings
            if confidence < 0.7:
                encodings_to_try = ['utf-8', 'latin-1', 'cp1252', 'iso-8859-1']
            else:
                encodings_to_try = [encoding, 'utf-8', 'latin-1', 'cp1252']
            
            for enc in encodings_to_try:
                try:
                    decoded = content.decode(enc)
                    logger.debug(f"Successfully decoded with encoding: {enc}")
                    return decoded
                except (UnicodeDecodeError, LookupError):
                    continue
            
            # If all else fails, try with error handling
            try:
                return content.decode('utf-8', errors='replace')
            except Exception:
                return content.decode('latin-1', errors='replace')
                
        except Exception as e:
            logger.error(f"Encoding detection/decoding error: {str(e)}")
            return None
    
    def _extract_emails_from_text(self, text: str) -> List[str]:
        """
        Extract email addresses from text using multiple regex patterns
        
        Args:
            text: Text content to scan
            
        Returns:
            List of found email addresses
        """
        emails = set()
        
        try:
            # Primary email pattern
            primary_matches = self.email_pattern.findall(text)
            emails.update(primary_matches)
            
            # Quoted email pattern for edge cases
            quoted_matches = self.quoted_email_pattern.findall(text)
            emails.update(quoted_matches)
            
            # Additional cleanup and validation
            validated_emails = []
            for email in emails:
                cleaned_email = self._validate_and_clean_email(email)
                if cleaned_email:
                    validated_emails.append(cleaned_email)
            
            return list(set(validated_emails))  # Remove duplicates
            
        except Exception as e:
            logger.error(f"Error extracting emails from text: {str(e)}")
            return []
    
    def _validate_and_clean_email(self, email: str) -> Optional[str]:
        """
        Validate and clean extracted email address
        
        Args:
            email: Raw email address string
            
        Returns:
            Cleaned email address or None if invalid
        """
        try:
            # Basic cleanup
            email = email.strip().lower()
            
            # Remove quotes if present
            email = email.strip('"')
            
            # Basic validation checks
            if len(email) < 5 or len(email) > 254:  # RFC limits
                return None
            
            if email.count('@') != 1:
                return None
            
            local_part, domain = email.split('@')
            
            # Validate local part
            if len(local_part) == 0 or len(local_part) > 64:
                return None
            
            # Validate domain
            if len(domain) == 0 or len(domain) > 253:
                return None
            
            if not domain.count('.'):  # Must have at least one dot
                return None
            
            # Check for common false positives
            false_positive_patterns = [
                r'^\d+@\d+$',  # Numbers only
                r'@\d+\.\d+$',  # IP addresses (basic check)
                r'\.\.+',  # Multiple consecutive dots
            ]
            
            for pattern in false_positive_patterns:
                if re.search(pattern, email):
                    return None
            
            return email
            
        except Exception:
            return None
    
    def _process_emails(self, emails: List[str]) -> Dict[str, Any]:
        """
        Process emails for privacy and analysis
        
        Args:
            emails: List of extracted email addresses
            
        Returns:
            Dict with processed emails, hashes, and domain analysis
        """
        processed = {
            'emails': [],
            'email_hashes': [],
            'domains': []
        }
        
        try:
            unique_emails = list(set(emails))  # Remove duplicates
            domains = set()
            
            for email in unique_emails:
                # Privacy: Create SHA-256 hash of email
                email_hash = hashlib.sha256(email.encode('utf-8')).hexdigest()
                
                # Extract domain
                if '@' in email:
                    domain = email.split('@')[1]
                    domains.add(domain)
                
                processed['emails'].append(email)  # For internal processing
                processed['email_hashes'].append(email_hash)  # For reporting
            
            # Domain analysis
            domain_counts = {}
            for email in unique_emails:
                if '@' in email:
                    domain = email.split('@')[1]
                    domain_counts[domain] = domain_counts.get(domain, 0) + 1
            
            # Sort domains by frequency
            sorted_domains = sorted(domain_counts.items(), key=lambda x: x[1], reverse=True)
            processed['domains'] = [{'domain': domain, 'count': count} for domain, count in sorted_domains]
            
            return processed
            
        except Exception as e:
            logger.error(f"Error processing emails: {str(e)}")
            return processed
    
    def extract_from_text(self, text: str) -> Dict[str, Any]:
        """
        Public method to extract emails from text (for testing)
        
        Args:
            text: Text content to scan
            
        Returns:
            Dict with extraction results
        """
        result = {
            'success': False,
            'emails': [],
            'email_hashes': [],
            'domains': [],
            'error': None
        }
        
        try:
            emails = self._extract_emails_from_text(text)
            processed_emails = self._process_emails(emails)
            
            result.update({
                'success': True,
                'emails': processed_emails['emails'],
                'email_hashes': processed_emails['email_hashes'],
                'domains': processed_emails['domains']
            })
            
            return result
            
        except Exception as e:
            result['error'] = f"Text extraction error: {str(e)}"
            logger.error(f"Error extracting emails from text: {str(e)}")
            return result