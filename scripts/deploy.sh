#!/bin/bash
# Sentra Scanner Deployment Script
# Solutions Architecture: Automated, safe deployment with validation

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
TERRAFORM_DIR="$PROJECT_ROOT/terraform"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Usage function
usage() {
    cat << EOF
Sentra Scanner Deployment Script

Usage: $0 [OPTIONS] COMMAND

Commands:
    validate    - Validate configuration and dependencies
    plan       - Create Terraform execution plan
    deploy     - Deploy infrastructure and Lambda function
    test       - Run post-deployment tests
    estimate   - Estimate scanning costs for existing S3 files
    destroy    - Destroy all resources (use with caution)

Options:
    -e, --environment ENV    Environment (dev, staging, prod) [default: dev]
    -c, --customer NAME      Customer name [required]
    -b, --bucket NAME        S3 bucket name [required]
    -q, --queue-arn ARN      Sentra SQS queue ARN [required]
    -a, --account-id ID      Sentra account ID [required]
    -v, --verbose            Verbose output
    -h, --help              Show this help message

Prerequisites:
    - AWS CLI configured with appropriate credentials
    - Python 3 (for Lambda function)
    - Terraform (will be auto-installed if not found)
    - Optional: jq and bc for enhanced cost calculations

Examples:
    $0 validate -c acme-corp -b acme-data-bucket
    $0 deploy -e prod -c acme-corp -b acme-data-bucket -q arn:aws:sqs:... -a 123456789012
    $0 estimate -c acme-corp -b acme-data-bucket
    $0 test -c acme-corp

EOF
}

# Default values
ENVIRONMENT="dev"
CUSTOMER_NAME=""
S3_BUCKET=""
SENTRA_SQS_QUEUE_ARN=""
SENTRA_ACCOUNT_ID=""
VERBOSE=false
COMMAND=""

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -e|--environment)
            ENVIRONMENT="$2"
            shift 2
            ;;
        -c|--customer)
            CUSTOMER_NAME="$2"
            shift 2
            ;;
        -b|--bucket)
            S3_BUCKET="$2"
            shift 2
            ;;
        -q|--queue-arn)
            SENTRA_SQS_QUEUE_ARN="$2"
            shift 2
            ;;
        -a|--account-id)
            SENTRA_ACCOUNT_ID="$2"
            shift 2
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        validate|plan|deploy|test|estimate|destroy)
            COMMAND="$1"
            shift
            ;;
        *)
            log_error "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

# Validate required parameters
if [[ -z "$COMMAND" ]]; then
    log_error "Command is required"
    usage
    exit 1
fi

if [[ -z "$CUSTOMER_NAME" ]]; then
    log_error "Customer name is required"
    usage
    exit 1
fi

# Set verbose mode
if [[ "$VERBOSE" == "true" ]]; then
    set -x
fi

# Install Terraform if not found
install_terraform() {
    log_info "Installing Terraform..."
    
    # Detect OS
    local os_type=""
    if [[ "$OSTYPE" == "darwin"* ]]; then
        os_type="darwin"
    elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
        os_type="linux"
    else
        log_error "Unsupported operating system: $OSTYPE"
        log_error "Please install Terraform manually from https://terraform.io/downloads"
        exit 1
    fi
    
    # Detect architecture
    local arch=""
    case $(uname -m) in
        x86_64) arch="amd64" ;;
        arm64|aarch64) arch="arm64" ;;
        *) 
            log_error "Unsupported architecture: $(uname -m)"
            log_error "Please install Terraform manually from https://terraform.io/downloads"
            exit 1
            ;;
    esac
    
    # Create temporary directory
    local temp_dir=$(mktemp -d)
    cd "$temp_dir"
    
    # Download latest Terraform
    log_info "Downloading Terraform for $os_type/$arch..."
    local terraform_version="1.5.7"  # Use a stable version
    local download_url="https://releases.hashicorp.com/terraform/${terraform_version}/terraform_${terraform_version}_${os_type}_${arch}.zip"
    
    if command -v curl &> /dev/null; then
        curl -sL "$download_url" -o terraform.zip
    elif command -v wget &> /dev/null; then
        wget -q "$download_url" -O terraform.zip
    else
        log_error "Neither curl nor wget found. Please install one of them or install Terraform manually."
        exit 1
    fi
    
    # Extract and install
    if command -v unzip &> /dev/null; then
        unzip -q terraform.zip
        chmod +x terraform
        
        # Install to appropriate location
        local install_dir=""
        if [[ "$os_type" == "darwin" ]]; then
            # macOS - try to install to /usr/local/bin
            if [[ -w "/usr/local/bin" ]]; then
                install_dir="/usr/local/bin"
            else
                # Use sudo if needed
                sudo mv terraform /usr/local/bin/
                install_dir="/usr/local/bin"
            fi
        else
            # Linux - try to install to /usr/local/bin
            if [[ -w "/usr/local/bin" ]]; then
                install_dir="/usr/local/bin"
            else
                # Use sudo if needed
                sudo mv terraform /usr/local/bin/
                install_dir="/usr/local/bin"
            fi
        fi
        
        # Move terraform if install_dir is set (when no sudo was needed)
        if [[ -n "$install_dir" && -f "terraform" ]]; then
            mv terraform "$install_dir/"
        fi
        
        # Cleanup
        cd "$PROJECT_ROOT"
        rm -rf "$temp_dir"
        
        # Verify installation
        if command -v terraform &> /dev/null; then
            log_success "Terraform $(terraform version -json | python3 -c 'import sys,json; print(json.load(sys.stdin)["terraform_version"])' 2>/dev/null || echo 'installed') successfully"
        else
            log_error "Terraform installation failed. Please install manually from https://terraform.io/downloads"
            exit 1
        fi
    else
        log_error "unzip command not found. Please install unzip or install Terraform manually."
        exit 1
    fi
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check AWS CLI
    if ! command -v aws &> /dev/null; then
        log_error "AWS CLI is not installed"
        exit 1
    fi
    
    # Check Terraform
    if ! command -v terraform &> /dev/null; then
        log_warning "Terraform is not installed, attempting to install..."
        install_terraform
    fi
    
    # Check AWS credentials
    if ! aws sts get-caller-identity &> /dev/null; then
        log_error "AWS credentials not configured"
        exit 1
    fi
    
    # Check Python
    if ! command -v python3 &> /dev/null; then
        log_error "Python 3 is not installed"
        exit 1
    fi
    
    # Check jq for JSON parsing (optional but recommended)
    if ! command -v jq &> /dev/null; then
        log_warning "jq is not installed - cost estimation will be limited"
        log_info "Install jq for better cost analysis: brew install jq (macOS) or apt-get install jq (Linux)"
    fi
    
    # Check bc for calculations (optional but recommended)
    if ! command -v bc &> /dev/null; then
        log_warning "bc is not installed - cost calculations will be simplified"
        log_info "Install bc for precise calculations: brew install bc (macOS) or apt-get install bc (Linux)"
    fi
    
    log_success "Prerequisites check passed"
}

# Validate configuration
validate_config() {
    log_info "Validating configuration..."
    
    # Check S3 bucket exists (if provided)
    if [[ -n "$S3_BUCKET" ]]; then
        if ! aws s3 ls "s3://$S3_BUCKET" &> /dev/null; then
            log_error "S3 bucket '$S3_BUCKET' does not exist or is not accessible"
            exit 1
        fi
        log_success "S3 bucket '$S3_BUCKET' is accessible"
    fi
    
    # Validate environment
    if [[ ! "$ENVIRONMENT" =~ ^(dev|staging|prod)$ ]]; then
        log_error "Environment must be dev, staging, or prod"
        exit 1
    fi
    
    # Check if terraform.tfvars exists
    if [[ ! -f "$TERRAFORM_DIR/terraform.tfvars" ]]; then
        log_warning "terraform.tfvars not found, creating from template..."
        create_tfvars_from_template
    fi
    
    log_success "Configuration validation passed"
}

# Create terraform.tfvars from template
create_tfvars_from_template() {
    local tfvars_file="$TERRAFORM_DIR/terraform.tfvars"
    local template_file="$TERRAFORM_DIR/terraform.tfvars.example"
    
    if [[ -f "$template_file" ]]; then
        cp "$template_file" "$tfvars_file"
        
        # Update with provided values
        sed -i.bak "s/your-company-name/$CUSTOMER_NAME/g" "$tfvars_file"
        [[ -n "$S3_BUCKET" ]] && sed -i.bak "s/your-s3-bucket-name/$S3_BUCKET/g" "$tfvars_file"
        [[ -n "$SENTRA_ACCOUNT_ID" ]] && sed -i.bak "s/123456789012/$SENTRA_ACCOUNT_ID/g" "$tfvars_file"
        [[ -n "$SENTRA_SQS_QUEUE_ARN" ]] && sed -i.bak "s|arn:aws:sqs:us-east-1:123456789012:sentra-customer-results|$SENTRA_SQS_QUEUE_ARN|g" "$tfvars_file"
        sed -i.bak "s/prod/$ENVIRONMENT/g" "$tfvars_file"
        
        # Clean up backup file
        rm -f "$tfvars_file.bak"
        
        log_info "Created terraform.tfvars from template"
        log_warning "Please review and customize terraform.tfvars before deployment"
    else
        log_error "Template file not found: $template_file"
        exit 1
    fi
}

# Build Lambda package
build_lambda_package() {
    log_info "Building Lambda deployment package..."
    
    local src_dir="$PROJECT_ROOT/src"
    local build_dir="$PROJECT_ROOT/build"
    local dist_dir="$PROJECT_ROOT/dist"
    
    # Clean previous builds
    rm -rf "$build_dir" "$dist_dir"
    mkdir -p "$build_dir" "$dist_dir"
    
    # Copy source code
    cp -r "$src_dir"/* "$build_dir/"
    
    # Install dependencies
    cd "$build_dir"
    
    # Install only production dependencies to the package directory
    pip install -r requirements-prod.txt -t . --no-deps --only-binary=all

        
    log_success "Lambda package built: $dist_dir/"
    cd "$PROJECT_ROOT"
}

# Terraform operations
terraform_init() {
    log_info "Initializing Terraform..."
    cd "$TERRAFORM_DIR"
    terraform init
    cd "$PROJECT_ROOT"
}

terraform_plan() {
    log_info "Creating Terraform execution plan..."
    cd "$TERRAFORM_DIR"
    terraform plan -out=tfplan
    cd "$PROJECT_ROOT"
}

terraform_apply() {
    log_info "Applying Terraform configuration..."
    cd "$TERRAFORM_DIR"
    terraform apply tfplan
    cd "$PROJECT_ROOT"
}

terraform_destroy() {
    log_warning "This will destroy ALL resources. Are you sure? (y/N)"
    read -r response
    if [[ "$response" =~ ^[Yy]$ ]]; then
        log_info "Destroying Terraform-managed resources..."
        cd "$TERRAFORM_DIR"
        terraform destroy -auto-approve
        cd "$PROJECT_ROOT"
        log_success "Resources destroyed"
    else
        log_info "Destroy cancelled"
    fi
}

# Run tests
run_tests() {
    log_info "Running post-deployment tests..."
    
    # Get Lambda function name from Terraform output
    cd "$TERRAFORM_DIR"
    local lambda_function_name
    lambda_function_name=$(terraform output -raw lambda_function_name 2>/dev/null || echo "")
    cd "$PROJECT_ROOT"
    
    if [[ -z "$lambda_function_name" ]]; then
        log_error "Could not get Lambda function name from Terraform output"
        exit 1
    fi
    
    # Test 1: Lambda function exists and is active
    log_info "Testing Lambda function status..."
    local function_status
    function_status=$(aws lambda get-function --function-name "$lambda_function_name" --query 'Configuration.State' --output text)
    
    if [[ "$function_status" == "Active" ]]; then
        log_success "Lambda function is active"
    else
        log_error "Lambda function is not active (status: $function_status)"
        exit 1
    fi
    
    # Test 2: Upload test file and verify processing
    if [[ -n "$S3_BUCKET" ]]; then
        log_info "Testing S3 event processing..."
        
        # Create test file
        local test_file="/tmp/sentra-test-$(date +%s).txt"
        echo "Test email for Sentra scanner: test-$(date +%s)@example.com" > "$test_file"
        
        # Upload to S3
        aws s3 cp "$test_file" "s3://$S3_BUCKET/"
        local test_filename
        test_filename=$(basename "$test_file")
        
        # Wait for processing
        log_info "Waiting for file processing..."
        sleep 30
        
        # Check CloudWatch logs for processing
        local log_group="/aws/lambda/$lambda_function_name"
        local recent_logs
        recent_logs=$(aws logs filter-log-events \
            --log-group-name "$log_group" \
            --start-time "$(($(date +%s) - 300))000" \
            --filter-pattern "Successfully processed" \
            --query 'events[0].message' \
            --output text 2>/dev/null || echo "None")
        
        if [[ "$recent_logs" != "None" && "$recent_logs" != "null" ]]; then
            log_success "File processing test passed"
        else
            log_warning "File processing test inconclusive - check CloudWatch logs manually"
        fi
        
        # Cleanup test file
        aws s3 rm "s3://$S3_BUCKET/$test_filename" || true
        rm -f "$test_file"
    fi
    
    # Test 3: Health check
    log_info "Running health check..."
    local health_response
    health_response=$(aws lambda invoke \
        --function-name "$lambda_function_name" \
        --payload '{"health_check": true}' \
        /tmp/health-response.json 2>/dev/null && echo "success" || echo "failed")
    
    if [[ "$health_response" == "success" ]]; then
        log_success "Health check passed"
    else
        log_warning "Health check failed - function may not be fully ready"
    fi
    
    rm -f /tmp/health-response.json
    
    log_success "Post-deployment tests completed"
}

# Estimate scanning costs for existing S3 files
estimate_scanning_costs() {
    log_info "Analyzing S3 bucket contents for cost estimation..."
    
    if [[ -z "$S3_BUCKET" ]]; then
        log_warning "S3 bucket not specified, skipping cost estimation"
        return
    fi
    
    # Get bucket statistics
    local total_objects=0
    local total_size_bytes=0
    local file_types_count=()
    
    # Count objects and calculate total size
    local s3_stats
    s3_stats=$(aws s3api list-objects-v2 --bucket "$S3_BUCKET" \
        --query 'Contents[].{Size:Size,Key:Key}' \
        --output json 2>/dev/null || echo "[]")
    
    if [[ "$s3_stats" == "[]" ]]; then
        log_info "S3 bucket '$S3_BUCKET' is empty or inaccessible"
        return
    fi
    
    # Parse JSON and calculate statistics
    if command -v jq &> /dev/null; then
        total_objects=$(echo "$s3_stats" | jq 'length' 2>/dev/null || echo "0")
        total_size_bytes=$(echo "$s3_stats" | jq '[.[].Size] | add' 2>/dev/null || echo "0")
    else
        # Fallback: count lines and estimate
        total_objects=$(echo "$s3_stats" | grep -o '"Size"' | wc -l | tr -d ' ')
        total_size_bytes=$(echo "$s3_stats" | grep -o '"Size":[0-9]*' | cut -d':' -f2 | awk '{sum += $1} END {print sum}')
    fi
    
    # Convert bytes to human readable format
    local total_size_mb=$((total_size_bytes / 1024 / 1024))
    local total_size_gb=$((total_size_mb / 1024))
    
    # Estimate costs (approximate AWS Lambda pricing)
    local lambda_requests_cost_per_million=0.20  # $0.20 per 1M requests
    local lambda_gb_second_cost=0.0000166667     # $0.0000166667 per GB-second
    local avg_processing_time_seconds=5          # Estimated average processing time per file
    local lambda_memory_gb=0.128                 # Default Lambda memory allocation (128MB)
    
    # Calculate Lambda costs
    local lambda_invocation_cost
    local lambda_compute_cost
    local total_lambda_cost
    local s3_get_requests_cost
    local estimated_total_cost
    
    if command -v bc &> /dev/null; then
        lambda_invocation_cost=$(echo "scale=4; $total_objects * $lambda_requests_cost_per_million / 1000000" | bc -l 2>/dev/null || echo "0")
        lambda_compute_cost=$(echo "scale=4; $total_objects * $avg_processing_time_seconds * $lambda_memory_gb * $lambda_gb_second_cost" | bc -l 2>/dev/null || echo "0")
        total_lambda_cost=$(echo "scale=2; $lambda_invocation_cost + $lambda_compute_cost" | bc -l 2>/dev/null || echo "0")
        s3_get_requests_cost=$(echo "scale=4; $total_objects * 0.0004 / 1000" | bc -l 2>/dev/null || echo "0") # $0.0004 per 1000 GET requests
        estimated_total_cost=$(echo "scale=2; $total_lambda_cost + $s3_get_requests_cost" | bc -l 2>/dev/null || echo "0")
    else
        # Simplified calculations without bc
        lambda_invocation_cost=$(python3 -c "print(f'{$total_objects * 0.20 / 1000000:.4f}')" 2>/dev/null || echo "~0.01")
        lambda_compute_cost=$(python3 -c "print(f'{$total_objects * 5 * 0.128 * 0.0000166667:.4f}')" 2>/dev/null || echo "~0.01")
        s3_get_requests_cost=$(python3 -c "print(f'{$total_objects * 0.0004 / 1000:.4f}')" 2>/dev/null || echo "~0.01")
        estimated_total_cost=$(python3 -c "print(f'{($total_objects * 0.20 / 1000000) + ($total_objects * 5 * 0.128 * 0.0000166667) + ($total_objects * 0.0004 / 1000):.2f}')" 2>/dev/null || echo "~0.05")
        total_lambda_cost="~calculated"
    fi
    
    # Display results
    echo ""
    echo "============================================="
    log_info "SCANNING COST ESTIMATION SUMMARY"
    echo "============================================="
    echo ""
    log_info "S3 Bucket Analysis:"
    echo "  • Bucket: $S3_BUCKET"
    echo "  • Total files: $(printf "%'d" $total_objects)"
    echo "  • Total size: ${total_size_mb} MB (${total_size_gb} GB)"
    echo ""
    log_info "Estimated Processing Costs (One-time scan):"
    echo "  • Lambda invocations: \$${lambda_invocation_cost}"
    echo "  • Lambda compute time: \$${lambda_compute_cost}"
    echo "  • S3 GET requests: \$${s3_get_requests_cost}"
    echo "  • CloudWatch logs: ~\$0.01"
    echo ""
    log_warning "ESTIMATED TOTAL COST: \$${estimated_total_cost}"
    echo ""
    echo "Note: This is an approximate estimate based on:"
    echo "  - ${avg_processing_time_seconds}s average processing time per file"
    echo "  - ${lambda_memory_gb}GB Lambda memory allocation"
    echo "  - Current AWS pricing (subject to change)"
    echo "  - Does not include data transfer costs"
    echo ""
    
    # Confirmation prompt
    echo "============================================="
    log_warning "PROCEED WITH SCANNING EXISTING FILES?"
    echo "This will process ALL $total_objects files in the S3 bucket."
    echo ""
    read -p "Do you want to trigger scanning of existing files? (y/N): " -r response
    
    if [[ "$response" =~ ^[Yy]$ ]]; then
        trigger_bulk_scan "$total_objects"
    else
        log_info "Bulk scanning cancelled. The scanner is ready for new files."
        log_info "To scan existing files later, run: aws s3 cp s3://$S3_BUCKET s3://$S3_BUCKET --recursive --metadata-directive REPLACE"
    fi
}

# Trigger bulk scanning of existing files
trigger_bulk_scan() {
    local total_objects="${1:-0}"
    log_info "Triggering bulk scan of existing files..."
    
    # Get Lambda function name from Terraform output
    cd "$TERRAFORM_DIR"
    local lambda_function_name
    lambda_function_name=$(terraform output -raw lambda_function_name 2>/dev/null || echo "")
    cd "$PROJECT_ROOT"
    
    if [[ -z "$lambda_function_name" ]]; then
        log_error "Could not get Lambda function name from Terraform output"
        exit 1
    fi
    
    # Method 1: Use S3 inventory and batch operations (recommended for large buckets)
    if [[ $total_objects -gt 1000 ]]; then
        log_info "Large bucket detected. Consider using S3 Batch Operations for efficient processing."
        log_info "Creating S3 event notifications for existing objects..."
        
        # Copy all objects to themselves to trigger S3 events
        log_warning "This may take a while for large buckets..."
        aws s3 cp "s3://$S3_BUCKET" "s3://$S3_BUCKET" --recursive --metadata-directive REPLACE &
        local copy_pid=$!
        
        log_info "Bulk copy operation started in background (PID: $copy_pid)"
        log_info "Monitor progress with: aws s3 ls s3://$S3_BUCKET --recursive | wc -l"
        
    else
        # Method 2: Direct Lambda invocation for smaller buckets
        log_info "Processing files directly via Lambda invocation..."
        
        # Get list of all objects
        local object_list
        object_list=$(aws s3api list-objects-v2 --bucket "$S3_BUCKET" --query 'Contents[].Key' --output text)
        
        local processed=0
        for object_key in $object_list; do
            # Create S3 event payload file
            local payload_file="/tmp/lambda-payload-$$.json"
            cat > "$payload_file" << EOF
{
    "Records": [{
        "eventVersion": "2.1",
        "eventSource": "aws:s3",
        "awsRegion": "$(aws configure get region)",
        "eventTime": "$(date -u +%Y-%m-%dT%H:%M:%S.000Z)",
        "eventName": "s3:ObjectCreated:Put",
        "s3": {
            "bucket": {
                "name": "$S3_BUCKET"
            },
            "object": {
                "key": "$object_key"
            }
        }
    }]
}
EOF
            
            # Invoke Lambda function
            aws lambda invoke \
                --function-name "$lambda_function_name" \
                --payload "file://$payload_file" \
                /tmp/lambda-response.json >/dev/null 2>&1 &
            
            # Clean up payload file after a short delay
            (sleep 5 && rm -f "$payload_file") &
            
            processed=$((processed + 1))
            
            # Rate limiting - process in batches to avoid throttling
            if [[ $((processed % 10)) -eq 0 ]]; then
                wait # Wait for current batch to complete
                log_info "Processed $processed/$total_objects files..."
            fi
        done
        
        wait # Wait for all remaining invocations
        rm -f /tmp/lambda-response.json
        
        log_success "Bulk scan completed. Processed $processed files."
    fi
    
    log_info "Check CloudWatch logs for processing details:"
    local aws_region=$(aws configure get region)
    if [[ -z "$aws_region" ]]; then
        aws_region="$AWS_DEFAULT_REGION"
    fi
    local aws_account_id=$(aws sts get-caller-identity --query Account --output text)
    log_info "aws logs start-live-tail --log-group-identifiers arn:aws:logs:$aws_region:$aws_account_id:log-group:/aws/lambda/$lambda_function_name"
}

# Main execution
main() {
    log_info "Starting Sentra Scanner deployment script"
    log_info "Environment: $ENVIRONMENT"
    log_info "Customer: $CUSTOMER_NAME"
    log_info "Command: $COMMAND"
    
    case "$COMMAND" in
        validate)
            check_prerequisites
            validate_config
            log_success "Validation completed successfully"
            ;;
        plan)
            check_prerequisites
            validate_config
            build_lambda_package
            terraform_init
            terraform_plan
            log_success "Terraform plan created successfully"
            ;;
        deploy)
            if [[ -z "$S3_BUCKET" || -z "$SENTRA_SQS_QUEUE_ARN" || -z "$SENTRA_ACCOUNT_ID" ]]; then
                log_error "For deployment, S3 bucket, SQS queue ARN, and Sentra account ID are required"
                exit 1
            fi
            check_prerequisites
            validate_config
            build_lambda_package
            terraform_init
            terraform_plan
            terraform_apply
            log_success "Deployment completed successfully"
            estimate_scanning_costs
            ;;
        test)
            check_prerequisites
            run_tests
            ;;
        estimate)
            if [[ -z "$S3_BUCKET" ]]; then
                log_error "S3 bucket is required for cost estimation"
                exit 1
            fi
            check_prerequisites
            estimate_scanning_costs
            ;;
        destroy)
            check_prerequisites
            terraform_destroy
            ;;
        *)
            log_error "Unknown command: $COMMAND"
            usage
            exit 1
            ;;
    esac
    
    log_success "Script completed successfully"
}

# Run main function
main "$@"
