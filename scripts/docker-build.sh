#!/bin/bash
set -e

# DevSecureX Docker Build Automation Script
# Supports multiple build profiles: minimal, core, full

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Help function
show_help() {
    cat << EOF
DevSecureX Docker Build Script

Usage: $0 [PROFILE] [OPTIONS]

PROFILES:
  minimal    Build minimal profile (~1.5GB) - Basic security scanning
  core       Build core profile (~2.3GB) - Comprehensive scanning (default)
  full       Build full profile (~4.0GB) - All security tools

OPTIONS:
  --no-cache     Build without Docker cache
  --clean        Clean existing images before building
  --push         Push to registry after successful build
  --test         Run basic tests after building
  --help, -h     Show this help message

EXAMPLES:
  $0                           # Build core profile
  $0 minimal                   # Build minimal profile
  $0 full --no-cache          # Build full profile without cache
  $0 core --clean --test      # Build core, clean first, then test

BUILD PROFILES:
  minimal: Python, JavaScript, Secrets, Infrastructure basics
  core:    All minimal + Go, Ruby, enhanced rules
  full:    All tools + Java, .NET, PHP, AI analysis, analytics
EOF
}

# Parse arguments
PROFILE=${1:-core}
NO_CACHE=""
CLEAN=false
PUSH=false
TEST=false

# Parse options
while [[ $# -gt 0 ]]; do
    case $1 in
        --no-cache)
            NO_CACHE="--no-cache"
            shift
            ;;
        --clean)
            CLEAN=true
            shift
            ;;
        --push)
            PUSH=true
            shift
            ;;
        --test)
            TEST=true
            shift
            ;;
        --help|-h)
            show_help
            exit 0
            ;;
        minimal|core|full)
            PROFILE=$1
            shift
            ;;
        *)
            print_error "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

# Validate profile
case $PROFILE in
    minimal|core|full)
        ;;
    *)
        print_error "Invalid profile: $PROFILE. Must be minimal, core, or full"
        exit 1
        ;;
esac

print_status "Starting DevSecureX Docker build with profile: $PROFILE"

# Check required files
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

print_status "Project root: $PROJECT_ROOT"

# Check if we're in the right directory
if [[ ! -f "$PROJECT_ROOT/Dockerfile" ]]; then
    print_error "Dockerfile not found. Please run this script from the project root or ensure Dockerfile exists."
    exit 1
fi

if [[ ! -f "$PROJECT_ROOT/.env.docker.$PROFILE" ]]; then
    print_error "Environment file .env.docker.$PROFILE not found."
    exit 1
fi

# Clean existing images if requested
if [[ "$CLEAN" == "true" ]]; then
    print_status "Cleaning existing DevSecureX images..."
    
    # Remove containers
    docker ps -a --filter="name=devsecurex-backend" --format="{{.ID}}" | xargs -r docker rm -f 2>/dev/null || true
    
    # Remove images
    docker images --filter="reference=devsecurex*" --format="{{.ID}}" | xargs -r docker rmi -f 2>/dev/null || true
    
    print_success "Cleanup completed"
fi

# Set environment based on profile
print_status "Loading environment configuration for $PROFILE profile..."
cp "$PROJECT_ROOT/.env.docker.$PROFILE" "$PROJECT_ROOT/.env.docker.active"

# Export environment variables for docker-compose
set -a
source "$PROJECT_ROOT/.env.docker.$PROFILE"
set +a

# Display build configuration
print_status "Build Configuration:"
echo "  Profile: $PROFILE"
echo "  Java Tools: ${INSTALL_JAVA_TOOLS:-false}"
echo "  Go Tools: ${INSTALL_GO_TOOLS:-false}" 
echo "  .NET Tools: ${INSTALL_DOTNET_TOOLS:-false}"
echo "  Ruby Tools: ${INSTALL_RUBY_TOOLS:-false}"
echo "  PHP Tools: ${INSTALL_PHP_TOOLS:-false}"
echo "  Requirements: ${REQUIREMENTS_FILE:-requirements-core.txt}"
echo "  Build Args: $NO_CACHE"

# Calculate expected size ranges
case $PROFILE in
    minimal)
        print_status "Expected image size: ~1.5GB (Basic scanning tools)"
        ;;
    core)
        print_status "Expected image size: ~2.3GB (Comprehensive scanning)"
        ;;
    full)
        print_status "Expected image size: ~4.0GB (All security tools + analytics)"
        ;;
esac

# Start build with timing
print_status "Starting Docker build..."
BUILD_START=$(date +%s)

# Build command
BUILD_CMD="docker-compose -f $PROJECT_ROOT/docker-compose.yml --env-file $PROJECT_ROOT/.env.docker.active build"

if [[ -n "$NO_CACHE" ]]; then
    BUILD_CMD="$BUILD_CMD --no-cache"
fi

print_status "Executing: $BUILD_CMD"

# Execute build
if $BUILD_CMD; then
    BUILD_END=$(date +%s)
    BUILD_DURATION=$((BUILD_END - BUILD_START))
    
    print_success "Build completed in ${BUILD_DURATION} seconds"
    
    # Tag the build
    IMAGE_NAME="devsecurex-backend-backup-backend:latest"
    NEW_TAG="devsecurex-backend:$PROFILE"
    
    print_status "Tagging image: $IMAGE_NAME -> $NEW_TAG"
    docker tag "$IMAGE_NAME" "$NEW_TAG"
    
    # Show image size
    print_status "Final image information:"
    docker images "$NEW_TAG" --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}\t{{.CreatedAt}}"
    
    # Get actual size for comparison
    ACTUAL_SIZE=$(docker images "$NEW_TAG" --format "{{.Size}}")
    print_success "Build completed successfully!"
    print_success "Image: $NEW_TAG"
    print_success "Size: $ACTUAL_SIZE"
    
    # Run basic tests if requested
    if [[ "$TEST" == "true" ]]; then
        print_status "Running basic container tests..."
        
        # Test container startup
        print_status "Testing container startup..."
        if docker run --rm -d --name "test-$PROFILE" "$NEW_TAG" sleep 30 > /dev/null; then
            sleep 5
            
            # Check if container is running
            if docker ps --filter="name=test-$PROFILE" --format="{{.Names}}" | grep -q "test-$PROFILE"; then
                print_success "Container startup test passed"
                docker stop "test-$PROFILE" > /dev/null
            else
                print_error "Container startup test failed"
            fi
        else
            print_error "Failed to start test container"
        fi
        
        # Test tool availability if we can
        print_status "Testing tool availability..."
        docker run --rm "$NEW_TAG" python -c "
import sys
sys.path.append('/app')
try:
    from scans.scanner_engine import ScannerEngine
    engine = ScannerEngine()
    available_tools = engine._detect_available_tools()
    total_tools = len(available_tools)
    available_count = sum(1 for available in available_tools.values() if available)
    print(f'Tool availability: {available_count}/{total_tools} tools available')
    if available_count > 0:
        print('✅ Tool detection test passed')
        sys.exit(0)
    else:
        print('❌ No tools available')
        sys.exit(1)
except Exception as e:
    print(f'❌ Tool detection test failed: {e}')
    sys.exit(1)
" && print_success "Tool availability test passed" || print_warning "Tool availability test had issues"
    fi
    
    # Push to registry if requested
    if [[ "$PUSH" == "true" ]]; then
        print_status "Pushing to registry..."
        if docker push "$NEW_TAG"; then
            print_success "Successfully pushed $NEW_TAG to registry"
        else
            print_error "Failed to push to registry"
            exit 1
        fi
    fi
    
    # Cleanup temporary files
    rm -f "$PROJECT_ROOT/.env.docker.active"
    
    print_success "Build process completed successfully!"
    print_status "To use this build:"
    print_status "  docker run --rm $NEW_TAG"
    print_status "  docker-compose up (with BUILD_PROFILE=$PROFILE)"
    
else
    BUILD_END=$(date +%s)
    BUILD_DURATION=$((BUILD_END - BUILD_START))
    
    print_error "Build failed after ${BUILD_DURATION} seconds"
    
    # Cleanup on failure
    rm -f "$PROJECT_ROOT/.env.docker.active"
    
    print_error "Build troubleshooting tips:"
    print_error "  1. Check Docker daemon is running"
    print_error "  2. Ensure sufficient disk space (>10GB free)"
    print_error "  3. Try --clean to remove cached layers"
    print_error "  4. Check network connectivity for package downloads"
    print_error "  5. Review build logs above for specific errors"
    
    exit 1
fi