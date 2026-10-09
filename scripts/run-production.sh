#!/bin/bash
# DevSecureX Production Environment Deployment
# This script deploys to production (Render + Firebase) using external services

set -e  # Exit on any error

echo "🚀 DevSecureX - Production Deployment"
echo "====================================="
echo ""

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

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

# Check required tools
check_requirements() {
    local missing_tools=()
    
    if ! command -v git &> /dev/null; then
        missing_tools+=("git")
    fi
    
    if ! command -v firebase &> /dev/null; then
        missing_tools+=("firebase-tools")
    fi
    
    if [ ${#missing_tools[@]} -ne 0 ]; then
        print_error "Missing required tools: ${missing_tools[*]}"
        echo "Install with:"
        for tool in "${missing_tools[@]}"; do
            case $tool in
                "firebase-tools")
                    echo "  npm install -g firebase-tools"
                    ;;
                *)
                    echo "  Install $tool from official website"
                    ;;
            esac
        done
        exit 1
    fi
}

# Verify environment variables
check_environment() {
    print_status "🔍 Checking environment configuration..."
    
    local required_vars=("GITHUB_CLIENT_ID" "GOOGLE_CLIENT_ID" "RAZORPAY_KEY_ID")
    local missing_vars=()
    
    for var in "${required_vars[@]}"; do
        if [ -z "${!var}" ]; then
            missing_vars+=("$var")
        fi
    done
    
    if [ ${#missing_vars[@]} -ne 0 ]; then
        print_error "Missing environment variables: ${missing_vars[*]}"
        print_warning "Please set these in your .env file and try again"
        return 1
    fi
    
    print_success "✅ Environment variables are set"
    return 0
}

# Deploy backend to Render
deploy_backend() {
    print_status "🏗️  Deploying Backend to Render..."
    print_warning "This will use:"
    echo "  • Render.com hosting"
    echo "  • Neon PostgreSQL (production)"
    echo "  • Upstash Redis (production - costs money!)"
    echo "  • Custom domain: api.devsecurex.com"
    echo "  • Background workers: DISABLED (to save Redis costs)"
    echo ""
    
    read -p "Continue with backend deployment? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_status "Backend deployment cancelled."
        return 1
    fi
    
    # Check if there are uncommitted changes
    if ! git diff --quiet || ! git diff --cached --quiet; then
        print_status "📝 Committing changes..."
        git add .
        git commit -m "Production deployment: Updated configurations for api.devsecurex.com

🔧 Changes:
- Fixed GitHub OAuth test data issue
- Disabled background Redis workers to prevent costs
- Updated URLs to use custom domain
- Environment configured for production" || true
    fi
    
    # Push to trigger Render deployment
    print_status "🚀 Pushing to trigger Render auto-deployment..."
    git push origin main
    
    print_success "✅ Backend deployment triggered!"
    print_status "🔗 Monitor deployment at: https://dashboard.render.com"
    print_warning "⏳ Wait for deployment to complete before proceeding to frontend"
}

# Deploy frontend to Firebase
deploy_frontend() {
    print_status "🌐 Deploying Frontend to Firebase..."
    
    if [ ! -d "frontend" ]; then
        print_error "Frontend directory not found!"
        return 1
    fi
    
    cd frontend
    
    print_status "📦 Installing frontend dependencies..."
    npm install
    
    print_status "🏗️  Building frontend for production..."
    npm run build || {
        print_error "Frontend build failed!"
        cd ..
        return 1
    }
    
    print_status "🔥 Deploying to Firebase Hosting..."
    firebase deploy --only hosting || {
        print_error "Firebase deployment failed!"
        cd ..
        return 1
    }
    
    cd ..
    print_success "✅ Frontend deployed successfully!"
}

# Main deployment flow
main() {
    print_warning "⚠️  PRODUCTION DEPLOYMENT WARNING"
    echo "This will deploy to production services that may incur costs:"
    echo "  • Render hosting (has free tier limits)"
    echo "  • Neon PostgreSQL (has free tier limits)"  
    echo "  • Upstash Redis (background workers DISABLED to prevent costs)"
    echo "  • Firebase Hosting (free tier)"
    echo ""
    
    read -p "Do you want to proceed with production deployment? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_status "Production deployment cancelled."
        exit 0
    fi
    
    # Check requirements
    check_requirements
    
    # Load environment variables
    if [ -f ".env" ]; then
        export $(grep -v '^#' .env | xargs)
    fi
    
    # Check environment
    if ! check_environment; then
        exit 1
    fi
    
    # Deploy backend
    if deploy_backend; then
        print_status "⏳ Waiting for backend deployment (30 seconds)..."
        sleep 30
        
        # Test backend
        print_status "🧪 Testing backend deployment..."
        if curl -s https://api.devsecurex.com/health > /dev/null 2>&1; then
            print_success "✅ Backend is responding"
            
            # Deploy frontend
            deploy_frontend
            
            print_success "🎉 PRODUCTION DEPLOYMENT COMPLETE!"
            echo ""
            echo "🌐 Production URLs:"
            echo "  • Frontend: https://app.devsecurex.com"
            echo "  • Backend API: https://api.devsecurex.com"
            echo "  • API Docs: https://api.devsecurex.com/docs"
            echo ""
            print_warning "💰 Remember: Monitor your usage to avoid unexpected costs!"
            
        else
            print_error "❌ Backend deployment failed or still starting"
            print_status "Check Render dashboard for deployment status"
        fi
    fi
}

# Run main function
main