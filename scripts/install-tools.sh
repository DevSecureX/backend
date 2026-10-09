#!/bin/bash
set -e

PROFILE=${BUILD_PROFILE:-core}
INSTALL_JAVA_TOOLS=${INSTALL_JAVA_TOOLS:-false}
INSTALL_GO_TOOLS=${INSTALL_GO_TOOLS:-true}
INSTALL_DOTNET_TOOLS=${INSTALL_DOTNET_TOOLS:-false}
INSTALL_RUBY_TOOLS=${INSTALL_RUBY_TOOLS:-false}
INSTALL_PHP_TOOLS=${INSTALL_PHP_TOOLS:-false}

echo "Installing security tools with profile: $PROFILE"

# Core tools (always installed) - ~800MB
install_core_tools() {
    echo "Installing core security tools..."
    
    # Core Python security tools
    pip install --no-cache-dir semgrep bandit safety checkov
    
    # Lightweight binary tools
    echo "Installing TruffleHog..."
    curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin
    
    echo "Installing GitLeaks..."
    wget -O /tmp/gitleaks.tar.gz "https://github.com/gitleaks/gitleaks/releases/download/v8.28.0/gitleaks_8.28.0_linux_x64.tar.gz"
    tar -xzf /tmp/gitleaks.tar.gz -C /tmp/
    mv /tmp/gitleaks /usr/local/bin/gitleaks
    chmod +x /usr/local/bin/gitleaks
    rm -f /tmp/gitleaks.tar.gz
    
    echo "Installing Trivy..."
    curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
    
    
    # CPP check (lightweight C++ analyzer)
    echo "CPP check already installed via system packages"
}

# JavaScript tools installation
install_js_tools() {
    echo "Installing JavaScript security tools..."
    npm install -g eslint@9.32.0 eslint-plugin-security@3.0.1 @eslint/eslintrc@3.1.0
    
    # Create symlink for compatibility
    mkdir -p /usr/local/lib/node_modules/@eslint
    ln -sf /usr/local/lib/node_modules/eslint-plugin-security /usr/local/lib/node_modules/@eslint/eslint-plugin-security || true
}

# Go tools installation (conditional) - ~200MB
install_go_tools() {
    if [ "$INSTALL_GO_TOOLS" = "true" ]; then
        echo "Installing Go runtime and tools..."
        
        # Install Go runtime
        wget -O /tmp/go.tar.gz "https://golang.org/dl/go1.21.6.linux-amd64.tar.gz"
        tar -xzf /tmp/go.tar.gz -C /usr/local
        ln -s /usr/local/go/bin/go /usr/local/bin/go
        ln -s /usr/local/go/bin/gofmt /usr/local/bin/gofmt
        rm -f /tmp/go.tar.gz
        
        # Install Gosec
        echo "Installing Gosec..."
        wget -O /tmp/gosec.tar.gz "https://github.com/securego/gosec/releases/download/v2.22.7/gosec_2.22.7_linux_amd64.tar.gz"
        tar -xzf /tmp/gosec.tar.gz -C /tmp/
        mv /tmp/gosec /usr/local/bin/gosec
        chmod +x /usr/local/bin/gosec
        rm -f /tmp/gosec.tar.gz
        
        echo "Go tools installed successfully"
    else
        echo "Skipping Go tools installation"
    fi
}

# Java tools installation (conditional) - ~500MB
install_java_tools() {
    if [ "$INSTALL_JAVA_TOOLS" = "true" ]; then
        echo "Installing Java tools..."
        
        # Install SpotBugs
        wget https://repo1.maven.org/maven2/com/github/spotbugs/spotbugs/4.9.3/spotbugs-4.9.3.tgz
        tar -xzf spotbugs-4.9.3.tgz -C /opt
        ln -s /opt/spotbugs-4.9.3/bin/spotbugs /usr/local/bin/spotbugs
        chmod +x /usr/local/bin/spotbugs
        rm -f spotbugs-4.9.3.tgz
        
        echo "Java tools installed successfully"
    else
        echo "Skipping Java tools installation"
    fi
}

# .NET tools installation (conditional) - ~800MB
install_dotnet_tools() {
    ARCH=$(dpkg --print-architecture)
    if [ "$INSTALL_DOTNET_TOOLS" = "true" ] && [ "$ARCH" = "amd64" ]; then
        echo "Installing .NET tools..."
        
        # Install .NET SDK (already handled in system dependencies if needed)
        # Install Roslynator
        dotnet tool install -g Roslynator.DotNet.Cli || echo "Roslynator installation failed, continuing..."
        
        echo ".NET tools installed successfully"
    else
        echo "Skipping .NET tools installation (not supported on $ARCH or disabled)"
    fi
}

# Ruby tools installation (conditional) - ~100MB
install_ruby_tools() {
    if [ "$INSTALL_RUBY_TOOLS" = "true" ]; then
        echo "Installing Ruby tools..."
        
        # Install Brakeman
        gem install brakeman --version 7.1.0
        
        echo "Ruby tools installed successfully"
    else
        echo "Skipping Ruby tools installation"
    fi
}

# PHP tools installation (conditional) - ~150MB
install_php_tools() {
    if [ "$INSTALL_PHP_TOOLS" = "true" ]; then
        echo "Installing PHP tools..."
        
        # Install Psalm
        composer global require vimeo/psalm --prefer-dist
        
        echo "PHP tools installed successfully"
    else
        echo "Skipping PHP tools installation"
    fi
}

# Tool verification function
verify_tools() {
    echo "Verifying installed tools..."
    
    # Core tools
    echo "=== Core Tools ==="
    semgrep --version || echo "WARNING: Semgrep not available"
    bandit --version || echo "WARNING: Bandit not available"
    safety --version || echo "WARNING: Safety not available"
    checkov --version || echo "WARNING: Checkov not available"
    trivy --version || echo "WARNING: Trivy not available"
    trufflehog --version || echo "WARNING: TruffleHog not available"
    gitleaks version || echo "WARNING: GitLeaks not available"
    cppcheck --version || echo "WARNING: CPPCheck not available"
    
    # JavaScript tools
    echo "=== JavaScript Tools ==="
    eslint --version || echo "WARNING: ESLint not available"
    
    # Conditional tools
    echo "=== Conditional Tools ==="
    if command -v go &> /dev/null; then
        go version
        gosec --version || echo "WARNING: Gosec not available"
    else
        echo "Go tools not installed"
    fi
    
    if command -v spotbugs &> /dev/null; then
        echo "SpotBugs installed"
    else
        echo "SpotBugs not installed"
    fi
    
    if command -v roslynator &> /dev/null; then
        roslynator --version || echo "WARNING: Roslynator not available"
    else
        echo "Roslynator not installed"
    fi
    
    if command -v brakeman &> /dev/null; then
        brakeman --version || echo "WARNING: Brakeman not available"
    else
        echo "Brakeman not installed"
    fi
    
    if command -v psalm &> /dev/null; then
        psalm --version || echo "WARNING: Psalm not available"
    else
        echo "Psalm not installed"
    fi
    
    echo "Tool verification completed"
}

# Main installation logic based on profile
case $PROFILE in
    "minimal")
        echo "Installing minimal profile tools..."
        install_core_tools
        install_js_tools
        ;;
    "core") 
        echo "Installing core profile tools..."
        install_core_tools
        install_js_tools
        install_go_tools
        install_ruby_tools
        ;;
    "full")
        echo "Installing full profile tools..."
        install_core_tools
        install_js_tools
        install_go_tools
        install_java_tools
        install_dotnet_tools
        install_ruby_tools
        install_php_tools
        ;;
    *)
        echo "Unknown profile: $PROFILE, defaulting to core"
        install_core_tools
        install_js_tools
        install_go_tools
        install_ruby_tools
        ;;
esac

# Verify installations
verify_tools

echo "Security tools installation completed for profile: $PROFILE"