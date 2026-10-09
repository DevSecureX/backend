#!/bin/sh

echo "=== DevSecureX Security Tools Verification (Container Mode) ==="
echo "Verifying all security tools in existing container..."
echo

# Counter for successful tools
TOOLS_VERIFIED=0
TOOLS_FAILED=0

# Function to verify a tool
verify_tool() {
    local tool_name="$1"
    local test_command="$2"
    echo -n "Checking $tool_name: "
    
    if eval "$test_command" >/dev/null 2>&1; then
        echo "✅ WORKING"
        TOOLS_VERIFIED=$((TOOLS_VERIFIED + 1))
    else
        echo "❌ FAILED"
        TOOLS_FAILED=$((TOOLS_FAILED + 1))
    fi
}

echo "=== Core Security Tools (Python-based) ==="
verify_tool "Semgrep" "semgrep --version"
verify_tool "Bandit" "bandit --version"
verify_tool "Safety" "safety --version"
verify_tool "Checkov" "checkov --version"

echo
echo "=== Binary Security Tools ==="
verify_tool "TruffleHog" "trufflehog --version"
verify_tool "GitLeaks" "gitleaks version"
verify_tool "Trivy" "trivy --version"
verify_tool "CPPCheck" "cppcheck --version"

echo
echo "=== JavaScript Tools ==="
verify_tool "ESLint" "eslint --version"
verify_tool "ESLint Security Plugin" "npm list -g eslint-plugin-security"

echo
echo "=== Go Tools ==="
verify_tool "Go Runtime" "go version"
verify_tool "Gosec" "gosec --version"

echo
echo "=== Java Tools ==="
verify_tool "SpotBugs" "test -f /opt/spotbugs-*/bin/spotbugs"

echo
echo "=== Ruby Tools ==="
verify_tool "Brakeman" "brakeman --version"

echo
echo "=== PHP Tools ==="
verify_tool "Psalm" "test -f ~/.composer/vendor/bin/psalm || psalm --version"

echo
echo "=== VERIFICATION SUMMARY ==="
echo "✅ Tools verified: $TOOLS_VERIFIED"
echo "❌ Tools failed: $TOOLS_FAILED"
echo "📊 Total tools: 14"

if [ $TOOLS_VERIFIED -ge 11 ]; then
    echo "🎉 SUCCESS: Most security tools are working correctly!"
    exit 0
else
    echo "⚠️  WARNING: $TOOLS_FAILED tools failed verification"
    exit 1
fi