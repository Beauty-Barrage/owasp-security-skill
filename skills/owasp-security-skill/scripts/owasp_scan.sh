#!/usr/bin/env bash
# ==============================================================================
# OWASP Static Heuristic Scanner
# Scans source code for common OWASP Top 10 and Mobile Top 10 vulnerability patterns.
# Usage: ./owasp_scan.sh [target_directory]
# ==============================================================================

set -eo pipefail

TARGET_DIR="${1:-.}"
SCAN_DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

echo "================================================================================"
echo " OWASP Static Heuristic Code Scanner"
echo " Target: $TARGET_DIR"
echo " Date:   $SCAN_DATE"
echo "================================================================================"

# Standard directory exclusions
EXCLUDES="--exclude-dir=.git --exclude-dir=node_modules --exclude-dir=bin --exclude-dir=obj --exclude-dir=dist --exclude-dir=Build --exclude-dir=Content/Build"

print_header() {
    local category="$1"
    local title="$2"
    echo ""
    echo "--------------------------------------------------------------------------------"
    echo " [$category] $title"
    echo "--------------------------------------------------------------------------------"
}

scan_pattern() {
    local severity="$1"
    local description="$2"
    local pattern="$3"
    local file_pattern="$4"

    local extra_args=""
    if [ -n "$file_pattern" ]; then
        extra_args="--include=$file_pattern"
    fi

    local matches
    matches=$(grep -rnEI $EXCLUDES $extra_args "$pattern" "$TARGET_DIR" 2>/dev/null || true)

    if [ -n "$matches" ]; then
        local count
        count=$(echo "$matches" | wc -l | tr -d ' ')
        echo " [!] $severity: $description ($count occurrences found)"
        echo "$matches" | head -n 5 | sed 's/^/     /'
        if [ "$count" -gt 5 ]; then
            echo "     ... and $((count - 5)) more matches"
        fi
    else
        echo " [OK] $description (0 findings)"
    fi
}

# ------------------------------------------------------------------------------
# Category A02: Cryptographic Failures & Hardcoded Credentials
# ------------------------------------------------------------------------------
print_header "A02:2021" "Cryptographic Failures & Hardcoded Secrets"
scan_pattern "CRITICAL" "Hardcoded Passwords/Secrets in Assignments" '(password|secret|apikey|api_key)[[:space:]]*=[[:space:]]*["\x27][^"\x27]{6,}["\x27]' "*.*"
scan_pattern "HIGH" "Legacy Hashing Algorithms (MD5 / SHA1)" '\b(MD5|SHA1|DESCryptoServiceProvider|TripleDESCryptoServiceProvider)\b' "*.cs"
scan_pattern "HIGH" "Static or Hardcoded Salts / Keys" 'static[[:space:]]+(byte\[\]|string)[[:space:]]+.*(salt|key|iv|secret)' "*.cs"

# ------------------------------------------------------------------------------
# Category A03: Injection & Raw SQL Queries
# ------------------------------------------------------------------------------
print_header "A03:2021" "Injection & Dynamic SQL"
scan_pattern "HIGH" "String Concatenation in SQL Query" '\.(SqlQuery|ExecuteSqlCommand|FromSqlRaw)\([^)]*\+[^)]*\)' "*.cs"
scan_pattern "MEDIUM" "Dynamic SQL Execution in Stored Procedures" 'EXEC[[:space:]]*\([[:space:]]*@' "*.sql"
scan_pattern "MEDIUM" "Unsanitized dangerouslySetInnerHTML in React" 'dangerouslySetInnerHTML' "*.tsx"

# ------------------------------------------------------------------------------
# Category A01 / A07: Access Control & Authentication Failures
# ------------------------------------------------------------------------------
print_header "A01/A07:2021" "Broken Access Control & Session Handling"
scan_pattern "HIGH" "AllowAnonymous on Sensitive Endpoints" '\[AllowAnonymous\]' "*Controller.cs"
scan_pattern "HIGH" "Direct HttpResponseException(Unauthorized) without Filter" 'throw[[:space:]]+new[[:space:]]+HttpResponseException\(HttpStatusCode\.Unauthorized\)' "*.cs"
scan_pattern "MEDIUM" "Missing Anti-Forgery Validation on POST Actions" '\[HttpPost\]' "*Controller.cs"

# ------------------------------------------------------------------------------
# Category A05: Security Misconfigurations
# ------------------------------------------------------------------------------
print_header "A05:2021" "Security Misconfiguration"
scan_pattern "HIGH" "Permissive CORS (AllowAnyOrigin)" '\.AllowAnyOrigin\(\)' "*.cs"
scan_pattern "MEDIUM" "Disabled Request Size Limits" '\[DisableRequestSizeLimit\]' "*.cs"
scan_pattern "HIGH" "iOS NSAllowsArbitraryLoads Enabled" '<key>NSAllowsArbitraryLoads</key>[[:space:]]*<true/>' "*.plist"

# ------------------------------------------------------------------------------
# Category Mobile M9: Insecure Client Storage
# ------------------------------------------------------------------------------
print_header "Mobile M9" "Insecure Client-side Storage"
scan_pattern "HIGH" "AsyncStorage Storing Auth / Token Data" 'AsyncStorage\.(setItem|getItem)\([^\)]*(token|password|auth|secret)' "*.ts*"

echo ""
echo "================================================================================"
echo " Scan Complete. Review any [CRITICAL] or [HIGH] findings for source-to-sink flow."
echo "================================================================================"
