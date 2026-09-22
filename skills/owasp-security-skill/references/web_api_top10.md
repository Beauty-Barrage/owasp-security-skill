# OWASP Web Top 10 (2021) & API Security Top 10 (2023) Reference

This reference outlines patterns, vulnerable anti-patterns, and secure implementations for .NET 8 / ASP.NET Core and React web applications.

---

## 1. A01:2021 – Broken Access Control / API1:2023 – Broken Object Level Authorization (BOLA)

### Risk Description
Attackers access unauthorized resources or records by manipulating IDs (IDOR), bypassing role checks, or navigating direct URLs without tenant/user boundary enforcement.

### Vulnerable Pattern (.NET 8):
```csharp
// VULNERABLE: Direct access using route ID without checking if current user owns the job
[HttpGet("api/job/{jobId}")]
public async Task<IActionResult> GetJob(int jobId)
{
    var job = await _db.Jobs.FindAsync(jobId);
    return Ok(job);
}
```

### Secure Pattern:
```csharp
// SECURE: Enforce authorization attribute and assert tenancy / specialist ownership
[HttpGet("api/job/{jobId}")]
[Authorize(Roles = "Specialist,Manager,Admin")]
public async Task<IActionResult> GetJob(int jobId)
{
    var currentUserId = User.GetUserId();
    var job = await _db.Jobs
        .Where(j => j.JobId == jobId && (j.SpecialistId == currentUserId || User.IsInRole("Admin")))
        .FirstOrDefaultAsync();

    if (job == null) return NotFound();
    return Ok(job);
}
```

---

## 2. A02:2021 – Cryptographic Failures / API8:2023 – Security Misconfiguration

### Risk Description
Sensitive data (passwords, tokens, compensation, PII) transmitted in cleartext, stored with weak or static encryption, or hashed using legacy algorithms (MD5, SHA1, static salts).

### Key Auditing Points:
1. **Password Hashing:** Passwords must be hashed using PBKDF2 with SHA-256 (minimum 100,000 iterations), Argon2id, or BCrypt. A static or application-wide salt is a critical vulnerability.
2. **Data-at-Rest:** Secrets in configuration files must be moved to Azure Key Vault (ADR-001). Connection strings must use Managed Identity or Azure Key Vault references.
3. **Data Protection Key Ring:** ASP.NET Core Data Protection must use distributed storage (Azure Blob Storage + Azure Key Vault encryption) when hosted on multi-instance clusters.

---

## 3. A03:2021 – Injection / API3:2023 – Broken Object Property Level Authorization

### Risk Description
Untrusted input evaluated directly by database interpreters (SQLi), operating system commands, or unescaped HTML renderers (XSS).

### Vulnerable Pattern (Dynamic SQL / ADO.NET):
```csharp
// VULNERABLE: String concatenation into SQL query
string query = "SELECT * FROM Users WHERE UserName = '" + input + "'";
var users = db.Database.SqlQuery<User>(query).ToList();
```

### Secure Pattern:
```csharp
// SECURE: Parameterized query
var users = await db.Users
    .FromSqlInterpolated($"SELECT * FROM Users WHERE UserName = {input}")
    .ToListAsync();
```

### Mass Assignment Defense (.NET 8):
Never bind raw database entities directly in controller parameters. Always bind to dedicated, strongly-typed ViewModels or Request DTOs to prevent unauthorized overwrites of privileged fields (e.g., `IsAdmin`, `Role`, `Rate`).

---

## 4. A05:2021 – Security Misconfiguration / API7:2023 – Server-Side Request Forgery (SSRF)

### Key Auditing Points:
1. **Error Handling:** Ensure `app.UseDeveloperExceptionPage()` is disabled in production. Unhandled exceptions must be caught by custom filters (`HttpResponseExceptionFilter`) or mapped error pages without leaking stack traces or connection strings.
2. **Security Headers:** Enforce:
   - `Strict-Transport-Security: max-age=31536000; includeSubDomains`
   - `X-Content-Type-Options: nosniff`
   - `X-Frame-Options: DENY` or `SAMEORIGIN`
   - `Content-Security-Policy` appropriate for SPA bundles.
3. **CORS:** Ensure `WithOrigins(...)` explicitly whitelists trusted domains; never combine `AllowAnyOrigin()` with `AllowCredentials()`.
4. **SSRF:** Outbound HTTP requests to user-supplied URLs (e.g., webhooks, logo downloads) must validate against private IP address ranges (RFC 1918 / Azure metadata endpoint `169.254.169.254`).

---

## 5. A07:2021 – Identification & Authentication Failures / API2:2023 – Broken Authentication

### Key Auditing Points:
1. **Token Invalidation:** When a session token expires, the API must return `HTTP 401 Unauthorized`. Returning `HTTP 500` breaks client refresh loops and traps users in invalid states.
2. **Session Hijacking:** Ensure session cookies carry `HttpOnly; Secure; SameSite=Lax` (or `Strict`).
3. **Brute Force Defense:** Enforce account lockout policies or rate limiting (`AspNetCoreRateLimit`) on `/Login` and `/api/login` endpoints.
