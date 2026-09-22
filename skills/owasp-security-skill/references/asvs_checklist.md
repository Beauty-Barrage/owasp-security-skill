# OWASP ASVS v4.0 Level 2 Verification Checklist

The OWASP Application Security Verification Standard (ASVS) Level 2 is designed for applications handling sensitive B2B/B2C transactions, user PII, and financial data (such as enterprise SaaS and workforce platforms).

---

## V1: Architecture, Design and Threat Modeling
* [ ] **V1.1.2:** All application components are identified and documented, including third-party dependencies.
* [ ] **V1.2.2:** Multi-tenant architecture guarantees strict tenant isolation at the data access layer.
* [ ] **V1.4.1:** All untrusted input sources (headers, forms, query strings, cookies) are identified and sanitized before processing.

---

## V2: Authentication Verification
* [ ] **V2.1.1:** Passwords are at least 8 characters long and checked against common breached lists.
* [ ] **V2.1.2:** Multi-Factor Authentication (MFA) is strictly enforced for administrative roles (Entra ID Conditional Access).
* [ ] **V2.4.1:** Failed authentication attempts are rate-limited and do not reveal whether the username or password was incorrect.
* [ ] **V2.8.1:** Session tokens are transmitted exclusively over TLS and carry `HttpOnly`, `Secure`, and `SameSite` flags.

---

## V3: Session Management Verification
* [ ] **V3.2.1:** Session tokens are cryptographically random with sufficient entropy (e.g. 128-bit GUIDs or CSPRNG).
* [ ] **V3.3.1:** Logout immediately invalidates server-side session records and clears client session cookies.
* [ ] **V3.7.1:** Expired session tokens return unambiguous `HTTP 401 Unauthorized` responses to client applications.

---

## V4: Access Control Verification
* [ ] **V4.1.1:** The principle of least privilege is enforced: users can only perform operations explicitly permitted by their assigned role.
* [ ] **V4.1.3:** Contextual authorization checks prevent Insecure Direct Object References (IDOR).
* [ ] **V4.2.1:** Sensitive administrative endpoints are inaccessible to non-administrative roles at the router/controller level.

---

## V5: Validation, Sanitization and Encoding
* [ ] **V5.1.2:** Server-side validation is strictly enforced; client-side validation is treated solely as a UX convenience.
* [ ] **V5.2.2:** Structured data (JSON, XML) deserialization enforces strict schema typing to prevent prototype pollution or gadget chain execution.
* [ ] **V5.3.1:** Output encoding is applied contextually before user data is rendered in HTML, JavaScript, or attributes to prevent XSS.

---

## V6: Stored Cryptography Verification
* [ ] **V6.2.1:** All cryptographic algorithms adhere to modern industry standards (AES-GCM, HMAC-SHA256, RSA-OAEP, PBKDF2/Argon2).
* [ ] **V6.2.5:** Cryptographic keys and secrets are loaded from dedicated hardware security modules or key vaults (Azure Key Vault).
* [ ] **V6.4.1:** Secrets are never hardcoded in source code, configuration files committed to VCS, or client bundles.

---

## V8: Data Protection Verification
* [ ] **V8.2.1:** Sensitive data (compensation, SSN, bank details) is protected with field-level encryption or role-based column filtering.
* [ ] **V8.3.1:** Sensitive data is never written to application logs, console logs, or client-accessible diagnostics streams.
* [ ] **V8.3.4:** Backups and point-in-time restore policies are active with immutability/change-feed protections.
