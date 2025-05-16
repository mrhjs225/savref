/**
 * @name Java Security Patterns Detection
 * @description Detects common security vulnerability patterns in Java code
 * @kind problem
 * @problem.severity error
 * @precision medium
 * @id java/security-patterns
 * @tags security
 */

import java
import semmle.code.java.security.SqlInjectionQuery
import semmle.code.java.security.XssQuery
import semmle.code.java.security.PathInjectionQuery
import semmle.code.java.security.CommandInjectionQuery
import semmle.code.java.security.UnsafeDeserializationQuery
import semmle.code.java.security.PasswordInConfigurationFileQuery
import semmle.code.java.security.XPathInjectionQuery
import semmle.code.java.security.RequestForgeryQuery
import semmle.code.java.security.ExternalAPIsQuery
import semmle.code.java.security.LdapInjectionQuery
import semmle.code.java.security.TaintedPathQuery
import semmle.code.java.security.InsecureRandomQuery
import semmle.code.java.security.CryptographyQuery

from ASTNode node, string message, string pattern_id, string severity
where
  // SQL Injection
  exists(SqlInjection sqlInj |
    node = sqlInj.getVulnerableExpr() and
    message = "SQL Injection vulnerability: unsanitized user input used in SQL query" and
    pattern_id = "CWE-89" and
    severity = "HIGH"
  )
  or
  // Cross-site Scripting (XSS)
  exists(XSS xss |
    node = xss.getVulnerableExpr() and
    message = "Cross-site Scripting (XSS) vulnerability: unsanitized input written to web page" and
    pattern_id = "CWE-79" and
    severity = "HIGH"
  )
  or
  // Path Traversal / Path Injection
  exists(PathInjection pathInj |
    node = pathInj.getVulnerableExpr() and
    message = "Path Traversal vulnerability: unsanitized user input used in file path" and
    pattern_id = "CWE-22" and
    severity = "HIGH"
  )
  or
  // Command Injection
  exists(CommandInjection cmdInj |
    node = cmdInj.getVulnerableExpr() and
    message = "Command Injection vulnerability: unsanitized user input used in command execution" and
    pattern_id = "CWE-78" and
    severity = "HIGH"
  )
  or
  // Unsafe Deserialization
  exists(UnsafeDeserialization unsafeDes |
    node = unsafeDes.getVulnerableExpr() and
    message = "Unsafe Deserialization vulnerability: potential remote code execution" and
    pattern_id = "CWE-502" and
    severity = "HIGH"
  )
  or
  // Hard-coded Credentials
  exists(HardcodedCredentialsApiCall pwdConfig |
    node = pwdConfig.getArg() and
    message = "Hard-coded Credentials in code: security-sensitive data should not be hard-coded" and
    pattern_id = "CWE-798" and
    severity = "MEDIUM"
  )
  or
  // XPath Injection
  exists(XPathInjection xpathInj |
    node = xpathInj.getVulnerableExpr() and
    message = "XPath Injection vulnerability: unsanitized user input used in XPath query" and
    pattern_id = "CWE-643" and
    severity = "MEDIUM"
  )
  or
  // Server-Side Request Forgery (SSRF)
  exists(RequestForgery ssrf |
    node = ssrf.getVulnerableExpr() and
    message = "Server-Side Request Forgery (SSRF) vulnerability: user-controlled URLs in server-side requests" and
    pattern_id = "CWE-918" and
    severity = "MEDIUM"
  )
  or
  // LDAP Injection
  exists(LdapInjection ldapInj |
    node = ldapInj.getVulnerableExpr() and
    message = "LDAP Injection vulnerability: unsanitized user input used in LDAP query" and
    pattern_id = "CWE-90" and
    severity = "MEDIUM"
  )
  or
  // Insecure Random Number Generation
  exists(InsecureRandom insecureRand |
    node = insecureRand.getSource() and
    message = "Insecure Random Number Generation: using predictable pseudo-random number generator" and
    pattern_id = "CWE-330" and
    severity = "MEDIUM"
  )
  or
  // Weak Cryptography
  exists(BrokenCryptoAlgorithm weakCrypto |
    node = weakCrypto.getAlg() and
    message = "Weak Cryptography: using outdated or weak cryptographic algorithm" and
    pattern_id = "CWE-327" and
    severity = "HIGH"
  )

select node, message + " [" + pattern_id + "]"