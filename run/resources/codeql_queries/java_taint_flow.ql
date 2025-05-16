/**
 * @name Java Taint Flow Analysis for Security Vulnerabilities
 * @description Detects dangerous data flows from untrusted sources to sensitive sinks
 * @kind path-problem
 * @problem.severity error
 * @precision medium
 * @id java/taint-flow
 * @tags security
 *       taint
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.FlowSources
import DataFlow::PathGraph

/**
 * Sources of untrusted data in a Java application.
 */
class JavaSecuritySource extends DataFlow::Node {
  JavaSecuritySource() {
    // HTTP request parameters (from servlet API)
    exists(MethodAccess ma |
      ma.getMethod().hasName(["getParameter", "getParameterValues", "getParameterMap", "getParameterNames"]) and
      ma.getMethod().getDeclaringType().hasQualifiedName("javax.servlet.http", "HttpServletRequest") and
      this.asExpr() = ma
    )
    or
    // HTTP request headers and other data (from servlet API)
    exists(MethodAccess ma |
      ma.getMethod().hasName(["getHeader", "getHeaders", "getHeaderNames", "getQueryString", "getRequestURI", "getRequestURL", "getPathInfo", "getPathTranslated"]) and
      ma.getMethod().getDeclaringType().hasQualifiedName("javax.servlet.http", "HttpServletRequest") and
      this.asExpr() = ma
    )
    or
    // HTTP request input stream and reader (from servlet API)
    exists(MethodAccess ma |
      ma.getMethod().hasName(["getInputStream", "getReader"]) and
      ma.getMethod().getDeclaringType().hasQualifiedName("javax.servlet.http", "HttpServletRequest") and
      this.asExpr() = ma
    )
    or
    // JDBC results (potentially untrusted data from database)
    exists(MethodAccess ma |
      ma.getMethod().hasName(["getString", "getObject", "getBytes", "getBlob", "getClob", "getArray"]) and
      ma.getMethod().getDeclaringType().hasQualifiedName("java.sql", "ResultSet") and
      this.asExpr() = ma
    )
    or
    // File inputs (potentially untrusted)
    exists(ClassInstanceExpr cie |
      cie.getConstructedType().hasQualifiedName("java.io", ["FileInputStream", "FileReader"]) and
      this.asExpr() = cie
    )
    or
    // Command line arguments
    exists(ArrayAccess aa |
      aa.getArray() = any(Parameter p | p.getName() = "args" and p.getType() instanceof Array) and
      this.asExpr() = aa
    )
  }
}

/**
 * Sinks where untrusted data can lead to security vulnerabilities.
 */
class JavaSecuritySink extends DataFlow::Node {
  JavaSecuritySink() {
    // SQL injection sinks
    exists(MethodAccess ma |
      ma.getMethod().hasName(["execute", "executeQuery", "executeUpdate"]) and
      ma.getMethod().getDeclaringType().hasQualifiedName("java.sql", ["Statement", "PreparedStatement"]) and
      this.asExpr() = ma.getArgument(0)
    )
    or
    // Command injection sinks
    exists(MethodAccess ma |
      ma.getMethod().hasName("exec") and
      ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "Runtime") and
      this.asExpr() = ma.getArgument(0)
    )
    or
    // Path traversal sinks
    exists(ClassInstanceExpr cie |
      cie.getConstructedType().hasQualifiedName("java.io", ["File", "FileInputStream", "FileOutputStream", "FileReader", "FileWriter"]) and
      this.asExpr() = cie.getArgument(0)
    )
    or
    // XSS sinks
    exists(MethodAccess ma |
      ma.getMethod().hasName(["print", "println", "write"]) and
      ma.getMethod().getDeclaringType().hasQualifiedName("java.io", "PrintWriter") and
      this.asExpr() = ma.getArgument(0) and
      // Writer comes from a servlet response
      exists(MethodAccess respWriter |
        respWriter.getMethod().hasName("getWriter") and
        respWriter.getMethod().getDeclaringType().hasQualifiedName("javax.servlet.http", "HttpServletResponse") and
        DataFlow::localExprFlow(respWriter, ma.getQualifier())
      )
    )
    or
    // Open redirect sinks
    exists(MethodAccess ma |
      ma.getMethod().hasName("sendRedirect") and
      ma.getMethod().getDeclaringType().hasQualifiedName("javax.servlet.http", "HttpServletResponse") and
      this.asExpr() = ma.getArgument(0)
    )
    or
    // Unsafe deserialization sinks
    exists(MethodAccess ma |
      ma.getMethod().hasName("readObject") and
      ma.getMethod().getDeclaringType().hasQualifiedName("java.io", "ObjectInputStream") and
      this.asExpr() = ma
    )
  }
}

/**
 * Sanitizers for security vulnerabilities.
 */
class JavaSecuritySanitizer extends DataFlow::Node {
  JavaSecuritySanitizer() {
    // SQL prepared statement parameter setting (prevents SQL injection)
    exists(MethodAccess ma |
      ma.getMethod().getName().matches("set%") and
      ma.getMethod().getDeclaringType().hasQualifiedName("java.sql", "PreparedStatement") and
      this.asExpr() = ma.getArgument(1)
    )
    or
    // Sanitization methods for XSS
    exists(MethodAccess ma |
      (
        // OWASP ESAPI
        ma.getMethod().hasName(["encodeForHTML", "encodeForHTMLAttribute", "encodeForJavaScript"]) and
        ma.getMethod().getDeclaringType().hasQualifiedName("org.owasp.esapi.encoder", "Encoder")
        or
        // Apache Commons Text
        ma.getMethod().hasName("escapeHtml4") and
        ma.getMethod().getDeclaringType().hasQualifiedName("org.apache.commons.text", "StringEscapeUtils")
      ) and
      this.asExpr() = ma
    )
    or
    // Path traversal sanitization
    exists(MethodAccess ma |
      ma.getMethod().hasName("getCanonicalPath") and
      ma.getMethod().getDeclaringType().hasQualifiedName("java.io", "File") and
      this.asExpr() = ma
    )
  }
}

/**
 * Taint configuration for tracking flow from sources to sinks.
 */
class JavaSecurityConfig extends TaintTracking::Configuration {
  JavaSecurityConfig() { this = "JavaSecurityConfig" }

  override predicate isSource(DataFlow::Node source) { source instanceof JavaSecuritySource }

  override predicate isSink(DataFlow::Node sink) { sink instanceof JavaSecuritySink }

  override predicate isSanitizer(DataFlow::Node node) { node instanceof JavaSecuritySanitizer }
}

from JavaSecurityConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Potential security vulnerability: data from $@ flows to sensitive sink.", source.getNode(), "user input"
