# Auth - CVPlus Authentication Module

**Author**: Gil Klainert  
**Domain**: Authentication, Authorization, Session Management, and Security Systems  
**Type**: CVPlus Git Submodule  
**Independence**: Fully autonomous build and run capability

## Critical Requirements

⚠️ **MANDATORY**: You are a submodule of the CVPlus project. You MUST ensure you can run autonomously in every aspect.

🚫 **ABSOLUTE PROHIBITION**: Never create mock data or use placeholders - EVER!

🚨 **CRITICAL**: Never delete ANY files without explicit user approval - this is a security violation.

🔒 **SECURITY MANDATE**: This module handles critical authentication infrastructure - enhanced security protocols apply.

## Dependency Resolution Strategy

### Layer Position: Layer 1 (Base Services)
**Auth depends ONLY on Core module.**

### Allowed Dependencies
```typescript
// ✅ ALLOWED: Core module only
import { User, ApiResponse, SecurityError } from '@cvplus/core';
import { validateEmail, hashPassword } from '@cvplus/core/utils';
import { AuthConfig } from '@cvplus/core/config';

// ✅ ALLOWED: External libraries
import { firestore } from 'firebase-admin';
import * as jwt from 'jsonwebtoken';
```

### Forbidden Dependencies  
```typescript
// ❌ FORBIDDEN: Same layer modules
import { TranslationService } from '@cvplus/i18n'; // NEVER

// ❌ FORBIDDEN: Higher layer modules  
import { CVProcessor } from '@cvplus/cv-processing'; // NEVER
import { PremiumService } from '@cvplus/premium'; // NEVER
import { AdminService } from '@cvplus/admin'; // NEVER
```

### Dependency Rules for Auth
1. **Core Only**: Auth only depends on @cvplus/core
2. **No Peer Dependencies**: No dependencies on other Layer 1 modules (i18n)
3. **Provider Role**: Provides authentication services to higher layers
4. **Security First**: All external dependencies must pass security review
5. **Interface Implementation**: Implements interfaces defined in Core

### Import/Export Patterns
```typescript
// Correct imports from Core
import { User, AuthConfig } from '@cvplus/core';

// Correct exports for higher layers
export interface AuthService {
  authenticate(token: string): Promise<User>;
  authorize(user: User, permission: string): boolean;
}
export class FirebaseAuthService implements AuthService { /* */ }

// Higher layers import from Auth
// @cvplus/cv-processing: import { AuthService } from '@cvplus/auth';
// @cvplus/premium: import { AuthService } from '@cvplus/auth';
```

### Build Dependencies
- **Builds After**: Core must be built first
- **Builds Before**: All Layer 2+ modules depend on Auth build output
- **Security Validation**: Enhanced security checks during build process

## Submodule Overview

The CVPlus Authentication module is the security backbone of the entire CVPlus ecosystem, providing comprehensive authentication, authorization, session management, and security services. This module ensures secure access control across all CVPlus features while maintaining the highest security standards.

### Core Authentication Infrastructure
- **Firebase Authentication Integration**: Complete Firebase Auth implementation with custom user management
- **Session Management**: Advanced session handling with security monitoring and concurrent session control
- **Multi-Factor Authentication (MFA)**: TOTP, SMS, and backup code MFA implementation
- **Permission System**: Role-based access control (RBAC) with granular permissions and inheritance
- **Premium Feature Gates**: Secure subscription and tier validation for premium features
- **Security Monitoring**: Real-time threat detection, anomaly identification, and security event logging

## Domain Expertise

### Primary Responsibilities
- **User Authentication**: Registration, login, password reset, email verification flows
- **Session Security**: Secure session creation, validation, rotation, and termination
- **Permission Management**: Role assignment, permission validation, access control enforcement
- **Premium Integration**: Subscription validation, feature gating, tier management
- **Security Enforcement**: Threat detection, rate limiting, brute force protection
- **Compliance**: GDPR, data privacy, audit logging, user consent management

### Key Features
- **Secure Authentication Flows**: Multi-step verification with security validation
- **Advanced Session Management**: Concurrent session handling with security monitoring
- **Comprehensive Permission System**: RBAC with inheritance and conditional permissions
- **Multi-Factor Authentication**: Complete MFA implementation with multiple methods
- **Premium Feature Integration**: Secure tier validation and subscription management
- **Security Analytics**: Real-time monitoring and threat detection capabilities
- **Compliance Framework**: GDPR compliance with audit trails and user consent

### Integration Points
- **Core Module**: Shared types, constants, utilities, and error handling
- **Premium Module**: Subscription validation, billing integration, feature gating
- **I18n Module**: Multi-language support for authentication interfaces
- **Multimedia Module**: User avatar management and media access control
- **Public Profiles Module**: Profile visibility permissions and social features
- **Admin Module**: User management, system monitoring, and security dashboards
- **Analytics Module**: Authentication metrics and security event tracking

## Specialized Subagents

### Primary Specialist
- **auth-module-specialist**: Domain expert for authentication, session management, RBAC systems, Firebase Auth integration, security enforcement, and premium feature gates

### Security-Focused Specialists
- **security-specialist**: Security architecture, vulnerability assessment, threat modeling, compliance validation
- **legal-compliance-checker**: GDPR compliance, data privacy regulations, user consent, audit requirements

### Supporting Specialists
- **firebase-integration-specialist**: Firebase Auth configuration, rules, security optimization
- **premium-specialist**: Subscription integration, billing security, feature gate implementation

### Universal Specialists
- **code-reviewer**: MANDATORY quality assurance and security review for ALL changes
- **debugger**: Complex troubleshooting, authentication flow debugging, security incident analysis
- **git-expert**: All git operations with security considerations and secure branching
- **test-writer-fixer**: Comprehensive testing with security test scenarios and edge case coverage

## Technology Stack

### Core Technologies
- **TypeScript 5.0+**: Strict type safety for security-critical code
- **Firebase Auth**: Primary authentication provider with custom claims
- **React 18**: Authentication components and context providers
- **Node.js**: Backend authentication services and middleware

### Security Libraries
- **JWT**: Secure token handling and validation
- **bcrypt**: Password hashing and validation
- **crypto**: Encryption utilities and secure random generation
- **helmet**: Security headers and middleware protection

### Testing Framework
- **Vitest**: Primary testing framework with security test scenarios
- **Firebase Testing**: Authentication flow testing with Firebase emulators

### Build System
- **tsup**: TypeScript bundling with security considerations
- **Rollup**: Module bundling for optimal security and performance

### Dependencies
- **Firebase SDK 9+**: Authentication, Firestore, Cloud Functions
- **React Context**: State management for authentication flows
- **CVPlus Core**: Shared utilities, types, and constants

## Build System

### Core Commands
- **Build Command**: `npm run build` - Comprehensive build with security validation
- **Test Command**: `npm run test` - Complete test suite including security tests
- **Type Check**: `npm run type-check` - Strict TypeScript validation
- **Security Audit**: `npm run audit` - Dependency vulnerability scanning
- **Lint**: `npm run lint` - Code quality and security linting

### Security-Specific Commands
- **Security Audit**: `npm run security:audit` - Comprehensive security assessment
- **Permission Validation**: `npm run security:permissions` - Permission system validation
- **Auth Flow Testing**: `npm run test:auth-flows` - Authentication flow validation
- **Session Security**: `npm run test:session-security` - Session management testing
- **Compliance Check**: `npm run security:compliance` - GDPR and privacy compliance

## Development Workflow

### Setup Instructions
1. Clone auth submodule repository: `git clone git@github.com:gilco1973/cvplus-auth.git`
2. Install dependencies: `npm install`
3. Run security audit: `npm audit --audit-level=moderate`
4. Run type checks: `npm run type-check`
5. Run comprehensive tests: `npm test --coverage`
6. Build module: `npm run build`
7. Validate security: `npm run security:audit`

### Security Development Practices
1. **Security-First Design**: All authentication flows designed with security as primary concern
2. **Threat Modeling**: Regular threat assessment and vulnerability analysis
3. **Secure Coding**: Input validation, output encoding, secure data handling
4. **Defense in Depth**: Multiple security layers and validation points
5. **Principle of Least Privilege**: Minimal permission grants and access control

### Testing Requirements
- **Coverage Requirement**: Minimum 90% code coverage (higher than standard due to security criticality)
- **Security Test Coverage**: 100% coverage for all authentication and authorization flows
- **Test Framework**: Vitest with Firebase emulators for integration testing
- **Test Types**: Unit tests, integration tests, security tests, end-to-end authentication flows

### Security Testing Requirements
- **Authentication Flow Tests**: Complete validation of all authentication paths
- **Session Security Tests**: Session hijacking prevention, timeout validation, concurrent sessions
- **Permission Tests**: Role validation, privilege escalation prevention, access control
- **Input Validation Tests**: XSS prevention, injection attack protection, sanitization
- **Rate Limiting Tests**: Brute force protection, DoS prevention, throttling validation

## Integration Patterns

### CVPlus Ecosystem Integration
- **Import Pattern**: `@cvplus/auth` - Main module exports
- **Component Import**: `@cvplus/auth/components` - React authentication components
- **Hook Import**: `@cvplus/auth/hooks` - Authentication hooks and state management
- **Service Import**: `@cvplus/auth/services` - Authentication services and utilities
- **Type Import**: `@cvplus/auth/types` - TypeScript type definitions
- **Constants Import**: `@cvplus/auth/constants` - Authentication constants and configurations

### Export Pattern
```typescript
// Main exports - comprehensive authentication system
export {
  // Components
  AuthGuard, PermissionGate, SignInDialog,
  // Context
  AuthContext, AuthProvider,
  // Hooks  
  useAuth, usePermissions, useSession, usePremium,
  // Services
  AuthService, PermissionService, SessionService, PremiumService,
  // Types
  User, UserRole, Permission, AuthState, SessionData,
  // Constants
  AUTH_CONSTANTS, PERMISSION_CONSTANTS, PREMIUM_CONSTANTS
} from '@cvplus/auth';
```

### Dependency Chain
- **Direct Dependencies**: `@cvplus/core` (types, utilities, error handling)
- **Integration Dependencies**: `@cvplus/premium` (subscription validation), `@cvplus/i18n` (localization)
- **Consumer Modules**: All other CVPlus modules depend on auth for access control

### Firebase Functions Integration
- **Authentication Middleware**: Exported authentication middleware for Firebase Functions
- **Permission Validation**: Server-side permission checking utilities
- **Session Management**: Cloud Function session validation and management
- **Premium Gates**: Server-side premium feature validation functions

### Security Integration Patterns
```typescript
// Secure component wrapping with permission validation
<AuthGuard requireAuth={true}>
  <PermissionGate permissions={['read:profile']} premiumTier="pro">
    <PremiumFeatureComponent />
  </PermissionGate>
</AuthGuard>

// Service integration with security validation
const authService = new AuthService({
  securityConfig: AUTH_SECURITY_CONFIG,
  encryptionKey: process.env.AUTH_ENCRYPTION_KEY,
  auditLogger: auditLogger
});
```

## Scripts and Automation

### Available Scripts
- **build**: `npm run build` - Production build with security optimization
- **dev**: `npm run dev` - Development mode with security monitoring
- **test**: `npm run test` - Complete test suite including security tests
- **test:watch**: `npm run test:watch` - Watch mode for development testing
- **test:coverage**: `npm run test:coverage` - Coverage report with security metrics
- **test:auth-flows**: `npm run test:auth-flows` - Authentication flow validation
- **test:security**: `npm run test:security` - Security-specific test suite
- **lint**: `npm run lint` - Code quality and security linting
- **type-check**: `npm run type-check` - TypeScript strict validation
- **audit**: `npm run audit` - Security dependency audit
- **security:audit**: Security audit and vulnerability assessment
- **security:permissions**: Permission system validation
- **security:compliance**: GDPR and privacy compliance check

### Build Automation
- **Pre-build Security Checks**: Dependency audit, type validation, security linting
- **Build Process**: TypeScript compilation, bundling, minification with security optimization
- **Post-build Validation**: Module integrity checks, export validation, security verification
- **Deployment Preparation**: Security configuration validation, environment variable checking

### Security Automation
- **Automated Security Testing**: Continuous security test execution with CI/CD integration
- **Vulnerability Scanning**: Regular dependency and code vulnerability assessment
- **Compliance Monitoring**: Automated GDPR and privacy compliance validation
- **Security Metrics**: Authentication security metrics collection and analysis

## Quality Standards

### Code Quality
- **TypeScript Strict Mode**: Enhanced type safety for security-critical code
- **ESLint Security Rules**: Security-focused linting with custom authentication rules
- **Prettier Configuration**: Consistent code formatting with security considerations
- **File Size Compliance**: All files under 200 lines with security-focused modularization
- **Comprehensive Error Handling**: Security-aware error handling with audit logging

### Security Requirements
- **Zero Hardcoded Secrets**: All secrets managed through environment variables or Firebase Secrets
- **Input Validation**: Comprehensive input sanitization and validation for all user inputs
- **Secure Firebase Integration**: Firebase security rules, custom claims, proper authentication flows
- **Encryption at Rest**: Sensitive data encryption using industry-standard algorithms
- **Audit Logging**: Complete audit trail for all authentication and authorization events
- **Rate Limiting**: Comprehensive rate limiting and brute force protection
- **Session Security**: Secure session management with rotation, validation, and monitoring

### Performance Requirements
- **Authentication Speed**: Sub-200ms authentication validation response time
- **Session Management**: Efficient session storage and retrieval with caching
- **Permission Checking**: Optimized permission validation with minimal latency
- **Concurrent Users**: Support for high concurrent authentication loads
- **Memory Efficiency**: Minimal memory footprint with efficient data structures

### Compliance Requirements
- **GDPR Compliance**: Full GDPR compliance with user consent, data portability, deletion rights
- **Data Privacy**: Privacy-by-design implementation with minimal data collection
- **Audit Requirements**: Comprehensive audit logging with tamper-proof event records
- **Security Standards**: SOC 2 Type II compliance with regular security assessments

## Security Architecture

### Authentication Security
- **Multi-Factor Authentication**: TOTP, SMS, backup codes with secure enrollment
- **Password Security**: Secure password policies, breach detection, rotation requirements
- **Account Security**: Account lockout, suspicious activity detection, security notifications
- **Token Security**: JWT validation, token rotation, secure token storage

### Authorization Security  
- **Role-Based Access Control**: Hierarchical roles with permission inheritance
- **Principle of Least Privilege**: Minimal permission grants with regular review
- **Permission Validation**: Multi-layer permission checking with caching
- **Premium Feature Gates**: Secure subscription validation with anti-tampering

### Session Security
- **Secure Session Management**: Session encryption, rotation, concurrent session limits
- **Session Monitoring**: Real-time session tracking, anomaly detection, security alerts
- **Device Management**: Device tracking, trusted device management, security notifications
- **Session Termination**: Secure logout, session invalidation, cleanup procedures

## Troubleshooting

### Common Issues
- **Firebase Auth Configuration**: Verify Firebase project settings, API keys, security rules
- **Session Persistence**: Check session storage, cookie configuration, domain settings  
- **Permission Validation**: Validate role assignments, permission inheritance, cache invalidation
- **Premium Integration**: Verify subscription status, billing integration, feature gate configuration
- **Security Errors**: Check rate limiting, failed login attempts, suspicious activity detection

### Debug Commands
- **Authentication Debug**: `npm run debug:auth` - Authentication flow debugging
- **Session Debug**: `npm run debug:session` - Session management debugging  
- **Permission Debug**: `npm run debug:permissions` - Permission validation debugging
- **Security Debug**: `npm run debug:security` - Security event and monitoring debugging
- **Integration Debug**: `npm run debug:integration` - Cross-module integration debugging

### Security Incident Response
- **Incident Detection**: Automated threat detection with real-time alerts
- **Incident Analysis**: Security event analysis, impact assessment, root cause analysis  
- **Incident Response**: Automated security responses, account protection, system isolation
- **Incident Recovery**: Service restoration, security validation, post-incident monitoring
- **Incident Documentation**: Complete incident documentation, lessons learned, security improvements

### Support Resources
- **Firebase Auth Documentation**: Official Firebase Authentication guides and references
- **CVPlus Auth Guide**: Internal authentication implementation and security documentation
- **Security Best Practices**: Authentication security guidelines and implementation standards
- **Troubleshooting Guide**: Common issues, solutions, and debugging procedures
- **Security Incident Playbook**: Step-by-step security incident response procedures