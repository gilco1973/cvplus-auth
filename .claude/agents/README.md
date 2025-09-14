# Auth Submodule Agent Configuration

This directory contains references to specialized subagents for the CVPlus Authentication module.

## Primary Specialist

### auth-module-specialist
**Location**: `/Users/gklainert/.local/share/claude-007-agents/.claude/agents/cvplus/auth-module-specialist.md`  
**Role**: Primary domain expert for authentication, session management, and security systems  
**Expertise**: Firebase Auth, JWT tokens, RBAC, session security, permission systems

## Security-Focused Specialists

### security-specialist  
**Location**: `/Users/gklainert/.local/share/claude-007-agents/.claude/agents/security/security-specialist.md`  
**Role**: Security architecture, vulnerability assessment, compliance validation  
**Expertise**: Security audit, threat modeling, encryption, secure coding practices

### legal-compliance-checker
**Location**: `/Users/gklainert/.local/share/claude-007-agents/.claude/agents/security/legal-compliance-checker.md`  
**Role**: Privacy law compliance, data protection regulations  
**Expertise**: GDPR, CCPA, data privacy, user consent, audit trails

## Universal Specialists

### code-reviewer
**Location**: `/Users/gklainert/.local/share/claude-007-agents/.claude/agents/universal/code-reviewer.md`  
**Role**: Code quality assurance, security review, best practices enforcement  
**Critical**: Must review ALL authentication code changes

### debugger
**Location**: `/Users/gklainert/.local/share/claude-007-agents/.claude/agents/universal/debugger.md`  
**Role**: Complex troubleshooting, error analysis, system debugging  
**Expertise**: Authentication flow debugging, session issues, security incidents

### git-expert
**Location**: `/Users/gklainert/.local/share/claude-007-agents/.claude/agents/universal/git-expert.md`  
**Role**: All git operations, repository management, secure branching  
**Critical**: Handles ALL git operations with security considerations

## Testing Specialists

### test-writer-fixer
**Location**: `/Users/gklainert/.local/share/claude-007-agents/.claude/agents/testing/test-writer-fixer.md`  
**Role**: Comprehensive test creation, security test validation, test maintenance  
**Focus**: Authentication flow tests, security test scenarios, edge case coverage

### backend-test-engineer
**Location**: `/Users/gklainert/.local/share/claude-007-agents/.claude/agents/testing/backend-test-engineer.md`  
**Role**: Backend service testing, API security testing, integration tests  
**Focus**: Firebase Auth integration, session management, permission validation

## Usage Guidelines

### Primary Workflow
1. **auth-module-specialist** for all domain-specific authentication tasks
2. **security-specialist** for security architecture and audit requirements
3. **code-reviewer** for MANDATORY final review of all changes
4. **test-writer-fixer** for comprehensive test coverage

### Security-Critical Tasks
- Authentication flow modifications → auth-module-specialist + security-specialist
- Permission system changes → auth-module-specialist + legal-compliance-checker  
- Session management updates → auth-module-specialist + security-specialist
- Firebase Auth integration → auth-module-specialist + backend-test-engineer

### Quality Assurance
- ALL code changes MUST be reviewed by code-reviewer subagent
- Security-related changes MUST include security-specialist review
- ALL changes require comprehensive test coverage via test-writer-fixer

## Security Standards

### Authentication Standards
- Multi-factor authentication implementation
- Secure password policies and validation
- Session timeout and rotation mechanisms
- Failed login attempt rate limiting

### Authorization Standards
- Role-based access control (RBAC) implementation
- Principle of least privilege enforcement
- Permission validation at all access points
- Secure attribute-based access control

### Compliance Standards
- GDPR compliance for user data handling
- Privacy-by-design implementation
- Audit logging for all authentication events
- Data retention and deletion policies