/**
 * PII Detection LLM Service
 *
 * Moved from admin module - contains PII detection business logic that belongs in auth module.
 * This service provides PII detection capabilities using LLM integration for security purposes.
 */

import {
  VerifiedClaudeService,
  VerifiedMessageOptions
} from '@cvplus/admin/backend/services/verified-claude.service';
import { ValidationCriteria } from '@cvplus/admin/backend/services/llm-verification.service';

export interface PIIDetectionOptions {
  categories?: string[];
  sensitivity?: 'low' | 'medium' | 'high';
  includeContext?: boolean;
}

export interface PIIDetectionResponse {
  content: string;
  verified?: boolean;
  verificationScore?: number;
  auditId?: string;
  usage?: {
    inputTokens: number;
    outputTokens: number;
  };
}

/**
 * PII Detection LLM Service with enhanced validation
 */
export class PIIDetectionLLMService {
  private verifiedClaudeService: VerifiedClaudeService;

  constructor() {
    this.verifiedClaudeService = new VerifiedClaudeService();
  }

  async detectPII(
    text: string,
    options?: PIIDetectionOptions
  ): Promise<PIIDetectionResponse> {
    const prompt = this.buildPIIDetectionPrompt(text, options);

    const verifiedRequest: VerifiedMessageOptions = {
      prompt: `You are a PII detection expert. Identify all personally identifiable information with high accuracy while minimizing false positives.\n\n${prompt}`,
      model: 'claude-sonnet-4-20250514',
      messages: [{
        role: 'user',
        content: `You are a PII detection expert. Identify all personally identifiable information with high accuracy while minimizing false positives.\n\n${prompt}`
      }],
      maxTokens: 2000,
      temperature: 0
    };

    try {
      const response = await this.verifiedClaudeService.createVerifiedMessage(verifiedRequest);

      return {
        content: Array.isArray(response.content) ? response.content.map(c => c.content || '').join('') : String(response.content || response.response || ''),
        verified: response.verification?.verified || false,
        verificationScore: response.verification?.confidence || 0,
        auditId: `audit-${Date.now()}`,
        usage: response.usage ? {
          inputTokens: response.usage.inputTokens || 0,
          outputTokens: response.usage.outputTokens || 0
        } : undefined
      };

    } catch (error) {
      throw error;
    }
  }

  private buildPIIDetectionPrompt(
    text: string,
    options?: PIIDetectionOptions
  ): string {
    const categories = options?.categories || [
      'names', 'email', 'phone', 'address', 'ssn', 'credit_card',
      'bank_account', 'date_of_birth', 'government_id'
    ];

    return `Analyze the following text and identify all personally identifiable information (PII).

DETECTION CATEGORIES:
${categories.map(cat => `- ${cat}`).join('\n')}

SENSITIVITY LEVEL: ${options?.sensitivity || 'medium'}

TEXT TO ANALYZE:
${text}

Return results in JSON format:
{
  "piiDetected": boolean,
  "totalFindings": number,
  "findings": [
    {
      "type": string,
      "value": string,
      "confidence": number,
      "location": {
        "start": number,
        "end": number
      },
      "context": string
    }
  ],
  "riskLevel": "low|medium|high|critical",
  "recommendations": [string]
}`;
  }
}

// Export default instance for convenience
export const piiDetectionService = new PIIDetectionLLMService();