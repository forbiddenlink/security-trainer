// Groq AI client for security training feedback
// Note: In a Vite app, API calls should go through a backend
// This provides types and a mock for development

export interface SecurityFeedbackRequest {
  code: string;
  vulnerability: string; // e.g., "SQL Injection", "XSS"
  challengeType: 'find' | 'fix'; // Find the vulnerability or fix it
  expectedFix?: string;
}

export interface SecurityFeedbackResponse {
  isCorrect: boolean;
  feedback: string;
  hints: string[];
  securityExplanation?: string;
  severity?: 'critical' | 'high' | 'medium' | 'low';
}

// For client-side, we'd call an API endpoint
// This is the expected API shape for when backend is implemented
export async function getSecurityFeedback(
  request: SecurityFeedbackRequest
): Promise<SecurityFeedbackResponse> {
  const apiKey = import.meta.env.VITE_GROQ_API_KEY;

  if (!apiKey) {
    // Return mock response for development
    return {
      isCorrect: false,
      feedback: 'AI feedback not configured. Check your VITE_GROQ_API_KEY.',
      hints: ['Hint: Look for user input that goes directly into the query.'],
      securityExplanation:
        'This vulnerability occurs when user input is not properly sanitized.',
    };
  }

  // In production, this would call your backend API
  // which securely holds the Groq API key
  try {
    const response = await fetch('/api/security-feedback', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(request),
    });

    if (!response.ok) {
      throw new Error('API request failed');
    }

    return await response.json();
  } catch {
    // Fallback response
    return {
      isCorrect: false,
      feedback: 'Unable to get AI feedback. Please try again.',
      hints: [],
    };
  }
}

// Prompt template for security feedback (used by backend)
export function buildSecurityPrompt(request: SecurityFeedbackRequest): string {
  const { code, vulnerability, challengeType, expectedFix } = request;

  if (challengeType === 'find') {
    return `You are a security expert reviewing code for ${vulnerability} vulnerabilities.

Code to review:
\`\`\`
${code}
\`\`\`

The student needs to identify the ${vulnerability} vulnerability in this code.
Provide feedback on whether they correctly identified the vulnerable part.

Respond in JSON:
{
  "isCorrect": boolean,
  "feedback": "encouraging feedback",
  "hints": ["hint if they're stuck"],
  "securityExplanation": "brief explanation of why this is dangerous",
  "severity": "critical|high|medium|low"
}`;
  }

  return `You are a security expert reviewing a fix for ${vulnerability}.

Original vulnerable code pattern: ${expectedFix ? 'Known' : 'Unknown'}
Student's fixed code:
\`\`\`
${code}
\`\`\`

Evaluate if this code properly mitigates the ${vulnerability} vulnerability.

Respond in JSON:
{
  "isCorrect": boolean,
  "feedback": "encouraging feedback on their fix",
  "hints": ["improvement suggestions"],
  "securityExplanation": "why this fix works (or doesn't)"
}`;
}
