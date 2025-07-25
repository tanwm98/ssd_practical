/* global describe, test, expect */
const { z } = require('zod');
const validator = require('validator');

// Import the validation logic from server.js
const searchTermSchema = z
  .string()
  .trim()
  .min(1, 'Search term cannot be empty')
  .max(100, 'Search term is too long (maximum 100 characters)')
  .refine(
    (value) => {
      // Check for XSS patterns
      const xssPatterns = [
        /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
        /javascript:/gi,
        /on\w+\s*=/gi,
        /<iframe/gi,
        /<object/gi,
        /<embed/gi,
        /<link/gi,
        /<meta/gi,
        /expression\s*\(/gi,
        /vbscript:/gi,
        /data:text\/html/gi,
        /<img[^>]+src[^>]*>/gi,
        /<svg/gi,
        /style\s*=/gi
      ];
      
      return !xssPatterns.some(pattern => pattern.test(value));
    },
    { message: 'Potentially malicious XSS content detected. Please enter a valid search term' }
  )
  .refine(
    (value) => {
      // Check for SQL injection patterns
      const sqlPatterns = [
        /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|CREATE)\b)/gi,
        /(\b(OR|AND)\s+\d+\s*=\s*\d+)/gi,
        /(\b(OR|AND)\s+['"]\w+['"]?\s*=\s*['"]\w+['"]?)/gi,
        /(--|#|\/\*|\*\/)/g,
        /(\bEXEC\b|\bEXECUTE\b)/gi,
        /(\bSP_\w+)/gi,
        /(\bXP_\w+)/gi,
        /(;\s*(SELECT|INSERT|UPDATE|DELETE|DROP))/gi,
        /(\bunion\b.*\bselect\b)/gi,
        /(\bwhere\b.*\b(or|and)\b.*=)/gi
      ];
      
      return !sqlPatterns.some(pattern => pattern.test(value));
    },
    { message: 'Potentially malicious SQL injection detected. Please enter a valid search term' }
  )
  .refine(
    (value) => {
      // Check for suspicious characters using allowlist approach
      const allowedPattern = /^[a-zA-Z0-9\s\-_.,!?()]+$/;
      return allowedPattern.test(value);
    },
    { message: 'Please use only letters, numbers, spaces, and basic punctuation (.-_,!?())' }
  )
  .refine(
    (value) => {
      // Check for control characters and encoded attacks using character codes
      const hasControlChars = Array.from(value).some(char => {
        const code = char.charCodeAt(0);
        return (
          code < 32 ||                    // Control characters (0-31)
          (code >= 127 && code <= 159) || // Extended control characters
          code === 60 ||                  // <
          code === 62 ||                  // >
          code === 34 ||                  // "
          code === 39 ||                  // '
          code === 59                     // ;
        );
      });
      
      return !hasControlChars;
    },
    { message: 'Invalid characters detected. Please avoid special characters that could be harmful' }
  )
  .transform((value) => {
    return validator.escape(value);
  });

function validateSearchInput(input) {
  try {
    const sanitized = searchTermSchema.parse(input);
    return {
      valid: true,
      errors: [],
      sanitized: sanitized
    };
  } catch (error) {
    if (error instanceof z.ZodError) {
      const errors = error.issues.map(err => err.message);
      return {
        valid: false,
        errors: errors,
        sanitized: ''
      };
    }
    
    return {
      valid: false,
      errors: ['Validation failed. Please try again.'],
      sanitized: ''
    };
  }
}

describe('Search Input Validation', () => {
  test('should accept valid search terms and reject malicious inputs', () => {
    // Test valid input
    const validResult = validateSearchInput('javascript programming');
    expect(validResult.valid).toBe(true);
    expect(validResult.errors).toHaveLength(0);
    expect(validResult.sanitized).toBe('javascript programming');

    // Test XSS attack
    const xssResult = validateSearchInput('<script>alert("xss")</script>');
    expect(xssResult.valid).toBe(false);
    expect(xssResult.errors.some(error => 
      error.includes('XSS content detected')
    )).toBe(true);
  });
});