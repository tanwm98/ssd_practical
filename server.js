  const express = require('express');
  const { z } = require('zod');
  const validator = require('validator');
  const app = express();
  const port = 3000;

  app.use(express.static('public'));
  app.use(express.urlencoded({ extended: true }));
  app.disable('x-powered-by');

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

  // Home page route
  app.get('/', (req, res) => {
    const errorMessage = req.query.error || '';
    const errorDisplay = errorMessage ? `<div>${validator.escape(errorMessage)}</div>` : '';
    
    res.send(`
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Search</title>
      </head>
      <body>
        <div class="container">
          <div class="info">
            <strong>Input Guidelines:</strong><br>
            • Maximum 100 characters<br>
          </div>
          ${errorDisplay}
          <form action="/search" method="POST">
            <label for="searchTerm">Enter your search term:</label>
            <input type="text" id="searchTerm" name="searchTerm" required maxlength="100" 
                  placeholder="e.g., javascript programming, web security, database design...">
            <button type="submit">Validate & Search</button>
          </form>
        </div>
      </body>
      </html>
    `);
  });

  // Search processing route
  app.post('/search', (req, res) => {
    const { searchTerm } = req.body;
    
    if (!searchTerm) {
      return res.redirect('/');
    }
    
    const validation = validateSearchInput(searchTerm);
    
    if (!validation.valid) {
      return res.redirect('/');
    }
    
    // If validation passes, show results page
    res.send(`
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Search Results - Validated</title>
      </head>
      <body>
        <div class="container">
          <h1>✅ Search Validated Successfully!</h1>
          <div class="results">
            <strong>Validation Complete!</strong><br>
          </div>
          <div>
            <strong>🔍 Processed Search Term:</strong>
            <div class="search-term">${validation.sanitized}</div>
          </div>
          <div class="back-link">
            <form action="/" method="GET" style="display: inline;">
              <button type="submit">🏠 Back to Search</button>
            </form>
          </div>
        </div>
      </body>
      </html>
    `);
  });

  // Error handling middleware
  app.use((err, req, res) => {
    console.error(err.stack);
    res.status(500).redirect('/');
  });

  app.listen(port, '0.0.0.0', () => {
    console.log('Server running at http://0.0.0.0:3000');
  });
