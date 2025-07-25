const { test, expect } = require('@playwright/test');

test.describe('Search Application UI Tests', () => {
  test('should display search form and handle valid search term', async ({ page }) => {
    // Navigate to the application
    await page.goto('http://localhost:3000');

    // Check if search form is visible - updated to match server.js content
    await expect(page.locator('input[type="text"]')).toBeVisible();
    await expect(page.locator('button[type="submit"]')).toBeVisible();
    await expect(page.locator('button[type="submit"]')).toContainText('Validate & Search');

    // Enter a valid search term
    await page.fill('input[type="text"]', 'javascript programming');
    await page.click('button[type="submit"]');

    // Should redirect to results page - updated to match actual server response
    await expect(page.locator('h1')).toContainText('Search Validated Successfully!');
    await expect(page.locator('text=Validation Complete!')).toBeVisible();
    
    // Check for the processed search term - updated selector to match server.js
    await expect(page.locator('.search-term')).toContainText('javascript programming');
    await expect(page.locator('button[type="submit"]')).toContainText('🏠 Back to Search');
  });
});