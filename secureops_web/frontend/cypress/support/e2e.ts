// cypress/support/e2e.ts

// Prevent Cypress from failing tests due to double <Router> errors
Cypress.on('uncaught:exception', (err, runnable) => {
  if (err.message.includes('You cannot render a <Router> inside another <Router>')) {
    return false; // ignore this specific error
  }
  return true; // throw other errors normally
});

