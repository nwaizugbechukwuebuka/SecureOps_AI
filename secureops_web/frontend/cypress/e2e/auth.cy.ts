describe('Auth Page', () => {
  it('should allow user to login', () => {
    cy.visit('/login');
    cy.get('input[data-testid="username"]').should('exist').type('testuser');
    cy.get('input[data-testid="password"]').should('exist').type('password');
    cy.get('button[type="submit"]').click();
    cy.url().should('include', '/dashboard');
  });
});
