describe('Dashboard Page', () => {
  it('should display dashboard metrics and widgets', () => {
    cy.visit('/dashboard');
    cy.get('h1').should('exist').and('contain.text', 'Dashboard');
  });
});
