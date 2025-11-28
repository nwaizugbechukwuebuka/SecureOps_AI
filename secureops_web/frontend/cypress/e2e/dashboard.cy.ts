describe('Dashboard Page', () => {
  it('should display dashboard metrics and widgets', () => {
    cy.visit('/');
    cy.contains('Total Scans');
    cy.contains('Risk Score');
    cy.contains('Vulnerabilities');
    cy.contains('Scan Status');
    cy.contains('Threat Types');
    cy.contains('Recent Scans');
    cy.contains('Threat Intel Feed');
    cy.contains('AI Analysis Summary');
    cy.contains('Activity Timeline');
  });
});
