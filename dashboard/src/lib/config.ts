export const config = {
  opensearchUrl: process.env.OPENSEARCH_URL || 'http://opensearch:9200',
  clientId: process.env.CLIENT_ID || 'UNKNOWN',
  clientName: process.env.CLIENT_NAME || 'Unknown Client',
  jwtSecret: process.env.JWT_SECRET || 'dev-secret-change-in-production',
  dashboardPasswordHash: process.env.DASHBOARD_PASSWORD_HASH || '',
  timezone: process.env.TIMEZONE || 'Asia/Jerusalem',
  retentionDays: parseInt(process.env.RETENTION_DAYS || '730', 10),
  licenseApiUrl: process.env.LICENSE_API_URL || 'https://siemsys.plan-b.systems/api/license/check',
}
