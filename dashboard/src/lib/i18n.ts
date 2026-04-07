export type Locale = 'he' | 'en'

export const translations = {
  // Navigation
  'nav.overview': { he: 'סקירה כללית', en: 'Overview' },
  'nav.threats': { he: 'איומים', en: 'Threats' },
  'nav.forensics': { he: 'חקירות', en: 'Forensics' },
  'nav.sources': { he: 'מקורות', en: 'Sources' },
  'nav.health': { he: 'בריאות המערכת', en: 'System Health' },
  'nav.settings': { he: 'הגדרות', en: 'Settings' },
  'nav.logout': { he: 'התנתק', en: 'Logout' },
  'nav.collapse': { he: 'כווץ', en: 'Collapse' },

  // Login
  'login.title': { he: 'לוח בקרה SIEM', en: 'SIEM Dashboard' },
  'login.subtitle': { he: 'הזן סיסמת מנהל להמשך', en: 'Enter admin password to continue' },
  'login.password': { he: 'סיסמה', en: 'Password' },
  'login.button': { he: 'כניסה', en: 'Login' },
  'login.loading': { he: 'מאמת...', en: 'Authenticating...' },
  'login.error': { he: 'סיסמה שגויה', en: 'Invalid password' },

  // Overview
  'overview.title': { he: 'סקירה כללית', en: 'Overview' },
  'overview.totalLogs': { he: 'סה"כ לוגים', en: 'Total Logs' },
  'overview.severity': { he: 'חומרה', en: 'Severity' },
  'overview.topSources': { he: 'מקורות מובילים', en: 'Top Sources' },
  'overview.topApps': { he: 'אפליקציות מובילות', en: 'Top Applications' },
  'overview.timeRange': { he: 'טווח זמן', en: 'Time Range' },
  'overview.logsOverTime': { he: 'לוגים לאורך זמן', en: 'Logs Over Time' },

  // Threats
  'threats.title': { he: 'איומים', en: 'Threats' },
  'threats.critical': { he: 'קריטי', en: 'Critical' },
  'threats.high': { he: 'גבוה', en: 'High' },
  'threats.medium': { he: 'בינוני', en: 'Medium' },
  'threats.timeline': { he: 'ציר זמן איומים', en: 'Threat Timeline' },
  'threats.noThreats': { he: 'לא זוהו איומים', en: 'No threats detected' },
  'threats.attackSources': { he: 'מקורות תקיפה', en: 'Attack Sources' },

  // Forensics
  'forensics.title': { he: 'חקירות', en: 'Forensics' },
  'forensics.search': { he: 'חיפוש בלוגים...', en: 'Search logs...' },
  'forensics.severity': { he: 'חומרה', en: 'Severity' },
  'forensics.allSeverities': { he: 'כל הרמות', en: 'All Severities' },
  'forensics.timestamp': { he: 'זמן', en: 'Timestamp' },
  'forensics.source': { he: 'מקור', en: 'Source' },
  'forensics.application': { he: 'אפליקציה', en: 'Application' },
  'forensics.message': { he: 'הודעה', en: 'Message' },
  'forensics.export': { he: 'ייצוא CSV', en: 'Export CSV' },
  'forensics.refresh': { he: 'רענון אוטומטי', en: 'Auto Refresh' },
  'forensics.showing': { he: 'מציג', en: 'Showing' },
  'forensics.of': { he: 'מתוך', en: 'of' },
  'forensics.prev': { he: 'הקודם', en: 'Previous' },
  'forensics.next': { he: 'הבא', en: 'Next' },
  'forensics.noLogs': { he: 'לא נמצאו לוגים', en: 'No logs found' },

  // Sources
  'sources.title': { he: 'מקורות', en: 'Sources' },
  'sources.device': { he: 'מכשיר', en: 'Device' },
  'sources.lastSeen': { he: 'נראה לאחרונה', en: 'Last Seen' },
  'sources.logCount': { he: 'מספר לוגים', en: 'Log Count' },
  'sources.topSeverity': { he: 'חומרה גבוהה', en: 'Top Severity' },
  'sources.status': { he: 'סטטוס', en: 'Status' },
  'sources.active': { he: 'פעיל', en: 'Active' },
  'sources.inactive': { he: 'לא פעיל', en: 'Inactive' },
  'sources.noSources': { he: 'לא נמצאו מקורות', en: 'No sources found' },

  // Settings
  'settings.title': { he: 'הגדרות', en: 'Settings' },
  'settings.language': { he: 'שפה', en: 'Language' },
  'settings.hebrew': { he: 'עברית', en: 'Hebrew' },
  'settings.english': { he: 'אנגלית', en: 'English' },
  'settings.timezone': { he: 'אזור זמן', en: 'Timezone' },
  'settings.retention': { he: 'שמירת לוגים (ימים)', en: 'Log Retention (days)' },
  'settings.clientInfo': { he: 'פרטי לקוח', en: 'Client Info' },
  'settings.clientName': { he: 'שם לקוח', en: 'Client Name' },
  'settings.clientId': { he: 'מזהה לקוח', en: 'Client ID' },
  'settings.opensearch': { he: 'סטטוס OpenSearch', en: 'OpenSearch Status' },
  'settings.connected': { he: 'מחובר', en: 'Connected' },
  'settings.disconnected': { he: 'מנותק', en: 'Disconnected' },
  'settings.save': { he: 'שמור', en: 'Save' },
  'settings.saved': { he: 'נשמר בהצלחה', en: 'Saved successfully' },
  'settings.changePassword': { he: 'שנה סיסמה', en: 'Change Password' },
  'settings.newPassword': { he: 'סיסמה חדשה', en: 'New Password' },
  'settings.confirmPassword': { he: 'אשר סיסמה', en: 'Confirm Password' },

  // Time ranges
  'time.15m': { he: '15 דקות', en: '15 min' },
  'time.1h': { he: 'שעה', en: '1 hour' },
  'time.6h': { he: '6 שעות', en: '6 hours' },
  'time.24h': { he: '24 שעות', en: '24 hours' },
  'time.7d': { he: '7 ימים', en: '7 days' },
  'time.30d': { he: '30 יום', en: '30 days' },

  // Severity names
  'severity.emergency': { he: 'חירום', en: 'Emergency' },
  'severity.alert': { he: 'התרעה', en: 'Alert' },
  'severity.critical': { he: 'קריטי', en: 'Critical' },
  'severity.error': { he: 'שגיאה', en: 'Error' },
  'severity.warning': { he: 'אזהרה', en: 'Warning' },
  'severity.notice': { he: 'הודעה', en: 'Notice' },
  'severity.info': { he: 'מידע', en: 'Info' },
  'severity.debug': { he: 'דיבאג', en: 'Debug' },

  // Common
  'common.loading': { he: 'טוען...', en: 'Loading...' },
  'common.error': { he: 'שגיאה', en: 'Error' },
  'common.noData': { he: 'אין נתונים', en: 'No data' },
  'common.logs': { he: 'לוגים', en: 'logs' },
} as const

export type TranslationKey = keyof typeof translations

export function t(key: TranslationKey, locale: Locale): string {
  return translations[key]?.[locale] || key
}

export function getDirection(locale: Locale): 'rtl' | 'ltr' {
  return locale === 'he' ? 'rtl' : 'ltr'
}
