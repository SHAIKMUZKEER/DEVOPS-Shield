import React, { useState } from 'react';

const ModernDashboard = () => {
  // Removed unused useEffect import
  
  const [metrics] = useState({
    threatsBlocked: { value: 2847, trend: '+12%', isPositive: true }, // Added explicit status
    activeSessions: { value: 156, trend: '+8%', isPositive: true },
    uptime: { value: '99.94%', trend: '+0.02%', isPositive: true },
    failedLogins: { value: 23, trend: '-45%', isPositive: true } // Decreasing failed logins is good
  });

  const [recentAlerts] = useState([
    { id: 1, type: 'Critical', message: 'Potential SQL injection detected on API endpoint', time: '2 minutes ago', severity: 'high' },
    { id: 2, type: 'Warning', message: 'Unusual login attempt from new location', time: '15 minutes ago', severity: 'medium' },
    { id: 3, type: 'Info', message: 'Daily backup completed successfully', time: '1 hour ago', severity: 'low' },
    { id: 4, type: 'Critical', message: 'DDoS attack attempt blocked', time: '3 hours ago', severity: 'high' },
  ]);

  const [securityEvents] = useState([
    { id: 1, event: 'Authentication Failed', user: 'user@example.com', time: '10:45 AM', count: 5 },
    { id: 2, event: 'Malicious Pattern Detected', source: '192.168.1.100', time: '10:32 AM', count: 1 },
    { id: 3, event: 'Webhook Signature Invalid', endpoint: '/api/webhook', time: '10:15 AM', count: 3 },
    { id: 4, event: 'Brute Force Attempt', user: 'admin@example.com', time: '09:58 AM', count: 12 },
  ]);

  const getSeverityColor = (severity) => {
    switch(severity) {
      case 'high': return '#ef4444';
      case 'medium': return '#f59e0b';
      case 'low': return '#10b981';
      default: return '#6b7280';
    }
  };

  // Helper for trend color to fix the "Uptime up is bad" logic error
  const getTrendColor = (isPositive) => isPositive ? '#10b981' : '#ef4444';

  return (
    <div style={{ 
      minHeight: '100vh', // Fix: Ensures background covers full screen
      padding: '2rem 0', 
      background: 'linear-gradient(135deg, #0f172a 0%, #1e293b 50%, #0f172a 100%)',
      color: '#f8fafc', // Fix: Sets default text color to white/slate-50 so it's visible
      fontFamily: 'system-ui, -apple-system, sans-serif'
    }}>
      <div style={{ maxWidth: '1600px', margin: '0 auto', padding: '0 1.5rem' }}>
        
        {/* Dashboard Header */}
        <div style={{ marginBottom: '2rem' }}>
          <h1 style={{ fontSize: '2.25rem', fontWeight: 'bold', marginBottom: '0.5rem', color: '#fff' }}>Security Dashboard</h1>
          <p style={{ color: '#9ca3af', fontSize: '1.125rem' }}>Real-time threat detection and system monitoring</p>
        </div>

        {/* Metrics Grid */}
        <div style={{ 
          display: 'grid', 
          gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))',
          gap: '1.5rem',
          marginBottom: '2rem'
        }}>
          {[
            { label: 'Threats Blocked', ...metrics.threatsBlocked, icon: '🛡️' },
            { label: 'Active Sessions', ...metrics.activeSessions, icon: '👥' },
            { label: 'System Uptime', ...metrics.uptime, icon: '⬆️' },
            { label: 'Failed Logins', ...metrics.failedLogins, icon: '🚫' }
          ].map((metric, idx) => (
            <div 
              key={idx} 
              style={{
                background: 'rgba(30, 41, 59, 0.5)',
                border: '1px solid rgba(168, 85, 247, 0.3)',
                borderRadius: '0.75rem',
                padding: '1.5rem',
                transition: 'all 0.3s ease',
                cursor: 'pointer'
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.background = 'rgba(30, 41, 59, 0.8)';
                e.currentTarget.style.borderColor = 'rgba(59, 130, 246, 0.6)';
                e.currentTarget.style.transform = 'translateY(-2px)'; // Added subtle lift effect
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.background = 'rgba(30, 41, 59, 0.5)';
                e.currentTarget.style.borderColor = 'rgba(168, 85, 247, 0.3)';
                e.currentTarget.style.transform = 'translateY(0)';
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '1rem' }}>
                <div>
                  <p style={{ color: '#9ca3af', fontSize: '0.875rem', marginBottom: '0.5rem' }}>{metric.label}</p>
                  <div style={{ fontSize: '1.875rem', fontWeight: 'bold', color: '#fff' }}>{metric.value}</div>
                </div>
                <div style={{ fontSize: '1.75rem' }}>{metric.icon}</div>
              </div>
              <div style={{ 
                color: getTrendColor(metric.isPositive), // Fix: Uses explicit positive/negative status
                fontSize: '0.875rem',
                fontWeight: '500'
              }}>
                {metric.trend} from yesterday
              </div>
            </div>
          ))}
        </div>

        {/* Recent Alerts Section */}
        <div style={{ marginBottom: '2rem' }}>
          <h2 style={{ fontSize: '1.5rem', fontWeight: 'bold', marginBottom: '1rem', color: '#fff' }}>Recent Security Alerts</h2>
          <div style={{
            background: 'rgba(30, 41, 59, 0.5)',
            border: '1px solid rgba(168, 85, 247, 0.3)',
            borderRadius: '0.75rem',
            overflow: 'hidden'
          }}>
            <div style={{ maxHeight: '400px', overflowY: 'auto' }}>
              {recentAlerts.map((alert, idx) => (
                <div 
                  key={alert.id} // Fix: Use unique ID instead of index
                  style={{
                    padding: '1.5rem',
                    borderBottom: idx !== recentAlerts.length - 1 ? '1px solid rgba(168, 85, 247, 0.1)' : 'none',
                    display: 'flex',
                    alignItems: 'flex-start',
                    gap: '1rem',
                    transition: 'background-color 0.2s'
                  }}
                  onMouseEnter={(e) => e.currentTarget.style.backgroundColor = 'rgba(59, 130, 246, 0.1)'}
                  onMouseLeave={(e) => e.currentTarget.style.backgroundColor = 'transparent'}
                >
                  <div style={{
                    width: '12px',
                    height: '12px',
                    borderRadius: '50%',
                    backgroundColor: getSeverityColor(alert.severity),
                    marginTop: '0.375rem',
                    flexShrink: 0,
                    boxShadow: `0 0 8px ${getSeverityColor(alert.severity)}` // Added glow for visibility
                  }}/>
                  <div style={{ flex: 1 }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.25rem' }}>
                      <span style={{ fontWeight: 'bold', color: alert.severity === 'high' ? '#ef4444' : (alert.severity === 'medium' ? '#f59e0b' : '#10b981') }}>
                        {alert.type}
                      </span>
                      <span style={{ fontSize: '0.875rem', color: '#9ca3af' }}>{alert.time}</span>
                    </div>
                    <p style={{ color: '#e2e8f0', fontSize: '0.9375rem' }}>{alert.message}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Security Events Section */}
        <div>
          <h2 style={{ fontSize: '1.5rem', fontWeight: 'bold', marginBottom: '1rem', color: '#fff' }}>Security Events</h2>
          <div style={{
            background: 'rgba(30, 41, 59, 0.5)',
            border: '1px solid rgba(168, 85, 247, 0.3)',
            borderRadius: '0.75rem',
            overflow: 'hidden'
          }}>
            <div style={{ overflowX: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', color: '#e2e8f0' }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid rgba(168, 85, 247, 0.2)', background: 'rgba(30, 41, 59, 0.8)' }}>
                    <th style={{ padding: '1.25rem 1.5rem', textAlign: 'left', fontWeight: '600', color: '#9ca3af', fontSize: '0.875rem' }}>Event Type</th>
                    <th style={{ padding: '1.25rem 1.5rem', textAlign: 'left', fontWeight: '600', color: '#9ca3af', fontSize: '0.875rem' }}>Details</th>
                    <th style={{ padding: '1.25rem 1.5rem', textAlign: 'left', fontWeight: '600', color: '#9ca3af', fontSize: '0.875rem' }}>Time</th>
                    <th style={{ padding: '1.25rem 1.5rem', textAlign: 'center', fontWeight: '600', color: '#9ca3af', fontSize: '0.875rem' }}>Count</th>
                  </tr>
                </thead>
                <tbody>
                  {securityEvents.map((event, idx) => (
                    <tr 
                      key={event.id} // Fix: Use unique ID
                      style={{
                        borderBottom: idx !== securityEvents.length - 1 ? '1px solid rgba(168, 85, 247, 0.1)' : 'none',
                        transition: 'background-color 0.2s'
                      }}
                      onMouseEnter={(e) => e.currentTarget.style.backgroundColor = 'rgba(59, 130, 246, 0.1)'}
                      onMouseLeave={(e) => e.currentTarget.style.backgroundColor = 'transparent'}
                    >
                      <td style={{ padding: '1.25rem 1.5rem', fontWeight: '500' }}>{event.event}</td>
                      <td style={{ padding: '1.25rem 1.5rem', color: '#94a3b8', fontSize: '0.9375rem' }}>
                        {event.user || event.source || event.endpoint}
                      </td>
                      <td style={{ padding: '1.25rem 1.5rem', color: '#9ca3af', fontSize: '0.9375rem' }}>{event.time}</td>
                      <td style={{ padding: '1.25rem 1.5rem', textAlign: 'center' }}>
                        <span style={{
                          background: event.count > 5 ? 'rgba(239, 68, 68, 0.2)' : 'rgba(59, 130, 246, 0.2)',
                          color: event.count > 5 ? '#ef4444' : '#3b82f6',
                          padding: '0.375rem 0.75rem',
                          borderRadius: '0.375rem',
                          fontSize: '0.875rem',
                          fontWeight: '600',
                          border: `1px solid ${event.count > 5 ? 'rgba(239, 68, 68, 0.3)' : 'rgba(59, 130, 246, 0.3)'}`
                        }}>
                          {event.count}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ModernDashboard;