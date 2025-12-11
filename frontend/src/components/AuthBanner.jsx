import React from 'react';
import { formatDateTime } from '../utils/dateHelpers';

const AuthBanner = ({ session, onReconnect, onDisconnect }) => {
  if (!session) return null;
  const scopeList = session.scopes || [];

  return (
    <section className="auth-banner" aria-live="polite">
      <div className="auth-banner-main">
        <div>
          <span className="auth-label">Identity provider</span>
          <h2>{session.provider} OAuth</h2>
          <p className="muted">
            Connected as <strong>{session.account}</strong> using application <strong>{session.oauthApp}</strong>. Tokens remain server side.
          </p>
        </div>
        <div className={`auth-status ${session.status === 'Connected' ? 'status-online' : 'status-offline'}`}>
          {session.status}
        </div>
      </div>

      <div className="auth-banner-meta">
        <div>
          <span className="auth-label">Scopes</span>
          <div className="scope-chips">
            {scopeList.map((scope) => (
              <span key={scope} className="scope-chip">{scope}</span>
            ))}
          </div>
        </div>
        <div>
          <span className="auth-label">PKCE enforced</span>
          <span>{session.pkce ? 'Yes' : 'No'}</span>
        </div>
        <div>
          <span className="auth-label">Least privilege</span>
          <span>{session.leastPrivilege ? 'Yes' : 'Review'}</span>
        </div>
        <div>
          <span className="auth-label">Token storage</span>
          <span>{session.encryptedStorage}</span>
        </div>
        <div>
          <span className="auth-label">Frontend token exposure</span>
          <span>{session.tokensExposedToFrontend ? 'Sensitive' : 'Never exposed'}</span>
        </div>
        <div>
          <span className="auth-label">Last verification</span>
          <span>{formatDateTime(session.lastVerification)}</span>
        </div>
      </div>

      <div className="auth-banner-actions">
        <button type="button" className="btn-outline" onClick={() => onReconnect?.(session.provider)}>Re-authenticate</button>
        <button type="button" className="btn-ghost" onClick={() => onDisconnect?.(session.provider)}>Disconnect</button>
      </div>
    </section>
  );
};

export default AuthBanner;
