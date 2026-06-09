import React from 'react';
import Layout from '@theme/Layout';
import Link from '@docusaurus/Link';

const anomalyDimensions = [
  ['Observation', 'Point, contextual, collective, conditional, and residual deviations.'],
  ['Time', 'Trend, level, variance, periodicity, sequence, and change-point behavior.'],
  ['Distribution', 'Drift, tail, entropy, modality, quantile, and dispersion changes.'],
  ['Structure', 'Multivariate, graph, relationship, spatial, and cross-view anomalies.'],
];

const telemetryDomains = [
  'Endpoint and operating systems',
  'Identity and authentication',
  'Network infrastructure and traffic',
  'Applications, APIs, and databases',
  'Cloud, containers, and orchestration',
  'Security controls and observability',
];

export default function Home() {
  return (
    <Layout
      title="Anomaly Detection Atlas"
      description="A vendor-neutral reference for statistical anomaly types and security log sources."
    >
      <header className="atlas-hero">
        <div className="container atlas-hero__content">
          <div className="atlas-eyebrow">Detection Engineering Reference</div>
          <h1>Understand deviation.<br />Measure observable change.</h1>
          <p>
            A structured foundation for reasoning about anomaly detection before selecting models,
            writing rules, or mapping behavior to adversary techniques.
          </p>
          <div className="atlas-actions">
            <Link className="button button--primary button--lg" to="/attack-activity-log-source-catalog">
              Explore ATT&CK activities
            </Link>
            <Link className="button button--primary button--lg" to="/statistical-anomaly-taxonomy">
              Explore 118 anomaly types
            </Link>
            <Link className="button button--secondary button--lg" to="/security-log-source-taxonomy">
              Explore 175 log sources
            </Link>
          </div>
          <div className="atlas-signal" aria-hidden="true">
            {[18, 24, 20, 34, 26, 52, 31, 28, 64, 37, 30, 25, 22, 18].map((height, index) => (
              <span key={index} style={{ height }} />
            ))}
            <i />
          </div>
        </div>
      </header>

      <main>
        <section className="atlas-section atlas-section--surface">
          <div className="container">
            <div className="atlas-section-heading">
              <span className="atlas-index">00</span>
              <div>
                <span className="atlas-kicker">Activity and observability</span>
                <h2>ATT&CK Activity Catalog</h2>
              </div>
              <strong>Enterprise tactics</strong>
            </div>
            <p style={{ maxWidth: 760, color: 'var(--atlas-muted)', lineHeight: 1.8 }}>
              Browse suspicious and malicious activity by MITRE ATT&CK tactic. Every activity
              includes inline links to the vendor-neutral log sources capable of reporting it.
            </p>
            <Link className="atlas-text-link" to="/attack-activity-log-source-catalog">
              Open the ATT&CK activity and log-source catalog →
            </Link>
          </div>
        </section>

        <section className="atlas-section">
          <div className="container">
            <div className="atlas-section-heading">
              <span className="atlas-index">00.5</span>
              <div>
                <span className="atlas-kicker">Deterministic detection</span>
                <h2>Basic Detection Rule Catalog</h2>
              </div>
              <strong>Thresholds · signatures · state changes</strong>
            </div>
            <p style={{ maxWidth: 760, color: 'var(--atlas-muted)', lineHeight: 1.8 }}>
              Technique-level algorithmic detection logic using exact matches, fixed thresholds,
              allowlists, state changes, and bounded-window correlations, with direct links to the
              required telemetry sources.
            </p>
            <Link className="atlas-text-link" to="/attack-basic-detection-rule-catalog">
              Open the basic detection rule catalog →
            </Link>
          </div>
        </section>

        <section className="atlas-section atlas-intro">
          <div className="container atlas-two-column">
            <div>
              <span className="atlas-kicker">Statistical detection</span>
              <h2>Explain malicious activity as measurable deviation.</h2>
            </div>
            <div>
              <p>
                The activity-to-anomaly catalog maps ATT&CK-aligned behavior to its comparison unit,
                expected baseline, measurable deviation, applicable anomaly types, and supporting
                telemetry. It also identifies activity better handled by signatures or policy rules.
              </p>
              <Link className="atlas-text-link" to="/attack-statistical-anomaly-mapping">
                Open the activity-to-anomaly mapping catalog →
              </Link>
            </div>
          </div>
        </section>

        <section className="atlas-section">
          <div className="container">
            <div className="atlas-section-heading">
              <span className="atlas-index">01</span>
              <div>
                <span className="atlas-kicker">Statistical foundation</span>
                <h2>Statistical Anomaly Taxonomy</h2>
              </div>
              <strong>118 types</strong>
            </div>
            <div className="atlas-grid">
              {anomalyDimensions.map(([title, body]) => (
                <article className="atlas-card" key={title}>
                  <h3>{title}</h3>
                  <p>{body}</p>
                </article>
              ))}
            </div>
            <Link className="atlas-text-link" to="/statistical-anomaly-taxonomy">
              Open the complete statistical taxonomy →
            </Link>
          </div>
        </section>

        <section className="atlas-section atlas-section--surface">
          <div className="container">
            <div className="atlas-section-heading">
              <span className="atlas-index">02</span>
              <div>
                <span className="atlas-kicker">Observable evidence</span>
                <h2>Security Log Source Taxonomy</h2>
              </div>
              <strong>175 sources</strong>
            </div>
            <div className="atlas-domain-list">
              {telemetryDomains.map((domain, index) => (
                <div key={domain}>
                  <span>{String(index + 1).padStart(2, '0')}</span>
                  <p>{domain}</p>
                </div>
              ))}
            </div>
            <Link className="atlas-text-link" to="/security-log-source-taxonomy">
              Open the complete log-source taxonomy →
            </Link>
          </div>
        </section>

        <section className="atlas-section">
          <div className="container atlas-principles">
            <span className="atlas-kicker">Working principles</span>
            <h2>Model the behavior before choosing the detector.</h2>
            <div>
              <p><strong>Define the baseline.</strong> State the population, entity, peer group, context, and time window.</p>
              <p><strong>Verify observability.</strong> Confirm that a source records the activity and retains the required detail.</p>
              <p><strong>Separate rarity from meaning.</strong> Statistical deviation is evidence to investigate, not a conclusion.</p>
            </div>
          </div>
        </section>
      </main>
    </Layout>
  );
}
