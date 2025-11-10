import React, { useEffect, useState } from 'react';
import { getFindings, Finding, resolveFinding } from '../services/api';

const Findings: React.FC = () => {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);
  const [selectedSeverity, setSelectedSeverity] = useState<string>('');

  useEffect(() => {
    fetchFindings();
  }, [page, selectedSeverity]);

  const fetchFindings = async () => {
    setLoading(true);
    try {
      const data = await getFindings(page, 50, selectedSeverity);
      setFindings(data.findings);
      setTotal(data.total);
    } catch (error) {
      console.error('Error fetching findings:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleResolve = async (id: number) => {
    try {
      await resolveFinding(id);
      fetchFindings();
    } catch (error) {
      console.error('Error resolving finding:', error);
    }
  };

  if (loading) {
    return <div className="loading">Loading findings...</div>;
  }

  return (
    <div className="findings-page">
      <div className="page-header">
        <h1>Findings</h1>
        <div className="filters">
          <select
            value={selectedSeverity}
            onChange={(e) => setSelectedSeverity(e.target.value)}
            className="filter-select"
          >
            <option value="">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="info">Info</option>
          </select>
        </div>
      </div>

      {findings.length === 0 ? (
        <div className="empty-state">
          <p>No findings yet. Run scans to discover vulnerabilities.</p>
        </div>
      ) : (
        <>
          <div className="findings-list">
            {findings.map((finding) => (
              <div key={finding.id} className={`finding-card ${finding.severity}`}>
                <div className="finding-header">
                  <div className="finding-title">
                    <h3>{finding.title}</h3>
                    <span className={`severity-badge ${finding.severity}`}>
                      {finding.severity}
                    </span>
                    {finding.is_resolved && (
                      <span className="status-badge resolved">Resolved</span>
                    )}
                  </div>
                  {!finding.is_resolved && (
                    <button
                      onClick={() => handleResolve(finding.id)}
                      className="btn btn-sm btn-resolve"
                    >
                      Mark Resolved
                    </button>
                  )}
                </div>

                <div className="finding-info">
                  <div className="info-item">
                    <strong>Asset:</strong>{' '}
                    {finding.asset_ip}
                    {finding.asset_hostname && ` (${finding.asset_hostname})`}
                  </div>
                  {finding.affected_service && (
                    <div className="info-item">
                      <strong>Service:</strong> {finding.affected_service}
                      {finding.affected_port && ` on port ${finding.affected_port}`}
                    </div>
                  )}
                  {finding.cvss_score && (
                    <div className="info-item">
                      <strong>CVSS Score:</strong> {finding.cvss_score}
                    </div>
                  )}
                  {finding.cve_ids && finding.cve_ids.length > 0 && (
                    <div className="info-item">
                      <strong>CVE IDs:</strong>{' '}
                      {finding.cve_ids.map((cve, idx) => (
                        <span key={idx} className="badge badge-cve">
                          {cve}
                        </span>
                      ))}
                    </div>
                  )}
                </div>

                <div className="finding-description">
                  <strong>Description:</strong>
                  <p>{finding.description}</p>
                </div>

                {finding.evidence && (
                  <div className="finding-evidence">
                    <strong>Evidence:</strong>
                    <pre>{finding.evidence}</pre>
                  </div>
                )}

                {finding.remediation && (
                  <div className="finding-remediation">
                    <strong>Remediation:</strong>
                    <p>{finding.remediation}</p>
                  </div>
                )}

                <div className="finding-footer">
                  <span className="discovered-date">
                    Discovered: {new Date(finding.discovered_at).toLocaleString()}
                  </span>
                </div>
              </div>
            ))}
          </div>

          {/* Pagination */}
          <div className="pagination">
            <button
              onClick={() => setPage(page - 1)}
              disabled={page === 1}
              className="pagination-btn"
            >
              Previous
            </button>
            <span className="page-info">
              Page {page} (Total: {total})
            </span>
            <button
              onClick={() => setPage(page + 1)}
              disabled={findings.length < 50}
              className="pagination-btn"
            >
              Next
            </button>
          </div>
        </>
      )}
    </div>
  );
};

export default Findings;
