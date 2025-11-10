import React, { useEffect, useState } from 'react';
import { getScans, createDiscoveryScan, Scan } from '../services/api';

const Scans: React.FC = () => {
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);
  const [showNewScan, setShowNewScan] = useState(false);
  const [newScanTargets, setNewScanTargets] = useState('');
  const [creating, setCreating] = useState(false);

  useEffect(() => {
    fetchScans();
  }, [page]);

  const fetchScans = async () => {
    setLoading(true);
    try {
      const data = await getScans(page, 50);
      setScans(data.scans);
      setTotal(data.total);
    } catch (error) {
      console.error('Error fetching scans:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleCreateScan = async (e: React.FormEvent) => {
    e.preventDefault();
    setCreating(true);

    try {
      const targets = newScanTargets.split('\n').filter(t => t.trim() !== '');
      await createDiscoveryScan(targets);
      setNewScanTargets('');
      setShowNewScan(false);
      fetchScans();
    } catch (error) {
      console.error('Error creating scan:', error);
      alert('Failed to create scan');
    } finally {
      setCreating(false);
    }
  };

  if (loading) {
    return <div className="loading">Loading scans...</div>;
  }

  return (
    <div className="scans-page">
      <div className="page-header">
        <h1>Scans</h1>
        <button
          onClick={() => setShowNewScan(!showNewScan)}
          className="btn btn-primary"
        >
          + New Discovery Scan
        </button>
      </div>

      {/* New Scan Form */}
      {showNewScan && (
        <div className="new-scan-form">
          <h3>Create Discovery Scan</h3>
          <form onSubmit={handleCreateScan}>
            <div className="form-group">
              <label htmlFor="targets">Targets (one per line)</label>
              <textarea
                id="targets"
                value={newScanTargets}
                onChange={(e) => setNewScanTargets(e.target.value)}
                placeholder="192.168.1.0/24&#10;10.0.0.1&#10;scanme.nmap.org"
                rows={5}
                required
              />
              <p className="help-text">
                Enter IP addresses, CIDR ranges, or hostnames (one per line)
              </p>
            </div>
            <div className="form-actions">
              <button type="submit" className="btn btn-primary" disabled={creating}>
                {creating ? 'Creating...' : 'Start Scan'}
              </button>
              <button
                type="button"
                className="btn btn-secondary"
                onClick={() => setShowNewScan(false)}
              >
                Cancel
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Scans Table */}
      {scans.length === 0 ? (
        <div className="empty-state">
          <p>No scans yet. Create your first discovery scan to get started.</p>
        </div>
      ) : (
        <>
          <div className="table-container">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Type</th>
                  <th>Status</th>
                  <th>Targets</th>
                  <th>Assets Found</th>
                  <th>Findings</th>
                  <th>Created</th>
                  <th>Duration</th>
                </tr>
              </thead>
              <tbody>
                {scans.map((scan) => {
                  const duration = scan.started_at && scan.completed_at
                    ? Math.round((new Date(scan.completed_at).getTime() - new Date(scan.started_at).getTime()) / 1000)
                    : null;

                  return (
                    <tr key={scan.id}>
                      <td>
                        <strong>{scan.name}</strong>
                        {scan.description && <div className="text-sm">{scan.description}</div>}
                      </td>
                      <td>
                        <span className="badge">{scan.scan_type}</span>
                      </td>
                      <td>
                        <span className={`status-badge ${scan.status}`}>
                          {scan.status}
                        </span>
                      </td>
                      <td>
                        <span className="badge">{scan.targets.length} targets</span>
                      </td>
                      <td>{scan.total_assets}</td>
                      <td>{scan.total_findings}</td>
                      <td>{new Date(scan.created_at).toLocaleString()}</td>
                      <td>{duration ? `${duration}s` : '-'}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
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
            <span className="page-info">Page {page}</span>
            <button
              onClick={() => setPage(page + 1)}
              disabled={scans.length < 50}
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

export default Scans;
