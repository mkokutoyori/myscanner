import React, { useEffect, useState } from 'react';
import { getAssets, Asset } from '../services/api';

const Assets: React.FC = () => {
  const [assets, setAssets] = useState<Asset[]>([]);
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);

  useEffect(() => {
    fetchAssets();
  }, [page]);

  const fetchAssets = async () => {
    setLoading(true);
    try {
      const data = await getAssets(page, 50);
      setAssets(data.assets);
      setTotal(data.total);
    } catch (error) {
      console.error('Error fetching assets:', error);
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return <div className="loading">Loading assets...</div>;
  }

  return (
    <div className="assets-page">
      <div className="page-header">
        <h1>Assets</h1>
        <div className="page-info">
          <span>Total: {total}</span>
        </div>
      </div>

      {assets.length === 0 ? (
        <div className="empty-state">
          <p>No assets discovered yet. Run a discovery scan to get started.</p>
        </div>
      ) : (
        <>
          <div className="table-container">
            <table className="data-table">
              <thead>
                <tr>
                  <th>IP Address</th>
                  <th>Hostname</th>
                  <th>Type</th>
                  <th>OS</th>
                  <th>Open Ports</th>
                  <th>Findings</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {assets.map((asset) => (
                  <tr key={asset.id}>
                    <td>
                      <strong>{asset.ip_address}</strong>
                    </td>
                    <td>{asset.hostname || '-'}</td>
                    <td>
                      <span className="badge">{asset.asset_type}</span>
                    </td>
                    <td>
                      {asset.os_family ? (
                        <div className="os-info">
                          <div>{asset.os_family}</div>
                          {asset.os_version && <div className="text-sm">{asset.os_version}</div>}
                        </div>
                      ) : '-'}
                    </td>
                    <td>
                      <span className="badge">{asset.open_ports?.length || 0} ports</span>
                    </td>
                    <td>
                      <div className="findings-info">
                        <span className="total">{asset.finding_count || 0} total</span>
                        {(asset.critical_findings || 0) > 0 && (
                          <span className="critical">
                            {asset.critical_findings} critical
                          </span>
                        )}
                      </div>
                    </td>
                    <td>
                      <span className={`status-badge ${asset.is_active ? 'active' : 'inactive'}`}>
                        {asset.is_active ? 'Active' : 'Inactive'}
                      </span>
                    </td>
                  </tr>
                ))}
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
              disabled={assets.length < 50}
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

export default Assets;
