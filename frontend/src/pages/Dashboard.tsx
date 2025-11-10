import React, { useEffect, useState } from 'react';
import { getAssetStats, getScanStats, getFindingStats } from '../services/api';

const Dashboard: React.FC = () => {
  const [assetStats, setAssetStats] = useState<any>(null);
  const [scanStats, setScanStats] = useState<any>(null);
  const [findingStats, setFindingStats] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchStats = async () => {
      try {
        const [assets, scans, findings] = await Promise.all([
          getAssetStats(),
          getScanStats(),
          getFindingStats(),
        ]);
        setAssetStats(assets);
        setScanStats(scans);
        setFindingStats(findings);
      } catch (error) {
        console.error('Error fetching stats:', error);
      } finally {
        setLoading(false);
      }
    };

    fetchStats();
  }, []);

  if (loading) {
    return <div className="loading">Loading dashboard...</div>;
  }

  return (
    <div className="dashboard">
      <h1>Dashboard</h1>

      <div className="stats-grid">
        {/* Assets Stats */}
        <div className="stat-card">
          <h2>Assets</h2>
          <div className="stat-value">{assetStats?.total_assets || 0}</div>
          <div className="stat-label">Total Assets</div>
        </div>

        {/* Scans Stats */}
        <div className="stat-card">
          <h2>Scans</h2>
          <div className="stat-value">{scanStats?.total_scans || 0}</div>
          <div className="stat-label">Total Scans</div>
        </div>

        {/* Findings Stats */}
        <div className="stat-card critical">
          <h2>Critical Findings</h2>
          <div className="stat-value">{findingStats?.findings_by_severity?.critical || 0}</div>
          <div className="stat-label">Unresolved</div>
        </div>

        <div className="stat-card high">
          <h2>High Findings</h2>
          <div className="stat-value">{findingStats?.findings_by_severity?.high || 0}</div>
          <div className="stat-label">Unresolved</div>
        </div>
      </div>

      {/* Detailed Stats */}
      <div className="details-grid">
        <div className="details-card">
          <h3>Assets by Type</h3>
          <ul>
            {assetStats?.assets_by_type && Object.entries(assetStats.assets_by_type).map(([type, count]) => (
              <li key={type}>
                <span className="type-name">{type}</span>
                <span className="type-count">{count as number}</span>
              </li>
            ))}
          </ul>
        </div>

        <div className="details-card">
          <h3>Scans by Status</h3>
          <ul>
            {scanStats?.scans_by_status && Object.entries(scanStats.scans_by_status).map(([status, count]) => (
              <li key={status}>
                <span className="status-name">{status}</span>
                <span className="status-count">{count as number}</span>
              </li>
            ))}
          </ul>
        </div>

        <div className="details-card">
          <h3>Findings by Severity</h3>
          <ul>
            {findingStats?.findings_by_severity && Object.entries(findingStats.findings_by_severity).map(([severity, count]) => (
              <li key={severity}>
                <span className={`severity-badge ${severity}`}>{severity}</span>
                <span className="severity-count">{count as number}</span>
              </li>
            ))}
          </ul>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
