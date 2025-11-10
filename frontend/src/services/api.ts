import axios from 'axios';

const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';
const API_V1_PREFIX = '/api/v1';

const api = axios.create({
  baseURL: `${API_URL}${API_V1_PREFIX}`,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Types
export interface Asset {
  id: number;
  ip_address: string;
  hostname?: string;
  asset_type: string;
  os_family?: string;
  os_version?: string;
  open_ports: number[];
  services: { [key: string]: any };
  finding_count?: number;
  critical_findings?: number;
  is_active: boolean;
  first_seen: string;
  last_seen?: string;
}

export interface Scan {
  id: number;
  name: string;
  description?: string;
  scan_type: string;
  status: string;
  targets: string[];
  created_at: string;
  started_at?: string;
  completed_at?: string;
  total_assets: number;
  total_findings: number;
  requires_approval: boolean;
  approval_status?: string;
}

export interface Finding {
  id: number;
  scan_id: number;
  asset_id: number;
  asset_ip?: string;
  asset_hostname?: string;
  title: string;
  description: string;
  severity: string;
  cve_ids: string[];
  cvss_score?: number;
  affected_service?: string;
  affected_port?: number;
  evidence?: string;
  remediation?: string;
  is_resolved: boolean;
  discovered_at: string;
}

// API Functions
export const getAssets = async (page: number = 1, pageSize: number = 50) => {
  const response = await api.get(`/assets?page=${page}&page_size=${pageSize}`);
  return response.data;
};

export const getAsset = async (id: number) => {
  const response = await api.get(`/assets/${id}`);
  return response.data;
};

export const getAssetStats = async () => {
  const response = await api.get('/assets/stats/summary');
  return response.data;
};

export const getScans = async (page: number = 1, pageSize: number = 50) => {
  const response = await api.get(`/scans?page=${page}&page_size=${pageSize}`);
  return response.data;
};

export const getScan = async (id: number) => {
  const response = await api.get(`/scans/${id}`);
  return response.data;
};

export const createDiscoveryScan = async (targets: string[]) => {
  const response = await api.post('/scans/discovery', { targets });
  return response.data;
};

export const getScanStats = async () => {
  const response = await api.get('/scans/stats/summary');
  return response.data;
};

export const getFindings = async (page: number = 1, pageSize: number = 50, severity?: string) => {
  let url = `/findings?page=${page}&page_size=${pageSize}`;
  if (severity) {
    url += `&severity=${severity}`;
  }
  const response = await api.get(url);
  return response.data;
};

export const getFinding = async (id: number) => {
  const response = await api.get(`/findings/${id}`);
  return response.data;
};

export const getFindingStats = async () => {
  const response = await api.get('/findings/stats/summary');
  return response.data;
};

export const resolveFinding = async (id: number) => {
  const response = await api.patch(`/findings/${id}/resolve`);
  return response.data;
};

export const markFalsePositive = async (id: number) => {
  const response = await api.patch(`/findings/${id}/false-positive`);
  return response.data;
};

export const getHealth = async () => {
  const response = await api.get('/health');
  return response.data;
};

// Credentials API
export interface Credential {
  id: number;
  name: string;
  description?: string;
  credential_type: string;
  username?: string;
  has_password: boolean;
  has_private_key: boolean;
  has_api_key: boolean;
  created_at: string;
}

export const getCredentials = async (page: number = 1, pageSize: number = 50) => {
  const response = await api.get(`/credentials?page=${page}&page_size=${pageSize}`);
  return response.data;
};

export const getCredential = async (id: number) => {
  const response = await api.get(`/credentials/${id}`);
  return response.data;
};

export const createCredential = async (credentialData: {
  name: string;
  description?: string;
  credential_type: string;
  username?: string;
  password?: string;
  private_key?: string;
}) => {
  const response = await api.post('/credentials', credentialData);
  return response.data;
};

export const deleteCredential = async (id: number) => {
  await api.delete(`/credentials/${id}`);
};

// Vulnerability Scans API
export const createVulnerabilityScan = async (scanData: {
  targets: string[];
  credential_id: number;
  name?: string;
  description?: string;
  plugin_name?: string;
  auto_detect_distro?: boolean;
}) => {
  const response = await api.post('/scans/vulnerability', scanData);
  return response.data;
};

export const executeScan = async (scanId: number) => {
  const response = await api.post(`/scans/${scanId}/execute`);
  return response.data;
};

// Plugins API
export const getPlugins = async () => {
  const response = await api.get('/plugins');
  return response.data;
};

export const getPlugin = async (name: string) => {
  const response = await api.get(`/plugins/${name}`);
  return response.data;
};

export default api;
