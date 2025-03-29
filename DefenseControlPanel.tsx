// DefenseControlPanel.tsx
import React, { useEffect, useState } from 'react';
import { Card, Button, ProgressBar, Badge, Table, Tabs, Tab, Form, Alert } from 'react-bootstrap';
import axios from 'axios';
import './DefenseControlPanel.css';

interface DefenseStatus {
  status: string;
  level: number;
  active_countermeasures: number;
  countermeasure_types: Record<string, number>;
  resources: Record<string, { current: number; max: number; percentage: number }>;
  last_status_change: number;
  uptime: number;
  timestamp: number;
}

interface CountermeasureData {
  id: string;
  type: string;
  threat_id: string;
  start_time: number;
  status: string;
  effectiveness: number;
}

interface DefenseControlPanelProps {
  selectedTrack: any;
  onDefenseAction: (action: string, data: any) => void;
}

const DefenseControlPanel: React.FC<DefenseControlPanelProps> = ({ selectedTrack, onDefenseAction }) => {
  const [defenseStatus, setDefenseStatus] = useState<DefenseStatus | null>(null);
  const [activeCountermeasures, setActiveCountermeasures] = useState<CountermeasureData[]>([]);
  const [availableProtocols, setAvailableProtocols] = useState<string[]>([
    'alpha', 'beta', 'gamma', 'delta', 'omega'
  ]);
  const [selectedProtocol, setSelectedProtocol] = useState('alpha');
  const [defenseLevel, setDefenseLevel] = useState(1);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);
  
  // Fetch defense status
  useEffect(() => {
    fetchDefenseStatus();
    const interval = setInterval(fetchDefenseStatus, 5000);
    
    return () => clearInterval(interval);
  }, []);
  
  const fetchDefenseStatus = async () => {
    try {
      const token = localStorage.getItem('token');
      
      const response = await axios.get('/api/defense/status', {
        headers: {
          Authorization: `Bearer ${token}`
        }
      });
      
      setDefenseStatus(response.data.status);
      setActiveCountermeasures(response.data.active_countermeasures || []);
      setDefenseLevel(response.data.status.level);
      
    } catch (err) {
      console.error('Error fetching defense status:', err);
    }
  };
  
  const handleActivateDefense = async () => {
    setLoading(true);
    setError(null);
    setSuccessMessage(null);
    
    try {
      const token = localStorage.getItem('token');
      
      const response = await axios.post('/api/defense/level', {
        level: defenseLevel
      }, {
        headers: {
          Authorization: `Bearer ${token}`
        }
      });
      
      if (response.data.success) {
        setSuccessMessage(`Defense level set to ${defenseLevel}`);
        fetchDefenseStatus();
        
        if (onDefenseAction) {
          onDefenseAction('defense_level_changed', { level: defenseLevel });
        }
      } else {
        setError(response.data.message || 'Failed to set defense level');
      }
      
    } catch (err: any) {
      setError(err.response?.data?.message || 'An error occurred');
    } finally {
      setLoading(false);
    }
  };
  
  const handleActivateProtocol = async () => {
    setLoading(true);
    setError(null);
    setSuccessMessage(null);
    
    try {
      const token = localStorage.getItem('token');
      
      const response = await axios.post('/api/defense/protocol', {
        protocol: selectedProtocol
      }, {
        headers: {
          Authorization: `Bearer ${token}`
        }
      });
      
      if (response.data.success) {
        setSuccessMessage(`Defense protocol ${selectedProtocol} activated`);
        fetchDefenseStatus();
        
        if (onDefenseAction) {
          onDefenseAction('defense_protocol_activated', { protocol: selectedProtocol });
        }
      } else {
        setError(response.data.message || 'Failed to activate protocol');
      }
      
    } catch (err: any) {
      setError(err.response?.data?.message || 'An error occurred');
    } finally {
      setLoading(false);
    }
  };
  
  const handleCountermeasure = async () => {
    if (!selectedTrack) {
      setError('No track selected');
      return;
    }
    
    setLoading(true);
    setError(null);
    setSuccessMessage(null);
    
    try {
      const token = localStorage.getItem('token');
      
      const response = await axios.post('/api/defense/countermeasure', {
        threat_id: selectedTrack.id,
        threat_assessment: selectedTrack
      }, {
        headers: {
          Authorization: `Bearer ${token}`
        }
      });
      
      if (response.data.success) {
        setSuccessMessage(`Countermeasure activated against ${selectedTrack.id}`);
        fetchDefenseStatus();
        
        if (onDefenseAction) {
          onDefenseAction('countermeasure_activated', { 
            threat_id: selectedTrack.id,
            countermeasure_type: response.data.type
          });
        }
      } else {
        setError(response.data.message || 'Failed to activate countermeasure');
      }
      
    } catch (err: any) {
      setError(err.response?.data?.message || 'An error occurred');
    } finally {
      setLoading(false);
    }
  };
  
  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'active':
        return <Badge bg="success">Active</Badge>;
      case 'engaged':
        return <Badge bg="danger">Engaged</Badge>;
      case 'standby':
        return <Badge bg="warning">Standby</Badge>;
      case 'recovering':
        return <Badge bg="info">Recovering</Badge>;
      case 'offline':
        return <Badge bg="secondary">Offline</Badge>;
      case 'maintenance':
        return <Badge bg="primary">Maintenance</Badge>;
      default:
        return <Badge bg="secondary">{status}</Badge>;
    }
  };
  
  const getResourceVariant = (percentage: number) => {
    if (percentage < 20) return 'danger';
    if (percentage < 50) return 'warning';
    return 'success';
  };
  
  const formatTimestamp = (timestamp: number) => {
    return new Date(timestamp * 1000).toLocaleString();
  };
  
  const formatDuration = (seconds: number) => {
    const hours = Math.floor(seconds / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    const secs = Math.floor(seconds % 60);
    
    return `${hours}h ${minutes}m ${secs}s`;
  };
  
  return (
    <Card className="defense-control-panel">
      <Card.Header>
        <div className="d-flex justify-content-between align-items-center">
          <h5>Defense Control</h5>
          {defenseStatus && (
            <div>
              Status: {getStatusBadge(defenseStatus.status)}
              <Badge bg="info" className="ms-2">Level {defenseStatus.level}</Badge>
            </div>
          )}
        </div>
      </Card.Header>
      <Card.Body>
        {error && <Alert variant="danger">{error}</Alert>}
        {successMessage && <Alert variant="success">{successMessage}</Alert>}
        
        <Tabs defaultActiveKey="status" className="mb-3">
          <Tab eventKey="status" title="Status">
            {defenseStatus ? (
              <div className="defense-status">
                <h6>Defense Resources</h6>
                <div className="resources-container">
                  {Object.entries(defenseStatus.resources).map(([name, data]) => (
                    <div key={name} className="resource-item">
                      <div className="resource-header">
                        <span className="resource-name">{name}</span>
                        <span className="resource-value">
                          {Math.round(data.current)} / {Math.round(data.max)}
                        </span>
                      </div>
                      <ProgressBar 
                        variant={getResourceVariant(data.percentage)}
                        now={data.percentage}
                        label={`${Math.round(data.percentage)}%`}
                      />
                    </div>
                  ))}
                </div>
                
                <h6 className="mt-4">Active Countermeasures</h6>
                {activeCountermeasures.length > 0 ? (
                  <Table striped bordered hover size="sm">
                    <thead>
                      <tr>
                        <th>Type</th>
                        <th>Target</th>
                        <th>Status</th>
                        <th>Effectiveness</th>
                      </tr>
                    </thead>
                    <tbody>
                      {activeCountermeasures.map(cm => (
                        <tr key={cm.id}>
                          <td>{cm.type}</td>
                          <td>{cm.threat_id}</td>
                          <td>{cm.status}</td>
                          <td>{Math.round(cm.effectiveness * 100)}%</td>
                        </tr>
                      ))}
                    </tbody>
                  </Table>
                ) : (
                  <p>No active countermeasures</p>
                )}
                
                <div className="status-details mt-4">
                  <div className="status-item">
                    <span className="status-label">Last Status Change:</span>
                    <span className="status-value">{formatTimestamp(defenseStatus.last_status_change)}</span>
                  </div>
                  <div className="status-item">
                    <span className="status-label">Uptime:</span>
                    <span className="status-value">{formatDuration(defenseStatus.uptime)}</span>
                  </div>
                  <div className="status-item">
                    <span className="status-label">Active Countermeasures:</span>
                    <span className="status-value">{defenseStatus.active_countermeasures}</span>
                  </div>
                </div>
              </div>
            ) : (
              <div className="text-center">
                <p>Loading defense status...</p>
              </div>
            )}
          </Tab>
          
          <Tab eventKey="controls" title="Controls">
            <div className="defense-controls">
              <div className="control-section">
                <h6>Defense Level</h6>
                <Form.Group className="mb-3">
                  <Form.Label>Set Defense Level (1-5)</Form.Label>
                  <div className="d-flex">
                    <Form.Control
                      type="range"
                      min={1}
                      max={5}
                      step={1}
                      value={defenseLevel}
                      onChange={(e) => setDefenseLevel(parseInt(e.target.value))}
                      className="me-2"
                    />
                    <span className="defense-level-value">{defenseLevel}</span>
                  </div>
                  <div className="level-description">
                    {defenseLevel === 1 && "Minimal defensive measures, conserving resources"}
                    {defenseLevel === 2 && "Standard defensive posture, monitoring threats"}
                    {defenseLevel === 3 && "Enhanced defenses, prepared for engagement"}
                    {defenseLevel === 4 && "High alert, active defensive measures"}
                    {defenseLevel === 5 && "Maximum defense, all systems engaged"}
                  </div>
                </Form.Group>
                <Button 
                  variant="primary" 
                  onClick={handleActivateDefense}
                  disabled={loading || !defenseStatus}
                  className="w-100"
                >
                  {loading ? 'Setting Level...' : 'Set Defense Level'}
                </Button>
              </div>
              
              <div className="control-section mt-4">
                <h6>Defense Protocols</h6>
                <Form.Group className="mb-3">
                  <Form.Label>Select Protocol</Form.Label>
                  <Form.Select
                    value={selectedProtocol}
                    onChange={(e) => setSelectedProtocol(e.target.value)}
                  >
                    {availableProtocols.map(protocol => (
                      <option key={protocol} value={protocol}>
                        {protocol.toUpperCase()} Protocol
                      </option>
                    ))}
                  </Form.Select>
                  <div className="protocol-description">
                    {selectedProtocol === 'alpha' && "Standard defensive posture"}
                    {selectedProtocol === 'beta' && "Enhanced defensive posture"}
                    {selectedProtocol === 'gamma' && "Active defense with limited offensive capabilities"}
                    {selectedProtocol === 'delta' && "Full defensive alert with offensive capabilities"}
                                        {selectedProtocol === 'omega' && "Last resort protocol - all resources committed"}
                  </div>
                </Form.Group>
                <Button 
                  variant="warning" 
                  onClick={handleActivateProtocol}
                  disabled={loading || !defenseStatus}
                  className="w-100"
                >
                  {loading ? 'Activating...' : 'Activate Protocol'}
                </Button>
              </div>
              
              <div className="control-section mt-4">
                <h6>Track Countermeasures</h6>
                <div className="selected-track-info mb-3">
                  {selectedTrack ? (
                    <div>
                      <div className="track-info-item">
                        <span className="track-info-label">Selected Track:</span>
                        <span className="track-info-value">{selectedTrack.id}</span>
                      </div>
                      <div className="track-info-item">
                        <span className="track-info-label">Type:</span>
                        <span className="track-info-value">{selectedTrack.type}</span>
                      </div>
                      <div className="track-info-item">
                        <span className="track-info-label">Threat Level:</span>
                        <span className="track-info-value">
                          <Badge 
                            bg={
                              selectedTrack.threatLevel === 'high' ? 'danger' : 
                              selectedTrack.threatLevel === 'medium' ? 'warning' : 
                              'success'
                            }
                          >
                            {selectedTrack.threatLevel}
                          </Badge>
                        </span>
                      </div>
                    </div>
                  ) : (
                    <p>No track selected</p>
                  )}
                </div>
                <Button 
                  variant="danger" 
                  onClick={handleCountermeasure}
                  disabled={loading || !defenseStatus || !selectedTrack}
                  className="w-100"
                >
                  {loading ? 'Activating...' : 'Activate Countermeasure'}
                </Button>
              </div>
            </div>
          </Tab>
          
          <Tab eventKey="analytics" title="Analytics">
            <div className="defense-analytics">
              <h6>Countermeasure Effectiveness</h6>
              {defenseStatus ? (
                <div className="effectiveness-chart">
                  <div className="chart-container">
                    {Object.entries(defenseStatus.countermeasure_types || {}).map(([type, count]) => {
                      // This would be replaced with actual effectiveness data
                      const effectiveness = Math.random() * 0.5 + 0.5; // Random between 50-100%
                      return (
                        <div key={type} className="chart-item">
                          <div className="chart-label">{type}</div>
                          <div className="chart-bar-container">
                            <div 
                              className="chart-bar" 
                              style={{ width: `${effectiveness * 100}%` }}
                            ></div>
                          </div>
                          <div className="chart-value">{Math.round(effectiveness * 100)}%</div>
                        </div>
                      );
                    })}
                  </div>
                  <div className="chart-legend">
                    <div className="legend-item">
                      <span className="legend-color" style={{ backgroundColor: '#28a745' }}></span>
                      <span className="legend-label">High Effectiveness (80-100%)</span>
                    </div>
                    <div className="legend-item">
                      <span className="legend-color" style={{ backgroundColor: '#ffc107' }}></span>
                      <span className="legend-label">Medium Effectiveness (50-80%)</span>
                    </div>
                    <div className="legend-item">
                      <span className="legend-color" style={{ backgroundColor: '#dc3545' }}></span>
                      <span className="legend-label">Low Effectiveness (0-50%)</span>
                    </div>
                  </div>
                </div>
              ) : (
                <p>Loading analytics data...</p>
              )}
              
              <h6 className="mt-4">Resource Utilization History</h6>
              <div className="resource-history">
                <p className="text-muted">Historical resource utilization data would be displayed here</p>
                {/* This would be replaced with an actual chart component */}
                <div className="placeholder-chart">
                  <div className="chart-line" style={{ top: '30%' }}></div>
                  <div className="chart-line" style={{ top: '60%' }}></div>
                  <div className="chart-line" style={{ top: '90%' }}></div>
                </div>
              </div>
            </div>
          </Tab>
        </Tabs>
      </Card.Body>
      <Card.Footer>
        <div className="d-flex justify-content-between align-items-center">
          <small className="text-muted">
            Last updated: {defenseStatus ? formatTimestamp(defenseStatus.timestamp) : 'N/A'}
          </small>
          <Button 
            size="sm" 
            variant="outline-secondary" 
            onClick={fetchDefenseStatus}
            disabled={loading}
          >
            Refresh
          </Button>
        </div>
      </Card.Footer>
    </Card>
  );
};

export default DefenseControlPanel;
