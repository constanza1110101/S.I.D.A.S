// frontend/src/components/CommandCenter.tsx
import React, { useEffect, useState, useCallback } from 'react';
import { Map, View } from 'ol';
import { Tile as TileLayer, Vector as VectorLayer } from 'ol/layer';
import { OSM, Vector as VectorSource } from 'ol/source';
import { Circle, Fill, Stroke, Style, Text } from 'ol/style';
import { Feature } from 'ol';
import { Point } from 'ol/geom';
import { fromLonLat } from 'ol/proj';
import { io, Socket } from 'socket.io-client';
import { Button, Card, Tabs, Tab, Table, Badge, Alert, Modal, Form } from 'react-bootstrap';
import 'bootstrap/dist/css/bootstrap.min.css';
import './CommandCenter.css';

interface Track {
  id: string;
  position: [number, number, number]; // lon, lat, alt
  velocity: [number, number, number];
  threatLevel: string;
  type: string;
  lastUpdated: string;
}

interface SystemStatus {
  defense: string;
  attack: string;
  tracking: string;
  threat_level: string;
  last_updated: string;
}

interface Command {
  type: string;
  target_id?: string;
  parameters?: Record<string, any>;
}

const trackStyleFunction = (feature: Feature): Style => {
  const track = feature.get('track') as Track;
  
  // Color based on threat level
  let color = 'blue';
  switch (track.threatLevel) {
    case 'high':
      color = 'red';
      break;
    case 'medium':
      color = 'orange';
      break;
    case 'low':
      color = 'green';
      break;
  }
  
  // Different shapes based on type
  let radius = 6;
  switch (track.type) {
    case 'aircraft':
      radius = 8;
      break;
    case 'vessel':
      radius = 7;
      break;
    case 'ground':
      radius = 5;
      break;
  }
  
  return new Style({
    image: new Circle({
      radius: radius,
      fill: new Fill({ color }),
      stroke: new Stroke({ color: 'white', width: 2 })
    }),
    text: new Text({
      text: track.id,
      offsetY: -15,
      fill: new Fill({ color: 'white' }),
      stroke: new Stroke({ color: 'black', width: 2 })
    })
  });
};

const CommandCenter: React.FC = () => {
  const [map, setMap] = useState<Map | null>(null);
  const [tracks, setTracks] = useState<Track[]>([]);
  const [selectedTrack, setSelectedTrack] = useState<Track | null>(null);
  const [systemStatus, setSystemStatus] = useState<SystemStatus>({
    defense: 'online',
    attack: 'standby',
    tracking: 'online',
    threat_level: 'low',
    last_updated: new Date().toISOString()
  });
  const [socket, setSocket] = useState<Socket | null>(null);
  const [showCommandModal, setShowCommandModal] = useState(false);
  const [commandType, setCommandType] = useState('track');
  const [commandParams, setCommandParams] = useState({});
  const [alerts, setAlerts] = useState<{message: string, type: string}[]>([]);
  const [vectorSource] = useState(new VectorSource());
  
  // Initialize map and WebSocket connection
  useEffect(() => {
    // Initialize map
    const mapInstance = new Map({
      target: 'map',
      layers: [
        new TileLayer({
          source: new OSM()
        }),
        new VectorLayer({
          source: vectorSource,
          style: trackStyleFunction
        })
      ],
      view: new View({
        center: fromLonLat([0, 0]),
        zoom: 2
      })
    });
    
    setMap(mapInstance);
    
    // Set up click handler
    mapInstance.on('click', (event) => {
      const feature = mapInstance.forEachFeatureAtPixel(event.pixel, feature => feature);
      if (feature) {
        const track = feature.get('track') as Track;
        setSelectedTrack(track);
      } else {
        setSelectedTrack(null);
      }
    });
    
    // Establish WebSocket connection
    const socketInstance = io('http://localhost:5000');
    setSocket(socketInstance);
    
    socketInstance.on('connect', () => {
      console.log('Connected to server');
      addAlert('Connected to command server', 'success');
    });
    
    socketInstance.on('tracks_update', (data) => {
      if (data.type === 'tracks_update') {
        setTracks(data.tracks);
      }
    });
    
    socketInstance.on('system_update', (data) => {
      if (data.type === 'system_status') {
        setSystemStatus(data.status);
        
        // Alert if threat level is high
        if (data.status.threat_level === 'high') {
          addAlert('ALERT: High threat level detected!', 'danger');
        }
      }
    });
    
    socketInstance.on('command_update', (data) => {
      addAlert(`Command ${data.command} ${data.status} for target ${data.target}`, 'info');
    });
    
    return () => {
      socketInstance.disconnect();
      mapInstance.dispose();
    };
  }, []);
  
  // Update features when tracks change
  useEffect(() => {
    if (!vectorSource) return;
    
    // Clear existing features
    vectorSource.clear();
    
    // Add new features for each track
    tracks.forEach(track => {
      const feature = new Feature({
        geometry: new Point(fromLonLat([track.position[0], track.position[1]])),
        track: track
      });
      vectorSource.addFeature(feature);
    });
  }, [tracks, vectorSource]);
  
  // Add an alert message
  const addAlert = useCallback((message: string, type: string) => {
    setAlerts(prev => [...prev, { message, type }]);
    
    // Remove alert after 5 seconds
    setTimeout(() => {
      setAlerts(prev => prev.filter(a => a.message !== message));
    }, 5000);
  }, []);
  
  // Handle command submission
  const handleCommandSubmit = () => {
    if (!socket) return;
    
    const command: Command = {
      type: commandType,
      parameters: commandParams
    };
    
    if (selectedTrack) {
      command.target_id = selectedTrack.id;
    }
    
    // Send command to server
    socket.emit('command', command);
    
    addAlert(`Command ${commandType} issued`, 'primary');
    setShowCommandModal(false);
  };
  
  // Render threat level badge
  const renderThreatBadge = (level: string) => {
    let variant = 'info';
    switch (level) {
      case 'high':
        variant = 'danger';
        break;
      case 'medium':
        variant = 'warning';
        break;
      case 'low':
        variant = 'success';
        break;
    }
    
    return <Badge bg={variant}>{level.toUpperCase()}</Badge>;
  };
  
  return (
    <div className="command-center">
      <div className="header">
        <h1>S.I.D.A.S Command Center</h1>
        <div className="system-status">
          <span>Defense: <Badge bg={systemStatus.defense === 'online' ? 'success' : 'danger'}>{systemStatus.defense}</Badge></span>
          <span>Attack: <Badge bg={systemStatus.attack === 'standby' ? 'warning' : 'danger'}>{systemStatus.attack}</Badge></span>
          <span>Tracking: <Badge bg={systemStatus.tracking === 'online' ? 'success' : 'danger'}>{systemStatus.tracking}</Badge></span>
          <span>Threat Level: {renderThreatBadge(systemStatus.threat_level)}</span>
        </div>
      </div>
      
      <div className="main-content">
        <div id="map" className="map-container"></div>
        
        <div className="control-panel">
          <Tabs defaultActiveKey="tracks" className="mb-3">
            <Tab eventKey="tracks" title="Tracks">
              <Card>
                <Card.Header>Active Tracks ({tracks.length})</Card.Header>
                <Card.Body>
                  <div className="tracks-table-container">
                    <Table striped bordered hover size="sm">
                      <thead>
                        <tr>
                          <th>ID</th>
                          <th>Type</th>
                          <th>Threat</th>
                          <th>Position</th>
                          <th>Actions</th>
                        </tr>
                      </thead>
                      <tbody>
                        {tracks.map(track => (
                          <tr 
                            key={track.id} 
                            className={selectedTrack?.id === track.id ? 'selected-track' : ''}
                            onClick={() => setSelectedTrack(track)}
                          >
                            <td>{track.id}</td>
                            <td>{track.type}</td>
                            <td>{renderThreatBadge(track.threatLevel)}</td>
                            <td>
                              {track.position[0].toFixed(2)}, {track.position[1].toFixed(2)}, {track.position[2].toFixed(0)}m
                            </td>
                            <td>
                              <Button 
                                size="sm" 
                                variant="primary"
                                onClick={() => {
                                  setCommandType('track');
                                  setShowCommandModal(true);
                                }}
                              >
                                Command
                              </Button>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </Table>
                  </div>
                </Card.Body>
              </Card>
            </Tab>
            
            <Tab eventKey="details" title="Track Details">
              <Card>
                <Card.Header>Track Details</Card.Header>
                <Card.Body>
                  {selectedTrack ? (
                    <div>
                      <h4>Track {selectedTrack.id}</h4>
                      <Table>
                        <tbody>
                          <tr>
                            <td>Type:</td>
                            <td>{selectedTrack.type}</td>
                          </tr>
                          <tr>
                            <td>Threat Level:</td>
                            <td>{renderThreatBadge(selectedTrack.threatLevel)}</td>
                          </tr>
                          <tr>
                            <td>Position:</td>
                            <td>
                              Lon: {selectedTrack.position[0].toFixed(4)}<br />
                              Lat: {selectedTrack.position[1].toFixed(4)}<br />
                              Alt: {selectedTrack.position[2].toFixed(0)}m
                            </td>
                          </tr>
                          <tr>
                            <td>Velocity:</td>
                            <td>
                              X: {selectedTrack.velocity[0].toFixed(2)}<br />
                              Y: {selectedTrack.velocity[1].toFixed(2)}<br />
                              Z: {selectedTrack.velocity[2].toFixed(2)}
                            </td>
                          </tr>
                          <tr>
                            <td>Last Updated:</td>
                            <td>{new Date(selectedTrack.lastUpdated).toLocaleString()}</td>
                          </tr>
                        </tbody>
                      </Table>
                      
                      <div className="track-actions">
                        <Button 
                          variant="primary" 
                          onClick={() => {
                            setCommandType('track_focus');
                            setShowCommandModal(true);
                          }}
                        >
                          Focus
                        </Button>
                        <Button 
                          variant="warning"
                          onClick={() => {
                            setCommandType('track_analyze');
                            setShowCommandModal(true);
                          }}
                        >
                          Analyze
                        </Button>
                        <Button 
                          variant="danger"
                          onClick={() => {
                            setCommandType('track_intercept');
                            setShowCommandModal(true);
                          }}
                        >
                          Intercept
                        </Button>
                      </div>
                    </div>
                  ) : (
                    <p>Select a track to view details</p>
                  )}
                </Card.Body>
              </Card>
            </Tab>
            
            <Tab eventKey="system" title="System Control">
              <Card>
                <Card.Header>System Control</Card.Header>
                <Card.Body>
                  <div className="system-controls">
                    <Button 
                      variant="success" 
                      onClick={() => {
                        setCommandType('system_scan');
                        setShowCommandModal(true);
                      }}
                    >
                      Initiate Scan
                    </Button>
                    <Button 
                      variant="primary"
                      onClick={() => {
                        setCommandType('defense_activate');
                        setShowCommandModal(true);
                      }}
                    >
                      Activate Defense
                    </Button>
                    <Button 
                      variant="warning"
                      onClick={() => {
                        setCommandType('system_reset');
                        setShowCommandModal(true);
                      }}
                    >
                      Reset Systems
                    </Button>
                    <Button 
                      variant="danger"
                      onClick={() => {
                        setCommandType('emergency_protocol');
                        setShowCommandModal(true);
                      }}
                    >
                      Emergency Protocol
                    </Button>
                  </div>
                  
                  <div className="system-info">
                    <h5>System Information</h5>
                    <p>Last Updated: {new Date(systemStatus.last_updated).toLocaleString()}</p>
                    <p>Current Status: {systemStatus.defense} / {systemStatus.attack} / {systemStatus.tracking}</p>
                  </div>
                </Card.Body>
              </Card>
            </Tab>
          </Tabs>
        </div>
      </div>
      
      <div className="alerts-container">
        {alerts.map((alert, index) => (
          <Alert key={index} variant={alert.type}>
            {alert.message}
          </Alert>
        ))}
      </div>
      
      <Modal show={showCommandModal} onHide={() => setShowCommandModal(false)}>
        <Modal.Header closeButton>
          <Modal.Title>Issue Command: {commandType}</Modal.Title>
        </Modal.Header>
        <Modal.Body>
          <Form>
            <Form.Group className="mb-3">
              <Form.Label>Command Type</Form.Label>
              <Form.Select 
                value={commandType}
                onChange={(e) => setCommandType(e.target.value)}
              >
                <option value="track_focus">Track Focus</option>
                <option value="track_analyze">Track Analyze</option>
                <option value="track_intercept">Track Intercept</option>
                <option value="system_scan">System Scan</option>
                <option value="defense_activate">Defense Activate</option>
                <option value="system_reset">System Reset</option>
                <option value="emergency_protocol">Emergency Protocol</option>
              </Form.Select>
            </Form.Group>
            
            <Form.Group className="mb-3">
              <Form.Label>Target</Form.Label>
              <Form.Control 
                type="text" 
                readOnly 
                value={selectedTrack ? selectedTrack.id : 'No target selected'}
              />
            </Form.Group>
            
            <Form.Group className="mb-3">
              <Form.Label>Priority</Form.Label>
              <Form.Select 
                onChange={(e) => setCommandParams({...commandParams, priority: e.target.value})}
              >
                <option value="low">Low</option>
                <option value="medium">Medium</option>
                <option value="high">High</option>
                <option value="critical">Critical</option>
              </Form.Select>
            </Form.Group>
            
            <Form.Group className="mb-3">
              <Form.Label>Notes</Form.Label>
              <Form.Control 
                as="textarea" 
                rows={3}
                onChange={(e) => setCommandParams({...commandParams, notes: e.target.value})}
              />
            </Form.Group>
          </Form>
        </Modal.Body>
        <Modal.Footer>
          <Button variant="secondary" onClick={() => setShowCommandModal(false)}>
            Cancel
          </Button>
          <Button variant="primary" onClick={handleCommandSubmit}>
            Issue Command
          </Button>
        </Modal.Footer>
      </Modal>
    </div>
  );
};

export default CommandCenter;
