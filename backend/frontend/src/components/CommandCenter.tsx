// CommandCenter.tsx - Updated to include Defense Control Panel
import React, { useEffect, useState, useCallback } from 'react';
import { Map, View } from 'ol';
import { Tile as TileLayer, Vector as VectorLayer } from 'ol/layer';
import { OSM, Vector as VectorSource } from 'ol/source';
import { Circle, Fill, Stroke, Style, Text } from 'ol/style';
import { Feature } from 'ol';
import { Point } from 'ol/geom';
import { fromLonLat } from 'ol/proj';
import { io, Socket } from 'socket.io-client';
import { Button, Card, Tabs, Tab, Table, Badge, Alert, Modal, Form, Nav, Row, Col } from 'react-bootstrap';
import Battlefield3D from './Battlefield3D';
import DefenseControlPanel from './DefenseControlPanel';
import 'bootstrap/dist/css/bootstrap.min.css';
import './CommandCenter.css';

// ... [existing imports and interfaces]

const CommandCenter: React.FC = () => {
  // ... [existing state variables]
  
  // Handle defense action
  const handleDefenseAction = (action: string, data: any) => {
    // Log the action
    console.log(`Defense action: ${action}`, data);
    
    // Add an alert based on the action
    switch (action) {
      case 'defense_level_changed':
        addAlert(`Defense level set to ${data.level}`, data.level >= 4 ? 'danger' : 'warning');
        break;
      case 'defense_protocol_activated':
        addAlert(`Defense protocol ${data.protocol.toUpperCase()} activated`, 'warning');
        break;
      case 'countermeasure_activated':
        addAlert(`Countermeasure activated against ${data.threat_id}`, 'info');
        break;
      default:
        addAlert(`Defense action: ${action}`, 'info');
        break;
    }
    
    // If we have a socket connection, emit an event
    if (socket) {
      socket.emit('defense_action', { action, data });
    }
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
          
          <Nav className="ms-auto">
            <Nav.Item>
              <Button 
                variant={viewMode === '2d' ? 'primary' : 'outline-primary'} 
                onClick={() => setViewMode('2d')}
                className="me-2"
              >
                2D Map
              </Button>
            </Nav.Item>
            <Nav.Item>
              <Button 
                variant={viewMode === '3d' ? 'primary' : 'outline-primary'} 
                onClick={() => setViewMode('3d')}
              >
                3D View
              </Button>
            </Nav.Item>
          </Nav>
        </div>
      </div>
      
      <div className="main-content">
        <Row className="g-0 h-100">
          <Col md={8} className="visualization-container">
            {viewMode === '2d' ? (
              <div id="map" className="map-container"></div>
            ) : (
              <Battlefield3D 
                tracks={tracks} 
                selectedTrackId={selectedTrack?.id} 
                onTrackSelect={handleTrackSelect} 
              />
            )}
          </Col>
          
          <Col md={4} className="control-container">
            <Tabs defaultActiveKey="tracks" className="mb-3 control-tabs">
              <Tab eventKey="tracks" title="Tracks">
                <Card className="h-100">
                  <Card.Header>Active Tracks ({tracks.length})</Card.Header>
                  <Card.Body className="p-0">
                    <div className="tracks-table-container">
                      <Table striped bordered hover size="sm">
                        <thead>
                          <tr>
                            <th>ID</th>
                            <th>Type</th>
                            <th>Threat</th>
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
              
              <Tab eventKey="details" title="Details">
                <Card className="h-100">
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
              
              <Tab eventKey="defense" title="Defense">
                <DefenseControlPanel 
                  selectedTrack={selectedTrack}
                  onDefenseAction={handleDefenseAction}
                />
              </Tab>
              
              <Tab eventKey="system" title="System">
                <Card className="h-100">
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
              
              <Tab eventKey="analytics" title="Analytics">
                <Card className="h-100">
                  <Card.Header>Threat Analytics</Card.Header>
                  <Card.Body>
                    <div className="analytics-container">
                      <div className="analytics-chart">
                        <h5>Threat Distribution</h5>
                        <div className="threat-distribution">
                          {['low', 'medium', 'high'].map(level => {
                            const count = tracks.filter(t => t.threatLevel === level).length;
                            const percentage = tracks.length > 0 ? (count / tracks.length) * 100 : 0;
                            
                            return (
                              <div key={level} className="threat-bar-container">
                                <div className="threat-label">{level}</div>
                                <div className="threat-bar">
                                  <div 
                                    className={`threat-bar-fill threat-${level}`} 
                                    style={{ width: `${percentage}%` }}
                                  ></div>
                                </div>
                                <div className="threat-count">{count}</div>
                              </div>
                            );
                          })}
                        </div>
                      </div>
                      
                      <div className="analytics-chart">
                        <h5>Track Types</h5>
                        <div className="track-types">
                          {Array.from(new Set(tracks.map(t => t.type))).map(type => {
                            const count = tracks.filter(t => t.type === type).length;
                            const percentage = tracks.length > 0 ? (count / tracks.length) * 100 : 0;
                            
                            return (
                              <div key={type} className="track-type-container">
                                <div className="track-type-label">{type}</div>
                                <div className="track-type-bar">
                                  <div 
                                    className="track-type-bar-fill" 
                                    style={{ width: `${percentage}%` }}
                                  ></div>
                                </div>
                                <div className="track-type-count">{count}</div>
                              </div>
                            );
                          })}
                        </div>
                      </div>
                      
                      <div className="threat-summary">
                        <h5>Threat Summary</h5>
                        <p>
                          Current system threat level: <strong>{systemStatus.threat_level.toUpperCase()}</strong>
                        </p>
                        <p>
                          Active tracks: <strong>{tracks.length}</strong>
                        </p>
                        <p>
                          High threat tracks: <strong>{tracks.filter(t => t.threatLevel === 'high').length}</strong>
                        </p>
                        <p>
                          Recommended action: <strong>
                            {systemStatus.threat_level === 'high' 
                              ? 'Activate defensive measures' 
                              : systemStatus.threat_level === 'medium'
                                ? 'Increase monitoring frequency'
                                : 'Maintain standard protocols'}
                          </strong>
                        </p>
                      </div>
                    </div>
                  </Card.Body>
                </Card>
              </Tab>
            </Tabs>
          </Col>
        </Row>
      </div>
      
      <div className="alerts-container">
        {alerts.map((alert, index) => (
          <Alert key={index} variant={alert.type}>
            {alert.message}
          </Alert>
        ))}
      </div>
      
      {/* Command Modal - unchanged */}
      <Modal show={showCommandModal} onHide={() => setShowCommandModal(false)}>
        {/* ... (Modal content remains unchanged) */}
      </Modal>
    </div>
  );
};

export default CommandCenter;
