// Login.tsx
import React, { useState } from 'react';
import { Container, Form, Button, Card, Alert } from 'react-bootstrap';
import axios from 'axios';
import './Login.css';

interface LoginProps {
  onLogin: (token: string, userData: any) => void;
}

const Login: React.FC<LoginProps> = ({ onLogin }) => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setIsLoading(true);
    
    try {
      const response = await axios.post('http://localhost:5000/api/login', {
        username,
        password
      });
      
      const { token, user } = response.data;
      onLogin(token, user);
    } catch (err: any) {
      setError(err.response?.data?.error || 'An error occurred during login');
    } finally {
      setIsLoading(false);
    }
  };
  
  return (
    <Container className="login-container">
      <div className="login-background"></div>
      <Card className="login-card">
        <Card.Header className="text-center">
          <h2>S.I.D.A.S</h2>
          <h5>Secure Intelligent Data Authentication System</h5>
        </Card.Header>
        <Card.Body>
          {error && <Alert variant="danger">{error}</Alert>}
          
          <Form onSubmit={handleSubmit}>
            <Form.Group className="mb-3">
              <Form.Label>Username</Form.Label>
              <Form.Control 
                type="text" 
                placeholder="Enter username" 
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                required
              />
            </Form.Group>
            
            <Form.Group className="mb-3">
              <Form.Label>Password</Form.Label>
              <Form.Control 
                type="password" 
                placeholder="Password" 
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
              />
            </Form.Group>
            
            <Button 
              variant="primary" 
              type="submit" 
              className="w-100" 
              disabled={isLoading}
            >
              {isLoading ? 'Authenticating...' : 'Login'}
            </Button>
          </Form>
        </Card.Body>
        <Card.Footer className="text-center text-muted">
          <small>Secure Access Only • Authorized Personnel Only</small>
        </Card.Footer>
      </Card>
    </Container>
  );
};

export default Login;
