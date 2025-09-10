import React, { useState, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import axios from 'axios';
import './App.css';

// Import UI components
import { Button } from './components/ui/button';
import { Input } from './components/ui/input';
import { Label } from './components/ui/label';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from './components/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from './components/ui/tabs';
import { Badge } from './components/ui/badge';
import { Textarea } from './components/ui/textarea';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from './components/ui/select';
import { toast } from 'sonner';
import { Toaster } from './components/ui/sonner';
import { 
  Heart, 
  Thermometer, 
  Activity, 
  AlertTriangle, 
  CheckCircle, 
  Clock, 
  User,
  LogOut,
  Shield,
  Volume2,
  Mail
} from 'lucide-react';

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

// Audio alert function using browser-generated beep tones
const playAudioAlert = (severity, symptomSummary) => {
  // Check if Web Audio API is supported
  if (!window.AudioContext && !window.webkitAudioContext) {
    console.warn('Web Audio API not supported');
    return;
  }

  const AudioContext = window.AudioContext || window.webkitAudioContext;
  const audioContext = new AudioContext();

  const playBeep = (frequency, duration, volume = 0.3) => {
    const oscillator = audioContext.createOscillator();
    const gainNode = audioContext.createGain();
    
    oscillator.connect(gainNode);
    gainNode.connect(audioContext.destination);
    
    oscillator.frequency.setValueAtTime(frequency, audioContext.currentTime);
    oscillator.type = 'sine';
    
    gainNode.gain.setValueAtTime(0, audioContext.currentTime);
    gainNode.gain.linearRampToValueAtTime(volume, audioContext.currentTime + 0.01);
    gainNode.gain.exponentialRampToValueAtTime(0.01, audioContext.currentTime + duration - 0.01);
    gainNode.gain.linearRampToValueAtTime(0, audioContext.currentTime + duration);
    
    oscillator.start(audioContext.currentTime);
    oscillator.stop(audioContext.currentTime + duration);
  };

  const playSequentialBeeps = (beeps) => {
    let currentTime = audioContext.currentTime;
    beeps.forEach(({ frequency, duration, volume, delay = 0 }) => {
      setTimeout(() => {
        playBeep(frequency, duration, volume);
      }, delay);
    });
  };

  switch (severity) {
    case 'high':
      // High frequency, urgent beeping pattern - 3 rapid beeps
      playSequentialBeeps([
        { frequency: 1000, duration: 0.2, volume: 0.5, delay: 0 },
        { frequency: 1000, duration: 0.2, volume: 0.5, delay: 300 },
        { frequency: 1000, duration: 0.2, volume: 0.5, delay: 600 }
      ]);
      break;
    case 'medium':
      // Medium frequency, attention beeping - 2 beeps
      playSequentialBeeps([
        { frequency: 700, duration: 0.3, volume: 0.4, delay: 0 },
        { frequency: 700, duration: 0.3, volume: 0.4, delay: 500 }
      ]);
      break;
    case 'low':
      // Low frequency, gentle single beep
      playBeep(400, 0.5, 0.3);
      break;
    default:
      // Default notification beep
      playBeep(600, 0.2, 0.3);
  }
};

// Authentication Component
const AuthPage = ({ onLogin }) => {
  const [isLogin, setIsLogin] = useState(true);
  const [formData, setFormData] = useState({
    email: '',
    password: '',
    full_name: ''
  });
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);

    try {
      const endpoint = isLogin ? '/auth/login' : '/auth/signup';
      const response = await axios.post(`${API}${endpoint}`, formData);
      
      if (isLogin) {
        localStorage.setItem('token', response.data.access_token);
        localStorage.setItem('user', JSON.stringify(response.data.user));
        onLogin(response.data.user);
        toast.success('Login successful!');
      } else {
        toast.success('Account created successfully! Please login.');
        setIsLogin(true);
        setFormData({ email: '', password: '', full_name: '' });
      }
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Authentication failed');
    } finally {
      setLoading(false);
    }
  };

  const handleInputChange = (e) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-emerald-50 to-teal-100 flex items-center justify-center p-4">
      <Card className="w-full max-w-md shadow-2xl border-0 bg-white/90 backdrop-blur-sm">
        <CardHeader className="text-center pb-6">
          <div className="mx-auto mb-4 w-16 h-16 bg-gradient-to-br from-emerald-500 to-teal-600 rounded-full flex items-center justify-center">
            <Shield className="w-8 h-8 text-white" />
          </div>
          <CardTitle className="text-2xl font-bold text-gray-800">AlertRx</CardTitle>
          <CardDescription className="text-gray-600">
            Real-Time Health Monitoring System
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Tabs value={isLogin ? 'login' : 'signup'} onValueChange={(value) => setIsLogin(value === 'login')}>
            <TabsList className="grid w-full grid-cols-2 mb-6">
              <TabsTrigger value="login">Login</TabsTrigger>
              <TabsTrigger value="signup">Sign Up</TabsTrigger>
            </TabsList>
            
            <form onSubmit={handleSubmit}>
              <TabsContent value="login" className="space-y-4">
                <div>
                  <Label htmlFor="email">Email</Label>
                  <Input
                    id="email"
                    name="email"
                    type="email"
                    required
                    value={formData.email}
                    onChange={handleInputChange}
                    className="mt-1"
                  />
                </div>
                <div>
                  <Label htmlFor="password">Password</Label>
                  <Input
                    id="password"
                    name="password"
                    type="password"
                    required
                    value={formData.password}
                    onChange={handleInputChange}
                    className="mt-1"
                  />
                </div>
              </TabsContent>
              
              <TabsContent value="signup" className="space-y-4">
                <div>
                  <Label htmlFor="full_name">Full Name</Label>
                  <Input
                    id="full_name"
                    name="full_name"
                    type="text"
                    required
                    value={formData.full_name}
                    onChange={handleInputChange}
                    className="mt-1"
                  />
                </div>
                <div>
                  <Label htmlFor="email">Email</Label>
                  <Input
                    id="email"
                    name="email"
                    type="email"
                    required
                    value={formData.email}
                    onChange={handleInputChange}
                    className="mt-1"
                  />
                </div>
                <div>
                  <Label htmlFor="password">Password</Label>
                  <Input
                    id="password"
                    name="password"
                    type="password"
                    required
                    value={formData.password}
                    onChange={handleInputChange}
                    className="mt-1"
                  />
                  <p className="text-xs text-gray-500 mt-1">
                    Must contain 8+ chars, uppercase, lowercase, number & special character
                  </p>
                </div>
              </TabsContent>
              
              <Button 
                type="submit" 
                className="w-full mt-6 bg-gradient-to-r from-emerald-500 to-teal-600 hover:from-emerald-600 hover:to-teal-700"
                disabled={loading}
              >
                {loading ? 'Please wait...' : (isLogin ? 'Sign In' : 'Create Account')}
              </Button>
            </form>
          </Tabs>
        </CardContent>
      </Card>
    </div>
  );
};

// Main Dashboard Component
const Dashboard = ({ user, onLogout }) => {
  const [symptoms, setSymptoms] = useState([]);
  const [alertHistory, setAlertHistory] = useState([]);
  const [loading, setLoading] = useState(false);
  const [symptomForm, setSymptomForm] = useState({
    temperature: '',
    heart_rate: '',
    blood_pressure_systolic: '',
    blood_pressure_diastolic: '',
    pain_level: '',
    pain_location: '',
    breathing_difficulty: '',
    custom_symptoms: ''
  });

  useEffect(() => {
    fetchSymptoms();
    fetchAlertHistory();
  }, []);

  const fetchSymptoms = async () => {
    try {
      const token = localStorage.getItem('token');
      const response = await axios.get(`${API}/symptoms`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setSymptoms(response.data);
    } catch (error) {
      toast.error('Failed to fetch symptoms');
    }
  };

  const fetchAlertHistory = async () => {
    try {
      const token = localStorage.getItem('token');
      const response = await axios.get(`${API}/alerts`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setAlertHistory(response.data);
    } catch (error) {
      toast.error('Failed to fetch alert history');
    }
  };

  const handleSymptomSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);

    try {
      const token = localStorage.getItem('token');
      const symptomData = {
        symptoms: Object.fromEntries(
          Object.entries(symptomForm).filter(([key, value]) => 
            key !== 'custom_symptoms' && value !== ''
          )
        ),
        custom_symptoms: symptomForm.custom_symptoms || null
      };

      const response = await axios.post(`${API}/symptoms`, symptomData, {
        headers: { Authorization: `Bearer ${token}` }
      });

      const result = response.data;
      
      // Play audio alert
      const symptomSummary = Object.keys(symptomData.symptoms).join(', ');
      playAudioAlert(result.severity_prediction, symptomSummary);
      
      // Show toast notification
      const severityColors = {
        low: 'success',
        medium: 'warning', 
        high: 'error'
      };
      
      toast[severityColors[result.severity_prediction] || 'info'](
        `Symptoms logged - ${result.severity_prediction.toUpperCase()} risk level detected`
      );

      // Reset form and refresh data
      setSymptomForm({
        temperature: '',
        heart_rate: '',
        blood_pressure_systolic: '',
        blood_pressure_diastolic: '',
        pain_level: '',
        pain_location: '',
        breathing_difficulty: '',
        custom_symptoms: ''
      });
      
      fetchSymptoms();
      fetchAlertHistory();
      
    } catch (error) {
      toast.error('Failed to log symptoms');
    } finally {
      setLoading(false);
    }
  };

  const handleInputChange = (name, value) => {
    setSymptomForm({ ...symptomForm, [name]: value });
  };

  const getSeverityBadge = (severity) => {
    const variants = {
      low: 'bg-green-100 text-green-800 border-green-200',
      medium: 'bg-yellow-100 text-yellow-800 border-yellow-200',
      high: 'bg-red-100 text-red-800 border-red-200'
    };
    
    const icons = {
      low: <CheckCircle className="w-3 h-3" />,
      medium: <AlertTriangle className="w-3 h-3" />,
      high: <AlertTriangle className="w-3 h-3" />
    };

    return (
      <Badge className={`${variants[severity]} gap-1`}>
        {icons[severity]}
        {severity.toUpperCase()}
      </Badge>
    );
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 to-blue-50">
      {/* Header */}
      <header className="bg-white shadow-sm border-b border-gray-200">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center h-16">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 bg-gradient-to-br from-emerald-500 to-teal-600 rounded-lg flex items-center justify-center">
                <Shield className="w-6 h-6 text-white" />
              </div>
              <div>
                <h1 className="text-xl font-bold text-gray-900">AlertRx</h1>
                <p className="text-sm text-gray-500">Health Monitoring</p>
              </div>
            </div>
            <div className="flex items-center gap-4">
              <div className="flex items-center gap-2 text-sm text-gray-600">
                <User className="w-4 h-4" />
                {user.full_name}
              </div>
              <Button variant="outline" size="sm" onClick={onLogout}>
                <LogOut className="w-4 h-4 mr-1" />
                Logout
              </Button>
            </div>
          </div>
        </div>
      </header>

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          
          {/* Symptom Logging Form */}
          <div className="lg:col-span-2">
            <Card className="shadow-lg border-0 bg-white/80 backdrop-blur-sm">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Heart className="w-5 h-5 text-red-500" />
                  Log Symptoms
                </CardTitle>
                <CardDescription>
                  Enter your current symptoms for real-time health monitoring
                </CardDescription>
              </CardHeader>
              <CardContent>
                <form onSubmit={handleSymptomSubmit} className="space-y-6">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div>
                      <Label htmlFor="temperature" className="flex items-center gap-2">
                        <Thermometer className="w-4 h-4" />
                        Temperature (°F)
                      </Label>
                      <Input
                        id="temperature"
                        type="number"
                        step="0.1"
                        placeholder="98.6"
                        value={symptomForm.temperature}
                        onChange={(e) => handleInputChange('temperature', e.target.value)}
                        className="mt-1"
                      />
                    </div>
                    
                    <div>
                      <Label htmlFor="heart_rate" className="flex items-center gap-2">
                        <Activity className="w-4 h-4" />
                        Heart Rate (BPM)
                      </Label>
                      <Input
                        id="heart_rate"
                        type="number"
                        placeholder="72"
                        value={symptomForm.heart_rate}
                        onChange={(e) => handleInputChange('heart_rate', e.target.value)}
                        className="mt-1"
                      />
                    </div>
                    
                    <div>
                      <Label htmlFor="bp_systolic">Blood Pressure (Systolic)</Label>
                      <Input
                        id="bp_systolic"
                        type="number"
                        placeholder="120"
                        value={symptomForm.blood_pressure_systolic}
                        onChange={(e) => handleInputChange('blood_pressure_systolic', e.target.value)}
                        className="mt-1"
                      />
                    </div>
                    
                    <div>
                      <Label htmlFor="bp_diastolic">Blood Pressure (Diastolic)</Label>
                      <Input
                        id="bp_diastolic"
                        type="number"
                        placeholder="80"
                        value={symptomForm.blood_pressure_diastolic}
                        onChange={(e) => handleInputChange('blood_pressure_diastolic', e.target.value)}
                        className="mt-1"
                      />
                    </div>
                    
                    <div>
                      <Label htmlFor="pain_level">Pain Level (1-10)</Label>
                      <Select value={symptomForm.pain_level} onValueChange={(value) => handleInputChange('pain_level', value)}>
                        <SelectTrigger className="mt-1">
                          <SelectValue placeholder="Select pain level" />
                        </SelectTrigger>
                        <SelectContent>
                          {[...Array(10)].map((_, i) => (
                            <SelectItem key={i + 1} value={(i + 1).toString()}>
                              {i + 1} - {i === 0 ? 'No pain' : i < 3 ? 'Mild' : i < 7 ? 'Moderate' : 'Severe'}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    </div>
                    
                    <div>
                      <Label htmlFor="breathing">Breathing Difficulty</Label>
                      <Select value={symptomForm.breathing_difficulty} onValueChange={(value) => handleInputChange('breathing_difficulty', value)}>
                        <SelectTrigger className="mt-1">
                          <SelectValue placeholder="Select difficulty level" />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="none">None</SelectItem>
                          <SelectItem value="mild">Mild</SelectItem>
                          <SelectItem value="moderate">Moderate</SelectItem>
                          <SelectItem value="severe">Severe</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                  </div>
                  
                  <div>
                    <Label htmlFor="pain_location">Pain Location</Label>
                    <Input
                      id="pain_location"
                      placeholder="e.g., chest, head, back"
                      value={symptomForm.pain_location}
                      onChange={(e) => handleInputChange('pain_location', e.target.value)}
                      className="mt-1"
                    />
                  </div>
                  
                  <div>
                    <Label htmlFor="custom_symptoms">Additional Symptoms</Label>
                    <Textarea
                      id="custom_symptoms"
                      placeholder="Describe any other symptoms you're experiencing..."
                      value={symptomForm.custom_symptoms}
                      onChange={(e) => handleInputChange('custom_symptoms', e.target.value)}
                      className="mt-1"
                      rows={3}
                    />
                  </div>
                  
                  <Button 
                    type="submit" 
                    disabled={loading}
                    className="w-full bg-gradient-to-r from-emerald-500 to-teal-600 hover:from-emerald-600 hover:to-teal-700"
                  >
                    {loading ? 'Processing...' : 'Log Symptoms & Analyze Risk'}
                  </Button>
                </form>
              </CardContent>
            </Card>
          </div>
          
          {/* Recent Symptoms & Alert History */}
          <div className="space-y-6">
            {/* Recent Symptoms */}
            <Card className="shadow-lg border-0 bg-white/80 backdrop-blur-sm">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Clock className="w-5 h-5 text-blue-500" />
                  Recent Symptoms
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-3 max-h-64 overflow-y-auto">
                  {symptoms.slice(0, 5).map((symptom) => (
                    <div key={symptom.id} className="p-3 border rounded-lg bg-gray-50/50">
                      <div className="flex items-center justify-between mb-2">
                        {getSeverityBadge(symptom.severity_prediction)}
                        <span className="text-xs text-gray-500">
                          {new Date(symptom.timestamp).toLocaleDateString()}
                        </span>
                      </div>
                      <div className="text-sm text-gray-700">
                        {Object.entries(symptom.symptoms).map(([key, value]) => (
                          <div key={key} className="flex justify-between">
                            <span className="capitalize">{key.replace('_', ' ')}</span>
                            <span className="font-medium">{value}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  ))}
                  {symptoms.length === 0 && (
                    <p className="text-gray-500 text-center py-4">No symptoms logged yet</p>
                  )}
                </div>
              </CardContent>
            </Card>
            
            {/* Alert History */}
            <Card className="shadow-lg border-0 bg-white/80 backdrop-blur-sm">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Mail className="w-5 h-5 text-orange-500" />
                  Alert History
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-3 max-h-64 overflow-y-auto">
                  {alertHistory.slice(0, 5).map((alert) => (
                    <div key={alert.id} className="p-3 border rounded-lg bg-gray-50/50">
                      <div className="flex items-center justify-between mb-2">
                        {getSeverityBadge(alert.severity)}
                        <span className="text-xs text-gray-500">
                          {new Date(alert.timestamp).toLocaleDateString()}
                        </span>
                      </div>
                      <div className="flex items-center gap-2 text-sm">
                        {alert.email_sent ? (
                          <><Mail className="w-3 h-3 text-green-500" /> Email sent</>
                        ) : (
                          <><Mail className="w-3 h-3 text-gray-400" /> No email</>
                        )}
                        <Volume2 className="w-3 h-3 text-blue-500 ml-2" />
                        <span>Audio alert played</span>
                      </div>
                    </div>
                  ))}
                  {alertHistory.length === 0 && (
                    <p className="text-gray-500 text-center py-4">No alerts yet</p>
                  )}
                </div>
              </CardContent>
            </Card>
          </div>
        </div>
      </div>
    </div>
  );
};

// Main App Component
const App = () => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const token = localStorage.getItem('token');
    const userData = localStorage.getItem('user');
    
    if (token && userData) {
      setUser(JSON.parse(userData));
    }
    setLoading(false);
  }, []);

  const handleLogin = (userData) => {
    setUser(userData);
  };

  const handleLogout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    setUser(null);
    toast.success('Logged out successfully');
  };

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-center">
          <div className="w-16 h-16 bg-gradient-to-br from-emerald-500 to-teal-600 rounded-full flex items-center justify-center mx-auto mb-4">
            <Shield className="w-8 h-8 text-white animate-pulse" />
          </div>
          <p className="text-gray-600">Loading AlertRx...</p>
        </div>
      </div>
    );
  }

  return (
    <Router>
      <div className="App">
        <Toaster position="top-right" />
        <Routes>
          <Route 
            path="/" 
            element={
              user ? (
                <Dashboard user={user} onLogout={handleLogout} />
              ) : (
                <AuthPage onLogin={handleLogin} />
              )
            } 
          />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </div>
    </Router>
  );
};

export default App;