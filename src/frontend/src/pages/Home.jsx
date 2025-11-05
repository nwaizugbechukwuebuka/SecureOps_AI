import React, { useState, useEffect } from 'react';
import {
  Box,
  Container,
  Grid,
  Typography,
  Card,
  CardContent,
  useTheme,
  Fade,
  Skeleton,
  Alert
} from '@mui/material';
import {
  Dashboard as DashboardIcon,
  Security as SecurityIcon,
  TrendingUp as TrendingUpIcon,
  Speed as SpeedIcon
} from '@mui/icons-material';
import { motion } from 'framer-motion';
import Dashboard from '../components/Dashboard';
import AIThreatDashboardEntry from '../components/AIThreatDashboardEntry';
import { useAuth } from '../services/auth';
import { api } from '../services/api';

const Home = () => {
  const theme = useTheme();
  const { user } = useAuth();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [quickStats, setQuickStats] = useState(null);

  useEffect(() => {
    loadQuickStats();
  }, []);

  const loadQuickStats = async () => {
    try {
      setLoading(true);
      setError(null);
      const response = await api.get('/dashboard/quick-stats');
      setQuickStats(response.data);
    } catch (err) {
      setError('Failed to load quick statistics');
      console.error('Quick stats error:', err);
    } finally {
      setLoading(false);
    }
  };

  const getGreeting = () => {
    const hour = new Date().getHours();
    if (hour < 12) return 'Good morning';
    if (hour < 18) return 'Good afternoon';
    return 'Good evening';
  };

  const containerVariants = {
    hidden: { opacity: 0 },
    visible: {
      opacity: 1,
      transition: {
        duration: 0.6,
        staggerChildren: 0.1
      }
    }
  };

  const itemVariants = {
    hidden: { y: 20, opacity: 0 },
    visible: {
      y: 0,
      opacity: 1,
      transition: {
        duration: 0.5,
        ease: "easeOut"
      }
    }
  };

  return (
    <Container maxWidth="xl" sx={{ py: 3 }}>
      <motion.div
        variants={containerVariants}
        initial="hidden"
        animate="visible"
      >
        {/* Welcome Header */}
        <motion.div variants={itemVariants}>
          <Box sx={{ mb: 4 }}>
            <Typography 
              variant="h3" 
              sx={{ 
                fontWeight: 700,
                background: `linear-gradient(45deg, ${theme.palette.primary.main}, ${theme.palette.secondary.main})`,
                backgroundClip: 'text',
                WebkitBackgroundClip: 'text',
                WebkitTextFillColor: 'transparent',
                mb: 1
              }}
            >
              {getGreeting()}, {user?.firstName || 'User'}!
            </Typography>
            <Typography 
              variant="h6" 
              color="text.secondary"
              sx={{ fontWeight: 400 }}
            >
              Welcome to your SecureOps Dashboard - Your DevSecOps Command Center
            </Typography>
          </Box>
        </motion.div>

        {/* Quick Stats Cards */}
        {quickStats && (
          <motion.div variants={itemVariants}>
            <Grid container spacing={3} sx={{ mb: 4 }}>
              <Grid item xs={12} sm={6} md={3}>
                <Card 
                  sx={{ 
                    background: `linear-gradient(135deg, ${theme.palette.primary.main}15 0%, ${theme.palette.primary.main}05 100%)`,
                    border: `1px solid ${theme.palette.primary.main}20`,
                    transition: 'transform 0.2s ease-in-out',
                    '&:hover': {
                      transform: 'translateY(-4px)',
                      boxShadow: theme.shadows[8]
                    }
                  }}
                >
                  <CardContent>
                    <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                      <Box>
                        <Typography variant="body2" color="text.secondary" gutterBottom>
                          Active Pipelines
                        </Typography>
                        <Typography variant="h4" sx={{ fontWeight: 600 }}>
                          {loading ? <Skeleton width={60} /> : quickStats.activePipelines || 0}
                        </Typography>
                        <Typography variant="caption" color="primary">
                          {loading ? <Skeleton width={80} /> : `${quickStats.pipelineGrowth || 0}% this week`}
                        </Typography>
                      </Box>
                      <SpeedIcon 
                        sx={{ 
                          fontSize: 48, 
                          color: theme.palette.primary.main, 
                          opacity: 0.7 
                        }} 
                      />
                    </Box>
                  </CardContent>
                </Card>
              </Grid>

              <Grid item xs={12} sm={6} md={3}>
                <Card 
                  sx={{ 
                    background: `linear-gradient(135deg, ${theme.palette.error.main}15 0%, ${theme.palette.error.main}05 100%)`,
                    border: `1px solid ${theme.palette.error.main}20`,
                    transition: 'transform 0.2s ease-in-out',
                    '&:hover': {
                      transform: 'translateY(-4px)',
                      boxShadow: theme.shadows[8]
                    }
                  }}
                >
                  <CardContent>
                    <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                      <Box>
                        <Typography variant="body2" color="text.secondary" gutterBottom>
                          Critical Vulnerabilities
                        </Typography>
                        <Typography variant="h4" sx={{ fontWeight: 600 }}>
                          {loading ? <Skeleton width={60} /> : quickStats.criticalVulns || 0}
                        </Typography>
                        <Typography variant="caption" color="error">
                          {loading ? <Skeleton width={80} /> : 'Needs immediate attention'}
                        </Typography>
                      </Box>
                      <SecurityIcon 
                        sx={{ 
                          fontSize: 48, 
                          color: theme.palette.error.main, 
                          opacity: 0.7 
                        }} 
                      />
                    </Box>
                  </CardContent>
                </Card>
              </Grid>

              <Grid item xs={12} sm={6} md={3}>
                <Card 
                  sx={{ 
                    background: `linear-gradient(135deg, ${theme.palette.success.main}15 0%, ${theme.palette.success.main}05 100%)`,
                    border: `1px solid ${theme.palette.success.main}20`,
                    transition: 'transform 0.2s ease-in-out',
                    '&:hover': {
                      transform: 'translateY(-4px)',
                      boxShadow: theme.shadows[8]
                    }
                  }}
                >
                  <CardContent>
                    <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                      <Box>
                        <Typography variant="body2" color="text.secondary" gutterBottom>
                          Security Score
                        </Typography>
                        <Typography variant="h4" sx={{ fontWeight: 600 }}>
                          {loading ? <Skeleton width={60} /> : `${quickStats.securityScore || 0}%`}
                        </Typography>
                        <Typography variant="caption" color="success.main">
                          {loading ? <Skeleton width={80} /> : 'Above average'}
                        </Typography>
                      </Box>
                      <TrendingUpIcon 
                        sx={{ 
                          fontSize: 48, 
                          color: theme.palette.success.main, 
                          opacity: 0.7 
                        }} 
                      />
                    </Box>
                  </CardContent>
                </Card>
              </Grid>

              <Grid item xs={12} sm={6} md={3}>
                <Card 
                  sx={{ 
                    background: `linear-gradient(135deg, ${theme.palette.info.main}15 0%, ${theme.palette.info.main}05 100%)`,
                    border: `1px solid ${theme.palette.info.main}20`,
                    transition: 'transform 0.2s ease-in-out',
                    '&:hover': {
                      transform: 'translateY(-4px)',
                      boxShadow: theme.shadows[8]
                    }
                  }}
                >
                  <CardContent>
                    <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                      <Box>
                        <Typography variant="body2" color="text.secondary" gutterBottom>
                          Scans Today
                        </Typography>
                        <Typography variant="h4" sx={{ fontWeight: 600 }}>
                          {loading ? <Skeleton width={60} /> : quickStats.scansToday || 0}
                        </Typography>
                        <Typography variant="caption" color="info.main">
                          {loading ? <Skeleton width={80} /> : `${quickStats.successRate || 0}% success rate`}
                        </Typography>
                      </Box>
                      <DashboardIcon 
                        sx={{ 
                          fontSize: 48, 
                          color: theme.palette.info.main, 
                          opacity: 0.7 
                        }} 
                      />
                    </Box>
                  </CardContent>
                </Card>
              </Grid>
            </Grid>
          </motion.div>
        )}

        {/* Error Alert */}
        {error && (
          <motion.div variants={itemVariants}>
            <Alert severity="error" sx={{ mb: 3 }}>
              {error}
            </Alert>
          </motion.div>
        )}

        {/* Main Dashboard */}

        <motion.div variants={itemVariants}>
          <Fade in={!loading} timeout={600}>
            <Box>
              <Dashboard />
              {/* AI Threats Dashboard Section */}
              <AIThreatDashboardEntry />
            </Box>
          </Fade>
        </motion.div>

        {/* Getting Started Section */}
        {(!quickStats?.activePipelines || quickStats.activePipelines === 0) && (
          <motion.div variants={itemVariants}>
            <Card sx={{ mt: 4, p: 2 }}>
              <CardContent>
                <Typography variant="h5" gutterBottom>
                  🚀 Getting Started with SecureOps
                </Typography>
                <Typography variant="body1" paragraph>
                  Welcome to SecureOps! To get started with monitoring your DevSecOps pipelines:
                </Typography>
                <Box component="ol" sx={{ pl: 2 }}>
                  <Typography component="li" variant="body2" paragraph>
                    <strong>Connect your CI/CD platforms:</strong> Integrate with GitHub Actions, GitLab CI, Jenkins, or Azure DevOps
                  </Typography>
                  <Typography component="li" variant="body2" paragraph>
                    <strong>Configure security scanners:</strong> Set up Trivy, Safety, Bandit, and other security tools
                  </Typography>
                  <Typography component="li" variant="body2" paragraph>
                    <strong>Define compliance frameworks:</strong> Choose from OWASP, NIST, SOC2, and other standards
                  </Typography>
                  <Typography component="li" variant="body2" paragraph>
                    <strong>Set up alerts:</strong> Configure notifications for critical security findings
                  </Typography>
                </Box>
                <Typography variant="body2" color="text.secondary">
                  Visit the Settings page to configure your integrations and start monitoring your pipelines.
                </Typography>
              </CardContent>
            </Card>
          </motion.div>
        )}
      </motion.div>
    </Container>
  );
};

export default Home;
