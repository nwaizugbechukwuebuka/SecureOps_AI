import React from 'react'
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from 'react-query'
import { ReactQueryDevtools } from 'react-query/devtools'
import { Toaster } from 'react-hot-toast'
<<<<<<< HEAD
import { AuthProvider } from './context/AuthContext.jsx'
import { useAuth } from './hooks/useAuth'

// Page Components
import LoginPage from './pages/LoginPage'
import Dashboard from './pages/Dashboard'
=======
import { AuthProvider, useAuth } from './contexts/AuthContext'
import { WebSocketProvider } from './contexts/WebSocketContext'
import { ThemeProvider } from './contexts/ThemeContext'

// Layout Components
import Navbar from './components/Navbar'
import Sidebar from './components/Sidebar'
import LoadingSpinner from './components/LoadingSpinner'
import ErrorBoundary from './components/ErrorBoundary'

// Page Components
import Home from './pages/Home'
import Pipelines from './pages/Pipelines'
import Alerts from './pages/Alerts'
import Compliance from './pages/Compliance'
import Settings from './pages/Settings'
import Login from './pages/Login'
import Dashboard from './components/Dashboard'
>>>>>>> 7c10f27ecb7c8b1a33ad81e0ccc85bf68459bdc3

// Create React Query client
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 2,
      staleTime: 5 * 60 * 1000, // 5 minutes
      cacheTime: 10 * 60 * 1000, // 10 minutes
      refetchOnWindowFocus: false,
    },
    mutations: {
      retry: 1,
    },
  },
})

// Protected Route Component
const ProtectedRoute = ({ children }) => {
<<<<<<< HEAD
  const { user, loading } = useAuth()
=======
  const { isAuthenticated, loading } = useAuth()
>>>>>>> 7c10f27ecb7c8b1a33ad81e0ccc85bf68459bdc3

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <LoadingSpinner size="large" />
      </div>
    )
  }

<<<<<<< HEAD
  if (!user) {
=======
  if (!isAuthenticated) {
>>>>>>> 7c10f27ecb7c8b1a33ad81e0ccc85bf68459bdc3
    return <Navigate to="/login" replace />
  }

  return <>{children}</>
}

<<<<<<< HEAD
// Main App Component
const App = () => {
  return (
    <AuthProvider>
      <QueryClientProvider client={queryClient}>
        <Router>
          <div className="App">
            <Routes>
              <Route path="/login" element={<LoginPage />} />
              <Route 
                path="/" 
                element={
                  <ProtectedRoute>
                    <Dashboard />
                  </ProtectedRoute>
                } 
              />
            </Routes>
            
            {/* Global Toast Notifications */}
            <Toaster
              position="top-right"
              toastOptions={{
                duration: 4000,
                className: 'toast-custom',
                style: {
                  background: '#363636',
                  color: '#fff',
                },
                success: {
                  iconTheme: {
                    primary: '#10B981',
                    secondary: '#fff',
                  },
                },
                error: {
                  iconTheme: {
                    primary: '#EF4444',
                    secondary: '#fff',
                  },
                },
              }}
            />
          </div>
        </Router>
=======
// Main Layout Component
const Layout = ({ children }) => {
  const [sidebarOpen, setSidebarOpen] = React.useState(false)

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900">
      <Navbar onMenuClick={() => setSidebarOpen(!sidebarOpen)} />
      
      <div className="flex">
        <Sidebar open={sidebarOpen} onClose={() => setSidebarOpen(false)} />
        
        <main className="flex-1 lg:ml-64">
          <div className="px-4 sm:px-6 lg:px-8 py-6">
            {children}
          </div>
        </main>
      </div>
    </div>
  )
}

// Public Layout Component (for login page)
const PublicLayout = ({ children }) => {
  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 dark:from-gray-900 dark:to-gray-800">
      {children}
    </div>
  )
}

// App Routes Component
const AppRoutes = () => {
  const { isAuthenticated } = useAuth()

  return (
    <Routes>
      {/* Public Routes */}
      <Route 
        path="/login" 
        element={
          isAuthenticated ? (
            <Navigate to="/" replace />
          ) : (
            <PublicLayout>
              <Login />
            </PublicLayout>
          )
        } 
      />

      {/* Protected Routes */}
      <Route 
        path="/" 
        element={
          <ProtectedRoute>
            <Layout>
              <Home />
            </Layout>
          </ProtectedRoute>
        } 
      />

      <Route 
        path="/dashboard" 
        element={
          <ProtectedRoute>
            <Layout>
              <Dashboard />
            </Layout>
          </ProtectedRoute>
        } 
      />

      <Route 
        path="/pipelines/*" 
        element={
          <ProtectedRoute>
            <Layout>
              <Pipelines />
            </Layout>
          </ProtectedRoute>
        } 
      />

      <Route 
        path="/alerts/*" 
        element={
          <ProtectedRoute>
            <Layout>
              <Alerts />
            </Layout>
          </ProtectedRoute>
        } 
      />

      <Route 
        path="/compliance/*" 
        element={
          <ProtectedRoute>
            <Layout>
              <Compliance />
            </Layout>
          </ProtectedRoute>
        } 
      />

      <Route 
        path="/settings/*" 
        element={
          <ProtectedRoute>
            <Layout>
              <Settings />
            </Layout>
          </ProtectedRoute>
        } 
      />

      {/* Catch-all redirect */}
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  )
}

// Main App Component
const App = () => {
  return (
    <ErrorBoundary>
      <QueryClientProvider client={queryClient}>
        <ThemeProvider>
          <AuthProvider>
            <WebSocketProvider>
              <Router>
                <div className="App">
                  <AppRoutes />
                  
                  {/* Global Toast Notifications */}
                  <Toaster
                    position="top-right"
                    toastOptions={{
                      duration: 4000,
                      className: 'toast-custom',
                      style: {
                        background: '#363636',
                        color: '#fff',
                      },
                      success: {
                        iconTheme: {
                          primary: '#10B981',
                          secondary: '#fff',
                        },
                      },
                      error: {
                        iconTheme: {
                          primary: '#EF4444',
                          secondary: '#fff',
                        },
                      },
                    }}
                  />
                </div>
              </Router>
            </WebSocketProvider>
          </AuthProvider>
        </ThemeProvider>
>>>>>>> 7c10f27ecb7c8b1a33ad81e0ccc85bf68459bdc3
        
        {/* React Query Devtools (only in development) */}
        {process.env.NODE_ENV === 'development' && (
          <ReactQueryDevtools initialIsOpen={false} />
        )}
      </QueryClientProvider>
<<<<<<< HEAD
    </AuthProvider>
=======
    </ErrorBoundary>
>>>>>>> 7c10f27ecb7c8b1a33ad81e0ccc85bf68459bdc3
  )
}

export default App
