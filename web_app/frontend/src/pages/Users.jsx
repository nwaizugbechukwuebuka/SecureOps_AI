import React, { useState, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';
import { apiService } from '../services/api';
import { formatTimeAgo, capitalize, getStatusColor } from '../utils/helpers';
import { useTheme } from '../utils/theme';
import { 
  Users as UsersIcon, 
  UserPlus, 
  Edit, 
  Trash2, 
  Shield, 
  ShieldCheck, 
  Search,
  RefreshCw,
  Eye,
  EyeOff,
  X
} from 'lucide-react';
import toast from 'react-hot-toast';

const Users = () => {
  const { user } = useAuth();
  const { isDark } = useTheme();
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [showModal, setShowModal] = useState(false);
  const [selectedUser, setSelectedUser] = useState(null);
  const [formData, setFormData] = useState({
    username: '',
    email: '',
    full_name: '',
    role: 'user',
    password: '',
    is_active: true
  });

  // Check if current user is admin
  const isAdmin = user?.role === 'admin';

  // Role options
  const roleOptions = [
    { value: 'user', label: 'User', icon: <UsersIcon className="w-4 h-4" /> },
    { value: 'admin', label: 'Administrator', icon: <Shield className="w-4 h-4" /> },
    { value: 'moderator', label: 'Moderator', icon: <ShieldCheck className="w-4 h-4" /> }
  ];

  // Load users
  const loadUsers = async () => {
    try {
      setLoading(true);
      const data = await apiService.getUsers();
      setUsers(data || []);
    } catch (error) {
      console.error('Error loading users:', error);
      toast.error('Failed to load users');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (isAdmin) {
      loadUsers();
    }
  }, [isAdmin]);

  // Filter users based on search term
  const filteredUsers = users.filter(u => 
    !searchTerm || 
    u.username.toLowerCase().includes(searchTerm.toLowerCase()) ||
    u.email.toLowerCase().includes(searchTerm.toLowerCase()) ||
    u.full_name?.toLowerCase().includes(searchTerm.toLowerCase())
  );

  // Handle form submission
  const handleSubmit = async (e) => {
    e.preventDefault();
    
    try {
      if (selectedUser) {
        // Update existing user
        const updatedUser = await apiService.updateUser(selectedUser.id, formData);
        setUsers(prev => prev.map(u => u.id === selectedUser.id ? updatedUser : u));
        toast.success('User updated successfully');
      } else {
        // Create new user
        const newUser = await apiService.createUser(formData);
        setUsers(prev => [newUser, ...prev]);
        toast.success('User created successfully');
      }
      
      setShowModal(false);
      resetForm();
    } catch (error) {
      toast.error(selectedUser ? 'Failed to update user' : 'Failed to create user');
    }
  };

  // Handle user deletion
  const handleDelete = async (userId) => {
    if (!window.confirm('Are you sure you want to delete this user?')) return;
    
    try {
      await apiService.deleteUser(userId);
      setUsers(prev => prev.filter(u => u.id !== userId));
      toast.success('User deleted successfully');
    } catch (error) {
      toast.error('Failed to delete user');
    }
  };

  // Reset form
  const resetForm = () => {
    setFormData({
      username: '',
      email: '',
      full_name: '',
      role: 'user',
      password: '',
      is_active: true
    });
    setSelectedUser(null);
  };

  // Open create modal
  const openCreateModal = () => {
    resetForm();
    setShowModal(true);
  };

  // Open edit modal
  const openEditModal = (u) => {
    setSelectedUser(u);
    setFormData({
      username: u.username,
      email: u.email,
      full_name: u.full_name || '',
      role: u.role,
      password: '',
      is_active: u.is_active
    });
    setShowModal(true);
  };

  const getRoleIcon = (role) => {
    const roleOption = roleOptions.find(r => r.value === role);
    return roleOption ? roleOption.icon : <UsersIcon className="w-4 h-4" />;
  };

  const themeClasses = {
    background: isDark ? 'bg-gray-900' : 'bg-gray-50',
    card: isDark ? 'bg-gray-800 border-gray-700' : 'bg-white border-gray-200',
    text: isDark ? 'text-gray-100' : 'text-gray-900',
    textSecondary: isDark ? 'text-gray-400' : 'text-gray-600',
    input: isDark ? 'bg-gray-700 border-gray-600 text-white' : 'bg-white border-gray-300',
    button: isDark ? 'bg-blue-600 hover:bg-blue-700' : 'bg-blue-600 hover:bg-blue-700'
  };

  if (!isAdmin) {
    return (
      <div className={`min-h-screen ${themeClasses.background} flex items-center justify-center`}>
        <div className={`${themeClasses.card} rounded-lg border p-8 text-center`}>
          <Shield className={`w-12 h-12 mx-auto mb-4 ${themeClasses.textSecondary}`} />
          <h2 className={`text-xl font-semibold ${themeClasses.text} mb-2`}>
            Access Denied
          </h2>
          <p className={themeClasses.textSecondary}>
            You need administrator privileges to access user management.
          </p>
        </div>
      </div>
    );
  }

  if (loading) {
    return (
      <div className={`min-h-screen ${themeClasses.background} flex items-center justify-center`}>
        <div className="text-center">
          <RefreshCw className="w-8 h-8 mx-auto mb-4 animate-spin text-blue-500" />
          <p className={themeClasses.text}>Loading users...</p>
        </div>
      </div>
    );
  }

  return (
    <div className={`min-h-screen ${themeClasses.background} p-6`}>
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="flex justify-between items-center mb-6">
          <div>
            <h1 className={`text-3xl font-bold ${themeClasses.text}`}>User Management</h1>
            <p className={themeClasses.textSecondary}>
              Manage user accounts, roles, and permissions
            </p>
          </div>
          
          <div className="flex space-x-3">
            <button
              onClick={loadUsers}
              className="px-4 py-2 text-gray-600 hover:text-gray-800 hover:bg-gray-100 rounded-lg flex items-center space-x-2 transition-colors"
            >
              <RefreshCw className="w-4 h-4" />
              <span>Refresh</span>
            </button>
            
            <button
              onClick={openCreateModal}
              className={`px-4 py-2 rounded-lg ${themeClasses.button} text-white flex items-center space-x-2`}
            >
              <UserPlus className="w-4 h-4" />
              <span>Add User</span>
            </button>
          </div>
        </div>

        {/* Search */}
        <div className={`${themeClasses.card} rounded-lg border p-4 mb-6`}>
          <div className="flex items-center space-x-3">
            <Search className={`w-5 h-5 ${themeClasses.textSecondary}`} />
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Search users by username, email, or name..."
              className={`flex-1 px-3 py-2 border rounded-lg ${themeClasses.input}`}
            />
          </div>
        </div>

        {/* Users List */}
        <div className={`${themeClasses.card} rounded-lg border overflow-hidden`}>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className={`${isDark ? 'bg-gray-700' : 'bg-gray-50'} border-b ${isDark ? 'border-gray-600' : 'border-gray-200'}`}>
                <tr>
                  <th className={`px-6 py-3 text-left text-xs font-medium ${themeClasses.textSecondary} uppercase tracking-wider`}>
                    User
                  </th>
                  <th className={`px-6 py-3 text-left text-xs font-medium ${themeClasses.textSecondary} uppercase tracking-wider`}>
                    Role
                  </th>
                  <th className={`px-6 py-3 text-left text-xs font-medium ${themeClasses.textSecondary} uppercase tracking-wider`}>
                    Status
                  </th>
                  <th className={`px-6 py-3 text-left text-xs font-medium ${themeClasses.textSecondary} uppercase tracking-wider`}>
                    Last Login
                  </th>
                  <th className={`px-6 py-3 text-right text-xs font-medium ${themeClasses.textSecondary} uppercase tracking-wider`}>
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody className={`divide-y ${isDark ? 'divide-gray-700' : 'divide-gray-200'}`}>
                {filteredUsers.length === 0 ? (
                  <tr>
                    <td colSpan="5" className="px-6 py-8 text-center">
                      <UsersIcon className={`w-12 h-12 mx-auto mb-4 ${themeClasses.textSecondary}`} />
                      <h3 className={`text-lg font-semibold ${themeClasses.text} mb-2`}>
                        No users found
                      </h3>
                      <p className={themeClasses.textSecondary}>
                        {searchTerm ? 'Try adjusting your search terms.' : 'No users have been created yet.'}
                      </p>
                    </td>
                  </tr>
                ) : (
                  filteredUsers.map(u => (
                    <tr key={u.id} className={`hover:${isDark ? 'bg-gray-700' : 'bg-gray-50'}`}>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <div>
                          <div className={`text-sm font-medium ${themeClasses.text}`}>
                            {u.full_name || u.username}
                          </div>
                          <div className={`text-sm ${themeClasses.textSecondary}`}>
                            {u.email}
                          </div>
                        </div>
                      </td>
                      
                      <td className="px-6 py-4 whitespace-nowrap">
                        <div className="flex items-center space-x-2">
                          {getRoleIcon(u.role)}
                          <span className={`text-sm ${themeClasses.text}`}>
                            {capitalize(u.role)}
                          </span>
                        </div>
                      </td>
                      
                      <td className="px-6 py-4 whitespace-nowrap">
                        <span className={`px-2 py-1 text-xs font-medium rounded-full ${getStatusColor(u.is_active ? 'active' : 'inactive')}`}>
                          {u.is_active ? 'Active' : 'Inactive'}
                        </span>
                      </td>
                      
                      <td className="px-6 py-4 whitespace-nowrap">
                        <span className={`text-sm ${themeClasses.textSecondary}`}>
                          {u.last_login ? formatTimeAgo(u.last_login) : 'Never'}
                        </span>
                      </td>
                      
                      <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                        <div className="flex items-center justify-end space-x-2">
                          <button
                            onClick={() => openEditModal(u)}
                            className="text-blue-600 hover:text-blue-900 p-1 rounded"
                            title="Edit user"
                          >
                            <Edit className="w-4 h-4" />
                          </button>
                          
                          {u.id !== user.id && (
                            <button
                              onClick={() => handleDelete(u.id)}
                              className="text-red-600 hover:text-red-900 p-1 rounded"
                              title="Delete user"
                            >
                              <Trash2 className="w-4 h-4" />
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* User Form Modal */}
        {showModal && (
          <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
            <div className={`${themeClasses.card} rounded-lg border max-w-md w-full`}>
              <div className="p-6">
                <div className="flex items-center justify-between mb-4">
                  <h2 className={`text-xl font-bold ${themeClasses.text}`}>
                    {selectedUser ? 'Edit User' : 'Create New User'}
                  </h2>
                  
                  <button
                    onClick={() => setShowModal(false)}
                    className="text-gray-500 hover:text-gray-700"
                  >
                    <X className="w-6 h-6" />
                  </button>
                </div>
                
                <form onSubmit={handleSubmit} className="space-y-4">
                  <div>
                    <label className={`block text-sm font-medium ${themeClasses.text} mb-1`}>
                      Username *
                    </label>
                    <input
                      type="text"
                      value={formData.username}
                      onChange={(e) => setFormData(prev => ({ ...prev, username: e.target.value }))}
                      className={`w-full px-3 py-2 border rounded-lg ${themeClasses.input}`}
                      required
                    />
                  </div>
                  
                  <div>
                    <label className={`block text-sm font-medium ${themeClasses.text} mb-1`}>
                      Email *
                    </label>
                    <input
                      type="email"
                      value={formData.email}
                      onChange={(e) => setFormData(prev => ({ ...prev, email: e.target.value }))}
                      className={`w-full px-3 py-2 border rounded-lg ${themeClasses.input}`}
                      required
                    />
                  </div>
                  
                  <div>
                    <label className={`block text-sm font-medium ${themeClasses.text} mb-1`}>
                      Full Name
                    </label>
                    <input
                      type="text"
                      value={formData.full_name}
                      onChange={(e) => setFormData(prev => ({ ...prev, full_name: e.target.value }))}
                      className={`w-full px-3 py-2 border rounded-lg ${themeClasses.input}`}
                    />
                  </div>
                  
                  <div>
                    <label className={`block text-sm font-medium ${themeClasses.text} mb-1`}>
                      Role *
                    </label>
                    <select
                      value={formData.role}
                      onChange={(e) => setFormData(prev => ({ ...prev, role: e.target.value }))}
                      className={`w-full px-3 py-2 border rounded-lg ${themeClasses.input}`}
                      required
                    >
                      {roleOptions.map(option => (
                        <option key={option.value} value={option.value}>
                          {option.label}
                        </option>
                      ))}
                    </select>
                  </div>
                  
                  <div>
                    <label className={`block text-sm font-medium ${themeClasses.text} mb-1`}>
                      Password {selectedUser ? '(leave empty to keep current)' : '*'}
                    </label>
                    <input
                      type="password"
                      value={formData.password}
                      onChange={(e) => setFormData(prev => ({ ...prev, password: e.target.value }))}
                      className={`w-full px-3 py-2 border rounded-lg ${themeClasses.input}`}
                      required={!selectedUser}
                    />
                  </div>
                  
                  <div className="flex items-center">
                    <input
                      type="checkbox"
                      id="is_active"
                      checked={formData.is_active}
                      onChange={(e) => setFormData(prev => ({ ...prev, is_active: e.target.checked }))}
                      className="mr-2"
                    />
                    <label htmlFor="is_active" className={`text-sm ${themeClasses.text}`}>
                      Active user
                    </label>
                  </div>
                  
                  <div className="flex justify-end space-x-3 pt-4">
                    <button
                      type="button"
                      onClick={() => setShowModal(false)}
                      className="px-4 py-2 text-gray-600 hover:text-gray-800 hover:bg-gray-100 rounded-lg transition-colors"
                    >
                      Cancel
                    </button>
                    
                    <button
                      type="submit"
                      className={`px-4 py-2 rounded-lg ${themeClasses.button} text-white`}
                    >
                      {selectedUser ? 'Update' : 'Create'}
                    </button>
                  </div>
                </form>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default Users;