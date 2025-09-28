import React, { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { useTheme } from '@/hooks/useTheme';
import { 
  X,
  User,
  Bell,
  Shield,
  Palette,
  Database,
  Download,
  Upload,
  Settings as SettingsIcon,
  Save,
  RotateCcw,
  Sun,
  Moon,
  Monitor
} from 'lucide-react';

interface SettingsModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export default function SettingsModal({ isOpen, onClose }: SettingsModalProps) {
  const [activeTab, setActiveTab] = useState('general');
  const { theme, setTheme } = useTheme();
  const [settings, setSettings] = useState({
    notifications: true,
    autoSave: true,
    dataRetention: '12',
    defaultUnit: 'metric',
    language: 'en',
    timezone: 'UTC'
  });

  if (!isOpen) return null;

  const tabs = [
    { id: 'general', name: 'General', icon: SettingsIcon },
    { id: 'account', name: 'Account', icon: User },
    { id: 'notifications', name: 'Notifications', icon: Bell },
    { id: 'data', name: 'Data & Privacy', icon: Database },
    { id: 'appearance', name: 'Appearance', icon: Palette }
  ];

  const handleSettingChange = (key: string, value: any) => {
    setSettings(prev => ({ ...prev, [key]: value }));
  };

  const handleSave = () => {
    // Save settings logic would go here
    console.log('Settings saved:', settings);
    onClose();
  };

  const handleReset = () => {
    setSettings({
      notifications: true,
      darkMode: false,
      autoSave: true,
      dataRetention: '12',
      defaultUnit: 'metric',
      language: 'en',
      timezone: 'UTC'
    });
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      {/* Backdrop */}
      <div 
        className="absolute inset-0 bg-black bg-opacity-50"
        onClick={onClose}
      />
      
      {/* Modal */}
      <div className="relative bg-white dark:bg-gray-800 rounded-lg shadow-xl w-full max-w-4xl max-h-[90vh] overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between p-6 border-b border-gray-200 dark:border-gray-700">
          <div className="flex items-center space-x-3">
            <div className="p-2 bg-green-100 dark:bg-green-900/30 rounded-lg">
              <SettingsIcon className="h-6 w-6 text-green-600 dark:text-green-400" />
            </div>
            <div>
              <h2 className="text-xl font-semibold text-gray-900 dark:text-gray-100">Settings</h2>
              <p className="text-sm text-gray-500 dark:text-gray-400">Manage your Carbon Companion preferences</p>
            </div>
          </div>
          <Button variant="ghost" size="sm" onClick={onClose}>
            <X className="h-4 w-4" />
          </Button>
        </div>

        <div className="flex h-[600px]">
          {/* Sidebar */}
          <div className="w-64 bg-gray-50 dark:bg-gray-900 border-r border-gray-200 dark:border-gray-700 p-4">
            <nav className="space-y-2">
              {tabs.map((tab) => {
                const Icon = tab.icon;
                return (
                  <button
                    key={tab.id}
                    onClick={() => setActiveTab(tab.id)}
                    className={`w-full flex items-center px-3 py-2 text-sm font-medium rounded-md ${
                      activeTab === tab.id
                        ? 'bg-green-100 text-green-700'
                        : 'text-gray-600 hover:bg-gray-100 hover:text-gray-900'
                    }`}
                  >
                    <Icon className="h-4 w-4 mr-3" />
                    {tab.name}
                  </button>
                );
              })}
            </nav>
          </div>

          {/* Content */}
          <div className="flex-1 p-6 overflow-y-auto">
            {activeTab === 'general' && (
              <div className="space-y-6">
                <div>
                  <h3 className="text-lg font-medium text-gray-900 mb-4">General Settings</h3>
                  
                  <div className="space-y-4">
                    <div className="flex items-center justify-between">
                      <div>
                        <label className="text-sm font-medium text-gray-700">Auto-save data</label>
                        <p className="text-xs text-gray-500">Automatically save your work every few minutes</p>
                      </div>
                      <Button
                        variant={settings.autoSave ? 'default' : 'outline'}
                        size="sm"
                        onClick={() => handleSettingChange('autoSave', !settings.autoSave)}
                      >
                        {settings.autoSave ? 'Enabled' : 'Disabled'}
                      </Button>
                    </div>

                    <div className="flex items-center justify-between">
                      <div>
                        <label className="text-sm font-medium text-gray-700">Default units</label>
                        <p className="text-xs text-gray-500">Choose your preferred measurement system</p>
                      </div>
                      <select 
                        value={settings.defaultUnit}
                        onChange={(e) => handleSettingChange('defaultUnit', e.target.value)}
                        className="px-3 py-1 border border-gray-300 rounded-md text-sm"
                      >
                        <option value="metric">Metric (km, L, kg)</option>
                        <option value="imperial">Imperial (mi, gal, lb)</option>
                      </select>
                    </div>

                    <div className="flex items-center justify-between">
                      <div>
                        <label className="text-sm font-medium text-gray-700">Data retention</label>
                        <p className="text-xs text-gray-500">How long to keep historical data</p>
                      </div>
                      <select 
                        value={settings.dataRetention}
                        onChange={(e) => handleSettingChange('dataRetention', e.target.value)}
                        className="px-3 py-1 border border-gray-300 rounded-md text-sm"
                      >
                        <option value="6">6 months</option>
                        <option value="12">12 months</option>
                        <option value="24">24 months</option>
                        <option value="unlimited">Unlimited</option>
                      </select>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {activeTab === 'account' && (
              <div className="space-y-6">
                <div>
                  <h3 className="text-lg font-medium text-gray-900 mb-4">Account Information</h3>
                  
                  <div className="space-y-4">
                    <div className="p-4 bg-blue-50 rounded-lg">
                      <div className="flex items-center space-x-3">
                        <div className="p-2 bg-blue-100 rounded-full">
                          <User className="h-5 w-5 text-blue-600" />
                        </div>
                        <div>
                          <p className="font-medium text-blue-900">CarbonConstruct Integration</p>
                          <p className="text-sm text-blue-700">Connected to your CarbonConstruct account</p>
                        </div>
                        <Badge className="bg-green-100 text-green-800">Active</Badge>
                      </div>
                    </div>

                    <div className="grid grid-cols-2 gap-4">
                      <div>
                        <label className="block text-sm font-medium text-gray-700 mb-1">Organization</label>
                        <input 
                          type="text" 
                          value="CarbonConstruct Ltd"
                          className="w-full px-3 py-2 border border-gray-300 rounded-md text-sm bg-gray-50"
                          disabled
                        />
                      </div>
                      <div>
                        <label className="block text-sm font-medium text-gray-700 mb-1">Role</label>
                        <input 
                          type="text" 
                          value="Administrator"
                          className="w-full px-3 py-2 border border-gray-300 rounded-md text-sm bg-gray-50"
                          disabled
                        />
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {activeTab === 'notifications' && (
              <div className="space-y-6">
                <div>
                  <h3 className="text-lg font-medium text-gray-900 mb-4">Notification Preferences</h3>
                  
                  <div className="space-y-4">
                    <div className="flex items-center justify-between">
                      <div>
                        <label className="text-sm font-medium text-gray-700">Email notifications</label>
                        <p className="text-xs text-gray-500">Receive updates about your emissions data</p>
                      </div>
                      <Button
                        variant={settings.notifications ? 'default' : 'outline'}
                        size="sm"
                        onClick={() => handleSettingChange('notifications', !settings.notifications)}
                      >
                        {settings.notifications ? 'Enabled' : 'Disabled'}
                      </Button>
                    </div>

                    <div className="p-4 bg-yellow-50 rounded-lg">
                      <div className="flex items-start space-x-3">
                        <Bell className="h-5 w-5 text-yellow-600 mt-0.5" />
                        <div>
                          <p className="font-medium text-yellow-900">Supplier Data Requests</p>
                          <p className="text-sm text-yellow-700">Get notified when suppliers submit emissions data</p>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {activeTab === 'data' && (
              <div className="space-y-6">
                <div>
                  <h3 className="text-lg font-medium text-gray-900 mb-4">Data & Privacy</h3>
                  
                  <div className="space-y-4">
                    <div className="p-4 bg-green-50 rounded-lg">
                      <div className="flex items-center space-x-3">
                        <Shield className="h-5 w-5 text-green-600" />
                        <div>
                          <p className="font-medium text-green-900">Data Security</p>
                          <p className="text-sm text-green-700">Your data is encrypted and securely stored</p>
                        </div>
                      </div>
                    </div>

                    <div className="grid grid-cols-2 gap-4">
                      <Button variant="outline" className="flex items-center space-x-2">
                        <Download className="h-4 w-4" />
                        <span>Export Data</span>
                      </Button>
                      <Button variant="outline" className="flex items-center space-x-2">
                        <Upload className="h-4 w-4" />
                        <span>Import Data</span>
                      </Button>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {activeTab === 'appearance' && (
              <div className="space-y-6">
                <div>
                  <h3 className="text-lg font-medium text-gray-900 dark:text-gray-100 mb-4">Appearance</h3>
                  
                  <div className="space-y-4">
                    <div>
                      <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-3">Theme</label>
                      <div className="grid grid-cols-3 gap-3">
                        <button
                          onClick={() => setTheme('light')}
                          className={`p-3 rounded-lg border-2 transition-all ${
                            theme === 'light' 
                              ? 'border-green-500 bg-green-50 dark:bg-green-900/20' 
                              : 'border-gray-200 dark:border-gray-700 hover:border-gray-300 dark:hover:border-gray-600'
                          }`}
                        >
                          <Sun className="h-5 w-5 mx-auto mb-2 text-gray-700 dark:text-gray-300" />
                          <span className="text-sm font-medium text-gray-700 dark:text-gray-300">Light</span>
                        </button>
                        
                        <button
                          onClick={() => setTheme('dark')}
                          className={`p-3 rounded-lg border-2 transition-all ${
                            theme === 'dark' 
                              ? 'border-green-500 bg-green-50 dark:bg-green-900/20' 
                              : 'border-gray-200 dark:border-gray-700 hover:border-gray-300 dark:hover:border-gray-600'
                          }`}
                        >
                          <Moon className="h-5 w-5 mx-auto mb-2 text-gray-700 dark:text-gray-300" />
                          <span className="text-sm font-medium text-gray-700 dark:text-gray-300">Dark</span>
                        </button>
                        
                        <button
                          onClick={() => setTheme('system')}
                          className={`p-3 rounded-lg border-2 transition-all ${
                            theme === 'system' 
                              ? 'border-green-500 bg-green-50 dark:bg-green-900/20' 
                              : 'border-gray-200 dark:border-gray-700 hover:border-gray-300 dark:hover:border-gray-600'
                          }`}
                        >
                          <Monitor className="h-5 w-5 mx-auto mb-2 text-gray-700 dark:text-gray-300" />
                          <span className="text-sm font-medium text-gray-700 dark:text-gray-300">System</span>
                        </button>
                      </div>
                      <p className="text-xs text-gray-500 dark:text-gray-400 mt-2">
                        {theme === 'system' ? 'Automatically matches your system preference' : 
                         theme === 'dark' ? 'Dark theme is active' : 'Light theme is active'}
                      </p>
                    </div>

                    <div className="p-4 bg-blue-50 dark:bg-blue-900/20 rounded-lg">
                      <div className="flex items-start space-x-3">
                        <Palette className="h-5 w-5 text-blue-600 dark:text-blue-400 mt-0.5" />
                        <div>
                          <p className="font-medium text-blue-900 dark:text-blue-100">Theme Customization</p>
                          <p className="text-sm text-blue-700 dark:text-blue-300">More theme options coming soon</p>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Footer */}
        <div className="flex items-center justify-between p-6 border-t border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-800">
          <Button variant="outline" onClick={handleReset} className="flex items-center space-x-2">
            <RotateCcw className="h-4 w-4" />
            <span>Reset to Defaults</span>
          </Button>
          
          <div className="flex items-center space-x-3">
            <Button variant="outline" onClick={onClose}>
              Cancel
            </Button>
            <Button onClick={handleSave} className="flex items-center space-x-2">
              <Save className="h-4 w-4" />
              <span>Save Changes</span>
            </Button>
          </div>
        </div>
      </div>
    </div>
  );
}

