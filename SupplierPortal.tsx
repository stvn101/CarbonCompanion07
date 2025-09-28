import React, { useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { 
  Upload, 
  Download, 
  CheckCircle, 
  Clock, 
  AlertCircle,
  Building,
  Mail,
  Phone,
  FileText,
  Calendar
} from 'lucide-react';

interface SupplierData {
  id: string;
  name: string;
  email: string;
  category: string;
  status: 'pending' | 'submitted' | 'verified' | 'rejected';
  lastUpdated: string;
  emissions: number;
  dataQuality: 'high' | 'medium' | 'low';
}

interface DataRequest {
  id: string;
  category: string;
  description: string;
  dueDate: string;
  status: 'sent' | 'received' | 'overdue';
  priority: 'high' | 'medium' | 'low';
}

const mockSuppliers: SupplierData[] = [
  {
    id: 'SUP001',
    name: 'Green Materials Ltd',
    email: 'sustainability@greenmaterials.com',
    category: 'Purchased Goods & Services',
    status: 'verified',
    lastUpdated: '2025-01-10',
    emissions: 450.2,
    dataQuality: 'high'
  },
  {
    id: 'SUP002',
    name: 'EcoTransport Solutions',
    email: 'data@ecotransport.com',
    category: 'Upstream Transportation',
    status: 'submitted',
    lastUpdated: '2025-01-08',
    emissions: 95.3,
    dataQuality: 'medium'
  },
  {
    id: 'SUP003',
    name: 'Renewable Energy Corp',
    email: 'reporting@renewablecorp.com',
    category: 'Fuel & Energy Related',
    status: 'pending',
    lastUpdated: '2025-01-05',
    emissions: 0,
    dataQuality: 'low'
  }
];

const mockDataRequests: DataRequest[] = [
  {
    id: 'REQ001',
    category: 'Capital Goods',
    description: 'Q4 2024 equipment purchases emissions data',
    dueDate: '2025-01-15',
    status: 'sent',
    priority: 'high'
  },
  {
    id: 'REQ002',
    category: 'Business Travel',
    description: 'Employee travel emissions for 2024',
    dueDate: '2025-01-20',
    status: 'received',
    priority: 'medium'
  },
  {
    id: 'REQ003',
    category: 'Waste Management',
    description: 'Waste disposal emissions data',
    dueDate: '2025-01-12',
    status: 'overdue',
    priority: 'high'
  }
];

export default function SupplierPortal() {
  const [activeTab, setActiveTab] = useState<'overview' | 'suppliers' | 'requests' | 'submit'>('overview');
  const [selectedSupplier, setSelectedSupplier] = useState<SupplierData | null>(null);

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'verified': return <CheckCircle className="h-4 w-4 text-green-500" />;
      case 'submitted': return <Clock className="h-4 w-4 text-yellow-500" />;
      case 'pending': return <AlertCircle className="h-4 w-4 text-red-500" />;
      default: return <AlertCircle className="h-4 w-4 text-gray-500" />;
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'verified': return 'bg-green-100 text-green-800';
      case 'submitted': return 'bg-yellow-100 text-yellow-800';
      case 'pending': return 'bg-red-100 text-red-800';
      default: return 'bg-gray-100 text-gray-800';
    }
  };

  const getPriorityColor = (priority: string) => {
    switch (priority) {
      case 'high': return 'bg-red-100 text-red-800';
      case 'medium': return 'bg-yellow-100 text-yellow-800';
      default: return 'bg-green-100 text-green-800';
    }
  };

  const verifiedSuppliers = mockSuppliers.filter(s => s.status === 'verified').length;
  const pendingSuppliers = mockSuppliers.filter(s => s.status === 'pending').length;
  const totalEmissions = mockSuppliers.reduce((sum, s) => sum + s.emissions, 0);
  const dataCompleteness = (verifiedSuppliers / mockSuppliers.length) * 100;

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold text-gray-900">Supplier Engagement Portal</h1>
          <p className="text-gray-600 mt-2">Collaborate with suppliers on emissions data collection</p>
        </div>
        <div className="flex space-x-2">
          <Button variant="outline">
            <Download className="h-4 w-4 mr-2" />
            Export Data
          </Button>
          <Button>
            <Mail className="h-4 w-4 mr-2" />
            Send Request
          </Button>
        </div>
      </div>

      {/* Tab Navigation */}
      <div className="flex space-x-1 bg-gray-100 p-1 rounded-lg">
        {[
          { id: 'overview', label: 'Overview' },
          { id: 'suppliers', label: 'Suppliers' },
          { id: 'requests', label: 'Data Requests' },
          { id: 'submit', label: 'Submit Data' }
        ].map((tab) => (
          <Button
            key={tab.id}
            variant={activeTab === tab.id ? 'default' : 'ghost'}
            onClick={() => setActiveTab(tab.id as any)}
            className="flex-1"
          >
            {tab.label}
          </Button>
        ))}
      </div>

      {/* Overview Tab */}
      {activeTab === 'overview' && (
        <div className="space-y-6">
          {/* Summary Cards */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium text-gray-600">Total Suppliers</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold text-gray-900">{mockSuppliers.length}</div>
              </CardContent>
            </Card>
            
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium text-gray-600">Verified Data</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold text-green-600">{verifiedSuppliers}</div>
              </CardContent>
            </Card>
            
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium text-gray-600">Pending Responses</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold text-red-600">{pendingSuppliers}</div>
              </CardContent>
            </Card>
            
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium text-gray-600">Data Completeness</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold text-blue-600">{dataCompleteness.toFixed(0)}%</div>
                <Progress value={dataCompleteness} className="mt-2" />
              </CardContent>
            </Card>
          </div>

          {/* Recent Activity */}
          <Card>
            <CardHeader>
              <CardTitle>Recent Activity</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                {mockSuppliers.slice(0, 3).map((supplier) => (
                  <div key={supplier.id} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                    <div className="flex items-center space-x-3">
                      {getStatusIcon(supplier.status)}
                      <div>
                        <div className="font-medium">{supplier.name}</div>
                        <div className="text-sm text-gray-600">{supplier.category}</div>
                      </div>
                    </div>
                    <div className="text-right">
                      <div className="text-sm font-medium">{supplier.emissions > 0 ? `${supplier.emissions} tCO₂e` : 'Pending'}</div>
                      <div className="text-xs text-gray-500">{supplier.lastUpdated}</div>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Suppliers Tab */}
      {activeTab === 'suppliers' && (
        <div className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {mockSuppliers.map((supplier) => (
              <Card key={supplier.id} className="cursor-pointer hover:shadow-lg transition-shadow">
                <CardHeader className="pb-3">
                  <div className="flex items-start justify-between">
                    <div className="flex items-center space-x-3">
                      <Building className="h-8 w-8 text-blue-600" />
                      <div>
                        <CardTitle className="text-lg">{supplier.name}</CardTitle>
                        <p className="text-sm text-gray-600">{supplier.email}</p>
                      </div>
                    </div>
                    {getStatusIcon(supplier.status)}
                  </div>
                </CardHeader>
                <CardContent>
                  <div className="space-y-3">
                    <div>
                      <Badge variant="outline" className="text-xs">
                        {supplier.category}
                      </Badge>
                    </div>
                    
                    <div className="flex justify-between items-center">
                      <div>
                        <div className="text-sm text-gray-600">Emissions</div>
                        <div className="font-semibold">
                          {supplier.emissions > 0 ? `${supplier.emissions} tCO₂e` : 'No data'}
                        </div>
                      </div>
                      <Badge className={getStatusColor(supplier.status)}>
                        {supplier.status}
                      </Badge>
                    </div>
                    
                    <div className="text-xs text-gray-500">
                      Last updated: {supplier.lastUpdated}
                    </div>
                    
                    <Button size="sm" className="w-full">
                      View Details
                    </Button>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </div>
      )}

      {/* Data Requests Tab */}
      {activeTab === 'requests' && (
        <div className="space-y-4">
          {mockDataRequests.map((request) => (
            <Card key={request.id}>
              <CardContent className="p-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-4">
                    <FileText className="h-8 w-8 text-blue-600" />
                    <div>
                      <h3 className="font-semibold">{request.category}</h3>
                      <p className="text-sm text-gray-600">{request.description}</p>
                      <div className="flex items-center space-x-2 mt-1">
                        <Calendar className="h-4 w-4 text-gray-400" />
                        <span className="text-xs text-gray-500">Due: {request.dueDate}</span>
                      </div>
                    </div>
                  </div>
                  <div className="flex items-center space-x-2">
                    <Badge className={getPriorityColor(request.priority)}>
                      {request.priority}
                    </Badge>
                    <Badge className={getStatusColor(request.status)}>
                      {request.status}
                    </Badge>
                    <Button size="sm" variant="outline">
                      Follow Up
                    </Button>
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {/* Submit Data Tab */}
      {activeTab === 'submit' && (
        <Card>
          <CardHeader>
            <CardTitle>Submit Supplier Data</CardTitle>
            <p className="text-gray-600">Upload emissions data from suppliers</p>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <Label htmlFor="supplier-name">Supplier Name</Label>
                <Input id="supplier-name" placeholder="Enter supplier name" />
              </div>
              <div>
                <Label htmlFor="category">Scope 3 Category</Label>
                <select className="w-full p-2 border rounded-md">
                  <option>Select category</option>
                  <option>Purchased Goods & Services</option>
                  <option>Capital Goods</option>
                  <option>Fuel & Energy Related</option>
                  <option>Upstream Transportation</option>
                  <option>Waste Generated</option>
                  <option>Business Travel</option>
                </select>
              </div>
            </div>
            
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <Label htmlFor="emissions">Emissions (tCO₂e)</Label>
                <Input id="emissions" type="number" placeholder="0.00" />
              </div>
              <div>
                <Label htmlFor="period">Reporting Period</Label>
                <Input id="period" placeholder="e.g., Q4 2024" />
              </div>
            </div>
            
            <div>
              <Label htmlFor="methodology">Calculation Methodology</Label>
              <Textarea id="methodology" placeholder="Describe the calculation method used..." />
            </div>
            
            <div className="border-2 border-dashed border-gray-300 rounded-lg p-6 text-center">
              <Upload className="h-12 w-12 text-gray-400 mx-auto mb-4" />
              <p className="text-gray-600">Drag and drop files here, or click to browse</p>
              <p className="text-sm text-gray-500 mt-2">Supported formats: PDF, Excel, CSV</p>
              <Button variant="outline" className="mt-4">
                Choose Files
              </Button>
            </div>
            
            <div className="flex space-x-2">
              <Button className="flex-1">Submit Data</Button>
              <Button variant="outline" className="flex-1">Save Draft</Button>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

