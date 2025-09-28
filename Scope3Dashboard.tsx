import React, { useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { 
  ShoppingCart, 
  Building2, 
  Zap, 
  Truck, 
  Trash2, 
  Plane, 
  Car, 
  Home,
  Package,
  Cog,
  Users,
  Recycle,
  Building,
  Store,
  TrendingUp
} from 'lucide-react';

interface Scope3Category {
  id: number;
  name: string;
  description: string;
  icon: React.ReactNode;
  type: 'upstream' | 'downstream';
  completionStatus: 'not-started' | 'in-progress' | 'completed';
  emissions: number; // in tCO2e
  dataQuality: 'high' | 'medium' | 'low';
}

const scope3Categories: Scope3Category[] = [
  {
    id: 1,
    name: 'Purchased Goods & Services',
    description: 'Emissions from production of purchased goods and services',
    icon: <ShoppingCart className="h-6 w-6" />,
    type: 'upstream',
    completionStatus: 'completed',
    emissions: 1250.5,
    dataQuality: 'high'
  },
  {
    id: 2,
    name: 'Capital Goods',
    description: 'Emissions from production of capital goods purchased',
    icon: <Building2 className="h-6 w-6" />,
    type: 'upstream',
    completionStatus: 'in-progress',
    emissions: 320.8,
    dataQuality: 'medium'
  },
  {
    id: 3,
    name: 'Fuel & Energy Related Activities',
    description: 'Upstream emissions from fuel and energy not in Scope 1 & 2',
    icon: <Zap className="h-6 w-6" />,
    type: 'upstream',
    completionStatus: 'completed',
    emissions: 180.2,
    dataQuality: 'high'
  },
  {
    id: 4,
    name: 'Upstream Transportation',
    description: 'Transportation and distribution of purchased goods',
    icon: <Truck className="h-6 w-6" />,
    type: 'upstream',
    completionStatus: 'completed',
    emissions: 95.3,
    dataQuality: 'medium'
  },
  {
    id: 5,
    name: 'Waste Generated in Operations',
    description: 'Disposal and treatment of waste generated in operations',
    icon: <Trash2 className="h-6 w-6" />,
    type: 'upstream',
    completionStatus: 'in-progress',
    emissions: 45.7,
    dataQuality: 'medium'
  },
  {
    id: 6,
    name: 'Business Travel',
    description: 'Employee business travel including flights and accommodation',
    icon: <Plane className="h-6 w-6" />,
    type: 'upstream',
    completionStatus: 'completed',
    emissions: 78.9,
    dataQuality: 'high'
  },
  {
    id: 7,
    name: 'Employee Commuting',
    description: 'Employee commuting to and from work',
    icon: <Car className="h-6 w-6" />,
    type: 'upstream',
    completionStatus: 'not-started',
    emissions: 0,
    dataQuality: 'low'
  },
  {
    id: 8,
    name: 'Upstream Leased Assets',
    description: 'Operation of leased assets not included in Scope 1 & 2',
    icon: <Home className="h-6 w-6" />,
    type: 'upstream',
    completionStatus: 'not-started',
    emissions: 0,
    dataQuality: 'low'
  },
  {
    id: 9,
    name: 'Downstream Transportation',
    description: 'Transportation and distribution of sold products',
    icon: <Package className="h-6 w-6" />,
    type: 'downstream',
    completionStatus: 'in-progress',
    emissions: 156.4,
    dataQuality: 'medium'
  },
  {
    id: 10,
    name: 'Processing of Sold Products',
    description: 'Processing of intermediate products sold',
    icon: <Cog className="h-6 w-6" />,
    type: 'downstream',
    completionStatus: 'not-started',
    emissions: 0,
    dataQuality: 'low'
  },
  {
    id: 11,
    name: 'Use of Sold Products',
    description: 'Use of goods and services sold by the organization',
    icon: <Users className="h-6 w-6" />,
    type: 'downstream',
    completionStatus: 'completed',
    emissions: 2340.1,
    dataQuality: 'medium'
  },
  {
    id: 12,
    name: 'End-of-Life Treatment',
    description: 'Disposal and treatment of products at end of life',
    icon: <Recycle className="h-6 w-6" />,
    type: 'downstream',
    completionStatus: 'not-started',
    emissions: 0,
    dataQuality: 'low'
  },
  {
    id: 13,
    name: 'Downstream Leased Assets',
    description: 'Operation of assets owned and leased to others',
    icon: <Building className="h-6 w-6" />,
    type: 'downstream',
    completionStatus: 'not-started',
    emissions: 0,
    dataQuality: 'low'
  },
  {
    id: 14,
    name: 'Franchises',
    description: 'Operation of franchises',
    icon: <Store className="h-6 w-6" />,
    type: 'downstream',
    completionStatus: 'not-started',
    emissions: 0,
    dataQuality: 'low'
  },
  {
    id: 15,
    name: 'Investments',
    description: 'Scope 1 and 2 emissions of investees',
    icon: <TrendingUp className="h-6 w-6" />,
    type: 'downstream',
    completionStatus: 'not-started',
    emissions: 0,
    dataQuality: 'low'
  }
];

export default function Scope3Dashboard() {
  const [selectedCategory, setSelectedCategory] = useState<Scope3Category | null>(null);
  const [viewMode, setViewMode] = useState<'overview' | 'upstream' | 'downstream'>('overview');

  const totalEmissions = scope3Categories.reduce((sum, cat) => sum + cat.emissions, 0);
  const completedCategories = scope3Categories.filter(cat => cat.completionStatus === 'completed').length;
  const inProgressCategories = scope3Categories.filter(cat => cat.completionStatus === 'in-progress').length;
  const overallProgress = (completedCategories / scope3Categories.length) * 100;

  const upstreamCategories = scope3Categories.filter(cat => cat.type === 'upstream');
  const downstreamCategories = scope3Categories.filter(cat => cat.type === 'downstream');

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'completed': return 'bg-green-500';
      case 'in-progress': return 'bg-yellow-500';
      default: return 'bg-gray-300';
    }
  };

  const getDataQualityColor = (quality: string) => {
    switch (quality) {
      case 'high': return 'bg-green-100 text-green-800';
      case 'medium': return 'bg-yellow-100 text-yellow-800';
      default: return 'bg-red-100 text-red-800';
    }
  };

  const filteredCategories = viewMode === 'overview' 
    ? scope3Categories 
    : viewMode === 'upstream' 
    ? upstreamCategories 
    : downstreamCategories;

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold text-gray-900">Scope 3 Emissions Tracking</h1>
          <p className="text-gray-600 mt-2">Comprehensive value chain emissions management</p>
        </div>
        <div className="flex space-x-2">
          <Button 
            variant={viewMode === 'overview' ? 'default' : 'outline'}
            onClick={() => setViewMode('overview')}
          >
            Overview
          </Button>
          <Button 
            variant={viewMode === 'upstream' ? 'default' : 'outline'}
            onClick={() => setViewMode('upstream')}
          >
            Upstream
          </Button>
          <Button 
            variant={viewMode === 'downstream' ? 'default' : 'outline'}
            onClick={() => setViewMode('downstream')}
          >
            Downstream
          </Button>
        </div>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-gray-600">Total Scope 3 Emissions</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-gray-900">{totalEmissions.toFixed(1)} tCO₂e</div>
          </CardContent>
        </Card>
        
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-gray-600">Categories Completed</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-green-600">{completedCategories}/15</div>
          </CardContent>
        </Card>
        
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-gray-600">In Progress</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-yellow-600">{inProgressCategories}</div>
          </CardContent>
        </Card>
        
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-gray-600">Overall Progress</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-blue-600">{overallProgress.toFixed(0)}%</div>
            <Progress value={overallProgress} className="mt-2" />
          </CardContent>
        </Card>
      </div>

      {/* Categories Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {filteredCategories.map((category) => (
          <Card 
            key={category.id} 
            className="cursor-pointer hover:shadow-lg transition-shadow"
            onClick={() => setSelectedCategory(category)}
          >
            <CardHeader className="pb-3">
              <div className="flex items-start justify-between">
                <div className="flex items-center space-x-3">
                  <div className={`p-2 rounded-lg ${category.type === 'upstream' ? 'bg-blue-100 text-blue-600' : 'bg-purple-100 text-purple-600'}`}>
                    {category.icon}
                  </div>
                  <div>
                    <CardTitle className="text-sm font-semibold">Category {category.id}</CardTitle>
                    <Badge variant="outline" className="text-xs">
                      {category.type}
                    </Badge>
                  </div>
                </div>
                <div className={`w-3 h-3 rounded-full ${getStatusColor(category.completionStatus)}`} />
              </div>
            </CardHeader>
            <CardContent>
              <h3 className="font-semibold text-gray-900 mb-2">{category.name}</h3>
              <p className="text-sm text-gray-600 mb-3">{category.description}</p>
              
              <div className="flex justify-between items-center">
                <div>
                  <div className="text-lg font-bold text-gray-900">
                    {category.emissions > 0 ? `${category.emissions.toFixed(1)} tCO₂e` : 'No data'}
                  </div>
                  <Badge className={`text-xs ${getDataQualityColor(category.dataQuality)}`}>
                    {category.dataQuality} quality
                  </Badge>
                </div>
                <Button size="sm" variant="outline">
                  {category.completionStatus === 'not-started' ? 'Start' : 'View'}
                </Button>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Category Detail Modal would go here */}
      {selectedCategory && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
          <Card className="w-full max-w-2xl max-h-[80vh] overflow-y-auto">
            <CardHeader>
              <div className="flex justify-between items-start">
                <div>
                  <CardTitle className="text-xl">Category {selectedCategory.id}: {selectedCategory.name}</CardTitle>
                  <p className="text-gray-600 mt-2">{selectedCategory.description}</p>
                </div>
                <Button variant="outline" onClick={() => setSelectedCategory(null)}>
                  Close
                </Button>
              </div>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="text-sm font-medium text-gray-600">Current Emissions</label>
                    <div className="text-2xl font-bold text-gray-900">
                      {selectedCategory.emissions > 0 ? `${selectedCategory.emissions.toFixed(1)} tCO₂e` : 'No data'}
                    </div>
                  </div>
                  <div>
                    <label className="text-sm font-medium text-gray-600">Data Quality</label>
                    <div>
                      <Badge className={getDataQualityColor(selectedCategory.dataQuality)}>
                        {selectedCategory.dataQuality} quality
                      </Badge>
                    </div>
                  </div>
                </div>
                
                <div className="flex space-x-2">
                  <Button className="flex-1">Enter Data</Button>
                  <Button variant="outline" className="flex-1">View Details</Button>
                  <Button variant="outline" className="flex-1">Export</Button>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>
      )}
    </div>
  );
}

