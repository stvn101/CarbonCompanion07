import React, { useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { 
  Calculator, 
  Database, 
  TrendingUp, 
  AlertTriangle,
  CheckCircle,
  Info,
  Download
} from 'lucide-react';

interface EmissionFactor {
  id: string;
  name: string;
  value: number;
  unit: string;
  source: string;
  uncertainty: number;
  lastUpdated: string;
}

interface CalculationResult {
  emissions: number;
  uncertainty: number;
  method: string;
  dataQuality: 'high' | 'medium' | 'low';
  factors: EmissionFactor[];
}

const emissionFactors: Record<string, EmissionFactor[]> = {
  'purchased-goods': [
    {
      id: 'steel',
      name: 'Steel Production',
      value: 2.3,
      unit: 'tCO₂e/tonne',
      source: 'DEFRA 2024',
      uncertainty: 15,
      lastUpdated: '2024-12-01'
    },
    {
      id: 'concrete',
      name: 'Concrete Production',
      value: 0.13,
      unit: 'tCO₂e/tonne',
      source: 'EPA 2024',
      uncertainty: 20,
      lastUpdated: '2024-11-15'
    }
  ],
  'transportation': [
    {
      id: 'truck-freight',
      name: 'Truck Freight',
      value: 0.062,
      unit: 'kgCO₂e/tonne-km',
      source: 'GLEC Framework',
      uncertainty: 25,
      lastUpdated: '2024-10-30'
    },
    {
      id: 'rail-freight',
      name: 'Rail Freight',
      value: 0.022,
      unit: 'kgCO₂e/tonne-km',
      source: 'GLEC Framework',
      uncertainty: 30,
      lastUpdated: '2024-10-30'
    }
  ],
  'business-travel': [
    {
      id: 'domestic-flight',
      name: 'Domestic Flight',
      value: 0.255,
      unit: 'kgCO₂e/km',
      source: 'DEFRA 2024',
      uncertainty: 10,
      lastUpdated: '2024-12-01'
    },
    {
      id: 'hotel-night',
      name: 'Hotel Stay',
      value: 30.5,
      unit: 'kgCO₂e/night',
      source: 'Hotel Carbon Measurement Initiative',
      uncertainty: 35,
      lastUpdated: '2024-11-20'
    }
  ]
};

export default function EmissionsCalculator() {
  const [selectedCategory, setSelectedCategory] = useState('purchased-goods');
  const [calculationMethod, setCalculationMethod] = useState<'supplier-specific' | 'hybrid' | 'average-data' | 'spend-based'>('average-data');
  const [inputData, setInputData] = useState<Record<string, number>>({});
  const [results, setResults] = useState<CalculationResult | null>(null);

  const categories = [
    { id: 'purchased-goods', name: 'Purchased Goods & Services' },
    { id: 'capital-goods', name: 'Capital Goods' },
    { id: 'fuel-energy', name: 'Fuel & Energy Related' },
    { id: 'transportation', name: 'Transportation' },
    { id: 'waste', name: 'Waste Generated' },
    { id: 'business-travel', name: 'Business Travel' },
    { id: 'commuting', name: 'Employee Commuting' }
  ];

  const methods = [
    {
      id: 'supplier-specific',
      name: 'Supplier-Specific',
      description: 'Use direct emissions data from suppliers',
      accuracy: 'High',
      complexity: 'Low'
    },
    {
      id: 'hybrid',
      name: 'Hybrid Method',
      description: 'Combination of supplier data and secondary sources',
      accuracy: 'Medium-High',
      complexity: 'Medium'
    },
    {
      id: 'average-data',
      name: 'Average-Data',
      description: 'Use industry average emission factors',
      accuracy: 'Medium',
      complexity: 'Low'
    },
    {
      id: 'spend-based',
      name: 'Spend-Based',
      description: 'Calculate based on financial spend data',
      accuracy: 'Low-Medium',
      complexity: 'Low'
    }
  ];

  const handleInputChange = (key: string, value: string) => {
    setInputData(prev => ({
      ...prev,
      [key]: parseFloat(value) || 0
    }));
  };

  const calculateEmissions = () => {
    const factors = emissionFactors[selectedCategory] || [];
    let totalEmissions = 0;
    let totalUncertainty = 0;
    let dataQuality: 'high' | 'medium' | 'low' = 'medium';

    // Simple calculation logic (would be more complex in real implementation)
    factors.forEach(factor => {
      const activityData = inputData[factor.id] || 0;
      const emissions = activityData * factor.value;
      totalEmissions += emissions;
      totalUncertainty += (emissions * factor.uncertainty / 100) ** 2;
    });

    totalUncertainty = Math.sqrt(totalUncertainty);

    // Determine data quality based on method and uncertainty
    if (calculationMethod === 'supplier-specific' && totalUncertainty < 20) {
      dataQuality = 'high';
    } else if (calculationMethod === 'spend-based' || totalUncertainty > 40) {
      dataQuality = 'low';
    }

    setResults({
      emissions: totalEmissions,
      uncertainty: totalUncertainty,
      method: calculationMethod,
      dataQuality,
      factors
    });
  };

  const getDataQualityColor = (quality: string) => {
    switch (quality) {
      case 'high': return 'bg-green-100 text-green-800';
      case 'medium': return 'bg-yellow-100 text-yellow-800';
      default: return 'bg-red-100 text-red-800';
    }
  };

  const getAccuracyColor = (accuracy: string) => {
    if (accuracy.includes('High')) return 'text-green-600';
    if (accuracy.includes('Medium')) return 'text-yellow-600';
    return 'text-red-600';
  };

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold text-gray-900">Emissions Calculator</h1>
          <p className="text-gray-600 mt-2">Calculate Scope 3 emissions using multiple methodologies</p>
        </div>
        <div className="flex space-x-2">
          <Button variant="outline">
            <Database className="h-4 w-4 mr-2" />
            Emission Factors
          </Button>
          <Button variant="outline">
            <Download className="h-4 w-4 mr-2" />
            Export Results
          </Button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Configuration Panel */}
        <div className="lg:col-span-1 space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center">
                <Calculator className="h-5 w-5 mr-2" />
                Configuration
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              {/* Category Selection */}
              <div>
                <Label>Scope 3 Category</Label>
                <select 
                  className="w-full p-2 border rounded-md mt-1"
                  value={selectedCategory}
                  onChange={(e) => setSelectedCategory(e.target.value)}
                >
                  {categories.map(cat => (
                    <option key={cat.id} value={cat.id}>{cat.name}</option>
                  ))}
                </select>
              </div>

              {/* Method Selection */}
              <div>
                <Label>Calculation Method</Label>
                <div className="space-y-2 mt-2">
                  {methods.map(method => (
                    <div 
                      key={method.id}
                      className={`p-3 border rounded-lg cursor-pointer transition-colors ${
                        calculationMethod === method.id 
                          ? 'border-blue-500 bg-blue-50' 
                          : 'border-gray-200 hover:border-gray-300'
                      }`}
                      onClick={() => setCalculationMethod(method.id as any)}
                    >
                      <div className="flex justify-between items-start">
                        <div>
                          <div className="font-medium">{method.name}</div>
                          <div className="text-sm text-gray-600">{method.description}</div>
                        </div>
                        <div className="text-right">
                          <div className={`text-sm font-medium ${getAccuracyColor(method.accuracy)}`}>
                            {method.accuracy}
                          </div>
                          <div className="text-xs text-gray-500">{method.complexity}</div>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Input Panel */}
        <div className="lg:col-span-1">
          <Card>
            <CardHeader>
              <CardTitle>Activity Data Input</CardTitle>
              <p className="text-sm text-gray-600">
                Enter activity data for {categories.find(c => c.id === selectedCategory)?.name}
              </p>
            </CardHeader>
            <CardContent>
              <Tabs defaultValue="manual" className="w-full">
                <TabsList className="grid w-full grid-cols-2">
                  <TabsTrigger value="manual">Manual Entry</TabsTrigger>
                  <TabsTrigger value="upload">Bulk Upload</TabsTrigger>
                </TabsList>
                
                <TabsContent value="manual" className="space-y-4">
                  {(emissionFactors[selectedCategory] || []).map(factor => (
                    <div key={factor.id}>
                      <Label htmlFor={factor.id}>
                        {factor.name}
                        <span className="text-sm text-gray-500 ml-2">({factor.unit.split('/')[1]})</span>
                      </Label>
                      <Input
                        id={factor.id}
                        type="number"
                        placeholder="0"
                        value={inputData[factor.id] || ''}
                        onChange={(e) => handleInputChange(factor.id, e.target.value)}
                        className="mt-1"
                      />
                      <div className="flex items-center mt-1">
                        <Info className="h-3 w-3 text-gray-400 mr-1" />
                        <span className="text-xs text-gray-500">
                          Factor: {factor.value} {factor.unit} (±{factor.uncertainty}%)
                        </span>
                      </div>
                    </div>
                  ))}
                  
                  <Button onClick={calculateEmissions} className="w-full mt-4">
                    Calculate Emissions
                  </Button>
                </TabsContent>
                
                <TabsContent value="upload" className="space-y-4">
                  <div className="border-2 border-dashed border-gray-300 rounded-lg p-6 text-center">
                    <div className="text-gray-600">
                      <p>Upload CSV or Excel file with activity data</p>
                      <p className="text-sm mt-2">Template available for download</p>
                    </div>
                    <Button variant="outline" className="mt-4">
                      Choose File
                    </Button>
                  </div>
                </TabsContent>
              </Tabs>
            </CardContent>
          </Card>
        </div>

        {/* Results Panel */}
        <div className="lg:col-span-1">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center">
                <TrendingUp className="h-5 w-5 mr-2" />
                Calculation Results
              </CardTitle>
            </CardHeader>
            <CardContent>
              {results ? (
                <div className="space-y-4">
                  {/* Main Result */}
                  <div className="text-center p-4 bg-blue-50 rounded-lg">
                    <div className="text-3xl font-bold text-blue-900">
                      {results.emissions.toFixed(2)}
                    </div>
                    <div className="text-blue-700">tCO₂e</div>
                    <div className="text-sm text-blue-600 mt-1">
                      ±{results.uncertainty.toFixed(1)}% uncertainty
                    </div>
                  </div>

                  {/* Quality Indicators */}
                  <div className="space-y-2">
                    <div className="flex justify-between items-center">
                      <span className="text-sm text-gray-600">Data Quality</span>
                      <Badge className={getDataQualityColor(results.dataQuality)}>
                        {results.dataQuality}
                      </Badge>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-sm text-gray-600">Method</span>
                      <span className="text-sm font-medium">{results.method}</span>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-sm text-gray-600">Factors Used</span>
                      <span className="text-sm font-medium">{results.factors.length}</span>
                    </div>
                  </div>

                  {/* Breakdown */}
                  <div>
                    <h4 className="font-medium mb-2">Emissions Breakdown</h4>
                    <div className="space-y-2">
                      {results.factors.map(factor => {
                        const activityData = inputData[factor.id] || 0;
                        const emissions = activityData * factor.value;
                        return (
                          <div key={factor.id} className="flex justify-between text-sm">
                            <span>{factor.name}</span>
                            <span>{emissions.toFixed(2)} tCO₂e</span>
                          </div>
                        );
                      })}
                    </div>
                  </div>

                  {/* Actions */}
                  <div className="space-y-2">
                    <Button className="w-full">Save Results</Button>
                    <Button variant="outline" className="w-full">
                      Generate Report
                    </Button>
                  </div>

                  {/* Validation Alerts */}
                  <div className="space-y-2">
                    {results.uncertainty > 50 && (
                      <div className="flex items-center p-2 bg-yellow-50 border border-yellow-200 rounded">
                        <AlertTriangle className="h-4 w-4 text-yellow-600 mr-2" />
                        <span className="text-sm text-yellow-800">
                          High uncertainty detected. Consider improving data quality.
                        </span>
                      </div>
                    )}
                    {results.dataQuality === 'high' && (
                      <div className="flex items-center p-2 bg-green-50 border border-green-200 rounded">
                        <CheckCircle className="h-4 w-4 text-green-600 mr-2" />
                        <span className="text-sm text-green-800">
                          High quality data - results are reliable.
                        </span>
                      </div>
                    )}
                  </div>
                </div>
              ) : (
                <div className="text-center text-gray-500 py-8">
                  <Calculator className="h-12 w-12 mx-auto mb-4 text-gray-300" />
                  <p>Enter activity data and click calculate to see results</p>
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}

