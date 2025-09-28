import React, { useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { 
  ChevronLeft, 
  ChevronRight, 
  CheckCircle, 
  AlertCircle,
  Upload,
  Download,
  FileText,
  Database,
  Users,
  Building
} from 'lucide-react';

interface WizardStep {
  id: string;
  title: string;
  description: string;
  category: string;
  fields: FormField[];
  validationRules: ValidationRule[];
}

interface FormField {
  id: string;
  label: string;
  type: 'text' | 'number' | 'select' | 'textarea' | 'file' | 'date';
  required: boolean;
  placeholder?: string;
  options?: string[];
  unit?: string;
  helpText?: string;
}

interface ValidationRule {
  field: string;
  rule: 'required' | 'min' | 'max' | 'pattern';
  value?: any;
  message: string;
}

const wizardSteps: WizardStep[] = [
  {
    id: 'category-1',
    title: 'Purchased Goods & Services',
    description: 'Collect data on purchased goods and services emissions',
    category: 'upstream',
    fields: [
      {
        id: 'supplier-name',
        label: 'Supplier Name',
        type: 'text',
        required: true,
        placeholder: 'Enter supplier company name'
      },
      {
        id: 'product-category',
        label: 'Product Category',
        type: 'select',
        required: true,
        options: ['Raw Materials', 'Components', 'Services', 'Office Supplies', 'IT Equipment']
      },
      {
        id: 'spend-amount',
        label: 'Annual Spend',
        type: 'number',
        required: true,
        unit: 'USD',
        placeholder: '0.00'
      },
      {
        id: 'quantity',
        label: 'Quantity Purchased',
        type: 'number',
        required: false,
        unit: 'units',
        placeholder: '0'
      },
      {
        id: 'emission-factor',
        label: 'Emission Factor',
        type: 'number',
        required: false,
        unit: 'kgCO₂e/unit',
        helpText: 'If known, provide specific emission factor'
      },
      {
        id: 'data-source',
        label: 'Data Source',
        type: 'select',
        required: true,
        options: ['Supplier Provided', 'Industry Average', 'Spend-based Calculation', 'LCA Study']
      },
      {
        id: 'supporting-docs',
        label: 'Supporting Documents',
        type: 'file',
        required: false,
        helpText: 'Upload invoices, certificates, or emission reports'
      }
    ],
    validationRules: [
      { field: 'supplier-name', rule: 'required', message: 'Supplier name is required' },
      { field: 'spend-amount', rule: 'min', value: 0, message: 'Spend amount must be positive' }
    ]
  },
  {
    id: 'category-6',
    title: 'Business Travel',
    description: 'Track emissions from employee business travel',
    category: 'upstream',
    fields: [
      {
        id: 'travel-type',
        label: 'Travel Type',
        type: 'select',
        required: true,
        options: ['Air Travel', 'Rail Travel', 'Road Travel', 'Accommodation']
      },
      {
        id: 'origin',
        label: 'Origin',
        type: 'text',
        required: true,
        placeholder: 'Departure city/airport'
      },
      {
        id: 'destination',
        label: 'Destination',
        type: 'text',
        required: true,
        placeholder: 'Arrival city/airport'
      },
      {
        id: 'distance',
        label: 'Distance',
        type: 'number',
        required: false,
        unit: 'km',
        placeholder: '0'
      },
      {
        id: 'passengers',
        label: 'Number of Passengers',
        type: 'number',
        required: true,
        placeholder: '1'
      },
      {
        id: 'travel-class',
        label: 'Travel Class',
        type: 'select',
        required: false,
        options: ['Economy', 'Business', 'First Class']
      },
      {
        id: 'accommodation-nights',
        label: 'Accommodation Nights',
        type: 'number',
        required: false,
        unit: 'nights',
        placeholder: '0'
      }
    ],
    validationRules: [
      { field: 'passengers', rule: 'min', value: 1, message: 'At least 1 passenger required' }
    ]
  }
];

export default function DataCollectionWizard() {
  const [currentStep, setCurrentStep] = useState(0);
  const [formData, setFormData] = useState<Record<string, any>>({});
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [completedSteps, setCompletedSteps] = useState<Set<number>>(new Set());

  const step = wizardSteps[currentStep];
  const progress = ((currentStep + 1) / wizardSteps.length) * 100;

  const handleInputChange = (fieldId: string, value: any) => {
    setFormData(prev => ({
      ...prev,
      [fieldId]: value
    }));
    
    // Clear error when user starts typing
    if (errors[fieldId]) {
      setErrors(prev => {
        const newErrors = { ...prev };
        delete newErrors[fieldId];
        return newErrors;
      });
    }
  };

  const validateStep = () => {
    const stepErrors: Record<string, string> = {};
    
    step.validationRules.forEach(rule => {
      const value = formData[rule.field];
      
      switch (rule.rule) {
        case 'required':
          if (!value || value === '') {
            stepErrors[rule.field] = rule.message;
          }
          break;
        case 'min':
          if (value < rule.value) {
            stepErrors[rule.field] = rule.message;
          }
          break;
        case 'max':
          if (value > rule.value) {
            stepErrors[rule.field] = rule.message;
          }
          break;
      }
    });

    setErrors(stepErrors);
    return Object.keys(stepErrors).length === 0;
  };

  const handleNext = () => {
    if (validateStep()) {
      setCompletedSteps(prev => new Set([...prev, currentStep]));
      if (currentStep < wizardSteps.length - 1) {
        setCurrentStep(currentStep + 1);
      }
    }
  };

  const handlePrevious = () => {
    if (currentStep > 0) {
      setCurrentStep(currentStep - 1);
    }
  };

  const handleSubmit = () => {
    if (validateStep()) {
      setCompletedSteps(prev => new Set([...prev, currentStep]));
      // Handle form submission
      console.log('Form submitted:', formData);
    }
  };

  const renderField = (field: FormField) => {
    const value = formData[field.id] || '';
    const error = errors[field.id];

    switch (field.type) {
      case 'text':
      case 'number':
        return (
          <div key={field.id} className="space-y-2">
            <Label htmlFor={field.id} className="flex items-center">
              {field.label}
              {field.required && <span className="text-red-500 ml-1">*</span>}
              {field.unit && <span className="text-gray-500 ml-2">({field.unit})</span>}
            </Label>
            <Input
              id={field.id}
              type={field.type}
              value={value}
              onChange={(e) => handleInputChange(field.id, e.target.value)}
              placeholder={field.placeholder}
              className={error ? 'border-red-500' : ''}
            />
            {field.helpText && (
              <p className="text-sm text-gray-500">{field.helpText}</p>
            )}
            {error && (
              <p className="text-sm text-red-500 flex items-center">
                <AlertCircle className="h-4 w-4 mr-1" />
                {error}
              </p>
            )}
          </div>
        );

      case 'select':
        return (
          <div key={field.id} className="space-y-2">
            <Label htmlFor={field.id} className="flex items-center">
              {field.label}
              {field.required && <span className="text-red-500 ml-1">*</span>}
            </Label>
            <select
              id={field.id}
              value={value}
              onChange={(e) => handleInputChange(field.id, e.target.value)}
              className={`w-full p-2 border rounded-md ${error ? 'border-red-500' : 'border-gray-300'}`}
            >
              <option value="">Select {field.label}</option>
              {field.options?.map(option => (
                <option key={option} value={option}>{option}</option>
              ))}
            </select>
            {error && (
              <p className="text-sm text-red-500 flex items-center">
                <AlertCircle className="h-4 w-4 mr-1" />
                {error}
              </p>
            )}
          </div>
        );

      case 'textarea':
        return (
          <div key={field.id} className="space-y-2">
            <Label htmlFor={field.id} className="flex items-center">
              {field.label}
              {field.required && <span className="text-red-500 ml-1">*</span>}
            </Label>
            <Textarea
              id={field.id}
              value={value}
              onChange={(e) => handleInputChange(field.id, e.target.value)}
              placeholder={field.placeholder}
              className={error ? 'border-red-500' : ''}
            />
            {error && (
              <p className="text-sm text-red-500 flex items-center">
                <AlertCircle className="h-4 w-4 mr-1" />
                {error}
              </p>
            )}
          </div>
        );

      case 'file':
        return (
          <div key={field.id} className="space-y-2">
            <Label className="flex items-center">
              {field.label}
              {field.required && <span className="text-red-500 ml-1">*</span>}
            </Label>
            <div className="border-2 border-dashed border-gray-300 rounded-lg p-4 text-center">
              <Upload className="h-8 w-8 text-gray-400 mx-auto mb-2" />
              <p className="text-sm text-gray-600">Click to upload or drag and drop</p>
              {field.helpText && (
                <p className="text-xs text-gray-500 mt-1">{field.helpText}</p>
              )}
              <Button variant="outline" size="sm" className="mt-2">
                Choose Files
              </Button>
            </div>
          </div>
        );

      default:
        return null;
    }
  };

  return (
    <div className="max-w-4xl mx-auto p-6 space-y-6">
      {/* Header */}
      <div className="text-center">
        <h1 className="text-3xl font-bold text-gray-900">Data Collection Wizard</h1>
        <p className="text-gray-600 mt-2">Step-by-step Scope 3 emissions data collection</p>
      </div>

      {/* Progress Bar */}
      <Card>
        <CardContent className="p-4">
          <div className="flex items-center justify-between mb-2">
            <span className="text-sm font-medium text-gray-700">
              Step {currentStep + 1} of {wizardSteps.length}
            </span>
            <span className="text-sm text-gray-500">{progress.toFixed(0)}% Complete</span>
          </div>
          <Progress value={progress} className="h-2" />
        </CardContent>
      </Card>

      {/* Step Navigation */}
      <div className="flex justify-center">
        <div className="flex space-x-2">
          {wizardSteps.map((_, index) => (
            <div
              key={index}
              className={`w-8 h-8 rounded-full flex items-center justify-center text-sm font-medium ${
                index === currentStep
                  ? 'bg-blue-600 text-white'
                  : completedSteps.has(index)
                  ? 'bg-green-600 text-white'
                  : 'bg-gray-200 text-gray-600'
              }`}
            >
              {completedSteps.has(index) ? (
                <CheckCircle className="h-4 w-4" />
              ) : (
                index + 1
              )}
            </div>
          ))}
        </div>
      </div>

      {/* Current Step */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="flex items-center">
                <Database className="h-5 w-5 mr-2" />
                {step.title}
              </CardTitle>
              <p className="text-gray-600 mt-1">{step.description}</p>
            </div>
            <Badge variant="outline" className={step.category === 'upstream' ? 'bg-blue-50' : 'bg-purple-50'}>
              {step.category}
            </Badge>
          </div>
        </CardHeader>
        <CardContent className="space-y-6">
          {/* Form Fields */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {step.fields.map(renderField)}
          </div>

          {/* Navigation Buttons */}
          <div className="flex justify-between pt-6 border-t">
            <Button
              variant="outline"
              onClick={handlePrevious}
              disabled={currentStep === 0}
            >
              <ChevronLeft className="h-4 w-4 mr-2" />
              Previous
            </Button>

            <div className="flex space-x-2">
              <Button variant="outline">
                <FileText className="h-4 w-4 mr-2" />
                Save Draft
              </Button>
              
              {currentStep === wizardSteps.length - 1 ? (
                <Button onClick={handleSubmit}>
                  <CheckCircle className="h-4 w-4 mr-2" />
                  Submit Data
                </Button>
              ) : (
                <Button onClick={handleNext}>
                  Next
                  <ChevronRight className="h-4 w-4 ml-2" />
                </Button>
              )}
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Help Section */}
      <Card>
        <CardHeader>
          <CardTitle className="text-lg">Need Help?</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="flex items-center space-x-3">
              <Download className="h-8 w-8 text-blue-600" />
              <div>
                <h4 className="font-medium">Download Template</h4>
                <p className="text-sm text-gray-600">Get Excel template for bulk upload</p>
              </div>
            </div>
            <div className="flex items-center space-x-3">
              <Users className="h-8 w-8 text-green-600" />
              <div>
                <h4 className="font-medium">Contact Support</h4>
                <p className="text-sm text-gray-600">Get help from our experts</p>
              </div>
            </div>
            <div className="flex items-center space-x-3">
              <Building className="h-8 w-8 text-purple-600" />
              <div>
                <h4 className="font-medium">Supplier Portal</h4>
                <p className="text-sm text-gray-600">Direct supplier data submission</p>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

