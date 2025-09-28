# CarbonCompanion Integration Guide

This document provides comprehensive integration instructions for connecting CarbonCompanion with your CarbonConstruct parent application.

## Overview

CarbonCompanion automatically calculates carbon emissions using the standard diesel fuel conversion rate of **2.68 kg CO₂ per liter** and provides multiple integration methods for seamless data transfer.

## Integration Methods

### 1. REST API Integration

#### Get All Operations with Carbon Data
```
GET /api/carbonconstruct/operations
```

**Optional Query Parameters:**
- `startDate`: ISO date string (e.g., "2024-01-01")
- `endDate`: ISO date string (e.g., "2024-12-31")

**Response Format:**
```json
{
  "success": true,
  "data": [
    {
      "operationId": 123,
      "equipmentId": "TRK-001",
      "equipmentType": "truck",
      "projectId": 2,
      "projectName": "Riverside Homes Phase 2",
      "fuelConsumption": 7.5,
      "distance": 50,
      "duration": 0.5,
      "carbonEmissions": 20.1,
      "operationDate": "2025-06-06T18:41:10.577Z",
      "operationType": "delivery",
      "metadata": {
        "loadWeight": 1000,
        "fuelEfficiency": 13.2,
        "notes": "Traffic peak hour"
      }
    }
  ],
  "metadata": {
    "totalOperations": 2,
    "totalCarbonEmissions": 41.54,
    "totalFuelConsumption": 15.5
  }
}
```

#### Get Project Summary
```
GET /api/carbonconstruct/projects/{projectId}/summary
```

**Response Format:**
```json
{
  "success": true,
  "data": {
    "projectId": 2,
    "projectName": "Riverside Homes Phase 2",
    "totalOperations": 1,
    "totalFuelConsumption": 7.5,
    "totalCarbonEmissions": 20.1,
    "totalDistance": 50,
    "totalDuration": 0.5,
    "averageFuelEfficiency": 15
  }
}
```

### 2. Webhook Integration

Send real-time notifications for operation events to your CarbonConstruct application.

#### Configure Webhook
```
POST /api/carbonconstruct/webhook
Content-Type: application/json

{
  "webhookUrl": "https://your-carbonconstruct-app.com/webhook/carboncompanion",
  "operationId": 123,
  "eventType": "completed"
}
```

**Event Types:**
- `created`: New operation started
- `updated`: Operation details modified
- `completed`: Operation finished

**Webhook Payload:**
```json
{
  "event": "operation.completed",
  "timestamp": "2025-06-06T18:57:42.000Z",
  "data": {
    "operationId": 123,
    "equipmentId": "TRK-001",
    "equipmentType": "truck",
    "projectName": "Industrial Park Expansion",
    "fuelConsumption": 8,
    "carbonEmissions": 21.44,
    "distance": 48,
    "duration": 0.9,
    "operationDate": "2025-06-06T18:52:32.317Z",
    "operationType": "delivery"
  }
}
```

### 3. Data Sync Export

Bulk data export for comprehensive integration with external systems.

#### JSON Export
```
GET /api/sync/data?format=json&includeMetadata=true
```

#### CSV Export
```
GET /api/sync/data?format=csv
```

**CSV Headers:**
- Operation ID
- Equipment ID
- Equipment Type
- Project Name
- Fuel Consumption (L)
- Carbon Emissions (kg CO2)
- Distance (km)
- Duration (hrs)
- Operation Date
- Operation Type

## TypeScript Integration Example

```typescript
interface CarbonConstructData {
  operationId: number;
  equipmentId: string;
  equipmentType: string;
  projectId: number;
  projectName: string;
  fuelConsumption: number;
  distance?: number;
  duration: number;
  carbonEmissions: number;
  operationDate: string;
  operationType: string;
  metadata: {
    loadWeight?: number;
    materialMoved?: number;
    fuelEfficiency: number;
    notes?: string;
  };
}

// Fetch operations from CarbonCompanion
async function fetchCarbonData(): Promise<CarbonConstructData[]> {
  const response = await fetch('http://carboncompanion-url/api/carbonconstruct/operations');
  const result = await response.json();
  return result.data;
}

// Setup webhook endpoint in your CarbonConstruct app
app.post('/webhook/carboncompanion', (req, res) => {
  const { event, timestamp, data } = req.body;
  
  // Process carbon emission data
  console.log(`Received ${event} for operation ${data.operationId}`);
  console.log(`Carbon emissions: ${data.carbonEmissions} kg CO₂`);
  
  // Update your carbon tracking system
  updateCarbonFootprint(data);
  
  res.status(200).json({ received: true });
});
```

## Python Integration Example

```python
import requests
from datetime import datetime, timedelta

class CarbonCompanionClient:
    def __init__(self, base_url):
        self.base_url = base_url
    
    def get_operations(self, start_date=None, end_date=None):
        """Fetch operation data with carbon emissions"""
        url = f"{self.base_url}/api/carbonconstruct/operations"
        params = {}
        
        if start_date:
            params['startDate'] = start_date.isoformat()
        if end_date:
            params['endDate'] = end_date.isoformat()
        
        response = requests.get(url, params=params)
        return response.json()
    
    def get_project_summary(self, project_id):
        """Get carbon footprint summary for a project"""
        url = f"{self.base_url}/api/carbonconstruct/projects/{project_id}/summary"
        response = requests.get(url)
        return response.json()
    
    def download_csv_export(self, filename="carbon_data.csv"):
        """Download complete data export as CSV"""
        url = f"{self.base_url}/api/sync/data?format=csv"
        response = requests.get(url)
        
        with open(filename, 'w') as f:
            f.write(response.text)
        
        return filename

# Usage example
client = CarbonCompanionClient('http://carboncompanion-url')

# Get last 30 days of data
end_date = datetime.now()
start_date = end_date - timedelta(days=30)
operations = client.get_operations(start_date, end_date)

print(f"Total carbon emissions: {operations['metadata']['totalCarbonEmissions']} kg CO₂")
```

## Carbon Emission Calculations

CarbonCompanion uses the industry-standard diesel fuel emission factor:
- **2.68 kg CO₂ per liter of diesel fuel**

This calculation includes:
- Direct combustion emissions (Scope 1)
- Lifecycle emissions from fuel production and distribution
- Compliant with GHG Protocol standards

## Security Considerations

1. **API Authentication**: Consider implementing API keys for production deployments
2. **Webhook Security**: Validate webhook signatures to ensure data integrity
3. **Rate Limiting**: Implement appropriate rate limits for API endpoints
4. **Data Privacy**: Ensure compliance with data protection regulations

## Deployment URLs

Replace `carboncompanion-url` in examples with your actual deployment URL:
- Development: `http://localhost:5000`
- Production: Your Replit deployment URL

## Support

For integration assistance or troubleshooting, verify all endpoints are accessible and returning valid JSON responses. The system has been tested with real operation data and verified carbon emission calculations.