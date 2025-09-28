# Carbon Companion API Documentation

## 📋 Table of Contents

1. [Authentication](#authentication)
2. [Operations API](#operations-api)
3. [Scope 3 API](#scope-3-api)
4. [Supplier Management API](#supplier-management-api)
5. [Equipment API](#equipment-api)
6. [Projects API](#projects-api)
7. [Reporting API](#reporting-api)
8. [Settings API](#settings-api)
9. [Webhooks](#webhooks)
10. [Error Handling](#error-handling)

## 🔐 Authentication

All API endpoints require authentication using JWT tokens.

### Login
```http
POST /api/auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "password123"
}
```

**Response:**
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": 1,
    "email": "user@example.com",
    "organization": "CarbonConstruct Ltd",
    "role": "administrator"
  }
}
```

### Using Authentication
Include the JWT token in the Authorization header:
```http
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

## 🚛 Operations API

### Get All Operations
```http
GET /api/operations
Authorization: Bearer {token}
```

**Query Parameters:**
- `page` (optional): Page number (default: 1)
- `limit` (optional): Items per page (default: 20)
- `type` (optional): Filter by operation type (delivery, machinery)
- `project` (optional): Filter by project ID
- `startDate` (optional): Filter by start date (ISO 8601)
- `endDate` (optional): Filter by end date (ISO 8601)

**Response:**
```json
{
  "operations": [
    {
      "id": 1,
      "type": "delivery",
      "vehicle": {
        "id": 1,
        "name": "Truck-001",
        "type": "Dump Truck"
      },
      "project": {
        "id": 1,
        "name": "Highway Construction Project"
      },
      "startTime": "2024-01-15T08:00:00Z",
      "endTime": "2024-01-15T12:30:00Z",
      "distance": 45.2,
      "fuelUsed": 18.5,
      "emissions": 49.58,
      "status": "completed"
    }
  ],
  "pagination": {
    "page": 1,
    "limit": 20,
    "total": 150,
    "pages": 8
  }
}
```

### Create Operation
```http
POST /api/operations
Authorization: Bearer {token}
Content-Type: application/json

{
  "type": "delivery",
  "vehicleId": 1,
  "projectId": 1,
  "operationType": "Material Delivery",
  "loadWeight": 25.5,
  "estimatedDistance": 45.0,
  "notes": "Concrete delivery to site A"
}
```

**Response:**
```json
{
  "id": 123,
  "type": "delivery",
  "status": "active",
  "startTime": "2024-01-15T08:00:00Z",
  "estimatedEmissions": 48.2,
  "trackingId": "TRK-2024-001-123"
}
```

### Update Operation
```http
PUT /api/operations/{id}
Authorization: Bearer {token}
Content-Type: application/json

{
  "endTime": "2024-01-15T12:30:00Z",
  "actualDistance": 47.3,
  "fuelUsed": 19.2,
  "status": "completed"
}
```

### Start Live Tracking
```http
POST /api/operations/{id}/start-tracking
Authorization: Bearer {token}
```

### Stop Live Tracking
```http
POST /api/operations/{id}/stop-tracking
Authorization: Bearer {token}
Content-Type: application/json

{
  "finalDistance": 47.3,
  "finalFuelUsed": 19.2,
  "notes": "Delivery completed successfully"
}
```

## 🌍 Scope 3 API

### Get All Scope 3 Categories
```http
GET /api/scope3/categories
Authorization: Bearer {token}
```

**Response:**
```json
{
  "categories": [
    {
      "id": 1,
      "name": "Purchased Goods and Services",
      "description": "Emissions from purchased materials and services",
      "type": "upstream",
      "emissions": 1250.5,
      "dataQuality": "high",
      "completionStatus": "complete",
      "methodology": "supplier-specific",
      "lastUpdated": "2024-01-15T10:30:00Z"
    }
  ],
  "summary": {
    "totalEmissions": 15420.8,
    "completedCategories": 12,
    "totalCategories": 15,
    "dataQualityScore": 85
  }
}
```

### Submit Scope 3 Data
```http
POST /api/scope3/data
Authorization: Bearer {token}
Content-Type: application/json

{
  "categoryId": 1,
  "reportingPeriod": "2024-Q1",
  "methodology": "supplier-specific",
  "data": {
    "activityData": 1000,
    "emissionFactor": 1.25,
    "emissions": 1250.0,
    "dataQuality": "high",
    "sources": ["Supplier A", "Supplier B"]
  },
  "documentation": {
    "calculationMethod": "Direct supplier data collection",
    "assumptions": "Based on supplier-provided emission factors",
    "uncertaintyRange": "±5%"
  }
}
```

### Get Scope 3 Report
```http
GET /api/scope3/report
Authorization: Bearer {token}
```

**Query Parameters:**
- `period` (required): Reporting period (2024-Q1, 2024-annual)
- `format` (optional): Response format (json, csv, pdf)
- `categories` (optional): Comma-separated category IDs

## 👥 Supplier Management API

### Get All Suppliers
```http
GET /api/suppliers
Authorization: Bearer {token}
```

**Response:**
```json
{
  "suppliers": [
    {
      "id": 1,
      "name": "Green Materials Ltd",
      "email": "contact@greenmaterials.com",
      "status": "active",
      "dataSubmissionStatus": "complete",
      "lastSubmission": "2024-01-10T14:30:00Z",
      "scope3Categories": [1, 2, 4],
      "emissionsData": {
        "totalEmissions": 450.2,
        "dataQuality": "high"
      }
    }
  ]
}
```

### Invite Supplier
```http
POST /api/suppliers/invite
Authorization: Bearer {token}
Content-Type: application/json

{
  "email": "supplier@example.com",
  "companyName": "Example Supplier Ltd",
  "contactName": "John Smith",
  "scope3Categories": [1, 2, 4],
  "message": "We invite you to participate in our carbon tracking program"
}
```

### Get Supplier Data
```http
GET /api/suppliers/{id}/data
Authorization: Bearer {token}
```

**Query Parameters:**
- `period` (optional): Reporting period
- `categories` (optional): Specific Scope 3 categories

### Request Data from Supplier
```http
POST /api/suppliers/{id}/data-request
Authorization: Bearer {token}
Content-Type: application/json

{
  "categories": [1, 2],
  "period": "2024-Q1",
  "deadline": "2024-02-15T23:59:59Z",
  "message": "Please provide your Q1 emissions data"
}
```

## 🚜 Equipment API

### Get All Equipment
```http
GET /api/equipment
Authorization: Bearer {token}
```

**Response:**
```json
{
  "equipment": [
    {
      "id": 1,
      "name": "Excavator-001",
      "type": "Excavator",
      "model": "CAT 320D",
      "fuelType": "diesel",
      "fuelCapacity": 400,
      "averageConsumption": 25.5,
      "emissionFactor": 2.68,
      "status": "active",
      "lastMaintenance": "2024-01-01T00:00:00Z",
      "operatingHours": 1250
    }
  ]
}
```

### Add Equipment
```http
POST /api/equipment
Authorization: Bearer {token}
Content-Type: application/json

{
  "name": "Bulldozer-003",
  "type": "Bulldozer",
  "model": "CAT D6T",
  "fuelType": "diesel",
  "fuelCapacity": 350,
  "averageConsumption": 22.0,
  "emissionFactor": 2.68
}
```

### Update Equipment
```http
PUT /api/equipment/{id}
Authorization: Bearer {token}
Content-Type: application/json

{
  "status": "maintenance",
  "operatingHours": 1275,
  "lastMaintenance": "2024-01-15T10:00:00Z"
}
```

## 🏗️ Projects API

### Get All Projects
```http
GET /api/projects
Authorization: Bearer {token}
```

**Response:**
```json
{
  "projects": [
    {
      "id": 1,
      "name": "Highway Construction Project",
      "location": "Highway 401, Ontario",
      "status": "active",
      "startDate": "2024-01-01T00:00:00Z",
      "estimatedEndDate": "2024-12-31T23:59:59Z",
      "totalEmissions": 2450.8,
      "operationsCount": 156
    }
  ]
}
```

### Create Project
```http
POST /api/projects
Authorization: Bearer {token}
Content-Type: application/json

{
  "name": "Bridge Construction Project",
  "location": "Toronto, Ontario",
  "description": "New bridge construction over Don River",
  "startDate": "2024-03-01T00:00:00Z",
  "estimatedEndDate": "2024-11-30T23:59:59Z"
}
```

## 📊 Reporting API

### Generate Summary Report
```http
GET /api/reports/summary
Authorization: Bearer {token}
```

**Query Parameters:**
- `period` (required): today, week, month, quarter, year
- `format` (optional): json, csv, pdf

**Response:**
```json
{
  "period": "month",
  "startDate": "2024-01-01T00:00:00Z",
  "endDate": "2024-01-31T23:59:59Z",
  "summary": {
    "totalOperations": 45,
    "totalDistance": 2150.5,
    "totalFuelUsed": 850.2,
    "totalEmissions": 2278.5,
    "averageEfficiency": 12.5
  },
  "breakdown": {
    "byType": {
      "delivery": { "operations": 30, "emissions": 1520.3 },
      "machinery": { "operations": 15, "emissions": 758.2 }
    },
    "byProject": [
      {
        "projectId": 1,
        "projectName": "Highway Construction",
        "operations": 25,
        "emissions": 1350.8
      }
    ]
  }
}
```

### Generate Scope 3 Report
```http
GET /api/reports/scope3
Authorization: Bearer {token}
```

**Query Parameters:**
- `period` (required): 2024-Q1, 2024-annual
- `format` (optional): json, csv, pdf
- `standard` (optional): ghg-protocol, iso14064

### Export Data
```http
POST /api/reports/export
Authorization: Bearer {token}
Content-Type: application/json

{
  "type": "operations",
  "format": "csv",
  "dateRange": {
    "start": "2024-01-01T00:00:00Z",
    "end": "2024-01-31T23:59:59Z"
  },
  "filters": {
    "projects": [1, 2],
    "operationTypes": ["delivery", "machinery"]
  },
  "includeFields": [
    "date", "type", "vehicle", "project", 
    "distance", "fuelUsed", "emissions"
  ]
}
```

## ⚙️ Settings API

### Get User Settings
```http
GET /api/settings
Authorization: Bearer {token}
```

**Response:**
```json
{
  "general": {
    "autoSave": true,
    "defaultUnits": "metric",
    "dataRetention": "12months"
  },
  "notifications": {
    "emailNotifications": true,
    "supplierRequests": true,
    "systemAlerts": true
  },
  "privacy": {
    "dataSharing": false,
    "analyticsTracking": true
  }
}
```

### Update Settings
```http
PUT /api/settings
Authorization: Bearer {token}
Content-Type: application/json

{
  "general": {
    "autoSave": true,
    "defaultUnits": "imperial",
    "dataRetention": "24months"
  }
}
```

## 🔗 Webhooks

### Register Webhook
```http
POST /api/webhooks
Authorization: Bearer {token}
Content-Type: application/json

{
  "url": "https://your-app.com/webhooks/carbon-companion",
  "events": ["operation.completed", "scope3.data.submitted"],
  "secret": "your-webhook-secret"
}
```

### Webhook Events

#### Operation Completed
```json
{
  "event": "operation.completed",
  "timestamp": "2024-01-15T12:30:00Z",
  "data": {
    "operationId": 123,
    "type": "delivery",
    "emissions": 49.58,
    "fuelUsed": 18.5,
    "distance": 45.2
  }
}
```

#### Scope 3 Data Submitted
```json
{
  "event": "scope3.data.submitted",
  "timestamp": "2024-01-15T14:00:00Z",
  "data": {
    "categoryId": 1,
    "supplierId": 5,
    "emissions": 125.5,
    "period": "2024-Q1"
  }
}
```

## ❌ Error Handling

### Error Response Format
```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid input data",
    "details": [
      {
        "field": "fuelUsed",
        "message": "Must be a positive number"
      }
    ],
    "timestamp": "2024-01-15T10:30:00Z",
    "requestId": "req_123456789"
  }
}
```

### Common Error Codes

| Code | Status | Description |
|------|--------|-------------|
| `AUTHENTICATION_REQUIRED` | 401 | Missing or invalid authentication token |
| `AUTHORIZATION_FAILED` | 403 | Insufficient permissions for the requested resource |
| `RESOURCE_NOT_FOUND` | 404 | Requested resource does not exist |
| `VALIDATION_ERROR` | 400 | Invalid input data or missing required fields |
| `RATE_LIMIT_EXCEEDED` | 429 | Too many requests in a given time period |
| `INTERNAL_SERVER_ERROR` | 500 | Unexpected server error |
| `DATABASE_ERROR` | 503 | Database connection or query error |

### Rate Limiting

API requests are limited to:
- **Authentication endpoints**: 5 requests per minute
- **Data submission endpoints**: 100 requests per hour
- **Read endpoints**: 1000 requests per hour
- **Export endpoints**: 10 requests per hour

Rate limit headers are included in responses:
```http
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 999
X-RateLimit-Reset: 1642248000
```

## 🔧 SDK and Integration Examples

### JavaScript/Node.js SDK
```javascript
const CarbonCompanion = require('@carbon-companion/sdk');

const client = new CarbonCompanion({
  apiKey: 'your-api-key',
  baseUrl: 'https://api.carbon-companion.com'
});

// Create an operation
const operation = await client.operations.create({
  type: 'delivery',
  vehicleId: 1,
  projectId: 1,
  operationType: 'Material Delivery'
});

// Submit Scope 3 data
await client.scope3.submitData({
  categoryId: 1,
  emissions: 1250.5,
  methodology: 'supplier-specific'
});
```

### Python Integration
```python
import requests

class CarbonCompanionAPI:
    def __init__(self, api_key, base_url):
        self.api_key = api_key
        self.base_url = base_url
        self.headers = {
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/json'
        }
    
    def create_operation(self, operation_data):
        response = requests.post(
            f'{self.base_url}/api/operations',
            json=operation_data,
            headers=self.headers
        )
        return response.json()
```

### cURL Examples
```bash
# Create operation
curl -X POST https://api.carbon-companion.com/api/operations \
  -H "Authorization: Bearer your-token" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "delivery",
    "vehicleId": 1,
    "projectId": 1,
    "operationType": "Material Delivery"
  }'

# Get Scope 3 data
curl -X GET "https://api.carbon-companion.com/api/scope3/categories" \
  -H "Authorization: Bearer your-token"
```

---

*This API documentation provides comprehensive coverage of all Carbon Companion endpoints. For additional examples or specific integration questions, please refer to the SDK documentation or contact the development team.*

