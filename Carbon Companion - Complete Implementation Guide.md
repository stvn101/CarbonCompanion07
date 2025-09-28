# Carbon Companion - Complete Implementation Guide

## 📋 Table of Contents

1. [Overview](#overview)
2. [System Requirements](#system-requirements)
3. [Installation & Setup](#installation--setup)
4. [Architecture Overview](#architecture-overview)
5. [Core Features](#core-features)
6. [Scope 3 Enhancements](#scope-3-enhancements)
7. [API Integration](#api-integration)
8. [Database Configuration](#database-configuration)
9. [Deployment Guide](#deployment-guide)
10. [Customization](#customization)
11. [Troubleshooting](#troubleshooting)

## 🎯 Overview

Carbon Companion is a comprehensive carbon emissions tracking application designed for the earthworks and construction industry. It provides real-time monitoring, Scope 3 emissions tracking, supplier engagement, and advanced reporting capabilities.

### Key Capabilities
- **Dual Operation Modes**: Delivery Tracking & Machinery Operations
- **Scope 3 Compliance**: All 15 GHG Protocol categories covered
- **Supplier Engagement**: Complete supplier collaboration platform
- **Advanced Analytics**: Interactive reporting and data visualization
- **Enterprise Integration**: API-ready for CarbonConstruct SaaS platform

## 🔧 System Requirements

### Development Environment
- **Node.js**: v18.0.0 or higher
- **npm**: v8.0.0 or higher
- **Database**: PostgreSQL 14+ (Neon, Supabase, or local)
- **OS**: Windows 10+, macOS 10.15+, or Linux Ubuntu 20.04+

### Production Environment
- **Memory**: 2GB RAM minimum, 4GB recommended
- **Storage**: 10GB minimum for application and data
- **Network**: HTTPS required for production deployment
- **Database**: Managed PostgreSQL service recommended

## 🚀 Installation & Setup

### 1. Clone and Install Dependencies

```bash
# Clone the repository
git clone <repository-url>
cd carbon-companion

# Install dependencies
npm install

# Install development dependencies
npm install --save-dev
```

### 2. Environment Configuration

Create a `.env` file in the root directory:

```env
# Database Configuration
DATABASE_URL="postgresql://username:password@host:port/database"

# Application Settings
NODE_ENV=development
PORT=5000

# API Keys (if using external services)
OPENAI_API_KEY=your_openai_key_here
OPENAI_API_BASE=https://api.openai.com/v1

# Security
JWT_SECRET=your_jwt_secret_here
ENCRYPTION_KEY=your_encryption_key_here

# External Integrations
CARBONCONSTRUCT_API_URL=https://api.carbonconstruct.com
CARBONCONSTRUCT_API_KEY=your_api_key_here
```

### 3. Database Setup

```bash
# Generate database schema
npm run db:generate

# Push schema to database
npm run db:push

# Seed initial data (optional)
npm run db:seed
```

### 4. Development Server

```bash
# Start development server
npm run dev

# Application will be available at http://localhost:5000
```

## 🏗️ Architecture Overview

### Frontend Architecture
```
client/
├── src/
│   ├── components/          # Reusable UI components
│   │   ├── Navigation.tsx   # Main navigation bar
│   │   ├── Scope3Dashboard.tsx
│   │   ├── SupplierPortal.tsx
│   │   ├── EmissionsCalculator.tsx
│   │   ├── AdvancedReporting.tsx
│   │   ├── DataCollectionWizard.tsx
│   │   └── SettingsModal.tsx
│   ├── pages/              # Page components
│   │   └── dashboard.tsx   # Main dashboard
│   ├── lib/               # Utilities and helpers
│   ├── hooks/             # Custom React hooks
│   └── types/             # TypeScript type definitions
├── public/                # Static assets
└── dist/                  # Built application
```

### Backend Architecture
```
server/
├── routes/                # API route handlers
├── middleware/            # Express middleware
├── services/              # Business logic
├── models/                # Data models
└── utils/                 # Utility functions

shared/
├── schema.ts              # Database schema (Drizzle ORM)
└── types.ts               # Shared type definitions
```

## 🎯 Core Features

### 1. Delivery Tracking Mode

**Purpose**: Track vehicle deliveries, material transport, and logistics operations

**Key Components**:
- Real-time GPS tracking simulation
- Fuel consumption monitoring
- Load weight and distance tracking
- Project site assignment

**Implementation**:
```typescript
// Example usage in dashboard.tsx
const handleDeliveryStart = async (deliveryData) => {
  const response = await fetch('/api/operations', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      type: 'delivery',
      vehicle: deliveryData.vehicle,
      project: deliveryData.project,
      operationType: deliveryData.operationType
    })
  });
};
```

### 2. Machinery Operations Mode

**Purpose**: Monitor heavy equipment operations, earthmoving, and construction activities

**Key Components**:
- Equipment selection and management
- Operating hours tracking
- Material moved (cubic meters)
- Fuel efficiency monitoring

**Implementation**:
```typescript
// Example machinery operation tracking
const trackMachineryOperation = async (operationData) => {
  const emissions = calculateEmissions(
    operationData.fuelUsed,
    operationData.operatingHours,
    operationData.equipmentType
  );
  
  await saveOperation({
    ...operationData,
    emissions,
    carbonFootprint: emissions * CARBON_FACTOR
  });
};
```

## 🌍 Scope 3 Enhancements

### Complete GHG Protocol Coverage

The application covers all 15 Scope 3 categories as defined by the GHG Protocol:

#### Upstream Categories (1-8)
1. **Purchased Goods and Services**: Supplier emissions from materials
2. **Capital Goods**: Equipment and infrastructure emissions
3. **Fuel and Energy Related Activities**: Upstream fuel production
4. **Transportation and Distribution**: Inbound logistics
5. **Waste Generated in Operations**: Waste disposal emissions
6. **Business Travel**: Employee travel emissions
7. **Employee Commuting**: Daily commute tracking
8. **Upstream Leased Assets**: Leased equipment emissions

#### Downstream Categories (9-15)
9. **Transportation and Distribution**: Outbound logistics
10. **Processing of Sold Products**: Customer processing emissions
11. **Use of Sold Products**: Product lifecycle emissions
12. **End-of-Life Treatment**: Product disposal emissions
13. **Downstream Leased Assets**: Customer leased assets
14. **Franchises**: Franchise operations emissions
15. **Investments**: Investment portfolio emissions

### Implementation Example

```typescript
// Scope3Dashboard.tsx implementation
const scope3Categories = [
  {
    id: 1,
    name: "Purchased Goods and Services",
    description: "Emissions from purchased materials and services",
    emissions: 1250.5,
    dataQuality: "high",
    completionStatus: "complete",
    methodology: "supplier-specific"
  },
  // ... other categories
];

const calculateCategoryEmissions = (category, data) => {
  switch (category.methodology) {
    case 'supplier-specific':
      return data.supplierEmissions;
    case 'hybrid':
      return (data.supplierEmissions + data.averageEmissions) / 2;
    case 'average-data':
      return data.industryAverage * data.activityData;
    case 'spend-based':
      return data.spend * data.emissionFactor;
    default:
      return 0;
  }
};
```

## 🔌 API Integration

### RESTful API Endpoints

#### Operations Management
```typescript
// GET /api/operations - Retrieve all operations
// POST /api/operations - Create new operation
// PUT /api/operations/:id - Update operation
// DELETE /api/operations/:id - Delete operation

// Example API call
const createOperation = async (operationData) => {
  const response = await fetch('/api/operations', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`
    },
    body: JSON.stringify(operationData)
  });
  return response.json();
};
```

#### Scope 3 Data Management
```typescript
// GET /api/scope3/categories - Get all Scope 3 categories
// POST /api/scope3/data - Submit Scope 3 data
// GET /api/scope3/reports - Generate Scope 3 reports

// Example Scope 3 data submission
const submitScope3Data = async (categoryId, data) => {
  const response = await fetch('/api/scope3/data', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      categoryId,
      data,
      methodology: data.methodology,
      dataQuality: data.quality
    })
  });
};
```

#### Supplier Integration
```typescript
// GET /api/suppliers - List all suppliers
// POST /api/suppliers/invite - Invite new supplier
// GET /api/suppliers/:id/data - Get supplier emissions data

// Example supplier invitation
const inviteSupplier = async (supplierInfo) => {
  const response = await fetch('/api/suppliers/invite', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      email: supplierInfo.email,
      company: supplierInfo.company,
      categories: supplierInfo.scope3Categories
    })
  });
};
```

## 🗄️ Database Configuration

### Schema Overview

The application uses Drizzle ORM with PostgreSQL. Key tables include:

```typescript
// shared/schema.ts
export const operations = pgTable('operations', {
  id: serial('id').primaryKey(),
  type: varchar('type', { length: 50 }).notNull(),
  vehicleId: integer('vehicle_id').references(() => vehicles.id),
  projectId: integer('project_id').references(() => projects.id),
  startTime: timestamp('start_time').defaultNow(),
  endTime: timestamp('end_time'),
  distance: decimal('distance', { precision: 10, scale: 2 }),
  fuelUsed: decimal('fuel_used', { precision: 10, scale: 2 }),
  emissions: decimal('emissions', { precision: 10, scale: 2 }),
  createdAt: timestamp('created_at').defaultNow(),
  updatedAt: timestamp('updated_at').defaultNow()
});

export const scope3Data = pgTable('scope3_data', {
  id: serial('id').primaryKey(),
  categoryId: integer('category_id').notNull(),
  organizationId: integer('organization_id'),
  emissions: decimal('emissions', { precision: 15, scale: 2 }),
  methodology: varchar('methodology', { length: 50 }),
  dataQuality: varchar('data_quality', { length: 20 }),
  reportingPeriod: varchar('reporting_period', { length: 20 }),
  createdAt: timestamp('created_at').defaultNow()
});
```

### Database Setup Commands

```bash
# Generate migration files
npm run db:generate

# Apply migrations
npm run db:migrate

# Reset database (development only)
npm run db:reset

# Backup database
npm run db:backup

# Restore database
npm run db:restore backup_file.sql
```

## 🚀 Deployment Guide

### Production Build

```bash
# Build the application
npm run build

# Test production build locally
npm start

# Verify all features work correctly
npm run test:e2e
```

### Environment-Specific Deployments

#### Vercel Deployment
```bash
# Install Vercel CLI
npm i -g vercel

# Deploy to Vercel
vercel --prod

# Set environment variables
vercel env add DATABASE_URL
vercel env add JWT_SECRET
```

#### Docker Deployment
```dockerfile
# Dockerfile
FROM node:18-alpine

WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production

COPY . .
RUN npm run build

EXPOSE 5000
CMD ["npm", "start"]
```

#### Traditional Server Deployment
```bash
# On your server
git clone <repository>
cd carbon-companion
npm install
npm run build

# Set up PM2 for process management
npm install -g pm2
pm2 start ecosystem.config.js
pm2 save
pm2 startup
```

### Environment Variables for Production

```env
NODE_ENV=production
DATABASE_URL=postgresql://prod_user:password@prod_host:5432/carbon_companion
JWT_SECRET=your_production_jwt_secret
ENCRYPTION_KEY=your_production_encryption_key
CARBONCONSTRUCT_API_URL=https://api.carbonconstruct.com
CARBONCONSTRUCT_API_KEY=your_production_api_key
```

## 🎨 Customization

### Theming and Branding

```typescript
// tailwind.config.ts
module.exports = {
  theme: {
    extend: {
      colors: {
        primary: {
          50: '#f0fdf4',
          500: '#22c55e',
          900: '#14532d'
        },
        brand: {
          primary: '#your-brand-color',
          secondary: '#your-secondary-color'
        }
      }
    }
  }
};
```

### Custom Emission Factors

```typescript
// lib/emissionFactors.ts
export const customEmissionFactors = {
  diesel: 2.68, // kg CO2/L
  gasoline: 2.31, // kg CO2/L
  electricity: 0.5, // kg CO2/kWh
  // Add your region-specific factors
};

export const calculateCustomEmissions = (fuelType, amount, region) => {
  const factor = getRegionalFactor(fuelType, region);
  return amount * factor;
};
```

### Adding New Equipment Types

```typescript
// Add to shared/schema.ts
export const equipmentTypes = [
  'Excavator',
  'Bulldozer',
  'Crane',
  'Your Custom Equipment'
];

// Update components/dashboard.tsx
const customEquipmentSpecs = {
  'Your Custom Equipment': {
    fuelCapacity: 200,
    averageConsumption: 15,
    emissionFactor: 2.8
  }
};
```

## 🔧 Troubleshooting

### Common Issues and Solutions

#### Database Connection Issues
```bash
# Check database connectivity
npm run db:check

# Reset database connection
npm run db:reset-connection

# Verify environment variables
echo $DATABASE_URL
```

#### Build Failures
```bash
# Clear node modules and reinstall
rm -rf node_modules package-lock.json
npm install

# Clear build cache
npm run clean
npm run build
```

#### API Authentication Issues
```typescript
// Check JWT token validity
const verifyToken = (token) => {
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    return decoded;
  } catch (error) {
    console.error('Token verification failed:', error);
    return null;
  }
};
```

### Performance Optimization

#### Database Optimization
```sql
-- Add indexes for better query performance
CREATE INDEX idx_operations_created_at ON operations(created_at);
CREATE INDEX idx_scope3_data_category ON scope3_data(category_id);
CREATE INDEX idx_operations_project ON operations(project_id);
```

#### Frontend Optimization
```typescript
// Implement lazy loading for large components
const Scope3Dashboard = lazy(() => import('./components/Scope3Dashboard'));
const AdvancedReporting = lazy(() => import('./components/AdvancedReporting'));

// Use React.memo for expensive components
export const ExpensiveComponent = React.memo(({ data }) => {
  // Component implementation
});
```

### Monitoring and Logging

```typescript
// Add comprehensive logging
import winston from 'winston';

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.json(),
  transports: [
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.File({ filename: 'combined.log' })
  ]
});

// Log API requests
app.use((req, res, next) => {
  logger.info(`${req.method} ${req.url}`, {
    ip: req.ip,
    userAgent: req.get('User-Agent')
  });
  next();
});
```

## 📞 Support and Resources

### Documentation Links
- [GHG Protocol Scope 3 Standard](https://ghgprotocol.org/scope-3-standard)
- [Drizzle ORM Documentation](https://orm.drizzle.team/)
- [React Documentation](https://react.dev/)
- [Tailwind CSS Documentation](https://tailwindcss.com/)

### Community and Support
- GitHub Issues: Report bugs and feature requests
- Documentation: Comprehensive guides and API reference
- Community Forum: Connect with other developers

### Version History
- **v2.0.0**: Scope 3 enhancements, supplier portal, advanced reporting
- **v1.5.0**: Settings modal, improved navigation, bug fixes
- **v1.0.0**: Initial release with delivery tracking and machinery operations

---

*This implementation guide provides comprehensive coverage of the Carbon Companion application. For specific questions or advanced customization needs, please refer to the source code or contact the development team.*

