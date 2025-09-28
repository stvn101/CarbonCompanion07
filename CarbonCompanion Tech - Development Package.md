# CarbonCompanion Tech - Development Package

## 🚀 Quick Start

### Prerequisites
- Node.js 18+
- PostgreSQL 14+
- npm or yarn

### Installation
```bash
# Install dependencies
npm install

# Set up environment variables
cp .env.example .env
# Edit .env with your database URL and other configurations

# Set up database
npm run db:push

# Start development server
npm run dev
```

### Build for Production
```bash
npm run build
npm start
```

## 📁 Package Contents

### Core Application Files
- `src/` - Main application source code
- `server/` - Backend API and server logic
- `shared/` - Shared types and utilities

### Configuration Files
- `package.json` - Dependencies and scripts
- `tsconfig.json` - TypeScript configuration
- `vite.config.ts` - Build configuration
- `tailwind.config.ts` - Styling configuration
- `drizzle.config.ts` - Database configuration

### Documentation
- `IMPLEMENTATION_GUIDE.md` - Complete setup guide
- `API_DOCUMENTATION.md` - API reference
- `QUICK_START.md` - Quick setup instructions
- `CARBONCOMPANION_TECH_INTEGRATION_FEATURES.md` - Features overview

## 🔧 Environment Variables

Create a `.env` file with:
```
DATABASE_URL=postgresql://user:password@localhost:5432/carboncompanion
OPENAI_API_KEY=your_openai_key_here
OPENAI_API_BASE=https://api.openai.com/v1
```

## 📊 Key Features
- Dual operation modes (Delivery Tracking & Machinery Operations)
- Complete Scope 3 emissions tracking (15 GHG Protocol categories)
- Supplier engagement portal
- Advanced reporting and analytics
- Dark/Light mode support
- Real-time data validation

## 🔗 Integration Ready
- RESTful API endpoints
- Webhook support
- ERP system integration
- AI capabilities (OpenAI pre-configured)
- Multi-tenant architecture

## 📞 Support
For technical questions or implementation support, refer to the included documentation files.

