# Carbon Companion - Quick Start Guide

## 🚀 Get Started in 5 Minutes

This guide will get you up and running with Carbon Companion quickly.

## ⚡ Prerequisites

- Node.js 18+ installed
- PostgreSQL database (local or cloud)
- Git (for cloning)

## 📥 Installation

### 1. Extract and Setup
```bash
# Extract the downloaded package
tar -xzf carbon-companion-complete-v2.0.tar.gz
cd carbon-companion

# Install dependencies
npm install
```

### 2. Environment Configuration
```bash
# Copy environment template
cp .env.example .env

# Edit .env file with your database URL
DATABASE_URL="postgresql://username:password@localhost:5432/carbon_companion"
```

### 3. Database Setup
```bash
# Generate and push database schema
npm run db:generate
npm run db:push
```

### 4. Start Development Server
```bash
# Start the application
npm run dev

# Open http://localhost:5000 in your browser
```

## 🎯 Key Features to Try

### 1. Dashboard
- Switch between "Delivery Tracking" and "Machinery Operations"
- Create a new operation
- View real-time statistics

### 2. Scope 3 Tracking
- Click "Scope 3 Tracking" in the navigation
- Explore all 15 GHG Protocol categories
- View emissions data and completion status

### 3. Supplier Portal
- Access supplier management features
- Send data requests to suppliers
- Track supplier engagement

### 4. Advanced Calculator
- Use the emissions calculator
- Try different calculation methodologies
- Compare accuracy indicators

### 5. Reporting
- Generate comprehensive reports
- Export data in multiple formats
- View interactive charts

### 6. Settings
- Click the cog icon in the top-right
- Explore all settings categories
- Customize your preferences

## 🔧 Production Deployment

### Quick Deploy to Vercel
```bash
# Install Vercel CLI
npm i -g vercel

# Deploy
vercel --prod

# Set environment variables in Vercel dashboard
```

### Docker Deployment
```bash
# Build Docker image
docker build -t carbon-companion .

# Run container
docker run -p 5000:5000 -e DATABASE_URL="your_db_url" carbon-companion
```

## 📊 Sample Data

To populate with sample data for testing:
```bash
npm run db:seed
```

This will create:
- Sample projects
- Equipment inventory
- Test operations
- Scope 3 sample data

## 🔗 Integration

### API Access
```javascript
// Example API call
const response = await fetch('/api/operations', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Authorization': 'Bearer your-token'
  },
  body: JSON.stringify({
    type: 'delivery',
    vehicleId: 1,
    projectId: 1
  })
});
```

### Webhook Setup
```bash
# Register webhook endpoint
curl -X POST http://localhost:5000/api/webhooks \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://your-app.com/webhook",
    "events": ["operation.completed"]
  }'
```

## 📱 Mobile Access

The application is fully responsive and works on:
- Desktop browsers
- Tablets
- Mobile phones
- Progressive Web App (PWA) capable

## 🆘 Quick Troubleshooting

### Database Connection Issues
```bash
# Check database connectivity
npm run db:check

# Reset database
npm run db:reset
```

### Build Issues
```bash
# Clear cache and rebuild
rm -rf node_modules package-lock.json
npm install
npm run build
```

### Port Already in Use
```bash
# Use different port
PORT=3000 npm run dev
```

## 📚 Next Steps

1. **Read Full Documentation**: Check `IMPLEMENTATION_GUIDE.md` for comprehensive setup
2. **API Integration**: Review `API_DOCUMENTATION.md` for complete API reference
3. **Customization**: Modify components in `client/src/components/`
4. **Database Schema**: Extend `shared/schema.ts` for custom fields
5. **Deployment**: Follow production deployment guide for your platform

## 🎯 Live Demo

**Production URL**: https://gitgtqlg.manus.space

Try all features without any setup required!

## 📞 Support

- **Documentation**: Complete guides in the package
- **API Reference**: Comprehensive API documentation included
- **Examples**: Integration examples in `/examples` folder
- **Issues**: Check troubleshooting section in implementation guide

---

*You're now ready to use Carbon Companion! The application provides enterprise-level carbon emissions tracking with full Scope 3 compliance.*

