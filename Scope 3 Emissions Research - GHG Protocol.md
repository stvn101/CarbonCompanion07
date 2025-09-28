# Scope 3 Emissions Research - GHG Protocol

## Overview
Scope 3 emissions are all indirect emissions that occur in the reporting company's upstream and downstream supply chain. The GHG Protocol defines 15 categories of Scope 3 emissions, though not every category will be relevant to all organizations.

## Key Findings from GHG Protocol and EPA

### What are Scope 3 Emissions?
- Scope 3 emissions are the result of activities from assets not owned or controlled by the reporting organization, but that the organization indirectly affects in its value chain
- An organization's value chain consists of both its upstream and downstream activities
- Scope 3 emissions include all sources not within an organization's scope 1 and 2 boundary
- Scope 3 emissions often represent the majority of an organization's total greenhouse gas (GHG) emissions

### The 15 Categories (from visual diagram):

**Upstream Activities:**
1. Purchased goods and services
2. Capital goods
3. Fuel and energy related activities
4. Transportation and distribution (upstream)
5. Waste generated in operations
6. Business travel
7. Employee commuting
8. Leased assets (upstream)

**Downstream Activities:**
9. Transportation and distribution (downstream)
10. Processing of sold products
11. Use of sold products
12. End-of-life treatment of sold products
13. Leased assets (downstream)
14. Franchising
15. Investments

### Key Requirements:
- Organizations must report emissions from all relevant scope 3 categories to fully meet GHG Protocol standards
- Relevance assessment criteria include: Size, Influence, Risk, Stakeholders, Outsourcing, Sector guidance
- Scope 3 emissions can be improved over time through more accurate data sources and more specific calculation methods

### Implementation Approach:
1. **Step 1**: Determine relevant scope 3 categories
2. **Step 2**: Estimate GHG emissions
3. **Step 3**: Improve and expand emissions estimate over time

## Sources:
- GHG Protocol Corporate Value Chain (Scope 3) Standard
- EPA Scope 3 Inventory Guidance
- Various industry resources and calculation guidance documents



## Detailed Breakdown of All 15 Scope 3 Categories

### Upstream Activities (Categories 1-8):

**Category 1 - Purchased goods and services**
- Emissions from production of goods and services purchased by the organization
- Includes raw materials, components, and services
- Often the largest category for many organizations

**Category 2 - Capital goods**
- Emissions from production of capital goods purchased by the organization
- Includes equipment, machinery, buildings, vehicles, and IT equipment
- Typically amortized over the useful life of the asset

**Category 3 - Fuel and energy related activities**
- Emissions from fuel and energy purchased that are not included in Scope 1 or 2
- Includes upstream emissions from fuel production, transmission and distribution losses
- Covers well-to-tank emissions for fuels

**Category 4 - Upstream transportation and distribution**
- Emissions from transportation and distribution of purchased goods
- Includes inbound logistics, third-party transportation services
- Covers transportation between suppliers and the organization

**Category 5 - Waste generated in operations**
- Emissions from disposal and treatment of waste generated in operations
- Includes landfill, recycling, composting, and incineration
- Covers both hazardous and non-hazardous waste

**Category 6 - Business travel**
- Emissions from employee business travel
- Includes air travel, rail, rental cars, and hotel stays
- One of the most commonly reported categories

**Category 7 - Employee commuting**
- Emissions from employee commuting to and from work
- Includes personal vehicles, public transportation, and remote work
- Can be significant for large organizations

**Category 8 - Upstream leased assets**
- Emissions from operation of leased assets not included in Scope 1 or 2
- Includes leased buildings, vehicles, and equipment
- Where the organization is the lessee

### Downstream Activities (Categories 9-15):

**Category 9 - Downstream transportation and distribution**
- Emissions from transportation and distribution of sold products
- Includes outbound logistics and distribution to customers
- Covers transportation between the organization and end customers

**Category 10 - Processing of sold products**
- Emissions from processing of intermediate products sold by the organization
- Applies when sold products require further processing
- Common in manufacturing and chemical industries

**Category 11 - Use of sold products**
- Emissions from use of goods and services sold by the organization
- Often the largest category for product manufacturers
- Includes energy consumption during product use phase

**Category 12 - End-of-life treatment of sold products**
- Emissions from disposal and treatment of products at end of life
- Includes recycling, landfill, and incineration of sold products
- Covers the entire product lifecycle

**Category 13 - Downstream leased assets**
- Emissions from operation of assets owned and leased to others
- Where the organization is the lessor
- Includes leased buildings, vehicles, and equipment

**Category 14 - Franchises**
- Emissions from operation of franchises
- Applies to organizations with franchise business models
- Covers emissions from franchise operations

**Category 15 - Investments**
- Emissions from investments including equity and debt investments
- Includes scope 1 and 2 emissions of investees
- Relevant for financial institutions and holding companies

## Calculation Methods by Category

### Primary Calculation Approaches:
1. **Supplier-specific method**: Direct data from suppliers
2. **Hybrid method**: Combination of supplier-specific and secondary data
3. **Average-data method**: Industry averages and emission factors
4. **Spend-based method**: Financial data with emission factors

### Data Collection Requirements:
- **Activity data**: Quantities, distances, energy consumption
- **Emission factors**: CO2e per unit of activity
- **Supplier data**: Direct emissions data from value chain partners
- **Financial data**: Spend data for spend-based calculations

## Integration Considerations for CarbonConstruct:

### API Requirements:
- Data collection APIs for each category
- Supplier engagement portals
- Emission factor databases
- Calculation engines for different methods

### Scalability Features:
- Multi-tenant architecture for different organizations
- Bulk data import capabilities
- Automated data validation and quality checks
- Real-time calculation and reporting

### Customization Needs:
- Industry-specific emission factors
- Custom calculation methodologies
- Flexible reporting templates
- Integration with existing ERP/procurement systems

