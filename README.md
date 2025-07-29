# Vuln Data

An interactive Observable notebook that analyzes and visualizes CVE (Common Vulnerabilities and Exposures) publication trends for open source projects. Users can customize project selections and explore security timelines through interactive charts and data tables.

## Overview

This Interactive Observable notebook enables users to:
- **Customize project selections** - Enter any open source projects you want to analyze through an editable text input
- **Visualize CVE timelines** - See vulnerability publication trends over time with interactive charts
- **Analyze severity distributions** - Filter and view CVE severity levels (Critical, High, Medium, Low)
- **Browse detailed CVE data** - Explore individual vulnerability records with full details
- **Real-time updates** - The notebook automatically updates all charts and data when you change project selections

The system intelligently normalizes project names (e.g., "NodeJS" → "nodejs", "GoLang" → "golang") and matches them against CVE data from 2023-2025.

## Data Collection Plan

### Primary Data Sources

1. **NIST National Vulnerability Database (NVD) - JSON 2.0 Data Feeds**
   - Primary source via bulk CVE data feeds (preferred approach)
   - 2024 Feed: `https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-2024.json.gz`
   - Benefits: No rate limiting, complete dataset, offline processing
   - Updated regularly with all CVEs for the year
   - File size: ~17MB compressed, contains full CVE details with CPE mappings

2. **NVD REST API 2.0** (Fallback for incremental updates)
   - Endpoint: `https://services.nvd.nist.gov/rest/json/cves/2.0`
   - Rate limit: 2000 results per request
   - Used for real-time updates and missing data

3. **Distribution Security Advisories** (Future enhancement)
   - Debian Security Advisory (DSA) feeds
   - Alpine Linux security database

### Interactive Project Selection

The notebook supports analysis of any open source project through an **interactive text input**. Users can:

- **Enter custom project lists** - Type project names one per line in the editable text area
- **Use common names** - The system understands variations like "NodeJS", "GoLang", "Python3"
- **Get real-time feedback** - See which projects match available CVE data immediately
- **Mix and match categories** - Combine any projects from these supported categories:

Project normalization is handled by `src/data/project-normalizer.js`, which converts user-friendly names to standardized identifiers. Each project is configured with CPE (Common Platform Enumeration) patterns for precise vulnerability matching, plus fallback description keywords for CVEs awaiting analysis.

### Data Collection Architecture

1. **CVE Data Fetcher** (`src/data/cve-fetcher.js`)
   - Downloads and extracts NVD JSON 2.0 GZ feeds
   - Parses CVE data and filters by project CPE patterns
   - Falls back to description keyword matching for CVEs awaiting analysis
   - Generates both project-grouped and timeline data formats
   - Handles both current year and historical data feeds

2. **Project Name Normalizer** (`src/data/project-normalizer.js`) - **NEW**
   - Converts user-friendly project names to standardized format
   - Handles common variations and aliases (e.g., "NodeJS" → "nodejs")
   - Supports 100+ project name mappings for better user experience
   - Provides transformation debugging for transparency

3. **Data Processing Pipeline** (Integrated in `cve-fetcher.js`)
   - Extract project-specific CVEs from bulk feed data using configurable patterns
   - Normalize severity scores and classifications
   - Generate timeline events for visualization
   - Support for both CPE-based and description-based matching

4. **Caching Layer** (`src/data/cache/`)
   - `cve-data-{year}.json` - CVEs grouped by project for detailed analysis
   - `cve-timeline-{year}.json` - Chronological CVE events for visualization
   - `nvdcve-{year}-chunks/` - Raw NVD feed data split into manageable chunks
     - `metadata.json` - Feed metadata and chunk information
     - `chunk-001.json`, `chunk-002.json`, etc. - Chunked CVE data (5000 CVEs per chunk)

5. **Observable Data Loaders** (`src/data/*.js`)
   - `cve-multi-year.json.js` - Multi-year weekly CVE aggregation data
   - `cve-weekly.json.js` - Weekly CVE timeline data
   - Project-specific CVE datasets with interactive filtering
   - Severity distribution calculations

### Data Update Strategy

- **Initial Load**: Download NVD JSON 2.0 feeds for current and previous year
- **Bulk Processing**: Extract and filter CVE data locally from GZ files
- **Incremental Updates**: Daily downloads of updated feed files
- **Cache Strategy**: Store filtered project data as JSON files for fast access
- **No Rate Limiting**: Using bulk feeds eliminates API rate limit concerns

### Adding New Tracked Projects

To add new projects to track, update the `TRACKED_PROJECTS` configuration in `src/data/cve-fetcher.js`:

```javascript
const TRACKED_PROJECTS = {
  newproject: {
    name: 'New Project',
    cpePatterns: [
      'cpe:2.3:a:vendor:product:*'
    ],
    descriptionKeywords: [
      'project specific keyword',
      'another identifying phrase'
    ]
  }
};
```

The system will automatically:
- Search for CVEs matching the CPE patterns
- Fall back to description keyword matching for CVEs awaiting analysis
- Include the new project in both grouped and timeline outputs

## Interactive Features

This is an [Observable Framework](https://observablehq.com/framework/) notebook designed for **interactive use**:

### Getting Started

**Option 1: Using Docker (Recommended - no Node.js installation required)**
1. **Build the container**: `docker build -t vuln-data .`
2. **Run the application**: `docker run -p 3000:3000 vuln-data`
3. **Open in browser**: Visit <http://localhost:3000>
4. **Customize analysis**: Edit the project list in the text area to analyze your preferred projects

**Option 2: Using Node.js directly**
1. **Install dependencies**: `npm install`
2. **Start the notebook**: `npm run dev`
3. **Open in browser**: Visit <http://localhost:3000>
4. **Customize analysis**: Edit the project list in the text area to analyze your preferred projects

## Project structure

A typical Framework project looks like this:

```ini
.
├─ src
│  ├─ components
│  │  └─ timeline.js              # timeline visualization component
│  ├─ data
│  │  ├─ cache/                   # cached CVE data
│  │  │  ├─ cve-data-{year}.json       # CVEs grouped by project
│  │  │  ├─ cve-timeline-{year}.json   # timeline events for visualization  
│  │  │  └─ nvdcve-{year}-chunks/      # chunked raw NVD feed data
│  │  ├─ cve-fetcher.js           # CVE data collection script
│  │  ├─ project-normalizer.js    # project name normalization (NEW)
│  │  ├─ cve-multi-year.json.js   # multi-year aggregated data loader
│  │  ├─ cve-weekly.json.js       # weekly timeline data loader
│  │  └─ launches.csv.js          # space launch data loader
│  └─ index.md                    # interactive notebook home page
├─ .gitignore
├─ observablehq.config.js         # the app config file
├─ package.json
└─ README.md
```

**`src`** - This is the “source root” — where your source files live. Pages go here. Each page is a Markdown file. Observable Framework uses [file-based routing](https://observablehq.com/framework/project-structure#routing), which means that the name of the file controls where the page is served. You can create as many pages as you like. Use folders to organize your pages.

**`src/index.md`** - This is the home page for your app. You can have as many additional pages as you’d like, but you should always have a home page, too.

**`src/data`** - You can put [data loaders](https://observablehq.com/framework/data-loaders) or static data files anywhere in your source root, but we recommend putting them here.

**`src/components`** - You can put shared [JavaScript modules](https://observablehq.com/framework/imports) anywhere in your source root, but we recommend putting them here. This helps you pull code out of Markdown files and into JavaScript modules, making it easier to reuse code across pages, write tests and run linters, and even share code with vanilla web applications.

**`observablehq.config.js`** - This is the [app configuration](https://observablehq.com/framework/config) file, such as the pages and sections in the sidebar navigation, and the app’s title.

## Command reference

| Command           | Description                                              |
| ----------------- | -------------------------------------------------------- |
| `npm install`            | Install or reinstall dependencies                        |
| `npm run dev`        | Start local preview server                               |
| `npm run build`      | Build your static site, generating `./dist`              |
| `npm run deploy`     | Deploy your app to Observable                            |
| `npm run clean`      | Clear the local data loader cache                        |
| `npm run observable` | Run commands like `observable help`                      |
