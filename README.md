# Vuln Data

A vulnerability tracking dashboard that visualizes CVE publication frequency for popular open source projects and Linux distributions.

## Overview

This project tracks and visualizes vulnerability data (CVEs) for key open source projects to help understand security trends over time. The system automatically collects CVE data from various sources and presents it through interactive charts showing publication frequency, severity distributions, and temporal patterns.

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

### Tracked Projects

#### Linux Distributions
- **Debian Linux**
  - CPE Pattern: `cpe:2.3:o:debian:debian_linux:*`
  - Focus on major releases (10, 11, 12)
  
- **Alpine Linux**
  - CPE Pattern: `cpe:2.3:o:alpinelinux:alpine_linux:*`
  - Focus on current stable releases

#### Open Source Applications
- **NGINX**
  - CPE Pattern: `cpe:2.3:a:f5:nginx_open_source:*` (F5 nginx open source)
  - Description Keywords: `nginx open source`, `nginx plus`
  - Web server vulnerabilities
  
- **Redis**
  - CPE Pattern: `cpe:2.3:a:redis:redis:*`
  - Description Keywords: `redis is an open source`, `redis is a`
  - In-memory database vulnerabilities
  
- **PostgreSQL**
  - CPE Pattern: `cpe:2.3:a:postgresql:postgresql:*`
  - Database server vulnerabilities

### Data Collection Architecture

1. **CVE Data Fetcher** (`src/data/cve-fetcher.js`)
   - Downloads and extracts NVD JSON 2.0 GZ feeds
   - Parses CVE data and filters by project CPE patterns
   - Falls back to description keyword matching for CVEs awaiting analysis
   - Generates both project-grouped and timeline data formats
   - Handles both current year and historical data feeds

2. **Data Processing Pipeline** (Integrated in `cve-fetcher.js`)
   - Extract project-specific CVEs from bulk feed data using configurable patterns
   - Normalize severity scores and classifications
   - Generate timeline events for visualization
   - Support for both CPE-based and description-based matching

3. **Caching Layer** (`src/data/cache/`)
   - `cve-data-{year}.json` - CVEs grouped by project for detailed analysis
   - `cve-timeline-{year}.json` - Chronological CVE events for visualization
   - `nvdcve-{year}.json` - Raw NVD feed data (cached)

4. **Observable Data Loaders** (`src/data/*.js`)
   - CVE timeline data formatted for chart consumption
   - Project-specific CVE datasets
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

This is an [Observable Framework](https://observablehq.com/framework/) app. To install the required dependencies, run:

```
npm install
```

Then, to start the local preview server, run:

```
npm run dev
```

Then visit <http://localhost:3000> to preview your app.

For more, see <https://observablehq.com/framework/getting-started>.

## Project structure

A typical Framework project looks like this:

```ini
.
├─ src
│  ├─ components
│  │  └─ timeline.js           # timeline visualization component
│  ├─ data
│  │  ├─ cache/                # cached CVE data
│  │  │  ├─ cve-data-2024.json       # CVEs grouped by project
│  │  │  ├─ cve-timeline-2024.json   # timeline events for visualization  
│  │  │  └─ nvdcve-2024.json         # raw NVD feed data
│  │  ├─ cve-fetcher.js        # CVE data collection script
│  │  ├─ launches.csv.js       # space launch data loader
│  │  └─ events.json           # timeline events data
│  ├─ example-dashboard.md     # dashboard example page
│  ├─ example-report.md        # report example page
│  └─ index.md                 # the home page
├─ .gitignore
├─ observablehq.config.js      # the app config file
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
