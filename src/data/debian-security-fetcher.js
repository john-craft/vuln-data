/**
 * Debian Security Tracker Data Fetcher
 * Fetches vulnerability data directly from Debian's security tracker API
 * https://security-tracker.debian.org/tracker/data/json
 */

import { writeFile, readFile } from 'fs/promises';
import { existsSync } from 'fs';

const DEBIAN_SECURITY_API = 'https://security-tracker.debian.org/tracker/data/json';
const CACHE_DIR = './src/data/cache';

/**
 * Fetch Debian security tracker data
 * @returns {Object} - Raw Debian security data
 */
async function fetchDebianSecurityData() {
  console.log('Fetching Debian security tracker data...');
  
  const response = await fetch(DEBIAN_SECURITY_API);
  if (!response.ok) {
    throw new Error(`Failed to fetch Debian security data: ${response.statusText}`);
  }
  
  const data = await response.json();
  console.log(`Loaded security data for ${Object.keys(data).length} Debian packages`);
  
  return data;
}

/**
 * Extract CVE publication year from CVE ID
 * @param {string} cveId - CVE identifier (e.g., "CVE-2024-1234")
 * @returns {number} - Publication year
 */
function getCveYear(cveId) {
  const match = cveId.match(/^CVE-(\d{4})-/);
  return match ? parseInt(match[1]) : null;
}

/**
 * Convert Debian urgency to severity level
 * @param {string} urgency - Debian urgency level
 * @returns {string} - Standardized severity
 */
function urgencyToSeverity(urgency) {
  switch (urgency?.toLowerCase()) {
    case 'high':
      return 'HIGH';
    case 'medium':
      return 'MEDIUM';
    case 'low':
      return 'LOW';
    case 'unimportant':
      return 'LOW';
    case 'not yet assigned':
      return 'UNKNOWN';
    default:
      return 'UNKNOWN';
  }
}

/**
 * Load NVD CVE publication dates from raw chunks
 * @param {number[]} years - Years to load
 * @returns {Map} - Map of CVE ID -> publication date
 */
async function loadNvdPublicationDates(years) {
  const cvePublicationDates = new Map();
  
  for (const year of years) {
    const chunksDir = `${CACHE_DIR}/nvdcve-${year}-chunks`;
    if (existsSync(chunksDir)) {
      try {
        // Read metadata to know how many chunks exist
        const metadataPath = `${chunksDir}/metadata.json`;
        if (existsSync(metadataPath)) {
          const metadata = JSON.parse(await readFile(metadataPath, 'utf8'));
          
          // Process each chunk
          for (let i = 1; i <= metadata.totalChunks; i++) {
            const chunkFile = `${chunksDir}/chunk-${String(i).padStart(3, '0')}.json`;
            if (existsSync(chunkFile)) {
              const chunkData = JSON.parse(await readFile(chunkFile, 'utf8'));
              
              chunkData.vulnerabilities.forEach(vuln => {
                const cve = vuln.cve;
                if (cve && cve.id && cve.published) {
                  // Extract just the date part (YYYY-MM-DD)
                  const publishedDate = cve.published.split('T')[0];
                  cvePublicationDates.set(cve.id, publishedDate);
                }
              });
            }
          }
          
          console.log(`Loaded ${cvePublicationDates.size} CVE publication dates for ${year}`);
        }
      } catch (error) {
        console.warn(`Could not load NVD publication dates for ${year}:`, error.message);
      }
    } else {
      console.log(`No NVD chunks found for ${year}`);
    }
  }
  
  return cvePublicationDates;
}

/**
 * Process Debian security data into timeline format
 * @param {Object} securityData - Raw Debian security data
 * @param {number[]} years - Years to process (defaults to [2023, 2024, 2025])
 * @returns {Array} - Timeline events in standard format
 */
async function processDebianSecurityData(securityData, years = [2023, 2024, 2025]) {
  const timelineEvents = [];
  
  console.log(`Processing Debian security data for years: ${years.join(', ')}`);
  
  // Load NVD publication dates for accurate timeline data
  const nvdPublicationDates = await loadNvdPublicationDates(years);
  console.log(`Loaded ${nvdPublicationDates.size} NVD publication dates for cross-reference`);
  
  for (const [packageName, packageData] of Object.entries(securityData)) {
    for (const [cveId, cveData] of Object.entries(packageData)) {
      const cveYear = getCveYear(cveId);
      
      // Skip if not in target years
      if (!years.includes(cveYear)) {
        continue;
      }
      
      // Get urgency from current Debian releases (prefer bookworm, fallback to others)
      const releases = cveData.releases || {};
      let urgency = 'unknown';
      
      // Priority order: bookworm (current stable) -> trixie (testing) -> sid (unstable)
      const priorityReleases = ['bookworm', 'trixie', 'sid', 'bullseye'];
      for (const release of priorityReleases) {
        if (releases[release]?.urgency) {
          urgency = releases[release].urgency;
          break;
        }
      }
      
      // Get publication date from NVD data, or use year-based fallback
      let publicationDate = nvdPublicationDates.get(cveId);
      if (!publicationDate) {
        // Fallback: use January 1st of CVE year if no NVD date available
        publicationDate = `${cveYear}-01-01`;
      }
      
      // Determine if this is a kernel CVE
      const isKernelCve = packageName === 'linux' || 
                         packageName.startsWith('linux-') ||
                         packageName === 'linux-image' ||
                         packageName === 'linux-headers';
      
      // Create timeline event with appropriate project classification
      const timelineEvent = {
        date: publicationDate,
        project: isKernelCve ? 'kernel' : 'debian',
        projectName: isKernelCve ? 'Linux Kernel' : 'Debian Linux',
        cve: cveId,
        severity: urgencyToSeverity(urgency),
        score: 0, // Debian doesn't provide CVSS scores
        description: cveData.description || 'No description available',
        package: packageName,
        scope: cveData.scope || 'unknown'
      };
      
      timelineEvents.push(timelineEvent);
    }
  }
  
  console.log(`Extracted ${timelineEvents.length} Debian CVE events`);
  
  // Sort by publication date for consistent timeline ordering
  return timelineEvents.sort((a, b) => new Date(a.date) - new Date(b.date));
}

/**
 * Generate enhanced Debian timeline data
 * @param {number[]} years - Years to process
 * @returns {Object} - Enhanced timeline data
 */
export async function generateDebianTimelineData(years = [2023, 2024, 2025]) {
  try {
    // Fetch fresh data from Debian security tracker
    const securityData = await fetchDebianSecurityData();
    
    // Save raw data for debugging
    const rawDataPath = `${CACHE_DIR}/debian-security-raw.json`;
    await writeFile(rawDataPath, JSON.stringify(securityData, null, 2));
    console.log(`Saved raw Debian security data to ${rawDataPath}`);
    
    // Process into timeline format
    const timelineData = await processDebianSecurityData(securityData, years);
    
    // Save processed timeline data, split by project type
    for (const year of years) {
      const yearEvents = timelineData.filter(event => event.date.startsWith(year.toString()));
      
      // Split into Debian and Kernel CVEs
      const debianEvents = yearEvents.filter(event => event.project === 'debian');
      const kernelEvents = yearEvents.filter(event => event.project === 'kernel');
      
      // Save Debian CVEs
      const debianTimelinePath = `${CACHE_DIR}/debian-timeline-${year}.json`;
      await writeFile(debianTimelinePath, JSON.stringify(debianEvents, null, 2));
      console.log(`Saved ${debianEvents.length} Debian CVEs for ${year} to ${debianTimelinePath}`);
      
      // Save Kernel CVEs  
      const kernelTimelinePath = `${CACHE_DIR}/kernel-timeline-${year}.json`;
      await writeFile(kernelTimelinePath, JSON.stringify(kernelEvents, null, 2));
      console.log(`Saved ${kernelEvents.length} Kernel CVEs for ${year} to ${kernelTimelinePath}`);
    }
    
    return {
      totalEvents: timelineData.length,
      eventsByYear: years.reduce((acc, year) => {
        acc[year] = timelineData.filter(event => event.date.startsWith(year.toString())).length;
        return acc;
      }, {})
    };
    
  } catch (error) {
    console.error('Error generating Debian timeline data:', error);
    throw error;
  }
}

// If run directly, generate data for recent years
if (import.meta.url === `file://${process.argv[1]}`) {
  generateDebianTimelineData([2023, 2024, 2025]).catch(console.error);
}