/**
 * Project Name Normalizer - Handles conversion of human-friendly project names
 * to standardized format for CVE analysis
 */

/**
 * Normalize project names to standard format
 * Handles common variations, capitalization differences, and special characters
 * @param {string} name - Raw project name from user input
 * @returns {string} - Normalized project name
 */
export function normalizeProjectName(name) {
  // Handle non-string inputs
  if (!name || typeof name !== 'string') {
    return '';
  }
  
  const cleaned = name.trim().toLowerCase();
  
  // Handle common variations and aliases
  const nameMap = {
    'nodejs': 'nodejs',
    'node.js': 'nodejs', 
    'node': 'nodejs',
    'python3': 'python3',
    'python': 'python3',
    'golang': 'golang',
    'go': 'golang',
    'apache': 'apache',
    'httpd': 'apache',
    'nginx': 'nginx',
    'postgresql': 'postgresql',
    'postgres': 'postgresql',
    'mysql': 'mysql',
    'mariadb': 'mysql',
    'redis': 'redis',
    'memcached': 'memcached',
    'memcache': 'memcached',
    'rabbitmq': 'rabbitmq',
    'rabbit': 'rabbitmq',
    'docker': 'docker',
    'kubernetes': 'kubernetes',
    'k8s': 'kubernetes',
    'bash': 'bash',
    'sh': 'bash',
    'busybox': 'busybox',
    'tomcat': 'tomcat',
    'java': 'java',
    'openjdk': 'java',
    'php': 'php',
    'perl': 'perl',
    'fastapi': 'fastapi',
    'django': 'django',
    'flask': 'flask',
    'dotnet': 'dotnet',
    '.net': 'dotnet',
    'maven': 'maven',
    'gradle': 'gradle',
    'openssl': 'openssl',
    'ssl': 'openssl',
    'curl': 'curl',
    'ubuntu': 'ubuntu',
    'debian': 'debian',
    'alpine': 'alpine',
    'bun': 'bun',
    'deno': 'deno',
    'fluentbit': 'fluentbit',
    'fluent-bit': 'fluentbit',
    'fluent_bit': 'fluentbit',
    'v8': 'v8',
    'ruby': 'ruby',
    'rust': 'rust',
    'express': 'express',
    'react': 'react',
    'angular': 'angular',
    'vue': 'vue',
    'laravel': 'laravel',
    'rails': 'rails',
    'spring': 'spring',
    'mongodb': 'mongodb',
    'mongo': 'mongodb',
    'elasticsearch': 'elasticsearch',
    'elastic': 'elasticsearch',
    'sqlite': 'sqlite',
    'cassandra': 'cassandra',
    'kafka': 'kafka',
    'nats': 'nats',
    'activemq': 'activemq',
    'npm': 'npm',
    'jenkins': 'jenkins',
    'gitlab': 'gitlab',
    'git': 'git',
    'vim': 'vim',
    'prometheus': 'prometheus',
    'grafana': 'grafana',
    'jaeger': 'jaeger',
    'zipkin': 'zipkin',
    'centos': 'centos',
    'fedora': 'fedora',
    'linux': 'linux',
    'caddy': 'caddy',
    'traefik': 'traefik',
    'haproxy': 'haproxy',
    'lua': 'lua'
  };
  
  // Remove special characters and normalize
  const normalized = cleaned.replace(/[^a-z0-9]/g, '');
  
  return nameMap[normalized] || nameMap[cleaned] || normalized;
}

/**
 * Parse and normalize a list of project names
 * @param {string} rawInput - Raw text input with project names (one per line)
 * @returns {string[]} - Array of normalized project names (deduplicated)
 */
export function parseProjectNames(rawInput) {
  // Handle non-string inputs
  if (!rawInput || typeof rawInput !== 'string') {
    return [];
  }
  
  return rawInput
    .split('\n')
    .map(line => line.trim())
    .filter(line => line.length > 0)
    .map(normalizeProjectName)
    .filter(name => name && name.length > 0) // Remove empty results
    .filter((name, index, array) => array.indexOf(name) === index); // Remove duplicates
}

/**
 * Show transformations for debugging/transparency
 * @param {string} rawInput - Raw text input with project names
 * @returns {Array} - Array of {original, normalized} objects
 */
export function showTransformations(rawInput) {
  // Handle non-string inputs
  if (!rawInput || typeof rawInput !== 'string') {
    return [];
  }
  
  return rawInput
    .split('\n')
    .map(line => line.trim())
    .filter(line => line.length > 0)
    .map(original => ({
      original,
      normalized: normalizeProjectName(original)
    }))
    .filter(item => item.normalized && item.normalized.length > 0); // Remove items with empty normalized names
}