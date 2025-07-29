---
theme: dashboard
toc: false
---

# CVE Timeline Analysis

This notebook analyzes CVE (Common Vulnerabilities and Exposures) publication trends for open source projects. You can customize the list of projects and visualize their security timelines over time.

## Step 1: Choose your projects

Enter the open source projects you want to analyze, one per line. You can edit the list below or replace it entirely with your own projects. The system will automatically handle variations in naming and capitalization.

```js
// Editable project input
const projectInput = Inputs.textarea({
  value: `NodeJS
Bun
Deno
FastAPI
Django
Flask
Python3
PHP
Perl
Apache
Nginx
RabbitMQ
Redis
MemCached
Tomcat
GoLang
Busybox
BASH
Dotnet
Maven
Gradle
Java
Fluent-Bit`,
  rows: 15
});

// Make it reactive
const rawProjectInput = Generators.input(projectInput);
```

${projectInput}

## Step 2: Process and load CVE data

The system standardizes project names, configures CVE search patterns, and loads vulnerability data.

```js
// Import project normalization functions
import { 
  normalizeProjectName, 
  parseProjectNames, 
  showTransformations 
} from "./data/project-normalizer.js";

// Load the weekly CVE data
const weeklyData = await FileAttachment("data/cve-multi-year.json").json();

// Process and normalize project names
const inputText = rawProjectInput || "";
const initialTransformations = showTransformations(inputText);
const parsedProjects = initialTransformations.map(item => item.normalized)
  .filter(name => name && typeof name === 'string' && name.trim().length > 0)
  .map(name => name.trim());

// Known project configurations with CVE search patterns
const KNOWN_PROJECTS = {
  nginx: { name: 'NGINX', cpePatterns: ['cpe:2.3:a:f5:nginx_open_source:*'], descriptionKeywords: ['nginx open source', 'nginx plus'] },
  apache: { name: 'Apache HTTP Server', cpePatterns: ['cpe:2.3:a:apache:http_server:*'], descriptionKeywords: ['apache http server', 'apache httpd'] },
  nodejs: { name: 'Node.js', cpePatterns: ['cpe:2.3:a:nodejs:node.js:*'], descriptionKeywords: ['node.js', 'nodejs'] },
  python3: { name: 'Python', cpePatterns: ['cpe:2.3:a:python:python:*'], descriptionKeywords: ['python programming language', 'cpython'] },
  golang: { name: 'Go', cpePatterns: ['cpe:2.3:a:golang:go:*'], descriptionKeywords: ['go programming language', 'golang'] },
  java: { name: 'Java', cpePatterns: ['cpe:2.3:a:oracle:jdk:*', 'cpe:2.3:a:oracle:openjdk:*'], descriptionKeywords: ['oracle java', 'openjdk'] },
  php: { name: 'PHP', cpePatterns: ['cpe:2.3:a:php:php:*'], descriptionKeywords: ['php programming language', 'php hypertext preprocessor'] },
  redis: { name: 'Redis', cpePatterns: ['cpe:2.3:a:redis:redis:*'], descriptionKeywords: ['redis is an open source', 'redis is a'] },
  postgresql: { name: 'PostgreSQL', cpePatterns: ['cpe:2.3:a:postgresql:postgresql:*'], descriptionKeywords: ['postgresql database'] },
  mysql: { name: 'MySQL', cpePatterns: ['cpe:2.3:a:mysql:mysql:*', 'cpe:2.3:a:oracle:mysql:*'], descriptionKeywords: ['mysql database', 'mysql server'] },
  docker: { name: 'Docker', cpePatterns: ['cpe:2.3:a:docker:docker:*'], descriptionKeywords: ['docker container', 'docker engine'] },
  kubernetes: { name: 'Kubernetes', cpePatterns: ['cpe:2.3:a:kubernetes:kubernetes:*'], descriptionKeywords: ['kubernetes orchestration', 'kubernetes cluster', 'k8s'] },
  bash: { name: 'Bash', cpePatterns: ['cpe:2.3:a:gnu:bash:*'], descriptionKeywords: ['bash shell', 'gnu bash'] },
  busybox: { name: 'BusyBox', cpePatterns: ['cpe:2.3:a:busybox:busybox:*'], descriptionKeywords: ['busybox utilities'] },
  tomcat: { name: 'Apache Tomcat', cpePatterns: ['cpe:2.3:a:apache:tomcat:*'], descriptionKeywords: ['apache tomcat'] },
  perl: { name: 'Perl', cpePatterns: ['cpe:2.3:a:perl:perl:*'], descriptionKeywords: ['perl programming language'] },
  fastapi: { name: 'FastAPI', cpePatterns: ['cpe:2.3:a:tiangolo:fastapi:*'], descriptionKeywords: ['fastapi framework', 'fastapi is a'] },
  django: { name: 'Django', cpePatterns: ['cpe:2.3:a:djangoproject:django:*'], descriptionKeywords: ['django framework', 'django web framework'] },
  flask: { name: 'Flask', cpePatterns: ['cpe:2.3:a:palletsprojects:flask:*'], descriptionKeywords: ['flask framework', 'flask web framework'] },
  dotnet: { name: '.NET', cpePatterns: ['cpe:2.3:a:microsoft:.net:*', 'cpe:2.3:a:microsoft:.net_core:*'], descriptionKeywords: ['microsoft .net', 'dotnet core'] },
  maven: { name: 'Apache Maven', cpePatterns: ['cpe:2.3:a:apache:maven:*'], descriptionKeywords: ['apache maven', 'maven build tool'] },
  gradle: { name: 'Gradle', cpePatterns: ['cpe:2.3:a:gradle:gradle:*'], descriptionKeywords: ['gradle build tool'] },
  openssl: { name: 'OpenSSL', cpePatterns: ['cpe:2.3:a:openssl:openssl:*'], descriptionKeywords: ['openssl cryptography', 'openssl ssl'] },
  curl: { name: 'cURL', cpePatterns: ['cpe:2.3:a:haxx:curl:*', 'cpe:2.3:a:haxx:libcurl:*'], descriptionKeywords: ['curl library', 'libcurl'] },
  ubuntu: { name: 'Ubuntu', cpePatterns: ['cpe:2.3:o:canonical:ubuntu_linux:*'], descriptionKeywords: ['ubuntu linux', 'ubuntu operating system'] },
  debian: { name: 'Debian Linux', cpePatterns: ['cpe:2.3:o:debian:debian_linux:*'], descriptionKeywords: ['debian linux', 'debian operating system'] },
  alpine: { name: 'Alpine Linux', cpePatterns: ['cpe:2.3:o:alpinelinux:alpine_linux:*'], descriptionKeywords: ['alpine linux', 'alpine operating system'] },
  bun: { name: 'Bun', cpePatterns: ['cpe:2.3:a:oven:bun:*'], descriptionKeywords: ['bun javascript runtime', 'bun runtime'] },
  deno: { name: 'Deno', cpePatterns: ['cpe:2.3:a:deno:deno:*'], descriptionKeywords: ['deno runtime', 'deno is a'] },
  fluentbit: { name: 'Fluent Bit', cpePatterns: ['cpe:2.3:a:fluentbit:fluent_bit:*'], descriptionKeywords: ['fluent bit', 'fluent-bit'] },
  rabbitmq: { name: 'RabbitMQ', cpePatterns: ['cpe:2.3:a:rabbitmq:rabbitmq:*', 'cpe:2.3:a:pivotal:rabbitmq:*'], descriptionKeywords: ['rabbitmq message broker'] },
  memcached: { name: 'Memcached', cpePatterns: ['cpe:2.3:a:memcached:memcached:*'], descriptionKeywords: ['memcached caching system'] }
};

// Create project configuration
function createTrackedProjectsConfig(projectNames) {
  const config = {};
  const unknown = [];
  
  projectNames.forEach(name => {
    if (KNOWN_PROJECTS[name]) {
      config[name] = KNOWN_PROJECTS[name];
    } else {
      const displayName = name.charAt(0).toUpperCase() + name.slice(1);
      config[name] = {
        name: displayName,
        cpePatterns: [`cpe:2.3:a:*:${name}:*`],
        descriptionKeywords: [name, `${name} vulnerability`]
      };
      unknown.push(name);
    }
  });
  
  return { config, unknown };
}

const { config: trackedProjects, unknown: unknownProjects } = createTrackedProjectsConfig(parsedProjects);

// Ensure weeklyData is an array
if (!Array.isArray(weeklyData)) {
  throw new Error(`Weekly data should be an array, got ${typeof weeklyData}`);
}

// Get all available projects from the data
const allAvailableProjects = [];
weeklyData.forEach(week => {
  if (week.projects) {
    allAvailableProjects.push(...Object.keys(week.projects));
  }
});
const uniqueAvailableProjects = [...new Set(allAvailableProjects)].sort();

// Filter data to only include our selected projects that actually exist in the data
const selectedProjectKeys = Object.keys(trackedProjects).filter(project => 
  uniqueAvailableProjects.includes(project)
);

const filteredWeeklyData = weeklyData.map(week => {
  // Filter projects to only include selected ones
  const filteredProjects = Object.fromEntries(
    Object.entries(week.projects || {})
      .filter(([project]) => selectedProjectKeys.includes(project))
  );
  
  // Calculate total for selected projects only
  const filteredTotal = Object.values(filteredProjects).reduce((sum, count) => sum + count, 0);
  
  // Filter severities to match only the selected projects' CVEs
  // Note: This is an approximation since we don't have per-project severity data
  // We'll scale the original severities proportionally to the filtered project data
  const originalTotal = Object.values(week.projects || {}).reduce((sum, count) => sum + count, 0);
  const scaleFactor = originalTotal > 0 ? filteredTotal / originalTotal : 0;
  
  const filteredSeverities = {};
  if (week.severities && scaleFactor > 0) {
    Object.entries(week.severities).forEach(([severity, count]) => {
      filteredSeverities[severity] = Math.round(count * scaleFactor);
    });
  }
  
  return {
    ...week,
    projects: filteredProjects,
    total: filteredTotal,
    severities: filteredSeverities
  };
});

// Calculate summary statistics
const totalCves = filteredWeeklyData.reduce((sum, week) => sum + (week.total || 0), 0);
const activeWeeks = filteredWeeklyData.filter(week => week.total > 0).length;

// Show processing summary
display(html`<div style="background: #e8f5e8; border: 1px solid #4caf50; border-radius: 6px; padding: 15px; margin: 20px 0;">
  <strong>✅ Data Processing Complete</strong><br/>
  <div style="font-size: 14px; color: #2e7d32; margin-top: 8px;">
    • Processed <strong>${parsedProjects.length} projects</strong> with standardized names<br/>
    • Found <strong>${totalCves} CVEs</strong> across <strong>${selectedProjectKeys.length} matching projects</strong><br/>
    • Loaded CVE data from 2023-2025 for analysis
    ${unknownProjects.length > 0 ? `<br/>• ${unknownProjects.length} unknown projects using fallback patterns` : ''}
  </div>
</div>`);

filteredWeeklyData
```

```js
// Project color scheme
const projectColors = {
  nginx: "#e41a1c", apache: "#ff7f00", nodejs: "#4daf4a", python3: "#a65628",
  golang: "#66c2a5", java: "#8da0cb", php: "#f781bf", redis: "#e5c494",
  postgresql: "#b3b3b3", mysql: "#fc8d62", docker: "#fb8072", kubernetes: "#80b1d3",
  bash: "#80b1d3", busybox: "#fb8072", tomcat: "#ffff33", perl: "#999999",
  fastapi: "#e78ac3", django: "#a6d854", flask: "#ffd92f", dotnet: "#8da0cb",
  maven: "#d9d9d9", gradle: "#bc80bd", openssl: "#e78ac3", curl: "#a6d854",
  ubuntu: "#ffffb3", debian: "#fdb462", alpine: "#ccebc5", bun: "#984ea3",
  deno: "#377eb8", fluentbit: "#bebada", rabbitmq: "#fccde5", memcached: "#ccebc5"
};
```

## CVE Timeline Chart

CVE publication timeline showing vulnerability trends across your selected projects.

```js
function createTimelineChart(data, projectKeys, trackedProjectsConfig, projectColorsMap, {width}) {
  // Handle empty data case
  if (!data || data.length === 0 || !projectKeys || projectKeys.length === 0) {
    return html`<div style="background: #fff3cd; border: 1px solid #ffc107; border-radius: 6px; padding: 20px; text-align: center;">
      <strong>⚠️ No Data to Display</strong><br/>
      <div style="margin-top: 10px; font-size: 14px; color: #856404;">
        ${!projectKeys || projectKeys.length === 0 
          ? 'No matching projects found in the dataset. Try different project names or check the debug info above.' 
          : 'No CVE data available for the selected time period.'}
      </div>
    </div>`;
  }

  const barData = [];
  
  data.forEach(week => {
    projectKeys.forEach(project => {
      const count = week.projects?.[project] || 0;
      if (count > 0) {
        barData.push({
          week: week.week,
          startDate: week.startDate,
          project: project,
          projectName: trackedProjectsConfig[project]?.name || project,
          count: count,
          total: week.total || 0,
          severities: week.severities || {}
        });
      }
    });
  });

  // Handle case where we have data but no matching projects
  if (barData.length === 0) {
    return html`<div style="background: #fff3cd; border: 1px solid #ffc107; border-radius: 6px; padding: 20px; text-align: center;">
      <strong>⚠️ No Matching CVE Data</strong><br/>
      <div style="margin-top: 10px; font-size: 14px; color: #856404;">
        The dataset contains CVE data, but none match your selected projects.<br/>
        Check the debug info above to see available vs selected projects.
      </div>
    </div>`;
  }

  return Plot.plot({
    title: `CVE Publications Over Time (${projectKeys.length} projects)`,
    width,
    height: 400,
    marginBottom: 60,
    x: {
      label: "Year",
      tickFormat: (d) => d.split('-W')[0],
      tickRotate: 0,
      ticks: (() => {
        const yearStarts = new Map();
        data.forEach(d => {
          const year = d.week.split('-W')[0];
          if (!yearStarts.has(year)) {
            yearStarts.set(year, d.week);
          }
        });
        return Array.from(yearStarts.values());
      })()
    },
    y: {
      grid: true, 
      label: "CVEs Published"
    },
    color: {
      domain: projectKeys,
      range: projectKeys.map(p => projectColorsMap[p] || "#666"),
      legend: true
    },
    marks: [
      Plot.rectY(barData, {
        x: "week",
        y: "count", 
        fill: "project",
        tip: true,
        title: (d) => `${d.week} (${d.startDate})\n${d.projectName}: ${d.count} CVEs\nWeek total: ${d.total} CVEs`
      }),
      Plot.ruleY([0])
    ]
  });
}
```


<div class="grid grid-cols-1" style="margin-bottom: 2rem;">
  <div class="card">
    ${resize((width) => createTimelineChart(filteredWeeklyData, selectedProjectKeys, trackedProjects, projectColors, {width}))}
  </div>
</div>

## Severity Distribution Chart

CVE severity breakdown over time. Choose which severity levels to display:

```js
// Interactive severity filter
const severityFilter = Inputs.checkbox(
  ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"], 
  {
    label: "Show Severity Levels:",
    value: ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"],
    format: x => x
  }
);
const selectedSeverities = Generators.input(severityFilter);
```

${severityFilter}

```js
function createSeverityChart(data, selectedSeverities, {width}) {
  const severityData = [];
  
  data.forEach(week => {
    selectedSeverities.forEach(severity => {
      const count = week.severities?.[severity] || 0;
      if (count > 0) {
        severityData.push({
          week: week.week,
          startDate: week.startDate,
          severity: severity,
          count: count,
          total: Object.values(week.severities || {}).reduce((a, b) => a + b, 0)
        });
      }
    });
  });

  const severityColors = {
    CRITICAL: "#8B0000",
    HIGH: "#FF0000", 
    MEDIUM: "#FFA500",
    LOW: "#90EE90",
    UNKNOWN: "#888888"
  };

  return Plot.plot({
    title: `CVE Severity Distribution${selectedSeverities.length < 5 ? ` - ${selectedSeverities.join(', ')}` : ''}`,
    width,
    height: 400,
    marginBottom: 60,
    x: {
      label: "Year",
      tickFormat: (d) => d.split('-W')[0],
      tickRotate: 0,
      ticks: (() => {
        const yearStarts = new Map();
        data.forEach(d => {
          const year = d.week.split('-W')[0];
          if (!yearStarts.has(year)) {
            yearStarts.set(year, d.week);
          }
        });
        return Array.from(yearStarts.values());
      })()
    },
    y: {
      grid: true, 
      label: "CVEs Published"
    },
    color: {
      domain: selectedSeverities,
      range: selectedSeverities.map(s => severityColors[s]),
      legend: true
    },
    marks: [
      Plot.rectY(severityData, {
        x: "week",
        y: "count", 
        fill: "severity",
        tip: true,
        title: (d) => `${d.week} (${d.startDate})\n${d.severity}: ${d.count} CVEs\nWeek total: ${d.total} CVEs`
      }),
      Plot.ruleY([0])
    ]
  });
}
```

<div class="grid grid-cols-1">
  <div class="card">
    ${resize((width) => createSeverityChart(filteredWeeklyData, selectedSeverities, {width}))}
  </div>
</div>

## CVE Details

Browse all CVEs found for your selected projects:

```js
// Load detailed CVE timeline data from multiple years
const timelineData2023 = await FileAttachment("data/cache/cve-timeline-2023.json").json();
const timelineData2024 = await FileAttachment("data/cache/cve-timeline-2024.json").json();
const timelineData2025 = await FileAttachment("data/cache/cve-timeline-2025.json").json();

// Combine all timeline data
const allTimelineData = [
  ...timelineData2023,
  ...timelineData2024, 
  ...timelineData2025
];

// Filter CVE details to only include selected projects
const cveDetails = allTimelineData
  .filter(cve => selectedProjectKeys.includes(cve.project))
  .map(cve => ({
    ...cve,
    // Ensure consistent date format
    date: cve.date,
    // Convert score to display format
    scoreDisplay: cve.score ? cve.score.toFixed(1) : 'N/A',
    // Truncate description for table display
    shortDescription: cve.description.length > 80 
      ? cve.description.substring(0, 80) + '...' 
      : cve.description
  }))
  .sort((a, b) => {
    // Sort by date (most recent first) then by severity
    const dateCompare = new Date(b.date) - new Date(a.date);
    if (dateCompare !== 0) return dateCompare;
    
    const severityOrder = { 'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'UNKNOWN': 4 };
    return severityOrder[a.severity] - severityOrder[b.severity];
  });

cveDetails
```

<div class="grid grid-cols-1">
  <div class="card">
    ${Inputs.table(cveDetails, {
      columns: [
        "cve",
        "projectName",
        "severity", 
        "date",
        "scoreDisplay",
        "shortDescription"
      ],
      header: {
        cve: "CVE ID",
        projectName: "Project",
        severity: "Severity",
        date: "Published",
        scoreDisplay: "CVSS Score",
        shortDescription: "Description"
      },
      width: {
        cve: 140,
        projectName: 120,
        severity: 90,
        date: 100,
        scoreDisplay: 80,
        shortDescription: 400
      },
      format: {
        cve: (d) => html`<code style="font-size: 12px; background: #f8f9fa; padding: 2px 4px; border-radius: 3px;">${d}</code>`,
        severity: (d) => html`<span style="
          padding: 3px 8px; 
          border-radius: 4px; 
          font-size: 11px; 
          font-weight: bold;
          color: white;
          background: ${d === 'CRITICAL' ? '#8B0000' : 
                       d === 'HIGH' ? '#FF0000' : 
                       d === 'MEDIUM' ? '#FFA500' : 
                       d === 'LOW' ? '#90EE90' : '#888888'};
        ">${d}</span>`,
        date: (d) => new Date(d).toLocaleDateString(),
        scoreDisplay: (d) => html`<span style="font-family: monospace; font-weight: bold;">${d}</span>`
      },
      sort: "date",
      reverse: true
    })}
  </div>
</div>

## Summary

Analysis complete: **${selectedProjectKeys.length} projects** with **${totalCves} total CVEs** from 2023-2025.

To analyze different projects, edit the project list in Step 1 and the notebook will automatically update.