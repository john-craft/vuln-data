---
theme: dashboard
toc: false
---

# CVE Timeline

<!-- Load the weekly CVE data -->

```js
const weeklyData = await FileAttachment("data/cve-multi-year.json").json();

// Ensure weeklyData is an array
if (!Array.isArray(weeklyData)) {
  throw new Error(`Weekly data should be an array, got ${typeof weeklyData}`);
}

// Get unique projects for color scale
const allProjects = [];
weeklyData.forEach(week => {
  if (week.projects) {
    allProjects.push(...Object.keys(week.projects));
  }
});
const projects = [...new Set(allProjects)];

// Create project color scale with more colors for all projects
const projectColors = {
  // Web Servers
  nginx: "#e41a1c",
  apache: "#ff7f00", 
  tomcat: "#ffff33",
  
  // JavaScript Runtimes
  nodejs: "#4daf4a",
  bun: "#984ea3",
  deno: "#377eb8",
  
  // Programming Languages
  python3: "#a65628",
  php: "#f781bf",
  perl: "#999999",
  golang: "#66c2a5",
  java: "#fc8d62",
  dotnet: "#8da0cb",
  
  // Web Frameworks
  fastapi: "#e78ac3",
  django: "#a6d854",
  flask: "#ffd92f",
  
  // Databases & Caching
  redis: "#e5c494",
  postgresql: "#b3b3b3",
  memcached: "#ccebc5",
  
  // Message Queues & Tools
  rabbitmq: "#fccde5",
  maven: "#d9d9d9",
  gradle: "#bc80bd",
  busybox: "#fb8072",
  bash: "#80b1d3",
  fluentbit: "#bebada",
  
  // Operating Systems
  debian: "#ffffb3",
  alpine: "#fdb462"
};

// Calculate total CVE counts
const totalCves = weeklyData.reduce((sum, week) => sum + (week.total || 0), 0);
const projectTotals = {};
projects.forEach(project => {
  projectTotals[project] = weeklyData.reduce((sum, week) => sum + (week.projects?.[project] || 0), 0);
});
```

<!-- Interactive severity filter controls -->

```js
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

<!-- Chart function definitions -->

```js
function createTimelineChart(data, {width}) {
  // Prepare data for stacked bars - flatten the weekly data by project
  const barData = [];
  
  data.forEach(week => {
    projects.forEach(project => {
      const count = week.projects?.[project] || 0;
      if (count > 0) {
        barData.push({
          week: week.week,
          startDate: week.startDate,
          project: project,
          count: count,
          total: week.total || 0,
          severities: week.severities || {}
        });
      }
    });
  });

  return Plot.plot({
    title: "CVEs published over the weeks (2023-2025)",
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
      label: "CVEs"
    },
    color: {
      domain: projects,
      range: projects.map(p => projectColors[p] || "#666"),
      legend: true
    },
    marks: [
      Plot.rectY(barData, {
        x: "week",
        y: "count", 
        fill: "project",
        tip: true,
        title: (d) => `${d.week} (${d.startDate})\\n${d.project}: ${d.count} CVEs\\nWeek total: ${d.total} CVEs\\nHIGH: ${d.severities.HIGH || 0}, MEDIUM: ${d.severities.MEDIUM || 0}, LOW: ${d.severities.LOW || 0}`
      }),
      Plot.ruleY([0])
    ]
  });
}
```

```js
function createSeverityChart(data, selectedSeverities, {width}) {
  // Prepare data for stacked bars - flatten the weekly data by severity
  const severityData = [];
  
  // Only include selected severity levels
  const severityLevels = selectedSeverities;
  
  data.forEach(week => {
    severityLevels.forEach(severity => {
      const count = week.severities?.[severity] || 0;
      if (count > 0) {
        severityData.push({
          week: week.week,
          startDate: week.startDate,
          severity: severity,
          count: count,
          total: week.total || 0
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
    title: `CVE Severity Distribution by Week (2023-2025)${selectedSeverities.length < 5 ? ` - ${selectedSeverities.join(', ')}` : ''}`,
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
      label: "CVEs"
    },
    color: {
      domain: severityLevels,
      range: severityLevels.map(s => severityColors[s]),
      legend: true
    },
    marks: [
      Plot.rectY(severityData, {
        x: "week",
        y: "count", 
        fill: "severity",
        tip: true,
        title: (d) => `${d.week} (${d.startDate})\\n${d.severity}: ${d.count} CVEs\\nWeek total: ${d.total} CVEs`
      }),
      Plot.ruleY([0])
    ]
  });
}
```

```js
function createWeeklySummary(data) {
  const maxWeek = data.reduce((max, week) => 
    week.total > max.total ? week : max, data[0]);
  
  const activeWeeks = data.filter(w => w.total > 0).length;
  const averagePerWeek = (totalCves / data.length).toFixed(1);
  
  const peakSeverityMix = Object.entries(maxWeek.severities || {})
    .map(([sev, count]) => `${count} ${sev}`)
    .join(', ') || 'No data';

  return {
    mostActiveWeek: `${maxWeek.week} (${maxWeek.total} CVEs)`,
    averagePerWeek: `${averagePerWeek} CVEs`,
    activeWeeks: `${activeWeeks} of ${data.length}`,
    peakSeverityMix: peakSeverityMix
  };
}
```

<!-- Main timeline chart -->

<div class="grid grid-cols-1" style="margin-bottom: 2rem;">
  <div class="card">
    ${resize((width) => createTimelineChart(weeklyData, {width}))}
  </div>
</div>


<!-- Severity chart -->

<div class="grid grid-cols-1">
  <div class="card">
    <div style="margin-bottom: 1rem;">
      ${severityFilter}
    </div>
    ${resize((width) => createSeverityChart(weeklyData, selectedSeverities, {width}))}
  </div>
</div>
