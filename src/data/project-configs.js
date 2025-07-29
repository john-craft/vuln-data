/**
 * Project configurations for CVE analysis
 * Browser-compatible module that defines tracked projects with their CPE patterns and description keywords
 */

export const TRACKED_PROJECTS = {
  // Web Servers & Reverse Proxies
  nginx: {
    name: 'NGINX',
    cpePatterns: [
      'cpe:2.3:a:f5:nginx_open_source:*'
    ],
    descriptionKeywords: [
      'nginx open source',
      'nginx plus'
    ]
  },
  apache: {
    name: 'Apache HTTP Server',
    cpePatterns: [
      'cpe:2.3:a:apache:http_server:*'
    ],
    descriptionKeywords: [
      'apache http server',
      'apache httpd'
    ]
  },
  tomcat: {
    name: 'Apache Tomcat',
    cpePatterns: [
      'cpe:2.3:a:apache:tomcat:*'
    ],
    descriptionKeywords: [
      'apache tomcat'
    ]
  },

  // JavaScript Runtimes
  nodejs: {
    name: 'Node.js',
    cpePatterns: [
      'cpe:2.3:a:nodejs:node.js:*'
    ],
    descriptionKeywords: [
      'node.js',
      'nodejs'
    ]
  },
  bun: {
    name: 'Bun',
    cpePatterns: [
      'cpe:2.3:a:oven:bun:*'
    ],
    descriptionKeywords: [
      'bun javascript runtime',
      'bun runtime'
    ]
  },
  deno: {
    name: 'Deno',
    cpePatterns: [
      'cpe:2.3:a:deno:deno:*'
    ],
    descriptionKeywords: [
      'deno runtime',
      'deno is a'
    ]
  },

  // Programming Languages
  python3: {
    name: 'Python',
    cpePatterns: [
      'cpe:2.3:a:python:python:*'
    ],
    descriptionKeywords: [
      'python programming language',
      'cpython'
    ]
  },
  php: {
    name: 'PHP',
    cpePatterns: [
      'cpe:2.3:a:php:php:*'
    ],
    descriptionKeywords: [
      'php programming language',
      'php hypertext preprocessor'
    ]
  },
  perl: {
    name: 'Perl',
    cpePatterns: [
      'cpe:2.3:a:perl:perl:*'
    ],
    descriptionKeywords: [
      'perl programming language'
    ]
  },
  golang: {
    name: 'Go',
    cpePatterns: [
      'cpe:2.3:a:golang:go:*'
    ],
    descriptionKeywords: [
      'go programming language',
      'golang'
    ]
  },
  java: {
    name: 'Java',
    cpePatterns: [
      'cpe:2.3:a:oracle:jdk:*',
      'cpe:2.3:a:oracle:openjdk:*'
    ],
    descriptionKeywords: [
      'oracle java',
      'openjdk'
    ]
  },
  dotnet: {
    name: '.NET',
    cpePatterns: [
      'cpe:2.3:a:microsoft:.net:*',
      'cpe:2.3:a:microsoft:.net_core:*'
    ],
    descriptionKeywords: [
      'microsoft .net',
      'dotnet core'
    ]
  },

  // Web Frameworks
  fastapi: {
    name: 'FastAPI',
    cpePatterns: [
      'cpe:2.3:a:tiangolo:fastapi:*'
    ],
    descriptionKeywords: [
      'fastapi framework',
      'fastapi is a'
    ]
  },
  django: {
    name: 'Django',
    cpePatterns: [
      'cpe:2.3:a:djangoproject:django:*'
    ],
    descriptionKeywords: [
      'django framework',
      'django web framework'
    ]
  },
  flask: {
    name: 'Flask',
    cpePatterns: [
      'cpe:2.3:a:palletsprojects:flask:*'
    ],
    descriptionKeywords: [
      'flask framework',
      'flask web framework'
    ]
  },

  // Databases & Caching
  redis: {
    name: 'Redis',
    cpePatterns: [
      'cpe:2.3:a:redis:redis:*'
    ],
    descriptionKeywords: [
      'redis is an open source',
      'redis is a'
    ]
  },
  postgresql: {
    name: 'PostgreSQL',
    cpePatterns: [
      'cpe:2.3:a:postgresql:postgresql:*'
    ],
    descriptionKeywords: [
      'postgresql database'
    ]
  },
  memcached: {
    name: 'Memcached',
    cpePatterns: [
      'cpe:2.3:a:memcached:memcached:*'
    ],
    descriptionKeywords: [
      'memcached caching system'
    ]
  },
  mysql: {
    name: 'MySQL',
    cpePatterns: [
      'cpe:2.3:a:mysql:mysql:*',
      'cpe:2.3:a:oracle:mysql:*'
    ],
    descriptionKeywords: [
      'mysql database',
      'mysql server'
    ]
  },

  // Message Queues
  rabbitmq: {
    name: 'RabbitMQ',
    cpePatterns: [
      'cpe:2.3:a:rabbitmq:rabbitmq:*',
      'cpe:2.3:a:pivotal:rabbitmq:*'
    ],
    descriptionKeywords: [
      'rabbitmq message broker'
    ]
  },

  // Build Tools
  maven: {
    name: 'Apache Maven',
    cpePatterns: [
      'cpe:2.3:a:apache:maven:*'
    ],
    descriptionKeywords: [
      'apache maven',
      'maven build tool'
    ]
  },
  gradle: {
    name: 'Gradle',
    cpePatterns: [
      'cpe:2.3:a:gradle:gradle:*'
    ],
    descriptionKeywords: [
      'gradle build tool'
    ]
  },

  // System Tools
  busybox: {
    name: 'BusyBox',
    cpePatterns: [
      'cpe:2.3:a:busybox:busybox:*'
    ],
    descriptionKeywords: [
      'busybox utilities'
    ]
  },
  bash: {
    name: 'Bash',
    cpePatterns: [
      'cpe:2.3:a:gnu:bash:*'
    ],
    descriptionKeywords: [
      'bash shell',
      'gnu bash'
    ]
  },
  fluentbit: {
    name: 'Fluent Bit',
    cpePatterns: [
      'cpe:2.3:a:fluentbit:fluent_bit:*'
    ],
    descriptionKeywords: [
      'fluent bit',
      'fluent-bit'
    ]
  },
  docker: {
    name: 'Docker',
    cpePatterns: [
      'cpe:2.3:a:docker:docker:*'
    ],
    descriptionKeywords: [
      'docker container',
      'docker engine'
    ]
  },
  kubernetes: {
    name: 'Kubernetes',
    cpePatterns: [
      'cpe:2.3:a:kubernetes:kubernetes:*'
    ],
    descriptionKeywords: [
      'kubernetes orchestration',
      'kubernetes cluster',
      'k8s'
    ]
  },
  openssl: {
    name: 'OpenSSL',
    cpePatterns: [
      'cpe:2.3:a:openssl:openssl:*'
    ],
    descriptionKeywords: [
      'openssl cryptography',
      'openssl ssl'
    ]
  },
  curl: {
    name: 'cURL',
    cpePatterns: [
      'cpe:2.3:a:haxx:curl:*',
      'cpe:2.3:a:haxx:libcurl:*'
    ],
    descriptionKeywords: [
      'curl library',
      'libcurl'
    ]
  },

  // Operating Systems
  debian: {
    name: 'Debian Linux',
    cpePatterns: [
      'cpe:2.3:o:debian:debian_linux:*'
    ],
    descriptionKeywords: [
      'debian linux',
      'debian operating system'
    ]
  },
  alpine: {
    name: 'Alpine Linux',
    cpePatterns: [
      'cpe:2.3:o:alpinelinux:alpine_linux:*'
    ],
    descriptionKeywords: [
      'alpine linux',
      'alpine operating system'
    ]
  },
  ubuntu: {
    name: 'Ubuntu',
    cpePatterns: [
      'cpe:2.3:o:canonical:ubuntu_linux:*'
    ],
    descriptionKeywords: [
      'ubuntu linux',
      'ubuntu operating system'
    ]
  }
};