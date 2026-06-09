// @ts-check
const config = {
  title: 'Anomaly Detection Atlas',
  tagline: 'A vendor-neutral reference for statistical anomalies and observable security telemetry.',
  favicon: 'img/favicon.svg',

  url: 'https://anpa1200.github.io',
  baseUrl: '/anomaly-detection-atlas/',
  organizationName: 'anpa1200',
  projectName: 'anomaly-detection-atlas',

  headTags: [
    {
      tagName: 'script',
      attributes: {
        async: 'true',
        src: 'https://www.googletagmanager.com/gtag/js?id=G-TMTG21RVHM',
      },
    },
    {
      tagName: 'script',
      attributes: {},
      innerHTML: `
        window.dataLayer = window.dataLayer || [];
        function gtag(){dataLayer.push(arguments);}
        gtag('js', new Date());
        gtag('config', 'G-TMTG21RVHM');
      `,
    },
  ],

  deploymentBranch: 'gh-pages',
  trailingSlash: true,
  onBrokenLinks: 'warn',
  markdown: {
    hooks: {
      onBrokenMarkdownLinks: 'warn',
    },
  },
  i18n: {
    defaultLocale: 'en',
    locales: ['en'],
  },

  presets: [
    [
      'classic',
      {
        docs: {
          path: 'docs',
          routeBasePath: '/',
          sidebarPath: require.resolve('./sidebars.js'),
        },
        blog: false,
        theme: {
          customCss: require.resolve('./src/css/custom.css'),
        },
      },
    ],
  ],

  themeConfig: {
    image: 'img/social-card.svg',
    metadata: [
      {
        name: 'keywords',
        content:
          'anomaly detection, statistics, outliers, security telemetry, log sources, detection engineering',
      },
    ],
    navbar: {
      title: 'Anomaly Detection Atlas',
      logo: {
        alt: 'Anomaly Detection Atlas',
        src: 'img/logo.svg',
      },
      items: [
        { to: '/threatmapper-integration', label: 'ThreatMapper Integration', position: 'left' },
        { to: '/attack-activity-log-source-catalog', label: 'ATT&CK Activities', position: 'left' },
        { to: '/attack-basic-detection-rule-catalog', label: 'Basic Rules', position: 'left' },
        { to: '/attack-statistical-anomaly-mapping', label: 'Anomaly Mappings', position: 'left' },
        { to: '/statistical-anomaly-taxonomy', label: 'Anomaly Taxonomy', position: 'left' },
        { to: '/security-log-source-taxonomy', label: 'Log Sources', position: 'left' },
        {
          href: 'https://github.com/anpa1200/threatmapper/tree/main/anomaly_detection',
          label: 'GitHub',
          position: 'right',
        },
        {
          href: 'https://medium.com/@1200km',
          label: 'Medium',
          position: 'right',
        },
      ],
    },
    footer: {
      style: 'dark',
      links: [
        {
          title: 'References',
          items: [
            { label: 'ATT&CK Activities', to: '/attack-activity-log-source-catalog' },
            { label: 'Basic Detection Rules', to: '/attack-basic-detection-rule-catalog' },
            { label: 'Activity-Anomaly Mappings', to: '/attack-statistical-anomaly-mapping' },
            { label: 'Statistical Anomalies', to: '/statistical-anomaly-taxonomy' },
            { label: 'Security Log Sources', to: '/security-log-source-taxonomy' },
          ],
        },
        {
          title: 'Project',
          items: [
            {
              label: 'ThreatMapper',
              href: 'https://github.com/anpa1200/threatmapper',
            },
            {
              label: 'Medium',
              href: 'https://medium.com/@1200km',
            },
          ],
        },
      ],
      copyright: `Copyright © ${new Date().getFullYear()} Andrey Pautov. Anomaly Detection Atlas.`,
    },
    colorMode: {
      defaultMode: 'dark',
      respectPrefersColorScheme: true,
    },
    prism: {
      theme: require('prism-react-renderer').themes.github,
      darkTheme: require('prism-react-renderer').themes.dracula,
    },
  },
};

module.exports = config;
