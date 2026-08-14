// @ts-check
const {loadDateManifest} = require('./seo/date-manifest.cjs');

const seoDateManifest = loadDateManifest(__dirname);

const config = {
  title: '1200km',
  tagline: 'A vendor-neutral reference for statistical anomalies and observable security telemetry.',
  favicon: 'img/favicon.svg',

  url: 'https://1200km.com',
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
  onBrokenLinks: 'throw',
  onBrokenAnchors: 'throw',
  markdown: {
    hooks: {
      onBrokenMarkdownLinks: 'throw',
    },
  },
  i18n: {
    defaultLocale: 'en',
    locales: ['en'],
  },

  plugins: ['./seo-metadata-plugin.cjs'],

  presets: [
    [
      'classic',
      {
        docs: {
          path: 'docs',
          routeBasePath: '/',
          sidebarPath: require.resolve('./sidebars.js'),
          rehypePlugins: [[require('./src/rehype/explicitAnchors'), {}]],
        },
        blog: false,
        sitemap: {
          lastmod: null,
          createSitemapItems: async ({defaultCreateSitemapItems, ...params}) => {
            const items = await defaultCreateSitemapItems(params);
            return items.map((item) => {
              const pathname = new URL(item.url).pathname;
              const dateRecord = seoDateManifest.routes[pathname];
              if (!dateRecord) throw new Error(`Missing sitemap date for ${pathname}`);
              return {...item, lastmod: dateRecord.lastModified};
            });
          },
        },
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
        property: 'og:site_name',
        content: '1200km — Andrey Pautov Security Research',
      },
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
        { to: '/adversarygraph-integration', label: 'AdversaryGraph Integration', position: 'left' },
        { to: '/attack-activity-log-source-catalog', label: 'ATT&CK Activities', position: 'left' },
        { to: '/attack-basic-detection-rule-catalog', label: 'Basic Rules', position: 'left' },
        { to: '/attack-statistical-anomaly-mapping', label: 'Anomaly Mappings', position: 'left' },
        { to: '/statistical-anomaly-taxonomy', label: 'Anomaly Taxonomy', position: 'left' },
        { to: '/security-log-source-taxonomy', label: 'Log Sources', position: 'left' },
        {
          href: 'https://github.com/anpa1200/adversarygraph/tree/main/anomaly_detection',
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
              label: 'AdversaryGraph',
              href: 'https://github.com/anpa1200/adversarygraph',
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
