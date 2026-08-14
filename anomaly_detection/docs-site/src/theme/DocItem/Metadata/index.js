import React from 'react';
import {PageMetadata} from '@docusaurus/theme-common';
import {useDoc} from '@docusaurus/plugin-content-docs/client';
import seoDates from '../../../../seo/dates.json';
import seoMetadata from '../../../../seo/descriptions.json';

export default function DocItemMetadata() {
  const {metadata, frontMatter, assets} = useDoc();
  const pathname = new URL(metadata.permalink, 'https://1200km.com').pathname;
  const description = seoMetadata.descriptions[pathname]
    ?? seoMetadata.descriptions[`${pathname.replace(/\/$/, '')}/`]
    ?? seoMetadata.descriptions[pathname.replace(/\/$/, '')];
  if (!description) {
    throw new Error(`Missing authored SEO description for ${pathname}`);
  }

  const title = `${metadata.title} | 1200km`;
  const lastModified = seoDates.routes[pathname]?.lastModified
    ?? seoDates.routes[`${pathname.replace(/\/$/, '')}/`]?.lastModified;
  if (!/^\d{4}-\d{2}-\d{2}$/.test(lastModified ?? '')) {
    throw new Error(`Missing or malformed SEO last-modified date for ${pathname}`);
  }
  const modifiedTime = `${lastModified}T00:00:00.000Z`;

  return (
    <PageMetadata
      title={metadata.title}
      description={description}
      keywords={frontMatter.keywords}
      image={assets.image ?? frontMatter.image}
    >
      <meta name="twitter:title" content={title} />
      <meta name="twitter:description" content={description} />
      <meta property="article:modified_time" content={modifiedTime} />
    </PageMetadata>
  );
}
