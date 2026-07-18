import React from 'react';
import useBrokenLinks from '@docusaurus/useBrokenLinks';
import MDXComponents from '@theme-original/MDXComponents';

/**
 * Register explicit HTML anchors with Docusaurus' build-time link checker.
 *
 * The activity catalogs use stable, semantic anchors inside table cells (for
 * example, `<a id="password-spraying"></a>`). Docusaurus renders those anchors
 * correctly, but its default MDX component does not report their IDs to the
 * broken-link collector. Keeping the registration here makes every catalog
 * anchor both usable in the browser and verifiable during a production build.
 */
function ExplicitAnchor({id}) {
  const brokenLinks = useBrokenLinks();

  if (id) {
    brokenLinks.collectAnchor(id);
  }

  return <a id={id} aria-hidden="true" />;
}

export default {
  ...MDXComponents,
  ExplicitAnchor,
};
