/**
 * Convert empty HTML anchors into an MDX component that participates in
 * Docusaurus' build-time broken-anchor collection.
 *
 * The source catalogs intentionally stay ordinary Markdown so they remain
 * readable outside Docusaurus. rehype-raw has already parsed their
 * `<a id="..."></a>` targets by the time this transformer runs.
 */
function rehypeExplicitAnchors() {
  function transform(node) {
    if (!Array.isArray(node.children)) {
      return;
    }

    node.children = node.children.map((child) => {
      const htmlId = child.properties?.id;
      const isHtmlAnchor =
        child.type === 'element' &&
        child.tagName === 'a' &&
        typeof htmlId === 'string' &&
        htmlId.length > 0 &&
        child.properties?.href === undefined &&
        child.children?.length === 0;

      if (isHtmlAnchor) {
        return {
          type: 'mdxJsxTextElement',
          name: 'ExplicitAnchor',
          attributes: [
            {
              type: 'mdxJsxAttribute',
              name: 'id',
              value: htmlId,
            },
          ],
          children: [],
          position: child.position,
        };
      }

      const idAttribute = child.attributes?.find(
        (attribute) => attribute.type === 'mdxJsxAttribute' && attribute.name === 'id',
      );
      const hasHref = child.attributes?.some(
        (attribute) => attribute.type === 'mdxJsxAttribute' && attribute.name === 'href',
      );
      const isMdxAnchor =
        child.type === 'mdxJsxTextElement' &&
        child.name === 'a' &&
        typeof idAttribute?.value === 'string' &&
        idAttribute.value.length > 0 &&
        !hasHref &&
        child.children?.length === 0;

      if (isMdxAnchor) {
        return {
          ...child,
          name: 'ExplicitAnchor',
        };
      }

      transform(child);
      return child;
    });
  }

  return transform;
}

module.exports = rehypeExplicitAnchors;
