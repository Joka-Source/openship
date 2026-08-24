/**
 * Sanitize untrusted HTML email bodies before rendering them in the
 * client. The read pane injects the result with `shadowRoot.innerHTML`
 * in the app origin with no CSP, so this module is the only thing
 * standing between an inbound message and script execution: it must
 * handle XSS-class threats (script tags, on* attributes, javascript:
 * URLs) and it must not disagree with the browser about tree shape.
 *
 * `blockRemoteImages` implements the "block remote images" preference,
 * which is a privacy control rather than an XSS one.
 */

import * as cheerio from 'cheerio';
import type { Declaration } from 'postcss';
import safeParser from 'postcss-safe-parser';
import selectorParser from 'postcss-selector-parser';
import sanitizeHtml from 'sanitize-html';

const ALLOWED_TAGS = [
  ...sanitizeHtml.defaults.allowedTags,
  'img',
  'span',
  'div',
  'h1',
  'h2',
  'h3',
  'h4',
  'h5',
  'h6',
  'style',
];

const MESSAGE_SCOPE_ATTRIBUTE = 'data-mail-content-fit';
const SAFE_CSS_AT_RULES = new Set(['media']);
const BLOCKED_CSS_PROPERTIES =
  /^(?:-moz-binding|-webkit-user-modify|all|animation(?:-.+)?|backdrop-filter|background-attachment|behavior|clip(?:-.+)?|contain|content|counter(?:-.+)?|cursor|filter|inset(?:-.+)?|isolation|left|mask(?:-.+)?|mix-blend-mode|perspective(?:-.+)?|pointer-events|position|right|rotate|scale|top|transform(?:-.+)?|transition(?:-.+)?|translate|will-change|z-index|zoom)$/i;
const UNSAFE_CSS_VALUE =
  /(?:expression\s*\(|javascript\s*:|vbscript\s*:|file\s*:|blob\s*:|-moz-binding|behavior\s*\(|var\s*\()/i;
const CSS_URL_VALUE = /url\(\s*(['"]?)(.*?)\1\s*\)/gi;
const SAFE_CSS_URL = /^(?:https?:\/\/|\/\/|cid:|data:image\/(?:gif|png|jpe?g|webp|avif);)/i;

function decodeCssEscapes(value: string): string {
  return value.replace(/\\([0-9a-f]{1,6}\s?|.)/gi, (_match, escaped: string) => {
    const hex = escaped.trim();
    if (/^[0-9a-f]+$/i.test(hex)) {
      const codePoint = Number.parseInt(hex, 16);
      return codePoint > 0 && codePoint <= 0x10ffff ? String.fromCodePoint(codePoint) : '';
    }
    return escaped;
  });
}

function normalizedCssValue(value: string): string {
  return decodeCssEscapes(value).replace(/\/\*[\s\S]*?\*\//g, '');
}

function isSafeCssDeclaration(declaration: Declaration): boolean {
  const property = decodeCssEscapes(declaration.prop).trim().toLowerCase();
  if (!property || property.startsWith('--') || declaration.prop.includes('\\')) return false;
  if (BLOCKED_CSS_PROPERTIES.test(property)) return false;

  const value = normalizedCssValue(declaration.value);
  if (UNSAFE_CSS_VALUE.test(value) || declaration.value.includes('\\')) return false;

  for (const match of value.matchAll(CSS_URL_VALUE)) {
    if (!SAFE_CSS_URL.test((match[2] ?? '').trim())) return false;
  }

  return true;
}

function scopeCssSelectors(selector: string): string | null {
  try {
    const scoped = selectorParser((selectors) => {
      selectors.each((candidate) => {
        let unsafe = false;
        candidate.walkPseudos((pseudo) => {
          const value = decodeCssEscapes(pseudo.value).toLowerCase();
          if (
            value === ':host' ||
            value === ':host-context' ||
            value === '::part' ||
            value === '::slotted'
          ) {
            unsafe = true;
          }
        });

        if (unsafe) {
          candidate.remove();
          return;
        }

        while (candidate.nodes.length > 0) {
          const first = candidate.at(0);
          const isDocumentRoot =
            (first?.type === 'tag' && ['html', 'body'].includes(first.value.toLowerCase())) ||
            (first?.type === 'pseudo' && first.value.toLowerCase() === ':root');
          if (!isDocumentRoot) break;

          first.remove();
          if (candidate.at(0)?.type === 'combinator') candidate.at(0)?.remove();
        }

        const first = candidate.at(0);
        if (selectorParser.isAttribute(first) && first.attribute === MESSAGE_SCOPE_ATTRIBUTE) {
          return;
        }

        const scope = selectorParser.attribute({
          attribute: MESSAGE_SCOPE_ATTRIBUTE,
          value: undefined,
          raws: {},
        });
        if (candidate.nodes.length === 0) {
          candidate.append(scope);
        } else {
          candidate.prepend(selectorParser.combinator({ value: ' ' }));
          candidate.prepend(scope);
        }
      });
    }).processSync(selector);

    return scoped.trim() || null;
  } catch {
    return null;
  }
}

function sanitizeStyleSheet(css: string): string {
  let root;
  try {
    root = safeParser(css, { from: undefined });
  } catch {
    return '';
  }

  root.walkComments((comment) => {
    comment.remove();
  });
  root.walkAtRules((atRule) => {
    const name = decodeCssEscapes(atRule.name).toLowerCase();
    const params = normalizedCssValue(atRule.params);
    if (!SAFE_CSS_AT_RULES.has(name) || UNSAFE_CSS_VALUE.test(params) || /url\s*\(/i.test(params)) {
      atRule.remove();
    }
  });
  root.walkRules((rule) => {
    const scoped = scopeCssSelectors(rule.selector);
    if (scoped) rule.selector = scoped;
    else rule.remove();
  });
  root.walkDecls((declaration) => {
    if (!isSafeCssDeclaration(declaration)) declaration.remove();
  });

  return root.toString().trim();
}

function sanitizeInlineStyle(style: string): string {
  let root;
  try {
    root = safeParser(`[data-mail-inline]{${style}}`, { from: undefined });
  } catch {
    return '';
  }

  const declarations: string[] = [];
  root.walkDecls((declaration) => {
    if (isSafeCssDeclaration(declaration)) declarations.push(declaration.toString());
  });
  return declarations.join(';');
}

function sanitizeMailStyles(input: string): string {
  const $ = cheerio.load(input, null, false);

  $('style').each((_i, element) => {
    const node = $(element);
    const css = sanitizeStyleSheet(node.text());
    if (css) node.text(css);
    else node.remove();
  });

  $('[style]').each((_i, element) => {
    const node = $(element);
    const style = sanitizeInlineStyle(node.attr('style') ?? '');
    if (style) node.attr('style', style);
    else node.removeAttr('style');
  });

  return $.html();
}

/**
 * Re-parse with parse5 (via cheerio) and re-serialize before sanitizing.
 *
 * sanitize-html parses with htmlparser2, which disagrees with the HTML
 * spec on several constructs. The one that mattered: in RAWTEXT content
 * `</style/` is a valid end tag to a browser but not to htmlparser2, so
 * a sender could write `<style></style/><img src=x onerror=...>` and
 * htmlparser2 would treat the payload as inert CSS text and emit it
 * verbatim — while the browser closed <style> and ran it. Foreign
 * content (<svg>, <math>) and mis-nesting have the same failure mode.
 *
 * parse5 is spec-compliant, so normalizing first guarantees the
 * sanitizer inspects the same tree the browser will build. Keep this in
 * front of every sanitize call; the parsed stylesheet filter handles CSS,
 * while this normalization closes the parser-confusion class.
 */
function normalizeToSpecTree(input: string): string {
  return cheerio.load(input, null, false).html();
}

export function sanitizeMailHtml(input: string): string {
  return sanitizeHtml(sanitizeMailStyles(normalizeToSpecTree(input)), {
    allowedTags: ALLOWED_TAGS,
    // The stylesheet has already been parsed, scoped, and declaration-filtered
    // by sanitizeMailStyles above. Acknowledge that explicit boundary instead
    // of logging sanitize-html's generic <style> warning for every message.
    allowVulnerableTags: true,
    allowedAttributes: {
      '*': ['style', 'class', 'id', 'align', 'width', 'height', 'bgcolor'],
      a: ['href', 'name', 'target', 'rel'],
      img: ['src', 'srcset', 'alt', 'title', 'width', 'height'],
    },
    // `cid:`/`data:` are how inline attachment images arrive, so they stay for
    // src. A link never needs them: `data:text/html` in an href is a navigable
    // XSS primitive (browsers block top-level data: today, but that is their
    // mitigation, not ours) and `cid:` in an href is meaningless.
    allowedSchemes: ['http', 'https', 'mailto', 'cid', 'data'],
    allowedSchemesByTag: { a: ['http', 'https', 'mailto'] },
    allowProtocolRelative: false,
    transformTags: {
      a: (tagName, attribs) => ({
        tagName,
        attribs: { ...attribs, target: '_blank', rel: 'noopener noreferrer' },
      }),
    },
  });
}

const TRANSPARENT_GIF =
  'data:image/gif;base64,R0lGODlhAQABAAAAACH5BAEKAAEALAAAAAABAAEAAAICTAEAOw==';

// Anything that leaves the machine on render. `cid:` (inline attachment)
// and `data:` stay - they cost the sender no signal.
const REMOTE_URL = /^(?:https?:)?\/\//i;
const CSS_URL = /url\(\s*(['"]?)([^'")]*)\1\s*\)/gi;

function stripRemoteCssUrls(css: string): string {
  const stripped = css.replace(CSS_URL, (match, _quote, url: string) =>
    REMOTE_URL.test(url.trim()) ? 'none' : match,
  );
  const normalized = normalizedCssValue(stripped);
  if (/(?:-webkit-)?image-set\([^)]*(?:https?:)?\/\//i.test(normalized)) return '';
  if (/url\(\s*(['"]?)(?:https?:)?\/\//i.test(normalized)) return '';
  if (/(?:https?:)?\/\//i.test(normalized)) return '';
  return stripped;
}

function hasRemoteCandidate(srcset: string): boolean {
  return srcset
    .split(',')
    .some((candidate) => REMOTE_URL.test((candidate.trim().split(/\s+/)[0] ?? '').trim()));
}

/**
 * Neutralize every remote fetch a message body can trigger, for the
 * "block remote images" preference. Regex over `<img src>` alone is not
 * enough - `srcset` and CSS `url()` in a style attribute both fetch, and
 * both used to load with the setting on and no warning banner, handing
 * the sender the reader's IP, user-agent and open time.
 *
 * Expects already-sanitized HTML: it re-parses, so it must not be the
 * thing deciding what tags are safe.
 */
export function blockRemoteImages(html: string): { html: string; blocked: boolean } {
  const $ = cheerio.load(html, null, false);
  let blocked = false;

  $('img').each((_i, el) => {
    const img = $(el);

    const src = img.attr('src');
    if (src && REMOTE_URL.test(src.trim())) {
      img.attr('src', TRANSPARENT_GIF);
      blocked = true;
    }

    const srcset = img.attr('srcset');
    if (srcset && hasRemoteCandidate(srcset)) {
      img.removeAttr('srcset');
      blocked = true;
    }
  });

  $('[style]').each((_i, el) => {
    const node = $(el);
    const style = node.attr('style') ?? '';
    const stripped = stripRemoteCssUrls(style);
    if (stripped !== style) {
      node.attr('style', stripped);
      blocked = true;
    }
  });

  $('style').each((_i, el) => {
    const node = $(el);
    let root;
    try {
      root = safeParser(node.text(), { from: undefined });
    } catch {
      node.remove();
      blocked = true;
      return;
    }

    root.walkDecls((declaration) => {
      const stripped = stripRemoteCssUrls(declaration.value);
      if (stripped === declaration.value) return;

      blocked = true;
      if (stripped) declaration.value = stripped;
      else declaration.remove();
    });
    node.text(root.toString());
  });

  return { html: $.html(), blocked };
}
