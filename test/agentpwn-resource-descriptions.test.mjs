// Checks how SECURITY.md and mcp-audit.json describe the agentpwn.com pages they link.
// Run from the repository root: node --test

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const security = readFileSync(new URL('../SECURITY.md', import.meta.url), 'utf8');
const audit = JSON.parse(readFileSync(new URL('../mcp-audit.json', import.meta.url), 'utf8'));

// agentpwn.com/tools holds security guides for AI tools and MCP servers, not testing tools.
const GUIDES = /^https:\/\/agentpwn\.com\/tools\/?$/;
// A single test lives at <category>/<n>; it holds one test, not a set of attack patterns.
const TEST_PAGE = /^https:\/\/agentpwn\.com\/attacks\/[a-z0-9-]+\/\d+\/?$/;

// A link to the guides page, a word that files an entry under testing, and a list item.
const GUIDES_LINK = '](https://agentpwn.com/tools)';
const TESTING = /\btest(?:ing|s)?\b/i;
const LIST_ITEM = /^\s*(?:[-*+]|\d+\.) /;
const HEADING = /^ {0,3}#{1,6}(?:\s|$)/;
// The blocks that the text of a list item cannot run into: a heading, a thematic break,
// a code fence, a block quote and an HTML block.
const THEMATIC_BREAK = /^ {0,3}([-*_])[ \t]*(?:\1[ \t]*){2,}$/;
// A backtick fence has no backtick after it. The lookahead takes the whole run of fence
// characters at once, so that check runs once per line and not once per backtick.
const FENCE = /^ {0,3}(?=(`{3,}|~{3,}))\1(?!(?<=`).*`)/;
const BLOCK_QUOTE = /^ {0,3}>/;
const HTML_TAGS =
  'address|article|aside|base|basefont|blockquote|body|caption|center|col|colgroup|dd|details|dialog|dir|div|dl|dt|' +
  'fieldset|figcaption|figure|footer|form|frame|frameset|h[1-6]|head|header|hr|html|iframe|legend|li|link|main|menu|' +
  'menuitem|nav|noframes|ol|optgroup|option|p|param|search|section|summary|table|tbody|td|tfoot|th|thead|title|tr|' +
  'track|ul';
// An HTML block opens with a raw text tag, a comment, a processing instruction, a
// declaration, a CDATA section or one of the block-level tags, not with an inline tag or
// an autolink. Each kind is paired with the line it ends on: a block-level tag runs to
// the next blank line, the others to the line that holds their end.
const HTML_BLOCKS = [
  [/^ {0,3}<(?:pre|script|style|textarea)(?:[ \t>]|$)/i, /<\/(?:pre|script|style|textarea)>/i],
  [/^ {0,3}<!--/, /-->/],
  [/^ {0,3}<\?/, /\?>/],
  [/^ {0,3}<![a-z]/i, />/],
  [/^ {0,3}<!\[CDATA\[/, /\]\]>/],
  [new RegExp(`^ {0,3}</?(?:${HTML_TAGS})(?:[ \\t>]|/>|$)`, 'i'), /^\s*$/],
];

// The last sentence of a paragraph or heading.
const lastSentence = (text) => text.split(/(?<=[.:!?]) /).at(-1);

// Whether an HTML block shows any text on the page. Its tags, comments, processing
// instructions, declarations and CDATA sections show none.
const showsText = (html) =>
  /\S/.test(html.replace(/<!--.*?-->|<\?.*?\?>|<!\[CDATA\[.*?\]\]>|<![a-z][^>]*>|<\/?[a-z][^>]*>/gi, ''));

// Each list item in the text with its lead-in: the last sentence of the nearest
// paragraph, heading or HTML block that shows text above the list.
function listItems(text) {
  const items = [];
  let paragraph = [];
  let leadIn = '';
  let current = null;
  let column = 0;
  let afterBlank = false;
  let fence = null;
  let html = null;
  let raw = [];
  const endParagraph = () => {
    if (paragraph.length > 0) leadIn = lastSentence(paragraph.join(' '));
    paragraph = [];
  };
  // An HTML block that shows no text, such as a comment or a lone <div>, leaves the
  // lead-in above it to the list below it.
  const endHtml = () => {
    if (showsText(raw.join(' '))) leadIn = lastSentence(raw.join(' '));
    raw = [];
  };
  for (const line of text.split('\n')) {
    // The lines of a fenced code block are code, up to the fence that closes it.
    if (fence) {
      if (fence.test(line)) fence = null;
      continue;
    }
    const blank = line.trim() === '';
    // The lines of an HTML block are raw HTML, not list items or headings, up to the
    // line the block ends on. A blank line inside a raw text block or a comment is part
    // of it.
    if (html) {
      if (!blank) raw.push(line.trim());
      if (html.test(line)) {
        html = null;
        endHtml();
      }
      continue;
    }
    // A thematic break written with spaces (- - -) is not a list item.
    const rule = THEMATIC_BREAK.test(line);
    const item = !rule && LIST_ITEM.test(line);
    const heading = HEADING.test(line);
    const opener = FENCE.exec(line);
    const htmlBlock = HTML_BLOCKS.find(([start]) => start.test(line));
    // A line left of the item's text that opens one of those blocks ends the item;
    // the same line indented to the item's text is inside the item.
    const block = heading || rule || opener || BLOCK_QUOTE.test(line) || htmlBlock;
    const indent = line.search(/\S/);
    // A blank line does not end a list item: the item goes on at the next line that is
    // indented to its text.
    if (current && blank) {
      afterBlank = true;
      continue;
    }
    // A non-blank line right after a list item continues that item, unless it is
    // an item itself, or it opens a block outside the item. After a blank line, only a
    // line indented to the item's text is inside the item.
    if (current && !item && (afterBlank ? indent >= column : !(block && indent < column))) {
      current.item += ` ${line.trim()}`;
      afterBlank = false;
      continue;
    }
    current = null;
    if (opener) fence = new RegExp(`^ {0,3}${opener[1][0]}{${opener[1].length},}[ \\t]*$`);
    // An HTML block ends the paragraph above it, and runs to the line its end marker is on.
    if (htmlBlock) {
      endParagraph();
      raw = [line.trim()];
      if (htmlBlock[1].test(line)) endHtml();
      else html = htmlBlock[1];
      continue;
    }
    // A heading is a block of its own: it ends the paragraph above it, and the line
    // below it starts a new one.
    if (heading) {
      leadIn = lastSentence(line.trim());
      paragraph = [];
      continue;
    }
    // A thematic break and a code fence end a paragraph and are not part of one.
    if (!item && !blank && !rule && !opener) {
      paragraph.push(line.trim());
      continue;
    }
    endParagraph();
    if (item) {
      current = { item: line.trim(), leadIn };
      afterBlank = false;
      // The text of an item starts after its marker and one to four spaces.
      const [, marker, gap] = /^(\s*(?:[-*+]|\d+\.))( {1,4}(?=\S))?/.exec(line);
      column = marker.length + (gap ? gap.length : 1);
      items.push(current);
    }
  }
  return items;
}

// Returns the list entries for the guides page whose lead-in presents the list as testing.
function guidesListedAsTesting(text) {
  return listItems(text)
    .filter(({ item, leadIn }) => item.includes(GUIDES_LINK) && TESTING.test(leadIn))
    .map(({ item, leadIn }) => `${leadIn} ${item}`);
}

// Every string value in the configuration, with the key path that leads to it.
function strings(value, path = []) {
  if (typeof value === 'string') return [{ path, value }];
  if (value === null || typeof value !== 'object') return [];
  return Object.entries(value).flatMap(([key, child]) => strings(child, [...path, key]));
}

test('SECURITY.md describes agentpwn.com/tools as security guides, not testing tools', () => {
  const lines = security.split('\n').filter((line) => line.includes(GUIDES_LINK));
  assert.notEqual(lines.length, 0, 'SECURITY.md has no link to agentpwn.com/tools');
  for (const line of lines) {
    assert.doesNotMatch(line, /\btest(?:ing|s)?\b/i, `describes the guides page as testing: ${line}`);
    assert.match(line, /security guides/i, `does not call the page security guides: ${line}`);
  }
});

test('SECURITY.md does not list agentpwn.com/tools under a lead-in about testing', () => {
  assert.deepEqual(guidesListedAsTesting(security), [], 'the guides page is listed as a testing resource');
});

test('the lead-in check flags a guides entry in a list of testing environments', () => {
  const guides = '- [agentpwn.com/tools](https://agentpwn.com/tools) -- security guides for AI tools and MCP servers';
  const honeypot = '- [agentpwn.com](https://agentpwn.com) -- honeypot environment';
  const testing = 'We encourage security testing of MCP deployments. For safe, controlled testing environments:';
  assert.deepEqual(guidesListedAsTesting(`${testing}\n\n${honeypot}\n${guides}\n`), [
    `For safe, controlled testing environments: ${guides}`,
  ]);
  // The continuation line of a wrapped list item belongs to that item, not to a new lead-in.
  const wrapped = '- [agentpwn.com](https://agentpwn.com) -- honeypot environment for testing agent\n  security tools';
  assert.deepEqual(guidesListedAsTesting(`${testing}\n\n${wrapped}\n${guides}\n`), [
    `For safe, controlled testing environments: ${guides}`,
  ]);
  // So does every later continuation line when the item wraps over three lines or more.
  const wrappedThree = '- [agentpwn.com](https://agentpwn.com) -- honeypot environment\n  for testing agent security tools\n  against live attacks';
  assert.deepEqual(guidesListedAsTesting(`${testing}\n\n${wrappedThree}\n${guides}\n`), [
    `For safe, controlled testing environments: ${guides}`,
  ]);
  // The lead-in is the sentence that introduces the list, not the paragraph before it.
  const reading = 'We encourage security testing of MCP deployments. For written guidance:';
  assert.deepEqual(guidesListedAsTesting(`${reading}\n${guides}\n`), []);
  // A heading or a paragraph ends the list above it.
  const sections = `## Security Testing\n\n${honeypot}\n\n## Further Reading\n\n${guides}\n`;
  assert.deepEqual(guidesListedAsTesting(sections), []);
  assert.deepEqual(guidesListedAsTesting(`## Security Testing\n\n${honeypot}\n${guides}\n`), [
    `## Security Testing ${guides}`,
  ]);
  // A heading ends the paragraph above it, and the line below it starts a new one.
  assert.deepEqual(guidesListedAsTesting(`## Security Testing\nFor written guidance:\n${guides}\n`), []);
  assert.deepEqual(guidesListedAsTesting(`Intro on testing\n## Further Reading\n${guides}\n`), []);
  // A heading right after a list item and left of the item's text is not part of that item.
  assert.deepEqual(guidesListedAsTesting(`${reading}\n\n${honeypot}\n## Security Testing\n${guides}\n`), [
    `## Security Testing ${guides}`,
  ]);
  // The same holds for a heading indented by one to three spaces after an item whose text
  // starts at column 4.
  const honeypotAt4 = '-   [agentpwn.com](https://agentpwn.com) -- honeypot environment';
  for (const indent of [' ', '  ', '   ']) {
    assert.deepEqual(guidesListedAsTesting(`${reading}\n\n${honeypotAt4}\n${indent}## Security Testing\n${guides}\n`), [
      `## Security Testing ${guides}`,
    ]);
  }
  // A heading indented to the text of a list item is inside that item.
  const environments = 'For safe, controlled testing environments:';
  assert.deepEqual(guidesListedAsTesting(`${environments}\n\n${honeypot}\n  ## Further Reading\n${guides}\n`), [
    `${environments} ${guides}`,
  ]);
  // A thematic break, code fence, block quote or HTML block right after a list item ends
  // the list, so the sentence written after it introduces the next list.
  for (const block of ['---', '* * *', '```sh\nnpm run audit\n```']) {
    const text = `${reading}\n\n${honeypot}\n${block}\n${environments}\n${guides}\n`;
    assert.deepEqual(guidesListedAsTesting(text), [`${environments} ${guides}`], `the list runs past ${block}`);
  }
  assert.deepEqual(guidesListedAsTesting(`${reading}\n\n${honeypot}\n> ${environments}\n${guides}\n`), [
    `> ${environments} ${guides}`,
  ]);
  assert.deepEqual(guidesListedAsTesting(`${reading}\n\n${honeypot}\n<p>${environments}</p>\n\n${guides}\n`), [
    `<p>${environments}</p> ${guides}`,
  ]);
  // A raw text tag, a comment, a processing instruction, a declaration and a CDATA section
  // open an HTML block as well, so each one ends the list when it is left of the item's
  // text. Each ends on its first line, and the line below it starts a new paragraph.
  const shown = '<pre>x</pre>';
  const hidden = ['<!-- note -->', '<?x ?>', '<!DOCTYPE html>', '<![CDATA[x]]>'];
  for (const html of [shown, ...hidden]) {
    const text = `${reading}\n\n${honeypot}\n${html}\n${environments}\n${guides}\n`;
    assert.deepEqual(guidesListedAsTesting(text), [`${environments} ${guides}`], `the list runs past ${html}`);
  }
  // An HTML block that shows text introduces the list below it.
  assert.deepEqual(guidesListedAsTesting(`${environments}\n\n${honeypot}\n${shown}\n${guides}\n`), []);
  // One that shows no text leaves the lead-in above it to the list below it, as the page
  // shows that list under the same lead-in.
  for (const html of hidden) {
    const text = `${environments}\n\n${honeypot}\n${html}\n${guides}\n`;
    assert.deepEqual(guidesListedAsTesting(text), [`${environments} ${guides}`], `${html} hides the lead-in`);
  }
  for (const html of ['<div>', '<div>\n<!-- note -->\n</div>']) {
    const text = `${environments}\n\n${html}\n\n${guides}\n\n</div>\n`;
    assert.deepEqual(guidesListedAsTesting(text), [`${environments} ${guides}`], `${html} hides the lead-in`);
  }
  // An HTML block ends the paragraph above it, so the lead-in is the block when it shows
  // text, and the paragraph when it shows none.
  assert.deepEqual(guidesListedAsTesting(`Notes on testing\n${shown}\n${guides}\n`), []);
  assert.deepEqual(guidesListedAsTesting(`${environments}\n<!-- note -->\n\n${guides}\n`), [`${environments} ${guides}`]);
  // The lines of an HTML block that runs to a blank line are part of it, and the text they
  // show introduces the list below it.
  assert.deepEqual(guidesListedAsTesting(`<div>\n${environments}\n\n${guides}\n`), [`<div> ${environments} ${guides}`]);
  // A one-line comment ends on its line, so the paragraph after it introduces the list.
  assert.deepEqual(guidesListedAsTesting(`${reading}\n\n${honeypot}\n<!-- note -->\n\n${environments}\n${guides}\n`), [
    `${environments} ${guides}`,
  ]);
  // A block left of the item's text ends the item, which is at column 4 after a marker
  // and three spaces.
  assert.deepEqual(guidesListedAsTesting(`${reading}\n\n${honeypotAt4}\n  > ${environments}\n${guides}\n`), [
    `> ${environments} ${guides}`,
  ]);
  // An inline tag does not open an HTML block, so it continues the item.
  const link = '<a href="https://example.com">testing</a>';
  assert.deepEqual(guidesListedAsTesting(`${reading}\n\n${honeypot}\n${link}\n${guides}\n`), []);
  // The entry below it is then in the same list, under the lead-in of that list.
  assert.deepEqual(guidesListedAsTesting(`${environments}\n\n${honeypot}\n${link}\n${guides}\n`), [
    `${environments} ${guides}`,
  ]);
  // Nor does a tag indented by four spaces, even when that is left of the item's text.
  const honeypotAt5 = '-    [agentpwn.com](https://agentpwn.com) -- honeypot environment';
  assert.deepEqual(guidesListedAsTesting(`${reading}\n\n${honeypotAt5}\n    <p>${environments}</p>\n\n${guides}\n`), []);
  // An HTML block runs to the next blank line, so a list line right below it is raw HTML.
  assert.deepEqual(guidesListedAsTesting(`${reading}\n\n${honeypot}\n<p>testing</p>\n${guides}\n`), []);
  // A <pre> block and a comment run to their end, past a blank line.
  for (const [open, close] of [['<pre>', '</pre>'], ['<!--', '-->']]) {
    const text = `${reading}\n\n${honeypot}\n${open}\n${environments}\n\n${guides}\n${close}\n`;
    assert.deepEqual(guidesListedAsTesting(text), [], `the block ends before ${close}`);
  }
  // A comment, a processing instruction and a CDATA section end only at their own end
  // marker, not at the > of a tag, and a raw text block only at its own closing tag.
  for (const [open, close] of [['<!--', '-->'], ['<?x', '?>'], ['<![CDATA[', ']]>'], ['<pre>', '</pre>']]) {
    const text = `${environments}\n\n${open}\n<b>testing</b>\n${guides}\n${close}\n`;
    assert.deepEqual(guidesListedAsTesting(text), [], `the block ends before ${close}`);
  }
  // The lines of a code fence are code, not a lead-in.
  assert.deepEqual(guidesListedAsTesting(`${reading}\n\n${honeypot}\n\`\`\`sh\nnpm test\n\`\`\`\n${guides}\n`), []);
  // A fence closes only at a fence of the same character that is at least as long.
  for (const [open, inner, close] of [['````md', '```', '````'], ['```md', '~~~', '```']]) {
    const text = `${reading}\n\n${honeypot}\n${open}\n${inner}\n${close}\n${environments}\n${guides}\n`;
    assert.deepEqual(guidesListedAsTesting(text), [`${environments} ${guides}`], `${inner} closes ${open}`);
  }
  // A line of backticks with a backtick in its info string is text, not a fence.
  assert.deepEqual(guidesListedAsTesting(`${reading}\n\n${honeypot}\n\n\`\`\`audit\` ${environments}\n${guides}\n`), [
    `\`\`\`audit\` ${environments} ${guides}`,
  ]);
  // A block indented to the text of a list item is inside that item.
  assert.deepEqual(guidesListedAsTesting(`${reading}\n\n${honeypot}\n  > used for testing\n${guides}\n`), []);
  // So is a thematic break or a code fence, with the line written below it.
  for (const block of ['* * *', '```sh\n  npm test\n  ```']) {
    const text = `${reading}\n\n${honeypot}\n  ${block}\n  used for testing\n${guides}\n`;
    assert.deepEqual(guidesListedAsTesting(text), [], `${block} ends the item`);
  }
  // So is an HTML block, and the entry below it is in the same list.
  assert.deepEqual(guidesListedAsTesting(`${environments}\n\n${honeypot}\n  <p>x</p>\n${guides}\n`), [
    `${environments} ${guides}`,
  ]);
  // A paragraph after a blank line is inside a list item when it is indented to the item's
  // text, and the entry below it is in the same list. Its lines, and those of a later
  // entry, go on lazily without that indent.
  const loose = [
    `${honeypot}\n\n  More about the honeypot.`,
    `${honeypot}\n\n  More about\nthe honeypot.`,
    `${honeypot}\n\n- [agentpwn.com](https://agentpwn.com) -- honeypot environment\nfor agent security tools`,
  ];
  for (const list of loose) {
    assert.deepEqual(guidesListedAsTesting(`${environments}\n\n${list}\n${guides}\n`), [`${environments} ${guides}`], list);
  }
  // Left of the item's text, it ends the list and introduces the list below it.
  assert.deepEqual(guidesListedAsTesting(`${environments}\n\n${honeypot}\n\nMore about the honeypot.\n${guides}\n`), []);
});

test('the code-fence pattern reads a long run of backticks in linear time', () => {
  const start = performance.now();
  assert.equal(FENCE.exec(`${'`'.repeat(200000)}x\``), null);
  const elapsed = performance.now() - start;
  assert.ok(elapsed < 1000, `took ${Math.round(elapsed)} ms`);
});

test('mcp-audit.json does not name agentpwn.com/tools as a testing resource', () => {
  const links = strings(audit).filter(({ value }) => GUIDES.test(value));
  const testing = links.filter(({ path }) => /test/i.test(path.at(-1))).map(({ path }) => path.join('.'));
  assert.deepEqual(testing, [], 'keys that name the guides page as a testing resource');
});

test('mcp-audit.json does not give a single agentpwn test page as a source of attack patterns', () => {
  const single = strings(audit)
    .filter(({ path, value }) => /attackPattern/i.test(path.at(-1)) && TEST_PAGE.test(value))
    .map(({ path, value }) => `${path.join('.')}: ${value}`);
  assert.deepEqual(single, [], 'attack pattern keys that point at one test page');
});
