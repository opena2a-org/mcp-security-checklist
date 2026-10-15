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

// A link to the guides page, a word that files an entry under testing, and a list item,
// whose marker is indented at most three spaces past the text it is in.
const GUIDES_LINK = '](https://agentpwn.com/tools)';
const TESTING = /\btest(?:ing|s)?\b/i;
const LIST_ITEM = /^ {0,3}(?:[-*+]|\d+\.) /;
const HEADING = /^ {0,3}#{1,6}(?:\s|$)/;
// The blocks that the text of a list item cannot run into: a heading, a thematic break,
// a code fence, a block quote and an HTML block.
const THEMATIC_BREAK = /^ {0,3}([-*_])[ \t]*(?:\1[ \t]*){2,}$/;
// A backtick fence has no backtick after it. The lookahead takes the whole run of fence
// characters at once, so that check runs once per line and not once per backtick.
const FENCE = /^ {0,3}(?=(`{3,}|~{3,}))\1(?!(?<=`).*`)/;
// The line that closes a fence: a run of its character at least as long as its opener.
const closingFence = ([, opener]) => new RegExp(`^ {0,3}${opener[0]}{${opener.length},}[ \\t]*$`);
const BLOCK_QUOTE = /^ {0,3}>/;
const HTML_TAGS =
  'address|article|aside|base|basefont|blockquote|body|caption|center|col|colgroup|dd|details|dialog|dir|div|dl|dt|' +
  'fieldset|figcaption|figure|footer|form|frame|frameset|h[1-6]|head|header|hr|html|iframe|legend|li|link|main|menu|' +
  'menuitem|nav|noframes|ol|optgroup|option|p|param|search|section|summary|table|tbody|td|tfoot|th|thead|title|tr|' +
  'track|ul';
// A complete open or closing tag alone on its line: a tag name and, in an open tag, any
// number of attributes, each a name with an optional value that is unquoted or quoted.
const CLOSING_TAG = /^ {0,3}<\/[a-z][a-z\d-]*[ \t]*>[ \t]*$/i;
const OPEN_TAG_NAME = /^ {0,3}<[a-z][a-z\d-]*/i;
const ATTRIBUTE = /[ \t]+[a-z_:][\w.:-]*(?:[ \t]*=[ \t]*(?:[^\x00-\x20"'=<>`]+|'[^']*'|"[^"]*"))?/iy;
const OPEN_TAG_END = /[ \t]*\/?>[ \t]*$/y;
// The attributes of an open tag are read one at a time. One pattern for the whole tag keeps
// a place to go back to for each attribute, and throws a RangeError on a line that has
// about a million of them. A line is tested against it as against a pattern.
const LONE_TAG = {
  test(line) {
    if (CLOSING_TAG.test(line)) return true;
    const name = OPEN_TAG_NAME.exec(line);
    if (!name) return false;
    let end = name[0].length;
    for (ATTRIBUTE.lastIndex = end; ATTRIBUTE.test(line); ) end = ATTRIBUTE.lastIndex;
    OPEN_TAG_END.lastIndex = end;
    return OPEN_TAG_END.test(line);
  },
};
// An HTML block opens with a raw text tag, a comment, a processing instruction, a
// declaration, a CDATA section, one of the block-level tags or any other tag alone on its
// line, not with an autolink or a tag that has text after it. Each kind is paired with the
// line it ends on: a block-level tag and a lone tag run to the next blank line, the others
// to the line that holds their end. A lone tag cannot interrupt a paragraph, so it opens a
// block only where no paragraph is open, which the true after it marks.
const HTML_BLOCKS = [
  [/^ {0,3}<(?:pre|script|style|textarea)(?:[ \t>]|$)/i, /<\/(?:pre|script|style|textarea)>/i],
  [/^ {0,3}<!--/, /-->/],
  [/^ {0,3}<\?/, /\?>/],
  [/^ {0,3}<![a-z]/i, />/],
  [/^ {0,3}<!\[CDATA\[/, /\]\]>/],
  [new RegExp(`^ {0,3}</?(?:${HTML_TAGS})(?:[ \\t>]|/>|$)`, 'i'), /^\s*$/],
  [LONE_TAG, /^\s*$/, true],
];

// The part of a line where a tab sets the structure of a block: the indent of the line
// and the gap between a list marker and its text.
const TAB_STRUCTURE = /^[ \t]*(?:(?:[-*+]|\d+\.)[ \t]+)?/;

// The line with each tab in that part written as the spaces up to the next multiple of
// four columns, which is how CommonMark reads it. A tab further into the line is text.
function expandTabs(line) {
  const [structure] = TAB_STRUCTURE.exec(line);
  let added = 0;
  const spaced = structure.replace(/\t/g, (tab, index) => {
    const width = 4 - ((index + added) % 4);
    added += width - 1;
    return ' '.repeat(width);
  });
  return spaced + line.slice(structure.length);
}

// The last sentence of a paragraph or heading.
const lastSentence = (text) => text.split(/(?<=[.:!?]) /).at(-1);

// The named character references that stand for white space. Every other named reference
// is read as text, even one for a character that shows nothing, such as &ZeroWidthSpace;,
// &zwj; or &shy;. A numeric reference is read as the code point it gives, though the page
// reads one from &#x80; to &#x9F; as a Windows-1252 character; each of those is read as text.
const SPACE_REFERENCE =
  /&(?:Tab;|NewLine;|nbsp;?|NonBreakingSpace;|ensp;|emsp;|emsp13;|emsp14;|numsp;|puncsp;|thinsp;|ThinSpace;|hairsp;|VeryThinSpace;|MediumSpace;|ThickSpace;)/y;
const NUMERIC_REFERENCE = /&#(?:[xX]([\da-fA-F]+)|(\d+));?/y;
// The markup a page hides up to an end marker, each with that marker. A comment ends at
// -->. A processing instruction, a declaration and a CDATA section in any letter case end
// at their first >: a page reads a CDATA section as one only inside SVG or MathML, and
// anywhere else as a comment that the first > ends. The end marker is looked for from
// right after the <! or <? that opens the markup, so a comment can end in the dashes that
// open it: a page reads <!--> and <!---> as an empty comment.
const MARKED = [['<!--', '-->'], ['<?', '>'], ['<!', '>']];
// The = of an attribute and the quote that opens its value.
const QUOTED_VALUE = /=\s*(["'])/y;

// Where the part of an HTML block that starts at index i and shows no text ends, or -1
// when what starts there shows. White space shows none, written as itself or as a
// character reference, and nor does markup: a comment up to its end marker, a processing
// instruction, declaration or CDATA section up to its first >, and a tag up to its first
// > outside a quoted attribute value. Markup that has no end is text.
function hiddenEnd(html, i) {
  if (/\s/.test(html[i])) return i + 1;
  SPACE_REFERENCE.lastIndex = i;
  if (SPACE_REFERENCE.test(html)) return SPACE_REFERENCE.lastIndex;
  NUMERIC_REFERENCE.lastIndex = i;
  const numeric = NUMERIC_REFERENCE.exec(html);
  if (numeric) {
    const code = numeric[1] ? parseInt(numeric[1], 16) : parseInt(numeric[2], 10);
    // A reference to 0 or past the last code point stands for U+FFFD, which shows.
    const space = code > 0 && code <= 0x10ffff && /\s/.test(String.fromCodePoint(code));
    return space ? NUMERIC_REFERENCE.lastIndex : -1;
  }
  const marked = MARKED.find(([open]) => html.startsWith(open, i));
  if (marked) {
    const end = html.indexOf(marked[1], i + 2);
    return end === -1 ? -1 : end + marked[1].length;
  }
  if (!/^<\/?[a-z]/i.test(html.slice(i, i + 3))) return -1;
  for (let j = i + 1; j < html.length; j++) {
    if (html[j] === '>') return j + 1;
    QUOTED_VALUE.lastIndex = j;
    const value = QUOTED_VALUE.exec(html);
    if (value) {
      j = html.indexOf(value[1], QUOTED_VALUE.lastIndex);
      if (j === -1) return -1;
    }
  }
  return -1;
}

// Whether an HTML block shows any text on the page. It is read once from left to right,
// and stops at the first part that shows, so that no position is read again from each
// later one when a long run of markup has no end.
function showsText(html) {
  for (let i = 0; i < html.length; ) {
    i = hiddenEnd(html, i);
    if (i === -1) return true;
  }
  return false;
}

// Each list item in the text with its lead-in: the last sentence of the nearest
// paragraph, heading or HTML block that shows text above the list. A list nested in an
// item has the lead-in of the list that holds the item.
function listItems(text) {
  const items = [];
  let paragraph = [];
  let leadIn = '';
  // The list items that are open, outermost first, each with the column its text starts
  // at. An item nested in another starts its text right of the other's.
  const open = [];
  // Whether the innermost open item ends with a paragraph, which a line left of the item's
  // text can go on lazily. A blank line, a heading, a thematic break, a code block or an
  // HTML block ends it. A block quote does not, as the paragraph in the quote goes on lazily.
  let lazy = false;
  let fence = null;
  let html = null;
  let code = false;
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
  // Opens a list item, inside the innermost open item when there is one. The text of an
  // item starts after its marker and one to four spaces.
  const openItem = (line) => {
    const [, marker, gap] = /^(\s*(?:[-*+]|\d+\.))( {1,4}(?=\S))?/.exec(line);
    const entry = { item: line.trim(), leadIn, column: marker.length + (gap ? gap.length : 1) };
    open.push(entry);
    items.push(entry);
    lazy = true;
  };
  for (const line of text.split('\n').map(expandTabs)) {
    const blank = line.trim() === '';
    const indent = line.search(/\S/);
    // How many of the open items the line is inside: those whose text it is indented to.
    // A blank line is inside all of them.
    const reached = blank ? open.length : open.filter(({ column }) => indent >= column).length;
    // A code block or HTML block inside a list item ends with the item, at the first line
    // that is neither blank nor indented to the item's text.
    if ((fence || html || code) && reached < open.length) {
      fence = null;
      html = null;
      code = false;
      open.length = reached;
    }
    // A line inside a list item is read from the text of the innermost item it is inside.
    const column = reached > 0 ? open[reached - 1].column : 0;
    const content = line.slice(column);
    // The lines of a fenced code block are code, up to the fence that closes it.
    if (fence) {
      if (fence.test(content)) fence = null;
      continue;
    }
    // The lines of an HTML block are raw HTML, not list items or headings, up to the
    // line the block ends on. A blank line inside a raw text block or a comment is part
    // of it. The text of a block inside a list item is not a lead-in.
    if (html) {
      if (!blank && open.length === 0) raw.push(line.trim());
      if (html.test(content)) {
        html = null;
        endHtml();
      }
      continue;
    }
    // A line indented four spaces or more past the text it is in opens no block or list
    // item: it goes on an open paragraph, and is code where none is open. An indented code
    // block runs on over blank lines and lines indented as far.
    const indented = !blank && indent - column >= 4;
    if (code && (blank || indented)) continue;
    code = false;
    // A thematic break written with spaces (- - -) is not a list item.
    const rule = THEMATIC_BREAK.test(content);
    const item = !rule && LIST_ITEM.test(content);
    const heading = HEADING.test(content);
    const opener = FENCE.exec(content);
    const inParagraph = open.length > 0 ? lazy : paragraph.length > 0;
    const htmlBlock = HTML_BLOCKS.find(([start, , alone]) => start.test(content) && !(alone && inParagraph));
    // A line left of the item's text that opens one of those blocks ends the item;
    // the same line indented to the item's text is inside the item.
    const block = heading || rule || opener || BLOCK_QUOTE.test(content) || htmlBlock;
    // A blank line does not end a list item: the item goes on at the next line that is
    // indented to its text.
    if (open.length > 0 && blank) {
      lazy = false;
      continue;
    }
    // A line left of the innermost item's text goes on lazily while that item ends with a
    // paragraph, unless it opens a block or a list item. Otherwise it ends each item it is
    // not inside, and only those.
    if (reached < open.length) {
      if (lazy && !item && !block) {
        open.at(-1).item += ` ${line.trim()}`;
        continue;
      }
      open.length = reached;
      lazy = false;
    }
    // A line inside a list item is part of the innermost one. A list item it opens is nested
    // in that item, and the lines of a code block or HTML block it opens are not its text.
    if (open.length > 0) {
      if (item) {
        openItem(line);
        continue;
      }
      if (indented && !lazy) code = true;
      else if (opener) fence = closingFence(opener);
      else if (htmlBlock) html = htmlBlock[1].test(content) ? null : htmlBlock[1];
      else if (!rule) open.at(-1).item += ` ${line.trim()}`;
      lazy = !(code || heading || rule || opener || htmlBlock);
      continue;
    }
    if (opener) fence = closingFence(opener);
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
    // Where no paragraph is open, an indented line opens a code block. Code is not a
    // lead-in, so the lead-in above it still introduces the list below it.
    if (indented && !inParagraph) {
      code = true;
      continue;
    }
    // A thematic break and a code fence end a paragraph and are not part of one.
    if (!item && !blank && !rule && !opener) {
      paragraph.push(line.trim());
      continue;
    }
    endParagraph();
    if (item) openItem(line);
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
  // A CDATA section is hidden in any letter case.
  for (const html of ['<div>', '<div>\n<!-- note -->\n</div>', '<div>\n<![cdata[x]]>']) {
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
  // A tag with text after it on its line does not open an HTML block, so it continues the item.
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
  // The HTML block of a comment, a processing instruction or a CDATA section ends only at
  // its own end marker, not at the > of a tag, and a raw text block only at its own closing tag.
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
  // A code fence or HTML block indented to the item's text opens inside the item, with or
  // without a blank line above it, and the lines in it are code or raw HTML, not list items.
  for (const gap of ['\n', '']) {
    for (const [open, close] of [['```md', '```'], ['<!--', '-->']]) {
      const text = `${environments}\n\n${honeypot}\n${gap}  ${open}\n  ${guides}\n  ${close}\n`;
      assert.deepEqual(guidesListedAsTesting(text), [], `${open} does not open inside the item`);
    }
  }
  // So does a fence at the text of an item that starts at column 4, where it also closes,
  // and an entry written there after the fence is in a list nested in the item.
  const fenced = `${environments}\n\n${honeypotAt4}\n\n    \`\`\`md\n    ${guides}\n    \`\`\`\n`;
  assert.deepEqual(guidesListedAsTesting(fenced), [], 'the fence does not open inside the item');
  const afterFence = `${environments}\n\n${honeypotAt4}\n\n    \`\`\`\n    x\n    \`\`\`\n    ${guides}\n`;
  assert.deepEqual(guidesListedAsTesting(afterFence), [`${environments} ${guides}`], 'the fence does not close inside the item');
  // The text of an HTML block inside an item is not a lead-in, so the entry below the item
  // is in the same list.
  const div = `${environments}\n\n${honeypot}\n  <div>\n  plain text\n\n${guides}\n`;
  assert.deepEqual(guidesListedAsTesting(div), [`${environments} ${guides}`], 'the text of the block is read as a lead-in');
  // Only a paragraph goes on lazily without the item's indent. After a code fence, heading,
  // thematic break or HTML block inside the item, a line left of its text ends the list, and
  // the sentence written there introduces the list below it.
  for (const gap of ['\n', '']) {
    for (const block of ['```\n  x\n  ```', '## Notes', '* * *', '<!-- note -->', '<p>x</p>']) {
      const text = `${reading}\n\n${honeypot}\n${gap}  ${block}\nTesting environments:\n${guides}\n`;
      assert.deepEqual(guidesListedAsTesting(text), [`Testing environments: ${guides}`], `the item runs past ${block}`);
    }
  }
  // An item can hold a list of its own, and an entry in it has the lead-in of the outer list.
  assert.deepEqual(guidesListedAsTesting(`${environments}\n\n${honeypot}\n  ${guides}\n`), [`${environments} ${guides}`]);
  // A line indented to the outer item's text and not to the nested item's ends only the
  // nested item. After a code fence in the nested item it is a paragraph of the outer item,
  // with or without a blank line above it, and the entry below it is in the outer list.
  const nested = `${honeypot}\n  - Run it locally:\n    \`\`\`sh\n    docker run agentpwn\n    \`\`\``;
  for (const gap of ['\n', '']) {
    const text = `${environments}\n\n${nested}\n${gap}  Then point your agent at it.\n${guides}\n`;
    assert.deepEqual(guidesListedAsTesting(text), [`${environments} ${guides}`], 'the outer item ends with the nested one');
  }
  // A line indented four spaces or more past the text it is in opens no list item. After a
  // blank line or a block other than a paragraph it is code, and otherwise it goes on the
  // paragraph above it. Code is not a lead-in, so the paragraph above it introduces the list
  // below it.
  for (const before of ['\n', '\n<p>&nbsp;</p>\n\n', '']) {
    const text = `${environments}\n${before}    ${guides}\n`;
    assert.deepEqual(guidesListedAsTesting(text), [], `the indented line after ${JSON.stringify(before)} is a list item`);
  }
  assert.deepEqual(guidesListedAsTesting(`For written guidance:\n\n    Testing environments:\n${guides}\n`), []);
  // In an item the indent is counted from the item's text.
  assert.deepEqual(guidesListedAsTesting(`${environments}\n\n${honeypot}\n\n      ${guides}\n`), []);
  assert.deepEqual(guidesListedAsTesting(`${environments}\n\n${honeypot}\n      ${guides}\n`), [
    `${environments} ${honeypot} ${guides}`,
  ]);
  // A complete tag alone on its line opens an HTML block that runs to the next blank line,
  // so the lines below it are raw HTML, not a lead-in or a list item.
  for (const tag of ['</pre>', '<span>', '<a href="https://example.com">', '<img src="x" />']) {
    const text = `For written guidance:\n\n${tag}\nTesting environments:\n${guides}\n`;
    assert.deepEqual(guidesListedAsTesting(text), [], `${tag} does not open an HTML block`);
  }
  assert.deepEqual(guidesListedAsTesting(`${environments}\n\n${honeypot}\n\n  <span>\n  ${guides}\n`), []);
  // It shows no text, so the lead-in above it introduces the list below it.
  assert.deepEqual(guidesListedAsTesting(`${environments}\n\n<span>\n\n${guides}\n`), [`${environments} ${guides}`]);
  // It cannot interrupt a paragraph, so right after a paragraph or the text of a list item it
  // is text.
  assert.deepEqual(guidesListedAsTesting(`For written guidance:\n<span>\nTesting environments:\n${guides}\n`), [
    `<span> Testing environments: ${guides}`,
  ]);
  assert.deepEqual(guidesListedAsTesting(`${environments}\n\n${honeypot}\n<span>\n${guides}\n`), [`${environments} ${guides}`]);
  // The line that ends a multi-line HTML block is part of the block, not a paragraph below it.
  assert.deepEqual(guidesListedAsTesting(`${reading}\n\n<pre>\ntesting\n</pre>\n${guides}\n`), [
    `<pre> testing </pre> ${guides}`,
  ]);
  // A character reference for white space shows no text, and nor does a > inside a quoted
  // attribute value, so neither hides the lead-in above it. A tag is read in any letter case.
  const hiding = ['<p>&nbsp;</p>', '<p>&#xA0;&#32;&ensp;&Tab;</p>', '<div title="a>b">', "<div title='a>b'>", '<P>&nbsp;</P>'];
  for (const html of hiding) {
    const text = `${environments}\n\n${html}\n\n${guides}\n`;
    assert.deepEqual(guidesListedAsTesting(text), [`${environments} ${guides}`], `${html} hides the lead-in`);
  }
  // A character reference for a character that shows is text, as is one past the last code
  // point, which stands for U+FFFD. So is a tag whose quoted attribute value has no closing quote.
  for (const html of ['<p>&amp;</p>', '<p>&#65;</p>', '<p>&#0;</p>', '<p>&#x110000;</p>', '<div title="a>']) {
    assert.deepEqual(guidesListedAsTesting(`${environments}\n\n${html}\n\n${guides}\n`), [], `${html} shows no text`);
  }
});

test('the lead-in check reads a tab as the spaces up to the next multiple of four columns', () => {
  const guides = '- [agentpwn.com/tools](https://agentpwn.com/tools) -- security guides for AI tools and MCP servers';
  const honeypot = '- [agentpwn.com](https://agentpwn.com) -- honeypot environment';
  const environments = 'For safe, controlled testing environments:';
  // A tab, alone or after one to three spaces, indents a line to column 4. That is inside an
  // item whose text starts at column 2, so the entry is in a list nested in that item.
  for (const indent of ['\t', ' \t', '  \t', '   \t']) {
    const text = `${environments}\n\n${honeypot}\n${indent}${guides}\n`;
    assert.deepEqual(guidesListedAsTesting(text), [`${environments} ${guides}`], `indented with ${JSON.stringify(indent)}`);
  }
  // Two tabs indent it to column 8, four columns or more past the item's text, so it opens
  // no list item and goes on the paragraph of the item.
  assert.deepEqual(guidesListedAsTesting(`${environments}\n\n${honeypot}\n\t\t${guides}\n`), [
    `${environments} ${honeypot} ${guides}`,
  ]);
  // Where no paragraph is open, a line indented with a tab is code, not a lead-in.
  assert.deepEqual(guidesListedAsTesting(`For written guidance:\n\n\tTesting environments:\n${guides}\n`), []);
  // A tab between a list marker and its text is read the same way: the line is a list item
  // whose text starts at column 4.
  const tabbed = listItems(`${environments}\n\n-\t[agentpwn.com/tools](https://agentpwn.com/tools)\n`);
  assert.deepEqual(tabbed.map(({ leadIn, column }) => ({ leadIn, column })), [{ leadIn: environments, column: 4 }]);
  assert.equal(guidesListedAsTesting(`${environments}\n\n-\t[agentpwn.com/tools](https://agentpwn.com/tools)\n`).length, 1);
  // A tab further into a line is text and is left as it is.
  assert.deepEqual(listItems('- a\tb\n').map(({ item }) => item), ['- a\tb']);
});

test('the lead-in check reads a long run of tabs in linear time', () => {
  for (const indent of ['\t'.repeat(200000), ' \t'.repeat(100000), `-${'\t'.repeat(200000)}`]) {
    const start = performance.now();
    assert.equal(listItems(`${indent}x\n`).length, indent.startsWith('-') ? 1 : 0);
    const elapsed = performance.now() - start;
    assert.ok(elapsed < 1000, `${JSON.stringify(indent.slice(0, 4))}... took ${Math.round(elapsed)} ms`);
  }
});

test('the HTML text check ends a processing instruction, a declaration and a CDATA section at the first >', () => {
  // A page hides each of them up to its first >, so what follows that > shows.
  for (const html of ['<![CDATA[a>b]]>', '<![cdata[a>b]]>', '<?x a>b?>', '<!DOCTYPE a>b>', '<!a>b']) {
    assert.equal(showsText(html), true, `${html} shows no text`);
  }
  // One whose first > is its last character shows no text.
  for (const html of ['<![CDATA[x]]>', '<![cdata[x]]>', '<?x ?>', '<!DOCTYPE html>', '<!>']) {
    assert.equal(showsText(html), false, `${html} shows text`);
  }
  // Only a comment written as one runs past a > to its own end marker.
  assert.equal(showsText('<!-- a>b -->'), false);
  // The HTML block of a CDATA section still runs to the line that holds ]]>, and the text
  // after the first > of the section introduces the list below the block.
  const environments = 'For safe, controlled testing environments:';
  const guides = '- [agentpwn.com/tools](https://agentpwn.com/tools) -- security guides for AI tools and MCP servers';
  assert.deepEqual(guidesListedAsTesting(`${environments}\n\n<![CDATA[a>\nFor written guidance:]]>\n\n${guides}\n`), []);
});

test('the HTML text check ends a comment at a > right after the dashes that open it', () => {
  // A page reads <!--> and <!---> as an empty comment, so each shows no text.
  for (const html of ['<!-->', '<!--->', '<!-->\n<!--->']) {
    assert.equal(showsText(html), false, `${html} shows text`);
  }
  // What follows that > shows.
  for (const html of ['<!-->x', '<!--->x', '<!-->-->']) {
    assert.equal(showsText(html), true, `${html} shows no text`);
  }
  // A line that holds only an empty comment leaves the lead-in above it to the list below it.
  const environments = 'For safe, controlled testing environments:';
  const guides = '- [agentpwn.com/tools](https://agentpwn.com/tools) -- security guides for AI tools and MCP servers';
  for (const html of ['<!-->', '<!--->']) {
    const text = `${environments}\n\n${html}\n${guides}\n`;
    assert.deepEqual(guidesListedAsTesting(text), [`${environments} ${guides}`], `${html} hides the lead-in`);
  }
});

test('the HTML text check reads a long run of unterminated markup in linear time', () => {
  for (const markup of ['<a', '<!a', '</a', '<?', '<!--', '<![CDATA[', '<a b="']) {
    // An odd count leaves the last quoted value of '<a b="' with no closing quote.
    const html = markup.repeat(2 * Math.ceil(100000 / markup.length) + 1);
    const start = performance.now();
    assert.equal(showsText(html), true, markup);
    const elapsed = performance.now() - start;
    assert.ok(elapsed < 1000, `${markup} took ${Math.round(elapsed)} ms`);
  }
});

test('the code-fence pattern reads a long run of backticks in linear time', () => {
  const start = performance.now();
  assert.equal(FENCE.exec(`${'`'.repeat(200000)}x\``), null);
  const elapsed = performance.now() - start;
  assert.ok(elapsed < 1000, `took ${Math.round(elapsed)} ms`);
});

test('the lone-tag check reads a long run of attributes or white space in linear time', () => {
  for (const html of [`<a${' b=c'.repeat(50000)}!`, `<a${' '.repeat(200000)}!`, `<a b=${'/'.repeat(200000)}`]) {
    const start = performance.now();
    assert.equal(LONE_TAG.test(html), false);
    const elapsed = performance.now() - start;
    assert.ok(elapsed < 1000, `${html.slice(0, 8)}... took ${Math.round(elapsed)} ms`);
  }
});

test('the lone-tag check reads a tag with a million attributes', () => {
  const attributes = ' b=c'.repeat(1000000);
  assert.equal(LONE_TAG.test(`<a${attributes}>`), true);
  assert.equal(LONE_TAG.test(`<a${attributes}`), false);
});

test('the lone-tag check accepts a complete tag alone on its line and nothing else', () => {
  const tags = ['<a>', '<a/>', '<a />', '<a b>', '<a b=c>', '<a b=c/>', '<a b=/>', '<a b = "c>d" e=\'f\' g>', '</a>', '</a >', '   <A B=C>  ', '<x-y a:b.c-d="">'];
  for (const tag of tags) assert.equal(LONE_TAG.test(tag), true, `${tag} is not read as a lone tag`);
  const others = ['<a', '<a b=>', '<a b="c>', '<a b="c"d>', '<a b=c d="e>', '<a> x', '<ab=c>', '</a b>', '</a/>', '    <a>', '<1>', '< a>', 'x <a>'];
  for (const other of others) assert.equal(LONE_TAG.test(other), false, `${other} is read as a lone tag`);
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
