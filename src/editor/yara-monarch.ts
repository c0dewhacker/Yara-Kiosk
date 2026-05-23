import type * as Monaco from 'monaco-editor';

const KEYWORDS = [
  'rule', 'private', 'global', 'import', 'include',
  'meta', 'strings', 'condition',
  'any', 'all', 'of', 'them', 'for', 'in', 'at',
  'not', 'and', 'or', 'true', 'false',
  'defined', 'matches', 'contains',
  'startswith', 'endswith', 'icontains', 'istartswith', 'iendswith',
];

const BUILTINS = [
  'filesize', 'entrypoint',
  'uint8', 'uint16', 'uint32', 'uint64',
  'uint8be', 'uint16be', 'uint32be', 'uint64be',
  'int8', 'int16', 'int32', 'int64',
  'int8be', 'int16be', 'int32be', 'int64be',
];

const MODIFIERS = [
  'ascii', 'wide', 'nocase', 'fullword',
  'xor', 'base64', 'base64wide',
];

export function registerYaraLanguage(monaco: typeof Monaco): void {
  if (monaco.languages.getLanguages().some(l => l.id === 'yara')) return;

  monaco.languages.register({
    id: 'yara',
    extensions: ['.yar', '.yara'],
    aliases: ['YARA', 'yara'],
  });

  monaco.languages.setMonarchTokensProvider('yara', {
    keywords: KEYWORDS,
    builtins: BUILTINS,
    modifiers: MODIFIERS,

    tokenizer: {
      root: [
        // Comments
        [/\/\/.*$/, 'comment'],
        [/\/\*/, 'comment', '@blockcomment'],

        // Quoted strings
        [/"/, 'string', '@dqstring'],

        // YARA regex literals: /pattern/modifiers — only after = or matches keyword.
        // We approximate by matching /.../ that doesn't look like division (starts
        // with a non-whitespace, non-operator char following the slash).
        [/\/[^/\n*][^/\n]*\/[igsmx]*/, 'regexp'],

        // Hex byte strings: { DE AD [1-4] BE EF }.
        // Matched inline rather than via state to avoid falsely entering hex mode
        // on rule-body braces.  Handles simple single-line hex strings; multi-line
        // ones fall back to delimiter colouring (acceptable for a syntax highlighter).
        [/\{[0-9a-fA-F\s?~|[\]().-]*\}/, 'number.hex'],

        // String variable references ($name, $$name, #name, @name)
        [/\$\$?\w*/, 'variable.name'],
        [/[#@]\w+/, 'variable.predefined'],

        // Numbers — hex and decimal (with optional KB/MB/GB suffix)
        [/0x[0-9a-fA-F]+/, 'number.hex'],
        [/\d+(\.\d+)?[KMGT]?B?/, 'number'],

        // Identifiers and keywords
        [/[a-zA-Z_]\w*/, {
          cases: {
            '@keywords': 'keyword',
            '@builtins': 'support.function',
            '@modifiers': 'keyword.modifier',
            '@default': 'identifier',
          },
        }],

        // Operators
        [/[<>=!]=?/, 'operator'],
        [/[+\-*/%]/, 'operator'],
        [/[|&^~]/, 'operator'],

        // Delimiters — { } are rule-body braces at this level
        [/[{}()[\]]/, 'delimiter'],
        [/[:,]/, 'delimiter'],

        [/\s+/, ''],
      ],

      blockcomment: [
        [/[^/*]+/, 'comment'],
        [/\*\//, 'comment', '@pop'],
        [/[/*]/, 'comment'],
      ],

      dqstring: [
        [/[^\\"]+/, 'string'],
        [/\\./, 'string.escape'],
        [/"/, 'string', '@pop'],
      ],
    },
  });

  monaco.languages.setLanguageConfiguration('yara', {
    comments: {
      lineComment: '//',
      blockComment: ['/*', '*/'],
    },
    brackets: [
      ['{', '}'],
      ['[', ']'],
      ['(', ')'],
    ],
    autoClosingPairs: [
      { open: '{', close: '}' },
      { open: '[', close: ']' },
      { open: '(', close: ')' },
      { open: '"', close: '"' },
    ],
    surroundingPairs: [
      { open: '{', close: '}' },
      { open: '[', close: ']' },
      { open: '(', close: ')' },
      { open: '"', close: '"' },
    ],
  });

  monaco.editor.defineTheme('yara-dark', {
    base: 'vs-dark',
    inherit: true,
    rules: [
      { token: 'keyword',           foreground: '009efd', fontStyle: 'bold' },
      { token: 'keyword.modifier',  foreground: '2af598' },
      { token: 'support.function',  foreground: 'ff9f43' },
      { token: 'variable.name',     foreground: 'e17055' },
      { token: 'variable.predefined', foreground: 'fd79a8' },
      { token: 'string',            foreground: 'a8ff78' },
      { token: 'string.escape',     foreground: 'ffeaa7' },
      { token: 'regexp',            foreground: '55efc4' },
      { token: 'number',            foreground: 'fdcb6e' },
      { token: 'number.hex',        foreground: 'fdcb6e' },
      { token: 'comment',           foreground: '636e72', fontStyle: 'italic' },
      { token: 'operator',          foreground: 'dfe6e9' },
      { token: 'delimiter',         foreground: 'b2bec3' },
    ],
    colors: {
      'editor.background':              '#1a1f2e',
      'editor.foreground':              '#dfe6e9',
      'editor.lineHighlightBackground': '#2d3561',
      'editorLineNumber.foreground':    '#636e72',
      'editorLineNumber.activeForeground': '#b2bec3',
      'editor.selectionBackground':     '#009efd33',
      'editorCursor.foreground':        '#2af598',
    },
  });
}
