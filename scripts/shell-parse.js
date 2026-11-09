// Privacy Shield - small, quote-aware parser for Bash and PowerShell command lines.
//
// It is not a full shell grammar. It splits a command line into pipelines of simple
// commands so the hooks can reason about "which programs run, with which arguments, fed
// by what", instead of matching raw text that changes with flag order, case or wrappers.
//
// parseShell(src, shell) -> { pipelines, subs }
//   pipelines: Array<Array<Command>>   (a pipeline is the list of its | stages)
//   subs:      Array<pipelines>        (bodies of $(…), `…`, <(…), (…), { } script blocks)
//   Command:   { words: string[], redirects: Array<{ dir: '<'|'>', target: string }> }
// A substitution shows up inside a word as SUB_MARK + id + SUB_MARK.

const SUB_MARK = '\u0001';
const SUB_RE = /\u0001(\d+)\u0001/g;

function parseShell(src, shell) {
  const ps = shell === 'powershell';
  const subs = [];
  let i = 0;

  function parseSeq(closer) {
    const pipelines = [];
    let pipeline = [];
    let words = [];
    let redirects = [];
    let word = '';
    let inWord = false;
    let redirectDir = null; // set when the next word is a redirect target
    const heredocs = [];

    const endWord = () => {
      if (inWord) {
        if (redirectDir) { redirects.push({ dir: redirectDir, target: word }); redirectDir = null; }
        else words.push(word);
      }
      word = '';
      inWord = false;
    };
    const endCommand = () => {
      endWord();
      if (words.length || redirects.length) pipeline.push({ words, redirects });
      words = [];
      redirects = [];
    };
    const endPipeline = () => {
      endCommand();
      if (pipeline.length) pipelines.push(pipeline);
      pipeline = [];
    };
    const subst = (close) => {
      const inner = parseSeq(close);
      const id = subs.length;
      subs.push(inner);
      word += SUB_MARK + id + SUB_MARK;
      inWord = true;
    };
    const skipHeredocBodies = () => {
      // i points just past a newline; drop lines until each pending delimiter line
      while (heredocs.length) {
        const delim = heredocs.shift();
        while (i < src.length) {
          const nl = src.indexOf('\n', i);
          const line = src.slice(i, nl === -1 ? src.length : nl);
          i = nl === -1 ? src.length : nl + 1;
          if (line.replace(/^\t+/, '').trim() === delim) break;
        }
      }
    };
    const readDouble = () => {
      // i points just past the opening "
      while (i < src.length) {
        const c = src[i];
        const n = src[i + 1];
        if (c === '"') {
          if (ps && n === '"') { word += '"'; i += 2; continue; }
          i++;
          return;
        }
        if (!ps && c === '\\' && n !== undefined && '"\\$`\n'.includes(n)) { if (n !== '\n') word += n; i += 2; continue; }
        if (ps && c === '`' && n !== undefined) { word += n; i += 2; continue; }
        if (c === '$' && n === '(') { i += 2; subst(')'); continue; }
        if (!ps && c === '`') { i++; subst('`'); continue; }
        word += c;
        i++;
      }
    };

    while (i < src.length) {
      const c = src[i];
      const n = src[i + 1];

      if (closer && c === closer) { i++; endPipeline(); return pipelines; }

      // Escapes
      if (!ps && c === '\\') {
        if (n === '\n') { i += 2; continue; }
        if (n !== undefined) { word += n; inWord = true; }
        i += 2;
        continue;
      }
      if (ps && c === '`') {
        if (n !== undefined && n !== '\n') { word += n; inWord = true; }
        i += 2;
        continue;
      }

      // Quotes
      if (c === "'") {
        const j = src.indexOf("'", i + 1);
        const end = j === -1 ? src.length : j;
        word += src.slice(i + 1, end);
        inWord = true;
        i = end + 1;
        continue;
      }
      if (c === '"') { i++; inWord = true; readDouble(); continue; }

      // Comments
      if (c === '#' && !inWord) {
        const nl = src.indexOf('\n', i);
        i = nl === -1 ? src.length : nl;
        continue;
      }

      // Substitutions and groups
      if (c === '$' && n === '(') { i += 2; subst(')'); continue; }
      if (ps && c === '$' && n === '{') {
        const j = src.indexOf('}', i);
        const end = j === -1 ? src.length : j + 1;
        word += src.slice(i, end);
        inWord = true;
        i = end;
        continue;
      }
      if (!ps && c === '`') { i++; subst('`'); continue; }
      if (!ps && (c === '<' || c === '>') && n === '(') { endWord(); i += 2; subst(')'); continue; }
      if (ps && c === '@' && (n === '(' || n === '{')) { i++; continue; }
      if (c === '(') { i++; subst(')'); continue; }
      if (ps && c === '{') { i++; subst('}'); continue; }
      if (c === ')' || (ps && c === '}')) { endCommand(); i++; continue; }

      // Separators
      if (c === ' ' || c === '\t' || c === '\r') { endWord(); i++; continue; }
      if (c === '\n') { endPipeline(); i++; skipHeredocBodies(); continue; }
      if (c === ';') { endPipeline(); i++; continue; }
      if (c === '|') {
        if (n === '|') { endPipeline(); i += 2; continue; }
        endCommand();
        i += n === '&' ? 2 : 1;
        continue;
      }
      if (c === '&') {
        if (n === '&') { endPipeline(); i += 2; continue; }
        if (n === '>') { endWord(); i++; continue; } // &> redirect: handled by the > branch
        if (ps) { endWord(); i++; continue; }      // call operator
        endPipeline();                              // background job
        i++;
        continue;
      }

      // Redirections: [n]> [n]>> [n]>&m < <<< and heredocs
      if (c === '>' || c === '<') {
        if (inWord && /^\d*$/.test(word)) { word = ''; inWord = false; } // fd number
        else endWord();
        if (!ps && c === '<' && n === '<' && src[i + 2] !== '<') {
          // heredoc: <<[-] DELIM, body skipped at the next newline
          i += 2;
          if (src[i] === '-') i++;
          while (src[i] === ' ' || src[i] === '\t') i++;
          const m = /^(['"]?)([^\s'";|&<>()]+)\1/.exec(src.slice(i));
          if (m) { heredocs.push(m[2]); i += m[0].length; }
          continue;
        }
        let op = '';
        while (src[i] === '>' || src[i] === '<') op += src[i++];
        if (src[i] === '&') {
          i++;
          const fd = /^(?:\d+|-)/.exec(src.slice(i));
          if (fd) { i += fd[0].length; continue; } // 2>&1, >&-
        }
        redirectDir = op.startsWith('<') ? '<' : '>'; // <<< here-string data counts as input
        continue;
      }

      word += c;
      inWord = true;
      i++;
    }

    endPipeline();
    return pipelines;
  }

  const pipelines = parseSeq(null);
  return { pipelines, subs };
}

// ─── Command helpers ───

function cmdName(word) {
  let w = String(word || '').replace(/^\\/, '');
  w = w.split(/[\\/]/).pop();
  return w.toLowerCase().replace(/\.(exe|cmd|bat|com|ps1)$/, '');
}

// Wrappers run the command that follows them. Values: flags that take a separate argument.
const WRAPPERS = {
  sudo: ['-u', '-g', '-C', '-D', '-h', '-p', '-r', '-t', '-U', '-T', '--user', '--group', '--chdir', '--prompt'],
  doas: ['-u', '-C'],
  env: ['-u', '-C', '-S', '--unset', '--chdir', '--split-string'],
  command: [],
  builtin: [],
  exec: ['-a'],
  nohup: [],
  time: ['-f', '-o'],
  nice: ['-n'],
  ionice: ['-c', '-n', '-p'],
  stdbuf: ['-i', '-o', '-e'],
  timeout: ['-s', '-k', '--signal', '--kill-after'],
  xargs: ['-I', '-n', '-P', '-L', '-d', '-E', '-s', '-a', '--max-args', '--max-procs', '--delimiter', '--arg-file'],
  busybox: [],
  nocorrect: [],
  noglob: [],
};

/**
 * Strip leading VAR=value assignments and wrappers (sudo, env, xargs …).
 * @returns {{ chain: string[], name: string, args: string[] }}
 */
function unwrap(words) {
  const chain = [];
  let k = 0;
  // PowerShell assignment: $x = <command>
  if (words.length > 2 && /^\$[\w:]+$/.test(words[0]) && /^[+\-*/]?=$/.test(words[1])) k = 2;
  while (k < words.length) {
    const w = words[k];
    if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(w)) { k++; continue; }
    const name = cmdName(w);
    const argFlags = WRAPPERS[name];
    if (!argFlags) break;
    chain.push(name);
    k++;
    let positionalSkipped = name !== 'timeout';
    while (k < words.length) {
      const a = words[k];
      if (a === '--') { k++; break; }
      if (name === 'env' && /^[A-Za-z_][A-Za-z0-9_]*=/.test(a)) { k++; continue; }
      if (a.startsWith('-') && a.length > 1) {
        k += argFlags.includes(a) ? 2 : 1;
        continue;
      }
      if (!positionalSkipped) { positionalSkipped = true; k++; continue; } // timeout DURATION
      break;
    }
  }
  if (k >= words.length) return { chain, name: '', args: [] };
  return { chain, name: cmdName(words[k]), args: words.slice(k + 1) };
}

/** Ids of the substitutions referenced by a word. */
function subIds(word) {
  const ids = [];
  let m;
  SUB_RE.lastIndex = 0;
  while ((m = SUB_RE.exec(word)) !== null) ids.push(Number(m[1]));
  return ids;
}

/** Every command inside the given substitution ids, recursively. */
function commandsInSubs(ids, subs, seen = new Set()) {
  const out = [];
  for (const id of ids) {
    if (seen.has(id) || !subs[id]) continue;
    seen.add(id);
    for (const pipeline of subs[id]) {
      for (const cmd of pipeline) {
        out.push(cmd);
        for (const w of cmd.words) out.push(...commandsInSubs(subIds(w), subs, seen));
      }
    }
  }
  return out;
}

/** All pipelines: top level and inside every substitution. */
function allPipelines(parsed) {
  return [...parsed.pipelines, ...parsed.subs.flat()];
}

/** Word text without substitution markers (for path and flag tests). */
function plain(word) {
  return String(word).replace(SUB_RE, ' ');
}

module.exports = { parseShell, unwrap, cmdName, subIds, commandsInSubs, allPipelines, plain, SUB_MARK };
