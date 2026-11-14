r"""Word-level LaTeX change-marking (latexdiff style, pure Python).
Usage: python3 texdiff.py OLD.tex NEW.tex OUT.tex
Deleted text: red strikethrough (\DIFdel); added text: blue underline (\DIFadd). Prose paragraphs are compared word by word;
table rows and algorithm lines line by line; equations as blocks; floats removed from the main text are shown as a
struck-through note that names where they went (Supplementary Material)."""
import re, sys, difflib

OLD, NEW, OUT = sys.argv[1:4]
MOVED = {  # label -> where it went
    'tab:limits': 'Table S1', 'tab:decision': 'Table S2', 'tab:example': 'Table S3', 'tab:bench': 'Table S4',
    'tab:probe': 'Table S5', 'tab:manifest': 'Table S6', 'tab:holdout': 'Table S7', 'tab:robust': 'Table S8',
    'tab:unseen': 'Table S9', 'tab:lodo': 'Table S10', 'tab:cost': 'Table S11', 'fig:threat': 'Figure S1',
    'fig:witness': 'Figure S2', 'fig:roc': 'Figure S3', 'fig:factors': 'Figure S4', 'fig:judgeswap': 'Figure S5',
    'tab:prf': 'the text of Section 7.1', 'tab:detprf': 'the text of Section 7.4.2'}

# ---------------------------------------------------------------- units
BLOCK_ENVS = ('table', 'figure', 'algorithm', 'equation', 'itemize', 'enumerate')

def units(path):
    lines = open(path, encoding='utf-8').read().split('\n')
    out, i = [], 0
    while i < len(lines):
        l = lines[i]
        m = re.match(r'\\begin\{(%s)\}' % '|'.join(BLOCK_ENVS), l)
        if m:
            env = m.group(1); j = i
            while not re.match(r'\\end\{%s\}' % env, lines[j]): j += 1
            out.append(('block', '\n'.join(lines[i:j + 1]))); i = j + 1; continue
        out.append(('line', l)); i += 1
    return out

def label_of(block):
    m = re.search(r'\\label\{([^}]*)\}', block); return m.group(1) if m else None

def env_of(block):
    return re.match(r'\\begin\{(\w+)\}', block).group(1)

# ---------------------------------------------------------------- tokens
TOK = re.compile(r'''\\[a-zA-Z]+\*?(?:\[[^\]]*\])?(?:\{(?:[^{}]|\{(?:[^{}]|\{[^{}]*\})*\})*\})*|\$(?:[^$\\]|\\.)*\$|[^\s]+''')

def toks(s): return TOK.findall(s)

def join(ts):
    out = ''
    for t in ts:
        if out and re.match(r'^[.,;:)\]]+$', t): out += t
        else: out += (' ' if out else '') + t
    return out

UNSAFE = re.compile(r'\\\\|\\begin|\\end|\\item|&|\\(?:sub)*section|\\caption|\\label')

def strike(text):
    """per-word strikeout so that lines can break (no ulem available)"""
    return ' '.join('\\DIFdelw{%s}' % t for t in toks(text))

PLAIN = [False]
def mark(kind, text):
    if not text.strip(): return text
    if kind == 'del' and not PLAIN[0]: return strike(text)
    return '\\DIF%s{%s}' % (kind, text)

def wdiff(a, b):
    """word-level diff of two strings -> marked string (or None if unsafe)"""
    ta, tb = toks(a), toks(b)
    if any(UNSAFE.search(t) for t in ta + tb): return None
    sm = difflib.SequenceMatcher(None, ta, tb, autojunk=False)
    out = []
    for op, i1, i2, j1, j2 in sm.get_opcodes():
        if op == 'equal': out.append(join(tb[j1:j2]))
        else:
            if i2 > i1: out.append(mark('del', join(ta[i1:i2])))
            if j2 > j1: out.append(mark('add', join(tb[j1:j2])))
    return join([x for x in out if x])

HEAD = re.compile(r'^\\((?:sub)*section\*?)\{(.*)\}$')
CMD1 = re.compile(r'^\\(abstract|dataavailability|supplementary|acknowledgments|funding|authorcontributions|conflictsofinterest)\{(.*)\}$')

def mark_line(kind, l):
    """whole-line marking of a prose/heading/command line"""
    s = l.strip()
    if not s: return l
    m = HEAD.match(s)
    if m:
        if kind == 'del': return '\\noindent ' + strike('[Heading of the submitted version removed: %s]' % m.group(2))
        return '\\%s{\\texorpdfstring{\\DIF%s{%s}}{%s}}' % (m.group(1), kind, m.group(2), m.group(2))
    m = CMD1.match(s)
    if m: return '\\%s{\\DIF%s{%s}}' % (m.group(1), kind, m.group(2))
    m = re.match(r'^(\\item(?:\[[^\]]*\])?)\s*(.*)$', s)
    if m: return '%s \\DIF%s{%s}' % (m.group(1), kind, m.group(2)) if kind == 'add' else '\\DIFdel{%s}' % m.group(2)
    if s.startswith('\\noindent{\\footnotesize'):
        return '\\noindent{\\footnotesize \\DIF%s{%s}}' % (kind, s[len('\\noindent{\\footnotesize'):-1].strip())
    if s.startswith('\\') and not s.startswith('\\textbf'):   # other structural command lines: keep (add) or drop (del)
        return l if kind == 'add' else ''
    if UNSAFE.search(s): return l if kind == 'add' else ''
    return strike(s) if kind == 'del' else '\\DIFadd{%s}' % s

def diff_line(a, b):
    sa, sb = a.strip(), b.strip()
    ma, mb = HEAD.match(sa), HEAD.match(sb)
    if ma and mb:
        if ma.group(2) == mb.group(2): return b
        PLAIN[0] = True; w = wdiff(ma.group(2), mb.group(2)); PLAIN[0] = False
        return '\\%s{\\texorpdfstring{%s}{%s}}' % (mb.group(1), w, mb.group(2)) if w else mark_line('add', b)
    ca, cb = CMD1.match(sa), CMD1.match(sb)
    if ca and cb:
        PLAIN[0] = True; w = wdiff(ca.group(2), cb.group(2)); PLAIN[0] = False; return '\\%s{%s}' % (cb.group(1), w) if w else mark_line('add', b)
    ia, ib = re.match(r'^(\\item(?:\[[^\]]*\])?)\s*(.*)$', sa), re.match(r'^(\\item(?:\[[^\]]*\])?)\s*(.*)$', sb)
    if ia and ib:
        w = wdiff(ia.group(2), ib.group(2)); return '%s %s' % (ib.group(1), w) if w else mark_line('add', b)
    if sa.startswith('\\noindent{\\footnotesize') and sb.startswith('\\noindent{\\footnotesize'):
        w = wdiff(sa[len('\\noindent{\\footnotesize'):-1], sb[len('\\noindent{\\footnotesize'):-1])
        return '\\noindent{\\footnotesize %s}' % w if w else mark_line('add', b)
    w = wdiff(sa, sb)
    if w is None: return mark_line('del', a) + '\n' + mark_line('add', b)
    return w

# ---------------------------------------------------------------- floats / blocks
def cellmark(kind, row):
    body, tail = row.rsplit('\\\\', 1) if '\\\\' in row else (row, '')
    cells = re.split(r'\s*&\s*', body)
    def c(x):
        x = x.strip()
        if not x or x == '--' or '\\multicolumn' in x or '\\begin' in x: return x if not x else ('{\\color{%s}%s}' % ('blue' if kind == 'add' else 'red', x))
        return '\\DIF%s{%s}' % (kind, x)
    return ' & '.join(c(x) for x in cells) + ('\\\\' + tail if '\\\\' in row else '')

def block_lines_mark(kind, lines):
    out = []
    for l in lines:
        s = l.strip()
        if s.startswith('\\caption{'):
            out.append('\\caption{\\DIF%s{%s}}' % (kind, s[len('\\caption{'):-1])); continue
        if ' & ' in s and '\\\\' in s: out.append(cellmark(kind, s)); continue
        m = re.match(r'^(\\(?:STATE|REQUIRE|RETURN|ENSURE))\s+(.*)$', s)
        if m: out.append('%s {\\color{%s}%s}' % (m.group(1), 'blue' if kind == 'add' else 'red', m.group(2))); continue
        if s.startswith(('\\IF', '\\ELSE', '\\FOR', '\\WHILE', '\\ENDIF')):
            out.append('{\\color{%s}%s}' % ('blue' if kind == 'add' else 'red', s)); continue
        m = re.match(r'^(\\item)\s*(.*)$', s)
        if m: out.append('%s \\DIF%s{%s}' % (m.group(1), kind, m.group(2))); continue
        if s.startswith('\\noindent{\\footnotesize'):
            out.append('\\noindent{\\footnotesize \\DIF%s{%s}}' % (kind, s[len('\\noindent{\\footnotesize'):-1].strip())); continue
        if kind == 'del':
            if s.startswith('\\') or not s: continue
            out.append('\\DIFdel{%s}' % s); continue
        out.append(l)
    return out

def diff_block(a, b):
    if a == b: return b
    env = env_of(b)
    if env == 'equation':
        return ('\\DIFdel{[Equation of the submitted version:]}\n{\\color{red}' + a.replace('\\begin{equation}', '\\begin{equation*}').replace('\\end{equation}', '\\end{equation*}')
                + '}\n' + b.replace('\\begin{equation}', '\\begin{equation}\\color{blue}'))
    la, lb = a.split('\n'), b.split('\n')
    spec = lambda ls: [x for x in ls if x.strip().startswith('\\begin{tabularx}')]
    if env == 'table' and spec(la) != spec(lb):
        return removed_block_note(a).replace('removed from the main text, now %s' % MOVED.get(label_of(a), 'removed'), 'replaced by the table below').replace('replaced:', 'replaced by the table below:') + '\n' + '\n'.join(block_lines_mark('add', lb))
    sm = difflib.SequenceMatcher(None, la, lb, autojunk=False); out = []
    for op, i1, i2, j1, j2 in sm.get_opcodes():
        if op == 'equal': out.extend(lb[j1:j2])
        elif op == 'replace' and (i2 - i1) == (j2 - j1):
            for x, y in zip(la[i1:i2], lb[j1:j2]):
                xs, ys = x.strip(), y.strip()
                if xs.startswith('\\caption{') and ys.startswith('\\caption{'):
                    w = wdiff(xs[len('\\caption{'):-1], ys[len('\\caption{'):-1]); out.append('\\caption{%s}' % w if w else '\\caption{\\DIFadd{%s}}' % ys[len('\\caption{'):-1])
                elif ' & ' in ys and '\\\\' in ys:
                    out.append(cellmark('del', xs)); out.append(cellmark('add', ys))
                else:
                    out.extend(block_lines_mark('del', [x])); out.extend(block_lines_mark('add', [y]))
        else:
            out.extend(block_lines_mark('del', la[i1:i2])); out.extend(block_lines_mark('add', lb[j1:j2]))
    return '\n'.join(out)

def removed_block_note(a):
    lab = label_of(a); env = env_of(a)
    m = re.search(r'\\caption\{(.*)\}', a); cap = m.group(1) if m else ''
    where = MOVED.get(lab, 'removed')
    if lab not in MOVED: return '\\noindent ' + strike('[%s of the submitted version replaced: %s]' % ({'table': 'Table', 'figure': 'Figure', 'algorithm': 'Algorithm'}.get(env, env), cap))
    what = {'table': 'Table', 'figure': 'Figure', 'algorithm': 'Algorithm', 'equation': 'Equation'}.get(env, env)
    if env in ('itemize', 'enumerate'):
        return '\n'.join(block_lines_mark('del', a.split('\n')))
    return '\\noindent ' + strike('[%s of the submitted version removed from the main text, now %s: %s]' % (what, where, cap))

# ---------------------------------------------------------------- alignment
def key(u): return u[1]
def sim(a, b):
    return difflib.SequenceMatcher(None, toks(a), toks(b), autojunk=False).ratio()

def emit_pair(a, b):
    if a[0] == 'block' and b[0] == 'block': return diff_block(a[1], b[1])
    if a[0] == 'line' and b[0] == 'line': return diff_line(a[1], b[1])
    return mark_line('del', a[1]) if a[0] == 'line' else removed_block_note(a[1]) + '\n' + (mark_line('add', b[1]) if b[0] == 'line' else '\n'.join(block_lines_mark('add', b[1].split('\n'))))

def emit_del(a): return mark_line('del', a[1]) if a[0] == 'line' else removed_block_note(a[1])
def emit_add(b): return mark_line('add', b[1]) if b[0] == 'line' else '\n'.join(block_lines_mark('add', b[1].split('\n')))

UA, UB = units(OLD), units(NEW)
NEWLABELS = set(re.findall(r'\\label\{([^}]*)\}', open(NEW, encoding='utf-8').read()))
sm = difflib.SequenceMatcher(None, [key(u) for u in UA], [key(u) for u in UB], autojunk=False)
out = []
for op, i1, i2, j1, j2 in sm.get_opcodes():
    if op == 'equal': out.extend(u[1] for u in UB[j1:j2]); continue
    A, B = UA[i1:i2], UB[j1:j2]
    # pair blocks by label first, then prose by similarity (order-preserving greedy)
    usedA = set(); pairs = {}
    for jb, b in enumerate(B):
        if b[0] == 'block' and label_of(b[1]):
            for ia, a in enumerate(A):
                if ia not in usedA and a[0] == 'block' and label_of(a[1]) == label_of(b[1]): pairs[jb] = ia; usedA.add(ia); break
    for jb, b in enumerate(B):
        cb = CMD1.match(b[1].strip()) if b[0] == 'line' else None
        if cb:
            for ia, a in enumerate(A):
                ca = CMD1.match(a[1].strip()) if a[0] == 'line' else None
                if ia not in usedA and ca and ca.group(1) == cb.group(1): pairs[jb] = ia; usedA.add(ia); break
    for jb, b in enumerate(B):
        if jb in pairs or not b[1].strip(): continue
        best, bi = 0.0, None
        for ia, a in enumerate(A):
            if ia in usedA or a[0] != b[0] or not a[1].strip(): continue
            if a[0] == 'line' and (HEAD.match(a[1].strip()) is not None) != (HEAD.match(b[1].strip()) is not None): continue
            r = sim(a[1], b[1])
            if r > best: best, bi = r, ia
        if bi is not None and best >= 0.45: pairs[jb] = bi; usedA.add(bi)
    # emit in new order; deleted old units are emitted before the first new unit that follows them
    delA = [ia for ia in range(len(A)) if ia not in usedA]
    for jb, b in enumerate(B):
        # flush deletions that precede the paired old unit
        if jb in pairs:
            while delA and delA[0] < pairs[jb]:
                ia = delA.pop(0); d = emit_del(A[ia])
                if d: out.append(d)
            out.append(emit_pair(A[pairs[jb]], b))
        else:
            e = emit_add(b)
            if e or not b[1].strip(): out.append(e)
    for ia in delA:
        d = emit_del(A[ia])
        if d: out.append(d)
res = '\n'.join(out)
# preamble
res = res.replace('\\usepackage{algorithmic}\n', '\\usepackage{algorithmic}\n\\providecommand{\\DIFadd}[1]{{\\protect\\color{blue}#1}}\n\\providecommand{\\DIFdel}[1]{{\\protect\\color{red}#1}}\n\\newcommand{\\DIFdelw}[1]{{\\color{red}\\settowidth{\\dimen0}{#1}\\makebox[\\dimen0][l]{#1}\\hspace{-\\dimen0}\\rule[0.55ex]{\\dimen0}{0.45pt}}}\n', 1)
OLDNUM = {'tab:related': '1', 'tab:limits': '2', 'tab:decision': '3', 'tab:adapters': '4', 'tab:example': '5', 'tab:bench': '6', 'tab:probe': '7', 'tab:manifest': '8', 'tab:main': '9', 'tab:prf': '10', 'tab:holdout': '11', 'tab:detect': '12', 'tab:lodo': '13', 'tab:detprf': '14', 'tab:cost': '15', 'tab:robust': '16', 'fig:threat': '1', 'fig:overview': '2', 'fig:kernel': '3', 'fig:witness': '4', 'fig:holdout': '5', 'fig:scores': '6', 'fig:roc': '7', 'fig:factors': '8', 'fig:robust': '9', 'fig:judgeswap': '10', 'alg:tsa': '1', 'alg:gate': '2'}
# references inside deleted text point to labels that no longer exist: print the submitted version's number
res = re.sub(r'\\DIFdelw\{([^{}]*\\ref\{([^}]*)\}[^{}]*)\}', lambda m: '\\DIFdelw{' + m.group(1).replace('\\ref{%s}' % m.group(2), OLDNUM.get(m.group(2), '??')) + '}' if m.group(2) in OLDNUM and m.group(2) not in NEWLABELS else m.group(0), res)
res = res.replace('\\begin{document}\n', '\\begin{document}\n\\noindent{\\small\\textbf{Change marking (relative to the submitted version):} \\DIFdelw{red} \\DIFdelw{strikethrough} = removed text; \\DIFadd{blue} = added or revised text; tables and figures moved to the Supplementary Material are indicated by a struck-through note at their former position; in the abstract and headings, removed text is shown in red without strikethrough.}\\par\\medskip\n', 1)
open(OUT, 'w', encoding='utf-8').write(res)
print('units old/new', len(UA), len(UB), '-> written', OUT)
