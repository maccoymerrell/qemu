"""Index of the Arm MRA A64 XML: encodings, fields, and pseudocode."""
import glob, html, os, pickle, re

XMLDIR = '/mnt/md0/QEMU/cst_runs/_arc3_cov/aarch64/_ref/isa/ISA_A64_xml_A_profile-2022-12'
CACHE = '/mnt/md0/QEMU/cst_runs/_arc3_cov/aarch64/asl/mra_index.pkl'

TAG = re.compile(r'<[^>]+>')


def strip_ps(t):
    t = re.sub(r'<a [^>]*>', '', t)
    t = t.replace('</a>', '')
    t = re.sub(r'<anchor[^>]*>', '', t)
    t = t.replace('</anchor>', '')
    t = TAG.sub('', t)
    return html.unescape(t)


def _attrs(tag):
    return dict(re.findall(r'([a-zA-Z_0-9]+)="([^"]*)"', tag))


def build_index():
    idx = {'enc': {}, 'files': {}}
    for path in sorted(glob.glob(os.path.join(XMLDIR, '*.xml'))):
        base = os.path.basename(path)
        if base == 'shared_pseudocode.xml':
            continue
        d = open(path, encoding='utf-8', errors='replace').read()
        if '<instructionsection' not in d:
            continue
        # instruction-level ps sections (execute / postdecode)
        top_ps = []
        for m in re.finditer(r'<ps ([^>]*)>\s*<pstext([^>]*)>(.*?)</pstext>', d, re.S):
            a = _attrs('<ps ' + m.group(1) + '>')
            b = _attrs('<x' + m.group(2) + '>')
            top_ps.append({'name': a.get('name', ''), 'enclabels': a.get('enclabels', ''),
                           'sect': b.get('rep_section', ''), 'text': strip_ps(m.group(3)),
                           'span': m.span()})
        iclasses = []
        for im in re.finditer(r'<iclass ([^>]*)>(.*?)</iclass>', d, re.S):
            ic = im.group(2)
            ia = _attrs('<iclass ' + im.group(1) + '>')
            rd = re.search(r'<regdiagram([^>]*)>(.*?)</regdiagram>', ic, re.S)
            boxes = []
            psname = ''
            if rd:
                psname = _attrs('<x' + rd.group(1) + '>').get('psname', '')
                for bm in re.finditer(r'<box ([^>]*)>(.*?)</box>', rd.group(2), re.S):
                    ba = _attrs('<box ' + bm.group(1) + '>')
                    cells = re.findall(r'<c[^>]*>(.*?)</c>', bm.group(2), re.S)
                    boxes.append({'hibit': int(ba['hibit']), 'width': int(ba.get('width', '1')),
                                  'name': ba.get('name'), 'cells': [strip_ps(c).strip() for c in cells]})
            encs = []
            for em in re.finditer(r'<encoding ([^>]*)>(.*?)</encoding>', ic, re.S):
                ea = _attrs('<encoding ' + em.group(1) + '>')
                ebox = []
                for bm in re.finditer(r'<box ([^>]*)>(.*?)</box>', em.group(2), re.S):
                    ba = _attrs('<box ' + bm.group(1) + '>')
                    cells = re.findall(r'<c[^>]*>(.*?)</c>', bm.group(2), re.S)
                    ebox.append({'hibit': int(ba['hibit']), 'width': int(ba.get('width', '1')),
                                 'name': ba.get('name'), 'cells': [strip_ps(c).strip() for c in cells]})
                dv = dict(re.findall(r'<docvar key="([^"]*)" value="([^"]*)" />', em.group(2)))
                encs.append({'name': ea.get('name', ''), 'label': ea.get('label', ''),
                             'boxes': ebox, 'docvars': dv})
            # iclass-local ps sections (decode)
            ic_ps = []
            for m in re.finditer(r'<ps ([^>]*)>\s*<pstext([^>]*)>(.*?)</pstext>', ic, re.S):
                a = _attrs('<ps ' + m.group(1) + '>')
                b = _attrs('<x' + m.group(2) + '>')
                ic_ps.append({'name': a.get('name', ''), 'sect': b.get('rep_section', ''),
                              'text': strip_ps(m.group(3))})
            iclasses.append({'name': ia.get('name', ''), 'psname': psname, 'boxes': boxes,
                             'encs': encs, 'ps': ic_ps})
        idx['files'][base] = {'iclasses': iclasses, 'top_ps': top_ps}
        for ci, ic in enumerate(iclasses):
            for ei, e in enumerate(ic['encs']):
                idx['enc'][e['name']] = (base, ci, ei)
    return idx


def load_index():
    if os.path.exists(CACHE):
        with open(CACHE, 'rb') as f:
            return pickle.load(f)
    idx = build_index()
    with open(CACHE, 'wb') as f:
        pickle.dump(idx, f, 2)
    return idx


# ------------------------------------------------------------ shared library
SHCACHE = '/mnt/md0/QEMU/cst_runs/_arc3_cov/aarch64/asl/mra_shared.pkl'

SIGN_RE = re.compile(
    r'^(?P<ret>(?:[A-Za-z_][A-Za-z_0-9.]*\s*(?:\([^)]*\))?\s*)*?)'
    r'(?P<name>[A-Za-z_][A-Za-z_0-9.]*)\s*\((?P<args>[^)]*)\)\s*$')


def build_shared():
    d = open(os.path.join(XMLDIR, 'shared_pseudocode.xml'), encoding='utf-8',
             errors='replace').read()
    funcs = {}
    for m in re.finditer(r'<pstext([^>]*)>(.*?)</pstext>', d, re.S):
        text = strip_ps(m.group(2))
        _harvest(text, funcs)
    return funcs


def _harvest(text, funcs):
    lines = text.split('\n')
    i = 0
    while i < len(lines):
        ln = lines[i]
        if not ln or ln[0] in ' \t' or ln.lstrip().startswith('//'):
            i += 1
            continue
        s = ln.rstrip()
        if s.endswith(';'):
            i += 1                       # bare declaration, no body
            continue
        sig = _parse_sig(s)
        if sig is None:
            i += 1
            continue
        name, params, kind = sig
        j = i + 1
        body = []
        while j < len(lines):
            l2 = lines[j]
            if l2.strip() == '':
                body.append('')
                j += 1
                continue
            if l2[0] not in ' \t':
                break
            body.append(l2)
            j += 1
        key = (name, len(params), kind)
        funcs.setdefault(key, (params, '\n'.join(body)))
        i = j


def _find_open(s, close_at):
    """Index of the bracket matching the one that closes at close_at."""
    depth = 0
    for i in range(close_at, -1, -1):
        c = s[i]
        if c in ')]':
            depth += 1
        elif c in '([':
            depth -= 1
            if depth == 0:
                return i
    return None


IDENT_END = re.compile(r'([A-Za-z_][A-Za-z_0-9.]*)$')


def _parse_sig(s):
    """Return (name, [param names], kind) for a function/accessor header."""
    s = s.strip()
    if not s or s.startswith('//'):
        return None
    # setter accessor:  NAME[args] = <type> value
    eq = _top_eq(s)
    if eq is not None:
        lhs, rhs = s[:eq].rstrip(), s[eq+1:].strip()
        if lhs.endswith(']'):
            op = _find_open(lhs, len(lhs) - 1)
            if op is None:
                return None
            m = IDENT_END.search(lhs[:op])
            if m is None:
                return None
            params = _params(lhs[op+1:-1])
            vm = re.search(r'([A-Za-z_][A-Za-z_0-9]*)$', rhs)
            if vm:
                params = params + [vm.group(1)]
            return m.group(1), params, 'set'
        return None
    if s.endswith(']'):
        op = _find_open(s, len(s) - 1)
        if op is None:
            return None
        m = IDENT_END.search(s[:op])
        if m is None or not s[:op][:m.start()].strip():
            return None
        return m.group(1), _params(s[op+1:-1]), 'get'
    if s.endswith(')'):
        op = _find_open(s, len(s) - 1)
        if op is None:
            return None
        m = IDENT_END.search(s[:op])
        if m is None:
            return None
        head = s[:op][:m.start()].strip()
        if head and not re.fullmatch(r'[A-Za-z_0-9 ,()<>:\[\]*+-]*', head):
            return None
        return m.group(1), _params(s[op+1:-1]), 'func'
    return None


def _top_eq(s):
    depth, inq = 0, False
    for i, ch in enumerate(s):
        if ch == "'":
            inq = not inq
            continue
        if inq:
            continue
        if ch in '([':
            depth += 1
        elif ch in ')]':
            depth -= 1
        elif ch == '=' and depth == 0:
            if s[i-1] in '=!<>' or (i + 1 < len(s) and s[i+1] == '='):
                continue
            return i
    return None


def _params(s):
    out = []
    for p in s.split(','):
        p = p.strip()
        if not p:
            continue
        w = p.split()
        out.append(w[-1] if len(w) > 1 else w[0])
    return out


def load_shared():
    if os.path.exists(SHCACHE):
        with open(SHCACHE, 'rb') as f:
            return pickle.load(f)
    fs = build_shared()
    with open(SHCACHE, 'wb') as f:
        pickle.dump(fs, f, 2)
    return fs
