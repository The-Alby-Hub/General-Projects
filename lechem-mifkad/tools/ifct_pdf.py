#!/usr/bin/env python3
"""Read Table 1 (Proximate Principles and Dietary Fibre) of IFCT 2017 from its PDF.

IFCT 2017 = Indian Food Composition Tables, ICMR-National Institute of Nutrition (Longvah et al.).
The PDF has a real text layer, so this reads text with its position on the page and rebuilds the
table rows. Standard library only (zlib + re). It knows just enough PDF to read this file:
objects, Flate streams, ToUnicode maps and the text operators.

read_table1(path) -> list of dicts, one per food (528 in the book), each with:
    code, name, sci, group ('plant' | 'animal'), page (book page), regions (number sampled),
    raw (the printed cells, e.g. '9.20±0.40'), and means: water, protein, ash, fat, kj,
    plus fibre, fib_ins, fib_sol, carbs on plant pages (None where the cell is blank).
Plant pages (groups A–L) have 9 value columns; egg, poultry, meat and fish pages (M–S) have no
carbohydrate or fibre columns at all.

Run directly to print every row:  python3 lechem-mifkad/tools/ifct_pdf.py
"""
import re
import sys
import zlib
from pathlib import Path

PLANT_COLS = ['water', 'protein', 'ash', 'fat', 'fibre', 'fib_ins', 'fib_sol', 'carbs', 'kj']
ANIMAL_COLS = ['water', 'protein', 'ash', 'fat', 'kj']
CODE = re.compile(r'^([A-S]\d{3})\b\s*(.*)$')

# Two rows (Paneer, Khoa) are kerned letter by letter in the PDF, so their cells come out as
# fragments at overlapping positions. These are those fragments reassembled by hand; the parser
# checks that the row's raw fragments still contain exactly these digits before using them.
KERNED = {
    'L003': ['6', '51.96±0.76', '18.86±0.75', '1.98±0.08', '24.78±0.17', '2.41±0.12', '1278±61'],
    'L004': ['6', '42.51±0.21', '16.34±0.61', '4.00±0.14', '20.62±0.83', '16.53±1.26', '1322±14'],
}


class Pdf:
    def __init__(self, path):
        self.d = Path(path).read_bytes()
        self.offsets = {int(m.group(1)): m.end() for m in re.finditer(rb'(\d+)\s+0\s+obj\b', self.d)}

    def obj(self, n):
        s = self.offsets[n]
        return self.d[s:self.d.find(b'endobj', s)]

    def stream(self, n):
        o = self.obj(n)
        i = o.find(b'stream')
        if i < 0:
            return b''
        j = i + 6
        j += 2 if o[j:j + 2] == b'\r\n' else (1 if o[j:j + 1] in b'\r\n' else 0)
        raw = o[j:o.rfind(b'endstream')]
        return zlib.decompressobj().decompress(raw) if b'FlateDecode' in o[:i] else raw

    @staticmethod
    def ref(o, key):
        m = re.search(rb'/' + key + rb'\s*(\d+)\s+0\s+R', o)
        return int(m.group(1)) if m else None

    def refs(self, o, key):
        m = re.search(rb'/' + key + rb'\s*\[([^\]]*)\]', o)
        if m:
            return [int(x) for x in re.findall(rb'(\d+)\s+0\s+R', m.group(1))]
        r = self.ref(o, key)
        return [r] if r else []

    def dict_value(self, o, key):
        """The << … >> dictionary (inline or referenced) stored under /key in o."""
        i = o.find(b'/' + key)
        if i < 0:
            return None
        j = i + len(key) + 1
        while o[j:j + 1] in b' \r\n':
            j += 1
        if o[j:j + 2] == b'<<':
            depth, k = 0, j
            while k < len(o):
                if o[k:k + 2] == b'<<':
                    depth += 1
                    k += 2
                elif o[k:k + 2] == b'>>':
                    depth -= 1
                    k += 2
                    if depth == 0:
                        return o[j:k]
                else:
                    k += 1
        m = re.match(rb'(\d+)\s+0\s+R', o[j:])
        return self.obj(int(m.group(1))) if m else None

    def pages(self):
        root = self.ref(self.d[self.d.rfind(b'trailer'):], b'Root')

        def walk(n):
            o = self.obj(n)
            if re.search(rb'/Type\s*/Pages', o):
                return [p for k in self.refs(o, b'Kids') for p in walk(k)]
            return [n]
        return walk(self.ref(self.obj(root), b'Pages'))

    def cmap(self, n):
        s, m = self.stream(n), {}
        for blk in re.findall(rb'beginbfchar(.*?)endbfchar', s, re.S):
            for a, b in re.findall(rb'<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>', blk):
                m[int(a, 16)] = bytes.fromhex(b.decode()).decode('utf-16-be', 'replace')
        for blk in re.findall(rb'beginbfrange(.*?)endbfrange', s, re.S):
            for a, b, c in re.findall(rb'<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>', blk):
                for i, code in enumerate(range(int(a, 16), int(b, 16) + 1)):
                    m[code] = chr(int(c, 16) + i)
        width = 2 if re.search(rb'begincodespacerange\s*<[0-9A-Fa-f]{4}>', s) else 1
        return m, width

    def fonts(self, page):
        o = self.obj(page)
        res = self.dict_value(o, b'Resources')
        while res is None:
            o = self.obj(self.ref(o, b'Parent'))
            res = self.dict_value(o, b'Resources')
        out = {}
        for name, num in re.findall(rb'/([\w.+-]+)\s+(\d+)\s+0\s+R', self.dict_value(res, b'Font') or b''):
            fo = self.obj(int(num))
            tu = self.ref(fo, b'ToUnicode')
            out[name.decode()] = self.cmap(tu) if tu else ({}, 2 if b'Type0' in fo else 1)
        return out


TOKEN = re.compile(rb'\((?:\\.|[^\\)])*\)|<[0-9A-Fa-f\s]*>|\[|\]|/[^\s/\[\]()<>]+|[-+]?\d*\.?\d+|[A-Za-z\'"*]+|<<|>>')
NUMBER = re.compile(rb'[-+]?\d*\.?\d+$')


def _unescape(s):
    out, i = bytearray(), 0
    while i < len(s):
        c = s[i]
        if c == 92:  # backslash
            i += 1
            c = s[i]
            if c in b'nrtbf':
                out += {110: b'\n', 114: b'\r', 116: b'\t', 98: b'\b', 102: b'\f'}[c]
            elif 48 <= c <= 55:
                j = i
                while j < len(s) and j < i + 3 and 48 <= s[j] <= 55:
                    j += 1
                out.append(int(s[i:j], 8) & 255)
                i = j
                continue
            elif c not in b'\r\n':
                out.append(c)
        else:
            out.append(c)
        i += 1
    return bytes(out)


def _decode(bs, font):
    m, width = font
    codes = [int.from_bytes(bs[i:i + 2], 'big') for i in range(0, len(bs) - 1, 2)] if width == 2 else list(bs)
    return ''.join(m.get(c, chr(c) if width == 1 else '?') for c in codes)


def page_text(pdf, page):
    """Text runs on a page as (x, y, text), in content-stream order."""
    fonts = pdf.fonts(page)
    content = b''.join(pdf.stream(n) for n in pdf.refs(pdf.obj(page), b'Contents'))
    runs, stack, font = [], [], ({}, 1)
    tm, lm, lead = [1, 0, 0, 1, 0, 0], [0, 0], 0
    ctm, saved = [0, 0], []
    for t in (m.group() for m in TOKEN.finditer(content)):
        if t == b'[':
            stack.append('[')
            continue
        if t == b']':
            arr = []
            while stack and stack[-1] != '[':
                arr.append(stack.pop())
            if stack:
                stack.pop()
            stack.append(arr[::-1])
            continue
        if t[:1] in b'(</' or NUMBER.match(t):
            stack.append(t)
            continue
        op, a, stack = t.decode(errors='replace'), stack, []
        f = lambda x: float(x)
        if op == 'q':
            saved.append(ctm[:])
        elif op == 'Q':
            ctm = saved.pop() if saved else ctm
        elif op == 'cm' and len(a) >= 6:
            ctm = [ctm[0] + f(a[-2]), ctm[1] + f(a[-1])]
        elif op == 'BT':
            tm, lm = [1, 0, 0, 1, 0, 0], [0, 0]
        elif op == 'Tf' and len(a) >= 2:
            font = fonts.get(a[-2][1:].decode(), ({}, 1))
        elif op == 'TL':
            lead = f(a[-1])
        elif op in ('Td', 'TD'):
            tx, ty = f(a[-2]), f(a[-1])
            if op == 'TD':
                lead = -ty
            lm = [lm[0] + tx * tm[0] + ty * tm[2], lm[1] + tx * tm[1] + ty * tm[3]]
            tm[4], tm[5] = lm
        elif op == 'Tm':
            tm = [f(x) for x in a[-6:]]
            lm = [tm[4], tm[5]]
        elif op in ('T*', "'", '"', 'Tj', 'TJ'):
            if op in ('T*', "'", '"'):
                lm = [lm[0] - lead * tm[2], lm[1] - lead * tm[3]]
                tm[4], tm[5] = lm
            if op == 'T*':
                continue
            items = a[-1] if op == 'TJ' else [a[-1]]
            s = ''
            for it in items if isinstance(items, list) else [items]:
                if not isinstance(it, bytes):
                    continue
                if it[:1] == b'(':
                    s += _decode(_unescape(it[1:-1]), font)
                elif it[:1] == b'<':
                    s += _decode(bytes.fromhex(re.sub(rb'\s', b'', it[1:-1]).decode()), font)
                elif NUMBER.match(it) and float(it) < -250:  # a wide kerning gap is a space
                    s += ' '
            runs.append((round(tm[4] + ctm[0], 1), round(tm[5] + ctm[1], 1), s))
    return runs


def _mean(cell):
    return float(cell.split('±')[0])


def _split_name(text, code):
    """'Bajra (Pennisetum typhoideum)' -> ('Bajra', 'Pennisetum typhoideum'). Egg, poultry and meat rows
    (M, N, O) print no scientific names, so their brackets stay in the name: 'Goat, tube (small intestine)'."""
    text = re.sub(r'\s+', ' ', text).strip()
    text = re.sub(r'\(\s*\)\s*(.+)$', r'(\1)', text)  # "Avocado fruit ( ) Persea sp." -> "(Persea sp.)"
    text = re.sub(r'\(\s+', '(', text)
    text = re.sub(r'\s+\)', ')', text)
    if code[0] in 'MNO':
        return text.strip(' ,'), ''
    m = re.match(r'^(.*)\(([^()]*)\)?\s*$', text)
    if m and m.group(1).strip():
        return m.group(1).strip(' ,'), m.group(2).strip()
    return text.strip(' ,'), ''


def read_table1(path):
    pdf = Pdf(path)
    foods = []
    for page in pdf.pages():
        runs = [(x, y, s.strip()) for x, y, s in page_text(pdf, page) if s.strip()]
        header = ' '.join(s for _, _, s in runs[:40])
        if 'WATER PROTCNT' not in header:
            continue
        group = 'plant' if 'CHOAVLDF' in header else 'animal'
        cols = PLANT_COLS if group == 'plant' else ANIMAL_COLS
        # Page number and running header sit in the left margin (x = 32).
        book_page = next((int(s) for x, y, s in runs if x < 40 and s.isdigit()), None)
        runs = [r for r in runs if r[0] >= 40 and not r[2].startswith('Table 1.')]
        code_x = min((x for x, y, s in runs if CODE.match(s)), default=0)
        value_x = 270 if group == 'plant' else 295
        rows = []
        for x, y, s in runs:
            m = CODE.match(s)
            if m and x < code_x + 5:
                rows.append({'y': y, 'code': m.group(1), 'name': [(y, x, m.group(2))], 'vals': []})
        for x, y, s in runs:
            if (CODE.match(s) and x < code_x + 5) or not rows:
                continue
            row = min(rows, key=lambda r: abs(r['y'] - y))
            if abs(row['y'] - y) > 12:
                continue
            if x >= value_x and abs(row['y'] - y) < 2:
                row['vals'].append((x, s))
            elif x < value_x and not s.isupper():  # skip group headings such as "N POULTRY"
                row['name'].append((y, x, s))
        for r in rows:
            code = r['code']
            fragments = ' '.join(s for x, s in sorted(r['vals']))
            if code in KERNED:
                want = re.sub(r'\D', '', ''.join(KERNED[code]))
                if sorted(re.sub(r'\D', '', fragments)) != sorted(want):
                    raise SystemExit(f'IFCT {code}: kerned cells changed ({fragments!r}); check KERNED')
                cells = KERNED[code]
            else:
                cells = fragments.split()
            if len(cells) == len(cols) + 1:
                vals = dict(zip(cols, cells[1:]))
            elif group == 'plant' and len(cells) == 7:
                # The three dietary-fibre cells are blank: below detectable limit.
                vals = dict(zip(['water', 'protein', 'ash', 'fat', 'carbs', 'kj'], cells[1:]))
                vals.update(fibre=None, fib_ins=None, fib_sol=None)
            else:
                raise SystemExit(f'IFCT {code}: could not read cells {cells}')
            name_text = ' '.join(s for y, x, s in sorted(r['name'], key=lambda p: (-p[0], p[1])) if s)
            name, sci = _split_name(name_text, code)
            food = {'code': code, 'name': name, 'sci': sci, 'group': group, 'page': book_page,
                    'regions': int(cells[0]), 'raw': cells[1:]}
            food.update({k: (_mean(v) if v else None) for k, v in vals.items()})
            foods.append(food)
    return foods


if __name__ == '__main__':
    path = sys.argv[1] if len(sys.argv) > 1 else Path(__file__).resolve().parent.parent / 'data' / 'IFCT2017_Table1.pdf'
    for f in read_table1(path):
        print(f['code'], f['page'], f['name'], '|', f['sci'], '|', ' '.join(f['raw']))
