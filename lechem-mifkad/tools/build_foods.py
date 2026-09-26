#!/usr/bin/env python3
"""Build Lechem Mifkad's food list.

Reads   data/INDB.xlsx              Indian Nutrient Databank (1,014 recipes, per 100 g)
        data/phase1-seed-foods.json the 100 Phase 1 foods (kept unless replaced)
        data/seed-map.json          Phase 1 id -> INDB code that replaces it (old ids keep working)
        data/estimates.json         foods INDB lacks (source: estimate)
        data/oil-adjust.json        fried INDB dishes to correct for unabsorbed frying oil
        data/aliases.json           search synonyms, aliases, everyday list, name/unit/category fixes
Writes  index.html                  the <script id="seed-foods"> block
        data/import-report.md       what was imported, changed, flagged and why

Standard library only. Run from anywhere:  python3 lechem-mifkad/tools/build_foods.py
To add another source later (e.g. raw foods), load it like estimates.json with its own
`source` value and append to `foods` before the checks run.
"""
import json
import re
import sys
import zipfile
import xml.etree.ElementTree as ET
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / 'data'
HTML = ROOT / 'index.html'
MAX_BYTES = 16 * 1024 * 1024
NUTRIENTS = ['kcal', 'protein', 'carbs', 'fat', 'fibre']
INDB_COLS = {'kcal': 'energy_kcal', 'protein': 'protein_g', 'carbs': 'carb_g', 'fat': 'fat_g', 'fibre': 'fibre_g'}

# INDB rows whose values look wrong for reasons other than frying oil. Kept as INDB, flagged in the app.
OTHER_FLAGS = {
    'ASC056': 'INDB lists 45 kcal/100 g, about a third of a real boiled egg (about 150). Cooking water may be counted. Use "Boiled egg" (estimate) instead.',
}


# ---------------------------------------------------------------- xlsx reading
def read_xlsx(path):
    ns = {'m': 'http://schemas.openxmlformats.org/spreadsheetml/2006/main',
          'r': 'http://schemas.openxmlformats.org/officeDocument/2006/relationships'}
    z = zipfile.ZipFile(path)
    shared = []
    if 'xl/sharedStrings.xml' in z.namelist():
        for si in ET.fromstring(z.read('xl/sharedStrings.xml')).findall('m:si', ns):
            shared.append(''.join(t.text or '' for t in si.iter('{%s}t' % ns['m'])))
    wb = ET.fromstring(z.read('xl/workbook.xml'))
    rels = {r.get('Id'): r.get('Target') for r in ET.fromstring(z.read('xl/_rels/workbook.xml.rels'))}
    sheet = wb.find('m:sheets', ns)[0]
    target = rels[sheet.get('{%s}id' % ns['r'])].lstrip('/')
    target = target if target.startswith('xl/') else 'xl/' + target

    def col(ref):
        n = 0
        for ch in re.match(r'[A-Z]+', ref).group():
            n = n * 26 + ord(ch) - 64
        return n - 1

    rows = []
    for row in ET.fromstring(z.read(target)).iter('{%s}row' % ns['m']):
        cells = {}
        for c in row.findall('m:c', ns):
            t, v = c.get('t'), c.find('m:v', ns)
            if t == 's':
                val = shared[int(v.text)]
            elif t == 'inlineStr':
                val = ''.join(x.text or '' for x in c.iter('{%s}t' % ns['m']))
            elif v is None:
                val = None
            else:
                try:
                    val = float(v.text)
                except ValueError:
                    val = v.text
            cells[col(c.get('r'))] = val
        rows.append([cells.get(i) for i in range(max(cells) + 1)] if cells else [])
    header = [str(h).strip() for h in rows[0]]
    return [dict(zip(header, r + [None] * (len(header) - len(r)))) for r in rows[1:] if r]


# ---------------------------------------------------------------- helpers
def load(name):
    return json.loads((DATA / name).read_text(encoding='utf-8'))


def r1(x):
    return round(x + 0.0, 1)


def atwater(p):
    return 4 * p['protein'] + 4 * p['carbs'] + 9 * p['fat']


def kcal_off(p):
    """True when listed kcal differs from 4/4/9 by more than 15% and more than 20 kcal."""
    est = atwater(p)
    return abs(p['kcal'] - est) > max(20, 0.15 * max(p['kcal'], est))


def norm(s):
    return re.sub(r'\s+', ' ', re.sub(r'[^a-z0-9 ]+', ' ', s.lower())).strip()


def clean_name(s):
    s = s.replace('\xa0', ' ')
    s = re.sub(r'\s+', ' ', s).strip()
    s = re.sub(r'\(\s+', '(', s)
    s = re.sub(r'\s+\)', ')', s)
    return s


def aliases_from_name(name):
    """'Curd rice (Dahi bhaat/Dahi chawal/ Perugu annam)' -> ['dahi bhaat', 'dahi chawal', 'perugu annam']."""
    out = []
    for inner in re.findall(r'\(([^()]*)\)', name):
        for part in re.split(r'[/,;]', inner):
            part = part.strip()
            if len(part) > 2 and not re.fullmatch(r'(with|without|dry|wet|curry|toasted|steamed|baked|thin|thick|medium|salted|restaurant)\b.*', part.lower()):
                out.append(part)
    main = re.sub(r'\([^()]*\)', ' ', name)
    if '/' in main:
        out += [p.strip() for p in main.split('/') if len(p.strip()) > 2]
    return out


def uniq(items, skip=()):
    seen, out = {norm(s) for s in skip}, []
    for s in items:
        k = norm(s)
        if k and k not in seen:
            seen.add(k)
            out.append(s)
    return out


# ---------------------------------------------------------------- categories
def has(name, *words):
    n = ' ' + norm(name) + ' '
    return any((' ' + w) in n for w in words)


def categorise(code, name, overrides):
    if overrides.get(code):
        return overrides[code]
    num = int(re.sub(r'\D', '', code))
    if code.startswith('BFP') and 546 <= num <= 560:
        return 'infant'
    if has(name, 'soup', 'consomme', 'stock'):
        return 'soup'
    drinkish = has(name, 'tea', 'coffee', 'cocoa', 'hot chocolate', 'milkshake', 'lassi', 'cooler', 'lemonade', 'lem o gin',
                   'punch', 'panna', 'sharbat', 'juice', 'drink', 'thandai', 'smoothie', 'egg nog', 'jal jeera', 'kehwa', 'canjee',
                   'mintade', 'gingo', 'squash', 'infused water', 'saffron milk', 'cold coffee')
    not_drink = has(name, 'souffle', 'biscuit', 'cookie', 'cake', 'drops', 'pudding', 'mousse', 'alaska', 'sundae', 'sorbet') or \
        (has(name, 'ice cream') and not has(name, 'milkshake', 'cold coffee'))
    if drinkish and not not_drink:
        return 'drink'
    low = name.lower()
    condiment = has(name, 'chutney', 'pickle', 'achaar', 'achar', 'aachar', 'murabba', 'marmalade', 'preserves', 'ketchup',
                    'baghar', 'icing', 'frosting', 'dressing', 'mayonnaise', 'spice blend') or \
        re.search(r'\b(sauce|jam|jelly|masala|filling|candy|dip|puree|powder)\s*(\([^()]*\))?\s*$', low)
    if condiment and not re.search(r'\b(with|in|and)\b.*\b(sauce|dressing|icing|baghar)\b', low) and \
            not has(name, 'sandwich', 'pancake', 'tart', 'cake', 'salad', 'lasagne', 'pasta', 'fettuccine', 'ice cream', 'chops',
                    'arbi', 'pakora', 'pakoda', 'dosa', 'vada', 'oats', 'paneer', 'chicken', 'fish', 'shahi', 'tomato fish'):
        return 'chutney'
    if has(name, 'souffle') and has(name, 'cheese', 'potato', 'fish', 'spinach', 'masala', 'chicken', 'paneer'):
        return 'continental'
    if has(name, 'cake', 'cookie', 'biscuit', 'pastry', 'tart', 'eclair', 'clair', 'gateau', 'swiss roll', 'flan', 'horn',
           'cream buns', 'straws', 'shells', 'swans', 'aigrette', 'meringue', 'pavlova', 'mousse', 'pudding', 'custard',
           'ice cream', 'sundae', 'trifle', 'triffle', 'fool', 'whip', 'bavarian', 'charlotte', 'loaf', 'cream puffs', 'souffle',
           'alaska', 'melba', 'sorbet', 'butterscotch', 'fruit delight', 'fruit salad', 'coffee drops', 'finger',
           'stewed', 'apple snowballs', 'orange and pineapple cream', 'honey banana cream', 'snow flakes', 'mould'):
        return 'bakery'
    if has(name, 'sandwich', 'toast', 'pizza', 'burger', 'pasta', 'spaghetti', 'macaroni', 'macroni', 'lasagne', 'fettuccine',
           'penne', 'noodle', 'casserole', 'pie', 'patties', 'salad', 'au gratin', 'baked', 'roast', 'fricassee', 'cajun',
           'lemon butter', 'orly', 'steak', 'nests', 'ducheese', 'parsley', 'spanish rice', 'mexican rice', 'stew',
           'fish finger', 'chips', 'deviled', 'bacon', 'cheese balls', 'creamed', 'broccoli', 'musallam', 'basket',
           'towers', 'aspic', 'ala king', 'lemon chicken', 'shepherd', 'black beans', 'sauteed', 'scotch egg', 'cabbage rolls'):
        return 'continental'
    if has(name, 'kheer', 'halwa', 'burfi', 'ladoo', 'jamun', 'rasgulla', 'rasmalai', 'chum chum', 'dil bahar', 'rasbhari',
           'rajbogh', 'phirni', 'kulfi', 'mal pua', 'malpua', 'gunjia', 'ghujia', 'shahi tukre', 'chikki', 'brittle', 'murki',
           'milk cake', 'payasam', 'shrikhand', 'rabri', 'chhena poda', 'putharekulu', 'kesari', 'sweet rice', 'fudge',
           'couscous dessert', 'granola pudding', 'custard'):
        return 'sweet'
    if has(name, 'roti', 'chapati', 'parantha', 'paratha', 'poori', 'naan', 'bhatura', 'thepla', 'kulcha', 'khakhra'):
        return 'bread'
    if has(name, 'idli', 'dosa', 'uttapam', 'appam', 'upma', 'pesarattu', 'puttu', 'pongal'):
        return 'south'
    if has(name, 'rice', 'pulao', 'biryani', 'biriyani', 'khichdi', 'khichri', 'khitchdi', 'tahar', 'bhat'):
        return 'rice'
    if has(name, 'chicken', 'mutton', 'fish', 'prawn', 'keema', 'minced meat', 'meat', 'lamb', 'salami', 'ham ', 'machli',
           'gushtaba', 'roghan josh', 'chops', 'boti', 'fillet'):
        return 'meat'
    if has(name, 'egg', 'omelette', 'omlet'):
        return 'egg'
    if has(name, 'raita', 'curd', 'dahi', 'yogurt'):
        return 'dairy'
    if has(name, 'pakora', 'pakoda', 'samosa', 'cutlet', 'kachori', 'mathri', 'namak paras', 'dhokla', 'cheela', 'chilla',
           'poha', 'sev ', 'papdi', 'bhel', 'chaat', 'chat', 'tikki', 'bonda', 'muthia', 'vada', 'handvo', 'murukku', 'chips',
           'murmura', 'flakes', 'porridge', 'daliya', 'dalia', 'oats', 'pancake', 'spring roll', 'kebab', 'kabab', 'khandvi',
           'jave', 'premix', 'mixture', 'fritters', 'sprout', 'patty', 'patties', 'jackfruit fritters', 'banana chips'):
        return 'snack'
    if has(name, 'paneer'):
        return 'paneer'
    if has(name, 'dal', 'sambar', 'rasam', 'kadhi', 'channa', 'chana', 'chickpea', 'rajmah', 'lobia', 'soyabean curry',
           'moong', 'masoor', 'moth', 'urad', 'dhansak', 'dalma', 'gatte', 'lentil', 'arhar'):
        return 'dal'
    return 'sabzi'


LOW_RANK_WORDS = ('stock', 'sauce', 'dressing', 'icing', 'frosting', 'filling', 'masala', 'baghar', 'puree', 'premix',
                  'short crust', 'choux pastry', 'flaky pastry', 'spice blend', 'gravy for kofta', 'mayonnaise', 'squash',
                  'jelly', 'jam', 'marmalade', 'murabba', 'preserves', 'candy', 'dip')


def tier_for(code, name, category, everyday, seed_codes, flags):
    if code in everyday or code in seed_codes:
        return 'D' if 'kcal' in flags else 'A'
    if category == 'infant' or 'kcal' in flags or 'water' in flags or has(name, *LOW_RANK_WORDS):
        return 'D'
    if category in ('bakery', 'continental'):
        return 'C'
    return 'B'


# ---------------------------------------------------------------- units
KATORI = {'dal': 150, 'rice': 130, 'sabzi': 120, 'paneer': 150, 'meat': 150, 'egg': 150, 'soup': 150, 'sweet': 120,
          'dairy': 120, 'snack': 150, 'south': 150, 'continental': 150, 'indochinese': 150, 'street': 150,
          'infant': 100, 'bakery': 120}
TBSP_TOO = {'dal', 'rice', 'sabzi', 'paneer', 'meat', 'dairy', 'sweet', 'egg', 'indochinese'}
COUNT_UNITS = {'piece', 'biscuit', 'cookie', 'cookies', 'slice', 'large slice', 'sandwich', 'triangle', 'toasted triangle',
               'egg', 'omelette', 'cutlet', 'poori', 'pancake', 'ladoo', 'burfi', 'vada', 'tart', 'cheela', 'dosa', 'pastry',
               'idli', 'kabab', 'kebab', 'samosa', 'patty', 'pakora', 'kofta', 'kachori', 'roll', 'uttapam', 'gunjia', 'puff',
               'appam', 'dhokla', 'square', 'horn', 'swiss roll', 'fillet', 'chop', 'chops', 'gushtaba', 'gulab jamun',
               'malqura', 'tukra', 'bonda', 'toast', 'burger', 'spring roll', 'éclair', 'finger', 'muthia', 'tikki', 'kulfi',
               'naan', 'bhatura', 'kaathi roll', 'capsicum', 'brinjal', 'tomato', 'stuffed tomato', 'potato', 'chicken breast',
               'cauliflower steak', 'joint', 'nest', 'basket', 'meringue', 'ribbon', 'hot dog bun', 'gingerman', 'small',
               'shell', 'straw', 'bun', 'swan', 'aigrette', 'candy', 'khakhra', 'pesarattu', 'thepla', 'puttu',
               'mulik/fritter', 'bread roll', 'large piece', 'parantha', 'fish', 'chicken', 'pie', 'cake'}
ROTI_UNITS = {'roti', 'chapati'}
CUP_UNITS = {'cup', 'tea cup', 'glass', 'tall glass', 'juice glass'}
UNIT_LABEL_FIX = {'ice-cream cup': 'ice cream cup', 'kabab': 'kebab', 'malqura': 'malpua', 'half-pints': 'half-pint jar',
                  'mulik/fritter': 'fritter', 'small': 'piece', 'cookies': 'cookie', 'portion': 'portion'}


def build_units(category, unit_name, grams, liquid):
    """Returns (units, serving_label, note). grams is the INDB serving weight (already oil-adjusted), or None."""
    units, label, note = {}, None, None
    u = (unit_name or '').strip().lower()
    ok = grams is not None and 10 <= grams <= 600
    if u and grams is not None and not ok:
        note = f'INDB serving "{u}" of {grams:.0f} g not used (outside 10–600 g)'
    if u in ROTI_UNITS and ok:
        units['roti'] = round(grams)
    elif u in COUNT_UNITS and grams is not None and 5 <= grams <= 400:
        units['piece'] = round(grams)
    elif u == 'tablespoon' and grams is not None:
        units['tbsp'] = round(grams) if 5 <= grams <= 40 else 15
    elif u in CUP_UNITS and category in ('drink', 'soup'):
        units['cup'] = round(grams) if grams is not None and 100 <= grams <= 400 else 240
    elif u and u not in ('gm', 'ml', 'teaspoon') and ok:
        units['serving'] = round(grams)
        label = UNIT_LABEL_FIX.get(u, u)
    if category in KATORI and 'piece' not in units and 'roti' not in units and category != 'bakery':
        units['katori'] = KATORI[category]
        if category in TBSP_TOO:
            units.setdefault('tbsp', 15)
    if category in ('drink', 'soup'):
        units.setdefault('cup', 240)
    if category == 'chutney':
        units.setdefault('tbsp', 15)
    units['g'] = 1
    return units, label, note


def default_unit(units, category):
    order = ['piece', 'roti', 'katori', 'cup', 'tbsp', 'serving', 'g']
    if category in ('drink',):
        order = ['cup', 'serving', 'g']
    if category == 'chutney':
        order = ['tbsp', 'piece', 'serving', 'g']
    return next(u for u in order if u in units)


# ---------------------------------------------------------------- oil adjustment
def oil_targets():
    out = {}
    for group, spec in load('oil-adjust.json')['targets'].items():
        for code in spec['codes']:
            if code in out:
                raise SystemExit(f'{code} appears twice in oil-adjust.json')
            out[code] = (spec['fat'], group)
    return out


def adjust_for_oil(per100, target):
    """Remove unabsorbed oil so fat = target g per 100 g; returns (new per100, factor on weights, oil removed g/100 g)."""
    F, T = per100['fat'], target
    E = (F - T) / (1 - T / 100)
    rest = 100 - E
    new = {k: per100[k] / rest * 100 for k in ('protein', 'carbs', 'fibre')}
    new['fat'] = T
    # Scale INDB's kcal by the share of 4/4/9 energy that remains, so rows whose kcal uses slightly
    # different factors stay consistent with their own listing (and never go negative).
    before = atwater(per100)
    after = 4 * per100['protein'] + 4 * per100['carbs'] + 9 * (F - E)
    new['kcal'] = per100['kcal'] * after / before / rest * 100
    return new, rest / 100, E


# ---------------------------------------------------------------- main build
def main():
    today = date.today().isoformat()
    rows = read_xlsx(DATA / 'INDB.xlsx')
    seeds = load('phase1-seed-foods.json')
    seed_by_id = {s['id']: s for s in seeds}
    seed_map = load('seed-map.json')['map']
    code_to_seed = {code: sid for sid, code in seed_map.items() if code}
    estimates = load('estimates.json')['foods']
    al = load('aliases.json')
    everyday = set(al['everyday'])
    oil = oil_targets()
    rows_by_code = {r['food_code'].strip(): r for r in rows}
    for code in list(oil) + list(code_to_seed) + list(al['byCode']) + list(everyday):
        if code not in rows_by_code:
            raise SystemExit(f'Unknown INDB code {code}')

    foods, report = [], {'oil': [], 'oil_skipped': [], 'swap': [], 'serving_skipped': [], 'no_serving': [], 'kcal': [], 'kept_seed_piece': []}

    for r in rows:
        code = r['food_code'].strip()
        name = al['names'].get(code) or clean_name(r['food_name'])
        per100 = {k: float(r[c]) for k, c in INDB_COLS.items()}
        orig = dict(per100)
        g = None
        if r.get('unit_serving_energy_kcal') is not None and per100['kcal'] > 0:
            g = r['unit_serving_energy_kcal'] / per100['kcal'] * 100
        flags, notes, source = [], [], 'INDB'
        adjusted = None
        if code in oil and kcal_off(per100):
            # kcal already disagrees with the macros, so removing oil from it would compound the error.
            report['oil_skipped'].append((code, name))
        elif code in oil and per100['fat'] > oil[code][0] + 3:
            target, group = oil[code]
            per100, factor, removed = adjust_for_oil(per100, target)
            if g is not None:
                g *= factor
            adjusted = {'kcal': round(orig['kcal']), 'fat': r1(orig['fat'])}
            source = 'estimate'
            notes.append(f'Adjusted from INDB {code}: INDB counts all frying oil ({orig["kcal"]:.0f} kcal, {orig["fat"]:.0f} g fat per 100 g). '
                         f'Recalculated with {target} g fat per 100 g ({group}).')
            report['oil'].append((code, name, orig, per100, removed, group))
        if code in OTHER_FLAGS:
            flags.append('water')
            notes.append(OTHER_FLAGS[code])
        per100 = {k: (round(v) if k == 'kcal' else r1(v)) for k, v in per100.items()}
        if kcal_off(per100):
            flags.append('kcal')
        category = categorise(code, name, al['categories'])
        liquid = category in ('drink', 'soup')
        units, label, unote = build_units(category, r.get('servings_unit'), g, liquid)
        if unote:
            report['serving_skipped'].append((code, name, unote))
        if not r.get('servings_unit'):
            report['no_serving'].append((code, name))
        aliases = aliases_from_name(name) + al['byCode'].get(code, [])
        food = {'id': 'indb-' + code.lower(), 'name': name, 'aliases': [], 'category': category, 'per100g': per100,
                'units': units, 'defaultUnit': None, 'source': source, 'tier': None, 'ref': code}
        if liquid:
            food['liquid'] = True
        if label:
            food['serving'] = {'label': label}
        if adjusted:
            food['indb'] = adjusted
        seed_id = code_to_seed.get(code)
        if seed_id:
            seed = seed_by_id[seed_id]
            aliases = [seed['name']] + seed.get('aliases', []) + aliases
            for u, grams in seed['units'].items():
                if u in ('piece', 'roti') and u in units:
                    ratio = units[u] / grams
                    if not 0.5 <= ratio <= 2:
                        # Weights disagree a lot: keep whichever gives a per-piece kcal closer to Phase 1's.
                        want = grams * seed['per100g']['kcal'] / 100
                        pick = min((units[u], grams), key=lambda w: abs(w * per100['kcal'] / 100 - want))
                        report['kept_seed_piece'].append((seed_id, u, grams, units[u], pick, per100['kcal'], want))
                        units[u] = pick
                elif u not in units or u in ('katori', 'tbsp', 'cup'):
                    units[u] = grams
            if seed.get('liquid'):
                food['liquid'] = True
            food['defaultUnit'] = seed['defaultUnit'] if seed['defaultUnit'] in units else None
            report['swap'].append((seed_id, seed, code, food))
        units.update(al['units'].get(code, {}))  # explicit overrides win over INDB and Phase 1 weights
        food['aliases'] = uniq(aliases + al['byId'].get(food['id'], []), skip=[name])
        food['defaultUnit'] = food['defaultUnit'] or default_unit(units, category)
        food['tier'] = tier_for(code, name, category, everyday, code_to_seed, flags)
        if flags:
            food['flags'] = flags
        if notes:
            food['note'] = ' '.join(notes)
        foods.append(food)

    # Phase 1 foods with no INDB match stay, now labelled "estimate".
    for s in seeds:
        if seed_map[s['id']]:
            continue
        f = {**s, 'source': 'estimate', 'tier': 'A'}
        f['aliases'] = uniq(s.get('aliases', []) + al['byId'].get(s['id'], []), skip=[s['name']])
        if s['id'] == 'boiled-egg':
            f['note'] = 'Kept from Phase 1: INDB boiled egg (ASC056) lists 45 kcal/100 g, which is too low for an egg.'
        foods.append(f)

    for e in estimates:
        f = {**e, 'source': 'estimate'}
        f['aliases'] = uniq(e.get('aliases', []) + al['byId'].get(e['id'], []), skip=[e['name']])
        f['units'] = {**e['units'], 'g': 1}
        foods.append(f)

    # Checks: unique ids, valid shape, calories vs macros.
    ids = [f['id'] for f in foods]
    dup = {i for i in ids if ids.count(i) > 1}
    if dup:
        raise SystemExit(f'Duplicate ids: {sorted(dup)}')
    redirects = {sid: 'indb-' + code.lower() for sid, code in seed_map.items() if code}
    for f in foods:
        assert all(isinstance(f['per100g'][k], (int, float)) for k in NUTRIENTS), f['id']
        assert f['defaultUnit'] in f['units'], f['id']
        if 'serving' in f['units']:
            assert f.get('serving', {}).get('label'), f['id']
        if kcal_off(f['per100g']):
            f.setdefault('flags', [])
            if 'kcal' not in f['flags']:
                f['flags'].append('kcal')
            report['kcal'].append(f)

    payload = {'version': 2, 'built': today,
               'about': 'Built by tools/build_foods.py from data/. Edit the files in data/ and re-run; do not edit this block by hand.',
               'redirects': redirects, 'synonyms': al['synonyms'], 'foods': foods}
    block = '{\n"version": 2, "built": ' + json.dumps(today) + ',\n"about": ' + json.dumps(payload['about']) + \
            ',\n"redirects": ' + json.dumps(redirects, separators=(',', ':')) + \
            ',\n"synonyms": [\n' + ',\n'.join(json.dumps(s, ensure_ascii=False) for s in al['synonyms']) + \
            '\n],\n"foods": [\n' + ',\n'.join(json.dumps(f, ensure_ascii=False, separators=(',', ':')) for f in foods) + '\n]\n}'
    json.loads(block)  # must stay valid JSON
    html = HTML.read_text(encoding='utf-8')
    pat = re.compile(r'(<script type="application/json" id="seed-foods">\n).*?(\n</script>)', re.S)
    if not pat.search(html):
        raise SystemExit('seed-foods block not found in index.html')
    html = pat.sub(lambda m: m.group(1) + block.replace('</', '<\\/') + m.group(2), html, count=1)
    HTML.write_text(html, encoding='utf-8')
    size = HTML.stat().st_size
    if size > MAX_BYTES:
        raise SystemExit(f'index.html is {size:,} bytes, over the 16 MB limit')

    write_report(rows, foods, report, size, seed_map, seed_by_id, today)
    by_source = {}
    for f in foods:
        by_source[f['source']] = by_source.get(f['source'], 0) + 1
    print(f'{len(foods)} foods {by_source}; {len(report["oil"])} oil-adjusted; {len(report["kcal"])} calorie mismatches; '
          f'index.html {size / 1024:.0f} KB')


# ---------------------------------------------------------------- report
def write_report(rows, foods, rep, size, seed_map, seed_by_id, today):
    L = []
    w = L.append
    cats, srcs = {}, {}
    for f in foods:
        cats[f['category']] = cats.get(f['category'], 0) + 1
        srcs[f['source']] = srcs.get(f['source'], 0) + 1
    w(f'# Lechem Mifkad: food data import report\n')
    w(f'Built {today} by `tools/build_foods.py`. Re-running it regenerates this file.\n')
    w('## Summary\n')
    w(f'- **{len(foods)} foods** in the app: ' + ', '.join(f'{v} {k}' for k, v in sorted(srcs.items())) + '.')
    w(f'- INDB rows read: {len(rows)}. {len(rep["oil"])} fried dishes were corrected for frying oil (now labelled *estimate*, original INDB values kept on the food).')
    w(f'- Phase 1 foods: {sum(1 for v in seed_map.values() if v)} replaced by INDB matches (old ids redirect), '
      f'{sum(1 for v in seed_map.values() if not v)} kept as *estimate*.')
    w(f'- Calorie check (4/4/9 kcal per g protein/carbs/fat, flagged when off by more than 15% and more than 20 kcal): **{len(rep["kcal"])} foods flagged**, listed below, values unchanged.')
    w(f'- `index.html` size: {size / 1024:.0f} KB (limit 16 MB).')
    w('- Categories: ' + ', '.join(f'{k} {v}' for k, v in sorted(cats.items(), key=lambda x: -x[1])) + '.\n')

    w('## INDB file: what it contains\n')
    w('One sheet, *Nutrient Data*, 1,014 rows × 82 columns. `food_code` (ASC 490, BFP 376, OSR 148), `food_name`, '
      '`primarysource`; 39 nutrients per 100 g (energy kJ/kcal, macros in g, minerals mg, vitamins mg/µg; no blanks); '
      '`servings_unit`; the same 39 nutrients per serving. The app uses kcal, protein, carbs, fat and fibre.\n')
    w('**Problems found in the source**\n')
    w('1. 82 rows have no serving data; 15 more have serving numbers but no unit name (14 infant foods BFP546–560 and OSR112 Pav bhaji).')
    w('2. Serving weight isn\'t given; it is derived as serving kcal ÷ kcal per 100 g (every nutrient agrees). 57 servings are over 600 g '
      '(whole dishes, e.g. lasagne 1,775 g). Serving units are inconsistent ("bowl" is 47–1,020 g).')
    w('3. About 110 fried dishes count all the frying oil as eaten (poori 738 kcal/100 g with 78 g fat). Corrected, see below.')
    w('4. About 28 soups list ~30 kcal/100 g while their macros add up to 150–215 kcal, with 8–14 g sodium per 100 g. Flagged, not changed.')
    w('5. kJ and kcal were calculated separately (ratio 3.4–4.29 instead of 4.184). kcal is used.')
    w('6. Some recipes look too watery: boiled egg 45 kcal/100 g (a real egg is about 150). Flagged; Phase 1 boiled egg kept.')
    w('7. Names: 46 with stray spaces, 3 with non-breaking spaces, 2 with broken brackets (BFP261/262), a few spelling slips (Espreso, Macroni, Waldroff). Cleaned for display.')
    w('8. No duplicate names. 378 names carry a Hindi/regional name in brackets; those became search aliases.\n')

    w('## Phase 1 foods replaced by INDB\n')
    w('Old diary entries keep the name, grams and nutrients they were logged with. Editing only the meal keeps them; '
      'changing the quantity recalculates from the food below.\n')
    w('Changes of more than 40% are in **bold**: INDB\'s home recipes are often thinner (dals, kheer, lassi, tea) '
      'or drier (dosa, poha) than the Phase 1 estimates, so per-100 g values move even where a typical portion is similar.\n')
    w('| Phase 1 id | Phase 1 food | kcal/100 g | INDB food | kcal/100 g | change | source |')
    w('|---|---|---:|---|---:|---:|---|')
    for sid, seed, code, f in sorted(rep['swap'], key=lambda x: x[0]):
        a, b = seed['per100g']['kcal'], f['per100g']['kcal']
        ch = f'{(b - a) / a * 100:+.0f}%'
        if abs(b - a) / a > 0.4:
            ch = f'**{ch}**'
        w(f'| `{sid}` | {seed["name"]} | {a} | {code} {f["name"]} | {b} | {ch} | {f["source"]} |')
    w('\nKept from Phase 1 (no fair INDB match), now labelled *estimate*: ' +
      ', '.join(f'`{k}`' for k, v in seed_map.items() if not v) + '.\n')
    if rep['kept_seed_piece']:
        w('Where the INDB and Phase 1 piece weights differ more than 2×, the weight giving a per-piece kcal closer to Phase 1 was used:\n')
        for s, u, a, b, pick, k, want in rep['kept_seed_piece']:
            w(f'- `{s}`: Phase 1 {a} g, INDB {b} g → **{pick} g** = {pick * k / 100:.0f} kcal per {u} (Phase 1: {want:.0f} kcal)')
        w('')

    w('## Frying-oil corrections\n')
    w('Method: remove unabsorbed oil so fat per 100 g equals a typical value for that kind of dish, then express every nutrient per 100 g '
      'of what is left. Piece/serving weights shrink by the same factor. Targets are in `data/oil-adjust.json`.\n')
    w('| Code | Food | INDB kcal | INDB fat g | Adjusted kcal | Adjusted fat g | Oil removed g/100 g |')
    w('|---|---|---:|---:|---:|---:|---:|')
    for code, name, o, n, e, group in rep['oil']:
        w(f'| {code} | {name} | {o["kcal"]:.0f} | {o["fat"]:.1f} | {n["kcal"]:.0f} | {n["fat"]:.0f} | {e:.0f} |')
    if rep['oil_skipped']:
        w('\nListed for correction but left as INDB because their kcal already disagrees with their macros (see calorie check): ' +
          ', '.join(f'{c} {n}' for c, n in rep['oil_skipped']) + '.')
    w('\nNot corrected (their high values are close to real products): sev, banana chips, rice murukku, mayonnaise, dressings, '
      'tadka/baghar, oil pickles, burfi/ladoo/biscuits.\n')

    w('## Calorie check: foods whose kcal does not match protein/carbs/fat\n')
    w('Values are shown as listed; nothing was changed to make them match. They carry a ⚠ note in the app and rank lower in search.\n')
    w('| Food | Source | Listed kcal | 4P+4C+9F | Difference |')
    w('|---|---|---:|---:|---:|')
    for f in sorted(rep['kcal'], key=lambda f: f['name']):
        p = f['per100g']
        est = atwater(p)
        w(f'| {f["name"]}{" (" + f["ref"] + ")" if f.get("ref") else ""} | {f["source"]} | {p["kcal"]} | {est:.0f} | {p["kcal"] - est:+.0f} |')

    w('\n## Serving sizes not used\n')
    w(f'{len(rep["serving_skipped"])} INDB servings were outside 10–600 g (after oil correction) and were not offered as a portion; '
      f'the food still has katori/tbsp/g. {len(rep["no_serving"])} rows had no serving unit and got category defaults.\n')
    for code, name, note in rep['serving_skipped']:
        w(f'- {code} {name}: {note}')
    w('\n## Estimates\n')
    w('Foods marked *estimate* were written by Claude from typical recipes and labels: Indo-Chinese, street food, restaurant dishes, '
      'packaged foods (Maggi, Parle-G, Haldiram\'s, Amul and others) and the Phase 1 foods INDB lacks. Packaged values are typical label '
      'values and may differ from your packet; add the packet as a "From packet label" food to replace them.\n')
    (DATA / 'import-report.md').write_text('\n'.join(L) + '\n', encoding='utf-8')


if __name__ == '__main__':
    sys.exit(main())
