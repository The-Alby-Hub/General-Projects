"""Raw ingredients for Lechem Mifkad (Phase 3), used by build_foods.py.

Sources (all per 100 g edible portion):
  data/IFCT2017_Table1.pdf  IFCT 2017, ICMR-NIN, Table 1 (528 foods)           source "IFCT"
  data/UK_fct.xlsx          UK CoFID extra ingredients (144 rows)             source "CoFID"
  data/US_fct.xlsx          USDA extra ingredients (54 rows)                  source "USDA"
  data/ingredient-overrides.json  names, aliases, units, tiers, dropped duplicates

Rules
  IFCT: mean of "mean ± SD"; energy kJ -> kcal with the book's factor 4.18; carbohydrate = CHOAVLDF
        (available carbohydrate by difference, fibre not included); blank cell = below detection = 0.
        Egg, poultry, meat and fish pages have no carbohydrate or fibre column: both are 0, with a note.
  UK:   "Tr" (trace) = 0; "N" (not known) and empty cells = unknown (None, shown as "—" in the app).
  US:   "NA" = unknown.
  A UK/US row that is the same ingredient as an IFCT food is left out (IFCT is kept); see overrides "drop".
"""
import random
import re

from ifct_pdf import read_table1

UK_US_COLS = {'kcal': 'energy_kcal', 'protein': 'protein_g', 'carbs': 'carb_g', 'fat': 'fat_g', 'fibre': 'fibre_g'}
IFCT_KCAL_PER_KJ = 1 / 4.18
EXPECTED_ROWS = {'IFCT': 528, 'CoFID': 144, 'USDA': 54}

# Category from the first letter of the food code (IFCT groups; the UK and US files use the same letters).
LETTER_CATEGORY = {'A': 'grains', 'B': 'pulses', 'C': 'veg', 'D': 'veg', 'E': 'fruit', 'F': 'veg', 'G': 'spices',
                   'H': 'nuts', 'I': 'sweet', 'J': 'veg', 'K': 'drink', 'L': 'dairy', 'M': 'egg', 'N': 'meat', 'O': 'meat',
                   'P': 'meat', 'Q': 'meat', 'R': 'meat', 'S': 'meat', 'T': 'oils', 'U': 'bread', 'V': 'drink',
                   'W': 'sweet', 'X': 'chutney'}
CATEGORY_FIX = {  # rows whose letter doesn't fit how people look for them
    'cofid-uk-17-719': 'chutney', 'cofid-uk-17-517': 'chutney', 'cofid-uk-17-339': 'chutney', 'cofid-uk-17-654': 'chutney',
    'cofid-uk-17-718': 'chutney', 'usda-us-503149': 'chutney', 'usda-us-499035': 'chutney', 'usda-us-172237': 'chutney',
    'usda-us-1860491': 'chutney', 'usda-us-468991': 'spices', 'usda-us-627292': 'spices', 'usda-us-463153': 'veg',
    'cofid-uk-14-892': 'nuts', 'cofid-uk-14-878': 'nuts', 'cofid-uk-11-023': 'grains', 'cofid-uk-11-1016': 'bread',
    'cofid-uk-11-799': 'bakery', 'cofid-uk-11-800': 'bakery', 'usda-us-476436': 'drink', 'cofid-uk-17-247': 'drink',
    'cofid-uk-17-377': 'drink', 'cofid-uk-17-355': 'spices', 'cofid-uk-17-356': 'spices', 'cofid-uk-11-1138': 'spices',
    'cofid-uk-17-360': 'spices', 'cofid-uk-17-358': 'spices',
}
# Portion units (grams) a category gets when the overrides give none. Veg and fruit also keep these
# alongside their own units (a tomato is a piece or a katori chopped); other categories use the override alone.
DEFAULT_UNITS = {'grains': {'tbsp': 12, 'katori': 130}, 'pulses': {'tbsp': 12, 'katori': 130}, 'veg': {'katori': 100},
                 'fruit': {'katori': 100}, 'spices': {'tsp': 2.5}, 'nuts': {'tbsp': 9}, 'oils': {'tsp': 5, 'tbsp': 14},
                 'dairy': {'tbsp': 15}, 'egg': {'piece': 50}, 'meat': {}, 'drink': {'cup': 240}, 'sweet': {'tsp': 5, 'tbsp': 15},
                 'chutney': {'tbsp': 15}, 'bread': {'piece': 30}, 'bakery': {'piece': 15}}
LEAFY_KATORI = 30  # chopped raw greens are light

ANIMAL_NOTE = ('IFCT 2017 gives no carbohydrate or fibre for eggs, meat and fish, so both are shown as 0 '
               '(IFCT\'s own energy value assumes the same).')
BLANK_FIBRE_NOTE = 'Fibre is blank in IFCT 2017 (below detectable limit), shown as 0.'
KNOWN_ISSUES = {
    'ifct-n001': ('Kept as printed in IFCT 2017: 1605 kJ (384 kcal) per 100 g. Its protein and fat give about 192 kcal, '
                  'and chicken thigh in the same table is 836 kJ, so this is probably a misprint. Chicken thigh or breast is a safer choice.'),
    'ifct-g026': 'Kept as printed in IFCT 2017: 983 kJ (235 kcal), while protein, carbs and fat give about 195 kcal.',
    'ifct-q001': 'Kept as printed in IFCT 2017: 343 kJ (82 kcal), while protein and fat give about 54 kcal.',
    'usda-us-384277': 'The USDA entry (a branded label) lists 0 for every nutrient, which is not plausible for star anise (typically about 330 kcal per 100 g). Kept as listed; use a small amount or a label value.',
    'usda-us-627292': 'The USDA entry (a branded label) lists 0 for every nutrient, which is not plausible for a spice mix. Kept as listed.',
    'usda-us-1860491': 'The USDA entry (a branded label) lists 100 kcal but 0 g protein, carbs and fat. Kept as listed.',
    'cofid-uk-17-358': 'Energy comes from tartaric acid, which isn\'t protein, carbs or fat, so the calorie check doesn\'t apply.',
    'cofid-uk-17-247': 'Energy comes from alcohol (7 kcal per g), which isn\'t protein, carbs or fat, so the calorie check doesn\'t apply.',
    'usda-us-173471': 'Most of the energy comes from alcohol, so it doesn\'t match protein, carbs and fat.',
}
ZERO_SUSPECT = {'usda-us-384277', 'usda-us-627292'}
UNKNOWN_LABEL = {'CoFID': 'UK CoFID', 'USDA': 'USDA'}


def _r1(x):
    return round(x + 0.0, 1)


def _cell(v, source):
    """UK/US cell -> number, 0 for trace, None for not known."""
    if v is None:
        return None
    if isinstance(v, (int, float)):
        return float(v)
    s = str(v).strip()
    if s == 'Tr':
        return 0.0
    if s in ('', 'N', 'NA'):
        return None
    return float(s)


def _clean_ifct_name(s, code):
    s = re.sub(r'\s+', ' ', s).strip()
    s = s.replace('tende r', 'tender').replace('var .', 'var.').replace('omlet', 'omelette').replace('quial', 'quail')
    s = re.sub(r',(?=\S)', ', ', s)
    s = re.sub(r'\s*\($', '', s)
    if code[0] in 'PS' and 'fish' not in s.lower() and not re.search(r'prawn|crab|eel', s, re.I):
        s += ' (fish)'
    return s


def _title(s):
    """USDA branded names are in capitals."""
    if s.upper() != s:
        return s
    return re.sub(r"\b([A-Z])([A-Z']*)\b", lambda m: m.group(1) + m.group(2).lower(), s).capitalize()


def _units(fid, category, code, ov):
    own = dict(ov.get('units', {}))
    if category in ('veg', 'fruit') or not own:
        base = dict(DEFAULT_UNITS.get(category, {}))
        if category == 'veg' and code[:1] == 'C':
            base['katori'] = LEAFY_KATORI
        base.update(own)
        own = base
    own['g'] = 1
    return own


def build(overrides, read_xlsx, data_dir):
    """Returns (foods, report). foods use the app's food shape plus kind: 'ingredient'."""
    foods_ov = overrides['foods']
    drop, no_energy = overrides['drop'], overrides['noEnergy']
    used_ov, rep = set(), {'counts': {}, 'dropped': [], 'no_energy': [], 'unknown': {}, 'spot': [], 'ifct_rows': [],
                           'blank_fibre': [], 'missing_names': []}
    foods = []

    def make(fid, name, code, source, per100, extra_note=None, sci=None):
        ov = foods_ov.get(fid, {})
        if ov:
            used_ov.add(fid)
        category = ov.get('category') or CATEGORY_FIX.get(fid) or LETTER_CATEGORY[code[0]]
        if source == 'IFCT' and code[0] == 'G' and int(code[1:]) <= 18:
            category = 'veg'  # fresh chillies, garlic, ginger, onion, coriander, mint, curry leaves
        if source == 'CoFID' and code[0] == 'K' and fid not in CATEGORY_FIX:
            category = 'spices'
        aliases = list(ov.get('aliases', []))
        if sci:
            aliases.append(sci)
        food = {'id': fid, 'name': ov.get('name') or name, 'aliases': aliases, 'category': category, 'kind': 'ingredient',
                'per100g': per100, 'units': _units(fid, category, code, ov), 'defaultUnit': 'g', 'source': source,
                'tier': ov.get('tier', 'C'), 'ref': code}
        if ov.get('liquid'):
            food['liquid'] = True
        if ov.get('serving'):
            food['serving'] = ov['serving']
        notes = [n for n in (extra_note, KNOWN_ISSUES.get(fid)) if n]
        unknown = [k for k in ('protein', 'carbs', 'fat', 'fibre') if per100[k] is None]
        if unknown:
            notes.append(f'{UNKNOWN_LABEL[source]} doesn\'t give {", ".join(unknown)} for this food, so it shows as "—" and adds nothing to your totals.')
            for k in unknown:
                rep['unknown'].setdefault(source, {}).setdefault(k, []).append(food['name'])
        if fid in ZERO_SUSPECT:
            food['flags'] = ['zero']
        if notes:
            food['note'] = ' '.join(notes)
        if not ov and source != 'IFCT':
            rep['missing_names'].append(fid)
        foods.append(food)
        return food

    # ---- IFCT 2017
    rows = read_table1(data_dir / 'IFCT2017_Table1.pdf')
    rep['ifct_rows'] = rows
    for r in rows:
        code = r['code']
        animal = r['group'] == 'animal'
        blank = not animal and r['fibre'] is None
        if blank:
            rep['blank_fibre'].append(code)
        per100 = {'kcal': round(r['kj'] * IFCT_KCAL_PER_KJ), 'protein': _r1(r['protein']),
                  'carbs': 0.0 if animal else _r1(r['carbs']), 'fat': _r1(r['fat']),
                  'fibre': 0.0 if animal or blank else _r1(r['fibre'])}
        note = ANIMAL_NOTE if animal else (BLANK_FIBRE_NOTE if blank else None)
        make('ifct-' + code.lower(), _clean_ifct_name(r['name'], code), code, 'IFCT', per100, note, r['sci'] or None)
    rep['counts']['IFCT'] = len(rows)

    # ---- UK CoFID and USDA gap files
    for fname, source, prefix in (('UK_fct.xlsx', 'CoFID', 'cofid-'), ('US_fct.xlsx', 'USDA', 'usda-')):
        rows = [r for r in read_xlsx(data_dir / fname) if r.get('food_name')]
        rep['counts'][source] = len(rows)
        for r in rows:
            org = r['food_code_org'].strip()
            fid = prefix + org.lower()
            name = _title(re.sub(r'\s+', ' ', r['food_name']).strip())
            if org in drop:
                rep['dropped'].append((source, org, name, drop[org]))
                continue
            per100 = {k: _cell(r[c], source) for k, c in UK_US_COLS.items()}
            if per100['kcal'] is None:
                if org not in no_energy:
                    raise SystemExit(f'{source} {org} {name} has no energy value and no decision in ingredient-overrides.json "noEnergy"')
                rep['no_energy'].append((org, name, no_energy[org]))
                continue
            per100 = {k: (None if v is None else (round(v) if k == 'kcal' else _r1(v))) for k, v in per100.items()}
            make(fid, name, r['food_code'].strip(), source, per100)

    for src, n in EXPECTED_ROWS.items():
        if rep['counts'][src] != n:
            raise SystemExit(f'{src}: expected {n} rows, read {rep["counts"][src]}')
    for key in list(drop) + list(no_energy):
        if not any(key == d[1] for d in rep['dropped']) and not any(key == d[0] for d in rep['no_energy']):
            raise SystemExit(f'ingredient-overrides.json lists {key}, which is not in the UK/US files')
    stale = set(foods_ov) - used_ov
    if stale:
        raise SystemExit(f'ingredient-overrides.json has foods that were not built: {sorted(stale)}')

    # ---- spot-check: 15 IFCT foods picked at random (fixed seed, so the report is stable)
    by_id = {f['id']: f for f in foods}
    for r in random.Random(2017).sample(rep['ifct_rows'], 15):
        rep['spot'].append((r, by_id['ifct-' + r['code'].lower()]))
    return foods, rep
