# Lechem Mifkad: food data import report

Built 2026-09-26 by `tools/build_foods.py`. Re-running it regenerates this file.

## Summary

- **1151 foods** in the app: 894 INDB, 257 estimate.
- INDB rows read: 1014. 120 fried dishes were corrected for frying oil (now labelled *estimate*, original INDB values kept on the food).
- Phase 1 foods: 64 replaced by INDB matches (old ids redirect), 36 kept as *estimate*.
- Calorie check (4/4/9 kcal per g protein/carbs/fat, flagged when off by more than 15% and more than 20 kcal): **37 foods flagged**, listed below, values unchanged.
- `index.html` size: 459 KB (limit 16 MB).
- Categories: bakery 181, continental 143, chutney 100, snack 98, sweet 83, sabzi 69, drink 55, soup 52, meat 48, dal 42, bread 41, packaged 36, rice 32, indochinese 32, dairy 32, street 26, south 25, egg 21, paneer 18, infant 14, fruit 3.

## INDB file: what it contains

One sheet, *Nutrient Data*, 1,014 rows × 82 columns. `food_code` (ASC 490, BFP 376, OSR 148), `food_name`, `primarysource`; 39 nutrients per 100 g (energy kJ/kcal, macros in g, minerals mg, vitamins mg/µg; no blanks); `servings_unit`; the same 39 nutrients per serving. The app uses kcal, protein, carbs, fat and fibre.

**Problems found in the source**

1. 82 rows have no serving data; 15 more have serving numbers but no unit name (14 infant foods BFP546–560 and OSR112 Pav bhaji).
2. Serving weight isn't given; it is derived as serving kcal ÷ kcal per 100 g (every nutrient agrees). 57 servings are over 600 g (whole dishes, e.g. lasagne 1,775 g). Serving units are inconsistent ("bowl" is 47–1,020 g).
3. About 110 fried dishes count all the frying oil as eaten (poori 738 kcal/100 g with 78 g fat). Corrected, see below.
4. About 28 soups list ~30 kcal/100 g while their macros add up to 150–215 kcal, with 8–14 g sodium per 100 g. Flagged, not changed.
5. kJ and kcal were calculated separately (ratio 3.4–4.29 instead of 4.184). kcal is used.
6. Some recipes look too watery: boiled egg 45 kcal/100 g (a real egg is about 150). Flagged; Phase 1 boiled egg kept.
7. Names: 46 with stray spaces, 3 with non-breaking spaces, 2 with broken brackets (BFP261/262), a few spelling slips (Espreso, Macroni, Waldroff). Cleaned for display.
8. No duplicate names. 378 names carry a Hindi/regional name in brackets; those became search aliases.

## Phase 1 foods replaced by INDB

Old diary entries keep the name, grams and nutrients they were logged with. Editing only the meal keeps them; changing the quantity recalculates from the food below.

Changes of more than 40% are in **bold**: INDB's home recipes are often thinner (dals, kheer, lassi, tea) or drier (dosa, poha) than the Phase 1 estimates, so per-100 g values move even where a typical portion is similar.

| Phase 1 id | Phase 1 food | kcal/100 g | INDB food | kcal/100 g | change | source |
|---|---|---:|---|---:|---:|---|
| `aloo-gobi` | Aloo gobi | 110 | ASC171 Potato cauliflower (Aloo gobhi) | 106 | -4% | INDB |
| `aloo-matar` | Aloo matar | 105 | ASC190 Pea potato curry (Aloo matar) | 101 | -4% | INDB |
| `aloo-paratha` | Aloo paratha | 260 | ASC098 Potato parantha/paratha (Aloo ka parantha/paratha) | 205 | -21% | INDB |
| `aloo-sabzi` | Aloo sabzi (dry) | 125 | ASC178 Dry potato (Sookhe aloo) | 103 | -18% | INDB |
| `appam` | Appam | 150 | BFP153 Appam | 268 | **+79%** | INDB |
| `avial` | Avial | 110 | ASC219 Avial | 125 | +14% | INDB |
| `baingan-bharta` | Baingan bharta | 105 | ASC177 Brinjal bhartha (Baingan ka bhartha) | 65 | -38% | INDB |
| `beans-poriyal` | Beans poriyal | 90 | ASC179 Beans with coconut (Nariyal aur sem/phali; Beans thoran) | 132 | **+47%** | INDB |
| `besan-chilla` | Besan chilla | 190 | OSR100 Gram flour chilla/cheela (Besan chilla/cheela) | 136 | -28% | INDB |
| `bhel-puri` | Bhel puri | 190 | OSR114 Bhel puri | 228 | +20% | estimate |
| `bhindi` | Bhindi fry | 115 | BFP269 Okra/Lady's fingers fry (Bhindi sabzi/sabji/subji) | 111 | -3% | INDB |
| `cabbage-sabzi` | Cabbage sabzi | 80 | ASC173 Cabbage and peas (Pattagobhi aur matar) | 64 | -20% | INDB |
| `chaas` | Chaas | 20 | ASC022 Lassi (salted) | 19 | -5% | INDB |
| `chai` | Chai (milk and sugar) | 52 | ASC001 Hot tea (Garam Chai) | 16 | **-69%** | INDB |
| `chana-dal` | Chana dal | 130 | OSR142 Split bengal gram dal (Channa dal) | 100 | -23% | INDB |
| `chicken-curry` | Chicken curry | 160 | ASC240 Chicken curry | 129 | -19% | INDB |
| `chole` | Chole | 150 | ASC162 Chickpeas curry (Safed channa curry) | 163 | +9% | INDB |
| `coconut-chutney` | Coconut chutney | 225 | ASC386 Coconut chutney (Nariyal ki chutney) | 266 | +18% | INDB |
| `curd-rice` | Curd rice | 115 | ASC126 Curd rice (Dahi bhaat/Dahi chawal/ Perugu annam/Daddojanam/Thayir saadam) | 196 | **+70%** | INDB |
| `dal-makhani` | Dal makhani | 165 | OSR139 Dal makhani | 74 | **-55%** | INDB |
| `dal-palak` | Dal palak | 100 | BFP172 Arhar with spinach (Arhar dal aur palak) | 53 | **-47%** | INDB |
| `dhokla` | Dhokla | 160 | ASC474 Dhokla | 216 | +35% | INDB |
| `fish-curry` | Fish curry | 130 | ASC246 Fish curry (Machli curry) | 111 | -15% | INDB |
| `gulab-jamun` | Gulab jamun | 300 | ASC348 Gulab Jamun with khoya | 317 | +6% | estimate |
| `idli` | Idli | 130 | ASC144 Idli | 138 | +6% | INDB |
| `jeera-rice` | Jeera rice | 160 | BFP134 Cumin pulao (Jeera/Zeera pulao) | 135 | -16% | INDB |
| `kadai-paneer` | Kadai paneer | 190 | ASC226 Kadhai Paneer | 108 | **-43%** | INDB |
| `kala-chana` | Kala chana curry | 140 | ASC161 Black channa curry/Bengal gram curry (Kale chane ki curry) | 141 | +1% | INDB |
| `kheer` | Kheer | 140 | ASC282 Rice kheer (Chawal ki kheer) | 75 | **-46%** | INDB |
| `khichdi` | Moong dal khichdi | 120 | BFP144 Plain khitchdi (Plain khichri/khichdi) | 57 | **-52%** | INDB |
| `lemon-rice` | Lemon rice | 165 | ASC124 Lemon rice (Pulihora, Elumichai sadam, Chitranna) | 176 | +7% | INDB |
| `makki-roti` | Makki roti | 290 | ASC150 Makki ki roti | 264 | -9% | INDB |
| `masala-dosa` | Masala dosa | 180 | ASC146 Masala dosa | 165 | -8% | INDB |
| `matar-paneer` | Matar paneer | 165 | ASC191 Pea paneer curry (Matar paneer) | 135 | -18% | INDB |
| `medu-vada` | Medu vada | 290 | BFP436 Plain urad dal vada (Uzunne vada/Minapa garelu/Ulundu vadai/Medu vada) | 332 | +14% | estimate |
| `methi-thepla` | Methi thepla | 300 | OSR104 Methi thepla | 346 | +15% | INDB |
| `moong-dal` | Moong dal (yellow) | 105 | ASC151 Washed moong dal (Dhuli moong ki dal) | 50 | **-52%** | INDB |
| `naan` | Naan | 300 | ASC142 Naan | 286 | -5% | INDB |
| `nimbu-pani` | Nimbu pani | 30 | ASC008 Lemonade | 21 | -30% | INDB |
| `omelette` | Masala omelette (2 eggs) | 170 | ASC061 Plain omelette | 272 | **+60%** | INDB |
| `pakora` | Pakora | 315 | ASC352 Onion pakora/pakoda (Pyaaz ke pakode) | 247 | -22% | estimate |
| `palak-paneer` | Palak paneer | 150 | ASC215 Spinach paneer (Palak paneer) | 78 | **-48%** | INDB |
| `paneer-butter-masala` | Paneer butter masala | 220 | ASC222 Paneer in butter sauce | 146 | -34% | INDB |
| `paneer-paratha` | Paneer paratha | 285 | ASC105 Paneer parantha/paratha | 263 | -8% | INDB |
| `paneer-tikka` | Paneer tikka | 220 | ASC381 Paneer shaslik/tikka | 94 | **-57%** | INDB |
| `paratha` | Plain paratha | 326 | ASC097 Plain parantha/paratha | 298 | -9% | INDB |
| `pav-bhaji` | Pav bhaji (bhaji only) | 140 | OSR112 Pav bhaji | 97 | -31% | INDB |
| `pesarattu` | Pesarattu | 160 | OSR103 Moong bean dosa (Pesarattu) | 286 | **+79%** | INDB |
| `plain-dosa` | Plain dosa | 170 | BFP148 Plain dosa | 381 | **+124%** | INDB |
| `poha` | Poha | 180 | BFP044 Poha | 295 | **+64%** | INDB |
| `puri` | Puri | 350 | ASC107 Poori | 288 | -18% | estimate |
| `raita` | Raita | 70 | ASC273 Cucumber raita (Kheere ka raita) | 59 | -16% | INDB |
| `rajma` | Rajma | 125 | ASC165 Kidney bean curry (Rajmah curry) | 144 | +15% | INDB |
| `rasam` | Rasam | 35 | BFP176 Rasam with tamarind (Puli rasam/ Chintapandu rasam/ Charu/Saaru) | 27 | -23% | INDB |
| `roti` | Roti / phulka | 264 | ASC096 Chapati/Roti | 202 | -23% | INDB |
| `sambar` | Sambar | 70 | ASC167 Sambar | 97 | +39% | INDB |
| `samosa` | Samosa | 308 | ASC361 Potato samosa (Aloo ka samosa) | 242 | -21% | estimate |
| `sprouts-chaat` | Sprouts chaat | 95 | ASC170 Sprouted moong dal chat | 32 | **-66%** | INDB |
| `steamed-rice` | Steamed rice (white) | 130 | ASC113 Boiled rice (Uble chawal) | 117 | -10% | INDB |
| `sweet-lassi` | Sweet lassi | 100 | ASC021 Sweet Lassi (Meethi lassi) | 36 | **-64%** | INDB |
| `upma` | Upma | 150 | BFP039 Semolina upma (Suji/Rava upma) | 148 | -1% | INDB |
| `uttapam` | Uttapam | 165 | BFP152 Uttapam | 256 | **+55%** | INDB |
| `veg-biryani` | Veg biryani | 165 | ASC123 Vegetable biryani/biriyani | 175 | +6% | INDB |
| `veg-pulao` | Veg pulao | 150 | ASC115 Mixed vegetable pulao | 113 | -25% | INDB |

Kept from Phase 1 (no fair INDB match), now labelled *estimate*: `toor-dal`, `masoor-dal`, `kadhi`, `brown-rice`, `chicken-biryani`, `bisi-bele-bath`, `roti-ghee`, `butter-naan`, `jowar-roti`, `bajra-roti`, `mix-veg`, `lauki`, `palak-sabzi`, `karela`, `paneer-bhurji`, `paneer`, `pongal`, `aloo-tikki`, `pav`, `vada-pav`, `roasted-chana`, `peanuts`, `makhana`, `marie-biscuit`, `curd`, `milk-toned`, `milk-full`, `ghee`, `butter`, `filter-coffee`, `coconut-water`, `banana`, `apple`, `papaya`, `boiled-egg`, `sugar`.

Where the INDB and Phase 1 piece weights differ more than 2×, the weight giving a per-piece kcal closer to Phase 1 was used:

- `gulab-jamun`: Phase 1 40 g, INDB 83 g → **40 g** = 127 kcal per piece (Phase 1: 120 kcal)
- `plain-dosa`: Phase 1 80 g, INDB 36 g → **36 g** = 137 kcal per piece (Phase 1: 136 kcal)
- `appam`: Phase 1 60 g, INDB 153 g → **60 g** = 161 kcal per piece (Phase 1: 90 kcal)
- `medu-vada`: Phase 1 45 g, INDB 22 g → **45 g** = 149 kcal per piece (Phase 1: 130 kcal)
- `pesarattu`: Phase 1 90 g, INDB 27 g → **27 g** = 77 kcal per piece (Phase 1: 144 kcal)

## Frying-oil corrections

Method: remove unabsorbed oil so fat per 100 g equals a typical value for that kind of dish, then express every nutrient per 100 g of what is left. Piece/serving weights shrink by the same factor. Targets are in `data/oil-adjust.json`.

| Code | Food | INDB kcal | INDB fat g | Adjusted kcal | Adjusted fat g | Oil removed g/100 g |
|---|---|---:|---:|---:|---:|---:|
| ASC046 | Sesame toast | 495 | 49.4 | 262 | 20 | 37 |
| ASC090 | Chinese cabbage and meat ball soup | 484 | 56.6 | 93 | 5 | 54 |
| ASC107 | Poori | 738 | 77.6 | 288 | 16 | 73 |
| ASC108 | Spinach poori (Palak poori) | 684 | 71.9 | 254 | 16 | 66 |
| ASC109 | Methi poori | 710 | 74.6 | 269 | 16 | 70 |
| ASC110 | Dal stuffed poori | 785 | 81.7 | 369 | 16 | 78 |
| ASC111 | Potato stuffed poori (Aloo ki poori) | 777 | 81.4 | 341 | 16 | 78 |
| ASC118 | Paneer pulao | 582 | 59.8 | 171 | 8 | 56 |
| ASC137 | Spaghetti and cheese balls in tomato sauce | 508 | 52.1 | 166 | 10 | 47 |
| ASC143 | Bhatura | 793 | 82.6 | 370 | 14 | 80 |
| ASC148 | Onion tomato uttapam | 462 | 45.3 | 161 | 8 | 41 |
| ASC168 | Besan kadhi with pakodies | 403 | 42.6 | 105 | 8 | 38 |
| ASC198 | Pea kofta curry (Matar kofta curry) | 596 | 63.4 | 168 | 12 | 58 |
| ASC199 | Spinach kofta curry (Palak kofta curry) | 572 | 61.5 | 150 | 12 | 56 |
| ASC200 | Paneer kofta curry | 671 | 72.1 | 179 | 12 | 68 |
| ASC201 | Lotus stem kofta curry (Kamal kakdi kofta curry) | 634 | 67.8 | 173 | 12 | 63 |
| ASC202 | Raw banana kofta curry (Kela kofta curry) | 627 | 68.0 | 152 | 12 | 64 |
| ASC203 | Cauliflower kofta curry (Phoolgobhi kofta curry) | 641 | 69.6 | 150 | 12 | 65 |
| ASC204 | Cabbage kofta curry (Pattagobhi kofta curry) | 640 | 69.4 | 152 | 12 | 65 |
| ASC205 | Ghiya/Lauki Kofta Curry | 639 | 69.4 | 149 | 12 | 65 |
| ASC206 | Spinach paneer kofta curry (Palak paneer kofta curry) | 606 | 65.4 | 152 | 12 | 61 |
| ASC207 | Vegetarian egg kofta curry | 627 | 67.2 | 168 | 12 | 63 |
| ASC214 | Dum aloo | 682 | 74.0 | 146 | 10 | 71 |
| ASC216 | Methi chaman | 476 | 50.9 | 122 | 10 | 45 |
| ASC218 | Jackfruit sabzi (Kathal ki sabzi) | 625 | 67.6 | 136 | 10 | 64 |
| ASC224 | Chilli paneer | 778 | 84.0 | 242 | 14 | 81 |
| ASC225 | Paneer makhana korma | 776 | 82.8 | 283 | 14 | 80 |
| ASC236 | Mutton chops | 664 | 71.3 | 192 | 14 | 67 |
| ASC237 | Shammi kebab | 686 | 72.6 | 211 | 12 | 69 |
| ASC238 | Scotch egg | 677 | 72.6 | 201 | 14 | 68 |
| ASC243 | Chicken kebab | 729 | 78.9 | 188 | 12 | 76 |
| ASC247 | Fried fish (Indian style) (Tali hui machli) | 659 | 68.9 | 218 | 12 | 65 |
| ASC248 | Fried fish and Chips (English Style) (Tali hui machli aur chips) | 652 | 69.7 | 179 | 12 | 66 |
| ASC249 | Tomato fish | 490 | 51.9 | 132 | 10 | 47 |
| ASC277 | Boondi raita | 688 | 73.8 | 150 | 7 | 72 |
| ASC279 | Dahi vadas/Dahi bhalla | 668 | 70.4 | 177 | 8 | 68 |
| ASC280 | Gunjia | 667 | 70.3 | 289 | 22 | 62 |
| ASC347 | Ghujia/Lavang latika | 769 | 78.9 | 418 | 22 | 73 |
| ASC348 | Gulab Jamun with khoya | 586 | 53.2 | 317 | 12 | 47 |
| ASC349 | Mal pua | 567 | 54.6 | 271 | 14 | 47 |
| ASC351 | Potato pakora/pakoda (Aloo pakoda) | 677 | 71.8 | 254 | 18 | 66 |
| ASC352 | Onion pakora/pakoda (Pyaaz ke pakode) | 675 | 71.8 | 247 | 18 | 66 |
| ASC353 | Cauliflower pakora/pakoda (Phoolgobhi ke pakode) | 672 | 71.9 | 237 | 18 | 66 |
| ASC354 | Mixed vegetable pakora/pakoda | 674 | 71.9 | 244 | 18 | 66 |
| ASC355 | Spinach pakora/pakoda (Palak pakoda) | 713 | 76.4 | 254 | 18 | 71 |
| ASC356 | Methi pakora/pakoda (Methi ke pakode) | 713 | 76.4 | 255 | 18 | 71 |
| ASC357 | Egg pakora/pakoda (Ande ke pakode) | 711 | 75.9 | 261 | 18 | 71 |
| ASC358 | Bread pakora/pakoda | 711 | 74.2 | 306 | 18 | 69 |
| ASC359 | Paneer pakora/pakoda | 718 | 76.1 | 282 | 18 | 71 |
| ASC360 | Potato bonda (Aloo bonda) | 633 | 67.8 | 203 | 16 | 62 |
| ASC361 | Potato samosa (Aloo ka samosa) | 577 | 59.2 | 242 | 17 | 51 |
| ASC362 | Minced meat samosa (Keema ka samosa) | 621 | 64.3 | 251 | 17 | 57 |
| ASC363 | Paneer and pea samosa (Paneer matar ka samosa) | 624 | 63.6 | 268 | 17 | 56 |
| ASC364 | Mathri | 805 | 83.1 | 504 | 30 | 76 |
| ASC365 | Khasta kachori | 713 | 72.3 | 371 | 22 | 64 |
| ASC366 | Vegetable cutlet | 665 | 71.3 | 181 | 12 | 67 |
| ASC367 | Flattened rice cutlet (Chirwa cutlet/Chivda cutlet/Poha cutlet) | 702 | 73.9 | 231 | 12 | 70 |
| ASC368 | Peanut cutlet (Mungfali ke cutlet) | 699 | 74.0 | 220 | 12 | 70 |
| ASC369 | Fish cutlet (Machli ka cutlet) | 655 | 70.1 | 177 | 12 | 66 |
| ASC370 | Paneer potato cutlet (Paneer aloo cutlet) | 673 | 71.4 | 203 | 12 | 68 |
| ASC371 | Spinach chickpeas cutlet (Palak channa dal cutlet) | 688 | 73.6 | 193 | 12 | 70 |
| ASC372 | Cheese toast | 785 | 84.1 | 294 | 15 | 81 |
| ASC375 | Vegetable burger | 520 | 50.6 | 227 | 12 | 44 |
| ASC377 | Vegetable seekh kebab | 691 | 73.7 | 200 | 12 | 70 |
| ASC378 | Masala vada | 826 | 89.2 | 309 | 14 | 87 |
| ASC379 | Peanut sago vada (Sabudana mungfali vada) | 750 | 79.8 | 279 | 16 | 76 |
| ASC380 | Vegetarian scotch egg | 682 | 72.8 | 212 | 14 | 68 |
| ASC383 | Spring roll | 624 | 64.6 | 211 | 12 | 60 |
| ASC409 | Cheese balls | 681 | 72.6 | 246 | 18 | 67 |
| ASC456 | Soyabean muthias | 839 | 90.4 | 335 | 12 | 89 |
| ASC457 | Soyabean tikki | 698 | 74.0 | 215 | 12 | 70 |
| ASC458 | Soyabean namak paras | 838 | 89.8 | 471 | 30 | 85 |
| ASC460 | Spinach peanut namak paras (Palak moongfali namak paras) | 740 | 78.5 | 378 | 30 | 69 |
| ASC461 | Gram flour and semolina chilla/cheela/savory pancake (Besan suji chilla/cheela) | 759 | 80.0 | 251 | 8 | 78 |
| ASC462 | Rice moong dal cheela (Chawal aur moong dal ka cheela) | 798 | 82.4 | 363 | 8 | 81 |
| ASC464 | Sweet poori (Meethi poori) | 783 | 79.6 | 426 | 18 | 75 |
| ASC473 | Semolina carrot vada (Suji gajar vada) | 700 | 74.1 | 233 | 14 | 70 |
| BFP114 | Bathua poori | 599 | 59.1 | 278 | 16 | 51 |
| BFP115 | Gram flour poori (Besan poori) | 698 | 71.5 | 303 | 16 | 66 |
| BFP116 | Beetroot poori (Chukandar ki poori) | 528 | 52.2 | 244 | 16 | 43 |
| BFP117 | Peas poori (Matar ki poori) | 593 | 57.7 | 287 | 16 | 50 |
| BFP118 | Peas kachori (Matar kachori) | 585 | 57.5 | 320 | 22 | 46 |
| BFP196 | Shahi keema kofta curry | 418 | 43.8 | 145 | 12 | 36 |
| BFP201 | Indian lamb and egg curry (Nargisi kofta) | 336 | 34.7 | 140 | 12 | 26 |
| BFP203 | Soya chunks sweet and sour (Nutrinugget sweet and sour) | 501 | 56.0 | 133 | 10 | 51 |
| BFP207 | Vegetable yakhni | 406 | 43.8 | 92 | 8 | 39 |
| BFP210 | Vegetarian nargisi kofta curry | 332 | 32.9 | 155 | 12 | 24 |
| BFP221 | Chicken sweet and sour | 445 | 47.6 | 149 | 10 | 42 |
| BFP226 | Fish finger | 543 | 55.8 | 205 | 14 | 49 |
| BFP246 | Potato kofta curry (Aloo kofta curry) | 455 | 49.1 | 131 | 12 | 42 |
| BFP249 | Yam kofta curry (Zimikand/Suran kofta curry) | 323 | 33.8 | 132 | 12 | 25 |
| BFP250 | Jackfruit kofta curry (Kathal ka kofta curry) | 321 | 33.8 | 129 | 12 | 25 |
| BFP270 | Crispy okra/Crispy lady's fingers (Karare bhindi) | 658 | 70.4 | 231 | 18 | 64 |
| BFP274 | Jackfruit/Kathal (dry) | 489 | 51.8 | 148 | 12 | 45 |
| BFP275 | Yam fried (Zimikand/Suran fried) | 492 | 51.8 | 154 | 12 | 45 |
| BFP386 | Gulab jamun with milk powder | 471 | 40.2 | 275 | 12 | 32 |
| BFP415 | Masala onion pakora/pakoda (Pyaaz ke pakode) | 552 | 57.6 | 228 | 18 | 48 |
| BFP416 | Masala green chilli pakora/pakoda (Hari mirch kay pakode) | 669 | 71.0 | 249 | 18 | 65 |
| BFP420 | Chicken pakora/pakoda | 590 | 61.0 | 235 | 16 | 54 |
| BFP421 | Fish pakora/pakoda | 577 | 59.5 | 231 | 16 | 52 |
| BFP424 | Paneer cutlet | 672 | 69.4 | 248 | 12 | 65 |
| BFP425 | Sago cutlet/vadas (Sabudana cutlet/vadas) | 559 | 57.0 | 220 | 14 | 50 |
| BFP427 | Poshtik cutlet | 496 | 50.9 | 176 | 12 | 44 |
| BFP428 | Egg cutlet (Anda cutlet) | 575 | 60.2 | 181 | 12 | 55 |
| BFP430 | Minced meat cutlet | 532 | 54.5 | 190 | 12 | 48 |
| BFP431 | Vegetable samosa | 443 | 42.2 | 242 | 17 | 30 |
| BFP436 | Plain urad dal vada (Uzunne vada/Minapa garelu/Ulundu vadai/Medu vada) | 745 | 76.3 | 332 | 14 | 72 |
| BFP437 | Masala urad dal vada | 704 | 71.6 | 300 | 14 | 67 |
| BFP539 | Potato aigrettes | 530 | 54.2 | 220 | 16 | 46 |
| BFP564 | Pearl millet mathri (Bajra mathri) | 785 | 83.1 | 423 | 30 | 76 |
| BFP566 | Fermented bengal gram vada (Khameerikrit/Ufna hua channa dal ka vada) | 658 | 67.2 | 260 | 14 | 62 |
| BFP568 | Poshtik namak paras | 613 | 56.6 | 438 | 30 | 38 |
| OSR063 | Fish orly | 564 | 58.2 | 209 | 14 | 51 |
| OSR110 | Banana appam | 470 | 42.5 | 224 | 10 | 36 |
| OSR111 | Veg manchurian | 586 | 61.7 | 179 | 12 | 56 |
| OSR114 | Bhel puri | 510 | 47.9 | 228 | 10 | 42 |
| OSR116 | Spicy corn chaat | 480 | 46.6 | 181 | 8 | 42 |
| OSR118 | Jackfruit fritters (Ponsa mulik/Kathal ka pakora) | 598 | 54.4 | 353 | 18 | 44 |
| OSR148 | Papdi | 709 | 72.1 | 418 | 30 | 60 |
| OSR152 | Bread roll | 435 | 40.2 | 249 | 16 | 29 |

Not corrected (their high values are close to real products): sev, banana chips, rice murukku, mayonnaise, dressings, tadka/baghar, oil pickles, burfi/ladoo/biscuits.

## Calorie check: foods whose kcal does not match protein/carbs/fat

Values are shown as listed; nothing was changed to make them match. They carry a ⚠ note in the app and rank lower in search.

| Food | Source | Listed kcal | 4P+4C+9F | Difference |
|---|---|---:|---:|---:|
| Almond soup (Badam ka soup) (BFP087) | INDB | 79 | 179 | -100 |
| Bengal 5 Spice Blend (Panch Phoran) (OSR082) | INDB | 290 | 353 | -63 |
| Brown sauce (ASC078) | INDB | 109 | 282 | -174 |
| Cheese soup (BFP075) | INDB | 41 | 211 | -170 |
| Chicken consomme (Clear chicken soup) (ASC081) | INDB | 48 | 159 | -111 |
| Chicken manchurian (OSR065) | INDB | 142 | 170 | -28 |
| Chicken pulao (BFP142) | INDB | 108 | 146 | -38 |
| Chicken sweet corn soup (ASC087) | INDB | 28 | 178 | -150 |
| Classic seasoned black beans (OSR154) | INDB | 29 | 138 | -108 |
| Clear tomato soup (Tamatar ka soup) (ASC079) | INDB | 80 | 143 | -63 |
| Cold summer garden soup (ASC095) | INDB | 49 | 172 | -123 |
| Consomme au julienne (BFP066) | INDB | 28 | 152 | -124 |
| Consomme au vermicelli (BFP067) | INDB | 30 | 183 | -153 |
| Cream of broccoli soup (BFP080) | INDB | 56 | 165 | -109 |
| Cream of carrot soup (BFP079) | INDB | 60 | 168 | -108 |
| Cream of green peas soup (ASC083) | INDB | 128 | 189 | -61 |
| Cream of mixed vegetable soup (ASC085) | INDB | 60 | 128 | -68 |
| Cream of mushroom soup (ASC086) | INDB | 117 | 181 | -64 |
| Cream of potato soup (BFP082) | INDB | 60 | 165 | -105 |
| Cream of spinach soup (ASC084) | INDB | 101 | 154 | -53 |
| Cream of tomato soup (ASC082) | INDB | 98 | 152 | -54 |
| Curried Cauliflower soup (OSR135) | INDB | 37 | 127 | -90 |
| Egg drop soup (ASC089) | INDB | 27 | 178 | -150 |
| French onion soup (ASC091) | INDB | 56 | 192 | -136 |
| Green pea soup (Matar ka soup) (BFP072) | INDB | 40 | 175 | -135 |
| Lentil soup (ASC080) | INDB | 31 | 160 | -129 |
| Meat and macaroni casserole (BFP157) | INDB | 162 | 193 | -31 |
| Meat consomme (with mutton) (BFP065) | INDB | 30 | 185 | -155 |
| Millet soup (OSR136) | INDB | 56 | 191 | -135 |
| Minced meat pancake (with chicken) (BFP127) | INDB | 116 | 175 | -59 |
| Minestrone soup (ASC088) | INDB | 43 | 152 | -109 |
| Mixed vegetable soup (BFP074) | INDB | 36 | 150 | -114 |
| Mulligatawny soup (BFP076) | INDB | 54 | 198 | -144 |
| Mutton pulao (BFP141) | INDB | 131 | 168 | -37 |
| Spaghetti bolognese (BFP155) | INDB | 97 | 163 | -66 |
| Spinach soup (Palak ka soup) (BFP073) | INDB | 33 | 183 | -150 |
| Talaumein soup (ASC093) | INDB | 36 | 172 | -136 |

## Serving sizes not used

30 INDB servings were outside 10–600 g (after oil correction) and were not offered as a portion; the food still has katori/tbsp/g. 97 rows had no serving unit and got category defaults.

- ASC139 Pasta hot pot: INDB serving "plate" of 831 g not used (outside 10–600 g)
- ASC241 Tandoori chicken: INDB serving "chicken" of 1441 g not used (outside 10–600 g)
- BFP059 Mixed stock: INDB serving "cup" of 910 g not used (outside 10–600 g)
- BFP060 Meat stock: INDB serving "cup" of 870 g not used (outside 10–600 g)
- BFP062 White stock: INDB serving "cup" of 765 g not used (outside 10–600 g)
- BFP065 Meat consomme (with mutton): INDB serving "bowl" of 620 g not used (outside 10–600 g)
- BFP066 Consomme au julienne: INDB serving "bowl" of 770 g not used (outside 10–600 g)
- BFP067 Consomme au vermicelli: INDB serving "bowl" of 627 g not used (outside 10–600 g)
- BFP141 Mutton pulao: INDB serving "plate" of 663 g not used (outside 10–600 g)
- BFP142 Chicken pulao: INDB serving "plate" of 668 g not used (outside 10–600 g)
- BFP161 Lasagne with meat sauce: INDB serving "dish" of 1775 g not used (outside 10–600 g)
- BFP162 Lasagne with vegetables: INDB serving "dish" of 1757 g not used (outside 10–600 g)
- BFP231 Baked stuffed fish: INDB serving "fish" of 608 g not used (outside 10–600 g)
- BFP518 Cheese straws: INDB serving "straw" of 10 g not used (outside 10–600 g)
- BFP532 Orange chiffon pie: INDB serving "pie" of 698 g not used (outside 10–600 g)
- BFP568 Poshtik namak paras: INDB serving "piece" of 8 g not used (outside 10–600 g)
- OSR007 Apple oats chia seed smoothie: INDB serving "glass" of 629 g not used (outside 10–600 g)
- OSR008 Nannari sharbat: INDB serving "cup" of 1115 g not used (outside 10–600 g)
- OSR012 Coconut kheer (Nariyal ki kheer): INDB serving "bowl" of 650 g not used (outside 10–600 g)
- OSR055 Pickled mustard greens: INDB serving "jar" of 1175 g not used (outside 10–600 g)
- OSR075 Cabbage manchurian (Pattagobhi manchurian): INDB serving "bowl" of 740 g not used (outside 10–600 g)
- OSR076 Gobi 65: INDB serving "plate" of 858 g not used (outside 10–600 g)
- OSR081 Schezwan chutney: INDB serving "box" of 757 g not used (outside 10–600 g)
- OSR094 Masala souffle: INDB serving "souffle dish" of 1485 g not used (outside 10–600 g)
- OSR096 Tamarind chutney (Chintapandu pachadi/Puli chutney): INDB serving "ml" of 4 g not used (outside 10–600 g)
- OSR097 Pav bhaji masala: INDB serving "gm" of 1 g not used (outside 10–600 g)
- OSR108 Khakhra chaat: INDB serving "plate" of 835 g not used (outside 10–600 g)
- OSR127 Tutti frutti cake: INDB serving "cake" of 848 g not used (outside 10–600 g)
- OSR134 Paneer soup: INDB serving "bowl" of 611 g not used (outside 10–600 g)
- OSR146 Gujarati handvo: INDB serving "cake" of 697 g not used (outside 10–600 g)

## Estimates

Foods marked *estimate* were written by Claude from typical recipes and labels: Indo-Chinese, street food, restaurant dishes, packaged foods (Maggi, Parle-G, Haldiram's, Amul and others) and the Phase 1 foods INDB lacks. Packaged values are typical label values and may differ from your packet; add the packet as a "From packet label" food to replace them.

