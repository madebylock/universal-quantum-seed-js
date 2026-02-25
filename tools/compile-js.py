#!/usr/bin/env python3
# Copyright (c) 2026 Signer.io — MIT License

"""
Compile language files into words.js for the JavaScript edition.

Reads data/languages/*.py (same format as universal-quantum-seed Python),
builds a flat lookup dictionary, and saves words.js as a CommonJS module.

Usage: python tools/compile-js.py
"""

import importlib
import json
import os
import re
import sys
import unicodedata

# Zero-width and invisible characters to strip from all input
_INVISIBLE_CHARS = re.compile(
    "["
    "\u200b"   # zero-width space
    "\u200c"   # zero-width non-joiner
    "\u200d"   # zero-width joiner
    "\u200e"   # left-to-right mark
    "\u200f"   # right-to-left mark
    "\u00ad"   # soft hyphen
    "\u034f"   # combining grapheme joiner
    "\u061c"   # arabic letter mark
    "\ufeff"   # BOM / zero-width no-break space
    "\u2060"   # word joiner
    "\u2061"   # function application
    "\u2062"   # invisible times
    "\u2063"   # invisible separator
    "\u2064"   # invisible plus
    "\u180e"   # mongolian vowel separator
    "]"
)

if sys.platform == "win32":
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(SCRIPT_DIR)
LANGUAGES_DIR = os.path.join(PROJECT_DIR, "data", "languages")
VISUALS_DIR = os.path.join(PROJECT_DIR, "data", "visuals", "png")
OUTPUT_FILE = os.path.join(PROJECT_DIR, "words.js")

sys.path.insert(0, LANGUAGES_DIR)


def normalize(word):
    w = word.strip()
    w = _INVISIBLE_CHARS.sub("", w)
    w = unicodedata.normalize("NFKC", w)
    return w.lower()


def detect_script(word):
    script_counts = {}
    for c in word:
        if not c.isalpha():
            continue
        name = unicodedata.name(c, "")
        if "LATIN" in name:
            script_counts["latin"] = script_counts.get("latin", 0) + 1
        elif "GREEK" in name:
            script_counts["greek"] = script_counts.get("greek", 0) + 1
        elif "CYRILLIC" in name:
            script_counts["cyrillic"] = script_counts.get("cyrillic", 0) + 1
        elif "ARABIC" in name:
            script_counts["arabic"] = script_counts.get("arabic", 0) + 1
        elif "HEBREW" in name:
            script_counts["hebrew"] = script_counts.get("hebrew", 0) + 1
        elif "THAI" in name:
            script_counts["thai"] = script_counts.get("thai", 0) + 1
        elif "DEVANAGARI" in name:
            script_counts["devanagari"] = script_counts.get("devanagari", 0) + 1
        elif "BENGALI" in name:
            script_counts["bengali"] = script_counts.get("bengali", 0) + 1
        elif "TAMIL" in name:
            script_counts["tamil"] = script_counts.get("tamil", 0) + 1
        elif "TELUGU" in name:
            script_counts["telugu"] = script_counts.get("telugu", 0) + 1
        elif "GURMUKHI" in name:
            script_counts["gurmukhi"] = script_counts.get("gurmukhi", 0) + 1
        elif "CJK" in name or "KANGXI" in name:
            script_counts["cjk"] = script_counts.get("cjk", 0) + 1
        elif "HANGUL" in name:
            script_counts["hangul"] = script_counts.get("hangul", 0) + 1
        elif "HIRAGANA" in name or "KATAKANA" in name:
            script_counts["kana"] = script_counts.get("kana", 0) + 1
    if not script_counts:
        return "other"
    return max(script_counts, key=script_counts.get)


_SAFE_STRIP_SCRIPTS = {"latin", "greek", "arabic", "hebrew", "cyrillic"}


def strip_diacritics(word, script=None):
    if script is None:
        script = detect_script(word)
    if script not in _SAFE_STRIP_SCRIPTS:
        return word
    result = word
    if script == "latin":
        for old, new in {"ß": "ss", "ø": "o", "æ": "ae", "œ": "oe",
                         "ð": "d", "þ": "th", "ł": "l", "đ": "d"}.items():
            result = result.replace(old, new)
    if script == "cyrillic":
        result = result.replace("ё", "е").replace("Ё", "Е")
    nfkd = unicodedata.normalize("NFKD", result)
    stripped = "".join(c for c in nfkd if unicodedata.category(c) != "Mn")
    return unicodedata.normalize("NFC", stripped)


def get_variants(word):
    nw = normalize(word)
    variants = {nw}
    script = detect_script(nw)
    if script in _SAFE_STRIP_SCRIPTS:
        stripped = strip_diacritics(nw, script)
        if stripped != nw:
            variants.add(stripped)
    return variants


def normalize_emoji(emoji):
    e = emoji.strip()
    e = e.replace("\ufe0e", "").replace("\ufe0f", "")
    e = _INVISIBLE_CHARS.sub("", e)
    return e


def compile_lookup():
    # Discover all language modules (Python files in data/languages/)
    lang_files = sorted([
        f[:-3] for f in os.listdir(LANGUAGES_DIR)
        if f.endswith(".py") and f != "__init__.py"
    ])

    if not lang_files:
        print("ERROR: No language files found in data/languages/")
        return False

    print(f"Found {len(lang_files)} language files\n")

    word_sources = {}
    lang_stats = {}

    for lang_file in lang_files:
        try:
            mod = importlib.import_module(lang_file)
        except Exception as e:
            print(f"  ERROR importing {lang_file}.py: {e}")
            continue

        label = getattr(mod, "LABEL", lang_file)
        seed_words = getattr(mod, "SEED_WORDS", None)

        if seed_words is None:
            # base.py has signer_universal_seed_base instead
            continue

        word_count = 0
        for idx, words in seed_words.items():
            idx = int(idx)
            for word in words:
                for variant in get_variants(word):
                    if not variant:
                        continue
                    if variant not in word_sources:
                        word_sources[variant] = []
                    word_sources[variant].append((idx, label))
                    word_count += 1

        lang_stats[label] = word_count
        print(f"  {label} ({lang_file}): {word_count} words")

    # Add emoji from base.py
    try:
        base_mod = importlib.import_module("base")
        base_data = getattr(base_mod, "signer_universal_seed_base", [])
        emoji_count = 0
        for idx, emoji, _word in base_data:
            e_norm = normalize_emoji(emoji)
            if not e_norm:
                continue
            if e_norm not in word_sources:
                word_sources[e_norm] = []
            word_sources[e_norm].append((idx, "emoji"))
            emoji_count += 1
            e_raw = emoji.strip()
            if e_raw != e_norm:
                if e_raw not in word_sources:
                    word_sources[e_raw] = []
                word_sources[e_raw].append((idx, "emoji"))
                emoji_count += 1
        print(f"\n  Emoji entries added: {emoji_count}")
    except Exception as e:
        print(f"\n  WARNING: Could not load base.py: {e}")

    # Build flat lookup (first index wins)
    lookup = {}
    for word, sources in word_sources.items():
        lookup[word] = sources[0][0]

    # Build languages section
    languages = {}
    for lang_file in lang_files:
        if lang_file == "base" or lang_file.startswith("_"):
            continue
        try:
            mod = importlib.import_module(lang_file)
        except Exception:
            continue
        seed_words = getattr(mod, "SEED_WORDS", None)
        if seed_words is None:
            continue
        label = getattr(mod, "LABEL", lang_file.replace("_", " ").title())
        words_map = {}
        for idx, word_list in seed_words.items():
            if word_list:
                words_map[int(idx)] = word_list[0]
        languages[lang_file] = {"label": label, "words": words_map}

    # Scan visuals for dark icons
    dark_visuals = set()
    try:
        from PIL import Image
        for idx in range(256):
            path = os.path.join(VISUALS_DIR, f"{idx}.png")
            if not os.path.exists(path):
                continue
            img = Image.open(path).convert("RGBA")
            w, h = img.size
            total, count = 0.0, 0
            pixels = img.load()
            for y in range(0, h, 2):
                for x in range(0, w, 2):
                    r, g, b, a = pixels[x, y]
                    if a < 50:
                        continue
                    total += 0.299 * r + 0.587 * g + 0.114 * b
                    count += 1
            if count > 0 and (total / count) < 80:
                dark_visuals.add(idx)
        print(f"\n  Dark visuals: {sorted(dark_visuals)} ({len(dark_visuals)} icons)")
    except ImportError:
        # Fallback: known dark visuals from previous compile
        dark_visuals = {11, 62, 183, 195, 213}
        print(f"\n  Pillow not installed, using known dark visuals: {sorted(dark_visuals)}")

    # Write words.js
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write('// Auto-generated by tools/compile-js.py \u2014 do not edit manually.\n\n')
        f.write('"use strict";\n\n')
        f.write(f"const LOOKUP = {json.dumps(lookup, ensure_ascii=False)};\n\n")

        # For LANGUAGES, we need int keys which JSON doesn't support natively.
        # Write it as a JS object literal instead.
        f.write("const LANGUAGES = {\n")
        for lang_code in sorted(languages):
            lang_data = languages[lang_code]
            f.write(f"  {json.dumps(lang_code)}: {{\n")
            f.write(f"    \"label\": {json.dumps(lang_data['label'])},\n")
            f.write(f"    \"words\": {{")
            word_items = sorted(lang_data["words"].items())
            parts = []
            for idx, word in word_items:
                parts.append(f"{idx}: {json.dumps(word, ensure_ascii=False)}")
            f.write(", ".join(parts))
            f.write("}\n")
            f.write(f"  }},\n")
        f.write("};\n\n")

        f.write(f"const DARK_VISUALS = new Set({json.dumps(sorted(dark_visuals))});\n\n")
        f.write("module.exports = { LOOKUP, LANGUAGES, DARK_VISUALS };\n")

    size_kb = os.path.getsize(OUTPUT_FILE) / 1024
    print(f"\n{'='*60}")
    print(f"Total languages: {len(languages)}")
    print(f"Total unique lookup keys: {len(lookup)}")
    print(f"\nSaved {OUTPUT_FILE}")
    print(f"  {len(lookup)} lookup entries + {len(languages)} languages, {size_kb:.1f} KB")

    return True


if __name__ == "__main__":
    ok = compile_lookup()
    sys.exit(0 if ok else 1)
