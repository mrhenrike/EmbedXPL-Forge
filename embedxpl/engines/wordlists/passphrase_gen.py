"""
passphrase_gen.py - Diceware and mnemonic passphrase generation.

Generates memorable passphrases from a word list using a cryptographically
secure random source (``secrets``). Ships a compact built-in list and accepts a
custom list (for example the EFF long list) via a file argument. Supports word
count, separators, capitalization, and optional appended digit and symbol.

Author: André Henrique (@mrhenrike)
Version: 1.0.0
"""
from __future__ import annotations

import logging
import secrets
from pathlib import Path
from typing import Generator, Optional

logger = logging.getLogger(__name__)

# Compact built-in word list. For higher entropy per word, pass a larger list
# such as the EFF long wordlist via --wordlist.
_BUILTIN = """
able acid acorn actor adapt agile album alert alien alloy amber anchor angle
ankle apple apron arbor arrow aspen atlas atom audio autumn axis bacon badge
baker balm bamboo banjo barn basil batch beach beam bean bear beaver bench
berry birch bison black blade bloom board boat bolt bonus boot booth borrow
bottle boxer brave bread brick bridge brief broom brown brush bubble bucket
buffalo bugle build bulb bundle bunny burst butter cabin cable cactus camel
candle canoe canvas canyon carbon cargo carol carpet carrot castle cedar
cell chalk charm cheese cherry chess chief chili chime cider cinema circle
clay clever cliff cloak clock cloud clover coach coast cobra cocoa comet
copper coral cotton cougar cover coyote crane crate cream creek crisp crown
crystal cube dagger daisy dance dawn deer delta denim depot desert diamond
dice diesel dinner ditch dolphin domino donut draft dragon dream drift drum
eagle earth ebony echo eclipse elder elk ember emerald engine ember evening
fable falcon fancy fang farm feather fern ferry fiber fig finch flame flask
fleet flint flock flour flower flute forest forge fossil fox frame frost
galaxy garden garlic gecko ginger glacier glass globe glove goat golden goose
grain grape grass gravel green grove guitar gulf hammer hamster harbor hawk
hazel heart hedge helmet heron hickory hill hollow honey hornet horse hotel
hunter husky igloo indigo iris iron island ivory jacket jaguar jasmine jelly
jewel jungle kangaroo kayak kernel kettle kitten koala ladder lagoon lantern
laptop laser lava leaf ledge lemon lentil leopard lily lime linen lion lizard
llama lobster locket lodge lotus lumber lunar lynx magnet mango maple marble
marsh meadow melon meteor mint mirror mist mitten monkey moose moss mother
motor muffin mule mushroom nectar needle nickel noble noodle north oak oasis
ocean olive onion opal orange orbit orchid otter owl oyster paddle palace
panda pansy panther paper parrot pasta peach peanut pearl pebble pecan pelican
pepper petal phoenix piano pigeon pillow pine pixel planet plum polar pond
poppy portal potato powder prairie pretzel prism prune puffin pumpkin puzzle
python quail quartz quilt rabbit raccoon radar radish rain ranch raven razor
recess rice ridge rifle river robin rocket rope rose ruby rug saddle saffron
sage salmon salt sand sapphire scarf script sculpt seal shadow shark sheep
shell shield shore shrimp silver siren sketch sky slate sloth snail snow
socket sofa solar sonar spark sparrow spice spider spinach spiral spring
sprout spruce squid stag stamp star stem stone stork storm stream sugar summit
sunset swan sword syrup table talon tandem tango teal temple thorn thunder
tiger timber toast tomato topaz torch tower trail train trout tulip tundra
turtle tusk twine ultra umbra unicorn valley vanilla velvet vine violet viper
volcano vortex walnut walrus wander wasp water weasel whale wheat willow window
winter wolf wood wren yacht yarn yeti zebra zenith zephyr zinc zone
""".split()


def _load_words(wordlist_path: Optional[str]) -> list[str]:
    """Load words from a file, or return the built-in list."""
    if not wordlist_path:
        return _BUILTIN
    p = Path(wordlist_path)
    if not p.exists():
        logger.warning("wordlist not found, using built-in: %s", wordlist_path)
        return _BUILTIN
    words: list[str] = []
    with p.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            w = line.strip()
            # Support diceware files with a leading dice index column.
            if "\t" in w:
                w = w.split("\t")[-1]
            elif " " in w and w.split()[0].isdigit():
                w = w.split()[-1]
            if w:
                words.append(w)
    return words or _BUILTIN


def generate(
    words: list[str],
    count: int,
    num_words: int = 4,
    separator: str = "-",
    capitalize: bool = False,
    add_number: bool = False,
    add_symbol: bool = False,
) -> Generator[str, None, None]:
    """Generate passphrases using a CSPRNG.

    Args:
        words: Source word list.
        count: Number of passphrases to produce.
        num_words: Words per passphrase.
        separator: Separator between words.
        capitalize: Capitalize each word.
        add_number: Append a random digit.
        add_symbol: Append a random symbol.

    Yields:
        Passphrase strings.
    """
    if not words:
        return
    symbols = "!@#$%&*?"
    for _ in range(count):
        chosen = [secrets.choice(words) for _ in range(num_words)]
        if capitalize:
            chosen = [w.capitalize() for w in chosen]
        phrase = separator.join(chosen)
        if add_number:
            phrase += str(secrets.randbelow(10))
        if add_symbol:
            phrase += secrets.choice(symbols)
        yield phrase


def handle_passphrase(args, ctx: dict) -> Optional[Generator[str, None, None]]:
    """CLI handler for the ``passphrase`` command."""
    words = _load_words(getattr(args, "wordlist", None))
    count = int(getattr(args, "count", 20) or 20)
    return generate(
        words,
        count,
        num_words=int(getattr(args, "words", 4) or 4),
        separator=getattr(args, "separator", "-"),
        capitalize=bool(getattr(args, "capitalize", False)),
        add_number=bool(getattr(args, "number", False)),
        add_symbol=bool(getattr(args, "symbol", False)),
    )
