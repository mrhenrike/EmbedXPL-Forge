"""Interactive Wordlist Generator for Bruteforce Attacks.

Generates custom password and username wordlists based on target profile
(corporate vs personal) with mutation rules inspired by crunch/CUPP,
tailored for router and network device contexts.

After generation, the user can directly feed the output to any bruteforce
module via the file:// URI option.

Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""

import os

from embedxpl.core.exploit import *
from embedxpl.core.wordlist.generator import (
    TargetProfile,
    generate_wordlist,
    save_wordlist,
    estimate_size_human,
)


def _ask(prompt: str, default: str = "") -> str:
    """Prompt the user for input with an optional default."""
    suffix = " [{}]: ".format(default) if default else ": "
    try:
        value = input(prompt + suffix).strip()
    except (EOFError, KeyboardInterrupt):
        print("")
        return default
    return value if value else default


def _ask_bool(prompt: str, default: bool = True) -> bool:
    """Prompt the user for a yes/no answer."""
    hint = "Y/n" if default else "y/N"
    try:
        value = input("{} [{}]: ".format(prompt, hint)).strip().lower()
    except (EOFError, KeyboardInterrupt):
        print("")
        return default
    if value in ("y", "yes", "s", "sim"):
        return True
    if value in ("n", "no", "nao", "não"):
        return False
    return default


class Exploit(Exploit):
    __info__ = {
        "name": "Interactive Wordlist Generator",
        "description": "Generates custom password and username wordlists based on target "
                       "profile (corporate or personal). Applies mutation rules "
                       "(leet speak, case variations, number suffixes, date fragments, "
                       "word combinations) to produce a focused wordlist for bruteforce "
                       "attacks. The user answers a series of questions about the target, "
                       "then the tool estimates size and asks for confirmation before "
                       "generating the file. Output is ready to use as file:// in any "
                       "bruteforce module.",
        "authors": (
            "André Henrique (@mrhenrike)",
        ),
        "references": (
            "https://github.com/Mebus/cupp",
            "https://github.com/jim3ma/crunch",
        ),
        "devices": (
            "Any target — wordlist generation is target-independent",
        ),
    }

    output_dir = OptString("", "Directory to save generated wordlists (default: current dir)")
    min_length = OptInteger(4, "Minimum password length")
    max_length = OptInteger(16, "Maximum password length")
    max_candidates = OptInteger(50000, "Maximum password candidates to generate")
    enable_leet = OptBool(True, "Apply leet-speak mutations (a→@, e→3, etc.)")
    enable_case = OptBool(True, "Apply case mutations (upper, lower, capitalize)")
    enable_numbers = OptBool(True, "Append common number/symbol suffixes")

    def run(self):
        print_status("=" * 60)
        print_status("  EmbedXPL-Forge Wordlist Generator")
        print_status("  Generates focused wordlists for bruteforce attacks")
        print_status("=" * 60)
        print_status("")

        # Step 1: Target type
        print_status("[1/5] Target Profile Type")
        print_info("  This affects the base seed words and mutation strategy.")
        print_info("  'corporate' → company names, departments, vendor defaults")
        print_info("  'personal'  → personal names, dates, pets, family")
        print_status("")

        profile_type = _ask("Target type (corporate/personal)", "corporate").lower()
        if profile_type not in ("corporate", "personal"):
            print_error("Invalid profile type. Using 'corporate'.")
            profile_type = "corporate"

        profile = TargetProfile(
            profile_type=profile_type,
            min_length=self.min_length,
            max_length=self.max_length,
            max_candidates=self.max_candidates,
            enable_leet=self.enable_leet,
            enable_case_mutations=self.enable_case,
            enable_number_suffix=self.enable_numbers,
        )

        # Step 2: Profile-specific questions
        print_status("")
        print_status("[2/5] Target Information")

        if profile_type == "corporate":
            self._ask_corporate(profile)
        else:
            self._ask_personal(profile)

        # Step 3: Shared/device fields
        print_status("")
        print_status("[3/5] Device and Network Information")

        profile.ssid_name = _ask("Wi-Fi SSID name (if known)")
        profile.device_vendor = _ask("Device vendor (e.g. TP-Link, MikroTik)")
        profile.device_model = _ask("Device model (e.g. Archer C7, RB4011)")
        profile.city = _ask("City/location (if relevant)")
        profile.zip_code = _ask("ZIP/postal code (if relevant)")
        profile.phone_suffix = _ask("Phone number suffix — last 4-6 digits (if relevant)")

        custom_raw = _ask("Custom seed words (comma-separated, e.g. 'safelabs,projeto,rede')")
        if custom_raw:
            profile.custom_words = [w.strip() for w in custom_raw.split(",") if w.strip()]

        # Step 4: Estimate and confirm
        print_status("")
        print_status("[4/5] Generation Preview")
        print_status("")

        result = generate_wordlist(profile)

        print_info("Profile type     : {}".format(profile_type))
        print_info("Base seed words  : {}".format(result.base_words_used))
        print_info("Mutations applied: {}".format(result.mutations_applied))
        print_info("Passwords generated: {}".format(len(result.passwords)))
        print_info("Usernames generated: {}".format(len(result.usernames)))
        print_info("Estimated file size: {}".format(estimate_size_human(result.estimated_size_bytes)))
        print_info("Password length range: {}-{} chars".format(profile.min_length, profile.max_length))

        if len(result.passwords) >= 10000:
            print_status("")
            print_status("WARNING: Large wordlist ({} entries). Bruteforce may take "
                         "significant time depending on target service.".format(len(result.passwords)))

        print_status("")
        if not _ask_bool("Proceed with generation and save to files?"):
            print_error("Generation cancelled by user.")
            return

        # Step 5: Save files
        print_status("")
        print_status("[5/5] Saving Wordlists")

        out_dir = self.output_dir if self.output_dir else os.getcwd()

        pwd_filename = "exf_generated_passwords_{}.txt".format(profile_type)
        usr_filename = "exf_generated_usernames_{}.txt".format(profile_type)

        pwd_path = save_wordlist(result.passwords, os.path.join(out_dir, pwd_filename), "passwords")
        result.passwords_file = str(pwd_path)

        if result.usernames:
            usr_path = save_wordlist(result.usernames, os.path.join(out_dir, usr_filename), "usernames")
            result.usernames_file = str(usr_path)

        print_status("")
        print_success("Wordlists generated successfully!")
        print_status("")
        print_info("Passwords: {} ({} entries, {})".format(
            result.passwords_file, len(result.passwords),
            estimate_size_human(result.estimated_size_bytes),
        ))
        if result.usernames_file:
            print_info("Usernames: {} ({} entries)".format(
                result.usernames_file, len(result.usernames),
            ))

        print_status("")
        print_status("To use in bruteforce modules, set:")
        print_info("  set passwords file://{}".format(result.passwords_file))
        if result.usernames_file:
            print_info("  set usernames file://{}".format(result.usernames_file))

        print_status("")
        print_info("Sample passwords (first 15):")
        for pwd in result.passwords[:15]:
            print_info("  {}".format(pwd))
        if len(result.passwords) > 15:
            print_info("  ... and {} more".format(len(result.passwords) - 15))

    def _ask_corporate(self, profile: TargetProfile) -> None:
        """Collect corporate-specific profile fields."""
        print_info("  Fill in what you know about the target organization.")
        print_info("  Leave blank to skip any field.")
        print_status("")

        profile.company_name = _ask("Company/organization name")
        profile.company_acronym = _ask("Company acronym or short name")
        profile.company_domain = _ask("Company domain (e.g. acme.com)")
        profile.department = _ask("Department (e.g. TI, infra, NOC)")
        profile.admin_name = _ask("Known admin full name")

    def _ask_personal(self, profile: TargetProfile) -> None:
        """Collect personal-specific profile fields."""
        print_info("  Fill in what you know about the target person.")
        print_info("  Leave blank to skip any field.")
        print_status("")

        profile.first_name = _ask("First name")
        profile.last_name = _ask("Last name")
        profile.nickname = _ask("Nickname or alias")
        profile.birth_date = _ask("Birth date (DDMMYYYY)")
        profile.pet_name = _ask("Pet name")
        profile.partner_name = _ask("Partner/spouse name")

    @mute
    def check(self):
        return True
