"""
prompts.py - Todas as strings interativas do wizard WFH em 4 locales.

Uso:
    from embedxpl.engines.wordlists.i18n import t, set_session_locale
    set_session_locale("pt-br")
    print(t("wizard.personal_info"))

Author: André Henrique (@mrhenrike)
"""
from __future__ import annotations

# ── Catalog de traduções ───────────────────────────────────────────────────────
# Chaves hierárquicas com ponto. Valor por locale.

_CATALOG: dict[str, dict[str, str]] = {

    # ── Seleção de idioma ──────────────────────────────────────────────────────
    "lang.select_header": {
        "en":    "Select language / Selecione o idioma / Seleccione el idioma:",
        "pt-br": "Selecione o idioma:",
        "pt-pt": "Selecione o idioma:",
        "es":    "Seleccione el idioma:",
    },
    "lang.option_en": {
        "en": "1  English (default)", "pt-br": "1  English (padrão)",
        "pt-pt": "1  English (predefinição)", "es": "1  English (predeterminado)",
    },
    "lang.option_ptbr": {
        "en": "2  Portuguese (Brazil)", "pt-br": "2  Português (Brasil)",
        "pt-pt": "2  Português (Brasil)", "es": "2  Portugués (Brasil)",
    },
    "lang.option_ptpt": {
        "en": "3  Portuguese (Portugal)", "pt-br": "3  Português (Portugal)",
        "pt-pt": "3  Português (Portugal)", "es": "3  Portugués (Portugal)",
    },
    "lang.option_es": {
        "en": "4  Spanish", "pt-br": "4  Espanhol",
        "pt-pt": "4  Espanhol", "es": "4  Español",
    },
    "lang.prompt": {
        "en": "Choice [1-4, Enter=1]",
        "pt-br": "Escolha [1-4, Enter=1]",
        "pt-pt": "Escolha [1-4, Enter=1]",
        "es": "Opción [1-4, Enter=1]",
    },

    # ── Cabeçalho wizard ──────────────────────────────────────────────────────
    "wizard.header": {
        "en":    "WFH Profile Wizard - Press Enter to skip any field.",
        "pt-br": "WFH Assistente de Perfil - Pressione Enter para pular qualquer campo.",
        "pt-pt": "WFH Assistente de Perfil - Prima Enter para ignorar qualquer campo.",
        "es":    "WFH Asistente de Perfil - Pulse Enter para omitir cualquier campo.",
    },

    # ── Seções ────────────────────────────────────────────────────────────────
    "section.personal": {
        "en": "[ PERSONAL INFORMATION ]", "pt-br": "[ INFORMAÇÕES PESSOAIS ]",
        "pt-pt": "[ INFORMAÇÃO PESSOAL ]", "es": "[ INFORMACIÓN PERSONAL ]",
    },
    "section.partner": {
        "en": "[ PARTNER / SPOUSE ]", "pt-br": "[ PARCEIRO(A) / CÔNJUGE ]",
        "pt-pt": "[ PARCEIRO(A) / CÔNJUGE ]", "es": "[ PAREJA / CÓNYUGE ]",
    },
    "section.children": {
        "en": "[ CHILDREN ]", "pt-br": "[ FILHOS ]",
        "pt-pt": "[ FILHOS ]", "es": "[ HIJOS ]",
    },
    "section.pets": {
        "en": "[ PETS ]", "pt-br": "[ ANIMAIS DE ESTIMAÇÃO ]",
        "pt-pt": "[ ANIMAIS DE ESTIMAÇÃO ]", "es": "[ MASCOTAS ]",
    },
    "section.corporate": {
        "en": "[ CORPORATE DATA ]", "pt-br": "[ DADOS CORPORATIVOS ]",
        "pt-pt": "[ DADOS CORPORATIVOS ]", "es": "[ DATOS CORPORATIVOS ]",
    },
    "section.religion": {
        "en": "[ RELIGION / BELIEFS ]", "pt-br": "[ RELIGIÃO / CRENÇAS ]",
        "pt-pt": "[ RELIGIÃO / CRENÇAS ]", "es": "[ RELIGIÓN / CREENCIAS ]",
    },
    "section.keywords": {
        "en": "[ KEYWORDS & INTERESTS ]", "pt-br": "[ PALAVRAS-CHAVE E INTERESSES ]",
        "pt-pt": "[ PALAVRAS-CHAVE E INTERESSES ]", "es": "[ PALABRAS CLAVE E INTERESES ]",
    },
    "section.phrases": {
        "en": "[ PHRASES & JARGON ]", "pt-br": "[ FRASES E JARGÃO ]",
        "pt-pt": "[ FRASES E JARGÃO ]", "es": "[ FRASES Y JERGA ]",
    },
    "section.generation": {
        "en": "[ GENERATION OPTIONS ]", "pt-br": "[ OPÇÕES DE GERAÇÃO ]",
        "pt-pt": "[ OPÇÕES DE GERAÇÃO ]", "es": "[ OPCIONES DE GENERACIÓN ]",
    },
    "section.keyword_mutations": {
        "en": "[ KEYWORD MUTATIONS ]", "pt-br": "[ MUTAÇÕES DE PALAVRAS ]",
        "pt-pt": "[ MUTAÇÕES DE PALAVRAS ]", "es": "[ MUTACIONES DE PALABRAS ]",
    },
    "section.engines": {
        "en": "[ ENGINES ]", "pt-br": "[ MOTORES ]",
        "pt-pt": "[ MOTORES ]", "es": "[ MOTORES ]",
    },
    "section.output": {
        "en": "[ OUTPUT FINALIZATION ]", "pt-br": "[ FINALIZAÇÃO DA SAÍDA ]",
        "pt-pt": "[ FINALIZAÇÃO DA SAÍDA ]", "es": "[ FINALIZACIÓN DE SALIDA ]",
    },

    # ── Campos pessoais ───────────────────────────────────────────────────────
    "field.full_name": {
        "en": "Full name", "pt-br": "Nome completo",
        "pt-pt": "Nome completo", "es": "Nombre completo",
    },
    "field.short_name": {
        "en": "Short name or part of name", "pt-br": "Apelido ou parte do nome",
        "pt-pt": "Nome curto ou parte do nome", "es": "Nombre corto o parte del nombre",
    },
    "field.aliases": {
        "en": "Aliases / nicknames / name parts used in passwords (e.g. robotx, pessoax)",
        "pt-br": "Apelidos, nicknames e partes do nome usadas em senhas (ex. robotx, pessoax)",
        "pt-pt": "Alcunhas, nicknames e partes do nome usadas em palavras-passe (ex. robotx)",
        "es": "Apodos, alias y partes del nombre usadas en contraseñas (ej. Mel)",
    },
    "field.nicknames": {
        "en": "Nicknames / aliases", "pt-br": "Apelidos / nicknames",
        "pt-pt": "Alcunhas / nicknames", "es": "Apodos / alias",
    },
    "field.multi_hint": {
        "en": "(one per line, empty to stop)", "pt-br": "(uma por linha, vazio para parar)",
        "pt-pt": "(uma por linha, vazio para parar)", "es": "(una por línea, vacío para terminar)",
    },
    "field.national_id": {
        "en": "National ID / SSN / CPF (or leave blank)", "pt-br": "CPF / RG / Identidade (ou deixe em branco)",
        "pt-pt": "NIF / BI (ou deixe em branco)", "es": "DNI / CURP / RUT (o deje en blanco)",
    },
    "field.phones": {
        "en": "Phone numbers (DDI+DDD+number, e.g. +5511912345678)", "pt-br": "Telefones (DDI+DDD+número, ex. +5511912345678)",
        "pt-pt": "Telefones (indicativo+número, ex. +351912345678)", "es": "Teléfonos (prefijo+número, ej. +5491112345678)",
    },
    "field.city": {
        "en": "City / hometown", "pt-br": "Cidade / cidade natal",
        "pt-pt": "Cidade / terra natal", "es": "Ciudad / ciudad natal",
    },
    "field.state": {
        "en": "State / province / region", "pt-br": "Estado / UF / região",
        "pt-pt": "Distrito / região", "es": "Estado / provincia / región",
    },
    "field.country": {
        "en": "Country", "pt-br": "País",
        "pt-pt": "País", "es": "País",
    },

    # ── Datas ─────────────────────────────────────────────────────────────────
    "date.menu_header": {
        "en":    "Select input mode:",
        "pt-br": "Selecione o modo de entrada:",
        "pt-pt": "Selecione o modo de entrada:",
        "es":    "Seleccione modo de entrada:",
    },
    "date.label_birth": {
        "en": "Date of birth", "pt-br": "Data de nascimento",
        "pt-pt": "Data de nascimento", "es": "Fecha de nacimiento",
    },
    "date.mode_full": {
        "en": "1  Full date (dd/mm/yyyy or ddmmyyyy)", "pt-br": "1  Data completa (dd/mm/aaaa ou ddmmaaaa)",
        "pt-pt": "1  Data completa (dd/mm/aaaa ou ddmmaaaa)", "es": "1  Fecha completa (dd/mm/aaaa o ddmmaaaa)",
    },
    "date.mode_month_year": {
        "en": "2  Month and year only (mm/yyyy)", "pt-br": "2  Apenas mês e ano (mm/aaaa)",
        "pt-pt": "2  Apenas mês e ano (mm/aaaa)", "es": "2  Solo mes y año (mm/aaaa)",
    },
    "date.mode_year": {
        "en": "3  Year only (yyyy)", "pt-br": "3  Apenas o ano (aaaa)",
        "pt-pt": "3  Apenas o ano (aaaa)", "es": "3  Solo el año (aaaa)",
    },
    "date.mode_age": {
        "en": "4  Approximate age", "pt-br": "4  Idade aproximada",
        "pt-pt": "4  Idade aproximada", "es": "4  Edad aproximada",
    },
    "date.mode_age_sign": {
        "en": "5  Age + zodiac sign", "pt-br": "5  Idade + signo do zodíaco",
        "pt-pt": "5  Idade + signo do zodíaco", "es": "5  Edad + signo zodiacal",
    },
    "date.mode_skip": {
        "en": "6  Skip (no date)", "pt-br": "6  Pular (sem data)",
        "pt-pt": "6  Ignorar (sem data)", "es": "6  Omitir (sin fecha)",
    },
    "date.prompt_full": {
        "en": "Full date (dd/mm/yyyy)", "pt-br": "Data completa (dd/mm/aaaa)",
        "pt-pt": "Data completa (dd/mm/aaaa)", "es": "Fecha completa (dd/mm/aaaa)",
    },
    "date.prompt_month_year": {
        "en": "Month/year (mm/yyyy)", "pt-br": "Mês/ano (mm/aaaa)",
        "pt-pt": "Mês/ano (mm/aaaa)", "es": "Mes/año (mm/aaaa)",
    },
    "date.prompt_year": {
        "en": "Year (yyyy)", "pt-br": "Ano (aaaa)",
        "pt-pt": "Ano (aaaa)", "es": "Año (aaaa)",
    },
    "date.prompt_age": {
        "en": "Approximate age", "pt-br": "Idade aproximada",
        "pt-pt": "Idade aproximada", "es": "Edad aproximada",
    },
    "date.prompt_sign": {
        "en": "Zodiac sign (name)", "pt-br": "Signo do zodíaco (nome)",
        "pt-pt": "Signo do zodíaco (nome)", "es": "Signo zodiacal (nombre)",
    },
    "date.mode_select": {
        "en": "Choice [1-6, Enter=skip]", "pt-br": "Escolha [1-6, Enter=pular]",
        "pt-pt": "Escolha [1-6, Enter=ignorar]", "es": "Opción [1-6, Enter=omitir]",
    },

    # ── Dados de parceiro ─────────────────────────────────────────────────────
    "partner.add": {
        "en": "Add partner data? [y/N]", "pt-br": "Adicionar dados do parceiro(a)? [s/N]",
        "pt-pt": "Adicionar dados do parceiro(a)? [s/N]", "es": "¿Agregar datos de la pareja? [s/N]",
    },
    "partner.full_name": {
        "en": "Partner full name", "pt-br": "Nome completo do parceiro(a)",
        "pt-pt": "Nome completo do parceiro(a)", "es": "Nombre completo de la pareja",
    },
    "partner.nick": {
        "en": "Partner nickname", "pt-br": "Apelido do parceiro(a)",
        "pt-pt": "Alcunha do parceiro(a)", "es": "Apodo de la pareja",
    },
    "partner.birth": {
        "en": "Partner date of birth", "pt-br": "Data de nascimento do parceiro(a)",
        "pt-pt": "Data de nascimento do parceiro(a)", "es": "Fecha de nacimiento de la pareja",
    },

    # ── Filhos ────────────────────────────────────────────────────────────────
    "children.add": {
        "en": "Add children data? [y/N]", "pt-br": "Adicionar dados dos filhos? [s/N]",
        "pt-pt": "Adicionar dados dos filhos? [s/N]", "es": "¿Agregar datos de hijos? [s/N]",
    },
    "children.name": {
        "en": "Child name (Enter to stop)", "pt-br": "Nome do filho(a) (Enter para parar)",
        "pt-pt": "Nome do filho(a) (Enter para parar)", "es": "Nombre del hijo(a) (Enter para terminar)",
    },
    "children.birth": {
        "en": "{name} date of birth", "pt-br": "Data de nascimento de {name}",
        "pt-pt": "Data de nascimento de {name}", "es": "Fecha de nacimiento de {name}",
    },

    # ── Pets ──────────────────────────────────────────────────────────────────
    "pets.add": {
        "en": "Add pet data? [y/N]", "pt-br": "Adicionar dados de animais de estimação? [s/N]",
        "pt-pt": "Adicionar dados de animais de estimação? [s/N]", "es": "¿Agregar datos de mascotas? [s/N]",
    },
    "pets.name": {
        "en": "Pet name (Enter to stop)", "pt-br": "Nome do pet (Enter para parar)",
        "pt-pt": "Nome do animal (Enter para parar)", "es": "Nombre de la mascota (Enter para terminar)",
    },
    "pets.year": {
        "en": "{name} adoption/since year (YYYY, or skip)", "pt-br": "Ano de adoção/desde quando ({name}) (AAAA, ou pular)",
        "pt-pt": "Ano de adoção/desde quando ({name}) (AAAA, ou ignorar)", "es": "Año de adopción/desde cuando ({name}) (AAAA, u omitir)",
    },

    # ── Corporativo ───────────────────────────────────────────────────────────
    "corp.add": {
        "en": "Add corporate data? [y/N]", "pt-br": "Adicionar dados corporativos? [s/N]",
        "pt-pt": "Adicionar dados corporativos? [s/N]", "es": "¿Agregar datos corporativos? [s/N]",
    },
    "corp.name": {
        "en": "Company name / trade name", "pt-br": "Nome da empresa / nome fantasia",
        "pt-pt": "Nome da empresa / nome comercial", "es": "Nombre de la empresa / nombre comercial",
    },
    "corp.legal": {
        "en": "Legal company name", "pt-br": "Razão social",
        "pt-pt": "Denominação social", "es": "Razón social",
    },
    "corp.department": {
        "en": "Department / team / role (e.g. Cyber Security, SOC)", "pt-br": "Departamento / equipe / cargo (ex. Cyber Security, SOC)",
        "pt-pt": "Departamento / equipa / cargo (ex. Cyber Security, SOC)", "es": "Departamento / equipo / cargo (ej. Cyber Security, SOC)",
    },
    "corp.email": {
        "en": "Corporate email", "pt-br": "E-mail corporativo",
        "pt-pt": "E-mail corporativo", "es": "Correo corporativo",
    },
    "corp.domain": {
        "en": "Company domain (e.g. acme.example)", "pt-br": "Domínio da empresa (ex. acme.example)",
        "pt-pt": "Domínio da empresa (ex. empresa.pt)", "es": "Dominio de la empresa (ej. empresa.com)",
    },
    "corp.hire_date": {
        "en": "Hire date / start date", "pt-br": "Data de contratação / entrada",
        "pt-pt": "Data de admissão / entrada", "es": "Fecha de contratación / inicio",
    },

    # ── Redes sociais ─────────────────────────────────────────────────────────
    "social.handles": {
        "en": "Social media handles / usernames (Twitter, Instagram, etc.)", "pt-br": "Usuários em redes sociais (Twitter, Instagram, etc.)",
        "pt-pt": "Utilizadores em redes sociais (Twitter, Instagram, etc.)", "es": "Nombres de usuario en redes sociales (Twitter, Instagram, etc.)",
    },

    # ── País ──────────────────────────────────────────────────────────────────
    "country.full_variations": {
        "en": "Include full country variations? [Y/n]", "pt-br": "Incluir variações completas de país? [S/n]",
        "pt-pt": "Incluir variações completas de país? [S/n]", "es": "¿Incluir variaciones completas del país? [S/n]",
    },

    # ── Religião ──────────────────────────────────────────────────────────────
    "religion.add": {
        "en": "Add religion data? [y/N]", "pt-br": "Adicionar dados de religião? [s/N]",
        "pt-pt": "Adicionar dados de religião? [s/N]", "es": "¿Agregar datos de religión? [s/N]",
    },
    "religion.select": {
        "en": "Select [{range}]", "pt-br": "Selecione [{range}]",
        "pt-pt": "Selecione [{range}]", "es": "Seleccione [{range}]",
    },
    "religion.custom": {
        "en": "Enter your religion name", "pt-br": "Digite o nome da sua religião",
        "pt-pt": "Introduza o nome da sua religião", "es": "Introduzca el nombre de su religión",
    },
    "church.add": {
        "en": "Add church / congregation / group data? [y/N]", "pt-br": "Adicionar dados de igreja / congregação? [s/N]",
        "pt-pt": "Adicionar dados de igreja / congregação? [s/N]", "es": "¿Agregar datos de iglesia / congregación? [s/N]",
    },
    "church.name": {
        "en": "Church or congregation name (e.g. First Baptist)", "pt-br": "Nome da igreja ou congregação (ex. Assembleia de Deus SP)",
        "pt-pt": "Nome da igreja ou congregação (ex. Igreja Universal)", "es": "Nombre de la iglesia o congregación",
    },
    "church.group": {
        "en": "Small group / cell / ministry name (or skip)", "pt-br": "Nome do grupo / célula / ministério (ou pular)",
        "pt-pt": "Nome do grupo / célula / ministério (ou ignorar)", "es": "Nombre del grupo / célula / ministerio (u omitir)",
    },

    # ── Keywords ──────────────────────────────────────────────────────────────
    "keywords.list": {
        "en": "Keywords / topics of interest (hobbies, teams, idols, games...)", "pt-br": "Palavras-chave / interesses (hobbies, times, ídolos, jogos...)",
        "pt-pt": "Palavras-chave / interesses (passatempos, equipas, ídolos...)", "es": "Palabras clave / intereses (aficiones, equipos, ídolos...)",
    },
    "keywords.special_dates": {
        "en": "Special dates (anniversaries, events - any format)", "pt-br": "Datas especiais (aniversários, eventos - qualquer formato)",
        "pt-pt": "Datas especiais (aniversários, eventos - qualquer formato)", "es": "Fechas especiales (aniversarios, eventos - cualquier formato)",
    },

    # ── Frases ────────────────────────────────────────────────────────────────
    "phrases.hint": {
        "en":    "Each phrase generates acrostic initials + mutations (e.g. _E+FpQTq@2026).",
        "pt-br": "Cada frase gera iniciais do acróstico + variações (ex.: _E+FpQTq@2026).",
        "pt-pt": "Cada frase gera iniciais do acróstico + variações (ex.: _E+FpQTq@2026).",
        "es":    "Cada frase genera iniciales del acrónimo + mutaciones (ej. _E+FpQTq@2026).",
    },
    "phrases.enter": {
        "en": "Personal phrases / jargon / sayings (empty line to finish)", "pt-br": "Frases pessoais / jargão / expressões (linha vazia para terminar)",
        "pt-pt": "Frases pessoais / jargão / expressões (linha vazia para terminar)", "es": "Frases personales / jerga / dichos (línea vacía para terminar)",
    },
    "phrases.mode": {
        "en": "Phrase mode? 1=acrostic  2=full words  3=both (default: 3)", "pt-br": "Modo de frase? 1=acróstico  2=palavras completas  3=ambos (padrão: 3)",
        "pt-pt": "Modo de frase? 1=acróstico  2=palavras completas  3=ambos (predefinição: 3)", "es": "Modo de frase? 1=acrónimo  2=palabras completas  3=ambos (predeterminado: 3)",
    },
    "phrases.prefixes": {
        "en": "Include common prefixes (_, @, #, !)? [Y/n]", "pt-br": "Incluir prefixos comuns (_, @, #, !)? [S/n]",
        "pt-pt": "Incluir prefixos comuns (_, @, #, !)? [S/n]", "es": "¿Incluir prefijos comunes (_, @, #, !)? [S/n]",
    },
    "phrases.suffix_years": {
        "en": "Include year suffixes (@2026, #26, etc.)? [Y/n]", "pt-br": "Incluir sufixos de ano (@2026, #26, etc.)? [S/n]",
        "pt-pt": "Incluir sufixos de ano (@2026, #26, etc.)? [S/n]", "es": "¿Incluir sufijos de año (@2026, #26, etc.)? [S/n]",
    },

    # ── Opções de geração ─────────────────────────────────────────────────────
    "gen.leet_mode": {
        "en": "Leet mode [none/basic/medium/aggressive] (default: basic)", "pt-br": "Modo leet [none/basic/medium/aggressive] (padrão: basic)",
        "pt-pt": "Modo leet [none/basic/medium/aggressive] (predefinição: basic)", "es": "Modo leet [none/basic/medium/aggressive] (predeterminado: basic)",
    },
    "gen.leet_menu": {
        "en": "Leet mode - 1=none  2=basic (default)  3=medium  4=aggressive  (or type slug)",
        "pt-br": "Modo leet - 1=none  2=basic (padrão)  3=medium  4=aggressive  (ou digite o slug)",
        "pt-pt": "Modo leet - 1=none  2=basic (predefinição)  3=medium  4=aggressive  (ou escreva o slug)",
        "es": "Modo leet - 1=none  2=basic (predeterminado)  3=medium  4=aggressive  (o escriba el slug)",
    },
    "gen.with_spaces": {
        "en": "Include spaces between words? [y/N]", "pt-br": "Incluir espaços entre palavras? [s/N]",
        "pt-pt": "Incluir espaços entre palavras? [s/N]", "es": "¿Incluir espacios entre palabras? [s/N]",
    },
    "gen.behavior_patterns": {
        "en": "Include behavioral/religious patterns from knowledge base? [Y/n]", "pt-br": "Incluir padrões comportamentais/religiosos da base de conhecimento? [S/n]",
        "pt-pt": "Incluir padrões comportamentais/religiosos da base de conhecimento? [S/n]", "es": "¿Incluir patrones conductuales/religiosos de la base de conocimiento? [S/n]",
    },
    "gen.min_len": {
        "en": "Minimum password length (default: 6)", "pt-br": "Comprimento mínimo da senha (padrão: 6)",
        "pt-pt": "Comprimento mínimo da senha (predefinição: 6)", "es": "Longitud mínima de contraseña (predeterminado: 6)",
    },
    "gen.max_len": {
        "en": "Maximum password length (default: 32, 0 = unlimited)", "pt-br": "Comprimento máximo da senha (padrão: 32, 0 = ilimitado)",
        "pt-pt": "Comprimento máximo da senha (predefinição: 32, 0 = ilimitado)", "es": "Longitud máxima de contraseña (predeterminado: 32, 0 = sin límite)",
    },
    "gen.include_specials": {
        "en": "Add special characters to combinations? [y/N]", "pt-br": "Adicionar caracteres especiais às combinações? [s/N]",
        "pt-pt": "Adicionar caracteres especiais às combinações? [s/N]", "es": "¿Agregar caracteres especiales a las combinaciones? [s/N]",
    },
    "gen.include_recent_years": {
        "en": "Include rolling recent year tokens (current + previous year)? [Y/n]", "pt-br": "Incluir tokens de anos recentes (ano atual + anterior)? [S/n]",
        "pt-pt": "Incluir tokens de anos recentes (ano atual + anterior)? [S/n]", "es": "¿Incluir tokens de años recientes (año actual + anterior)? [S/n]",
    },
    "gen.recent_years_lookback": {
        "en": "Recent years lookback (0=current only, 1=current+previous, default: 1)", "pt-br": "Retroação de anos recentes (0=só atual, 1=atual+anterior, padrão: 1)",
        "pt-pt": "Retroação de anos recentes (0=só atual, 1=atual+anterior, predefinição: 1)", "es": "Años recientes hacia atrás (0=solo actual, 1=actual+anterior, predeterminado: 1)",
    },

    # ── Mutações de keywords ───────────────────────────────────────────────────
    "mutations.ask": {
        "en": "Generate keyword mutations? [y/N]", "pt-br": "Gerar mutações de palavras-chave? [s/N]",
        "pt-pt": "Gerar mutações de palavras-chave? [s/N]", "es": "¿Generar mutaciones de palabras clave? [s/N]",
    },
    "mutations.hint": {
        "en":    "  1  letter_reverse     xpto → otpx\n  2  syllable_reverse   xpto → otpx\n  3  syllable_rotate    xpto → otpx (cyclic)",
        "pt-br": "  1  letter_reverse     xpto → otpx\n  2  syllable_reverse   xpto → otpx\n  3  syllable_rotate    xpto → otpx (cíclico)",
        "pt-pt": "  1  letter_reverse     xpto → otpx\n  2  syllable_reverse   xpto → otpx\n  3  syllable_rotate    xpto → otpx (cíclico)",
        "es":    "  1  letter_reverse     xpto → otpx\n  2  syllable_reverse   xpto → otpx\n  3  syllable_rotate    xpto → otpx (cíclico)",
    },
    "mutations.select": {
        "en": "Select [1-3, comma-separated, Enter=skip]", "pt-br": "Selecione [1-3, separado por vírgula, Enter=pular]",
        "pt-pt": "Selecione [1-3, separado por vírgula, Enter=ignorar]", "es": "Seleccione [1-3, separado por coma, Enter=omitir]",
    },

    # ── Menu de motores ───────────────────────────────────────────────────────
    "engines.header": {
        "en":    "Select variation engines:\n  Presets: L=light  M=medium  P=potent  N=NUCLEAR\n  Custom:  1-3  or  1,3,5  or  1-3,8,10\n  Default: Enter = all engines on by default",
        "pt-br": "Selecione os motores de variação:\n  Presets: L=leve  M=médio  P=potente  N=NUCLEAR\n  Manual:  1-3  ou  1,3,5  ou  1-3,8,10\n  Padrão:  Enter = todos os motores padrão ativos",
        "pt-pt": "Selecione os motores de variação:\n  Presets: L=leve  M=médio  P=potente  N=NUCLEAR\n  Manual:  1-3  ou  1,3,5  ou  1-3,8,10\n  Predefinição: Enter = todos os motores predefinidos ativos",
        "es":    "Seleccione los motores de variación:\n  Presets: L=ligero  M=medio  P=potente  N=NUCLEAR\n  Manual:  1-3  o  1,3,5  o  1-3,8,10\n  Predeterminado: Enter = todos los motores predeterminados activos",
    },
    "engines.prompt": {
        "en": "Choice (Enter=defaults)", "pt-br": "Escolha (Enter=padrão)",
        "pt-pt": "Escolha (Enter=predefinição)", "es": "Opción (Enter=predeterminado)",
    },
    "engines.nuclear_warning": {
        "en":    "WARNING: NUCLEAR preset runs ALL engines including heavy models. Requires --limit and >4GB free RAM.",
        "pt-br": "AVISO: o preset NUCLEAR roda TODOS os motores, incluindo modelos pesados. Requer --limit e >4 GB de RAM livre.",
        "pt-pt": "AVISO: o preset NUCLEAR corre TODOS os motores, incluindo modelos pesados. Requer --limit e >4 GB de RAM livre.",
        "es":    "ADVERTENCIA: el preset NUCLEAR ejecuta TODOS los motores, incluidos modelos pesados. Requiere --limit y >4 GB de RAM libre.",
    },
    "engines.nuclear_ram_block": {
        "en":    "ERROR: NUCLEAR requires at least 4 GB free RAM. Current free: {free:.1f} GB. Use P=potent instead.",
        "pt-br": "ERRO: NUCLEAR requer pelo menos 4 GB de RAM livre. Livre atual: {free:.1f} GB. Use P=potente.",
        "pt-pt": "ERRO: NUCLEAR requer pelo menos 4 GB de RAM livre. Livre atual: {free:.1f} GB. Use P=potente.",
        "es":    "ERROR: NUCLEAR requiere al menos 4 GB de RAM libre. Libre actual: {free:.1f} GB. Use P=potente.",
    },
    "engines.nuclear_fallback": {
        "en": "Try P=potent or M=medium, or press Enter for defaults.",
        "pt-br": "Use P=potente ou M=médio, ou Enter para o padrão.",
        "pt-pt": "Use P=potente ou M=médio, ou Enter para a predefinição.",
        "es": "Use P=potente o M=medio, o Enter para el predeterminado.",
    },
    "engines.nuclear_mark": {
        "en": "(* NUCLEAR-only engines marked with *)",
        "pt-br": "(* motores exclusivos do NUCLEAR marcados com *)",
        "pt-pt": "(* motores exclusivos do NUCLEAR marcados com *)",
        "es": "(* motores exclusivos de NUCLEAR marcados con *)",
    },

    # ── Nomes dos motores ────────────────────────────────────────────────────
    "engines.token_variants.name":      {"en": "Token variants",       "pt-br": "Variações de tokens",      "pt-pt": "Variações de tokens",      "es": "Variantes de tokens"},
    "engines.date_tokens.name":         {"en": "Date tokens",          "pt-br": "Tokens de data",           "pt-pt": "Tokens de data",           "es": "Tokens de fecha"},
    "engines.depth_combos.name":        {"en": "Depth combinations",   "pt-br": "Combinações por depth",    "pt-pt": "Combinações por depth",    "es": "Combinaciones por profundidad"},
    "engines.relationship_combos.name": {"en": "Relationship combos",  "pt-br": "Cruzamentos de relações",  "pt-pt": "Cruzamentos de relações",  "es": "Combinaciones relacionales"},
    "engines.phrase_acrostic.name":     {"en": "Phrase acrostic",      "pt-br": "Acróstico de frases",      "pt-pt": "Acróstico de frases",      "es": "Acrónimo de frases"},
    "engines.phrase_full.name":         {"en": "Phrase full words",    "pt-br": "Palavras da frase",        "pt-pt": "Palavras da frase",        "es": "Palabras de la frase"},
    "engines.behavior_patterns.name":   {"en": "Behavior patterns",    "pt-br": "Padrões comportamentais",  "pt-pt": "Padrões comportamentais",  "es": "Patrones de comportamiento"},
    "engines.cupp_concats.name":        {"en": "CUPP concatenations",  "pt-br": "Concatenações CUPP",       "pt-pt": "Concatenações CUPP",       "es": "Concatenaciones CUPP"},
    "engines.reversed_tokens.name":     {"en": "Reversed tokens",      "pt-br": "Tokens invertidos",        "pt-pt": "Tokens invertidos",        "es": "Tokens invertidos"},
    "engines.prince.name":              {"en": "PRINCE chains",        "pt-br": "Cadeias PRINCE",           "pt-pt": "Cadeias PRINCE",           "es": "Cadenas PRINCE"},
    "engines.rsmangler.name":           {"en": "RSMangler rules",      "pt-br": "Regras RSMangler",         "pt-pt": "Regras RSMangler",         "es": "Reglas RSMangler"},
    "engines.builtin_mangle.name":      {"en": "Built-in mangle",      "pt-br": "Mangling interno",         "pt-pt": "Mangling interno",         "es": "Mangling integrado"},
    "engines.osint_scrape.name":        {"en": "OSINT web scrape",     "pt-br": "Scrape OSINT web",         "pt-pt": "Scrape OSINT web",         "es": "Scrape OSINT web"},
    "engines.password_dna.name":        {"en": "Password DNA",         "pt-br": "DNA de senha",             "pt-pt": "DNA de senha",             "es": "ADN de contraseña"},
    "engines.rank_likelihood.name":     {"en": "Rank by likelihood",   "pt-br": "Ordenar por probabilidade","pt-pt": "Ordenar por probabilidade","es": "Ordenar por probabilidad"},
    "engines.maya_rank.name":           {"en": "MAYA DL rank (opt.)",  "pt-br": "Ranqueamento MAYA DL (op.)","pt-pt": "Ranqueamento MAYA DL (op.)","es": "Ranking MAYA DL (op.)"},
    "engines.osint_perm.name":          {"en": "OSINT permutations",   "pt-br": "Permutações OSINT",        "pt-pt": "Permutações OSINT",        "es": "Permutaciones OSINT"},
    "engines.pcfg_hybrid.name":         {"en": "PCFG hybrid",          "pt-br": "PCFG híbrido",             "pt-pt": "PCFG híbrido",             "es": "PCFG híbrido"},
    "engines.markov_omen.name":         {"en": "Markov/OMEN (heavy)",  "pt-br": "Markov/OMEN (pesado)",     "pt-pt": "Markov/OMEN (pesado)",     "es": "Markov/OMEN (pesado)"},
    "engines.num2text_dates.name":      {"en": "Dates as text",        "pt-br": "Datas por extenso",        "pt-pt": "Datas por extenso",        "es": "Fechas en texto"},
    "engines.pattern_templates.name":   {"en": "Pattern templates",    "pt-br": "Padrões estruturados",     "pt-pt": "Padrões estruturados",     "es": "Plantillas de patrones"},
    "engines.rulegen_oldpwd.name":      {"en": "Rule gen (old pwd)",   "pt-br": "Geração de regras (senha antiga)", "pt-pt": "Geração de regras (senha antiga)", "es": "Generación de reglas (pwd antigua)"},
    "engines.positional_leet.name":     {"en": "Positional leet",      "pt-br": "Leet posicional",          "pt-pt": "Leet posicional",          "es": "Leet posicional"},
    "engines.country_locale.name":      {"en": "Country/locale tokens","pt-br": "Tokens de país/locale",    "pt-pt": "Tokens de país/locale",    "es": "Tokens de país/locale"},
    "engines.corp_cross.name":          {"en": "Corporate cross",      "pt-br": "Cruzamento corporativo",   "pt-pt": "Cruzamento corporativo",   "es": "Cruzamiento corporativo"},
    "engines.scrape_merge.name":        {"en": "Scrape merge",         "pt-br": "Fusão de scrape",          "pt-pt": "Fusão de scrape",          "es": "Fusión de scrape"},
    "engines.output_finalize.name":     {"en": "Output finalize",      "pt-br": "Finalização da saída",     "pt-pt": "Finalização da saída",     "es": "Finalización de salida"},
    "engines.keyword_mutations.name":   {"en": "Keyword mutations",    "pt-br": "Mutações de palavras",     "pt-pt": "Mutações de palavras",     "es": "Mutaciones de palabras"},
    "engines.cewl_mut.name":            {"en": "CeWL scrape preset",   "pt-br": "Preset CeWL scrape",       "pt-pt": "Preset CeWL scrape",       "es": "Preset CeWL scrape"},

    # Engine descriptions (fallback: registry English string)
    "engines.charset.desc":             {"en": "Charset and mask generation", "pt-br": "Geração de charset e máscaras", "pt-pt": "Geração de charset e máscaras", "es": "Generación de charset y máscaras"},
    "engines.profile.desc":             {"en": "Personal target profiling", "pt-br": "Perfil de alvo pessoal", "pt-pt": "Perfil de alvo pessoal", "es": "Perfil de objetivo personal"},
    "engines.osint_perm.desc":          {"en": "OSINT token permutations", "pt-br": "Permutações de tokens OSINT", "pt-pt": "Permutações de tokens OSINT", "es": "Permutaciones de tokens OSINT"},
    "engines.cewl_mut.desc":            {"en": "CeWL scrape + RSMangler + John rules", "pt-br": "CeWL scrape + RSMangler + regras John", "pt-pt": "CeWL scrape + RSMangler + regras John", "es": "CeWL scrape + RSMangler + reglas John"},
    "engines.rank_likelihood.desc":     {"en": "Pattern-based likelihood ranking", "pt-br": "Ranking por padrões de probabilidade", "pt-pt": "Ranking por padrões de probabilidade", "es": "Ranking por patrones de probabilidad"},
    "engines.maya_rank.desc":           {"en": "MAYA ML-based password ranking", "pt-br": "Ranking ML MAYA de senhas", "pt-pt": "Ranking ML MAYA de palavras-passe", "es": "Ranking ML MAYA de contraseñas"},

    # ── Finalização da saída ──────────────────────────────────────────────────
    "output.sanitize": {
        "en": "Sanitize and remove duplicates? [Y/n, Enter=yes]", "pt-br": "Sanitizar e remover duplicatas? [S/n, Enter=sim]",
        "pt-pt": "Sanitizar e remover duplicados? [S/n, Enter=sim]", "es": "¿Sanitizar y eliminar duplicados? [S/n, Enter=sí]",
    },
    "output.sort": {
        "en": "Sort? 0=keep order  1=alpha asc  2=alpha desc  3=length asc  4=length desc [Enter=0]",
        "pt-br": "Ordenar? 0=manter ordem  1=alfa asc  2=alfa desc  3=tamanho asc  4=tamanho desc [Enter=0]",
        "pt-pt": "Ordenar? 0=manter ordem  1=alfa asc  2=alfa desc  3=tamanho asc  4=tamanho desc [Enter=0]",
        "es": "¿Ordenar? 0=mantener orden  1=alfa asc  2=alfa desc  3=longitud asc  4=longitud desc [Enter=0]",
    },
    "output.format": {
        "en": "Format? 1=lst  2=txt  3=tar  4=tar.gz  5=zip [Enter=1 lst]",
        "pt-br": "Formato? 1=lst  2=txt  3=tar  4=tar.gz  5=zip [Enter=1 lst]",
        "pt-pt": "Formato? 1=lst  2=txt  3=tar  4=tar.gz  5=zip [Enter=1 lst]",
        "es": "Formato? 1=lst  2=txt  3=tar  4=tar.gz  5=zip [Enter=1 lst]",
    },
    "output.summary": {
        "en": "  → Export: sanitize={sanitize} | sort={sort} | format={format}",
        "pt-br": "  → Exportação: sanitizar={sanitize} | ordenar={sort} | formato={format}",
        "pt-pt": "  → Exportação: sanitizar={sanitize} | ordenar={sort} | formato={format}",
        "es": "  → Exportación: sanitizar={sanitize} | ordenar={sort} | formato={format}",
    },
    "output.val_yes": {
        "en": "yes", "pt-br": "sim", "pt-pt": "sim", "es": "sí",
    },
    "output.val_no": {
        "en": "no", "pt-br": "não", "pt-pt": "não", "es": "no",
    },
    "output.path": {
        "en": "Output file path (leave blank for default)", "pt-br": "Caminho do arquivo de saída (Enter para usar padrão)",
        "pt-pt": "Caminho do ficheiro de saída (Enter para usar predefinição)", "es": "Ruta del archivo de salida (Enter para usar predeterminado)",
    },
    "output.default_hint": {
        "en": "Leave blank to use default: {path}", "pt-br": "Enter em branco para usar padrão: {path}",
        "pt-pt": "Enter em branco para usar predefinição: {path}", "es": "Enter en blanco para usar predeterminado: {path}",
    },
    "output.using_path": {
        "en": "  → Using output path from CLI: {path}", "pt-br": "  → Usando caminho da CLI: {path}",
        "pt-pt": "  → A usar caminho da CLI: {path}", "es": "  → Usando ruta de la CLI: {path}",
    },
    "output.will_save": {
        "en": "  → Will save to: {path}", "pt-br": "  → Salvará em: {path}",
        "pt-pt": "  → Guardará em: {path}", "es": "  → Se guardará en: {path}",
    },

    # ── Mensagens gerais ──────────────────────────────────────────────────────
    "msg.skip": {
        "en": "(skipped)", "pt-br": "(pulado)", "pt-pt": "(ignorado)", "es": "(omitido)",
    },
    "msg.invalid_choice": {
        "en": "Invalid choice. Try again.", "pt-br": "Opção inválida. Tente novamente.",
        "pt-pt": "Opção inválida. Tente novamente.", "es": "Opción inválida. Inténtelo de nuevo.",
    },
    "msg.press_enter_skip": {
        "en": "Press Enter to skip.", "pt-br": "Pressione Enter para pular.",
        "pt-pt": "Prima Enter para ignorar.", "es": "Pulse Enter para omitir.",
    },
}


def get_catalog() -> dict[str, dict[str, str]]:
    """Retorna o catálogo completo de traduções."""
    return _CATALOG
