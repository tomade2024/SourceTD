import re
import math
import time
import hashlib
import sqlite3
from dataclasses import dataclass
from typing import Dict, Tuple, Optional, List

import requests
from bs4 import BeautifulSoup
import streamlit as st
import bcrypt


# ============================
# CONFIG
# ============================
APP_NAME = "SourceTD (MVP)"
DB_PATH = "sourcetd.db"

# Tarif-Konstanten
TIER_FREE = "free"
TIER_BASIC = "basic"   # zweiter bezahlbarer Tarif
TIER_PRO = "pro"

# Limits pro Tag je Tarif
DAILY_LIMITS: Dict[str, int] = {
    TIER_FREE: 20,        # z. B. 20 Analysen/Tag
    TIER_BASIC: 100,      # z. B. 100 Analysen/Tag
    TIER_PRO: 10_000,     # quasi unbegrenzt im MVP
}

# URL Cache (Session)
CACHE_TTL_SECONDS = 60 * 30
DEFAULT_TIMEOUT = 12


# ============================
# HELFER
# ============================
def get_daily_limit(tier: str) -> int:
    return DAILY_LIMITS.get(tier, DAILY_LIMITS[TIER_FREE])


def day_key_local() -> str:
    return time.strftime("%Y-%m-%d")


def stable_key(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8", errors="ignore")).hexdigest()


# ============================
# DATABASE (SQLite)
# ============================
def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    return conn


def init_db():
    conn = db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            pw_hash BLOB NOT NULL,
            tier TEXT NOT NULL DEFAULT 'free',
            created_at INTEGER NOT NULL
        );
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS usage_daily (
            user_id INTEGER NOT NULL,
            day_key TEXT NOT NULL,
            count INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (user_id, day_key),
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
    """)
    # Feedback-Tabelle
    conn.execute("""
        CREATE TABLE IF NOT EXISTS feedback (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            created_at INTEGER NOT NULL,
            helpful INTEGER NOT NULL,           -- 1 = ja, 0 = nein
            comment TEXT,
            tscore INTEGER,
            source_url TEXT,
            source_mode TEXT,                   -- z.B. "URL analysieren" oder "Text einfügen"
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
    """)
    conn.commit()
    conn.close()


def get_user_by_email(email: str) -> Optional[dict]:
    conn = db()
    cur = conn.execute(
        "SELECT id, email, pw_hash, tier FROM users WHERE email = ?",
        (email.lower().strip(),),
    )
    row = cur.fetchone()
    conn.close()
    if not row:
        return None
    return {
        "id": row[0],
        "email": row[1],
        "pw_hash": row[2],
        "tier": row[3],
    }


def create_user(email: str, password: str) -> Tuple[bool, str]:
    email = email.lower().strip()
    if not re.match(r"^[^@]+@[^@]+\.[^@]+$", email):
        return False, "Bitte eine gültige E-Mail-Adresse eingeben."
    if len(password) < 8:
        return False, "Passwort muss mindestens 8 Zeichen lang sein."

    pw_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
    conn = db()
    try:
        conn.execute(
            "INSERT INTO users (email, pw_hash, tier, created_at) VALUES (?, ?, ?, ?)",
            (email, pw_hash, TIER_FREE, int(time.time())),
        )
        conn.commit()
        return True, "Account erstellt. Du kannst dich jetzt anmelden."
    except sqlite3.IntegrityError:
        return False, "Diese E-Mail ist bereits registriert."
    finally:
        conn.close()


def verify_login(email: str, password: str) -> Tuple[bool, Optional[dict], str]:
    user = get_user_by_email(email)
    if not user:
        return False, None, "Login fehlgeschlagen (E-Mail oder Passwort falsch)."

    stored = user["pw_hash"]
    try:
        ok = bcrypt.checkpw(password.encode("utf-8"), stored)
    except Exception as e:
        return False, None, f"Fehler bei der Passwortprüfung: {e}"

    if not ok:
        return False, None, "Login fehlgeschlagen (E-Mail oder Passwort falsch)."

    return True, user, ""


def get_usage_count(user_id: int, day: str) -> int:
    conn = db()
    cur = conn.execute(
        "SELECT count FROM usage_daily WHERE user_id = ? AND day_key = ?",
        (user_id, day),
    )
    row = cur.fetchone()
    conn.close()
    return int(row[0]) if row else 0


def increment_usage(user_id: int, day: str, amount: int = 1) -> None:
    conn = db()
    conn.execute(
        """
        INSERT INTO usage_daily (user_id, day_key, count)
        VALUES (?, ?, ?)
        ON CONFLICT(user_id, day_key) DO UPDATE SET count = count + ?;
        """,
        (user_id, day, amount, amount),
    )
    conn.commit()
    conn.close()


def set_tier(user_id: int, tier: str) -> None:
    conn = db()
    conn.execute(
        "UPDATE users SET tier = ? WHERE id = ?",
        (tier, user_id),
    )
    conn.commit()
    conn.close()


def save_feedback(
    user_id: Optional[int],
    helpful: bool,
    comment: str,
    tscore: Optional[int],
    source_url: Optional[str],
    source_mode: str,
) -> None:
    conn = db()
    conn.execute(
        """
        INSERT INTO feedback (user_id, created_at, helpful, comment, tscore, source_url, source_mode)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            user_id,
            int(time.time()),
            1 if helpful else 0,
            comment.strip() if comment else None,
            int(tscore) if tscore is not None else None,
            source_url.strip() if source_url else None,
            source_mode,
        ),
    )
    conn.commit()
    conn.close()


# ============================
# TEXT-EXTRAKTION
# ============================
def fetch_and_extract_text(url: str, timeout: int = DEFAULT_TIMEOUT) -> Tuple[str, Dict[str, str]]:
    headers = {"User-Agent": "SourceTD-MVP/0.1"}
    r = requests.get(url, headers=headers, timeout=timeout)
    r.raise_for_status()

    soup = BeautifulSoup(r.text, "lxml")
    title = (soup.title.get_text(strip=True) if soup.title else "").strip()

    for tag in soup(["script", "style", "noscript", "header", "footer", "nav", "aside", "form"]):
        tag.decompose()

    article = soup.find("article")
    node = article if article else soup.body if soup.body else soup

    text = node.get_text(separator="\n", strip=True)
    text = re.sub(r"\n{3,}", "\n\n", text).strip()

    return text, {"title": title, "status_code": str(r.status_code)}


# ============================
# SCORING (MVP)
# ============================
@dataclass
class ModuleResult:
    score: int
    reason: str


def clamp(x: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, x))


def logistic(x: float) -> float:
    return 1 / (1 + math.exp(-x))


def count_patterns(text: str, patterns) -> int:
    return sum(len(re.findall(p, text, flags=re.IGNORECASE)) for p in patterns)


EMOTIONAL_PATTERNS = [
    r"\bskandal\b", r"\bschock\b", r"\bkatastrophe\b", r"\bundlaublich\b", r"\bdramatisch\b",
    r"\bempör(ung|t)\b", r"\blüge(n)?\b", r"\bfake\b",
    r"\bimmer\b", r"\bnie\b", r"\balle\b", r"\bniemand\b"
]

SOURCE_PATTERNS = [
    r"https?://\S+",
    r"\bquelle(n)?\b", r"\bstudie(n)?\b", r"\bericht\b", r"\blaut\b",
    r"\bnach angaben\b", r"\bzitat\b", r"\berklärte\b", r"\bso heißt es\b"
]

PERSPECTIVE_PATTERNS = [
    r"\bjedoch\b", r"\ballerdings\b", r"\bhingegen\b", r"\bandererseits\b", r"\bzugleich\b",
    r"\bkritiker\b", r"\bbefürworter\b", r"\bgegner\b", r"\bexperten\b"
]

CONTEXT_PATTERNS = [
    r"\bseit\b", r"\bim jahr\b", r"\b(19|20)\d{2}\b", r"\bheute\b", r"\bgestern\b", r"\bmorgen\b",
    r"\bdefinition\b", r"\bhintergrund\b", r"\bkontext\b", r"\beinordnung\b"
]


def analyze_text(text: str) -> Dict[str, ModuleResult]:
    raw = text.strip()
    if len(raw) < 200:
        return {
            "sources": ModuleResult(15, "Sehr wenig Text: Quellenlage kann kaum eingeschätzt werden."),
            "evidence": ModuleResult(15, "Sehr wenig Text: Belegstruktur kann kaum eingeschätzt werden."),
            "language": ModuleResult(30, "Sehr wenig Text: Sprachmuster nur grob erkennbar."),
            "perspectives": ModuleResult(20, "Sehr wenig Text: Perspektivenvielfalt kann kaum eingeschätzt werden."),
            "context": ModuleResult(20, "Sehr wenig Text: Kontextvollständigkeit ist unklar."),
        }

    url_count = len(re.findall(r"https?://\S+", raw))
    citation_markers = count_patterns(raw, SOURCE_PATTERNS[1:])
    quote_count = raw.count("„") + raw.count("“") + raw.count('"')

    emotional_markers = count_patterns(raw, EMOTIONAL_PATTERNS)
    perspective_markers = count_patterns(raw, PERSPECTIVE_PATTERNS)
    context_markers = count_patterns(raw, CONTEXT_PATTERNS)

    n_words = len(re.findall(r"\w+", raw))
    length_factor = clamp((n_words - 200) / 1200, 0.0, 1.0)

    # Quellenlage (25%)
    sources_signal = (0.55 * logistic((url_count - 1) / 1.5) + 0.45 * logistic((citation_markers - 3) / 3.0))
    sources_score = int(round(clamp(20 + 80 * sources_signal * (0.6 + 0.4 * length_factor), 0, 100)))
    sources_reason = (
        "Es sind nur wenige identifizierbare Quellen-/Verweisindikatoren sichtbar."
        if sources_score < 40 else
        "Es gibt einige Quellen-/Verweisindikatoren, jedoch nicht durchgängig stark."
        if sources_score < 70 else
        "Mehrere Quellen-/Verweisindikatoren deuten auf eine grundsätzlich nachvollziehbare Quellenlage hin."
    )

    # Belegstruktur (25%)
    evidence_signal = (0.40 * logistic((citation_markers - 4) / 3.0) + 0.35 * logistic((quote_count - 2) / 5.0) + 0.25 * length_factor)
    evidence_score = int(round(clamp(15 + 85 * evidence_signal, 0, 100)))
    evidence_reason = (
        "Viele Aussagen wirken ohne erkennbare Belege."
        if evidence_score < 40 else
        "Teils erkennbare Belege/Zitate, aber nicht konsequent über den gesamten Text."
        if evidence_score < 70 else
        "Mehrere Belegindikatoren sprechen für eine solide Belegstruktur."
    )

    # Sprache & Tonalität (20%)
    emo_rate = emotional_markers / max(1, n_words / 250)
    language_penalty = clamp(emo_rate / 6.0, 0.0, 1.0)
    language_score = int(round(clamp(85 - 60 * language_penalty, 0, 100)))
    language_reason = (
        "Der Text nutzt überdurchschnittlich viele emotionalisierende oder polarisierende Formulierungen."
        if language_score < 50 else
        "Die Sprache ist teils emotional gefärbt, insgesamt aber noch moderat."
        if language_score < 75 else
        "Die Sprache wirkt überwiegend sachlich und wenig emotionalisierend."
    )

    # Perspektivenvielfalt (15%)
    perspectives_signal = (0.65 * logistic((perspective_markers - 3) / 3.0) + 0.35 * logistic((quote_count - 1) / 6.0))
    perspectives_score = int(round(clamp(10 + 90 * perspectives_signal, 0, 100)))
    perspectives_reason = (
        "Nur wenige Indikatoren für Gegenpositionen oder alternative Sichtweisen erkennbar."
        if perspectives_score < 40 else
        "Einige Hinweise auf unterschiedliche Perspektiven, aber eher begrenzt."
        if perspectives_score < 70 else
        "Mehrere Indikatoren deuten darauf hin, dass unterschiedliche Perspektiven berücksichtigt werden."
    )

    # Kontext & Vollständigkeit (15%)
    context_signal = (0.60 * logistic((context_markers - 4) / 4.0) + 0.40 * length_factor)
    context_score = int(round(clamp(10 + 90 * context_signal, 0, 100)))
    context_reason = (
        "Wenige Kontextindikatoren sichtbar – Einordnung erschwert."
        if context_score < 40 else
        "Teilweise Kontext/Hintergrund, aber nicht durchgängig umfassend."
        if context_score < 70 else
        "Mehrere Kontextindikatoren sprechen für eine gute Einordnung und Hintergrunddarstellung."
    )

    return {
        "sources": ModuleResult(sources_score, sources_reason),
        "evidence": ModuleResult(evidence_score, evidence_reason),
        "language": ModuleResult(language_score, language_reason),
        "perspectives": ModuleResult(perspectives_score, perspectives_reason),
        "context": ModuleResult(context_score, context_reason),
    }


def total_score(mods: Dict[str, ModuleResult]) -> int:
    weights = {"sources": 0.25, "evidence": 0.25, "language": 0.20, "perspectives": 0.15, "context": 0.15}
    return int(round(sum(mods[k].score * w for w in [0.25, 0.25, 0.20, 0.15, 0.15] for k in ["sources", "evidence", "language", "perspectives", "context"])))


# Korrektur: sinnvoller total_score (statt obiger verschachtelter Variante)
def total_score(mods: Dict[str, ModuleResult]) -> int:
    weights = {"sources": 0.25, "evidence": 0.25, "language": 0.20, "perspectives": 0.15, "context": 0.15}
    return int(round(sum(mods[k].score * weights[k] for k in weights)))


def short_summary(tscore: int, mods: Dict[str, ModuleResult]) -> str:
    low = [k for k, v in mods.items() if v.score < 45]
    if tscore >= 75 and not low:
        return "Der Inhalt wirkt insgesamt gut einordnungsfähig: nachvollziehbare Struktur, überwiegend sachlich, mit brauchbaren Kontext- und Belegindikatoren."
    if tscore >= 60:
        return "Der Inhalt ist grundsätzlich einordnungsfähig, weist jedoch Schwächen in einzelnen Modulen auf. Prüfe insbesondere die niedriger bewerteten Bereiche."
    return "Der Inhalt ist nur eingeschränkt einordnungsfähig: mehrere Indikatoren deuten auf Lücken bei Belegen, Kontext oder Perspektiven hin."


# ============================
# Zusätzlicher Mehrwert: TL;DR + Verbesserungsvorschläge
# ============================
def make_tldr(text: str, tscore: int, mods: Dict[str, ModuleResult]) -> Tuple[str, str]:
    """Grobe TL;DR-Zusammenfassung + Einordnungs-Kommentar."""
    raw = re.sub(r"\s+", " ", text.strip())
    # Sätze grob trennen
    sentences = re.split(r"([.!?])\s+", raw)
    combined = []
    current = ""
    for part in sentences:
        current += part
        if part in [".", "!", "?"]:
            combined.append(current.strip())
            current = ""
        if len(combined) >= 3:
            break
    if not combined and raw:
        tldr = raw[:280] + ("…" if len(raw) > 280 else "")
    else:
        tldr = " ".join(combined)
    comment = short_summary(tscore, mods)
    return tldr, comment


def find_first_snippet(text: str, pattern_list: List[str], window: int = 120) -> Optional[str]:
    for p in pattern_list:
        m = re.search(p, text, flags=re.IGNORECASE)
        if m:
            start = max(0, m.start() - window // 2)
            end = min(len(text), m.end() + window // 2)
            snippet = text[start:end].strip()
            snippet = re.sub(r"\s+", " ", snippet)
            return f"…{snippet}…"
    return None


def generate_suggestions(text: str, mods: Dict[str, ModuleResult]) -> List[str]:
    """Heuristische, konkrete Vorschläge basierend auf Scores & Mustern."""
    suggestions: List[str] = []
    raw = text.strip()

    url_count = len(re.findall(r"https?://\S+", raw))
    citation_markers = count_patterns(raw, SOURCE_PATTERNS[1:])
    emotional_markers = count_patterns(raw, EMOTIONAL_PATTERNS)
    perspective_markers = count_patterns(raw, PERSPECTIVE_PATTERNS)
    context_markers = count_patterns(raw, CONTEXT_PATTERNS)

    # Quellenlage schwach
    if mods["sources"].score < 55:
        msg = "An mehreren Stellen werden Aussagen ohne klare Quellenangabe getroffen. Ergänze Links zu Studien, Institutionen oder Primärdokumenten."
        suggestions.append(msg)
        if url_count == 0 and citation_markers == 0:
            suggestions[-1] += " Aktuell konnten kaum Verweiswörter oder Links gefunden werden."

    # Emotionale Sprache
    if mods["language"].score < 70 and emotional_markers > 0:
        snippet = find_first_snippet(raw, EMOTIONAL_PATTERNS)
        base = "Die Sprache wirkt stellenweise stark emotionalisiert (z. B. Wörter wie „Skandal“, „Katastrophe“, „Lüge“). Formuliere an diesen Stellen sachlicher."
        if snippet:
            base += f" Beispielstelle: {snippet}"
        suggestions.append(base)

    # Perspektivenvielfalt
    if mods["perspectives"].score < 60:
        suggestions.append(
            "Es sind nur wenige Hinweise auf alternative Sichtweisen oder Gegenargumente erkennbar. Ergänze z. B. eine Expertenmeinung, eine Gegenposition oder Kritik am beschriebenen Standpunkt."
        )

    # Kontext
    if mods["context"].score < 60:
        suggestions.append(
            "Der zeitliche oder sachliche Kontext könnte klarer sein. Ergänze z. B. seit wann etwas gilt, wichtige historische Ereignisse oder Definitionen zentraler Begriffe."
        )

    # Belege
    if mods["evidence"].score < 60 and citation_markers < 5:
        suggestions.append(
            "Mehr nachvollziehbare Belege würden die Einordnung erleichtern. Verweise explizit auf Studien, Berichte oder Datensätze, statt nur allgemein zu behaupten."
        )

    if not suggestions:
        suggestions.append("Der Text ist aus Sicht der Heuristik bereits relativ gut strukturiert und eingeordnet. Kleinere Verbesserungen sind je nach Zielgruppe dennoch möglich.")
    return suggestions


# ============================
# Session cache (URL -> extraction)
# ============================
def get_cache() -> Dict[str, dict]:
    return st.session_state.setdefault("cache", {})


def cache_get(key: str) -> Optional[dict]:
    cache = get_cache()
    item = cache.get(key)
    if not item:
        return None
    if time.time() - item["ts"] > CACHE_TTL_SECONDS:
        del cache[key]
        return None
    return item["value"]


def cache_set(key: str, value: dict) -> None:
    get_cache()[key] = {"ts": time.time(), "value": value}


# ============================
# Redeem Codes (Basic / Pro)
# ============================
def get_basic_codes() -> set:
    # In Streamlit Cloud: BASIC_CODES = ["BASIC-001", "BASIC-TEST"]
    try:
        codes = st.secrets.get("BASIC_CODES", [])
        return set(str(c).strip() for c in codes)
    except Exception:
        return set()


def get_pro_codes() -> set:
    # In Streamlit Cloud: PRO_CODES = ["PRO-001", "PRO-TEST"]
    try:
        codes = st.secrets.get("PRO_CODES", [])
        return set(str(c).strip() for c in codes)
    except Exception:
        return set()


def redeem_basic_ui(user: dict):
    st.markdown("#### Basic-Tarif aktivieren")
    code = st.text_input("Basic-Redeem-Code", key="redeem_basic_code")
    if st.button("Basic-Code einlösen"):
        codes = get_basic_codes()
        if not codes:
            st.error("Keine Basic-Redeem-Codes konfiguriert (BASIC_CODES in Secrets).")
            return
        if code.strip() in codes:
            set_tier(user["id"], TIER_BASIC)
            st.session_state["user"]["tier"] = TIER_BASIC
            st.success("Basic-Tarif wurde aktiviert.")
            st.rerun()
        else:
            st.error("Ungültiger Basic-Code.")


def redeem_pro_ui(user: dict):
    st.markdown("#### Pro-Tarif aktivieren")
    code = st.text_input("Pro-Redeem-Code", key="redeem_pro_code")
    if st.button("Pro-Code einlösen"):
        codes = get_pro_codes()
        if not codes:
            st.error("Keine Pro-Redeem-Codes konfiguriert (PRO_CODES in Secrets).")
            return
        if code.strip() in codes:
            set_tier(user["id"], TIER_PRO)
            st.session_state["user"]["tier"] = TIER_PRO
            st.success("Pro-Tarif wurde aktiviert.")
            st.rerun()
        else:
            st.error("Ungültiger Pro-Code.")


# ============================
# Admin-Helfer
# ============================
def get_admin_emails() -> set:
    """Admin-E-Mails aus Secrets (ADMIN_EMAILS = ["du@example.com"])."""
    try:
        emails = st.secrets.get("ADMIN_EMAILS", [])
        return set(str(e).lower().strip() for e in emails)
    except Exception:
        return set()


def is_admin(user: Optional[dict]) -> bool:
    if not user:
        return False
    admins = get_admin_emails()
    return user["email"].lower() in admins


def fetch_feedback_overview(limit: int = 50) -> List[dict]:
    conn = db()
    cur = conn.execute(
        """
        SELECT f.id,
               f.created_at,
               u.email,
               f.helpful,
               f.tscore,
               f.source_url,
               f.source_mode,
               f.comment
        FROM feedback f
        LEFT JOIN users u ON f.user_id = u.id
        ORDER BY f.created_at DESC
        LIMIT ?
        """,
        (limit,),
    )
    rows = cur.fetchall()
    conn.close()

    result = []
    for r in rows:
        ts = time.strftime("%Y-%m-%d %H:%M", time.localtime(r[1]))
        result.append(
            {
                "ID": r[0],
                "Zeit": ts,
                "User": r[2] or "(unbekannt)",
                "Hilfreich": "Ja" if r[3] == 1 else "Nein",
                "Score": r[4],
                "URL": r[5] or "",
                "Modus": r[6] or "",
                "Kommentar": (r[7] or "")[:200],
            }
        )
    return result


def fetch_feedback_stats() -> dict:
    conn = db()
    cur = conn.execute("SELECT COUNT(*), SUM(helpful), AVG(tscore) FROM feedback")
    total, sum_helpful, avg_score = cur.fetchone()
    cur2 = conn.execute(
        "SELECT source_mode, COUNT(*) FROM feedback GROUP BY source_mode"
    )
    by_mode = cur2.fetchall()
    conn.close()

    total = total or 0
    sum_helpful = sum_helpful or 0
    avg_score = avg_score if avg_score is not None else None

    mode_stats = {m or "(unbekannt)": c for (m, c) in by_mode}
    return {
        "total": total,
        "helpful": sum_helpful,
        "avg_score": avg_score,
        "by_mode": mode_stats,
    }


def fetch_usage_stats(limit_days: int = 14) -> List[dict]:
    conn = db()
    cur = conn.execute(
        """
        SELECT day_key, SUM(count)
        FROM usage_daily
        GROUP BY day_key
        ORDER BY day_key DESC
        LIMIT ?
        """,
        (limit_days,),
    )
    rows = cur.fetchall()
    conn.close()
    return [{"Tag": r[0], "Analysen gesamt": r[1]} for r in rows]


# ============================
# AUTH UI
# ============================
def require_login():
    if "user" not in st.session_state:
        st.session_state["user"] = None


def login_box():
    st.markdown("### Login")
    email = st.text_input("E-Mail", key="login_email")
    pw = st.text_input("Passwort", type="password", key="login_pw")
    if st.button("Anmelden", type="primary"):
        ok, user, msg = verify_login(email, pw)
        if ok:
            st.session_state["user"] = {
                "id": user["id"],
                "email": user["email"],
                "tier": user["tier"],
            }
            st.success("Erfolgreich angemeldet.")
            st.rerun()
        else:
            st.error(msg)


def register_box():
    st.markdown("### Registrieren")
    email = st.text_input("E-Mail", key="reg_email")
    pw = st.text_input("Passwort (min. 8 Zeichen)", type="password", key="reg_pw")
    pw2 = st.text_input("Passwort wiederholen", type="password", key="reg_pw2")
    if st.button("Account erstellen"):
        if pw != pw2:
            st.error("Passwörter stimmen nicht überein.")
        else:
            ok, msg = create_user(email, pw)
            (st.success if ok else st.error)(msg)


def logout_button():
    if st.button("Abmelden"):
        st.session_state["user"] = None
        st.rerun()


def tier_badge(tier: str) -> str:
    if tier == TIER_PRO:
        return "Pro"
    if tier == TIER_BASIC:
        return "Basic"
    return "Free"


def can_analyze(user: dict, needed: int = 1) -> Tuple[bool, str, int, int]:
    day = day_key_local()
    used = get_usage_count(user["id"], day)
    limit = get_daily_limit(user["tier"])
    if used + needed > limit:
        return (
            False,
            f"Tageslimit erreicht ({used}/{limit}). Für diese Aktion wären {needed} weitere Analysen nötig.",
            used,
            limit,
        )
    return True, "", used, limit


# ============================
# INIT & UI
# ============================
init_db()
st.set_page_config(page_title=APP_NAME, layout="centered")

st.title("SourceTD")
st.subheader("Transparenz für digitale Informationen.")
st.caption("Hinweis: SourceTD bewertet keine Wahrheit. Die Analyse dient der Einordnung anhand nachvollziehbarer Kriterien.")

require_login()

tab_analyze, tab_compare, tab_method, tab_account, tab_admin, tab_imprint = st.tabs(
    ["Analyse", "Vergleich", "Methodik", "Account", "Admin", "Impressum"]
)

# --- Account-Tab ---
with tab_account:
    user = st.session_state.get("user")

    if not user:
        col1, col2 = st.columns(2)
        with col1:
            login_box()
        with col2:
            register_box()
        st.info("Für die Analyse ist ein Login erforderlich, damit Free/Basic/Pro-Limits fair umgesetzt werden können.")
    else:
        st.markdown(f"**Angemeldet:** {user['email']}")
        st.markdown(f"**Tarif:** {tier_badge(user['tier'])}")
        day = day_key_local()
        used = get_usage_count(user["id"], day)
        limit = get_daily_limit(user["tier"])
        st.markdown(f"**Nutzung heute:** {used} / {limit}")
        logout_button()

        st.divider()
        st.markdown("### Tarife & Upgrades")

        if user["tier"] == TIER_FREE:
            st.write("Du nutzt aktuell den Free-Tarif. Du kannst auf Basic oder Pro upgraden (Redeem-Code).")
            redeem_basic_ui(user)
            st.divider()
            redeem_pro_ui(user)
        elif user["tier"] == TIER_BASIC:
            st.success("Du bist aktuell Basic-Nutzer.")
            st.write("Wenn du möchtest, kannst du auf Pro upgraden (Redeem-Code).")
            redeem_pro_ui(user)
        else:
            st.success("Du bist aktuell Pro-Nutzer.")

# --- Methodik-Tab ---
with tab_method:
    st.markdown("## Methodik (MVP)")
    st.write(
        "SourceTD liefert einen **Transparenz-Score (0–100)**. "
        "Er misst nicht, ob etwas „wahr“ ist, sondern wie **nachvollziehbar** ein Inhalt anhand erkennbarer Indikatoren wirkt."
    )
    st.markdown("### Module & Gewichte")
    st.markdown(
        "- **Quellenlage (25%)**: Links, Quellenhinweise, Verweisstruktur\n"
        "- **Belegstruktur (25%)**: Zitate/Studien-/Datenindikatoren, Konsistenz\n"
        "- **Sprache & Tonalität (20%)**: Emotionalisierung/Polarisierung (indikativ)\n"
        "- **Perspektivenvielfalt (15%)**: Hinweise auf Gegenpositionen/Alternativen (indikativ)\n"
        "- **Kontext & Vollständigkeit (15%)**: Zeit-/Hintergrund-/Einordnungsmarker (indikativ)\n"
    )
    st.markdown("### Grenzen")
    st.markdown(
        "- Heuristisches MVP: Indikatoren können irren.\n"
        "- Keine journalistische Prüfung, keine Rechts- oder Faktenberatung.\n"
        "- Paywalls/Layouts können Extraktion erschweren.\n"
    )

# --- Analyse-Tab ---
with tab_analyze:
    user = st.session_state.get("user")
    if not user:
        st.warning("Bitte zuerst im Tab „Account“ registrieren/anmelden.")
        st.stop()

    ok, msg, used, limit = can_analyze(user)
    st.markdown(f"**Tarif:** {tier_badge(user['tier'])}  |  **Heute genutzt:** {used}/{limit}")

    url: str = ""
    mode = st.radio("Eingabe", ["URL analysieren", "Text einfügen"], horizontal=True)

    article_text: Optional[str] = None
    meta: Dict[str, str] = {}
    run_clicked = False

    if mode == "URL analysieren":
        url = st.text_input("Artikel-URL", placeholder="https://…")
        run_clicked = st.button("Analysieren", type="primary", disabled=not url)
        if run_clicked and url:
            if not ok:
                st.error(msg)
            else:
                increment_usage(user["id"], day_key_local())
                key = "url:" + stable_key(url.strip())
                cached = cache_get(key)
                if cached:
                    article_text, meta = cached["text"], cached["meta"]
                    st.info("Extraktion aus Cache (Session, zeitlich begrenzt).")
                else:
                    try:
                        with st.spinner("Artikel wird geladen und analysiert…"):
                            article_text, meta = fetch_and_extract_text(url.strip())
                        cache_set(key, {"text": article_text, "meta": meta})
                    except Exception as e:
                        st.error(f"Fehler beim Laden/Extrahieren: {e}")
    else:
        article_text = st.text_area("Artikeltext", height=220, placeholder="Text hier einfügen…")
        run_clicked = st.button("Analysieren", type="primary", disabled=not article_text)
        if run_clicked and article_text:
            if not ok:
                st.error(msg)
            else:
                increment_usage(user["id"], day_key_local())
                meta = {"title": "Eingefügter Text", "status_code": "-"}

    if article_text:
        st.divider()
        if meta.get("title"):
            st.markdown(f"**Titel:** {meta['title']}")

        mods = analyze_text(article_text)
        tscore = total_score(mods)

        # TL;DR + Kommentar
        tldr, comment = make_tldr(article_text, tscore, mods)
        st.markdown("### TL;DR")
        st.write(tldr)

        st.metric("SourceTD-Transparenz-Score", f"{tscore} / 100")
        st.write(comment)

        # Konkrete Verbesserungsvorschläge
        st.divider()
        st.markdown("### Konkrete Verbesserungsvorschläge")
        suggestions = generate_suggestions(article_text, mods)
        for s in suggestions:
            st.markdown(f"- {s}")

        # Feedback-Block
        st.divider()
        st.markdown("### Feedback zur Einordnung")
        st.write("War diese Einordnung für dich hilfreich?")

        helpful_choice = st.radio(
            "Bitte wähle eine Option:",
            ("Ja", "Eher nicht"),
            label_visibility="collapsed",
            key="feedback_helpful_choice",
        )
        comment_fb = st.text_area(
            "Optionaler Kommentar (z. B. was dir gefehlt hat):",
            key="feedback_comment",
            height=80,
        )

        if st.button("Feedback senden"):
            source_url = url.strip() if (mode == "URL analysieren" and url) else None
            source_mode = mode  # "URL analysieren" oder "Text einfügen"
            helpful_flag = True if helpful_choice == "Ja" else False

            try:
                save_feedback(
                    user_id=user["id"],
                    helpful=helpful_flag,
                    comment=comment_fb,
                    tscore=tscore,
                    source_url=source_url,
                    source_mode=source_mode,
                )
                st.success("Danke für dein Feedback – es hilft, SourceTD weiter zu verbessern.")
            except Exception as e:
                st.error(f"Feedback konnte nicht gespeichert werden: {e}")

        st.divider()
        st.markdown("## Modulübersicht")

        def module_block(label: str, key: str):
            r = mods[key]
            with st.expander(f"{label}: {r.score}/100", expanded=False):
                st.write(r.reason)

        module_block("Quellenlage", "sources")
        module_block("Belegstruktur", "evidence")
        module_block("Sprache & Tonalität", "language")
        module_block("Perspektivenvielfalt", "perspectives")
        module_block("Kontext & Vollständigkeit", "context")


# --- Vergleichs-Tab ---
with tab_compare:
    user = st.session_state.get("user")
    if not user:
        st.warning("Bitte zuerst im Tab „Account“ registrieren/anmelden.")
        st.stop()

    st.markdown("## Vergleich mehrerer Quellen")
    st.write("Gib bis zu drei Artikel-URLs ein, um Quellenlage, Sprache und Kontext zu vergleichen.")

    col1, col2, col3 = st.columns(3)
    with col1:
        url1 = st.text_input("URL 1", key="cmp_url1", placeholder="https://…")
    with col2:
        url2 = st.text_input("URL 2", key="cmp_url2", placeholder="https://…")
    with col3:
        url3 = st.text_input("URL 3", key="cmp_url3", placeholder="https://…")

    urls = [u.strip() for u in [url1, url2, url3] if u.strip()]
    needed = len(urls)

    if st.button("Vergleich starten", type="primary", disabled=needed == 0):
        if needed == 0:
            st.error("Bitte mindestens eine URL eingeben.")
        else:
            ok, msg, used, limit = can_analyze(user, needed=needed)
            st.markdown(f"**Tarif:** {tier_badge(user['tier'])}  |  **Heute genutzt:** {used}/{limit}")
            if not ok:
                st.error(msg)
            else:
                increment_usage(user["id"], day_key_local(), amount=needed)

                results = []
                for u in urls:
                    key = "url:" + stable_key(u)
                    cached = cache_get(key)
                    if cached:
                        text_u, meta_u = cached["text"], cached["meta"]
                    else:
                        try:
                            with st.spinner(f"Lade und analysiere {u}…"):
                                text_u, meta_u = fetch_and_extract_text(u)
                            cache_set(key, {"text": text_u, "meta": meta_u})
                        except Exception as e:
                            st.error(f"Fehler bei {u}: {e}")
                            continue

                    mods_u = analyze_text(text_u)
                    tscore_u = total_score(mods_u)
                    results.append((u, meta_u.get("title", ""), tscore_u, mods_u))

                if not results:
                    st.warning("Es konnten keine gültigen Analysen durchgeführt werden.")
                else:
                    st.divider()
                    st.markdown("### Gesamtvergleich")

                    table_data = []
                    for (u, title, tscore_u, mods_u) in results:
                        row = {
                            "URL": u,
                            "Titel": title[:80] + ("…" if len(title) > 80 else ""),
                            "Score gesamt": tscore_u,
                            "Quellenlage": mods_u["sources"].score,
                            "Belegstruktur": mods_u["evidence"].score,
                            "Sprache": mods_u["language"].score,
                            "Perspektiven": mods_u["perspectives"].score,
                            "Kontext": mods_u["context"].score,
                        }
                        table_data.append(row)
                    st.dataframe(table_data)

                    st.markdown("### Einordnung")
                    best = max(results, key=lambda r: r[2])
                    best_url, best_title, best_score, best_mods = best
                    st.write(
                        f"Unter den eingegebenen Quellen wirkt die Seite mit der URL "
                        f"`{best_url}` insgesamt am einordnungsfähigsten (Score {best_score}/100). "
                        f"Prüfe dennoch im Detail, ob Quellen, Kontext und Sprache zu deinem Bedarf passen."
                    )


# --- Admin-Tab ---
with tab_admin:
    user = st.session_state.get("user")
    if not user:
        st.warning("Bitte zuerst im Tab „Account“ anmelden.")
        st.stop()

    if not is_admin(user):
        st.error("Kein Admin-Zugriff. Hinterlege deine E-Mail-Adresse in den ADMIN_EMAILS-Secrets, um den Admin-Bereich zu nutzen.")
        st.info("Beispiel in Streamlit Secrets:\n\nADMIN_EMAILS = [\"deine.mail@example.com\"]")
        st.stop()

    st.markdown("## Admin-Bereich")
    st.caption("Nur sichtbar für Admin-E-Mails (ADMIN_EMAILS in Secrets).")

    # Feedback-Statistiken
    st.subheader("Feedback-Statistiken")
    stats = fetch_feedback_stats()
    col_a, col_b, col_c = st.columns(3)
    with col_a:
        st.metric("Feedback gesamt", stats["total"])
    with col_b:
        helpful_rate = (stats["helpful"] / stats["total"] * 100) if stats["total"] > 0 else 0
        st.metric("Hilfreich-Anteil", f"{helpful_rate:.1f} %")
    with col_c:
        avg_sc = stats["avg_score"] if stats["avg_score"] is not None else 0
        st.metric("Ø Score (Feedback)", f"{avg_sc:.1f}")

    st.markdown("**Feedback nach Modus**")
    st.write(stats["by_mode"])

    st.divider()
    st.subheader("Letzte Feedback-Einträge")
    fb_rows = fetch_feedback_overview(limit=50)
    if fb_rows:
        st.dataframe(fb_rows)
    else:
        st.info("Noch keine Feedback-Einträge vorhanden.")

    st.divider()
    st.subheader("Nutzung nach Tagen (global)")
    usage_rows = fetch_usage_stats(limit_days=14)
    if usage_rows:
        st.dataframe(usage_rows)
    else:
        st.info("Noch keine Nutzungsdaten vorhanden.")


# --- Impressum-Tab ---
with tab_imprint:
    st.markdown("## Impressum")
    st.write(
        "Hinweis: Die folgenden Angaben sind ein Platzhalter. "
        "Bitte ersetze sie durch deine tatsächlichen Impressumsdaten entsprechend der rechtlichen Anforderungen "
        "(z. B. nach § 5 TMG in Deutschland)."
    )
    st.markdown("---")

    st.markdown("### Angaben gemäß § 5 TMG (Beispiel)")
    st.markdown(
        """
**Betreiber der Website / Verantwortlich für den Inhalt**

Tobias Demmler  
Klosterstraße 8  
13581 Berlin 
Deutschlandd  

Telefon: +49 (0)1702109497  
E-Mail: Tobias.demmler@outlook.de  

---

### Verantwortlich für den Inhalt nach § 55 Abs. 2 RStV

Tobias Demmler  
Klosterstraße 8  
13581 Berlin 
Deutschland  

---

### Haftungsausschluss

**Haftung für Inhalte**  
Die Inhalte dieser Anwendung wurden mit größter Sorgfalt erstellt. Für die Richtigkeit, Vollständigkeit und Aktualität der Inhalte kann jedoch keine Gewähr übernommen werden.  
SourceTD bewertet keine Wahrheit, sondern analysiert Inhalte anhand heuristischer Transparenz-Indikatoren.

**Haftung für Links**  
Diese Anwendung kann Links zu externen Websites enthalten, auf deren Inhalte kein Einfluss besteht. Für diese fremden Inhalte wird keine Gewähr übernommen; verantwortlich ist jeweils der Anbieter oder Betreiber der verlinkten Seiten.

---

### Urheberrecht

Die durch den Betreiber erstellten Inhalte und Werke in dieser Anwendung unterliegen dem deutschen Urheberrecht. Beiträge Dritter sind als solche gekennzeichnet.  
Die Vervielfältigung, Bearbeitung, Verbreitung und jede Art der Verwertung außerhalb der Grenzen des Urheberrechtes bedürfen der schriftlichen Zustimmung des jeweiligen Autors bzw. Erstellers.

"""
    )
    st.info("Bitte passe Namen, Adresse und Kontaktdaten im Impressum an deine tatsächlichen Angaben an.")
