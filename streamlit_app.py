import re
import math
import time
import hashlib
from dataclasses import dataclass
from typing import Dict, Tuple, Optional

import requests
from bs4 import BeautifulSoup
import streamlit as st
import bcrypt
import psycopg2
from psycopg2 import IntegrityError
import stripe


# ============================
# CONFIG
# ============================
APP_NAME = "SourceTD (MVP)"

# Supabase / Postgres
DATABASE_URL = st.secrets["DATABASE_URL"]

# Stripe
stripe.api_key = st.secrets["STRIPE_SECRET_KEY"]
BASIC_PRICE_ID = st.secrets["STRIPE_BASIC_PRICE_ID"]
PRO_PRICE_ID = st.secrets["STRIPE_PRO_PRICE_ID"]
APP_BASE_URL = st.secrets["APP_BASE_URL"]

# Tarif-Konstanten
TIER_FREE = "free"
TIER_BASIC = "basic"    # neuer bezahlter Tarif
TIER_PRO = "pro"

# Limits pro Tag je Tarif
DAILY_LIMITS: Dict[str, int] = {
    TIER_FREE: 5,        # z. B. 20 Analysen/Tag
    TIER_BASIC: 100,      # z. B. 100 Analysen/Tag
    TIER_PRO: 10_000,     # praktisch unbegrenzt
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


def debug_db_connection():
    try:
        with db_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT current_database(), current_user;")
                row = cur.fetchone()
        st.success(f"DB-Verbindung OK: DB={row[0]}, User={row[1]}")
    except Exception as e:
        st.error(f"DB-Verbindungsfehler: {e!r}")

# ============================
# DATABASE (Supabase Postgres)
# ============================
def db_conn():
    """
    Stellt die Verbindung zu Supabase Postgres her.
    Supabase erwartet SSL, daher ergänzen wir sslmode=require,
    falls es nicht bereits in der URL steht.
    """
    dsn = DATABASE_URL
    if "sslmode=" not in dsn:
        sep = "&" if "?" in dsn else "?"
        dsn = dsn + f"{sep}sslmode=require"
    return psycopg2.connect(dsn)


def get_user_by_email(email: str) -> Optional[dict]:
    email = email.lower().strip()
    with db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, email, pw_hash, tier, stripe_customer_id
                FROM public.users
                WHERE email = %s
                """,
                (email,),
            )
            row = cur.fetchone()
    if not row:
        return None
    return {
        "id": row[0],
        "email": row[1],
        "pw_hash": row[2],  # bytea -> memoryview/bytes
        "tier": row[3],
        "stripe_customer_id": row[4],
    }


def create_user(email: str, password: str) -> Tuple[bool, str]:
    email = email.lower().strip()
    if not re.match(r"^[^@]+@[^@]+\.[^@]+$", email):
        return False, "Bitte eine gültige E-Mail-Adresse eingeben."
    if len(password) < 8:
        return False, "Passwort muss mindestens 8 Zeichen lang sein."

    pw_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

    try:
        with db_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO public.users (email, pw_hash, tier)
                    VALUES (%s, %s, %s)
                    """,
                    (email, psycopg2.Binary(pw_hash), TIER_FREE),
                )
        return True, "Account erstellt. Du kannst dich jetzt anmelden."
    except IntegrityError:
        return False, "Diese E-Mail ist bereits registriert."
    except Exception as e:
        return False, f"Fehler beim Anlegen des Accounts: {e}"


def verify_login(email: str, password: str) -> Tuple[bool, Optional[dict], str]:
    user = get_user_by_email(email)
    if not user:
        return False, None, "Login fehlgeschlagen (E-Mail oder Passwort falsch)."

    stored = user["pw_hash"]
    if isinstance(stored, memoryview):
        stored_bytes = stored.tobytes()
    elif isinstance(stored, (bytes, bytearray)):
        stored_bytes = bytes(stored)
    elif isinstance(stored, str):
        stored_bytes = stored.encode("utf-8")
    else:
        return False, None, "Login nicht möglich: unerwartetes Passwortformat in der Datenbank."

    try:
        ok = bcrypt.checkpw(password.encode("utf-8"), stored_bytes)
    except Exception as e:
        return False, None, f"Fehler bei der Passwortprüfung: {e}"

    if not ok:
        return False, None, "Login fehlgeschlagen (E-Mail oder Passwort falsch)."

    return True, user, ""


def get_usage_count(user_id: int, day: str) -> int:
    with db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT count FROM public.usage_daily WHERE user_id = %s AND day_key = %s",
                (user_id, day),
            )
            row = cur.fetchone()
    return int(row[0]) if row else 0


def increment_usage(user_id: int, day: str) -> None:
    with db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO public.usage_daily (user_id, day_key, count)
                VALUES (%s, %s, 1)
                ON CONFLICT (user_id, day_key)
                DO UPDATE SET count = public.usage_daily.count + 1;
                """,
                (user_id, day),
            )


def set_tier(user_id: int, tier: str) -> None:
    with db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE public.users SET tier = %s WHERE id = %s",
                (tier, user_id),
            )


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
    citation_markers = count_patterns(raw, [
        r"\bquelle(n)?\b", r"\bstudie(n)?\b", r"\bericht\b", r"\blaut\b",
        r"\bnach angaben\b", r"\bzitat\b", r"\berklärte\b", r"\bso heißt es\b"
    ])
    quote_count = raw.count("„") + raw.count("“") + raw.count('"')

    emotional_markers = count_patterns(raw, [
        r"\bskandal\b", r"\bschock\b", r"\bkatastrophe\b", r"\bundlaublich\b", r"\bdramatisch\b",
        r"\bempör(ung|t)\b", r"\blüge(n)?\b", r"\bfake\b",
        r"\bimmer\b", r"\bnie\b", r"\balle\b", r"\bniemand\b"
    ])

    perspective_markers = count_patterns(raw, [
        r"\bjedoch\b", r"\ballerdings\b", r"\bhingegen\b", r"\bandererseits\b", r"\bzugleich\b",
        r"\bkritiker\b", r"\bbefürworter\b", r"\bgegner\b", r"\bexperten\b"
    ])

    context_markers = count_patterns(raw, [
        r"\bseit\b", r"\bim jahr\b", r"\b(19|20)\d{2}\b", r"\bheute\b", r"\bgestern\b", r"\bmorgen\b",
        r"\bdefinition\b", r"\bhintergrund\b", r"\bkontext\b", r"\beinordnung\b"
    ])

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
    return int(round(sum(mods[k].score * w for k, w in weights.items())))


def short_summary(tscore: int, mods: Dict[str, ModuleResult]) -> str:
    low = [k for k, v in mods.items() if v.score < 45]
    if tscore >= 75 and not low:
        return "Der Inhalt wirkt insgesamt gut einordnungsfähig: nachvollziehbare Struktur, überwiegend sachlich, mit brauchbaren Kontext- und Belegindikatoren."
    if tscore >= 60:
        return "Der Inhalt ist grundsätzlich einordnungsfähig, weist jedoch Schwächen in einzelnen Modulen auf. Prüfe insbesondere die niedriger bewerteten Bereiche."
    return "Der Inhalt ist nur eingeschränkt einordnungsfähig: mehrere Indikatoren deuten auf Lücken bei Belegen, Kontext oder Perspektiven hin."


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
# Stripe Checkout & Billing Portal
# ============================
def create_checkout_session(price_id: str, user_email: str, user_id: int, success_flag: str) -> str:
    """
    Erstellt eine Stripe-Checkout-Session für ein Subscription-Produkt.
    success_flag ist z. B. 'success_basic' oder 'success_pro'
    """
    session = stripe.checkout.Session.create(
        mode="subscription",
        line_items=[{"price": price_id, "quantity": 1}],
        success_url=f"{APP_BASE_URL}?checkout={success_flag}",
        cancel_url=f"{APP_BASE_URL}?checkout=cancel",
        customer_email=user_email,
        client_reference_id=str(user_id),
        allow_promotion_codes=True,
    )
    return session.url


def create_billing_portal(user_customer_id: str) -> str:
    portal = stripe.billing_portal.Session.create(
        customer=user_customer_id,
        return_url=APP_BASE_URL,
    )
    return portal.url


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
                "stripe_customer_id": user.get("stripe_customer_id"),
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


def can_analyze(user: dict) -> Tuple[bool, str, int, int]:
    day = day_key_local()
    used = get_usage_count(user["id"], day)
    limit = get_daily_limit(user["tier"])
    if used >= limit:
        return (
            False,
            f"Tageslimit erreicht ({used}/{limit}). Ein Upgrade auf einen höheren Tarif ermöglicht mehr Analysen.",
            used,
            limit,
        )
    return True, "", used, limit


# ============================
# UI
# ============================
st.set_page_config(page_title=APP_NAME, layout="centered")

st.title("SourceTD")
st.subheader("Transparenz für digitale Informationen.")
st.caption("Hinweis: SourceTD bewertet keine Wahrheit. Die Analyse dient der Einordnung anhand nachvollziehbarer Kriterien.")

require_login()

tab_analyze, tab_method, tab_account = st.tabs(["Analyse", "Methodik", "Account"])

# --- Account-Tab ---
with tab_account:
    user = st.session_state.get("user")

    # Query-Parameter (Checkout Rückkehr)
    params = st.experimental_get_query_params()
    checkout_status = params.get("checkout", [None])[0]

    if checkout_status in ("success_basic", "success_pro") and user:
        st.success("Zahlung bei Stripe erfolgreich. Dein Tarif wird aktualisiert.")
        fresh = get_user_by_email(user["email"])
        if fresh:
            st.session_state["user"]["tier"] = fresh["tier"]
            st.session_state["user"]["stripe_customer_id"] = fresh.get("stripe_customer_id")
            user = st.session_state["user"]
    elif checkout_status == "cancel":
        st.info("Checkout bei Stripe wurde abgebrochen.")

    if not user:
        col1, col2 = st.columns(2)
        with col1:
            login_box()
        with col2:
            register_box()
        st.info("Für die Analyse ist ein Login erforderlich (MVP), damit Free/Basic/Pro-Limits fair umgesetzt werden können.")
    else:
        st.markdown(f"**Angemeldet:** {user['email']}")
        st.markdown(f"**Tarif:** {tier_badge(user['tier'])}")
        day = day_key_local()
        used = get_usage_count(user["id"], day)
        limit = get_daily_limit(user["tier"])
        st.markdown(f"**Nutzung heute:** {used} / {limit}")
        logout_button()

        st.divider()
        st.markdown("### Abo / Tarife")

        if user["tier"] == TIER_FREE:
            st.write("Du nutzt aktuell den Free-Tarif. Du kannst auf Basic oder Pro upgraden, um höhere Limits zu erhalten.")
            col_basic, col_pro = st.columns(2)
            with col_basic:
                if st.button("Basic abonnieren", type="secondary"):
                    checkout_url = create_checkout_session(
                        price_id=BASIC_PRICE_ID,
                        user_email=user["email"],
                        user_id=user["id"],
                        success_flag="success_basic",
                    )
                    st.link_button("Weiter zu Stripe Checkout (Basic)", checkout_url)
            with col_pro:
                if st.button("Pro abonnieren", type="primary"):
                    checkout_url = create_checkout_session(
                        price_id=PRO_PRICE_ID,
                        user_email=user["email"],
                        user_id=user["id"],
                        success_flag="success_pro",
                    )
                    st.link_button("Weiter zu Stripe Checkout (Pro)", checkout_url)
        elif user["tier"] == TIER_BASIC:
            st.success("Du bist aktuell Basic-Nutzer.")
            col_upgrade, col_portal = st.columns(2)
            with col_upgrade:
                if st.button("Auf Pro upgraden", type="primary"):
                    checkout_url = create_checkout_session(
                        price_id=PRO_PRICE_ID,
                        user_email=user["email"],
                        user_id=user["id"],
                        success_flag="success_pro",
                    )
                    st.link_button("Weiter zu Stripe Checkout (Pro)", checkout_url)
            with col_portal:
                if user.get("stripe_customer_id"):
                    if st.button("Abo verwalten (Billing Portal)"):
                        portal_url = create_billing_portal(user["stripe_customer_id"])
                        st.link_button("Zum Stripe Billing Portal", portal_url)
                else:
                    st.info("Stripe-Konto ist noch nicht vollständig verknüpft (stripe_customer_id fehlt).")
        else:  # Pro
            st.success("Du bist aktuell Pro-Nutzer.")
            if user.get("stripe_customer_id"):
                if st.button("Abo verwalten (Billing Portal)"):
                    portal_url = create_billing_portal(user["stripe_customer_id"])
                    st.link_button("Zum Stripe Billing Portal", portal_url)
            else:
                st.info("Stripe-Konto ist noch nicht vollständig verknüpft (stripe_customer_id fehlt).")

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

        st.metric("SourceTD-Transparenz-Score", f"{tscore} / 100")
        st.write(short_summary(tscore, mods))

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
