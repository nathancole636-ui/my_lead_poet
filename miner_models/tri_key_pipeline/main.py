import asyncio
import json
import os
import random
import re
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

import aiohttp

from validator_models.industry_taxonomy import INDUSTRY_TAXONOMY
from gateway.api.submit import check_description_sanity


VALID_EMPLOYEE_COUNTS = {
    "0-1", "2-10", "11-50", "51-200", "201-500",
    "501-1,000", "1,001-5,000", "5,001-10,000", "10,001+",
}

GENERIC_EMAIL_PREFIXES = {
    "info", "hello", "support", "contact", "sales", "admin", "office",
    "team", "service", "help", "careers", "hr", "billing", "privacy",
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _valid_http_url(u: str) -> bool:
    return bool(re.match(r"^https?://[^\s]+$", (u or "").strip(), re.I))


def _extract_emails(text: str) -> List[str]:
    if not text:
        return []
    # Basic RFC-ish pattern, excludes trailing punctuation.
    emails = re.findall(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", text, re.I)
    out = []
    for e in emails:
        e = e.strip().lower()
        if e not in out:
            out.append(e)
    return out


def _is_generic_email(email: str) -> bool:
    if not email or "@" not in email:
        return True
    local = email.split("@", 1)[0].lower()
    # Allow firstname.lastname, firstname, firstlast patterns etc.
    if local in GENERIC_EMAIL_PREFIXES:
        return True
    if any(local.startswith(p + "+") for p in GENERIC_EMAIL_PREFIXES):
        return True
    return False


def _best_subindustry(text: str) -> Tuple[Optional[str], Optional[str]]:
    """Pick a taxonomy-valid (industry, sub_industry) pair using lightweight matching.

    INDUSTRY_TAXONOMY is keyed by sub_industry, with a list of allowed industries.
    We score by token overlap between (sub_industry + definition) and text.
    """
    if not text:
        return None, None
    hay = re.sub(r"\s+", " ", text.lower())

    best = (0, None, None)
    for sub, meta in INDUSTRY_TAXONOMY.items():
        definition = (meta.get("definition") or "").lower()
        needles = f"{sub} {definition}".lower()

        # Token overlap score (fast + robust)
        tokens = [t for t in re.split(r"[^a-z0-9]+", needles) if len(t) >= 4]
        if not tokens:
            continue
        score = sum(1 for t in set(tokens) if t in hay)

        if score > best[0]:
            industries = meta.get("industries") or []
            industry = industries[0] if industries else None
            best = (score, industry, sub)

    if best[0] <= 0:
        return None, None
    return best[1], best[2]


def _validate_lead_minimum(lead: Dict) -> Tuple[bool, str]:
    """Strict local gate to avoid wasting daily rejection quota."""
    required = [
        "business", "full_name", "first", "last", "email", "role", "website",
        "industry", "sub_industry", "country", "city", "linkedin",
        "company_linkedin", "source_url", "description", "employee_count",
        "source_type",
    ]
    for k in required:
        if not (lead.get(k) or "").strip():
            return False, f"missing_{k}"

    if not _valid_http_url(lead.get("website")):
        return False, "invalid_website"

    if not _valid_http_url(lead.get("source_url")) and lead.get("source_url") != "proprietary_database":
        return False, "invalid_source_url"

    if "linkedin.com" in (lead.get("source_url") or "").lower():
        return False, "blocked_source_url_linkedin"

    if lead.get("employee_count") not in VALID_EMPLOYEE_COUNTS:
        return False, "invalid_employee_count"

    # Description sanity: match gateway
    err_code, _ = check_description_sanity(lead.get("description") or "")
    if err_code:
        return False, err_code

    # Email sanity
    email = (lead.get("email") or "").strip().lower()
    if _is_generic_email(email):
        return False, "generic_email"

    # US requires state
    if (lead.get("country") or "").strip().lower() in {"united states", "usa", "us"}:
        if not (lead.get("state") or "").strip():
            return False, "missing_state_for_us"

    # Taxonomy compatibility
    sub = lead.get("sub_industry")
    ind = lead.get("industry")
    meta = INDUSTRY_TAXONOMY.get(sub)
    if not meta:
        return False, "invalid_sub_industry"
    if ind not in (meta.get("industries") or []):
        return False, "invalid_industry_for_sub"

    return True, "ok"


class UrlDedupe:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._init()

    def _init(self):
        con = sqlite3.connect(self.db_path)
        try:
            con.execute(
                "CREATE TABLE IF NOT EXISTS seen_urls (url TEXT PRIMARY KEY, first_seen TEXT)"
            )
            con.commit()
        finally:
            con.close()

    def seen(self, url: str) -> bool:
        con = sqlite3.connect(self.db_path)
        try:
            cur = con.execute("SELECT 1 FROM seen_urls WHERE url=? LIMIT 1", (url,))
            return cur.fetchone() is not None
        finally:
            con.close()

    def mark(self, url: str):
        con = sqlite3.connect(self.db_path)
        try:
            con.execute(
                "INSERT OR IGNORE INTO seen_urls(url, first_seen) VALUES (?, ?)",
                (url, _utc_now()),
            )
            con.commit()
        finally:
            con.close()


@dataclass
class Keys:
    scrapingdog: str
    firecrawl: str
    openrouter: str
    openrouter_model: str


def load_keys() -> Keys:
    return Keys(
        scrapingdog=os.environ.get("SCRAPINGDOG_API_KEY", "").strip(),
        firecrawl=os.environ.get("FIRECRAWL_API_KEY", "").strip(),
        openrouter=os.environ.get("OPENROUTER_API_KEY", "").strip(),
        openrouter_model=os.environ.get("OPENROUTER_MODEL", "openai/gpt-4.1").strip(),
    )


async def scrapingdog_google(session: aiohttp.ClientSession, api_key: str, q: str, num: int = 10) -> List[str]:
    url = "https://api.scrapingdog.com/google"
    params = {"api_key": api_key, "q": q, "num": str(num)}
    async with session.get(url, params=params, timeout=aiohttp.ClientTimeout(total=30)) as resp:
        if resp.status != 200:
            text = await resp.text()
            raise RuntimeError(f"scrapingdog_http_{resp.status}: {text[:200]}")
        data = await resp.json(content_type=None)
    links: List[str] = []
    for item in (data.get("organic_results") or data.get("organic") or []):
        link = item.get("link") or item.get("url")
        if link and _valid_http_url(link):
            links.append(link)
    # fallback fields
    for item in (data.get("results") or []):
        link = item.get("link") or item.get("url")
        if link and _valid_http_url(link):
            links.append(link)
    # unique preserve order
    out = []
    for l in links:
        if l not in out:
            out.append(l)
    return out


async def firecrawl_scrape(session: aiohttp.ClientSession, api_key: str, target_url: str) -> Dict:
    base = os.environ.get("FIRECRAWL_BASE_URL", "https://api.firecrawl.dev").rstrip("/")
    endpoint = f"{base}/v1/scrape"
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    payload = {
        "url": target_url,
        "formats": ["markdown"],
        "onlyMainContent": True,
    }
    async with session.post(endpoint, headers=headers, json=payload, timeout=aiohttp.ClientTimeout(total=60)) as resp:
        text = await resp.text()
        if resp.status != 200:
            raise RuntimeError(f"firecrawl_http_{resp.status}: {text[:200]}")
        try:
            return json.loads(text)
        except Exception:
            return {"raw": text}


async def openrouter_structured_lead(
    session: aiohttp.ClientSession,
    api_key: str,
    model: str,
    context: Dict,
) -> Dict:
    endpoint = "https://openrouter.ai/api/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    schema = {
        "business": "",
        "full_name": "",
        "first": "",
        "last": "",
        "email": "",
        "role": "",
        "website": "",
        "industry": "",
        "sub_industry": "",
        "country": "",
        "state": "",
        "city": "",
        "linkedin": "",
        "company_linkedin": "",
        "source_url": "",
        "description": "",
        "employee_count": "",
        "source_type": "company_site",
        "phone_numbers": [],
        "founded_year": None,
        "ownership_type": "",
        "company_type": "",
        "number_of_locations": None,
        "socials": {},
    }

    # Keep the taxonomy prompt small: we classify sub_industry using our local matcher.
    system = (
        "You are a data-extraction assistant. Output ONLY valid JSON. "
        "Do not include markdown, comments, or trailing text."
    )
    user = {
        "task": "Extract ONE high-quality B2B lead from the provided web content.",
        "rules": [
            "Email must be a personal/corporate mailbox (not info@, hello@, support@, etc.).",
            "Provide a full company description (>= 70 chars, no trailing ...).",
            "Provide country/city; for United States also provide state.",
            "Provide linkedin and company_linkedin if present in content; otherwise infer from known patterns ONLY if confident.",
            "employee_count must be one of: 0-1, 2-10, 11-50, 51-200, 201-500, 501-1,000, 1,001-5,000, 5,001-10,000, 10,001+.",
            "source_url should be the page URL where the contact data was found.",
        ],
        "output_schema": schema,
        "context": context,
    }

    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": json.dumps(user, ensure_ascii=False)},
        ],
        "temperature": 0.2,
        "max_tokens": 1200,
    }

    async with session.post(endpoint, headers=headers, json=payload, timeout=aiohttp.ClientTimeout(total=60)) as resp:
        raw = await resp.text()
        if resp.status != 200:
            raise RuntimeError(f"openrouter_http_{resp.status}: {raw[:200]}")
        data = json.loads(raw)
        content = data["choices"][0]["message"]["content"]
        try:
            return json.loads(content)
        except Exception:
            # best effort: extract JSON object
            m = re.search(r"\{.*\}", content, re.S)
            if not m:
                raise
            return json.loads(m.group(0))


def _build_queries(industry_hint: Optional[str]) -> List[str]:
    # These queries are tuned to find staff pages that often contain direct emails.
    base = [
        '"@" "leadership" "team"',
        '"@" "management" "team"',
        '"@" "our team" "CEO"',
        '"@" "founder" "team"',
        '"contact" "@" "VP"',
        'site:crunchbase.com "CEO" "email"',
    ]
    if industry_hint:
        return [f"{industry_hint} {q}" for q in base]
    # Lightly diversify
    picks = random.sample(base, k=min(3, len(base)))
    return picks


async def get_leads(
    n: int,
    industry: Optional[str],
    region: Optional[str],
    dedupe_db_path: str,
    log_cb=None,
) -> List[Dict]:
    """Return up to n leads (may return fewer) using tri-key pipeline."""
    keys = load_keys()
    if not (keys.scrapingdog and keys.firecrawl and keys.openrouter):
        raise RuntimeError("Missing one of SCRAPINGDOG_API_KEY / FIRECRAWL_API_KEY / OPENROUTER_API_KEY")

    deduper = UrlDedupe(dedupe_db_path)

    async with aiohttp.ClientSession() as session:
        leads: List[Dict] = []

        queries = _build_queries(industry)
        for q in queries:
            if len(leads) >= n:
                break
            if log_cb:
                log_cb({"event": "discover_query", "q": q})

            try:
                urls = await scrapingdog_google(session, keys.scrapingdog, q=q, num=10)
            except Exception as e:
                if log_cb:
                    log_cb({"event": "discover_error", "q": q, "error": str(e)})
                continue

            for url in urls:
                if len(leads) >= n:
                    break
                if deduper.seen(url):
                    continue
                deduper.mark(url)

                if log_cb:
                    log_cb({"event": "crawl_start", "url": url})

                try:
                    crawled = await firecrawl_scrape(session, keys.firecrawl, url)
                except Exception as e:
                    if log_cb:
                        log_cb({"event": "crawl_error", "url": url, "error": str(e)})
                    continue

                md = None
                if isinstance(crawled, dict):
                    # Common Firecrawl response formats
                    md = (
                        (crawled.get("data") or {}).get("markdown")
                        or (crawled.get("markdown"))
                        or (crawled.get("data") or {}).get("content")
                    )
                md = md or ""

                emails = _extract_emails(md)
                # If no emails on page, skip (saves OpenRouter calls)
                if not emails:
                    if log_cb:
                        log_cb({"event": "crawl_no_emails", "url": url})
                    continue

                # Prefer non-generic
                emails = [e for e in emails if not _is_generic_email(e)] or emails

                context = {
                    "source_url": url,
                    "page_markdown": md[:9000],
                    "emails_found": emails[:10],
                    "industry_hint": industry,
                    "region_hint": region,
                }

                if log_cb:
                    log_cb({"event": "enrich_start", "url": url, "emails": emails[:5], "model": keys.openrouter_model})

                try:
                    lead = await openrouter_structured_lead(
                        session, keys.openrouter, keys.openrouter_model, context
                    )
                except Exception as e:
                    if log_cb:
                        log_cb({"event": "enrich_error", "url": url, "error": str(e)})
                    continue

                # Force provenance
                lead["source_url"] = url
                lead.setdefault("source_type", "company_site")

                # If taxonomy missing, try to fill via local matcher
                if not lead.get("sub_industry") or not lead.get("industry"):
                    ind, sub = _best_subindustry(
                        f"{lead.get('business','')} {lead.get('description','')} {md[:2000]}"
                    )
                    if ind and sub:
                        lead["industry"] = ind
                        lead["sub_industry"] = sub

                ok, reason = _validate_lead_minimum(lead)
                if not ok:
                    if log_cb:
                        log_cb({"event": "lead_rejected_local", "url": url, "reason": reason, "email": lead.get("email")})
                    continue

                lead["_tri_key_pipeline"] = {
                    "ts": _utc_now(),
                    "source_url": url,
                    "emails_found": emails[:10],
                    "openrouter_model": keys.openrouter_model,
                }
                leads.append(lead)
                if log_cb:
                    log_cb({"event": "lead_accepted_local", "url": url, "email": lead.get("email"), "business": lead.get("business")})

        return leads
