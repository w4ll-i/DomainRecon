# backend/app/scanners/email.py
import asyncio
import re
import smtplib
from typing import Optional

import dns.resolver

from ._config import DKIM_SELECTORS, DNSBL_SERVERS


def _analyze_email_security_sync(domain: str) -> dict:
    result = {"spf": None, "dkim": {}, "dmarc": None}
    try:
        for rdata in dns.resolver.resolve(domain, "TXT", lifetime=5):
            txt = str(rdata).strip('"')
            if txt.startswith("v=spf1"):
                result["spf"] = txt
                break
    except Exception:
        pass
    for sel in DKIM_SELECTORS:
        try:
            for rdata in dns.resolver.resolve(f"{sel}._domainkey.{domain}", "TXT", lifetime=3):
                txt = str(rdata)
                if "v=DKIM1" in txt:
                    result["dkim"][sel] = txt[:100]
                    break
        except Exception:
            pass
    try:
        for rdata in dns.resolver.resolve(f"_dmarc.{domain}", "TXT", lifetime=5):
            txt = str(rdata).strip('"')
            if txt.startswith("v=DMARC1"):
                result["dmarc"] = txt
                break
    except Exception:
        pass
    return result


async def analyze_email_security(domain: str) -> dict:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _analyze_email_security_sync, domain)


def _get_primary_mx(domain: str) -> Optional[str]:
    try:
        answers = dns.resolver.resolve(domain, "MX", lifetime=5)
        return str(sorted(answers, key=lambda r: r.preference)[0].exchange).rstrip(".")
    except Exception:
        return None


def _check_smtp_sync(domain: str) -> dict:
    """Connect to primary MX, grab banner, test STARTTLS, detect open relay."""
    result = {
        "banner": None, "starttls": False,
        "auth_methods": [], "open_relay": False, "error": None,
    }
    mx_host = _get_primary_mx(domain)
    if not mx_host:
        return {**result, "error": "No MX record found"}
    try:
        with smtplib.SMTP(mx_host, 25, timeout=10) as smtp:
            result["banner"] = smtp.getwelcome().decode(errors="ignore")
            try:
                smtp.ehlo()
                smtp.starttls()
                result["starttls"] = True
            except Exception:
                pass
            try:
                code, msg = smtp.ehlo(domain)
                caps = msg.decode(errors="ignore").upper()
                if "AUTH" in caps:
                    result["auth_methods"] = re.findall(r"AUTH\s+([\w ]+)", caps)
            except Exception:
                pass
            try:
                smtp.mail(f"probe@{domain}")
                code2, _ = smtp.rcpt("test@openrelay.check.invalid")
                result["open_relay"] = code2 == 250
            except Exception:
                pass
    except Exception as e:
        result["error"] = str(e)
    return result


async def check_smtp_security(domain: str) -> dict:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _check_smtp_sync, domain)


def _check_catch_all_sync(domain: str) -> dict:
    mx_host = _get_primary_mx(domain)
    if not mx_host:
        return {"catch_all": None, "error": "No MX record found"}
    fake = f"no_such_user_xyzabc99@{domain}"
    try:
        with smtplib.SMTP(mx_host, 25, timeout=10) as smtp:
            smtp.ehlo()
            smtp.mail("probe@probe.invalid")
            code, _ = smtp.rcpt(fake)
            return {"catch_all": code == 250, "response_code": code}
    except smtplib.SMTPRecipientsRefused:
        return {"catch_all": False}
    except Exception as e:
        return {"catch_all": None, "error": str(e)}


async def check_catch_all(domain: str) -> dict:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _check_catch_all_sync, domain)


def compute_spoofability(email_data: dict, catch_all_data: dict) -> dict:
    """Pure calculation, no network. Score starts at 100 (fully spoofable)."""
    score = 100
    spf = email_data.get("spf")
    dmarc = email_data.get("dmarc")
    dkim = email_data.get("dkim", {})
    catch_all = catch_all_data.get("catch_all")

    if spf:
        score -= 30
    if dmarc:
        score -= 35
        if "p=reject" in dmarc:
            score -= 10
        elif "p=quarantine" in dmarc:
            score -= 5
    if dkim:
        score -= 20
    if catch_all is False:
        score -= 5

    score = max(0, score)
    if score >= 80:
        risk = "Critical"
    elif score >= 60:
        risk = "High"
    elif score >= 40:
        risk = "Medium"
    else:
        risk = "Low"

    return {
        "spoofability_score": score,
        "risk_level": risk,
        "details": {
            "spf_present": bool(spf),
            "dmarc_present": bool(dmarc),
            "dkim_present": bool(dkim),
            "catch_all": catch_all,
        },
    }


def _check_email_blacklists_sync(ip: str) -> dict:
    listed = []
    for dnsbl in DNSBL_SERVERS:
        try:
            reversed_ip = ".".join(reversed(ip.split(".")))
            dns.resolver.resolve(f"{reversed_ip}.{dnsbl}", "A", lifetime=3)
            listed.append(dnsbl)
        except dns.resolver.NXDOMAIN:
            pass
        except Exception:
            pass
    return {"listed_on": listed, "is_blacklisted": len(listed) > 0}


async def check_email_blacklists(ip: str) -> dict:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _check_email_blacklists_sync, ip)
