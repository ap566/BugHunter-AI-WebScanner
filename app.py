import ipaddress, socket, time
from urllib.parse import urljoin, urlparse, urldefrag

import pandas as pd
import requests
import streamlit as st
from bs4 import BeautifulSoup

st.set_page_config(page_title="BugHunter AI Web Scanner", page_icon="🛡️", layout="wide")
st.title("🛡️ BugHunter AI — Website Scanner")
st.caption("Passive website security checks for systems you own or are explicitly authorized to assess.")
st.warning("Authorization required. This tool makes limited HTTP GET requests only. It does not exploit vulnerabilities, submit forms, brute-force logins, or modify website data.")

MAX_PAGES, TIMEOUT, MAX_BYTES = 10, 8, 750_000
UA = "BugHunterAI-PassiveScanner/1.0"

CHECKS = {
    "Content-Security-Policy": ("Medium", "Add a Content-Security-Policy suited to the application."),
    "X-Content-Type-Options": ("Low", "Set X-Content-Type-Options: nosniff."),
    "Referrer-Policy": ("Low", "Set an appropriate Referrer-Policy."),
    "Permissions-Policy": ("Info", "Consider restricting browser features the site does not need."),
    "X-Frame-Options": ("Low", "Set X-Frame-Options or CSP frame-ancestors to control framing."),
}

def validate_url(url):
    p = urlparse(url.strip())
    if p.scheme not in ("http", "https") or not p.hostname or p.username or p.password:
        raise ValueError("Enter a valid http:// or https:// URL without embedded credentials.")
    host = p.hostname
    if host.lower() == "localhost" or host.endswith(".local"):
        raise ValueError("Local and private network targets are blocked.")
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        raise ValueError("The hostname could not be resolved.")
    ips = {x[4][0].split("%")[0] for x in infos}
    if not ips or any(not ipaddress.ip_address(x).is_global for x in ips):
        raise ValueError("The hostname resolves to a private, local, or reserved IP address and is blocked.")
    return p

def request_page(url, origin):
    current = url
    for _ in range(4):
        p = validate_url(current)
        r = requests.get(current, headers={"User-Agent": UA, "Accept": "text/html"}, timeout=TIMEOUT,
                         allow_redirects=False, stream=True, verify=True)
        if r.is_redirect or r.is_permanent_redirect:
            loc = r.headers.get("Location")
            r.close()
            if not loc:
                raise ValueError("Redirect without Location header.")
            current = urljoin(current, loc)
            np = validate_url(current)
            if (np.scheme, np.hostname, np.port or (443 if np.scheme == "https" else 80)) != origin:
                raise ValueError("Cross-origin redirect blocked.")
            continue
        body = r.raw.read(MAX_BYTES + 1, decode_content=True)
        if len(body) > MAX_BYTES:
            r.close()
            raise ValueError("Page exceeds the response size limit.")
        r._content = body
        r._content_consumed = True
        return r
    raise ValueError("Redirect limit reached.")

def scan(url):
    start = validate_url(url)
    origin = (start.scheme, start.hostname, start.port or (443 if start.scheme == "https" else 80))
    queue, seen, findings, pages, errors = [url], set(), [], [], []
    while queue and len(seen) < MAX_PAGES:
        page = urldefrag(queue.pop(0))[0]
        if page in seen: continue
        seen.add(page)
        try:
            r = request_page(page, origin)
            p = urlparse(r.url)
            if (p.scheme, p.hostname, p.port or (443 if p.scheme == "https" else 80)) != origin:
                r.close()
                continue
            h = r.headers
            pages.append({"URL": r.url, "HTTP status": r.status_code, "Content type": h.get("Content-Type", "")})
            def add(sev, name, detail):
                findings.append({"Severity": sev, "Finding": name, "Details": detail, "Page": r.url})
            if p.scheme != "https":
                add("High", "Page uses HTTP", "The page is not protected by HTTPS; traffic may be exposed in transit.")
            for name, (sev, detail) in CHECKS.items():
                if name not in h: add(sev, "Missing " + name, detail)
            if p.scheme == "https" and "Strict-Transport-Security" not in h:
                add("Medium", "Missing Strict-Transport-Security", "Consider enabling HSTS after confirming HTTPS works across the site.")
            if h.get("Server"):
                add("Info", "Server banner disclosed", "Server response header: " + h["Server"][:120])
            if h.get("X-Powered-By"):
                add("Low", "Technology banner disclosed", "X-Powered-By header is present; consider removing unnecessary version details.")
            raw_headers = getattr(r.raw, "headers", None)
            cookies = raw_headers.getlist("Set-Cookie") if raw_headers and hasattr(raw_headers, "getlist") else []
            for c in cookies:
                name = c.split("=", 1)[0][:80]
                low = c.lower()
                if p.scheme == "https" and "secure" not in low:
                    add("Medium", "Cookie missing Secure flag: " + name, "Set Secure on cookies that should only travel over HTTPS.")
                if "httponly" not in low:
                    add("Low", "Cookie missing HttpOnly flag: " + name, "Set HttpOnly when JavaScript does not need to read the cookie.")
                if "samesite" not in low:
                    add("Low", "Cookie missing SameSite attribute: " + name, "Set an appropriate SameSite attribute.")
            if "text/html" in h.get("Content-Type", "").lower():
                soup = BeautifulSoup(r.content, "html.parser")
                if p.scheme == "https":
                    for tag in soup.find_all(src=True) + soup.find_all(href=True):
                        ref = tag.get("src") or tag.get("href")
                        if isinstance(ref, str) and ref.startswith("http://"):
                            add("Medium", "Potential mixed content", "HTTPS page references an HTTP resource: " + ref[:160])
                            break
                for a in soup.find_all("a", href=True):
                    dest = urljoin(r.url, a["href"])
                    dp = urlparse(dest)
                    d_origin = (dp.scheme, dp.hostname, dp.port or (443 if dp.scheme == "https" else 80))
                    if dp.scheme in ("http", "https") and d_origin == origin and dest not in seen and len(queue) < MAX_PAGES * 2:
                        if not dp.path.lower().endswith((".png",".jpg",".jpeg",".gif",".pdf",".zip",".docx")):
                            queue.append(dest)
            r.close()
            time.sleep(0.3)
        except Exception as e:
            errors.append(page + " — " + str(e)[:180])
    return findings, pages, errors

with st.form("urlscan"):
    target = st.text_input("Website URL", placeholder="https://example.com")
    authorized = st.checkbox("I own this website or have explicit permission to assess it.")
    go = st.form_submit_button("Scan website", type="primary")
if go:
    if not authorized:
        st.error("Confirm authorization before scanning.")
    elif not target.strip():
        st.error("Enter a website URL.")
    else:
        try:
            validate_url(target)
            with st.spinner("Checking a limited number of public pages..."):
                f, p, e = scan(target)
            st.session_state["result"] = (target, f, p, e)
        except Exception as e:
            st.error(str(e))

if "result" in st.session_state:
    target, findings, pages, errors = st.session_state["result"]
    st.subheader("Assessment results")
    a,b,c,d = st.columns(4)
    a.metric("Pages checked", len(pages))
    b.metric("Findings", len(findings))
    c.metric("High", sum(x["Severity"] == "High" for x in findings))
    d.metric("Medium", sum(x["Severity"] == "Medium" for x in findings))
    st.caption("Target: " + target + " · GET-only passive checks · Maximum 10 pages")
    if findings:
        df = pd.DataFrame(findings)
        filt = st.multiselect("Severity filter", ["Critical","High","Medium","Low","Info"], default=["Critical","High","Medium","Low","Info"])
        st.dataframe(df[df["Severity"].isin(filt)], use_container_width=True, hide_index=True)
        st.download_button("Download CSV report", df.to_csv(index=False).encode(), "bughunter_findings.csv", "text/csv")
        try:
            import io
            from reportlab.lib import colors
            from reportlab.lib.pagesizes import A4, landscape
            from reportlab.lib.styles import getSampleStyleSheet
            from reportlab.lib.units import mm
            from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph
            buf = io.BytesIO()
            doc = SimpleDocTemplate(buf, pagesize=landscape(A4))
            styles = getSampleStyleSheet()
            data = [["Severity","Finding","Details","Page"]]
            for x in findings:
                data.append([x["Severity"], x["Finding"], Paragraph(x["Details"][:400],styles["BodyText"]), Paragraph(x["Page"][:160],styles["BodyText"])])
            table = Table(data, repeatRows=1, colWidths=[22*mm,48*mm,105*mm,85*mm])
            table.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#26364A")),("TEXTCOLOR",(0,0),(-1,0),colors.white),("GRID",(0,0),(-1,-1),.4,colors.grey),("VALIGN",(0,0),(-1,-1),"TOP"),("FONTSIZE",(0,0),(-1,-1),7),("PADDING",(0,0),(-1,-1),5)]))
            doc.build([Paragraph("BugHunter AI — Passive Website Assessment",styles["Title"]),table])
            st.download_button("Download PDF report",buf.getvalue(),"bughunter_report.pdf","application/pdf")
        except Exception:
            st.info("PDF generation unavailable; CSV report is available.")
    else:
        st.success("No issues found by these limited checks. This does not prove the website is secure.")
    st.subheader("Pages checked")
    if pages: st.dataframe(pd.DataFrame(pages), use_container_width=True, hide_index=True)
    if errors:
        with st.expander("Skipped pages and errors"):
            for x in errors: st.write(x)

st.divider()
st.caption("Limitations: This is a basic passive scanner, not a penetration test. It does not test authentication, authorization, SQL injection or XSS exploitability, private pages, or server-side source code. Findings may be false positives and need manual verification.")
