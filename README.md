# BugHunter AI — Web Scanner

A Streamlit app for low-impact, passive website checks on sites the operator owns or is explicitly authorized to assess.

## Features
- Scan a website by entering its URL.
- Limited same-origin crawl of public HTML pages.
- Checks HTTPS use, common security headers, cookie attributes, technology banners, and possible mixed content.
- Severity-labelled findings with CSV and PDF reports.
- Safety limits: GET requests only, page count and response-size limits, request delay, redirect restrictions, and blocking of private/local/reserved IP destinations.

## Deploy
1. Open https://share.streamlit.io/ and sign in with GitHub.
2. Create app and select this repository.
3. Branch: `main`; main file: `app.py`.
4. Click Deploy.

## Local run
```bash
pip install -r requirements.txt
streamlit run app.py
```

## Important
Only scan systems you own or have explicit permission to assess. This is not a penetration test. It does not exploit vulnerabilities, submit forms, brute-force logins, test authenticated areas, or prove the absence of vulnerabilities. Results require manual verification.
