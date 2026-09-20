from flask import Blueprint, Response, request, render_template_string
from datetime import datetime

seo_bp = Blueprint("seo", __name__)


@seo_bp.route("/robots.txt")
def robots_txt():
    base_url = request.url_root.rstrip("/")
    content = f"""User-agent: *
Disallow: /reports/
Disallow: /profile
Disallow: /settings
Disallow: /api/
Disallow: /auth/callback

Sitemap: {base_url}/sitemap.xml
"""
    return Response(content, mimetype="text/plain")


@seo_bp.route("/sitemap.xml")
def sitemap_xml():
    base_url = request.url_root.rstrip("/")
    today = datetime.utcnow().strftime("%Y-%m-%d")

    public_routes = [
        {"loc": "/", "priority": "1.0", "changefreq": "daily"},
        {"loc": "/scanner", "priority": "0.9", "changefreq": "daily"},
        {"loc": "/api/docs", "priority": "0.8", "changefreq": "weekly"},
        {"loc": "/privacy", "priority": "0.5", "changefreq": "monthly"},
        {"loc": "/terms", "priority": "0.5", "changefreq": "monthly"},
        {"loc": "/auth/login", "priority": "0.6", "changefreq": "monthly"},
    ]

    xml = ['<?xml version="1.0" encoding="UTF-8"?>']
    xml.append('<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">')

    for route in public_routes:
        xml.append("  <url>")
        xml.append(f"    <loc>{base_url}{route['loc']}</loc>")
        xml.append(f"    <lastmod>{today}</lastmod>")
        xml.append(f"    <changefreq>{route['changefreq']}</changefreq>")
        xml.append(f"    <priority>{route['priority']}</priority>")
        xml.append("  </url>")

    xml.append("</urlset>")
    return Response("\n".join(xml), mimetype="application/xml")
