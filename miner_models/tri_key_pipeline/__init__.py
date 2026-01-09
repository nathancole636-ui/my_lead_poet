"""Tri-key miner pipeline.

This module implements a strict, self-contained lead generation flow using ONLY:
- ScrapingDog (discovery via Google results)
- Firecrawl (crawl/scrape page content)
- OpenRouter (LLM enrichment -> Leadpoet lead JSON)

It does NOT modify validator/gateway logic; it only aims to generate leads that
already satisfy gateway checks.
"""
