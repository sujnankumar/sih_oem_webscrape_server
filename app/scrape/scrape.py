from playwright.sync_api import sync_playwright
from langchain_community.document_transformers import Html2TextTransformer
from typing import Any, Literal
import re
from bs4 import BeautifulSoup
from document import Document

def get_page_content(url):
    with sync_playwright() as p:
        # Launch the browser
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()

        # Open the dynamic page
        page.goto(url)

        # Wait for the network to be idle
        page.wait_for_load_state('networkidle')

        # Scroll to the bottom of the page to ensure all content is rendered
        page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
        
        # Wait for any additional network requests to complete
        page.wait_for_load_state('networkidle')

        # Wait for no network requests for a specific period
        page.wait_for_timeout(2000)  # Adjust the timeout as needed

        # Get the full HTML content
        content = page.evaluate("document.documentElement.outerHTML")

        # Close the browser
        browser.close()

        return content

def check_for_cve(content):
    cve_pattern = re.compile(r'CVE-2024-\d{4,5}')
    return cve_pattern.search(content)

def scrape_page(documents):
    for doc in documents:
        print(type(doc))
        doc.page_content = get_page_content(doc.metadata["source"])
        contains_cve = check_for_cve(doc.page_content)
        doc.metadata["contains_cve"] = True if contains_cve else False
    return documents

def convert_docs_without_cve(documents):
    for doc in documents:
        page_content = doc.page_content
        soup = BeautifulSoup(page_content, 'html.parser')

        links = '\n'.join([a['href'] for a in soup.find_all('a', href=True)])
        doc.metadata["links"] = links
        doc.contains_listing = True
        doc.contains_date = True
    return documents

