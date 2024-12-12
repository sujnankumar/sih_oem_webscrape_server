from playwright.sync_api import sync_playwright
import re
from .. logging_functions import log_scraping_start
import logging



def get_page_content(url):
    with sync_playwright() as p:
        # Launch the browser
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()

        # Open the dynamic page
        response = page.goto(url)

        if response.url:
            res_url = response.url.split('?')[0].split('#')[0]
            url = url.split('?')[0].split('#')[0]
            print(res_url, url)
            if res_url != url:
                return None

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

def scrape_page(app,documents):
    for doc in documents:
        log_scraping_start(app,doc.metadata["source"],logging)
        print(doc.metadata["source"])
        page_content = get_page_content(doc.metadata["source"])
        if page_content:
            doc.page_content = page_content
            contains_cve = check_for_cve(doc.page_content)
            doc.metadata["contains_cve"] = True if contains_cve else False
            doc.set_flag("scraped", True)
        doc.set_flag("scraped", False)
    return documents