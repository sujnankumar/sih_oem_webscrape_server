from playwright.sync_api import sync_playwright
import hashlib
from bs4 import BeautifulSoup
import time

urls = ["https://www.oracle.com/in/security-alerts/"]
def clean_html(html):
    soup = BeautifulSoup(html, 'html.parser')
    text = soup.get_text()
    return str(text)


def get_dynamic_page_hash(url):
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()

        # Open the dynamic page
        page.goto(url)

        # Wait for the network to be idle
        page.wait_for_load_state('networkidle')

        # Scroll to the bottom of the page to load lazy-loaded content
        page.evaluate("window.scrollTo(0, document.body.scrollHeight)")

        page.wait_for_timeout(2000)
        content = page.evaluate("document.documentElement.outerHTML")

        browser.close()

        cleaned_content = clean_html(content)
        print(cleaned_content)

        return hashlib.md5(cleaned_content.encode()).hexdigest()
    
current_hash = None
previous_hash = None

def check_for_updates(urls: list) -> bool:
    time.sleep(10)
    for url in urls:
        current_hash = get_dynamic_page_hash(url)

        if current_hash != previous_hash:
            print(current_hash)
            print(previous_hash)
            previous_hash = current_hash
            return True
        else:
            return False

