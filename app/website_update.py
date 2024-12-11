from playwright.sync_api import sync_playwright
import hashlib
from bs4 import BeautifulSoup
import time
from app.models import OEMWebsite
from app import db
def get_urls()-> list:
    urls = [url[0] for url in db.session.query(OEMWebsite.website_url).all()]
    return urls

#"https://www.intel.com/content/www/us/en/security-center/default.html"
def clean_html(html):
    soup = BeautifulSoup(html, 'html.parser')
    text = soup.get_text()
    return str(text)

index = 0
files = ["microsoft_update_guide.txt", "microsoft_update_guide_change.txt"]


def remove_elements_by_keywords(page, keywords):
    """
    Remove elements from the page whose class or id contains specific keywords.
    Args:
        page: Playwright page object.
        keywords: List of keywords to search for in class or id attributes.
    """
    try:
        for keyword in keywords:
            page.evaluate(f"""
                document.querySelectorAll('[class*="{keyword}"], [id*="{keyword}"]').forEach(el => el.remove());
            """)
    except Exception as e:
        print(f"Error removing elements with keywords {keywords}: {e}")


def remove_elements_by_aria_label(page, aria_label):
    """
    Remove elements from the page with a specific aria-label attribute.
    Args:
        page: Playwright page object.
        aria_label: The aria-label value to target for removal.
    """
    try:
        page.evaluate(f"""
    Array.from(document.querySelectorAll('[aria-label="{aria_label}"]')).forEach(element => element.remove());
""")
    except Exception as e:
        print(f"Error removing elements with aria-label='{aria_label}': {e}")


# Example usage
def clean_dynamic_page(page):
    # Remove popups or other unwanted elements using keywords
    keywords = ['popup', 'modal', 'overlay', 'banner', 'signup']
    remove_elements_by_keywords(page, keywords)

    # Remove elements with a specific aria-label
    remove_elements_by_aria_label(page, "Sign In to your account")

    # Optionally retrieve and return cleaned HTML
    return page.evaluate("document.documentElement.outerHTML")


def get_dynamic_page_hash(url: str)-> str:
    global index,files
    with sync_playwright() as p:
        try:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()

            page.goto(url)

            page.wait_for_load_state('networkidle')

            page.evaluate("window.scrollTo(0, document.body.scrollHeight)")

            page.wait_for_timeout(2000)
            clean_dynamic_page(page)
            content = page.evaluate("document.documentElement.outerHTML")
            
            cleaned_content = clean_html(content)
            
            if url == "https://msrc.microsoft.com/update-guide/": 
                if index==2:
                    index=0
                with open(files[index], "w", encoding="utf-8") as file:
                    file.write(cleaned_content)
                    index += 1
            return hashlib.md5(cleaned_content.encode()).hexdigest()
        except Exception as e:
            print(f"An error occurred: {e}")
        finally:
            browser.close()

def check_for_updates() -> bool:
    urls = get_urls()
    print(urls)
    for url in urls:
        oem = OEMWebsite.query.filter_by(website_url=url).first()
        if oem:
            previous_hash =oem.website_hash
            print("Checking for updates in the following URL:", url)
            current_hash = get_dynamic_page_hash(url)

            if current_hash != previous_hash:
                print(current_hash)
                print(previous_hash)
                try:
                    oem.website_hash = current_hash
                    db.session.commit()
                except Exception as e:
                    print(f"An error occurred: {e}")
                    db.session.rollback()
                print("Update detected in the following URL:", url)
                #Put the scrape function here
            else:
                print("No updates found in the following URL:", url)
        else:
            try:
                oem.website_hash = get_dynamic_page_hash(url)
                db.session.commit()
            except Exception as e:
                print(f"An error occurred: {e}")
                db.session.rollback()
            print("No updates found in the following URL:", url)

def run_now():
    while True:
        check_for_updates()
        time.sleep(2)