from playwright.sync_api import sync_playwright
from langchain_community.document_transformers import Html2TextTransformer
from typing import Any, Literal

class Document:
    """Class for storing a piece of text and associated metadata."""

    page_content: str
    """String text."""
    type: Literal["Document"] = "Document"

    def __init__(self, page_content: str, **kwargs: Any) -> None:
        """Pass page_content in as positional or named arg."""
        self.page_content = page_content
        self.metadata = kwargs.get("metadata", {})

    @classmethod
    def is_lc_serializable(cls) -> bool:
        """Return whether this class is serializable."""
        return True

    @classmethod
    def get_lc_namespace(cls) -> list[str]:
        """Get the namespace of the langchain object."""
        return ["langchain", "schema", "document"]

    def __str__(self) -> str:
        """Override __str__ to restrict it to page_content and metadata."""
        if self.metadata:
            return f"page_content='{self.page_content}' metadata={self.metadata}"
        else:
            return f"page_content='{self.page_content}'"

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

def scrape_page(urls):
    documents = []
    for url in urls:
        content = get_page_content(url)
        document =  Document(page_content=content, metadata={"source": url})
        documents.append(document)
    return documents