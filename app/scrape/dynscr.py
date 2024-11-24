from playwright.sync_api import sync_playwright
from langchain_community.document_transformers import Html2TextTransformer
from langchain.chains import create_extraction_chain
from typing import Any, Literal
from langchain_openai import ChatOpenAI
from dotenv import load_dotenv
import os
from langchain_text_splitters import RecursiveCharacterTextSplitter
import pprint

load_dotenv()

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

# Replace with the URL of the dynamic page you want to load
url = 'https://sec.cloudapps.cisco.com/security/center/publicationListing.x'
page_content = get_page_content(url)

# Create a Document instance with the page content
document = Document(page_content=page_content, metadata={"source": url})

# Wrap the Document instance in a list
documents = [document]

# Initialize the BeautifulSoupTransformer
html2text = Html2TextTransformer()
docs_transformed = html2text.transform_documents(documents)


schema = {
    "properties": {
        "date": {"type": "string"},
        "cve": {"type": "string"},
        "impact": {"type": "string"},
        "max_severity": {"type": "string"},
    },
    "required": ["date", "cve", "max_severity"],
}

def extract(content: str, schema: dict):
    return create_extraction_chain(schema=schema, llm=llm).run(content)
OPENAI_API_KEY= os.environ.get("OPENAI_API_KEY")
llm = ChatOpenAI(temperature=0, model="gpt-3.5-turbo", api_key=OPENAI_API_KEY)

splitter = RecursiveCharacterTextSplitter.from_tiktoken_encoder(
        chunk_size=1000, chunk_overlap=0
)
splits = splitter.split_documents(docs_transformed)
cont = '''[Home ](https://www.cisco.com) / [Cisco Security](/security/center/home.x) /
[Security
Advisories](https://sec.cloudapps.cisco.com/security/center/publicationListing.x)

#### Cisco Security

# Cisco Security Advisories

* [Vulnerabilities](javascript:void\(0\))
* [Filter By Product](javascript:void\(0\))

Quick Search

[_Advanced Search_](/security/center/Search.x)

Advisory | Impact  | CVE | Last Updated  | Version   
---|---|---|---|---  
|  All   All   Critical   High   Medium   Low   Informational Done  |  |  Most Recent 2024 Nov 2024 Oct 2024 Sep 2024 Aug 2024 Jul 2024 Jun 2024 May 2024 Apr 2024 Mar 2024 Feb 2024 Jan 2023 Dec |   
|  [Cisco Secure Web Appliance Privilege Escalation Vulnerability](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-swa-priv-esc-7uHpZsCC) | High |  CVE-2024-20435   
| 2024 Nov 22 | 1.1  
---|---|---|---|---  
CVE: CVE-2024-20435  
Publication ID:cisco-sa-swa-priv-esc-7uHpZsCC Version: 1.1 First
Published:2024 Jul 17 16:00 GMT Workaround:No  Summary:A vulnerability in the
CLI of Cisco AsyncOS for Secure Web Appliance could allow an authenticated,
local attacker to execute arbitrary commands and elevate privileges to
root.This vulnerability is due to insufficient validation of user-supplied
input for the CLI. An attacker [Read
More...](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-
sa-swa-priv-esc-7uHpZsCC)  
|  [Cisco IOS XR Software Bootloader Unauthenticated Information Disclosure Vulnerability](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxr-load-infodisc-9rdOr5Fq) | Medium |  CVE-2023-20064   
| 2024 Nov 13 | 1.3  
---|---|---|---|---  
CVE: CVE-2023-20064  
Publication ID:cisco-sa-iosxr-load-infodisc-9rdOr5Fq Version: 1.3 First
Published:2023 Mar 08 16:00 GMT Workaround:No  Summary:A vulnerability in the
GRand Unified Bootloader (GRUB) for Cisco IOS XR Software could allow an
unauthenticated attacker with physical access to the device to view sensitive
files on the console using the GRUB bootloader command line. This
vulnerability is due to the inclusion of [Read
More...](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-
sa-iosxr-load-infodisc-9rdOr5Fq) '''
extracted_content = extract(cont, schema)
pprint.pprint(extracted_content)