from dotenv import load_dotenv
import os
from .scraper import scrape_page
from .html_transform import transfer_documents, custom_transform, convert_doc_without_cve
from .extract_info import extract_info_from_results, extract_vulnerability_info, get_relevant_links, get_base_url, is_relative_url
from .document import Document
import tiktoken
from ..logging_functions import log_scraping_start, log_scraping_end

def load_api_key():
    load_dotenv()
    print(os.getenv("OPENAI_API_KEY"))
    return os.getenv("OPENAI_API_KEY")


def initialize_documents():
    return [
        Document(page_content="", metadata={"source": "https://msrc.microsoft.com/update-guide/", "contains_cve": False}, contains_listing=False, contains_date=True, contains_details=True)
    ]
# ,
        # Document(page_content="", metadata={"source": "https://www.intel.com/content/www/us/en/security-center/default.html", "contains_cve": False}, contains_listing=True, contains_date=False, contains_details=False),
        # Document(page_content="", metadata={"source": "https://support.sap.com/en/my-support/knowledge-base/security-notes-news.html", "contains_cve": False}, contains_listing=True, contains_date=False, contains_details=False)

def process_documents_with_listings(documents):
    documents_listing = []
    for doc in documents:
        if doc.contains_listing:
            doc_all_links = convert_doc_without_cve(doc)
            for link in doc_all_links.metadata['links'][:1]:
                new_doc = Document(page_content="", metadata={"source": get_base_url(doc.metadata['source'])+link if is_relative_url(link) else link, 'id': doc.metadata['id']}, contains_listing=False, contains_date=False, contains_details=doc.contains_details)
                print(new_doc)
                documents_listing.append(new_doc)
    return documents_listing

def scrape_documents(app,documents):
    # website-id,status,last-scraped
    documents = scrape_page(app,documents)
    return documents

def transform_documents(documents):
    return custom_transform(documents)

def extract_info_from_documents(docs_with_details, api_key):
    return extract_info_from_results(docs_with_details, api_key)

def gather_more_links(docs_extracted_info):
    more_links = set()
    for doc in docs_extracted_info:
        info = doc.get_flag("extracted_info")
        if info:
            for entry in info:
                link = entry.get("Link for more details", "")
                more_links.add((get_base_url(doc.metadata['source'])+link if is_relative_url(link) else link, doc.metadata['id']))
    return more_links

def create_further_documents(more_links):
    for link, id in more_links:
        return [Document(page_content="", metadata={"source": link, "contains_cve": False, "id": id}, contains_listing=False, contains_date=False, contains_details=False)]

def dynamic_scraper(app,initial_documents):
    api_key = load_api_key()


    documents = scrape_documents(app,initial_documents)

    documents_listing = process_documents_with_listings(documents)
    documents += scrape_documents(app,documents_listing)
    
    docs_transformed = transform_documents(documents)

    docs_with_details = [doc for doc in docs_transformed if doc.contains_details]
    docs_without_details = [doc for doc in docs_transformed if not doc.contains_details]

    docs_extracted_info = extract_info_from_documents(docs_with_details, api_key)

    more_links = gather_more_links(docs_extracted_info)
    further_documents = create_further_documents(more_links)

    documents = scrape_documents(app,further_documents)
    docs_transformed = transform_documents(documents) + docs_without_details
    
    ret_results = []
    for doc in docs_transformed:
        extracted_info = extract_vulnerability_info(doc, api_key)
        for info in extracted_info:
            ret_results.append([info, doc.metadata['id']])

    return ret_results