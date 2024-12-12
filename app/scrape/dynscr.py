from dotenv import load_dotenv
import os
from .scraper import scrape_page
from .html_transform import transfer_documents, custom_transform, convert_doc_without_cve, custom_html_to_text, convert_doc_with_cve
from .extract_info import extract_info_from_results, extract_vulnerability_info, get_relevant_links, get_base_url, is_relative_url
from .document import Document
import tiktoken
from ..logging_functions import log_scraping_start, log_scraping_end

def load_api_key():
    load_dotenv()
    return os.getenv("OPENAI_API_KEY")


def initialize_documents():
    return [
        Document(page_content="", metadata={"source": "https://api.msrc.microsoft.com/update-guide/rss", "contains_cve": False}, contains_listing=True, contains_date=True, contains_details=False, is_rss=True)
    ]
# ,
        # Document(page_content="", metadata={"source": "https://www.intel.com/content/www/us/en/security-center/default.html", "contains_cve": False}, contains_listing=True, contains_date=False, contains_details=False),
        # Document(page_content="", metadata={"source": "https://support.sap.com/en/my-support/knowledge-base/security-notes-news.html", "contains_cve": False}, contains_listing=True, contains_date=False, contains_details=False)

def process_documents_with_listings(documents):
    documents_listing = []
    for doc in documents:
        if doc.contains_listing:
            print(doc.metadata['contains_cve'])
            if not doc.metadata['contains_cve']:
                doc_all_links = convert_doc_without_cve(doc)
            else:
                doc_all_links = convert_doc_with_cve(doc)

            for link in doc_all_links.metadata['links'][:1]:
                new_doc = Document(page_content="", metadata={"source": get_base_url(doc.metadata['source'])+link if is_relative_url(link) else link, 'id': doc.metadata['id'], 'contains_cve': doc.metadata['contains_cve']}, contains_listing=False, contains_date=False, contains_details=doc.contains_details)
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
    ret_docs = []
    for doc in docs_extracted_info:
        more_links = set()
        info = doc.get_flag("extracted_info")
        if info:
            for entry in info:
                link = entry.get("Link for more details", "")
                print(link)
                more_links.add((get_base_url(doc.metadata['source'])+link if is_relative_url(link) else link, doc.metadata['id']))
        ret_docs.append(Document(page_content="", metadata={"source": link, "contains_cve": True, "id": doc.metadata['id'], "more_links": list(more_links)}, contains_listing=False, contains_date=False, contains_details=False))
    return ret_docs

def create_further_documents(docs_with_more_links):
    ret_docs = []
    for doc in docs_with_more_links:
        for link, id in doc.metadata['more_links']:
            ret_docs.append(Document(page_content="", metadata={"source": link, "contains_cve": False, "id": id}, contains_listing=False, contains_date=False, contains_details=False))
    return ret_docs

def dynamic_scraper(app, initial_documents):
    api_key = load_api_key()
    
    rss_docs = [doc for doc in initial_documents if doc.is_rss]
    
    documents = [doc for doc in initial_documents if not doc.is_rss]
    if documents:
        
        documents = scrape_documents(app,initial_documents)

        documents_listing = process_documents_with_listings(documents)
        documents += scrape_documents(app,documents_listing)
        
        docs_transformed = transform_documents(documents)
        docs_with_cves = [doc for doc in docs_transformed if doc.metadata['contains_cve']]
        docs_transformed = [doc for doc in docs_transformed if not doc.metadata['contains_cve']]

        docs_with_details = [doc for doc in docs_transformed if doc.contains_details]
        docs_without_details = [doc for doc in docs_transformed if not doc.contains_details]
        docs_extracted_info = extract_info_from_documents(docs_with_details, api_key)
        docs_with_more_links = gather_more_links(docs_extracted_info)

        further_documents = create_further_documents(docs_with_more_links)

        documents = scrape_documents(app,further_documents)
        docs_transformed = transform_documents(documents) + docs_without_details

        docs_transformed += custom_html_to_text(docs_with_cves)
    if rss_docs:
        rss_docs = process_documents_with_listings(rss_docs)
        rss_documents = scrape_documents(app,rss_docs)
        rss_refined = custom_html_to_text(rss_documents)
        docs_transformed += rss_refined

    if not docs_transformed:
        return []
    ret_results = []
    for doc in docs_transformed:
        extracted_info = extract_vulnerability_info(doc, api_key)
        for info in extracted_info:
            ret_results.append([info, doc.metadata['id']])
    print(ret_results)
    return ret_results