from dotenv import load_dotenv
import os
import pprint
from scrape import scrape_page, convert_docs_without_cve
from html_transform import transfer_documents, custom_transform
from extract_info import extract_info_from_results, get_relevant_links, get_base_url, is_relative_url
from document import Document
import tiktoken

def num_tokens_from_string(string: str, encoding_name: str) -> int:
    encoding = tiktoken.get_encoding(encoding_name)
    num_tokens = len(encoding.encode(string))
    return num_tokens

load_dotenv()
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

# documents = scrape_page(["https://cloud.google.com/support/bulletins", "https://msrc.microsoft.com/update-guide/", ])

# doc1 = Document(page_content="", metadata={"source": "https://support.sap.com/en/my-support/knowledge-base/security-notes-news.html", "contains_cve": False}, contains_listing=True, contains_date=False)
doc2 = Document(page_content="", metadata={"source": "https://www.intel.com/content/www/us/en/security-center/default.html#", "contains_cve": False}, contains_listing=True, contains_date=False)

documents_without_cve = scrape_page([doc2])

docs_all_links = convert_docs_without_cve(documents_without_cve)
relevant_links =  get_relevant_links(docs_all_links, OPENAI_API_KEY)

documents = []
for doc in relevant_links:
    for link in doc.metadata['relevant_links']:
        documents.append(Document(page_content="", metadata={"source": get_base_url(doc.metadata['source'])+link if is_relative_url(link) else link}, contains_listing=False, contains_date=False))

for doc in documents:
    print(doc.metadata)


documents = scrape_page(documents)
i=0
for doc in documents:
    with open("scraped_{}.txt".format(i), "w", encoding="utf-8") as f:
        f.write(str(doc.page_content))
    print("written scraped_{}.txt".format(i))
    i+=1

docs_transformed = transfer_documents(documents)
i=0
for doc in docs_transformed:
    print(num_tokens_from_string(str(doc.page_content), "o200k_base"))
    with open("transformed_{}.txt".format(i), "w", encoding="utf-8") as f:
        f.write(str(doc.page_content))
    print("written transformed_{}.txt".format(i))
    i+=1

extracted_info = extract_info_from_results(docs_transformed, OPENAI_API_KEY)

for idx, info in enumerate(extracted_info):
    print(f"Document {idx + 1}:\n")
    print(info["extracted_info"])
    print("\n" + "="*50 + "\n")

