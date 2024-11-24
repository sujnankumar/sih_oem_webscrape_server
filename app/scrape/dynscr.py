from dotenv import load_dotenv
import os
import pprint
from scrape import scrape_page
from html_transform import transfer_documents
from extract import extract_content
load_dotenv()
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

documents = scrape_page(["https://msrc.microsoft.com/update-guide/", "https://cloud.google.com/support/bulletins", "https://support.sap.com/en/my-support/knowledge-base/security-notes-news/november-2024.html"])

docs_transformed = transfer_documents(documents)

extracted_content = extract_content(docs_transformed, OPENAI_API_KEY)
pprint.pprint(extracted_content)