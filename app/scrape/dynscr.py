from dotenv import load_dotenv
import os
import pprint
from scrape import scrape_page
from html_transform import transfer_documents
from extract import extract_content
from extract_info import extract_info_from_results

load_dotenv()
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

documents = scrape_page(["https://msrc.microsoft.com/update-guide/", "https://cloud.google.com/support/bulletins"])

docs_transformed = transfer_documents(documents)


extracted_info = extract_info_from_results(docs_transformed, OPENAI_API_KEY)
    
    # Print the extracted information
for idx, info in enumerate(extracted_info):
    print(f"Document {idx + 1}:\n")
    print(info["extracted_info"])
    print("\n" + "="*50 + "\n")
# extracted_content = extract_content(docs_transformed, OPENAI_API_KEY)
# pprint.pprint(extracted_content)