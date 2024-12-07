from openai import OpenAI
from datetime import datetime
from urllib.parse import urlparse
import json
import re

def get_base_url(full_url: str) -> str:
    """Extract the base URL (scheme + netloc) from a full URL."""
    parsed_url = urlparse(full_url)
    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
    return base_url

def is_relative_url(url):
    parsed_url = urlparse(url)
    return not parsed_url.scheme and not parsed_url.netloc


def to_json(str):
    try:
        return json.loads(str)
    except json.JSONDecodeError:
        pass
    match = re.search(r'```json(.*?)```', str, re.DOTALL)
    if match:
        json_block = match.group(1).strip()
        try:
            return json.loads(json_block)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in Markdown block: {e}")
    raise ValueError("Input is not valid JSON and does not contain a parsable JSON block.")


def extract_info_from_results(documents, OPENAI_API_KEY):
    client = OpenAI(api_key=OPENAI_API_KEY)

    today_date = datetime(2024, 11, 12).strftime("%d %B %Y")

    extracted_data = []
    for doc in documents:
        url = get_base_url(doc.metadata.get("source", ""))
        messages = [
            {
                "role": "system",
                "content": (
                    "You are a cybersecurity assistant specialized in extracting "
                    "structured information from unstructured text."
                    "Extract only vulnerabilities with 'Critical' or 'High' severity levels ('"
                    + today_date
                    + "').\n"
                    "Ignore any vulnerabilities with severity levels like 'Important' or 'Medium' or any other even if they appear.\n"
                    "Include links from the same website (" + url + ") or relative links for more details on vulnerability.\n"
                    "Ignore incomplete or ambiguous entries at the start or end of the text. "
                    "Strictly return data of today's date and only url from the same website.\n"
                    "Strictly return empty data when no relevant data is found.\n"
                    "Return results as a JSON array of objects with the following fields:\n"
                    "- 'CVE ID'\n"
                    "- 'Summary'\n"
                    "- 'Severity Level'\n"
                    "- 'Date'\n"
                    "- 'Product Affected'\n"
                    "- 'Link for more details'\n"
                    "If any field is missing, use 'None'."
                ),
            },
            {
                "role": "user",
                "content": (
                    f"Document Section:\n{doc}\n\n"
                    "Extracted Information Format:\n"
                    "[\n"
                    "  {\n"
                    "    'CVE ID': <CVE-ID>,\n"
                    "    'Summary': <Short summary>,\n"
                    "    'Severity Level': <Critical/High>,\n"
                    "    'Date': <Date>,\n"
                    "    'Product Affected': <Product name>,\n"
                    "    'Link for Extra Info': <URL or 'None'>\n"
                    "  }\n"
                    "]\n\n"
                    "Please extract only complete and relevant entries."
                ),
            },
        ]
        try:
            response = client.chat.completions.create(
                messages=messages,
                model="gpt-4o-mini",
                temperature=0,
                max_tokens=1000
            )
            output = response.choices[0].message.content.strip()
            
            # Ensure link domain matches the base_url
            if "'Link for Extra Info':" in output:
                link_start = output.find("'Link for Extra Info':") + len("'Link for Extra Info': ")
                link_end = output.find(",", link_start) if "," in output[link_start:] else len(output)
                extracted_link = output[link_start:link_end].strip().strip("'\"")

                # Check if the link is valid relative to the base_url
                if extracted_link != "None" and not extracted_link.startswith(url):
                    if not extracted_link.startswith("/"):
                        output = output.replace(f"'{extracted_link}'", "'None'")

            extracted_json = to_json(output)
            extracted_data.append({"input_doc": str(doc), "extracted_info": extracted_json})
        except Exception as e:
            print(f"Error processing document: {e}")
    return extracted_data

def get_relevant_links(documents, OPENAI_API_KEY, target_date = datetime(2024, 11, 12).strftime("%d %B %Y")):
    client = OpenAI(api_key=OPENAI_API_KEY)
    for doc in documents:
        links = doc.metadata.get("links", "").split("\n")
        messages = [
            {
                "role": "system",
                "content": ("You are an assistant that helps identify the most relevant link related to a specific date, based on    vulnerability details. Just provide the links seperated by commas. without any additional context."),
            },
            {
                "role": "user",
                "content": f"The following are links to vulnerability details. Please find the one most relevant to the date {target_date}.\n\n" +
                "\n".join(links) +
                f"\n\nPlease provide the relevant links based on the target date {target_date}.",
            },
        ]
        try:
            response = client.chat.completions.create(
                messages=messages,
                model="gpt-4o-mini",
                temperature=0,
                max_tokens=1000
            )
            output = response.choices[0].message.content.strip()
            ret_links = output.split(", ")
        except Exception as e:
            print(f"Error processing document: {e}")
        doc.metadata["relevant_links"] = ret_links
    return documents