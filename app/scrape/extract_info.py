from openai import OpenAI
from datetime import datetime
from urllib.parse import urlparse, parse_qsl, urlunparse, urlencode
import json
import re
from .vuln_details import Vulnerability, AdditionalDetails 

today = datetime(2024, 12, 10)

def get_base_url(full_url: str) -> str:
    """Extract the base URL (scheme + netloc) from a full URL."""
    parsed_url = urlparse(full_url)
    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
    return base_url

def is_relative_url(url):
    parsed_url = urlparse(url)
    return not parsed_url.scheme and not parsed_url.netloc


def normalize_url(url):
    parsed_url = urlparse(url)
    sorted_query = sorted(parse_qsl(parsed_url.query))
    normalized_url = urlunparse((
        parsed_url.scheme,
        parsed_url.netloc.lower(),
        parsed_url.path.rstrip('/'),
        parsed_url.params,
        urlencode(sorted_query),
        parsed_url.fragment
    ))
    return normalized_url

def are_links_same(link1, link2):
    return normalize_url(link1) == normalize_url(link2)

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

    global today
    today_date = today.strftime("%d %B %Y")

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
                    f"Document Section:\n{doc.page_content}\n\n"
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
            stream = client.chat.completions.create(
                messages=messages,
                model="gpt-4o-mini",
                temperature=0,
                stream=True,
            )
            output = ""

            for chunk in stream:
                if chunk.choices[0].delta.content is not None:
                    output += chunk.choices[0].delta.content

            # Ensure link domain matches the base_url
            if "'Link for Extra Info':" in output:
                link_start = output.find("'Link for Extra Info':") + len("'Link for Extra Info': ")
                link_end = output.find(",", link_start) if "," in output[link_start:] else len(output)
                extracted_link = output[link_start:link_end].strip().strip("'\"")

                # Check if the link is valid relative to the base_url
                if extracted_link != "None" and not extracted_link.startswith(url):
                    if not extracted_link.startswith("/"):
                        output = output.replace(f"'{extracted_link}'", "'None'")

                    if are_links_same(extracted_link, doc.metadata.get("source", "")):
                        output = output.replace(f"'{extracted_link}'", "'None'")
            extracted_json = to_json(output)

            doc.set_flag("extracted_info", extracted_json)
        except Exception as e:
            print(f"Error processing document: {e}")
    return documents

def get_relevant_links(document, OPENAI_API_KEY, target_date = datetime(2024, 11, 26).strftime("%d %B %Y")):
    client = OpenAI(api_key=OPENAI_API_KEY)
    links = document.metadata.get("links", "")
    messages = [
        {
            "role": "system",
            "content": ("You are an assistant that helps identify the most relevant link related to vulnerability details, based on specific date {target_date}. Links must be related to more info on vulnerabilities. Just provide the links seperated by commas. without any additional context. If no relevant links are found return nothing."),
        },
        {
            "role": "user",
            "content": f"The following are links to vulnerability details. Please find the most relevant to the date {target_date}.\n\n" +
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
    document.metadata["relevant_links"] = ret_links
    return document

def extract_vulnerability_info(document, OPENAI_API_KEY):
    ret_list = []
    client = OpenAI(api_key=OPENAI_API_KEY)
    matches = re.findall(r"CVE-\d{4}-\d{4,7}", document.page_content)

    # Preserve only unique matches in the order found
    unique_matches = []
    seen = set()

    for match in matches:
        if match not in seen:
            unique_matches.append(match)
            seen.add(match)

    for cve in unique_matches:
        response = client.beta.chat.completions.parse(
            model="gpt-4o-mini",
            messages=[
                {
                    "role": "system",
                    "content": f"You are a cybersecurity assistant that extracts structured vulnerability information from provided content of specific CVE ({cve}) and severity of only Critical or High. Return details of only the provided CVE. Strictly return NOTHING if the severity level is Low, Medium or Important."
                },
                {
                    "role": "user",
                    "content": f"Analyze the following content and extract vulnerability information of {cve} from: {document.page_content}"
                }
            ],
            response_format = AdditionalDetails
        )
        try:
            extracted_data = response.choices[0].message.parsed
            ret_list.append((extracted_data, cve))
        except Exception as e:
            print(f"Error processing document: {e}")
    return ret_list
