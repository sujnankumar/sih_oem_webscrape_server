from datetime import datetime
import re
from bs4 import BeautifulSoup
from .document import Document
import html2text
import feedparser
import json

today = datetime(2024, 12, 10)
date_formats = [
        '%Y-%m-%d', '%d-%m-%Y', '%m/%d/%Y', '%d/%m/%Y', '%Y %b %d', '%m-%d-%Y',
        '%d %B %Y', '%B %d, %Y', '%b %d, %Y', '%B %Y', '%b %Y', "%d %b %Y"
    ]

def custom_transform(documents):
    for doc in documents:
        soup = BeautifulSoup(doc.page_content, 'html.parser')
        for tag in soup.find_all(True):
            if tag.name == 'a':  # Preserve link-related attributes for <a> tags
                tag.attrs = {key: tag.attrs[key] for key in ['href', 'target'] if key in tag.attrs}
            else:
                tag.attrs = {}  # Clear all attributes
        doc.page_content = soup.prettify()
        soup = BeautifulSoup(doc.page_content, 'html.parser')
        for tag in soup(["style", "head", "footer", "script", "iframe"]):
            tag.decompose()
        doc.page_content = soup.prettify()
        doc.page_content = ''.join(extract_relevant_snippets(doc.page_content, doc.contains_date, ['critical', 'high']))
    
    return transfer_documents(documents)


def extract_relevant_snippets(
    html_content, contains_date, severity_keywords, summary_keywords=["summary", "description"]
):
    from datetime import datetime
    from bs4 import BeautifulSoup
    import re

    global date_formats
    global today

    def contains_today_date(text):
        """Check if the text contains today's date in any of the specified formats."""
        for fmt in date_formats:
            try:
                parsed_date = datetime.strptime(text.strip(), fmt)
                if parsed_date == today:
                    return True
            except ValueError:
                continue
        return False

    def find_relevant_snippets(elements, seen_elements):
        """Process elements to find relevant HTML snippets based on severity and summary."""
        snippets = []
        for elem in elements:
            current_elem = elem.parent
            add_snippet = True  # Flag to determine if this snippet should be added

            while current_elem:
                # If current element is already in seen_elements, skip it
                if current_elem in seen_elements:
                    add_snippet = False
                    break

                # Check text content of the element for severity and summary keywords
                text_content = current_elem.get_text(separator=" ").lower()
                contains_severity = any(kw in text_content for kw in severity_keywords)
                contains_summary = any(kw in text_content for kw in summary_keywords)

                if contains_severity:
                    # Extract the HTML content of the current element
                    snippet_html = str(current_elem).strip()

                    # If this snippet should be added
                    if add_snippet:
                        seen_elements.add(current_elem)  # Mark this element as seen
                        snippets.append(snippet_html)
                        break  # Stop traversing upward, we've added the snippet

                current_elem = current_elem.parent  # Move up to the next parent

        return snippets

    # Parse the HTML content
    soup = BeautifulSoup(html_content, 'html.parser')

    # Identify elements based on whether we're looking for dates or CVEs
    if contains_date:
        elements = soup.find_all(string=lambda text: text and contains_today_date(text))
    else:
        elements = soup.find_all(string=lambda text: text and re.search(r"CVE-\d{4}-\d{4,7}", text))

    # Extract snippets
    seen_snippets = set()
    snippets = find_relevant_snippets(elements, seen_snippets)

    return snippets

def convert_doc_without_cve(document):
    # Extract the page content from the document
    page_content = document.page_content

    if document.is_rss:
        global today
        global date_formats
        feed = feedparser.parse(document.metadata["source"])

            # Dictionary to store entry-wise extracted links
        all_links = set()
        date_patterns = [today.strftime(fmt) for fmt in date_formats]
        date_pattern = re.compile('|'.join(date_patterns))

        for entry in feed.entries:
            if re.search(date_pattern, json.dumps(entry)):
                links = entry.get("link", [])
                if links!=document.metadata["source"]:
                    all_links.add(links)

        document.metadata["links"] = list(all_links)
        document.contains_listing = True
        document.contains_date = True
        return document

    # Define a regex pattern to match month-related text
    global today
    month_formats = ["%B", "%b", "%m"]

    def contains_today_month(text):
        """Check if the text contains the current month and year in any format, regardless of order."""
        month_formats = ["%B", "%b", "%m"]  # Define month formats
        words = text.strip().split()  # Split text into words to process each part
        
        found_month = False  # Flag to track if the current month is found
        found_year = False  # Flag to track if the current year is found
        
        for word in words:
            # Check if the word matches any of the month formats
            for fmt in month_formats:
                try:
                    parsed_month = datetime.strptime(word, fmt)
                    if parsed_month.month == today.month:
                        found_month = True
                except ValueError:
                    continue
            
            try:
                if int(word) == today.year or int(word) == today.day:
                    found_year = True
            except ValueError:
                continue

        # Return True only if both the month and year are found
        return found_month and found_year

    def find_relevant_snippets(elements, seen_elements):
        """Process elements to find relevant HTML snippets based on anchor tags."""
        snippets = []
        links = []
        for elem in elements:
            current_elem = elem.parent
            add_snippet = True

            while current_elem:
                if current_elem in seen_elements:
                    add_snippet = False
                    break

                link_tag = current_elem.find("a", href=True)
                if link_tag:
                    snippet_html = str(current_elem).strip()
                    link_href = link_tag['href']

                    if add_snippet:
                        seen_elements.add(current_elem)
                        snippets.append(snippet_html)
                        links.append(link_href)
                        break
                current_elem = current_elem.parent
        return snippets, links


    soup = BeautifulSoup(page_content, 'html.parser')

    elements = soup.find_all(string=lambda text: text and contains_today_month(text))

    seen_snippets = set()
    snippets, links = find_relevant_snippets(elements, seen_snippets)


    document.metadata["links"] = links
    document.contains_listing = True
    document.contains_date = True

    return document

def convert_doc_with_cve(document):
    # Extract the page content from the document
    page_content = document.page_content
    # Define a regex pattern to match CVE references
    cve_pattern = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)

    def contains_cve(text):
        """Check if the text contains any CVE references."""
        return bool(cve_pattern.search(text))

    def find_relevant_snippets(elements, seen_elements):
        """Process elements to find relevant HTML snippets based on anchor tags."""
        snippets = []
        links = []
        for elem in elements:
            current_elem = elem.parent
            add_snippet = True

            while current_elem:
                if current_elem in seen_elements:
                    add_snippet = False
                    break

                link_tag = current_elem.find("a", href=True)
                if link_tag:
                    snippet_html = str(current_elem).strip()
                    link_href = link_tag['href']

                    if add_snippet:
                        seen_elements.add(current_elem)
                        snippets.append(snippet_html)
                        links.append(link_href)
                        break
                current_elem = current_elem.parent
        return snippets, links

    soup = BeautifulSoup(page_content, 'html.parser')

    elements = soup.find_all(string=lambda text: text and contains_cve(text))

    seen_snippets = set()
    snippets, links = find_relevant_snippets(elements, seen_snippets)

    document.metadata["links"] = links
    document.contains_listing = True
    document.contains_cve = True

    return document


def custom_html_to_text(documents):
    html_to_text = html2text.HTML2Text()
    html_to_text.ignore_links = False
    html_to_text.ignore_images = True
    for doc in documents:
        doc.page_content = html_to_text.handle(doc.page_content)
    return documents

def transfer_documents(documents):
    html_to_text = html2text.HTML2Text()
    html_to_text.ignore_links = False
    html_to_text.ignore_images = True
    
    global today
    global date_formats
    
    date_patterns = [today.strftime(fmt) for fmt in date_formats]

    date_pattern = re.compile('|'.join(date_patterns))
    cve_pattern = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)
    
    results = []
    
    for doc in documents:
        doc.page_content = html_to_text.handle(doc.page_content)
        pattern = date_pattern if doc.contains_date else cve_pattern
        lines = doc.page_content.split('\n')
        cleaned_lines = [line for line in lines if re.search(r'\w', line)]
        
        processed_ranges = []
        
        for i, line in enumerate(cleaned_lines):
            if pattern.search(line):
                start = max(0, i - 15)
                end = min(len(cleaned_lines), i + 16)
                context = '\n'.join(cleaned_lines[start:end])

                if re.search(r'\bcritical\b', context, re.IGNORECASE) or re.search(r'\bhigh\b', context, re.IGNORECASE):
                    f=1
                    idx = 0
                    for varStart, varEnd in processed_ranges:
                        if ((varStart<=start) and (start<=end)) or ((start<=varStart) and (varStart<=end)):
                            processed_ranges[idx]=(min(varStart, start), max(varEnd, end))
                            f=0
                            break
                        idx+=1
                    if f:
                        processed_ranges.append((start, end))
        final_doc = ""
        for varStart, varEnd in processed_ranges:  # Combine the relevant snippets
            final_doc += '\n'.join(cleaned_lines[varStart:varEnd])
            final_doc = final_doc + "\n" + "="*50 + "\n"

        document = Document(page_content=final_doc, metadata=doc.metadata, contains_listing=doc.contains_listing, contains_date=doc.contains_date, contains_details=doc.contains_details)
        results.append(document)
    return results