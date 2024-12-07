import re
from datetime import datetime
import re
from bs4 import BeautifulSoup
from document import Document
import html2text

today = datetime(2024, 11, 26)
date_formats = [
        '%Y-%m-%d', '%d-%m-%Y', '%m/%d/%Y', '%d/%m/%Y', '%Y %b %d', '%m-%d-%Y',
        '%d %B %Y', '%B %d, %Y', '%b %d, %Y', '%B %Y', '%b %Y'
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
    i = 0
    for doc in documents:
        with open("html_content_{}.txt".format(i), "w", encoding="utf-8") as f:
            f.write(str(doc.page_content))
        print("written html_content_{}.txt".format(i))
        i+=1

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

    def find_relevant_snippets(elements, seen_snippets):
        """Process elements to find relevant snippets based on severity and summary."""
        snippets = []
        print(elements)
        for elem in elements:
            current_elem = elem.parent
            while current_elem:
                text_content = current_elem.get_text(separator=" ").lower()
                contains_severity = any(kw in text_content for kw in severity_keywords)
                contains_summary = any(kw in text_content for kw in summary_keywords)

                if contains_severity:
                    snippet = str(current_elem).strip()
                    if snippet not in seen_snippets:
                        seen_snippets.add(snippet)
                        snippets.append(snippet)
                    if contains_summary:
                        break  # If summary is found, stop traversing up
                current_elem = current_elem.parent
        return snippets

    # Parse the HTML content
    soup = BeautifulSoup(html_content, 'html.parser')

    # Identify elements based on whether we're looking for dates or CVEs
    if not contains_date:
        elements = soup.find_all(string=lambda text: text and contains_today_date(text))
    else:
        elements = soup.find_all(string=lambda text: text and re.search(r"CVE-\d{4}-\d{4,7}", text))

    # Extract snippets
    seen_snippets = set()
    snippets = find_relevant_snippets(elements, seen_snippets)
    print(snippets)
    return snippets


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
                        print(varStart, varEnd)
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
        document = Document(page_content=final_doc, metadata=doc.metadata)
        results.append(document)
    return results