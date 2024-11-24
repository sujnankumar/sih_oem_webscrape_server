from langchain_community.document_transformers import Html2TextTransformer
import re
from typing import Any, Literal

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

def transfer_documents(documents):
    html2text = Html2TextTransformer()
    docs_transformed = html2text.transform_documents(documents)
    
    # Define the pattern to search for CVE-2024-xxxx and the words "high" or "critical"
    cve_pattern = re.compile(r'CVE-2024-\d{4}')
    severity_pattern = re.compile(r'\b(high|critical)\b', re.IGNORECASE)
    
    results = []
    
    for doc in docs_transformed:
        # Split the document content into lines
        lines = doc.page_content.split('\n')
        
        # Remove lines with just whitespace or random characters
        cleaned_lines = [line for line in lines if re.search(r'\w', line)]
        
        for i, line in enumerate(cleaned_lines):
            if cve_pattern.search(line) and severity_pattern.search(line):
                # Extract 2 lines before and 2 lines after the found pattern
                start = max(0, i - 2)
                end = min(len(cleaned_lines), i + 3)
                context = '\n'.join(cleaned_lines[start:end])
                document =  Document(page_content=context, metadata=doc.metadata)
                results.append(document)
    
    return results