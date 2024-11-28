from langchain_community.document_transformers import Html2TextTransformer
import re
from typing import Any, Literal
from datetime import datetime

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
    
    # Get today's date in different formats
    today = datetime(2024, 11, 12)
    date_patterns = [
        today.strftime(r'%Y-%m-%d'),   # 2024-01-01
        today.strftime(r'%d-%m-%Y'),   # 01-01-2024
        today.strftime(r'%m-%d-%Y'),   # 01-01-2024
        today.strftime(r'%d/%m/%Y'),   # 01/01/2024
        today.strftime(r'%m/%d/%Y'),   # 01/01/2024
        today.strftime(r'%d %B %Y'),   # 01 January 2024
        today.strftime(r'%B %d, %Y'),  # January 01, 2024
        today.strftime(r'%b %d, %Y'),  # Jan 01, 2024
    ]
    
    # Compile the date patterns into a single regex pattern
    date_pattern = re.compile('|'.join(date_patterns))
    
    results = []
    
    for doc in docs_transformed:
        # Split the document content into lines
        lines = doc.page_content.split('\n')
        
        # Remove lines with just whitespace or random characters
        cleaned_lines = [line for line in lines if re.search(r'\w', line)]
        
        # To track ranges already processed
        processed_ranges = []
        
        for i, line in enumerate(cleaned_lines):
            if date_pattern.search(line):
                # Determine the range of lines to include (±15 lines)
                start = max(0, i - 15)
                end = min(len(cleaned_lines), i + 15)
                
                # Check if this range overlaps with any previously processed range
                overlap = any(start <= r_end and end >= r_start for r_start, r_end in processed_ranges)
                
                if not overlap:
                    # Extract the context and add to results
                    context = '\n'.join(cleaned_lines[start:end])
                    document = Document(page_content=context, metadata=doc.metadata)
                    results.append(document)
                    
                    # Mark this range as processed
                    processed_ranges.append((start, end))
                
                # Additional check for "critical" or "high"
                if re.search(r'\bcritical\b', context, re.IGNORECASE) or re.search(r'\bhigh\b', context, re.IGNORECASE):
                    document = Document(page_content=context, metadata=doc.metadata)
                    results.append(document)
    
    return results
