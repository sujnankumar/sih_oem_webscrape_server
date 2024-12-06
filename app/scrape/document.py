from typing import Any

class Document:
    """Class for storing a piece of text and associated metadata."""

    page_content: str
    contains_listing: bool
    contains_date: bool
    metadata: dict[str, Any]

    def __init__(self, page_content: str, contains_listing: bool = False, contains_date: bool = False, **kwargs: Any) -> None:
        """Initialize the Document with content, metadata, and additional flags."""
        self.page_content = page_content
        self.contains_listing = contains_listing
        self.contains_date = contains_date

        # Ensure metadata is a dictionary and handle lists properly
        metadata = kwargs.get("metadata", {})
        if isinstance(metadata, str):
            raise ValueError("Metadata must be a dictionary, not a string.")
        self.metadata = dict(metadata)

    def __str__(self) -> str:
        """Override __str__ to restrict it to page_content, metadata, and flags."""
        additional_flags = []
        if self.contains_listing:
            additional_flags.append("contains_listing=True")
        if self.contains_date:
            additional_flags.append("contains_date=True")

        flags_str = " " + " ".join(additional_flags) if additional_flags else ""

        if self.metadata:
            return f"page_content='{self.page_content}' metadata={self.metadata}{flags_str}"
        else:
            return f"page_content='{self.page_content}'{flags_str}"