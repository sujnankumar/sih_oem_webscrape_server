from typing import Any

class Document:
    """Class for storing a piece of text and associated metadata."""

    page_content: str
    is_rss: bool
    contains_listing: bool
    contains_date: bool
    contains_details: bool
    metadata: dict[str, Any]
    flags: dict[str, bool]  # Store dynamic flags

    def __init__(self, page_content: str, is_rss=True, contains_listing: bool = False, contains_date: bool = False, contains_details = False, **kwargs: Any) -> None:
        """
        Initialize the Document with content, metadata, and additional flags.

        Args:
            page_content (str): The content of the document.
            contains_listing (bool): Whether the document contains a listing.
            contains_date (bool): Whether the document contains a date.
            **kwargs: Additional metadata or flags.
        """
        self.page_content = page_content
        self.contains_listing = contains_listing
        self.contains_date = contains_date
        self.contains_details = contains_details
        self.is_rss = is_rss
        
        # Handle metadata
        metadata = kwargs.get("metadata", {})
        if isinstance(metadata, str):
            raise ValueError("Metadata must be a dictionary, not a string.")
        self.metadata = dict(metadata)

        # Initialize additional flags
        self.flags = {key: value for key, value in kwargs.items() if key not in {"metadata"}}

    def set_flag(self, flag_name: str, value: bool) -> None:
        """Set a dynamic flag."""
        self.flags[flag_name] = value

    def get_flag(self, flag_name: str) -> bool:
        """Retrieve the value of a dynamic flag."""
        return self.flags.get(flag_name, False)

    def __str__(self) -> str:
        """Override __str__ to include page_content, metadata, and all flags."""
        # Predefined flags
        predefined_flags = []
        if self.contains_listing:
            predefined_flags.append("contains_listing=True")
        if self.contains_date:
            predefined_flags.append("contains_date=True")

        # Dynamic flags
        dynamic_flags = [f"{key}={value}" for key, value in self.flags.items()]

        # Combine all flags
        all_flags = " ".join(predefined_flags + dynamic_flags)
        flags_str = f" {all_flags}" if all_flags else ""

        # Metadata string
        metadata_str = f" metadata={self.metadata}" if self.metadata else ""

        return f"page_content='{self.page_content}'{metadata_str}{flags_str}"
