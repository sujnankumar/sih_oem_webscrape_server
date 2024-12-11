from pydantic import BaseModel, Field
from typing import List, Optional, Dict

# Define the schema for the expected vulnerability data
class AdditionalDetails(BaseModel):
    CVE_ID: Optional[str] = Field(None, alias="CVE ID")
    Summary: Optional[str] = None
    Remediation: Optional[str] = None   
    Severity_Level: Optional[str] = Field(None, alias="Severity Level")
    Affected_Products_with_Version: Optional[List[str]] = Field(None, alias="Affected Products with Version")
    Impact_or_Exploitation: Optional[str] = Field(None, alias="Impact or Exploitation")
    Vulnerability_Type: Optional[str] = Field(None, alias="Vulnerability Type")
    CVSS_Base_Score: Optional[str] = Field(None, alias="CVSS Base Score")
    References: Optional[List[str]] = None
    Vendor: Optional[str] = Field(None, alias="Vendor")
    Other_Relevant_Info: Optional[str] = Field(None, alias="Other Relevant Info")

class Vulnerability(BaseModel):
    CVE_ID: Optional[str] = Field(None, alias="CVE ID")
    Severity_Level: Optional[str] = Field(None, alias="Severity Level")
    Summary: Optional[str] = None
    Affected_Products_with_Version: Optional[List[str]] = Field(None, alias="Affected Products with Version")
    Published_Date: Optional[str] = Field(None, alias="Published Date")
    Remediation: Optional[str] = None
    Link_for_Extra_Info: Optional[str] = Field(None, alias="Link for Extra Info")

class Link(BaseModel):
    Link_for_Extra_Info: Optional[str] = Field(None, alias="Link for Extra Info")