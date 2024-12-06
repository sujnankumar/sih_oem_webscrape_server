from langchain.chains import create_extraction_chain
from langchain_openai import ChatOpenAI
from langchain_text_splitters import RecursiveCharacterTextSplitter


schema = {
    "properties": {
        "date": {"type": "string"},
        "cve": {"type": "string"},
        "impact": {"type": "string"},
        "max_severity": {"type": "string"},
        "more_info_links": {"type": "string"},
        "summary_or_more_info": {"type": "string"},
    },
    "required": ["date", "cve", "max_severity", "summary_or_more_info", "more_info_links"],
}



def extract_content(docs_transformed, api_key):
    schema = {
        "properties": {
            "date": {"type": "string"},
            "cve": {"type": "string"},
            "impact": {"type": "string"},
            "max_severity": {"type": "string"},
            "more_info_links": {"type": "string"},
            "summary_or_more_info": {"type": "string"},
        },
        "required": ["date", "cve", "max_severity", "summary_or_more_info", "more_info_links"],
    }


    llm = ChatOpenAI(temperature=0, model="gpt-4o", api_key=api_key)

    splitter = RecursiveCharacterTextSplitter.from_tiktoken_encoder(
            chunk_size=1000, chunk_overlap=0
    )

    splits = splitter.split_documents(docs_transformed)
    extracted = []
    for spl in splits:
        extracted_content = create_extraction_chain(schema=schema, llm=llm).run(spl.page_content)
        extracted.append(extracted_content)
    return extracted