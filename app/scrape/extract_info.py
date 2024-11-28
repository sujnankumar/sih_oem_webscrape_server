from openai import OpenAI

def extract_info_from_results(documents, OPENAI_API_KEY):
    client = OpenAI(api_key=OPENAI_API_KEY)  # Replace with your actual API key
    
    extracted_data = []
    for doc in documents:
        # Prepare the prompt for OpenAI API
        messages = [
            {
                "role": "system",
                "content": (
                    "You are a cybersecurity assistant specialized in extracting "
                    "structured information from unstructured text. Extract the following fields "
                    "from the given document: CVE ID, Summary, Severity Level, Date, Product Affected, "
                    "and Link for Extra Info. If any field is missing, use 'None'."
                ),
            },
            {
                "role": "user",
                "content": (
                    f"Document:\n{doc.page_content}\n\n"
                    "Extracted Information Format:\n"
                    "- CVE ID: <CVE-ID>\n"
                    "- Summary: <Short summary>\n"
                    "- Severity Level: <Critical/High/Medium/Low>\n"
                    "- Date: <Date>\n"
                    "- Product Affected: <Product name>\n"
                    "- Link for Extra Info: <URL or 'None'>\n\n"
                    "Please extract the required information."
                ),
            },
        ]



        try:
            response = client.chat.completions.create(
                messages= messages,
                model ="gpt-3.5-turbo",
                temperature= 0,
                max_tokens= 1000
            )
            output = response.choices[0].message.content.strip()
            extracted_data.append({"input_doc": str(doc), "extracted_info": output})
        except Exception as e:
            print(f"Error processing document: {e}")
    
    return extracted_data

