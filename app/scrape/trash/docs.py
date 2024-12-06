from langchain_community.document_loaders import AsyncChromiumLoader

urls = ["https://msrc.microsoft.com/update-guide/"]
loader = AsyncChromiumLoader(urls)
docs = loader.load()
print(type(docs[0]))
