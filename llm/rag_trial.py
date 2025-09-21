from dotenv import load_dotenv
from langchain import hub
from langchain.chains.combine_documents import create_stuff_documents_chain
from langchain.chains.retrieval import create_retrieval_chain
from langchain.globals import set_verbose
from langchain_core.tracers import ConsoleCallbackHandler
from langchain_google_genai import ChatGoogleGenerativeAI, GoogleGenerativeAIEmbeddings
from langchain_text_splitters import CharacterTextSplitter
from langchain_community.document_loaders import PyPDFLoader
from langchain_community.vectorstores import FAISS


load_dotenv()

embeddings = GoogleGenerativeAIEmbeddings(model="models/gemini-embedding-001")


def init_doc():
    pdf_path = "rag/manual.pdf"
    loader = PyPDFLoader(file_path=pdf_path)
    documents = loader.load()
    text_splitter = CharacterTextSplitter(
        chunk_size=1000, chunk_overlap=30, separator='\n')
    docs = text_splitter.split_documents(documents)
    for i, doc in enumerate(docs):
        doc.metadata["page_number"] = i + 1
    vector_store = FAISS.from_documents(docs, embeddings)
    vector_store.save_local("rag/faiss")


def load_or_init_vector_store():
    try:

        load_vector_store = FAISS.load_local("rag/faiss", embeddings=embeddings,
                                             allow_dangerous_deserialization=True)
        print("Vector store loaded successfully.")
        return load_vector_store
    except RuntimeError as e:
        init_doc()
        load_vector_store = FAISS.load_local("rag/faiss", embeddings=embeddings,
                                             allow_dangerous_deserialization=True)
        print("Vector store loaded successfully after initialization.")
        return load_vector_store


if __name__ == '__main__':
    local_vector_store = load_or_init_vector_store()
    prompt = hub.pull("langchain-ai/retrieval-qa-chat")
    llm = ChatGoogleGenerativeAI(
        model="gemini-2.0-flash",
        temperature=0,
        max_tokens=None,
        timeout=None,
        max_retries=2
    )
    combine_docs_chain = create_stuff_documents_chain(llm, prompt)
    retrieval_chain = create_retrieval_chain(retriever=local_vector_store.as_retriever(),
                                            combine_docs_chain=combine_docs_chain)
    print("How may I help you?")
    while True:
        user_input = input("Query : ")
        if user_input == "bye":
            break
        result = retrieval_chain.invoke(input={'input': user_input},config={"callbacks": [ConsoleCallbackHandler()]})
        print(result["answer"])
