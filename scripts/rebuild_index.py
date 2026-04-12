from langchain_community.document_loaders import TextLoader
from llm.gateway import get_embeddings
from langchain_text_splitters import CharacterTextSplitter
from langchain_community.vectorstores import FAISS
from dotenv import load_dotenv
import os

# Load environment variables
load_dotenv()

def rebuild_index():
    print("Loading documents...")
    try:
        # Try finding manual.txt in root or db or rag folder
        if os.path.exists("manual.txt"):
            loader = TextLoader("manual.txt")
        elif os.path.exists("db/manual.txt"):
             loader = TextLoader("db/manual.txt")
        elif os.path.exists("llm/rag/manual.pdf"):
             # If pdf exists, try pdf loader, but for now fallback to manual.txt
             print("Found PDF, but looking for manual.txt")
             return
        else:
             print("manual.txt not found")
             return
             
        documents = loader.load()
    except Exception as e:
        print(f"Error loading manual.txt: {e}")
        return

    print("Splitting text...")
    text_splitter = CharacterTextSplitter(chunk_size=1000, chunk_overlap=0)
    docs = text_splitter.split_documents(documents)

    print("Initializing embeddings (Ollama tinyllama)...")
    # Using local Ollama embeddings
    embeddings = get_embeddings()

    print("Creating FAISS index...")
    db = FAISS.from_documents(docs, embeddings)
    
    output_path = "llm/rag/faiss"
    print(f"Saving index to '{output_path}'...")
    db.save_local(output_path)
    print("Index rebuilt successfully!")

if __name__ == "__main__":
    rebuild_index()
