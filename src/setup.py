import nltk

def download_nltk_data():
    """Download required NLTK data"""
    print("Downloading NLTK data...")
    nltk.download('punkt')
    nltk.download('averaged_perceptron_tagger')
    nltk.download('maxent_ne_chunker')
    nltk.download('words')
    print("NLTK data download complete!")

if __name__ == "__main__":
    download_nltk_data() 