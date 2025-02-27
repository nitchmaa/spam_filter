import pandas as pd
import pickle
import re
import string
from nltk.corpus import stopwords
from nltk.stem import PorterStemmer
from sklearn.feature_extraction.text import CountVectorizer, TfidfTransformer
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score

# Download stopwords if not already present
import nltk
nltk.download('stopwords')

# Load dataset and clean it
DATASET_PATH = "spam.csv"
df = pd.read_csv(DATASET_PATH, encoding="latin-1", usecols=[0, 1])  # Select only first two columns
df.columns = ["label", "text"]  # Rename columns

# Remove NaN values
df.dropna(inplace=True)

# Convert labels to binary (spam=1, ham=0)
df["label"] = df["label"].map({"ham": 0, "spam": 1})

# Initialize NLTK tools
stop_words = set(stopwords.words("english"))
stemmer = PorterStemmer()

def preprocess_text(text):
    """Cleans and preprocesses email text."""
    text = text.lower()  # Convert to lowercase
    text = re.sub(r'\d+', '', text)  # Remove numbers
    text = text.translate(str.maketrans("", "", string.punctuation))  # Remove punctuation
    words = text.split()
    words = [stemmer.stem(word) for word in words if word not in stop_words]  # Remove stopwords & stem words
    return " ".join(words)

# Apply preprocessing
df["text"] = df["text"].apply(preprocess_text)

# Split dataset
X_train, X_test, y_train, y_test = train_test_split(df["text"], df["label"], test_size=0.2, random_state=42)

# Use a stronger model: Logistic Regression instead of Naïve Bayes
model = Pipeline([
    ("vect", CountVectorizer()),
    ("tfidf", TfidfTransformer()),
    ("clf", LogisticRegression(solver='liblinear'))
])

# Train model
model.fit(X_train, y_train)

# Evaluate accuracy
y_pred = model.predict(X_test)
print(f"✅ Improved Model Accuracy: {accuracy_score(y_test, y_pred) * 100:.2f}%")

# Save trained model
with open("spam_classifier.pkl", "wb") as f:
    pickle.dump(model, f)

print("✅ Improved model trained and saved as 'spam_classifier.pkl'.")
