import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
import joblib

print("1. Loading dataset...")
df = pd.read_csv('url_data.csv') 

if len(df) > 100000:
    df = df.sample(n=100000, random_state=42)

df = df.dropna(subset=['label', 'url'])

# Let's print out the cheat sheet to see how imbalanced your data really is!
print("\n--- Data Balance Check ---")
print(df['label'].value_counts())
print("--------------------------\n")

print("2. Extracting Live Features from URLs...")
def get_live_features(url):
    url = str(url).lower()
    
    # Let's add a few more fast features so the AI is smarter
    length = len(url)
    dots = url.count('.')
    hyphens = url.count('-')
    has_https = 1 if "https" in url else 0
    has_bad_words = 1 if any(w in url for w in ['login', 'update', 'free', 'verify', 'bank', 'secure', 'account']) else 0
    slashes = url.count('/')
    
    return [length, dots, hyphens, has_https, has_bad_words, slashes]

X = df['url'].apply(get_live_features).tolist()
y = df['label'].tolist()

print("3. Training the New Live AI Model...")
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# THE MAGIC FIX: class_weight='balanced' forces the AI to care about the rare malicious links!
model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1, class_weight='balanced')
model.fit(X_train, y_train)

print(f"--> Live AI Overall Accuracy: {accuracy_score(y_test, model.predict(X_test)) * 100:.2f}%\n")

# This will show us if it's actually catching the 1s (malicious) now
print("Detailed AI Report Card:")
print(classification_report(y_test, model.predict(X_test)))

print("\n4. Saving the Brain...")
joblib.dump(model, 'url_model.pkl')
print("Done! Restart app.py")