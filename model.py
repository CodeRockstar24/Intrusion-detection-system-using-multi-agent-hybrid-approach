# Import libraries
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
from sklearn.utils import resample
import joblib
data = pd.read_csv("data/cleaned_data.csv")
print("Loaded data:", data.shape)
# Split features and label
features = data.drop("Label", axis=1)
labels = data["Label"]
combined = pd.concat([features, labels], axis=1)
# Separate classes
normal_data = combined[combined["Label"] == 0]
attack_data = combined[combined["Label"] == 1]
# Upsample minority class
attack_upsampled = resample(
    attack_data,
    replace=True,
    n_samples=len(normal_data),
    random_state=42
)
# Combine balanced dataset
balanced_data = pd.concat([normal_data, attack_upsampled])
balanced_data = balanced_data.sample(frac=1, random_state=42)
print(balanced_data["Label"].value_counts())
X_balanced = balanced_data.drop("Label", axis=1)
y_balanced = balanced_data["Label"]

X_train, X_test, y_train, y_test = train_test_split(
    X_balanced, y_balanced, test_size=0.2, random_state=42
)

# Train Random Forest classifier
model = RandomForestClassifier(
    n_estimators=80,
    max_depth=10,
    min_samples_split=5,
    random_state=42,
    n_jobs=-1,
    min_samples_leaf=3
)
model.fit(X_train, y_train)
predictions = model.predict(X_test)
print("Accuracy:", accuracy_score(y_test, predictions))
print("Report:\n", classification_report(y_test, predictions))
joblib.dump(model, "models/model.pkl")
print("Model saved.")