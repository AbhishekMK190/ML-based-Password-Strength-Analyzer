# import pandas as pd
# from sklearn.ensemble import RandomForestClassifier
# from sklearn.model_selection import train_test_split
# from sklearn.metrics import accuracy_score
# import joblib

# # Step 1: Load the existing labeled data
# labeled_data_path = r"C:\Users\hat94\Desktop\ML based Password Strength Analyzer\Labeled_data.csv"
# labeled_data = pd.read_csv(labeled_data_path)

# # Step 2: Load the list of common passwords from 'common_passwords.csv'
# def load_common_passwords(file_path):
#     try:
#         common_passwords = pd.read_csv(file_path, usecols=[0]).dropna().iloc[:, 0].unique()
#         print(f"Loaded {len(common_passwords)} common passwords.")
#         return pd.DataFrame({'password': common_passwords, 'strength_label': 'weak'})  # Label common passwords as 'weak'
#     except Exception as e:
#         print(f"Error loading common passwords: {str(e)}")
#         return pd.DataFrame(columns=['password', 'strength_label'])

# # Load common passwords and label them as weak
# common_passwords_path = r"C:\Users\hat94\Desktop\ML based Password Strength Analyzer\common_passwords.csv"
# common_password_data = load_common_passwords(common_passwords_path)

# # Step 3: Append the common passwords data to the original labeled data
# labeled_data = pd.concat([labeled_data, common_password_data], ignore_index=True).drop_duplicates(subset=['password'])

# # Step 4: Add feature extraction columns based on password characteristics
# labeled_data['password'] = labeled_data['password'].fillna('')  # Replace NaN values with empty strings
# labeled_data['length'] = labeled_data['password'].apply(len)
# labeled_data['has_uppercase'] = labeled_data['password'].apply(lambda x: any(char.isupper() for char in x))
# labeled_data['has_lowercase'] = labeled_data['password'].apply(lambda x: any(char.islower() for char in x))
# labeled_data['has_digits'] = labeled_data['password'].apply(lambda x: any(char.isdigit() for char in x))
# labeled_data['has_special'] = labeled_data['password'].apply(lambda x: any(not char.isalnum() for char in x))
# labeled_data['has_unique_chars'] = labeled_data['password'].apply(lambda x: len(set(x)))
# labeled_data['has_entropy'] = labeled_data['password'].apply(lambda x: sum(ord(char) for char in set(x)) / len(x) if len(x) > 0 else 0)
# labeled_data['has_sequential'] = labeled_data['password'].apply(lambda x: any(x[i] == x[i+1] for i in range(len(x)-1)))
# labeled_data['has_repetition'] = labeled_data['password'].apply(lambda x: len(x) > len(set(x)))
# labeled_data['is_common_password'] = labeled_data['password'].apply(lambda x: x in common_password_data['password'].values)

# # Define features and target
# X = labeled_data[['length', 'has_uppercase', 'has_lowercase', 'has_digits', 'has_special', 
#                   'has_unique_chars', 'has_entropy', 'has_sequential', 'has_repetition', 'is_common_password']]
# y = labeled_data['strength_label']

# # Step 5: Split the data into training and testing sets
# X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# # Step 6: Initialize and train the new Random Forest model
# model = RandomForestClassifier(random_state=42, n_estimators=100, max_depth=10)
# model.fit(X_train, y_train)

# # Step 7: Evaluate and save the model
# y_pred = model.predict(X_test)
# accuracy = accuracy_score(y_test, y_pred) * 100
# print(f"Model retrained. Test accuracy: {accuracy:.2f}%")

# # Save the retrained model
# model_save_path = r"C:\Users\hat94\Desktop\ML based Password Strength Analyzer\NewModelRF_V4.joblib"
# joblib.dump(model, model_save_path)
# print(f"Model saved as '{model_save_path}'.")

# # Function to assess password strength with the new model
# def assess_password_strength(password):
#     features = {
#         'length': len(password),
#         'has_uppercase': any(char.isupper() for char in password),
#         'has_lowercase': any(char.islower() for char in password),
#         'has_digits': any(char.isdigit() for char in password),
#         'has_special': any(not char.isalnum() for char in password),
#         'has_unique_chars': len(set(password)),
#         'has_entropy': sum(ord(char) for char in set(password)) / len(password) if len(password) > 0 else 0,
#         'has_sequential': any(password[i] == password[i+1] for i in range(len(password)-1)),
#         'has_repetition': len(password) > len(set(password)),
#         'is_common_password': password in common_password_data['password'].values
#     }
#     features_df = pd.DataFrame([features])
#     predicted_strength = model.predict(features_df)[0]
#     print(f"The assessed strength of the password is: {predicted_strength}")
#     return predicted_strength

# # Test the function with an example password
# test_password = "Qwerty" 
# assess_password_strength(test_password)

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import joblib

# Step 1: Load the existing labeled data
labeled_data_path = r"C:\Users\hat94\Desktop\ML based Password Strength Analyzer\Labeled_data.csv"
labeled_data = pd.read_csv(labeled_data_path)

# Step 2: Load the list of common passwords from 'common_passwords.csv'
def load_common_passwords(file_path):
    try:
        common_passwords = pd.read_csv(file_path, usecols=[0]).dropna().iloc[:, 0].unique()
        print(f"Loaded {len(common_passwords)} common passwords.")
        return pd.DataFrame({'password': common_passwords, 'strength_label': 'weak'})  # Label common passwords as 'weak'
    except Exception as e:
        print(f"Error loading common passwords: {str(e)}")
        return pd.DataFrame(columns=['password', 'strength_label'])

# Load common passwords and label them as weak
common_passwords_path = r"C:\Users\hat94\Desktop\ML based Password Strength Analyzer\common_passwords.csv"
common_password_data = load_common_passwords(common_passwords_path)

# Step 3: Append the common passwords data to the original labeled data
labeled_data = pd.concat([labeled_data, common_password_data], ignore_index=True).drop_duplicates(subset=['password'])

# Step 4: Add feature extraction columns based on password characteristics
labeled_data['password'] = labeled_data['password'].fillna('')  # Replace NaN values with empty strings
labeled_data['length'] = labeled_data['password'].apply(len)
labeled_data['has_uppercase'] = labeled_data['password'].apply(lambda x: any(char.isupper() for char in x))
labeled_data['has_lowercase'] = labeled_data['password'].apply(lambda x: any(char.islower() for char in x))
labeled_data['has_digits'] = labeled_data['password'].apply(lambda x: any(char.isdigit() for char in x))
labeled_data['has_special'] = labeled_data['password'].apply(lambda x: any(not char.isalnum() for char in x))
labeled_data['has_unique_chars'] = labeled_data['password'].apply(lambda x: len(set(x)))
labeled_data['has_entropy'] = labeled_data['password'].apply(lambda x: sum(ord(char) for char in set(x)) / len(x) if len(x) > 0 else 0)
labeled_data['has_sequential'] = labeled_data['password'].apply(lambda x: any(x[i] == x[i+1] for i in range(len(x)-1)))
labeled_data['has_repetition'] = labeled_data['password'].apply(lambda x: len(x) > len(set(x)))
labeled_data['is_common_password'] = labeled_data['password'].apply(lambda x: x in common_password_data['password'].values)

# Define features and target
X = labeled_data[['length', 'has_uppercase', 'has_lowercase', 'has_digits', 'has_special', 
                  'has_unique_chars', 'has_entropy', 'has_sequential', 'has_repetition', 'is_common_password']]
y = labeled_data['strength_label']

# Step 5: Split the data into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Step 6: Initialize and train the new Random Forest model
model = RandomForestClassifier(random_state=42, n_estimators=100, max_depth=10)
model.fit(X_train, y_train)

# Step 7: Evaluate and save the model
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred) * 100
print(f"Model retrained. Test accuracy: {accuracy:.2f}%")

# Save the retrained model
model_save_path = r"C:\Users\hat94\Desktop\ML based Password Strength Analyzer\NewModelRF_V4.joblib"
joblib.dump(model, model_save_path)
print(f"Model saved as '{model_save_path}'.")

# Function to assess password strength with the new model
def assess_password_strength(password):
    features = {
        'length': len(password),
        'has_uppercase': any(char.isupper() for char in password),
        'has_lowercase': any(char.islower() for char in password),
        'has_digits': any(char.isdigit() for char in password),
        'has_special': any(not char.isalnum() for char in password),
        'has_unique_chars': len(set(password)),
        'has_entropy': sum(ord(char) for char in set(password)) / len(password) if len(password) > 0 else 0,
        'has_sequential': any(password[i] == password[i+1] for i in range(len(password)-1)),
        'has_repetition': len(password) > len(set(password)),
        'is_common_password': password in common_password_data['password'].values
    }
    features_df = pd.DataFrame([features])
    predicted_strength = model.predict(features_df)[0]
    print(f"The assessed strength of the password is: {predicted_strength}")
    return predicted_strength

# Test the function with an example password
test_password = "AbhishekMK123#" 
assess_password_strength(test_password)

import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import classification_report, confusion_matrix

# Step 1: Confusion Matrix
def plot_confusion_matrix(y_true, y_pred):
    cm = confusion_matrix(y_true, y_pred, labels=model.classes_)
    plt.figure(figsize=(8, 6))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=model.classes_, yticklabels=model.classes_)
    plt.xlabel('Predicted')
    plt.ylabel('Actual')
    plt.title('Confusion Matrix')
    plt.show()

print("Confusion Matrix:")
plot_confusion_matrix(y_test, y_pred)

# Step 2: Classification Report
print("Classification Report:")
print(classification_report(y_test, y_pred, target_names=model.classes_))

# Step 3: Feature Importance
def plot_feature_importance(model, feature_names):
    importance = model.feature_importances_
    sorted_idx = importance.argsort()
    plt.figure(figsize=(10, 8))
    plt.barh([feature_names[i] for i in sorted_idx], importance[sorted_idx], color='teal')
    plt.xlabel('Feature Importance')
    plt.ylabel('Feature')
    plt.title('Feature Importance of the Random Forest Model')
    plt.show()

print("Feature Importance:")
plot_feature_importance(model, X.columns)

# Step 4: Training vs Testing Accuracy Curve
train_sizes = range(1, len(X_train), max(1, len(X_train) // 10))
train_scores = []
test_scores = []

for size in train_sizes:
    model.fit(X_train[:size], y_train[:size])
    train_scores.append(model.score(X_train[:size], y_train[:size]))
    test_scores.append(model.score(X_test, y_test))

plt.figure(figsize=(10, 6))
plt.plot(train_sizes, train_scores, label='Training Accuracy', marker='o')
plt.plot(train_sizes, test_scores, label='Testing Accuracy', marker='o')
plt.xlabel('Training Data Size')
plt.ylabel('Accuracy')
plt.title('Training vs Testing Accuracy')
plt.legend()
plt.grid()
plt.show()
