import pandas as pd
import json
from io import StringIO  # Correct import for StringIO

# File path
file_path = 'C:\\Users\\gumma\\OneDrive\\Desktop\\wb\\full_email_templates.csv'  # Replace with your actual file path

# Step 1: Read the CSV Safely
try:
    # Attempt to read the CSV normally
    df = pd.read_csv(file_path)
except pd.errors.ParserError:
    print("⚠️ Parser error detected. Attempting to fix the file...")

    # Fallback: Read line by line to identify and clean problematic lines
    cleaned_lines = []
    with open(file_path, 'r', encoding='utf-8') as file:
        for i, line in enumerate(file):
            try:
                # Attempt to parse each line separately
                pd.read_csv(StringIO(line))  # ✅ Corrected import
                cleaned_lines.append(line)
            except Exception as e:
                print(f"❌ Error in line {i+1}: {e}. Skipping this line.")

    # Write the cleaned lines to a new temporary CSV
    temp_file_path = 'cleaned_email_templates.csv'
    with open(temp_file_path, 'w', encoding='utf-8') as temp_file:
        temp_file.writelines(cleaned_lines)

    # Re-read the cleaned CSV
    try:
        df = pd.read_csv(temp_file_path)
        print("✅ Cleaned CSV loaded successfully!")
    except pd.errors.EmptyDataError:
        print("❌ No valid data left after cleaning. Please review the original CSV.")
        exit()

# Step 2: Convert to JSONL Format
jsonl_data = [
    {"prompt": f"Generate an email template for {row['Category']}.", "completion": row['Email Body']}
    for _, row in df.iterrows()
]

# Step 3: Save as JSONL
jsonl_file_path = 'email_templates_training_data.jsonl'
with open(jsonl_file_path, 'w', encoding='utf-8') as f:
    for item in jsonl_data:
        f.write(json.dumps(item) + '\n')

print(f"✅ JSONL file '{jsonl_file_path}' created successfully!")
