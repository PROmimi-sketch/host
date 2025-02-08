from bs4 import BeautifulSoup
import pandas as pd

# Load the HTML file
file_path = 'index.html'  # Replace with your actual file path
with open(file_path, 'r', encoding='utf-8') as file:
    soup = BeautifulSoup(file, 'html.parser')

# Define categories
categories = ["Banking", "Delivery", "Lottery", "Insurance"]
full_templates = []

# Extract templates for each category
for category in categories:
    # Find all occurrences of the category
    category_sections = soup.find_all(string=lambda text: text and category.lower() in text.lower())
    
    for section in category_sections:
        parent = section.find_parent()  # Get the parent tag for more content
        if parent:
            # Get full text under this section
            full_text = parent.get_text(separator='\n', strip=True)
            full_templates.append({
                "Category": category,
                "Email Body": full_text
            })

# Convert to DataFrame
df = pd.DataFrame(full_templates)

# Save as CSV
df.to_csv('full_email_templates.csv', index=False)
print("✅ CSV file 'full_email_templates.csv' created successfully.")
