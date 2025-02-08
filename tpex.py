import google.generativeai as genai
import os
import re
import nltk
import pandas as pd
from textblob import TextBlob
from io import StringIO
import json

nltk.download('punkt')

# Initialize Gemini API Key
genai.configure(api_key="AIzaSyALBrWQdEEhdZTtDHtvO8gGjTEeRigRWjM")

# Function to clean and analyze text
def clean_and_analyze_text(text):
    """Cleans input text and ensures professional tone."""
    text = re.sub(r'[^\x00-\x7F]+', ' ', text)  # Remove non-ASCII characters
    text = re.sub(r'\s+', ' ', text).strip()  # Remove extra whitespace
    sentiment = TextBlob(text).sentiment

    if sentiment.polarity < -0.2:
        if sentiment.subjectivity > 0.5:
            text = "This content might be too subjective. Consider making it more objective. " + text
    
    return text

# Function to clean unwanted phrases
def clean_unwanted_phrases(text):
    """Remove unwanted phrases related to links."""
    unwanted_phrases = ["Phishing Awareness", "phishing awareness", "cyberguard", "nithin1207v", "ngit.cyberguard"]

    for phrase in unwanted_phrases:
        pattern = rf'(?<!href=")\b{re.escape(phrase)}\b(?!")'
        text = re.sub(pattern, '', text, flags=re.IGNORECASE)

    text = re.sub(r'\s+', ' ', text).strip()  # Clean extra spaces
    return text

# Function to train the LLM with extracted templates
def train_llm_with_templates(file_path='full_email_templates.csv'):
    df = pd.read_csv('full_email_templates.csv')

    model = genai.GenerativeModel("gemini-1.5-flash-8b")
    training_data = ""

    for _, row in df.iterrows():
        training_data += f"Category: {row['Category']}\nEmail Body: {row['Email Body']}\n\n"

    return model, training_data

# Email prompt template
email_prompt_template = """
You are a highly skilled professional email designer, known for creating detailed and comprehensive HTML email templates. Each email should meet the following criteria:

### Email Specifications:
1. **HTML Structure**:
    - Use `<html>`, `<head>`, and `<body>` tags for each email.
    - Include design elements like `<div>`, `<table>`, `<ul>`, and `<img>` for variety.
    - Apply inline or embedded CSS for polished styling.
    - **Avoid any phishing-like language or overly urgent messaging.**
    
    - **Do not include company logos, branding banners, or any placeholder images.**
2. **Content**:
*Use a neutral, professional, and friendly tone.**
    - Write a **large, detailed body** with at least 500 words or 5 paragraphs.
    - Start with a professional greeting: "Dear {recipient},"
    - Expand the main body with context, explanations, and engaging details.
    - **Do not add any generic branding elements such as "Company Logo" at the top.**
    - Include elements like bullet points or tables where appropriate.
     Include useful details in a **helpful, reassuring** way.
**Call-to-Action:**
    - If a CTA is needed, **use soft language**, such as:
      - `"Visit Our Website"` instead of `"Click Here to Confirm"`
      - `"Check Your Account Settings"` instead of `"Update Your Information"`
    - Ensure all links redirect to: **https://teamy-labs.github.io/phishing-awareness/**
4. **Signature**:
    - End with a professional closing: "Sincerely," followed by "[Your Name], [Your Position]."
5. **No Placeholders**:
    - Each email should be a complete and stand-alone HTML template.
    - **Ensure no unnecessary placeholders such as "Company Logo" appear anywhere in the email.**
6. **Important Restrictions**:
    - **DO NOT** include explanations, analysis, or additional commentary after the email body.
    - **DO NOT** add any "Explanation of Changes" or security notes at the end.
    - The email must **end with the signature** and **nothing else**.
### Task:
Generate exactly 1 complete email template in HTML format for the following details:
- **Subject**: {subject}
- **Purpose**: {purpose}
- **Recipient**: {recipient}

Ensure the template is professional, detailed, and aligns with the provided input details.
"""
def modify_email_links(email_body, email_id):
    """Dynamically replace the phishing-awareness URL with userID"""
    user_id = email_id.split('@')[0]
    updated_email_body = email_body.replace(
        'https://teamy-labs.github.io/phishing-awareness/', 
        f'https://teamy-labs.github.io/phishing-awareness-/?id={user_id}'
    )
    return updated_email_body






# Function to generate email templates based on trained model
import concurrent.futures

def generate_templates(model, training_data, category, email_addresses):
    """Generates 5 email templates per prompt using the trained LLM in parallel."""

    category_prompts = {
        "Banking": [
            ("Verify Your Account Details to Avoid Disruption", "To ensure account continuity by prompting verification.", "Customer"),
            ("Your Bank Statement is Ready for Download", "To inform the recipient about their account statement availability.", "Customer"),
            ("New Security Alert: Confirm Your Login Activity", "To notify the recipient about unusual login activity.", "Customer")
        ],
        "Healthcare": [
            ("Important Update About Your Health Records", "To notify patients of changes in their health information.", "Patient"),
            ("Upcoming Appointment Reminder", "To remind patients of scheduled appointments.", "Patient"),
            ("Health Tips for a Better Lifestyle", "To provide useful health advice and wellness tips.", "Patient")
        ],
        "Retail": [
            ("Exclusive Offers Just for You!", "To promote special discounts and offers.", "Customer"),
            ("Your Order Has Been Shipped", "To confirm shipment of a customer's order.", "Customer"),
            ("New Arrivals: Check Out the Latest Trends", "To inform customers about new products.", "Customer")
        ],
        "Technology": [
            ("Your Subscription Renewal Notice", "To remind users about upcoming subscription renewals.", "User"),
            ("New Software Update Available", "To notify users of the latest software updates.", "User"),
            ("Join Our Tech Webinar for Free", "To invite users to attend a technology-related webinar.", "User")
        ],
        "Education": [
            ("Upcoming Semester Enrollment Reminder", "To remind students to enroll for the next semester.", "Student"),
            ("Important Exam Schedule Update", "To notify students about changes in the exam schedule.", "Student"),
            ("Scholarship Opportunities You Shouldn't Miss", "To inform students about available scholarships.", "Student")
        ]
    }

    if category not in category_prompts:
        print(f"❌ Error: No prompts found for category '{category}'")
        return {}

    print(f"🚀 Generating email templates for category: {category}")

    emails = {email: [] for email in email_addresses}

    def generate_email(email,subject, purpose, recipient):
        """Helper function to generate multiple emails in parallel."""
        try:
            prompt = email_prompt_template.format(subject=subject, purpose=purpose, recipient=recipient)
            prompt = f"Based on the following training data:\n{training_data}\n{prompt}"

            print(f"🛠️ Generating email for: {subject}")

            result = model.generate_content([prompt])
            if not hasattr(result, 'text') or not result.text:
                print(f"❌ Error: Model returned empty response for {subject}")
                return None

            email_body = result.text.strip()
            email_body = clean_and_analyze_text(email_body)
            email_body = clean_unwanted_phrases(email_body)

            email_body = modify_email_links(email_body, email)

            return email,subject, email_body

        except Exception as e:
            print(f"❌ Error generating template for {subject}: {e}")
            return None

    # ✅ Use ThreadPoolExecutor to process templates in parallel
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        future_to_email = {
            executor.submit(generate_email,email, subject, purpose, recipient): email
            for email in email_addresses
            for subject, purpose, recipient in category_prompts[category]
            
        }

        for future in concurrent.futures.as_completed(future_to_email):
            result = future.result()
            if result:
                email, subject, body = result
                emails[email].append((subject, body))  # ✅ Ensures correct mapping

    # print(f"✅ Successfully generated {sum(len(templates) for templates in emails.values())} email templates.")
    return emails
