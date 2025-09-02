# linkook/ai/persona_analyzer.py

import os
import json
import re
from groq import Groq

class PersonaAnalyzer:
    def __init__(self, api_key: str):
        self.client = Groq(api_key=api_key)

    def analyze_persona(self, scan_data: dict) -> str:
        if not scan_data or not scan_data.get("found_accounts"):
            return "Not enough data to analyze."

        system_prompt = """You are a professional OSINT analyst. Your task is to provide a detailed, structured analysis based on the user's scan data. The output must be structured with the following specific sections: 'Identity Assessment', 'Digital Footprint', and 'Behavioral Analysis'. Use simple bullet points, not paragraphs. The tone must be professional and analytical. Do not use any markdown formatting such as using asterisk symbols.

Here are the detailed instructions for each section:
1.  Identity Assessment:
    -   Verified Full Name: State the most probable full name. If names are inconsistent across platforms or not found, state 'Unconfirmed'.
    -   Probable Age Range: Estimate an age range based on platform usage.
    -   Probable Location: Estimate the country. If not enough data, state 'Unconfirmed'.

2.  Digital Footprint:
    -   Cross-Verification Confidence: Give a confidence score (e.g., High, Moderate, Low) that the accounts belong to the same person, based on consistency in bios and full names.
    -   Public Exposure Level: Rate as 'Low', 'Moderate', or 'High' based on the amount of public information.
    -   Digital Sophistication: Rate as 'Low', 'Moderate', or 'High' and justify (e.g., use of privacy-focused services like Proton Mail indicates higher sophistication).

3.  Behavioral Analysis:
    -   Key Interests: List 3-5 primary interests extracted directly from bios or inferred from platform types (e.g., GitHub -> Technology).
    -   Probable Profession: Suggest 1-2 likely professions based on all available data.
"""
        
        formatted_data = self._format_data_for_prompt(scan_data)

        try:
            chat_completion = self.client.chat.completions.create(
                messages=[
                    {
                        "role": "system",
                        "content": system_prompt
                    },
                    {
                        "role": "user",
                        "content": formatted_data,
                    }
                ],
                model="llama-3.1-8b-instant",
            )
            
            response_text = chat_completion.choices[0].message.content
            # Membersihkan markdown dan simbol bullet yang tidak diinginkan
            cleaned_response = re.sub(r"^\s*[\*\-•+]\s*", "", response_text, flags=re.MULTILINE)
            return cleaned_response
            
        except Exception as e:
            return f"Failed to generate AI summary: {str(e)}"

    def _format_data_for_prompt(self, scan_data: dict) -> str:
        username = scan_data.get("username", "N/A")
        found_platforms = list(scan_data.get("found_accounts", {}).keys())
        found_usernames = list(scan_data.get("found_usernames", set()))
        found_emails = [email for email, breached in scan_data.get("found_emails", [])]
        extracted_data = scan_data.get("extracted_data", {})

        prompt = f"Analyze the OSINT data for the user '{username}':\n\n"
        
        prompt += "--- Aggregated Data ---\n"
        if found_platforms:
            prompt += f"Platforms Found: {', '.join(sorted(list(set(found_platforms))))}\n"
        
        related_usernames = [u for u in found_usernames if u.lower() != username.lower()]
        if related_usernames:
            prompt += f"Other Usernames: {', '.join(related_usernames)}\n"

        if found_emails:
            prompt += f"Emails: {', '.join(found_emails)}\n"
        
        prompt += "\n--- Detailed Profile Data ---\n"
        if not extracted_data:
            prompt += "No detailed profile data was extracted.\n"
        else:
            for platform, data in extracted_data.items():
                details = ', '.join([f"{key}: {value}" for key, value in data.items()])
                prompt += f"- {platform}: {details}\n"
            
        prompt += "\nBased on all this data, generate the structured OSINT summary."
        return prompt