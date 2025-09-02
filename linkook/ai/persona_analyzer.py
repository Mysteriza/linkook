# linkook/ai/persona_analyzer.py

import os
from groq import Groq

class PersonaAnalyzer:
    def __init__(self, api_key: str):
        self.client = Groq(api_key=api_key)

    def analyze_persona(self, scan_data: dict) -> str:
        if not scan_data or not scan_data.get("found_accounts"):
            return "Not enough data to analyze."

        system_prompt = """You are a professional OSINT analyst. Your task is to provide a quantitative and informative summary based on the user's scan data. The output must be structured with the following specific sections: 'Age Estimation', 'Location Assessment', 'Online Activity Score', 'Key Interests & Profession', 'Digital Sophistication', and 'Public Exposure Level'. Use simple bullet points for each section, not paragraphs. The tone should be professional and analytical, but use simple words for clarity. Do not use any markdown formatting.

Here are the detailed instructions for each section:
1.  **Age Estimation**: Provide a probable age range.
2.  **Location Assessment**: Estimate the country of origin. If not enough data, state 'Unconfirmed'.
3.  **Online Activity Score**: Calculate a percentage representing the user's digital footprint activity.
4.  **Key Interests & Profession**: List 3-4 probable interests and potential job roles based on platform analysis.
5.  **Digital Sophistication**: Rate as 'Low', 'Moderate', or 'High' with a brief justification (e.g., use of privacy-focused services).
6.  **Public Exposure Level**: Rate as 'Low', 'Moderate', or 'High' based on the number and type of public profiles found.
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
            # Clean up any residual markdown formatting
            cleaned_response = response_text.replace("*", "").replace("#", "")
            return cleaned_response
            
        except Exception as e:
            return f"Failed to generate AI summary: {str(e)}"

    def _format_data_for_prompt(self, scan_data: dict) -> str:
        username = scan_data.get("username", "N/A")
        found_platforms = list(scan_data.get("found_accounts", {}).keys())
        found_usernames = list(scan_data.get("found_usernames", set()))
        found_emails = [email for email, breached in scan_data.get("found_emails", [])]
        
        total_providers_scanned = len(scan_data.get("all_providers", []))

        prompt = f"Analyze the OSINT data for the user '{username}':\n\n"
        prompt += f"Total Platforms Scanned: {total_providers_scanned}\n"
        
        if found_platforms:
            prompt += "Found Platforms:\n"
            prompt += f"- {', '.join(sorted(list(set(found_platforms))))}\n"
        
        if found_usernames:
            related_usernames = [u for u in found_usernames if u.lower() != username.lower()]
            if related_usernames:
                prompt += "\nOther Related Usernames:\n"
                prompt += f"- {', '.join(related_usernames)}\n"

        if found_emails:
            prompt += "\nRelated Emails:\n"
            prompt += f"- {', '.join(found_emails)}\n"
            
        prompt += "\nBased on this data, generate the structured OSINT summary."
        return prompt