---
description: "Generate phishing infrastructure — clone site, harvest form, deploy server"
agent: redteam
---

Target site to clone and brand: $ARGUMENTS

Generate complete phishing infrastructure:

1. Clone the target website for credential harvesting
2. Generate a credential harvest form that captures username/password
3. Create a capture server script that logs all submissions
4. Generate a phishing email template impersonating the brand
5. Set up tracking pixel for open/click tracking
6. Deploy the phishing server locally

Use the phishing_gen tool for all generation steps. Provide the deployment URL and instructions for external access (ngrok). Include the email template ready to send via GoPhish or SMTP relay.
