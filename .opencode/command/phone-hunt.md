---
description: "Phone number OSINT — carrier, location, social profiles, breach data"
agent: redteam
---

Phone number: $ARGUMENTS

Execute full phone number intelligence pipeline:

1. Carrier lookup — identify the carrier, line type (mobile/landline/VOIP), country
2. Geographic location — approximate region/city from area code and country code
3. Social media cross-reference — check WhatsApp, Telegram, Truecaller, Signal, Viber
4. Username hunt — try the phone number as username across 500+ platforms (Sherlock/Maigret)
5. Breach database search — check HaveIBeenPwned, IntelX, LeakCheck, Dehashed for accounts linked to this number
6. Chain intelligence — if emails discovered from breach data, search those emails for leaked passwords
7. Social profile deep dive — for any discovered profiles, extract location data, habits, relationships
8. Physical location estimation — combine area code, social media check-ins, EXIF data from photos

Use phone_lookup, social_profile, and darkweb_search tools. Build a complete intelligence profile on the phone number owner. Report carrier, location, all associated accounts, and any leaked credentials.
