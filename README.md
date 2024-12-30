# Phishing-Email-Analysis-Challenge

# Phishing Email Analysis Challenge

## 🛠 Challenge Objective
Analyze a suspicious email to determine if it is a phishing attempt using tools like Microsoft Outlook, VirusTotal, and Cisco Talos Intelligence.

---

## 📂 Scenario
An email claiming to be from PayPal in German was provided as a password-protected `.zip` file. The task was to investigate the email, focusing on headers, domain reputation, and embedded URLs.

---

## 🔍 Analysis Steps

### Step 1: Unzip the File
- The challenge provided a password-protected `.zip` file.
- Used the password `infected` to extract the contents, which included an `.eml` file (email format).

### Step 2: Open the Email File
- Used **Microsoft Outlook** to analyze the extracted `.eml` file.
- Translated the German email to English using Microsoft Translate.

### Step 3: Investigate the Return Path
- Accessed email headers via Outlook properties.
- Identified a suspicious return path: `{bounce@rjttznyzjjzydnillquh.designclub.uk.com}`.

### Step 4: Analyze the Email Content
- The email contained a button labeled **"Setzen Sie die Lieferung fort"** (translated: "Continue Delivery").
- Hovered over the button to reveal the URL: `storage.googleapis.com`.
  - Observed that the domain is legitimate, but the URL path included randomized strings, raising suspicion.

### Step 5: Scan the URL in VirusTotal
- Entered the suspicious URL into **VirusTotal**.
- Observations:
  - The URL was flagged as suspicious by multiple detection engines.
  - Opened the **Details** tab in VirusTotal to retrieve the **SHA-256 hash** for documentation.

### Step 6: Check Domain Reputation
- Verified the domain reputation using **Cisco Talos Intelligence** and **VirusTotal**.
- Confirmed that the subdomain was involved in phishing activity.

### Step 7: Retrieve SHA-256 Hash
- From the VirusTotal **Details** tab, obtained the SHA-256 hash of the suspicious URL:  
  `{13945ecc33afee74ac7f72e1d5bb73050894356c4bf63d02a1a53e76830567f5}`.

---

## 🛡️ Conclusion
The email was confirmed to be a phishing attempt based on:
1. A suspicious return path unrelated to PayPal.
2. A legitimate domain (`storage.googleapis.com`) exploited via DNS shadowing.
3. VirusTotal flagged the URL as suspicious, supported by its SHA-256 hash.
4. Community reviews and detection engines identified phishing activity.

---

## 🧰 Tools Used
- **Microsoft Outlook**: Email header analysis.
- **VirusTotal**: URL scanning, hash retrieval, and threat intelligence.
- **Cisco Talos Intelligence**: Domain reputation analysis.

---

## 🖼️ Screenshots
<img width="1470" alt="Screenshot 2024-12-30 at 1 45 46 PM" src="https://github.com/user-attachments/assets/0524edde-383b-4106-ac6c-fd671e4951ab" />
<img width="1470" alt="Screenshot 2024-12-30 at 1 45 28 PM" src="https://github.com/user-attachments/assets/11fd2efb-929f-40a3-a873-54d4e335102a" />
<img width="1470" alt="Screenshot 2024-12-30 at 1 44 41 PM" src="https://github.com/user-attachments/assets/d0a13863-d811-415b-a8fa-
ad9b397e83cf" />
<img width="1470" alt="Screenshot 2024-12-30 at 1 37 16 PM" src="https://github.com/user-attachments/assets/8dc3dd8d-2051-4f39-b655-015221e3fbed" />
<img width="1470" alt="Screenshot 2024-12-30 at 1 41 23 PM" src="https://github.com/user-attachments/assets/3939b435-f7e7-499e-901f-35d4ef139a1e" />
<img width="1470" alt="Screenshot 2024-12-30 at 1 40 26 PM" src="https://github.com/user-attachments/assets/188ead8b-eb04-4a05-bdde-be58a99d8c94" />

<img width="1470" alt="Screenshot 2024-12-30 at 1 40 39 PM" src="https://github.com/user-attachments/assets/a3a37043-f5ac-48cd-b4c9-2827c957adb3" />
## 📎 Resources
- [VirusTotal](https://www.virustotal.com)
- [Cisco Talos Intelligence](https://talosintelligence.com)

---

## 💡 Key Skills Demonstrated
- Phishing detection and analysis.
- Investigating suspicious URLs and return paths.
- Using VirusTotal for detailed threat analysis.
- Retrieving cryptographic hashes for documentation.

