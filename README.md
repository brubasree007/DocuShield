# 🛡️ DocuShield — AI-Powered Document Forgery Detection Platform

> An enterprise-grade forensic document verification system utilizing **Computer Vision**, **Error Level Analysis (ELA)**, **EXIF & PDF Metadata Forensics**, **OCR Text Extraction**, and **Groq AI Neural Audit** to detect tampered, forged, or manipulated documents with high precision.

---

## 🌟 Overview

Modern document fraud is becoming increasingly sophisticated with digital image editors, synthetic generation, and copy-paste manipulation. **DocuShield** provides organizations—including banks, HR departments, academic institutions, and legal firms—with a unified, multi-layered forensic pipeline to automatically verify certificate, ID, and statement authenticity in seconds.

---

## 🚀 Key Features

- 🔍 **Error Level Analysis (ELA)**: Resaves document images at intentional compression ratios to expose differential pixel error levels and highlight spliced or modified regions via high-contrast heatmaps.
- 🔬 **Computer Vision Pipeline**: Utilizes OpenCV for Laplacian edge variance sharpness analysis, noise inconsistency detection, and copy-move clone pattern matching.
- 🧠 **Groq LLM Forensic Audit**: Integrates high-throughput Groq AI inference to perform logical verification on extracted text—flagging impossible dates, mismatched numbers, and anomalous formatting.
- 📊 **100-Point Authenticity Index**: Generates a unified 0–100 authenticity score backed by 5 weighted forensic sub-scores:
  1. **Image Quality & Sharpness** (20 pts)
  2. **PDF Metadata Integrity** (20 pts)
  3. **OCR Text Confidence** (20 pts)
  4. **Vision Forgery Scan** (20 pts)
  5. **AI Logical Classification** (20 pts)
- 🖼️ **Side-by-Side Visual Inspection**: Real-time interactive inspection card displaying the original document side-by-side with its forensic ELA heatmap.
- 📄 **Automated PDF Forensic Audit Reports**: Instantly generates downloadable, court-ready PDF audit reports (via ReportLab) complete with confidence scores, detected anomalies, and metadata signatures.
- 📈 **Analytics & Live Audit Log**: Interactive Chart.js analytics tracking daily verification volume, verdict breakdown (*Genuine*, *Suspicious*, *Forged*), and searchable audit logs.
- 🌓 **Adaptive Light & Dark Themes**: Sleek glassmorphism UI with one-click theme toggling and `localStorage` preference persistence.
- 🔐 **Firebase Authentication & Firestore**: Secure email/password login, password recovery, and cloud audit storage.

---

## 🛠️ Technology Stack

| Layer | Technology |
|---|---|
| **Frontend** | HTML5, Vanilla CSS, Tailwind CSS, Chart.js, FontAwesome |
| **Backend** | Python 3, Flask, Flask-CORS |
| **Computer Vision** | OpenCV (`cv2`), Pillow (`PIL`), NumPy |
| **Document Processing & OCR** | `pdfplumber` |
| **AI / LLM Engine** | Groq API (`openai/gpt-oss-120b`, `qwen/qwen3.8-27b`, Llama 3) |
| **Auth & Cloud Database** | Firebase Authentication, Google Cloud Firestore |
| **Report Generation** | ReportLab (PDF Engine) |

---

## 📁 Project Structure

```text
DocuShield/
│
├── app.py                  # Flask backend & forensic verification pipeline
├── requirements.txt        # Python package dependencies
├── .env                    # Environment variables & API keys (git ignored)
├── serviceAccountKey.json  # Firebase Admin SDK private key (git ignored)
├── .gitignore              # Git ignore rules protecting credentials & data
│
├── frontend/               # Web application interfaces
│   ├── Main.html           # Landing page & feature showcase
│   ├── dashboard.html      # Forensic console & live analytics dashboard
│   ├── login.html          # Authentication page & password reset
│   └── signup.html         # User registration page
│
├── uploads/                # Document upload storage (git ignored)
│   └── ela/                # Generated ELA compression heatmaps
└── reports/                # Output directory for exported PDF reports
```

---

## ⚙️ Installation & Setup

### 1. Clone the Repository
```bash
git clone https://github.com/brubasree007/DocuShield.git
cd DocuShield
```

### 2. Create and Activate a Virtual Environment
```bash
# Windows
python -m venv venv
venv\Scripts\activate

# macOS / Linux
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Configure Environment Variables
Create a `.env` file in the project root directory:
```env
# Groq Cloud API
GROQ_API_KEY=your_groq_api_key_here
GROQ_MODEL=openai/gpt-oss-120b

# Firebase Client Web SDK Configuration
FIREBASE_API_KEY=your_firebase_api_key
FIREBASE_AUTH_DOMAIN=your_project.firebaseapp.com
FIREBASE_PROJECT_ID=your_project_id
FIREBASE_STORAGE_BUCKET=your_project.firebasestorage.app
FIREBASE_MESSAGING_SENDER_ID=your_messaging_sender_id
FIREBASE_APP_ID=your_app_id
```

### 5. Add Firebase Admin SDK Service Account
1. Go to **Firebase Console** → **Project Settings** → **Service Accounts**.
2. Click **Generate New Private Key**.
3. Save the downloaded JSON file as `serviceAccountKey.json` in the root of the project.

### 6. Run the Application
```bash
python app.py
```

Open your browser and navigate to:
**[http://localhost:5000](http://localhost:5000)**

---

## 🔒 Security & Privacy

- All sensitive keys (`.env`, `serviceAccountKey.json`) are excluded from version control via `.gitignore`.
- User authentication and document records are secured with Firebase Auth and Firestore security rules.
- Local document uploads and temporary heatmaps are kept strictly in local runtime folders and never committed.

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
