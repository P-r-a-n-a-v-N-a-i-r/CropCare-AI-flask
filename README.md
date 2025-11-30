# CropCareAI 🌱 — Cloud-Based Plant Disease Detection

<img width="1896" height="815" alt="Screenshot 2025-11-30 160215" src="https://github.com/user-attachments/assets/24136410-faa7-4059-a264-591e0a3048ec" />


**CropCareAI** is a cloud-native, AI-powered plant disease diagnosis application designed for MSc Cloud Platform Programming. It leverages AWS cloud services, modern containerization, and a friendly web interface to help users diagnose plant diseases in real time.

---
## 🌐 Live Demo

You can access the deployed CropCareAI application at:

http://cropcare-ai.us-east-1.elasticbeanstalk.com/

---

## 🚀 Features

- **AI-Powered Detection:** Upload a plant photo and get instant disease identification via a deep learning model.
- **Secure User Auth:** AWS Cognito-based registration, sign-in, and JWT access.
- **Scalable Storage:** Images stored in AWS S3.
- **Data Persistence:** Predictions and user histories saved in AWS DynamoDB.
- **Serverless Inference:** ML inference triggered by S3 → AWS Lambda.
- **Notifications:** AWS SNS for sending help/alert requests.
- **Modern Frontend:** Responsive UI with Tailwind CSS and Toastr notifications.

---

## 🧑‍💻 Technology Stack

- **Frontend:** Angular 16+, Tailwind CSS
- **Backend:** Flask (Python 3.9), Gunicorn, custom ML library (`plant_disease_lib`)
- **Cloud Services:** 
  - AWS S3
  - AWS Lambda
  - AWS DynamoDB
  - AWS Cognito
  - AWS SNS
  - AWS Elastic Beanstalk (Docker)
- **CI/CD:** Docker, GitHub, Elastic Beanstalk CLI

---

## 🏗️ Cloud Architecture



text
*Image: Add your PNG/SVG architecture diagram here!*

_Event Flow:_ upload → S3 triggers Lambda → Lambda predicts → DynamoDB → UI fetches result.

---

## 📦 Project Structure

- app.py # Main Flask web app
- requirements.txt # Python dependencies
- models/ # Trained model files
- templates/ # Jinja2 HTML templates
- static/ # CSS/JS/assets
- plant_disease_lib/ # OOP ML library (PyTorch)
- disease_info.csv # Disease metadata
- supplement_info.csv # Supplement metadata
- wsgi.py # WSGI entrypoint
- Dockerfile # Docker build recipe
- .env # Environment variables (not committed)


## 🔐 .env Setup (IMPORTANT)

Create a `.env` file in the project root (this file is **not** committed to GitHub) with your AWS and Cognito configuration:
**Add Environment Variables**
- **AWS_ACCESS_KEY_ID**=YOUR_KEY
- **AWS_SECRET_ACCESS_KEY**=YOUR_SECRET
- **AWS_REGION**=eu-west-1
- **S3_BUCKET**=cropcareai-images
- **DYNAMODB_TABLE**=cropcareai-history
- **COGNITO_USER_POOL_ID**=your_id
- **COGNITO_CLIENT_ID**=your_client
- **SNS_TOPIC_ARN**=your_sns_topic


---

## 💻 Local Development

1. **Clone the repo:**
- git clone https://github.com/P-r-a-n-a-v-N-a-i-r/CropCare-AI-flask.git
- cd cropcareai


---


2. **Build and run in Docker:**
- docker build -t cropcare-app .
- docker run --rm -p 8000:8000 --env-file .env cropcare-app

---

3. **Access app:**  
- Visit http://localhost:8000

---

## 📊 Supported Plants & Diseases

- Detects 38 diseases in 14 plant types (Apple, Tomato, Potato, Peach, Corn, Strawberry, etc.).
- OOP-encapsulated PyTorch model.

---

## ☁️ Deployment

- **Production:** Docker app deployed to AWS Elastic Beanstalk, public endpoint available for demonstration.
- **Cloud9:** AWS Cloud9 used for cloud development and AWS integration.

---

## 📜 License

This codebase was developed for the MSc Cloud Computing program at the National College of Ireland and is academic coursework. Do not copy or redistribute.

---

*For issues and collaboration, open an Issue or contact the maintainer.*
