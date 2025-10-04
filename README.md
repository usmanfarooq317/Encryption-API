# 🔐 Gateway Login Encryption API (Flask + RSA)

This project is a **Flask-based API service** that securely generates login payloads using **RSA encryption** for two different gateways:  
- **Subgateway**  
- **Retailergateway**

The service automatically detects which gateway to use based on the input format (`number` field) and forwards the encrypted login payload to a remote **CorporateLogin** API.  

---

## 🚀 Features
- 🔑 **RSA encryption** with separate public keys for **Subgateway** and **Retailergateway**.  
- 🌐 Auto-detection of gateway type based on `number`.  
- 📡 Forwards encrypted login payloads to a remote API.  
- 🛡️ Generates optional **x-hash** from API response.  
- ⚡ Simple REST API with a single `/loginpayload` endpoint.  

---

## 📂 Project Structure
