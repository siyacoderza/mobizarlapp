# mobizarlapp
commuters manage their tickets/view their pay cards online/verify which bus/taxi boarded and which driver was driving which bus/view trips balance
# Commuter Hub MVP 🚌

A commercial Minimum Viable Product (MVP) application designed for commuters to seamlessly track bus trips, check transit card balances, and access digital ticketing. 

## 🚀 Key Features

* **Real-Time Bus Trips**: View active transit schedules, routes, and trip details online.
* **Digital Ticketing**: Instant access to mobile commuter tickets and scannable passes.
* **Smart Card Status**: Check balance, transaction history, and card statuses instantly.
* **OTP Authentication**: Secure login verification powered by **Africa's Talking SMS API**.

## 🛠️ Tech Stack

* **Backend**: Node.js, Express.js
* **SMS Gateway**: Africa'sTalking Node.js SDK (v0.8.0)
* **Environment Configuration**: Dotenv

## 📦 Local Installation & Setup

Follow these steps to run the development environment locally:

### 1. Clone the Repository
```bash
git clone https://github.com
cd YOUR_REPO_NAME
```

### 2. Install Project Dependencies
```bash
npm install
```

### 3. Configure Your Credentials
Create a `.env` file in the root directory:
```bash
nano .env
```
Populate the file with your active API parameters:
```ini
AT_USERNAME="sandbox"
AT_API_KEY="your_africas_talking_api_key"
```

### 4. Launch the Local Application
```bash
node sendOtp.js
```

## 🔒 License

**Proprietary & Confidential**. All Rights Reserved.  
Unauthorized copying, modification, or distribution of this code repository is strictly prohibited. See the `LICENSE` file for explicit terms.
