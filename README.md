# Local Anonymous Chat

A local network chat application with file sharing capabilities.

## Features

- Anonymous user registration and login
- Real-time chat messaging
- File upload and sharing (up to 100MB)
- Local network access
- Modern and responsive UI

## Setup

1. Install Python 3.7 or higher if you haven't already

2. Install the required dependencies:
```bash
pip install -r requirements.txt
```

3. Run the application:
```bash
python app.py
```

4. Access the application:
   - Open your web browser
   - Go to `http://localhost:5000` or `http://[your-local-ip]:5000`
   - Other devices on the same network can access using your computer's local IP address

## Usage

1. Register a new account or login with existing credentials
2. Chat with other users on the network
3. Upload and share files (max 100MB per file)
4. Download shared files from other users

## Security Notes

- This application runs on your local network only
- Files are stored locally in the 'uploads' directory
- Change the SECRET_KEY in app.py before deploying
- Ensure your network is secure as this is a local network application
