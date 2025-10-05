# Secure File Share - Hackathon Project

## Project Overview
Secure File Share is an open-source, end-to-end encrypted file sharing platform that ensures complete privacy and security for users' files.

## Files Created

### Core Application Files
- `server.js` - Main backend server with encryption functionality
- `js/app.js` - Frontend JavaScript with file sharing features
- `index.html` - Main UI interface
- `css/style.css` - Styling for the application
- `secure_file_share.db` - SQLite database file

### Documentation & Presentation
- `SecureFileShare_Pitch_Presentation.pdf` - Professional PDF pitch for hackathons
- `SecureFileShare_Pitch_Presentation.md` - Markdown source for the pitch
- `generate_pdf.js` - Script to generate the PDF pitch
- `README.md` - This file

## Key Features Implemented
1. **End-to-End Encryption**: Files are encrypted before upload
2. **Secure File Sharing**: Proper ownership attribution fixed
3. **User Authentication**: JWT-based secure login
4. **File Permissions**: Read/write access controls
5. **Responsive UI**: Bootstrap-based interface

## How to Run
1. Install dependencies: `npm install`
2. Start the server: `node server.js`
3. Access the application at: http://localhost:3000

## Hackathon Pitch Materials
The PDF presentation contains a comprehensive pitch for hackathons covering:
- Problem statement and market need
- Technical architecture and security features
- Implementation details and impact
- Business model and growth potential
- Call to action for investors and developers

## Security Features
- AES-256 encryption for all uploaded files
- Client-side encryption before server upload
- Proper file ownership attribution preserved
- Secure temporary file handling
- No plaintext file storage on server