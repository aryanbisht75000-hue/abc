# Phishing Website Detection System

A web-based tool that analyzes URLs to detect potential phishing websites using various detection techniques.

## Features

- **URL Pattern Analysis**: Detects suspicious patterns in URLs
- **Domain Age Verification**: Checks how long a domain has been registered
- **SSL Certificate Check**: Verifies if the website uses HTTPS
- **Website Reachability**: Checks if the website is accessible
- **Risk Score Calculation**: Provides an overall risk assessment
- **Modern Web Interface**: Built with Flask and Tailwind CSS

## Prerequisites

- Python 3.7 or higher
- pip (Python package manager)

## Installation

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd phishing-detector
   ```

2. Create a virtual environment (recommended):
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install the required packages:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

1. Start the Flask development server:
   ```bash
   python app.py
   ```

2. Open your web browser and navigate to:
   ```
   http://127.0.0.1:5000
   ```

3. Enter a URL in the input field and click "Scan Now" to analyze it.

## Project Structure

```
phishing-detector/
├── app.py                # Main Flask application
├── requirements.txt      # Python dependencies
├── static/               # Static files (CSS, JS, images)
│   ├── css/
│   └── js/
│       └── main.js       # Frontend JavaScript
└── templates/
    └── index.html        # Main HTML template
```

## Detection Methods

The system uses the following methods to detect phishing websites:

1. **URL Pattern Analysis**:
   - Checks for suspicious keywords (login, bank, secure, etc.)
   - Analyzes URL length and structure
   - Detects suspicious symbols (@, multiple hyphens, etc.)

2. **Domain Age Verification**:
   - Newly registered domains are considered more suspicious
   - Uses WHOIS data to check domain registration date

3. **SSL Certificate Check**:
   - Verifies if the website uses HTTPS
   - Checks for valid SSL certificates

4. **Website Reachability**:
   - Verifies if the website is accessible
   - Checks for common error responses

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
