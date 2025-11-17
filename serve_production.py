from waitress import serve
from app import app

if __name__ == '__main__':
    # Serve app on port 8000 for local production testing
    serve(app, host='0.0.0.0', port=8000)
