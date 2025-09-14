from flask import Flask, request, jsonify
from aiwaf_flask.flask_integration import AIWAF

# Import your AIWAF middleware from the main aiwaf package
from aiwaf.middleware import AIWAFMiddleware

app = Flask(__name__)

# Initialize AIWAF middleware and integrate with Flask
aiwaf_middleware = AIWAFMiddleware()
aiwaf = AIWAF(app, aiwaf_middleware)

@app.route('/')
def index():
    return "AIWAF Flask integration is running!"

@app.route('/protected', methods=['GET', 'POST'])
def protected():
    # Example endpoint protected by AIWAF
    return jsonify({"message": "Protected endpoint accessed."})

if __name__ == '__main__':
    app.run(debug=True)
