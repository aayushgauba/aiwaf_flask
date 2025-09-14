# Test Flask AIWAF middleware integration
from flask import Flask, jsonify
from aiwaf_flask.middleware import register_aiwaf_middlewares

def create_app():
    app = Flask(__name__)
    app.config['AIWAF_RATE_WINDOW'] = 10
    app.config['AIWAF_RATE_MAX'] = 20
    app.config['AIWAF_RATE_FLOOD'] = 40
    app.config['AIWAF_MIN_FORM_TIME'] = 1.0
    register_aiwaf_middlewares(app)

    @app.route('/')
    def index():
        return "AIWAF Flask integration test OK"

    @app.route('/test', methods=['GET', 'POST'])
    def test():
        return jsonify({'result': 'success'})

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True)
