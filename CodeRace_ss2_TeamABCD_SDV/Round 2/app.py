from flask import Flask
from src.applications import mod_user

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Register the mod_user blueprint
app.register_blueprint(mod_user)

if __name__ == '__main__':
    app.run()