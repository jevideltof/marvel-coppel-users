# https://stackoverflow.com/questions/56991649/virtualenv-not-activating-the-virtual-enviroment
# windows: $env:FLASK_APP = 'main', $env:FLASK_ENV = 1
# linux: export FLASK_APP=main, export FLASK_ENV=1
# Hice downgrade a PyMONGO 3.10.1 por el "bendito" error de timeout con la conexión a Atlas

from datetime import datetime
import json
import sys
import os
import certifi
import datetime
import pymongo
from flask import Flask, request, redirect, url_for, session
from flask_login import LoginManager, login_required, logout_user
from flask_jwt_extended import JWTManager

sys.path.append('./auth_stuff')
import signup
import login
from user import User

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY')

login_manager = LoginManager()
login_manager.init_app(app)

jwt = JWTManager(app) # initialize JWTManager
app.config['JWT_SECRET_KEY'] = os.environ.get('SECRET_KEY')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(days=1) # define the life span of the token

MONGODB_URI = os.environ.get("MONGODB_URI")
client = pymongo.MongoClient(MONGODB_URI, tlsCAFile=certifi.where())
db = client.Marvel

# Loader de usuario requerido por el control de sesiones
@login_manager.user_loader
def load_user(user_id):
    users = db.users
    user_json = users.find_one({"id": user_id})
    return User(user_json)

@app.route('/')
def index():
    return redirect(url_for('users_main'))

@app.route('/users')
@app.route('/users/')
@login_required
def users_main():
    user = {
        'name': session['name'],
        # 'email': session['email'],
        'age': session['age'],
        'id': session['id'],
        'info': 'El access_token se devuelve únicamente en el login'
    }
    return json.dumps(user, default=str)

@app.route("/users/signup", methods=['POST'])
@app.route("/users/signup/", methods=['POST'])
def _signup():
    return signup.exec(request)

@app.route("/users/login", methods=['POST', 'GET'])
def _login():
    return login.exec(request)

@app.route("/users/logout")
@app.route("/users/logout/")
@login_required
def _logout():
    logout_user()
    return json.dumps({'logout': True})

@login_manager.unauthorized_handler
def unauthorized():
    resp = {'error': 'No autorizado'}
    return json.dumps(resp, default=str), 401, {'ContentType': 'application/json'}

#end of code to run it
if __name__ == "__main__":
  app.run(debug=True)

@app.after_request
def add_header(r):
    """
    Add headers to both force latest IE rendering engine or Chrome Frame,
    and also to cache the rendered page for 10 minutes.
    """
    r.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    r.headers["Pragma"] = "no-cache"
    r.headers["Expires"] = "0"
    r.headers['Cache-Control'] = 'public, max-age=0'
    return r
