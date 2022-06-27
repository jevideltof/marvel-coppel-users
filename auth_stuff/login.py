from datetime import datetime
import json
import sys
import os
import certifi
import datetime
import pymongo
import bcrypt
from flask import redirect, session
from flask_login import login_user
from flask_jwt_extended import create_access_token

MONGODB_URI = os.environ.get("MONGODB_URI")
client = pymongo.MongoClient(MONGODB_URI, tlsCAFile=certifi.where())
db = client.Marvel

sys.path.append('./utils')
from validations import vemail, vpassword

from user import User

def exec(request):
    status = 409 # "Mientras no se demuestre que algo esta bien, está mal (política pesimista pero efectiva)"
    resp = {}
    if "email" in session:
        return redirect('/users')
    args = request.args
    if request.method == "POST" or request.method == "GET":
        # Validamos el correo / validate email
        email = args["email"]
        if not email or not vemail(email):
            status = 409
            resp['error'] = 'El correo no es válido'
            return json.dumps(resp), status, {'ContentType': 'application/json'}
        # Validamos la contraseña / Validate the password
        password = args["password"]
        if not password or not vpassword(password):
            status = 409
            resp['error'] = 'La contraseña debe tener al menos 8 caracteres, una mayúscula, una minúscula y un número'
            return json.dumps(resp), status, {'ContentType': 'application/json'}
        
        # Si los datos anteriores son correctos, intentamos logearnos / If the data is correct, we try to login
        users = db.users
        user_found = users.find_one({"email": email})
        if user_found:
            print('----------->User found: ', user_found)
            if bcrypt.checkpw(password.encode('utf-8'), user_found['password']):
                status = 200
                id = str(user_found.get('_id'))
                loginuser = User(user_found)
                login_user(loginuser)
                access_token = create_access_token(identity=id)
                session['name'] = user_found.get('fullname')
                # session['email'] = user_found['email']
                session['age'] = get_age_by_date(user_found.get('birthdate'))
                session['id'] = id
                # resp['message'] = 'Bienvenidx, ' + user_found['fullname']
                resp['access_token'] = access_token
                resp['name'] = session['name']
                resp['age'] = session['age']
                resp['id'] = session['id']
            else:
                status = 409
                resp['error'] = 'Contraseña incorrecta'
        else:
            status = 409
            resp['error'] = 'Usuario no encontrado'
    else:
        print("Método: " + str(request.method))
        status = 400
        resp['status'] = status
        resp['error'] = 'Método no soportado'
    return json.dumps(resp), status, {'ContentType': 'application/json'}

def get_age_by_date(date):
    today = datetime.datetime.now()
    birthdate = datetime.datetime.strptime(date, '%Y-%m-%d')
    age = today.year - birthdate.year - ((today.month, today.day) < (birthdate.month, birthdate.day))
    return age