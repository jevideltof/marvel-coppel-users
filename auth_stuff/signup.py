import json
# import math
import sys
import os
import certifi
from datetime import datetime, timedelta
import pymongo
import bcrypt
# import hashlib
from flask import redirect, session
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity

MONGODB_URI = os.environ.get("MONGODB_URI")
client = pymongo.MongoClient(MONGODB_URI, tlsCAFile=certifi.where())
db = client.Marvel

sys.path.append('./utils')
from validations import vdate, vemail, vpassword

def exec(request):
    status = 409 # "Mientras no se demuestre que algo esta bien, está mal (política pesimista pero efectiva)"
    resp = {}
    if "email" in session:
        return redirect('/users')
    if request.method == "POST":
        user = request.form.get("fullname")
        # Validamos el correo / validate email
        email = request.form.get("email")
        if not email or not vemail(email):
            status = 409
            resp['error'] = 'El correo no es válido'
            return json.dumps(resp), status, {'ContentType': 'application/json'}
        # Validamos la contraseña / Validate the password
        password = request.form.get("password")
        if not password or not vpassword(password):
            status = 409
            resp['error'] = 'La contraseña debe tener al menos 8 caracteres, una mayúscula, una minúscula y un número'
            return json.dumps(resp), status, {'ContentType': 'application/json'}
        # Validamos la fecha de nacimiento / Validate birthdate
        birthdate = request.form.get("birthdate")
        if not birthdate or not vdate(birthdate):
            status = 409
            resp['error'] = 'Fecha de nacimiento inválida'
            return json.dumps(resp), status, {'ContentType': 'application/json'}
        # Si los datos anteriores son correctos, buscamos si ya existe el usuario y si no existe lo creamos / If the data is correct, we search if the user exists and if not we create it
        users = db.users
        email_found = users.find_one({"email": email})
        if email_found:
            status = 409
            resp['error'] = 'Ya existe una cuenta asociada a este correo'
            return json.dumps(resp), status, {'ContentType': 'application/json'}
        else:
            hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            # user_input = {'name': user, 'email': email, 'password': hashed}
            # users.insert_one(user_input)
            
            newUserDocument = {
                "fullname": user,
                "email": email,
                "password": hashed,
                "birthdate": birthdate,
            }
            inserted = users.insert_one(newUserDocument)
            id = str(inserted.inserted_id)

            if id:
                status = 201
                resp['msg'] = 'Usuario creado correctamente'
                resp['user_id'] = id
                resp['access_token'] = create_access_token(identity=id) # create jwt token
                return json.dumps(resp, default=str), status, {'ContentType': 'application/json'}
            else :
                status = 409
                resp['error'] = 'Error al crear el usuario'
    else:
        status = 400
        resp['status'] = status
        resp['error'] = 'Método no soportado'
    return json.dumps(resp), status, {'ContentType': 'application/json'}
