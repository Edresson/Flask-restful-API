#!/usr/bin/env python
# -*- coding: utf-8 -*-
from flask import Flask, request
from flask_restful import Resource, Api, abort
from werkzeug.security import generate_password_hash, check_password_hash
from email.utils import parseaddr
import datetime
import functools
import pymongo
import jwt

import config

app = Flask(__name__)
app.config.from_object('config')
api = Api(app)


#conexao com o mongo db
client = pymongo.MongoClient(host=app.config['DB_HOST'], port=app.config['DB_PORT'])

#define a base de dados do mongodb para api
db = client.api


# validação de token para funcionalidades que requerem login
def login_required(method):
    @functools.wraps(method)
    def wrapper(self):
        token = request.headers.get('Authorization')
        try:
            decoded = jwt.decode(token, app.config['KEY'], algorithms='HS256')
        except jwt.DecodeError:
            abort(400, message='O Token de login invalido !.')
        except jwt.ExpiredSignatureError:
            abort(400, message='O seu token de login expirou.')
        email = decoded['email']
        if db.users.find({'email': email}).count() == 0:
            abort(400, message='Esse usuario não existe.')
        user = db.users.find_one({'email': email})
        return method(self, user)
    return wrapper

#recurso para registrar usuario
class Register(Resource):
    def post(self):
        pass

# recurso para ativar o usuario após registro
class Activate(Resource):
    def put(self):
        pass


# recurso para login
class Login(Resource):
    def post(self):
        pass


#recurso de teste para funções que  requerem o login
class Test(Resource):
    @login_required
    def get(self, user):
        pass

#definir rotas
api.add_resource(Register, '/api/register')

@app.route('/')
def hello_world():
    return "Hello World !"

if __name__ == '__main__':
    app.run(host="127.0.0.1", port=8085)
