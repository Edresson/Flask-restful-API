
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



client = pymongo.MongoClient(host=app.config['DB_HOST'], port=app.config['DB_PORT'])

#define a base de dados do mongodb para api
db = client.api

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

class Register(Resource):
    def post(self):
        email = request.json['email']
        senha = request.json['senha']
        if(not '@' in parseaddr(email)[1]):
            abort(400, message='o Email é inválido.')
        if len(senha) < 6:
            abort(400, message='A senha indicada é muito curta.')
        if db.users.find({'email': email}).count() != 0:
            if db.users.find_one({'email': email})['active'] == True:
                abort(400, message='Esse email já está sendo usado, faça login !')
        else:
            db.users.insert_one({'email': email, 'senha': generate_password_hash(senha), 'active': False})
        exp = datetime.datetime.utcnow() + datetime.timedelta(days=app.config['ACTIVATION_EXPIRE_DAYS'])
        encoded = jwt.encode({'email': email, 'exp': exp},
                             app.config['KEY'], algorithm='HS256')
        return {'email': email,'activation_code':encoded.decode('utf-8')}

class Activate(Resource):
    def put(self):
        activation_code = request.json['activation_code']
        
        try:
            decoded = jwt.decode(activation_code, app.config['KEY'], algorithms='HS256')
        except jwt.DecodeError:
            abort(400, message='O codigo de ativação não é valido.')
        except jwt.ExpiredSignatureError:
            abort(400, message='O codigo de ativação expirou.')
        email = decoded['email']
        db.users.update({'email': email}, {'$set': {'active': True}})
        return {'email': email}

class Login(Resource):
    def get(self):
        email = request.json['email']
        senha = request.json['senha']
        if db.users.find({'email': email}).count() == 0:
            abort(400, message='Esse usuario não existe.')
        user = db.users.find_one({'email': email})
        if not check_password_hash(user['senha'], senha):
            abort(400, message='A senha está incorreta')
        exp = datetime.datetime.utcnow() + \
            datetime.timedelta(hours=app.config['TOKEN_EXPIRE_HOURS'])
        token = jwt.encode({'email': email, 'exp': exp},
                             app.config['KEY'], algorithm='HS256')
        return {'email': email, 'token': token.decode('utf-8')}

class Test(Resource):
    @login_required
    def get(self, user):
        return {'email': user['email']}

api.add_resource(Register, '/api/register')
api.add_resource(Activate, '/api/activate')
api.add_resource(Login, '/api/login')
api.add_resource(Test, '/api/test')

@app.route('/')
def hello_world():
    return "Hello World !"

if __name__ == '__main__':
    app.run(host="127.0.0.1", port=8085)
