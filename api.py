from flask import Flask
import config

app = Flask(__name__)
app.config.from_object('config')
api = Api(app)



@app.route('/')
def hello_world():
    return "Hello World !"

if __name__ == '__main__':
    app.run(host="127.0.0.1", port=8085)
