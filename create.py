from flask import Flask, render_template, request
from models import *

from config import Config

thisConfig = Config()

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = thisConfig.DB_URL
app.config["SQLALCHEMY_TRACK_MODIFICITION"] = False
db.init_app(app)

# def main():
# 	db.create_all()


def main():
	user = User()
if __name__ == '__main__':
	with app.app_context():
		main()
