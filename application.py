from flask import Flask, render_template, request, session, redirect, url_for, abort
from os import system
from flask_bcrypt import Bcrypt
from config import Config
from models import *
import re
thisConfig = Config()

app = Flask(__name__)
app.secret_key = thisConfig.secret_key

app.config["SQLALCHEMY_DATABASE_URI"] = thisConfig.DB_URL
app.config["SQLALCHEMY_TRACK_MODIFICITION"] = False
db.init_app(app)

bcrypt = Bcrypt(app)

@app.route('/')
def index():
	if 'login_user' not in session:
		login_user = None
	else : 
		login_user=session['login_user']

	page = render_template('index.html', login_user=login_user)
	return page

@app.route('/about')
def about():
	return render_template('about.html')

def validate_name(f_name, l_name):
	if (len(f_name) < 3) or (len(l_name) < 3):
		return False, "Empty field or name less than 3 characters"
	return True, ""

def validate_username(username):
	if len(username) < 5:
		return False, "Empty Username Field or less than 5 character"
	user = User.query.filter_by(username=username).first()
	# user = User.query.filter(User.username == username).first()
	if user :
		return False, "Email adress has been used."

	regex = '^(\w|\.|\_|\-)+[@](\w|\_|\-|\.)+[.]\w{2,3}$'

	if (re.search(regex, username)) == False:
		return False, "Email index is not valid"

	return True, ""

def check_title_note(thing):
	if thing == '':
		return False, "should not remain empty."
	return True, ""


def validate_password(password, confirm):
	if len(password) < 5:
		return False, "Empty field or less than 5 character"
	if password != confirm:
		return False, "Password doesn't match"
	return True, "Created"

	
@app.route('/register', methods=['GET', 'POST'])
def register():

	if 'login_user' in session:
		return redirect(url_for('index'))
	if request.method == 'POST':
		f_name = request.form.get('f_name')
		l_name = request.form.get('l_name')
		username = request.form.get('username')
		password = request.form.get('password')
		confirm = request.form.get('confirm')


		validate_names = validate_name(f_name, l_name)
		validate_email = validate_username(username)
		validate_passwords = validate_password(password, confirm)

		if (validate_names[0] == False) or (validate_email[0] == False) or (validate_passwords[0] == False):
			return render_template('register.html',msg=False, name_status=False, message_name=validate_names[1], email_status=False, message_email=validate_email[1], password_status=False, message_password=validate_passwords[1])

		hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
		user = User(first_name=f_name, last_name=l_name, username=username, password=hashed_password)
		db.session.add(user)
		db.session.commit()

		return render_template('register.html', msg=True, name_status=True, email_status=True, password_status=True)

	return render_template('register.html', msg=False, name_status=True, email_status=True, password_status=True)


@app.route('/create', methods=['GET', 'POST'])
def create():

	if 'login_user' not in session:
		return render_template('login.html', msg="Please login first before creating note.", category='danger')

	login_user=session['login_user']
	notes = db.session.query(Note, User).filter(Note.created_by == User.id, Note.created_by == login_user['id']).order_by(Note.created_on.desc()).all()

	if request.method == 'POST':
		title = request.form.get('title')
		note = request.form.get('note')

		title_check = check_title_note(title)
		note_check = check_title_note(note)

		my_note = Note(created_by=login_user['id'], title=title, note=note)
		db.session.add(my_note)
		db.session.commit()
		return redirect(url_for('create'))

	return render_template('create.html', login_user=login_user, notes=notes)

@app.route('/edit/<int:note_id>', methods=['GET', 'POST'])
def edit(note_id):
	if 'login_user' not in session:
		return redirect(url_for('index'))
	# note = Note.query.get_or_404(note_id).first()
	note = Note.query.get(note_id)
	if not note :
		abort(404) #Not Found
	if note.created_by != session['login_user']['id']:
		abort(403) #Permission Denied

	if request.method == 'POST':
		title_form = request.form.get('title')
		note_form = request.form.get('note')


		note.note = note_form
		note.title = title_form

		db.session.commit()
		return redirect(url_for('create'))

	return render_template('edit.html', note=note, login_user=session['login_user'])

@app.route('/delete/<int:note_id>', methods=['GET', 'POST'])
def delete(note_id):
	if 'login_user' not in session:
		return redirect(url_for('index'))
	# note = Note.query.get_or_404(note_id).first()
	note = Note.query.get(note_id)
	if not note :
		abort(404) #Not Found
	if note.created_by != session['login_user']['id']:
		abort(403) #Permission Denied

	db.session.delete(note)
	db.session.commit()

	return redirect(url_for('.create'))

@app.route('/more/<int:note_id>')
def more(note_id):
	if 'login_user' not in session:
		return redirect(url_for('index'))
	# note = Note.query.get_or_404(note_id).first()
	note = Note.query.get(note_id)
	if not note :
		abort(404) #Not Found
	if note.created_by != session['login_user']['id']:
		abort(403) #Permission Denied

	return render_template('more.html', note=note, login_user=session['login_user'])

@app.route('/login', methods=['GET' , 'POST'])
def login():
	if 'login_user' in session:
		return redirect(url_for('index'))

	if request.method == 'POST':
		username = request.form.get('username')
		password = request.form.get('password')

		
		user = User.query.filter_by(username=username).first()
		if password == '':
			return render_template('login.html', check_pass=True, pass_message='Should not remained empty.')
		if user:
			if bcrypt.check_password_hash(user.password, password):
				session['login_user'] = {
					'id' : user.id,
					'username' : user.username,
					'first_name' : user.first_name,
					'last_name' : user.last_name
				}
				return redirect(url_for('.index'))
		else : 
			return render_template('login.html', check_pass=True, pass_message='Incorrect password or email adress.')

		
	return render_template('login.html', check_pass=False)

@app.route('/logout')
def logout():
	if 'login_user' in session:
		session.pop('login_user')
		return redirect(url_for('index'))


	return redirect(url_for('index'))

@app.route('/admin')
def admin():
	return render_template('edit.html', note='250')

@app.route('/api/<user>/<string:username>')
def user_api(username):
	return username

@app.route('/api/note/<int:note_id>')
def note_api(note_id):
	return note_id

@app.route('/portfolio')
def portfolio():
	if 'login_user' in session:
		return render_template('portfolio.html', login_user=session['login_user'])
	return render_template('portfolio.html')
