from flask import Flask, render_template, request, redirect, url_for, flash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, EqualTo
import sqlite3
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import re
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'  # Change this to a random secret key

# Configure Flask-Login
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Create a SQLite database
conn = sqlite3.connect('user_database.db', check_same_thread=False)
cursor = conn.cursor()
cursor.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT)')
cursor.execute('CREATE TABLE IF NOT EXISTS words (id INTEGER PRIMARY KEY, word TEXT, language TEXT, user_id INTEGER, username TEXT, FOREIGN KEY (user_id) REFERENCES users(id))')
cursor.execute('CREATE TABLE IF NOT EXISTS user_word_counts (id INTEGER PRIMARY KEY, user_id INTEGER, username TEXT, accepted_words_count INTEGER, FOREIGN KEY (user_id) REFERENCES users(id))')
conn.commit()

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, user_id, username):
        self.id = user_id
        self.username = username

@login_manager.user_loader
def load_user(user_id):
    cursor.execute('SELECT * FROM users WHERE id=?', (user_id,))
    user_data = cursor.fetchone()
    if user_data:
        return User(user_data[0], user_data[1])
    return None

# Flask-WTF forms
class SignupForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Log In')

class WordForm(FlaskForm):
    word = StringField('Word', validators=[DataRequired()])
    language = StringField('Language', validators=[DataRequired()])  # New field for language
    submit = SubmitField('Submit')

@app.route('/')
@login_required
def index():
    return render_template('index.html', form=WordForm())

@app.route('/check_word', methods=['POST'])
@login_required
def check_word():
    word = request.form['word']
    language = request.form['language']

    # Check if the word contains only letters and is not empty
    if not re.match("^[a-zA-Z]+$", word):
        return "Invalid word. Please use only letters without spaces and special characters."

    # Check if the word exists in the database
    if is_word_allowed(word, current_user.id):
         flash("Word not allowed, it already exists in the database.", 'error_message')
         return redirect(url_for('index'))
        #  return render_template('index.html', form=WordForm())
    else:
        # If the word is unique, add it to the database, update the user's word count, and update the user's accepted words count
        add_word_to_database(word, language, current_user.id, current_user.username)
        update_user_word_count(current_user.id, current_user.username)
        flash("Word allowed and added to the database.")
        return redirect(url_for('index'))

   

def is_word_allowed(word, user_id):
    # Check if the word exists in the user's word list
    cursor.execute('SELECT * FROM words WHERE word=? AND user_id=?', (word, user_id))
    result = cursor.fetchone()
    return result is not None

def add_word_to_database(word, language, user_id, username):
    # Add the word to the user's word list along with the language
    cursor.execute('INSERT INTO words (word, language, user_id, username) VALUES (?, ?, ?, ?)', (word, language, user_id, username))
    conn.commit()

def update_user_word_count(user_id, username):
    # Update the user's accepted words count
    cursor.execute('SELECT * FROM user_word_counts WHERE user_id=?', (user_id,))
    result = cursor.fetchone()

    if result:
        # If the user exists in the user_word_counts table, update the count
        cursor.execute('UPDATE user_word_counts SET accepted_words_count = accepted_words_count + 1 WHERE user_id=?', (user_id,))
    else:
        # If the user does not exist, create a new entry
        cursor.execute('INSERT INTO user_word_counts (user_id, username, accepted_words_count) VALUES (?, ?, 1)', (user_id, username))

    conn.commit()

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm()

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        # Check if the username is already taken
        if is_username_taken(username):
            flash("Username is already taken. Please choose another one.")
        else:
            # Create a new user
            create_user(username, password)
            flash("Account created successfully. You can now log in.")
            return redirect(url_for('login'))

    return render_template('signup.html', form=form)

def is_username_taken(username):
    # Check if the username is already taken
    cursor.execute('SELECT * FROM users WHERE username=?', (username,))
    result = cursor.fetchone()
    return result is not None

def create_user(username, password):
    # Create a new user
    cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, password))
    conn.commit()

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        # Check if the username and password are valid
        user = validate_user(username, password)
        if user:
            login_user(user)
            flash(f"Logged in as {user.username}.")
            return redirect(url_for('index'))
        else:
            flash("Invalid username or password.")

    return render_template('login.html', form=form)

def validate_user(username, password):
    # Validate the username and password
    cursor.execute('SELECT * FROM users WHERE username=? AND password=?', (username, password))
    user_data = cursor.fetchone()
    if user_data:
        return User(user_data[0], user_data[1])
    return None

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)






# from flask import Flask, render_template, request, redirect, url_for, flash
# from flask_wtf import FlaskForm
# from wtforms import StringField, PasswordField, SubmitField
# from wtforms.validators import DataRequired, EqualTo
# import sqlite3
# from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
# import re

# app = Flask(__name__)
# app.config['SECRET_KEY'] = 'your_secret_key'  # Change this to a random secret key

# # Configure Flask-Login
# login_manager = LoginManager(app)
# login_manager.login_view = 'login'

# # Create a SQLite database
# conn = sqlite3.connect('user_database.db', check_same_thread=False)
# cursor = conn.cursor()
# cursor.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, organization TEXT)')
# cursor.execute('CREATE TABLE IF NOT EXISTS words (id INTEGER PRIMARY KEY, word TEXT, language TEXT, user_id INTEGER, username TEXT, organization TEXT, FOREIGN KEY (user_id) REFERENCES users(id))')
# cursor.execute('CREATE TABLE IF NOT EXISTS user_word_counts (id INTEGER PRIMARY KEY, user_id INTEGER, username TEXT, accepted_words_count INTEGER, FOREIGN KEY (user_id) REFERENCES users(id))')
# conn.commit()

# # User class for Flask-Login
# class User(UserMixin):
#     def __init__(self, user_id, username, organization):
#         self.id = user_id
#         self.username = username
#         self.organization = organization

# @login_manager.user_loader
# def load_user(user_id):
#     cursor.execute('SELECT * FROM users WHERE id=?', (user_id,))
#     user_data = cursor.fetchone()
#     if user_data:
#         return User(user_data[0], user_data[1], user_data[3])  # Add organization to User
#     return None

# # Flask-WTF forms
# class SignupForm(FlaskForm):
#     username = StringField('Username', validators=[DataRequired()])
#     password = PasswordField('Password', validators=[DataRequired()])
#     confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
#     organization = StringField('Organization', validators=[DataRequired()])  # Add organization field
#     submit = SubmitField('Sign Up')

# class LoginForm(FlaskForm):
#     username = StringField('Username', validators=[DataRequired()])
#     password = PasswordField('Password', validators=[DataRequired()])
#     submit = SubmitField('Log In')

# class WordForm(FlaskForm):
#     word = StringField('Word', validators=[DataRequired()])
#     language = StringField('Language', validators=[DataRequired()])
#     submit = SubmitField('Submit')

# @app.route('/')
# @login_required
# def index():
#     return render_template('index.html', form=WordForm())

# @app.route('/check_word', methods=['POST'])
# @login_required
# def check_word():
#     word = request.form['word']
#     language = request.form['language']

#     # Check if the word contains only letters and is not empty
#     if not re.match("^[a-zA-Z]+$", word):
#         flash("Invalid word. Please use only letters without spaces and special characters.", 'error_message')
#         return redirect(url_for('index'))

#     # Check if the word exists in the database
#     if is_word_allowed(word, current_user.id):
#         flash("Word not allowed, it already exists in the database.", 'error_message')
#         return redirect(url_for('index'))
#     else:
#         # If the word is unique, add it to the database, update the user's word count, and update the user's accepted words count
#         add_word_to_database(word, language, current_user.id, current_user.username, current_user.organization)
#         update_user_word_count(current_user.id, current_user.username)
#         flash("Word allowed and added to the database.")
#         return redirect(url_for('index'))

# def is_word_allowed(word, user_id):
#     # Check if the word exists in the user's word list
#     cursor.execute('SELECT * FROM words WHERE word=? AND user_id=?', (word, user_id))
#     result = cursor.fetchone()
#     return result is not None

# def add_word_to_database(word, language, user_id, username, organization):
#     # Add the word to the user's word list along with the language and organization
#     cursor.execute('INSERT INTO words (word, language, user_id, username, organization) VALUES (?, ?, ?, ?, ?)', (word, language, user_id, username, organization))
#     conn.commit()

# def update_user_word_count(user_id, username):
#     # Update the user's accepted words count
#     cursor.execute('SELECT * FROM user_word_counts WHERE user_id=?', (user_id,))
#     result = cursor.fetchone()

#     if result:
#         # If the user exists in the user_word_counts table, update the count
#         cursor.execute('UPDATE user_word_counts SET accepted_words_count = accepted_words_count + 1 WHERE user_id=?', (user_id,))
#     else:
#         # If the user does not exist, create a new entry
#         cursor.execute('INSERT INTO user_word_counts (user_id, username, accepted_words_count) VALUES (?, ?, 1)', (user_id, username))

#     conn.commit()

# @app.route('/signup', methods=['GET', 'POST'])
# def signup():
#     form = SignupForm()

#     if form.validate_on_submit():
#         username = form.username.data
#         password = form.password.data
#         organization = form.organization.data

#         # Check if the username is already taken
#         if is_username_taken(username):
#             flash("Username is already taken. Please choose another one.", 'error_message')
#         else:
#             # Create a new user
#             create_user(username, password, organization)
#             flash("Account created successfully. You can now log in.")
#             return redirect(url_for('login'))

#     return render_template('signup.html', form=form)

# def is_username_taken(username):
#     # Check if the username is already taken
#     cursor.execute('SELECT * FROM users WHERE username=?', (username,))
#     result = cursor.fetchone()
#     return result is not None

# def create_user(username, password, organization):
#     # Create a new user
#     cursor.execute('INSERT INTO users (username, password, organization) VALUES (?, ?, ?)', (username, password, organization))
#     conn.commit()

# @app.route('/login', methods=['GET', 'POST'])
# def login():
#     form = LoginForm()

#     if form.validate_on_submit():
#         username = form.username.data
#         password = form.password.data

#         # Check if the username and password are valid
#         user = validate_user(username, password)
#         if user:
#             login_user(user)
#             flash(f"Logged in as {user.username}.")
#             return redirect(url_for('index'))
#         else:
#             flash("Invalid username or password.", 'error_message')

#     return render_template('login.html', form=form)

# def validate_user(username, password):
#     # Validate the username and password
#     cursor.execute('SELECT * FROM users WHERE username=? AND password=?', (username, password))
#     user_data = cursor.fetchone()
#     if user_data:
#         return User(user_data[0], user_data[1], user_data[3])  # Add organization to User
#     return None

# @app.route('/logout')
# @login_required
# def logout():
#     logout_user()
#     return redirect(url_for('login'))

# if __name__ == '__main__':
#     app.run(debug=True)
