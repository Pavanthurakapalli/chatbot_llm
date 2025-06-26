from flask import Flask, render_template, request, redirect, url_for, flash, make_response, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField
from wtforms.validators import InputRequired, Length, Email
import openai
import os
from dotenv import load_dotenv
from datetime import datetime
import uuid
import pytz

load_dotenv()

app = Flask(__name__)
app.secret_key = '123456789'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///queries.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
openai.api_key = os.getenv("OPENAI_API_KEY")

IST = pytz.timezone('Asia/Kolkata')

# Models
class Query(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_query = db.Column(db.String(500), nullable=False)
    ai_response = db.Column(db.String(500), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    chat_session_id = db.Column(db.String(100), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref='user_queries')

   

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    email = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(150), nullable=False)
    queries = db.relationship('Query', backref='creator', lazy=True)

with app.app_context():
    db.create_all()

# Forms
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=150)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=6, max=150)])

class SignupForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=150)])
    email = StringField('Email', validators=[InputRequired(), Email(), Length(min=6, max=150)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=6, max=150)])

# Utils
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
def index_redirect():
    return redirect(url_for('login'))

@app.route('/home', methods=['GET'])
@login_required
def home():
    session_id = request.args.get('session_id') or session.get('chat_session_id')

    if not session_id:
        latest_query = Query.query.filter_by(user_id=current_user.id).order_by(Query.timestamp.desc()).first()
        if latest_query:
            session_id = latest_query.chat_session_id

    if session_id:
        session['chat_session_id'] = session_id

    all_queries = Query.query.filter_by(
        user_id=current_user.id,
        chat_session_id=session_id
    ).order_by(Query.timestamp.asc()).all()

    for query in all_queries:
        query.timestamp = query.timestamp.replace(tzinfo=pytz.utc).astimezone(IST)

    sessions = db.session.query(
        Query.chat_session_id,
        db.func.min(Query.timestamp).label("started_at"),
        db.func.min(Query.user_query).label("title")
    ).filter_by(user_id=current_user.id)\
     .group_by(Query.chat_session_id)\
     .order_by(db.func.min(Query.timestamp).desc())\
     .all()

    session_items = []
    for s in sessions:
        started_at_ist = s.started_at.replace(tzinfo=pytz.utc).astimezone(IST)
        session_items.append({
            'chat_session_id': s.chat_session_id,
            'title': s.title,
            'started_at': started_at_ist
        })

    session_is_empty = len(all_queries) == 0
    latest_session_id = sessions[0].chat_session_id if sessions else None
    readonly = False if session_is_empty else (session_id != latest_session_id)

    response = make_response(render_template(
        'index.html',
        current_user=current_user,
        all_queries=all_queries,
        sessions=session_items,
        current_session=session_id,
        readonly=readonly
    ))
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Login Unsuccessful. Please check username and password', 'danger')
    response = make_response(render_template('login.html', form=form))
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = SignupForm()
    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        password = form.password.data
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'danger')
            return redirect(url_for('signup'))
        if User.query.filter_by(email=email).first():
            flash('Email already exists.', 'danger')
            return redirect(url_for('signup'))
        new_user = User(username=username, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Signup successful! You can now log in.', 'success')
        return redirect(url_for('login'))
    return render_template('signup.html', form=form)

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    flash('You have been logged out successfully.', 'success')
    return redirect(url_for('login'))

@app.route('/submit', methods=['POST'])
@login_required
def submit_query():
    user_query = request.form['query']
    chat_session_id = session.get('chat_session_id')

    if not chat_session_id:
        chat_session_id = str(uuid.uuid4())
        session['chat_session_id'] = chat_session_id

    previous_queries = Query.query.filter_by(user_id=current_user.id, chat_session_id=chat_session_id).order_by(Query.id.asc()).all()
    messages = []
    for q in previous_queries:
        messages.append({"role": "user", "content": q.user_query})
        messages.append({"role": "assistant", "content": q.ai_response})

    messages.append({"role": "user", "content": user_query})

    response = openai.ChatCompletion.create(
        model="gpt-3.5-turbo",
        messages=messages,
        max_tokens=1000,
        temperature=0.7,
        top_p=1.0,
        n=1
    )

    ai_response = response['choices'][0]['message']['content'].strip()

    new_query = Query(
        user_query=user_query,
        ai_response=ai_response,
        user_id=current_user.id,
        chat_session_id=chat_session_id
    )
    db.session.add(new_query)
    db.session.commit()

    flash('Query submitted successfully! AI response stored.', 'success')
    return redirect(url_for('home'))

@app.route('/new_chat', methods=['POST'])
@login_required
def new_chat():
    new_session_id = str(uuid.uuid4())
    session['chat_session_id'] = new_session_id
    return redirect(url_for('home', session_id=new_session_id))

@app.route('/clear', methods=['POST'])
@login_required
def clear_history():
    Query.query.filter_by(user_id=current_user.id).delete()
    db.session.commit()
    flash('Chat history cleared.', 'success')
    return redirect(url_for('home'))

if __name__ == "__main__":
    app.run(debug=True)
