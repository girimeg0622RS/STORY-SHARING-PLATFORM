from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'instance', 'stories.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # 'reader' or 'writer'
    stories = db.relationship('Story', backref='author', lazy=True)
    comments = db.relationship('Comment', backref='user', lazy=True)
    likes = db.relationship('Like', backref='user', lazy=True)

class Story(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    comments = db.relationship('Comment', backref='story', lazy=True)
    likes = db.relationship('Like', backref='story', lazy=True)

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    story_id = db.Column(db.Integer, db.ForeignKey('story.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Like(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    story_id = db.Column(db.Integer, db.ForeignKey('story.id'), nullable=False)
    __table_args__ = (db.UniqueConstraint('user_id', 'story_id', name='unique_like'),)

# Context Processor
@app.context_processor
def inject_user():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        return {'current_user': user}
    return {'current_user': None}

# Routes
@app.route('/')
def index():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user and user.role == 'writer':
            return redirect(url_for('writer_dashboard'))
        elif user:
            return redirect(url_for('reader_dashboard'))
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if not username or not password:
            flash('Username and password are required')
            return render_template('login.html')
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            if user.role == 'writer':
                return redirect(url_for('writer_dashboard'))
            return redirect(url_for('reader_dashboard'))
        flash('Invalid credentials')
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        role = request.form.get('role')
        if not username or not password or not role:
            flash('All fields are required')
            return render_template('signup.html')
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
        elif role not in ['reader', 'writer']:
            flash('Invalid role selected')
        else:
            hashed_password = generate_password_hash(password)
            new_user = User(username=username, password=hashed_password, role=role)
            db.session.add(new_user)
            db.session.commit()
            flash('Account created! Please log in.')
            return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('Logged out successfully')
    return redirect(url_for('index'))

@app.route('/reader_dashboard')
def reader_dashboard():
    if 'user_id' not in session:
        flash('Please log in to access the dashboard')
        return redirect(url_for('login'))
    stories = Story.query.all()
    return render_template('reader_dashboard.html', stories=stories)

@app.route('/writer_dashboard')
def writer_dashboard():
    if 'user_id' not in session:
        flash('Please log in to access the dashboard')
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    if not user or user.role != 'writer':
        flash('Access restricted to writers')
        return redirect(url_for('reader_dashboard'))
    stories = Story.query.filter_by(author_id=user.id).all()
    return render_template('writer_dashboard.html', stories=stories)

@app.route('/story/<int:story_id>', methods=['GET', 'POST'])
def story_view(story_id):
    if 'user_id' not in session:
        flash('Please log in to view stories')
        return redirect(url_for('login'))
    story = Story.query.get_or_404(story_id)
    if request.method == 'POST':
        content = request.form.get('content')
        if not content:
            flash('Comment cannot be empty')
            return redirect(url_for('story_view', story_id=story_id))
        new_comment = Comment(content=content, story_id=story_id, user_id=session['user_id'])
        db.session.add(new_comment)
        db.session.commit()
        flash('Comment added successfully')
        return redirect(url_for('story_view', story_id=story_id))
    return render_template('story_view.html', story=story)

@app.route('/story/upload', methods=['GET', 'POST'])
def story_upload():
    if 'user_id' not in session:
        flash('Please log in to upload stories')
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    if not user or user.role != 'writer':
        flash('Only writers can upload stories')
        return redirect(url_for('reader_dashboard'))
    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content')
        if not title or not content:
            flash('Title and content are required')
            return render_template('story_upload.html')
        new_story = Story(title=title, content=content, author_id=user.id)
        db.session.add(new_story)
        db.session.commit()
        flash('Story uploaded successfully!')
        return redirect(url_for('writer_dashboard'))
    return render_template('story_upload.html')

@app.route('/story/edit/<int:story_id>', methods=['GET', 'POST'])
def story_edit(story_id):
    if 'user_id' not in session:
        flash('Please log in to edit stories')
        return redirect(url_for('login'))
    story = Story.query.get_or_404(story_id)
    if story.author_id != session['user_id']:
        flash('You can only edit your own stories')
        return redirect(url_for('reader_dashboard'))
    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content')
        if not title or not content:
            flash('Title and content are required')
            return render_template('story_edit.html', story=story)
        story.title = title
        story.content = content
        db.session.commit()
        flash('Story updated successfully!')
        return redirect(url_for('writer_dashboard'))
    return render_template('story_edit.html', story=story)

@app.route('/story/like/<int:story_id>', methods=['POST'])
def like_story(story_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Please log in to like stories'}), 401
    story = Story.query.get_or_404(story_id)
    user_id = session['user_id']
    existing_like = Like.query.filter_by(user_id=user_id, story_id=story_id).first()
    if existing_like:
        db.session.delete(existing_like)
        db.session.commit()
        liked = False
    else:
        new_like = Like(user_id=user_id, story_id=story_id)
        db.session.add(new_like)
        db.session.commit()
        liked = True
    like_count = Like.query.filter_by(story_id=story_id).count()
    return jsonify({'liked': liked, 'like_count': like_count})

if __name__ == '__main__':
    with app.app_context():
        os.makedirs(os.path.join(basedir, 'instance'), exist_ok=True)
        db.create_all()
    app.run(debug=True)