import os

from flask_wtf.csrf import CSRFProtect
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash


app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'ViRuS435345325346475')
csrf = CSRFProtect(app)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///database.db')
db = SQLAlchemy(app)
migrate = Migrate(app, db)



class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)


class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), nullable=False)
    content = db.Column(db.Text, nullable=False)
    date_posted = db.Column(db.DateTime, default=db.func.now())
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    author = db.relationship('User', backref=db.backref('posts', lazy=True))

    # Лайки (many-to-many)
    likes = db.relationship('User', secondary='post_likes', backref=db.backref('liked_posts', lazy=True))

    # Комментарии
    comments = db.relationship('Comment', backref='post', lazy=True, cascade='all, delete-orphan')


# Таблица для лайков (many-to-many)
post_likes = db.Table('post_likes',
                      db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
                      db.Column('post_id', db.Integer, db.ForeignKey('post.id'), primary_key=True)
                      )


# Модель комментариев
class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    date_posted = db.Column(db.DateTime, default=db.func.now())
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'))
    author = db.relationship('User', backref=db.backref('comments', lazy=True))


# Декоратор для защиты роутов
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    posts = Post.query.order_by(Post.date_posted.desc()).all()  # Все посты из БД
    return render_template('index.html', posts=posts)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html')
    elif request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = generate_password_hash(password)  # Превращаем пароль в хэш


        # Сохраняем пользователя в БД
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        session['user_id'] = new_user.id
    return redirect(url_for('index'))



@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    elif request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Ищем пользователя в БД
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):  # Сравниваем хэш из БД с введенным паролем
            session['user_id'] = user.id  # Сохраняем в сессию
            return redirect(url_for('index'))
        else:
            return render_template('login.html', error='Неверный логин или пароль')



@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('index'))


@app.route('/profile')
def profile():
    if 'user_id' not in session:  # Простая проверка
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    user = User.query.get(user_id)
    return f'Привет, {user.username}! Это твой профиль.'


@app.route('/create_post', methods=['GET', 'POST'])
@login_required  # Только для авторизованных!
def create_post():
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        user_id = session['user_id']  # ID из сессии

        new_post = Post(title=title, content=content, user_id=user_id)
        db.session.add(new_post)
        db.session.commit()

        return redirect(url_for('index'))

    return render_template('create_post.html')


@app.route('/like_post/<int:post_id>', methods=['POST'])
@login_required
def like_post(post_id):
    post = Post.query.get_or_404(post_id)
    user_id = session['user_id']
    user = User.query.get(user_id)

    if user in post.likes:
        post.likes.remove(user)  # Дизлайк
    else:
        post.likes.append(user)  # Лайк

    db.session.commit()
    return redirect(url_for('index'))


# Добавление комментария
@app.route('/add_comment/<int:post_id>', methods=['POST'])
@login_required
def add_comment(post_id):
    post = Post.query.get_or_404(post_id)
    text = request.form['comment_text']
    user_id = session['user_id']

    new_comment = Comment(text=text, user_id=user_id, post_id=post_id)
    db.session.add(new_comment)
    db.session.commit()

    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(debug=False)