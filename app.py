import os

from datetime import datetime

from sqlalchemy import or_, and_
from flask_wtf.csrf import CSRFProtect
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, jsonify
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
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


    def __repr__(self):
        return f"User('{self.username}',)"


class Friendship(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # user.id
    friend_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # user.id
    status = db.Column(db.String(20), default='pending')  # pending, accepted, rejected
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    user = db.relationship('User', foreign_keys=[user_id], backref='friendships')
    friend = db.relationship('User', foreign_keys=[friend_id], backref='friend_of')

    __table_args__ = (
        db.UniqueConstraint('user_id', 'friend_id', name='unique_friendship'),
    )


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


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    date_sent = db.Column(db.DateTime, default=db.func.now())  # data_sent → date_sent
    # Кто отправил
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    sender = db.relationship('User', foreign_keys=[sender_id], backref='sent_messages')
    # Кто получил
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    receiver = db.relationship('User', foreign_keys=[receiver_id], backref='received_messages')  # reciiver → receiver

    def __repr__(self):
        return f"Message('{self.text}', from {self.sender_id} to {self.receiver_id})"


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
    return redirect(url_for('profile'))



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
            return redirect(url_for('profile'))
        else:
            return render_template('login.html', error='Неверный логин или пароль')



@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))



@app.route('/profile')
@login_required
def profile():
    try:
        user_id = session['user_id']
        user_from_db = User.query.get(user_id)

        if user_from_db:
            return render_template('profile.html', user=user_from_db)
        else:
            return redirect(url_for('login'))

    except Exception as e:
        print(f"Ошибка в профиле: {e}")  # Это покажет ошибку в консоли
        return redirect(url_for('index'))



@app.route('/all_users')
@login_required
def all_users():
    users = User.query.filter(User.id != session['user_id']).all()  # Все кроме себя
    return render_template('all_users.html', users=users)


@app.route('/search')
@login_required
def search():
    query = request.args.get('q', '')
    if query:
        users = User.query.filter(User.username.ilike(f'%{query}%')).all()
    else:
        users = []
    return render_template('search.html', users=users, query=query)


# Отправка запроса в друзья
@app.route('/add_friend/<int:friend_id>', methods=['POST'])
@login_required
def add_friend(friend_id):
    current_user_id = session['user_id']

    # Проверяем, не отправили ли уже запрос
    existing = Friendship.query.filter_by(
        user_id=current_user_id,
        friend_id=friend_id
    ).first()

    if not existing:
        new_friendship = Friendship(
            user_id=current_user_id,
            friend_id=friend_id,
            status='pending'
        )
        db.session.add(new_friendship)
        db.session.commit()

    return redirect(url_for('search'))


# Принятие запроса в друзья
@app.route('/accept_friend/<int:friendship_id>', methods=['POST'])
@login_required
def accept_friend(friendship_id):
    friendship = Friendship.query.get_or_404(friendship_id)

    # Проверяем, что запрос адресован текущему пользователю
    if friendship.friend_id == session['user_id']:
        friendship.status = 'accepted'
        db.session.commit()

    return redirect(url_for('friends'))


# Страница друзей
@app.route('/friends')
@login_required
def friends():
    user_id = session['user_id']

    # Запросы в друзья, отправленные нам
    incoming_requests = Friendship.query.filter_by(
        friend_id=user_id,
        status='pending'
    ).all()

    # Наши исходящие запросы
    outgoing_requests = Friendship.query.filter_by(
        user_id=user_id,
        status='pending'
    ).all()

    # Принятые друзья
    accepted_friends = Friendship.query.filter(
        ((Friendship.user_id == user_id) | (Friendship.friend_id == user_id)) &
        (Friendship.status == 'accepted')
    ).all()

    # Преобразуем в список пользователей
    friends_list = []
    for friendship in accepted_friends:
        if friendship.user_id == user_id:
            friends_list.append(friendship.friend)
        else:
            friends_list.append(friendship.user)

    return render_template('friends.html',
                           incoming_requests=incoming_requests,
                           outgoing_requests=outgoing_requests,
                           friends=friends_list)


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
        post.likes.remove(user) # Дизлайк
        liked = False
    else:
        post.likes.append(user)  # Лайк
        liked = True

    db.session.commit()

    return jsonify({
        'likes_count': len(post.likes),
        'liked': liked
    })



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


@app.route('/messages')
@login_required
def message_list():
    users = User.query.filter(User.id != session['user_id']).all()  # Все кроме себя
    return render_template('message_list.html', users=users)


@app.route('/message/<username>', methods=['GET', 'POST'])
@login_required
def message(username):
    # Находим пользователя, с которым переписываемся
    other_user = User.query.filter_by(username=username).first_or_404()
    current_user_id = session['user_id']
    current_user_obj = User.query.get(current_user_id)

    if request.method == "POST":
        text = request.form.get("message_text")
        if text:
            new_message = Message(
                text=text,
                sender_id=current_user_id,
                receiver_id=other_user.id
            )
            db.session.add(new_message)
            db.session.commit()

    # Получаем всю переписку между текущим пользователем и other_user
    message = Message.query.filter(
        or_(
            and_(Message.sender_id == current_user_id, Message.receiver_id == other_user.id),
            and_(Message.sender_id == other_user.id, Message.receiver_id == current_user_id)
        )
    ).order_by(Message.date_sent).all()

    return render_template('message.html',
                           message=message,
                           other_user=other_user,
                           current_user=current_user_obj)


if __name__ == '__main__':
    app.run(debager=False)