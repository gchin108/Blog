from flask import Flask, render_template, redirect, url_for, flash, abort, request
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import datetime as dt
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
import secrets
from functools import wraps
import hashlib
import urllib.parse
import smtplib
import os
from dotenv import load_dotenv


# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16)

ckeditor = CKEditor(app)
Bootstrap(app)

# CONNECT TO DB
print(os.getenv('blog_local'))
if os.getenv('blog_local') == 'TRUE':
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')



db = SQLAlchemy(app)

# Flask Login
login_manager = LoginManager()
login_manager.init_app(app)


# CONFIGURE TABLES
class User(db.Model, UserMixin):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(100))
    posts = relationship('BlogPost', back_populates='author')
    comments = relationship('Comment', back_populates='comment_author')

    def __repr__(self):
        return f'<User: {self.name}>'

    def has_the_right_password(self, password):
        return check_password_hash(self.password, password)


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    author = relationship('User', back_populates='posts')
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    comments = relationship('Comment', back_populates='parent_post')


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    comment_author = relationship('User', back_populates='comments')
    post_id = db.Column(db.Integer, db.ForeignKey('blog_posts.id'))
    parent_post = relationship('BlogPost', back_populates='comments')
    date = db.Column(db.String(250), nullable=False)
    text = db.Column(db.Text, nullable=False)


with app.app_context():
    db.create_all()


def get_gravatar_url(email):
    email_hash = hashlib.md5(email.lower().encode('utf-8')).hexdigest()
    gravatar_params = urllib.parse.urlencode({'d': 'identicon', 's': str(100)})
    return f"https://www.gravatar.com/avatar/{email_hash}?{gravatar_params}"


def admin_only(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        if current_user.id != 1:
            abort(403)  # Return a forbidden status code if the user is not the admin
        return func(*args, **kwargs)

    return decorated_function


@app.route('/')
def home():
    posts = BlogPost.query.all()
    today = dt.today()
    return render_template("index.html", all_posts=posts, year=today.year)


@app.route('/register', methods=['GET', 'POST'])
def register():
    register_form = RegisterForm()
    if register_form.validate_on_submit():
        new_user = User()
        new_user.email = register_form.email.data
        new_user.password = generate_password_hash(register_form.password.data, method='pbkdf2:sha256', salt_length=8)
        new_user.name = register_form.name.data
        all_users = User.query.all()
        print(all_users)

        if User.query.filter_by(email=register_form.email.data).first():
            flash("This email already exist in our database. Please login")
            return redirect(url_for('login'))
        else:
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect(url_for('home'))

    return render_template("register.html", form=register_form, year=dt.today().year)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(str(user_id))


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        # Find the user by email
        user = User.query.filter_by(email=email).first()

        if user:
            if user.has_the_right_password(password):
                login_user(user)
                return redirect(url_for('home'))
            else:
                flash("Password is incorrect.")
                return redirect(url_for('login'))
        else:
            flash("This email doesn't exist. Please try again.")
            return redirect(url_for('login'))

    return render_template('login.html', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route("/post/<int:post_id>", methods=['POST', 'GET'])
def show_post(post_id):
    gravatar = Gravatar(app, size=100, rating='g', default='retro', force_default=False, force_lower=False,
                        use_ssl=False, base_url=None)
    requested_post = BlogPost.query.get(post_id)

    form = CommentForm()

    if form.validate_on_submit():
        if not current_user.is_authenticated:

            flash("You need to login to comment")
            return redirect(url_for('login'))
        else:
            comments = Comment(comment_author=current_user, text=form.comment.data, parent_post=requested_post,
                               date=dt.today().strftime("%B %d, %Y"))
            db.session.add(comments)
            db.session.commit()
            return redirect(url_for('show_post', post_id=post_id))

    return render_template("post.html", post=requested_post, form=form, gravatar=gravatar, year=dt.today().year)


@app.route("/about")
def about():
    return render_template("about.html", year=dt.today().year)


email2 = os.getenv('email2')
key = os.getenv('email2_key')
email1 = os.getenv('email1')
print(f'email1={email1}, email2={email2}')


def send_mail(message):
    with smtplib.SMTP("smtp.gmail.com") as connection:
        connection.starttls()
        connection.login(user=email2, password=key)
        connection.sendmail(from_addr=email2, to_addrs=email1,
                            msg=f"Subject:Hello\n\n{message}")


@app.route("/contact", methods=["POST", "GET"])
def contact():
    if request.method == "POST":
        print(f'request is POST')

        data = request.form
        message = f'Name: {data["name"]}\nEmail: {data["email"]}\nPhone: {data["phone"]}\nMessage:\n{data["message"]}'
        send_mail(message)
        return render_template("contact.html", is_sent=True)
    return render_template("contact.html", year=dt.today().year)


@app.route("/new-post", methods=['GET', 'POST'])
@login_required
@admin_only
def add_new_post():
    print(current_user.name)
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=dt.today().strftime("%B %d, %Y")
        )
        print(form.body.data)
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("home"))
    return render_template("make-post.html", form=form, is_edit=False, year=dt.today().year)


@app.route("/edit-post/<int:post_id>", methods=['POST', 'GET'])
@login_required
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = current_user
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form, is_edit=True, year=dt.today().year)


@app.route("/delete/<int:post_id>")
@login_required
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('home'))


@app.route("/post/<int:post_id>/comment/delete/<int:comment_id>")
@admin_only
def delete_comment(post_id, comment_id):
    comment_to_delete = Comment.query.get(comment_id)
    print(comment_to_delete.text)
    db.session.delete(comment_to_delete)
    db.session.commit()
    return redirect(url_for('show_post', post_id=post_id))


if __name__ == "__main__":
    app.run(debug=True)
