from flask import Flask, render_template, redirect, url_for, flash, abort
from flask_bootstrap import Bootstrap
from functools import wraps
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import *
from flask_gravatar import Gravatar

def admin_only(f):
    @wraps(f)
    def df(*args, **kwargs):
        if current_user.id != 1:
            return abort(403)
        return f(*args, **kwargs)
    return df

app = Flask(__name__)
login_manager = LoginManager(app)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

##CONFIGURE TABLES

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)

    author = relationship("User", back_populates="posts")
    comments = relationship('Comment', back_populates="parent_post")


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key = True)
    name = db.Column(db.String(24), nullable = False)
    email = db.Column(db.String(250), nullable = False)
    password = db.Column(db.String(250), nullable = False)
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="comment_author")

class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key = True)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    comment_author = relationship("User", back_populates="comments")    
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    parent_post = relationship("BlogPost", back_populates="comments")
    text = db.Column(db.Text, nullable = False)

with app.app_context() as con:
    db.create_all()

gravatar = Gravatar(
    app,
    size = 100,
    rating = "g", default = "retro", force_default = False,
    force_lower = False, use_ssl = False, base_url = None
)

@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts, logged_in = current_user.is_authenticated)


@app.route('/register', methods = ["GET", "POST"])
def register():
    form = RegisterForm()
    error = None
    if form.validate_on_submit():
        reg_user = User.query.filter_by(email = form.email.data).first()
        if reg_user:
            error = "You've already Signed Up with that email. Login Instead."
        else:
            new_user = User(
                name = form.name.data,
                email = form.email.data,
                password = generate_password_hash(form.password.data, "pbkdf2:sha256", salt_length=10)
            )
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect(url_for("get_all_posts"))
    return render_template("register.html", form = form, err = error)


@app.route('/login', methods = ["GET", "POST"])
def login():
    form = LoginForm()
    error = None
    email = form.email.data
    password = form.password.data
    if form.validate_on_submit():
        user = User.query.filter_by(email = email).first()
        if user:
            if check_password_hash(user.password, password):
                login_user(user)
                return redirect(url_for("get_all_posts"))
            else:
                error = "The entered password is incorrect."
        else:
            error = "The entered email does not exist."
    return render_template("login.html", form = form, err = error)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods = ["GET", "POST"])
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    c_form = CommentForm()
    err = None
    if c_form.validate_on_submit():
        if current_user.is_authenticated:
            new_comm = Comment(
                text = c_form.comment.data,
                comment_author = current_user,
                parent_post = requested_post
            )
            db.session.add(new_comm)
            db.session.commit()
        else:
            err = "You need to Register or Login to Comment."
    return render_template("post.html", err = err, form = c_form, post=requested_post, logged_in = current_user.is_authenticated)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods = ["GET","POST"])
@admin_only
def add_new_post():
    form = BlogForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, logged_in = current_user.is_authenticated)


@app.route("/edit-post/<int:post_id>", methods = ["GET", "POST"])
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = BlogForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author.name,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form, logged_in = current_user.is_authenticated)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(host='127.0.0.1', port=8000, debug = True)
