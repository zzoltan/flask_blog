from flask import Flask, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship

from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, Commentform
from flask_gravatar import Gravatar
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, Email
from functools import wraps
from flask import abort

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)
gravatar = Gravatar(app, size=100, rating='g', default='retro', force_default=False, force_lower=False, use_ssl=False, base_url=None)


##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# create admin only decorator
def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
#         if id is not 1 then return abort with 403 error
        if current_user.id != 1:
            return abort(403)
#         otherwise continue with route function
        return f(*args, **kwargs)
    return decorated_function

login_manager = LoginManager()
login_manager.init_app(app)



@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)



##CONFIGURE TABLES

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author = db.Column(db.String(250), nullable=False)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
#     create Foreign key, "users.id" the users refers to the table name of User
    author_id = db.Column(db.Integer, db.ForeignKey("user.id"))
#     create reference to the User object, the posts refers to the posts property in teh User class
    author = relationship("User", back_populates="posts")
    comment = relationship("Comment", back_populates="blog_commented")

# creating the Register forms

class RegisterUser(FlaskForm):
    email = StringField("Please enter a valid email: ", validators=[DataRequired("Field is empty"), Email("Please enter a valid emial!")])
    name = StringField("Please enter your name: ", validators=[DataRequired("Field is empty")])
    password = PasswordField("Please enter your password: ", validators=[DataRequired("Field cannot be empty!")])
    submit = SubmitField("Register")

# Creating Logon form

class LoginUser(FlaskForm):
    email = StringField("Please enter your email/user name: ", validators=[DataRequired("Field cannot be empty!!"), Email("Please enter a valid email!")])
    password = PasswordField("Please enter your password: ", validators=[DataRequired("Field cannot be empty!")])
    submit = SubmitField("Login")




# creating the User class for the database
class User(UserMixin, db.Model):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
    # This will act like a List of BlogPost objects attached to each User
    # The author refers to the author property in the BlogPost class
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates = "user_commented")

class Comment(db.Model):
    __tablename__="comment"
    id = db.Column(db.Integer,primary_key=True)
    comments = db.Column(db.Text, nullable=False)
    comments_owner_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    commented_blog = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    user_commented = relationship("User", back_populates ="comments")
    blog_commented = relationship("BlogPost", back_populates="comment")

# db.create_all()


@app.route('/', methods=["GET","POST"])
def get_all_posts():
    posts = BlogPost.query.all()
    name = request.args.get("name")
    id = request.args.get("id")
    logged_in = request.args.get("logged_in")
    print(id)
    return render_template("index.html", all_posts=posts, name =name, logged_in = logged_in, id=id)


@app.route('/register', methods=["POST", "GET"])
def register():
    form = RegisterUser()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        name = form.name.data
        new_user = User(
            email = email,
            password = generate_password_hash(password, method="pbkdf2:sha256", salt_length=8),
            name = name
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for("get_all_posts", logged_in = current_user.is_authenticated, name = current_user.name))
    return render_template("register.html", form=form, logged_in = current_user.is_authenticated)


@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginUser()

    if form.validate_on_submit():
        user_name = form.email.data
        password = form.password.data

        user = User.query.filter_by(email=user_name).first()
        if not user:
            flash("Email doesn't exist, please register first!")
            return redirect(url_for("register"))
        elif not check_password_hash(user.password, password):
            flash("The password is incorrect!")
            return redirect(url_for("login"))
        else:
            login_user(user)
            return redirect(url_for("get_all_posts", logged_in = current_user.is_authenticated, name=current_user.name, id=user.id))


    return render_template("login.html", form = form, logged_in = current_user.is_authenticated)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    form = Commentform()

    id = request.args.get("user_id")
    requested_post = BlogPost.query.get(post_id)
    if form.validate_on_submit():
        new_comment=Comment(
            comments = form.comments.data,
            user_commented=current_user,
            blog_commented = requested_post
        )
        db.session.add(new_comment)
        db.session.commit()


    # print(current_user.is_authenticated)
    # print(requested_post.user_commented.name)
    # return render_template("post.html", form = form, post=requested_post, logged_in = current_user.is_authenticated, name=current_user.name, id=id)
    return render_template("post.html", form = form, post=requested_post, logged_in = current_user.is_authenticated)



@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
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
    return render_template("make-post.html", form=form, logged_in = current_user.is_authenticated, name = current_user.name)


@app.route("/edit-post/<int:post_id>")
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
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form, is_edit=True, logged_in = current_user.is_authenticated, name=current_user.name)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(debug=True)
