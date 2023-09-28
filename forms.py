from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, EmailField
from wtforms.validators import DataRequired, URL, Email
from flask_ckeditor import CKEditorField

##WTForm
class RegisterForm(FlaskForm):
    name = StringField("Name", [DataRequired()])
    email = EmailField("Email", [DataRequired(), Email()])
    password = PasswordField("Password", [DataRequired()])
    submit = SubmitField("SIGN ME UP!")

class LoginForm(FlaskForm):
    email = EmailField("Email", [DataRequired(), Email()])
    password = PasswordField("Password", [DataRequired()])
    submit = SubmitField("Login")

class BlogForm(FlaskForm):
    title = StringField("Blog Post Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    author = StringField("Your Name", validators=[DataRequired()])
    img_url = StringField("Blog Image URL", validators=[DataRequired(), URL()])
    body = CKEditorField("Blog Content", validators=[DataRequired()])
    submit = SubmitField("Submit Post")

class CommentForm(FlaskForm):
    comment = CKEditorField("Comment", validators=[DataRequired()])
    submit = SubmitField("SUBMIT COMMENT")
