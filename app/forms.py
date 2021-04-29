from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from flask_login import current_user
from wtforms import StringField, PasswordField, SubmitField, BooleanField, RadioField, TextAreaField, SelectField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from app.models import User

class AddUserForm(FlaskForm):
    add_username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    role = BooleanField('Admin')
    gender = RadioField('Gender', choices=[('male', 'Male'), ('female', 'Female')])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    add_submit = SubmitField('Add')

    def validate_add_username(self, add_username):
        user = User.query.filter_by(username=add_username.data).first()
        # if user already in database
        if user:
            raise ValidationError('That username is taken. Please choose a different one')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        # if user already in database
        if user:
            raise ValidationError('That email is taken. Please choose a different one')

class DeleteUserForm(FlaskForm):
    delete_username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    delete_submit = SubmitField('Delete')

    def validate_delete_username(self, delete_username):
        user = User.query.filter_by(username=delete_username.data).first()
        # if user not exist
        if not user:
            raise ValidationError('Username not exist in database')

class RequestForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    content = TextAreaField('Content', validators=[DataRequired()])
    submit = SubmitField('Send Request')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')


class UpdateProfileForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    profile_picture = FileField('Update Profile Picture', validators=[FileAllowed( ['png', '.jpeg', 'jpg', 'tif', 'tiff'] )])
    submit = SubmitField('Update')

    def validate_username(self, username):
        if username.data != current_user.username:
            user = User.query.filter_by(username=username.data).first()
            # if user already in database
            if user:
                raise ValidationError('That username is taken. Please choose a different one')

    def validate_email(self, email):
        if email.data != current_user.email:
            user = User.query.filter_by(email=email.data).first()
            # if user already in database
            if user:
                raise ValidationError('That email is taken. Please choose a different one')

class ArticleForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    content = TextAreaField('Content', validators=[DataRequired()])
    category = StringField('Category', validators=[DataRequired()])
    submit = SubmitField('Post')
