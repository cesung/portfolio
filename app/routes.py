import os
import uuid
import markdown
import markdown2
import requests
from PIL import Image
from functools import wraps
from threading import Thread
from app import app, db, bcrypt, mail
from datetime import datetime, timedelta
from flask_mail import Message
from app.models import User, Article, Quote
from flask import render_template, url_for, flash, redirect, request, abort
from flask_login import login_user, current_user, logout_user, login_required
from app.forms import (AddUserForm, DeleteUserForm, LoginForm, UpdateProfileForm,
                        ArticleForm, RequestResetForm, ResetPasswordForm)

APP_ROOT = app.root_path
PROFILE_PICTURE_PATH = os.path.join(APP_ROOT, 'static/profile_image')
POST_MEDIA_PATH = os.path.join(APP_ROOT, 'static/post_media')

ARTICLES_PER_PAGE = 5
ROLE_ADMIN = 'admin'
ROLE_GENERAL = 'general'

def admin_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if current_user.is_anonymous or current_user.role == ROLE_GENERAL:
            flash('You need to be an admin to view this page.', 'danger')
            return redirect(url_for('login'))
        if current_user.role == ROLE_ADMIN:
            return f(*args, **kwargs)

    return wrap

@app.route('/')
@app.route('/home')
@app.route('/index')
@app.route('/about')
def about():
    return render_template('about.html', title='About Me')

@app.route('/posts')
def posts():
    page = request.args.get('page', 1, type=int)
    all_articles = Article.query.all()
    articles = Article.query.order_by(Article.date_posted.desc()).paginate(per_page=ARTICLES_PER_PAGE, page=page)

    quote = Quote.query.first()
    tomorrow_eight = datetime.combine(quote.date.date() + timedelta(hours=24), datetime.min.time()) + timedelta(hours=8)
    now = datetime.utcnow()
    if now > tomorrow_eight:
        url = "https://api.quotable.io/random"
        response = requests.get(url)
        quote.date = now
        quote.content = response.json()['content']
        db.session.commit()

    for article in articles.items:
        article.content = markdown2.markdown(article.content, extras=[
            "fenced-code-blocks",
            "code-friendly",
            "cuddled-lists",
            "tables",
            "task_list",
            "footnotes",
            "xml",
            "target-blank-links",
            "toc",
        ])

    return render_template('posts.html', title='Posts', articles=articles, all_articles=all_articles, cur_time=datetime.utcnow(), quote=quote)

@app.route('/album')
def album():
    return render_template('album.html', title='Album')

@app.route('/manage', methods=['GET', 'POST'])
@admin_required
@login_required
def manage():
    add_user_form = AddUserForm()

    # on add user form submit
    if add_user_form.add_submit.data and add_user_form.validate():

        # hash the user password and decode to string format
        hashed_password = bcrypt.generate_password_hash(add_user_form.password.data).decode('utf-8')
        # create a new user
        user = User(username=add_user_form.add_username.data, \
                    role=ROLE_ADMIN if add_user_form.role.data == True else ROLE_GENERAL, \
                    gender=add_user_form.gender.data, \
                    email=add_user_form.email.data, \
                    password=hashed_password, profile_picture='man.png' if add_user_form.gender.data == 'male' else 'woman.png')
        # commit to database
        db.session.add(user)
        db.session.commit()

        flash(f'Account {add_user_form.add_username.data} has been created!', 'success')
        app.logger.info(f'Account create for {add_user_form.add_username.data}')

        # redirect to login page
        return redirect(url_for('login'))

    delete_user_form = DeleteUserForm()

    # on delete user form submit
    if delete_user_form.delete_submit.data and delete_user_form.validate():
        user = User.query.filter_by(username=delete_user_form.delete_username.data).first_or_404()

        for post in user.posts:
            db.session.delete(post)
            db.session.commit()

        db.session.delete(user)
        db.session.commit()

        flash(f'Account {delete_user_form.delete_username.data} has been deleted!', 'success')
        return redirect( url_for('manage') )


    return render_template('manage.html', title='Manage', add_user_form=add_user_form, delete_user_form=delete_user_form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    # redirect to posts page if user already login
    if current_user.is_authenticated:
        return redirect(url_for('posts'))

    login_form = LoginForm()

    if login_form.validate_on_submit():

        # check if user exist. return None if username not in database
        user = User.query.filter_by(username=login_form.username.data).first()

        # if user exist and password match
        if user and bcrypt.check_password_hash(user.password, login_form.password.data):
            login_user(user, remember=login_form.remember.data)
            desired_page = request.args.get('next')
            return redirect(desired_page) if desired_page else redirect(url_for('posts'))
        else:
            flash(f'Login unsuccessful. Please check username and password', 'danger')
            # do nothing
            # render login.html to user

    return render_template('login.html', title='Login', form=login_form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/account', methods=['GET', 'POST'])
@login_required
def account():
    update_profile_form = UpdateProfileForm()

    if update_profile_form.validate_on_submit():

        # if user update his/her profile picture
        if update_profile_form.profile_picture.data:

            # delete user's old profile picture
            if not (current_user.gender == 'male' and current_user.profile_picture == 'man.png' ) and \
               not (current_user.gender == 'female' and current_user.profile_picture == 'woman.png'):
                os.remove( os.path.join(PROFILE_PICTURE_PATH, current_user.profile_picture ) )

            # get new profile picture from the update profile form
            profile_picture = update_profile_form.profile_picture.data

            # hash the uploaed picture
            hex_uid = uuid.uuid4().hex
            _, file_name_extension = os.path.splitext(profile_picture.filename)
            file_name = f'{hex_uid}.{file_name_extension}'

            # resize the uploaded picture
            picture_size = (125, 125)
            i = Image.open(profile_picture)
            i.thumbnail(picture_size)
            i.save( os.path.join(PROFILE_PICTURE_PATH, file_name) )

            # update user's profile picture
            current_user.profile_picture = file_name

        current_user.username =  update_profile_form.username.data
        current_user.email = update_profile_form.email.data
        db.session.commit()
        flash('Your account has been successfully updated!', 'success')
        return redirect(url_for('account'))

    elif request.method == 'GET':
        update_profile_form.username.data = current_user.username
        update_profile_form.email.data = current_user.email

    profile_picture = url_for('static', filename=f'profile_image/{current_user.profile_picture}')
    return render_template('account.html',
                            title='Profile',
                            profile_picture=profile_picture,
                            form=update_profile_form)

@app.route('/posts/create', methods=['GET', 'POST'])
@login_required
def create_article():
    article_form = ArticleForm()

    if article_form.validate_on_submit():

        article = Article(title=article_form.title.data, content=article_form.content.data, category=article_form.category.data, author=current_user)
        db.session.add(article)
        db.session.commit()

        flash('Your article has been created!', 'success')

        return redirect(url_for('posts'))

    return render_template('create_article.html', title='New Article',
                            form=article_form, legend='New Article')

@app.route('/posts/<int:article_id>')
def article(article_id):
    article = Article.query.get_or_404(article_id)
    return render_template('article.html', title=article.title, article=article, content=markdown2.markdown(article.content, extras=[
        "fenced-code-blocks",
        "code-friendly",
        "cuddled-lists",
        "tables",
        "task_list",
        "footnotes",
        "xml",
        "target-blank-links",
        "toc",
    ]), cur_time=datetime.utcnow())

@app.route('/posts/<int:article_id>/update', methods=['GET', 'POST'])
@login_required
def update_article(article_id):
    article = Article.query.get_or_404(article_id)

    if article.author != current_user:
        abort(403)

    article_form = ArticleForm()
    if article_form.validate_on_submit():
        article.title = article_form.title.data
        article.content = article_form.content.data
        article.category = article_form.category.data
        article.date_posted = datetime.utcnow()
        db.session.commit()
        flash('Your article has been updated!', 'success')
        return redirect( url_for('article', article_id=article.id) )

    elif request.method == 'GET':
        article_form.title.data = article.title
        article_form.content.data = article.content
        article_form.category.data = article.category

    return render_template('create_article.html', title='Update Article',
                            form=article_form, legend='Update Article')

@app.route('/posts/<int:article_id>/delete', methods=['POST'])
@login_required
def delete_article(article_id):
    article = Article.query.get_or_404(article_id)

    if article.author != current_user and current_user.role != ROLE_ADMIN:
        abort(403)

    db.session.delete(article)
    db.session.commit()

    flash('Your article has been deleted!', 'success')
    return redirect( url_for('posts') )


@app.route('/user/<string:username>')
def user_posts(username):
    page = request.args.get('page', 1, type=int)
    user = User.query.filter_by(username=username).first_or_404()
    articles = Article.query.filter_by(author=user) \
        .order_by(Article.date_posted.desc()) \
        .paginate(per_page=ARTICLES_PER_PAGE, page=page)

    for article in articles.items:
        article.content = markdown2.markdown(article.content, extras=[
            "fenced-code-blocks",
            "code-friendly",
            "cuddled-lists",
            "tables",
            "task_list",
            "footnotes",
            "xml",
            "target-blank-links",
            "toc",
        ])

    return render_template('user_posts.html', title='Articles', articles=articles, \
                            user=user, cur_time=datetime.utcnow())

@app.route('/search_article/', methods=['GET', 'POST'])
def search_article():
    article_title = request.form['article_title']

    try:
        article = Article.query.filter_by(title=article_title)[0]
    except:
        return redirect(url_for('posts'))

    return render_template('article.html', title=article.title, article=article, content=markdown2.markdown(article.content, extras=[
        "fenced-code-blocks",
        "code-friendly",
        "cuddled-lists",
        "tables",
        "task_list",
        "footnotes",
        "xml",
        "target-blank-links",
        "toc",
    ]), cur_time=datetime.utcnow())


def async_send_email(app, msg):
    with app.app_context():
        print('in')
        mail.send(msg)

def send_reset_email(user):
    token = user.get_reset_token()
    msg = Message('Password Reset Request',
                    sender='noreply@demo.com',
                    recipients=[user.email])
    msg.body = f'''To reset your password, visit the following link:
{url_for('reset_token', token=token, _external=True)}

If you did not make this request then simply ignore thios email and no change will be made.
'''
    thread = Thread(target=async_send_email, args=[app, msg])
    thread.start()

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_request():
    # redirect to posts page if user already login
    if current_user.is_authenticated:
        return redirect(url_for('posts'))

    reset_request_form = RequestResetForm()

    if reset_request_form.validate_on_submit():
        user = User.query.filter_by(email=reset_request_form.email.data).first()
        send_reset_email(user)
        flash('An email has been sent with instructions to reset your password', 'info')
        return redirect(url_for('login'))

    return render_template('reset_request.html', title='Reset Password', form=reset_request_form)

@app.route('/reset_password/<string:token>', methods=['GET', 'POST'])
def reset_token(token):
    # redirect to posts page if user already login
    if current_user.is_authenticated:
        return redirect(url_for('posts'))

    user = User.verify_reset_token(token)
    if not user:
        flash('That is an invaliad or expired token.', 'warning')
        return redirect(url_for('reset_request'))

    reset_password_form = ResetPasswordForm()

    if reset_password_form.validate_on_submit():

        # hash the user password and decode to string format
        hashed_password = bcrypt.generate_password_hash(reset_password_form.password.data).decode('utf-8')
        user.password = hashed_password
        db.session.commit()

        flash(f'Your password has been updated', 'success')

        # redirect to login page
        return redirect(url_for('login'))

    return render_template('reset_token.html', title='Reset Password', form=reset_password_form)
