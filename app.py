from flask import Flask, render_template, request, flash, redirect, url_for, session, send_from_directory
from wtforms import Form, PasswordField, StringField, TextAreaField, BooleanField, validators
from db import update_db, query_db
from passlib.hash import sha256_crypt
from functools import wraps
import datetime
from werkzeug.utils import secure_filename
import os
import base64, re

UPLOAD_FOLDER = 'storage/app/'
ALLOWED_EXTENSIONS = set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'])
dt_format = '%Y-%m-%d %H:%M:%S'

app = Flask(__name__)
app.instance_path = os.path.join(app.root_path, 'storage/app')
app.config['DATABASE'] = 'database.db'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


def auth(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' not in session:
            flash('You need to login to access this resource. ', 'warning')
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return wrap


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def upload_file(file, path='uploads', fname=datetime.datetime.today().strftime(dt_format), ext='.png'):
    path = path or app.config['UPLOAD_FOLDER']

    if file and allowed_file(file.filename):
        filename = secure_filename(fname + ext)
        write_dir = os.path.join(app.instance_path, path)
        verify_create_path(write_dir)
        file.save(os.path.join(write_dir, filename))
        return os.path.join('storage', path, filename)


def save_base64(b64_string, path='uploads', fname=datetime.datetime.today().strftime(dt_format), ext='.png'):
    path = os.path.join(app.instance_path, path)
    fname = os.path.join(path, (fname + ext))
    verify_create_path(path)
    with open(fname, "wb") as fh:
        fh.write(base64.decodebytes(b64_string))
        return fname


def verify_create_path(path):
    if not os.path.exists(path):
        os.makedirs(path)


@app.route('/storage/<path:resource>')
def get_resource(resource):
    return send_from_directory(directory=os.path.join(app.instance_path), filename=resource)


@app.route('/')
def home():
    return render_template('pages/home.html')


@app.route('/about')
def about():
    return render_template('pages/about.html')


class LoginForm(Form):
    username = StringField('Username', [validators.DataRequired()])
    password = PasswordField('Password', [validators.DataRequired()])


@app.route('/auth/login', methods=('POST', 'GET'))
def login():
    form = LoginForm(request.form)
    if request.method == 'POST':
        username = form.username.data
        password = form.password.data

        sql = "SELECT * FROM users WHERE username=?"
        result = query_db(sql, (username, ), True)
        if result is not None and sha256_crypt.verify(password, result['password']):
            session['logged_in'] = True
            session['username'] = result['username']
            flash('Successfully logged in as [%s]' % result['username'], category='info')
            return redirect(request.form['intended'] or url_for('dashboard'))
        else:
            flash('Invalid username or password', 'danger')

    return render_template('auth/login.html', form=form)


@app.route('/logout')
@auth
def logout():
    session.clear()
    flash('You are logged out.', 'info')
    app.logger.info(request)
    return redirect(request.referrer)


class RegisterForm(Form):
    name = StringField('Name', [validators.Length(min=4)])
    email = StringField('Email', [validators.Length(min=7), validators.Email()])
    username = StringField('Username', [validators.Length(min=3), validators.DataRequired()])
    password = PasswordField('Password', [
        validators.Length(min=6),
        validators.EqualTo('confirm', message="Passwords do not match")
    ])
    confirm = PasswordField('Confirm Password', [validators.Length(min=6)])


@app.route('/auth/register', methods=('GET', 'POST'))
def register():
    form = RegisterForm(request.form)
    if request.method == 'POST' and form.validate():
        data = form.name.data, form.email.data, form.username.data, sha256_crypt.hash(form.password.data)
        photo = False
        if request.files['photo'] and request.files['photo'].filename:
            file = request.files['photo']
            photo_path = upload_file(file, 'uploads/profiles', form.username.data)
            data = data + (photo_path, )
            photo = True
        else:
            data = data + ('storage/uploads/default.png',)
        # if request.form['photo_thumbnail']:
        #     thumbnail = request.form['photo_thumbnail']
        #     thumbnail_path = save_base64(thumbnail, 'uploads/profiles', form.username.data + '_thumbnail')
        #     data = data + (thumbnail_path,)
        # else:
        #     if photo:
        #         data = data + (photo_path, )
        #     else:
        #         data = data + ('storage/uploads/default.png', )

        sql = 'INSERT INTO users (name, email, username, password, photo) VALUES (?, ?, ?, ?, ?, ?)'
        app.logger.info(form)
        update_db(sql, data)
        msg = "You successfully signed up. You can now sign in"
        flash(msg, 'success')
        return redirect(url_for('login', next=request.form['intended']))

    return render_template('auth/register.html', form=form)


@app.route('/dashboard')
@auth
def dashboard():
    docs = query_db('SELECT * FROM articles WHERE NOT deleted_at IS NOT NULL')
    return render_template('pages/dashboard.html', articles=docs)


class ArticleForm(Form):
    title = StringField('Title', [validators.DataRequired(), validators.Length(min=5)])
    body = TextAreaField('Content', [validators.DataRequired(), validators.Length(min=10)])
    published = BooleanField('Publish Now', [validators.DataRequired()], default='y')


@app.route('/articles')
def articles():
    docs = query_db('SELECT * FROM articles WHERE published=1 AND deleted_at IS NULL')
    return render_template('pages/articles/articles.html', articles=docs)


@app.route('/article/<string:key>/')
@auth
def article(key):
    doc = query_db('SELECT * FROM articles WHERE id=?', (key, ), True)
    return render_template('pages/articles/article.html', article=doc)


@app.route('/articles/create', methods=('GET', 'POST'))
@auth
def create_article():
    form = ArticleForm(request.form)
    if request.method == 'POST' and form.validate():
        title = form.title.data
        body = form.body.data
        pub_status = 1 if form.published.data else 0
        author = session['username']
        pub_date = datetime.datetime.today().strftime(dt_format)

        sql = "INSERT INTO articles(title, body, author, created_at, published) VALUES (?, ?, ?, ?, ?)"

        update_db(sql, (title, body, author, pub_date, pub_status))
        flash('Article created successfully!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('pages/articles/create.html', form=form)


@app.route('/articles/update/<int:key>', methods=('GET', 'POST'))
@auth
def update_article(key):
    form = ArticleForm(request.form)
    doc = query_db('SELECT * FROM articles WHERE id=? AND author=?', (key, session['username']), True)
    if doc:
        form.title.data = doc['title']
        form.body.data = doc['body']
        form.published.data = doc['published']
        if request.method == 'POST':
            title = request.form['title']
            body = request.form['body']
            app.logger.info(request.form['published'])
            pub_status = request.form['published']
            updated = datetime.datetime.today().strftime(dt_format)
            if title and body:
                sql = "UPDATE articles SET title=?, body=?, published=?, updated_at=? WHERE id=?"

                update_db(sql, (title, body, pub_status, updated, key))
                flash('Article updated successfully!', 'info')
                return redirect(url_for('dashboard'))
            flash('One or two entries are empty or invalid!', 'warning')

            form.title.data = title
            form.body.data = body
            form.published.data = pub_status

        return render_template('pages/articles/update.html', form=form, article=doc)
    flash('Record not found!', 'warning')
    return redirect(request.referrer)


@app.route('/articles/published')
@auth
def published_articles():
    docs = query_db('SELECT * FROM articles WHERE  published=1')
    return render_template('pages/articles/published.html', articles=docs)


@app.route('/articles/withhold/<int:key>', methods=('POST',))
@auth
def withhold_article(key):
    doc = query_db('SELECT published FROM articles WHERE  id=?', (key,), True)
    if doc:
        updated = datetime.datetime.today().strftime(dt_format)
        update_db('UPDATE articles SET published=?, updated_at=? WHERE id = ?',
                  (0 if doc['published'] == 1 else 1, updated, key))
        flash('Article publication status updated.', 'success')
    return redirect(request.referrer)


@app.route('/articles/trash')
@auth
def deleted_articles():
    docs = query_db('SELECT * FROM articles WHERE deleted_at IS NOT NULL')
    return render_template('pages/articles/trashed.html', articles=docs)


@app.route('/articles/trash/<int:key>', methods=('POST', ))
@auth
def delete_article(key):
    rec = query_db('SELECT * FROM articles WHERE id=?', (key,), True)
    if rec and rec['author'] == session['username']:
        updated = datetime.datetime.today().strftime(dt_format)
        update_db('UPDATE articles SET deleted_at=? WHERE id=?', (updated, key))
        flash('Article moved to trash', category='info')
    else:
        flash('Operation not allowed', category='warning')
    return redirect(request.referrer)


@app.route('/articles/restore/<int:key>', methods=('POST', ))
@auth
def restore_article(key):
    rec = query_db('SELECT * FROM articles WHERE id=? AND author=?', (key, session['username']), True)
    if rec:
        update_db('UPDATE articles SET deleted_at=? WHERE id=?', (None, key))
        flash('Article restored to successfully', category='info')
    else:
        flash('Operation not allowed', category='warning')
    return redirect(request.referrer)


@app.route('/articles/delete/<int:key>', methods=('POST', ))
@auth
def permanently_delete_article(key):
    rec = query_db('SELECT * FROM articles WHERE id=?', (key,), True)
    if rec and rec['author'] == session['username']:
        update_db('DELETE FROM articles WHERE id=?', (key,))
        flash('Article permanently deleted', category='info')
    else:
        flash('Operation not allowed', category='warning')
    return redirect(request.referrer)


if __name__ == '__main__':
    app.secret_key = 'lksd057&(*)($*OJKLJDFJkjs;jksljdfkuijjld=='
    app.run(debug=True)
