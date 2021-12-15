import datetime

from flask import Flask, request, render_template, redirect, flash, url_for
from flask_sqlalchemy import SQLAlchemy
from forms import RegisterForm
from flask_login import UserMixin, current_user, login_user, logout_user, login_required, LoginManager
from werkzeug.security import generate_password_hash, check_password_hash
import os
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor, CKEditorField
from sqlalchemy.orm import relationship


app = Flask(__name__)
ckeditor = CKEditor(app)


app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
Bootstrap(app)

# CONNECTING TO DATABASE
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL1', 'sqlite:///todo.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Flask LOGIN
login_manager = LoginManager()
login_manager.init_app(app)


class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key = True)
    name = db.Column(db.String(250), nullable = False)
    email = db.Column(db.String(300), nullable = False, unique = True)
    password = db.Column(db.String(250), nullable = False)

    lists = relationship('List', back_populates = 'user')


class List(db.Model):
    __tablename__ = 'lists'
    id = db.Column(db.Integer, primary_key = True)
    name = db.Column(db.String(250), nullable = False)

    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    user = relationship('User', back_populates = 'lists')

    items = relationship('Item', back_populates ='list' )


class Item(db.Model):
    __tablename__ = 'items'
    id = db.Column(db.Integer, primary_key= True)
    desc = db.Column(db.String(500), nullable = False)
    complete = db.Column(db.Boolean, server_default ='f', default = False, nullable = False)

    list_id = db.Column(db.Integer, db.ForeignKey('lists.id'))
    list = relationship('List', back_populates = 'items')


# db.create_all()


@app.route('/')
def home():
    return render_template('index.html')


@app.route('/register', methods = ['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        name = form.name.data
        email = form.email.data
        hashed_password = generate_password_hash(password=form.password.data, salt_length=8, method='pbkdf2:sha256')
        all_users = db.session.query(User).all()
        for user in all_users:
            if user.email == email:
                flash("You've already signed up with that Email.Login instead.")
                return redirect(url_for('login'))

        new_user = User(name= name,
                        email=email,
                        password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html', form = form)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


@app.route('/login', methods = ['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email = email).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            # flash('Logged in successfully.')
            return redirect(url_for('home'))
        elif not user or not check_password_hash(user.password,password):
            flash("Email or password incorrect, please try again.")
    return render_template('login.html')


@app.route('/new_list', methods= ['GET'])
@login_required
def new_list():
    current_date = datetime.date.today().strftime('%m/%d/%Y')
    name = f'New List {current_date}'

    new_list = List(name=name, user = current_user)

    db.session.add(new_list)
    db.session.commit()

    all__incompleted_items = Item.query.filter_by(list_id=new_list.id, complete=False).all()

    all_completed_items = Item.query.filter_by(list_id=new_list.id, complete=True).all()

    return render_template('new_list.html', list_name = name, list_id = new_list.id, incomplete_items= all__incompleted_items, complete_items = all_completed_items)


@app.route('/all_lists')
@login_required
def all_list():
    all_lists = List.query.filter_by(user_id = current_user.id)
    return render_template('all_lists.html', lists = all_lists)


@app.route('/show_list<int:list_id>')
@login_required
def show_list(list_id):
    list_shown = db.session.query(List).get(list_id)

    all__incompleted_items = Item.query.filter_by(list_id=list_id, complete=False).all()

    all_completed_items = Item.query.filter_by(list_id=list_id, complete=True).all()

    return render_template('show_list.html', list_id = list_id, incomplete_items= all__incompleted_items, complete_items = all_completed_items, list_name = list_shown.name)


@app.route('/delete_list<int:list_id>')
@login_required
def delete_list(list_id):
    list_to_delete = List.query.get(list_id)

    items_to_delete = Item.query.filter_by(list_id= list_id).all()

    db.session.delete(list_to_delete)

    for item in items_to_delete:
        db.session.delete(item)

    db.session.commit()
    return redirect(url_for('all_list'))


@app.route('/add_item/<int:id>', methods = ['POST'])
@login_required
def add_item(id):
    item_desc = request.form['item_name']
    completed = False

    todo_list = db.session.query(List).get(id)

    new_item = Item(desc = item_desc, complete = completed, list = todo_list)

    db.session.add(new_item)
    db.session.commit()

    all__incompleted_items = Item.query.filter_by(list_id = id, complete = False).all()

    all_completed_items = Item.query.filter_by(list_id = id, complete = True).all()

    return render_template('new_list.html', list_id = id, incomplete_items= all__incompleted_items, complete_items = all_completed_items, list_name = todo_list.name)


@app.route('/edit_list_name/<int:id>', methods = ['POST'])
@login_required
def edit_list_name(id):
    new_name = request.form['list_name']
    list_to_update = List.query.get(id)
    list_to_update.name = new_name
    db.session.commit()

    all__incompleted_items = Item.query.filter_by(list_id=id, complete=False).all()

    all_completed_items = Item.query.filter_by(list_id=id, complete=True).all()

    return render_template('new_list.html', list_id = id, incomplete_items = all__incompleted_items, complete_items = all_completed_items, list_name = list_to_update.name)


@app.route('/complete/<int:item_id>')
@login_required
def completed_item(item_id):
    completed_i = db.session.query(Item).get(item_id)
    completed_i.complete = True

    db.session.commit()

    all_completed_items = Item.query.filter_by(list_id= completed_i.list_id, complete = True).all()

    all__incompleted_items = Item.query.filter_by(list_id=completed_i.list_id , complete=False).all()

    current_list = db.session.query(List).get(completed_i.list_id)

    return render_template('new_list.html', list_id = current_list.id, incomplete_items = all__incompleted_items, complete_items = all_completed_items, list_name = current_list.name )


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return render_template('index.html')


if __name__ == '__main__':
    app.run(debug=True)