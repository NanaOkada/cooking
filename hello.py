from flask import Flask, render_template, request, redirect, flash, url_for
from flask_bootstrap import Bootstrap
from flask_moment import Moment
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, BooleanField, Label, TextAreaField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, current_user, logout_user, login_required
from flask_migrate import Migrate

app = Flask(__name__)
application = app
app.config['SECRET_KEY'] = 'hard to guess string'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///community.db'
bcrypt = Bcrypt(app)
db = SQLAlchemy(app)
migrate = Migrate(app, db)  # this
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    recipes = db.relationship('Recipe', backref='author', lazy=True)

    def __repr__(self):
        return f"User('{self.username}',{self.email}')"

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    username = db.Column(db.String(30), nullable=False)
    recipe_id = db.Column(db.Integer, db.ForeignKey('recipe.id'), nullable=False)
    description = db.Column(db.String(65535), nullable=False)

    def __repr__(self):
        return f"Comment('{self.title}')"


class Recipe(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), nullable=False)
    description = db.Column(db.String(65535), nullable=False)
    ingredients = db.Column(db.String(65535), nullable=False)
    instructions = db.Column(db.String(65535), nullable=False)
    notes = db.Column(db.String(65535), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    like = db.Column(db.Integer, default=0, nullable=False)
    dislike = db.Column(db.Integer, default=0, nullable=False)

    def __repr__(self):
        return f"Post('{self.title}')"


class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=30)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign up')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Username already exists.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Email already exists.')


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Sign in')


class CommentForm(FlaskForm):
    title = StringField('Title for your comment:', validators=[DataRequired()])
    description = TextAreaField('Enter you comment here:', validators=[DataRequired()])
    submit = SubmitField('Add Comment')

class RecipeForm(FlaskForm):
    title = StringField('Title for your recipe', validators=[DataRequired()])
    description = TextAreaField('Enter a description', validators=[DataRequired()])
    ingredients = TextAreaField('Enter ingredients one on each line', validators=[DataRequired()])
    instructions = TextAreaField('Enter instructions one on each line', validators=[DataRequired()])
    notes = TextAreaField('Wanna brag?', validators=[DataRequired()])
    submit = SubmitField('Add Recipe')

    def __init__(self, mode=None, **kwargs):
        super().__init__(**kwargs)
        if mode is not None:
            # Update labels based on the mode the form is opened!
            self.submit.label = Label(self.submit.id, "Update existing recipe")
            self.title.label = Label(self.title.id, "Update recipe name?")
            self.description.label = Label(self.title.id, "Update description?")
            self.ingredients.label = Label(self.title.id, "Update ingredients?")
            self.instructions.label = Label(self.title.id, "Update instructions?")
            self.notes.label = Label(self.title.id, "Update notes?")


bootstrap = Bootstrap(app)
moment = Moment(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500


@app.route('/')
@app.route('/home')
def home():
    recipes = Recipe.query.order_by(Recipe.like.desc()).all()
    comments = Comment.query.all()
    return render_template('index.html', recipes=recipes, comments=comments)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Welcome to our community! You can now login.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            flash(f'Login succeeded. Welcome! {user.username} .', 'success')
            return redirect(url_for('home'))
        else:
            flash('Login failed, please check your email and password.', 'danger')
    return render_template('login.html', form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/account')
@login_required
def account():
    return render_template('account.html', title='Account')

@app.route('/comment', methods=['POST', 'GET'])
@login_required
def comment():
    user = User.query.filter_by(username=current_user.username).first()
    form = CommentForm()
    if form.validate_on_submit():
        recipe_id = request.args.get('recipe_id')
        new_comment=Comment(title=form.title.data, user_id=user.id, username=user.username, description=form.description.data, recipe_id=recipe_id)
        db.session.add(new_comment)
        db.session.commit()
        flash('Comment added successfully.', 'success')
        return redirect(url_for('home'))
    return render_template('comment.html', form=form)

@app.route('/like', methods=['GET'])
@login_required
def like():
    recipe_id = request.args.get('recipe_id')
    recipe = Recipe.query.filter_by(id=recipe_id).first()
    new_like = recipe.like+1
    recipe.like = new_like
    db.session.commit()
    recipes = Recipe.query.order_by(Recipe.like.desc()).all()
    comments = Comment.query.all()
    return render_template('index.html', recipes=recipes, comments=comments)

@app.route('/dislike', methods=['GET'])
@login_required
def dislike():
    recipe_id = request.args.get('recipe_id')
    recipe = Recipe.query.filter_by(id=recipe_id).first()
    new_dislike = recipe.dislike+1
    recipe.dislike = new_dislike
    db.session.commit()
    recipes = Recipe.query.order_by(Recipe.like.desc()).all()
    comments = Comment.query.all()
    return render_template('index.html', recipes=recipes, comments=comments)

@app.route('/recipe', methods=['POST', 'GET'])
@login_required
def recipe():
    user = User.query.filter_by(username=current_user.username).first()
    form = RecipeForm()
    if request.method == "GET":
        form_mode = "add"
        recipes = Recipe.query.filter_by(user_id=user.id).order_by(Recipe.like.desc()).all()
        if 'edit_recipe' in request.args:
            recipe_id = request.args.get('edit_recipe')
            recipe_to_update = Recipe.query.filter_by(id=recipe_id).first()
            edit_form = RecipeForm(recipe_to_update)
            edit_form.ingredients.data = recipe_to_update.ingredients
            edit_form.title.data = recipe_to_update.title
            edit_form.description.data = recipe_to_update.description
            edit_form.notes.data = recipe_to_update.notes
            edit_form.instructions.data = recipe_to_update.instructions
            edit_form.submit.data = "Update recipe!"
            form_mode = "edit"
            form = edit_form
        return render_template('recipe.html', recipes=recipes, form=form, form_mode=form_mode)
    elif request.method == "POST":
        form = RecipeForm(request.form)
        if form.validate_on_submit():
            print(form)
            if 'edit_recipe' not in request.args:
                # Create a db.Model type of Ingredient from the form data received
                new_recipe = Recipe(title=form.title.data, description=form.description.data,
                                    instructions=form.instructions.data, ingredients=form.ingredients.data,
                                    notes=form.notes.data, user_id=user.id)
                # Add the record in a pending transaction
                db.session.add(new_recipe)
                # Finally commit it to push the changes to the database
                db.session.commit()
                # Saved, send a get request on homepage
                return redirect('/')
            else:
                # Need to edit recipe
                recipe_id = request.args.get('edit_recipe')
                to_update_recipe = Recipe.query.filter_by(id=recipe_id).first()
                to_update_recipe.title = form.title.data
                to_update_recipe.description = form.description.data
                to_update_recipe.ingredients = form.ingredients.data
                to_update_recipe.instructions = form.instructions.data
                to_update_recipe.notes = form.notes.data
                db.session.add(to_update_recipe)
                db.session.commit()
        return redirect('/')
    return render_template('recipe.html')


@app.route('/recipe/delete/<recipe_id>', methods=['GET'])
@login_required
def delete_recipe(recipe_id):
    recipe = Recipe.query.filter_by(id=recipe_id).first()
    db.session.delete(recipe)
    db.session.commit()
    return redirect('/')
