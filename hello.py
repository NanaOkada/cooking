from flask import Flask, render_template,request,redirect
from flask_bootstrap import Bootstrap
from flask_moment import Moment
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
application=app
app.config['SECRET_KEY'] = 'hard to guess string'
app.config['SQLALCHEMY_DATABASE_URI']='sqlite:///ingred.db'

db=SQLAlchemy(app)



bootstrap = Bootstrap(app)
moment = Moment(app)

class ingred(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    item = db.Column(db.String(200),nullable=False)


class IngredForm(FlaskForm):
    item = StringField('Add a new ingredient:')
    submit = SubmitField('Submit')

def __repr__(self):
    return '<Ingredient %r>' % self.id


@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500


@app.route('/', methods=['GET', 'POST'])
def index():
    item = None
    form = IngredForm()
    if request.method == "POST":
        item_name = request.form['item']
        new_item = ingred(item=item_name)
        try:
            db.session.add(new_item)
            db.session.commit()
            return redirect('/crud')
        except:
            return "There's something wrong!"
    else:
        ing=ingred.query.order_by(ingred.id)
        return render_template('index.html', form=form, ing=ing)

@app.route('/update/<int:id>',methods=['GET', 'POST'])
def update(id):
    ingred_to_update = ingred.query.get_or_404(id)
    if request.method=="POST":
        ingred_to_update.item = request.form['item']
        try:
            db.session.commit()
            return redirect('/crud')
        except:
            return "Something went wrong..."
    else:
        return render_template('update.html', ingred_to_update=ingred_to_update)

@app.route('/delete/<int:id>')
def delete(id):
    friend_to_delete = ingred.query.get_or_404(id)
    try:
        db.session.delete(friend_to_delete)
        db.session.commit()
        return redirect('/crud')
    except:
        return "Something went wrong..."

