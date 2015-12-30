from flask import Flask, render_template, request, redirect, flash, \
     url_for, session, escape
from flask.ext.mongoengine import MongoEngine
from werkzeug.security import generate_password_hash, \
     check_password_hash
from flask_debugtoolbar import DebugToolbarExtension
from yahoo_finance import Share
from forms import RegisterForm, LoginForm
app = Flask(__name__);

# Enable debug toolbar
app.config['DEBUG_TB_PANELS'] = ['flask.ext.mongoengine.panels.MongoDebugPanel']
# Disable url redirect intercept
app.config['DEBUG_TB_INTERCEPT_REDIRECTS'] = False
# secret key is needed for forms(csrf)
app.config['SECRET_KEY'] = 's3cr3t'
# Database to use for mongoDB
app.config['MONGODB_DB'] = 'finance'
app.debug = True

db = MongoEngine(app)
toolbar = DebugToolbarExtension(app)

# Classname = collectionName
# Same schema as the collection
class Users(db.Document):
    username = db.StringField(min_length=4, unique=True)
    password = db.StringField(max_length=255)
    cash = db.IntField(default=20000)
    stock = db.MapField(field=db.IntField(), default={'FREE':100,'USA':200})

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

# Try to create new user. Returns True if new user is created successfully else
# returns False
def createUser(form):
    new_user = Users()
    new_user.username = form.username.data
    new_user.set_password(form.password.data)
    try:
        new_user.save()
    except Exception as e:
        return False
    return True

# Verify login credentials
def check_login(form):
    current_user = Users.objects.get(username=form.username.data)
    return current_user.check_password(form.password.data)

new_stock = []
total = 0.0                     # Total value of all shares

@app.route("/")
def index():
    if 'username' in session:
        return render_template('portfolio.html', title='Portfolio', stocks=new_stock, total=total)
    return redirect('login')

@app.route("/portfolio")
def portfolio():
    #If user is logged in
    if 'username' in session:
        #Get current user object from db
        return render_template('portfolio.html', title='Portfolio', stocks=new_stock, total=total)
    else:
        return render_template('apology.html', title='Error', message=['Log In to see this page'])
@app.route("/quote", methods=['GET'])
def quote():
    s = request.args.get('stock')
    # Validate submitted data
    if s is not None and s != '':
        yahoo = Share(s)
        quote = yahoo.get_price()
        # for invalid stock
        if quote is None:
            return render_template('quote.html', stock=s)
        # for a valid stock
        return render_template('quote.html', stock=s, quote=quote)
    # if no form data is submitted
    return render_template('quote.html', title='Quote')

@app.route("/sell")
def sell():
    if 'username' in session:
        return render_template('construction.html', page='sell')
    return render_template('apology.html', page='sell', message=['Log In to see this page'])

@app.route('/buy')
def buy():
    if 'username' in session:
        return render_template('construction.html', title='Buy')
    return render_template('apology.html', page='buy', message=['Log In to see this page'])

@app.route('/history')
def history():
    if 'username' in session:
        return render_template('construction.html', page='sell')
    return render_template('apology.html', page='history', message=['Log In to see this page'])

@app.route("/login", methods=['POST', 'GET'])
def login():
    if request.method == 'GET':
        # Generate a new form and return it
        form = LoginForm()
        return render_template('login_form_new.html', form=form, title='Login',no='as')
    elif request.method == 'POST':
        form = LoginForm(request.form)
        # Validate form data
        if form.validate():
            # Check username and password
            check_login(form)
            flash('You were successfully logged in')

            # Log user session
            session['username'] = form.username.data
            current_user = Users.objects.get(username=session['username'])
            stocks = current_user.stock
            cost = []                       # Cost of each stock
            value = []                      # Value of stock = Cost * number of shares
            global total
            global new_stock
            new_stock = []
            for key in new_stock:
                print key
            for stock, shares in stocks.items():
                temp = {}
                yahoo = Share(stock)
                temp['name'] = stock
                temp['shares'] = int(shares)
                temp['cost'] = float(yahoo.get_price())
                temp['value'] = temp['cost'] * int(shares)
                total = total + temp['value']
                new_stock.append(temp)
            return redirect(url_for('index'))
        else:
            return render_template('apology.html', message=form.errors, title='Error')

@app.route('/logout')
def logout():
    # Clear user session
    session.clear()
    global new_stock
    new_stock[:]
    flash('You were successfully logged out')
    return redirect(url_for('index'))

@app.route("/register", methods=['POST', 'GET'])
def register():
    if request.method == 'GET':
        form = RegisterForm()
        return render_template('register_form.html', form=form, title='Register')
    elif request.method == 'POST':
        form = RegisterForm(request.form)
        if form.validate():
            if createUser(form):
                flash('You were successfully registered')
                return redirect(url_for('index'))
            else:
                return render_template('apology.html', message=['Unable to create user'])
        else:
            return render_template('form_error.html', form=form)
    return render_template('apology.html', message=['Something went wrong'])

if __name__ == '__main__':
    app.run()
