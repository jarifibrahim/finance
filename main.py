from flask import Flask, render_template, request, redirect, flash, \
     url_for, session, escape
from werkzeug.security import generate_password_hash, \
     check_password_hash
from yahoo_finance import Share
from forms import RegisterForm, LoginForm
from mongoengine import *
app = Flask(__name__);

# secret key is needed for forms(csrf)
app.config['SECRET_KEY'] = 's3cr3t'
# Database to use for mongoDB
app.config['MONGODB_DB'] = 'finance'
app.debug = True
connect(host='mongodb://finance-user:imibrahim@ds037215.mongolab.com:37215/finance-database')

# Classname = collectionName
# Same schema as the collection
class Users(Document):
    username = StringField(min_length=4, unique=True)
    password = StringField(max_length=255)
    cash = IntField(default=20000)
    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)


    # Try to create new user. Returns True if new user is created successfully else
    # returns False
    @staticmethod
    def create_user(form):
        new_user = Users()
        new_user.username = form.username.data
        new_user.set_password(form.password.data)
        holding = Stockholding()
        holding.symbol = 'FREE'
        holding.shares = 200
        holding.owner_username = new_user.username
        try:
            holding.save()
            new_user.save()
        except Exception as e:
            return flash('Username already in use. Please choose a different one.', 'text-danger')
        return True

    # Verify login credentials
    @staticmethod
    def check_login(form):
        try:
            current_user = Users.objects.get(username=form.username.data)
            return current_user.check_password(form.password.data)
        except Exception as e:
            print e
            return False

    @staticmethod
    def reload_user():
        current_user = Users.objects.get(username=session['username'])
        holding = Stockholding.objects(owner_username=session['username'])
        cost = []                       # Cost of each stock
        value = []                      # Value of stock = Cost * number of shares
        global total
        global new_stock
        new_stock = []
        total = 0.0
        print new_stock
        for s in new_stock:
            print s
        for item in holding:
            temp = {}
            yahoo = Share(item.symbol)
            temp['name'] = item.symbol
            temp['shares'] = int(item.shares)
            temp['cost'] = float(yahoo.get_price())
            temp['value'] = temp['cost'] * int(item.shares)
            total = total + temp['value']
            new_stock.append(temp)
        global cash
        cash = current_user.cash
        total = total + cash

class Stockholding(Document):
    symbol = StringField()
    owner_username = StringField()
    shares = IntField()

class Transaction(Document):
    owner_username = StringField()
    date = DateTimeField()
    type = IntField()
    price = FloatField()
    shares = IntField()

new_stock = []                  # User data from the db
total = 0.0                     # Total value of all shares
cash = 0

@app.route("/")
def index():
    if 'username' in session:
        return redirect('portfolio')
    return redirect('login')

@app.route("/portfolio")
def portfolio():
    #If user is logged in
    if 'username' in session:
        #Get current user object from db
        Users.reload_user()
        for n in new_stock:
            print n
        return render_template('portfolio.html', title='Portfolio', stocks=new_stock, total=total, cash=cash)
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
        s = request.args.get('symbol')
        if s is not None and s != '':
            holding = Stockholding.objects.get(owner_username=session['username'], symbol=s)
            holding.delete()
            flash('Stock sold successfully', 'text-success')
            return redirect('portfolio')
        return render_template('sell.html', stocks=new_stock)
    return render_template('apology.html', message=['Log In to see this page'])

@app.route('/buy')
def buy():
    if 'username' in session:
        s = request.args.get('symbol')
        sh = request.args.get('shares')
        if s is None or s == '':
            flash('Please enter a valid symbol', 'text-danger')
        elif sh is None or sh =='':
            flash('Please enter a valid number of shares', 'text-danger')
        else:
            temp = Share(s)
            price = temp.get_price()
            if price is not None:
                holding = Stockholding(symbol=s, owner_username=session['username'], shares=sh)
                holding.save()
            else:
                flash('Symbol not found', 'text-danger')
                return redirect('buy')

            current_user = Users.objects.get(username=session['username'])
            print price
            print int(sh)
            if current_user.cash < price * int(sh):
                Users.objects(username=session['username']).update(dec__cash=price*int(sh))m
                flash('Shares bought successfully', 'text-success')
            return redirect('portfolio')
        return render_template('buy.html', title='Buy')
    return render_template('apology.html', message=['Log In to see this page'])

@app.route('/history')
def history():
    if 'username' in session:
        return render_template('construction.html')
    return render_template('apology.html', message=['Log In to see this page'])

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
            if Users.check_login(form):
                flash('You were successfully logged in', 'text-success')
                # Log user session
                session['username'] = form.username.data
                return redirect(url_for('index'))
            else:
                flash('Incorrect login credentials', 'text-danger')
                return redirect('login')
        else:
            return render_template('apology.html', message=form.errors, title='Error')

@app.route('/logout')
def logout():
    # Clear user session
    session.clear()
    global new_stock
    new_stock[:]
    flash('You were successfully logged out', 'text-success')
    return redirect(url_for('index'))

@app.route("/register", methods=['POST', 'GET'])
def register():
    if request.method == 'GET':
        form = RegisterForm()
        return render_template('register_form.html', form=form, title='Register', no='ar')
    elif request.method == 'POST':
        form = RegisterForm(request.form)
        if form.validate():
            if Users.create_user(form):
                flash('You were successfully registered', 'text-success')
                return redirect(url_for('index'))
            else:
                return render_template('apology.html', message=['Unable to create user'])
        else:
            return render_template('register_form.html',form=form)
    return render_template('apology.html', message=['Something went wrong'])

@app.errorhandler(404)
def page_not_found(e):
    return render_template('apology.html',message=['User not found. Please register before trying to log in.'],title='Page Not Found', no='asd'), 404

if __name__ == '__main__':
    app.run()
