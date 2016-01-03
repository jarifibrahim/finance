from flask import Flask, render_template, request, redirect, flash, \
     url_for, session, escape
from werkzeug.security import generate_password_hash, \
     check_password_hash
from yahoo_finance import Share
from forms import RegisterForm, LoginForm
from mongoengine import *
import time

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
    cash = FloatField(default=20000.00)
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
        holding.username = new_user.username
        transaction = Transaction(username=new_user.username, date=time.strftime("%d/%m/%Y"), \
                                    type=Transaction.BUY, symbol='Cash', shares=0)
        try:
            holding.save()
            new_user.save()
            transaction.save()
        except Exception as e:
            z = e
            print z
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
        holding = Stockholding.objects(username=session['username'])
        cost = []                       # Cost of each stock
        value = []                      # Value of stock = Cost * number of shares
        global total
        global new_stock
        new_stock = []
        total = 0.0
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
    username = StringField()
    shares = IntField()

class Transaction(Document):
    BUY = 1
    SELL = 2
    TRANSACTION_CHOICES = (
        (BUY, 'buy'),
        (SELL, 'sell'),
    )
    username = StringField()
    date = StringField()
    type = IntField(choices=TRANSACTION_CHOICES)
    symbol = StringField()
    shares = IntField()

new_stock = []                  # User data from the db
total = 0.0                     # Total value of all shares
cash = 0.0

@app.route("/")
def index():
    if 'username' in session:
        return redirect('portfolio')
    return redirect('login')

@app.route("/portfolio")
def portfolio():
    #If user is logged in
    if 'username' in session:
        if not new_stock:
            Users.reload_user()
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
        if not new_stock:
            Users.reload_user()
        if s is not None and s != '':
            symbol = Share(s)
            if symbol.get_price() is None:
                return render_template('apology.html', message=['Something went wrong. Please try again.'])
            else:
                holding = Stockholding.objects.get(username=session['username'], symbol=s)
                amount_to_add = int(holding.shares) * float(symbol.get_price())
                Users.objects(username=session['username']).update(inc__cash=amount_to_add)

                transaction = Transaction(username=session['username'], date=time.strftime("%d/%m/%Y"), \
                                            type=Transaction.SELL, symbol=s, shares=holding.shares)
                transaction.save()
                holding.delete()
                flash('Stock sold successfully', 'text-success')
                Users.reload_user()
                return redirect('portfolio')
        return render_template('sell.html', stocks=new_stock)
    return render_template('apology.html', message=['Log In to see this page'])

@app.route('/buy')
def buy():
    if 'username' in session:
        if not request.query_string:        # If query string is empty return original template
            return render_template('buy.html')
        s = request.args.get('symbol')
        sh = request.args.get('shares')
        if s is None or s == '':
            flash('Please enter a valid symbol', 'text-danger')
        elif sh is None or sh =='':
            flash('Please enter a valid number of shares', 'text-danger')
        else:
            temp = Share(s)
            price = temp.get_price()
            if price is not None: # Valid symbol exists
                current_user = Users.objects.get(username=session['username'])
                if current_user.cash > float(price) * int(sh): # Verify acc balance

                    # if user already has shares of 's' inc shares value
                    if Stockholding.objects(username=session['username'], symbol=s):
                        Stockholding.objects(symbol=s, username=session['username']).update(inc__shares=int(sh))
                    # Else create a new Stock object
                    else:
                        holding = Stockholding(symbol=s, username=session['username'], shares=sh)
                        holding.save()

                    transaction = Transaction(username=session['username'], date=time.strftime("%d/%m/%Y"), \
                                                type=Transaction.BUY, symbol=s, shares=sh)
                    transaction.save()
                    # Dec user cash
                    Users.objects(username=session['username']).update(dec__cash=float(price)*int(sh))
                    flash('Shares bought successfully', 'text-success')
                else:
                    flash("You don't have enough balance", 'text-danger')
                    return redirect('buy')
            else:
                flash('Symbol not found', 'text-danger')
                return redirect('buy')
            Users.reload_user()
            return redirect('portfolio')
        return render_template('buy.html', title='Buy')
    return render_template('apology.html', message=['Log In to see this page'])

@app.route('/history')
def history():
    if 'username' in session:
        transactions = Transaction.objects(username=session['username'])
        t = []
        for trans in transactions:
            temp = {}
            temp['type'] = trans.type
            temp['symbol'] = trans.symbol
            temp['shares'] = trans.shares
            temp['date'] = trans.date
            t.append(temp)
        return render_template('history.html', transactions=t)
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
                Users.reload_user()
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

if __name__ == '__main__':
    app.run()
