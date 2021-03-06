import os

from flask import Flask, render_template, request, redirect, flash, \
     url_for, session, escape
from yahoo_finance import Share
from mongoengine import connect
import models, time
from forms import LoginForm, RegisterForm
from flask.ext.mail import Message, Mail

mail = Mail()

app = Flask(__name__)

# secret key is needed for forms(csrf)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
# Database to use for mongoDB
app.config['MONGODB_DB'] = os.getenv('MONGODB')
app.debug = True
connect(host=os.getenv('CONNECTION_URL'))
app.config["MAIL_SERVER"] = os.getenv('MAIL_SERVER')
app.config["MAIL_PORT"] = os.getenv('MAIL_PORT')
app.config["MAIL_USE_SSL"] = True
app.config["MAIL_USERNAME"] = os.getenv('MAIL_USERNAME')
app.config["MAIL_PASSWORD"] = os.getenv('MAIL_PASSWORD')

mail.init_app(app)


@app.route("/")
def index():
    if 'username' in session:
        return redirect('portfolio')
    return redirect('login')

@app.route("/portfolio")
def portfolio():
    #If user is logged in
    if 'username' in session:
        current_user = models.Users.objects.get(username=session['username'])
        result = current_user.get_status()
        return render_template('portfolio.html', title='Portfolio', stocks=result['all_items'], cash=result['cash'], total=result['total'])
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
        # for a valid symbol
        return render_template('quote.html', stock=s, quote=quote)
    # if no form data is submitted
    return render_template('quote.html', title='Quote')

@app.route("/sell")
def sell():
    if 'username' in session:
        # Get symbol name
        s = request.args.get('symbol')
        current_user = models.Users.objects.get(username=session['username'])
        # symbol name is valid
        if s is not None and s != '':
            symbol = Share(s)
            if symbol.get_price() is None:
                return render_template('apology.html', message=['Something went wrong. Please try again.'])
            else:
                # Get user's stock info
                holding = models.Stockholding.objects.get(username=current_user.username, symbol=s)
                amount_to_add = int(holding.shares) * float(symbol.get_price())
                # add value of shares to user's cash
                current_user.update(inc__cash=amount_to_add)
                # log transaction
                transaction = models.Transaction(username=current_user.username, date=time.strftime("%d/%m/%Y"), \
                                            type=models.Transaction.SELL, symbol=s, shares=holding.shares)
                transaction.save()
                holding.delete() # Remove stock
                flash('Stock sold successfully', 'text-success')
                result = current_user.get_status()
                return redirect('portfolio', stocks=result['all_items'], cash=result['cash'], total=result['total']) 
        return render_template('sell.html', stocks=result['all_items'])
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
                current_user = models.Users.objects.get(username=session['username'])
                try:
                    int(sh)
                except:
                    flash("Enter valid share count", 'text-danger')
                    return render_template('buy.html')
                if current_user.cash > float(price) * int(sh): # Verify acc balance

                    # if user already has shares of 's', increment shares count
                    if models.Stockholding.objects(username=current_user.username, symbol=s):
                        models.Stockholding.objects(symbol=s, username=current_user.username).update(inc__shares=int(sh))
                    # Else create a new Stock object
                    else:
                        holding = models.Stockholding(symbol=s, username=current_user.username, shares=sh)
                        holding.save()

                    transaction = models.Transaction(username=current_user.username, date=time.strftime("%d/%m/%Y"), \
                                                type=models.Transaction.BUY, symbol=s, shares=sh)
                    transaction.save()
                    # Decrement user cash
                    current_user.update(dec__cash=float(price)*int(sh))
                    flash('Shares bought successfully', 'text-success')
                else:
                    flash("You don't have enough balance", 'text-danger')
                    return redirect('buy')
            else:
                flash('Symbol not found', 'text-danger')
                return redirect('buy')
            result = current_user.get_status()
            return redirect('portfolio', stocks=result['all_items'], total=result['total'], cash=result['cash'])
        return render_template('buy.html', title='Buy')
    return render_template('apology.html', message=['Log In to see this page'])

@app.route('/history')
def history():
    if 'username' in session:
        transactions = models.Transaction.objects(username=session['username'])
        # Generate transactions table
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
            if models.Users.check_login(form):
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
            if models.Users.create_user(form):
                flash('You were successfully registered', 'text-success')
                msg = Message('Login Credentials for fynance.herokuapp.com', sender='jarifibrahim@gmail.com', recipients=[str(form.email.data)])
                msg.body = """
Hey %s,
Thanks for registering to fynance.herokuapp.com

Kindly use the following username and password to log in to you fynance account

Username: %s
Password: %s

Cheers,
Ibrahim

----
Please note: This is a system generated email.
----
                """ % (str(form.username.data), str(form.username.data), str(form.password.data))
                print msg.body
                mail.send(msg)
                return redirect(url_for('index'))
            else:
                return render_template('register_form.html', form=form)
        else:
            return render_template('register_form.html',form=form)
    return render_template('apology.html', message=['Something went wrong'])

if __name__ == '__main__':
    app.run()
