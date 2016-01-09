from mongoengine import *
from flask import session, flash
from yahoo_finance import Share
from werkzeug.security import generate_password_hash, \
     check_password_hash
import time

new_stock = []                  # User data from the db
cash = 0.0

# Classname = collectionName
# Same schema as the collection
class Users(Document):
    username = StringField(min_length=4, unique=True)
    password = StringField(max_length=255)
    cash = FloatField(default=20000.00)
    email = EmailField(unique=True)
    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

    # Try to create new user. Returns True if new user is created successfully else
    # returns False
    @staticmethod
    def create_user(form):
        Users.reload()
        transaction.reload()
        new_user = Users()
        new_user.username = form.username.data
        new_user.set_password(form.password.data)
        new_user.email = form.email.data.lower()
        '''
        holding = Stockholding()
        holding.symbol = 'FREE'
        holding.shares = 200
        holding.username = new_user.username.lower()
        '''
        transaction = Transaction(username=new_user.username, date=time.strftime("%d/%m/%Y"), \
                                    type=Transaction.BUY, symbol='Cash', shares=0)
        try:
            new_user.save()
            holding.save()
            transaction.save()
        except Exception as e:

            if(e.message.find('username') > -1):
                flash('Username already in use. Please choose a different one.', 'text-danger')
            elif(e.message.find('email') > -1):
                flash('Email ID already in use. Please choose a different one.', 'text-danger')
            else:
                flash('Something went wrong.', 'text-danger')
            return False
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
