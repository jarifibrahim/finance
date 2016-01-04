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
            new_user.save()
            holding.save()
            transaction.save()
        except Exception as e:
            z = e
            print z
            flash('Username already in use. Please choose a different one.', 'text-danger')
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
