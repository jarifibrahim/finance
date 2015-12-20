from flask import Flask, render_template

app = Flask(__name__);

@app.route("/")
def index():
    return render_template('home.html',title='Home')

@app.route("/login")
def login():
    return 'Login'

@app.route("/register")
def register():
    return 'Register'


if __name__ == '__main__':
    app.run(debug=True)
