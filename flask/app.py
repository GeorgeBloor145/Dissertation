from flask import Flask, redirect, url_for, render_template

app = Flask(__name__)
name = "George"
@app.route("/")
def welcome():
    return render_template("welcome.html", content=name) #in html file, use {{}} with var inside to pass variables. backend use front end var name with back end var

@app.route("/home")
def home():
    return  render_template("home.html")




if __name__ == "__main__":
    app.run(debug =True)

