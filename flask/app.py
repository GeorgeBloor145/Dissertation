from flask import Flask, redirect, url_for, render_template
from main import ip2location
import time

app = Flask(__name__)
name = "George"
@app.route("/")
def welcome():
    return render_template("welcome.html", content=name) #in html file, use {{}} with var inside to pass variables. backend use front end var name with back end var

@app.route("/home", methods = ["POST","GET"])
def home():

    return  render_template("home.html")
    if request.method == "POST":
        print("TEST")

@app.route('/results')
def run_script():
    processing = ip2location()
    print(processing)
    return render_template("results.html", result= processing)

if __name__ == "__main__":
    app.run(debug =True)

