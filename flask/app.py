from flask import Flask, redirect, url_for, render_template

app = Flask(__name__)
name = "George"
@app.route("/")
def home():
    return render_template("index.html", content=name) #in html file, use {{}} with var inside to pass variables. backend use front end var name with back end var



@app.route("/admin")
def admin():
    return redirect(url_for("home"))

if __name__ == "__main__":
    app.run()

