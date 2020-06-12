 
from flask import Flask, render_template, request, redirect
import os, datetime

app = Flask(__name__)

@app.route('/')
def home():
    return render_template("home.html")

@app.route('/about', strict_slashes=False)
def about():
    return render_template("about.html")

def save_file(file):
    file.save(os.path.join(app.config["VAULT"], datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S__') + file.filename))
       
app.config["VAULT"] = "vault"
@app.route('/file-upload', methods=["POST"])
def upload_file():
    if request.method == 'POST' and request.files:
        file = request.files["file"] 
        if not file.filename:
            print("Invalid file")
            return home()

        save_file(file)
        print("Sent file --> {}".format(file))
        redirect("scan-results.html")

    return home()

if __name__ == '__main__':
    app.run(debug=True)