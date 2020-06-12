# /usr/bin/python3

# Copyright (C) 2020
# Created by Javier Izquierdo Vera. <javierizquierdovera.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os, datetime
from flask import Flask, render_template, request, redirect, url_for, send_from_directory
from werkzeug.utils import secure_filename

VAULT = "vault"

app = Flask(__name__)
app.config["VAULT"] = VAULT

@app.route('/')
def home():
    return render_template("home.html")

@app.route('/about', strict_slashes=False)
def about():
    return render_template("about.html")

def save_file(file):
    filename = secure_filename(file.filename)
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S__')
    file.save(os.path.join(app.config["VAULT"], timestamp + filename))
       
@app.route('/file-upload', methods=["POST"])
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            print("Upload error")
            return home()

        file = request.files["file"] 

        if not file.filename:
            print("Empty file")
            return home()

        save_file(file)
        print("Sent file --> {}".format(file))
        redirect(url_for("scan-results.html", filename=secure_filename(file.filename)))

    return home()

if __name__ == '__main__':
    app.run(debug=True)