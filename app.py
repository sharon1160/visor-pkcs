from flask import Flask, render_template, request, redirect, url_for, flash
from read_pkcs import *

app = Flask(__name__)

@app.route("/", methods=('GET', 'POST'))
def index():
    if request.method == 'POST':
        # Recibimos el archivo
        uploaded_file = request.files['file']

        # Recibimos contraseña
        password = bytes(request.form.getlist('password')[0], 'utf-8')

        # Si el archivo ha sido cargado y el tipo de llave ha sido especificado
        if password != '' and uploaded_file != b'':
            # Leemos el archivo
            file_bytes = uploaded_file.stream.read()
            private_key_data, certificate_data, additional_certificates_data = generate_data(file_bytes, password)

        return render_template("results.html", private_key_data = private_key_data,
                                                certificate_data = certificate_data,
                                                additional_certificates_data = additional_certificates_data )
    return render_template("index.html")

if __name__ == '__main__':
    app.run(debug=True)