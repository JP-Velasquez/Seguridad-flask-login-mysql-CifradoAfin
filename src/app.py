# Flask
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_mysqldb import MySQL
from flask_wtf.csrf import CSRFProtect
from flask_login import LoginManager, login_user, logout_user, login_required
#Log
import logging
#Time para Temporizador de bloqueo después de varios intentos fallidos
import time
# Bibliotecas a utilizar para cifrado afin
from unidecode import unidecode
from config import config
import base64
import io
import matplotlib.pyplot as plt
import matplotlib
# Configura el backend de Matplotlib para evitar problemas con tkinter
matplotlib.use('agg')

#Configuracion BD
from config import config

# Models:
from models.ModelUser import ModelUser
# Entities:
from models.entities.User import User


app = Flask(__name__)
csrf = CSRFProtect()
db = MySQL(app)
login_manager_app = LoginManager(app)

# Configura el registro
logging.basicConfig(level=logging.INFO)
#Filtro de log
failed_login_log = logging.FileHandler('failed_login.log')
failed_login_log.setLevel(logging.INFO)
failed_login_formatter = logging.Formatter('%(asctime)s - %(message)s')
failed_login_log.setFormatter(failed_login_formatter)
app.logger.addHandler(failed_login_log)

# <!---- Seguridad, bloquear usuarios temporizador y bloqueo Ip ---->
# Variable para rastrear los intentos fallidos por IP
failed_attempts = {}
block_timers = {}
blocked_ips = set()
tiempo_restante = 0
contador = 0
totalIntentos = 0


# Constantes
MAX_FAILED_ATTEMPTS = 9 
BLOCK_TIME_1 = 60  # 60 segundos en segundos
BLOCK_TIME_2 = 300  # 5 minutos en segundos

# Mensajes estilizados 
context = {
        "type": "",
        "mensaje": ""
    } 
#context["type"]="danger"
#context["mensaje"]= f"Acceso denegado. IP bloqueada temporalmente. \nTiempo restante: {tiempo_restante} segundos."

@login_manager_app.user_loader
def load_user(id):
    return ModelUser.get_by_id(db, id)

@app.route('/')
def index():
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    global tiempo_restante 
    global contador
    global totalIntentos
    if(contador < 3):
        # Verificar y eliminar bloqueos temporales que hayan expirado
        current_time = time.time()
        for ip in list(block_timers.keys()):
            if block_timers[ip] <= current_time:
                del block_timers[ip]
    if request.method == 'POST':
        # print(request.form['username'])
        # print(request.form['password'])
        user = User(0, request.form['username'], request.form['password'])
        logged_user = ModelUser.login(db, user)
        remote_ip = request.remote_addr
        print(f"Ip bloqueadas {blocked_ips}")

        # Verifica si la IP está bloqueada
        if remote_ip in blocked_ips:
            return "Acceso denegado. IP bloqueada permanentemente."
        
        if remote_ip in block_timers:
            tiempo_restante = max(0, int(block_timers[remote_ip] - time.time()))
            return render_template('auth/login.html', tiempo_restante=tiempo_restante, context=context)
        else:
            tiempo_restante = 0
        
        if logged_user != None:
            if logged_user.password:
                login_user(logged_user)
                failed_attempts[remote_ip] = 0
                totalIntentos = 0
                contador = 0
                return redirect(url_for('home'))
            else:
                totalIntentos+=1
                print(f"Total de intentos {totalIntentos}")
                app.logger.info(f'PASSWORD INCORRECTA - para el usuario [ {request.form["username"]} ] desde la direccion IP [ {request.remote_addr} ], con intento de password [ {request.form["password"]} ]')            
                flash("Password Invalida...")
                # Incrementa el contador de intentos fallidos para la IP
                failed_attempts[remote_ip] = failed_attempts.get(remote_ip, 0) + 1

                if failed_attempts[remote_ip] == 3 and contador == 0:
                    # Bloqueo temporal de 60 segundos
                    app.logger.info(f'Bloqueo temporal ({BLOCK_TIME_1} segundos) para la dirección IP [ {remote_ip} ]')
                    block_timers[remote_ip] = time.time() + BLOCK_TIME_1
                    contador += 1
                    print(f"Este es el contador: {contador}")   
                    return render_template('auth/login.html', tiempo_restante=tiempo_restante, context=context)

                if failed_attempts[remote_ip] == 6 and contador == 1:
                    # Bloqueo temporal de 5 minutos
                    app.logger.info(f'Bloqueo temporal ({BLOCK_TIME_2} segundos) para la dirección IP [ {remote_ip} ]')
                    block_timers[remote_ip] = time.time() + BLOCK_TIME_2
                    contador += 1
                    print(f"Este es el contador 5min: {contador}")
                    return render_template('auth/login.html', tiempo_restante=tiempo_restante, context=context)
            
                if failed_attempts[remote_ip] >= MAX_FAILED_ATTEMPTS:
                    print(f"Este es el contador+MAX: {contador}")
                    # Bloqueo permanente (bloqueo de la IP)
                    blocked_ips.add(remote_ip)
                    app.logger.info(f'Bloqueo permanente para la direccion IP [ {remote_ip} ] Credenciales: Usuario: [ {request.form["username"]} ], Password: [ {request.form["password"]} ]')        
                    return "Acceso denegado. IP bloqueada permanentemente."                

                print(f"Numero de intentos: {failed_attempts[remote_ip]}")
                return render_template('auth/login.html', tiempo_restante=tiempo_restante, context=context)
        else:
            app.logger.info(f'USER NOT FOUND - credenciales: Usuario [ {request.form["username"]} ] desde la direccion IP [ {request.remote_addr} ], con intento de password [ {request.form["password"]} ]')
            flash("Usuario no encontrado...")
            return render_template('auth/login.html', tiempo_restante=tiempo_restante, context=context)
    else:
        return render_template('auth/login.html', tiempo_restante=tiempo_restante, context=context)

#Cierra seccion
@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

# Ruta principal que renderiza la página de inicio (cifrado)
@app.route('/home')
@login_required
def home():
    return render_template('home.html')


#@app.route('/protected')
#@login_required
#def protected():
#    return "<h1>Esta es una vista protegida, solo para usuarios autenticados.</h1>"


#Error para usuarios no identificados y que accedan a una
#URL protegida
def status_401(error):
    return redirect(url_for('login'))

#URL no existente
def status_404(error):
    return "<h1>Página no encontrada</h1>", 404

# Pagina Cifrado Afin!
# logica - De pagina Cifrado afin
# Define el alfabeto extendido español con los números correspondientes
alphabet = {
    'A': 0, 'B': 1, 'C': 2, 'D': 3, 'E': 4, 'F': 5, 'G': 6, 'H': 7, 'I': 8, 'J': 9,
    'K': 10, 'L': 11, 'M': 12, 'N': 13, 'Ñ': 14, 'O': 15, 'P': 16, 'Q': 17, 'R': 18,
    'S': 19, 'T': 20, 'U': 21, 'V': 22, 'W': 23, 'X': 24, 'Y': 25, 'Z': 26
}

# Función para realizar el cifrado afin en el texto
def afin_cipher(text, a, b):
    result = []
    for char in text:
        if char.isalpha():
            char = char.upper()  # Convierte el carácter a mayúscula
            # Obtiene el valor numérico del carácter
            char_value = alphabet[char]
            encrypted_value = (a * char_value + b) % 27
            encrypted_char = [
                key for key, value in alphabet.items() if value == encrypted_value][0]
            result.append(encrypted_char)
        else:
            result.append(char)
    return ''.join(result)

# Función para realizar el análisis de frecuencia en el texto
def frequency_analysis(text):
    frequency = {}
    for char in text:
        if char.isalpha():
            char = char.lower()  # Convierte el carácter a minúscula
            frequency[char] = frequency.get(char, 0) + 1
    return frequency

# Función para generar un gráfico de barras de análisis de frecuencia y convertirlo en base64
def generate_frequency_chart(text, tituloCustom = 0):
    # Elimina los espacios en blanco y cuenta la cantidad de caracteres
    text_without_spaces = ''.join(text.split())
    num_characters = len(text_without_spaces)

    frequency_data = frequency_analysis(text_without_spaces)

    # Crear una lista de todas las letras del alfabeto español extendido, incluyendo la "ñ"
    alphabet = [chr(i) for i in range(97, 123)]  # Excluye la "ñ" temporalmente

    # Agregar la "ñ" después de la letra "n"
    alphabet.insert(alphabet.index("n") + 1, "ñ")

    # Filtrar solo las letras que tienen frecuencia, eliminando los símbolos no utilizados
    labels = [char for char in alphabet if char in frequency_data]
    values = [frequency_data[char] for char in labels]

    # Ordenar las letras por frecuencia en orden descendente
    sorted_labels, sorted_values = zip(
        *sorted(zip(labels, values), key=lambda x: x[1], reverse=True))

    # Tomar solo las 6 letras principales
    top_labels = sorted_labels[:6]
    top_values = sorted_values[:6]

    # Genera el gráfico de barras con Matplotlib para las 6 letras principales
    plt.bar(top_labels, top_values)
    plt.xlabel('Letra')
    plt.ylabel('Frecuencia')

    # Configura el título de la gráfica en función de si es cifrado o descifrado
    if (tituloCustom == 0):
        title = f'Análisis de Frecuencia - {num_characters} caracteres (SIN espacios)'
    elif (tituloCustom == 1):
        title = f'Texto ingresado - {num_characters} caracteres (SIN espacios)'
    elif (tituloCustom == 2):
        title = f'Texto resultado - {num_characters} caracteres (SIN espacios)'
   
    plt.title(title)

    # Configura el eje Y para mostrar solo los valores correspondientes a las 6 letras principales
    plt.yticks(top_values)

    # Agregar los porcentajes en cada columna de la gráfica
    for i, value in enumerate(top_values):
        percentage = (value / num_characters) * 100
        plt.text(i, value, f'{percentage:.1f}%', ha='center', va='bottom')

    # Guarda el gráfico en un flujo de bytes y lo convierte a base64
    img_stream = io.BytesIO()
    plt.savefig(img_stream, format='png')
    img_stream.seek(0)
    img_data = base64.b64encode(img_stream.read()).decode('utf-8')

    plt.close()  # Cierra la figura de Matplotlib

    return img_data

# Variable global para almacenar el texto cifrado
encrypted_text = ""
# Función para cifrar el texto usando el cifrado afin
@app.route('/encrypt', methods=['POST'])
@login_required
def encrypt():
    global encrypted_text  # Acceder a la variable global
    text = request.form['text']
    a = int(request.form['a'])
    b = int(request.form['b'])

    # Convierte el texto a mayúsculas y quita acentos y caracteres especiales
    text_without_special_chars = unidecode(text.upper())

    # Aplica el cifrado afin al texto sin caracteres especiales
    encrypted_text = afin_cipher(text_without_special_chars, a, b)

    return encrypted_text

# Ruta para la página de descifrado
@app.route('/decrypt', methods=['GET', 'POST'])
@login_required
def decrypt_page():
    return render_template('decrypt.html')

# Variable global para almacenar el texto descifrado
decrypted_text = ""
# Ruta para realizar el descifrado manual
@app.route('/decrypt_manual', methods=['POST'])
@login_required
def decrypt_manual():
    global decrypted_text  # Acceder a la variable global

    ciphertext = request.form['ciphertext']
    a_decipher = int(request.form['a_decipher'])
    b_decipher = int(request.form['b_decipher'])
    text_without_special_chars = unidecode(ciphertext.upper())

    # Realiza el descifrado utilizando la fórmula
    result = []
    for char in text_without_special_chars:
        if char.isalpha():
            char = char.upper()  # Convierte el carácter a mayúscula
            # Obtiene el valor numérico del carácter
            char_value = alphabet[char]
            decrypted_value = (char_value - b_decipher) * inv(a_decipher, 27) % 27
            decrypted_char = [
                key for key, value in alphabet.items() if value == decrypted_value][0]
            result.append(decrypted_char)
        else:
            result.append(char)

    decrypted_text = ''.join(result)

    # Enviar el texto descifrado a la página web
    return decrypted_text

# Función para calcular el inverso multiplicativo en módulo n
def inv(a, n):
    for i in range(1, n):
        if (a * i) % n == 1:
            return i
    return None  # No tiene inverso

# Nueva ruta para realizar el descifrado automático
@app.route('/decrypt_auto', methods=['POST'])
@login_required
def decrypt_auto():
    global decrypted_text  # Acceder a la variable global
    ciphertext = request.form['ciphertext']
    text_without_special_chars = unidecode(ciphertext.upper())

    # Identificar las letras más frecuentes en el criptograma
    frequency_data = frequency_analysis(text_without_special_chars)
    sorted_frequency = sorted(frequency_data.items(),
                              key=lambda x: x[1], reverse=True)
    
    # Asignar la letra más frecuente a "E" y la segunda más frecuente a "A"
    most_frequent_letter = sorted_frequency[0][0]
    second_most_frequent_letter = sorted_frequency[1][0]

    # Resuelve el sistema de ecuaciones
    a, b = solve_affine_cipher_parameters(most_frequent_letter, second_most_frequent_letter)

    # Descifra el criptograma utilizando "a" y "b"
    decrypted_text = affine_decrypt(ciphertext, a, b)

    return decrypted_text

# Función para resolver el sistema de ecuaciones para "a" y "b"
def solve_affine_cipher_parameters(one_letter, two_letter):
    # W
    oneletter_value = alphabet[unidecode(one_letter.upper())]
    # K
    twoletter_value = alphabet[unidecode(two_letter.upper())]

    # E = 4, A = 0, W = 23, K = 10

    # Resolver el sistema de ecuaciones
    # [1] W = a * E + b mod 27
    # [2] K = a * A + b mod 27

    # Encontrar "b"
    a = 0
    A_value = alphabet.get('A', None)
    # [2] K = a * A + b mod 27
    # De [2] encontramos, despejando b:
    # b = K - a * A mod 27
    b = (twoletter_value - (a * A_value)) % 27 # b = 10 - a * 0 mod 27 = 10

    # Encontrar "a"
    E_value = alphabet.get('E', None)
    # [1] W = a * E + b mod 27
    # Reemplazando b en [1] y despejando a:
    # a = (W - b) * inv(E, 27) mod 27
    a = ((oneletter_value - b) * inv(E_value, 27)) % 27 # a = (23 – 10) * inv (4, 27) mod 27
    # a = 13 * 7 mod 27 = 10 
    # (valor válido, porque 10 tiene inverso en modulo 27)
    
    return a, b

# Función para descifrar el criptograma utilizando "a" y "b"
def affine_decrypt(ciphertext, a, b):
    result = []
    for char in ciphertext:
        if char.isalpha():
            char = char.upper()  # Convierte el carácter a mayúscula
            char_value = alphabet[char]
            decrypted_value = (inv(a, 27) * (char_value - b)) % 27
            decrypted_char = [
                key for key, value in alphabet.items() if value == decrypted_value][0]
            result.append(decrypted_char)
        else:
            result.append(char)

    return ''.join(result)

# Ruta para realizar el análisis de frecuencia y mostrar el gráfico en la página
# Grafico de analisis de frecuencia Txt Ingresado de cifrado
@app.route('/frequencyI_Cifrado', methods=['POST'])
@login_required
def frequencyTxtIngresado_Cifrado():
    text = request.form['text']
    img_data = generate_frequency_chart(text, tituloCustom = 1)
    return render_template('frequency.html', img_data=img_data)

# Grafico de analisis de frecuencia Txt Resultado de cifrado
@app.route('/frequencyR_Cifrado', methods=['POST'])
@login_required
def frequencyTxtResult_Cifrado():
    img_data = generate_frequency_chart(encrypted_text, tituloCustom = 2)
    return render_template('frequency.html', img_data=img_data)

# Grafico de analisis de frecuencia Txt Ingresado de Descifrado
@app.route('/frequencyI_DesCifrado', methods=['POST'])
@login_required
def frequencyTxtIngresado_DesCifrado():
    text = request.form['ciphertext']
    img_data = generate_frequency_chart(text, tituloCustom = 1)
    return render_template('frequency.html', img_data=img_data)

# Grafico de analisis de frecuencia Txt Resultado de Descifrado
@app.route('/frequencyR_DesCifrado', methods=['POST'])
@login_required
def frequencyTxtResult_DesCifrado():
    img_data = generate_frequency_chart(decrypted_text, tituloCustom = 2)
    return render_template('frequency.html', img_data=img_data)


# Inicia la aplicación
if __name__ == '__main__':
    app.config.from_object(config['development'])
    csrf.init_app(app)
    app.register_error_handler(401, status_401)
    app.register_error_handler(404, status_404)
    app.run()
