import re, random, signal
import bcrypt
import os, subprocess, sqlite3
import requests
import time
import math
import ast

'''
Welcome to buggy land :)) where you can find so many CWE and CVE.
Your tasks are to find some tools to detect them all and fix them.
Some will be found by scanning tool while others require you to fuzz them.
'''

######################################################################################

# Eval is devil ;-;
def boschcoderace_sum_of_list_number(lst):
    sum_num = 0
    
    numbers = ast.literal_eval(lst)
# numbers = eval(lst)
    for num in numbers:
        sum_num = sum_num + num
        
    print(f"Sum of {numbers} = {sum_num}")

# Fix syntax
def boschcoderace_validate_ip(ip):
    ip_validator = re.compile(r"((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}")
    if re.match(ip_validator, ip):
        return ip
    else:
        raise ValueError("IP address does not match valid pattern.")

# ok
def boschcoderace_run_ping(str):
    validated = boschcoderace_validate_ip(str)
    # The ping command treats zero-prepended IP addresses as octal
    result = subprocess.call(["ping", validated])
    print(result)

def boschcoderace_request_access():
    return True

def boschcoderace_remove_access():
    return True

def boschcoderace_check_username(username):
    # Define the regular expression pattern for valid usernames
    pattern = r'^[a-zA-Z0-9]+$'

    # Check if the username matches the pattern
    if re.match(pattern, username):
        return True
    else:
        if not re.match(r'[a-zA-Z]', username):
            print('Username must include at least one letter')
        elif not re.match(r'\d', username):
            print('Username must include at least one digit')
        else:
            print('Username cannot include special character')
        return False

def boschcoderace_make_new_userdir(username):
    if boschcoderace_check_username(username):
        print('Usernames cannot contain invalid characters')
        return False
    
    try:
        boschcoderace_request_access()
        subprocess.call(["cd", "/home/"])
        subprocess.call(["mkdir", username])
        # os.mkdir('/home/' + username)
        boschcoderace_remove_access()
    except OSError:
        print('Unable to create new user directory for user:' + username)
        return False
    
    return True

def boschcoderace_update_user_login(username, hashedPassword):
    return True

def boschcoderace_store_password(username, password):
    hashedPassword = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    # UpdateUserLogin returns True on success, False otherwise
    return boschcoderace_update_user_login(username, hashedPassword)

def boschcoderace_validate_password(actual_pw, typed_pw):
    if len(actual_pw) != len(typed_pw):
        return False
    
    for i in range(len(actual_pw)):
        if actual_pw[i] != typed_pw[i]:
            return False
    
    return True

def boschcoderace_random():
    seed = os.urandom(16)
    random.seed(a=seed)
    return random.getrandbits(128)

def boschcoderace_get_curuser():
    return os.getpid()

def boschcoderace_get_process_owner(processID):
    user = boschcoderace_get_curuser()
    #Check process owner against requesting user
    if processID == user:
        os.kill(processID, signal.SIGKILL)
        return
    else:
        print("You cannot kill a process you don't own")
        return

######################################################################################
def calculate_surface_area(s, r, d):
    pi = 3.14159
    surface_area = 0
    result = 0
    isSValid = False
    isRValid = False

    if(s > 2.0 and r > 0.0):
        isRValid = True
        isRValid = True # set wrong variable
        surface_area = (pi * r * s + pi * pow(r, 2))/d
        if (isRValid and isSValid):
            print("This is dead code !!!")
    elif(s > 0.0 and r > 1.0):
        isRValid = True
        isRValid = True # set wrong variable
        surface_area = (pi * r * s + pi * pow(r, 2))/d
        if (isSValid):
            print("This is also dead code !!!")
    
    if (isRValid and isSValid):
        print("This is also another dead code !!!")
        result = surface_area

    return result

def execute_internal_script():
    internal_script_name = "example_script.sh"
    options = input("Enter a options to execute: ")
    subprocess.call([internal_script_name, options])
    # os.system(internal_script_name + " " + options)

def calc_sum_of_exp_value():
    sum = 0
    numbers = ast.literal_eval(input("Enter a comma-separated list of numbers: "))
    for num in numbers:
        sum = sum + math.exp(num)
    print(f"Sum of {numbers} = {sum}")

def execute_user_query():
    user_query = input("Enter a SQL query: ")
    
    database = "db_users.sqlite"
    query = "SELECT * FROM users WHERE username = %(user_query)s;"
    data = {
        "user_query": user_query
    }
    
    lib.execute_sql_query(database, query, data)

def read_file():
    try:
        file_path = input("Enter the file path to read: ")
        with open(file_path, "r") as file:
            content = file.read()
            print("File content:", content)
    except:
        pass

######################################################################################
from flask import Blueprint, render_template, redirect, request, session, make_response, flash
import lib

mod_user = Blueprint('mod_user', __name__, template_folder='templates')

@mod_user.route('/user/login', methods=['GET', 'POST'])
def do_login():

    session.pop('username', None)

    if request.method == 'POST':

        username = request.form.get('username')
        password = request.form.get('password')
        otp = request.form.get('otp')

        hashedPassword = lib.login(username)
        
        if not hashedPassword:
            flash("Invalid user or password");
            return render_template('user.login.mfa.html')
        
        if not boschcoderace_validate_password(hashedPassword, password):
            flash("Invalid user or password");
            return render_template('user.login.mfa.html')

        if lib.mfa_is_enabled(username):
            if not lib.mfa_validate(username, otp):
                flash("Invalid OTP");
                return render_template('user.login.mfa.html')

        response = make_response(redirect('/'))
        response = lib.create_response(response=response, username=username)
        return response

    return render_template('user.login.mfa.html')

@mod_user.route('/create', methods=['GET', 'POST'])
def do_create():

    session.pop('username', None)

    if request.method == 'POST':

        username = request.form.get('username')
        password = request.form.get('password')
        #email = request.form.get('password')
        if not username or not password:
            flash("Please, complete username and password")
            return render_template('user.create.html')

        lib.create(username, password)
        flash("User created. Please login.")
        return redirect('/user/login')
    return render_template('user.create.html')


@mod_user.route('/chpasswd', methods=['GET', 'POST'])
def do_chpasswd():

    if request.method == 'POST':

        password = request.form.get('password')
        password_again = request.form.get('password_again')

        if password != password_again:
            flash("The passwords don't match")
            return render_template('user.chpasswd.html')

        if not lib.password_complexity(password):
            flash("The password don't comply our complexity requirements")
            return render_template('user.chpasswd.html')
        
        username = session.get('username')
        if not username:
            flash("User not logged in")
            return redirect('/user/login')
        
        lib.password_change(username, password) # = libuser.login(username, password)
        flash("Password changed")

    return render_template('user.chpasswd.html')