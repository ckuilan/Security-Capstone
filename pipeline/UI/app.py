from flask import Flask, render_template, request
import subprocess
import os

app = Flask(__name__)
POLICIES_DIR = '../../Policies'

@app.route('/', methods=['GET', 'POST'])
def index():
    output = ''
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'discovery':
            username = request.form.get('couchdb_username')
            password = request.form.get('couchdb_password')
            result = subprocess.run(['python3', '../modules/couchdb.py', username, password], capture_output=True, text=True)
            output = result.stdout + result.stderr
        
        elif action == 'push':
            firewall = request.form.get('firewall')
            token = request.form.get('token')
            result = subprocess.run(['python3', 'push_policy.py', token, firewall], capture_output=True, text=True)
            output = result.stdout + result.stderr
        
        elif action == 'deploy':
            firewall = request.form.get('firewall')
            username = request.form.get('username')
            password = request.form.get('password')
            result = subprocess.run(['python3', 'deploy_policy.py', firewall, username, password], capture_output=True, text=True)
            output = result.stdout + result.stderr
    
    policies = {}
    for fw in os.listdir(POLICIES_DIR):
        path = f'{POLICIES_DIR}/{fw}/staged-policies.yaml'
        if os.path.exists(path):
            with open(path) as f:
                policies[fw] = f.read()
    
    return render_template('index.html', policies=policies, output=output)

def main():
    app.run(host='0.0.0.0', port=5000)

main()
