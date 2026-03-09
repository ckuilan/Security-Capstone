from flask import Flask, render_template, jsonify, request, redirect, url_for, session
from flask_cors import CORS
import subprocess
import threading
import os
import yaml
from functools import wraps
from modules.config import FIREWALL_IP_MAPPING

app = Flask(__name__)
CORS(app)
app.secret_key = 'your-secret-key-change-this-in-production'

tasks = {}
POLICIES_FILE = 'staged-policies.yaml'

VALID_USERNAME = 'admin', 'admin123'
VALID_PASSWORD = 'admin', 'admin123'

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return jsonify({'error': 'Unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated_function

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.json if request.is_json else request.form
        username = data.get('username')
        password = data.get('password')
        
        if username in VALID_USERNAME and password in VALID_PASSWORD:
            session['user'] = username
            if request.is_json:
                return jsonify({'status': 'success'})
            return redirect(url_for('dashboard'))
        else:
            if request.is_json:
                return jsonify({'error': 'Invalid credentials'}), 401
            return render_template('login.html', error='Invalid username or password')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

@app.route('/')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template('index.html')

@app.route('/api/generate', methods=['POST'])
@login_required
def generate():
    def run_task():
        try:
            cmd = ['python', 'pipeline.py', 'generate',
                   '--couchdb-url', 'http://172.20.30.2:5984']
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding='utf-8',
                timeout=120
            )
            tasks['generate'] = {
                'status': 'success' if result.returncode == 0 else 'failed',
                'output': result.stdout + result.stderr
            }
        except Exception as e:
            tasks['generate'] = {'status': 'error', 'output': str(e)}
    
    thread = threading.Thread(target=run_task)
    thread.daemon = True
    thread.start()
    
    tasks['generate'] = {'status': 'running', 'output': 'Starting policy generation...'}
    return jsonify({'status': 'started', 'task': 'generate'})

@app.route('/api/list-firewalls', methods=['GET'])
@login_required
def list_firewalls():
    import glob
    files = glob.glob('staged-policies-*.yaml')
    firewalls = [f.replace('staged-policies-', '').replace('.yaml', '') for f in files]
    return jsonify({'firewalls': firewalls})

@app.route('/api/github-upload', methods=['POST'])
@login_required
def github_upload():
    data = request.json
    github_token = data.get('github_token')
    firewall_name = data.get('firewall_name')
    branch = data.get('branch', 'feature/discovery-rule-policies')
    
    if not firewall_name:
        return jsonify({'status': 'error', 'output': 'firewall_name is required'}), 400
    
    def run_task():
        try:
            cmd = ['python', 'pipeline.py', 'github-upload',
                   '--github-token', github_token,
                   '--firewall-name', firewall_name,
                   '--branch', branch]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding='utf-8',
                timeout=120
            )
            tasks['upload'] = {
                'status': 'success' if result.returncode == 0 else 'failed',
                'output': result.stdout + result.stderr
            }
        except Exception as e:
            tasks['upload'] = {'status': 'error', 'output': str(e)}
    
    thread = threading.Thread(target=run_task)
    thread.daemon = True
    thread.start()
    
    tasks['upload'] = {'status': 'running', 'output': 'Starting GitHub upload...'}
    return jsonify({'status': 'started', 'task': 'upload'})

@login_required
@app.route('/api/deploy', methods=['POST'])
def deploy():
    data = request.json
    github_token = data.get('github_token')
    firewall_name = data.get('firewall_name')
    branch = data.get('branch', 'feature/discovery-rule-policies')
    
    if not firewall_name:
        return jsonify({'status': 'error', 'output': 'firewall_name is required'}), 400
    
    firewall_ip = FIREWALL_IP_MAPPING.get(firewall_name)
    if not firewall_ip:
        return jsonify({'status': 'error', 'output': f'No IP mapping found for firewall: {firewall_name}'}), 400
    
    def run_task():
        try:
            cmd = ['python', 'pipeline.py', 'deploy',
                   '--github-token', github_token,
                   '--firewall-ip', firewall_ip,
                   '--firewall-name', firewall_name,
                   '--branch', branch]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding='utf-8',
                timeout=120
            )
            tasks['deploy'] = {
                'status': 'success' if result.returncode == 0 else 'failed',
                'output': result.stdout + result.stderr
            }
        except Exception as e:
            tasks['deploy'] = {'status': 'error', 'output': str(e)}
    
    thread = threading.Thread(target=run_task)
    thread.daemon = True
    thread.start()
    
    tasks['deploy'] = {'status': 'running', 'output': 'Starting deployment...'}
    return jsonify({'status': 'started', 'task': 'deploy'})

@login_required
@app.route('/api/validate', methods=['POST'])
def validate():
    def run_task():
        try:
            result = subprocess.run(
                ['python', 'pipeline.py', 'validate', '--firewall-ip', '172.20.30.7'],
                capture_output=True,
                text=True,
                encoding='utf-8',
                timeout=60
            )
            tasks['validate'] = {
                'status': 'success' if result.returncode == 0 else 'failed',
                'output': result.stdout + result.stderr
            }
        except Exception as e:
            tasks['validate'] = {'status': 'error', 'output': str(e)}
    
    thread = threading.Thread(target=run_task)
    thread.daemon = True
    thread.start()
    
    tasks['validate'] = {'status': 'running', 'output': 'Validating rules...'}
    return jsonify({'status': 'started', 'task': 'validate'})

@app.route('/api/task/<task_id>', methods=['GET'])
@login_required
def get_task(task_id):
    task = tasks.get(task_id, {'status': 'unknown', 'output': ''})
    return jsonify(task)

@app.route('/api/policies', methods=['GET'])
@login_required
def get_policies():
    try:
        firewall_name = request.args.get('firewall', 'default')
        policies_file = f'staged-policies-{firewall_name}.yaml'
        
        if not os.path.exists(policies_file):
            return jsonify({'policies': []})
        
        with open(policies_file, 'r') as f:
            data = yaml.safe_load(f) or {}
            policies = data.get('policies', [])
        
        return jsonify({'policies': policies})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/policies', methods=['POST'])
@login_required
def save_policies():
    try:
        data = request.json
        firewall_name = data.get('firewall', 'default')
        policies = data.get('policies', [])
        
        policies_file = f'staged-policies-{firewall_name}.yaml'
        with open(policies_file, 'w') as f:
            yaml.dump({'policies': policies}, f, default_flow_style=False, sort_keys=False)
        
        return jsonify({'status': 'saved', 'count': len(policies)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/policies/<int:index>', methods=['DELETE'])
@login_required
def delete_policy(index):
    try:
        firewall_name = request.args.get('firewall', 'default')
        policies_file = f'staged-policies-{firewall_name}.yaml'
        
        with open(policies_file, 'r') as f:
            file_data = yaml.safe_load(f) or {}
            policies = file_data.get('policies', [])
        
        if 0 <= index < len(policies):
            policies.pop(index)
            
            with open(policies_file, 'w') as f:
                yaml.dump({'policies': policies}, f, default_flow_style=False, sort_keys=False)
            
            return jsonify({'status': 'deleted', 'count': len(policies)})
        else:
            return jsonify({'error': 'Index out of range'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/policies', methods=['PUT'])
@login_required
def update_policy():
    try:
        data = request.json
        firewall_name = data.get('firewall', 'default')
        index = data.get('index')
        policy = data.get('policy')
        
        policies_file = f'staged-policies-{firewall_name}.yaml'
        with open(policies_file, 'r') as f:
            file_data = yaml.safe_load(f) or {}
            policies = file_data.get('policies', [])
        
        if 0 <= index < len(policies):
            policies[index] = policy
            
            with open(policies_file, 'w') as f:
                yaml.dump({'policies': policies}, f, default_flow_style=False, sort_keys=False)
            
            return jsonify({'status': 'updated'})
        else:
            return jsonify({'error': 'Index out of range'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/policies/add', methods=['POST'])
@login_required
def add_policy():
    try:
        data = request.json
        firewall_name = data.get('firewall', 'default')
        new_policy = data.get('policy')
        
        policies_file = f'staged-policies-{firewall_name}.yaml'
        with open(policies_file, 'r') as f:
            file_data = yaml.safe_load(f) or {}
            policies = file_data.get('policies', [])
        
        policies.append(new_policy)
        
        with open(policies_file, 'w') as f:
            yaml.dump({'policies': policies}, f, default_flow_style=False, sort_keys=False)
        
        return jsonify({'status': 'added', 'count': len(policies)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
