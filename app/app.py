import sys
sys.path.append(r'../engine')
sys.path.append(r'../rule')

import re
import os

from flask import Flask, request
import app.settings as settings
from .scanner import *

# from web.upload import handle_upload
# from web.git import clone
from web.dashboard import (
    home,
    scan_result,
    scans,
    view_file,
)

from web.upload import (
    handle_upload
)

from app import utils

app = Flask(__name__,
            template_folder='../templates',
            static_folder='../static')

app.config['UPLOAD_FOLDER'] = settings.UPLOAD_FOLDER

@app.template_filter('slugify')
def _slugify(string):
    if not string:
        return ''
    return utils.slugify(string)


@app.template_filter('deslugify')
def _deslugify(string):
    if not string:
        return ''
    return utils.deslugify(string)


@app.template_filter('relative')
def relative(string):
    if not string:
        return ''
    result = re.compile(r'[A-Fa-f0-9]{64}[/\\]').search(string)
    if not result:
        return string
    return string.split(result.group(0), 1)[1]


@app.context_processor
def _year():
    return {'year': utils.year()}


@app.template_filter('js_escape')
def _js_escape(string):
    if not string:
        return ''
    return utils.js_escape(string)


@app.route('/', methods=['GET'])
def index():
    """Handle Index."""
    return home()


@app.route('/upload/', methods=['POST'])
def upload():
    """Upload and scan from zip."""
    return handle_upload(app, request)


@app.route('/scan/', methods=['POST'])
def scan_filename():
    """Scan with filename."""
    filename = request.form['filename']
    return scan(filename)

@app.route('/result/', methods=['GET'])
def show_result():
    """Show a scan result."""
    return scan_result(request.args.get('filename'))

@app.route('/view_file', methods=['POST'])
def view():
    return view_file(request)

