import sys
import shutil
import zipfile
import subprocess
from pathlib import Path

from werkzeug.utils import secure_filename

from flask import jsonify

from app import (
    settings,
    utils,
    scanner
)


def unzip(app_path, ext_path):
    """Unzip files to a given path."""
    print('[INFO] Unzipping file', file=sys.stderr)
    try:
        ext_path = Path(ext_path)
        print("app_path: " + app_path)
        print("ext_path: " + ext_path)
        if not ext_path.exists():
            ext_path.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(app_path.as_posix(), 'r') as ptr:
            ptr.extractall(ext_path.as_posix())
    except Exception:
        print('[ERROR] Unzipping with Python API')
        print('[INFO] Using the default OS unzip utility.', file=sys.stderr)
        try:
            subprocess.call([
                shutil.which('unzip'),
                '-o',
                '-q',
                app_path,
                '-d',
                ext_path.as_posix()])
        except Exception:
            print('[ERROR] Unzipping from zip file')


def handle_upload(app, request):
    """Handle File Upload."""
    failed = {
        'status': 'failed',
        'message': 'Upload Failed!'}
    if 'file' not in request.files:
        return jsonify(failed)
    filen = request.files['file']
    ext = Path(filen.filename.lower()).suffix
    filename = filen.filename.lower()
    # Check for Valid ZIP
    if not ext in '.zip':
        return jsonify(failed)
    # Save file
    zip_file = Path(app.config['UPLOAD_FOLDER']) / filename
    filen.save(zip_file)
    # App analysis dir
    app_dir = Path(app.config['UPLOAD_FOLDER']) / filename.split('.')[0]
    # Make app analysis dir
    if not app_dir.exists():
        app_dir.mkdir(mode=0o755, parents=True, exist_ok=True)
    app_dir = app_dir.as_posix()
    # Unzip
    unzip(zip_file, app_dir)
    # Do scan
    results = scanner.scan_directory(app_dir)
    # Save Result
    print('[INFO] Saving Scan Results!')
    return jsonify({
        'status': 'success',
        'url': 'result/?filename=' + filename.split('.')[0]})
