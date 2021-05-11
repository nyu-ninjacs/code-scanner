from pathlib import Path

UPLOAD_FOLDER = "../testdata"
Path(UPLOAD_FOLDER).mkdir(parents=True, exist_ok=True)
IGNORE_PATHS = ('.git', '.DS_Store')
CHECK_MISSING_CONTROLS = True