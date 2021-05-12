import copy
import shutil
from pathlib import Path

from flask import (
    jsonify,
    render_template,
)

from app import (
    utils,
    scanner
)

# Templates
def home():
    """Home."""
    return render_template('index.html')


def scans():
    """Recent Scans view in ninjacs."""
    return render_template('scans.html')


def scan_result(filename):
    """Get Scan result."""
    res = utils.reconstruct(filename)
    total_sev, total_num_issues, combined_issues = {}, 0, []
    if isinstance(res, list):
        total_files = len(res)
        for item in res:
            sev, issues = utils.get_metrics(item)
            total_sev = utils.merge_dict(total_sev, sev)
            total_num_issues += issues
            combined_issues += item.Issues
    else:
        total_files = 1
        sev, issues = utils.get_metrics(res)
        total_sev = utils.merge_dict(total_sev, sev)
        total_num_issues += issues
        combined_issues += res.Issues
    context = dict()
    context['version'] = "1.0"
    context['year'] = utils.year()
    context['severity'] = total_sev
    context['total_issues'] = total_num_issues
    context['title'] = "Scan Result"
    context['scan_file'] = filename
    context['location'] = filename
    context['templates'] = {}
    context['issues'] = utils.get_issues(combined_issues)
    context['issues_dist'] = utils.get_issues_dist(combined_issues)
    context['total_files'] = total_files
    print(context)
    return render_template('scan_result.html', **context)


def view_file(request):
    """View a File."""
    context = {'contents': 'not_found'}
    path = request.form['path']
    contents = utils.read_file(path)
    context = {'contents': contents}
    return jsonify(**context)