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
    """Recent Scans view in nodejsscan."""
    return render_template('scans.html')


def scan_result(filename):
    """Get Scan result."""
    res = utils.reconstruct(filename)
    sev, issues = utils.get_metrics(res)
    context = dict()
    context['version'] = "1.0"
    context['year'] = utils.year()
    context['severity'] = sev
    context['total_issues'] = issues
    context['title'] = "Scan Result"
    context['scan_file'] = filename
    context['location'] = filename
    context['templates'] = {}
    context['issues'] = utils.get_issues(res.Issues)
    context['lines'] = res.Lines
    context['size'] = res.Size
    context['issues_dist'] = utils.get_issues_dist(res.Issues)
    print(context)
    return render_template('scan_result.html', **context)


def issue_revert(request):
    """Revert FP/NA."""
    scan_hash = request.form['scan_hash']
    finding_hash = request.form['finding_hash']
    if not (utils.issha2(scan_hash) and utils.issha2(finding_hash)):
        return jsonify(**{
            'status': 'failed',
            'message': 'Invalid hash'})
    res = get_results(scan_hash)
    if not res:
        return jsonify({
            'status': 'failed',
            'message': 'Scan hash not found'})
    fp_key = 'false_positive'
    na_key = 'not_applicable'
    fp = res[fp_key]
    na = res[na_key]
    if finding_hash in fp:
        fp.remove(finding_hash)
        update_issue(scan_hash, fp_key, fp)
    elif finding_hash in na:
        na.remove(finding_hash)
        update_issue(scan_hash, na_key, na)
    else:
        return jsonify({
            'status': 'failed',
            'message': 'Finding not found'})
    return jsonify({'status': 'ok'})


def issue_hide(request, issue_type):
    """Issue is FP/NA."""
    scan_hash = request.form['scan_hash']
    finding_hash = request.form['id']
    if not (utils.issha2(scan_hash) and utils.issha2(finding_hash)):
        return jsonify({
            'status': 'failed',
            'message': 'Invalid hash'})
    res = get_results(scan_hash)
    if not res:
        return jsonify({
            'status': 'failed',
            'message': 'Scan hash not found'})
    if issue_type == 'fp':
        key = 'false_positive'
    else:
        key = 'not_applicable'
    item = res[key]
    if finding_hash not in item:
        item.append(finding_hash)
        update_issue(scan_hash, key, item)
    return jsonify({'status': 'ok'})


def view_file(request):
    """View a File."""
    context = {'contents': 'not_found'}
    path = request.form['path']
    scan_hash = request.form['scan_hash']
    if not utils.issha2(scan_hash):
        return jsonify({
            'status': 'failed',
            'message': 'Invalid hash'})
    res = get_results(scan_hash)
    if not res:
        return jsonify({
            'status': 'failed',
            'message': 'Scan hash not found'})
    safe_dir = settings.UPLOAD_FOLDER
    req_path = Path(safe_dir) / path
    if not utils.is_safe_path(safe_dir, req_path.as_posix()):
        context = {
            'status': 'failed',
            'contents': 'Path Traversal Detected!'}
    else:
        if req_path.is_file():
            contents = utils.read_file(req_path.as_posix())
            context = {'contents': contents}
    return jsonify(**context)