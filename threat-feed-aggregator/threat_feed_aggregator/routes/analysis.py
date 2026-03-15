import csv
import io
import json

from flask import Blueprint, render_template, request, jsonify, Response, stream_with_context
from ..response_helpers import api_response
from .auth import login_required
from ..services.analysis_service import get_analysis_data
from ..db_manager import get_filter_options, get_indicators_paginated

bp_analysis = Blueprint('analysis', __name__, url_prefix='/analysis')

@bp_analysis.route('/')
@login_required
def index():
    return render_template('analysis.html')

@bp_analysis.route('/filter-options', methods=['GET'])
@login_required
def filter_options():
    """Returns autocomplete options for filters."""
    column = request.args.get('column')
    search = request.args.get('q', '')
    
    if not column:
        return api_response({"items": []})

    # Static lists for some columns
    if column == 'level':
        options = ['Critical', 'High', 'Medium', 'Low']
        if search:
            options = [o for o in options if search.lower() in o.lower()]
        return api_response({"items": options})

    if column == 'tag':
        common_tags = ['Botnet', 'C2', 'Malware', 'Phishing', 'Fraud', 'Abuse', 'Reputation', 'Tor', 'Proxy']
        if search:
            common_tags = [t for t in common_tags if search.lower() in t.lower()]
        return api_response({"items": common_tags})

    # Dynamic DB columns
    results = get_filter_options(column, search)
    return api_response({"items": results})

@bp_analysis.route('/data', methods=['GET'])
@login_required
def data():
    # DataTables Parameters
    draw = request.args.get('draw', type=int)
    start = request.args.get('start', default=0, type=int)
    length = request.args.get('length', default=10, type=int)
    search_value = request.args.get('search[value]', default=None)
    
    # Ordering
    order_column_index = request.args.get('order[0][column]', default=3, type=int) 
    order_dir = request.args.get('order[0][dir]', default='desc')
    
    # Map index to column name
    columns_map = ['indicator', 'type', 'country', 'risk_score', 'level', 'source_count', 'tags', 'last_seen']
    order_col = columns_map[order_column_index] if order_column_index < len(columns_map) else 'risk_score'

    # Extract Filters from 'custom_filters' JSON
    filters = {}
    custom_filters_str = request.args.get('custom_filters')
    if custom_filters_str:
        try:
            filters = json.loads(custom_filters_str)
        except json.JSONDecodeError:
            pass

    result = get_analysis_data(draw, start, length, search_value, filters, order_col, order_dir)
    return jsonify(result)


@bp_analysis.route('/export', methods=['GET'])
@login_required
def export_indicators():
    """Export filtered indicators as CSV or JSON download."""
    export_format = request.args.get('format', 'csv')
    search_value = request.args.get('search', None)
    order_col = request.args.get('order_col', 'risk_score')
    order_dir = request.args.get('order_dir', 'desc')

    filters = {}
    custom_filters_str = request.args.get('custom_filters')
    if custom_filters_str:
        try:
            filters = json.loads(custom_filters_str)
        except json.JSONDecodeError:
            pass

    # Fetch all matching (limit=100000 as safety cap)
    _, _, rows = get_indicators_paginated(
        start=0, length=100000, search_value=search_value,
        filters=filters, order_col=order_col, order_dir=order_dir
    )

    if export_format == 'json':
        return Response(
            json.dumps(rows, indent=2),
            mimetype='application/json',
            headers={'Content-Disposition': 'attachment; filename=indicators_export.json'}
        )

    # Default CSV
    def generate_csv():
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(['indicator', 'type', 'country', 'risk_score', 'source_count', 'last_seen'])
        yield buf.getvalue()
        buf.seek(0)
        buf.truncate(0)
        for row in rows:
            writer.writerow([row.get('indicator'), row.get('type'), row.get('country'),
                            row.get('risk_score'), row.get('source_count'), row.get('last_seen')])
            yield buf.getvalue()
            buf.seek(0)
            buf.truncate(0)

    return Response(
        stream_with_context(generate_csv()),
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=indicators_export.csv'}
    )
