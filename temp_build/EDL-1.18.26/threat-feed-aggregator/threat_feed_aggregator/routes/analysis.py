import json
from flask import Blueprint, render_template, request, jsonify
from .auth import login_required
from ..services.analysis_service import get_analysis_data
from ..db_manager import get_filter_options

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
        return jsonify([])

    # Static lists for some columns
    if column == 'level':
        options = ['Critical', 'High', 'Medium', 'Low']
        if search:
            options = [o for o in options if search.lower() in o.lower()]
        return jsonify(options)
    
    if column == 'tag':
        # Hardcoded common tags since they are logic-based
        common_tags = ['Botnet', 'C2', 'Malware', 'Phishing', 'Fraud', 'Abuse', 'Reputation', 'Tor', 'Proxy']
        if search:
            common_tags = [t for t in common_tags if search.lower() in t.lower()]
        return jsonify(common_tags)

    # Dynamic DB columns
    results = get_filter_options(column, search)
    return jsonify(results)

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
