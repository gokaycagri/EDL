import logging
from ..db_manager import get_indicators_paginated, get_sources_for_indicator, get_sources_for_indicators_batch

logger = logging.getLogger(__name__)

# Auto-Tagging Map based on Source Name keywords
TAG_MAPPINGS = {
    'feodo': ['Botnet', 'C2'],
    'urlhaus': ['Malware', 'Payload'],
    'usom': ['Phishing', 'Fraud', 'Malicious'],
    'openphish': ['Phishing'],
    'phishtank': ['Phishing'],
    'abuse': ['Abuse'],
    'alienvault': ['Reputation'],
    'blocklist': ['Blocklist'],
    'tor': ['Anonymizer'],
    'proxy': ['Proxy']
}

def _get_tags_from_sources(sources):
    tags = set()
    source_names = [s['source_name'].lower() for s in sources]
    
    for name in source_names:
        for keyword, mapped_tags in TAG_MAPPINGS.items():
            if keyword in name:
                tags.update(mapped_tags)
    
    if not tags:
        tags.add('Uncategorized')
    
    return list(tags)

def _calculate_risk_level(score):
    if score >= 90: return 'Critical'
    if score >= 70: return 'High'
    if score >= 40: return 'Medium'
    return 'Low'

def get_analysis_data(draw, start, length, search_value, filters, order_col, order_dir):
    """
    Orchestrates the fetching and enrichment of analysis data.
    """
    total, filtered, items = get_indicators_paginated(start, length, search_value, filters, order_col, order_dir)
    
    # 1. Batch fetch sources to avoid N+1 query problem
    indicators = [item['indicator'] for item in items]
    batch_sources = get_sources_for_indicators_batch(indicators)
    
    data = []
    for item in items:
        # Fetch Sources from batch result
        sources_info = batch_sources.get(item['indicator'], [])
        
        # 2. Generate Tags
        tags = _get_tags_from_sources(sources_info)
        
        # 3. Determine Level
        level = _calculate_risk_level(item['risk_score'])
        
        # 4. Format Reasons (Source breakdown)
        # We limit to showing top 3 sources to keep UI clean
        source_names = [s['source_name'] for s in sources_info]
        display_sources = ", ".join(source_names[:3])
        if len(source_names) > 3:
            display_sources += f" (+{len(source_names)-3} more)"

        data.append({
            "indicator": item['indicator'],
            "type": item['type'],
            "country": item['country'],
            "risk_score": item['risk_score'],
            "level": level,
            "source_count": item['source_count'],
            "last_seen": item['last_seen'],
            "sources": display_sources,
            "tags": tags
        })

    return {
        "draw": draw,
        "recordsTotal": total,
        "recordsFiltered": filtered,
        "data": data
    }