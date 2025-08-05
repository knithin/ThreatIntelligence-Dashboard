import os
import requests
from flask import Flask, jsonify, render_template
from cachetools import TTLCache, cached

app = Flask(__name__)
ABUSEIPDB_API_KEY = os.environ.get('ABUSEIPDB_API_KEY')
ABUSEIPDB_ENDPOINT = "https://api.abuseipdb.com/api/v2/reports"
CACHE_TTL = 900  # 15 minutes

# In-memory cache for threat data
country_threat_cache = TTLCache(maxsize=100, ttl=CACHE_TTL)

def parse_country_threat_counts(incidents):
    """Aggregates threat report counts by country"""
    country_counts = {}
    for incident in incidents:
        country = incident.get('countryCode')
        if country:
            country_counts[country] = country_counts.get(country, 0) + 1
    return country_counts

@cached(country_threat_cache)
def fetch_abuseipdb_threats():
    headers = {'Key': ABUSEIPDB_API_KEY, 'Accept': 'application/json'}
    params = {'maxAgeInDays': 1, 'confidenceMinimum': 70, 'limit': 1000}
    response = requests.get(ABUSEIPDB_ENDPOINT, headers=headers, params=params, timeout=15)
    response.raise_for_status()
    incidents = response.json().get('data', [])
    return parse_country_threat_counts(incidents)

@app.route('/api/threats')
def api_threats():
    try:
        threats_by_country = fetch_abuseipdb_threats()
        return jsonify(threats_by_country)
    except Exception as ex:
        return jsonify({"error": str(ex)}), 500

@app.route('/')
def dashboard():
    return render_template('dashboard.html')

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8080)
