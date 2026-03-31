"""Vercel Python serverless function for the /api/health endpoint."""

import json
from http.server import BaseHTTPRequestHandler


class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({
            "status": "healthy",
            "service": "fintech-threat-agent",
            "version": "2.0.0",
            "engine": "adaptive-ai",
        }).encode())
