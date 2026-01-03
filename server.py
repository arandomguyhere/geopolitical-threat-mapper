#!/usr/bin/env python3
"""
Geopolitical Threat Mapper - Web Dashboard Server

Serves a map-based UI showing:
- GPS interference zones
- Aviation activity (military flights)
- Cyber threat heatmap
- Chokepoint threat levels
- AIS Tracker integration (if running)
"""

import asyncio
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

import aiohttp
from flask import Flask, jsonify, render_template_string, send_from_directory

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("ThreatMapperUI")

app = Flask(__name__)

# Configuration
OUTPUT_DIR = Path(__file__).parent / "output"
CONFIG_DIR = Path(__file__).parent / "scripts" / "config"
AIS_TRACKER_URL = os.getenv("AIS_TRACKER_URL", "http://localhost:8080")

# HTML Template with Leaflet map
DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Geopolitical Threat Mapper</title>
    <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #1a1a2e; color: #eee; }

        #header {
            background: linear-gradient(135deg, #16213e 0%, #1a1a2e 100%);
            padding: 12px 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid #0f3460;
        }

        #header h1 {
            font-size: 1.4rem;
            font-weight: 600;
            color: #e94560;
        }

        .stats {
            display: flex;
            gap: 25px;
        }

        .stat {
            text-align: center;
        }

        .stat-value {
            font-size: 1.5rem;
            font-weight: bold;
        }

        .stat-label {
            font-size: 0.7rem;
            text-transform: uppercase;
            color: #888;
        }

        .critical { color: #e94560; }
        .high { color: #f39c12; }
        .medium { color: #3498db; }
        .low { color: #2ecc71; }

        #map { height: calc(100vh - 60px); width: 100%; }

        .layer-control {
            position: absolute;
            top: 80px;
            right: 10px;
            z-index: 1000;
            background: rgba(26, 26, 46, 0.95);
            padding: 15px;
            border-radius: 8px;
            border: 1px solid #0f3460;
            min-width: 200px;
        }

        .layer-control h3 {
            font-size: 0.9rem;
            margin-bottom: 10px;
            color: #e94560;
        }

        .layer-item {
            display: flex;
            align-items: center;
            gap: 8px;
            padding: 5px 0;
            cursor: pointer;
        }

        .layer-item input { cursor: pointer; }

        .legend {
            position: absolute;
            bottom: 30px;
            left: 10px;
            z-index: 1000;
            background: rgba(26, 26, 46, 0.95);
            padding: 15px;
            border-radius: 8px;
            border: 1px solid #0f3460;
        }

        .legend h4 {
            font-size: 0.8rem;
            margin-bottom: 8px;
            color: #e94560;
        }

        .legend-item {
            display: flex;
            align-items: center;
            gap: 8px;
            font-size: 0.75rem;
            padding: 3px 0;
        }

        .legend-color {
            width: 16px;
            height: 16px;
            border-radius: 3px;
        }

        .info-panel {
            position: absolute;
            top: 80px;
            left: 10px;
            z-index: 1000;
            background: rgba(26, 26, 46, 0.95);
            padding: 15px;
            border-radius: 8px;
            border: 1px solid #0f3460;
            max-width: 300px;
            display: none;
        }

        .info-panel.active { display: block; }

        .info-panel h3 {
            font-size: 1rem;
            margin-bottom: 10px;
            color: #e94560;
        }

        .info-row {
            display: flex;
            justify-content: space-between;
            padding: 4px 0;
            font-size: 0.85rem;
            border-bottom: 1px solid #0f3460;
        }

        .info-label { color: #888; }

        .pulse {
            animation: pulse 2s infinite;
        }

        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }

        .leaflet-popup-content-wrapper {
            background: #1a1a2e;
            color: #eee;
            border: 1px solid #0f3460;
        }

        .leaflet-popup-tip { background: #1a1a2e; }

        .popup-title {
            font-weight: bold;
            color: #e94560;
            margin-bottom: 8px;
        }

        .popup-row {
            font-size: 0.85rem;
            padding: 2px 0;
        }

        .ais-link {
            display: inline-block;
            margin-top: 10px;
            padding: 5px 10px;
            background: #e94560;
            color: white;
            text-decoration: none;
            border-radius: 4px;
            font-size: 0.8rem;
        }

        .ais-link:hover { background: #c73e54; }
    </style>
</head>
<body>
    <div id="header">
        <h1>Geopolitical Threat Mapper</h1>
        <div class="stats">
            <div class="stat">
                <div class="stat-value critical" id="critical-count">0</div>
                <div class="stat-label">Critical</div>
            </div>
            <div class="stat">
                <div class="stat-value high" id="high-count">0</div>
                <div class="stat-label">High</div>
            </div>
            <div class="stat">
                <div class="stat-value medium" id="aircraft-count">0</div>
                <div class="stat-label">Aircraft</div>
            </div>
            <div class="stat">
                <div class="stat-value low" id="gps-zones">0</div>
                <div class="stat-label">GPS Zones</div>
            </div>
        </div>
    </div>

    <div id="map"></div>

    <div class="layer-control">
        <h3>Layers</h3>
        <label class="layer-item">
            <input type="checkbox" id="layer-gps" checked> GPS Interference
        </label>
        <label class="layer-item">
            <input type="checkbox" id="layer-aviation" checked> Aviation
        </label>
        <label class="layer-item">
            <input type="checkbox" id="layer-chokepoints" checked> Chokepoints
        </label>
        <label class="layer-item">
            <input type="checkbox" id="layer-vessels"> AIS Vessels
        </label>
        <label class="layer-item">
            <input type="checkbox" id="layer-cyber" checked> Cyber Threats
        </label>
    </div>

    <div class="legend">
        <h4>Threat Levels</h4>
        <div class="legend-item">
            <div class="legend-color" style="background: #e94560;"></div>
            <span>Critical</span>
        </div>
        <div class="legend-item">
            <div class="legend-color" style="background: #f39c12;"></div>
            <span>High</span>
        </div>
        <div class="legend-item">
            <div class="legend-color" style="background: #3498db;"></div>
            <span>Medium</span>
        </div>
        <div class="legend-item">
            <div class="legend-color" style="background: #2ecc71;"></div>
            <span>Low</span>
        </div>
        <h4 style="margin-top: 10px;">Markers</h4>
        <div class="legend-item">
            <div class="legend-color" style="background: #3498db; border-radius: 50%;"></div>
            <span>Aircraft</span>
        </div>
        <div class="legend-item">
            <div class="legend-color" style="background: #9b59b6; border-radius: 50%;"></div>
            <span>GPS Interference</span>
        </div>
        <div class="legend-item">
            <div class="legend-color" style="background: #e94560;"></div>
            <span>Chokepoint</span>
        </div>
    </div>

    <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
    <script>
        // Initialize map
        const map = L.map('map', {
            center: [30, 50],
            zoom: 3,
            minZoom: 2,
            maxZoom: 18
        });

        // Dark tile layer
        L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
            attribution: '&copy; OpenStreetMap, &copy; CARTO'
        }).addTo(map);

        // Layer groups - no clustering for aircraft so they show individually
        const layers = {
            gps: L.layerGroup().addTo(map),
            aviation: L.layerGroup().addTo(map),
            chokepoints: L.layerGroup().addTo(map),
            vessels: L.layerGroup(),
            cyber: L.layerGroup().addTo(map)
        };

        // Create rotated aircraft icon based on heading
        function createAircraftIcon(heading, isMilitary) {
            const color = isMilitary ? '#e94560' : '#3498db';
            const size = isMilitary ? 24 : 18;
            const rotation = heading || 0;
            return L.divIcon({
                html: `<svg width="${size}" height="${size}" viewBox="0 0 24 24" style="transform: rotate(${rotation}deg);" fill="${color}"><path d="M21 16v-2l-8-5V3.5c0-.83-.67-1.5-1.5-1.5S10 2.67 10 3.5V9l-8 5v2l8-2.5V19l-2 1.5V22l3.5-1 3.5 1v-1.5L13 19v-5.5l8 2.5z"/></svg>`,
                className: 'aircraft-icon',
                iconSize: [size, size],
                iconAnchor: [size/2, size/2]
            });
        }

        // Custom icons using SVG
        const icons = {
            military: L.divIcon({
                html: '<svg width="24" height="24" viewBox="0 0 24 24" fill="#e94560"><path d="M21 16v-2l-8-5V3.5c0-.83-.67-1.5-1.5-1.5S10 2.67 10 3.5V9l-8 5v2l8-2.5V19l-2 1.5V22l3.5-1 3.5 1v-1.5L13 19v-5.5l8 2.5z"/></svg>',
                className: 'aircraft-icon',
                iconSize: [24, 24],
                iconAnchor: [12, 12]
            }),
            civilian: L.divIcon({
                html: '<svg width="20" height="20" viewBox="0 0 24 24" fill="#3498db" opacity="0.7"><path d="M21 16v-2l-8-5V3.5c0-.83-.67-1.5-1.5-1.5S10 2.67 10 3.5V9l-8 5v2l8-2.5V19l-2 1.5V22l3.5-1 3.5 1v-1.5L13 19v-5.5l8 2.5z"/></svg>',
                className: 'aircraft-icon',
                iconSize: [20, 20],
                iconAnchor: [10, 10]
            }),
            gps: L.divIcon({
                html: '<svg width="24" height="24" viewBox="0 0 24 24" fill="#9b59b6"><circle cx="12" cy="12" r="8" stroke="#9b59b6" stroke-width="2" fill="none"/><circle cx="12" cy="12" r="3" fill="#9b59b6"/><line x1="12" y1="2" x2="12" y2="6" stroke="#9b59b6" stroke-width="2"/><line x1="12" y1="18" x2="12" y2="22" stroke="#9b59b6" stroke-width="2"/><line x1="2" y1="12" x2="6" y2="12" stroke="#9b59b6" stroke-width="2"/><line x1="18" y1="12" x2="22" y2="12" stroke="#9b59b6" stroke-width="2"/></svg>',
                className: 'gps-icon pulse',
                iconSize: [24, 24],
                iconAnchor: [12, 12]
            }),
            chokepoint: L.divIcon({
                html: '<svg width="28" height="28" viewBox="0 0 24 24" fill="#e94560"><path d="M12 2L4 5v6.09c0 5.05 3.41 9.76 8 10.91 4.59-1.15 8-5.86 8-10.91V5l-8-3zm0 15c-2.76 0-5-2.24-5-5s2.24-5 5-5 5 2.24 5 5-2.24 5-5 5z"/></svg>',
                className: 'chokepoint-icon',
                iconSize: [28, 28],
                iconAnchor: [14, 14]
            })
        };

        // Threat level colors
        const threatColors = {
            critical: '#e94560',
            high: '#f39c12',
            medium: '#3498db',
            low: '#2ecc71',
            unknown: '#888'
        };

        // Stats
        let stats = {
            critical: 0,
            high: 0,
            aircraft: 0,
            gpsZones: 0
        };

        // Load threat data
        async function loadData() {
            try {
                // Load feed data
                const feedResp = await fetch('/api/feed');
                const feed = await feedResp.json();

                // Load chokepoints
                const chokepointsResp = await fetch('/api/chokepoints');
                const chokepoints = await chokepointsResp.json();

                // Process data
                processGPSData(feed.gps || []);
                processAviationData(feed.aviation || []);
                processChokepoints(chokepoints);
                processCyberData(feed.cyber || {});

                // Update stats display
                updateStats();

                // Try to load AIS data
                loadAISData();

            } catch (error) {
                console.error('Error loading data:', error);
            }
        }

        function processGPSData(gpsData) {
            layers.gps.clearLayers();

            const zones = gpsData.interference_zones || [];
            stats.gpsZones = zones.length;

            zones.forEach(zone => {
                const lat = zone.lat || zone.center_lat;
                const lon = zone.lon || zone.center_lon;

                if (lat && lon) {
                    // Add interference zone circle
                    const radius = (zone.radius_km || 100) * 1000;
                    const intensity = zone.intensity || 'moderate';
                    const color = intensity === 'severe' ? threatColors.critical :
                                  intensity === 'heavy' ? threatColors.high :
                                  intensity === 'moderate' ? threatColors.medium : threatColors.low;

                    L.circle([lat, lon], {
                        radius: radius,
                        color: color,
                        fillColor: color,
                        fillOpacity: 0.2,
                        weight: 2
                    }).addTo(layers.gps).bindPopup(`
                        <div class="popup-title">GPS Interference Zone</div>
                        <div class="popup-row"><strong>Region:</strong> ${zone.region || 'Unknown'}</div>
                        <div class="popup-row"><strong>Intensity:</strong> ${intensity}</div>
                        <div class="popup-row"><strong>Attribution:</strong> ${zone.attribution || 'Unknown'}</div>
                    `);

                    // Add marker
                    L.marker([lat, lon], { icon: icons.gps })
                        .addTo(layers.gps);
                }
            });
        }

        function processAviationData(aviationData) {
            layers.aviation.clearLayers();

            const aircraft = aviationData.aircraft || [];
            stats.aircraft = aircraft.length;

            let militaryCount = 0;

            aircraft.forEach(ac => {
                const lat = ac.lat || ac.latitude;
                const lon = ac.lon || ac.longitude;

                if (lat && lon) {
                    const isMilitary = ac.is_military || ac.category === 'military';
                    if (isMilitary) militaryCount++;

                    // Get heading/track for rotation (0 = North, 90 = East, etc.)
                    const heading = ac.heading || ac.true_track || ac.track || 0;

                    // Create rotated icon based on heading
                    const icon = createAircraftIcon(heading, isMilitary);

                    const marker = L.marker([lat, lon], { icon: icon })
                        .bindPopup(`
                            <div class="popup-title">${ac.callsign || ac.icao24 || 'Unknown'}</div>
                            <div class="popup-row"><strong>Type:</strong> ${isMilitary ? 'Military' : 'Civilian'}</div>
                            <div class="popup-row"><strong>Altitude:</strong> ${ac.altitude || ac.baro_altitude || 'N/A'} ft</div>
                            <div class="popup-row"><strong>Speed:</strong> ${ac.velocity || ac.ground_speed || 'N/A'} kts</div>
                            <div class="popup-row"><strong>Heading:</strong> ${heading.toFixed(0)}deg</div>
                            <div class="popup-row"><strong>Region:</strong> ${ac.region || 'N/A'}</div>
                        `);

                    layers.aviation.addLayer(marker);
                }
            });

            stats.high = militaryCount;
        }

        function processChokepoints(geojson) {
            layers.chokepoints.clearLayers();

            if (!geojson.features) return;

            geojson.features.forEach(feature => {
                const props = feature.properties || {};
                const geometry = feature.geometry;

                if (geometry && geometry.coordinates) {
                    let lat, lon;

                    if (geometry.type === 'Point') {
                        [lon, lat] = geometry.coordinates;
                    } else if (geometry.type === 'Polygon') {
                        // Use centroid
                        const coords = geometry.coordinates[0];
                        lat = coords.reduce((sum, c) => sum + c[1], 0) / coords.length;
                        lon = coords.reduce((sum, c) => sum + c[0], 0) / coords.length;
                    }

                    if (lat && lon) {
                        const priority = props.priority || 'medium';
                        const color = threatColors[priority] || threatColors.medium;

                        // Add polygon if available
                        if (geometry.type === 'Polygon') {
                            L.polygon(
                                geometry.coordinates[0].map(c => [c[1], c[0]]),
                                { color: color, fillColor: color, fillOpacity: 0.15, weight: 2 }
                            ).addTo(layers.chokepoints);
                        }

                        // Add marker
                        L.marker([lat, lon], { icon: icons.chokepoint })
                            .addTo(layers.chokepoints)
                            .bindPopup(`
                                <div class="popup-title">${props.name || props.id}</div>
                                <div class="popup-row"><strong>Priority:</strong> ${priority}</div>
                                <div class="popup-row"><strong>Threats:</strong> ${(props.threats || []).join(', ') || 'N/A'}</div>
                                <div class="popup-row"><strong>Actors:</strong> ${(props.actors || []).join(', ') || 'N/A'}</div>
                                <a href="http://localhost:8080" target="_blank" class="ais-link">View in AIS Tracker</a>
                            `);

                        if (priority === 'critical') stats.critical++;
                    }
                }
            });
        }

        function processCyberData(cyberData) {
            layers.cyber.clearLayers();

            // Country coordinates (simplified)
            const countryCoords = {
                'CN': [35, 105], 'RU': [60, 100], 'US': [38, -97],
                'IR': [32, 53], 'KP': [40, 127], 'UA': [49, 32],
                'TW': [23.5, 121], 'IL': [31, 35], 'SA': [24, 45],
                'DE': [51, 10], 'FR': [46, 2], 'GB': [54, -2],
                'NL': [52, 5], 'JP': [36, 138], 'KR': [36, 128],
                'IN': [20, 77], 'BR': [-15, -47], 'AU': [-25, 135],
                'CA': [56, -106], 'IT': [42, 12], 'ES': [40, -4],
                'PL': [52, 20], 'TR': [39, 35], 'VN': [16, 108],
                'TH': [15, 100], 'ID': [-5, 120], 'MX': [23, -102],
                'AR': [-34, -64], 'ZA': [-30, 25], 'EG': [27, 30],
                'PK': [30, 70], 'BD': [24, 90], 'PH': [12, 122],
                'MY': [4, 101], 'SG': [1, 104], 'HK': [22, 114],
                'AE': [24, 54], 'BY': [53, 28], 'CZ': [50, 15],
                'RO': [46, 25], 'HU': [47, 20], 'SE': [62, 15],
                'NO': [62, 10], 'FI': [64, 26], 'DK': [56, 10],
                'AT': [47, 13], 'CH': [47, 8], 'BE': [50, 4],
                'PT': [39, -8], 'GR': [39, 22], 'CL': [-35, -71],
                'CO': [4, -72], 'PE': [-10, -76], 'VE': [7, -66],
                'NG': [10, 8], 'KE': [-1, 38], 'MA': [32, -5],
                'DZ': [28, 3], 'LT': [55, 24], 'LV': [57, 25],
                'EE': [59, 26], 'SK': [48, 19], 'BG': [43, 25],
                'RS': [44, 21], 'HR': [45, 16], 'SI': [46, 15],
                'IE': [53, -8], 'NZ': [-41, 174]
            };

            // Track IOC counts by country for aggregation
            const countryIOCs = {};

            // Process IOCs (C2 servers, malware, etc.)
            const iocs = cyberData.iocs || [];
            iocs.forEach(ioc => {
                const country = ioc.country;
                if (country && countryCoords[country]) {
                    if (!countryIOCs[country]) {
                        countryIOCs[country] = {
                            count: 0,
                            c2: 0,
                            malware: 0,
                            botnet: 0,
                            families: new Set()
                        };
                    }
                    countryIOCs[country].count++;
                    if (ioc.threat_type === 'c2') countryIOCs[country].c2++;
                    if (ioc.threat_type === 'malware') countryIOCs[country].malware++;
                    if (ioc.threat_type === 'botnet') countryIOCs[country].botnet++;
                    if (ioc.malware_family) countryIOCs[country].families.add(ioc.malware_family);
                }
            });

            // Add IOC markers by country
            Object.entries(countryIOCs).forEach(([code, data]) => {
                const coords = countryCoords[code];
                if (coords) {
                    const score = Math.min(100, data.count * 5 + data.c2 * 10);
                    const color = score >= 80 ? threatColors.critical :
                                  score >= 50 ? threatColors.high :
                                  score >= 20 ? threatColors.medium : threatColors.low;

                    const families = Array.from(data.families).slice(0, 5).join(', ') || 'Unknown';

                    L.circleMarker(coords, {
                        radius: Math.min(25, 10 + data.count / 2),
                        color: color,
                        fillColor: color,
                        fillOpacity: 0.6,
                        weight: 2
                    }).addTo(layers.cyber).bindPopup(`
                        <div class="popup-title">Cyber Threats: ${code}</div>
                        <div class="popup-row"><strong>Total IOCs:</strong> ${data.count}</div>
                        <div class="popup-row"><strong>C2 Servers:</strong> ${data.c2}</div>
                        <div class="popup-row"><strong>Botnet:</strong> ${data.botnet}</div>
                        <div class="popup-row"><strong>Malware:</strong> ${families}</div>
                    `);
                }
            });

            // Also add markers for exposed services (if Shodan data available)
            const exposedServices = cyberData.exposed_services || [];
            exposedServices.forEach(exposure => {
                const code = exposure.country_code;
                const coords = countryCoords[code];

                // Skip if already have IOC marker for this country
                if (coords && !countryIOCs[code]) {
                    const score = exposure.threat_score || exposure.risk_score || 50;
                    const color = score >= 80 ? threatColors.critical :
                                  score >= 60 ? threatColors.high :
                                  score >= 40 ? threatColors.medium : threatColors.low;

                    L.circleMarker(coords, {
                        radius: Math.min(20, 8 + score / 10),
                        color: color,
                        fillColor: color,
                        fillOpacity: 0.6,
                        weight: 2
                    }).addTo(layers.cyber).bindPopup(`
                        <div class="popup-title">Cyber Exposure: ${code}</div>
                        <div class="popup-row"><strong>Threat Score:</strong> ${score}</div>
                        <div class="popup-row"><strong>Exposed Services:</strong> ${exposure.total_exposed || 0}</div>
                        <div class="popup-row"><strong>ICS/SCADA:</strong> ${exposure.ics_count || 0}</div>
                    `);
                }
            });

            // Update cyber threat count in stats
            const totalCyberThreats = Object.values(countryIOCs).reduce((sum, d) => sum + d.count, 0);
            if (totalCyberThreats > 0) {
                // Could update a stat counter here if we add one
                console.log(`Loaded ${totalCyberThreats} cyber IOCs from ${Object.keys(countryIOCs).length} countries`);
            }
        }

        async function loadAISData() {
            try {
                const resp = await fetch('/api/ais');
                const data = await resp.json();

                if (data.vessels && data.vessels.length > 0) {
                    layers.vessels.clearLayers();

                    data.vessels.forEach(vessel => {
                        if (vessel.lat && vessel.lon) {
                            const isDark = vessel.is_dark;
                            const color = isDark ? threatColors.critical : threatColors.low;

                            L.circleMarker([vessel.lat, vessel.lon], {
                                radius: 6,
                                color: color,
                                fillColor: color,
                                fillOpacity: 0.8
                            }).addTo(layers.vessels).bindPopup(`
                                <div class="popup-title">${vessel.name || vessel.mmsi}</div>
                                <div class="popup-row"><strong>MMSI:</strong> ${vessel.mmsi}</div>
                                <div class="popup-row"><strong>Flag:</strong> ${vessel.flag || 'Unknown'}</div>
                                <div class="popup-row"><strong>Type:</strong> ${vessel.vessel_type || 'Unknown'}</div>
                                <div class="popup-row"><strong>Dark Ship:</strong> ${isDark ? 'Yes' : 'No'}</div>
                                <a href="http://localhost:8080" target="_blank" class="ais-link">View in AIS Tracker</a>
                            `);
                        }
                    });

                    // Enable AIS layer checkbox
                    document.getElementById('layer-vessels').checked = true;
                    layers.vessels.addTo(map);
                }
            } catch (error) {
                console.log('AIS Tracker not available');
            }
        }

        function updateStats() {
            document.getElementById('critical-count').textContent = stats.critical;
            document.getElementById('high-count').textContent = stats.high;
            document.getElementById('aircraft-count').textContent = stats.aircraft;
            document.getElementById('gps-zones').textContent = stats.gpsZones;
        }

        // Layer toggle handlers
        document.getElementById('layer-gps').addEventListener('change', function() {
            this.checked ? map.addLayer(layers.gps) : map.removeLayer(layers.gps);
        });

        document.getElementById('layer-aviation').addEventListener('change', function() {
            this.checked ? map.addLayer(layers.aviation) : map.removeLayer(layers.aviation);
        });

        document.getElementById('layer-chokepoints').addEventListener('change', function() {
            this.checked ? map.addLayer(layers.chokepoints) : map.removeLayer(layers.chokepoints);
        });

        document.getElementById('layer-vessels').addEventListener('change', function() {
            this.checked ? map.addLayer(layers.vessels) : map.removeLayer(layers.vessels);
        });

        document.getElementById('layer-cyber').addEventListener('change', function() {
            this.checked ? map.addLayer(layers.cyber) : map.removeLayer(layers.cyber);
        });

        // Initial load
        loadData();

        // Refresh every 60 seconds
        setInterval(loadData, 60000);
    </script>
</body>
</html>
"""


@app.route("/")
def dashboard():
    """Serve the main dashboard"""
    return render_template_string(DASHBOARD_HTML)


@app.route("/api/feed")
def get_feed():
    """Get the latest threat feed"""
    feed_path = OUTPUT_DIR / "feed.json"

    if feed_path.exists():
        with open(feed_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            # Debug: log what cyber data we have
            cyber = data.get("cyber", {})
            iocs = cyber.get("iocs", [])
            logger.info(f"Feed has {len(iocs)} IOCs")
            if iocs:
                # Log sample IOC for debugging
                sample = iocs[0]
                logger.info(f"Sample IOC: country={sample.get('country')}, type={sample.get('type')}")
            return jsonify(data)

    # Return sample data if no feed exists
    return jsonify({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "aviation": {"aircraft": []},
        "gps": {"interference_zones": []},
        "cyber": {
            "exposed_services": [],
            "iocs": [
                # Sample IOCs for testing UI
                {"value": "192.0.2.1", "type": "ip", "threat_type": "botnet", "country": "RU", "confidence": 90, "malware_family": "Emotet"},
                {"value": "192.0.2.2", "type": "ip", "threat_type": "c2", "country": "CN", "confidence": 85, "malware_family": "Cobalt Strike"},
                {"value": "192.0.2.3", "type": "ip", "threat_type": "botnet", "country": "US", "confidence": 80, "malware_family": "TrickBot"},
                {"value": "192.0.2.4", "type": "ip", "threat_type": "malware", "country": "IR", "confidence": 75, "malware_family": "APT33"},
                {"value": "192.0.2.5", "type": "ip", "threat_type": "c2", "country": "KP", "confidence": 95, "malware_family": "Lazarus"},
            ]
        },
        "maritime": {"vessels": []}
    })


@app.route("/api/chokepoints")
def get_chokepoints():
    """Get chokepoint definitions"""
    chokepoints_path = CONFIG_DIR / "chokepoints.geojson"

    if chokepoints_path.exists():
        with open(chokepoints_path, "r", encoding="utf-8") as f:
            return jsonify(json.load(f))

    return jsonify({"type": "FeatureCollection", "features": []})


@app.route("/api/heatmap")
def get_heatmap():
    """Get cyber threat heatmap"""
    heatmap_path = OUTPUT_DIR / "cyber_heatmap.json"

    if heatmap_path.exists():
        with open(heatmap_path, "r", encoding="utf-8") as f:
            return jsonify(json.load(f))

    return jsonify({})


@app.route("/api/ais")
def get_ais_data():
    """Proxy to AIS Tracker API"""
    import requests

    try:
        # Try to fetch from AIS Tracker
        resp = requests.get(f"{AIS_TRACKER_URL}/api/vessels", timeout=5)
        if resp.status_code == 200:
            return jsonify(resp.json())
    except Exception as e:
        logger.debug(f"AIS Tracker not available: {e}")

    # Return data from feed if AIS Tracker unavailable
    feed_path = OUTPUT_DIR / "feed.json"
    if feed_path.exists():
        with open(feed_path, "r", encoding="utf-8") as f:
            feed = json.load(f)
            return jsonify(feed.get("maritime", {"vessels": []}))

    return jsonify({"vessels": []})


@app.route("/api/brief")
def get_brief():
    """Get daily brief"""
    brief_path = OUTPUT_DIR / "daily_brief.md"

    if brief_path.exists():
        with open(brief_path, "r", encoding="utf-8") as f:
            return jsonify({"content": f.read()})

    return jsonify({"content": "No brief available. Run main.py first."})


def main():
    """Run the web server"""
    import argparse

    parser = argparse.ArgumentParser(description="Geopolitical Threat Mapper Web Dashboard")
    parser.add_argument("--port", type=int, default=8081, help="Port to run on (default: 8081)")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind to (default: 0.0.0.0)")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")

    args = parser.parse_args()

    logger.info(f"Starting Geopolitical Threat Mapper UI on http://localhost:{args.port}")
    logger.info(f"AIS Tracker integration: {AIS_TRACKER_URL}")

    app.run(host=args.host, port=args.port, debug=args.debug)


if __name__ == "__main__":
    main()
