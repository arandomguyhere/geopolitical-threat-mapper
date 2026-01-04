#!/usr/bin/env python3
"""
Taiwan Critical Infrastructure Scanner - ZoomEye Only
Standalone script with minimal dependencies
"""

import asyncio
import aiohttp
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

# Taiwan critical infrastructure queries
TAIWAN_QUERIES = [
    # ICS/SCADA
    ("ics_scada", "country:TW port:502 modbus"),
    ("ics_scada", "country:TW port:102 s7"),
    ("ics_scada", "country:TW scada"),
    # Critical Infrastructure
    ("critical_infra", "country:TW port:47808 bacnet"),
    ("critical_infra", "country:TW port:20000 dnp3"),
    # Databases
    ("databases", "country:TW port:27017 mongodb"),
    ("databases", "country:TW port:9200 elasticsearch"),
    ("databases", "country:TW port:6379 redis"),
    # Remote Access
    ("remote_access", "country:TW port:3389 rdp"),
    ("remote_access", "country:TW port:5900 vnc"),
    # Webcams
    ("webcams", "country:TW hikvision"),
    ("webcams", "country:TW dahua"),
]

async def query_zoomeye(session, api_key, query, limit=20):
    """Query ZoomEye API"""
    url = "https://api.zoomeye.org/host/search"
    headers = {"API-KEY": api_key}
    params = {"query": query, "page": 1}

    try:
        async with session.get(url, headers=headers, params=params) as resp:
            if resp.status == 401:
                print(f"  ERROR: Invalid API key")
                return []
            if resp.status == 402:
                print(f"  WARNING: Quota exceeded (free tier: 20/month)")
                return []
            if resp.status != 200:
                print(f"  ERROR: Status {resp.status}")
                return []

            data = await resp.json()
            matches = data.get("matches", [])[:limit]
            results = []

            for m in matches:
                portinfo = m.get("portinfo", {})
                geoinfo = m.get("geoinfo", {})

                results.append({
                    "ip": m.get("ip", ""),
                    "port": portinfo.get("port", 0),
                    "protocol": portinfo.get("protocol", "tcp"),
                    "service": portinfo.get("service", "unknown"),
                    "product": portinfo.get("product", ""),
                    "version": portinfo.get("version", ""),
                    "country": "Taiwan",
                    "country_code": "TW",
                    "city": geoinfo.get("city", {}).get("names", {}).get("en", ""),
                    "org": geoinfo.get("organization", ""),
                    "asn": geoinfo.get("asn", ""),
                    "lat": geoinfo.get("location", {}).get("lat", 23.5),
                    "lon": geoinfo.get("location", {}).get("lon", 121.0),
                    "source": "zoomeye",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                })

            return results
    except Exception as e:
        print(f"  ERROR: {e}")
        return []

async def main():
    api_key = os.getenv("ZOOMEYE_API_KEY")

    if not api_key:
        print("ERROR: ZOOMEYE_API_KEY not set in .env file")
        print("Get a free key at: https://www.zoomeye.org/login")
        return

    print("=" * 60)
    print("TAIWAN CRITICAL INFRASTRUCTURE SCANNER")
    print(f"Using ZoomEye API (Free tier: 20 queries/month)")
    print("=" * 60)

    all_results = []
    stats = {
        "ics_scada": 0,
        "critical_infra": 0,
        "databases": 0,
        "remote_access": 0,
        "webcams": 0,
    }

    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30)) as session:
        for category, query in TAIWAN_QUERIES:
            print(f"\n[{category}] {query}")
            results = await query_zoomeye(session, api_key, query, limit=20)

            for r in results:
                r["category"] = category
                all_results.append(r)
                stats[category] += 1

            print(f"  Found: {len(results)} results")

            # Rate limit - be nice to the API
            await asyncio.sleep(1)

    # Deduplicate by IP
    seen_ips = set()
    unique_results = []
    for r in all_results:
        if r["ip"] not in seen_ips:
            seen_ips.add(r["ip"])
            unique_results.append(r)

    print("\n" + "=" * 60)
    print("RESULTS SUMMARY")
    print("=" * 60)
    print(f"Total unique IPs: {len(unique_results)}")
    for cat, count in stats.items():
        print(f"  {cat}: {count}")

    # Generate output for UI
    output_dir = Path(__file__).parent / "output"
    output_dir.mkdir(exist_ok=True)

    # Create feed.json for the UI
    feed = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": "zoomeye",
        "aviation": {"aircraft": []},
        "gps": {"interference_zones": []},
        "maritime": {"vessels": []},
        "cyber": {
            "exposed_services": unique_results,
            "iocs": [
                {
                    "value": r["ip"],
                    "type": "ip",
                    "threat_type": r["category"],
                    "country": "TW",
                    "confidence": 85,
                    "malware_family": r["service"],
                }
                for r in unique_results
            ],
            "country_exposure": {
                "TW": {
                    "country_code": "TW",
                    "country_name": "Taiwan",
                    "total_exposed": len(unique_results),
                    "exposed_ics_scada": stats["ics_scada"],
                    "ics_count": stats["ics_scada"],
                    "exposed_databases": stats["databases"],
                    "exposed_webcams": stats["webcams"],
                    "exposed_rdp": stats["remote_access"],
                    "risk_score": min(100, len(unique_results) * 2 + stats["ics_scada"] * 10),
                    "threat_score": min(100, len(unique_results) * 2 + stats["ics_scada"] * 10),
                    "source": "zoomeye",
                }
            }
        }
    }

    feed_path = output_dir / "feed.json"
    with open(feed_path, "w", encoding="utf-8") as f:
        json.dump(feed, f, indent=2, ensure_ascii=False)

    print(f"\nOutput saved to: {feed_path}")
    print("\nStart the UI with: python server.py")
    print("Then open: http://localhost:8081")

if __name__ == "__main__":
    asyncio.run(main())
