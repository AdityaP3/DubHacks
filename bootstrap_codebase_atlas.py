#!/usr/bin/env python3
"""
bootstrap_codebase_atlas.py

Creates a full Codebase Atlas project (FastAPI + React + Cytoscape + Docker)
in a folder named ./codebase-atlas

Usage:
  python bootstrap_codebase_atlas.py
  cd codebase-atlas
  docker compose up --build
"""

from pathlib import Path
import textwrap

ROOT = Path("codebase-atlas")

FILES = {
    "backend/requirements.txt": """
        fastapi==0.115.2
        uvicorn==0.30.6
        httpx==0.27.2
        pydantic==2.9.2
        networkx==3.3
        python-multipart==0.0.12
        packaging==24.1
        """,
    "backend/Dockerfile": """
        FROM python:3.11-slim
        WORKDIR /app
        COPY requirements.txt ./
        RUN pip install --no-cache-dir -r requirements.txt
        COPY app ./app
        CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
        """,
    "backend/app/__init__.py": """
        """,
    "backend/app/models.py": """
        from pydantic import BaseModel
        from typing import List, Dict, Optional

        class AnalyzeRequest(BaseModel):
            github_url: str

        class NodeRisk(BaseModel):
            name: str
            version: Optional[str] = None
            security_risk: float
            maintainer_risk: float
            centrality_risk: float
            freshness_risk: float
            total_risk: float
            advisories: List[Dict] = []

        class Edge(BaseModel):
            source: str
            target: str

        class AnalyzeResponse(BaseModel):
            nodes: List[Dict]
            edges: List[Edge]
            risks: List[NodeRisk]
            top_fixes: List[Dict]
        """,
    "backend/app/github_ingest.py": """
        import re
        from typing import Tuple

        import httpx

        RAW_BASE = "https://raw.githubusercontent.com"

        def parse_github_url(url: str) -> Tuple[str, str]:
            cleaned = (url or "").strip().rstrip("/")
            if not cleaned:
                raise ValueError("GitHub URL is required")

            if "/blob/" in cleaned or "/tree/" in cleaned:
                cleaned = cleaned.split("/blob/", 1)[0].split("/tree/", 1)[0]

            if "/issues" in cleaned:
                cleaned = cleaned.split("/issues", 1)[0]

            match = re.match(
                r"https?://github\.com/(?P<owner>[^/]+)/(?P<repo>[^/]+?)(?:\.git)?$",
                cleaned,
            )
            if not match:
                raise ValueError(f"Invalid GitHub URL: {url}")

            return match.group("owner"), match.group("repo")

        async def fetch_requirements_from_github(github_url: str) -> str:
            owner, repo = parse_github_url(github_url)
            candidates = ["main", "master", "develop", "trunk"]
            files = [
                "requirements.txt",
                "backend/requirements.txt",
                "server/requirements.txt",
                "requirements-dev.txt",
            ]

            async with httpx.AsyncClient(timeout=20) as client:
                for branch in candidates:
                    for path in files:
                        raw_url = f"{RAW_BASE}/{owner}/{repo}/{branch}/{path}"
                        try:
                            r = await client.get(raw_url)
                        except httpx.HTTPError:
                            continue
                        if r.status_code == 200 and r.text.strip():
                            return r.text

            raise FileNotFoundError(
                "Could not find a Python requirements file in the repo. "
                "Expected one of: requirements.txt, backend/requirements.txt, server/requirements.txt"
            )
        """,
    "backend/app/deps_parser.py": """
        import re
        from typing import List, Optional, Tuple

        def parse_requirements(requirements_text: str) -> List[Tuple[str, Optional[str]]]:
            deps: List[Tuple[str, Optional[str]]] = []
            for line in requirements_text.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                match = re.match(r"([A-Za-z0-9_.\\-]+)\\s*([=<>!~]+)\\s*([A-Za-z0-9_.\\-]+)?", line)
                if match:
                    name = match.group(1).lower()
                    version = match.group(3) if match.group(3) else None
                    deps.append((name, version))
                else:
                    deps.append((line.lower(), None))
            return deps
        """,
    "backend/app/osv_client.py": """
        from typing import Dict, List, Optional

        import httpx

        OSV_QUERY = "https://api.osv.dev/v1/query"

        async def query_osv(package: str, version: Optional[str]) -> List[Dict]:
            payload = {"package": {"name": package, "ecosystem": "PyPI"}}
            if version:
                payload["version"] = version

            async with httpx.AsyncClient(timeout=20) as client:
                r = await client.post(OSV_QUERY, json=payload)
                if r.status_code != 200:
                    return []
                data = r.json()
                vulns = data.get("vulns", [])
                out = []
                for vuln in vulns:
                    out.append({
                        "id": vuln.get("id"),
                        "summary": vuln.get("summary", ""),
                        "severity": extract_severity(vuln),
                    })
                return out

        def extract_severity(vuln: Dict) -> float:
            sev = vuln.get("severity", [])
            if sev and isinstance(sev, list):
                for s in sev:
                    score = s.get("score", "")
                    if "CVSS" in score:
                        return 7.0
            return 6.0
        """,
    "backend/app/pypi_client.py": """
        from datetime import datetime, timezone
        from typing import Optional

        import httpx

        def days_since(date_str: Optional[str]) -> int:
            if not date_str:
                return 9999
            try:
                dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
                return (datetime.now(timezone.utc) - dt).days
            except Exception:
                return 9999

        async def fetch_pypi_freshness(package: str) -> int:
            url = f"https://pypi.org/pypi/{package}/json"
            async with httpx.AsyncClient(timeout=20) as client:
                r = await client.get(url)
                if r.status_code != 200:
                    return 9999
                data = r.json()
                releases = data.get("releases", {})
                latest_upload = None
                for _, files in releases.items():
                    for file_entry in files:
                        t = file_entry.get("upload_time_iso_8601")
                        if t and (latest_upload is None or t > latest_upload):
                            latest_upload = t
                return days_since(latest_upload)
        """,
    "backend/app/graph_builder.py": """
        from typing import Dict, List, Optional, Tuple

        import networkx as nx

        def build_graph(deps: List[Tuple[str, Optional[str]]]) -> nx.DiGraph:
            g = nx.DiGraph()
            root = "repo_root"
            g.add_node(root)

            for name, version in deps:
                node = f"{name}=={version}" if version else name
                g.add_node(node, package=name, version=version)
                g.add_edge(root, node)

            return g

        def graph_to_payload(g: nx.DiGraph):
            nodes = [{"id": n, **g.nodes[n]} for n in g.nodes()]
            edges = [{"source": u, "target": v} for u, v in g.edges()]
            return nodes, edges

        def centrality_scores(g: nx.DiGraph) -> Dict[str, float]:
            c = nx.in_degree_centrality(g)
            return {k: float(v) for k, v in c.items()}
        """,
    "backend/app/risk.py": """
        from typing import Dict, List

        def normalize_freshness(days: int) -> float:
            if days <= 30:
                return 0.1
            if days <= 180:
                return 0.3
            if days <= 365:
                return 0.6
            return 0.9

        def security_risk_from_advisories(advisories: List[Dict]) -> float:
            if not advisories:
                return 0.0
            avg = sum(min(float(a.get("severity", 6.0)), 10.0) for a in advisories) / len(advisories)
            return avg / 10.0

        def total_risk(security: float, freshness: float, centrality: float) -> float:
            return round(100 * (0.5 * security + 0.3 * freshness + 0.2 * centrality), 2)

        def top_fixes(risks: List[Dict], k: int = 5) -> List[Dict]:
            ranked = sorted(risks, key=lambda x: x["total_risk"], reverse=True)
            fixes = []
            for r in ranked[:k]:
                fixes.append({
                    "package": r["name"],
                    "action": "Upgrade to the latest compatible version and rerun tests",
                    "estimated_risk_reduction": round(r["total_risk"] * 0.35, 2),
                })
            return fixes
        """,
    "backend/app/main.py": """
        from fastapi import FastAPI, HTTPException
        from fastapi.middleware.cors import CORSMiddleware

        from .deps_parser import parse_requirements
        from .github_ingest import fetch_requirements_from_github
        from .graph_builder import build_graph, centrality_scores, graph_to_payload
        from .models import AnalyzeRequest
        from .osv_client import query_osv
        from .pypi_client import fetch_pypi_freshness
        from .risk import (
            normalize_freshness,
            security_risk_from_advisories,
            top_fixes,
            total_risk,
        )

        app = FastAPI(title="Codebase Atlas API", version="0.1.0")

        app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

        @app.get("/health")
        async def health():
            return {"ok": True}

        @app.post("/analyze")
        async def analyze(req: AnalyzeRequest):
            try:
                req_text = await fetch_requirements_from_github(req.github_url)
            except Exception as exc:
                raise HTTPException(status_code=400, detail=f"Dependency ingest failed: {exc}") from exc

            deps = parse_requirements(req_text)
            if not deps:
                raise HTTPException(status_code=400, detail="No dependencies parsed from requirements file.")

            g = build_graph(deps)
            nodes, edges = graph_to_payload(g)
            centrality = centrality_scores(g)

            risks = []
            for node in nodes:
                if node["id"] == "repo_root":
                    continue

                package = node.get("package", node["id"])
                version = node.get("version")

                advisories = await query_osv(package, version)
                sec = security_risk_from_advisories(advisories)

                days_old = await fetch_pypi_freshness(package)
                fresh = normalize_freshness(days_old)

                cen = min(1.0, centrality.get(node["id"], 0.0) * 5.0)
                tr = total_risk(sec, fresh, cen)

                risks.append({
                    "name": package,
                    "version": version,
                    "security_risk": round(sec, 3),
                    "maintainer_risk": round(fresh, 3),
                    "centrality_risk": round(cen, 3),
                    "freshness_risk": round(fresh, 3),
                    "total_risk": tr,
                    "advisories": advisories,
                })

            fixes = top_fixes(risks, k=5)

            return {
                "nodes": nodes,
                "edges": edges,
                "risks": sorted(risks, key=lambda x: x["total_risk"], reverse=True),
                "top_fixes": fixes,
            }
        """,
    "frontend/package.json": """
        {
          "name": "codebase-atlas-ui",
          "version": "0.1.0",
          "private": true,
          "type": "module",
          "scripts": {
            "dev": "vite --host 0.0.0.0 --port 5173",
            "build": "vite build",
            "preview": "vite preview --host 0.0.0.0 --port 5173"
          },
          "dependencies": {
            "axios": "^1.7.7",
            "cytoscape": "^3.30.2",
            "react": "^18.3.1",
            "react-dom": "^18.3.1"
          },
          "devDependencies": {
            "@vitejs/plugin-react": "^4.3.2",
            "vite": "^5.4.8"
          }
        }
        """,
    "frontend/vite.config.js": """
        import { defineConfig } from "vite";
        import react from "@vitejs/plugin-react";

        export default defineConfig({
          plugins: [react()],
        });
        """,
    "frontend/index.html": """
        <!doctype html>
        <html lang="en">
          <head>
            <meta charset="UTF-8" />
            <meta name="viewport" content="width=device-width, initial-scale=1.0" />
            <title>Codebase Atlas</title>
          </head>
          <body>
            <div id="root"></div>
            <script type="module" src="/src/main.jsx"></script>
          </body>
        </html>
        """,
    "frontend/src/main.jsx": """
        import React from "react";
        import ReactDOM from "react-dom/client";
        import App from "./App";
        import "./styles.css";

        ReactDOM.createRoot(document.getElementById("root")).render(
          <React.StrictMode>
            <App />
          </React.StrictMode>
        );
        """,
    "frontend/src/api.js": """
        import axios from "axios";

        const API_BASE = import.meta.env.VITE_API_BASE || "http://localhost:8000";

        export async function analyzeRepo(githubUrl) {
          const { data } = await axios.post(`${API_BASE}/analyze`, { github_url: githubUrl });
          return data;
        }
        """,
    "frontend/src/components/GraphView.jsx": """
        import React, { useEffect, useRef } from "react";
        import cytoscape from "cytoscape";

        export default function GraphView({ nodes, edges, risks }) {
          const ref = useRef(null);

          useEffect(() => {
            if (!ref.current || !nodes?.length) return;

            const riskMap = new Map((risks || []).map((r) => [r.name, r.total_risk]));
            const elements = [
              ...nodes.map((n) => {
                const r = riskMap.get(n.package) || 0;
                return { data: { id: n.id, label: n.package || n.id, risk: r } };
              }),
              ...edges.map((e) => ({ data: { source: e.source, target: e.target } })),
            ];

            const cy = cytoscape({
              container: ref.current,
              elements,
              style: [
                {
                  selector: "node",
                  style: {
                    "background-color": (ele) => {
                      const risk = ele.data("risk") || 0;
                      if (risk > 70) return "#ff4d4f";
                      if (risk > 40) return "#faad14";
                      return "#52c41a";
                    },
                    label: "data(label)",
                    color: "#e6edf3",
                    "font-size": 10,
                    "text-wrap": "wrap",
                    "text-max-width": "100px",
                    width: (ele) => 20 + ((ele.data("risk") || 0) / 5),
                    height: (ele) => 20 + ((ele.data("risk") || 0) / 5),
                  },
                },
                {
                  selector: "edge",
                  style: {
                    "line-color": "#334155",
                    "target-arrow-color": "#334155",
                    "target-arrow-shape": "triangle",
                    "curve-style": "bezier",
                    width: 1,
                  },
                },
              ],
              layout: { name: "cose", animate: false, padding: 30 },
            });

            return () => cy.destroy();
          }, [nodes, edges, risks]);

          return <div style={{ height: "520px", border: "1px solid #1f2937", borderRadius: 12 }} ref={ref} />;
        }
        """,
    "frontend/src/components/RiskTable.jsx": """
        import React from "react";

        export default function RiskTable({ risks }) {
          return (
            <div className="card">
              <h3>Top Risks</h3>
              <table>
                <thead>
                  <tr>
                    <th>Package</th>
                    <th>Version</th>
                    <th>Total</th>
                    <th>Security</th>
                    <th>Freshness</th>
                  </tr>
                </thead>
                <tbody>
                  {(risks || []).slice(0, 10).map((r) => (
                    <tr key={`${r.name}-${r.version || "na"}`}>
                      <td>{r.name}</td>
                      <td>{r.version || "-"}</td>
                      <td>{r.total_risk}</td>
                      <td>{r.security_risk}</td>
                      <td>{r.freshness_risk}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          );
        }
        """,
    "frontend/src/components/TopFixes.jsx": """
        import React from "react";

        export default function TopFixes({ fixes }) {
          return (
            <div className="card">
              <h3>Top Fixes by Estimated Risk Reduction</h3>
              <ul>
                {(fixes || []).map((f, i) => (
                  <li key={i}>
                    <b>{f.package}</b>: {f.action} (↓ {f.estimated_risk_reduction})
                  </li>
                ))}
              </ul>
            </div>
          );
        }
        """,
    "frontend/src/App.jsx": """
        import React, { useState } from "react";
        import { analyzeRepo } from "./api";
        import GraphView from "./components/GraphView";
        import RiskTable from "./components/RiskTable";
        import TopFixes from "./components/TopFixes";
        import "./styles.css";

        export default function App() {
          const [url, setUrl] = useState("https://github.com/AdityaP3/DubHacks.git");
          const [data, setData] = useState(null);
          const [loading, setLoading] = useState(false);
          const [err, setErr] = useState("");

          const run = async () => {
            setLoading(true);
            setErr("");
            try {
              const d = await analyzeRepo(url);
              setData(d);
            } catch (e) {
              setErr(e?.response?.data?.detail || e.message);
            } finally {
              setLoading(false);
            }
          };

          return (
            <div className="page">
              <h1>Codebase Atlas</h1>
              <p className="sub">Dependency blast-radius and risk intelligence</p>

              <div className="controls">
                <input
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter") run();
                  }}
                />
                <button onClick={run} disabled={loading}>
                  {loading ? "Analyzing..." : "Analyze Repo"}
                </button>
              </div>

              {err && <div className="error">{err}</div>}

              {data && (
                <>
                  <GraphView nodes={data.nodes} edges={data.edges} risks={data.risks} />
                  <div className="grid">
                    <RiskTable risks={data.risks} />
                    <TopFixes fixes={data.top_fixes} />
                  </div>
                </>
              )}
            </div>
          );
        }
        """,
    "frontend/src/styles.css": """
        :root {
          font-family: Inter, system-ui, Arial, sans-serif;
          color: #e6edf3;
          background: #0b1220;
        }

        body,
        html,
        #root {
          margin: 0;
          padding: 0;
          background: #0b1220;
        }

        .page {
          max-width: 1200px;
          margin: 24px auto;
          padding: 0 16px;
        }

        h1 {
          margin: 0;
          font-size: 32px;
        }

        .sub {
          color: #94a3b8;
          margin-top: 6px;
        }

        .controls {
          display: flex;
          gap: 8px;
          margin: 16px 0;
        }

        input {
          flex: 1;
          background: #111827;
          color: #e5e7eb;
          border: 1px solid #374151;
          border-radius: 10px;
          padding: 10px;
        }

        button {
          background: #2563eb;
          color: white;
          border: none;
          border-radius: 10px;
          padding: 10px 14px;
          cursor: pointer;
        }

        .grid {
          display: grid;
          grid-template-columns: 2fr 1fr;
          gap: 12px;
          margin-top: 12px;
        }

        .card {
          background: #111827;
          border: 1px solid #1f2937;
          border-radius: 12px;
          padding: 12px;
        }

        table {
          width: 100%;
          border-collapse: collapse;
          font-size: 14px;
        }

        th,
        td {
          border-bottom: 1px solid #1f2937;
          text-align: left;
          padding: 8px;
        }

        .error {
          color: #fecaca;
          background: #7f1d1d;
          padding: 8px;
          border-radius: 8px;
          margin-bottom: 10px;
        }
        """,
    "frontend/Dockerfile": """
        FROM node:20-alpine
        WORKDIR /app
        COPY package.json package-lock.json* ./
        RUN npm install
        COPY . .
        CMD ["npm", "run", "dev"]
        """,
    "docker-compose.yml": """
        version: "3.9"

        services:
          backend:
            build: ./backend
            ports:
              - "8000:8000"

          frontend:
            build: ./frontend
            environment:
              - VITE_API_BASE=http://backend:8000
            ports:
              - "5173:5173"
            depends_on:
              - backend
        """,
    "README.md": """
        # Codebase Atlas

        Dependency blast-radius and risk intelligence for Python repositories.

        ## Run with Docker

        ```bash
        docker compose up --build
        ```

        Then open:

        - http://localhost:5173

        ## Notes

        - The frontend talks to the backend service using the Docker network name `backend`.
        - The backend tries to fetch a requirements file from the GitHub repo URL you enter.
        - It is intentionally conservative and supports common Python dependency layouts.
        """,
}


def write_project(root: Path):
    if root.exists():
        raise FileExistsError(f"Project directory already exists: {root.resolve()}")

    for relative_path, content in FILES.items():
        target = root / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(textwrap.dedent(content).lstrip(), encoding="utf-8")

    print(f"Created Codebase Atlas scaffold in {root.resolve()}")
    print("Next steps:")
    print(f"  cd {root}")
    print("  docker compose up --build")


if __name__ == "__main__":
    write_project(ROOT)
