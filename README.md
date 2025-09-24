# Network AI Platform

AI-powered network analysis and automation platform for Cisco networks.

## Features

- 🔍 **Intelligent Config Parsing**: Parse Cisco IOS/IOS-XE/NX-OS configurations using TextFSM
- 🤖 **AI-Powered Analysis**: Natural language queries about network infrastructure
- 🗺️ **Network Topology**: Automatic topology discovery and visualization
- ⚙️ **Config Generation**: AI-generated configuration changes and recommendations
- 📊 **Network Insights**: Best practices analysis and optimization recommendations

## Quick Start

1. **Clone and setup**:
   ```bash
   git clone <your-repo>
   cd network-ai-platform
   python -m venv venv
   source venv/bin/activate  # or `venv\Scripts\activate` on Windows
   pip install -r requirements.txt
   ```

2. **Configure environment**:
   ```bash
   cp .env.example .env
   # Edit .env with your settings (especially OPENAI_API_KEY)
   ```

3. **Initialize database**:
   ```bash
   python database/database.py init
   ```

4. **Run the application**:
   ```bash
   uvicorn main:app --reload
   ```

5. **Access the API**:
   - Interactive docs: http://localhost:8000/docs
   - Alternative docs: http://localhost:8000/redoc

## Usage

### Upload Configuration
```bash
curl -X POST "http://localhost:8000/api/v1/upload-config" \
  -H "Content-Type: multipart/form-data" \
  -F "file=@your-config.txt"
```

### Query Network
```bash
curl -X POST "http://localhost:8000/api/v1/query" \
  -H "Content-Type: application/json" \
  -d '{"query": "Show me all devices in VLAN 100"}'
```

## Development

Run tests:
```bash
pytest
```

Run with Docker:
```bash
docker-compose up --build
```

## License

MIT License
