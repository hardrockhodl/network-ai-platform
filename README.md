# Network AI Platform

An intelligent network analysis platform that processes natural language queries about network configurations and provides automated configuration recommendations.

## What This Does

This platform analyzes your network infrastructure and answers questions like:
- "Show me all VLANs"
- "Which devices have VLAN 50?"
- "Create VLAN 100 for guest users"
- "I need VLAN 30 to communicate with subnet 192.168.30.0/24"
- "Troubleshoot connectivity to 10.1.1.1"

The system generates actual Cisco configuration commands and provides detailed network analysis.

## Quick Start

### Using Docker (Recommended)

1. **Clone and build:**
   ```bash
   git clone <your-repo>
   cd network-ai-platform
   docker build -t network-ai .
   docker run -p 8000:8000 network-ai
   ```

2. **Access the application:**
   - Open http://localhost:8000 in your browser
   - The API will be available at http://localhost:8000/docs

### Local Development

1. **Install Python 3.11+:**
   ```bash
   python --version  # Should be 3.11 or higher
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application:**
   ```bash
   uvicorn main:app --host 0.0.0.0 --port 8000 --reload
   ```

## Core Features

### 🤖 Intelligent Query Processing
- **Rule-based analysis** - Works offline without external APIs
- **Natural language understanding** - Ask questions in plain English
- **Configuration generation** - Produces ready-to-use Cisco commands

### 🔧 Network Analysis
- **VLAN management** - Create, analyze, and troubleshoot VLANs
- **Connectivity analysis** - Understand routing requirements
- **Device inventory** - Track switches, routers, and interfaces
- **Troubleshooting** - Diagnostic steps for connectivity issues

### 📊 Data Processing
- **Device configuration parsing** - Extracts meaningful data from configs
- **Network topology mapping** - Understands device relationships
- **Subnet analysis** - Tracks IP addressing and routing

## Enhanced AI Features (Optional)

For more sophisticated analysis, you can integrate with local AI models:

### Option 1: Ollama + Qwen3 (Recommended)
```bash
# Install Ollama
curl -fsSL https://ollama.ai/install.sh | sh

# Download the Qwen3 model (32B version for best results)
ollama pull qwen3:32b

# The application will automatically detect and use it
```

### Option 2: OpenAI API
Add your API key to environment variables:
```bash
export OPENAI_API_KEY="your-key-here"
```

## Project Structure

```
network-ai-platform/
├── main.py                 # FastAPI application entry point
├── ai_engine/
│   ├── local_ai_processor.py    # Core query processing logic
│   ├── hybrid_processor.py     # AI integration layer  
│   └── config_templates/        # Cisco command templates
├── parsers/                     # Network config parsers
├── requirements.txt             # Python dependencies
├── Dockerfile                   # Container configuration
└── README.md                   # This file
```

## API Usage

### Basic Query
```bash
curl -X POST "http://localhost:8000/query" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "Show me all VLANs",
    "devices": [...]
  }'
```

### Response Format
```json
{
  "response": "Network has 15 VLANs configured...",
  "config_changes": [
    {
      "device_hostname": "CORE-SW-01",
      "commands": ["vlan 100", "name GUESTS"],
      "description": "Create VLAN 100",
      "risk_level": "low"
    }
  ],
  "affected_devices": ["CORE-SW-01", "ACCESS-SW-02"],
  "confidence": 0.95
}
```

## Configuration

### Environment Variables
- `OPENAI_API_KEY` - OpenAI API key (optional)
- `LOG_LEVEL` - Logging level (default: INFO)
- `PORT` - Application port (default: 8000)

### Device Data Format
Your network devices should provide this structure:
```python
{
  "hostname": "CORE-SW-01",
  "device_type": "Layer3Switch", 
  "parsed_data": {
    "interfaces": {...},
    "vlans": {...},
    "routing": {...}
  }
}
```

## Development

### Running Tests
```bash
# Test the core processor
python ai_engine/local_ai_processor.py

# Run full test suite (if available)
pytest
```

### Adding New Query Types
1. Add regex patterns to `_build_query_patterns()` in `local_ai_processor.py`
2. Create handler methods like `_handle_new_query_type()`
3. Add configuration templates to `_load_config_templates()`

### Custom Configuration Templates
Add new Cisco command templates:
```python
'create_new_feature': {
    'commands': [
        'configure terminal',
        'feature {feature_name}',
        'exit'
    ],
    'description': 'Enable {feature_name}',
    'risk_level': 'medium'
}
```

## Troubleshooting

### Common Issues

**"Module not found" errors:**
```bash
pip install -r requirements.txt
```

**"Port already in use":**
```bash
# Use a different port
uvicorn main:app --port 8001
```

**"Ollama not connecting":**
```bash
# Check if Ollama is running
curl http://localhost:11434/api/tags

# Restart Ollama service
ollama serve
```

**"No network data":**
- Ensure your device objects have the correct structure
- Check the `parsed_data` field contains interface/VLAN information

### Health Check
The application includes a health endpoint:
```bash
curl http://localhost:8000/health
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Submit a pull request

## Security Notes

- This application processes network configuration data
- Run in isolated environments for production use
- Validate all generated configurations before applying to live networks
- Consider using read-only network access for data collection

## License

[Add your license information here]