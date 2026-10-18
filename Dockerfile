FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Install system dependencies
# Node.js is needed for Shodan MCP server (npx)
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc \
        curl \
        ca-certificates \
        gnupg \
    && mkdir -p /etc/apt/keyrings \
    && curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key \
        | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg \
    && echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_20.x nodistro main" \
        > /etc/apt/sources.list.d/nodesource.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends nodejs \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Pre-install the Shodan MCP package globally so npx doesn't need to
# download it at runtime on every cold start (which caused >30s delays).
RUN npm install -g @burtthecoder/mcp-shodan || true

# Set work directory
WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy project
COPY . .

# Collect static files
RUN python manage.py collectstatic --noinput 2>/dev/null || true

# Expose port
EXPOSE ${PORT:-8000}

# Run with gunicorn
CMD python manage.py migrate --noinput && gunicorn osint_project.wsgi:application --bind [::]:${PORT:-8000} --workers 1 --timeout 120 --keep-alive 5