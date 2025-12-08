#!/bin/sh
set -e

echo "Creating password-protected manual.zip..."

# Check if APP_INTERNAL_API_KEY is set
if [ -z "$APP_INTERNAL_API_KEY" ]; then
    echo "WARNING: APP_INTERNAL_API_KEY environment variable is not set!"
    echo "Skipping manual.zip creation."
else
    # Check if all required files exist
    if [ -f "./manual.txt" ] && [ -f "./llm/rag/manual.odt" ] && [ -f "./llm/rag/manual.pdf" ]; then
        # Ensure static directory exists
        mkdir -p static
        
        # Remove existing zip if it exists
        rm -f static/manual.zip
        
        # Create password-protected zip file using zip command with -P flag
        # -P flag sets the password
        # -j flag junks the path (stores just filenames, not full paths)
        zip -P "$APP_INTERNAL_API_KEY" static/manual.zip \
            ./manual.txt \
            ./llm/rag/manual.odt \
            ./llm/rag/manual.pdf
        
        echo "✓ manual.zip created successfully in static/ with password protection"
    else
        echo "WARNING: One or more required files are missing:"
        [ ! -f "./manual.txt" ] && echo "  - manual.txt NOT FOUND"
        [ ! -f "./llm/rag/manual.odt" ] && echo "  - llm/rag/manual.odt NOT FOUND"
        [ ! -f "./llm/rag/manual.pdf" ] && echo "  - llm/rag/manual.pdf NOT FOUND"
        echo "Skipping manual.zip creation."
    fi
fi

echo "Starting FastAPI application..."

# Execute the main command (passed as arguments to this script)
exec "$@"
