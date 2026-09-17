#!/usr/bin/env fish

# Create directory structure for WebGuard project
echo "Creating WebGuard project directory structure..."

set dirs \
    config \
    database \
    services \
    scanner \
    reports \
    templates \
    static/css \
    static/js \
    tests

for dir in $dirs
    mkdir -p $dir
    echo "  [+] Created directory: $dir"
end

# Create __init__.py files in Python packages
set packages \
    config \
    database \
    services \
    scanner \
    reports

for pkg in $packages
    touch "$pkg/__init__.py"
    echo "  [+] Created $pkg/__init__.py"
end

echo "Directory structure setup complete."
