#!/bin/bash
# ACO-based Secure IoT Routing App Installation Script for Linux

echo "=== ACO-based Secure IoT Routing Application Installer ==="
echo "This script will install the application and its dependencies."
echo

# Check if Python 3 is installed
if command -v python3 &>/dev/null; then
    PYTHON_CMD="python3"
elif command -v python &>/dev/null; then
    PYTHON_VERSION=$(python --version 2>&1 | cut -d' ' -f2 | cut -d'.' -f1)
    if [ "$PYTHON_VERSION" -ge 3 ]; then
        PYTHON_CMD="python"
    else
        echo "Error: Python 3 is required but not found."
        echo "Please install Python 3 and try again."
        exit 1
    fi
else
    echo "Error: Python is not installed."
    echo "Please install Python 3 and try again."
    exit 1
fi

echo "Using Python: $($PYTHON_CMD --version)"

# Check for pip
if command -v pip3 &>/dev/null; then
    PIP_CMD="pip3"
elif command -v pip &>/dev/null; then
    PIP_CMD="pip"
else
    echo "Error: pip is not installed."
    echo "Installing pip..."
    $PYTHON_CMD -m ensurepip --upgrade || {
        echo "Failed to install pip. Please install pip manually and try again."
        exit 1
    }
    PIP_CMD="pip3"
fi

echo "Using pip: $($PIP_CMD --version)"

# Create a virtual environment (optional)
echo "Would you like to install the application in a virtual environment? (recommended) [Y/n]"
read -r create_venv

if [[ $create_venv != "n" && $create_venv != "N" ]]; then
    echo "Creating virtual environment..."
    $PYTHON_CMD -m venv venv || {
        echo "Failed to create virtual environment. Continuing with system Python..."
    }
    
    if [ -d "venv" ]; then
        echo "Activating virtual environment..."
        source venv/bin/activate
        PIP_CMD="pip"
        PYTHON_CMD="python"
        echo "Virtual environment activated."
    fi
fi

# Install dependencies
echo "Installing dependencies..."
$PIP_CMD install --upgrade pip
$PIP_CMD install pymongo networkx numpy matplotlib pandas pillow python-dateutil

# Check for MongoDB
echo "Checking for MongoDB..."
if command -v mongod &>/dev/null; then
    echo "MongoDB is installed."
    
    # Check if MongoDB is running
    if pgrep mongod >/dev/null; then
        echo "MongoDB is running."
    else
        echo "MongoDB is installed but not running."
        echo "You may need to start MongoDB manually:"
        echo "  sudo systemctl start mongod    # For systemd-based systems"
        echo "  sudo service mongod start      # For sysvinit-based systems"
    fi
else
    echo "MongoDB is not installed."
    echo "It is recommended to install MongoDB for full functionality."
    echo "Installation instructions: https://docs.mongodb.com/manual/administration/install-community/"
    
    echo "Would you like to continue without MongoDB? [Y/n]"
    read -r continue_without_mongodb
    if [[ $continue_without_mongodb == "n" || $continue_without_mongodb == "N" ]]; then
        echo "Installation aborted. Please install MongoDB and try again."
        exit 1
    fi
    echo "Continuing installation without MongoDB..."
fi

# Install the application using setup.py
echo "Installing the application..."
$PYTHON_CMD setup.py install || {
    echo "Warning: Failed to install the application using setup.py."
    echo "The application can still be run directly using '$PYTHON_CMD main.py'"
}

# Create a desktop entry (optional)
if [ -d "$HOME/.local/share/applications" ]; then
    echo "Would you like to create a desktop shortcut? [Y/n]"
    read -r create_shortcut
    
    if [[ $create_shortcut != "n" && $create_shortcut != "N" ]]; then
        echo "Creating desktop shortcut..."
        APP_DIR="$(pwd)"
        
        # Create the desktop entry
        cat > "$HOME/.local/share/applications/aco-iot-routing.desktop" << EOF
[Desktop Entry]
Type=Application
Name=ACO IoT Routing
Comment=Ant Colony Optimization based Secure IoT Routing Application
Exec=$APP_DIR/venv/bin/python $APP_DIR/main.py
Icon=utilities-terminal
Terminal=false
Categories=Network;Security;
EOF
        
        echo "Desktop shortcut created."
    fi
fi

echo
echo "=== Installation Complete ==="
echo "You can run the application using:"
if [ -d "venv" ]; then
    echo "  source venv/bin/activate"
    echo "  python main.py"
else
    echo "  $PYTHON_CMD main.py"
fi
echo
echo "Thank you for installing the ACO-based Secure IoT Routing Application!"
