#!/bin/sh

command -v cargo >/dev/null 2>&1 && { echo "The cargo is installed"; } || { 
    echo "The cargo is not installed"
    echo "This rock contains the Rust code: make sure you have a Rust development environment installed and try again"
    exit 1
}
