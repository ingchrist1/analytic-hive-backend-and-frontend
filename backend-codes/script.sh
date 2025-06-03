#!/bin/bash

# Directory to watch (change if needed)
WATCH_DIR="."

cd "$WATCH_DIR" || exit 1

echo "Watching $WATCH_DIR for changes..."

while inotifywait -r -e modify,create,delete,move .; do
    git add .
    git commit -m "in the mist of doing hard things by ingchrist: file/folder change detected"
    git push
    echo "Changes pushed to GitHub."

    echo "Pausing for 10 seconds..."
    for i in {10..1}; do
        echo -ne "Resuming in $i seconds...\r" # -ne for no newline and enable backspace
        sleep 1
    done
    echo "Resuming in 0 seconds.                                  " # Clear the line after countdown
    echo "Resuming watch."

done