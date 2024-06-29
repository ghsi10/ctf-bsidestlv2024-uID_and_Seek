#!/bin/bash

PORT=4444

echo "Starting the server on port $PORT..."
socat TCP-LISTEN:$PORT,fork EXEC:"./qemu-cmd.sh"
echo "Server has been gracefully shut down."
