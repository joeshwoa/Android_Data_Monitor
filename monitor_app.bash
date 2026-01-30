#!/bin/bash
# monitor.sh - Quick Android Data Monitor with APK support

if [ $# -lt 1 ]; then
    echo "Usage:"
    echo "  $0 <apk_file> [interval] [duration]"
    echo "  $0 -p <package_name> [interval] [duration]"
    echo ""
    echo "Examples:"
    echo "  $0 app.apk"
    echo "  $0 app.apk 1 60"
    echo "  $0 -p com.example.app 2 120"
    exit 1
fi

if [ "$1" = "-p" ]; then
    # Package name mode
    if [ $# -lt 2 ]; then
        echo "Error: Package name required after -p"
        exit 1
    fi
    PACKAGE="$2"
    INTERVAL="${3:-2}"
    DURATION="${4:-0}"
    
    echo "[*] Monitoring package: $PACKAGE"
    python3 android_data_monitor.py -p "$PACKAGE" -i "$INTERVAL" ${DURATION:+-d $DURATION}
else
    # APK file mode
    APK_FILE="$1"
    INTERVAL="${2:-2}"
    DURATION="${3:-0}"
    
    if [ ! -f "$APK_FILE" ]; then
        echo "Error: APK file not found: $APK_FILE"
        exit 1
    fi
    
    echo "[*] Monitoring APK: $APK_FILE"
    python3 android_data_monitor.py -a "$APK_FILE" -i "$INTERVAL" ${DURATION:+-d $DURATION}
fi
