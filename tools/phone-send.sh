#!/bin/bash
# Development helper: share a text from an Android phone with Samsung Quick
# Share over adb and tap this computer's entry in the share sheet.
#
#   tools/phone-send.sh [text]
#
# Needs adb to the phone with its screen unlocked. NEARCAST_NAME is the name
# nearcastd shows (default: this host's name). SETTLE=20 waits for discovery
# to replace any cached entry first. The text must not contain spaces, since
# adb shell splits it again. Exit 2 means the phone showed a pairing prompt.
text=${1:-nearcast-test}
name=${NEARCAST_NAME:-$(uname -n)}
ui() { adb shell uiautomator dump /sdcard/ui.xml >/dev/null && adb shell cat /sdcard/ui.xml; }
adb shell input keyevent KEYCODE_WAKEUP
adb shell input keyevent KEYCODE_HOME
sleep 1
adb shell am start -a android.intent.action.SEND -t text/plain \
    --es android.intent.extra.TEXT "$text" -p com.samsung.android.app.sharelive >/dev/null 2>&1
sleep "${SETTLE:-0}"
for i in $(seq 1 12); do
    sleep 5
    x=$(ui)
    if grep -q 'Pair with' <<<"$x"; then echo "pairing prompt after ${i}x5s"; exit 2; fi
    b=$(grep -oE "text=\"$name\"[^>]*bounds=\"\[[0-9]+,[0-9]+\]\[[0-9]+,[0-9]+\]\"" <<<"$x" | grep -oE '[0-9]+' | tail -4 | tr '\n' ' ')
    if [ -n "$b" ]; then
        read -r x1 y1 x2 y2 <<<"$b"
        adb shell input tap $(( (x1 + x2) / 2 )) $(( y1 - 80 ))
        echo "tapped $name after ${i}x5s"
        exit 0
    fi
done
echo "$name not found"; exit 1
