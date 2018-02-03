#!/usr/bin/env bash
# Run above script in another window

## At the terminal when you start getting the prompts, type `Accepts` and press enter
function Accepts () {
osascript <<EOF
  tell application "System Events"
    repeat while exists (processes where name is "SecurityAgent")
      tell process "SecurityAgent" to click button "Allow" of window 1
      delay 0.2
    end repeat
  end tell
EOF
}

## At the terminal when you start getting the prompts, type `Accepts YourUsername YourPassword` and press enter
function AcceptWithCreds () {
username="$1"
password="$2"

[ -z "${password}" ] && return 1

osascript 2>/dev/null <<EOF
    set appName to "${username}"
    set appPass to "${password}"
    tell application "System Events"
        repeat while exists (processes where name is "SecurityAgent")
            tell process "SecurityAgent"
                if exists (text field 1 of window 1) then
                    set value of text field 1 of window 1 to appName
                    set value of text field 2 of window 1 to appPass
                end if
            end tell
      tell process "SecurityAgent" to click button "Allow" of window 1
            delay 0.2
        end repeat
    end tell
EOF
echo 'Finished...'
}

security dump-keychain -d login.keychain
security dump-keychain -d /Library/Keychains/System.keychain
