#!/usr/bin/env osascript
# AppleScript which allows to automatically click on Allow button of SecurityAgent.
# See: http://apple.stackexchange.com/a/184901/22781
tell application "System Events"
	repeat while exists (processes where name is "SecurityAgent")
		tell process "SecurityAgent"
			click button "Allow" of group 1 of window 1
		end tell
		delay 0.2
	end repeat
end tell
