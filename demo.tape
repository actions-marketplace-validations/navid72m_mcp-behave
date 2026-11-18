# VHS Tape configuration for mcp-behave demo
# Run: vhs demo.tape

Output demo.gif

Set FontSize 15
Set Width 1000
Set Height 820
Set Padding 20
Set Framerate 30
Set PlaybackSpeed 1.0
Set Theme "Catppuccin Mocha"
Set WindowBar "Colorful"

# Title banner
Type "clear" Enter
Sleep 500ms

# Run honest server (clean baseline)
Type "mcp-behave python targets/honest_server.py" Enter
Sleep 4s

# Run leaky server (behavioral detection)
Type "mcp-behave python targets/leaky_server.py" Enter
Sleep 14s
