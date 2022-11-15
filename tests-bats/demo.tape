# Where should we write the GIF?
Output ../docs/demo.gif

# Set up a 1200x600 terminal with 46px font.
Set FontSize 16
Set Width 1200
Set Height 600

# Show Folders
Type "ls"
Enter

# Type a command in the terminal.
Type "export DECRYPT_TOOL_CONNECTION_STRING='server=localhost;database=datadonation;user=root;password=example;OldGuids=true'"
Sleep 200ms
Enter

Type "./decrypt-tool --privateKeyFolder keys"

# Pause for dramatic effect...
Sleep 500ms

# Run the command by pressing enter.
Enter

# Admire the output for a bit.
Sleep 5s