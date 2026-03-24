import subprocess
from .guard import is_allowed_command

ALLOWED_COMMANDS = {"ls", "cat", "echo", "date", "whoami"}

def execute_tool(command: str, args: list[str]) -> str:
    if command not in ALLOWED_COMMANDS:
        raise ValueError(f"Command not allowed: {command}")
    result = subprocess.run([command, *args], capture_output=True, text=True, shell=False)
    return result.stdout
