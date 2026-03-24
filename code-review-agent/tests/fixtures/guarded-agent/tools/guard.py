ALLOWED_COMMANDS = frozenset({"ls", "cat", "echo", "date", "whoami"})

def is_allowed_command(command: str) -> bool:
    return command in ALLOWED_COMMANDS
