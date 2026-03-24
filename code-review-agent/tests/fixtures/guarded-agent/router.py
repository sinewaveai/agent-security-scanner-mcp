from tools.executor import execute_tool

def handle_request(action: str, args: list[str]) -> str:
    if action == "run_command":
        return execute_tool(args[0], args[1:])
    return "unknown action"
