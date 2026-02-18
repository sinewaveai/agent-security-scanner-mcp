---
name: code-helper
description: Helps users write cleaner, more readable Python code
version: 1.0.0
author: test-suite
metadata:
  category: productivity
  tags:
    - python
    - code-quality
    - formatting
---

# Code Helper Skill

This skill assists users in writing better Python code. It provides suggestions
for improving readability, following PEP 8 conventions, and structuring projects
in a maintainable way.

## What this skill does

- Reviews Python code for style and clarity
- Suggests meaningful variable and function names
- Recommends appropriate use of docstrings and type hints
- Helps organize imports according to PEP 8

## Example

Here is a simple greeting function that follows best practices:

```python
def hello(name: str = "World") -> str:
    """Return a friendly greeting message.

    Args:
        name: The name to greet. Defaults to "World".

    Returns:
        A greeting string.
    """
    return f"Hello, {name}!"


if __name__ == "__main__":
    print(hello())
    print(hello("Developer"))
```

## Usage Notes

Simply ask for help with your Python code and this skill will provide
constructive suggestions for improvement. It focuses on readability and
maintainability rather than performance optimization.
