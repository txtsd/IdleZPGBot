def is_valid_name(name, allow_spaces=False):
    """
    Validate a name to ensure it is <=16 characters (excluding spaces if allowed).

    Name can contain letters (including accents, diacritics, CJK characters, etc.),
    numbers, dashes, and underscores. Class names may contain spaces.

    Args:
        name (str): The name to validate.
        allow_spaces (bool): Whether spaces are allowed in the name.

    Returns:
        Tuple[bool, str]: (is_valid, error_message)
            - is_valid (bool): True if the name is valid, False otherwise.
            - error_message (str): Reason why the name is invalid, if applicable.
    """
    name = name.strip()
    if not name:
        return False, 'Name cannot be empty.'

    if r'\t' in name or r'\n' in name:
        return False, 'Name cannot contain tabs or newlines.'

    # Allowed characters: letters, numbers, dashes, underscores, and optional spaces.
    invalid_chars = []
    for c in name:
        if c == ' ' and allow_spaces:
            continue
        elif c.isalnum() or c in ('-', '_'):
            continue
        else:
            invalid_chars.append(c)

    if invalid_chars:
        invalid_chars_str = ''.join(sorted(set(invalid_chars)))
        return False, f"Name contains invalid characters: '{invalid_chars_str}'"

    # Count the number of characters (excluding spaces if allowed).
    char_count = len(name.replace(' ', '')) if allow_spaces else len(name)
    if char_count > 16:
        return False, f'Name must be at most 16 characters, but it has {char_count} characters.'
    return True, ''


def strip_leading_the(s):
    """
    Strip leading 'the' from the class name.

    Args:
        s (str): The class name.

    Returns:
        str: Class name without leading 'the'.
    """
    s = s.strip()
    if s.lower().startswith('the '):
        return s[4:].strip()
    return s
