# Password Strength Analyzer

This project is a small Python password strength analyzer that checks a password against practical strength rules and reports a score out of 100. It includes both a command-line interface and a simple GUI so the same validation engine can be used in either workflow.

## Features

- Minimum length check with a default of 9 characters.
- Uppercase, lowercase, and special-character requirements.
- Common-password blacklist check.
- Score summary out of 100.
- Command-line mode and GUI mode using the Python standard library.
- `.env`-based configuration for documented settings.

## How It Works

The analyzer uses one shared validation function. Both the CLI and GUI call that same function so the rules stay consistent.

Each password is checked for:

- Length
- Uppercase letters
- Lowercase letters
- Special characters
- Common password blacklist matches

The score starts at 100 and loses points when a rule fails.

## Project Files

- `Password Strength Analyzer.py`: main application script.
- `.env`: local configuration values used by the app.
- `.env.example`: sample configuration template.

## Setup

1. Make sure Python 3.10 or newer is installed.
2. Open the project folder in a terminal.
3. Review `.env` if you want to change the default rules.

## Configuration

The application reads these variables from `.env`:

- `MIN_LENGTH`: minimum password length.
- `REQUIRE_UPPERCASE`: enables or disables the uppercase rule.
- `REQUIRE_LOWERCASE`: enables or disables the lowercase rule.
- `REQUIRE_SPECIAL`: enables or disables the special-character rule.
- `SCORE_MAX`: maximum score for the analyzer.
- `COMMON_PASSWORDS`: comma-separated blacklist values.
- `WINDOW_TITLE`: title shown in the GUI window.

Example values are stored in `.env.example`.

## Usage

Run the script with Python:

```powershell
python "Password Strength Analyzer.py"
```

When the app starts, choose:

- `1` for the command-line analyzer
- `2` for the GUI analyzer

## Example Passwords

- Strong example: `Secure!Pass9`
- Weak example: `password`

## Notes

The `.env` file in this project is for documented configuration, not secrets. If you want to customize the default rules, edit the values and rerun the script.