import re  # Use regular expressions for the password character checks.
from pathlib import Path  # Resolve the project directory in a Windows-safe way.
import tkinter as tk  # Build the GUI with the standard library.
from tkinter import messagebox, scrolledtext  # Show messages and a scrollable result box.


PROJECT_ROOT = Path(__file__).resolve().parent  # Point to the folder that holds this script.
ENV_PATH = PROJECT_ROOT / ".env"  # Load configuration from the local .env file.
DEFAULT_MIN_LENGTH = 9  # Require at least nine characters.
DEFAULT_REQUIRE_UPPERCASE = True  # Require at least one uppercase letter.
DEFAULT_REQUIRE_LOWERCASE = True  # Require at least one lowercase letter.
DEFAULT_REQUIRE_SPECIAL = True  # Require at least one special character.
DEFAULT_SCORE_MAX = 100  # Report results on a score scale of 100.
DEFAULT_COMMON_PASSWORDS = {  # Keep a short blacklist of weak passwords.
    "password",  # Block the most common weak password.
    "123456",  # Block a heavily reused numeric password.
    "123456789",  # Block a longer but still weak numeric password.
    "qwerty",  # Block a common keyboard pattern.
    "abc123",  # Block a simple mixed pattern.
    "letmein",  # Block a common prompt-style password.
    "welcome",  # Block a common greeting password.
    "admin",  # Block an administrative default-style password.
    "password1",  # Block a slight variation of password.
    "iloveyou",  # Block a common phrase password.
}  # End of the default blacklist.


def load_env_file(path: Path) -> dict[str, str]:  # Read key-value settings from the .env file.
    values: dict[str, str] = {}  # Store parsed environment pairs in a simple dictionary.
    if not path.exists():  # Skip parsing when the file is missing.
        return values  # Return an empty dictionary so defaults can take over.
    for raw_line in path.read_text(encoding="utf-8").splitlines():  # Read the file line by line.
        line = raw_line.strip()  # Remove whitespace so comments and blanks are easy to detect.
        if not line or line.startswith("#"):  # Ignore empty lines and comment lines.
            continue  # Move to the next line.
        if "=" not in line:  # Ignore malformed entries that do not look like key-value pairs.
            continue  # Move to the next line.
        key, value = line.split("=", 1)  # Split only once so values can contain extra equals signs.
        values[key.strip()] = value.strip().strip('"').strip("'")  # Store a cleaned-up value.
    return values  # Give the parsed settings back to the caller.


def parse_bool(raw_value: str | None, fallback: bool) -> bool:  # Convert text into a boolean setting.
    if raw_value is None:  # Use the default when no override exists.
        return fallback  # Preserve the configured default.
    return raw_value.strip().lower() in {"1", "true", "yes", "on"}  # Accept common truthy values.


def parse_int(raw_value: str | None, fallback: int) -> int:  # Convert text into an integer setting.
    if raw_value is None:  # Use the default when no override exists.
        return fallback  # Preserve the configured default.
    try:  # Protect the parser from bad numeric input.
        return int(raw_value.strip())  # Convert the setting into an integer.
    except ValueError:  # Fall back cleanly if the input is invalid.
        return fallback  # Preserve the configured default.


def parse_password_list(raw_value: str | None) -> set[str]:  # Turn a comma-separated blacklist into a set.
    if raw_value is None or not raw_value.strip():  # Handle missing or empty input.
        return set(DEFAULT_COMMON_PASSWORDS)  # Use the built-in blacklist when no override is present.
    return {item.strip().lower() for item in raw_value.split(",") if item.strip()}  # Normalize each entry.


def build_config() -> dict[str, object]:  # Collect all runtime settings in one place.
    env_values = load_env_file(ENV_PATH)  # Read any overrides from the local .env file.
    config = {  # Assemble the final configuration dictionary.
        "min_length": parse_int(env_values.get("MIN_LENGTH"), DEFAULT_MIN_LENGTH),  # Read the length rule.
        "require_uppercase": parse_bool(env_values.get("REQUIRE_UPPERCASE"), DEFAULT_REQUIRE_UPPERCASE),  # Read the uppercase rule.
        "require_lowercase": parse_bool(env_values.get("REQUIRE_LOWERCASE"), DEFAULT_REQUIRE_LOWERCASE),  # Read the lowercase rule.
        "require_special": parse_bool(env_values.get("REQUIRE_SPECIAL"), DEFAULT_REQUIRE_SPECIAL),  # Read the special-character rule.
        "score_max": parse_int(env_values.get("SCORE_MAX"), DEFAULT_SCORE_MAX),  # Read the score ceiling.
        "common_passwords": parse_password_list(env_values.get("COMMON_PASSWORDS")),  # Read the blacklist.
        "window_title": env_values.get("WINDOW_TITLE", "Password Strength Analyzer"),  # Read the GUI window title.
    }  # End of the config dictionary.
    return config  # Hand the configuration back to the rest of the app.


CONFIG = build_config()  # Load configuration once when the script starts.


def analyze_password(password: str, config: dict[str, object] | None = None) -> dict[str, object]:  # Score a password against all rules.
    active_config = config or CONFIG  # Use the provided settings or the default script configuration.
    min_length = int(active_config["min_length"])  # Pull the minimum length rule into a local variable.
    require_uppercase = bool(active_config["require_uppercase"])  # Pull the uppercase rule into a local variable.
    require_lowercase = bool(active_config["require_lowercase"])  # Pull the lowercase rule into a local variable.
    require_special = bool(active_config["require_special"])  # Pull the special-character rule into a local variable.
    score_max = int(active_config["score_max"])  # Pull the maximum score into a local variable.
    common_passwords = set(active_config["common_passwords"])  # Pull the blacklist into a local variable.
    has_min_length = len(password) >= min_length  # Check whether the password meets the minimum length.
    has_uppercase = any(char.isupper() for char in password)  # Check whether the password includes an uppercase letter.
    has_lowercase = any(char.islower() for char in password)  # Check whether the password includes a lowercase letter.
    has_special = any(not char.isalnum() for char in password)  # Check whether the password includes a special character.
    is_common_password = password.lower() in common_passwords  # Check whether the password appears in the blacklist.
    score = score_max  # Start with a perfect score before applying penalties.
    score -= score_max // 5 if not has_min_length else 0  # Deduct one-fifth of the total score for length failure.
    score -= score_max // 5 if require_uppercase and not has_uppercase else 0  # Deduct one-fifth for missing uppercase characters.
    score -= score_max // 5 if require_lowercase and not has_lowercase else 0  # Deduct one-fifth for missing lowercase characters.
    score -= score_max // 5 if require_special and not has_special else 0  # Deduct one-fifth for missing special characters.
    score -= score_max // 5 if is_common_password else 0  # Deduct one-fifth for using a common password.
    score = max(0, score)  # Keep the score from going below zero.
    checks = [  # Build the rule-by-rule results for display.
        {"name": f"Minimum length of {min_length}", "passed": has_min_length},  # Record the length rule.
        {"name": "At least one uppercase letter", "passed": has_uppercase if require_uppercase else True},  # Record the uppercase rule.
        {"name": "At least one lowercase letter", "passed": has_lowercase if require_lowercase else True},  # Record the lowercase rule.
        {"name": "At least one special character", "passed": has_special if require_special else True},  # Record the special-character rule.
        {"name": "Not a common password", "passed": not is_common_password},  # Record the blacklist rule.
    ]  # End of the rule list.
    issues = [item["name"] for item in checks if not item["passed"]]  # Collect every failed rule for friendly output.
    is_strong = score == score_max and not issues  # Treat the password as strong only when every rule passes.
    return {  # Return the complete analysis package.
        "password": password,  # Include the original password for reference.
        "score": score,  # Include the final score.
        "score_max": score_max,  # Include the score ceiling.
        "checks": checks,  # Include the detailed rules.
        "issues": issues,  # Include the failed rules.
        "is_strong": is_strong,  # Include the overall strength verdict.
    }  # End of the analysis result.


def format_analysis(result: dict[str, object]) -> str:  # Turn the analysis dictionary into readable text.
    lines = [  # Collect each line of the output in order.
        f"Password score: {result['score']}/{result['score_max']}",  # Show the score summary.
        f"Strength verdict: {'Strong' if result['is_strong'] else 'Weak'}",  # Show the overall verdict.
        "",  # Insert a blank line before the rule breakdown.
        "Rule breakdown:",  # Introduce the rule list.
    ]  # End of the initial output lines.
    for item in result["checks"]:  # Walk through each rule result one at a time.
        status = "PASS" if item["passed"] else "FAIL"  # Convert the boolean result into readable text.
        lines.append(f"- {item['name']}: {status}")  # Add the formatted rule line.
    if result["issues"]:  # Add a summary of problems when any rules fail.
        lines.append("")  # Insert a blank line before the issue summary.
        lines.append("Issues:")  # Introduce the issue list.
        for issue in result["issues"]:  # Walk through each failed rule.
            lines.append(f"- {issue}")  # Add the failed rule to the report.
    return "\n".join(lines)  # Merge the lines into a single printable string.


def run_cli(config: dict[str, object] | None = None) -> None:  # Run the analyzer in a terminal session.
    active_config = config or CONFIG  # Use the provided settings or the default script configuration.
    print("Password Strength Analyzer")  # Show the application title.
    print("Enter a password to see a full strength report.")  # Tell the user what to do.
    password = input("Password: ")  # Read the password from the terminal.
    result = analyze_password(password, active_config)  # Analyze the password with the shared engine.
    print()  # Separate the input prompt from the report.
    print(format_analysis(result))  # Display the formatted report.


def run_gui(config: dict[str, object] | None = None) -> None:  # Run the analyzer in a small desktop window.
    active_config = config or CONFIG  # Use the provided settings or the default script configuration.
    try:  # Handle environments where Tk cannot open a display.
        root = tk.Tk()  # Create the main GUI window.
    except tk.TclError:  # Catch failures caused by a missing desktop display.
        messagebox.showerror("Password Strength Analyzer", "The GUI could not start, so the CLI will open instead.")  # Explain the fallback.
        run_cli(active_config)  # Fall back to the terminal version.
        return  # Stop the GUI startup path.
    root.title(str(active_config["window_title"]))  # Set the window title from configuration.
    root.geometry("560x420")  # Give the window a practical starting size.
    root.minsize(520, 380)  # Prevent the window from becoming too small to read.
    root.configure(padx=16, pady=16)  # Add some breathing room around the content.
    title_label = tk.Label(root, text="Password Strength Analyzer", font=("Segoe UI", 18, "bold"))  # Build the title label.
    title_label.pack(anchor="w", pady=(0, 8))  # Place the title at the top of the window.
    prompt_label = tk.Label(root, text="Enter a password to analyze:", font=("Segoe UI", 10))  # Build the prompt label.
    prompt_label.pack(anchor="w")  # Place the prompt above the input box.
    password_entry = tk.Entry(root, show="*", font=("Segoe UI", 12), width=36)  # Create a masked password input.
    password_entry.pack(fill="x", pady=(6, 10))  # Stretch the input box across the window.
    result_box = scrolledtext.ScrolledText(root, height=14, font=("Consolas", 10), wrap="word")  # Create the results panel.
    result_box.pack(fill="both", expand=True, pady=(0, 10))  # Let the panel grow with the window.
    result_box.insert("1.0", "Your password report will appear here.")  # Show an initial placeholder message.
    result_box.configure(state="disabled")  # Make the result panel read-only until updated.

    def analyze_current_password() -> None:  # Analyze whatever the user entered into the GUI.
        password = password_entry.get()  # Read the current password from the input box.
        result = analyze_password(password, active_config)  # Reuse the shared rule engine.
        report = format_analysis(result)  # Format the analysis into readable text.
        result_box.configure(state="normal")  # Allow the result box to be updated.
        result_box.delete("1.0", "end")  # Clear the previous report.
        result_box.insert("1.0", report)  # Insert the new report.
        result_box.configure(state="disabled")  # Lock the result box again after the update.

    analyze_button = tk.Button(root, text="Analyze Password", command=analyze_current_password, font=("Segoe UI", 10, "bold"))  # Create the action button.
    analyze_button.pack(anchor="w", pady=(0, 8))  # Place the button below the input box.
    root.bind("<Return>", lambda _event: analyze_current_password())  # Let the Enter key trigger the analysis.
    password_entry.focus_set()  # Put the cursor in the password box immediately.
    root.mainloop()  # Start the GUI event loop.


def choose_mode() -> str:  # Ask the user whether to open the CLI or the GUI.
    print("Password Strength Analyzer")  # Show the application title.
    print("1. Command line")  # Offer the terminal version.
    print("2. GUI")  # Offer the desktop window version.
    choice = input("Choose a mode (1 or 2): ").strip()  # Read the user's choice.
    return choice  # Give the choice back to the caller.


def main() -> None:  # Start the application from one central entry point.
    choice = choose_mode()  # Ask the user which interface to launch.
    if choice == "2":  # Launch the GUI when the user selects option two.
        run_gui(CONFIG)  # Start the desktop interface.
        return  # Stop after the GUI exits.
    run_cli(CONFIG)  # Default to the command-line interface.


if __name__ == "__main__":  # Run the program only when the file is executed directly.
    main()  # Launch the selected interface.
