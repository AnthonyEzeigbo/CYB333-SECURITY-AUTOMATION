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
    root.geometry("760x560")  # Give the window a larger starting size for the themed layout.
    root.minsize(700, 520)  # Prevent the window from becoming too small to read.
    root.configure(bg="#5ec8ff")  # Use a bright sky-blue background for the retro game look.
    root.option_add("*Font", ("Segoe UI", 10))  # Set a consistent base font for the window.
    root.option_add("*TButton*Font", ("Segoe UI", 10, "bold"))  # Give buttons a stronger arcade feel.
    root.option_add("*TEntry*Font", ("Consolas", 12))  # Use a console-style font for the password field.

    outer_frame = tk.Frame(root, bg="#5ec8ff", padx=18, pady=18)  # Create the outer themed frame.
    outer_frame.pack(fill="both", expand=True)  # Let the frame fill the window.

    header_canvas = tk.Canvas(outer_frame, height=120, bg="#5ec8ff", highlightthickness=0)  # Create a sky backdrop.
    header_canvas.pack(fill="x", pady=(0, 14))  # Place the backdrop above the main panel.
    header_canvas.create_oval(22, 18, 112, 108, fill="#ffffff", outline="#ffffff")  # Draw a soft cloud.
    header_canvas.create_oval(72, 26, 156, 94, fill="#ffffff", outline="#ffffff")  # Draw the second cloud puff.
    header_canvas.create_oval(620, 16, 700, 92, fill="#fff6b0", outline="#fff6b0")  # Draw a bright sun.
    header_canvas.create_text(640, 34, text="*", fill="#ffffff", font=("Consolas", 18, "bold"))  # Add a sparkle near the sun.
    header_canvas.create_text(672, 68, text="*", fill="#ffffff", font=("Consolas", 18, "bold"))  # Add a second sparkle near the sun.
    header_canvas.create_text(18, 22, anchor="nw", text="RETRO POWER CHECK", fill="#ffe066", font=("Consolas", 15, "bold"))  # Add an arcade-style header.
    header_canvas.create_text(18, 50, anchor="nw", text="A platformer-inspired password analyzer", fill="#ffffff", font=("Segoe UI", 11, "bold"))  # Add the subtitle.
    header_canvas.create_rectangle(0, 102, 760, 120, fill="#8b5a2b", outline="#8b5a2b")  # Draw the ground strip.
    for x_position in range(0, 760, 40):  # Repeat block accents across the ground.
        header_canvas.create_line(x_position, 102, x_position, 120, fill="#6f451e")  # Draw vertical block seams.
    for x_position in range(18, 260, 66):  # Add brick accents to the ground.
        header_canvas.create_rectangle(x_position, 76, x_position + 46, 102, fill="#c96f2d", outline="#8b4513", width=2)  # Draw a brick block.
        header_canvas.create_line(x_position + 2, 89, x_position + 44, 89, fill="#8b4513")  # Split the brick block in half.
        header_canvas.create_line(x_position + 15, 76, x_position + 15, 102, fill="#8b4513")  # Add the brick seam.
    header_canvas.create_rectangle(610, 62, 672, 102, fill="#29a74a", outline="#1f7e37", width=3)  # Draw a green pipe.
    header_canvas.create_rectangle(630, 42, 652, 62, fill="#29a74a", outline="#1f7e37", width=3)  # Draw the pipe lip.
    header_canvas.create_rectangle(350, 58, 402, 98, fill="#ffd166", outline="#c98f00", width=3)  # Draw a question block.
    header_canvas.create_text(376, 78, text="?", fill="#8c5c00", font=("Consolas", 24, "bold"))  # Mark the block with a question symbol.
    header_canvas.create_rectangle(470, 64, 524, 100, fill="#ef7d31", outline="#a94d14", width=3)  # Draw a bonus block.
    header_canvas.create_text(497, 82, text="#", fill="#fff6d5", font=("Consolas", 20, "bold"))  # Mark the bonus block.

    panel_frame = tk.Frame(outer_frame, bg="#f8f1d9", highlightbackground="#d86a25", highlightthickness=4)  # Create the main content panel.
    panel_frame.pack(fill="both", expand=True)  # Let the panel fill the remaining space.

    title_label = tk.Label(panel_frame, text="Password Strength Analyzer", font=("Segoe UI", 20, "bold"), bg="#f8f1d9", fg="#c92a2a")  # Build the title label.
    title_label.pack(anchor="w", padx=18, pady=(14, 2))  # Place the title at the top of the panel.
    prompt_label = tk.Label(panel_frame, text="Enter a password to analyze:", font=("Segoe UI", 11, "bold"), bg="#f8f1d9", fg="#2d2d2d")  # Build the prompt label.
    prompt_label.pack(anchor="w", padx=18)  # Place the prompt above the input box.

    input_row = tk.Frame(panel_frame, bg="#f8f1d9")  # Create a row for the input and action button.
    input_row.pack(fill="x", padx=18, pady=(8, 10))  # Place the input row below the prompt.
    password_entry = tk.Entry(input_row, show="*", font=("Consolas", 12), width=34, relief="flat", bd=0, fg="#14324d", insertbackground="#14324d")  # Create a masked password input.
    password_entry.pack(side="left", fill="x", expand=True, ipady=6)  # Stretch the input box across the row.
    analyze_button = tk.Button(input_row, text="ANALYZE", command=lambda: analyze_current_password(), bg="#e53935", fg="#ffffff", activebackground="#c62828", activeforeground="#ffffff", relief="raised", bd=3, padx=16, pady=6, cursor="hand2")  # Create the action button.
    analyze_button.pack(side="left", padx=(10, 0))  # Place the button beside the input box.

    result_frame = tk.Frame(panel_frame, bg="#1f2a44", highlightbackground="#14324d", highlightthickness=3)  # Create a game-status style panel.
    result_frame.pack(fill="both", expand=True, padx=18, pady=(0, 14))  # Let the result panel grow with the window.
    result_label = tk.Label(result_frame, text="RESULTS", font=("Consolas", 12, "bold"), bg="#1f2a44", fg="#ffd166")  # Add a retro status heading.
    result_label.pack(anchor="w", padx=12, pady=(10, 4))  # Place the heading at the top of the result panel.
    result_box = scrolledtext.ScrolledText(result_frame, height=14, font=("Consolas", 10), wrap="word", bg="#102030", fg="#f7f7f7", insertbackground="#f7f7f7", relief="flat", bd=0, padx=10, pady=10)  # Create the themed results panel.
    result_box.pack(fill="both", expand=True, padx=12, pady=(0, 12))  # Let the panel fill the available space.
    result_box.insert("1.0", "Your password report will appear here.")  # Show an initial placeholder message.
    result_box.configure(state="disabled")  # Make the result panel read-only until updated.

    footer_label = tk.Label(panel_frame, text="Power up your password with length, mix, and a little style.", font=("Segoe UI", 9, "italic"), bg="#f8f1d9", fg="#6b4f1d")  # Add a playful footer line.
    footer_label.pack(anchor="w", padx=18, pady=(0, 12))  # Place the footer at the bottom of the panel.

    coin = header_canvas.create_oval(562, 34, 592, 64, fill="#ffd54f", outline="#f4b400", width=3)  # Draw a gold coin.
    coin_text = header_canvas.create_text(577, 49, text="$", fill="#8a5a00", font=("Consolas", 16, "bold"))  # Add a coin symbol.
    coin_state = {"direction": 1, "offset": 0}  # Track the coin bobbing animation.

    def animate_coin() -> None:  # Move the coin up and down like a floating reward.
        if not header_canvas.winfo_exists() or not root.winfo_exists():  # Stop if the window is gone.
            return  # Exit without rescheduling.
        delta = coin_state["direction"] * 2  # Move the coin by a small amount each step.
        header_canvas.move(coin, 0, delta)  # Shift the coin circle.
        header_canvas.move(coin_text, 0, delta)  # Shift the coin symbol.
        coin_state["offset"] += delta  # Update the tracked offset.
        if coin_state["offset"] >= 12:  # Reverse after the coin rises too far.
            coin_state["direction"] = -1  # Start moving the coin downward.
        elif coin_state["offset"] <= 0:  # Reverse after the coin drops back down.
            coin_state["direction"] = 1  # Start moving the coin upward.
        root.after(160, animate_coin)  # Keep the animation going.

    sparkles = [  # Store the sparkle text items so they can pulse.
        header_canvas.create_text(610, 28, text="*", fill="#ffffff", font=("Consolas", 14, "bold")),  # Create one sparkle.
        header_canvas.create_text(694, 46, text="*", fill="#ffffff", font=("Consolas", 14, "bold")),  # Create a second sparkle.
        header_canvas.create_text(330, 30, text="*", fill="#ffffff", font=("Consolas", 14, "bold")),  # Create a third sparkle.
    ]  # End of the sparkle list.
    sparkle_state = {"bright": True}  # Track whether the sparkles are bright or dim.

    def animate_sparkles() -> None:  # Alternate sparkle visibility to mimic a twinkle effect.
        if not header_canvas.winfo_exists() or not root.winfo_exists():  # Stop if the window is gone.
            return  # Exit without rescheduling.
        sparkle_state["bright"] = not sparkle_state["bright"]  # Flip the sparkle state.
        sparkle_color = "#ffffff" if sparkle_state["bright"] else "#cfefff"  # Pick a bright or softer glow.
        for sparkle in sparkles:  # Update each sparkle in the header.
            header_canvas.itemconfigure(sparkle, fill=sparkle_color)  # Apply the new sparkle color.
        root.after(280, animate_sparkles)  # Keep the twinkle effect going.

    animate_coin()  # Start the coin bobbing animation.
    animate_sparkles()  # Start the sparkle animation.

    def analyze_current_password() -> None:  # Analyze whatever the user entered into the GUI.
        password = password_entry.get()  # Read the current password from the input box.
        result = analyze_password(password, active_config)  # Reuse the shared rule engine.
        report = format_analysis(result)  # Format the analysis into readable text.
        result_box.configure(state="normal")  # Allow the result box to be updated.
        result_box.delete("1.0", "end")  # Clear the previous report.
        result_box.insert("1.0", report)  # Insert the new report.
        result_box.configure(state="disabled")  # Lock the result box again after the update.

    analyze_button.configure(command=analyze_current_password)  # Wire the themed button to the analysis action.
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
