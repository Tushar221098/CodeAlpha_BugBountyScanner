import os

# ---------------------------------------------------------
# Simple Bug Bounty Folder Scanner
# ---------------------------------------------------------
# This program scans a folder and checks files for common
# security risks like hardcoded passwords, API keys,
# insecure HTTP links, debug mode, and weak MD5 hashing.
# ---------------------------------------------------------


# These are folders that we do NOT want to scan.
# They usually contain many files that are not useful for this project.
# Skipping them saves time and avoids unnecessary scanning.
SKIP_FOLDERS = ["venv", ".git", "__pycache__", "node_modules"]


# These are the file types that the scanner will check.
# The tool will ignore other file types like images, videos, PDFs, etc.
ALLOWED_EXTENSIONS = [".py", ".js", ".txt", ".env", ".json"]


def check_line(line):
    """
    This function checks one line of code/text.

    It looks for simple risky keywords or patterns.
    If it finds a possible issue, it returns:
    1. Severity level
    2. Issue description

    If no issue is found, it returns None, None.
    """

    # Convert the line to lowercase so the scanner can match words
    # even if they are written as Password, PASSWORD, Api_Key, etc.
    line_lower = line.lower()

    # Check for possible hardcoded password.
    # Example: password = "admin123"
    if "password" in line_lower:
        return "HIGH", "Possible hardcoded password"

    # Check for possible hardcoded API key.
    # Example: api_key = "12345ABCDE"
    if "api_key" in line_lower or "apikey" in line_lower:
        return "HIGH", "Possible hardcoded API key"

    # Check for the word secret.
    # This may indicate a hardcoded secret key or token.
    if "secret" in line_lower:
        return "HIGH", "Possible hardcoded secret"

    # Check for insecure HTTP links.
    # HTTPS is safer because it encrypts traffic.
    if "http://" in line_lower:
        return "MEDIUM", "Insecure HTTP link"

    # Check if debug mode is enabled.
    # Debug mode should not be enabled in production.
    if "debug = true" in line_lower or "debug=true" in line_lower:
        return "LOW", "Debug mode may be enabled"

    # Check for MD5.
    # MD5 is considered weak and should not be used for secure hashing.
    if "md5" in line_lower:
        return "MEDIUM", "Weak hash function MD5 found"

    # If none of the checks matched, return no issue.
    return None, None


def should_scan_file(file_name):
    """
    This function checks whether a file should be scanned.

    It looks at the file extension.
    Only files ending with allowed extensions will be scanned.
    """

    # Go through each allowed extension one by one.
    for extension in ALLOWED_EXTENSIONS:

        # If the file name ends with an allowed extension,
        # then this file should be scanned.
        if file_name.endswith(extension):
            return True

    # If the file does not match any allowed extension,
    # do not scan it.
    return False


def scan_file(file_path):
    """
    This function scans one file.

    It opens the file, reads all lines, checks each line,
    and stores any findings in a list.
    """

    # This list will store all security findings from this file.
    findings = []

    try:
        # Open the file in read mode.
        # encoding="utf-8" helps read normal text/code files.
        # errors="ignore" prevents the program from crashing
        # if a file has strange characters.
        file = open(file_path, "r", encoding="utf-8", errors="ignore")

        # Read all lines from the file into a list.
        lines = file.readlines()

        # Close the file after reading it.
        file.close()

        # Go through each line with its line number.
        # start=1 means line numbering starts from 1 instead of 0.
        for line_number, line in enumerate(lines, start=1):

            # Check the current line for security issues.
            severity, issue = check_line(line)

            # If an issue was found, save the finding.
            if issue is not None:
                findings.append({
                    "file": file_path,
                    "line": line_number,
                    "severity": severity,
                    "issue": issue,
                    "code": line.strip()
                })

    except:
        # If the file cannot be read, print a message and continue.
        # This keeps the scanner from stopping completely.
        print("Could not scan file:", file_path)

    # Return all findings from this file.
    return findings


def scan_folder(folder_path):
    """
    This function scans a full folder.

    It walks through the folder, checks allowed files,
    skips unnecessary folders, and collects all findings.
    """

    # This list stores findings from all scanned files.
    all_findings = []

    # This counts how many files were scanned.
    total_files_scanned = 0

    # os.walk goes through the folder, its subfolders, and files.
    for root, folders, files in os.walk(folder_path):

        # Remove folders we do not want to scan.
        # This helps improve speed and avoids unnecessary files.
        folders[:] = [folder for folder in folders if folder not in SKIP_FOLDERS]

        # Go through each file in the current folder.
        for file_name in files:

            # Check if this file type is allowed.
            if should_scan_file(file_name):

                # Create the full file path.
                file_path = os.path.join(root, file_name)

                # Increase the scanned file count.
                total_files_scanned += 1

                # Scan the file and get findings.
                findings = scan_file(file_path)

                # Add findings from this file to the main findings list.
                all_findings.extend(findings)

    # Return the total scanned files and all findings.
    return total_files_scanned, all_findings


def print_report(total_files_scanned, findings):
    """
    This function prints the final scanner report.

    It shows:
    - Number of files scanned
    - Number of issues found
    - Count of HIGH, MEDIUM, and LOW issues
    - Details for each finding
    """

    print("\n========== Simple Bug Bounty Scanner Report ==========")
    print("Files scanned:", total_files_scanned)
    print("Issues found:", len(findings))

    # These variables count issues by severity.
    high_count = 0
    medium_count = 0
    low_count = 0

    # Count how many HIGH, MEDIUM, and LOW findings exist.
    for finding in findings:
        if finding["severity"] == "HIGH":
            high_count += 1
        elif finding["severity"] == "MEDIUM":
            medium_count += 1
        elif finding["severity"] == "LOW":
            low_count += 1

    # Print severity summary.
    print("\nSeverity Summary:")
    print("HIGH:", high_count)
    print("MEDIUM:", medium_count)
    print("LOW:", low_count)

    # Print each finding with details.
    print("\nDetailed Findings:")

    for finding in findings:
        print("\n--------------------------------")
        print("Severity:", finding["severity"])
        print("Issue:", finding["issue"])
        print("File:", finding["file"])
        print("Line:", finding["line"])
        print("Code:", finding["code"])


def main():
    """
    This is the main function.

    It asks the user for a folder path,
    checks if the folder exists,
    runs the scanner,
    and prints the final report.
    """

    # Ask the user which folder they want to scan.
    folder_path = input("Enter folder path to scan: ")

    # Check if the folder path exists.
    if not os.path.exists(folder_path):
        print("Error: Folder does not exist.")
        return

    # Scan the folder and collect results.
    total_files_scanned, findings = scan_folder(folder_path)

    # Print the final report.
    print_report(total_files_scanned, findings)


# Start the program by calling the main function.
main()