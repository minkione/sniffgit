import os
import sys
import fnmatch
from colorama import Fore, Back, Style, init
from collections import deque
import argparse
import codecs

SENSITIVE_FILE_PATTERN = set(["*.crt", ".bash_history", "*.pfx", "*.csr", "*.p12", "id_dsa", "*.der", ".htaccess", ".htpasswd", "*.jks", "wp-config.php", "*.pub", "web.config", "*.cert", "*.key", "id_rsa", "*.pem"])
SENSITIVE_KEYWORD = set(["secret_key", "pass", "credentials", "AWS_SESSION_TOKEN", "credential", "username", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "token", "password", "pw ", "pwd", "email", "api_key", "AWS_KEY"])
IGNORED_FILENAME_PATTERN = set(["*.egg-info", "Gemfile","site-packages", "bin", "node_modules", "bower_components", "tmp", "__pycache__", "db", ".git"])
IGNORED_TEXTFILE_PATTERN = set(["*.log", "*.pyc", "test_sniffgit.py", "sensitive_file_patterns.yaml", ".DS_Store", "package-lock.json", ".gitignore", "TODO", "sensitive_keywords.yaml", "sniffgit.py", "README.md"])

class SensitiveLine:

    def __init__(self, line_no, line, indicator):
        self.line_no = line_no
        self.line = line
        self.indicator = indicator

'''
Check if a file is potentially sensitive / secret (id_rsa, *.crt, etc)
'''
def file_is_sensitive(file_name):
    if any(fnmatch.fnmatch(file_name, pattern) for pattern in SENSITIVE_FILE_PATTERN):
        return True

    return False

'''
Remove any slashes at both ends of a gitignore entry.
'''
def sanitize_gitignore_content(file_name):
    return file_name.strip("\n").lstrip(os.sep).rstrip(os.sep)

'''
Determine if a line in a gitignore is a comment
'''
def line_is_not_comment(line):
    return line[0] is not "#"

'''
Get the content of a gitignore file.
'''
def get_gitignore_content(curr_path, result_set):
    gitignore_path = curr_path + os.sep + ".gitignore"

    if os.path.exists(gitignore_path):  # gitignore exists
        with open(gitignore_path) as all_lines:
            for line in all_lines:
                line = sanitize_gitignore_content(line)
                if line and line_is_not_comment(line):
                    if "!" not in line:
                        file_name = line.split("#")[0]  # Separate file name from any trailing comments
                        file_path = curr_path + os.sep + sanitize_gitignore_content(file_name)
                        result_set.add(file_path)

    return result_set

'''
Returns true if the file is not in the ignore (not gitignore!) list and doesn't
have extension that should be ignored.
'''
def file_name_not_ignored(file_name):
    if not any(fnmatch.fnmatch(file_name, pattern) for pattern in IGNORED_TEXTFILE_PATTERN):
        return True

    return False

'''
Check if file is exposed (not in any gitignore).
'''
def file_is_exposed(path_to_file, gitignored_files):
    if not any(fnmatch.fnmatch(path_to_file, pattern) for pattern in gitignored_files):
        return True

    return False

'''
Print out the safe sensitive files, exposed sensitive files, and sensitive lines.
'''
def print_result(safe_sensitive_files, exposed_sensitive_files, sensitive_lines, no_lines):
    print("-------------RESULT-------------")
    print(Fore.YELLOW + "Sensitive files found:" + Style.RESET_ALL)
    print(str(len(safe_sensitive_files)) + " Safe (gitignored) sensitive files:")
    for file_path in safe_sensitive_files:
        print(Fore.GREEN + file_path)

    print(Style.RESET_ALL)

    print(str(len(exposed_sensitive_files)) + " Exposed sensitive files:")
    if len(exposed_sensitive_files) > 0:
        print("(Fix: add the file(s) to .gitignore or store outside of the repo.)")
    for file_path in exposed_sensitive_files:
        print(Fore.RED + file_path)

    print(Style.RESET_ALL)
    if not no_lines:
        if len(sensitive_lines) > 0:
            print(Fore.YELLOW + "Exposed sensitive lines found:" + Style.RESET_ALL)
            for path in sorted(sensitive_lines.keys()):
                print("Sensitive lines in " + path)

                for entry in sensitive_lines[path]:
                    print(Fore.RED + "Line " + str(entry.line_no) + " (keyword: "+ entry.indicator + "): " + entry.line)

                print(Style.RESET_ALL)
        else:
            print(Fore.GREEN + "No exposed sensitive lines found!" + Style.RESET_ALL)

    print("--------------------------------")

'''
A file should be read if it's not a directory and file name is not ignored and
the the file is not a binary.
Refrence: https://stackoverflow.com/questions/898669/how-can-i-detect-if-a-file-is-binary-non-text-in-python
'''
def should_read_textfile(path_to_file, file_name):
    textchars = bytearray({7,8,9,10,12,13,27} | set(range(0x20, 0x100)) - {0x7f})
    is_binary_string = lambda bytes: bool(bytes.translate(None, textchars))

    return not os.path.isdir(path_to_file) and file_name_not_ignored(file_name) and not is_binary_string(open(path_to_file, 'rb').read(1024))

'''
Find  potential lines that potentially contain any sensitive information (e.g.
API key, email, password) in a non-directory file.
'''
def get_sensitive_lines(file_name, path_to_file, gitignored_files, no_lines):
    sen_lines = []
    if should_read_textfile(path_to_file, file_name):
        if path_to_file not in gitignored_files:
            with codecs.open(path_to_file,'r' , encoding='utf-8', errors = 'ignore') as f:
                line = f.readline()
                line_no = 1
                print(path_to_file)
                while line:
                    line_lowercase = line.lower()
                    for sensitive_word in sorted(SENSITIVE_KEYWORD):
                        if sensitive_word.lower() in line_lowercase:
                            new_sensitive_line = SensitiveLine(line_no, line.strip(), sensitive_word)
                            sen_lines.append(new_sensitive_line)
                            break

                    line = f.readline()
                    line_no += 1
    else:
        return None

    return None if len(sen_lines) is 0 else sen_lines

def main():
    parser = argparse.ArgumentParser(description='Find potential sensitive files and lines in your repository.')
    parser.add_argument("--root", default=".", help='The root of the diretory tree that you want to scan.')
    parser.add_argument("--paths", action='store_true', help="Show a list of processed paths in the result.")
    parser.add_argument("--no-lines", action='store_true', help="Do not show potential sensitive lines in result.")

    args = parser.parse_args()
    if args.root == ".":
        print("Scan starting at: " + args.root + " (current directory)")
    else:
        print("Scan starting at: " + args.root)

    # Do a breadth-first search to visit all directory, starting from the root.
    # For each directory, find potential sensitive files that might be exposed.
    # For each non-directory file, find any potential sensitive lines.
    q = deque()
    root = args.root
    q.append(root)
    path_processed = 1
    gitignored_files = set()
    safe_sensitive_files = set()
    exposed_sensitive_files = set()
    sensitive_lines = {}
    path_processed_list = []

    while len(q) > 0:
        curr_path = q.popleft()
        curr_path_children = os.listdir(curr_path)

        for child in curr_path_children:
            if not any(fnmatch.fnmatch(child, pattern) for pattern in IGNORED_FILENAME_PATTERN):
                child_path = curr_path + os.sep + child
                if os.path.isdir(child_path):
                    q.append(child_path)

        gitignored_files = get_gitignore_content(curr_path, gitignored_files)

        file_list = os.listdir(curr_path)   # file_list is the children of curr_path

        for file_name in file_list:
            path_to_file = curr_path + os.sep + file_name

            if file_is_sensitive(file_name):

                if file_is_exposed(path_to_file, gitignored_files):
                    exposed_sensitive_files.add(path_to_file)
                else:
                    if path_to_file in exposed_sensitive_files:
                        exposed_sensitive_files.remove(path_to_file)
                    safe_sensitive_files.add(path_to_file)

            sen_lines = None if args.no_lines else get_sensitive_lines(file_name, path_to_file, gitignored_files, args.no_lines)

            if sen_lines is not None:
                sensitive_lines[path_to_file] = sen_lines

        if args.paths:
            path_processed_list.append(path_to_file)
        path_processed += 1

    print_result(safe_sensitive_files, exposed_sensitive_files, sensitive_lines, args.no_lines)
    print("Path processed: " + str(path_processed))
    if args.paths:
        for path in path_processed_list:
            print("- " + path)
    print("Job done!")
    print("DISCLAIMER: The result might not be completely accurate due to false positive result, false negative result, etc.")

    if len(exposed_sensitive_files) == 0 and len(sensitive_lines.keys() == 0):
        sys.exit(0)
    else:
        sys.exit(1)

if __name__ == "__main__": main()
