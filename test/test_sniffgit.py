from sniffgit import sniffgit

def test_file_is_sensitive_positive():
    assert sniffgit.file_is_sensitive("something.cert") == True
    assert sniffgit.file_is_sensitive("123.cert") == True
    assert sniffgit.file_is_sensitive("something123.cert") == True
    assert sniffgit.file_is_sensitive("id_rsa") == True
    assert sniffgit.file_is_sensitive("id_dsa") == True
    assert sniffgit.file_is_sensitive("something.pfx") == True
    assert sniffgit.file_is_sensitive(".bash_history") == True
    assert sniffgit.file_is_sensitive("something.crt") == True
    assert sniffgit.file_is_sensitive("123.crt") == True
    assert sniffgit.file_is_sensitive("something123.crt") == True
    assert sniffgit.file_is_sensitive("something.pem") == True
    assert sniffgit.file_is_sensitive("something.csr") == True
    assert sniffgit.file_is_sensitive("something.key") == True
    assert sniffgit.file_is_sensitive("something.p12") == True
    assert sniffgit.file_is_sensitive("something.der") == True
    assert sniffgit.file_is_sensitive(".htaccess") == True
    assert sniffgit.file_is_sensitive(".htpasswd") == True
    assert sniffgit.file_is_sensitive("something.jks") == True
    assert sniffgit.file_is_sensitive("web.config") == True
    assert sniffgit.file_is_sensitive("wp-config.php") == True

def test_file_is_sensitive_negative():
    assert sniffgit.file_is_sensitive("cert.pdf") == False
    assert sniffgit.file_is_sensitive("key.txt") == False
    assert sniffgit.file_is_sensitive("crt.doc") == False
    assert sniffgit.file_is_sensitive("der.docx") == False
    assert sniffgit.file_is_sensitive("something.pdf") == False
    assert sniffgit.file_is_sensitive("secret.docx") == False


def test_sanitize_gitignore_content():
    assert sniffgit.sanitize_gitignore_content("hello.txt") == "hello.txt"
    assert sniffgit.sanitize_gitignore_content("hello.txt\n") == "hello.txt"
    assert sniffgit.sanitize_gitignore_content("/hello.txt") == "hello.txt"
    assert sniffgit.sanitize_gitignore_content("hello/") == "hello"
    assert sniffgit.sanitize_gitignore_content("/hello/") == "hello"
    assert sniffgit.sanitize_gitignore_content("/hello/\n") == "hello"
    assert sniffgit.sanitize_gitignore_content("\n/hello/\n") == "hello"
    assert sniffgit.sanitize_gitignore_content("/hello/\n\n") == "hello"
    assert sniffgit.sanitize_gitignore_content("\n\n/hello/") == "hello"
    assert sniffgit.sanitize_gitignore_content("\n\n/hello/\n\n") == "hello"

def create_gitignore_list(curr_path, gitignore_path, file_names):
    whole_content = ""
    for file_name in file_names:
        whole_content = whole_content + file_name + "\n"

    gitignore_path.write(whole_content)

def test_get_git_ignore_content_positive(tmpdir):
    root = tmpdir.mkdir("temp")
    gitignore_path = root.join(".gitignore")
    assert len(tmpdir.listdir()) == 1 # gitignore has been created.
    gitignore_content = ["/id_rsa", "id_dsa/", "/abc.java/", "/**/abc.go", "de?.java"]
    create_gitignore_list(root, gitignore_path, gitignore_content)
    gitignored_files_detected = set()
    gitignored_files_detected = sniffgit.get_gitignore_content(str(root), gitignored_files_detected)

    git_ignored_files_expected = [str(root) + "/" + sniffgit.sanitize_gitignore_content(name) for name in gitignore_content]
    for path in gitignored_files_detected:
        print(path)
    for path in git_ignored_files_expected:
        assert (path in gitignored_files_detected) == True

def test_get_git_ignore_content_negative(tmpdir):
    root = tmpdir.mkdir("temp")
    gitignore_path = root.join(".gitignore")
    assert len(tmpdir.listdir()) == 1 # gitignore has been created.
    gitignore_content = ["!*.py", "!/abc.go", "!def.java", "!**.rb"]
    create_gitignore_list(root, gitignore_path, gitignore_content)
    gitignored_files_detected = set()
    gitignored_files_detected = sniffgit.get_gitignore_content(str(root), gitignored_files_detected)

    git_ignored_files_expected = [str(root) + "/" + sniffgit.sanitize_gitignore_content(name) for name in gitignore_content]
    for path in gitignored_files_detected:
        print(path)
    for path in git_ignored_files_expected:
        assert (path in gitignored_files_detected) == False

def test_line_is_not_comment_positive():
    assert sniffgit.line_is_not_comment("#test") == False
    assert sniffgit.line_is_not_comment("##test") == False

def test_line_is_not_comment_negative():
    assert sniffgit.line_is_not_comment("test") == True
    assert sniffgit.line_is_not_comment("test #comment") == True
    assert sniffgit.line_is_not_comment("test      #comment") == True

def test_file_is_exposed(tmpdir):
    root = tmpdir.mkdir("temp")
    gitignore_path = root.join(".gitignore")
    assert len(tmpdir.listdir()) == 1 # gitignore has been created.
    gitignore_content = ["/id_rsa", "*.pfx", "/abc/*.py", "/**/abc.go", "de?.java"]

    create_gitignore_list(root, gitignore_path, gitignore_content)
    gitignored_files = set()
    gitignored_files = sniffgit.get_gitignore_content(str(root), gitignored_files)

    test_file_negative = ["/id_rsa", "/hello.pfx", "/123.pfx", "/abc/a.py", "/abc/b.py",
                          "/hello/abc.go", "/bonjour/abc.go", "/dex.java", "/dey.java"]

    for file_relative_path in test_file_negative:
        path_to_file = str(root) + file_relative_path
        assert sniffgit.file_is_exposed(path_to_file, gitignored_files) == False

def test_file_is_exposed(tmpdir):
    root = tmpdir.mkdir("temp")
    gitignore_path = root.join(".gitignore")
    assert len(tmpdir.listdir()) == 1 # gitignore has been created.
    gitignore_content = ["/id_rsa", "*.pfx", "/abc/*.py", "/**/abc.go", "de?.java"]

    create_gitignore_list(root, gitignore_path, gitignore_content)
    gitignored_files = set()
    gitignored_files = sniffgit.get_gitignore_content(str(root), gitignored_files)

    test_file_negative = ["/id_dsa", "/abc.pdf", "/def.py", "/def/a.py", "/def/b.py",
                          "/hello/abc.java", "/dexa.java", "/deya.java"]

    for file_relative_path in test_file_negative:
        path_to_file = str(root) + file_relative_path
        print(path_to_file)
        assert sniffgit.file_is_exposed(path_to_file, gitignored_files) == True


# get_sensitive_lines
# file_name_not_ignored
