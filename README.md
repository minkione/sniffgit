[![Build Status](https://travis-ci.org/Liandy213/sniffgit.svg?branch=master)](https://travis-ci.org/Liandy213/sniffgit)
# sniffgit
![Alt Text](https://media.giphy.com/media/xULW8yLG7FPSOcZhFS/giphy.gif)


We might have heard stories about programmers who forgot to remove their hardcoded
secret key before committing to a public repository, and some others have accidentally
committed their .crt file (in which they really shouldn't).

`sniffgit` solves that problem:
- It helps you to check whether or not you forgot to remove any sensitive
  information (e.g. email, API key, etc) from your files.
- It checks if you have hidden, via **.gitignore**, all sensitive files (e.g.
  id_dsa, something.crt, etc) in your repository.

Simply run `sniffgit` on your repository after installing it!

### Installation
```python
pip3 install sniffgit
```

### Usage
Recommended: go to the root of your root project and run the following command in terminal:
`sniffgit`

To specify a particular directory to start the "scan", use the `--root` argument:
`sniffgit --root path/to/another_dir`

To print out the list of processed directories at the end, use the `--paths` flag:
`sniffgit --paths`

### FAQ
#### How does `sniffgit` work?
`sniffgit` starts at a directory, called root, and see if there are any sensitive
files that have not been **gitignored**. `sniffgit` then proceed to check all of the
child directories (and other directories below it) of the root.

`sniffgit` also checks files with texts (.py, .go, .txt, etc) and see if there's
any potential sensitive lines in it. `sniffgit` will report any potential sensitive
lines that are exposed in the result.

#### How do you define "sensitive files" and "sensitive lines"?
Some files, such as `id_rsa`, `*.crt`, `*jks`, are known to be something that
needs to be kept secret. Hence they're considered as **"sensitive files"**.

Line of codes that contain keyword such as `email` or `API_KEY` are likely to
contain private data. Hence they're considered as **"sensitive lines"**.

There's **a lot more** files and keywords that can be included in the list, so
it would be awesome if you could expand this project :)!

#### How do you define "safe sensitive files" and "safe sensitive lines"?
***"safe sensitive files"*** are sensitive files that have been gitignored,
hence it won't (most likely) appear in the repository for wandering eyes to see.

Meanwhile, ***"safe sensitive lines"*** are sensitive lines that are contained
in a file that have been gititgnored, hence they are not publicly available on
the repository.



DISCLAIMER: The result of this program might not be completely accurate due to false positive, false negative result, etc. You can improve the program by contributing to this open-source project.
