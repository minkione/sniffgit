from setuptools import setup

setup(
    name='sniffgit',
    version='1.0.1',
    description='Find sensitive information and files in a git repository.',
    author='Liandy Hardikoesoemo',
    author_email='liandy.hardikoesoemo@gmail.com',
    url='https://github.com/Liandy213/sniffgit',
    packages=['sniffgit'],
    license=['MIT License'],
    entry_points = {
        'console_scripts': ['sniffgit = sniffgit.sniffgit:main']
    },
    classifier=[
        'Environment :: Console',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Operating System :: MacOS :: MacOS X',
        'Operating System :: Unix',
        'Operating System :: POSIX',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Topic :: Software Development',
        'Topic :: Software Development :: Build Tools',
        'Topic :: Software Development :: Debuggers',
        'Topic :: Software Development :: Libraries',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Topic :: System :: Software Distribution',
        'Topic :: System :: Systems Administration',
        'Topic :: Utilities'
    ],
    install_requires=['colorama']
)
