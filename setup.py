from setuptools import setup

setup(
    name='simpleai_base',
    version='0.3.0',
    packages=['simpleai_base'],
    install_requires=[
        'maturin @ git+https://github.com/PyO3/maturin.git@v0.14.0',
        'cbor2',
    ],
    include_package_data=True,
    description='A Python package with Rust code',
    author='Your Name',
    author_email='your.email@example.com',
    url='https://github.com/yourusername/my_python_package',
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
)