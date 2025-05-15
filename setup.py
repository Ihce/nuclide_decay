from setuptools import setup, find_packages
from setuptools_rust import Binding, RustExtension

setup(
    name="nuclide_decay",
    version="0.1.0",
    author="Dylan Stancil",
    description="A multi-architecture binary disassembler",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    packages=find_packages(where="python"),
    package_dir={"": "python"},
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Rust",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.7",
    rust_extensions=[
        RustExtension(
            "nuclide_decay.nuclide_decay",  # Must match the PyInit_nuclide_decay_py function name
            binding=Binding.PyO3,
        )
    ],
    zip_safe=False,
)