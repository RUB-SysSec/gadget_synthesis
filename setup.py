import setuptools

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setuptools.setup(
    name="synthesizer",
    version="1.0.0",
    author="Moritz Schloegel",
    author_email="moritz.schloegel@ruhr-uni-bochum.de",
    description="Generic gadget chain synthesizer (research prototype) by Moritz Schloegel, Tim Blazytko, Julius Basler, Fabian Hemmer, and Thorsten Holz",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://git.noc.ruhr-uni-bochum.de/gadget_synthesis/synthesizer",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)",
        "Operating System :: POSIX :: Linux",
    ],
    packages=setuptools.find_packages(),
    python_requires='>=3.8',
)