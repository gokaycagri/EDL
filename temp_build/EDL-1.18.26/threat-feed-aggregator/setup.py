from setuptools import setup, find_packages

import os

# Read version from version.py
version_ns = {}
with open(os.path.join("threat_feed_aggregator", "version.py")) as f:
    exec(f.read(), version_ns)

setup(
    name='threat-feed-aggregator',
    version=version_ns['__version__'],
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        'Flask',
        'requests',
    ],
    entry_points={
        'console_scripts': [
            'threat-feed-aggregator=threat_feed_aggregator.app:main',
        ],
    },
)
