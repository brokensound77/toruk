from setuptools import setup, find_packages

import toruk


REQUIRES = [
    'colorama>=0.3.9',
    'requests>=2.18.4'
]

setup(
    name='toruk',
    description=('Crowdstrike Falcon Host script for iterating through'
                 'instances to get alert and other relevant data'),
    keywords='falcon crowdstrike security',
    version=toruk.__version__,
    author='br0k3ns0und',
    install_requires=REQUIRES,
    entry_points={
        'console_scripts': [
            'toruk=toruk.toruk:main'
        ]
    },
    packages=find_packages(exclude=['bin']),
    include_package_data=True,
    license='MIT License',
    classifiers=["Programming Language :: Python"],
    url='https://github.com/brokensound77/toruk'
)
