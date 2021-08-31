import sys
from configparser import ConfigParser


cp = ConfigParser()
cp.read('setup.cfg')
version = cp['metadata']['version']
tag_version = sys.argv[1]

if tag_version != version:
    print(f'::error::Tag version {tag_version} does not match package version {version}')
    sys.exit(1)
