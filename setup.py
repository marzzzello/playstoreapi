from setuptools import setup
from setuptools.command.build_py import build_py as _build


import os.path
import subprocess
import shutil

PROTOC_EXEC = "protoc"

CURRENT_DIR = os.path.abspath(os.path.dirname(__file__))


class ProtobufBuilder(_build):
    def run(self):
        # check if protobuf is installed
        exec_path = shutil.which(PROTOC_EXEC)
        if exec_path is None:
            raise Exception("You should install protobuf compiler")

        print("Building protobuf file")
        subprocess.run(
            [
                exec_path,
                "--proto_path=" + CURRENT_DIR,
                "--python_out=" + CURRENT_DIR + "/playstoreapi/",
                CURRENT_DIR + "/googleplay.proto",
            ]
        )
        super().run()


setup(
    name='playstoreapi',
    version='0.5.2',
    description='Unofficial python api for google play',
    url='https://gitlab.com/marzzzello/playstoreapi',
    author='NoMore201, marzzzello',
    author_email='playstoreapi@07f.de',
    license='GPL3',
    packages=['playstoreapi'],
    package_data={'playstoreapi': ['config.py' 'device.properties', 'googleplay_pb2.py', 'googleplay.py', 'utils.py']},
    include_package_data=True,
    cmdclass={'build_py': ProtobufBuilder},
    install_requires=['cryptography>=2.2', 'protobuf>=3.5.2', 'requests'],
)
