# permite instalar analisador no venv e acessar classes de qualquer projeto
from setuptools import setup, find_packages
setup(
  name="network_traffic_analyzer",
  version="0.1",
  packages=find_packages(),
)