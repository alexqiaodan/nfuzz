#!/usr/bin/env python3
# -*- encoding: utf-8  -*-
'''
@author: sunqiao
@contact: sunqiao@corp.netease.com
@time: 2021/4/6 9:13
@desc:Fuzzing with Grammers
'''
import setuptools

with open("README.md", "r") as fh:
  long_description = fh.read()

setuptools.setup(
  name="nfuzz",
  version="0.0.3",
  author="alexqiaodan",
  author_email="sunqiao@corp.netease.com",
  description="A useful tool for fuzz job.",
  long_description=long_description,
  long_description_content_type="text/markdown",
  url="https://github.com/alexqiaodan/nfuzz",
  packages=setuptools.find_packages(),
  classifiers=[
  "Programming Language :: Python :: 3",
  "License :: OSI Approved :: MIT License",
  "Operating System :: OS Independent",
  ],
  install_requires=['requests', 'iPython', 'nbformat','graphviz'],
)