[![Website nfuzz-pypi](https://img.shields.io/badge/Usage-PyPI-green.svg)](https://pypi.org/project/nfuzz/)
&nbsp;
[![Made with Python](https://img.shields.io/badge/Made%20with-Python-blue.svg)](https://www.python.org/)
&nbsp;
[![License: MIT (Code) nfuzz](https://img.shields.io/badge/License-MIT_(Code),nfuzz-blue.svg)](https://github.com/alexqiaodan/nfuzz/blob/master/README.md)
# NFuzz
NFuzz has been created to conduct fuzzy testing and it is based on a simple concept: it generates the FUZZ keywords by an excellent fuzz grammar method that is created by this job. And it also provides a simple WebFuzzer for daily use.  

## Installation
To install NFuzz, simply use pip:
 _`pip install nfuzz`_

## Usage
A simple webFuzzer example base on Baidu homepage:
```
from nfuzz.WebFuzzer import WebFormFuzzer
from nfuzz.WebFuzzer import WebRunner
import requests
if __name__ == "__main__":
    print('\n### A WebFormFuzzer')
    httpd_url = "https://www.baidu.com/"
    base_url = "https://www.baidu.com/"
    web_form_fuzzer = WebFormFuzzer(httpd_url)
    web_form_fuzzer.fuzz()
    web_form_runner = WebRunner(base_url)
    out = web_form_fuzzer.runs(web_form_runner, 100000)
    print(out)
```

## Generate random characters
```
from nfuzz.Fuzzer import RandomFuzzer
if __name__ == "__main__":
    print('\n### Generate random characters')
    fuzzer = RandomFuzzer()
    print(fuzzer.fuzz())
```

## Generate random characters
```
from nfuzz.Fuzzer import RandomFuzzer
if __name__ == "__main__":
    print('\n### Generate random characters')
    fuzzer = RandomFuzzer()
    print(fuzzer.fuzz())
```

## Generate random characters with MutationFuzzer
```
from nfuzz.MutationFuzzer import MutationFuzzer
if __name__ == "__main__":
    print('\n### Generate random characters with MutationFuzzer')
    seed_input = "http://www.baidu.com/"
    mutation_fuzzer = MutationFuzzer(seed=[seed_input])
    for i in range(20):
        inp = mutation_fuzzer.fuzz()
        print(inp)
```


## Generate random characters with GrammarFuzzer
```
from nfuzz.GrammarFuzzer import GrammarFuzzer
URL_GRAMMAR = {
    "<start>": ["<url>"],
    "<url>":
        ["<scheme>://<domain><path><query>"],
    "<scheme>":
        ["http", "https"],
    "<domain>":
        ["<host>", "<host>:<port>"],
    "<host>":  # Just a few
        ["www.baidu.com", "lofter.com"],
    "<port>":
        ["80", "8080", "<nat>"],
    "<nat>":
        ["<digit>", "<digit><digit>"],
    "<digit>":
        ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"],
    "<path>":  # Just a few
        ["", "/", "/<id>"],
    "<id>":  # Just a few
        ["abc", "def", "x<digit><digit>"],
    "<query>":
        ["", "?<params>"],
    "<params>":
        ["<param>", "<param>&<params>"],
    "<param>":  # Just a few
        ["<id>=<id>", "<id>=<nat>"],
}

if __name__ == "__main__":
print('\n### Generate random characters with GrammarFuzzer')
    f = GrammarFuzzer(URL_GRAMMAR, log=False, min_nonterminals=10)
    for i in range(10):
        res = f.fuzz()
        print(res)
```
