# lwip-py

How to build:
 - Clone repo with submodules
 - Build liblwip with CMake (`mkdir liblwip/build && cd liblwip/build && cmake .. && make -j$(nproc)`)
 - Copy generated file `liblwip/build/headers.py` to `src/lwip/headers.py`
 - Make pip package (`python -m build`)
 - Install pip package (`python -m pip install ./dist/lwip_py-[...].whl`)
 - Copy `liblwip.so` to some path
 - Add an environment variable `LIBLWIP_PATH` with the absolute path to `liblwip.so`
 - Run tests to ensure everything is working properly (Ex: `python tests/tests_tcp.py`)
