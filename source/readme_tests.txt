cd c:\Users\sebas\sprachprofil\sourcecode\HTTPS_4_ANTIGRAVITY\http4_wiqc_mvp

# 1. Run the full 37-test automated suite (Python 3.15 or 3.14)
py -3.15 -m unittest discover -s tests -t . -v
py -3.14 -m unittest discover -s tests -t . -v

# 2. Run the self-contained 10-workflow live UDP demonstration
py -3.15 example.client.py --self-contained

# 3. Or run Server and Client in two separate terminals:
# Terminal 1:
py -3.15 example.server.py --host 127.0.0.1 --port 4433 --deterministic-key
# Terminal 2:
py -3.15 example.client.py --host 127.0.0.1 --port 4433