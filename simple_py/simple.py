import json
import logging
import os
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from eqty_sdk import (
    CID,
    DID,
    SIGNER_ALGORITHMS,
    Computation,
    Context,
    Dataset,
    Signer,
    compute,
    init,
    purge_statement_store,
    set_active_signer,
)

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

ENDPOINT = os.environ.get("ENDPOINT", "").strip()
SERVE_PORT = os.environ.get("SERVE_PORT", "").strip()

ctx = Context.new("simple-py")
config = init(default_context=ctx)
config = config.set_store_all_blobs(True)

DESCRIPTION="My Ed25519 signing key for integrity statements."
if ENDPOINT:
    signer = Signer.vcomp_notary(ENDPOINT)
    DESCRIPTION="VCOMP Notary Signer"
else:
    signer = Signer.new(SIGNER_ALGORITHMS.ED25519)

set_active_signer(signer)
did = DID.from_signer(
    signer,
    name="My key",
    description=DESCRIPTION
)

# Create sample objects
my_object = "My Object"
my_path = "./simple.py"
my_cid = "bafkr4icqw77khu73vgw74jpnlnep37ec3l6jd4lg5kvw2letvqjhgk6jmi"

# Registering a serializable Python object
d0 = Dataset.from_object(
    my_object, name="My dataset 0", description="My description for dataset 0"
)

# Registering a file or directory of files from the file system
d1 = Dataset.from_path(
    my_path, name="My dataset 1", description="My description for dataset 1"
)

# Registering a data asset or collection of assets by its CID
d2 = Dataset.from_cid(
    CID(my_cid), name="My dataset 2", description="My description for dataset 2", foo="bar"
)

# Registering a computation with builder
computation = (
    Computation.new()
    .add_input_cid(d0.cid)
    .add_input_cid(d1.cid)
    .add_output_cid(d2.cid)
    .finalize()
)


@compute(
    metadata={
        "name": "My computation",
        "description": "My description for the computation",
        "foo": "bar",
    }
)
def my_function(input_0: Dataset, input_1: Dataset):
    my_output_object = str(input_0.value) + str(input_1.value)
    output = Dataset.from_object(
        my_output_object,
        name="My dataset",
        description="My description for the output dataset",
    )
    return output


my_function(d0, d1)

# Export manifest
output_dir = Path(os.environ.get("OUTPUT_DIR", "/output"))
output_dir.mkdir(parents=True, exist_ok=True)
manifest_path = output_dir / "manifest_simple.json"
ctx.export(manifest_path)
logger.info("Manifest written to %s", manifest_path)

# Print the manifest to stdout (whitespace compressed) so it shows up in the log
with open(manifest_path) as f:
    manifest = json.load(f)
print("==========MANIFEST==============")
print(json.dumps(manifest, separators=(",", ":")))
print("========MANIFEST END============")


purge_statement_store()

# Optionally serve the output directory over HTTP (blocks until stopped)
if SERVE_PORT:
    handler = partial(SimpleHTTPRequestHandler, directory=str(output_dir))
    with ThreadingHTTPServer(("0.0.0.0", int(SERVE_PORT)), handler) as httpd:
        logger.info("Serving %s at http://0.0.0.0:%s/", output_dir, SERVE_PORT)
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            logger.info("Shutting down HTTP server")

