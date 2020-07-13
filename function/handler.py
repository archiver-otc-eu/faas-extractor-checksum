import hashlib
import zlib
import json

from fs.onedatafs import OnedataFS

BLOCK_SIZE = 262144


def handle(req: bytes):
    """handle a request to the function
    Args:
        req (str): request body
    """
    args = json.loads(req)

    odfs = OnedataFS(args["host"], args["accessToken"],
                     force_direct_io=True,
                     insecure=True)


    algorithm = args.get("algorithm", "md5")
    checksum = init(algorithm)

    with odfs.open(args["filePath"], 'rb') as f:
        while True:
            data = f.read(BLOCK_SIZE)
            if not data:
                break
            checksum = update(algorithm, checksum, data)

    return json.dumps({"xattrs": {"checksum": finish(algorithm, checksum)}})


def init(algorithm):
    if algorithm == "md5":
        return hashlib.md5()
    elif algorithm == "adler32":
        return 1


def update(algorithm, prev_checksum, data):
    if algorithm == "md5":
        prev_checksum.update(data)
        return prev_checksum
    elif algorithm == "adler32":
        return zlib.adler32(data, prev_checksum)


def finish(algorithm, checksum):
    if algorithm == "md5":
        return checksum.hexdigest()
    elif algorithm == "adler32":
        return format(checksum, 'x')

