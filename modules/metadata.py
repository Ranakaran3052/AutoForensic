import os
import datetime

def get_metadata(file_path):
    stats = os.stat(file_path)

    return {
        "Size (bytes)": stats.st_size,
        "Created": datetime.datetime.fromtimestamp(stats.st_ctime),
        "Modified": datetime.datetime.fromtimestamp(stats.st_mtime),
        "Accessed": datetime.datetime.fromtimestamp(stats.st_atime)
    }