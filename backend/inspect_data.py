"""Quick script to inspect dataset zip files."""
import zipfile
import os

root = os.path.dirname(os.path.dirname(__file__))

for zname in ["MachineLearningCSV.zip", "GeneratedLabelledFlows.zip"]:
    zpath = os.path.join(root, zname)
    if os.path.exists(zpath):
        print(f"\n=== {zname} ===")
        z = zipfile.ZipFile(zpath)
        for info in z.infolist()[:25]:
            print(f"  {info.filename}  ({info.file_size:,} bytes)")
        print(f"  ... total files: {len(z.infolist())}")
    else:
        print(f"\n[!] {zname} not found")
