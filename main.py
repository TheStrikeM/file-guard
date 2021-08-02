from cipheration.CIPHERAdapter import CIPHERAdapter
import sys


cipher = CIPHERAdapter()

operation_type = sys.argv[1]
if operation_type == "encrypt":
    folder = sys.argv[2]
    cipher.encrypt_walk(folder)

elif operation_type == "decrypt":
    folder = sys.argv[2]
    cipher.decrypt_walk(folder)
