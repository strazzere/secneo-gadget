# Simple stub like "plugin" for importing comments
# from the frida scripts, should be able to run multiple times
# without destroying old comments, and updating them by appending
# new ones if they are completely new
#
# diff@protonmail.com

import json
import ida_bytes
import ida_kernwin

# expected input will be along these lines
# {
#     "0x1234": "Comment for address 0x1234",
#     "0x5678": "Comment for address 0x5678",
#     ...
# }
with open("/home/diff/repo/rednaga/secneo-gadget/ida/comments.json", "r") as f:
	comments = json.load(f)

imported = 0
skipped = 0
for address, comment in comments.items():
	address = int(address, 16)

	existing_comment = ida_bytes.get_cmt(address, 0)
	if existing_comment:
		skipped += 1
		continue

	imported += 1
	ida_bytes.set_cmt(address, comment, 0)

ida_kernwin.msg("{} comments added, skipped {} identical comment imports!\n".format(imported, skipped))